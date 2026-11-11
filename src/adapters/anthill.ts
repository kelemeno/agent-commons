// The Anthill adapter: everything the commons knows about its first target
// project, kept out of the generic core. Core modules never import this file;
// the CLI and scripts pass its results (Rules, a TreeView, a GateReport) in.
//
// Two copies of the rules exist on purpose: anthillRules() here, and
// .commons/rules.json in the Anthill repo, which is what CI reads and what an
// Anthill poll ratifies. test/adapters-anthill.test.ts asserts they are equal,
// so changing one without the other fails the build.
//
// Backend code is loaded from a checkout directory at run time and executed in
// this process (anthillTree) or in a child (behaviourDeltaFor). Point it only at
// a checkout you would run anyway, never at an unreviewed PR in a process that
// holds credentials.

import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  type DeclaredDelta,
  type Divergence,
  GATE,
  loadManifest,
  type Manifest,
  runBehaviourDelta,
} from "../gates/behaviourDelta";
import { type EngineLike, treeFromEngine, treeFromSnapshot } from "../tree";
import type { GateReport, Rules, TreeView } from "../types";

export const BACKEND_DIR_ENV = "ANTHILL_BACKEND_DIR";
// The community the server moves the seed (the snapshot's tree) to.
export const SNAPSHOT_COMMUNITY = "demo";

// Anthill rules, version 1. First matching ring glob wins; unmatched is ring 1.
export function anthillRules(): Rules {
  return {
    version: 1,
    rings: [
      // The whole server: reputation maths, accounts, the log and its replay,
      // and everything they load. A ring 1 module imported from here would run
      // in the kernel's process (and inside the behaviour-delta replay), where
      // it can patch the kernel at load time, so every module the server can
      // reach is kernel. test/adapters-anthill.test.ts walks the import graph.
      { glob: "anthill-backend/src/**", ring: 0 },
      // The seed of the demo tree and of the behaviour-delta log; and the
      // compiler config, whose `paths` can redirect a package import.
      { glob: "anthill-backend/anthillSnapshot.json", ring: 0 },
      { glob: "anthill-backend/tsconfig*.json", ring: 0 },
      { glob: "anthill-contracts/src/**", ring: 0 },
      // Forge libraries compiled into the contracts, and the remappings that
      // decide which file an import resolves to.
      { glob: "anthill-contracts/lib/**", ring: 0 },
      { glob: "**/remappings.txt", ring: 0 },
      // A submodule pointer whose diff was not expanded into the submodule's
      // files could hide any change, so on its own it counts as kernel.
      { glob: "anthill-backend", ring: 0 },
      { glob: "anthill-contracts", ring: 0 },
      { glob: "anthill-frontend", ring: 0 },
      // What decides what runs and how changes are judged: where code is
      // fetched from (submodule URLs, package registries), CI, the commons
      // config (rules, behaviour-delta declarations), deploy config, and the
      // coordinator itself while it still lives in this repo.
      { glob: "**/.gitmodules", ring: 0 },
      { glob: "**/.npmrc", ring: 0 },
      { glob: "**/.yarnrc*", ring: 0 },
      { glob: ".github/**", ring: 0 },
      { glob: ".commons/**", ring: 0 },
      { glob: "anthill-commons/**", ring: 0 },
      { glob: "**/Dockerfile", ring: 0 },
      { glob: "**/Procfile", ring: 0 },
      { glob: "**/render.yaml", ring: 0 },
      { glob: "anthill-frontend/**", ring: 2 },
    ],
    // Only the dependency track may change these: what gets installed, and
    // from where.
    lockedPaths: [
      "**/package.json",
      "**/package-lock.json",
      "**/npm-shrinkwrap.json",
      "**/yarn.lock",
      "**/pnpm-lock.yaml",
      "**/bun.lock*",
      "**/.npmrc",
      "**/.yarnrc*",
      "**/foundry.toml",
      "**/remappings.txt",
      "**/.gitmodules",
      "anthill-contracts/lib/**",
    ],
    maxLinesPerSubmission: 400,
    minTreeDistance: 2,
    assignedReviewers: 3,
    requireOtherModelFamily: true,
    plantRate: 0.15,
    stake: { base: 10, exponent: 1.5, ringMultiplier: [4, 1.5, 1], review: 5, finding: 5 },
    rewards: {
      merge: 30,
      proposerCutFraction: 0.1,
      bounty: { low: 5, medium: 15, high: 40, critical: 100 },
      stageMultiplier: { dev: 1, release: 2, main: 4 },
      cleanReview: 2,
      missedPlantPenalty: 6,
      falseFindingPenalty: 5,
      duplicateDecay: 0.9,
      inviterShare: 0.25,
      honeytokenPenalty: 50,
    },
    vesting: { tailDays: 30 },
    reviewsPerSubmitCredit: 2,
    promotion: {
      minModelFamilies: 3,
      minDistinctOwners: 2,
      recallWindowDays: 28,
      minSeeds: 30,
      minRecallLowerBound90: 0.8,
      maxCriticalUpperBound90: 0.1,
      soakFloorHours: 72,
      kernelSignoffs: 2,
    },
    // Empty until a poll names them; with none, no snapshot can collect the
    // kernel signoffs, so nothing is promoted to main by the commons.
    kernelSigners: [],
  };
}

// explicit option > $ANTHILL_BACKEND_DIR > error. The directory must look like
// an anthill-backend checkout, so a wrong path fails here and not as a
// confusing module-not-found deep inside a replay.
export function resolveBackendDir(explicit?: string, env: NodeJS.ProcessEnv = process.env): string {
  const chosen = explicit !== undefined && explicit !== "" ? explicit : env[BACKEND_DIR_ENV];
  if (chosen === undefined || chosen === "") {
    throw new Error(
      `anthill: no backend directory: pass backendDir or set ${BACKEND_DIR_ENV} to an anthill-backend checkout`,
    );
  }
  const dir = resolve(chosen);
  for (const file of ["store.ts", "offchain.ts", "engine.ts"]) {
    if (!existsSync(join(dir, "src", file))) {
      throw new Error(`anthill: ${dir} is not an anthill-backend checkout (no src/${file})`);
    }
  }
  return dir;
}

// What anthillTree needs from a checkout's src/store.ts and src/offchain.ts.
export type BackendModules = {
  Store: new (dir: string) => object;
  Communities: new (store: object) => {
    load(onReplayed: (executed: unknown) => Promise<void>): Promise<void>;
    get(id: string): { engine: EngineLike } | undefined;
    all(): { id: string }[];
  };
  bigintReviver: (key: string, value: unknown) => unknown;
};

export function loadBackend(backendDir: string): BackendModules {
  const { Store, bigintReviver } = require(join(backendDir, "src", "store.ts")) as Pick<
    BackendModules,
    "Store" | "bigintReviver"
  >;
  const { Communities } = require(join(backendDir, "src", "offchain.ts")) as Pick<BackendModules, "Communities">;
  return { Store, Communities, bigintReviver };
}

// A frozen TreeView of one Anthill community.
//
// With snapshotPath: read anthillSnapshot.json (no backend code runs). A
// snapshot holds one tree, the original one, which the server keeps as the
// `demo` community; any other community, or a backend to replay, is refused
// rather than answered with the demo tree.
// Otherwise: replay <dataDir>/log.jsonl (default <backendDir>/data, the
// backend's own default when started from its directory) through the
// backend's Store and Communities, exactly as the server does on startup, and
// read the community's engine.
export async function anthillTree(opts: {
  backendDir?: string;
  dataDir?: string;
  snapshotPath?: string;
  community: string;
  env?: NodeJS.ProcessEnv;
}): Promise<TreeView> {
  if (opts.snapshotPath !== undefined) {
    if (opts.dataDir !== undefined || opts.backendDir !== undefined) {
      throw new Error("anthill: pass either snapshotPath or backendDir/dataDir, not both");
    }
    if (opts.community !== SNAPSHOT_COMMUNITY) {
      throw new Error(
        `anthill: a snapshot holds only the ${SNAPSHOT_COMMUNITY} community, not ${opts.community}; replay a backend log for other communities`,
      );
    }
    return treeFromSnapshot(readFileSync(opts.snapshotPath, "utf8"));
  }
  const backendDir = resolveBackendDir(opts.backendDir, opts.env);
  const dataDir = resolve(opts.dataDir ?? join(backendDir, "data"));
  // Checked first: Store creates a missing directory, and an empty log would
  // read as a backend with no communities rather than as a wrong path.
  if (!existsSync(join(dataDir, "log.jsonl"))) throw new Error(`anthill: no backend log at ${join(dataDir, "log.jsonl")}`);

  const { Store, Communities } = loadBackend(backendDir);
  const communities = new Communities(new Store(dataDir));
  await communities.load(async () => {});
  const tree = communities.get(opts.community);
  if (tree === undefined) {
    const known = communities
      .all()
      .map((t) => t.id)
      .sort();
    throw new Error(`anthill: no community ${opts.community} in the log (it has: ${known.join(", ")})`);
  }
  if (tree.engine.members().length === 0) throw new Error(`anthill: community ${opts.community} has no members yet`);
  return treeFromEngine(tree.engine);
}

// The declarations a change adds: head's, minus any already on the base. A
// declaration counts only in the change that adds it, so one left in the file
// cannot cover a later, unrelated divergence. Identity is the whole entry; an
// edited note is a new declaration, which reviewers then see in the diff.
export function addedDeclarations(base: Manifest, head: Manifest): Manifest {
  const key = (d: DeclaredDelta) => JSON.stringify([d.community, d.fromEntry, d.note]);
  const old = new Set(base.declared.map(key));
  return { declared: head.declared.filter((d) => !old.has(key(d))) };
}

// The behaviour-delta gate for Anthill. Never throws: an unreadable manifest
// is a failing report, like every other harness problem in runBehaviourDelta,
// because a gate that cannot judge must not pass.
//
// With baseManifestPath, only the declarations the change adds count (see
// addedDeclarations). A missing base file means the base declares nothing; a
// malformed one fails, since the base is what the change is judged against.
export async function behaviourDeltaFor(opts: {
  oldBackendDir: string;
  newBackendDir: string;
  logPath: string;
  manifestPath: string;
  baseManifestPath?: string;
  timeoutMs?: number;
}): Promise<GateReport & { divergences: Divergence[] }> {
  let manifest: Manifest;
  try {
    manifest = loadManifest(opts.manifestPath);
    if (opts.baseManifestPath !== undefined && existsSync(opts.baseManifestPath)) {
      manifest = addedDeclarations(loadBaseManifest(opts.baseManifestPath), manifest);
    }
  } catch (e) {
    return { gate: GATE, pass: false, details: (e as Error).message, divergences: [] };
  }
  return runBehaviourDelta({
    oldBackendDir: opts.oldBackendDir,
    newBackendDir: opts.newBackendDir,
    logPath: opts.logPath,
    manifest,
    ...(opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs }),
  });
}

function loadBaseManifest(path: string): Manifest {
  try {
    return loadManifest(path);
  } catch (e) {
    throw new Error(`base ${(e as Error).message}`);
  }
}
