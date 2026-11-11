// The behaviour-delta gate: does a change to the Anthill backend change what
// the backend computes from its own history?
//
// The backend's off-chain state is an append-only log (<DATA_DIR>/log.jsonl)
// replayed into one engine per community on startup. This gate replays the same
// log through the old and the new checkout's own `Store` and `Communities`
// (src/store.ts, src/offchain.ts), digests each community's tree after every
// replayed action, and reports the first entry at which each community's
// digest sequence differs. A divergence passes only if the change declares it
// in its manifest (`.commons/behaviour-delta.json`); an undeclared divergence
// fails. Refactors therefore pass silently, and a behaviour change has to say
// where it starts and why, which is what a reviewer would ask for anyway.
//
// Entry numbering: entry i is the i-th non-empty line of log.jsonl, 0-based,
// the same lines Store replays. After the last action, every community also
// gets a final digest at entry index = number of entries, so a community that
// has no actions (only a seed), or exists in one checkout only, is compared too.
//
// Isolation: each checkout is replayed in its own child process (this file,
// run with --worker), with a fresh copy of the log, a minimal environment and a
// timeout. The new checkout is code under review: loading it in the
// coordinator's process would let it patch the hash function or the old side's
// results, and would leak its environment and module state into ours. A child
// process is NOT a sandbox: the code still runs as the coordinator's user, can
// read what that user can read, and could print anything into its result
// file. Run the coordinator unprivileged (or in a container) for untrusted
// submissions; the gate catches honest mistakes and lazy gaming, not a
// determined adversary who rewrites the harness's view from inside engine.ts —
// that is in the diff, where reviewers see it.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import type { GateReport } from "../types";

export const GATE = "behaviourDelta";
const DEFAULT_TIMEOUT_MS = 120_000;
const STDERR_TAIL = 4000;

export type DeclaredDelta = { community: string; fromEntry: number; note: string };
export type Manifest = { declared: DeclaredDelta[] };

export type Divergence = {
  community: string;
  fromEntry: number;
  oldDigest: string; // "" when the community has no state on that side yet
  newDigest: string;
  // set when the sides differ in whether (or how) an entry failed to replay,
  // or when the community or entry is missing on one side
  error?: string;
};

// What digestEngine reads: the public getters of the backend's AnthillEngine.
// Structural so an older or newer engine works as long as these stay.
export type EngineLike = {
  members(): string[];
  parent(id: string): string;
  children(id: string): string[];
  calculateReputation(id: string): bigint;
  read: {
    nameOf(args: readonly [string]): Promise<string>;
    sentDagVoteCount(args: readonly [string]): Promise<bigint>;
    sentDagVote(args: readonly [string, bigint]): Promise<readonly [string, bigint, ...unknown[]]>;
  };
};

// sha256 of a canonical description of one community's tree: members sorted by
// id, each with name, parent, children in tree order, sent DAG votes in vote
// order (recipient, weight) and reputation. Order inside a member matters: the
// engine mirrors the contract's storage, and vote/child order changes later
// results. Only strings and arrays, so JSON.stringify is already canonical.
// calculateReputation writes the engine's reputation cache; nothing the engine
// decides reads that cache, so digesting does not change later replay.
export async function digestEngine(engine: EngineLike): Promise<string> {
  const rows: unknown[] = [];
  for (const id of [...engine.members()].sort()) {
    const votes: [string, string][] = [];
    const count = Number(await engine.read.sentDagVoteCount([id]));
    for (let pos = 0; pos < count; pos++) {
      const [recipient, weight] = await engine.read.sentDagVote([id, BigInt(pos)]);
      votes.push([recipient, weight.toString()]);
    }
    rows.push([
      id,
      await engine.read.nameOf([id]),
      engine.parent(id),
      engine.children(id),
      votes,
      engine.calculateReputation(id).toString(),
    ]);
  }
  return createHash("sha256").update(JSON.stringify(rows)).digest("hex");
}

// Throws with a message naming the first problem.
export function parseManifest(json: unknown): Manifest {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    throw new Error("manifest: expected an object");
  }
  const declared = (json as { declared?: unknown }).declared;
  if (!Array.isArray(declared)) throw new Error("manifest: `declared` must be an array");
  return {
    declared: declared.map((d: unknown, i) => {
      const where = `manifest: declared[${i}]`;
      if (typeof d !== "object" || d === null || Array.isArray(d)) throw new Error(`${where} must be an object`);
      const { community, fromEntry, note } = d as Record<string, unknown>;
      if (typeof community !== "string" || community === "") {
        throw new Error(`${where}.community must be a non-empty string`);
      }
      if (typeof fromEntry !== "number" || !Number.isSafeInteger(fromEntry) || fromEntry < 0) {
        throw new Error(`${where}.fromEntry must be a non-negative integer`);
      }
      // A declaration is an explanation for reviewers; an empty one explains nothing.
      if (typeof note !== "string" || note.trim() === "") {
        throw new Error(`${where}.note must say why the behaviour changes`);
      }
      return { community, fromEntry, note };
    }),
  };
}

export function loadManifest(path: string): Manifest {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`manifest: cannot read ${path}: ${errorMessage(e)}`);
  }
  return parseManifest(json);
}

// One point in a community's digest sequence. `error` is set when the entry
// failed to replay (the backend skips such entries; the digest is then the
// community's previous one).
export type DigestRecord = { entry: number; digest: string; error?: string };
export type ReplayResult = { entries: number; communities: Record<string, DigestRecord[]> };

export async function runBehaviourDelta(opts: {
  oldBackendDir: string;
  newBackendDir: string;
  logPath: string;
  manifest?: Manifest;
  timeoutMs?: number;
}): Promise<GateReport & { divergences: Divergence[] }> {
  const fail = (details: string) => ({ gate: GATE, pass: false, details, divergences: [] });

  let manifest: Manifest;
  try {
    manifest = parseManifest(opts.manifest ?? { declared: [] });
  } catch (e) {
    return fail(errorMessage(e));
  }
  if (!existsSync(opts.logPath)) return fail(`no log at ${opts.logPath}`);

  const work = mkdtempSync(join(tmpdir(), "behaviour-delta-"));
  try {
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const [oldRun, newRun] = await Promise.all([
      replayInChild(resolve(opts.oldBackendDir), opts.logPath, join(work, "old"), timeoutMs),
      replayInChild(resolve(opts.newBackendDir), opts.logPath, join(work, "new"), timeoutMs),
    ]);
    // Without both sequences nothing can be compared; that is never a pass,
    // and no manifest can declare it away.
    const problems: string[] = [];
    if ("error" in oldRun) problems.push(`old checkout: ${oldRun.error}`);
    if ("error" in newRun) problems.push(`new checkout: ${newRun.error}`);
    if ("error" in oldRun || "error" in newRun) return fail(`replay failed\n${problems.join("\n")}`);
    if (oldRun.entries !== newRun.entries) {
      return fail(`the checkouts read different entry counts (${oldRun.entries} vs ${newRun.entries})`);
    }

    const divergences = compareReplays(oldRun, newRun);
    const { pass, details } = judge(divergences, manifest, oldRun);
    return { gate: GATE, pass, details, divergences };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// First differing record per community, in community-id order.
export function compareReplays(oldRun: ReplayResult, newRun: ReplayResult): Divergence[] {
  const ids = [...new Set([...Object.keys(oldRun.communities), ...Object.keys(newRun.communities)])].sort();
  const divergences: Divergence[] = [];
  for (const community of ids) {
    const oldRecords = new Map((oldRun.communities[community] ?? []).map((r) => [r.entry, r]));
    const newRecords = new Map((newRun.communities[community] ?? []).map((r) => [r.entry, r]));
    const entries = [...new Set([...oldRecords.keys(), ...newRecords.keys()])].sort((a, b) => a - b);
    let oldLast = "";
    let newLast = "";
    for (const entry of entries) {
      const o = oldRecords.get(entry);
      const n = newRecords.get(entry);
      const error = recordMismatch(o, n);
      if (error !== undefined || o?.digest !== n?.digest) {
        divergences.push({
          community,
          fromEntry: entry,
          oldDigest: o?.digest ?? oldLast,
          newDigest: n?.digest ?? newLast,
          ...(error === undefined ? {} : { error }),
        });
        break;
      }
      oldLast = o?.digest ?? oldLast;
      newLast = n?.digest ?? newLast;
    }
  }
  return divergences;
}

function recordMismatch(o: DigestRecord | undefined, n: DigestRecord | undefined): string | undefined {
  if (o === undefined) return "the new checkout has state here and the old one does not";
  if (n === undefined) return "the old checkout has state here and the new one does not";
  if (o.error === n.error) return undefined;
  if (o.error === undefined) return `the new checkout fails to replay this entry: ${n.error}`;
  if (n.error === undefined) return `the old checkout failed to replay this entry and the new one replays it: ${o.error}`;
  return `the replay fails differently: old: ${o.error}; new: ${n.error}`;
}

function judge(
  divergences: Divergence[],
  manifest: Manifest,
  run: ReplayResult,
): { pass: boolean; details: string } {
  const lines: string[] = [];
  let pass = true;
  for (const d of divergences) {
    // The earliest covering declaration explains the most; any covering one passes.
    const covering = manifest.declared
      .filter((m) => m.community === d.community && m.fromEntry <= d.fromEntry)
      .sort((a, b) => a.fromEntry - b.fromEntry)[0];
    const what = `community ${d.community} diverges from entry ${d.fromEntry}${d.error ? ` (${d.error})` : ""}`;
    if (covering === undefined) {
      pass = false;
      const later = manifest.declared.find((m) => m.community === d.community);
      lines.push(
        `- UNDECLARED: ${what}${later ? `; declared only from entry ${later.fromEntry}, after it starts` : ""}`,
      );
    } else {
      lines.push(`- declared: ${what}; declared from entry ${covering.fromEntry}: ${covering.note}`);
    }
  }
  // Reported, not failed: the manifest is declared per change, and a reviewer
  // should see a stale declaration before it covers someone else's change.
  for (const m of manifest.declared) {
    if (!divergences.some((d) => d.community === m.community)) {
      lines.push(`- declared but not observed: community ${m.community} from entry ${m.fromEntry}`);
    }
  }
  const communities = Object.keys(run.communities).length;
  const head =
    divergences.length === 0
      ? `no behaviour change across ${communities} communities and ${run.entries} log entries`
      : `${divergences.length} of ${communities} communities diverge over ${run.entries} log entries`;
  return { pass, details: [head, ...lines].join("\n") };
}

////////////////////////////////////////////
//// replay in a child process

type ChildOutcome = ReplayResult | { error: string };

function tsxLoaderUrl(): string {
  return pathToFileURL(require.resolve("tsx")).href;
}

function replayInChild(checkoutDir: string, logPath: string, work: string, timeoutMs: number): Promise<ChildOutcome> {
  const dataDir = join(work, "data");
  const home = join(work, "home");
  mkdirSync(dataDir, { recursive: true });
  mkdirSync(home, { recursive: true });
  copyFileSync(logPath, join(dataDir, "log.jsonl"));
  const resultPath = join(work, "result.json");

  return new Promise((done) => {
    let stderr = "";
    let timedOut = false;
    const child = spawn(
      process.execPath,
      ["--import", tsxLoaderUrl(), __filename, "--worker", checkoutDir, dataDir, resultPath],
      {
        cwd: work,
        // Minimal and fixed, so replay cannot depend on the coordinator's
        // environment and the checkout cannot read its secrets from it.
        env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: home, TMPDIR: work },
        stdio: ["ignore", "ignore", "pipe"],
      },
    );
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString()).slice(-STDERR_TAIL);
    });
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    child.on("error", (e) => {
      clearTimeout(timer);
      done({ error: `cannot start the replay: ${e.message}` });
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) return done({ error: `replay timed out after ${timeoutMs} ms` });
      let result: unknown;
      try {
        result = JSON.parse(readFileSync(resultPath, "utf8"));
      } catch {
        const how = signal !== null ? `signal ${signal}` : `exit code ${code}`;
        return done({ error: `replay died (${how}) without a result${stderr ? `\n${stderr.trim()}` : ""}` });
      }
      done(validResult(result));
    });
  });
}

function validResult(result: unknown): ChildOutcome {
  const bad = { error: "the replay wrote a malformed result" };
  if (typeof result !== "object" || result === null) return bad;
  if ("error" in result) return { error: String((result as { error: unknown }).error) };
  const { entries, communities } = result as { entries?: unknown; communities?: unknown };
  if (typeof entries !== "number" || typeof communities !== "object" || communities === null) return bad;
  for (const records of Object.values(communities)) {
    if (!Array.isArray(records)) return bad;
    for (const r of records as unknown[]) {
      const { entry, digest, error } = (r ?? {}) as Record<string, unknown>;
      if (typeof entry !== "number" || typeof digest !== "string") return bad;
      if (error !== undefined && typeof error !== "string") return bad;
    }
  }
  return result as ReplayResult;
}

// What the worker needs from a checkout's src/store.ts and src/offchain.ts.
type StoreLike = { actions: readonly object[]; communityOf(entry: object): string };
type TreeLike = { id: string; engine: EngineLike };
type CommunitiesLike = {
  all(): TreeLike[];
  load(onReplayed: (executed: { tree: TreeLike; entry: object }) => Promise<void>): Promise<void>;
};

// Runs inside the child: replay one checkout and write its digest sequences.
export async function replayCheckout(checkoutDir: string, dataDir: string): Promise<ReplayResult> {
  // Which lines are actions, parsed the way Store reads them, so action k in
  // Store.actions maps back to its line number in the log.
  const lines = readFileSync(join(dataDir, "log.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "");
  const actionLines: number[] = [];
  lines.forEach((line, i) => {
    if ((JSON.parse(line) as { type?: unknown }).type === "action") actionLines.push(i);
  });

  const { Store } = require(join(checkoutDir, "src", "store.ts")) as { Store: new (dir: string) => StoreLike };
  const { Communities } = require(join(checkoutDir, "src", "offchain.ts")) as {
    Communities: new (store: StoreLike) => CommunitiesLike;
  };
  const store = new Store(dataDir);
  if (store.actions.length !== actionLines.length) {
    throw new Error(`Store read ${store.actions.length} actions, the log has ${actionLines.length}`);
  }
  const indexOf = new Map(store.actions.map((entry, k) => [entry, k]));

  const communities: Record<string, DigestRecord[]> = {};
  const lastDigest = new Map<string, string>();
  const record = (community: string, entry: object, digest: string | undefined, error?: string) => {
    const r: DigestRecord = {
      entry: actionLines[indexOf.get(entry) as number] as number,
      digest: digest ?? lastDigest.get(community) ?? "",
    };
    if (error !== undefined) r.error = error;
    (communities[community] ??= []).push(r);
    lastDigest.set(community, r.digest);
  };
  // The replay runs actions in log order and reports each one, by callback or
  // by warning. Any action it passes over without a report is a skip too; it is
  // recorded when the replay moves past it, so it gets the digest of that moment.
  let next = 0;
  const skipUpTo = (k: number) => {
    for (; next < k; next++) {
      const skipped = store.actions[next] as object;
      record(store.communityOf(skipped), skipped, undefined, "skipped without a report");
    }
  };
  const reached = (entry: object) => {
    const k = indexOf.get(entry);
    if (k === undefined) throw new Error("the replay reported an entry that is not in Store.actions");
    skipUpTo(k);
    next = Math.max(next, k + 1);
  };

  // Communities.load skips an action that now fails and only says so through
  // console.warn("replay: ...", entry, error). Restored afterwards, so calling
  // this outside the worker leaves console alone.
  const warn = console.warn;
  console.warn = (...args: unknown[]) => {
    const [message, entry, error] = args;
    if (typeof message !== "string" || !message.startsWith("replay:") || !indexOf.has(entry as object)) return;
    reached(entry as object);
    record(store.communityOf(entry as object), entry as object, undefined, errorMessage(error));
  };
  const communitiesObj = new Communities(store);
  try {
    await communitiesObj.load(async ({ tree, entry }) => {
      reached(entry);
      record(tree.id, entry, await digestEngine(tree.engine));
    });
  } finally {
    console.warn = warn;
  }
  skipUpTo(store.actions.length);
  for (const records of Object.values(communities)) records.sort((a, b) => a.entry - b.entry);

  for (const tree of communitiesObj.all()) {
    (communities[tree.id] ??= []).push({ entry: lines.length, digest: await digestEngine(tree.engine) });
  }
  return { entries: lines.length, communities };
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

if (require.main === module && process.argv[2] === "--worker") {
  const [checkoutDir, dataDir, resultPath] = process.argv.slice(3) as [string, string, string];
  replayCheckout(checkoutDir, dataDir).then(
    (result) => writeFileSync(resultPath, JSON.stringify(result)),
    (e: unknown) => writeFileSync(resultPath, JSON.stringify({ error: errorMessage(e) })),
  );
}
