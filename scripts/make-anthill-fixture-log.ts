// Writes an Anthill backend log.jsonl for the behaviour-delta gate, using the
// backend's own Store and Communities, so the log is exactly what that backend
// would write:
//   1. the seed graph from anthillSnapshot.json, moved to the demo community
//      (as the server does on first start), and the demo's story if the
//      checkout has one (src/demoStory.ts) — leaves, climbs, switched votes;
//   2. the commons, started by a founder, with every action kind;
//   3. a private community joined through invites (invite placement).
//
// CI runs this with the BASE checkout's backend: the log must come from code
// that is already trusted, and the head is then judged against it. Timestamps
// and invite codes differ between runs; entry order and count do not, so the
// entry numbers the gate reports are stable for a given base.
//
//   npx tsx scripts/make-anthill-fixture-log.ts --backend <anthill-backend dir> --out <log.jsonl>
//       [--snapshot <anthillSnapshot.json>]   (default <backend>/anthillSnapshot.json)
//   ANTHILL_BACKEND_DIR may stand in for --backend.

import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { loadBackend, resolveBackendDir } from "../src/adapters/anthill";

const id = (n: number) => `0x${n.toString(16).padStart(40, "0")}`;
const FOUNDER = id(0xc0f0);
// Store stamps entry times itself; this only fills the community records.
const CREATED_AT = "2026-01-01T00:00:00.000Z";

type Body = { fn: string; args?: Record<string, string> };
type Tree = {
  id: string;
  engine: { members(): string[]; children(id: string): string[]; root(): string };
  execute(by: string, body: Body): unknown;
  createAdminInvite(under: string): { code: string };
};
type Communities = {
  load(onReplayed: (executed: unknown) => Promise<void>): Promise<void>;
  get(id: string): Tree | undefined;
  create(founder: { id: string; name: string }, body: unknown): { tree: Tree };
};
type Store = {
  logPath: string;
  setSeed(graph: unknown): void;
  moveCommons(to: object, founder: string): void;
  markMigration(id: string): void;
};

export type FixtureSummary = { logPath: string; entries: number; actions: Record<string, number>; skipped: string[] };

export async function makeAnthillFixtureLog(opts: {
  backendDir?: string;
  outPath: string;
  snapshotPath?: string;
}): Promise<FixtureSummary> {
  const backendDir = resolveBackendDir(opts.backendDir);
  const outPath = resolve(opts.outPath);
  if (existsSync(outPath)) throw new Error(`fixture: ${outPath} exists; refusing to overwrite it`);
  const snapshotPath = opts.snapshotPath ?? join(backendDir, "anthillSnapshot.json");
  const backend = loadBackend(backendDir);
  const graph = (JSON.parse(readFileSync(snapshotPath, "utf8"), backend.bigintReviver) as { graph: unknown }).graph;

  const work = mkdtempSync(join(tmpdir(), "anthill-fixture-"));
  try {
    const store = new backend.Store(work) as Store;
    const fresh = async () => {
      const c = new backend.Communities(store) as unknown as Communities;
      await c.load(async () => {});
      return c;
    };
    const actions: Record<string, number> = {};
    const skipped: string[] = [];
    // An action the backend refuses is left out of the log, as a refused
    // request would be; the summary says which, so a fixture that silently
    // lost its coverage is visible.
    const act = (tree: Tree, by: string, body: Body) => {
      try {
        tree.execute(by, body);
        actions[body.fn] = (actions[body.fn] ?? 0) + 1;
      } catch (e) {
        skipped.push(`${tree.id}: ${by} ${body.fn}: ${(e as Error).message}`);
      }
    };

    // 1. seed, demo, demo story (mirrors offchainServer and its start()).
    store.setSeed(graph);
    store.moveCommons(
      {
        id: "demo",
        name: "Anthill Demo",
        description: "The original Anthill tree.",
        visibility: "public",
        joinPolicy: "invite",
        createdBy: "",
        createdAt: CREATED_AT,
      },
      FOUNDER,
    );
    const storyPath = join(backendDir, "src", "demoStory.ts");
    if (existsSync(storyPath)) {
      const { playDemoStory } = require(storyPath) as {
        playDemoStory(tree: Tree, invite: (under: string) => string, isReal: (id: string) => boolean): number;
      };
      store.markMigration("demo-story-1");
      const demo = (await fresh()).get("demo") as Tree;
      actions["demoStory"] = playDemoStory(demo, (under) => demo.createAdminInvite(under).code, () => false);
    }

    // 2. the commons: every action kind on a fresh tree.
    let communities = await fresh();
    const commons = communities.get("commons") as Tree;
    const [a, b, c, d, e, f] = [1, 2, 3, 4, 5, 6].map((n) => id(0xc000 + n)) as [string, string, string, string, string, string];
    act(commons, FOUNDER, { fn: "joinTreeAsRoot", args: { name: "Founder" } });
    act(commons, a, { fn: "joinTree", args: { name: "Ada", recipient: FOUNDER } });
    act(commons, b, { fn: "joinTree", args: { name: "Bo", recipient: FOUNDER } });
    act(commons, c, { fn: "joinTree", args: { name: "Cy", recipient: a } });
    act(commons, d, { fn: "joinTree", args: { name: "Di", recipient: a } });
    act(commons, e, { fn: "joinTree", args: { name: "Ed", recipient: b } });
    act(commons, f, { fn: "joinTree", args: { name: "Fay", recipient: c } });
    // Cy sends most of his support past Ada to the founder; once Di has left,
    // Ada's reputation rests on that small share and Cy outweighs her.
    act(commons, c, { fn: "addDagVote", args: { recipient: FOUNDER, weight: "7" } });
    act(commons, e, { fn: "addDagVote", args: { recipient: FOUNDER, weight: "3" } });
    act(commons, f, { fn: "addDagVote", args: { recipient: a, weight: "2" } });
    act(commons, f, { fn: "removeDagVote", args: { recipient: a } });
    act(commons, a, { fn: "changeName", args: { name: "Ada L" } });
    act(commons, d, { fn: "leaveTree" });
    act(commons, c, { fn: "switchPositionWithParent" });
    act(commons, e, { fn: "moveTreeVote", args: { recipient: a } });

    // 3. a private community, joined by invite (placed under the inviter, or
    // the first free spot below them).
    communities = await fresh();
    const { tree: club } = communities.create(
      { id: FOUNDER, name: "Founder" },
      { id: "fixture-club", name: "Fixture Club", visibility: "private", joinPolicy: "invite" },
    );
    actions["joinTreeAsRoot"] = (actions["joinTreeAsRoot"] ?? 0) + 1;
    for (const [n, name] of ["Gil", "Hal", "Ivy", "Jo"].entries()) {
      act(club, id(0xc100 + n), { fn: "joinTree", args: { name, invite: club.createAdminInvite(FOUNDER).code } });
    }
    act(club, id(0xc103), { fn: "addDagVote", args: { recipient: FOUNDER, weight: "3" } });

    const entries = readFileSync(store.logPath, "utf8")
      .split("\n")
      .filter((line) => line.trim() !== "").length;
    copyFileSync(store.logPath, outPath);
    return { logPath: outPath, entries, actions, skipped };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function argValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  if (i < 0) return undefined;
  const v = args[i + 1];
  if (v === undefined || v.startsWith("--")) throw new Error(`${flag} needs a value`);
  return v;
}

if (require.main === module) {
  (async () => {
    const args = process.argv.slice(2);
    const outPath = argValue(args, "--out");
    if (outPath === undefined) throw new Error("usage: make-anthill-fixture-log.ts --backend <dir> --out <log.jsonl> [--snapshot <path>]");
    const backendDir = argValue(args, "--backend");
    const snapshotPath = argValue(args, "--snapshot");
    const summary = await makeAnthillFixtureLog({
      outPath,
      ...(backendDir === undefined ? {} : { backendDir }),
      ...(snapshotPath === undefined ? {} : { snapshotPath }),
    });
    console.log(JSON.stringify(summary, null, 2));
  })().catch((e: unknown) => {
    console.error((e as Error).message);
    process.exit(2);
  });
}
