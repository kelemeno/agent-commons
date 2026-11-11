import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import {
  compareReplays,
  digestEngine,
  type EngineLike,
  loadManifest,
  parseManifest,
  type ReplayResult,
  replayCheckout,
  runBehaviourDelta,
} from "../src/gates/behaviourDelta";

const BACKEND = join(__dirname, "..", "..", "anthill-backend");
const id = (n: number) => `0x${n.toString(16).padStart(40, "0")}`;

let root: string;
let logPath: string; // seed (demo) + an "alpha" community with joins and votes
let seedOnlyLog: string; // seed and commonsMoved, no actions
let lines: { type: string; community?: string; action?: { fn: string } }[];
const checkouts: Record<string, string> = {};

// A copy of the backend's src with replacements applied to one file.
function checkout(name: string, file?: string, edits: [string, string][] = []): string {
  const dir = join(root, name);
  cpSync(join(BACKEND, "src"), join(dir, "src"), { recursive: true });
  if (file !== undefined) {
    const path = join(dir, "src", file);
    let text = readFileSync(path, "utf8");
    for (const [from, to] of edits) {
      assert.ok(text.includes(from), `fixture edit not applicable: ${from}`);
      text = text.replace(from, to);
    }
    writeFileSync(path, text);
  }
  return dir;
}

// Entry index of the first action of `community` (optionally of one fn).
function firstAction(community: string, fn?: string): number {
  const i = lines.findIndex((l) => l.type === "action" && l.community === community && (fn === undefined || l.action?.fn === fn));
  assert.ok(i >= 0);
  return i;
}

before(async () => {
  root = mkdtempSync(join(tmpdir(), "behaviour-delta-test-"));
  // Build the fixture with the backend's own APIs so the log is exactly what
  // the backend writes.
  const { Store, bigintReviver } = require(join(BACKEND, "src", "store.ts"));
  const { Communities } = require(join(BACKEND, "src", "offchain.ts"));
  const graph = JSON.parse(readFileSync(join(BACKEND, "anthillSnapshot.json"), "utf8"), bigintReviver).graph;
  const demo = {
    id: "demo",
    name: "Demo",
    description: "",
    visibility: "public",
    joinPolicy: "open",
    createdBy: "",
    createdAt: "2026-01-01T00:00:00.000Z",
  };

  const seedOnly = join(root, "seed-only");
  const s0 = new Store(seedOnly);
  s0.setSeed(graph);
  s0.moveCommons(demo, id(0xf00));
  seedOnlyLog = s0.logPath;

  const store = new Store(join(root, "data"));
  store.setSeed(graph);
  store.moveCommons(demo, id(0xf00));
  const communities = new Communities(store);
  await communities.load(async () => {});
  // demo: only tree moves, so a change to DAG voting leaves it alone
  const demoTree = communities.get("demo");
  const spot = demoTree.engine.members().sort().find((m: string) => demoTree.engine.children(m).length < 2);
  demoTree.execute(id(0xd1), { fn: "joinTree", args: { name: "Dee", recipient: spot } });
  demoTree.execute(id(0xd2), { fn: "joinTree", args: { name: "Dum", recipient: id(0xd1) } });

  const founder = { id: id(0xa1), name: "Ada" };
  const { tree: alpha } = communities.create(founder, {
    id: "alpha",
    name: "Alpha",
    visibility: "public",
    joinPolicy: "open",
  });
  alpha.execute(id(0xa2), { fn: "joinTree", args: { name: "Bo", recipient: id(0xa1) } });
  alpha.execute(id(0xa3), { fn: "joinTree", args: { name: "Cy", recipient: id(0xa1) } });
  alpha.execute(id(0xa4), { fn: "joinTree", args: { name: "Di", recipient: id(0xa2) } });
  alpha.execute(id(0xa4), { fn: "addDagVote", args: { recipient: id(0xa1), weight: "3" } });
  alpha.execute(id(0xa5), { fn: "joinTree", args: { name: "Ed", recipient: id(0xa3) } });
  alpha.execute(id(0xa5), { fn: "addDagVote", args: { recipient: id(0xa1), weight: "1" } });
  // An entry that fails on replay in every version: the backend skips it.
  store.appendAction("alpha", id(0xa3), { fn: "addDagVote", args: { recipient: id(0xbad), weight: "1" } });
  alpha.execute(id(0xa1), { fn: "changeName", args: { name: "Ada L" } });
  logPath = store.logPath;
  lines = readFileSync(logPath, "utf8")
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((l) => JSON.parse(l));

  checkouts.same = checkout("same");
  checkouts.doubled = checkout("doubled", "engine.ts", [
    ["voterReputation += 10n ** decimalPoint;", "voterReputation += 2n * 10n ** decimalPoint;"],
  ]);
  checkouts.heavyVotesRevert = checkout("no-dag-votes", "engine.ts", [
    // joinTree's own weight-1 vote still works; explicit heavier votes now revert
    ['check(votable && !voted, "A aDV 2");', 'check(votable && !voted && weight === 1n, "A aDV 2");'],
  ]);
  // A pure refactor: same behaviour, different code.
  checkouts.refactor = checkout("refactor", "engine.ts", [
    ["voterReputation += 10n ** decimalPoint;", "voterReputation = voterReputation + 10n ** 18n;"],
  ]);
  checkouts.silentSkip = checkout("silent-skip", "offchain.ts", [
    ['console.warn("replay: skipping action that now fails", entry, e);', ""],
  ]);
  checkouts.hangs = checkout("hangs", "store.ts", [["export class Store {", "while (true) {}\nexport class Store {"]]);
  checkouts.storeThrows = checkout("store-throws", "store.ts", [
    ["mkdirSync(dir, { recursive: true });", 'throw new Error("boom");'],
  ]);
  checkouts.exits = checkout("exits", "offchain.ts", [["export class ActionError", "process.exit(0);\nexport class ActionError"]]);
  checkouts.dropsAlpha = checkout("drops-alpha", "offchain.ts", [
    ["for (const { id } of store.communities()) {", 'for (const { id } of store.communities().filter((c) => c.id !== "alpha")) {'],
  ]);
});

after(() => rmSync(root, { recursive: true, force: true }));

describe("runBehaviourDelta on the real backend", () => {
  test("identical code passes with no divergences", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.same!, logPath });
    assert.equal(r.gate, "behaviourDelta");
    assert.equal(r.pass, true, r.details);
    assert.deepEqual(r.divergences, []);
    assert.match(r.details, /no behaviour change across 3 communities/);
  });

  test("a refactor that keeps behaviour passes", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.refactor!, logPath });
    assert.equal(r.pass, true, r.details);
  });

  test("an entry that fails on both sides is recorded as a skip and is not a divergence", async () => {
    const bad = lines.findIndex((l) => l.type === "action" && JSON.stringify(l).includes(id(0xbad)));
    assert.ok(bad > 0);
    const data = mkdtempSync(join(tmpdir(), "behaviour-delta-direct-"));
    const warn = console.warn;
    try {
      cpSync(logPath, join(data, "log.jsonl"));
      const result = await replayCheckout(checkouts.same!, data);
      assert.equal(console.warn, warn, "console.warn restored");
      assert.equal(result.entries, lines.length);
      const alpha = result.communities.alpha ?? [];
      const skipped = alpha.find((r) => r.entry === bad);
      assert.ok(skipped?.error, "the bad entry is recorded with its error");
      const before = alpha[alpha.indexOf(skipped) - 1];
      assert.equal(skipped.digest, before?.digest, "a skip leaves the digest unchanged");
      assert.deepEqual(
        alpha.map((r) => r.entry),
        [...lines.flatMap((l, i) => (l.type === "action" && l.community === "alpha" ? [i] : [])), lines.length],
      );
    } finally {
      rmSync(data, { recursive: true, force: true });
    }
    const r = await runBehaviourDelta({ oldBackendDir: checkouts.same!, newBackendDir: BACKEND, logPath });
    assert.equal(r.pass, true, r.details);
  });

  test("a reputation change diverges every community from its first action", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.doubled!, logPath });
    assert.equal(r.pass, false);
    assert.deepEqual(
      r.divergences.map((d) => [d.community, d.fromEntry]),
      [
        ["alpha", firstAction("alpha")],
        ["demo", firstAction("demo")],
      ],
    );
    for (const d of r.divergences) {
      assert.match(d.oldDigest, /^[0-9a-f]{64}$/);
      assert.match(d.newDigest, /^[0-9a-f]{64}$/);
      assert.notEqual(d.oldDigest, d.newDigest);
      assert.equal(d.error, undefined);
    }
    assert.match(r.details, /UNDECLARED: community alpha/);
    assert.match(r.details, /UNDECLARED: community demo/);
  });

  test("declared divergences pass; a declaration starting later than the divergence fails", async () => {
    const alpha = firstAction("alpha");
    const demo = firstAction("demo");
    const declared = (a: number, d: number) => ({
      declared: [
        { community: "alpha", fromEntry: a, note: "reputation doubled on purpose" },
        { community: "demo", fromEntry: d, note: "reputation doubled on purpose" },
      ],
    });
    const run = (manifest: ReturnType<typeof declared>) =>
      runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.doubled!, logPath, manifest });

    const exact = await run(declared(alpha, demo));
    assert.equal(exact.pass, true, exact.details);
    assert.equal(exact.divergences.length, 2);
    assert.match(exact.details, /declared: community alpha .*reputation doubled on purpose/);

    const earlier = await run(declared(0, 0));
    assert.equal(earlier.pass, true, earlier.details);

    const late = await run(declared(alpha + 1, demo));
    assert.equal(late.pass, false);
    assert.match(late.details, new RegExp(`UNDECLARED: community alpha diverges from entry ${alpha}.*declared only from entry ${alpha + 1}`));
    assert.match(late.details, /declared: community demo/);
  });

  test("a declaration for another community does not cover a divergence", async () => {
    const r = await runBehaviourDelta({
      oldBackendDir: BACKEND,
      newBackendDir: checkouts.doubled!,
      logPath,
      manifest: { declared: [{ community: "alpha", fromEntry: 0, note: "only alpha" }] },
    });
    assert.equal(r.pass, false);
    assert.match(r.details, /UNDECLARED: community demo/);
  });

  test("a new revert is reported at the first entry it hits, only in the community it touches", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.heavyVotesRevert!, logPath });
    assert.equal(r.pass, false);
    assert.equal(r.divergences.length, 1);
    const [d] = r.divergences;
    assert.equal(d?.community, "alpha");
    assert.equal(d?.fromEntry, firstAction("alpha", "addDagVote"));
    assert.match(d?.error ?? "", /new checkout fails to replay this entry: A aDV 2/);
    // the new side did not change state, so its digest is the previous one
    assert.match(d?.newDigest ?? "", /^[0-9a-f]{64}$/);
  });

  test("the reverse direction (old reverted, new replays) is a divergence too", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: checkouts.heavyVotesRevert!, newBackendDir: BACKEND, logPath });
    assert.equal(r.pass, false);
    assert.match(r.divergences[0]?.error ?? "", /old checkout failed to replay this entry/);
  });

  test("a skip the replay does not report is still caught", async () => {
    const bad = lines.findIndex((l) => l.type === "action" && JSON.stringify(l).includes(id(0xbad)));
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.silentSkip!, logPath });
    assert.equal(r.pass, false);
    assert.deepEqual(
      r.divergences.map((d) => [d.community, d.fromEntry]),
      [["alpha", bad]],
    );
    assert.match(r.divergences[0]?.error ?? "", /fails differently: old: .+; new: skipped without a report/);
    assert.equal(r.divergences[0]?.oldDigest, r.divergences[0]?.newDigest);
  });

  test("a community the new code no longer loads diverges", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.dropsAlpha!, logPath });
    assert.equal(r.pass, false);
    assert.deepEqual(
      r.divergences.map((d) => d.community),
      ["alpha"],
    );
    assert.equal(r.divergences[0]?.fromEntry, firstAction("alpha"));
    assert.match(r.divergences[0]?.error ?? "", /new checkout fails to replay this entry: no such community/);
  });

  test("a seed-only community is compared through its final digest", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.doubled!, logPath: seedOnlyLog });
    assert.equal(r.pass, false);
    assert.deepEqual(
      r.divergences.map((d) => [d.community, d.fromEntry]),
      [["demo", 2]], // two entries: seed, commonsMoved; the final digest sits at 2
    );
    const same = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.same!, logPath: seedOnlyLog });
    assert.equal(same.pass, true, same.details);
  });

  test("unused declarations are reported but do not fail", async () => {
    const r = await runBehaviourDelta({
      oldBackendDir: BACKEND,
      newBackendDir: checkouts.same!,
      logPath,
      manifest: { declared: [{ community: "alpha", fromEntry: 3, note: "stale" }] },
    });
    assert.equal(r.pass, true);
    assert.match(r.details, /declared but not observed: community alpha from entry 3/);
  });
});

describe("runBehaviourDelta failures that no manifest can excuse", () => {
  const everything = { declared: [{ community: "*", fromEntry: 0, note: "x" }] };

  test("a checkout that hangs times out", async () => {
    const r = await runBehaviourDelta({
      oldBackendDir: BACKEND,
      newBackendDir: checkouts.hangs!,
      logPath,
      manifest: everything,
      timeoutMs: 3000,
    });
    assert.equal(r.pass, false);
    assert.match(r.details, /new checkout: replay timed out/);
  });

  test("a checkout whose Store throws fails", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: checkouts.storeThrows!, newBackendDir: BACKEND, logPath });
    assert.equal(r.pass, false);
    assert.match(r.details, /old checkout: boom/);
    assert.deepEqual(r.divergences, []);
  });

  test("a checkout that exits early without a result fails", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: checkouts.exits!, logPath });
    assert.equal(r.pass, false);
    assert.match(r.details, /new checkout: replay died \(exit code 0\) without a result/);
  });

  test("a missing checkout fails", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: join(root, "nope"), logPath });
    assert.equal(r.pass, false);
    assert.match(r.details, /new checkout: .*Cannot find module/);
  });

  test("a missing log fails", async () => {
    const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: BACKEND, logPath: join(root, "none.jsonl") });
    assert.equal(r.pass, false);
    assert.match(r.details, /no log/);
  });

  test("a malformed manifest fails", async () => {
    const r = await runBehaviourDelta({
      oldBackendDir: BACKEND,
      newBackendDir: BACKEND,
      logPath,
      manifest: { declared: [{ community: "alpha", fromEntry: -1, note: "x" }] },
    });
    assert.equal(r.pass, false);
    assert.match(r.details, /fromEntry must be a non-negative integer/);
  });

  test("the child does not see the coordinator's environment", async () => {
    // a checkout that writes its environment into the log copy's directory
    const dir = checkout("env-spy", "store.ts", [
      ["mkdirSync(dir, { recursive: true });", "mkdirSync(dir, { recursive: true }); if (process.env.COMMONS_SECRET) throw new Error('leaked ' + process.env.COMMONS_SECRET);"],
    ]);
    process.env.COMMONS_SECRET = "hunter2";
    try {
      const r = await runBehaviourDelta({ oldBackendDir: BACKEND, newBackendDir: dir, logPath });
      assert.equal(r.pass, true, r.details);
    } finally {
      delete process.env.COMMONS_SECRET;
    }
  });
});

describe("manifest", () => {
  test("parses a valid manifest", () => {
    const m = { declared: [{ community: "demo", fromEntry: 4, note: "fix rounding" }] };
    assert.deepEqual(parseManifest(m), m);
    assert.deepEqual(parseManifest({ declared: [] }), { declared: [] });
  });

  test("rejects bad shapes", () => {
    const bad: [unknown, RegExp][] = [
      [null, /expected an object/],
      [[], /expected an object/],
      [{}, /`declared` must be an array/],
      [{ declared: {} }, /`declared` must be an array/],
      [{ declared: [3] }, /declared\[0\] must be an object/],
      [{ declared: [{ fromEntry: 1, note: "n" }] }, /community must be a non-empty string/],
      [{ declared: [{ community: "", fromEntry: 1, note: "n" }] }, /community/],
      [{ declared: [{ community: "a", fromEntry: "1", note: "n" }] }, /fromEntry/],
      [{ declared: [{ community: "a", fromEntry: 1.5, note: "n" }] }, /fromEntry/],
      [{ declared: [{ community: "a", fromEntry: Number.POSITIVE_INFINITY, note: "n" }] }, /fromEntry/],
      [{ declared: [{ community: "a", fromEntry: 1, note: "  " }] }, /note must say why/],
      [{ declared: [{ community: "a", fromEntry: 1, note: "ok" }, { community: "b", fromEntry: 1 }] }, /declared\[1\]\.note/],
    ];
    for (const [json, message] of bad) assert.throws(() => parseManifest(json), message, JSON.stringify(json));
  });

  test("loadManifest reads and validates a file", () => {
    const dir = mkdtempSync(join(tmpdir(), "behaviour-delta-manifest-"));
    try {
      const good = join(dir, "good.json");
      writeFileSync(good, JSON.stringify({ declared: [{ community: "c", fromEntry: 0, note: "n" }] }));
      assert.deepEqual(loadManifest(good).declared[0], { community: "c", fromEntry: 0, note: "n" });
      const broken = join(dir, "broken.json");
      writeFileSync(broken, "{");
      assert.throws(() => loadManifest(broken), /cannot read/);
      assert.throws(() => loadManifest(join(dir, "missing.json")), /cannot read/);
      const wrong = join(dir, "wrong.json");
      writeFileSync(wrong, JSON.stringify({ declared: [{ community: "c" }] }));
      assert.throws(() => loadManifest(wrong), /fromEntry/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("digestEngine", () => {
  type Node = { name: string; parent: string; children: string[]; votes: [string, bigint][]; rep: bigint };
  const stub = (nodes: Record<string, Node>, order = Object.keys(nodes)): EngineLike => {
    const at = (i: string) => nodes[i] as Node;
    return {
      members: () => order,
      parent: (i) => at(i).parent,
      children: (i) => at(i).children,
      calculateReputation: (i) => at(i).rep,
      read: {
        nameOf: async ([i]) => at(i).name,
        sentDagVoteCount: async ([i]) => BigInt(at(i).votes.length),
        sentDagVote: async ([i, pos]) => {
          const v = at(i).votes[Number(pos)] as [string, bigint];
          return [v[0], v[1], 0n, 0n] as const;
        },
      },
    };
  };
  const base = (): Record<string, Node> => ({
    r: { name: "R", parent: "0x1", children: ["a", "b"], votes: [], rep: 10n },
    a: { name: "A", parent: "r", children: [], votes: [["r", 2n]], rep: 1n },
    b: { name: "B", parent: "r", children: [], votes: [["r", 1n], ["a", 1n]], rep: 1n },
  });

  test("is independent of member enumeration order", async () => {
    assert.equal(await digestEngine(stub(base())), await digestEngine(stub(base(), ["b", "r", "a"])));
  });

  test("changes with every digested field", async () => {
    const d0 = await digestEngine(stub(base()));
    const variants: ((n: Record<string, Node>) => void)[] = [
      (n) => void (n.a!.name = "A2"),
      (n) => void (n.a!.parent = "b"),
      (n) => void (n.r!.children = ["b", "a"]), // child order is state
      (n) => void (n.a!.votes = [["r", 3n]]),
      (n) => void (n.b!.votes = [["a", 1n], ["r", 1n]]), // vote order is state
      (n) => void (n.r!.rep = 11n),
    ];
    for (const change of variants) {
      const n = base();
      change(n);
      assert.notEqual(await digestEngine(stub(n)), d0, change.toString());
    }
  });

  test("an empty tree has a stable digest", async () => {
    assert.equal(await digestEngine(stub({})), await digestEngine(stub({})));
    assert.match(await digestEngine(stub({})), /^[0-9a-f]{64}$/);
  });
});

describe("compareReplays", () => {
  const run = (communities: ReplayResult["communities"]): ReplayResult => ({ entries: 10, communities });

  test("reports the first difference only", () => {
    const d = compareReplays(
      run({ c: [{ entry: 1, digest: "a" }, { entry: 2, digest: "b" }, { entry: 3, digest: "c" }] }),
      run({ c: [{ entry: 1, digest: "a" }, { entry: 2, digest: "x" }, { entry: 3, digest: "y" }] }),
    );
    assert.deepEqual(d, [{ community: "c", fromEntry: 2, oldDigest: "b", newDigest: "x" }]);
  });

  test("a community or entry present on one side only diverges", () => {
    const d = compareReplays(
      run({ c: [{ entry: 1, digest: "a" }], gone: [{ entry: 4, digest: "g" }] }),
      run({ c: [{ entry: 1, digest: "a" }, { entry: 5, digest: "z" }], fresh: [{ entry: 6, digest: "f" }] }),
    );
    assert.deepEqual(
      d.map((x) => [x.community, x.fromEntry, x.oldDigest, x.newDigest]),
      [
        ["c", 5, "a", "z"],
        ["fresh", 6, "", "f"],
        ["gone", 4, "g", ""],
      ],
    );
    assert.match(d[0]?.error ?? "", /new checkout has state here/);
    assert.match(d[2]?.error ?? "", /old checkout has state here/);
  });

  test("same digest but different replay errors diverge", () => {
    const d = compareReplays(
      run({ c: [{ entry: 1, digest: "a", error: "A aDV 2" }] }),
      run({ c: [{ entry: 1, digest: "a", error: "A rDV 2" }] }),
    );
    assert.match(d[0]?.error ?? "", /fails differently: old: A aDV 2; new: A rDV 2/);
    assert.deepEqual(
      compareReplays(run({ c: [{ entry: 1, digest: "a", error: "e" }] }), run({ c: [{ entry: 1, digest: "a", error: "e" }] })),
      [],
    );
  });
});
