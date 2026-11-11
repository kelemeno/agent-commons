import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { AnthillEngine, type SeedGraph } from "../../anthill-backend/src/engine";
import { bigintReviver } from "../../anthill-backend/src/store";
import {
  type EngineLike,
  reputationPoints,
  treeFromEngine,
  treeFromParents,
  treeFromSnapshot,
  VIRTUAL_ROOT,
} from "../src/tree";

const SNAPSHOT_PATH = join(__dirname, "..", "..", "anthill-backend", "anthillSnapshot.json");
const snapshotText = readFileSync(SNAPSHOT_PATH, "utf8");

//        r
//      /   \
//     a     b
//    / \     \
//   c   d     e
//   |
//   f
const sample = { r: null, a: "r", b: "r", c: "a", d: "a", e: "b", f: "c" };

// Brute-force reference: walk both ancestries to the root and find the LCA.
function referenceDistance(parents: Record<string, string | null>, a: string, b: string): number {
  const chain = (x: string) => {
    const out = [x];
    for (let p = parents[x]; p !== null && p !== undefined; p = parents[p]) out.push(p);
    return out;
  };
  const ca = chain(a);
  const cb = chain(b);
  for (let i = 0; i < ca.length; i++) {
    const j = cb.indexOf(ca[i] as string);
    if (j !== -1) return i + j;
  }
  throw new Error("no common ancestor");
}

test("treeFromParents: structure queries", () => {
  const t = treeFromParents(sample, { a: 5, f: 2 });
  assert.equal(t.root(), "r");
  assert.equal(t.parent("r"), null);
  assert.equal(t.parent("f"), "c");
  assert.deepEqual(t.children("r"), ["a", "b"]);
  assert.deepEqual(t.children("a"), ["c", "d"]);
  assert.deepEqual(t.children("f"), []);
  assert.equal(t.depth("r"), 0);
  assert.equal(t.depth("a"), 1);
  assert.equal(t.depth("f"), 3);
  assert.deepEqual(t.members(), ["a", "b", "c", "d", "e", "f", "r"]);
  assert.equal(t.has("e"), true);
  assert.equal(t.has("z"), false);
  assert.equal(t.reputation("a"), 5);
  assert.equal(t.reputation("r"), 0);
  assert.equal(t.reputation("unknown"), 0);
});

test("treeFromParents: distances", () => {
  const t = treeFromParents(sample);
  assert.equal(t.distance("f", "f"), 0);
  assert.equal(t.distance("a", "r"), 1);
  assert.equal(t.distance("r", "a"), 1);
  assert.equal(t.distance("c", "d"), 2); // siblings
  assert.equal(t.distance("f", "d"), 3);
  assert.equal(t.distance("f", "e"), 5);
  assert.equal(t.distance("e", "f"), 5);
  assert.equal(t.distance("f", "r"), 3);
  for (const a of t.members()) {
    for (const b of t.members()) {
      assert.equal(t.distance(a, b), referenceDistance(sample, a, b), `${a}-${b}`);
      assert.equal(t.distance(a, b), t.distance(b, a));
    }
  }
});

test("treeFromParents: single-member tree", () => {
  const t = treeFromParents({ only: null });
  assert.equal(t.root(), "only");
  assert.deepEqual(t.members(), ["only"]);
  assert.equal(t.distance("only", "only"), 0);
  assert.equal(t.depth("only"), 0);
});

test("treeFromParents: deep chain and random trees match the reference", () => {
  const chain: Record<string, string | null> = { n0: null };
  for (let i = 1; i < 2000; i++) chain[`n${i}`] = `n${i - 1}`;
  const t = treeFromParents(chain);
  assert.equal(t.depth("n1999"), 1999);
  assert.equal(t.distance("n1999", "n0"), 1999);
  assert.equal(t.distance("n500", "n1500"), 1000);

  // Deterministic pseudo-random trees (LCG) so the test needs no entropy.
  let seed = 12345;
  const next = (n: number) => {
    seed = (seed * 1103515245 + 12345) % 2 ** 31;
    return seed % n;
  };
  for (let round = 0; round < 20; round++) {
    const parents: Record<string, string | null> = { x0: null };
    const size = 2 + next(60);
    for (let i = 1; i < size; i++) parents[`x${i}`] = `x${next(i)}`;
    const tree = treeFromParents(parents);
    for (let k = 0; k < 50; k++) {
      const a = `x${next(size)}`;
      const b = `x${next(size)}`;
      assert.equal(tree.distance(a, b), referenceDistance(parents, a, b));
    }
  }
});

test("treeFromParents: member and child order does not depend on input order", () => {
  const reversed = Object.fromEntries(Object.entries(sample).reverse());
  const a = treeFromParents(sample);
  const b = treeFromParents(reversed);
  assert.deepEqual(a.members(), b.members());
  for (const id of a.members()) assert.deepEqual(a.children(id), b.children(id));
});

test("treeFromParents: rejects invalid trees with clear messages", () => {
  assert.throws(() => treeFromParents({}), /no members/);
  assert.throws(() => treeFromParents({ a: null, b: null }), /more than one root: a, b/);
  assert.throws(() => treeFromParents({ a: "b", b: "a" }), /no root/);
  assert.throws(() => treeFromParents({ r: null, a: "ghost" }), /parent ghost of a is not a member/);
  assert.throws(() => treeFromParents({ r: null, a: "a" }), /own parent/);
  // A cycle beside a valid root: one root, all parents known, yet unreachable.
  assert.throws(() => treeFromParents({ r: null, x: "y", y: "z", z: "x" }), /cycle: x, y, z cannot reach the root r/);
  // A subtree hanging off a cycle is also unreachable.
  assert.throws(() => treeFromParents({ r: null, x: "y", y: "x", leaf: "x" }), /cycle: leaf, x, y/);
  assert.throws(() => treeFromParents({ r: null, a: 7 as unknown as string }), /must be a string or null/);
  assert.throws(() => treeFromParents({ r: null }, { r: Number.NaN }), /finite number/);
  assert.throws(() => treeFromParents({ r: null }, { r: Infinity }), /finite number/);
});

test("treeFromParents: structural queries on unknown ids throw rather than guess", () => {
  const t = treeFromParents(sample);
  assert.throws(() => t.parent("z"), /unknown member z/);
  assert.throws(() => t.children("z"), /unknown member z/);
  assert.throws(() => t.depth("z"), /unknown member z/);
  assert.throws(() => t.distance("a", "z"), /unknown member z/);
  assert.throws(() => t.distance("z", "a"), /unknown member z/);
});

test("treeFromParents: ids that collide with Object.prototype are ordinary members", () => {
  const parents = JSON.parse('{"__proto__": null, "constructor": "__proto__", "toString": "constructor"}');
  const t = treeFromParents(parents);
  assert.equal(t.root(), "__proto__");
  assert.equal(t.distance("toString", "__proto__"), 2);
  assert.equal(t.has("hasOwnProperty"), false);
  assert.equal(t.reputation("hasOwnProperty"), 0);
});

test("treeFromParents: the view is a frozen copy", () => {
  const parents: Record<string, string | null> = { r: null, a: "r" };
  const rep: Record<string, number> = { a: 3 };
  const t = treeFromParents(parents, rep);
  parents["b"] = "r";
  rep["a"] = 1000;
  t.members().push("intruder");
  t.children("r").push("intruder");
  assert.deepEqual(t.members(), ["a", "r"]);
  assert.deepEqual(t.children("r"), ["a"]);
  assert.equal(t.reputation("a"), 3);
  assert.equal(t.has("b"), false);
});

test("reputationPoints floors 18-decimal values", () => {
  assert.equal(reputationPoints(0n), 0);
  assert.equal(reputationPoints(10n ** 18n - 1n), 0);
  assert.equal(reputationPoints(10n ** 18n), 1);
  assert.equal(reputationPoints(62999999999999999970n), 62);
  assert.equal(reputationPoints(-1n), -1);
  assert.equal(reputationPoints(-(10n ** 18n)), -1);
});

// A hand-built snapshot in the file's format.
type MiniNode = { id: string; sentTreeVote: string; recTreeVotes: string[]; [field: string]: unknown };
function miniSnapshot(): { graph: { rootId: string; dict: Record<string, MiniNode> }; ids: { A: string; B: string; R: string } } {
  const big = (s: string) => ({ __bigint__: s });
  const A = "0x00000000000000000000000000000000000000aa";
  const B = "0x00000000000000000000000000000000000000bb";
  const R = "0x0000000000000000000000000000000000000002";
  return {
    graph: {
      rootId: R,
      dict: {
        [VIRTUAL_ROOT]: { id: VIRTUAL_ROOT, sentTreeVote: VIRTUAL_ROOT, recTreeVotes: [R], reputation: big("0") },
        [R]: { id: R, sentTreeVote: VIRTUAL_ROOT, recTreeVotes: [B, A], currentRep: big("3500000000000000000") },
        [A]: { id: A, sentTreeVote: R, recTreeVotes: [], reputation: big("1999999999999999999") },
        [B]: { id: B, sentTreeVote: R, recTreeVotes: [] },
      },
    },
    ids: { A, B, R },
  };
}

test("treeFromSnapshot: virtual node excluded, reputation floored", () => {
  const { graph, ids } = miniSnapshot();
  const t = treeFromSnapshot({ graph });
  assert.equal(t.root(), ids.R);
  assert.equal(t.has(VIRTUAL_ROOT), false);
  assert.equal(t.parent(ids.R), null);
  assert.deepEqual(t.members(), [ids.R, ids.A, ids.B]);
  assert.deepEqual(t.children(ids.R), [ids.A, ids.B]);
  assert.equal(t.distance(ids.A, ids.B), 2);
  assert.equal(t.reputation(ids.R), 3); // from currentRep
  assert.equal(t.reputation(ids.A), 1); // reputation preferred, floored
  assert.equal(t.reputation(ids.B), 0); // absent
});

test("treeFromSnapshot: accepts text, parsed and revived forms; lowercases ids", () => {
  const { graph, ids } = miniSnapshot();
  const text = JSON.stringify({ graph });
  const fromText = treeFromSnapshot(text);
  const fromRevived = treeFromSnapshot(JSON.parse(text, bigintReviver));
  assert.deepEqual(fromText.members(), fromRevived.members());
  assert.equal(fromRevived.reputation(ids.R), 3);

  const upper = treeFromSnapshot(text.replace(/0x00000000000000000000000000000000000000aa/g, "0x00000000000000000000000000000000000000AA"));
  assert.equal(upper.has(ids.A), true);
});

test("treeFromSnapshot: skips addresses that left the tree", () => {
  const { graph, ids } = miniSnapshot();
  const gone = "0x00000000000000000000000000000000000000cc";
  graph.dict[gone] = {
    id: gone,
    sentTreeVote: "0x0000000000000000000000000000000000000000",
    recTreeVotes: [],
  };
  const t = treeFromSnapshot({ graph });
  assert.equal(t.has(gone), false);
  assert.equal(t.members().length, 3);
  assert.equal(t.has(ids.A), true);
});

test("treeFromSnapshot: rejects corrupt snapshots", () => {
  assert.throws(() => treeFromSnapshot({}), /\{graph: \{rootId, dict\}\}/);
  assert.throws(() => treeFromSnapshot("not json"), SyntaxError);

  const twoRoots = miniSnapshot();
  twoRoots.graph.dict[twoRoots.ids.A]!.sentTreeVote = VIRTUAL_ROOT;
  assert.throws(() => treeFromSnapshot(twoRoots), /more than one root/);

  const wrongRoot = miniSnapshot();
  wrongRoot.graph.rootId = wrongRoot.ids.A;
  assert.throws(() => treeFromSnapshot(wrongRoot), /rootId .* but the tree's root is/);

  const virtualRoot = miniSnapshot();
  virtualRoot.graph.rootId = VIRTUAL_ROOT;
  assert.throws(() => treeFromSnapshot(virtualRoot), /virtual node/);

  // Claims a child that points elsewhere: the two copies of the edge disagree.
  const forged = miniSnapshot();
  forged.graph.dict[forged.ids.A]!.recTreeVotes = [forged.ids.B];
  assert.throws(() => treeFromSnapshot(forged), /recTreeVotes of .* disagree/);

  // Omits a real child.
  const hidden = miniSnapshot();
  hidden.graph.dict[hidden.ids.R]!.recTreeVotes = [hidden.ids.A];
  assert.throws(() => treeFromSnapshot(hidden), /recTreeVotes of .* disagree/);

  const unknownParent = miniSnapshot();
  unknownParent.graph.dict[unknownParent.ids.A]!.sentTreeVote = "0x00000000000000000000000000000000000000ff";
  assert.throws(() => treeFromSnapshot(unknownParent), /is not a member/);

  const cycle = miniSnapshot();
  cycle.graph.dict[cycle.ids.A]!.sentTreeVote = cycle.ids.B;
  cycle.graph.dict[cycle.ids.B]!.sentTreeVote = cycle.ids.A;
  assert.throws(() => treeFromSnapshot(cycle), /cycle/);

  const badRep = miniSnapshot();
  badRep.graph.dict[badRep.ids.B]!["currentRep"] = { __bigint__: "1e18" };
  assert.throws(() => treeFromSnapshot(badRep), /not a bigint/);

  const dup = miniSnapshot();
  dup.graph.dict["copy"] = { ...dup.graph.dict[dup.ids.B]! };
  assert.throws(() => treeFromSnapshot(dup), /lists .* twice/);
});

test("treeFromSnapshot: the real anthillSnapshot.json", () => {
  const raw = JSON.parse(snapshotText);
  const t = treeFromSnapshot(snapshotText);
  const dict = raw.graph.dict as Record<string, { sentTreeVote: string; depth: number }>;
  assert.equal(t.root(), raw.graph.rootId);
  assert.equal(t.members().length, Object.keys(dict).length - 1);
  assert.equal(t.has(VIRTUAL_ROOT), false);
  for (const id of t.members()) {
    const node = dict[id]!;
    assert.equal(t.parent(id), node.sentTreeVote === VIRTUAL_ROOT ? null : node.sentTreeVote);
    assert.equal(t.depth(id), node.depth, `depth of ${id}`); // the crawler records depth too
  }
  assert.equal(t.reputation(raw.graph.rootId), 62);
});

function loadEngine(): AnthillEngine {
  const graph = JSON.parse(snapshotText, bigintReviver).graph as SeedGraph;
  const engine = new AnthillEngine();
  engine.loadFromGraph(graph);
  return engine;
}

test("treeFromEngine and treeFromSnapshot agree on the real snapshot", () => {
  const fromEngine = treeFromEngine(loadEngine());
  const fromSnapshot = treeFromSnapshot(snapshotText);
  assert.equal(fromEngine.root(), fromSnapshot.root());
  assert.deepEqual(fromEngine.members(), fromSnapshot.members());
  const members = fromSnapshot.members();
  for (const id of members) {
    assert.equal(fromEngine.parent(id), fromSnapshot.parent(id), `parent of ${id}`);
    assert.deepEqual(fromEngine.children(id), fromSnapshot.children(id), `children of ${id}`);
    assert.equal(fromEngine.depth(id), fromSnapshot.depth(id), `depth of ${id}`);
    // The engine recomputes reputation; the snapshot stores the crawler's copy.
    assert.equal(fromEngine.reputation(id), fromSnapshot.reputation(id), `reputation of ${id}`);
  }
  for (const a of members) {
    for (const b of members) assert.equal(fromEngine.distance(a, b), fromSnapshot.distance(a, b), `${a}-${b}`);
  }
  assert.ok(fromEngine.reputation(fromEngine.root()) > 0);
});

test("treeFromEngine follows engine changes only when rebuilt", () => {
  const engine = loadEngine();
  const before = treeFromEngine(engine);
  const leaf = before.members().find((id) => before.children(id).length === 0 && before.depth(id) >= 2)!;
  engine.run((e) => e.leaveTree(leaf));
  assert.equal(before.has(leaf), true); // frozen copy
  const after = treeFromEngine(engine);
  assert.equal(after.has(leaf), false);
  assert.equal(after.members().length, before.members().length - 1);
});

// A fake engine whose answers can be made inconsistent.
function fakeEngine(over: Partial<EngineLike> = {}): EngineLike {
  const parents: Record<string, string> = { r: VIRTUAL_ROOT, a: "r", b: "r", c: "a" };
  return {
    root: () => "r",
    members: () => Object.keys(parents),
    parent: (id) => parents[id] ?? "0x0000000000000000000000000000000000000000",
    children: (id) => Object.keys(parents).filter((k) => parents[k] === id),
    calculateReputation: (id) => (id === "r" ? 5n * 10n ** 18n + 7n : 10n ** 18n),
    ...over,
  };
}

test("treeFromEngine: fake engine happy path", () => {
  const t = treeFromEngine(fakeEngine());
  assert.equal(t.root(), "r");
  assert.equal(t.parent("r"), null);
  assert.equal(t.distance("c", "b"), 3);
  assert.equal(t.reputation("r"), 5);
  assert.equal(t.reputation("c"), 1);
});

test("treeFromEngine: rejects inconsistent engines", () => {
  assert.throws(() => treeFromEngine(fakeEngine({ root: () => "a" })), /engine root a/);
  assert.throws(() => treeFromEngine(fakeEngine({ members: () => ["r", "a", "a", "b", "c"] })), /twice/);
  assert.throws(
    () => treeFromEngine(fakeEngine({ children: (id) => (id === "r" ? ["a", "b", "c"] : []) })),
    /children of .* disagree/,
  );
  // A member whose parent the engine does not list as a member.
  assert.throws(() => treeFromEngine(fakeEngine({ members: () => ["r", "c"] })), /parent a of c is not a member/);
});
