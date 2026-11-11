import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { performance } from "node:perf_hooks";

import { AnthillEngine, type SeedGraph } from "../../anthill-backend/src/engine";
import { bigintReviver } from "../../anthill-backend/src/store";
import {
  type EngineLike,
  NotAMemberError,
  reputationPoints,
  TEMP_ADDRESS,
  treeFromEngine,
  treeFromParents,
  treeFromSnapshot,
  VIRTUAL_ROOT,
} from "../src/tree";

const SNAPSHOT_PATH = join(__dirname, "..", "..", "anthill-backend", "anthillSnapshot.json");
const snapshotText = readFileSync(SNAPSHOT_PATH, "utf8");
const E18 = 10n ** 18n;

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
});

test("treeFromParents: reputation must be a non-negative safe integer, for members only", () => {
  for (const bad of [Number.NaN, Infinity, -Infinity, -1, 1.5, 2 ** 53, "3" as unknown as number]) {
    assert.throws(() => treeFromParents({ r: null }, { r: bad }), /non-negative safe integer/, String(bad));
  }
  assert.equal(treeFromParents({ r: null }, { r: Number.MAX_SAFE_INTEGER }).reputation("r"), Number.MAX_SAFE_INTEGER);
  assert.throws(() => treeFromParents({ r: null }, { z: 1 }), /reputation given for z, which is not a member/);
});

test("treeFromParents: ids are taken exactly as given (no case folding)", () => {
  const t = treeFromParents({ A: null, a: "A" }, { a: 2 });
  assert.equal(t.root(), "A");
  assert.deepEqual(t.members(), ["A", "a"]);
  assert.equal(t.distance("a", "A"), 1);
  assert.equal(t.reputation("a"), 2);
  assert.equal(t.reputation("A"), 0);
  assert.throws(() => treeFromParents({ A: null }).parent("a"), NotAMemberError);
});

test("treeFromParents: structural queries on unknown ids throw NotAMemberError", () => {
  const t = treeFromParents(sample);
  const calls: [string, () => unknown][] = [
    ["parent", () => t.parent("z")],
    ["children", () => t.children("z")],
    ["depth", () => t.depth("z")],
    ["distance a-z", () => t.distance("a", "z")],
    ["distance z-a", () => t.distance("z", "a")],
  ];
  for (const [name, call] of calls) {
    assert.throws(call, (e: unknown) => e instanceof NotAMemberError && e.id === "z" && /unknown member z/.test(e.message), name);
  }
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

test("reputationPoints floors 18-decimal values and rejects impossible ones", () => {
  assert.equal(reputationPoints(0n), 0);
  assert.equal(reputationPoints(E18 - 1n), 0);
  assert.equal(reputationPoints(E18), 1);
  assert.equal(reputationPoints(62999999999999999970n), 62);
  const max = BigInt(Number.MAX_SAFE_INTEGER);
  assert.equal(reputationPoints(max * E18 + E18 - 1n), Number.MAX_SAFE_INTEGER);
  assert.throws(() => reputationPoints(-1n), /negative/);
  assert.throws(() => reputationPoints(-E18), /negative/);
  assert.throws(() => reputationPoints((max + 1n) * E18), /too large/);
});

// A hand-built snapshot in the file's format. Votes default to the dist the
// engine computes for a vote to an ancestor (the depth difference).
type Vote = { id: string; weight: { __bigint__: string }; dist: number; posInOther: number };
type MiniNode = {
  id: string;
  sentTreeVote: string;
  recTreeVotes: string[];
  sentDagVotes: Vote[];
  recDagVotes: Vote[];
  totalWeight: { __bigint__: string };
  [field: string]: unknown;
};
type Mini = { graph: { rootId: string; dict: Record<string, MiniNode> } };
const big = (n: bigint) => ({ __bigint__: n.toString() });

function buildSnapshot(parents: Record<string, string | null>, votes: [from: string, to: string, weight: bigint, dist?: number][]): Mini {
  const depth = (id: string): number => {
    const p = parents[id];
    return p === null || p === undefined ? 0 : 1 + depth(p);
  };
  const root = Object.keys(parents).find((id) => parents[id] === null)!;
  const dict: Record<string, MiniNode> = {
    [VIRTUAL_ROOT]: {
      id: VIRTUAL_ROOT,
      sentTreeVote: VIRTUAL_ROOT,
      recTreeVotes: [root],
      sentDagVotes: [],
      recDagVotes: [],
      totalWeight: big(0n),
      reputation: big(0n),
    },
  };
  for (const [id, parent] of Object.entries(parents)) {
    dict[id] = { id, sentTreeVote: parent ?? VIRTUAL_ROOT, recTreeVotes: [], sentDagVotes: [], recDagVotes: [], totalWeight: big(0n) };
  }
  for (const [id, parent] of Object.entries(parents)) if (parent !== null) dict[parent]!.recTreeVotes.push(id);
  for (const [from, to, weight, dist] of votes) {
    const s = dict[from]!;
    const r = dict[to]!;
    s.sentDagVotes.push({ id: to, weight: big(weight), dist: dist ?? depth(from) - depth(to), posInOther: r.recDagVotes.length });
    r.recDagVotes.push({ id: from, weight: big(weight), dist: 0, posInOther: s.sentDagVotes.length - 1 });
    s.totalWeight = big(BigInt(s.totalWeight.__bigint__) + weight);
  }
  return { graph: { rootId: root, dict } };
}

const R = "0x0000000000000000000000000000000000000002";
const A = "0x00000000000000000000000000000000000000aa";
const B = "0x00000000000000000000000000000000000000bb";
const C = "0x00000000000000000000000000000000000000cc";
const D = "0x00000000000000000000000000000000000000dd";

//      R
//     / \
//    A   B
//    |
//    C        votes: A->R, B->R, C->A, C->R (weight 1 each)
// rep(C) = 1, rep(A) = 1 + 1/2 = 1.5, rep(B) = 1, rep(R) = 1 + 1.5 + 1 + 1/2 = 4
function miniSnapshot(): Mini {
  return buildSnapshot({ [R]: null, [A]: R, [B]: R, [C]: A }, [
    [A, R, 1n],
    [B, R, 1n],
    [C, A, 1n],
    [C, R, 1n],
  ]);
}

test("treeFromSnapshot: virtual node excluded, reputation computed from DAG votes", () => {
  const t = treeFromSnapshot(miniSnapshot());
  assert.equal(t.root(), R);
  assert.equal(t.has(VIRTUAL_ROOT), false);
  assert.equal(t.parent(R), null);
  assert.deepEqual(t.members(), [R, A, B, C]);
  assert.deepEqual(t.children(R), [A, B]);
  assert.equal(t.distance(C, B), 3);
  assert.equal(t.reputation(R), 4);
  assert.equal(t.reputation(A), 1); // 1.5, floored
  assert.equal(t.reputation(B), 1);
  assert.equal(t.reputation(C), 1);
});

test("treeFromSnapshot: cached currentRep and reputation fields are ignored", () => {
  const snap = miniSnapshot();
  snap.graph.dict[C]!["currentRep"] = big(9n * 10n ** 30n);
  snap.graph.dict[B]!["reputation"] = big(500n * E18);
  snap.graph.dict[A]!["currentRep"] = { __bigint__: "not a number" };
  const t = treeFromSnapshot(snap);
  assert.equal(t.reputation(C), 1);
  assert.equal(t.reputation(B), 1);
  assert.equal(t.reputation(A), 1);
  assert.equal(t.reputation(R), 4);
});

test("treeFromSnapshot: accepts text, parsed and revived forms; ids are case-insensitive", () => {
  const text = JSON.stringify(miniSnapshot());
  const fromText = treeFromSnapshot(text);
  const fromRevived = treeFromSnapshot(JSON.parse(text, bigintReviver));
  assert.deepEqual(fromText.members(), fromRevived.members());
  assert.equal(fromRevived.reputation(R), 4);

  const upperA = A.replace("aa", "AA");
  const upper = treeFromSnapshot(text.replaceAll(A, upperA));
  assert.deepEqual(upper.members(), [R, A, B, C]); // stored lowercase
  assert.equal(upper.has(upperA), true);
  assert.equal(upper.parent(upperA), R);
  assert.deepEqual(upper.children(upperA), [C]);
  assert.equal(upper.depth(upperA), 1);
  assert.equal(upper.distance(upperA, B), upper.distance(A, B));
  assert.equal(upper.distance(upperA, A), 0); // a re-cased id is not a stranger
  assert.equal(upper.reputation(upperA), 1);
  assert.equal(upper.reputation(R.toUpperCase().replace("0X", "0x")), 4);
});

test("treeFromSnapshot: a cousin vote carries the engine's dist", () => {
  //      R
  //     / \
  //    A   B
  //    |   |
  //    C   D      D -> A: one level up, across; dist = 1 (B~A) + 1
  const parents = { [R]: null, [A]: R, [B]: R, [C]: A, [D]: B };
  const votes: [string, string, bigint, number?][] = [
    [A, R, 1n],
    [B, R, 1n],
    [C, A, 1n],
    [D, B, 1n],
    [D, A, 1n, 2],
  ];
  const t = treeFromSnapshot(buildSnapshot(parents, votes));
  assert.equal(t.reputation(A), 2); // 1 + C's 1 + half of D's 1
  votes[4] = [D, A, 1n, 1];
  assert.throws(() => treeFromSnapshot(buildSnapshot(parents, votes)), /stale dist/);
});

test("treeFromSnapshot: addresses out of the tree are skipped only when they carry no edges", () => {
  const withGone = (edit: (n: MiniNode) => void) => {
    const snap = miniSnapshot();
    const gone = "0x00000000000000000000000000000000000000ee";
    const node: MiniNode = {
      id: gone,
      sentTreeVote: "0x0000000000000000000000000000000000000000",
      recTreeVotes: [],
      sentDagVotes: [],
      recDagVotes: [],
      totalWeight: big(0n),
    };
    edit(node);
    snap.graph.dict[gone] = node;
    return { snap, gone };
  };
  const { snap, gone } = withGone(() => {});
  const t = treeFromSnapshot(snap);
  assert.equal(t.has(gone), false);
  assert.equal(t.members().length, 4);

  assert.throws(() => treeFromSnapshot(withGone((n) => n.recTreeVotes.push(A)).snap), /not in the tree but lists children/);
  const voting = withGone((n) => n.sentDagVotes.push({ id: R, weight: big(1n), dist: 1, posInOther: 0 })).snap;
  assert.throws(() => treeFromSnapshot(voting), /not in the tree but has DAG votes/);
});

test("treeFromSnapshot: rejects corrupt tree structure", () => {
  assert.throws(() => treeFromSnapshot({}), /\{graph: \{rootId, dict\}\}/);
  assert.throws(() => treeFromSnapshot("not json"), SyntaxError);

  const twoRoots = miniSnapshot();
  twoRoots.graph.dict[B]!.sentTreeVote = VIRTUAL_ROOT;
  twoRoots.graph.dict[R]!.recTreeVotes = [A];
  assert.throws(() => treeFromSnapshot(twoRoots), /more than one root/);

  // rootId and the virtual node agree on A, but A has a parent.
  const wrongRoot = miniSnapshot();
  wrongRoot.graph.rootId = A;
  wrongRoot.graph.dict[VIRTUAL_ROOT]!.recTreeVotes = [A];
  assert.throws(() => treeFromSnapshot(wrongRoot), new RegExp(`snapshot rootId ${A} but the tree's root is ${R}`));

  const virtualDisagrees = miniSnapshot();
  virtualDisagrees.graph.dict[VIRTUAL_ROOT]!.recTreeVotes = [A];
  assert.throws(() => treeFromSnapshot(virtualDisagrees), /virtual node's recTreeVotes disagree with rootId/);

  const virtualExtra = miniSnapshot();
  virtualExtra.graph.dict[VIRTUAL_ROOT]!.recTreeVotes = [R, A];
  assert.throws(() => treeFromSnapshot(virtualExtra), /virtual node's recTreeVotes disagree with rootId/);

  const noVirtual = miniSnapshot();
  delete noVirtual.graph.dict[VIRTUAL_ROOT];
  assert.throws(() => treeFromSnapshot(noVirtual), /no virtual node/);

  const virtualElsewhere = miniSnapshot();
  virtualElsewhere.graph.dict[VIRTUAL_ROOT]!.sentTreeVote = R;
  assert.throws(() => treeFromSnapshot(virtualElsewhere), /virtual node does not point at itself/);

  const virtualRoot = miniSnapshot();
  virtualRoot.graph.rootId = VIRTUAL_ROOT;
  assert.throws(() => treeFromSnapshot(virtualRoot), /rootId is the virtual node/);

  // Claims a child that points elsewhere: the two copies of the edge disagree.
  const forged = miniSnapshot();
  forged.graph.dict[A]!.recTreeVotes = [B];
  assert.throws(() => treeFromSnapshot(forged), /recTreeVotes of .* disagree/);

  // Omits a real child.
  const hidden = miniSnapshot();
  hidden.graph.dict[R]!.recTreeVotes = [A];
  assert.throws(() => treeFromSnapshot(hidden), /recTreeVotes of .* disagree/);

  const noRecTree = miniSnapshot();
  delete (noRecTree.graph.dict[B] as Partial<MiniNode>).recTreeVotes;
  assert.throws(() => treeFromSnapshot(noRecTree), /missing or malformed recTreeVotes/);

  const unknownParent = miniSnapshot();
  unknownParent.graph.dict[B]!.sentTreeVote = "0x00000000000000000000000000000000000000ff";
  assert.throws(() => treeFromSnapshot(unknownParent), /is not a member/);

  const cycle = miniSnapshot();
  cycle.graph.dict[A]!.sentTreeVote = B;
  cycle.graph.dict[B]!.sentTreeVote = A;
  assert.throws(() => treeFromSnapshot(cycle), /cycle/);

  const dup = miniSnapshot();
  dup.graph.dict["copy"] = { ...dup.graph.dict[B]! };
  assert.throws(() => treeFromSnapshot(dup), /lists .* twice/);

  // The engine's move placeholder is never a member between calls.
  const temp = buildSnapshot({ [R]: null, [TEMP_ADDRESS]: R }, [[TEMP_ADDRESS, R, 1n]]);
  assert.throws(() => treeFromSnapshot(temp), /reserved address/);
});

test("treeFromSnapshot: rejects DAG votes the engine would not hold", () => {
  const noSent = miniSnapshot();
  delete (noSent.graph.dict[B] as Partial<MiniNode>).sentDagVotes;
  assert.throws(() => treeFromSnapshot(noSent), /has no sentDagVotes/);

  const noTotal = miniSnapshot();
  delete (noTotal.graph.dict[B] as Partial<MiniNode>).totalWeight;
  assert.throws(() => treeFromSnapshot(noTotal), /totalWeight of .* is not a bigint/);

  const badWeight = miniSnapshot();
  badWeight.graph.dict[B]!.sentDagVotes[0]!.weight = { __bigint__: "1e18" };
  assert.throws(() => treeFromSnapshot(badWeight), /not a bigint/);

  // A received vote with no sender: inflates R in a reader that trusts it.
  const phantom = miniSnapshot();
  phantom.graph.dict[R]!.recDagVotes.push({ id: B, weight: big(1000n), dist: 0, posInOther: 5 });
  assert.throws(() => treeFromSnapshot(phantom), /DAG vote .* -> .* is not linked both ways/);

  // A sent vote the recipient does not list.
  const unreceived = miniSnapshot();
  unreceived.graph.dict[R]!.recDagVotes = unreceived.graph.dict[R]!.recDagVotes.filter((v) => v.id !== B);
  assert.throws(() => treeFromSnapshot(unreceived), /not linked both ways/);

  // The two ends disagree on the weight.
  const heavier = miniSnapshot();
  heavier.graph.dict[R]!.recDagVotes.find((v) => v.id === C)!.weight = big(100n);
  assert.throws(() => treeFromSnapshot(heavier), /not linked both ways/);

  // A totalWeight smaller than the weights sent would multiply them.
  const lightTotal = miniSnapshot();
  lightTotal.graph.dict[C]!.totalWeight = big(1n);
  assert.throws(() => treeFromSnapshot(lightTotal), /totalWeight of .* is not the sum/);

  const parents = { [R]: null, [A]: R, [B]: R, [C]: A };
  assert.throws(() => treeFromSnapshot(buildSnapshot(parents, [[R, A, 1n, 1]])), /not upward/);
  assert.throws(() => treeFromSnapshot(buildSnapshot(parents, [[A, B, 1n, 1]])), /not upward/);
  assert.throws(() => treeFromSnapshot(buildSnapshot(parents, [[R, R, 1n, 0]])), /not upward/);
  // A cousin one level up is local (both lie under the root): accepted.
  assert.equal(treeFromSnapshot(buildSnapshot(parents, [[C, B, 1n, 2]])).reputation(B), 2);

  // More than MAX_REL_ROOT_DEPTH (6) levels up is not local.
  const chain: Record<string, string | null> = {};
  const ids = Array.from({ length: 9 }, (_, i) => `0x${(0x100 + i).toString(16).padStart(40, "0")}`);
  ids.forEach((id, i) => (chain[id] = i === 0 ? null : ids[i - 1]!));
  assert.equal(treeFromSnapshot(buildSnapshot(chain, [[ids[7]!, ids[1]!, 1n]])).reputation(ids[1]!), 2);
  assert.throws(() => treeFromSnapshot(buildSnapshot(chain, [[ids[7]!, ids[0]!, 1n]])), /not local/);

  // The vote target must be a member.
  const outside = miniSnapshot();
  outside.graph.dict[B]!.sentDagVotes[0]!.id = "0x00000000000000000000000000000000000000ff";
  assert.throws(() => treeFromSnapshot(outside), /not linked both ways/);
});

test("treeFromSnapshot: the real anthillSnapshot.json", () => {
  const raw = JSON.parse(snapshotText);
  const t = treeFromSnapshot(snapshotText);
  const dict = raw.graph.dict as Record<string, { sentTreeVote: string; depth: number; currentRep: { __bigint__: string } }>;
  assert.equal(t.root(), raw.graph.rootId);
  assert.equal(t.members().length, Object.keys(dict).length - 1);
  assert.equal(t.has(VIRTUAL_ROOT), false);
  for (const id of t.members()) {
    const node = dict[id]!;
    assert.equal(t.parent(id), node.sentTreeVote === VIRTUAL_ROOT ? null : node.sentTreeVote);
    assert.equal(t.depth(id), node.depth, `depth of ${id}`); // the crawler records depth too
    // The crawler computed currentRep with the same formula; computing it here agrees.
    assert.equal(t.reputation(id), Number(BigInt(node.currentRep.__bigint__) / E18), `reputation of ${id}`);
  }
  assert.equal(t.reputation(raw.graph.rootId), 62);
});

function loadEngine(text = snapshotText): AnthillEngine {
  const graph = JSON.parse(text, bigintReviver).graph as SeedGraph;
  const engine = new AnthillEngine();
  engine.loadFromGraph(graph);
  return engine;
}

function assertSameView(x: ReturnType<typeof treeFromEngine>, y: ReturnType<typeof treeFromEngine>) {
  assert.equal(x.root(), y.root());
  assert.deepEqual(x.members(), y.members());
  const members = y.members();
  for (const id of members) {
    assert.equal(x.parent(id), y.parent(id), `parent of ${id}`);
    assert.deepEqual(x.children(id), y.children(id), `children of ${id}`);
    assert.equal(x.depth(id), y.depth(id), `depth of ${id}`);
    assert.equal(x.reputation(id), y.reputation(id), `reputation of ${id}`);
  }
  for (const a of members) {
    for (const b of members) assert.equal(x.distance(a, b), y.distance(a, b), `${a}-${b}`);
  }
}

// The engine's own (slow, cache-writing) reputation, for comparison.
function assertEngineReputation(t: ReturnType<typeof treeFromEngine>, engine: AnthillEngine) {
  for (const id of t.members()) {
    assert.equal(t.reputation(id), reputationPoints(engine.calculateReputation(id)), `reputation of ${id}`);
  }
}

test("treeFromEngine and treeFromSnapshot agree on the real snapshot", () => {
  const engine = loadEngine();
  const fromEngine = treeFromEngine(engine);
  assertSameView(fromEngine, treeFromSnapshot(snapshotText));
  assertEngineReputation(fromEngine, engine);
  assert.ok(fromEngine.reputation(fromEngine.root()) > 0);
});

test("treeFromEngine leaves the engine's state untouched", async () => {
  const engine = loadEngine();
  const t = treeFromEngine(engine);
  // calculateReputation would have filled this cache; the view must not.
  for (const id of t.members()) assert.equal(await engine.read.reputation([id]), 0n, id);
  const before = JSON.stringify(
    await Promise.all(t.members().map(async (id) => [id, String(await engine.read.sentDagVoteCount([id])), engine.children(id)])),
  );
  treeFromEngine(engine);
  const after = JSON.stringify(
    await Promise.all(t.members().map(async (id) => [id, String(await engine.read.sentDagVoteCount([id])), engine.children(id)])),
  );
  assert.equal(after, before);
});

test("a tampered snapshot reputation is ignored by both readers", () => {
  const raw = JSON.parse(snapshotText);
  const leaf = Object.keys(raw.graph.dict).find((id) => id !== VIRTUAL_ROOT && raw.graph.dict[id].recTreeVotes.length === 0)!;
  raw.graph.dict[leaf].currentRep = big(9n * 10n ** 30n);
  raw.graph.dict[leaf].reputation = big(9n * 10n ** 30n);
  const edited = JSON.stringify(raw);
  const fromSnapshot = treeFromSnapshot(edited);
  assert.equal(fromSnapshot.reputation(leaf), treeFromSnapshot(snapshotText).reputation(leaf));
  assertSameView(treeFromEngine(loadEngine(edited)), fromSnapshot);
});

test("treeFromEngine matches calculateReputation after the engine changes", () => {
  const engine = loadEngine();
  const before = treeFromEngine(engine);

  // A fresh endorsement with an odd weight, from the first member that can add one.
  let added = false;
  for (const voter of before.members()) {
    for (const recipient of before.members()) {
      const { votable, voted } = engine.dagVoteState(voter, recipient);
      if (votable && !voted) {
        engine.run((e) => e.addDagVote(voter, recipient, 7n));
        added = true;
        break;
      }
    }
    if (added) break;
  }
  assert.ok(added);

  const leaf = before.members().find((id) => before.children(id).length === 0 && before.depth(id) >= 2)!;
  engine.run((e) => e.leaveTree(leaf));
  assert.equal(before.has(leaf), true); // frozen copy

  const after = treeFromEngine(engine);
  assert.equal(after.has(leaf), false);
  assert.equal(after.members().length, before.members().length - 1);
  assertEngineReputation(after, engine);
});

// A chain where member i endorses every ancestor 2 to 6 levels up: the shape
// that makes the engine's unmemoised recursion exponential.
function sybilChain(n: number): { engine: AnthillEngine; ids: string[] } {
  const ids = Array.from({ length: n }, (_, i) => `0x${(0x1000 + i).toString(16).padStart(40, "0")}`);
  const engine = new AnthillEngine();
  engine.run((e) => {
    e.joinTreeAsRoot(ids[0]!, "n0");
    for (let i = 1; i < n; i++) {
      e.joinTree(ids[i]!, `n${i}`, ids[i - 1]!);
      for (let k = 2; k <= 6 && i - k >= 0; k++) e.addDagVote(ids[i]!, ids[i - k]!, 1n);
    }
  });
  return { engine, ids };
}

test("treeFromEngine: reputation is computed in one pass (no exponential blow-up)", () => {
  const small = sybilChain(14);
  assertEngineReputation(treeFromEngine(small.engine), small.engine);

  const { engine, ids } = sybilChain(40);
  const start = performance.now();
  const t = treeFromEngine(engine);
  assert.ok(performance.now() - start < 1000, "40-member sybil chain took over a second");
  assert.equal(t.members().length, 40);
  assert.ok(t.reputation(ids[0]!) > 1);
});

test("treeFromEngine: a member with zero total weight cannot break the view", () => {
  const { engine, ids } = sybilChain(4);
  const voter = ids[3]!;
  engine.run((e) => {
    for (const to of e.endorsing(voter)) e.removeDagVote(voter, to);
    e.addDagVote(voter, ids[2]!, 0n);
  });
  // The engine itself divides by zero here.
  assert.throws(() => engine.calculateReputation(ids[2]!), RangeError);
  const t = treeFromEngine(engine);
  assert.equal(t.reputation(ids[2]!), 1);
});

// A fake engine whose answers can be made inconsistent. Votes: everyone below
// the root endorses their parent with weight 1.
function fakeEngine(over: Partial<EngineLike> = {}, parents: Record<string, string> = { r: VIRTUAL_ROOT, a: "r", b: "r", c: "a" }): EngineLike {
  const engine: EngineLike = {
    root: () => Object.keys(parents).find((k) => parents[k] === VIRTUAL_ROOT)!,
    members: () => Object.keys(parents),
    parent: (id) => parents[id] ?? "0x0000000000000000000000000000000000000000",
    children: (id) => Object.keys(parents).filter((k) => parents[k] === id),
    endorsing: (id) => (parents[id] === VIRTUAL_ROOT || parents[id] === undefined ? [] : [parents[id]!]),
    findSentDagVote: (voter, recipient) => {
      const voted = parents[voter] === recipient;
      return [voted, voted, 1, 0, 0, { weight: voted ? 1n : 0n }];
    },
  };
  return { ...engine, ...over };
}

test("treeFromEngine: fake engine happy path", () => {
  const t = treeFromEngine(fakeEngine());
  assert.equal(t.root(), "r");
  assert.equal(t.parent("r"), null);
  assert.equal(t.distance("c", "b"), 3);
  assert.equal(t.reputation("c"), 1);
  assert.equal(t.reputation("a"), 2);
  assert.equal(t.reputation("r"), 4); // 1 + a's 2 + b's 1
});

test("treeFromEngine: calls the engine with its own spelling of an id", () => {
  const t = treeFromEngine(fakeEngine({}, { "0xROOT": VIRTUAL_ROOT, "0xKid": "0xROOT" }));
  assert.deepEqual(t.members(), ["0xkid", "0xroot"]);
  assert.equal(t.root(), "0xroot");
  assert.equal(t.reputation("0xRoot"), 2);
  assert.equal(t.distance("0xKID", "0xroot"), 1);
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
  // Lists a vote it cannot produce.
  assert.throws(() => treeFromEngine(fakeEngine({ endorsing: (id) => (id === "c" ? ["b"] : []) })), /DAG vote c -> b it cannot find/);
  const yes = (): ReturnType<EngineLike["findSentDagVote"]> => [true, true, 1, 0, 0, { weight: 1n }];
  // Votes that point down, sideways, or out of the tree.
  assert.throws(() => treeFromEngine(fakeEngine({ endorsing: (id) => (id === "r" ? ["c"] : []), findSentDagVote: yes })), /does not point up/);
  assert.throws(() => treeFromEngine(fakeEngine({ endorsing: (id) => (id === "a" ? ["b"] : []), findSentDagVote: yes })), /does not point up/);
  assert.throws(() => treeFromEngine(fakeEngine({ endorsing: (id) => (id === "a" ? ["z"] : []), findSentDagVote: yes })), /non-member/);
  const negative = (): ReturnType<EngineLike["findSentDagVote"]> => [true, true, 1, 0, 0, { weight: -1n }];
  assert.throws(() => treeFromEngine(fakeEngine({ findSentDagVote: negative })), /negative weight/);
});
