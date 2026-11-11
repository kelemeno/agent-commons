import { test } from "node:test";
import assert from "node:assert/strict";

import { generateKeyPair } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, ID_RE, LedgerError, replay, signEntry, type LedgerState, type Signer } from "../src/ledger";
import { MEMBER_ROOT, memberDigest, memberTree, treeDigest, treeFromParents } from "../src/members";
import { defaultRules } from "../src/rules";
import type { EntryBody, LedgerEntry, OwnerId } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: an in-memory ledger where the admin admits owners.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();

class World {
  admin = generateKeyPair();
  coord = generateKeyPair();
  minute = 0;
  entries: LedgerEntry[];
  state: LedgerState;

  constructor() {
    const genesis = genesisEntry(
      { kind: "genesis", project: "demo", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules: defaultRules() },
      iso(0),
    );
    this.entries = [genesis];
    this.state = emptyState(genesis);
  }

  append(body: EntryBody, signer: Signer = this.admin): LedgerEntry {
    this.minute += 1;
    const e = signEntry(this.state, body, signer, iso(this.minute));
    applyEntry(this.state, e);
    this.entries.push(e);
    return e;
  }

  owner(owner: OwnerId, inviter: OwnerId | null = null): this {
    this.append({ kind: "ownerKey", owner, publicKey: generateKeyPair().publicKey, inviter });
    return this;
  }
}

//   (commons) ─┬─ alice ─┬─ bob ─── dave
//              │         └─ carol
//              └─ erin ─── frank
function sampleWorld(): World {
  return new World().owner("alice").owner("bob", "alice").owner("carol", "alice").owner("erin").owner("dave", "bob").owner("frank", "erin");
}

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

// ---------------------------------------------------------------------------
// memberTree
// ---------------------------------------------------------------------------

test("memberTree: owners hang under their inviters, null inviters under the virtual root", () => {
  const t = memberTree(sampleWorld().state);
  assert.equal(t.root(), MEMBER_ROOT);
  assert.deepEqual(t.members(), [MEMBER_ROOT, "alice", "bob", "carol", "dave", "erin", "frank"].sort());
  assert.deepEqual(t.children(MEMBER_ROOT), ["alice", "erin"]);
  assert.deepEqual(t.children("alice"), ["bob", "carol"]);
  assert.equal(t.parent("alice"), MEMBER_ROOT);
  assert.equal(t.parent("dave"), "bob");
  assert.equal(t.parent(MEMBER_ROOT), null);
  assert.equal(t.depth(MEMBER_ROOT), 0);
  assert.equal(t.depth("alice"), 1);
  assert.equal(t.depth("dave"), 3);
  assert.equal(t.distance("alice", "bob"), 1, "an inviter and its invitee");
  assert.equal(t.distance("bob", "carol"), 2, "two invitees of one owner");
  assert.equal(t.distance("alice", "erin"), 2, "two owners without an inviter");
  assert.equal(t.distance("dave", "frank"), 5);
  assert.equal(t.has("zed"), false);
  assert.throws(() => t.distance("alice", "zed"), /unknown member zed/);
});

test("memberTree: owners added with no inviter are all at distance 2 (the Phase 1 allowlist)", () => {
  const w = new World().owner("carol").owner("alice").owner("bob");
  const t = memberTree(w.state);
  for (const a of ["alice", "bob", "carol"]) {
    assert.equal(t.parent(a), MEMBER_ROOT);
    for (const b of ["alice", "bob", "carol"]) assert.equal(t.distance(a, b), a === b ? 0 : 2);
  }
});

test("memberTree: a ledger with no owners is the virtual root alone", () => {
  const t = memberTree(new World().state);
  assert.deepEqual(t.members(), [MEMBER_ROOT]);
  assert.equal(t.root(), MEMBER_ROOT);
});

test("memberTree: an inviter chain gives depth and distance along the chain", () => {
  const w = new World().owner("n0");
  for (let i = 1; i < 200; i++) w.owner(`n${i}`, `n${i - 1}`);
  const t = memberTree(w.state);
  assert.equal(t.depth("n199"), 200);
  assert.equal(t.distance("n199", "n0"), 199);
  assert.equal(t.distance("n50", "n150"), 100);
  assert.equal(t.distance("n0", MEMBER_ROOT), 1);
});

test("memberTree: the same ledger prefix always yields the same tree and digest", () => {
  const w = sampleWorld();
  const again = replay(w.entries);
  assert.equal(memberDigest(again), memberDigest(w.state));
  assert.deepEqual(memberTree(again).members(), memberTree(w.state).members());
  for (let n = 1; n <= w.entries.length; n++) {
    const prefix = w.entries.slice(0, n);
    assert.equal(memberDigest(replay(prefix)), memberDigest(replay(prefix)), `prefix of ${n}`);
  }
});

test("memberTree: the digest is the canonical parent map, independent of admission order", () => {
  const a = new World().owner("alice").owner("erin").owner("bob", "alice");
  const b = new World().owner("erin").owner("alice").owner("bob", "alice");
  assert.equal(memberDigest(a.state), memberDigest(b.state), "owner order does not matter");
  assert.equal(memberDigest(a.state), treeDigest(treeFromParents({ [MEMBER_ROOT]: null, alice: MEMBER_ROOT, erin: MEMBER_ROOT, bob: "alice" })));
  const moved = new World().owner("alice").owner("erin").owner("bob", "erin");
  assert.notEqual(memberDigest(moved.state), memberDigest(a.state), "another inviter is another tree");
  const before = memberDigest(a.state);
  a.owner("zoe");
  assert.notEqual(memberDigest(a.state), before, "a new owner is a new tree");
});

test("memberTree: a newcomer never changes distances between existing owners", () => {
  const w = sampleWorld();
  const before = memberTree(w.state);
  w.owner("gus", "carol").owner("hal");
  const after = memberTree(w.state);
  for (const a of before.members()) {
    for (const b of before.members()) assert.equal(after.distance(a, b), before.distance(a, b), `${a}-${b}`);
  }
});

test("memberTree: the view is a frozen copy", () => {
  const w = sampleWorld();
  const t = memberTree(w.state);
  w.owner("late");
  t.members().push("intruder");
  t.children(MEMBER_ROOT).push("intruder");
  assert.equal(t.has("late"), false);
  assert.deepEqual(t.children(MEMBER_ROOT), ["alice", "erin"]);
});

test("the virtual root can never be an owner: the ledger's id rule refuses it", () => {
  assert.equal(ID_RE.test(MEMBER_ROOT), false);
  const w = new World();
  assert.throws(
    () => w.owner(MEMBER_ROOT),
    (e: unknown) => e instanceof LedgerError && e.code === "malformed",
  );
  // Nor an inviter: an unknown inviter is refused, so no owner hangs under a made-up node.
  assert.throws(
    () => w.owner("alice", MEMBER_ROOT),
    (e: unknown) => e instanceof LedgerError,
  );
});

test("owner ids that differ only in case are still one owner", () => {
  const w = new World().owner("Alice");
  assert.throws(
    () => w.owner("alice"),
    (e: unknown) => e instanceof LedgerError && e.code === "duplicate-id" && /ignore case/.test(e.message),
  );
  assert.throws(
    () => w.owner("Alice"),
    (e: unknown) => e instanceof LedgerError && e.code === "duplicate-id",
  );
  // An inviter must be named exactly as registered.
  assert.throws(() => w.owner("bob", "alice"), (e: unknown) => e instanceof LedgerError && e.code === "unknown-ref");
  assert.deepEqual(memberTree(w.state).members(), [MEMBER_ROOT, "Alice"]);
});

test("memberTree: a hand-built state with a reserved id, unknown inviter or cycle throws", () => {
  const owner = (id: string, inviter: string | null) => [id, { id, keyId: id, inviter, reputationDelta: 0, lockedStake: 0 }] as const;
  assert.throws(() => memberTree({ owners: new Map([owner(MEMBER_ROOT, null)]) }), /reserved/);
  assert.throws(() => memberTree({ owners: new Map([owner("a", "ghost")]) }), /parent ghost of a is not a member/);
  assert.throws(() => memberTree({ owners: new Map([owner("a", "b"), owner("b", "a")]) }), /cycle/);
});

// ---------------------------------------------------------------------------
// The generic structure (treeFromParents, for tests and tools)
// ---------------------------------------------------------------------------

//        r
//      /   \
//     a     b
//    / \     \
//   c   d     e
//   |
//   f
const sample = { r: null, a: "r", b: "r", c: "a", d: "a", e: "b", f: "c" };

test("treeFromParents: structure queries and distances match the reference", () => {
  const t = treeFromParents(sample);
  assert.equal(t.root(), "r");
  assert.deepEqual(t.children("a"), ["c", "d"]);
  assert.equal(t.depth("f"), 3);
  assert.equal(t.distance("c", "d"), 2);
  assert.equal(t.distance("f", "e"), 5);
  for (const a of t.members()) {
    for (const b of t.members()) {
      assert.equal(t.distance(a, b), referenceDistance(sample, a, b), `${a}-${b}`);
      assert.equal(t.distance(a, b), t.distance(b, a));
    }
  }
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
  assert.equal(treeDigest(a), treeDigest(b));
});

test("treeFromParents: rejects invalid trees with clear messages", () => {
  assert.throws(() => treeFromParents({}), /no members/);
  assert.throws(() => treeFromParents({ a: null, b: null }), /more than one root: a, b/);
  assert.throws(() => treeFromParents({ a: "b", b: "a" }), /no root/);
  assert.throws(() => treeFromParents({ r: null, a: "ghost" }), /parent ghost of a is not a member/);
  assert.throws(() => treeFromParents({ r: null, a: "a" }), /own parent/);
  assert.throws(() => treeFromParents({ r: null, x: "y", y: "z", z: "x" }), /cycle: x, y, z cannot reach the root r/);
  assert.throws(() => treeFromParents({ r: null, x: "y", y: "x", leaf: "x" }), /cycle: leaf, x, y/);
  assert.throws(() => treeFromParents({ r: null, a: 7 as unknown as string }), /must be a string or null/);
});

test("treeFromParents: structural queries on unknown ids throw", () => {
  const t = treeFromParents(sample);
  const calls: [string, () => unknown][] = [
    ["parent", () => t.parent("z")],
    ["children", () => t.children("z")],
    ["depth", () => t.depth("z")],
    ["distance a-z", () => t.distance("a", "z")],
    ["distance z-a", () => t.distance("z", "a")],
  ];
  for (const [name, call] of calls) {
    assert.throws(call, /tree: unknown member z/, name);
  }
  assert.throws(() => treeFromParents({ A: null }).parent("a"), /unknown member a/, "ids are exact");
});

test("treeFromParents: ids that collide with Object.prototype are ordinary members", () => {
  const parents = JSON.parse('{"__proto__": null, "constructor": "__proto__", "toString": "constructor"}');
  const t = treeFromParents(parents);
  assert.equal(t.root(), "__proto__");
  assert.equal(t.distance("toString", "__proto__"), 2);
  assert.equal(t.has("hasOwnProperty"), false);
});
