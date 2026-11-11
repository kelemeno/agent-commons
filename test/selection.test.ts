import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import {
  MAX_WEIGHT,
  computeBeacon,
  drawFraction,
  selectReviewers,
  verifyAssignment,
  verifyAssignmentInLedger,
} from "../src/selection";
import { treeFromParents } from "../src/tree";
import type { CommonsState, EntryBody, KeyId, OwnerId, Rules, TreeView } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture. Twelve owners o0..o11; the author is o7:
//
//   o0 ─┬─ o1 ─┬─ o3 ─┬─ o7 (author)       distance from o7, weight (N = 2, cap 2)
//       │      │      └─ o8                 o3 1 ✗, o1 2 ✗, o8 2 ✗
//       │      └─ o4                        o4 3 w1, o0 3 w1 (lineal), o2 4 w2
//       └─ o2 ─┬─ o5 ─┬─ o9                 o5 5 w2, o6 5 w2
//              │      └─ o10                o9 6 w2, o10 6 w2, o11 6 w2
//              └─ o6 ─── o11
// ---------------------------------------------------------------------------

const PARENTS: Record<OwnerId, OwnerId | null> = {
  o0: null,
  o1: "o0",
  o2: "o0",
  o3: "o1",
  o4: "o1",
  o5: "o2",
  o6: "o2",
  o7: "o3",
  o8: "o3",
  o9: "o5",
  o10: "o5",
  o11: "o6",
};
const TREE = treeFromParents(PARENTS);
const OWNERS = Object.keys(PARENTS);
const NEAR = ["o1", "o3", "o8"];
const WEIGHT: Record<string, number> = { o0: 1, o4: 1, o2: 2, o5: 2, o6: 2, o9: 2, o10: 2, o11: 2 };
const ELIGIBLE = Object.keys(WEIGHT);

const T0 = Date.UTC(2026, 0, 1);

class World {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "selection-test-"));
  admin = generateKeyPair();
  coord = generateKeyPair();
  keys = new Map<string, Signer>();
  minute = 0;
  ledger: Ledger;

  constructor(rules: Partial<Rules> = {}) {
    this.ledger = Ledger.create(
      path.join(this.dir, "ledger.jsonl"),
      {
        kind: "genesis",
        project: "anthill",
        admins: [this.admin.publicKey],
        coordinator: this.coord.publicKey,
        rules: { ...defaultRules(), ...rules },
      },
      this.now(),
    );
  }

  now(): string {
    return new Date(T0 + this.minute * 60_000).toISOString();
  }

  key(name: string): Signer {
    let k = this.keys.get(name);
    if (!k) {
      k = generateKeyPair();
      this.keys.set(name, k);
    }
    return k;
  }

  id(name: string): KeyId {
    return keyIdOf(this.key(name).publicKey);
  }

  append(body: EntryBody, signer: Signer) {
    this.minute += 1;
    return this.ledger.append(body, signer, this.now());
  }

  get state(): CommonsState {
    return this.ledger.state();
  }

  owner(owner: OwnerId): this {
    this.append({ kind: "ownerKey", owner, publicKey: this.key(owner).publicKey, inviter: null }, this.admin);
    return this;
  }

  agent(name: string, owner: OwnerId, modelFamily: string): this {
    this.append(
      { kind: "agentRegistered", owner, publicKey: this.key(name).publicKey, modelFamily, harness: "cli" },
      this.key(owner),
    );
    return this;
  }

  submit(id: string, agent: string): this {
    this.append(
      {
        kind: "submission",
        id,
        taskId: null,
        baseCommit: "base",
        headCommit: `head-${id}`,
        changedFiles: ["anthill-backend/src/feature.ts"],
        linesChanged: 10,
      },
      this.key(agent),
    );
    return this;
  }

  assign(submissionId: string, beacon: string, reviewers: KeyId[]) {
    return this.append({ kind: "reviewAssignment", submissionId, beacon, reviewers }, this.coord);
  }

  cleanup(): void {
    fs.rmSync(this.dir, { recursive: true, force: true });
  }
}

// Every owner registered; one agent each (`ag-<owner>`). The author agent is
// `ag-o7` (claude); everyone else is "gpt" unless `families` says otherwise.
// `owners` and `author` replace the fixture's for tests with their own tree.
function world(
  opts: { rules?: Partial<Rules>; families?: Record<string, string>; owners?: string[]; author?: string } = {},
): World {
  const w = new World(opts.rules);
  const owners = opts.owners ?? OWNERS;
  const author = opts.author ?? "o7";
  for (const o of owners) w.owner(o);
  for (const o of owners) w.agent(`ag-${o}`, o, opts.families?.[o] ?? (o === author ? "claude" : "gpt"));
  return w;
}

const ownerOf = (state: CommonsState, k: KeyId): OwnerId => {
  const a = state.agents.get(k);
  assert.ok(a, `unknown agent ${k}`);
  return a.owner;
};

function beacons(n: number): string[] {
  return Array.from({ length: n }, (_, i) => sha256hex(`round-${i}`));
}

// ---------------------------------------------------------------------------
// computeBeacon / drawFraction
// ---------------------------------------------------------------------------

test("computeBeacon is sha256 of the canonical head, submission head commit and entropy", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  const expected = sha256hex(canonical({ head: st.headHash, submission: "head-s1", entropy: "drand-123" }));
  assert.equal(computeBeacon(st, "s1", "drand-123"), expected);
  assert.equal(computeBeacon(st, "s1", "drand-123"), expected, "deterministic");
  assert.notEqual(computeBeacon(st, "s1", "drand-124"), expected, "entropy matters");
});

test("computeBeacon changes with the ledger head and the submission", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const before = computeBeacon(w.state, "s1", "e");
  w.submit("s2", "ag-o7");
  assert.notEqual(computeBeacon(w.state, "s1", "e"), before, "a new entry moves the head");
  assert.notEqual(computeBeacon(w.state, "s2", "e"), computeBeacon(w.state, "s1", "e"));
});

test("computeBeacon and selectReviewers throw on an unknown submission", (t) => {
  const w = world();
  t.after(() => w.cleanup());
  assert.throws(() => computeBeacon(w.state, "nope", "e"), /no submission nope/);
  assert.throws(() => selectReviewers(w.state, TREE, "nope", "b"), /no submission nope/);
});

test("drawFraction lies in (0, 1] and is a function of beacon and label", () => {
  for (const b of beacons(200)) {
    const u = drawFraction(b, "k");
    assert.ok(u > 0 && u <= 1, `u = ${u}`);
    assert.equal(drawFraction(b, "k"), u);
  }
  const h = sha256hex("b:k");
  assert.equal(drawFraction("b", "k"), Math.max(parseInt(h.slice(0, 13), 16), 1) / 16 ** 13);
});

// ---------------------------------------------------------------------------
// selectReviewers
// ---------------------------------------------------------------------------

test("selection is deterministic and survives a replay from disk", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const b = computeBeacon(w.state, "s1", "e");
  const first = selectReviewers(w.state, TREE, "s1", b);
  assert.equal(first.reviewers.length, 3);
  assert.deepEqual(selectReviewers(w.state, TREE, "s1", b), first);
  const reopened = Ledger.open(w.ledger.path).state();
  assert.deepEqual(selectReviewers(reopened, TREE, "s1", b), first);
  // A different beacon gives a different draw at least sometimes.
  const draws = new Set(beacons(20).map((x) => selectReviewers(w.state, TREE, "s1", x).reviewers.join(",")));
  assert.ok(draws.size > 1);
});

test("never picks the author's owner, near owners, inactive agents, or owners outside the tree", (t) => {
  const w = world();
  t.after(() => w.cleanup());
  w.agent("ag-o7-second", "o7", "gpt"); // the author's owner's other agent
  w.agent("ag-o9-revoked", "o9", "gpt");
  w.append({ kind: "agentRevoked", agent: w.id("ag-o9-revoked"), reason: "test" }, w.key("o9"));
  w.owner("outsider").agent("ag-outsider", "outsider", "gpt");
  w.submit("s1", "ag-o7");
  const st = w.state;
  const forbidden = new Set([w.id("ag-o7-second"), w.id("ag-o9-revoked"), w.id("ag-outsider")]);
  for (const b of beacons(400)) {
    const { reviewers, candidates, notes } = selectReviewers(st, TREE, "s1", b);
    assert.equal(reviewers.length, 3);
    assert.equal(candidates, ELIGIBLE.length);
    assert.ok(notes.some((n) => /1 owner\(s\) with active agents skipped: not in the tree/.test(n)));
    const owners = reviewers.map((k) => ownerOf(st, k));
    assert.equal(new Set(owners).size, owners.length, "one seat per owner");
    for (const k of reviewers) assert.ok(!forbidden.has(k), `picked forbidden ${k}`);
    for (const o of owners) {
      assert.ok(o !== "o7" && !NEAR.includes(o), `picked ${o}`);
      assert.ok(TREE.distance(o, "o7") > st.rules.minTreeDistance);
    }
  }
});

test("distant owners are drawn more often, in proportion to the capped weight", (t) => {
  // One seat: with Efraimidis–Spirakis the top score wins with probability w_i / Σw.
  const w = world({ rules: { assignedReviewers: 1, requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  const n = 4000;
  const counts = new Map<OwnerId, number>();
  for (const b of beacons(n)) {
    const { reviewers } = selectReviewers(st, TREE, "s1", b);
    assert.equal(reviewers.length, 1);
    const o = ownerOf(st, reviewers[0] as KeyId);
    counts.set(o, (counts.get(o) ?? 0) + 1);
  }
  const total = Object.values(WEIGHT).reduce((a, x) => a + x, 0);
  for (const [o, wt] of Object.entries(WEIGHT)) {
    const expected = (n * wt) / total;
    const got = counts.get(o) ?? 0;
    // ~5 standard deviations; a deterministic set of beacons, so no flakiness.
    const sd = Math.sqrt(expected * (1 - wt / total));
    assert.ok(Math.abs(got - expected) < 5 * sd, `${o}: got ${got}, expected ~${expected.toFixed(0)}`);
  }
  for (const o of NEAR) assert.equal(counts.get(o) ?? 0, 0);
  const far = (counts.get("o9") ?? 0) + (counts.get("o10") ?? 0) + (counts.get("o11") ?? 0);
  const close = (counts.get("o0") ?? 0) + (counts.get("o4") ?? 0);
  // Weights 6 vs 2: three times as many seats, give or take sampling noise.
  assert.ok(far > 2.4 * close, `far ${far} vs close ${close}`);
});

test("with three seats, distant owners still fill more seats than close ones", (t) => {
  const w = world({ rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  const counts = new Map<OwnerId, number>();
  for (const b of beacons(2000)) {
    for (const k of selectReviewers(st, TREE, "s1", b).reviewers) {
      const o = ownerOf(st, k);
      counts.set(o, (counts.get(o) ?? 0) + 1);
    }
  }
  const c = (o: string) => counts.get(o) ?? 0;
  assert.ok(c("o9") > 1.3 * c("o4") && c("o2") > 1.3 * c("o4"), `o9 ${c("o9")}, o2 ${c("o2")}, o4 ${c("o4")}`);
  assert.ok(c("o11") > 1.3 * c("o0"));
});

test("gaming: registering many agents does not buy an owner more seats", (t) => {
  const base = world().submit("s1", "ag-o7");
  const sybil = world().submit("s1", "ag-o7");
  t.after(() => {
    base.cleanup();
    sybil.cleanup();
  });
  for (let i = 0; i < 20; i++) sybil.agent(`o4-sybil-${i}`, "o4", "gpt");
  const seatsOf = (st: CommonsState, b: string) =>
    selectReviewers(st, TREE, "s1", b)
      .reviewers.map((k) => ownerOf(st, k))
      .sort();
  let o4Seats = 0;
  for (const b of beacons(500)) {
    const owners = seatsOf(sybil.state, b);
    assert.deepEqual(owners, seatsOf(base.state, b), "the owners drawn do not depend on agent count");
    if (owners.includes("o4")) o4Seats += 1;
  }
  assert.ok(o4Seats < 250, `o4 is a weight-1 owner and must not dominate (${o4Seats}/500)`);
});

test("model family: a lone other-family candidate always gets a seat", (t) => {
  // Everyone is claude like the author, except o4 (weight 1, rarely drawn on its own).
  const families = Object.fromEntries(OWNERS.map((o) => [o, o === "o4" ? "gpt" : "claude"]));
  const w = world({ families }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  let forced = 0;
  for (const b of beacons(300)) {
    const { reviewers, notes } = selectReviewers(st, TREE, "s1", b);
    assert.equal(reviewers.length, 3);
    assert.ok(reviewers.includes(w.id("ag-o4")), "the gpt reviewer is always present");
    if (notes.some((n) => n.includes("model family other than claude"))) forced += 1;
  }
  assert.ok(forced > 200, `the rule usually has to intervene (${forced})`);
});

test("model family: the rule is off when requireOtherModelFamily is false", (t) => {
  const families = Object.fromEntries(OWNERS.map((o) => [o, o === "o4" ? "gpt" : "claude"]));
  const w = world({ families, rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const without = beacons(300).filter((b) => !selectReviewers(w.state, TREE, "s1", b).reviewers.includes(w.id("ag-o4")));
  assert.ok(without.length > 100);
});

test("model family: an owner already seated switches to its other-family agent", (t) => {
  // Every agent is claude; o9 (a heavy owner) also runs a gpt agent.
  const families = Object.fromEntries(OWNERS.map((o) => [o, "claude"]));
  const w = world({ families });
  t.after(() => w.cleanup());
  w.agent("ag-o9-gpt", "o9", "gpt").submit("s1", "ag-o7");
  const st = w.state;
  for (const b of beacons(300)) {
    const { reviewers } = selectReviewers(st, TREE, "s1", b);
    assert.equal(reviewers.length, 3);
    assert.ok(reviewers.includes(w.id("ag-o9-gpt")));
    assert.ok(!reviewers.includes(w.id("ag-o9")), "o9 never holds two seats");
    const owners = reviewers.map((k) => ownerOf(st, k));
    assert.equal(new Set(owners).size, 3);
  }
});

test("model family: no other family anywhere gives a note, not a failure", (t) => {
  const families = Object.fromEntries(OWNERS.map((o) => [o, "claude"]));
  const w = world({ families }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers, notes } = selectReviewers(w.state, TREE, "s1", "b");
  assert.equal(reviewers.length, 3);
  assert.ok(notes.some((n) => /no eligible reviewer has a model family other than the author's \(claude\)/.test(n)));
});

test("too few candidates returns fewer reviewers with a note", (t) => {
  // Only o0 and o4 are more than 2 hops from o7 here.
  const small = treeFromParents({ o0: null, o1: "o0", o3: "o1", o4: "o1", o7: "o3", o8: "o3" });
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers, candidates, notes } = selectReviewers(w.state, small, "s1", "b");
  assert.deepEqual(reviewers.map((k) => ownerOf(w.state, k)).sort(), ["o0", "o4"]);
  assert.equal(candidates, 2);
  assert.ok(notes.some((n) => n.startsWith("only 2 of 3 reviewers")));
});

test("no candidates at all, or an author outside the tree, returns none", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const tiny = treeFromParents({ o3: null, o7: "o3", o8: "o3" });
  const none = selectReviewers(w.state, tiny, "s1", "b");
  assert.deepEqual(none.reviewers, []);
  assert.equal(none.candidates, 0);
  assert.ok(none.notes.some((n) => n.startsWith("only 0 of 3")));

  const withoutAuthor: TreeView = treeFromParents({ o0: null, o9: "o0", o10: "o0" });
  const r = selectReviewers(w.state, withoutAuthor, "s1", "b");
  assert.deepEqual(r.reviewers, []);
  assert.deepEqual(r.notes, ["author's owner o7 is not in the tree"]);
});

test("a larger minTreeDistance shrinks the pool", (t) => {
  const w = world({ rules: { minTreeDistance: 5 } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers, candidates } = selectReviewers(w.state, TREE, "s1", "b");
  assert.equal(candidates, 3); // o9, o10, o11 at distance 6
  assert.deepEqual(reviewers.map((k) => ownerOf(w.state, k)).sort(), ["o10", "o11", "o9"]);
});

// ---------------------------------------------------------------------------
// verifyAssignment
// ---------------------------------------------------------------------------

test("verifyAssignment accepts the honest draw and the ledger accepts it", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const beacon = computeBeacon(w.state, "s1", "drand-1");
  const { reviewers } = selectReviewers(w.state, TREE, "s1", beacon);
  w.assign("s1", beacon, reviewers);
  assert.equal(verifyAssignment(w.state, TREE, "s1"), true);
  assert.equal(verifyAssignment(Ledger.open(w.ledger.path).state(), TREE, "s1"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1"), true);
  // Order is not significant.
  const reordered = structuredClone(w.state);
  const a = reordered.submissions.get("s1")?.assignment;
  assert.ok(a);
  a.reviewers.reverse();
  assert.equal(verifyAssignment(reordered, TREE, "s1"), true);
});

test("gaming: a coordinator that hand-picks reviewers is caught", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const beacon = computeBeacon(w.state, "s1", "drand-1");
  const honest = selectReviewers(w.state, TREE, "s1", beacon).reviewers;
  // A ledger-valid but wrong list: swap one honest pick for another eligible agent.
  const other = ELIGIBLE.map((o) => w.id(`ag-${o}`)).find((k) => !honest.includes(k));
  assert.ok(other);
  const rigged = [...honest.slice(0, 2), other];
  w.assign("s1", beacon, rigged); // the ledger only checks owners, so it accepts this
  assert.equal(verifyAssignment(w.state, TREE, "s1"), false);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1"), false);
});

test("verifyAssignment detects tampered reviewer lists and beacons in a state", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const beacon = computeBeacon(w.state, "s1", "drand-1");
  const { reviewers } = selectReviewers(w.state, TREE, "s1", beacon);
  w.assign("s1", beacon, reviewers);
  const tamper = (f: (a: { beacon: string; reviewers: KeyId[] }) => void) => {
    const st = structuredClone(w.state);
    const a = st.submissions.get("s1")?.assignment;
    assert.ok(a);
    f(a);
    return verifyAssignment(st, TREE, "s1");
  };
  assert.equal(
    tamper((a) => a.reviewers.pop()),
    false,
    "dropped reviewer",
  );
  assert.equal(
    tamper((a) => a.reviewers.push(w.id("ag-o4"))),
    false,
    "extra reviewer",
  );
  assert.equal(
    tamper((a) => (a.reviewers[0] = w.id("ag-o3"))),
    false,
    "near owner swapped in",
  );
  assert.equal(
    tamper((a) => (a.reviewers = [reviewers[0] as KeyId, reviewers[0] as KeyId, reviewers[1] as KeyId])),
    false,
    "duplicate reviewer",
  );
  assert.equal(
    tamper((a) => (a.beacon = sha256hex("another"))),
    false,
    "different beacon, same reviewers",
  );
});

test("verifyAssignment is false without an assignment or submission", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  assert.equal(verifyAssignment(w.state, TREE, "s1"), false);
  assert.equal(verifyAssignment(w.state, TREE, "nope"), false);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1"), false);
});

test("verifyAssignmentInLedger audits an old assignment after the agent pool changed", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const beacon = computeBeacon(w.state, "s1", "drand-1");
  const { reviewers } = selectReviewers(w.state, TREE, "s1", beacon);
  w.assign("s1", beacon, reviewers);
  // Revoke a seated reviewer later: the current pool no longer yields the same draw.
  const seated = reviewers[0] as KeyId;
  const seatedOwner = ownerOf(w.state, seated);
  w.append({ kind: "agentRevoked", agent: seated, reason: "left" }, w.key(seatedOwner));
  assert.equal(verifyAssignment(w.state, TREE, "s1"), false, "current-state check is only exact while the pool is unchanged");
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1"), true);
});

test("verifyAssignmentInLedger with the entropy also checks how the beacon was derived", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const beacon = computeBeacon(w.state, "s1", "drand-7");
  w.assign("s1", beacon, selectReviewers(w.state, TREE, "s1", beacon).reviewers);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1", "drand-7"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1", "drand-8"), false);
});

test("gaming: a beacon chosen by the coordinator fails the entropy check even with a matching draw", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  // The coordinator grinds arbitrary beacons and records one; the draw itself is consistent.
  const ground = sha256hex("ground-42");
  w.assign("s1", ground, selectReviewers(w.state, TREE, "s1", ground).reviewers);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1"), true, "without the entropy this passes");
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), TREE, "s1", "drand-7"), false);
});

// ---------------------------------------------------------------------------
// The documented algorithm, reimplemented from the header of selection.ts, as
// a third-party verifier would. Exact integer comparison throughout.
// ---------------------------------------------------------------------------

function referenceRanking(tree: TreeView, author: OwnerId, owners: OwnerId[], beacon: string, n: number): OwnerId[] {
  const SPAN = 16n ** 13n;
  const scored: { owner: OwnerId; U: bigint; w: bigint }[] = [];
  for (const o of owners) {
    if (o === author) continue;
    const d = tree.distance(o, author);
    if (d <= n) continue;
    const lineal = d === Math.abs(tree.depth(o) - tree.depth(author));
    const w = lineal ? 1 : Math.min(d - n, MAX_WEIGHT);
    const raw = BigInt(`0x${sha256hex(`${beacon}:owner:${o}`).slice(0, 13)}`);
    scored.push({ owner: o, U: raw === 0n ? 1n : raw, w: BigInt(w) });
  }
  scored.sort((a, b) => {
    const l = a.U ** b.w * SPAN ** a.w;
    const r = b.U ** a.w * SPAN ** b.w;
    return l > r ? -1 : l < r ? 1 : 0;
  });
  return scored.map((x) => x.owner);
}

test("the draw matches an independent reimplementation of the documented algorithm", (t) => {
  const w = world({ rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  for (const b of beacons(300)) {
    const expected = referenceRanking(TREE, "o7", OWNERS, b, st.rules.minTreeDistance).slice(0, 3);
    const got = selectReviewers(st, TREE, "s1", b).reviewers.map((k) => ownerOf(st, k));
    assert.deepEqual(got, expected, `beacon ${b}`);
  }
});

// ---------------------------------------------------------------------------
// Gaming: long invite chains. Probe from review: socks at increasing distance
// used to hold increasing weights, so the longest chain won the most seats.
// ---------------------------------------------------------------------------

// r ─┬─ A (author) ── s1 ── s2 ── … ── s8          (a chain the author built)
//    ├─ q1 ── q2 ── … ── q8                         (a chain on a side branch)
//    ├─ h1 ── h1a ── h1b    (and h2…, h3…)          (ordinary members)
function chainTree() {
  const parents: Record<OwnerId, OwnerId | null> = { r: null, A: "r" };
  for (let i = 1; i <= 8; i++) parents[`s${i}`] = i === 1 ? "A" : `s${i - 1}`;
  for (let i = 1; i <= 8; i++) parents[`q${i}`] = i === 1 ? "r" : `q${i - 1}`;
  for (const h of ["h1", "h2", "h3"]) {
    parents[h] = "r";
    parents[`${h}a`] = h;
    parents[`${h}b`] = `${h}a`;
  }
  return { tree: treeFromParents(parents), owners: Object.keys(parents) };
}

test("gaming: a deep chain of invitees gains nothing from its depth", (t) => {
  const { tree, owners } = chainTree();
  const w = world({ owners, author: "A", rules: { assignedReviewers: 1, requireOtherModelFamily: false } });
  w.submit("s1", "ag-A");
  t.after(() => w.cleanup());
  const st = w.state;
  const counts = new Map<OwnerId, number>();
  const n = 4000;
  for (const b of beacons(n)) {
    const [k] = selectReviewers(st, tree, "s1", b).reviewers;
    assert.ok(k);
    const o = ownerOf(st, k);
    counts.set(o, (counts.get(o) ?? 0) + 1);
  }
  const c = (o: string) => counts.get(o) ?? 0;
  // Lineal socks s3..s8 (weight 1 each, however deep) vs an ordinary weight-1 member.
  for (const s of ["s3", "s8"]) assert.ok(Math.abs(c(s) - c("h1a")) < 90, `${s} ${c(s)} vs h1a ${c("h1a")}`);
  // The side chain: q3 and q8 both sit past the cap, so they hold the same weight.
  assert.ok(Math.abs(c("q8") - c("q3")) < 120, `q8 ${c("q8")} vs q3 ${c("q3")}`);
  assert.ok(c("h1b") > 1.4 * c("s8"), `a distant member beats the deepest lineal sock (${c("h1b")} vs ${c("s8")})`);
  // Total weight: s3..s8 = 6, q2 = 1, q3..q8 = 12, h*a = 3, h*b = 6 → 28. The
  // author's own chain is entitled to 6/28 of the seats, not the 21/42 an
  // uncapped weight would give it.
  const lineal = ["s3", "s4", "s5", "s6", "s7", "s8"].reduce((a, s) => a + c(s), 0);
  assert.ok(lineal < 0.27 * n, `lineal socks took ${lineal} of ${n}`);
});

test("gaming: with three seats the author's own chain rarely fills the panel", (t) => {
  const { tree, owners } = chainTree();
  const w = world({ owners, author: "A", rules: { requireOtherModelFamily: false } });
  w.submit("s1", "ag-A");
  t.after(() => w.cleanup());
  const st = w.state;
  let allSocks = 0;
  const n = 2000;
  for (const b of beacons(n)) {
    const owners = selectReviewers(st, tree, "s1", b).reviewers.map((k) => ownerOf(st, k));
    assert.equal(owners.length, 3);
    if (owners.every((o) => /^s\d$/.test(o))) allSocks += 1;
  }
  assert.ok(allSocks < 0.03 * n, `all-sock panels: ${allSocks} of ${n}`);
});

// ---------------------------------------------------------------------------
// Model family: which seat the rule takes and who gets it
// ---------------------------------------------------------------------------

test("model family: the lowest pick is replaced by the best-scored other-family agent", (t) => {
  // claude everywhere except o4, o0 (weight 1) and o2 (weight 2), which are gpt.
  const gpt = new Set(["o4", "o0", "o2"]);
  const families = Object.fromEntries(OWNERS.map((o) => [o, gpt.has(o) ? "gpt" : "claude"]));
  const on = world({ families }).submit("s1", "ag-o7");
  const off = world({ families, rules: { requireOtherModelFamily: false, assignedReviewers: OWNERS.length } });
  off.submit("s1", "ag-o7");
  t.after(() => {
    on.cleanup();
    off.cleanup();
  });
  // The same keys are not shared between worlds, so compare by owner.
  const ranked = (b: string) => selectReviewers(off.state, TREE, "s1", b).reviewers.map((k) => ownerOf(off.state, k));
  let intervened = 0;
  const bestOther = new Map<OwnerId, number>();
  for (const b of beacons(400)) {
    const full = ranked(b); // every eligible owner, best first
    const got = selectReviewers(on.state, TREE, "s1", b).reviewers.map((k) => ownerOf(on.state, k));
    const top = full.slice(0, 3);
    if (top.some((o) => gpt.has(o))) {
      assert.deepEqual(got, top, "no intervention when a gpt owner is drawn anyway");
      continue;
    }
    intervened += 1;
    const other = full.find((o) => gpt.has(o));
    assert.ok(other);
    bestOther.set(other, (bestOther.get(other) ?? 0) + 1);
    assert.deepEqual(got, [...top.slice(0, 2), other], `beacon ${b}: top two kept, third seat to ${other}`);
  }
  assert.ok(intervened > 100, `the rule intervened ${intervened} times`);
  assert.ok(bestOther.size > 1, "the test covers more than one possible other-family owner");
});

test("model family: case and spaces do not make a different family", (t) => {
  const families = Object.fromEntries(OWNERS.map((o, i) => [o, ["Claude", "claude ", " CLAUDE", "claude"][i % 4] as string]));
  const w = world({ families }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { notes } = selectReviewers(w.state, TREE, "s1", "b");
  assert.ok(notes.some((n) => /no eligible reviewer has a model family other than the author's \(claude\)/.test(n)), notes.join("; "));
  assert.ok(!notes.some((n) => n.startsWith("seat given")));
});

// ---------------------------------------------------------------------------
// Owner identity follows the tree
// ---------------------------------------------------------------------------

// Mimics the Anthill readers: ids are case-insensitive, queries fold to lowercase.
function foldingTree(parents: Record<OwnerId, OwnerId | null>): TreeView {
  const t = treeFromParents(parents);
  const f = (id: OwnerId) => id.toLowerCase();
  return {
    root: () => t.root(),
    has: (id) => t.has(f(id)),
    parent: (id) => t.parent(f(id)),
    children: (id) => t.children(f(id)),
    depth: (id) => t.depth(f(id)),
    distance: (a, b) => t.distance(f(a), f(b)),
    members: () => t.members(),
    reputation: (id) => t.reputation(f(id)),
  };
}

test("gaming: one member registered under two spellings holds one ticket and one seat", (t) => {
  const tree = foldingTree(PARENTS);
  const base = world({ rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  const twice = world({ rules: { requireOtherModelFamily: false } });
  twice.owner("O9").agent("ag-O9", "O9", "gpt").submit("s1", "ag-o7");
  t.after(() => {
    base.cleanup();
    twice.cleanup();
  });
  const seats = (st: CommonsState, b: string) =>
    selectReviewers(st, tree, "s1", b)
      .reviewers.map((k) => ownerOf(st, k).toLowerCase())
      .sort();
  for (const b of beacons(400)) {
    const sel = selectReviewers(twice.state, tree, "s1", b);
    assert.equal(sel.candidates, ELIGIBLE.length, "O9 and o9 are one candidate");
    const owners = seats(twice.state, b);
    assert.equal(new Set(owners).size, owners.length, `two seats for o9: ${owners.join(",")}`);
    assert.deepEqual(owners, seats(base.state, b), "the second spelling buys no extra ticket");
  }
});

test("an author registered under another spelling is still excluded", (t) => {
  const tree = foldingTree(PARENTS);
  const w = world();
  t.after(() => w.cleanup());
  w.owner("O7").agent("ag-O7", "O7", "gpt").submit("s1", "ag-o7");
  for (const b of beacons(200)) {
    assert.ok(!selectReviewers(w.state, tree, "s1", b).reviewers.includes(w.id("ag-O7")));
  }
});
