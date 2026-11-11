import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger, LedgerError, type Signer } from "../src/ledger";
import { defaultRules, phase1Rules } from "../src/rules";
import { assignmentBeacon } from "../src/review";
import {
  MAX_WEIGHT,
  assignmentBody,
  computeBeacon,
  drawAssignment,
  drawFraction,
  selectReviewers,
  verifyAssignment,
  verifyAssignmentInLedger,
} from "../src/selection";
import { MEMBER_ROOT, memberDigest, memberTree, treeDigest, treeFromParents } from "../src/members";
import type { CommonsState, EntryBody, KeyId, OwnerId, Rules, TreeView } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture. Twelve owners o0..o11, each admitted with its inviter (o0 with
// none, so it hangs under the member tree's virtual root); the author is o7:
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
// The member tree the fixture's ownerKey entries must give, built
// independently of memberTree.
const TREE = treeFromParents({ [MEMBER_ROOT]: null, ...PARENTS, o0: MEMBER_ROOT });
const DIGEST = treeDigest(TREE);
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
        project: "demo",
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

  owner(owner: OwnerId, inviter: OwnerId | null = null): this {
    this.append({ kind: "ownerKey", owner, publicKey: this.key(owner).publicKey, inviter }, this.admin);
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
        changedFiles: ["src/feature.ts"],
        linesChanged: 10,
      },
      this.key(agent),
    );
    return this;
  }

  // The beacon follows from the entropy and the member tree's digest; the ledger checks both.
  assign(submissionId: string, entropy: string, reviewers: KeyId[]) {
    return this.append(assignmentBody(this.state, submissionId, reviewers, entropy), this.coord);
  }

  cleanup(): void {
    fs.rmSync(this.dir, { recursive: true, force: true });
  }
}

// Every owner admitted with its inviter from `parents` (null: none; parents
// come before their invitees); one agent each (`ag-<owner>`). The author agent
// is `ag-o7` (claude); everyone else is "gpt" unless `families` says
// otherwise. `parents` and `author` replace the fixture's for tests with their
// own tree; `owners` alone admits them all with no inviter (an allowlist).
function world(
  opts: {
    rules?: Partial<Rules>;
    families?: Record<string, string>;
    owners?: string[];
    parents?: Record<OwnerId, OwnerId | null>;
    author?: string;
  } = {},
): World {
  const w = new World(opts.rules);
  const parents = opts.parents ?? (opts.owners ? Object.fromEntries(opts.owners.map((o) => [o, null])) : PARENTS);
  const owners = Object.keys(parents);
  const author = opts.author ?? "o7";
  for (const o of owners) w.owner(o, parents[o] ?? null);
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

test("computeBeacon is sha256 of the canonical submission id, head commit and entropy", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  const expected = sha256hex(canonical({ submission: "s1", head: "head-s1", entropy: "drand-123" }));
  assert.equal(computeBeacon(st, "s1", "drand-123"), expected);
  assert.equal(assignmentBeacon("s1", "head-s1", "drand-123"), expected);
  assert.equal(computeBeacon(st, "s1", "drand-123"), expected, "deterministic");
  assert.notEqual(computeBeacon(st, "s1", "drand-124"), expected, "entropy matters");
  assert.notEqual(assignmentBeacon("s1", "head-s2", "drand-123"), expected, "the head commit matters");
});

// Regression: the beacon used to include the member tree's digest, which an
// owner admitted between the submission and the draw changes. With a public
// round, the admin could try owner ids offline and admit the one whose digest
// seated the reviewers it wanted, and the coordinator could pick between two
// beacons by drawing before or after a pending admission.
test("gaming: admitting owners between the submission and the draw moves neither the beacon nor the draw", (t) => {
  const w = world({ rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const before = drawAssignment(w.state, "s1", "drand-4242");
  const digestBefore = memberDigest(w.state);
  for (let i = 0; i < 6; i++) {
    w.owner(`newbie-${i}`, i % 2 === 0 ? null : "o11");
    const now = drawAssignment(w.state, "s1", "drand-4242");
    assert.equal(now.body.beacon, before.body.beacon, `after admitting newbie-${i}`);
    assert.deepEqual(now.reviewers, before.reviewers, `after admitting newbie-${i}`);
  }
  assert.notEqual(memberDigest(w.state), digestBefore, "the digest still records the tree at the draw");
  // The later draw is the one appended; it verifies, with the public round too.
  w.append(drawAssignment(w.state, "s1", "drand-4242").body, w.coord);
  assert.equal(verifyAssignment(w.state, "s1"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1", "drand-4242"), true);
});

test("computeBeacon ignores the ledger head (the coordinator controls it) and binds the submission", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const before = computeBeacon(w.state, "s1", "e");
  w.submit("s2", "ag-o7");
  assert.equal(computeBeacon(w.state, "s1", "e"), before, "padding the ledger does not move the beacon");
  assert.notEqual(computeBeacon(w.state, "s2", "e"), computeBeacon(w.state, "s1", "e"));
});

test("the draw's tree is the member tree of the ownerKey entries; its digest is the canonical parent map", (t) => {
  const w = world();
  t.after(() => w.cleanup());
  assert.equal(memberDigest(w.state), DIGEST);
  assert.equal(DIGEST, sha256hex(canonical({ [MEMBER_ROOT]: null, ...PARENTS, o0: MEMBER_ROOT })));
  const tree = memberTree(w.state);
  for (const a of OWNERS) for (const b of OWNERS) assert.equal(tree.distance(a, b), TREE.distance(a, b), `${a}-${b}`);
  assert.notEqual(treeDigest(treeFromParents({ [MEMBER_ROOT]: null, ...PARENTS, o0: MEMBER_ROOT, o11: "o5" })), DIGEST, "a moved member changes it");
});

test("computeBeacon and selectReviewers throw on an unknown submission", (t) => {
  const w = world();
  t.after(() => w.cleanup());
  assert.throws(() => computeBeacon(w.state, "nope", "e"), /no submission nope/);
  assert.throws(() => selectReviewers(w.state, "nope", "b"), /no submission nope/);
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
  const first = selectReviewers(w.state, "s1", b);
  assert.equal(first.reviewers.length, 3);
  assert.deepEqual(selectReviewers(w.state, "s1", b), first);
  const reopened = Ledger.open(w.ledger.path).state();
  assert.deepEqual(selectReviewers(reopened, "s1", b), first);
  // A different beacon gives a different draw at least sometimes.
  const draws = new Set(beacons(20).map((x) => selectReviewers(w.state, "s1", x).reviewers.join(",")));
  assert.ok(draws.size > 1);
});

test("never picks the author's owner, near owners, inactive agents, or the author's invitees", (t) => {
  const w = world();
  t.after(() => w.cleanup());
  w.agent("ag-o7-second", "o7", "gpt"); // the author's owner's other agent
  w.agent("ag-o9-revoked", "o9", "gpt");
  w.append({ kind: "agentRevoked", agent: w.id("ag-o9-revoked"), reason: "test" }, w.key("o9"));
  w.owner("invitee", "o7").agent("ag-invitee", "invitee", "gpt"); // distance 1 from the author
  w.submit("s1", "ag-o7");
  const st = w.state;
  const forbidden = new Set([w.id("ag-o7-second"), w.id("ag-o9-revoked"), w.id("ag-invitee")]);
  for (const b of beacons(400)) {
    const { reviewers, candidates } = selectReviewers(st, "s1", b);
    assert.equal(reviewers.length, 3);
    assert.equal(candidates, ELIGIBLE.length);
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
    const { reviewers } = selectReviewers(st, "s1", b);
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
    for (const k of selectReviewers(st, "s1", b).reviewers) {
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
    selectReviewers(st, "s1", b)
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

// This test used to assert the opposite ("a lone other-family candidate
// always gets a seat"). That was the hole: families are self-declared and
// agents free, so one owner declaring a family nobody else runs bought a seat
// on every majority-family submission, whatever its draw or distance.
test("regression: a lone other-family owner is not forced into a seat; it is drawn like everyone else", (t) => {
  // Everyone is claude like the author, except o4 (weight 1, rarely drawn on its own).
  const families = Object.fromEntries(OWNERS.map((o) => [o, o === "o4" ? "gpt" : "claude"]));
  const w = world({ families }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  let seated = 0;
  for (const b of beacons(300)) {
    const { reviewers, notes } = selectReviewers(st, "s1", b);
    assert.equal(reviewers.length, 3);
    if (reviewers.includes(w.id("ag-o4"))) seated += 1;
    else assert.ok(notes.some((n) => /only o4 offers a model family other than claude; no seat is forced/.test(n)), notes.join("; "));
  }
  assert.ok(seated > 0 && seated < 200, `o4 is seated by its draw only (${seated} of 300)`);
});

test("model family: the rule is off when requireOtherModelFamily is false", (t) => {
  const families = Object.fromEntries(OWNERS.map((o) => [o, o === "o4" ? "gpt" : "claude"]));
  const w = world({ families, rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const without = beacons(300).filter((b) => !selectReviewers(w.state, "s1", b).reviewers.includes(w.id("ag-o4")));
  assert.ok(without.length > 100);
});

test("model family: an owner already seated switches to its other-family agent, and is not seated otherwise", (t) => {
  // Every agent is claude; o9 (a heavy owner) also runs a gpt agent.
  const families = Object.fromEntries(OWNERS.map((o) => [o, "claude"]));
  const w = world({ families });
  t.after(() => w.cleanup());
  w.agent("ag-o9-gpt", "o9", "gpt").submit("s1", "ag-o7");
  const st = w.state;
  let seated = 0;
  for (const b of beacons(300)) {
    const { reviewers } = selectReviewers(st, "s1", b);
    assert.equal(reviewers.length, 3);
    assert.ok(!reviewers.includes(w.id("ag-o9")), "a seated o9 always sits with its gpt agent");
    if (reviewers.includes(w.id("ag-o9-gpt"))) seated += 1;
    const owners = reviewers.map((k) => ownerOf(st, k));
    assert.equal(new Set(owners).size, 3);
  }
  assert.ok(seated > 0 && seated < 300, `o9 holds a seat only when drawn (${seated} of 300)`);
});

test("model family: no other family anywhere gives a note, not a failure", (t) => {
  const families = Object.fromEntries(OWNERS.map((o) => [o, "claude"]));
  const w = world({ families }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers, notes } = selectReviewers(w.state, "s1", "b");
  assert.equal(reviewers.length, 3);
  assert.ok(notes.some((n) => /no eligible reviewer has a model family other than the author's \(claude\)/.test(n)));
});

test("too few candidates returns fewer reviewers with a note", (t) => {
  // Only o0 and o4 are more than 2 hops from o7 here.
  const w = world({ parents: { o0: null, o1: "o0", o3: "o1", o4: "o1", o7: "o3", o8: "o3" } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers, candidates, notes } = selectReviewers(w.state, "s1", "b");
  assert.deepEqual(reviewers.map((k) => ownerOf(w.state, k)).sort(), ["o0", "o4"]);
  assert.equal(candidates, 2);
  assert.ok(notes.some((n) => n.startsWith("only 2 of 3 reviewers")));
});

test("no candidates at all returns none; a hand-built state with an owner outside the tree stops the draw", (t) => {
  const tiny = world({ parents: { o3: null, o7: "o3", o8: "o3" } }).submit("s1", "ag-o7");
  t.after(() => tiny.cleanup());
  const none = selectReviewers(tiny.state, "s1", "b");
  assert.deepEqual(none.reviewers, []);
  assert.equal(none.candidates, 0);
  assert.ok(none.notes.some((n) => n.startsWith("only 0 of 3")));

  // The ledger registers agents only under owners, so an agent whose owner
  // is not in the member tree exists only in a corrupt, hand-built state.
  // No distance is guessed for it: the draw throws.
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const withoutO9 = structuredClone(w.state);
  withoutO9.owners.delete("o9");
  assert.throws(() => selectReviewers(withoutO9, "s1", "b"), /unknown member o9/);
  const withoutAuthor = structuredClone(w.state);
  withoutAuthor.owners.delete("o7");
  assert.throws(() => selectReviewers(withoutAuthor, "s1", "b"), /unknown member o7/);
});

test("a larger minTreeDistance shrinks the pool", (t) => {
  const w = world({ rules: { minTreeDistance: 5 } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers, candidates } = selectReviewers(w.state, "s1", "b");
  assert.equal(candidates, 3); // o9, o10, o11 at distance 6
  assert.deepEqual(reviewers.map((k) => ownerOf(w.state, k)).sort(), ["o10", "o11", "o9"]);
});

// ---------------------------------------------------------------------------
// verifyAssignment
// ---------------------------------------------------------------------------

test("verifyAssignment accepts the honest draw and the ledger accepts it", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const drawn = drawAssignment(w.state, "s1", "drand-1");
  const { reviewers } = selectReviewers(w.state, "s1", computeBeacon(w.state, "s1", "drand-1"));
  assert.deepEqual(drawn.reviewers, reviewers);
  assert.deepEqual(drawn.body, assignmentBody(w.state, "s1", reviewers, "drand-1"));
  w.append(drawn.body, w.coord);
  assert.equal(verifyAssignment(w.state, "s1"), true);
  assert.equal(verifyAssignment(Ledger.open(w.ledger.path).state(), "s1"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1"), true);
  // Order is not significant.
  const reordered = structuredClone(w.state);
  const a = reordered.submissions.get("s1")?.assignment;
  assert.ok(a);
  a.reviewers.reverse();
  assert.equal(verifyAssignment(reordered, "s1"), true);
});

test("regression: agents registered after the submission are not drawn, so a registration cannot be timed to a winning draw", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const atSubmission = drawAssignment(w.state, "s1", "drand-1").reviewers;
  // Once the round is public, every eligible owner adds an agent of a new
  // family (which would also win the other-family seat).
  for (const o of ELIGIBLE) w.agent(`late-${o}`, o, "qwen");
  const later = drawAssignment(w.state, "s1", "drand-1");
  assert.deepEqual(later.reviewers, atSubmission, "the late agents change nothing");
  // An assignment that seats one of them anyway does not verify.
  w.assign("s1", "drand-1", [...atSubmission.slice(0, -1), w.id(`late-${ELIGIBLE.find((o) => !atSubmission.includes(w.id(`ag-${o}`))) ?? ""}`)]);
  assert.equal(verifyAssignment(w.state, "s1"), false);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1"), false);
});

test("gaming: a coordinator that hand-picks reviewers is caught", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const honest = drawAssignment(w.state, "s1", "drand-1").reviewers;
  // A ledger-valid but wrong list: swap one honest pick for another eligible agent.
  const other = ELIGIBLE.map((o) => w.id(`ag-${o}`)).find((k) => !honest.includes(k));
  assert.ok(other);
  const rigged = [...honest.slice(0, 2), other];
  w.assign("s1", "drand-1", rigged); // the ledger checks the beacon and owners, not the draw, so it accepts this
  assert.equal(verifyAssignment(w.state, "s1"), false);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1"), false);
});

test("verifyAssignment detects tampered reviewer lists and beacons in a state", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers } = drawAssignment(w.state, "s1", "drand-1");
  w.assign("s1", "drand-1", reviewers);
  type A = { beacon: string; entropy: string; treeDigest: string; reviewers: KeyId[] };
  const tamper = (f: (a: A) => void) => {
    const st = structuredClone(w.state);
    const a = st.submissions.get("s1")?.assignment;
    assert.ok(a);
    f(a);
    return verifyAssignment(st, "s1");
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
  assert.equal(
    tamper((a) => (a.entropy = "drand-2")),
    false,
    "entropy that does not give the beacon",
  );
  assert.equal(
    tamper((a) => (a.treeDigest = sha256hex("another tree"))),
    false,
    "another tree's digest",
  );
});

test("verification rebuilds the tree from the ledger before the assignment: owners admitted later change nothing", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  w.append(drawAssignment(w.state, "s1", "drand-1").body, w.coord);
  w.owner("o12", "o11").agent("ag-o12", "o12", "qwen").owner("o13");
  assert.notEqual(memberDigest(w.state), DIGEST, "the current tree has grown");
  assert.equal(verifyAssignment(w.state, "s1"), true);
  assert.equal(verifyAssignment(Ledger.open(w.ledger.path).state(), "s1"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1"), true);
});

test("gaming: the ledger refuses a draw over any tree but the member tree", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  // A coordinator that draws over a tree of its own making (here: o4 moved
  // far from the author) records that tree's digest and a beacon consistent
  // with the entry.
  const made = treeDigest(treeFromParents({ [MEMBER_ROOT]: null, ...PARENTS, o0: MEMBER_ROOT, o4: "o11" }));
  const honest = drawAssignment(w.state, "s1", "drand-1").body;
  const body = { ...honest, treeDigest: made, beacon: assignmentBeacon("s1", "head-s1", "drand-1") };
  assert.throws(
    () => w.append(body, w.coord),
    (e: unknown) => e instanceof LedgerError && e.code === "invalid-value" && /treeDigest/.test(e.message),
  );
  assert.equal(w.state.submissions.get("s1")?.assignment, undefined);
});

test("verifyAssignment is false without an assignment or submission", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  assert.equal(verifyAssignment(w.state, "s1"), false);
  assert.equal(verifyAssignment(w.state, "nope"), false);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1"), false);
});

test("verifyAssignmentInLedger audits an old assignment after the agent pool changed", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const { reviewers } = drawAssignment(w.state, "s1", "drand-1");
  w.assign("s1", "drand-1", reviewers);
  // Revoke a seated reviewer later, register a new agent and change the
  // rules: the current pool and rules no longer yield the same draw, but both
  // checks recompute over the pool and rules as they were at the assignment.
  const seated = reviewers[0] as KeyId;
  const seatedOwner = ownerOf(w.state, seated);
  w.append({ kind: "agentRevoked", agent: seated, reason: "left" }, w.key(seatedOwner));
  w.agent("ag-o2-new", "o2", "qwen");
  w.append({ kind: "rulesChange", rules: { ...w.state.rules, version: 2, assignedReviewers: 2 }, pollId: "p1" }, w.admin);
  const now = selectReviewers(w.state, "s1", computeBeacon(w.state, "s1", "drand-1")).reviewers;
  assert.notDeepEqual([...now].sort(), [...reviewers].sort(), "the current pool draws differently");
  assert.equal(verifyAssignment(w.state, "s1"), true);
  assert.equal(verifyAssignment(Ledger.open(w.ledger.path).state(), "s1"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1"), true);
});

test("verifyAssignmentInLedger with the entropy also checks how the beacon was derived", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  w.append(drawAssignment(w.state, "s1", "drand-7").body, w.coord);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1", "drand-7"), true);
  assert.equal(verifyAssignmentInLedger(w.ledger.entries(), "s1", "drand-8"), false);
});

test("gaming: the ledger refuses a beacon the coordinator chose", (t) => {
  const w = world().submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  // The coordinator grinds arbitrary beacons and records one with a consistent draw.
  const ground = sha256hex("ground-42");
  const body = { ...assignmentBody(w.state, "s1", selectReviewers(w.state, "s1", ground).reviewers, "drand-7"), beacon: ground };
  assert.throws(() => w.append(body, w.coord), (e: unknown) => e instanceof LedgerError && e.code === "invalid-value");
  assert.equal(w.state.submissions.get("s1")?.assignment, undefined);
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
    // Paths that meet only at the virtual root: different invite lines.
    const otherLine = d === tree.depth(o) + tree.depth(author);
    const w = lineal ? 1 : otherLine ? MAX_WEIGHT : Math.min(d - n, MAX_WEIGHT);
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
    const got = selectReviewers(st, "s1", b).reviewers.map((k) => ownerOf(st, k));
    assert.deepEqual(got, expected, `beacon ${b}`);
  }
});

test("the draw matches the reimplementation over a forest of invite lines", (t) => {
  // Three invite lines under the virtual root; the author o7 sits in the first.
  const parents: Record<OwnerId, OwnerId | null> = { ...PARENTS, x0: null, x1: "x0", x2: "x1", y0: null };
  const w = world({ parents, rules: { requireOtherModelFamily: false } }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  const st = w.state;
  const tree = memberTree(st);
  for (const b of beacons(300)) {
    const expected = referenceRanking(tree, "o7", Object.keys(parents), b, st.rules.minTreeDistance).slice(0, 3);
    const got = selectReviewers(st, "s1", b).reviewers.map((k) => ownerOf(st, k));
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
  return parents;
}

test("gaming: a deep chain of invitees gains nothing from its depth", (t) => {
  const w = world({ parents: chainTree(), author: "A", rules: { assignedReviewers: 1, requireOtherModelFamily: false } });
  w.submit("s1", "ag-A");
  t.after(() => w.cleanup());
  const st = w.state;
  const counts = new Map<OwnerId, number>();
  const n = 4000;
  for (const b of beacons(n)) {
    const [k] = selectReviewers(st, "s1", b).reviewers;
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
  const w = world({ parents: chainTree(), author: "A", rules: { requireOtherModelFamily: false } });
  w.submit("s1", "ag-A");
  t.after(() => w.cleanup());
  const st = w.state;
  let allSocks = 0;
  const n = 2000;
  for (const b of beacons(n)) {
    const owners = selectReviewers(st, "s1", b).reviewers.map((k) => ownerOf(st, k));
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
  const ranked = (b: string) => selectReviewers(off.state, "s1", b).reviewers.map((k) => ownerOf(off.state, k));
  let intervened = 0;
  const bestOther = new Map<OwnerId, number>();
  for (const b of beacons(400)) {
    const full = ranked(b); // every eligible owner, best first
    const got = selectReviewers(on.state, "s1", b).reviewers.map((k) => ownerOf(on.state, k));
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

test("model family: the ledger takes only the closed list, and case and spaces are one family", (t) => {
  const w = world({ families: Object.fromEntries(OWNERS.map((o) => [o, "claude"])) }).submit("s1", "ag-o7");
  t.after(() => w.cleanup());
  for (const spelling of ["Claude", "claude ", "anthropic"]) {
    assert.throws(() => w.agent(`x-${spelling}`, "o0", spelling), (e: unknown) => e instanceof LedgerError && e.code === "invalid-value");
  }
  // A hand-built state can still hold other spellings; selection folds them.
  const st = structuredClone(w.state);
  [...st.agents.values()].forEach((a, i) => (a.modelFamily = ["Claude", "claude ", " CLAUDE", "claude"][i % 4] as string));
  const { notes } = selectReviewers(st, "s1", "b");
  assert.ok(notes.some((n) => /no eligible reviewer has a model family other than the author's \(claude\)/.test(n)), notes.join("; "));
  assert.ok(!notes.some((n) => n.startsWith("seat given")));
});

// ---------------------------------------------------------------------------
// Owner identity: one person, one spelling
// ---------------------------------------------------------------------------

// One member registered under two spellings would hold two tickets and two
// seats, or dodge the author exclusion. The ledger now refuses the second
// spelling (owner ids ignore case), so such a state cannot be replayed; these
// tests used to build it and check selection's own folding.
test("gaming: a member cannot register a second spelling to hold a second ticket", (t) => {
  const twice = world({ rules: { requireOtherModelFamily: false } });
  t.after(() => twice.cleanup());
  assert.throws(() => twice.owner("O9"), (e: unknown) => e instanceof LedgerError && e.code === "duplicate-id");
});

test("an author cannot register another spelling to escape exclusion", (t) => {
  const w = world();
  t.after(() => w.cleanup());
  assert.throws(() => w.owner("O7"), (e: unknown) => e instanceof LedgerError && e.code === "duplicate-id");
});

// ---------------------------------------------------------------------------
// Phase 1: an allowlist, i.e. owners the admin admitted with no inviter
// ---------------------------------------------------------------------------

test("over an allowlist the default minTreeDistance leaves no candidates, with a note", (t) => {
  const owners = ["alice", "bob", "carol"];
  const w = world({ owners, author: "alice" }).submit("s1", "ag-alice");
  t.after(() => w.cleanup());
  const r = selectReviewers(w.state, "s1", sha256hex("b"));
  assert.deepEqual(r.reviewers, []);
  assert.equal(r.candidates, 0);
  assert.ok(r.notes.some((n) => /farther than 2/.test(n)), r.notes.join("; "));
});

test("over an allowlist with phase1Rules every non-author owner is eligible, drawn uniformly", (t) => {
  const owners = ["alice", "bob", "carol", "dave"];
  const w = world({ owners, author: "alice", rules: { ...phase1Rules(), assignedReviewers: 1 } }).submit("s1", "ag-alice");
  t.after(() => w.cleanup());
  const counts = new Map<OwnerId, number>();
  for (const b of beacons(600)) {
    const r = selectReviewers(w.state, "s1", b);
    assert.equal(r.candidates, 3);
    assert.equal(r.reviewers.length, 1);
    const o = ownerOf(w.state, r.reviewers[0] as KeyId);
    counts.set(o, (counts.get(o) ?? 0) + 1);
  }
  assert.deepEqual([...counts.keys()].sort(), ["bob", "carol", "dave"]);
  // Expected 200 each (sd about 12); equal weights, not a tilt toward anyone.
  for (const [o, n] of counts) assert.ok(n > 150 && n < 250, `${o} drawn ${n} of 600`);
});

test("phase1Rules over a 3-person allowlist draws both other owners, and the draw verifies", (t) => {
  const owners = ["alice", "bob", "carol"];
  const w = world({ owners, author: "alice", rules: phase1Rules() }).submit("s1", "ag-alice");
  t.after(() => w.cleanup());
  const r = selectReviewers(w.state, "s1", computeBeacon(w.state, "s1", "e1"));
  assert.deepEqual(r.reviewers.map((k) => ownerOf(w.state, k)).sort(), ["bob", "carol"]);
  w.assign("s1", "e1", r.reviewers);
  assert.equal(verifyAssignment(w.state, "s1"), true);
  w.owner("dave");
  assert.equal(verifyAssignment(w.state, "s1"), true, "a later admission does not change the recorded tree");
});

// Regression: distance through the virtual root used to count toward the
// weight, so an owner admitted under an inviter (distance 3 from everyone
// outside its line) held twice the tickets of owners admitted with none
// (distance 2).
test("phase1Rules: an owner admitted under an inviter gets the same seat share as owners admitted with none", (t) => {
  const parents = { alice: null, bob: "alice", carol: null, dave: null };
  const w = world({ parents, author: "carol", rules: { ...phase1Rules(), assignedReviewers: 1, requireOtherModelFamily: false } });
  w.submit("s1", "ag-carol");
  t.after(() => w.cleanup());
  const tree = memberTree(w.state);
  assert.equal(tree.distance("bob", "carol"), 3);
  assert.equal(tree.distance("alice", "carol"), 2);
  const counts = new Map<OwnerId, number>();
  const n = 3000;
  for (const b of beacons(n)) {
    const [k] = selectReviewers(w.state, "s1", b).reviewers;
    assert.ok(k);
    const o = ownerOf(w.state, k);
    counts.set(o, (counts.get(o) ?? 0) + 1);
  }
  assert.deepEqual([...counts.keys()].sort(), ["alice", "bob", "dave"]);
  // Expected 1000 each (sd about 26); the old weights gave bob about 1500.
  for (const [o, c] of counts) assert.ok(c > 900 && c < 1100, `${o} drawn ${c} of ${n}`);
});

test("an inviter and its invitee are too close to review each other under phase1Rules", (t) => {
  const w = world({ parents: { alice: null, bob: "alice", carol: null }, author: "alice", rules: phase1Rules() }).submit("s1", "ag-alice");
  t.after(() => w.cleanup());
  const r = selectReviewers(w.state, "s1", sha256hex("b"));
  assert.deepEqual(r.reviewers.map((k) => ownerOf(w.state, k)), ["carol"]);
});

test("regression: an owner that committed openly before the draw is seated through the agent that committed, never an unfillable one", (t) => {
  const owners = ["alice", "bob", "carol"];
  const w = world({ owners, author: "alice", rules: phase1Rules() });
  t.after(() => w.cleanup());
  w.agent("ag-bob-2", "bob", "gemini").agent("ag-carol-2", "carol", "claude");
  w.submit("s1", "ag-alice");
  const commit = (agent: string, n: number) =>
    w.append({ kind: "reviewCommit", submissionId: "s1", commitment: sha256hex(`c${n}`), stake: 5 }, w.key(agent));
  commit("ag-bob-2", 1);
  commit("ag-carol", 2);
  // Over many beacons, bob's seat is always ag-bob-2 and carol's ag-carol.
  for (const b of beacons(64)) {
    const r = selectReviewers(w.state, "s1", b);
    assert.deepEqual(new Set(r.reviewers), new Set([w.id("ag-bob-2"), w.id("ag-carol")]));
  }
  // The ledger refuses a seat for an owner's other agent.
  assert.throws(() => w.assign("s1", "e1", [w.id("ag-bob"), w.id("ag-carol")]), /already committed through/);
  const d = drawAssignment(w.state, "s1", "e1");
  w.append(d.body, w.coord);
  assert.equal(verifyAssignment(w.state, "s1"), true);
  // After the draw, another agent of a seated owner cannot take the commit.
  w.submit("s2", "ag-alice");
  w.append(drawAssignment(w.state, "s2", "e2").body, w.coord);
  const seated = w.state.submissions.get("s2")?.assignment?.reviewers ?? [];
  const bobSeat = seated.find((k) => ownerOf(w.state, k) === "bob");
  const other = bobSeat === w.id("ag-bob") ? "ag-bob-2" : "ag-bob";
  assert.throws(
    () => w.append({ kind: "reviewCommit", submissionId: "s2", commitment: sha256hex("c3"), stake: 5 }, w.key(other)),
    /seat on s2 is/,
  );
});
