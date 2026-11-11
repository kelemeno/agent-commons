import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import {
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
//   o0 ─┬─ o1 ─┬─ o3 ─┬─ o7 (author)       distance from o7, weight (N = 2)
//       │      │      └─ o8                 o3 1 ✗, o1 2 ✗, o8 2 ✗
//       │      └─ o4                        o4 3 w1, o0 3 w1, o2 4 w2
//       └─ o2 ─┬─ o5 ─┬─ o9                 o5 5 w3, o6 5 w3
//              │      └─ o10                o9 6 w4, o10 6 w4, o11 6 w4
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
const WEIGHT: Record<string, number> = { o0: 1, o4: 1, o2: 2, o5: 3, o6: 3, o9: 4, o10: 4, o11: 4 };
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
function world(opts: { rules?: Partial<Rules>; families?: Record<string, string> } = {}): World {
  const w = new World(opts.rules);
  for (const o of OWNERS) w.owner(o);
  for (const o of OWNERS) w.agent(`ag-${o}`, o, opts.families?.[o] ?? (o === "o7" ? "claude" : "gpt"));
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

test("distant owners are drawn more often, in proportion to distance minus N", (t) => {
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
  assert.ok(far > 4 * close, `far ${far} vs close ${close}`);
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
  assert.ok(c("o9") > c("o2") && c("o2") > c("o4"), `o9 ${c("o9")}, o2 ${c("o2")}, o4 ${c("o4")}`);
  assert.ok(c("o11") > 1.5 * c("o0"));
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
