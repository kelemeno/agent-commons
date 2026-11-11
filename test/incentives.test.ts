import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, signEntry, submissionDead, type LedgerState, type Signer } from "../src/ledger";
import { claimStake as rulesClaimStake, defaultRules, phase1Rules } from "../src/rules";
import { memberTree } from "../src/members";
import {
  apportion,
  claimStake,
  duplicateShares,
  prSlots,
  settleCleanReviews,
  settleExpiredClaims,
  settleFalseFinding,
  settleFinding,
  settleHoneytoken,
  settleMerge,
  settleMissedPlant,
  submitCredits,
  type SettlementBody,
} from "../src/incentives";
import type { EntryBody, OwnerId, ReviewVerdict, Rules, Severity } from "../src/types";
import { assignmentBody } from "../src/selection";
import { commitmentFor } from "../src/review";
import { plantCaught, plantCaughtBy, reviewWindowCloseSeq } from "../src/plants";

// ---------------------------------------------------------------------------
// Fixture: a real, signed, in-memory ledger. Settlements are applied through
// the ledger too, so every body incentives returns must be one it accepts.
//
// The member tree comes from the ownerKey entries: ivy invited alice and
// carol, alice invited amy, everyone else came in with no inviter. The
// fixture's rules set minTreeDistance 1, so only an inviter and its invitee
// are too close: from alice, amy and ivy are at distance 1 (her friends),
// carol 2, and bob, dave, eve and ghost 3.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const DAY_MIN = 24 * 60;
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();

// defaultRules() but for minTreeDistance (see above).
function fixtureRules(): Rules {
  return { ...defaultRules(), minTreeDistance: 1 };
}

const OWNERS: [OwnerId, OwnerId | null][] = [
  ["ivy", null],
  ["alice", "ivy"],
  ["amy", "alice"],
  ["bob", null],
  ["carol", "ivy"],
  ["dave", null],
  ["eve", null],
  ["ghost", null],
];
const AGENTS: [string, OwnerId, string][] = [
  ["a1", "alice", "claude"],
  ["a2", "alice", "claude"],
  ["m1", "amy", "gpt"],
  ["b1", "bob", "gpt"],
  ["c1", "carol", "qwen"],
  ["d1", "dave", "kimi"],
  ["e1", "eve", "glm"],
  ["g1", "ghost", "deepseek"],
];

const verdictOf = (p: number): ReviewVerdict => ({ defectProbability: p, summary: "s", findingIds: [] });

class World {
  admin = generateKeyPair();
  coord = generateKeyPair();
  keys = new Map<string, Signer>();
  minute = 0;
  state: LedgerState;

  constructor(rules: Rules = fixtureRules()) {
    this.state = emptyState(
      genesisEntry(
        { kind: "genesis", project: "demo", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
        iso(0),
      ),
    );
    for (const [owner, inviter] of OWNERS) {
      this.apply({ kind: "ownerKey", owner, publicKey: this.key(owner).publicKey, inviter }, this.admin);
    }
    for (const [agent, owner, family] of AGENTS) {
      this.apply(
        { kind: "agentRegistered", owner, publicKey: this.key(agent).publicKey, modelFamily: family, harness: "cli" },
        this.key(owner),
      );
    }
  }

  key(name: string): Signer {
    let k = this.keys.get(name);
    if (!k) this.keys.set(name, (k = generateKeyPair()));
    return k;
  }

  id(name: string): string {
    return keyIdOf(this.key(name).publicKey);
  }

  now(): string {
    return iso(this.minute);
  }

  apply(body: EntryBody, signer: Signer): void {
    this.minute += 1;
    applyEntry(this.state, signEntry(this.state, body, signer, this.now()));
  }

  advanceDays(days: number): void {
    this.minute += days * DAY_MIN;
  }

  // A submission for its own task (proposal, task and claim made here): the
  // kind of merge that earns tranches. The author proposed it, so no cut.
  submitTask(id: string, agent = "a1"): void {
    const task = `t-${id}`;
    this.apply({ kind: "proposal", id: `p-${id}`, title: "t", evidence: [{ kind: "location", file: "src/x.ts", line: 1, note: "n" }] }, this.key(agent));
    this.apply({ kind: "task", id: task, proposalId: `p-${id}`, ring: 1, acceptanceTestPaths: ["test/t.test.ts"], sizeEstimate: 10, specAuthor: "bob" }, this.coord);
    this.apply({ kind: "claim", taskId: task, until: iso(this.minute + 600), stake: 5 }, this.key(agent));
    this.submit(id, agent, task);
  }

  submit(id: string, agent = "a1", taskId: string | null = null): void {
    this.apply(
      { kind: "submission", id, taskId, baseCommit: `base-${id}`, headCommit: `head-${id}`, changedFiles: ["src/x.ts"], linesChanged: 10 },
      this.key(agent),
    );
  }

  assign(sid: string, agents: string[]): void {
    this.apply(assignmentBody(this.state, sid, agents.map((a) => this.id(a)), "e"), this.coord);
  }

  // Commits close once any verdict is revealed, so commit everyone first.
  // Reveals wait for the commit phase: every assigned reviewer committed, or
  // the phase's deadline passed (then time moves past it). Without an
  // assignment the reviewers given are the assigned ones.
  reviews(sid: string, ps: Record<string, number>): void {
    if (!this.state.submissions.get(sid)?.assignment) this.assign(sid, Object.keys(ps));
    for (const [agent, p] of Object.entries(ps)) this.commit(sid, agent, p);
    this.endCommitPhase(sid);
    for (const [agent, p] of Object.entries(ps)) this.reveal(sid, agent, p);
  }

  // Moves time past the commit deadline unless every assigned reviewer committed.
  endCommitPhase(sid: string): void {
    const s = this.state.submissions.get(sid);
    if (!s?.assignment) return;
    const all = s.assignment.reviewers.every((k) => s.reviews.some((r) => r.reviewer === k));
    if (!all) this.minute = Math.max(this.minute, (Date.parse(s.assignment.at ?? "") - T0) / 60_000 + this.state.rules.review.commitHours * 60);
  }

  commit(sid: string, agent: string, p: number): void {
    this.apply({ kind: "reviewCommit", submissionId: sid, commitment: commitmentFor(verdictOf(p), `salt-${agent}`, this.id(agent), { submissionId: sid }), stake: 5 }, this.key(agent));
  }

  reveal(sid: string, agent: string, p: number): void {
    this.apply({ kind: "reviewReveal", submissionId: sid, verdict: verdictOf(p), salt: `salt-${agent}` }, this.key(agent));
  }

  attest(snapshotId: string, ps: Record<string, number>): void {
    for (const [agent, p] of Object.entries(ps)) {
      this.apply({ kind: "attestCommit", snapshotId, commitment: commitmentFor(verdictOf(p), `asalt-${agent}`, this.id(agent), { snapshotId }), stake: 5 }, this.key(agent));
    }
    // Attestation reveals wait for the end of the snapshot's commit phase.
    const at = this.state.snapshots.get(snapshotId)?.at ?? "";
    this.minute = Math.max(this.minute, (Date.parse(at) - T0) / 60_000 + this.state.rules.review.commitHours * 60);
    for (const [agent, p] of Object.entries(ps)) {
      this.apply({ kind: "attestReveal", snapshotId, verdict: verdictOf(p), salt: `asalt-${agent}` }, this.key(agent));
    }
  }

  file(id: string, target: { submissionId: string } | { snapshotId: string }, severity: Severity, agent: string): void {
    this.apply({ kind: "finding", id, target, severity, testPath: `test/${id}.test.ts`, testCommand: "npm test", stake: 5 }, this.key(agent));
  }

  // A reproduced result is confirmed by the admin (a real defect) unless
  // `decide` says otherwise: "dismiss", or "none" to leave it undecided.
  result(findingId: string, reproduced: boolean, decide: "confirm" | "dismiss" | "none" = "confirm"): void {
    this.apply(
      { kind: "findingResult", findingId, reproduced, failsOnHead: reproduced, passesOnParent: true, logDigest: "d" },
      this.coord,
    );
    if (reproduced && decide !== "none") this.decide(findingId, decide === "confirm");
  }

  decide(findingId: string, confirmed: boolean): void {
    this.apply({ kind: "findingDecision", findingId, confirmed, reason: confirmed ? "a real defect" : "tests the intended change" }, this.admin);
  }

  // The ledger merges nothing unassigned: without an assignment, eve's agent
  // (or bob's, for eve's own work) is drawn.
  merge(sid: string): void {
    this.apply({ kind: "gateResult", submissionId: sid, gate: "test", pass: true, details: "" }, this.coord);
    const s = this.state.submissions.get(sid);
    if (s && !s.assignment) this.assign(sid, [this.state.agents.get(s.author)?.owner === "eve" ? "b1" : "e1"]);
    this.apply({ kind: "merge", submissionId: sid, commit: `m-${sid}` }, this.coord);
  }

  snapshot(id: string, submissionIds: string[], previousSnapshotId: string | null = null): void {
    this.apply({ kind: "snapshot", id, commit: `c-${id}`, previousSnapshotId, submissionIds }, this.coord);
  }

  promote(id: string): void {
    this.apply({ kind: "promotion", snapshotId: id, commit: `c-${id}` }, this.coord);
  }

  plantCommit(sid: string): void {
    this.apply({ kind: "plantCommit", commitment: sha256hex(`${sid}:salt`) }, this.admin);
  }

  plantReveal(sid: string): void {
    this.apply({ kind: "plantReveal", submissionId: sid, salt: "salt", description: "planted", severity: "medium" }, this.admin);
  }

  // Applies settlement bodies through the ledger (which rejects bad ones).
  settle(bodies: SettlementBody[]): void {
    for (const b of bodies) this.apply(b, this.coord);
  }

  rep(owner: OwnerId): number {
    return this.state.owners.get(owner)?.reputationDelta ?? 0;
  }
}

// Sorted (owner, reason, delta) triples: order-independent comparison.
function summary(bodies: SettlementBody[]): string[] {
  return bodies.map((b) => `${b.owner} ${b.reason} ${b.delta}`).sort();
}

function assertWellFormed(bodies: SettlementBody[]): void {
  const keys = new Set<string>();
  for (const b of bodies) {
    assert.ok(Number.isInteger(b.delta), `integer delta: ${b.delta}`);
    assert.notEqual(b.delta, 0);
    assert.ok(!Object.is(b.delta, -0));
    const k = `${b.owner}|${b.reason}|${b.ref}`;
    assert.ok(!keys.has(k), `duplicate key ${k}`);
    keys.add(k);
  }
}

// alice submits s1; bob, carol, dave review; returns the world.
function reviewedSubmission(ps: Record<string, number> = { b1: 0.1, c1: 0.2, d1: 1 }): World {
  const w = new World();
  w.submit("s1");
  w.assign("s1", Object.keys(ps));
  w.reviews("s1", ps);
  return w;
}

const get = (bodies: SettlementBody[], owner: string, reason: string) =>
  bodies.find((b) => b.owner === owner && b.reason === reason)?.delta;
const total = (bodies: SettlementBody[], reason: string) =>
  bodies.filter((b) => b.reason === reason).reduce((a, b) => a + b.delta, 0);

// ---------------------------------------------------------------------------
// Volume limits and shares
// ---------------------------------------------------------------------------

test("prSlots grows with log2(1 + reputation) and floors bad input to one slot", () => {
  assert.equal(prSlots(0), 1);
  assert.equal(prSlots(1), 2);
  assert.equal(prSlots(2), 2);
  assert.equal(prSlots(3), 3);
  assert.equal(prSlots(7), 4);
  assert.equal(prSlots(1023), 11);
  assert.equal(prSlots(-50), 1);
  assert.equal(prSlots(Number.NaN), 1);
  assert.equal(prSlots(Number.POSITIVE_INFINITY), 1);
});

test("claimStake is the rules.ts function: superlinear in lines, scaled by ring", () => {
  const r = defaultRules();
  assert.equal(claimStake, rulesClaimStake);
  assert.equal(claimStake(100, 1, r), 15);
  assert.equal(claimStake(400, 0, r), 320);
  assert.equal(claimStake(0, 2, r), 1); // max(lines, 1) and ceil
  assert.ok(claimStake(200, 1, r) > 2 * claimStake(100, 1, r));
});

test("duplicateShares: normalised decaying weights in filing order", () => {
  assert.deepEqual(duplicateShares(0, 0.9), []);
  assert.deepEqual(duplicateShares(1, 0.9), [1]);
  const s = duplicateShares(3, 0.9);
  assert.equal(s.length, 3);
  assert.ok(Math.abs(s.reduce((a, b) => a + b, 0) - 1) < 1e-12);
  assert.ok(Math.abs((s[1] as number) / (s[0] as number) - 0.9) < 1e-12);
  assert.ok(Math.abs((s[2] as number) / (s[1] as number) - 0.9) < 1e-12);
  assert.deepEqual(duplicateShares(4, 1), [0.25, 0.25, 0.25, 0.25]);
  assert.deepEqual(duplicateShares(-1, 0.9), []);
  assert.deepEqual(duplicateShares(1.5, 0.9), []);
  assert.throws(() => duplicateShares(2, 0), RangeError);
  assert.throws(() => duplicateShares(2, 1.1), RangeError);
});

test("apportion: integer parts that sum exactly to the total (rounding each share can overpay)", () => {
  assert.deepEqual(apportion(15, duplicateShares(2, 1)), [8, 7]); // not 8 + 8
  assert.deepEqual(apportion(10, [1, 1, 1]), [4, 3, 3]);
  assert.deepEqual(apportion(0, [1, 2]), [0, 0]);
  assert.deepEqual(apportion(5, []), []);
  assert.deepEqual(apportion(5, [0, 0]), [0, 0]);
  for (const decay of [1, 0.9]) {
    for (const t of [1, 5, 15, 40, 100]) {
      for (let n = 1; n <= 7; n++) {
        const parts = apportion(t, duplicateShares(n, decay));
        assert.equal(parts.reduce((a, b) => a + b, 0), t, `t=${t} n=${n} decay=${decay}`);
        assert.ok(parts.every((x, i) => Number.isInteger(x) && x >= 0 && (i === 0 || x <= (parts[i - 1] as number))));
      }
    }
  }
});

test("submitCredits: one starter credit, one per two revealed reviews, minus submissions, across an owner's agents", () => {
  const w = new World();
  assert.equal(submitCredits(w.state, "alice"), 1);
  w.submit("s1", "a1");
  assert.equal(submitCredits(w.state, "alice"), 0);
  w.submit("s2", "a2"); // a second agent of the same owner spends the same pool
  assert.equal(submitCredits(w.state, "alice"), -1);

  assert.equal(submitCredits(w.state, "bob"), 1);
  w.reviews("s1", { b1: 0.1 });
  assert.equal(submitCredits(w.state, "bob"), 1); // one review is half a credit
  // An unrevealed commit earns nothing.
  w.assign("s2", ["b1"]);
  w.commit("s2", "b1", 0.3);
  assert.equal(submitCredits(w.state, "bob"), 1);
  w.reveal("s2", "b1", 0.3);
  assert.equal(submitCredits(w.state, "bob"), 2);
  assert.equal(submitCredits(w.state, "nobody"), 1);
});

test("submitCredits: under phase1Rules, gate failures do not freeze a three-owner group", () => {
  // Only alice, bob and carol take part; each starts with one credit.
  const w = new World(phase1Rules());
  const owners = ["alice", "bob", "carol"];
  const fail = (sid: string, agent: string) => {
    w.submit(sid, agent);
    w.apply({ kind: "gateResult", submissionId: sid, gate: "size", pass: false, details: "too big" }, w.coord);
  };
  fail("s1", "a1"); // no assignment follows a failed gate, so nobody earns
  fail("s2", "c1");
  w.submit("s3", "b1");
  w.reviews("s3", { a1: 0.1, c1: 0.1 }); // the two assigned seats
  assert.ok(owners.some((o) => submitCredits(w.state, o) >= 1), "someone can still submit");
  // The supply grows with every reviewed submission instead of only shrinking.
  const total = () => owners.reduce((n, o) => n + submitCredits(w.state, o), 0);
  const before = total();
  w.submit("s4", "a1");
  w.reviews("s4", { b1: 0.1, c1: 0.1 });
  assert.equal(total(), before + 1);
});

test("submitCredits: a reveal held back until after the merge earns no credit", () => {
  const w = new World();
  w.submit("s1");
  w.submit("s2");
  w.reviews("s1", { b1: 0.1 });
  w.assign("s2", ["b1"]);
  w.commit("s2", "b1", 0.1);
  w.merge("s2");
  w.reveal("s2", "b1", 0.1);
  assert.equal(submitCredits(w.state, "bob"), 1, "only the in-time reveal on s1 counts: half a credit");
  w.submit("s3");
  w.reviews("s3", { b1: 0.1 });
  assert.equal(submitCredits(w.state, "bob"), 2);
});

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

test("reproduced finding: stranger paid, author and approvers slashed by confidence, inviter charged per invitee", () => {
  const w = reviewedSubmission({ b1: 0.1, c1: 0.2, d1: 1 });
  w.file("f1", { submissionId: "s1" }, "critical", "e1");
  assert.deepEqual(settleFinding(w.state, "f1", "main"), [], "no result yet");
  w.result("f1", true);
  const bodies = settleFinding(w.state, "f1", "main");
  assertWellFormed(bodies);
  // Settled at bounty.low (5) whatever severity was declared; main stage: 5 x 4 = 20.
  assert.deepEqual(
    summary(bodies),
    [
      "alice authorSlash -20",
      "bob approverSlash -18", // 20 - 20 * .1
      "carol approverSlash -16",
      "eve bounty 5",
      // dave said p = 1: nothing.
      "ivy inviterSlash -5", // for alice: round(20 * .25)
      "ivy inviterSlash -4", // for carol: round(16 * .25)
    ].sort(),
  );
  assert.deepEqual(
    bodies.filter((b) => b.owner === "ivy").map((b) => b.ref).sort(),
    ["finding:f1:approverSlash:carol", "finding:f1:authorSlash:alice"],
  );
  assert.ok(bodies.filter((b) => b.owner !== "ivy").every((b) => b.ref === "finding:f1"));
  w.settle(bodies);
  assert.deepEqual(settleFinding(w.state, "f1", "main"), []);
});

test("severity is the finder's claim: one bug filed at four severities pays one low bounty and slashes once", () => {
  const w = reviewedSubmission({ b1: 0 });
  const sev: Severity[] = ["low", "medium", "high", "critical"];
  sev.forEach((s, i) => w.file(`f${i}`, { submissionId: "s1" }, s, "e1"));
  sev.forEach((_, i) => w.result(`f${i}`, true));
  const all = sev.flatMap((_, i) => settleFinding(w.state, `f${i}`, "dev"));
  assertWellFormed(all);
  assert.equal(total(all, "bounty"), 5, "one bounty.low, split by rank");
  assert.deepEqual(
    all.filter((b) => b.reason !== "bounty").map((b) => `${b.owner} ${b.reason} ${b.delta} ${b.ref}`).sort(),
    ["alice authorSlash -5 finding:f0", "bob approverSlash -5 finding:f0", "ivy inviterSlash -1 finding:f0:authorSlash:alice"],
  );
  w.settle(all);
  assert.equal(w.rep("eve"), 5);
  assert.equal(w.rep("alice"), -5);
  assert.equal(w.rep("bob"), -5);
});

test("farming: the author's friend within minTreeDistance earns 0, the author still pays, the pair nets negative", () => {
  const w = reviewedSubmission({ b1: 0.1 });
  w.file("f1", { submissionId: "s1" }, "high", "m1");
  w.result("f1", true);
  const bodies = settleFinding(w.state, "f1", "dev");
  assert.equal(memberTree(w.state).distance("amy", "alice"), 1);
  assert.ok(!bodies.some((b) => b.owner === "amy"), "no bounty body for amy");
  assert.deepEqual(summary(bodies).filter((s) => s.startsWith("alice")), ["alice authorSlash -5"]);
  w.settle(bodies);
  assert.equal(w.rep("alice") + w.rep("amy"), -5);
});

test("a finder outside the tree (only a corrupt, hand-built state) stops the settlement: no distance is guessed", () => {
  const w = reviewedSubmission({ b1: 0.5 });
  w.file("f1", { submissionId: "s1" }, "low", "g1");
  w.result("f1", true);
  // Every ledger owner is in the member tree; only a hand-built state can
  // hold an agent whose owner is not.
  const st = structuredClone(w.state);
  st.owners.delete("ghost");
  assert.throws(() => settleFinding(st, "f1", "dev"), /unknown member ghost/);
  // The replayed state settles normally.
  assert.equal(get(settleFinding(w.state, "f1", "dev"), "alice", "authorSlash"), -5);
});

test("stage multipliers raise the author and approver slash, never the bounty", () => {
  const cases: ["dev" | "release" | "main", number, number][] = [
    ["dev", -5, -4],
    ["release", -10, -8],
    ["main", -20, -16],
  ];
  for (const [stage, author, approver] of cases) {
    const w = reviewedSubmission({ c1: 0.2 });
    w.file("f1", { submissionId: "s1" }, "medium", "b1");
    w.result("f1", true);
    const bodies = settleFinding(w.state, "f1", stage);
    assert.equal(get(bodies, "bob", "bounty"), 5, stage);
    assert.equal(get(bodies, "alice", "authorSlash"), author, stage);
    assert.equal(get(bodies, "carol", "approverSlash"), approver, stage);
  }
});

test("author slash floor: with a multiplier that rounds below the bounty, the author still pays the bounty paid", () => {
  // validateRules forbids multipliers < 1; set one on the state directly so the floor is the deciding term.
  const w = reviewedSubmission({ b1: 0 });
  w.state.rules.rewards.stageMultiplier.dev = 0.5; // round(5 * .5) = 3 < 5
  w.file("f1", { submissionId: "s1" }, "low", "e1");
  w.result("f1", true);
  const bodies = settleFinding(w.state, "f1", "dev");
  const slash = -(get(bodies, "alice", "authorSlash") ?? 0);
  assert.equal(total(bodies, "bounty"), 5);
  assert.equal(slash, 5, "max(round(bounty x stage), bounty)");
  assert.ok(slash > Math.round(5 * 0.5));
  assert.equal(get(bodies, "bob", "approverSlash"), -3, "approvers have no floor: round(2.5)");
});

test("duplicates filed before the first result share one bounty by rank; slashes go out with the first result", () => {
  const w = reviewedSubmission({ c1: 0.4 });
  w.file("f1", { submissionId: "s1" }, "medium", "b1");
  w.file("f2", { submissionId: "s1" }, "high", "e1"); // a different declared severity is still the same class
  w.result("f1", true);
  // f2 has no result yet. f1's share and the slashes do not wait for it.
  const b1 = settleFinding(w.state, "f1", "dev");
  assertWellFormed(b1);
  // shares of 5 by apportion([1, .9] / 1.9): 3 and 2.
  assert.deepEqual(
    summary(b1),
    ["alice authorSlash -5", "bob bounty 3", "carol approverSlash -3", "ivy inviterSlash -1", "ivy inviterSlash -1"].sort(),
  );
  assert.deepEqual(settleFinding(w.state, "f2", "dev"), [], "no result yet");
  w.settle(b1);
  w.result("f2", true);
  const b2 = settleFinding(w.state, "f2", "dev");
  assert.deepEqual(summary(b2), ["eve bounty 2"], "only the leader carries the slashes");
  assert.ok(b2.every((b) => b.ref === "finding:f2"));
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), [], "the leader's bodies are final");

  // Filed after the first result: the reproduction was public. Not paid, slashes nobody.
  w.file("f3", { submissionId: "s1" }, "low", "d1");
  w.result("f3", true);
  assert.deepEqual(settleFinding(w.state, "f3", "dev"), []);

  w.settle(b2);
  for (const f of ["f1", "f2", "f3"]) assert.deepEqual(settleFinding(w.state, f, "dev"), [], f);
  assert.equal(w.rep("bob") + w.rep("eve"), 5);
});

test("a duplicate that never gets a result does not freeze the settlement; the author is still slashed", () => {
  // amy (alice's friend) files first on the merged s1 and never uploads her test.
  const w = reviewedSubmission({ b1: 0.1 });
  w.merge("s1");
  w.file("f1", { submissionId: "s1" }, "critical", "m1");
  w.file("f2", { submissionId: "s1" }, "critical", "e1");
  w.result("f2", true);
  const bodies = settleFinding(w.state, "f2", "dev");
  assertWellFormed(bodies);
  assert.equal(get(bodies, "alice", "authorSlash"), -5);
  assert.equal(get(bodies, "bob", "approverSlash"), -5); // round(4.5)
  // amy's pending filing holds rank 0 and dilutes eve's share; it never earns.
  assert.equal(get(bodies, "eve", "bounty"), 2);
  assert.ok(!bodies.some((b) => b.owner === "amy"));
});

test("an earlier finding already resolved false is not a duplicate; one resolved later keeps its unpaid rank", () => {
  const w = reviewedSubmission({ c1: 0.4 });
  w.file("f0", { submissionId: "s1" }, "medium", "d1");
  w.file("f1", { submissionId: "s1" }, "medium", "b1");
  w.result("f0", false);
  w.result("f1", true);
  assert.equal(get(settleFinding(w.state, "f1", "dev"), "bob", "bounty"), 5);
  assert.deepEqual(summary(settleFalseFinding(w.state, "f0")), ["dave falseFinding -5"]);

  const v = reviewedSubmission({ c1: 0.4 });
  v.file("f0", { submissionId: "s1" }, "medium", "d1");
  v.file("f1", { submissionId: "s1" }, "medium", "b1");
  v.result("f1", true);
  v.result("f0", false); // known only after the class formed: its share stays unpaid
  assert.equal(get(settleFinding(v.state, "f1", "dev"), "bob", "bounty"), 2);
});

test("duplicate shares never sum past the bounty, at decay 1 and 0.9, for 2 to 5 finders", () => {
  const finders = ["b1", "c1", "d1", "e1", "e2"];
  for (const decay of [1, 0.9]) {
    for (let n = 2; n <= 5; n++) {
      const rules = fixtureRules();
      rules.rewards.duplicateDecay = decay;
      rules.rewards.bounty.low = 15; // odd, so equal halves would round up
      const w = new World(rules);
      w.apply({ kind: "agentRegistered", owner: "eve", publicKey: w.key("e2").publicKey, modelFamily: "glm", harness: "cli" }, w.key("eve"));
      w.submit("s1");
      for (let i = 0; i < n; i++) w.file(`f${i}`, { submissionId: "s1" }, "low", finders[i] as string);
      for (let i = 0; i < n; i++) w.result(`f${i}`, true);
      const all = Array.from({ length: n }, (_, i) => settleFinding(w.state, `f${i}`, "dev")).flat();
      assertWellFormed(all);
      assert.equal(total(all, "bounty"), 15, `decay ${decay} n ${n}`);
      assert.equal(get(all, "alice", "authorSlash"), -15);
      w.settle(all);
    }
  }
});

test("same-owner duplicates cannot farm: two agents' shares sum to one bounty", () => {
  const w = new World();
  w.apply({ kind: "agentRegistered", owner: "eve", publicKey: w.key("e2").publicKey, modelFamily: "glm", harness: "cli" }, w.key("eve"));
  w.submit("s1");
  w.file("f1", { submissionId: "s1" }, "medium", "e1");
  w.file("f2", { submissionId: "s1" }, "medium", "e2");
  w.result("f1", true);
  w.result("f2", true);
  const all = [...settleFinding(w.state, "f1", "dev"), ...settleFinding(w.state, "f2", "dev")];
  w.settle(all);
  assert.equal(w.rep("eve"), 5);
});

test("unrevealed or late reviews count as p = 0 once the submission merged", () => {
  const w = new World();
  w.submit("s1");
  w.assign("s1", ["b1", "c1", "d1"]);
  w.commit("s1", "b1", 0.5);
  w.commit("s1", "c1", 0); // never revealed
  w.commit("s1", "d1", 0.9); // revealed only after the merge
  w.reveal("s1", "b1", 0.5);
  w.merge("s1");
  w.reveal("s1", "d1", 0.9);
  w.file("f1", { submissionId: "s1" }, "low", "e1");
  w.result("f1", true);
  const bodies = settleFinding(w.state, "f1", "dev");
  assertWellFormed(bodies);
  assert.equal(get(bodies, "bob", "approverSlash"), -3); // round(5 - 2.5)
  assert.equal(get(bodies, "carol", "approverSlash"), -5, "withheld reveal");
  assert.equal(get(bodies, "dave", "approverSlash"), -5, "a reveal after the merge could have seen the outcome");
});

test("before merge, an unrevealed approver is settled when it reveals", () => {
  const w = new World();
  w.submit("s1");
  w.assign("s1", ["b1", "c1"]);
  w.commit("s1", "b1", 0.2);
  w.commit("s1", "c1", 0.6);
  w.reveal("s1", "b1", 0.2);
  w.file("f1", { submissionId: "s1" }, "low", "e1");
  w.result("f1", true);
  const first = settleFinding(w.state, "f1", "dev");
  assert.equal(get(first, "bob", "approverSlash"), -4);
  assert.equal(get(first, "carol", "approverSlash"), undefined);
  w.settle(first);
  w.reveal("s1", "c1", 0.6);
  assert.deepEqual(summary(settleFinding(w.state, "f1", "dev")), ["carol approverSlash -2", "ivy inviterSlash -1"].sort());
});

test("regression: tranche 3 and clean-review rewards wait while a finding has no result", () => {
  const w = new World();
  w.submitTask("s1");
  w.reviews("s1", { b1: 0.1, c1: 0.1 });
  w.merge("s1");
  w.snapshot("S1", ["s1"]);
  w.promote("S1");
  w.advanceDays(w.state.rules.vesting.tailDays - 0.1);
  w.file("f1", { submissionId: "s1" }, "low", "e1"); // filed just before the tail ends
  w.advanceDays(0.2);
  assert.deepEqual(settleMerge(w.state, "s1", 3, w.now()), [], "undecided is not clean");
  assert.deepEqual(settleCleanReviews(w.state, "S1", w.now()), []);
  w.result("f1", false); // judged: not reproduced
  assert.equal(get(settleMerge(w.state, "s1", 3, w.now()), "alice", "mergeVest"), 10);
  assert.equal(get(settleCleanReviews(w.state, "S1", w.now()), "bob", "cleanReview"), 2);
});

test("a review withheld on a submission with a confirmed defect counts as p = 0 after the reveal deadline", () => {
  const w = new World();
  w.submit("s1");
  w.assign("s1", ["b1", "c1"]);
  w.commit("s1", "b1", 0);
  w.commit("s1", "c1", 0);
  w.reveal("s1", "c1", 0);
  w.file("f1", { submissionId: "s1" }, "low", "e1");
  w.result("f1", true); // confirmed: s1 can never merge, its review stakes are released
  assert.equal(w.state.owners.get("bob")?.lockedStake, 0);
  // Before the deadline bob may still reveal and be judged on its own p.
  assert.equal(get(settleFinding(w.state, "f1", "dev"), "bob", "approverSlash"), undefined);
  w.settle(settleFinding(w.state, "f1", "dev"));
  const assignedAt = Date.parse(w.state.submissions.get("s1")?.assignment?.at ?? "");
  const late = new Date(assignedAt + 2 * w.state.rules.review.commitHours * 3_600_000).toISOString();
  const bodies = settleFinding(w.state, "f1", "dev", late);
  assert.deepEqual(summary(bodies), ["bob approverSlash -5"], "withholding costs what a confident clean reveal costs");
});

test("snapshot finding: author slash split across covered submissions, bounty capped at the smallest part; attesters are approvers", () => {
  const w = new World();
  w.submit("s1", "a1");
  w.submit("s2", "a2");
  w.submit("s3", "b1");
  for (const s of ["s1", "s2", "s3"]) w.merge(s);
  w.snapshot("snapA", ["s1"]);
  w.snapshot("snapB", ["s2", "s3"], "snapA"); // covers snapA too (unpromoted)
  w.attest("snapB", { d1: 0.5, e1: 0 });
  w.file("f1", { snapshotId: "snapB" }, "low", "c1");
  w.result("f1", true);
  const bodies = settleFinding(w.state, "f1", "release");
  assertWellFormed(bodies);
  // slash = 5 * 2 = 10 over [s2, s3, s1] -> 4, 3, 3: alice (s2, s1) 7, bob (s3) 3.
  // pool = min(5, 3) = 3. dave attested p = .5: 10 - 5; eve p = 0: 10.
  assert.deepEqual(
    summary(bodies),
    [
      "alice authorSlash -7",
      "bob authorSlash -3",
      "carol bounty 3",
      "dave approverSlash -5",
      "eve approverSlash -10",
      "ivy inviterSlash -2", // round(7 * .25)
    ].sort(),
  );
});

test("snapshot finding: a buggy author and a distant friend cannot net positive, whatever the split order", () => {
  // alice's bug ships in x1 with bob's and dave's work; eve files it against the
  // snapshot at every severity instead of naming alice's submission.
  for (const order of [
    ["s1", "s2", "s3"],
    ["s2", "s3", "s1"],
  ]) {
    const w = new World();
    w.submit("s1", "a1");
    w.submit("s2", "b1");
    w.submit("s3", "d1");
    for (const s of ["s1", "s2", "s3"]) w.merge(s);
    w.snapshot("x1", order);
    const sev: Severity[] = ["low", "medium", "high", "critical"];
    sev.forEach((s, i) => w.file(`f${i}`, { snapshotId: "x1" }, s, "e1"));
    sev.forEach((_, i) => w.result(`f${i}`, true));
    const all = sev.flatMap((_, i) => settleFinding(w.state, `f${i}`, "release"));
    assertWellFormed(all);
    w.settle(all);
    assert.ok(w.rep("alice") + w.rep("eve") <= 0, `pair ${w.rep("alice") + w.rep("eve")} (${order.join(",")})`);
    assert.ok(w.rep("alice") + w.rep("eve") + w.rep("ivy") < 0);
    assert.equal(w.rep("eve"), 3, "capped at the smallest author part, floor(10 / 3)");
  }
});

test("a snapshot finder within distance of any covered author earns nothing", () => {
  const w = new World();
  w.submit("s1", "a1");
  w.submit("s2", "b1");
  w.merge("s1");
  w.merge("s2");
  w.snapshot("snap", ["s1", "s2"]);
  w.file("f1", { snapshotId: "snap" }, "medium", "m1"); // amy: far from bob, close to alice
  w.result("f1", true);
  const bodies = settleFinding(w.state, "f1", "release");
  assert.ok(!bodies.some((b) => b.reason === "bounty"));
  assert.equal(total(bodies, "authorSlash"), -10);
});

test("one bug filed against a submission and the snapshot that ships it is paid and slashed once", () => {
  const w = new World();
  w.submit("s1");
  w.merge("s1");
  w.snapshot("x1", ["s1"]);
  w.file("f1", { submissionId: "s1" }, "high", "e1");
  w.file("f2", { snapshotId: "x1" }, "high", "e1");
  w.result("f2", true);
  w.result("f1", true);
  const all = [...settleFinding(w.state, "f1", "release"), ...settleFinding(w.state, "f2", "release")];
  assertWellFormed(all);
  assert.deepEqual(settleFinding(w.state, "f2", "release"), [], "the submission finding names the culprit and wins");
  w.settle(all);
  assert.equal(w.rep("eve"), 5);
  assert.equal(w.rep("alice"), -10);

  // Overlapping snapshots: the earlier filing wins.
  const v = new World();
  v.submit("s1");
  v.submit("s2", "b1");
  v.merge("s1");
  v.merge("s2");
  v.snapshot("x1", ["s1"]);
  v.snapshot("x2", ["s2"], "x1"); // covers s1 too
  v.file("g1", { snapshotId: "x1" }, "low", "e1");
  v.file("g2", { snapshotId: "x2" }, "low", "c1");
  v.result("g1", true);
  v.result("g2", true);
  assert.ok(settleFinding(v.state, "g1", "release").length > 0);
  assert.deepEqual(settleFinding(v.state, "g2", "release"), []);
});

test("plant: a finding filed after the review window closed settles nothing", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.assign("p1", ["b1", "c1"]);
  w.reviews("p1", { b1: 0.1, c1: 0.2 }); // the last assigned reveal closes the window
  w.plantReveal("p1");
  w.file("f1", { submissionId: "p1" }, "medium", "e1"); // written from the published description
  w.result("f1", true);
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), []);
});

test("plant: a blind finding settles as real work, custodian included, the same before and after the reveal", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1"); // alice's agent is the custodian
  w.assign("p1", ["b1", "c1"]);
  w.commit("p1", "b1", 0.1);
  w.commit("p1", "c1", 0.2);
  w.file("f1", { submissionId: "p1" }, "medium", "e1"); // before the window closes
  w.reveal("p1", "b1", 0.1);
  w.reveal("p1", "c1", 0.2);
  w.result("f1", true);
  const before = settleFinding(w.state, "f1", "dev");
  assertWellFormed(before);
  assert.equal(get(before, "eve", "bounty"), 5);
  assert.equal(get(before, "alice", "authorSlash"), -5, "the custodian pays, or it could feed its plants to a friend");
  w.plantReveal("p1");
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), before);
});

test("false finding: finder pays the penalty, inviter pays a share; reproduced findings are not false", () => {
  const w = reviewedSubmission({ b1: 0.1 });
  w.file("f1", { submissionId: "s1" }, "high", "c1");
  assert.deepEqual(settleFalseFinding(w.state, "f1"), [], "no result yet");
  w.result("f1", false);
  const bodies = settleFalseFinding(w.state, "f1");
  assert.deepEqual(summary(bodies), ["carol falseFinding -5", "ivy inviterSlash -1"].sort());
  assert.equal(bodies.find((b) => b.owner === "ivy")?.ref, "finding:f1:falseFinding:carol");
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), []);
  w.settle(bodies);
  assert.deepEqual(settleFalseFinding(w.state, "f1"), []);
  assert.deepEqual(settleFalseFinding(w.state, "missing"), []);

  w.file("f2", { submissionId: "s1" }, "low", "e1");
  w.result("f2", true);
  assert.deepEqual(settleFalseFinding(w.state, "f2"), []);
});

test("idempotency: once applied to the ledger, every settlement returns []", () => {
  const w = reviewedSubmission({ b1: 0.1, c1: 0.3 });
  w.file("f1", { submissionId: "s1" }, "critical", "e1");
  w.result("f1", true);
  const first = settleFinding(w.state, "f1", "main");
  assert.ok(first.length > 2);
  assert.deepEqual(settleFinding(w.state, "f1", "main"), first, "pure: same answer before applying");
  // Partial application (a crash mid-batch) leaves only the rest outstanding.
  w.settle(first.slice(0, 2));
  assert.deepEqual(settleFinding(w.state, "f1", "main"), first.slice(2));
  w.settle(first.slice(2));
  assert.deepEqual(settleFinding(w.state, "f1", "main"), []);
  // A different stage asked later does not re-slash: the key is owner + reason + ref.
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), []);
  assert.equal(w.rep("eve"), 5);
  assert.equal(w.rep("alice"), -20);
});

// ---------------------------------------------------------------------------
// Merges and clean reviews
// ---------------------------------------------------------------------------

// A task proposed by `proposer` (agent or owner key), claimed and submitted by a1.
function taskWorld(proposer: string): World {
  const w = new World();
  w.apply({ kind: "proposal", id: "p1", title: "t", evidence: [{ kind: "location", file: "src/x.ts", line: 1, note: "n" }] }, w.key(proposer));
  w.apply(
    { kind: "task", id: "t1", proposalId: "p1", ring: 1, acceptanceTestPaths: ["test/t1.test.ts"], sizeEstimate: 10, specAuthor: "bob" },
    w.coord,
  );
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 600), stake: 5 }, w.key("a1"));
  w.submit("s1", "a1", "t1");
  return w;
}

test("merge tranche 1: author vests round(merge/3) minus the proposer's cut", () => {
  const w = taskWorld("b1");
  assert.deepEqual(settleMerge(w.state, "s1", 1, w.now()), [], "not merged");
  w.merge("s1");
  const bodies = settleMerge(w.state, "s1", 1, w.now());
  assert.deepEqual(summary(bodies), ["alice mergeVest 9", "bob proposerCut 1"].sort());
  assert.ok(bodies.every((b) => b.ref === "merge:s1:1"));
  w.settle(bodies);
  assert.deepEqual(settleMerge(w.state, "s1", 1, w.now()), []);
});

test("proposer cut goes to an owner who signed the proposal with the owner key; none to yourself", () => {
  const byOwner = taskWorld("carol");
  byOwner.merge("s1");
  assert.deepEqual(summary(settleMerge(byOwner.state, "s1", 1, byOwner.now())), ["alice mergeVest 9", "carol proposerCut 1"].sort());

  const self = taskWorld("a2");
  self.merge("s1");
  assert.deepEqual(summary(settleMerge(self.state, "s1", 1, self.now())), ["alice mergeVest 10"]);

  // A taskless merge earns nothing at all: merge rewards come only from work
  // someone asked for (a task), or whitespace edits would mint reputation.
  const none = new World();
  none.submit("s1");
  none.merge("s1");
  assert.deepEqual(settleMerge(none.state, "s1", 1, none.now()), []);
});

test("merge tranches 2 and 3 wait for promotion and the tail; tranche 3 needs a valid nowIso", () => {
  const w = taskWorld("b1");
  w.merge("s1");
  assert.deepEqual(settleMerge(w.state, "s1", 2, w.now()), []);
  w.snapshot("snap", ["s1"]);
  assert.deepEqual(settleMerge(w.state, "s1", 2, w.now()), [], "snapshotted but not promoted");
  w.promote("snap");
  const promotedAt = w.now();
  assert.deepEqual(summary(settleMerge(w.state, "s1", 2, w.now())), ["alice mergeVest 9", "bob proposerCut 1"].sort());
  assert.ok(settleMerge(w.state, "s1", 2, w.now()).every((b) => b.ref === "merge:s1:2"));

  const tailEnd = new Date(Date.parse(promotedAt) + 30 * 86_400_000);
  assert.deepEqual(settleMerge(w.state, "s1", 3, new Date(tailEnd.getTime() - 1).toISOString()), []);
  const t3 = settleMerge(w.state, "s1", 3, tailEnd.toISOString());
  assert.equal(t3.length, 2);
  assert.ok(t3.every((b) => b.ref === "merge:s1:3"));
  // No silent fallback to the ledger head: a missing or zone-less time is an error.
  assert.throws(() => settleMerge(w.state, "s1", 3, undefined as unknown as string), RangeError);
  assert.throws(() => settleMerge(w.state, "s1", 3, "2026-03-01T00:00:00"), RangeError);
  assert.throws(() => settleMerge(w.state, "s1", 4 as 3, w.now()), RangeError);
});

test("a snapshot shipped by a later promotion vests tranche 2", () => {
  const w = new World();
  w.submitTask("s1");
  w.submit("s2", "b1");
  w.merge("s1");
  w.merge("s2");
  w.snapshot("A", ["s1"]);
  w.snapshot("B", ["s2"], "A");
  w.promote("B");
  assert.deepEqual(summary(settleMerge(w.state, "s1", 2, w.now())), ["alice mergeVest 10"]);
});

test("a reproduced finding on a merged submission forfeits its unpaid tranches 2 and 3", () => {
  const w = new World();
  w.submitTask("s1");
  w.merge("s1");
  w.settle(settleMerge(w.state, "s1", 1, w.now()));
  w.snapshot("snap", ["s1"]);
  w.promote("snap");
  w.file("f1", { submissionId: "s1" }, "medium", "b1");
  w.result("f1", true);
  assert.deepEqual(settleMerge(w.state, "s1", 2, w.now()), []);
  assert.deepEqual(settleMerge(w.state, "s1", 3, iso(w.minute + 60 * DAY_MIN)), []);
  assert.equal(w.rep("alice"), 10, "tranche 1 is never clawed back");
});

test("a snapshot finding names no culprit and voids no tranche (documented choice)", () => {
  const w = new World();
  w.submitTask("s1");
  w.merge("s1");
  w.snapshot("snap", ["s1"]);
  w.promote("snap");
  w.file("f1", { snapshotId: "snap" }, "critical", "e1");
  w.result("f1", true);
  assert.deepEqual(summary(settleMerge(w.state, "s1", 2, w.now())), ["alice mergeVest 10"]);
  assert.equal(settleMerge(w.state, "s1", 3, iso(w.minute + 31 * DAY_MIN)).length, 1);
});

test("a plant vests nothing, even one merged before its reveal", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submitTask("p1");
  w.merge("p1");
  assert.equal(settleMerge(w.state, "p1", 1, w.now()).length, 1, "before the reveal it looks like real work");
  w.plantReveal("p1");
  w.snapshot("snap", ["p1"]);
  w.promote("snap");
  for (const t of [1, 2, 3] as const) assert.deepEqual(settleMerge(w.state, "p1", t, iso(w.minute + 31 * DAY_MIN)), [], `${t}`);
});

test("clean reviews: after the tail, reviewers of a clean shipped submission earn cleanReview x (1 - p^2)", () => {
  const w = new World();
  w.submitTask("s1");
  w.submitTask("s2");
  w.reviews("s1", { b1: 0.1, c1: 0.6, d1: 0.9, e1: 1 });
  // s2: bob reveals, dave commits and never reveals, a finding reproduces after merge.
  w.commit("s2", "d1", 0.2);
  w.reviews("s2", { b1: 0.1 });
  w.merge("s1");
  w.merge("s2");
  w.snapshot("snap", ["s1", "s2"]);
  w.file("f1", { submissionId: "s2" }, "low", "e1");
  w.result("f1", true);
  assert.deepEqual(settleCleanReviews(w.state, "snap", iso(w.minute + 60 * DAY_MIN)), [], "not promoted");
  w.promote("snap");
  const promoted = w.minute;
  assert.deepEqual(settleCleanReviews(w.state, "snap", iso(promoted + 29 * DAY_MIN)), [], "tail not over");
  const bodies = settleCleanReviews(w.state, "snap", iso(promoted + 30 * DAY_MIN));
  // b1 .1: round(1.98) = 2; c1 .6: round(1.28) = 1; d1 .9: round(.38) = 0; e1 1: 0.
  assert.deepEqual(summary(bodies), ["bob cleanReview 2", "carol cleanReview 1"].sort());
  assert.ok(bodies.every((b) => b.ref === "review:s1"));
  w.settle(bodies);
  assert.deepEqual(settleCleanReviews(w.state, "snap", iso(promoted + 31 * DAY_MIN)), []);
  assert.deepEqual(settleCleanReviews(w.state, "nope", iso(promoted + 31 * DAY_MIN)), []);
  assert.throws(() => settleCleanReviews(w.state, "snap", undefined as unknown as string), RangeError);
});

test("clean reviews: a reveal held back until after the merge earns nothing", () => {
  const w = new World();
  w.submitTask("s1");
  w.assign("s1", ["b1", "c1"]);
  w.commit("s1", "b1", 0);
  w.commit("s1", "c1", 0);
  w.reveal("s1", "b1", 0);
  w.merge("s1");
  w.reveal("s1", "c1", 0); // waited to see the change ship
  w.snapshot("snap", ["s1"]);
  w.promote("snap");
  assert.deepEqual(summary(settleCleanReviews(w.state, "snap", iso(w.minute + 31 * DAY_MIN))), ["bob cleanReview 2"]);
});

test("clean reviews: a reproduced finding on the shipping snapshot during the tail blocks them", () => {
  const w = new World();
  w.submitTask("s1");
  w.submitTask("s2", "d1");
  w.reviews("s1", { b1: 0.1 });
  w.reviews("s2", { c1: 0.1 }); // carol: bob is within distance of dave
  w.merge("s1");
  w.merge("s2");
  w.snapshot("A", ["s1"]);
  w.snapshot("B", ["s2"], "A");
  w.promote("B");
  w.file("f1", { snapshotId: "A" }, "low", "e1"); // an escape on A: covers s1 only
  w.result("f1", true);
  w.apply({ kind: "escape", findingId: "f1", snapshotId: "B" }, w.coord);
  const bodies = settleCleanReviews(w.state, "B", iso(w.minute + 31 * DAY_MIN));
  assert.deepEqual(bodies.map((b) => b.ref), ["review:s2"]);
});

test("clean reviews of a promoted snapshot cover its unpromoted ancestors once", () => {
  const w = new World();
  w.submitTask("s1");
  w.submitTask("s2");
  w.reviews("s1", { b1: 0.1 });
  w.reviews("s2", { b1: 0.1 });
  w.merge("s1");
  w.merge("s2");
  w.snapshot("A", ["s1"]);
  w.snapshot("B", ["s2"], "A");
  w.promote("B");
  const later = iso(w.minute + 31 * DAY_MIN);
  const viaB = settleCleanReviews(w.state, "B", later);
  assert.deepEqual(viaB.map((b) => b.ref).sort(), ["review:s1", "review:s2"]);
  const viaA = settleCleanReviews(w.state, "A", later);
  assert.deepEqual(viaA.map((b) => b.ref), ["review:s1"], "same body as B produced for s1");
  w.settle(viaB);
  assert.deepEqual(settleCleanReviews(w.state, "A", later), []);
  assert.equal(w.rep("bob"), 4);
});

// ---------------------------------------------------------------------------
// Penalties
// ---------------------------------------------------------------------------

test("missed plant: who pays, who waits, and each invitee's inviter charge has its own key", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1", "d1"); // dave is the custodian
  w.assign("p1", ["b1", "c1", "e1"]); // eve holds a seat and never commits
  w.commit("p1", "b1", 0.9);
  w.commit("p1", "c1", 0.1);
  w.commit("p1", "a1", 0.3); // alice reviews openly
  w.commit("p1", "m1", 0.2); // amy reviews openly
  w.endCommitPhase("p1"); // eve's seat stays empty; reveals wait for the deadline
  for (const [a, p] of [["b1", 0.9], ["c1", 0.1], ["a1", 0.3], ["m1", 0.2]] as const) w.reveal("p1", a, p);
  w.file("fA", { submissionId: "p1" }, "medium", "a1"); // blind, no result yet: alice waits
  w.file("fB", { submissionId: "p1" }, "medium", "b1");
  w.result("fB", true); // closes the window
  assert.deepEqual(settleMissedPlant(w.state, "p1"), [], "not revealed yet");
  w.plantReveal("p1");
  w.file("fM", { submissionId: "p1" }, "medium", "m1"); // after the reveal: does not defer amy's charge

  const first = settleMissedPlant(w.state, "p1");
  assertWellFormed(first);
  assert.deepEqual(
    summary(first),
    // alice is charged as amy's inviter, ivy as carol's.
    ["alice inviterSlash -2", "amy missedPlant -6", "carol missedPlant -6", "eve missedPlant -6", "ivy inviterSlash -2"].sort(),
  );
  w.settle(first);
  assert.deepEqual(settleMissedPlant(w.state, "p1"), []);

  w.result("fA", false); // alice did not catch it after all
  const second = settleMissedPlant(w.state, "p1");
  assert.deepEqual(summary(second), ["alice missedPlant -6", "ivy inviterSlash -2"].sort());
  assert.deepEqual(
    [...first, ...second].filter((b) => b.owner === "ivy").map((b) => b.ref).sort(),
    ["plant:p1:missedPlant:alice", "plant:p1:missedPlant:carol"],
  );
  w.settle(second);
  assert.equal(w.rep("ivy"), -4, "one charge per invitee, across calls");
});

test("missed plant: a finding filed after the reveal is no catch, even once it reproduces", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.assign("p1", ["b1", "c1"]);
  w.reviews("p1", { b1: 0, c1: 0.9 }); // the last assigned reveal closes the window
  w.plantReveal("p1");
  w.file("f1", { submissionId: "p1" }, "medium", "b1"); // built from the published description
  assert.deepEqual(summary(settleMissedPlant(w.state, "p1")), ["bob missedPlant -6"]);
  w.result("f1", true);
  assert.deepEqual(summary(settleMissedPlant(w.state, "p1")), ["bob missedPlant -6"]);
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), [], "and it earns nothing");
});

test("missed plant: a reviewer whose blind finding reproduced caught it; a late reveal does not", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.assign("p1", ["b1", "c1"]);
  w.commit("p1", "b1", 0.1);
  w.commit("p1", "c1", 0.9);
  w.file("f1", { submissionId: "p1" }, "medium", "b1");
  w.result("f1", true); // closes the window before anyone revealed
  w.plantReveal("p1");
  w.reveal("p1", "c1", 0.9); // after the close: no longer a catch
  assert.deepEqual(summary(settleMissedPlant(w.state, "p1")), ["carol missedPlant -6", "ivy inviterSlash -2"].sort());
  assert.deepEqual(settleMissedPlant(w.state, "missing"), []);
});

test("missed plant: a plant revealed while its window is open charges nobody", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.assign("p1", ["b1", "c1"]);
  w.commit("p1", "b1", 0);
  w.commit("p1", "c1", 0);
  w.reveal("p1", "b1", 0); // c1 never reveals, so the window stays open
  w.plantReveal("p1");
  assert.deepEqual(settleMissedPlant(w.state, "p1"), []);
});

test("regression: dismissing the reproduction that closed a plant's window, after the reveal, does not reopen it", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.assign("p1", ["b1", "c1"]);
  w.commit("p1", "b1", 0.9);
  w.commit("p1", "c1", 0.1);
  w.file("f1", { submissionId: "p1" }, "low", "d1");
  w.result("f1", true, "none"); // reproduced: the window closes, so the custodian may reveal
  const closed = reviewWindowCloseSeq(w.state, "p1");
  assert.notEqual(closed, null);
  w.plantReveal("p1");
  w.decide("f1", false); // the test only pinned the old text
  w.endCommitPhase("p1");
  w.reveal("p1", "b1", 0.9); // b1's flag is public only after the plant was announced
  w.reveal("p1", "c1", 0.1);
  assert.equal(reviewWindowCloseSeq(w.state, "p1"), w.state.submissions.get("p1")?.planted?.seq, "the reveal caps the window");
  assert.equal(plantCaught(w.state, "p1"), false, "a flag revealed after the plant reveal is no catch");
  assert.equal(plantCaughtBy(w.state, "p1", w.id("b1")), false);
});

function claimWorld(): World {
  const w = new World();
  w.apply({ kind: "proposal", id: "p1", title: "t", evidence: [{ kind: "location", file: "src/x.ts", line: 1, note: "n" }] }, w.key("b1"));
  for (const t of ["t1", "t2"]) {
    w.apply(
      { kind: "task", id: t, proposalId: "p1", ring: 1, acceptanceTestPaths: [`test/${t}.test.ts`], sizeEstimate: 100, specAuthor: "bob" },
      w.coord,
    );
  }
  return w;
}

test("expired claims forfeit their stake when the claimer never submitted", () => {
  const w = claimWorld();
  const until = iso(w.minute + 120);
  w.apply({ kind: "claim", taskId: "t1", until, stake: 20 }, w.key("c1"));
  w.apply({ kind: "claim", taskId: "t2", until, stake: 15 }, w.key("a1"));
  w.submit("s2", "a1", "t2");
  const seq = w.state.claims.get("t1")?.seq;

  assert.deepEqual(settleExpiredClaims(w.state, until), [], "until itself is not past");
  const after = iso(w.minute + 200);
  const bodies = settleExpiredClaims(w.state, after);
  assert.deepEqual(summary(bodies), ["carol claimExpired -20", "ivy inviterSlash -5"].sort());
  assert.ok(bodies.every((b) => b.ref.startsWith(`claim:t1:${seq}`)));
  w.settle(bodies);
  assert.deepEqual(settleExpiredClaims(w.state, after), []);
  assert.throws(() => settleExpiredClaims(w.state, "not a date"), RangeError);
});

test("expired claims: a submission in the holder's unbroken run covers its extensions; one from a lapsed run does not", () => {
  // Submitting and then extending (to hold the task through review) costs
  // nothing more than not extending (regression: it used to forfeit the stake).
  const w = claimWorld();
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 60), stake: 15 }, w.key("a1"));
  w.submit("s1", "a1", "t1");
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 600), stake: 15 }, w.key("a1")); // extended while live
  assert.deepEqual(settleExpiredClaims(w.state, iso(w.minute + 700)), []);
  // A new run after the claim lapsed must deliver again.
  const v = claimWorld();
  v.apply({ kind: "claim", taskId: "t1", until: iso(v.minute + 60), stake: 15 }, v.key("a1"));
  v.submit("junk", "a1", "t1");
  v.minute += 61;
  v.apply({ kind: "claim", taskId: "t1", until: iso(v.minute + 600), stake: 15 }, v.key("a1")); // re-claimed after it lapsed
  assert.deepEqual(summary(settleExpiredClaims(v.state, iso(v.minute + 700))), ["alice claimExpired -15", "ivy inviterSlash -4"].sort());
});

test("expired claims: a task that merged before until releases the claim", () => {
  const w = claimWorld();
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 30), stake: 15 }, w.key("a1"));
  w.submit("s1", "a1", "t1");
  w.minute += 60; // a1's claim lapses with its submission still in review
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 120), stake: 15 }, w.key("c1"));
  w.merge("s1");
  assert.deepEqual(settleExpiredClaims(w.state, iso(w.minute + 600)), []);
});

test("honeytoken: owner pays per distinct token, inviter pays a share, repeats are idempotent", () => {
  const w = new World();
  w.apply({ kind: "honeytokenTriggered", agent: w.id("c1"), tokenId: "tok1" }, w.coord);
  w.apply({ kind: "honeytokenTriggered", agent: w.id("c1"), tokenId: "tok1" }, w.coord);
  w.apply({ kind: "honeytokenTriggered", agent: w.id("c1"), tokenId: "tok2" }, w.coord);
  const bodies = settleHoneytoken(w.state, w.id("c1"));
  assertWellFormed(bodies);
  assert.deepEqual(
    summary(bodies),
    ["carol honeytoken -50", "carol honeytoken -50", "ivy inviterSlash -13", "ivy inviterSlash -13"].sort(),
  );
  w.settle(bodies);
  assert.equal(w.rep("carol"), -100);
  assert.deepEqual(settleHoneytoken(w.state, w.id("c1")), []);
  assert.deepEqual(settleHoneytoken(w.state, w.id("b1")), [], "bob's agent did nothing");
  assert.deepEqual(settleHoneytoken(w.state, "unknown-agent"), []);
});

test("inviter share rounds per slash and never produces a -0 or zero body", () => {
  const rules = fixtureRules();
  rules.rewards.inviterShare = 0.01; // round(5 * .01) = 0: no inviter body at all
  const w = new World(rules);
  w.submit("s1", "b1");
  w.file("f1", { submissionId: "s1" }, "low", "c1");
  w.result("f1", false);
  const bodies = settleFalseFinding(w.state, "f1");
  assertWellFormed(bodies);
  assert.deepEqual(summary(bodies), ["carol falseFinding -5"]);
});

// ---------------------------------------------------------------------------
// Payoffs: rubber-stamping and flag-everything against honest review
// ---------------------------------------------------------------------------

test("EV on a real ledger: 20 submissions, 3 plants (15%), 4 organic bugs; honest review beats p = 0 and p = 1", () => {
  // Per review, always p = 0 earns 0.85 x (1 - d) x 2 - 0.15 x 6 - 0.85 x d x 5
  // with bounties at bounty.low on dev: negative once organic defects d exceed
  // about 13%. Here d = 4 / 17.
  const w = new World();
  const plants = new Set(["s03", "s09", "s15"]);
  const bugs = new Set(["s04", "s08", "s12", "s18"]);
  const ids = Array.from({ length: 20 }, (_, i) => `s${String(i + 1).padStart(2, "0")}`);
  const all: SettlementBody[] = [];
  for (const sid of ids) {
    if (plants.has(sid)) w.plantCommit(sid);
    w.submitTask(sid, "a1");
    w.assign(sid, ["b1", "c1", "e1"]);
    const defective = plants.has(sid) || bugs.has(sid);
    // bob always says clean; carol is honest and accurate; eve flags everything.
    w.reviews(sid, { b1: 0, c1: defective ? 0.9 : 0.1, e1: 1 });
    if (plants.has(sid)) {
      w.plantReveal(sid);
      all.push(...settleMissedPlant(w.state, sid));
    } else if (bugs.has(sid)) {
      w.file(`f-${sid}`, { submissionId: sid }, "medium", "d1");
      w.result(`f-${sid}`, true);
      all.push(...settleFinding(w.state, `f-${sid}`, "dev"));
    } else {
      w.merge(sid);
    }
  }
  const clean = ids.filter((s) => !plants.has(s) && !bugs.has(s));
  w.snapshot("snap", clean);
  w.promote("snap");
  all.push(...settleCleanReviews(w.state, "snap", iso(w.minute + 31 * DAY_MIN)));
  assertWellFormed(all);
  w.settle(all);

  // bob: 13 clean x 2 - 3 plants x 6 - 4 bugs x 5 = -12
  // carol: 13 x round(2 - .02) - 4 x round(5 - 4.5) = 22
  // eve: 13 x round(2 - 2) = 0; she risks nothing and earns nothing.
  assert.equal(w.rep("bob"), -12);
  assert.equal(w.rep("carol"), 22);
  assert.equal(w.rep("eve"), 0);
  assert.ok(w.rep("carol") > w.rep("bob") && w.rep("carol") > w.rep("eve"));
  // The stranger who found the organic bugs was paid; the author paid every slash.
  assert.equal(w.rep("dave"), 20);
  assert.equal(w.rep("alice"), -20);
});

test("false finding: a result with a harness error is neither slashed nor paid", () => {
  const w = reviewedSubmission({ b1: 0.1 });
  w.file("f1", { submissionId: "s1" }, "high", "c1");
  w.apply(
    {
      kind: "findingResult",
      findingId: "f1",
      reproduced: false,
      failsOnHead: false,
      passesOnParent: false,
      logDigest: "void:harness-error",
      harnessError: "voided after 3 harness errors",
    },
    w.coord,
  );
  assert.deepEqual(settleFalseFinding(w.state, "f1"), [], "could not run is not did not reproduce");
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), [], "nor a reproduction");
});

// ---------------------------------------------------------------------------
// Review findings fixed in the whole-system pass
// ---------------------------------------------------------------------------

test("a reproduction settles only once confirmed; a dismissed one costs its finder, not the author", () => {
  // The change-detector attack: a test that pins the old text "reproduces"
  // against any change. Undecided, it pays and slashes nobody.
  const w = reviewedSubmission({ b1: 0.1, c1: 0.2 });
  w.file("f1", { submissionId: "s1" }, "medium", "e1");
  w.result("f1", true, "none");
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), [], "undecided: nobody paid or slashed");
  assert.deepEqual(settleFalseFinding(w.state, "f1"), []);
  w.decide("f1", false); // an operator: it tests the intended change
  assert.deepEqual(settleFinding(w.state, "f1", "dev"), []);
  assert.deepEqual(summary(settleFalseFinding(w.state, "f1")), ["eve falseFinding -5"]);

  const c = reviewedSubmission({ b1: 0.1, c1: 0.2 });
  c.file("f1", { submissionId: "s1" }, "medium", "e1");
  c.result("f1", true, "none");
  c.decide("f1", true);
  assert.ok(settleFinding(c.state, "f1", "dev").some((b) => b.reason === "authorSlash"), "confirmed: settles as before");
});

test("a class settles nothing until its leader (the first reproduction) is decided; a dismissed leader passes it on", () => {
  const w = reviewedSubmission({ b1: 0.1 });
  w.file("f1", { submissionId: "s1" }, "medium", "e1");
  w.file("f2", { submissionId: "s1" }, "medium", "c1");
  w.result("f1", true, "none");
  w.result("f2", true, "confirm");
  assert.deepEqual(settleFinding(w.state, "f2", "dev"), [], "the leader f1 is still undecided");
  w.decide("f1", false);
  const bodies = settleFinding(w.state, "f2", "dev");
  assert.ok(bodies.some((b) => b.reason === "authorSlash" && b.ref === "finding:f2"), "f2 now leads the class");
});

test("taskless merges vest nothing: activity alone mints no reputation", () => {
  const w = new World();
  w.submit("readme");
  w.reviews("readme", { b1: 1, c1: 1 }); // both reviewers flagged it; the author still tries
  w.merge("readme");
  for (const t of [1, 2, 3] as const) assert.deepEqual(settleMerge(w.state, "readme", t, iso(w.minute + 60 * DAY_MIN)), []);
});

test("missed plant: a seat shut out by someone else's reproduction before its commit deadline is not charged", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1", "d1"); // dave is the custodian
  w.assign("p1", ["b1", "c1"]);
  w.commit("p1", "b1", 0.1); // carol has not committed yet...
  w.file("f1", { submissionId: "p1" }, "medium", "e1");
  w.result("f1", true, "none"); // ...when a reproduction closes commits
  w.endCommitPhase("p1");
  w.decide("f1", false); // dismissed only after the deadline: a change detector
  w.reveal("p1", "b1", 0.1);
  // The window's time runs out with a quorum: the coordinator closes it on the ledger.
  w.apply({ kind: "reviewWindowClosed", submissionId: "p1", missing: [w.id("c1")] }, w.coord);
  w.plantReveal("p1");
  const bodies = settleMissedPlant(w.state, "p1");
  assert.deepEqual(summary(bodies).filter((x) => x.includes("missedPlant")), ["bob missedPlant -6"], "bob saw and missed it; carol never could commit");
});

test("expired claims: a claim replaced after it lapsed is still settled", () => {
  const w = claimWorld();
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 60), stake: 15 }, w.key("a1"));
  const lapsed = w.state.claims.get("t1")?.seq;
  w.minute += 61; // it lapses...
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 600), stake: 15 }, w.key("a1")); // ...and its holder re-claims
  const bodies = settleExpiredClaims(w.state, w.now());
  assert.deepEqual(summary(bodies), ["alice claimExpired -15", "ivy inviterSlash -4"].sort());
  assert.ok(bodies.every((b) => b.ref.startsWith(`claim:t1:${lapsed}`)));
  // A colluder's re-claim does not erase it either; an extension while live is no expiry.
  const v = claimWorld();
  v.apply({ kind: "claim", taskId: "t1", until: iso(v.minute + 60), stake: 15 }, v.key("a1"));
  v.apply({ kind: "claim", taskId: "t1", until: iso(v.minute + 300), stake: 15 }, v.key("a1")); // extended while live
  v.minute += 400;
  v.apply({ kind: "claim", taskId: "t1", until: iso(v.minute + 600), stake: 15 }, v.key("c1"));
  assert.deepEqual(summary(settleExpiredClaims(v.state, v.now())).filter((x) => x.includes("claimExpired")), ["alice claimExpired -15"]);
});

test("regression: a taskless merge settles nothing for anyone, and an open reviewer within minTreeDistance of the author earns no clean review", () => {
  const w = new World();
  // Taskless whitespace edit: assigned seats and an open reviewer (amy, alice's friend) all say p = 0.
  w.submit("ws1");
  w.assign("ws1", ["b1", "c1"]);
  w.reviews("ws1", { b1: 0, c1: 0, m1: 0 });
  w.merge("ws1");
  // A task's submission: the same reviewers.
  w.submitTask("t1");
  w.assign("t1", ["b1", "c1"]);
  w.reviews("t1", { b1: 0, c1: 0, m1: 0 });
  w.merge("t1");
  w.snapshot("S1", ["ws1", "t1"]);
  w.promote("S1");
  const later = iso(w.minute + 31 * DAY_MIN);
  assert.deepEqual([1, 2, 3].flatMap((t) => settleMerge(w.state, "ws1", t as 1 | 2 | 3, later)), []);
  const bodies = settleCleanReviews(w.state, "S1", later);
  assert.ok(bodies.every((b) => b.ref === "review:t1"), "nothing for the taskless merge");
  assert.deepEqual(summary(bodies), ["bob cleanReview 2", "carol cleanReview 2"].sort(), "nothing for amy, within distance 2 of alice");
});

test("regression: key rotation hands a live claim's run to the owner's next agent, and ends the old agent's submission without stranding stakes", () => {
  const w = claimWorld();
  // a1 submits s1, b1 and c1 commit reviews; a2 holds a claim on t1.
  w.submit("s0", "a1");
  w.assign("s0", ["b1", "c1"]);
  w.commit("s0", "b1", 0.1);
  w.commit("s0", "c1", 0.1);
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 600), stake: 15 }, w.key("a2"));
  assert.equal(w.state.owners.get("bob")?.lockedStake, 5);
  // alice rotates both keys; her new agent n1 re-claims t1 and delivers.
  w.apply({ kind: "agentRevoked", agent: w.id("a1"), reason: "key rotation" }, w.key("alice"));
  w.apply({ kind: "agentRevoked", agent: w.id("a2"), reason: "key rotation" }, w.key("alice"));
  assert.equal(submissionDead(w.state, "s0"), true, "the coordinator never progresses a revoked author's work");
  assert.equal(w.state.owners.get("bob")?.lockedStake, 0, "reviewers' stakes released");
  assert.equal(w.state.owners.get("carol")?.lockedStake, 0);
  w.apply({ kind: "agentRegistered", owner: "alice", publicKey: w.key("n1").publicKey, modelFamily: "claude", harness: "cli" }, w.key("alice"));
  w.apply({ kind: "claim", taskId: "t1", until: iso(w.minute + 600), stake: 15 }, w.key("n1"));
  w.submit("s1", "n1", "t1");
  assert.deepEqual(settleExpiredClaims(w.state, iso(w.minute + 2000)), [], "the run passed to n1, which delivered");
  // Rotating without re-claiming still abandons the task.
  const v = claimWorld();
  v.apply({ kind: "claim", taskId: "t1", until: iso(v.minute + 60), stake: 15 }, v.key("a2"));
  v.apply({ kind: "agentRevoked", agent: v.id("a2"), reason: "key rotation" }, v.key("alice"));
  assert.deepEqual(summary(settleExpiredClaims(v.state, iso(v.minute + 700))), ["alice claimExpired -15", "ivy inviterSlash -4"].sort());
});
