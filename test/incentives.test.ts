import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, signEntry, type LedgerState, type Signer } from "../src/ledger";
import { claimStake as rulesClaimStake, defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import {
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

// ---------------------------------------------------------------------------
// Fixture: a real, signed, in-memory ledger. Settlements are applied through
// the ledger too, so every body incentives returns must be one it accepts.
//
// Tree (distances from alice): amy 2 (her friend, within minTreeDistance 2),
// bob, dave 4 and carol, eve 4. ivy invited alice and carol.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const DAY_MIN = 24 * 60;
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();

const tree = treeFromParents({
  root: null,
  x: "root",
  y: "root",
  z: "root",
  alice: "x",
  amy: "x",
  bob: "y",
  dave: "y",
  carol: "z",
  eve: "z",
  ivy: "root",
  // ghost is a ledger owner who is not in the tree.
});

const OWNERS: [OwnerId, OwnerId | null][] = [
  ["ivy", null],
  ["alice", "ivy"],
  ["amy", null],
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

  constructor(rules: Rules = defaultRules()) {
    this.state = emptyState(
      genesisEntry(
        { kind: "genesis", project: "anthill", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
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

  submit(id: string, agent = "a1", taskId: string | null = null): void {
    this.apply(
      { kind: "submission", id, taskId, baseCommit: `base-${id}`, headCommit: `head-${id}`, changedFiles: ["src/x.ts"], linesChanged: 10 },
      this.key(agent),
    );
  }

  assign(sid: string, agents: string[]): void {
    this.apply({ kind: "reviewAssignment", submissionId: sid, beacon: "b", reviewers: agents.map((a) => this.id(a)) }, this.coord);
  }

  // Commits close once any verdict is revealed, so commit everyone first.
  reviews(sid: string, ps: Record<string, number>): void {
    for (const [agent, p] of Object.entries(ps)) {
      this.apply({ kind: "reviewCommit", submissionId: sid, commitment: sha256hex(canonical(verdictOf(p)) + `salt-${agent}`), stake: 5 }, this.key(agent));
    }
    for (const [agent, p] of Object.entries(ps)) {
      this.apply({ kind: "reviewReveal", submissionId: sid, verdict: verdictOf(p), salt: `salt-${agent}` }, this.key(agent));
    }
  }

  attest(snapshotId: string, ps: Record<string, number>): void {
    for (const [agent, p] of Object.entries(ps)) {
      this.apply({ kind: "attestCommit", snapshotId, commitment: sha256hex(canonical(verdictOf(p)) + `asalt-${agent}`), stake: 5 }, this.key(agent));
    }
    for (const [agent, p] of Object.entries(ps)) {
      this.apply({ kind: "attestReveal", snapshotId, verdict: verdictOf(p), salt: `asalt-${agent}` }, this.key(agent));
    }
  }

  file(id: string, target: { submissionId: string } | { snapshotId: string }, severity: Severity, agent: string): void {
    this.apply({ kind: "finding", id, target, severity, testPath: `test/${id}.test.ts`, testCommand: "npm test", stake: 5 }, this.key(agent));
  }

  result(findingId: string, reproduced: boolean): void {
    this.apply(
      { kind: "findingResult", findingId, reproduced, failsOnHead: reproduced, passesOnParent: true, logDigest: "d" },
      this.coord,
    );
  }

  merge(sid: string): void {
    this.apply({ kind: "gateResult", submissionId: sid, gate: "test", pass: true, details: "" }, this.coord);
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
  w.apply({ kind: "reviewCommit", submissionId: "s2", commitment: sha256hex(canonical(verdictOf(0.3)) + "x"), stake: 5 }, w.key("b1"));
  assert.equal(submitCredits(w.state, "bob"), 1);
  w.apply({ kind: "reviewReveal", submissionId: "s2", verdict: verdictOf(0.3), salt: "x" }, w.key("b1"));
  assert.equal(submitCredits(w.state, "bob"), 2);
  assert.equal(submitCredits(w.state, "nobody"), 1);
});

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

test("reproduced finding: stranger paid, author and approvers slashed by confidence, inviter charged", () => {
  const w = reviewedSubmission({ b1: 0.1, c1: 0.2, d1: 1 });
  w.file("f1", { submissionId: "s1" }, "medium", "e1");
  assert.deepEqual(settleFinding(w.state, tree, "f1", "dev"), [], "no result yet");
  w.result("f1", true);
  const bodies = settleFinding(w.state, tree, "f1", "dev");
  assertWellFormed(bodies);
  assert.ok(bodies.every((b) => b.ref === "finding:f1"));
  assert.deepEqual(
    summary(bodies),
    [
      "alice authorSlash -15",
      "bob approverSlash -14", // round(15 * 0.9) = 13.5 -> 14
      "carol approverSlash -12", // round(15 * 0.8)
      "eve bounty 15",
      // dave said p = 1: nothing.
      // ivy invited alice and carol: round(15 * .25) + round(12 * .25) = 4 + 3, one body.
      "ivy inviterSlash -7",
    ].sort(),
  );
});

test("farming: the author's friend within minTreeDistance earns 0, the author still pays, the pair nets negative", () => {
  const w = reviewedSubmission({ b1: 0.1 });
  w.file("f1", { submissionId: "s1" }, "high", "m1");
  w.result("f1", true);
  const bodies = settleFinding(w.state, tree, "f1", "dev");
  assert.equal(tree.distance("amy", "alice"), 2);
  assert.ok(!bodies.some((b) => b.owner === "amy"), "no bounty body for amy");
  assert.deepEqual(summary(bodies).filter((s) => s.startsWith("alice")), ["alice authorSlash -40"]);
  w.settle(bodies);
  assert.ok(w.rep("alice") + w.rep("amy") < 0);
  assert.equal(w.rep("alice") + w.rep("amy"), -40);
});

test("a finder who is not in the tree earns nothing: unknown distance is not distance", () => {
  const w = reviewedSubmission({ b1: 0.5 });
  w.file("f1", { submissionId: "s1" }, "low", "g1");
  w.result("f1", true);
  const bodies = settleFinding(w.state, tree, "f1", "dev");
  assert.ok(!bodies.some((b) => b.owner === "ghost"));
  assert.ok(bodies.some((b) => b.owner === "alice" && b.reason === "authorSlash" && b.delta === -5));
});

test("stage multipliers raise the author and approver slash, never the bounty", () => {
  const cases: ["dev" | "release" | "main", number, number][] = [
    ["dev", -15, -12],
    ["release", -30, -24],
    ["main", -60, -48],
  ];
  for (const [stage, author, approver] of cases) {
    const w = reviewedSubmission({ c1: 0.2 });
    w.file("f1", { submissionId: "s1" }, "medium", "b1");
    w.result("f1", true);
    const bodies = settleFinding(w.state, tree, "f1", stage);
    const get = (o: string, r: string) => bodies.find((b) => b.owner === o && b.reason === r)?.delta;
    assert.equal(get("bob", "bounty"), 15, stage);
    assert.equal(get("alice", "authorSlash"), author, stage);
    assert.equal(get("carol", "approverSlash"), approver, stage);
    assert.ok(-author >= 15, "author pays at least the bounty");
  }
});

test("author slash is never less than the bounty, even with a multiplier rounded below it", () => {
  // validateRules forbids multipliers < 1, so the floor matters only for
  // rounding; check it holds for the smallest bounty at every stage.
  const w = reviewedSubmission({ b1: 0 });
  w.file("f1", { submissionId: "s1" }, "low", "e1");
  w.result("f1", true);
  for (const stage of ["dev", "release", "main"] as const) {
    const bodies = settleFinding(w.state, tree, "f1", stage);
    const slash = -(bodies.find((b) => b.reason === "authorSlash")?.delta ?? 0);
    const paid = bodies.filter((b) => b.reason === "bounty").reduce((a, b) => a + b.delta, 0);
    assert.ok(slash >= paid && slash >= 5, `${stage}: ${slash} vs ${paid}`);
  }
});

test("duplicates filed before the first result split one bounty in filing order; author slashed once", () => {
  const w = reviewedSubmission({ c1: 0.4 });
  w.file("f1", { submissionId: "s1" }, "medium", "b1");
  w.file("f2", { submissionId: "s1" }, "medium", "e1");
  w.result("f1", true);
  // f2 is still pending: the group might still grow, so nothing settles.
  assert.deepEqual(settleFinding(w.state, tree, "f1", "dev"), []);
  w.result("f2", true);
  const b1 = settleFinding(w.state, tree, "f1", "dev");
  const b2 = settleFinding(w.state, tree, "f2", "dev");
  assertWellFormed([...b1, ...b2]);
  // shares 1/1.9 and 0.9/1.9 of 15: 7.89 -> 8, 7.11 -> 7
  assert.deepEqual(
    summary(b1),
    ["alice authorSlash -15", "bob bounty 8", "carol approverSlash -9", "ivy inviterSlash -6"].sort(),
  );
  assert.deepEqual(summary(b2), ["eve bounty 7"], "only the first finding carries the slashes");
  assert.ok(b2.every((b) => b.ref === "finding:f2"));

  // Filed after the first result: the reproduction was public. Not paid, slashes nobody.
  w.file("f3", { submissionId: "s1" }, "medium", "d1");
  w.result("f3", true);
  assert.deepEqual(settleFinding(w.state, tree, "f3", "dev"), []);

  // A different severity is a different bug, settled on its own.
  w.file("f4", { submissionId: "s1" }, "low", "d1");
  w.result("f4", true);
  const b4 = settleFinding(w.state, tree, "f4", "dev");
  assert.ok(b4.some((b) => b.owner === "dave" && b.reason === "bounty" && b.delta === 5));
  assert.ok(b4.some((b) => b.owner === "alice" && b.reason === "authorSlash" && b.delta === -5));

  w.settle([...b1, ...b2, ...b4]);
  for (const f of ["f1", "f2", "f3", "f4"]) assert.deepEqual(settleFinding(w.state, tree, f, "dev"), [], f);
});

test("a not-reproduced earlier finding does not join or block the group", () => {
  const w = reviewedSubmission({ c1: 0.4 });
  w.file("f0", { submissionId: "s1" }, "medium", "d1");
  w.file("f1", { submissionId: "s1" }, "medium", "b1");
  w.result("f0", false);
  w.result("f1", true);
  const bodies = settleFinding(w.state, tree, "f1", "dev");
  assert.equal(bodies.find((b) => b.owner === "bob")?.delta, 15);
  assert.deepEqual(summary(settleFalseFinding(w.state, "f0")), ["dave falseFinding -5"]);
});

test("same-owner duplicates cannot farm: two agents' shares sum to one bounty", () => {
  // eve's single finding would earn 15. Two from her own agents earn 8 + 7.
  const w = new World();
  w.apply({ kind: "agentRegistered", owner: "eve", publicKey: w.key("e2").publicKey, modelFamily: "glm", harness: "cli" }, w.key("eve"));
  w.submit("s1");
  w.file("f1", { submissionId: "s1" }, "medium", "e1");
  w.file("f2", { submissionId: "s1" }, "medium", "e2");
  w.result("f1", true);
  w.result("f2", true);
  const all = [...settleFinding(w.state, tree, "f1", "dev"), ...settleFinding(w.state, tree, "f2", "dev")];
  w.settle(all);
  assert.equal(w.rep("eve"), 15);
});

test("snapshot finding: author slash split across covered submissions, remainder first; attesters are approvers", () => {
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
  const bodies = settleFinding(w.state, tree, "f1", "release");
  assertWellFormed(bodies);
  // slash = 5 * 2 = 10 over [s2, s3, s1] -> 4, 3, 3: alice (s2, s1) 7, bob (s3) 3.
  // dave attested p = .5: round(10 * .5) = 5; eve p = 0: 10.
  // ivy: round(7 * .25) = 2 for alice.
  assert.deepEqual(
    summary(bodies),
    [
      "alice authorSlash -7",
      "bob authorSlash -3",
      "carol bounty 5",
      "dave approverSlash -5",
      "eve approverSlash -10",
      "ivy inviterSlash -2",
    ].sort(),
  );
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
  const bodies = settleFinding(w.state, tree, "f1", "release");
  assert.ok(!bodies.some((b) => b.reason === "bounty"));
  assert.equal(bodies.filter((b) => b.reason === "authorSlash").reduce((a, b) => a + b.delta, 0), -30);
});

test("findings on a revealed plant settle nothing: no bounty after the reveal, no custodian slash", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.reviews("p1", { b1: 0.1 });
  w.plantReveal("p1");
  w.file("f1", { submissionId: "p1" }, "medium", "e1"); // written from the published description
  w.result("f1", true);
  assert.deepEqual(settleFinding(w.state, tree, "f1", "dev"), []);
});

test("false finding: finder pays the penalty, inviter pays a share; reproduced findings are not false", () => {
  const w = reviewedSubmission({ b1: 0.1 });
  w.file("f1", { submissionId: "s1" }, "high", "c1");
  assert.deepEqual(settleFalseFinding(w.state, "f1"), [], "no result yet");
  w.result("f1", false);
  const bodies = settleFalseFinding(w.state, "f1");
  assert.deepEqual(summary(bodies), ["carol falseFinding -5", "ivy inviterSlash -1"].sort());
  assert.deepEqual(settleFinding(w.state, tree, "f1", "dev"), []);
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
  const first = settleFinding(w.state, tree, "f1", "main");
  assert.ok(first.length > 0);
  assert.deepEqual(settleFinding(w.state, tree, "f1", "main"), first, "pure: same answer before applying");
  // Partial application (a crash mid-batch) leaves only the rest outstanding.
  w.settle(first.slice(0, 2));
  assert.deepEqual(settleFinding(w.state, tree, "f1", "main"), first.slice(2));
  w.settle(first.slice(2));
  assert.deepEqual(settleFinding(w.state, tree, "f1", "main"), []);
  // A different stage asked later does not re-slash: the key is owner + reason + ref.
  assert.deepEqual(settleFinding(w.state, tree, "f1", "dev"), []);
  assert.equal(w.rep("eve"), 100);
  assert.equal(w.rep("alice"), -400);
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
  assert.deepEqual(settleMerge(w.state, "s1", 1), [], "not merged");
  w.merge("s1");
  const bodies = settleMerge(w.state, "s1", 1);
  assert.deepEqual(summary(bodies), ["alice mergeVest 9", "bob proposerCut 1"].sort());
  assert.ok(bodies.every((b) => b.ref === "merge:s1:1"));
  w.settle(bodies);
  assert.deepEqual(settleMerge(w.state, "s1", 1), []);
});

test("proposer cut goes to an owner who signed the proposal with the owner key; none to yourself", () => {
  const byOwner = taskWorld("carol");
  byOwner.merge("s1");
  assert.deepEqual(summary(settleMerge(byOwner.state, "s1", 1)), ["alice mergeVest 9", "carol proposerCut 1"].sort());

  const self = taskWorld("a2");
  self.merge("s1");
  assert.deepEqual(summary(settleMerge(self.state, "s1", 1)), ["alice mergeVest 10"]);

  const none = new World();
  none.submit("s1");
  none.merge("s1");
  assert.deepEqual(summary(settleMerge(none.state, "s1", 1)), ["alice mergeVest 10"]);
});

test("merge tranches 2 and 3 wait for promotion and the tail; nowIso or the ledger head decides tranche 3", () => {
  const w = taskWorld("b1");
  w.merge("s1");
  assert.deepEqual(settleMerge(w.state, "s1", 2), []);
  w.snapshot("snap", ["s1"]);
  assert.deepEqual(settleMerge(w.state, "s1", 2), [], "snapshotted but not promoted");
  w.promote("snap");
  const promotedAt = w.now();
  assert.deepEqual(summary(settleMerge(w.state, "s1", 2)), ["alice mergeVest 9", "bob proposerCut 1"].sort());
  assert.ok(settleMerge(w.state, "s1", 2).every((b) => b.ref === "merge:s1:2"));

  const tailEnd = new Date(Date.parse(promotedAt) + 30 * 86_400_000);
  assert.deepEqual(settleMerge(w.state, "s1", 3, new Date(tailEnd.getTime() - 1).toISOString()), []);
  assert.equal(settleMerge(w.state, "s1", 3, tailEnd.toISOString()).length, 2);
  // Without nowIso the ledger's own latest time is used: still inside the tail.
  assert.deepEqual(settleMerge(w.state, "s1", 3), []);
  w.advanceDays(31);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "tick", pass: true, details: "" }, w.coord);
  assert.equal(settleMerge(w.state, "s1", 3).length, 2);
  assert.throws(() => settleMerge(w.state, "s1", 4 as 3), RangeError);
});

test("a snapshot shipped by a later promotion vests tranche 2", () => {
  const w = new World();
  w.submit("s1");
  w.submit("s2", "b1");
  w.merge("s1");
  w.merge("s2");
  w.snapshot("A", ["s1"]);
  w.snapshot("B", ["s2"], "A");
  w.promote("B");
  assert.deepEqual(summary(settleMerge(w.state, "s1", 2)), ["alice mergeVest 10"]);
});

test("a reproduced finding on a merged submission forfeits its unpaid tranches 2 and 3", () => {
  const w = new World();
  w.submit("s1");
  w.merge("s1");
  w.settle(settleMerge(w.state, "s1", 1));
  w.snapshot("snap", ["s1"]);
  w.promote("snap");
  w.file("f1", { submissionId: "s1" }, "medium", "b1");
  w.result("f1", true);
  assert.deepEqual(settleMerge(w.state, "s1", 2), []);
  assert.deepEqual(settleMerge(w.state, "s1", 3, iso(w.minute + 60 * DAY_MIN)), []);
  assert.equal(w.rep("alice"), 10, "tranche 1 is never clawed back");
});

test("clean reviews: after the tail, every revealed reviewer of a clean shipped submission earns cleanReview", () => {
  const w = new World();
  w.submit("s1");
  w.submit("s2");
  w.reviews("s1", { b1: 0.1, c1: 0.9 });
  // s2: bob reveals, dave commits and never reveals, a finding reproduces after merge.
  w.apply({ kind: "reviewCommit", submissionId: "s2", commitment: sha256hex(canonical(verdictOf(0.2)) + "d"), stake: 5 }, w.key("d1"));
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
  assert.deepEqual(summary(bodies), ["bob cleanReview 2", "carol cleanReview 2"].sort());
  assert.ok(bodies.every((b) => b.ref === "review:s1"));
  w.settle(bodies);
  assert.deepEqual(settleCleanReviews(w.state, "snap", iso(promoted + 31 * DAY_MIN)), []);
  assert.deepEqual(settleCleanReviews(w.state, "nope", iso(promoted + 31 * DAY_MIN)), []);
});

test("clean reviews of a promoted snapshot cover its unpromoted ancestors once", () => {
  const w = new World();
  w.submit("s1");
  w.submit("s2");
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

test("missed plant: every owner who saw it and neither flagged nor found it pays; the custodian never does", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1"); // alice's agent is the custodian here
  w.assign("p1", ["b1", "c1", "d1"]);
  // dave holds a seat and never commits; eve reviews openly and waves it through,
  // amy reviews openly too but has a finding on it that has no result yet.
  w.reviews("p1", { b1: 0.1, c1: 0.9, e1: 0.49, m1: 0.2 });
  w.file("f1", { submissionId: "p1" }, "medium", "m1");
  assert.deepEqual(settleMissedPlant(w.state, "p1"), [], "not revealed yet");
  w.plantReveal("p1");
  const bodies = settleMissedPlant(w.state, "p1");
  assertWellFormed(bodies);
  assert.deepEqual(summary(bodies), ["bob missedPlant -6", "dave missedPlant -6", "eve missedPlant -6"].sort());
  assert.ok(bodies.every((b) => b.ref === "plant:p1"));
  w.settle(bodies);
  assert.deepEqual(settleMissedPlant(w.state, "p1"), []);
  // amy's finding comes back false: she did not catch it after all.
  w.result("f1", false);
  assert.deepEqual(summary(settleMissedPlant(w.state, "p1")), ["amy missedPlant -6"]);
});

test("missed plant: a reviewer whose own finding reproduced caught it", () => {
  const w = new World();
  w.plantCommit("p1");
  w.submit("p1");
  w.assign("p1", ["b1", "c1"]);
  w.reviews("p1", { b1: 0.1, c1: 0.1 });
  w.file("f1", { submissionId: "p1" }, "medium", "b1");
  w.result("f1", true);
  w.plantReveal("p1");
  assert.deepEqual(summary(settleMissedPlant(w.state, "p1")), ["carol missedPlant -6", "ivy inviterSlash -2"].sort());
  assert.deepEqual(settleMissedPlant(w.state, "missing"), []);
});

test("expired claims forfeit their stake when the claimer never submitted", () => {
  const w = new World();
  w.apply({ kind: "proposal", id: "p1", title: "t", evidence: [{ kind: "location", file: "src/x.ts", line: 1, note: "n" }] }, w.key("b1"));
  for (const t of ["t1", "t2"]) {
    w.apply(
      { kind: "task", id: t, proposalId: "p1", ring: 1, acceptanceTestPaths: [`test/${t}.test.ts`], sizeEstimate: 100, specAuthor: "bob" },
      w.coord,
    );
  }
  const until = iso(w.minute + 120);
  w.apply({ kind: "claim", taskId: "t1", until, stake: 20 }, w.key("c1"));
  w.apply({ kind: "claim", taskId: "t2", until, stake: 15 }, w.key("a1"));
  w.submit("s2", "a1", "t2");
  const seq = w.state.claims.get("t1")?.seq;

  assert.deepEqual(settleExpiredClaims(w.state, until), [], "until itself is not past");
  const after = iso(w.minute + 200);
  const bodies = settleExpiredClaims(w.state, after);
  assert.deepEqual(summary(bodies), ["carol claimExpired -20", "ivy inviterSlash -5"].sort());
  assert.ok(bodies.every((b) => b.ref === `claim:t1:${seq}`));
  w.settle(bodies);
  assert.deepEqual(settleExpiredClaims(w.state, after), []);
  assert.throws(() => settleExpiredClaims(w.state, "not a date"), RangeError);
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
  const rules = defaultRules();
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
// Payoffs: rubber-stamping against honest review
// ---------------------------------------------------------------------------

// Per-review expected value, from the rules alone, of a reviewer who reports p
// on a submission that is a plant with probability plantRate and otherwise
// organically defective with probability d (found at dev stage, severity
// medium, by a stranger). Plants never ship; clean work ships and pays
// cleanReview whatever p was.
function expectedValue(rules: Rules, d: number, pOnClean: number, pOnDefect: number): number {
  const plant = rules.plantRate;
  const { cleanReview, missedPlantPenalty, bounty, stageMultiplier } = rules.rewards;
  const flagged = pOnDefect >= 0.5;
  const onPlant = flagged ? 0 : -missedPlantPenalty;
  const onDefect = -Math.round(bounty.medium * stageMultiplier.dev * (1 - pOnDefect));
  void pOnClean; // the clean-review reward does not depend on p (protocol §6.2 gap)
  return plant * onPlant + (1 - plant) * ((1 - d) * cleanReview + d * onDefect);
}

test("EV: at plantRate 0.15 rubber-stamping loses once organic bugs exist; honest review gains", () => {
  const r = defaultRules();
  assert.equal(r.plantRate, 0.15);
  // Plants alone do not do it with the default numbers (+0.8 per review): the
  // missed-plant penalty needs approver slashes on real bugs to bite.
  assert.ok(Math.abs(expectedValue(r, 0, 0, 0) - 0.8) < 1e-9);
  for (const d of [0.1, 0.15, 0.25]) {
    const rubber = expectedValue(r, d, 0, 0);
    const honest = expectedValue(r, d, 0.1, 0.9);
    assert.ok(rubber < 0, `rubber-stamp EV ${rubber} at d=${d}`);
    assert.ok(honest > 0, `honest EV ${honest} at d=${d}`);
    assert.ok(honest > rubber);
  }
});

test("EV on a real ledger: 20 submissions, 3 plants (15%), 2 organic bugs; rubber stamp nets negative, honest positive", () => {
  const w = new World();
  const plants = new Set(["s03", "s09", "s15"]);
  const bugs = new Set(["s06", "s12"]);
  const ids = Array.from({ length: 20 }, (_, i) => `s${String(i + 1).padStart(2, "0")}`);
  const all: SettlementBody[] = [];
  for (const sid of ids) {
    if (plants.has(sid)) w.plantCommit(sid);
    w.submit(sid, "a1");
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
      all.push(...settleFinding(w.state, tree, `f-${sid}`, "dev"));
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

  // bob: 15 clean x 2 - 3 plants x 6 - 2 bugs x 15 = -18
  // carol: 30 - 2 x round(15 x .1) = 26 (ivy's inviter charges fall on ivy)
  assert.equal(w.rep("bob"), -18);
  assert.equal(w.rep("carol"), 26);
  assert.ok(w.rep("bob") < 0 && w.rep("carol") > 0);
  // Known gap (protocol §6.2), pinned so a fix updates this test: flagging
  // everything pays at least as well as honest review.
  assert.equal(w.rep("eve"), 30);
  assert.ok(w.rep("eve") >= w.rep("carol"));
  // The stranger who found both organic bugs was paid both bounties; the author paid both slashes.
  assert.equal(w.rep("dave"), 30);
  assert.equal(w.rep("alice"), -30);
});
