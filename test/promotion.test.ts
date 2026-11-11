import { after, test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger } from "../src/ledger";
import { plantCommitment } from "../src/plants";
import { assignmentBeacon, commitmentFor } from "../src/review";
import { coveredSubmissionIds, evaluatePromotion } from "../src/promotion";
import { claimStake, defaultRules, phase1Rules } from "../src/rules";
import { MEMBER_ROOT, treeDigest, treeFromParents } from "../src/members";
import { submitCredits } from "../src/incentives";
import type { EntryBody, KeyId, ModelFamily, Rules, Severity } from "../src/types";
import { assignmentBody, drawAssignment } from "../src/selection";

// --- a real, signed ledger ----------------------------------------------------

type Key = { publicKey: string; privateKey: string; keyId: KeyId };
const key = (): Key => {
  const k = generateKeyPair();
  return { ...k, keyId: keyIdOf(k.publicKey) };
};

const T0 = Date.UTC(2026, 9, 1); // 2026-10-01
const HOUR = 3_600_000;
const ring1 = (name: string) => [`src/${name}.ts`];
// The fixture project's kernel, declared in its rules as a target project
// declares its own (defaultRules names no project paths).
const KERNEL_FILE = "src/kernel/engine.ts";
function projectRules(): Rules {
  const r = defaultRules();
  r.rings = [{ glob: "src/kernel/**", ring: 0 }, ...r.rings];
  return r;
}

const dirs: string[] = [];
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

class World {
  readonly ledger: Ledger;
  readonly admin = key();
  readonly coord = key();
  readonly owners = new Map<string, Key>();
  readonly agents = new Map<string, Key>();
  private t = T0;
  private n = 0;

  constructor(rules: Rules) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "promotion-test-"));
    dirs.push(dir);
    this.ledger = Ledger.create(
      path.join(dir, "ledger.jsonl"),
      { kind: "genesis", project: "demo", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
      new Date(this.t).toISOString(),
    );
  }

  get state() {
    return this.ledger.state();
  }
  // Every entry is one minute after the previous one.
  private stamp(): string {
    this.t += 60_000;
    return new Date(this.t).toISOString();
  }
  nowPlus(hours: number): string {
    return new Date(this.t + hours * HOUR).toISOString();
  }
  advance(hours: number): void {
    this.t += hours * HOUR;
  }
  append(body: EntryBody, signer: Key): void {
    this.ledger.append(body, signer, this.stamp());
  }
  coordinator(body: EntryBody): void {
    this.append(body, this.coord);
  }
  agentKey(name: string): Key {
    const k = this.agents.get(name);
    assert.ok(k, `no agent ${name}`);
    return k;
  }

  owner(name: string): void {
    const k = key();
    this.owners.set(name, k);
    this.append({ kind: "ownerKey", owner: name, publicKey: k.publicKey, inviter: null }, this.admin);
  }
  agent(name: string, owner: string, modelFamily: ModelFamily): void {
    const k = key();
    this.agents.set(name, k);
    const o = this.owners.get(owner);
    assert.ok(o);
    this.append({ kind: "agentRegistered", owner, publicKey: k.publicKey, modelFamily, harness: "test" }, o);
  }

  submit(id: string, author: string, files: string[], taskId: string | null = null): void {
    this.append(
      {
        kind: "submission",
        id,
        taskId,
        baseCommit: "base",
        headCommit: `head-${id}`,
        changedFiles: files,
        linesChanged: 20,
      },
      this.agentKey(author),
    );
    this.coordinator({ kind: "gateResult", submissionId: id, gate: "tests", pass: true, details: "ok" });
  }
  // A genuine draw over the member tree, with entropy tried until it seats
  // exactly the first rules.assignedReviewers of `reviewers` (the rest review
  // openly, which coverage counts the same). When the rules have more seats
  // than `reviewers`, a draw that also seats others is taken; those never
  // commit, so reveals wait for the commit deadline. Promotion verifies it.
  assign(id: string, reviewers: string[]): void {
    const want = reviewers.slice(0, this.state.rules.assignedReviewers).map((r) => this.agentKey(r).keyId);
    let fallback: EntryBody | undefined;
    for (let i = 0; i < 1024; i++) {
      const d = drawAssignment(this.state, id, `e-${i}`);
      if (!want.every((k) => d.reviewers.includes(k))) continue;
      if (d.reviewers.length === want.length) {
        this.coordinator(d.body);
        return;
      }
      fallback ??= d.body;
    }
    assert.ok(fallback, `no draw seats ${reviewers.join(", ")} on ${id}`);
    this.coordinator(fallback);
  }
  // All commits first, then all reveals: the ledger closes commits at the first
  // reveal, and reveals wait for the commit phase (every assigned reviewer
  // committed, or its deadline; a snapshot's always runs to its deadline).
  // A submission without an assignment gets the reviewers given.
  reviews(id: string, verdicts: [string, number][], on: "submission" | "snapshot" = "submission"): void {
    if (on === "submission" && !this.state.submissions.get(id)?.assignment) this.assign(id, verdicts.map(([a]) => a));
    const salts = verdicts.map(([agent]) => `salt-${id}-${agent}-${this.n++}`);
    verdicts.forEach(([agent, p], i) => {
      const v = { defectProbability: p, summary: "looked", findingIds: [] };
      const commitment = commitmentFor(v, salts[i] as string, this.agentKey(agent).keyId, on === "submission" ? { submissionId: id } : { snapshotId: id });
      const body: EntryBody =
        on === "submission"
          ? { kind: "reviewCommit", submissionId: id, commitment, stake: 5 }
          : { kind: "attestCommit", snapshotId: id, commitment, stake: 5 };
      this.append(body, this.agentKey(agent));
    });
    const hours = this.state.rules.review.commitHours;
    if (on === "snapshot") {
      this.t = Math.max(this.t, Date.parse(this.state.snapshots.get(id)?.at ?? "") + hours * HOUR);
    } else {
      const s = this.state.submissions.get(id);
      const a = s?.assignment;
      if (a && !a.reviewers.every((k) => s.reviews.some((r) => r.reviewer === k))) {
        this.t = Math.max(this.t, Date.parse(a.at ?? "") + hours * HOUR);
      }
    }
    verdicts.forEach(([agent, p], i) => {
      const verdict = { defectProbability: p, summary: "looked", findingIds: [] };
      const salt = salts[i] as string;
      const body: EntryBody =
        on === "submission"
          ? { kind: "reviewReveal", submissionId: id, verdict, salt }
          : { kind: "attestReveal", snapshotId: id, verdict, salt };
      this.append(body, this.agentKey(agent));
    });
  }
  // The ledger merges nothing unassigned: without an assignment one
  // reviewer outside the author's owner is drawn (and never reviews).
  merge(id: string): void {
    const s = this.state.submissions.get(id);
    if (s && !s.assignment) {
      const author = this.state.agents.get(s.author)?.owner;
      const pick = ["b1", "c1", "d1"].find((a) => this.state.agents.get(this.agentKey(a).keyId)?.owner !== author) as string;
      this.assign(id, [pick]);
    }
    this.coordinator({ kind: "merge", submissionId: id, commit: `merge-${id}` });
  }
  snapshot(id: string, submissionIds: string[], previousSnapshotId: string | null = null): void {
    this.coordinator({ kind: "snapshot", id, commit: `snap-${id}`, previousSnapshotId, submissionIds });
  }
  promote(id: string): void {
    this.coordinator({ kind: "promotion", snapshotId: id, commit: `snap-${id}` });
  }
  signoff(snapshotId: string, owner: string): void {
    const o = this.owners.get(owner);
    assert.ok(o);
    this.append({ kind: "signoff", snapshotId }, o);
  }
  finding(
    id: string,
    finder: string,
    target: { submissionId: string } | { snapshotId: string },
    severity: Severity,
  ): void {
    this.append(
      { kind: "finding", id, target, severity, testPath: `test/${id}.test.ts`, testCommand: "npm test", stake: 5 },
      this.agentKey(finder),
    );
  }
  // A reproduction is confirmed by the admin unless decide says otherwise.
  result(findingId: string, reproduced: boolean, decide: "confirm" | "dismiss" | "none" = "confirm"): void {
    this.coordinator({
      kind: "findingResult",
      findingId,
      reproduced,
      failsOnHead: reproduced,
      passesOnParent: true,
      logDigest: "d",
    });
    if (reproduced && decide !== "none") {
      this.append({ kind: "findingDecision", findingId, confirmed: decide === "confirm", reason: "judged" }, this.admin);
    }
  }

  // A plant through the normal path: committed by the custodian before the
  // submission, reviewed by one assigned reviewer, revealed after the window closed.
  plant(id: string, reviewer: string, p: number): void {
    const salt = `plantsalt${this.n++}`;
    this.append({ kind: "plantCommit", commitment: plantCommitment(id, salt) }, this.admin);
    this.submit(id, "k1", ring1("plant"));
    this.assign(id, [reviewer]);
    this.reviews(id, [[reviewer, p]]);
    this.append(
      { kind: "plantReveal", submissionId: id, salt, description: "off by one", severity: "high" },
      this.admin,
    );
  }
  plants(count: number, missed = 0): void {
    const reviewers = ["b1", "c1", "d1"];
    for (let i = 0; i < count; i++) {
      this.plant(`plant-${this.n}`, reviewers[i % reviewers.length] as string, i < missed ? 0.1 : 0.9);
    }
  }
}

// Every owner is admitted with no inviter, so every pair is at distance 2 in
// the member tree, and minTreeDistance 1 makes every non-author eligible.
// One assigned seat, so World.assign can seat exactly the reviewer a test
// names; the other reviewers a test names review openly.
function rules(over: (r: Rules) => void = () => {}): Rules {
  const r = projectRules();
  r.kernelSigners = ["erin", "frank"];
  r.minTreeDistance = 1;
  r.assignedReviewers = 1;
  over(r);
  return r;
}

// Five owners with agents of four families, two kernel signers without agents.
function people(r: Rules = rules()): World {
  const w = new World(r);
  for (const o of ["alice", "bob", "carol", "dave", "cust", "erin", "frank"]) w.owner(o);
  w.agent("a1", "alice", "claude");
  w.agent("b1", "bob", "gpt");
  w.agent("b2", "bob", "kimi");
  w.agent("c1", "carol", "qwen");
  w.agent("d1", "dave", "deepseek");
  w.agent("k1", "cust", "claude"); // the plant custodian's agent
  return w;
}

// s1 (alice) and s2 (bob), each reviewed by three families and three other
// owners, in snapshot S1 with one attestation, 60 caught plants, soaked 100h.
function healthy(opts: { plants?: number; missed?: number; rules?: Rules } = {}): World {
  const w = people(opts.rules);
  w.plants(opts.plants ?? 60, opts.missed ?? 0);
  w.submit("s1", "a1", ring1("routes"));
  w.assign("s1", ["b1", "c1"]);
  w.reviews("s1", [
    ["b1", 0.1],
    ["c1", 0.2],
  ]);
  w.merge("s1");
  w.submit("s2", "b1", ring1("votes"));
  w.assign("s2", ["c1", "d1"]);
  w.reviews("s2", [
    ["c1", 0.1],
    ["d1", 0.1],
    ["a1", 0.3], // open reviewer
  ]);
  w.merge("s2");
  w.snapshot("S1", ["s1", "s2"]);
  w.reviews("S1", [["d1", 0.1]], "snapshot");
  w.advance(100);
  return w;
}

function check(w: World, snapshotId: string, name: string, now = w.nowPlus(0)) {
  const r = evaluatePromotion(w.state, snapshotId, now);
  const c = r.checks.find((x) => x.name === name);
  assert.ok(c, `no check ${name} in ${JSON.stringify(r.checks)}`);
  return { ...c, overall: r.pass };
}

// --- tests ---------------------------------------------------------------------

test("a healthy snapshot passes every check, in the documented order", () => {
  const w = healthy();
  const r = evaluatePromotion(w.state, "S1", w.nowPlus(0));
  assert.deepEqual(
    r.checks.map((c) => c.name),
    ["notPromoted", "lineage", "coverage", "assignments", "recall", "criticals", "openIssues", "kernel", "soak"],
  );
  for (const c of r.checks) assert.equal(c.pass, true, `${c.name}: ${c.detail}`);
  assert.equal(r.pass, true);
  assert.match(check(w, "S1", "recall").detail, /^60\/60 /);
});

test("assignments: every covered draw must verify over the member tree before it; a hand-picked panel fails", () => {
  const w = people(rules((r) => (r.assignedReviewers = 2)));
  w.submit("s1", "a1", ring1("routes"));
  w.coordinator(drawAssignment(w.state, "s1", "round-1").body);
  w.submit("s2", "b1", ring1("votes"));
  // A hand-picked panel recorded with an honest beacon and tree digest: the ledger cannot tell.
  const honest = drawAssignment(w.state, "s2", "round-2").reviewers;
  const other = ["a1", "c1", "d1", "k1"].map((a) => w.agentKey(a).keyId).find((k) => !honest.includes(k));
  assert.ok(other);
  w.coordinator(assignmentBody(w.state, "s2", [honest[0] as KeyId, other], "round-2"));
  // Owners admitted later change the current tree, not the one each draw used.
  w.owner("gus");
  for (const sid of ["s1", "s2"]) w.merge(sid);
  w.snapshot("S1", ["s1", "s2"]);
  const c = check(w, "S1", "assignments");
  assert.equal(c.pass, false);
  assert.equal(c.overall, false);
  assert.match(c.detail, /^draw does not verify: s2$/);
});

test("assignments: a panel recorded over a made-up tree digest never reaches the ledger", () => {
  const w = people(rules((r) => (r.assignedReviewers = 2)));
  w.submit("s1", "a1", ring1("routes"));
  // A tree of the coordinator's choosing, in which only bob and carol are eligible.
  const made = treeDigest(
    treeFromParents({ [MEMBER_ROOT]: null, far: MEMBER_ROOT, alice: MEMBER_ROOT, bob: "far", carol: "far", dave: "alice", cust: "alice", erin: "alice", frank: "alice" }),
  );
  const body = assignmentBody(w.state, "s1", [w.agentKey("b1").keyId, w.agentKey("c1").keyId], "round-1");
  assert.throws(() => w.coordinator({ ...body, treeDigest: made, beacon: assignmentBeacon("s1", "head-s1", "round-1") }), /treeDigest/);
  assert.equal(w.state.submissions.get("s1")?.assignment, undefined);
});

test("unknown snapshot fails; a nowIso without a zone throws", () => {
  const w = people();
  const r = evaluatePromotion(w.state, "nope", "2026-10-02T00:00:00.000Z");
  assert.equal(r.pass, false);
  assert.deepEqual(
    r.checks.map((c) => c.name),
    ["snapshot"],
  );
  assert.throws(() => evaluatePromotion(w.state, "nope", "2026-10-02T00:00:00"), RangeError);
  assert.throws(() => evaluatePromotion(w.state, "nope", "yesterday"), RangeError);
});

test("notPromoted: a promoted snapshot cannot be promoted again", () => {
  const w = healthy();
  w.promote("S1");
  const c = check(w, "S1", "notPromoted");
  assert.equal(c.pass, false);
  assert.equal(c.overall, false);
  assert.match(c.detail, /already promoted/);
});

test("notPromoted: an ancestor already shipped by a descendant's promotion cannot be promoted (main would move back)", () => {
  const w = healthy();
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S1");
  w.promote("S2");
  const c = check(w, "S1", "notPromoted");
  assert.equal(c.pass, false);
  assert.match(c.detail, /descendant S2/);
});

test("coverage: a submission reviewed by two families fails and is named", () => {
  const w = healthy();
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S1"); // S1's attestation does not count for s3
  const c = check(w, "S2", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s3: 2\/3 families \[gpt,qwen\], 2\/2 owners/);
  // An attestation from a third family, within S2's commit phase, fixes it.
  w.reviews("S2", [["d1", 0.1]], "snapshot");
  assert.equal(check(w, "S2", "coverage").pass, true);
});

test("coverage: commits without reveals count for nothing", () => {
  const w = people();
  w.submit("s1", "a1", ring1("x"));
  w.assign("s1", ["b1", "c1"]);
  for (const a of ["b1", "c1", "d1"]) {
    w.append({ kind: "reviewCommit", submissionId: "s1", commitment: sha256hex(a), stake: 5 }, w.agentKey(a));
  }
  w.merge("s1");
  w.snapshot("S1", ["s1"]);
  const c = check(w, "S1", "coverage", w.nowPlus(100));
  assert.equal(c.pass, false);
  assert.match(c.detail, /s1: 0\/3 families \[\], 0\/2 owners/);
});

test("coverage: one owner's two agents are one owner (Sybil seats)", () => {
  const w = healthy({ rules: rules((r) => (r.promotion.minDistinctOwners = 3)) });
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.promote("S1"); // so S2 covers only s3, which bob may attest
  w.snapshot("S2", ["s3"], "S1");
  w.reviews("S2", [["b2", 0.1]], "snapshot"); // bob's second agent, a third family
  w.advance(100);
  const c = check(w, "S2", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s3: 3\/3 families \[gpt,kimi,qwen\], 2\/3 owners/);
});

test("coverage: an agent that obeyed a honeytoken stops vouching", () => {
  const w = healthy();
  assert.equal(check(w, "S1", "coverage").pass, true);
  w.coordinator({ kind: "honeytokenTriggered", agent: w.agentKey("c1").keyId, tokenId: "tok" });
  w.coordinator({ kind: "agentRevoked", agent: w.agentKey("c1").keyId, reason: "honeytoken tok" });
  const c = check(w, "S1", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s1: 2\/3 families \[deepseek,gpt\]/);
});

test("coverage: an agent the coordinator revoked for another reason (a leaked key) stops vouching too", () => {
  const w = healthy();
  w.coordinator({ kind: "agentRevoked", agent: w.agentKey("c1").keyId, reason: "key leaked" });
  assert.equal(w.state.agents.get(w.agentKey("c1").keyId)?.revokedBy, "coordinator");
  const c = check(w, "S1", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s1: 2\/3 families \[deepseek,gpt\]/);
});

test("coverage: an owner revoking their own agent (key rotation) does not withdraw its verdicts", () => {
  // Regression: revocation used to drop the verdicts, so an owner could make a
  // snapshot unpromotable for free once nobody could replace the coverage.
  const w = healthy();
  w.append(
    { kind: "agentRevoked", agent: w.agentKey("c1").keyId, reason: "rotating keys" },
    w.owners.get("carol") as Key,
  );
  assert.equal(w.state.agents.get(w.agentKey("c1").keyId)?.revokedBy, "owner");
  w.agent("c2", "carol", "qwen");
  assert.equal(check(w, "S1", "coverage").pass, true);
  assert.equal(evaluatePromotion(w.state, "S1", w.nowPlus(0)).pass, true);
});

test("coverage runs over unpromoted ancestors; attestations count only on the snapshot that lists the work", () => {
  const w = healthy();
  // s0: barely reviewed, parked in S0 which nobody promotes.
  w.submit("s0", "a1", ring1("parked"));
  w.assign("s0", ["b1"]);
  w.reviews("s0", [["b1", 0.1]]);
  w.merge("s0");
  w.snapshot("S0", ["s0"], "S1");
  w.reviews("S0", [["c1", 0.1]], "snapshot");
  // s3: well reviewed, in S2 on top of S0.
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S0");
  w.reviews("S2", [["d1", 0.1]], "snapshot");
  w.advance(100);
  assert.deepEqual(coveredSubmissionIds(w.state, "S2"), ["s3", "s0", "s1", "s2"]);
  const c = check(w, "S2", "coverage");
  assert.equal(c.pass, false, "s0 rides in on S2");
  // s0 has b1 (review) + c1 (S0 attestation, which saw it) = 2 families; d1
  // attested S2, whose diff starts at S0's commit and does not contain s0.
  assert.match(c.detail, /s0: 2\/3 families \[gpt,qwen\]/);
  assert.doesNotMatch(c.detail, /s3:|s1:|s2:/);

  // Once S0 is promoted (with its ancestor S1 shipped), S2 covers only s3.
  w.promote("S0");
  assert.deepEqual(coveredSubmissionIds(w.state, "S2"), ["s3"]);
  assert.equal(check(w, "S2", "coverage").pass, true);
});

test("coverage: attesters of a later snapshot do not vouch for an unattested ancestor (probe P1)", () => {
  // Regression: every attestation on the head snapshot used to count for every
  // covered submission, so s0 (one gpt review) reached main on S2.
  const w = healthy();
  w.promote("S1");
  w.submit("s0", "a1", ring1("weak"));
  w.assign("s0", ["b1"]);
  w.reviews("s0", [["b1", 0.1]]);
  w.merge("s0");
  w.snapshot("S0", ["s0"], "S1"); // nobody attests S0
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1"]);
  w.reviews("s3", [["b1", 0.1]]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S0");
  w.reviews(
    "S2",
    [
      ["c1", 0.1],
      ["d1", 0.1],
    ],
    "snapshot",
  );
  w.advance(100);
  const r = evaluatePromotion(w.state, "S2", w.nowPlus(0));
  const c = r.checks.find((x) => x.name === "coverage");
  assert.equal(c?.pass, false);
  assert.match(c?.detail ?? "", /s0: 1\/3 families \[gpt\], 1\/2 owners/);
  assert.doesNotMatch(c?.detail ?? "", /s3:/, "s3 is in S2, which c1 and d1 attested");
  assert.equal(r.pass, false);
});

test("lineage: a snapshot that skips an unpromoted earlier snapshot fails and names what it skipped", () => {
  const w = healthy(); // S1 unpromoted
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"]); // previous null, but S2's commit holds s1 and s2
  w.reviews("S2", [["d1", 0.1]], "snapshot");
  w.advance(100);
  const c = check(w, "S2", "lineage");
  assert.equal(c.pass, false);
  assert.equal(c.overall, false);
  assert.match(c.detail, /s1 \(in S1, not on this chain\); s2 \(in S1, not on this chain\)/);
  assert.equal(check(w, "S2", "coverage").pass, true, "every other check would have passed");
  // The same work on the proper chain passes.
  assert.equal(check(w, "S1", "lineage").pass, true);
});

test("lineage: a fork that drops an unreviewed ancestor fails; after a forced promotion the ancestor cannot follow (probe P2)", () => {
  const w = healthy();
  w.submit("s0", "a1", ring1("unreviewed")); // zero reviews
  w.merge("s0");
  w.snapshot("S0", ["s0"], "S1");
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S1"); // names S1, not S0
  w.reviews("S2", [["d1", 0.1]], "snapshot");
  w.advance(100);
  const c = check(w, "S2", "lineage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s0 \(in S0, not on this chain\)/);
  // Coverage, soak, openIssues and kernel only see the chain; lineage is what catches s0.
  assert.equal(check(w, "S2", "coverage").pass, true);

  // The ledger accepts a promotion the rule refused (e.g. an operator).
  w.promote("S2");
  const np = check(w, "S0", "notPromoted");
  assert.equal(np.pass, false, "main would move backwards");
  assert.match(np.detail, /main has moved past it: later snapshot S2 was promoted/);
});

test("lineage: a merge left out of every snapshot blocks; one merged after the snapshot or already on main does not", () => {
  const w = healthy();
  w.promote("S1");
  w.submit("lost", "a1", ring1("lost"));
  w.assign("lost", ["b1", "c1"]);
  w.reviews("lost", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("lost");
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S1"); // leaves "lost" out
  w.reviews("S2", [["d1", 0.1]], "snapshot");
  w.submit("after", "a1", ring1("after"));
  w.assign("after", ["b1"]);
  w.reviews("after", [["b1", 0.1]]);
  w.merge("after"); // merged after S2 was taken: not in S2's commit
  w.advance(100);
  const c = check(w, "S2", "lineage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /^merged before this snapshot but neither covered nor on main: lost \(in no snapshot\)$/);

  // Work merged before an already promoted snapshot was taken is on main: a
  // snapshot after that promotion does not ship it and is not blocked by it.
  const v = healthy();
  v.submit("early", "a1", ring1("early"));
  v.merge("early");
  v.submit("s3", "a1", ring1("x"));
  v.merge("s3");
  v.snapshot("P", ["s3"], "S1"); // omits "early"
  v.promote("P"); // forced past the rule
  v.submit("s4", "a1", ring1("y"));
  v.merge("s4");
  v.snapshot("S3", ["s4"], "P");
  assert.equal(check(v, "S3", "lineage").pass, true);
});

test("recall: fewer than minSeeds revealed plants fails even if all were caught", () => {
  const w = healthy({ plants: 20 });
  const c = check(w, "S1", "recall");
  assert.equal(c.pass, false);
  assert.match(c.detail, /^20\/20 /);
});

test("recall: enough seeds but too many missed fails", () => {
  const w = healthy({ plants: 60, missed: 12 });
  const c = check(w, "S1", "recall");
  assert.equal(c.pass, false, c.detail);
  assert.match(c.detail, /^48\/60 /);
});

test("recall and criticals: plants older than the window do not count", () => {
  const w = healthy();
  w.advance(29 * 24);
  const recall = check(w, "S1", "recall");
  assert.equal(recall.pass, false);
  assert.match(recall.detail, /^0\/0 /);
  const crit = check(w, "S1", "criticals");
  assert.equal(crit.pass, false);
  assert.match(crit.detail, /Infinity/);
});

test("criticals: 30 caught plants pass recall but not the critical bound (it needs ~55)", () => {
  const w = healthy({ plants: 30 });
  assert.equal(check(w, "S1", "recall").pass, true);
  const c = check(w, "S1", "criticals");
  assert.equal(c.pass, false);
  assert.match(c.detail, /0\.18\d/);
});

test("recall: an open reviewer flagging every plant does not buy recall (gaming)", () => {
  const w = people();
  for (let i = 0; i < 60; i++) {
    const id = `gamed-${i}`;
    const salt = `gs${i}`;
    w.append({ kind: "plantCommit", commitment: plantCommitment(id, salt) }, w.admin);
    w.submit(id, "k1", ring1("plant"));
    w.assign(id, ["b1"]);
    w.reviews(id, [
      ["b1", 0.1], // the assigned reviewer misses it
      ["d1", 1], // dave flags everything he is not assigned to
    ]);
    w.append({ kind: "plantReveal", submissionId: id, salt, description: "d", severity: "critical" }, w.admin);
  }
  w.submit("s1", "a1", ring1("x"));
  w.assign("s1", ["b1", "c1"]);
  w.reviews("s1", [
    ["b1", 0.1],
    ["c1", 0.1],
    ["d1", 1],
  ]);
  w.merge("s1");
  w.snapshot("S1", ["s1"]);
  w.advance(100);
  const c = check(w, "S1", "recall");
  assert.equal(c.pass, false);
  assert.match(c.detail, /^0\/60 /);
  assert.equal(check(w, "S1", "criticals").pass, false);
});

test("openIssues: an unresolved high finding blocks; not reproduced clears it; reproduced blocks", () => {
  const w = healthy();
  w.finding("f1", "c1", { submissionId: "s1" }, "high");
  let c = check(w, "S1", "openIssues");
  assert.equal(c.pass, false);
  assert.match(c.detail, /f1 \(high\) unresolved/);
  w.result("f1", false);
  assert.equal(check(w, "S1", "openIssues").pass, true);

  w.finding("f2", "c1", { submissionId: "s2" }, "critical");
  w.result("f2", true, "none");
  c = check(w, "S1", "openIssues");
  assert.equal(c.pass, false);
  assert.match(c.detail, /f2 \(critical\) reproduced, awaiting an operator's decision/);
  w.append({ kind: "findingDecision", findingId: "f2", confirmed: true, reason: "real" }, w.admin);
  assert.match(check(w, "S1", "openIssues").detail, /f2 \(critical\) a confirmed defect/);
});

test("openIssues: a dismissed reproduction (a change detector) is cleared", () => {
  const w = healthy();
  w.finding("f1", "c1", { submissionId: "s1" }, "critical");
  w.result("f1", true, "dismiss");
  assert.equal(check(w, "S1", "openIssues").pass, true);
});

test("openIssues: an unresolved finding of any severity blocks, as the coordinator's rule did; a reproduced one of any severity does (probe P4)", () => {
  // One rule: `commons promote run` and the coordinator used to disagree here
  // (the CLI shipped a snapshot with a pending low or medium finding).
  const w = healthy();
  w.finding("f1", "c1", { submissionId: "s1" }, "low");
  w.finding("f2", "d1", { submissionId: "s1" }, "medium");
  assert.equal(check(w, "S1", "openIssues").detail, "f1 (low) unresolved; f2 (medium) unresolved");
  w.result("f1", false);
  w.result("f2", false);
  w.finding("f3", "c1", { submissionId: "s2" }, "medium");
  w.result("f3", false);
  assert.equal(check(w, "S1", "openIssues").pass, true);
  // Regression: a reproduced defect labelled "medium" by the finder used to ship.
  w.finding("f4", "c1", { snapshotId: "S1" }, "medium");
  w.result("f4", true);
  const c = check(w, "S1", "openIssues");
  assert.equal(c.pass, false);
  assert.equal(c.detail, "f4 (medium) a confirmed defect");
  assert.equal(c.overall, false);
  w.finding("f5", "d1", { submissionId: "s1" }, "low");
  w.result("f5", true);
  assert.equal(check(w, "S1", "openIssues").detail, "f4 (medium) a confirmed defect; f5 (low) a confirmed defect");
});

test("openIssues: findings on the snapshot or a covered ancestor snapshot block; on another snapshot they do not", () => {
  const w = healthy();
  w.submit("s3", "a1", ring1("x"));
  w.assign("s3", ["b1", "c1"]);
  w.reviews("s3", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s3");
  w.snapshot("S2", ["s3"], "S1");
  w.advance(100);
  w.finding("f1", "c1", { snapshotId: "S1" }, "high"); // carol owns no covered work
  assert.equal(check(w, "S2", "openIssues").pass, false, "S1 is covered by S2");
  w.result("f1", false);
  w.finding("f2", "d1", { snapshotId: "S2" }, "critical");
  assert.match(check(w, "S2", "openIssues").detail, /f2 \(critical\) unresolved/);
  w.result("f2", false);
  assert.equal(check(w, "S2", "openIssues").pass, true);

  // A finding on an unrelated snapshot does not touch S2.
  w.submit("s9", "a1", ring1("y"));
  w.assign("s9", ["b1"]);
  w.reviews("s9", [["b1", 0.1]]);
  w.merge("s9");
  w.snapshot("X", ["s9"]);
  w.finding("f3", "c1", { snapshotId: "X" }, "critical");
  assert.equal(check(w, "S2", "openIssues").pass, true);
});

test("openIssues: a plant revealed after it merged is a known defect in the snapshot", () => {
  const w = people();
  w.plants(60);
  const salt = "latesalt";
  w.append({ kind: "plantCommit", commitment: plantCommitment("p-merged", salt) }, w.admin);
  w.submit("p-merged", "k1", ring1("plant"));
  w.assign("p-merged", ["b1"]);
  w.reviews("p-merged", [
    ["b1", 0.9],
    ["c1", 0.2],
    ["d1", 0.2],
  ]);
  w.merge("p-merged"); // the custodian was late
  w.snapshot("S1", ["p-merged"]);
  w.advance(100);
  assert.equal(check(w, "S1", "openIssues").pass, true, "unrevealed, it is indistinguishable");
  w.append({ kind: "plantReveal", submissionId: "p-merged", salt, description: "d", severity: "low" }, w.admin);
  const c = check(w, "S1", "openIssues");
  assert.equal(c.pass, false);
  assert.match(c.detail, /p-merged is a revealed plant \(low\)/);
});

function kernelWorld(r: Rules = rules()): World {
  const w = healthy({ rules: r });
  w.append(
    {
      kind: "proposal",
      id: "P1",
      title: "fix engine",
      evidence: [{ kind: "location", file: KERNEL_FILE, line: 1, note: "n" }],
    },
    w.agentKey("a1"),
  );
  w.coordinator({
    kind: "task",
    id: "T1",
    proposalId: "P1",
    ring: 0,
    acceptanceTestPaths: ["test/engine.test.ts"],
    sizeEstimate: 50,
    specAuthor: "carol",
  });
  w.append(
    { kind: "claim", taskId: "T1", until: w.nowPlus(24), stake: claimStake(50, 0, w.state.rules) },
    w.agentKey("a1"),
  );
  w.submit("sk", "a1", [KERNEL_FILE], "T1");
  w.assign("sk", ["b1", "c1"]);
  w.reviews("sk", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("sk");
  w.snapshot("S2", ["sk"], "S1");
  w.reviews("S2", [["d1", 0.1]], "snapshot");
  w.advance(100);
  return w;
}

test("kernel: no ring 0 change needs no sign-off", () => {
  const w = healthy();
  const c = check(w, "S1", "kernel");
  assert.equal(c.pass, true);
  assert.match(c.detail, /no covered submission touches ring 0/);
});

test("kernel: a ring 0 change needs k sign-offs from kernel signers", () => {
  const w = kernelWorld();
  let c = check(w, "S2", "kernel");
  assert.equal(c.pass, false);
  assert.match(c.detail, /ring 0 touched by sk; 0\/2/);
  w.signoff("S2", "erin");
  c = check(w, "S2", "kernel");
  assert.equal(c.pass, false);
  assert.match(c.detail, /1\/2 kernel sign-offs \[erin\]/);
  w.signoff("S2", "frank");
  assert.equal(check(w, "S2", "kernel").pass, true);
  assert.equal(evaluatePromotion(w.state, "S2", w.nowPlus(0)).pass, true);
});

test("kernel: sign-offs on an ancestor snapshot do not count; the ancestor's own ring 0 work is still covered", () => {
  const w = kernelWorld();
  w.signoff("S1", "erin"); // S1 touches no kernel; this is not a sign-off of sk
  w.signoff("S1", "frank");
  assert.equal(check(w, "S2", "kernel").pass, false);
  // A snapshot on top of S2 still covers sk.
  w.submit("s5", "a1", ring1("z"));
  w.assign("s5", ["b1", "c1"]);
  w.reviews("s5", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("s5");
  w.snapshot("S3", ["s5"], "S2");
  assert.match(check(w, "S3", "kernel").detail, /ring 0 touched by sk/);
});

test("kernel: a signer removed by a rules change no longer counts", () => {
  const w = kernelWorld();
  w.signoff("S2", "erin");
  w.signoff("S2", "frank");
  assert.equal(check(w, "S2", "kernel").pass, true);
  const next = rules((r) => {
    r.version = 2;
    r.kernelSigners = ["erin", "dave"];
  });
  w.append({ kind: "rulesChange", rules: next, pollId: "poll-1" }, w.admin);
  const c = check(w, "S2", "kernel");
  assert.equal(c.pass, false);
  assert.match(c.detail, /1\/2 kernel sign-offs \[erin\]/);
});

test("regression: a kernel signer's own non-kernel work in the snapshot does not stop its sign-off (Phase 1 would deadlock)", () => {
  // dave (agent d1) is a kernel signer and wrote a ring-1 change that S3
  // covers with alice's kernel change sk; alice, the kernel author, may not sign.
  const w = kernelWorld(rules((r) => (r.kernelSigners = ["dave", "alice"])));
  w.submit("sd", "d1", ring1("dave-docs"));
  w.assign("sd", ["b1", "c1"]);
  w.reviews("sd", [
    ["b1", 0.1],
    ["c1", 0.1],
  ]);
  w.merge("sd");
  w.snapshot("S3", ["sd"], "S2");
  assert.throws(() => w.signoff("S3", "alice"), /kernel changes include your own agents' work/);
  w.signoff("S3", "dave");
  const c = check(w, "S3", "kernel");
  assert.match(c.detail, /1\/\d kernel sign-offs \[dave\]/);
});

test("kernel: with no kernel signers named, ring 0 work cannot be promoted", () => {
  const w = kernelWorld(rules((r) => (r.kernelSigners = [])));
  const c = check(w, "S2", "kernel");
  assert.equal(c.pass, false);
  assert.match(c.detail, /no kernel signers named/);
});

test("soak: a submission merged less than soakFloorHours ago blocks; exactly the floor passes", () => {
  const w = people();
  w.plants(60);
  w.submit("s1", "a1", ring1("x"));
  w.assign("s1", ["b1", "c1"]);
  w.reviews("s1", [
    ["b1", 0.1],
    ["c1", 0.1],
    ["d1", 0.1],
  ]);
  w.merge("s1");
  const mergedAt = w.state.submissions.get("s1")?.merged?.at as string;
  w.snapshot("S1", ["s1"]);
  const at = (h: number) => new Date(Date.parse(mergedAt) + h * HOUR).toISOString();
  const young = check(w, "S1", "soak", at(50));
  assert.equal(young.pass, false);
  assert.match(young.detail, /s1 merged 50\.0h ago \(need >= 72h\)/);
  assert.equal(young.overall, false);
  assert.equal(check(w, "S1", "soak", at(72)).pass, true);
  assert.equal(evaluatePromotion(w.state, "S1", at(72)).pass, true);
});

test("soak: a fresh submission in an unpromoted ancestor blocks a later snapshot", () => {
  const w = healthy();
  for (const id of ["s4", "s3"]) {
    w.submit(id, "a1", ring1(id));
    w.assign(id, ["b1", "c1"]);
    w.reviews(id, [
      ["b1", 0.1],
      ["c1", 0.1],
    ]);
    w.merge(id);
    if (id === "s4") w.advance(50);
  }
  w.snapshot("S0", ["s3"], "S1"); // s3 merged last, parked in the ancestor
  w.snapshot("S2", ["s4"], "S0");
  const c = check(w, "S2", "soak", w.nowPlus(30));
  assert.equal(c.pass, false);
  assert.match(c.detail, /^s3 merged 30\.0h ago/);
  assert.doesNotMatch(c.detail, /s4|s1|s2/);
});

test("Phase 1 promotes: ten caught plants under phase1Rules pass the whole rule (protocol §5.11)", () => {
  const r = phase1Rules(projectRules());
  r.kernelSigners = ["erin"];
  const w = healthy({ plants: 10, rules: r });
  const result = evaluatePromotion(w.state, "S1", w.nowPlus(0));
  for (const c of result.checks) assert.equal(c.pass, true, `${c.name}: ${c.detail}`);
  // Nine of ten is not enough while there are fewer than twelve seeds.
  const missed = healthy({ plants: 10, missed: 1, rules: r });
  assert.equal(check(missed, "S1", "recall").pass, false);
});

test("Phase 1 as documented promotes: three owners, the custodian's agents review, two kernel signers, one signer's ring-0 work signed by the other", () => {
  // README / HANDOFF: alice holds the admin key and is the plant custodian;
  // alice, bob and carol each run two agents of different families; the
  // kernel signers are alice and bob. Every submission is checked against
  // the server's submit-credit rule before it is made.
  const r = phase1Rules(projectRules());
  r.kernelSigners = ["alice", "bob"];
  const w = new World(r);
  for (const o of ["alice", "bob", "carol"]) w.owner(o);
  w.agent("a1", "alice", "claude");
  w.agent("a2", "alice", "gpt");
  w.agent("b1", "bob", "gpt");
  w.agent("b2", "bob", "gemini");
  w.agent("c1", "carol", "gemini");
  w.agent("c2", "carol", "claude");
  const ownerOf = (a: string) => w.state.agents.get(w.agentKey(a).keyId)?.owner as string;
  const submit = (id: string, author: string, files: string[], taskId: string | null = null) => {
    assert.ok(submitCredits(w.state, ownerOf(author)) >= 1, `${ownerOf(author)} has a submit credit for ${id}`);
    w.submit(id, author, files, taskId);
  };
  // The custodian's batch, well ahead of any plant.
  const salts = Array.from({ length: 10 }, (_, i) => `plantsalt-${i}`);
  for (const [i, salt] of salts.entries()) w.append({ kind: "plantCommit", commitment: plantCommitment(`plant-${i}`, salt) }, w.admin);
  const merged: string[] = [];
  for (let i = 0; i < 10; i++) {
    // A plant through the custodian's own agents, rotating.
    const plant = `plant-${i}`;
    submit(plant, i % 2 === 0 ? "a1" : "a2", ring1(`p${i}`));
    w.reviews(plant, [
      [i % 2 === 0 ? "b1" : "b2", 0.9],
      [i % 2 === 0 ? "c1" : "c2", 0.8],
    ]);
    w.append({ kind: "plantReveal", submissionId: plant, salt: salts[i] as string, description: "off by one", severity: "high" }, w.admin);
    // Ordinary work by bob or carol, reviewed by the custodian's agent and the third owner's.
    const id = `work-${i}`;
    const [author, other] = i % 2 === 0 ? ["b1", "c1"] : ["c1", "b2"];
    submit(id, author, ring1(`w${i}`));
    w.reviews(id, [
      [i % 2 === 0 ? "a1" : "a2", 0.1],
      [other, 0.1],
    ]);
    w.merge(id);
    merged.push(id);
  }
  // A kernel change by alice, a kernel signer: bob signs it off.
  w.append({ kind: "proposal", id: "P1", title: "fix engine", evidence: [{ kind: "location", file: KERNEL_FILE, line: 1, note: "n" }] }, w.agentKey("a1"));
  w.coordinator({ kind: "task", id: "T1", proposalId: "P1", ring: 0, acceptanceTestPaths: ["test/engine.test.ts"], sizeEstimate: 50, specAuthor: "carol" });
  w.append({ kind: "claim", taskId: "T1", until: w.nowPlus(24), stake: claimStake(50, 0, w.state.rules) }, w.agentKey("a1"));
  submit("kernel", "a1", [KERNEL_FILE], "T1");
  w.reviews("kernel", [
    ["b2", 0.1],
    ["c2", 0.1],
  ]);
  w.merge("kernel");
  w.snapshot("S1", [...merged, "kernel"]);
  assert.throws(() => w.signoff("S1", "alice"), /your own agents' work/);
  w.signoff("S1", "bob");
  w.advance(r.promotion.soakFloorHours + 1);
  const result = evaluatePromotion(w.state, "S1", w.nowPlus(0));
  for (const c of result.checks) assert.equal(c.pass, true, `${c.name}: ${c.detail}`);
});
