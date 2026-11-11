import { after, test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger } from "../src/ledger";
import { plantCommitment } from "../src/plants";
import { coveredSubmissionIds, evaluatePromotion } from "../src/promotion";
import { claimStake, defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import type { EntryBody, KeyId, ModelFamily, Rules, Severity } from "../src/types";

// --- a real, signed ledger ----------------------------------------------------

type Key = { publicKey: string; privateKey: string; keyId: KeyId };
const key = (): Key => {
  const k = generateKeyPair();
  return { ...k, keyId: keyIdOf(k.publicKey) };
};

const T0 = Date.UTC(2026, 9, 1); // 2026-10-01
const HOUR = 3_600_000;
const ring1 = (name: string) => [`anthill-backend/src/${name}.ts`];

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
      { kind: "genesis", project: "anthill", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
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
  assign(id: string, reviewers: string[]): void {
    this.coordinator({
      kind: "reviewAssignment",
      submissionId: id,
      beacon: "beacon",
      reviewers: reviewers.map((r) => this.agentKey(r).keyId),
    });
  }
  // All commits first, then all reveals: the ledger closes commits at the first reveal.
  reviews(id: string, verdicts: [string, number][], on: "submission" | "snapshot" = "submission"): void {
    const salts = verdicts.map(([agent]) => `salt-${id}-${agent}-${this.n++}`);
    verdicts.forEach(([agent, p], i) => {
      const v = { defectProbability: p, summary: "looked", findingIds: [] };
      const commitment = sha256hex(canonical(v) + salts[i]);
      const body: EntryBody =
        on === "submission"
          ? { kind: "reviewCommit", submissionId: id, commitment, stake: 5 }
          : { kind: "attestCommit", snapshotId: id, commitment, stake: 5 };
      this.append(body, this.agentKey(agent));
    });
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
  merge(id: string): void {
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
  result(findingId: string, reproduced: boolean): void {
    this.coordinator({
      kind: "findingResult",
      findingId,
      reproduced,
      failsOnHead: reproduced,
      passesOnParent: true,
      logDigest: "d",
    });
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

const tree = treeFromParents({ root: null, alice: "root", bob: "root", carol: "root", dave: "root", cust: "root" });

function rules(over: (r: Rules) => void = () => {}): Rules {
  const r = defaultRules();
  r.kernelSigners = ["erin", "frank"];
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
  const r = evaluatePromotion(w.state, tree, snapshotId, now);
  const c = r.checks.find((x) => x.name === name);
  assert.ok(c, `no check ${name} in ${JSON.stringify(r.checks)}`);
  return { ...c, overall: r.pass };
}

// --- tests ---------------------------------------------------------------------

test("a healthy snapshot passes every check, in the documented order", () => {
  const w = healthy();
  const r = evaluatePromotion(w.state, tree, "S1", w.nowPlus(0));
  assert.deepEqual(
    r.checks.map((c) => c.name),
    ["notPromoted", "coverage", "recall", "criticals", "openIssues", "kernel", "soak"],
  );
  for (const c of r.checks) assert.equal(c.pass, true, `${c.name}: ${c.detail}`);
  assert.equal(r.pass, true);
  assert.match(check(w, "S1", "recall").detail, /^60\/60 /);
});

test("unknown snapshot fails; a nowIso without a zone throws", () => {
  const w = people();
  const r = evaluatePromotion(w.state, tree, "nope", "2026-10-02T00:00:00.000Z");
  assert.equal(r.pass, false);
  assert.deepEqual(
    r.checks.map((c) => c.name),
    ["snapshot"],
  );
  assert.throws(() => evaluatePromotion(w.state, tree, "nope", "2026-10-02T00:00:00"), RangeError);
  assert.throws(() => evaluatePromotion(w.state, tree, "nope", "yesterday"), RangeError);
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
  w.snapshot("S2", ["s3"]); // previous null: covers only s3, no attestation
  w.advance(100);
  const c = check(w, "S2", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s3: 2\/3 families \[gpt,qwen\], 2\/2 owners/);
  // An attestation from a third family fixes it.
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
  w.snapshot("S2", ["s3"]);
  w.reviews("S2", [["b2", 0.1]], "snapshot"); // bob's second agent, a third family
  w.advance(100);
  const c = check(w, "S2", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s3: 3\/3 families \[gpt,kimi,qwen\], 2\/3 owners/);
});

test("coverage: a revoked reviewer's verdict stops vouching", () => {
  const w = healthy();
  assert.equal(check(w, "S1", "coverage").pass, true);
  w.append(
    { kind: "agentRevoked", agent: w.agentKey("c1").keyId, reason: "obeyed a honeytoken" },
    w.owners.get("carol") as Key,
  );
  const c = check(w, "S1", "coverage");
  assert.equal(c.pass, false);
  assert.match(c.detail, /s1: 2\/3 families/);
});

test("coverage runs over unpromoted ancestors; attestations count only on the snapshot itself", () => {
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
  // s0 has b1 (review) + d1 (S2 attestation) = 2 families; c1's attestation was on S0.
  assert.match(c.detail, /s0: 2\/3 families \[deepseek,gpt\]/);
  assert.doesNotMatch(c.detail, /s3:|s1:|s2:/);

  // Once S0 is promoted (with its ancestor S1 shipped), S2 covers only s3.
  w.promote("S0");
  assert.deepEqual(coveredSubmissionIds(w.state, "S2"), ["s3"]);
  assert.equal(check(w, "S2", "coverage").pass, true);
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
  w.result("f2", true);
  c = check(w, "S1", "openIssues");
  assert.equal(c.pass, false);
  assert.match(c.detail, /f2 \(critical\) reproduced/);
});

test("openIssues: low and medium findings never block", () => {
  const w = healthy();
  w.finding("f1", "c1", { submissionId: "s1" }, "low");
  w.finding("f2", "d1", { submissionId: "s1" }, "medium");
  w.finding("f3", "c1", { submissionId: "s2" }, "medium");
  w.result("f3", true);
  assert.equal(check(w, "S1", "openIssues").pass, true);
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
      evidence: [{ kind: "location", file: "anthill-backend/src/engine.ts", line: 1, note: "n" }],
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
  w.submit("sk", "a1", ["anthill-backend/src/engine.ts"], "T1");
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
  assert.equal(evaluatePromotion(w.state, tree, "S2", w.nowPlus(0)).pass, true);
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
  assert.equal(evaluatePromotion(w.state, tree, "S1", at(72)).pass, true);
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
