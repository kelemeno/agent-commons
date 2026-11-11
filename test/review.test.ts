import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger, LedgerError, type Signer } from "../src/ledger";
import { brier, commitmentFor, reviewerScores, submissionOutcome, validateVerdict } from "../src/review";
import { defaultRules } from "../src/rules";
import type { CommonsState, EntryBody, KeyId, ReviewVerdict, Severity } from "../src/types";
import { assignmentBody } from "../src/selection";

// ---------------------------------------------------------------------------
// Fixture: a file-backed ledger with a clock in minutes. Owners alice (the
// author), bob, carol, dave, eve, one agent each (a1, b1, c1, d1, e1).
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const DAY = 24 * 60;
const iso = (minute: number) => new Date(T0 + minute * 60_000).toISOString();

const verdict = (p: number, summary = "looked at it"): ReviewVerdict => ({ defectProbability: p, summary, findingIds: [] });

class World {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "review-test-"));
  admin = generateKeyPair();
  coord = generateKeyPair();
  keys = new Map<string, Signer>();
  minute = 0;
  ledger: Ledger;
  fresh = 0;

  constructor() {
    this.ledger = Ledger.create(
      path.join(this.dir, "ledger.jsonl"),
      {
        kind: "genesis",
        project: "demo",
        admins: [this.admin.publicKey],
        coordinator: this.coord.publicKey,
        rules: defaultRules(),
      },
      iso(0),
    );
    const people: [string, string, string][] = [
      ["alice", "a1", "claude"],
      ["bob", "b1", "gpt"],
      ["carol", "c1", "qwen"],
      ["dave", "d1", "kimi"],
      ["eve", "e1", "glm"],
    ];
    for (const [owner] of people) {
      this.append({ kind: "ownerKey", owner, publicKey: this.key(owner).publicKey, inviter: null }, this.admin);
    }
    for (const [owner, agent, modelFamily] of people) {
      this.append(
        { kind: "agentRegistered", owner, publicKey: this.key(agent).publicKey, modelFamily, harness: "cli" },
        this.key(owner),
      );
    }
  }

  get state(): CommonsState {
    return this.ledger.state();
  }

  now(): string {
    return iso(this.minute);
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

  // Moves the clock to `minute` (never backwards).
  at(minute: number): this {
    this.minute = Math.max(this.minute, minute);
    return this;
  }

  submit(id: string, agent = "a1"): this {
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

  assign(submissionId: string, agents: string[]): this {
    this.append(assignmentBody(this.state, submissionId, agents.map((a) => this.id(a)), "e"), this.coord);
    return this;
  }

  commit(submissionId: string, agent: string, v: ReviewVerdict): string {
    const salt = `salt-${agent}-${submissionId}`;
    this.append({ kind: "reviewCommit", submissionId, commitment: commitmentFor(v, salt, this.id(agent), { submissionId }), stake: 5 }, this.key(agent));
    return salt;
  }

  reveal(submissionId: string, agent: string, v: ReviewVerdict): this {
    this.append({ kind: "reviewReveal", submissionId, verdict: v, salt: `salt-${agent}-${submissionId}` }, this.key(agent));
    return this;
  }

  // Assigned reviewers commit, then reveal: the window closes at the last reveal.
  reviewed(submissionId: string, verdicts: Record<string, number>): this {
    this.assign(submissionId, Object.keys(verdicts));
    for (const [a, p] of Object.entries(verdicts)) this.commit(submissionId, a, verdict(p));
    for (const [a, p] of Object.entries(verdicts)) this.reveal(submissionId, a, verdict(p));
    return this;
  }

  finding(
    target: { submissionId: string } | { snapshotId: string },
    agent: string,
    severity: Severity,
    reproduced: boolean,
  ): string {
    const id = `f${++this.fresh}`;
    this.append(
      { kind: "finding", id, target, severity, testPath: `test/${id}.test.ts`, testCommand: "npm test", stake: 5 },
      this.key(agent),
    );
    this.append(
      { kind: "findingResult", findingId: id, reproduced, failsOnHead: reproduced, passesOnParent: true, logDigest: "d" },
      this.coord,
    );
    // An operator confirms every reproduction here: only a confirmed one is a known defect.
    if (reproduced) this.append({ kind: "findingDecision", findingId: id, confirmed: true, reason: "real" }, this.admin);
    return id;
  }

  // The ledger merges nothing unassigned; d1 is drawn when nobody was.
  merge(submissionId: string): this {
    this.append({ kind: "gateResult", submissionId, gate: "size", pass: true, details: "" }, this.coord);
    if (!this.state.submissions.get(submissionId)?.assignment) this.assign(submissionId, ["d1"]);
    this.append({ kind: "merge", submissionId, commit: `m-${submissionId}` }, this.coord);
    return this;
  }

  snapshot(id: string, submissionIds: string[], previousSnapshotId: string | null = null): this {
    this.append({ kind: "snapshot", id, commit: `c-${id}`, previousSnapshotId, submissionIds }, this.coord);
    return this;
  }

  // Returns the minute of the promotion entry.
  promote(snapshotId: string): number {
    this.append({ kind: "promotion", snapshotId, commit: `c-${snapshotId}` }, this.coord);
    return this.minute;
  }

  plantCommit(submissionId: string): void {
    this.append({ kind: "plantCommit", commitment: sha256hex(`${submissionId}:plantsalt`) }, this.admin);
  }

  plantReveal(submissionId: string, severity: Severity): void {
    this.append({ kind: "plantReveal", submissionId, salt: "plantsalt", description: "planted", severity }, this.admin);
  }

  cleanup(): void {
    fs.rmSync(this.dir, { recursive: true, force: true });
  }
}

function setup(t: { after: (f: () => void) => void }): World {
  const w = new World();
  t.after(() => w.cleanup());
  return w;
}

// ---------------------------------------------------------------------------
// commitmentFor / validateVerdict / brier
// ---------------------------------------------------------------------------

test("commitmentFor binds verdict, salt, reviewer and subject", () => {
  const v = verdict(0.3);
  const c = (vv: ReviewVerdict, salt = "s", reviewer = "k1", subject: { submissionId: string } | { snapshotId: string } = { submissionId: "s1" }) =>
    commitmentFor(vv, salt, reviewer, subject);
  assert.equal(c(v), sha256hex(canonical({ verdict: v, salt: "s", reviewer: "k1", subject: { submissionId: "s1" } })));
  // Key order does not matter (canonical); content, salt, reviewer and subject do.
  assert.equal(c({ findingIds: [], summary: v.summary, defectProbability: 0.3 }), c(v));
  assert.notEqual(c(verdict(0.31)), c(v));
  assert.notEqual(c(v, "t"), c(v));
  assert.notEqual(c(v, "s", "k2"), c(v), "another reviewer cannot reuse the commitment");
  assert.notEqual(c(v, "s", "k1", { submissionId: "s2" }), c(v), "nor another submission");
  assert.notEqual(c(v, "s", "k1", { snapshotId: "s1" }), c(v), "nor a snapshot of the same id");
});

test("gaming: the ledger refuses a reveal that differs from the commitment", (t) => {
  const w = setup(t);
  w.submit("s1").assign("s1", ["b1"]);
  w.commit("s1", "b1", verdict(0.9));
  // The reviewer tries to reveal a better-looking probability under the same salt.
  assert.throws(
    () => w.reveal("s1", "b1", verdict(0.1)),
    (e: unknown) => e instanceof LedgerError && e.code === "commitment-mismatch",
  );
  w.reveal("s1", "b1", verdict(0.9));
});

test("validateVerdict accepts a good verdict and lists every problem", () => {
  assert.deepEqual(validateVerdict(verdict(0)), []);
  assert.deepEqual(validateVerdict(verdict(1)), []);
  assert.deepEqual(validateVerdict({ defectProbability: 0.5, summary: "", findingIds: ["f1", "f2"] }), []);
  assert.deepEqual(validateVerdict({ ...verdict(0.5), extra: undefined }), [], "undefined fields are dropped by canonical");
  for (const bad of [null, [], "x", 3, undefined]) assert.deepEqual(validateVerdict(bad), ["verdict is not an object"]);
  for (const p of [-0.01, 1.01, Number.NaN, Number.POSITIVE_INFINITY, "0.5", null]) {
    assert.deepEqual(validateVerdict({ ...verdict(0), defectProbability: p }), ["defectProbability must be a number in [0, 1]"]);
  }
  assert.deepEqual(validateVerdict({ ...verdict(0.5), summary: 1 }), ["summary must be a string"]);
  assert.deepEqual(validateVerdict({ ...verdict(0.5), findingIds: "f1" }), ["findingIds must be an array of strings"]);
  assert.deepEqual(validateVerdict({ ...verdict(0.5), findingIds: [1] }), ["findingIds must be an array of strings"]);
  assert.deepEqual(validateVerdict({ ...verdict(0.5), findingIds: [""] }), ["empty finding id"]);
  assert.deepEqual(validateVerdict({ ...verdict(0.5), findingIds: ["a", "a"] }), ["duplicate finding id"]);
  assert.deepEqual(validateVerdict({ ...verdict(0.5), severity: "high" }), ["unknown field severity"]);
  assert.equal(validateVerdict({}).length, 3);
});

test("validateVerdict agrees with the ledger's reveal check", (t) => {
  const w = setup(t);
  w.submit("s1").assign("s1", ["b1"]);
  const v = { ...verdict(0.5), findingIds: ["x", "x"] };
  assert.ok(validateVerdict(v).length > 0);
  w.commit("s1", "b1", v);
  assert.throws(() => w.reveal("s1", "b1", v), (e: unknown) => e instanceof LedgerError && e.code === "invalid-verdict");
});

test("brier is the squared error and rejects bad input", () => {
  assert.equal(brier(0, 0), 0);
  assert.equal(brier(1, 1), 0);
  assert.equal(brier(1, 0), 1);
  assert.equal(brier(0.5, 1), 0.25);
  assert.ok(Math.abs(brier(0.7, 1) - 0.09) < 1e-12);
  assert.ok(Math.abs(brier(0.2, 0) - 0.04) < 1e-12);
  for (const p of [-0.1, 1.1, Number.NaN, Number.POSITIVE_INFINITY]) assert.throws(() => brier(p, 1), RangeError);
  assert.throws(() => brier(0.5, 2 as 0 | 1), RangeError);
});

// ---------------------------------------------------------------------------
// submissionOutcome
// ---------------------------------------------------------------------------

test("outcome: unknown submission is null; a bad nowIso throws", (t) => {
  const w = setup(t);
  w.submit("s1");
  assert.equal(submissionOutcome(w.state, "nope", w.now()), null);
  assert.equal(submissionOutcome(w.state, "s1", w.now()), null, "nothing known yet");
  assert.throws(() => submissionOutcome(w.state, "s1", "yesterday"), RangeError);
  assert.throws(() => submissionOutcome(w.state, "s1", "2026-01-01T00:00:00"), RangeError, "no zone");
});

test("outcome: a reproduced finding of severity >= medium makes it 1", (t) => {
  const w = setup(t);
  for (const sev of ["medium", "high", "critical"] as const) {
    w.submit(`s-${sev}`);
    w.finding({ submissionId: `s-${sev}` }, "b1", sev, true);
    assert.equal(submissionOutcome(w.state, `s-${sev}`, w.now()), 1, sev);
  }
});

test("outcome: a finding that did not reproduce, or a low-severity one, is not a defect", (t) => {
  const w = setup(t);
  w.submit("s1");
  w.finding({ submissionId: "s1" }, "b1", "critical", false);
  assert.equal(submissionOutcome(w.state, "s1", w.now()), null);
  w.submit("s2");
  w.finding({ submissionId: "s2" }, "b1", "low", true);
  assert.equal(submissionOutcome(w.state, "s2", w.now()), null);
});

test("outcome: a revealed plant is 1; an unrevealed or low plant is not", (t) => {
  const w = setup(t);
  w.plantCommit("p1");
  w.plantCommit("p2");
  w.submit("p1").reviewed("p1", { b1: 0.2 });
  w.submit("p2").reviewed("p2", { b1: 0.2 });
  assert.equal(submissionOutcome(w.state, "p1", w.now()), null, "until revealed, a plant is ordinary work");
  w.plantReveal("p1", "high");
  w.plantReveal("p2", "low");
  assert.equal(submissionOutcome(w.state, "p1", w.now()), 1);
  assert.equal(submissionOutcome(w.state, "p2", w.now()), null);
});

test("outcome: shipped and past the vesting tail is 0, not a minute earlier", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1");
  const notMerged = "s2";
  w.submit(notMerged);
  assert.equal(submissionOutcome(w.state, "s1", iso(w.minute + 365 * DAY)), null, "merged is not shipped");
  w.snapshot("snap1", ["s1"]);
  assert.equal(submissionOutcome(w.state, "s1", iso(w.minute + 365 * DAY)), null, "snapshotted is not shipped");
  const promoted = w.promote("snap1");
  const tail = defaultRules().vesting.tailDays * DAY;
  assert.equal(submissionOutcome(w.state, "s1", iso(promoted)), null);
  assert.equal(submissionOutcome(w.state, "s1", iso(promoted + tail - 1)), null);
  assert.equal(submissionOutcome(w.state, "s1", iso(promoted + tail)), 0);
  assert.equal(submissionOutcome(w.state, "s1", iso(promoted + tail + DAY)), 0);
  assert.equal(submissionOutcome(w.state, notMerged, iso(promoted + tail)), null);
});

test("outcome: an offset nowIso is read as the same instant", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1").snapshot("snap1", ["s1"]);
  const promoted = w.promote("snap1");
  const tailMs = defaultRules().vesting.tailDays * DAY * 60_000;
  const exact = new Date(T0 + promoted * 60_000 + tailMs);
  // The same instant written as 02:00 at +02:00.
  const shifted = new Date(exact.getTime() + 2 * 3_600_000).toISOString().replace("Z", "+02:00").replace(".000", "");
  assert.equal(submissionOutcome(w.state, "s1", shifted), 0);
});

test("outcome: promoting a later snapshot ships the earlier unpromoted one", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1").snapshot("snap1", ["s1"]);
  w.submit("s2").reviewed("s2", { b1: 0.1 }).merge("s2").snapshot("snap2", ["s2"], "snap1");
  const promoted = w.promote("snap2");
  const after = iso(promoted + defaultRules().vesting.tailDays * DAY);
  assert.equal(submissionOutcome(w.state, "s1", after), 0);
  assert.equal(submissionOutcome(w.state, "s2", after), 0);
});

test("outcome: a reproduced finding on the carrying snapshot (an escape) leaves it unknown", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1");
  w.submit("s2").reviewed("s2", { b1: 0.1 }).merge("s2");
  w.snapshot("snap1", ["s1"]);
  w.snapshot("snap2", ["s2"], "snap1");
  w.promote("snap1");
  const promoted = w.promote("snap2");
  const fid = w.finding({ snapshotId: "snap2" }, "c1", "high", true);
  w.append({ kind: "escape", findingId: fid, snapshotId: "snap2" }, w.coord);
  const after = iso(promoted + defaultRules().vesting.tailDays * DAY);
  assert.equal(submissionOutcome(w.state, "s2", after), null, "cannot be pinned on s2, cannot be called clean");
  assert.equal(submissionOutcome(w.state, "s1", after), 0, "an earlier snapshot is not implicated");
});

test("outcome: a defect found after the tail still flips it to 1", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1").snapshot("snap1", ["s1"]);
  const promoted = w.promote("snap1");
  const tail = defaultRules().vesting.tailDays * DAY;
  assert.equal(submissionOutcome(w.state, "s1", iso(promoted + tail)), 0);
  w.at(promoted + tail + DAY);
  w.finding({ submissionId: "s1" }, "c1", "medium", true);
  assert.equal(submissionOutcome(w.state, "s1", w.now()), 1);
});

// ---------------------------------------------------------------------------
// reviewerScores
// ---------------------------------------------------------------------------

// X is defective (reproduced finding), Y is clean (shipped, tail passed), P is a
// high plant. b1 is well calibrated, c1 is not.
function scenario(w: World): { promoted: number } {
  w.submit("X").reviewed("X", { b1: 0.9, c1: 0.2 });
  w.finding({ submissionId: "X" }, "d1", "high", true);
  w.submit("Y").reviewed("Y", { b1: 0.1, c1: 0.6 }).merge("Y").snapshot("snapY", ["Y"]);
  const promoted = w.promote("snapY");
  w.plantCommit("P");
  w.submit("P").reviewed("P", { b1: 0.8, c1: 0.1 });
  w.plantReveal("P", "high");
  return { promoted };
}

const close = (a: number, b: number) => assert.ok(Math.abs(a - b) < 1e-12, `${a} != ${b}`);

test("reviewerScores: mean Brier over scored reviews, plants seen and caught", (t) => {
  const w = setup(t);
  const { promoted } = scenario(w);
  const after = iso(promoted + defaultRules().vesting.tailDays * DAY);
  const scores = reviewerScores(w.state, after);
  const b = scores.get(w.id("b1"));
  const c = scores.get(w.id("c1"));
  assert.ok(b && c);
  assert.deepEqual({ ...b, meanBrier: 0 }, { reviews: 3, scored: 3, meanBrier: 0, plantsSeen: 1, plantsCaught: 1, unrevealed: 0 });
  close(b.meanBrier, (brier(0.9, 1) + brier(0.1, 0) + brier(0.8, 1)) / 3);
  assert.deepEqual({ ...c, meanBrier: 0 }, { reviews: 3, scored: 3, meanBrier: 0, plantsSeen: 1, plantsCaught: 0, unrevealed: 0 });
  close(c.meanBrier, (brier(0.2, 1) + brier(0.6, 0) + brier(0.1, 1)) / 3);
  assert.ok(b.meanBrier < c.meanBrier);
  assert.equal(scores.has(w.id("a1")), false, "authors are not reviewers");
  assert.equal(scores.has(w.id("d1")), false, "d1 only filed a finding on real work");
});

test("reviewerScores: an empty ledger has no scores", (t) => {
  assert.equal(reviewerScores(setup(t).state, iso(0)).size, 0);
});

test("reviewerScores: before the tail passes the clean submission is unscored", (t) => {
  const w = setup(t);
  const { promoted } = scenario(w);
  const b = reviewerScores(w.state, iso(promoted + 1)).get(w.id("b1"));
  assert.ok(b);
  assert.equal(b.reviews, 3);
  assert.equal(b.scored, 2);
  close(b.meanBrier, (brier(0.9, 1) + brier(0.8, 1)) / 2);
});

test("reviewerScores: nothing known means scored 0 and meanBrier 0", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.4 });
  const b = reviewerScores(w.state, w.now()).get(w.id("b1"));
  assert.deepEqual(b, { reviews: 1, scored: 0, meanBrier: 0, plantsSeen: 0, plantsCaught: 0, unrevealed: 0 });
});

test("gaming: revealing only after the outcome is known scores as a forfeit", (t) => {
  const w = setup(t);
  w.submit("X").assign("X", ["b1"]);
  w.commit("X", "b1", verdict(0.3));
  w.commit("X", "e1", verdict(0.95)); // an open reviewer, committed in time
  w.reveal("X", "b1", verdict(0.3)); // closes the review window
  w.finding({ submissionId: "X" }, "d1", "high", true);
  w.reveal("X", "e1", verdict(0.95)); // revealed once the defect is public
  const scores = reviewerScores(w.state, w.now());
  // A perfect-looking late reveal earns nothing: scored as Brier 1, and visible as unrevealed.
  assert.deepEqual(scores.get(w.id("e1")), { reviews: 1, scored: 1, meanBrier: 1, plantsSeen: 0, plantsCaught: 0, unrevealed: 1 });
  const b = scores.get(w.id("b1"));
  assert.ok(b);
  assert.equal(b.scored, 1);
  close(b.meanBrier, brier(0.3, 1));
});

test("gaming: a reviewer who never reveals is unrevealed and scored as confidently wrong", (t) => {
  const w = setup(t);
  w.submit("X").assign("X", ["b1"]);
  w.commit("X", "b1", verdict(0.3));
  w.commit("X", "e1", verdict(0.3));
  w.reveal("X", "b1", verdict(0.3));
  w.finding({ submissionId: "X" }, "d1", "high", true);
  const e = reviewerScores(w.state, w.now()).get(w.id("e1"));
  assert.deepEqual(e, { reviews: 0, scored: 1, meanBrier: 1, plantsSeen: 0, plantsCaught: 0, unrevealed: 1 });
});

test("reviewerScores: a plant caught by a reproduced finding counts for the finder", (t) => {
  const w = setup(t);
  w.plantCommit("P");
  w.submit("P").assign("P", ["b1"]);
  w.commit("P", "b1", verdict(0.1));
  w.finding({ submissionId: "P" }, "e1", "high", true); // closes the window: the finding reproduced
  w.reveal("P", "b1", verdict(0.1)); // after the window: not scored, and no catch
  w.plantReveal("P", "high");
  const scores = reviewerScores(w.state, w.now());
  const e = scores.get(w.id("e1"));
  assert.deepEqual(e, { reviews: 0, scored: 0, meanBrier: 0, plantsSeen: 1, plantsCaught: 1, unrevealed: 0 });
  const b = scores.get(w.id("b1"));
  assert.ok(b);
  assert.equal(b.plantsSeen, 1);
  assert.equal(b.plantsCaught, 0);
  assert.equal(b.scored, 1, "the late reveal is scored as a forfeit");
  assert.equal(b.meanBrier, 1);
  assert.equal(b.unrevealed, 1);
});

test("reviewerScores is deterministic and the same after reopening the ledger", (t) => {
  const w = setup(t);
  const { promoted } = scenario(w);
  const after = iso(promoted + 40 * DAY);
  const a = reviewerScores(w.state, after);
  assert.deepEqual(reviewerScores(Ledger.open(w.ledger.path).state(), after), a);
  assert.deepEqual(reviewerScores(w.state, after), a);
});

// ---------------------------------------------------------------------------
// Regressions from review
// ---------------------------------------------------------------------------

test("gaming: withholding a reveal until a finding reproduces does not erase a wrong call", (t) => {
  // b1 commits p = 0.05 on two submissions, sees a high finding filed, waits
  // for it to reproduce and only then reveals. c1 reveals honestly.
  const w = setup(t);
  for (const id of ["X1", "X2"]) {
    w.submit(id).assign(id, ["b1", "c1"]);
    w.commit(id, "b1", verdict(0.05));
    w.commit(id, "c1", verdict(0.05));
    w.reveal(id, "c1", verdict(0.05));
    w.finding({ submissionId: id }, "d1", "high", true); // closes the window
    w.reveal(id, "b1", verdict(0.05));
  }
  const scores = reviewerScores(w.state, w.now());
  const b = scores.get(w.id("b1"));
  const c = scores.get(w.id("c1"));
  assert.ok(b && c);
  assert.deepEqual(b, { reviews: 2, scored: 2, meanBrier: 1, plantsSeen: 0, plantsCaught: 0, unrevealed: 2 });
  assert.equal(c.scored, 2);
  close(c.meanBrier, brier(0.05, 1));
  assert.ok(b.meanBrier >= c.meanBrier, "withholding never beats revealing");
});

test("reviewerScores: a commit whose window is still open is neither scored nor unrevealed", (t) => {
  const w = setup(t);
  w.submit("X").assign("X", ["b1", "c1"]);
  w.commit("X", "b1", verdict(0.4));
  w.commit("X", "c1", verdict(0.4));
  w.reveal("X", "c1", verdict(0.4)); // b1 still to reveal: the window is open
  const b = reviewerScores(w.state, w.now()).get(w.id("b1"));
  assert.deepEqual(b, { reviews: 0, scored: 0, meanBrier: 0, plantsSeen: 0, plantsCaught: 0, unrevealed: 0 });
});

test("reviewerScores: a missed reveal on an unknown outcome is unrevealed but unscored", (t) => {
  const w = setup(t);
  w.submit("X").assign("X", ["b1"]);
  w.commit("X", "b1", verdict(0.4));
  w.merge("X"); // closes the window; nothing known about X yet
  const b = reviewerScores(w.state, w.now()).get(w.id("b1"));
  assert.deepEqual(b, { reviews: 0, scored: 0, meanBrier: 0, plantsSeen: 0, plantsCaught: 0, unrevealed: 1 });
});

test("reviewerScores throws on a bad nowIso even on an empty ledger", (t) => {
  assert.throws(() => reviewerScores(setup(t).state, "2026-01-01T00:00:00"), RangeError);
});

test("outcome: a snapshot finding on a later snapshot leaves its unpromoted ancestors unknown", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1").snapshot("snap1", ["s1"]);
  w.submit("s2").reviewed("s2", { b1: 0.1 }).merge("s2").snapshot("snap2", ["s2"], "snap1");
  const promoted = w.promote("snap2"); // ships snap1 too; snap1 itself was never promoted
  w.finding({ snapshotId: "snap2" }, "c1", "high", true);
  const after = iso(promoted + defaultRules().vesting.tailDays * DAY);
  assert.equal(submissionOutcome(w.state, "s2", after), null);
  assert.equal(submissionOutcome(w.state, "s1", after), null, "s1 is in what snap2 covers, so it may be the culprit");
  assert.equal(reviewerScores(w.state, after).get(w.id("b1"))?.scored, 0, "nobody is rewarded for calling s1 clean");
});

test("outcome: a low-severity snapshot finding or escape does not block a clean outcome", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1").snapshot("snap1", ["s1"]);
  const promoted = w.promote("snap1");
  const fid = w.finding({ snapshotId: "snap1" }, "c1", "low", true);
  w.append({ kind: "escape", findingId: fid, snapshotId: "snap1" }, w.coord);
  const after = iso(promoted + defaultRules().vesting.tailDays * DAY);
  assert.equal(submissionOutcome(w.state, "s1", after), 0, "the verdict predicts defects of severity >= medium only");
});

test("outcome: shipped time is the earliest promotion that covers the submission", (t) => {
  const w = setup(t);
  w.submit("s1").reviewed("s1", { b1: 0.1 }).merge("s1").snapshot("snap1", ["s1"]);
  const first = w.promote("snap1");
  w.at(first + 10 * DAY);
  w.submit("s2").reviewed("s2", { b1: 0.1 }).merge("s2").snapshot("snap2", ["s2"], "snap1");
  w.promote("snap2");
  const tail = defaultRules().vesting.tailDays * DAY;
  assert.equal(submissionOutcome(w.state, "s1", iso(first + tail)), 0);
  assert.equal(submissionOutcome(w.state, "s2", iso(first + tail)), null);
});

test("validateVerdict wants a plain object with its own fields, like the ledger", () => {
  const inherited = Object.create({ defectProbability: 0.5, summary: "", findingIds: [] }) as unknown;
  assert.deepEqual(validateVerdict(inherited), ["verdict is not a plain object"]);
  class V {
    defectProbability = 0.5;
    summary = "";
    findingIds: string[] = [];
  }
  assert.deepEqual(validateVerdict(new V()), ["verdict is not a plain object"]);
  const bare = Object.assign(Object.create(null) as object, verdict(0.5));
  assert.deepEqual(validateVerdict(bare), []);
});

test("validateVerdict checks shape only: the ledger also requires findings on this submission", (t) => {
  const w = setup(t);
  w.submit("s1").submit("s2").assign("s1", ["b1"]);
  const elsewhere = w.finding({ submissionId: "s2" }, "c1", "high", false);
  const v = { ...verdict(0.5), findingIds: [elsewhere] };
  assert.deepEqual(validateVerdict(v), []);
  w.commit("s1", "b1", v);
  assert.throws(() => w.reveal("s1", "b1", v), (e: unknown) => e instanceof LedgerError && e.code === "invalid-target");
});
