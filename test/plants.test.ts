import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  atOrAfter,
  CATCH_THRESHOLD,
  instantMs,
  plantCaught,
  plantCaughtBy,
  plantCommitment,
  plantCommitmentMatches,
  plantStats,
  revealedPlants,
  reviewWindowClosed,
  reviewWindowCloseSeq,
  UNKNOWN_FAMILY,
} from "../src/plants";
import type { CommonsState, Rules, Severity, SubmissionState } from "../src/types";

// --- hand-built state (no ledger.ts) ----------------------------------------
// `state.length` doubles as the next seq, so every helper call is one entry and
// call order is ledger order.

function emptyState(): CommonsState {
  return {
    project: "p",
    rules: {} as Rules, // plants.ts never reads rules
    adminKeys: [],
    coordinatorKey: "coord",
    publicKeys: new Map(),
    owners: new Map(),
    ownerByKey: new Map(),
    agents: new Map(),
    proposals: new Map(),
    tasks: new Map(),
    claims: new Map(),
    submissions: new Map(),
    findings: new Map(),
    snapshots: new Map(),
    plantCommitments: [],
    honeytokens: [],
    escapes: [],
    settlements: [],
    headHash: "",
    length: 1,
  };
}

const next = (s: CommonsState): number => s.length++;

function agent(s: CommonsState, keyId: string, owner: string, modelFamily: string): void {
  s.agents.set(keyId, { keyId, owner, modelFamily, harness: "h", active: true });
}

function sub(s: CommonsState, id: string): SubmissionState {
  const x = s.submissions.get(id);
  assert.ok(x, `no submission ${id}`);
  return x;
}

function submission(
  s: CommonsState,
  id: string,
  author: string,
  opts: { at?: string; planted?: Severity; assigned?: string[] } = {},
): SubmissionState {
  const x: SubmissionState = {
    id,
    author,
    taskId: null,
    baseCommit: "b",
    headCommit: "h",
    changedFiles: [],
    linesChanged: 1,
    submittedSeq: next(s),
    submittedAt: opts.at ?? "2026-10-01T00:00:00Z",
    gates: [],
    reviews: [],
    findingIds: [],
  };
  if (opts.assigned) x.assignment = { beacon: "b", reviewers: opts.assigned, seq: next(s) };
  if (opts.planted) x.planted = { severity: opts.planted, description: "planted bug" };
  s.submissions.set(id, x);
  return x;
}

function commit(s: CommonsState, submissionId: string, reviewer: string): void {
  sub(s, submissionId).reviews.push({ reviewer, commitment: "c", stake: 1, committedSeq: next(s) });
}

function reveal(s: CommonsState, submissionId: string, reviewer: string, p: number): void {
  const r = sub(s, submissionId).reviews.find((v) => v.reviewer === reviewer);
  assert.ok(r, `${reviewer} did not commit on ${submissionId}`);
  r.verdict = { defectProbability: p, summary: "", findingIds: [] };
  r.revealedSeq = next(s);
}

// Commit and reveal at once; p undefined = committed but never revealed.
function review(s: CommonsState, submissionId: string, reviewer: string, p?: number): void {
  commit(s, submissionId, reviewer);
  if (p !== undefined) reveal(s, submissionId, reviewer, p);
}

function finding(
  s: CommonsState,
  id: string,
  finder: string,
  target: { submissionId: string } | { snapshotId: string },
  reproduced?: boolean,
): void {
  s.findings.set(id, {
    id,
    finder,
    target,
    severity: "high",
    testPath: "t",
    testCommand: "c",
    stake: 1,
    seq: next(s),
    at: "2026-10-02T00:00:00Z",
  });
  if (reproduced !== undefined) result(s, id, reproduced);
  if ("submissionId" in target) s.submissions.get(target.submissionId)?.findingIds.push(id);
}

function result(s: CommonsState, findingId: string, reproduced: boolean): void {
  const f = s.findings.get(findingId);
  assert.ok(f);
  f.result = { reproduced, failsOnHead: reproduced, passesOnParent: true, logDigest: "d", seq: next(s) };
}

function merge(s: CommonsState, submissionId: string): void {
  sub(s, submissionId).merged = { commit: "m", seq: next(s), at: "2026-10-03T00:00:00Z" };
}

// author A (owner oa, claude); reviewers R1 (o1, gpt), R2 (o2, gpt), R3 (o3, qwen);
// A2 is a second agent of the author's owner; X (ox, deepseek) is an open reviewer.
function world(): CommonsState {
  const s = emptyState();
  agent(s, "A", "oa", "claude");
  agent(s, "A2", "oa", "kimi");
  agent(s, "R1", "o1", "gpt");
  agent(s, "R2", "o2", "gpt");
  agent(s, "R3", "o3", "qwen");
  agent(s, "X", "ox", "deepseek");
  return s;
}

// --- commitments ---------------------------------------------------------------

test("plantCommitment is sha256hex(submissionId + ':' + salt)", () => {
  assert.equal(plantCommitment("s1", "abc"), "3fcf52628d3d4de73357997f026b73f0b8b6d8a4d9b753270e696650dd6aeb9a");
  const expected = createHash("sha256").update("sub-42:deadbeef").digest("hex");
  assert.equal(plantCommitment("sub-42", "deadbeef"), expected);
  assert.match(plantCommitment("", ""), /^[0-9a-f]{64}$/);
  assert.notEqual(plantCommitment("s1", "abc"), plantCommitment("s1", "abd"));
});

test("plantCommitmentMatches accepts only the committed (id, salt) made before the plant", () => {
  const s = world();
  s.plantCommitments.push({ commitment: plantCommitment("s1", "salt"), seq: 5 });
  assert.equal(plantCommitmentMatches(s, "s1", "salt"), true);
  assert.equal(plantCommitmentMatches(s, "s1", "salt", 10), true);
  assert.equal(plantCommitmentMatches(s, "s1", "other"), false, "wrong salt");
  assert.equal(plantCommitmentMatches(s, "s2", "salt"), false, "commitment does not transfer to another submission");
  // Backdating: a commitment recorded after the plant was submitted proves nothing.
  assert.equal(plantCommitmentMatches(s, "s1", "salt", 5), false);
  assert.equal(plantCommitmentMatches(s, "s1", "salt", 3), false);
});

test("a reveal string that differs only by separator placement does not match", () => {
  const s = world();
  s.plantCommitments.push({ commitment: plantCommitment("s1", "x"), seq: 1 });
  assert.equal(plantCommitmentMatches(s, "s1:", "x"), false);
  assert.equal(plantCommitmentMatches(s, "s", "1:x"), false);
});

// --- time -------------------------------------------------------------------

test("timestamps need an explicit zone (determinism across host time zones)", () => {
  assert.equal(instantMs("2026-10-01T00:00:00Z"), Date.UTC(2026, 9, 1));
  assert.equal(instantMs("2026-10-01T02:00:00+02:00"), Date.UTC(2026, 9, 1));
  assert.equal(instantMs("2026-10-01T00:00:00.123Z"), Date.UTC(2026, 9, 1) + 123);
  assert.equal(instantMs("2026-10-01T00:00Z"), Date.UTC(2026, 9, 1));
  for (const bad of ["2026-10-01T00:00:00", "2026-10-01", "2026-10-01T00:00:00+0200", "garbage", "", "2026-13-40T00:00:00Z"]) {
    assert.ok(Number.isNaN(instantMs(bad)), bad);
  }
  assert.throws(() => atOrAfter("2026-10-01T00:00:00Z", "2026-10-01T00:00:00"), RangeError);
  assert.equal(atOrAfter("2026-10-01T00:00:00", "2026-01-01T00:00:00Z"), false, "offset-less entries drop out");
});

test("revealedPlants: offset-less timestamps drop out; offset-less sinceIso throws", () => {
  const s = world();
  submission(s, "local", "A", { planted: "high", at: "2026-10-05T00:00:00" });
  submission(s, "utc", "A", { planted: "high", at: "2026-10-05T00:00:00Z" });
  assert.deepEqual(
    revealedPlants(s, "2026-10-01T00:00:00Z").map((p) => p.id),
    ["utc"],
  );
  assert.throws(() => revealedPlants(s, "2026-10-01T00:00:00"), RangeError);
  assert.throws(() => revealedPlants(emptyState(), "garbage"), RangeError, "validated even with nothing to compare");
});

// --- review window ----------------------------------------------------------

test("reviewWindowClosed requires every assigned reviewer to have revealed, or a merge", () => {
  const s = world();
  const x = submission(s, "s1", "A");
  assert.equal(reviewWindowClosed(s, "s1"), false, "no assignment yet");
  x.assignment = { beacon: "b", reviewers: ["R1", "R2"], seq: next(s) };
  assert.equal(reviewWindowClosed(s, "s1"), false);
  review(s, "s1", "R1", 0.2);
  commit(s, "s1", "R2");
  assert.equal(reviewWindowClosed(s, "s1"), false, "a commit without a reveal keeps the window open");
  review(s, "s1", "R3", 0.9); // open reviewer, not assigned
  assert.equal(reviewWindowClosed(s, "s1"), false, "an unassigned reveal does not close it");
  reveal(s, "s1", "R2", 0.1);
  assert.equal(reviewWindowClosed(s, "s1"), true);
  assert.equal(reviewWindowCloseSeq(s, "s1"), x.reviews.find((r) => r.reviewer === "R2")?.revealedSeq);
  assert.equal(reviewWindowClosed(s, "missing"), false);

  submission(s, "s2", "A");
  merge(s, "s2");
  assert.equal(reviewWindowClosed(s, "s2"), true);
  assert.equal(reviewWindowCloseSeq(s, "s2"), sub(s, "s2").merged?.seq);
});

test("reviewWindowClosed: an empty assignment closes nothing (regression)", () => {
  const s = world();
  submission(s, "s1", "A", { assigned: [] });
  assert.equal(reviewWindowClosed(s, "s1"), false);
  review(s, "s1", "X", 0.9);
  assert.equal(reviewWindowClosed(s, "s1"), false);
  merge(s, "s1");
  assert.equal(reviewWindowClosed(s, "s1"), true);
});

test("reviewWindowClosed: a reproduced finding closes the window even if an assigned reviewer stalls", () => {
  const s = world();
  submission(s, "s1", "A", { assigned: ["R1", "R2"] });
  review(s, "s1", "R1", 0.1);
  commit(s, "s1", "R2"); // never reveals; the submission cannot merge either
  finding(s, "f0", "R3", { submissionId: "s1" }, false);
  assert.equal(reviewWindowClosed(s, "s1"), false, "an unreproduced finding closes nothing");
  finding(s, "f1", "R3", { submissionId: "s1" });
  assert.equal(reviewWindowClosed(s, "s1"), false, "not until the harness says so");
  result(s, "f1", true);
  assert.equal(reviewWindowCloseSeq(s, "s1"), s.findings.get("f1")?.result?.seq);
});

test("reviewWindowCloseSeq: the earliest closing event wins", () => {
  const s = world();
  submission(s, "s1", "A", { assigned: ["R1"] });
  commit(s, "s1", "R1");
  merge(s, "s1");
  reveal(s, "s1", "R1", 0.1); // after the merge
  assert.equal(reviewWindowCloseSeq(s, "s1"), sub(s, "s1").merged?.seq);
});

test("reviewWindowCloseSeq: a verdict with no revealedSeq cannot close the window", () => {
  const s = world();
  const x = submission(s, "s1", "A", { assigned: ["R1"] });
  x.reviews.push({
    reviewer: "R1",
    commitment: "c",
    stake: 1,
    committedSeq: next(s),
    verdict: { defectProbability: 0.9, summary: "", findingIds: [] },
  });
  assert.equal(reviewWindowClosed(s, "s1"), false);
  assert.equal(plantCaught(s, "s1"), false);
});

// --- caught -----------------------------------------------------------------

test("plantCaught: an assigned reveal at >= 0.5 catches; below does not", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high", assigned: ["R1", "R2"] });
  review(s, "s1", "R1", 0.49);
  review(s, "s1", "R2", CATCH_THRESHOLD);
  assert.equal(plantCaught(s, "s1"), true);
  assert.equal(plantCaughtBy(s, "s1", "R2"), true);
  assert.equal(plantCaughtBy(s, "s1", "R1"), false);

  submission(s, "s2", "A", { planted: "high", assigned: ["R1", "R2"] });
  review(s, "s2", "R1", 0.49);
  review(s, "s2", "R2", 0.1);
  assert.equal(plantCaught(s, "s2"), false);
});

test("plantCaught: an unrevealed commit never catches", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high", assigned: ["R1"] });
  commit(s, "s1", "R1");
  merge(s, "s1");
  assert.equal(plantCaught(s, "s1"), false);
});

test("plantCaught: an open reviewer's flag is a track record, not a system catch (gaming)", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high", assigned: ["R1"] });
  review(s, "s1", "X", 1); // open reviewer who flags everything
  review(s, "s1", "R1", 0.1);
  assert.equal(plantCaught(s, "s1"), false);
  assert.equal(plantCaughtBy(s, "s1", "X"), true);
  // An open reviewer's reproduced finding does count: the harness, not the reviewer, decides it.
  submission(s, "s2", "A", { planted: "high", assigned: ["R1"] });
  finding(s, "f", "X", { submissionId: "s2" }, true);
  assert.equal(plantCaught(s, "s2"), true);
});

test("plantCaught: only a reproduced finding on the submission catches", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high", assigned: ["R1"] });
  finding(s, "f0", "R1", { submissionId: "s1" }); // no result yet
  finding(s, "f1", "R1", { submissionId: "s1" }, false);
  finding(s, "f2", "R2", { snapshotId: "snap" }, true);
  submission(s, "other", "A");
  finding(s, "f3", "R2", { submissionId: "other" }, true);
  review(s, "s1", "R1", 0.1); // closes the window
  assert.equal(plantCaught(s, "s1"), false);

  submission(s, "s2", "A", { planted: "high", assigned: ["R1"] });
  finding(s, "f4", "R3", { submissionId: "s2" }, true);
  assert.equal(plantCaught(s, "s2"), true);
  assert.equal(plantCaughtBy(s, "s2", "R3"), true);
  assert.equal(plantCaughtBy(s, "s2", "R1"), false);
});

test("plantCaught: catches after the review window closed do not count (post-reveal regression)", () => {
  // The custodian reveals once the window closed; anything filed or revealed
  // after that point can be written from the published description.
  const s = world();
  submission(s, "s1", "A", { planted: "critical", assigned: ["R1"] });
  commit(s, "s1", "X"); // open reviewer commits p = 1 early ...
  review(s, "s1", "R1", 0.1); // window closes here; the plant may now be revealed
  finding(s, "late", "R3", { submissionId: "s1" }, true); // ... a finding built from the description
  reveal(s, "s1", "X", 1); // ... and a reveal made only because it was a plant
  assert.equal(plantCaught(s, "s1"), false);
  assert.equal(plantCaughtBy(s, "s1", "R3"), false);
  assert.equal(plantCaughtBy(s, "s1", "X"), false);
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.equal(st.caught, 0);
  assert.equal(st.byReviewer.has("R3"), false, "a post-window finding is not a sighting either");
  assert.deepEqual(st.byReviewer.get("X"), { seen: 1, caught: 0 }, "committed in time, revealed too late: a miss");
});

test("plantCaught: a finding filed in the window counts even if the harness answers later", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high", assigned: ["R1"] });
  finding(s, "f", "R3", { submissionId: "s1" });
  review(s, "s1", "R1", 0.1); // window closes
  result(s, "f", true); // reproduced after the close
  assert.equal(plantCaught(s, "s1"), true);
  assert.equal(plantCaughtBy(s, "s1", "R3"), true);
});

test("plantCaught: a plant revealed while its window is open counts as missed", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high", assigned: ["R1", "R2"] });
  review(s, "s1", "R1", 0.9);
  commit(s, "s1", "R2"); // never reveals; window open, plant already revealed
  assert.equal(plantCaught(s, "s1"), false);
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.equal(st.seeds, 1);
  assert.equal(st.caught, 0);
  assert.equal(st.byReviewer.size, 0, "no sighting can be ordered before an early reveal");
});

test("plantCaught: the author's owner cannot catch their own plant (gaming)", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "critical", assigned: ["A2"] });
  finding(s, "f1", "A", { submissionId: "s1" }, true);
  finding(s, "f2", "A2", { submissionId: "s1" }, true);
  review(s, "s1", "A2", 1);
  assert.equal(plantCaught(s, "s1"), false);
  assert.equal(plantCaughtBy(s, "s1", "A"), false);
  assert.equal(plantCaughtBy(s, "s1", "A2"), false);
});

test("plantCaught: NaN probability and unknown submission are not catches", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "low", assigned: ["R1"] });
  review(s, "s1", "R1", Number.NaN);
  assert.equal(plantCaught(s, "s1"), false);
  assert.equal(plantCaught(s, "nope"), false);
  assert.equal(plantCaughtBy(s, "nope", "R1"), false);
});

test("plantCaught applies to any submission, planted or not", () => {
  const s = world();
  submission(s, "s1", "A", { assigned: ["R1"] });
  review(s, "s1", "R1", 0.8);
  assert.equal(plantCaught(s, "s1"), true);
});

// --- stats ------------------------------------------------------------------

test("revealedPlants: only revealed plants inside the window", () => {
  const s = world();
  submission(s, "old", "A", { planted: "high", at: "2026-09-01T00:00:00Z" });
  submission(s, "edge", "A", { planted: "high", at: "2026-10-01T00:00:00Z" });
  submission(s, "new", "A", { planted: "low", at: "2026-10-05T00:00:00Z" });
  submission(s, "real", "A", { at: "2026-10-05T00:00:00Z" });
  submission(s, "badtime", "A", { planted: "low", at: "not a date" });
  assert.deepEqual(
    revealedPlants(s, "2026-10-01T00:00:00Z").map((p) => p.id),
    ["edge", "new"],
  );
  // Different ISO spellings of the same instant compare as equal.
  assert.deepEqual(
    revealedPlants(s, "2026-10-01T02:00:00+02:00").map((p) => p.id),
    ["edge", "new"],
  );
  assert.throws(() => revealedPlants(s, "garbage"), RangeError);
});

test("plantStats: totals, per reviewer and per family", () => {
  const s = world();
  submission(s, "p1", "A", { planted: "high", assigned: ["R1", "R2"] });
  commit(s, "p1", "R1");
  commit(s, "p1", "R2");
  commit(s, "p1", "R3"); // open reviewer
  reveal(s, "p1", "R1", 0.9); // gpt catches
  reveal(s, "p1", "R3", 0.2); // qwen misses
  reveal(s, "p1", "R2", 0.1); // gpt misses, family already caught; closes the window

  submission(s, "p2", "A", { planted: "medium", assigned: ["R1", "R3"] });
  finding(s, "f", "R2", { submissionId: "p2" }, true); // R2 caught via finding without reviewing; closes p2
  commit(s, "p2", "R1"); // committed after the close: not a sighting
  assert.equal(reviewWindowClosed(s, "p2"), true);

  submission(s, "p3", "A", { planted: "low", assigned: ["R1"] });
  review(s, "p3", "A2", 0.9); // author's owner: neither seen nor caught
  review(s, "p3", "R1", 0.3);

  submission(s, "real", "A", { assigned: ["R1"] });
  review(s, "real", "R1", 0.9); // not a plant: only in flagsOnOtherWork

  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.equal(st.seeds, 3);
  assert.equal(st.caught, 2);
  assert.deepEqual(st.byReviewer.get("R1"), { seen: 2, caught: 1 });
  assert.deepEqual(st.byReviewer.get("R2"), { seen: 2, caught: 1 });
  assert.deepEqual(st.byReviewer.get("R3"), { seen: 1, caught: 0 });
  assert.equal(st.byReviewer.has("A2"), false);
  assert.equal(st.byReviewer.has("A"), false);
  // gpt: p1 (R1 caught), p2 (R2 caught), p3 (R1 missed) — each plant once.
  assert.deepEqual(st.byFamily.get("gpt"), { seen: 3, caught: 2 });
  assert.deepEqual(st.byFamily.get("qwen"), { seen: 1, caught: 0 });
  assert.equal(st.byFamily.has("kimi"), false);
  assert.equal(st.byFamily.has("claude"), false);
  assert.deepEqual(st.flagsOnOtherWork.get("R1"), { reviewed: 1, flagged: 1 });
});

test("plantStats: flagsOnOtherWork exposes an indiscriminate flagger", () => {
  const s = world();
  for (let i = 0; i < 4; i++) {
    submission(s, `p${i}`, "A", { planted: "high", assigned: ["R1"] });
    review(s, `p${i}`, "R1", 1);
    submission(s, `r${i}`, "A", { assigned: ["R1"] });
    review(s, `r${i}`, "R1", 1);
    review(s, `r${i}`, "A2", 0); // author's owner is ignored
  }
  submission(s, "late", "A", { assigned: ["R1"] });
  review(s, "late", "R1", 0.1); // closes
  review(s, "late", "R2", 1); // revealed after the close: not counted
  submission(s, "open", "A", { assigned: ["R3"] });
  review(s, "open", "R1", 1); // window never closed: not counted
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.deepEqual(st.byReviewer.get("R1"), { seen: 4, caught: 4 });
  assert.deepEqual(st.flagsOnOtherWork.get("R1"), { reviewed: 5, flagged: 4 });
  assert.equal(st.flagsOnOtherWork.has("R2"), false);
  assert.equal(st.flagsOnOtherWork.has("A2"), false);
});

test("plantStats: unknown agents go to the unknown family; empty window is zero", () => {
  const s = world();
  submission(s, "p1", "A", { planted: "high", assigned: ["ghost"] });
  review(s, "p1", "ghost", 0.7);
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.deepEqual(st.byFamily.get(UNKNOWN_FAMILY), { seen: 1, caught: 1 });
  const empty = plantStats(s, "2027-01-01T00:00:00Z");
  assert.equal(empty.seeds, 0);
  assert.equal(empty.caught, 0);
  assert.equal(empty.byReviewer.size, 0);
  assert.equal(empty.byFamily.size, 0);
  assert.equal(empty.flagsOnOtherWork.size, 0);
});

test("plantStats: duplicate reviews/findings by one agent count one sighting", () => {
  const s = world();
  submission(s, "p1", "A", { planted: "high", assigned: ["R1"] });
  finding(s, "f1", "R1", { submissionId: "p1" }, false);
  finding(s, "f2", "R1", { submissionId: "p1" }, true);
  review(s, "p1", "R1", 0.1);
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.deepEqual(st.byReviewer.get("R1"), { seen: 1, caught: 1 });
});

test("plantStats: a sybil reviewing 60 plants after the window gets nothing (critical regression)", () => {
  const s = world();
  for (let i = 0; i < 60; i++) {
    submission(s, `p${i}`, "A", { planted: "critical", assigned: ["R1"] });
    commit(s, `p${i}`, "X");
    review(s, `p${i}`, "R1", 0.1); // window closes; plant revealed
  }
  for (let i = 0; i < 60; i++) {
    reveal(s, `p${i}`, "X", 1);
    finding(s, `f${i}`, "X", { submissionId: `p${i}` }, true);
  }
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.equal(st.seeds, 60);
  assert.equal(st.caught, 0);
  assert.deepEqual(st.byReviewer.get("X"), { seen: 60, caught: 0 });
  assert.deepEqual(st.byReviewer.get("R1"), { seen: 60, caught: 0 });
});
