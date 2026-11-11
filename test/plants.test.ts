import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import {
  CATCH_THRESHOLD,
  plantCaught,
  plantCaughtBy,
  plantCommitment,
  plantCommitmentMatches,
  plantStats,
  revealedPlants,
  reviewWindowClosed,
  UNKNOWN_FAMILY,
} from "../src/plants";
import type { CommonsState, Rules, Severity, SubmissionState } from "../src/types";

// --- hand-built state (no ledger.ts) ----------------------------------------

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
    length: 0,
  };
}

function agent(s: CommonsState, keyId: string, owner: string, modelFamily: string): void {
  s.agents.set(keyId, { keyId, owner, modelFamily, harness: "h", active: true });
}

function submission(
  s: CommonsState,
  id: string,
  author: string,
  opts: { at?: string; planted?: Severity; seq?: number } = {},
): SubmissionState {
  const sub: SubmissionState = {
    id,
    author,
    taskId: null,
    baseCommit: "b",
    headCommit: "h",
    changedFiles: [],
    linesChanged: 1,
    submittedSeq: opts.seq ?? 10,
    submittedAt: opts.at ?? "2026-10-01T00:00:00Z",
    gates: [],
    reviews: [],
    findingIds: [],
  };
  if (opts.planted) sub.planted = { severity: opts.planted, description: "planted bug" };
  s.submissions.set(id, sub);
  return sub;
}

// p undefined = committed but never revealed
function review(s: CommonsState, submissionId: string, reviewer: string, p?: number): void {
  const sub = s.submissions.get(submissionId);
  assert.ok(sub);
  sub.reviews.push({
    reviewer,
    commitment: "c",
    stake: 1,
    committedSeq: 20,
    ...(p === undefined ? {} : { verdict: { defectProbability: p, summary: "", findingIds: [] }, revealedSeq: 21 }),
  });
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
    seq: 30,
    at: "2026-10-02T00:00:00Z",
    ...(reproduced === undefined
      ? {}
      : { result: { reproduced, failsOnHead: reproduced, passesOnParent: true, logDigest: "d", seq: 31 } }),
  });
  if ("submissionId" in target) s.submissions.get(target.submissionId)?.findingIds.push(id);
}

// author A (owner oa, claude); reviewers R1 (o1, gpt), R2 (o2, gpt), R3 (o3, qwen);
// A2 is a second agent of the author's owner.
function world(): CommonsState {
  const s = emptyState();
  agent(s, "A", "oa", "claude");
  agent(s, "A2", "oa", "kimi");
  agent(s, "R1", "o1", "gpt");
  agent(s, "R2", "o2", "gpt");
  agent(s, "R3", "o3", "qwen");
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

// --- review window ----------------------------------------------------------

test("reviewWindowClosed requires every assigned reviewer to have revealed, or a merge", () => {
  const s = world();
  const sub = submission(s, "s1", "A");
  assert.equal(reviewWindowClosed(s, "s1"), false, "no assignment yet");
  sub.assignment = { beacon: "b", reviewers: ["R1", "R2"], seq: 11 };
  assert.equal(reviewWindowClosed(s, "s1"), false);
  review(s, "s1", "R1", 0.2);
  review(s, "s1", "R2"); // committed only
  assert.equal(reviewWindowClosed(s, "s1"), false, "a commit without a reveal keeps the window open");
  review(s, "s1", "R3", 0.9); // open reviewer, not assigned
  assert.equal(reviewWindowClosed(s, "s1"), false, "an unassigned reveal does not close it");
  const r2 = sub.reviews.find((r) => r.reviewer === "R2");
  assert.ok(r2);
  r2.verdict = { defectProbability: 0.1, summary: "", findingIds: [] };
  assert.equal(reviewWindowClosed(s, "s1"), true);
  assert.equal(reviewWindowClosed(s, "missing"), false);

  const merged = submission(s, "s2", "A");
  merged.merged = { commit: "m", seq: 40, at: "2026-10-03T00:00:00Z" };
  assert.equal(reviewWindowClosed(s, "s2"), true);
});

// --- caught -----------------------------------------------------------------

test("plantCaught: a revealed review at >= 0.5 catches; below does not", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high" });
  review(s, "s1", "R1", 0.49);
  assert.equal(plantCaught(s, "s1"), false);
  review(s, "s1", "R2", CATCH_THRESHOLD);
  assert.equal(plantCaught(s, "s1"), true);
  assert.equal(plantCaughtBy(s, "s1", "R2"), true);
  assert.equal(plantCaughtBy(s, "s1", "R1"), false);
});

test("plantCaught: an unrevealed commit never catches", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high" });
  review(s, "s1", "R1");
  assert.equal(plantCaught(s, "s1"), false);
});

test("plantCaught: only a reproduced finding on the submission catches", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "high" });
  finding(s, "f0", "R1", { submissionId: "s1" }); // no result yet
  finding(s, "f1", "R1", { submissionId: "s1" }, false);
  finding(s, "f2", "R2", { snapshotId: "snap" }, true);
  finding(s, "f3", "R2", { submissionId: "other" }, true);
  assert.equal(plantCaught(s, "s1"), false);
  finding(s, "f4", "R3", { submissionId: "s1" }, true);
  assert.equal(plantCaught(s, "s1"), true);
  assert.equal(plantCaughtBy(s, "s1", "R3"), true);
  assert.equal(plantCaughtBy(s, "s1", "R1"), false);
});

test("plantCaught: the author's owner cannot catch their own plant (gaming)", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "critical" });
  finding(s, "f1", "A", { submissionId: "s1" }, true);
  finding(s, "f2", "A2", { submissionId: "s1" }, true);
  review(s, "s1", "A2", 1);
  assert.equal(plantCaught(s, "s1"), false);
  assert.equal(plantCaughtBy(s, "s1", "A"), false);
  assert.equal(plantCaughtBy(s, "s1", "A2"), false);
});

test("plantCaught: NaN probability and unknown submission are not catches", () => {
  const s = world();
  submission(s, "s1", "A", { planted: "low" });
  review(s, "s1", "R1", Number.NaN);
  assert.equal(plantCaught(s, "s1"), false);
  assert.equal(plantCaught(s, "nope"), false);
  assert.equal(plantCaughtBy(s, "nope", "R1"), false);
});

test("plantCaught applies to any submission, planted or not", () => {
  const s = world();
  submission(s, "s1", "A");
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
  submission(s, "p1", "A", { planted: "high" });
  review(s, "p1", "R1", 0.9); // gpt catches
  review(s, "p1", "R2", 0.1); // gpt misses, family already caught
  review(s, "p1", "R3", 0.2); // qwen misses

  submission(s, "p2", "A", { planted: "medium" });
  review(s, "p2", "R1", 0.1);
  review(s, "p2", "R3"); // never revealed: saw it and missed it
  finding(s, "f", "R2", { submissionId: "p2" }, true); // R2 caught via finding without reviewing

  submission(s, "p3", "A", { planted: "low" });
  review(s, "p3", "R1", 0.3);
  review(s, "p3", "A2", 0.9); // author's owner: neither seen nor caught

  submission(s, "real", "A");
  review(s, "real", "R1", 0.9); // not a plant: ignored

  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.equal(st.seeds, 3);
  assert.equal(st.caught, 2);
  assert.deepEqual(st.byReviewer.get("R1"), { seen: 3, caught: 1 });
  assert.deepEqual(st.byReviewer.get("R2"), { seen: 2, caught: 1 });
  assert.deepEqual(st.byReviewer.get("R3"), { seen: 2, caught: 0 });
  assert.equal(st.byReviewer.has("A2"), false);
  assert.equal(st.byReviewer.has("A"), false);
  // gpt: p1 (R1 caught), p2 (R2 caught), p3 (R1 missed) — each plant once.
  assert.deepEqual(st.byFamily.get("gpt"), { seen: 3, caught: 2 });
  assert.deepEqual(st.byFamily.get("qwen"), { seen: 2, caught: 0 });
  assert.equal(st.byFamily.has("kimi"), false);
  assert.equal(st.byFamily.has("claude"), false);
});

test("plantStats: unknown agents go to the unknown family; empty window is zero", () => {
  const s = world();
  submission(s, "p1", "A", { planted: "high" });
  review(s, "p1", "ghost", 0.7);
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.deepEqual(st.byFamily.get(UNKNOWN_FAMILY), { seen: 1, caught: 1 });
  const empty = plantStats(s, "2027-01-01T00:00:00Z");
  assert.equal(empty.seeds, 0);
  assert.equal(empty.caught, 0);
  assert.equal(empty.byReviewer.size, 0);
  assert.equal(empty.byFamily.size, 0);
});

test("plantStats: duplicate reviews/findings by one agent count one sighting", () => {
  const s = world();
  submission(s, "p1", "A", { planted: "high" });
  review(s, "p1", "R1", 0.1);
  finding(s, "f1", "R1", { submissionId: "p1" }, false);
  finding(s, "f2", "R1", { submissionId: "p1" }, true);
  const st = plantStats(s, "2026-01-01T00:00:00Z");
  assert.deepEqual(st.byReviewer.get("R1"), { seen: 1, caught: 1 });
});
