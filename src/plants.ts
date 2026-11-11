// Planted bugs: the seeded-recall measurement. A custodian commits to a plant
// (plantCommit), submits it like any other change, and reveals it (plantReveal)
// only after its review window closed, so reviewers cannot tell plants from real
// work. This module holds the shared definition of "a plant was caught" so that
// risk, promotion, metrics and incentives all count the same thing.
//
// Timing is the whole point. Once a plant's description is public, anyone can
// "catch" it: file a finding written from the description, or reveal a review
// they committed earlier only because it turned out to be a plant. So every
// catch here is cut off at the seq where the review window closed
// (reviewWindowCloseSeq). That is sound only while plantReveal happens after
// the window closed. ARCHITECTURE.md requires it, but ledger.ts does not
// enforce it yet, and SubmissionState.planted does not record the reveal seq.
// A plant revealed early whose window closes later leaks the catches in
// between.

import { createHash } from "node:crypto";

import type { CommonsState, KeyId, ModelFamily, SubmissionState } from "./types";

// A revealed review at or above this probability counts as flagging the change.
export const CATCH_THRESHOLD = 0.5;

// sha256hex(submissionId + ":" + salt), the plantCommit contract in types.ts.
export function plantCommitment(submissionId: string, salt: string): string {
  return createHash("sha256").update(`${submissionId}:${salt}`, "utf8").digest("hex");
}

// True if (submissionId, salt) opens one of the recorded plant commitments
// made before `beforeSeq` (default: anywhere in the ledger). A commitment made
// after the plant was submitted proves nothing, so callers validating a reveal
// pass the submission's submittedSeq.
export function plantCommitmentMatches(
  state: CommonsState,
  submissionId: string,
  salt: string,
  beforeSeq: number = Number.POSITIVE_INFINITY,
): boolean {
  const c = plantCommitment(submissionId, salt);
  return state.plantCommitments.some((p) => p.commitment === c && p.seq < beforeSeq);
}

// ---------------------------------------------------------------------------
// Time windows (shared with risk.ts)
// ---------------------------------------------------------------------------

// Only ISO date-times with an explicit zone. Date.parse reads an offset-less
// date-time in the host's local zone, so the same ledger would give different
// windows on different machines.
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:\d{2})$/;

// Milliseconds since the epoch, or NaN if `iso` is not an instant with a zone.
export function instantMs(iso: string): number {
  return ISO_INSTANT.test(iso) ? Date.parse(iso) : Number.NaN;
}

// Start of a window in milliseconds. A `sinceIso` without an explicit zone, or
// one that does not parse, throws RangeError.
export function windowStart(sinceIso: string): number {
  const since = instantMs(sinceIso);
  if (Number.isNaN(since)) throw new RangeError(`invalid sinceIso (need an ISO date-time with Z or ±HH:MM): ${sinceIso}`);
  return since;
}

// True if `iso` is at or after `sinceIso`. A bad `iso` returns false, so that
// entry drops out of every window.
export function atOrAfter(iso: string, sinceIso: string): boolean {
  return instantMs(iso) >= windowStart(sinceIso);
}

// ---------------------------------------------------------------------------
// Review window
// ---------------------------------------------------------------------------

function findingsOn(state: CommonsState, s: SubmissionState) {
  return [...state.findings.values()].filter((f) => "submissionId" in f.target && f.target.submissionId === s.id);
}

// The seq of the entry that closed the submission's review window, or null
// while it is open. The window closes at the first of:
// - the merge;
// - the reveal that completed the assigned reviewers' verdicts. This needs at
//   least one assigned reviewer: an empty assignment closes nothing;
// - the result of the first reproduced finding. The submission can no longer
//   merge, and the ledger stops taking review commits then.
// An assigned reviewer who never reveals does not hold the window open for
// ever. The coordinator merges once its review window has passed, and the merge
// closes it.
export function reviewWindowCloseSeq(state: CommonsState, submissionId: string): number | null {
  const s = state.submissions.get(submissionId);
  if (!s) return null;
  let close = Number.POSITIVE_INFINITY;
  if (s.merged) close = s.merged.seq;
  const assigned = s.assignment?.reviewers ?? [];
  if (assigned.length > 0) {
    let last = Number.NEGATIVE_INFINITY;
    for (const r of assigned) {
      // A verdict without a revealedSeq has no position on the ledger, so it cannot close anything.
      const seq = s.reviews.find((v) => v.reviewer === r && v.verdict !== undefined)?.revealedSeq;
      last = Math.max(last, seq ?? Number.POSITIVE_INFINITY);
    }
    close = Math.min(close, last);
  }
  for (const f of findingsOn(state, s)) {
    if (f.result?.reproduced === true) close = Math.min(close, f.result.seq);
  }
  return close === Number.POSITIVE_INFINITY ? null : close;
}

// Revealing a plant before this is true would tell the remaining reviewers what to look for.
export function reviewWindowClosed(state: CommonsState, submissionId: string): boolean {
  return reviewWindowCloseSeq(state, submissionId) !== null;
}

// ---------------------------------------------------------------------------
// Catches
// ---------------------------------------------------------------------------

// Findings and reviews by the submission's own author (or another agent of the
// same owner) never count as catches: the plant's author is the custodian, who
// knows where the bug is.
function sameOwnerAsAuthor(state: CommonsState, s: SubmissionState, agent: KeyId): boolean {
  if (agent === s.author) return true;
  const authorOwner = state.agents.get(s.author)?.owner;
  return authorOwner !== undefined && state.agents.get(agent)?.owner === authorOwner;
}

// Finders whose reproduced finding was filed by `cutoff`. The harness result
// may come later: the test was fixed when the finding was filed.
function reproducedFindersOn(state: CommonsState, s: SubmissionState, cutoff: number): Set<KeyId> {
  const finders = new Set<KeyId>();
  for (const f of findingsOn(state, s)) {
    if (f.result?.reproduced !== true || !(f.seq <= cutoff)) continue;
    if (sameOwnerAsAuthor(state, s, f.finder)) continue;
    finders.add(f.finder);
  }
  return finders;
}

// Reviewers who revealed p >= CATCH_THRESHOLD by `cutoff`. The reveal time
// matters as well as the commit time. Someone who commits p = 1 everywhere and
// reveals only where a plant was announced would otherwise catch every plant.
function flaggers(state: CommonsState, s: SubmissionState, cutoff: number): Set<KeyId> {
  const out = new Set<KeyId>();
  for (const r of s.reviews) {
    if (r.verdict === undefined || !(r.verdict.defectProbability >= CATCH_THRESHOLD)) continue;
    if (r.revealedSeq === undefined || !(r.revealedSeq <= cutoff)) continue;
    if (sameOwnerAsAuthor(state, s, r.reviewer)) continue;
    out.add(r.reviewer);
  }
  return out;
}

// System-level catch, the one seeded recall counts. Within the review window,
// either someone outside the author's owner filed a finding that reproduced, or
// an *assigned* reviewer revealed p >= 0.5. Open reviewers choose what they
// review and pay only stake and Brier score for a flag. If their flags counted,
// one agent flagging every submission would make recall 100%. Assigned seats
// are drawn by beacon, so nobody can steer towards the plants. An
// indiscriminate assigned reviewer still inflates recall on the plants they
// are drawn for. plantStats.flagsOnOtherWork exposes that.
// An open window gives false. For a revealed plant that means it was revealed
// early, and no catch on it can be ordered before the reveal.
export function plantCaught(state: CommonsState, submissionId: string): boolean {
  const s = state.submissions.get(submissionId);
  const cutoff = reviewWindowCloseSeq(state, submissionId);
  if (!s || cutoff === null) return false;
  const assigned = new Set(s.assignment?.reviewers ?? []);
  for (const r of flaggers(state, s, cutoff)) if (assigned.has(r)) return true;
  return reproducedFindersOn(state, s, cutoff).size > 0;
}

// Per-reviewer statistic: this agent's own flag (assigned or open) or
// reproduced finding, within the review window. It is a track record, not
// evidence that the system stopped the plant.
export function plantCaughtBy(state: CommonsState, submissionId: string, reviewer: KeyId): boolean {
  const s = state.submissions.get(submissionId);
  const cutoff = reviewWindowCloseSeq(state, submissionId);
  if (!s || cutoff === null) return false;
  return flaggers(state, s, cutoff).has(reviewer) || reproducedFindersOn(state, s, cutoff).has(reviewer);
}

// Agents that looked at a submission within its review window. That means a
// committed review (revealed or not: a reviewer who never reveals still saw the
// plant and still missed it) or a filed finding. The author's own owner is
// excluded.
function sawSubmission(state: CommonsState, s: SubmissionState, cutoff: number): Set<KeyId> {
  const out = new Set<KeyId>();
  for (const r of s.reviews) {
    if (r.committedSeq <= cutoff && !sameOwnerAsAuthor(state, s, r.reviewer)) out.add(r.reviewer);
  }
  for (const f of findingsOn(state, s)) {
    if (f.seq <= cutoff && !sameOwnerAsAuthor(state, s, f.finder)) out.add(f.finder);
  }
  return out;
}

// Plants revealed so far whose submission falls in the window. Unrevealed
// plants are indistinguishable from real work and are never counted. A plant
// revealed while its window is still open is included, and plantCaught counts
// it as missed. It cannot inflate recall.
export function revealedPlants(state: CommonsState, sinceIso: string): SubmissionState[] {
  windowStart(sinceIso); // validate even when there is nothing to compare
  const out: SubmissionState[] = [];
  for (const s of state.submissions.values()) {
    if (s.planted !== undefined && atOrAfter(s.submittedAt, sinceIso)) out.push(s);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

export type PlantTally = { seen: number; caught: number };

export type PlantStats = {
  seeds: number;
  caught: number; // system-level, as plantCaught
  // Per reviewer: plants seen in the window and caught by that reviewer (plantCaughtBy).
  byReviewer: Map<KeyId, PlantTally>;
  // A family saw a plant if any of its agents saw it, and caught it if any of
  // those agents caught it; each plant counts once per family.
  byFamily: Map<ModelFamily, PlantTally>;
  // Per reviewer, over the other submissions in the window: reviews revealed
  // within the review window, and how many of them flagged the change. Most
  // real work is clean. A catch rate on plants no higher than this flag rate
  // means the reviewer is not telling plants apart. ("Other" includes plants
  // not yet revealed.)
  flagsOnOtherWork: Map<KeyId, { reviewed: number; flagged: number }>;
};

// Agents missing from state.agents are grouped under this family.
export const UNKNOWN_FAMILY = "unknown";

function bump(m: Map<string, PlantTally>, key: string, caught: boolean): void {
  const t = m.get(key) ?? { seen: 0, caught: 0 };
  t.seen += 1;
  if (caught) t.caught += 1;
  m.set(key, t);
}

export function plantStats(state: CommonsState, sinceIso: string): PlantStats {
  const stats: PlantStats = {
    seeds: 0,
    caught: 0,
    byReviewer: new Map(),
    byFamily: new Map(),
    flagsOnOtherWork: new Map(),
  };
  for (const s of revealedPlants(state, sinceIso)) {
    stats.seeds += 1;
    if (plantCaught(state, s.id)) stats.caught += 1;
    // Revealed early: nobody's sighting can be ordered before the reveal, so it
    // stays out of the per-agent records. It still counts as a missed seed above.
    const cutoff = reviewWindowCloseSeq(state, s.id);
    if (cutoff === null) continue;
    const familyCaught = new Map<ModelFamily, boolean>();
    for (const agent of sawSubmission(state, s, cutoff)) {
      const caught = plantCaughtBy(state, s.id, agent);
      bump(stats.byReviewer, agent, caught);
      const family = state.agents.get(agent)?.modelFamily ?? UNKNOWN_FAMILY;
      familyCaught.set(family, (familyCaught.get(family) ?? false) || caught);
    }
    for (const [family, caught] of familyCaught) bump(stats.byFamily, family, caught);
  }
  for (const s of state.submissions.values()) {
    if (s.planted !== undefined || !atOrAfter(s.submittedAt, sinceIso)) continue;
    const cutoff = reviewWindowCloseSeq(state, s.id);
    if (cutoff === null) continue;
    for (const r of s.reviews) {
      if (r.verdict === undefined || r.revealedSeq === undefined || r.revealedSeq > cutoff) continue;
      if (sameOwnerAsAuthor(state, s, r.reviewer)) continue;
      const t = stats.flagsOnOtherWork.get(r.reviewer) ?? { reviewed: 0, flagged: 0 };
      t.reviewed += 1;
      if (r.verdict.defectProbability >= CATCH_THRESHOLD) t.flagged += 1;
      stats.flagsOnOtherWork.set(r.reviewer, t);
    }
  }
  return stats;
}
