// Review verdicts and reviewer track records.
//
// A review is a probability that the change holds a defect of severity >=
// medium, committed blind (commitmentFor) and revealed later. Reviewers are
// scored with the Brier score against what later became known about the
// change: a confirmed finding (findingStatus.ts) or a revealed plant of severity >= medium says
// it was defective; shipping to main and surviving the vesting tail without
// such a defect says it was clean. Anything else is unknown and scores nothing.

import { canonical, sha256hex } from "./crypto";
import { isConfirmedDefect, isReproducedOpen } from "./findingStatus";
import { instantMs, plantStats, reviewWindowCloseSeq } from "./plants";
import type { CommonsState, FindingState, KeyId, ReviewVerdict, Severity, SnapshotState, SubmissionState } from "./types";

// What a review or attestation commits to: a submission or a snapshot.
export type CommitSubject = { submissionId: string } | { snapshotId: string };

// The ledger checks reveals against exactly this. It binds the reviewer and the
// subject as well as the verdict: commitments are public, so one that bound
// only the verdict could be posted again by another agent and, once the
// original was revealed, revealed as that agent's own review (a seat filled,
// a clean-review reward and a Brier score earned, with no review done).
export function commitmentFor(verdict: ReviewVerdict, salt: string, reviewer: KeyId, subject: CommitSubject): string {
  return sha256hex(canonical({ verdict, salt, reviewer, subject }));
}

// What falseFindingPenalty charges and the false-finding rate counts; defined
// with the other finding standings in findingStatus.ts.
export { isFalseFinding } from "./findingStatus";

// The reviewer-draw beacon of a reviewAssignment; the ledger recomputes it from
// the entry and refuses a mismatch, and selection.ts draws from it. It binds
// the draw to this exact change (submission id and declared head commit) and
// to entropy the coordinator does not choose: the public randomness round
// fixed by rule (docs/protocol.md §5.6). It deliberately leaves out anything
// the coordinator or admin can still change between the submission and the
// draw, since each such input is a choice of beacon:
// - the ledger head: the coordinator decides what it is, so a head-bound
//   beacon could be ground by reordering or padding its own entries;
// - the member tree's digest: an owner admitted after the submission changes
//   it, while it cannot change the draw (it has no agent in the pool, which
//   is fixed at the submission, and a new leaf moves no existing distance).
//   With the digest in the beacon, the admin could try owner ids offline
//   against a public round and admit the one that seats friendly reviewers,
//   and the coordinator could pick a beacon by drawing before or after a
//   pending admission. The entry still records the digest, and the ledger
//   checks it against the member tree before the entry.
export function assignmentBeacon(submissionId: string, headCommit: string, entropy: string): string {
  return sha256hex(canonical({ submission: submissionId, head: headCommit, entropy }));
}

const VERDICT_FIELDS = ["defectProbability", "summary", "findingIds"];

// Shape only, with the ledger's rules (a plain object, own fields only, no
// unknown fields). A verdict that passes can still be refused at reveal: the
// ledger also requires every findingId to name a finding on the reviewed
// submission. Empty list = valid.
export function validateVerdict(v: unknown): string[] {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return ["verdict is not an object"];
  const proto: unknown = Object.getPrototypeOf(v);
  if (proto !== Object.prototype && proto !== null) return ["verdict is not a plain object"];
  const o = v as Record<string, unknown>;
  const own = (k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);
  const problems: string[] = [];
  for (const key of Object.keys(o)) {
    if (!VERDICT_FIELDS.includes(key) && o[key] !== undefined) problems.push(`unknown field ${key}`);
  }
  const p = own("defectProbability");
  if (typeof p !== "number" || !Number.isFinite(p) || p < 0 || p > 1) {
    problems.push("defectProbability must be a number in [0, 1]");
  }
  if (typeof own("summary") !== "string") problems.push("summary must be a string");
  const ids = own("findingIds");
  if (!Array.isArray(ids) || !ids.every((x) => typeof x === "string")) {
    problems.push("findingIds must be an array of strings");
  } else {
    if (ids.some((x) => x === "")) problems.push("empty finding id");
    if (new Set(ids).size !== ids.length) problems.push("duplicate finding id");
  }
  return problems;
}

// Squared error; 0 is perfect, 0.25 is always saying 0.5, 1 is confidently wrong.
export function brier(probability: number, outcome: 0 | 1): number {
  if (!Number.isFinite(probability) || probability < 0 || probability > 1) {
    throw new RangeError(`brier: probability must be in [0, 1], got ${probability}`);
  }
  if (outcome !== 0 && outcome !== 1) throw new RangeError(`brier: outcome must be 0 or 1, got ${String(outcome)}`);
  return (probability - outcome) ** 2;
}

// The verdict predicts a defect of severity >= medium, so only such defects
// make the outcome 1. A reproduced low-severity finding neither confirms nor
// refutes the prediction; the submission then falls through to the shipped
// test like any other. Severity is the finder's (or custodian's) claim.
const COUNTS: Record<Severity, boolean> = { low: false, medium: true, high: true, critical: true };

const DAY_MS = 86_400_000;

// What submissionOutcome needs beyond the submission itself, built in one pass
// over snapshots and findings so that scoring every submission stays linear.
type OutcomeIndex = {
  shippedAt: Map<string, number>; // submissionId -> earliest ms it reached main
  unpinned: Set<string>; // submissionIds under a reproduced snapshot-level defect
};

function outcomeIndex(state: CommonsState): OutcomeIndex {
  // A promotion ships the promoted snapshot and every snapshot before it.
  // Walking promotions in time order, a walk can stop at the first snapshot
  // already marked: it and its ancestors shipped no later.
  const promotions: { snap: SnapshotState; at: number }[] = [];
  for (const snap of state.snapshots.values()) {
    const at = snap.promoted ? instantMs(snap.promoted.at) : Number.NaN;
    if (!Number.isNaN(at)) promotions.push({ snap, at });
  }
  promotions.sort((a, b) => a.at - b.at);
  const snapShipped = new Map<string, number>();
  for (const { snap, at } of promotions) {
    for (let cur: SnapshotState | undefined = snap; cur && !snapShipped.has(cur.id); ) {
      snapShipped.set(cur.id, at);
      cur = cur.previousSnapshotId === null ? undefined : state.snapshots.get(cur.previousSnapshotId);
    }
  }
  const shippedAt = new Map<string, number>();
  for (const [id, at] of snapShipped) {
    for (const sid of state.snapshots.get(id)?.submissionIds ?? []) {
      const prev = shippedAt.get(sid);
      if (prev === undefined || at < prev) shippedAt.set(sid, at);
    }
  }

  // A snapshot-level finding covers what the ledger says it covers: the
  // snapshot and its ancestors back to (not including) the first promoted one.
  // It cannot be pinned on one of those submissions, so all of them stay
  // unknown rather than clean. Every escape rests on a reproduced finding
  // (ledger.ts), so escapes need no separate pass: one on a finding against a
  // submission makes that submission 1, one on a snapshot finding lands here,
  // and low-severity escapes count no more than low-severity findings.
  const unpinned = new Set<string>();
  const walked = new Set<string>();
  for (const f of state.findings.values()) {
    // Undecided counts here too: until an operator dismisses it, it may be a defect.
    if (!("snapshotId" in f.target) || !isReproducedOpen(f) || !COUNTS[f.severity]) continue;
    for (let cur = state.snapshots.get(f.target.snapshotId); cur && !walked.has(cur.id); ) {
      walked.add(cur.id);
      for (const sid of cur.submissionIds) unpinned.add(sid);
      const prev = cur.previousSnapshotId === null ? undefined : state.snapshots.get(cur.previousSnapshotId);
      cur = prev?.promoted ? undefined : prev;
    }
  }
  return { shippedAt, unpinned };
}

function outcomeWith(state: CommonsState, index: OutcomeIndex, s: SubmissionState, now: number): 0 | 1 | null {
  if (s.planted && COUNTS[s.planted.severity]) return 1;
  for (const fid of s.findingIds) {
    const f = state.findings.get(fid);
    if (f !== undefined && isConfirmedDefect(f) && COUNTS[f.severity]) return 1;
  }
  const shipped = index.shippedAt.get(s.id);
  if (shipped === undefined || shipped + state.rules.vesting.tailDays * DAY_MS > now) return null;
  return index.unpinned.has(s.id) ? null : 0;
}

function parseNow(nowIso: string): number {
  const now = instantMs(nowIso);
  if (Number.isNaN(now)) throw new RangeError(`invalid nowIso (need an ISO date-time with Z or ±HH:MM): ${nowIso}`);
  return now;
}

// 1: a confirmed finding of severity >= medium targets the submission, or it
// is a revealed plant of severity >= medium.
// 0: it shipped (its snapshot, or a later one, was promoted) at least
// rules.vesting.tailDays before nowIso, and no reproduced snapshot-level
// finding (or escape) of severity >= medium covers a snapshot carrying it.
// null: anything else.
// Throws RangeError on a nowIso without an explicit zone.
export function submissionOutcome(state: CommonsState, submissionId: string, nowIso: string): 0 | 1 | null {
  const now = parseNow(nowIso);
  const s = state.submissions.get(submissionId);
  return s ? outcomeWith(state, outcomeIndex(state), s, now) : null;
}

export type ReviewerScore = {
  reviews: number; // revealed reviews, whenever revealed
  // Commits made while the review window was open, on a submission whose
  // window has closed and whose outcome is known. Each scores the Brier of its
  // reveal, or 1 if it was not revealed by the time the window closed.
  scored: number;
  meanBrier: number; // over scored; 0 when scored = 0
  plantsSeen: number;
  plantsCaught: number;
  // Commits not revealed by the time their window closed: never revealed, or
  // revealed late. Commits whose window is still open are not counted.
  unrevealed: number;
};

const ALL_TIME = "1970-01-01T00:00:00Z";

function blank(): ReviewerScore {
  return { reviews: 0, scored: 0, meanBrier: 0, plantsSeen: 0, plantsCaught: 0, unrevealed: 0 };
}

// Worst possible Brier score, charged for a commit not revealed in time.
const FORFEIT = 1;

// Per agent, over submission reviews (snapshot attestations are not scored
// here). Withholding a reveal must never pay: during the window a reviewer can
// watch findings being filed and other reveals arrive, and reveal only when
// their sealed verdict looks right. So a commit not revealed by the time the
// window closed is scored as if confidently wrong, and a late reveal never
// improves it.
// Plants follow plants.ts: seen = committed a review or filed a finding on a
// revealed plant within its window; caught = plantCaughtBy (p >= 0.5 revealed,
// or a reproduced finding, within the window). Agents who only filed findings
// on plants appear with reviews = 0.
export function reviewerScores(state: CommonsState, nowIso: string): Map<KeyId, ReviewerScore> {
  const now = parseNow(nowIso);
  const out = new Map<KeyId, ReviewerScore>();
  const get = (k: KeyId): ReviewerScore => {
    let sc = out.get(k);
    if (!sc) {
      sc = blank();
      out.set(k, sc);
    }
    return sc;
  };
  const brierSum = new Map<KeyId, number>();
  const index = outcomeIndex(state);

  for (const s of state.submissions.values()) {
    if (s.reviews.length === 0) continue;
    const outcome = outcomeWith(state, index, s, now);
    const cutoff = reviewWindowCloseSeq(state, s.id);
    for (const r of s.reviews) {
      const sc = get(r.reviewer);
      if (r.verdict !== undefined) sc.reviews += 1;
      if (cutoff === null || r.committedSeq > cutoff) continue;
      const inTime = r.verdict !== undefined && r.revealedSeq !== undefined && r.revealedSeq <= cutoff;
      if (!inTime) sc.unrevealed += 1;
      if (outcome === null) continue;
      sc.scored += 1;
      const b = inTime && r.verdict ? brier(r.verdict.defectProbability, outcome) : FORFEIT;
      brierSum.set(r.reviewer, (brierSum.get(r.reviewer) ?? 0) + b);
    }
  }
  for (const [k, sum] of brierSum) {
    const sc = get(k);
    sc.meanBrier = sum / sc.scored;
  }

  const plants = plantStats(state, ALL_TIME);
  for (const [k, tally] of plants.byReviewer) {
    const sc = get(k);
    sc.plantsSeen = tally.seen;
    sc.plantsCaught = tally.caught;
  }
  return out;
}
