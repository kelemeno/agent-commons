// Review verdicts and reviewer track records.
//
// A review is a probability that the change holds a defect of severity >=
// medium, committed blind (commitmentFor) and revealed later. Reviewers are
// scored with the Brier score against what later became known about the
// change: a reproduced finding or a revealed plant says it was defective;
// shipping to main and surviving the vesting tail without an escape says it
// was clean. Anything else is unknown and scores nothing.

import { canonical, sha256hex } from "./crypto";
import { instantMs, plantStats, reviewWindowCloseSeq } from "./plants";
import type { CommonsState, KeyId, ReviewVerdict, Severity, SnapshotState } from "./types";

// The ledger checks reveals against exactly this.
export function commitmentFor(verdict: ReviewVerdict, salt: string): string {
  return sha256hex(canonical(verdict) + salt);
}

const VERDICT_FIELDS = ["defectProbability", "summary", "findingIds"];

// Same rules the ledger applies at reveal, so a verdict that passes here can
// be revealed. Empty list = valid.
export function validateVerdict(v: unknown): string[] {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return ["verdict is not an object"];
  const o = v as Record<string, unknown>;
  const problems: string[] = [];
  for (const key of Object.keys(o)) {
    if (!VERDICT_FIELDS.includes(key) && o[key] !== undefined) problems.push(`unknown field ${key}`);
  }
  const p = o["defectProbability"];
  if (typeof p !== "number" || !Number.isFinite(p) || p < 0 || p > 1) {
    problems.push("defectProbability must be a number in [0, 1]");
  }
  if (typeof o["summary"] !== "string") problems.push("summary must be a string");
  const ids = o["findingIds"];
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

// Earliest time the submission reached main: a promotion ships the promoted
// snapshot and every snapshot before it. null if never promoted.
function shippedAt(state: CommonsState, submissionId: string): number | null {
  let earliest: number | null = null;
  for (const snap of state.snapshots.values()) {
    if (!snap.promoted) continue;
    const at = instantMs(snap.promoted.at);
    if (Number.isNaN(at)) continue;
    for (let cur: SnapshotState | undefined = snap; cur; ) {
      if (cur.submissionIds.includes(submissionId)) {
        if (earliest === null || at < earliest) earliest = at;
        break;
      }
      cur = cur.previousSnapshotId === null ? undefined : state.snapshots.get(cur.previousSnapshotId);
    }
  }
  return earliest;
}

// 1: a reproduced finding of severity >= medium targets the submission, or it
// is a revealed plant of severity >= medium.
// 0: it shipped in a promoted snapshot at least rules.vesting.tailDays before
// nowIso, and no reproduced finding of severity >= medium targets the snapshot
// that carried it (an escape always rests on a reproduced finding). A
// snapshot-level finding cannot be pinned on one of the snapshot's
// submissions, so it leaves all of them unknown rather than clean.
// null: anything else.
// Throws RangeError on a nowIso without an explicit zone.
export function submissionOutcome(state: CommonsState, submissionId: string, nowIso: string): 0 | 1 | null {
  const now = instantMs(nowIso);
  if (Number.isNaN(now)) throw new RangeError(`invalid nowIso (need an ISO date-time with Z or ±HH:MM): ${nowIso}`);
  const s = state.submissions.get(submissionId);
  if (!s) return null;
  if (s.planted && COUNTS[s.planted.severity]) return 1;
  for (const f of state.findings.values()) {
    if (!("submissionId" in f.target) || f.target.submissionId !== submissionId) continue;
    if (f.result?.reproduced === true && COUNTS[f.severity]) return 1;
  }

  const shipped = shippedAt(state, submissionId);
  if (shipped === null || shipped + state.rules.vesting.tailDays * DAY_MS > now) return null;
  const carriers = new Set<string>();
  for (const snap of state.snapshots.values()) if (snap.submissionIds.includes(submissionId)) carriers.add(snap.id);
  for (const f of state.findings.values()) {
    if ("snapshotId" in f.target && carriers.has(f.target.snapshotId) && f.result?.reproduced === true && COUNTS[f.severity]) {
      return null;
    }
  }
  return 0;
}

export type ReviewerScore = {
  reviews: number; // revealed reviews
  scored: number; // of those, revealed within the review window on a submission with a known outcome
  meanBrier: number; // over scored reviews; 0 when scored = 0
  plantsSeen: number;
  plantsCaught: number;
  unrevealed: number; // committed and never revealed
};

const ALL_TIME = "1970-01-01T00:00:00Z";

function blank(): ReviewerScore {
  return { reviews: 0, scored: 0, meanBrier: 0, plantsSeen: 0, plantsCaught: 0, unrevealed: 0 };
}

// Per agent, over submission reviews (snapshot attestations are not scored
// here). A reveal counts towards Brier only if it landed by the time the
// review window closed. Otherwise a reviewer could commit on everything and
// reveal only where the outcome, once known, made the commitment look good.
// Plants follow plants.ts: seen = committed a review or filed a finding on a
// revealed plant within its window; caught = plantCaughtBy (p >= 0.5 revealed,
// or a reproduced finding, within the window). Agents who only filed findings
// on plants appear with reviews = 0.
export function reviewerScores(state: CommonsState, nowIso: string): Map<KeyId, ReviewerScore> {
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

  for (const s of state.submissions.values()) {
    const outcome = submissionOutcome(state, s.id, nowIso);
    const cutoff = reviewWindowCloseSeq(state, s.id);
    for (const r of s.reviews) {
      const sc = get(r.reviewer);
      if (r.verdict === undefined) {
        sc.unrevealed += 1;
        continue;
      }
      sc.reviews += 1;
      if (outcome === null || cutoff === null || r.revealedSeq === undefined || r.revealedSeq > cutoff) continue;
      sc.scored += 1;
      brierSum.set(r.reviewer, (brierSum.get(r.reviewer) ?? 0) + brier(r.verdict.defectProbability, outcome));
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
