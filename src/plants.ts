// Planted bugs: the seeded-recall measurement. A custodian commits to a plant
// (plantCommit), submits it like any other change, and reveals it (plantReveal)
// only after its review window closed, so reviewers cannot tell plants from real
// work. This module holds the shared definition of "a plant was caught" so that
// risk, promotion, metrics and incentives all count the same thing.

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

// The review window of a submission is closed once it has an assignment and
// every assigned reviewer has revealed, or once it was merged. Revealing a plant
// earlier would tell the remaining reviewers what to look for.
export function reviewWindowClosed(state: CommonsState, submissionId: string): boolean {
  const s = state.submissions.get(submissionId);
  if (!s) return false;
  if (s.merged) return true;
  if (!s.assignment) return false;
  return s.assignment.reviewers.every((r) => s.reviews.some((rv) => rv.reviewer === r && rv.verdict !== undefined));
}

// Findings and reviews by the submission's own author (or another agent of the
// same owner) never count as catches: the plant's author is the custodian, who
// knows where the bug is.
function sameOwnerAsAuthor(state: CommonsState, s: SubmissionState, agent: KeyId): boolean {
  if (agent === s.author) return true;
  const authorOwner = state.agents.get(s.author)?.owner;
  return authorOwner !== undefined && state.agents.get(agent)?.owner === authorOwner;
}

function reproducedFindersOn(state: CommonsState, s: SubmissionState): Set<KeyId> {
  const finders = new Set<KeyId>();
  for (const f of state.findings.values()) {
    if (!("submissionId" in f.target) || f.target.submissionId !== s.id) continue;
    if (f.result?.reproduced !== true) continue;
    if (sameOwnerAsAuthor(state, s, f.finder)) continue;
    finders.add(f.finder);
  }
  return finders;
}

function flaggers(state: CommonsState, s: SubmissionState): Set<KeyId> {
  const out = new Set<KeyId>();
  for (const r of s.reviews) {
    if (r.verdict === undefined || !(r.verdict.defectProbability >= CATCH_THRESHOLD)) continue;
    if (sameOwnerAsAuthor(state, s, r.reviewer)) continue;
    out.add(r.reviewer);
  }
  return out;
}

// Caught = a reproduced finding targets the submission, or a revealed review on
// it has defectProbability >= 0.5. Independent of whether it is a plant.
export function plantCaught(state: CommonsState, submissionId: string): boolean {
  const s = state.submissions.get(submissionId);
  if (!s) return false;
  return flaggers(state, s).size > 0 || reproducedFindersOn(state, s).size > 0;
}

// Same definition, restricted to one reviewer's own reveal and findings.
export function plantCaughtBy(state: CommonsState, submissionId: string, reviewer: KeyId): boolean {
  const s = state.submissions.get(submissionId);
  if (!s) return false;
  return flaggers(state, s).has(reviewer) || reproducedFindersOn(state, s).has(reviewer);
}

// Agents that looked at a submission: committed a review (revealed or not — a
// reviewer who never reveals still saw the plant and still missed it) or filed
// a finding on it. The author's own owner is excluded.
function sawSubmission(state: CommonsState, s: SubmissionState): Set<KeyId> {
  const out = new Set<KeyId>();
  for (const r of s.reviews) if (!sameOwnerAsAuthor(state, s, r.reviewer)) out.add(r.reviewer);
  for (const f of state.findings.values()) {
    if ("submissionId" in f.target && f.target.submissionId === s.id && !sameOwnerAsAuthor(state, s, f.finder)) {
      out.add(f.finder);
    }
  }
  return out;
}

function atOrAfter(iso: string, sinceIso: string): boolean {
  const since = Date.parse(sinceIso);
  if (Number.isNaN(since)) throw new RangeError(`invalid sinceIso: ${sinceIso}`);
  // An unparseable timestamp compares false and drops out of every window.
  return Date.parse(iso) >= since;
}

// Plants revealed so far whose submission falls in the window. Unrevealed
// plants are indistinguishable from real work and are never counted.
export function revealedPlants(state: CommonsState, sinceIso: string): SubmissionState[] {
  const out: SubmissionState[] = [];
  for (const s of state.submissions.values()) {
    if (s.planted !== undefined && atOrAfter(s.submittedAt, sinceIso)) out.push(s);
  }
  return out;
}

export type PlantTally = { seen: number; caught: number };

export type PlantStats = {
  seeds: number;
  caught: number;
  byReviewer: Map<KeyId, PlantTally>;
  // A family saw a plant if any of its agents saw it, and caught it if any of
  // those agents caught it; each plant counts once per family.
  byFamily: Map<ModelFamily, PlantTally>;
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
  const stats: PlantStats = { seeds: 0, caught: 0, byReviewer: new Map(), byFamily: new Map() };
  for (const s of revealedPlants(state, sinceIso)) {
    stats.seeds += 1;
    if (plantCaught(state, s.id)) stats.caught += 1;
    const familyCaught = new Map<ModelFamily, boolean>();
    for (const agent of sawSubmission(state, s)) {
      const caught = plantCaughtBy(state, s.id, agent);
      bump(stats.byReviewer, agent, caught);
      const family = state.agents.get(agent)?.modelFamily ?? UNKNOWN_FAMILY;
      familyCaught.set(family, (familyCaught.get(family) ?? false) || caught);
    }
    for (const [family, caught] of familyCaught) bump(stats.byFamily, family, caught);
  }
  return stats;
}
