// The merge judgement: whether the reviews let a submission merge without a
// human. Probabilistic about the code, deterministic about the reviewers.
//
// Each counted verdict (a seated reviewer's defect probability, revealed
// before its round closed) is weighted by its reviewer's track record, and
// the verdicts are pooled in log-odds:
//
//   logit(P) = (w0·logit(priorRisk) + Σ wᵢ·logit(pᵢ)) / (w0 + Σ wᵢ)
//
// with pᵢ clamped to [0.01, 0.99] and w0 = rules.judgement.priorWeight. The
// prior acts as one more reviewer who knows nothing: reviewers without a
// record (low weight) leave P near priorRisk, so only reviewers whose past
// verdicts turned out right can carry a merge alone.
//
// A reviewer's weight comes from review.reviewerScores: the Brier skill of
// their scored reviews (1 - meanBrier/0.25, so always saying 0.5 is worth
// nothing), shrunk towards newReviewerWeight by priorReviews pseudo-reviews,
// times their plant record ((caught + 1)/(seen + 1)). A commit not revealed in
// time already scores as confidently wrong there. Plants and escapes are what
// make outcomes known, so they are what keep the weights honest: without
// them every reviewer would stay at newReviewerWeight.
//
// The submission merges when P <= rules.judgement.maxRisk[ring] and nothing
// triggers an escalation: the verdicts spread by at least `disagreement`, or a
// reviewer of weight >= trustedWeight said p >= CATCH_THRESHOLD, or too few
// verdicts were revealed. A trigger, or P above the threshold, draws more
// reviewers (a reviewEscalation round) while rounds and eligible owners
// remain; after that a human decides (mergeApproval). Ring 0 always needs a
// human. A reproduced finding blocks whatever the reviews say (coordinator.ts,
// ledger.ts).
//
// Pure: the caller passes `nowIso` (weights change as outcomes become known).

import { submissionRing } from "./gates/rings";
import { CATCH_THRESHOLD, reviewCloseSeq, reviewRounds } from "./plants";
import { type ReviewerScore, reviewerScores } from "./review";
import type { CommonsState, KeyId, MergeJudgement, Ring, Rules, SubmissionState } from "./types";

// Recorded weights and risks are rounded to this, and a recomputed pool may
// differ from the recorded one by at most this much: Math.log and Math.exp
// are not correctly rounded on every engine.
export const JUDGEMENT_PRECISION = 1e-6;
const P_MIN = 0.01;
const P_MAX = 0.99;
const COIN_BRIER = 0.25;

export function roundJudgement(x: number): number {
  return Math.round(x / JUDGEMENT_PRECISION) * JUDGEMENT_PRECISION;
}

const logit = (p: number) => Math.log(p / (1 - p));
const clampP = (p: number) => Math.min(P_MAX, Math.max(P_MIN, p));

// A reviewer's weight in [0, 1]; `score` absent means no record.
export function reviewerWeight(score: ReviewerScore | undefined, rules: Rules): number {
  const j = rules.judgement;
  const n = score?.scored ?? 0;
  const skill = n === 0 ? 0 : Math.max(0, 1 - score!.meanBrier / COIN_BRIER);
  const shrunk = j.priorReviews + n === 0 ? j.newReviewerWeight : (j.priorReviews * j.newReviewerWeight + n * skill) / (j.priorReviews + n);
  const seen = score?.plantsSeen ?? 0;
  const caught = Math.min(score?.plantsCaught ?? 0, seen);
  const recall = (caught + 1) / (seen + 1);
  return Math.min(1, Math.max(0, shrunk * recall));
}

// Every agent's weight at `nowIso`; agents without a record get newReviewerWeight.
export function reviewerWeights(state: CommonsState, nowIso: string): (reviewer: KeyId) => number {
  const scores = reviewerScores(state, nowIso);
  return (k) => reviewerWeight(scores.get(k), state.rules);
}

// The pooled defect risk of weighted verdicts; see the header.
export function poolRisk(verdicts: readonly { p: number; weight: number }[], rules: Rules): number {
  const j = rules.judgement;
  let num = j.priorWeight * logit(j.priorRisk);
  let den = j.priorWeight;
  for (const v of verdicts) {
    num += v.weight * logit(clampP(v.p));
    den += v.weight;
  }
  if (!(den > 0)) return j.priorRisk;
  return 1 / (1 + Math.exp(-num / den));
}

export type CountedVerdict = { reviewer: KeyId; p: number; round: number };

// The verdicts the judgement counts: one per seat, across all rounds, revealed
// no later than its round closed. Open reviewers choose what they review, so
// they are not counted (their reviews are still scored and paid). Sorted by
// reviewer.
export function countedVerdicts(state: CommonsState, s: SubmissionState): CountedVerdict[] {
  const out: CountedVerdict[] = [];
  for (const round of reviewRounds(s)) {
    for (const k of round.reviewers) {
      const r = s.reviews.find((v) => v.reviewer === k && v.verdict !== undefined);
      if (!r?.verdict || r.revealedSeq === undefined) continue;
      const close = reviewCloseSeq(state, s, k);
      if (close !== null && r.revealedSeq > close) continue;
      out.push({ reviewer: k, p: r.verdict.defectProbability, round: round.round });
    }
  }
  return out.sort((a, b) => (a.reviewer < b.reviewer ? -1 : a.reviewer > b.reviewer ? 1 : 0));
}

// Why these verdicts call for more reviewers, beyond the pooled risk: empty
// when none. The ledger runs the same check on a recorded judgement.
export function escalationTriggers(verdicts: readonly { reviewer: KeyId; p: number; weight: number }[], rules: Rules): string[] {
  const j = rules.judgement;
  const out: string[] = [];
  if (verdicts.length > 0) {
    const ps = verdicts.map((v) => v.p);
    const spread = Math.max(...ps) - Math.min(...ps);
    if (spread >= j.disagreement) out.push(`reviewers disagree (p from ${fmt(Math.min(...ps))} to ${fmt(Math.max(...ps))})`);
  }
  for (const v of verdicts) {
    if (v.weight >= j.trustedWeight && v.p >= CATCH_THRESHOLD) {
      out.push(`${v.reviewer} (weight ${fmt(v.weight)}) says p = ${fmt(v.p)}`);
    }
  }
  return out;
}

const fmt = (x: number) => String(Math.round(x * 1000) / 1000);

export type Judgement = {
  record: MergeJudgement; // what a merge entry records
  verdicts: (CountedVerdict & { weight: number })[];
  triggers: string[]; // escalation triggers, including too few verdicts
  outcome: "merge" | "escalate" | "human";
  reason: string;
};

export type JudgeOptions = {
  quorum: number; // counted verdicts a mechanical merge needs
  canEscalate: boolean; // a round is left and some owner could fill a seat
};

// The judgement on `submissionId` at `nowIso`, over the rounds so far.
export function judge(state: CommonsState, submissionId: string, nowIso: string, opts: JudgeOptions): Judgement {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`judgement: no submission ${submissionId}`);
  const rules = state.rules;
  const weightOf = reviewerWeights(state, nowIso);
  const verdicts = countedVerdicts(state, s).map((v) => ({ ...v, weight: roundJudgement(weightOf(v.reviewer)) }));
  const ring = submissionRing(s.changedFiles, rules);
  const threshold = rules.judgement.maxRisk[ring];
  const pooledRisk = roundJudgement(poolRisk(verdicts, rules));
  const record: MergeJudgement = {
    asOf: nowIso,
    ring,
    pooledRisk,
    threshold,
    weights: verdicts.map((v) => ({ reviewer: v.reviewer, weight: v.weight })),
  };
  const triggers = escalationTriggers(verdicts, rules);
  if (verdicts.length < opts.quorum) triggers.push(`${verdicts.length} of ${opts.quorum} required verdicts`);
  const risk = `pooled risk ${fmt(pooledRisk)} vs ${fmt(threshold)} for ring ${ring}`;
  if (triggers.length === 0 && pooledRisk <= threshold) {
    if (ring === 0) return { record, verdicts, triggers, outcome: "human", reason: `${risk}; ring 0 (kernel) always needs a human` };
    return { record, verdicts, triggers, outcome: "merge", reason: risk };
  }
  const why = [...(pooledRisk > threshold ? [`${risk} is too high`] : []), ...triggers].join("; ");
  return { record, verdicts, triggers, outcome: opts.canEscalate ? "escalate" : "human", reason: why };
}

// What is wrong with a merge entry's recorded judgement, checked against the
// state before the merge: null when nothing. Cheap and clock-free, so the
// ledger runs it on every merge: the ring and threshold follow from the rules,
// the reviewers are exactly the counted verdicts, and the pooled risk follows
// from the recorded weights. The weights themselves need the reviewers' whole
// record, so they are audited by replay (selection.verifyJudgementInLedger).
export function judgementProblem(state: CommonsState, s: SubmissionState, j: unknown): string | null {
  if (!isRecord(j)) return "judgement must be an object";
  const keys = Object.keys(j).filter((k) => j[k] !== undefined);
  const want = ["asOf", "ring", "pooledRisk", "threshold", "weights"];
  if (keys.length !== want.length || !want.every((k) => keys.includes(k))) return `judgement must have exactly the fields ${want.join(", ")}`;
  const ring = submissionRing(s.changedFiles, state.rules);
  if (j.ring !== ring) return `judgement.ring must be ${ring}`;
  if (j.threshold !== state.rules.judgement.maxRisk[ring as Ring]) return "judgement.threshold is not rules.judgement.maxRisk for the ring";
  if (!Array.isArray(j.weights)) return "judgement.weights must be an array";
  const counted = countedVerdicts(state, s);
  if (j.weights.length !== counted.length) return "judgement.weights must list exactly the counted verdicts";
  const verdicts: { reviewer: KeyId; p: number; weight: number }[] = [];
  for (let i = 0; i < counted.length; i++) {
    const w: unknown = j.weights[i];
    const c = counted[i] as CountedVerdict;
    if (!isRecord(w) || Object.keys(w).length !== 2 || w.reviewer !== c.reviewer) {
      return "judgement.weights must list exactly the counted verdicts, sorted by reviewer";
    }
    if (typeof w.weight !== "number" || !(w.weight >= 0 && w.weight <= 1)) return "judgement weights must be in [0, 1]";
    verdicts.push({ reviewer: c.reviewer, p: c.p, weight: w.weight });
  }
  if (typeof j.pooledRisk !== "number" || Math.abs(poolRisk(verdicts, state.rules) - j.pooledRisk) > 2 * JUDGEMENT_PRECISION) {
    return "judgement.pooledRisk is not the pool of the recorded weights";
  }
  return null;
}

// Whether a recorded judgement lets the merge go ahead without a human.
export function judgementPasses(state: CommonsState, s: SubmissionState, j: MergeJudgement): string | null {
  if (j.ring === 0) return "ring 0 (kernel) needs a mergeApproval";
  if (!(j.pooledRisk <= j.threshold)) return `pooled risk ${fmt(j.pooledRisk)} is above ${fmt(j.threshold)}`;
  const counted = countedVerdicts(state, s);
  const byReviewer = new Map(j.weights.map((w) => [w.reviewer, w.weight]));
  const triggers = escalationTriggers(
    counted.map((c) => ({ reviewer: c.reviewer, p: c.p, weight: byReviewer.get(c.reviewer) ?? 0 })),
    state.rules,
  );
  return triggers.length > 0 ? triggers.join("; ") : null;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
