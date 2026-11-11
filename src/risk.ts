// Risk maths for promotion and metrics: exact binomial and Poisson bounds,
// capture–recapture style estimators, and the two ledger-derived numbers the
// promotion rule gates on (seeded recall and the critical-defect upper bound).
// Pure: no clock, no randomness. Accuracy target is 1e-6 absolute on bounds.

import { plantCaught, revealedPlants } from "./plants";
import type { CommonsState } from "./types";

// ---------------------------------------------------------------------------
// Special functions
// ---------------------------------------------------------------------------

// Lanczos approximation (g = 7, 9 terms), relative error ~1e-15 for x > 0.
const LANCZOS = [
  0.99999999999980993, 676.5203681218851, -1259.1392167224028, 771.32342877765313, -176.61502916214059,
  12.507343278686905, -0.13857109526572012, 9.9843695780195716e-6, 1.5056327351493116e-7,
];

export function logGamma(x: number): number {
  if (!(x > 0)) throw new RangeError(`logGamma needs x > 0, got ${x}`);
  if (x < 0.5) return Math.log(Math.PI / Math.sin(Math.PI * x)) - logGamma(1 - x);
  const z = x - 1;
  let sum = LANCZOS[0] as number;
  for (let i = 1; i < LANCZOS.length; i++) sum += (LANCZOS[i] as number) / (z + i);
  const t = z + 7.5;
  return 0.5 * Math.log(2 * Math.PI) + (z + 0.5) * Math.log(t) - t + Math.log(sum);
}

const EPS = 1e-15;
const TINY = 1e-300;
const MAX_ITER = 1000;

// Continued fraction for the incomplete beta (Numerical Recipes betacf, modified
// Lentz). Converges fast for x < (a+1)/(a+b+2); the caller uses the symmetry
// I_x(a,b) = 1 - I_{1-x}(b,a) otherwise.
function betaContinuedFraction(a: number, b: number, x: number): number {
  const qab = a + b;
  const qap = a + 1;
  const qam = a - 1;
  let c = 1;
  let d = 1 - (qab * x) / qap;
  if (Math.abs(d) < TINY) d = TINY;
  d = 1 / d;
  let h = d;
  for (let m = 1; m <= MAX_ITER; m++) {
    const m2 = 2 * m;
    let aa = (m * (b - m) * x) / ((qam + m2) * (a + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < TINY) d = TINY;
    c = 1 + aa / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    h *= d * c;
    aa = (-(a + m) * (qab + m) * x) / ((a + m2) * (qap + m2));
    d = 1 + aa * d;
    if (Math.abs(d) < TINY) d = TINY;
    c = 1 + aa / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < EPS) return h;
  }
  throw new Error(`incomplete beta did not converge (a=${a}, b=${b}, x=${x})`);
}

// Regularized incomplete beta I_x(a, b), a > 0, b > 0.
export function regularizedBeta(x: number, a: number, b: number): number {
  if (!(a > 0) || !(b > 0)) throw new RangeError(`regularizedBeta needs a, b > 0 (a=${a}, b=${b})`);
  if (Number.isNaN(x)) throw new RangeError("regularizedBeta: x is NaN");
  if (x <= 0) return 0;
  if (x >= 1) return 1;
  const front = Math.exp(
    logGamma(a + b) - logGamma(a) - logGamma(b) + a * Math.log(x) + b * Math.log1p(-x),
  );
  if (x < (a + 1) / (a + b + 2)) return (front * betaContinuedFraction(a, b, x)) / a;
  return 1 - (front * betaContinuedFraction(b, a, 1 - x)) / b;
}

// Quantile of Beta(a, b): the x with I_x(a, b) = p. Bisection, because I_x is
// monotone in x and bisection cannot diverge; 200 halvings reach the float
// resolution of [0, 1] long before the loop ends.
export function betaInv(p: number, a: number, b: number): number {
  if (!(p >= 0 && p <= 1)) throw new RangeError(`betaInv needs 0 <= p <= 1, got ${p}`);
  if (p === 0) return 0;
  if (p === 1) return 1;
  let lo = 0;
  let hi = 1;
  for (let i = 0; i < 200 && hi - lo > 1e-16; i++) {
    const mid = (lo + hi) / 2;
    if (regularizedBeta(mid, a, b) < p) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}

// Regularized lower incomplete gamma P(a, x): series below a+1, continued
// fraction above (Numerical Recipes gser/gcf).
export function regularizedGammaP(a: number, x: number): number {
  if (!(a > 0)) throw new RangeError(`regularizedGammaP needs a > 0, got ${a}`);
  if (Number.isNaN(x)) throw new RangeError("regularizedGammaP: x is NaN");
  if (x <= 0) return 0;
  if (x === Number.POSITIVE_INFINITY) return 1;
  const logFront = -x + a * Math.log(x) - logGamma(a);
  if (x < a + 1) {
    let ap = a;
    let sum = 1 / a;
    let del = sum;
    for (let n = 0; n < MAX_ITER; n++) {
      ap += 1;
      del *= x / ap;
      sum += del;
      if (Math.abs(del) < Math.abs(sum) * EPS) return sum * Math.exp(logFront);
    }
    throw new Error(`incomplete gamma series did not converge (a=${a}, x=${x})`);
  }
  let b = x + 1 - a;
  let c = 1 / TINY;
  let d = 1 / b;
  let h = d;
  for (let i = 1; i <= MAX_ITER; i++) {
    const an = -i * (i - a);
    b += 2;
    d = an * d + b;
    if (Math.abs(d) < TINY) d = TINY;
    c = b + an / c;
    if (Math.abs(c) < TINY) c = TINY;
    d = 1 / d;
    const del = d * c;
    h *= del;
    if (Math.abs(del - 1) < EPS) return 1 - Math.exp(logFront) * h;
  }
  throw new Error(`incomplete gamma fraction did not converge (a=${a}, x=${x})`);
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

export type Interval = { lower: number; upper: number };

function checkBinomial(k: number, n: number, confidence: number): void {
  if (!Number.isInteger(n) || n < 0) throw new RangeError(`n must be a non-negative integer, got ${n}`);
  if (!Number.isInteger(k) || k < 0 || k > n) throw new RangeError(`k must be an integer in [0, n], got ${k}`);
  checkConfidence(confidence);
}

function checkConfidence(confidence: number): void {
  if (!(confidence > 0 && confidence < 1)) throw new RangeError(`confidence must be in (0, 1), got ${confidence}`);
}

// Exact two-sided Clopper–Pearson interval: each tail holds (1-confidence)/2.
// n = 0 carries no information and returns [0, 1].
export function clopperPearson(k: number, n: number, confidence: number): Interval {
  checkBinomial(k, n, confidence);
  const alpha = 1 - confidence;
  return {
    lower: k === 0 ? 0 : betaInv(alpha / 2, k, n - k + 1),
    upper: k === n ? 1 : betaInv(1 - alpha / 2, k + 1, n - k),
  };
}

// One-sided Clopper–Pearson bounds: `lower` is the bound such that
// P(p < lower) <= 1 - confidence, and `upper` likewise from above. They are two
// separate one-sided statements, not a single interval at `confidence`.
export function clopperPearsonOneSided(k: number, n: number, confidence: number): Interval {
  checkBinomial(k, n, confidence);
  return {
    lower: k === 0 ? 0 : betaInv(1 - confidence, k, n - k + 1),
    upper: k === n ? 1 : betaInv(confidence, k + 1, n - k),
  };
}

// One-sided upper bound on a Poisson mean having seen `observed` events: the λ
// with P(X <= observed; λ) = 1 - confidence. Uses P(X <= k; λ) = 1 - P(k+1, λ)
// (regularized gamma) and bisects, since the CDF falls monotonically in λ.
export function poissonUpper(observed: number, confidence: number): number {
  if (!Number.isInteger(observed) || observed < 0) {
    throw new RangeError(`observed must be a non-negative integer, got ${observed}`);
  }
  checkConfidence(confidence);
  const tail = 1 - confidence;
  const cdf = (lambda: number) => 1 - regularizedGammaP(observed + 1, lambda);
  let lo = 0;
  let hi = Math.max(1, 2 * observed);
  while (cdf(hi) > tail) hi *= 2;
  for (let i = 0; i < 200 && hi - lo > 1e-12 * Math.max(1, hi); i++) {
    const mid = (lo + hi) / 2;
    if (cdf(mid) > tail) lo = mid;
    else hi = mid;
  }
  return (lo + hi) / 2;
}

// ---------------------------------------------------------------------------
// Estimators
// ---------------------------------------------------------------------------

// Defects found in an earlier stage versus those that still surfaced later.
// Treating the earlier stage as a filter with recall r, later ≈ earlier·(1-r)
// gives recall ≈ 1 - later/earlier; the geometric tail of what the next stage
// would still miss is residual ≈ later² / (earlier - later).
// Guard: with earlier <= 0 or later >= earlier the filter demonstrated nothing,
// so recall is 0 and the residual is unbounded (Infinity) — never an
// optimistic default.
export function escapeRate(nEarlier: number, nLater: number): { recall: number; residual: number } {
  if (!Number.isFinite(nEarlier) || !Number.isFinite(nLater) || nLater < 0) {
    throw new RangeError(`escapeRate needs finite counts and nLater >= 0 (got ${nEarlier}, ${nLater})`);
  }
  if (nEarlier <= 0 || nLater >= nEarlier) return { recall: 0, residual: Number.POSITIVE_INFINITY };
  return { recall: 1 - nLater / nEarlier, residual: (nLater * nLater) / (nEarlier - nLater) };
}

// Chao1 lower-bound estimate of total distinct defects from the distinct count
// S and the singleton/doubleton counts: S + f1²/(2 f2), or the bias-corrected
// S + f1(f1-1)/2 when no doubletons were seen.
export function chao1(observedDistinct: number, f1: number, f2: number): number {
  for (const [name, v] of [
    ["observedDistinct", observedDistinct],
    ["f1", f1],
    ["f2", f2],
  ] as const) {
    if (!Number.isFinite(v) || v < 0) throw new RangeError(`chao1: ${name} must be finite and >= 0, got ${v}`);
  }
  if (f2 === 0) return observedDistinct + (f1 * (f1 - 1)) / 2;
  return observedDistinct + (f1 * f1) / (2 * f2);
}

// How much worse reality was than predicted, never below 1: a model that
// over-predicts escapes is not rewarded with a tighter bound. With no
// prediction, zero escapes is "no evidence" (1) and any escape is a miss of
// unknown size, charged as actual + 1.
export function calibrationFactor(predictedEscapes: number, actualEscapes: number): number {
  if (!Number.isFinite(predictedEscapes) || predictedEscapes < 0 || !Number.isFinite(actualEscapes) || actualEscapes < 0) {
    throw new RangeError(`calibrationFactor needs finite non-negative inputs (got ${predictedEscapes}, ${actualEscapes})`);
  }
  if (predictedEscapes > 0) return Math.max(1, actualEscapes / predictedEscapes);
  return actualEscapes === 0 ? 1 : actualEscapes + 1;
}

// ---------------------------------------------------------------------------
// Ledger-derived
// ---------------------------------------------------------------------------

function atOrAfter(iso: string, sinceIso: string): boolean {
  const since = Date.parse(sinceIso);
  if (Number.isNaN(since)) throw new RangeError(`invalid sinceIso: ${sinceIso}`);
  return Date.parse(iso) >= since;
}

// Seeded recall over revealed plants submitted since `sinceIso`, with one-sided
// 90% Clopper–Pearson bounds. No seeds gives the uninformative [0, 1].
export function seededRecall(
  state: CommonsState,
  sinceIso: string,
): { seeds: number; caught: number; lower90: number; upper90: number } {
  const plants = revealedPlants(state, sinceIso);
  const seeds = plants.length;
  const caught = plants.filter((s) => plantCaught(state, s.id)).length;
  const { lower, upper } = clopperPearsonOneSided(caught, seeds, 0.9);
  return { seeds, caught, lower90: lower, upper90: upper };
}

const AT_LEAST_MEDIUM = new Set(["medium", "high", "critical"]);

// Escapes since `sinceIso`, one per finding, whose finding is on the ledger.
function escapesSince(state: CommonsState, sinceIso: string): { severity: string }[] {
  const seen = new Set<string>();
  const out: { severity: string }[] = [];
  for (const e of state.escapes) {
    if (seen.has(e.findingId) || !atOrAfter(e.at, sinceIso)) continue;
    const f = state.findings.get(e.findingId);
    if (!f) continue;
    seen.add(e.findingId);
    out.push({ severity: f.severity });
  }
  return out;
}

// What reviewers predicted would escape: for each non-plant submission shipped
// in a snapshot promoted since `sinceIso`, the mean revealed defectProbability
// (the probability of a defect of severity >= medium). Submissions without a
// revealed review contribute nothing; there was no prediction to calibrate.
export function predictedEscapes(state: CommonsState, sinceIso: string): number {
  const shipped = new Set<string>();
  for (const snap of state.snapshots.values()) {
    if (snap.promoted && atOrAfter(snap.promoted.at, sinceIso)) for (const id of snap.submissionIds) shipped.add(id);
  }
  let total = 0;
  for (const id of shipped) {
    const s = state.submissions.get(id);
    if (!s || s.planted) continue;
    const ps = s.reviews.flatMap((r) => (r.verdict ? [r.verdict.defectProbability] : []));
    if (ps.length > 0) total += ps.reduce((a, b) => a + b, 0) / ps.length;
  }
  return total;
}

// Escapes since `sinceIso` of severity >= medium: the outcome predictedEscapes predicts.
export function actualEscapes(state: CommonsState, sinceIso: string): number {
  return escapesSince(state, sinceIso).filter((e) => AT_LEAST_MEDIUM.has(e.severity)).length;
}

// Upper bound (90%) on critical defects still undiscovered in what shipped.
//
// Model: reviewers find a fraction r of defects (r = seeded recall, taken at
// its pessimistic 90% lower bound). If c criticals were found anyway (escapes
// into main), the ones still hidden are about c·(1-r)/r. c is a Poisson count,
// so it is replaced by its 90% upper bound, which is > 0 even when c = 0 —
// zero observed escapes is not proof of zero defects. The result is scaled by
// the calibration factor of reviewer predictions against actual escapes.
// Without any revealed plant, recall is unknown and the bound is Infinity.
export function criticalUpperBound90(state: CommonsState, sinceIso: string): number {
  const recall = seededRecall(state, sinceIso);
  if (recall.seeds < 1) return Number.POSITIVE_INFINITY;
  const r = recall.lower90;
  const criticals = escapesSince(state, sinceIso).filter((e) => e.severity === "critical").length;
  const calibration = calibrationFactor(predictedEscapes(state, sinceIso), actualEscapes(state, sinceIso));
  return ((poissonUpper(criticals, 0.9) * (1 - r)) / Math.max(r, 1e-9)) * calibration;
}
