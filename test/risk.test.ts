import { test } from "node:test";
import assert from "node:assert/strict";

import {
  actualEscapes,
  betaInv,
  calibrationFactor,
  chao1,
  clopperPearson,
  clopperPearsonOneSided,
  criticalUpperBound90,
  escapeRate,
  logGamma,
  poissonUpper,
  predictedEscapes,
  regularizedBeta,
  regularizedGammaP,
  seededRecall,
} from "../src/risk";
import type { CommonsState, Rules, Severity, SubmissionState } from "../src/types";

function close(actual: number, expected: number, tol = 1e-6, msg?: string): void {
  assert.ok(Math.abs(actual - expected) <= tol, `${msg ?? ""} expected ${expected}, got ${actual}`);
}

// --- reference implementations by direct summation --------------------------

function logChoose(n: number, k: number): number {
  return logGamma(n + 1) - logGamma(k + 1) - logGamma(n - k + 1);
}
function binomTail(k: number, n: number, p: number): number {
  // P(X >= k), X ~ Bin(n, p)
  let s = 0;
  for (let j = k; j <= n; j++) s += Math.exp(logChoose(n, j) + j * Math.log(p) + (n - j) * Math.log1p(-p));
  return s;
}
function poissonCdf(k: number, lambda: number): number {
  let term = Math.exp(-lambda);
  let s = term;
  for (let j = 1; j <= k; j++) {
    term *= lambda / j;
    s += term;
  }
  return s;
}

// --- special functions ------------------------------------------------------

test("logGamma matches factorials and Γ(1/2) = √π", () => {
  let fact = 1;
  for (let n = 1; n <= 20; n++) {
    close(logGamma(n), Math.log(fact), 1e-10, `n=${n}`);
    fact *= n;
  }
  close(logGamma(0.5), 0.5 * Math.log(Math.PI), 1e-12);
  close(logGamma(0.1), 2.252712651734206, 1e-12);
  close(logGamma(100), 359.1342053695754, 1e-9);
  assert.throws(() => logGamma(0), RangeError);
  assert.throws(() => logGamma(-1), RangeError);
});

test("regularizedBeta equals the binomial upper tail I_p(k, n-k+1) = P(X >= k)", () => {
  for (const n of [1, 2, 5, 10, 30, 100]) {
    for (let k = 1; k <= n; k += Math.max(1, Math.floor(n / 7))) {
      for (const p of [0.001, 0.05, 0.3, 0.5, 0.77, 0.99]) {
        close(regularizedBeta(p, k, n - k + 1), binomTail(k, n, p), 1e-10, `n=${n} k=${k} p=${p}`);
      }
    }
  }
});

test("regularizedBeta: bounds, symmetry and closed forms", () => {
  assert.equal(regularizedBeta(0, 2, 3), 0);
  assert.equal(regularizedBeta(-1, 2, 3), 0);
  assert.equal(regularizedBeta(1, 2, 3), 1);
  assert.equal(regularizedBeta(2, 2, 3), 1);
  for (const x of [0.01, 0.2, 0.5, 0.9]) {
    close(regularizedBeta(x, 3.5, 1.2), 1 - regularizedBeta(1 - x, 1.2, 3.5), 1e-12);
    close(regularizedBeta(x, 1, 1), x, 1e-12); // uniform
    close(regularizedBeta(x, 7, 1), x ** 7, 1e-12);
  }
  close(regularizedBeta(0.5, 500, 500), 0.5, 1e-10);
  assert.throws(() => regularizedBeta(0.5, 0, 1), RangeError);
  assert.throws(() => regularizedBeta(0.5, 1, -2), RangeError);
  assert.throws(() => regularizedBeta(Number.NaN, 1, 1), RangeError);
});

test("betaInv inverts regularizedBeta", () => {
  for (const [a, b] of [
    [1, 1],
    [0.5, 0.5],
    [3, 9],
    [30, 1],
    [200, 50],
  ] as const) {
    for (const p of [1e-6, 0.025, 0.1, 0.5, 0.9, 0.975]) {
      const x = betaInv(p, a, b);
      close(regularizedBeta(x, a, b), p, 1e-9, `a=${a} b=${b} p=${p}`);
    }
  }
  assert.equal(betaInv(0, 2, 2), 0);
  assert.equal(betaInv(1, 2, 2), 1);
  assert.throws(() => betaInv(1.1, 2, 2), RangeError);
  assert.throws(() => betaInv(Number.NaN, 2, 2), RangeError);
});

test("regularizedGammaP matches the Poisson CDF: P(X <= k; λ) = 1 - P(k+1, λ)", () => {
  for (const k of [0, 1, 3, 10, 50]) {
    for (const lambda of [0.01, 0.5, 2.3, 7, 40, 80]) {
      close(1 - regularizedGammaP(k + 1, lambda), poissonCdf(k, lambda), 1e-10, `k=${k} λ=${lambda}`);
    }
  }
  assert.equal(regularizedGammaP(2, 0), 0);
  assert.equal(regularizedGammaP(2, Number.POSITIVE_INFINITY), 1);
  assert.throws(() => regularizedGammaP(0, 1), RangeError);
});

// --- Clopper–Pearson --------------------------------------------------------

test("clopperPearson: known values", () => {
  const ci = clopperPearson(8, 10, 0.95);
  close(ci.lower, 0.4439045, 1e-6);
  close(ci.upper, 0.9747893, 1e-6);
  const big = clopperPearson(500, 1000, 0.95);
  close(big.lower, 0.4685492, 1e-6);
  close(big.upper, 0.5314508, 1e-6);
  close(big.lower + big.upper, 1, 1e-9); // symmetric at k = n/2
});

test("clopperPearson: endpoints and closed forms", () => {
  for (const n of [1, 5, 10, 37]) {
    const zero = clopperPearson(0, n, 0.95);
    assert.equal(zero.lower, 0);
    close(zero.upper, 1 - 0.025 ** (1 / n), 1e-9);
    const all = clopperPearson(n, n, 0.95);
    assert.equal(all.upper, 1);
    close(all.lower, 0.025 ** (1 / n), 1e-9);
  }
  assert.deepEqual(clopperPearson(0, 0, 0.95), { lower: 0, upper: 1 });
});

test("clopperPearson: bounds are exact tail quantiles", () => {
  for (const [k, n] of [
    [1, 4],
    [7, 20],
    [29, 30],
  ] as const) {
    const { lower, upper } = clopperPearson(k, n, 0.9);
    close(binomTail(k, n, lower), 0.05, 1e-8, "P(X >= k | lower)");
    close(1 - binomTail(k + 1, n, upper), 0.05, 1e-8, "P(X <= k | upper)");
  }
});

test("clopperPearson: monotone in k, narrows with n, nested in confidence", () => {
  let prev = clopperPearson(0, 20, 0.95);
  for (let k = 1; k <= 20; k++) {
    const cur = clopperPearson(k, 20, 0.95);
    assert.ok(cur.lower > prev.lower && cur.upper >= prev.upper);
    assert.ok(cur.lower <= k / 20 && k / 20 <= cur.upper);
    prev = cur;
  }
  const small = clopperPearson(5, 10, 0.95);
  const large = clopperPearson(50, 100, 0.95);
  assert.ok(large.upper - large.lower < small.upper - small.lower);
  const c90 = clopperPearson(5, 10, 0.9);
  assert.ok(c90.lower > small.lower && c90.upper < small.upper);
});

test("clopperPearsonOneSided: known values and relation to two-sided", () => {
  close(clopperPearsonOneSided(30, 30, 0.9).lower, 0.1 ** (1 / 30), 1e-9);
  close(clopperPearsonOneSided(30, 30, 0.9).lower, 0.9261187, 1e-6);
  assert.equal(clopperPearsonOneSided(30, 30, 0.9).upper, 1);
  close(clopperPearsonOneSided(0, 30, 0.9).upper, 1 - 0.1 ** (1 / 30), 1e-9);
  assert.equal(clopperPearsonOneSided(0, 30, 0.9).lower, 0);
  // One-sided at c is the two-sided interval at 2c - 1.
  for (const [k, n] of [
    [3, 10],
    [24, 30],
    [0, 5],
    [5, 5],
  ] as const) {
    const one = clopperPearsonOneSided(k, n, 0.9);
    const two = clopperPearson(k, n, 0.8);
    close(one.lower, two.lower, 1e-12);
    close(one.upper, two.upper, 1e-12);
  }
  // 28 of 30 does not clear a 0.8 lower bound at 90%; 30 of 30 does.
  assert.ok(clopperPearsonOneSided(26, 30, 0.9).lower < 0.8);
  assert.ok(clopperPearsonOneSided(30, 30, 0.9).lower > 0.8);
  assert.deepEqual(clopperPearsonOneSided(0, 0, 0.9), { lower: 0, upper: 1 });
});

test("clopperPearson rejects invalid inputs", () => {
  for (const f of [clopperPearson, clopperPearsonOneSided]) {
    assert.throws(() => f(11, 10, 0.95), RangeError);
    assert.throws(() => f(-1, 10, 0.95), RangeError);
    assert.throws(() => f(1.5, 10, 0.95), RangeError);
    assert.throws(() => f(1, 10.5, 0.95), RangeError);
    assert.throws(() => f(1, -1, 0.95), RangeError);
    assert.throws(() => f(1, 10, 0), RangeError);
    assert.throws(() => f(1, 10, 1), RangeError);
    assert.throws(() => f(1, 10, Number.NaN), RangeError);
    assert.throws(() => f(Number.NaN, 10, 0.9), RangeError);
  }
});

// --- Poisson ----------------------------------------------------------------

test("poissonUpper: known values", () => {
  close(poissonUpper(0, 0.9), 2.302585, 1e-6);
  close(poissonUpper(0, 0.95), 2.995732, 1e-6);
  close(poissonUpper(0, 0.9), Math.log(10), 1e-9);
  close(poissonUpper(1, 0.9), 3.889720, 1e-6);
  close(poissonUpper(2, 0.95), 6.295794, 1e-6);
  close(poissonUpper(5, 0.95), 10.513035, 1e-6);
});

test("poissonUpper: defining property and monotonicity", () => {
  let prev = 0;
  for (const k of [0, 1, 2, 5, 10, 50, 200]) {
    const u = poissonUpper(k, 0.9);
    close(poissonCdf(k, u), 0.1, 1e-9, `k=${k}`);
    assert.ok(u > prev && u > k);
    prev = u;
  }
  assert.ok(poissonUpper(3, 0.99) > poissonUpper(3, 0.9));
});

test("poissonUpper rejects invalid inputs", () => {
  assert.throws(() => poissonUpper(-1, 0.9), RangeError);
  assert.throws(() => poissonUpper(1.5, 0.9), RangeError);
  assert.throws(() => poissonUpper(Number.NaN, 0.9), RangeError);
  assert.throws(() => poissonUpper(1, 1), RangeError);
  assert.throws(() => poissonUpper(1, 0), RangeError);
});

// --- estimators -------------------------------------------------------------

test("escapeRate: recall and residual", () => {
  const r = escapeRate(10, 2);
  close(r.recall, 0.8, 1e-12);
  close(r.residual, 0.5, 1e-12);
  assert.deepEqual(escapeRate(10, 0), { recall: 1, residual: 0 });
});

test("escapeRate: guards never return an optimistic default", () => {
  const unbounded = { recall: 0, residual: Number.POSITIVE_INFINITY };
  assert.deepEqual(escapeRate(0, 0), unbounded);
  assert.deepEqual(escapeRate(-3, 0), unbounded);
  assert.deepEqual(escapeRate(5, 5), unbounded);
  assert.deepEqual(escapeRate(5, 9), unbounded);
  assert.throws(() => escapeRate(5, -1), RangeError);
  assert.throws(() => escapeRate(Number.NaN, 1), RangeError);
  assert.throws(() => escapeRate(5, Number.POSITIVE_INFINITY), RangeError);
});

test("chao1", () => {
  assert.equal(chao1(10, 4, 2), 14);
  assert.equal(chao1(10, 4, 0), 16); // bias-corrected
  assert.equal(chao1(10, 1, 0), 10);
  assert.equal(chao1(10, 0, 0), 10);
  assert.equal(chao1(0, 0, 3), 0);
  assert.throws(() => chao1(-1, 0, 0), RangeError);
  assert.throws(() => chao1(1, Number.NaN, 0), RangeError);
  assert.throws(() => chao1(1, 0, -2), RangeError);
});

test("calibrationFactor", () => {
  assert.equal(calibrationFactor(2, 1), 1, "over-prediction is floored at 1");
  assert.equal(calibrationFactor(2, 4), 2);
  assert.equal(calibrationFactor(0.5, 1), 2);
  assert.equal(calibrationFactor(0, 0), 1, "no data");
  assert.equal(calibrationFactor(0, 3), 4, "unpredicted escapes");
  assert.throws(() => calibrationFactor(-1, 0), RangeError);
  assert.throws(() => calibrationFactor(1, Number.NaN), RangeError);
});

// --- ledger-derived ---------------------------------------------------------

function emptyState(): CommonsState {
  return {
    project: "p",
    rules: {} as Rules, // risk.ts never reads rules
    adminKeys: [],
    coordinatorKey: "coord",
    publicKeys: new Map(),
    owners: new Map(),
    ownerByKey: new Map(),
    agents: new Map([
      ["A", { keyId: "A", owner: "oa", modelFamily: "claude", harness: "h", active: true }],
      ["R", { keyId: "R", owner: "or", modelFamily: "gpt", harness: "h", active: true }],
    ]),
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

const T0 = "2026-10-01T00:00:00Z";

// A submission by A, reviewed by R with probability p (undefined: no review).
function sub(s: CommonsState, id: string, opts: { planted?: Severity; p?: number; at?: string } = {}): SubmissionState {
  const x: SubmissionState = {
    id,
    author: "A",
    taskId: null,
    baseCommit: "b",
    headCommit: "h",
    changedFiles: [],
    linesChanged: 1,
    submittedSeq: 1,
    submittedAt: opts.at ?? "2026-10-05T00:00:00Z",
    gates: [],
    reviews:
      opts.p === undefined
        ? []
        : [
            {
              reviewer: "R",
              commitment: "c",
              stake: 1,
              committedSeq: 2,
              verdict: { defectProbability: opts.p, summary: "", findingIds: [] },
              revealedSeq: 3,
            },
          ],
    findingIds: [],
  };
  if (opts.planted) x.planted = { severity: opts.planted, description: "d" };
  s.submissions.set(id, x);
  return x;
}

function plants(s: CommonsState, caught: number, missed: number): void {
  for (let i = 0; i < caught; i++) sub(s, `c${i}`, { planted: "high", p: 0.9 });
  for (let i = 0; i < missed; i++) sub(s, `m${i}`, { planted: "high", p: 0.1 });
}

function escape(s: CommonsState, findingId: string, severity: Severity, at = "2026-10-10T00:00:00Z"): void {
  s.findings.set(findingId, {
    id: findingId,
    finder: "R",
    target: { snapshotId: "snap" },
    severity,
    testPath: "t",
    testCommand: "c",
    stake: 1,
    seq: 50,
    at,
    result: { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d", seq: 51 },
  });
  s.escapes.push({ findingId, snapshotId: "snap", seq: 52, at });
}

function promoted(s: CommonsState, id: string, submissionIds: string[], at: string | null = "2026-10-08T00:00:00Z"): void {
  s.snapshots.set(id, {
    id,
    commit: "c",
    previousSnapshotId: null,
    submissionIds,
    seq: 40,
    at: "2026-10-07T00:00:00Z",
    attestations: [],
    signoffs: [],
    ...(at === null ? {} : { promoted: { seq: 41, at } }),
  });
}

test("seededRecall: no seeds is uninformative", () => {
  const s = emptyState();
  sub(s, "real", { p: 0.9 });
  assert.deepEqual(seededRecall(s, T0), { seeds: 0, caught: 0, lower90: 0, upper90: 1 });
});

test("seededRecall: 30 of 30 caught gives 0.1^(1/30)", () => {
  const s = emptyState();
  plants(s, 30, 0);
  const r = seededRecall(s, T0);
  assert.equal(r.seeds, 30);
  assert.equal(r.caught, 30);
  close(r.lower90, 0.9261187, 1e-6);
  assert.equal(r.upper90, 1);
});

test("seededRecall: window, mixed results and bounds", () => {
  const s = emptyState();
  plants(s, 24, 6);
  sub(s, "old", { planted: "high", p: 0.1, at: "2026-09-01T00:00:00Z" });
  sub(s, "real", { p: 0.1 }); // not a plant
  const r = seededRecall(s, T0);
  assert.equal(r.seeds, 30);
  assert.equal(r.caught, 24);
  const cp = clopperPearsonOneSided(24, 30, 0.9);
  close(r.lower90, cp.lower, 1e-12);
  close(r.upper90, cp.upper, 1e-12);
  assert.ok(r.lower90 < 0.8 && 0.8 < r.upper90);
  assert.throws(() => seededRecall(s, "not-a-date"), RangeError);
});

test("seededRecall: self-caught plants do not raise recall (gaming)", () => {
  const s = emptyState();
  const p = sub(s, "p", { planted: "critical" });
  p.reviews.push({
    reviewer: "A",
    commitment: "c",
    stake: 1,
    committedSeq: 2,
    verdict: { defectProbability: 1, summary: "", findingIds: [] },
  });
  assert.equal(seededRecall(s, T0).caught, 0);
});

test("criticalUpperBound90: Infinity without seeds", () => {
  const s = emptyState();
  escape(s, "e1", "critical");
  assert.equal(criticalUpperBound90(s, T0), Number.POSITIVE_INFINITY);
});

test("criticalUpperBound90: zero escapes still gives a positive bound", () => {
  const s = emptyState();
  plants(s, 30, 0);
  const r = 0.1 ** (1 / 30);
  const expected = (Math.log(10) * (1 - r)) / r;
  close(criticalUpperBound90(s, T0), expected, 1e-6);
  assert.ok(expected > 0.18 && expected < 0.19);
});

test("criticalUpperBound90: counts critical escapes in the window only", () => {
  const s = emptyState();
  plants(s, 30, 0);
  const r = 0.1 ** (1 / 30);
  escape(s, "crit", "critical");
  escape(s, "crit-old", "critical", "2026-09-01T00:00:00Z");
  escape(s, "crit-dup", "critical");
  s.escapes.push({ findingId: "crit", snapshotId: "snap", seq: 60, at: "2026-10-11T00:00:00Z" }); // replayed escape
  s.escapes.push({ findingId: "ghost", snapshotId: "snap", seq: 61, at: "2026-10-11T00:00:00Z" }); // no finding
  // two distinct critical escapes; nothing predicted, two actual (>= medium) → calibration 3
  const expected = ((poissonUpper(2, 0.9) * (1 - r)) / r) * 3;
  close(criticalUpperBound90(s, T0), expected, 1e-6);
  assert.equal(actualEscapes(s, T0), 2);
});

test("criticalUpperBound90: non-critical escapes move only the calibration", () => {
  const s = emptyState();
  plants(s, 30, 0);
  const r = 0.1 ** (1 / 30);
  sub(s, "shipped1", { p: 0.25 });
  sub(s, "shipped2", { p: 0.25 });
  promoted(s, "snap", ["shipped1", "shipped2"]);
  escape(s, "lo", "low"); // below medium: not a predicted outcome
  assert.equal(actualEscapes(s, T0), 0);
  close(criticalUpperBound90(s, T0), (Math.log(10) * (1 - r)) / r, 1e-9);
  escape(s, "hi1", "high");
  escape(s, "hi2", "high");
  // predicted 0.5, actual 2 → factor 4
  close(predictedEscapes(s, T0), 0.5, 1e-12);
  close(criticalUpperBound90(s, T0), ((Math.log(10) * (1 - r)) / r) * 4, 1e-9);
});

test("criticalUpperBound90: zero recall is enormous but finite", () => {
  const s = emptyState();
  plants(s, 0, 5);
  const b = criticalUpperBound90(s, T0);
  assert.ok(Number.isFinite(b) && b > 1e9);
});

test("criticalUpperBound90 grows as recall falls", () => {
  const hi = emptyState();
  plants(hi, 30, 0);
  const lo = emptyState();
  plants(lo, 25, 5);
  assert.ok(criticalUpperBound90(lo, T0) > criticalUpperBound90(hi, T0));
});

test("predictedEscapes: only promoted, non-plant, revealed predictions, each submission once", () => {
  const s = emptyState();
  sub(s, "a", { p: 0.2 });
  const b = sub(s, "b", { p: 0.4 });
  b.reviews.push({
    reviewer: "X",
    commitment: "c",
    stake: 1,
    committedSeq: 2,
    verdict: { defectProbability: 0.8, summary: "", findingIds: [] },
  });
  b.reviews.push({ reviewer: "Y", commitment: "c", stake: 1, committedSeq: 2 }); // unrevealed
  sub(s, "unreviewed");
  sub(s, "plant", { planted: "high", p: 0.9 });
  sub(s, "unshipped", { p: 0.9 });
  promoted(s, "s1", ["a", "b", "unreviewed", "plant", "missing"]);
  promoted(s, "s2", ["a"]); // listed twice
  promoted(s, "draft", ["unshipped"], null); // never promoted
  promoted(s, "old", ["unshipped"], "2026-09-01T00:00:00Z"); // promoted before the window
  close(predictedEscapes(s, T0), 0.2 + 0.6, 1e-12);
});
