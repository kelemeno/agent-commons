import { test } from "node:test";
import assert from "node:assert/strict";
import { defaultRules, globToRegExp, validateRules } from "../src/rules";
import type { Ring, Rules } from "../src/types";

// First matching glob wins; unmatched is ring 1 (the contract in types.ts).
function ringOf(path: string, rules: Rules): Ring {
  return rules.rings.find((r) => globToRegExp(r.glob).test(path))?.ring ?? 1;
}

function withRules(edit: (r: Rules) => void): string[] {
  const r = defaultRules();
  edit(r);
  return validateRules(r);
}

function rejects(edit: (r: Rules) => void, pattern: RegExp) {
  const problems = withRules(edit);
  assert.ok(
    problems.some((p) => pattern.test(p)),
    `expected a problem matching ${pattern}, got ${JSON.stringify(problems)}`,
  );
}

test("defaultRules is valid and carries the design values", () => {
  const r = defaultRules();
  assert.deepEqual(validateRules(r), []);
  assert.equal(r.version, 1);
  assert.equal(r.maxLinesPerSubmission, 400);
  assert.equal(r.minTreeDistance, 2);
  assert.equal(r.assignedReviewers, 3);
  assert.equal(r.requireOtherModelFamily, true);
  assert.equal(r.plantRate, 0.15);
  assert.deepEqual(r.stake, { base: 10, exponent: 1.5, ringMultiplier: [4, 1.5, 1], review: 5, finding: 5 });
  assert.deepEqual(r.rewards.bounty, { low: 5, medium: 15, high: 40, critical: 100 });
  assert.deepEqual(r.rewards.stageMultiplier, { dev: 1, release: 2, main: 4 });
  assert.equal(r.rewards.missedPlantPenalty, 6);
  assert.equal(r.rewards.honeytokenPenalty, 50);
  assert.equal(r.vesting.tailDays, 30);
  assert.equal(r.reviewsPerSubmitCredit, 2);
  assert.equal(r.promotion.kernelSignoffs, 2);
  assert.equal(r.promotion.minRecallLowerBound90, 0.8);
  assert.deepEqual(r.kernelSigners, []);
});

test("defaultRules returns a fresh object each call", () => {
  const a = defaultRules();
  a.rings.push({ glob: "x", ring: 0 });
  a.rewards.bounty.low = 999;
  const b = defaultRules();
  assert.notEqual(b.rewards.bounty.low, 999);
  assert.ok(!b.rings.some((r) => r.glob === "x"));
});

test("default rings classify the Anthill monorepo", () => {
  const r = defaultRules();
  const cases: [string, Ring][] = [
    ["anthill-backend/src/engine.ts", 0],
    ["anthill-backend/src/auth.ts", 0],
    ["anthill-backend/src/store.ts", 0],
    ["anthill-backend/src/offchain.ts", 0],
    ["anthill-backend/src/offchainVotes.ts", 0],
    ["anthill-contracts/src/Anthill.sol", 0],
    ["anthill-contracts/src/lib/Tree.sol", 0],
    ["anthill-commons/src/ledger.ts", 0],
    [".github/workflows/ci.yml", 0],
    ["anthill-backend/Dockerfile", 0],
    ["Dockerfile", 0],
    ["anthill-backend/render.yaml", 0],
    ["docker-compose.yml", 0],
    ["anthill-frontend/src/App.tsx", 2],
    ["anthill-backend/src/routes.ts", 1],
    ["anthill-backend/src/engine.test.ts", 1],
    ["anthill-backend/src/sub/engine.ts", 1],
    ["anthill-contracts/test/Anthill.t.sol", 1],
    ["README.md", 1],
  ];
  for (const [path, ring] of cases) assert.equal(ringOf(path, r), ring, path);
});

test("default locked paths cover lockfiles and manifests", () => {
  const locked = defaultRules().lockedPaths.map(globToRegExp);
  const isLocked = (p: string) => locked.some((re) => re.test(p));
  for (const p of [
    "package.json",
    "anthill-backend/package.json",
    "package-lock.json",
    "anthill-frontend/yarn.lock",
    "a/b/pnpm-lock.yaml",
    "anthill-contracts/foundry.toml",
    ".gitmodules",
  ]) {
    assert.ok(isLocked(p), p);
  }
  for (const p of ["anthill-backend/src/package.ts", "sub/.gitmodules", "package.json.bak"]) assert.ok(!isLocked(p), p);
});

test("globToRegExp: ** spans segments, * and ? stay within one", () => {
  const m = (glob: string, path: string) => globToRegExp(glob).test(path);
  assert.ok(m("a/**", "a/b/c.ts"));
  assert.ok(!m("a/**", "b/a/c.ts"));
  assert.ok(m("**/x.ts", "x.ts"), "**/ also matches at the root");
  assert.ok(m("**/x.ts", "a/b/x.ts"));
  assert.ok(!m("**/x.ts", "a/bx.ts"));
  assert.ok(m("a/**/b", "a/b"));
  assert.ok(m("a/**/b", "a/x/y/b"));
  assert.ok(!m("a/**/b", "a/xb"));
  assert.ok(m("a/*.ts", "a/b.ts"));
  assert.ok(!m("a/*.ts", "a/b/c.ts"));
  assert.ok(m("a/?.ts", "a/b.ts"));
  assert.ok(!m("a/?.ts", "a/bc.ts"));
  assert.ok(!m("a/?", "a//"));
  assert.ok(m("a/**.ts", "a/b/c.ts"), "** not a whole segment still spans '/'");
});

test("globToRegExp treats regex metacharacters literally and anchors", () => {
  const m = (glob: string, path: string) => globToRegExp(glob).test(path);
  assert.ok(m(".github/**", ".github/x"));
  assert.ok(!m(".github/**", "xgithub/x"));
  assert.ok(m("a+(b)[c]{d}$^|.ts", "a+(b)[c]{d}$^|.ts"));
  assert.ok(!m("a.ts", "aXts"));
  assert.ok(!m("a.ts", "src/a.ts"), "anchored at the start");
  assert.ok(!m("a.ts", "a.tsx"), "anchored at the end");
});

test("globToRegExp rejects globs that cannot name repo-relative paths", () => {
  for (const bad of ["", "/abs/path", "a\\b", "a/***", "a//b", "a/"]) {
    assert.throws(() => globToRegExp(bad), Error, JSON.stringify(bad));
  }
});

test("validateRules: stage multipliers must be >= 1 and non-decreasing", () => {
  rejects((r) => (r.rewards.stageMultiplier.dev = 0.5), /stageMultiplier values must be >= 1/);
  rejects((r) => (r.rewards.stageMultiplier.main = 1.5), /non-decreasing/);
  rejects((r) => (r.rewards.stageMultiplier.release = 0.9), /stageMultiplier/);
  assert.deepEqual(
    withRules((r) => (r.rewards.stageMultiplier = { dev: 1, release: 1, main: 1 })),
    [],
  );
});

test("validateRules: missedPlantPenalty must exceed cleanReview", () => {
  rejects((r) => (r.rewards.missedPlantPenalty = r.rewards.cleanReview), /missedPlantPenalty must exceed/);
  rejects((r) => (r.rewards.cleanReview = 10), /missedPlantPenalty must exceed/);
});

test("validateRules: duplicateDecay in (0, 1]", () => {
  rejects((r) => (r.rewards.duplicateDecay = 0), /duplicateDecay/);
  rejects((r) => (r.rewards.duplicateDecay = 1.01), /duplicateDecay/);
  assert.deepEqual(withRules((r) => (r.rewards.duplicateDecay = 1)), []);
});

test("validateRules: plantRate in [0, 0.5]", () => {
  rejects((r) => (r.plantRate = 0.51), /plantRate/);
  rejects((r) => (r.plantRate = -0.1), /plantRate/);
  assert.deepEqual(withRules((r) => (r.plantRate = 0.5)), []);
  assert.deepEqual(withRules((r) => (r.plantRate = 0)), []);
});

test("validateRules: counts", () => {
  rejects((r) => (r.assignedReviewers = 0), /assignedReviewers/);
  rejects((r) => (r.assignedReviewers = 2.5), /assignedReviewers/);
  rejects((r) => (r.minTreeDistance = -1), /minTreeDistance/);
  assert.deepEqual(withRules((r) => (r.minTreeDistance = 0)), []);
  rejects((r) => (r.version = 0), /version/);
  rejects((r) => (r.reviewsPerSubmitCredit = 0), /reviewsPerSubmitCredit/);
});

test("validateRules: kernelSignoffs cannot exceed a non-empty kernelSigners list", () => {
  rejects((r) => (r.kernelSigners = ["alice"]), /kernelSignoffs exceeds/);
  assert.deepEqual(withRules((r) => (r.kernelSigners = ["alice", "bob"])), []);
  assert.deepEqual(withRules((r) => (r.kernelSigners = [])), [], "an empty list disables the check");
  rejects((r) => (r.kernelSigners = ["alice", "alice", "bob"]), /duplicates/);
  rejects((r) => (r.kernelSigners = ["", "bob"]), /kernelSigners\[0\]/);
});

test("validateRules: every glob must compile", () => {
  rejects((r) => r.rings.push({ glob: "/abs", ring: 0 }), /rings\[\d+\]\.glob/);
  rejects((r) => r.lockedPaths.push("a//b"), /lockedPaths\[\d+\]/);
  rejects((r) => r.rings.push({ glob: "x", ring: 3 as Ring }), /ring must be 0, 1 or 2/);
});

test("validateRules: all numbers finite and non-negative", () => {
  rejects((r) => (r.stake.base = Number.NaN), /stake\.base/);
  rejects((r) => (r.rewards.merge = Number.POSITIVE_INFINITY), /rewards\.merge/);
  rejects((r) => (r.rewards.bounty.critical = -1), /bounty\.critical/);
  rejects((r) => (r.stake.ringMultiplier = [1, -1, 1]), /ringMultiplier\[1\]/);
  rejects((r) => (r.stake.ringMultiplier = [1, 1] as unknown as [number, number, number]), /3 entries/);
  rejects((r) => (r.vesting.tailDays = -5), /tailDays/);
});

test("validateRules: fractions at most 1", () => {
  rejects((r) => (r.rewards.proposerCutFraction = 1.5), /proposerCutFraction/);
  rejects((r) => (r.rewards.inviterShare = 2), /inviterShare/);
  rejects((r) => (r.promotion.minRecallLowerBound90 = 1.1), /minRecallLowerBound90/);
});

test("validateRules survives malformed input from a ledger line", () => {
  const cast = (v: unknown) => v as Rules;
  assert.ok(validateRules(cast(null)).length > 0);
  assert.ok(validateRules(cast("rules")).length > 0);
  assert.ok(validateRules(cast({})).length > 0);
  rejects((r) => delete (r as Partial<Rules>).rewards, /rules\.rewards is missing/);
  rejects((r) => ((r as unknown as Record<string, unknown>).extra = 1), /extra is not a known field/);
  rejects((r) => ((r as unknown as { requireOtherModelFamily: unknown }).requireOtherModelFamily = "yes"), /boolean/);
  rejects((r) => ((r as unknown as { rings: unknown }).rings = "a/**"), /rings must be an array/);
  rejects((r) => ((r as unknown as { stake: unknown }).stake = 5), /stake must be an object/);
  rejects((r) => ((r as unknown as { rings: unknown[] }).rings = [null]), /rings\[0\] must be an object/);
  rejects((r) => ((r.rings[0] as unknown as Record<string, unknown>).extra = 1), /exactly the fields/);
});
