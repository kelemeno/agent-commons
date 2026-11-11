// Rules: the versioned thresholds every other module reads. Changed only by a
// rulesChange ledger entry, and only to something validateRules accepts.

import type { Ring, Rules } from "./types";

export function defaultRules(): Rules {
  return {
    version: 1,
    // First match wins, so the specific kernel paths come before the broad UI
    // glob. Kernel is whatever decides who may act or what runs: reputation
    // maths, auth (auth.ts, and http.ts, whose requireAdmin guards the admin
    // endpoints), the composition root that wires routes, CORS and env
    // (App.ts), the log, the contracts and what compiles into them, the commons
    // and its config, and every build, CI, deploy and shell-script file.
    rings: [
      { glob: "anthill-backend/src/engine.ts", ring: 0 },
      { glob: "anthill-backend/src/auth.ts", ring: 0 },
      { glob: "anthill-backend/src/http.ts", ring: 0 },
      { glob: "anthill-backend/src/App.ts", ring: 0 },
      { glob: "anthill-backend/src/store.ts", ring: 0 },
      { glob: "anthill-backend/src/offchain*.ts", ring: 0 },
      { glob: "anthill-contracts/src/**", ring: 0 },
      { glob: "anthill-contracts/lib/**", ring: 0 },
      { glob: "anthill-contracts/remappings.txt", ring: 0 },
      // A bare submodule pointer could hide any change inside the submodule.
      { glob: "anthill-backend", ring: 0 },
      { glob: "anthill-contracts", ring: 0 },
      { glob: "anthill-frontend", ring: 0 },
      { glob: "anthill-commons/**", ring: 0 },
      { glob: ".commons/**", ring: 0 },
      { glob: ".github/**", ring: 0 },
      { glob: "**/Dockerfile*", ring: 0 },
      { glob: "**/Procfile", ring: 0 },
      { glob: "**/*.yml", ring: 0 },
      { glob: "**/*.yaml", ring: 0 },
      { glob: "**/tsconfig*.json", ring: 0 },
      { glob: "**/*.sh", ring: 0 },
      { glob: "anthill-frontend/vite.config.*", ring: 0 },
      { glob: "anthill-frontend/index.html", ring: 0 },
      { glob: "anthill-frontend/**", ring: 2 },
    ],
    // Registry and toolchain overrides (.npmrc, .yarnrc, .nvmrc) change what
    // gets installed as surely as a lockfile does.
    lockedPaths: [
      "**/package.json",
      "**/package-lock.json",
      "**/yarn.lock",
      "**/pnpm-lock.yaml",
      "**/foundry.toml",
      "**/.npmrc",
      "**/.yarnrc",
      "**/.yarnrc.yml",
      "**/.nvmrc",
      ".gitmodules",
    ],
    maxLinesPerSubmission: 400,
    minTreeDistance: 2,
    assignedReviewers: 3,
    requireOtherModelFamily: true,
    plantRate: 0.15,
    stake: { base: 10, exponent: 1.5, ringMultiplier: [4, 1.5, 1], review: 5, finding: 5 },
    rewards: {
      merge: 30,
      proposerCutFraction: 0.1,
      bounty: { low: 5, medium: 15, high: 40, critical: 100 },
      stageMultiplier: { dev: 1, release: 2, main: 4 },
      cleanReview: 2,
      missedPlantPenalty: 6,
      falseFindingPenalty: 5,
      duplicateDecay: 0.9,
      inviterShare: 0.25,
      honeytokenPenalty: 50,
    },
    vesting: { tailDays: 30 },
    reviewsPerSubmitCredit: 2,
    promotion: {
      minModelFamilies: 3,
      minDistinctOwners: 2,
      recallWindowDays: 28,
      minSeeds: 30,
      minRecallLowerBound90: 0.8,
      maxCriticalUpperBound90: 0.1,
      soakFloorHours: 72,
      kernelSignoffs: 2,
    },
    kernelSigners: [],
  };
}

// Ring of one repo-relative path: the first matching glob wins, unmatched is 1.
export function ringOf(path: string, rules: Rules): Ring {
  return rules.rings.find((r) => globToRegExp(r.glob).test(path))?.ring ?? 1;
}

// The stake a claim must lock (docs/protocol.md §5.3): superlinear in the
// task's size estimate, scaled by its ring. Lives here, beside the numbers it
// reads, so the ledger (which enforces it as a floor) and the coordinator's
// policy compute the same value.
export function claimStake(lines: number, ring: Ring, rules: Rules): number {
  const { base, exponent, ringMultiplier } = rules.stake;
  return Math.ceil(base * Math.pow(Math.max(lines, 1) / 100, exponent) * ringMultiplier[ring]);
}

// Returns every problem found; empty means valid. Rules arrive from ledger
// lines, so this must not assume the value really has the Rules shape: it
// first checks the shape against defaultRules() (same keys, same leaf types,
// every number finite and >= 0) and only then the relations between values.
export function validateRules(rules: Rules): string[] {
  const problems: string[] = [];
  checkShape(rules, defaultRules(), "rules", problems);
  if (problems.length > 0) return problems;
  const r = rules;

  r.rings.forEach((entry, i) => {
    const at = `rules.rings[${i}]`;
    if (!isPlainObject(entry)) {
      problems.push(`${at} must be an object`);
      return;
    }
    const keys = Object.keys(entry).filter((k) => (entry as Record<string, unknown>)[k] !== undefined);
    if (keys.length !== 2 || !keys.includes("glob") || !keys.includes("ring")) {
      problems.push(`${at} must have exactly the fields glob and ring`);
    }
    checkGlob(entry.glob, `${at}.glob`, problems);
    if (entry.ring !== 0 && entry.ring !== 1 && entry.ring !== 2) problems.push(`${at}.ring must be 0, 1 or 2`);
  });
  r.lockedPaths.forEach((glob, i) => checkGlob(glob, `rules.lockedPaths[${i}]`, problems));
  if (r.stake.ringMultiplier.length !== 3) problems.push("rules.stake.ringMultiplier must have 3 entries");
  r.stake.ringMultiplier.forEach((m, i) => {
    if (!isNonNegative(m)) problems.push(`rules.stake.ringMultiplier[${i}] must be a finite number >= 0`);
  });
  const signers = new Set<string>();
  r.kernelSigners.forEach((s, i) => {
    if (typeof s !== "string" || s === "") problems.push(`rules.kernelSigners[${i}] must be a non-empty string`);
    else if (signers.has(s)) problems.push(`rules.kernelSigners[${i}] duplicates ${s}`);
    else signers.add(s);
  });

  const integers: [string, number, number][] = [
    ["version", r.version, 1],
    ["maxLinesPerSubmission", r.maxLinesPerSubmission, 1],
    ["minTreeDistance", r.minTreeDistance, 0],
    ["assignedReviewers", r.assignedReviewers, 1],
    ["reviewsPerSubmitCredit", r.reviewsPerSubmitCredit, 1],
    ["promotion.minModelFamilies", r.promotion.minModelFamilies, 0],
    ["promotion.minDistinctOwners", r.promotion.minDistinctOwners, 0],
    ["promotion.minSeeds", r.promotion.minSeeds, 0],
    ["promotion.kernelSignoffs", r.promotion.kernelSignoffs, 0],
  ];
  for (const [name, value, min] of integers) {
    if (!Number.isInteger(value) || value < min) problems.push(`rules.${name} must be an integer >= ${min}`);
  }

  const fractions: [string, number][] = [
    ["rewards.proposerCutFraction", r.rewards.proposerCutFraction],
    ["rewards.inviterShare", r.rewards.inviterShare],
    ["promotion.minRecallLowerBound90", r.promotion.minRecallLowerBound90],
    ["promotion.maxCriticalUpperBound90", r.promotion.maxCriticalUpperBound90],
  ];
  for (const [name, value] of fractions) {
    if (value > 1) problems.push(`rules.${name} must be <= 1`);
  }

  if (r.plantRate > 0.5) problems.push("rules.plantRate must be between 0 and 0.5");
  if (!(r.rewards.duplicateDecay > 0 && r.rewards.duplicateDecay <= 1)) {
    problems.push("rules.rewards.duplicateDecay must be in (0, 1]");
  }
  // A reviewer who waves a plant through must lose more than a clean review
  // earns, or approving everything blindly is the winning strategy.
  if (!(r.rewards.missedPlantPenalty > r.rewards.cleanReview)) {
    problems.push("rules.rewards.missedPlantPenalty must exceed rules.rewards.cleanReview");
  }
  // The author's slash is the bounty times the stage multiplier; a multiplier
  // below 1 would let a defect cost its author less than its finder earns, and
  // a later stage must never be cheaper than an earlier one.
  const { dev, release, main } = r.rewards.stageMultiplier;
  if (dev < 1 || release < 1 || main < 1) problems.push("rules.rewards.stageMultiplier values must be >= 1");
  if (!(dev <= release && release <= main)) {
    problems.push("rules.rewards.stageMultiplier must be non-decreasing: dev <= release <= main");
  }
  if (r.kernelSigners.length > 0 && r.promotion.kernelSignoffs > r.kernelSigners.length) {
    problems.push("rules.promotion.kernelSignoffs exceeds the number of kernelSigners");
  }
  return problems;
}

// Structural comparison with the template. Arrays only get a type check here;
// their elements are checked by the caller, which knows what they hold.
function checkShape(value: unknown, template: unknown, path: string, problems: string[]): void {
  if (Array.isArray(template)) {
    if (!Array.isArray(value)) problems.push(`${path} must be an array`);
    return;
  }
  if (typeof template === "number") {
    if (!isNonNegative(value)) problems.push(`${path} must be a finite number >= 0`);
    return;
  }
  if (typeof template === "boolean") {
    if (typeof value !== "boolean") problems.push(`${path} must be a boolean`);
    return;
  }
  if (!isPlainObject(value)) {
    problems.push(`${path} must be an object`);
    return;
  }
  // Own properties only: `key in tmpl` would also find Object.prototype names
  // (constructor, valueOf, ...) and let them through as known fields.
  const tmpl = template as Record<string, unknown>;
  for (const key of Object.keys(tmpl)) {
    if (!Object.hasOwn(value, key) || value[key] === undefined) problems.push(`${path}.${key} is missing`);
    else checkShape(value[key], tmpl[key], `${path}.${key}`, problems);
  }
  for (const key of Object.keys(value)) {
    if (!Object.hasOwn(tmpl, key) && value[key] !== undefined) problems.push(`${path}.${key} is not a known field`);
  }
}

function checkGlob(glob: unknown, path: string, problems: string[]): void {
  if (typeof glob !== "string") {
    problems.push(`${path} must be a string`);
    return;
  }
  try {
    globToRegExp(glob);
  } catch (e) {
    problems.push(`${path}: ${(e as Error).message}`);
  }
}

function isNonNegative(v: unknown): v is number {
  return typeof v === "number" && Number.isFinite(v) && v >= 0;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Globs over POSIX repo-relative paths. `**` spans any number of segments
// (including none when written as a whole segment, so `**/x` matches `x` and
// `a/**/b` matches `a/b`), `*` stays within one segment, `?` is one non-'/'
// character, everything else is literal. The match is anchored at both ends.
// Globs that cannot mean a repo-relative path throw, so a typo in rules is
// caught by validateRules instead of silently matching nothing.
export function globToRegExp(glob: string): RegExp {
  if (glob === "") throw new Error("empty glob");
  if (glob.startsWith("/")) throw new Error(`glob must be repo-relative: ${glob}`);
  if (glob.includes("\\")) throw new Error(`glob must use '/' separators: ${glob}`);
  if (glob.includes("***")) throw new Error(`ambiguous '***' in glob: ${glob}`);
  if (glob.split("/").includes("")) throw new Error(`empty path segment in glob: ${glob}`);

  let re = "";
  let i = 0;
  while (i < glob.length) {
    const c = glob[i] as string;
    if (c === "*" && glob[i + 1] === "*") {
      const atSegmentStart = i === 0 || glob[i - 1] === "/";
      const atSegmentEnd = i + 2 === glob.length || glob[i + 2] === "/";
      if (atSegmentStart && atSegmentEnd && glob[i + 2] === "/") {
        re += "(?:.*/)?"; // `**/` : zero or more whole segments
        i += 3;
      } else {
        re += ".*";
        i += 2;
      }
    } else if (c === "*") {
      re += "[^/]*";
      i += 1;
    } else if (c === "?") {
      re += "[^/]";
      i += 1;
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      i += 1;
    }
  }
  return new RegExp(`^${re}$`);
}
