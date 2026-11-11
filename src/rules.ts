// Rules: the versioned thresholds every other module reads. Changed only by a
// rulesChange ledger entry, and only to something validateRules accepts.

import type { Ring, Rules } from "./types";

// The starting closed list of model families. "other" is for a model no entry
// names; it is still one family, so two "other" agents do not satisfy
// requireOtherModelFamily against each other.
export const DEFAULT_MODEL_FAMILIES: readonly string[] = [
  "claude",
  "gpt",
  "gemini",
  "qwen",
  "deepseek",
  "kimi",
  "glm",
  "llama",
  "mistral",
  "other",
];

// A family name: lowercase, at most 64 characters (the ledger's name limit).
const FAMILY_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

// Generic starting values for any target repository, for a group with
// strangers in it: minTreeDistance 2 needs real social distance in the member
// tree, which a group whose owners were all added with no inviter (every pair
// at distance 2) does not have, so a small trusted group starts from
// phase1Rules().
//
// The rings name no project's paths. Each target project declares its own
// kernel (auth, the ledger or state store, reputation maths, whatever decides
// who may act) in its .commons/rules.json (rulesChange, or init --rules).
// The first matching glob wins, so the project's ring-0 globs may go anywhere
// in the list, but its ring-2 (UI) globs go after these: placed first,
// `web/**` would take web/vite.config.ts or web/build.sh out of ring 0.
//
// What is ring 0 here is ring 0 in every repository: the commons config, and
// everything that decides what runs or how a checkout is written:
// - CI and git hooks (.github/**, Jenkinsfile, .husky/**, any YAML);
// - build entry points (Makefiles, Dockerfiles and Containerfiles, CMake,
//   Gradle and Maven files, build.rs, setup.py, Rakefile, shell, PowerShell
//   and batch scripts) and deploy configs (Procfile, netlify.toml,
//   vercel.json, fly.toml, wrangler.toml);
// - compiler, bundler and test-runner config (tsconfig/jsconfig, vite,
//   webpack, rollup, esbuild, babel, next, nuxt, svelte, astro, postcss,
//   tailwind, jest, vitest, playwright) and import remappings
//   (remappings.txt): aliases there redirect imports, which the ring gate
//   does not follow;
// - index.html, the bundler's entry: it decides which scripts load;
// - .gitattributes (working-tree-encoding, filters and eol rewrite every
//   checkout, while gates and reviewers read raw blobs) and gyp files (npm
//   runs a root binding.gyp as `node-gyp rebuild` on install, and gyp's
//   `<!(cmd)` runs shell).
// A submodule pointer is expanded into the submodule's files (cli.ts
// diffTrees); one that cannot be expanded makes the change ring 0 whatever
// the rules say. Everything else is ring 1. Globs have no brace syntax, so
// each family is listed on its own.
export function defaultRules(): Rules {
  return {
    version: 1,
    rings: [
      { glob: ".commons/**", ring: 0 },
      { glob: ".github/**", ring: 0 },
      { glob: ".husky/**", ring: 0 },
      { glob: "**/Jenkinsfile", ring: 0 },
      { glob: "**/*.yml", ring: 0 },
      { glob: "**/*.yaml", ring: 0 },
      { glob: "**/Makefile", ring: 0 },
      { glob: "**/GNUmakefile", ring: 0 },
      { glob: "**/*.mk", ring: 0 },
      { glob: "**/Dockerfile*", ring: 0 },
      { glob: "**/Containerfile*", ring: 0 },
      { glob: "**/CMakeLists.txt", ring: 0 },
      { glob: "**/*.cmake", ring: 0 },
      { glob: "**/build.gradle*", ring: 0 },
      { glob: "**/settings.gradle*", ring: 0 },
      { glob: "**/gradlew*", ring: 0 },
      { glob: "**/pom.xml", ring: 0 },
      { glob: "**/build.rs", ring: 0 },
      { glob: "**/setup.py", ring: 0 },
      { glob: "**/Rakefile", ring: 0 },
      { glob: "**/*.sh", ring: 0 },
      { glob: "**/*.ps1", ring: 0 },
      { glob: "**/*.bat", ring: 0 },
      { glob: "**/*.cmd", ring: 0 },
      { glob: "**/Procfile", ring: 0 },
      { glob: "**/netlify.toml", ring: 0 },
      { glob: "**/vercel.json", ring: 0 },
      { glob: "**/fly.toml", ring: 0 },
      { glob: "**/wrangler.toml", ring: 0 },
      { glob: "**/tsconfig*.json", ring: 0 },
      { glob: "**/jsconfig*.json", ring: 0 },
      { glob: "**/vite.config.*", ring: 0 },
      { glob: "**/webpack.config.*", ring: 0 },
      { glob: "**/rollup.config.*", ring: 0 },
      { glob: "**/esbuild.config.*", ring: 0 },
      { glob: "**/babel.config.*", ring: 0 },
      { glob: "**/next.config.*", ring: 0 },
      { glob: "**/nuxt.config.*", ring: 0 },
      { glob: "**/svelte.config.*", ring: 0 },
      { glob: "**/astro.config.*", ring: 0 },
      { glob: "**/postcss.config.*", ring: 0 },
      { glob: "**/tailwind.config.*", ring: 0 },
      { glob: "**/jest.config.*", ring: 0 },
      { glob: "**/vitest.config.*", ring: 0 },
      { glob: "**/playwright.config.*", ring: 0 },
      { glob: "**/.babelrc*", ring: 0 },
      { glob: "**/remappings.txt", ring: 0 },
      { glob: "**/index.html", ring: 0 },
      { glob: "**/.gitattributes", ring: 0 },
      { glob: "**/*.gyp", ring: 0 },
      { glob: "**/*.gypi", ring: 0 },
    ],
    // What the package manager installs or runs at install: manifests and
    // lockfiles (JS and the common other ecosystems), registry and toolchain
    // overrides (.npmrc, .yarnrc, .nvmrc), and the code the manager itself
    // executes (.pnpmfile.cjs; .yarn/** holds the yarnPath release and
    // plugins; .pnp.* is yarn's resolver).
    lockedPaths: [
      "**/package.json",
      "**/package-lock.json",
      "**/npm-shrinkwrap.json",
      "**/yarn.lock",
      "**/pnpm-lock.yaml",
      "**/pnpm-workspace.yaml",
      "**/bun.lock",
      "**/bun.lockb",
      "**/deno.lock",
      "**/.pnpmfile.cjs",
      ".yarn/**",
      "**/.pnp.*",
      "**/foundry.toml",
      "**/Cargo.toml",
      "**/Cargo.lock",
      "**/go.mod",
      "**/go.sum",
      "**/pyproject.toml",
      "**/poetry.lock",
      "**/uv.lock",
      "**/requirements*.txt",
      "**/Pipfile",
      "**/Pipfile.lock",
      "**/Gemfile",
      "**/Gemfile.lock",
      "**/.npmrc",
      "**/.yarnrc",
      "**/.yarnrc.yml",
      "**/.nvmrc",
      "**/.node-version",
      "**/.tool-versions",
      "**/*.gyp",
      "**/*.gypi",
      ".gitmodules",
    ],
    maxLinesPerSubmission: 400,
    minTreeDistance: 2,
    assignedReviewers: 3,
    requireOtherModelFamily: true,
    modelFamilies: [...DEFAULT_MODEL_FAMILIES],
    plantRate: 0.15,
    stake: { base: 10, exponent: 1.5, ringMultiplier: [4, 1.5, 1], review: 5, finding: 5, allowance: 100 },
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
    review: { commitHours: 12 },
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

// The Phase 1 preset: 3-10 trusted people, admitted by the admin's ownerKey
// entries (the allowlist), and simple round numbers that are not tuned (do
// not tune them until there are real participants). It keeps `base`'s rings,
// locked paths and model families, so phase1Rules(projectRules) is a
// project's Phase 1 set; defaultRules() stays the values for a group with
// strangers.
//
// - minTreeDistance 1: owners added with no inviter are all at distance 2
//   in the member tree (it has no social distance information yet), so with
//   the default 2 nobody would be eligible to review or earn a bounty. With
//   1, everyone but the author's own owner (and the author's inviter and
//   invitees) is eligible, and the draw is uniform among them: owners in
//   another invite line all hold the full weight however deep they sit
//   (selection.ts), so an invitee does not outweigh an owner admitted with
//   no inviter.
// - assignedReviewers 2: three people leave at most two non-authors.
// - reviewsPerSubmitCredit 1: reviewers work from assignments, so a passing
//   submission earns at most assignedReviewers credits. At 2 that is one
//   credit for the one it cost, so the group's credits could never grow, and
//   every submission that failed a gate (no assignment, no reviews) would
//   burn one for good until nobody could submit. At 1 each reviewed
//   submission adds a credit.
// - requireOtherModelFamily stays true: independence between models is the
//   one diversity a small trusted group can still buy.
// - kernelSignoffs 1: one human signs off kernel changes. kernelSigners must
//   still be named (init --kernel-signer), or nothing touching ring 0 is promoted.
//
// - Phase 1 promotes (protocol §5.11): vesting.tailDays is 7, so the second
//   and third merge tranches and clean-review rewards settle within weeks
//   of a promotion, not months. stake.allowance covers the largest claim the
//   rules allow (a ring-0 task at maxLinesPerSubmission) plus ten review
//   stakes of headroom (370), so no task is out of reach before anyone has
//   earned reputation, and one pending review, open finding or small slash
//   does not put it out of reach either. While holding that claim an owner
//   can still back the review seats the draw gives it.
//
// Phase 1 recall bounds are wide. promotion.minSeeds is 10: from ten revealed
// plants, all ten caught, the one-sided 90% lower bound on recall is only
// 0.79, and nine of ten gives 0.66. With minRecallLowerBound90 0.7 and
// maxCriticalUpperBound90 1 (the most validateRules allows), every plant must
// be caught until 12 seeds; from 12 on, one miss passes (11 of 12 gives 0.71,
// and a critical bound of 0.93). They say "almost no plant has slipped
// through", not "recall is measured". Plants are drawn at rate 0.2 and
// counted over 56 days so that ten of them can accrue in a small group.
export function phase1Rules(base: Rules = defaultRules()): Rules {
  const r = structuredClone(base);
  r.minTreeDistance = 1;
  r.assignedReviewers = 2;
  r.reviewsPerSubmitCredit = 1;
  r.requireOtherModelFamily = true;
  r.plantRate = 0.2;
  r.stake = { ...r.stake, base: 10, review: 5, finding: 5, allowance: 100 };
  r.stake.allowance = Math.max(100, claimStake(r.maxLinesPerSubmission, 0, r) + 10 * r.stake.review);
  r.vesting = { tailDays: 7 };
  r.rewards = {
    ...r.rewards,
    merge: 30,
    proposerCutFraction: 0.1,
    bounty: { low: 5, medium: 10, high: 20, critical: 50 },
    stageMultiplier: { dev: 1, release: 2, main: 4 },
    cleanReview: 2,
    missedPlantPenalty: 5,
    falseFindingPenalty: 5,
    honeytokenPenalty: 50,
  };
  r.promotion = {
    ...r.promotion,
    minModelFamilies: 2,
    minDistinctOwners: 2,
    recallWindowDays: 56,
    minSeeds: 10,
    minRecallLowerBound90: 0.7,
    maxCriticalUpperBound90: 1,
    soakFloorHours: 24,
    kernelSignoffs: 1,
  };
  return r;
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

  if (r.modelFamilies.length === 0) problems.push("rules.modelFamilies must not be empty");
  const families = new Set<string>();
  r.modelFamilies.forEach((f, i) => {
    if (typeof f !== "string" || !FAMILY_RE.test(f)) {
      problems.push(`rules.modelFamilies[${i}] must be a lowercase name matching ${FAMILY_RE.source}`);
    } else if (families.has(f)) problems.push(`rules.modelFamilies[${i}] duplicates ${f}`);
    else families.add(f);
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
