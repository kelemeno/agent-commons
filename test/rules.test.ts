import { test } from "node:test";
import assert from "node:assert/strict";
import { ringOf } from "../src/gates/rings";
import { clopperPearsonOneSided, poissonUpper } from "../src/risk";
import { claimStake, defaultRules, globToRegExp, phase1Rules, validateRules } from "../src/rules";
import type { Ring, Rules } from "../src/types";

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
  assert.deepEqual(r.stake, { base: 10, exponent: 1.5, ringMultiplier: [4, 1.5, 1], review: 5, finding: 5, allowance: 100 });
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

test("default rings are generic: config, CI, build and checkout-writing files are ring 0, the rest ring 1", () => {
  const r = defaultRules();
  const cases: [string, Ring][] = [
    [".commons/rules.json", 0],
    [".github/workflows/ci.yml", 0],
    [".github/CODEOWNERS", 0],
    ["binding.gyp", 0], // npm runs it on install
    ["server/binding.gyp", 0],
    ["server/src/common.gypi", 0],
    [".gitattributes", 0], // rewrites every checkout's bytes
    ["web/.gitattributes", 0],
    ["Dockerfile", 0],
    ["server/Dockerfile", 0],
    ["server/render.yaml", 0],
    ["docker-compose.yml", 0],
    // No project's kernel is built in: a target declares its own.
    ["server/src/auth.ts", 1],
    ["server/src/engine.ts", 1],
    ["web/src/App.tsx", 1],
    ["src/ledger.ts", 1],
    ["README.md", 1],
  ];
  for (const [path, ring] of cases) assert.equal(ringOf(path, r), ring, path);
  assert.ok(!r.rings.some((g) => g.ring === 2), "no default UI ring: that is project-specific too");
});

test("a target project's own kernel globs (anywhere) and UI globs (after the defaults) take effect", () => {
  const base = defaultRules();
  const r: Rules = { ...base, rings: [{ glob: "server/src/auth.ts", ring: 0 }, ...base.rings, { glob: "web/**", ring: 2 }] };
  assert.deepEqual(validateRules(r), []);
  assert.equal(ringOf("server/src/auth.ts", r), 0);
  assert.equal(ringOf("web/src/App.tsx", r), 2);
  assert.equal(ringOf("server/src/routes.ts", r), 1);
  // Generic kernel files under the UI stay ring 0 because the UI glob comes last.
  for (const p of ["web/vite.config.ts", "web/tsconfig.json", "web/scripts/build.sh", "web/index.html"]) assert.equal(ringOf(p, r), 0, p);
  // Placed first, the UI glob would take them out of ring 0: the order matters.
  const uiFirst: Rules = { ...base, rings: [{ glob: "web/**", ring: 2 }, ...base.rings] };
  assert.equal(ringOf("web/vite.config.ts", uiFirst), 2);
});

test("default locked paths cover lockfiles and manifests", () => {
  const locked = defaultRules().lockedPaths.map(globToRegExp);
  const isLocked = (p: string) => locked.some((re) => re.test(p));
  for (const p of [
    "package.json",
    "server/package.json",
    "package-lock.json",
    "web/yarn.lock",
    "a/b/pnpm-lock.yaml",
    "contracts/foundry.toml",
    ".gitmodules",
    // What the package manager runs or pins at install.
    ".pnpmfile.cjs",
    ".yarn/releases/yarn-4.1.0.cjs",
    ".yarn/plugins/plugin.cjs",
    ".pnp.cjs",
    ".pnp.loader.mjs",
    "bun.lock",
    "web/bun.lockb",
    "deno.lock",
    "npm-shrinkwrap.json",
    "pnpm-workspace.yaml",
    // Other ecosystems' manifests and lockfiles.
    "Cargo.toml",
    "crates/x/Cargo.lock",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile.lock",
    "Gemfile",
    "Gemfile.lock",
  ]) {
    assert.ok(isLocked(p), p);
  }
  for (const p of ["server/src/package.ts", "sub/.gitmodules", "package.json.bak"]) assert.ok(!isLocked(p), p);
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

test("validateRules: modelFamilies is a non-empty closed list of distinct lowercase names", () => {
  assert.deepEqual(defaultRules().modelFamilies, ["claude", "gpt", "gemini", "qwen", "deepseek", "kimi", "glm", "llama", "mistral", "other"]);
  rejects((r) => (r.modelFamilies = []), /modelFamilies must not be empty/);
  rejects((r) => (r.modelFamilies = ["claude", "Claude"]), /modelFamilies\[1\] must be a lowercase name/);
  rejects((r) => (r.modelFamilies = ["claude", "claude"]), /modelFamilies\[1\] duplicates claude/);
  rejects((r) => (r.modelFamilies = ["claude", " gpt"]), /modelFamilies\[1\]/);
  rejects((r) => (r.modelFamilies = ["x".repeat(65)]), /modelFamilies\[0\]/);
  rejects((r) => (r.modelFamilies = [3 as unknown as string]), /modelFamilies\[0\]/);
  rejects((r) => delete (r as Partial<Rules>).modelFamilies, /modelFamilies is missing/);
  assert.deepEqual(withRules((r) => (r.modelFamilies = ["claude", "grok-2", "other"])), []);
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

test("ringOf: first matching glob wins, unmatched is ring 1", () => {
  const r: Rules = { ...defaultRules(), rings: [{ glob: "a/**", ring: 2 }, { glob: "a/k.ts", ring: 0 }] };
  assert.equal(ringOf("a/k.ts", r), 2);
  assert.equal(ringOf("b.ts", r), 1);
});

test("claimStake: the protocol formula, superlinear in lines and scaled by ring", () => {
  const r = defaultRules();
  assert.equal(claimStake(100, 1, r), 15);
  assert.equal(claimStake(400, 0, r), 320);
  assert.equal(claimStake(50, 1, r), 6);
  assert.equal(claimStake(0, 2, r), 1, "max(lines, 1) keeps a zero-line task priced");
  assert.ok(claimStake(200, 1, r) > 2 * claimStake(100, 1, r));
});

// Regression: these decide what runs or how a checkout is written, so they are kernel.
test("default rings put build, deploy and toolchain config in ring 0", () => {
  const r = defaultRules();
  for (const p of [
    "server/Procfile",
    "Procfile",
    "Makefile",
    "server/Makefile",
    "Jenkinsfile",
    "server/tsconfig.json",
    "web/tsconfig.app.json",
    "server/scripts/backupLog.sh",
    "server/docker-compose.yml",
    "web/.github-like/ci.yaml",
    "server/Dockerfile.prod",
    "web/vite.config.ts",
    ".commons/rules.json",
    // Bundler, compiler and test-runner config: aliases redirect imports.
    "webpack.config.js",
    "rollup.config.mjs",
    "esbuild.config.mjs",
    "babel.config.js",
    "web/.babelrc",
    ".babelrc.json",
    "next.config.js",
    "nuxt.config.ts",
    "svelte.config.js",
    "astro.config.mjs",
    "postcss.config.cjs",
    "tailwind.config.ts",
    "jest.config.js",
    "vitest.config.ts",
    "playwright.config.ts",
    "web/jsconfig.json",
    "contracts/remappings.txt",
    // The HTML entry decides which scripts load.
    "index.html",
    "web/index.html",
    // Build entry points.
    "GNUmakefile",
    "build/rules.mk",
    "Containerfile",
    "server/Containerfile.dev",
    "CMakeLists.txt",
    "cmake/deps.cmake",
    "build.gradle",
    "app/build.gradle.kts",
    "settings.gradle.kts",
    "gradlew",
    "gradlew.bat",
    "pom.xml",
    "build.rs",
    "setup.py",
    "Rakefile",
    "scripts/deploy.ps1",
    "scripts/build.bat",
    "scripts/build.cmd",
    // Git hooks and deploy configs.
    ".husky/pre-commit",
    "netlify.toml",
    "web/vercel.json",
    "fly.toml",
    "wrangler.toml",
  ]) {
    assert.equal(ringOf(p, r), 0, p);
  }
  // Ordinary code and app config stay ring 1.
  for (const p of ["src/config.ts", "web/src/site.ts", "docs/guide.md", "src/build.ts"]) assert.equal(ringOf(p, r), 1, p);
  assert.equal(ringOf("server/scripts/diffEngine.ts", r), 1);
  assert.equal(ringOf("web/src/main.tsx", r), 1);
});

test("default locked paths cover registry and toolchain overrides", () => {
  const locked = defaultRules().lockedPaths.map(globToRegExp);
  for (const p of [".npmrc", "server/.npmrc", "web/.yarnrc.yml", ".yarnrc", "server/.nvmrc"]) {
    assert.ok(locked.some((re) => re.test(p)), p);
  }
});

// Regression: `key in template` let Object.prototype names through as fields.
test("validateRules: Object.prototype names are not known fields", () => {
  for (const name of ["constructor", "valueOf", "toString", "hasOwnProperty"]) {
    rejects((r) => ((r as unknown as Record<string, unknown>)[name] = "x"), new RegExp(`${name} is not a known field`));
    rejects((r) => ((r.stake as unknown as Record<string, unknown>)[name] = 1), new RegExp(`stake\\.${name} is not a known field`));
  }
  const proto = JSON.parse(JSON.stringify(defaultRules()).replace(/^\{/, '{"__proto__":{"x":1},')) as Rules;
  assert.ok(validateRules(proto).some((p) => /__proto__ is not a known field/.test(p)));
});

test("phase1Rules: the Phase 1 preset is valid and carries its values", () => {
  const r = phase1Rules();
  assert.deepEqual(validateRules(r), []);
  assert.equal(r.minTreeDistance, 1, "owners admitted with no inviter are all at distance 2");
  assert.equal(r.assignedReviewers, 2);
  assert.equal(r.requireOtherModelFamily, true);
  assert.equal(r.promotion.kernelSignoffs, 1);
  assert.equal(r.promotion.minSeeds, 10);
  // The allowance covers the largest claim the rules allow (a ring-0 task at
  // maxLinesPerSubmission), or that task could not be claimed before anyone
  // earned reputation, with headroom: a pending review commit, an open
  // finding or a small slash must not put that task out of reach, and the
  // claim's holder must still be able to back its review seats (regression:
  // the allowance was exactly the largest claim). Phase 1's vesting tail is a
  // week, not a month.
  const largest = claimStake(r.maxLinesPerSubmission, 0, r);
  assert.equal(largest, 320);
  assert.equal(r.stake.allowance, 370);
  assert.ok(r.stake.allowance - largest >= r.assignedReviewers * r.stake.review + r.stake.finding + r.rewards.falseFindingPenalty);
  assert.equal(r.reviewsPerSubmitCredit, 1, "reviewed submissions must add credits, or gate failures freeze the group");
  assert.equal(r.vesting.tailDays, 7);
  assert.equal(r.review.commitHours, 12);
  assert.deepEqual(r.rewards.bounty, { low: 5, medium: 10, high: 20, critical: 50 });
  assert.ok(r.rewards.missedPlantPenalty > r.rewards.cleanReview);
});

test("phase1Rules keeps its base's rings, locked paths and families, and does not mutate it", () => {
  const base = defaultRules();
  base.rings = [{ glob: "server/src/auth.ts", ring: 0 }, ...base.rings];
  base.lockedPaths = [...base.lockedPaths, "vendor/**"];
  base.modelFamilies = ["claude", "gpt", "other"];
  const before = structuredClone(base);
  const r = phase1Rules(base);
  assert.deepEqual(base, before);
  assert.deepEqual(r.rings, base.rings);
  assert.deepEqual(r.lockedPaths, base.lockedPaths);
  assert.deepEqual(r.modelFamilies, base.modelFamilies);
  assert.deepEqual(validateRules(r), []);
  assert.deepEqual(phase1Rules().rings, defaultRules().rings);
});

test("phase1Rules: ten seeds pass recall and the critical bound only if all ten were caught", () => {
  // The same arithmetic as promotion's recall and criticals checks, with no
  // critical escapes and no calibration data (factor 1).
  const p = phase1Rules().promotion;
  const passes = (caught: number, seeds: number) => {
    const r = clopperPearsonOneSided(caught, seeds, 0.9).lower;
    const critical = (poissonUpper(0, 0.9) * (1 - r)) / r;
    return seeds >= p.minSeeds && r >= p.minRecallLowerBound90 && critical < p.maxCriticalUpperBound90;
  };
  assert.equal(passes(10, 10), true);
  assert.equal(passes(9, 10), false, "the bounds are wide: one miss in ten fails");
  assert.equal(passes(9, 9), false, "fewer than minSeeds");
});
