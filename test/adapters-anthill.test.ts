import assert from "node:assert/strict";
import { copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { after, before, describe, test } from "node:test";
import { makeAnthillFixtureLog } from "../scripts/make-anthill-fixture-log";
import {
  addedDeclarations,
  anthillRules,
  anthillTree,
  BACKEND_DIR_ENV,
  behaviourDeltaFor,
  resolveBackendDir,
} from "../src/adapters/anthill";
import { globToRegExp, ringOf, validateRules } from "../src/rules";
import type { Ring, Rules } from "../src/types";


const ANTHILL = join(__dirname, "..", "..");
const BACKEND = join(ANTHILL, "anthill-backend");
const SNAPSHOT = join(BACKEND, "anthillSnapshot.json");
const SNAPSHOT_ROOT = "0x0000000000000000000000000000000000000002";

// TODO: when src/gates/rings.ts (the classifier the CI gate runs) lands, check
// that it agrees with rules.ts ringOf on these paths.
const locked = (path: string, rules: Rules) => rules.lockedPaths.some((g) => globToRegExp(g).test(path));

let root: string;
let dataDir: string; // holds log.jsonl from the fixture generator
let fixture: Awaited<ReturnType<typeof makeAnthillFixtureLog>>;

before(async () => {
  root = mkdtempSync(join(tmpdir(), "adapters-anthill-test-"));
  dataDir = join(root, "data");
  mkdirSync(dataDir);
  fixture = await makeAnthillFixtureLog({ backendDir: BACKEND, outPath: join(dataDir, "log.jsonl") });
});

after(() => rmSync(root, { recursive: true, force: true }));

describe("anthillRules", () => {
  test("is exactly .commons/rules.json, and valid", () => {
    const committed = JSON.parse(readFileSync(join(ANTHILL, ".commons", "rules.json"), "utf8"));
    assert.deepEqual(committed, anthillRules());
    assert.deepEqual(validateRules(anthillRules()), []);
  });

  test("returns a fresh copy each call", () => {
    const r = anthillRules();
    r.rings.push({ glob: "**", ring: 2 });
    r.lockedPaths.length = 0;
    assert.notDeepEqual(anthillRules(), r);
  });

  test("classifies the Anthill monorepo", () => {
    const r = anthillRules();
    const expected: [string, Ring][] = [
      ["anthill-backend/src/engine.ts", 0],
      ["anthill-backend/src/auth.ts", 0],
      ["anthill-backend/src/store.ts", 0],
      ["anthill-backend/src/offchain.ts", 0],
      ["anthill-backend/src/offchainApi.ts", 0],
      // loaded by the kernel, or security and governance in their own right:
      // explain() runs in the replay, requireAdmin, the polls that ratify rules,
      // the server entry point
      ["anthill-backend/src/reasons.ts", 0],
      ["anthill-backend/src/http.ts", 0],
      ["anthill-backend/src/social.ts", 0],
      ["anthill-backend/src/App.ts", 0],
      ["anthill-backend/src/dagBase.ts", 0],
      ["anthill-backend/src/demoStory.ts", 0],
      // a module added later, wherever it is imported from
      ["anthill-backend/src/newHelper.ts", 0],
      ["anthill-backend/src/util/x.ts", 0],
      ["anthill-backend/anthillSnapshot.json", 0],
      ["anthill-backend/tsconfig.json", 0],
      ["anthill-contracts/src/Anthill.sol", 0],
      ["anthill-contracts/src/lib/Dag.sol", 0],
      ["anthill-contracts/lib/forge-std", 0],
      ["anthill-contracts/lib/openzeppelin-contracts/contracts/token/ERC20.sol", 0],
      ["anthill-contracts/remappings.txt", 0],
      [".github/workflows/commons-gates.yml", 0],
      [".github/CODEOWNERS", 0],
      [".commons/rules.json", 0],
      [".commons/behaviour-delta.json", 0],
      ["anthill-commons/src/ledger.ts", 0],
      ["anthill-backend/render.yaml", 0],
      ["anthill-backend/Procfile", 0],
      // where code is fetched from
      [".gitmodules", 0],
      ["anthill-contracts/.gitmodules", 0],
      [".npmrc", 0],
      ["anthill-backend/.npmrc", 0],
      ["anthill-frontend/.npmrc", 0],
      ["anthill-frontend/.yarnrc.yml", 0],
      // unexpanded submodule pointers
      ["anthill-backend", 0],
      ["anthill-contracts", 0],
      ["anthill-frontend", 0],
      ["anthill-frontend/src/App.tsx", 2],
      ["anthill-frontend/src/components/Graph.tsx", 2],
      ["anthill-backend/scripts/diffEngine.ts", 1],
      ["anthill-backend/abi/Anthill.json", 1],
      ["anthill-contracts/test/Anthill.t.sol", 1],
      ["README.md", 1],
      // near misses of kernel globs
      ["anthill-backend/store.ts", 1],
      ["anthill-backend/srcx/engine.ts", 1],
      ["docs/.github/x", 1],
      ["anthill-contracts/library/x.sol", 1],
    ];
    for (const [path, ring] of expected) assert.equal(ringOf(path, r), ring, path);
  });

  // Ring 1 code that a kernel module loads runs inside the kernel's process,
  // and inside the behaviour-delta replay, where it can patch the kernel at
  // load time. So everything the backend's entry points reach must be ring 0.
  test("every module the backend's kernel entry points import is ring 0", () => {
    const src = join(BACKEND, "src");
    const entries = readdirSync(src)
      .filter((f) => /^(engine|store|auth|offchain.*|App)\.ts$/.test(f))
      .map((f) => join(src, f));
    assert.ok(entries.length >= 6, `entry points: ${entries.join(", ")}`);
    const reached = new Set<string>();
    const pending = [...entries];
    for (let file = pending.pop(); file !== undefined; file = pending.pop()) {
      if (reached.has(file)) continue;
      reached.add(file);
      const text = readFileSync(file, "utf8");
      // static and dynamic imports, re-exports and require() of relative paths
      const specifiers = [...text.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)["'](\.{1,2}\/[^"']+)["']/g)];
      for (const [, spec] of specifiers) {
        const base = join(dirname(file), spec as string);
        const found = [base, `${base}.ts`, `${base}.js`, `${base}.json`, join(base, "index.ts")].find(
          (p) => existsSync(p) && statSync(p).isFile(),
        );
        assert.ok(found, `${relative(ANTHILL, file)} imports ${spec}, which does not resolve`);
        pending.push(found);
      }
    }
    assert.ok(reached.has(join(src, "reasons.ts")), "the walk should reach reasons.ts through offchain.ts");
    const r = anthillRules();
    for (const file of reached) {
      const path = relative(ANTHILL, file).split("\\").join("/");
      assert.equal(ringOf(path, r), 0, `${path} is loaded by the kernel but is ring ${ringOf(path, r)}`);
    }
  });

  test("locks what decides which dependencies are installed, and from where", () => {
    const r = anthillRules();
    for (const path of [
      "package.json",
      "package-lock.json",
      "anthill-backend/package.json",
      "anthill-frontend/package-lock.json",
      "anthill-frontend/yarn.lock",
      "anthill-frontend/pnpm-lock.yaml",
      "anthill-backend/npm-shrinkwrap.json",
      "anthill-frontend/bun.lock",
      "anthill-frontend/bun.lockb",
      ".npmrc",
      "anthill-backend/.npmrc",
      "anthill-frontend/.yarnrc.yml",
      ".yarnrc",
      "anthill-contracts/foundry.toml",
      "anthill-contracts/remappings.txt",
      ".gitmodules",
      "anthill-contracts/.gitmodules",
      "anthill-contracts/lib/forge-std",
      "anthill-contracts/lib/forge-std/src/Test.sol",
    ]) {
      assert.ok(locked(path, r), path);
    }
    for (const path of ["anthill-backend/src/store.ts", "anthill-backend/package.json.bak", ".gitmodules.old", "anthill-contracts/src/lib/Dag.sol"]) {
      assert.ok(!locked(path, r), path);
    }
  });
});

describe("resolveBackendDir", () => {
  test("an explicit directory wins over the environment", () => {
    assert.equal(resolveBackendDir(BACKEND, { [BACKEND_DIR_ENV]: join(root, "nope") }), BACKEND);
  });

  test("falls back to ANTHILL_BACKEND_DIR, resolved to an absolute path", () => {
    const relative = join("..", "anthill-backend");
    const env = { [BACKEND_DIR_ENV]: relative };
    const cwd = process.cwd();
    process.chdir(join(ANTHILL, "anthill-commons"));
    try {
      assert.equal(resolveBackendDir(undefined, env), BACKEND);
      assert.equal(resolveBackendDir("", env), BACKEND);
    } finally {
      process.chdir(cwd);
    }
  });

  test("without either, says how to provide one", () => {
    assert.throws(() => resolveBackendDir(undefined, {}), /pass backendDir or set ANTHILL_BACKEND_DIR/);
    assert.throws(() => resolveBackendDir(undefined, { [BACKEND_DIR_ENV]: "" }), /ANTHILL_BACKEND_DIR/);
  });

  test("rejects a directory that is not a backend checkout", () => {
    assert.throws(() => resolveBackendDir(root, {}), /is not an anthill-backend checkout \(no src\/store\.ts\)/);
  });
});

describe("anthillTree", () => {
  // The fixture log carries refused actions on purpose; the backend's replay
  // warns about each one. Expected here, so kept out of the test output.
  const warn = console.warn;
  before(() => {
    console.warn = (...args: unknown[]) => {
      if (typeof args[0] === "string" && args[0].startsWith("replay:")) return;
      warn(...args);
    };
  });
  after(() => {
    console.warn = warn;
  });

  test("from the real anthillSnapshot.json", async () => {
    const tree = await anthillTree({ snapshotPath: SNAPSHOT, community: "demo", env: {} });
    assert.equal(tree.root(), SNAPSHOT_ROOT);
    assert.equal(tree.members().length, 63);
    assert.equal(tree.parent(SNAPSHOT_ROOT), null);
  });

  test("a snapshot is the demo tree only, and is not mixed with a backend", async () => {
    await assert.rejects(anthillTree({ snapshotPath: SNAPSHOT, dataDir, community: "demo" }), /either snapshotPath or backendDir\/dataDir/);
    await assert.rejects(
      anthillTree({ snapshotPath: SNAPSHOT, backendDir: BACKEND, community: "demo" }),
      /either snapshotPath or backendDir\/dataDir/,
    );
    await assert.rejects(
      anthillTree({ snapshotPath: SNAPSHOT, community: "commons" }),
      /a snapshot holds only the demo community, not commons/,
    );
  });

  test("from a live log, with the backend named by the environment", async () => {
    const env = { [BACKEND_DIR_ENV]: BACKEND };
    const demo = await anthillTree({ dataDir, community: "demo", env });
    assert.equal(demo.root(), SNAPSHOT_ROOT);
    // the seed, plus the story's two newcomers, minus the one who leaves
    assert.equal(demo.members().length, 64);
    const commons = await anthillTree({ dataDir, community: "commons", env });
    assert.equal(commons.root(), "0x000000000000000000000000000000000000c0f0");
    assert.equal(commons.members().length, 6);
    const club = await anthillTree({ backendDir: BACKEND, dataDir, community: "fixture-club", env: {} });
    assert.equal(club.members().length, 5);
  });

  test("explains a missing backend, log or community", async () => {
    await assert.rejects(anthillTree({ dataDir, community: "demo", env: {} }), /ANTHILL_BACKEND_DIR/);
    await assert.rejects(
      anthillTree({ backendDir: BACKEND, dataDir: join(root, "empty"), community: "demo", env: {} }),
      /no backend log at/,
    );
    await assert.rejects(
      anthillTree({ backendDir: BACKEND, dataDir, community: "nowhere", env: {} }),
      /no community nowhere in the log \(it has: commons, demo, fixture-club\)/,
    );
  });
});

describe("make-anthill-fixture-log", () => {
  test("covers every action kind and loses nothing", () => {
    assert.deepEqual(fixture.skipped, []);
    assert.deepEqual(fixture.notRefused, []);
    assert.equal(fixture.refused, 14);
    for (const fn of [
      "joinTreeAsRoot",
      "joinTree",
      "changeName",
      "addDagVote",
      "removeDagVote",
      "leaveTree",
      "switchPositionWithParent",
      "moveTreeVote",
    ]) {
      assert.ok((fixture.actions[fn] ?? 0) > 0, fn);
    }
    assert.ok((fixture.actions["demoStory"] ?? 0) > 0);
    const lines = readFileSync(fixture.logPath, "utf8").trim().split("\n");
    assert.equal(lines.length, fixture.entries);
    assert.equal(JSON.parse(lines[0] as string).type, "seed");
  });

  test("refuses to overwrite a log", async () => {
    await assert.rejects(makeAnthillFixtureLog({ backendDir: BACKEND, outPath: fixture.logPath }), /refusing to overwrite/);
  });
});

describe("behaviourDeltaFor", () => {
  let changed: string; // a backend whose reputation maths differs
  before(() => {
    changed = join(root, "changed");
    cpSync(join(BACKEND, "src"), join(changed, "src"), { recursive: true });
    const engine = join(changed, "src", "engine.ts");
    const from = "voterReputation += 10n ** decimalPoint;";
    const text = readFileSync(engine, "utf8");
    assert.ok(text.includes(from), "fixture edit not applicable");
    writeFileSync(engine, text.replace(from, "voterReputation += 2n * 10n ** decimalPoint;"));
  });

  test("the same backend passes with the committed manifest", async () => {
    const r = await behaviourDeltaFor({
      oldBackendDir: BACKEND,
      newBackendDir: BACKEND,
      logPath: fixture.logPath,
      manifestPath: join(ANTHILL, ".commons", "behaviour-delta.json"),
    });
    assert.equal(r.pass, true, r.details);
    assert.match(r.details, /no behaviour change across 3 communities/);
  });

  test("an undeclared change fails; declaring it in the manifest file passes", async () => {
    const opts = { oldBackendDir: BACKEND, newBackendDir: changed, logPath: fixture.logPath };
    const empty = join(root, "empty-manifest.json");
    copyFileSync(join(ANTHILL, ".commons", "behaviour-delta.json"), empty);
    const undeclared = await behaviourDeltaFor({ ...opts, manifestPath: empty });
    assert.equal(undeclared.pass, false);
    assert.deepEqual(undeclared.divergences.map((d) => d.community), ["commons", "demo", "fixture-club"]);

    const declaredPath = join(root, "declared.json");
    const declared = undeclared.divergences.map((d) => ({ community: d.community, fromEntry: d.fromEntry, note: "reputation doubles" }));
    writeFileSync(declaredPath, JSON.stringify({ declared }));
    const r = await behaviourDeltaFor({ ...opts, manifestPath: declaredPath });
    assert.equal(r.pass, true, r.details);
  });

  test("a change that drops a revert fails: the log carries refused actions", async () => {
    const lax = join(root, "lax");
    cpSync(join(BACKEND, "src"), join(lax, "src"), { recursive: true });
    const engine = join(lax, "src", "engine.ts");
    const from = 'check(this.sentTree(voter) !== address0, "A jTAR 5");';
    const text = readFileSync(engine, "utf8");
    assert.ok(text.includes(from), "fixture edit not applicable");
    writeFileSync(engine, text.replace(from, ""));
    const r = await behaviourDeltaFor({
      oldBackendDir: BACKEND,
      newBackendDir: lax,
      logPath: fixture.logPath,
      manifestPath: join(ANTHILL, ".commons", "behaviour-delta.json"),
    });
    assert.equal(r.pass, false, r.details);
    // a non-member renaming themselves: refused in the commons and the demo
    assert.deepEqual(r.divergences.map((d) => d.community), ["commons", "demo"]);
    for (const d of r.divergences) assert.match(d.error ?? "", /the old checkout failed to replay this entry and the new one replays it/);
  });

  test("with a base manifest, only the declarations the change adds count", async () => {
    const opts = { oldBackendDir: BACKEND, newBackendDir: changed, logPath: fixture.logPath };
    const first = await behaviourDeltaFor({ ...opts, manifestPath: join(ANTHILL, ".commons", "behaviour-delta.json") });
    const declared = first.divergences.map((d) => ({ community: d.community, fromEntry: d.fromEntry, note: "reputation doubles" }));
    const headPath = join(root, "head-manifest.json");
    writeFileSync(headPath, JSON.stringify({ declared }));

    // the base already had these declarations: they cover nothing now
    const stale = await behaviourDeltaFor({ ...opts, manifestPath: headPath, baseManifestPath: headPath });
    assert.equal(stale.pass, false, stale.details);
    // the base had none (or no file): all of them are this change's
    const fresh = await behaviourDeltaFor({
      ...opts,
      manifestPath: headPath,
      baseManifestPath: join(ANTHILL, ".commons", "behaviour-delta.json"),
    });
    assert.equal(fresh.pass, true, fresh.details);
    const noBase = await behaviourDeltaFor({ ...opts, manifestPath: headPath, baseManifestPath: join(root, "absent.json") });
    assert.equal(noBase.pass, true, noBase.details);
    // a malformed base cannot be judged against
    const badBase = join(root, "bad-base.json");
    writeFileSync(badBase, "{");
    const bad = await behaviourDeltaFor({ ...opts, manifestPath: headPath, baseManifestPath: badBase });
    assert.equal(bad.pass, false);
    assert.match(bad.details, /^base manifest: cannot read/);
  });

  test("an unreadable or malformed manifest is a failing report, not a throw", async () => {
    const base = { oldBackendDir: BACKEND, newBackendDir: BACKEND, logPath: fixture.logPath };
    const missing = await behaviourDeltaFor({ ...base, manifestPath: join(root, "missing.json") });
    assert.equal(missing.pass, false);
    assert.match(missing.details, /manifest: cannot read/);
    const bad = join(root, "bad.json");
    writeFileSync(bad, JSON.stringify({ declared: [{ community: "demo", fromEntry: 0, note: "" }] }));
    const malformed = await behaviourDeltaFor({ ...base, manifestPath: bad });
    assert.equal(malformed.pass, false);
    assert.match(malformed.details, /note must say why/);
  });
});

describe("addedDeclarations", () => {
  test("drops what the base already declares, by the whole entry", () => {
    const d = (community: string, fromEntry: number, note: string) => ({ community, fromEntry, note });
    const base = { declared: [d("demo", 3, "old change"), d("commons", 9, "x")] };
    const head = { declared: [d("demo", 3, "old change"), d("commons", 9, "x, reworded"), d("demo", 40, "new")] };
    assert.deepEqual(addedDeclarations(base, head), { declared: [d("commons", 9, "x, reworded"), d("demo", 40, "new")] });
    assert.deepEqual(addedDeclarations({ declared: [] }, head), head);
    assert.deepEqual(addedDeclarations(head, head), { declared: [] });
  });
});
