import assert from "node:assert/strict";
import { copyFileSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { makeAnthillFixtureLog } from "../scripts/make-anthill-fixture-log";
import {
  anthillRules,
  anthillTree,
  BACKEND_DIR_ENV,
  behaviourDeltaFor,
  resolveBackendDir,
} from "../src/adapters/anthill";
import { globToRegExp, validateRules } from "../src/rules";
import type { Ring, Rules } from "../src/types";

const ANTHILL = join(__dirname, "..", "..");
const BACKEND = join(ANTHILL, "anthill-backend");
const SNAPSHOT = join(BACKEND, "anthillSnapshot.json");
const SNAPSHOT_ROOT = "0x0000000000000000000000000000000000000002";

// The contract in types.ts: first matching glob wins, unmatched is ring 1.
function ringOf(path: string, rules: Rules): Ring {
  return rules.rings.find((r) => globToRegExp(r.glob).test(path))?.ring ?? 1;
}
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
      ["anthill-contracts/src/Anthill.sol", 0],
      ["anthill-contracts/src/lib/Dag.sol", 0],
      [".github/workflows/commons-gates.yml", 0],
      [".commons/rules.json", 0],
      [".commons/behaviour-delta.json", 0],
      ["anthill-commons/src/ledger.ts", 0],
      ["anthill-backend/render.yaml", 0],
      ["anthill-backend/Procfile", 0],
      // unexpanded submodule pointers
      ["anthill-backend", 0],
      ["anthill-contracts", 0],
      ["anthill-frontend", 0],
      ["anthill-frontend/src/App.tsx", 2],
      ["anthill-frontend/src/components/Graph.tsx", 2],
      ["anthill-backend/src/App.ts", 1],
      ["anthill-backend/src/dagBase.ts", 1],
      ["anthill-backend/src/demoStory.ts", 1],
      ["anthill-backend/scripts/diffEngine.ts", 1],
      ["anthill-contracts/test/Anthill.t.sol", 1],
      ["README.md", 1],
      // near misses of kernel globs
      ["anthill-backend/src/engine.test.ts", 1],
      ["anthill-backend/store.ts", 1],
      ["docs/.github/x", 1],
    ];
    for (const [path, ring] of expected) assert.equal(ringOf(path, r), ring, path);
  });

  test("locks lockfiles, package.json files, .gitmodules and foundry.toml", () => {
    const r = anthillRules();
    for (const path of [
      "package.json",
      "package-lock.json",
      "anthill-backend/package.json",
      "anthill-frontend/package-lock.json",
      "anthill-frontend/yarn.lock",
      "anthill-contracts/foundry.toml",
      ".gitmodules",
    ]) {
      assert.ok(locked(path, r), path);
    }
    for (const path of ["anthill-backend/src/store.ts", "anthill-backend/package.json.bak", ".gitmodules.old"]) {
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
  test("from the real anthillSnapshot.json", async () => {
    const tree = await anthillTree({ snapshotPath: SNAPSHOT, community: "demo", env: {} });
    assert.equal(tree.root(), SNAPSHOT_ROOT);
    assert.equal(tree.members().length, 63);
    assert.equal(tree.parent(SNAPSHOT_ROOT), null);
  });

  test("snapshotPath and dataDir together are ambiguous", async () => {
    await assert.rejects(anthillTree({ snapshotPath: SNAPSHOT, dataDir, community: "demo" }), /either snapshotPath or dataDir/);
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
