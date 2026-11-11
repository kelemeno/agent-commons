import { after, test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { generateKeyPair, keyIdOf } from "../src/crypto";
import { applyEntry, emptyState, signEntry, type LedgerState, type Signer } from "../src/ledger";
import { claimStake, defaultRules, ringOf as rulesRingOf } from "../src/rules";
import {
  BYTES_PER_LINE,
  checkAirlock,
  checkRingImports,
  checkSize,
  checkSpecSeparation,
  checkTaskRing,
  decodeIdentifierEscapes,
  isAcceptancePath,
  normalizeRepoPath,
  ringOf,
  runStaticGates,
  scanImports,
  submissionRing,
} from "../src/gates";
import type { EntryBody, Rules } from "../src/types";

const rules = defaultRules();
const ENGINE = "anthill-backend/src/engine.ts";
const UI = "anthill-frontend/src";

const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gates-test-"));
after(() => fs.rmSync(tmpRoot, { recursive: true, force: true }));
let n = 0;

// A repo directory with the given files; a value starting with "->" is a symlink.
function repo(files: Record<string, string>): string {
  const dir = path.join(tmpRoot, `r${n++}`);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(dir, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    if (content.startsWith("->")) fs.symlinkSync(content.slice(2), abs);
    else fs.writeFileSync(abs, content);
  }
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

const kernel = { [ENGINE]: "export const k = 1;\n", "anthill-backend/src/util.ts": "export const u = 1;\n" };

// One ring-2 file `a.ts` (or `name`) with `source`, beside a kernel; the gate's verdict on it.
function importGate(source: string, name = `${UI}/a.ts`, extra: Record<string, string> = {}) {
  const dir = repo({ ...kernel, [name]: source, ...extra });
  return checkRingImports(dir, [name], rules);
}

function fails(report: { pass: boolean; details: string }, pattern?: RegExp) {
  assert.equal(report.pass, false, `expected a failure, got: ${report.details}`);
  if (pattern) assert.match(report.details, pattern);
}

function passes(report: { pass: boolean; details: string }) {
  assert.equal(report.pass, true, `expected a pass, got: ${report.details}`);
}

// ---------------------------------------------------------------------------
// Paths and rings
// ---------------------------------------------------------------------------

test("normalizeRepoPath: one spelling, unusable paths are null", () => {
  assert.equal(normalizeRepoPath("a/b.ts"), "a/b.ts");
  assert.equal(normalizeRepoPath("./a//b/./c.ts"), "a/b/c.ts");
  assert.equal(normalizeRepoPath("a/b/"), "a/b");
  assert.equal(normalizeRepoPath("anthill-frontend/../anthill-backend/src/engine.ts"), ENGINE);
  for (const bad of ["", ".", "./", "..", "../x", "a/../../x", "/etc/passwd", "/anthill-frontend/a.ts", "a\\b", "a\0b"]) {
    assert.equal(normalizeRepoPath(bad), null, JSON.stringify(bad));
  }
});

test("ringOf: first matching glob on the normalised path, unmatched ring 1, unusable ring 0", () => {
  assert.equal(ringOf(ENGINE, rules), 0);
  assert.equal(ringOf("anthill-frontend/src/App.tsx", rules), 2);
  assert.equal(ringOf("anthill-frontend/vite.config.ts", rules), 0); // listed before the UI glob
  assert.equal(ringOf("anthill-backend/src/routes.ts", rules), 1);
  assert.equal(ringOf("docs/x.md", rules), 1);
  // Normalisation attacks are classified by what they name.
  assert.equal(ringOf("anthill-frontend/../anthill-backend/src/engine.ts", rules), 0);
  assert.equal(ringOf("./anthill-frontend/src/App.tsx", rules), 2);
  assert.equal(ringOf("anthill-frontend//src/../../anthill-commons/src/ledger.ts", rules), 0);
  assert.equal(ringOf("/anthill-frontend/src/App.tsx", rules), 0);
  assert.equal(ringOf("../anthill-frontend/src/App.tsx", rules), 0);
  // Agrees with rules.ts on canonical paths.
  for (const p of [ENGINE, "anthill-frontend/src/x.ts", "README.md", ".github/workflows/ci.yml", "anthill-frontend"]) {
    assert.equal(ringOf(p, rules), rulesRingOf(p, rules), p);
  }
});

test("submissionRing: the lowest ring touched", () => {
  assert.equal(submissionRing([`${UI}/a.ts`, `${UI}/b.tsx`], rules), 2);
  assert.equal(submissionRing([`${UI}/a.ts`, "README.md"], rules), 1);
  assert.equal(submissionRing([`${UI}/a.ts`, "README.md", ENGINE], rules), 0);
  assert.equal(submissionRing([`${UI}/../../anthill-backend/src/engine.ts`], rules), 0);
  assert.equal(submissionRing([`${UI}/a.ts`, "/abs"], rules), 0);
  assert.equal(submissionRing([], rules), 1);
});

// ---------------------------------------------------------------------------
// Ring imports
// ---------------------------------------------------------------------------

test("rings: UI importing UI, ring 1 and packages passes", () => {
  const dir = repo({
    ...kernel,
    [`${UI}/a.ts`]: [
      'import React from "react";',
      'import { b } from "./b";',
      'import * as lib from "../../lib/pure";',
      'export { c } from "./c.js";',
      'import "./styles.css";',
      'const p = import("./pages/Home");',
      'import data from "./data.json" with { type: "json" };',
      'const f = Array.from("abc");',
    ].join("\n"),
    [`${UI}/b.ts`]: "export const b = 1;\n",
    [`${UI}/c.ts`]: "export const c = 1;\n",
    "lib/pure.ts": "export const x = 1;\n",
  });
  const r = checkRingImports(dir, [`${UI}/a.ts`, `${UI}/b.ts`], rules);
  passes(r);
  assert.equal(r.gate, "rings");
  assert.match(r.details, /2 ring-2 code files scanned/);
});

test("rings: relative kernel imports fail, with or without extension", () => {
  for (const spec of [
    "../../anthill-backend/src/engine",
    "../../anthill-backend/src/engine.ts",
    "../../anthill-backend/src/engine.js", // TS ESM style names engine.ts
    "./../../anthill-backend//src/./engine",
    "../../anthill-frontend/../anthill-backend/src/engine",
    "../../anthill-commons/src/ledger",
  ]) {
    fails(importGate(`import { k } from "${spec}";\n`), /ring-0/);
  }
});

test("rings: every import form is seen", () => {
  const E = "../../anthill-backend/src/engine";
  const forms = [
    `import k from "${E}";`,
    `import { k as kk, type T } from '${E}';`,
    `import * as ns from "${E}";`,
    `import "${E}";`,
    `import type { T } from "${E}";`,
    `export * from "${E}";`,
    `export { k } from "${E}";`,
    `export * as eng from "${E}";`,
    `const m = await import("${E}");`,
    `const m = await import('${E}', { with: {} });`,
    "const m = await import(`" + E + "`);",
    `const m = require("${E}");`,
    `import k = require("${E}");`,
    `const w = new Worker(new URL("${E}.ts", import.meta.url));`,
    `import {\n  k,\n  j,\n} from\n  "${E}";`,
  ];
  for (const f of forms) fails(importGate(f + "\n"), /ring-0/);
});

test("rings: lexical obfuscation is seen through", () => {
  const forms = [
    'import/**/k/**/from/**/"../../anthill-backend/src/engine";',
    'import k from /* a long comment, "with quotes" */ "../../anthill-backend/src/engine";',
    'import k from // trailing\n "../../anthill-backend/src/engine";',
    'import k from "\\x2e\\x2e/\\x2e\\x2e/anthill-backend/src/engine";',
    'import k from "\\u002e\\u002e/../anthill-backend/src/engin\\u{65}";',
    'import k from "../../anthill-backend/src/en\\\ngine";', // line continuation
    'const a = "/*"; import k from /* */ "../../anthill-backend/src/engine"; const b = "*/";',
    'if (a) /\'/.test(s); import k from "../../anthill-backend/src/engine"; /\'/',
    'await import /* c */ ( "../../anthill-backend/src/engine" );',
    'import k from "../../anthill-backend/src/engine?raw";',
    "// import k from '../../anthill-backend/src/engine'", // commented out still fails: conservative
  ];
  for (const f of forms) fails(importGate(f + "\n"), /ring-0/);
});

test("rings: computed and absolute specifiers cannot be checked and fail", () => {
  fails(importGate('const m = await import("../../anthill-backend/src/" + "engine");\n'), /computed/);
  fails(importGate("const m = await import(`../../anthill-backend/src/${name}`);\n"), /computed/);
  fails(importGate("const m = require(name);\n"), /computed/);
  fails(importGate('import k from "/anthill-backend/src/engine.ts";\n'), /absolute/);
  fails(importGate('import k from "file:///etc/passwd";\n'), /absolute/);
  fails(importGate('import k from "../../../outside";\n'), /outside the repository/);
  // Not imports: member names and prose without a call.
  passes(importGate('x.import("../../anthill-backend/src/engine"); const from = 1; y.from = 2;\n'));
  passes(importGate("const s = require.resolve; // what is required\n"));
});

test("rings: a missing kernel file still classifies (submodules absent from the checkout)", () => {
  const dir = repo({ [`${UI}/a.ts`]: 'import k from "../../anthill-backend/src/engine";\n' });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /ring-0 anthill-backend\/src\/engine\.ts/);
});

test("rings: index resolution and directory imports", () => {
  const extra = { "anthill-contracts/src/index.ts": "export {};\n" };
  fails(importGate('import c from "../../anthill-contracts/src";\n', undefined, extra), /ring-0/);
  fails(importGate('import c from "../../anthill-contracts/src/";\n', undefined, extra), /ring-0/);
  // A directory that is itself a kernel pointer (the backend submodule).
  fails(importGate('import b from "../../anthill-backend";\n'), /ring-0 anthill-backend/);
});

test("rings: files in other rings are not scanned; declared deletions are skipped", () => {
  const dir = repo({ ...kernel, "lib/x.ts": 'import k from "../anthill-backend/src/engine";\n' });
  const r = checkRingImports(dir, ["lib/x.ts", ENGINE, `${UI}/deleted.ts`], rules, { deleted: [`${UI}/deleted.ts`] });
  passes(r);
  assert.match(r.details, /0 ring-2 code files scanned, 1 deleted/);
  // Non-code UI files (docs, styles) are not parsed.
  passes(importGate('see "../../anthill-backend/src/engine" from "../../anthill-backend/src/engine"\n', `${UI}/notes.md`));
});

test("rings: ring-2 files in .tsx, .vue and .html are scanned", () => {
  fails(importGate('import k from "../../anthill-backend/src/engine";\nexport const A = () => <div/>;\n', `${UI}/A.tsx`));
  fails(importGate('<script setup>\nimport k from "../../anthill-backend/src/engine";\n</script>\n', `${UI}/A.vue`));
  fails(importGate('<script type="module">import "../../anthill-backend/src/engine";</script>\n', `${UI}/page.html`));
});

test("rings: symlinks out of ring 2 fail", () => {
  // The changed file is itself a link to the kernel.
  let dir = repo({ ...kernel, [`${UI}/a.ts`]: "->../../anthill-backend/src/engine.ts" });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /symlink to anthill-backend\/src\/engine\.ts/);
  // ...or to ring 1, or outside the repository, or dangling into the kernel.
  dir = repo({ "lib/x.ts": "export {};\n", [`${UI}/a.ts`]: "->../../lib/x.ts" });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /outside ring 2/);
  dir = repo({ [`${UI}/a.ts`]: "->/etc/hostname" });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /outside the repository/);
  dir = repo({ [`${UI}/a.ts`]: "->../../anthill-backend/src/engine.ts" });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /symlink/);
  // A link within ring 2 is fine.
  dir = repo({ [`${UI}/b.ts`]: "export const b = 1;\n", [`${UI}/a.ts`]: "->b.ts" });
  passes(checkRingImports(dir, [`${UI}/a.ts`], rules));
  // An unchanged ring-2 link to the kernel, imported by a changed file.
  dir = repo({ ...kernel, [`${UI}/link.ts`]: "->../../anthill-backend/src/engine.ts", [`${UI}/a.ts`]: 'import "./link";\n' });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /symlink to ring-0/);
  // A linked directory inside ring 2 that leads into the kernel.
  dir = repo({ ...kernel, [`${UI}/k`]: "->../../anthill-backend/src", [`${UI}/a.ts`]: 'import "./k/engine";\n' });
  fails(checkRingImports(dir, [`${UI}/a.ts`], rules), /symlink to ring-0/);
});

test("rings: import.meta.glob is walked", () => {
  const pages = { [`${UI}/pages/Home.tsx`]: "export default 1;\n", [`${UI}/pages/About.tsx`]: "export default 2;\n" };
  passes(importGate('const pages = import.meta.glob("./pages/*.tsx");\n', undefined, pages));
  passes(importGate('const pages = import.meta.glob(["./pages/*.tsx", "!./pages/Secret.tsx"], { eager: true });\n', undefined, pages));
  fails(importGate('const m = import.meta.glob("../../anthill-backend/src/*.ts");\n'), /outside ring 2/);
  fails(importGate('const m = import.meta.globEager("../../anthill-backend/**");\n'), /outside ring 2/);
  // Ring-0 files inside the UI tree (vite config) are reachable by a broad glob.
  fails(
    importGate('const m = import.meta.glob("../*.ts");\n', undefined, { "anthill-frontend/vite.config.ts": "export {};\n" }),
    /ring-0 anthill-frontend\/vite\.config\.ts/,
  );
  fails(importGate("const m = import.meta.glob(patterns);\n"), /computed/);
  fails(importGate('const m = import.meta.glob("/src/**");\n'), /absolute/);
  fails(importGate('const m = import.meta.glob("./x/*.ts");\n', undefined, { [`${UI}/x/l`]: "->../../../anthill-backend/src" }), /symlink/);
});

test("rings: unusable changed paths fail", () => {
  const dir = repo({});
  fails(checkRingImports(dir, ["/etc/passwd"], rules), /not a path inside the repository/);
  fails(checkRingImports(dir, ["anthill-frontend/../../x.ts"], rules), /not a path inside/);
  // A traversal spelling of a UI file is read as that file.
  const d2 = repo({ ...kernel, [`${UI}/a.ts`]: 'import "../../anthill-backend/src/engine";\n' });
  fails(checkRingImports(d2, [`anthill-backend/../${UI}/./a.ts`], rules), /ring-0/);
});

test("rings: problem lists are capped", () => {
  const src = Array.from({ length: 50 }, (_, i) => `import k${i} from "../../anthill-backend/src/engine";`).join("\n");
  const r = importGate(src);
  fails(r, /; and 30 more$/);
  assert.match(r.details, /a\.ts:1:/);
  assert.match(r.details, /a\.ts:20:/);
});

test("scanImports: linear on adversarial input", () => {
  const big =
    "from /*".repeat(100_000) + "*/" + " ".repeat(500_000) + "/* from /**/ ".repeat(50_000) + "import(`" + "x".repeat(200_000);
  const t = process.hrtime.bigint();
  scanImports(big);
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  assert.ok(ms < 3000, `scan took ${ms} ms`);
});

test("scanImports: reports kinds and specifiers", () => {
  const refs = scanImports('import a from "./a";\nexport * from "./b";\nimport("./c");\nrequire(x);\n');
  assert.deepEqual(
    refs.map((r) => [r.how, r.spec]),
    [
      ["from", "./a"],
      ["from", "./b"],
      ["import()", "./c"],
      ["require()", null],
    ],
  );
});

// ---------------------------------------------------------------------------
// Airlock and size
// ---------------------------------------------------------------------------

test("airlock: locked paths need the dependency track", () => {
  passes(checkAirlock(["src/a.ts", "README.md"], rules, { dependencyTrack: false }));
  const r = checkAirlock(["src/a.ts", "package-lock.json", "anthill-frontend/package.json", ".npmrc"], rules, { dependencyTrack: false });
  fails(r, /package-lock\.json, anthill-frontend\/package\.json, \.npmrc/);
  assert.equal(r.gate, "airlock");
  passes(checkAirlock(["package-lock.json", "anthill-frontend/yarn.lock"], rules, { dependencyTrack: true }));
});

test("airlock: normalisation does not hide a lockfile; unusable paths always fail", () => {
  fails(checkAirlock(["src/../package-lock.json"], rules, { dependencyTrack: false }), /package-lock\.json/);
  fails(checkAirlock(["./anthill-frontend//package.json"], rules, { dependencyTrack: false }), /anthill-frontend\/package\.json/);
  fails(checkAirlock(["../package-lock.json"], rules, { dependencyTrack: true }), /not a path inside/);
  fails(checkAirlock(["/package.json"], rules, { dependencyTrack: true }), /not a path inside/);
  // Look-alikes are not locked.
  passes(checkAirlock(["src/package.json.md", "docs/yarn.lock.txt"], rules, { dependencyTrack: false }));
});

test("size: at most maxLinesPerSubmission; garbage fails", () => {
  passes(checkSize(0, rules));
  passes(checkSize(400, rules));
  fails(checkSize(401, rules), /split/);
  assert.equal(checkSize(1, rules).gate, "size");
  for (const bad of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) fails(checkSize(bad, rules), /not a non-negative integer/);
  passes(checkSize(10, { ...rules, maxLinesPerSubmission: 10 }));
  fails(checkSize(11, { ...rules, maxLinesPerSubmission: 10 }));
});

// ---------------------------------------------------------------------------
// Spec separation: a real ledger built with signed entries
// ---------------------------------------------------------------------------

const AT = (m: number) => new Date(Date.UTC(2026, 0, 1) + m * 60_000).toISOString();

class World {
  admin = generateKeyPair();
  coord = generateKeyPair();
  keys: Record<string, Signer> = {};
  state: LedgerState;
  minute = 0;

  constructor(r: Rules = defaultRules()) {
    this.state = emptyState({ kind: "genesis", project: "anthill", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules: r }, AT(0));
  }
  append(body: EntryBody, signer: Signer) {
    applyEntry(this.state, signEntry(this.state, body, signer, AT(++this.minute)));
  }
  owner(name: string) {
    this.keys[name] = generateKeyPair();
    this.append({ kind: "ownerKey", owner: name, publicKey: (this.keys[name] as Signer).publicKey, inviter: null }, this.admin);
  }
  agent(name: string, owner: string, modelFamily = "claude") {
    this.keys[name] = generateKeyPair();
    const publicKey = (this.keys[name] as Signer).publicKey;
    this.append({ kind: "agentRegistered", owner, publicKey, modelFamily, harness: "test" }, this.keys[owner] as Signer);
  }
  key(name: string): Signer {
    return this.keys[name] as Signer;
  }
  task(id: string, specAuthor: string, acceptanceTestPaths: string[], ring: 0 | 1 | 2 = 1) {
    this.append({ kind: "proposal", id: `p-${id}`, title: id, evidence: [{ kind: "location", file: "src/a.ts", line: 1, note: "n" }] }, this.key("a1"));
    this.append({ kind: "task", id, proposalId: `p-${id}`, ring, acceptanceTestPaths, sizeEstimate: 40, specAuthor }, this.coord);
  }
  submit(id: string, agent: string, taskId: string | null, changedFiles: string[], linesChanged = 10) {
    if (taskId !== null) {
      const task = this.state.tasks.get(taskId);
      const stake = claimStake(task?.sizeEstimate ?? 0, task?.ring ?? 1, this.state.rules);
      this.append({ kind: "claim", taskId, until: AT(this.minute + 600), stake }, this.key(agent));
    }
    this.append({ kind: "submission", id, taskId, baseCommit: "b".repeat(40), headCommit: "c".repeat(40), changedFiles, linesChanged }, this.key(agent));
  }
}

function world(): World {
  const w = new World();
  w.owner("alice");
  w.owner("bob");
  w.agent("a1", "alice");
  w.agent("a2", "alice", "gpt");
  w.agent("b1", "bob");
  return w;
}

test("specSeparation: another owner implementing without touching the tests passes", () => {
  const w = world();
  w.task("t1", "alice", ["test/a.test.ts"]);
  w.submit("s1", "b1", "t1", ["src/a.ts"]);
  const r = checkSpecSeparation(w.state, "s1");
  passes(r);
  assert.equal(r.gate, "specSeparation");
});

test("specSeparation: the spec author's own agents cannot implement the task", () => {
  const w = world();
  w.task("t1", "alice", ["test/a.test.ts"]);
  w.submit("s1", "a2", "t1", ["src/a.ts"]); // a different agent, same owner
  fails(checkSpecSeparation(w.state, "s1"), /alice wrote the spec of task t1/);
});

test("specSeparation: the implementer cannot edit acceptance tests (exact, normalised, glob, directory)", () => {
  const w = world();
  w.task("t1", "alice", ["test/a.test.ts", "test/acceptance/**/*.test.ts", "test/fixtures"]);
  w.submit("s1", "b1", "t1", ["src/a.ts", "test/a.test.ts"]);
  fails(checkSpecSeparation(w.state, "s1"), /changes acceptance tests of task t1: test\/a\.test\.ts/);
  w.submit("s2", "b1", "t1", ["test/acceptance/deep/x.test.ts"]);
  fails(checkSpecSeparation(w.state, "s2"), /test\/acceptance\/deep\/x\.test\.ts/);
  w.submit("s3", "b1", "t1", ["test/fixtures/data.json"]);
  fails(checkSpecSeparation(w.state, "s3"), /test\/fixtures\/data\.json/);
  // Neighbours are not acceptance tests.
  w.submit("s4", "b1", "t1", ["test/b.test.ts", "test/a.test.ts.bak", "test/fixtures2/x"]);
  passes(checkSpecSeparation(w.state, "s4"));
  assert.equal(isAcceptancePath("test/a.test.ts", "test/a.test.ts"), true);
  assert.equal(isAcceptancePath("test/acceptance/x.test.ts", "test/acceptance/**/*.test.ts"), true);
  assert.equal(isAcceptancePath("test/acceptancex/x.test.ts", "test/acceptance"), false);
});

test("specSeparation: a spelling the ledger would refuse is still caught", () => {
  // The ledger refuses non-canonical paths; the gate must not depend on that.
  const w = world();
  w.task("t1", "alice", ["test/a.test.ts"]);
  w.submit("s1", "b1", "t1", ["src/a.ts"]);
  const s = w.state.submissions.get("s1");
  assert.ok(s);
  s.changedFiles = ["src/../test/a.test.ts"];
  fails(checkSpecSeparation(w.state, "s1"), /test\/a\.test\.ts/);
  s.changedFiles = ["../test/a.test.ts"];
  fails(checkSpecSeparation(w.state, "s1"), /not a path inside/);
});

test("specSeparation: no task passes with a note; unknown task or author fails; unknown submission throws", () => {
  const w = world();
  w.submit("s1", "a1", null, ["src/a.ts"]);
  const r = checkSpecSeparation(w.state, "s1");
  passes(r);
  assert.match(r.details, /no task/);
  const s = w.state.submissions.get("s1");
  assert.ok(s);
  s.taskId = "ghost";
  fails(checkSpecSeparation(w.state, "s1"), /task ghost is not in the ledger/);
  w.task("t1", "alice", ["test/a.test.ts"]);
  s.taskId = "t1";
  s.author = keyIdOf(generateKeyPair().publicKey);
  fails(checkSpecSeparation(w.state, "s1"), /has no registered owner/);
  assert.throws(() => checkSpecSeparation(w.state, "nope"), /no submission nope/);
});

// ---------------------------------------------------------------------------
// runStaticGates
// ---------------------------------------------------------------------------

test("runStaticGates: all four reports, in order", () => {
  const w = world();
  w.task("t1", "alice", ["test/a.test.ts"]);
  const dir = repo({
    ...kernel,
    [`${UI}/a.ts`]: 'import { b } from "./b";\n',
    [`${UI}/b.ts`]: "export const b = 1;\n",
    "test/a.test.ts": "export {};\n",
  });
  w.submit("s1", "b1", "t1", [`${UI}/a.ts`], 12);
  const reports = runStaticGates(w.state, "s1", dir, { dependencyTrack: false });
  assert.deepEqual(
    reports.map((r) => [r.gate, r.pass]),
    [
      ["rings", true],
      ["airlock", true],
      ["specSeparation", true],
      ["size", true],
    ],
  );
});

test("runStaticGates: each gate fails on its own problem", () => {
  const w = world();
  w.task("t1", "alice", ["test/a.test.ts"]);
  const dir = repo({ ...kernel, [`${UI}/a.ts`]: 'import { k } from "../../anthill-backend/src/engine";\n' });
  w.submit("s1", "a1", "t1", [`${UI}/a.ts`, "anthill-frontend/package.json", "test/a.test.ts"], 401);
  const reports = runStaticGates(w.state, "s1", dir, { dependencyTrack: false });
  assert.deepEqual(
    reports.map((r) => [r.gate, r.pass]),
    [
      ["rings", false],
      ["airlock", false],
      ["specSeparation", false],
      ["size", false],
    ],
  );
  // The dependency track opens the airlock and nothing else.
  const dep = runStaticGates(w.state, "s1", dir, { dependencyTrack: true });
  assert.deepEqual(dep.map((r) => r.pass), [false, true, false, false]);
});

test("runStaticGates: untasked submission gets a passing spec-separation report", () => {
  const w = world();
  const dir = repo({ "src/a.ts": "export {};\n" });
  w.submit("s1", "a1", null, ["src/a.ts"]);
  const reports = runStaticGates(w.state, "s1", dir, { dependencyTrack: false });
  assert.equal(reports.length, 4);
  assert.ok(reports.every((r) => r.pass));
  assert.match(reports[2]?.details ?? "", /no task/);
});

test("runStaticGates: unknown submission and missing repo are harness errors", () => {
  const w = world();
  assert.throws(() => runStaticGates(w.state, "nope", tmpRoot, { dependencyTrack: false }), /no submission/);
  w.submit("s1", "a1", null, ["src/a.ts"]);
  assert.throws(() => runStaticGates(w.state, "s1", path.join(tmpRoot, "does-not-exist"), { dependencyTrack: false }));
});

// ---------------------------------------------------------------------------
// Regressions from review
// ---------------------------------------------------------------------------

const E = "../../anthill-backend/src/engine";

test("rings: a spread does not hide import() or new URL() (it is not a member dot)", () => {
  for (const f of [
    `const o = {...import("${E}")};`,
    `f(...import("${E}"));`,
    `const o = { ... import("${E}") };`,
    `const o = {...new URL("${E}.ts", import.meta.url)};`,
    `f(...require("${E}"));`,
  ]) {
    fails(importGate(f + "\n"), /ring-0/);
  }
  // Member access, plain or optional, is still not an import.
  passes(importGate(`x.import("${E}"); x?.import("${E}"); x. new URL;\n`));
});

test("rings: a changed ring-2 file absent from the checkout fails unless deleted (uninitialised submodule)", () => {
  // The superproject checkout of a submodule that was never initialised: an empty directory.
  const dir = repo({ ...kernel });
  fs.mkdirSync(path.join(dir, "anthill-frontend"));
  const file = `${UI}/App.tsx`;
  fails(checkRingImports(dir, [file], rules), /App\.tsx is not present in the checkout and cannot be checked/);
  fails(checkRingImports(dir, [file, `${UI}/gone.ts`], rules, { deleted: [`${UI}/gone.ts`] }), /App\.tsx is not present/);
  passes(checkRingImports(dir, [file], rules, { deleted: [`./${file}`] })); // deletions are normalised too
  // A file declared deleted that is in fact present is scanned anyway.
  const d2 = repo({ ...kernel, [file]: `import k from "${E}";\n` });
  fails(checkRingImports(d2, [file], rules, { deleted: [file] }), /ring-0/);
});

test("runStaticGates: passes deletions through; absence alone fails rings", () => {
  const w = world();
  w.submit("s1", "a1", null, [`${UI}/gone.ts`]);
  const dir = repo({ "README.md": "x\n" });
  assert.equal(runStaticGates(w.state, "s1", dir, { dependencyTrack: false })[0]?.pass, false);
  assert.equal(runStaticGates(w.state, "s1", dir, { dependencyTrack: false, deleted: [`${UI}/gone.ts`] })[0]?.pass, true);
});

test("rings: import.meta.glob options are read; base or anything unreadable fails", () => {
  const pages = { [`${UI}/pages/Home.tsx`]: "export default 1;\n" };
  for (const ok of [
    'import.meta.glob("./pages/*.tsx", { eager: true })',
    "import.meta.glob('./pages/*.tsx', { eager: false, import: 'default', })",
    'import.meta.glob("./pages/*.tsx", { query: "?raw", as: "raw", exhaustive: true })',
    'import.meta.glob("./pages/*.tsx", { query: { url: "", size: "10" } })',
    'import.meta.glob(["./pages/*.tsx"], { "eager": true },)',
    'import.meta.glob("./pages/*.tsx",)',
  ]) {
    passes(importGate(`const m = ${ok};\n`, undefined, pages));
  }
  for (const bad of [
    'import.meta.glob("./*.ts", { base: "../../anthill-backend/src" })',
    'import.meta.glob("./*.ts", { eager: true, base: "../../anthill-backend/src" })',
    'import.meta.glob("./*.ts", { "base": "../../anthill-backend/src" })',
    'import.meta.glob("./*.ts", { b\\u0061se: "../../anthill-backend/src" })',
    'import.meta.glob("./*.ts", { base })',
    'import.meta.glob("./*.ts", { ...opts })',
    'import.meta.glob("./*.ts", opts)',
    'import.meta.glob("./*.ts", { eager: flag })',
    'import.meta.glob("./*.ts", { query: { a: { b: "c" } } })',
    'import.meta.glob("./pages/" + x)',
    'import.meta.glob("./*.ts", {}, extra)',
  ]) {
    fails(importGate(`const m = ${bad};\n`, undefined, pages), /import\.meta\.glob .*cannot be checked/);
  }
});

test("rings: import.meta.glob with type arguments and every glob variant is seen", () => {
  const B = "../../anthill-backend/src/*.ts";
  for (const f of [
    `import.meta.glob<Mod>("${B}", { eager: true })`,
    `import.meta.glob<{ a: T }>("${B}")`,
    `import.meta.glob<Record<string, () => Promise<M>>>("${B}")`,
    `import.meta.glob < Mod > ("${B}")`,
    `import.meta.globEagerDefault("${B}")`,
    `import.meta.globEager<M>("${B}")`,
  ]) {
    fails(importGate(`const m = ${f};\n`), /outside ring 2/);
  }
  // Ring-2 patterns with type arguments still pass.
  const pages = { [`${UI}/pages/Home.tsx`]: "export default 1;\n" };
  passes(importGate('const m = import.meta.glob<Record<string, () => Promise<{ default: C }>>>("./pages/*.tsx");\n', undefined, pages));
  passes(importGate("const m = import.meta.glob<'a>b'>(\"./pages/*.tsx\");\n", undefined, pages));
  // A glob function that is not called, or whose type arguments never close, cannot be checked.
  fails(importGate("const g = import.meta.glob; g(p);\n"), /other than as a call/);
  fails(importGate(`const m = import.meta.glob<Mod("${B}");\n`), /type arguments/);
  // Other import.meta members are not module references.
  passes(importGate("const u = import.meta.url; const e = import.meta.env.MODE; const h = import.meta.hot;\n"));
});

test("rings: legacy octal and \\8/\\9 escapes are not guessed at", () => {
  fails(importGate('const m = require("\\56\\56/\\56\\56/anthill-backend/src/engine");\n'), /computed/);
  fails(importGate('const m = require("./\\8");\n'), /computed/);
  fails(importGate('import k from "./a\\01";\n'), /computed/);
  // \0 not followed by a digit is a NUL, valid everywhere.
  assert.deepEqual(
    scanImports('import k from "./a\\0";').map((r) => r.spec),
    ["./a\0"],
  );
});

test("rings: '?' and '#' are path characters to require(); both readings are judged", () => {
  fails(importGate('const m = require("./x?/../../../anthill-backend/src/engine");\n'), /ring-0/);
  fails(importGate('const m = require("./x#/../../../anthill-backend/src/engine");\n'), /ring-0/);
  passes(importGate('import u from "./logo.svg?url"; import r from "./a.ts?raw#x";\n'));
});

test("rings: identifier escapes expose require/import", () => {
  for (const f of [
    `const m = \\u0072equire("${E}");`,
    `const m = re\\u{71}uire("${E}");`,
    `const m = await \\u0069mport("${E}");`,
    `im\\u0070ort k fr\\u006fm "${E}";`,
    `const m = import.met\\u0061.glob("../../anthill-backend/src/*.ts");`,
  ]) {
    fails(importGate(f + "\n"), /ring-0|outside ring 2/);
  }
  // Escaped backslashes are kept: the string is a backslash then "u0072...".
  assert.equal(decodeIdentifierEscapes('"\\\\u0072"'), '"\\\\u0072"');
  assert.equal(decodeIdentifierEscapes("\\u0072\\u{0000065}"), "re");
  assert.equal(decodeIdentifierEscapes('"\\u0022" \\u0031 \\u{110000}'), '"\\u0022" \\u0031 \\u{110000}');
  // The decoding is line-preserving: problem line numbers stay right.
  const r = importGate(`// line 1\nconst a = "\\u0061";\nconst m = \\u0072equire("${E}");\n`);
  fails(r, /a\.ts:3:/);
});

test("rings: a glob without wildcards and extensionless JSON are classified even when absent", () => {
  fails(importGate('const m = import.meta.glob("../vite.config.ts");\n'), /names ring-0 anthill-frontend\/vite\.config\.ts/);
  fails(importGate('const m = import.meta.glob("../index.html", { query: "?raw" });\n'), /ring-0/);
  fails(importGate('import c from "../../anthill-backend/tsconfig";\n'), /ring-0 anthill-backend\/tsconfig\.json/);
  passes(importGate('import d from "./data";\n', undefined, { [`${UI}/data.json`]: "{}\n" }));
});

test("rings: kernel paths in another letter case fail (case-insensitive filesystems)", () => {
  fails(importGate('import k from "../../anthill-backend/src/Engine";\n'), /ring-0 anthill-backend\/src\/Engine/);
  fails(importGate('import k from "../../Anthill-Backend/src/AUTH.ts";\n'), /ring-0/);
  fails(importGate('const m = import.meta.glob("../Vite.Config.ts");\n'), /ring-0/);
});

test("rings: new URL() with an interpolated template fails as computed", () => {
  fails(importGate("const u = new URL(`../../anthill-backend/src/${n}.ts`, import.meta.url);\n"), /new URL\(\) with a computed specifier/);
  passes(importGate("const u = new URL(`./${n}.png`, location.href);\n")); // not import.meta.url: not bundled
});

test("rings: glob walks are memoised and every path counts against one budget", () => {
  const files: Record<string, string> = {};
  for (let i = 0; i < 3000; i++) files[`${UI}/d/f${i}.ts`] = "";
  const src = 'import.meta.glob("./d/*");\n'.repeat(2000);
  const t = process.hrtime.bigint();
  passes(importGate(src, undefined, files));
  const ms = Number(process.hrtime.bigint() - t) / 1e6;
  assert.ok(ms < 5000, `2000 globs over 3000 files took ${ms} ms`);
  // Thousands of distinct specifiers: tens of thousands of lstat calls, over budget.
  const many = Array.from({ length: 4000 }, (_, i) => `import "./m${i}";`).join("\n");
  fails(importGate(many), /more than 50000 paths to check/);
});

// ---------------------------------------------------------------------------
// Size: the whole change, not only its line count
// ---------------------------------------------------------------------------

test("size: binary code files, too many files and too many bytes fail", () => {
  passes(checkSize({ linesChanged: 10, files: ["a.ts", "logo.png"], binary: ["logo.png", "f/x.WOFF2"] }, rules));
  // One NUL byte makes git call a 5000-line file binary and count it as 0 lines.
  fails(checkSize({ linesChanged: 0, files: ["big.ts"], binary: ["big.ts"] }, rules), /git counts no lines for big\.ts/);
  fails(checkSize({ linesChanged: 0, files: ["a.svg"], binary: ["a.svg"] }, rules), /a\.svg/); // svg is text and can carry script
  fails(checkSize({ linesChanged: 0, files: ["Makefile"], binary: ["Makefile"] }, rules), /Makefile/);
  // Empty files count no lines; their number is bounded too.
  const empties = Array.from({ length: 401 }, (_, i) => `e/${i}.ts`);
  fails(checkSize({ linesChanged: 0, files: empties }, rules), /401 files changed, limit 400/);
  passes(checkSize({ linesChanged: 0, files: empties.slice(0, 400) }, rules));
  // A minified file is one line; bytes are bounded at BYTES_PER_LINE per allowed line.
  fails(checkSize({ linesChanged: 1, bytesAdded: 1_000_000 }, rules), /1000000 bytes added, limit 80000/);
  passes(checkSize({ linesChanged: 1, bytesAdded: 400 * BYTES_PER_LINE }, rules));
  fails(checkSize({ linesChanged: 1, bytesAdded: -1 }, rules), /bytesAdded -1/);
  // Problems accumulate.
  const r = checkSize({ linesChanged: 500, files: ["a.ts"], binary: ["a.ts"] }, rules);
  fails(r, /500 lines changed.*; git counts no lines for a\.ts/);
});

test("runStaticGates: size sees the file count and the binary list", () => {
  const w = world();
  w.submit("s1", "a1", null, ["src/a.ts"], 0);
  const dir = repo({ "src/a.ts": "x\n" });
  assert.equal(runStaticGates(w.state, "s1", dir, { dependencyTrack: false })[3]?.pass, true);
  const r = runStaticGates(w.state, "s1", dir, { dependencyTrack: false, binary: ["src/a.ts"] })[3];
  assert.equal(r?.pass, false);
  assert.match(r?.details ?? "", /git counts no lines for src\/a\.ts/);
});

// ---------------------------------------------------------------------------
// Task ring: a submission must not reach below the ring its stake was priced at
// ---------------------------------------------------------------------------

test("task ring: kernel files under a ring-2 task fail the rings gate", () => {
  const w = world();
  w.task("t2", "alice", ["test/a.test.ts"], 2);
  const dir = repo({ ...kernel, [`${UI}/a.ts`]: "export {};\n" });
  w.submit("s1", "b1", "t2", [`${UI}/a.ts`, ENGINE]);
  const t = checkTaskRing(w.state, "s1");
  assert.equal(t?.pass, false);
  assert.match(t?.details ?? "", /task t2 is scoped at ring 2 .*anthill-backend\/src\/engine\.ts/);
  assert.doesNotMatch(t?.details ?? "", /a\.ts/);
  const [rings] = runStaticGates(w.state, "s1", dir, { dependencyTrack: false });
  assert.equal(rings?.gate, "rings");
  assert.equal(rings?.pass, false);
  assert.match(rings?.details ?? "", /scoped at ring 2/);
  // Ring-1 files under a ring-2 task fail too; within or above the task ring passes.
  w.submit("s2", "b1", "t2", ["docs/x.md"]);
  assert.equal(checkTaskRing(w.state, "s2")?.pass, false);
  w.submit("s3", "b1", "t2", [`${UI}/a.ts`]);
  assert.equal(checkTaskRing(w.state, "s3")?.pass, true);
  w.task("t0", "alice", ["test/a.test.ts"], 0);
  w.submit("s4", "b1", "t0", [`${UI}/a.ts`]);
  assert.equal(checkTaskRing(w.state, "s4")?.pass, true);
  // No task: nothing to compare.
  w.submit("s5", "b1", null, ["docs/x.md"]);
  assert.equal(checkTaskRing(w.state, "s5"), null);
  assert.throws(() => checkTaskRing(w.state, "nope"), /no submission/);
});

// ---------------------------------------------------------------------------
// Spec separation: the tests cannot be made vacuous from outside their files
// ---------------------------------------------------------------------------

test("specSeparation: runner config, mocks and the acceptance tests' snapshots are off limits", () => {
  const w = world();
  w.task("t1", "alice", ["anthill-backend/test/a.test.ts"]);
  const cases: [string, boolean][] = [
    ["anthill-backend/vitest.config.ts", false],
    ["anthill-backend/vitest.workspace.mjs", false],
    ["anthill-backend/jest.config.js", false],
    ["anthill-backend/.mocharc.json", false],
    ["anthill-backend/test/setupTests.ts", false],
    ["anthill-backend/src/__mocks__/store.ts", false],
    ["anthill-backend/test/__snapshots__/a.test.ts.snap", false],
    ["anthill-backend/test/__snapshots__/other.test.ts.snap", true], // another test's snapshot
    ["anthill-backend/test/new.test.ts", true], // the implementer's own new test
    ["anthill-backend/src/routes.ts", true],
  ];
  cases.forEach(([file, ok], i) => {
    w.submit(`s${i}`, "b1", "t1", [file]);
    const r = checkSpecSeparation(w.state, `s${i}`);
    assert.equal(r.pass, ok, `${file}: ${r.details}`);
    if (!ok) assert.match(r.details, /test runner configuration, mocks or snapshots/);
  });
});

test("specSeparation: with the checkout, changed helpers the acceptance tests import fail", () => {
  const w = world();
  w.task("t1", "alice", ["anthill-backend/test/a.test.ts"]);
  const dir = repo({
    "anthill-backend/test/a.test.ts": [
      'import { check } from "./helpers/assert";',
      'import { fixture } from "../fixtures/data";',
      'import { route } from "../src/routes";',
      'import assert from "node:assert";',
    ].join("\n"),
    "anthill-backend/test/helpers/assert.ts": 'export { deep } from "./deep.js";\nexport const check = 1;\n',
    "anthill-backend/test/helpers/deep.ts": "export const deep = 1;\n",
    "anthill-backend/fixtures/data.ts": "export const fixture = 1;\n",
    "anthill-backend/src/routes.ts": 'import { util } from "./util";\nexport const route = 1;\n',
    "anthill-backend/src/util.ts": "export const util = 1;\n",
    "anthill-backend/test/unrelated.helper.ts": "export {};\n",
  });
  // The module under test (and what it imports) is the implementation: fine.
  w.submit("s1", "b1", "t1", ["anthill-backend/src/routes.ts", "anthill-backend/src/util.ts", "anthill-backend/test/unrelated.helper.ts"]);
  passes(checkSpecSeparation(w.state, "s1", dir));
  // A direct helper, a transitive one (imported as .js) and a fixture all fail.
  w.submit("s2", "b1", "t1", ["anthill-backend/src/routes.ts", "anthill-backend/test/helpers/assert.ts"]);
  fails(checkSpecSeparation(w.state, "s2", dir), /test helpers .*: anthill-backend\/test\/helpers\/assert\.ts/);
  w.submit("s3", "b1", "t1", ["anthill-backend/test/helpers/deep.ts"]);
  fails(checkSpecSeparation(w.state, "s3", dir), /anthill-backend\/test\/helpers\/deep\.ts/);
  w.submit("s4", "b1", "t1", ["anthill-backend/fixtures/data.ts"]);
  fails(checkSpecSeparation(w.state, "s4", dir), /anthill-backend\/fixtures\/data\.ts/);
  // Without the checkout only paths are judged.
  passes(checkSpecSeparation(w.state, "s4"));
  // runStaticGates passes the checkout.
  assert.equal(runStaticGates(w.state, "s4", dir, { dependencyTrack: false })[2]?.pass, false);
  // Acceptance tests missing from the checkout (uninitialised submodule): cannot be checked.
  fails(checkSpecSeparation(w.state, "s1", repo({ "README.md": "x\n" })), /no acceptance test is present in the checkout/);
});

test("specSeparation: acceptance globs and directories are followed too", () => {
  const w = world();
  w.task("t1", "alice", ["test/acceptance/**/*.test.ts", "test/golden"]);
  const dir = repo({
    "test/acceptance/x/a.test.ts": 'import "../../support/env";\n',
    "test/support/env.ts": "export {};\n",
    "test/golden/out.json": "{}\n",
  });
  w.submit("s1", "b1", "t1", ["test/support/env.ts"]);
  fails(checkSpecSeparation(w.state, "s1", dir), /test\/support\/env\.ts/);
  w.submit("s2", "b1", "t1", ["src/a.ts"]);
  passes(checkSpecSeparation(w.state, "s2", dir));
});
