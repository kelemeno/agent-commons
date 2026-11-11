// Spec separation: whoever wrote a task's spec (its acceptance tests) must not
// implement it, and the implementer must not edit those tests. Otherwise one
// owner both sets the bar and clears it, and the acceptance tests prove nothing.
//
// Owners, not agents, are compared: two agents of one owner are one party.
//
// "Editing the tests" includes making them vacuous without touching their
// files: changing the test runner's configuration or setup (which can exclude
// a file, mock the module under test or patch `expect`), jest `__mocks__`,
// the acceptance tests' snapshots, or a test helper or fixture an acceptance
// test imports. Helpers are found by following the acceptance tests' relative
// imports through test-support files (test directories, *.test.*/*.spec.*);
// that needs the checkout (`repoDir`). The module under test is imported too,
// but it lives outside test support, so implementing it is not flagged.

import * as fs from "node:fs";
import * as path from "node:path";
import { globToRegExp } from "../rules";
import type { CommonsState, GateReport } from "../types";
import { CODE_FILE, RESOLVE_SUFFIXES, listProblems, normalizeRepoPath, scanImports } from "./rings";

export const GATE = "specSeparation";

// Files whose change alters how every test runs.
const RUNNER_FILES = [
  "**/vitest.config.*",
  "**/vitest.workspace.*",
  "**/vitest.setup.*",
  "**/vite.config.*", // vitest reads its `test` section
  "**/jest.config.*",
  "**/jest.setup.*",
  "**/jest.preset.*",
  "**/.mocharc*",
  "**/mocha.opts",
  "**/playwright.config.*",
  "**/cypress.config.*",
  "**/karma.conf.*",
  "**/ava.config.*",
  "**/setupTests.*",
  "**/test-setup.*",
  "**/test.setup.*",
  "**/__mocks__/**",
].map((g) => globToRegExp(g));

const TEST_SUPPORT_DIR = /(?:^|\/)(?:tests?|__tests__|specs?|fixtures|__fixtures__|__mocks__|testing|test-?utils|test-?helpers)\//;
const TEST_FILE = /\.(?:test|spec)\.[^/]*$/;
const GRAPH_LIMIT = 2_000; // files read while following acceptance-test imports

export function isTestSupport(file: string): boolean {
  return TEST_SUPPORT_DIR.test(file) || TEST_FILE.test(file);
}

// An acceptance test path names a file exactly, a glob of files, or a
// directory whose whole contents are the tests.
export function isAcceptancePath(file: string, acceptancePath: string): boolean {
  const p = normalizeRepoPath(acceptancePath) ?? acceptancePath;
  if (file === p || file.startsWith(`${p}/`)) return true;
  try {
    return globToRegExp(p).test(file);
  } catch {
    return false;
  }
}

// Throws for an unknown submission: that is a caller error, not a verdict.
// `repoDir`, the checkout at the submission's head, enables the helper check;
// without it only paths are judged.
export function checkSpecSeparation(state: CommonsState, submissionId: string, repoDir?: string): GateReport {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`no submission ${submissionId}`);
  if (s.taskId === null) return { gate: GATE, pass: true, details: "no task: the submission implements no spec" };
  const task = state.tasks.get(s.taskId);
  if (!task) return { gate: GATE, pass: false, details: `task ${s.taskId} is not in the ledger` };
  const owner = state.agents.get(s.author)?.owner ?? state.ownerByKey.get(s.author);
  if (owner === undefined) return { gate: GATE, pass: false, details: `author ${s.author} has no registered owner` };

  const problems: string[] = [];
  if (owner === task.specAuthor) problems.push(`owner ${owner} wrote the spec of task ${task.id} and cannot implement it`);
  const isAcceptance = (f: string) => task.acceptanceTestPaths.some((p) => isAcceptancePath(f, p));
  const changed = new Set<string>();
  const touched: string[] = [];
  const machinery: string[] = [];
  for (const raw of s.changedFiles) {
    const file = normalizeRepoPath(raw);
    if (file === null) {
      problems.push(`${JSON.stringify(raw)} is not a path inside the repository`);
      continue;
    }
    changed.add(file);
    if (isAcceptance(file)) touched.push(file);
    else if (task.acceptanceTestPaths.length > 0 && (RUNNER_FILES.some((re) => re.test(file)) || isAcceptanceSnapshot(file, isAcceptance))) {
      machinery.push(file);
    }
  }
  if (touched.length > 0) problems.push(`changes acceptance tests of task ${task.id}: ${touched.join(", ")}`);
  if (machinery.length > 0) problems.push(`changes test runner configuration, mocks or snapshots of task ${task.id}: ${machinery.join(", ")}`);
  if (repoDir !== undefined && task.acceptanceTestPaths.length > 0) {
    const helpers = changedHelpers(repoDir, task.acceptanceTestPaths, changed, isAcceptance);
    if (typeof helpers === "string") problems.push(helpers);
    else if (helpers.length > 0) problems.push(`changes test helpers that acceptance tests of task ${task.id} import: ${helpers.join(", ")}`);
  }
  if (problems.length > 0) return { gate: GATE, pass: false, details: listProblems(problems) };
  return { gate: GATE, pass: true, details: `implementer ${owner} is not spec author ${task.specAuthor}; acceptance tests untouched` };
}

// `dir/__snapshots__/name.snap` belongs to the test `dir/name`.
function isAcceptanceSnapshot(file: string, isAcceptance: (f: string) => boolean): boolean {
  const m = /^(.*?)(?:^|\/)__snapshots__\/([^/]+)\.snap$/.exec(file);
  return m !== null && isAcceptance(m[1] ? `${m[1]}/${m[2]}` : (m[2] as string));
}

// Changed test-support files reachable from the acceptance tests by relative
// imports, or why the graph could not be followed. The acceptance tests are
// unchanged (checked above), so reading them at head reads them as specified.
function changedHelpers(
  repoDir: string,
  acceptancePaths: string[],
  changed: Set<string>,
  isAcceptance: (f: string) => boolean,
): string[] | string {
  const root = fs.realpathSync(repoDir);
  const files = acceptanceFiles(root, acceptancePaths, isAcceptance);
  if (files === null) return `acceptance paths cover more than ${GRAPH_LIMIT * 10} paths: helpers cannot be checked`;
  // The spec author writes the tests before the task is claimed, so none on
  // disk means the checkout is incomplete (an uninitialised submodule).
  if (files.present === 0) return "no acceptance test is present in the checkout: helpers cannot be checked";
  const queue = files.code;
  const seen = new Set(queue);
  const found: string[] = [];
  for (let next = queue.pop(); next !== undefined; next = queue.pop()) {
    if (seen.size > GRAPH_LIMIT) return `acceptance tests import more than ${GRAPH_LIMIT} test files: helpers cannot be checked`;
    let source: string;
    try {
      source = fs.readFileSync(path.join(root, next), "utf8");
    } catch {
      continue;
    }
    for (const ref of scanImports(source)) {
      if (ref.spec === null || ref.how === "import.meta.glob") continue;
      const target = resolveExisting(root, path.posix.dirname(next), ref.spec);
      if (target === null || seen.has(target) || !isTestSupport(target)) continue;
      seen.add(target);
      if (changed.has(target) && !isAcceptance(target)) found.push(target);
      queue.push(target);
    }
  }
  return found.sort();
}

// The acceptance test files on disk: exact paths, directories, and globs
// matched under their static prefix: the code files among them and how many
// files there are in all; null when there are too many to walk.
function acceptanceFiles(
  root: string,
  acceptancePaths: string[],
  isAcceptance: (f: string) => boolean,
): { code: string[]; present: number } | null {
  const out = new Set<string>();
  let present = 0;
  let budget = GRAPH_LIMIT * 10;
  for (const raw of acceptancePaths) {
    const p = normalizeRepoPath(raw);
    if (p === null) continue;
    const segments = p.split("/");
    const wild = segments.findIndex((x) => /[*?]/.test(x));
    const stack = [(wild < 0 ? segments : segments.slice(0, wild)).join("/")];
    while (stack.length > 0) {
      if (--budget < 0) return null;
      const rel = stack.pop() as string;
      let st: fs.Stats;
      try {
        st = fs.lstatSync(path.join(root, rel));
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        for (const name of fs.readdirSync(path.join(root, rel))) {
          if (name !== ".git" && name !== "node_modules") stack.push(rel === "" ? name : `${rel}/${name}`);
        }
      }
      else if (st.isFile() && isAcceptance(rel)) {
        present += 1;
        if (CODE_FILE.test(rel)) out.add(rel);
      }
    }
  }
  return { code: [...out], present };
}

function resolveExisting(root: string, dir: string, spec: string): string | null {
  const bare = spec.replace(/[?#].*$/s, "");
  if (!/^\.\.?(?:\/|$)/.test(bare)) return null;
  const lexical = normalizeRepoPath(path.posix.join(dir, bare));
  if (lexical === null) return null;
  const candidates = RESOLVE_SUFFIXES.map((x) => lexical + x);
  const m = /\.([cm]?)js(x?)$/.exec(lexical);
  if (m) candidates.push(`${lexical.slice(0, -m[0].length)}.${m[1] ?? ""}ts${m[2] ?? ""}`);
  for (const c of candidates) {
    try {
      if (fs.statSync(path.join(root, c)).isFile()) return c;
    } catch {
      // try the next candidate
    }
  }
  return null;
}
