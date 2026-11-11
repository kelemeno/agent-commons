import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  checkTestPath,
  isSecretName,
  MAX_LOG_BYTES_PER_RUN,
  minimalEnv,
  reproduceFinding,
  type ReproduceOptions,
} from "../src/findings";

// One repository for the whole file: parent has a correct add(), head
// subtracts instead, and a side branch off parent plants symlinks pointing
// outside the repo (a hostile submission).
let scratch = "";
let repo = "";
let outside = "";
let parent = "";
let head = "";
let symlinkCommit = "";

// node must be on PATH for the commands under test; the harness only forwards PATH.
const PATH = `${dirname(process.execPath)}:${process.env.PATH ?? "/usr/bin:/bin"}`;

function sh(args: string[], cwd = repo): string {
  return execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", ...args], {
    cwd,
    encoding: "utf8",
  }).trim();
}

before(() => {
  scratch = mkdtempSync(join(tmpdir(), "findings-test-"));
  repo = join(scratch, "repo");
  outside = join(scratch, "outside");
  mkdirSync(repo);
  mkdirSync(outside);
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  writeFileSync(join(repo, "math.js"), "exports.add = (a, b) => a + b;\n");
  sh(["add", "."]);
  sh(["commit", "-q", "-m", "add"]);
  parent = sh(["rev-parse", "HEAD"]);
  writeFileSync(join(repo, "math.js"), "exports.add = (a, b) => a - b;\n");
  sh(["commit", "-q", "-am", "refactor add"]);
  head = sh(["rev-parse", "HEAD"]);

  sh(["checkout", "-q", "-b", "evil", parent]);
  symlinkSync(outside, join(repo, "evil"));
  symlinkSync(join(outside, "target.js"), join(repo, "link.js"));
  sh(["add", "."]);
  sh(["commit", "-q", "-m", "symlinks"]);
  symlinkCommit = sh(["rev-parse", "HEAD"]);
  sh(["checkout", "-q", "main"]);
});

after(() => {
  rmSync(scratch, { recursive: true, force: true });
});

function opts(over: Partial<ReproduceOptions>): ReproduceOptions {
  return {
    repoDir: repo,
    baseCommit: parent,
    headCommit: head,
    testPath: "test/finding-1.test.js",
    testContent: "",
    testCommand: "node test/finding-1.test.js",
    env: { PATH },
    ...over,
  };
}

const ADD_TEST = `const assert = require("node:assert/strict");
const { add } = require("../math.js");
assert.equal(add(2, 3), 5);
console.log("add ok");
`;

function worktreeCount(): number {
  return sh(["worktree", "list", "--porcelain"])
    .split("\n")
    .filter((l) => l.startsWith("worktree ")).length;
}

function harnessTempDirs(): string[] {
  return readdirSync(tmpdir()).filter((n) => n.startsWith("anthill-finding-"));
}

test("a test that fails on head and passes on the parent reproduces", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST }));
  assert.equal(r.failsOnHead, true);
  assert.equal(r.passesOnParent, true);
  assert.equal(r.reproduced, true);
  assert.equal(r.harnessError, null);
  assert.equal(r.logDigest, createHash("sha256").update(r.log).digest("hex"));
  assert.match(r.log, new RegExp(`=== head ${head} ===\\n\\$ node test/finding-1.test.js\\n`));
  assert.match(r.log, new RegExp(`=== base ${parent} ===`));
  assert.match(r.log, /=== head: exit 1 ===/);
  assert.match(r.log, /=== base: exit 0 ===/);
  assert.match(r.log, /add ok/);
  assert.ok(r.log.indexOf("=== head") < r.log.indexOf("=== base"));
});

test("the log digest is stable across runs: no temp paths or timings leak into the log", async () => {
  // The failing assertion prints a stack trace containing the worktree path.
  const a = await reproduceFinding(opts({ testContent: ADD_TEST }));
  const b = await reproduceFinding(opts({ testContent: ADD_TEST }));
  assert.equal(a.logDigest, b.logDigest);
  assert.match(a.log, /<worktree>/);
  assert.doesNotMatch(a.log, /anthill-finding-/);
});

test("commits may be given as any commit-ish and are logged as full shas", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, headCommit: "main", baseCommit: "main~1" }));
  assert.equal(r.reproduced, true);
  assert.match(r.log, new RegExp(`=== head ${head} ===`));
  assert.match(r.log, new RegExp(`=== base ${parent} ===`));
});

test("a test that passes on both commits does not reproduce", async () => {
  const content = `const { add } = require("../math.js"); if (add(0, 0) !== 0) process.exit(1);\n`;
  const r = await reproduceFinding(opts({ testContent: content }));
  assert.equal(r.failsOnHead, false);
  assert.equal(r.passesOnParent, true);
  assert.equal(r.reproduced, false);
  assert.equal(r.harnessError, null);
});

test("a test that fails on both commits does not reproduce", async () => {
  const r = await reproduceFinding(opts({ testContent: "process.exit(3);\n" }));
  assert.equal(r.failsOnHead, true);
  assert.equal(r.passesOnParent, false);
  assert.equal(r.reproduced, false);
  assert.match(r.log, /=== head: exit 3 ===/);
  assert.match(r.log, /=== base: exit 3 ===/);
});

test("reversed commits do not reproduce: the test must pass on the parent", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, baseCommit: head, headCommit: parent }));
  assert.equal(r.failsOnHead, false);
  assert.equal(r.passesOnParent, false);
  assert.equal(r.reproduced, false);
});

test("death by a signal on head counts as failing", async () => {
  const content = `const { add } = require("../math.js"); if (add(2, 3) !== 5) process.kill(process.pid, "SIGSEGV");\n`;
  const r = await reproduceFinding(opts({ testContent: content, testCommand: "exec node test/finding-1.test.js" }));
  assert.equal(r.failsOnHead, true);
  assert.equal(r.passesOnParent, true);
  assert.equal(r.reproduced, true);
  assert.match(r.log, /=== head: killed by SIGSEGV ===/);
});

test("a timeout on head is a harness error, not a failure, and kills the whole process group", async () => {
  // Hangs on head only (and leaves a backgrounded child), passes on parent: a
  // naive harness would count the hang as "fails on head" and reproduce.
  const pidFile = join(scratch, "bg.pid");
  const content = `const { add } = require("../math.js"); if (add(2, 3) !== 5) setInterval(() => {}, 1000);\n`;
  const r = await reproduceFinding(
    opts({
      testContent: content,
      testCommand: `sleep 300 & echo $! >> "$PIDFILE"; node test/finding-1.test.js`,
      timeoutMs: 1500,
      env: { PATH, PIDFILE: pidFile },
    }),
  );
  assert.equal(r.failsOnHead, false);
  assert.equal(r.passesOnParent, true);
  assert.equal(r.reproduced, false);
  assert.match(r.harnessError ?? "", /^head: timed out/);
  assert.match(r.log, /=== head: timeout/);
  // One backgrounded sleep per run: head's dies with the timed-out group,
  // base's is killed as a straggler when its shell exits.
  const pids = readFileSync(pidFile, "utf8").trim().split("\n").map(Number);
  assert.equal(pids.length, 2);
  for (const pid of pids) await waitDead(pid);
  assert.equal(worktreeCount(), 1);
});

test("a straggler that keeps stdout open does not turn a finished run into a timeout", async () => {
  const r = await reproduceFinding(
    opts({ testContent: ADD_TEST, testCommand: "sleep 300 & node test/finding-1.test.js", timeoutMs: 5000 }),
  );
  assert.equal(r.reproduced, true);
  assert.equal(r.harnessError, null);
});

test("an unresolvable commit is a harness error, never a reproduction", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, baseCommit: "0".repeat(40) }));
  assert.equal(r.failsOnHead, true);
  assert.equal(r.passesOnParent, false);
  assert.equal(r.reproduced, false);
  assert.match(r.harnessError ?? "", /^base: commit does not resolve/);
  assert.equal(worktreeCount(), 1);
});

test("a commit that looks like a git option is refused, not passed to git", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, headCommit: `--output=${join(scratch, "pwned")}` }));
  assert.equal(r.reproduced, false);
  assert.match(r.harnessError ?? "", /^head: invalid commit/);
  assert.equal(existsSync(join(scratch, "pwned")), false);
});

test("lexically unsafe test paths are rejected before anything is checked out", async () => {
  const before = worktreeCount();
  for (const bad of ["", "/tmp/x.test.js", "../x.test.js", "test/../../x.js", "a/..", ".git/hooks/post-checkout", ".git", "test\\x.js", "test/", "."]) {
    await assert.rejects(reproduceFinding(opts({ testPath: bad, testContent: ADD_TEST })), Error, `should reject ${JSON.stringify(bad)}`);
  }
  assert.equal(worktreeCount(), before);
});

test("checkTestPath normalises harmless paths", () => {
  assert.equal(checkTestPath("test//a.test.js"), "test/a.test.js");
  assert.equal(checkTestPath("./test/a.test.js"), "test/a.test.js");
  assert.equal(checkTestPath("deep/new/dir/a.test.js"), "deep/new/dir/a.test.js");
  assert.throws(() => checkTestPath("x\0y"));
  assert.throws(() => checkTestPath("C:/x.js"));
});

test("a test path through a committed symlink is refused and nothing is written outside", async () => {
  for (const testPath of ["evil/x.test.js", "link.js"]) {
    const r = await reproduceFinding(
      opts({ testPath, testContent: "process.exit(0);\n", testCommand: "true", headCommit: symlinkCommit }),
    );
    assert.equal(r.reproduced, false);
    assert.match(r.harnessError ?? "", /^head: testPath goes through a symlink/);
    // The parent commit has no symlinks, so the base run is fine.
    assert.equal(r.passesOnParent, true);
  }
  assert.deepEqual(readdirSync(outside), []);
  assert.equal(worktreeCount(), 1);
});

test("missing parent directories are created inside the worktree", async () => {
  const r = await reproduceFinding(
    opts({ testPath: "a/b/c/finding.test.js", testContent: ADD_TEST.replace("../math.js", "../../../math.js"), testCommand: "node a/b/c/finding.test.js" }),
  );
  assert.equal(r.reproduced, true);
});

test("secret-looking variables never reach the command, from process.env or opts.env", async () => {
  process.env.HARNESS_TEST_SECRET_TOKEN = "proc-secret-value";
  process.env.HARNESS_TEST_PLAIN = "proc-plain-value";
  try {
    const check = `const e = process.env;
const bad = Object.keys(e).filter((k) => /TOKEN|KEY|SECRET|PASSWORD/i.test(k));
if (bad.length) { console.log("leaked", bad); process.exit(1); }
if (e.HARNESS_TEST_PLAIN !== undefined) { console.log("inherited process.env"); process.exit(1); }
if (e.FOO !== "bar" || e.CI !== "1" || e.LANG !== "C.UTF-8") { console.log("bad fixed env"); process.exit(1); }
if (!e.HOME || e.HOME === ${JSON.stringify(process.env.HOME ?? "")}) { console.log("real HOME"); process.exit(1); }
console.log("env ok");
`;
    const r = await reproduceFinding(
      opts({
        headCommit: parent,
        testContent: check,
        testCommand: "env; node test/finding-1.test.js",
        env: {
          PATH,
          FOO: "bar",
          GITHUB_TOKEN: "opt-token-value",
          api_key: "opt-key-value",
          DB_PASSWORD: "opt-password-value",
          AWS_SECRET_ACCESS_KEY: "opt-aws-value",
          HOME: "/root",
          CI: "0",
        },
      }),
    );
    assert.equal(r.failsOnHead, false, r.log);
    assert.equal(r.passesOnParent, true, r.log);
    assert.match(r.log, /env ok/);
    for (const v of ["proc-secret-value", "proc-plain-value", "opt-token-value", "opt-key-value", "opt-password-value", "opt-aws-value"]) {
      assert.ok(!r.log.includes(v), `log leaks ${v}`);
    }
    assert.match(r.log, /HOME=<home>/);
  } finally {
    delete process.env.HARNESS_TEST_SECRET_TOKEN;
    delete process.env.HARNESS_TEST_PLAIN;
  }
});

test("minimalEnv keeps only PATH, fixed HOME/CI/LANG and non-secret extras", () => {
  const env = minimalEnv("/tmp/h", { PATH: "/p", X: "1", MY_KEY: "k", Session_Token: "t", HOME: "/root", LANG: "fr" });
  assert.deepEqual(env, { X: "1", PATH: "/p", HOME: "/tmp/h", CI: "1", LANG: "C.UTF-8" });
  assert.equal(minimalEnv("/h").PATH, process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin");
  assert.equal(isSecretName("npm_config_authtoken"), true);
  assert.equal(isSecretName("NODE_OPTIONS"), false);
});

test("each run's output is truncated to 64 KiB with a marker", async () => {
  const r = await reproduceFinding(
    opts({ testContent: `process.stdout.write("x".repeat(200 * 1024)); process.exitCode = 1;\n` }),
  );
  assert.equal(r.failsOnHead, true);
  assert.ok(r.log.length < 2 * MAX_LOG_BYTES_PER_RUN + 4096, `log is ${r.log.length} bytes`);
  const markers = r.log.match(/\[output truncated: (\d+) more bytes\]/g) ?? [];
  assert.equal(markers.length, 2);
  assert.match(r.log, new RegExp(`truncated: ${200 * 1024 - MAX_LOG_BYTES_PER_RUN} more bytes`));
});

test("the test file overwrites nothing in the main checkout and worktrees and temp dirs are always removed", async () => {
  const tempBefore = harnessTempDirs().length;
  await reproduceFinding(opts({ testContent: ADD_TEST }));
  await reproduceFinding(opts({ testContent: "process.exit(1);\n", baseCommit: "nope" }));
  await reproduceFinding(opts({ testContent: "rm -rf .", testCommand: "rm -rf ./* && exit 1" }));
  assert.equal(worktreeCount(), 1);
  assert.equal(sh(["worktree", "list"]).split("\n").length, 1);
  assert.equal(existsSync(join(repo, "test")), false);
  assert.equal(sh(["status", "--porcelain"]), "");
  assert.equal(harnessTempDirs().length, tempBefore);
});

test("rejects a non-positive timeout", async () => {
  await assert.rejects(reproduceFinding(opts({ testContent: ADD_TEST, timeoutMs: 0 })));
});

async function waitDead(pid: number): Promise<void> {
  for (let i = 0; i < 50; i++) {
    if (!alive(pid)) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  assert.fail(`process ${pid} survived the harness`);
}

function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
  } catch {
    return false;
  }
  // A killed child whose reaper has not run yet is a zombie: dead for our purposes.
  try {
    return !/^\d+ \(.*\) Z/.test(readFileSync(`/proc/${pid}/stat`, "utf8"));
  } catch {
    return false;
  }
}
