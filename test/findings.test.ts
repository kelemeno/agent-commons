import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import {
  checkTestPath,
  isSecretName,
  MAX_LOG_BYTES_PER_RUN,
  MAX_TIMEOUT_MS,
  minimalEnv,
  PID_NAMESPACE_SANDBOX,
  redact,
  removeTree,
  reproduceFinding,
  runCommand,
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

// The harness's temp roots under `root`. Tests that count them pass their own
// tmpRoot: other test files run the harness concurrently in os.tmpdir(), so a
// count there changes under the test (that made it fail at random).
function harnessTempDirs(root: string): string[] {
  return readdirSync(root).filter((n) => n.startsWith("commons-finding-"));
}

function ownTmpRoot(): string {
  return mkdtempSync(join(tmpdir(), "findings-own-root-"));
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
  // Base runs first, so the submission's code never runs before the parent's.
  assert.ok(r.log.indexOf("=== base") < r.log.indexOf("=== head"));
});

test("the log digest is stable across runs: no temp paths or timings leak into the log", async () => {
  // The failing assertion prints a stack trace containing the worktree path.
  const a = await reproduceFinding(opts({ testContent: ADD_TEST }));
  const b = await reproduceFinding(opts({ testContent: ADD_TEST }));
  assert.equal(a.logDigest, b.logDigest);
  assert.match(a.log, /<worktree>/);
  assert.doesNotMatch(a.log, /commons-finding-/);
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
  assert.equal(r.harnessError, null);
  assert.match(r.log, /=== head: exit 3 ===/);
  assert.match(r.log, /=== base: exit 3 ===/);
});

test("reversed commits do not reproduce: the test must pass on the parent", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, baseCommit: head, headCommit: parent }));
  assert.equal(r.failsOnHead, false);
  assert.equal(r.passesOnParent, false);
  assert.equal(r.reproduced, false);
  assert.equal(r.harnessError, null);
});

test("death by a signal on head counts as failing", async () => {
  const content = `const { add } = require("../math.js"); if (add(2, 3) !== 5) process.kill(process.pid, "SIGSEGV");\n`;
  const r = await reproduceFinding(opts({ testContent: content, testCommand: "exec node test/finding-1.test.js" }));
  assert.equal(r.failsOnHead, true);
  assert.equal(r.passesOnParent, true);
  assert.equal(r.reproduced, true);
  assert.equal(r.harnessError, null);
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
  const tmpRoot = ownTmpRoot();
  await reproduceFinding(opts({ testContent: ADD_TEST, tmpRoot }));
  await reproduceFinding(opts({ testContent: "process.exit(1);\n", baseCommit: "nope", tmpRoot }));
  await reproduceFinding(opts({ testContent: "rm -rf .", testCommand: "rm -rf ./* && exit 1", tmpRoot }));
  assert.equal(worktreeCount(), 1);
  assert.equal(sh(["worktree", "list"]).split("\n").length, 1);
  assert.equal(existsSync(join(repo, "test")), false);
  assert.equal(sh(["status", "--porcelain"]), "");
  assert.deepEqual(harnessTempDirs(tmpRoot), []);
});

test("rejects a timeout outside (0, MAX_TIMEOUT_MS]", async () => {
  // setTimeout turns anything above 2^31-1 ms into 1 ms, which would time out
  // every run instantly and make every finding unreproducible.
  for (const bad of [0, -1, NaN, Infinity, MAX_TIMEOUT_MS + 1, 3e9]) {
    await assert.rejects(reproduceFinding(opts({ testContent: ADD_TEST, timeoutMs: bad })), /timeoutMs/, `should reject ${bad}`);
  }
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, timeoutMs: MAX_TIMEOUT_MS }));
  assert.equal(r.reproduced, true);
  assert.equal(r.harnessError, null);
});

// --- hostile repositories and hostile commands -------------------------------

function refsAndConfig(): string {
  return sh(["for-each-ref", "--format=%(refname) %(objectname)"]) + "\n" + readFileSync(join(repo, ".git", "config"), "utf8");
}

function liveHooks(): string[] {
  return readdirSync(join(repo, ".git", "hooks")).filter((n) => !n.endsWith(".sample"));
}

test("hooks and fsmonitor configured in the repository never run during the harness's own git calls", async () => {
  // Stands for a repository an earlier hostile run already tampered with.
  const marker = join(scratch, "hook-ran");
  const script = `#!/bin/sh\necho "$0" >> ${JSON.stringify(marker)}\nexit 0\n`;
  const hooks = ["post-checkout", "post-index-change", "reference-transaction", "pre-auto-gc"];
  for (const h of hooks) {
    writeFileSync(join(repo, ".git", "hooks", h), script);
    chmodSync(join(repo, ".git", "hooks", h), 0o755);
  }
  const fsmonitor = join(scratch, "fsmonitor.sh");
  writeFileSync(fsmonitor, script);
  chmodSync(fsmonitor, 0o755);
  sh(["config", "core.fsmonitor", fsmonitor]);
  try {
    const r = await reproduceFinding(opts({ testContent: ADD_TEST }));
    assert.equal(r.reproduced, true, r.log);
    assert.equal(existsSync(marker), false, existsSync(marker) ? readFileSync(marker, "utf8") : "");
  } finally {
    sh(["config", "--unset", "core.fsmonitor"]);
    for (const h of hooks) rmSync(join(repo, ".git", "hooks", h));
  }
});

test("the command's checkout is not linked to the repository: it cannot plant hooks, move refs, replace objects or edit config", async () => {
  const before = refsAndConfig();
  const attack = [
    `if git rev-parse --git-dir >/dev/null 2>&1; then echo FOUND""-A-REPO; fi`,
    `d=$(git rev-parse --git-common-dir 2>/dev/null) && mkdir -p "$d/hooks" && printf '#!/bin/sh\\necho $DEPLOY_TOKEN > /tmp/stolen\\n' > "$d/hooks/post-checkout" && chmod +x "$d/hooks/post-checkout"`,
    `git replace -f ${parent} ${head} 2>/dev/null`,
    `git update-ref refs/heads/main ${parent} 2>/dev/null`,
    `git config core.hooksPath /tmp 2>/dev/null`,
    `test -e .git && echo HAS""-DOT-GIT`,
    `node test/finding-1.test.js`,
  ].join("\n");
  process.env.DEPLOY_TOKEN = "deploy-token-value-1234";
  try {
    const r = await reproduceFinding(opts({ testContent: ADD_TEST, testCommand: attack }));
    assert.equal(r.reproduced, true, r.log);
    assert.equal(r.harnessError, null);
    assert.doesNotMatch(r.log, /FOUND-A-REPO|HAS-DOT-GIT|deploy-token-value/);
  } finally {
    delete process.env.DEPLOY_TOKEN;
  }
  assert.equal(refsAndConfig(), before);
  assert.deepEqual(liveHooks(), []);
  assert.equal(sh(["replace", "--list"]), "");
  assert.equal(worktreeCount(), 1);
});

test("both commits are resolved and checked out before any command runs, and base runs first", async () => {
  // A same-uid command that knows where the repository is can still change it;
  // what must hold is that it cannot change what this reproduction checks.
  sh(["branch", "-f", "basebr", parent]);
  try {
    const attack = `git -C "$REPO" update-ref refs/heads/basebr ${head}; git -C "$REPO" update-ref refs/heads/headbr ${parent}; node test/finding-1.test.js`;
    sh(["branch", "-f", "headbr", head]);
    const r = await reproduceFinding(
      opts({ testContent: ADD_TEST, testCommand: attack, baseCommit: "basebr", headCommit: "headbr", env: { PATH, REPO: repo } }),
    );
    assert.equal(r.reproduced, true, r.log);
    assert.match(r.log, new RegExp(`=== base ${parent} ===`));
    assert.match(r.log, new RegExp(`=== head ${head} ===`));
  } finally {
    sh(["branch", "-D", "basebr", "headbr"]);
  }
});

test("a planted git replace cannot swap the tree behind a genuine parent sha", async () => {
  sh(["replace", "-f", parent, head]);
  try {
    // Plain git now shows the buggy tree under the parent's sha...
    assert.match(sh(["show", `${parent}:math.js`]), /a - b/);
    // ...but the harness checks out the real one.
    const r = await reproduceFinding(opts({ testContent: ADD_TEST }));
    assert.equal(r.passesOnParent, true, r.log);
    assert.equal(r.reproduced, true);
  } finally {
    sh(["replace", "-d", parent]);
  }
});

test("a timeout settles even when a setsid descendant keeps the output pipes open", async () => {
  const pidFile = join(scratch, "setsid-timeout.pid");
  const started = Date.now();
  try {
    const r = await reproduceFinding(
      opts({
        testContent: ADD_TEST,
        testCommand: `setsid sh -c 'echo $$ >> "$PIDFILE"; exec sleep 1000' & sleep 1000`,
        timeoutMs: 1000,
        env: { PATH, PIDFILE: pidFile },
      }),
    );
    assert.ok(Date.now() - started < 15_000, `took ${Date.now() - started} ms`);
    assert.equal(r.reproduced, false);
    assert.match(r.harnessError ?? "", /^head: timed out/);
    assert.match(r.log, /=== base: timeout/);
    assert.equal(worktreeCount(), 1);
    assert.equal(r.cleanupError, null);
  } finally {
    killPids(pidFile);
  }
});

test("a setsid descendant holding the pipes after the shell exits delays the result by at most the drain period", async () => {
  const pidFile = join(scratch, "setsid-exit.pid");
  const started = Date.now();
  try {
    const r = await reproduceFinding(
      opts({
        testContent: ADD_TEST,
        testCommand: `setsid sh -c 'echo $$ >> "$PIDFILE"; exec sleep 1000' & node test/finding-1.test.js`,
        timeoutMs: 60_000,
        env: { PATH, PIDFILE: pidFile },
      }),
    );
    assert.ok(Date.now() - started < 15_000, `took ${Date.now() - started} ms`);
    assert.equal(r.reproduced, true, r.log);
    assert.equal(r.harnessError, null);
  } finally {
    killPids(pidFile);
  }
});

test("a spawn failure is a harness error, never a reproduction", async () => {
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, sandbox: ["/nonexistent/sandbox-wrapper"] }));
  assert.equal(r.failsOnHead, false);
  assert.equal(r.passesOnParent, false);
  assert.equal(r.reproduced, false);
  assert.match(r.harnessError ?? "", /^head: spawn failed: .*ENOENT/);
  assert.match(r.log, /=== base: harness error: spawn failed/);
  assert.equal(worktreeCount(), 1);

  const o = await runCommand("true", join(scratch, "no-such-dir"), { PATH }, 5000);
  assert.equal(o.kind, "error");
  await assert.rejects(reproduceFinding(opts({ testContent: ADD_TEST, sandbox: [] })), /sandbox/);
});

test("cleanup survives a command that fakes .git and locks directories, and never replaces the result", async () => {
  const tmpRoot = ownTmpRoot();
  const r = await reproduceFinding(
    opts({
      tmpRoot,
      testContent: ADD_TEST,
      testCommand: `echo 'gitdir: /x' > .git; mkdir -p locked/inner; touch locked/inner/f; chmod 000 locked/inner locked; chmod 000 "$HOME"; node test/finding-1.test.js`,
    }),
  );
  assert.equal(r.reproduced, true, r.log);
  assert.equal(r.cleanupError, null);
  assert.equal(worktreeCount(), 1);
  assert.equal(sh(["worktree", "list"]).split("\n").length, 1);
  assert.deepEqual(harnessTempDirs(tmpRoot), []);
  // removeTree reports instead of throwing when something truly cannot go:
  // here a directory whose parent we may not write (root ignores that, so
  // as root use a /proc directory, which nobody can remove).
  const stuckParent = join(scratch, "stuck-parent");
  mkdirSync(join(stuckParent, "stuck", "inner"), { recursive: true });
  chmodSync(stuckParent, 0o500);
  try {
    const err = await removeTree(process.getuid?.() === 0 ? "/proc/self/fdinfo" : join(stuckParent, "stuck"));
    assert.match(err ?? "", /could not remove/);
  } finally {
    chmodSync(stuckParent, 0o700);
  }
});

test("redact replaces secret values and drops a secret's prefix left at a truncation cut", () => {
  assert.equal(redact("a hunter22 b hunter22", ["hunter22"], false), "a <redacted> b <redacted>");
  assert.equal(redact("x abcdefgh", ["abcdefgh", "abcd"], false), "x <redacted>");
  assert.equal(redact("tail abcd", ["abcdefgh"], true), "tail ");
  assert.equal(redact("tail abcd", ["abcdefgh"], false), "tail abcd");
});

// The secret is in the environment the process was LAUNCHED with, so it shows
// in /proc/<pid>/environ; setting process.env at runtime would not.
function runInChild(over: Record<string, unknown>, secret: string): ReturnType<typeof reproduceFinding> extends Promise<infer R> ? R : never {
  const script = join(scratch, "child-reproduce.ts");
  writeFileSync(
    script,
    `import { reproduceFinding } from ${JSON.stringify(resolve(__dirname, "../src/findings.ts"))};
reproduceFinding(JSON.parse(process.argv[2] ?? "{}")).then((r) => process.stdout.write(JSON.stringify(r)));
`,
  );
  const out = execFileSync(process.execPath, ["--import", "tsx", script, JSON.stringify({ ...opts({}), ...over })], {
    cwd: resolve(__dirname, ".."),
    env: { ...process.env, LAUNCH_SECRET_TOKEN: secret },
    encoding: "utf8",
  });
  return JSON.parse(out);
}

// How a same-uid command reads its parent's launch environment: Linux's
// /proc/<pid>/environ, or BSD/macOS `ps -E`.
const READ_PARENT_ENV = existsSync("/proc/self/environ")
  ? `tr '\\0' '\\n' < /proc/$PPID/environ | grep LAUNCH_SECRET; cat /proc/$PPID/environ > "$OUT"`
  : `ps -Eww -o command= -p $PPID | tr ' ' '\\n' | grep LAUNCH_SECRET; ps -Eww -o command= -p $PPID > "$OUT"`;

test("a secret in the coordinator's launch environment, read from the parent process, is redacted from the log", () => {
  const secret = "launch-secret-value-5678";
  const out = join(scratch, "proc-dump-plain");
  const r = runInChild(
    {
      testContent: ADD_TEST,
      testCommand: `${READ_PARENT_ENV}; node test/finding-1.test.js`,
      env: { PATH, OUT: out },
    },
    secret,
  );
  assert.equal(r.reproduced, true, r.log);
  assert.ok(!r.log.includes(secret), "log leaks the launch secret");
  assert.match(r.log, /LAUNCH_SECRET_TOKEN=<redacted>/);
  // Redaction protects the log only: without a sandbox the command can still
  // read the value, which is why untrusted findings need `sandbox`.
  assert.ok(readFileSync(out, "utf8").includes(secret));
});

const sandboxWorks =
  spawnSync(PID_NAMESPACE_SANDBOX[0] ?? "", [...PID_NAMESPACE_SANDBOX.slice(1), "/bin/sh", "-c", "true"], { stdio: "ignore" })
    .status === 0;

test("with the PID-namespace sandbox the command cannot see the coordinator's processes or outlive the run", { skip: !sandboxWorks && "unshare/setpriv sandbox unavailable" }, async () => {
  const secret = "sandboxed-secret-value-9012";
  const out = join(scratch, "proc-dump-sandbox");
  const late = join(scratch, "daemon-survived");
  const r = runInChild(
    {
      testContent: ADD_TEST,
      testCommand: [
        `cat /proc/[0-9]*/environ > "$OUT" 2>/dev/null`,
        `umount /proc 2>/dev/null && echo UM""OUNTED`,
        `unshare --user --mount sh -c 'umount /proc' 2>/dev/null && echo UM""OUNTED-NESTED`,
        `setsid sh -c 'sleep 2; echo alive > "$LATE"' &`,
        `node test/finding-1.test.js`,
      ].join("\n"),
      env: { PATH, OUT: out, LATE: late },
      sandbox: PID_NAMESPACE_SANDBOX,
    },
    secret,
  );
  assert.equal(r.reproduced, true, r.log);
  assert.equal(r.harnessError, null);
  assert.doesNotMatch(r.log, /UMOUNTED/);
  assert.ok(!readFileSync(out, "utf8").includes(secret), "sandboxed command read the coordinator's environment");
  await new Promise((done) => setTimeout(done, 3000));
  assert.equal(existsSync(late), false, "a setsid daemon outlived the sandboxed run");
});

test("the sandbox preserves exit codes, signals and timeouts", { skip: !sandboxWorks && "unshare/setpriv sandbox unavailable" }, async () => {
  const sig = `const { add } = require("../math.js"); if (add(2, 3) !== 5) process.kill(process.pid, "SIGSEGV");\n`;
  const a = await reproduceFinding(opts({ testContent: sig, testCommand: "exec node test/finding-1.test.js", sandbox: PID_NAMESPACE_SANDBOX }));
  assert.equal(a.reproduced, true, a.log);
  assert.match(a.log, /=== head: exit 139 ===/);
  const b = await reproduceFinding(opts({ testContent: "process.exit(3);\n", sandbox: PID_NAMESPACE_SANDBOX }));
  assert.match(b.log, /=== head: exit 3 ===/);
  const c = await reproduceFinding(opts({ testContent: ADD_TEST, testCommand: "setsid sleep 1000 & sleep 1000", timeoutMs: 1000, sandbox: PID_NAMESPACE_SANDBOX }));
  assert.match(c.harnessError ?? "", /^head: timed out/);
  assert.equal(c.reproduced, false);
});

function killPids(file: string): void {
  if (!existsSync(file)) return;
  for (const pid of readFileSync(file, "utf8").trim().split("\n").map(Number)) {
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // already gone
    }
  }
}

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

test("a sandbox that cannot use its checkout is a harness error, never a false finding", async () => {
  // A stand-in for a uid switch that cannot enter the harness's 0700 temp
  // directory: the sandbox runs the command somewhere else entirely.
  const elsewhere = mkdtempSync(join(tmpdir(), "findings-elsewhere-"));
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, sandbox: ["/bin/sh", "-c", `cd ${elsewhere} && exec "$@"`, "box"] }));
  assert.equal(r.reproduced, false);
  assert.match(r.harnessError ?? "", /cannot read and write its checkout/);
  assert.equal(r.passesOnParent, false, "the test never ran");
  rmSync(elsewhere, { recursive: true, force: true });
});

test("setupCommand runs in each checkout before the test; a failed setup is a harness error", async () => {
  const withDeps = await reproduceFinding(
    opts({
      testContent: ADD_TEST,
      setupCommand: "echo installed > deps.txt",
      testCommand: "test -f deps.txt && node test/finding-1.test.js",
    }),
  );
  assert.equal(withDeps.reproduced, true, withDeps.log);
  const broken = await reproduceFinding(opts({ testContent: ADD_TEST, setupCommand: "exit 3" }));
  assert.equal(broken.reproduced, false);
  assert.match(broken.harnessError ?? "", /setup command failed \(exit 3\)/);
});

test("regression: a commit holding the harness's old probe names cannot turn findings into harness errors", async () => {
  // A head that is the buggy head plus files named after the probe's former
  // fixed sentinel and write target (one a file, one a directory).
  sh(["checkout", "-q", "-b", "probe-names", head]);
  writeFileSync(join(repo, ".commons-harness-sentinel"), "taken\n");
  mkdirSync(join(repo, ".commons-harness-write"));
  writeFileSync(join(repo, ".commons-harness-write", "x"), "x\n");
  sh(["add", "."]);
  sh(["commit", "-q", "-m", "squat the probe names"]);
  const squatter = sh(["rev-parse", "HEAD"]);
  sh(["checkout", "-q", "main"]);
  const r = await reproduceFinding(opts({ testContent: ADD_TEST, headCommit: squatter }));
  assert.equal(r.harnessError, null, r.log);
  assert.equal(r.reproduced, true);
});

test("regression: with shareCheckout, files the setup step made that the harness cannot chmod do not break the run", { skip: spawnSync("chflags", ["-h"]).error ? "needs chflags (BSD, macOS) to make a file the coordinator cannot chmod" : false }, async () => {
  // An immutable file stands in for one the sandbox uid created during setup
  // (node_modules from `npm ci` under scripts/sandbox-docker on Linux).
  const tmpRoot = mkdtempSync(join(tmpdir(), "findings-setup-"));
  try {
    const r = await reproduceFinding(
      opts({
        testContent: ADD_TEST,
        tmpRoot,
        shareCheckout: true,
        setupCommand: "mkdir -p node_modules/dep && echo x > node_modules/dep/index.js && chflags uchg node_modules/dep/index.js",
      }),
    );
    assert.equal(r.harnessError, null, r.log);
    assert.equal(r.reproduced, true);
  } finally {
    spawnSync("chflags", ["-R", "nouchg", tmpRoot]);
    rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test("regression: leftovers only the sandbox can remove are cleaned up through the sandbox", { skip: spawnSync("chflags", ["-h"]).error ? "needs chflags (BSD, macOS) to make a file the coordinator cannot remove" : false }, async () => {
  // Stand-in for a sandbox uid's 0700 directories on a Linux bind mount: an
  // immutable file the coordinator cannot delete, which every run under this
  // sandbox can undo (as the sandbox uid could chmod its own files).
  const tmpRoot = mkdtempSync(join(tmpdir(), "findings-cleanup-"));
  const sandbox = ["/bin/sh", "-c", 'chflags -R nouchg . 2>/dev/null; exec "$@"', "box"];
  try {
    const r = await reproduceFinding(
      opts({
        testContent: ADD_TEST,
        tmpRoot,
        sandbox,
        shareCheckout: true,
        testCommand: "node test/finding-1.test.js; rc=$?; mkdir -p junk && echo x > junk/f && chflags uchg junk/f; exit $rc",
      }),
    );
    assert.equal(r.reproduced, true, r.log);
    assert.equal(r.cleanupError, null);
    assert.deepEqual(harnessTempDirs(tmpRoot), []);
  } finally {
    spawnSync("chflags", ["-R", "nouchg", tmpRoot]);
    rmSync(tmpRoot, { recursive: true, force: true });
  }
});

// A writer outside the harness's process group (as a container runs under
// dockerd) that keeps swapping directories of `root` for symlinks to `victim`.
const SWAPPER = `const fs = require("node:fs"), path = require("node:path");
const [root, victim, ms] = process.argv.slice(1);
const end = Date.now() + Number(ms);
const dirs = Array.from({ length: 40 }, (_, i) => path.join(root, "d" + i));
const mk = (d) => { try { fs.mkdirSync(d); fs.writeFileSync(path.join(d, "f"), "x"); } catch {} };
dirs.forEach(mk);
while (Date.now() < end) {
  for (const d of dirs) { try { fs.renameSync(d, d + ".x"); } catch {} try { fs.symlinkSync(victim, d); } catch {} }
  for (const d of dirs) { try { fs.unlinkSync(d); } catch {} try { fs.rmSync(d + ".x", { recursive: true, force: true }); } catch {} mk(d); }
}`;

test("regression: removeTree never deletes through a symlink a still-running writer swaps in", async () => {
  const base = mkdtempSync(join(tmpdir(), "findings-swap-"));
  const root = join(base, "root");
  const victim = join(base, "victim");
  mkdirSync(root);
  mkdirSync(victim);
  for (let i = 0; i < 500; i++) writeFileSync(join(victim, `canary-${i}`), "x");
  const writer = spawn(process.execPath, ["-e", SWAPPER, root, victim, "4000"], { detached: true, stdio: "ignore" });
  try {
    await new Promise((r) => setTimeout(r, 300));
    const until = Date.now() + 3000;
    while (Date.now() < until) {
      await removeTree(root);
      mkdirSync(root, { recursive: true });
    }
  } finally {
    try {
      process.kill(-(writer.pid as number), "SIGKILL");
    } catch {
      // already gone
    }
  }
  assert.equal(readdirSync(victim).length, 500, "cleanup deleted files outside the tree it was removing");
  rmSync(base, { recursive: true, force: true });
});

test("regression: a timed-out run's sandbox gets SIGTERM first, so it can stop a command that runs outside the harness's group", async () => {
  // The fake sandbox starts the command in its own session (as docker runs a
  // container under its daemon, beyond the client's process group) and stops
  // it on SIGTERM, as scripts/sandbox-docker kills its container.
  const dir = mkdtempSync(join(tmpdir(), "findings-term-"));
  const box = join(dir, "box.js");
  const ticks = join(dir, "ticks");
  writeFileSync(
    box,
    `const { spawn } = require("node:child_process");
const c = spawn(process.argv[2], process.argv.slice(3), { detached: true, stdio: "inherit" });
require("node:fs").appendFileSync(${JSON.stringify(join(dir, "pids"))}, c.pid + "\\n");
process.on("SIGTERM", () => { try { process.kill(-c.pid, "SIGKILL"); } catch {} });
c.on("exit", (code) => process.exit(code ?? 143));\n`,
  );
  try {
    const r = await reproduceFinding(
      opts({ testContent: ADD_TEST, sandbox: [process.execPath, box], testCommand: `node test/finding-1.test.js && while :; do echo x >> ${ticks}; sleep 0.05; done`, timeoutMs: 1500 }),
    );
    assert.match(r.harnessError ?? "", /timed out/);
    const size = readFileSync(ticks).length;
    await new Promise((res) => setTimeout(res, 500));
    assert.equal(readFileSync(ticks).length, size, "the sandboxed command kept running after the harness returned");
  } finally {
    for (const pid of readFileSync(join(dir, "pids"), "utf8").trim().split("\n").map(Number)) {
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        // already gone
      }
    }
    rmSync(dir, { recursive: true, force: true });
  }
});
