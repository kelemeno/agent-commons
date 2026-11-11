// The reproduction harness. A finding counts only if its test fails on the
// submission's head and passes on its parent; this module is the one place that
// decides that, by running the test, never by reading anyone's prose.
//
// Each commit is checked out into its own detached `git worktree` under a fresh
// temporary directory, the finding's test file is written into it, and the
// finding's command runs there with a minimal environment. The worktrees and
// the temporary directory are removed whatever happens.
//
// This is NOT a sandbox. The command runs as the coordinator's user and can
// read anything that user can read. The minimal environment only keeps secrets
// that live in environment variables out of reach; run the harness as an
// unprivileged user (or in a container) for untrusted findings.
//
// Outcome rules:
// - failsOnHead  = the head run finished with a non-zero exit code or died of a
//   signal it was not sent by the harness.
// - passesOnParent = the base run finished with exit code 0.
// - A timeout, a spawn failure, a commit that does not resolve, or a testPath
//   that escapes the worktree through a symlink is a harness error: that run
//   counts as neither failing nor passing, so it can never produce a
//   reproduction. `harnessError` says what happened; callers should not treat a
//   harness error as a false finding without looking.
// - A testPath that is absolute, empty, climbs out with "..", or touches `.git`
//   is a caller error and rejects before anything is checked out.

import { execFile, spawn, type ChildProcessByStdio } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, posix } from "node:path";
import type { Readable } from "node:stream";
import type { CommitSha } from "./types";

export type ReproduceOptions = {
  repoDir: string;
  baseCommit: CommitSha;
  headCommit: CommitSha;
  testPath: string; // relative POSIX path inside the repo
  testContent: string;
  testCommand: string; // run with /bin/sh -c in the worktree root
  timeoutMs?: number; // per run; default DEFAULT_TIMEOUT_MS
  env?: Record<string, string>; // extra variables; secret-looking names are dropped
};

export type ReproductionResult = {
  failsOnHead: boolean;
  passesOnParent: boolean;
  reproduced: boolean; // failsOnHead && passesOnParent
  log: string;
  logDigest: string; // sha256 hex of log
  harnessError: string | null; // first harness error, if any run had one
};

export const DEFAULT_TIMEOUT_MS = 120_000;
export const MAX_LOG_BYTES_PER_RUN = 64 * 1024;

// Any variable whose name contains one of these (case-insensitive) is never
// passed to the command, even when the caller lists it in opts.env. Matching is
// deliberately broad: dropping a harmless MONKEY_COUNT costs nothing, leaking a
// deploy key costs a lot.
const SECRET_NAME_PARTS = ["TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH"];

export function isSecretName(name: string): boolean {
  const upper = name.toUpperCase();
  return SECRET_NAME_PARTS.some((part) => upper.includes(part));
}

// The whole environment the command sees. Nothing is inherited from
// process.env except PATH (when opts.env has none). HOME, CI and LANG are fixed
// so a test cannot pick up the operator's dotfiles and so runs on different
// machines see the same locale; extras cannot override them.
export function minimalEnv(home: string, extra: Record<string, string> = {}): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [name, value] of Object.entries(extra)) {
    if (!isSecretName(name)) env[name] = value;
  }
  env.PATH = extra.PATH ?? process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin";
  env.HOME = home;
  env.CI = "1";
  env.LANG = "C.UTF-8";
  return env;
}

// Lexical validation of a finding's testPath. Returns the normalised relative
// path or throws. Symlinks are checked later, per worktree, because whether a
// component is a symlink depends on the commit.
export function checkTestPath(testPath: string): string {
  if (testPath === "" || testPath.includes("\0")) throw new Error("testPath must be a non-empty path");
  if (testPath.startsWith("/") || testPath.includes("\\") || /^[A-Za-z]:/.test(testPath)) {
    throw new Error(`testPath must be a relative POSIX path: ${JSON.stringify(testPath)}`);
  }
  const parts = testPath.split("/");
  if (parts.includes("..")) throw new Error(`testPath must not contain "..": ${JSON.stringify(testPath)}`);
  const normal = posix.normalize(testPath);
  if (normal === "." || normal.endsWith("/")) throw new Error(`testPath must name a file: ${JSON.stringify(testPath)}`);
  // `.git` in a worktree is a pointer file to the main repository's metadata;
  // overwriting it would redirect our own cleanup commands.
  if (normal.split("/").some((p) => p.toLowerCase() === ".git")) {
    throw new Error(`testPath must not touch .git: ${JSON.stringify(testPath)}`);
  }
  return normal;
}

export async function reproduceFinding(opts: ReproduceOptions): Promise<ReproductionResult> {
  const testPath = checkTestPath(opts.testPath);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error("timeoutMs must be a positive number");

  const root = await mkdtemp(join(tmpdir(), "anthill-finding-"));
  const created: string[] = [];
  try {
    const run = async (role: "head" | "base", commit: CommitSha): Promise<RunResult> => {
      const worktree = join(root, role);
      const home = join(root, `home-${role}`);
      await mkdir(home);
      const sha = await resolveCommit(opts.repoDir, commit);
      if (sha.error !== null) return harnessFailure(role, commit, sha.error);
      try {
        await git(opts.repoDir, ["worktree", "add", "--detach", worktree, sha.value]);
      } catch (err) {
        return harnessFailure(role, sha.value, `git worktree add failed: ${message(err)}`);
      }
      created.push(worktree);
      try {
        await writeInside(worktree, testPath, opts.testContent);
      } catch (err) {
        return harnessFailure(role, sha.value, message(err));
      }
      const env = minimalEnv(home, opts.env);
      const outcome = await runCommand(opts.testCommand, worktree, env, timeoutMs);
      const scrub = await scrubber([worktree, home, root]);
      return { role, sha: sha.value, outcome, output: scrub(outcome.output.toString("utf8")) };
    };

    const head = await run("head", opts.headCommit);
    const base = await run("base", opts.baseCommit);

    const failsOnHead = head.outcome.kind === "exit" ? head.outcome.code !== 0 : head.outcome.kind === "signal";
    const passesOnParent = base.outcome.kind === "exit" && base.outcome.code === 0;
    const log = [head, base].map((r) => formatRun(r, opts.testCommand)).join("");
    const harnessError = [head, base].map(errorOf).find((e) => e !== null) ?? null;
    return {
      failsOnHead,
      passesOnParent,
      reproduced: failsOnHead && passesOnParent,
      log,
      logDigest: createHash("sha256").update(log, "utf8").digest("hex"),
      harnessError,
    };
  } finally {
    for (const worktree of created) {
      await git(opts.repoDir, ["worktree", "remove", "--force", worktree]).catch(() => undefined);
    }
    await git(opts.repoDir, ["worktree", "prune"]).catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }
}

type Outcome =
  | { kind: "exit"; code: number; output: Buffer; truncated: number }
  | { kind: "signal"; signal: string; output: Buffer; truncated: number }
  | { kind: "timeout"; output: Buffer; truncated: number }
  | { kind: "error"; error: string; output: Buffer; truncated: number };

type RunResult = { role: "head" | "base"; sha: string; outcome: Outcome; output: string };

function harnessFailure(role: "head" | "base", sha: string, error: string): RunResult {
  return { role, sha, outcome: { kind: "error", error, output: Buffer.alloc(0), truncated: 0 }, output: "" };
}

function errorOf(r: RunResult): string | null {
  if (r.outcome.kind === "error") return `${r.role}: ${r.outcome.error}`;
  if (r.outcome.kind === "timeout") return `${r.role}: timed out`;
  return null;
}

// Headers carry the resolved commit and the command but no temp paths or
// timings, and output has temp paths replaced, so the same finding on the same
// commits yields the same log digest on every run.
function formatRun(r: RunResult, command: string): string {
  const o = r.outcome;
  const status =
    o.kind === "exit"
      ? `exit ${o.code}`
      : o.kind === "signal"
        ? `killed by ${o.signal}`
        : o.kind === "timeout"
          ? "timeout: process group killed (harness error, not a failure)"
          : `harness error: ${o.error}`;
  let text = `=== ${r.role} ${r.sha} ===\n$ ${command}\n${r.output}`;
  if (r.output !== "" && !r.output.endsWith("\n")) text += "\n";
  if (o.truncated > 0) text += `[output truncated: ${o.truncated} more bytes]\n`;
  return `${text}=== ${r.role}: ${status} ===\n`;
}

async function scrubber(paths: string[]): Promise<(s: string) => string> {
  const pairs: [string, string][] = [];
  for (const [i, p] of paths.entries()) {
    const label = ["<worktree>", "<home>", "<tmp>"][i] ?? "<tmp>";
    pairs.push([p, label]);
    const real = await realpath(p).catch(() => p);
    if (real !== p) pairs.push([real, label]);
  }
  // Longest first, so a worktree inside the temp root is not half-replaced.
  pairs.sort((a, b) => b[0].length - a[0].length);
  return (s) => pairs.reduce((acc, [from, to]) => acc.split(from).join(to), s);
}

// Writes the test file, creating missing directories, and refuses to follow a
// symlink anywhere on the way: a commit can contain `test -> /etc`, and writing
// through it would put the finding's file outside the worktree.
async function writeInside(worktree: string, relPath: string, content: string): Promise<void> {
  const parts = relPath.split("/");
  let current = worktree;
  for (const [i, part] of parts.entries()) {
    current = join(current, part);
    const last = i === parts.length - 1;
    const st = await lstat(current).catch((err: NodeJS.ErrnoException) => {
      if (err.code === "ENOENT") return null;
      throw err;
    });
    if (st?.isSymbolicLink()) throw new Error(`testPath goes through a symlink in this commit: ${parts.slice(0, i + 1).join("/")}`);
    if (last) {
      if (st !== null && !st.isFile()) throw new Error(`testPath exists and is not a regular file: ${relPath}`);
    } else if (st === null) {
      await mkdir(current);
    } else if (!st.isDirectory()) {
      throw new Error(`testPath component is not a directory: ${parts.slice(0, i + 1).join("/")}`);
    }
  }
  await writeFile(current, content, "utf8");
}

// Runs the command in its own process group so that a timeout kills everything
// it started, not just the shell. Once the shell exits, any stragglers it left
// in the group are killed too, so a backgrounded daemon holding stdout open
// cannot turn a finished run into a timeout or outlive the worktree.
function runCommand(command: string, cwd: string, env: Record<string, string>, timeoutMs: number): Promise<Outcome> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let kept = 0;
    let truncated = 0;
    const collect = (chunk: Buffer): void => {
      const room = Math.max(0, MAX_LOG_BYTES_PER_RUN - kept);
      const part = chunk.subarray(0, room);
      if (part.length > 0) chunks.push(part);
      kept += part.length;
      truncated += chunk.length - part.length;
    };
    let settled = false;
    const finish = (o: Outcome): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(o);
    };

    let child: ChildProcessByStdio<null, Readable, Readable>;
    try {
      child = spawn("/bin/sh", ["-c", command], { cwd, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    } catch (err) {
      resolve({ kind: "error", error: `spawn failed: ${message(err)}`, output: Buffer.alloc(0), truncated: 0 });
      return;
    }
    const pid = child.pid;
    const killGroup = (): void => {
      if (pid === undefined) return;
      try {
        process.kill(-pid, "SIGKILL");
      } catch {
        // ESRCH: the group is already gone.
      }
    };

    let timedOut = false;
    let exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
    const timer = setTimeout(() => {
      if (exit === null) {
        timedOut = true;
        killGroup();
      } else {
        // The shell finished but something that left the process group still
        // holds our pipes; stop waiting for it rather than call this a timeout.
        child.stdout.destroy();
        child.stderr.destroy();
      }
    }, timeoutMs);

    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.on("error", (err) => {
      killGroup();
      finish({ kind: "error", error: `spawn failed: ${message(err)}`, output: Buffer.concat(chunks), truncated });
    });
    child.on("exit", (code, signal) => {
      exit = { code, signal };
      killGroup();
    });
    child.on("close", () => {
      const output = Buffer.concat(chunks);
      if (timedOut) finish({ kind: "timeout", output, truncated });
      else if (exit === null) finish({ kind: "error", error: "process closed without an exit status", output, truncated });
      else if (exit.code !== null) finish({ kind: "exit", code: exit.code, output, truncated });
      else finish({ kind: "signal", signal: exit.signal ?? "unknown signal", output, truncated });
    });
  });
}

// Resolves to a full commit sha. `--end-of-options` stops a "commit" such as
// "--output=/tmp/x" from being read as a git option.
async function resolveCommit(repoDir: string, commit: string): Promise<{ value: string; error: null } | { value: null; error: string }> {
  if (commit === "" || commit.startsWith("-")) return { value: null, error: `invalid commit ${JSON.stringify(commit)}` };
  try {
    const out = await git(repoDir, ["rev-parse", "--verify", "--quiet", "--end-of-options", `${commit}^{commit}`]);
    return { value: out.trim(), error: null };
  } catch {
    return { value: null, error: `commit does not resolve: ${JSON.stringify(commit)}` };
  }
}

// Our own git calls inherit the operator's environment (for git config and
// PATH) minus GIT_* variables, which would otherwise point git at whatever
// repository the coordinator happened to be launched from.
function git(repoDir: string, args: string[]): Promise<string> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !k.startsWith("GIT_")) env[k] = v;
  }
  return new Promise((resolve, reject) => {
    execFile("git", ["-C", repoDir, ...args], { env, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${err.message.trim()}${stderr ? `\n${stderr.trim()}` : ""}`));
      else resolve(stdout);
    });
  });
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
