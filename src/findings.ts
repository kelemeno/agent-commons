// The reproduction harness. A finding counts only if its test fails on the
// submission's head and passes on its parent; this module is the one place that
// decides that, by running the test, never by reading anyone's prose.
//
// Both commits are resolved to full shas and exported into plain directories
// under one fresh temporary directory BEFORE any untrusted code runs. After
// that the harness never runs git against the operator's repository again, so
// nothing a command does (planting hooks, moving refs, `git replace`, editing
// .git/config) can steer the harness's own git processes or change which tree
// the other run sees. The checkouts have no `.git` at all: they are made with
// `read-tree` into a private index plus `checkout-index`, which gives real
// checkout semantics (attributes, eol, symlinks, modes) without linking the
// directory to the repository the way a `git worktree` does. Base runs first,
// so the head commit's code (the submission under test) has no chance to
// tamper with the parent run.
//
// Threat model, stated plainly:
// - Without `sandbox`, this is NOT isolation. The command runs as the
//   coordinator's uid: it can read and write anything that uid can, including
//   the operator's repository by absolute path, and it can read the
//   coordinator's launch environment through /proc/<ppid>/environ. The minimal
//   environment only stops secrets from being handed to the command; it does
//   not stop a hostile command from fetching them. As a guard against
//   accidental leaks, the values of secret-named variables are redacted from
//   the log, but a hostile command can trivially encode a value past that.
// - With `sandbox: PID_NAMESPACE_SANDBOX` the command runs in its own user,
//   PID and mount namespaces with every capability dropped: it cannot see the
//   coordinator's (or any other) processes, so /proc/<pid>/environ and
//   /proc/<pid>/mem are out of reach, and every process it starts dies with
//   it, even ones that call setsid. It can still read and write the
//   filesystem as the coordinator's uid. Findings from strangers need that
//   plus a separate uid or a container; this module cannot provide that.
//
// Outcome rules:
// - failsOnHead  = the head run finished with a non-zero exit code or died of a
//   signal it was not sent by the harness.
// - passesOnParent = the base run finished with exit code 0.
// - A timeout, a spawn failure, a commit that does not resolve, or a testPath
//   that escapes the checkout through a symlink is a harness error: that run
//   counts as neither failing nor passing, so it can never produce a
//   reproduction. `harnessError` says what happened; callers should not treat a
//   harness error as a false finding without looking.
// - Failing to delete the temporary directory afterwards is reported in
//   `cleanupError` and never changes the outcome: the head commit's code runs
//   in the harness, and making cleanup fail must not be a way to void a
//   finding against it.
// - A testPath that is absolute, empty, climbs out with "..", or touches `.git`,
//   and a timeout outside (0, MAX_TIMEOUT_MS], are caller errors and reject
//   before anything is checked out.

import { execFile, spawn, type ChildProcessByStdio } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
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
  testCommand: string; // run with /bin/sh -c in the checkout root
  timeoutMs?: number; // per run; default DEFAULT_TIMEOUT_MS, at most MAX_TIMEOUT_MS
  env?: Record<string, string>; // extra variables; secret-looking names are dropped
  // argv prefix the shell is run under, e.g. PID_NAMESPACE_SANDBOX. It is
  // spawned with the same minimal environment, so it must be on that PATH.
  sandbox?: readonly string[];
};

export type ReproductionResult = {
  failsOnHead: boolean;
  passesOnParent: boolean;
  reproduced: boolean; // failsOnHead && passesOnParent
  log: string;
  logDigest: string; // sha256 hex of log
  harnessError: string | null; // first harness error, if any run had one
  cleanupError: string | null; // the temp dir could not be fully removed; outcome unaffected
};

export const DEFAULT_TIMEOUT_MS = 120_000;
// setTimeout silently turns larger delays into 1 ms.
export const MAX_TIMEOUT_MS = 2_147_483_647;
export const MAX_LOG_BYTES_PER_RUN = 64 * 1024;
// How long to keep reading output after the shell has exited or been killed.
// A descendant that left the process group can hold the pipes open forever.
export const DRAIN_MS = 1_000;

// util-linux recipe: new user/PID/mount namespaces with a private /proc, then
// drop every capability so the command cannot unmount that /proc to uncover
// the host's. --kill-child makes the namespace die with the harness's kill.
// The trailing shell is the namespace's PID 1 so the test is not: the kernel
// drops signals PID 1 has no handler for, so a test that crashes itself would
// otherwise exit 0. The cost is that a death by signal N is reported as exit
// 128+N, which still counts as failing.
export const PID_NAMESPACE_SANDBOX: readonly string[] = [
  "unshare",
  "--user",
  "--map-root-user",
  "--pid",
  "--fork",
  "--mount-proc",
  "--kill-child",
  "setpriv",
  "--bounding-set=-all",
  "--inh-caps=-all",
  "--no-new-privs",
  "/bin/sh",
  "-c",
  '"$@"; exit $?',
  "sandbox-init",
];

// Any variable whose name contains one of these (case-insensitive) is never
// passed to the command, even when the caller lists it in opts.env, and its
// value is redacted from the log. Matching is deliberately broad: dropping a
// harmless MONKEY_COUNT costs nothing, leaking a deploy key costs a lot.
const SECRET_NAME_PARTS = ["TOKEN", "KEY", "SECRET", "PASSWORD", "PASSWD", "CREDENTIAL", "AUTH"];
// Shorter values are not redacted: replacing every "1" or "true" in a log
// would destroy it, and a secret that short is not protecting anything.
const MIN_REDACTED_LENGTH = 6;
const REDACTED = "<redacted>";

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
// path or throws. Symlinks are checked later, per checkout, because whether a
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
  // A test that creates `.git` would turn the checkout back into something git
  // commands inside it treat as a repository.
  if (normal.split("/").some((p) => p.toLowerCase() === ".git")) {
    throw new Error(`testPath must not touch .git: ${JSON.stringify(testPath)}`);
  }
  return normal;
}

type Role = "head" | "base";
type Prepared = { role: Role; sha: string; dir: string; home: string; error: string | null };

export async function reproduceFinding(opts: ReproduceOptions): Promise<ReproductionResult> {
  const testPath = checkTestPath(opts.testPath);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > MAX_TIMEOUT_MS) {
    throw new Error(`timeoutMs must be in (0, ${MAX_TIMEOUT_MS}]`);
  }
  const sandbox = opts.sandbox ?? [];
  if (opts.sandbox !== undefined && (sandbox.length === 0 || sandbox.some((a) => typeof a !== "string" || a === ""))) {
    throw new Error("sandbox must be a non-empty argv of non-empty strings");
  }
  // Collected before any untrusted code runs.
  const secrets = await secretValues(opts.env ?? {});

  const root = await mkdtemp(join(tmpdir(), "anthill-finding-"));
  let outcome: Omit<ReproductionResult, "cleanupError">;
  try {
    outcome = await reproduceIn(root, opts, testPath, timeoutMs, sandbox, secrets);
  } catch (err) {
    await removeTree(root);
    throw err;
  }
  return { ...outcome, cleanupError: await removeTree(root) };
}

async function reproduceIn(
  root: string,
  opts: ReproduceOptions,
  testPath: string,
  timeoutMs: number,
  sandbox: readonly string[],
  secrets: string[],
): Promise<Omit<ReproductionResult, "cleanupError">> {
  // Everything that touches the repository happens here, before any command.
  const prepared: Prepared[] = [];
  for (const [role, commit] of [["base", opts.baseCommit], ["head", opts.headCommit]] as const) {
    prepared.push(await prepare(root, opts.repoDir, role, commit, testPath, opts.testContent));
  }

  const runs: RunResult[] = [];
  for (const p of prepared) {
    if (p.error !== null) {
      runs.push(harnessFailure(p.role, p.sha, p.error));
      continue;
    }
    const env = minimalEnv(p.home, opts.env);
    const outcome = await runCommand(opts.testCommand, p.dir, env, timeoutMs, sandbox);
    const scrub = await scrubber([p.dir, p.home, root]);
    const output = scrub(redact(outcome.output.toString("utf8"), secrets, outcome.truncated > 0));
    runs.push({ role: p.role, sha: p.sha, outcome, output });
  }
  const [base, head] = runs as [RunResult, RunResult];

  const failsOnHead = head.outcome.kind === "exit" ? head.outcome.code !== 0 : head.outcome.kind === "signal";
  const passesOnParent = base.outcome.kind === "exit" && base.outcome.code === 0;
  const log = runs.map((r) => formatRun(r, opts.testCommand)).join("");
  return {
    failsOnHead,
    passesOnParent,
    reproduced: failsOnHead && passesOnParent,
    log,
    logDigest: createHash("sha256").update(log, "utf8").digest("hex"),
    harnessError: [head, base].map(errorOf).find((e) => e !== null) ?? null,
  };
}

// Never throws: every failure becomes that run's harness error.
async function prepare(root: string, repoDir: string, role: Role, commit: string, testPath: string, content: string): Promise<Prepared> {
  const dir = join(root, role);
  const home = join(root, `home-${role}`);
  const resolved = await resolveCommit(repoDir, commit, root);
  const sha = resolved.value ?? commit;
  if (resolved.error !== null) return { role, sha, dir, home, error: resolved.error };
  try {
    await mkdir(dir);
    await mkdir(home);
  } catch (err) {
    return { role, sha, dir, home, error: `could not create checkout: ${message(err)}` };
  }
  try {
    const index = { GIT_INDEX_FILE: join(root, `index-${role}`) };
    await git(repoDir, ["read-tree", sha], root, index);
    await git(repoDir, ["checkout-index", "--all", "--force", `--prefix=${dir}/`], root, index);
  } catch (err) {
    return { role, sha, dir, home, error: `checkout failed: ${message(err)}` };
  }
  try {
    await writeInside(dir, testPath, content);
  } catch (err) {
    return { role, sha, dir, home, error: message(err) };
  }
  return { role, sha, dir, home, error: null };
}

type Outcome =
  | { kind: "exit"; code: number; output: Buffer; truncated: number }
  | { kind: "signal"; signal: string; output: Buffer; truncated: number }
  | { kind: "timeout"; output: Buffer; truncated: number }
  | { kind: "error"; error: string; output: Buffer; truncated: number };

type RunResult = { role: Role; sha: string; outcome: Outcome; output: string };

function harnessFailure(role: Role, sha: string, error: string): RunResult {
  return { role, sha, outcome: { kind: "error", error, output: Buffer.alloc(0), truncated: 0 }, output: "" };
}

function errorOf(r: RunResult): string | null {
  if (r.outcome.kind === "error") return `${r.role}: ${r.outcome.error}`;
  if (r.outcome.kind === "timeout") return `${r.role}: timed out`;
  return null;
}

// Runs appear in the order they ran (base, then head). Headers carry the
// resolved commit and the command but no temp paths or timings, and output has
// temp paths replaced, so the same finding on the same commits yields the same
// log digest on every run.
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
  // Longest first, so a checkout inside the temp root is not half-replaced.
  pairs.sort((a, b) => b[0].length - a[0].length);
  return (s) => pairs.reduce((acc, [from, to]) => acc.split(from).join(to), s);
}

// Values of secret-named variables in the coordinator's current environment,
// in the environment it was launched with (what /proc/<pid>/environ shows,
// which runtime changes to process.env do not touch), and in opts.env.
async function secretValues(extra: Record<string, string>): Promise<string[]> {
  const pairs: [string, string | undefined][] = [...Object.entries(process.env), ...Object.entries(extra)];
  const launch = await readFile("/proc/self/environ", "utf8").catch(() => "");
  for (const entry of launch.split("\0")) {
    const eq = entry.indexOf("=");
    if (eq > 0) pairs.push([entry.slice(0, eq), entry.slice(eq + 1)]);
  }
  const values = new Set<string>();
  for (const [name, value] of pairs) {
    if (value !== undefined && value.length >= MIN_REDACTED_LENGTH && isSecretName(name)) values.add(value);
  }
  // Longest first, so a secret containing another is replaced whole.
  return [...values].sort((a, b) => b.length - a.length);
}

// When the output was truncated, a secret can straddle the cut; whatever
// prefix of it survived is dropped too.
export function redact(text: string, secrets: readonly string[], truncated: boolean): string {
  let out = text;
  for (const s of secrets) out = out.split(s).join(REDACTED);
  if (!truncated) return out;
  for (const s of secrets) {
    for (let k = Math.min(s.length - 1, out.length); k > 0; k--) {
      if (out.endsWith(s.slice(0, k))) {
        out = out.slice(0, out.length - k);
        break;
      }
    }
  }
  return out;
}

// Writes the test file, creating missing directories, and refuses to follow a
// symlink anywhere on the way: a commit can contain `test -> /etc`, and writing
// through it would put the finding's file outside the checkout.
async function writeInside(dir: string, relPath: string, content: string): Promise<void> {
  const parts = relPath.split("/");
  let current = dir;
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
// it started, not just the shell. Once the shell exits, stragglers left in the
// group are killed too. A descendant that left the group (setsid) is out of
// reach without a sandbox; the promise still settles DRAIN_MS after the shell
// exits or is killed, whoever holds the pipes.
export function runCommand(
  command: string,
  cwd: string,
  env: Record<string, string>,
  timeoutMs: number,
  sandbox: readonly string[] = [],
): Promise<Outcome> {
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

    const argv = [...sandbox, "/bin/sh", "-c", command];
    let child: ChildProcessByStdio<null, Readable, Readable>;
    try {
      child = spawn(argv[0] as string, argv.slice(1), { cwd, env, detached: true, stdio: ["ignore", "pipe", "pipe"] });
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
    let spawnError: string | null = null;
    let exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
    let drain: NodeJS.Timeout | undefined;
    let settled = false;
    const settle = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(drain);
      child.stdout.destroy();
      child.stderr.destroy();
      const output = Buffer.concat(chunks);
      if (spawnError !== null) resolve({ kind: "error", error: `spawn failed: ${spawnError}`, output, truncated });
      else if (timedOut) resolve({ kind: "timeout", output, truncated });
      else if (exit === null) resolve({ kind: "error", error: "process closed without an exit status", output, truncated });
      else if (exit.code !== null) resolve({ kind: "exit", code: exit.code, output, truncated });
      else resolve({ kind: "signal", signal: exit.signal ?? "unknown signal", output, truncated });
    };
    const armDrain = (): void => {
      if (drain === undefined) drain = setTimeout(settle, DRAIN_MS);
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killGroup();
      armDrain();
    }, timeoutMs);

    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.on("error", (err) => {
      spawnError = message(err);
      killGroup();
      settle();
    });
    child.on("exit", (code, signal) => {
      // An exit racing the timer after it fired is still a timeout: the
      // SIGKILL it reports is ours.
      if (!timedOut) clearTimeout(timer);
      exit = { code, signal };
      killGroup();
      armDrain();
    });
    child.on("close", settle);
  });
}

// Resolves to a full commit sha. `--end-of-options` stops a "commit" such as
// "--output=/tmp/x" from being read as a git option.
async function resolveCommit(repoDir: string, commit: string, home: string): Promise<{ value: string; error: null } | { value: null; error: string }> {
  if (commit === "" || commit.startsWith("-")) return { value: null, error: `invalid commit ${JSON.stringify(commit)}` };
  try {
    const out = await git(repoDir, ["rev-parse", "--verify", "--quiet", "--end-of-options", `${commit}^{commit}`], home);
    return { value: out.trim(), error: null };
  } catch {
    return { value: null, error: `commit does not resolve: ${JSON.stringify(commit)}` };
  }
}

// The harness's own git calls get a minimal environment too: no operator
// secrets (a filter or hook git runs would inherit them), no GIT_* that would
// point git at another repository, no global or system config. Replace refs
// are ignored, so a planted `git replace` cannot swap the tree behind a
// genuine sha, and hooks and fsmonitor are switched off whatever the
// repository's own config says.
function git(repoDir: string, args: string[], home: string, extra: Record<string, string> = {}): Promise<string> {
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "/usr/local/bin:/usr/bin:/bin",
    HOME: home,
    LANG: "C",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_NO_REPLACE_OBJECTS: "1",
    GIT_TERMINAL_PROMPT: "0",
    ...extra,
  };
  const argv = ["--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-C", repoDir, ...args];
  return new Promise((resolve, reject) => {
    execFile("git", argv, { env, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${err.message.trim()}${stderr ? `\n${stderr.trim()}` : ""}`));
      else resolve(stdout);
    });
  });
}

// Never throws. A command can leave directories it made unreadable, so on
// failure everything is made owner-accessible and removal is retried once.
export async function removeTree(path: string): Promise<string | null> {
  try {
    await rm(path, { recursive: true, force: true });
    return null;
  } catch {
    await makeAccessible(path);
  }
  try {
    await rm(path, { recursive: true, force: true });
    return null;
  } catch (err) {
    return `could not remove ${path}: ${message(err)}`;
  }
}

async function makeAccessible(path: string): Promise<void> {
  const st = await lstat(path).catch(() => null);
  if (st === null || !st.isDirectory()) return;
  await chmod(path, 0o700).catch(() => undefined);
  const names = await readdir(path).catch(() => [] as string[]);
  for (const name of names) await makeAccessible(join(path, name));
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
