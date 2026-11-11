#!/usr/bin/env -S npx tsx
// `commons`: the command line over the ledger, the gates and the coordinator.
//
// This file is allowed to touch the outside world (clock, randomness, files,
// git, sockets); core modules are not, so time and entropy are read here and
// passed in. Every command:
// - takes --ledger (default ./commons-ledger.jsonl), --key (the signing key
//   file, {publicKey, privateKey} JSON) and --at (ISO time; default the wall
//   clock, never earlier than the ledger head, since the ledger refuses time
//   that goes backwards). --at must lie within DEFAULT_MAX_SKEW_MS of the
//   clock unless --force-time is given (tests only): a far-future stamp would
//   freeze the ledger and expire every claim, and settle/promote judge "now"
//   by it;
// - exits 0 on success, 1 when the ledger refuses an entry or a check fails,
//   2 on a usage or harness error (bad flags, unreadable files, git failed,
//   a module that is not available). Nothing that could not run reads as a pass;
// - prints attacker-controlled strings (paths, ids, gate details) with control
//   and bidi characters escaped, so a file name cannot forge log lines or
//   GitHub workflow commands.
//
// Two ways to write an entry:
// - local (default): open the ledger file, validate, append. This is the
//   operator's mode, and the only one for coordinator- and admin-signed kinds.
//   Do not write the file locally while `serve --coordinator` holds it: the
//   server's ledger would go stale. Post through --url instead.
// - remote (--url): sign for the coordinator's head and POST it (client.ts),
//   for the kinds a participant may post. Patches and finding tests upload too.
//
// What the gates judge. Code is never read from a working tree: the head is
// materialised from git objects into a private temporary directory (raw blob
// bytes; no checkout, so no hooks, filters, LFS or attributes), submodules
// included, and the ring gate reads that. In ledger mode the head is the
// commit built from baseCommit plus the stored patch (the patch binding), not
// the author's declared headCommit, because the patch is what gets merged.
//
// Strangers' code (finding tests) runs only under an explicit --sandbox,
// which a preflight checks cannot read the signing key or write the ledger,
// the patches or the repository's .git.
//
// The gate, selection, incentives, promotion, metrics and playground modules
// are loaded through `Io.load`, typed here from ARCHITECTURE.md, so tests can
// inject stand-ins.

import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import type * as http from "node:http";
import * as path from "node:path";
import { anthillRules, anthillTree, behaviourDeltaFor } from "./adapters/anthill";
import { CommonsClient, commitmentOf, fileSaltStore, newId, verdictProblems, type CommitKind } from "./client";
import {
  type GithubBridge,
  type IncentivesApi,
  BINDING_GATE,
  bindingDetails,
  localReproducer,
  type PatchBinding,
  patchBinding,
  planActions,
  type PromotionApi,
  runOnce,
  type SelectionApi,
} from "./coordinator";
import { canonical, generateKeyPair, isValidPublicKey, keyIdOf, randomSalt, sha256hex } from "./crypto";
import { minimalEnv, reproduceFinding } from "./findings";
import { applyUnifiedDiff, parsePatch } from "./github";
import { DEFAULT_MAX_SKEW_MS, isCanonicalPath, Ledger, LedgerError, type LedgerState, type Signer } from "./ledger";
import { plantCommitment } from "./plants";
import { claimStake, defaultRules, ringOf, validateRules } from "./rules";
import { createCoordinatorServer, findingTestFile, LedgerStore, patchFile, type SubmitPolicy, summarisePatch } from "./server";
import { treeFromParents, treeFromSnapshot } from "./tree";
import type {
  CommonsState,
  EntryBody,
  Evidence,
  GateReport,
  LedgerEntry,
  Ring,
  ReviewVerdict,
  Rules,
  Severity,
  SubmissionState,
  TreeView,
} from "./types";

// ---------------------------------------------------------------------------
// Lazily loaded modules (contracts from ARCHITECTURE.md)
// ---------------------------------------------------------------------------

export type RingsApi = {
  submissionRing(files: string[], rules: Rules): Ring;
  // `deleted`: the changed files the diff removes; any other absent file fails.
  checkRingImports(repoDir: string, files: string[], rules: Rules, opts?: { deleted?: Iterable<string> }): GateReport;
};
export type AirlockApi = { checkAirlock(files: string[], rules: Rules, opts: { dependencyTrack: boolean }): GateReport };
export type SizeChange = { linesChanged: number; files?: readonly string[]; binary?: readonly string[]; bytesAdded?: number };
export type SizeApi = { checkSize(change: number | SizeChange, rules: Rules): GateReport };
export type SpecSeparationApi = { checkSpecSeparation(state: CommonsState, submissionId: string, repoDir?: string): GateReport };
export type GatesIndexApi = { checkTaskRing(state: CommonsState, submissionId: string): GateReport | null };
export type MetricsApi = {
  computeMetrics(
    state: CommonsState,
    tree: TreeView,
    nowIso: string,
  ): { group: string; metric: string; value: unknown; bad: boolean; note: string }[];
};
export type PlaygroundApi = {
  startPlayground(opts: { ledgerPath: string; tree: TreeView; port: number; host?: string }): http.Server;
};

export type ModuleName =
  | "gates"
  | "gates/rings"
  | "gates/airlock"
  | "gates/size"
  | "gates/specSeparation"
  | "selection"
  | "incentives"
  | "promotion"
  | "metrics"
  | "playground";

export type Loader = (name: ModuleName) => unknown;

const requireModule: Loader = (name) => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(`./${name}`) as unknown;
  } catch (e) {
    throw new CliError(2, `src/${name}.ts is not available (${(e as Error).message.split("\n")[0]})`);
  }
};

// ---------------------------------------------------------------------------
// I/O and errors
// ---------------------------------------------------------------------------

export type Io = {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  cwd: string;
  now: () => Date;
  load: Loader;
  git: GitRunner;
  fetch?: typeof globalThis.fetch;
  // Resolves when a long-running command (serve) should stop; default: never.
  until?: Promise<void>;
};

// exitCode 1 = refused or failed check, 2 = usage or harness error.
export class CliError extends Error {
  constructor(
    readonly exitCode: 1 | 2,
    message: string,
  ) {
    super(message);
    this.name = "CliError";
  }
}

function usage(message: string): never {
  throw new CliError(2, message);
}
function refuse(message: string): never {
  throw new CliError(1, message);
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

type FlagType = "string" | "boolean" | "list";
type FlagSpec = { type: FlagType; help: string; required?: boolean };
type Flags = Record<string, string | boolean | string[] | undefined>;

// --name value, --name=value, boolean --name, repeatable list flags; `--` ends flags.
export function parseArgs(args: readonly string[], spec: Record<string, FlagSpec>): { flags: Flags; rest: string[] } {
  const flags: Flags = {};
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    if (arg === "--") {
      rest.push(...args.slice(i + 1));
      break;
    }
    if (!arg.startsWith("--")) {
      rest.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    const name = arg.slice(2, eq === -1 ? undefined : eq);
    const s = spec[name] ?? usage(`unknown flag --${name}`);
    if (s.type === "boolean") {
      if (eq !== -1) usage(`--${name} takes no value`);
      flags[name] = true;
      continue;
    }
    let value: string;
    if (eq !== -1) value = arg.slice(eq + 1);
    else {
      const next = args[i + 1];
      if (next === undefined || (next.startsWith("--") && next.length > 2)) usage(`--${name} needs a value`);
      value = next as string;
      i++;
    }
    if (s.type === "list") flags[name] = [...((flags[name] as string[] | undefined) ?? []), value];
    else {
      if (flags[name] !== undefined) usage(`--${name} given twice`);
      flags[name] = value;
    }
  }
  for (const [name, s] of Object.entries(spec)) {
    if (s.required && flags[name] === undefined) usage(`missing --${name}`);
  }
  return { flags, rest };
}

const str = (f: Flags, name: string): string | undefined => f[name] as string | undefined;
const req = (f: Flags, name: string): string => str(f, name) ?? usage(`missing --${name}`);
const list = (f: Flags, name: string): string[] => (f[name] as string[] | undefined) ?? [];
const bool = (f: Flags, name: string): boolean => f[name] === true;

function int(f: Flags, name: string, opts: { min?: number; dflt?: number } = {}): number | undefined {
  const v = str(f, name);
  if (v === undefined) return opts.dflt;
  if (!/^-?\d+$/.test(v)) usage(`--${name} must be an integer, got ${JSON.stringify(v)}`);
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n < (opts.min ?? Number.MIN_SAFE_INTEGER)) usage(`--${name} must be an integer >= ${opts.min}`);
  return n;
}

function num(f: Flags, name: string): number | undefined {
  const v = str(f, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (v.trim() === "" || !Number.isFinite(n)) usage(`--${name} must be a number, got ${JSON.stringify(v)}`);
  return n;
}

// ---------------------------------------------------------------------------
// Commands table
// ---------------------------------------------------------------------------

// out: one line, every control/bidi character escaped (newlines included).
// block: multi-line text we built (JSON), escaped except its own newlines.
type Ctx = { io: Io; out: (line: string) => void; block: (text: string) => void; flags: Flags; name: string };
type Command = {
  summary: string;
  flags: Record<string, FlagSpec>;
  run(ctx: Ctx): Promise<number> | number;
};

const COMMON: Record<string, FlagSpec> = {
  ledger: { type: "string", help: "ledger file (default ./commons-ledger.jsonl)" },
  key: { type: "string", help: "signing key file ({publicKey, privateKey} JSON)" },
  at: { type: "string", help: "ISO time to stamp, within 5 minutes of the clock (default: now, never before the ledger head)" },
  "force-time": { type: "boolean", help: "accept any --at (tests and replays only: it can freeze the ledger)" },
  help: { type: "boolean", help: "show this help" },
};
const REMOTE: Record<string, FlagSpec> = {
  url: { type: "string", help: "post to a coordinator at this URL instead of writing the ledger file" },
};
const TREE: Record<string, FlagSpec> = {
  tree: { type: "string", help: "tree JSON: an anthillSnapshot.json, {parents, reputation} or a parent map" },
  "anthill-backend": { type: "string", help: "build the tree by replaying this anthill-backend checkout's log" },
  "anthill-data": { type: "string", help: "backend data dir holding log.jsonl (default <backend>/data)" },
  community: { type: "string", help: "Anthill community id for --anthill-backend (default demo)" },
};

const command = (summary: string, flags: Record<string, FlagSpec>, run: Command["run"]): Command => ({
  summary,
  flags: { ...COMMON, ...flags },
  run,
});

// ---------------------------------------------------------------------------
// Shared helpers: files, keys, time, ledger
// ---------------------------------------------------------------------------

function resolvePath(ctx: Ctx, p: string): string {
  return path.resolve(ctx.io.cwd, p);
}

function readText(ctx: Ctx, p: string, what: string): string {
  try {
    return fs.readFileSync(resolvePath(ctx, p), "utf8");
  } catch (e) {
    return usage(`cannot read ${what} ${p}: ${(e as NodeJS.ErrnoException).code ?? (e as Error).message}`);
  }
}

function readJson(ctx: Ctx, p: string, what: string): unknown {
  const text = readText(ctx, p, what);
  try {
    return JSON.parse(text) as unknown;
  } catch (e) {
    return usage(`${what} ${p} is not JSON: ${(e as Error).message}`);
  }
}

// A JSON flag value, inline or @file.
function jsonArg(ctx: Ctx, value: string, what: string): unknown {
  if (value.startsWith("@")) return readJson(ctx, value.slice(1), what);
  try {
    return JSON.parse(value) as unknown;
  } catch (e) {
    return usage(`${what} is not JSON: ${(e as Error).message}`);
  }
}

function readKey(ctx: Ctx, p: string): Signer {
  const k = readJson(ctx, p, "key file") as Partial<Signer> | null;
  if (!k || typeof k !== "object" || !isValidPublicKey(k.publicKey) || typeof k.privateKey !== "string") {
    usage(`key file ${p} must hold {publicKey, privateKey} as written by commons keygen`);
  }
  return { publicKey: (k as Signer).publicKey, privateKey: (k as Signer).privateKey };
}

const signerKey = (ctx: Ctx): Signer => readKey(ctx, req(ctx.flags, "key"));

// A public key given as a key file (only publicKey is read) or as the base64url key itself.
function publicKeyArg(ctx: Ctx, value: string, flag: string): string {
  if (isValidPublicKey(value)) return value;
  const k = readJson(ctx, value, `--${flag} file`) as { publicKey?: unknown } | null;
  if (!k || !isValidPublicKey(k.publicKey)) usage(`--${flag} ${value}: no valid ed25519 publicKey in it`);
  return (k as { publicKey: string }).publicKey;
}

function isoArg(value: string, flag: string): string {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) usage(`--${flag} is not a time: ${JSON.stringify(value)}`);
  return new Date(ms).toISOString();
}

// --at, or the clock; never before `headAt`, which the ledger would refuse.
// The time also drives evaluation (claim expiry, vesting, soak), so --at is
// bounded by the clock like the server bounds agents' entries.
function stamp(ctx: Ctx, headAt?: string): string {
  const at = str(ctx.flags, "at");
  const now = ctx.io.now();
  if (at !== undefined) {
    const iso = isoArg(at, "at");
    if (!bool(ctx.flags, "force-time") && Math.abs(Date.parse(iso) - now.getTime()) > DEFAULT_MAX_SKEW_MS) {
      usage(`--at ${iso} is more than ${DEFAULT_MAX_SKEW_MS / 60_000} minutes from the clock (${now.toISOString()}); --force-time accepts it (tests only)`);
    }
    return iso;
  }
  const nowIso = now.toISOString();
  return headAt !== undefined && Date.parse(headAt) > Date.parse(nowIso) ? headAt : nowIso;
}

// Escapes C0/C1 controls, DEL, line separators and bidi overrides as \uXXXX,
// the way core.quotePath protects a terminal. `keepNewlines` is for text whose
// line breaks we wrote ourselves.
const UNPRINTABLE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
const UNPRINTABLE_BUT_NL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
export function printable(text: string, keepNewlines = false): string {
  return text.replace(keepNewlines ? UNPRINTABLE_BUT_NL : UNPRINTABLE, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

const ledgerPath = (ctx: Ctx): string => resolvePath(ctx, str(ctx.flags, "ledger") ?? "commons-ledger.jsonl");

function openLedger(ctx: Ctx): Ledger {
  const p = ledgerPath(ctx);
  if (!fs.existsSync(p)) usage(`no ledger at ${p} (create one with commons init, or pass --ledger)`);
  try {
    return Ledger.open(p);
  } catch (e) {
    if (e instanceof LedgerError) refuse(`ledger ${p} is invalid (${e.code}): ${e.message}`);
    throw e;
  }
}

const state = (ctx: Ctx): LedgerState => openLedger(ctx).state() as LedgerState;

function appendLocal(ctx: Ctx, body: EntryBody, signer: Signer): LedgerEntry {
  const ledger = openLedger(ctx);
  const at = stamp(ctx, (ledger.state() as LedgerState).headAt);
  try {
    return ledger.append(body, signer, at);
  } catch (e) {
    if (e instanceof LedgerError) refuse(`the ledger refused the ${body.kind} entry (${e.code}): ${e.message}`);
    throw e;
  }
}

function client(ctx: Ctx, signer: Signer, saltDir?: string): CommonsClient {
  const at = str(ctx.flags, "at");
  return new CommonsClient({
    baseUrl: req(ctx.flags, "url"),
    agentKey: signer,
    clock: () => (at === undefined ? ctx.io.now() : stamp(ctx)),
    ...(ctx.io.fetch ? { fetch: ctx.io.fetch as never } : {}),
    ...(saltDir === undefined ? {} : { saltStore: fileSaltStore(saltDir) }),
  });
}

function report(ctx: Ctx, e: { seq: number; hash: string; body: EntryBody }, extra = ""): void {
  const b = e.body as { id?: unknown };
  const id = typeof b.id === "string" ? ` ${b.id}` : "";
  ctx.out(`#${e.seq} ${e.body.kind}${id} ${e.hash.slice(0, 16)}${extra ? ` ${extra}` : ""}`);
}

// Writes a participant entry: POSTed with --url, appended to the file otherwise.
async function emit(ctx: Ctx, body: EntryBody, signer: Signer): Promise<LedgerEntry> {
  if (str(ctx.flags, "url") !== undefined) {
    try {
      return (await client(ctx, signer).post(body)).entry;
    } catch (e) {
      return refuse(`the coordinator refused the ${body.kind} entry: ${(e as Error).message}`);
    }
  }
  return appendLocal(ctx, body, signer);
}

// Salts, plant salts and other secrets of a key live next to it: <key>.salts/.
const saltDirOf = (ctx: Ctx): string => `${resolvePath(ctx, req(ctx.flags, "key"))}.salts`;

function needState(ctx: Ctx, what: string): LedgerState {
  if (str(ctx.flags, "url") !== undefined) usage(`with --url, pass ${what} explicitly`);
  return state(ctx);
}

// ---------------------------------------------------------------------------
// Tree
// ---------------------------------------------------------------------------

async function loadTree(ctx: Ctx): Promise<TreeView> {
  const f = ctx.flags;
  const file = str(f, "tree");
  const backend = str(f, "anthill-backend");
  if (file !== undefined && backend !== undefined) usage("pass --tree or --anthill-backend, not both");
  if (backend !== undefined) {
    try {
      return await anthillTree({
        backendDir: resolvePath(ctx, backend),
        ...(str(f, "anthill-data") === undefined ? {} : { dataDir: resolvePath(ctx, req(f, "anthill-data")) }),
        community: str(f, "community") ?? "demo",
      });
    } catch (e) {
      return usage((e as Error).message);
    }
  }
  if (file === undefined) return usage("this command needs the trust tree: pass --tree <file> or --anthill-backend <dir>");
  const json = readJson(ctx, file, "tree file") as Record<string, unknown> | null;
  try {
    if (json && typeof json === "object" && "graph" in json) return treeFromSnapshot(json);
    if (json && typeof json === "object" && "parents" in json) {
      return treeFromParents(json.parents as Record<string, string | null>, (json.reputation ?? {}) as Record<string, number>);
    }
    return treeFromParents(json as Record<string, string | null>);
  } catch (e) {
    return usage(`tree file ${file}: ${(e as Error).message}`);
  }
}

// ---------------------------------------------------------------------------
// Git: what a change really touches
// ---------------------------------------------------------------------------

export type GitRunner = (cwd: string, args: string[], input?: string) => string;

// Every git the CLI runs works on repositories that hold strangers' commits.
// None of these commands checks anything out, but config and environment make
// sure no hook, fsmonitor or LFS filter of anyone's could run if one did.
const GIT_SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "filter.lfs.process=", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.required=false"];

// Caps on what materialising a head may write. Blobs are deduplicated, so a
// tiny pack can expand into a huge tree and fill the disk the ledger lives on.
export const MAX_HEAD_FILES = 200_000;
export const MAX_HEAD_BYTES = 256 * 1024 * 1024;

function rawGit(cwd: string, args: string[], opts: { input?: string; env?: Record<string, string> } = {}): Buffer {
  try {
    return execFileSync("git", [...GIT_SAFE, ...args], {
      cwd,
      input: opts.input,
      maxBuffer: MAX_HEAD_BYTES + 64 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", GIT_LFS_SKIP_SMUDGE: "1", ...opts.env },
    });
  } catch (e) {
    const err = e as { stderr?: Buffer | string; message: string };
    throw new CliError(2, `git ${args.join(" ")} (in ${cwd}) failed: ${(err.stderr?.toString() || err.message).trim()}`);
  }
}

const defaultGit: GitRunner = (cwd, args, input) => rawGit(cwd, args, input === undefined ? {} : { input }).toString("utf8");

export type Change = {
  files: string[]; // sorted, unique, repo-relative POSIX; submodule files carry the submodule path
  linesChanged: number; // added + deleted over all files, submodule files included; binary files by their newlines
  deleted: string[]; // changed files that are absent at head
  binary: string[]; // files git counts no lines for
  bytesAdded: number; // the added side: `+` lines of text files, the whole new blob of binary ones
  unexpanded: { path: string; reason: string }[]; // gitlinks reported bare
  submodules: { path: string; sha: string }[]; // expanded gitlinks and the commit their new side is at
};

const GITLINK = "160000";
const NO_MODE = "000000";
const MAX_SUBMODULE_DEPTH = 8;
export const FULL_SHA = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;

function revArg(value: string, flag: string): string {
  if (!/^[0-9A-Za-z][0-9A-Za-z._/^~@{}-]*$/.test(value)) usage(`--${flag} ${JSON.stringify(value)} is not a commit`);
  return value;
}

// A commit name the ledger may record: a full sha, never a ref or an
// expression whose meaning can move between gating and merging.
function shaArg(value: string, flag: string): string {
  if (!FULL_SHA.test(value)) usage(`--${flag} ${JSON.stringify(value)} must be a full commit sha (40 or 64 hex digits)`);
  return value;
}

function resolveCommit(git: GitRunner, repo: string, rev: string): string {
  return git(repo, ["rev-parse", "--verify", "--quiet", "--end-of-options", `${rev}^{commit}`]).trim();
}

// Why `sha` cannot be gated in `repo`, or null: it must be a full sha naming
// a commit there, not a tag or anything else that peels to one.
function pinProblem(git: GitRunner, repo: string, what: string, sha: string): string | null {
  if (!FULL_SHA.test(sha)) return `${what} ${JSON.stringify(sha)} is not a full commit sha`;
  try {
    return resolveCommit(git, repo, sha) === sha ? null : `${what} ${sha} is not a commit`;
  } catch {
    return `${what} ${sha} is not in ${repo}`;
  }
}

// The change base..head (git diff base head), every path on both sides of a
// rename, with each differing gitlink expanded into the submodule's own
// change. A gitlink that cannot be expanded is reported as its bare path and
// keeps its pointer line count; the gates classify a bare pointer as ring 0.
export function gitChanges(git: GitRunner, repo: string, base: string, head: string): Change {
  return diffTrees(git, repo, resolveCommit(git, repo, base), resolveCommit(git, repo, head), 0);
}

function diffTrees(git: GitRunner, repo: string, a: string, b: string, depth: number): Change {
  const common = ["--no-renames", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none"];
  const raw = git(repo, ["diff", "--raw", "--no-abbrev", "-z", ...common, a, b, "--"]).split("\0");
  const gitlinks = new Map<string, { old: string | null; new: string | null; typechange: boolean }>();
  const blobs = new Map<string, { old: string | null; new: string | null }>();
  const deleted: string[] = [];
  for (let i = 0; i + 1 < raw.length; i += 2) {
    const [oldMode, newMode, oldSha, newSha] = (raw[i] as string).replace(/^:/, "").split(" ");
    const p = raw[i + 1] as string;
    if (oldMode !== GITLINK && newMode !== GITLINK) {
      blobs.set(p, { old: oldMode === NO_MODE ? null : (oldSha as string), new: newMode === NO_MODE ? null : (newSha as string) });
      if (newMode === NO_MODE) deleted.push(p);
      continue;
    }
    const typechange = (oldMode !== GITLINK && oldMode !== NO_MODE) || (newMode !== GITLINK && newMode !== NO_MODE);
    gitlinks.set(p, {
      old: oldMode === GITLINK ? (oldSha as string) : null,
      new: newMode === GITLINK ? (newSha as string) : null,
      typechange,
    });
  }

  const files = new Set<string>();
  const binary: string[] = [];
  const unexpanded: Change["unexpanded"] = [];
  const submodules: Change["submodules"] = [];
  let lines = 0;
  let bytesAdded = addedTextBytes(git, repo, a, b, common);
  const numstat = git(repo, ["diff", "--numstat", "-z", ...common, a, b, "--"]).split("\0");
  const pointerLines = new Map<string, number>();
  for (const rec of numstat) {
    if (rec === "") continue;
    const m = /^(-|\d+)\t(-|\d+)\t([\s\S]*)$/.exec(rec);
    if (!m) throw new CliError(2, `unexpected git numstat record ${JSON.stringify(rec)}`);
    const p = m[3] as string;
    let n = m[1] === "-" ? 0 : Number(m[1]) + Number(m[2]);
    if (gitlinks.has(p)) {
      pointerLines.set(p, (pointerLines.get(p) ?? 0) + n);
      continue;
    }
    if (m[1] === "-") {
      // git counts nothing for a file it calls binary (one NUL byte, or a
      // `-diff` attribute the change itself can add). Count its lines and
      // bytes from the blobs, so it cannot hide from the size gate.
      binary.push(p);
      const blob = blobs.get(p);
      n = blobLines(git, repo, blob?.old ?? null) + blobLines(git, repo, blob?.new ?? null);
      bytesAdded += blob?.new ? Number(git(repo, ["cat-file", "-s", blob.new]).trim()) : 0;
    }
    files.add(p);
    lines += n;
  }

  for (const [p, link] of gitlinks) {
    const sub = expandSubmodule(git, repo, p, link.old, link.new, depth);
    if (typeof sub === "string" || link.typechange) {
      files.add(p);
      lines += pointerLines.get(p) ?? 0;
      if (typeof sub === "string") {
        unexpanded.push({ path: p, reason: sub });
        continue;
      }
    }
    for (const f of sub.files) files.add(`${p}/${f}`);
    lines += sub.linesChanged;
    bytesAdded += sub.bytesAdded;
    deleted.push(...sub.deleted.map((f) => `${p}/${f}`));
    binary.push(...sub.binary.map((f) => `${p}/${f}`));
    unexpanded.push(...sub.unexpanded.map((u) => ({ ...u, path: `${p}/${u.path}` })));
    if (link.new !== null) submodules.push({ path: p, sha: link.new });
    submodules.push(...sub.submodules.map((s) => ({ ...s, path: `${p}/${s.path}` })));
  }
  return { files: [...files].sort(), linesChanged: lines, deleted: deleted.sort(), binary: binary.sort(), bytesAdded, unexpanded, submodules };
}

// Bytes on the `+` lines of the text diff (each `+` stands in for its line's
// newline). Binary files print no hunks here; diffTrees adds their blobs.
function addedTextBytes(git: GitRunner, repo: string, a: string, b: string, common: string[]): number {
  let n = 0;
  let inHunk = false;
  for (const line of git(repo, ["diff", "-U0", "--no-color", ...common, a, b, "--"]).split("\n")) {
    if (line.startsWith("diff --git ")) inHunk = false;
    else if (line.startsWith("@@")) inHunk = true;
    else if (inHunk && line.startsWith("+")) n += Buffer.byteLength(line, "utf8");
  }
  return n;
}

// Lines in a blob as a line count would see them; 0 for an absent side.
// UTF-8 decoding never creates or removes a 0x0a byte, so the count is exact.
function blobLines(git: GitRunner, repo: string, sha: string | null): number {
  if (sha === null) return 0;
  const text = git(repo, ["cat-file", "blob", sha]);
  let n = 0;
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) n++;
  return text.length > 0 && !text.endsWith("\n") ? n + 1 : n;
}

// An initialised submodule checkout at `dir`. An uninitialised one is an
// empty directory, where git would find the superproject instead.
function isCheckoutRoot(git: GitRunner, dir: string): boolean {
  if (!fs.existsSync(path.join(dir, ".git"))) return false;
  try {
    return fs.realpathSync(git(dir, ["rev-parse", "--show-toplevel"]).trim()) === fs.realpathSync(dir);
  } catch {
    return false;
  }
}

// The submodule's own change, or why it could not be computed.
function expandSubmodule(
  git: GitRunner,
  repo: string,
  p: string,
  oldSha: string | null,
  newSha: string | null,
  depth: number,
): Change | string {
  if (depth >= MAX_SUBMODULE_DEPTH) return "submodules nested too deep";
  const dir = path.join(repo, p);
  if (!isCheckoutRoot(git, dir)) return "submodule not initialised";
  try {
    for (const sha of [oldSha, newSha]) {
      if (sha === null || hasCommit(git, dir, sha)) continue;
      try {
        git(dir, ["fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "origin", sha]);
      } catch {
        // reported below
      }
      if (!hasCommit(git, dir, sha)) return `commit ${sha} not available in the submodule`;
    }
    const empty = git(dir, ["hash-object", "-t", "tree", "--stdin"], "").trim();
    return diffTrees(git, dir, oldSha ?? empty, newSha ?? empty, depth + 1);
  } catch (e) {
    return (e as Error).message;
  }
}

function hasCommit(git: GitRunner, dir: string, sha: string): boolean {
  try {
    git(dir, ["cat-file", "-e", `${sha}^{commit}`]);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Materialising a head
// ---------------------------------------------------------------------------

type Budget = { files: number; bytes: number };

// Writes the tree of `commit` into the empty directory `dest` from git
// objects alone: regular files and symlinks with their raw bytes, and each
// gitlink whose commit the submodule checkout at that path has, recursively.
// Nothing is checked out and `dest` is not linked to any repository, so no
// hook, filter, LFS smudge or attribute runs, and nothing the gates later do
// in `dest` can reach the repository. A gitlink in `required` (a submodule the
// change moves, by top-level path) that cannot be written is an error, never
// an empty directory: the ring gate would read its files as absent. Other
// gitlinks stay empty, as in a checkout without that submodule.
export function materialiseCommit(
  repo: string,
  commit: string,
  dest: string,
  required: ReadonlySet<string>,
  prefix = "",
  depth = 0,
  budget: Budget = { files: 0, bytes: 0 },
): void {
  if (depth >= MAX_SUBMODULE_DEPTH) throw new Error("submodules nested too deep");
  const root = fs.realpathSync(dest);
  type Item = { mode: string; sha: string; size: number; path: string };
  const items: Item[] = [];
  const links: Item[] = [];
  for (const rec of rawGit(repo, ["ls-tree", "-r", "-z", "-l", "--full-tree", commit]).toString("utf8").split("\0")) {
    if (rec === "") continue;
    const m = /^(\d{6}) (\w+) ([0-9a-f]+) +(-|\d+)\t([\s\S]+)$/.exec(rec);
    if (!m) throw new Error(`unexpected git ls-tree record ${JSON.stringify(rec)}`);
    const item = { mode: m[1] as string, sha: m[3] as string, size: m[4] === "-" ? 0 : Number(m[4]), path: m[5] as string };
    const segments = item.path.split("/");
    if (segments.some((x) => x === "" || x === "." || x === ".." || x.toLowerCase() === ".git")) {
      throw new Error(`commit ${commit} has an unsafe path ${JSON.stringify(item.path)}`);
    }
    if (item.mode === GITLINK) links.push(item);
    else if (["100644", "100755", "120000"].includes(item.mode)) items.push(item);
    else throw new Error(`commit ${commit}: unsupported mode ${item.mode} at ${JSON.stringify(item.path)}`);
    budget.files += 1;
    budget.bytes += item.size;
  }
  if (budget.files > MAX_HEAD_FILES || budget.bytes > MAX_HEAD_BYTES) {
    throw new Error(`the head is too large to check (${budget.files} files, ${budget.bytes} bytes; limits ${MAX_HEAD_FILES}, ${MAX_HEAD_BYTES})`);
  }

  const shas = [...new Set(items.map((i) => i.sha))];
  const blobs = new Map<string, Buffer>();
  if (shas.length > 0) {
    const out = rawGit(repo, ["cat-file", "--batch"], { input: `${shas.join("\n")}\n` });
    let at = 0;
    while (at < out.length) {
      const nl = out.indexOf(0x0a, at);
      const header = out.subarray(at, nl).toString("utf8");
      const m = /^([0-9a-f]+) blob (\d+)$/.exec(header);
      if (!m) throw new Error(`git cat-file: ${header}`);
      const size = Number(m[2]);
      blobs.set(m[1] as string, out.subarray(nl + 1, nl + 1 + size));
      at = nl + 1 + size + 1;
    }
  }
  for (const item of items) {
    const abs = path.join(root, item.path);
    const parent = path.dirname(abs);
    fs.mkdirSync(parent, { recursive: true });
    // Paths are unique in a well-formed tree; a crafted one could put a file
    // under a symlink written earlier, so every parent must still be ours.
    const real = fs.realpathSync(parent);
    if (real !== root && !real.startsWith(`${root}${path.sep}`)) throw new Error(`${JSON.stringify(item.path)} escapes the checkout`);
    const content = blobs.get(item.sha) ?? Buffer.alloc(0);
    if (item.mode === "120000") fs.symlinkSync(content.toString("utf8"), abs);
    else fs.writeFileSync(abs, content, { flag: "wx", mode: item.mode === "100755" ? 0o755 : 0o644 });
  }
  for (const link of links) {
    const full = prefix === "" ? link.path : `${prefix}/${link.path}`;
    const sub = path.join(repo, link.path);
    const target = path.join(root, link.path);
    fs.mkdirSync(target, { recursive: true });
    if (isCheckoutRoot(defaultGit, sub) && hasCommit(defaultGit, sub, link.sha)) {
      materialiseCommit(sub, link.sha, target, required, full, depth + 1, budget);
    } else if (required.has(full)) {
      throw new Error(`submodule ${full} at ${link.sha} is not available in ${sub}; its files cannot be checked`);
    }
  }
}

// Runs fn on a private directory holding `head`, then removes it. With
// need=false the directory stays empty (nothing will be read from it).
function withHead<T>(repo: string, head: string, change: Change, need: boolean, fn: (dir: string) => T): T {
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "commons-head-"));
  try {
    const dir = path.join(tmp, "head");
    fs.mkdirSync(dir);
    if (need) materialiseCommit(repo, head, dir, new Set(change.submodules.map((s) => s.path)));
    return fn(dir);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Static gates
// ---------------------------------------------------------------------------

type GateRun = { ring: Ring | null; reports: GateReport[]; harness: string[]; notes: string[] };

function attempt(run: GateRun, gate: string, fn: () => GateReport): GateReport {
  try {
    return fn();
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    run.harness.push(`${gate}: ${message}`);
    return { gate, pass: false, details: `could not run: ${message}` };
  }
}

// rings, airlock and size over a computed change, in that order. The ring
// gate reads `head` materialised from git (never a working tree), and only
// when the size gate passed: an oversized change is not written to disk.
// `inHead` runs more gates on that directory (ledger mode).
function staticGates(
  io: Io,
  repo: string,
  head: string,
  change: Change,
  rules: Rules,
  dependencyTrack: boolean,
  inHead?: (dir: string, run: GateRun) => void,
): GateRun {
  const run: GateRun = { ring: null, reports: [], harness: [], notes: [] };
  let rings: RingsApi | null = null;
  try {
    rings = io.load("gates/rings") as RingsApi;
    run.ring = rings.submissionRing(change.files, rules);
  } catch (e) {
    run.harness.push(`rings: ${(e as Error).message}`);
  }
  if (change.unexpanded.length > 0) {
    run.ring = 0;
    run.notes.push(`ring 0 whatever the rules say: ${change.unexpanded.length} submodule pointer(s) could not be expanded, so their content is not inspected`);
  }
  const airlock = attempt(run, "airlock", () => (io.load("gates/airlock") as AirlockApi).checkAirlock(change.files, rules, { dependencyTrack }));
  const size = attempt(run, "size", () =>
    (io.load("gates/size") as SizeApi).checkSize(
      { linesChanged: change.linesChanged, files: change.files, binary: change.binary, bytesAdded: change.bytesAdded },
      rules,
    ),
  );
  let ringReport: GateReport;
  if (rings === null) ringReport = { gate: "rings", pass: false, details: "could not run: gates/rings is not available" };
  else if (!size.pass) ringReport = { gate: "rings", pass: false, details: "not run: the change fails the size gate, so its head is not materialised" };
  else {
    const r = rings;
    const need = inHead !== undefined || change.files.some((f) => ringOf(f, rules) === 2);
    ringReport = attempt(run, "rings", () =>
      withHead(repo, head, change, need, (dir) => {
        const report = r.checkRingImports(dir, change.files, rules, { deleted: change.deleted });
        inHead?.(dir, run);
        return report;
      }),
    );
  }
  run.reports.unshift(ringReport, airlock, size);
  return run;
}

function printChange(ctx: Ctx, change: Change, rules: Rules): void {
  ctx.out(`changed files: ${change.files.length}, lines changed: ${change.linesChanged}, bytes added: ${change.bytesAdded}`);
  const bare = new Set(change.unexpanded.map((u) => u.path));
  const deleted = new Set(change.deleted);
  const binary = new Set(change.binary);
  for (const f of change.files) {
    const ring = bare.has(f) ? 0 : ringOf(f, rules);
    ctx.out(`  [ring ${ring}] ${f}${deleted.has(f) ? " (deleted)" : ""}${binary.has(f) ? " (binary)" : ""}`);
  }
  for (const u of change.unexpanded) ctx.out(`  submodule ${u.path} not expanded: ${u.reason}`);
}

function printReports(ctx: Ctx, reports: GateReport[]): void {
  for (const r of reports) ctx.out(`${r.pass ? "PASS" : "FAIL"} ${r.gate}: ${r.details}`);
}

function readRules(ctx: Ctx, p: string): Rules {
  const rules = readJson(ctx, p, "rules file") as Rules;
  const problems = rules && typeof rules === "object" ? validateRules(rules) : ["not an object"];
  if (problems.length > 0) usage(`rules ${p} are invalid:\n  ${problems.join("\n  ")}`);
  return rules;
}

// CI mode: no ledger. The working tree is not read: in CI it is the base, and
// the head was only fetched (see .commons/README.md).
async function gatesCi(ctx: Ctx): Promise<number> {
  const f = ctx.flags;
  const repo = resolvePath(ctx, req(f, "repo"));
  const rules = readRules(ctx, req(f, "rules"));
  const git = ctx.io.git;
  const base = resolveCommit(git, repo, revArg(req(f, "base"), "base"));
  const head = resolveCommit(git, repo, revArg(req(f, "head"), "head"));
  const change = diffTrees(git, repo, base, head, 0);
  const run = staticGates(ctx.io, repo, head, change, rules, bool(f, "dependency-track"));
  if (change.files.length === 0) run.notes.push(`no changes between ${base} and ${head}`);
  return finishGates(ctx, change, rules, run);
}

function finishGates(ctx: Ctx, change: Change | null, rules: Rules, run: GateRun, recorded = ""): number {
  const pass = run.harness.length === 0 && run.reports.length > 0 && run.reports.every((r) => r.pass);
  if (bool(ctx.flags, "json")) {
    ctx.block(
      JSON.stringify(
        {
          pass,
          ring: run.ring,
          files: change?.files ?? [],
          linesChanged: change?.linesChanged ?? 0,
          deleted: change?.deleted ?? [],
          binary: change?.binary ?? [],
          bytesAdded: change?.bytesAdded ?? 0,
          unexpanded: change?.unexpanded ?? [],
          notes: run.notes,
          reports: run.reports,
        },
        null,
        2,
      ),
    );
  } else {
    if (change) printChange(ctx, change, rules);
    ctx.out(`submission ring: ${run.ring ?? "unknown"}`);
    for (const n of run.notes) ctx.out(`note: ${n}`);
    printReports(ctx, run.reports);
    if (recorded) ctx.out(recorded);
    ctx.out(pass ? "gates: PASS" : "gates: FAIL");
  }
  if (run.harness.length > 0) {
    ctx.io.stderr(`commons gates: could not run every gate:\n  ${run.harness.map((h) => printable(h)).join("\n  ")}\n`);
    return 2;
  }
  return pass ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Patch binding: the commit that gets merged
// ---------------------------------------------------------------------------

// Builds, in `repo`, the commit the GitHub bridge would build for a stored
// patch: parent baseCommit, tree = baseCommit's tree with the patch applied by
// the bridge's own strict parser and applier, and the bridge's refusals
// (binary, symlink, mode, .github/, a missing or existing path). The commit is
// kept alive by refs/commons/<id>. If the declared headCommit is in `repo`,
// its tree must be the patch's tree. null = no patch stored yet.
export function bindPatchLocal(repo: string, patchesDir: string, s: SubmissionState): PatchBinding | { error: string } | null {
  let file: string;
  try {
    file = patchFile(patchesDir, s.id);
  } catch {
    return { error: `submission id ${JSON.stringify(s.id)} cannot have a patch file` };
  }
  if (!fs.existsSync(file)) return null;
  const bytes = fs.readFileSync(file);
  const patchSha256 = sha256hex(bytes);
  const text = bytes.toString("utf8");
  if (!Buffer.from(text, "utf8").equals(bytes)) return { error: "the patch is not valid UTF-8" };
  const base = pinProblem(defaultGit, repo, "baseCommit", s.baseCommit);
  if (base !== null) return { error: base };
  let patches;
  try {
    patches = parsePatch(text);
  } catch (e) {
    return { error: `the patch does not parse: ${(e as Error).message}` };
  }
  const tmp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "commons-bind-"));
  const env = { GIT_INDEX_FILE: path.join(tmp, "index") };
  const g = (args: string[], input?: string) => rawGit(repo, args, { env, ...(input === undefined ? {} : { input }) }).toString("utf8");
  try {
    g(["read-tree", s.baseCommit]);
    const at = (p: string): { mode: string; type: string; sha: string } | null => {
      const out = g(["ls-tree", "-z", "--full-tree", s.baseCommit, "--", p]).split("\0")[0] ?? "";
      const m = /^(\d{6}) (\w+) ([0-9a-f]+)\t/.exec(out);
      return m ? { mode: m[1] as string, type: m[2] as string, sha: m[3] as string } : null;
    };
    const textAt = (p: string, expectMode?: string): { mode: string; sha: string; text: string } => {
      const e = at(p);
      if (e === null) throw new Error(`${p}: does not exist at the base commit`);
      if (e.type !== "blob" || e.mode === "120000" || !["100644", "100755"].includes(e.mode)) throw new Error(`${p}: is not a regular file at the base commit`);
      if (expectMode !== undefined && expectMode !== e.mode) throw new Error(`${p}: mode is ${e.mode}, the patch says ${expectMode}`);
      const raw = rawGit(repo, ["cat-file", "blob", e.sha]);
      if (raw.includes(0)) throw new Error(`${p}: is a binary file`);
      const t = raw.toString("utf8");
      if (!Buffer.from(t, "utf8").equals(raw)) throw new Error(`${p}: is not valid UTF-8`);
      return { mode: e.mode, sha: e.sha, text: t };
    };
    const absent = (p: string) => {
      if (at(p) !== null) throw new Error(`${p}: already exists at the base commit`);
    };
    const apply = (original: string, hunks: string[]) => (hunks.length === 0 ? original : applyUnifiedDiff(original, `${hunks.join("\n")}\n`));
    const put = (mode: string, p: string, content: string) => {
      const sha = g(["hash-object", "-w", "--stdin"], content).trim();
      g(["update-index", "--add", "--cacheinfo", `${mode},${sha},${p}`]);
    };
    const remove = (p: string) => g(["update-index", "--force-remove", "--", p]);
    try {
      for (const p of patches) {
        for (const touched of p.kind === "add" ? [p.newPath] : p.kind === "delete" ? [p.oldPath] : [p.oldPath, p.newPath]) {
          if (/^\.github(\/|$)/i.test(touched)) throw new Error(`${touched}: changes under .github/ need explicit approval`);
        }
        if (p.kind === "add") {
          absent(p.newPath);
          put(p.newMode, p.newPath, apply("", p.hunks));
        } else if (p.kind === "delete") {
          const old = textAt(p.oldPath, p.oldMode);
          if (apply(old.text, p.hunks) !== "") throw new Error(`${p.oldPath}: deletion does not remove the whole file`);
          remove(p.oldPath);
        } else {
          const old = textAt(p.oldPath, p.oldMode);
          if (p.kind !== "modify") absent(p.newPath);
          if (p.kind === "rename") remove(p.oldPath);
          put(p.newMode ?? old.mode, p.newPath, apply(old.text, p.hunks));
        }
      }
    } catch (e) {
      return { error: `the patch does not apply to ${s.baseCommit}: ${(e as Error).message}` };
    }
    const tree = g(["write-tree"]).trim();
    if (tree === g(["rev-parse", `${s.baseCommit}^{tree}`]).trim()) return { error: "the patch changes nothing" };
    if (pinProblem(defaultGit, repo, "headCommit", s.headCommit) === null) {
      const declared = g(["rev-parse", `${s.headCommit}^{tree}`]).trim();
      if (declared !== tree) return { error: `the patch produces tree ${tree}, but the declared headCommit ${s.headCommit} has tree ${declared}` };
    }
    // Deterministic, so binding the same patch twice gives the same commit.
    const id = { GIT_AUTHOR_NAME: "commons", GIT_AUTHOR_EMAIL: "commons@invalid", GIT_COMMITTER_NAME: "commons", GIT_COMMITTER_EMAIL: "commons@invalid" };
    const date = `${Math.floor(Date.parse(s.submittedAt) / 1000)} +0000`;
    const head = rawGit(repo, ["commit-tree", tree, "-p", s.baseCommit], {
      env: { ...id, GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date },
      input: `commons submission ${s.id}\n\nCommons-Submission: ${s.id}\nCommons-Patch-Sha256: ${patchSha256}\n`,
    })
      .toString("utf8")
      .trim();
    rawGit(repo, ["update-ref", `refs/commons/${s.id}`, head]);
    return { head, patchSha256 };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Ledger-mode gates
// ---------------------------------------------------------------------------

// The gates for a ledger submission at `s.headCommit` (the caller passes the
// bound head, see bindPatchLocal). The declared changedFiles/linesChanged are
// what the ledger and the other gates trust, so they are checked against git
// first (ledger.ts leaves that to the coordinator): a submission that
// misstates its change, or moves a submodule pointer that cannot be expanded,
// fails declaredChange.
export function submissionGates(io: Io, st: CommonsState, s: SubmissionState, repo: string, dependencyTrack = false): GateRun & { change: Change | null } {
  const pins = [pinProblem(io.git, repo, "baseCommit", s.baseCommit), pinProblem(io.git, repo, "headCommit", s.headCommit)].filter((x) => x !== null);
  if (pins.length > 0) {
    return { ring: null, reports: [{ gate: "declaredChange", pass: false, details: pins.join("; ") }], harness: [], notes: [], change: null };
  }
  const change = diffTrees(io.git, repo, s.baseCommit, s.headCommit, 0);
  const run = staticGates(io, repo, s.headCommit, change, st.rules, dependencyTrack, (dir, r) => {
    r.reports.push(attempt(r, "specSeparation", () => (io.load("gates/specSeparation") as SpecSeparationApi).checkSpecSeparation(st, s.id, dir)));
  });
  // A submission must not touch a lower ring than its task was priced at.
  const task = attempt(run, "rings", () => (io.load("gates") as GatesIndexApi).checkTaskRing(st, s.id) ?? { gate: "rings", pass: true, details: "" });
  const rings = run.reports.find((r) => r.gate === "rings");
  if (rings && !task.pass) {
    rings.pass = false;
    rings.details = rings.details === "" ? task.details : `${task.details}; ${rings.details}`;
  }
  const declared = [...new Set(s.changedFiles)].sort();
  const why: string[] = [];
  if (declared.join("\n") !== change.files.join("\n") || s.linesChanged !== change.linesChanged) {
    why.push(
      `declared ${declared.length} files / ${s.linesChanged} lines, git diff has ${change.files.length} files / ${change.linesChanged} lines` +
        ` (${diffList(declared, change.files)})`,
    );
  }
  if (change.unexpanded.length > 0) {
    why.push(`submodule pointers that cannot be expanded, so their content cannot be gated: ${change.unexpanded.map((u) => `${u.path} (${u.reason})`).join(", ")}`);
  }
  run.reports.unshift({
    gate: "declaredChange",
    pass: why.length === 0,
    details: why.length === 0 ? `changedFiles and linesChanged match git diff ${s.baseCommit}..${s.headCommit}` : why.join("; "),
  });
  if (!run.reports.some((r) => r.gate === "specSeparation")) {
    // the head was not materialised (size failed or rings could not run)
    run.reports.push(attempt(run, "specSeparation", () => (io.load("gates/specSeparation") as SpecSeparationApi).checkSpecSeparation(st, s.id)));
  }
  return { ...run, change };
}

function diffList(declared: string[], actual: string[]): string {
  const a = new Set(actual);
  const d = new Set(declared);
  const extra = actual.filter((x) => !d.has(x)).map((x) => `undeclared ${x}`);
  const missing = declared.filter((x) => !a.has(x)).map((x) => `not changed ${x}`);
  return [...extra, ...missing].slice(0, 10).join(", ") || "line count differs";
}

// The head the gates judge for a ledger submission: its recorded binding, or
// one computed now from the stored patch. Without a patch, the declared head
// (a dry run that may not be recorded: nothing ties it to what gets merged).
function gatedHead(
  ctx: Ctx,
  st: CommonsState,
  s: SubmissionState,
  repo: string,
): { head: string; bind: GateReport | null; note: string } | { failed: GateReport } {
  const recorded = s.gates.find((g) => g.gate === BINDING_GATE);
  if (recorded && !recorded.pass) return { failed: { gate: BINDING_GATE, pass: false, details: recorded.details } };
  const bound = patchBinding(s);
  if (bound) return { head: bound.head, bind: null, note: `gating the bound head ${bound.head} (patch ${bound.patchSha256.slice(0, 16)})` };
  void st;
  const b = bindPatchLocal(repo, patchesDir(ctx), s);
  if (b === null) return { head: s.headCommit, bind: null, note: `no stored patch: gating the declared headCommit ${s.headCommit}, which is not what would be merged` };
  if ("error" in b) return { failed: { gate: BINDING_GATE, pass: false, details: b.error } };
  return { head: b.head, bind: { gate: BINDING_GATE, pass: true, details: bindingDetails(b) }, note: `gating ${b.head}, built from the stored patch (${b.patchSha256.slice(0, 16)})` };
}

async function gatesSubmission(ctx: Ctx): Promise<number> {
  const f = ctx.flags;
  const sid = req(f, "submission");
  const repo = resolvePath(ctx, req(f, "repo"));
  const st = state(ctx);
  const s = st.submissions.get(sid) ?? usage(`no submission ${sid}`);
  const g = gatedHead(ctx, st, s, repo);
  let run: GateRun & { change: Change | null };
  if ("failed" in g) run = { ring: null, reports: [g.failed], harness: [], notes: [], change: null };
  else {
    run = submissionGates(ctx.io, st, { ...s, headCommit: g.head }, repo, bool(f, "dependency-track"));
    run.notes.unshift(g.note);
    if (g.bind) run.reports.unshift(g.bind);
  }
  let recorded = "";
  if (bool(f, "record")) {
    if (run.harness.length > 0) usage("not recording: some gates could not run");
    if (!("failed" in g) && g.bind === null && patchBinding(s) === null) {
      usage("not recording: there is no stored patch, so the gates did not judge what would be merged");
    }
    const signer = signerKey(ctx);
    const done = new Set(s.gates.map((x) => x.gate));
    let n = 0;
    for (const r of run.reports) {
      if (done.has(r.gate)) continue;
      appendLocal(ctx, { kind: "gateResult", submissionId: sid, gate: r.gate, pass: r.pass, details: printable(r.details) }, signer);
      n++;
    }
    recorded = `recorded ${n} gate results`;
  }
  return finishGates(ctx, run.change, st.rules, run, recorded);
}

// ---------------------------------------------------------------------------
// Commit-reveal and plants
// ---------------------------------------------------------------------------

function verdictFrom(ctx: Ctx): ReviewVerdict {
  const f = ctx.flags;
  let v: unknown;
  if (str(f, "verdict") !== undefined) v = jsonArg(ctx, req(f, "verdict"), "--verdict");
  else {
    v = {
      defectProbability: num(f, "probability") ?? usage("missing --probability (or --verdict)"),
      summary: str(f, "summary") ?? "",
      findingIds: list(f, "finding"),
    };
  }
  const problems = verdictProblems(v);
  if (problems.length > 0) usage(`invalid verdict: ${problems.join("; ")}`);
  return JSON.parse(canonical(v)) as ReviewVerdict;
}

async function commitVerdict(ctx: Ctx, kind: CommitKind): Promise<number> {
  const f = ctx.flags;
  const subject = kind === "review" ? req(f, "submission") : req(f, "snapshot");
  const verdict = verdictFrom(ctx);
  const signer = signerKey(ctx);
  const dir = saltDirOf(ctx);
  if (str(f, "url") !== undefined) {
    const c = client(ctx, signer, dir);
    const stake = int(f, "stake", { min: 0 });
    try {
      const r =
        kind === "review"
          ? await c.commitReview(subject, verdict, stake === undefined ? {} : { stake })
          : await c.attestCommit(subject, verdict, stake ?? usage("missing --stake"));
      report(ctx, r.entry, `commitment ${r.commitment}`);
    } catch (e) {
      return refuse(`${kind} commit failed: ${(e as Error).message}`);
    }
    ctx.out(`salt saved in ${dir}`);
    return 0;
  }
  const st = state(ctx);
  const stake = int(f, "stake", { min: 0 }) ?? st.rules.stake.review;
  const store = fileSaltStore(dir);
  if (store.load(kind, subject)) usage(`a ${kind} commit for ${subject} is already recorded in ${dir}`);
  const salt = randomSalt();
  const commitment = commitmentOf(verdict, salt);
  // Saved before the entry exists: a commit whose salt is lost can never be revealed.
  store.save({ kind, subjectId: subject, keyId: keyIdOf(signer.publicKey), verdict, salt, commitment });
  const body: EntryBody =
    kind === "review"
      ? { kind: "reviewCommit", submissionId: subject, commitment, stake }
      : { kind: "attestCommit", snapshotId: subject, commitment, stake };
  let e: LedgerEntry;
  try {
    e = appendLocal(ctx, body, signer);
  } catch (err) {
    store.remove(kind, subject); // a local append that throws wrote nothing
    throw err;
  }
  report(ctx, e, `commitment ${commitment}`);
  ctx.out(`salt saved in ${dir}`);
  return 0;
}

async function revealVerdict(ctx: Ctx, kind: CommitKind): Promise<number> {
  const subject = kind === "review" ? req(ctx.flags, "submission") : req(ctx.flags, "snapshot");
  const signer = signerKey(ctx);
  const dir = saltDirOf(ctx);
  if (str(ctx.flags, "url") !== undefined) {
    const c = client(ctx, signer, dir);
    try {
      const r = kind === "review" ? await c.revealReview(subject) : await c.attestReveal(subject);
      report(ctx, r.entry);
    } catch (e) {
      return refuse(`${kind} reveal failed: ${(e as Error).message}`);
    }
    return 0;
  }
  const r = fileSaltStore(dir).load(kind, subject) ?? usage(`no stored ${kind} commit for ${subject} in ${dir}`);
  if (r.keyId !== keyIdOf(signer.publicKey)) usage(`the stored ${kind} commit for ${subject} belongs to key ${r.keyId}`);
  const body: EntryBody =
    kind === "review"
      ? { kind: "reviewReveal", submissionId: subject, verdict: r.verdict, salt: r.salt }
      : { kind: "attestReveal", snapshotId: subject, verdict: r.verdict, salt: r.salt };
  report(ctx, appendLocal(ctx, body, signer));
  return 0;
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

function plantFile(ctx: Ctx, submissionId: string): string {
  if (!SAFE_ID.test(submissionId)) usage(`unsafe submission id ${JSON.stringify(submissionId)}`);
  return path.join(saltDirOf(ctx), "plants", `${submissionId}.json`);
}

// ---------------------------------------------------------------------------
// Coordinator helpers
// ---------------------------------------------------------------------------

const noBridge: GithubBridge = {
  merge: () => Promise.reject(new Error("no GitHub bridge configured; merge by hand with `commons merge`")),
  fastForwardMain: () => Promise.reject(new Error("no GitHub bridge configured; promote by hand with `commons promote run`")),
};

const COORDINATOR_FLAGS: Record<string, FlagSpec> = {
  ...TREE,
  repo: { type: "string", help: "git clone with the submissions' commits (gates, reproductions)" },
  patches: { type: "string", help: "patches and finding tests directory (default <ledger dir>/patches)" },
  "review-window-hours": { type: "string", help: "hours reviewers have to reveal (default 48)" },
  phase: { type: "string", help: "1 (a human approves each merge, default) or 2" },
  approve: { type: "list", help: "phase 1: submission ids a human approved (repeatable)" },
  "snapshot-every": { type: "string", help: "merged submissions that trigger a snapshot (default: never)" },
  "required-gate": { type: "list", help: "gate every submission must pass (repeatable)" },
};

function patchesDir(ctx: Ctx): string {
  const p = str(ctx.flags, "patches");
  return p === undefined ? path.join(path.dirname(ledgerPath(ctx)), "patches") : resolvePath(ctx, p);
}

async function coordinatorPass(ctx: Ctx, store: LedgerStore, tree: TreeView): Promise<number> {
  const f = ctx.flags;
  const repo = str(f, "repo") === undefined ? null : resolvePath(ctx, req(f, "repo"));
  const approved = new Set(list(f, "approve"));
  const phase = int(f, "phase", { min: 1, dflt: 1 });
  if (phase !== 1 && phase !== 2) usage("--phase must be 1 or 2");
  const planPhase = phase as 1 | 2;
  const snapshotEvery = int(f, "snapshot-every", { min: 1 });
  const required = list(f, "required-gate");
  const dir = patchesDir(ctx);
  const { log } = await runOnce({
    state: () => store.state(),
    entries: () => store.ledger.entries(),
    append: (b) => store.appendAsCoordinator(b),
    tree,
    clock: () => ctx.io.now().toISOString(),
    entropy: () => randomSalt(),
    runGates: async (s: SubmissionState) => {
      if (repo === null) throw new Error("no --repo: cannot run gates");
      const run = submissionGates(ctx.io, store.state(), s.id, repo);
      if (run.harness.length > 0) throw new Error(`gates could not run: ${run.harness.join("; ")}`);
      return run.reports;
    },
    reproduce:
      repo === null
        ? () => Promise.resolve(null)
        : localReproducer({ repoDir: repo, testFile: (fid) => findingTestFile(dir, fid), reproduceFinding }),
    bridge: noBridge,
    selection: lazy<SelectionApi>(ctx.io, "selection"),
    humanApproval: (sid) => approved.has(sid),
    plan: {
      reviewWindowHours: int(f, "review-window-hours", { min: 0, dflt: 48 }) as number,
      phase: planPhase,
      ...(snapshotEvery === undefined ? {} : { snapshotEvery }),
      ...(required.length > 0 ? { requiredGates: required } : {}),
      incentives: lazy<IncentivesApi>(ctx.io, "incentives"),
      promotion: lazy<PromotionApi>(ctx.io, "promotion"),
    },
  });
  let failed = 0;
  for (const l of log) {
    const subject = "submissionId" in l.action ? ` ${l.action.submissionId}` : "findingId" in l.action ? ` ${l.action.findingId}` : "";
    ctx.out(`${l.ok ? "ok  " : "FAIL"} ${l.action.kind}${subject}: ${l.detail}${l.seqs.length ? ` [#${l.seqs.join(", #")}]` : ""}`);
    if (!l.ok) failed++;
  }
  if (log.length === 0) ctx.out("nothing to do");
  return failed === 0 ? 0 : 1;
}

// A module proxy that loads on first use, so a pass that never needs it never fails on it.
function lazy<T extends object>(io: Io, name: ModuleName): T {
  let mod: T | undefined;
  return new Proxy({} as T, {
    get(_t, prop) {
      mod ??= io.load(name) as T;
      return (mod as Record<string | symbol, unknown>)[prop];
    },
  });
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];
const severityArg = (v: string): Severity =>
  (SEVERITIES as readonly string[]).includes(v) ? (v as Severity) : usage(`--severity must be one of ${SEVERITIES.join(", ")}`);

const ringArg = (v: string): Ring => (v === "0" || v === "1" || v === "2" ? (Number(v) as Ring) : usage("--ring must be 0, 1 or 2"));

function evidenceFrom(ctx: Ctx): Evidence[] {
  const out: Evidence[] = [];
  for (const v of list(ctx.flags, "evidence")) {
    const j = jsonArg(ctx, v, "--evidence");
    out.push(...((Array.isArray(j) ? j : [j]) as Evidence[]));
  }
  for (const v of list(ctx.flags, "location")) {
    const m = /^([^:]+):(\d+)(?::([\s\S]*))?$/.exec(v) ?? usage(`--location must be file:line[:note], got ${JSON.stringify(v)}`);
    out.push({ kind: "location", file: m[1] as string, line: Number(m[2]), note: m[3] ?? "" });
  }
  for (const v of list(ctx.flags, "failing-test")) {
    const i = v.indexOf("=");
    if (i <= 0) usage(`--failing-test must be testId=command, got ${JSON.stringify(v)}`);
    out.push({ kind: "failingTest", testId: v.slice(0, i), command: v.slice(i + 1) });
  }
  if (out.length === 0) usage("a proposal needs evidence: --evidence <json>, --location file:line:note or --failing-test id=command");
  return out;
}

const COMMANDS: Record<string, Command> = {
  keygen: command(
    "write a new ed25519 key pair (0600) and print its key id",
    { out: { type: "string", help: "key file to create (never overwritten)", required: true } },
    (ctx) => {
      const out = resolvePath(ctx, req(ctx.flags, "out"));
      const pair = generateKeyPair();
      try {
        fs.writeFileSync(out, `${JSON.stringify(pair, null, 2)}\n`, { flag: "wx", mode: 0o600 });
        fs.chmodSync(out, 0o600);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        usage(code === "EEXIST" ? `${out} already exists; keygen never overwrites a key` : `cannot write ${out}: ${code}`);
      }
      ctx.out(keyIdOf(pair.publicKey));
      return 0;
    },
  ),

  init: command(
    "create a ledger with its genesis entry",
    {
      project: { type: "string", help: "Anthill community id of the project", required: true },
      "admin-key": { type: "list", help: "admin key file or public key (repeatable)", required: true },
      "coordinator-key": { type: "string", help: "coordinator key file or public key", required: true },
      rules: { type: "string", help: "rules JSON (default: built-in rules, or the Anthill rules with --target anthill)" },
      target: { type: "string", help: "anthill: use the Anthill adapter's rules" },
    },
    (ctx) => {
      const f = ctx.flags;
      const target = str(f, "target");
      if (target !== undefined && target !== "anthill") usage(`unknown --target ${target} (known: anthill)`);
      if (target !== undefined && str(f, "rules") !== undefined) usage("pass --rules or --target, not both");
      const rules = str(f, "rules") !== undefined ? readRules(ctx, req(f, "rules")) : target === "anthill" ? anthillRules() : defaultRules();
      const admins = list(f, "admin-key").map((k) => publicKeyArg(ctx, k, "admin-key"));
      const coordinator = publicKeyArg(ctx, req(f, "coordinator-key"), "coordinator-key");
      const p = ledgerPath(ctx);
      let ledger: Ledger;
      try {
        ledger = Ledger.create(p, { kind: "genesis", project: req(f, "project"), admins, coordinator, rules }, stamp(ctx));
      } catch (e) {
        if (e instanceof LedgerError) return usage(`cannot create ${p} (${e.code}): ${e.message}`);
        throw e;
      }
      const g = ledger.entries()[0] as LedgerEntry;
      ctx.out(`created ${p}`);
      report(ctx, g, `rules v${rules.version}`);
      return 0;
    },
  ),

  "owner add": command(
    "bind an Anthill user to a signing key (signed by an admin key)",
    {
      owner: { type: "string", help: "Anthill user id", required: true },
      "owner-key": { type: "string", help: "the owner's key file or public key", required: true },
      inviter: { type: "string", help: "owner id of the inviter (default none)" },
    },
    (ctx) => {
      const f = ctx.flags;
      const body: EntryBody = {
        kind: "ownerKey",
        owner: req(f, "owner"),
        publicKey: publicKeyArg(ctx, req(f, "owner-key"), "owner-key"),
        inviter: str(f, "inviter") ?? null,
      };
      report(ctx, appendLocal(ctx, body, signerKey(ctx)), `key ${keyIdOf(body.publicKey)}`);
      return 0;
    },
  ),

  "agent register": command(
    "register an agent key under an owner (signed by the owner key)",
    {
      ...REMOTE,
      owner: { type: "string", help: "owner id", required: true },
      "agent-key": { type: "string", help: "the agent's key file or public key", required: true },
      "model-family": { type: "string", help: "e.g. claude, gpt, qwen", required: true },
      harness: { type: "string", help: "the agent harness, e.g. claude-code", required: true },
    },
    async (ctx) => {
      const f = ctx.flags;
      const publicKey = publicKeyArg(ctx, req(f, "agent-key"), "agent-key");
      const body: EntryBody = {
        kind: "agentRegistered",
        owner: req(f, "owner"),
        publicKey,
        modelFamily: req(f, "model-family"),
        harness: req(f, "harness"),
      };
      report(ctx, await emit(ctx, body, signerKey(ctx)), `agent ${keyIdOf(publicKey)}`);
      return 0;
    },
  ),

  "agent revoke": command(
    "revoke an agent (signed by its owner, or the coordinator)",
    {
      ...REMOTE,
      agent: { type: "string", help: "agent key id, key file or public key", required: true },
      reason: { type: "string", help: "why", required: true },
    },
    async (ctx) => {
      const a = req(ctx.flags, "agent");
      const agent = /^[0-9a-f]{32}$/.test(a) ? a : keyIdOf(publicKeyArg(ctx, a, "agent"));
      report(ctx, await emit(ctx, { kind: "agentRevoked", agent, reason: req(ctx.flags, "reason") }, signerKey(ctx)));
      return 0;
    },
  ),

  propose: command(
    "propose work, with checkable evidence (signed by an agent or owner)",
    {
      ...REMOTE,
      id: { type: "string", help: "proposal id (default generated)" },
      title: { type: "string", help: "what is wrong or missing", required: true },
      evidence: { type: "list", help: "Evidence JSON (object or array; @file reads a file)" },
      location: { type: "list", help: "location evidence file:line[:note]" },
      "failing-test": { type: "list", help: "failing-test evidence testId=command" },
    },
    async (ctx) => {
      const body: EntryBody = {
        kind: "proposal",
        id: str(ctx.flags, "id") ?? newId("p"),
        title: req(ctx.flags, "title"),
        evidence: evidenceFrom(ctx),
      };
      report(ctx, await emit(ctx, body, signerKey(ctx)));
      return 0;
    },
  ),

  task: command(
    "turn a proposal into a claimable task (signed by the coordinator)",
    {
      id: { type: "string", help: "task id (default generated)" },
      proposal: { type: "string", help: "proposal id", required: true },
      ring: { type: "string", help: "0, 1 or 2", required: true },
      "acceptance-test": { type: "list", help: "acceptance test path (repeatable)", required: true },
      size: { type: "string", help: "estimated changed lines", required: true },
      "spec-author": { type: "string", help: "owner id of the spec author", required: true },
    },
    (ctx) => {
      const f = ctx.flags;
      const body: EntryBody = {
        kind: "task",
        id: str(f, "id") ?? newId("t"),
        proposalId: req(f, "proposal"),
        ring: ringArg(req(f, "ring")),
        acceptanceTestPaths: list(f, "acceptance-test"),
        sizeEstimate: int(f, "size", { min: 0 }) as number,
        specAuthor: req(f, "spec-author"),
      };
      report(ctx, appendLocal(ctx, body, signerKey(ctx)));
      return 0;
    },
  ),

  claim: command(
    "claim a task, locking stake (signed by an agent)",
    {
      ...REMOTE,
      task: { type: "string", help: "task id", required: true },
      until: { type: "string", help: "ISO expiry (default --hours from now)" },
      hours: { type: "string", help: "claim length in hours (default 24)" },
      stake: { type: "string", help: "points to lock (default the rules' minimum for the task)" },
    },
    async (ctx) => {
      const f = ctx.flags;
      if (str(f, "until") !== undefined && str(f, "hours") !== undefined) usage("pass --until or --hours, not both");
      const taskId = req(f, "task");
      let stake = int(f, "stake", { min: 0 });
      if (stake === undefined) {
        const st = needState(ctx, "--stake");
        const t = st.tasks.get(taskId) ?? refuse(`no task ${taskId}`);
        stake = Math.max(1, claimStake(t.sizeEstimate, t.ring, st.rules));
      }
      const until =
        str(f, "until") !== undefined
          ? isoArg(req(f, "until"), "until")
          : new Date(Date.parse(stamp(ctx)) + (int(f, "hours", { min: 1, dflt: 24 }) as number) * 3_600_000).toISOString();
      report(ctx, await emit(ctx, { kind: "claim", taskId, until, stake }, signerKey(ctx)), `until ${until} stake ${stake}`);
      return 0;
    },
  ),

  submit: command(
    "submit a change (signed by an agent); the change comes from --repo, --patch or --files/--lines",
    {
      ...REMOTE,
      id: { type: "string", help: "submission id (default generated)" },
      task: { type: "string", help: "task id (omit for an untasked change)" },
      base: { type: "string", help: "base commit", required: true },
      head: { type: "string", help: "head commit", required: true },
      repo: { type: "string", help: "compute files and lines from git diff base..head here" },
      patch: { type: "string", help: "unified diff file (uploaded with --url)" },
      files: { type: "list", help: "changed file (repeatable), with --lines" },
      lines: { type: "string", help: "lines changed, with --files" },
    },
    async (ctx) => {
      const f = ctx.flags;
      const sources = ["repo", "patch", "files"].filter((k) => f[k] !== undefined);
      if (sources.length !== 1) usage("pass exactly one of --repo, --patch or --files (with --lines)");
      let patch: string | null = null;
      let files: string[];
      let lines: number;
      let base = req(f, "base");
      let head = req(f, "head");
      if (str(f, "repo") !== undefined) {
        const repo = resolvePath(ctx, req(f, "repo"));
        base = resolveCommit(ctx.io.git, repo, revArg(base, "base"));
        head = resolveCommit(ctx.io.git, repo, revArg(head, "head"));
        const change = gitChanges(ctx.io.git, repo, base, head);
        if (change.unexpanded.length > 0 || change.submodules.length > 0) {
          usage("the change moves a submodule pointer; submit to the submodule's own project instead");
        }
        files = change.files;
        lines = change.linesChanged;
        if (str(f, "url") !== undefined) {
          patch = ctx.io.git(repo, ["diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--no-color", base, head, "--"]);
        }
      } else if (str(f, "patch") !== undefined) {
        patch = readText(ctx, req(f, "patch"), "patch");
        let summary;
        try {
          summary = summarisePatch(patch);
        } catch (e) {
          return usage(`patch ${req(f, "patch")}: ${(e as Error).message}`);
        }
        files = summary.files;
        lines = summary.linesChanged;
      } else {
        files = list(f, "files");
        lines = int(f, "lines", { min: 0 }) ?? usage("--files needs --lines");
      }
      const bad = files.find((p) => !isCanonicalPath(p));
      if (bad !== undefined) usage(`changed file ${JSON.stringify(bad)} is not a canonical repo path`);
      const body: EntryBody = {
        kind: "submission",
        id: str(f, "id") ?? newId("s"),
        taskId: str(f, "task") ?? null,
        baseCommit: base,
        headCommit: head,
        changedFiles: [...new Set(files)].sort(),
        linesChanged: lines,
      };
      const signer = signerKey(ctx);
      const e = await emit(ctx, body, signer);
      report(ctx, e, `${body.changedFiles.length} files, ${lines} lines`);
      if (str(f, "url") !== undefined) {
        if (patch === null) {
          ctx.out("no patch uploaded (pass --patch or --repo); the coordinator cannot gate it until one is");
          return 0;
        }
        try {
          const up = await client(ctx, signer).uploadPatch(body.id, patch);
          ctx.out(`patch ${up.created ? "uploaded" : "already stored"} ${up.sha256.slice(0, 16)}`);
        } catch (err) {
          return refuse(`submission posted but the patch upload failed: ${(err as Error).message}`);
        }
      }
      return 0;
    },
  ),

  gates: command(
    "run the static gates: CI mode (--base --head --rules) or a ledger submission (--submission)",
    {
      repo: { type: "string", help: "git checkout with both commits (CI mode: checked out at --head)", required: true },
      base: { type: "string", help: "CI mode: base commit" },
      head: { type: "string", help: "CI mode: head commit" },
      rules: { type: "string", help: "CI mode: Rules JSON to judge against" },
      submission: { type: "string", help: "ledger mode: submission id (gates run in a temporary worktree)" },
      record: { type: "boolean", help: "ledger mode: append gateResult entries (signed by the coordinator --key)" },
      "dependency-track": { type: "boolean", help: "the change is on the dependency track (may touch locked paths)" },
      json: { type: "boolean", help: "print the reports as JSON" },
    },
    (ctx) => {
      const f = ctx.flags;
      if (str(f, "submission") !== undefined) {
        for (const k of ["base", "head", "rules"]) if (f[k] !== undefined) usage(`--${k} is CI mode; --submission reads it from the ledger`);
        return gatesSubmission(ctx);
      }
      if (bool(f, "record")) usage("--record needs --submission");
      return gatesCi(ctx);
    },
  ),

  delta: command(
    "the behaviour-delta gate: replay a backend log through two anthill-backend checkouts",
    {
      old: { type: "string", help: "base anthill-backend checkout", required: true },
      new: { type: "string", help: "changed anthill-backend checkout", required: true },
      log: { type: "string", help: "backend log.jsonl", required: true },
      manifest: { type: "string", help: "behaviour-delta manifest (missing or malformed fails)", required: true },
      "base-manifest": { type: "string", help: "count only declarations not already in this manifest" },
      "timeout-ms": { type: "string", help: "per replay" },
      json: { type: "boolean", help: "print the report as JSON" },
    },
    async (ctx) => {
      const f = ctx.flags;
      const dir = (k: string) => {
        const p = resolvePath(ctx, req(f, k));
        if (!fs.existsSync(p)) usage(`--${k} ${p} does not exist`);
        return p;
      };
      const timeoutMs = int(f, "timeout-ms", { min: 1 });
      const r = await behaviourDeltaFor({
        oldBackendDir: dir("old"),
        newBackendDir: dir("new"),
        logPath: dir("log"),
        manifestPath: resolvePath(ctx, req(f, "manifest")),
        ...(str(f, "base-manifest") === undefined ? {} : { baseManifestPath: resolvePath(ctx, req(f, "base-manifest")) }),
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
      });
      if (bool(f, "json")) ctx.out(JSON.stringify(r, null, 2));
      else {
        ctx.out(`${r.pass ? "PASS" : "FAIL"} ${r.gate}: ${r.details}`);
        for (const d of r.divergences) {
          ctx.out(`  ${d.community} diverges from entry ${d.fromEntry}${d.error ? ` (${d.error})` : ""}: ${d.oldDigest.slice(0, 12) || "-"} -> ${d.newDigest.slice(0, 12) || "-"}`);
        }
      }
      return r.pass ? 0 : 1;
    },
  ),

  assign: command(
    "draw reviewers for a submission (signed by the coordinator)",
    {
      ...TREE,
      submission: { type: "string", help: "submission id", required: true },
      entropy: { type: "string", help: "external entropy for the beacon (default 32 random bytes)" },
    },
    async (ctx) => {
      const sid = req(ctx.flags, "submission");
      const tree = await loadTree(ctx);
      const selection = ctx.io.load("selection") as SelectionApi;
      const st = state(ctx);
      const beacon = selection.computeBeacon(st, sid, str(ctx.flags, "entropy") ?? randomSalt());
      const picked = selection.selectReviewers(st, tree, sid, beacon);
      for (const n of picked.notes) ctx.out(`note: ${n}`);
      if (picked.reviewers.length === 0) refuse(`no eligible reviewers among ${picked.candidates} candidates`);
      const e = appendLocal(ctx, { kind: "reviewAssignment", submissionId: sid, beacon, reviewers: picked.reviewers }, signerKey(ctx));
      report(ctx, e, `reviewers ${picked.reviewers.join(", ")}`);
      return 0;
    },
  ),

  "review commit": command(
    "commit to a review verdict; the salt is saved next to the key (<key>.salts/)",
    {
      ...REMOTE,
      submission: { type: "string", help: "submission id", required: true },
      probability: { type: "string", help: "probability of a defect of severity >= medium, 0..1" },
      summary: { type: "string", help: "verdict summary" },
      finding: { type: "list", help: "finding id the verdict cites (repeatable)" },
      verdict: { type: "string", help: "the whole verdict as JSON (or @file), instead of the three above" },
      stake: { type: "string", help: "points to lock (default the rules' review stake)" },
    },
    (ctx) => commitVerdict(ctx, "review"),
  ),

  "review reveal": command(
    "reveal a committed review verdict",
    { ...REMOTE, submission: { type: "string", help: "submission id", required: true } },
    (ctx) => revealVerdict(ctx, "review"),
  ),

  "attest commit": command(
    "commit to a snapshot attestation; the salt is saved next to the key",
    {
      ...REMOTE,
      snapshot: { type: "string", help: "snapshot id", required: true },
      probability: { type: "string", help: "probability of a defect, 0..1" },
      summary: { type: "string", help: "verdict summary" },
      finding: { type: "list", help: "finding id (repeatable)" },
      verdict: { type: "string", help: "the whole verdict as JSON (or @file)" },
      stake: { type: "string", help: "points to lock (default the rules' review stake)" },
    },
    (ctx) => commitVerdict(ctx, "attest"),
  ),

  "attest reveal": command(
    "reveal a committed attestation",
    { ...REMOTE, snapshot: { type: "string", help: "snapshot id", required: true } },
    (ctx) => revealVerdict(ctx, "attest"),
  ),

  "finding file": command(
    "claim a defect, with the test that reproduces it (signed by an agent)",
    {
      ...REMOTE,
      id: { type: "string", help: "finding id (default generated)" },
      submission: { type: "string", help: "target submission id" },
      snapshot: { type: "string", help: "target snapshot id" },
      severity: { type: "string", help: "low, medium, high or critical", required: true },
      "test-path": { type: "string", help: "repo path the test is written to", required: true },
      "test-command": { type: "string", help: "command run in the repo root; non-zero exit = failing", required: true },
      "test-file": { type: "string", help: "local file with the test content (uploaded with --url)" },
      stake: { type: "string", help: "points to lock (default the rules' finding stake)" },
    },
    async (ctx) => {
      const f = ctx.flags;
      const sub = str(f, "submission");
      const snap = str(f, "snapshot");
      if ((sub === undefined) === (snap === undefined)) usage("pass exactly one of --submission or --snapshot");
      const stake = int(f, "stake", { min: 0 }) ?? needState(ctx, "--stake").rules.stake.finding;
      const testPath = req(f, "test-path");
      if (!isCanonicalPath(testPath)) usage(`--test-path ${JSON.stringify(testPath)} is not a canonical repo path`);
      const body: EntryBody = {
        kind: "finding",
        id: str(f, "id") ?? newId("f"),
        target: sub !== undefined ? { submissionId: sub } : { snapshotId: snap as string },
        severity: severityArg(req(f, "severity")),
        testPath,
        testCommand: req(f, "test-command"),
        stake,
      };
      const content = str(f, "test-file") === undefined ? null : readText(ctx, req(f, "test-file"), "test file");
      const signer = signerKey(ctx);
      report(ctx, await emit(ctx, body, signer));
      if (str(f, "url") !== undefined) {
        if (content === null) {
          ctx.out("no test uploaded (pass --test-file); the finding cannot be reproduced until it is");
          return 0;
        }
        try {
          await client(ctx, signer).uploadFindingTest(body.id, content);
          ctx.out("test uploaded");
        } catch (e) {
          return refuse(`finding posted but the test upload failed: ${(e as Error).message}`);
        }
      }
      return 0;
    },
  ),

  "finding verify": command(
    "run a finding's test on head and parent locally (exit 0 reproduced, 1 not, 2 harness error)",
    {
      finding: { type: "string", help: "finding id", required: true },
      repo: { type: "string", help: "git clone with both commits", required: true },
      "test-file": { type: "string", help: "the finding's test content (default <patches>/findings/<id>.test)" },
      patches: { type: "string", help: "patches directory (default <ledger dir>/patches)" },
      "timeout-ms": { type: "string", help: "per run" },
      record: { type: "boolean", help: "append the findingResult (signed by the coordinator --key)" },
    },
    async (ctx) => {
      const f = ctx.flags;
      const fid = req(f, "finding");
      const st = state(ctx);
      const finding = st.findings.get(fid) ?? refuse(`no finding ${fid}`);
      const commits = findingCommits(st, fid) ?? refuse(`cannot tell which commits finding ${fid} is about`);
      const testFile = str(f, "test-file") ?? findingTestFile(patchesDir(ctx), fid);
      const timeoutMs = int(f, "timeout-ms", { min: 1 });
      const r = await reproduceFinding({
        repoDir: resolvePath(ctx, req(f, "repo")),
        baseCommit: commits.base,
        headCommit: commits.head,
        testPath: finding.testPath,
        testContent: readText(ctx, testFile, "test file"),
        testCommand: finding.testCommand,
        ...(timeoutMs === undefined ? {} : { timeoutMs }),
      });
      ctx.out(`fails on head ${commits.head}: ${r.failsOnHead}`);
      ctx.out(`passes on parent ${commits.base}: ${r.passesOnParent}`);
      ctx.out(`reproduced: ${r.reproduced} (log ${r.logDigest.slice(0, 16)})`);
      if (r.harnessError) {
        ctx.io.stderr(`commons finding verify: harness error: ${r.harnessError}\n${r.log.slice(-4000)}\n`);
        return 2;
      }
      if (bool(f, "record")) {
        const body: EntryBody = {
          kind: "findingResult",
          findingId: fid,
          reproduced: r.reproduced,
          failsOnHead: r.failsOnHead,
          passesOnParent: r.passesOnParent,
          logDigest: r.logDigest,
        };
        report(ctx, appendLocal(ctx, body, signerKey(ctx)));
      }
      return r.reproduced ? 0 : 1;
    },
  ),

  merge: command(
    "record that a submission merged into dev (signed by the coordinator)",
    {
      submission: { type: "string", help: "submission id", required: true },
      commit: { type: "string", help: "the dev commit after the merge", required: true },
    },
    (ctx) => {
      const body: EntryBody = { kind: "merge", submissionId: req(ctx.flags, "submission"), commit: req(ctx.flags, "commit") };
      report(ctx, appendLocal(ctx, body, signerKey(ctx)));
      return 0;
    },
  ),

  snapshot: command(
    "freeze a release candidate (signed by the coordinator)",
    {
      id: { type: "string", help: "snapshot id (default snapshot-<n>)" },
      commit: { type: "string", help: "dev commit (default the latest included merge)" },
      previous: { type: "string", help: "previous snapshot id, or none (default the latest snapshot)" },
      submission: { type: "list", help: "included submission (default every merged one not yet in a snapshot)" },
    },
    (ctx) => {
      const f = ctx.flags;
      const st = state(ctx);
      const inSnapshot = new Set([...st.snapshots.values()].flatMap((s) => s.submissionIds));
      const ids = list(f, "submission").length > 0
        ? list(f, "submission")
        : [...st.submissions.values()].filter((s) => s.merged && !inSnapshot.has(s.id)).sort((a, b) => (a.merged?.seq ?? 0) - (b.merged?.seq ?? 0)).map((s) => s.id);
      if (ids.length === 0) refuse("no merged submissions outside a snapshot");
      const lastMerged = ids.map((id) => st.submissions.get(id)?.merged).filter((m) => m !== undefined).sort((a, b) => b.seq - a.seq)[0];
      const commit = str(f, "commit") ?? lastMerged?.commit ?? usage("pass --commit");
      const latest = [...st.snapshots.values()].sort((a, b) => b.seq - a.seq)[0];
      const prevFlag = str(f, "previous");
      const previousSnapshotId = prevFlag === "none" ? null : (prevFlag ?? latest?.id ?? null);
      let id = str(f, "id");
      if (id === undefined) {
        let n = st.snapshots.size + 1;
        while (st.snapshots.has(`snapshot-${n}`)) n++;
        id = `snapshot-${n}`;
      }
      report(ctx, appendLocal(ctx, { kind: "snapshot", id, commit, previousSnapshotId, submissionIds: ids }, signerKey(ctx)), `${ids.length} submissions at ${commit}`);
      return 0;
    },
  ),

  signoff: command(
    "kernel signoff of a snapshot (signed by a kernel signer's owner key)",
    { ...REMOTE, snapshot: { type: "string", help: "snapshot id", required: true } },
    async (ctx) => {
      report(ctx, await emit(ctx, { kind: "signoff", snapshotId: req(ctx.flags, "snapshot") }, signerKey(ctx)));
      return 0;
    },
  ),

  "promote check": command(
    "evaluate the promotion rule for a snapshot (exit 0 pass, 1 fail)",
    { ...TREE, snapshot: { type: "string", help: "snapshot id", required: true }, json: { type: "boolean", help: "print JSON" } },
    async (ctx) => {
      const r = await evaluate(ctx);
      if (bool(ctx.flags, "json")) ctx.out(JSON.stringify(r, null, 2));
      return r.pass ? 0 : 1;
    },
  ),

  "promote run": command(
    "promote a snapshot to main if the rule passes (signed by the coordinator); moving the main branch is the bridge's job",
    { ...TREE, snapshot: { type: "string", help: "snapshot id", required: true } },
    async (ctx) => {
      const r = await evaluate(ctx);
      if (!r.pass) refuse("the promotion rule does not pass; nothing appended");
      const sid = req(ctx.flags, "snapshot");
      const snap = state(ctx).snapshots.get(sid) ?? refuse(`no snapshot ${sid}`);
      report(ctx, appendLocal(ctx, { kind: "promotion", snapshotId: sid, commit: snap.commit }, signerKey(ctx)), `main at ${snap.commit}`);
      return 0;
    },
  ),

  "plant commit": command(
    "commit to a planted bug before submitting it (signed by an admin); the salt is saved next to the key",
    {
      submission: { type: "string", help: "the id the plant will be submitted under", required: true },
      salt: { type: "string", help: "salt (default 32 random bytes)" },
    },
    (ctx) => {
      const sid = req(ctx.flags, "submission");
      const file = plantFile(ctx, sid);
      const salt = str(ctx.flags, "salt") ?? randomSalt();
      const commitment = plantCommitment(sid, salt);
      fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
      try {
        fs.writeFileSync(file, `${JSON.stringify({ submissionId: sid, salt, commitment }, null, 2)}\n`, { flag: "wx", mode: 0o600 });
      } catch (e) {
        usage((e as NodeJS.ErrnoException).code === "EEXIST" ? `a plant for ${sid} is already recorded in ${file}` : `cannot write ${file}`);
      }
      try {
        report(ctx, appendLocal(ctx, { kind: "plantCommit", commitment }, signerKey(ctx)), `commitment ${commitment}`);
      } catch (e) {
        fs.rmSync(file, { force: true }); // nothing was appended
        throw e;
      }
      ctx.out(`salt saved in ${file}`);
      return 0;
    },
  ),

  "plant reveal": command(
    "reveal a plant after its review window closed (signed by an admin)",
    {
      submission: { type: "string", help: "the planted submission id", required: true },
      description: { type: "string", help: "what the planted bug is", required: true },
      severity: { type: "string", help: "low, medium, high or critical", required: true },
    },
    (ctx) => {
      const sid = req(ctx.flags, "submission");
      const rec = readJson(ctx, plantFile(ctx, sid), "plant record") as { salt?: unknown };
      if (typeof rec?.salt !== "string") usage(`plant record for ${sid} has no salt`);
      const body: EntryBody = {
        kind: "plantReveal",
        submissionId: sid,
        salt: rec.salt as string,
        description: req(ctx.flags, "description"),
        severity: severityArg(req(ctx.flags, "severity")),
      };
      report(ctx, appendLocal(ctx, body, signerKey(ctx)));
      return 0;
    },
  ),

  settle: command(
    "append every settlement the ledger now implies (signed by the coordinator)",
    { ...TREE },
    async (ctx) => {
      const tree = await loadTree(ctx);
      const st = state(ctx);
      const nowIso = stamp(ctx, st.headAt);
      const actions = planActions(st, tree, nowIso, {
        reviewWindowHours: 0,
        incentives: ctx.io.load("incentives") as IncentivesApi,
        // settle moves reputation only; promotion is not its business
        promotion: { evaluatePromotion: () => ({ pass: false, checks: [] }) },
      });
      const signer = signerKey(ctx);
      let n = 0;
      for (const a of actions) {
        if (a.kind !== "settle") continue;
        for (const b of a.bodies) {
          report(ctx, appendLocal(ctx, b, signer), `${b.owner} ${b.delta >= 0 ? "+" : ""}${b.delta} ${b.reason}`);
          n++;
        }
      }
      ctx.out(`${n} settlements`);
      return 0;
    },
  ),

  metrics: command(
    "the health table (informs; never gates)",
    { ...TREE, json: { type: "boolean", help: "print JSON" } },
    async (ctx) => {
      const tree = await loadTree(ctx);
      const st = state(ctx);
      const rows = (ctx.io.load("metrics") as MetricsApi).computeMetrics(st, tree, stamp(ctx));
      if (bool(ctx.flags, "json")) {
        ctx.out(JSON.stringify(rows, null, 2));
        return 0;
      }
      const cells = rows.map((r) => [r.group, r.metric, typeof r.value === "string" ? r.value : JSON.stringify(r.value) ?? "", r.bad ? "BAD" : "", r.note]);
      const head = ["group", "metric", "value", "", "note"];
      const widths = head.map((h, i) => Math.max(h.length, ...cells.map((c) => (c[i] as string).length)));
      for (const row of [head, ...cells]) ctx.out(row.map((c, i) => c.padEnd(widths[i] as number)).join("  ").trimEnd());
      return 0;
    },
  ),

  serve: command(
    "the read-only playground; with --coordinator also the coordinator API (and its loop)",
    {
      ...COORDINATOR_FLAGS,
      port: { type: "string", help: "playground port (default 8080)" },
      host: { type: "string", help: "listen address (default 127.0.0.1)" },
      coordinator: { type: "boolean", help: "also serve the coordinator API (needs the coordinator --key)" },
      "api-port": { type: "string", help: "coordinator API port (default port + 1)" },
      "loop-seconds": { type: "string", help: "with --coordinator: run a coordinator pass this often (default: never)" },
    },
    async (ctx) => {
      const f = ctx.flags;
      const tree = await loadTree(ctx);
      const port = int(f, "port", { min: 0, dflt: 8080 }) as number;
      const host = str(f, "host") ?? "127.0.0.1";
      const ledger = ledgerPath(ctx);
      state(ctx); // fail now on a missing or invalid ledger
      const servers: http.Server[] = [];
      const pg = (ctx.io.load("playground") as PlaygroundApi).startPlayground({ ledgerPath: ledger, tree, port, host });
      servers.push(pg);
      pg.on("listening", () => ctx.out(`playground on http://${host}:${addrPort(pg)}`));
      let timer: NodeJS.Timeout | undefined;
      if (bool(f, "coordinator")) {
        const clock = () => ctx.io.now().toISOString();
        const store = openStore(ctx, clock);
        const api = createCoordinatorServer({
          store,
          coordinatorKey: signerKey(ctx),
          tree,
          clock,
          patchesDir: patchesDir(ctx),
          policy: ctx.io.load("incentives") as SubmitPolicy,
        });
        const apiPort = int(f, "api-port", { min: 0 }) ?? (port === 0 ? 0 : port + 1);
        api.listen(apiPort, host, () => ctx.out(`coordinator API on http://${host}:${addrPort(api)}`));
        servers.push(api);
        const every = int(f, "loop-seconds", { min: 1 });
        if (every !== undefined) {
          let running = false;
          timer = setInterval(() => {
            if (running) return;
            running = true;
            coordinatorPass(ctx, store, tree)
              .catch((e: unknown) => ctx.io.stderr(`coordinator pass: ${(e as Error).message}\n`))
              .finally(() => (running = false));
          }, every * 1000);
        }
      }
      await (ctx.io.until ?? new Promise<void>(() => {}));
      if (timer) clearInterval(timer);
      await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
      return 0;
    },
  ),

  "coordinator run-once": command(
    "one coordinator pass: settle, reproduce findings, gate, assign, merge, snapshot, promote",
    COORDINATOR_FLAGS,
    async (ctx) => {
      const tree = await loadTree(ctx);
      const store = openStore(ctx, () => ctx.io.now().toISOString());
      return coordinatorPass(ctx, store, tree);
    },
  ),
};

// The coordinator's single writer; refuses a key that is not the genesis coordinator.
function openStore(ctx: Ctx, clock: () => string): LedgerStore {
  const ledger = openLedger(ctx);
  try {
    return new LedgerStore(ledger, signerKey(ctx), clock);
  } catch (e) {
    return usage(`--key: ${(e as Error).message}`);
  }
}

function addrPort(s: http.Server): string {
  const a = s.address();
  return a !== null && typeof a === "object" ? String(a.port) : String(a);
}

async function evaluate(ctx: Ctx): Promise<{ pass: boolean; checks: { name: string; pass: boolean; detail: string }[] }> {
  const tree = await loadTree(ctx);
  const st = state(ctx);
  const sid = req(ctx.flags, "snapshot");
  if (!st.snapshots.has(sid)) refuse(`no snapshot ${sid}`);
  const r = (ctx.io.load("promotion") as PromotionApi).evaluatePromotion(st, tree, sid, stamp(ctx, st.headAt));
  if (!bool(ctx.flags, "json")) {
    for (const c of r.checks) ctx.out(`${c.pass ? "PASS" : "FAIL"} ${c.name}: ${c.detail}`);
    ctx.out(r.pass ? `promotion of ${sid}: PASS` : `promotion of ${sid}: FAIL`);
  }
  return r;
}

// Base and head a finding is judged on: a submission's own; a snapshot's
// against the previous snapshot or, for the first, the base of its earliest
// merged submission. The same rule as coordinator.ts's planner, which does not
// export it.
function findingCommits(st: CommonsState, fid: string): { base: string; head: string } | null {
  const f = st.findings.get(fid);
  if (!f) return null;
  if ("submissionId" in f.target) {
    const s = st.submissions.get(f.target.submissionId);
    return s ? { base: s.baseCommit, head: s.headCommit } : null;
  }
  const snap = st.snapshots.get(f.target.snapshotId);
  if (!snap) return null;
  const prev = snap.previousSnapshotId === null ? undefined : st.snapshots.get(snap.previousSnapshotId);
  if (prev) return { base: prev.commit, head: snap.commit };
  const first = snap.submissionIds
    .map((id) => st.submissions.get(id))
    .filter((s): s is SubmissionState => s?.merged !== undefined)
    .sort((a, b) => (a.merged?.seq ?? 0) - (b.merged?.seq ?? 0))[0];
  return first ? { base: first.baseCommit, head: snap.commit } : null;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function helpText(): string {
  const names = Object.keys(COMMANDS);
  const w = Math.max(...names.map((n) => n.length));
  return [
    "usage: commons <command> [flags]   (commons <command> --help for its flags)",
    "",
    ...names.map((n) => `  ${n.padEnd(w)}  ${(COMMANDS[n] as Command).summary}`),
    "",
    "Every command takes --ledger (default ./commons-ledger.jsonl), --key and --at.",
    "Exit codes: 0 ok, 1 refused or a check failed, 2 usage or harness error.",
    "",
  ].join("\n");
}

function commandHelp(name: string, c: Command): string {
  const flags = Object.entries(c.flags);
  const w = Math.max(...flags.map(([n, s]) => n.length + (s.type === "boolean" ? 0 : 8)));
  return [
    `usage: commons ${name} [flags]`,
    "",
    c.summary,
    "",
    ...flags.map(([n, s]) => {
      const left = `--${n}${s.type === "boolean" ? "" : " <value>"}`;
      return `  ${left.padEnd(w + 2)}  ${s.help}${s.required ? " (required)" : ""}${s.type === "list" ? " (repeatable)" : ""}`;
    }),
    "",
  ].join("\n");
}

export async function main(argv: readonly string[], io: Partial<Io> = {}): Promise<number> {
  const full: Io = {
    stdout: (t) => process.stdout.write(t),
    stderr: (t) => process.stderr.write(t),
    cwd: process.cwd(),
    now: () => new Date(),
    load: requireModule,
    git: defaultGit,
    ...io,
  };
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
    full.stdout(helpText());
    return argv.length === 0 ? 2 : 0;
  }
  const two = `${argv[0]} ${argv[1] ?? ""}`;
  const name = COMMANDS[two] ? two : (argv[0] as string);
  const cmd = COMMANDS[name];
  if (!cmd) {
    const subs = Object.keys(COMMANDS).filter((n) => n.startsWith(`${argv[0]} `));
    full.stderr(
      subs.length > 0
        ? `commons ${argv[0]}: needs a subcommand: ${subs.map((s) => s.split(" ")[1]).join(", ")}\n`
        : `commons: unknown command ${JSON.stringify(argv[0])}\n\n${helpText()}`,
    );
    return 2;
  }
  const args = argv.slice(name.split(" ").length);
  if (args.includes("--help") || args.includes("-h")) {
    full.stdout(commandHelp(name, cmd));
    return 0;
  }
  try {
    const { flags, rest } = parseArgs(args, cmd.flags);
    if (rest.length > 0) usage(`unexpected argument ${JSON.stringify(rest[0])}`);
    const ctx: Ctx = { io: full, out: (line) => full.stdout(`${line}\n`), flags, name };
    return await cmd.run(ctx);
  } catch (e) {
    if (e instanceof CliError) {
      full.stderr(`commons ${name}: ${e.message}${e.exitCode === 2 && e.message.startsWith("missing --") ? ` (see commons ${name} --help)` : ""}\n`);
      return e.exitCode;
    }
    // Unexpected: the message, and the stack only when asked for.
    const debug = process.env.COMMONS_DEBUG !== undefined && e instanceof Error;
    full.stderr(`commons ${name}: ${e instanceof Error ? (debug ? e.stack : e.message) : String(e)}\n`);
    return 2;
  }
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      process.stderr.write(`commons: ${String(e)}\n`);
      process.exitCode = 2;
    },
  );
}
