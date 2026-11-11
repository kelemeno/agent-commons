// The behaviour-delta gate: does a change to the Anthill backend change what
// the backend computes from its own history?
//
// The backend's off-chain state is an append-only log (<DATA_DIR>/log.jsonl)
// replayed into one engine per community on startup. This gate replays the same
// log through the old and the new checkout's own `Store` and `Communities`
// (src/store.ts, src/offchain.ts), digests each community's tree (digestEngine)
// at fixed points, and reports the first point at which each community's digest
// sequence differs. A divergence passes only if the change declares it in its
// manifest (`.commons/behaviour-delta.json`); an undeclared divergence fails.
// Refactors therefore pass silently, and a behaviour change has to say where it
// starts and why, which is what a reviewer would ask for anyway.
//
// What is compared is the engines' tree state, nothing else. Store-level state
// (users, passkeys, invites, polls, community settings) is not digested, so a
// store.ts change to those passes unless it also changes a tree.
//
// Entry numbering: entry i is the i-th non-empty line of log.jsonl, 0-based,
// the same lines Store replays. Digest points, per community:
// - the seed line's index, once the seed is loaded and before any action runs
//   (Store applies every non-action line up front, so this is the state the
//   first action starts from; skipped when the log has no seed);
// - each action line's index, after that action replays (or fails to);
// - the number of entries, after the whole replay, so a community that exists
//   in one checkout only is compared too.
//
// Isolation: each checkout is replayed in its own child process (this file,
// run with --worker) in its own process group, with a fresh temp dir and copy
// of the log, a minimal environment and a timeout. The result comes back over
// the IPC channel, never through a file, and the old side runs to completion
// before the new side starts, so the new code cannot find, copy or rewrite
// the old side's result (or that of any other run of this gate). A child process is
// NOT a sandbox: the new code runs as the coordinator's user, can read and
// write what that user can (the old checkout, this file), can escape the
// process group, and can forge its own result. Run the coordinator unprivileged
// or in a throwaway container for untrusted submissions; the gate catches
// honest mistakes and lazy gaming, not a determined adversary — whose
// harness-tampering code is in the diff, where reviewers see it.
//
// Harness failures (a replay that throws, times out, dies or writes a
// malformed result) fail the gate with no divergences: no manifest can
// declare them away, because nothing was compared.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import type { Readable } from "node:stream";
import { pathToFileURL } from "node:url";
import type { GateReport } from "../types";

export const GATE = "behaviourDelta";
const DEFAULT_TIMEOUT_MS = 120_000;
const STDERR_TAIL = 4000;
// How long to wait, after the worker exits, for its result message and stderr
// to arrive. Bounded: a grandchild holding a pipe open must not hold the gate.
const EXIT_GRACE_MS = 250;

export type DeclaredDelta = { community: string; fromEntry: number; note: string };
export type Manifest = { declared: DeclaredDelta[] };

export type Divergence = {
  community: string;
  fromEntry: number;
  oldDigest: string; // "" when the community has no state on that side yet
  newDigest: string;
  // set when the sides differ in whether (or how) an entry failed to replay,
  // or when the community or entry is missing on one side
  error?: string;
};

type VoteTuple = readonly [string, bigint, bigint, bigint]; // id, weight, dist, posInOther

// What digestEngine reads: the public getters of the backend's AnthillEngine.
// Structural so an older or newer engine works as long as these stay.
export type EngineLike = {
  members(): string[];
  parent(id: string): string;
  children(id: string): string[];
  calculateReputation(id: string): bigint;
  read: {
    nameOf(args: readonly [string]): Promise<string>;
    sentDagVoteCount(args: readonly [string]): Promise<bigint>;
    sentDagVote(args: readonly [string, bigint]): Promise<VoteTuple>;
    recDagVoteCount(args: readonly [string]): Promise<bigint>;
    recDagVote(args: readonly [string, bigint]): Promise<VoteTuple>;
    sentDagVoteTotalWeight(args: readonly [string]): Promise<bigint>;
  };
};

// sha256 of a canonical description of one community's tree: members sorted by
// id, each with name, parent, children in tree order, sent and received DAG
// votes as full slot tuples in slot order, total sent weight, and reputation.
// Slot order, dist and posInOther are state: the engine mirrors the contract's
// storage, and later moves and removals read them. Only strings and arrays, so
// JSON.stringify is already canonical.
//
// Not digested: the stored reputation and its epoch. That cache is written by
// calculateReputation (by this digest too, so reading it here would measure
// the digest), and nothing the engine decides reads it.
export async function digestEngine(engine: EngineLike): Promise<string> {
  const votes = async (count: bigint, at: (pos: bigint) => Promise<VoteTuple>) => {
    const out: string[][] = [];
    for (let pos = 0n; pos < count; pos++) out.push((await at(pos)).map(String));
    return out;
  };
  const rows: unknown[] = [];
  for (const id of [...engine.members()].sort()) {
    rows.push([
      id,
      await engine.read.nameOf([id]),
      engine.parent(id),
      engine.children(id),
      await votes(await engine.read.sentDagVoteCount([id]), (pos) => engine.read.sentDagVote([id, pos])),
      await votes(await engine.read.recDagVoteCount([id]), (pos) => engine.read.recDagVote([id, pos])),
      (await engine.read.sentDagVoteTotalWeight([id])).toString(),
      engine.calculateReputation(id).toString(),
    ]);
  }
  return createHash("sha256").update(JSON.stringify(rows)).digest("hex");
}

// Throws with a message naming the first problem.
export function parseManifest(json: unknown): Manifest {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    throw new Error("manifest: expected an object");
  }
  const declared = (json as { declared?: unknown }).declared;
  if (!Array.isArray(declared)) throw new Error("manifest: `declared` must be an array");
  return {
    declared: declared.map((d: unknown, i) => {
      const where = `manifest: declared[${i}]`;
      if (typeof d !== "object" || d === null || Array.isArray(d)) throw new Error(`${where} must be an object`);
      const { community, fromEntry, note } = d as Record<string, unknown>;
      if (typeof community !== "string" || community === "") {
        throw new Error(`${where}.community must be a non-empty string`);
      }
      if (typeof fromEntry !== "number" || !Number.isSafeInteger(fromEntry) || fromEntry < 0) {
        throw new Error(`${where}.fromEntry must be a non-negative integer`);
      }
      // A declaration is an explanation for reviewers; an empty one explains nothing.
      if (typeof note !== "string" || note.trim() === "") {
        throw new Error(`${where}.note must say why the behaviour changes`);
      }
      return { community, fromEntry, note };
    }),
  };
}

export function loadManifest(path: string): Manifest {
  let json: unknown;
  try {
    json = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new Error(`manifest: cannot read ${path}: ${errorMessage(e)}`);
  }
  return parseManifest(json);
}

// One point in a community's digest sequence. `error` is set when the entry
// failed to replay (the backend skips such entries; the digest is then the
// community's previous one). A Map, not an object: community ids come from
// users, and "constructor" is a valid one.
export type DigestRecord = { entry: number; digest: string; error?: string };
export type ReplayResult = { entries: number; communities: Map<string, DigestRecord[]> };

export async function runBehaviourDelta(opts: {
  oldBackendDir: string;
  newBackendDir: string;
  logPath: string;
  manifest?: Manifest;
  timeoutMs?: number;
}): Promise<GateReport & { divergences: Divergence[] }> {
  const fail = (details: string) => ({ gate: GATE, pass: false, details, divergences: [] });

  let manifest: Manifest;
  try {
    manifest = parseManifest(opts.manifest ?? { declared: [] });
  } catch (e) {
    return fail(errorMessage(e));
  }
  if (!existsSync(opts.logPath)) return fail(`no log at ${opts.logPath}`);

  // Sequential on purpose: see "Isolation" above.
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const oldRun = await replayInChild(resolve(opts.oldBackendDir), opts.logPath, timeoutMs);
  const newRun = await replayInChild(resolve(opts.newBackendDir), opts.logPath, timeoutMs);
  const problems: string[] = [];
  if ("error" in oldRun) problems.push(`old checkout: ${oldRun.error}`);
  if ("error" in newRun) problems.push(`new checkout: ${newRun.error}`);
  if ("error" in oldRun || "error" in newRun) return fail(`replay failed\n${problems.join("\n")}`);
  if (oldRun.entries !== newRun.entries) {
    return fail(`the checkouts read different entry counts (${oldRun.entries} vs ${newRun.entries})`);
  }

  const divergences = compareReplays(oldRun, newRun);
  const { pass, details } = judge(divergences, manifest, oldRun);
  return { gate: GATE, pass, details, divergences };
}

// First differing record per community, in community-id order.
export function compareReplays(oldRun: ReplayResult, newRun: ReplayResult): Divergence[] {
  const ids = [...new Set([...oldRun.communities.keys(), ...newRun.communities.keys()])].sort();
  const divergences: Divergence[] = [];
  for (const community of ids) {
    const oldRecords = new Map((oldRun.communities.get(community) ?? []).map((r) => [r.entry, r]));
    const newRecords = new Map((newRun.communities.get(community) ?? []).map((r) => [r.entry, r]));
    const entries = [...new Set([...oldRecords.keys(), ...newRecords.keys()])].sort((a, b) => a - b);
    let oldLast = "";
    let newLast = "";
    for (const entry of entries) {
      const o = oldRecords.get(entry);
      const n = newRecords.get(entry);
      const error = recordMismatch(o, n);
      if (error !== undefined || o?.digest !== n?.digest) {
        divergences.push({
          community,
          fromEntry: entry,
          oldDigest: o?.digest ?? oldLast,
          newDigest: n?.digest ?? newLast,
          ...(error === undefined ? {} : { error }),
        });
        break;
      }
      oldLast = o?.digest ?? oldLast;
      newLast = n?.digest ?? newLast;
    }
  }
  return divergences;
}

function recordMismatch(o: DigestRecord | undefined, n: DigestRecord | undefined): string | undefined {
  if (o === undefined) return "the new checkout has state here and the old one does not";
  if (n === undefined) return "the old checkout has state here and the new one does not";
  if (o.error === n.error) return undefined;
  if (o.error === undefined) return `the new checkout fails to replay this entry: ${n.error}`;
  if (n.error === undefined) return `the old checkout failed to replay this entry and the new one replays it: ${o.error}`;
  return `the replay fails differently: old: ${o.error}; new: ${n.error}`;
}

// Declarations are trusted as given. Tying them to the change that adds them
// (so one left in the file cannot cover a later change) is the caller's job:
// see addedDeclarations in src/adapters/anthill.ts. Only the first divergence
// per community is visible, so a declaration covers everything after it in
// that community; the gap between where it starts and where the divergence
// starts is reported so reviewers see how much it could hide.
function judge(
  divergences: Divergence[],
  manifest: Manifest,
  run: ReplayResult,
): { pass: boolean; details: string } {
  const lines: string[] = [];
  let pass = true;
  for (const d of divergences) {
    // The latest covering declaration is the tightest; any covering one passes.
    const covering = manifest.declared
      .filter((m) => m.community === d.community && m.fromEntry <= d.fromEntry)
      .sort((a, b) => b.fromEntry - a.fromEntry)[0];
    const what = `community ${d.community} diverges from entry ${d.fromEntry}${d.error ? ` (${d.error})` : ""}`;
    if (covering === undefined) {
      pass = false;
      const later = manifest.declared.find((m) => m.community === d.community);
      lines.push(
        `- UNDECLARED: ${what}${later ? `; declared only from entry ${later.fromEntry}, after it starts` : ""}`,
      );
    } else {
      const gap = d.fromEntry - covering.fromEntry;
      const early = gap > 0 ? `, ${gap} entries before it starts` : "";
      lines.push(`- declared: ${what}; declared from entry ${covering.fromEntry}${early}: ${covering.note}`);
    }
  }
  for (const m of manifest.declared) {
    if (!divergences.some((d) => d.community === m.community)) {
      lines.push(`- declared but not observed: community ${m.community} from entry ${m.fromEntry}`);
    }
  }
  const communities = run.communities.size;
  const head =
    divergences.length === 0
      ? `no behaviour change across ${communities} communities and ${run.entries} log entries`
      : `${divergences.length} of ${communities} communities diverge over ${run.entries} log entries`;
  return { pass, details: [head, ...lines].join("\n") };
}

////////////////////////////////////////////
//// replay in a child process

type ChildOutcome = ReplayResult | { error: string };

function tsxLoaderUrl(): string {
  return pathToFileURL(require.resolve("tsx")).href;
}

// Settles on the worker's exit (plus a bounded grace for its last message) or
// the deadline, whichever comes first; never on stdio EOF, which a grandchild
// can hold off forever. On settling, the worker's process group is killed and
// its temp dir removed.
async function replayInChild(checkoutDir: string, logPath: string, timeoutMs: number): Promise<ChildOutcome> {
  const work = mkdtempSync(join(tmpdir(), "behaviour-delta-"));
  try {
    const dataDir = join(work, "data");
    const home = join(work, "home");
    mkdirSync(dataDir, { recursive: true });
    mkdirSync(home, { recursive: true });
    copyFileSync(logPath, join(dataDir, "log.jsonl"));
    return await new Promise<ChildOutcome>((done) => {
      let stderr = "";
      let settled = false;
      let message: { result: unknown } | undefined;
      const child = spawn(
        process.execPath,
        ["--import", tsxLoaderUrl(), __filename, "--worker", checkoutDir, dataDir],
        {
          cwd: work,
          // Minimal and fixed, so replay cannot depend on the coordinator's
          // environment and the checkout cannot read its secrets from it.
          env: { PATH: process.env.PATH ?? "/usr/bin:/bin", HOME: home, TMPDIR: work },
          stdio: ["ignore", "ignore", "pipe", "ipc"],
          detached: true, // its own process group, so a timeout kills its children too
        },
      );
      const errPipe = child.stderr as Readable; // stdio[2] is "pipe"
      const settle = (outcome: ChildOutcome) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (child.pid !== undefined) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            // the group is already gone
          }
        }
        errPipe.destroy();
        done(outcome);
      };
      errPipe.on("data", (chunk: Buffer) => {
        stderr = (stderr + chunk.toString()).slice(-STDERR_TAIL);
      });
      // The first message is the result; a well-behaved worker sends one.
      child.on("message", (m: unknown) => {
        message ??= { result: m };
      });
      const timer = setTimeout(() => settle({ error: `replay timed out after ${timeoutMs} ms` }), timeoutMs);
      child.on("error", (e) => settle({ error: `cannot start the replay: ${e.message}` }));
      child.on("exit", (code, signal) => {
        const finish = () => {
          if (message !== undefined) return settle(validResult(message.result));
          const how = signal !== null ? `signal ${signal}` : `exit code ${code}`;
          settle({ error: `replay died (${how}) without a result${stderr ? `\n${stderr.trim()}` : ""}` });
        };
        // Both the message and stderr's end usually arrive before or right
        // after 'exit'; wait for the two, but never past the grace.
        const grace = setTimeout(finish, EXIT_GRACE_MS);
        let pending = 2;
        const arrived = () => {
          if (--pending === 0) {
            clearTimeout(grace);
            finish();
          }
        };
        errPipe.once("end", arrived);
        if (message !== undefined || !child.connected) arrived();
        else child.once("disconnect", arrived);
      });
    });
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// The worker's wire format: communities as [id, records] pairs.
function validResult(result: unknown): ChildOutcome {
  const bad = { error: "the replay wrote a malformed result" };
  if (typeof result !== "object" || result === null) return bad;
  if ("error" in result) return { error: String((result as { error: unknown }).error) };
  const { entries, communities } = result as { entries?: unknown; communities?: unknown };
  if (typeof entries !== "number" || !Array.isArray(communities)) return bad;
  const out = new Map<string, DigestRecord[]>();
  for (const pair of communities as unknown[]) {
    if (!Array.isArray(pair) || pair.length !== 2) return bad;
    const [id, records] = pair as [unknown, unknown];
    if (typeof id !== "string" || out.has(id) || !Array.isArray(records)) return bad;
    const list: DigestRecord[] = [];
    for (const r of records as unknown[]) {
      if (typeof r !== "object" || r === null) return bad;
      const { entry, digest, error } = r as Record<string, unknown>;
      if (typeof entry !== "number" || typeof digest !== "string") return bad;
      if (error !== undefined && typeof error !== "string") return bad;
      list.push(error === undefined ? { entry, digest } : { entry, digest, error });
    }
    out.set(id, list);
  }
  return { entries, communities: out };
}

// What the worker needs from a checkout's src/store.ts and src/offchain.ts.
type StoreLike = { communityOf(entry: object): string };
type TreeLike = { id: string; engine: EngineLike };
type CommunitiesLike = {
  all(): TreeLike[];
  load(onReplayed: (executed: { tree: TreeLike; entry: object }) => Promise<void>): Promise<void>;
};

// The log's own encoding of an entry, so a replayed entry is matched to its
// line by content: the replay may pass copies, and a Store that drops or
// alters an action must show up as a divergence, not break the harness.
// bigints are written the way the backend's bigintReplacer writes them.
function entryKey(entry: unknown): string {
  return JSON.stringify(entry, (_k, v: unknown) => (typeof v === "bigint" ? { __bigint__: v.toString() } : v));
}

// Runs inside the child: replay one checkout and return its digest sequences.
export async function replayCheckout(checkoutDir: string, dataDir: string): Promise<ReplayResult> {
  const { Store } = require(join(checkoutDir, "src", "store.ts")) as { Store: new (dir: string) => StoreLike };
  const { Communities } = require(join(checkoutDir, "src", "offchain.ts")) as {
    Communities: new (store: StoreLike) => CommunitiesLike;
  };

  const lines = readFileSync(join(dataDir, "log.jsonl"), "utf8")
    .split("\n")
    .filter((line) => line.trim() !== "");
  const parsed = lines.map((line) => JSON.parse(line) as { type?: unknown; community?: string });
  const actionLines = parsed.flatMap((e, i) => (e.type === "action" ? [i] : []));
  const byKey = new Map<string, number[]>(); // unreplayed action lines, in log order, per content
  for (const i of actionLines) {
    const key = entryKey(parsed[i]);
    const queue = byKey.get(key);
    if (queue === undefined) byKey.set(key, [i]);
    else queue.push(i);
  }

  const communities = new Map<string, DigestRecord[]>();
  const lastDigest = new Map<string, string>();
  const record = (community: string, entry: number, digest: string | undefined, error?: string) => {
    const r: DigestRecord = { entry, digest: digest ?? lastDigest.get(community) ?? "" };
    if (error !== undefined) r.error = error;
    const list = communities.get(community);
    if (list === undefined) communities.set(community, [r]);
    else list.push(r);
    lastDigest.set(community, r.digest);
  };

  // The state before the first action: a second replay of only the non-action
  // lines, since Communities.load gives no hook between seeding and actions.
  const seedLine = parsed.findIndex((e) => e.type === "seed");
  if (seedLine >= 0) {
    const seedDir = mkdtempSync(join(tmpdir(), "behaviour-delta-seed-"));
    try {
      const nonActions = lines.filter((_, i) => parsed[i]?.type !== "action");
      writeFileSync(join(seedDir, "log.jsonl"), `${nonActions.join("\n")}\n`);
      const seeded = new Communities(new Store(seedDir));
      await seeded.load(async () => {});
      for (const tree of seeded.all()) record(tree.id, seedLine, await digestEngine(tree.engine));
    } finally {
      rmSync(seedDir, { recursive: true, force: true });
    }
  }

  const store = new Store(dataDir);
  // The replay runs actions in log order and reports each one, by callback or
  // by warning. An action line it passes over without a report (or that Store
  // never loaded) is a skip too; it is recorded when the replay moves past it,
  // so it gets the digest of that moment.
  const done = new Set<number>();
  let cursor = 0; // into actionLines: everything before it is done
  const skipUpTo = (line: number) => {
    for (; cursor < actionLines.length && (actionLines[cursor] as number) < line; cursor++) {
      const i = actionLines[cursor] as number;
      if (done.has(i)) continue;
      done.add(i);
      record(store.communityOf(parsed[i] as object), i, undefined, "skipped without a report");
    }
  };
  // The log line a reported entry came from, and an error when the entry is
  // not on any unreplayed line as written (then it takes the next one).
  const reached = (entry: object): { line: number; error?: string } => {
    const queue = byKey.get(entryKey(entry)) ?? [];
    while (queue.length > 0 && done.has(queue[0] as number)) queue.shift();
    let line = queue.shift();
    let error: string | undefined;
    if (line === undefined) {
      line = actionLines.slice(cursor).find((i) => !done.has(i));
      if (line === undefined) throw new Error("the replay reported more actions than the log has");
      error = "the replay ran an entry that differs from the log line";
    }
    skipUpTo(line);
    done.add(line);
    return error === undefined ? { line } : { line, error };
  };

  // Communities.load skips an action that now fails and only says so through
  // console.warn("replay: ...", entry, error). Restored afterwards, so calling
  // this outside the worker leaves console alone.
  const warn = console.warn;
  console.warn = (...args: unknown[]) => {
    const [message, entry, error] = args;
    if (typeof message !== "string" || !message.startsWith("replay:")) return;
    if (typeof entry !== "object" || entry === null) return;
    const at = reached(entry);
    const why = at.error === undefined ? errorMessage(error) : `${at.error}; ${errorMessage(error)}`;
    record(store.communityOf(entry), at.line, undefined, why);
  };
  const replayed = new Communities(store);
  try {
    await replayed.load(async ({ tree, entry }) => {
      const at = reached(entry);
      record(tree.id, at.line, await digestEngine(tree.engine), at.error);
    });
  } finally {
    console.warn = warn;
  }
  skipUpTo(lines.length);

  for (const tree of replayed.all()) record(tree.id, lines.length, await digestEngine(tree.engine));
  for (const records of communities.values()) records.sort((a, b) => a.entry - b.entry);
  return { entries: lines.length, communities };
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// Exits explicitly once the result is sent: checkout code that leaves a timer
// or socket open must not turn a finished replay into a timeout.
if (require.main === module && process.argv[2] === "--worker") {
  const [checkoutDir, dataDir] = process.argv.slice(3) as [string, string];
  const send = (payload: unknown) => {
    if (process.send === undefined) {
      process.stderr.write("the worker needs an IPC channel to its coordinator\n");
      process.exit(1);
    }
    process.send(payload, () => process.exit(0));
  };
  replayCheckout(checkoutDir, dataDir).then(
    (r) => send({ entries: r.entries, communities: [...r.communities] }),
    (e: unknown) => send({ error: errorMessage(e) }),
  );
}
