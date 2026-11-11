// The coordinator's HTTP API: the only door through which participants' agents
// reach the ledger. The coordinator process is the sole holder of the ledger
// file and the coordinator key; agents sign entries themselves and POST them.
//
// Contract with clients:
// - GET /api/head returns the last entry's {seq, hash, at} and nextSeq. A client
//   signs its entry with seq = nextSeq, prev = hash and at = max(its clock,
//   head.at) (the ledger rejects time that goes backwards). On 409 it
//   refetches the head and signs again; nothing else changes.
// - POST /api/entries takes exactly one signed LedgerEntry. Policy (kind
//   allowlist, clock skew, rate limit, submit credits, PR slots, claim stake)
//   is enforced before the ledger's own validation, so a policy refusal never
//   reaches the file. The ledger then validates the entry against its own
//   signature (Ledger.appendSigned) and writes it only if valid.
// - POST /api/patches/:submissionId takes the raw unified diff of a submission,
//   authenticated by the submission's author key over sha256hex(patch). The
//   patch must touch exactly the submission's changedFiles and change exactly
//   linesChanged lines, because the gates judge those declared fields. Stored
//   once; a different patch for the same submission is refused.
// - POST /api/findings/:findingId/test takes the test file of a finding, by the
//   finder, same authentication. The reproduction harness reads it from disk.
//
// Every ledger write (agent entries here, coordinator entries from the loop in
// coordinator.ts) goes through one LedgerStore, whose mutex serialises them.

import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { keyIdOf, sha256hex, verify } from "./crypto";
import { parsePatch } from "./github";
import { entryMessage, Ledger, LedgerError, type LedgerState, type Signer } from "./ledger";
import type { CommonsState, EntryBody, EntryKind, LedgerEntry, OwnerId, Ring, Rules, TreeView } from "./types";

// ---------------------------------------------------------------------------
// Ledger store: one Ledger instance, one writer at a time.
// ---------------------------------------------------------------------------

export type Head = { seq: number; hash: string; at: string; nextSeq: number };

export class LedgerStore {
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    readonly ledger: Ledger,
    private readonly coordinatorKey: Signer,
    private readonly clock: () => string,
  ) {
    if (keyIdOf(coordinatorKey.publicKey) !== ledger.state().coordinatorKey) {
      throw new Error("coordinator key does not match the genesis coordinator");
    }
  }

  static open(ledgerPath: string, coordinatorKey: Signer, clock: () => string): LedgerStore {
    return new LedgerStore(Ledger.open(ledgerPath), coordinatorKey, clock);
  }

  // Runs fn after every earlier locked call has settled. Ledger operations are
  // synchronous, so the lock matters for callers that read state, await, then
  // write: they must hold it across the whole sequence.
  lock<T>(fn: () => T | Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.catch(() => undefined);
    return run;
  }

  state(): CommonsState {
    return this.ledger.state();
  }

  head(): Head {
    const s = this.ledger.state() as LedgerState;
    return { seq: s.length - 1, hash: s.headHash, at: s.headAt, nextSeq: s.length };
  }

  // Coordinator entries are stamped no earlier than the head: an agent whose
  // clock runs ahead (within the allowed skew) must not make the loop's next
  // write look like time going backwards. A function body is built from the
  // state it will be appended to, under the lock, so nothing lands between
  // what it read and what it appends (a reviewer beacon covers the exact head;
  // a merge is re-checked while the bridge merges). Agent posts wait meanwhile.
  appendAsCoordinator(body: EntryBody | ((state: CommonsState) => EntryBody | Promise<EntryBody>)): Promise<LedgerEntry> {
    return this.lock(async () => {
      const made = typeof body === "function" ? await body(this.ledger.state()) : body;
      const now = this.clock();
      const headAt = this.head().at;
      const at = Date.parse(now) >= Date.parse(headAt) ? now : headAt;
      return this.ledger.append(made, this.coordinatorKey, at);
    });
  }
}

// ---------------------------------------------------------------------------
// Policy hooks from incentives.ts. Typed here from ARCHITECTURE.md so this file
// compiles and its tests run before incentives.ts exists; the default loads
// the real module at server creation and fails loudly if it is missing.
// ---------------------------------------------------------------------------

export type SubmitPolicy = {
  submitCredits(state: CommonsState, owner: OwnerId): number;
  prSlots(reputation: number): number;
  claimStake(lines: number, ring: Ring, rules: Rules): number;
};

function loadIncentives(): SubmitPolicy {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("./incentives") as SubmitPolicy;
  } catch (e) {
    throw new Error(`src/incentives.ts could not be loaded; pass opts.policy (${String(e)})`);
  }
}

export type ServerLimits = {
  entryBytes: number; // POST /api/entries body
  patchBytes: number; // POST /api/patches/:id body
  testBytes: number; // POST /api/findings/:id/test body
  clockSkewMs: number; // |entry.at - now| must not exceed this
  ratePerMinute: number; // token bucket per owner, burst = one minute's worth
};

export const DEFAULT_LIMITS: ServerLimits = {
  entryBytes: 256 * 1024,
  patchBytes: 1024 * 1024,
  testBytes: 256 * 1024,
  clockSkewMs: 5 * 60_000,
  ratePerMinute: 60,
};

// Kinds a participant may post. Everything else is signed by the coordinator
// loop or an admin (ownerKey comes from the Anthill backend, plants from the
// custodian) and never enters through this API.
export const PARTICIPANT_KINDS: ReadonlySet<EntryKind> = new Set<EntryKind>([
  "agentRegistered",
  "agentRevoked",
  "proposal",
  "claim",
  "submission",
  "reviewCommit",
  "reviewReveal",
  "finding",
  "attestCommit",
  "attestReveal",
  "signoff",
]);

export type CoordinatorServerOptions = {
  ledgerPath?: string; // opened here unless `store` is given
  store?: LedgerStore; // share one store with the coordinator loop
  coordinatorKey: Signer;
  tree: TreeView;
  clock: () => string;
  patchesDir: string;
  limits?: Partial<ServerLimits>;
  policy?: SubmitPolicy; // default: src/incentives.ts
  // Called after a patch is stored for the first time (the GitHub bridge opens
  // the PR from here). Errors are logged, never shown to the uploader.
  onPatch?: (submissionId: string, file: string) => void | Promise<void>;
  // Requests no route here matches (e.g. the playground's GET routes).
  fallback?: http.RequestListener;
};

export type CoordinatorServer = http.Server & { store: LedgerStore };

// Returned unlistened: the caller picks the port (tests use 0).
export function createCoordinatorServer(opts: CoordinatorServerOptions): CoordinatorServer {
  const limits: ServerLimits = { ...DEFAULT_LIMITS, ...opts.limits };
  const policy = opts.policy ?? loadIncentives();
  const store =
    opts.store ??
    LedgerStore.open(opts.ledgerPath ?? fail("ledgerPath or store is required"), opts.coordinatorKey, opts.clock);
  const buckets = new Map<OwnerId, { tokens: number; atMs: number }>();
  fs.mkdirSync(path.join(opts.patchesDir, "findings"), { recursive: true });

  // True and one token spent, or false when the owner's bucket is empty.
  const takeToken = (owner: OwnerId): boolean => {
    const now = Date.parse(opts.clock());
    const cap = limits.ratePerMinute;
    const b = buckets.get(owner) ?? { tokens: cap, atMs: now };
    b.tokens = Math.min(cap, b.tokens + (Math.max(0, now - b.atMs) * cap) / 60_000);
    b.atMs = now;
    buckets.set(owner, b);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  };

  const ctx: Ctx = { opts, limits, policy, store, takeToken };
  const server = http.createServer((req, res) => {
    handle(ctx, req, res).catch((e: unknown) => {
      console.error("coordinator server:", e);
      if (!res.headersSent) send(res, 500, { error: "internal", message: "internal error" });
      else res.destroy();
    });
  }) as CoordinatorServer;
  server.store = store;
  return server;
}

type Ctx = {
  opts: CoordinatorServerOptions;
  limits: ServerLimits;
  policy: SubmitPolicy;
  store: LedgerStore;
  takeToken: (owner: OwnerId) => boolean;
};

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: Record<string, unknown> = {},
  ) {
    super(message);
  }
}

function fail(message: string): never {
  throw new Error(message);
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

async function handle(ctx: Ctx, req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const method = req.method ?? "GET";
  const p = url.pathname;
  try {
    if (method === "GET" && p === "/api/head") return send(res, 200, ctx.store.head());
    if (method === "POST" && p === "/api/entries") return send(res, 201, await postEntry(ctx, req));
    if (method === "GET" && p === "/api/assignments") return send(res, 200, assignments(ctx, url));
    const patch = /^\/api\/patches\/([^/]+)$/.exec(p);
    if (patch) {
      const sid = decodeURIComponent(patch[1] ?? "");
      if (method === "POST") return send(res, 201, await postPatch(ctx, req, sid));
      if (method === "GET") return getPatch(ctx, res, sid);
    }
    const test = /^\/api\/findings\/([^/]+)\/test$/.exec(p);
    if (test && method === "POST") return send(res, 201, await postFindingTest(ctx, req, decodeURIComponent(test[1] ?? "")));
  } catch (e) {
    if (e instanceof HttpError) {
      const headers: Record<string, string> = {};
      if (e.status === 413) headers.Connection = "close";
      if (e.status === 429) headers["Retry-After"] = "1";
      return send(res, e.status, { error: e.code, message: e.message, ...e.extra }, headers);
    }
    if (e instanceof URIError) return send(res, 400, { error: "malformed", message: "bad path encoding" });
    throw e;
  }
  if (ctx.opts.fallback) return ctx.opts.fallback(req, res);
  send(res, 404, { error: "not-found", message: `no route ${method} ${p}` });
}

function send(res: http.ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": String(Buffer.byteLength(text)),
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(text);
}

// Reads at most `limit` bytes; a declared or actual larger body is a 413
// without buffering the rest.
function readBody(req: http.IncomingMessage, limit: number): Promise<Buffer> {
  const declared = Number(req.headers["content-length"] ?? "0");
  if (declared > limit) {
    req.resume();
    return Promise.reject(new HttpError(413, "too-large", `body exceeds ${limit} bytes`));
  }
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on("data", (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > limit) {
        done = true;
        reject(new HttpError(413, "too-large", `body exceeds ${limit} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!done) resolve(Buffer.concat(chunks));
    });
    req.on("error", (e) => {
      if (!done) reject(e);
      done = true;
    });
  });
}

// ---------------------------------------------------------------------------
// POST /api/entries
// ---------------------------------------------------------------------------

const ENVELOPE_KEYS = ["at", "body", "hash", "prev", "seq", "sig", "signer"];

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// Only enough shape to read the fields policy needs; the ledger checks the rest.
function envelope(raw: unknown): LedgerEntry {
  const bad = (msg: string): never => {
    throw new HttpError(400, "malformed", msg);
  };
  if (!isObject(raw)) return bad("expected one ledger entry object");
  const keys = Object.keys(raw).sort();
  if (keys.join(",") !== ENVELOPE_KEYS.join(",")) bad(`entry fields must be exactly ${ENVELOPE_KEYS.join(", ")}`);
  if (!Number.isSafeInteger(raw.seq)) bad("seq must be an integer");
  for (const k of ["prev", "at", "signer", "sig", "hash"]) if (typeof raw[k] !== "string") bad(`${k} must be a string`);
  if (!isObject(raw.body) || typeof raw.body.kind !== "string") bad("body must be an object with a kind");
  return raw as unknown as LedgerEntry;
}

async function postEntry(ctx: Ctx, req: http.IncomingMessage): Promise<{ seq: number; hash: string }> {
  const raw = await readBody(req, ctx.limits.entryBytes);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HttpError(400, "malformed", "body is not JSON");
  }
  const entry = envelope(parsed);
  const kind = entry.body.kind;
  if (!PARTICIPANT_KINDS.has(kind)) {
    throw new HttpError(403, "forbidden-kind", `${kind} entries are written by the coordinator or an admin only`);
  }
  const atMs = Date.parse(entry.at);
  if (Number.isNaN(atMs)) throw new HttpError(400, "time", "at is not a time");
  if (Math.abs(atMs - Date.parse(ctx.opts.clock())) > ctx.limits.clockSkewMs) {
    throw new HttpError(400, "clock-skew", `at must be within ${ctx.limits.clockSkewMs / 1000}s of the server clock`);
  }

  return ctx.store.lock(() => {
    const state = ctx.store.state();
    const head = ctx.store.head();
    // The signature is checked before the rate limit is charged, so nobody can
    // drain another owner's bucket by posting garbage under their key id.
    if (entry.signer === state.coordinatorKey) {
      throw new HttpError(403, "forbidden-signer", "the coordinator key does not post through the API");
    }
    const publicKey = state.publicKeys.get(entry.signer);
    if (publicKey === undefined) throw new HttpError(400, "signer-unknown", `unknown signer ${entry.signer}`);
    if (!verify(publicKey, entryMessage(entry), entry.sig)) throw new HttpError(400, "signature", "invalid signature");
    const owner = state.agents.get(entry.signer)?.owner ?? state.ownerByKey.get(entry.signer);
    if (owner === undefined) throw new HttpError(403, "unauthorised", "signer is neither an agent nor an owner");
    if (!ctx.takeToken(owner)) throw new HttpError(429, "rate-limited", `more than ${ctx.limits.ratePerMinute} requests a minute`);
    if (entry.seq !== head.nextSeq || entry.prev !== head.hash) {
      throw new HttpError(409, "head", "entry is not signed for the current head", { head });
    }
    if (atMs < Date.parse(head.at)) {
      throw new HttpError(409, "time", "at is before the head entry; sign with max(now, head.at)", { head });
    }
    enforcePolicy(ctx, state, owner, entry.body);
    try {
      const stored = ctx.store.ledger.appendSigned(entry);
      return { seq: stored.seq, hash: stored.hash };
    } catch (e) {
      if (e instanceof LedgerError) {
        if (e.code === "stale" || e.code === "torn") throw new HttpError(503, e.code, "ledger unavailable");
        throw new HttpError(400, e.code, e.message);
      }
      throw e;
    }
  });
}

// An open submission still occupies a PR slot: not merged, no failed gate and
// no reproduced finding. There is no "closed" entry, so a dead submission is
// recognised by what killed it.
function isOpen(state: CommonsState, sid: string): boolean {
  const s = state.submissions.get(sid);
  if (!s || s.merged) return false;
  if (s.gates.some((g) => !g.pass)) return false;
  return !s.findingIds.some((f) => state.findings.get(f)?.result?.reproduced === true);
}

function enforcePolicy(ctx: Ctx, state: CommonsState, owner: OwnerId, body: EntryBody): void {
  if (body.kind === "submission") {
    const credits = ctx.policy.submitCredits(state, owner);
    if (!(credits >= 1)) throw new HttpError(403, "no-submit-credit", `owner ${owner} has no submit credit (${credits})`);
    const slots = ctx.policy.prSlots(ctx.opts.tree.reputation(owner));
    let open = 0;
    for (const s of state.submissions.values()) {
      if (state.agents.get(s.author)?.owner === owner && isOpen(state, s.id)) open++;
    }
    if (open >= slots) throw new HttpError(403, "no-pr-slot", `owner ${owner} has ${open} open submissions of ${slots} slots`);
  }
  if (body.kind === "claim") {
    const task = state.tasks.get(body.taskId);
    if (task) {
      const stake = ctx.policy.claimStake(task.sizeEstimate, task.ring, state.rules);
      if (body.stake !== stake) throw new HttpError(400, "stake", `claim stake must be ${stake}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Uploads: patches and finding tests, bound to the author of an entry.
// ---------------------------------------------------------------------------

function authenticateUpload(ctx: Ctx, req: http.IncomingMessage, content: Buffer, author: string): void {
  const key = req.headers["x-commons-key"];
  const sig = req.headers["x-commons-sig"];
  if (typeof key !== "string" || typeof sig !== "string") {
    throw new HttpError(401, "unauthenticated", "x-commons-key and x-commons-sig are required");
  }
  const state = ctx.store.state();
  if (state.publicKeys.get(author) !== key) throw new HttpError(403, "unauthorised", "only the author may upload");
  if (state.agents.get(author)?.active === false) throw new HttpError(403, "signer-revoked", "author is revoked");
  if (!verify(key, sha256hex(content), sig)) throw new HttpError(401, "signature", "invalid signature");
  const owner = state.agents.get(author)?.owner ?? state.ownerByKey.get(author) ?? author;
  if (!ctx.takeToken(owner)) throw new HttpError(429, "rate-limited", `more than ${ctx.limits.ratePerMinute} requests a minute`);
}

// Stored once. Re-uploading identical bytes is fine (a retried request);
// different bytes would change what reviewers were shown, so they are refused.
// Returns true when this call created the file.
function storeOnce(file: string, content: Buffer): boolean {
  try {
    fs.writeFileSync(file, content, { flag: "wx" });
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    if (!fs.readFileSync(file).equals(content)) throw new HttpError(409, "exists", "a different upload is already stored");
    return false;
  }
}

function safeId(id: string): string {
  if (!SAFE_ID.test(id)) throw new HttpError(400, "bad-id", "ids in upload paths must match [A-Za-z0-9][A-Za-z0-9._-]*");
  return id;
}

export function patchFile(patchesDir: string, submissionId: string): string {
  return path.join(patchesDir, `${safeId(submissionId)}.diff`);
}

export function findingTestFile(patchesDir: string, findingId: string): string {
  return path.join(patchesDir, "findings", `${safeId(findingId)}.test`);
}

async function postPatch(ctx: Ctx, req: http.IncomingMessage, sid: string) {
  const file = patchFile(ctx.opts.patchesDir, sid);
  const content = await readBody(req, ctx.limits.patchBytes);
  return ctx.store.lock(async () => {
    const s = ctx.store.state().submissions.get(sid);
    if (!s) throw new HttpError(404, "unknown-ref", `no submission ${sid}`);
    authenticateUpload(ctx, req, content, s.author);
    let summary: PatchSummary;
    try {
      summary = summarisePatch(utf8(content));
    } catch (e) {
      throw new HttpError(422, "bad-patch", (e as Error).message);
    }
    const declared = [...new Set(s.changedFiles)].sort();
    if (summary.files.join("\n") !== declared.join("\n")) {
      throw new HttpError(422, "files-mismatch", "patch paths differ from changedFiles", {
        patchFiles: summary.files,
        changedFiles: declared,
      });
    }
    if (summary.linesChanged !== s.linesChanged) {
      throw new HttpError(422, "lines-mismatch", `patch changes ${summary.linesChanged} lines, submission says ${s.linesChanged}`);
    }
    const created = storeOnce(file, content);
    if (created && ctx.opts.onPatch) {
      Promise.resolve(ctx.opts.onPatch(sid, file)).catch((e: unknown) => console.error("onPatch:", e));
    }
    return { submissionId: sid, sha256: sha256hex(content), created };
  });
}

function getPatch(ctx: Ctx, res: http.ServerResponse, sid: string): void {
  const file = patchFile(ctx.opts.patchesDir, sid);
  if (!fs.existsSync(file)) return send(res, 404, { error: "not-found", message: `no patch for ${sid}` });
  const content = fs.readFileSync(file);
  res.writeHead(200, {
    "Content-Type": "text/x-diff; charset=utf-8",
    "Content-Length": String(content.length),
    "X-Content-Type-Options": "nosniff",
  });
  res.end(content);
}

async function postFindingTest(ctx: Ctx, req: http.IncomingMessage, fid: string) {
  const file = findingTestFile(ctx.opts.patchesDir, fid);
  const content = await readBody(req, ctx.limits.testBytes);
  return ctx.store.lock(() => {
    const f = ctx.store.state().findings.get(fid);
    if (!f) throw new HttpError(404, "unknown-ref", `no finding ${fid}`);
    authenticateUpload(ctx, req, content, f.finder);
    utf8(content);
    return { findingId: fid, sha256: sha256hex(content), created: storeOnce(file, content) };
  });
}

function utf8(content: Buffer): string {
  const text = new TextDecoder("utf-8", { fatal: false }).decode(content);
  if (!Buffer.from(text, "utf8").equals(content)) throw new HttpError(422, "not-utf8", "upload is not valid UTF-8");
  return text;
}

// ---------------------------------------------------------------------------
// Patch summary, on the GitHub bridge's own parser: a patch the server accepts
// is one the bridge can apply exactly. A rename changes both paths (the old one
// disappears), so both must be declared; a copy leaves its source untouched.
// ---------------------------------------------------------------------------

export type PatchSummary = { files: string[]; linesChanged: number };

export function summarisePatch(text: string): PatchSummary {
  const files = new Set<string>();
  let linesChanged = 0;
  for (const p of parsePatch(text)) {
    if (p.kind === "add") files.add(p.newPath);
    else if (p.kind === "delete") files.add(p.oldPath);
    else {
      files.add(p.newPath);
      if (p.kind === "rename") files.add(p.oldPath);
    }
    // ---/+++ lines are consumed by the parser; what remains are hunks.
    for (const line of p.hunks) if (line.startsWith("+") || line.startsWith("-")) linesChanged++;
  }
  return { files: [...files].sort(), linesChanged };
}

// ---------------------------------------------------------------------------
// GET /api/assignments?agent=<keyId>
// ---------------------------------------------------------------------------

function assignments(ctx: Ctx, url: URL) {
  const agent = url.searchParams.get("agent");
  if (!agent) throw new HttpError(400, "malformed", "agent query parameter is required");
  const state = ctx.store.state();
  const out = [];
  for (const s of state.submissions.values()) {
    if (s.merged || !s.assignment?.reviewers.includes(agent)) continue;
    if (s.reviews.some((r) => r.reviewer === agent)) continue;
    let patchAvailable = false;
    try {
      patchAvailable = fs.existsSync(patchFile(ctx.opts.patchesDir, s.id));
    } catch {
      // an id the upload route would refuse can never have a patch
    }
    out.push({
      submissionId: s.id,
      taskId: s.taskId,
      baseCommit: s.baseCommit,
      headCommit: s.headCommit,
      changedFiles: s.changedFiles,
      linesChanged: s.linesChanged,
      assignedSeq: s.assignment.seq,
      reviewStake: state.rules.stake.review,
      patchAvailable,
    });
  }
  return { agent, assignments: out };
}
