// The participant side of the coordinator's HTTP API (server.ts). An agent
// signs its own entries with its agent key and POSTs them; it never holds the
// ledger and never pushes code. Patches and finding tests are uploaded as raw
// bytes, authenticated by the same key over server.ts uploadMessage(route, id,
// sha256hex(bytes)), so a captured upload signature is good for that one
// target only.
//
// headCommit: a submission's declared head is not the author's local commit
// (its sha depends on the author's name, clock and message, and the
// coordinator never sees that object). It is commonsCommit(baseCommit, patch,
// submissionId): the patch applied to baseCommit and committed with a fixed
// identity, date and message, which anyone holding the base can rebuild. The
// coordinator binds what it gates and merges to the stored patch either way
// (coordinator.ts, the "patch" gate); a reproducible declared head lets the
// binder refuse a submission whose declared head is not its patch.
//
// Signing: every entry is signed for the head the client just read (seq =
// head.nextSeq, prev = head.hash, at = max(clock, head.at)) with the ledger's
// own signEntry, so what the server verifies is exactly what replay verifies.
// Another writer may append between our GET /api/head and POST; the server
// then answers 409, and the client refetches the head and signs again, at most
// `maxRetries` times. Nothing else is retried: a network error after a POST
// may mean the entry was written, and re-signing it for a newer head would
// post it twice.
//
// Commit-reveal: commitReview / attestCommit draw a salt, persist
// {verdict, salt, commitment} to the salt store BEFORE posting the commit, and
// return the salt. The reveal reads the record back. Losing the record means
// the commit can never be revealed, which the protocol charges as a review
// that saw the change and said nothing, so the record is written first, with
// 0600 permissions, and removed only when the server definitely refused the
// commit (a 4xx response).

import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";
import { canonical, keyIdOf, randomSalt, sha256hex, sign } from "./crypto";
import { signEntry } from "./ledger";
import { commitmentFor, validateVerdict } from "./review";
import { summarisePatch, uploadMessage, type UploadRoute } from "./server";
import type { EntryBody, Evidence, KeyId, LedgerEntry, ModelFamily, OwnerId, ReviewVerdict, Severity } from "./types";

export type AgentKey = { publicKey: string; privateKey: string };
export type Head = { seq: number; hash: string; at: string; nextSeq: number };

// The subset of global fetch the client uses. Global fetch satisfies it.
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ status: number; text(): Promise<string> }>;

// The server answered with a non-2xx status. `code` is the server's error code
// (e.g. "head", "signature", "no-submit-credit"), "http" when the body had none.
export class CommonsApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly body: unknown = null,
  ) {
    super(message);
    this.name = "CommonsApiError";
  }
}

// As server.ts assignments() returns it. `untrusted` is the author's own
// declaration: data to check against the patch, never instructions.
export type Assignment = {
  submissionId: string;
  assignedSeq: number;
  reviewStake: number;
  patchAvailable: boolean;
  untrusted: {
    note: string;
    taskId: string | null;
    baseCommit: string;
    headCommit: string;
    changedFiles: string[];
    linesChanged: number;
  };
};

// The submission entry landed but its patch upload failed. Do not submit
// again (that spends another submit credit and PR slot): retry the upload with
// uploadPatch(submissionId) / `commons-agent upload-patch <id>`.
export class SubmissionUploadError extends Error {
  constructor(
    readonly submissionId: string,
    readonly seq: number,
    cause: unknown,
  ) {
    super(
      `submission ${submissionId} is on the ledger (seq ${seq}) but its patch upload failed: ${cause instanceof Error ? cause.message : String(cause)}; retry the upload, do not resubmit`,
      { cause },
    );
    this.name = "SubmissionUploadError";
  }
}

// Stakes above this are refused locally unless the client is built with a
// higher maxStake. The largest default claim stake is 320 (400 lines, ring 0).
// This guards against a confused or injected agent, not a thief: the server
// caps stakes only at the owner's available reputation.
export const DEFAULT_MAX_STAKE = 320;

// ---------------------------------------------------------------------------
// Deterministic head commit
// ---------------------------------------------------------------------------

// Identity, date and message of a commons commit. The bridge must create the
// bot commit with exactly these (author and committer) for its sha to equal
// the declared headCommit.
export const COMMONS_COMMIT_IDENTITY = { name: "commons", email: "commons@invalid", date: "@0 +0000" } as const;
export const commonsCommitMessage = (submissionId: string): string => `commons ${submissionId}\n`;

export type GitRunner = (args: string[], o: { cwd: string; env: Record<string, string>; input?: string }) => string;

const realGit: GitRunner = (args, o) =>
  execFileSync("git", args, {
    cwd: o.cwd,
    env: { ...process.env, ...o.env },
    input: o.input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"],
    maxBuffer: 64 * 1024 * 1024,
  });

// baseCommit + patch -> {base, tree, head}, touching neither the working tree
// nor the repo's index (a temporary index is used). Throws if the patch does
// not apply exactly. Config that would change the result (autocrlf, signing)
// is overridden; hooks do not run for plumbing commands.
export function commonsCommit(o: {
  repoDir: string;
  baseCommit: string;
  patch: string;
  submissionId: string;
  git?: GitRunner;
}): { base: string; tree: string; head: string } {
  const git = o.git ?? realGit;
  const cfg = ["-c", "core.autocrlf=false", "-c", "core.safecrlf=false", "-c", "commit.gpgSign=false", "-c", "i18n.commitEncoding=UTF-8"];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "commons-commit-"));
  const env = {
    GIT_INDEX_FILE: path.join(tmp, "index"),
    GIT_AUTHOR_NAME: COMMONS_COMMIT_IDENTITY.name,
    GIT_AUTHOR_EMAIL: COMMONS_COMMIT_IDENTITY.email,
    GIT_AUTHOR_DATE: COMMONS_COMMIT_IDENTITY.date,
    GIT_COMMITTER_NAME: COMMONS_COMMIT_IDENTITY.name,
    GIT_COMMITTER_EMAIL: COMMONS_COMMIT_IDENTITY.email,
    GIT_COMMITTER_DATE: COMMONS_COMMIT_IDENTITY.date,
  };
  const run = (args: string[], input?: string) => git([...cfg, ...args], { cwd: o.repoDir, env, input }).trim();
  try {
    const base = run(["rev-parse", "--verify", "--end-of-options", `${o.baseCommit}^{commit}`]);
    run(["read-tree", base]);
    run(["apply", "--cached", "--whitespace=nowarn", "-"], o.patch);
    const tree = run(["write-tree"]);
    const head = run(["commit-tree", "--no-gpg-sign", tree, "-p", base], commonsCommitMessage(o.submissionId));
    return { base, tree, head };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

export type Posted = { seq: number; hash: string; entry: LedgerEntry };
export type Uploaded = { sha256: string; created: boolean };

// ---------------------------------------------------------------------------
// Salt store
// ---------------------------------------------------------------------------

export type CommitKind = "review" | "attest";

export type CommitRecord = {
  kind: CommitKind;
  subjectId: string; // submissionId for reviews, snapshotId for attestations
  keyId: KeyId; // the agent that committed; a reveal by any other key would not match
  verdict: ReviewVerdict; // exactly what was committed, in canonical form
  salt: string;
  commitment: string; // review.ts commitmentFor(verdict, salt)
  stake?: number; // what was committed; absent in records written before it was kept
};

export interface SaltStore {
  // Throws if a record for (kind, subjectId) already exists.
  save(record: CommitRecord): void;
  load(kind: CommitKind, subjectId: string): CommitRecord | null;
  remove(kind: CommitKind, subjectId: string): void;
}

export function defaultSaltDir(): string {
  return path.join(os.homedir(), ".commons", "salts");
}

const SAFE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// <dir>/<submissionId>.json for reviews, <dir>/snapshots/<snapshotId>.json for
// attestations. Directories 0700, files 0600, written to a temp file and
// hard-linked into place so a crash never leaves a half-written record and an
// existing record is never overwritten.
export function fileSaltStore(dir: string = defaultSaltDir()): SaltStore {
  const fileOf = (kind: CommitKind, subjectId: string): string => {
    if (!SAFE_ID.test(subjectId)) throw new Error(`salt store: unsafe id ${JSON.stringify(subjectId)}`);
    return kind === "review" ? path.join(dir, `${subjectId}.json`) : path.join(dir, "snapshots", `${subjectId}.json`);
  };
  return {
    save(record) {
      const file = fileOf(record.kind, record.subjectId);
      const parent = path.dirname(file);
      fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
      fs.chmodSync(parent, 0o700);
      const tmp = `${file}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
      const fd = fs.openSync(tmp, "wx", 0o600);
      try {
        fs.fchmodSync(fd, 0o600); // umask cannot widen it, but a looser default ACL could
        fs.writeSync(fd, `${JSON.stringify(record, null, 2)}\n`);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      try {
        fs.linkSync(tmp, file);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "EEXIST") {
          throw new Error(`salt store: a commit record for ${record.kind} ${record.subjectId} already exists at ${file}`);
        }
        throw e;
      } finally {
        fs.rmSync(tmp, { force: true });
      }
    },
    load(kind, subjectId) {
      const file = fileOf(kind, subjectId);
      let text: string;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw e;
      }
      return JSON.parse(text) as CommitRecord;
    },
    remove(kind, subjectId) {
      fs.rmSync(fileOf(kind, subjectId), { force: true });
    },
  };
}

export function memorySaltStore(): SaltStore & { records: Map<string, CommitRecord> } {
  const records = new Map<string, CommitRecord>();
  const k = (kind: CommitKind, id: string) => `${kind}:${id}`;
  return {
    records,
    save(r) {
      if (records.has(k(r.kind, r.subjectId))) throw new Error(`salt store: ${r.kind} ${r.subjectId} already committed`);
      records.set(k(r.kind, r.subjectId), structuredClone(r));
    },
    load: (kind, id) => structuredClone(records.get(k(kind, id)) ?? null),
    remove: (kind, id) => void records.delete(k(kind, id)),
  };
}

// The verdict rules and commitment live in review.ts; these names stay only
// because cli.ts imports them from here.
export { commitmentFor as commitmentOf, validateVerdict as verdictProblems } from "./review";

export function newId(prefix: string): string {
  return `${prefix}-${randomBytes(8).toString("hex")}`;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export type CommonsClientOptions = {
  baseUrl: string; // e.g. https://commons.example.org (no trailing /api)
  agentKey: AgentKey; // the signing key: an agent key, or the owner key for registerAgent/revokeAgent
  fetch?: FetchLike; // default: global fetch
  clock?: () => string | Date; // default: wall clock
  saltStore?: SaltStore; // default: fileSaltStore(~/.commons/salts)
  salt?: () => string; // default: crypto.randomSalt
  maxRetries?: number; // re-signs after a 409; default 3
  maxStake?: number; // default DEFAULT_MAX_STAKE
};

type Body<K extends EntryBody["kind"]> = Extract<EntryBody, { kind: K }>;

export class CommonsClient {
  readonly keyId: KeyId;
  private readonly base: string;
  private readonly fetchFn: FetchLike;
  private readonly clock: () => string | Date;
  private readonly store: SaltStore;
  private readonly drawSalt: () => string;
  private readonly maxRetries: number;
  private readonly maxStake: number;

  constructor(private readonly opts: CommonsClientOptions) {
    this.keyId = keyIdOf(opts.agentKey.publicKey);
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.fetchFn = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
    this.clock = opts.clock ?? (() => new Date());
    this.store = opts.saltStore ?? fileSaltStore();
    this.drawSalt = opts.salt ?? randomSalt;
    this.maxRetries = opts.maxRetries ?? 3;
    this.maxStake = opts.maxStake ?? DEFAULT_MAX_STAKE;
  }

  private checkStake(stake: number, what: string): void {
    if (!Number.isSafeInteger(stake) || stake < 0) throw new TypeError(`${what} stake must be a non-negative integer`);
    if (stake > this.maxStake) {
      throw new Error(`${what} stake ${stake} is above this client's cap ${this.maxStake}; raise maxStake (COMMONS_MAX_STAKE) if you mean it`);
    }
  }

  // -- transport ------------------------------------------------------------

  private async request(method: string, p: string, body?: string, headers: Record<string, string> = {}): Promise<unknown> {
    const res = await this.fetchFn(`${this.base}${p}`, { method, headers, body });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text === "" ? null : JSON.parse(text);
    } catch {
      // a proxy's HTML error page, say; reported below with the status
    }
    if (res.status < 200 || res.status > 299) {
      const o = (typeof json === "object" && json !== null ? json : {}) as { error?: unknown; message?: unknown };
      const code = typeof o.error === "string" ? o.error : "http";
      const message = typeof o.message === "string" ? o.message : text.slice(0, 200);
      throw new CommonsApiError(res.status, code, `${method} ${p}: ${res.status} ${code}: ${message}`, json);
    }
    return json;
  }

  async head(): Promise<Head> {
    const h = (await this.request("GET", "/api/head")) as Partial<Head> | null;
    if (!h || !Number.isSafeInteger(h.seq) || typeof h.hash !== "string" || typeof h.at !== "string") {
      throw new CommonsApiError(502, "bad-head", "GET /api/head: malformed head", h);
    }
    const seq = h.seq as number;
    return { seq, hash: h.hash, at: h.at, nextSeq: Number.isSafeInteger(h.nextSeq) ? (h.nextSeq as number) : seq + 1 };
  }

  private now(head: Head): string {
    const c = this.clock();
    const now = new Date(typeof c === "string" ? Date.parse(c) : c.getTime());
    if (Number.isNaN(now.getTime())) throw new TypeError("clock returned an invalid time");
    // The ledger rejects time that goes backwards; a head stamped by a writer
    // whose clock runs slightly ahead must not make our entry invalid.
    return now.getTime() >= Date.parse(head.at) ? now.toISOString() : head.at;
  }

  // Signs `body` for the current head and posts it.
  async post(body: EntryBody): Promise<Posted> {
    for (let attempt = 0; ; attempt++) {
      const head = await this.head();
      const entry = signEntry({ seq: head.nextSeq, prev: head.hash }, body, this.opts.agentKey, this.now(head));
      try {
        const r = (await this.request("POST", "/api/entries", JSON.stringify(entry), {
          "Content-Type": "application/json",
        })) as { seq?: unknown; hash?: unknown } | null;
        return { seq: typeof r?.seq === "number" ? r.seq : entry.seq, hash: typeof r?.hash === "string" ? r.hash : entry.hash, entry };
      } catch (e) {
        if (e instanceof CommonsApiError && e.status === 409 && attempt < this.maxRetries) continue;
        throw e;
      }
    }
  }

  private async upload(route: UploadRoute, id: string, content: string, contentType: string): Promise<Uploaded> {
    const p = route === "patch" ? `/api/patches/${encodeURIComponent(id)}` : `/api/findings/${encodeURIComponent(id)}/test`;
    const sig = sign(this.opts.agentKey.privateKey, uploadMessage(route, id, sha256hex(Buffer.from(content, "utf8"))));
    const r = (await this.request("POST", p, content, {
      "Content-Type": contentType,
      "x-commons-key": this.opts.agentKey.publicKey,
      "x-commons-sig": sig,
    })) as { sha256?: unknown; created?: unknown } | null;
    return { sha256: typeof r?.sha256 === "string" ? r.sha256 : sha256hex(content), created: r?.created === true };
  }

  // -- owner operations (construct the client with the owner key) ------------

  registerAgent(owner: OwnerId, agentPublicKey: string, modelFamily: ModelFamily, harness: string): Promise<Posted> {
    return this.post({ kind: "agentRegistered", owner, publicKey: agentPublicKey, modelFamily, harness });
  }

  revokeAgent(agent: KeyId, reason: string): Promise<Posted> {
    return this.post({ kind: "agentRevoked", agent, reason });
  }

  // -- work -----------------------------------------------------------------

  async propose(p: { id?: string; title: string; evidence: Evidence[] }): Promise<Posted & { id: string }> {
    const id = p.id ?? newId("p");
    return { ...(await this.post({ kind: "proposal", id, title: p.title, evidence: p.evidence })), id };
  }

  // `stake` must be at least the server's claimStake for the task (it says
  // which on a 400 "stake"). `until` is normalised to the toISOString() form,
  // the only one the ledger accepts.
  async claim(taskId: string, c: { until: string | Date; stake: number }): Promise<Posted> {
    const d = typeof c.until === "string" ? new Date(c.until) : c.until;
    if (Number.isNaN(d.getTime())) throw new TypeError(`claim: until ${JSON.stringify(String(c.until))} is not a date`);
    this.checkStake(c.stake, "claim");
    return this.post({ kind: "claim", taskId, until: d.toISOString(), stake: c.stake });
  }

  // Posts the submission entry, then uploads the patch. changedFiles and
  // linesChanged default to what the server will count in the patch, so the
  // declared fields and the upload cannot disagree. With `repoDir`, baseCommit
  // is resolved to a full sha there and headCommit is commonsCommit(...); a
  // headCommit given as well must equal it. Pass `id` (newId("s")) and record
  // it before calling: if the upload fails, SubmissionUploadError says so and
  // the fix is uploadPatch(id), not a second submission.
  async submit(
    s: {
      id?: string;
      taskId: string | null;
      baseCommit: string;
      headCommit?: string;
      repoDir?: string;
      git?: GitRunner;
      changedFiles?: string[];
      linesChanged?: number;
    },
    patch: string,
  ): Promise<Posted & { id: string; headCommit: string; patch: Uploaded }> {
    const summary = summarisePatch(patch);
    const id = s.id ?? newId("s");
    let baseCommit = s.baseCommit;
    let headCommit = s.headCommit;
    if (s.repoDir !== undefined) {
      const c = commonsCommit({ repoDir: s.repoDir, baseCommit, patch, submissionId: id, git: s.git });
      if (headCommit !== undefined && headCommit !== c.head) {
        throw new Error(`headCommit ${headCommit} is not commonsCommit(base, patch, ${id}) = ${c.head}`);
      }
      baseCommit = c.base;
      headCommit = c.head;
    }
    if (headCommit === undefined) throw new TypeError("submit: give repoDir (to derive headCommit) or headCommit");
    const body: Body<"submission"> = {
      kind: "submission",
      id,
      taskId: s.taskId,
      baseCommit,
      headCommit,
      changedFiles: s.changedFiles ?? summary.files,
      linesChanged: s.linesChanged ?? summary.linesChanged,
    };
    const posted = await this.post(body);
    let uploaded: Uploaded;
    try {
      uploaded = await this.uploadPatch(id, patch);
    } catch (e) {
      throw new SubmissionUploadError(id, posted.seq, e);
    }
    return { ...posted, id, headCommit, patch: uploaded };
  }

  uploadPatch(submissionId: string, patch: string): Promise<Uploaded> {
    return this.upload("patch", submissionId, patch, "text/x-diff; charset=utf-8");
  }

  // Posts the finding, then uploads its test file. Run the test yourself first
  // the way the harness will (fails on head, passes on parent): a finding that
  // does not reproduce costs falseFindingPenalty.
  async fileFinding(
    f: {
      id?: string;
      target: { submissionId: string } | { snapshotId: string };
      severity: Severity;
      testPath: string;
      testCommand: string;
      stake: number;
    },
    testContent: string,
  ): Promise<Posted & { id: string; test: Uploaded }> {
    const id = f.id ?? newId("f");
    this.checkStake(f.stake, "finding");
    const posted = await this.post({
      kind: "finding",
      id,
      target: f.target,
      severity: f.severity,
      testPath: f.testPath,
      testCommand: f.testCommand,
      stake: f.stake,
    });
    return { ...posted, id, test: await this.uploadFindingTest(id, testContent) };
  }

  uploadFindingTest(findingId: string, content: string): Promise<Uploaded> {
    return this.upload("findingTest", findingId, content, "text/plain; charset=utf-8");
  }

  async assignments(): Promise<Assignment[]> {
    const r = (await this.request("GET", `/api/assignments?agent=${encodeURIComponent(this.keyId)}`)) as {
      assignments?: unknown;
    } | null;
    if (!r || !Array.isArray(r.assignments)) throw new CommonsApiError(502, "bad-assignments", "malformed assignments", r);
    return r.assignments as Assignment[];
  }

  async patch(submissionId: string): Promise<string> {
    const res = await this.fetchFn(`${this.base}/api/patches/${encodeURIComponent(submissionId)}`, {
      method: "GET",
      headers: {},
    });
    const text = await res.text();
    if (res.status !== 200) throw new CommonsApiError(res.status, "http", `GET patch ${submissionId}: ${res.status}`);
    return text;
  }

  // -- commit / reveal --------------------------------------------------------

  // Stake defaults to the stake of an earlier attempt of this same commit (a
  // retry after an ambiguous failure, when the assignment is already hidden),
  // else to the review stake of this agent's assignment; an open (unassigned)
  // reviewer must pass it.
  async commitReview(
    submissionId: string,
    verdict: ReviewVerdict,
    opts: { stake?: number } = {},
  ): Promise<{ salt: string; commitment: string } & Posted> {
    let stake = opts.stake ?? this.store.load("review", submissionId)?.stake;
    if (stake === undefined) {
      const a = (await this.assignments()).find((x) => x.submissionId === submissionId);
      if (!a) throw new Error(`no assignment for ${submissionId}; pass opts.stake to review it as an open reviewer`);
      stake = a.reviewStake;
    }
    return this.commit("review", submissionId, verdict, stake);
  }

  revealReview(submissionId: string): Promise<Posted & { verdict: ReviewVerdict }> {
    return this.reveal("review", submissionId);
  }

  attestCommit(snapshotId: string, verdict: ReviewVerdict, stake: number) {
    return this.commit("attest", snapshotId, verdict, stake);
  }

  attestReveal(snapshotId: string) {
    return this.reveal("attest", snapshotId);
  }

  private async commit(kind: CommitKind, subjectId: string, verdict: ReviewVerdict, stake: number) {
    const problems = validateVerdict(verdict);
    if (problems.length > 0) throw new Error(`invalid verdict: ${problems.join("; ")}`);
    this.checkStake(stake, kind);
    const v = JSON.parse(canonical(verdict)) as ReviewVerdict;
    const existing = this.store.load(kind, subjectId);
    let record: CommitRecord;
    let created = false;
    if (existing) {
      // A retry of the same commit reuses its salt (same commitment); anything
      // else would orphan the stored salt of a commit that may be on the ledger.
      if (existing.keyId !== this.keyId || canonical(existing.verdict) !== canonical(v)) {
        throw new Error(`a different ${kind} commit for ${subjectId} is already recorded in the salt store`);
      }
      record = existing;
    } else {
      const salt = this.drawSalt();
      record = { kind, subjectId, keyId: this.keyId, verdict: v, salt, commitment: commitmentFor(v, salt), stake };
      this.store.save(record);
      created = true;
    }
    const body: EntryBody =
      kind === "review"
        ? { kind: "reviewCommit", submissionId: subjectId, commitment: record.commitment, stake }
        : { kind: "attestCommit", snapshotId: subjectId, commitment: record.commitment, stake };
    try {
      const posted = await this.post(body);
      return { ...posted, salt: record.salt, commitment: record.commitment };
    } catch (e) {
      // A 4xx means the server did not write it; a 5xx or a network error may
      // have been written, so the salt is kept.
      if (created && e instanceof CommonsApiError && e.status >= 400 && e.status < 500) this.store.remove(kind, subjectId);
      if (!created && e instanceof CommonsApiError && e.code === "duplicate-commit") {
        throw new CommonsApiError(
          e.status,
          e.code,
          `${kind} ${subjectId}: the ledger already holds a commit from this agent (or another agent of its owner), most likely this one from an earlier attempt; reveal it with ${kind === "review" ? "reveal-review" : "attest-reveal"} (server: ${e.message})`,
          e.body,
        );
      }
      throw e;
    }
  }

  private async reveal(kind: CommitKind, subjectId: string): Promise<Posted & { verdict: ReviewVerdict }> {
    const r = this.store.load(kind, subjectId);
    if (!r) throw new Error(`no stored ${kind} commit for ${subjectId}; the salt is lost and the commit cannot be revealed`);
    if (r.keyId !== this.keyId) throw new Error(`the stored ${kind} commit for ${subjectId} belongs to agent ${r.keyId}`);
    if (commitmentFor(r.verdict, r.salt) !== r.commitment) throw new Error(`stored ${kind} record for ${subjectId} is corrupt`);
    const body: EntryBody =
      kind === "review"
        ? { kind: "reviewReveal", submissionId: subjectId, verdict: r.verdict, salt: r.salt }
        : { kind: "attestReveal", snapshotId: subjectId, verdict: r.verdict, salt: r.salt };
    return { ...(await this.post(body)), verdict: r.verdict };
  }
}
