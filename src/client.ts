// The participant side of the coordinator's HTTP API (server.ts). An agent
// signs its own entries with its agent key and POSTs them; it never holds the
// ledger and never pushes code. Patches and finding tests are uploaded as raw
// bytes, authenticated by the same key over sha256hex(bytes).
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

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";
import { canonical, keyIdOf, randomSalt, sha256hex, sign } from "./crypto";
import { signEntry } from "./ledger";
import { summarisePatch } from "./server";
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

export type Assignment = {
  submissionId: string;
  taskId: string | null;
  baseCommit: string;
  headCommit: string;
  changedFiles: string[];
  linesChanged: number;
  assignedSeq: number;
  reviewStake: number;
  patchAvailable: boolean;
};

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
  commitment: string; // sha256hex(canonical(verdict) + salt)
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

// ---------------------------------------------------------------------------
// Verdicts
// ---------------------------------------------------------------------------

// The same rules the ledger applies at reveal time. Checked before committing:
// the ledger only sees the verdict at reveal, and a verdict it would refuse
// then cannot be revealed at all.
export function verdictProblems(v: unknown): string[] {
  const problems: string[] = [];
  if (typeof v !== "object" || v === null || Array.isArray(v)) return ["verdict is not an object"];
  const o = v as Record<string, unknown>;
  for (const key of Object.keys(o)) {
    if (!["defectProbability", "summary", "findingIds"].includes(key) && o[key] !== undefined) {
      problems.push(`unknown field ${key}`);
    }
  }
  const p = o.defectProbability;
  if (typeof p !== "number" || !Number.isFinite(p) || p < 0 || p > 1) problems.push("defectProbability must be a number in [0, 1]");
  if (typeof o.summary !== "string") problems.push("summary must be a string");
  const ids = o.findingIds;
  if (!Array.isArray(ids) || !ids.every((x) => typeof x === "string")) {
    problems.push("findingIds must be an array of strings");
  } else {
    if (ids.some((x) => x === "")) problems.push("empty finding id");
    if (new Set(ids).size !== ids.length) problems.push("duplicate finding id");
  }
  return problems;
}

export function commitmentOf(verdict: ReviewVerdict, salt: string): string {
  return sha256hex(canonical(verdict) + salt);
}

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

  constructor(private readonly opts: CommonsClientOptions) {
    this.keyId = keyIdOf(opts.agentKey.publicKey);
    this.base = opts.baseUrl.replace(/\/+$/, "");
    this.fetchFn = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
    this.clock = opts.clock ?? (() => new Date());
    this.store = opts.saltStore ?? fileSaltStore();
    this.drawSalt = opts.salt ?? randomSalt;
    this.maxRetries = opts.maxRetries ?? 3;
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

  private async upload(p: string, content: string, contentType: string): Promise<Uploaded> {
    const sig = sign(this.opts.agentKey.privateKey, sha256hex(Buffer.from(content, "utf8")));
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

  // `stake` must equal the server's claimStake for the task (it says which on a 400 "stake").
  claim(taskId: string, c: { until: string | Date; stake: number }): Promise<Posted> {
    const until = typeof c.until === "string" ? c.until : c.until.toISOString();
    return this.post({ kind: "claim", taskId, until, stake: c.stake });
  }

  // Posts the submission entry, then uploads the patch. changedFiles and
  // linesChanged default to what the server will count in the patch, so the
  // declared fields and the upload cannot disagree.
  async submit(
    s: {
      id?: string;
      taskId: string | null;
      baseCommit: string;
      headCommit: string;
      changedFiles?: string[];
      linesChanged?: number;
    },
    patch: string,
  ): Promise<Posted & { id: string; patch: Uploaded }> {
    const summary = summarisePatch(patch);
    const id = s.id ?? newId("s");
    const body: Body<"submission"> = {
      kind: "submission",
      id,
      taskId: s.taskId,
      baseCommit: s.baseCommit,
      headCommit: s.headCommit,
      changedFiles: s.changedFiles ?? summary.files,
      linesChanged: s.linesChanged ?? summary.linesChanged,
    };
    const posted = await this.post(body);
    return { ...posted, id, patch: await this.uploadPatch(id, patch) };
  }

  uploadPatch(submissionId: string, patch: string): Promise<Uploaded> {
    return this.upload(`/api/patches/${encodeURIComponent(submissionId)}`, patch, "text/x-diff; charset=utf-8");
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
    return this.upload(`/api/findings/${encodeURIComponent(findingId)}/test`, content, "text/plain; charset=utf-8");
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

  // Stake defaults to the review stake of this agent's assignment; an open
  // (unassigned) reviewer must pass it.
  async commitReview(
    submissionId: string,
    verdict: ReviewVerdict,
    opts: { stake?: number } = {},
  ): Promise<{ salt: string; commitment: string } & Posted> {
    let stake = opts.stake;
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
    const problems = verdictProblems(verdict);
    if (problems.length > 0) throw new Error(`invalid verdict: ${problems.join("; ")}`);
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
      record = { kind, subjectId, keyId: this.keyId, verdict: v, salt, commitment: commitmentOf(v, salt) };
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
      throw e;
    }
  }

  private async reveal(kind: CommitKind, subjectId: string): Promise<Posted & { verdict: ReviewVerdict }> {
    const r = this.store.load(kind, subjectId);
    if (!r) throw new Error(`no stored ${kind} commit for ${subjectId}; the salt is lost and the commit cannot be revealed`);
    if (r.keyId !== this.keyId) throw new Error(`the stored ${kind} commit for ${subjectId} belongs to agent ${r.keyId}`);
    if (commitmentOf(r.verdict, r.salt) !== r.commitment) throw new Error(`stored ${kind} record for ${subjectId} is corrupt`);
    const body: EntryBody =
      kind === "review"
        ? { kind: "reviewReveal", submissionId: subjectId, verdict: r.verdict, salt: r.salt }
        : { kind: "attestReveal", snapshotId: subjectId, verdict: r.verdict, salt: r.salt };
    return { ...(await this.post(body)), verdict: r.verdict };
  }
}
