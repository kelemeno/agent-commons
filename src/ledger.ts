// The ledger: an append-only, hash-chained, signed log of EntryBody values, and
// the deterministic replay that turns it into CommonsState.
//
// Invariants a replayed state guarantees (each enforced below, with a stable
// LedgerError code so callers and tests can tell failures apart):
// - entries are contiguous from seq 0, each `prev` is the previous `hash`, each
//   `hash` is sha256hex(canonical(entry without hash)), and `at` never goes
//   backwards (claims and expiry are judged by `at`, so backdating would let an
//   agent resurrect an expired claim);
// - every entry after genesis is signed by a known, non-revoked key whose role
//   may sign that kind (roles are documented on EntryBody in types.ts);
// - every reference resolves, ids are unique, and the per-kind rules hold.
// applyEntry checks everything before it mutates anything, so a rejected entry
// leaves the state exactly as it was, and every rejection is a LedgerError.
//
// What replay cannot know: real time, and what a submission really changed.
// The writer bounds `at` against its own clock (appendSigned's `now`), and the
// coordinator must check a submission's declared changedFiles and linesChanged
// against `git diff baseCommit..headCommit` (server.ts does, on patch upload)
// before any gate trusts them. Replay only checks that the paths are canonical.

import * as fs from "node:fs";
import { canonical, isValidPublicKey, keyIdOf, sha256hex, sign, verify } from "./crypto";
import { isConfirmedDefect, isReproducedOpen } from "./findingStatus";
import { ringOf } from "./gates/rings";
import { MEMBER_ROOT, memberDigest } from "./members";
import { judgementPasses, judgementProblem } from "./judgement";
import { commitDeadlineMs, plantCommitment, reviewRounds, roundCloseSeq, seatRound } from "./plants";
import { assignmentBeacon, type CommitSubject, commitmentFor, escalationBeacon, validateVerdict } from "./review";
import { claimStake, validateRules } from "./rules";
import type {
  CommonsState,
  EntryBody,
  EntryKind,
  Evidence,
  FindingState,
  KeyId,
  LedgerEntry,
  OwnerId,
  ReviewState,
  ReviewVerdict,
  Rules,
  SettlementReason,
  Severity,
  SnapshotState,
} from "./types";

export type LedgerErrorCode =
  // envelope and chain
  | "malformed"
  | "genesis"
  | "seq"
  | "prev"
  | "hash"
  | "time"
  | "clock-skew"
  // signer
  | "signer-unknown"
  | "signature"
  | "signer-revoked"
  | "unauthorised"
  // semantics
  | "invalid-key"
  | "duplicate-key"
  | "duplicate-id"
  | "unknown-ref"
  | "invalid-rules"
  | "rules-version"
  | "invalid-evidence"
  | "invalid-value"
  | "inactive-agent"
  | "claim-live"
  | "claim-missing"
  | "claim-too-long"
  | "task-required"
  | "task-done"
  | "planted-by-author"
  | "merged"
  | "assigned"
  | "invalid-reviewers"
  | "same-owner"
  | "duplicate-commit"
  | "commit-closed"
  | "stake"
  | "no-commit"
  | "already-revealed"
  | "commitment-mismatch"
  | "invalid-verdict"
  | "invalid-target"
  | "result-exists"
  | "result-inconsistent"
  | "gates-missing"
  | "gate-failed"
  | "reproduced-finding"
  | "finding-pending"
  | "planted"
  | "not-merged"
  | "already-snapshotted"
  | "promoted"
  | "duplicate-signoff"
  | "plant-mismatch"
  | "plant-late"
  | "already-planted"
  | "not-reproduced"
  | "not-promoted"
  | "duplicate-escape"
  | "duplicate-settlement"
  | "commit-phase"
  | "not-assigned"
  | "decided"
  | "not-decidable"
  | "approved"
  | "window-closed"
  | "window-open"
  | "escalations"
  | "judgement"
  // file
  | "exists"
  | "torn"
  | "stale"
  | "locked";

export class LedgerError extends Error {
  readonly code: LedgerErrorCode;
  readonly seq: number | null;
  constructor(code: LedgerErrorCode, message: string, seq: number | null = null) {
    super(message);
    this.name = "LedgerError";
    this.code = code;
    this.seq = seq;
  }
}

export type GenesisBody = Extract<EntryBody, { kind: "genesis" }>;
export type Signer = { publicKey: string; privateKey: string };
type BodyOf<K extends EntryKind> = Extract<EntryBody, { kind: K }>;

// CommonsState plus the time of the last applied entry, which expiry and the
// monotonic-time rule need. CommonsState has no field for it, so it travels as
// an extra property on the state object (a structured clone keeps it).
export type LedgerState = CommonsState & { headAt: string };

const EPOCH = "1970-01-01T00:00:00.000Z";

// Longest a claim may run: one entry, and also one holder's unbroken run of
// extensions unless the holder delivered a submission for the task during the
// run. A cap is what stops one agent from locking a task forever for a token
// stake. It belongs in Rules (claim.maxHours); until then it is fixed here.
export const MAX_CLAIM_MS = 7 * 24 * 3_600_000;

// Default tolerance between an entry's `at` and the writer's clock.
export const DEFAULT_MAX_SKEW_MS = 5 * 60_000;

// Input limits. The ledger is permanent and every node replays all of it, so
// every free-text field, id and list is bounded here, at the one place every
// entry passes; the server's caps (server.ts FIELD_CAPS) are a stricter edge
// policy on top. Lengths are in UTF-16 code units (String.length).
export const LEDGER_LIMITS = {
  id: 128, // ids, refs to ids, owner ids, commit shas, salts, gate names: also ID_RE
  title: 300, // proposal titles
  text: 4000, // summaries, details, descriptions, notes, reasons, messages, harness errors
  path: 512, // repo paths: also canonical POSIX (isCanonicalPath)
  command: 2000, // test commands
  name: 64, // harness and modelFamily
  ref: 256, // settlement refs, evidence test ids and tools, entropy, log digests
  evidence: 20, // items per proposal
  changedFiles: 2000, // per submission
  acceptanceTestPaths: 100, // per task
  reviewers: 10, // per assignment
  findingIds: 50, // per verdict
  snapshotSubmissions: 500, // submissionIds per snapshot
} as const;

// An id starts with a letter or digit, so "", "." and ".." (and any id made
// only of dots) are impossible, and has no '/', space or control character:
// ids name files (patches, salts) and appear in refs and URLs.
export const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
// The trust tree's virtual root must never be an owner id (members.ts).
if (ID_RE.test(MEMBER_ROOT)) throw new Error(`ledger: ID_RE accepts the reserved tree root ${MEMBER_ROOT}`);

// Whether a submission for the task has merged: the task is done.
export function taskMerged(state: CommonsState, taskId: string): boolean {
  for (const s of state.submissions.values()) if (s.taskId === taskId && s.merged) return true;
  return false;
}

// An existing id equal to `id` ignoring letter case, if any.
function caseTwin(ids: Iterable<string>, id: string): string | undefined {
  const lower = id.toLowerCase();
  for (const other of ids) if (other.toLowerCase() === lower) return other;
  return undefined;
}

// An id git accepts as one ref name component (git check-ref-format), on top
// of ID_RE: no ':' and no "..", and no '.' or ".lock" at the end.
export function isRefSafeId(id: string): boolean {
  return !id.includes(":") && !id.includes("..") && !id.endsWith(".") && !id.endsWith(".lock");
}

// ---------------------------------------------------------------------------
// Envelope: what is signed and what is hashed.
// ---------------------------------------------------------------------------

export function entryMessage(e: Pick<LedgerEntry, "seq" | "prev" | "at" | "signer" | "body">): string {
  return canon({ seq: e.seq, prev: e.prev, at: e.at, signer: e.signer, body: e.body });
}

export function entryHash(e: Omit<LedgerEntry, "hash">): string {
  return sha256hex(canon({ seq: e.seq, prev: e.prev, at: e.at, signer: e.signer, body: e.body, sig: e.sig }));
}

// canonical() throws TypeError on values JSON cannot carry and RangeError on
// absurd nesting; from untrusted input both are just a malformed entry.
function canon(value: unknown): string {
  try {
    return canonical(value);
  } catch (e) {
    throw new LedgerError("malformed", `not canonical JSON: ${(e as Error).message}`);
  }
}

export function genesisEntry(body: GenesisBody, at: string): LedgerEntry {
  const unsigned = { seq: 0, prev: "", at, signer: "", body: cloneJson(body), sig: "" };
  return { ...unsigned, hash: entryHash(unsigned) };
}

// Signs `body` as the next entry after `head`. Pure: the caller supplies the
// time. The body is stored in its canonical JSON form, so the entry does not
// alias the caller's object and survives a write/read round trip unchanged.
export function signEntry(
  head: CommonsState | { seq: number; prev: string },
  body: EntryBody,
  signer: Signer,
  at: string,
): LedgerEntry {
  const seq = "headHash" in head ? head.length : head.seq;
  const prev = "headHash" in head ? head.headHash : head.prev;
  const unsigned = { seq, prev, at, signer: keyIdOf(signer.publicKey), body: cloneJson(body) };
  const signed = { ...unsigned, sig: sign(signer.privateKey, entryMessage(unsigned)) };
  return { ...signed, hash: entryHash(signed) };
}

function cloneJson<T>(value: T): T {
  return JSON.parse(canon(value)) as T;
}

// ---------------------------------------------------------------------------
// Shapes. Ledger lines are untrusted JSON, so every field is checked before
// any rule reads it. Fields whose value is undefined count as absent, matching
// canonical(), which drops them from what is signed.
// ---------------------------------------------------------------------------

type Check = (v: unknown) => boolean;

const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];
const REASONS: readonly SettlementReason[] = [
  "mergeVest",
  "proposerCut",
  "bounty",
  "authorSlash",
  "approverSlash",
  "cleanReview",
  "missedPlant",
  "falseFinding",
  "claimExpired",
  "inviterSlash",
  "honeytoken",
];

const L = LEDGER_LIMITS;
const any: Check = () => true;
const str: Check = (v) => typeof v === "string";
// A string of at most `max` characters; non-empty unless `empty`.
const text =
  (max: number, empty = false): Check =>
  (v) =>
    typeof v === "string" && v.length <= max && (empty || v.length > 0);
const id: Check = (v) => typeof v === "string" && v.length <= L.id && ID_RE.test(v);
const idOrNull: Check = (v) => v === null || id(v);

// Everything about a verdict the ledger checks at reveal without state: the
// shape (review.validateVerdict) and the ledger's limits. A commit carries only
// a hash, so a verdict that fails here would land as a commit no reveal could
// ever open (a silent approver, slashed as p = 0): clients call this before
// committing (client.ts, cli.ts).
export function verdictProblems(verdict: unknown): string[] {
  const problems = validateVerdict(verdict);
  if (problems.length > 0) return problems;
  const v = verdict as { summary: string; findingIds: unknown[] };
  if (v.summary.length > L.text) problems.push(`summary longer than ${L.text} characters`);
  if (v.findingIds.length > L.findingIds) problems.push(`more than ${L.findingIds} findingIds`);
  if (!v.findingIds.every(id)) problems.push("findingIds must be ids");
  return problems;
}

// The findings a verdict cites must exist and target its subject: a review's
// its submission, an attestation's its snapshot. `targetOf` gives a finding's
// target, or undefined for no such finding. The ledger applies this at reveal;
// clients apply it before committing, for the reason verdictProblems gives.
export function citedFindingProblems(
  targetOf: (findingId: string) => CommitSubject | undefined,
  findingIds: readonly string[],
  subject: CommitSubject,
): string[] {
  const out: string[] = [];
  for (const fid of findingIds) {
    const t = targetOf(fid);
    const here =
      t !== undefined &&
      ("submissionId" in subject ? "submissionId" in t && t.submissionId === subject.submissionId : "snapshotId" in t && t.snapshotId === subject.snapshotId);
    if (t === undefined) out.push(`no finding ${fid}`);
    else if (!here) out.push(`finding ${fid} does not target this review's subject`);
  }
  return out;
}
const path: Check = (v) => isCanonicalPath(v);
const int: Check = (v) => Number.isSafeInteger(v);
const nat: Check = (v) => Number.isSafeInteger(v) && (v as number) >= 0;
const bool: Check = (v) => typeof v === "boolean";
const listOf =
  (max: number, item: Check): Check =>
  (v) =>
    Array.isArray(v) && v.length <= max && v.every(item);
const hex64: Check = (v) => typeof v === "string" && HEX64_RE.test(v);
// One spelling per instant: the UTC form toISOString() produces. Date.parse
// alone would accept 2026-02-30 (rolled to March 2) and many spellings of one
// time, and other modules compare these strings.
const iso: Check = (v) =>
  typeof v === "string" && ISO_RE.test(v) && !Number.isNaN(Date.parse(v)) && new Date(v).toISOString() === v;
// A finding target: an object of string fields, checked in depth by the rule.
const target: Check = (v) => isPlainObject(v) && Object.values(v).every((x) => x === undefined || typeof x === "string");
const severity: Check = (v) => SEVERITIES.includes(v as Severity);
const ring: Check = (v) => v === 0 || v === 1 || v === 2;
const reason: Check = (v) => REASONS.includes(v as SettlementReason);

// Field checks per kind (besides `kind`). Arrays of ids, evidence, verdicts,
// targets and rules are type-checked here and validated in depth by the rules.
// Every limit in LEDGER_LIMITS is applied here, so an over-long field or list
// is a "malformed" entry before any rule reads it. Paths are only typed here:
// the per-kind rules check isCanonicalPath (which includes the length limit)
// and refuse with "invalid-value".
const SHAPES: { [K in EntryKind]: Record<string, Check> } = {
  genesis: { project: id, admins: listOf(Number.MAX_SAFE_INTEGER, str), coordinator: str, rules: any },
  ownerKey: { owner: id, publicKey: str, inviter: idOrNull },
  agentRegistered: { owner: id, publicKey: str, modelFamily: text(L.name), harness: text(L.name) },
  agentRevoked: { agent: id, reason: text(L.text, true) },
  proposal: { id, title: text(L.title), evidence: listOf(L.evidence, any) },
  task: { id, proposalId: id, ring, acceptanceTestPaths: listOf(L.acceptanceTestPaths, str), sizeEstimate: nat, specAuthor: id },
  claim: { taskId: id, until: iso, stake: int },
  submission: {
    id,
    taskId: idOrNull,
    baseCommit: id,
    headCommit: id,
    changedFiles: listOf(L.changedFiles, str),
    linesChanged: int,
  },
  gateResult: { submissionId: id, gate: id, pass: bool, details: text(L.text, true) },
  reviewAssignment: {
    submissionId: id,
    beacon: hex64,
    entropy: text(L.ref),
    treeDigest: hex64,
    reviewers: listOf(L.reviewers, id),
  },
  reviewEscalation: {
    submissionId: id,
    round: nat,
    beacon: hex64,
    entropy: text(L.ref),
    treeDigest: hex64,
    reviewers: listOf(L.reviewers, id),
  },
  reviewCommit: { submissionId: id, commitment: hex64, stake: int },
  reviewReveal: { submissionId: id, verdict: any, salt: id },
  finding: { id, target, severity, testPath: str, testCommand: text(L.command), stake: int },
  findingResult: {
    findingId: id,
    reproduced: bool,
    failsOnHead: bool,
    passesOnParent: bool,
    logDigest: text(L.ref, true),
  },
  findingAttempt: { findingId: id, harnessError: text(L.text) },
  findingDecision: { findingId: id, confirmed: bool, reason: text(L.text, true) },
  mergeApproval: { submissionId: id },
  reviewWindowClosed: { submissionId: id, missing: listOf(L.reviewers, id) },
  merge: { submissionId: id, commit: id },
  snapshot: { id, commit: id, previousSnapshotId: idOrNull, submissionIds: listOf(L.snapshotSubmissions, id) },
  attestCommit: { snapshotId: id, commitment: hex64, stake: int },
  attestReveal: { snapshotId: id, verdict: any, salt: id },
  signoff: { snapshotId: id },
  promotion: { snapshotId: id, commit: id },
  plantCommit: { commitment: hex64 },
  plantReveal: { submissionId: id, salt: id, description: text(L.text, true), severity },
  honeytokenTriggered: { agent: id, tokenId: id },
  escape: { findingId: id, snapshotId: id },
  settlement: { owner: id, delta: int, reason, ref: text(L.ref, true) },
  rulesChange: { rules: any, pollId: id },
};

// Optional fields, checked when present. `planted` may appear on a submission
// only so that the "authors may not set planted" rule can reject it with its
// own code instead of a shape error.
const OPTIONAL: Partial<Record<EntryKind, Record<string, Check>>> = {
  submission: { planted: any },
  findingResult: { harnessError: text(L.text) },
  reviewWindowClosed: { round: nat },
  merge: { judgement: any },
};

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

function definedKeys(o: Record<string, unknown>): string[] {
  return Object.keys(o).filter((k) => o[k] !== undefined);
}

// Exactly these fields, each passing its check. Returns a problem or null.
// Own properties only, on both sides: `in` would also find Object.prototype
// names (constructor, valueOf, ...), and JSON.parse makes "__proto__" an own
// key, so either way extra data could ride along unhashed in the envelope.
function fieldProblem(o: Record<string, unknown>, fields: Record<string, Check>, optional: Record<string, Check> = {}) {
  for (const [name, check] of Object.entries(fields)) {
    if (!Object.hasOwn(o, name) || o[name] === undefined) return `missing field ${name}`;
    if (!check(o[name])) return `bad field ${name}`;
  }
  for (const key of definedKeys(o)) {
    if (Object.hasOwn(fields, key)) continue;
    if (!Object.hasOwn(optional, key)) return `unknown field ${key}`;
    if (!(optional[key] as Check)(o[key])) return `bad field ${key}`;
  }
  return null;
}

// A repo-relative POSIX path in its one spelling, at most LEDGER_LIMITS.path
// long: no leading '/', no empty, '.' or '..' segment, no backslash or NUL.
// Ring and airlock globs are anchored, so `./a`, `a//b` or `a/../b` would
// dodge them while naming the same file.
export function isCanonicalPath(p: unknown): p is string {
  if (typeof p !== "string" || p === "" || p.length > LEDGER_LIMITS.path) return false;
  if (p.includes("\\") || p.includes("\0")) return false;
  return p.split("/").every((seg) => seg !== "" && seg !== "." && seg !== "..");
}

const ENVELOPE: Record<string, Check> = { seq: nat, prev: str, at: iso, signer: str, body: any, sig: str, hash: str };

function checkShape(entry: unknown): LedgerEntry {
  const seq = isPlainObject(entry) && nat(entry.seq) ? (entry.seq as number) : null;
  const bad = (msg: string): never => {
    throw new LedgerError("malformed", `entry${seq === null ? "" : ` ${seq}`}: ${msg}`, seq);
  };
  if (!isPlainObject(entry)) return bad("not an object");
  const envelopeProblem = fieldProblem(entry, ENVELOPE);
  if (envelopeProblem) return bad(envelopeProblem);
  const body = entry.body;
  if (!isPlainObject(body)) return bad("body is not an object");
  const kind = body.kind;
  if (typeof kind !== "string" || !Object.hasOwn(SHAPES, kind)) return bad(`unknown body kind ${String(kind)}`);
  const fields = { kind: str, ...SHAPES[kind as EntryKind] };
  const bodyProblem = fieldProblem(body, fields, OPTIONAL[kind as EntryKind]);
  if (bodyProblem) return bad(`${kind}: ${bodyProblem}`);
  return entry as unknown as LedgerEntry;
}

function evidenceProblem(e: unknown): string | null {
  if (!isPlainObject(e)) return "evidence item is not an object";
  const line: Check = (v) => Number.isSafeInteger(v) && (v as number) >= 1;
  switch (e.kind) {
    case "failingTest":
      return fieldProblem(e, { kind: str, testId: text(L.ref), command: text(L.command) });
    case "diagnostic":
      return fieldProblem(e, { kind: str, tool: text(L.ref), message: text(L.text), file: path, line });
    case "location":
      return fieldProblem(e, { kind: str, file: path, line, note: text(L.text, true) });
    default:
      return `unknown evidence kind ${String(e.kind)}`;
  }
}

// ---------------------------------------------------------------------------
// State construction and replay.
// ---------------------------------------------------------------------------

// The state just after genesis. Accepts the genesis entry, or a bare genesis
// body, in which case the entry is synthesised at `at` (default: the epoch);
// use genesisEntry() when the entry itself must be kept.
export function emptyState(genesis: LedgerEntry | GenesisBody, at: string = EPOCH): LedgerState {
  const isBody = isPlainObject(genesis) && (genesis as { kind?: unknown }).kind === "genesis";
  // The synthesised entry gets the same shape check as a genesis line read from a file.
  const entry = checkShape(isBody ? genesisEntry(genesis as GenesisBody, at) : genesis);
  const fail = (code: LedgerErrorCode, msg: string): never => {
    throw new LedgerError(code, `genesis: ${msg}`, 0);
  };
  if (entry.body.kind !== "genesis") return fail("genesis", "first entry must be genesis");
  if (entry.seq !== 0) return fail("seq", "genesis must have seq 0");
  if (entry.prev !== "") return fail("prev", "genesis must have an empty prev");
  if (entry.signer !== "" || entry.sig !== "") return fail("genesis", "genesis is unsigned");
  if (entry.hash !== entryHash(entry)) return fail("hash", "hash does not match contents");
  const body = entry.body;
  const keys = [...body.admins, body.coordinator];
  for (const k of keys) if (!isValidPublicKey(k)) fail("invalid-key", "not a canonical ed25519 SPKI key");
  const adminKeys = body.admins.map(keyIdOf);
  if (new Set(adminKeys).size !== adminKeys.length) fail("duplicate-key", "admin keys repeat");
  const problems = validateRules(body.rules);
  if (problems.length > 0) fail("invalid-rules", problems.join("; "));

  // The coordinator may also be an admin; separating those duties is a
  // deployment choice, not something the ledger can verify.
  const publicKeys = new Map<KeyId, string>();
  for (const k of keys) publicKeys.set(keyIdOf(k), k);
  return {
    project: body.project,
    rules: cloneJson(body.rules),
    rulesHistory: [{ seq: 0, rules: cloneJson(body.rules) }],
    adminKeys,
    coordinatorKey: keyIdOf(body.coordinator),
    publicKeys,
    owners: new Map(),
    ownerByKey: new Map(),
    agents: new Map(),
    proposals: new Map(),
    tasks: new Map(),
    claims: new Map(),
    claimHistory: [],
    submissions: new Map(),
    findings: new Map(),
    snapshots: new Map(),
    plantCommitments: [],
    honeytokens: [],
    escapes: [],
    settlements: [],
    headHash: entry.hash,
    length: 1,
    headAt: entry.at,
  };
}

export function replay(entries: readonly LedgerEntry[]): LedgerState {
  const first = entries[0];
  if (first === undefined) throw new LedgerError("genesis", "empty ledger", null);
  const state = emptyState(checkShape(first));
  for (let i = 1; i < entries.length; i++) applyUnlocked(state, entries[i]);
  recomputeLockedStake(state);
  return state;
}

export function applyEntry(state: CommonsState, entry: LedgerEntry): void {
  applyUnlocked(state, entry);
  recomputeLockedStake(state);
}

// lockedStake per owner, from scratch. Stake is locked while its outcome is
// open: a claim until it expires (judged at the latest entry time) or its task
// merges, a review commit until its submission merges or can never merge, an
// attestation until its snapshot ships or can never ship, a finding until its
// result is recorded. Without the "can never" release, every dead submission
// (a failed gate, a confirmed defect, a revealed plant) would lock its
// reviewers' stakes for good and drain the allowance of a small group.
export function recomputeLockedStake(state: CommonsState): void {
  for (const owner of state.owners.values()) owner.lockedStake = 0;
  const now = Date.parse(headAtOf(state));
  const add = (agent: KeyId, amount: number) => {
    const owner = state.owners.get(state.agents.get(agent)?.owner ?? "");
    if (owner) owner.lockedStake += amount;
  };
  const doneTasks = new Set<string>();
  for (const s of state.submissions.values()) if (s.merged && s.taskId !== null) doneTasks.add(s.taskId);
  for (const c of state.claims.values()) {
    if (!doneTasks.has(c.taskId) && Date.parse(c.until) >= now) add(c.agent, c.stake);
  }
  const dead = new Set<string>();
  for (const s of state.submissions.values()) {
    if (!s.merged && submissionDead(state, s.id)) dead.add(s.id);
    if (!s.merged && !dead.has(s.id)) for (const r of s.reviews) add(r.reviewer, r.stake);
  }
  const shipped = shippedSnapshotIds(state);
  for (const snap of state.snapshots.values()) {
    if (shipped.has(snap.id) || snapshotDead(state, snap)) continue;
    for (const a of snap.attestations) add(a.reviewer, a.stake);
  }
  for (const f of state.findings.values()) if (!f.result) add(f.finder, f.stake);
}

// An unmerged submission that can never merge: a failed gate (the merge rule
// refuses any), a revealed plant, a confirmed defect, a task another
// submission already merged, or a revoked author.
export function submissionDead(state: CommonsState, submissionId: string): boolean {
  const s = state.submissions.get(submissionId);
  if (!s || s.merged) return false;
  if (s.planted || s.gates.some((g) => !g.pass)) return true;
  // The coordinator never progresses a revoked author's work (coordinator
  // planActions): key rotation or suspension ends it, so its PR slot and its
  // reviewers' stakes are released; the owner resubmits with a new agent.
  if (state.agents.get(s.author)?.active === false) return true;
  if (s.taskId !== null && taskMerged(state, s.taskId)) return true;
  return s.findingIds.some((fid) => {
    const f = state.findings.get(fid);
    return f !== undefined && isConfirmedDefect(f);
  });
}

// A snapshot that can never be promoted: a confirmed defect on it or on a
// submission it lists, or a revealed plant among them.
function snapshotDead(state: CommonsState, snap: SnapshotState): boolean {
  if (snap.submissionIds.some((sid) => state.submissions.get(sid)?.planted)) return true;
  for (const f of state.findings.values()) {
    if (!isConfirmedDefect(f)) continue;
    if ("snapshotId" in f.target ? f.target.snapshotId === snap.id : snap.submissionIds.includes(f.target.submissionId)) return true;
  }
  return false;
}

// Snapshots on main: promoted ones and every ancestor of one.
export function shippedSnapshotIds(state: CommonsState): Set<string> {
  const out = new Set<string>();
  for (const snap of state.snapshots.values()) {
    if (!snap.promoted) continue;
    for (let cur: string | null = snap.id; cur !== null && !out.has(cur); ) {
      out.add(cur);
      cur = state.snapshots.get(cur)?.previousSnapshotId ?? null;
    }
  }
  return out;
}

function headAtOf(state: CommonsState): string {
  return (state as Partial<LedgerState>).headAt ?? EPOCH;
}

// ---------------------------------------------------------------------------
// Applying one entry.
// ---------------------------------------------------------------------------

// operator = a genesis admin key, or the key of an owner named in
// rules.kernelSigners: the humans who decide what a machine cannot (whether a
// reproduction is a real defect, whether a merge may go ahead).
type Role = "admin" | "coordinator" | "owner" | "agent" | "agentOrOwner" | "ownerOrCoordinator" | "operator";

const SIGNERS: { [K in Exclude<EntryKind, "genesis">]: Role } = {
  ownerKey: "admin",
  agentRegistered: "owner",
  agentRevoked: "ownerOrCoordinator",
  proposal: "agentOrOwner",
  task: "coordinator",
  claim: "agent",
  submission: "agent",
  gateResult: "coordinator",
  reviewAssignment: "coordinator",
  reviewEscalation: "coordinator",
  reviewCommit: "agent",
  reviewReveal: "agent",
  finding: "agent",
  findingResult: "coordinator",
  findingAttempt: "coordinator",
  findingDecision: "operator",
  mergeApproval: "operator",
  reviewWindowClosed: "coordinator",
  merge: "coordinator",
  snapshot: "coordinator",
  attestCommit: "agent",
  attestReveal: "agent",
  signoff: "owner",
  promotion: "coordinator",
  plantCommit: "admin",
  plantReveal: "admin",
  honeytokenTriggered: "coordinator",
  escape: "coordinator",
  settlement: "coordinator",
  rulesChange: "admin",
};

function hasRole(state: CommonsState, signer: KeyId, role: Role): boolean {
  const isAgent = state.agents.get(signer)?.active === true;
  const isOwner = state.ownerByKey.has(signer);
  const isCoordinator = signer === state.coordinatorKey;
  switch (role) {
    case "admin":
      return state.adminKeys.includes(signer);
    case "coordinator":
      return isCoordinator;
    case "owner":
      return isOwner;
    case "agent":
      return isAgent;
    case "agentOrOwner":
      return isAgent || isOwner;
    case "ownerOrCoordinator":
      return isOwner || isCoordinator;
    case "operator":
      return state.adminKeys.includes(signer) || state.rules.kernelSigners.includes(state.ownerByKey.get(signer) ?? "");
  }
}

function applyUnlocked(state: CommonsState, raw: unknown): void {
  const entry = checkShape(raw);
  const body = entry.body;
  const reject = (code: LedgerErrorCode, msg: string): never => {
    throw new LedgerError(code, `entry ${entry.seq} (${body.kind}): ${msg}`, entry.seq);
  };

  if (body.kind === "genesis") return reject("genesis", "genesis is only valid at seq 0");
  if (entry.seq !== state.length) reject("seq", `expected seq ${state.length}`);
  if (entry.prev !== state.headHash) reject("prev", "prev does not match the previous entry's hash");
  if (entry.hash !== entryHash(entry)) reject("hash", "hash does not match contents");
  if (Date.parse(entry.at) < Date.parse(headAtOf(state))) reject("time", "time goes backwards");

  const publicKey = state.publicKeys.get(entry.signer);
  if (publicKey === undefined) return reject("signer-unknown", `unknown signer ${entry.signer}`);
  if (!verify(publicKey, entryMessage(entry), entry.sig)) reject("signature", "invalid signature");
  if (state.agents.get(entry.signer)?.active === false) reject("signer-revoked", "signer is a revoked agent");
  if (!hasRole(state, entry.signer, SIGNERS[body.kind])) {
    reject("unauthorised", `signer may not sign ${body.kind} (needs ${SIGNERS[body.kind]})`);
  }

  applyBody(state, entry, body, reject);
  state.length = entry.seq + 1;
  state.headHash = entry.hash;
  (state as LedgerState).headAt = entry.at;
}

type Reject = (code: LedgerErrorCode, msg: string) => never;

// Per-kind rules. Each case validates fully, then mutates.
function applyBody(state: CommonsState, entry: LedgerEntry, body: EntryBody, reject: Reject): void {
  const { seq, at, signer } = entry;
  const ms = Date.parse(at);
  const ownerOf = (agent: KeyId): OwnerId | undefined => state.agents.get(agent)?.owner;
  const submission = (sid: string) => state.submissions.get(sid) ?? reject("unknown-ref", `no submission ${sid}`);
  const snapshot = (sid: string) => state.snapshots.get(sid) ?? reject("unknown-ref", `no snapshot ${sid}`);
  const finding = (fid: string) => state.findings.get(fid) ?? reject("unknown-ref", `no finding ${fid}`);
  const newKey = (publicKey: string): KeyId => {
    if (!isValidPublicKey(publicKey)) reject("invalid-key", "not a canonical ed25519 SPKI key");
    const keyId = keyIdOf(publicKey);
    if (state.publicKeys.has(keyId)) reject("duplicate-key", "key already registered");
    return keyId;
  };

  switch (body.kind) {
    case "genesis":
      return reject("genesis", "genesis is only valid at seq 0");

    case "ownerKey": {
      if (state.owners.has(body.owner)) reject("duplicate-id", `owner ${body.owner} already has a key`);
      // Ids are chosen by people, who type them in any case. Two
      // spellings of one member would be two owners here (two tickets, two
      // review seats, a way round "not the author's owner"), so ids that
      // differ only in case are one id. Every other owner check can then
      // compare exact strings, as the member tree does.
      const lower = body.owner.toLowerCase();
      for (const o of state.owners.keys()) {
        if (o.toLowerCase() === lower) reject("duplicate-id", `owner ${body.owner} is already registered as ${o} (owner ids ignore case)`);
      }
      const keyId = newKey(body.publicKey);
      if (body.inviter !== null && !state.owners.has(body.inviter)) reject("unknown-ref", `no inviter ${body.inviter}`);
      state.publicKeys.set(keyId, body.publicKey);
      state.owners.set(body.owner, { id: body.owner, keyId, inviter: body.inviter, reputationDelta: 0, lockedStake: 0, registeredSeq: seq });
      state.ownerByKey.set(keyId, body.owner);
      return;
    }

    case "agentRegistered": {
      const owner = state.owners.get(body.owner) ?? reject("unknown-ref", `no owner ${body.owner}`);
      if (owner.keyId !== signer) reject("unauthorised", "only the named owner may register its agents");
      // A closed list: free spellings ("Claude ", "anthropic") would let one
      // family pass as two for requireOtherModelFamily and promotion coverage.
      if (!state.rules.modelFamilies.includes(body.modelFamily)) {
        reject("invalid-value", `model family ${JSON.stringify(body.modelFamily)} is not one of rules.modelFamilies`);
      }
      const keyId = newKey(body.publicKey);
      state.publicKeys.set(keyId, body.publicKey);
      state.agents.set(keyId, {
        keyId,
        owner: body.owner,
        modelFamily: body.modelFamily,
        harness: body.harness,
        active: true,
        registeredSeq: seq,
      });
      return;
    }

    case "agentRevoked": {
      const agent = state.agents.get(body.agent) ?? reject("unknown-ref", `no agent ${body.agent}`);
      if (signer !== state.coordinatorKey && state.ownerByKey.get(signer) !== agent.owner) {
        reject("unauthorised", "only the agent's owner or the coordinator may revoke it");
      }
      if (!agent.active) reject("inactive-agent", "agent already revoked");
      agent.active = false;
      agent.revokedReason = body.reason;
      agent.revokedBy = signer === state.coordinatorKey ? "coordinator" : "owner";
      agent.revokedSeq = seq;
      return;
    }

    case "proposal": {
      if (state.proposals.has(body.id)) reject("duplicate-id", `proposal ${body.id} exists`);
      if (body.evidence.length === 0) reject("invalid-evidence", "a proposal needs evidence");
      for (const e of body.evidence) {
        const problem = evidenceProblem(e);
        if (problem) reject("invalid-evidence", problem);
      }
      state.proposals.set(body.id, {
        id: body.id,
        title: body.title,
        evidence: cloneJson<Evidence[]>(body.evidence),
        by: signer,
        seq,
      });
      return;
    }

    case "task": {
      if (state.tasks.has(body.id)) reject("duplicate-id", `task ${body.id} exists`);
      if (!state.proposals.has(body.proposalId)) reject("unknown-ref", `no proposal ${body.proposalId}`);
      if (!state.owners.has(body.specAuthor)) reject("unknown-ref", `spec author ${body.specAuthor} is not an owner`);
      if (body.acceptanceTestPaths.length === 0) reject("invalid-value", "a task needs acceptance test paths");
      if (!body.acceptanceTestPaths.every(isCanonicalPath)) reject("invalid-value", "acceptance test paths must be canonical");
      state.tasks.set(body.id, { ...body, acceptanceTestPaths: [...body.acceptanceTestPaths], seq });
      return;
    }

    case "claim": {
      const task = state.tasks.get(body.taskId) ?? reject("unknown-ref", `no task ${body.taskId}`);
      // The stake is a floor, not a fee: a token stake would let one agent
      // squat every task for a point each.
      const minStake = Math.max(1, claimStake(task.sizeEstimate, task.ring, state.rules));
      if (body.stake < minStake) reject("stake", `claim stake must be at least ${minStake}`);
      const until = Date.parse(body.until);
      if (until <= ms) reject("invalid-value", "claim must expire after it is made");
      if (until - ms > MAX_CLAIM_MS) reject("claim-too-long", `a claim may run at most ${MAX_CLAIM_MS / 3_600_000} hours`);
      if (taskMerged(state, body.taskId)) reject("task-done", `task ${body.taskId} already merged`);
      const current = state.claims.get(body.taskId);
      // Live through its `until` instant, as everywhere else (the submission
      // rule, recomputeLockedStake, settleExpiredClaims): a re-claim stamped
      // exactly at `until` is an extension, capped like one, not a fresh run.
      const live = current !== undefined && Date.parse(current.until) >= ms;
      // The holder may extend its own live claim; anyone else waits for
      // expiry. A revoked holder's claim is dead: revocation must not leave the
      // task locked.
      if (current && live && current.agent !== signer && state.agents.get(current.agent)?.active === true) {
        reject("claim-live", `task ${body.taskId} is claimed until ${current.until}`);
      }
      // An unbroken run of extensions is capped like one claim, unless the
      // holder delivered a submission for the task since its previous claim
      // entry (it is working, not squatting). Re-claiming after expiry starts
      // a new run; the lapsed claim stays in claimHistory and is still settled.
      const extending = current !== undefined && live && current.agent === signer;
      const since = extending ? (current.since ?? at) : at;
      if (extending && until - Date.parse(since) > MAX_CLAIM_MS) {
        const delivered = [...state.submissions.values()].some(
          (x) => x.taskId === body.taskId && x.author === signer && x.submittedSeq > current.seq,
        );
        if (!delivered) {
          reject("claim-too-long", `claims on ${body.taskId} since ${since} would run past ${MAX_CLAIM_MS / 3_600_000} hours without a submission`);
        }
      }
      state.claims.set(body.taskId, { taskId: body.taskId, agent: signer, until: body.until, stake: body.stake, seq, since });
      state.claimHistory?.push({ taskId: body.taskId, agent: signer, until: body.until, stake: body.stake, seq, at });
      return;
    }

    case "submission": {
      if (body.planted !== undefined) reject("planted-by-author", "authors may not set planted");
      if (state.submissions.has(body.id)) reject("duplicate-id", `submission ${body.id} exists`);
      // A submission id names its patch file and its ref refs/commons/<id>:
      // one that differs from another only in case is the same file on a
      // case-insensitive filesystem (the default on macOS), and git refuses
      // some names outright.
      const twin = caseTwin(state.submissions.keys(), body.id);
      if (twin !== undefined) reject("duplicate-id", `submission ${body.id} differs from ${twin} only in case`);
      if (!isRefSafeId(body.id)) reject("invalid-value", `submission id ${body.id} cannot name a git ref (no ':', '..', or a '.' or '.lock' ending)`);
      if (body.taskId !== null) {
        if (!state.tasks.has(body.taskId)) reject("unknown-ref", `no task ${body.taskId}`);
        // A task is done once one submission for it merged; a claim still live
        // must not let its holder submit (and be paid) again for it.
        if (taskMerged(state, body.taskId)) reject("task-done", `task ${body.taskId} already merged`);
        const claim = state.claims.get(body.taskId);
        if (!claim || claim.agent !== signer || Date.parse(claim.until) < ms) {
          reject("claim-missing", `submitter holds no live claim on task ${body.taskId}`);
        }
      }
      if (body.linesChanged < 0) reject("invalid-value", "linesChanged must be >= 0");
      if (body.changedFiles.length === 0) reject("invalid-value", "changedFiles must be non-empty");
      const bad = body.changedFiles.find((f) => !isCanonicalPath(f));
      if (bad !== undefined) reject("invalid-value", `changed file ${JSON.stringify(bad)} is not a canonical repo path`);
      if (new Set(body.changedFiles).size !== body.changedFiles.length) reject("invalid-value", "changed file listed twice");
      // A kernel change must go through a task, so it carries a claim stake at
      // the ring 0 multiplier instead of none.
      if (body.taskId === null && body.changedFiles.some((f) => ringOf(f, state.rules) === 0)) {
        reject("task-required", "a submission touching ring 0 must name a task");
      }
      state.submissions.set(body.id, {
        id: body.id,
        author: signer,
        taskId: body.taskId,
        baseCommit: body.baseCommit,
        headCommit: body.headCommit,
        changedFiles: [...body.changedFiles],
        linesChanged: body.linesChanged,
        submittedSeq: seq,
        submittedAt: at,
        gates: [],
        escalations: [],
        reviews: [],
        findingIds: [],
      });
      return;
    }

    case "gateResult": {
      submission(body.submissionId).gates.push({ gate: body.gate, pass: body.pass, details: body.details });
      return;
    }

    case "reviewAssignment": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      if (s.assignment) reject("assigned", "submission already has an assignment");
      if (body.reviewers.length === 0) reject("invalid-reviewers", "no reviewers");
      // The tree is the member tree of the ledger so far, so the coordinator
      // cannot draw over another one; the beacon is a function of the
      // submission and the entropy, never the coordinator's choice (it leaves
      // the digest out: see review.assignmentBeacon). Replay does not redo the
      // draw itself (selection.verifyAssignment does).
      if (body.treeDigest !== memberDigest(state)) {
        reject("invalid-value", "treeDigest is not the digest of the member tree before this entry");
      }
      if (body.beacon !== assignmentBeacon(s.id, s.headCommit, body.entropy)) {
        reject("invalid-value", "beacon is not assignmentBeacon(submissionId, headCommit, entropy)");
      }
      const authorOwner = ownerOf(s.author);
      const owners = new Set<OwnerId>();
      for (const r of body.reviewers) {
        const agent = state.agents.get(r);
        if (!agent?.active) return reject("invalid-reviewers", `reviewer ${r} is not an active agent`);
        if (agent.owner === authorOwner) reject("invalid-reviewers", `reviewer ${r} shares the author's owner`);
        // Distinct owners, not just distinct keys: one person running several
        // agents must not fill several review seats.
        if (owners.has(agent.owner)) reject("invalid-reviewers", `owner ${agent.owner} holds two seats`);
        owners.add(agent.owner);
        // One review commit per owner (checkCommit): a seat given to another
        // agent of an owner that already committed could never be filled.
        const other = s.reviews.find((c) => c.reviewer !== r && ownerOf(c.reviewer) === agent.owner);
        if (other) reject("invalid-reviewers", `owner ${agent.owner} already committed through ${other.reviewer}; that agent holds its seat`);
      }
      s.assignment = {
        beacon: body.beacon,
        entropy: body.entropy,
        treeDigest: body.treeDigest,
        reviewers: [...body.reviewers],
        seq,
        at,
      };
      return;
    }

    case "reviewEscalation": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      if (!s.assignment) reject("not-assigned", "no reviewer assignment");
      if (s.planted) reject("planted", "a revealed plant is a known defect");
      // Nobody new could commit (reviewCommitsClosedBy), and the reproduction
      // blocks the merge whatever more reviewers say.
      if (s.findingIds.some((fid) => isReproducedOpen(finding(fid)))) {
        reject("reproduced-finding", "a reproduced finding targets this submission");
      }
      const rounds = (s.escalations ??= []);
      if (body.round !== rounds.length + 1) reject("invalid-value", `round must be ${rounds.length + 1}`);
      if (body.round > state.rules.judgement.maxEscalations) {
        reject("escalations", `rules.judgement.maxEscalations is ${state.rules.judgement.maxEscalations}`);
      }
      // The judgement escalates on closed rounds only: what the earlier
      // reviewers said is what calls for more of them.
      if (roundCloseSeq(state, s.id, body.round - 1) === null) reject("window-open", `review round ${body.round - 1} has not closed`);
      if (body.reviewers.length === 0) reject("invalid-reviewers", "no reviewers");
      if (body.reviewers.length > state.rules.judgement.escalationReviewers) {
        reject("invalid-reviewers", `more than rules.judgement.escalationReviewers (${state.rules.judgement.escalationReviewers}) reviewers`);
      }
      // As for the assignment: the tree is the ledger's, the beacon follows
      // from the entry; selection.verifyEscalation redoes the draw.
      if (body.treeDigest !== memberDigest(state)) {
        reject("invalid-value", "treeDigest is not the digest of the member tree before this entry");
      }
      if (body.beacon !== escalationBeacon(s.id, s.headCommit, body.round, body.entropy)) {
        reject("invalid-value", "beacon is not escalationBeacon(submissionId, headCommit, round, entropy)");
      }
      const authorOwner = ownerOf(s.author);
      const taken = new Set<OwnerId>();
      for (const k of [...reviewRounds(s).flatMap((r) => r.reviewers), ...s.reviews.map((r) => r.reviewer)]) {
        const o = ownerOf(k);
        if (o !== undefined) taken.add(o);
      }
      const owners = new Set<OwnerId>();
      for (const r of body.reviewers) {
        const agent = state.agents.get(r);
        if (!agent?.active) return reject("invalid-reviewers", `reviewer ${r} is not an active agent`);
        if (agent.owner === authorOwner) reject("invalid-reviewers", `reviewer ${r} shares the author's owner`);
        if (taken.has(agent.owner)) reject("invalid-reviewers", `owner ${agent.owner} already holds a seat or a commit on ${s.id}`);
        if (owners.has(agent.owner)) reject("invalid-reviewers", `owner ${agent.owner} holds two seats`);
        owners.add(agent.owner);
      }
      rounds.push({
        round: body.round,
        beacon: body.beacon,
        entropy: body.entropy,
        treeDigest: body.treeDigest,
        reviewers: [...body.reviewers],
        seq,
        at,
      });
      return;
    }

    case "reviewCommit": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      checkCommit(s.reviews, ownerSet([s.id]), body.commitment, body.stake, reviewCommitsClosedBy(state, s.id, ms, signer));
      // The owner's seat is its assigned agent's: a commit by another of its
      // agents would leave that seat unfillable (one commit per owner). A
      // seated agent since revoked can fill nothing, so it holds nothing.
      const seated = reviewRounds(s).flatMap((r) => r.reviewers);
      const seat = seated.find((k) => k !== signer && ownerOf(k) === ownerOf(signer) && state.agents.get(k)?.active === true);
      if (seat !== undefined) reject("duplicate-commit", `this owner's seat on ${s.id} is ${seat}'s; commit with that agent`);
      s.reviews.push({ reviewer: signer, commitment: body.commitment, stake: body.stake, committedSeq: seq });
      return;
    }

    case "reviewReveal": {
      const s = submission(body.submissionId);
      // The commit phase: no verdict is public until every assigned reviewer
      // committed or the phase ended. Otherwise one reveal, by anyone, seconds
      // after a submission would shut the assigned reviewers out for good.
      if (!s.assignment) reject("commit-phase", "reveals wait for the reviewer assignment");
      // An escalated seat waits for its own round's commit phase; everyone
      // else for round 0's.
      const round = seatRound(s, signer) ?? reviewRounds(s)[0];
      const deadline = commitDeadlineMs(state.rules, round?.at);
      const allCommitted = (round?.reviewers ?? []).every((k) => s.reviews.some((r) => r.reviewer === k));
      if (!allCommitted && ms < deadline) {
        reject("commit-phase", `reveals wait until every reviewer of round ${round?.round ?? 0} committed or ${new Date(deadline).toISOString()}`);
      }
      const review = checkReveal(s.reviews, body.verdict, body.salt, { submissionId: s.id });
      review.verdict = cloneJson(body.verdict);
      review.revealedSeq = seq;
      return;
    }

    case "finding": {
      if (state.findings.has(body.id)) reject("duplicate-id", `finding ${body.id} exists`);
      // Finding ids name the uploaded test file: unique ignoring case, as above.
      const twin = caseTwin(state.findings.keys(), body.id);
      if (twin !== undefined) reject("duplicate-id", `finding ${body.id} differs from ${twin} only in case`);
      const target = body.target as unknown;
      if (!isPlainObject(target) || definedKeys(target).length !== 1) {
        return reject("invalid-target", "target must name exactly one submission or snapshot");
      }
      let targetSubmission: string | null = null;
      if (Object.hasOwn(target, "submissionId") && id(target.submissionId)) {
        const s = submission(target.submissionId as string);
        if (ownerOf(s.author) === ownerOf(signer)) reject("same-owner", "cannot file a finding on your owner's work");
        targetSubmission = s.id;
      } else if (Object.hasOwn(target, "snapshotId") && id(target.snapshotId)) {
        const snap = snapshot(target.snapshotId as string);
        if (ownerSet(covered(snap)).has(ownerOf(signer) ?? "")) {
          reject("same-owner", "cannot file a finding on a snapshot of your owner's work");
        }
      } else {
        reject("invalid-target", "target must name exactly one submission or snapshot");
      }
      if (!isCanonicalPath(body.testPath)) reject("invalid-value", "testPath must be a canonical repo path");
      if (body.stake < state.rules.stake.finding) reject("stake", `finding stake below ${state.rules.stake.finding}`);
      state.findings.set(body.id, {
        id: body.id,
        finder: signer,
        target: cloneJson(body.target),
        severity: body.severity,
        testPath: body.testPath,
        testCommand: body.testCommand,
        stake: body.stake,
        seq,
        at,
      });
      if (targetSubmission !== null) state.submissions.get(targetSubmission)?.findingIds.push(body.id);
      return;
    }

    case "findingResult": {
      const f = finding(body.findingId);
      if (f.result) reject("result-exists", "finding already has a result");
      if (body.reproduced !== (body.failsOnHead && body.passesOnParent)) {
        reject("result-inconsistent", "reproduced must equal failsOnHead && passesOnParent");
      }
      // "Could not run" is not "did not reproduce", and never a reproduction.
      if (body.harnessError !== undefined && body.reproduced) {
        reject("result-inconsistent", "a result with a harness error cannot be a reproduction");
      }
      f.result = {
        reproduced: body.reproduced,
        failsOnHead: body.failsOnHead,
        passesOnParent: body.passesOnParent,
        logDigest: body.logDigest,
        ...(body.harnessError === undefined ? {} : { harnessError: body.harnessError }),
        seq,
        at,
      };
      return;
    }

    case "findingAttempt": {
      const f = finding(body.findingId);
      if (f.result) reject("result-exists", "finding already has a result");
      f.harnessErrors = (f.harnessErrors ?? 0) + 1;
      return;
    }

    case "findingDecision": {
      const f = finding(body.findingId);
      if (f.result?.reproduced !== true) reject("not-decidable", "only a reproduced finding is confirmed or dismissed");
      if (f.decision) reject("decided", "finding already decided");
      // An owner judges neither its own finding nor a finding on its own work.
      const mine = state.ownerByKey.get(signer);
      if (mine !== undefined && !state.adminKeys.includes(signer)) {
        if (ownerOf(f.finder) === mine) reject("same-owner", "cannot decide your own owner's finding");
        const targetOwners =
          "submissionId" in f.target ? ownerSet([f.target.submissionId]) : ownerSet(covered(snapshot(f.target.snapshotId)));
        if (targetOwners.has(mine)) reject("same-owner", "cannot decide a finding on your owner's work");
      }
      f.decision = { confirmed: body.confirmed, reason: body.reason, by: signer, seq, at };
      return;
    }

    case "mergeApproval": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      if (s.approval) reject("approved", "submission already approved");
      const mine = state.ownerByKey.get(signer);
      if (mine !== undefined && !state.adminKeys.includes(signer) && ownerOf(s.author) === mine) {
        reject("same-owner", "cannot approve your owner's work");
      }
      s.approval = { by: signer, seq, at };
      return;
    }

    case "reviewWindowClosed": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      if (!s.assignment) reject("not-assigned", "no reviewer assignment");
      const k = body.round ?? 0;
      const round = reviewRounds(s).find((r) => r.round === k);
      if (!round) return reject("unknown-ref", `no review round ${k}`);
      if (round.closed) reject("window-closed", `review round ${k} already closed`);
      const unrevealed = round.reviewers.filter((r) => !s.reviews.some((v) => v.reviewer === r && v.verdict));
      if (canon([...body.missing].sort()) !== canon([...unrevealed].sort())) {
        reject("invalid-reviewers", "missing must be exactly the round's reviewers who have not revealed");
      }
      const closed = { missing: [...body.missing], seq, at };
      if (k === 0) s.windowClosed = closed;
      else round.closed = closed;
      return;
    }

    case "merge": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      if (s.taskId !== null && taskMerged(state, s.taskId)) reject("task-done", `task ${s.taskId} already merged`);
      if (s.gates.length === 0) reject("gates-missing", "no gate results recorded");
      const failed = s.gates.find((g) => !g.pass);
      if (failed) reject("gate-failed", `gate ${failed.gate} failed`);
      // Mechanical and cheap: nothing merges unreviewed. The quorum and the
      // human approval are the coordinator's rule (mergeReadiness), which
      // needs the clock; `commons merge` checks it before appending.
      if (!s.assignment) reject("not-assigned", "no reviewers were assigned");
      // A reproduction blocks until an operator dismisses it.
      if (s.findingIds.some((fid) => isReproducedOpen(finding(fid)))) {
        reject("reproduced-finding", "a reproduced finding targets this submission");
      }
      // Undecided is not clean: merging before the harness answers would get
      // past the reproduced-finding rule by timing alone.
      if (s.findingIds.some((fid) => !state.findings.get(fid)?.result)) {
        reject("finding-pending", "a finding on this submission has no result yet");
      }
      if (s.planted) reject("planted", "a revealed plant is a known defect");
      // The reviews decide (judgement.ts): without a human's approval the
      // merge must record a judgement that passes. Its pool and fields are
      // checked here; its weights by replay (selection.verifyJudgementInLedger).
      const j = body.judgement;
      if (j !== undefined) {
        const problem = judgementProblem(state, s, j);
        if (problem !== null) reject("judgement", problem);
        const asOf = typeof j.asOf === "string" && iso(j.asOf) ? Date.parse(j.asOf) : Number.NaN;
        if (!(asOf >= Date.parse(headAtOf(state)) && asOf <= ms)) {
          reject("judgement", "judgement.asOf must be a time between the previous entry and this one");
        }
      }
      if (!s.approval) {
        if (j === undefined) return reject("judgement", "a merge without a mergeApproval must record the merge judgement");
        const fails = judgementPasses(state, s, j);
        if (fails !== null) reject("judgement", `the judgement does not pass without a mergeApproval: ${fails}`);
      }
      s.merged = { commit: body.commit, seq, at, ...(j !== undefined ? { judgement: cloneJson(j) } : {}) };
      return;
    }

    case "snapshot": {
      if (state.snapshots.has(body.id)) reject("duplicate-id", `snapshot ${body.id} exists`);
      if (body.previousSnapshotId !== null) snapshot(body.previousSnapshotId);
      if (body.submissionIds.length === 0) reject("invalid-value", "a snapshot needs submissions");
      if (new Set(body.submissionIds).size !== body.submissionIds.length) {
        reject("invalid-value", "submission listed twice");
      }
      const earlier = new Set<string>();
      for (const snap of state.snapshots.values()) for (const sid of snap.submissionIds) earlier.add(sid);
      for (const sid of body.submissionIds) {
        if (!submission(sid).merged) reject("not-merged", `submission ${sid} is not merged`);
        if (earlier.has(sid)) reject("already-snapshotted", `submission ${sid} is in an earlier snapshot`);
      }
      state.snapshots.set(body.id, {
        id: body.id,
        commit: body.commit,
        previousSnapshotId: body.previousSnapshotId,
        submissionIds: [...body.submissionIds],
        seq,
        at,
        attestations: [],
        signoffs: [],
      });
      return;
    }

    case "attestCommit": {
      const snap = snapshot(body.snapshotId);
      if (snap.promoted) reject("promoted", "snapshot already promoted");
      const chain = ancestry(snap, true);
      const subs = chain.flatMap((x) => x.submissionIds);
      // Commits close at the end of the commit phase, never at the first
      // reveal (reveals wait for that end): one early reveal must not shut
      // every other attester out.
      const closedBy =
        ms >= commitDeadlineMs(state.rules, snap.at)
          ? "the commit phase ended"
          : snap.attestations.some((a) => a.verdict)
            ? "an attestation was revealed"
            : subs.some((sid) => state.submissions.get(sid)?.planted)
              ? "a plant it covers was revealed"
              : [...state.findings.values()].some((f) => isReproducedOpen(f) && chain.some((x) => targets(f, x, subs)))
                ? "a finding on it reproduced"
                : null;
      checkCommit(snap.attestations, ownerSet(subs), body.commitment, body.stake, closedBy);
      snap.attestations.push({ reviewer: signer, commitment: body.commitment, stake: body.stake, committedSeq: seq });
      return;
    }

    case "attestReveal": {
      const snap = snapshot(body.snapshotId);
      const deadline = commitDeadlineMs(state.rules, snap.at);
      if (ms < deadline) reject("commit-phase", `attestation reveals wait until ${new Date(deadline).toISOString()}`);
      const attestation = checkReveal(snap.attestations, body.verdict, body.salt, { snapshotId: snap.id });
      attestation.verdict = cloneJson(body.verdict);
      attestation.revealedSeq = seq;
      return;
    }

    case "signoff": {
      const snap = snapshot(body.snapshotId);
      const owner = state.ownerByKey.get(signer) ?? reject("unauthorised", "signer is not an owner");
      if (!state.rules.kernelSigners.includes(owner)) reject("unauthorised", `${owner} is not a kernel signer`);
      if (snap.promoted) reject("promoted", "snapshot already promoted");
      // Independence is about the kernel diff being signed: a signer's own
      // ring-1 or ring-2 work in the same snapshot does not stop it reading
      // someone else's kernel change. In a small group every snapshot soon
      // covers everyone's work, so excluding all authors would leave nobody.
      const kernelWork = covered(snap).filter((sid) => state.submissions.get(sid)?.changedFiles.some((f) => ringOf(f, state.rules) === 0));
      if (ownerSet(kernelWork).has(owner)) reject("same-owner", "cannot sign off a snapshot whose kernel changes include your own agents' work");
      if (snap.signoffs.includes(owner)) reject("duplicate-signoff", `${owner} already signed off`);
      snap.signoffs.push(owner);
      return;
    }

    case "promotion": {
      const snap = snapshot(body.snapshotId);
      if (snap.promoted) reject("promoted", "snapshot already promoted");
      // Main never moves backwards: not onto what a promoted descendant
      // already shipped, nor behind a later promoted snapshot. Every derived
      // notion of "covered" and "shipped" relies on this.
      if (shippedSnapshotIds(state).has(snap.id)) reject("promoted", "a promoted descendant already shipped this snapshot");
      for (const other of state.snapshots.values()) {
        if (other.promoted && other.seq > snap.seq) reject("promoted", `main has moved past it: ${other.id} is promoted`);
      }
      snap.promoted = { seq, at };
      return;
    }

    case "plantCommit": {
      if (state.plantCommitments.some((c) => c.commitment === body.commitment)) {
        reject("duplicate-commit", "commitment already recorded");
      }
      state.plantCommitments.push({ commitment: body.commitment, seq });
      return;
    }

    case "plantReveal": {
      const s = submission(body.submissionId);
      if (s.planted) reject("already-planted", "plant already revealed");
      // The preimage `${submissionId}:${salt}` is unambiguous only if the salt
      // has no ':'; then a commitment names exactly one submission id, and
      // already-planted is what makes each commitment usable once. Without this
      // one commitment to "a:b:c" could later label "a" or "a:b", at choice.
      if (body.salt.includes(":")) reject("invalid-value", "plant salt may not contain ':'");
      const commitment = plantCommitment(body.submissionId, body.salt);
      const commit = state.plantCommitments.find((c) => c.commitment === commitment);
      if (!commit) return reject("plant-mismatch", "no plant commitment matches");
      // The commitment must predate the submission; otherwise the custodian
      // could label any submission a plant after seeing who caught it.
      if (commit.seq > s.submittedSeq) reject("plant-late", "plant committed after the submission");
      s.planted = { severity: body.severity, description: body.description, seq };
      return;
    }

    case "honeytokenTriggered": {
      if (!state.agents.has(body.agent)) reject("unknown-ref", `no agent ${body.agent}`);
      state.honeytokens.push({ agent: body.agent, tokenId: body.tokenId, seq, at });
      return;
    }

    case "escape": {
      const f = finding(body.findingId);
      if (f.result?.reproduced !== true) reject("not-reproduced", "escape needs a reproduced finding");
      if (!isConfirmedDefect(f)) reject("not-decidable", "escape needs a finding an operator confirmed");
      const snap = snapshot(body.snapshotId);
      if (!snap.promoted) reject("not-promoted", "escape needs a promoted snapshot");
      // What main holds at a snapshot is the snapshot and all its ancestors.
      const lineage = ancestry(snap, false);
      const shipped = lineage.flatMap((x) => x.submissionIds);
      if (!lineage.some((x) => targets(f, x, shipped))) {
        reject("invalid-target", "the finding is not on anything this snapshot shipped");
      }
      if (state.escapes.some((e) => e.findingId === body.findingId)) reject("duplicate-escape", "already recorded");
      state.escapes.push({ findingId: body.findingId, snapshotId: body.snapshotId, seq, at });
      return;
    }

    case "settlement": {
      const owner = state.owners.get(body.owner) ?? reject("unknown-ref", `no owner ${body.owner}`);
      // (owner, reason, ref) names one event's movement: settled once, whoever
      // appends it (protocol §6). incentives.ts and the coordinator filter on
      // the same key; this makes a duplicate invalid on replay too.
      const keys = settledKeys(state);
      const key = settlementKey(body);
      if (keys.has(key)) reject("duplicate-settlement", `${body.owner} ${body.reason} ${body.ref} is already settled`);
      owner.reputationDelta += body.delta;
      state.settlements.push({ owner: body.owner, delta: body.delta, reason: body.reason, ref: body.ref, seq, at });
      keys.add(key);
      return;
    }

    case "rulesChange": {
      const problems = validateRules(body.rules);
      if (problems.length > 0) reject("invalid-rules", problems.join("; "));
      if (body.rules.version <= state.rules.version) {
        reject("rules-version", `version must exceed ${state.rules.version}`);
      }
      state.rules = cloneJson<Rules>(body.rules);
      state.rulesHistory?.push({ seq, rules: cloneJson<Rules>(body.rules) });
      return;
    }

    default: {
      const unreachable: never = body;
      return reject("malformed", `unhandled kind ${String((unreachable as { kind: unknown }).kind)}`);
    }
  }

  // Shared by review and attestation commits: never by an author's owner, one
  // commit per owner (one person running several agents must not fill several
  // seats), at least the rules' review stake, and only while the outcome is
  // still hidden. Once a verdict is revealed, a plant is revealed or a finding
  // reproduces, a late commit could copy the answer.
  function checkCommit(existing: ReviewState[], authors: Set<OwnerId>, commitment: string, stake: number, closedBy: string | null): void {
    const mine = ownerOf(signer);
    if (mine !== undefined && authors.has(mine)) reject("same-owner", "cannot review your owner's work");
    if (existing.some((r) => r.reviewer === signer)) reject("duplicate-commit", "already committed");
    // Commitments bind the reviewer (review.commitmentFor), so a copy could
    // never be revealed; refusing it also keeps a copier from holding a seat.
    if (existing.some((r) => r.commitment === commitment)) reject("duplicate-commit", "that commitment is already posted");
    if (existing.some((r) => ownerOf(r.reviewer) === mine)) {
      reject("duplicate-commit", "another agent of this owner already committed");
    }
    if (closedBy !== null) reject("commit-closed", `commits are closed: ${closedBy}`);
    if (stake < state.rules.stake.review) reject("stake", `review stake below ${state.rules.stake.review}`);
  }

  function ownerSet(submissionIds: readonly string[]): Set<OwnerId> {
    const owners = new Set<OwnerId>();
    for (const sid of submissionIds) {
      const o = ownerOf(state.submissions.get(sid)?.author ?? "");
      if (o !== undefined) owners.add(o);
    }
    return owners;
  }

  // The snapshot and its ancestors, newest first. With `stopAtPromoted`, the
  // walk ends before the first promoted ancestor: that is what a promotion of
  // `snap` would cover. Ids are unique and a snapshot can only name an earlier
  // one, so the chain is finite.
  function ancestry(snap: SnapshotState, stopAtPromoted: boolean): SnapshotState[] {
    const out = [snap];
    for (let p = snap.previousSnapshotId; p !== null; ) {
      const prev = state.snapshots.get(p);
      if (!prev || (stopAtPromoted && prev.promoted)) break;
      out.push(prev);
      p = prev.previousSnapshotId;
    }
    return out;
  }

  function covered(snap: SnapshotState): string[] {
    return ancestry(snap, true).flatMap((x) => x.submissionIds);
  }

  function targets(f: FindingState, snap: SnapshotState, submissionIds: readonly string[]): boolean {
    const t = f.target;
    return "snapshotId" in t ? t.snapshotId === snap.id : submissionIds.includes(t.submissionId);
  }

  function checkReveal(
    existing: ReviewState[],
    verdict: ReviewVerdict,
    salt: string,
    subject: CommitSubject,
  ): ReviewState {
    const review = existing.find((r) => r.reviewer === signer) ?? reject("no-commit", "no earlier commit by signer");
    if (review.verdict) reject("already-revealed", "already revealed");
    const problems = verdictProblems(verdict);
    if (problems.length > 0) reject("invalid-verdict", problems.join("; "));
    if (commitmentFor(verdict, salt, signer, subject) !== review.commitment) {
      reject("commitment-mismatch", "verdict and salt do not match the commitment");
    }
    // finding() refuses an unknown id (unknown-ref) before the target rule.
    for (const fid of verdict.findingIds) {
      const problem = citedFindingProblems((f) => finding(f).target, [fid], subject)[0];
      if (problem !== undefined) reject("invalid-target", problem);
    }
    return review;
  }
}

const settlementKey = (b: { owner: OwnerId; reason: string; ref: string }) => `${b.owner}\u0000${b.reason}\u0000${b.ref}`;
const settledKeyCache = new WeakMap<CommonsState, Set<string>>();

// The settled (owner, reason, ref) keys, cached per state object and rebuilt
// whenever it no longer matches state.settlements (a clone, a hand-built state).
function settledKeys(state: CommonsState): Set<string> {
  let keys = settledKeyCache.get(state);
  if (!keys || keys.size !== state.settlements.length) {
    keys = new Set(state.settlements.map(settlementKey));
    settledKeyCache.set(state, keys);
  }
  return keys;
}

// Why review commits on the submission are closed at `atMs`, or null while
// they are open. The ledger's reviewCommit rule; the server's assignment list
// asks the same. Commits close at the end of the commit phase (commitHours
// after the assignment), at the first reveal (which the commit phase holds
// back until every assigned reviewer committed or the phase ended), at a plant
// reveal, or while a reproduction nobody dismissed stands: a later commit
// could copy the answer.
// `reviewer` matters for an escalated seat: its round has its own commit
// phase, which opens after earlier reveals are public.
export function reviewCommitsClosedBy(state: CommonsState, submissionId: string, atMs: number, reviewer?: KeyId): string | null {
  const s = state.submissions.get(submissionId);
  if (!s) return "no such submission";
  if (s.merged) return "the submission merged";
  const escalated = reviewer === undefined ? undefined : s.escalations?.find((r) => r.reviewers.includes(reviewer));
  if (escalated) {
    if (atMs >= commitDeadlineMs(state.rules, escalated.at)) return `round ${escalated.round}'s commit phase ended`;
    if (escalated.reviewers.some((k) => s.reviews.some((r) => r.reviewer === k && r.verdict))) return `a review of round ${escalated.round} was revealed`;
  } else {
    if (s.assignment && atMs >= commitDeadlineMs(state.rules, s.assignment.at)) return "the commit phase ended";
    if (s.reviews.some((r) => r.verdict)) return "a review was revealed";
  }
  if (s.planted) return "the plant was revealed";
  const open = s.findingIds.some((fid) => {
    const f = state.findings.get(fid);
    return f !== undefined && isReproducedOpen(f);
  });
  return open ? "a finding on it reproduced" : null;
}

// ---------------------------------------------------------------------------
// File-backed ledger: one JSON entry per line, each line newline-terminated.
// ---------------------------------------------------------------------------

export class Ledger {
  private constructor(
    readonly path: string,
    private list: LedgerEntry[],
    private current: LedgerState,
    private bytes: number,
  ) {}

  // Never overwrites: an existing file at `path` is an error.
  static create(path: string, genesisBody: GenesisBody, at: string): Ledger {
    const genesis = genesisEntry(genesisBody, at);
    const state = emptyState(genesis);
    const line = `${JSON.stringify(genesis)}\n`;
    try {
      fs.writeFileSync(path, line, { flag: "wx" });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "EEXIST") throw new LedgerError("exists", `${path} already exists`);
      throw e;
    }
    return new Ledger(path, [genesis], state, Buffer.byteLength(line));
  }

  // Replays and validates every line; a corrupt, truncated or tampered file throws.
  // Drops an unterminated last line (a write interrupted by a crash or a full
  // disk), under the lock, and only when everything before it replays: a
  // complete entry is never dropped, and a file damaged anywhere else is left
  // alone (it throws). Returns the number of bytes dropped (0: nothing torn).
  static repair(path: string): number {
    return withFileLock(path, () => {
      const text = fs.readFileSync(path, "utf8");
      if (text.endsWith("\n")) return 0;
      const keep = text.lastIndexOf("\n") + 1;
      if (keep === 0) throw new LedgerError("torn", "no complete entry before the torn line; not a ledger to repair");
      replay(parseLines(text.slice(0, keep)));
      const bytes = Buffer.byteLength(text.slice(0, keep));
      fs.truncateSync(path, bytes);
      return Buffer.byteLength(text) - bytes;
    });
  }

  static open(path: string): Ledger {
    const text = withFileLock(path, () => fs.readFileSync(path, "utf8"), LOCK_WAIT_STEPS, true);
    const entries = parseLines(text);
    return new Ledger(path, entries, replay(entries), Buffer.byteLength(text));
  }

  entries(): readonly LedgerEntry[] {
    return this.list;
  }

  // Catches up with entries another writer appended to the file since this
  // instance read it (an operator's local `commons task`, say, while `serve`
  // holds the ledger). The file must extend what this instance holds; a
  // rewritten, truncated or torn file throws and leaves this instance as it
  // was. Returns whether anything was read. Writers in other processes are
  // serialised by the file lock (withFileLock): a write signed against an old
  // head fails as stale and is re-signed against the new one, and two writers
  // never both append the same seq.
  refresh(): boolean {
    const text = withFileLock(this.path, () => {
      let size: number;
      try {
        size = fs.statSync(this.path).size;
      } catch {
        throw new LedgerError("stale", `${this.path} is gone`);
      }
      return size === this.bytes ? null : fs.readFileSync(this.path, "utf8");
    }, LOCK_WAIT_STEPS, true);
    if (text === null) return false;
    const entries = parseLines(text);
    const known = this.list.length;
    if (entries.length < known || entries[known - 1]?.hash !== this.list[known - 1]?.hash) {
      throw new LedgerError("stale", `${this.path} no longer extends the ledger this process read`);
    }
    try {
      for (let i = known; i < entries.length; i++) applyEntry(this.current, entries[i] as LedgerEntry);
    } catch (e) {
      this.current = replay(this.list);
      throw e;
    }
    this.list = entries;
    this.bytes = Buffer.byteLength(text);
    return true;
  }

  state(): CommonsState {
    return this.current;
  }

  // Writes the writer's own entry: the writer is the clock, so `at` is trusted.
  append(body: EntryBody, signer: Signer, at: string): LedgerEntry {
    return this.write(signEntry(this.current, body, signer, at));
  }

  // For entries signed elsewhere (an agent signs, the coordinator appends).
  // The signer chose `at`, and replay judges claims, expiry and the
  // no-backwards rule by it, so it must lie within `maxSkewMs` of the
  // writer's clock `now` (both directions: far-future freezes the ledger and
  // expires every claim, backdating revives an expired one). Then validates
  // against the current state; only a valid entry is written. `clock` is
  // optional only for callers that already enforce the same bound (server.ts);
  // anything else appending a foreign entry must pass it.
  appendSigned(entry: LedgerEntry, clock?: { now: string; maxSkewMs?: number }): LedgerEntry {
    if (clock === undefined) return this.write(entry);
    const now = Date.parse(clock.now);
    const skew = clock.maxSkewMs ?? DEFAULT_MAX_SKEW_MS;
    const at = isPlainObject(entry) && typeof entry.at === "string" ? Date.parse(entry.at) : Number.NaN;
    if (Number.isNaN(now)) throw new TypeError("appendSigned: clock.now is not a time");
    if (!(Math.abs(at - now) <= skew)) {
      throw new LedgerError("clock-skew", `at must be within ${skew / 1000}s of ${clock.now}`, null);
    }
    return this.write(entry);
  }

  // The size check, the validation and the append happen under the file
  // lock, so no other process can append between them.
  private write(entry: LedgerEntry): LedgerEntry {
    return withFileLock(this.path, () => this.writeLocked(entry));
  }

  private writeLocked(entry: LedgerEntry): LedgerEntry {
    if (!fs.existsSync(this.path) || fs.statSync(this.path).size !== this.bytes) {
      throw new LedgerError("stale", `${this.path} changed on disk since it was opened`);
    }
    let line: string;
    try {
      line = `${JSON.stringify(entry)}\n`;
    } catch {
      throw new LedgerError("malformed", "entry is not serialisable");
    }
    // Validate the form that will be read back, not the caller's object.
    const stored = JSON.parse(line) as LedgerEntry;
    applyEntry(this.current, stored);
    try {
      fs.appendFileSync(this.path, line);
    } catch (e) {
      this.current = replay(this.list); // the write failed: undo the in-memory apply
      // A write that failed part way (ENOSPC) left an unterminated fragment,
      // and every later read would refuse the file as torn. Still holding the
      // lock, cut the file back to what was read. If even that fails, the
      // fragment stays: see `Ledger.repair`.
      try {
        fs.truncateSync(this.path, this.bytes);
      } catch {
        // reported by the next read as "torn"
      }
      throw e;
    }
    this.list.push(stored);
    this.bytes += Buffer.byteLength(line);
    return stored;
  }
}

// ---------------------------------------------------------------------------
// Cross-process lock. Every process that touches the ledger file (serve, the
// coordinator loop, a local `commons approve` or `task`) goes through a Ledger
// instance, and every Ledger reads and appends only while it holds
// `<ledger>.lock`. Without it two processes can both see the file unchanged
// and both append, leaving two entries with one seq: a ledger no replay
// accepts. The lock is taken atomically (a hard link to a file that already
// holds our pid), held for one synchronous read or write, then removed. A lock
// whose pid no longer runs was left by a crash and is broken. Same host only
// (pids, not hosts), which is how the coordinator runs; a ledger shared over a
// network filesystem by several hosts is not supported.
// ---------------------------------------------------------------------------

export const LOCK_WAIT_STEPS = 2000; // x LOCK_STEP_MS: about 10 s, then "locked"
const LOCK_STEP_MS = 5;
const sleeper = new Int32Array(new SharedArrayBuffer(4));

export const lockPathOf = (ledgerPath: string): string => `${ledgerPath}.lock`;

// `forRead`: a reader that cannot create files next to the ledger (a
// read-only mount, another user's directory) reads without the lock; it can
// corrupt nothing, and at worst meets a half-written last line ("torn").
export function withFileLock<T>(ledgerPath: string, fn: () => T, waitSteps = LOCK_WAIT_STEPS, forRead = false): T {
  const lock = lockPathOf(ledgerPath);
  const mine = `${lock}.${process.pid}`;
  try {
    fs.writeFileSync(mine, String(process.pid));
  } catch (e) {
    if (forRead && ["EACCES", "EPERM", "EROFS"].includes((e as NodeJS.ErrnoException).code ?? "")) return fn();
    throw e;
  }
  try {
    for (let step = 0; ; step++) {
      try {
        fs.linkSync(mine, lock); // atomic: fails while anyone holds the lock
        break;
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
      }
      breakIfStale(lock);
      if (step >= waitSteps) {
        throw new LedgerError("locked", `${lock} is held by another process; if none is running, remove it`);
      }
      Atomics.wait(sleeper, 0, 0, LOCK_STEP_MS); // a synchronous sleep, no clock read
    }
  } finally {
    fs.rmSync(mine, { force: true });
  }
  try {
    return fn();
  } finally {
    fs.rmSync(lock, { force: true });
  }
}

// Removes the lock if the pid in it no longer runs. It re-reads the file just
// before removing it, so a lock a live writer took meanwhile is left alone
// (two processes breaking one crashed writer's lock in the same microsecond
// remain a theoretical race).
function breakIfStale(lock: string): void {
  const holder = readLockPid(lock);
  if (holder === null || pidRuns(holder)) return;
  if (readLockPid(lock) === holder) fs.rmSync(lock, { force: true });
}

function readLockPid(lock: string): number | null {
  try {
    const pid = Number(fs.readFileSync(lock, "utf8"));
    return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

function pidRuns(pid: number): boolean {
  // Ledger calls are synchronous, so this thread never meets a lock it holds:
  // one with our own pid is a leftover.
  if (pid === process.pid) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM"; // it runs, as another user
  }
}

export function parseLines(text: string): LedgerEntry[] {
  if (text === "") throw new LedgerError("genesis", "empty ledger file");
  if (!text.endsWith("\n")) {
    throw new LedgerError("torn", "last line is not terminated (interrupted write?); `commons ledger repair` drops it once the rest replays");
  }
  return text
    .slice(0, -1)
    .split("\n")
    .map((line, i) => {
      if (line === "") throw new LedgerError("malformed", `line ${i + 1} is empty`, i);
      try {
        return JSON.parse(line) as LedgerEntry;
      } catch {
        throw new LedgerError("malformed", `line ${i + 1} is not JSON`, i);
      }
    });
}
