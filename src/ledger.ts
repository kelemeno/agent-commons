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
import { claimStake, ringOf, validateRules } from "./rules";
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
  // file
  | "exists"
  | "torn"
  | "stale";

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

// Longest a single claim entry may run. A cap is what stops one agent from
// locking a task forever for a token stake. It belongs in Rules (claim.maxHours);
// until types.ts has that field it is fixed here.
export const MAX_CLAIM_MS = 7 * 24 * 3_600_000;

// Default tolerance between an entry's `at` and the writer's clock.
export const DEFAULT_MAX_SKEW_MS = 5 * 60_000;

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

const any: Check = () => true;
const str: Check = (v) => typeof v === "string";
const id: Check = (v) => typeof v === "string" && v.length > 0;
const idOrNull: Check = (v) => v === null || id(v);
const int: Check = (v) => Number.isSafeInteger(v);
const nat: Check = (v) => Number.isSafeInteger(v) && (v as number) >= 0;
const bool: Check = (v) => typeof v === "boolean";
const array: Check = (v) => Array.isArray(v);
const strings: Check = (v) => Array.isArray(v) && v.every(str);
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
const SHAPES: { [K in EntryKind]: Record<string, Check> } = {
  genesis: { project: id, admins: strings, coordinator: str, rules: any },
  ownerKey: { owner: id, publicKey: str, inviter: idOrNull },
  agentRegistered: { owner: id, publicKey: str, modelFamily: id, harness: str },
  agentRevoked: { agent: id, reason: str },
  proposal: { id, title: id, evidence: array },
  task: { id, proposalId: id, ring, acceptanceTestPaths: strings, sizeEstimate: nat, specAuthor: id },
  claim: { taskId: id, until: iso, stake: int },
  submission: { id, taskId: idOrNull, baseCommit: id, headCommit: id, changedFiles: strings, linesChanged: int },
  gateResult: { submissionId: id, gate: id, pass: bool, details: str },
  reviewAssignment: { submissionId: id, beacon: id, reviewers: strings },
  reviewCommit: { submissionId: id, commitment: hex64, stake: int },
  reviewReveal: { submissionId: id, verdict: any, salt: id },
  finding: { id, target, severity, testPath: id, testCommand: id, stake: int },
  findingResult: { findingId: id, reproduced: bool, failsOnHead: bool, passesOnParent: bool, logDigest: str },
  merge: { submissionId: id, commit: id },
  snapshot: { id, commit: id, previousSnapshotId: idOrNull, submissionIds: strings },
  attestCommit: { snapshotId: id, commitment: hex64, stake: int },
  attestReveal: { snapshotId: id, verdict: any, salt: id },
  signoff: { snapshotId: id },
  promotion: { snapshotId: id, commit: id },
  plantCommit: { commitment: hex64 },
  plantReveal: { submissionId: id, salt: id, description: str, severity },
  honeytokenTriggered: { agent: id, tokenId: id },
  escape: { findingId: id, snapshotId: id },
  settlement: { owner: id, delta: int, reason, ref: str },
  rulesChange: { rules: any, pollId: id },
};

// `planted` may appear on a submission only so that the "authors may not set
// planted" rule can reject it with its own code instead of a shape error.
const OPTIONAL: Partial<Record<EntryKind, readonly string[]>> = { submission: ["planted"] };

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
function fieldProblem(o: Record<string, unknown>, fields: Record<string, Check>, optional: readonly string[] = []) {
  for (const [name, check] of Object.entries(fields)) {
    if (!Object.hasOwn(o, name) || o[name] === undefined) return `missing field ${name}`;
    if (!check(o[name])) return `bad field ${name}`;
  }
  for (const key of definedKeys(o)) {
    if (!Object.hasOwn(fields, key) && !optional.includes(key)) return `unknown field ${key}`;
  }
  return null;
}

// A repo-relative POSIX path in its one spelling. Ring and airlock globs are
// anchored, so `./a`, `a//b` or `a/../b` would dodge them while naming the same file.
export function isCanonicalPath(p: unknown): p is string {
  if (typeof p !== "string" || p === "" || p.includes("\\") || p.includes("\0")) return false;
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
      return fieldProblem(e, { kind: str, testId: id, command: id });
    case "diagnostic":
      return fieldProblem(e, { kind: str, tool: id, message: id, file: id, line });
    case "location":
      return fieldProblem(e, { kind: str, file: id, line, note: str });
    default:
      return `unknown evidence kind ${String(e.kind)}`;
  }
}

function verdictProblem(v: unknown): string | null {
  if (!isPlainObject(v)) return "verdict is not an object";
  const problem = fieldProblem(v, { defectProbability: any, summary: str, findingIds: strings });
  if (problem) return problem;
  const p = v.defectProbability;
  if (typeof p !== "number" || !Number.isFinite(p) || p < 0 || p > 1) return "defectProbability must be in [0, 1]";
  const ids = v.findingIds as string[];
  if (ids.some((x) => x === "")) return "empty finding id";
  if (new Set(ids).size !== ids.length) return "duplicate finding id";
  return null;
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
    adminKeys,
    coordinatorKey: keyIdOf(body.coordinator),
    publicKeys,
    owners: new Map(),
    ownerByKey: new Map(),
    agents: new Map(),
    proposals: new Map(),
    tasks: new Map(),
    claims: new Map(),
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
// merges, a review commit until its submission merges, an attestation until
// its snapshot is promoted, a finding until its result is recorded.
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
  for (const s of state.submissions.values()) if (!s.merged) for (const r of s.reviews) add(r.reviewer, r.stake);
  for (const s of state.snapshots.values()) if (!s.promoted) for (const a of s.attestations) add(a.reviewer, a.stake);
  for (const f of state.findings.values()) if (!f.result) add(f.finder, f.stake);
}

function headAtOf(state: CommonsState): string {
  return (state as Partial<LedgerState>).headAt ?? EPOCH;
}

// ---------------------------------------------------------------------------
// Applying one entry.
// ---------------------------------------------------------------------------

type Role = "admin" | "coordinator" | "owner" | "agent" | "agentOrOwner" | "ownerOrCoordinator";

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
  reviewCommit: "agent",
  reviewReveal: "agent",
  finding: "agent",
  findingResult: "coordinator",
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
      const keyId = newKey(body.publicKey);
      if (body.inviter !== null && !state.owners.has(body.inviter)) reject("unknown-ref", `no inviter ${body.inviter}`);
      state.publicKeys.set(keyId, body.publicKey);
      state.owners.set(body.owner, { id: body.owner, keyId, inviter: body.inviter, reputationDelta: 0, lockedStake: 0 });
      state.ownerByKey.set(keyId, body.owner);
      return;
    }

    case "agentRegistered": {
      const owner = state.owners.get(body.owner) ?? reject("unknown-ref", `no owner ${body.owner}`);
      if (owner.keyId !== signer) reject("unauthorised", "only the named owner may register its agents");
      const keyId = newKey(body.publicKey);
      state.publicKeys.set(keyId, body.publicKey);
      state.agents.set(keyId, {
        keyId,
        owner: body.owner,
        modelFamily: body.modelFamily,
        harness: body.harness,
        active: true,
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
      for (const s of state.submissions.values()) {
        if (s.taskId === body.taskId && s.merged) reject("task-done", `task ${body.taskId} already merged`);
      }
      const current = state.claims.get(body.taskId);
      // The holder may extend its own claim (each extension capped like a new
      // claim); anyone else waits for expiry. A revoked holder's claim is dead:
      // revocation must not leave the task locked.
      if (
        current &&
        current.agent !== signer &&
        Date.parse(current.until) > ms &&
        state.agents.get(current.agent)?.active === true
      ) {
        reject("claim-live", `task ${body.taskId} is claimed until ${current.until}`);
      }
      state.claims.set(body.taskId, { taskId: body.taskId, agent: signer, until: body.until, stake: body.stake, seq });
      return;
    }

    case "submission": {
      if (body.planted !== undefined) reject("planted-by-author", "authors may not set planted");
      if (state.submissions.has(body.id)) reject("duplicate-id", `submission ${body.id} exists`);
      if (body.taskId !== null) {
        if (!state.tasks.has(body.taskId)) reject("unknown-ref", `no task ${body.taskId}`);
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
      }
      s.assignment = { beacon: body.beacon, reviewers: [...body.reviewers], seq };
      return;
    }

    case "reviewCommit": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      const closedBy = s.reviews.some((r) => r.verdict)
        ? "a review was revealed"
        : s.planted
          ? "the plant was revealed"
          : s.findingIds.some((fid) => state.findings.get(fid)?.result?.reproduced === true)
            ? "a finding on it reproduced"
            : null;
      checkCommit(s.reviews, ownerSet([s.id]), body.stake, closedBy);
      s.reviews.push({ reviewer: signer, commitment: body.commitment, stake: body.stake, committedSeq: seq });
      return;
    }

    case "reviewReveal": {
      const s = submission(body.submissionId);
      const review = checkReveal(s.reviews, body.verdict, body.salt, (fid) => {
        const f = finding(fid);
        return "submissionId" in f.target && f.target.submissionId === s.id;
      });
      review.verdict = cloneJson(body.verdict);
      review.revealedSeq = seq;
      return;
    }

    case "finding": {
      if (state.findings.has(body.id)) reject("duplicate-id", `finding ${body.id} exists`);
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
      f.result = {
        reproduced: body.reproduced,
        failsOnHead: body.failsOnHead,
        passesOnParent: body.passesOnParent,
        logDigest: body.logDigest,
        seq,
      };
      return;
    }

    case "merge": {
      const s = submission(body.submissionId);
      if (s.merged) reject("merged", "submission already merged");
      if (s.gates.length === 0) reject("gates-missing", "no gate results recorded");
      const failed = s.gates.find((g) => !g.pass);
      if (failed) reject("gate-failed", `gate ${failed.gate} failed`);
      if (s.findingIds.some((fid) => state.findings.get(fid)?.result?.reproduced === true)) {
        reject("reproduced-finding", "a reproduced finding targets this submission");
      }
      // Undecided is not clean: merging before the harness answers would get
      // past the reproduced-finding rule by timing alone.
      if (s.findingIds.some((fid) => !state.findings.get(fid)?.result)) {
        reject("finding-pending", "a finding on this submission has no result yet");
      }
      if (s.planted) reject("planted", "a revealed plant is a known defect");
      s.merged = { commit: body.commit, seq, at };
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
      const closedBy = snap.attestations.some((a) => a.verdict)
        ? "an attestation was revealed"
        : subs.some((sid) => state.submissions.get(sid)?.planted)
          ? "a plant it covers was revealed"
          : [...state.findings.values()].some((f) => f.result?.reproduced === true && chain.some((x) => targets(f, x, subs)))
            ? "a finding on it reproduced"
            : null;
      checkCommit(snap.attestations, ownerSet(subs), body.stake, closedBy);
      snap.attestations.push({ reviewer: signer, commitment: body.commitment, stake: body.stake, committedSeq: seq });
      return;
    }

    case "attestReveal": {
      const snap = snapshot(body.snapshotId);
      const attestation = checkReveal(snap.attestations, body.verdict, body.salt, (fid) => {
        const f = finding(fid);
        return "snapshotId" in f.target && f.target.snapshotId === snap.id;
      });
      attestation.verdict = cloneJson(body.verdict);
      attestation.revealedSeq = seq;
      return;
    }

    case "signoff": {
      const snap = snapshot(body.snapshotId);
      const owner = state.ownerByKey.get(signer) ?? reject("unauthorised", "signer is not an owner");
      if (!state.rules.kernelSigners.includes(owner)) reject("unauthorised", `${owner} is not a kernel signer`);
      if (snap.promoted) reject("promoted", "snapshot already promoted");
      if (ownerSet(covered(snap)).has(owner)) reject("same-owner", "cannot sign off a snapshot of your own agents' work");
      if (snap.signoffs.includes(owner)) reject("duplicate-signoff", `${owner} already signed off`);
      snap.signoffs.push(owner);
      return;
    }

    case "promotion": {
      const snap = snapshot(body.snapshotId);
      if (snap.promoted) reject("promoted", "snapshot already promoted");
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
      const commitment = sha256hex(`${body.submissionId}:${body.salt}`);
      const commit = state.plantCommitments.find((c) => c.commitment === commitment);
      if (!commit) return reject("plant-mismatch", "no plant commitment matches");
      // The commitment must predate the submission; otherwise the custodian
      // could label any submission a plant after seeing who caught it.
      if (commit.seq > s.submittedSeq) reject("plant-late", "plant committed after the submission");
      s.planted = { severity: body.severity, description: body.description };
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
      owner.reputationDelta += body.delta;
      state.settlements.push({ owner: body.owner, delta: body.delta, reason: body.reason, ref: body.ref, seq, at });
      return;
    }

    case "rulesChange": {
      const problems = validateRules(body.rules);
      if (problems.length > 0) reject("invalid-rules", problems.join("; "));
      if (body.rules.version <= state.rules.version) {
        reject("rules-version", `version must exceed ${state.rules.version}`);
      }
      state.rules = cloneJson<Rules>(body.rules);
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
  function checkCommit(existing: ReviewState[], authors: Set<OwnerId>, stake: number, closedBy: string | null): void {
    const mine = ownerOf(signer);
    if (mine !== undefined && authors.has(mine)) reject("same-owner", "cannot review your owner's work");
    if (existing.some((r) => r.reviewer === signer)) reject("duplicate-commit", "already committed");
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
    targetsHere: (findingId: string) => boolean,
  ): ReviewState {
    const review = existing.find((r) => r.reviewer === signer) ?? reject("no-commit", "no earlier commit by signer");
    if (review.verdict) reject("already-revealed", "already revealed");
    const problem = verdictProblem(verdict);
    if (problem) reject("invalid-verdict", problem);
    if (sha256hex(canonical(verdict) + salt) !== review.commitment) {
      reject("commitment-mismatch", "verdict and salt do not match the commitment");
    }
    for (const fid of verdict.findingIds) {
      if (!targetsHere(fid)) reject("invalid-target", `finding ${fid} does not target this review's subject`);
    }
    return review;
  }
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
  static open(path: string): Ledger {
    const text = fs.readFileSync(path, "utf8");
    const entries = parseLines(text);
    return new Ledger(path, entries, replay(entries), Buffer.byteLength(text));
  }

  entries(): readonly LedgerEntry[] {
    return this.list;
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

  private write(entry: LedgerEntry): LedgerEntry {
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
      throw e;
    }
    this.list.push(stored);
    this.bytes += Buffer.byteLength(line);
    return stored;
  }
}

export function parseLines(text: string): LedgerEntry[] {
  if (text === "") throw new LedgerError("genesis", "empty ledger file");
  if (!text.endsWith("\n")) throw new LedgerError("torn", "last line is not terminated (interrupted write?)");
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
