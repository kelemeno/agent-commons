import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { spawn } from "node:child_process";
import { canonical, generateKeyPair, keyIdOf, sha256hex, sign } from "../src/crypto";
import {
  applyEntry,
  emptyState,
  entryHash,
  entryMessage,
  genesisEntry,
  ID_RE,
  isCanonicalPath,
  LEDGER_LIMITS,
  Ledger,
  LedgerError,
  MAX_CLAIM_MS,
  type LedgerErrorCode,
  type GenesisBody,
  type LedgerState,
  replay,
  signEntry,
  type Signer,
  submissionDead,
  withFileLock,
} from "../src/ledger";
import { defaultRules } from "../src/rules";
import type { EntryBody, LedgerEntry, ReviewVerdict, Rules } from "../src/types";
import { assignmentBeacon, type CommitSubject, commitmentFor } from "../src/review";
import { assignmentBody } from "../src/selection";
import { memberDigest } from "../src/members";

// ---------------------------------------------------------------------------
// Fixture: an in-memory ledger with a fake clock. Every append advances the
// clock by one minute unless a time is given.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();

function isCode(code: LedgerErrorCode) {
  return (e: unknown) => {
    assert.ok(e instanceof LedgerError, `expected LedgerError, got ${String(e)}`);
    assert.equal(e.code, code, e.message);
    return true;
  };
}

class World {
  admin = generateKeyPair();
  coord = generateKeyPair();
  keys = new Map<string, Signer>();
  minute = 0;
  genesis: LedgerEntry;
  state: LedgerState;
  entries: LedgerEntry[];

  constructor(rules: Rules = { ...defaultRules(), kernelSigners: ["carol", "dave"] }) {
    this.genesis = genesisEntry(this.genesisBody(rules), iso(0));
    this.state = emptyState(this.genesis);
    this.entries = [this.genesis];
  }

  genesisBody(rules: Rules): GenesisBody {
    return { kind: "genesis", project: "demo", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules };
  }

  now(): string {
    return iso(this.minute);
  }

  key(name: string): Signer {
    let k = this.keys.get(name);
    if (!k) {
      k = generateKeyPair();
      this.keys.set(name, k);
    }
    return k;
  }

  id(name: string): string {
    return keyIdOf(this.key(name).publicKey);
  }

  sign(body: EntryBody, signer: Signer, at?: string): LedgerEntry {
    if (at === undefined) this.minute += 1;
    else this.minute = Math.max(this.minute, (Date.parse(at) - T0) / 60_000);
    return signEntry(this.state, body, signer, at ?? this.now());
  }

  apply(body: EntryBody, signer: Signer, at?: string): LedgerEntry {
    const e = this.sign(body, signer, at);
    applyEntry(this.state, e);
    this.entries.push(e);
    return e;
  }

  // The entry must be rejected with `code`, and the state must be untouched.
  reject(code: LedgerErrorCode, body: EntryBody, signer: Signer, at?: string): void {
    this.rejectEntry(code, this.sign(body, signer, at));
  }

  rejectEntry(code: LedgerErrorCode, entry: LedgerEntry): void {
    const before = structuredClone(this.state);
    assert.throws(() => applyEntry(this.state, entry), isCode(code));
    assert.deepStrictEqual(this.state, before, "a rejected entry must not change the state");
  }

  // owners alice, bob, carol, dave; agents a1 + a2 (alice), b1, c1, d1
  people(): this {
    this.apply({ kind: "ownerKey", owner: "alice", publicKey: this.key("alice").publicKey, inviter: null }, this.admin);
    for (const o of ["bob", "carol", "dave"]) {
      this.apply({ kind: "ownerKey", owner: o, publicKey: this.key(o).publicKey, inviter: "alice" }, this.admin);
    }
    const agents: [string, string, string][] = [
      ["a1", "alice", "claude"],
      ["a2", "alice", "gpt"],
      ["b1", "bob", "gpt"],
      ["c1", "carol", "qwen"],
      ["d1", "dave", "kimi"],
    ];
    for (const [agent, owner, modelFamily] of agents) {
      this.apply(
        { kind: "agentRegistered", owner, publicKey: this.key(agent).publicKey, modelFamily, harness: "cli" },
        this.key(owner),
      );
    }
    return this;
  }

  // proposal p1, task t1 (spec by bob), a1 claims it for 10 hours
  task(): this {
    this.people();
    this.apply({ kind: "proposal", id: "p1", title: "fix", evidence: [EVIDENCE] }, this.key("a1"));
    this.apply(taskBody("t1"), this.coord);
    this.apply({ kind: "claim", taskId: "t1", until: iso(this.minute + 600), stake: 10 }, this.key("a1"));
    return this;
  }

  // a1 submits s1 for t1
  submitted(): this {
    this.task();
    this.apply(submissionBody("s1", "t1"), this.key("a1"));
    return this;
  }

  // s1 passes a gate, gets a reviewer (b1; the ledger merges nothing
  // unassigned) and merges
  merged(): this {
    this.submitted();
    this.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, this.coord);
    this.assign("s1", ["b1"]);
    this.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, this.coord);
    return this;
  }

  assign(sid: string, reviewers: string[]): void {
    this.apply(assignmentBody(this.state, sid, reviewers.map((r) => this.id(r)), "e"), this.coord);
  }

  // Past the commit phase of everything assigned or snapshotted so far.
  afterCommitPhase(): void {
    this.minute += this.state.rules.review.commitHours * 60 + 1;
  }

  // snapshot r1 containing s1
  snapshotted(): this {
    this.merged();
    this.apply({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, this.coord);
    return this;
  }

  owner(name: string) {
    const o = this.state.owners.get(name);
    assert.ok(o, name);
    return o;
  }
}

const EVIDENCE = { kind: "failingTest", testId: "engine.vote", command: "npm test" } as const;

function taskBody(id: string, over: Partial<Extract<EntryBody, { kind: "task" }>> = {}): EntryBody {
  return {
    kind: "task",
    id,
    proposalId: "p1",
    ring: 1,
    acceptanceTestPaths: ["test/accept.test.ts"],
    sizeEstimate: 50,
    specAuthor: "bob",
    ...over,
  };
}

function submissionBody(id: string, taskId: string | null, over: Record<string, unknown> = {}): EntryBody {
  return {
    kind: "submission",
    id,
    taskId,
    baseCommit: "base",
    headCommit: `head-${id}`,
    changedFiles: ["server/src/routes.ts"],
    linesChanged: 20,
    ...over,
  } as EntryBody;
}

const verdict = (p = 0.1, findingIds: string[] = []): ReviewVerdict => ({ defectProbability: p, summary: "ok", findingIds });
// A commitment binds the reviewer and the subject (review.commitmentFor).
const commitOf = (v: ReviewVerdict, salt: string, reviewer: string, subject: CommitSubject) => commitmentFor(v, salt, reviewer, subject);

function findingBody(id: string, target: { submissionId: string } | { snapshotId: string }, stake = 5): EntryBody {
  return { kind: "finding", id, target, severity: "high", testPath: `test/${id}.test.ts`, testCommand: "npm test", stake };
}

function tmpFile(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ledger-test-"));
  return path.join(dir, "ledger.jsonl");
}

// ---------------------------------------------------------------------------
// Genesis
// ---------------------------------------------------------------------------

test("genesis: admins and coordinator become known keys", () => {
  const w = new World();
  assert.equal(w.state.length, 1);
  assert.equal(w.state.headHash, w.genesis.hash);
  assert.equal(w.state.coordinatorKey, keyIdOf(w.coord.publicKey));
  assert.deepEqual(w.state.adminKeys, [keyIdOf(w.admin.publicKey)]);
  assert.equal(w.state.publicKeys.get(keyIdOf(w.admin.publicKey)), w.admin.publicKey);
  assert.equal(w.state.project, "demo");
});

test("genesis: emptyState also accepts a bare body", () => {
  const w = new World();
  const s = emptyState(w.genesisBody(defaultRules()));
  assert.equal(s.length, 1);
  assert.equal(s.headHash, genesisEntry(w.genesisBody(defaultRules()), "1970-01-01T00:00:00.000Z").hash);
});

test("genesis: rules are validated", () => {
  const w = new World();
  const bad = { ...defaultRules(), plantRate: 0.9 };
  assert.throws(() => emptyState(genesisEntry(w.genesisBody(bad), iso(0))), isCode("invalid-rules"));
});

test("genesis: keys must be valid and admin keys distinct", () => {
  const w = new World();
  const body = w.genesisBody(defaultRules());
  assert.throws(() => emptyState(genesisEntry({ ...body, coordinator: "junk" }, iso(0))), isCode("invalid-key"));
  assert.throws(() => emptyState(genesisEntry({ ...body, admins: [`${w.admin.publicKey}=`] }, iso(0))), isCode("invalid-key"));
  assert.throws(
    () => emptyState(genesisEntry({ ...body, admins: [w.admin.publicKey, w.admin.publicKey] }, iso(0))),
    isCode("duplicate-key"),
  );
});

test("genesis: must be unsigned, at seq 0, and first", () => {
  const w = new World();
  const body = w.genesisBody(defaultRules());
  const signed = signEntry({ seq: 0, prev: "" }, body, w.admin, iso(0));
  assert.throws(() => emptyState(signed), isCode("genesis"));
  const late = genesisEntry(body, iso(0));
  const relabelled = { ...late, seq: 1 };
  assert.throws(() => emptyState({ ...relabelled, hash: entryHash(relabelled) }), isCode("seq"));
  assert.throws(() => replay([]), isCode("genesis"));
  w.people();
  assert.throws(() => replay(w.entries.slice(1)), isCode("genesis"));
  // a genesis body appended later, even signed by an admin, is refused
  w.reject("genesis", body, w.admin);
});

// ---------------------------------------------------------------------------
// Envelope, chain, signatures
// ---------------------------------------------------------------------------

test("replay rebuilds the same state as incremental application", () => {
  const w = new World().snapshotted();
  assert.deepStrictEqual(replay(w.entries), w.state);
});

test("chain: an entry applied twice is a replay and fails on seq", () => {
  const w = new World().people();
  const e = w.apply({ kind: "proposal", id: "p1", title: "x", evidence: [EVIDENCE] }, w.key("a1"));
  w.rejectEntry("seq", e);
});

test("chain: an entry signed against another ledger fails on prev", () => {
  const w = new World().people();
  const e = signEntry({ seq: w.state.length, prev: "0".repeat(64) }, { kind: "proposal", id: "p", title: "x", evidence: [EVIDENCE] }, w.key("a1"), iso(100));
  w.rejectEntry("prev", e);
});

test("chain: edited body fails the hash check; re-hashed it fails the signature", () => {
  const w = new World().people();
  const e = w.sign({ kind: "settlement", owner: "alice", delta: 5, reason: "bounty", ref: "x" }, w.coord);
  const edited = { ...e, body: { ...e.body, delta: 500 } as EntryBody };
  w.rejectEntry("hash", edited);
  w.rejectEntry("signature", { ...edited, hash: entryHash(edited) });
});

test("chain: time may not go backwards", () => {
  const w = new World().people();
  w.reject("time", { kind: "proposal", id: "p", title: "x", evidence: [EVIDENCE] }, w.key("a1"), iso(0));
  w.apply({ kind: "proposal", id: "p", title: "x", evidence: [EVIDENCE] }, w.key("a1"), w.now()); // equal is fine
});

test("signer: a forged signer id with someone else's signature is rejected", () => {
  const w = new World().people();
  const body: EntryBody = { kind: "settlement", owner: "alice", delta: 1000, reason: "bounty", ref: "forged" };
  const unsigned = { seq: w.state.length, prev: w.state.headHash, at: iso(500), signer: w.state.coordinatorKey, body };
  const withSig = { ...unsigned, sig: sign(w.key("a1").privateKey, entryMessage(unsigned)) };
  w.rejectEntry("signature", { ...withSig, hash: entryHash(withSig) });
});

test("signer: unknown keys and empty signers are rejected", () => {
  const w = new World().people();
  w.reject("signer-unknown", { kind: "proposal", id: "p", title: "x", evidence: [EVIDENCE] }, generateKeyPair());
  const unsigned = { seq: w.state.length, prev: w.state.headHash, at: iso(500), signer: "", body: { kind: "plantCommit", commitment: "0".repeat(64) } as EntryBody };
  const e = { ...unsigned, sig: "" };
  w.rejectEntry("signer-unknown", { ...e, hash: entryHash(e) });
});

test("signer: each kind needs its role", () => {
  const w = new World().task();
  w.reject("unauthorised", taskBody("t2"), w.key("a1")); // agent signing a coordinator kind
  w.reject("unauthorised", taskBody("t2"), w.admin);
  w.reject("unauthorised", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 1 }, w.key("alice")); // owner as agent
  w.reject("unauthorised", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 1 }, w.coord);
  w.reject("unauthorised", { kind: "ownerKey", owner: "eve", publicKey: w.key("eve").publicKey, inviter: null }, w.coord);
  w.reject("unauthorised", { kind: "ownerKey", owner: "eve", publicKey: w.key("eve").publicKey, inviter: null }, w.key("alice"));
  w.reject("unauthorised", { kind: "plantCommit", commitment: "a".repeat(64) }, w.coord);
  w.reject("unauthorised", { kind: "rulesChange", rules: { ...defaultRules(), version: 2 }, pollId: "p" }, w.coord);
  w.reject("unauthorised", { kind: "settlement", owner: "alice", delta: 1, reason: "bounty", ref: "r" }, w.admin);
  w.reject("unauthorised", { kind: "signoff", snapshotId: "r1" }, w.key("c1")); // agent of a kernel signer
});

test("signer: a revoked agent can no longer sign anything", () => {
  const w = new World().people();
  w.apply({ kind: "agentRevoked", agent: w.id("a1"), reason: "lost key" }, w.key("alice"));
  assert.equal(w.state.agents.get(w.id("a1"))?.active, false);
  assert.equal(w.state.agents.get(w.id("a1"))?.revokedReason, "lost key");
  w.reject("signer-revoked", { kind: "proposal", id: "p", title: "x", evidence: [EVIDENCE] }, w.key("a1"));
});

test("shape: unknown kinds, extra fields and wrong types are malformed", () => {
  const w = new World().people();
  w.reject("malformed", { kind: "mint", amount: 5 } as unknown as EntryBody, w.coord);
  w.reject("malformed", { kind: "settlement", owner: "alice", delta: 1, reason: "bounty", ref: "r", extra: 1 } as unknown as EntryBody, w.coord);
  w.reject("malformed", { kind: "settlement", owner: "alice", delta: 1.5, reason: "bounty", ref: "r" }, w.coord);
  w.reject("malformed", { kind: "settlement", owner: "alice", delta: 1, reason: "gift", ref: "r" } as unknown as EntryBody, w.coord);
  w.reject("malformed", ({ ...findingBody("f", { submissionId: "s" }), severity: "huge" } as unknown as EntryBody), w.key("b1"));
  w.reject("malformed", { kind: "reviewCommit", submissionId: "s", commitment: "A".repeat(64), stake: 5 }, w.key("b1"));
  w.rejectEntry("malformed", { ...w.sign({ kind: "plantCommit", commitment: "a".repeat(64) }, w.admin), extra: 1 } as LedgerEntry);
  w.rejectEntry("malformed", { ...w.sign({ kind: "plantCommit", commitment: "a".repeat(64) }, w.admin), at: "yesterday" });
  assert.throws(() => applyEntry(w.state, null as unknown as LedgerEntry), isCode("malformed"));
});

// ---------------------------------------------------------------------------
// Owners and agents
// ---------------------------------------------------------------------------

test("ownerKey: registers owner with inviter", () => {
  const w = new World().people();
  const seq = w.entries.findIndex((e) => e.body.kind === "ownerKey" && e.body.owner === "bob");
  assert.deepEqual(w.owner("bob"), { id: "bob", keyId: w.id("bob"), inviter: "alice", reputationDelta: 0, lockedStake: 0, registeredSeq: seq });
  assert.equal(w.state.ownerByKey.get(w.id("bob")), "bob");
});

test("ownerKey: owner ids and keys are unique; inviter must exist; key must be valid", () => {
  const w = new World().people();
  w.reject("duplicate-id", { kind: "ownerKey", owner: "alice", publicKey: w.key("x").publicKey, inviter: null }, w.admin);
  // One member, two spellings: one owner (selection groups them by tree identity too).
  w.reject("duplicate-id", { kind: "ownerKey", owner: "Alice", publicKey: w.key("x").publicKey, inviter: null }, w.admin);
  w.reject("duplicate-key", { kind: "ownerKey", owner: "eve", publicKey: w.key("alice").publicKey, inviter: null }, w.admin);
  w.reject("duplicate-key", { kind: "ownerKey", owner: "eve", publicKey: w.key("a1").publicKey, inviter: null }, w.admin);
  w.reject("duplicate-key", { kind: "ownerKey", owner: "eve", publicKey: w.coord.publicKey, inviter: null }, w.admin);
  w.reject("unknown-ref", { kind: "ownerKey", owner: "eve", publicKey: w.key("eve").publicKey, inviter: "mallory" }, w.admin);
  w.reject("invalid-key", { kind: "ownerKey", owner: "eve", publicKey: `${w.key("eve").publicKey}=`, inviter: null }, w.admin);
  w.reject("invalid-key", { kind: "ownerKey", owner: "eve", publicKey: "abc", inviter: null }, w.admin);
});

test("agentRegistered: only the named owner may register, key unique, owner must exist", () => {
  const w = new World().people();
  const body = { kind: "agentRegistered", owner: "alice", publicKey: w.key("a3").publicKey, modelFamily: "glm", harness: "x" } as const;
  w.reject("unauthorised", body, w.key("bob"));
  w.reject("duplicate-key", { ...body, publicKey: w.key("b1").publicKey }, w.key("alice"));
  w.reject("duplicate-key", { ...body, publicKey: w.admin.publicKey }, w.key("alice"));
  w.reject("unknown-ref", { ...body, owner: "mallory" }, w.key("alice"));
  w.apply(body, w.key("alice"));
  assert.equal(w.state.agents.get(w.id("a3"))?.owner, "alice");
  assert.equal(w.state.agents.get(w.id("a3"))?.active, true);
});

test("agentRevoked: owner or coordinator only; agent must exist and be active", () => {
  const w = new World().people();
  w.reject("unauthorised", { kind: "agentRevoked", agent: w.id("a1"), reason: "x" }, w.key("bob"));
  w.reject("unknown-ref", { kind: "agentRevoked", agent: "nobody", reason: "x" }, w.key("alice"));
  w.apply({ kind: "agentRevoked", agent: w.id("b1"), reason: "suspended" }, w.coord);
  w.reject("inactive-agent", { kind: "agentRevoked", agent: w.id("b1"), reason: "again" }, w.key("bob"));
  // a revoked agent's key stays reserved
  w.reject("duplicate-key", { kind: "agentRegistered", owner: "bob", publicKey: w.key("b1").publicKey, modelFamily: "gpt", harness: "x" }, w.key("bob"));
});

// ---------------------------------------------------------------------------
// Proposals, tasks, claims
// ---------------------------------------------------------------------------

test("proposal: unique id, non-empty well-formed evidence; agents and owners may propose", () => {
  const w = new World().people();
  w.apply({ kind: "proposal", id: "p1", title: "x", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply({ kind: "proposal", id: "p2", title: "x", evidence: [{ kind: "location", file: "a.ts", line: 3, note: "" }] }, w.key("bob"));
  assert.equal(w.state.proposals.get("p2")?.by, w.id("bob"));
  w.reject("duplicate-id", { kind: "proposal", id: "p1", title: "x", evidence: [EVIDENCE] }, w.key("b1"));
  w.reject("invalid-evidence", { kind: "proposal", id: "p3", title: "x", evidence: [] }, w.key("b1"));
  const bad = [
    { kind: "location", file: "a.ts", line: 0, note: "" },
    { kind: "diagnostic", tool: "tsc", message: "", file: "a.ts", line: 1 },
    { kind: "failingTest", testId: "t", command: "c", extra: true },
    { kind: "vibes", feeling: "bad" },
    "see chat",
  ];
  for (const e of bad) {
    w.reject("invalid-evidence", { kind: "proposal", id: "p3", title: "x", evidence: [EVIDENCE, e] } as unknown as EntryBody, w.key("b1"));
  }
});

test("task: unique id, proposal exists, spec author is an owner, acceptance tests non-empty", () => {
  const w = new World().people();
  w.apply({ kind: "proposal", id: "p1", title: "x", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply(taskBody("t1"), w.coord);
  assert.equal(w.state.tasks.get("t1")?.specAuthor, "bob");
  w.reject("duplicate-id", taskBody("t1"), w.coord);
  w.reject("unknown-ref", taskBody("t2", { proposalId: "nope" }), w.coord);
  w.reject("unknown-ref", taskBody("t2", { specAuthor: w.id("b1") }), w.coord);
  w.reject("invalid-value", taskBody("t2", { acceptanceTestPaths: [] }), w.coord);
  w.reject("malformed", taskBody("t2", { ring: 3 as 0 }), w.coord);
});

test("claim: task must exist, stake positive, expiry after the claim", () => {
  const w = new World().task();
  w.reject("unknown-ref", { kind: "claim", taskId: "nope", until: iso(10_000), stake: 10 }, w.key("b1"));
  w.reject("stake", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 0 }, w.key("a1"));
  w.reject("stake", { kind: "claim", taskId: "t1", until: iso(10_000), stake: -3 }, w.key("a1"));
  w.reject("invalid-value", { kind: "claim", taskId: "t1", until: w.now(), stake: 10 }, w.key("a1"), w.now());
});

test("claim: another agent cannot take a live claim, but can after it expires", () => {
  const w = new World().task();
  const until = w.state.claims.get("t1")?.until ?? "";
  w.reject("claim-live", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 6 }, w.key("b1"));
  // the holder may extend
  w.apply({ kind: "claim", taskId: "t1", until: iso(800), stake: 10 }, w.key("a1"));
  w.reject("claim-live", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 6 }, w.key("b1"), until);
  // A claim is live through its `until` instant (as the submission rule has it), and lapsed after.
  w.reject("claim-live", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 6 }, w.key("b1"), iso(800));
  w.apply({ kind: "claim", taskId: "t1", until: iso(10_000), stake: 6 }, w.key("b1"), iso(801));
  assert.equal(w.state.claims.get("t1")?.agent, w.id("b1"));
});

test("regression: a task that merged takes no further submission or merge (one task, one reward)", () => {
  const w = new World().submitted(); // a1 holds t1 and submitted s1
  w.apply(submissionBody("s2", "t1"), w.key("a1")); // a second try while the claim is live
  for (const sid of ["s1", "s2"]) {
    w.apply({ kind: "gateResult", submissionId: sid, gate: "tsc", pass: true, details: "" }, w.coord);
    w.assign(sid, ["b1"]);
  }
  w.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  w.reject("task-done", { kind: "merge", submissionId: "s2", commit: "m2" }, w.coord);
  w.reject("task-done", submissionBody("s3", "t1"), w.key("a1"));
  assert.equal(submissionDead(w.state, "s2"), true, "s2 can never merge: its stakes and PR slot are released");
});

test("claim: a merged task cannot be claimed again", () => {
  const w = new World().merged();
  w.reject("task-done", { kind: "claim", taskId: "t1", until: iso(10_000), stake: 10 }, w.key("a1"));
});

// ---------------------------------------------------------------------------
// Submissions and gates
// ---------------------------------------------------------------------------

test("submission: recorded with its author and claim checked", () => {
  const w = new World().submitted();
  const s = w.state.submissions.get("s1");
  assert.equal(s?.author, w.id("a1"));
  assert.equal(s?.taskId, "t1");
  assert.deepEqual(s?.reviews, []);
});

test("submission: unique id, task exists, live claim by this agent", () => {
  const w = new World().submitted();
  w.reject("duplicate-id", submissionBody("s1", "t1"), w.key("a1"));
  w.reject("unknown-ref", submissionBody("s2", "nope"), w.key("a1"));
  w.reject("claim-missing", submissionBody("s2", "t1"), w.key("b1"));
  w.apply({ kind: "proposal", id: "p2", title: "y", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply({ ...taskBody("t2"), proposalId: "p2" } as EntryBody, w.coord);
  w.reject("claim-missing", submissionBody("s2", "t2"), w.key("a1"), w.now()); // never claimed
  const until = iso(w.minute + 10);
  w.apply({ kind: "claim", taskId: "t2", until, stake: 6 }, w.key("a1"));
  w.apply(submissionBody("s2", "t2"), w.key("a1"), until); // until >= at is still live
  w.apply({ kind: "proposal", id: "p3", title: "z", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply({ ...taskBody("t3"), proposalId: "p3" } as EntryBody, w.coord);
  const short = iso(w.minute + 2);
  w.apply({ kind: "claim", taskId: "t3", until: short, stake: 6 }, w.key("a1"));
  w.reject("claim-missing", submissionBody("s3", "t3"), w.key("a1"), iso(w.minute + 3)); // expired
});

test("regression: submission and finding ids are unique ignoring case and submission ids are git ref names", () => {
  // Ids name upload files (and refs/commons/<id>): on a case-insensitive
  // filesystem a twin would take over the victim's patch or finding test.
  const w = new World().submitted();
  const doc = { changedFiles: ["README.md"] };
  w.reject("duplicate-id", submissionBody("S1", null, doc), w.key("b1"));
  for (const bad of ["s1.lock", "s2.", "a..b", "a:b"]) w.reject("invalid-value", submissionBody(bad, null, doc), w.key("b1"));
  w.apply(submissionBody("s2.x", null, doc), w.key("b1"));
  w.apply(findingBody("f-a", { submissionId: "s1" }), w.key("b1"));
  w.reject("duplicate-id", findingBody("F-A", { submissionId: "s1" }), w.key("c1"));
});

test("submission: lines, files and the planted flag", () => {
  const w = new World().task();
  w.reject("invalid-value", submissionBody("s1", "t1", { linesChanged: -1 }), w.key("a1"));
  w.reject("invalid-value", submissionBody("s1", "t1", { changedFiles: [] }), w.key("a1"));
  w.reject("planted-by-author", submissionBody("s1", "t1", { planted: false }), w.key("a1"));
  w.reject("planted-by-author", submissionBody("s1", "t1", { planted: { severity: "low" } }), w.key("a1"));
  w.apply(submissionBody("s0", null), w.key("b1")); // untasked submissions need no claim
});

test("gateResult: submission must exist; results accumulate", () => {
  const w = new World().submitted();
  w.reject("unknown-ref", { kind: "gateResult", submissionId: "nope", gate: "tsc", pass: true, details: "" }, w.coord);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, w.coord);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "test", pass: false, details: "1 failing" }, w.coord);
  assert.deepEqual(w.state.submissions.get("s1")?.gates.map((g) => g.pass), [true, false]);
});

// ---------------------------------------------------------------------------
// Review assignment, commit, reveal
// ---------------------------------------------------------------------------

test("reviewAssignment: once, before merge, distinct active agents of distinct non-author owners", () => {
  const w = new World().submitted();
  const assign = (reviewers: string[]): EntryBody => assignmentBody(w.state, "s1", reviewers, "e");
  w.reject("unknown-ref", { ...assignmentBody(w.state, "s1", [w.id("b1")], "e"), submissionId: "nope" }, w.coord);
  w.reject("invalid-reviewers", assign([]), w.coord);
  w.reject("invalid-reviewers", assign([w.id("b1"), w.id("a2")]), w.coord); // author's owner
  w.reject("invalid-reviewers", assign([w.id("b1"), w.id("b1")]), w.coord); // same agent twice
  w.reject("invalid-reviewers", assign([w.id("bob")]), w.coord); // an owner key, not an agent
  w.apply({ kind: "agentRegistered", owner: "bob", publicKey: w.key("b2").publicKey, modelFamily: "qwen", harness: "x" }, w.key("bob"));
  w.reject("invalid-reviewers", assign([w.id("b1"), w.id("b2")]), w.coord); // one owner, two seats
  w.apply({ kind: "agentRevoked", agent: w.id("d1"), reason: "x" }, w.key("dave"));
  w.reject("invalid-reviewers", assign([w.id("b1"), w.id("d1")]), w.coord);
  w.apply(assign([w.id("b1"), w.id("c1")]), w.coord);
  assert.deepEqual(w.state.submissions.get("s1")?.assignment?.reviewers, [w.id("b1"), w.id("c1")]);
  w.reject("assigned", assign([w.id("c1")]), w.coord);
  const m = new World().merged();
  m.reject("merged", assignmentBody(m.state, "s1", [m.id("b1")], "e"), m.coord);
});

test("reviewCommit: before merge, not by the author's owner, once per agent, enough stake", () => {
  const w = new World().submitted();
  const c = (stake = 5): EntryBody => ({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s", w.id("b1"), { submissionId: "s1" }), stake });
  w.reject("unknown-ref", { kind: "reviewCommit", submissionId: "nope", commitment: "a".repeat(64), stake: 5 }, w.key("b1"));
  w.reject("same-owner", c(), w.key("a2"));
  w.reject("stake", c(4), w.key("b1"));
  w.apply(c(), w.key("b1"));
  w.reject("duplicate-commit", c(), w.key("b1"));
  const m = new World().merged();
  m.reject("merged", { kind: "reviewCommit", submissionId: "s1", commitment: "a".repeat(64), stake: 5 }, m.key("b1"));
});

test("reviewReveal: must match the signer's own earlier commit exactly once", () => {
  const w = new World().submitted();
  w.assign("s1", ["b1"]);
  const v = verdict(0.3);
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(v, "salt-b1", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.reject("no-commit", { kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "salt-b1" }, w.key("c1"));
  w.reject("commitment-mismatch", { kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "other" }, w.key("b1"));
  w.reject("commitment-mismatch", { kind: "reviewReveal", submissionId: "s1", verdict: verdict(0.9), salt: "salt-b1" }, w.key("b1"));
  w.reject("unknown-ref", { kind: "reviewReveal", submissionId: "nope", verdict: v, salt: "salt-b1" }, w.key("b1"));
  w.apply({ kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "salt-b1" }, w.key("b1"));
  const review = w.state.submissions.get("s1")?.reviews[0];
  assert.deepEqual(review?.verdict, v);
  assert.equal(typeof review?.revealedSeq, "number");
  w.reject("already-revealed", { kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "salt-b1" }, w.key("b1"));
});

test("reviewReveal: verdict must be well-formed even when the commitment matches", () => {
  const w = new World().submitted();
  w.assign("s1", ["b1"]);
  const bad = { defectProbability: 1.5, summary: "", findingIds: [] };
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(bad, "s", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: bad, salt: "s" }, w.key("b1"));
  const extra = { ...verdict(), approve: true } as ReviewVerdict;
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(extra, "s", w.id("c1"), { submissionId: "s1" }), stake: 5 }, w.key("c1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: extra, salt: "s" }, w.key("c1"));
});

test("reviewReveal: cited findings must exist and target this submission", () => {
  const w = new World().submitted();
  w.apply(submissionBody("s9", null), w.key("c1"));
  w.apply(findingBody("f-other", { submissionId: "s9" }), w.key("b1"));
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  w.assign("s1", ["b1"]);
  const ghost = verdict(0.8, ["ghost"]);
  const elsewhere = verdict(0.8, ["f-other"]);
  const good = verdict(0.8, ["f1"]);
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(ghost, "x", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.reject("unknown-ref", { kind: "reviewReveal", submissionId: "s1", verdict: ghost, salt: "x" }, w.key("b1"));
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(elsewhere, "x", w.id("c1"), { submissionId: "s1" }), stake: 5 }, w.key("c1"));
  w.reject("invalid-target", { kind: "reviewReveal", submissionId: "s1", verdict: elsewhere, salt: "x" }, w.key("c1"));
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(good, "x", w.id("d1"), { submissionId: "s1" }), stake: 5 }, w.key("d1"));
  w.apply({ kind: "reviewReveal", submissionId: "s1", verdict: good, salt: "x" }, w.key("d1"));
});

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

test("finding: unique id, existing target, not the author's owner, enough stake", () => {
  const w = new World().submitted();
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  assert.deepEqual(w.state.submissions.get("s1")?.findingIds, ["f1"]);
  w.reject("duplicate-id", findingBody("f1", { submissionId: "s1" }), w.key("c1"));
  w.reject("unknown-ref", findingBody("f2", { submissionId: "nope" }), w.key("c1"));
  w.reject("unknown-ref", findingBody("f2", { snapshotId: "nope" }), w.key("c1"));
  w.reject("same-owner", findingBody("f2", { submissionId: "s1" }), w.key("a2"));
  w.reject("stake", findingBody("f2", { submissionId: "s1" }, 4), w.key("c1"));
  w.reject("invalid-target", findingBody("f2", { submissionId: "s1", snapshotId: "r1" } as unknown as { submissionId: string }), w.key("c1"));
  w.reject("invalid-target", findingBody("f2", {} as { submissionId: string }), w.key("c1"));
  w.reject("invalid-target", findingBody("f2", { commit: "x" } as unknown as { submissionId: string }), w.key("c1"));
});

test("finding: snapshot targets may be filed by any agent except the authors' owners", () => {
  const w = new World().snapshotted();
  w.reject("same-owner", findingBody("f1", { snapshotId: "r1" }), w.key("a2")); // alice wrote s1
  w.apply(findingBody("f1", { snapshotId: "r1" }), w.key("b1"));
  assert.deepEqual(w.state.findings.get("f1")?.target, { snapshotId: "r1" });
});

test("findingResult: finding exists, one result, reproduced is derived", () => {
  const w = new World().submitted();
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  const r = (reproduced: boolean, failsOnHead: boolean, passesOnParent: boolean): EntryBody => ({
    kind: "findingResult",
    findingId: "f1",
    reproduced,
    failsOnHead,
    passesOnParent,
    logDigest: "d",
  });
  w.reject("unknown-ref", { ...r(false, false, false), findingId: "nope" } as EntryBody, w.coord);
  w.reject("result-inconsistent", r(true, true, false), w.coord);
  w.reject("result-inconsistent", r(false, true, true), w.coord);
  w.reject("unauthorised", r(true, true, true), w.key("b1")); // the finder cannot judge itself
  w.apply(r(true, true, true), w.coord);
  w.reject("result-exists", r(false, false, true), w.coord);
});

// ---------------------------------------------------------------------------
// Merge, snapshot, attestation, signoff, promotion
// ---------------------------------------------------------------------------

test("merge: needs at least one gate, all passing, no reproduced finding, once", () => {
  const w = new World().submitted();
  const merge: EntryBody = { kind: "merge", submissionId: "s1", commit: "m1" };
  w.reject("unknown-ref", { kind: "merge", submissionId: "nope", commit: "m" }, w.coord);
  w.reject("gates-missing", merge, w.coord);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, w.coord);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "test", pass: false, details: "" }, w.coord);
  w.reject("gate-failed", merge, w.coord);

  const v = new World().submitted();
  v.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, v.coord);
  v.apply(findingBody("f-false", { submissionId: "s1" }), v.key("c1"));
  v.apply({ kind: "findingResult", findingId: "f-false", reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "" }, v.coord);
  v.apply(findingBody("f1", { submissionId: "s1" }), v.key("b1"));
  v.apply({ kind: "findingResult", findingId: "f1", reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "" }, v.coord);
  v.reject("not-assigned", merge, v.coord); // nothing merges unreviewed
  v.assign("s1", ["d1"]);
  v.reject("reproduced-finding", merge, v.coord);
  // An operator's dismissal (the test only pinned the intended change) clears it.
  v.apply({ kind: "findingDecision", findingId: "f1", confirmed: false, reason: "tests the old text" }, v.admin);
  v.apply(merge, v.coord);

  const m = new World().merged();
  assert.equal(m.state.submissions.get("s1")?.merged?.commit, "m1");
  m.reject("merged", merge, m.coord);
});

test("snapshot: unique id, existing previous, merged submissions not already shipped", () => {
  const w = new World().snapshotted();
  const snap = (id: string, submissionIds: string[], previousSnapshotId: string | null = "r1"): EntryBody => ({
    kind: "snapshot",
    id,
    commit: "c",
    previousSnapshotId,
    submissionIds,
  });
  w.apply(submissionBody("s2", null), w.key("b1"));
  w.reject("duplicate-id", snap("r1", ["s2"]), w.coord);
  w.reject("unknown-ref", snap("r2", ["s2"], "nope"), w.coord);
  w.reject("invalid-value", snap("r2", []), w.coord);
  w.reject("unknown-ref", snap("r2", ["nope"]), w.coord);
  w.reject("not-merged", snap("r2", ["s2"]), w.coord);
  w.apply({ kind: "gateResult", submissionId: "s2", gate: "tsc", pass: true, details: "" }, w.coord);
  w.assign("s2", ["c1"]);
  w.apply({ kind: "merge", submissionId: "s2", commit: "m2" }, w.coord);
  w.reject("already-snapshotted", snap("r2", ["s1", "s2"]), w.coord);
  w.reject("invalid-value", snap("r2", ["s2", "s2"]), w.coord);
  w.apply(snap("r2", ["s2"]), w.coord);
  assert.equal(w.state.snapshots.get("r2")?.previousSnapshotId, "r1");
});

test("attestCommit/attestReveal: any active non-author agent, once each, before promotion", () => {
  const w = new World().snapshotted();
  const v = verdict(0.05);
  const commit = (stake = 5): EntryBody => ({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(v, "q", w.id("b1"), { snapshotId: "r1" }), stake });
  w.reject("unknown-ref", { kind: "attestCommit", snapshotId: "nope", commitment: commitOf(v, "q", w.id("b1"), { snapshotId: "nope" }), stake: 5 }, w.key("b1"));
  w.reject("stake", commit(1), w.key("b1"));
  w.reject("unauthorised", commit(), w.key("bob"));
  w.reject("same-owner", commit(), w.key("a2")); // alice wrote s1, which r1 ships
  w.apply(commit(), w.key("b1"));
  w.reject("duplicate-commit", commit(), w.key("b1"));
  // Reveals wait for the end of the commit phase, so one early reveal cannot
  // shut every other attester out.
  w.reject("commit-phase", { kind: "attestReveal", snapshotId: "r1", verdict: v, salt: "q" }, w.key("b1"));

  // cited findings must target the snapshot itself
  w.apply(findingBody("f-sub", { submissionId: "s1" }), w.key("c1"));
  const cites = verdict(0.5, ["f-sub"]);
  w.apply({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(cites, "q", w.id("c1"), { snapshotId: "r1" }), stake: 5 }, w.key("c1"));
  w.afterCommitPhase();
  w.reject("commit-closed", { kind: "attestCommit", snapshotId: "r1", commitment: commitOf(v, "q", w.id("d1"), { snapshotId: "r1" }), stake: 5 }, w.key("d1"));
  w.reject("no-commit", { kind: "attestReveal", snapshotId: "r1", verdict: v, salt: "q" }, w.key("d1"));
  w.reject("invalid-target", { kind: "attestReveal", snapshotId: "r1", verdict: cites, salt: "q" }, w.key("c1"));

  w.reject("commitment-mismatch", { kind: "attestReveal", snapshotId: "r1", verdict: v, salt: "z" }, w.key("b1"));
  w.apply({ kind: "attestReveal", snapshotId: "r1", verdict: v, salt: "q" }, w.key("b1"));
  w.reject("already-revealed", { kind: "attestReveal", snapshotId: "r1", verdict: v, salt: "q" }, w.key("b1"));

  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  w.reject("promoted", commit(), w.key("b1"));
});

test("signoff: kernel signers only, once each, before promotion", () => {
  const w = new World().snapshotted();
  w.reject("unknown-ref", { kind: "signoff", snapshotId: "nope" }, w.key("carol"));
  w.reject("unauthorised", { kind: "signoff", snapshotId: "r1" }, w.key("bob"));
  w.apply({ kind: "signoff", snapshotId: "r1" }, w.key("carol"));
  w.reject("duplicate-signoff", { kind: "signoff", snapshotId: "r1" }, w.key("carol"));
  w.apply({ kind: "signoff", snapshotId: "r1" }, w.key("dave"));
  assert.deepEqual(w.state.snapshots.get("r1")?.signoffs, ["carol", "dave"]);
  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  const v = new World().snapshotted();
  v.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, v.coord);
  v.reject("promoted", { kind: "signoff", snapshotId: "r1" }, v.key("carol"));
});

test("promotion: snapshot exists, once", () => {
  const w = new World().snapshotted();
  w.reject("unknown-ref", { kind: "promotion", snapshotId: "nope", commit: "m" }, w.coord);
  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  assert.ok(w.state.snapshots.get("r1")?.promoted);
  w.reject("promoted", { kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
});

// ---------------------------------------------------------------------------
// Plants, honeytokens, escapes, settlements, rules
// ---------------------------------------------------------------------------

test("plants: commitment before the submission, matching reveal, once", () => {
  const w = new World().task();
  const salt = "plant-salt";
  w.apply({ kind: "plantCommit", commitment: sha256hex(`s1:${salt}`) }, w.admin);
  w.reject("duplicate-commit", { kind: "plantCommit", commitment: sha256hex(`s1:${salt}`) }, w.admin);
  w.apply(submissionBody("s1", "t1"), w.key("a1"));
  assert.equal(w.state.submissions.get("s1")?.planted, undefined, "plants stay hidden until revealed");
  const reveal = (submissionId: string, s: string): EntryBody => ({ kind: "plantReveal", submissionId, salt: s, description: "off by one", severity: "medium" });
  w.reject("unknown-ref", reveal("nope", salt), w.admin);
  w.reject("plant-mismatch", reveal("s1", "wrong"), w.admin);
  w.reject("unauthorised", reveal("s1", salt), w.coord);
  const revealed = w.apply(reveal("s1", salt), w.admin);
  assert.deepEqual(w.state.submissions.get("s1")?.planted, { severity: "medium", description: "off by one", seq: revealed.seq });
  w.reject("already-planted", reveal("s1", salt), w.admin);
});

test("plants: a commitment made after the submission cannot label it a plant", () => {
  const w = new World().submitted();
  w.apply({ kind: "plantCommit", commitment: sha256hex("s1:late") }, w.admin);
  w.reject("plant-late", { kind: "plantReveal", submissionId: "s1", salt: "late", description: "", severity: "low" }, w.admin);
});

test("honeytokenTriggered: agent must exist", () => {
  const w = new World().people();
  w.reject("unknown-ref", { kind: "honeytokenTriggered", agent: "nobody", tokenId: "t" }, w.coord);
  w.apply({ kind: "honeytokenTriggered", agent: w.id("b1"), tokenId: "tok-1" }, w.coord);
  assert.equal(w.state.honeytokens[0]?.agent, w.id("b1"));
});

test("escape: reproduced finding against a promoted snapshot, once per finding", () => {
  const w = new World().snapshotted();
  w.apply(findingBody("f1", { snapshotId: "r1" }), w.key("b1"));
  const esc: EntryBody = { kind: "escape", findingId: "f1", snapshotId: "r1" };
  w.reject("unknown-ref", { kind: "escape", findingId: "nope", snapshotId: "r1" }, w.coord);
  w.reject("not-reproduced", esc, w.coord);
  w.apply({ kind: "findingResult", findingId: "f1", reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "" }, w.coord);
  w.reject("not-decidable", esc, w.coord); // a reproduction alone is not a known defect
  w.apply({ kind: "findingDecision", findingId: "f1", confirmed: true, reason: "real" }, w.admin);
  w.reject("not-promoted", esc, w.coord);
  w.reject("unknown-ref", { kind: "escape", findingId: "f1", snapshotId: "nope" }, w.coord);
  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  w.apply(esc, w.coord);
  w.reject("duplicate-escape", esc, w.coord);
});

test("settlement: owner exists, integer delta, accumulates reputation", () => {
  const w = new World().people();
  w.reject("unknown-ref", { kind: "settlement", owner: "mallory", delta: 5, reason: "bounty", ref: "f" }, w.coord);
  // NaN cannot even be signed: canonical() refuses it
  assert.throws(
    () => w.sign({ kind: "settlement", owner: "alice", delta: Number.NaN, reason: "bounty", ref: "f" }, w.coord),
    isCode("malformed"),
  );
  w.apply({ kind: "settlement", owner: "alice", delta: 30, reason: "mergeVest", ref: "s1" }, w.coord);
  w.apply({ kind: "settlement", owner: "alice", delta: -12, reason: "authorSlash", ref: "f1" }, w.coord);
  assert.equal(w.owner("alice").reputationDelta, 18);
  assert.equal(w.state.settlements.length, 2);
});

test("rulesChange: valid rules with a strictly greater version", () => {
  const w = new World();
  const next = { ...defaultRules(), version: 2, maxLinesPerSubmission: 300 };
  w.reject("invalid-rules", { kind: "rulesChange", rules: { ...next, plantRate: 0.9 }, pollId: "poll" }, w.admin);
  w.reject("rules-version", { kind: "rulesChange", rules: { ...next, version: 1 }, pollId: "poll" }, w.admin);
  w.reject("invalid-rules", { kind: "rulesChange", rules: { ...next, extra: 1 } as unknown as Rules, pollId: "poll" }, w.admin);
  w.apply({ kind: "rulesChange", rules: next, pollId: "poll" }, w.admin);
  assert.equal(w.state.rules.maxLinesPerSubmission, 300);
  assert.equal(w.state.rules.version, 2);
  next.maxLinesPerSubmission = 1;
  assert.equal(w.state.rules.maxLinesPerSubmission, 300, "state does not alias the entry");
});

test("rulesChange: new stakes apply to later entries", () => {
  const w = new World().submitted();
  const rules = { ...defaultRules(), version: 2, stake: { ...defaultRules().stake, review: 50 } };
  w.apply({ kind: "rulesChange", rules, pollId: "poll" }, w.admin);
  w.reject("stake", { kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
});

// ---------------------------------------------------------------------------
// Locked stake
// ---------------------------------------------------------------------------

test("lockedStake: claims until expiry or merge", () => {
  const w = new World().task(); // a1 claimed t1 with stake 10 until minute ~+600
  assert.equal(w.owner("alice").lockedStake, 10);
  const until = Date.parse(w.state.claims.get("t1")?.until ?? "");
  w.apply({ kind: "honeytokenTriggered", agent: w.id("b1"), tokenId: "tick" }, w.coord, new Date(until).toISOString());
  assert.equal(w.owner("alice").lockedStake, 10, "still locked at exactly `until`");
  w.apply({ kind: "honeytokenTriggered", agent: w.id("b1"), tokenId: "tick" }, w.coord, new Date(until + 1000).toISOString());
  assert.equal(w.owner("alice").lockedStake, 0, "released once the latest entry is past expiry");

  const m = new World().merged();
  assert.equal(m.owner("alice").lockedStake, 0, "released when the task merges");
});

test("lockedStake: review commits until merge, findings until result, attestations until promotion", () => {
  const w = new World().submitted();
  const aliceClaim = 10;
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s", w.id("b1"), { submissionId: "s1" }), stake: 7 }, w.key("b1"));
  w.apply(findingBody("f1", { submissionId: "s1" }, 6), w.key("b1"));
  assert.equal(w.owner("bob").lockedStake, 13);
  w.apply({ kind: "findingResult", findingId: "f1", reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "" }, w.coord);
  assert.equal(w.owner("bob").lockedStake, 7);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, w.coord);
  w.assign("s1", ["b1"]);
  w.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  assert.equal(w.owner("bob").lockedStake, 0);
  assert.equal(w.owner("alice").lockedStake, 0, `claim of ${aliceClaim} released by merge`);
  w.apply({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, w.coord);
  w.apply({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(verdict(), "s", w.id("c1"), { snapshotId: "r1" }), stake: 9 }, w.key("c1"));
  assert.equal(w.owner("carol").lockedStake, 9);
  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  assert.equal(w.owner("carol").lockedStake, 0);
});

// ---------------------------------------------------------------------------
// File-backed ledger
// ---------------------------------------------------------------------------

function lifecycle(ledger: Ledger, w: World): void {
  const at = () => {
    w.minute += 1;
    return w.now();
  };
  const add = (body: EntryBody, signer: Signer) => ledger.append(body, signer, at());
  add({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin);
  for (const o of ["bob", "carol", "dave"]) add({ kind: "ownerKey", owner: o, publicKey: w.key(o).publicKey, inviter: "alice" }, w.admin);
  const agents: [string, string, string][] = [
    ["a1", "alice", "claude"],
    ["b1", "bob", "gpt"],
    ["c1", "carol", "qwen"],
    ["d1", "dave", "kimi"],
  ];
  for (const [agent, owner, fam] of agents) {
    add({ kind: "agentRegistered", owner, publicKey: w.key(agent).publicKey, modelFamily: fam, harness: "cli" }, w.key(owner));
  }
  add({ kind: "plantCommit", commitment: sha256hex("s-plant:pepper") }, w.admin);
  add({ kind: "proposal", id: "p1", title: "vote bug", evidence: [EVIDENCE] }, w.key("b1"));
  add(taskBody("t1"), w.coord);
  add({ kind: "claim", taskId: "t1", until: iso(w.minute + 600), stake: 10 }, w.key("a1"));
  add(submissionBody("s1", "t1"), w.key("a1"));
  add(submissionBody("s-plant", null), w.key("d1")); // the custodian's plant, submitted through an agent
  add({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "ok" }, w.coord);
  add(assignmentBody(ledger.state(), "s1", [w.id("b1"), w.id("c1")], "e"), w.coord);
  const vb = verdict(0.1);
  const vc = verdict(0.2, ["f1"]);
  add({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(vb, "sb", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  add(findingBody("f1", { submissionId: "s1" }), w.key("c1"));
  add({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(vc, "sc", w.id("c1"), { submissionId: "s1" }), stake: 5 }, w.key("c1"));
  add({ kind: "reviewReveal", submissionId: "s1", verdict: vb, salt: "sb" }, w.key("b1"));
  add({ kind: "reviewReveal", submissionId: "s1", verdict: vc, salt: "sc" }, w.key("c1"));
  add({ kind: "findingResult", findingId: "f1", reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d" }, w.coord);
  add({ kind: "settlement", owner: "carol", delta: -5, reason: "falseFinding", ref: "f1" }, w.coord);
  add({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  add({ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: "s1" }, w.coord);
  add({ kind: "plantReveal", submissionId: "s-plant", salt: "pepper", description: "planted", severity: "high" }, w.admin);
  add({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, w.coord);
  const va = verdict(0.05);
  add({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(va, "sa", w.id("b1"), { snapshotId: "r1" }), stake: 5 }, w.key("b1"));
  w.afterCommitPhase();
  add({ kind: "attestReveal", snapshotId: "r1", verdict: va, salt: "sa" }, w.key("b1"));
  add({ kind: "signoff", snapshotId: "r1" }, w.key("carol"));
  add({ kind: "signoff", snapshotId: "r1" }, w.key("dave"));
  add({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  add(findingBody("f2", { snapshotId: "r1" }), w.key("b1"));
  add({ kind: "findingResult", findingId: "f2", reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" }, w.coord);
  add({ kind: "findingDecision", findingId: "f2", confirmed: true, reason: "a real defect on main" }, w.admin);
  add({ kind: "escape", findingId: "f2", snapshotId: "r1" }, w.coord);
  add({ kind: "honeytokenTriggered", agent: w.id("d1"), tokenId: "decoy-1" }, w.coord);
  add({ kind: "agentRevoked", agent: w.id("d1"), reason: "honeytoken" }, w.coord);
  add({ kind: "rulesChange", rules: { ...defaultRules(), version: 2, kernelSigners: ["carol", "dave"] }, pollId: "poll-1" }, w.admin);
}

function freshLedger(): { file: string; ledger: Ledger; w: World } {
  const w = new World();
  const file = tmpFile();
  const ledger = Ledger.create(file, w.genesisBody({ ...defaultRules(), kernelSigners: ["carol", "dave"] }), iso(0));
  return { file, ledger, w };
}

test("Ledger: full lifecycle survives a round trip through the file", () => {
  const { file, ledger, w } = freshLedger();
  lifecycle(ledger, w);
  const s = ledger.state();
  assert.equal(s.submissions.get("s1")?.merged?.commit, "m1");
  assert.equal(s.submissions.get("s1")?.reviews.filter((r) => r.verdict).length, 2);
  const planted = s.submissions.get("s-plant")?.planted;
  assert.deepEqual([planted?.severity, planted?.description, typeof planted?.seq], ["high", "planted", "number"]);
  assert.ok(s.snapshots.get("r1")?.promoted);
  assert.deepEqual(s.snapshots.get("r1")?.signoffs, ["carol", "dave"]);
  assert.equal(s.escapes.length, 1);
  assert.equal(s.agents.get(w.id("d1"))?.active, false);
  assert.equal(s.owners.get("alice")?.reputationDelta, 10);
  assert.equal(s.owners.get("carol")?.reputationDelta, -5);
  assert.equal(s.rules.version, 2);
  for (const o of s.owners.values()) assert.equal(o.lockedStake, 0, `${o.id} has nothing open`);

  const reopened = Ledger.open(file);
  assert.deepStrictEqual(reopened.state(), s);
  assert.deepStrictEqual(reopened.entries(), ledger.entries());
  assert.equal(fs.readFileSync(file, "utf8").split("\n").length, ledger.entries().length + 1);
});

test("Ledger: create never overwrites", () => {
  const { file, w } = freshLedger();
  assert.throws(() => Ledger.create(file, w.genesisBody(defaultRules()), iso(0)), isCode("exists"));
});

test("Ledger: create refuses an invalid genesis without writing", () => {
  const w = new World();
  const file = tmpFile();
  assert.throws(() => Ledger.create(file, w.genesisBody({ ...defaultRules(), version: 0 }), iso(0)), isCode("invalid-rules"));
  assert.equal(fs.existsSync(file), false);
});

test("Ledger: an invalid append is not written and leaves the ledger usable", () => {
  const { file, ledger, w } = freshLedger();
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  const before = fs.readFileSync(file, "utf8");
  const state = structuredClone(ledger.state());
  assert.throws(
    () => ledger.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("x").publicKey, inviter: null }, w.admin, iso(2)),
    isCode("duplicate-id"),
  );
  assert.throws(() => ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.key("alice"), iso(2)), isCode("unauthorised"));
  assert.equal(fs.readFileSync(file, "utf8"), before);
  assert.deepStrictEqual(ledger.state(), state);
  ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: "alice" }, w.admin, iso(3));
  assert.equal(Ledger.open(file).state().owners.size, 2);
});

test("Ledger: appendSigned accepts entries signed elsewhere", () => {
  const { file, ledger, w } = freshLedger();
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  // alice signs on her own machine against the head she was shown
  const entry = signEntry(
    { seq: ledger.state().length, prev: ledger.state().headHash },
    { kind: "agentRegistered", owner: "alice", publicKey: w.key("a1").publicKey, modelFamily: "claude", harness: "cli" },
    w.key("alice"),
    iso(2),
  );
  ledger.appendSigned(entry);
  assert.throws(() => ledger.appendSigned(entry), isCode("seq"), "the same entry cannot be appended twice");
  assert.equal(Ledger.open(file).state().agents.size, 1);
});

test("Ledger: a second writer makes the first one stale instead of forking the file", () => {
  const { file, ledger, w } = freshLedger();
  const other = Ledger.open(file);
  other.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  assert.throws(
    () => ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.admin, iso(2)),
    isCode("stale"),
  );
  assert.equal(Ledger.open(file).entries().length, 2);
});

test("Ledger: two processes appending at once never fork the file (cross-process lock)", async () => {
  const { file, w } = freshLedger();
  const keyFile = path.join(path.dirname(file), "admin.json");
  fs.writeFileSync(keyFile, JSON.stringify(w.admin));
  const writer = path.join(__dirname, "ledger-writer.ts");
  const run = (tag: string) =>
    new Promise<number>((resolve) => {
      const child = spawn(process.execPath, ["--import", "tsx", writer, file, keyFile, tag, "150"], { stdio: ["ignore", "ignore", "inherit"] });
      child.on("exit", (code) => resolve(code ?? 1));
    });
  assert.deepEqual(await Promise.all([run("a"), run("b")]), [0, 0]);
  const reopened = Ledger.open(file); // replays: one seq per line, one chain
  assert.equal(reopened.entries().length, 301);
  assert.equal(fs.existsSync(`${file}.lock`), false, "the lock is released");
});

test("Ledger: a lock left by a crashed process is broken; a live holder makes writers wait", () => {
  const { file, ledger, w } = freshLedger();
  fs.writeFileSync(`${file}.lock`, "999999999"); // no such pid
  ledger.append({ kind: "plantCommit", commitment: sha256hex("x") }, w.admin, iso(1));
  assert.equal(Ledger.open(file).entries().length, 2);
  fs.writeFileSync(`${file}.lock`, String(process.ppid)); // a running process
  assert.throws(() => withFileLock(file, () => 0, 3), isCode("locked"), "a lock held by a running pid is never broken");
  fs.rmSync(`${file}.lock`);
  // A reader that cannot create the lock (a read-only directory) still reads.
  if (process.getuid?.() !== 0) {
    fs.chmodSync(path.dirname(file), 0o555);
    try {
      assert.equal(Ledger.open(file).entries().length, 2);
    } finally {
      fs.chmodSync(path.dirname(file), 0o755);
    }
  }
});

function tamper(edit: (lines: string[]) => string[]): string {
  const { file, ledger, w } = freshLedger();
  lifecycle(ledger, w);
  const lines = fs.readFileSync(file, "utf8").slice(0, -1).split("\n");
  fs.writeFileSync(file, `${edit(lines).join("\n")}\n`);
  return file;
}

function editLine(lines: string[], i: number, edit: (e: LedgerEntry) => LedgerEntry): string[] {
  const out = [...lines];
  out[i] = JSON.stringify(edit(JSON.parse(lines[i] ?? "") as LedgerEntry));
  return out;
}

const settlementIndex = (lines: string[]) => lines.findIndex((l) => l.includes('"kind":"settlement"'));

test("tamper: editing a body breaks the hash", () => {
  const file = tamper((lines) =>
    editLine(lines, settlementIndex(lines), (e) => ({ ...e, body: { ...e.body, delta: 1_000_000 } as EntryBody })),
  );
  assert.throws(() => Ledger.open(file), isCode("hash"));
});

test("tamper: editing a body and re-hashing breaks the signature", () => {
  const file = tamper((lines) =>
    editLine(lines, settlementIndex(lines), (e) => {
      const edited = { ...e, body: { ...e.body, delta: 1_000_000 } as EntryBody };
      return { ...edited, hash: entryHash(edited) };
    }),
  );
  assert.throws(() => Ledger.open(file), isCode("signature"));
});

test("tamper: re-signing with a valid but different key is unauthorised or unknown", () => {
  const attacker = generateKeyPair();
  const file = tamper((lines) =>
    editLine(lines, settlementIndex(lines), (e) => {
      const edited = { ...e, signer: keyIdOf(attacker.publicKey), body: { ...e.body, delta: 1_000_000 } as EntryBody };
      const sig = sign(attacker.privateKey, entryMessage(edited));
      return { ...edited, sig, hash: entryHash({ ...edited, sig }) };
    }),
  );
  assert.throws(() => Ledger.open(file), isCode("signer-unknown"));
});

test("tamper: reordering, dropping or duplicating lines breaks the chain", () => {
  const swapped = tamper((lines) => {
    const out = [...lines];
    [out[5], out[6]] = [out[6] ?? "", out[5] ?? ""];
    return out;
  });
  assert.throws(() => Ledger.open(swapped), isCode("seq"));
  const dropped = tamper((lines) => lines.filter((_, i) => i !== 7));
  assert.throws(() => Ledger.open(dropped), isCode("seq"));
  const duplicated = tamper((lines) => [...lines, lines[lines.length - 1] ?? ""]);
  assert.throws(() => Ledger.open(duplicated), isCode("seq"));
  const relinked = tamper((lines) => editLine(lines, 3, (e) => ({ ...e, prev: "0".repeat(64) })));
  assert.throws(() => Ledger.open(relinked), isCode("prev"));
});

test("tamper: whitespace-only changes to a line are harmless (hashes cover canonical form)", () => {
  const file = tamper((lines) => lines.map((l, i) => (i === 2 ? JSON.stringify(JSON.parse(l), null, 0).replace(/^\{/, "{ ") : l)));
  assert.doesNotThrow(() => Ledger.open(file));
});

test("corrupt files are refused", () => {
  const { file, ledger, w } = freshLedger();
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  const text = fs.readFileSync(file, "utf8");
  fs.writeFileSync(file, text.slice(0, -10));
  assert.throws(() => Ledger.open(file), isCode("torn"));
  fs.writeFileSync(file, `${text}not json\n`);
  assert.throws(() => Ledger.open(file), isCode("malformed"));
  fs.writeFileSync(file, `${text}\n`);
  assert.throws(() => Ledger.open(file), isCode("malformed"));
  fs.writeFileSync(file, "");
  assert.throws(() => Ledger.open(file), isCode("genesis"));
  fs.writeFileSync(file, `${JSON.stringify({ ...JSON.parse(text.split("\n")[0] ?? ""), project: "x" })}\n`);
  assert.throws(() => Ledger.open(file), isCode("malformed"));
});

// ---------------------------------------------------------------------------
// Regressions from review: each test pins one fixed hole.
// ---------------------------------------------------------------------------

const passGate = (sid: string): EntryBody => ({ kind: "gateResult", submissionId: sid, gate: "tsc", pass: true, details: "" });
const result = (findingId: string, reproduced: boolean): EntryBody => ({
  kind: "findingResult",
  findingId,
  reproduced,
  failsOnHead: reproduced,
  passesOnParent: true,
  logDigest: "",
});
const plantReveal = (submissionId: string, salt: string): EntryBody => ({
  kind: "plantReveal",
  submissionId,
  salt,
  description: "",
  severity: "high",
});
const confirm = (findingId: string, confirmed = true): EntryBody => ({ kind: "findingDecision", findingId, confirmed, reason: "judged" });

test("regression: one plant commitment cannot label two submissions via ':' in ids or salts", () => {
  const w = new World().people();
  w.apply({ kind: "plantCommit", commitment: sha256hex("a:b:c") }, w.admin);
  w.apply(submissionBody("a", null), w.key("d1"));
  // Submission ids cannot hold ':' (they name git refs), so "a:b" never exists...
  w.reject("invalid-value", submissionBody("a:b", null), w.key("d1"));
  // ...and "a" + ":" + "b:c" hashes to the same preimage, but a salt with ':' is refused.
  w.reject("invalid-value", plantReveal("a", "b:c"), w.admin);
  assert.equal(w.state.submissions.get("a")?.planted, undefined);
});

test("regression: Object.prototype names are unknown fields at every level", () => {
  const w = new World().submitted();
  const settle: EntryBody = { kind: "settlement", owner: "alice", delta: 1, reason: "bounty", ref: "r" };
  // envelope
  w.rejectEntry("malformed", { ...w.sign(settle, w.coord), constructor: { approvedBy: "admin" } } as unknown as LedgerEntry);
  w.rejectEntry("malformed", { ...w.sign(settle, w.coord), hasOwnProperty: "injected" } as unknown as LedgerEntry);
  // body
  w.reject("malformed", { ...settle, toString: "x" } as unknown as EntryBody, w.coord);
  w.reject("malformed", { ...settle, valueOf: 1 } as unknown as EntryBody, w.coord);
  // __proto__ arrives as an own key from JSON.parse
  const proto = JSON.parse(JSON.stringify(w.sign(settle, w.coord)).replace('"ref":"r"', '"ref":"r","__proto__":{"x":1}'));
  assert.ok(Object.hasOwn(proto.body, "__proto__"));
  w.rejectEntry("malformed", proto as LedgerEntry);
  // evidence item
  const ev = { ...EVIDENCE, toString: "x" };
  w.reject("invalid-evidence", { kind: "proposal", id: "p9", title: "x", evidence: [ev] } as unknown as EntryBody, w.key("b1"));
  // verdict
  const v = { ...verdict(), constructor: "x" } as unknown as ReviewVerdict;
  w.assign("s1", ["b1"]);
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(v, "s", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "s" }, w.key("b1"));
});

test("regression: a file line with injected prototype-named envelope keys fails to open", () => {
  for (const inject of ['"valueOf":"attacker note","constructor":{"approvedBy":"admin"}', '"__proto__":{"approvedBy":"admin"}']) {
    const file = tamper((lines) => lines.map((l, i) => (i === 1 ? l.replace(/^\{/, `{${inject},`) : l)));
    assert.throws(() => Ledger.open(file), isCode("malformed"), inject);
  }
});

test("regression: emptyState checks a bare genesis body as strictly as a genesis line", () => {
  const w = new World();
  const body = w.genesisBody(defaultRules());
  assert.throws(() => emptyState(body, "garbage"), isCode("malformed"));
  assert.throws(() => emptyState({ ...body, project: 42 } as unknown as GenesisBody), isCode("malformed"));
  assert.throws(() => emptyState({ ...body, extra: 1 } as unknown as GenesisBody), isCode("malformed"));
  assert.throws(() => emptyState({ ...body, project: 1n } as unknown as GenesisBody), isCode("malformed"));
  assert.equal(emptyState(body, iso(0)).headAt, iso(0));
});

test("regression: times must be real instants in the one canonical UTC spelling", () => {
  const w = new World().task();
  const claim = (until: string): EntryBody => ({ kind: "claim", taskId: "t1", until, stake: 10 });
  for (const bad of ["2026-02-30T00:00:00.000Z", "2026-01-01T24:00:00.000Z", "2026-01-02T01:00:00.000+01:00", "2026-01-02T00:00:00Z", "2026-01-02T00:00:00.5Z"]) {
    w.reject("malformed", claim(bad), w.key("a1"));
    w.rejectEntry("malformed", w.sign({ kind: "settlement", owner: "bob", delta: 1, reason: "bounty", ref: "r" }, w.coord, bad));
  }
  w.apply(claim(iso(w.minute + 60)), w.key("a1"));
});

test("regression: claims are capped in length, staked at the task's price, and die with their agent", () => {
  const w = new World().people();
  w.apply({ kind: "proposal", id: "p1", title: "fix", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply(taskBody("t1"), w.coord); // ring 1, 50 lines: ceil(10 * 0.5^1.5 * 1.5) = 6
  w.apply(taskBody("k1", { ring: 0, sizeEstimate: 400 }), w.coord); // 10 * 8 * 4 = 320
  const claim = (taskId: string, until: string, stake: number): EntryBody => ({ kind: "claim", taskId, until, stake });
  w.reject("claim-too-long", claim("t1", "9999-12-31T23:59:59.000Z", 6), w.key("c1"));
  w.reject("stake", claim("t1", iso(w.minute + 60), 1), w.key("c1"));
  w.reject("stake", claim("k1", iso(w.minute + 60), 319), w.key("c1"));
  w.apply(claim("k1", iso(w.minute + 60), 320), w.key("c1"));
  const cap = MAX_CLAIM_MS / 60_000;
  w.apply(claim("t1", iso(w.minute + 1 + cap), 6), w.key("c1")); // exactly the cap is allowed
  // an extension is capped like a fresh claim
  w.reject("claim-too-long", claim("t1", iso(w.minute + 2 + cap), 6), w.key("c1"));
  w.reject("claim-live", claim("t1", iso(w.minute + 60), 6), w.key("d1"));
  // revoking the holder frees the task at once
  w.apply({ kind: "agentRevoked", agent: w.id("c1"), reason: "squatting" }, w.coord);
  w.apply(claim("t1", iso(w.minute + 60), 6), w.key("d1"));
  assert.equal(w.state.claims.get("t1")?.agent, w.id("d1"));
});

test("regression: a ring 0 change cannot skip the claim by omitting the task", () => {
  const w = new World().people();
  w.reject("task-required", submissionBody("s1", null, { changedFiles: ["README.md", "scripts/deploy.sh"] }), w.key("a1"));
  w.reject("task-required", submissionBody("s1", null, { changedFiles: [".github/workflows/ci.yml"] }), w.key("a1"));
  w.apply(submissionBody("s1", null, { changedFiles: ["README.md"] }), w.key("a1"));
});

test("regression: changed files, acceptance tests and finding tests must be canonical repo paths", () => {
  const w = new World().task();
  const bad = ["./server/src/auth.ts", "/etc/passwd", "server//src/auth.ts", "server/src/../src/auth.ts", "a/./b", "a\\b", "a\0b", "a/", ""];
  for (const f of bad) {
    w.reject("invalid-value", submissionBody("s1", "t1", { changedFiles: [f] }), w.key("a1"));
    w.reject("invalid-value", taskBody("t9", { acceptanceTestPaths: [f] }), w.coord);
  }
  w.reject("invalid-value", submissionBody("s1", "t1", { changedFiles: ["a.ts", "a.ts"] }), w.key("a1"));
  w.apply(submissionBody("s1", "t1"), w.key("a1"));
  w.reject("invalid-value", { ...findingBody("f1", { submissionId: "s1" }), testPath: "../../outside.test.ts" } as EntryBody, w.key("b1"));
});

test("regression: review commits close once the outcome is public", () => {
  const commit = (salt: string): EntryBody => ({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(1), salt, w.id(salt), { submissionId: "s1" }), stake: 5 });
  // after a reveal (which waits until every assigned reviewer committed)
  const w = new World().submitted();
  w.assign("s1", ["b1"]);
  w.apply(commit("b1"), w.key("b1"));
  w.apply({ kind: "reviewReveal", submissionId: "s1", verdict: verdict(1), salt: "b1" }, w.key("b1"));
  w.reject("commit-closed", commit("c1"), w.key("c1"));

  // after the commit phase, even with nothing revealed
  const t = new World().submitted();
  t.assign("s1", ["b1"]);
  t.afterCommitPhase();
  t.reject("commit-closed", commit("c1"), t.key("c1"));

  // after the plant is revealed
  const p = new World().people();
  p.apply({ kind: "plantCommit", commitment: sha256hex("s1:salt") }, p.admin);
  p.apply(submissionBody("s1", null), p.key("a1"));
  p.apply(plantReveal("s1", "salt"), p.admin);
  p.reject("commit-closed", commit("d1"), p.key("d1"));

  // after a finding on it reproduced (a non-reproduced result says little and closes nothing)
  const f = new World().submitted();
  f.apply(findingBody("f0", { submissionId: "s1" }), f.key("b1"));
  f.apply(result("f0", false), f.coord);
  f.apply(commit("c1"), f.key("c1"));
  f.apply(findingBody("f1", { submissionId: "s1" }), f.key("b1"));
  f.apply(result("f1", true), f.coord);
  f.reject("commit-closed", commit("d1"), f.key("d1"));
});

test("regression: attestation commits close once the outcome is public", () => {
  const attest = (agent: string): EntryBody => ({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(verdict(1), agent, w.id(agent), { snapshotId: "r1" }), stake: 5 });
  const w = new World().snapshotted();
  w.apply(attest("b1"), w.key("b1"));
  w.afterCommitPhase(); // reveals wait for the end of the commit phase, which also closes commits
  w.apply({ kind: "attestReveal", snapshotId: "r1", verdict: verdict(1), salt: "b1" }, w.key("b1"));
  w.reject("commit-closed", attest("c1"), w.key("c1"));

  const f = new World().snapshotted();
  f.apply(findingBody("f1", { submissionId: "s1" }), f.key("b1")); // on a submission the snapshot ships
  f.apply(result("f1", true), f.coord);
  f.reject("commit-closed", attest("c1"), f.key("c1"));
});

test("regression: one owner fills at most one review or attestation seat", () => {
  const w = new World().submitted();
  w.apply({ kind: "agentRegistered", owner: "bob", publicKey: w.key("b2").publicKey, modelFamily: "deepseek", harness: "cli" }, w.key("bob"));
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "x", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.reject("duplicate-commit", { kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "y", w.id("b2"), { submissionId: "s1" }), stake: 5 }, w.key("b2"));
  assert.equal(w.owner("bob").lockedStake, 5);

  w.apply(passGate("s1"), w.coord);
  w.assign("s1", ["c1"]);
  w.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  w.apply({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, w.coord);
  w.apply({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(verdict(), "x", w.id("b2"), { snapshotId: "r1" }), stake: 5 }, w.key("b2"));
  w.reject("duplicate-commit", { kind: "attestCommit", snapshotId: "r1", commitment: commitOf(verdict(), "y", w.id("b1"), { snapshotId: "r1" }), stake: 5 }, w.key("b1"));
});

test("regression: authors' owners cannot attest or file findings on a snapshot of their work or its unpromoted ancestry", () => {
  const w = new World().people();
  const ship = (sid: string, agent: string) => {
    w.apply(submissionBody(sid, null), w.key(agent));
    w.apply(passGate(sid), w.coord);
    w.assign(sid, ["d1"]);
    w.apply({ kind: "merge", submissionId: sid, commit: `m-${sid}` }, w.coord);
  };
  ship("s1", "c1"); // carol, a kernel signer, wrote s1
  w.apply({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, w.coord);
  ship("s2", "b1");
  w.apply({ kind: "snapshot", id: "r2", commit: "m2", previousSnapshotId: "r1", submissionIds: ["s2"] }, w.coord);
  const attest = (sid: string): EntryBody => ({ kind: "attestCommit", snapshotId: sid, commitment: commitOf(verdict(), "q", w.id("c1"), { snapshotId: sid }), stake: 5 });
  for (const snap of ["r1", "r2"]) {
    w.reject("same-owner", attest(snap), w.key("c1"));
    w.reject("same-owner", findingBody(`f-${snap}`, { snapshotId: snap }), w.key("c1"));
  }
  w.reject("same-owner", attest("r2"), w.key("b1"));
  // Sign-offs exclude only authors of covered kernel changes; carol's s1 is
  // ring 1, so it does not stop her (see the kernel sign-off test below).
  w.apply({ kind: "signoff", snapshotId: "r1" }, w.key("carol"));
  w.apply({ kind: "signoff", snapshotId: "r1" }, w.key("dave"));
  // once r1 is promoted, r2 no longer covers carol's work
  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  w.apply(attest("r2"), w.key("c1"));
});

test("regression: merge waits for every finding's result and refuses a revealed plant", () => {
  const w = new World().submitted();
  w.apply(passGate("s1"), w.coord);
  w.assign("s1", ["c1"]);
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  w.reject("finding-pending", { kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  w.apply(result("f1", false), w.coord);
  w.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);

  const p = new World().people();
  p.apply({ kind: "plantCommit", commitment: sha256hex("s1:salt") }, p.admin);
  p.apply(submissionBody("s1", null), p.key("d1"));
  p.apply(passGate("s1"), p.coord);
  p.assign("s1", ["c1"]);
  p.apply(plantReveal("s1", "salt"), p.admin);
  p.reject("planted", { kind: "merge", submissionId: "s1", commit: "m1" }, p.coord);
});

test("regression: an escape must be a finding on something the snapshot shipped", () => {
  const w = new World().snapshotted();
  w.apply(submissionBody("s-other", null), w.key("c1")); // never merged, never shipped
  w.apply(findingBody("f-other", { submissionId: "s-other" }), w.key("b1"));
  w.apply(result("f-other", true), w.coord);
  w.apply(confirm("f-other"), w.admin);
  w.apply(findingBody("f-sub", { submissionId: "s1" }), w.key("b1"));
  w.apply(result("f-sub", true), w.coord);
  w.apply(confirm("f-sub"), w.admin);
  w.apply({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  w.reject("invalid-target", { kind: "escape", findingId: "f-other", snapshotId: "r1" }, w.coord);
  w.apply({ kind: "escape", findingId: "f-sub", snapshotId: "r1" }, w.coord);
  // a later snapshot ships its ancestors too
  w.apply(submissionBody("s2", null), w.key("c1"));
  w.apply(passGate("s2"), w.coord);
  w.assign("s2", ["d1"]);
  w.apply({ kind: "merge", submissionId: "s2", commit: "m2" }, w.coord);
  w.apply({ kind: "snapshot", id: "r2", commit: "m2", previousSnapshotId: "r1", submissionIds: ["s2"] }, w.coord);
  w.apply({ kind: "promotion", snapshotId: "r2", commit: "m2" }, w.coord);
  w.apply(findingBody("f-r1", { snapshotId: "r1" }), w.key("d1"));
  w.apply(result("f-r1", true), w.coord);
  w.apply(confirm("f-r1"), w.admin);
  w.apply({ kind: "escape", findingId: "f-r1", snapshotId: "r2" }, w.coord);
});

test("regression: hostile values raise LedgerError, never a raw TypeError or RangeError", () => {
  const w = new World().submitted();
  let deep: unknown = "x";
  for (let i = 0; i < 100_000; i++) deep = { submissionId: deep };
  const nested = { ...w.sign(findingBody("f1", { submissionId: "s1" }), w.key("b1")) };
  (nested.body as { target: unknown }).target = deep;
  w.rejectEntry("malformed", nested as LedgerEntry);
  const deepVerdict = { ...w.sign({ kind: "reviewReveal", submissionId: "s1", verdict: verdict(), salt: "s" }, w.key("b1")) };
  (deepVerdict.body as { verdict: unknown }).verdict = { defectProbability: 0.1, summary: deep, findingIds: [] };
  w.rejectEntry("malformed", deepVerdict as LedgerEntry);
  const big = { ...w.sign({ kind: "rulesChange", rules: defaultRules(), pollId: "p" }, w.admin) };
  (big.body as { rules: unknown }).rules = { ...defaultRules(), version: 2n };
  w.rejectEntry("malformed", big as LedgerEntry);
  assert.throws(() => replay([{ ...w.genesis, body: { ...w.genesis.body, rules: { version: 1n } } } as unknown as LedgerEntry]), isCode("malformed"));

  // the same from a file: deep nesting inside rules (shape-checked only after hashing)
  const depth = 100_000;
  const file = tamper((lines) => {
    const i = lines.findIndex((l) => l.includes('"kind":"rulesChange"'));
    const out = [...lines];
    out[i] = (lines[i] ?? "").replace('"rules":{', `"rules":{"deep":${'{"a":'.repeat(depth)}1${"}".repeat(depth)},`);
    return out;
  });
  assert.throws(() => Ledger.open(file), isCode("malformed"));
});

test("regression: appendSigned bounds a foreign entry's time by the writer's clock", () => {
  const { file, ledger, w } = freshLedger();
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  const body: EntryBody = { kind: "agentRegistered", owner: "alice", publicKey: w.key("a1").publicKey, modelFamily: "claude", harness: "cli" };
  const signedAt = (at: string) => signEntry(ledger.state(), body, w.key("alice"), at);
  const now = iso(60);
  assert.throws(() => ledger.appendSigned(signedAt("9000-01-01T00:00:00.000Z"), { now }), isCode("clock-skew"));
  assert.throws(() => ledger.appendSigned(signedAt(iso(2)), { now }), isCode("clock-skew"), "backdated past the skew");
  assert.throws(() => ledger.appendSigned(signedAt(iso(66)), { now }), isCode("clock-skew"));
  assert.throws(() => ledger.appendSigned(signedAt(iso(62)), { now, maxSkewMs: 60_000 }), isCode("clock-skew"));
  assert.equal(Ledger.open(file).entries().length, 2, "nothing was written");
  ledger.appendSigned(signedAt(iso(64)), { now });
  // the coordinator's next entry at real time still fits
  ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.admin, iso(64));
  assert.equal(Ledger.open(file).entries().length, 4);
});

// ---------------------------------------------------------------------------
// Hardening: input limits, verifiable assignment, model families, harness errors
// ---------------------------------------------------------------------------

test("limits: ids are bounded and spelled [A-Za-z0-9][A-Za-z0-9._:-]*", () => {
  const w = new World().people();
  const proposal = (id: string): EntryBody => ({ kind: "proposal", id, title: "t", evidence: [EVIDENCE] });
  const longest = `p${"x".repeat(LEDGER_LIMITS.id - 1)}`;
  w.apply(proposal(longest), w.key("a1"));
  w.reject("malformed", proposal(`${longest}x`), w.key("a1"));
  for (const bad of ["", ".", "..", "...", ".hidden", "a/b", "a b", "a\nb", "-x", "é"]) {
    w.reject("malformed", proposal(bad), w.key("a1"));
  }
  for (const good of ["a", "s-1", "v1.2", "snap:3", "A_b"]) w.apply(proposal(good), w.key("a1"));
  assert.ok(ID_RE.test("0xAbC") && !ID_RE.test(".."));
  // References are ids too: an over-long one is malformed before any lookup.
  w.reject("malformed", { kind: "gateResult", submissionId: "s".repeat(LEDGER_LIMITS.id + 1), gate: "g", pass: true, details: "" }, w.coord);
  w.reject("malformed", { kind: "ownerKey", owner: "a/b", publicKey: w.key("eve").publicKey, inviter: null }, w.admin);
});

test("limits: free-text fields are bounded", () => {
  const L = LEDGER_LIMITS;
  const w = new World().submitted();
  const text = (n: number) => "x".repeat(n);
  const cases: [EntryBody, EntryBody, Signer][] = [
    [
      { kind: "proposal", id: "pt1", title: text(L.title), evidence: [EVIDENCE] },
      { kind: "proposal", id: "pt2", title: text(L.title + 1), evidence: [EVIDENCE] },
      w.key("a1"),
    ],
    [
      { kind: "gateResult", submissionId: "s1", gate: "g", pass: true, details: text(L.text) },
      { kind: "gateResult", submissionId: "s1", gate: "g", pass: true, details: text(L.text + 1) },
      w.coord,
    ],
    [
      { kind: "settlement", owner: "alice", delta: 0, reason: "bounty", ref: text(L.ref) },
      { kind: "settlement", owner: "alice", delta: 0, reason: "bounty", ref: text(L.ref + 1) },
      w.coord,
    ],
    [
      { kind: "finding", id: "fl1", target: { submissionId: "s1" }, severity: "low", testPath: "t/a.sh", testCommand: text(L.command), stake: 5 },
      { kind: "finding", id: "fl2", target: { submissionId: "s1" }, severity: "low", testPath: "t/a.sh", testCommand: text(L.command + 1), stake: 5 },
      w.key("b1"),
    ],
    [
      { kind: "agentRegistered", owner: "bob", publicKey: w.key("b8").publicKey, modelFamily: "gpt", harness: text(L.name) },
      { kind: "agentRegistered", owner: "bob", publicKey: w.key("b9").publicKey, modelFamily: "gpt", harness: text(L.name + 1) },
      w.key("bob"),
    ],
    [
      { kind: "agentRevoked", agent: w.id("b8"), reason: text(L.text) },
      { kind: "agentRevoked", agent: w.id("b1"), reason: text(L.text + 1) },
      w.key("bob"),
    ],
  ];
  for (const [ok, tooLong, signer] of cases) {
    w.reject("malformed", tooLong, signer);
    w.apply(ok, signer);
  }
  // Evidence fields have their own limits, refused as invalid evidence.
  const withEvidence = (e: object): EntryBody => ({ kind: "proposal", id: "pe", title: "t", evidence: [e as never] });
  w.reject("invalid-evidence", withEvidence({ kind: "failingTest", testId: text(L.ref + 1), command: "c" }), w.key("a1"));
  w.reject("invalid-evidence", withEvidence({ kind: "location", file: "a.ts", line: 1, note: text(L.text + 1) }), w.key("a1"));
  w.reject("invalid-evidence", withEvidence({ kind: "location", file: "../a.ts", line: 1, note: "" }), w.key("a1"));
  w.reject("invalid-evidence", withEvidence({ kind: "diagnostic", tool: "tsc", message: "m", file: `${text(L.path)}.ts`, line: 1 }), w.key("a1"));
});

test("limits: paths are canonical POSIX and at most LEDGER_LIMITS.path long", () => {
  const w = new World().submitted();
  const longest = `src/${"p".repeat(LEDGER_LIMITS.path - 4)}`;
  assert.equal(isCanonicalPath(longest), true);
  assert.equal(isCanonicalPath(`${longest}x`), false);
  for (const bad of ["/etc/passwd", "a/../b", "../a", "./a", "a//b", "a\\b"]) assert.equal(isCanonicalPath(bad), false, bad);
  w.reject("invalid-value", submissionBody("sp1", null, { changedFiles: [`${longest}x`] }), w.key("b1"));
  w.apply(submissionBody("sp1", null, { changedFiles: [longest] }), w.key("b1"));
  w.reject("invalid-value", { ...findingBody("fp1", { submissionId: "s1" }), testPath: `${longest}x` } as EntryBody, w.key("b1"));
});

test("limits: lists are bounded", () => {
  const L = LEDGER_LIMITS;
  const w = new World().submitted();
  const files = (n: number) => Array.from({ length: n }, (_, i) => `src/f${i}.ts`);
  w.reject("malformed", submissionBody("sl1", null, { changedFiles: files(L.changedFiles + 1) }), w.key("b1"));
  w.apply(submissionBody("sl1", null, { changedFiles: files(L.changedFiles) }), w.key("b1"));
  const evidence = (n: number): EntryBody => ({ kind: "proposal", id: `pl${n}`, title: "t", evidence: Array(n).fill(EVIDENCE) });
  w.reject("malformed", evidence(L.evidence + 1), w.key("a1"));
  w.apply(evidence(L.evidence), w.key("a1"));
  const tests = (n: number) => taskBody(`tl${n}`, { acceptanceTestPaths: files(n).map((f) => `test/${f}`) });
  w.reject("malformed", tests(L.acceptanceTestPaths + 1), w.coord);
  w.apply(tests(L.acceptanceTestPaths), w.coord);
  const reviewers = Array.from({ length: L.reviewers + 1 }, (_, i) => w.id(`r${i}`));
  w.reject("malformed", assignmentBody(w.state, "s1", reviewers, "e"), w.coord);
  // findingIds per verdict: refused at reveal.
  w.assign("s1", ["b1"]);
  const many = verdict(0.1, Array.from({ length: L.findingIds + 1 }, (_, i) => `f${i}`));
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(many, "salt1", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: many, salt: "salt1" }, w.key("b1"));
  const long = { ...verdict(0.1), summary: "x".repeat(L.text + 1) };
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(long, "salt2", w.id("c1"), { submissionId: "s1" }), stake: 5 }, w.key("c1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: long, salt: "salt2" }, w.key("c1"));
  // submissionIds per snapshot
  const snap = (n: number): EntryBody => ({ kind: "snapshot", id: "rl", commit: "m", previousSnapshotId: null, submissionIds: files(n).map((_, i) => `x${i}`) });
  w.reject("malformed", snap(L.snapshotSubmissions + 1), w.coord);
  w.reject("unknown-ref", snap(L.snapshotSubmissions), w.coord); // within the limit, judged by the rules
});

test("reviewAssignment: the tree digest is the member tree's; the beacon must follow from submission, head commit and entropy", () => {
  const w = new World().submitted();
  const digest = memberDigest(w.state);
  const honest = assignmentBody(w.state, "s1", [w.id("b1")], "round-7");
  assert.equal(honest.kind === "reviewAssignment" && honest.treeDigest, digest);
  assert.equal(honest.kind === "reviewAssignment" && honest.beacon, assignmentBeacon("s1", "head-s1", "round-7"));
  // A beacon the coordinator chose, or one for other entropy or another tree, is refused.
  w.reject("invalid-value", { ...honest, beacon: sha256hex("chosen") }, w.coord);
  w.reject("invalid-value", { ...honest, entropy: "round-8" }, w.coord);
  w.reject("invalid-value", { ...honest, treeDigest: sha256hex("other tree") }, w.coord);
  // Another tree's digest with the right beacon: the tree is not the coordinator's to choose.
  w.reject("invalid-value", { ...honest, treeDigest: sha256hex("other tree"), beacon: assignmentBeacon("s1", "head-s1", "round-7") }, w.coord);
  w.reject("malformed", { ...honest, beacon: "b" }, w.coord);
  w.reject("malformed", { ...honest, treeDigest: "t" }, w.coord);
  w.reject("malformed", { ...honest, entropy: "" }, w.coord);
  const { entropy: _e, ...noEntropy } = honest as Extract<EntryBody, { kind: "reviewAssignment" }>;
  w.reject("malformed", noEntropy as EntryBody, w.coord);
  w.apply(honest, w.coord);
  const a = w.state.submissions.get("s1")?.assignment;
  assert.deepEqual(
    { entropy: a?.entropy, treeDigest: a?.treeDigest, beacon: a?.beacon },
    { entropy: "round-7", treeDigest: digest, beacon: (honest as { beacon: string }).beacon },
  );
});

test("agentRegistered: the model family must be one of rules.modelFamilies", () => {
  const w = new World().people();
  const reg = (agent: string, modelFamily: string): EntryBody => ({
    kind: "agentRegistered",
    owner: "bob",
    publicKey: w.key(agent).publicKey,
    modelFamily,
    harness: "cli",
  });
  for (const bad of ["Claude", "claude ", "anthropic", "GPT-4o"]) w.reject("invalid-value", reg(`x-${bad}`, bad), w.key("bob"));
  for (const f of defaultRules().modelFamilies) w.apply(reg(`ok-${f}`, f), w.key("bob"));
  // The list is the rules': a ratified change can add a family.
  w.apply({ kind: "rulesChange", rules: { ...w.state.rules, version: 2, modelFamilies: [...w.state.rules.modelFamilies, "grok"] }, pollId: "p" }, w.admin);
  w.apply(reg("ok-grok", "grok"), w.key("bob"));
  assert.equal(w.state.agents.get(w.id("ok-grok"))?.registeredSeq, w.state.length - 1);
});

test("findingResult: a harness error is recorded, never as a reproduction", () => {
  const w = new World().submitted();
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  const r = (over: Record<string, unknown>): EntryBody =>
    ({ kind: "findingResult", findingId: "f1", reproduced: false, failsOnHead: false, passesOnParent: false, logDigest: "d", ...over }) as EntryBody;
  w.reject("result-inconsistent", r({ reproduced: true, failsOnHead: true, passesOnParent: true, harnessError: "timeout" }), w.coord);
  w.reject("malformed", r({ harnessError: "" }), w.coord);
  w.reject("malformed", r({ harnessError: "x".repeat(LEDGER_LIMITS.text + 1) }), w.coord);
  w.reject("malformed", r({ harnessError: 3 }), w.coord);
  w.apply(r({ harnessError: "timed out 3 times" }), w.coord);
  assert.equal(w.state.findings.get("f1")?.result?.harnessError, "timed out 3 times");
  assert.equal(w.state.findings.get("f1")?.result?.reproduced, false);
  // The finding is decided either way: the merge is no longer held for it.
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, w.coord);
  w.assign("s1", ["c1"]);
  w.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
});

// ---------------------------------------------------------------------------
// Review findings fixed in the whole-system pass
// ---------------------------------------------------------------------------

test("commit phase: no reveal before the assignment, nor before every assigned reviewer committed or the phase ended", () => {
  const w = new World().submitted();
  const commit = (agent: string, p = 0.1, on: World = w): EntryBody => ({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(p), agent, on.id(agent), { submissionId: "s1" }), stake: 5 });
  const reveal = (agent: string, p = 0.1): EntryBody => ({ kind: "reviewReveal", submissionId: "s1", verdict: verdict(p), salt: agent });
  // A griefer commits as an open reviewer the moment the submission lands...
  w.apply(commit("d1"), w.key("d1"));
  w.reject("commit-phase", reveal("d1"), w.key("d1")); // ...but cannot reveal before the draw
  w.assign("s1", ["b1", "c1"]);
  w.reject("commit-phase", reveal("d1"), w.key("d1")); // nor before the assigned seats committed
  w.apply(commit("b1"), w.key("b1"));
  w.reject("commit-phase", reveal("b1"), w.key("b1"));
  w.apply(commit("c1"), w.key("c1")); // so every assigned seat can still commit
  w.apply(reveal("d1"), w.key("d1"));
  w.apply(reveal("b1"), w.key("b1"));

  // A seat that never commits holds reveals back only until the phase ends.
  const v = new World().submitted();
  v.assign("s1", ["b1", "c1"]);
  v.apply({ ...commit("b1", 0.1, v) }, v.key("b1"));
  v.reject("commit-phase", reveal("b1"), v.key("b1"));
  v.afterCommitPhase();
  v.reject("commit-closed", commit("c1", 0.1, v), v.key("c1"));
  v.apply(reveal("b1"), v.key("b1"));
});

test("regression: a reviewer cannot copy another's sealed commitment and reveal it as its own", () => {
  const w = new World().submitted();
  w.assign("s1", ["b1", "c1"]);
  const v = verdict(0.9);
  const sealed = commitOf(v, "bsalt", w.id("b1"), { submissionId: "s1" });
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: sealed, stake: 5 }, w.key("b1"));
  // The public commitment, reposted by an assigned seat and by an open reviewer.
  w.reject("duplicate-commit", { kind: "reviewCommit", submissionId: "s1", commitment: sealed, stake: 5 }, w.key("c1"));
  w.reject("duplicate-commit", { kind: "reviewCommit", submissionId: "s1", commitment: sealed, stake: 5 }, w.key("d1"));
  // Even a commitment computed the old way (verdict and salt only) gives the copier nothing.
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: sha256hex(canonical(v) + "bsalt"), stake: 5 }, w.key("c1"));
  w.apply({ kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "bsalt" }, w.key("b1"));
  w.reject("commitment-mismatch", { kind: "reviewReveal", submissionId: "s1", verdict: v, salt: "bsalt" }, w.key("c1"));

  // Attestations are bound the same way.
  const a = new World().snapshotted();
  const att = commitOf(v, "asalt", a.id("b1"), { snapshotId: "r1" });
  a.apply({ kind: "attestCommit", snapshotId: "r1", commitment: att, stake: 5 }, a.key("b1"));
  a.reject("duplicate-commit", { kind: "attestCommit", snapshotId: "r1", commitment: att, stake: 5 }, a.key("d1"));
});

test("findingDecision: an admin or a kernel signer not involved decides a reproduced finding once", () => {
  const w = new World().submitted(); // kernel signers carol and dave; alice wrote s1
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("c1")); // carol's agent filed it
  w.reject("not-decidable", confirm("f1"), w.admin); // no result yet
  w.apply(result("f1", true), w.coord);
  w.reject("unauthorised", confirm("f1"), w.key("bob")); // not a kernel signer
  w.reject("unauthorised", confirm("f1"), w.key("b1")); // agents never decide
  w.reject("unauthorised", confirm("f1"), w.coord); // nor the coordinator
  w.reject("same-owner", confirm("f1"), w.key("carol")); // her own owner's finding
  w.reject("unknown-ref", { kind: "findingDecision", findingId: "nope", confirmed: true, reason: "" }, w.admin);
  w.apply(confirm("f1", false), w.key("dave"));
  assert.equal(w.state.findings.get("f1")?.decision?.confirmed, false);
  w.reject("decided", confirm("f1"), w.admin);

  // A not-reproduced result has nothing to decide.
  w.apply(findingBody("f2", { submissionId: "s1" }), w.key("d1"));
  w.apply(result("f2", false), w.coord);
  w.reject("not-decidable", confirm("f2"), w.admin);

  // A kernel signer whose own work is the target does not decide either.
  const k = new World().people();
  k.apply(submissionBody("s1", null, { changedFiles: ["README.md"] }), k.key("d1")); // dave's
  k.apply(findingBody("f1", { submissionId: "s1" }), k.key("b1"));
  k.apply(result("f1", true), k.coord);
  k.reject("same-owner", confirm("f1"), k.key("dave"));
  k.apply(confirm("f1"), k.key("carol"));
});

test("mergeApproval: an operator other than the author's owner, once, before the merge", () => {
  const w = new World().people();
  w.apply(submissionBody("s1", null, { changedFiles: ["README.md"] }), w.key("c1")); // carol's
  const approve: EntryBody = { kind: "mergeApproval", submissionId: "s1" };
  w.reject("unauthorised", approve, w.key("bob"));
  w.reject("same-owner", approve, w.key("carol"));
  w.reject("unknown-ref", { kind: "mergeApproval", submissionId: "nope" }, w.admin);
  w.apply(approve, w.key("dave"));
  assert.equal(w.state.submissions.get("s1")?.approval?.by, w.id("dave"));
  w.reject("approved", approve, w.admin);
  const m = new World().merged();
  m.reject("merged", approve, m.admin);
});

test("reviewWindowClosed: names exactly the unrevealed assigned reviewers, once, before the merge", () => {
  const w = new World().submitted();
  const close = (missing: string[]): EntryBody => ({ kind: "reviewWindowClosed", submissionId: "s1", missing: missing.map((m) => w.id(m)) });
  w.reject("not-assigned", close([]), w.coord);
  w.assign("s1", ["b1", "c1"]);
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "b", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.afterCommitPhase();
  w.apply({ kind: "reviewReveal", submissionId: "s1", verdict: verdict(), salt: "b" }, w.key("b1"));
  w.reject("invalid-reviewers", close(["b1", "c1"]), w.coord);
  w.reject("unauthorised", close(["c1"]), w.admin);
  w.apply(close(["c1"]), w.coord);
  assert.deepEqual(w.state.submissions.get("s1")?.windowClosed?.missing, [w.id("c1")]);
  w.reject("window-closed", close(["c1"]), w.coord);
});

test("findingAttempt: harness errors are counted on the ledger until the result", () => {
  const w = new World().submitted();
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  const attempt: EntryBody = { kind: "findingAttempt", findingId: "f1", harnessError: "timed out" };
  w.reject("unauthorised", attempt, w.key("b1"));
  w.apply(attempt, w.coord);
  w.apply(attempt, w.coord);
  assert.equal(w.state.findings.get("f1")?.harnessErrors, 2);
  assert.equal(replay(w.entries).findings.get("f1")?.harnessErrors, 2, "it survives replay, unlike an in-memory count");
  w.apply(result("f1", false), w.coord);
  w.reject("result-exists", attempt, w.coord);
});

test("claims: a holder's unbroken run of extensions is capped unless it delivered; every claim stays in the history", () => {
  const w = new World().people();
  w.apply({ kind: "proposal", id: "p1", title: "fix", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply(taskBody("t1"), w.coord);
  const day = 24 * 60;
  const claim = (until: number): EntryBody => ({ kind: "claim", taskId: "t1", until: iso(until), stake: 6 });
  w.apply(claim(w.minute + 1 + 6 * day), w.key("c1"));
  w.minute += 5 * day;
  // 5 days in, extending to 7 days from now would run 12 days without a submission.
  w.reject("claim-too-long", claim(w.minute + 1 + 7 * day), w.key("c1"));
  w.apply(claim(w.minute + day), w.key("c1")); // within the run's cap
  w.apply(submissionBody("s1", "t1"), w.key("c1"));
  w.apply(claim(w.minute + 1 + 6 * day), w.key("c1")); // delivered since its previous claim: may go on
  assert.equal(w.state.claimHistory?.length, 3);
  assert.equal(w.state.claims.get("t1")?.since, w.state.claimHistory?.[0]?.at);
});

test("regression: a re-claim stamped exactly at `until` is an extension, so the run cap holds", () => {
  const w = new World().people();
  w.apply({ kind: "proposal", id: "p1", title: "fix", evidence: [EVIDENCE] }, w.key("a1"));
  w.apply(taskBody("t1"), w.coord);
  const day = 24 * 60;
  const claim = (until: number): EntryBody => ({ kind: "claim", taskId: "t1", until: iso(until), stake: 6 });
  let until = w.minute + 1 + 6 * day;
  w.apply(claim(until), w.key("c1"));
  w.minute = until - 1; // the next entry is stamped at exactly `until`
  // Live at its own `until`: another agent still waits...
  w.reject("claim-live", claim(until + day), w.key("d1"));
  w.minute = until - 1;
  // ...and the holder re-claiming then extends the same run, which may not pass 7 days.
  w.reject("claim-too-long", claim(until + 6 * day), w.key("c1"));
  until += 1;
  w.minute = until - 1;
  w.apply(claim(until + 6 * day), w.key("d1")); // a minute later it has lapsed: anyone may claim
});

test("promotion: main never moves backwards", () => {
  const w = new World().snapshotted(); // r1 holds s1
  w.apply(submissionBody("s2", null), w.key("c1"));
  w.apply(passGate("s2"), w.coord);
  w.assign("s2", ["d1"]);
  w.apply({ kind: "merge", submissionId: "s2", commit: "m2" }, w.coord);
  w.apply({ kind: "snapshot", id: "r2", commit: "m2", previousSnapshotId: "r1", submissionIds: ["s2"] }, w.coord);
  w.apply({ kind: "promotion", snapshotId: "r2", commit: "m2" }, w.coord);
  w.reject("promoted", { kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord); // r2 already shipped it

  // A later snapshot that does not name r1 still holds its content (dev is linear).
  const v = new World().snapshotted();
  v.apply(submissionBody("s2", null), v.key("c1"));
  v.apply(passGate("s2"), v.coord);
  v.assign("s2", ["d1"]);
  v.apply({ kind: "merge", submissionId: "s2", commit: "m2" }, v.coord);
  v.apply({ kind: "snapshot", id: "r2", commit: "m2", previousSnapshotId: null, submissionIds: ["s2"] }, v.coord);
  v.apply({ kind: "promotion", snapshotId: "r2", commit: "m2" }, v.coord);
  v.reject("promoted", { kind: "promotion", snapshotId: "r1", commit: "m1" }, v.coord);
});

test("settlement: one (owner, reason, ref) is settled once, whoever appends it", () => {
  const w = new World().people();
  const body: EntryBody = { kind: "settlement", owner: "alice", delta: 5, reason: "bounty", ref: "finding:f1" };
  w.apply(body, w.coord);
  w.reject("duplicate-settlement", body, w.coord);
  w.reject("duplicate-settlement", { ...body, delta: 7 } as EntryBody, w.coord);
  w.apply({ ...body, owner: "bob" } as EntryBody, w.coord);
  w.apply({ ...body, reason: "authorSlash", delta: -5 } as EntryBody, w.coord);
  assert.equal(replay(w.entries).owners.get("alice")?.reputationDelta, 0);
});

test("lockedStake: a dead submission releases its reviewers' stakes", () => {
  const w = new World().submitted();
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s", w.id("b1"), { submissionId: "s1" }), stake: 5 }, w.key("b1"));
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("c1"));
  w.apply(result("f1", true), w.coord);
  assert.equal(w.owner("bob").lockedStake, 5, "an undecided reproduction might still be dismissed");
  w.apply(confirm("f1"), w.admin);
  assert.equal(w.owner("bob").lockedStake, 0, "a confirmed defect never merges");
  const g = new World().submitted();
  g.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s", g.id("b1"), { submissionId: "s1" }), stake: 5 }, g.key("b1"));
  g.apply({ kind: "gateResult", submissionId: "s1", gate: "size", pass: false, details: "" }, g.coord);
  assert.equal(g.owner("bob").lockedStake, 0, "a failed gate never merges");
});

test("Ledger.refresh catches up with another writer and refuses a rewritten file", () => {
  const { file, ledger, w } = freshLedger();
  const other = Ledger.open(file);
  other.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  assert.throws(
    () => ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.admin, iso(2)),
    isCode("stale"),
  );
  assert.equal(ledger.refresh(), true);
  assert.ok(ledger.state().owners.has("alice"));
  ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.admin, iso(2));
  assert.equal(Ledger.open(file).entries().length, 3);
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").split("\n").slice(0, 1).join("\n") + "\n");
  fs.appendFileSync(file, `${JSON.stringify(signEntry({ seq: 1, prev: Ledger.open(file).entries()[0]?.hash ?? "" }, { kind: "ownerKey", owner: "carol", publicKey: w.key("carol").publicKey, inviter: null }, w.admin, iso(1)))}\n`);
  fs.appendFileSync(file, `${JSON.stringify(signEntry(Ledger.open(file).state(), { kind: "ownerKey", owner: "dave", publicKey: w.key("dave").publicKey, inviter: null }, w.admin, iso(1)))}\n`);
  fs.appendFileSync(file, `${JSON.stringify(signEntry(Ledger.open(file).state(), { kind: "ownerKey", owner: "erin", publicKey: w.key("erin").publicKey, inviter: null }, w.admin, iso(1)))}\n`);
  assert.throws(() => ledger.refresh(), isCode("stale"));
});

test("regression: an append that fails part way (a full disk) leaves no fragment, and `Ledger.repair` drops a torn line left by a crash", async () => {
  const { syncBuiltinESMExports } = await import("node:module");
  const nodeFs = (await import("node:fs")).default;
  const { file, ledger, w } = freshLedger();
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: w.key("alice").publicKey, inviter: null }, w.admin, iso(1));
  const real = nodeFs.appendFileSync;
  nodeFs.appendFileSync = ((p: fs.PathOrFileDescriptor, data: string | Uint8Array) => {
    nodeFs.writeFileSync(p, String(data).slice(0, 40), { flag: "a" });
    throw Object.assign(new Error("ENOSPC: no space left on device"), { code: "ENOSPC" });
  }) as typeof nodeFs.appendFileSync;
  syncBuiltinESMExports();
  try {
    assert.throws(() => ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.admin, iso(2)), /ENOSPC/);
  } finally {
    nodeFs.appendFileSync = real;
    syncBuiltinESMExports();
  }
  // Space is back: the same instance appends, and the file reopens.
  ledger.append({ kind: "ownerKey", owner: "bob", publicKey: w.key("bob").publicKey, inviter: null }, w.admin, iso(3));
  assert.equal(Ledger.open(file).state().owners.size, 2);
  // A crash mid-write leaves a torn line: open refuses it, repair drops it.
  fs.appendFileSync(file, '{"seq":3,"prev":"a03593');
  assert.throws(() => Ledger.open(file), isCode("torn"));
  assert.equal(Ledger.repair(file), 23);
  assert.equal(Ledger.open(file).entries().length, 3);
  assert.equal(Ledger.repair(file), 0, "nothing to repair");
  // A damaged complete line is never "repaired" away.
  fs.appendFileSync(file, "not json\n{");
  assert.throws(() => Ledger.repair(file));
});
