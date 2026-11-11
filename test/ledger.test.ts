import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { canonical, generateKeyPair, keyIdOf, sha256hex, sign } from "../src/crypto";
import {
  applyEntry,
  emptyState,
  entryHash,
  entryMessage,
  genesisEntry,
  Ledger,
  LedgerError,
  type LedgerErrorCode,
  type GenesisBody,
  type LedgerState,
  replay,
  signEntry,
  type Signer,
} from "../src/ledger";
import { defaultRules } from "../src/rules";
import type { EntryBody, LedgerEntry, ReviewVerdict, Rules } from "../src/types";

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
    return { kind: "genesis", project: "anthill", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules };
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

  // s1 passes a gate and merges
  merged(): this {
    this.submitted();
    this.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, this.coord);
    this.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, this.coord);
    return this;
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
    changedFiles: ["anthill-backend/src/routes.ts"],
    linesChanged: 20,
    ...over,
  } as EntryBody;
}

const verdict = (p = 0.1, findingIds: string[] = []): ReviewVerdict => ({ defectProbability: p, summary: "ok", findingIds });
const commitOf = (v: ReviewVerdict, salt: string) => sha256hex(canonical(v) + salt);

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
  assert.equal(w.state.project, "anthill");
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
  assert.deepEqual(w.owner("bob"), { id: "bob", keyId: w.id("bob"), inviter: "alice", reputationDelta: 0, lockedStake: 0 });
  assert.equal(w.state.ownerByKey.get(w.id("bob")), "bob");
});

test("ownerKey: owner ids and keys are unique; inviter must exist; key must be valid", () => {
  const w = new World().people();
  w.reject("duplicate-id", { kind: "ownerKey", owner: "alice", publicKey: w.key("x").publicKey, inviter: null }, w.admin);
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
  w.apply({ kind: "claim", taskId: "t1", until: iso(10_000), stake: 6 }, w.key("b1"), iso(800));
  assert.equal(w.state.claims.get("t1")?.agent, w.id("b1"));
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
  const assign = (reviewers: string[]): EntryBody => ({ kind: "reviewAssignment", submissionId: "s1", beacon: "b", reviewers });
  w.reject("unknown-ref", { kind: "reviewAssignment", submissionId: "nope", beacon: "b", reviewers: [w.id("b1")] }, w.coord);
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
  m.reject("merged", { kind: "reviewAssignment", submissionId: "s1", beacon: "b", reviewers: [m.id("b1")] }, m.coord);
});

test("reviewCommit: before merge, not by the author's owner, once per agent, enough stake", () => {
  const w = new World().submitted();
  const c = (stake = 5): EntryBody => ({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s"), stake });
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
  const v = verdict(0.3);
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(v, "salt-b1"), stake: 5 }, w.key("b1"));
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
  const bad = { defectProbability: 1.5, summary: "", findingIds: [] };
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(bad, "s"), stake: 5 }, w.key("b1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: bad, salt: "s" }, w.key("b1"));
  const extra = { ...verdict(), approve: true } as ReviewVerdict;
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(extra, "s"), stake: 5 }, w.key("c1"));
  w.reject("invalid-verdict", { kind: "reviewReveal", submissionId: "s1", verdict: extra, salt: "s" }, w.key("c1"));
});

test("reviewReveal: cited findings must exist and target this submission", () => {
  const w = new World().submitted();
  w.apply(submissionBody("s9", null), w.key("c1"));
  w.apply(findingBody("f-other", { submissionId: "s9" }), w.key("b1"));
  w.apply(findingBody("f1", { submissionId: "s1" }), w.key("b1"));
  const ghost = verdict(0.8, ["ghost"]);
  const elsewhere = verdict(0.8, ["f-other"]);
  const good = verdict(0.8, ["f1"]);
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(ghost, "x"), stake: 5 }, w.key("b1"));
  w.reject("unknown-ref", { kind: "reviewReveal", submissionId: "s1", verdict: ghost, salt: "x" }, w.key("b1"));
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(elsewhere, "x"), stake: 5 }, w.key("c1"));
  w.reject("invalid-target", { kind: "reviewReveal", submissionId: "s1", verdict: elsewhere, salt: "x" }, w.key("c1"));
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(good, "x"), stake: 5 }, w.key("d1"));
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
  v.reject("reproduced-finding", merge, v.coord);

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
  w.apply({ kind: "merge", submissionId: "s2", commit: "m2" }, w.coord);
  w.reject("already-snapshotted", snap("r2", ["s1", "s2"]), w.coord);
  w.reject("invalid-value", snap("r2", ["s2", "s2"]), w.coord);
  w.apply(snap("r2", ["s2"]), w.coord);
  assert.equal(w.state.snapshots.get("r2")?.previousSnapshotId, "r1");
});

test("attestCommit/attestReveal: any active non-author agent, once each, before promotion", () => {
  const w = new World().snapshotted();
  const v = verdict(0.05);
  const commit = (stake = 5): EntryBody => ({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(v, "q"), stake });
  w.reject("unknown-ref", { kind: "attestCommit", snapshotId: "nope", commitment: commitOf(v, "q"), stake: 5 }, w.key("b1"));
  w.reject("stake", commit(1), w.key("b1"));
  w.reject("unauthorised", commit(), w.key("bob"));
  w.reject("same-owner", commit(), w.key("a2")); // alice wrote s1, which r1 ships
  w.apply(commit(), w.key("b1"));
  w.reject("duplicate-commit", commit(), w.key("b1"));
  w.reject("no-commit", { kind: "attestReveal", snapshotId: "r1", verdict: v, salt: "q" }, w.key("d1"));

  // cited findings must target the snapshot itself
  w.apply(findingBody("f-sub", { submissionId: "s1" }), w.key("c1"));
  const cites = verdict(0.5, ["f-sub"]);
  w.apply({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(cites, "q"), stake: 5 }, w.key("c1"));
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
  w.apply(reveal("s1", salt), w.admin);
  assert.deepEqual(w.state.submissions.get("s1")?.planted, { severity: "medium", description: "off by one" });
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
  w.reject("stake", { kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s"), stake: 5 }, w.key("b1"));
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
  w.apply({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(verdict(), "s"), stake: 7 }, w.key("b1"));
  w.apply(findingBody("f1", { submissionId: "s1" }, 6), w.key("b1"));
  assert.equal(w.owner("bob").lockedStake, 13);
  w.apply({ kind: "findingResult", findingId: "f1", reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "" }, w.coord);
  assert.equal(w.owner("bob").lockedStake, 7);
  w.apply({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: "" }, w.coord);
  w.apply({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  assert.equal(w.owner("bob").lockedStake, 0);
  assert.equal(w.owner("alice").lockedStake, 0, `claim of ${aliceClaim} released by merge`);
  w.apply({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, w.coord);
  w.apply({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(verdict(), "s"), stake: 9 }, w.key("c1"));
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
  add({ kind: "reviewAssignment", submissionId: "s1", beacon: "beacon", reviewers: [w.id("b1"), w.id("c1")] }, w.coord);
  const vb = verdict(0.1);
  const vc = verdict(0.2, ["f1"]);
  add({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(vb, "sb"), stake: 5 }, w.key("b1"));
  add(findingBody("f1", { submissionId: "s1" }), w.key("c1"));
  add({ kind: "reviewCommit", submissionId: "s1", commitment: commitOf(vc, "sc"), stake: 5 }, w.key("c1"));
  add({ kind: "reviewReveal", submissionId: "s1", verdict: vb, salt: "sb" }, w.key("b1"));
  add({ kind: "reviewReveal", submissionId: "s1", verdict: vc, salt: "sc" }, w.key("c1"));
  add({ kind: "findingResult", findingId: "f1", reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d" }, w.coord);
  add({ kind: "settlement", owner: "carol", delta: -5, reason: "falseFinding", ref: "f1" }, w.coord);
  add({ kind: "merge", submissionId: "s1", commit: "m1" }, w.coord);
  add({ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: "s1" }, w.coord);
  add({ kind: "plantReveal", submissionId: "s-plant", salt: "pepper", description: "planted", severity: "high" }, w.admin);
  add({ kind: "snapshot", id: "r1", commit: "m1", previousSnapshotId: null, submissionIds: ["s1"] }, w.coord);
  const va = verdict(0.05);
  add({ kind: "attestCommit", snapshotId: "r1", commitment: commitOf(va, "sa"), stake: 5 }, w.key("b1"));
  add({ kind: "attestReveal", snapshotId: "r1", verdict: va, salt: "sa" }, w.key("b1"));
  add({ kind: "signoff", snapshotId: "r1" }, w.key("carol"));
  add({ kind: "signoff", snapshotId: "r1" }, w.key("dave"));
  add({ kind: "promotion", snapshotId: "r1", commit: "m1" }, w.coord);
  add(findingBody("f2", { snapshotId: "r1" }), w.key("b1"));
  add({ kind: "findingResult", findingId: "f2", reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" }, w.coord);
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
  assert.deepEqual(s.submissions.get("s-plant")?.planted, { severity: "high", description: "planted" });
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
