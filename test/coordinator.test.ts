import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, signEntry, type LedgerState, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import {
  BINDING_GATE,
  executeActions,
  localReproducer,
  mergeReadiness,
  patchBinding,
  planActions,
  runOnce,
  type Action,
  type ExecuteDeps,
  type IncentivesApi,
  type PlanOptions,
  type PromotionApi,
  type ReproductionOutcome,
  type SelectionApi,
  type SettlementBody,
  type TaskBody,
} from "../src/coordinator";
import type { CommonsState, EntryBody, LedgerEntry, ReviewVerdict, Severity } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: an in-memory ledger with a minute clock, fake incentives /
// selection / promotion, a fake patch binder (bot head = "bot-<id>") and an
// executor whose effects are recorded.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();
const tree = treeFromParents({ alice: null, bob: "alice", carol: "alice", dave: "bob" });

// Idempotent by construction (checks recorded settlements), like the contract.
const settled = (state: CommonsState, b: SettlementBody) =>
  state.settlements.some((s) => s.owner === b.owner && s.reason === b.reason && s.ref === b.ref);
const ownerOfAgent = (state: CommonsState, agent: string) => state.agents.get(agent)?.owner ?? "";

const fakeIncentives: IncentivesApi = {
  settleMerge: (state, sid, tranche) => {
    const s = state.submissions.get(sid);
    if (!s) return [];
    const b: SettlementBody = { kind: "settlement", owner: ownerOfAgent(state, s.author), delta: 10, reason: "mergeVest", ref: `${sid}#${tranche}` };
    return settled(state, b) ? [] : [b];
  },
  settleFinding: (state, _tree, fid, stage) => {
    const f = state.findings.get(fid);
    if (!f) return [];
    const b: SettlementBody = { kind: "settlement", owner: ownerOfAgent(state, f.finder), delta: 5, reason: "bounty", ref: `${fid}@${stage}` };
    return settled(state, b) ? [] : [b];
  },
  settleFalseFinding: (state, fid) => {
    const f = state.findings.get(fid);
    if (!f) return [];
    const b: SettlementBody = { kind: "settlement", owner: ownerOfAgent(state, f.finder), delta: -5, reason: "falseFinding", ref: fid };
    return settled(state, b) ? [] : [b];
  },
  settleHoneytoken: (state, agent) => {
    const b: SettlementBody = { kind: "settlement", owner: ownerOfAgent(state, agent), delta: -50, reason: "honeytoken", ref: agent };
    return settled(state, b) ? [] : [b];
  },
  settleCleanReviews: () => [],
  settleMissedPlant: () => [],
  settleExpiredClaims: () => [],
};

let promotionPasses = false;
const fakePromotion: PromotionApi = {
  evaluatePromotion: () => ({ pass: promotionPasses, checks: [{ name: "fake", pass: promotionPasses, detail: "" }] }),
};

// Every active agent whose owner differs from the author's, one per owner, two at most.
const fakeSelection: SelectionApi = {
  computeBeacon: (state, sid, entropy) => sha256hex(`${state.headHash}:${sid}:${entropy}`),
  selectReviewers: (state, _tree, sid) => {
    const author = ownerOfAgent(state, state.submissions.get(sid)?.author ?? "");
    const owners = new Set<string>();
    const reviewers: string[] = [];
    for (const a of state.agents.values()) {
      if (!a.active || a.owner === author || owners.has(a.owner)) continue;
      owners.add(a.owner);
      reviewers.push(a.keyId);
      if (reviewers.length === 2) break;
    }
    return { reviewers, candidates: reviewers.length, notes: [] };
  },
};

const verdictOf = (p: number): ReviewVerdict => ({ defectProbability: p, summary: "ok", findingIds: [] });

class World {
  admin = generateKeyPair();
  coord = generateKeyPair();
  keys = new Map<string, Signer>();
  minute = 0;
  state: LedgerState;
  entries: LedgerEntry[];
  approved = new Set<string>();
  confirmed = new Set<string>();
  bridgeCalls: string[] = [];
  bridgeFails = false;
  reproductions = new Map<string, ReproductionOutcome>();
  reproduceCalls: string[] = [];
  harnessErrors = new Map<string, number>();
  gateResult = true;
  unpatched = new Set<string>(); // the binder has no patch for these
  unbindable = new Set<string>(); // the patch does not apply
  private queue: Promise<unknown> = Promise.resolve();

  constructor() {
    const rules = { ...defaultRules(), kernelSigners: ["carol", "dave"] };
    const g = genesisEntry(
      { kind: "genesis", project: "anthill", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
      iso(0),
    );
    this.state = emptyState(g);
    this.entries = [g];
    this.apply({ kind: "ownerKey", owner: "alice", publicKey: this.key("alice").publicKey, inviter: null }, this.admin);
    for (const o of ["bob", "carol", "dave"]) {
      this.apply({ kind: "ownerKey", owner: o, publicKey: this.key(o).publicKey, inviter: "alice" }, this.admin);
    }
    for (const [agent, owner, family] of [
      ["a1", "alice", "claude"],
      ["b1", "bob", "gpt"],
      ["c1", "carol", "qwen"],
      ["d1", "dave", "kimi"],
    ] as const) {
      this.apply(
        { kind: "agentRegistered", owner, publicKey: this.key(agent).publicKey, modelFamily: family, harness: "cli" },
        this.key(owner),
      );
    }
  }

  key(name: string): Signer {
    let k = this.keys.get(name);
    if (!k) this.keys.set(name, (k = generateKeyPair()));
    return k;
  }

  id(name: string): string {
    return keyIdOf(this.key(name).publicKey);
  }

  name(keyId: string): string {
    return [...this.keys.keys()].find((n) => this.id(n) === keyId) ?? "";
  }

  now(): string {
    return iso(this.minute);
  }

  advance(minutes: number): void {
    this.minute += minutes;
  }

  apply(body: EntryBody, signer: Signer): LedgerEntry {
    this.minute += 1;
    const e = signEntry(this.state, body, signer, this.now());
    applyEntry(this.state, e);
    this.entries.push(e);
    return e;
  }

  // Like LedgerStore.appendAsCoordinator: one locked call at a time.
  appendLocked(body: EntryBody | ((s: CommonsState) => EntryBody | Promise<EntryBody>)): Promise<LedgerEntry> {
    const run = this.queue.then(async () => this.apply(typeof body === "function" ? await body(this.state) : body, this.coord));
    this.queue = run.catch(() => undefined);
    return run;
  }

  submit(id: string, agent = "a1"): void {
    this.apply(
      { kind: "submission", id, taskId: null, baseCommit: `base-${id}`, headCommit: `head-${id}`, changedFiles: ["src/x.ts"], linesChanged: 3 },
      this.key(agent),
    );
  }

  // Commits close once any verdict is revealed, so tests commit every
  // reviewer first and reveal afterwards.
  commit(sid: string, agent: string, p = 0.1): void {
    this.apply({ kind: "reviewCommit", submissionId: sid, commitment: sha256hex(canonical(verdictOf(p)) + `salt-${agent}`), stake: 5 }, this.key(agent));
  }

  reveal(sid: string, agent: string, p = 0.1): void {
    this.apply({ kind: "reviewReveal", submissionId: sid, verdict: verdictOf(p), salt: `salt-${agent}` }, this.key(agent));
  }

  reviewers(sid: string): string[] {
    return (this.state.submissions.get(sid)?.assignment?.reviewers ?? []).map((r) => this.name(r));
  }

  // Every assigned reviewer commits, then the first `n` reveal.
  reviewAll(sid: string, n = Infinity): void {
    const rs = this.reviewers(sid);
    assert.ok(rs.length > 0, `no reviewers on ${sid}`);
    for (const r of rs) this.commit(sid, r);
    for (const r of rs.slice(0, n)) this.reveal(sid, r);
  }

  finding(id: string, target: { submissionId: string } | { snapshotId: string }, severity: Severity, agent = "b1"): void {
    this.apply(
      { kind: "finding", id, target, severity, testPath: `test/${id}.test.ts`, testCommand: "npm test", stake: 5 },
      this.key(agent),
    );
  }

  opts(extra: Partial<PlanOptions> = {}): PlanOptions {
    return {
      reviewWindowHours: 24,
      humanApproval: (sid) => this.approved.has(sid),
      findingConfirmed: (fid) => this.confirmed.has(fid),
      harnessErrors: (fid) => this.harnessErrors.get(fid) ?? 0,
      snapshotEvery: 2,
      entries: this.entries,
      incentives: fakeIncentives,
      promotion: fakePromotion,
      ...extra,
    };
  }

  plan(extra: Partial<PlanOptions> = {}): Action[] {
    return planActions(this.state, tree, this.now(), this.opts(extra));
  }

  deps(extra: Partial<PlanOptions> = {}): ExecuteDeps {
    return {
      state: () => this.state,
      append: (body) => this.appendLocked(body),
      tree,
      recheck: { clock: () => this.now(), opts: this.opts(extra) },
      entropy: (sid) => `round-${sid}`,
      bindPatch: async (s) => {
        if (this.unpatched.has(s.id)) return null;
        if (this.unbindable.has(s.id)) return { error: "hunk 1 does not apply" };
        return { head: `bot-${s.id}`, patchSha256: sha256hex(s.id) };
      },
      runGates: async (s, gates) =>
        (gates ?? ["size", "rings"]).map((gate) => ({ gate, pass: this.gateResult, details: `${gate} on ${s.headCommit}` })),
      reproduce: async (a) => {
        this.reproduceCalls.push(`${a.findingId}@${a.headCommit}`);
        return this.reproductions.get(a.findingId) ?? null;
      },
      harnessErrors: this.harnessErrors,
      bridge: {
        merge: async (s, expected) => {
          if (this.bridgeFails) throw new Error("github down");
          this.bridgeCalls.push(`merge ${s.id} ${expected}`);
          return `merge-${s.id}`;
        },
        fastForwardMain: async (commit) => {
          this.bridgeCalls.push(`ff ${commit}`);
        },
      },
      selection: fakeSelection,
    };
  }

  exec(actions: readonly Action[], extra: Partial<PlanOptions> = {}) {
    return executeActions(actions, this.deps(extra));
  }

  // Plan + execute until nothing is left (bounded).
  async settle(extra: Partial<PlanOptions> = {}): Promise<void> {
    for (let i = 0; i < 20; i++) {
      const actions = this.plan(extra);
      if (actions.length === 0) return;
      const log = await this.exec(actions, extra);
      if (log.every((l) => !l.ok || l.detail.startsWith("skipped"))) return; // stuck
    }
    assert.fail("loop did not settle");
  }

  // Submit, bind, gate and assign; approve in phase 1.
  async ready(id: string, agent = "a1"): Promise<void> {
    this.submit(id, agent);
    this.approved.add(id);
    await this.settle();
    assert.ok(this.state.submissions.get(id)?.assignment, `${id} has reviewers`);
  }
}

const kinds = (actions: readonly Action[]) => actions.map((a) => a.kind);

// ---------------------------------------------------------------------------
// Binding and gates
// ---------------------------------------------------------------------------

test("a new submission is bound to its patch first; gates run on the bound head, never the declared one", async () => {
  const w = new World();
  w.submit("s1");
  assert.deepEqual(w.plan(), [{ kind: "bindPatch", submissionId: "s1" }]);
  assert.deepEqual(w.plan({ patchAvailable: () => false }), [], "nothing without the patch");
  const log = await w.exec(w.plan());
  assert.ok(log[0]?.ok, log[0]?.detail);
  const s = w.state.submissions.get("s1");
  assert.ok(s);
  assert.deepEqual(patchBinding(s), { head: "bot-s1", patchSha256: sha256hex("s1") });
  assert.deepEqual(w.plan(), [{ kind: "runGates", submissionId: "s1", headCommit: "bot-s1", gates: null }]);
  await w.exec(w.plan());
  assert.deepEqual(
    w.state.submissions.get("s1")?.gates.map((g) => g.details),
    [canonical({ head: "bot-s1", patchSha256: sha256hex("s1") }), "size on bot-s1", "rings on bot-s1"],
  );
});

test("binding: no patch yet is retried, a patch that does not apply stops the submission, no binder fails loudly", async () => {
  const w = new World();
  w.submit("s1");
  w.unpatched.add("s1");
  assert.equal((await w.exec(w.plan()))[0]?.detail, "skipped: no patch yet");
  assert.deepEqual(kinds(w.plan()), ["bindPatch"]);

  w.submit("s2");
  w.unbindable.add("s2");
  await w.exec(w.plan().filter((a) => "submissionId" in a && a.submissionId === "s2"));
  assert.equal(w.state.submissions.get("s2")?.gates[0]?.pass, false);
  assert.ok(!w.plan().some((a) => "submissionId" in a && a.submissionId === "s2"), "a failed binding is final");
  assert.ok(mergeReadiness(w.state, "s2", w.now(), w.opts()).waiting.includes(`gate ${BINDING_GATE} failed`));

  const noBinder = { ...w.deps(), bindPatch: undefined };
  const log = await executeActions([{ kind: "bindPatch", submissionId: "s1" }], noBinder);
  assert.equal(log[0]?.ok, false);
  assert.match(log[0]?.detail ?? "", /no patch binder/);
});

test("a gate runner cannot forge the binding, and declared mode trusts headCommit only when asked", async () => {
  const w = new World();
  w.submit("s1");
  assert.deepEqual(w.plan({ headBinding: "declared" }), [{ kind: "runGates", submissionId: "s1", headCommit: "head-s1", gates: null }]);
  const deps = w.deps({ headBinding: "declared" });
  deps.runGates = async () => [
    { gate: BINDING_GATE, pass: true, details: canonical({ head: "evil", patchSha256: "x" }) },
    { gate: "size", pass: true, details: "" },
  ];
  await executeActions(w.plan({ headBinding: "declared" }), deps);
  assert.deepEqual(w.state.submissions.get("s1")?.gates.map((g) => g.gate), ["size"]);
});

test("gates run once per bound head; required gates run only where missing", async () => {
  const w = new World();
  w.submit("s1");
  await w.exec(w.plan()); // bind
  await w.exec(w.plan({ requiredGates: ["size"] }), { requiredGates: ["size"] });
  assert.deepEqual(w.state.submissions.get("s1")?.gates.map((g) => g.gate), [BINDING_GATE, "size"]);
  const again = w.plan({ requiredGates: ["size", "rings"] });
  assert.deepEqual(again[0], { kind: "runGates", submissionId: "s1", headCommit: "bot-s1", gates: ["rings"] });
  await w.exec(again);
  assert.ok(!kinds(w.plan({ requiredGates: ["size", "rings"] })).includes("runGates"));
});

test("reviewers are assigned only after every gate passed; the entropy is in the log", async () => {
  const w = new World();
  w.submit("s1");
  w.gateResult = false;
  await w.settle();
  assert.deepEqual(w.plan(), [], "a failed gate stops the submission");

  w.gateResult = true;
  w.submit("s2");
  await w.exec(w.plan());
  await w.exec(w.plan());
  assert.deepEqual(w.plan(), [{ kind: "assignReviewers", submissionId: "s2" }]);
  const log = await w.exec(w.plan());
  assert.ok(log[0]?.ok, log[0]?.detail);
  const a = w.state.submissions.get("s2")?.assignment;
  assert.ok(a);
  assert.equal(a.reviewers.length, 2);
  // The beacon covers the head hash the assignment was appended to.
  const before = w.entries[a.seq - 1];
  assert.equal(a.beacon, sha256hex(`${before?.hash}:s2:round-s2`));
  assert.match(log[0]?.detail ?? "", /entropy "round-s2"/);
});

// ---------------------------------------------------------------------------
// Merges
// ---------------------------------------------------------------------------

test("merge waits for all reveals and human approval; phase 2 needs no human; the bridge gets the bound head", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  const [r1, r2] = w.reviewers("s1");
  assert.ok(r1 && r2);
  w.commit("s1", r1);
  w.commit("s1", r2);
  w.reveal("s1", r1);
  assert.deepEqual(w.plan(), [], "one reviewer has not revealed");
  w.reveal("s1", r2);
  assert.deepEqual(w.plan(), [], "phase 1: no merge without human approval");
  assert.deepEqual(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting, ["awaiting human approval"]);
  assert.deepEqual(w.plan({ phase: 2 }), [{ kind: "merge", submissionId: "s1" }]);
  assert.deepEqual(w.plan({ humanApproval: undefined }), [], "no approval function means never approved");

  w.approved.add("s1");
  assert.deepEqual(w.plan(), [{ kind: "merge", submissionId: "s1" }]);
  await w.exec(w.plan());
  assert.equal(w.state.submissions.get("s1")?.merged?.commit, "merge-s1");
  assert.deepEqual(w.bridgeCalls, ["merge s1 bot-s1"]);
  // Next pass settles the first tranche, once.
  assert.deepEqual(kinds(w.plan()), ["settle"]);
  await w.exec(w.plan());
  assert.deepEqual(w.plan(), []);
});

test("after the review window a quorum of reveals merges; the rest count as missing", async () => {
  const w = new World();
  await w.ready("s1");
  const ids = w.state.submissions.get("s1")?.assignment?.reviewers ?? [];
  w.reviewAll("s1", 1);
  assert.deepEqual(w.plan(), []);
  w.advance(24 * 60);
  assert.deepEqual(w.plan(), [
    { kind: "revealPhaseClose", submissionId: "s1", missing: [ids[1]] },
    { kind: "merge", submissionId: "s1" },
  ]);
  assert.deepEqual(w.plan({ reviewQuorum: 2 }), [], "an explicit quorum of two is not met");
});

test("a window that closes with no reveal never merges, even in phase 2", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1", 0); // committed, nobody revealed
  w.advance(48 * 60);
  assert.deepEqual(w.plan({ phase: 2 }), []);
  const r = mergeReadiness(w.state, "s1", w.now(), w.opts({ phase: 2 }));
  assert.match(r.waiting.join("; "), /review quorum not met: 0 of 1/);
});

test("the review window fails closed: without entries it never counts as closed", async () => {
  const w = new World();
  w.submit("s1");
  w.approved.add("s1");
  w.advance(23 * 60); // gates run late: the submission is 23h old at assignment
  await w.settle();
  w.reviewAll("s1", 1);
  w.advance(2 * 60);
  assert.deepEqual(w.plan(), [], "only ~2h since assignment");
  w.advance(30 * 24 * 60);
  assert.deepEqual(w.plan({ entries: undefined }), [], "unknown assignment time: not closed");
  assert.deepEqual(kinds(w.plan()), ["revealPhaseClose", "merge"]);
});

test("never merges with a reproduced finding, even when approved", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  const merge = w.plan();
  assert.deepEqual(kinds(merge), ["merge"]);
  w.finding("f1", { submissionId: "s1" }, "low");
  // Any undecided finding blocks (the ledger refuses finding-pending merges),
  // and it is reproduced against the bound head.
  assert.deepEqual(w.plan(), [
    { kind: "reproduceFinding", findingId: "f1", baseCommit: "base-s1", headCommit: "bot-s1", testPath: "test/f1.test.ts", testCommand: "npm test" },
  ]);
  // A merge planned before the finding arrived is re-checked against live
  // state before the bridge is called.
  const stale = await w.exec(merge);
  assert.equal(stale[0]?.ok, false);
  assert.match(stale[0]?.detail ?? "", /unresolved low finding f1/);
  w.reproductions.set("f1", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  await w.exec(w.plan());
  const after = await w.exec(merge);
  assert.match(after[0]?.detail ?? "", /reproduced finding f1/);
  assert.deepEqual(w.bridgeCalls, []);
  assert.equal(w.state.submissions.get("s1")?.merged, undefined);
  for (let i = 0; i < 3; i++) {
    const next = w.plan({ phase: 2 });
    assert.ok(!kinds(next).includes("merge"));
    await w.exec(next, { phase: 2 });
  }
  assert.ok(w.state.settlements.some((s) => s.reason === "bounty" && s.ref === "f1@dev"));
});

test("the merge re-asks the human under the lock: a withdrawn approval stops it", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  const plan = w.plan();
  assert.deepEqual(kinds(plan), ["merge"]);
  w.approved.delete("s1");
  const log = await w.exec(plan);
  assert.equal(log[0]?.ok, false);
  assert.match(log[0]?.detail ?? "", /awaiting human approval/);
  assert.deepEqual(w.bridgeCalls, []);
  // An async approver is consulted at merge time too.
  const asked: string[] = [];
  const deps = w.deps();
  deps.recheck = { ...deps.recheck, humanApproval: async (sid) => (asked.push(sid), false) };
  w.approved.add("s1");
  assert.equal((await executeActions(plan, deps))[0]?.ok, false);
  assert.deepEqual(asked, ["s1"]);
});

test("a failing bridge leaves no merge entry and the merge is retried", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.bridgeFails = true;
  const log = await w.exec(w.plan());
  assert.ok(log.some((l) => l.action.kind === "merge" && !l.ok));
  assert.equal(w.state.submissions.get("s1")?.merged, undefined);
  assert.ok(kinds(w.plan()).includes("merge"));
});

test("a suspended author's open submissions stop where they are", async () => {
  const w = new World();
  await w.ready("s1");
  w.submit("s2");
  w.reviewAll("s1");
  w.apply({ kind: "agentRevoked", agent: w.id("a1"), reason: "honeytoken" }, w.coord);
  assert.deepEqual(w.plan({ phase: 2 }), []);
  assert.ok(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting.includes("author suspended"));
});

test("while a plant commitment is unrevealed, later merges wait for the window plus grace", async () => {
  const w = new World();
  w.apply({ kind: "plantCommit", commitment: sha256hex("s1:salt") }, w.admin);
  await w.ready("s1");
  w.reviewAll("s1");
  assert.deepEqual(w.plan(), [], "all revealed, but the custodian may not have revealed yet");
  assert.ok(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting.some((x) => x.startsWith("plant reveal grace")));
  w.advance(24 * 60 + 61);
  assert.deepEqual(kinds(w.plan()), ["merge"], "window + 1h grace passed");
  w.apply({ kind: "plantReveal", submissionId: "s1", salt: "salt", description: "off by one", severity: "medium" }, w.admin);
  assert.deepEqual(w.plan().filter((a) => a.kind === "merge"), [], "the revealed plant never merges");
});

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

test("a finding whose test never arrives is voided after the grace period, and the merge proceeds", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.finding("f1", { submissionId: "s1" }, "high");
  const noTest = { findingTestAvailable: (fid: string) => fid !== "f1" };
  assert.deepEqual(w.plan(noTest), [], "waits for the test within the grace period");
  await w.exec(w.plan()); // unknown availability: reproducer has nothing, skipped
  assert.deepEqual(kinds(w.plan()), ["reproduceFinding"]);
  w.advance(24 * 60);
  assert.deepEqual(w.plan(noTest), [{ kind: "voidFinding", findingId: "f1", reason: "no-test" }]);
  await w.exec(w.plan(noTest));
  assert.deepEqual(w.state.findings.get("f1")?.result, {
    reproduced: false,
    failsOnHead: false,
    passesOnParent: false,
    logDigest: "void:no-test",
    seq: w.state.findings.get("f1")?.result?.seq,
  });
  const next = w.plan(noTest);
  assert.deepEqual(kinds(next), ["settle", "merge"]);
  assert.equal((next[0] as Extract<Action, { kind: "settle" }>).bodies[0]?.reason, "falseFinding");
});

test("harness errors are counted and the finding is voided after maxHarnessErrors", async () => {
  const w = new World();
  await w.ready("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  w.reproductions.set("f1", { reproduced: false, failsOnHead: false, passesOnParent: false, logDigest: "d", harnessError: "timeout" });
  for (let i = 0; i < 3; i++) {
    const log = await w.exec(w.plan());
    assert.equal(log[0]?.ok, false);
    assert.equal(w.state.findings.get("f1")?.result, undefined, "a harness error is never recorded as a result");
  }
  assert.equal(w.harnessErrors.get("f1"), 3);
  assert.deepEqual(w.plan(), [{ kind: "voidFinding", findingId: "f1", reason: "harness-error" }]);
  await w.exec(w.plan());
  assert.equal(w.state.findings.get("f1")?.result?.logDigest, "void:harness-error");
});

test("reproductions per pass are capped, oldest first, and run beside the rest of the pass", async () => {
  const w = new World();
  await w.ready("s1");
  for (const f of ["f1", "f2", "f3"]) w.finding(f, { submissionId: "s1" }, "low");
  const plan = w.plan({ maxReproductionsPerPass: 2 });
  assert.deepEqual(plan.filter((a) => a.kind === "reproduceFinding").map((a) => (a as { findingId: string }).findingId), ["f1", "f2"]);

  // A hanging reproduction does not hold up an unrelated merge.
  await w.ready("s2");
  w.reviewAll("s2");
  let release!: () => void;
  const hang = new Promise<void>((r) => (release = r));
  const deps = w.deps();
  deps.reproduce = async () => {
    await hang;
    return null;
  };
  const actions: Action[] = [
    { kind: "reproduceFinding", findingId: "f1", baseCommit: "base-s1", headCommit: "bot-s1", testPath: "t", testCommand: "c" },
    { kind: "merge", submissionId: "s2" },
  ];
  const running = executeActions(actions, deps);
  for (let i = 0; i < 50 && !w.state.submissions.get("s2")?.merged; i++) await new Promise((r) => setImmediate(r));
  assert.ok(w.state.submissions.get("s2")?.merged, "merged while the reproduction hangs");
  release();
  const log = await running;
  assert.deepEqual(log.map((l) => l.action.kind), ["reproduceFinding", "merge"]);
});

test("phase 1: a reproduced finding pays, slashes and records an escape only after a human confirms it", async () => {
  const w = new World();
  await w.ready("s1");
  w.finding("f1", { submissionId: "s1" }, "high");
  w.reproductions.set("f1", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  await w.exec(w.plan());
  assert.equal(w.state.findings.get("f1")?.result?.reproduced, true);
  assert.deepEqual(w.plan(), [], "held: no bounty or slash without confirmation");
  assert.ok(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting.includes("reproduced finding f1"), "still blocks the merge");
  w.confirmed.add("f1");
  assert.deepEqual(kinds(w.plan()), ["settle"]);
  assert.deepEqual(kinds(w.plan({ phase: 2, findingConfirmed: undefined })), ["settle"], "phase 2 is mechanical");
});

// ---------------------------------------------------------------------------
// Snapshots and promotion
// ---------------------------------------------------------------------------

async function mergedWorld(ids: string[]): Promise<World> {
  const w = new World();
  for (const id of ids) {
    w.submit(id);
    w.approved.add(id);
  }
  await w.settle({ snapshotEvery: undefined });
  for (const id of ids) w.reviewAll(id);
  await w.settle({ snapshotEvery: undefined });
  for (const id of ids) assert.ok(w.state.submissions.get(id)?.merged, `${id} merged`);
  return w;
}

test("snapshot after snapshotEvery merges, promotion when the rule passes, escape for a defect on main", async () => {
  promotionPasses = false;
  const w = await mergedWorld(["s1", "s2", "s3"]);
  await w.settle();
  const snap = w.state.snapshots.get("snapshot-1");
  assert.ok(snap, "one snapshot of all three");
  assert.deepEqual(snap.submissionIds, ["s1", "s2", "s3"]);
  assert.equal(snap.commit, w.state.submissions.get("s3")?.merged?.commit);
  assert.equal(snap.previousSnapshotId, null);
  assert.deepEqual(w.plan(), [], "promotion rule not yet met; nothing to repeat");

  promotionPasses = true;
  assert.deepEqual(w.plan(), [{ kind: "promote", snapshotId: "snapshot-1", commit: snap.commit }]);
  await w.settle();
  assert.ok(w.state.snapshots.get("snapshot-1")?.promoted);
  assert.ok(w.bridgeCalls.includes(`ff ${snap.commit}`));
  assert.deepEqual(w.plan(), [], "promoted snapshot is not promoted again");

  // A defect in a promoted submission: escape and a main-stage bounty, once confirmed.
  w.finding("f9", { submissionId: "s2" }, "critical", "c1");
  w.reproductions.set("f9", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "x" });
  await w.exec(w.plan());
  assert.deepEqual(w.plan(), [], "phase 1: waits for confirmation");
  w.confirmed.add("f9");
  const next = w.plan();
  assert.deepEqual(next[0], { kind: "escape", findingId: "f9", snapshotId: "snapshot-1" });
  const settle = next.find((a): a is Extract<Action, { kind: "settle" }> => a.kind === "settle");
  assert.ok(settle?.bodies.some((b) => b.reason === "bounty" && b.ref === "f9@main"));
  await w.settle();
  assert.equal(w.state.escapes.length, 1);
  assert.deepEqual(w.plan(), []);
  promotionPasses = false;
});

test("snapshots cover only a clean prefix: a pending finding waits, a defect blocks", async () => {
  const w = await mergedWorld(["s1", "s2", "s3"]);
  w.finding("f2", { submissionId: "s2" }, "medium", "c1");
  const plan = w.plan({ snapshotEvery: 1 });
  const snap = plan.find((a): a is Extract<Action, { kind: "snapshot" }> => a.kind === "snapshot");
  assert.deepEqual(snap?.submissionIds, ["s1"], "s3's merge commit contains s2, so it waits too");
  assert.equal(snap?.commit, w.state.submissions.get("s1")?.merged?.commit);
  assert.equal(w.plan({ snapshotEvery: 2 }).some((a) => a.kind === "snapshot"), false);
  // Reproduced: a known defect is never frozen into a snapshot.
  w.reproductions.set("f2", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  await w.exec(w.plan({ snapshotEvery: undefined }));
  const after = w.plan({ snapshotEvery: 1 }).find((a): a is Extract<Action, { kind: "snapshot" }> => a.kind === "snapshot");
  assert.deepEqual(after?.submissionIds, ["s1"]);
  // A stale snapshot action naming s2 is refused under the lock.
  const stale: Action = { kind: "snapshot", id: "snapshot-x", commit: "c", previousSnapshotId: null, submissionIds: ["s1", "s2"] };
  const log = await w.exec([stale]);
  assert.equal(log[0]?.ok, false);
  assert.match(log[0]?.detail ?? "", /s2 is defective/);
});

test("promotion is re-checked under the lock: a finding reproduced in the same pass stops main moving", async () => {
  promotionPasses = true;
  const w = await mergedWorld(["s1", "s2"]);
  await w.exec(w.plan()); // settle + snapshot
  assert.ok(w.state.snapshots.get("snapshot-1"));
  w.finding("f1", { snapshotId: "snapshot-1" }, "high", "c1");
  assert.ok(!kinds(w.plan()).includes("promote"), "an open finding on the snapshot blocks planning");
  // A promote planned before the finding arrived, executed with its reproduction.
  const snap = w.state.snapshots.get("snapshot-1");
  assert.ok(snap);
  w.reproductions.set("f1", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  const actions: Action[] = [...w.plan(), { kind: "promote", snapshotId: "snapshot-1", commit: snap.commit }];
  const log = await w.exec(actions);
  const promote = log.find((l) => l.action.kind === "promote");
  assert.equal(promote?.ok, false);
  assert.match(promote?.detail ?? "", /reproduced finding f1/);
  assert.ok(!w.bridgeCalls.some((c) => c.startsWith("ff")), "main never moved");
  assert.equal(w.state.snapshots.get("snapshot-1")?.promoted, undefined);
  // And the rule itself is re-evaluated against live state.
  promotionPasses = false;
  const w2 = await mergedWorld(["s1", "s2"]);
  await w2.exec(w2.plan());
  const snap2 = w2.state.snapshots.get("snapshot-1");
  assert.ok(snap2);
  const log2 = await w2.exec([{ kind: "promote", snapshotId: "snapshot-1", commit: snap2.commit }]);
  assert.match(log2[0]?.detail ?? "", /promotion rule fails: fake/);
  assert.deepEqual(w2.bridgeCalls.filter((c) => c.startsWith("ff")), []);
});

// ---------------------------------------------------------------------------
// Coordinator entries from outside facts, and honeytokens
// ---------------------------------------------------------------------------

test("approved tasks and observed honeytoken hits are appended once each", async () => {
  const w = new World();
  w.apply({ kind: "proposal", id: "p1", title: "t", evidence: [{ kind: "location", file: "src/x.ts", line: 1, note: "n" }] }, w.key("a1"));
  const task: TaskBody = { kind: "task", id: "t1", proposalId: "p1", ring: 1, acceptanceTestPaths: ["test/t1.test.ts"], sizeEstimate: 10, specAuthor: "bob" };
  const orphan = { ...task, id: "t2", proposalId: "nope" };
  const hits = [{ agent: w.id("b1"), tokenId: "tok-1" }, { agent: "unknown", tokenId: "x" }];
  const extra = { approvedTasks: [task, orphan], honeytokenHits: hits };
  assert.deepEqual(kinds(w.plan(extra)), ["task", "honeytoken"]);
  await w.exec(w.plan(extra));
  assert.ok(w.state.tasks.has("t1"));
  assert.deepEqual(kinds(w.plan(extra)), ["settle", "suspend"]);
  await w.exec(w.plan(extra));
  assert.equal(w.state.agents.get(w.id("b1"))?.active, false);
  assert.deepEqual(w.plan(extra), []);
});

test("an agent that obeyed a honeytoken is settled and suspended once", async () => {
  const w = new World();
  w.apply({ kind: "honeytokenTriggered", agent: w.id("b1"), tokenId: "tok-1" }, w.coord);
  assert.deepEqual(kinds(w.plan()), ["settle", "suspend"]);
  await w.exec(w.plan());
  assert.equal(w.state.agents.get(w.id("b1"))?.active, false);
  assert.deepEqual(w.plan(), []);
});

// ---------------------------------------------------------------------------
// Whole-loop properties
// ---------------------------------------------------------------------------

test("idempotency: planning again after executing repeats nothing", async () => {
  const w = new World();
  for (const id of ["s1", "s2"]) {
    w.submit(id);
    w.approved.add(id);
  }
  w.finding("f1", { submissionId: "s1" }, "medium", "c1");
  w.reproductions.set("f1", { reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d" });
  const seen: string[] = [];
  for (let i = 0; i < 12; i++) {
    if (i === 4) for (const id of ["s1", "s2"]) w.reviewAll(id);
    const actions = w.plan();
    for (const a of actions) {
      // Only settlements may recur, and only with new bodies.
      const key = a.kind === "settle" ? `settle ${a.bodies.map((b) => b.ref).join(",")}` : canonical(a);
      assert.ok(!seen.includes(key), `planned twice: ${key}`);
      seen.push(key);
    }
    await w.exec(actions);
  }
  assert.deepEqual(w.plan(), []);
  const refs = w.state.settlements.map((s) => `${s.owner}/${s.reason}/${s.ref}`);
  assert.equal(new Set(refs).size, refs.length, "no settlement twice");
  assert.equal(w.state.snapshots.size, 1);
});

test("plan order: settlements, suspensions, reproductions, binding, gates, assignments", async () => {
  const w = new World();
  w.submit("s1");
  w.submit("s2");
  w.submit("s3");
  await w.exec(w.plan().filter((a) => "submissionId" in a && a.submissionId !== "s3"));
  await w.exec(w.plan().filter((a) => "submissionId" in a && a.submissionId === "s1"));
  w.apply({ kind: "honeytokenTriggered", agent: w.id("d1"), tokenId: "t" }, w.coord);
  w.finding("f1", { submissionId: "s2" }, "low");
  assert.deepEqual(kinds(w.plan()), ["settle", "suspend", "reproduceFinding", "assignReviewers", "runGates", "bindPatch"]);
});

test("runOnce resolves async approvals and confirmations, defaults uploads from patchesDir, keeps harness counts", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  w.advance(25 * 60);
  const asked: string[] = [];
  const harness = new Map<string, number>();
  const deps = w.deps();
  const run = () =>
    runOnce({
      ...deps,
      harnessErrors: harness,
      clock: () => w.now(),
      entries: () => w.entries,
      patchesDir: "/nonexistent/patches",
      plan: { reviewWindowHours: 24, incentives: fakeIncentives, promotion: fakePromotion },
      humanApproval: async (sid) => {
        asked.push(sid);
        return true;
      },
    });
  // No test file under patchesDir and past the grace period: voided.
  const first = await run();
  assert.deepEqual(kinds(first.actions), ["voidFinding"]);
  const { actions, log } = await run();
  assert.deepEqual(kinds(actions), ["settle", "merge"]);
  assert.ok(log.every((l) => l.ok), JSON.stringify(log));
  assert.ok(asked.filter((s) => s === "s1").length >= 2, "asked before planning and again at merge time");
  assert.ok(w.state.submissions.get("s1")?.merged);

  // Without a patch on disk, a new submission is not even bound.
  w.submit("s2");
  assert.deepEqual((await run()).actions.filter((a) => "submissionId" in a && a.submissionId === "s2"), []);
});

test("planActions does not mutate the state", () => {
  const w = new World();
  w.submit("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  const before = structuredClone(w.state);
  w.plan();
  assert.deepStrictEqual(w.state, before);
});

test("localReproducer refuses to run without a sandbox and forwards sandbox and timeout", async () => {
  const calls: Record<string, unknown>[] = [];
  const reproduceFinding = async (o: Record<string, unknown>) => {
    calls.push(o);
    return { reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d" };
  };
  const action = { kind: "reproduceFinding", findingId: "f1", baseCommit: "b", headCommit: "h", testPath: "t", testCommand: "c" } as const;
  const bare = localReproducer({ repoDir: "/r", testFile: () => __filename, reproduceFinding });
  await assert.rejects(bare(action), /without a sandbox/);
  assert.equal(calls.length, 0, "nothing ran");
  const boxed = localReproducer({ repoDir: "/r", testFile: () => __filename, reproduceFinding, sandbox: ["box"], timeoutMs: 5000 });
  await boxed(action);
  assert.deepEqual(calls[0]?.sandbox, ["box"]);
  assert.equal(calls[0]?.timeoutMs, 5000);
  const missing = localReproducer({ repoDir: "/r", testFile: () => "/nonexistent/test", reproduceFinding, sandbox: ["box"] });
  assert.equal(await missing(action), null, "no test file yet");
});
