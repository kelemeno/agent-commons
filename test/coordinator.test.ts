import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, signEntry, submissionDead, type LedgerState, type Signer } from "../src/ledger";
import * as incentives from "../src/incentives";
import { defaultRules } from "../src/rules";
import { reviewWindowClosed } from "../src/plants";
import { assignmentBeacon, commitmentFor } from "../src/review";
import { assignmentBody } from "../src/selection";
import { memberDigest } from "../src/members";
import {
  BINDING_GATE,
  executeActions,
  localReproducer,
  MERGE_GATE,
  MergeConflictError,
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
import { blocksTarget } from "../src/findingStatus";
import type { CommonsState, EntryBody, LedgerEntry, ReviewVerdict, Severity } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: an in-memory ledger with a minute clock, fake incentives /
// selection / promotion, a fake patch binder (bot head = "bot-<id>") and an
// executor whose effects are recorded.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const iso = (minutes: number) => new Date(T0 + minutes * 60_000).toISOString();

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
  settleFinding: (state, fid, stage) => {
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

// The flag stands for every check but openIssues, which is real: a finding
// on the snapshot or a submission it lists blocks until cleared (the one
// promotion rule now carries what the coordinator used to add on its own).
let promotionPasses = false;
const fakePromotion: PromotionApi = {
  evaluatePromotion: (state, id) => {
    const snap = state.snapshots.get(id);
    const blocked = [...state.findings.values()].some(
      (f) => blocksTarget(f) && ("snapshotId" in f.target ? f.target.snapshotId === id : (snap?.submissionIds ?? []).includes(f.target.submissionId)),
    );
    return {
      pass: promotionPasses && !blocked,
      checks: [
        { name: "fake", pass: promotionPasses, detail: "" },
        { name: "openIssues", pass: !blocked, detail: "" },
      ],
    };
  },
};

// Every active agent whose owner differs from the author's, one per owner, two
// at most. The beacon and tree digest are the real ones: the ledger refuses
// any other.
const fakeSelection: SelectionApi = {
  drawAssignment: (state, sid, entropy) => {
    const author = ownerOfAgent(state, state.submissions.get(sid)?.author ?? "");
    const owners = new Set<string>();
    const reviewers: string[] = [];
    for (const a of state.agents.values()) {
      if (!a.active || a.owner === author || owners.has(a.owner)) continue;
      owners.add(a.owner);
      reviewers.push(a.keyId);
      if (reviewers.length === 2) break;
    }
    return { reviewers, candidates: reviewers.length, notes: [], body: assignmentBody(state, sid, reviewers, entropy) };
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
  bridgeCalls: string[] = [];
  bridgeFails = false;
  bridgeConflicts = false;
  reproductions = new Map<string, ReproductionOutcome>();
  reproduceCalls: string[] = [];
  gateResult = true;
  unpatched = new Set<string>(); // the binder has no patch for these
  unbindable = new Set<string>(); // the patch does not apply
  private queue: Promise<unknown> = Promise.resolve();

  constructor() {
    const rules = { ...defaultRules(), kernelSigners: ["carol", "dave"] };
    const g = genesisEntry(
      { kind: "genesis", project: "demo", admins: [this.admin.publicKey], coordinator: this.coord.publicKey, rules },
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
    this.apply({ kind: "reviewCommit", submissionId: sid, commitment: commitmentFor(verdictOf(p), `salt-${agent}`, this.id(agent), { submissionId: sid }), stake: 5 }, this.key(agent));
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

  // A human approves the merge: a ledger entry, signed by an admin.
  approve(sid: string): void {
    this.apply({ kind: "mergeApproval", submissionId: sid }, this.admin);
  }

  // An operator decides a reproduced finding.
  confirm(fid: string, confirmed = true): void {
    this.apply({ kind: "findingDecision", findingId: fid, confirmed, reason: confirmed ? "a real defect" : "tests the intended change" }, this.admin);
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
      snapshotEvery: 2,
      entries: this.entries,
      incentives: fakeIncentives,
      promotion: fakePromotion,
      ...extra,
    };
  }

  plan(extra: Partial<PlanOptions> = {}): Action[] {
    return planActions(this.state, this.now(), this.opts(extra));
  }

  deps(extra: Partial<PlanOptions> = {}): ExecuteDeps {
    return {
      state: () => this.state,
      append: (body) => this.appendLocked(body),
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
      bridge: {
        merge: async (s, expected) => {
          if (this.bridgeFails) throw new Error("github down");
          if (this.bridgeConflicts) throw new MergeConflictError(`${s.id} does not merge cleanly onto refs/heads/dev (conflicts)`);
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
    this.approve(id);
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

test("regression: a failing gate with details past the ledger's limit is recorded (cut), and a partial record is not a pass", async () => {
  const w = new World();
  w.submit("s1");
  await w.exec(w.plan()); // bind
  const deps = w.deps();
  const long = `ring-2 file imports "${"../x".repeat(1500)}server/src/engine", which is ring 0`;
  deps.runGates = async () => [
    { gate: "size", pass: true, details: "ok" },
    { gate: "rings", pass: false, details: long },
  ];
  const log = await executeActions(w.plan(), deps);
  assert.ok(log[0]?.ok, log[0]?.detail);
  const rings = w.state.submissions.get("s1")?.gates.find((g) => g.gate === "rings");
  assert.equal(rings?.pass, false, "the failure is on the ledger");
  assert.ok((rings?.details.length ?? 0) <= 4000 && /characters, cut\]$/.test(rings?.details ?? ""));
  assert.ok(!kinds(w.plan()).includes("assignReviewers"), "a failed gate stops the submission");

  // A record that stopped after one gate (a crash between appends) is not taken for all of them.
  const p = new World();
  p.submit("s2");
  await p.exec(p.plan());
  await p.appendLocked({ kind: "gateResult", submissionId: "s2", gate: "size", pass: true, details: "" });
  assert.deepEqual(p.plan({ requiredGates: ["size", "rings"] })[0], { kind: "runGates", submissionId: "s2", headCommit: "bot-s2", gates: ["rings"] });
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
  // The entry records the entropy and the member tree's digest; the beacon follows from the entropy.
  const s2 = w.state.submissions.get("s2");
  assert.equal(a.entropy, "round-s2");
  assert.equal(a.treeDigest, memberDigest(w.state)); // no owner was admitted since
  assert.equal(a.beacon, assignmentBeacon("s2", s2?.headCommit ?? "", "round-s2"));
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
  assert.deepEqual(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting, ["awaiting human approval (mergeApproval)"]);
  assert.deepEqual(w.plan({ phase: 2 }), [{ kind: "merge", submissionId: "s1" }]);

  w.approve("s1"); // on the ledger: replay shows who approved it
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
  assert.deepEqual(w.plan({ reviewQuorum: 2 }), [], "an explicit quorum of two is not met");
  // The close goes on the ledger first; the merge follows on the next pass.
  assert.deepEqual(w.plan(), [{ kind: "closeReviewWindow", submissionId: "s1", missing: [ids[1]] }]);
  await w.exec(w.plan());
  assert.deepEqual(w.state.submissions.get("s1")?.windowClosed?.missing, [ids[1]]);
  assert.deepEqual(w.plan(), [{ kind: "merge", submissionId: "s1" }]);
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
  w.approve("s1");
  w.advance(23 * 60); // gates run late: the submission is 23h old at assignment
  await w.settle();
  w.reviewAll("s1", 1);
  w.advance(2 * 60);
  assert.deepEqual(w.plan(), [], "only ~2h since assignment");
  w.advance(30 * 24 * 60);
  assert.deepEqual(w.plan({ entries: undefined }), [], "unknown assignment time: not closed");
  assert.deepEqual(kinds(w.plan()), ["closeReviewWindow"]);
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
  assert.match(after[0]?.detail ?? "", /reproduced finding f1 awaits an operator's decision/);
  assert.deepEqual(w.bridgeCalls, []);
  assert.equal(w.state.submissions.get("s1")?.merged, undefined);
  w.confirm("f1");
  for (let i = 0; i < 3; i++) {
    const next = w.plan({ phase: 2 });
    assert.ok(!kinds(next).includes("merge"));
    await w.exec(next, { phase: 2 });
  }
  assert.ok(w.state.settlements.some((s) => s.reason === "bounty" && s.ref === "f1@dev"));
});

test("the merge is re-checked under the lock against the ledger's approvals", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  w.reviewAll("s1");
  assert.deepEqual(w.plan(), [], "phase 1: no approval entry yet");
  // A merge action from a plan made elsewhere (say, in phase 2) is refused.
  const stale: Action[] = [{ kind: "merge", submissionId: "s1" }];
  const log = await w.exec(stale);
  assert.equal(log[0]?.ok, false);
  assert.match(log[0]?.detail ?? "", /awaiting human approval/);
  assert.deepEqual(w.bridgeCalls, []);
  w.approve("s1");
  assert.equal((await w.exec(stale))[0]?.ok, true);
  assert.deepEqual(w.bridgeCalls, ["merge s1 bot-s1"]);
});

test("phase 2: a submission the assigned reviewers flagged waits for a human instead of merging", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle({ phase: 2 });
  const [r1, r2] = w.reviewers("s1");
  assert.ok(r1 && r2);
  w.commit("s1", r1, 0.9);
  w.commit("s1", r2, 0.8);
  w.reveal("s1", r1, 0.9);
  w.reveal("s1", r2, 0.8);
  assert.deepEqual(w.plan({ phase: 2 }), []);
  assert.match(mergeReadiness(w.state, "s1", w.now(), w.opts({ phase: 2 })).waiting.join("; "), /flagged a defect/);
  w.approve("s1");
  assert.deepEqual(kinds(w.plan({ phase: 2 })), ["merge"]);
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

test("regression: when another process appends a blocking entry while the bridge merges, dev is moved back", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  const refs: Record<"dev" | "main", string | null> = { dev: "dev-0", main: null };
  const deps = w.deps();
  deps.bridge = {
    merge: async (s) => {
      // Another process (a local `commons finding file`) lands a finding on s1 meanwhile.
      w.finding("f-race", { submissionId: s.id }, "high");
      refs.dev = `merge-${s.id}`;
      return refs.dev;
    },
    fastForwardMain: async () => undefined,
    tip: async (ref) => refs[ref],
    restore: async (ref, before, after) => {
      if (refs[ref] !== after) return false;
      refs[ref] = before;
      return true;
    },
  };
  const log = await executeActions(w.plan(), deps);
  const merge = log.find((l) => l.action.kind === "merge");
  assert.ok(merge && !merge.ok, "the ledger refused the merge entry");
  assert.match(merge.detail, /dev restored to dev-0/);
  assert.equal(refs.dev, "dev-0", "dev does not keep a merge the ledger never recorded");
  assert.equal(w.state.submissions.get("s1")?.merged, undefined);
});

test("regression: a head that conflicts with dev is recorded as a failed merge gate, so the submission is closed", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.bridgeConflicts = true;
  const log = await w.exec(w.plan());
  assert.ok(log.some((l) => l.action.kind === "merge" && l.ok && /does not merge/.test(l.detail)), JSON.stringify(log));
  const s = w.state.submissions.get("s1");
  assert.equal(s?.merged, undefined);
  assert.deepEqual(s?.gates.filter((g) => g.gate === MERGE_GATE).map((g) => g.pass), [false]);
  assert.equal(submissionDead(w.state, "s1"), true, "dead: its PR slot and review stakes are released");
  assert.deepEqual(w.plan().filter((a) => "submissionId" in a && a.submissionId === "s1"), [], "never retried");
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

test("a plant with a silent assigned reviewer: the window closes on the ledger and the custodian can reveal before the merge", async () => {
  const w = new World();
  w.apply({ kind: "plantCommit", commitment: sha256hex("s1:salt") }, w.admin);
  await w.ready("s1");
  w.reviewAll("s1", 1); // one assigned reviewer never reveals
  w.advance(24 * 60 + 1);
  assert.equal(reviewWindowClosed(w.state, "s1"), false, "before the close entry the custodian may not reveal");
  assert.deepEqual(kinds(w.plan()), ["closeReviewWindow"], "no merge: the close goes on the ledger first");
  await w.exec(w.plan());
  assert.equal(reviewWindowClosed(w.state, "s1"), true, "now `commons plant reveal` may run");
  assert.deepEqual(w.plan(), [], "and the merge waits the grace after the close entry");
  w.apply({ kind: "plantReveal", submissionId: "s1", salt: "salt", description: "off by one", severity: "medium" }, w.admin);
  w.advance(2 * 60);
  assert.deepEqual(w.plan().filter((a) => a.kind === "merge"), [], "the plant never merged");
  // So later merges can still be snapshotted: nothing defective sits on dev.
  await w.ready("s2");
  w.reviewAll("s2");
  w.advance(2 * 60);
  await w.settle({ snapshotEvery: 1 });
  assert.ok(w.state.submissions.get("s2")?.merged);
  assert.deepEqual(w.state.snapshots.get("snapshot-1")?.submissionIds, ["s2"]);
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
    at: w.state.findings.get("f1")?.result?.at,
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
  assert.equal(w.state.findings.get("f1")?.harnessErrors, 3, "counted on the ledger: a fresh run-once process sees them");
  assert.deepEqual(w.plan(), [{ kind: "voidFinding", findingId: "f1", reason: "harness-error" }]);
  await w.exec(w.plan());
  const result = w.state.findings.get("f1")?.result;
  assert.equal(result?.logDigest, "void:harness-error");
  // "Could not run" is recorded as such: not a reproduction, and not a false finding.
  assert.equal(result?.reproduced, false);
  assert.equal(result?.harnessError, "voided after 3 harness errors");
  assert.deepEqual(incentives.settleFalseFinding(w.state, "f1"), []);
});

test("reproductions per pass are capped, oldest first, and run beside the rest of the pass", async () => {
  const w = new World();
  await w.ready("s1");
  for (const f of ["f1", "f2", "f3"]) w.finding(f, { submissionId: "s1" }, "low");
  const plan = w.plan({ maxReproductionsPerPass: 2 });
  assert.deepEqual(plan.filter((a) => a.kind === "reproduceFinding").map((a) => (a as { findingId: string }).findingId), ["f1", "f2"]);
  // A finding whose test keeps failing to run goes behind the others, so it
  // cannot hold every slot.
  w.apply({ kind: "findingAttempt", findingId: "f1", harnessError: "timeout" }, w.coord);
  const again = w.plan({ maxReproductionsPerPass: 2 });
  assert.deepEqual(again.filter((a) => a.kind === "reproduceFinding").map((a) => (a as { findingId: string }).findingId), ["f2", "f3"]);

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

test("in every phase a reproduction pays and slashes only once confirmed; a dismissed one costs its finder and unblocks", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.finding("f1", { submissionId: "s1" }, "high");
  w.reproductions.set("f1", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  await w.exec(w.plan());
  assert.equal(w.state.findings.get("f1")?.result?.reproduced, true);
  assert.deepEqual(w.plan(), [], "held: no bounty or slash without confirmation");
  assert.deepEqual(w.plan({ phase: 2 }), [], "phase 2 too: a test pinning the old text 'reproduces' against any change");
  assert.ok(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting.includes("reproduced finding f1 awaits an operator's decision"));
  // Dismissed: the change-detector veto clears and costs its filer.
  w.confirm("f1", false);
  const next = w.plan();
  assert.deepEqual(kinds(next), ["settle", "merge"]);
  assert.equal((next[0] as Extract<Action, { kind: "settle" }>).bodies[0]?.reason, "falseFinding");

  const v = new World();
  await v.ready("s1");
  v.finding("f1", { submissionId: "s1" }, "high");
  v.reproductions.set("f1", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  await v.exec(v.plan());
  v.confirm("f1");
  assert.deepEqual(kinds(v.plan()), ["settle"]);
  assert.ok(mergeReadiness(v.state, "s1", v.now(), v.opts()).waiting.includes("confirmed defect f1"));
});

test("a finding with no result past its deadline is voided as a harness error: it unblocks, nobody is slashed", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.finding("f1", { submissionId: "s1" }, "high");
  // The reproducer never answers (no sandbox on this host, say).
  w.advance(72 * 60);
  assert.deepEqual(w.plan(), [{ kind: "voidFinding", findingId: "f1", reason: "deadline" }]);
  await w.exec(w.plan());
  assert.match(w.state.findings.get("f1")?.result?.harnessError ?? "", /result deadline/);
  assert.ok(kinds(w.plan()).includes("merge"));
  assert.deepEqual(incentives.settleFalseFinding(w.state, "f1"), [], "the real rule slashes nobody for it");
});

// ---------------------------------------------------------------------------
// Snapshots and promotion
// ---------------------------------------------------------------------------

async function mergedWorld(ids: string[]): Promise<World> {
  const w = new World();
  for (const id of ids) {
    w.submit(id);
    w.approve(id);
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

  // The real incentives module, after the vesting tail: tranche 3 and clean
  // reviews need the evaluation time (they threw RangeError without it).
  // These submissions have no task, so they vest nothing at all: no merge
  // tranche and no clean-review reward (or whitespace edits would mint
  // reputation). Before the tail the real module is not even asked.
  const real: IncentivesApi = incentives;
  const afterTail = new Date(Date.parse(w.now()) + (w.state.rules.vesting.tailDays + 1) * 86_400_000).toISOString();
  let asked = 0;
  const counting: IncentivesApi = { ...real, settleCleanReviews: (...a) => (asked++, real.settleCleanReviews(...a)) };
  const vested = planActions(w.state, afterTail, w.opts({ incentives: counting }));
  assert.ok(asked > 0, "clean reviews are evaluated after the tail (they threw RangeError without nowIso)");
  assert.ok(!vested.some((a) => a.kind === "settle" && a.bodies.some((b) => b.reason === "cleanReview")), "taskless reviews earn nothing");
  assert.ok(!vested.some((a) => a.kind === "settle" && a.bodies.some((b) => b.reason === "mergeVest")), "taskless merges vest nothing");

  // A defect in a promoted submission: escape and a main-stage bounty, once confirmed.
  w.finding("f9", { submissionId: "s2" }, "critical", "c1");
  w.reproductions.set("f9", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "x" });
  await w.exec(w.plan());
  assert.deepEqual(w.plan(), [], "waits for an operator's confirmation");
  w.confirm("f9");
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
  w.confirm("f2");
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
  assert.match(promote?.detail ?? "", /promotion rule fails: openIssues/);
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
    w.approve(id);
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

test("runOnce reads approvals from the ledger and defaults uploads from patchesDir", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  w.advance(25 * 60);
  const deps = w.deps();
  const run = () =>
    runOnce({
      ...deps,
      clock: () => w.now(),
      entries: () => w.entries,
      patchesDir: "/nonexistent/patches",
      plan: { reviewWindowHours: 24, incentives: fakeIncentives, promotion: fakePromotion },
    });
  // No test file under patchesDir and past the grace period: voided.
  const first = await run();
  assert.deepEqual(kinds(first.actions), ["voidFinding"]);
  const { actions, log } = await run();
  assert.deepEqual(kinds(actions), ["settle", "merge"]);
  assert.ok(log.every((l) => l.ok), JSON.stringify(log));
  assert.ok(w.state.submissions.get("s1")?.merged);

  // Without a patch on disk, a new submission is not even bound.
  w.submit("s2");
  assert.deepEqual((await run()).actions.filter((a) => "submissionId" in a && a.submissionId === "s2"), []);
});

test("harness errors survive between runs: three fresh run-once passes void a test that always times out", async () => {
  const w = new World();
  await w.ready("s1");
  w.reviewAll("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  w.reproductions.set("f1", { reproduced: false, failsOnHead: false, passesOnParent: false, logDigest: "d", harnessError: "timeout" });
  // Each pass gets brand-new deps, as a new process would: nothing in memory carries over.
  const pass = () =>
    runOnce({ ...w.deps(), clock: () => w.now(), entries: () => w.entries, plan: { reviewWindowHours: 24, incentives: fakeIncentives, promotion: fakePromotion } });
  for (let i = 0; i < 3; i++) await pass();
  assert.equal(w.state.findings.get("f1")?.harnessErrors, 3);
  const fourth = await pass();
  assert.deepEqual(kinds(fourth.actions), ["voidFinding"]);
  assert.match(w.state.findings.get("f1")?.result?.harnessError ?? "", /voided after 3 harness errors/);
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
