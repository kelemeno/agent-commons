import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { applyEntry, emptyState, genesisEntry, signEntry, type LedgerState, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import {
  executeActions,
  mergeReadiness,
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
} from "../src/coordinator";
import type { CommonsState, EntryBody, LedgerEntry, ReviewVerdict, Severity } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: an in-memory ledger with a minute clock, fake incentives /
// selection / promotion (the real modules are written in parallel), and an
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

// Every active agent whose owner differs from the author's, one per owner.
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
  bridgeCalls: string[] = [];
  bridgeFails = false;
  reproductions = new Map<string, ReproductionOutcome>();
  gateResult = true;

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

  review(sid: string, agent: string, p = 0.1): void {
    this.commit(sid, agent, p);
    this.reveal(sid, agent, p);
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

  deps(): ExecuteDeps {
    return {
      state: () => this.state,
      append: (body) => this.apply(typeof body === "function" ? body(this.state) : body, this.coord),
      tree,
      entropy: (sid) => `round-${sid}`,
      runGates: async (s, gates) =>
        (gates ?? ["size", "rings"]).map((gate) => ({ gate, pass: this.gateResult, details: `${gate} on ${s.headCommit}` })),
      reproduce: async (a) => this.reproductions.get(a.findingId) ?? null,
      bridge: {
        merge: async (s) => {
          if (this.bridgeFails) throw new Error("github down");
          this.bridgeCalls.push(`merge ${s.id}`);
          return `merge-${s.id}`;
        },
        fastForwardMain: async (commit) => {
          this.bridgeCalls.push(`ff ${commit}`);
        },
      },
      selection: fakeSelection,
    };
  }

  // Plan + execute until nothing is left (bounded).
  async settle(extra: Partial<PlanOptions> = {}): Promise<void> {
    for (let i = 0; i < 20; i++) {
      const actions = this.plan(extra);
      if (actions.length === 0) return;
      const log = await executeActions(actions, this.deps());
      const failed = log.filter((l) => !l.ok);
      if (failed.length === actions.length) return; // stuck on failures only
    }
    assert.fail("loop did not settle");
  }
}

const kinds = (actions: Action[]) => actions.map((a) => a.kind);

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

test("a new submission gets gates first, and nothing else", () => {
  const w = new World();
  w.submit("s1");
  const actions = w.plan();
  assert.deepEqual(actions, [{ kind: "runGates", submissionId: "s1", headCommit: "head-s1", gates: null }]);
  assert.deepEqual(w.plan({ patchAvailable: () => false }), [], "no gates without the patch");
});

test("gates run once per submission head; required gates run only where missing", async () => {
  const w = new World();
  w.submit("s1");
  await executeActions(w.plan({ requiredGates: ["size"] }), w.deps());
  assert.deepEqual(w.state.submissions.get("s1")?.gates.map((g) => g.gate), ["size"]);
  const again = w.plan({ requiredGates: ["size", "rings"] });
  assert.deepEqual(again[0], { kind: "runGates", submissionId: "s1", headCommit: "head-s1", gates: ["rings"] });
  await executeActions(again, w.deps());
  assert.ok(!kinds(w.plan({ requiredGates: ["size", "rings"] })).includes("runGates"));
});

test("reviewers are assigned only after every gate passed", async () => {
  const w = new World();
  w.submit("s1");
  w.gateResult = false;
  await executeActions(w.plan(), w.deps());
  assert.deepEqual(w.plan(), [], "a failed gate stops the submission");

  w.gateResult = true;
  w.submit("s2");
  await executeActions(w.plan(), w.deps());
  assert.deepEqual(w.plan(), [{ kind: "assignReviewers", submissionId: "s2" }]);
  const log = await executeActions(w.plan(), w.deps());
  assert.ok(log[0]?.ok, log[0]?.detail);
  const a = w.state.submissions.get("s2")?.assignment;
  assert.ok(a);
  assert.equal(a.reviewers.length, 2);
  // The beacon covers the head hash the assignment was appended to.
  const before = w.entries[a.seq - 1];
  assert.equal(a.beacon, sha256hex(`${before?.hash}:s2:round-s2`));
});

test("merge waits for all reveals and human approval; phase 2 needs no human", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  const [r1, r2] = w.state.submissions.get("s1")?.assignment?.reviewers ?? [];
  assert.ok(r1 && r2);
  const name = (keyId: string) => [...w.keys.keys()].find((n) => w.id(n) === keyId) ?? "";

  w.commit("s1", name(r1));
  w.commit("s1", name(r2));
  w.reveal("s1", name(r1));
  assert.deepEqual(w.plan(), [], "one reviewer has not revealed");
  w.reveal("s1", name(r2));
  assert.deepEqual(w.plan(), [], "phase 1: no merge without human approval");
  assert.deepEqual(mergeReadiness(w.state, "s1", w.now(), w.opts()).waiting, ["awaiting human approval"]);
  assert.deepEqual(w.plan({ phase: 2 }), [{ kind: "merge", submissionId: "s1" }]);
  assert.deepEqual(w.plan({ humanApproval: undefined }), [], "no approval function means never approved");

  w.approved.add("s1");
  assert.deepEqual(w.plan(), [{ kind: "merge", submissionId: "s1" }]);
  await executeActions(w.plan(), w.deps());
  assert.equal(w.state.submissions.get("s1")?.merged?.commit, "merge-s1");
  assert.deepEqual(w.bridgeCalls, ["merge s1"]);
  // Next pass settles the first tranche, once.
  assert.deepEqual(kinds(w.plan()), ["settle"]);
  await executeActions(w.plan(), w.deps());
  assert.deepEqual(w.plan(), []);
});

test("after the review window, non-revealers count as missing and the merge proceeds", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  w.approved.add("s1");
  const [r1, r2] = w.state.submissions.get("s1")?.assignment?.reviewers ?? [];
  const name = (keyId: string) => [...w.keys.keys()].find((n) => w.id(n) === keyId) ?? "";
  w.review("s1", name(r1 ?? ""));
  assert.deepEqual(w.plan(), []);
  w.advance(24 * 60);
  assert.deepEqual(w.plan(), [
    { kind: "revealPhaseClose", submissionId: "s1", missing: [r2] },
    { kind: "merge", submissionId: "s1" },
  ]);
});

test("the review window runs from the assignment entry when entries are given", async () => {
  const w = new World();
  w.submit("s1");
  w.advance(23 * 60); // gates run late: the submission is 23h old at assignment
  await w.settle();
  w.approved.add("s1");
  w.advance(2 * 60);
  assert.deepEqual(w.plan(), [], "only ~2h since assignment");
  assert.equal(kinds(w.plan({ entries: undefined })).includes("merge"), true, "fallback times from the submission");
});

test("never merges with a reproduced finding, even when approved", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  w.approved.add("s1");
  w.advance(25 * 60);
  w.finding("f1", { submissionId: "s1" }, "low");
  // An unresolved low finding does not block; it is reproduced in the same pass, first.
  assert.deepEqual(kinds(w.plan()), ["reproduceFinding", "revealPhaseClose", "merge"]);
  const repro = w.plan()[0];
  assert.deepEqual(repro, {
    kind: "reproduceFinding",
    findingId: "f1",
    baseCommit: "base-s1",
    headCommit: "head-s1",
    testPath: "test/f1.test.ts",
    testCommand: "npm test",
  });
  w.reproductions.set("f1", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d" });
  const log = await executeActions(w.plan(), w.deps());
  assert.equal(log[0]?.ok, true);
  // The executor re-checks live state: the bridge is never called.
  assert.equal(log[2]?.ok, false);
  assert.match(log[2]?.detail ?? "", /reproduced/);
  assert.deepEqual(w.bridgeCalls, []);
  assert.equal(w.state.submissions.get("s1")?.merged, undefined);
  const next = w.plan();
  assert.ok(!kinds(next).includes("merge"));
  assert.deepEqual(kinds(next), ["settle"]);
});

test("an unresolved high finding blocks the merge until it is resolved", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  w.approved.add("s1");
  w.advance(25 * 60);
  w.finding("f1", { submissionId: "s1" }, "high");
  assert.deepEqual(kinds(w.plan()), ["reproduceFinding"]);
  await executeActions(w.plan(), w.deps()); // reproducer not ready: skipped
  assert.deepEqual(kinds(w.plan()), ["reproduceFinding"]);
  w.reproductions.set("f1", { reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d" });
  await executeActions(w.plan(), w.deps());
  assert.deepEqual(kinds(w.plan()), ["settle", "revealPhaseClose", "merge"]);
  assert.equal((w.plan()[0] as Extract<Action, { kind: "settle" }>).bodies[0]?.reason, "falseFinding");
});

test("a harness error is never recorded as a result", async () => {
  const w = new World();
  w.submit("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  w.reproductions.set("f1", { reproduced: false, failsOnHead: false, passesOnParent: false, logDigest: "d", harnessError: "timeout" });
  const log = await executeActions(w.plan().filter((a) => a.kind === "reproduceFinding"), w.deps());
  assert.equal(log[0]?.ok, false);
  assert.equal(w.state.findings.get("f1")?.result, undefined);
});

test("a failing bridge leaves no merge entry and the merge is retried", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  w.approved.add("s1");
  w.advance(25 * 60);
  w.bridgeFails = true;
  const log = await executeActions(w.plan(), w.deps());
  assert.ok(log.some((l) => l.action.kind === "merge" && !l.ok));
  assert.equal(w.state.submissions.get("s1")?.merged, undefined);
  assert.ok(kinds(w.plan()).includes("merge"));
});

test("snapshot after snapshotEvery merges, promotion when the rule passes, escape for a defect on main", async () => {
  const w = new World();
  promotionPasses = false;
  for (const id of ["s1", "s2", "s3"]) {
    w.submit(id);
    w.approved.add(id);
  }
  await w.settle();
  w.advance(25 * 60);
  await w.settle();
  const merged = ["s1", "s2", "s3"].filter((id) => w.state.submissions.get(id)?.merged);
  assert.equal(merged.length, 3);
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

  // A defect in a promoted submission: escape and a main-stage bounty.
  w.finding("f9", { submissionId: "s2" }, "critical", "c1");
  w.reproductions.set("f9", { reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "x" });
  await executeActions(w.plan(), w.deps());
  const next = w.plan();
  assert.deepEqual(next[0], { kind: "escape", findingId: "f9", snapshotId: "snapshot-1" });
  const settle = next.find((a): a is Extract<Action, { kind: "settle" }> => a.kind === "settle");
  assert.ok(settle?.bodies.some((b) => b.reason === "bounty" && b.ref === "f9@main"));
  await w.settle();
  assert.equal(w.state.escapes.length, 1);
  assert.deepEqual(w.plan(), []);
  promotionPasses = false;
});

test("an agent that obeyed a honeytoken is settled and suspended once", async () => {
  const w = new World();
  w.apply({ kind: "honeytokenTriggered", agent: w.id("b1"), tokenId: "tok-1" }, w.coord);
  assert.deepEqual(kinds(w.plan()), ["settle", "suspend"]);
  await executeActions(w.plan(), w.deps());
  assert.equal(w.state.agents.get(w.id("b1"))?.active, false);
  assert.deepEqual(w.plan(), []);
});

test("idempotency: planning again after executing repeats nothing", async () => {
  const w = new World();
  for (const id of ["s1", "s2"]) {
    w.submit(id);
    w.approved.add(id);
  }
  w.finding("f1", { submissionId: "s1" }, "medium", "c1");
  w.reproductions.set("f1", { reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d" });
  const seen: string[] = [];
  for (let i = 0; i < 10; i++) {
    if (i === 3) w.advance(25 * 60);
    const actions = w.plan();
    for (const a of actions) {
      // Only settlements may recur, and only with new bodies.
      const key = a.kind === "settle" ? `settle ${a.bodies.map((b) => b.ref).join(",")}` : canonical(a);
      assert.ok(!seen.includes(key), `planned twice: ${key}`);
      seen.push(key);
    }
    await executeActions(actions, w.deps());
  }
  assert.deepEqual(w.plan(), []);
  const refs = w.state.settlements.map((s) => `${s.owner}/${s.reason}/${s.ref}`);
  assert.equal(new Set(refs).size, refs.length, "no settlement twice");
  assert.ok(w.state.snapshots.size === 1);
});

test("plan order: settlements, suspensions, reproductions, gates, assignments, merges", async () => {
  const w = new World();
  w.submit("s1");
  w.submit("s2");
  await executeActions(w.plan().filter((a) => a.kind === "runGates" && a.submissionId === "s1"), w.deps());
  w.apply({ kind: "honeytokenTriggered", agent: w.id("d1"), tokenId: "t" }, w.coord);
  w.finding("f1", { submissionId: "s2" }, "low");
  assert.deepEqual(kinds(w.plan()), ["settle", "suspend", "reproduceFinding", "assignReviewers", "runGates"]);
});

test("runOnce resolves async approvals before planning", async () => {
  const w = new World();
  w.submit("s1");
  await w.settle();
  w.advance(25 * 60);
  const asked: string[] = [];
  const run = () =>
    runOnce({
      ...w.deps(),
      clock: () => w.now(),
      entries: () => w.entries,
      plan: { reviewWindowHours: 24, incentives: fakeIncentives, promotion: fakePromotion },
      humanApproval: async (sid) => {
        asked.push(sid);
        return true;
      },
    });
  const { actions, log } = await run();
  assert.deepEqual(asked, ["s1"]);
  assert.deepEqual(kinds(actions), ["revealPhaseClose", "merge"]);
  assert.ok(log.every((l) => l.ok));
  assert.ok(w.state.submissions.get("s1")?.merged);
});

test("planActions does not mutate the state", () => {
  const w = new World();
  w.submit("s1");
  w.finding("f1", { submissionId: "s1" }, "low");
  const before = structuredClone(w.state);
  w.plan();
  assert.deepStrictEqual(w.state, before);
});
