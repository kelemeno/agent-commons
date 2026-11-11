// The coordinator loop: a pure planner and an effectful executor.
//
// planActions(state, tree, nowIso, opts) reads only its arguments and returns
// what the coordinator should do next. Every rule is decided from the ledger,
// so planning is idempotent: once a plan's actions are executed (and their
// entries appended), planning again does not repeat them. Actions whose
// preconditions depend on an earlier action in the same plan (gates before
// reviewers, reviewers before merge, merge before snapshot) are planned on the
// next pass, never speculatively.
//
// executeActions(actions, deps) performs them in order with injected effects:
// ledger appends as the coordinator, the gate runner, the reproduction
// harness, the GitHub bridge and the entropy source. Each action is isolated:
// a failure is logged and the rest still run. Effects with an outside-world
// side (bridge merge, main fast-forward) happen before the ledger entry that
// records them, so the ledger never claims a merge that did not happen; the
// bridge calls must therefore be idempotent (a retried merge of an already
// merged PR returns its commit).
//
// runOnce(deps) = read state, plan, execute.

import { readFileSync } from "node:fs";
import type {
  CommitSha,
  CommonsState,
  EntryBody,
  GateReport,
  KeyId,
  LedgerEntry,
  OwnerId,
  SubmissionState,
  TreeView,
} from "./types";

type Body<K extends EntryBody["kind"]> = Extract<EntryBody, { kind: K }>;
export type SettlementBody = Body<"settlement">;
export type Stage = "dev" | "release" | "main";

// ---------------------------------------------------------------------------
// Module APIs this file consumes, typed from ARCHITECTURE.md so it compiles and
// its tests run before those modules exist. Defaults load the real modules.
// ---------------------------------------------------------------------------

export type IncentivesApi = {
  settleFinding(state: CommonsState, tree: TreeView, findingId: string, stage: Stage): SettlementBody[];
  settleMerge(state: CommonsState, submissionId: string, tranche: 1 | 2 | 3): SettlementBody[];
  settleCleanReviews(state: CommonsState, snapshotId: string): SettlementBody[];
  settleMissedPlant(state: CommonsState, submissionId: string): SettlementBody[];
  settleFalseFinding(state: CommonsState, findingId: string): SettlementBody[];
  settleExpiredClaims(state: CommonsState, nowIso: string): SettlementBody[];
  settleHoneytoken(state: CommonsState, agent: KeyId): SettlementBody[];
};

export type PromotionApi = {
  evaluatePromotion(
    state: CommonsState,
    tree: TreeView,
    snapshotId: string,
    nowIso: string,
  ): { pass: boolean; checks: { name: string; pass: boolean; detail: string }[] };
};

export type SelectionApi = {
  computeBeacon(state: CommonsState, submissionId: string, externalEntropy: string): string;
  selectReviewers(
    state: CommonsState,
    tree: TreeView,
    submissionId: string,
    beacon: string,
  ): { reviewers: KeyId[]; candidates: number; notes: string[] };
};

function load<T>(name: "incentives" | "promotion" | "selection"): T {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require(`./${name}`) as T;
  } catch (e) {
    throw new Error(`src/${name}.ts could not be loaded; inject it (${String(e)})`);
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type Action =
  | { kind: "settle"; bodies: SettlementBody[] }
  | { kind: "suspend"; agent: KeyId; reason: string }
  | { kind: "escape"; findingId: string; snapshotId: string }
  | {
      kind: "reproduceFinding";
      findingId: string;
      baseCommit: CommitSha;
      headCommit: CommitSha;
      testPath: string;
      testCommand: string;
    }
  | { kind: "runGates"; submissionId: string; headCommit: CommitSha; gates: string[] | null }
  | { kind: "assignReviewers"; submissionId: string }
  // The review window closed with reviewers who never revealed; they count as
  // missing. Planned only alongside the merge it unblocks, so it is not
  // repeated while the submission waits for something else.
  | { kind: "revealPhaseClose"; submissionId: string; missing: KeyId[] }
  | { kind: "merge"; submissionId: string }
  | { kind: "snapshot"; id: string; commit: CommitSha; previousSnapshotId: string | null; submissionIds: string[] }
  | { kind: "promote"; snapshotId: string; commit: CommitSha };

export type PlanOptions = {
  reviewWindowHours: number;
  // Gate names every submission must pass. Without it, at least one gate
  // result must exist and all must pass (what the ledger's merge rule needs).
  requiredGates?: string[];
  phase?: 1 | 2; // default 1: a human must approve every merge
  humanApproval?: (submissionId: string) => boolean; // phase 1; absent = never approved
  snapshotEvery?: number; // merged, unsnapshotted submissions that trigger a snapshot; absent = never
  // Gates need the code; without a patch they are not planned. Absent = always available.
  patchAvailable?: (submissionId: string) => boolean;
  // Ledger entries, to time the review window from the assignment entry.
  // Without them the window runs from the submission time (shorter, never longer).
  entries?: readonly LedgerEntry[];
  incentives?: IncentivesApi;
  promotion?: PromotionApi;
};

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export type MergeReadiness = { ready: boolean; missing: KeyId[]; waiting: string[] };

// Why a submission can or cannot merge now. `waiting` lists every unmet rule.
export function mergeReadiness(
  state: CommonsState,
  submissionId: string,
  nowIso: string,
  opts: PlanOptions,
): MergeReadiness {
  const s = state.submissions.get(submissionId);
  if (!s) return { ready: false, missing: [], waiting: ["unknown submission"] };
  const waiting: string[] = [];
  let missing: KeyId[] = [];
  if (s.merged) waiting.push("already merged");
  if (s.planted) waiting.push("revealed plant");
  waiting.push(...gateProblems(s, opts));
  if (!s.assignment) {
    waiting.push("no reviewers assigned");
  } else {
    const unrevealed = s.assignment.reviewers.filter(
      (r) => !s.reviews.some((v) => v.reviewer === r && v.verdict !== undefined),
    );
    if (unrevealed.length > 0) {
      const opened = assignmentTime(s, opts);
      if (Date.parse(nowIso) >= Date.parse(opened) + opts.reviewWindowHours * HOUR) missing = unrevealed;
      else waiting.push(`awaiting reveals from ${unrevealed.join(", ")}`);
    }
  }
  for (const fid of s.findingIds) {
    const f = state.findings.get(fid);
    if (!f) continue;
    if (f.result?.reproduced) waiting.push(`reproduced finding ${fid}`);
    // Stricter than "no unresolved finding >= high": the ledger refuses a merge
    // while any finding on the submission is undecided (finding-pending), and
    // the bridge merge happens before the ledger entry, so the planner must not
    // plan a merge the ledger would refuse.
    else if (!f.result) waiting.push(`unresolved ${f.severity} finding ${fid}`);
  }
  if ((opts.phase ?? 1) === 1 && opts.humanApproval?.(submissionId) !== true) waiting.push("awaiting human approval");
  return { ready: waiting.length === 0, missing, waiting };
}

// Problems with the gate record; empty means all required gates passed.
function gateProblems(s: SubmissionState, opts: PlanOptions): string[] {
  const out: string[] = [];
  for (const g of s.gates) if (!g.pass) out.push(`gate ${g.gate} failed`);
  if (opts.requiredGates) {
    for (const name of missingGates(s, opts.requiredGates)) out.push(`gate ${name} not run`);
  } else if (s.gates.length === 0) {
    out.push("gates not run");
  }
  return out;
}

function missingGates(s: SubmissionState, required: string[]): string[] {
  return required.filter((name) => !s.gates.some((g) => g.gate === name));
}

function assignmentTime(s: SubmissionState, opts: PlanOptions): string {
  const seq = s.assignment?.seq;
  const entry = seq === undefined ? undefined : opts.entries?.[seq];
  return entry && entry.seq === seq ? entry.at : s.submittedAt;
}

// The earliest promotion that put this snapshot's content on main: its own, or
// that of any later snapshot whose ancestry includes it.
function promotionCovering(state: CommonsState, snapshotId: string): { snapshotId: string; seq: number; at: string } | null {
  let best: { snapshotId: string; seq: number; at: string } | null = null;
  for (const snap of state.snapshots.values()) {
    if (!snap.promoted || (best && best.seq <= snap.promoted.seq)) continue;
    for (let cur: string | null = snap.id; cur !== null; cur = state.snapshots.get(cur)?.previousSnapshotId ?? null) {
      if (cur === snapshotId) {
        best = { snapshotId: snap.id, seq: snap.promoted.seq, at: snap.promoted.at };
        break;
      }
    }
  }
  return best;
}

function snapshotOf(state: CommonsState, submissionId: string): string | null {
  for (const snap of state.snapshots.values()) if (snap.submissionIds.includes(submissionId)) return snap.id;
  return null;
}

// Where a defect was found, judged at the finding's own seq so the answer never
// changes after the fact. `escapeSnapshot` is set when the defect was on main.
function findingStage(state: CommonsState, findingId: string): { stage: Stage; escapeSnapshot: string | null } {
  const f = state.findings.get(findingId);
  if (!f) return { stage: "dev", escapeSnapshot: null };
  const snapId = "snapshotId" in f.target ? f.target.snapshotId : snapshotOf(state, f.target.submissionId);
  const snap = snapId === null ? undefined : state.snapshots.get(snapId);
  if (!snap || snap.seq > f.seq) return { stage: "dev", escapeSnapshot: null };
  const promo = promotionCovering(state, snap.id);
  if (promo && promo.seq < f.seq) return { stage: "main", escapeSnapshot: promo.snapshotId };
  return { stage: "release", escapeSnapshot: null };
}

// Base and head of what a finding claims is broken. A snapshot is judged
// against the previous snapshot or, for the first one, the base of its
// earliest merged submission.
function findingCommits(state: CommonsState, findingId: string): { base: CommitSha; head: CommitSha } | null {
  const f = state.findings.get(findingId);
  if (!f) return null;
  if ("submissionId" in f.target) {
    const s = state.submissions.get(f.target.submissionId);
    return s ? { base: s.baseCommit, head: s.headCommit } : null;
  }
  const snap = state.snapshots.get(f.target.snapshotId);
  if (!snap) return null;
  const prev = snap.previousSnapshotId === null ? undefined : state.snapshots.get(snap.previousSnapshotId);
  if (prev) return { base: prev.commit, head: snap.commit };
  const first = snap.submissionIds
    .map((id) => state.submissions.get(id))
    .filter((s): s is SubmissionState => s?.merged !== undefined)
    .sort((a, b) => (a.merged?.seq ?? 0) - (b.merged?.seq ?? 0))[0];
  return first ? { base: first.baseCommit, head: snap.commit } : null;
}

const settlementKey = (b: { owner: OwnerId; reason: string; ref: string }) => `${b.owner}\u0000${b.reason}\u0000${b.ref}`;

export function planActions(state: CommonsState, tree: TreeView, nowIso: string, opts: PlanOptions): Action[] {
  const incentives = opts.incentives ?? load<IncentivesApi>("incentives");
  const promotion = opts.promotion ?? load<PromotionApi>("promotion");
  const now = Date.parse(nowIso);
  const actions: Action[] = [];

  // 1. Consequences of events already on the ledger: escapes, then settlements.
  // incentives.ts promises idempotency; the filter against recorded settlements
  // (owner + reason + ref, the same key) keeps the plan idempotent regardless.
  const bodies: SettlementBody[] = [];
  const escapes = new Set(state.escapes.map((e) => e.findingId));
  for (const f of state.findings.values()) {
    if (!f.result) continue;
    if (f.result.reproduced) {
      const { stage, escapeSnapshot } = findingStage(state, f.id);
      if (escapeSnapshot !== null && !escapes.has(f.id)) {
        actions.push({ kind: "escape", findingId: f.id, snapshotId: escapeSnapshot });
      }
      bodies.push(...incentives.settleFinding(state, tree, f.id, stage));
    } else {
      bodies.push(...incentives.settleFalseFinding(state, f.id));
    }
  }
  const tail = state.rules.vesting.tailDays * DAY;
  for (const s of state.submissions.values()) {
    if (s.planted) bodies.push(...incentives.settleMissedPlant(state, s.id));
    if (!s.merged) continue;
    bodies.push(...incentives.settleMerge(state, s.id, 1));
    const snap = snapshotOf(state, s.id);
    const promo = snap === null ? null : promotionCovering(state, snap);
    if (promo) {
      bodies.push(...incentives.settleMerge(state, s.id, 2));
      if (Date.parse(promo.at) + tail <= now) bodies.push(...incentives.settleMerge(state, s.id, 3));
    }
  }
  for (const snap of state.snapshots.values()) {
    if (snap.promoted && Date.parse(snap.promoted.at) + tail <= now) {
      bodies.push(...incentives.settleCleanReviews(state, snap.id));
    }
  }
  bodies.push(...incentives.settleExpiredClaims(state, nowIso));
  const offenders = [...new Set(state.honeytokens.map((h) => h.agent))];
  for (const agent of offenders) bodies.push(...incentives.settleHoneytoken(state, agent));

  const seen = new Set(state.settlements.map(settlementKey));
  const fresh = bodies.filter((b) => {
    const k = settlementKey(b);
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  if (fresh.length > 0) actions.push({ kind: "settle", bodies: fresh });

  // 2. Suspend agents that obeyed a decoy.
  for (const agent of offenders) {
    if (state.agents.get(agent)?.active) {
      const tokens = state.honeytokens.filter((h) => h.agent === agent).map((h) => h.tokenId);
      actions.push({ kind: "suspend", agent, reason: `honeytoken ${tokens.join(", ")}` });
    }
  }

  // 3. Reproduce findings without a result (before merges: a reproduced finding blocks one).
  for (const f of state.findings.values()) {
    if (f.result) continue;
    const commits = findingCommits(state, f.id);
    if (!commits) continue;
    actions.push({
      kind: "reproduceFinding",
      findingId: f.id,
      baseCommit: commits.base,
      headCommit: commits.head,
      testPath: f.testPath,
      testCommand: f.testCommand,
    });
  }

  // 4-6. Per submission: gates once per head, then reviewers, then merge.
  for (const s of state.submissions.values()) {
    if (s.merged || s.planted) continue;
    const missing = opts.requiredGates ? missingGates(s, opts.requiredGates) : s.gates.length === 0 ? null : [];
    if (missing === null || missing.length > 0) {
      if (opts.patchAvailable?.(s.id) !== false) {
        actions.push({ kind: "runGates", submissionId: s.id, headCommit: s.headCommit, gates: missing });
      }
      continue;
    }
    if (gateProblems(s, opts).length > 0) continue;
    if (!s.assignment) {
      actions.push({ kind: "assignReviewers", submissionId: s.id });
      continue;
    }
    const r = mergeReadiness(state, s.id, nowIso, opts);
    if (!r.ready) continue;
    if (r.missing.length > 0) actions.push({ kind: "revealPhaseClose", submissionId: s.id, missing: r.missing });
    actions.push({ kind: "merge", submissionId: s.id });
  }

  // 7. Snapshot once enough merged submissions are outside every snapshot. The
  // commit is the latest included merge: dev is linear, so it contains the rest.
  if (opts.snapshotEvery !== undefined && opts.snapshotEvery > 0) {
    const inSnapshot = new Set<string>();
    for (const snap of state.snapshots.values()) for (const id of snap.submissionIds) inSnapshot.add(id);
    const pending = [...state.submissions.values()]
      .filter((s) => s.merged && !inSnapshot.has(s.id))
      .sort((a, b) => (a.merged?.seq ?? 0) - (b.merged?.seq ?? 0));
    const last = pending[pending.length - 1];
    if (pending.length >= opts.snapshotEvery && last?.merged) {
      const latest = [...state.snapshots.values()].sort((a, b) => b.seq - a.seq)[0];
      let n = state.snapshots.size + 1;
      while (state.snapshots.has(`snapshot-${n}`)) n++;
      actions.push({
        kind: "snapshot",
        id: `snapshot-${n}`,
        commit: last.merged.commit,
        previousSnapshotId: latest?.id ?? null,
        submissionIds: pending.map((s) => s.id),
      });
    }
  }

  // 8. Promote the newest unpromoted snapshot after the last promotion that
  // passes the promotion rule. Older candidates are covered by its ancestry.
  const lastPromotedSnapshotSeq = Math.max(-1, ...[...state.snapshots.values()].filter((s) => s.promoted).map((s) => s.seq));
  const candidates = [...state.snapshots.values()]
    .filter((s) => !s.promoted && s.seq > lastPromotedSnapshotSeq)
    .sort((a, b) => b.seq - a.seq);
  for (const snap of candidates) {
    if (promotion.evaluatePromotion(state, tree, snap.id, nowIso).pass) {
      actions.push({ kind: "promote", snapshotId: snap.id, commit: snap.commit });
      break;
    }
  }
  return actions;
}

// ---------------------------------------------------------------------------
// Executor
// ---------------------------------------------------------------------------

export type ReproductionOutcome = {
  reproduced: boolean;
  failsOnHead: boolean;
  passesOnParent: boolean;
  logDigest: string;
  harnessError?: string | null;
};

export type GithubBridge = {
  // Merges the submission's PR into dev; returns the resulting dev commit.
  // Must be idempotent: an already merged PR returns its merge commit.
  merge(submission: SubmissionState): Promise<CommitSha>;
  // Fast-forwards main to the snapshot commit. Idempotent.
  fastForwardMain(commit: CommitSha): Promise<void>;
};

export type BodyFn = (state: CommonsState) => EntryBody | Promise<EntryBody>;

export type ExecuteDeps = {
  state(): CommonsState; // live state, reflecting every append so far
  // Signed as the coordinator. A function body is evaluated against the state
  // the entry is appended to, under the store's lock, so nothing lands between
  // what it read and what it appends (LedgerStore.appendAsCoordinator).
  append(body: EntryBody | BodyFn): Promise<LedgerEntry> | LedgerEntry;
  tree: TreeView;
  // External entropy for the reviewer beacon (e.g. a public randomness round).
  entropy(submissionId: string): string | Promise<string>;
  // Runs the named gates (null = all) on the submission's head.
  runGates(submission: SubmissionState, gates: string[] | null): Promise<GateReport[]>;
  // null = cannot run yet (e.g. the test file was not uploaded); retried next pass.
  reproduce(action: Extract<Action, { kind: "reproduceFinding" }>): Promise<ReproductionOutcome | null>;
  bridge: GithubBridge;
  selection?: SelectionApi;
  onRevealPhaseClose?: (submissionId: string, missing: KeyId[]) => void;
};

export type LogLine = { action: Action; ok: boolean; detail: string; seqs: number[] };

export async function executeActions(actions: readonly Action[], deps: ExecuteDeps): Promise<LogLine[]> {
  const log: LogLine[] = [];
  for (const action of actions) {
    const seqs: number[] = [];
    const append = async (body: EntryBody | BodyFn) => {
      const e = await deps.append(body);
      seqs.push(e.seq);
      return e;
    };
    try {
      const detail = await execute(action, deps, append);
      log.push({ action, ok: true, detail, seqs });
    } catch (e) {
      log.push({ action, ok: false, detail: e instanceof Error ? e.message : String(e), seqs });
    }
  }
  return log;
}

type Append = (body: EntryBody | BodyFn) => Promise<LedgerEntry>;

async function execute(action: Action, deps: ExecuteDeps, append: Append): Promise<string> {
  switch (action.kind) {
    case "settle": {
      for (const b of action.bodies) await append(b);
      return `${action.bodies.length} settlements`;
    }
    case "suspend": {
      await append({ kind: "agentRevoked", agent: action.agent, reason: action.reason });
      return `suspended ${action.agent}`;
    }
    case "escape": {
      await append({ kind: "escape", findingId: action.findingId, snapshotId: action.snapshotId });
      return `escape ${action.findingId}`;
    }
    case "reproduceFinding": {
      const r = await deps.reproduce(action);
      if (r === null) return "skipped: not ready";
      // A harness error proves nothing either way; it is not recorded.
      if (r.harnessError) throw new Error(`harness error: ${r.harnessError}`);
      await append({
        kind: "findingResult",
        findingId: action.findingId,
        reproduced: r.failsOnHead && r.passesOnParent,
        failsOnHead: r.failsOnHead,
        passesOnParent: r.passesOnParent,
        logDigest: r.logDigest,
      });
      return r.failsOnHead && r.passesOnParent ? "reproduced" : "not reproduced";
    }
    case "runGates": {
      const s = deps.state().submissions.get(action.submissionId) ?? fail(`no submission ${action.submissionId}`);
      if (s.headCommit !== action.headCommit) fail("submission head changed since planning");
      const reports = await deps.runGates(s, action.gates);
      // Re-read: another pass may have recorded some gates meanwhile.
      const recorded = new Set((deps.state().submissions.get(s.id)?.gates ?? []).map((g) => g.gate));
      const wanted = action.gates === null ? null : new Set(action.gates);
      let n = 0;
      for (const r of reports) {
        if (recorded.has(r.gate) || (wanted && !wanted.has(r.gate))) continue;
        recorded.add(r.gate);
        await append({ kind: "gateResult", submissionId: s.id, gate: r.gate, pass: r.pass, details: r.details });
        n++;
      }
      if (n === 0) fail("gate runner returned no new results");
      return reports.map((r) => `${r.gate}:${r.pass ? "pass" : "fail"}`).join(" ");
    }
    case "assignReviewers": {
      const selection = deps.selection ?? load<SelectionApi>("selection");
      const entropy = await deps.entropy(action.submissionId);
      // The beacon covers the ledger head at assignment time, so it is computed
      // inside the append, against the state the entry is appended to: no other
      // entry can land in between and make verifyAssignment disagree.
      let note = "";
      await append((state) => {
        const beacon = selection.computeBeacon(state, action.submissionId, entropy);
        const picked = selection.selectReviewers(state, deps.tree, action.submissionId, beacon);
        if (picked.reviewers.length === 0) fail(`no eligible reviewers (${picked.notes.join("; ")})`);
        note = `${picked.reviewers.length} of ${picked.candidates} candidates${picked.notes.length ? `; ${picked.notes.join("; ")}` : ""}`;
        return { kind: "reviewAssignment", submissionId: action.submissionId, beacon, reviewers: picked.reviewers };
      });
      return note;
    }
    case "revealPhaseClose": {
      deps.onRevealPhaseClose?.(action.submissionId, action.missing);
      return `missing reviewers: ${action.missing.join(", ")}`;
    }
    case "merge": {
      // Checked and merged under the store lock: a finding posted while the
      // bridge merges would otherwise make the ledger refuse a merge GitHub
      // already made. The bridge call therefore needs its own timeout.
      let detail = "";
      await append(async (state) => {
        const s = state.submissions.get(action.submissionId) ?? fail(`no submission ${action.submissionId}`);
        if (s.merged) fail("already merged");
        for (const fid of s.findingIds) {
          const f = state.findings.get(fid);
          if (f?.result?.reproduced) fail(`finding ${fid} reproduced`);
          if (f && !f.result) fail(`finding ${fid} unresolved`);
        }
        const commit = await deps.bridge.merge(s);
        detail = `merged at ${commit}`;
        return { kind: "merge", submissionId: s.id, commit };
      });
      return detail;
    }
    case "snapshot": {
      const { id, commit, previousSnapshotId, submissionIds } = action;
      await append({ kind: "snapshot", id, commit, previousSnapshotId, submissionIds });
      return `${id}: ${submissionIds.length} submissions`;
    }
    case "promote": {
      const snap = deps.state().snapshots.get(action.snapshotId) ?? fail(`no snapshot ${action.snapshotId}`);
      if (snap.promoted) return "already promoted";
      await deps.bridge.fastForwardMain(action.commit);
      await append({ kind: "promotion", snapshotId: action.snapshotId, commit: action.commit });
      return `main at ${action.commit}`;
    }
  }
}

function fail(message: string): never {
  throw new Error(message);
}

// ---------------------------------------------------------------------------
// One pass of the loop.
// ---------------------------------------------------------------------------

export type RunDeps = ExecuteDeps & {
  clock: () => string;
  entries?: () => readonly LedgerEntry[];
  plan: Omit<PlanOptions, "humanApproval" | "entries">;
  // May be async (e.g. a GitHub review lookup); resolved before planning for
  // every unmerged submission that has reviewers, so the planner stays pure.
  humanApproval?: (submissionId: string) => boolean | Promise<boolean>;
};

export async function runOnce(deps: RunDeps): Promise<{ actions: Action[]; log: LogLine[] }> {
  const state = deps.state();
  const approved = new Set<string>();
  if (deps.humanApproval) {
    for (const s of state.submissions.values()) {
      if (!s.merged && s.assignment && (await deps.humanApproval(s.id))) approved.add(s.id);
    }
  }
  const actions = planActions(state, deps.tree, deps.clock(), {
    ...deps.plan,
    entries: deps.entries?.(),
    humanApproval: (sid) => approved.has(sid),
  });
  return { actions, log: await executeActions(actions, deps) };
}

// A reproducer over a local clone, for ExecuteDeps.reproduce. The finding's
// test file is the one uploaded through the server (findingTestFile); until it
// exists the finding is skipped. `reproduceFinding` is findings.ts's, passed in
// so this file does not run processes itself.
export function localReproducer(opts: {
  repoDir: string;
  testFile: (findingId: string) => string;
  reproduceFinding: (o: {
    repoDir: string;
    baseCommit: string;
    headCommit: string;
    testPath: string;
    testContent: string;
    testCommand: string;
  }) => Promise<ReproductionOutcome>;
}): ExecuteDeps["reproduce"] {
  return async (a) => {
    let testContent: string;
    try {
      testContent = readFileSync(opts.testFile(a.findingId), "utf8");
    } catch {
      return null;
    }
    return opts.reproduceFinding({
      repoDir: opts.repoDir,
      baseCommit: a.baseCommit,
      headCommit: a.headCommit,
      testPath: a.testPath,
      testContent,
      testCommand: a.testCommand,
    });
  };
}
