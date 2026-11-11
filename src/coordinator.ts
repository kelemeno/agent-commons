// The coordinator loop: a pure planner and an effectful executor.
//
// planActions(state, tree, nowIso, opts) reads only its arguments and returns
// what the coordinator should do next. Every rule is decided from the ledger
// (plus the injected facts in PlanOptions), so planning is idempotent: once a
// plan's actions are executed (and their entries appended), planning again does
// not repeat them. Actions whose preconditions depend on an earlier action in
// the same plan (binding before gates, gates before reviewers, reviewers before
// merge, merge before snapshot) are planned on the next pass, never speculatively.
//
// What code is judged. The declared `headCommit` of a submission is chosen by
// its author and proves nothing about the uploaded patch, which is what
// reviewers read and what the bridge merges. So the first step for every
// submission is a binding: the bridge builds a bot commit from baseCommit +
// the stored patch, and the coordinator records it as the coordinator-signed
// gate result "patch" whose details are canonical({head, patchSha256}). Gates,
// finding reproduction and the merge (as the bridge's expected-sha guard) all
// use that bound head; the declared head is used only with
// `headBinding: "declared"` (an operator's own trusted repository).
//
// executeActions(actions, deps) performs them with injected effects: ledger
// appends as the coordinator, the patch binder, the gate runner, the
// reproduction harness, the GitHub bridge and the entropy source. Each action
// is isolated: a failure is logged and the rest still run. Reproductions run
// concurrently with the rest of the pass (they never sit in front of
// unrelated merges); snapshot and promote wait for them. Effects with an
// outside-world side (bridge merge, main fast-forward) happen inside the
// ledger lock, after the rule is re-checked against live state and before
// the entry that records them, so the ledger never claims a merge that did
// not happen and nothing lands between the check and the effect; the bridge
// calls must therefore be idempotent and carry their own timeouts.
//
// Trust boundary. A finding's testCommand, its test file and the submission's
// code are attacker-chosen. They must never run in the process, or as the
// uid, that holds the coordinator key, the ledger file, patchesDir or the
// GitHub token: localReproducer refuses to run without a sandbox argv, and
// that sandbox must be a separate uid or container with no network and only
// a copy of the repository. The same holds for any gate runner that executes
// submission code (ExecuteDeps.runGates).
//
// runOnce(deps) = read state, plan, execute.

import { readFileSync } from "node:fs";
import { canonical } from "./crypto";
import { uploadExists } from "./server";
import type {
  CommitSha,
  CommonsState,
  EntryBody,
  GateReport,
  KeyId,
  LedgerEntry,
  OwnerId,
  SnapshotState,
  SubmissionState,
  TreeView,
} from "./types";

type Body<K extends EntryBody["kind"]> = Extract<EntryBody, { kind: K }>;
export type SettlementBody = Body<"settlement">;
export type TaskBody = Body<"task">;
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
// Patch binding
// ---------------------------------------------------------------------------

// Reserved gate name for the binding; a gate runner may not report it.
export const BINDING_GATE = "patch";

export type PatchBinding = { head: CommitSha; patchSha256: string };

export function bindingDetails(b: PatchBinding): string {
  return canonical({ head: b.head, patchSha256: b.patchSha256 });
}

// The recorded binding, if the "patch" gate passed with well-formed details.
export function patchBinding(s: SubmissionState): PatchBinding | null {
  const g = s.gates.find((x) => x.gate === BINDING_GATE);
  if (!g?.pass) return null;
  try {
    const d = JSON.parse(g.details) as Record<string, unknown>;
    if (typeof d.head === "string" && d.head !== "" && typeof d.patchSha256 === "string") {
      return { head: d.head, patchSha256: d.patchSha256 };
    }
  } catch {
    // malformed details bind nothing
  }
  return null;
}

const bindingRequired = (opts: Pick<PlanOptions, "headBinding">) => (opts.headBinding ?? "required") === "required";

// The commit whose code is judged and merged; null while unbound.
export function codeHead(s: SubmissionState, opts: Pick<PlanOptions, "headBinding">): CommitSha | null {
  return bindingRequired(opts) ? (patchBinding(s)?.head ?? null) : s.headCommit;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type VoidReason = "no-test" | "harness-error";

export type Action =
  | { kind: "task"; body: TaskBody }
  | { kind: "honeytoken"; agent: KeyId; tokenId: string }
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
  // A finding that can never get a mechanical answer (no test uploaded within
  // the grace period, or the harness failed on it too often) is closed as not
  // reproduced, so its stake settles and it stops blocking the submission.
  | { kind: "voidFinding"; findingId: string; reason: VoidReason }
  | { kind: "bindPatch"; submissionId: string }
  | { kind: "runGates"; submissionId: string; headCommit: CommitSha; gates: string[] | null }
  | { kind: "assignReviewers"; submissionId: string }
  // The review window closed with a quorum of reveals; the reviewers who
  // never revealed count as missing. Planned only alongside the merge it
  // unblocks, so it is not repeated while the submission waits for something else.
  | { kind: "revealPhaseClose"; submissionId: string; missing: KeyId[] }
  | { kind: "merge"; submissionId: string }
  | { kind: "snapshot"; id: string; commit: CommitSha; previousSnapshotId: string | null; submissionIds: string[] }
  | { kind: "promote"; snapshotId: string; commit: CommitSha };

export type PlanOptions = {
  reviewWindowHours: number;
  // Revealed assigned reviews a merge needs; default max(1, assigned - 1),
  // clamped to [1, assigned]. A window that closes below quorum never merges.
  reviewQuorum?: number;
  // Gate names every submission must pass. Without it, at least one gate
  // besides the binding must exist and all must pass.
  requiredGates?: string[];
  // "required" (default): judge and merge only the bot commit bound to the
  // stored patch. "declared": trust the author's headCommit (trusted repos only).
  headBinding?: "required" | "declared";
  phase?: 1 | 2; // default 1: a human must approve every merge and confirm every reproduced finding
  humanApproval?: (submissionId: string) => boolean; // phase 1; absent = never approved
  // Phase 1: a reproduced finding pays and slashes (and records an escape) only
  // once a human confirmed it tests a real defect, not merely the intended
  // change. Absent = never confirmed. The merge stays blocked either way.
  findingConfirmed?: (findingId: string) => boolean;
  snapshotEvery?: number; // merged, unsnapshotted submissions that trigger a snapshot; absent = never
  // Binding and gates need the patch; while this says false they are not planned.
  patchAvailable?: (submissionId: string) => boolean;
  // false = the finder's test is not uploaded (or can never be). After
  // findingGraceHours such a finding is voided. Absent = unknown, never voided for it.
  findingTestAvailable?: (findingId: string) => boolean;
  findingGraceHours?: number; // default 24
  harnessErrors?: (findingId: string) => number; // failed harness runs so far
  maxHarnessErrors?: number; // default 3; then the finding is voided
  maxReproductionsPerPass?: number; // default 4, oldest findings first
  // While a plant commitment is unrevealed, merges of later submissions wait
  // until the review window closed plus this grace, so the custodian (who
  // reveals only after the window) can reveal before a plant merges. Default 1.
  plantRevealGraceHours?: number;
  // Ledger entries, to time the review window from the assignment entry.
  // Without them the window never counts as closed (fail closed).
  entries?: readonly LedgerEntry[];
  // Tasks an operator approved; appended as coordinator task entries once.
  approvedTasks?: readonly TaskBody[];
  // Decoy hits observed outside the ledger; appended once each.
  honeytokenHits?: readonly { agent: KeyId; tokenId: string }[];
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
  const now = Date.parse(nowIso);
  const waiting: string[] = [];
  let missing: KeyId[] = [];
  if (s.merged) waiting.push("already merged");
  if (s.planted) waiting.push("revealed plant");
  if (state.agents.get(s.author)?.active === false) waiting.push("author suspended");
  if (codeHead(s, opts) === null) waiting.push("patch not bound");
  waiting.push(...gateProblems(s, opts));
  const windowEnd = reviewWindowEnd(s, opts);
  if (!s.assignment) {
    waiting.push("no reviewers assigned");
  } else {
    const assigned = s.assignment.reviewers;
    const revealed = assigned.filter((r) => s.reviews.some((v) => v.reviewer === r && v.verdict !== undefined));
    const unrevealed = assigned.filter((r) => !revealed.includes(r));
    const quorum = Math.min(assigned.length, Math.max(1, opts.reviewQuorum ?? assigned.length - 1));
    if (unrevealed.length > 0) {
      const expired = windowEnd !== null && now >= windowEnd;
      if (!expired) waiting.push(`awaiting reveals from ${unrevealed.join(", ")}`);
      else if (revealed.length < quorum) {
        // Never "window expired" as "reviewed". A fresh draw needs a second
        // reviewAssignment, which the ledger does not accept yet.
        waiting.push(`review quorum not met: ${revealed.length} of ${quorum} revealed when the window closed`);
      } else missing = unrevealed;
    }
  }
  if (plantMayBePending(state, s)) {
    const grace = (opts.plantRevealGraceHours ?? 1) * HOUR;
    if (windowEnd === null || now < windowEnd + grace) waiting.push("plant reveal grace: a plant commitment is unrevealed");
  }
  for (const fid of s.findingIds) {
    const f = state.findings.get(fid);
    if (!f) continue;
    if (f.result?.reproduced) waiting.push(`reproduced finding ${fid}`);
    // Stricter than "no unresolved finding >= high": the ledger refuses a merge
    // while any finding on the submission is undecided (finding-pending). An
    // undecidable finding is voided after a deadline (voidFinding), so this
    // cannot block for ever.
    else if (!f.result) waiting.push(`unresolved ${f.severity} finding ${fid}`);
  }
  if ((opts.phase ?? 1) === 1 && opts.humanApproval?.(submissionId) !== true) waiting.push("awaiting human approval");
  return { ready: waiting.length === 0, missing, waiting };
}

// Problems with the gate record; empty means all required gates passed.
function gateProblems(s: SubmissionState, opts: PlanOptions): string[] {
  const out: string[] = [];
  for (const g of s.gates) if (!g.pass) out.push(`gate ${g.gate} failed`);
  const missing = missingGates(s, opts);
  if (missing === null) out.push("gates not run");
  else for (const name of missing) out.push(`gate ${name} not run`);
  return out;
}

// Required gates without a result; null when no gate besides the binding ran
// and no list is given (all gates are wanted).
function missingGates(s: SubmissionState, opts: PlanOptions): string[] | null {
  if (opts.requiredGates) return opts.requiredGates.filter((name) => !s.gates.some((g) => g.gate === name));
  return s.gates.some((g) => g.gate !== BINDING_GATE) ? [] : null;
}

// When the review window closes; null when the assignment time is unknown,
// which never counts as closed.
function reviewWindowEnd(s: SubmissionState, opts: PlanOptions): number | null {
  const seq = s.assignment?.seq;
  const entry = seq === undefined ? undefined : opts.entries?.[seq];
  if (!entry || entry.seq !== seq) return null;
  return Date.parse(entry.at) + opts.reviewWindowHours * HOUR;
}

// Some plant commitment is unrevealed and predates the submission, so it may
// be the plant. Which commitment a reveal used is not recorded, so this
// compares counts: every submission after a commitment is treated alike,
// which reveals nothing about which one is planted.
function plantMayBePending(state: CommonsState, s: SubmissionState): boolean {
  let revealed = 0;
  for (const x of state.submissions.values()) if (x.planted) revealed++;
  if (state.plantCommitments.length <= revealed) return false;
  return state.plantCommitments.some((c) => c.seq < s.submittedSeq);
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

// Base and head of what a finding claims is broken: the submission's bound
// code head (never the declared one unless trusted), or for a snapshot the
// previous snapshot or, for the first one, the base of its earliest merged
// submission.
function findingCommits(state: CommonsState, findingId: string, opts: PlanOptions): { base: CommitSha; head: CommitSha } | null {
  const f = state.findings.get(findingId);
  if (!f) return null;
  if ("submissionId" in f.target) {
    const s = state.submissions.get(f.target.submissionId);
    const head = s ? codeHead(s, opts) : null;
    return s && head !== null ? { base: s.baseCommit, head } : null;
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

// A merged submission's standing for snapshots: "defective" can never be
// snapshotted (its code needs a revert first), "pending" waits for a result.
function submissionStanding(state: CommonsState, s: SubmissionState): "clean" | "pending" | "defective" {
  if (s.planted) return "defective";
  let pending = false;
  for (const fid of s.findingIds) {
    const f = state.findings.get(fid);
    if (f?.result?.reproduced) return "defective";
    if (f && !f.result) pending = true;
  }
  return pending ? "pending" : "clean";
}

// Why main must not move to this snapshot: any reproduced or undecided
// finding on it, on an unpromoted ancestor, or on a submission they cover.
export function ancestryProblems(state: CommonsState, snapshotId: string): string[] {
  const out: string[] = [];
  const ids = new Set<string>();
  const subs = new Set<string>();
  for (let cur: SnapshotState | undefined = state.snapshots.get(snapshotId); cur; ) {
    ids.add(cur.id);
    for (const sid of cur.submissionIds) subs.add(sid);
    const prev = cur.previousSnapshotId === null ? undefined : state.snapshots.get(cur.previousSnapshotId);
    if (!prev || prev.promoted) break;
    cur = prev;
  }
  for (const f of state.findings.values()) {
    const hit = "snapshotId" in f.target ? ids.has(f.target.snapshotId) : subs.has(f.target.submissionId);
    if (!hit) continue;
    if (f.result?.reproduced) out.push(`reproduced finding ${f.id}`);
    else if (!f.result) out.push(`unresolved finding ${f.id}`);
  }
  for (const sid of subs) if (state.submissions.get(sid)?.planted) out.push(`revealed plant ${sid}`);
  return out;
}

const settlementKey = (b: { owner: OwnerId; reason: string; ref: string }) => `${b.owner}\u0000${b.reason}\u0000${b.ref}`;

export function planActions(state: CommonsState, tree: TreeView, nowIso: string, opts: PlanOptions): Action[] {
  const incentives = opts.incentives ?? load<IncentivesApi>("incentives");
  const promotion = opts.promotion ?? load<PromotionApi>("promotion");
  const now = Date.parse(nowIso);
  const phase1 = (opts.phase ?? 1) === 1;
  const actions: Action[] = [];

  // 0. Coordinator entries from outside facts: approved tasks, decoy hits.
  for (const t of opts.approvedTasks ?? []) {
    if (!state.tasks.has(t.id) && state.proposals.has(t.proposalId)) actions.push({ kind: "task", body: t });
  }
  const recordedHits = new Set(state.honeytokens.map((h) => `${h.agent}\u0000${h.tokenId}`));
  for (const h of opts.honeytokenHits ?? []) {
    const k = `${h.agent}\u0000${h.tokenId}`;
    if (recordedHits.has(k) || !state.agents.has(h.agent)) continue;
    recordedHits.add(k);
    actions.push({ kind: "honeytoken", agent: h.agent, tokenId: h.tokenId });
  }

  // 1. Consequences of events already on the ledger: escapes, then settlements.
  // incentives.ts promises idempotency; the filter against recorded settlements
  // (owner + reason + ref, the same key) keeps the plan idempotent regardless.
  const bodies: SettlementBody[] = [];
  const escapes = new Set(state.escapes.map((e) => e.findingId));
  for (const f of state.findings.values()) {
    if (!f.result) continue;
    if (f.result.reproduced) {
      // A test can be made to "reproduce" by asserting the old text the change
      // intentionally removed. In phase 1 a human confirms before anyone is
      // paid or slashed and before an escape is recorded.
      if (phase1 && opts.findingConfirmed?.(f.id) !== true) continue;
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

  // 3. Findings without a result: void the undecidable ones, reproduce the
  // rest (oldest first, a bounded number per pass).
  const grace = (opts.findingGraceHours ?? 24) * HOUR;
  const maxErrors = opts.maxHarnessErrors ?? 3;
  let budget = opts.maxReproductionsPerPass ?? 4;
  const open = [...state.findings.values()].filter((f) => !f.result).sort((a, b) => a.seq - b.seq);
  for (const f of open) {
    if ((opts.harnessErrors?.(f.id) ?? 0) >= maxErrors) {
      actions.push({ kind: "voidFinding", findingId: f.id, reason: "harness-error" });
      continue;
    }
    if (opts.findingTestAvailable?.(f.id) === false) {
      if (now >= Date.parse(f.at) + grace) actions.push({ kind: "voidFinding", findingId: f.id, reason: "no-test" });
      continue;
    }
    const commits = findingCommits(state, f.id, opts);
    if (!commits || budget <= 0) continue;
    budget--;
    actions.push({
      kind: "reproduceFinding",
      findingId: f.id,
      baseCommit: commits.base,
      headCommit: commits.head,
      testPath: f.testPath,
      testCommand: f.testCommand,
    });
  }

  // 4-6. Per submission: binding, gates once per bound head, reviewers, merge.
  for (const s of state.submissions.values()) {
    if (s.merged || s.planted) continue;
    // Code by an agent known to follow injected instructions goes no further.
    if (state.agents.get(s.author)?.active === false) continue;
    if (bindingRequired(opts) && !s.gates.some((g) => g.gate === BINDING_GATE)) {
      if (opts.patchAvailable?.(s.id) !== false) actions.push({ kind: "bindPatch", submissionId: s.id });
      continue;
    }
    const head = codeHead(s, opts);
    if (head === null) continue; // the binding failed: the patch does not apply
    const missing = missingGates(s, opts);
    if (missing === null || missing.length > 0) {
      if (opts.patchAvailable?.(s.id) !== false) {
        actions.push({ kind: "runGates", submissionId: s.id, headCommit: head, gates: missing });
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

  // 7. Snapshot once enough merged submissions are outside every snapshot.
  // Dev is linear, so a snapshot at a merge commit contains every earlier
  // merge: it can only cover a prefix in merge order, and the prefix stops
  // before the first submission with an undecided finding (wait) or a known
  // defect (needs a revert, which no action does yet).
  if (opts.snapshotEvery !== undefined && opts.snapshotEvery > 0) {
    const inSnapshot = new Set<string>();
    for (const snap of state.snapshots.values()) for (const id of snap.submissionIds) inSnapshot.add(id);
    const pending = [...state.submissions.values()]
      .filter((s) => s.merged && !inSnapshot.has(s.id))
      .sort((a, b) => (a.merged?.seq ?? 0) - (b.merged?.seq ?? 0));
    const prefix: SubmissionState[] = [];
    for (const s of pending) {
      if (submissionStanding(state, s) !== "clean") break;
      prefix.push(s);
    }
    const last = prefix[prefix.length - 1];
    if (prefix.length >= opts.snapshotEvery && last?.merged) {
      const latest = [...state.snapshots.values()].sort((a, b) => b.seq - a.seq)[0];
      let n = state.snapshots.size + 1;
      while (state.snapshots.has(`snapshot-${n}`)) n++;
      actions.push({
        kind: "snapshot",
        id: `snapshot-${n}`,
        commit: last.merged.commit,
        previousSnapshotId: latest?.id ?? null,
        submissionIds: prefix.map((s) => s.id),
      });
    }
  }

  // 8. Promote the newest unpromoted snapshot after the last promotion that
  // passes the promotion rule and has no open or reproduced finding in its
  // ancestry. Older candidates are covered by its ancestry.
  const lastPromotedSnapshotSeq = Math.max(-1, ...[...state.snapshots.values()].filter((s) => s.promoted).map((s) => s.seq));
  const candidates = [...state.snapshots.values()]
    .filter((s) => !s.promoted && s.seq > lastPromotedSnapshotSeq)
    .sort((a, b) => b.seq - a.seq);
  for (const snap of candidates) {
    if (ancestryProblems(state, snap.id).length > 0) continue;
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
  // `expectedHead` is the bound code head: the bridge must pass it as the
  // merge's sha guard (mergePullRequest's sha) and refuse if the PR head moved.
  // Must be idempotent: an already merged PR returns its merge commit.
  merge(submission: SubmissionState, expectedHead: CommitSha): Promise<CommitSha>;
  // Fast-forwards main to the snapshot commit. Idempotent.
  fastForwardMain(commit: CommitSha): Promise<void>;
};

export type BodyFn = (state: CommonsState) => EntryBody | Promise<EntryBody>;

// What the executor re-checks under the ledger lock right before an effect:
// the merge rule (including a fresh human approval) and the promotion rule.
export type Recheck = {
  clock: () => string;
  opts: PlanOptions;
  // Re-asked under the lock; absent = opts.humanApproval.
  humanApproval?: (submissionId: string) => boolean | Promise<boolean>;
};

export type ExecuteDeps = {
  state(): CommonsState; // live state, reflecting every append so far
  // Signed as the coordinator. A function body is evaluated against the state
  // the entry is appended to, under the store's lock, so nothing lands between
  // what it read and what it appends (LedgerStore.appendAsCoordinator).
  append(body: EntryBody | BodyFn): Promise<LedgerEntry> | LedgerEntry;
  tree: TreeView;
  recheck: Recheck;
  // External entropy for the reviewer beacon (e.g. a public randomness round).
  // Recorded in the log line, so the beacon can be recomputed.
  entropy(submissionId: string): string | Promise<string>;
  // Builds the bot commit from baseCommit + the stored patch (idempotent) and
  // opens or updates the bot-owned PR at it. patchSha256 = sha256hex of the
  // stored patch file, the bytes GET /api/patches/:id serves to reviewers.
  // null = no patch yet; {error} = the patch does not apply (the "patch" gate fails).
  bindPatch?: (submission: SubmissionState) => Promise<PatchBinding | { error: string } | null>;
  // Runs the named gates (null = all) on the submission, whose headCommit is
  // the bound code head. A runner that executes submission code must do it
  // in a sandbox outside the coordinator's uid (see the header).
  runGates(submission: SubmissionState, gates: string[] | null): Promise<GateReport[]>;
  // null = cannot run yet (the test file was not uploaded); retried next pass.
  // A returned harnessError counts toward maxHarnessErrors; a thrown error
  // (an operator problem, e.g. no sandbox) does not.
  reproduce(action: Extract<Action, { kind: "reproduceFinding" }>): Promise<ReproductionOutcome | null>;
  // Harness errors per finding, kept by the caller across passes.
  harnessErrors?: Map<string, number>;
  reproduceConcurrency?: number; // default 2
  bridge: GithubBridge;
  selection?: SelectionApi;
  onRevealPhaseClose?: (submissionId: string, missing: KeyId[]) => void;
};

export type LogLine = { action: Action; ok: boolean; detail: string; seqs: number[] };

// The log is in action order. Reproductions run concurrently (bounded) beside
// the other actions; snapshot and promote wait until they are all done, so a
// finding reproduced in this pass is seen by their re-check.
export async function executeActions(actions: readonly Action[], deps: ExecuteDeps): Promise<LogLine[]> {
  const log: LogLine[] = new Array<LogLine>(actions.length);
  const run = async (i: number) => {
    const action = actions[i] as Action;
    const seqs: number[] = [];
    const append = async (body: EntryBody | BodyFn) => {
      const e = await deps.append(body);
      seqs.push(e.seq);
      return e;
    };
    try {
      log[i] = { action, ok: true, detail: await execute(action, deps, append), seqs };
    } catch (e) {
      log[i] = { action, ok: false, detail: e instanceof Error ? e.message : String(e), seqs };
    }
  };
  const repro = actions.flatMap((a, i) => (a.kind === "reproduceFinding" ? [i] : []));
  let next = 0;
  const worker = async () => {
    while (next < repro.length) await run(repro[next++] as number);
  };
  const workers = Math.min(repro.length, Math.max(1, deps.reproduceConcurrency ?? 2));
  const reproductions = Promise.all(Array.from({ length: workers }, worker));
  for (let i = 0; i < actions.length; i++) {
    const kind = actions[i]?.kind;
    if (kind === "reproduceFinding") continue;
    if (kind === "snapshot" || kind === "promote") await reproductions;
    await run(i);
  }
  await reproductions;
  return log;
}

type Append = (body: EntryBody | BodyFn) => Promise<LedgerEntry>;

async function execute(action: Action, deps: ExecuteDeps, append: Append): Promise<string> {
  switch (action.kind) {
    case "task": {
      await append(action.body);
      return `task ${action.body.id}`;
    }
    case "honeytoken": {
      await append({ kind: "honeytokenTriggered", agent: action.agent, tokenId: action.tokenId });
      return `honeytoken ${action.tokenId} by ${action.agent}`;
    }
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
      // A harness error proves nothing either way; it is not recorded, but it
      // is counted, and after maxHarnessErrors the planner voids the finding.
      if (r.harnessError) {
        deps.harnessErrors?.set(action.findingId, (deps.harnessErrors.get(action.findingId) ?? 0) + 1);
        throw new Error(`harness error: ${r.harnessError}`);
      }
      await append((state) => {
        if (state.findings.get(action.findingId)?.result) fail("finding already has a result");
        return {
          kind: "findingResult",
          findingId: action.findingId,
          reproduced: r.failsOnHead && r.passesOnParent,
          failsOnHead: r.failsOnHead,
          passesOnParent: r.passesOnParent,
          logDigest: r.logDigest,
        };
      });
      return r.failsOnHead && r.passesOnParent ? "reproduced" : "not reproduced";
    }
    case "voidFinding": {
      await append((state) => {
        if (state.findings.get(action.findingId)?.result) fail("finding already has a result");
        return {
          kind: "findingResult",
          findingId: action.findingId,
          reproduced: false,
          failsOnHead: false,
          passesOnParent: false,
          logDigest: `void:${action.reason}`,
        };
      });
      return `voided (${action.reason})`;
    }
    case "bindPatch": {
      const s = deps.state().submissions.get(action.submissionId) ?? fail(`no submission ${action.submissionId}`);
      if (!deps.bindPatch) fail("no patch binder configured (ExecuteDeps.bindPatch); the declared headCommit is not trusted");
      const b = await deps.bindPatch(s);
      if (b === null) return "skipped: no patch yet";
      await append((state) => {
        if (state.submissions.get(s.id)?.gates.some((g) => g.gate === BINDING_GATE)) fail("already bound");
        return "error" in b
          ? { kind: "gateResult", submissionId: s.id, gate: BINDING_GATE, pass: false, details: b.error }
          : { kind: "gateResult", submissionId: s.id, gate: BINDING_GATE, pass: true, details: bindingDetails(b) };
      });
      return "error" in b ? `patch does not bind: ${b.error}` : `bound to ${b.head} (patch ${b.patchSha256})`;
    }
    case "runGates": {
      const s = deps.state().submissions.get(action.submissionId) ?? fail(`no submission ${action.submissionId}`);
      if (codeHead(s, deps.recheck.opts) !== action.headCommit) fail("submission code head changed since planning");
      const reports = await deps.runGates({ ...s, headCommit: action.headCommit }, action.gates);
      // Re-read: another pass may have recorded some gates meanwhile.
      const recorded = new Set((deps.state().submissions.get(s.id)?.gates ?? []).map((g) => g.gate));
      const wanted = action.gates === null ? null : new Set(action.gates);
      let n = 0;
      for (const r of reports) {
        if (r.gate === BINDING_GATE || recorded.has(r.gate) || (wanted && !wanted.has(r.gate))) continue;
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
      // entry can land in between and make verifyAssignment disagree. The
      // reviewAssignment entry has no field for the entropy, so it is in the log.
      let note = "";
      await append((state) => {
        const beacon = selection.computeBeacon(state, action.submissionId, entropy);
        const picked = selection.selectReviewers(state, deps.tree, action.submissionId, beacon);
        if (picked.reviewers.length === 0) fail(`no eligible reviewers (${picked.notes.join("; ")})`);
        note = `entropy ${JSON.stringify(entropy)}; beacon ${beacon}; ${picked.reviewers.length} of ${picked.candidates} candidates${picked.notes.length ? `; ${picked.notes.join("; ")}` : ""}`;
        return { kind: "reviewAssignment", submissionId: action.submissionId, beacon, reviewers: picked.reviewers };
      });
      return note;
    }
    case "revealPhaseClose": {
      deps.onRevealPhaseClose?.(action.submissionId, action.missing);
      return `missing reviewers: ${action.missing.join(", ")}`;
    }
    case "merge": {
      // The whole merge rule, re-checked under the store lock with a fresh
      // human approval: a finding posted, or an approval withdrawn, while this
      // pass ran must stop the merge. The bridge merges the bound head only.
      let detail = "";
      await append(async (state) => {
        const s = state.submissions.get(action.submissionId) ?? fail(`no submission ${action.submissionId}`);
        const ask = deps.recheck.humanApproval ?? deps.recheck.opts.humanApproval;
        const approved = ask === undefined ? false : await ask(s.id);
        const r = mergeReadiness(state, s.id, deps.recheck.clock(), { ...deps.recheck.opts, humanApproval: () => approved });
        if (!r.ready) fail(`not mergeable: ${r.waiting.join("; ")}`);
        const head = codeHead(s, deps.recheck.opts) ?? fail("patch not bound");
        const commit = await deps.bridge.merge({ ...s, headCommit: head }, head);
        detail = `merged ${head} at ${commit}`;
        return { kind: "merge", submissionId: s.id, commit };
      });
      return detail;
    }
    case "snapshot": {
      const { id, commit, previousSnapshotId, submissionIds } = action;
      await append((state) => {
        for (const sid of submissionIds) {
          const s = state.submissions.get(sid) ?? fail(`no submission ${sid}`);
          const standing = submissionStanding(state, s);
          if (standing !== "clean") fail(`submission ${sid} is ${standing}`);
        }
        return { kind: "snapshot", id, commit, previousSnapshotId, submissionIds };
      });
      return `${id}: ${submissionIds.length} submissions`;
    }
    case "promote": {
      if (deps.state().snapshots.get(action.snapshotId)?.promoted) return "already promoted";
      const promotion = deps.recheck.opts.promotion ?? load<PromotionApi>("promotion");
      // Re-checked against live state under the lock, then main moves, then
      // the entry: nothing can land between the check and the fast-forward.
      await append(async (state) => {
        const snap = state.snapshots.get(action.snapshotId) ?? fail(`no snapshot ${action.snapshotId}`);
        if (snap.promoted) fail("already promoted");
        if (snap.commit !== action.commit) fail("snapshot commit differs from the planned one");
        const problems = ancestryProblems(state, snap.id);
        if (problems.length > 0) fail(`not promotable: ${problems.join("; ")}`);
        const verdict = promotion.evaluatePromotion(state, deps.tree, snap.id, deps.recheck.clock());
        if (!verdict.pass) {
          const failed = verdict.checks.filter((c) => !c.pass).map((c) => c.name);
          fail(`promotion rule fails: ${failed.join(", ")}`);
        }
        await deps.bridge.fastForwardMain(action.commit);
        return { kind: "promotion", snapshotId: snap.id, commit: action.commit };
      });
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

export type RunDeps = Omit<ExecuteDeps, "recheck"> & {
  clock: () => string;
  entries?: () => readonly LedgerEntry[];
  plan: Omit<PlanOptions, "humanApproval" | "entries" | "findingConfirmed" | "harnessErrors" | "approvedTasks" | "honeytokenHits">;
  // May be async (e.g. a GitHub review lookup); resolved before planning for
  // every unmerged submission that has reviewers, so the planner stays pure,
  // and asked again under the lock right before each merge.
  humanApproval?: (submissionId: string) => boolean | Promise<boolean>;
  // Phase 1: a human confirmed this reproduced finding (see PlanOptions).
  findingConfirmed?: (findingId: string) => boolean | Promise<boolean>;
  // The server's patchesDir: defaults patchAvailable and findingTestAvailable
  // from the uploads on disk unless plan sets them.
  patchesDir?: string;
  approvedTasks?: () => readonly TaskBody[] | Promise<readonly TaskBody[]>;
  honeytokenHits?: () => readonly { agent: KeyId; tokenId: string }[] | Promise<readonly { agent: KeyId; tokenId: string }[]>;
};

export async function runOnce(deps: RunDeps): Promise<{ actions: Action[]; log: LogLine[] }> {
  const state = deps.state();
  const approved = new Set<string>();
  if (deps.humanApproval) {
    for (const s of state.submissions.values()) {
      if (!s.merged && s.assignment && (await deps.humanApproval(s.id))) approved.add(s.id);
    }
  }
  const confirmed = new Set<string>();
  if (deps.findingConfirmed) {
    for (const f of state.findings.values()) {
      if (f.result?.reproduced && (await deps.findingConfirmed(f.id))) confirmed.add(f.id);
    }
  }
  const dir = deps.patchesDir;
  const harness = deps.harnessErrors;
  const opts: PlanOptions = {
    ...(dir === undefined
      ? {}
      : {
          patchAvailable: (sid: string) => uploadExists(dir, "patch", sid),
          findingTestAvailable: (fid: string) => uploadExists(dir, "findingTest", fid),
        }),
    ...deps.plan,
    entries: deps.entries?.(),
    humanApproval: (sid) => approved.has(sid),
    findingConfirmed: (fid) => confirmed.has(fid),
    ...(harness === undefined ? {} : { harnessErrors: (fid: string) => harness.get(fid) ?? 0 }),
    approvedTasks: deps.approvedTasks ? await deps.approvedTasks() : undefined,
    honeytokenHits: deps.honeytokenHits ? await deps.honeytokenHits() : undefined,
  };
  const actions = planActions(state, deps.tree, deps.clock(), opts);
  const recheck: Recheck = { clock: deps.clock, opts, ...(deps.humanApproval ? { humanApproval: deps.humanApproval } : {}) };
  return { actions, log: await executeActions(actions, { ...deps, recheck }) };
}

// A reproducer over a local clone, for ExecuteDeps.reproduce. The finding's
// test file is the one uploaded through the server (findingTestFile); until it
// exists the finding is skipped. `reproduceFinding` is findings.ts's, passed in
// so this file does not run processes itself.
//
// It refuses to run without `sandbox`: the command, the test and the head's
// code are chosen by strangers. The sandbox argv must put them outside the
// coordinator's uid (a container or a dedicated user, no network, a copy of
// the repository); findings.ts's PID_NAMESPACE_SANDBOX alone still runs as the
// coordinator's uid and can read its files. The refusal is thrown, not
// returned as a harness error, so a misconfigured coordinator never voids
// findings.
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
    timeoutMs?: number;
    env?: Record<string, string>;
    sandbox?: readonly string[];
  }) => Promise<ReproductionOutcome>;
  sandbox?: readonly string[];
  timeoutMs?: number; // per run; bounds what a hanging test costs a pass
  env?: Record<string, string>;
}): ExecuteDeps["reproduce"] {
  return async (a) => {
    const sandbox = opts.sandbox;
    if (!sandbox || sandbox.length === 0) {
      throw new Error("refusing to run an untrusted finding without a sandbox (localReproducer opts.sandbox)");
    }
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
      sandbox,
      ...(opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs }),
      ...(opts.env === undefined ? {} : { env: opts.env }),
    });
  };
}
