// The promotion rule (docs/protocol.md §5.11): whether a release snapshot may
// become `main`. Pure: the caller passes `nowIso`.
//
// A promotion ships the snapshot and every earlier snapshot it builds on that
// has not reached main yet, so every check runs over that whole ancestry (the
// "covered" submissions), the same walk ledger.ts uses for attestation and
// sign-off eligibility. Otherwise a change could be parked in an earlier
// snapshot nobody promoted and ride into main on a later, well-reviewed one.
//
// Not checked: that the snapshot commit descends from the current main or
// contains the covered merge commits. The ledger records commits but not git
// ancestry; the coordinator's fast-forward of main is what would refuse a
// non-descendant.

import { instantMs } from "./plants";
import { criticalUpperBound90, seededRecall } from "./risk";
import { ringOf } from "./rules";
import type { AgentState, CommonsState, FindingState, SnapshotState, SubmissionState, TreeView } from "./types";

export type PromotionCheck = { name: string; pass: boolean; detail: string };
export type PromotionResult = { pass: boolean; checks: PromotionCheck[] };

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const BLOCKING = new Set(["high", "critical"]);

// The snapshot and its unpromoted ancestors, newest first: the walk stops
// before the first promoted ancestor. A missing or repeated id ends the walk
// (replayed state cannot have either; hand-built state might).
export function coveredSnapshots(state: CommonsState, snapshotId: string): SnapshotState[] {
  const out: SnapshotState[] = [];
  const seen = new Set<string>();
  for (let cur: string | null = snapshotId; cur !== null && !seen.has(cur); ) {
    seen.add(cur);
    const snap = state.snapshots.get(cur);
    if (!snap || (out.length > 0 && snap.promoted)) break;
    out.push(snap);
    cur = snap.previousSnapshotId;
  }
  return out;
}

// Ids of the submissions a promotion of `snapshotId` would ship, in snapshot order.
export function coveredSubmissionIds(state: CommonsState, snapshotId: string): string[] {
  return coveredSnapshots(state, snapshotId).flatMap((s) => s.submissionIds);
}

// The promotion that already shipped this snapshot's content: its own, or a
// descendant's (a descendant's promotion ships its whole ancestry, but the
// ledger only marks the descendant). Promoting an ancestor afterwards would
// move main backwards.
function shippedBy(state: CommonsState, snapshotId: string): string | null {
  for (const snap of state.snapshots.values()) {
    if (!snap.promoted) continue;
    const seen = new Set<string>();
    for (let cur: string | null = snap.id; cur !== null && !seen.has(cur); ) {
      if (cur === snapshotId) return snap.id;
      seen.add(cur);
      cur = state.snapshots.get(cur)?.previousSnapshotId ?? null;
    }
  }
  return null;
}

function parseNow(nowIso: string): number {
  const now = instantMs(nowIso);
  if (Number.isNaN(now)) throw new RangeError(`invalid nowIso (need an ISO date-time with Z or ±HH:MM): ${nowIso}`);
  return now;
}

const fmt = (x: number): string => (Number.isFinite(x) ? x.toFixed(3) : String(x));

// `tree` is part of the shared signature. Coverage does not filter reviewers
// by tree distance: assignment already does for assigned seats, and open
// reviewers are a documented residual (threat model #4).
export function evaluatePromotion(
  state: CommonsState,
  _tree: TreeView,
  snapshotId: string,
  nowIso: string,
): PromotionResult {
  const now = parseNow(nowIso);
  const snap = state.snapshots.get(snapshotId);
  if (!snap) return { pass: false, checks: [{ name: "snapshot", pass: false, detail: `no snapshot ${snapshotId}` }] };

  const rules = state.rules;
  const p = rules.promotion;
  const chain = coveredSnapshots(state, snapshotId);
  const subIds = chain.flatMap((s) => s.submissionIds);
  const missing = subIds.filter((id) => !state.submissions.has(id));
  const subs = subIds.flatMap((id) => state.submissions.get(id) ?? []);
  const missingNote = missing.length > 0 ? `; unknown submissions: ${missing.join(", ")}` : "";
  const checks: PromotionCheck[] = [];

  // 0. Not already shipped.
  const shipped = shippedBy(state, snapshotId);
  checks.push({
    name: "notPromoted",
    pass: shipped === null,
    detail:
      shipped === null
        ? "not promoted"
        : shipped === snapshotId
          ? "already promoted"
          : `already shipped by the promotion of descendant ${shipped}`,
  });

  // 1. Coverage. Per covered submission: revealed reviews on it plus revealed
  // attestations on this snapshot. Agents of the author's owner never count
  // (the ledger refuses their commits; this holds for hand-built state too),
  // and neither do revoked agents: revocation is how a compromised or
  // injection-obeying agent is suspended, so its verdicts stop vouching.
  const attesters = snap.attestations.filter((a) => a.verdict !== undefined).map((a) => a.reviewer);
  const short: string[] = [];
  let minFamilies = Number.POSITIVE_INFINITY;
  let minOwners = Number.POSITIVE_INFINITY;
  for (const s of subs) {
    const authorOwner = state.agents.get(s.author)?.owner;
    const voters = [...s.reviews.filter((r) => r.verdict !== undefined).map((r) => r.reviewer), ...attesters]
      .map((k) => state.agents.get(k))
      .filter((a): a is AgentState => a !== undefined && a.active && a.owner !== authorOwner);
    const families = new Set(voters.map((a) => a.modelFamily));
    const owners = new Set(voters.map((a) => a.owner));
    minFamilies = Math.min(minFamilies, families.size);
    minOwners = Math.min(minOwners, owners.size);
    if (families.size < p.minModelFamilies || owners.size < p.minDistinctOwners) {
      short.push(
        `${s.id}: ${families.size}/${p.minModelFamilies} families [${[...families].sort().join(",")}], ${owners.size}/${p.minDistinctOwners} owners`,
      );
    }
  }
  checks.push({
    name: "coverage",
    pass: short.length === 0 && missing.length === 0 && subs.length > 0,
    detail:
      (short.length > 0
        ? `short: ${short.join("; ")}`
        : subs.length === 0
          ? "no covered submissions"
          : `${subs.length} covered submissions; fewest families ${minFamilies}, fewest other owners ${minOwners}`) +
      missingNote,
  });

  // 2 and 3. Seeded recall and the critical bound over the rules' window.
  const since = new Date(now - p.recallWindowDays * DAY_MS).toISOString();
  const recall = seededRecall(state, since);
  checks.push({
    name: "recall",
    pass: recall.seeds >= p.minSeeds && recall.lower90 >= p.minRecallLowerBound90,
    detail: `${recall.caught}/${recall.seeds} revealed plants caught since ${since}, lower90 ${fmt(recall.lower90)} (need >= ${p.minSeeds} seeds and lower90 >= ${p.minRecallLowerBound90})`,
  });
  const critical = criticalUpperBound90(state, since);
  checks.push({
    name: "criticals",
    pass: critical < p.maxCriticalUpperBound90,
    detail: `90% upper bound on undiscovered criticals ${fmt(critical)} (need < ${p.maxCriticalUpperBound90})`,
  });

  // 4. Open issues. A high or critical finding on a covered submission or on
  // any covered snapshot blocks while it has no result (undecided is not
  // clean) and when it reproduced: the defect is in this snapshot, and its fix
  // can only land in a later one. A covered submission that turned out to be a
  // plant (revealed after it merged) is a known defect of any severity and
  // blocks too.
  const subSet = new Set(subIds);
  const snapSet = new Set(chain.map((s) => s.id));
  const onCovered = (f: FindingState) =>
    "snapshotId" in f.target ? snapSet.has(f.target.snapshotId) : subSet.has(f.target.submissionId);
  const issues: string[] = [];
  for (const f of state.findings.values()) {
    if (!BLOCKING.has(f.severity) || !onCovered(f)) continue;
    if (!f.result) issues.push(`${f.id} (${f.severity}) unresolved`);
    else if (f.result.reproduced) issues.push(`${f.id} (${f.severity}) reproduced`);
  }
  for (const s of subs) if (s.planted) issues.push(`${s.id} is a revealed plant (${s.planted.severity})`);
  checks.push({
    name: "openIssues",
    pass: issues.length === 0,
    detail: issues.length === 0 ? "no open high or critical issues" : issues.sort().join("; "),
  });

  // 5. Kernel sign-off. Counted against the current rules: a signer removed by
  // a rulesChange no longer counts, nor does one who owns covered work (the
  // ledger checked that at signoff time over the same ancestry).
  const kernelSubs = subs.filter((s) => s.changedFiles.some((f) => ringOf(f, rules) === 0)).map((s) => s.id);
  if (kernelSubs.length === 0) {
    checks.push({ name: "kernel", pass: true, detail: "no covered submission touches ring 0" });
  } else {
    const authorOwners = new Set(subs.map((s) => state.agents.get(s.author)?.owner));
    const signers = new Set(snap.signoffs.filter((o) => rules.kernelSigners.includes(o) && !authorOwners.has(o)));
    checks.push({
      name: "kernel",
      pass: signers.size >= p.kernelSignoffs,
      detail: `ring 0 touched by ${kernelSubs.join(", ")}; ${signers.size}/${p.kernelSignoffs} kernel sign-offs${
        signers.size > 0 ? ` [${[...signers].sort().join(",")}]` : ""
      }${rules.kernelSigners.length === 0 ? "; no kernel signers named" : ""}`,
    });
  }

  // 6. Soak: a defect that triggers on a timer, or one the first users hit,
  // gets soakFloorHours on dev before it can reach main.
  const young: string[] = [];
  for (const s of subs) {
    const merged = s.merged ? instantMs(s.merged.at) : Number.NaN;
    const hours = (now - merged) / HOUR_MS;
    if (!(hours >= p.soakFloorHours)) {
      young.push(
        s.merged
          ? `${s.id} merged ${Number.isNaN(hours) ? "at an unreadable time" : `${hours.toFixed(1)}h ago`}`
          : `${s.id} not merged`,
      );
    }
  }
  checks.push({
    name: "soak",
    pass: young.length === 0 && missing.length === 0 && subs.length > 0,
    detail:
      (young.length === 0
        ? `every covered submission merged >= ${p.soakFloorHours}h ago`
        : `${young.join("; ")} (need >= ${p.soakFloorHours}h)`) + missingNote,
  });

  return { pass: checks.every((c) => c.pass), checks };
}
