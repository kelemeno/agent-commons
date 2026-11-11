// The promotion rule (docs/protocol.md §5.11): whether a release snapshot may
// become `main`. Pure: the caller passes `nowIso`.
//
// A promotion ships the snapshot and every earlier snapshot it builds on that
// has not reached main yet, so the checks run over that whole ancestry (the
// "covered" submissions), the same walk ledger.ts uses for attestation and
// sign-off eligibility. Otherwise a change could be parked in an earlier
// snapshot nobody promoted and ride into main on a later, well-reviewed one.
// The ancestry comes from `previousSnapshotId`, which the ledger lets the
// coordinator (or an operator with the CLI) set to anything; dev is linear, so
// a snapshot commit holds every earlier merge whatever it names. The lineage
// check closes that gap from the ledger alone: every submission merged before
// the snapshot must be covered by it or already be on main.
//
// Not checked: that the snapshot commit descends from the current main or
// contains the covered merge commits. The ledger records commits but not git
// ancestry; the coordinator's fast-forward of main is what would refuse a
// non-descendant. The lineage check assumes, as the coordinator does, that a
// snapshot commit is the dev head when the snapshot was taken.
//
// Known gaps, all needing new ledger entries (none exist in types.ts yet):
// - A block from openIssues is permanent. A reproduced finding or a revealed
//   plant in covered work has no entry that records its fix or revert, so the
//   snapshot holding it and every snapshot built on it stay unpromotable.
// - One stranger can therefore freeze main for one finding stake: a high or
//   critical finding that never gets a result (a test that always times out,
//   or one never uploaded), or a test that "reproduces" against any change
//   (say, one that compares a file's hash with its parent's). Needs a
//   coordinator-closed result after repeated harness errors, a re-run of a
//   finding's test at a later snapshot, and a signed adjudication of severity.
// - Coverage cannot be topped up once an attestation is revealed (the ledger
//   closes commits), so an ancestor snapshot that closed short of coverage
//   blocks its descendants for good. Attestations count only for the snapshot
//   they were made on, because attesters diff from the previous snapshot's
//   commit (agent-kit/roles/attester.md) and never see an ancestor's code.
// - AgentState does not record who revoked an agent. Coverage drops the
//   verdicts of agents with a honeytokenTriggered entry (the coordinator's
//   only automatic suspension) and keeps those of other revoked agents, so a
//   coordinator revocation for any other reason (say, a leaked key) does not
//   withdraw that agent's past verdicts.

import { instantMs } from "./plants";
import { criticalUpperBound90, seededRecall } from "./risk";
import { ringOf } from "./rules";
import type { AgentState, CommonsState, FindingState, SnapshotState, TreeView } from "./types";

export type PromotionCheck = { name: string; pass: boolean; detail: string };
export type PromotionResult = { pass: boolean; checks: PromotionCheck[] };

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
// Severities that block while a finding has no result. A reproduced finding
// blocks at any severity: the severity is the finder's own claim.
const BLOCKING_UNRESOLVED = new Set(["high", "critical"]);

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

// For every snapshot already on main, the promotion that shipped it: its own,
// or a descendant's (a descendant's promotion ships its whole ancestry, but the
// ledger only marks the descendant). The earliest such promotion wins.
function shippedSnapshots(state: CommonsState): Map<string, SnapshotState> {
  const out = new Map<string, SnapshotState>();
  const promoted = [...state.snapshots.values()].filter((s) => s.promoted);
  promoted.sort((a, b) => (a.promoted?.seq ?? 0) - (b.promoted?.seq ?? 0));
  for (const snap of promoted) {
    const seen = new Set<string>();
    for (let cur: string | null = snap.id; cur !== null && !seen.has(cur); ) {
      seen.add(cur);
      if (!out.has(cur)) out.set(cur, snap);
      cur = state.snapshots.get(cur)?.previousSnapshotId ?? null;
    }
  }
  return out;
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
  const shippedMap = shippedSnapshots(state);
  const checks: PromotionCheck[] = [];

  // 0. Not already shipped, and main has not moved past this snapshot: a
  // promoted snapshot taken later holds this one's content (dev is linear), so
  // promoting this one afterwards would move main backwards.
  const shipped = shippedMap.get(snapshotId)?.id ?? null;
  const later = [...state.snapshots.values()]
    .filter((s) => s.promoted && s.seq > snap.seq)
    .map((s) => s.id)
    .sort();
  checks.push({
    name: "notPromoted",
    pass: shipped === null && later.length === 0,
    detail:
      shipped === snapshotId
        ? "already promoted"
        : shipped !== null
          ? `already shipped by the promotion of descendant ${shipped}`
          : later.length > 0
            ? `main has moved past it: later snapshot ${later.join(", ")} was promoted`
            : "not promoted",
  });

  // 1. Lineage. Every submission merged before this snapshot was taken is in
  // its commit, so it must be covered here or already be on main: in a shipped
  // snapshot, or merged before the latest promoted snapshot was taken.
  // Otherwise a snapshot that names an older previousSnapshotId (or null), or
  // leaves submissions out, ships work no check below looked at.
  const covered = new Set(subIds);
  const onMain = new Set<string>();
  for (const id of shippedMap.keys()) for (const sid of state.snapshots.get(id)?.submissionIds ?? []) onMain.add(sid);
  let mainSeq = -1;
  for (const s of state.snapshots.values()) if (s.promoted && s.seq > mainSeq) mainSeq = s.seq;
  const snapshotOf = new Map<string, string>();
  for (const s of state.snapshots.values()) for (const sid of s.submissionIds) snapshotOf.set(sid, s.id);
  const uncovered: string[] = [];
  for (const s of state.submissions.values()) {
    if (!s.merged || s.merged.seq >= snap.seq || s.merged.seq < mainSeq) continue;
    if (covered.has(s.id) || onMain.has(s.id)) continue;
    const where = snapshotOf.get(s.id);
    uncovered.push(where === undefined ? `${s.id} (in no snapshot)` : `${s.id} (in ${where}, not on this chain)`);
  }
  checks.push({
    name: "lineage",
    pass: uncovered.length === 0,
    detail:
      uncovered.length === 0
        ? "every earlier merge is covered or on main"
        : `merged before this snapshot but neither covered nor on main: ${uncovered.sort().join("; ")}`,
  });

  // 2. Coverage. Per covered submission: revealed reviews on it plus revealed
  // attestations on the snapshot that lists it. An attestation on a later
  // snapshot does not count: its attesters diffed from the previous snapshot's
  // commit and never saw this code. Agents of the author's owner never count
  // (the ledger refuses their commits; this holds for hand-built state too).
  // Agents that obeyed a honeytoken never count: that is the coordinator's
  // only automatic suspension, and their verdicts are suspect. An agent its
  // owner revoked keeps its verdicts: revocation is also routine key rotation,
  // and dropping them would let an owner withdraw vouching for free when the
  // ledger no longer lets anyone replace it.
  const suspended = new Set(state.honeytokens.map((h) => h.agent));
  const short: string[] = [];
  let minFamilies = Number.POSITIVE_INFINITY;
  let minOwners = Number.POSITIVE_INFINITY;
  for (const x of chain) {
    const attesters = x.attestations.filter((a) => a.verdict !== undefined).map((a) => a.reviewer);
    for (const s of x.submissionIds.flatMap((id) => state.submissions.get(id) ?? [])) {
      const authorOwner = state.agents.get(s.author)?.owner;
      const voters = [...s.reviews.filter((r) => r.verdict !== undefined).map((r) => r.reviewer), ...attesters]
        .filter((k) => !suspended.has(k))
        .map((k) => state.agents.get(k))
        .filter((a): a is AgentState => a !== undefined && a.owner !== authorOwner);
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

  // 3 and 4. Seeded recall and the critical bound over the rules' window.
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

  // 5. Open issues, over findings on a covered submission or covered snapshot.
  // A reproduced finding blocks at any severity: the defect is in this
  // snapshot, its fix can only land in a later one, and the severity is the
  // finder's unchecked claim (a real backdoor filed as "medium" must not
  // ship). A finding without a result blocks if high or critical (undecided is
  // not clean); the threshold bounds what an unresolvable finding can block.
  // A covered submission revealed as a plant after it merged is a known defect
  // and blocks too. See the header: none of these blocks can be cleared yet.
  const snapSet = new Set(chain.map((s) => s.id));
  const onCovered = (f: FindingState) =>
    "snapshotId" in f.target ? snapSet.has(f.target.snapshotId) : covered.has(f.target.submissionId);
  const issues: string[] = [];
  for (const f of state.findings.values()) {
    if (!onCovered(f)) continue;
    if (!f.result) {
      if (BLOCKING_UNRESOLVED.has(f.severity)) issues.push(`${f.id} (${f.severity}) unresolved`);
    } else if (f.result.reproduced) issues.push(`${f.id} (${f.severity}) reproduced`);
  }
  for (const s of subs) if (s.planted) issues.push(`${s.id} is a revealed plant (${s.planted.severity})`);
  checks.push({
    name: "openIssues",
    pass: issues.length === 0,
    detail:
      issues.length === 0 ? "no reproduced finding and no unresolved high or critical one" : issues.sort().join("; "),
  });

  // 6. Kernel sign-off. Counted against the current rules: a signer removed by
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

  // 7. Soak: a defect that triggers on a timer, or one the first users hit,
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
