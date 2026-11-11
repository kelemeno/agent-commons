// Incentives: turns mechanical ledger events into settlement bodies. Pure and
// deterministic. Nothing here reads the clock; the coordinator appends what it
// returns. The rule table is docs/protocol.md §6; where this file departs from
// it, the comment on the function says so and why.
//
// Every settle* function is idempotent given the ledger. It never returns a
// body whose (owner, reason, ref) is already in state.settlements, and it never
// returns two bodies with the same key. Amounts for one key are summed before
// that. A ref names the event:
//   finding:<id>          bounty, falseFinding; and the author and approver
//                         slashes of a duplicate class, under its leader's id
//   merge:<sid>:<n>       mergeVest and proposerCut for tranche n
//   review:<sid>          cleanReview
//   plant:<sid>           missedPlant
//   claim:<taskId>:<seq>  claimExpired
//   honeytoken:<agent>:<tokenId>
// Every slash body also charges the slashed owner's inviter
// round(slash × inviterShare) as inviterSlash, under the ref
// `<slash ref>:<slash reason>:<slashed owner>`. Each invitee's charge thus has
// its own key, so slashes of one event that land in different calls never
// hide each other's inviter charge.
// Zero amounts are never returned. All amounts are integers, and no delta is -0.

import { blocksTarget, isConfirmedDefect, isReproducedOpen } from "./findingStatus";
import { memberTree } from "./members";
import { commitDeadlineMs, instantMs, plantCaughtBy, revealDeadlineMs, reviewWindowCloseSeq } from "./plants";
import { coveredSubmissionIds } from "./promotion";
import { isFalseFinding } from "./review";
import { claimStake } from "./rules";
import type {
  CommonsState,
  EntryBody,
  FindingState,
  KeyId,
  OwnerId,
  ReviewState,
  SettlementReason,
  Severity,
  SnapshotState,
  SubmissionState,
  TreeView,
} from "./types";

// The server loads its submit policy from this module, so claimStake is served
// here too. It is defined once, in rules.ts, beside the numbers it reads.
export { claimStake };

export type SettlementBody = Extract<EntryBody, { kind: "settlement" }>;
export type Stage = "dev" | "release" | "main";

// Severity is the finder's own claim; the harness checks only that the test
// fails on head and passes on the parent. Paying bounty[f.severity] would let
// the finder set the price the author and approvers pay, and filing one bug at
// four severities used to collect four bounties. Until a trusted entry confirms
// severity (protocol §6 gap), every finding settles at the lowest tier.
const SETTLED_SEVERITY: Severity = "low";
const DAY_MS = 24 * 3_600_000;

// ---------------------------------------------------------------------------
// Volume limits and shares
// ---------------------------------------------------------------------------

// Open-submission slots for an owner: 1 + floor(log2(1 + reputation)), log
// base 2, where reputation is the owner's commons reputation
// (OwnerState.reputationDelta). One slot at 0 reputation, two at 1, three at
// 3, four at 7, and so on: volume grows with standing, but slowly. Negative or
// non-finite reputation counts as 0, so a newcomer, or an owner slashed below
// zero, still has the base slot.
export function prSlots(reputation: number): number {
  const r = Number.isFinite(reputation) && reputation > 0 ? reputation : 0;
  return 1 + Math.floor(Math.log2(1 + r));
}

// Submit credits left for an owner. Each revealed review by any of the owner's
// agents earns 1 / reviewsPerSubmitCredit of a credit. On a merged submission
// only a reveal before the merge counts: one held back until the outcome is
// known did no review work anyone could use. Every owner starts with one free
// credit, so a newcomer can submit once before reviewing. Each submission by
// any of the owner's agents spends one. Attestations do not earn credits. The
// result can be negative if the ledger holds submissions the server would have
// refused. Callers allow a submission only at >= 1.
export function submitCredits(state: CommonsState, owner: OwnerId): number {
  let reviews = 0;
  let submissions = 0;
  for (const s of state.submissions.values()) {
    if (ownerOf(state, s.author) === owner) submissions += 1;
    for (const r of s.reviews) {
      if (revealedInTime(r, s.merged?.seq) && ownerOf(state, r.reviewer) === owner) reviews += 1;
    }
  }
  return Math.floor(reviews / state.rules.reviewsPerSubmitCredit) + 1 - submissions;
}

// How a bounty is split among n duplicate findings, in filing order. Weights
// decay^i are normalised to sum to 1. Duplicates share one bounty, so filing
// the same bug n times, from your own agents or from sybils, earns nothing
// extra. Filing first earns the largest share. decay 1 splits evenly.
export function duplicateShares(n: number, decay: number): number[] {
  if (!Number.isInteger(n) || n <= 0) return [];
  if (!(decay > 0 && decay <= 1)) throw new RangeError(`duplicateShares: decay must be in (0, 1], got ${decay}`);
  const weights = Array.from({ length: n }, (_, i) => Math.pow(decay, i));
  const total = weights.reduce((a, b) => a + b, 0);
  return weights.map((w) => w / total);
}

// `total` (a non-negative integer) split into integer parts proportional to
// `weights` that sum to exactly `total`: floors first, then the largest
// remainders get one more each, earlier index first on ties. Rounding each part
// on its own can pay out more than the total (two halves of 15 round to 8 + 8).
export function apportion(total: number, weights: number[]): number[] {
  const sum = weights.reduce((a, b) => a + b, 0);
  if (weights.length === 0 || !(sum > 0)) return weights.map(() => 0);
  const exact = weights.map((w) => (total * w) / sum);
  const parts = exact.map(Math.floor);
  let rest = total - parts.reduce((a, b) => a + b, 0);
  const order = exact.map((x, i) => ({ i, frac: x - Math.floor(x) })).sort((a, b) => b.frac - a.frac || a.i - b.i);
  for (const { i } of order) {
    if (rest <= 0) break;
    parts[i] = (parts[i] ?? 0) + 1;
    rest -= 1;
  }
  return parts;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// Settles a confirmed finding. Returns [] if it is not confirmed (a
// reproduction alone shows only that its test tells head from parent, which a
// test pinning the old behaviour does against any change: findingStatus.ts),
// if its class leader is not confirmed yet, if it is a duplicate filed after
// its class reproduced, or if it is superseded.
//
// Classes. Findings on the same target are one class, whatever severity they
// declare: severity is not checked (see SETTLED_SEVERITY), so it cannot tell
// two bugs apart. The leader is the finding whose reproduced result landed
// first, among those not dismissed; nothing in the class settles until the
// leader is confirmed, so the leader never changes after anyone was paid. The
// class's early findings are those filed before that result, minus
// those already resolved as not reproduced by then. They are treated as the
// same bug. All of this is fixed once the leader's result is on the ledger, so
// nothing waits on findings that may never get a result (§5.8).
// - The early findings share one bounty by filing rank (duplicateShares, then
//   apportion). Each share is final. A share is paid when its finding
//   reproduces, and never if it does not. Unpaid shares are not redistributed.
//   So a junk finding filed early dilutes the others but never earns, and a
//   friend's duplicate cannot shift money to the other finder.
// - A finding filed after the leader's result is not paid and slashes nobody.
//   By then the reproduction is public, and a copy cannot be told from a new
//   bug. A second, different bug on a target that already reproduced is
//   therefore not paid either. A submission in that state cannot merge.
// - The author and approver slashes belong to the class and are emitted with
//   the leader, as soon as it reproduces.
//
// Bounty. A share goes to its finder's owner, unless that owner is within
// rules.minTreeDistance of an author's owner.
//
// Slashes. The author pays max(round(bounty × stageMultiplier[stage]), bounty).
// The shares sum to at most the bounty, so that is never less than what was
// paid. The author pays even when no bounty is paid, so a friend "finding" the
// author's bug costs the pair money. Each approver pays
// round(bounty × stageMultiplier × (1 − p)), in proportion to the confidence
// they stated that the change was clean. Approvers are everyone who committed
// a review (an attestation, for a snapshot). Once the subject merged (was
// promoted), a review not revealed before that counts as p = 0. Otherwise a
// reviewer could hold back a confident "clean" until the outcome was known and
// reveal it only if it shipped clean. A subject with a confirmed defect never
// merges (is never promoted), and its review stakes are released, so there
// the same rule runs on a deadline: an unrevealed review counts as p = 0 once
// plants.revealDeadlineMs (commitHours after the commit phase) has passed by
// `nowIso`. Otherwise a reviewer could commit p = 0 everywhere and reveal only
// where no defect turned up. A review that could never be revealed (no
// assignment, so no commit phase) is left out.
//
// Snapshot targets name no culprit. The authors are the owners of every
// submission the snapshot covers (it and its unpromoted ancestors, as the
// ledger defines it), and the author slash is split equally per submission.
// The bounty pool is capped at the smallest author part. Otherwise a buggy
// author's distant friend could file against the snapshot, earn the full
// bounty, and leave the author paying 1/n of the slash. A finder who can name
// the culprit files against that submission and earns the full bounty; that
// finding is never superseded by a snapshot finding. A snapshot class settles
// nothing if overlapping work already holds the bug: a reproduced finding on a
// covered submission filed before this class's leader reproduced, or one on an
// overlapping snapshot filed before this class's first finding. A snapshot
// finding voids no merge tranche (see settleMerge).
//
// Plants. Once revealed, a plant settles only findings filed by the close of
// its review window (plants.ts). The custodian reveals after the window closes,
// so those were filed blind. They settle exactly as real work, custodian slash
// included, whether settled before or after the reveal. The custodian must pay:
// otherwise it could tell a friend where its plant is for a free bounty.
// Approvers are slashed as for real work and also pay settleMissedPlant. A
// finding filed after the close but before the reveal still settles as real
// work if settled before the reveal and as nothing after it. Removing that needs
// the reveal's seq on SubmissionState.planted. A custodian who reveals early
// leaks the same way, as in plants.ts.
// `nowIso` defaults to the time of the ledger's last entry.
export function settleFinding(
  state: CommonsState,
  findingId: string,
  stage: Stage,
  nowIso: string = (state as { headAt?: string }).headAt ?? "",
): SettlementBody[] {
  const f = state.findings.get(findingId);
  if (f === undefined || !isConfirmedDefect(f)) return [];
  const subject = findingSubject(state, f);
  if (subject === null || subject.authors.length === 0 || !(f.seq <= subject.maxSeq)) return [];
  const cls = findingClass(state, f, subject.maxSeq);
  if (cls === null || !isConfirmedDefect(cls.leader) || !cls.early.includes(f)) return [];
  if (subject.snapshot !== undefined && superseded(state, subject.snapshot, cls)) return [];

  const rules = state.rules;
  const bounty = rules.rewards.bounty[SETTLED_SEVERITY];
  const multiplier = rules.rewards.stageMultiplier[stage];
  const authorSlash = Math.max(Math.round(bounty * multiplier), bounty);
  const authorParts = apportion(authorSlash, subject.authors.map(() => 1));
  const pool = subject.snapshot === undefined ? bounty : Math.min(bounty, ...authorParts);
  const shares = apportion(pool, duplicateShares(cls.early.length, rules.rewards.duplicateDecay));

  const book = new Book(state);
  const finder = ownerOf(state, f.finder);
  if (finder !== undefined && farEnough(memberTree(state), finder, subject.authors, rules.minTreeDistance)) {
    book.credit(finder, "bounty", `finding:${f.id}`, shares[cls.early.indexOf(f)] ?? 0);
  }
  if (cls.leader === f) {
    const ref = `finding:${f.id}`;
    subject.authors.forEach((owner, i) => book.slash(owner, "authorSlash", ref, authorParts[i] ?? 0));
    // bm − bm·p, not bm·(1 − p): 1 − 0.9 is 0.0999…, which would round 1.5 down to 1.
    const bm = bounty * multiplier;
    const withheldCounts = subject.revealBy !== undefined && Date.parse(nowIso) >= subject.revealBy;
    for (const a of approvals(subject.reviews, subject.closeSeq, withheldCounts)) {
      const owner = ownerOf(state, a.reviewer);
      if (owner !== undefined) book.slash(owner, "approverSlash", ref, Math.round(bm - bm * clamp01(a.p)));
    }
  }
  return book.bodies();
}

// A finding the harness judged and did not reproduce, or a reproduction an
// operator dismissed as testing the intended change, costs its finder's owner
// falseFindingPenalty: a change-detector "finding" vetoes nothing for free. A
// result with harnessError (the harness could not run the test, e.g. timeouts
// past the retry limit) costs nothing: it proves nothing about the finding
// (findingStatus.isFalseFinding).
export function settleFalseFinding(state: CommonsState, findingId: string): SettlementBody[] {
  const f = state.findings.get(findingId);
  if (f === undefined || !isFalseFinding(f)) return [];
  const owner = ownerOf(state, f.finder);
  if (owner === undefined) return [];
  const book = new Book(state);
  book.slash(owner, "falseFinding", `finding:${f.id}`, state.rules.rewards.falseFindingPenalty);
  return book.bodies();
}

type Subject = {
  authors: OwnerId[]; // one entry per authored submission, so an owner can repeat
  reviews: ReviewState[];
  closeSeq: number | undefined; // merge or promotion; reveals after it count as p = 0
  revealBy: number | undefined; // ms; past it an unrevealed review counts as p = 0 (see settleFinding)
  maxSeq: number; // findings filed after this settle nothing (a revealed plant's window close)
  snapshot?: SnapshotState;
};

function findingSubject(state: CommonsState, f: FindingState): Subject | null {
  if ("submissionId" in f.target) {
    const s = state.submissions.get(f.target.submissionId);
    if (!s) return null;
    const owner = ownerOf(state, s.author);
    let maxSeq = Number.POSITIVE_INFINITY;
    if (s.planted) {
      // A reproduced finding closes the window, so this is never null here.
      const close = reviewWindowCloseSeq(state, s.id);
      if (close === null) return null;
      maxSeq = close;
    }
    return {
      authors: owner === undefined ? [] : [owner],
      reviews: s.reviews,
      closeSeq: s.merged?.seq,
      revealBy: s.assignment ? revealDeadlineMs(state.rules, s.assignment.at) : undefined,
      maxSeq,
    };
  }
  const snap = state.snapshots.get(f.target.snapshotId);
  if (!snap) return null;
  const authors: OwnerId[] = [];
  for (const sid of covered(state, snap)) {
    const owner = ownerOf(state, state.submissions.get(sid)?.author ?? "");
    if (owner !== undefined) authors.push(owner);
  }
  return {
    authors,
    reviews: snap.attestations,
    closeSeq: snap.promoted?.seq,
    revealBy: revealDeadlineMs(state.rules, snap.at),
    maxSeq: Number.POSITIVE_INFINITY,
    snapshot: snap,
  };
}

// The stated p of each approver. Unrevealed reviews of an open subject are
// left out until they are revealed, the subject closes, or (withheldCounts)
// the reveal deadline of a subject that can never close has passed.
function approvals(reviews: ReviewState[], closeSeq: number | undefined, withheldCounts = false): { reviewer: KeyId; p: number }[] {
  const out: { reviewer: KeyId; p: number }[] = [];
  for (const r of reviews) {
    if (r.verdict !== undefined && revealedInTime(r, closeSeq)) out.push({ reviewer: r.reviewer, p: r.verdict.defectProbability });
    else if (closeSeq !== undefined || withheldCounts) out.push({ reviewer: r.reviewer, p: 0 });
  }
  return out;
}

// Revealed, and before closeSeq if the subject has closed.
function revealedInTime(r: ReviewState, closeSeq: number | undefined): boolean {
  if (r.verdict === undefined) return false;
  return closeSeq === undefined || (r.revealedSeq !== undefined && r.revealedSeq < closeSeq);
}

type FindingClass = { key: string; leader: FindingState; early: FindingState[] };

// f's class among findings filed by maxSeq: see settleFinding.
function findingClass(state: CommonsState, f: FindingState, maxSeq: number): FindingClass | null {
  const key = targetKey(f);
  const same = [...state.findings.values()].filter((g) => targetKey(g) === key && g.seq <= maxSeq);
  let leader: FindingState | null = null;
  let firstResult = Number.POSITIVE_INFINITY;
  for (const g of same) {
    if (g.result && isReproducedOpen(g) && g.result.seq < firstResult) {
      leader = g;
      firstResult = g.result.seq;
    }
  }
  if (leader === null) return null;
  const knownFalse = (g: FindingState) => g.result !== undefined && !g.result.reproduced && g.result.seq < firstResult;
  const early = same.filter((g) => g.seq < firstResult && !knownFalse(g)).sort((a, b) => a.seq - b.seq);
  return { key, leader, early };
}

// True if overlapping work already holds the bug of this snapshot class (see
// settleFinding). The two tests differ on purpose. A submission finding names
// the culprit, so it wins whenever it was filed before this class's
// reproduction was public. Between two snapshots, the earlier filing wins, so
// two concurrent classes do not block each other. Classes settled before the
// overlapping finding reproduced stay settled; that double payment is bounded
// by the snapshot bounty cap.
function superseded(state: CommonsState, snap: SnapshotState, cls: FindingClass): boolean {
  const mine = new Set(covered(state, snap));
  const firstFiled = cls.early[0]?.seq ?? cls.leader.seq;
  const leaderResult = cls.leader.result?.seq ?? Number.POSITIVE_INFINITY;
  for (const g of state.findings.values()) {
    if (!isConfirmedDefect(g) || targetKey(g) === cls.key) continue;
    if ("submissionId" in g.target) {
      if (mine.has(g.target.submissionId) && g.seq < leaderResult) return true;
    } else {
      const other = state.snapshots.get(g.target.snapshotId);
      if (other && g.seq < firstFiled && covered(state, other).some((sid) => mine.has(sid))) return true;
    }
  }
  return false;
}

function targetKey(f: FindingState): string {
  return "submissionId" in f.target ? `submission:${f.target.submissionId}` : `snapshot:${f.target.snapshotId}`;
}

// The finder must be farther than minTreeDistance from every author's owner
// in the member tree. Every owner is a member; the tree throws on anything
// else (only a corrupt, hand-built state), so no settlement guesses a distance.
function farEnough(tree: TreeView, finder: OwnerId, authors: OwnerId[], minDistance: number): boolean {
  return authors.every((a) => tree.distance(finder, a) > minDistance);
}

// ---------------------------------------------------------------------------
// Merges and clean reviews
// ---------------------------------------------------------------------------

// One tranche of the author's merge reward, round(merge / 3), for work someone
// asked for: a submission for a task. A taskless merge earns nothing. Tasks
// come from evidenced proposals the operator approved; anything else would
// mint reputation from activity (whitespace and comment edits nobody can
// block), not from work.
// - Tranche 1 vests at merge.
// - Tranche 2 vests when a promotion ships the submission.
// - Tranche 3 vests tailDays after that promotion, judged at nowIso.
// If the condition does not hold yet, the result is []. The proposer's owner
// takes round(tranche × proposerCutFraction) out of each tranche. The proposer
// is the owner of the key that signed the task's proposal, whether an owner key
// or an agent key. There is no cut when the author's owner is the proposer.
//
// A revealed plant vests nothing, even if it merged before its reveal. A paid
// tranche cannot be clawed back here.
//
// Forfeiture. A reproduced finding that targets the submission directly voids
// its unpaid tranches 2 and 3 (while undecided they wait; a dismissal releases
// them). A finding with no result yet makes them wait too: undecided is not
// clean, and which way a finding filed at the end of the tail goes must not
// depend on how fast the harness runs (the 72 h result deadline bounds the
// wait). Tranche 1 is never clawed back.
//
// One task pays once: only the first submission merged for it vests (the
// ledger refuses a second, so this only guards hand-built states). A finding on a
// snapshot names no culprit, so it voids no tranche: voiding every covered
// author's vest would make honest co-authors pay for one author's bug. A
// finder who can name the culprit targets the submission, which voids it, and
// earns more (see settleFinding).
//
// nowIso is read only for tranche 3, where a missing or invalid one throws
// RangeError. A silent fallback would only delay a payment the caller decided
// was due.
export function settleMerge(
  state: CommonsState,
  submissionId: string,
  tranche: 1 | 2 | 3,
  nowIso: string,
): SettlementBody[] {
  if (tranche !== 1 && tranche !== 2 && tranche !== 3) throw new RangeError(`settleMerge: tranche must be 1, 2 or 3`);
  const s = state.submissions.get(submissionId);
  if (!s?.merged || s.planted || s.taskId === null) return [];
  for (const x of state.submissions.values()) {
    if (x.taskId === s.taskId && x.merged && x.merged.seq < s.merged.seq) return [];
  }
  if (tranche >= 2) {
    const promo = promotionShipping(state, s.id);
    if (promo === null) return [];
    if (tranche === 3 && nowMs(nowIso) < Date.parse(promo.at) + state.rules.vesting.tailDays * DAY_MS) return [];
    if (hasBlockingFinding(state, s)) return [];
  }
  const author = ownerOf(state, s.author);
  if (author === undefined) return [];
  const amount = Math.round(state.rules.rewards.merge / 3);
  const proposer = proposerOf(state, s);
  const cut = proposer !== undefined && proposer !== author ? Math.round(amount * state.rules.rewards.proposerCutFraction) : 0;
  const ref = `merge:${s.id}:${tranche}`;
  const book = new Book(state);
  book.credit(author, "mergeVest", ref, amount - cut);
  if (proposer !== undefined) book.credit(proposer, "proposerCut", ref, cut);
  return book.bodies();
}

// Clean-review rewards for the submissions a promotion shipped, once tailDays
// have passed at nowIso (which must be a valid instant, or RangeError). For a
// promoted snapshot this covers the snapshot and its unpromoted ancestors. For
// an unpromoted snapshot that a later promotion shipped, its own submissions.
// Overlapping calls produce the same bodies, and those are recorded once.
//
// A submission is clean if no reproduced finding targets it or a snapshot that
// covers it, of any declared severity, and none of those is still without a
// result (it waits; see settleMerge). review.ts's submissionOutcome ignores
// low-severity findings, but severity is the finder's claim, and it must not be
// able to pay reviewers for code with a confirmed bug. An escape always rests
// on a reproduced finding, so it is covered too.
//
// Each review revealed before the merge earns round(cleanReview × (1 − p²)).
// That is the clean side of the Brier score (protocol §6.2 departs here: a flat
// reward made p = 1 on everything collect every reward and risk nothing). A
// reveal after the merge earns nothing: it could have waited to see the outcome.
//
// Only work someone asked for pays, as with settleMerge: a taskless merge
// earns its reviewers nothing, or a ring of owners could submit whitespace
// edits, open-review each other's at p = 0 and mint reputation without limit.
// And only reviewers whose owner is farther than minTreeDistance from the
// author's owner in the member tree earn it, as with the bounty (farEnough): a friend
// who could never be drawn for the seat must not be paid for approving.
export function settleCleanReviews(state: CommonsState, snapshotId: string, nowIso: string): SettlementBody[] {
  const now = nowMs(nowIso);
  const snap = state.snapshots.get(snapshotId);
  if (!snap) return [];
  const promo = snap.promoted ?? promotionShipping(state, snap.submissionIds[0] ?? "");
  if (!promo) return [];
  if (now < Date.parse(promo.at) + state.rules.vesting.tailDays * DAY_MS) return [];
  const c = state.rules.rewards.cleanReview;
  const tree = memberTree(state);
  const book = new Book(state);
  for (const sid of snap.promoted ? covered(state, snap) : snap.submissionIds) {
    const s = state.submissions.get(sid);
    if (!s?.merged || s.planted || s.taskId === null || hasBlockingFinding(state, s) || snapshotFindingCovers(state, s.id)) continue;
    const author = ownerOf(state, s.author);
    for (const r of s.reviews) {
      const owner = ownerOf(state, r.reviewer);
      if (r.verdict === undefined || owner === undefined || author === undefined || !revealedInTime(r, s.merged.seq)) continue;
      if (!farEnough(tree, owner, [author], state.rules.minTreeDistance)) continue;
      const p = clamp01(r.verdict.defectProbability);
      book.credit(owner, "cleanReview", `review:${s.id}`, Math.round(c - c * p * p));
    }
  }
  return book.bodies();
}

// ---------------------------------------------------------------------------
// Penalties
// ---------------------------------------------------------------------------

// Each owner who saw a revealed plant and did not catch it pays
// missedPlantPenalty. An owner saw the plant if one of its agents held an
// assigned seat or committed a review on it. That covers a reviewer who never
// revealed, and a seat that never committed while it could. A seat whose
// commit phase someone else cut short (a reproduction landed before the commit
// deadline, which closes commits until it is dismissed, and was not dismissed
// before that deadline) and that had not committed was shut out, not
// negligent, and is not charged. The plant's author's owner (the custodian)
// is never charged.
//
// A catch is plants.ts's plantCaughtBy: by the close of the review window, the
// agent revealed p >= 0.5 or filed a finding later confirmed. A finding or a
// reveal after the close never counts. The plant's description is public by
// then. An owner whose only possible catch is a finding filed by the close with
// no result or no decision yet waits. That finding was filed blind, so charging now could not
// be undone if it reproduces. A finding filed after the close never defers the
// charge.
//
// A plant revealed while its window was still open broke custodian policy:
// the reveal itself closed the window (plants.reviewWindowCloseSeq), and
// nobody's miss can be ordered against it, so nobody is charged.
export function settleMissedPlant(state: CommonsState, submissionId: string): SettlementBody[] {
  const s = state.submissions.get(submissionId);
  if (!s?.planted) return [];
  const close = reviewWindowCloseSeq(state, s.id);
  if (close === null || close === s.planted.seq) return [];
  const custodian = ownerOf(state, s.author);
  const saw = new Set<OwnerId>();
  const caught = new Set<OwnerId>();
  const waiting = new Set<OwnerId>();
  const deadline = commitDeadlineMs(state.rules, s.assignment?.at);
  const before = (iso: string | undefined) => iso !== undefined && Date.parse(iso) < deadline;
  const shut = s.findingIds.some((fid) => {
    const f = state.findings.get(fid);
    if (!f?.result?.reproduced || !before(f.result.at)) return false;
    return !(f.decision?.confirmed === false && before(f.decision.at));
  });
  for (const k of s.assignment?.reviewers ?? []) {
    const o = ownerOf(state, k);
    if (o !== undefined && (!shut || s.reviews.some((r) => r.reviewer === k))) saw.add(o);
  }
  for (const r of s.reviews) {
    const o = ownerOf(state, r.reviewer);
    if (o === undefined) continue;
    saw.add(o);
    if (plantCaughtBy(state, s.id, r.reviewer)) caught.add(o);
  }
  for (const fid of s.findingIds) {
    const f = state.findings.get(fid);
    const o = f && ownerOf(state, f.finder);
    if (!f || o === undefined) continue;
    if (plantCaughtBy(state, s.id, f.finder)) caught.add(o);
    else if ((f.result === undefined || (f.result.reproduced && f.decision === undefined)) && f.seq <= close) waiting.add(o);
  }
  const book = new Book(state);
  for (const o of saw) {
    if (o === custodian || caught.has(o) || waiting.has(o)) continue;
    book.slash(o, "missedPlant", `plant:${s.id}`, state.rules.rewards.missedPlantPenalty);
  }
  return book.bodies();
}

// A claim that has expired (until < now) loses its stake unless it was
// delivered: its agent submitted for the task during the holder's unbroken
// run of claims (from the first claim of the run, extensions made while live
// included) and by this claim's `until`, or the task merged by then. A claim
// its own holder extended while it was live did not expire: the extension
// carries its stake on, and so its delivery too. Otherwise a worker that
// submitted and then extended to keep the task through review would lose the
// stake a worker that did not extend keeps. A submission from an earlier,
// lapsed run does not count, and the ledger lets a run go past 7 days only
// with a fresh submission per extension, so one junk submission cannot keep
// a task claimed for long.
//
// Every claim entry is judged (state.claimHistory), not only the latest, so
// re-claiming a lapsed claim a minute after its `until`, by its holder or a
// colluder, no longer erases its slash.
//
// A run passes to another agent of the same owner when the holder was revoked
// before that agent claimed (key rotation: the ledger lets anyone re-claim a
// revoked agent's live claim). The new agent carries the run on, so its
// delivery counts for the old claim, as an extension's would. An owner who
// revokes and does not re-claim abandoned the task, and pays as before.
export function settleExpiredClaims(state: CommonsState, nowIso: string): SettlementBody[] {
  const now = nowMs(nowIso);
  const book = new Book(state);
  const history = state.claimHistory ?? [...state.claims.values()];
  const revokedBefore = (agent: KeyId, seq: number): boolean => {
    const a = state.agents.get(agent);
    return a !== undefined && (a.revokedSeq !== undefined ? a.revokedSeq < seq : !a.active);
  };
  // Whether claim `c` continues the run of `prev`: the same holder, or the
  // same owner's next agent after the holder was revoked; made while live.
  const continues = (prev: (typeof history)[number], c: (typeof history)[number]): boolean =>
    "at" in c &&
    Date.parse(c.at) <= Date.parse(prev.until) &&
    (prev.agent === c.agent || (ownerOf(state, prev.agent) === ownerOf(state, c.agent) && revokedBefore(prev.agent, c.seq)));
  // The seq of the first claim of each entry's unbroken run, and its holders.
  const runStart: number[] = [];
  const runAgents: Set<KeyId>[] = [];
  const last = new Map<string, number>(); // task -> index of its latest entry so far
  for (const [i, c] of history.entries()) {
    const p = last.get(c.taskId);
    const prev = p === undefined ? undefined : history[p];
    const extendsRun = prev !== undefined && p !== undefined && continues(prev, c);
    runStart[i] = extendsRun ? (runStart[p] as number) : c.seq;
    runAgents[i] = extendsRun ? new Set([...(runAgents[p] as Set<KeyId>), c.agent]) : new Set([c.agent]);
    last.set(c.taskId, i);
  }
  for (const [i, c] of history.entries()) {
    const until = Date.parse(c.until);
    if (!(until < now)) continue;
    const next = history.slice(i + 1).find((x) => x.taskId === c.taskId);
    if (next && continues(c, next)) continue;
    let delivered = false;
    for (const s of state.submissions.values()) {
      if (s.taskId !== c.taskId) continue;
      if (s.merged && Date.parse(s.merged.at) <= until) delivered = true;
      if (runAgents[i]?.has(s.author) && s.submittedSeq > (runStart[i] as number) && Date.parse(s.submittedAt) <= until) delivered = true;
    }
    const owner = ownerOf(state, c.agent);
    if (!delivered && owner !== undefined) book.slash(owner, "claimExpired", `claim:${c.taskId}:${c.seq}`, c.stake);
  }
  return book.bodies();
}

// honeytokenPenalty for each distinct token that the agent triggered, charged to its owner.
export function settleHoneytoken(state: CommonsState, agent: KeyId): SettlementBody[] {
  const owner = ownerOf(state, agent);
  if (owner === undefined) return [];
  const book = new Book(state);
  const tokens = new Set(state.honeytokens.filter((h) => h.agent === agent).map((h) => h.tokenId));
  for (const t of tokens) book.slash(owner, "honeytoken", `honeytoken:${agent}:${t}`, state.rules.rewards.honeytokenPenalty);
  return book.bodies();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const keyOf = (owner: OwnerId, reason: SettlementReason, ref: string) => `${owner}\u0000${reason}\u0000${ref}`;

// Sums amounts per (owner, reason, ref), adds the inviter charge of each summed
// slash, and drops keys already settled.
class Book {
  private readonly sums = new Map<string, SettlementBody>();
  private readonly slashes = new Set<string>();
  constructor(private readonly state: CommonsState) {}

  credit(owner: OwnerId, reason: SettlementReason, ref: string, amount: number): void {
    const key = keyOf(owner, reason, ref);
    const b = this.sums.get(key);
    if (b) b.delta += amount;
    else this.sums.set(key, { kind: "settlement", owner, delta: amount, reason, ref });
  }

  // A slash of `amount` (>= 0) on owner. Its inviter's share is added in bodies().
  slash(owner: OwnerId, reason: SettlementReason, ref: string, amount: number): void {
    if (!(amount > 0)) return;
    this.credit(owner, reason, ref, -amount);
    this.slashes.add(keyOf(owner, reason, ref));
  }

  bodies(): SettlementBody[] {
    const all = [...this.sums.values()];
    for (const key of this.slashes) {
      const b = this.sums.get(key);
      if (!b) continue;
      const inviter = this.state.owners.get(b.owner)?.inviter ?? null;
      if (inviter === null) continue;
      const charge = Math.round(-b.delta * this.state.rules.rewards.inviterShare);
      all.push({ kind: "settlement", owner: inviter, delta: -charge, reason: "inviterSlash", ref: `${b.ref}:${b.reason}:${b.owner}` });
    }
    const done = new Set(this.state.settlements.map((s) => keyOf(s.owner, s.reason, s.ref)));
    // `+ 0` turns -0 into 0. Zero bodies are dropped anyway, but a negated
    // zero charge is -0.
    return all.filter((b) => b.delta !== 0 && !done.has(keyOf(b.owner, b.reason, b.ref))).map((b) => ({ ...b, delta: b.delta + 0 }));
  }
}

function ownerOf(state: CommonsState, agent: KeyId): OwnerId | undefined {
  return state.agents.get(agent)?.owner;
}

// The proposer's owner. The proposal may be signed by an owner key or by an agent key.
function proposerOf(state: CommonsState, s: SubmissionState): OwnerId | undefined {
  if (s.taskId === null) return undefined;
  const task = state.tasks.get(s.taskId);
  const by = task && state.proposals.get(task.proposalId)?.by;
  if (by === undefined) return undefined;
  return state.ownerByKey.get(by) ?? ownerOf(state, by);
}

// A reproduction nobody dismissed: payments that a defect would void wait on it.
// A finding on the submission still without a result, or reproduced and not
// dismissed (findingStatus.blocksTarget).
function hasBlockingFinding(state: CommonsState, s: SubmissionState): boolean {
  return s.findingIds.some((fid) => {
    const f = state.findings.get(fid);
    return f !== undefined && blocksTarget(f);
  });
}

// A finding on a snapshot that covers the submission blocks it the same way.
function snapshotFindingCovers(state: CommonsState, submissionId: string): boolean {
  for (const f of state.findings.values()) {
    if (!("snapshotId" in f.target) || !blocksTarget(f)) continue;
    const snap = state.snapshots.get(f.target.snapshotId);
    if (snap && covered(state, snap).includes(submissionId)) return true;
  }
  return false;
}

// What a promotion of `snap` ships and what a finding on it covers: the
// submissions of the snapshot and its unpromoted ancestors (promotion.ts holds
// the definition).
function covered(state: CommonsState, snap: SnapshotState): string[] {
  return coveredSubmissionIds(state, snap.id);
}

// The earliest promotion that shipped the submission, or null.
function promotionShipping(state: CommonsState, submissionId: string): { seq: number; at: string } | null {
  let best: { seq: number; at: string } | null = null;
  for (const snap of state.snapshots.values()) {
    if (!snap.promoted || (best !== null && snap.promoted.seq >= best.seq)) continue;
    if (covered(state, snap).includes(submissionId)) best = snap.promoted;
  }
  return best;
}

// An ISO instant with an explicit zone (plants.ts), else RangeError.
function nowMs(nowIso: string): number {
  const ms = typeof nowIso === "string" ? instantMs(nowIso) : Number.NaN;
  if (Number.isNaN(ms)) throw new RangeError(`invalid nowIso (need an ISO date-time with Z or ±HH:MM): ${String(nowIso)}`);
  return ms;
}

// The ledger only accepts p in [0, 1]. Anything else counts as p = 0, the
// most confident "clean", so a malformed verdict never escapes a slash.
function clamp01(p: number): number {
  return Number.isFinite(p) ? Math.min(1, Math.max(0, p)) : 0;
}
