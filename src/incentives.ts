// Incentives: turns mechanical ledger events into settlement bodies. Pure and
// deterministic. Nothing here reads the clock; the coordinator appends what it
// returns. The rule table is docs/protocol.md §6.
//
// Every settle* function is idempotent given the ledger. It never returns a
// body whose (owner, reason, ref) is already in state.settlements, and it never
// returns two bodies with the same key. Amounts for one key are summed before
// that. A ref names the event:
//   finding:<id>          bounty, falseFinding, and the author, approver and inviter
//                         slashes of a duplicate group (keyed by the group's first finding)
//   merge:<sid>:<n>       mergeVest and proposerCut for tranche n
//   review:<sid>          cleanReview
//   plant:<sid>           missedPlant
//   claim:<taskId>:<seq>  claimExpired
//   honeytoken:<agent>:<tokenId>
// Zero amounts are never returned. All amounts are integers, and no delta is -0.
//
// Every slash also charges the slashed owner's inviter round(slash × inviterShare)
// as inviterSlash, under the same ref. When one inviter is charged for several
// invitees in the same event, the charges are summed into one body.

import { claimStake } from "./rules";
import type {
  CommonsState,
  EntryBody,
  FindingState,
  KeyId,
  OwnerId,
  SettlementReason,
  SnapshotState,
  SubmissionState,
  TreeView,
} from "./types";

// The server loads its submit policy from this module, so claimStake is served
// here too. It is defined once, in rules.ts, beside the numbers it reads.
export { claimStake };

export type SettlementBody = Extract<EntryBody, { kind: "settlement" }>;
export type Stage = "dev" | "release" | "main";

// A revealed review at or above this probability flags the change (protocol §5.7).
const FLAG_THRESHOLD = 0.5;
const DAY_MS = 24 * 3_600_000;

// ---------------------------------------------------------------------------
// Volume limits and shares
// ---------------------------------------------------------------------------

// Open-submission slots for an owner: 1 + floor(log2(1 + reputation)), log
// base 2. One slot at 0 reputation, two at 1, three at 3, four at 7, and so on:
// volume grows with standing, but slowly. Negative or non-finite reputation
// counts as 0.
export function prSlots(reputation: number): number {
  const r = Number.isFinite(reputation) && reputation > 0 ? reputation : 0;
  return 1 + Math.floor(Math.log2(1 + r));
}

// Submit credits left for an owner. Each revealed review by any of the owner's
// agents earns 1 / reviewsPerSubmitCredit of a credit. Every owner starts with
// one free credit, so a newcomer can submit once before reviewing. Each
// submission by any of the owner's agents spends one. Attestations do not earn
// credits. The result can be negative if the ledger holds submissions the
// server would have refused. Callers allow a submission only at >= 1.
export function submitCredits(state: CommonsState, owner: OwnerId): number {
  let reviews = 0;
  let submissions = 0;
  for (const s of state.submissions.values()) {
    if (ownerOf(state, s.author) === owner) submissions += 1;
    for (const r of s.reviews) if (r.verdict !== undefined && ownerOf(state, r.reviewer) === owner) reviews += 1;
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

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

// Settles a reproduced finding. Returns [] if the finding has no reproduced
// result, or if it must wait (see duplicate groups below).
//
// Duplicate groups. Reproduced findings with the same target and severity
// that were filed before the first reproduced result in that class are one
// group. They are treated as the same bug. The group shares one bounty
// (duplicateShares, in filing order), and the author and approvers are slashed
// once for it. Those slashes are emitted with the group's first finding, under
// its ref. While any finding of that class filed before the first result still
// has no result, the group may still grow, so nothing is settled yet. A finding
// filed after the first result is not paid and slashes nobody. By then the
// reproduction is public, and a copy of it cannot be told apart from a new bug.
//
// Bounty. Each member's share of bounty[severity] goes to its finder's owner.
// The share is 0 if that owner is within rules.minTreeDistance of an author's
// owner, or is not in the tree, because the distance of an outsider is not
// known. A zero share is not redistributed. Otherwise a friend could file a
// duplicate to shift money to the other finder.
//
// Slashes. The author pays max(round(bounty × stageMultiplier[stage]), bounty,
// bounties paid). The author pays even when no bounty is paid, so a friend
// "finding" a planted bug costs the pair money. For a snapshot target, the
// authors are the owners of every submission that the snapshot covers (it and
// its unpromoted ancestors, as the ledger defines it). The slash is split
// equally per submission, and the remainder goes to the first submissions in
// order. Approvers are the revealed reviewers of the submission, or the
// revealed attesters of the snapshot. Each pays
// round(bounty × stageMultiplier × (1 − p)), in proportion to the confidence
// they stated that the change was clean.
//
// Revealed plants. Once a plant is revealed, a finding on it settles nothing.
// The custodian planted the bug on purpose, so the custodian is not slashed.
// Reviewers who missed it pay through settleMissedPlant. A finding filed after
// the reveal must not pay. SubmissionState does not record when the plant was
// revealed, so no finding can be ordered against the reveal, and none is paid.
// A finding settled before the reveal looks like real work and is settled as
// real work.
export function settleFinding(state: CommonsState, tree: TreeView, findingId: string, stage: Stage): SettlementBody[] {
  const f = state.findings.get(findingId);
  if (!f?.result?.reproduced) return [];
  const subject = findingSubject(state, f);
  if (subject === null || subject.planted) return [];
  const group = duplicateGroup(state, f);
  if (group === "pending" || group.length === 0 || !group.includes(f)) return [];

  const rules = state.rules;
  const bounty = rules.rewards.bounty[f.severity];
  const multiplier = rules.rewards.stageMultiplier[stage];
  const shares = duplicateShares(group.length, rules.rewards.duplicateDecay);
  const authorOwners = subject.authors
    .map((sid) => ownerOf(state, state.submissions.get(sid)?.author ?? ""))
    .filter((o): o is OwnerId => o !== undefined);
  const paid = group.map((g, i) => {
    const finder = ownerOf(state, g.finder);
    if (finder === undefined || !farEnough(tree, finder, authorOwners, rules.minTreeDistance)) return 0;
    return Math.round(bounty * (shares[i] ?? 0));
  });

  const book = new Book(state);
  const finder = ownerOf(state, f.finder);
  const index = group.indexOf(f);
  if (finder !== undefined) book.credit(finder, "bounty", `finding:${f.id}`, paid[index] ?? 0);

  // The slashes belong to the group, so only its first finding emits them.
  const leader = group[0];
  if (leader === f) {
    const ref = `finding:${leader.id}`;
    const paidTotal = paid.reduce((a, b) => a + b, 0);
    const authorSlash = Math.max(Math.round(bounty * multiplier), bounty, paidTotal);
    const parts = splitInteger(authorSlash, subject.authors.length);
    subject.authors.forEach((sid, i) => {
      const owner = ownerOf(state, state.submissions.get(sid)?.author ?? "");
      if (owner !== undefined) book.slash(owner, "authorSlash", ref, parts[i] ?? 0);
    });
    for (const a of subject.approvals) {
      const owner = ownerOf(state, a.reviewer);
      const p = clamp01(a.p);
      // bm − bm·p, not bm·(1 − p): 1 − 0.9 is 0.0999…, which would round 1.5 down to 1.
      const bm = bounty * multiplier;
      if (owner !== undefined) book.slash(owner, "approverSlash", ref, Math.round(bm - bm * p));
    }
  }
  return book.bodies();
}

// A finding with a result that did not reproduce costs its finder's owner
// falseFindingPenalty. The harness counts a timeout or a harness error as not
// reproduced.
export function settleFalseFinding(state: CommonsState, findingId: string): SettlementBody[] {
  const f = state.findings.get(findingId);
  if (f?.result === undefined || f.result.reproduced) return [];
  const owner = ownerOf(state, f.finder);
  if (owner === undefined) return [];
  const book = new Book(state);
  book.slash(owner, "falseFinding", `finding:${f.id}`, state.rules.rewards.falseFindingPenalty);
  return book.bodies();
}

type Subject = {
  authors: string[]; // submission ids whose authors' owners are "the author"
  approvals: { reviewer: KeyId; p: number }[];
  planted: boolean;
};

function findingSubject(state: CommonsState, f: FindingState): Subject | null {
  if ("submissionId" in f.target) {
    const s = state.submissions.get(f.target.submissionId);
    if (!s) return null;
    return { authors: [s.id], approvals: revealed(s.reviews), planted: s.planted !== undefined };
  }
  const snap = state.snapshots.get(f.target.snapshotId);
  if (!snap) return null;
  return { authors: covered(state, snap), approvals: revealed(snap.attestations), planted: false };
}

function revealed(reviews: SubmissionState["reviews"]): { reviewer: KeyId; p: number }[] {
  const out: { reviewer: KeyId; p: number }[] = [];
  for (const r of reviews) if (r.verdict !== undefined) out.push({ reviewer: r.reviewer, p: r.verdict.defectProbability });
  return out;
}

// The members of f's duplicate group, in filing order, or "pending" while a
// finding of the same class filed before the first reproduced result has no
// result. f itself is a member only if it was filed before that result.
function duplicateGroup(state: CommonsState, f: FindingState): FindingState[] | "pending" {
  const key = targetKey(f);
  const same = [...state.findings.values()].filter((g) => g.severity === f.severity && targetKey(g) === key);
  let firstResult = Number.POSITIVE_INFINITY;
  for (const g of same) if (g.result?.reproduced) firstResult = Math.min(firstResult, g.result.seq);
  const early = same.filter((g) => g.seq < firstResult);
  if (early.some((g) => g.result === undefined)) return "pending";
  return early.filter((g) => g.result?.reproduced === true).sort((a, b) => a.seq - b.seq);
}

function targetKey(f: FindingState): string {
  return "submissionId" in f.target ? `submission:${f.target.submissionId}` : `snapshot:${f.target.snapshotId}`;
}

// The finder must be farther than minTreeDistance from every author's owner.
// The tree throws on non-members. An owner with no known place in the tree
// cannot show distance, so it earns nothing.
function farEnough(tree: TreeView, finder: OwnerId, authors: OwnerId[], minDistance: number): boolean {
  if (!tree.has(finder)) return false;
  for (const a of authors) {
    if (!tree.has(a) || tree.distance(finder, a) <= minDistance) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Merges and clean reviews
// ---------------------------------------------------------------------------

// One tranche of the author's merge reward, round(merge / 3).
// - Tranche 1 vests at merge.
// - Tranche 2 vests when a promotion ships the submission.
// - Tranche 3 vests tailDays after that promotion.
// If the condition does not hold yet, the result is []. The proposer's owner
// takes round(tranche × proposerCutFraction) out of each tranche. The proposer
// is the owner of the key that signed the task's proposal, whether an owner key
// or an agent key. There is no cut when the author's owner is the proposer.
//
// Forfeiture. A reproduced finding that targets the submission directly voids
// its unpaid tranches 2 and 3. Tranche 1 is never clawed back. A finding on a
// snapshot cannot be pinned on one submission, so it voids no tranche. It is
// settled through the split author slash instead.
//
// nowIso decides tranche 3. Without it, the time of the latest ledger entry is
// used (LedgerState.headAt), or the epoch if the state carries none. Omitting
// it can only delay a tranche, never pay one early.
export function settleMerge(
  state: CommonsState,
  submissionId: string,
  tranche: 1 | 2 | 3,
  nowIso?: string,
): SettlementBody[] {
  if (tranche !== 1 && tranche !== 2 && tranche !== 3) throw new RangeError(`settleMerge: tranche must be 1, 2 or 3`);
  const s = state.submissions.get(submissionId);
  if (!s?.merged) return [];
  if (tranche >= 2) {
    const promo = promotionShipping(state, s.id);
    if (promo === null) return [];
    if (tranche === 3 && nowMs(state, nowIso) < Date.parse(promo.at) + state.rules.vesting.tailDays * DAY_MS) return [];
    if (hasReproducedFinding(state, s)) return [];
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

// cleanReview for every revealed review, of any p, on a submission that a
// promotion shipped, once tailDays have passed with no reproduced finding
// targeting it. For a promoted snapshot this covers every submission the
// promotion shipped: the snapshot and its unpromoted ancestors. For an
// unpromoted snapshot that a later promotion shipped, it covers the
// snapshot's own submissions. Overlapping calls produce the same bodies, and
// those are recorded once. nowIso falls back as in settleMerge.
//
// Known gap (protocol §6.2). The reward does not depend on p, and the approver
// slash is 0 at p = 1. So "flag everything" collects every clean-review reward
// and pays nothing.
export function settleCleanReviews(state: CommonsState, snapshotId: string, nowIso?: string): SettlementBody[] {
  const snap = state.snapshots.get(snapshotId);
  if (!snap) return [];
  const promo = snap.promoted ?? promotionShipping(state, snap.submissionIds[0] ?? "");
  if (!promo) return [];
  if (nowMs(state, nowIso) < Date.parse(promo.at) + state.rules.vesting.tailDays * DAY_MS) return [];
  const book = new Book(state);
  for (const sid of snap.promoted ? covered(state, snap) : snap.submissionIds) {
    const s = state.submissions.get(sid);
    if (!s?.merged || s.planted || hasReproducedFinding(state, s)) continue;
    for (const r of s.reviews) {
      const owner = ownerOf(state, r.reviewer);
      if (r.verdict !== undefined && owner !== undefined) {
        book.credit(owner, "cleanReview", `review:${s.id}`, state.rules.rewards.cleanReview);
      }
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
// revealed, and a seat that never committed. An owner caught the plant if one
// of its agents revealed p >= 0.5 or filed a finding on it that reproduced. An
// owner with a finding on the plant that has no result yet waits. The plant's
// author's owner (the custodian) is never charged.
//
// This counts any reveal, whenever it happened. plants.ts holds the stricter,
// window-bounded definition of a catch that recall uses. Reveals are bound to
// earlier commitments, so a late reveal cannot change the verdict. It can only
// be withheld until the plant is known.
export function settleMissedPlant(state: CommonsState, submissionId: string): SettlementBody[] {
  const s = state.submissions.get(submissionId);
  if (!s?.planted) return [];
  const custodian = ownerOf(state, s.author);
  const saw = new Set<OwnerId>();
  const caught = new Set<OwnerId>();
  const waiting = new Set<OwnerId>();
  for (const k of s.assignment?.reviewers ?? []) {
    const o = ownerOf(state, k);
    if (o !== undefined) saw.add(o);
  }
  for (const r of s.reviews) {
    const o = ownerOf(state, r.reviewer);
    if (o === undefined) continue;
    saw.add(o);
    if (r.verdict !== undefined && r.verdict.defectProbability >= FLAG_THRESHOLD) caught.add(o);
  }
  for (const fid of s.findingIds) {
    const f = state.findings.get(fid);
    const o = f && ownerOf(state, f.finder);
    if (!f || o === undefined) continue;
    if (f.result === undefined) waiting.add(o);
    else if (f.result.reproduced) caught.add(o);
  }
  const book = new Book(state);
  for (const o of saw) {
    if (o === custodian || caught.has(o) || waiting.has(o)) continue;
    book.slash(o, "missedPlant", `plant:${s.id}`, state.rules.rewards.missedPlantPenalty);
  }
  return book.bodies();
}

// A claim that has expired (until < now) loses its stake if its agent never
// submitted for the task. state.claims keeps only the latest claim per task. A
// claim that a newer claim replaced before this ran can no longer be
// settled, so the coordinator should run this before it accepts a new claim.
export function settleExpiredClaims(state: CommonsState, nowIso: string): SettlementBody[] {
  const now = Date.parse(nowIso);
  if (Number.isNaN(now)) throw new RangeError(`settleExpiredClaims: invalid nowIso ${nowIso}`);
  const book = new Book(state);
  for (const c of state.claims.values()) {
    if (!(Date.parse(c.until) < now)) continue;
    let submitted = false;
    for (const s of state.submissions.values()) if (s.taskId === c.taskId && s.author === c.agent) submitted = true;
    const owner = ownerOf(state, c.agent);
    if (!submitted && owner !== undefined) book.slash(owner, "claimExpired", `claim:${c.taskId}:${c.seq}`, c.stake);
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

// Sums amounts per (owner, reason, ref) and drops keys already settled.
class Book {
  private readonly sums = new Map<string, SettlementBody>();
  constructor(private readonly state: CommonsState) {}

  credit(owner: OwnerId, reason: SettlementReason, ref: string, amount: number): void {
    const key = `${owner}\u0000${reason}\u0000${ref}`;
    const b = this.sums.get(key);
    if (b) b.delta += amount;
    else this.sums.set(key, { kind: "settlement", owner, delta: amount, reason, ref });
  }

  // A slash of `amount` (>= 0) on owner, plus the inviter's share of it.
  slash(owner: OwnerId, reason: SettlementReason, ref: string, amount: number): void {
    if (!(amount > 0)) return;
    this.credit(owner, reason, ref, -amount);
    const inviter = this.state.owners.get(owner)?.inviter ?? null;
    if (inviter !== null) this.credit(inviter, "inviterSlash", ref, -Math.round(amount * this.state.rules.rewards.inviterShare));
  }

  bodies(): SettlementBody[] {
    const done = new Set(this.state.settlements.map((s) => `${s.owner}\u0000${s.reason}\u0000${s.ref}`));
    const out: SettlementBody[] = [];
    for (const [key, b] of this.sums) {
      // `+ 0` turns -0 into 0. Zero bodies are dropped anyway, but a sum of
      // signed parts can still land on -0.
      if (b.delta === 0 || done.has(key)) continue;
      out.push({ ...b, delta: b.delta + 0 });
    }
    return out;
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

function hasReproducedFinding(state: CommonsState, s: SubmissionState): boolean {
  return s.findingIds.some((fid) => state.findings.get(fid)?.result?.reproduced === true);
}

// The snapshot and its ancestors up to (not including) the first promoted
// one: what a promotion of `snap` ships, and what a finding on it covers. This
// is the ledger's definition. Ids are unique and only name earlier snapshots,
// so the walk ends. The seen-set guards a malformed state anyway.
function ancestry(state: CommonsState, snap: SnapshotState): SnapshotState[] {
  const out = [snap];
  const seen = new Set([snap.id]);
  for (let p = snap.previousSnapshotId; p !== null && !seen.has(p); ) {
    const prev = state.snapshots.get(p);
    if (!prev || prev.promoted) break;
    seen.add(p);
    out.push(prev);
    p = prev.previousSnapshotId;
  }
  return out;
}

function covered(state: CommonsState, snap: SnapshotState): string[] {
  return ancestry(state, snap).flatMap((x) => x.submissionIds);
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

function nowMs(state: CommonsState, nowIso: string | undefined): number {
  const iso = nowIso ?? (state as CommonsState & { headAt?: string }).headAt ?? "1970-01-01T00:00:00.000Z";
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new RangeError(`invalid nowIso ${iso}`);
  return ms;
}

// `total` split into n integer parts that differ by at most 1 and sum to
// total. The first parts take the remainder.
function splitInteger(total: number, n: number): number[] {
  if (n <= 0) return [];
  const base = Math.floor(total / n);
  const rest = total - base * n;
  return Array.from({ length: n }, (_, i) => base + (i < rest ? 1 : 0));
}

// The ledger only accepts p in [0, 1]. Anything else counts as p = 0, the
// most confident "clean", so a malformed verdict never escapes a slash.
function clamp01(p: number): number {
  return Number.isFinite(p) ? Math.min(1, Math.max(0, p)) : 0;
}
