// Reviewer selection: who reviews a submission, drawn from a beacon fixed after
// the submission, so that nobody (author, reviewer or coordinator) can steer a
// change towards friendly reviewers once it exists.
//
// The draw is Efraimidis–Spirakis weighted sampling without replacement over
// owners. This is the exact algorithm an independent verifier must reproduce:
//
//   U(owner) = max(int(sha256hex(beacon + ":owner:" + owner)[0:13], 16), 1)
//   u        = U / 16^13                                   (in (0, 1))
//   w        = 1                       if owner and author are lineal
//            = MAX_WEIGHT              if they are in different invite lines
//            = min(d - N, MAX_WEIGHT)  otherwise
//   score    = u^(1/w), compared exactly (see beats), highest first
//
// d is the tree distance between the owner and the author's owner, N is
// rules.minTreeDistance, and owners with d <= N are ineligible. "Lineal" means
// one is an ancestor of the other (d equals the difference of their depths).
// "Different invite lines" means their paths meet only at the member tree's
// virtual root (d equals the sum of their depths): nobody vouched for both.
// Within an owner, the seat goes to the agent with the highest
// drawFraction(beacon, keyId), or to the agent that already committed a
// review on the submission (one commit per owner). Ties (equal scores, then
// equal agent draws) are broken by the smaller keyId.
//
// Why the weight is small and capped. Collusion is cheapest between people who
// invited each other, so an owner just past the limit gets one ticket and a
// more distant one two. Beyond that the distance says nothing more, and an
// uncapped weight would hand the most tickets to the longest invite chain,
// which is exactly what a person building sock accounts produces. The author's
// own ancestors and descendants get no bonus however far away they are: the
// author (or someone in that line) vouched for every one of them. Owners in
// another invite line share no voucher with the author at all, so they hold
// the full weight however deep they sit: the two edges through the virtual
// root are not a social relation, and counting them would give an owner
// admitted under an inviter twice the tickets of one admitted with none.
// In Phase 1 (every owner admitted with no inviter, or a few vouched for)
// that makes the draw uniform over every eligible owner outside the
// author's line.
//
// The lottery ticket belongs to the owner, not the agent. Registering an agent
// is free, so a per-agent draw would let one person buy extra tickets by
// registering twenty agents. Everything is a function of (state, beacon):
// the tree is the member tree of the same state (members.memberTree), so
// anyone holding the ledger can recompute an assignment.
//
// The beacon (review.assignmentBeacon) is fixed by the entry itself: the
// submission, its head commit and the entropy. The ledger refuses any other
// beacon, and any tree digest but that of the member tree before the entry.
// The entropy rule: the first round of a public randomness beacon (e.g.
// drand) published after the submission's `at` plus the clock skew the
// server allows (5 minutes), since the author stamps `at` and may backdate it
// that far; a round named that way was not public when the submission was
// posted, so neither the author (choosing an id) nor the coordinator can
// grind it. Phase 1 may use a value the coordinator committed to before the
// submission (and published after the assignment); that trusts the
// coordinator not to grind, and verifiers can only check that the recorded
// value was used.
//
// The pool is fixed too: agents registered before the submission, less those
// revoked before the assignment (the draw happens after binding and gates,
// when the round may be public, so a later registration could be timed to a
// winning draw). The tree is the ledger's own, so nobody chooses it at the
// draw, and an owner admitted between the submission and the draw changes
// nothing: it has no agent in the pool, a new leaf moves no existing
// distance or depth, and the tree's digest is not a beacon input. What the
// coordinator still chooses is which agents it revokes (a suspension, on the
// ledger with its reason, promotes the next-ranked owner); Phase 1 trusts it
// with that.

import { sha256hex } from "./crypto";
import { replay } from "./ledger";
import { memberDigest, memberTree } from "./members";
import { assignmentBeacon } from "./review";
import type { AgentState, CommonsState, EntryBody, KeyId, LedgerEntry, OwnerId, OwnerState, SubmissionState } from "./types";

export type Selection = { reviewers: KeyId[]; candidates: number; notes: string[] };

// Largest number of tickets a distant owner holds; see the header.
export const MAX_WEIGHT = 2;

// requireOtherModelFamily forces a seat for an unseated owner only when at
// least this many eligible owners offer a family other than the author's.
export const MIN_OTHER_FAMILY_OWNERS = 2;

// `draw` (1..SPAN-1) and `weight` give the owner's exact score; `agentDraw`
// only orders agents within one owner.
type Candidate = { keyId: KeyId; owner: OwnerId; family: string; draw: bigint; weight: number; agentDraw: number };

function submissionOf(state: CommonsState, submissionId: string): SubmissionState {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`selection: no submission ${submissionId}`);
  return s;
}

// The beacon the ledger will accept for this submission and entropy; see
// the header.
export function computeBeacon(state: CommonsState, submissionId: string, externalEntropy: string): string {
  const s = submissionOf(state, submissionId);
  return assignmentBeacon(s.id, s.headCommit, externalEntropy);
}

// The whole reviewAssignment body for an already drawn set of reviewers.
export function assignmentBody(
  state: CommonsState,
  submissionId: string,
  reviewers: KeyId[],
  entropy: string,
): Extract<EntryBody, { kind: "reviewAssignment" }> {
  const beacon = computeBeacon(state, submissionId, entropy);
  return { kind: "reviewAssignment", submissionId, beacon, entropy, treeDigest: memberDigest(state), reviewers };
}

// Draws over the member tree of `state` and returns the body to append (the
// beacon, entropy, tree digest and drawn reviewers) with the draw's notes.
export function drawAssignment(
  state: CommonsState,
  submissionId: string,
  entropy: string,
): Selection & { body: Extract<EntryBody, { kind: "reviewAssignment" }> } {
  const picked = selectReviewers(state, submissionId, computeBeacon(state, submissionId, entropy));
  return { ...picked, body: assignmentBody(state, submissionId, picked.reviewers, entropy) };
}

const SPAN = 16 ** 13; // 52 bits: exact in a double
const SPAN_BIG = BigInt(SPAN);

// First 13 hex digits of sha256hex(beacon + ":" + label), with 0 moved to 1:
// a zero draw would score 0 whatever the weight.
function drawInt(beacon: string, label: string): number {
  return Math.max(parseInt(sha256hex(`${beacon}:${label}`).slice(0, 13), 16), 1);
}

// The same draw as a fraction in (0, 1).
export function drawFraction(beacon: string, label: string): number {
  return drawInt(beacon, label) / SPAN;
}

// Owner labels carry a prefix so an owner id can never collide with a keyId.
const ownerLabel = (owner: OwnerId) => `owner:${owner}`;

// True if a's score u_a^(1/w_a) exceeds b's, decided in integers so every
// verifier agrees: raising both sides to w_a * w_b gives
// U_a^w_b * SPAN^w_a > U_b^w_a * SPAN^w_b. Floating-point pow is not
// correctly rounded everywhere and could order a near-tie differently.
function compareScore(a: Candidate, b: Candidate): number {
  const wa = BigInt(a.weight);
  const wb = BigInt(b.weight);
  const left = a.draw ** wb * SPAN_BIG ** wa;
  const right = b.draw ** wa * SPAN_BIG ** wb;
  return left > right ? 1 : left < right ? -1 : 0;
}

// Best owner first, then that owner's best agent, then the smaller keyId, so
// the order never depends on Map iteration.
function byScore(a: Candidate, b: Candidate): number {
  return -compareScore(a, b) || b.agentDraw - a.agentDraw || (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0);
}

// The ledger only accepts families from rules.modelFamilies (lowercase), so
// this normalisation matters only for hand-built states; it keeps "Claude "
// and "claude" one family there too.
const familyKey = (f: string) => f.trim().toLowerCase();

// The draw over the member tree of `state`. `candidates` counts distinct
// eligible owners: that is the pool seats are drawn from, since an owner
// fills at most one seat. Owner ids are exact: the ledger refuses a second
// spelling of an owner (ids ignore case there), so one person cannot hold two
// tickets under two spellings.
export function selectReviewers(state: CommonsState, submissionId: string, beacon: string): Selection {
  const s = submissionOf(state, submissionId);
  const tree = memberTree(state);
  const rules = state.rules;
  if (!Number.isInteger(rules.minTreeDistance)) throw new Error("selection: rules.minTreeDistance must be an integer");
  const notes: string[] = [];
  const author = state.agents.get(s.author);
  if (!author) throw new Error(`selection: author ${s.author} of ${submissionId} is not an agent`);
  // Every agent's owner is a member (the ledger registers agents only under
  // owners, and memberTree holds every owner); the tree throws on anything
  // else, so a corrupt state stops the draw instead of skipping a check.
  const authorOwner = author.owner;
  const authorDepth = tree.depth(authorOwner);
  const authorFamily = familyKey(author.modelFamily);

  // An owner that already committed on the submission (open reviewers may
  // commit before the draw) is represented by the committing agent: the
  // ledger takes one commit per owner, so a seat drawn for its other agent
  // could never be filled. If that agent is outside the pool, the owner has
  // no seat; it could already leave the draw by revoking its agents.
  const committedFor = new Map<OwnerId, KeyId>();
  for (const r of s.reviews) {
    const a = state.agents.get(r.reviewer);
    if (a) committedFor.set(a.owner, r.reviewer);
  }

  const eligible: Candidate[] = [];
  const ownerDraw = new Map<OwnerId, { draw: bigint; weight: number } | null>();
  for (const agent of state.agents.values()) {
    if (!agent.active) continue;
    // The pool is fixed at the submission: an agent registered after it is
    // not drawn. The draw happens later (after binding and gates), when the
    // entropy round the rule names may already be public, so otherwise an
    // owner could register an agent exactly when its draw would win a seat.
    if (agent.registeredSeq !== undefined && agent.registeredSeq >= s.submittedSeq) continue;
    const owner = agent.owner;
    if (owner === authorOwner) continue;
    const committed = committedFor.get(owner);
    if (committed !== undefined && committed !== agent.keyId) continue;
    let o = ownerDraw.get(owner);
    if (o === undefined) {
      const distance = tree.distance(owner, authorOwner);
      const lineal = distance === Math.abs(tree.depth(owner) - authorDepth);
      const otherLine = distance === tree.depth(owner) + authorDepth;
      const weight =
        distance <= rules.minTreeDistance ? 0 : lineal ? 1 : otherLine ? MAX_WEIGHT : Math.min(distance - rules.minTreeDistance, MAX_WEIGHT);
      o = weight > 0 ? { draw: BigInt(drawInt(beacon, ownerLabel(owner))), weight } : null;
      ownerDraw.set(owner, o);
    }
    if (o === null) continue;
    eligible.push({
      keyId: agent.keyId,
      owner,
      family: familyKey(agent.modelFamily),
      draw: o.draw,
      weight: o.weight,
      agentDraw: drawFraction(beacon, agent.keyId),
    });
  }
  eligible.sort(byScore);

  // One seat per owner: the owner's best-drawn agent represents it.
  const bestPerOwner: Candidate[] = [];
  const seen = new Set<OwnerId>();
  for (const c of eligible) {
    if (seen.has(c.owner)) continue;
    seen.add(c.owner);
    bestPerOwner.push(c);
  }
  const picks = bestPerOwner.slice(0, Math.max(0, rules.assignedReviewers));

  if (rules.requireOtherModelFamily && picks.length > 0 && picks.every((p) => p.family === authorFamily)) {
    // `eligible` is sorted: the first other-family candidate of a seated
    // owner is that owner's best such agent, and otherOwners is in score order.
    const seated = new Set(picks.map((p) => p.owner));
    const switchTo = eligible.find((c) => c.family !== authorFamily && seated.has(c.owner));
    const otherOwners = [...new Set(eligible.filter((c) => c.family !== authorFamily).map((c) => c.owner))];
    if (switchTo) {
      // A seated owner takes its seat with its other-family agent: nobody
      // gains a seat.
      picks[picks.findIndex((p) => p.owner === switchTo.owner)] = switchTo;
      picks.sort(byScore);
      notes.push(`${switchTo.owner}'s seat taken by ${switchTo.keyId} (${switchTo.family}) for a model family other than ${authorFamily}`);
    } else if (otherOwners.length >= MIN_OTHER_FAMILY_OWNERS) {
      // The lowest pick goes to the best-scored other-family owner: the same
      // lottery, over the owners that offer another family.
      const other = eligible.find((c) => c.family !== authorFamily) as Candidate;
      picks[picks.length - 1] = other;
      picks.sort(byScore);
      notes.push(`seat given to ${other.keyId} (${other.family}) for a model family other than ${authorFamily}`);
    } else if (otherOwners.length === 1) {
      // Families are self-declared and agents are free: if the only owner
      // offering another family always won the forced seat, one declaration
      // would buy a seat on every majority-family submission, whatever its
      // draw or distance.
      notes.push(`only ${otherOwners[0]} offers a model family other than ${authorFamily}; no seat is forced (one declaration must not buy a seat on every draw)`);
    } else {
      notes.push(`no eligible reviewer has a model family other than the author's (${authorFamily})`);
    }
  }

  if (picks.length < rules.assignedReviewers) {
    notes.push(
      `only ${picks.length} of ${rules.assignedReviewers} reviewers: ${bestPerOwner.length} eligible owner(s) farther than ${rules.minTreeDistance} from ${author.owner}`,
    );
  }
  return { reviewers: picks.map((p) => p.keyId), candidates: bestPerOwner.length, notes };
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const x = [...a].sort();
  const y = [...b].sort();
  return x.every((v, i) => v === y[i]);
}

// The state as the draw at `seq` saw it: the owners (so the member tree) and
// agents registered before it, each agent active unless revoked before it,
// under the rules then in force, and the submission's review commits made
// before it. Replay records the seqs (registeredSeq, revokedSeq,
// rulesHistory); a hand-built state without them is taken as it is.
function stateAt(state: CommonsState, seq: number, submissionId: string): CommonsState {
  const owners = new Map<OwnerId, OwnerState>();
  for (const [id, o] of state.owners) if (o.registeredSeq === undefined || o.registeredSeq < seq) owners.set(id, o);
  const agents = new Map<KeyId, AgentState>();
  for (const [k, a] of state.agents) {
    if (a.registeredSeq !== undefined && a.registeredSeq >= seq) continue;
    const active = a.registeredSeq === undefined ? a.active : a.revokedSeq === undefined || a.revokedSeq > seq;
    agents.set(k, { ...a, active });
  }
  const rules = state.rulesHistory?.filter((r) => r.seq < seq).at(-1)?.rules ?? state.rules;
  const submissions = new Map(state.submissions);
  const s = state.submissions.get(submissionId);
  if (s) submissions.set(submissionId, { ...s, reviews: s.reviews.filter((r) => r.committedSeq < seq) });
  return { ...state, owners, agents, rules, submissions };
}

// True if the recorded assignment is the draw the ledger before it gives: the
// member tree then has the recorded digest, the beacon is the one its entropy
// gives (with the submission id and head), and the draw over the state as it was at the assignment
// picks the same reviewers (order is not significant).
export function verifyAssignment(state: CommonsState, submissionId: string): boolean {
  const s = state.submissions.get(submissionId);
  const a = s?.assignment;
  if (!s || !a) return false;
  const before = stateAt(state, a.seq, submissionId);
  if (memberDigest(before) !== a.treeDigest) return false;
  if (assignmentBeacon(s.id, s.headCommit, a.entropy) !== a.beacon) return false;
  const { reviewers } = selectReviewers(before, submissionId, a.beacon);
  return sameSet(reviewers, a.reviewers);
}

// The same audit from the entries alone: replays the ledger up to the entry
// before the assignment (the state the coordinator drew from) and recomputes
// there. With `entropy` (the published round the rule names), the recorded
// entropy must also be that value: the ledger only checks that the beacon
// follows from whatever entropy was recorded.
export function verifyAssignmentInLedger(entries: readonly LedgerEntry[], submissionId: string, entropy?: string): boolean {
  const at = entries.findIndex((e) => e.body.kind === "reviewAssignment" && e.body.submissionId === submissionId);
  const entry = entries[at];
  if (!entry || entry.body.kind !== "reviewAssignment") return false;
  const body = entry.body;
  if (entropy !== undefined && body.entropy !== entropy) return false;
  const before = replay(entries.slice(0, at));
  if (memberDigest(before) !== body.treeDigest) return false;
  const s = before.submissions.get(submissionId);
  if (!s || assignmentBeacon(s.id, s.headCommit, body.entropy) !== body.beacon) return false;
  const { reviewers } = selectReviewers(before, submissionId, body.beacon);
  return sameSet(reviewers, body.reviewers);
}
