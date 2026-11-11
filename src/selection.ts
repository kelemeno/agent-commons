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
//            = min(d - N, MAX_WEIGHT)  otherwise
//   score    = u^(1/w), compared exactly (see beats), highest first
//
// d is the tree distance between the owner and the author's owner, N is
// rules.minTreeDistance, and owners with d <= N are ineligible. "Lineal" means
// one is an ancestor of the other (d equals the difference of their depths).
// Within an owner, the seat goes to the agent with the highest
// drawFraction(beacon, keyId). Ties (equal scores, then equal agent draws) are
// broken by the smaller keyId.
//
// Why the weight is small and capped. Collusion is cheapest between people who
// invited each other, so an owner just past the limit gets one ticket and a
// more distant one two. Beyond that the distance says nothing more, and an
// uncapped weight would hand the most tickets to the longest invite chain,
// which is exactly what a person building sock accounts produces. The author's
// own ancestors and descendants get no bonus however far away they are: the
// author (or someone in that line) vouched for every one of them.
//
// The lottery ticket belongs to the owner, not the agent. Registering an agent
// is free, so a per-agent draw would let one person buy extra tickets by
// registering twenty agents. Everything is a function of (state, tree,
// beacon), so anyone holding the ledger and the tree can recompute an
// assignment.

import { canonical, sha256hex } from "./crypto";
import { replay } from "./ledger";
import type { CommonsState, KeyId, LedgerEntry, OwnerId, SubmissionState, TreeView } from "./types";

export type Selection = { reviewers: KeyId[]; candidates: number; notes: string[] };

// Largest number of tickets a distant owner holds; see the header.
export const MAX_WEIGHT = 2;

// `draw` (1..SPAN-1) and `weight` give the owner's exact score; `agentDraw`
// only orders agents within one owner.
type Candidate = { keyId: KeyId; owner: OwnerId; family: string; draw: bigint; weight: number; agentDraw: number };

function submissionOf(state: CommonsState, submissionId: string): SubmissionState {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`selection: no submission ${submissionId}`);
  return s;
}

// The head hash binds the beacon to everything on the ledger so far, the head
// commit to this exact change. The external entropy (a public randomness
// round) is what stops the coordinator from choosing the outcome; without it
// the beacon is predictable by anyone who can see the ledger. The coordinator
// still controls which entry is the head, so this binding is only as strong as
// the rule fixing which entropy round must be used (not yet on the ledger).
export function computeBeacon(state: CommonsState, submissionId: string, externalEntropy: string): string {
  const s = submissionOf(state, submissionId);
  return sha256hex(canonical({ head: state.headHash, submission: s.headCommit, entropy: externalEntropy }));
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

// Model families are free text on the ledger. Case and surrounding spaces are
// not a different model, so "Claude " and "claude" must not satisfy the
// other-family rule against each other. Different names for one family
// ("anthropic") still slip through until Rules carries a closed list.
const familyKey = (f: string) => f.trim().toLowerCase();

// The tree's identity for an owner. Anthill trees fold addresses to lowercase,
// but ledger owner ids are exact strings, so one member registered under two
// spellings would otherwise hold two tickets and two seats. Ids the tree keeps
// case-sensitive (treeFromParents) are left alone. `owner` must be a member.
function treeIdentity(tree: TreeView, owner: OwnerId): OwnerId {
  const lower = owner.toLowerCase();
  return lower !== owner && tree.has(lower) && tree.distance(owner, lower) === 0 ? lower : owner;
}

// `candidates` counts distinct eligible owners: that is the pool seats are
// drawn from, since an owner fills at most one seat.
export function selectReviewers(state: CommonsState, tree: TreeView, submissionId: string, beacon: string): Selection {
  const s = submissionOf(state, submissionId);
  const rules = state.rules;
  if (!Number.isInteger(rules.minTreeDistance)) throw new Error("selection: rules.minTreeDistance must be an integer");
  const notes: string[] = [];
  const author = state.agents.get(s.author);
  if (!author) throw new Error(`selection: author ${s.author} of ${submissionId} is not an agent`);
  if (!tree.has(author.owner)) {
    // Without the author's position no distance can be checked, and an
    // unchecked distance is exactly what a colluding pair would want.
    return { reviewers: [], candidates: 0, notes: [`author's owner ${author.owner} is not in the tree`] };
  }
  const authorOwner = treeIdentity(tree, author.owner);
  const authorDepth = tree.depth(authorOwner);
  const authorFamily = familyKey(author.modelFamily);

  const eligible: Candidate[] = [];
  const outsideTree = new Set<OwnerId>();
  const ownerDraw = new Map<OwnerId, { draw: bigint; weight: number } | null>();
  for (const agent of state.agents.values()) {
    if (!agent.active) continue;
    if (!tree.has(agent.owner)) {
      outsideTree.add(agent.owner);
      continue;
    }
    const owner = treeIdentity(tree, agent.owner);
    if (owner === authorOwner) continue;
    let o = ownerDraw.get(owner);
    if (o === undefined) {
      const distance = tree.distance(owner, authorOwner);
      const lineal = distance === Math.abs(tree.depth(owner) - authorDepth);
      const weight = distance <= rules.minTreeDistance ? 0 : lineal ? 1 : Math.min(distance - rules.minTreeDistance, MAX_WEIGHT);
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
  if (outsideTree.size > 0) notes.push(`${outsideTree.size} owner(s) with active agents skipped: not in the tree`);
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
    // `eligible` is sorted, so this is the best-scored owner with an
    // other-family agent, and that owner's best such agent.
    const other = eligible.find((c) => c.family !== authorFamily);
    if (other) {
      // Replace the lowest pick, unless the other-family agent's owner already
      // holds a seat: then it takes that owner's seat, keeping one per owner.
      const sameOwner = picks.findIndex((p) => p.owner === other.owner);
      picks[sameOwner >= 0 ? sameOwner : picks.length - 1] = other;
      picks.sort(byScore);
      notes.push(`seat given to ${other.keyId} (${other.family}) for a model family other than ${authorFamily}`);
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

// Recomputes the draw from the recorded beacon and compares reviewer sets
// (order is not significant). The answer is exact only if agents, rules and
// the tree are as they were when the assignment was made: an agent registered
// or revoked since changes the pool, and AgentState records no seq to undo
// that. For an audit of an old assignment use verifyAssignmentInLedger.
// This does not check how the beacon was derived; the entropy is not on the
// ledger.
export function verifyAssignment(state: CommonsState, tree: TreeView, submissionId: string): boolean {
  const s = state.submissions.get(submissionId);
  if (!s?.assignment) return false;
  const { reviewers } = selectReviewers(state, tree, submissionId, s.assignment.beacon);
  return sameSet(reviewers, s.assignment.reviewers);
}

// The exact audit: replays the ledger up to the entry before the assignment
// (the state the coordinator drew from) and recomputes there. `tree` must be
// the tree as it was then. With `entropy` (the published randomness the
// coordinator says it used), the recorded beacon must also equal
// computeBeacon over that state; without it, a coordinator free to pick any
// beacon can keep trying until it likes the draw.
export function verifyAssignmentInLedger(
  entries: readonly LedgerEntry[],
  tree: TreeView,
  submissionId: string,
  entropy?: string,
): boolean {
  const at = entries.findIndex((e) => e.body.kind === "reviewAssignment" && e.body.submissionId === submissionId);
  const entry = entries[at];
  if (!entry || entry.body.kind !== "reviewAssignment") return false;
  const before = replay(entries.slice(0, at));
  if (!before.submissions.has(submissionId)) return false;
  if (entropy !== undefined && computeBeacon(before, submissionId, entropy) !== entry.body.beacon) return false;
  const { reviewers } = selectReviewers(before, tree, submissionId, entry.body.beacon);
  return sameSet(reviewers, entry.body.reviewers);
}
