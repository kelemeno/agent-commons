// Reviewer selection: who reviews a submission, drawn from a beacon fixed after
// the submission, so that nobody (author, reviewer or coordinator) can steer a
// change towards friendly reviewers once it exists.
//
// The draw is Efraimidis–Spirakis weighted sampling without replacement over
// owners. Each eligible owner gets u = H(beacon, owner) in (0, 1) and score
// u^(1/w), where w is how much farther than rules.minTreeDistance the owner
// sits from the author's owner in the Anthill tree. The top scores win.
// Distance is the weight because collusion is cheapest between people who
// invited each other: an owner three hops past the limit is three times as
// likely to be drawn as one just past it.
//
// The lottery ticket belongs to the owner, not the agent. Registering an agent
// is free, so a per-agent draw would let one person buy extra tickets by
// registering twenty agents. Within an owner, the seat goes to the agent with
// the best H(beacon, keyId). Everything is a function of (state, tree, beacon),
// so anyone holding the ledger and the tree can recompute an assignment.

import { canonical, sha256hex } from "./crypto";
import { replay } from "./ledger";
import type { CommonsState, KeyId, LedgerEntry, OwnerId, SubmissionState, TreeView } from "./types";

export type Selection = { reviewers: KeyId[]; candidates: number; notes: string[] };

// `score` is the owner's weighted draw; `agentDraw` only orders agents within one owner.
type Candidate = { keyId: KeyId; owner: OwnerId; family: string; score: number; agentDraw: number };

function submissionOf(state: CommonsState, submissionId: string): SubmissionState {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`selection: no submission ${submissionId}`);
  return s;
}

// The head hash binds the beacon to everything on the ledger so far, the head
// commit to this exact change. The external entropy (a public randomness
// round) is what stops the coordinator from choosing the outcome; without it
// the beacon is predictable by anyone who can see the ledger.
export function computeBeacon(state: CommonsState, submissionId: string, externalEntropy: string): string {
  const s = submissionOf(state, submissionId);
  return sha256hex(canonical({ head: state.headHash, submission: s.headCommit, entropy: externalEntropy }));
}

const SPAN = 16 ** 13; // 52 bits: exact in a double

// Uniform in (0, 1) from the first 13 hex digits of sha256hex(beacon + ":" +
// label). A zero draw would score 0 whatever the weight, so it is moved to the
// smallest step instead.
export function drawFraction(beacon: string, label: string): number {
  const n = parseInt(sha256hex(`${beacon}:${label}`).slice(0, 13), 16);
  return Math.max(n, 1) / SPAN;
}

// Owner labels carry a prefix so an owner id can never collide with a keyId.
const ownerLabel = (owner: OwnerId) => `owner:${owner}`;

// Best owner first, then that owner's best agent; the keyId breaks exact ties
// (vanishingly rare) so the order never depends on Map iteration.
function byScore(a: Candidate, b: Candidate): number {
  return b.score - a.score || b.agentDraw - a.agentDraw || (a.keyId < b.keyId ? -1 : a.keyId > b.keyId ? 1 : 0);
}

// `candidates` counts distinct eligible owners: that is the pool seats are
// drawn from, since an owner fills at most one seat.
export function selectReviewers(state: CommonsState, tree: TreeView, submissionId: string, beacon: string): Selection {
  const s = submissionOf(state, submissionId);
  const rules = state.rules;
  const notes: string[] = [];
  const author = state.agents.get(s.author);
  if (!author) throw new Error(`selection: author ${s.author} of ${submissionId} is not an agent`);
  if (!tree.has(author.owner)) {
    // Without the author's position no distance can be checked, and an
    // unchecked distance is exactly what a colluding pair would want.
    return { reviewers: [], candidates: 0, notes: [`author's owner ${author.owner} is not in the tree`] };
  }

  const eligible: Candidate[] = [];
  const outsideTree = new Set<OwnerId>();
  const ownerScore = new Map<OwnerId, number | null>();
  for (const agent of state.agents.values()) {
    if (!agent.active || agent.owner === author.owner) continue;
    if (!tree.has(agent.owner)) {
      outsideTree.add(agent.owner);
      continue;
    }
    let o = ownerScore.get(agent.owner);
    if (o === undefined) {
      const distance = tree.distance(agent.owner, author.owner);
      const weight = distance - rules.minTreeDistance;
      o = weight > 0 ? drawFraction(beacon, ownerLabel(agent.owner)) ** (1 / weight) : null;
      ownerScore.set(agent.owner, o);
    }
    if (o === null) continue;
    eligible.push({
      keyId: agent.keyId,
      owner: agent.owner,
      family: agent.modelFamily,
      score: o,
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

  if (rules.requireOtherModelFamily && picks.length > 0 && picks.every((p) => p.family === author.modelFamily)) {
    const other = eligible.find((c) => c.family !== author.modelFamily);
    if (other) {
      // Replace the lowest pick, unless the other-family agent's owner already
      // holds a seat: then it takes that owner's seat, keeping one per owner.
      const sameOwner = picks.findIndex((p) => p.owner === other.owner);
      picks[sameOwner >= 0 ? sameOwner : picks.length - 1] = other;
      picks.sort(byScore);
      notes.push(`seat given to ${other.keyId} (${other.family}) for a model family other than ${author.modelFamily}`);
    } else {
      notes.push(`no eligible reviewer has a model family other than the author's (${author.modelFamily})`);
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
// the tree as it was then.
export function verifyAssignmentInLedger(entries: readonly LedgerEntry[], tree: TreeView, submissionId: string): boolean {
  const at = entries.findIndex(
    (e) => e.body.kind === "reviewAssignment" && e.body.submissionId === submissionId,
  );
  const entry = entries[at];
  if (!entry || entry.body.kind !== "reviewAssignment") return false;
  const before = replay(entries.slice(0, at));
  if (!before.submissions.has(submissionId)) return false;
  const { reviewers } = selectReviewers(before, tree, submissionId, entry.body.beacon);
  return sameSet(reviewers, entry.body.reviewers);
}
