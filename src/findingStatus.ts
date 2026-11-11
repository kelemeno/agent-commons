// What a finding has established, in one place. Every module that asks "is
// this a known defect?", "does it block a merge?" or "was it false?" asks here.
//
// A reproduced result alone shows only that the finder's test fails on head
// and passes on the parent. A test that pins the old behaviour (asserting the
// text the change intentionally replaced) does that against any change, so a
// reproduction is evidence for an operator to judge, not a verdict: a
// findingDecision entry confirms it (a real defect) or dismisses it (it tests
// the intended change). Until then it blocks the merge but pays, slashes and
// counts as a catch for nobody.

import type { FindingState } from "./types";

export type FindingStatus =
  | "pending" // no result yet
  | "notReproduced" // judged and not reproduced, or the harness could not judge it
  | "undecided" // reproduced, awaiting an operator's decision
  | "confirmed" // reproduced and confirmed a real defect
  | "dismissed"; // reproduced, but dismissed as testing the intended change

export function findingStatus(f: FindingState): FindingStatus {
  if (!f.result) return "pending";
  if (!f.result.reproduced) return "notReproduced";
  if (!f.decision) return "undecided";
  return f.decision.confirmed ? "confirmed" : "dismissed";
}

// A defect the ledger has established: it pays, slashes, records escapes,
// makes a review outcome 1 and counts as a plant catch.
export function isConfirmedDefect(f: FindingState): boolean {
  return findingStatus(f) === "confirmed";
}

// Reproduced and not dismissed: possibly a defect. Merges, snapshots,
// promotions and unpaid merge tranches wait on these.
export function isReproducedOpen(f: FindingState): boolean {
  const s = findingStatus(f);
  return s === "undecided" || s === "confirmed";
}

// Whether the finding stops its target from merging or shipping: undecided
// work (no result, or a reproduction nobody judged) and confirmed defects.
export function blocksTarget(f: FindingState): boolean {
  const s = findingStatus(f);
  return s === "pending" || s === "undecided" || s === "confirmed";
}

// What falseFindingPenalty charges and the false-finding rate counts: judged
// and not reproduced, without a harness error (which proves nothing either
// way), or a reproduction an operator dismissed.
export function isFalseFinding(f: FindingState): boolean {
  if (!f.result) return false;
  if (!f.result.reproduced) return f.result.harnessError === undefined;
  return f.decision?.confirmed === false;
}
