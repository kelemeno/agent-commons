// The static gates of a ledger submission: everything that can be decided
// from the declared change and the checkout at its head, without running code.
// The caller checks first that changedFiles/linesChanged match git (see
// cli.ts submissionGates); these gates trust the declaration.

import type { CommonsState, GateReport } from "../types";
import { checkAirlock } from "./airlock";
import { checkRingImports } from "./rings";
import { checkSize } from "./size";
import { checkSpecSeparation } from "./specSeparation";

export { checkAirlock, isLocked } from "./airlock";
export { checkRingImports, normalizeRepoPath, ringOf, scanImports, submissionRing, type ImportRef } from "./rings";
export { checkSize } from "./size";
export { checkSpecSeparation, isAcceptancePath } from "./specSeparation";

// Reports in the order rings, airlock, specSeparation, size. `repoDir` must be
// checked out at the submission's head commit. Throws for an unknown
// submission or an unreadable repoDir: a harness error, never a verdict.
export function runStaticGates(
  state: CommonsState,
  submissionId: string,
  repoDir: string,
  opts: { dependencyTrack: boolean },
): GateReport[] {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`no submission ${submissionId}`);
  return [
    checkRingImports(repoDir, s.changedFiles, state.rules),
    checkAirlock(s.changedFiles, state.rules, opts),
    checkSpecSeparation(state, submissionId),
    checkSize(s.linesChanged, state.rules),
  ];
}
