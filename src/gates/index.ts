// The static gates of a ledger submission: everything that can be decided
// from the declared change and the checkout at its head, without running code.
// The caller checks first that changedFiles/linesChanged match git (see
// cli.ts submissionGates); these gates trust the declaration.

import type { CommonsState, GateReport, Ring, Rules } from "../types";
import { checkAirlock } from "./airlock";
import { checkRingImports, ringOf, submissionRing } from "./rings";
import { checkSize } from "./size";
import { checkSpecSeparation } from "./specSeparation";

export { checkAirlock, isLocked } from "./airlock";
export {
  checkRingImports,
  decodeIdentifierEscapes,
  normalizeRepoPath,
  ringOf,
  scanImports,
  submissionRing,
  type ImportRef,
  type RingImportOptions,
} from "./rings";
export { BYTES_PER_LINE, checkSize, type SizeChange } from "./size";
export { checkSpecSeparation, isAcceptancePath, isTestSupport } from "./specSeparation";

export type StaticGateOptions = {
  dependencyTrack: boolean;
  deleted?: Iterable<string>; // changed files the diff deletes (see RingImportOptions)
  binary?: readonly string[]; // changed files git counts no lines for
  bytesAdded?: number; // size of the added side of the diff
};

// A claim's stake is priced by the task's ring, so a submission must not
// touch a lower (more privileged) ring than its task was scoped at: kernel
// work bought at UI stake. null when the submission has no task (the ledger
// requires one for ring-0 files) or the task is unknown (specSeparation
// reports that).
export function checkTaskRing(state: CommonsState, submissionId: string): GateReport | null {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`no submission ${submissionId}`);
  const task = s.taskId === null ? undefined : state.tasks.get(s.taskId);
  if (task === undefined) return null;
  return taskRingReport(s.changedFiles, task.id, task.ring, state.rules);
}

function taskRingReport(files: string[], taskId: string, ring: Ring, rules: Rules): GateReport {
  if (submissionRing(files, rules) >= ring) return { gate: "rings", pass: true, details: `within task ${taskId}'s ring ${ring}` };
  const below = files.filter((f) => ringOf(f, rules) < ring);
  return {
    gate: "rings",
    pass: false,
    details: `task ${taskId} is scoped at ring ${ring} but the submission changes lower-ring files: ${below.slice(0, 20).join(", ")}${below.length > 20 ? ", ..." : ""}`,
  };
}

// Reports in the order rings, airlock, specSeparation, size. `repoDir` must be
// checked out at the submission's head commit (submodules included). Throws
// for an unknown submission or an unreadable repoDir: a harness error, never
// a verdict.
export function runStaticGates(state: CommonsState, submissionId: string, repoDir: string, opts: StaticGateOptions): GateReport[] {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`no submission ${submissionId}`);
  let rings = checkRingImports(repoDir, s.changedFiles, state.rules, opts.deleted === undefined ? {} : { deleted: opts.deleted });
  const taskRing = checkTaskRing(state, submissionId);
  if (taskRing !== null && !taskRing.pass) {
    rings = { gate: rings.gate, pass: false, details: rings.pass ? taskRing.details : `${taskRing.details}; ${rings.details}` };
  }
  return [
    rings,
    checkAirlock(s.changedFiles, state.rules, opts),
    checkSpecSeparation(state, submissionId, repoDir),
    checkSize(
      {
        linesChanged: s.linesChanged,
        files: s.changedFiles,
        ...(opts.binary === undefined ? {} : { binary: opts.binary }),
        ...(opts.bytesAdded === undefined ? {} : { bytesAdded: opts.bytesAdded }),
      },
      state.rules,
    ),
  ];
}
