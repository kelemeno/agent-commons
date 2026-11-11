// Spec separation: whoever wrote a task's spec (its acceptance tests) must not
// implement it, and the implementer must not edit those tests. Otherwise one
// owner both sets the bar and clears it, and the acceptance tests prove nothing.
//
// Owners, not agents, are compared: two agents of one owner are one party.

import type { CommonsState, GateReport } from "../types";
import { globToRegExp } from "../rules";
import { listProblems, normalizeRepoPath } from "./rings";

export const GATE = "specSeparation";

// An acceptance test path names a file exactly, a glob of files, or a
// directory whose whole contents are the tests.
export function isAcceptancePath(file: string, acceptancePath: string): boolean {
  const p = normalizeRepoPath(acceptancePath) ?? acceptancePath;
  if (file === p || file.startsWith(`${p}/`)) return true;
  try {
    return globToRegExp(p).test(file);
  } catch {
    return false;
  }
}

// Throws for an unknown submission: that is a caller error, not a verdict.
export function checkSpecSeparation(state: CommonsState, submissionId: string): GateReport {
  const s = state.submissions.get(submissionId);
  if (!s) throw new Error(`no submission ${submissionId}`);
  if (s.taskId === null) return { gate: GATE, pass: true, details: "no task: the submission implements no spec" };
  const task = state.tasks.get(s.taskId);
  if (!task) return { gate: GATE, pass: false, details: `task ${s.taskId} is not in the ledger` };
  const owner = state.agents.get(s.author)?.owner ?? state.ownerByKey.get(s.author);
  if (owner === undefined) return { gate: GATE, pass: false, details: `author ${s.author} has no registered owner` };

  const problems: string[] = [];
  if (owner === task.specAuthor) problems.push(`owner ${owner} wrote the spec of task ${task.id} and cannot implement it`);
  const touched: string[] = [];
  for (const raw of s.changedFiles) {
    const file = normalizeRepoPath(raw);
    if (file === null) problems.push(`${JSON.stringify(raw)} is not a path inside the repository`);
    else if (task.acceptanceTestPaths.some((p) => isAcceptancePath(file, p))) touched.push(file);
  }
  if (touched.length > 0) problems.push(`changes acceptance tests of task ${task.id}: ${touched.join(", ")}`);
  if (problems.length > 0) return { gate: GATE, pass: false, details: listProblems(problems) };
  return { gate: GATE, pass: true, details: `implementer ${owner} is not spec author ${task.specAuthor}; acceptance tests untouched` };
}
