// The airlock: lockfiles, package manifests and registry/toolchain config
// change what gets installed and run, so only the dependency track (a separate,
// slower review) may touch them. Paths are judged by their normalised form, so
// `x/../package.json` is the manifest it names.

import { globToRegExp } from "../rules";
import type { GateReport, Rules } from "../types";
import { listProblems, normalizeRepoPath } from "./rings";

export const GATE = "airlock";

export function isLocked(file: string, rules: Rules): boolean {
  return rules.lockedPaths.some((g) => globToRegExp(g).test(file));
}

// Fails if any changed file is a locked path (unless on the dependency track)
// or is not a usable repo path (always: the track does not excuse a path that
// cannot be classified).
export function checkAirlock(files: string[], rules: Rules, opts: { dependencyTrack: boolean }): GateReport {
  const invalid: string[] = [];
  const locked: string[] = [];
  for (const raw of files) {
    const file = normalizeRepoPath(raw);
    if (file === null) invalid.push(`${JSON.stringify(raw)} is not a path inside the repository`);
    else if (isLocked(file, rules)) locked.push(file);
  }
  if (invalid.length > 0) return { gate: GATE, pass: false, details: listProblems(invalid) };
  if (locked.length === 0) return { gate: GATE, pass: true, details: "no locked paths changed" };
  if (opts.dependencyTrack) {
    return { gate: GATE, pass: true, details: `dependency track: locked paths changed: ${listProblems(locked)}` };
  }
  return { gate: GATE, pass: false, details: `locked paths need the dependency track: ${listProblems(locked)}` };
}
