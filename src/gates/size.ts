// The size gate: a submission larger than rules.maxLinesPerSubmission cannot
// be reviewed properly in one sitting, so it is split before review.

import type { GateReport, Rules } from "../types";

export const GATE = "size";

export function checkSize(linesChanged: number, rules: Rules): GateReport {
  const max = rules.maxLinesPerSubmission;
  if (!Number.isSafeInteger(linesChanged) || linesChanged < 0) {
    return { gate: GATE, pass: false, details: `linesChanged ${String(linesChanged)} is not a non-negative integer` };
  }
  const pass = linesChanged <= max;
  return { gate: GATE, pass, details: `${linesChanged} lines changed, limit ${max}${pass ? "" : ": split the change"}` };
}
