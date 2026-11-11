// The size gate: a submission larger than rules.maxLinesPerSubmission cannot
// be reviewed properly in one sitting, so it is split before review.
//
// A line count alone is easy to dodge: git counts no lines for a file it
// thinks is binary (one NUL byte is enough, and a `-diff` attribute does the
// same to any file), empty files count nothing however many there are, and a
// minified file is one line. So when the caller knows more than the count it
// passes the whole change, and the gate also bounds
// - binary files: only known asset types may be binary; a binary `.ts` still
//   compiles but neither the count nor a reviewer's diff sees its content;
// - the number of files, at maxLinesPerSubmission (every file a reviewer must
//   at least open costs about a line);
// - added bytes, at BYTES_PER_LINE per allowed line.
// The bounds derive from maxLinesPerSubmission so the rules keep one knob.

import type { GateReport, Rules } from "../types";
import { listProblems, normalizeRepoPath } from "./rings";

export const GATE = "size";

export const BYTES_PER_LINE = 200;

// Formats a browser or bundler treats as data, never as code or text.
const ASSET = /\.(?:png|jpe?g|gif|webp|avif|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp3|mp4|m4a|ogg|oga|wav|webm|flac|pdf|zip|gz)$/i;

export type SizeChange = {
  linesChanged: number;
  files?: readonly string[]; // every changed file
  binary?: readonly string[]; // files git counts no lines for
  bytesAdded?: number; // total size of the added side of the diff
};

export function checkSize(change: number | SizeChange, rules: Rules): GateReport {
  const c: SizeChange = typeof change === "number" ? { linesChanged: change } : change;
  const max = rules.maxLinesPerSubmission;
  const { linesChanged } = c;
  if (!isCount(linesChanged)) {
    return { gate: GATE, pass: false, details: `linesChanged ${String(linesChanged)} is not a non-negative integer` };
  }
  const problems: string[] = [];
  if (linesChanged > max) problems.push(`${linesChanged} lines changed, limit ${max}: split the change`);
  if (c.files !== undefined && c.files.length > max) problems.push(`${c.files.length} files changed, limit ${max}: split the change`);
  const hidden = (c.binary ?? []).filter((f) => !ASSET.test(normalizeRepoPath(f) ?? f));
  if (hidden.length > 0) {
    problems.push(`git counts no lines for ${listProblems(hidden, ", ", 10)}: not a known binary asset type, so its content is neither counted nor reviewable`);
  }
  if (c.bytesAdded !== undefined) {
    const maxBytes = max * BYTES_PER_LINE;
    if (!isCount(c.bytesAdded)) problems.push(`bytesAdded ${String(c.bytesAdded)} is not a non-negative integer`);
    else if (c.bytesAdded > maxBytes) problems.push(`${c.bytesAdded} bytes added, limit ${maxBytes}: split the change`);
  }
  if (problems.length > 0) return { gate: GATE, pass: false, details: problems.join("; ") };
  return { gate: GATE, pass: true, details: `${linesChanged} lines changed, limit ${max}` };
}

function isCount(n: unknown): n is number {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= 0;
}
