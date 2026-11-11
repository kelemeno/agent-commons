// The ring gate: classification of paths into capability rings, and the check
// that UI code (ring 2) does not reach into the kernel (ring 0).
//
// Paths: every path a gate sees is first normalised with path.posix.normalize.
// Ring and airlock globs are anchored, so `anthill-frontend/../anthill-backend/
// src/engine.ts` must be judged as the engine it names, not as UI. Paths that
// cannot name a file inside the repository (absolute, escaping with `..`,
// empty, NUL or backslash) classify as ring 0 and fail every gate that sees
// them: a gate never guesses what such a path means.
//
// What checkRingImports catches: relative import/export-from/require/dynamic
// import specifiers, Vite's import.meta.glob and `new URL(lit, import.meta.url)`
// (worker and asset references, which the bundler follows), string escapes in
// specifiers, comments between tokens, symlinks out of ring 2, and computed
// dynamic imports it cannot follow (those fail). What it does not: bare
// specifiers, including aliases configured in vite/tsconfig files (those
// files are ring 0, so adding an alias is itself a kernel change), and
// transitive imports through ring-1 modules. The scan reads the raw text
// without a JS parser, so it errs towards failing: a commented-out kernel
// import fails too, which a reviewer would also flag.

import * as fs from "node:fs";
import * as path from "node:path";
import { ringOf as ruleRingOf } from "../rules";
import type { GateReport, Ring, Rules } from "../types";

export const GATE = "rings";

// The one spelling of a repo-relative POSIX path, or null if `p` cannot name
// a file inside the repository.
export function normalizeRepoPath(p: string): string | null {
  if (typeof p !== "string" || p === "" || p.includes("\0") || p.includes("\\") || p.startsWith("/")) return null;
  let n = path.posix.normalize(p);
  while (n.length > 1 && n.endsWith("/")) n = n.slice(0, -1);
  if (n === "." || n === ".." || n.startsWith("../")) return null;
  return n;
}

// First matching rules.rings glob on the normalised path, else ring 1. An
// unusable path is ring 0: the most scrutiny for what cannot be classified.
export function ringOf(p: string, rules: Rules): Ring {
  const n = normalizeRepoPath(p);
  return n === null ? 0 : ruleRingOf(n, rules);
}

// The lowest ring touched. An empty change touches nothing and is ring 1, the
// same as an unclassified file.
export function submissionRing(files: string[], rules: Rules): Ring {
  if (files.length === 0) return 1;
  return Math.min(...files.map((f) => ringOf(f, rules))) as Ring;
}

const CODE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|html?)$/;
const RESOLVE_SUFFIXES = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", "/index.ts", "/index.tsx", "/index.js"];
const GLOB_WALK_LIMIT = 20_000;

// Reads the changed ring-2 files under `repoDir` (the checkout at the
// submission's head) and fails if any import resolves into ring 0, if a
// changed ring-2 file is a symlink out of ring 2, or if any changed path is
// unusable. Missing files are deletions and are skipped.
export function checkRingImports(repoDir: string, files: string[], rules: Rules): GateReport {
  const root = fs.realpathSync(repoDir);
  const problems: string[] = [];
  let scanned = 0;
  let missing = 0;
  for (const raw of files) {
    const file = normalizeRepoPath(raw);
    if (file === null) {
      problems.push(`${JSON.stringify(raw)} is not a path inside the repository`);
      continue;
    }
    if (ruleRingOf(file, rules) !== 2) continue;
    const abs = path.join(root, file);
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(abs);
    } catch {
      missing += 1;
      continue;
    }
    // realpath also catches a symlinked parent directory, not only a link file.
    const real = realLocation(root, abs, lst);
    if (real !== file && (real === null || ruleRingOf(real, rules) !== 2)) {
      problems.push(`${file} is a symlink to ${real ?? "a path outside the repository"}, outside ring 2`);
      continue;
    }
    let st: fs.Stats;
    try {
      st = fs.statSync(abs);
    } catch {
      continue; // a dangling link whose target is ring 2: nothing to read
    }
    if (!st.isFile() || !CODE_FILE.test(file)) continue;
    scanned += 1;
    const source = fs.readFileSync(abs, "utf8");
    const dirs = [...new Set([path.posix.dirname(file), path.posix.dirname(real ?? file)])];
    const lineOf = lineIndex(source);
    for (const ref of scanImports(source)) {
      const where = `${file}:${lineOf(ref.index)}`;
      if (ref.spec === null) {
        problems.push(`${where}: ${ref.how} with a computed specifier cannot be checked`);
        continue;
      }
      for (const dir of dirs) {
        const why = ref.how === "import.meta.glob" ? checkGlob(root, dir, ref.spec, rules) : checkSpecifier(root, dir, ref.spec, rules);
        if (why !== null) {
          problems.push(`${where}: ${ref.how} ${JSON.stringify(ref.spec)} ${why}`);
          break;
        }
      }
    }
  }
  if (problems.length > 0) return { gate: GATE, pass: false, details: listProblems(problems) };
  return {
    gate: GATE,
    pass: true,
    details: `no ring-2 file reaches ring 0 (${scanned} ring-2 code files scanned${missing > 0 ? `, ${missing} absent (deleted)` : ""})`,
  };
}

// Gate details end up in a ledger entry; a crafted file must not bloat it.
export function listProblems(problems: string[], sep = "; ", max = 20): string {
  const shown = problems.slice(0, max).join(sep);
  return problems.length > max ? `${shown}${sep}and ${problems.length - max} more` : shown;
}

// Repo-relative real location of an existing path, following every symlink
// on the way; for a dangling link, its target taken literally. null when the
// result lies outside the repository.
function realLocation(root: string, abs: string, lst: fs.Stats): string | null {
  let target: string;
  try {
    target = fs.realpathSync(abs);
  } catch {
    target = lst.isSymbolicLink() ? path.resolve(path.dirname(abs), fs.readlinkSync(abs)) : abs;
  }
  const rel = path.relative(root, target);
  if (rel === "" || rel === ".." || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) return null;
  return rel.split(path.sep).join("/");
}

// Why a specifier from a file in `dir` reaches ring 0, or null if it does not.
// Every resolution candidate is classified, existing or not (a submodule or
// a file absent from this checkout is still what the bundler would load), and
// each existing one also by where its symlinks really lead.
function checkSpecifier(root: string, dir: string, spec: string, rules: Rules): string | null {
  if (/^(?:\/|file:)/i.test(spec)) return "is absolute and cannot be checked";
  const bare = spec.replace(/[?#].*$/s, "");
  if (!/^\.\.?(?:\/|$)/.test(bare)) return null; // a package (or alias) import
  const lexical = normalizeRepoPath(path.posix.join(dir, bare));
  if (lexical === null) return "resolves outside the repository";
  const candidates = RESOLVE_SUFFIXES.map((s) => lexical + s);
  // TypeScript ESM style: `./engine.js` names engine.ts.
  const m = /\.([cm]?)js(x?)$/.exec(lexical);
  if (m) {
    const stem = lexical.slice(0, -m[0].length);
    candidates.push(`${stem}.${m[1] ?? ""}ts${m[2] ?? ""}`, `${stem}.ts`, `${stem}.tsx`);
  }
  for (const c of candidates) {
    if (ruleRingOf(c, rules) === 0) return `resolves to ring-0 ${c}`;
    const abs = path.join(root, c);
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(abs);
    } catch {
      continue;
    }
    const real = realLocation(root, abs, lst);
    if (real === null) return `resolves through a symlink outside the repository (${c})`;
    if (ruleRingOf(real, rules) === 0) return `resolves through a symlink to ring-0 ${real}`;
  }
  return null;
}

// import.meta.glob patterns: the static part of the pattern (before the first
// wildcard segment) must lie in ring 2, and nothing under it on disk may be
// ring 0 or a symlink out of ring 2. This over-approximates what the pattern
// matches, which is the safe direction.
function checkGlob(root: string, dir: string, pattern: string, rules: Rules): string | null {
  if (pattern.startsWith("!")) return null; // negations only exclude
  if (pattern.startsWith("/")) return "is absolute and cannot be checked";
  if (!/^\.\.?\//.test(pattern)) return null;
  const lexical = normalizeRepoPath(path.posix.join(dir, pattern));
  if (lexical === null) return "resolves outside the repository";
  const segments = lexical.split("/");
  const firstWild = segments.findIndex((s) => /[*?[\]{}()!+@]/.test(s));
  const prefix = (firstWild < 0 ? segments : segments.slice(0, firstWild)).join("/");
  if (prefix === "" || ruleRingOf(`${prefix}/__commons_probe__`, rules) !== 2) return `reaches outside ring 2 (${prefix || "."})`;
  const stack = [prefix];
  let seen = 0;
  while (stack.length > 0) {
    const rel = stack.pop() as string;
    if (++seen > GLOB_WALK_LIMIT) return `matches more than ${GLOB_WALK_LIMIT} paths and cannot be checked`;
    const abs = path.join(root, rel);
    let lst: fs.Stats;
    try {
      lst = fs.lstatSync(abs);
    } catch {
      continue;
    }
    // Directories are not classified: `anthill-frontend` the submodule
    // pointer is ring 0, the files under it are not.
    if (!lst.isDirectory() && ruleRingOf(rel, rules) === 0) return `can match ring-0 ${rel}`;
    if (lst.isSymbolicLink()) {
      const real = realLocation(root, abs, lst);
      if (real === null || ruleRingOf(real, rules) !== 2) return `can match ${rel}, a symlink outside ring 2`;
    } else if (lst.isDirectory()) {
      for (const name of fs.readdirSync(abs)) stack.push(`${rel}/${name}`);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Specifier scan
// ---------------------------------------------------------------------------

export type ImportRef = {
  how: "from" | "import" | "import()" | "require()" | "import.meta.glob" | "new URL()";
  spec: string | null; // null: a computed specifier
  index: number;
};

// Every module reference in `src`. Linear in the source length: comment
// skipping is memoised and searches the precomputed comment ends, so a file
// crafted with thousands of unterminated comments cannot stall the gate.
export function scanImports(src: string): ImportRef[] {
  const refs: ImportRef[] = [];
  const skip = skipper(src);
  // The index just past `tokens`, each preceded by optional whitespace and
  // comments, or null if they do not follow i. Word tokens must end there.
  const expect = (i: number, ...tokens: string[]): number | null => {
    let p = i;
    for (const t of tokens) {
      p = skip(p);
      if (!src.startsWith(t, p) || (/\w$/.test(t) && /[\w$]/.test(src[p + t.length] ?? ""))) return null;
      p += t.length;
    }
    return p;
  };
  // `( literal , ...` or `( literal )` after a call-like keyword ending at e;
  // any other argument is a computed specifier.
  const callArg = (e: number): string | null => {
    const open = expect(e, "(") as number;
    const lit = readLiteral(src, skip(open), true);
    if (lit === null || lit.value === null) return null;
    const after = src[skip(lit.end)];
    return after === "," || after === ")" ? lit.value : null;
  };
  // `x.import(` and `x.from "` are member names, not keywords; `module.require(` is a require.
  const word = /(?<![\w$])(?:from|import|new|require)(?![\w$])/g;
  for (let m = word.exec(src); m !== null; m = word.exec(src)) {
    const k = m.index;
    const e = k + m[0].length;
    if (m[0] !== "require" && afterDot(src, k)) continue;
    if (m[0] === "from") {
      const lit = readLiteral(src, skip(e), false);
      if (lit !== null) refs.push({ how: "from", spec: lit.value, index: k });
    } else if (m[0] === "require") {
      if (expect(e, "(") !== null) refs.push({ how: "require()", spec: callArg(e), index: k });
    } else if (m[0] === "import") {
      const j = skip(e);
      const glob = expect(e, ".", "meta", ".", "globEager") ?? expect(e, ".", "meta", ".", "glob");
      if (src[j] === '"' || src[j] === "'") {
        const lit = readLiteral(src, j, false);
        if (lit !== null) refs.push({ how: "import", spec: lit.value, index: k });
      } else if (src[j] === "(") {
        refs.push({ how: "import()", spec: callArg(e), index: k });
      } else if (glob !== null) {
        for (const spec of globArgs(src, skip, glob)) refs.push({ how: "import.meta.glob", spec, index: k });
      }
    } else {
      // new URL("lit", import.meta.url): Vite bundles the target.
      const open = expect(e, "URL", "(");
      if (open === null) continue;
      const lit = readLiteral(src, skip(open), true);
      if (lit === null || lit.value === null) continue;
      if (expect(lit.end, ",", "import", ".", "meta", ".", "url") !== null) refs.push({ how: "new URL()", spec: lit.value, index: k });
    }
  }
  return refs;
}

// import.meta.glob("p") or import.meta.glob(["p", "q"]); anything else is a
// pattern the gate cannot read, reported as one computed reference.
function globArgs(src: string, skip: (i: number) => number, e: number): (string | null)[] {
  const open = skip(e);
  if (src[open] !== "(") return [];
  let p = skip(open + 1);
  if (src[p] !== "[") {
    const lit = readLiteral(src, p, true);
    return [lit === null ? null : lit.value];
  }
  const out: (string | null)[] = [];
  p = skip(p + 1);
  while (src[p] !== "]") {
    const lit = readLiteral(src, p, true);
    if (lit === null || lit.value === null) return [null];
    out.push(lit.value);
    p = skip(lit.end);
    if (src[p] === ",") p = skip(p + 1);
    else if (src[p] !== "]") return [null];
  }
  return out;
}

// A string literal (or a template literal when allowed) starting at i: its
// cooked value (null for a template with `${`) and the index just past it.
function readLiteral(src: string, i: number, template: boolean): { value: string | null; end: number } | null {
  const q = src[i];
  if (q !== '"' && q !== "'" && !(template && q === "`")) return null;
  let j = i + 1;
  let interpolated = false;
  while (j < src.length) {
    const c = src[j];
    if (c === "\\") j += 2;
    else if (c === q) break;
    else if (q !== "`" && (c === "\n" || c === "\r")) return null;
    else {
      if (q === "`" && c === "$" && src[j + 1] === "{") interpolated = true;
      j += 1;
    }
  }
  if (j >= src.length) return null;
  return { value: interpolated ? null : unescape(src.slice(i + 1, j)), end: j + 1 };
}

// JS string escapes, so "\x2e\x2e/engine" is read as the "../engine" it is.
// An escape that is not valid JS yields null (treated as computed: fails).
function unescape(body: string): string | null {
  const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", "0": "\0" };
  try {
    return body.replace(/\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(\r\n|[\s\S]))/g, (_, cp, u4, x2, ch) => {
      const hex = (cp ?? u4 ?? x2) as string | undefined;
      if (hex !== undefined) return String.fromCodePoint(parseInt(hex, 16));
      const c = ch as string;
      if (c === "\n" || c === "\r" || c === "\r\n" || c === "\u2028" || c === "\u2029") return "";
      if (c === "u" || c === "x") throw new Error("bad escape");
      return simple[c] ?? c;
    });
  } catch {
    return null;
  }
}

// skip(i): the first index at or after i that is neither whitespace nor
// inside a comment.
function skipper(src: string): (i: number) => number {
  const closes: number[] = [];
  for (let i = src.indexOf("*/"); i >= 0; i = src.indexOf("*/", i + 1)) closes.push(i);
  const lineEnds: number[] = [];
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "\n" || c === "\r" || c === "\u2028" || c === "\u2029") lineEnds.push(i);
  }
  const memo = new Map<number, number>();
  return (start) => {
    // Every position passed through is memoised, so no stretch of whitespace
    // or comments is walked twice, however many keywords lead into it.
    const visited: number[] = [];
    let i = start;
    for (;;) {
      let known = memo.get(i);
      if (known === undefined) {
        visited.push(i);
        while (i < src.length && /\s/.test(src[i] as string)) i++;
        known = memo.get(i);
      }
      if (known !== undefined) {
        i = known;
        break;
      }
      visited.push(i);
      if (src.startsWith("/*", i)) {
        const c = firstAtLeast(closes, i + 2);
        i = c === undefined ? src.length : c + 2;
      } else if (src.startsWith("//", i)) {
        i = firstAtLeast(lineEnds, i) ?? src.length;
      } else break;
    }
    for (const v of visited) memo.set(v, i);
    return i;
  };
}

function afterDot(src: string, k: number): boolean {
  let i = k - 1;
  while (i >= 0 && /\s/.test(src[i] as string)) i--;
  return src[i] === ".";
}

// Index of the first element >= x in an ascending array (its length if none).
function lowerBound(sorted: number[], x: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if ((sorted[mid] as number) < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

function firstAtLeast(sorted: number[], x: number): number | undefined {
  return sorted[lowerBound(sorted, x)];
}

// 1-based line number of a source index.
function lineIndex(src: string): (index: number) => number {
  const newlines: number[] = [];
  for (let i = src.indexOf("\n"); i >= 0; i = src.indexOf("\n", i + 1)) newlines.push(i);
  return (index) => lowerBound(newlines, index) + 1;
}
