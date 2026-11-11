// The ring gate: classification of paths into capability rings, and the check
// that UI code (ring 2) does not reach into the kernel (ring 0).
//
// Paths: every path a gate sees is first normalised with path.posix.normalize.
// Ring and airlock globs are anchored, so `web/../server/src/auth.ts` must be
// judged as the auth module it names, not as UI. Paths that
// cannot name a file inside the repository (absolute, escaping with `..`,
// empty, NUL or backslash) classify as ring 0 and fail every gate that sees
// them: a gate never guesses what such a path means.
//
// What checkRingImports catches: relative import/export-from/require/dynamic
// import specifiers, Vite's import.meta.glob* (with type arguments and the
// options it can read) and `new URL(lit, import.meta.url)` (worker and asset
// references, which the bundler follows), string and identifier escapes,
// comments between tokens, kernel paths spelled in another letter case (a
// case-insensitive filesystem resolves them), symlinks out of ring 2, and
// computed references it cannot follow (those fail). What it does not: bare
// specifiers, including aliases configured in vite/tsconfig files (those
// files are ring 0, so adding an alias is itself a kernel change), and
// transitive imports through ring-1 modules. The scan reads the raw text
// without a JS parser, so it errs towards failing: a commented-out kernel
// import fails too, which a reviewer would also flag.

import * as fs from "node:fs";
import * as path from "node:path";
import { globToRegExp } from "../rules";
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

// First matching rules.rings glob on the normalised path, else ring 1, and
// never above the ring of a case-folded match (see classify). An unusable
// path is ring 0: the most scrutiny for what cannot be classified.
export function ringOf(p: string, rules: Rules): Ring {
  const n = normalizeRepoPath(p);
  return n === null ? 0 : classify(n, rules);
}

// The one ring classifier (ledger, gates, promotion, metrics and the CLI all
// use ringOf). Globs are compiled once per rings table, since a glob walk
// classifies thousands of paths. Rules come from ledger state and are never
// mutated in place, so the array is a sound cache key.
type RingTable = { exact: RegExp; folded: RegExp; ring: Ring }[];
const tables = new WeakMap<Rules["rings"], RingTable>();

function table(rules: Rules): RingTable {
  let t = tables.get(rules.rings);
  if (t === undefined) {
    t = rules.rings.map(({ glob, ring }) => {
      const exact = globToRegExp(glob);
      return { exact, folded: new RegExp(exact.source, `${exact.flags}i`), ring };
    });
    tables.set(rules.rings, t);
  }
  return t;
}

// The lower of the ring under the exact spelling and the ring under case
// folding. On a case-insensitive filesystem (macOS, Windows: operators',
// developers' and agents' checkouts, the harness's) `Src/offchain.ts` is
// src/offchain.ts: `git pull` writes it over the kernel file, and a fresh
// checkout keeps whichever sorts last. So a spelling is never a lower
// scrutiny than the file it can become.
function classify(n: string, rules: Rules): Ring {
  const t = table(rules);
  const exact = t.find((r) => r.exact.test(n))?.ring ?? 1;
  const folded = t.find((r) => r.folded.test(n))?.ring ?? 1;
  return Math.min(exact, folded) as Ring;
}

// Whether a path the bundler might load is kernel (case folding included, as
// everywhere: `src/Engine` is engine.ts on a case-insensitive filesystem).
function isKernel(n: string, rules: Rules): boolean {
  return classify(n, rules) === 0;
}

// The lowest ring touched. An empty change touches nothing and is ring 1, the
// same as an unclassified file.
export function submissionRing(files: string[], rules: Rules): Ring {
  if (files.length === 0) return 1;
  return Math.min(...files.map((f) => ringOf(f, rules))) as Ring;
}

export const CODE_FILE = /\.(?:[cm]?[jt]sx?|vue|svelte|html?)$/;
// Vite's default resolve.extensions (.mjs .js .mts .ts .jsx .tsx .json) and
// their index files, plus what TypeScript resolves.
export const RESOLVE_SUFFIXES = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs", ".cts", ".json"].flatMap((x) =>
  x === "" ? [""] : [x, `/index${x}`],
);
// Paths one gate run may lstat, over all files, specifiers and glob walks: a
// submission crafted to make the gate walk forever fails instead.
const PATH_BUDGET = 50_000;

export type RingImportOptions = {
  // Changed files the diff deletes (repo-relative). Only these may be absent
  // from the checkout: any other absent ring-2 file (an uninitialised
  // submodule, a sparse checkout) could not be read, so it fails.
  deleted?: Iterable<string>;
};

type Run = {
  root: string;
  rules: Rules;
  budget: number;
  globs: Map<string, string | null>; // walk result by prefix
  specs: Map<string, string | null>; // checkSpecifier result by dir + spec
};

class OverBudget extends Error {}

// Reads the changed ring-2 files under `repoDir` (the checkout at the
// submission's head) and fails if any import resolves into ring 0, if a
// changed ring-2 file is a symlink out of ring 2 or is absent without being
// deleted, or if any changed path is unusable.
export function checkRingImports(repoDir: string, files: string[], rules: Rules, opts: RingImportOptions = {}): GateReport {
  const run: Run = { root: fs.realpathSync(repoDir), rules, budget: PATH_BUDGET, globs: new Map(), specs: new Map() };
  const deleted = new Set<string>();
  for (const d of opts.deleted ?? []) {
    const n = normalizeRepoPath(d);
    if (n !== null) deleted.add(n);
  }
  const problems: string[] = [];
  let scanned = 0;
  let removed = 0;
  try {
    for (const raw of files) {
      const file = normalizeRepoPath(raw);
      if (file === null) {
        problems.push(`${JSON.stringify(raw)} is not a path inside the repository`);
        continue;
      }
      if (classify(file, rules) !== 2) continue;
      const r = checkChangedFile(run, file, deleted, problems);
      if (r === "scanned") scanned += 1;
      else if (r === "deleted") removed += 1;
    }
  } catch (e) {
    if (!(e instanceof OverBudget)) throw e;
    problems.push(`more than ${PATH_BUDGET} paths to check: the change cannot be checked`);
  }
  if (problems.length > 0) return { gate: GATE, pass: false, details: listProblems(problems) };
  return {
    gate: GATE,
    pass: true,
    details: `no ring-2 file reaches ring 0 (${scanned} ring-2 code files scanned${removed > 0 ? `, ${removed} deleted` : ""})`,
  };
}

function lstat(run: Run, abs: string): fs.Stats | null {
  if (--run.budget < 0) throw new OverBudget();
  try {
    return fs.lstatSync(abs);
  } catch {
    return null;
  }
}

function checkChangedFile(run: Run, file: string, deleted: Set<string>, problems: string[]): "scanned" | "deleted" | "skipped" {
  const { root, rules } = run;
  const abs = path.join(root, file);
  const lst = lstat(run, abs);
  if (lst === null) {
    if (deleted.has(file)) return "deleted";
    problems.push(`${file} is not present in the checkout and cannot be checked (uninitialised submodule?)`);
    return "skipped";
  }
  // realpath also catches a symlinked parent directory, not only a link file.
  const real = realLocation(root, abs, lst);
  if (real !== file && (real === null || classify(real, rules) !== 2)) {
    problems.push(`${file} is a symlink to ${real ?? "a path outside the repository"}, outside ring 2`);
    return "skipped";
  }
  let st: fs.Stats;
  try {
    st = fs.statSync(abs);
  } catch {
    return "skipped"; // a dangling link whose target is ring 2: nothing to read
  }
  if (!st.isFile() || !CODE_FILE.test(file)) return "skipped";
  const source = decodeIdentifierEscapes(fs.readFileSync(abs, "utf8"));
  const dirs = [...new Set([path.posix.dirname(file), path.posix.dirname(real ?? file)])];
  const lineOf = lineIndex(source);
  const refs = MARKUP_FILE.test(file) ? [...scanImports(source), ...scanMarkupRefs(source)] : scanImports(source);
  for (const ref of refs) {
    const where = `${file}:${lineOf(ref.index)}`;
    if (ref.spec === null) {
      problems.push(`${where}: ${ref.how} ${ref.reason ?? "with a computed specifier"} cannot be checked`);
      continue;
    }
    for (const dir of dirs) {
      const why = ref.how === "import.meta.glob" ? checkGlob(run, dir, ref.spec) : checkSpecifier(run, dir, ref.spec);
      if (why !== null) {
        problems.push(`${where}: ${ref.how} ${JSON.stringify(ref.spec)} ${why}`);
        break;
      }
    }
  }
  return "scanned";
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
// Every resolution candidate is classified, existing or not (a file absent
// from this checkout is still what the bundler would load), and each existing
// one also by where its symlinks really lead. `?` and `#` start a query in
// ESM and Vite but are path characters to CommonJS require(), so both
// readings are judged.
function checkSpecifier(run: Run, dir: string, spec: string): string | null {
  const key = `${dir}\0${spec}`;
  let why = run.specs.get(key);
  if (why === undefined) {
    why = resolveSpecifier(run, dir, spec);
    run.specs.set(key, why);
  }
  return why;
}

function resolveSpecifier(run: Run, dir: string, spec: string): string | null {
  const { root, rules } = run;
  if (/^(?:\/|file:)/i.test(spec)) return "is absolute and cannot be checked";
  const stripped = spec.replace(/[?#].*$/s, "");
  for (const reading of stripped === spec ? [spec] : [stripped, spec]) {
    if (!/^\.\.?(?:\/|$)/.test(reading)) continue; // a package (or alias) import
    const lexical = normalizeRepoPath(path.posix.join(dir, reading));
    if (lexical === null) return "resolves outside the repository";
    const candidates = RESOLVE_SUFFIXES.map((x) => lexical + x);
    // TypeScript ESM style: `./engine.js` names engine.ts.
    const m = /\.([cm]?)js(x?)$/.exec(lexical);
    if (m) {
      const stem = lexical.slice(0, -m[0].length);
      candidates.push(`${stem}.${m[1] ?? ""}ts${m[2] ?? ""}`, `${stem}.ts`, `${stem}.tsx`);
    }
    for (const c of candidates) {
      if (isKernel(c, rules)) return `resolves to ring-0 ${c}`;
      const abs = path.join(root, c);
      const lst = lstat(run, abs);
      if (lst === null) continue;
      const real = realLocation(root, abs, lst);
      if (real === null) return `resolves through a symlink outside the repository (${c})`;
      if (classify(real, rules) === 0) return `resolves through a symlink to ring-0 ${real}`;
    }
  }
  return null;
}

// import.meta.glob patterns: the static part of the pattern (before the first
// wildcard segment) must lie in ring 2, and nothing under it on disk may be
// ring 0 or a symlink out of ring 2. This over-approximates what the pattern
// matches, which is the safe direction. A pattern without wildcards names one
// file, judged like a specifier whether or not it exists here.
function checkGlob(run: Run, dir: string, pattern: string): string | null {
  const { rules } = run;
  if (pattern.startsWith("!")) return null; // negations only exclude
  if (pattern.startsWith("/")) return "is absolute and cannot be checked";
  if (!/^\.\.?\//.test(pattern)) return null;
  const lexical = normalizeRepoPath(path.posix.join(dir, pattern));
  if (lexical === null) return "resolves outside the repository";
  const segments = lexical.split("/");
  const firstWild = segments.findIndex((x) => /[*?[\]{}()!+@]/.test(x));
  if (firstWild < 0 && isKernel(lexical, rules)) return `names ring-0 ${lexical}`;
  const prefix = (firstWild < 0 ? segments : segments.slice(0, firstWild)).join("/");
  if (prefix === "" || classify(`${prefix}/__commons_probe__`, rules) !== 2) return `reaches outside ring 2 (${prefix || "."})`;
  let why = run.globs.get(prefix);
  if (why === undefined) {
    why = walk(run, prefix);
    run.globs.set(prefix, why);
  }
  return why;
}

function walk(run: Run, prefix: string): string | null {
  const { root, rules } = run;
  const stack = [prefix];
  while (stack.length > 0) {
    const rel = stack.pop() as string;
    const abs = path.join(root, rel);
    const lst = lstat(run, abs);
    if (lst === null) continue;
    // Directories are not classified: a glob naming a directory (say, a
    // submodule pointer) as ring 0 says nothing about the files under it.
    if (!lst.isDirectory() && classify(rel, rules) === 0) return `can match ring-0 ${rel}`;
    if (lst.isSymbolicLink()) {
      const real = realLocation(root, abs, lst);
      if (real === null || classify(real, rules) !== 2) return `can match ${rel}, a symlink outside ring 2`;
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
  how: "from" | "import" | "import()" | "require()" | "import.meta.glob" | "new URL()" | "<script src>" | "<link href>";
  spec: string | null; // null: a reference the gate cannot read
  reason?: string; // why spec is null, when it is not simply a computed specifier
  index: number; // into decodeIdentifierEscapes(src)
};

// `require(...)` is a require to every JS parser. Escapes that decode to
// an ASCII letter, `_` or `$` are replaced by that character everywhere: in
// an identifier that exposes the keyword, and inside a string, template or
// regex literal it means the same character either way. Escaped backslashes
// are consumed in pairs so `"\\u0072"` (a backslash, then u0072) is kept.
// Lines are unchanged, so line numbers agree with the original file.
export function decodeIdentifierEscapes(src: string): string {
  return src.replace(/\\\\|\\u(?:\{([0-9a-fA-F]{1,8})\}|([0-9a-fA-F]{4}))/g, (m, cp: string | undefined, u4: string | undefined) => {
    const hex = cp ?? u4;
    if (hex === undefined) return m;
    const code = parseInt(hex, 16);
    const c = code <= 0x7f ? String.fromCharCode(code) : "";
    return /^[A-Za-z_$]$/.test(c) ? c : m;
  });
}

// Files whose markup the bundler follows: Vite loads an HTML page's
// <script src> and <link href> (modulepreload, stylesheets), and a Vue or
// Svelte component's <script src>, like an import.
const MARKUP_FILE = /\.(?:html?|vue|svelte)$/;

// The src of every <script> and the href of every <link> in markup. A value
// in markup is relative to its file even without "./", so it is read as
// "./value"; a URL with a scheme (https:, data:) or "//host" is not a file of
// the repository and is skipped; a value the gate cannot read (an expression
// such as Svelte's {x}) is a reference that cannot be checked.
export function scanMarkupRefs(source: string): ImportRef[] {
  const refs: ImportRef[] = [];
  const tag = /<(script|link)\b([^>]*)>/gi;
  for (let m = tag.exec(source); m !== null; m = tag.exec(source)) {
    const how = (m[1] as string).toLowerCase() === "script" ? "<script src>" : "<link href>";
    const attr = how === "<script src>" ? "src" : "href";
    const a = new RegExp(`(?:^|\\s):?${attr}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>\`]+))`, "i").exec(m[2] as string);
    if (a === null) continue;
    const value = (a[1] ?? a[2] ?? a[3] ?? "").trim();
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(value) && !/^file:/i.test(value)) continue;
    const readable = value !== "" && !/[{}]/.test(value) && !(a[0] as string).trimStart().startsWith(":");
    refs.push({ how, spec: readable ? (/^(?:\.\.?\/|\/)/.test(value) ? value : `./${value}`) : null, index: m.index });
  }
  return refs;
}

// Every module reference in `src`. Linear in the source length: comment
// skipping is memoised and searches the precomputed comment ends, so a file
// crafted with thousands of unterminated comments cannot stall the gate.
export function scanImports(source: string): ImportRef[] {
  const src = decodeIdentifierEscapes(source);
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
  const globName = /glob[\w$]*/y;
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
      const meta = expect(e, ".", "meta", ".");
      if (src[j] === '"' || src[j] === "'") {
        const lit = readLiteral(src, j, false);
        if (lit !== null) refs.push({ how: "import", spec: lit.value, index: k });
      } else if (src[j] === "(") {
        refs.push({ how: "import()", spec: callArg(e), index: k });
      } else if (meta !== null) {
        // import.meta.glob, globEager, globEagerDefault, ...: every Vite variant.
        globName.lastIndex = skip(meta);
        if (globName.exec(src) === null) continue;
        const call = globCall(src, skip, globName.lastIndex);
        if (typeof call === "string") refs.push({ how: "import.meta.glob", spec: null, reason: call, index: k });
        else for (const spec of call) refs.push({ how: "import.meta.glob", spec, index: k });
      }
    } else {
      // new URL("lit", import.meta.url): Vite bundles the target, and turns an
      // interpolated template into a glob it cannot be checked against.
      const open = expect(e, "URL", "(");
      if (open === null) continue;
      const lit = readLiteral(src, skip(open), true);
      if (lit === null) continue;
      if (expect(lit.end, ",", "import", ".", "meta", ".", "url") !== null) refs.push({ how: "new URL()", spec: lit.value, index: k });
    }
  }
  return refs;
}

// Options of import.meta.glob the gate understands. Anything else, `base`
// above all (it re-roots relative patterns), makes the call unreadable.
const GLOB_OPTIONS = new Set(["eager", "import", "query", "as", "exhaustive"]);

// The patterns of `import.meta.glob<T>(pattern | [patterns], options?)` whose
// name ends at e, or why the call cannot be read.
function globCall(src: string, skip: (i: number) => number, e: number): (string | null)[] | string {
  let p = skip(e);
  if (src[p] === "<") {
    const q = skipTypeArgs(src, p);
    if (q === null) return "with type arguments the gate cannot read";
    p = skip(q);
  }
  if (src[p] !== "(") return "used other than as a call";
  p = skip(p + 1);
  const out: (string | null)[] = [];
  if (src[p] === "[") {
    p = skip(p + 1);
    while (src[p] !== "]") {
      const lit = readLiteral(src, p, true);
      if (lit === null || lit.value === null) return "with a computed pattern";
      out.push(lit.value);
      p = skip(lit.end);
      if (src[p] === ",") p = skip(p + 1);
      else if (src[p] !== "]") return "with a computed pattern";
    }
    p = skip(p + 1);
  } else {
    const lit = readLiteral(src, p, true);
    if (lit === null || lit.value === null) return "with a computed pattern";
    out.push(lit.value);
    p = skip(lit.end);
  }
  if (src[p] === ",") {
    p = skip(p + 1);
    if (src[p] !== ")") {
      const q = readObject(src, skip, p, GLOB_OPTIONS);
      if (q === null) return "with options other than eager/import/query/as/exhaustive literals";
      p = skip(q);
      if (src[p] === ",") p = skip(p + 1);
    }
  }
  if (src[p] !== ")") return "with arguments the gate cannot read";
  return out;
}

// An object literal at p whose keys are in `keys` (any key when null, which
// also forbids nesting) and whose values are string or boolean literals, or a
// nested object for `query`. Returns the index past `}`, or null.
function readObject(src: string, skip: (i: number) => number, p: number, keys: Set<string> | null): number | null {
  if (src[p] !== "{") return null;
  p = skip(p + 1);
  while (src[p] !== "}") {
    let key: string | null;
    const lit = readLiteral(src, p, false);
    if (lit !== null) {
      key = lit.value;
      p = lit.end;
    } else {
      const id = /[A-Za-z_$][\w$]*/y;
      id.lastIndex = p;
      key = id.exec(src)?.[0] ?? null;
      p = id.lastIndex;
    }
    if (key === null || (keys !== null && !keys.has(key))) return null;
    p = skip(p);
    if (src[p] !== ":") return null;
    p = skip(p + 1);
    const value = readLiteral(src, p, true);
    const bool = /(?:true|false)(?![\w$])/y;
    bool.lastIndex = p;
    if (value !== null) {
      if (value.value === null) return null;
      p = value.end;
    } else if (bool.exec(src) !== null) {
      p = bool.lastIndex;
    } else if (keys !== null && key === "query" && src[p] === "{") {
      const q = readObject(src, skip, p, null);
      if (q === null) return null;
      p = q;
    } else return null;
    p = skip(p);
    if (src[p] === ",") p = skip(p + 1);
    else if (src[p] !== "}") return null;
  }
  return p + 1;
}

// The index past a balanced `<...>` type argument list at p, or null. `=>`
// inside (function types) does not close a bracket; strings are skipped.
// Bounded, so an unclosed `<` costs little.
function skipTypeArgs(src: string, p: number): number | null {
  let depth = 0;
  for (let i = p; i < src.length && i < p + 2048; i++) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      const lit = readLiteral(src, i, true);
      if (lit === null) return null;
      i = lit.end - 1;
    } else if (c === "<") depth++;
    else if (c === ">" && src[i - 1] !== "=") {
      if (--depth === 0) return i + 1;
    }
  }
  return null;
}

// A string literal (or a template literal when allowed) starting at i: its
// cooked value (null for a template with `${` or an invalid escape) and the
// index just past it.
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
// An escape that is not valid in strict code yields null (treated as
// computed: fails): legacy octal `\56` and `\8` mean "." and "8" to sloppy
// scripts and CommonJS, and the gate does not guess which one a file is.
function unescape(body: string): string | null {
  const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", v: "\v", "0": "\0" };
  try {
    return body.replace(
      /\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|(\r\n|[\s\S]))/g,
      (m: string, cp: string | undefined, u4: string | undefined, x2: string | undefined, ch: string | undefined, at: number) => {
        const hex = cp ?? u4 ?? x2;
        if (hex !== undefined) return String.fromCodePoint(parseInt(hex, 16));
        const c = ch as string;
        if (c === "\n" || c === "\r" || c === "\r\n" || c === " " || c === " ") return "";
        if (c === "u" || c === "x" || /[1-9]/.test(c) || (c === "0" && /[0-9]/.test(body[at + m.length] ?? ""))) {
          throw new Error("bad escape");
        }
        return simple[c] ?? c;
      },
    );
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

// Whether the word at k follows a member-access dot. A spread `...import(x)`
// is not one: the import is real.
function afterDot(src: string, k: number): boolean {
  let i = k - 1;
  while (i >= 0 && /\s/.test(src[i] as string)) i--;
  return src[i] === "." && src[i - 1] !== ".";
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
