// The GitHub bridge: the only module that talks to GitHub. Code reaches the
// project repo through here and nowhere else: participants submit a unified
// diff, and the coordinator bot turns it into a branch `commons/<submissionId>`
// and a pull request with its own token. Participants' credentials never touch
// the repo.
//
// REST only (api.github.com v3); GraphQL is not available to the bot. Every
// request goes through the injected fetch, so tests run without a network.
//
// The token is a secret held by the coordinator process. It is sent only in the
// Authorization header to `apiBase`, never logged, and scrubbed from every error
// message. Pagination therefore never follows URLs from Link headers: it builds
// page URLs itself, so a response cannot redirect the token to another host.
//
// The patch applier is deliberately strict. A patch applies byte-exactly at the
// line numbers its hunk headers state or not at all: no fuzz, no offsets, no
// whitespace leniency. What lands in the PR is exactly what reviewers read in
// the submitted diff, and anything the applier cannot represent exactly
// (binary files, symlinks, submodules, quoted paths) is refused rather than
// approximated.

export const TOKEN_ENV = "COMMONS_GITHUB_TOKEN";
export const DEFAULT_API_BASE = "https://api.github.com";

// The subset of global fetch the bridge uses. Global fetch satisfies it.
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

export type GitHubOptions = {
  token?: string; // default: process.env.COMMONS_GITHUB_TOKEN
  fetch?: FetchLike; // default: global fetch
  apiBase?: string; // default: https://api.github.com
  log?: (line: string) => void; // one line per request: method, path, status. Never the token.
};

// status is the HTTP status, or 0 when no HTTP status applies (no token,
// network failure, a response that is not the shape GitHub documents).
export class GitHubError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "GitHubError";
    this.status = status;
  }
}

// A patch the strict applier refuses. Never retried with leniency.
export class PatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PatchError";
  }
}

export type OpenPullRequestArgs = {
  owner: string;
  repo: string;
  baseBranch: string;
  submissionId: string;
  patch: string; // `git diff` output (git format, a/ and b/ prefixes) against the base commit
  title: string;
  body: string;
  // The commit the patch was made against. Defaults to the current head of
  // baseBranch. Pass the submission's baseCommit so the branch is the author's
  // change on the author's base, even if baseBranch moved since.
  baseCommit?: string;
};

export type OpenedPullRequest = {
  number: number;
  url: string;
  branch: string; // commons/<submissionId>
  baseSha: string;
  headSha: string; // the commit the bot created; the submission's headCommit
  files: string[]; // every path the patch writes or deletes, sorted
};

export type ChangedFile = {
  path: string;
  status: string; // added | removed | modified | renamed | copied | changed | unchanged
  additions: number;
  deletions: number;
  // Set for renames. The old path is changed too (it disappears), so ring and
  // airlock checks must look at it as well as at `path`.
  previousPath?: string;
};

export type GitHub = {
  openPullRequest(args: OpenPullRequestArgs): Promise<OpenedPullRequest>;
  listChangedFiles(owner: string, repo: string, prNumber: number): Promise<ChangedFile[]>;
  mergePullRequest(
    owner: string,
    repo: string,
    prNumber: number,
    sha: string,
    message?: { title?: string; body?: string },
  ): Promise<{ sha: string }>;
  fastForward(owner: string, repo: string, branch: string, sha: string): Promise<{ sha: string }>;
  commentOnPullRequest(owner: string, repo: string, prNumber: number, body: string): Promise<{ id: number; url: string }>;
};

export function createGitHub(opts: GitHubOptions = {}): GitHub {
  const token = opts.token ?? process.env[TOKEN_ENV] ?? "";
  const doFetch: FetchLike = opts.fetch ?? (globalThis.fetch as FetchLike);
  const apiBase = (opts.apiBase ?? DEFAULT_API_BASE).replace(/\/+$/, "");
  const redact = (s: string): string => (token === "" ? s : s.split(token).join("[redacted]"));
  const log = (line: string): void => opts.log?.(redact(line));

  type Reply = { status: number; data: unknown; link: string | null };

  async function request(method: string, path: string, body?: unknown): Promise<Reply> {
    if (token === "") throw new GitHubError(0, `no GitHub token: set ${TOKEN_ENV} or pass options.token`);
    const headers: Record<string, string> = {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${token}`,
      "User-Agent": "anthill-commons",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    const init: { method: string; headers: Record<string, string>; body?: string } = { method, headers };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    let res: Awaited<ReturnType<FetchLike>>;
    let text: string;
    try {
      res = await doFetch(apiBase + path, init);
      text = await res.text();
    } catch (e) {
      // Only the message: an error object from the fetch layer may carry the request.
      const msg = e instanceof Error ? e.message : String(e);
      log(`${method} ${path} network error`);
      throw new GitHubError(0, redact(`${method} ${path}: network error: ${msg}`));
    }
    log(`${method} ${path} ${res.status}`);
    let data: unknown = null;
    let parsed = true;
    if (text !== "") {
      try {
        data = JSON.parse(text);
      } catch {
        parsed = false;
      }
    }
    if (res.status < 200 || res.status > 299) {
      throw new GitHubError(res.status, redact(`${method} ${path} -> ${res.status}: ${errorText(data, text, parsed)}`));
    }
    if (!parsed) throw new GitHubError(res.status, redact(`${method} ${path}: response is not JSON`));
    return { status: res.status, data, link: res.headers.get("link") };
  }

  const repoPath = (owner: string, repo: string): string => {
    if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo) || owner.startsWith(".") || repo.startsWith(".")) {
      throw new GitHubError(0, `invalid repository ${JSON.stringify(owner)}/${JSON.stringify(repo)}`);
    }
    return `/repos/${owner}/${repo}`;
  };

  async function openPullRequest(args: OpenPullRequestArgs): Promise<OpenedPullRequest> {
    const rp = repoPath(args.owner, args.repo);
    checkBranch(args.baseBranch);
    checkSubmissionId(args.submissionId);
    if (args.baseCommit !== undefined) checkSha(args.baseCommit);
    const branch = `commons/${args.submissionId}`;
    // Parse before any request: a refused patch costs no API calls.
    const patches = parsePatch(args.patch);

    let baseSha = args.baseCommit;
    if (baseSha === undefined) {
      const ref = await request("GET", `${rp}/git/ref/heads/${refUrl(args.baseBranch)}`);
      const object = get(ref.data, "object");
      if (get(object, "type") !== "commit") throw shape(`ref heads/${args.baseBranch} does not point at a commit`);
      baseSha = getString(object, "sha");
    }
    const baseCommit = await request("GET", `${rp}/git/commits/${baseSha}`);
    const baseTree = getString(get(baseCommit.data, "tree"), "sha");

    const trees = new Map<string, TreeItem[]>();
    async function readTree(sha: string): Promise<TreeItem[]> {
      const cached = trees.get(sha);
      if (cached) return cached;
      const r = await request("GET", `${rp}/git/trees/${sha}`);
      if (get(r.data, "truncated") === true) throw shape(`tree ${sha} listing is truncated`);
      const raw = get(r.data, "tree");
      if (!Array.isArray(raw)) throw shape(`tree ${sha} has no entries array`);
      const items = raw.map((e) => ({
        path: getString(e, "path"),
        mode: getString(e, "mode"),
        type: getString(e, "type"),
        sha: getString(e, "sha"),
      }));
      trees.set(sha, items);
      return items;
    }
    // The base tree entry at `path`, or null if nothing is there. Walks one
    // directory listing per level, so large repos never hit the truncation of
    // recursive listings.
    async function lookup(path: string): Promise<TreeItem | null> {
      const segments = path.split("/");
      let tree = baseTree;
      for (let i = 0; i < segments.length; i++) {
        const entry = (await readTree(tree)).find((e) => e.path === segments[i]);
        if (!entry) return null;
        if (i === segments.length - 1) return entry;
        if (entry.type !== "tree") throw new PatchError(`${path}: ${segments.slice(0, i + 1).join("/")} is not a directory`);
        tree = entry.sha;
      }
      return null;
    }
    // A regular file in the base tree, with its text. Anything else is refused.
    async function existing(path: string): Promise<{ mode: string; sha: string; text: string }> {
      const entry = await lookup(path);
      if (!entry) throw new PatchError(`${path}: does not exist at the base commit`);
      if (entry.type !== "blob") throw new PatchError(`${path}: is a ${entry.type}, not a file`);
      if (entry.mode === "120000") throw new PatchError(`${path}: is a symlink; symlinks are not supported`);
      if (!FILE_MODES.has(entry.mode)) throw new PatchError(`${path}: unsupported mode ${entry.mode}`);
      const blob = await request("GET", `${rp}/git/blobs/${entry.sha}`);
      const content = getString(blob.data, "content");
      const encoding = getString(blob.data, "encoding");
      const bytes = encoding === "base64" ? Buffer.from(content, "base64") : Buffer.from(content, "utf8");
      if (bytes.includes(0)) throw new PatchError(`${path}: is a binary file`);
      const text = bytes.toString("utf8");
      if (!Buffer.from(text, "utf8").equals(bytes)) throw new PatchError(`${path}: is not valid UTF-8`);
      return { mode: entry.mode, sha: entry.sha, text };
    }
    async function absent(path: string): Promise<void> {
      if ((await lookup(path)) !== null) throw new PatchError(`${path}: already exists at the base commit`);
    }
    async function blob(text: string): Promise<string> {
      const r = await request("POST", `${rp}/git/blobs`, {
        content: Buffer.from(text, "utf8").toString("base64"),
        encoding: "base64",
      });
      return getString(r.data, "sha");
    }

    const entries: { path: string; mode: string; type: "blob"; sha: string | null }[] = [];
    for (const p of patches) {
      if (p.kind === "add") {
        await absent(p.newPath);
        const text = p.hunks.length > 0 ? applyHunks("", p.hunks, p.newPath) : "";
        entries.push({ path: p.newPath, mode: p.newMode, type: "blob", sha: await blob(text) });
      } else if (p.kind === "delete") {
        const old = await existing(p.oldPath);
        checkMode(p.oldPath, old.mode, p.oldMode);
        const rest = p.hunks.length > 0 ? applyHunks(old.text, p.hunks, p.oldPath) : old.text;
        if (rest !== "") throw new PatchError(`${p.oldPath}: deletion does not remove the whole file`);
        entries.push({ path: p.oldPath, mode: old.mode, type: "blob", sha: null });
      } else {
        const old = await existing(p.oldPath);
        checkMode(p.oldPath, old.mode, p.oldMode);
        if (p.kind !== "modify") await absent(p.newPath);
        const mode = p.newMode ?? old.mode;
        const sha = p.hunks.length > 0 ? await blob(applyHunks(old.text, p.hunks, p.oldPath)) : old.sha;
        if (p.kind === "rename") entries.push({ path: p.oldPath, mode: old.mode, type: "blob", sha: null });
        entries.push({ path: p.newPath, mode, type: "blob", sha });
      }
    }

    const tree = await request("POST", `${rp}/git/trees`, { base_tree: baseTree, tree: entries });
    const treeSha = getString(tree.data, "sha");
    if (treeSha === baseTree) throw new PatchError("patch changes nothing");
    const commit = await request("POST", `${rp}/git/commits`, {
      message: `${args.title}\n\nCommons-Submission: ${args.submissionId}\n`,
      tree: treeSha,
      parents: [baseSha],
    });
    const headSha = getString(commit.data, "sha");
    await request("POST", `${rp}/git/refs`, { ref: `refs/heads/${branch}`, sha: headSha });
    let pr: Reply;
    try {
      pr = await request("POST", `${rp}/pulls`, { title: args.title, head: branch, base: args.baseBranch, body: args.body });
    } catch (e) {
      // Leave no orphan branch behind: it would block a retry with the same id.
      await request("DELETE", `${rp}/git/refs/heads/${refUrl(branch)}`).catch(() => undefined);
      throw e;
    }
    return {
      number: getNumber(pr.data, "number"),
      url: getString(pr.data, "html_url"),
      branch,
      baseSha,
      headSha,
      files: [...new Set(entries.map((e) => e.path))].sort(),
    };
  }

  async function listChangedFiles(owner: string, repo: string, prNumber: number): Promise<ChangedFile[]> {
    const rp = repoPath(owner, repo);
    checkPrNumber(prNumber);
    const files: ChangedFile[] = [];
    for (let page = 1; ; page++) {
      if (page > MAX_PAGES) throw new GitHubError(0, `pull ${prNumber}: more than ${MAX_PAGES} pages of files`);
      const r = await request("GET", `${rp}/pulls/${prNumber}/files?per_page=${PER_PAGE}&page=${page}`);
      if (!Array.isArray(r.data)) throw shape(`pull ${prNumber} files page ${page} is not an array`);
      for (const f of r.data) {
        const file: ChangedFile = {
          path: getString(f, "filename"),
          status: getString(f, "status"),
          additions: getNumber(f, "additions"),
          deletions: getNumber(f, "deletions"),
        };
        const previous = get(f, "previous_filename");
        if (typeof previous === "string") file.previousPath = previous;
        files.push(file);
      }
      if (!hasNextPage(r.link)) break;
    }
    // GitHub silently stops listing at 3000 files. An incomplete list would let
    // a change hide files from ring and airlock checks, so compare against the
    // count GitHub reports for the PR and refuse any mismatch.
    const pr = await request("GET", `${rp}/pulls/${prNumber}`);
    const expected = getNumber(pr.data, "changed_files");
    if (expected !== files.length) {
      throw new GitHubError(0, `pull ${prNumber}: listed ${files.length} files but GitHub reports ${expected}`);
    }
    return files;
  }

  async function mergePullRequest(
    owner: string,
    repo: string,
    prNumber: number,
    sha: string,
    message: { title?: string; body?: string } = {},
  ): Promise<{ sha: string }> {
    const rp = repoPath(owner, repo);
    checkPrNumber(prNumber);
    // The sha guard is mandatory: GitHub merges only if the PR head is exactly
    // the commit that passed gates and review (409 otherwise), so a push after
    // review can never ride along.
    checkSha(sha);
    const body: Record<string, string> = { sha, merge_method: "squash" };
    if (message.title !== undefined) body.commit_title = message.title;
    if (message.body !== undefined) body.commit_message = message.body;
    const r = await request("PUT", `${rp}/pulls/${prNumber}/merge`, body);
    if (get(r.data, "merged") !== true) {
      const why = get(r.data, "message");
      throw new GitHubError(r.status, redact(`pull ${prNumber} not merged: ${typeof why === "string" ? why : "no reason given"}`));
    }
    return { sha: getString(r.data, "sha") };
  }

  async function fastForward(owner: string, repo: string, branch: string, sha: string): Promise<{ sha: string }> {
    const rp = repoPath(owner, repo);
    checkBranch(branch);
    checkSha(sha);
    // force: false makes GitHub refuse (422) anything that is not a fast-forward.
    const r = await request("PATCH", `${rp}/git/refs/heads/${refUrl(branch)}`, { sha, force: false });
    const now = getString(get(r.data, "object"), "sha");
    if (now !== sha) throw new GitHubError(r.status, `heads/${branch} is at ${now}, expected ${sha}`);
    return { sha: now };
  }

  async function commentOnPullRequest(
    owner: string,
    repo: string,
    prNumber: number,
    body: string,
  ): Promise<{ id: number; url: string }> {
    const rp = repoPath(owner, repo);
    checkPrNumber(prNumber);
    // PR conversation comments are issue comments in the REST API.
    const r = await request("POST", `${rp}/issues/${prNumber}/comments`, { body });
    return { id: getNumber(r.data, "id"), url: getString(r.data, "html_url") };
  }

  return { openPullRequest, listChangedFiles, mergePullRequest, fastForward, commentOnPullRequest };
}

// One-shot forms of the client methods, for callers that do not keep a client.
export function openPullRequest(args: OpenPullRequestArgs, opts?: GitHubOptions): Promise<OpenedPullRequest> {
  return createGitHub(opts).openPullRequest(args);
}
export function listChangedFiles(owner: string, repo: string, prNumber: number, opts?: GitHubOptions): Promise<ChangedFile[]> {
  return createGitHub(opts).listChangedFiles(owner, repo, prNumber);
}
export function mergePullRequest(
  owner: string,
  repo: string,
  prNumber: number,
  sha: string,
  opts?: GitHubOptions,
): Promise<{ sha: string }> {
  return createGitHub(opts).mergePullRequest(owner, repo, prNumber, sha);
}
export function fastForward(owner: string, repo: string, branch: string, sha: string, opts?: GitHubOptions): Promise<{ sha: string }> {
  return createGitHub(opts).fastForward(owner, repo, branch, sha);
}
export function commentOnPullRequest(
  owner: string,
  repo: string,
  prNumber: number,
  body: string,
  opts?: GitHubOptions,
): Promise<{ id: number; url: string }> {
  return createGitHub(opts).commentOnPullRequest(owner, repo, prNumber, body);
}

// ---------------------------------------------------------------------------
// Patch parsing and application. Pure.
// ---------------------------------------------------------------------------

// One file section of a git-format patch. Paths are validated repo paths.
export type FilePatch =
  | { kind: "add"; newPath: string; newMode: string; hunks: string[] }
  | { kind: "delete"; oldPath: string; oldMode: string; hunks: string[] }
  | { kind: "modify" | "rename" | "copy"; oldPath: string; newPath: string; oldMode?: string; newMode?: string; hunks: string[] };

const FILE_MODES = new Set(["100644", "100755"]);

// Parse `git diff` output into file sections. Strict: every section starts with
// `diff --git a/<p> b/<p>`, only the extended headers git emits for text files
// are accepted, and every path is checked by checkRepoPath. Hunk bodies are
// validated when applied (applyHunks), not here.
export function parsePatch(patch: string): FilePatch[] {
  if (patch === "") throw new PatchError("empty patch");
  const lines = (patch.endsWith("\n") ? patch.slice(0, -1) : patch).split("\n");
  if (!lines[0]?.startsWith("diff --git ")) throw new PatchError("patch must start with a `diff --git` line");
  const starts: number[] = [];
  lines.forEach((l, i) => {
    if (l.startsWith("diff --git ")) starts.push(i);
  });
  const result: FilePatch[] = [];
  const touched = new Set<string>();
  const touch = (path: string): void => {
    if (touched.has(path)) throw new PatchError(`${path}: appears more than once in the patch`);
    touched.add(path);
  };
  for (let s = 0; s < starts.length; s++) {
    const section = lines.slice(starts[s], starts[s + 1] ?? lines.length);
    const p = parseSection(section);
    if (p.kind === "add") touch(p.newPath);
    else if (p.kind === "delete") touch(p.oldPath);
    else {
      touch(p.newPath);
      if (p.kind === "rename") touch(p.oldPath);
    }
    result.push(p);
  }
  return result;
}

function parseSection(section: string[]): FilePatch {
  const header = section[0] ?? "";
  const h: Record<string, string> = {};
  let i = 1;
  for (; i < section.length; i++) {
    const line = section[i] ?? "";
    if (line.startsWith("--- ") || line.startsWith("@@")) break;
    if (line === "GIT binary patch" || line.startsWith("Binary files ")) {
      throw new PatchError(`${header}: binary patches are not supported`);
    }
    const m = /^(old mode|new mode|deleted file mode|new file mode|index|similarity index|dissimilarity index|rename from|rename to|copy from|copy to) (.+)$/.exec(line);
    if (!m) throw new PatchError(`${header}: unsupported header line ${JSON.stringify(line)}`);
    const key = m[1] as string;
    if (key in h) throw new PatchError(`${header}: duplicate header ${key}`);
    h[key] = m[2] as string;
  }
  for (const key of ["old mode", "new mode", "deleted file mode", "new file mode"]) {
    const mode = h[key];
    if (mode !== undefined) checkModeValue(header, mode);
  }
  let indexMode: string | undefined;
  if (h.index !== undefined) {
    const m = /^[0-9a-f]+\.\.[0-9a-f]+(?: (\d+))?$/.exec(h.index);
    if (!m) throw new PatchError(`${header}: malformed index line`);
    indexMode = m[1];
    if (indexMode !== undefined) checkModeValue(header, indexMode);
  }

  let minus: string | null | undefined; // undefined: no ---/+++ lines; null: /dev/null
  let plus: string | null | undefined;
  if (section[i]?.startsWith("--- ")) {
    minus = diffName(section[i] as string, "--- ", "a/", header);
    const next = section[i + 1];
    if (next === undefined || !next.startsWith("+++ ")) throw new PatchError(`${header}: --- line without +++ line`);
    plus = diffName(next, "+++ ", "b/", header);
    i += 2;
  }
  const hunks = section.slice(i);
  if (minus === undefined && hunks.length > 0) throw new PatchError(`${header}: hunks without ---/+++ lines`);
  if (minus !== undefined && hunks.length === 0) throw new PatchError(`${header}: ---/+++ lines without hunks`);
  if (minus === null && plus === null) throw new PatchError(`${header}: both sides are /dev/null`);

  const isNew = h["new file mode"] !== undefined;
  const isDeleted = h["deleted file mode"] !== undefined;
  const renamed = h["rename from"] !== undefined || h["rename to"] !== undefined;
  const copied = h["copy from"] !== undefined || h["copy to"] !== undefined;
  if ([isNew, isDeleted, renamed, copied].filter(Boolean).length > 1) {
    throw new PatchError(`${header}: contradictory headers`);
  }
  if ((isNew || isDeleted) && (h["old mode"] !== undefined || h["new mode"] !== undefined)) {
    throw new PatchError(`${header}: mode change on an added or deleted file`);
  }

  let a: string;
  let b: string;
  if (renamed || copied) {
    const from = renamed ? h["rename from"] : h["copy from"];
    const to = renamed ? h["rename to"] : h["copy to"];
    if (from === undefined || to === undefined) throw new PatchError(`${header}: incomplete rename/copy headers`);
    a = from;
    b = to;
  } else if (minus !== undefined) {
    a = minus ?? (plus as string);
    b = plus ?? (minus as string);
  } else {
    // No file headers (mode change only, or an empty file added or deleted):
    // the header is `diff --git a/P b/P` with the same P twice.
    const rest = header.slice("diff --git ".length);
    const half = (rest.length - 1) / 2;
    const p = rest.slice(2, half);
    if (!Number.isInteger(half) || rest !== `a/${p} b/${p}`) throw new PatchError(`${header}: cannot parse paths`);
    a = p;
    b = p;
  }
  if (header !== `diff --git a/${a} b/${b}`) throw new PatchError(`${header}: header does not match the file names`);
  if (minus !== undefined) {
    if (isNew ? minus !== null : minus !== a) throw new PatchError(`${header}: --- line does not match`);
    if (isDeleted ? plus !== null : plus !== b) throw new PatchError(`${header}: +++ line does not match`);
  }
  checkRepoPath(a);
  checkRepoPath(b);

  if (isNew) {
    const newMode = h["new file mode"] as string;
    if (indexMode !== undefined && indexMode !== newMode) throw new PatchError(`${header}: index mode disagrees`);
    return { kind: "add", newPath: b, newMode, hunks };
  }
  if (isDeleted) {
    const oldMode = h["deleted file mode"] as string;
    if (indexMode !== undefined && indexMode !== oldMode) throw new PatchError(`${header}: index mode disagrees`);
    return { kind: "delete", oldPath: a, oldMode, hunks };
  }
  if ((h["old mode"] === undefined) !== (h["new mode"] === undefined)) throw new PatchError(`${header}: incomplete mode change`);
  // The index line carries the mode only when it did not change.
  const oldMode = h["old mode"] ?? indexMode;
  const newMode = h["new mode"];
  if (!renamed && !copied) {
    if (a !== b) throw new PatchError(`${header}: paths differ without a rename or copy header`);
    if (hunks.length === 0 && (newMode === undefined || newMode === oldMode)) throw new PatchError(`${header}: section changes nothing`);
  }
  const kind = renamed ? "rename" : copied ? "copy" : "modify";
  const p: FilePatch = { kind, oldPath: a, newPath: b, hunks };
  if (oldMode !== undefined) p.oldMode = oldMode;
  if (newMode !== undefined) p.newMode = newMode;
  return p;
}

// The path on a ---/+++ line: `<marker><prefix>path`, or /dev/null. git adds a
// trailing tab when the path contains a space; anything else after a tab
// (timestamps from non-git diffs) is not git format and is refused.
function diffName(line: string, marker: string, prefix: string, header: string): string | null {
  let name = line.slice(marker.length);
  if (name.endsWith("\t") && name.includes(" ")) name = name.slice(0, -1);
  if (name === "/dev/null") return null;
  if (name.startsWith('"')) throw new PatchError(`${header}: quoted paths are not supported`);
  if (!name.startsWith(prefix)) throw new PatchError(`${header}: ${marker.trim()} path must start with ${prefix}`);
  return name.slice(prefix.length);
}

function checkModeValue(header: string, mode: string): void {
  if (mode === "120000") throw new PatchError(`${header}: symlinks are not supported`);
  if (mode === "160000") throw new PatchError(`${header}: submodules are not supported`);
  if (!FILE_MODES.has(mode)) throw new PatchError(`${header}: unsupported mode ${mode}`);
}

function checkMode(path: string, actual: string, stated: string | undefined): void {
  if (stated !== undefined && stated !== actual) {
    throw new PatchError(`${path}: patch says mode ${stated}, base commit has ${actual}`);
  }
}

// A path the bridge will write: relative, POSIX, no traversal, nothing git or
// GitHub would reinterpret. Throws PatchError.
export function checkRepoPath(path: string): void {
  const bad = (why: string): never => {
    throw new PatchError(`${JSON.stringify(path)}: ${why}`);
  };
  if (path === "") bad("empty path");
  if (path.startsWith("/")) bad("absolute path");
  if (/[\u0000-\u001f\u007f\\]/.test(path)) bad("control character or backslash in path");
  if (path.startsWith('"')) bad("quoted path");
  for (const segment of path.split("/")) {
    if (segment === "") bad("empty path segment");
    if (segment === "." || segment === "..") bad("path traversal");
    if (segment.toLowerCase() === ".git") bad("path inside .git");
  }
}

// Apply a unified diff for one file to `original` and return the new content.
// The diff may start with `--- `/`+++ ` lines; everything else must be hunks.
// Throws PatchError on anything it cannot apply exactly.
export function applyUnifiedDiff(original: string, diff: string): string {
  const lines = (diff.endsWith("\n") ? diff.slice(0, -1) : diff).split("\n");
  let i = 0;
  if (lines.some((l) => l === "GIT binary patch" || l.startsWith("Binary files "))) {
    throw new PatchError("binary patches are not supported");
  }
  if (lines[0]?.startsWith("--- ")) {
    if (!lines[1]?.startsWith("+++ ")) throw new PatchError("--- line without +++ line");
    for (const [line, marker] of [
      [lines[0], "--- "],
      [lines[1], "+++ "],
    ] as const) {
      let name = line.slice(marker.length);
      if (name.endsWith("\t") && name.includes(" ")) name = name.slice(0, -1);
      if (name === "/dev/null") continue;
      if (name.startsWith("a/") || name.startsWith("b/")) name = name.slice(2);
      checkRepoPath(name);
    }
    i = 2;
  }
  const hunks = lines.slice(i);
  if (hunks.length === 0 || (hunks.length === 1 && hunks[0] === "")) throw new PatchError("diff has no hunks");
  return applyHunks(original, hunks, "file");
}

type Line = { text: string; nl: boolean }; // nl: the line ends with "\n"

// Apply hunk lines (starting at an @@ header) to `original`. Each hunk must
// sit exactly where its header says, its context and removed lines must match
// byte for byte (including the end-of-file newline state), and its header
// counts must match its body.
function applyHunks(original: string, lines: string[], name: string): string {
  const bad = (why: string): never => {
    throw new PatchError(`${name}: ${why}`);
  };
  const source = toLines(original);
  const out: Line[] = [];
  let cursor = 0; // next unconsumed index in source
  let delta = 0; // new-side line count minus old-side line count so far
  let i = 0;
  if (lines.length === 0) bad("no hunks");
  while (i < lines.length) {
    const header = lines[i] as string;
    const m = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$/.exec(header);
    if (!m) bad(`expected a hunk header, got ${JSON.stringify(header)}`);
    const [oldStart, oldCount, newStart, newCount] = [m![1], m![2] ?? "1", m![3], m![4] ?? "1"].map(Number) as [
      number,
      number,
      number,
      number,
    ];
    if (![oldStart, oldCount, newStart, newCount].every(Number.isSafeInteger)) bad(`hunk header out of range: ${header}`);
    if (oldCount === 0 && newCount === 0) bad(`empty hunk: ${header}`);
    if (oldCount > 0 && oldStart === 0) bad(`hunk starts at line 0: ${header}`);
    // A zero-length side names the line *after which* it applies.
    const at = oldCount === 0 ? oldStart : oldStart - 1;
    if (at < cursor) bad(`hunk out of order or overlapping: ${header}`);
    if (at + oldCount > source.length) bad(`hunk extends past the end of the file: ${header}`);
    const expectedNew = at + delta + (newCount === 0 ? 0 : 1);
    if (newStart !== expectedNew) bad(`hunk header offset: ${header} (expected +${expectedNew})`);
    i++;

    const oldSide: Line[] = [];
    const newSide: Line[] = [];
    while (oldSide.length < oldCount || newSide.length < newCount) {
      const line = lines[i];
      if (line === undefined) bad(`truncated hunk: ${header}`);
      const tag = line![0];
      const text = line!.slice(1);
      const both = tag === " ";
      if (!both && tag !== "-" && tag !== "+") bad(`invalid hunk line ${JSON.stringify(line)}`);
      const targets = both ? [oldSide, newSide] : tag === "-" ? [oldSide] : [newSide];
      for (const side of targets) {
        if (side.length >= (side === oldSide ? oldCount : newCount)) bad(`hunk body longer than its header: ${header}`);
      }
      i++;
      let nl = true;
      if (lines[i]?.startsWith("\\")) {
        nl = false;
        i++;
      }
      for (const side of targets) side.push({ text, nl });
    }
    for (let k = 0; k < oldSide.length; k++) {
      const want = source[at + k] as Line;
      const got = oldSide[k] as Line;
      if (want.text !== got.text || want.nl !== got.nl) bad(`context mismatch at line ${at + k + 1}`);
    }
    out.push(...source.slice(cursor, at), ...newSide);
    cursor = at + oldCount;
    delta += newCount - oldCount;
    if (i < lines.length && !lines[i]!.startsWith("@@")) bad(`unexpected line after hunk: ${JSON.stringify(lines[i])}`);
  }
  out.push(...source.slice(cursor));
  for (let k = 0; k < out.length - 1; k++) {
    if (!out[k]!.nl) bad("a line without a trailing newline is not at the end of the file");
  }
  return out.map((l) => l.text + (l.nl ? "\n" : "")).join("");
}

function toLines(text: string): Line[] {
  if (text === "") return [];
  const parts = text.split("\n");
  const last = parts.pop() as string;
  const lines = parts.map((t) => ({ text: t, nl: true }));
  if (last !== "") lines.push({ text: last, nl: false });
  return lines;
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

type TreeItem = { path: string; mode: string; type: string; sha: string };

const PER_PAGE = 100;
const MAX_PAGES = 100;

function hasNextPage(link: string | null): boolean {
  return link !== null && /<[^>]*>\s*;\s*rel="next"/.test(link);
}

function errorText(data: unknown, text: string, parsed: boolean): string {
  if (parsed && typeof data === "object" && data !== null) {
    const message = (data as Record<string, unknown>).message;
    const errors = (data as Record<string, unknown>).errors;
    const parts = [typeof message === "string" ? message : ""];
    if (Array.isArray(errors) && errors.length > 0) parts.push(JSON.stringify(errors));
    const joined = parts.filter((p) => p !== "").join(" ");
    if (joined !== "") return joined.slice(0, 500);
  }
  return text.slice(0, 500) || "(empty response)";
}

function shape(what: string): GitHubError {
  return new GitHubError(0, `unexpected GitHub response: ${what}`);
}

function get(v: unknown, key: string): unknown {
  if (typeof v !== "object" || v === null) throw shape(`expected an object with ${key}`);
  return (v as Record<string, unknown>)[key];
}

function getString(v: unknown, key: string): string {
  const s = get(v, key);
  if (typeof s !== "string") throw shape(`${key} is not a string`);
  return s;
}

function getNumber(v: unknown, key: string): number {
  const n = get(v, key);
  if (typeof n !== "number" || !Number.isFinite(n)) throw shape(`${key} is not a number`);
  return n;
}

function checkSha(sha: string): void {
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sha)) throw new GitHubError(0, `invalid commit sha ${JSON.stringify(sha)}`);
}

function checkPrNumber(n: number): void {
  if (!Number.isSafeInteger(n) || n <= 0) throw new GitHubError(0, `invalid pull request number ${n}`);
}

// Submission ids become branch names, so they are held to ref-name rules.
function checkSubmissionId(id: string): void {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(id) || id.includes("..") || id.endsWith(".lock") || id.endsWith(".")) {
    throw new GitHubError(0, `submission id ${JSON.stringify(id)} cannot be a branch name`);
  }
}

function checkBranch(name: string): void {
  const ok =
    /^[A-Za-z0-9._/-]+$/.test(name) &&
    name.split("/").every((s) => s !== "" && !s.startsWith(".") && !s.endsWith(".lock")) &&
    !name.includes("..") &&
    !name.endsWith(".");
  if (!ok) throw new GitHubError(0, `invalid branch name ${JSON.stringify(name)}`);
}

function refUrl(branch: string): string {
  return branch.split("/").map(encodeURIComponent).join("/");
}
