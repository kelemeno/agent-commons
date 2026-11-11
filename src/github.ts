// The GitHub bridge: the only module that talks to GitHub. Code reaches the
// project repo through here and nowhere else: participants submit a unified
// diff, and the coordinator bot turns it into a branch `commons/<submissionId>`
// in a bot-owned fork and a pull request from that fork, with its own token.
// Participants' credentials never touch the repo.
//
// Why a fork: a branch pushed into the project repo itself fires `push` and
// `pull_request` workflows with the repo's secrets and a write-scoped token,
// before any gate or review has run. A PR from a fork runs with no secrets and
// a read-only token, and outside contributors' workflows wait for approval.
// The bot token must not have the `workflow` scope, Actions should be disabled
// on the fork, and `.github/` changes are refused unless the caller allows them.
//
// What lands is bound to what the ledger names. openPullRequest refuses a base
// commit that is not already in the base branch (otherwise a submission could
// parent its tiny patch on someone else's unreviewed branch and a squash merge
// would land all of it), and refuses a patch whose resulting tree is not the
// tree of the submission's signed headCommit. The PR head is therefore "parent
// = submission.baseCommit, tree = tree(submission.headCommit)", which anyone
// with the repo can check; its commit sha is GitHub's and is not in the ledger.
// Ring and airlock decisions on a live PR use listChangedFiles with the head
// sha they were made for; mergePullRequest merges only that sha.
//
// REST only (api.github.com v3); GraphQL is not available to the bot. Every
// request goes through the injected fetch, so tests run without a network.
//
// The token is a secret held by the coordinator process. It is sent only in the
// Authorization header to `apiBase`, never logged, and scrubbed from every error
// message. Redirects are never followed (a renamed repo must be renamed in the
// config, not silently acted on) and pagination builds its own page URLs, so a
// response cannot steer the token or a write to another host or repo. Every
// request has a timeout: the coordinator merges under the ledger lock.
//
// The patch applier is deliberately strict. A patch applies byte-exactly at the
// line numbers its hunk headers state or not at all: no fuzz, no offsets, no
// whitespace leniency. Anything it cannot represent exactly (binary files,
// symlinks, submodules, quoted or non-ASCII paths) is refused rather than
// approximated, and a patch's structure is checked when it is parsed, so the
// server refuses a malformed patch at upload rather than at PR time.

export const TOKEN_ENV = "COMMONS_GITHUB_TOKEN";
export const DEFAULT_API_BASE = "https://api.github.com";
export const DEFAULT_TIMEOUT_MS = 30_000;

// Caps checked before any request. Every file costs base-tree reads, and the
// bot token's request budget is shared by every participant.
export const PATCH_LIMITS = { files: 300, lines: 100_000 } as const;

// The subset of global fetch the bridge uses. Global fetch satisfies it.
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; redirect: "manual"; signal: AbortSignal },
) => Promise<{ status: number; headers: { get(name: string): string | null }; text(): Promise<string> }>;

export type GitHubOptions = {
  token?: string; // default: process.env.COMMONS_GITHUB_TOKEN
  fetch?: FetchLike; // default: global fetch
  apiBase?: string; // default: https://api.github.com
  timeoutMs?: number; // per request, including reading the body; default 30s
  log?: (line: string) => void; // one line per request: method, path, status. Never the token.
};

// status is the HTTP status, or 0 when no HTTP status applies (no token,
// network failure, timeout, a response that is not the shape GitHub documents,
// a guard the bridge checks itself).
export class GitHubError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "GitHubError";
    this.status = status;
  }
}

// A patch (or submission) the bridge refuses. Never retried with leniency.
export class PatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PatchError";
  }
}

export type RepoRef = { owner: string; repo: string };

export type OpenPullRequestArgs = {
  owner: string;
  repo: string;
  baseBranch: string;
  submissionId: string;
  patch: string; // `git diff` output (git format, a/ and b/ prefixes) against the base commit
  title: string; // one line, at most 256 characters
  body: string; // participant text in here must be fenced by the caller (fenceUntrusted)
  // Where the bot creates commons/<submissionId>: its fork of owner/repo.
  headRepo: RepoRef;
  // Opening from a branch in owner/repo itself runs the project's CI with its
  // secrets on unreviewed code. Refused unless this is set.
  allowSameRepoHead?: boolean;
  // The commit the patch was made against (the submission's baseCommit). Must
  // be in baseBranch. Defaults to the current head of baseBranch.
  baseCommit?: string;
  // The tree of the submission's headCommit (`git rev-parse <headCommit>^{tree}`
  // in the coordinator's clone). The patch must produce exactly this tree.
  expectedTree: string;
  // `.github/` is where CI and repo automation live. A path there is refused
  // unless this returns true for it (e.g. after airlock approval).
  allowDotGithub?: (path: string) => boolean;
};

export type OpenedPullRequest = {
  number: number;
  url: string;
  branch: string; // commons/<submissionId>, in headRepo
  baseSha: string;
  headSha: string; // the bot's commit: parent baseSha, tree treeSha
  treeSha: string; // equals args.expectedTree
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

export type PullRequestInfo = {
  number: number;
  url: string;
  state: string; // open | closed
  merged: boolean;
  mergeCommitSha: string | null; // for a merged squash PR: the commit on the base branch
  headSha: string;
  headLabel: string; // owner:branch
  baseRef: string;
};

export type MergeOptions = {
  title?: string; // squash commit title
  body?: string; // squash commit message
  // Refuse unless the head commit has this tree (the submission's head tree).
  expectedTree?: string;
  // Refuse unless the base branch is at this commit, so the squash tree is
  // exactly the head tree rather than a merge with commits nobody gated.
  expectedBase?: string;
};

export type GitHub = {
  openPullRequest(args: OpenPullRequestArgs): Promise<OpenedPullRequest>;
  // The PR for commons/<submissionId> from headOwner (default: owner), or null.
  // Prefers a merged PR, then an open one, then the newest.
  findPullRequest(owner: string, repo: string, submissionId: string, headOwner?: string): Promise<PullRequestInfo | null>;
  // Refuses unless the PR head is expectedHeadSha before and after listing.
  listChangedFiles(owner: string, repo: string, prNumber: number, expectedHeadSha: string): Promise<ChangedFile[]>;
  // Squash-merges only if the PR head is `sha`. Idempotent: a PR already merged
  // at `sha` returns its merge commit.
  mergePullRequest(owner: string, repo: string, prNumber: number, sha: string, opts?: MergeOptions): Promise<{ sha: string }>;
  fastForward(owner: string, repo: string, branch: string, sha: string): Promise<{ sha: string }>;
  commentOnPullRequest(owner: string, repo: string, prNumber: number, body: string): Promise<{ id: number; url: string }>;
};

export function createGitHub(opts: GitHubOptions = {}): GitHub {
  const token = opts.token ?? process.env[TOKEN_ENV] ?? "";
  const doFetch: FetchLike = opts.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const apiBase = (opts.apiBase ?? DEFAULT_API_BASE).replace(/\/+$/, "");
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
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
    const controller = new AbortController();
    const init: Parameters<FetchLike>[1] = { method, headers, redirect: "manual", signal: controller.signal };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    // Raced as well as signalled: an injected fetch may ignore the signal.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        controller.abort();
        reject(new GitHubError(0, `${method} ${path}: timeout after ${timeoutMs} ms`));
      }, timeoutMs);
    });
    let res: Awaited<ReturnType<FetchLike>>;
    let text: string;
    try {
      res = await Promise.race([doFetch(apiBase + path, init), timeout]);
      text = await Promise.race([res.text(), timeout]);
    } catch (e) {
      if (e instanceof GitHubError) {
        log(`${method} ${path} timeout`);
        throw e;
      }
      // Only the message: an error object from the fetch layer may carry the request.
      const msg = e instanceof Error ? e.message : String(e);
      log(`${method} ${path} network error`);
      throw new GitHubError(0, redact(`${method} ${path}: network error: ${msg}`));
    } finally {
      clearTimeout(timer);
    }
    log(`${method} ${path} ${res.status}`);
    if (res.status >= 300 && res.status <= 399) {
      throw new GitHubError(res.status, `${method} ${path} -> ${res.status}: redirect not followed (repository renamed or moved?)`);
    }
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

  async function branchHead(rp: string, branch: string): Promise<string> {
    const ref = await request("GET", `${rp}/git/ref/heads/${refUrl(branch)}`);
    const object = get(ref.data, "object");
    if (get(object, "type") !== "commit") throw shape(`ref heads/${branch} does not point at a commit`);
    return getString(object, "sha");
  }

  async function commitInfo(rp: string, sha: string): Promise<{ tree: string; parents: string[] }> {
    const c = await request("GET", `${rp}/git/commits/${sha}`);
    const parents = get(c.data, "parents");
    return {
      tree: getString(get(c.data, "tree"), "sha"),
      parents: Array.isArray(parents) ? parents.map((p) => getString(p, "sha")) : [],
    };
  }

  async function getPull(rp: string, prNumber: number): Promise<PullRequestInfo & { changedFiles: number }> {
    const r = await request("GET", `${rp}/pulls/${prNumber}`);
    return { ...pullInfo(r.data), changedFiles: getNumber(r.data, "changed_files") };
  }

  async function findPullRequest(owner: string, repo: string, submissionId: string, headOwner = owner): Promise<PullRequestInfo | null> {
    const rp = repoPath(owner, repo);
    repoPath(headOwner, repo); // validates headOwner
    checkSubmissionId(submissionId);
    const label = `${headOwner}:commons/${submissionId}`;
    const r = await request("GET", `${rp}/pulls?head=${encodeURIComponent(label)}&state=all&per_page=100`);
    if (!Array.isArray(r.data)) throw shape("pull request list is not an array");
    // GitHub filters by head already; checked again so a lookup never returns
    // another submission's PR.
    const prs = r.data.map(pullInfo).filter((p) => p.headLabel.toLowerCase() === label.toLowerCase());
    return prs.find((p) => p.merged) ?? prs.find((p) => p.state === "open") ?? prs[0] ?? null;
  }

  async function openPullRequest(args: OpenPullRequestArgs): Promise<OpenedPullRequest> {
    const rp = repoPath(args.owner, args.repo);
    const hp = repoPath(args.headRepo.owner, args.headRepo.repo);
    const sameRepo = hp.toLowerCase() === rp.toLowerCase();
    if (sameRepo && args.allowSameRepoHead !== true) {
      throw new GitHubError(0, `refusing to push commons/${args.submissionId} into ${args.owner}/${args.repo} itself: its CI would run unreviewed code with the repo's secrets; use a bot-owned fork as headRepo`);
    }
    checkBranch(args.baseBranch);
    checkSubmissionId(args.submissionId);
    checkTitle(args.title);
    if (args.baseCommit !== undefined) checkSha(args.baseCommit);
    checkSha(args.expectedTree);
    const branch = `commons/${args.submissionId}`;
    // Parse before any request: a refused patch costs no API calls.
    const patches = parsePatch(args.patch);
    const files = [...new Set(patches.flatMap(touchedPaths))].sort();
    for (const f of files) {
      if (/^\.github(\/|$)/i.test(f) && args.allowDotGithub?.(f) !== true) {
        throw new PatchError(`${f}: changes under .github/ need explicit approval`);
      }
    }

    // Reads only until every file is validated: a refused patch writes nothing.
    const tip = await branchHead(rp, args.baseBranch);
    const baseSha = args.baseCommit ?? tip;
    if (baseSha !== tip) {
      const cmp = await request("GET", `${rp}/compare/${baseSha}...${tip}?per_page=1`);
      const status = getString(cmp.data, "status");
      // ahead: the branch contains baseSha and more. Anything else means the
      // parent would bring in commits the branch does not have.
      if (status !== "ahead") throw new PatchError(`base commit ${baseSha} is not in ${args.baseBranch} (${status})`);
    }
    const baseTree = (await commitInfo(rp, baseSha)).tree;

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

    // New contents go inline in the tree request (`content`), so a patch costs
    // four writes whatever its size: tree, commit, ref, pull request.
    type Entry = { path: string; mode: string; type: "blob"; sha?: string | null; content?: string };
    const entries: Entry[] = [];
    for (const p of patches) {
      if (p.kind === "add") {
        await absent(p.newPath);
        const content = p.hunks.length > 0 ? applyHunks("", parseHunks(p.hunks, p.newPath), p.newPath) : "";
        entries.push({ path: p.newPath, mode: p.newMode, type: "blob", content });
      } else if (p.kind === "delete") {
        const old = await existing(p.oldPath);
        checkMode(p.oldPath, old.mode, p.oldMode);
        const rest = p.hunks.length > 0 ? applyHunks(old.text, parseHunks(p.hunks, p.oldPath), p.oldPath) : old.text;
        if (rest !== "") throw new PatchError(`${p.oldPath}: deletion does not remove the whole file`);
        entries.push({ path: p.oldPath, mode: old.mode, type: "blob", sha: null });
      } else {
        const old = await existing(p.oldPath);
        checkMode(p.oldPath, old.mode, p.oldMode);
        if (p.kind !== "modify") await absent(p.newPath);
        const mode = p.newMode ?? old.mode;
        if (p.kind === "rename") entries.push({ path: p.oldPath, mode: old.mode, type: "blob", sha: null });
        if (p.hunks.length > 0) {
          entries.push({ path: p.newPath, mode, type: "blob", content: applyHunks(old.text, parseHunks(p.hunks, p.oldPath), p.oldPath) });
        } else {
          entries.push({ path: p.newPath, mode, type: "blob", sha: old.sha });
        }
      }
    }

    const tree = await request("POST", `${hp}/git/trees`, { base_tree: baseTree, tree: entries });
    const treeSha = getString(tree.data, "sha");
    if (treeSha === baseTree) throw new PatchError("patch changes nothing");
    if (treeSha !== args.expectedTree) {
      throw new PatchError(`patch produces tree ${treeSha}, but the submission's head commit has tree ${args.expectedTree}`);
    }
    const commit = await request("POST", `${hp}/git/commits`, {
      message: `${args.title}\n\nCommons-Submission: ${args.submissionId}\n`,
      tree: treeSha,
      parents: [baseSha],
    });
    let headSha = getString(commit.data, "sha");

    // Nothing below deletes the branch. A branch left by a failed or lost
    // request is reused by the retry when it holds this change; deleting it
    // after an ambiguous failure could close a PR that was in fact opened.
    try {
      await request("POST", `${hp}/git/refs`, { ref: `refs/heads/${branch}`, sha: headSha });
    } catch (e) {
      if (!(e instanceof GitHubError && e.status === 422)) throw e;
      const there = await branchHead(hp, branch);
      const c = await commitInfo(hp, there);
      if (c.tree !== treeSha || c.parents.length !== 1 || c.parents[0] !== baseSha) {
        throw new GitHubError(422, `${branch} already exists in ${args.headRepo.owner}/${args.headRepo.repo} with a different change (${there})`);
      }
      headSha = there;
    }

    const head = sameRepo ? branch : `${args.headRepo.owner}:${branch}`;
    const prBody: Record<string, string | boolean> = { title: args.title, head, base: args.baseBranch, body: args.body };
    if (!sameRepo) {
      // Only the bot may move the head: maintainers pushing to the fork branch
      // would change what the head-sha guard protects.
      prBody.maintainer_can_modify = false;
      // GitHub needs head_repo for a cross-repo PR within one owner.
      if (args.headRepo.owner.toLowerCase() === args.owner.toLowerCase()) prBody.head_repo = args.headRepo.repo;
    }
    let number: number;
    let url: string;
    try {
      const pr = await request("POST", `${rp}/pulls`, prBody);
      number = getNumber(pr.data, "number");
      url = getString(pr.data, "html_url");
    } catch (e) {
      // 422 "already exists" (an earlier attempt opened it) or a lost reply:
      // the PR may be there. Return it only if it is exactly this change.
      if (!(e instanceof GitHubError) || (e.status !== 0 && e.status !== 422)) throw e;
      const found = await findPullRequest(args.owner, args.repo, args.submissionId, args.headRepo.owner).catch(() => null);
      if (!found || found.state !== "open" || found.headSha !== headSha || found.baseRef !== args.baseBranch) throw e;
      number = found.number;
      url = found.url;
    }
    return { number, url, branch, baseSha, headSha, treeSha, files };
  }

  async function listChangedFiles(owner: string, repo: string, prNumber: number, expectedHeadSha: string): Promise<ChangedFile[]> {
    const rp = repoPath(owner, repo);
    checkPrNumber(prNumber);
    checkSha(expectedHeadSha);
    const moved = (sha: string) => new GitHubError(409, `pull ${prNumber}: head is ${sha}, expected ${expectedHeadSha}`);
    const before = await getPull(rp, prNumber);
    if (before.headSha !== expectedHeadSha) throw moved(before.headSha);
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
    // The pages are separate reads: a push in between would mix two heads.
    // GitHub also silently stops listing at 3000 files, and an incomplete list
    // would hide files from ring and airlock checks. Re-read the PR and
    // require the same head and GitHub's own file count.
    const after = await getPull(rp, prNumber);
    if (after.headSha !== expectedHeadSha) throw moved(after.headSha);
    if (after.changedFiles !== files.length) {
      throw new GitHubError(0, `pull ${prNumber}: listed ${files.length} files but GitHub reports ${after.changedFiles}`);
    }
    return files;
  }

  async function mergePullRequest(
    owner: string,
    repo: string,
    prNumber: number,
    sha: string,
    m: MergeOptions = {},
  ): Promise<{ sha: string }> {
    const rp = repoPath(owner, repo);
    checkPrNumber(prNumber);
    // The sha guard is mandatory: GitHub merges only if the PR head is exactly
    // the commit that passed gates and review (409 otherwise), so a push after
    // review can never ride along.
    checkSha(sha);
    if (m.expectedTree !== undefined) checkSha(m.expectedTree);
    if (m.expectedBase !== undefined) checkSha(m.expectedBase);
    const alreadyMerged = (pr: PullRequestInfo): { sha: string } | null =>
      pr.merged && pr.headSha === sha && pr.mergeCommitSha !== null ? { sha: pr.mergeCommitSha } : null;

    if (m.expectedTree !== undefined || m.expectedBase !== undefined) {
      const pr = await getPull(rp, prNumber);
      const done = alreadyMerged(pr);
      if (done) return done;
      if (pr.headSha !== sha) throw new GitHubError(409, `pull ${prNumber}: head is ${pr.headSha}, expected ${sha}`);
      if (m.expectedTree !== undefined) {
        const tree = (await commitInfo(rp, sha)).tree;
        if (tree !== m.expectedTree) throw new GitHubError(0, `pull ${prNumber}: head tree is ${tree}, expected ${m.expectedTree}`);
      }
      if (m.expectedBase !== undefined) {
        const tip = await branchHead(rp, pr.baseRef);
        if (tip !== m.expectedBase) throw new GitHubError(409, `pull ${prNumber}: ${pr.baseRef} is at ${tip}, expected ${m.expectedBase}`);
      }
    }
    const body: Record<string, string> = { sha, merge_method: "squash" };
    if (m.title !== undefined) body.commit_title = m.title;
    if (m.body !== undefined) body.commit_message = m.body;
    let r: Reply;
    try {
      r = await request("PUT", `${rp}/pulls/${prNumber}/merge`, body);
    } catch (e) {
      // An earlier attempt may have merged and lost the reply, or merged and
      // then failed to record it: GitHub refuses a second merge (405).
      if (e instanceof GitHubError && (e.status === 405 || e.status === 409 || e.status === 422)) {
        const pr = await getPull(rp, prNumber).catch(() => null);
        const done = pr && alreadyMerged(pr);
        if (done) return done;
      }
      throw e;
    }
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

  return { openPullRequest, findPullRequest, listChangedFiles, mergePullRequest, fastForward, commentOnPullRequest };
}

// One-shot forms of the client methods, for callers that do not keep a client.
// Same parameters as the client methods, plus the client options last.
export function openPullRequest(args: OpenPullRequestArgs, opts?: GitHubOptions): Promise<OpenedPullRequest> {
  return createGitHub(opts).openPullRequest(args);
}
export function findPullRequest(
  owner: string,
  repo: string,
  submissionId: string,
  headOwner?: string,
  opts?: GitHubOptions,
): Promise<PullRequestInfo | null> {
  return createGitHub(opts).findPullRequest(owner, repo, submissionId, headOwner);
}
export function listChangedFiles(
  owner: string,
  repo: string,
  prNumber: number,
  expectedHeadSha: string,
  opts?: GitHubOptions,
): Promise<ChangedFile[]> {
  return createGitHub(opts).listChangedFiles(owner, repo, prNumber, expectedHeadSha);
}
export function mergePullRequest(
  owner: string,
  repo: string,
  prNumber: number,
  sha: string,
  merge?: MergeOptions,
  opts?: GitHubOptions,
): Promise<{ sha: string }> {
  return createGitHub(opts).mergePullRequest(owner, repo, prNumber, sha, merge);
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

// Participant text for a PR body or comment, as a fenced code block: GitHub
// renders it verbatim, @mentions inside do not notify, and readers (people and
// reviewer agents) can see where the coordinator's words end. The fence is
// longer than any backtick run in the text, so the text cannot close it.
export function fenceUntrusted(text: string): string {
  const longest = Math.max(0, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  return `${fence}text\n${text.replace(/\r/g, "")}\n${fence}`;
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

// Every path a section writes or deletes. A copy leaves its source untouched.
function touchedPaths(p: FilePatch): string[] {
  if (p.kind === "add") return [p.newPath];
  if (p.kind === "delete") return [p.oldPath];
  return p.kind === "rename" ? [p.oldPath, p.newPath] : [p.newPath];
}

// Parse `git diff` output into file sections. Strict: every section starts with
// `diff --git a/<p> b/<p>`, only the extended headers git emits for text files
// are accepted, every path is checked by checkRepoPath, and every hunk is
// checked for structure (header syntax, line tags, counts, order). Only the
// match against file content is left to application.
export function parsePatch(patch: string): FilePatch[] {
  if (patch === "") throw new PatchError("empty patch");
  const lines = (patch.endsWith("\n") ? patch.slice(0, -1) : patch).split("\n");
  if (lines.length > PATCH_LIMITS.lines) throw new PatchError(`patch has more than ${PATCH_LIMITS.lines} lines`);
  if (!lines[0]?.startsWith("diff --git ")) throw new PatchError("patch must start with a `diff --git` line");
  const starts: number[] = [];
  lines.forEach((l, i) => {
    if (l.startsWith("diff --git ")) starts.push(i);
  });
  if (starts.length > PATCH_LIMITS.files) throw new PatchError(`patch touches more than ${PATCH_LIMITS.files} files`);
  const result: FilePatch[] = [];
  const touched = new Set<string>();
  for (let s = 0; s < starts.length; s++) {
    const section = lines.slice(starts[s], starts[s + 1] ?? lines.length);
    const p = parseSection(section);
    for (const path of touchedPaths(p)) {
      if (touched.has(path)) throw new PatchError(`${path}: appears more than once in the patch`);
      touched.add(path);
    }
    if (p.hunks.length > 0) parseHunks(p.hunks, section[0] as string);
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

// A path the bridge will write: relative, POSIX, no traversal, and nothing git
// on any filesystem would read as `.git` or `.gitmodules` (git's verify_path:
// NTFS drops trailing dots and spaces and has 8.3 names like GIT~1 and ADS
// names after `:`; HFS+ ignores invisible codepoints). Printable ASCII only,
// which also rules out bidi and invisible characters that make a name read
// differently in review; git quotes non-ASCII names in diffs anyway, and quoted
// paths are refused. Throws PatchError.
export function checkRepoPath(path: string): void {
  const bad = (why: string): never => {
    throw new PatchError(`${JSON.stringify(path)}: ${why}`);
  };
  if (path === "") bad("empty path");
  if (path.startsWith("/")) bad("absolute path");
  if (!/^[\x20-\x7e]+$/.test(path)) bad("path must be printable ASCII (no control, non-ASCII or invisible characters)");
  if (/[\\:"]/.test(path)) bad("backslash, colon or quote in path");
  for (const segment of path.split("/")) {
    if (segment === "") bad("empty path segment");
    if (segment === "." || segment === "..") bad("path traversal");
    if (/[. ]$/.test(segment)) bad("path segment ends with a dot or space");
    const lower = segment.toLowerCase();
    if (lower === ".git" || lower === "git~1") bad("path inside .git");
    if (lower === ".gitmodules" || lower === "gitmod~1") bad(".gitmodules is not supported");
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
  return applyHunks(original, parseHunks(hunks, "file"), "file");
}

type Line = { text: string; nl: boolean }; // nl: the line ends with "\n"
type Hunk = { header: string; at: number; oldSide: Line[]; newSide: Line[] };

// Parse hunk lines (starting at an @@ header). Checks everything that does not
// need the file: header syntax, line tags, body length against the header
// counts, order, and that each new-side start follows from the hunks before
// it (no offsets). `at` is the 0-based old-side index the hunk replaces from.
function parseHunks(lines: string[], name: string): Hunk[] {
  const bad = (why: string): never => {
    throw new PatchError(`${name}: ${why}`);
  };
  const hunks: Hunk[] = [];
  let cursor = 0; // first old-side index not covered by an earlier hunk
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
    hunks.push({ header, at, oldSide, newSide });
    cursor = at + oldCount;
    delta += newCount - oldCount;
    if (i < lines.length && !lines[i]!.startsWith("@@")) bad(`unexpected line after hunk: ${JSON.stringify(lines[i])}`);
  }
  return hunks;
}

// Apply parsed hunks to `original`. Each hunk must sit exactly where its header
// says, and its context and removed lines must match byte for byte, including
// the end-of-file newline state.
function applyHunks(original: string, hunks: Hunk[], name: string): string {
  const bad = (why: string): never => {
    throw new PatchError(`${name}: ${why}`);
  };
  const source = toLines(original);
  // Appended one at a time: spreading a large slice into push() overflows the
  // call stack on files of ~100k lines.
  const out: Line[] = [];
  let cursor = 0;
  for (const h of hunks) {
    if (h.at + h.oldSide.length > source.length) bad(`hunk extends past the end of the file: ${h.header}`);
    for (let k = 0; k < h.oldSide.length; k++) {
      const want = source[h.at + k] as Line;
      const got = h.oldSide[k] as Line;
      if (want.text !== got.text || want.nl !== got.nl) bad(`context mismatch at line ${h.at + k + 1}`);
    }
    for (let k = cursor; k < h.at; k++) out.push(source[k] as Line);
    for (const l of h.newSide) out.push(l);
    cursor = h.at + h.oldSide.length;
  }
  for (let k = cursor; k < source.length; k++) out.push(source[k] as Line);
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

function pullInfo(v: unknown): PullRequestInfo {
  const merge = get(v, "merge_commit_sha");
  return {
    number: getNumber(v, "number"),
    url: getString(v, "html_url"),
    state: getString(v, "state"),
    merged: get(v, "merged_at") !== null && get(v, "merged_at") !== undefined,
    mergeCommitSha: typeof merge === "string" ? merge : null,
    headSha: getString(get(v, "head"), "sha"),
    headLabel: getString(get(v, "head"), "label"),
    baseRef: getString(get(v, "base"), "ref"),
  };
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

function repoPath(owner: string, repo: string): string {
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo) || owner.startsWith(".") || repo.startsWith(".")) {
    throw new GitHubError(0, `invalid repository ${JSON.stringify(owner)}/${JSON.stringify(repo)}`);
  }
  return `/repos/${owner}/${repo}`;
}

function checkSha(sha: string): void {
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(sha)) throw new GitHubError(0, `invalid commit sha ${JSON.stringify(sha)}`);
}

function checkPrNumber(n: number): void {
  if (!Number.isSafeInteger(n) || n <= 0) throw new GitHubError(0, `invalid pull request number ${n}`);
}

// The title becomes the commit subject: a newline would let it forge trailers.
function checkTitle(title: string): void {
  if (title.trim() === "" || title.length > 256 || /[\u0000-\u001f\u007f‪-‮⁦-⁩]/.test(title)) {
    throw new GitHubError(0, `title must be one line of 1-256 characters without control characters`);
  }
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
