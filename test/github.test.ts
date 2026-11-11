import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  applyUnifiedDiff,
  checkRepoPath,
  createGitHub,
  type FetchLike,
  fenceUntrusted,
  GitHubError,
  listChangedFiles,
  mergePullRequest,
  type OpenPullRequestArgs,
  parsePatch,
  PATCH_LIMITS,
  PatchError,
  TOKEN_ENV,
} from "../src/github";

const TOKEN = "ghp_SECRETtoken0123456789abcdef";
const SHA_A = "a".repeat(40);
const SHA_B = "b".repeat(40);
const SHA_C = "c".repeat(40);

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

type Recorded = {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
  init: Parameters<FetchLike>[1];
};
type Canned = { status: number; body?: unknown; raw?: string; link?: string };

// A fetch that records every request and answers from a handler. A handler
// that throws makes the fetch reject, like a network failure.
function recorder(handler: (r: Recorded) => Canned | Promise<Canned>): { fetch: FetchLike; requests: Recorded[] } {
  const requests: Recorded[] = [];
  const fetch: FetchLike = async (url, init) => {
    const u = new URL(url);
    const r: Recorded = {
      method: init.method,
      url,
      path: u.pathname + u.search,
      headers: init.headers,
      body: init.body === undefined ? undefined : JSON.parse(init.body),
      init,
    };
    requests.push(r);
    const c = await handler(r);
    const text = c.raw ?? (c.body === undefined ? "" : JSON.stringify(c.body));
    return {
      status: c.status,
      headers: { get: (name: string) => (name.toLowerCase() === "link" ? (c.link ?? null) : null) },
      text: async () => text,
    };
  };
  return { fetch, requests };
}

type Item = { path: string; mode: string; type: string; sha: string };
type Flat = Map<string, { mode: string; type: string; sha: string }>;
type FileSpec = { mode: string; text: string } | { mode: string; type: "commit" | "blob"; sha?: string; text?: string };
type Pull = {
  number: number;
  html_url: string;
  state: string;
  head: { ref: string; sha: string; label: string };
  base: { ref: string };
  merged_at: string | null;
  merge_commit_sha: string | null;
};

// An in-memory GitHub fork network: acme/proj and the bot's fork bot/proj share
// one object store and have their own refs. It implements the endpoints the
// bridge uses, and hashes blobs and trees the way git does, so a tree sha here
// can be compared with `git write-tree`.
class FakeRepo {
  blobs = new Map<string, Buffer>();
  trees = new Map<string, Item[]>();
  commits = new Map<string, { tree: string; parents: string[] }>();
  refs = new Map<string, string>(); // acme/proj
  forkRefs = new Map<string, string>(); // bot/proj
  pulls: Pull[] = [];
  failPulls: Canned | null = null;
  dropPullsReply = false; // create the PR, then fail the request as a lost reply
  rec = recorder((r) => this.handle(r));

  gitHash(type: string, body: Buffer): string {
    return createHash("sha1").update(`${type} ${body.length}\0`).update(body).digest("hex");
  }
  putBlob(buf: Buffer): string {
    const sha = this.gitHash("blob", buf);
    this.blobs.set(sha, buf);
    return sha;
  }
  putTree(items: Item[]): string {
    const key = (e: Item) => Buffer.from(e.path + (e.type === "tree" ? "/" : ""));
    const sorted = [...items].sort((a, b) => Buffer.compare(key(a), key(b)));
    const body = Buffer.concat(
      sorted.map((e) => Buffer.concat([Buffer.from(`${e.mode === "040000" ? "40000" : e.mode} ${e.path}\0`), Buffer.from(e.sha, "hex")])),
    );
    const sha = this.gitHash("tree", body);
    this.trees.set(sha, sorted);
    return sha;
  }
  buildTree(flat: Flat): string {
    const groups = new Map<string, Flat>();
    const items: Item[] = [];
    for (const [path, e] of flat) {
      const slash = path.indexOf("/");
      if (slash < 0) {
        items.push({ path, ...e });
        continue;
      }
      const dir = path.slice(0, slash);
      if (!groups.has(dir)) groups.set(dir, new Map());
      groups.get(dir)!.set(path.slice(slash + 1), e);
    }
    for (const [dir, sub] of groups) items.push({ path: dir, mode: "040000", type: "tree", sha: this.buildTree(sub) });
    return this.putTree(items);
  }
  flatten(treeSha: string, prefix = ""): Flat {
    const out: Flat = new Map();
    for (const item of this.trees.get(treeSha) ?? []) {
      const p = prefix + item.path;
      if (item.type === "tree") for (const [k, v] of this.flatten(item.sha, p + "/")) out.set(k, v);
      else out.set(p, { mode: item.mode, type: item.type, sha: item.sha });
    }
    return out;
  }
  treeOf(files: Record<string, FileSpec>): string {
    const flat: Flat = new Map();
    for (const [path, f] of Object.entries(files)) {
      if ("type" in f && f.type === "commit") flat.set(path, { mode: f.mode, type: "commit", sha: f.sha ?? SHA_B });
      else flat.set(path, { mode: f.mode, type: "blob", sha: this.putBlob(Buffer.from(f.text ?? "", "utf8")) });
    }
    return this.buildTree(flat);
  }
  commit(tree: string, parents: string[], message: string): string {
    const who = "bot <bot@example.com> 0 +0000";
    const body = `tree ${tree}\n${parents.map((p) => `parent ${p}\n`).join("")}author ${who}\ncommitter ${who}\n\n${message}`;
    const sha = this.gitHash("commit", Buffer.from(body));
    this.commits.set(sha, { tree, parents });
    return sha;
  }
  seed(branch: string, files: Record<string, FileSpec>, parents: string[] = []): string {
    const sha = this.commit(this.treeOf(files), parents, `seed ${branch} ${this.commits.size}`);
    this.refs.set(`refs/heads/${branch}`, sha);
    return sha;
  }
  files(commitSha: string): Record<string, { mode: string; text: string }> {
    const out: Record<string, { mode: string; text: string }> = {};
    for (const [p, e] of this.flatten(this.commits.get(commitSha)!.tree)) {
      out[p] = { mode: e.mode, text: this.blobs.get(e.sha)?.toString("utf8") ?? "" };
    }
    return out;
  }
  isAncestor(a: string, b: string): boolean {
    const todo = [b];
    const seen = new Set<string>();
    while (todo.length > 0) {
      const c = todo.pop()!;
      if (c === a) return true;
      if (seen.has(c)) continue;
      seen.add(c);
      todo.push(...(this.commits.get(c)?.parents ?? []));
    }
    return false;
  }
  writes(): string[] {
    return this.rec.requests.filter((r) => r.method !== "GET").map((r) => `${r.method} ${r.path}`);
  }
  handle(r: Recorded): Canned {
    const m = /^\/repos\/(acme|bot)\/proj(\/[^?]*)(?:\?(.*))?$/.exec(r.path);
    if (!m) return { status: 404, body: { message: "Not Found" } };
    const refs = m[1] === "bot" ? this.forkRefs : this.refs;
    const p = m[2]!;
    const query = new URLSearchParams(m[3] ?? "");
    const body = r.body as Record<string, unknown>;
    const notFound: Canned = { status: 404, body: { message: "Not Found" } };
    let x: RegExpExecArray | null;
    if (r.method === "GET" && (x = /^\/git\/ref\/(heads\/.+)$/.exec(p))) {
      const sha = refs.get(`refs/${decodeURIComponent(x[1]!)}`);
      return sha ? { status: 200, body: { ref: `refs/${x[1]}`, object: { type: "commit", sha } } } : notFound;
    }
    if (r.method === "GET" && (x = /^\/git\/commits\/(\w+)$/.exec(p))) {
      const c = this.commits.get(x[1]!);
      return c ? { status: 200, body: { sha: x[1], tree: { sha: c.tree }, parents: c.parents.map((sha) => ({ sha })) } } : notFound;
    }
    if (r.method === "GET" && (x = /^\/git\/trees\/(\w+)$/.exec(p))) {
      const t = this.trees.get(x[1]!);
      return t ? { status: 200, body: { sha: x[1], tree: t, truncated: false } } : notFound;
    }
    if (r.method === "GET" && (x = /^\/git\/blobs\/(\w+)$/.exec(p))) {
      const b = this.blobs.get(x[1]!);
      if (!b) return notFound;
      // GitHub wraps base64 at 60 columns.
      const content = b.toString("base64").replace(/.{60}/g, "$&\n");
      return { status: 200, body: { sha: x[1], content, encoding: "base64" } };
    }
    if (r.method === "GET" && (x = /^\/compare\/(\w+)\.\.\.(\w+)$/.exec(p))) {
      const [base, head] = [x[1]!, x[2]!];
      if (!this.commits.has(base) || !this.commits.has(head)) return notFound;
      const status =
        base === head ? "identical" : this.isAncestor(base, head) ? "ahead" : this.isAncestor(head, base) ? "behind" : "diverged";
      return { status: 200, body: { status } };
    }
    if (r.method === "POST" && p === "/git/trees") {
      const flat = this.flatten(body.base_tree as string);
      for (const e of body.tree as { path: string; mode: string; type: string; sha?: string | null; content?: string }[]) {
        assert.ok(!(e.content !== undefined && e.sha !== undefined), "tree entry with both content and sha");
        if (e.content !== undefined) flat.set(e.path, { mode: e.mode, type: e.type, sha: this.putBlob(Buffer.from(e.content, "utf8")) });
        else if (e.sha === null) {
          if (!flat.delete(e.path)) return { status: 422, body: { message: `no such path ${e.path}` } };
        } else flat.set(e.path, { mode: e.mode, type: e.type, sha: e.sha! });
      }
      return { status: 201, body: { sha: this.buildTree(flat) } };
    }
    if (r.method === "POST" && p === "/git/commits") {
      return { status: 201, body: { sha: this.commit(body.tree as string, body.parents as string[], body.message as string) } };
    }
    if (r.method === "POST" && p === "/git/refs") {
      if (refs.has(body.ref as string)) return { status: 422, body: { message: "Reference already exists" } };
      refs.set(body.ref as string, body.sha as string);
      return { status: 201, body: { ref: body.ref, object: { sha: body.sha } } };
    }
    if (r.method === "DELETE" && (x = /^\/git\/refs\/(heads\/.+)$/.exec(p))) {
      refs.delete(`refs/${x[1]}`);
      return { status: 204 };
    }
    if (m[1] === "acme" && r.method === "POST" && p === "/pulls") {
      if (this.failPulls) return this.failPulls;
      const head = body.head as string;
      const [owner, branch] = head.includes(":") ? head.split(":") : ["acme", head];
      const sha = (owner === "bot" ? this.forkRefs : this.refs).get(`refs/heads/${branch}`);
      if (!sha) return { status: 422, body: { message: "Validation Failed", errors: [{ field: "head", code: "invalid" }] } };
      const label = `${owner}:${branch}`;
      if (this.pulls.some((x) => x.state === "open" && x.head.label === label)) {
        return { status: 422, body: { message: "Validation Failed", errors: [{ message: `A pull request already exists for ${label}.` }] } };
      }
      const n = 7 + this.pulls.length;
      const pull: Pull = {
        number: n,
        html_url: `https://github.com/acme/proj/pull/${n}`,
        state: "open",
        head: { ref: branch!, sha, label },
        base: { ref: body.base as string },
        merged_at: null,
        merge_commit_sha: null,
      };
      this.pulls.push(pull);
      if (this.dropPullsReply) throw new Error("socket hang up");
      return { status: 201, body: pull };
    }
    if (m[1] === "acme" && r.method === "GET" && p === "/pulls") {
      const head = query.get("head")?.toLowerCase();
      return { status: 200, body: this.pulls.filter((x) => head === undefined || x.head.label.toLowerCase() === head) };
    }
    if (m[1] === "acme" && r.method === "GET" && (x = /^\/pulls\/(\d+)$/.exec(p))) {
      const pull = this.pulls.find((y) => y.number === Number(x![1]));
      return pull ? { status: 200, body: { ...pull, changed_files: 0 } } : notFound;
    }
    return { status: 404, body: { message: `fake: no route ${r.method} ${p}` } };
  }
}

function bridge(repo: FakeRepo, extra: { log?: (l: string) => void } = {}) {
  return createGitHub({ token: TOKEN, fetch: repo.rec.fetch, ...extra });
}

const MAIN_FILES = (): Record<string, FileSpec> => ({
  "README.md": { mode: "100644", text: "# proj\n" },
  "src/a.ts": { mode: "100644", text: lines(1, 20) },
  "src/b.ts": { mode: "100644", text: "export const b = 1;\n" },
  "scripts/run.sh": { mode: "100755", text: "#!/bin/sh\necho hi\n" },
  "link.ts": { mode: "120000", text: "src/a.ts" },
  vendor: { mode: "160000", type: "commit" },
});

const README_PATCH =
  "diff --git a/README.md b/README.md\nindex 1111111..2222222 100644\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-# proj\n+# Proj\n";

// The tree README_PATCH produces on MAIN_FILES.
function readmeTree(repo: FakeRepo): string {
  return repo.treeOf({ ...MAIN_FILES(), "README.md": { mode: "100644", text: "# Proj\n" } });
}

function args(over: Partial<OpenPullRequestArgs> & { expectedTree: string }): OpenPullRequestArgs {
  return {
    owner: "acme",
    repo: "proj",
    baseBranch: "dev",
    headRepo: { owner: "bot", repo: "proj" },
    submissionId: "s",
    patch: README_PATCH,
    title: "t",
    body: "b",
    ...over,
  };
}

function lines(from: number, to: number): string {
  let s = "";
  for (let i = from; i <= to; i++) s += `line ${i}\n`;
  return s;
}

async function rejectsPatch(p: Promise<unknown>, re: RegExp): Promise<void> {
  await assert.rejects(p, (e: unknown) => e instanceof PatchError && re.test(e.message));
}

// ---------------------------------------------------------------------------
// applyUnifiedDiff
// ---------------------------------------------------------------------------

test("applyUnifiedDiff applies several hunks exactly", () => {
  const original = lines(1, 20);
  const diff = [
    "--- a/src/a.ts",
    "+++ b/src/a.ts",
    "@@ -2,3 +2,4 @@",
    " line 2",
    "-line 3",
    "+line three",
    "+line 3.5",
    " line 4",
    "@@ -15,3 +16,2 @@ function context",
    " line 15",
    "-line 16",
    " line 17",
    "",
  ].join("\n");
  const want = original.replace("line 3\n", "line three\nline 3.5\n").replace("line 16\n", "");
  assert.equal(applyUnifiedDiff(original, diff), want);
});

test("applyUnifiedDiff creates and empties files", () => {
  assert.equal(applyUnifiedDiff("", "--- /dev/null\n+++ b/x.ts\n@@ -0,0 +1,2 @@\n+a\n+b\n"), "a\nb\n");
  assert.equal(applyUnifiedDiff("a\nb\n", "--- a/x.ts\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n"), "");
});

test("applyUnifiedDiff handles zero-context hunks (git diff -U0)", () => {
  const original = lines(1, 10);
  const diff = "@@ -3,2 +2,0 @@\n-line 3\n-line 4\n@@ -7,0 +6,1 @@\n+inserted\n";
  assert.equal(applyUnifiedDiff(original, diff), "line 1\nline 2\nline 5\nline 6\nline 7\ninserted\nline 8\nline 9\nline 10\n");
});

test("applyUnifiedDiff tracks the end-of-file newline exactly", () => {
  const marker = "\\ No newline at end of file";
  // add the missing newline
  assert.equal(applyUnifiedDiff("a\nb", `@@ -1,2 +1,2 @@\n a\n-b\n${marker}\n+b\n`), "a\nb\n");
  // remove it
  assert.equal(applyUnifiedDiff("a\nb\n", `@@ -1,2 +1,2 @@\n a\n-b\n+b\n${marker}\n`), "a\nb");
  // context line without a newline on both sides
  assert.equal(applyUnifiedDiff("a\nb", `@@ -1,2 +1,2 @@\n-a\n+A\n b\n${marker}\n`), "A\nb");
  // the patch claims a trailing newline the file does not have: mismatch
  assert.throws(() => applyUnifiedDiff("a\nb", "@@ -1,2 +1,2 @@\n-a\n+A\n b\n"), /context mismatch/);
  // appending after a last line that has no newline cannot be expressed as an insertion
  assert.throws(() => applyUnifiedDiff("a\nb", "@@ -2,0 +3,1 @@\n+c\n"), /trailing newline/);
});

test("applyUnifiedDiff preserves CRLF bytes", () => {
  assert.equal(applyUnifiedDiff("a\r\nb\r\n", "@@ -1,2 +1,2 @@\n a\r\n-b\r\n+c\r\n"), "a\r\nc\r\n");
  assert.throws(() => applyUnifiedDiff("a\r\nb\r\n", "@@ -1,2 +1,2 @@\n a\n-b\n+c\n"), /context mismatch/);
});

test("applyUnifiedDiff rejects context mismatch and fuzz", () => {
  const original = lines(1, 10);
  assert.throws(() => applyUnifiedDiff(original, "@@ -2,2 +2,2 @@\n line 2\n-line X\n+y\n"), PatchError);
  // whitespace-only difference is still a mismatch
  assert.throws(() => applyUnifiedDiff(original, "@@ -2,2 +2,2 @@\n line  2\n-line 3\n+y\n"), /context mismatch/);
});

test("applyUnifiedDiff rejects hunks at the wrong offset", () => {
  const original = lines(1, 10);
  // content is at line 4, header says 3: no searching for it
  assert.throws(() => applyUnifiedDiff(original, "@@ -3,2 +3,2 @@\n line 4\n-line 5\n+five\n"), /context mismatch/);
  // old side right, new side header inconsistent with the earlier hunks
  assert.throws(() => applyUnifiedDiff(original, "@@ -2,1 +2,2 @@\n line 2\n+x\n@@ -5,1 +5,1 @@\n-line 5\n+five\n"), /offset/);
});

test("applyUnifiedDiff rejects malformed hunks", () => {
  const original = lines(1, 10);
  assert.throws(() => applyUnifiedDiff(original, "@@ -1,3 +1,3 @@\n line 1\n-line 2\n+two\n"), /truncated/);
  assert.throws(() => applyUnifiedDiff(original, "@@ -1,1 +1,1 @@\n-line 1\n+one\n+extra\n"), /unexpected line|longer/);
  assert.throws(() => applyUnifiedDiff(original, "@@ -5,1 +5,1 @@\n-line 5\n+5\n@@ -2,1 +2,1 @@\n-line 2\n+2\n"), /out of order/);
  assert.throws(() => applyUnifiedDiff(original, "@@ -9,3 +9,3 @@\n line 9\n line 10\n-line 11\n+x\n"), /past the end/);
  assert.throws(() => applyUnifiedDiff(original, "@@ -1,1 +1,1 @@\n-line 1\n\n+one\n"), /invalid hunk line/);
  assert.throws(() => applyUnifiedDiff(original, "garbage\n"), /hunk header/);
  assert.throws(() => applyUnifiedDiff(original, ""), /no hunks/);
});

test("applyUnifiedDiff rejects unsafe paths and binary diffs", () => {
  const hunk = "@@ -1,1 +1,1 @@\n-line 1\n+one\n";
  assert.throws(() => applyUnifiedDiff("line 1\n", `--- a/../etc/passwd\n+++ b/../etc/passwd\n${hunk}`), /traversal/);
  assert.throws(() => applyUnifiedDiff("line 1\n", `--- /etc/passwd\n+++ /etc/passwd\n${hunk}`), /absolute/);
  assert.throws(() => applyUnifiedDiff("x", "Binary files a/x.png and b/x.png differ\n"), /binary/);
});

test("checkRepoPath accepts ordinary paths and refuses traversal", () => {
  checkRepoPath("anthill-backend/src/engine.ts");
  checkRepoPath("docs/my file.md");
  checkRepoPath(".github/workflows/ci.yml");
  for (const bad of ["", "/abs", "a/../b", "..", "./a", "a//b", "a/", ".git/config", "x/.GIT/hooks", "a\\b", "a\u0000b"]) {
    assert.throws(() => checkRepoPath(bad), PatchError, bad);
  }
});

// ---------------------------------------------------------------------------
// parsePatch
// ---------------------------------------------------------------------------

test("parsePatch reads add, delete, modify, rename and mode changes", () => {
  const patch = [
    "diff --git a/src/new.ts b/src/new.ts",
    "new file mode 100644",
    "index 0000000..1111111",
    "--- /dev/null",
    "+++ b/src/new.ts",
    "@@ -0,0 +1 @@",
    "+x",
    "diff --git a/src/b.ts b/src/b.ts",
    "deleted file mode 100644",
    "index 2222222..0000000",
    "--- a/src/b.ts",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    "-export const b = 1;",
    "diff --git a/scripts/run.sh b/scripts/run.sh",
    "old mode 100755",
    "new mode 100644",
    "diff --git a/README.md b/docs/README.md",
    "similarity index 100%",
    "rename from README.md",
    "rename to docs/README.md",
    "diff --git a/my file.md b/my file.md",
    "index 3333333..4444444 100644",
    "--- a/my file.md\t",
    "+++ b/my file.md\t",
    "@@ -1 +1 @@",
    "-a",
    "+b",
    "",
  ].join("\n");
  const parsed = parsePatch(patch);
  assert.deepEqual(
    parsed.map((p) => [p.kind, "oldPath" in p ? p.oldPath : null, "newPath" in p ? p.newPath : null]),
    [
      ["add", null, "src/new.ts"],
      ["delete", "src/b.ts", null],
      ["modify", "scripts/run.sh", "scripts/run.sh"],
      ["rename", "README.md", "docs/README.md"],
      ["modify", "my file.md", "my file.md"],
    ],
  );
  const modeChange = parsed[2]!;
  assert.ok(modeChange.kind === "modify" && modeChange.oldMode === "100755" && modeChange.newMode === "100644");
  assert.ok(parsed[4]!.kind === "modify" && parsed[4]!.oldMode === "100644");
});

test("parsePatch rejects symlinks, submodules, binaries and unsafe paths", () => {
  const cases: [string, RegExp][] = [
    ["diff --git a/l b/l\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+/etc/passwd\n\\ No newline at end of file\n", /symlink/],
    ["diff --git a/f b/f\nold mode 100644\nnew mode 120000\n", /symlink/],
    ["diff --git a/f b/f\nindex 1111111..2222222 120000\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n", /symlink/],
    ["diff --git a/sub b/sub\nnew file mode 160000\nindex 0000000..1111111\n--- /dev/null\n+++ b/sub\n@@ -0,0 +1 @@\n+Subproject commit abc\n", /submodule/],
    ["diff --git a/x.png b/x.png\nindex 1111111..2222222 100644\nGIT binary patch\nliteral 5\nabc\n", /binary/],
    ["diff --git a/x.png b/x.png\nindex 1111111..2222222 100644\nBinary files a/x.png and b/x.png differ\n", /binary/],
    ["diff --git a/../x b/../x\nindex 1111111..2222222 100644\n--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n", /traversal/],
    ["diff --git a//etc/x b//etc/x\nindex 1111111..2222222 100644\n--- a//etc/x\n+++ b//etc/x\n@@ -1 +1 @@\n-a\n+b\n", /absolute/],
    ["diff --git a/ok b/../../evil\nrename from ok\nrename to ../../evil\n", /traversal/],
    ["diff --git a/.git/hooks/pre-commit b/.git/hooks/pre-commit\nnew file mode 100755\n", /\.git/],
    ['diff --git "a/t\\tab" "b/t\\tab"\nindex 1111111..2222222 100644\n--- "a/t\\tab"\n+++ "b/t\\tab"\n@@ -1 +1 @@\n-a\n+b\n', /quoted|parse|match/],
    ["From abc Mon Sep 17 00:00:00 2001\ndiff --git a/f b/f\n", /must start/],
    ["diff --git a/f b/f\nindex 1111111..2222222 100644\n--- a/f\n+++ b/g\n@@ -1 +1 @@\n-a\n+b\n", /match/],
    ["diff --git a/f b/f\nindex 1111111..2222222 100644\n--- a/f\n+++ b/f\n", /without hunks/],
    ["diff --git a/f b/f\nweird header\n", /unsupported header/],
    ["diff --git a/f b/f\nindex 1111111..2222222 100644\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\n+b\ndiff --git a/f b/f\nindex 1111111..2222222 100644\n--- a/f\n+++ b/f\n@@ -1 +1 @@\n-b\n+c\n", /more than once/],
    ["", /empty/],
  ];
  for (const [patch, re] of cases) {
    assert.throws(() => parsePatch(patch), (e: unknown) => e instanceof PatchError && re.test(e.message), patch);
  }
});


test("applyUnifiedDiff edits near the end of a 200k-line file without overflowing the stack", () => {
  const original = lines(1, 200_000);
  const diff = "@@ -199999,2 +199999,2 @@\n line 199999\n-line 200000\n+the end\n";
  const out = applyUnifiedDiff(original, diff);
  assert.equal(out.length, original.length - "line 200000".length + "the end".length);
  assert.ok(out.endsWith("line 199999\nthe end\n"));
});

test("checkRepoPath refuses names git reads as .git or .gitmodules on other filesystems, and invisible characters", () => {
  checkRepoPath("a/.gitignore");
  checkRepoPath("a/.gitattributes");
  checkRepoPath("a/git~1x");
  for (const bad of [
    ".git.",
    ".git ",
    "x/.GIT..",
    "GIT~1/config",
    "a/git~1",
    ".git::$INDEX_ALLOCATION/hooks/x",
    "a:b",
    ".gitmodules",
    "sub/.GitModules",
    "gitmod~1",
    ".g‌it/hooks/pre-commit", // HFS+ ignores U+200C
    "a‮b.ts", // bidi override
    "﻿.git/config",
    "café.md",
    'a"b',
    "dir./x",
  ]) {
    assert.throws(() => checkRepoPath(bad), PatchError, JSON.stringify(bad));
  }
});

test("parsePatch checks hunk structure without the file", () => {
  const head = "diff --git a/f b/f\nindex 1111111..2222222 100644\n--- a/f\n+++ b/f\n";
  const cases: [string, RegExp][] = [
    [`${head}@@ -1 +1 @@\n-a\n+b\nGARBAGE\n`, /unexpected line after hunk/],
    [`${head}@@ -1,2 +1,1 @@\n-a\n+b\n+c\n`, /longer than its header/],
    [`${head}@@ -1 +1 @@\n-a\n+b\n+c\n`, /unexpected line after hunk/],
    [`${head}@@ -1,3 +1,3 @@\n a\n-b\n+c\n`, /truncated/],
    [`${head}@@ -5 +5 @@\n-a\n+b\n@@ -2 +2 @@\n-c\n+d\n`, /out of order/],
    [`${head}@@ -1 +2 @@\n-a\n+b\n`, /offset/],
    [`${head}@@ -1 +1 @@\n*a\n+b\n`, /invalid hunk line/],
    [`${head}@@ bogus @@\n-a\n`, /hunk header/],
  ];
  for (const [patch, re] of cases) {
    assert.throws(() => parsePatch(patch), (e: unknown) => e instanceof PatchError && re.test(e.message), patch);
  }
  assert.equal(parsePatch(`${head}@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n`).length, 1);
});

test("parsePatch caps the number of files and lines", () => {
  const many = Array.from({ length: PATCH_LIMITS.files + 1 }, (_, i) => `diff --git a/f${i} b/f${i}\nnew file mode 100644\n`).join("");
  assert.throws(() => parsePatch(many), /more than 300 files/);
  const ok = Array.from({ length: PATCH_LIMITS.files }, (_, i) => `diff --git a/f${i} b/f${i}\nnew file mode 100644\n`).join("");
  assert.equal(parsePatch(ok).length, PATCH_LIMITS.files);
  const n = PATCH_LIMITS.lines;
  const long = `diff --git a/f b/f\nnew file mode 100644\n--- /dev/null\n+++ b/f\n@@ -0,0 +1,${n} @@\n${"+x\n".repeat(n)}`;
  assert.throws(() => parsePatch(long), /more than 100000 lines/);
});

// ---------------------------------------------------------------------------
// openPullRequest
// ---------------------------------------------------------------------------

test("openPullRequest builds the branch in the fork and the PR from it, with four writes", async () => {
  const repo = new FakeRepo();
  const base = repo.seed("dev", MAIN_FILES());
  const patch = [
    "diff --git a/src/a.ts b/src/a.ts",
    "index 1111111..2222222 100644",
    "--- a/src/a.ts",
    "+++ b/src/a.ts",
    "@@ -1,3 +1,3 @@",
    "-line 1",
    "+line one",
    " line 2",
    " line 3",
    "@@ -18,3 +18,4 @@",
    " line 18",
    " line 19",
    " line 20",
    "+line 21",
    "diff --git a/src/new.ts b/src/new.ts",
    "new file mode 100755",
    "index 0000000..3333333",
    "--- /dev/null",
    "+++ b/src/new.ts",
    "@@ -0,0 +1,2 @@",
    "+#!/usr/bin/env node",
    "+console.log(1);",
    "diff --git a/src/empty.ts b/src/empty.ts",
    "new file mode 100644",
    "index 0000000..e69de29",
    "diff --git a/src/b.ts b/src/b.ts",
    "deleted file mode 100644",
    "index 4444444..0000000",
    "--- a/src/b.ts",
    "+++ /dev/null",
    "@@ -1 +0,0 @@",
    "-export const b = 1;",
    "diff --git a/README.md b/docs/README.md",
    "similarity index 80%",
    "rename from README.md",
    "rename to docs/README.md",
    "index 5555555..6666666 100644",
    "--- a/README.md",
    "+++ b/docs/README.md",
    "@@ -1 +1,2 @@",
    " # proj",
    "+more",
    "diff --git a/scripts/run.sh b/scripts/run.sh",
    "old mode 100755",
    "new mode 100644",
    "",
  ].join("\n");
  const want: Record<string, FileSpec> = {
    "src/a.ts": { mode: "100644", text: lines(1, 20).replace("line 1\n", "line one\n") + "line 21\n" },
    "src/new.ts": { mode: "100755", text: "#!/usr/bin/env node\nconsole.log(1);\n" },
    "src/empty.ts": { mode: "100644", text: "" },
    "docs/README.md": { mode: "100644", text: "# proj\nmore\n" },
    "scripts/run.sh": { mode: "100644", text: "#!/bin/sh\necho hi\n" },
    "link.ts": { mode: "120000", text: "src/a.ts" },
    vendor: { mode: "160000", type: "commit" },
  };
  const expectedTree = repo.treeOf(want);
  const logs: string[] = [];
  const gh = bridge(repo, { log: (l) => logs.push(l) });
  const pr = await gh.openPullRequest(args({ submissionId: "sub-1", patch, title: "Fix line one", body: "Ledger: submission sub-1", expectedTree }));
  assert.equal(pr.number, 7);
  assert.equal(pr.branch, "commons/sub-1");
  assert.equal(pr.baseSha, base);
  assert.equal(pr.treeSha, expectedTree);
  assert.deepEqual(pr.files, ["README.md", "docs/README.md", "scripts/run.sh", "src/a.ts", "src/b.ts", "src/empty.ts", "src/new.ts"]);
  assert.equal(repo.forkRefs.get("refs/heads/commons/sub-1"), pr.headSha);
  assert.deepEqual([...repo.refs.keys()], ["refs/heads/dev"], "nothing is pushed to the project repo");
  assert.deepEqual(repo.commits.get(pr.headSha), { tree: expectedTree, parents: [base] });

  const files = repo.files(pr.headSha);
  assert.equal(files["src/b.ts"], undefined);
  assert.equal(files["README.md"], undefined);
  assert.deepEqual(files["docs/README.md"], { mode: "100644", text: "# proj\nmore\n" });

  // Content goes inline in the tree: no blob writes, whatever the file count.
  assert.deepEqual(repo.writes(), [
    "POST /repos/bot/proj/git/trees",
    "POST /repos/bot/proj/git/commits",
    "POST /repos/bot/proj/git/refs",
    "POST /repos/acme/proj/pulls",
  ]);
  const prReq = repo.rec.requests.at(-1)!;
  assert.deepEqual(prReq.body, { title: "Fix line one", head: "bot:commons/sub-1", base: "dev", body: "Ledger: submission sub-1", maintainer_can_modify: false });
  const commitReq = repo.rec.requests.find((r) => r.path.endsWith("/git/commits") && r.method === "POST")!;
  assert.equal((commitReq.body as { message: string }).message, "Fix line one\n\nCommons-Submission: sub-1\n");
  for (const r of repo.rec.requests) {
    assert.equal(r.headers.Authorization, `Bearer ${TOKEN}`);
    assert.ok(r.url.startsWith("https://api.github.com/"));
    assert.equal(r.init.redirect, "manual");
  }
  assert.ok(logs.length > 0 && logs.every((l) => !l.includes(TOKEN)));
});

test("openPullRequest applies a real git diff and produces git's own tree", async (t) => {
  const git = (cwd: string, ...a: string[]): string => {
    const r = spawnSync("git", a, {
      cwd,
      encoding: "utf8",
      env: { PATH: process.env.PATH ?? "", HOME: cwd, GIT_CONFIG_NOSYSTEM: "1", GIT_CONFIG_GLOBAL: "/dev/null" },
    });
    if (r.status !== 0) throw new Error(`git ${a.join(" ")}: ${r.stderr}`);
    return r.stdout;
  };
  if (spawnSync("git", ["--version"]).status !== 0) {
    t.skip("git is not installed");
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), "commons-github-"));
  try {
    const base: Record<string, { mode: string; text: string }> = {
      "src/engine.ts": { mode: "100644", text: lines(1, 60) },
      "src/util.ts": { mode: "100644", text: "export const x = 1;\nexport const y = 2;\n" },
      "docs/old name.md": { mode: "100644", text: lines(1, 30) },
      "bin/tool": { mode: "100755", text: "#!/bin/sh\nexit 0" }, // no trailing newline
      "gone.txt": { mode: "100644", text: "bye\n" },
      "crlf.txt": { mode: "100644", text: "a\r\nb\r\nc\r\n" },
      "a-b/x.ts": { mode: "100644", text: "x\n" }, // sorts before a/ by bytes, after it as a tree
      "a/y.ts": { mode: "100644", text: "y\n" },
    };
    const write = (path: string, f: { mode: string; text: string }): void => {
      mkdirSync(dirname(join(dir, path)), { recursive: true });
      writeFileSync(join(dir, path), f.text);
      chmodSync(join(dir, path), f.mode === "100755" ? 0o755 : 0o644);
    };
    git(dir, "init", "-q", "-b", "dev");
    git(dir, "config", "user.email", "t@example.com");
    git(dir, "config", "user.name", "t");
    for (const [p, f] of Object.entries(base)) write(p, f);
    git(dir, "add", "-A");
    git(dir, "commit", "-q", "-m", "base");
    const baseTree = git(dir, "rev-parse", "HEAD^{tree}").trim();

    write("src/engine.ts", { mode: "100644", text: lines(1, 60).replace("line 5\n", "line five\n").replace("line 50\n", "") + "line 61\n" });
    write("src/util.ts", { mode: "100755", text: "export const x = 1;\nexport const y = 3;\n" });
    renameSync(join(dir, "docs/old name.md"), join(dir, "docs/new name.md"));
    writeFileSync(join(dir, "docs/new name.md"), lines(1, 30).replace("line 29\n", "line 29!\n"));
    write("bin/tool", { mode: "100755", text: "#!/bin/sh\nexit 1\n" });
    rmSync(join(dir, "gone.txt"));
    write("crlf.txt", { mode: "100644", text: "a\r\nB\r\nc\r\n" });
    write("src/fresh/empty.ts", { mode: "100644", text: "" });
    write("src/fresh/full.ts", { mode: "100644", text: "export {};\n" });
    git(dir, "add", "-A");
    const patch = git(dir, "diff", "--cached", "-M", "HEAD");
    assert.match(patch, /rename from docs\/old name\.md/);
    git(dir, "commit", "-q", "-m", "head");
    const headTree = git(dir, "rev-parse", "HEAD^{tree}").trim();

    const repo = new FakeRepo();
    const baseSha = repo.seed("dev", base);
    assert.equal(repo.commits.get(baseSha)!.tree, baseTree, "the fake hashes trees like git");
    const pr = await bridge(repo).openPullRequest(args({ submissionId: "sub-git", patch, expectedTree: headTree }));
    assert.equal(pr.treeSha, headTree);
    assert.equal(repo.commits.get(pr.headSha)!.tree, headTree);
    const want: Record<string, { mode: string; text: string }> = {};
    for (const p of git(dir, "ls-files").trim().split("\n")) {
      want[p] = { mode: (statSync(join(dir, p)).mode & 0o111) !== 0 ? "100755" : "100644", text: readFileSync(join(dir, p), "utf8") };
    }
    assert.deepEqual(repo.files(pr.headSha), want);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("openPullRequest refuses a patch whose tree is not the submission's head tree, before any commit", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  await rejectsPatch(bridge(repo).openPullRequest(args({ expectedTree: SHA_A })), /produces tree [0-9a-f]{40}, but the submission's head commit has tree a{40}/);
  assert.deepEqual(repo.writes(), ["POST /repos/bot/proj/git/trees"]);
  assert.equal(repo.forkRefs.size, 0);
  assert.equal(repo.pulls.length, 0);
});

test("openPullRequest refuses a base commit that is not in the base branch", async () => {
  const repo = new FakeRepo();
  const dev = repo.seed("dev", MAIN_FILES());
  // Another participant's rejected branch: same fork network, so it resolves.
  const evilTree = repo.treeOf({ ...MAIN_FILES(), "src/a.ts": { mode: "100644", text: "backdoor\n" } });
  const rejected = repo.commit(evilTree, [dev], "rejected submission");
  repo.forkRefs.set("refs/heads/commons/rejected", rejected);
  const unrelated = repo.commit(evilTree, [], "unrelated history");
  const tree = repo.treeOf({ ...MAIN_FILES(), "src/a.ts": { mode: "100644", text: "backdoor\n" }, "README.md": { mode: "100644", text: "# Proj\n" } });
  for (const [baseCommit, status] of [
    [rejected, "behind"],
    [unrelated, "diverged"],
  ] as const) {
    repo.rec.requests.length = 0;
    await rejectsPatch(bridge(repo).openPullRequest(args({ baseCommit, expectedTree: tree })), new RegExp(`is not in dev \\(${status}\\)`));
    assert.deepEqual(repo.writes(), [], "nothing written");
  }
});

test("openPullRequest uses a baseCommit the base branch has moved past as the parent", async () => {
  const repo = new FakeRepo();
  const old = repo.seed("dev", MAIN_FILES());
  repo.seed("dev", { ...MAIN_FILES(), "src/b.ts": { mode: "100644", text: "moved on\n" } }, [old]);
  const pr = await bridge(repo).openPullRequest(args({ submissionId: "s2", baseCommit: old, expectedTree: readmeTree(repo) }));
  assert.deepEqual(repo.commits.get(pr.headSha)!.parents, [old]);
  assert.equal(pr.baseSha, old);
});

test("openPullRequest refuses to push into the project repo unless told to, and opens a same-repo PR when it is", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  const same = { headRepo: { owner: "acme", repo: "proj" }, expectedTree: readmeTree(repo) };
  await assert.rejects(bridge(repo).openPullRequest(args(same)), (e: unknown) => e instanceof GitHubError && /fork/.test(e.message));
  await assert.rejects(bridge(repo).openPullRequest(args({ ...same, headRepo: { owner: "ACME", repo: "Proj" } })), /fork/);
  assert.equal(repo.rec.requests.length, 0);
  const pr = await bridge(repo).openPullRequest(args({ ...same, allowSameRepoHead: true }));
  assert.equal(repo.refs.get("refs/heads/commons/s"), pr.headSha);
  assert.equal((repo.rec.requests.at(-1)!.body as { head: string }).head, "commons/s");
});

test("openPullRequest refuses .github/ paths unless the caller allows each one", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  const patch = "diff --git a/.github/workflows/x.yml b/.github/workflows/x.yml\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/.github/workflows/x.yml\n@@ -0,0 +1 @@\n+on: push\n";
  const expectedTree = repo.treeOf({ ...MAIN_FILES(), ".github/workflows/x.yml": { mode: "100644", text: "on: push\n" } });
  await rejectsPatch(bridge(repo).openPullRequest(args({ patch, expectedTree })), /\.github\/workflows\/x\.yml: changes under \.github\/ need explicit approval/);
  await rejectsPatch(bridge(repo).openPullRequest(args({ patch, expectedTree, allowDotGithub: () => false })), /explicit approval/);
  const renamed = "diff --git a/README.md b/.GitHub/README.md\nsimilarity index 100%\nrename from README.md\nrename to .GitHub/README.md\n";
  await rejectsPatch(bridge(repo).openPullRequest(args({ patch: renamed, expectedTree })), /explicit approval/);
  assert.equal(repo.rec.requests.length, 0);
  const pr = await bridge(repo).openPullRequest(args({ patch, expectedTree, allowDotGithub: (p) => p === ".github/workflows/x.yml" }));
  assert.deepEqual(pr.files, [".github/workflows/x.yml"]);
});

test("openPullRequest refuses a title that could forge commit trailers", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  for (const title of ["x\n\nCommons-Submission: victim", "x\r", "", "   ", "a".repeat(257), "a‮b"]) {
    await assert.rejects(bridge(repo).openPullRequest(args({ title, expectedTree: SHA_A })), /title must be one line/);
  }
  assert.equal(repo.rec.requests.length, 0);
});

test("openPullRequest refuses patches that touch symlinks, submodules or existing paths, without writing", async () => {
  const cases: [string, RegExp][] = [
    ["diff --git a/link.ts b/link.ts\nindex 1111111..2222222\n--- a/link.ts\n+++ b/link.ts\n@@ -1 +1 @@\n-src/a.ts\n\\ No newline at end of file\n+/etc/passwd\n\\ No newline at end of file\n", /symlink/],
    ["diff --git a/vendor b/vendor\nindex 1111111..2222222\n--- a/vendor\n+++ b/vendor\n@@ -1 +1 @@\n-x\n+y\n", /commit, not a file/],
    ["diff --git a/vendor/x.ts b/vendor/x.ts\nnew file mode 100644\n", /not a directory/],
    ["diff --git a/README.md b/README.md\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b/README.md\n@@ -0,0 +1 @@\n+x\n", /already exists/],
    ["diff --git a/nope.ts b/nope.ts\nindex 1111111..2222222 100644\n--- a/nope.ts\n+++ b/nope.ts\n@@ -1 +1 @@\n-a\n+b\n", /does not exist/],
    ["diff --git a/scripts/run.sh b/scripts/run.sh\nindex 1111111..2222222 100644\n--- a/scripts/run.sh\n+++ b/scripts/run.sh\n@@ -1,2 +1,2 @@\n #!/bin/sh\n-echo hi\n+echo ho\n", /mode 100644, base commit has 100755/],
    ["diff --git a/src/b.ts b/src/b.ts\ndeleted file mode 100644\n", /does not remove the whole file/],
    ["diff --git a/src/a.ts b/src/a.ts\nindex 1111111..2222222 100644\n--- a/src/a.ts\n+++ b/src/a.ts\n@@ -2,1 +2,1 @@\n-line 3\n+three\n", /context mismatch/],
    // The refusal is the last section: earlier valid sections must not have written anything.
    [`diff --git a/src/new.ts b/src/new.ts\nnew file mode 100644\n${README_PATCH}diff --git a/src/a.ts b/src/a.ts\nindex 1111111..2222222 100644\n--- a/src/a.ts\n+++ b/src/a.ts\n@@ -20,1 +20,1 @@\n-line 21\n+x\n`, /context mismatch/],
  ];
  for (const [patch, re] of cases) {
    const repo = new FakeRepo();
    repo.seed("dev", MAIN_FILES());
    await rejectsPatch(bridge(repo).openPullRequest(args({ patch, expectedTree: SHA_A })), re);
    assert.deepEqual(repo.writes(), [], `no writes for a refused patch: ${patch}`);
  }
});

test("openPullRequest makes no request for a patch that does not parse, is too large, or a bad submission id", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  const gh = bridge(repo);
  await rejectsPatch(gh.openPullRequest(args({ patch: "diff --git a/../x b/../x\nnew file mode 100644\n", expectedTree: SHA_A })), /traversal/);
  const many = Array.from({ length: PATCH_LIMITS.files + 1 }, (_, i) => `diff --git a/e${i} b/e${i}\nnew file mode 100644\n`).join("");
  await rejectsPatch(gh.openPullRequest(args({ patch: many, expectedTree: SHA_A })), /more than 300 files/);
  for (const submissionId of ["../main", "a..b", "x.lock", "", "a/b", "-x"]) {
    await assert.rejects(gh.openPullRequest(args({ submissionId, expectedTree: SHA_A })), GitHubError);
  }
  await assert.rejects(gh.openPullRequest(args({ expectedTree: "HEAD^{tree}" })), /invalid commit sha/);
  assert.equal(repo.rec.requests.length, 0);
});

test("openPullRequest retried after a lost PR reply returns the PR it opened and deletes nothing", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  repo.dropPullsReply = true;
  const pr = await bridge(repo).openPullRequest(args({ submissionId: "s3", expectedTree: readmeTree(repo) }));
  assert.equal(pr.number, 7);
  assert.equal(pr.url, "https://github.com/acme/proj/pull/7");
  assert.equal(repo.pulls.length, 1);
  assert.equal(repo.forkRefs.get("refs/heads/commons/s3"), pr.headSha);
  assert.ok(!repo.writes().some((w) => w.startsWith("DELETE")));
});

test("openPullRequest called again for the same change reuses the branch and the open PR", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  const a = args({ submissionId: "s4", expectedTree: readmeTree(repo) });
  const first = await bridge(repo).openPullRequest(a);
  // An earlier attempt's commit: same tree and parent, different sha.
  const earlier = repo.commit(first.treeSha, [first.baseSha], "earlier attempt");
  repo.forkRefs.set("refs/heads/commons/s4", earlier);
  repo.pulls[0]!.head.sha = earlier;
  const second = await bridge(repo).openPullRequest(a);
  assert.equal(second.number, first.number);
  assert.equal(second.headSha, earlier);
  assert.equal(repo.pulls.length, 1);
  assert.ok(!repo.writes().some((w) => w.startsWith("DELETE")));
});

test("openPullRequest refuses an existing branch that holds a different change, and leaves it alone", async () => {
  const repo = new FakeRepo();
  const dev = repo.seed("dev", MAIN_FILES());
  repo.forkRefs.set("refs/heads/commons/s5", dev);
  await assert.rejects(
    bridge(repo).openPullRequest(args({ submissionId: "s5", expectedTree: readmeTree(repo) })),
    (e: unknown) => e instanceof GitHubError && e.status === 422 && /already exists in bot\/proj with a different change/.test(e.message),
  );
  assert.equal(repo.forkRefs.get("refs/heads/commons/s5"), dev);
  assert.equal(repo.pulls.length, 0);
  assert.ok(!repo.writes().some((w) => w.startsWith("DELETE") || w.endsWith("/pulls")));
});

test("openPullRequest reports a refused PR with its status and keeps the branch for a retry", async () => {
  const repo = new FakeRepo();
  repo.seed("dev", MAIN_FILES());
  repo.failPulls = { status: 422, body: { message: "Validation Failed", errors: [{ field: "base", code: "invalid" }] } };
  await assert.rejects(
    bridge(repo).openPullRequest(args({ submissionId: "s6", expectedTree: readmeTree(repo) })),
    (e: unknown) => e instanceof GitHubError && e.status === 422 && /Validation Failed/.test(e.message),
  );
  assert.ok(repo.forkRefs.has("refs/heads/commons/s6"));
  assert.ok(!repo.writes().some((w) => w.startsWith("DELETE")));
  repo.failPulls = null;
  assert.equal((await bridge(repo).openPullRequest(args({ submissionId: "s6", expectedTree: readmeTree(repo) }))).number, 7);
});

// ---------------------------------------------------------------------------
// findPullRequest, listChangedFiles
// ---------------------------------------------------------------------------

function pullBody(over: Record<string, unknown> = {}) {
  return {
    number: 9,
    html_url: "https://github.com/acme/proj/pull/9",
    state: "open",
    head: { sha: SHA_A, label: "bot:commons/s1", ref: "commons/s1" },
    base: { ref: "dev" },
    merged_at: null,
    merge_commit_sha: SHA_C,
    changed_files: 0,
    ...over,
  };
}

test("findPullRequest looks up the submission's branch and prefers a merged PR", async () => {
  const { fetch, requests } = recorder(() => ({
    status: 200,
    body: [
      pullBody({ number: 3, state: "closed" }),
      pullBody({ number: 4, state: "closed", merged_at: "2026-01-01T00:00:00Z", merge_commit_sha: SHA_B }),
      pullBody({ number: 5, head: { sha: SHA_A, label: "bot:commons/s10", ref: "commons/s10" } }),
    ],
  }));
  const gh = createGitHub({ token: TOKEN, fetch });
  const pr = await gh.findPullRequest("acme", "proj", "s1", "bot");
  assert.deepEqual(pr, {
    number: 4,
    url: "https://github.com/acme/proj/pull/9",
    state: "closed",
    merged: true,
    mergeCommitSha: SHA_B,
    headSha: SHA_A,
    headLabel: "bot:commons/s1",
    baseRef: "dev",
  });
  assert.equal(requests[0]!.path, "/repos/acme/proj/pulls?head=bot%3Acommons%2Fs1&state=all&per_page=100");
  const none = recorder(() => ({ status: 200, body: [] }));
  assert.equal(await createGitHub({ token: TOKEN, fetch: none.fetch }).findPullRequest("acme", "proj", "s1"), null);
  await assert.rejects(gh.findPullRequest("acme", "proj", "../x"), /cannot be a branch name/);
});

function filesPage(from: number, n: number) {
  return Array.from({ length: n }, (_, i) => ({ filename: `f${from + i}.ts`, status: "modified", additions: 1, deletions: 0 }));
}

test("listChangedFiles walks every page at the expected head and keeps rename sources", async () => {
  const { fetch, requests } = recorder((r) => {
    if (r.path === "/repos/acme/proj/pulls/9") return { status: 200, body: pullBody({ changed_files: 205 }) };
    const page = Number(new URL(r.url).searchParams.get("page"));
    const next = (p: number) => `<https://api.github.com/repositories/1/pulls/9/files?per_page=100&page=${p}>; rel="next", <https://api.github.com/repositories/1/pulls/9/files?per_page=100&page=3>; rel="last"`;
    if (page === 1) return { status: 200, body: filesPage(0, 100), link: next(2) };
    if (page === 2) return { status: 200, body: filesPage(100, 100), link: next(3) };
    const last = filesPage(200, 4);
    last.push({ filename: "new.ts", status: "renamed", additions: 0, deletions: 0, previous_filename: "old.ts" } as never);
    return { status: 200, body: last, link: '<https://api.github.com/repositories/1/pulls/9/files?page=1>; rel="first"' };
  });
  const files = await listChangedFiles("acme", "proj", 9, SHA_A, { token: TOKEN, fetch });
  assert.equal(files.length, 205);
  assert.equal(files[0]!.path, "f0.ts");
  assert.deepEqual(files.at(-1), { path: "new.ts", status: "renamed", additions: 0, deletions: 0, previousPath: "old.ts" });
  assert.deepEqual(
    requests.map((r) => r.path),
    [
      "/repos/acme/proj/pulls/9",
      "/repos/acme/proj/pulls/9/files?per_page=100&page=1",
      "/repos/acme/proj/pulls/9/files?per_page=100&page=2",
      "/repos/acme/proj/pulls/9/files?per_page=100&page=3",
      "/repos/acme/proj/pulls/9",
    ],
  );
});

test("listChangedFiles refuses a head other than the expected one, before or after listing", async () => {
  const before = recorder(() => ({ status: 200, body: pullBody({ head: { sha: SHA_B, label: "bot:commons/s1" } }) }));
  await assert.rejects(
    listChangedFiles("acme", "proj", 9, SHA_A, { token: TOKEN, fetch: before.fetch }),
    (e: unknown) => e instanceof GitHubError && e.status === 409 && /head is b{40}, expected a{40}/.test(e.message),
  );
  assert.equal(before.requests.length, 1, "no pages read for the wrong head");
  let reads = 0;
  const during = recorder((r) => {
    if (r.path === "/repos/acme/proj/pulls/9") {
      reads++;
      return { status: 200, body: pullBody({ changed_files: 1, head: { sha: reads === 1 ? SHA_A : SHA_B, label: "bot:commons/s1" } }) };
    }
    return { status: 200, body: filesPage(0, 1) };
  });
  await assert.rejects(listChangedFiles("acme", "proj", 9, SHA_A, { token: TOKEN, fetch: during.fetch }), /head is b{40}/);
  await assert.rejects(listChangedFiles("acme", "proj", 9, "HEAD", { token: TOKEN, fetch: during.fetch }), /invalid commit sha/);
});

test("listChangedFiles never follows a Link URL to another host", async () => {
  const { fetch, requests } = recorder((r) => {
    if (r.path === "/repos/acme/proj/pulls/9") return { status: 200, body: pullBody({ changed_files: 2 }) };
    const page = Number(new URL(r.url).searchParams.get("page"));
    return page === 1
      ? { status: 200, body: filesPage(0, 1), link: '<https://evil.example/steal>; rel="next"' }
      : { status: 200, body: filesPage(1, 1) };
  });
  await listChangedFiles("acme", "proj", 9, SHA_A, { token: TOKEN, fetch });
  assert.ok(requests.every((r) => r.url.startsWith("https://api.github.com/repos/acme/proj/")));
});

test("listChangedFiles refuses a list shorter than GitHub's file count", async () => {
  const { fetch } = recorder((r) =>
    r.path === "/repos/acme/proj/pulls/9" ? { status: 200, body: pullBody({ changed_files: 3001 }) } : { status: 200, body: filesPage(0, 3) },
  );
  await assert.rejects(listChangedFiles("acme", "proj", 9, SHA_A, { token: TOKEN, fetch }), /listed 3 files but GitHub reports 3001/);
});

// ---------------------------------------------------------------------------
// merge, fast-forward, comment
// ---------------------------------------------------------------------------

test("mergePullRequest squash-merges only at the given head sha", async () => {
  const { fetch, requests } = recorder(() => ({ status: 200, body: { sha: SHA_B, merged: true, message: "Pull Request successfully merged" } }));
  const gh = createGitHub({ token: TOKEN, fetch });
  assert.deepEqual(await gh.mergePullRequest("acme", "proj", 12, SHA_A, { title: "Fix (#12)", body: "Commons-Submission: s1" }), { sha: SHA_B });
  assert.equal(requests.length, 1);
  assert.equal(requests[0]!.method, "PUT");
  assert.equal(requests[0]!.path, "/repos/acme/proj/pulls/12/merge");
  assert.deepEqual(requests[0]!.body, { sha: SHA_A, merge_method: "squash", commit_title: "Fix (#12)", commit_message: "Commons-Submission: s1" });
});

test("the one-shot mergePullRequest takes the same merge options as the client", async () => {
  const { fetch, requests } = recorder(() => ({ status: 200, body: { sha: SHA_B, merged: true } }));
  await mergePullRequest("acme", "proj", 12, SHA_A, { title: "T" }, { token: TOKEN, fetch });
  assert.deepEqual(requests[0]!.body, { sha: SHA_A, merge_method: "squash", commit_title: "T" });
});

test("mergePullRequest surfaces a head-sha mismatch and refuses to merge without a sha", async () => {
  const { fetch, requests } = recorder((r) =>
    r.method === "PUT"
      ? { status: 409, body: { message: "Head branch was modified. Review and try the merge again." } }
      : { status: 200, body: pullBody({ number: 12, head: { sha: SHA_B, label: "bot:commons/s1" } }) },
  );
  const gh = createGitHub({ token: TOKEN, fetch });
  await assert.rejects(
    gh.mergePullRequest("acme", "proj", 12, SHA_A),
    (e: unknown) => e instanceof GitHubError && e.status === 409 && /Head branch was modified/.test(e.message),
  );
  for (const sha of ["", "HEAD", "abc123", SHA_A.toUpperCase()]) {
    await assert.rejects(gh.mergePullRequest("acme", "proj", 12, sha), /invalid commit sha/);
  }
  await assert.rejects(gh.mergePullRequest("acme", "proj", 0, SHA_A), /invalid pull request number/);
  assert.deepEqual(
    requests.map((r) => r.method),
    ["PUT", "GET"],
  );
});

test("mergePullRequest is idempotent: a PR already merged at the sha returns its merge commit", async () => {
  const merged = pullBody({ number: 12, state: "closed", merged_at: "2026-01-01T00:00:00Z", merge_commit_sha: SHA_B });
  const { fetch } = recorder((r) =>
    r.method === "PUT" ? { status: 405, body: { message: "Pull Request is not mergeable" } } : { status: 200, body: merged },
  );
  const gh = createGitHub({ token: TOKEN, fetch });
  assert.deepEqual(await gh.mergePullRequest("acme", "proj", 12, SHA_A), { sha: SHA_B });
  // With guards, the merged PR is recognised before the guards (the base has moved by the merge itself).
  assert.deepEqual(await gh.mergePullRequest("acme", "proj", 12, SHA_A, { expectedBase: SHA_C, expectedTree: SHA_C }), { sha: SHA_B });
  // Merged, but at another head: not this merge.
  await assert.rejects(gh.mergePullRequest("acme", "proj", 12, SHA_C), (e: unknown) => e instanceof GitHubError && e.status === 405);
});

test("mergePullRequest guards: the head tree and the base branch must be as expected", async () => {
  let baseTip = SHA_C;
  const { fetch, requests } = recorder((r) => {
    if (r.path === "/repos/acme/proj/pulls/12") return { status: 200, body: pullBody({ number: 12 }) };
    if (r.path === `/repos/acme/proj/git/commits/${SHA_A}`) return { status: 200, body: { sha: SHA_A, tree: { sha: SHA_B }, parents: [] } };
    if (r.path === "/repos/acme/proj/git/ref/heads/dev") return { status: 200, body: { object: { type: "commit", sha: baseTip } } };
    return { status: 200, body: { sha: "d".repeat(40), merged: true } };
  });
  const gh = createGitHub({ token: TOKEN, fetch });
  await assert.rejects(gh.mergePullRequest("acme", "proj", 12, SHA_A, { expectedTree: SHA_C }), /head tree is b{40}, expected c{40}/);
  await assert.rejects(gh.mergePullRequest("acme", "proj", 12, SHA_B, { expectedTree: SHA_B }), /head is a{40}, expected b{40}/);
  baseTip = SHA_B;
  await assert.rejects(
    gh.mergePullRequest("acme", "proj", 12, SHA_A, { expectedBase: SHA_C }),
    (e: unknown) => e instanceof GitHubError && e.status === 409 && /dev is at b{40}, expected c{40}/.test(e.message),
  );
  assert.ok(!requests.some((r) => r.method === "PUT"), "no merge attempted when a guard fails");
  baseTip = SHA_C;
  assert.deepEqual(await gh.mergePullRequest("acme", "proj", 12, SHA_A, { expectedTree: SHA_B, expectedBase: SHA_C }), { sha: "d".repeat(40) });
});

test("mergePullRequest treats merged: false as a failure", async () => {
  const { fetch } = recorder(() => ({ status: 200, body: { merged: false, message: "nope" } }));
  await assert.rejects(createGitHub({ token: TOKEN, fetch }).mergePullRequest("acme", "proj", 12, SHA_A), /not merged: nope/);
});

test("fastForward patches the ref without force and checks where it landed", async () => {
  const { fetch, requests } = recorder(() => ({ status: 200, body: { ref: "refs/heads/main", object: { sha: SHA_A, type: "commit" } } }));
  const gh = createGitHub({ token: TOKEN, fetch });
  assert.deepEqual(await gh.fastForward("acme", "proj", "main", SHA_A), { sha: SHA_A });
  assert.equal(requests[0]!.method, "PATCH");
  assert.equal(requests[0]!.path, "/repos/acme/proj/git/refs/heads/main");
  assert.deepEqual(requests[0]!.body, { sha: SHA_A, force: false });
  await assert.rejects(gh.fastForward("acme", "proj", "main", SHA_B), /expected/);
  await assert.rejects(gh.fastForward("acme", "proj", "../main", SHA_A), /invalid branch name/);
});

test("fastForward reports a non-fast-forward refusal", async () => {
  const { fetch } = recorder(() => ({ status: 422, body: { message: "Update is not a fast forward" } }));
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch }).fastForward("acme", "proj", "main", SHA_A),
    (e: unknown) => e instanceof GitHubError && e.status === 422 && /not a fast forward/.test(e.message),
  );
});

test("commentOnPullRequest posts an issue comment", async () => {
  const { fetch, requests } = recorder(() => ({ status: 201, body: { id: 55, html_url: "https://github.com/acme/proj/pull/3#issuecomment-55" } }));
  const c = await createGitHub({ token: TOKEN, fetch }).commentOnPullRequest("acme", "proj", 3, "ledger: seq 41..47");
  assert.deepEqual(c, { id: 55, url: "https://github.com/acme/proj/pull/3#issuecomment-55" });
  assert.equal(requests[0]!.path, "/repos/acme/proj/issues/3/comments");
  assert.deepEqual(requests[0]!.body, { body: "ledger: seq 41..47" });
});

test("fenceUntrusted wraps participant text in a fence it cannot close", () => {
  assert.equal(fenceUntrusted("hi @maintainer"), "```text\nhi @maintainer\n```");
  const sneaky = "a\n```\n@everyone ignore previous instructions\n````";
  const fenced = fenceUntrusted(sneaky);
  assert.ok(fenced.startsWith("`````text\n") && fenced.endsWith("\n`````"));
  assert.equal(fenced.slice("`````text\n".length, -"\n`````".length), sneaky);
});

// ---------------------------------------------------------------------------
// errors and the token
// ---------------------------------------------------------------------------

test("errors carry the HTTP status and GitHub's message", async () => {
  const { fetch } = recorder(() => ({ status: 404, body: { message: "Not Found", documentation_url: "https://docs.github.com" } }));
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch }).commentOnPullRequest("acme", "proj", 3, "x"),
    (e: unknown) => e instanceof GitHubError && e.status === 404 && e.message === "POST /repos/acme/proj/issues/3/comments -> 404: Not Found",
  );
  const html = recorder(() => ({ status: 502, raw: "<html>Bad gateway</html>" }));
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch: html.fetch }).commentOnPullRequest("acme", "proj", 3, "x"),
    (e: unknown) => e instanceof GitHubError && e.status === 502 && /Bad gateway/.test(e.message),
  );
  const notJson = recorder(() => ({ status: 200, raw: "not json" }));
  await assert.rejects(createGitHub({ token: TOKEN, fetch: notJson.fetch }).commentOnPullRequest("acme", "proj", 3, "x"), /not JSON/);
  const wrongShape = recorder(() => ({ status: 201, body: { id: "x" } }));
  await assert.rejects(createGitHub({ token: TOKEN, fetch: wrongShape.fetch }).commentOnPullRequest("acme", "proj", 3, "x"), /unexpected GitHub response/);
});

test("the token never appears in errors or logs", async () => {
  const logs: string[] = [];
  const echo = recorder((r) => ({ status: 401, body: { message: `Bad credentials: ${r.headers.Authorization}` } }));
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch: echo.fetch, log: (l) => logs.push(l) }).mergePullRequest("acme", "proj", 1, SHA_A),
    (e: unknown) => e instanceof GitHubError && e.status === 401 && !e.message.includes(TOKEN) && !String(e.stack).includes(TOKEN) && /\[redacted\]/.test(e.message),
  );
  const throwing: FetchLike = async (url, init) => {
    throw new Error(`connect ECONNREFUSED while sending ${init.headers.Authorization} to ${url}`);
  };
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch: throwing, log: (l) => logs.push(l) }).listChangedFiles("acme", "proj", 1, SHA_A),
    (e: unknown) => e instanceof GitHubError && e.status === 0 && /network error/.test(e.message) && !e.message.includes(TOKEN) && e.cause === undefined,
  );
  assert.ok(logs.length >= 2);
  for (const l of logs) assert.ok(!l.includes(TOKEN), l);
});

test("the token comes from COMMONS_GITHUB_TOKEN by default, and a missing token fails before any request", async () => {
  const saved = process.env[TOKEN_ENV];
  try {
    process.env[TOKEN_ENV] = "env-token-abcdef123456";
    const a = recorder(() => ({ status: 201, body: { id: 1, html_url: "u" } }));
    await createGitHub({ fetch: a.fetch }).commentOnPullRequest("acme", "proj", 1, "x");
    assert.equal(a.requests[0]!.headers.Authorization, "Bearer env-token-abcdef123456");

    delete process.env[TOKEN_ENV];
    const b = recorder(() => ({ status: 201, body: { id: 1, html_url: "u" } }));
    await assert.rejects(
      createGitHub({ fetch: b.fetch }).commentOnPullRequest("acme", "proj", 1, "x"),
      (e: unknown) => e instanceof GitHubError && e.status === 0 && /COMMONS_GITHUB_TOKEN/.test(e.message),
    );
    assert.equal(b.requests.length, 0);
  } finally {
    if (saved === undefined) delete process.env[TOKEN_ENV];
    else process.env[TOKEN_ENV] = saved;
  }
});

test("owner and repo are validated before they reach a URL", async () => {
  const { fetch, requests } = recorder(() => ({ status: 200, body: {} }));
  const gh = createGitHub({ token: TOKEN, fetch });
  await assert.rejects(gh.commentOnPullRequest("acme/../x", "proj", 1, "x"), /invalid repository/);
  await assert.rejects(gh.commentOnPullRequest("acme", "proj?x=1", 1, "x"), /invalid repository/);
  assert.equal(requests.length, 0);
});

test("a request that hangs times out with status 0 and aborts the fetch", async () => {
  let signal: AbortSignal | undefined;
  const hang: FetchLike = (_url, init) => {
    signal = init.signal;
    return new Promise(() => undefined);
  };
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch: hang, timeoutMs: 20 }).mergePullRequest("acme", "proj", 1, SHA_A),
    (e: unknown) => e instanceof GitHubError && e.status === 0 && /PUT \/repos\/acme\/proj\/pulls\/1\/merge: timeout after 20 ms/.test(e.message),
  );
  assert.equal(signal?.aborted, true);
  const slowBody: FetchLike = async () => ({ status: 200, headers: { get: () => null }, text: () => new Promise<string>(() => undefined) });
  await assert.rejects(createGitHub({ token: TOKEN, fetch: slowBody, timeoutMs: 20 }).commentOnPullRequest("acme", "proj", 1, "x"), /timeout/);
});

test("redirects are not followed, even to another host", async () => {
  const { fetch, requests } = recorder(() => ({ status: 307, body: { message: "Temporary Redirect", url: "https://evil.example/x" } }));
  await assert.rejects(
    createGitHub({ token: TOKEN, fetch }).mergePullRequest("acme", "proj", 1, SHA_A),
    (e: unknown) => e instanceof GitHubError && e.status === 307 && /redirect not followed/.test(e.message),
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0]!.init.redirect, "manual");
});
