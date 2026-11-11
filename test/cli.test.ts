import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { CliError, gitChanges, main, parseArgs, type Io, type ModuleName } from "../src/cli";
import { Ledger } from "../src/ledger";
import { claimStake, defaultRules, globToRegExp, ringOf } from "../src/rules";
import { createCoordinatorServer } from "../src/server";
import type { GateReport, Ring, Rules } from "../src/types";

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "src", "cli.ts");
const TSX = pathToFileURL(path.join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const T0 = "2026-01-01T00:00:00.000Z";

const tmp = (name: string) => fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), `cli-test-${name}-`));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type Run = { status: number; stdout: string; stderr: string };

// The real thing: a child process, the way CI and operators run it.
function spawnCli(cwd: string, ...args: string[]): Run {
  const r = spawnSync(process.execPath, ["--import", TSX, CLI, ...args], { cwd, encoding: "utf8", timeout: 60_000 });
  return { status: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

function ok(r: Run): string {
  assert.equal(r.status, 0, `exit ${r.status}\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
  return r.stdout;
}

const GIT_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "t",
  GIT_AUTHOR_EMAIL: "t@example.org",
  GIT_COMMITTER_NAME: "t",
  GIT_COMMITTER_EMAIL: "t@example.org",
  GIT_CONFIG_NOSYSTEM: "1",
};

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", ["-c", "commit.gpgsign=false", "-c", "protocol.file.allow=always", ...args], {
    cwd,
    env: GIT_ENV,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

function write(dir: string, rel: string, content: string): void {
  fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
  fs.writeFileSync(path.join(dir, rel), content);
}

function commitAll(dir: string, message: string): string {
  git(dir, "add", "-A");
  git(dir, "commit", "-q", "--allow-empty", "-m", message);
  return git(dir, "rev-parse", "HEAD");
}

function newRepo(dir: string): string {
  fs.mkdirSync(dir, { recursive: true });
  git(dir, "init", "-q", "-b", "main");
  return dir;
}

// In-process run with injected modules: lets tests cover the CLI's plumbing
// before the gate, selection and incentives modules exist.
async function runIn(cwd: string, args: string[], io: Partial<Io> = {}): Promise<Run> {
  let stdout = "";
  let stderr = "";
  const status = await main(args, {
    cwd,
    stdout: (t) => (stdout += t),
    stderr: (t) => (stderr += t),
    ...io,
  });
  return { status, stdout, stderr };
}

// Stand-ins for gates/rings, gates/airlock, gates/size and gates/specSeparation
// with the documented behaviour, simple enough to trust in a CLI test.
function fakeGates(): Record<string, unknown> {
  return {
    "gates/rings": {
      submissionRing: (files: string[], rules: Rules): Ring => Math.min(1, ...files.map((f) => ringOf(f, rules))) as Ring,
      checkRingImports: (_dir: string, _files: string[]): GateReport => ({ gate: "ringImports", pass: true, details: "no ring-2 imports" }),
    },
    "gates/airlock": {
      checkAirlock: (files: string[], rules: Rules, opts: { dependencyTrack: boolean }): GateReport => {
        const locked = files.filter((f) => rules.lockedPaths.some((g) => globToRegExp(g).test(f)));
        const pass = opts.dependencyTrack || locked.length === 0;
        return { gate: "airlock", pass, details: pass ? "no locked paths" : `locked: ${locked.join(", ")}` };
      },
    },
    "gates/size": {
      checkSize: (lines: number, rules: Rules): GateReport => ({
        gate: "size",
        pass: lines <= rules.maxLinesPerSubmission,
        details: `${lines} lines`,
      }),
    },
    "gates/specSeparation": {
      checkSpecSeparation: (): GateReport => ({ gate: "specSeparation", pass: true, details: "ok" }),
    },
  };
}

function loader(mods: Record<string, unknown>): (name: ModuleName) => unknown {
  return (name) => {
    if (name in mods) return mods[name];
    throw new CliError(2, `src/${name}.ts is not available (test)`);
  };
}

const exists = (rel: string) => fs.existsSync(path.join(ROOT, "src", rel));
const realGates = ["gates/rings.ts", "gates/airlock.ts", "gates/size.ts"].every(exists);
const NO_GATES = realGates ? false : "src/gates/{rings,airlock,size}.ts not written yet";

// ---------------------------------------------------------------------------
// Argument parser
// ---------------------------------------------------------------------------

test("parseArgs: values, =values, booleans, lists, required, unknown", () => {
  const spec = {
    a: { type: "string" as const, help: "" },
    b: { type: "boolean" as const, help: "" },
    c: { type: "list" as const, help: "" },
    d: { type: "string" as const, help: "", required: true },
  };
  const { flags, rest } = parseArgs(["--a", "1", "--b", "--c=x", "--c", "y", "--d=-5", "pos", "--", "--a"], spec);
  assert.deepEqual(flags, { a: "1", b: true, c: ["x", "y"], d: "-5" });
  assert.deepEqual(rest, ["pos", "--a"]);
  assert.throws(() => parseArgs(["--a", "1"], spec), /missing --d/);
  assert.throws(() => parseArgs(["--d", "1", "--zz"], spec), /unknown flag --zz/);
  assert.throws(() => parseArgs(["--d", "1", "--a"], spec), /--a needs a value/);
  assert.throws(() => parseArgs(["--d", "1", "--a", "--b"], spec), /--a needs a value/);
  assert.throws(() => parseArgs(["--d", "1", "--d", "2"], spec), /given twice/);
  assert.throws(() => parseArgs(["--d", "1", "--b=1"], spec), /takes no value/);
});

// ---------------------------------------------------------------------------
// The lifecycle, spawned: keygen → init → owner add → agent register →
// propose → task → claim → submit → gates
// ---------------------------------------------------------------------------

test("spawned: keygen, init, owner add, agent register, propose, task, claim, submit, gates", () => {
  const dir = tmp("flow");
  const L = ["--ledger", "ledger.jsonl"];
  const ids: Record<string, string> = {};
  for (const k of ["admin", "coord", "alice", "agent"]) {
    const out = ok(spawnCli(dir, "keygen", "--out", `${k}.json`)).trim();
    assert.match(out, /^[0-9a-f]{32}$/);
    ids[k] = out;
    assert.equal(fs.statSync(path.join(dir, `${k}.json`)).mode & 0o777, 0o600);
    const key = JSON.parse(fs.readFileSync(path.join(dir, `${k}.json`), "utf8")) as Record<string, unknown>;
    assert.deepEqual(Object.keys(key).sort(), ["privateKey", "publicKey"]);
  }
  const again = spawnCli(dir, "keygen", "--out", "admin.json");
  assert.equal(again.status, 2);
  assert.match(again.stderr, /already exists/);

  ok(spawnCli(dir, "init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--at", T0));
  assert.equal(spawnCli(dir, "init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json").status, 2);

  // Wrong key: an owner key may not bind owners; nothing is written.
  const before = fs.readFileSync(path.join(dir, "ledger.jsonl"), "utf8");
  ok(spawnCli(dir, "keygen", "--out", "bob.json"));
  const wrong = spawnCli(dir, "owner", "add", ...L, "--owner", "bob", "--owner-key", "bob.json", "--key", "bob.json");
  assert.equal(wrong.status, 1, wrong.stderr);
  assert.match(wrong.stderr, /refused the ownerKey entry \(signer-unknown\)/);
  assert.equal(fs.readFileSync(path.join(dir, "ledger.jsonl"), "utf8"), before);

  assert.match(ok(spawnCli(dir, "owner", "add", ...L, "--owner", "alice", "--owner-key", "alice.json", "--key", "admin.json")), /^#1 ownerKey/);
  ok(spawnCli(dir, "agent", "register", ...L, "--owner", "alice", "--agent-key", "agent.json", "--model-family", "claude", "--harness", "test", "--key", "alice.json"));

  // Missing flags: a usage error naming the flag, exit 2.
  const missing = spawnCli(dir, "propose", ...L, "--key", "agent.json");
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /missing --title \(see commons propose --help\)/);
  const noEvidence = spawnCli(dir, "propose", ...L, "--key", "agent.json", "--title", "x");
  assert.equal(noEvidence.status, 2);
  assert.match(noEvidence.stderr, /needs evidence/);

  assert.match(
    ok(spawnCli(dir, "propose", ...L, "--key", "agent.json", "--id", "p1", "--title", "a.ts mis-rounds", "--location", "src/a.ts:1:rounds down")),
    /^#3 proposal p1 /,
  );
  ok(spawnCli(dir, "task", ...L, "--key", "coord.json", "--id", "t1", "--proposal", "p1", "--ring", "1", "--acceptance-test", "test/a.test.ts", "--size", "40", "--spec-author", "alice"));
  // The coordinator's task, signed by an agent: refused.
  const agentTask = spawnCli(dir, "task", ...L, "--key", "agent.json", "--id", "t2", "--proposal", "p1", "--ring", "1", "--acceptance-test", "test/a.test.ts", "--size", "40", "--spec-author", "alice");
  assert.equal(agentTask.status, 1);
  assert.match(agentTask.stderr, /unauthorised/);

  const claim = ok(spawnCli(dir, "claim", ...L, "--key", "agent.json", "--task", "t1", "--hours", "12"));
  assert.match(claim, new RegExp(`stake ${claimStake(40, 1, defaultRules())}`));

  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "src/a.ts", "export const a = 1;\n");
  const base = commitAll(repo, "base");
  write(repo, "src/a.ts", "export const a = 2;\nexport const b = 3;\n");
  const head = commitAll(repo, "head");
  assert.match(
    ok(spawnCli(dir, "submit", ...L, "--key", "agent.json", "--id", "s1", "--task", "t1", "--base", base, "--head", head, "--repo", "repo")),
    /submission s1 .* 1 files, 3 lines/,
  );
  const st = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  const s = st.submissions.get("s1");
  assert.deepEqual(s?.changedFiles, ["src/a.ts"]);
  assert.equal(s?.linesChanged, 3);
  assert.equal(s?.author, ids.agent);

  const help = ok(spawnCli(dir, "submit", "--help"));
  assert.match(help, /--repo <value>/);
  assert.equal(spawnCli(dir, "nonsense").status, 2);
  assert.match(spawnCli(dir, "review").stderr, /needs a subcommand: commit, reveal/);

  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(defaultRules()));
  const gates = spawnCli(dir, "gates", "--repo", "repo", "--base", base, "--head", head, "--rules", "rules.json");
  if (!realGates) {
    // Without the gate modules nothing can pass: a harness error, never green.
    assert.equal(gates.status, 2, gates.stdout + gates.stderr);
    assert.match(gates.stdout, /gates: FAIL/);
    assert.match(gates.stderr, /not available/);
  } else {
    assert.equal(gates.status, 0, gates.stdout + gates.stderr);
    assert.match(gates.stdout, /gates: PASS/);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// gates (CI mode)
// ---------------------------------------------------------------------------

function ciRepo(): { dir: string; repo: string; base: string; head: string } {
  const dir = tmp("gates");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "anthill-backend/src/engine.ts", "export const k = 1;\n");
  write(repo, "package-lock.json", "{}\n");
  write(repo, "docs/x.md", "x\n");
  const base = commitAll(repo, "base");
  write(repo, "anthill-backend/src/engine.ts", "export const k = 2;\n");
  write(repo, "package-lock.json", '{"lockfileVersion":3}\n');
  fs.rmSync(path.join(repo, "docs/x.md"));
  write(repo, "docs/y.md", "y\n");
  const head = commitAll(repo, "head");
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(anthillLikeRules()));
  return { dir, repo, base, head };
}

// defaultRules() classifies anthill-backend/src/engine.ts as ring 0 and
// package-lock.json as locked, like the Anthill rules.
function anthillLikeRules(): Rules {
  return defaultRules();
}

test("gates: ring-0 change and a lockfile change fail the airlock (injected gates)", async () => {
  const { dir, repo, base, head } = ciRepo();
  const args = ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"];
  const r = await runIn(dir, args, { load: loader(fakeGates()) });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /changed files: 4, lines changed: 6/);
  assert.match(r.stdout, /\[ring 0\] anthill-backend\/src\/engine\.ts/);
  assert.match(r.stdout, /docs\/x\.md/); // deletions count as changed files
  assert.match(r.stdout, /submission ring: 0/);
  assert.match(r.stdout, /FAIL airlock: locked: package-lock\.json/);
  assert.match(r.stdout, /gates: FAIL/);

  const dep = await runIn(dir, [...args, "--dependency-track", "--json"], { load: loader(fakeGates()) });
  assert.equal(dep.status, 0, dep.stdout + dep.stderr);
  const j = JSON.parse(dep.stdout) as { pass: boolean; ring: number; files: string[]; linesChanged: number; reports: GateReport[] };
  assert.equal(j.pass, true);
  assert.equal(j.ring, 0);
  assert.deepEqual(j.files, ["anthill-backend/src/engine.ts", "docs/x.md", "docs/y.md", "package-lock.json"]);
  assert.equal(j.linesChanged, 6);
  assert.deepEqual(j.reports.map((x) => x.gate), ["ringImports", "airlock", "size"]);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("gates: usage and harness errors exit 2, never pass", async () => {
  const { dir, repo, base, head } = ciRepo();
  const load = loader(fakeGates());
  // Missing flags.
  assert.equal((await runIn(dir, ["gates", "--repo", repo, "--base", base, "--rules", "rules.json"], { load })).status, 2);
  // Invalid rules.
  fs.writeFileSync(path.join(dir, "bad.json"), JSON.stringify({ ...defaultRules(), maxLinesPerSubmission: -1 }));
  const bad = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "bad.json"], { load });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /rules bad\.json are invalid/);
  // Unknown commit.
  const unknown = await runIn(dir, ["gates", "--repo", repo, "--base", "0".repeat(40), "--head", head, "--rules", "rules.json"], { load });
  assert.equal(unknown.status, 2);
  // An option smuggled in as a commit.
  assert.equal((await runIn(dir, ["gates", "--repo", repo, "--base=--output=x", "--head", head, "--rules", "rules.json"], { load })).status, 2);
  // Working tree not at --head: the import gate would read the wrong files.
  const notHead = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", base, "--rules", "rules.json"], { load });
  assert.equal(notHead.status, 2);
  assert.match(notHead.stderr, /checked out at/);
  // A gate that throws is a harness error.
  const throwing = { ...fakeGates(), "gates/size": { checkSize: () => { throw new Error("boom"); } } };
  const t = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json", "--dependency-track"], { load: loader(throwing) });
  assert.equal(t.status, 2);
  assert.match(t.stdout, /FAIL size: could not run: boom/);
  // Missing gate modules.
  const none = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"], { load: loader({}) });
  assert.equal(none.status, 2);
  assert.match(none.stdout, /gates: FAIL/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("gates: a submodule pointer change is expanded into the submodule's files", async () => {
  const dir = tmp("submodule");
  const sub = newRepo(path.join(dir, "backend-origin"));
  write(sub, "src/engine.ts", "a\n");
  write(sub, "README.md", "r\n");
  commitAll(sub, "sub base");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "top\n");
  git(repo, "submodule", "add", "-q", sub, "anthill-backend");
  const base = commitAll(repo, "base");
  write(sub, "src/engine.ts", "b\nc\n");
  const subHead = commitAll(sub, "sub head");
  git(path.join(repo, "anthill-backend"), "fetch", "-q", "origin");
  git(path.join(repo, "anthill-backend"), "checkout", "-q", subHead);
  write(repo, "README.md", "top2\n");
  const head = commitAll(repo, "bump");

  const change = gitChanges((cwd, args, input) => execFileSync("git", args, { cwd, encoding: "utf8", input }), repo, base, head);
  assert.deepEqual(change.files, ["README.md", "anthill-backend/src/engine.ts"]);
  assert.equal(change.linesChanged, 2 + 3);
  assert.deepEqual(change.unexpanded, []);
  assert.deepEqual(change.submodules, [{ path: "anthill-backend", sha: subHead }]);

  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(defaultRules()));
  const r = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"], { load: loader(fakeGates()) });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /\[ring 0\] anthill-backend\/src\/engine\.ts/);

  // An uninitialised submodule cannot be expanded: the bare pointer is reported.
  const bare = path.join(dir, "bare");
  git(dir, "clone", "-q", repo, bare);
  const c2 = gitChanges((cwd, args, input) => execFileSync("git", args, { cwd, encoding: "utf8", input }), bare, base, head);
  assert.deepEqual(c2.files, ["README.md", "anthill-backend"]);
  assert.equal(c2.unexpanded[0]?.path, "anthill-backend");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("spawned gates with the real gate modules", { skip: NO_GATES }, () => {
  const { dir, repo, base, head } = ciRepo();
  const r = spawnCli(dir, "gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json");
  assert.equal(r.status, 1, r.stdout + r.stderr); // the lockfile is locked
  assert.match(r.stdout, /submission ring: 0/);
  assert.match(r.stdout, /FAIL/);
  const dep = spawnCli(dir, "gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json", "--dependency-track");
  assert.equal(dep.status, 0, dep.stdout + dep.stderr);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("delta: usage errors exit 2", () => {
  const dir = tmp("delta");
  const r = spawnCli(dir, "delta", "--old", "a", "--new", "b", "--log", "l.jsonl");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /missing --manifest/);
  const r2 = spawnCli(dir, "delta", "--old", "a", "--new", "b", "--log", "l.jsonl", "--manifest", "m.json");
  assert.equal(r2.status, 2);
  assert.match(r2.stderr, /--old .* does not exist/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// The rest of the lifecycle, in process with injected modules
// ---------------------------------------------------------------------------

test("in process: gates --record, assign, review commit/reveal, merge, snapshot, signoff, plants", async () => {
  const dir = tmp("lifecycle");
  const L = ["--ledger", "ledger.jsonl"];
  let clock = Date.parse(T0);
  const io = (mods: Record<string, unknown> = {}): Partial<Io> => ({ now: () => new Date((clock += 60_000)), load: loader({ ...fakeGates(), ...mods }) });
  const run = async (...args: string[]) => {
    const r = await runIn(dir, args, io());
    assert.equal(r.status, 0, `${args.join(" ")}\n${r.stdout}${r.stderr}`);
    return r.stdout;
  };
  const keyIds: Record<string, string> = {};
  for (const k of ["admin", "coord", "alice", "bob", "a1", "b1"]) keyIds[k] = (await run("keygen", "--out", `${k}.json`)).trim();
  await run("init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "alice", "--owner-key", "alice.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "bob", "--owner-key", "bob.json");
  await run("agent", "register", ...L, "--key", "alice.json", "--owner", "alice", "--agent-key", "a1.json", "--model-family", "claude", "--harness", "h");
  await run("agent", "register", ...L, "--key", "bob.json", "--owner", "bob", "--agent-key", "b1.json", "--model-family", "gpt", "--harness", "h");

  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "src/a.ts", "1\n");
  const base = commitAll(repo, "base");
  write(repo, "src/a.ts", "2\n");
  const head = commitAll(repo, "head");
  git(repo, "checkout", "-q", base); // ledger mode must not depend on what is checked out

  // An untasked ring-1 change; declared files that lie about the change fail declaredChange.
  await run("submit", ...L, "--key", "a1.json", "--id", "s-lie", "--base", base, "--head", head, "--files", "src/other.ts", "--lines", "2");
  const lie = await runIn(dir, ["gates", ...L, "--repo", repo, "--submission", "s-lie"], io());
  assert.equal(lie.status, 1, lie.stdout + lie.stderr);
  assert.match(lie.stdout, /FAIL declaredChange: .*undeclared src\/a\.ts/);

  await run("submit", ...L, "--key", "a1.json", "--id", "s1", "--base", base, "--head", head, "--repo", repo);
  const g = await run("gates", ...L, "--repo", repo, "--submission", "s1", "--record", "--key", "coord.json");
  assert.match(g, /recorded 5 gate results/);
  assert.equal(git(repo, "worktree", "list").split("\n").length, 1, "temporary worktree removed");

  // assign with an injected selection, which also needs a tree.
  fs.writeFileSync(path.join(dir, "tree.json"), JSON.stringify({ parents: { root: null, alice: "root", bob: "root" } }));
  const selection = {
    computeBeacon: (_s: unknown, sid: string, entropy: string) => `beacon-${sid}-${entropy}`,
    selectReviewers: () => ({ reviewers: [keyIds.b1], candidates: 1, notes: [] }),
  };
  const noTree = await runIn(dir, ["assign", ...L, "--key", "coord.json", "--submission", "s1"], io({ selection }));
  assert.equal(noTree.status, 2);
  assert.match(noTree.stderr, /needs the trust tree/);
  await runIn(dir, ["assign", ...L, "--key", "coord.json", "--submission", "s1", "--tree", "tree.json", "--entropy", "e"], io({ selection }));
  assert.equal(Ledger.open(path.join(dir, "ledger.jsonl")).state().submissions.get("s1")?.assignment?.beacon, "beacon-s1-e");

  // review commit/reveal: the salt lives next to the key.
  await run("review", "commit", ...L, "--key", "b1.json", "--submission", "s1", "--probability", "0.1", "--summary", "fine");
  const record = path.join(dir, "b1.json.salts", "s1.json");
  assert.equal(fs.statSync(record).mode & 0o777, 0o600);
  const dup = await runIn(dir, ["review", "commit", ...L, "--key", "b1.json", "--submission", "s1", "--probability", "0.2"], io());
  assert.equal(dup.status, 2);
  assert.match(dup.stderr, /already recorded/);
  // A refused commit leaves no salt behind.
  const refused = await runIn(dir, ["review", "commit", ...L, "--key", "a1.json", "--submission", "nope", "--probability", "0.2"], io());
  assert.equal(refused.status, 1);
  assert.equal(fs.existsSync(path.join(dir, "a1.json.salts", "nope.json")), false);
  const badVerdict = await runIn(dir, ["review", "commit", ...L, "--key", "b1.json", "--submission", "s1", "--probability", "2"], io());
  assert.equal(badVerdict.status, 2);
  await run("review", "reveal", ...L, "--key", "b1.json", "--submission", "s1");
  const st1 = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.equal(st1.submissions.get("s1")?.reviews[0]?.verdict?.summary, "fine");

  await run("merge", ...L, "--key", "coord.json", "--submission", "s1", "--commit", head);
  assert.match(await run("snapshot", ...L, "--key", "coord.json"), /snapshot snapshot-1 .*1 submissions at/);
  const st2 = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.deepEqual(st2.snapshots.get("snapshot-1")?.submissionIds, ["s1"]);
  assert.equal(st2.snapshots.get("snapshot-1")?.previousSnapshotId, null);

  // signoff by an owner who is not a kernel signer: refused.
  const so = await runIn(dir, ["signoff", ...L, "--key", "alice.json", "--snapshot", "snapshot-1"], io());
  assert.equal(so.status, 1);

  // plants: the commitment is made by an admin, the salt kept next to its key.
  await run("plant", "commit", ...L, "--key", "admin.json", "--submission", "s-plant");
  assert.ok(fs.existsSync(path.join(dir, "admin.json.salts", "plants", "s-plant.json")));
  const st3 = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.equal(st3.plantCommitments.length, 1);
  const notAdmin = await runIn(dir, ["plant", "commit", ...L, "--key", "alice.json", "--submission", "s-x"], io());
  assert.equal(notAdmin.status, 1);
  assert.equal(fs.existsSync(path.join(dir, "alice.json.salts", "plants", "s-x.json")), false);

  // settle with injected incentives that owe alice a merge reward once.
  const incentives = {
    settleFinding: () => [],
    settleMerge: (_s: unknown, sid: string, tranche: number) =>
      tranche === 1 ? [{ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: `${sid}:1` }] : [],
    settleCleanReviews: () => [],
    settleMissedPlant: () => [],
    settleFalseFinding: () => [],
    settleExpiredClaims: () => [],
    settleHoneytoken: () => [],
  };
  const s1 = await runIn(dir, ["settle", ...L, "--key", "coord.json", "--tree", "tree.json"], io({ incentives }));
  assert.equal(s1.status, 0, s1.stderr);
  assert.match(s1.stdout, /alice \+10 mergeVest/);
  const s2 = await runIn(dir, ["settle", ...L, "--key", "coord.json", "--tree", "tree.json"], io({ incentives }));
  assert.match(s2.stdout, /^0 settlements/m);

  // metrics with an injected module: table and JSON.
  const metrics = { computeMetrics: () => [{ group: "review", metric: "reveal rate", value: 1, bad: false, note: "all revealed" }] };
  const m = await runIn(dir, ["metrics", ...L, "--tree", "tree.json"], io({ metrics }));
  assert.match(m.stdout, /reveal rate\s+1\s+all revealed/);
  const mj = await runIn(dir, ["metrics", ...L, "--tree", "tree.json", "--json"], io({ metrics }));
  assert.equal((JSON.parse(mj.stdout) as unknown[]).length, 1);

  // promote check with an injected promotion that fails: exit 1, nothing appended by run.
  const promotion = { evaluatePromotion: () => ({ pass: false, checks: [{ name: "seeds", pass: false, detail: "0 < 30" }] }) };
  const pc = await runIn(dir, ["promote", "check", ...L, "--tree", "tree.json", "--snapshot", "snapshot-1"], io({ promotion }));
  assert.equal(pc.status, 1);
  assert.match(pc.stdout, /FAIL seeds: 0 < 30/);
  const len = Ledger.open(path.join(dir, "ledger.jsonl")).entries().length;
  const pr = await runIn(dir, ["promote", "run", ...L, "--key", "coord.json", "--tree", "tree.json", "--snapshot", "snapshot-1"], io({ promotion }));
  assert.equal(pr.status, 1);
  assert.equal(Ledger.open(path.join(dir, "ledger.jsonl")).entries().length, len);

  fs.rmSync(dir, { recursive: true, force: true });
});

test("in process: --url posts through the coordinator API", async () => {
  const dir = tmp("remote");
  let clock = Date.now();
  const io: Partial<Io> = { now: () => new Date((clock += 1000)), load: loader({}) };
  const run = async (...args: string[]) => {
    const r = await runIn(dir, args, io);
    assert.equal(r.status, 0, `${args.join(" ")}\n${r.stdout}${r.stderr}`);
    return r.stdout;
  };
  for (const k of ["admin", "coord", "alice", "a1"]) await run("keygen", "--out", `${k}.json`);
  const L = ["--ledger", "ledger.jsonl"];
  await run("init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "alice", "--owner-key", "alice.json");

  const coordinatorKey = JSON.parse(fs.readFileSync(path.join(dir, "coord.json"), "utf8")) as { publicKey: string; privateKey: string };
  const server = createCoordinatorServer({
    ledgerPath: path.join(dir, "ledger.jsonl"),
    coordinatorKey,
    tree: { root: () => "alice", has: () => true, parent: () => null, children: () => [], depth: () => 0, distance: () => 0, members: () => ["alice"], reputation: () => 0 },
    clock: () => new Date(clock).toISOString(),
    patchesDir: path.join(dir, "patches"),
    policy: { submitCredits: () => 10, prSlots: () => 10, claimStake },
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    await run("agent", "register", "--url", url, "--key", "alice.json", "--owner", "alice", "--agent-key", "a1.json", "--model-family", "claude", "--harness", "h");
    assert.match(await run("propose", "--url", url, "--key", "a1.json", "--id", "p1", "--title", "t", "--failing-test", "t1=npm test"), /proposal p1/);
    const dup = await runIn(dir, ["propose", "--url", url, "--key", "a1.json", "--id", "p1", "--title", "t", "--failing-test", "t1=npm test"], io);
    assert.equal(dup.status, 1);
    assert.match(dup.stderr, /coordinator refused/);
    // Coordinator kinds are not postable: task has no --url flag at all.
    assert.equal((await runIn(dir, ["task", "--url", url], io)).status, 2);
    // Defaults that need the ledger must be explicit over --url.
    const claim = await runIn(dir, ["claim", "--url", url, "--key", "a1.json", "--task", "t1"], io);
    assert.equal(claim.status, 2);
    assert.match(claim.stderr, /with --url, pass --stake/);
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
  assert.equal(server.store.state().proposals.get("p1")?.title, "t");
  fs.rmSync(dir, { recursive: true, force: true });
});

test("in process: coordinator run-once gates then assigns; serve starts playground and API", async () => {
  const dir = tmp("coordinator");
  const L = ["--ledger", "ledger.jsonl"];
  let clock = Date.now();
  const keyIds: Record<string, string> = {};
  const incentives = {
    settleFinding: () => [],
    settleMerge: () => [],
    settleCleanReviews: () => [],
    settleMissedPlant: () => [],
    settleFalseFinding: () => [],
    settleExpiredClaims: () => [],
    settleHoneytoken: () => [],
    submitCredits: () => 10,
    prSlots: () => 10,
    claimStake,
  };
  const mods = {
    ...fakeGates(),
    incentives,
    promotion: { evaluatePromotion: () => ({ pass: false, checks: [] }) },
    selection: {
      computeBeacon: () => "beacon",
      selectReviewers: () => ({ reviewers: [keyIds.b1], candidates: 1, notes: [] }),
    },
    playground: {
      startPlayground: (o: { port: number; host?: string }) => {
        const s = http.createServer((_q, r) => r.end("playground"));
        s.listen(o.port, o.host);
        return s;
      },
    },
  };
  const io = (extra: Partial<Io> = {}): Partial<Io> => ({ now: () => new Date((clock += 1000)), load: loader(mods), ...extra });
  const run = async (...args: string[]) => {
    const r = await runIn(dir, args, io());
    assert.equal(r.status, 0, `${args.join(" ")}\n${r.stdout}${r.stderr}`);
    return r.stdout;
  };
  for (const k of ["admin", "coord", "alice", "bob", "a1", "b1"]) keyIds[k] = (await run("keygen", "--out", `${k}.json`)).trim();
  await run("init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "alice", "--owner-key", "alice.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "bob", "--owner-key", "bob.json");
  await run("agent", "register", ...L, "--key", "alice.json", "--owner", "alice", "--agent-key", "a1.json", "--model-family", "claude", "--harness", "h");
  await run("agent", "register", ...L, "--key", "bob.json", "--owner", "bob", "--agent-key", "b1.json", "--model-family", "gpt", "--harness", "h");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "src/a.ts", "1\n");
  const base = commitAll(repo, "base");
  write(repo, "src/a.ts", "2\n");
  const head = commitAll(repo, "head");
  await run("submit", ...L, "--key", "a1.json", "--id", "s1", "--base", base, "--head", head, "--repo", repo);
  fs.writeFileSync(path.join(dir, "tree.json"), JSON.stringify({ root: null, alice: "root", bob: "root" }));

  const once = ["coordinator", "run-once", ...L, "--key", "coord.json", "--tree", "tree.json", "--repo", repo];
  assert.match(await run(...once), /ok {3}runGates s1: declaredChange:pass/);
  assert.match(await run(...once), /ok {3}assignReviewers s1/);
  const st = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.deepEqual(st.submissions.get("s1")?.assignment?.reviewers, [keyIds.b1]);
  // Nothing left but the merge, which waits for a reveal and a human.
  assert.match(await run(...once), /nothing to do/);
  // The wrong key is refused before anything runs.
  const wrongKey = await runIn(dir, [...once.slice(0, 4), "--key", "a1.json", "--tree", "tree.json"], io());
  assert.equal(wrongKey.status, 2);
  assert.match(wrongKey.stderr, /--key: coordinator key does not match the genesis coordinator/);

  let stop!: () => void;
  const until = new Promise<void>((r) => (stop = r));
  const out: string[] = [];
  const serving = main(["serve", ...L, "--tree", "tree.json", "--port", "0", "--coordinator", "--key", "coord.json"], {
    ...io(),
    cwd: dir,
    until,
    stdout: (t) => void out.push(t),
    stderr: (t) => void out.push(t),
  });
  const deadline = Date.now() + 5000;
  while (out.filter((l) => /on http:\/\//.test(l)).length < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
  const apiUrl = /coordinator API on (http:\/\/\S+)/.exec(out.join(""))?.[1];
  const pgUrl = /playground on (http:\/\/\S+)/.exec(out.join(""))?.[1];
  assert.ok(apiUrl && pgUrl, out.join(""));
  const h = (await (await fetch(`${apiUrl}/api/head`)).json()) as { nextSeq: number };
  assert.equal(h.nextSeq, st.length);
  assert.equal(await (await fetch(pgUrl)).text(), "playground");
  stop();
  assert.equal(await serving, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

const BACKEND = path.join(ROOT, "..", "anthill-backend");
const NO_BACKEND = fs.existsSync(path.join(BACKEND, "src", "store.ts")) ? false : "no anthill-backend checkout next to anthill-commons";

test("spawned delta: identical checkouts pass; a missing manifest fails", { skip: NO_BACKEND }, () => {
  const dir = tmp("delta-real");
  const log = path.join(dir, "log.jsonl");
  execFileSync(process.execPath, ["--import", TSX, path.join(ROOT, "scripts", "make-anthill-fixture-log.ts"), "--backend", BACKEND, "--out", log], {
    cwd: ROOT,
    stdio: "ignore",
  });
  fs.writeFileSync(path.join(dir, "m.json"), '{"declared":[]}');
  const pass = spawnCli(dir, "delta", "--old", BACKEND, "--new", BACKEND, "--log", log, "--manifest", "m.json");
  assert.equal(pass.status, 0, pass.stdout + pass.stderr);
  assert.match(pass.stdout, /^PASS behaviourDelta/);
  const json = spawnCli(dir, "delta", "--old", BACKEND, "--new", BACKEND, "--log", log, "--manifest", "m.json", "--json");
  assert.equal((JSON.parse(json.stdout) as { pass: boolean }).pass, true);
  const missing = spawnCli(dir, "delta", "--old", BACKEND, "--new", BACKEND, "--log", log, "--manifest", "absent.json");
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /^FAIL behaviourDelta: manifest/);
  fs.rmSync(dir, { recursive: true, force: true });
});
