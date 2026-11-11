import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import * as fs from "node:fs";
import * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import {
  bindPatchLocal,
  CliError,
  gitChanges,
  localGitBridge,
  main,
  sandboxLeaks,
  parseArgs,
  type AirlockApi,
  type GatesIndexApi,
  type Io,
  type MetricsApi,
  type ModuleName,
  type PlaygroundApi,
  type RingsApi,
  type SizeApi,
  type SpecSeparationApi,
} from "../src/cli";
import type { IncentivesApi, PromotionApi, SelectionApi } from "../src/coordinator";
import * as gatesIndex from "../src/gates";
import * as airlock from "../src/gates/airlock";
import * as rings from "../src/gates/rings";
import * as size from "../src/gates/size";
import * as spec from "../src/gates/specSeparation";
import * as incentives from "../src/incentives";
import * as metrics from "../src/metrics";
import * as playground from "../src/playground";
import * as promotion from "../src/promotion";
import * as selection from "../src/selection";
import { commonsCommit } from "../src/client";
import { MergeConflictError } from "../src/coordinator";
import { Ledger } from "../src/ledger";
import { assignmentBeacon } from "../src/review";
import { memberDigest } from "../src/members";
import { ringOf } from "../src/gates/rings";
import { claimStake, defaultRules, globToRegExp, phase1Rules } from "../src/rules";
import { createCoordinatorServer, type SubmitPolicy } from "../src/server";
import type { GateReport, Ring, Rules } from "../src/types";

const ROOT = path.join(__dirname, "..");
const CLI = path.join(ROOT, "src", "cli.ts");
const TSX = pathToFileURL(path.join(ROOT, "node_modules", "tsx", "dist", "loader.mjs")).href;
const T0 = "2026-01-01T00:00:00.000Z";

// An example target project's rules, as its .commons/rules.json would declare
// them (defaultRules names no project paths): a kernel file and a UI
// directory in ring 2, after the generic defaults.
function projectRules(): Rules {
  const r = defaultRules();
  r.rings = [{ glob: "server/src/engine.ts", ring: 0 }, ...r.rings, { glob: "web/**", ring: 2 }];
  return r;
}

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

// Work happens on dev, the branch the coordinator merges onto and every base
// must be on (cli.baseProblem).
function newRepo(dir: string): string {
  fs.mkdirSync(dir, { recursive: true });
  git(dir, "init", "-q", "-b", "dev");
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

// Stand-ins for the gate modules with the documented behaviour, simple enough
// to trust in a CLI plumbing test (harness errors, lifecycle wiring). The
// verdict tests below use the real modules.
function fakeGates(): Record<string, unknown> {
  return {
    "gates/rings": {
      submissionRing: (files: string[], rules: Rules): Ring => Math.min(1, ...files.map((f) => ringOf(f, rules))) as Ring,
      checkRingImports: (_dir: string, _files: string[]): GateReport => ({ gate: "rings", pass: true, details: "no ring-2 imports" }),
    },
    "gates/airlock": {
      checkAirlock: (files: string[], rules: Rules, opts: { dependencyTrack: boolean }): GateReport => {
        const locked = files.filter((f) => rules.lockedPaths.some((g) => globToRegExp(g).test(f)));
        const pass = opts.dependencyTrack || locked.length === 0;
        return { gate: "airlock", pass, details: pass ? "no locked paths" : `locked: ${locked.join(", ")}` };
      },
    },
    "gates/size": {
      checkSize: (change: { linesChanged: number }, rules: Rules): GateReport => ({
        gate: "size",
        pass: change.linesChanged <= rules.maxLinesPerSubmission,
        details: `${change.linesChanged} lines`,
      }),
    },
    "gates/specSeparation": {
      checkSpecSeparation: (): GateReport => ({ gate: "specSeparation", pass: true, details: "ok" }),
    },
    gates: { checkTaskRing: (): GateReport | null => null },
  };
}

// Only the injected modules: anything else is "not available".
function loader(mods: Record<string, unknown>): (name: ModuleName) => unknown {
  return (name) => {
    if (name in mods) return mods[name];
    throw new CliError(2, `src/${name}.ts is not available (test)`);
  };
}

// The injected modules, and the real one for every other name.
function withReal(mods: Record<string, unknown>): (name: ModuleName) => unknown {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  return (name) => (name in mods ? mods[name] : (require(path.join(ROOT, "src", name)) as unknown));
}

// The contracts the CLI and the coordinator load modules through (Io.load,
// lazy proxies) are typed by hand; the real modules must satisfy them, or a
// signature change (say a new nowIso) only shows up at run time.
test("the real modules satisfy the contracts the CLI and coordinator load them through", () => {
  const contracts: {
    rings: RingsApi;
    airlock: AirlockApi;
    size: SizeApi;
    spec: SpecSeparationApi;
    index: GatesIndexApi;
    metrics: MetricsApi;
    playground: PlaygroundApi;
    selection: SelectionApi;
    incentives: IncentivesApi & SubmitPolicy;
    promotion: PromotionApi;
  } = { rings, airlock, size, spec, index: gatesIndex, metrics, playground, selection, incentives, promotion };
  for (const [name, mod] of Object.entries(contracts)) assert.equal(typeof mod, "object", name);
});

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

  // --at far from the clock would freeze the ledger (and settle/promote judge
  // "now" by it): refused unless --force-time, and nothing is created.
  const skewed = spawnCli(dir, "init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--at", T0);
  assert.equal(skewed.status, 2, skewed.stderr);
  assert.match(skewed.stderr, /more than 5 minutes from the clock/);
  assert.equal(fs.existsSync(path.join(dir, "ledger.jsonl")), false);
  ok(spawnCli(dir, "init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--at", T0, "--force-time"));
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
  // The patch git produced is stored where the coordinator would keep it.
  assert.match(fs.readFileSync(path.join(dir, "patches", "s1.diff"), "utf8"), /^diff --git a\/src\/a\.ts b\/src\/a\.ts/);
  const gates = spawnCli(dir, "gates", "--repo", "repo", "--base", base, "--head", head, "--rules", "rules.json");
  assert.equal(gates.status, 0, gates.stdout + gates.stderr);
  assert.match(gates.stdout, /PASS rings: /);
  assert.match(gates.stdout, /gates: PASS/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// gates (CI mode)
// ---------------------------------------------------------------------------

function ciRepo(): { dir: string; repo: string; base: string; head: string } {
  const dir = tmp("gates");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "server/src/engine.ts", "export const k = 1;\n");
  write(repo, "package-lock.json", "{}\n");
  write(repo, "docs/x.md", "x\n");
  const base = commitAll(repo, "base");
  write(repo, "server/src/engine.ts", "export const k = 2;\n");
  write(repo, "package-lock.json", '{"lockfileVersion":3}\n');
  fs.rmSync(path.join(repo, "docs/x.md"));
  write(repo, "docs/y.md", "y\n");
  const head = commitAll(repo, "head");
  // The project's rules classify server/src/engine.ts as ring 0; the
  // defaults lock package-lock.json.
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(projectRules()));
  return { dir, repo, base, head };
}

type GatesJson = {
  pass: boolean;
  ring: number;
  files: string[];
  linesChanged: number;
  deleted: string[];
  binary: string[];
  unexpanded: { path: string }[];
  notes: string[];
  reports: GateReport[];
};

test("gates: a ring-0 change and a lockfile change, judged by the real gate modules", async () => {
  const { dir, repo, base, head } = ciRepo();
  const args = ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"];
  const r = await runIn(dir, args);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /changed files: 4, lines changed: 6/);
  assert.match(r.stdout, /\[ring 0\] server\/src\/engine\.ts/);
  assert.match(r.stdout, /\[ring 1\] docs\/x\.md \(deleted\)/); // deletions count as changed files
  assert.match(r.stdout, /submission ring: 0/);
  assert.match(r.stdout, /PASS rings: /);
  assert.match(r.stdout, /FAIL airlock: locked paths need the dependency track: package-lock\.json/);
  assert.match(r.stdout, /PASS size: 6 lines changed, limit 400/);
  assert.match(r.stdout, /gates: FAIL/);

  const dep = await runIn(dir, [...args, "--dependency-track", "--json"]);
  assert.equal(dep.status, 0, dep.stdout + dep.stderr);
  const j = JSON.parse(dep.stdout) as GatesJson;
  assert.equal(j.pass, true);
  assert.equal(j.ring, 0);
  assert.deepEqual(j.files, ["docs/x.md", "docs/y.md", "package-lock.json", "server/src/engine.ts"]);
  assert.deepEqual(j.deleted, ["docs/x.md"]);
  assert.equal(j.linesChanged, 6);
  assert.deepEqual(j.reports.map((x) => x.gate), ["rings", "airlock", "size"]);
  assert.match(j.reports[1]?.details ?? "", /dependency track: locked paths changed: package-lock\.json/);
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

test("gates: an empty change passes with a note", async () => {
  const { dir, repo, base } = ciRepo();
  const r = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", base, "--rules", "rules.json"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /note: no changes between/);
  assert.match(r.stdout, /gates: PASS/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// A CI workflow running the static gates checks out the base and only
// fetches the PR head as objects. The gates must
// judge the head from git objects, never from that working tree.
test("gates: the workflow's checkout (base checked out, head only fetched) gets the head's verdict", async () => {
  const dir = tmp("workflow");
  const origin = newRepo(path.join(dir, "origin"));
  write(origin, "server/src/engine.ts", "export const k = 1;\n");
  write(origin, "web/src/a.ts", "export const a = 1;\n");
  const base = commitAll(origin, "base");
  git(origin, "checkout", "-q", "-b", "bad");
  write(origin, "web/src/a.ts", 'import { k } from "../../server/src/engine";\nexport const a = k;\n');
  const bad = commitAll(origin, "UI imports the kernel");
  git(origin, "checkout", "-q", "-b", "good", base);
  write(origin, "web/src/a.ts", "export const a = 2;\n");
  const good = commitAll(origin, "UI change");
  const ci = path.join(dir, "ci");
  git(dir, "clone", "-q", "--no-checkout", origin, ci);
  git(ci, "checkout", "-q", base);
  git(ci, "fetch", "-q", "origin", `${bad}:refs/pr/bad`, `${good}:refs/pr/good`);
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(projectRules()));

  const r = await runIn(dir, ["gates", "--repo", ci, "--base", base, "--head", bad, "--rules", "rules.json"]);
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /submission ring: 2/);
  assert.match(r.stdout, /FAIL rings: .*ring-0/);
  const g = await runIn(dir, ["gates", "--repo", ci, "--base", base, "--head", good, "--rules", "rules.json"]);
  assert.equal(g.status, 0, g.stdout + g.stderr);
  assert.match(g.stdout, /PASS rings: /);
  // The working tree was never touched: still the base, clean.
  assert.equal(git(ci, "rev-parse", "HEAD"), base);
  assert.equal(git(ci, "status", "--porcelain"), "");
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
  git(repo, "submodule", "add", "-q", sub, "server");
  const base = commitAll(repo, "base");
  write(sub, "src/engine.ts", "b\nc\n");
  const subHead = commitAll(sub, "sub head");
  git(path.join(repo, "server"), "fetch", "-q", "origin");
  git(path.join(repo, "server"), "checkout", "-q", subHead);
  write(repo, "README.md", "top2\n");
  const head = commitAll(repo, "bump");

  const change = gitChanges((cwd, args, input) => execFileSync("git", args, { cwd, encoding: "utf8", input }), repo, base, head);
  assert.deepEqual(change.files, ["README.md", "server/src/engine.ts"]);
  assert.equal(change.linesChanged, 2 + 3);
  assert.deepEqual(change.unexpanded, []);
  assert.deepEqual(change.submodules, [{ path: "server", sha: subHead }]);

  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(projectRules()));
  const r = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.match(r.stdout, /\[ring 0\] server\/src\/engine\.ts/);

  // An uninitialised submodule cannot be expanded: the bare pointer is
  // reported and the change is ring 0 whatever the rules say.
  const bare = path.join(dir, "bare");
  git(dir, "clone", "-q", repo, bare);
  const c2 = gitChanges((cwd, args, input) => execFileSync("git", args, { cwd, encoding: "utf8", input }), bare, base, head);
  assert.deepEqual(c2.files, ["README.md", "server"]);
  assert.equal(c2.unexpanded[0]?.path, "server");
  const r2 = await runIn(dir, ["gates", "--repo", bare, "--base", base, "--head", head, "--rules", "rules.json", "--json"]);
  const j = JSON.parse(r2.stdout) as GatesJson;
  assert.equal(j.ring, 0);
  assert.match(j.notes.join("\n"), /ring 0 whatever the rules say/);
  fs.rmSync(dir, { recursive: true, force: true });
});

// A project whose ring 2 lives in a submodule: the ring gate must read the
// submodule's files at the new pointer, in both modes.
test("gates: a ring-2 submodule importing the kernel fails in CI and in ledger mode", async () => {
  const dir = tmp("ui-submodule");
  const ui = newRepo(path.join(dir, "frontend-origin"));
  write(ui, "src/a.ts", "export const a = 1;\n");
  commitAll(ui, "ui base");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "server/src/engine.ts", "export const k = 1;\n");
  git(repo, "submodule", "add", "-q", ui, "web");
  const base = commitAll(repo, "base");
  write(ui, "src/b.ts", 'import { k } from "../../server/src/engine";\nexport const b = k;\n');
  const uiHead = commitAll(ui, "ui reaches into the kernel");
  git(path.join(repo, "web"), "fetch", "-q", "origin");
  git(path.join(repo, "web"), "checkout", "-q", uiHead);
  const head = commitAll(repo, "bump the frontend");
  git(path.join(repo, "web"), "checkout", "-q", "HEAD~1"); // the operator's checkout is never read
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(projectRules()));

  const ci = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"]);
  assert.equal(ci.status, 1, ci.stdout + ci.stderr);
  assert.match(ci.stdout, /\[ring 2\] web\/src\/b\.ts/);
  assert.match(ci.stdout, /FAIL rings: .*web\/src\/b\.ts.*ring-0/);

  // Ledger mode: a declared change (no patch: a dry run, which cannot be recorded).
  const L = ["--ledger", "ledger.jsonl"];
  const run = async (...args: string[]) => {
    const r = await runIn(dir, args);
    assert.equal(r.status, 0, `${args.join(" ")}\n${r.stdout}${r.stderr}`);
  };
  for (const k of ["admin", "coord", "alice", "a1"]) await run("keygen", "--out", `${k}.json`);
  await run("init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--rules", "rules.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "alice", "--owner-key", "alice.json");
  await run("agent", "register", ...L, "--key", "alice.json", "--owner", "alice", "--agent-key", "a1.json", "--model-family", "claude", "--harness", "h");
  await run("submit", ...L, "--key", "a1.json", "--id", "s-ui", "--base", base, "--head", head, "--files", "web/src/b.ts", "--lines", "2");
  const led = await runIn(dir, ["gates", ...L, "--repo", repo, "--submission", "s-ui"]);
  assert.equal(led.status, 1, led.stdout + led.stderr);
  assert.match(led.stdout, /PASS declaredChange/);
  assert.match(led.stdout, /FAIL rings: .*ring-0/);
  const rec = await runIn(dir, ["gates", ...L, "--repo", repo, "--submission", "s-ui", "--record", "--key", "coord.json"]);
  assert.equal(rec.status, 2);
  assert.match(rec.stderr, /no stored patch/);

  // A clone without the submodule cannot expand the pointer: declaredChange fails.
  const bare = path.join(dir, "bare");
  git(dir, "clone", "-q", repo, bare);
  const opaque = await runIn(dir, ["gates", ...L, "--repo", bare, "--submission", "s-ui"]);
  assert.equal(opaque.status, 1, opaque.stdout + opaque.stderr);
  assert.match(opaque.stdout, /FAIL declaredChange: .*cannot be expanded/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("gates: files git calls binary cannot hide lines from the size gate", async () => {
  const dir = tmp("size");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "r\n");
  const base = commitAll(repo, "base");
  // A .gitattributes the change itself adds, making every .md "binary" to git diff.
  write(repo, ".gitattributes", "*.md -diff\n");
  write(repo, "docs/big.md", Array.from({ length: 2000 }, (_, i) => `line ${i}`).join("\n") + "\n");
  const attrs = commitAll(repo, "attributes");
  git(repo, "checkout", "-q", base);
  // One NUL byte in a comment: valid JS, binary to git.
  write(repo, "src/big.ts", `// \0\n${Array.from({ length: 2000 }, (_, i) => `export const v${i} = ${i};`).join("\n")}\n`);
  const nul = commitAll(repo, "nul");
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(defaultRules()));

  const a = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", attrs, "--rules", "rules.json", "--json"]);
  assert.equal(a.status, 1, a.stdout + a.stderr);
  const ja = JSON.parse(a.stdout) as GatesJson;
  assert.ok(ja.linesChanged >= 2000, String(ja.linesChanged));
  assert.match(ja.reports.find((x) => x.gate === "size")?.details ?? "", /lines changed, limit 400/);

  const n = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", nul, "--rules", "rules.json"]);
  assert.equal(n.status, 1, n.stdout + n.stderr);
  assert.match(n.stdout, /src\/big\.ts \(binary\)/);
  assert.match(n.stdout, /FAIL size: 2001 lines changed, limit 400.*git counts no lines for src\/big\.ts/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("gates: paths with control characters are printed escaped, never as raw lines", async () => {
  const dir = tmp("escape");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "r\n");
  const base = commitAll(repo, "base");
  write(repo, "x\n::error::gates: PASS", "x\n");
  const head = commitAll(repo, "forged log line");
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(defaultRules()));
  const r = await runIn(dir, ["gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json"]);
  assert.ok(!r.stdout.split("\n").some((l) => l.startsWith("::error::")), r.stdout);
  assert.match(r.stdout, /x\\u000a::error::gates: PASS/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("spawned gates with the real gate modules", () => {
  const { dir, repo, base, head } = ciRepo();
  const r = spawnCli(dir, "gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json");
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stdout, /submission ring: 0/);
  assert.match(r.stdout, /FAIL airlock: locked paths need the dependency track: package-lock\.json/);
  const dep = spawnCli(dir, "gates", "--repo", repo, "--base", base, "--head", head, "--rules", "rules.json", "--dependency-track");
  assert.equal(dep.status, 0, dep.stdout + dep.stderr);
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// The rest of the lifecycle, in process with injected modules
// ---------------------------------------------------------------------------

test("in process: gates --record, assign, review commit/reveal, merge, snapshot, attest, signoff, plants, findings", async () => {
  const dir = tmp("lifecycle");
  const L = ["--ledger", "ledger.jsonl"];
  let clock = Date.parse(T0);
  // The real gate modules; selection, incentives, metrics and promotion are injected per step.
  const io = (mods: Record<string, unknown> = {}): Partial<Io> => ({ now: () => new Date((clock += 60_000)), load: withReal(mods) });
  const run = async (...args: string[]) => {
    const r = await runIn(dir, args, io());
    assert.equal(r.status, 0, `${args.join(" ")}\n${r.stdout}${r.stderr}`);
    return r.stdout;
  };
  const keyIds: Record<string, string> = {};
  for (const k of ["admin", "coord", "alice", "bob", "a1", "b1", "b2"]) keyIds[k] = (await run("keygen", "--out", `${k}.json`)).trim();
  await run("init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "alice", "--owner-key", "alice.json");
  await run("owner", "add", ...L, "--key", "admin.json", "--owner", "bob", "--owner-key", "bob.json");
  await run("agent", "register", ...L, "--key", "alice.json", "--owner", "alice", "--agent-key", "a1.json", "--model-family", "claude", "--harness", "h");
  await run("agent", "register", ...L, "--key", "bob.json", "--owner", "bob", "--agent-key", "b1.json", "--model-family", "gpt", "--harness", "h");
  await run("agent", "register", ...L, "--key", "bob.json", "--owner", "bob", "--agent-key", "b2.json", "--model-family", "qwen", "--harness", "h");
  // An owner revokes their own agent, by key id; the coordinator's other kinds stay refused.
  await run("agent", "revoke", ...L, "--key", "bob.json", "--agent", keyIds.b2 as string, "--reason", "rotated");
  assert.equal(Ledger.open(path.join(dir, "ledger.jsonl")).state().agents.get(keyIds.b2 as string)?.active, false);

  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "src/a.ts", "1\n");
  const base = commitAll(repo, "base");
  write(repo, "src/a.ts", "2\n");
  const head = commitAll(repo, "head");
  write(repo, "src/a.ts", "3\n");
  const head2 = commitAll(repo, "head2");
  git(repo, "checkout", "-q", base); // ledger mode must not depend on what is checked out

  // An untasked ring-1 change; declared files that lie about the change fail declaredChange.
  await run("submit", ...L, "--key", "a1.json", "--id", "s-lie", "--base", base, "--head", head, "--files", "src/other.ts", "--lines", "2");
  // A path the GitHub bridge refuses is refused before anything is signed.
  const colon = await runIn(dir, ["submit", ...L, "--key", "a1.json", "--id", "s-colon", "--base", base, "--head", head, "--files", "src/a:b.ts", "--lines", "1"], io());
  assert.equal(colon.status, 2);
  assert.match(colon.stderr, /the GitHub bridge cannot carry it/);
  // Commit names other than full shas could move between gating and merging.
  const short = await runIn(dir, ["submit", ...L, "--key", "a1.json", "--id", "s-short", "--base", base.slice(0, 12), "--head", head, "--files", "src/a.ts", "--lines", "2"], io());
  assert.equal(short.status, 2);
  assert.match(short.stderr, /must be a full commit sha/);
  const lie = await runIn(dir, ["gates", ...L, "--repo", repo, "--submission", "s-lie"], io());
  assert.equal(lie.status, 1, lie.stdout + lie.stderr);
  assert.match(lie.stdout, /note: no stored patch/);
  assert.match(lie.stdout, /FAIL declaredChange: .*undeclared src\/a\.ts/);

  // With --repo the patch is stored, so the gates judge (and record) the head built from it.
  await run("submit", ...L, "--key", "a1.json", "--id", "s1", "--base", base, "--head", head, "--repo", repo);
  const g = await run("gates", ...L, "--repo", repo, "--submission", "s1", "--record", "--key", "coord.json");
  assert.match(g, /PASS patch: /);
  assert.match(g, /recorded 6 gate results/);
  const bound = Ledger.open(path.join(dir, "ledger.jsonl")).state().submissions.get("s1")?.gates.find((x) => x.gate === "patch");
  const boundHead = (JSON.parse(bound?.details ?? "{}") as { head?: string }).head as string;
  assert.equal(git(repo, "rev-parse", `${boundHead}^{tree}`), git(repo, "rev-parse", `${head}^{tree}`));
  // The bound head is the commons commit an agent can compute and declare itself.
  const patch = fs.readFileSync(path.join(dir, "patches", "s1.diff"), "utf8");
  assert.equal(commonsCommit({ repoDir: repo, baseCommit: base, patch, submissionId: "s1" }).head, boundHead);
  // `commons submit --repo` declares that commit, not the local one, so a
  // reviewer's head-commit check matches the declaration.
  const declaredHead = Ledger.open(path.join(dir, "ledger.jsonl")).state().submissions.get("s1")?.headCommit;
  assert.equal(declaredHead, boundHead);
  assert.equal(git(repo, "worktree", "list").split("\n").length, 1, "no worktree is ever added");

  // assign with an injected draw; the tree is the ledger's member tree and the
  // beacon the real one, since the ledger refuses any other.
  const picks: SelectionApi = {
    drawAssignment: (st, sid, entropy) => {
      const reviewers = [keyIds.b1 as string];
      return { reviewers, candidates: 1, notes: [], body: selection.assignmentBody(st, sid, reviewers, entropy) };
    },
  };
  const treeFlag = await runIn(dir, ["assign", ...L, "--key", "coord.json", "--submission", "s1", "--tree", "tree.json"], io({ selection: picks }));
  assert.equal(treeFlag.status, 2, "no tree comes from outside the ledger");
  assert.match(treeFlag.stderr, /unknown flag --tree/);
  const digest = memberDigest(Ledger.open(path.join(dir, "ledger.jsonl")).state());
  const assigned = await runIn(dir, ["assign", ...L, "--key", "coord.json", "--submission", "s1", "--entropy", "e"], io({ selection: picks }));
  assert.equal(assigned.status, 0, assigned.stderr);
  const a1 = Ledger.open(path.join(dir, "ledger.jsonl")).state().submissions.get("s1")?.assignment;
  assert.deepEqual([a1?.entropy, a1?.treeDigest], ["e", digest]);
  assert.equal(a1?.beacon, assignmentBeacon("s1", declaredHead as string, "e"));

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

  // `commons merge` applies the coordinator's merge rule: phase 1 needs a
  // human approval on the ledger, and the commit must contain the bound head.
  const unapproved = await runIn(dir, ["merge", ...L, "--key", "coord.json", "--submission", "s1", "--repo", repo, "--commit", boundHead], io());
  assert.equal(unapproved.status, 1, unapproved.stdout + unapproved.stderr);
  assert.match(unapproved.stderr, /awaiting human approval/);
  await run("approve", ...L, "--key", "admin.json", "--submission", "s1");
  const wrong = await runIn(dir, ["merge", ...L, "--key", "coord.json", "--submission", "s1", "--repo", repo, "--commit", base], io());
  assert.equal(wrong.status, 1);
  assert.match(wrong.stderr, /does not contain the bound head/);
  // When the ledger refuses the merge entry after the local merge moved dev
  // (here: a key that may not sign merges), dev is put back (regression).
  const devTip = git(repo, "rev-parse", "refs/heads/dev");
  git(repo, "update-ref", "refs/heads/dev", base); // so the local merge is a fast-forward to the bound head
  const unsigned = await runIn(dir, ["merge", ...L, "--key", "b1.json", "--submission", "s1", "--repo", repo], io());
  assert.equal(unsigned.status, 1, unsigned.stdout + unsigned.stderr);
  assert.match(unsigned.stderr, /dev restored to/);
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), base, "dev does not keep a merge the ledger refused");
  git(repo, "update-ref", "refs/heads/dev", devTip);
  await run("merge", ...L, "--key", "coord.json", "--submission", "s1", "--repo", repo, "--commit", boundHead);
  assert.match(await run("snapshot", ...L, "--key", "coord.json"), /snapshot snapshot-1 .*1 submissions at/);
  const st2 = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.deepEqual(st2.snapshots.get("snapshot-1")?.submissionIds, ["s1"]);
  assert.equal(st2.snapshots.get("snapshot-1")?.previousSnapshotId, null);

  // attest commit/reveal on the snapshot, by an agent outside the author's owner.
  await run("attest", "commit", ...L, "--key", "b1.json", "--snapshot", "snapshot-1", "--probability", "0.05", "--summary", "cumulative diff ok");
  clock += 13 * 3_600_000; // attestation reveals wait for the end of the snapshot's commit phase
  await run("attest", "reveal", ...L, "--key", "b1.json", "--snapshot", "snapshot-1");
  assert.equal(Ledger.open(path.join(dir, "ledger.jsonl")).state().snapshots.get("snapshot-1")?.attestations[0]?.verdict?.summary, "cumulative diff ok");

  // signoff by an owner who is not a kernel signer: refused.
  const so = await runIn(dir, ["signoff", ...L, "--key", "alice.json", "--snapshot", "snapshot-1"], io());
  assert.equal(so.status, 1);

  // plants: committed by an admin in a batch, well before submission; the salts kept next to its key.
  const batch = (...ids: string[]) => ids.flatMap((id) => ["--submission", id]);
  const plants = batch("s-plant", "p-2", "p-3", "p-4", "p-5");
  const lone = await runIn(dir, ["plant", "commit", ...L, "--key", "admin.json", "--submission", "s-x"], io());
  assert.equal(lone.status, 2);
  assert.match(lone.stderr, /batches of at least 5/);
  const good = "c".repeat(64);
  const weak = await runIn(dir, ["plant", "commit", ...L, "--key", "admin.json", ...plants, "--salt", "monday", ...Array(4).fill(["--salt", good]).flat()], io());
  assert.equal(weak.status, 2);
  assert.match(weak.stderr, /--salt must be 32 random bytes/);
  const taken = await runIn(dir, ["plant", "commit", ...L, "--key", "admin.json", ...batch("s1", "q-2", "q-3", "q-4", "q-5")], io());
  assert.equal(taken.status, 1, "an id already submitted cannot be a plant");
  assert.match(taken.stderr, /s1 is already submitted/);
  await run("plant", "commit", ...L, "--key", "admin.json", ...plants);
  assert.ok(fs.existsSync(path.join(dir, "admin.json.salts", "plants", "s-plant.json")));
  const generated = await run("plant", "commit", ...L, "--key", "admin.json", "--count", "5");
  assert.equal(generated.match(/plant id s-[0-9a-f]{16}: /g)?.length, 5, "generated ids look like submit's default ids");
  const st3 = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.equal(st3.plantCommitments.length, 10);
  const notAdmin = await runIn(dir, ["plant", "commit", ...L, "--key", "alice.json", ...batch("s-x", "x-2", "x-3", "x-4", "x-5")], io());
  assert.equal(notAdmin.status, 1);
  assert.equal(fs.existsSync(path.join(dir, "alice.json.salts", "plants", "s-x.json")), false);
  await run("submit", ...L, "--key", "a1.json", "--id", "s-plant", "--base", base, "--head", head2, "--files", "src/a.ts", "--lines", "2");
  const reveal = ["plant", "reveal", ...L, "--key", "admin.json", "--submission", "s-plant", "--description", "off by one", "--severity", "medium"];
  const early = await runIn(dir, reveal, io());
  assert.equal(early.status, 1, "a plant is never revealed while its review window is open");
  assert.match(early.stderr, /review window of s-plant is still open/);
  // The assigned reviewer's reveal closes the window.
  await runIn(dir, ["assign", ...L, "--key", "coord.json", "--submission", "s-plant", "--entropy", "e2"], io({ selection: picks }));
  await run("review", "commit", ...L, "--key", "b1.json", "--submission", "s-plant", "--probability", "0.7", "--summary", "off by one?");
  await run("review", "reveal", ...L, "--key", "b1.json", "--submission", "s-plant");
  await run(...reveal);
  const planted = Ledger.open(path.join(dir, "ledger.jsonl")).state().submissions.get("s-plant")?.planted;
  assert.deepEqual([planted?.severity, planted?.description, typeof planted?.seq], ["medium", "off by one", "number"]);

  // findings: verified on the bound head, never the declared one.
  await run("submit", ...L, "--key", "a1.json", "--id", "s2", "--base", base, "--head", head2, "--repo", repo);
  await run("gates", ...L, "--repo", repo, "--submission", "s2", "--record", "--key", "coord.json");
  write(dir, "finding.test.sh", "test \"$(cat src/a.ts)\" = 1\n");
  const fileFinding = (id: string, sid: string) =>
    run("finding", "file", ...L, "--key", "b1.json", "--id", id, "--submission", sid, "--severity", "low", "--test-path", "test/f.sh", "--test-command", "sh test/f.sh");
  await fileFinding("f-unbound", "s-lie");
  await fileFinding("f1", "s2");
  const verify = (...extra: string[]) => runIn(dir, ["finding", "verify", ...L, "--repo", repo, "--test-file", "finding.test.sh", ...extra], io());
  const unsafeFlags = ["--unsafe-same-uid", "--key", "b1.json"];
  const noMode = await verify("--finding", "f1");
  assert.equal(noMode.status, 2);
  assert.match(noMode.stderr, /pass --sandbox <argv JSON>, or --unsafe-same-uid/);
  const noSandboxRecord = await verify("--finding", "f1", "--unsafe-same-uid", "--record", "--key", "coord.json");
  assert.equal(noSandboxRecord.status, 2);
  assert.match(noSandboxRecord.stderr, /--record needs --sandbox/);
  // `env` runs the probe as this uid, which can read the key: refused before anything runs.
  const leaky = await verify("--finding", "f1", "--sandbox", '["env"]', "--key", "coord.json");
  assert.equal(leaky.status, 2);
  assert.match(leaky.stderr, /the --sandbox can still read .*coord\.json/);
  // The setup runner works over the same checkout: it gets the same preflight.
  const leakySetup = await verify("--finding", "f1", ...unsafeFlags, "--setup-command", "true", "--setup-sandbox", '["env"]');
  assert.equal(leakySetup.status, 2);
  assert.match(leakySetup.stderr, /the --setup-sandbox can still read .*b1\.json/);
  const unbound = await verify("--finding", "f-unbound", ...unsafeFlags);
  assert.equal(unbound.status, 1);
  assert.match(unbound.stderr, /recorded patch binding/);
  const v = await verify("--finding", "f1", ...unsafeFlags);
  assert.equal(v.status, 0, v.stdout + v.stderr);
  assert.match(v.stderr, /WARNING: running the test unsandboxed/);
  assert.match(v.stdout, /reproduced: true/);

  // The coordinator records f1's reproduction (as `finding verify --record` would under a sandbox).
  const coordKey = JSON.parse(fs.readFileSync(path.join(dir, "coord.json"), "utf8")) as { publicKey: string; privateKey: string };
  Ledger.open(path.join(dir, "ledger.jsonl")).append(
    { kind: "findingResult", findingId: "f1", reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "0".repeat(64) },
    coordKey,
    new Date((clock += 60_000)).toISOString(),
  );

  // settle with injected incentives that owe alice a merge reward once, and
  // bob a bounty for f1 (phase 1: only once a human confirmed the finding).
  const incentives = {
    settleFinding: (_s: unknown, fid: string) =>
      fid === "f1" ? [{ kind: "settlement", owner: "bob", delta: 5, reason: "bounty", ref: "f1" }] : [],
    settleMerge: (_s: unknown, sid: string, tranche: number) =>
      tranche === 1 ? [{ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: `${sid}:1` }] : [],
    settleCleanReviews: () => [],
    settleMissedPlant: () => [],
    settleFalseFinding: () => [],
    settleExpiredClaims: () => [],
    settleHoneytoken: () => [],
  };
  const s1 = await runIn(dir, ["settle", ...L, "--key", "coord.json"], io({ incentives }));
  assert.equal(s1.status, 0, s1.stderr);
  assert.match(s1.stdout, /alice \+10 mergeVest/);
  assert.doesNotMatch(s1.stdout, /bounty/);
  const s2 = await runIn(dir, ["settle", ...L, "--key", "coord.json"], io({ incentives }));
  assert.match(s2.stdout, /^0 settlements/m);
  // An operator's confirmation is a ledger entry now, not a flag: replay shows it.
  await run("finding", "confirm", ...L, "--key", "admin.json", "--finding", "f1", "--reason", "src/a.ts changed by mistake");
  const s3 = await runIn(dir, ["settle", ...L, "--key", "coord.json"], io({ incentives }));
  assert.equal(s3.status, 0, s3.stderr);
  assert.match(s3.stdout, /bob \+5 bounty/);

  // metrics with an injected module: table and JSON.
  const metrics = { computeMetrics: () => [{ group: "review", metric: "reveal rate", value: 1, bad: false, note: "all revealed" }] };
  const m = await runIn(dir, ["metrics", ...L], io({ metrics }));
  assert.match(m.stdout, /reveal rate\s+1\s+all revealed/);
  const mj = await runIn(dir, ["metrics", ...L, "--json"], io({ metrics }));
  assert.equal((JSON.parse(mj.stdout) as unknown[]).length, 1);

  // promote check with an injected promotion that fails: exit 1, nothing appended by run.
  const promotion = { evaluatePromotion: () => ({ pass: false, checks: [{ name: "seeds", pass: false, detail: "0 < 30" }] }) };
  const pc = await runIn(dir, ["promote", "check", ...L, "--snapshot", "snapshot-1"], io({ promotion }));
  assert.equal(pc.status, 1);
  assert.match(pc.stdout, /FAIL seeds: 0 < 30/);
  const len = Ledger.open(path.join(dir, "ledger.jsonl")).entries().length;
  const promote = ["promote", "run", ...L, "--snapshot", "snapshot-1", "--repo", repo];
  const pr = await runIn(dir, [...promote, "--key", "coord.json"], io({ promotion }));
  assert.equal(pr.status, 1);
  assert.equal(Ledger.open(path.join(dir, "ledger.jsonl")).entries().length, len);
  // ... and one that passes: main moves in --repo, then the entry records it.
  // When the ledger refuses the entry (a key that may not sign promotions),
  // main is put back (regression: promote run never moved main at all).
  const passing = { evaluatePromotion: () => ({ pass: true, checks: [{ name: "all", pass: true, detail: "ok" }] }) };
  const mainBefore = spawnSync("git", ["rev-parse", "--verify", "--quiet", "refs/heads/main"], { cwd: repo, encoding: "utf8" }).stdout.trim();
  const notCoord = await runIn(dir, [...promote, "--key", "b1.json"], io({ promotion: passing }));
  assert.equal(notCoord.status, 1, notCoord.stdout + notCoord.stderr);
  assert.match(notCoord.stderr, /main restored to/);
  assert.equal(spawnSync("git", ["rev-parse", "--verify", "--quiet", "refs/heads/main"], { cwd: repo, encoding: "utf8" }).stdout.trim(), mainBefore);
  const ok1 = await runIn(dir, [...promote, "--key", "coord.json"], io({ promotion: passing }));
  assert.equal(ok1.status, 0, ok1.stdout + ok1.stderr);
  assert.match(ok1.stdout, new RegExp(`promotion .*main at ${boundHead}`));
  assert.equal(git(repo, "rev-parse", "refs/heads/main"), boundHead, "main is where the ledger says");
  assert.ok(Ledger.open(path.join(dir, "ledger.jsonl")).state().snapshots.get("snapshot-1")?.promoted);

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
    incentives,
    promotion: { evaluatePromotion: () => ({ pass: false, checks: [] }) },
    selection: {
      drawAssignment: (st: Parameters<SelectionApi["drawAssignment"]>[0], sid: string, entropy: string) => {
        const reviewers = [keyIds.b1 as string];
        return { reviewers, candidates: 1, notes: [], body: selection.assignmentBody(st, sid, reviewers, entropy) };
      },
    },
    playground: {
      startPlayground: (o: { port: number; host?: string }) => {
        const s = http.createServer((_q, r) => r.end("playground"));
        s.listen(o.port, o.host);
        return s;
      },
    },
  };
  const io = (extra: Partial<Io> = {}): Partial<Io> => ({ now: () => new Date((clock += 1000)), load: withReal(mods), ...extra });
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
  const once = ["coordinator", "run-once", ...L, "--key", "coord.json", "--repo", repo];
  // The stored patch is bound first (the bot commit is what gets judged and
  // merged), then gated, then reviewers are drawn: one step per pass.
  const bind = await run(...once);
  assert.match(bind, /ok {3}bindPatch s1: bound to [0-9a-f]{40}/);
  const boundHead = /bound to ([0-9a-f]{40})/.exec(bind)?.[1] as string;
  assert.equal(git(repo, "rev-parse", `${boundHead}^{tree}`), git(repo, "rev-parse", `${head}^{tree}`));
  assert.match(await run(...once), /ok {3}runGates s1: declaredChange:pass/);
  assert.match(await run(...once), /ok {3}assignReviewers s1/);
  const st = Ledger.open(path.join(dir, "ledger.jsonl")).state();
  assert.deepEqual(st.submissions.get("s1")?.assignment?.reviewers, [keyIds.b1]);
  // Nothing left but the merge, which waits for a reveal and a human.
  assert.match(await run(...once), /nothing to do/);
  // A stranger's finding test never runs as the coordinator's uid: without
  // --sandbox the reproduction fails loudly (and is not a harness error that
  // could void the finding).
  await run("finding", "file", ...L, "--key", "b1.json", "--id", "f1", "--submission", "s1", "--severity", "low", "--test-path", "test/f.sh", "--test-command", "sh test/f.sh");
  write(path.join(dir, "patches", "findings"), "f1.test", "exit 1\n");
  const unsandboxed = await runIn(dir, once, io());
  assert.equal(unsandboxed.status, 1, unsandboxed.stdout + unsandboxed.stderr);
  assert.match(unsandboxed.stdout, /FAIL reproduceFinding f1: .*no --sandbox/);
  assert.equal(Ledger.open(path.join(dir, "ledger.jsonl")).state().findings.get("f1")?.result, undefined);
  // The wrong key is refused before anything runs.
  const wrongKey = await runIn(dir, [...once.slice(0, 4), "--key", "a1.json"], io());
  assert.equal(wrongKey.status, 2);
  assert.match(wrongKey.stderr, /--key: coordinator key does not match the genesis coordinator/);

  let stop!: () => void;
  const until = new Promise<void>((r) => (stop = r));
  const out: string[] = [];
  const serving = main(["serve", ...L, "--port", "0", "--coordinator", "--key", "coord.json"], {
    ...io(),
    cwd: dir,
    until,
    stdout: (t) => void out.push(t),
    stderr: (t) => void out.push(t),
  });
  try {
    const deadline = Date.now() + 5000;
    while (out.filter((l) => /on http:\/\//.test(l)).length < 2 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    const apiUrl = /coordinator API on (http:\/\/\S+)/.exec(out.join(""))?.[1];
    const pgUrl = /playground on (http:\/\/\S+)/.exec(out.join(""))?.[1];
    assert.ok(apiUrl && pgUrl, out.join(""));
    const h = (await (await fetch(`${apiUrl}/api/head`)).json()) as { nextSeq: number };
    assert.equal(h.nextSeq, Ledger.open(path.join(dir, "ledger.jsonl")).entries().length);
    assert.equal(await (await fetch(pgUrl)).text(), "playground");
  } finally {
    stop(); // a failed assertion must not leave the servers holding the test process open
  }
  assert.equal(await serving, 0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("in process: a 3-person Phase 1 group admitted by the admin (init --rules --preset phase1, owner add as the allowlist)", async () => {
  const dir = tmp("phase1");
  let clock = Date.parse(T0);
  const io = (): Partial<Io> => ({ now: () => new Date((clock += 60_000)), load: withReal({}) });
  const run = async (...args: string[]) => {
    const r = await runIn(dir, args, io());
    assert.equal(r.status, 0, `${args.join(" ")}\n${r.stdout}${r.stderr}`);
    return r.stdout;
  };
  for (const k of ["admin", "coord", "alice", "bob", "carol", "a1", "b1", "c1"]) await run("keygen", "--out", `${k}.json`);
  // The target project's own rules, as in its .commons/rules.json.
  fs.writeFileSync(path.join(dir, "rules.json"), JSON.stringify(projectRules()));

  const bad = await runIn(dir, ["init", "--ledger", "x.jsonl", "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--preset", "phase2"], io());
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown --preset phase2/);
  const target = await runIn(dir, ["init", "--ledger", "x.jsonl", "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", "--target", "x"], io());
  assert.equal(target.status, 2, "there are no built-in targets");
  assert.match(target.stderr, /unknown flag --target/);

  const families: Record<string, string> = { a1: "claude", b1: "gpt", c1: "gemini" };
  // The allowlist is the admin's owner entries: alice, bob and carol, bob
  // vouched for by alice when `inviters` says so.
  const setup = async (L: string[], extra: string[], inviters: Record<string, string> = {}) => {
    await run("init", ...L, "--project", "demo", "--admin-key", "admin.json", "--coordinator-key", "coord.json", ...extra);
    for (const [owner, agent] of [["alice", "a1"], ["bob", "b1"], ["carol", "c1"]] as const) {
      await run("owner", "add", ...L, "--key", "admin.json", "--owner", owner, "--owner-key", `${owner}.json`, ...(inviters[owner] ? ["--inviter", inviters[owner]] : []));
      await run("agent", "register", ...L, "--key", `${owner}.json`, "--owner", owner, "--agent-key", `${agent}.json`, "--model-family", families[agent] as string, "--harness", "h");
    }
    await run("submit", ...L, "--key", "a1.json", "--id", "s1", "--base", "a".repeat(40), "--head", "b".repeat(40), "--files", "src/a.ts", "--lines", "2");
  };

  const L = ["--ledger", "phase1.jsonl"];
  await setup(L, ["--rules", "rules.json", "--preset", "phase1", "--kernel-signer", "alice"]);
  const st = Ledger.open(path.join(dir, "phase1.jsonl")).state();
  assert.deepEqual(st.rules, { ...phase1Rules(projectRules()), kernelSigners: ["alice"] }, "the preset applies on top of the project's rules");

  // Every owner was admitted with no inviter: both other owners are drawn, and the draw verifies.
  await run("assign", ...L, "--key", "coord.json", "--submission", "s1", "--entropy", "e");
  const after = Ledger.open(path.join(dir, "phase1.jsonl")).state();
  const reviewers = after.submissions.get("s1")?.assignment?.reviewers ?? [];
  assert.deepEqual(reviewers.map((k) => after.agents.get(k)?.owner).sort(), ["bob", "carol"]);
  assert.equal(selection.verifyAssignment(after, "s1"), true);
  assert.equal(after.submissions.get("s1")?.assignment?.treeDigest, memberDigest(st));

  // An owner admitted under its inviter is too close to review the inviter's work.
  const V = ["--ledger", "vouched.jsonl"];
  await setup(V, ["--preset", "phase1"], { bob: "alice" });
  await run("assign", ...V, "--key", "coord.json", "--submission", "s1", "--entropy", "e");
  const vouched = Ledger.open(path.join(dir, "vouched.jsonl")).state();
  assert.deepEqual((vouched.submissions.get("s1")?.assignment?.reviewers ?? []).map((k) => vouched.agents.get(k)?.owner), ["carol"]);

  // Default rules over such a group: nobody is far enough, and the refusal says why.
  const D = ["--ledger", "default.jsonl"];
  await setup(D, []);
  const none = await runIn(dir, ["assign", ...D, "--key", "coord.json", "--submission", "s1"], io());
  assert.equal(none.status, 1, none.stdout + none.stderr);
  assert.match(none.stderr + none.stdout, /must be <= 1 \(init --preset phase1\)/);

  // Owner ids that differ only in case are one owner.
  const dup = await runIn(dir, ["owner", "add", ...L, "--key", "admin.json", "--owner", "Alice", "--owner-key", "c1.json"], io());
  assert.equal(dup.status, 1);
  assert.match(dup.stderr, /owner ids ignore case/);
});

// ---------------------------------------------------------------------------
// Review findings fixed in the whole-system pass
// ---------------------------------------------------------------------------

// A minimal SubmissionState for bindPatchLocal.
function sub(id: string, base: string, head: string, files: string[], lines: number) {
  return {
    id,
    author: "a",
    taskId: null,
    baseCommit: base,
    headCommit: head,
    changedFiles: files,
    linesChanged: lines,
    submittedSeq: 1,
    submittedAt: T0,
    gates: [],
    reviews: [],
    findingIds: [],
  };
}

function diffOf(repo: string, a: string, b: string): string {
  return git(repo, "diff", "--no-renames", "--full-index", "--src-prefix=a/", "--dst-prefix=b/", a, b) + "\n";
}

test("patch binding refuses a base that is not on dev (stacking on another submission's bound head)", () => {
  const dir = tmp("stack");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "hi\n");
  write(repo, "server/src/engine.ts", "kernel\n");
  const c0 = commitAll(repo, "c0");
  // A: a kernel edit, bound (refs/commons/A) but never reviewed or merged.
  git(repo, "checkout", "-q", "-b", "work");
  write(repo, "server/src/engine.ts", "backdoor\n");
  const aHead = commitAll(repo, "A");
  const patches = path.join(dir, "patches");
  fs.mkdirSync(patches);
  fs.writeFileSync(path.join(patches, "A.diff"), diffOf(repo, c0, aHead));
  const a = bindPatchLocal(repo, patches, sub("A", c0, aHead, ["server/src/engine.ts"], 2));
  assert.ok(a && "head" in a, JSON.stringify(a));
  // B names A's bound head as its base and touches only the README.
  git(repo, "checkout", "-q", a.head);
  write(repo, "README.md", "hello\n");
  const bHead = commitAll(repo, "B");
  fs.writeFileSync(path.join(patches, "B.diff"), diffOf(repo, a.head, bHead));
  const b = bindPatchLocal(repo, patches, sub("B", a.head, bHead, ["README.md"], 2));
  assert.deepEqual(b && "error" in b ? b.error : b, `baseCommit ${a.head} is not on dev (refs/heads/dev at ${c0})`);
  // (A itself bound: its base c0 is on dev.)
  fs.rmSync(dir, { recursive: true, force: true });
});

test("the sandbox preflight refuses a same-uid sandbox even when it hides every listed path", () => {
  if (process.getuid === undefined) return;
  // A wrapper that hides nothing at all passes a pure denylist with no paths to check.
  const leaks = sandboxLeaks(["/bin/sh", "-c", 'exec "$@"', "box"], []);
  assert.ok(leaks.some((l) => /coordinator's own uid/.test(l)), leaks.join("; "));
  // One that runs the probe somewhere it cannot use its checkout is refused too.
  const away = sandboxLeaks(["/bin/sh", "-c", 'cd / && exec "$@"', "box"], []);
  assert.ok(away.some((l) => /not use its checkout/.test(l)) || away.some((l) => /own uid/.test(l)), away.join("; "));
  // A sandbox whose runs share /tmp (a plain other uid shares it too) lets
  // one finding's test tamper with the next one's: refused as well.
  assert.ok(leaks.some((l) => /keep state between runs/.test(l)), leaks.join("; "));
});

test("patch binding: a patch that is not the declared head never binds; a broken --dev-ref is the operator's error, not the author's", () => {
  const dir = tmp("declared");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "hi\n");
  const c0 = commitAll(repo, "c0");
  const patches = path.join(dir, "patches");
  fs.mkdirSync(patches);
  // The author works in its own clone; the coordinator's repo never sees its commits.
  const author = path.join(dir, "author");
  git(dir, "clone", "-q", repo, author);
  const patchFor = (text: string) => {
    git(author, "checkout", "-q", "--detach", c0);
    write(author, "README.md", text);
    return diffOf(author, c0, commitAll(author, text));
  };
  const good = patchFor("good\n");
  const evil = patchFor("EVIL\n");
  // The author declared the commons commit of its good patch...
  const declared = commonsCommit({ repoDir: author, baseCommit: c0, patch: good, submissionId: "s-1" }).head;
  // ...but another patch was stored under its id (a case-twin upload, say).
  fs.writeFileSync(path.join(patches, "s-1.diff"), evil);
  const s = sub("s-1", c0, declared, ["README.md"], 2);
  const refused = bindPatchLocal(repo, patches, s);
  assert.ok(refused && "error" in refused && /not the declared headCommit/.test(refused.error), JSON.stringify(refused));
  fs.writeFileSync(path.join(patches, "s-1.diff"), good);
  const bound = bindPatchLocal(repo, patches, s);
  assert.deepEqual(bound && "head" in bound ? bound.head : bound, declared);
  // A dev ref the clone does not have is a misconfiguration: thrown, never recorded against the author.
  assert.throws(() => bindPatchLocal(repo, patches, s, "refs/heads/develop"), /dev ref refs\/heads\/develop is not in/);
});

test("the local git bridge merges bound heads onto dev and only ever moves main forward", async () => {
  const dir = tmp("bridge");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "a.txt", "a\n");
  write(repo, "b.txt", "b\n");
  const c0 = commitAll(repo, "c0");
  git(repo, "branch", "main", c0);
  git(repo, "checkout", "-q", "-b", "side", c0);
  write(repo, "a.txt", "A\n");
  const h1 = commitAll(repo, "h1");
  git(repo, "checkout", "-q", c0);
  write(repo, "b.txt", "B\n");
  const h2 = commitAll(repo, "h2");
  const bridge = localGitBridge(repo);
  const s = (id: string) => sub(id, c0, "x", ["a.txt"], 2);
  assert.equal(await bridge.merge(s("s1"), h1), h1, "a fast-forward");
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), h1);
  assert.equal(await bridge.merge(s("s1"), h1), h1, "idempotent");
  const m = await bridge.merge(s("s2"), h2);
  assert.notEqual(m, h2, "a merge commit of dev and the bound head");
  assert.equal(git(repo, "rev-parse", `${m}^1`), h1);
  assert.equal(git(repo, "rev-parse", `${m}^2`), h2);
  assert.equal(git(repo, "show", `${m}:a.txt`), "A");
  assert.equal(git(repo, "show", `${m}:b.txt`), "B");
  // A conflict is refused, and dev does not move.
  git(repo, "checkout", "-q", c0);
  write(repo, "a.txt", "conflict\n");
  const h3 = commitAll(repo, "h3");
  // (As a MergeConflictError, which the coordinator records as a failed merge gate.)
  await assert.rejects(bridge.merge(s("s3"), h3), (e: unknown) => e instanceof MergeConflictError && /does not merge cleanly/.test(e.message));
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), m);
  await bridge.fastForwardMain(h1);
  assert.equal(git(repo, "rev-parse", "refs/heads/main"), h1);
  await bridge.fastForwardMain(c0); // already past it: left alone
  assert.equal(git(repo, "rev-parse", "refs/heads/main"), h1);
  await assert.rejects(bridge.fastForwardMain(h3), /main only moves forward/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("regression: the local bridge never lets a gated change follow a rename dev made into a path nobody gated", async () => {
  const dir = tmp("bridge-rename");
  const repo = newRepo(path.join(dir, "repo"));
  const body = Array.from({ length: 20 }, (_, i) => `export const v${i} = ${i};\n`).join("");
  write(repo, "scripts/helper.js", body);
  write(repo, "tools/a.js", "a\n");
  const base = commitAll(repo, "base");
  // dev moves scripts/helper.js (ring 1) into src/ (ring 0), and tools/ under src/.
  fs.mkdirSync(path.join(repo, "src"));
  git(repo, "mv", "scripts/helper.js", "src/helper.js");
  git(repo, "mv", "tools", "src/tools");
  const moved = commitAll(repo, "move into src"); // on dev
  // The submission, on the old base: an edit to scripts/helper.js and a new tools/new.js.
  git(repo, "checkout", "-q", base);
  write(repo, "scripts/helper.js", body.replace("v3 = 3", "v3 = require('child_process').execSync(process.env.X)"));
  write(repo, "tools/new.js", "evil\n");
  const head = commitAll(repo, "payload");
  const bridge = localGitBridge(repo);
  const s = sub("s-ren", base, "x", ["scripts/helper.js", "tools/new.js"], 2);
  await assert.rejects(bridge.merge(s, head), (e: unknown) => e instanceof MergeConflictError);
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), moved, "dev did not move");
  assert.doesNotMatch(git(repo, "show", "refs/heads/dev:src/helper.js"), /execSync/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("the local bridge reads and restores refs with compare-and-swap (the coordinator's compensation)", async () => {
  const dir = tmp("bridge-restore");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "a.txt", "a\n");
  const c0 = commitAll(repo, "c0");
  write(repo, "a.txt", "b\n");
  const c1 = commitAll(repo, "c1"); // dev
  const bridge = localGitBridge(repo);
  assert.equal(await bridge.tip?.("dev"), c1);
  assert.equal(await bridge.tip?.("main"), null);
  await bridge.fastForwardMain(c1);
  assert.equal(await bridge.restore?.("main", null, c1), true, "main removed again: it did not exist before");
  assert.equal(await bridge.tip?.("main"), null);
  assert.equal(await bridge.restore?.("dev", c0, c0), false, "dev is not at `after`: left alone");
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), c1);
  assert.equal(await bridge.restore?.("dev", c0, c1), true);
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), c0);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("regression: git failing while the binder writes objects is thrown (retried), never recorded as the author's failed binding", { skip: process.getuid?.() === 0 ? "root ignores directory permissions" : false }, () => {
  const dir = tmp("bind-transient");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "hi\n");
  const c0 = commitAll(repo, "c0");
  const patches = path.join(dir, "patches");
  fs.mkdirSync(patches);
  const author = path.join(dir, "author");
  git(dir, "clone", "-q", repo, author);
  write(author, "README.md", "a new line nobody has stored yet\n");
  const patch = diffOf(author, c0, commitAll(author, "change"));
  const declared = commonsCommit({ repoDir: author, baseCommit: c0, patch, submissionId: "s-t" }).head;
  fs.writeFileSync(path.join(patches, "s-t.diff"), patch);
  const s = sub("s-t", c0, declared, ["README.md"], 2);
  const objects = path.join(repo, ".git", "objects");
  const dirs = fs.readdirSync(objects).map((d) => path.join(objects, d)).filter((d) => fs.statSync(d).isDirectory());
  for (const d of [objects, ...dirs]) fs.chmodSync(d, 0o555);
  try {
    assert.throws(() => bindPatchLocal(repo, patches, s), /hash-object|insufficient permission|failed/);
  } finally {
    for (const d of [objects, ...dirs]) fs.chmodSync(d, 0o755);
  }
  const bound = bindPatchLocal(repo, patches, s);
  assert.deepEqual(bound && "head" in bound ? bound.head : bound, declared);
  fs.rmSync(dir, { recursive: true, force: true });
});

test("regression: a patch adding a path that differs from an existing one only in letter case never binds", () => {
  const dir = tmp("bind-case");
  const repo = newRepo(path.join(dir, "repo"));
  write(repo, "README.md", "hi\n");
  const c0 = commitAll(repo, "c0");
  // Built with plumbing: a case-insensitive filesystem cannot hold both spellings in a worktree.
  const env = { ...process.env, GIT_INDEX_FILE: path.join(dir, "index") };
  const g = (...args: string[]) => execFileSync("git", args, { cwd: repo, env, encoding: "utf8", input: args[0] === "hash-object" ? "EVIL\n" : undefined }).trim();
  g("read-tree", c0);
  const blob = g("hash-object", "-w", "--stdin");
  g("update-index", "--add", "--cacheinfo", `100644,${blob},readme.md`);
  const tree = g("write-tree");
  const head = execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@x", "commit-tree", tree, "-p", c0, "-m", "twin"], { cwd: repo, encoding: "utf8" }).trim();
  const patches = path.join(dir, "patches");
  fs.mkdirSync(patches);
  fs.writeFileSync(path.join(patches, "s-c.diff"), diffOf(repo, c0, head));
  const r = bindPatchLocal(repo, patches, sub("s-c", c0, head, ["readme.md"], 1));
  assert.ok(r && "error" in r && /README\.md and readme\.md differ only in letter case/.test(r.error), JSON.stringify(r));
  fs.rmSync(dir, { recursive: true, force: true });
});
