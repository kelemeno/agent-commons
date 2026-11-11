// End-to-end: one task's whole life, and one buggy PR's, on a temporary git
// repository, through the real modules. Nothing in core is mocked; the only
// stand-ins are the two effects that would reach GitHub (the bridge's merge
// and main fast-forward), done here with git on the temp repository.
//
// The clock is a variable: core modules take time as an argument, so the
// story can cross the 24 h soak floor and the 30 day vesting tail in
// milliseconds. Every runtime piece (server, client, coordinator loop,
// playground, CLI) is handed the same clock.

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import type * as http from "node:http";
import type { AddressInfo } from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { bindPatchLocal, main } from "../src/cli";
import { CommonsClient, memorySaltStore } from "../src/client";
import {
  type Action,
  type GithubBridge,
  type LogLine,
  type PlanOptions,
  type RunDeps,
  type TaskBody,
  planActions,
  runOnce,
} from "../src/coordinator";
import { canonical, generateKeyPair, keyIdOf, randomSalt } from "../src/crypto";
import { reproduceFinding } from "../src/findings";
import { runStaticGates } from "../src/gates";
import { settleFinding, settleMerge } from "../src/incentives";
import { Ledger, replay, type Signer } from "../src/ledger";
import { computeMetrics } from "../src/metrics";
import { plantCommitment } from "../src/plants";
import { startPlayground } from "../src/playground";
import { evaluatePromotion } from "../src/promotion";
import { commitmentFor } from "../src/review";
import { phase1Rules } from "../src/rules";
import { drawAssignment, verifyAssignment, verifyAssignmentInLedger } from "../src/selection";
import { createCoordinatorServer, findingTestFile, LedgerStore, uploadExists } from "../src/server";
import { memberDigest, memberTree } from "../src/members";
import type { CommonsState, EntryBody, KeyId, ModelFamily, OwnerId, ReviewVerdict } from "../src/types";

const GIT_ENV = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  HOME: os.tmpdir(),
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_AUTHOR_NAME: "e2e",
  GIT_AUTHOR_EMAIL: "e2e@example.org",
  GIT_COMMITTER_NAME: "e2e",
  GIT_COMMITTER_EMAIL: "e2e@example.org",
};

function gitRaw(cwd: string, args: string[], env: Record<string, string> = {}, input?: string): string {
  return execFileSync("git", args, { cwd, env: { ...GIT_ENV, ...env }, input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
}
const git = (cwd: string, ...args: string[]) => gitRaw(cwd, args).trim();

// A commit of `files` on top of `parent`, built with a private index so the
// working tree (which never follows dev here) is irrelevant.
function commitFiles(repo: string, parent: string, files: Record<string, string>, message: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "e2e-index-"));
  const env = { GIT_INDEX_FILE: path.join(dir, "index") };
  try {
    gitRaw(repo, ["read-tree", parent], env);
    for (const [file, content] of Object.entries(files)) {
      const sha = gitRaw(repo, ["hash-object", "-w", "--stdin"], env, content).trim();
      gitRaw(repo, ["update-index", "--add", "--cacheinfo", `100644,${sha},${file}`], env);
    }
    const tree = gitRaw(repo, ["write-tree"], env).trim();
    return gitRaw(repo, ["commit-tree", tree, "-p", parent, "-m", message], env).trim();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const diff = (repo: string, base: string, head: string) => gitRaw(repo, ["diff", "--no-renames", "--no-ext-diff", base, head]);

// The checkout the static gates read: the commit's blobs, never a working tree.
function materialise(repo: string, commit: string, into: string): string {
  const dir = fs.mkdtempSync(path.join(into, "head-"));
  const tar = execFileSync("git", ["archive", "--format=tar", commit], { cwd: repo, env: GIT_ENV, maxBuffer: 64 * 1024 * 1024 });
  execFileSync("tar", ["-x", "-C", dir], { input: tar });
  return dir;
}

const MATH_V0 = "function add(a, b) {\n  return a + b;\n}\n\nmodule.exports = { add };\n";
// The task's implementation (clean).
const MATH_MUL = "function add(a, b) {\n  return a + b;\n}\n\nfunction mul(a, b) {\n  return a * b;\n}\n\nmodule.exports = { add, mul };\n";
// A "fast path" that truncates fractions: the real bug the finding catches.
const MATH_BUG = "function add(a, b) {\n  return (a | 0) + (b | 0);\n}\n\nmodule.exports = { add };\n";
const TEST_V0 =
  'const test = require("node:test");\nconst assert = require("node:assert");\nconst { add } = require("../src/math.js");\n\ntest("add", () => assert.equal(add(2, 3), 5));\n';
const ACCEPTANCE =
  'const test = require("node:test");\nconst assert = require("node:assert");\nconst { mul } = require("../../src/math.js");\n\ntest("mul", () => {\n  assert.equal(mul(3, 4), 12);\n  assert.equal(mul(-2, 5), -10);\n});\n';
const FINDING_TEST =
  'const test = require("node:test");\nconst assert = require("node:assert");\nconst { add } = require("../src/math.js");\n\ntest("add keeps fractions", () => assert.equal(add(0.5, 0.25), 0.75));\n';

const GATES = ["rings", "airlock", "specSeparation", "size"];
const ENTROPY = "e2e-fixed-round-4711";
const HOUR = 3_600_000;

test("e2e: propose → task → claim → submit → gates → review → finding → settle → merge → snapshot → plants → promote", { timeout: 120_000 }, async (t) => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), "commons-e2e-"));
  const servers: http.Server[] = [];
  t.after(async () => {
    await Promise.all(servers.map((s) => new Promise<void>((r) => s.close(() => r()))));
    fs.rmSync(root, { recursive: true, force: true });
  });

  let nowMs = Date.parse("2026-03-02T09:00:00.000Z");
  const clock = () => new Date(nowMs).toISOString();
  const tick = (ms = 1000) => (nowMs += ms);

  // --- The project repository -------------------------------------------------
  const repo = path.join(root, "repo");
  fs.mkdirSync(path.join(repo, "src"), { recursive: true });
  fs.mkdirSync(path.join(repo, "test"), { recursive: true });
  fs.writeFileSync(path.join(repo, "src", "math.js"), MATH_V0);
  fs.writeFileSync(path.join(repo, "test", "math.test.js"), TEST_V0);
  git(repo, "init", "-q", "-b", "dev");
  git(repo, "add", "-A");
  git(repo, "commit", "-q", "-m", "init");
  const c0 = git(repo, "rev-parse", "HEAD");
  git(repo, "branch", "main", c0);

  // --- Keys, owners, agents, genesis ----------------------------------------
  const admin = generateKeyPair();
  const coordinator = generateKeyPair();
  const OWNERS = ["owner-a", "owner-b", "owner-c", "owner-d", "owner-e"] as const;
  const FAMILIES: ModelFamily[] = ["claude", "gpt", "gemini", "qwen", "deepseek"];
  const ownerKeys = new Map<OwnerId, Signer>(OWNERS.map((o) => [o, generateKeyPair()]));
  const agentKeys = new Map<OwnerId, Signer>(OWNERS.map((o) => [o, generateKeyPair()]));
  const agentId = (o: OwnerId) => keyIdOf((agentKeys.get(o) as Signer).publicKey);
  const ownerOfAgent = new Map<KeyId, OwnerId>(OWNERS.map((o) => [agentId(o), o]));
  const signerOf = (agent: KeyId) => agentKeys.get(ownerOfAgent.get(agent) as OwnerId) as Signer;

  const rules = phase1Rules();
  rules.kernelSigners = ["owner-e"];
  const ledgerPath = path.join(root, "ledger.jsonl");
  const patchesDir = path.join(root, "patches");
  Ledger.create(ledgerPath, { kind: "genesis", project: "e2e", admins: [admin.publicKey], coordinator: coordinator.publicKey, rules }, clock());
  // The single writer: the coordinator loop, the HTTP server and this test's
  // own participant appends all go through it.
  const store = LedgerStore.open(ledgerPath, coordinator, clock);
  const state = (): CommonsState => store.state();
  const append = (body: EntryBody, signer: Signer) =>
    store.lock(() => {
      tick();
      return store.ledger.append(body, signer, clock());
    });

  // The admin's owner entries are the Phase 1 allowlist: nobody vouched for
  // anybody, so every pair sits at distance 2 in the member tree.
  for (const o of OWNERS) await append({ kind: "ownerKey", owner: o, publicKey: (ownerKeys.get(o) as Signer).publicKey, inviter: null }, admin);
  const tree = memberTree(state());
  for (const o of OWNERS) assert.equal(tree.distance(o, OWNERS[0]), o === OWNERS[0] ? 0 : 2);
  for (const [i, o] of OWNERS.entries()) {
    const body: EntryBody = { kind: "agentRegistered", owner: o, publicKey: (agentKeys.get(o) as Signer).publicKey, modelFamily: FAMILIES[i] as string, harness: "e2e" };
    await append(body, ownerKeys.get(o) as Signer);
  }
  assert.equal(state().agents.size, 5);
  assert.equal(new Set([...state().agents.values()].map((a) => a.modelFamily)).size, 5);

  // --- The coordinator: real modules, a git bridge, a fixed entropy round ----
  const approvedTasks: TaskBody[] = [];
  // Human decisions are ledger entries, signed by an operator (here the admin).
  const approveMerge = (submissionId: string) => append({ kind: "mergeApproval", submissionId }, admin);
  const confirm = (findingId: string) => append({ kind: "findingDecision", findingId, confirmed: true, reason: "a real defect" }, admin);
  const bridge: GithubBridge = {
    async merge(_s, expectedHead) {
      const dev = git(repo, "rev-parse", "refs/heads/dev");
      if (dev === expectedHead) return dev; // idempotent
      if (git(repo, "rev-parse", `${expectedHead}^`) !== dev) throw new Error("dev moved under the PR");
      git(repo, "update-ref", "refs/heads/dev", expectedHead, dev);
      return expectedHead;
    },
    async fastForwardMain(commit) {
      const main = git(repo, "rev-parse", "refs/heads/main");
      git(repo, "merge-base", "--is-ancestor", main, commit); // throws unless a fast-forward
      git(repo, "update-ref", "refs/heads/main", commit, main);
    },
  };
  const plan: RunDeps["plan"] = { reviewWindowHours: 48, phase: 1, snapshotEvery: 1, requiredGates: GATES };
  const deps: RunDeps = {
    state,
    entries: () => store.ledger.entries(),
    append: (b) => store.appendAsCoordinator(b),
    clock,
    entropy: () => ENTROPY,
    patchesDir,
    bindPatch: async (s) => bindPatchLocal(repo, patchesDir, s),
    // The real static gates over the bound head's blobs.
    runGates: async (s) => {
      const dir = materialise(repo, s.headCommit, root);
      try {
        const deleted = gitRaw(repo, ["diff", "--name-only", "--diff-filter=D", s.baseCommit, s.headCommit]).split("\n").filter(Boolean);
        return runStaticGates(state(), s.id, dir, { dependencyTrack: false, deleted });
      } finally {
        fs.rmSync(dir, { recursive: true, force: true });
      }
    },
    // The real harness. No sandbox: the only test it runs is this file's own
    // FINDING_TEST (strangers' tests need one; see localReproducer).
    reproduce: async (a) => {
      const file = findingTestFile(patchesDir, a.findingId);
      if (!fs.existsSync(file)) return null;
      const r = await reproduceFinding({
        repoDir: repo,
        baseCommit: a.baseCommit,
        headCommit: a.headCommit,
        testPath: a.testPath,
        testContent: fs.readFileSync(file, "utf8"),
        testCommand: a.testCommand,
        timeoutMs: 60_000,
      });
      return r;
    },
    bridge,
    approvedTasks: () => approvedTasks,
    plan,
  };
  // What runOnce plans with, for re-planning right after a pass.
  const planOpts = (): PlanOptions => ({
    ...plan,
    entries: store.ledger.entries(),
    patchAvailable: (sid) => uploadExists(patchesDir, "patch", sid),
    findingTestAvailable: (fid) => uploadExists(patchesDir, "findingTest", fid),
    approvedTasks,
  });
  // One coordinator pass. Every action must succeed, and planning again on
  // the resulting ledger must not repeat any action that just ran.
  const pass = async (label: string): Promise<LogLine[]> => {
    tick();
    const { actions, log } = await runOnce(deps);
    for (const l of log) assert.ok(l.ok, `${label}: ${l.action.kind} failed: ${l.detail}`);
    const again = new Set(planActions(state(), clock(), planOpts()).map((a) => canonical(a)));
    for (const a of actions) assert.ok(!again.has(canonical(a)), `${label}: ${a.kind} is planned again after it ran`);
    return log;
  };
  const kinds = (log: LogLine[]) => log.map((l) => `${l.action.kind}${"submissionId" in l.action ? `:${l.action.submissionId}` : ""}`).sort();
  const plannedNow = (): Action[] => planActions(state(), clock(), planOpts());

  // --- The coordinator HTTP API, which agents reach through client.ts --------
  const api = createCoordinatorServer({ store, coordinatorKey: coordinator, clock, patchesDir });
  servers.push(api);
  await new Promise<void>((r) => api.listen(0, "127.0.0.1", r));
  const baseUrl = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
  const clientOf = (o: OwnerId) => new CommonsClient({ baseUrl, agentKey: agentKeys.get(o) as Signer, clock, saltStore: memorySaltStore() });

  // --- Proposal with evidence → coordinator task (spec author A) ------------
  await clientOf("owner-a").propose({ id: "p-mul", title: "math: add mul()", evidence: [{ kind: "location", file: "src/math.js", line: 5, note: "no multiplication" }] });
  assert.equal(state().proposals.get("p-mul")?.by, agentId("owner-a"));
  approvedTasks.push({
    kind: "task",
    id: "t-mul",
    proposalId: "p-mul",
    ring: 1,
    acceptanceTestPaths: ["test/acceptance/mul.test.js"],
    sizeEstimate: 20,
    specAuthor: "owner-a",
  });
  assert.deepEqual(kinds(await pass("task")), ["task"]);
  assert.equal(state().tasks.get("t-mul")?.specAuthor, "owner-a");

  // Owner A's agent delivers the acceptance tests to dev before the task is
  // claimed (a direct dev commit here, to keep this test to one review cycle).
  const c1 = commitFiles(repo, c0, { "test/acceptance/mul.test.js": ACCEPTANCE }, "acceptance tests for t-mul");
  git(repo, "update-ref", "refs/heads/dev", c1, c0);

  // --- Claim by B, submission by B through the client; a buggy PR by C ------
  const b = clientOf("owner-b");
  await b.claim("t-mul", { until: new Date(nowMs + 72 * HOUR), stake: 10 });
  const mulPatch = diff(repo, c1, commitFiles(repo, c1, { "src/math.js": MATH_MUL }, "B: mul"));
  const sMul = await b.submit({ id: "s-mul", taskId: "t-mul", baseCommit: c1, repoDir: repo }, mulPatch);
  assert.equal(sMul.patch.created, true);
  const bugPatch = diff(repo, c1, commitFiles(repo, c1, { "src/math.js": MATH_BUG }, "C: integer fast path"));
  const sBug = await clientOf("owner-c").submit({ id: "s-bug", taskId: null, baseCommit: c1, repoDir: repo }, bugPatch);
  assert.deepEqual(state().submissions.get("s-mul")?.changedFiles, ["src/math.js"]);
  assert.equal(state().submissions.get("s-bug")?.author, agentId("owner-c"));

  // --- Coordinator: bind patches, then the real static gates ----------------
  assert.deepEqual(kinds(await pass("bind")), ["bindPatch:s-bug", "bindPatch:s-mul"]);
  // client.ts commonsCommit and the CLI's binder build the same commit.
  assert.equal(state().submissions.get("s-mul")?.gates[0]?.details.includes(sMul.headCommit), true);
  assert.equal(state().submissions.get("s-bug")?.gates[0]?.details.includes(sBug.headCommit), true);
  assert.deepEqual(kinds(await pass("gates")), ["runGates:s-bug", "runGates:s-mul"]);
  for (const sid of ["s-mul", "s-bug"]) {
    const gates = state().submissions.get(sid)?.gates ?? [];
    assert.deepEqual(gates.map((g) => g.gate).sort(), ["airlock", "patch", "rings", "size", "specSeparation"], sid);
    for (const g of gates) assert.ok(g.pass, `${sid} ${g.gate}: ${g.details}`);
  }
  assert.match(state().submissions.get("s-mul")?.gates.find((g) => g.gate === "specSeparation")?.details ?? "", /owner-b is not spec author owner-a/);

  // --- Reviewer assignment: real selection, fixed entropy, verified ---------
  assert.deepEqual(kinds(await pass("assign")), ["assignReviewers:s-bug", "assignReviewers:s-mul"]);
  for (const sid of ["s-mul", "s-bug"]) {
    const st = state();
    const s = st.submissions.get(sid);
    const a = s?.assignment;
    assert.ok(s && a, sid);
    assert.equal(a.entropy, ENTROPY);
    assert.equal(a.reviewers.length, 2);
    const authorOwner = ownerOfAgent.get(s.author);
    const owners = a.reviewers.map((r) => ownerOfAgent.get(r));
    assert.ok(!owners.includes(authorOwner), `${sid}: the author's owner reviews`);
    assert.equal(new Set(owners).size, 2);
    const authorFamily = st.agents.get(s.author)?.modelFamily;
    assert.ok(a.reviewers.some((r) => st.agents.get(r)?.modelFamily !== authorFamily));
    assert.ok(verifyAssignment(st, sid));
    const entries = store.ledger.entries();
    assert.ok(verifyAssignmentInLedger(entries, sid, ENTROPY));
    assert.ok(!verifyAssignmentInLedger(entries, sid, "another-round"));
    // Recomputed independently from the ledger before the assignment, tree included.
    const at = entries.findIndex((e) => e.body.kind === "reviewAssignment" && e.body.submissionId === sid);
    const before = replay(entries.slice(0, at));
    assert.equal(a.treeDigest, memberDigest(before));
    const redraw = drawAssignment(before, sid, ENTROPY);
    assert.deepEqual(redraw.body, entries[at]?.body);
  }

  // --- Reviews: commit, then reveal ----------------------------------------
  const commitReveal = async (sid: string, reviewer: KeyId, verdict: ReviewVerdict) => {
    const salt = randomSalt();
    await append({ kind: "reviewCommit", submissionId: sid, commitment: commitmentFor(verdict, salt, reviewer, { submissionId: sid }), stake: rules.stake.review }, signerOf(reviewer));
    return () => append({ kind: "reviewReveal", submissionId: sid, verdict, salt }, signerOf(reviewer));
  };
  const mulReviewers = state().submissions.get("s-mul")?.assignment?.reviewers ?? [];
  const reveals = [];
  for (const r of mulReviewers) reveals.push(await commitReveal("s-mul", r, { defectProbability: 0.05, summary: "mul is right", findingIds: [] }));
  for (const reveal of reveals) await reveal();

  // On the buggy PR the first reviewer files a finding (test uploaded through
  // the API) and commits and reveals through the client; the second approves.
  const [finderAgent, approverAgent] = state().submissions.get("s-bug")?.assignment?.reviewers ?? [];
  assert.ok(finderAgent && approverAgent);
  const finderOwner = ownerOfAgent.get(finderAgent) as OwnerId;
  const finder = clientOf(finderOwner);
  await finder.fileFinding(
    { id: "f-trunc", target: { submissionId: "s-bug" }, severity: "medium", testPath: "test/finding-trunc.test.js", testCommand: "node --test test/finding-trunc.test.js", stake: rules.stake.finding },
    FINDING_TEST,
  );
  await finder.commitReview("s-bug", { defectProbability: 0.9, summary: "add truncates fractions", findingIds: ["f-trunc"] });
  const approve = await commitReveal("s-bug", approverAgent, { defectProbability: 0.1, summary: "looks fine", findingIds: [] });
  await finder.revealReview("s-bug");
  await approve();

  // --- Reproduction (real harness) and the clean merge ----------------------
  await approveMerge("s-mul");
  await approveMerge("s-bug"); // approval cannot get a reproduced bug merged
  const log5 = await pass("reproduce+merge");
  assert.deepEqual(kinds(log5), ["merge:s-mul", "reproduceFinding"]);
  const f = state().findings.get("f-trunc");
  assert.deepEqual(
    { reproduced: f?.result?.reproduced, failsOnHead: f?.result?.failsOnHead, passesOnParent: f?.result?.passesOnParent },
    { reproduced: true, failsOnHead: true, passesOnParent: true },
  );
  const mergedMul = state().submissions.get("s-mul")?.merged;
  assert.equal(mergedMul?.commit, sMul.headCommit);
  assert.equal(git(repo, "rev-parse", "refs/heads/dev"), sMul.headCommit);
  assert.equal(state().submissions.get("s-bug")?.merged, undefined);

  // --- Settlements: from incentives, applied once ---------------------------
  // A reproduced finding settles only once an operator confirmed it.
  const log6a = await pass("settle (unconfirmed)");
  assert.deepEqual(kinds(log6a), ["settle", "snapshot"]);
  assert.ok(!state().settlements.some((x) => x.ref === "finding:f-trunc"));
  await confirm("f-trunc");
  assert.deepEqual(kinds(await pass("settle (confirmed)")), ["settle"]);
  const settled = (owner: OwnerId, reason: string, ref: string) =>
    state().settlements.filter((x) => x.owner === owner && x.reason === reason && x.ref === ref).map((x) => x.delta);
  assert.deepEqual(settled("owner-b", "mergeVest", "merge:s-mul:1"), [9]);
  assert.deepEqual(settled("owner-a", "proposerCut", "merge:s-mul:1"), [1]);
  assert.deepEqual(settled(finderOwner, "bounty", "finding:f-trunc"), [rules.rewards.bounty.low]);
  assert.deepEqual(settled("owner-c", "authorSlash", "finding:f-trunc"), [-rules.rewards.bounty.low]);
  assert.equal(settled(ownerOfAgent.get(approverAgent) as OwnerId, "approverSlash", "finding:f-trunc").length, 1);
  // Idempotent: the incentives functions and the planner find nothing new.
  const n = state().settlements.length;
  assert.deepEqual(settleFinding(state(), "f-trunc", "dev"), []);
  assert.deepEqual(settleMerge(state(), "s-mul", 1, clock()), []);
  assert.ok(!plannedNow().some((a) => a.kind === "settle"));
  assert.deepEqual(await pass("idle"), []);
  assert.equal(state().settlements.length, n);
  for (const o of OWNERS) {
    const sum = state().settlements.filter((x) => x.owner === o).reduce((a, x) => a + x.delta, 0);
    assert.equal(state().owners.get(o)?.reputationDelta, sum, o);
  }

  // --- Snapshot, attestations, sign-off -------------------------------------
  const snap = state().snapshots.get("snapshot-1");
  assert.deepEqual(snap?.submissionIds, ["s-mul"]);
  assert.equal(snap?.commit, sMul.headCommit);
  const attestVerdict: ReviewVerdict = { defectProbability: 0.05, summary: "cumulative diff is clean", findingIds: [] };
  const attestClients = (["owner-d", "owner-e"] as OwnerId[]).map(clientOf);
  for (const c of attestClients) await c.attestCommit("snapshot-1", attestVerdict, rules.stake.review);
  tick(rules.review.commitHours * HOUR + 60_000); // attestation reveals wait for the commit phase to end
  for (const c of attestClients) await c.attestReveal("snapshot-1");
  // A sign-off is signed by the owner's own key, not an agent's.
  const ownerE = new CommonsClient({ baseUrl, agentKey: ownerKeys.get("owner-e") as Signer, clock, saltStore: memorySaltStore() });
  await ownerE.post({ kind: "signoff", snapshotId: "snapshot-1" });
  assert.equal(state().snapshots.get("snapshot-1")?.attestations.filter((a) => a.verdict).length, 2);
  assert.deepEqual(state().snapshots.get("snapshot-1")?.signoffs, ["owner-e"]);

  // Past the soak floor; promotion now waits only for seeded recall.
  tick(25 * HOUR);

  // --- Plants: committed in one batch, submitted by rotating agents, reviewed
  // by drawn reviewers, revealed after their windows closed -----------------
  const plantIds = Array.from({ length: 10 }, (_, i) => `s-p${String(i + 1).padStart(2, "0")}`);
  const plantSalts = new Map(plantIds.map((id) => [id, randomSalt()]));
  for (const id of plantIds) await append({ kind: "plantCommit", commitment: plantCommitment(id, plantSalts.get(id) as string) }, admin);
  const runPlant = async (i: number) => {
    const id = plantIds[i] as string;
    const author = OWNERS[i % OWNERS.length] as OwnerId;
    const base = git(repo, "rev-parse", "refs/heads/dev");
    const head = commitFiles(repo, base, { [`src/util${i}.js`]: `module.exports = (x) => x + ${i};\n` }, `util ${i}`);
    await append({ kind: "submission", id, taskId: null, baseCommit: base, headCommit: head, changedFiles: [`src/util${i}.js`], linesChanged: 1 }, agentKeys.get(author) as Signer);
    tick();
    await store.appendAsCoordinator((st) => drawAssignment(st, id, ENTROPY).body);
    const reviewers = state().submissions.get(id)?.assignment?.reviewers ?? [];
    assert.equal(reviewers.length, 2, id);
    const rs = [];
    for (const r of reviewers) rs.push(await commitReveal(id, r, { defectProbability: 0.8, summary: "off by one", findingIds: [] }));
    for (const reveal of rs) await reveal();
    await append({ kind: "plantReveal", submissionId: id, salt: plantSalts.get(id) as string, description: "seeded off-by-one", severity: "medium" }, admin);
  };
  for (let i = 0; i < 3; i++) await runPlant(i);

  // --- Promotion: recall fails with three seeds ----------------------------
  const early = evaluatePromotion(state(), "snapshot-1", clock());
  assert.equal(early.pass, false);
  const failing = early.checks.filter((c) => !c.pass).map((c) => c.name);
  assert.ok(failing.includes("recall"), JSON.stringify(early.checks));
  assert.match(early.checks.find((c) => c.name === "recall")?.detail ?? "", /^3\/3 revealed plants caught/);
  for (const name of ["notPromoted", "lineage", "coverage", "assignments", "openIssues", "kernel", "soak"]) {
    assert.ok(early.checks.find((c) => c.name === name)?.pass, `${name} should already pass: ${JSON.stringify(early.checks)}`);
  }
  assert.ok(!plannedNow().some((a) => a.kind === "promote"));
  await pass("plants settle"); // missed-plant settlements, if any (all were caught)

  // ... and passes once enough seeds were caught.
  for (let i = 3; i < plantIds.length; i++) await runPlant(i);
  const ready = evaluatePromotion(state(), "snapshot-1", clock());
  assert.ok(ready.pass, JSON.stringify(ready.checks.filter((c) => !c.pass)));
  assert.match(ready.checks.find((c) => c.name === "recall")?.detail ?? "", /^10\/10 revealed plants caught/);
  assert.ok(!state().settlements.some((x) => x.reason === "missedPlant"));

  // --- The coordinator promotes, then vests the later tranches --------------
  assert.deepEqual(kinds(await pass("promote")), ["promote"]);
  assert.ok(state().snapshots.get("snapshot-1")?.promoted);
  assert.equal(git(repo, "rev-parse", "refs/heads/main"), sMul.headCommit);
  assert.deepEqual(kinds(await pass("tranche 2")), ["settle"]);
  assert.deepEqual(settled("owner-b", "mergeVest", "merge:s-mul:2"), [9]);
  assert.deepEqual(await pass("idle after promotion"), []);
  tick((rules.vesting.tailDays + 1) * 24 * HOUR);
  assert.deepEqual(kinds(await pass("tail")), ["settle"]);
  assert.deepEqual(settled("owner-b", "mergeVest", "merge:s-mul:3"), [9]);
  for (const r of mulReviewers) {
    // round(cleanReview × (1 − p²)) at p = 0.05
    assert.deepEqual(settled(ownerOfAgent.get(r) as OwnerId, "cleanReview", "review:s-mul"), [2], r);
  }
  assert.deepEqual(plannedNow(), []);

  // --- Metrics ------------------------------------------------------------
  const rows = computeMetrics(state(), clock());
  const metric = (name: string) => rows.find((r) => r.metric === name)?.value;
  assert.equal(metric("submissions"), 2); // plants excluded
  assert.equal(metric("merged"), 1);
  assert.equal(metric("tasks"), 1);
  const before = canonical([...state().settlements]);
  computeMetrics(state(), clock());
  assert.equal(canonical([...state().settlements]), before, "metrics mint nothing");

  // --- The CLI over the same ledger ----------------------------------------
  const cli = async (...argv: string[]) => {
    let stdout = "";
    let stderr = "";
    const code = await main(argv, { stdout: (s) => void (stdout += s), stderr: (s) => void (stderr += s), cwd: root, now: () => new Date(nowMs) });
    return { code, stdout, stderr };
  };
  for (const sid of ["s-mul", "s-bug"]) {
    const g = await cli("gates", "--ledger", ledgerPath, "--submission", sid, "--repo", repo, "--patches", patchesDir);
    assert.equal(g.code, 0, `${sid}: ${g.stdout}${g.stderr}`);
    assert.match(g.stdout, /gates: PASS/);
    assert.match(g.stdout, /declaredChange/);
  }
  const m = await cli("metrics", "--ledger", ledgerPath, "--json");
  assert.equal(m.code, 0, m.stderr);
  assert.deepEqual(JSON.parse(m.stdout), JSON.parse(JSON.stringify(rows)), "the CLI computes the same table");
  const promoteCheck = await cli("promote", "check", "--ledger", ledgerPath, "--snapshot", "snapshot-1");
  assert.equal(promoteCheck.code, 1, "already promoted"); // notPromoted fails now
  assert.match(promoteCheck.stdout, /FAIL notPromoted: already promoted/);

  // --- The playground renders the PRs and the snapshot ----------------------
  const pg = startPlayground({ ledgerPath, port: 0, host: "127.0.0.1", nowIso: clock() });
  servers.push(pg);
  if (!pg.listening) await new Promise<void>((r) => pg.once("listening", () => r()));
  const pgUrl = `http://127.0.0.1:${(pg.address() as AddressInfo).port}`;
  const page = async (p: string) => {
    const res = await fetch(`${pgUrl}${p}`);
    assert.equal(res.status, 200, p);
    return res.text();
  };
  const mulPage = await page("/submissions/s-mul");
  assert.match(mulPage, /s-mul/);
  assert.match(mulPage, /merged/);
  assert.match(await page("/submissions/s-bug"), /blocked: confirmed defect/);
  assert.match(await page("/snapshots/snapshot-1"), /promoted to main/);
  assert.match(await page("/submissions/s-p01"), /planted bug \(revealed\)/);
  assert.match(await page("/"), /snapshot-1/);

  // The whole ledger replays from the file to the state the store holds.
  const replayed = replay(Ledger.open(ledgerPath).entries());
  assert.equal(replayed.headHash, state().headHash);
});
