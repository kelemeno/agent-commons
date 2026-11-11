import { after, test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger } from "../src/ledger";
import { computeMetrics, gini, median, reciprocity, type MetricRow } from "../src/metrics";
import { plantCommitment } from "../src/plants";
import { claimStake, defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import type { EntryBody, KeyId, ModelFamily, TreeView } from "../src/types";

// --- a real, signed ledger ----------------------------------------------------

type Key = { publicKey: string; privateKey: string; keyId: KeyId };
const key = (): Key => {
  const k = generateKeyPair();
  return { ...k, keyId: keyIdOf(k.publicKey) };
};
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

const dirs: string[] = [];
after(() => {
  for (const d of dirs) fs.rmSync(d, { recursive: true, force: true });
});

class World {
  readonly ledger: Ledger;
  readonly admin = key();
  readonly coord = key();
  readonly owners = new Map<string, Key>();
  readonly agents = new Map<string, Key>();
  private t = Date.UTC(2026, 9, 1);
  private n = 0;

  constructor() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "metrics-test-"));
    dirs.push(dir);
    this.ledger = Ledger.create(
      path.join(dir, "ledger.jsonl"),
      {
        kind: "genesis",
        project: "anthill",
        admins: [this.admin.publicKey],
        coordinator: this.coord.publicKey,
        rules: defaultRules(),
      },
      new Date(this.t).toISOString(),
    );
  }
  get state() {
    return this.ledger.state();
  }
  now(hours = 0): string {
    return new Date(this.t + hours * HOUR).toISOString();
  }
  advance(hours: number): void {
    this.t += hours * HOUR;
  }
  append(body: EntryBody, signer: Key): void {
    this.t += 60_000;
    this.ledger.append(body, signer, new Date(this.t).toISOString());
  }
  coordinator(body: EntryBody): void {
    this.append(body, this.coord);
  }
  agentKey(name: string): Key {
    const k = this.agents.get(name);
    assert.ok(k, `no agent ${name}`);
    return k;
  }
  // An owner with one agent named after it ("alice" -> agent "alice1").
  person(name: string, family: ModelFamily): void {
    const o = key();
    this.owners.set(name, o);
    this.append({ kind: "ownerKey", owner: name, publicKey: o.publicKey, inviter: null }, this.admin);
    const a = key();
    this.agents.set(`${name}1`, a);
    this.append({ kind: "agentRegistered", owner: name, publicKey: a.publicKey, modelFamily: family, harness: "t" }, o);
  }
  submit(
    id: string,
    author: string,
    files = [`anthill-backend/src/${id}.ts`],
    gate = true,
    taskId: string | null = null,
  ): void {
    this.append(
      { kind: "submission", id, taskId, baseCommit: "b", headCommit: `h-${id}`, changedFiles: files, linesChanged: 10 },
      this.agentKey(author),
    );
    this.coordinator({ kind: "gateResult", submissionId: id, gate: "tests", pass: gate, details: "" });
  }
  // Each reviewer is assigned; commits first, then reveals.
  review(id: string, verdicts: [string, number][]): void {
    this.coordinator({
      kind: "reviewAssignment",
      submissionId: id,
      beacon: "b",
      reviewers: verdicts.map(([a]) => this.agentKey(a).keyId),
    });
    const salts = verdicts.map(() => `salt${this.n++}`);
    const verdict = (p: number) => ({ defectProbability: p, summary: "", findingIds: [] });
    verdicts.forEach(([a, p], i) =>
      this.append(
        { kind: "reviewCommit", submissionId: id, commitment: sha256hex(canonical(verdict(p)) + salts[i]), stake: 5 },
        this.agentKey(a),
      ),
    );
    verdicts.forEach(([a, p], i) =>
      this.append(
        { kind: "reviewReveal", submissionId: id, verdict: verdict(p), salt: salts[i] as string },
        this.agentKey(a),
      ),
    );
  }
  merge(id: string): void {
    this.coordinator({ kind: "merge", submissionId: id, commit: `m-${id}` });
  }
  finding(id: string, finder: string, submissionId: string, reproduced: boolean | null): void {
    this.append(
      {
        kind: "finding",
        id,
        target: { submissionId },
        severity: "high",
        testPath: `test/${id}.test.ts`,
        testCommand: "npm test",
        stake: 5,
      },
      this.agentKey(finder),
    );
    if (reproduced === null) return;
    this.coordinator({
      kind: "findingResult",
      findingId: id,
      reproduced,
      failsOnHead: reproduced,
      passesOnParent: true,
      logDigest: "d",
    });
  }
  plant(id: string, author: string, reviewer: string, p: number): void {
    const salt = `ps${this.n++}`;
    this.append({ kind: "plantCommit", commitment: plantCommitment(id, salt) }, this.admin);
    this.submit(id, author);
    this.review(id, [[reviewer, p]]);
    this.append({ kind: "plantReveal", submissionId: id, salt, description: "d", severity: "high" }, this.admin);
  }
  proposal(id: string, by: string): void {
    this.append(
      { kind: "proposal", id, title: id, evidence: [{ kind: "location", file: "a.ts", line: 1, note: "" }] },
      this.agentKey(by),
    );
  }
}

const PEOPLE: [string, ModelFamily][] = [
  ["alice", "claude"],
  ["bob", "gpt"],
  ["carol", "qwen"],
  ["dave", "deepseek"],
  ["erin", "kimi"],
];
const everyone: TreeView = treeFromParents({ root: null, ...Object.fromEntries(PEOPLE.map(([o]) => [o, "root"])) });

function people(): World {
  const w = new World();
  for (const [o, f] of PEOPLE) w.person(o, f);
  return w;
}

function rowsOf(w: World, now = w.now(), tree = everyone): MetricRow[] {
  return computeMetrics(w.state, tree, now);
}
function get(rows: MetricRow[], metric: string): MetricRow {
  const r = rows.find((x) => x.metric === metric);
  assert.ok(r, `no row ${metric}: ${rows.map((x) => x.metric).join(" | ")}`);
  return r;
}

// --- pure helpers --------------------------------------------------------------

test("gini: equal is 0, one holder of n approaches (n-1)/n, degenerate inputs are 0", () => {
  assert.equal(gini([5, 5, 5, 5]), 0);
  assert.ok(Math.abs(gini([0, 0, 0, 10]) - 0.75) < 1e-12);
  assert.ok(Math.abs(gini([1, 2, 3, 4]) - 0.25) < 1e-12);
  assert.equal(gini([]), 0);
  assert.equal(gini([7]), 0);
  assert.equal(gini([0, 0]), 0);
  assert.equal(gini([3, 1, 2]), gini([1, 2, 3]), "order does not matter");
});

test("median: odd, even, empty, unsorted", () => {
  assert.equal(median([3, 1, 2]), 2);
  assert.equal(median([4, 1, 3, 2]), 2.5);
  assert.equal(median([]), null);
  const xs = [9, 1];
  median(xs);
  assert.deepEqual(xs, [9, 1], "input is not mutated");
});

// --- the table -----------------------------------------------------------------

test("every group is present, rows are well-formed, output is deterministic", () => {
  const w = people();
  const rows = rowsOf(w);
  assert.deepEqual(
    [...new Set(rows.map((r) => r.group))],
    ["reviewer quality", "flow", "trust", "cost & liveness", "direction", "safety"],
  );
  for (const r of rows) {
    assert.ok(typeof r.value === "number" || typeof r.value === "string", r.metric);
    assert.equal(typeof r.bad, "boolean");
    assert.equal(typeof r.note, "string");
    if (typeof r.value === "number") assert.ok(Number.isFinite(r.value), r.metric);
  }
  assert.deepEqual(rowsOf(w), rows);
  assert.throws(() => computeMetrics(w.state, everyone, "2026-10-01T00:00:00"), RangeError);
});

test("an empty commons: recall unmeasured is bad, absent rates are n/a and not bad", () => {
  const rows = rowsOf(people());
  const recall = get(rows, "plant catch rate");
  assert.equal(recall.value, "n/a");
  assert.equal(recall.bad, true);
  for (const m of [
    "false-finding rate",
    "approvals later found defective",
    "merge rate",
    "median hours merge→promotion",
  ]) {
    assert.equal(get(rows, m).value, "n/a", m);
    assert.equal(get(rows, m).bad, false, m);
  }
  assert.equal(get(rows, "failed gates").value, 0);
  assert.equal(get(rows, "reciprocity").value, 0);
});

test("reciprocity: a pair that reviews each other is flagged and named", () => {
  const w = people();
  for (let i = 0; i < 6; i++) {
    w.submit(`a${i}`, "alice1");
    w.review(`a${i}`, [["bob1", 0.05]]);
    w.submit(`b${i}`, "bob1");
    w.review(`b${i}`, [["alice1", 0.05]]);
  }
  w.submit("c0", "carol1");
  w.review("c0", [["dave1", 0.1]]);
  w.submit("c1", "carol1");
  w.review("c1", [["erin1", 0.1]]);

  const rec = reciprocity(w.state);
  assert.equal(rec.total, 14);
  assert.deepEqual(rec.pair, ["alice", "bob"]);
  assert.ok(Math.abs(rec.share - 12 / 14) < 1e-12);
  const row = get(rowsOf(w), "reciprocity");
  assert.equal(row.bad, true);
  assert.equal(row.value, 0.857);
  assert.match(row.note, /alice ↔ bob exchanged 12 of 14 reviews/);
});

test("reciprocity: one-way reviewing (a cycle) is not reciprocity; small samples are not judged", () => {
  const w = people();
  const ring = ["alice1", "bob1", "carol1", "dave1"];
  for (let i = 0; i < 12; i++) {
    const author = ring[i % 4] as string;
    const reviewer = ring[(i + 1) % 4] as string;
    w.submit(`x${i}`, author);
    w.review(`x${i}`, [[reviewer, 0.1]]);
  }
  const row = get(rowsOf(w), "reciprocity");
  assert.equal(row.value, 0);
  assert.equal(row.bad, false);
  assert.match(row.note, /12 reviews, no owner pair/);

  // A perfectly reciprocal pair, but below 10 reviews: reported, not flagged.
  const v = people();
  for (let i = 0; i < 2; i++) {
    v.submit(`a${i}`, "alice1");
    v.review(`a${i}`, [["bob1", 0.1]]);
    v.submit(`b${i}`, "bob1");
    v.review(`b${i}`, [["alice1", 0.1]]);
  }
  const small = get(rowsOf(v), "reciprocity");
  assert.equal(small.value, 1);
  assert.equal(small.bad, false);
});

test("reviewer quality: plant catch rate overall and per family, false findings, defective approvals", () => {
  const w = people();
  w.plant("p1", "erin1", "alice1", 0.9); // caught by claude
  w.plant("p2", "erin1", "alice1", 0.1); // missed by claude
  w.plant("p3", "erin1", "bob1", 0.9); // caught by gpt
  w.submit("s1", "carol1");
  w.review("s1", [
    ["alice1", 0.1],
    ["bob1", 0.2],
    ["dave1", 0.7], // a flag, not an approval
  ]);
  w.merge("s1");
  w.finding("f1", "dave1", "s1", true); // the approvals were wrong
  w.finding("f2", "alice1", "s1", false);
  w.finding("f3", "bob1", "s1", false);
  w.finding("f4", "erin1", "s1", null); // undecided: not judged

  const rows = rowsOf(w);
  const recall = get(rows, "plant catch rate");
  assert.equal(recall.value, 0.667);
  assert.equal(recall.bad, true, "3 seeds cannot clear the promotion floor");
  assert.match(recall.note, /2\/3/);
  assert.equal(get(rows, "plant catch rate (claude)").value, 0.5);
  assert.equal(get(rows, "plant catch rate (claude)").bad, true);
  assert.equal(get(rows, "plant catch rate (gpt)").value, 1);
  assert.equal(get(rows, "plant catch rate (gpt)").bad, false);
  const ff = get(rows, "false-finding rate");
  assert.equal(ff.value, 0.667);
  assert.equal(ff.bad, true);
  const da = get(rows, "approvals later found defective");
  assert.equal(da.value, 1);
  assert.equal(da.bad, true);
  assert.match(da.note, /2\/2 approvals/);
});

test("flow: counts, merge rate, medians, open submissions per ring; plants and dead work excluded", () => {
  const w = people();
  w.plant("p1", "erin1", "alice1", 0.9);
  w.submit("s1", "alice1");
  w.advance(10);
  w.review("s1", [["bob1", 0.1]]);
  w.merge("s1"); // ~10h
  w.submit("s2", "bob1");
  w.advance(30);
  w.review("s2", [["carol1", 0.1]]);
  w.merge("s2"); // ~30h
  w.submit("s3", "carol1", ["anthill-frontend/src/Button.tsx"]); // ring 2, open
  w.submit("s4", "dave1"); // ring 1, open
  w.submit("s5", "dave1", ["anthill-backend/src/x5.ts"]);
  w.finding("f1", "alice1", "s5", true); // dead: can never merge
  w.proposal("P1", "alice1");
  w.coordinator({
    kind: "task",
    id: "T1",
    proposalId: "P1",
    ring: 0,
    acceptanceTestPaths: ["test/t.test.ts"],
    sizeEstimate: 10,
    specAuthor: "carol",
  });
  w.append(
    { kind: "claim", taskId: "T1", until: w.now(24), stake: claimStake(10, 0, w.state.rules) },
    w.agentKey("alice1"),
  );
  w.submit("s6", "alice1", ["anthill-backend/src/engine.ts", "anthill-frontend/src/A.tsx"], true, "T1"); // ring 0, open
  w.coordinator({ kind: "snapshot", id: "S1", commit: "c", previousSnapshotId: null, submissionIds: ["s1", "s2"] });
  w.advance(100);
  w.coordinator({ kind: "promotion", snapshotId: "S1", commit: "c" });

  const rows = rowsOf(w);
  assert.equal(get(rows, "proposals").value, 1);
  assert.equal(get(rows, "tasks").value, 1);
  assert.equal(get(rows, "submissions").value, 6, "the revealed plant is not organic work");
  assert.equal(get(rows, "merged").value, 2);
  assert.equal(get(rows, "merge rate").value, 0.333);
  const toMerge = get(rows, "median hours submission→merge").value as number;
  assert.ok(toMerge > 20 && toMerge < 21, String(toMerge)); // (10.07 + 30.1) / 2
  const toPromo = get(rows, "median hours merge→promotion").value as number;
  assert.ok(toPromo > 100 && toPromo < 131, String(toPromo));
  assert.equal(get(rows, "open submissions (ring 0)").value, 1);
  assert.equal(get(rows, "open submissions (ring 1)").value, 1, "s5 is dead");
  assert.equal(get(rows, "open submissions (ring 2)").value, 1);
});

test("merge→promotion counts a promotion that shipped an ancestor snapshot", () => {
  const w = people();
  for (const id of ["s1", "s2"]) {
    w.submit(id, "alice1");
    w.review(id, [["bob1", 0.1]]);
    w.merge(id);
  }
  w.coordinator({ kind: "snapshot", id: "S1", commit: "c1", previousSnapshotId: null, submissionIds: ["s1"] });
  w.coordinator({ kind: "snapshot", id: "S2", commit: "c2", previousSnapshotId: "S1", submissionIds: ["s2"] });
  w.advance(50);
  w.coordinator({ kind: "promotion", snapshotId: "S2", commit: "c2" });
  const row = get(rowsOf(w), "median hours merge→promotion");
  assert.match(row.note, /over 2 shipped/);
});

test("trust: locked stake, slashes against payouts, Gini of merges and reveals", () => {
  const w = people();
  for (let i = 0; i < 10; i++) {
    w.submit(`s${i}`, "alice1");
    w.review(`s${i}`, [["bob1", 0.1]]);
    w.merge(`s${i}`);
  }
  w.submit("open", "carol1");
  w.append({ kind: "reviewCommit", submissionId: "open", commitment: sha256hex("x"), stake: 7 }, w.agentKey("dave1"));
  w.coordinator({ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: "s0" });
  w.coordinator({ kind: "settlement", owner: "bob", delta: -6, reason: "missedPlant", ref: "p" });
  let rows = rowsOf(w);
  assert.equal(get(rows, "reputation staked (locked)").value, 7);
  assert.equal(get(rows, "reputation slashed").value, 6);
  assert.equal(get(rows, "reputation slashed").bad, false);
  const merges = get(rows, "Gini of merges across owners");
  assert.equal(merges.value, 0.8, "one of five owners merged everything");
  assert.equal(merges.bad, true);
  assert.equal(get(rows, "Gini of review reveals across owners").bad, true);

  w.coordinator({ kind: "settlement", owner: "carol", delta: -5, reason: "falseFinding", ref: "f" });
  rows = rowsOf(w);
  assert.equal(get(rows, "reputation slashed").value, 11);
  assert.equal(get(rows, "reputation slashed").bad, true, "more taken than paid");
});

test("trust: owners the tree does not know are flagged", () => {
  const w = people();
  const partial = treeFromParents({ root: null, alice: "root", bob: "root", carol: "root" });
  const row = get(rowsOf(w, w.now(), partial), "owners outside the tree");
  assert.equal(row.value, 2);
  assert.equal(row.bad, true);
  assert.equal(row.note, "dave, erin");
  assert.equal(get(rowsOf(w), "owners outside the tree").bad, false);
});

test("liveness: active agents and owners in the last 7 days; too few owners to staff a panel is bad", () => {
  const w = people();
  w.submit("s1", "alice1");
  w.review("s1", [
    ["bob1", 0.1],
    ["carol1", 0.1],
    ["dave1", 0.1],
  ]);
  w.merge("s1");
  let rows = rowsOf(w);
  assert.equal(get(rows, "active agents").value, 4);
  assert.equal(get(rows, "active owners").value, 4);
  assert.equal(get(rows, "active owners").bad, false, "4 = 3 reviewers + the author");
  assert.equal(get(rows, "agents per owner").value, 1);

  rows = rowsOf(w, w.now(8 * 24));
  assert.equal(get(rows, "active agents").value, 0);
  assert.equal(get(rows, "active agents").bad, true);
  assert.equal(get(rows, "active owners").bad, true);
  assert.equal(get(rows, "agents per owner").value, "n/a");

  // A revoked agent is not active even if it acted recently.
  w.append({ kind: "agentRevoked", agent: w.agentKey("bob1").keyId, reason: "r" }, w.owners.get("bob") as Key);
  assert.equal(get(rowsOf(w), "active agents").value, 3);
});

test("direction: proposals without a task older than 14 days", () => {
  const w = people();
  for (let i = 0; i < 7; i++) w.proposal(`P${i}`, "alice1");
  w.coordinator({
    kind: "task",
    id: "T0",
    proposalId: "P0",
    ring: 1,
    acceptanceTestPaths: ["test/t.test.ts"],
    sizeEstimate: 10,
    specAuthor: "carol",
  });
  w.submit("s1", "bob1"); // any entry that records its time
  const metric = "open proposals older than 14 days";
  assert.equal(get(rowsOf(w), metric).value, 0);
  w.advance(15 * 24);
  w.proposal("Pnew", "bob1");
  const row = get(rowsOf(w), metric);
  assert.equal(row.value, 6, "P0 has a task; Pnew is fresh");
  assert.equal(row.bad, true);
});

test("direction: with no timed entry after them, proposals are dated by the next known time (documented leniency)", () => {
  const w = people();
  w.proposal("P0", "alice1");
  w.advance(15 * 24);
  w.proposal("P1", "alice1"); // the head: the only later time the state keeps
  assert.equal(get(rowsOf(w), "open proposals older than 14 days").value, 0);
  // Once the head itself is 14 days old, both are.
  assert.equal(get(rowsOf(w, w.now(15 * 24)), "open proposals older than 14 days").value, 2);
});

test("safety: honeytokens, escapes and failed gates by gate", () => {
  const w = people();
  w.submit("s1", "alice1");
  w.review("s1", [["bob1", 0.1]]);
  w.merge("s1");
  w.coordinator({ kind: "snapshot", id: "S1", commit: "c", previousSnapshotId: null, submissionIds: ["s1"] });
  w.coordinator({ kind: "promotion", snapshotId: "S1", commit: "c" });
  w.finding("f1", "carol1", "s1", true);
  w.coordinator({ kind: "escape", findingId: "f1", snapshotId: "S1" });
  w.coordinator({ kind: "honeytokenTriggered", agent: w.agentKey("dave1").keyId, tokenId: "tok" });
  for (let i = 0; i < 10; i++) w.submit(`bad${i}`, "erin1", undefined, i < 4);
  const rows = rowsOf(w);
  assert.equal(get(rows, "honeytoken triggers").value, 1);
  assert.equal(get(rows, "honeytoken triggers").bad, true);
  assert.equal(get(rows, "escapes").value, 1);
  assert.equal(get(rows, "escapes").bad, true);
  const gates = get(rows, "failed gates (tests)");
  assert.equal(gates.value, 6);
  assert.equal(gates.bad, true, "6/11 runs failed");
  assert.equal(
    rows.some((r) => r.metric === "failed gates"),
    false,
  );
});

test("metrics never mutate the state", () => {
  const w = people();
  w.submit("s1", "alice1");
  w.review("s1", [["bob1", 0.1]]);
  const before = w.state.headHash;
  const subs = JSON.stringify([...w.state.submissions.values()]);
  rowsOf(w);
  assert.equal(w.state.headHash, before);
  assert.equal(JSON.stringify([...w.state.submissions.values()]), subs);
});
