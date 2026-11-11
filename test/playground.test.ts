import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";
import type * as http from "node:http";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { Ledger, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import {
  esc,
  h,
  Html,
  MAX_ENTRIES_PAGE,
  route,
  type Derive,
  type Reply,
  type Site,
} from "../src/playground/render";
import type { EntryBody, LedgerEntry, ReviewVerdict } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: a real file-backed ledger with generated keys, covering most entry
// kinds, with attacker-controlled strings in every free-text field and one
// sealed (never revealed) review whose verdict must not leak.
// ---------------------------------------------------------------------------

const XSS = `<script>alert(1)</script>"><img src=x onerror=alert(2)>`;
const SECRET_SUMMARY = "SECRET-UNREVEALED-VERDICT";
const SECRET_REVIEW_SALT = "a".repeat(64);
const PLANT_SALT = "b".repeat(64);
const NOW = "2026-01-02T00:00:00.000Z";

const T0 = Date.UTC(2026, 0, 1);
let minute = 0;
const tick = () => new Date(T0 + ++minute * 60_000).toISOString();

const tree = treeFromParents({ alice: null, bob: "alice", carol: "alice", dave: "bob" }, { alice: 100, bob: 40 });

function buildFixture() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "playground-"));
  const file = path.join(dir, "ledger.jsonl");
  const admin = generateKeyPair();
  const coord = generateKeyPair();
  const keys = new Map<string, Signer>();
  const key = (name: string) => {
    let k = keys.get(name);
    if (!k) keys.set(name, (k = generateKeyPair()));
    return k;
  };
  const id = (name: string) => keyIdOf(key(name).publicKey);
  const rules = { ...defaultRules(), kernelSigners: ["carol", "dave"] };
  const ledger = Ledger.create(
    file,
    { kind: "genesis", project: "anthill", admins: [admin.publicKey], coordinator: coord.publicKey, rules },
    tick(),
  );
  const add = (body: EntryBody, signer: Signer) => ledger.append(body, signer, tick());

  add({ kind: "ownerKey", owner: "alice", publicKey: key("alice").publicKey, inviter: null }, admin);
  for (const o of ["bob", "carol", "dave"]) {
    add({ kind: "ownerKey", owner: o, publicKey: key(o).publicKey, inviter: "alice" }, admin);
  }
  const agents: [string, string, string][] = [
    ["a1", "alice", "claude"],
    ["b1", "bob", "gpt"],
    ["c1", "carol", "qwen"],
    ["d1", "dave", "kimi"],
  ];
  for (const [agent, owner, modelFamily] of agents) {
    add({ kind: "agentRegistered", owner, publicKey: key(agent).publicKey, modelFamily, harness: `cli ${XSS}` }, key(owner));
  }
  add(
    {
      kind: "proposal",
      id: "p1",
      title: `Fix ${XSS}`,
      evidence: [{ kind: "failingTest", testId: "t", command: "npm test" }],
    },
    key("a1"),
  );
  add(
    { kind: "task", id: "t1", proposalId: "p1", ring: 1, acceptanceTestPaths: ["test/a.test.ts"], sizeEstimate: 50, specAuthor: "bob" },
    coord,
  );
  add({ kind: "claim", taskId: "t1", until: "2026-01-01T12:00:00.000Z", stake: 10 }, key("a1"));
  // The plant commitment for s2 predates s2, and s2 is never revealed.
  add({ kind: "plantCommit", commitment: sha256hex(`s2:${PLANT_SALT}`) }, admin);
  add(
    {
      kind: "submission",
      id: "s1",
      taskId: "t1",
      baseCommit: "base1",
      headCommit: "head1",
      changedFiles: [`src/${XSS}.ts`],
      linesChanged: 40,
    },
    key("a1"),
  );
  add({ kind: "gateResult", submissionId: "s1", gate: "tsc", pass: true, details: `ok ${XSS}` }, coord);
  add({ kind: "reviewAssignment", submissionId: "s1", beacon: "beacon1", reviewers: [id("b1"), id("c1")] }, coord);

  const revealed: ReviewVerdict = { defectProbability: 0.12, summary: `looks fine ${XSS}`, findingIds: [] };
  const sealed: ReviewVerdict = { defectProbability: 0.93, summary: SECRET_SUMMARY, findingIds: [] };
  const revealedSalt = "c".repeat(64);
  add({ kind: "reviewCommit", submissionId: "s1", commitment: sha256hex(canonical(revealed) + revealedSalt), stake: 5 }, key("b1"));
  add({ kind: "reviewCommit", submissionId: "s1", commitment: sha256hex(canonical(sealed) + SECRET_REVIEW_SALT), stake: 5 }, key("c1"));
  add({ kind: "reviewReveal", submissionId: "s1", verdict: revealed, salt: revealedSalt }, key("b1"));

  add(
    {
      kind: "finding",
      id: "F-7",
      target: { submissionId: "s1" },
      severity: "high",
      testPath: `test/${XSS}.test.ts`,
      testCommand: `node ${XSS}`,
      stake: 5,
    },
    key("d1"),
  );
  add(
    { kind: "findingResult", findingId: "F-7", reproduced: false, failsOnHead: false, passesOnParent: true, logDigest: "d1g" },
    coord,
  );
  add({ kind: "merge", submissionId: "s1", commit: "merge1" }, coord);
  add({ kind: "snapshot", id: "S-3", commit: "merge1", previousSnapshotId: null, submissionIds: ["s1"] }, coord);
  add({ kind: "signoff", snapshotId: "S-3" }, key("carol"));
  add({ kind: "promotion", snapshotId: "S-3", commit: "merge1" }, coord);
  add({ kind: "settlement", owner: "dave", delta: -5, reason: "falseFinding", ref: "F-7" }, coord);
  add({ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: "s1" }, coord);
  add(
    { kind: "submission", id: "s2", taskId: null, baseCommit: "merge1", headCommit: "head2", changedFiles: ["src/x.ts"], linesChanged: 3 },
    key("b1"),
  );
  return { dir, file, ledger, coord, a1: id("a1"), c1: id("c1") };
}

const fx = buildFixture();

const fakeDerive: Derive = {
  metrics: () => [
    { group: "review", metric: "seeded recall", value: 0.5, bad: true, note: `low ${XSS}` },
    { group: "flow", metric: "open PRs", value: 1, bad: false, note: "" },
  ],
  promotion: () => ({ pass: false, checks: [{ name: "seeds", pass: false, detail: `0 of 30 ${XSS}` }] }),
  reviewerScores: () => new Map([[fx.a1, { reviews: 0, scored: 0, meanBrier: 0, plantsSeen: 0, plantsCaught: 0 }]]),
};

function site(derive: Derive = fakeDerive): Site {
  const l = Ledger.open(fx.file);
  return { state: l.state(), entries: l.entries(), tree, nowIso: NOW, derive };
}

const get = (url: string, s: () => Site = () => site()): Reply => route(s, "GET", url);

const PAGES = ["/", "/submissions/s1", "/submissions/s2", "/snapshots/S-3", "/owners/alice", "/owners/dave"];
const pagesWithAgents = () => [...PAGES, `/agents/${fx.a1}`, `/agents/${fx.c1}`];
const API = ["/api/state", "/api/entries?since=0", "/api/metrics"];

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

test("esc and h escape every interpolation, and only Html passes through", () => {
  assert.equal(esc(`<a href="x" onclick='y'>&\``), "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&#96;");
  const out = h`<p title="${XSS}">${XSS}${[XSS, h`<b>ok</b>`]}${null}${undefined}${false}${3}</p>`;
  assert.ok(out instanceof Html);
  assert.ok(!out.value.includes("<script>"));
  assert.ok(!out.value.includes("<img"));
  assert.ok(out.value.includes("<b>ok</b>"));
  assert.ok(out.value.endsWith("3</p>"));
});

// ---------------------------------------------------------------------------
// Routes, rendered without a socket (works without metrics/promotion/review)
// ---------------------------------------------------------------------------

test("every page and API route answers 200 with security headers", () => {
  for (const url of [...pagesWithAgents(), ...API, "/static/refresh.js"]) {
    const r = get(url);
    assert.equal(r.status, 200, url);
    assert.match(r.headers["Content-Security-Policy"] ?? "", /default-src 'none'; style-src 'unsafe-inline'; script-src 'self'/, url);
    assert.equal(r.headers["X-Content-Type-Options"], "nosniff", url);
  }
  assert.match(get("/").headers["Content-Type"] ?? "", /^text\/html/);
  assert.match(get("/api/state").headers["Content-Type"] ?? "", /^application\/json/);
  assert.match(get("/static/refresh.js").headers["Content-Type"] ?? "", /^text\/javascript/);
  assert.ok(get("/").body.includes(`<script src="/static/refresh.js"></script>`));
});

test("unknown ids and paths are 404; bad queries 400; writes 405", () => {
  for (const url of [
    "/submissions/nope",
    "/snapshots/nope",
    "/owners/nope",
    "/agents/nope",
    "/nope",
    "/submissions/",
    "/submissions/s1/extra",
    "/api/nope",
    "/static/other.js",
    `/submissions/${encodeURIComponent(XSS)}`,
  ]) {
    const r = get(url);
    assert.equal(r.status, 404, url);
    assert.ok(!r.body.includes("<script>alert"), url);
  }
  assert.equal(get("/api/entries?since=-1").status, 400);
  assert.equal(get("/api/entries?since=abc").status, 400);
  assert.equal(get("/api/entries?limit=0").status, 400);
  assert.equal(get("/submissions/%E0%A4%A").status, 400);
  assert.equal(route(() => site(), "POST", "/").status, 405);
});

test("attacker strings are escaped on every page", () => {
  for (const url of pagesWithAgents()) {
    const body = get(url).body;
    assert.ok(!body.includes("<script>alert"), `${url} contains a raw script tag`);
    assert.ok(!body.includes("<img"), `${url} contains a raw img tag`);
    assert.ok(!/onerror=alert\(2\)>/.test(body) || body.includes("&quot;&gt;&lt;img"), url);
    // exactly one <script> tag: the external refresh script
    assert.equal(body.match(/<script/g)?.length, 1, url);
  }
  const pr = get("/submissions/s1").body;
  assert.ok(pr.includes("Fix &lt;script&gt;alert(1)&lt;/script&gt;"), "proposal title is shown escaped");
  assert.ok(pr.includes("looks fine &lt;script&gt;"), "revealed review summary is shown escaped");
  assert.ok(pr.includes("test/&lt;script&gt;"), "finding test path is shown escaped");
});

test("sealed verdicts, salts and plant meaning never leak", () => {
  const s = site();
  for (const url of [...pagesWithAgents(), ...API]) {
    const body = route(() => s, "GET", url).body;
    assert.ok(!body.includes(SECRET_SUMMARY), `${url} leaks a sealed verdict`);
    assert.ok(!body.includes(SECRET_REVIEW_SALT), `${url} leaks a sealed review's salt`);
    assert.ok(!body.includes(PLANT_SALT), `${url} leaks a plant salt`);
    assert.ok(!/0\.93/.test(body), `${url} leaks the sealed probability`);
  }
  const pr = get("/submissions/s1").body;
  assert.match(pr, /sealed<\/span> commitment recorded/);
  assert.match(pr, /defect p=0\.12/);
  const s2 = get("/submissions/s2").body;
  assert.ok(!/planted/i.test(s2), "an unrevealed plant is not labelled");
  const state = JSON.parse(get("/api/state").body);
  const sub = state.submissions.find((x: { id: string }) => x.id === "s1");
  const c1 = sub.reviews.find((r: { reviewer: string }) => r.reviewer === fx.c1);
  assert.deepEqual(c1, { reviewer: fx.c1, stake: 5, committedSeq: c1.committedSeq, revealed: false });
  assert.equal(state.submissions.find((x: { id: string }) => x.id === "s2").planted, null);
  assert.equal(state.counts.plantCommitments, 1);
});

test("overview renders the stream as sentences and highlights bad metrics", () => {
  const body = get("/").body;
  assert.match(body, /reviewed PR <a class="id" href="\/submissions\/s1"[^>]*>s1<\/a>: defect p=0\.12/);
  assert.match(body, /did not reproduce<\/span>: passes on head, passes on parent/);
  assert.match(body, /snapshot <a class="id" href="\/snapshots\/S-3"[^>]*>S-3<\/a> <span class="b ok">promoted<\/span> to main/);
  assert.match(body, /owner <a href="\/owners\/bob">bob<\/a> joined, invited by/);
  assert.match(body, /<tr class="bad"><td>review<\/td><td>seeded recall<\/td>/);
  assert.match(body, /committed to a planted bug \(sealed\)/);
});

test("submission page shows reviewers with model family and tree distance", () => {
  const body = get("/submissions/s1").body;
  // alice -> bob: 1 edge; alice -> carol: 1 edge
  assert.match(body, /gpt<\/td><td>1<\/td><td>assigned<\/td>/);
  assert.match(body, /qwen<\/td><td>1<\/td><td>assigned<\/td>/);
  assert.match(body, /other model family present/);
  assert.match(body, /did not reproduce/);
});

test("snapshot, owner and agent pages show promotion checks and track records", () => {
  const snap = get("/snapshots/S-3").body;
  assert.match(snap, /promoted to main/);
  assert.match(snap, /not ready/);
  assert.match(snap, /1 of 2 required/);
  assert.match(snap, /1\/2 revealed/);
  const dave = get("/owners/dave").body;
  assert.match(dave, /False findings/);
  assert.match(dave, /<b>1<\/b> false findings/);
  assert.match(dave, /falseFinding/);
  const alice = get("/owners/alice").body;
  assert.match(alice, /<b>1<\/b> merged of 1 PRs/);
  assert.match(alice, /Anthill reputation<\/dt><dd>100/);
});

test("a failing derived statistic renders as unavailable, not a 500", () => {
  const boom = () => {
    throw new Error(`boom ${XSS}`);
  };
  const s = () => site({ metrics: boom, promotion: boom, reviewerScores: boom });
  for (const url of ["/", "/snapshots/S-3", "/owners/alice"]) {
    const r = get(url, s);
    assert.equal(r.status, 200, url);
    assert.match(r.body, /unavailable/, url);
    assert.ok(!r.body.includes("<script>alert"), url);
  }
  assert.equal(get("/api/metrics", s).status, 500);
});

test("an unreadable ledger is a 503, and the refresh script is still served", () => {
  const broken = () => {
    throw new Error("torn <b>line</b>");
  };
  const r = get("/", broken);
  assert.equal(r.status, 503);
  assert.ok(!r.body.includes("<b>line"));
  assert.equal(get("/api/state", broken).status, 503);
  assert.equal(get("/static/refresh.js", broken).status, 200);
});

test("/api/entries pages raw signed entries and caps the page size", () => {
  const all = JSON.parse(get("/api/entries?since=0").body);
  assert.equal(all.entries.length, fx.ledger.entries().length);
  assert.deepEqual(all.entries, fx.ledger.entries(), "entries are the raw signed ledger lines");
  assert.equal(all.next, null);
  const part = JSON.parse(get("/api/entries?since=3&limit=2").body);
  assert.deepEqual(
    part.entries.map((e: LedgerEntry) => e.seq),
    [3, 4],
  );
  assert.equal(part.next, 5);

  // A long ledger: the cap holds whatever limit is asked for.
  const s = site();
  const long = Array.from({ length: 1200 }, (_, i) => ({ ...(s.entries[0] as LedgerEntry), seq: i }));
  const big = JSON.parse(route(() => ({ ...s, entries: long }), "GET", "/api/entries?since=100&limit=100000").body);
  assert.equal(big.entries.length, MAX_ENTRIES_PAGE);
  assert.equal(big.limit, MAX_ENTRIES_PAGE);
  assert.equal(big.next, 100 + MAX_ENTRIES_PAGE);
});

test("/api/state converts maps and carries counts", () => {
  const state = JSON.parse(get("/api/state").body);
  assert.equal(state.project, "anthill");
  assert.equal(state.counts.owners, 4);
  assert.equal(state.counts.merged, 1);
  assert.equal(state.counts.falseFindings, 1);
  assert.ok(Array.isArray(state.owners));
  assert.ok(Array.isArray(state.agents));
  const metrics = JSON.parse(get("/api/metrics").body);
  assert.equal(metrics.rows.length, 2);
});

// ---------------------------------------------------------------------------
// The real server (needs metrics.ts, promotion.ts and review.ts to exist)
// ---------------------------------------------------------------------------

test("startPlayground serves the ledger over HTTP and follows appends", async (t) => {
  let mod: typeof import("../src/playground");
  try {
    mod = await import("../src/playground");
  } catch (e) {
    t.skip(`playground.ts not loadable yet: ${(e as Error).message.split("\n")[0]}`);
    return;
  }
  const server: http.Server = mod.startPlayground({ ledgerPath: fx.file, tree, port: 0, host: "127.0.0.1", nowIso: NOW });
  await new Promise<void>((resolve) => server.once("listening", () => resolve()));
  t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  for (const url of [...pagesWithAgents(), ...API, "/static/refresh.js"]) {
    const res = await fetch(base + url);
    const body = await res.text();
    assert.equal(res.status, 200, `${url}: ${body.slice(0, 300)}`);
    assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/, url);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff", url);
    assert.ok(!body.includes(SECRET_SUMMARY), url);
    assert.ok(!body.includes("<script>alert"), url);
  }
  for (const url of ["/submissions/nope", "/agents/nope", "/owners/nope", "/snapshots/nope", "/x"]) {
    const res = await fetch(base + url);
    await res.text();
    assert.equal(res.status, 404, url);
  }
  const head = await fetch(base + "/", { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), "");

  // An append by another writer shows up on the next request.
  const before = JSON.parse(await (await fetch(base + "/api/state")).text()).length;
  const writer = Ledger.open(fx.file);
  writer.append({ kind: "settlement", owner: "bob", delta: 2, reason: "cleanReview", ref: "s1" }, fx.coord, tick());
  const after = JSON.parse(await (await fetch(base + "/api/state")).text());
  assert.equal(after.length, before + 1);
  assert.equal(after.counts.settlements, 3);
});

test.after(() => fs.rmSync(fx.dir, { recursive: true, force: true }));
