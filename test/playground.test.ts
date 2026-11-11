import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";
import type * as http from "node:http";
import { canonical, generateKeyPair, keyIdOf, sha256hex } from "../src/crypto";
import { commitmentFor } from "../src/review";
import { LEDGER_LIMITS, Ledger, LedgerError, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import {
  CLIP,
  clip,
  esc,
  h,
  Html,
  MAX_ENTRIES_BYTES,
  MAX_ENTRIES_PAGE,
  route,
  type Derive,
  type Reply,
  type Site,
} from "../src/playground/render";
import { startPlayground } from "../src/playground";
import type { EntryBody, LedgerEntry, ReviewVerdict } from "../src/types";
import { assignmentBody } from "../src/selection";

// ---------------------------------------------------------------------------
// Fixture: a real file-backed ledger with generated keys, covering most entry
// kind, with attacker-controlled strings in every free-text field and in ids
// (which are rendered inside attributes), one sealed review and one sealed
// attestation whose verdicts must not leak, and an unrevealed plant.
// ---------------------------------------------------------------------------

const XSS = `<script>alert(1)</script>"><img src=x onerror=alert(2)>`;
// Breaks out of a double-quoted attribute if it is not escaped there.
const ATTR = `q" onmouseover="alert(3)" data-x="`;
const SECRET_SUMMARY = "SECRET-UNREVEALED-VERDICT";
const SECRET_REVIEW_SALT = "a".repeat(64);
const SECRET_ATTEST = "SECRET-UNREVEALED-ATTESTATION";
const SECRET_ATTEST_SALT = "f".repeat(64);
const PLANT_SALT = "b".repeat(64);
// Ids can no longer carry markup (the ledger's ID_RE), so attribute escaping is
// exercised through free-text fields (the settlement ref below); these ids keep
// the characters ids may still hold that matter in a URL ('.' in a submission
// id, ':' in a finding id; submission ids name git refs, which refuse ':').
const PLANT3_ID = "s3.plant.x";
const FINDING8_ID = "F-8:x";
const NOW = "2026-01-02T00:00:00.000Z";

const T0 = Date.UTC(2026, 0, 1);
let minute = 0;
const tick = () => new Date(T0 + ++minute * 60_000).toISOString();


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
    { kind: "genesis", project: "demo", admins: [admin.publicKey], coordinator: coord.publicKey, rules },
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
  add(assignmentBody(ledger.state(), "s1", [id("b1"), id("c1")], "e"), coord);

  const revealed: ReviewVerdict = { defectProbability: 0.12, summary: `looks fine ${XSS}`, findingIds: [] };
  const sealed: ReviewVerdict = { defectProbability: 0.93, summary: SECRET_SUMMARY, findingIds: [] };
  const revealedSalt = "c".repeat(64);
  add({ kind: "reviewCommit", submissionId: "s1", commitment: commitmentFor(revealed, revealedSalt, id("b1"), { submissionId: "s1" }), stake: 5 }, key("b1"));
  add({ kind: "reviewCommit", submissionId: "s1", commitment: commitmentFor(sealed, SECRET_REVIEW_SALT, id("c1"), { submissionId: "s1" }), stake: 5 }, key("c1"));
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
  const attested: ReviewVerdict = { defectProbability: 0.05, summary: `ships ${XSS}`, findingIds: [] };
  const sealedAttest: ReviewVerdict = { defectProbability: 0.81, summary: SECRET_ATTEST, findingIds: [] };
  const attestSalt = "9".repeat(64);
  add({ kind: "attestCommit", snapshotId: "S-3", commitment: commitmentFor(sealedAttest, SECRET_ATTEST_SALT, id("c1"), { snapshotId: "S-3" }), stake: 5 }, key("c1"));
  add({ kind: "attestCommit", snapshotId: "S-3", commitment: commitmentFor(attested, attestSalt, id("b1"), { snapshotId: "S-3" }), stake: 5 }, key("b1"));
  minute += defaultRules().review.commitHours * 60; // attestation reveals wait for the commit phase
  add({ kind: "attestReveal", snapshotId: "S-3", verdict: attested, salt: attestSalt }, key("b1"));
  add({ kind: "signoff", snapshotId: "S-3" }, key("carol"));
  add({ kind: "promotion", snapshotId: "S-3", commit: "merge1" }, coord);
  add(
    { kind: "finding", id: FINDING8_ID, target: { snapshotId: "S-3" }, severity: "critical", testPath: "test/b.test.ts", testCommand: "npm test", stake: 5 },
    key("d1"),
  );
  add(
    { kind: "findingResult", findingId: FINDING8_ID, reproduced: true, failsOnHead: true, passesOnParent: true, logDigest: "d2g" },
    coord,
  );
  add({ kind: "findingDecision", findingId: FINDING8_ID, confirmed: true, reason: "a real defect" }, admin);
  add({ kind: "escape", findingId: FINDING8_ID, snapshotId: "S-3" }, coord);
  add({ kind: "settlement", owner: "dave", delta: -5, reason: "falseFinding", ref: "F-7" }, coord);
  add({ kind: "settlement", owner: "alice", delta: 10, reason: "mergeVest", ref: "s1" }, coord);
  add({ kind: "settlement", owner: "bob", delta: 1, reason: "cleanReview", ref: ATTR }, coord);
  add(
    { kind: "submission", id: "s2", taskId: null, baseCommit: "merge1", headCommit: "head2", changedFiles: ["src/x.ts"], linesChanged: 3 },
    key("b1"),
  );
  // A failure and a later pass of the same gate: the failure still blocks (ledger merge rule).
  add({ kind: "gateResult", submissionId: "s2", gate: "tsc", pass: false, details: "1 error" }, coord);
  add({ kind: "gateResult", submissionId: "s2", gate: "tsc", pass: true, details: "ok" }, coord);
  // A revealed plant, with an attribute-breaking id.
  const plant3Salt = "e".repeat(64);
  add({ kind: "plantCommit", commitment: sha256hex(`${PLANT3_ID}:${plant3Salt}`) }, admin);
  add(
    { kind: "submission", id: PLANT3_ID, taskId: null, baseCommit: "merge1", headCommit: "head3", changedFiles: ["src/z.ts"], linesChanged: 1 },
    key("b1"),
  );
  add({ kind: "plantReveal", submissionId: PLANT3_ID, salt: plant3Salt, description: `off by one ${XSS}`, severity: "high" }, admin);
  // Ids that are URL dot segments no longer reach the playground: the ledger
  // refuses them (ID_RE). An id with dots inside is fine (not "..", which git refs refuse).
  const fourth = (id: string): EntryBody => ({ kind: "submission", id, taskId: null, baseCommit: "merge1", headCommit: "head4", changedFiles: ["src/y.ts"], linesChanged: 2 });
  for (const bad of ["..", "."]) assert.throws(() => add(fourth(bad), key("b1")), (e: unknown) => e instanceof LedgerError && e.code === "malformed");
  const dots = add(fourth("s4.x.y"), key("b1"));
  add({ kind: "honeytokenTriggered", agent: id("c1"), tokenId: "tok:1" }, coord);
  add({ kind: "rulesChange", rules: { ...rules, version: rules.version + 1 }, pollId: "poll:1" }, admin);
  add({ kind: "agentRevoked", agent: id("d1"), reason: `retired ${XSS}` }, key("dave"));
  return { dir, file, ledger, coord, a1: id("a1"), c1: id("c1"), dotsSeq: dots.seq };
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

const quiet = () => {};

function site(derive: Derive = fakeDerive): Site {
  const l = Ledger.open(fx.file);
  return { state: l.state(), entries: l.entries(), nowIso: NOW, derive, log: quiet };
}

const get = (url: string, s: () => Site = () => site()): Reply => route(s, "GET", url, quiet);

const PAGES = [
  "/",
  "/submissions/s1",
  "/submissions/s2",
  `/submissions/${encodeURIComponent(PLANT3_ID)}`,
  "/snapshots/S-3",
  "/owners/alice",
  "/owners/bob",
  "/owners/dave",
];
const pagesWithAgents = () => [...PAGES, `/submissions?seq=${fx.dotsSeq}`, `/agents/${fx.a1}`, `/agents/${fx.c1}`];
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
    // Our own markup has no event handlers, so any one is a broken-out attribute.
    assert.ok(!/"\s*on[a-z]+=/i.test(body), `${url} lets a value break out of an attribute`);
    // exactly one <script> tag: the external refresh script
    assert.equal(body.match(/<script/g)?.length, 1, url);
  }
  const pr = get("/submissions/s1").body;
  assert.ok(pr.includes("Fix &lt;script&gt;alert(1)&lt;/script&gt;"), "proposal title is shown escaped");
  assert.ok(pr.includes("looks fine &lt;script&gt;"), "revealed review summary is shown escaped");
  assert.ok(pr.includes("test/&lt;script&gt;"), "finding test path is shown escaped");
  // Ids land in attributes (title=, href=, id=) and are escaped there too.
  const overview = get("/").body;
  assert.ok(overview.includes(`title="${esc(PLANT3_ID)}"`), "a submission id is escaped inside title=");
  assert.ok(overview.includes(`title="${esc("tok:1")}"`), "a honeytoken id is shown inside title=");
  assert.ok(overview.includes(`title="${esc("poll:1")}"`), "a poll id is shown inside title=");
  assert.ok(overview.includes(`href="/submissions/${encodeURIComponent(PLANT3_ID)}"`), "an id is URL-encoded in href=");
  assert.ok(get("/owners/bob").body.includes(`title="${esc(ATTR)}"`), "a settlement ref is escaped inside title=");
  assert.ok(get("/snapshots/S-3").body.includes(`title="${esc(FINDING8_ID)}"`), "a finding id is escaped inside title=");
});

test("sealed verdicts, salts and plant meaning never leak", () => {
  const s = site();
  for (const url of [...pagesWithAgents(), ...API]) {
    const body = route(() => s, "GET", url, quiet).body;
    assert.ok(!body.includes(SECRET_SUMMARY), `${url} leaks a sealed verdict`);
    assert.ok(!body.includes(SECRET_REVIEW_SALT), `${url} leaks a sealed review's salt`);
    assert.ok(!body.includes(SECRET_ATTEST), `${url} leaks a sealed attestation`);
    assert.ok(!body.includes(SECRET_ATTEST_SALT), `${url} leaks a sealed attestation's salt`);
    assert.ok(!body.includes(PLANT_SALT), `${url} leaks a plant salt`);
    assert.ok(!/0\.93|0\.81/.test(body), `${url} leaks a sealed probability`);
  }
  const pr = get("/submissions/s1").body;
  assert.match(pr, /sealed<\/span> commitment recorded/);
  assert.match(pr, /defect p=0\.12/);
  const snap = get("/snapshots/S-3").body;
  assert.match(snap, /sealed<\/span> commitment recorded/, "the sealed attestation is shown as a commitment only");
  assert.match(snap, /defect p=0\.05/, "the revealed attestation is shown");
  const s2 = get("/submissions/s2").body;
  assert.ok(!/planted/i.test(s2), "an unrevealed plant is not labelled");
  assert.match(get(`/submissions/${encodeURIComponent(PLANT3_ID)}`).body, /planted bug \(revealed\)/);

  const state = JSON.parse(get("/api/state").body);
  const sub = state.recentSubmissions.find((x: { id: string }) => x.id === "s1");
  assert.deepEqual(sub.reviews, { committed: 2, revealed: 1 });
  assert.equal(state.recentSubmissions.find((x: { id: string }) => x.id === "s2").planted, false);
  assert.equal(state.recentSubmissions.find((x: { id: string }) => x.id === PLANT3_ID).planted, true);
  assert.deepEqual(state.recentSnapshots.find((x: { id: string }) => x.id === "S-3").attestations, { committed: 2, revealed: 1 });
  // The number of outstanding plants is not published.
  assert.equal(state.counts.plantCommitments, undefined);
  assert.ok(!/verdict|summary|salt|commitment/i.test(get("/api/state").body), "/api/state carries no verdicts or commitments");
});

test("overview renders every entry kind as a sentence, except plant commitments", () => {
  const body = get("/").body;
  for (const [kind, pattern] of [
    ["reviewReveal", /reviewed PR <a class="id" href="\/submissions\/s1"[^>]*>s1<\/a>: defect p=0\.12/],
    ["findingResult", /did not reproduce<\/span>: passes on head, passes on parent/],
    ["promotion", /snapshot <a class="id" href="\/snapshots\/S-3"[^>]*>S-3<\/a> <span class="b ok">promoted<\/span> to main/],
    ["ownerKey", /owner <a href="\/owners\/bob">bob<\/a> joined, invited by/],
    ["agentRevoked", /was revoked by its owner: retired &lt;script&gt;/],
    ["attestCommit", /sealed an attestation of snapshot/],
    ["attestReveal", /attested snapshot <a[^>]*>S-3<\/a>: defect p=0\.05 — ships &lt;script&gt;/],
    ["plantReveal", /revealed as a <span class="b warn">planted bug<\/span> \(high\): off by one &lt;script&gt;/],
    ["honeytokenTriggered", /<span class="b bad">triggered a honeytoken<\/span>/],
    ["escape", /<span class="b bad">escape<\/span>: finding <a/],
    ["rulesChange", /rules changed to v\d+ \(poll <code/],
    ["settlement", /<span class="b ok">\+1<\/span> \(cleanReview, <code/],
  ] as const) {
    assert.match(body, pattern, kind);
  }
  assert.match(body, /<tr class="bad"><td>review<\/td><td>seeded recall<\/td>/);
  assert.ok(!body.includes("committed to a planted bug"), "plant commitments are not placed in the stream");
});

test("an object is reachable by path, by the seq that created it and by id", () => {
  const overview = get("/").body;
  assert.ok(overview.includes(`href="/submissions/s4.x.y"`), "an ordinary id is linked by path");
  for (const url of ["/submissions/s4.x.y", `/submissions?seq=${fx.dotsSeq}`, "/submissions?id=s4.x.y"]) {
    const r = get(url);
    assert.equal(r.status, 200, url);
    assert.match(r.body, /<h1>PR <code class="id" title="s4\.x\.y">s4\.x\.y<\/code>/, url);
  }
  assert.equal(get("/submissions?seq=0").status, 404, "seq of an entry that is not a submission");
  assert.equal(get("/submissions?seq=99999").status, 404);
  assert.equal(get("/submissions?id=nope").status, 404);
  assert.equal(get("/snapshots?seq=x").status, 404);
});

test("submission page shows reviewers with model family and tree distance", () => {
  const body = get("/submissions/s1").body;
  // In the member tree alice invited bob and carol: 1 edge each
  assert.match(body, /gpt<\/td><td>1<\/td><td>assigned<\/td>/);
  assert.match(body, /qwen<\/td><td>1<\/td><td>assigned<\/td>/);
  assert.match(body, /other model family present/);
  assert.match(body, /did not reproduce/);
});

test("a failed gate stays a block after a later pass, and the page says why", () => {
  const body = get("/submissions/s2").body;
  assert.match(body, /blocked: gate failed/);
  assert.match(body, /a later run passed; the ledger still counts this failure/);
});

test("snapshot, owner and agent pages show promotion checks and track records", () => {
  const snap = get("/snapshots/S-3").body;
  assert.match(snap, /promoted to main/);
  assert.match(snap, /not ready/);
  assert.match(snap, /1 of 2 required/);
  assert.match(snap, /1\/2 revealed/);
  assert.match(snap, /<h2>Escapes<\/h2>/);
  const dave = get("/owners/dave").body;
  assert.match(dave, /False findings/);
  assert.match(dave, /<b>1<\/b> false findings/);
  assert.match(dave, /<b>1<\/b> findings held up/);
  assert.match(dave, /falseFinding/);
  const alice = get("/owners/alice").body;
  assert.match(alice, /<b>1<\/b> merged of 1 PRs/);
  assert.match(alice, /invited by<\/dt><dd>nobody \(founding owner\)/);
  assert.match(get("/owners/bob").body, /invited by<\/dt><dd><a [^>]*>alice<\/a>/);
});

test("failures never put exception text on a public reply", () => {
  const secret = "/srv/operator/secret/ledger.jsonl";
  const boom = () => {
    throw new Error(`boom ${secret} ${XSS}`);
  };
  const logged: unknown[] = [];
  const s = () => ({ ...site({ metrics: boom, promotion: boom, reviewerScores: boom }), log: (e: unknown) => logged.push(e) });
  for (const url of ["/", "/snapshots/S-3", "/owners/alice"]) {
    const r = route(s, "GET", url, quiet);
    assert.equal(r.status, 200, url);
    assert.match(r.body, /unavailable/, url);
    assert.ok(!r.body.includes("boom") && !r.body.includes(secret), url);
  }
  const m = route(s, "GET", "/api/metrics", quiet);
  assert.equal(m.status, 500);
  assert.ok(!m.body.includes("boom"));
  assert.ok(logged.length >= 3, "failures are logged instead");
});

test("an unreadable ledger is a 503 with only the error code, and the refresh script is still served", () => {
  const secretPath = "/srv/operator/secret/ledger.jsonl";
  const torn = () => {
    throw new LedgerError("torn", `last line of ${secretPath} is not terminated <b>x</b>`);
  };
  const enoent = () => {
    throw new Error(`ENOENT: no such file or directory, stat '${secretPath}'`);
  };
  const logged: unknown[] = [];
  const log = (e: unknown) => logged.push(e);
  const html = route(torn, "GET", "/", log);
  assert.equal(html.status, 503);
  assert.ok(!html.body.includes(secretPath) && !html.body.includes("<b>x"));
  assert.match(html.body, /\(torn\)/);
  const json = route(torn, "GET", "/api/state", log);
  assert.equal(json.status, 503);
  assert.deepEqual(JSON.parse(json.body), { error: "ledger unavailable", code: "torn" });
  for (const url of ["/", "/api/state"]) {
    const r = route(enoent, "GET", url, log);
    assert.equal(r.status, 503, url);
    assert.ok(!r.body.includes(secretPath) && !r.body.includes("ENOENT"), url);
  }
  assert.equal(logged.length, 4);
  assert.equal(route(torn, "GET", "/static/refresh.js", log).status, 200);
});

test("/api/entries pages raw signed entries and caps the page size", () => {
  const all = JSON.parse(get("/api/entries?since=0").body);
  assert.equal(all.entries.length, fx.ledger.entries().length);
  assert.deepEqual(all.entries, fx.ledger.entries(), "entries are the raw signed ledger lines");
  assert.equal(all.next, null);
  assert.match(all.cursor, /inclusive/);
  const part = JSON.parse(get("/api/entries?since=3&limit=2").body);
  assert.deepEqual(
    part.entries.map((e: LedgerEntry) => e.seq),
    [3, 4],
  );
  assert.equal(part.next, 5);

  // A long ledger: the cap holds whatever limit is asked for.
  const s = site();
  const long = Array.from({ length: 1200 }, (_, i) => ({ ...(s.entries[0] as LedgerEntry), seq: i }));
  const big = JSON.parse(route(() => ({ ...s, entries: long }), "GET", "/api/entries?since=100&limit=100000", quiet).body);
  assert.equal(big.entries.length, MAX_ENTRIES_PAGE);
  assert.equal(big.limit, MAX_ENTRIES_PAGE);
  assert.equal(big.next, 100 + MAX_ENTRIES_PAGE);
});

test("/api/state carries counts and short summaries, compactly", () => {
  const body = get("/api/state").body;
  assert.ok(!body.includes("\n"), "no pretty-printing");
  const state = JSON.parse(body);
  assert.equal(state.project, "demo");
  assert.equal(state.counts.owners, 4);
  assert.equal(state.counts.merged, 1);
  assert.equal(state.counts.falseFindings, 1);
  assert.equal(state.counts.plantsRevealed, 1);
  assert.ok(Array.isArray(state.owners));
  assert.equal(state.owners.find((o: { id: string }) => o.id === "bob").agents, 1);
  assert.equal(state.recentSubmissions[0].id, "s4.x.y", "newest first");
  assert.equal(state.recentSubmissions[0].page, "/submissions/s4.x.y");
  assert.equal(state.recentSubmissions.find((x: { id: string }) => x.id === "s1").status, "merged");
  const metrics = JSON.parse(get("/api/metrics").body);
  assert.equal(metrics.rows.length, 2);
});

// ---------------------------------------------------------------------------
// Size: one agent writing huge strings and lists must not make pages huge
// ---------------------------------------------------------------------------

// The ledger bounds every field (LEDGER_LIMITS), so the biggest a page can get
// is built from values at those limits; the playground still clips what is
// longer than it shows.
test("titles, texts, paths and lists at the ledger's limits are clipped, and /api/entries is capped by bytes", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "playground-big-"));
  try {
    const file = path.join(dir, "ledger.jsonl");
    const admin = generateKeyPair();
    const coord = generateKeyPair();
    const [alice, bob, a1, b1] = [generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair()];
    const ledger = Ledger.create(
      file,
      { kind: "genesis", project: "demo", admins: [admin.publicKey], coordinator: coord.publicKey, rules: defaultRules() },
      tick(),
    );
    const add = (body: EntryBody, signer: Signer) => ledger.append(body, signer, tick());
    const LIM = LEDGER_LIMITS;
    const TEXT = "x".repeat(LIM.text);
    add({ kind: "ownerKey", owner: "alice", publicKey: alice.publicKey, inviter: null }, admin);
    add({ kind: "ownerKey", owner: "bob", publicKey: bob.publicKey, inviter: "alice" }, admin);
    add({ kind: "agentRegistered", owner: "alice", publicKey: a1.publicKey, modelFamily: "claude", harness: "h".repeat(LIM.name) }, alice);
    add({ kind: "agentRegistered", owner: "bob", publicKey: b1.publicKey, modelFamily: "gpt", harness: "cli" }, bob);
    for (let i = 0; i < 3; i++) {
      add({ kind: "proposal", id: `p${i}`, title: "x".repeat(LIM.title), evidence: [{ kind: "failingTest", testId: "t", command: "c" }] }, a1);
    }
    const longId = `L${"y".repeat(LIM.id - 1)}`;
    assert.throws(() => add({ kind: "proposal", id: `${longId}y`, title: "t", evidence: [{ kind: "failingTest", testId: "t", command: "c" }] }, a1), LedgerError);
    // Paths as long and lists as full as the ledger takes: about 0.8 MB per submission.
    const dirName = "d".repeat(LIM.path - 20);
    const files = (n: number) => Array.from({ length: LIM.changedFiles }, (_, i) => `src/${dirName}/f${n}-${i}.ts`);
    add({ kind: "submission", id: longId, taskId: null, baseCommit: "b", headCommit: "h", changedFiles: files(0), linesChanged: 1 }, a1);
    for (let n = 1; n <= 5; n++) {
      add({ kind: "submission", id: `big${n}`, taskId: null, baseCommit: "b", headCommit: "h", changedFiles: files(n), linesChanged: 1 }, a1);
    }
    add({ kind: "gateResult", submissionId: longId, gate: "tsc", pass: false, details: TEXT }, coord);
    add(
      {
        kind: "finding",
        id: "F1",
        target: { submissionId: longId },
        severity: "low",
        testPath: `t/${"z".repeat(LIM.path - 2)}`,
        testCommand: "c".repeat(LIM.command),
        stake: 5,
      },
      b1,
    );
    add({ kind: "settlement", owner: "alice", delta: 1, reason: "mergeVest", ref: "r".repeat(LIM.ref) }, coord);

    const l = Ledger.open(file);
    const s: Site = { state: l.state(), entries: l.entries(), nowIso: NOW, derive: fakeDerive, log: quiet };
    const at = (url: string) => route(() => s, "GET", url, quiet);
    const sub = s.state.submissions.get(longId);
    assert.ok(sub);
    const prUrl = `/submissions/${longId}`;
    for (const url of ["/", prUrl, "/owners/alice", `/agents/${keyIdOf(a1.publicKey)}`, "/api/state", "/api/metrics"]) {
      const r = at(url);
      assert.equal(r.status, 200, url);
      assert.ok(r.body.length < 200_000, `${url} is ${r.body.length} bytes`);
      assert.ok(!r.body.includes("x".repeat(CLIP.text + 1)), `${url} renders a huge string in full`);
    }
    const overview = at("/").body;
    assert.ok(overview.includes(`href="${prUrl}"`), "the longest id the ledger takes is linked by path");
    assert.equal(at(`/submissions?seq=${sub.submittedSeq}`).status, 200);
    assert.match(at(prUrl).body, new RegExp(`and ${LIM.changedFiles - 200} more not shown`));
    assert.equal(clip("abcdef", 3), "abc… [3 more characters]");

    // Pages of raw entries stop at the byte cap and still reach every entry.
    const seen: LedgerEntry[] = [];
    let since: number | null = 0;
    let pages = 0;
    while (since !== null) {
      const r = at(`/api/entries?since=${since}`);
      assert.ok(Buffer.byteLength(r.body) <= MAX_ENTRIES_BYTES + 2048, `page ${pages} is ${r.body.length} bytes`);
      const p = JSON.parse(r.body) as { entries: LedgerEntry[]; next: number | null };
      seen.push(...p.entries);
      since = p.next;
      pages++;
    }
    assert.ok(pages > 1, "a big ledger takes more than one page");
    assert.deepEqual(seen, l.entries());
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// The real server, over the real metrics, promotion and review modules
// ---------------------------------------------------------------------------

test("startPlayground serves the ledger over HTTP, follows appends and survives torn writes", async (t) => {
  const server: http.Server = startPlayground({ ledgerPath: fx.file, port: 0, host: "127.0.0.1", nowIso: NOW });
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

  const stateNow = async () => {
    const res = await fetch(base + "/api/state");
    assert.equal(res.status, 200);
    return JSON.parse(await res.text());
  };
  // An append by another writer shows up on the next request.
  const before = (await stateNow()).length;
  const writer = Ledger.open(fx.file);
  writer.append({ kind: "settlement", owner: "bob", delta: 2, reason: "cleanReview", ref: "s1" }, fx.coord, tick());
  const after = await stateNow();
  assert.equal(after.length, before + 1);
  assert.equal(after.counts.settlements, 4);

  // A half-written line is not an error: the last complete state is served.
  const size = fs.statSync(fx.file).size;
  fs.appendFileSync(fx.file, `{"seq":${before + 1},"half":`);
  assert.equal((await stateNow()).length, before + 1);
  // The file shrinking (here: back to the last complete line) is a full re-read.
  fs.truncateSync(fx.file, size);
  assert.equal((await stateNow()).length, before + 1);
  // Garbage appended: logged, and the last good state is still served.
  const errors = t.mock.method(console, "error", () => {});
  fs.appendFileSync(fx.file, "not json\n");
  assert.equal((await stateNow()).length, before + 1);
  assert.ok(errors.mock.callCount() >= 1);
  fs.truncateSync(fx.file, size);
});

test.after(() => fs.rmSync(fx.dir, { recursive: true, force: true }));
