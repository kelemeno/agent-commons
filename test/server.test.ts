import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";
import { generateKeyPair, keyIdOf, sha256hex, sign } from "../src/crypto";
import { Ledger, signEntry, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import { createCoordinatorServer, summarisePatch, type CoordinatorServer, type Head, type SubmitPolicy } from "../src/server";
import type { EntryBody, LedgerEntry } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: a real ledger file with owners alice and bob, agents a1 (alice) and
// b1 (bob), a server on port 0, a settable clock and a fake policy (the real
// incentives.ts is written in parallel).
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const tree = treeFromParents({ alice: null, bob: "alice" }, { alice: 100, bob: 0 });

type Fixture = {
  server: CoordinatorServer;
  url: string;
  dir: string;
  patchesDir: string;
  ledgerPath: string;
  key: (name: string) => Signer;
  id: (name: string) => string;
  coord: Signer;
  setMinutes: (m: number) => void;
  now: () => string;
  credits: Map<string, number>;
  close: () => Promise<void>;
};

async function fixture(
  limits: { ratePerMinute?: number; entryBytes?: number } = {},
  onPatch?: (submissionId: string) => void,
): Promise<Fixture> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "commons-server-"));
  const ledgerPath = path.join(dir, "ledger.jsonl");
  const patchesDir = path.join(dir, "patches");
  const admin = generateKeyPair();
  const coord = generateKeyPair();
  const keys = new Map<string, Signer>();
  const key = (name: string) => {
    let k = keys.get(name);
    if (!k) keys.set(name, (k = generateKeyPair()));
    return k;
  };
  const id = (name: string) => keyIdOf(key(name).publicKey);
  let minute = 0;
  const at = () => new Date(T0 + ++minute * 1000).toISOString();
  const rules = { ...defaultRules(), kernelSigners: ["alice", "bob"] };
  const ledger = Ledger.create(
    ledgerPath,
    { kind: "genesis", project: "anthill", admins: [admin.publicKey], coordinator: coord.publicKey, rules },
    at(),
  );
  ledger.append({ kind: "ownerKey", owner: "alice", publicKey: key("alice").publicKey, inviter: null }, admin, at());
  ledger.append({ kind: "ownerKey", owner: "bob", publicKey: key("bob").publicKey, inviter: "alice" }, admin, at());
  ledger.append({ kind: "agentRegistered", owner: "alice", publicKey: key("a1").publicKey, modelFamily: "claude", harness: "cli" }, key("alice"), at());
  ledger.append({ kind: "agentRegistered", owner: "bob", publicKey: key("b1").publicKey, modelFamily: "gpt", harness: "cli" }, key("bob"), at());

  let nowMs = T0 + 10 * 60_000;
  const credits = new Map<string, number>([["alice", 5]]);
  const policy: SubmitPolicy = {
    submitCredits: (_state, owner) => credits.get(owner) ?? 0,
    prSlots: (reputation) => 1 + Math.floor(Math.log2(1 + reputation)),
    claimStake: () => 15,
  };
  const server = createCoordinatorServer({
    ledgerPath,
    coordinatorKey: coord,
    tree,
    clock: () => new Date(nowMs).toISOString(),
    patchesDir,
    policy,
    limits,
    onPatch,
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return {
    server,
    url,
    dir,
    patchesDir,
    ledgerPath,
    key,
    id,
    coord,
    setMinutes: (m) => {
      nowMs = T0 + m * 60_000;
    },
    now: () => new Date(nowMs).toISOString(),
    credits,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

async function head(f: Fixture): Promise<Head> {
  const r = await fetch(`${f.url}/api/head`);
  assert.equal(r.status, 200);
  return (await r.json()) as Head;
}

async function signed(f: Fixture, body: EntryBody, signer: string, h?: Head, at?: string): Promise<LedgerEntry> {
  const hd = h ?? (await head(f));
  // What a client does: sign for the head, never earlier than the head's time.
  const now = at ?? new Date(Math.max(Date.parse(hd.at), Date.parse(f.now()))).toISOString();
  return signEntry({ seq: hd.nextSeq, prev: hd.hash }, body, f.key(signer), now);
}

async function post(f: Fixture, entry: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await fetch(`${f.url}/api/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof entry === "string" ? entry : JSON.stringify(entry),
  });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

const proposal = (id: string): EntryBody => ({
  kind: "proposal",
  id,
  title: "fix it",
  evidence: [{ kind: "location", file: "src/x.ts", line: 1, note: "bug" }],
});

const PATCH = [
  "diff --git a/src/x.ts b/src/x.ts",
  "index 1111111..2222222 100644",
  "--- a/src/x.ts",
  "+++ b/src/x.ts",
  "@@ -1,2 +1,2 @@",
  "-const a = 1;",
  "+const a = 2;",
  " export { a };",
  "",
].join("\n");

const submission = (id: string, extra: Partial<Extract<EntryBody, { kind: "submission" }>> = {}): EntryBody => ({
  kind: "submission",
  id,
  taskId: null,
  baseCommit: "b".repeat(40),
  headCommit: "c".repeat(40),
  changedFiles: ["src/x.ts"],
  linesChanged: 2,
  ...extra,
});

// ---------------------------------------------------------------------------

test("head and entries round trip with a real signed entry", async () => {
  const f = await fixture();
  try {
    const h0 = await head(f);
    assert.equal(h0.nextSeq, h0.seq + 1);
    const entry = await signed(f, proposal("p1"), "a1", h0);
    const r = await post(f, entry);
    assert.equal(r.status, 201, JSON.stringify(r.body));
    assert.equal(r.body.seq, h0.nextSeq);
    const h1 = await head(f);
    assert.equal(h1.hash, entry.hash);
    assert.equal(h1.seq, h0.nextSeq);
    // The file holds it: a fresh replay sees the proposal.
    assert.ok(Ledger.open(f.ledgerPath).state().proposals.has("p1"));
    // Owners may post too (proposal is agentOrOwner).
    assert.equal((await post(f, await signed(f, proposal("p2"), "bob"))).status, 201);
  } finally {
    await f.close();
  }
});

test("409 on a stale head, then success after re-signing", async () => {
  const f = await fixture();
  try {
    const h0 = await head(f);
    const first = await signed(f, proposal("p1"), "a1", h0);
    const stale = await signed(f, proposal("p2"), "b1", h0);
    assert.equal((await post(f, first)).status, 201);
    const r = await post(f, stale);
    assert.equal(r.status, 409);
    assert.equal(r.body.error, "head");
    assert.equal((r.body.head as Head).hash, first.hash);
    assert.equal((await post(f, await signed(f, proposal("p2"), "b1"))).status, 201);
  } finally {
    await f.close();
  }
});

test("coordinator and admin kinds are refused, and the coordinator key never posts", async () => {
  const f = await fixture();
  try {
    const forbidden: EntryBody[] = [
      { kind: "settlement", owner: "alice", delta: 1000, reason: "bounty", ref: "x" },
      { kind: "gateResult", submissionId: "s1", gate: "size", pass: true, details: "" },
      { kind: "merge", submissionId: "s1", commit: "c" },
      { kind: "ownerKey", owner: "mallory", publicKey: generateKeyPair().publicKey, inviter: null },
      { kind: "plantCommit", commitment: "a".repeat(64) },
    ];
    for (const body of forbidden) {
      const r = await post(f, await signed(f, body, "a1"));
      assert.equal(r.status, 403, body.kind);
      assert.equal(r.body.error, "forbidden-kind");
    }
    const h = await head(f);
    const byCoord = signEntry({ seq: h.nextSeq, prev: h.hash }, { kind: "agentRevoked", agent: f.id("a1"), reason: "x" }, f.coord, f.now());
    const r = await post(f, byCoord);
    assert.equal(r.status, 403);
    assert.equal(r.body.error, "forbidden-signer");
    assert.equal((await head(f)).hash, h.hash, "nothing was written");
  } finally {
    await f.close();
  }
});

test("malformed, oversized and badly signed entries are refused", async () => {
  const f = await fixture({ entryBytes: 4096 });
  try {
    assert.equal((await post(f, "not json")).status, 400);
    const one = await signed(f, proposal("p1"), "a1");
    const arr = await post(f, [one]);
    assert.equal(arr.status, 400);
    assert.equal(arr.body.error, "malformed");
    assert.equal((await post(f, { ...one, extra: 1 })).status, 400);

    const big = await post(f, { ...one, body: { ...proposal("p1"), title: "x".repeat(5000) } });
    assert.equal(big.status, 413);

    const tampered = { ...one, body: { ...proposal("p1"), title: "changed" } };
    const bad = await post(f, tampered);
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error, "signature");

    const unknown = signEntry({ seq: one.seq, prev: one.prev }, proposal("p1"), generateKeyPair(), one.at);
    assert.equal((await post(f, unknown)).body.error, "signer-unknown");

    // Ledger validation codes pass through.
    assert.equal((await post(f, one)).status, 201);
    const dup = await post(f, await signed(f, proposal("p1"), "a1"));
    assert.equal(dup.status, 400);
    assert.equal(dup.body.error, "duplicate-id");
  } finally {
    await f.close();
  }
});

test("a body over the limit is refused without being read whole", async () => {
  const f = await fixture();
  try {
    const status = await new Promise<number>((resolve, reject) => {
      const req = http.request(`${f.url}/api/entries`, { method: "POST", headers: { "Content-Type": "application/json" } });
      req.on("response", (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on("error", reject);
      // No Content-Length (chunked): the limit is enforced while streaming.
      req.write("x".repeat(200 * 1024));
      req.write("x".repeat(200 * 1024));
      req.end();
    });
    assert.equal(status, 413);
  } finally {
    await f.close();
  }
});

test("entries more than five minutes from the server clock are refused", async () => {
  const f = await fixture();
  try {
    const h = await head(f);
    const future = signEntry({ seq: h.nextSeq, prev: h.hash }, proposal("p1"), f.key("a1"), new Date(T0 + 16 * 60_000).toISOString());
    const r = await post(f, future);
    assert.equal(r.status, 400);
    assert.equal(r.body.error, "clock-skew");
    // Within the window but before the head entry: 409, re-sign with max(now, head.at).
    const okFuture = signEntry({ seq: h.nextSeq, prev: h.hash }, proposal("p1"), f.key("a1"), new Date(T0 + 14 * 60_000).toISOString());
    assert.equal((await post(f, okFuture)).status, 201);
    const h2 = await head(f);
    const behind = signEntry({ seq: h2.nextSeq, prev: h2.hash }, proposal("p2"), f.key("b1"), new Date(T0 + 10 * 60_000).toISOString());
    const r2 = await post(f, behind);
    assert.equal(r2.status, 409);
    assert.equal(r2.body.error, "time");
  } finally {
    await f.close();
  }
});

test("per-owner rate limit", async () => {
  const f = await fixture({ ratePerMinute: 3 });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await post(f, await signed(f, proposal(`p${i}`), "a1"))).status, 201);
    const r = await post(f, await signed(f, proposal("p3"), "a1"));
    assert.equal(r.status, 429);
    // Another owner has its own bucket; the same owner's key does not.
    assert.equal((await post(f, await signed(f, proposal("q0"), "b1"))).status, 201);
    assert.equal((await post(f, await signed(f, proposal("p3"), "alice"))).status, 429);
    // A forged entry under alice's agent id does not drain her bucket further.
    f.setMinutes(11);
    const h = await head(f);
    const forged = { ...signEntry({ seq: h.nextSeq, prev: h.hash }, proposal("p3"), generateKeyPair(), h.at), signer: f.id("a1") };
    assert.equal((await post(f, forged)).body.error, "signature");
    assert.equal((await post(f, await signed(f, proposal("p3"), "a1", undefined, new Date(T0 + 11 * 60_000).toISOString()))).status, 201);
  } finally {
    await f.close();
  }
});

test("submissions need a submit credit and a free PR slot; claims need the policy stake", async () => {
  const f = await fixture();
  try {
    f.credits.set("bob", 0);
    const noCredit = await post(f, await signed(f, submission("s0"), "b1"));
    assert.equal(noCredit.status, 403);
    assert.equal(noCredit.body.error, "no-submit-credit");

    // alice: reputation 100 -> 1 + floor(log2(101)) = 7 slots; bob (0) -> 1 slot.
    f.credits.set("bob", 5);
    assert.equal((await post(f, await signed(f, submission("s1"), "b1"))).status, 201);
    const second = await post(f, await signed(f, submission("s2"), "b1"));
    assert.equal(second.status, 403);
    assert.equal(second.body.error, "no-pr-slot");
    // A failed gate frees the slot.
    await f.server.store.appendAsCoordinator({ kind: "gateResult", submissionId: "s1", gate: "size", pass: false, details: "too big" });
    assert.equal((await post(f, await signed(f, submission("s2"), "b1"))).status, 201);

    // Claim stake must be at least policy.claimStake.
    assert.equal((await post(f, await signed(f, proposal("p1"), "a1"))).status, 201);
    await f.server.store.appendAsCoordinator({
      kind: "task",
      id: "t1",
      proposalId: "p1",
      ring: 1,
      acceptanceTestPaths: ["test/t1.test.ts"],
      sizeEstimate: 100,
      specAuthor: "bob",
    });
    const until = new Date(T0 + 600 * 60_000).toISOString();
    const wrong = await post(f, await signed(f, { kind: "claim", taskId: "t1", until, stake: 1 }, "a1"));
    assert.equal(wrong.status, 400);
    assert.equal(wrong.body.error, "stake");
    const good = await post(f, await signed(f, { kind: "claim", taskId: "t1", until, stake: 15 }, "a1"));
    assert.equal(good.status, 201, JSON.stringify(good.body));
  } finally {
    await f.close();
  }
});

async function upload(f: Fixture, route: string, content: string, signer?: string, sigOver?: string) {
  const headers: Record<string, string> = { "Content-Type": "text/x-diff" };
  if (signer) {
    headers["x-commons-key"] = f.key(signer).publicKey;
    headers["x-commons-sig"] = sign(f.key(signer).privateKey, sha256hex(sigOver ?? content));
  }
  const r = await fetch(`${f.url}${route}`, { method: "POST", headers, body: content });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

test("patch upload: only the author, signed, matching the declared files and lines, stored once", async () => {
  const patched: string[] = [];
  const g = await fixture({}, (sid) => patched.push(sid));
  try {
    assert.equal((await post(g, await signed(g, submission("s1"), "a1"))).status, 201);
    const route = "/api/patches/s1";
    assert.equal((await upload(g, route, PATCH)).status, 401, "no auth headers");
    assert.equal((await upload(g, route, PATCH, "b1")).status, 403, "not the author");
    assert.equal((await upload(g, route, PATCH, "alice")).status, 403, "the author's owner is not the author");
    assert.equal((await upload(g, route, PATCH, "a1", "other content")).status, 401, "signature over other bytes");
    assert.equal((await upload(g, "/api/patches/nope", PATCH, "a1")).status, 404);
    assert.equal((await upload(g, "/api/patches/..%2Fescape", PATCH, "a1")).status, 400);

    const wrongFiles = PATCH.replaceAll("src/x.ts", "src/y.ts");
    const wf = await upload(g, route, wrongFiles, "a1");
    assert.equal(wf.status, 422);
    assert.equal(wf.body.error, "files-mismatch");
    const extraLine = PATCH.replace("@@ -1,2 +1,2 @@", "@@ -1,2 +1,3 @@").replace(" export { a };", "+// x\n export { a };");
    assert.equal((await upload(g, route, extraLine, "a1")).body.error, "lines-mismatch");
    assert.equal((await upload(g, route, "not a diff", "a1")).body.error, "bad-patch");

    const ok = await upload(g, route, PATCH, "a1");
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    assert.equal(ok.body.created, true);
    assert.equal(fs.readFileSync(path.join(g.patchesDir, "s1.diff"), "utf8"), PATCH);
    assert.equal((await upload(g, route, PATCH, "a1")).body.created, false, "identical retry is fine");
    const changed = PATCH.replace("const a = 2;", "const a = 3;");
    assert.equal((await upload(g, route, changed, "a1")).status, 409, "a stored patch never changes");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(patched, ["s1"]);

    const got = await fetch(`${g.url}${route}`);
    assert.equal(got.status, 200);
    assert.equal(await got.text(), PATCH);
  } finally {
    await g.close();
  }
});

test("finding tests are uploaded by the finder", async () => {
  const f = await fixture();
  try {
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    const finding: EntryBody = {
      kind: "finding",
      id: "f1",
      target: { submissionId: "s1" },
      severity: "high",
      testPath: "test/f1.test.ts",
      testCommand: "node --test test/f1.test.ts",
      stake: 5,
    };
    assert.equal((await post(f, await signed(f, finding, "b1"))).status, 201);
    const content = "throw new Error('bug');\n";
    assert.equal((await upload(f, "/api/findings/f1/test", content, "a1")).status, 403);
    const ok = await upload(f, "/api/findings/f1/test", content, "b1");
    assert.equal(ok.status, 201);
    assert.equal(fs.readFileSync(path.join(f.patchesDir, "findings", "f1.test"), "utf8"), content);
  } finally {
    await f.close();
  }
});

test("assignments list reviews assigned to an agent and not yet committed", async () => {
  const f = await fixture();
  try {
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    await f.server.store.appendAsCoordinator({ kind: "reviewAssignment", submissionId: "s1", beacon: "x", reviewers: [f.id("b1")] });
    const list = async (agent: string) =>
      ((await (await fetch(`${f.url}/api/assignments?agent=${agent}`)).json()) as { assignments: { submissionId: string }[] }).assignments;
    assert.deepEqual((await list(f.id("b1"))).map((a) => a.submissionId), ["s1"]);
    assert.deepEqual(await list(f.id("a1")), []);
    const commitment = sha256hex("anything");
    assert.equal((await post(f, await signed(f, { kind: "reviewCommit", submissionId: "s1", commitment, stake: 5 }, "b1"))).status, 201);
    assert.deepEqual(await list(f.id("b1")), []);
    assert.equal((await fetch(`${f.url}/api/assignments`)).status, 400);
  } finally {
    await f.close();
  }
});

test("unknown routes fall through to the fallback handler, else 404", async () => {
  const f = await fixture();
  try {
    assert.equal((await fetch(`${f.url}/nope`)).status, 404);
  } finally {
    await f.close();
  }
});

test("summarisePatch counts both sides of a rename and only hunk lines", () => {
  const rename = [
    "diff --git a/src/old.ts b/src/new.ts",
    "similarity index 90%",
    "rename from src/old.ts",
    "rename to src/new.ts",
    "index 1111111..2222222 100644",
    "--- a/src/old.ts",
    "+++ b/src/new.ts",
    "@@ -1,2 +1,2 @@",
    "--- a removed line that looks like a header",
    "+++ an added line that looks like a header",
    " x",
    "",
  ].join("\n");
  assert.deepEqual(summarisePatch(rename), { files: ["src/new.ts", "src/old.ts"], linesChanged: 2 });
  assert.deepEqual(summarisePatch(PATCH), { files: ["src/x.ts"], linesChanged: 2 });
  assert.throws(() => summarisePatch("diff --git a/x b/x\nBinary files a/x and b/x differ\n"));
});
