import { test } from "node:test";
import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as http from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AddressInfo } from "node:net";
import { canonical, generateKeyPair, keyIdOf, sha256hex, sign } from "../src/crypto";
import { Ledger, signEntry, type Signer } from "../src/ledger";
import { defaultRules } from "../src/rules";
import { treeFromParents } from "../src/tree";
import {
  createCoordinatorServer,
  summarisePatch,
  uploadMessage,
  type CoordinatorServer,
  type CoordinatorServerOptions,
  type Head,
  type ServerLimits,
  type SubmitPolicy,
  type UploadRoute,
} from "../src/server";
import type { EntryBody, LedgerEntry } from "../src/types";

// ---------------------------------------------------------------------------
// Fixture: a real ledger file with owners alice (reputation 100) and bob (10),
// agents a1 (alice) and b1 (bob), a server on port 0, a settable clock and a
// fake policy.
// ---------------------------------------------------------------------------

const T0 = Date.UTC(2026, 0, 1);
const tree = treeFromParents({ alice: null, bob: "alice" }, { alice: 100, bob: 10 });

type Fixture = {
  server: CoordinatorServer;
  url: string;
  dir: string;
  patchesDir: string;
  ledgerPath: string;
  key: (name: string) => Signer;
  id: (name: string) => string;
  admin: Signer;
  coord: Signer;
  setSeconds: (s: number) => void;
  now: () => string;
  credits: Map<string, number>;
  close: () => Promise<void>;
};

async function fixture(
  limits: Partial<ServerLimits> = {},
  extra: Partial<CoordinatorServerOptions> = {},
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
  let second = 0;
  const at = () => new Date(T0 + ++second * 1000).toISOString();
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
    prSlots: (reputation) => (reputation >= 100 ? 7 : 1),
    // Above the ledger's own floor (15 for 100 lines, ring 1), so a test can
    // tell this policy's refusal from the ledger's.
    claimStake: () => 40,
  };
  const server = createCoordinatorServer({
    ledgerPath,
    coordinatorKey: coord,
    tree,
    clock: () => new Date(nowMs).toISOString(),
    patchesDir,
    policy,
    limits,
    ...extra,
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
    admin,
    coord,
    setSeconds: (s) => {
      nowMs = T0 + s * 1000;
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

async function signed(f: Fixture, body: EntryBody, signer: string | Signer, h?: Head, at?: string): Promise<LedgerEntry> {
  const hd = h ?? (await head(f));
  // What a client does: sign for the head, never earlier than the head's time.
  const now = at ?? new Date(Math.max(Date.parse(hd.at), Date.parse(f.now()))).toISOString();
  return signEntry({ seq: hd.nextSeq, prev: hd.hash }, body, typeof signer === "string" ? f.key(signer) : signer, now);
}

async function post(f: Fixture, entry: unknown): Promise<{ status: number; body: Record<string, unknown> }> {
  const r = await fetch(`${f.url}/api/entries`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: typeof entry === "string" ? entry : JSON.stringify(entry),
  });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

const proposal = (id: string, title = "fix it"): EntryBody => ({
  kind: "proposal",
  id,
  title,
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

const finding = (id: string, sid: string, stake = 5): EntryBody => ({
  kind: "finding",
  id,
  target: { submissionId: sid },
  severity: "high",
  testPath: `test/${id.replaceAll("/", "-")}.test.ts`,
  testCommand: "node --test",
  stake,
});

// ---------------------------------------------------------------------------
// Entries
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

test("coordinator kinds are refused; admin kinds only from an admin key, which onboards owners", async () => {
  const f = await fixture();
  try {
    const coordinatorOnly: EntryBody[] = [
      { kind: "settlement", owner: "alice", delta: 1000, reason: "bounty", ref: "x" },
      { kind: "gateResult", submissionId: "s1", gate: "size", pass: true, details: "" },
      { kind: "merge", submissionId: "s1", commit: "c" },
      { kind: "task", id: "t", proposalId: "p", ring: 1, acceptanceTestPaths: ["t"], sizeEstimate: 1, specAuthor: "bob" },
    ];
    for (const body of coordinatorOnly) {
      for (const signer of ["a1", f.admin] as const) {
        const r = await post(f, await signed(f, body, signer));
        assert.equal(r.status, 403, body.kind);
        assert.equal(r.body.error, "forbidden-kind");
      }
    }
    const mallory = generateKeyPair();
    const onboard: EntryBody = { kind: "ownerKey", owner: "mallory", publicKey: mallory.publicKey, inviter: "alice" };
    const byAgent = await post(f, await signed(f, onboard, "a1"));
    assert.equal(byAgent.status, 403);
    assert.equal(byAgent.body.error, "forbidden-kind");
    assert.equal((await post(f, await signed(f, { kind: "plantCommit", commitment: "a".repeat(64) }, "alice"))).status, 403);

    const h = await head(f);
    const byCoord = signEntry({ seq: h.nextSeq, prev: h.hash }, { kind: "agentRevoked", agent: f.id("a1"), reason: "x" }, f.coord, f.now());
    const r = await post(f, byCoord);
    assert.equal(r.status, 403);
    assert.equal(r.body.error, "forbidden-signer");
    assert.equal((await head(f)).hash, h.hash, "nothing was written");

    // The admin ingress: while the server holds the file, this is how owners join.
    const ok = await post(f, await signed(f, onboard, f.admin));
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    assert.equal(f.server.store.state().ownerByKey.get(keyIdOf(mallory.publicKey)), "mallory");
    const plant = await post(f, await signed(f, { kind: "plantCommit", commitment: "a".repeat(64) }, f.admin));
    assert.equal(plant.status, 201);
  } finally {
    await f.close();
  }
});

test("malformed, oversized, over-cap and badly signed entries are refused", async () => {
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

    // Field caps keep free text off the permanent ledger.
    const long = await post(f, await signed(f, proposal("p1", "t".repeat(201)), "a1"));
    assert.equal(long.status, 400);
    assert.equal(long.body.error, "too-long");

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
    assert.equal((await head(f)).nextSeq > 0, true, "the server still answers");
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

// ---------------------------------------------------------------------------
// Rate limits: only entries that could be appended are charged
// ---------------------------------------------------------------------------

test("per-owner rate limit; forged entries do not drain it", async () => {
  const f = await fixture({ ratePerMinute: 3 });
  try {
    f.setSeconds(600);
    for (let i = 0; i < 3; i++) assert.equal((await post(f, await signed(f, proposal(`p${i}`), "a1"))).status, 201);
    const r = await post(f, await signed(f, proposal("p3"), "a1"));
    assert.equal(r.status, 429);
    // Another owner has its own bucket; the same owner's key does not.
    assert.equal((await post(f, await signed(f, proposal("q0"), "b1"))).status, 201);
    assert.equal((await post(f, await signed(f, proposal("p3"), "alice"))).status, 429);
    // Exactly one token refills in 20 s. Forged entries under alice's id must not spend it.
    f.setSeconds(620);
    for (let i = 0; i < 5; i++) {
      const h = await head(f);
      const forged = { ...signEntry({ seq: h.nextSeq, prev: h.hash }, proposal("p3"), generateKeyPair(), f.now()), signer: f.id("a1") };
      assert.equal((await post(f, forged)).body.error, "signature");
    }
    assert.equal((await post(f, await signed(f, proposal("p3"), "a1"))).status, 201, "the refilled token was still there");
    assert.equal((await post(f, await signed(f, proposal("p4"), "a1"))).status, 429, "and it was the only one");
  } finally {
    await f.close();
  }
});

test("replaying an owner's already-appended entries costs the owner nothing", async () => {
  const f = await fixture({ ratePerMinute: 3 });
  try {
    const mine = await signed(f, proposal("p0"), "a1");
    assert.equal((await post(f, mine)).status, 201);
    // Anyone can replay a public entry; it is stale, so it is a free 409.
    for (let i = 0; i < 10; i++) assert.equal((await post(f, mine)).status, 409);
    assert.equal((await post(f, await signed(f, proposal("p1"), "a1"))).status, 201);
    assert.equal((await post(f, await signed(f, proposal("p2"), "a1"))).status, 201);
    assert.equal((await post(f, await signed(f, proposal("p3"), "a1"))).status, 429);
  } finally {
    await f.close();
  }
});

test("a revoked key's fresh entries are refused without spending its owner's bucket", async () => {
  const f = await fixture({ ratePerMinute: 3 });
  try {
    const reg: EntryBody = { kind: "agentRegistered", owner: "alice", publicKey: f.key("a2").publicKey, modelFamily: "claude", harness: "h" };
    assert.equal((await post(f, await signed(f, reg, "alice"))).status, 201);
    assert.equal((await post(f, await signed(f, { kind: "agentRevoked", agent: f.id("a2"), reason: "stolen" }, "alice"))).status, 201);
    for (let i = 0; i < 5; i++) {
      const r = await post(f, await signed(f, proposal(`x${i}`), "a2"));
      assert.equal(r.status, 403);
      assert.equal(r.body.error, "signer-revoked");
    }
    assert.equal((await post(f, await signed(f, proposal("p1"), "a1"))).status, 201, "alice's third token is untouched");
  } finally {
    await f.close();
  }
});

test("per-IP limit, concurrency cap, lock queue cap and daily byte quota", async () => {
  const ip = await fixture({ ipRatePerMinute: 3 });
  try {
    for (let i = 0; i < 3; i++) assert.equal((await fetch(`${ip.url}/api/head`)).status, 200);
    const r = await fetch(`${ip.url}/api/head`);
    assert.equal(r.status, 429);
    assert.equal(((await r.json()) as { error: string }).error, "ip-rate-limited");
  } finally {
    await ip.close();
  }
  const busy = await fixture({ maxConcurrent: 0 });
  try {
    assert.equal((await fetch(`${busy.url}/api/head`)).status, 503);
  } finally {
    await busy.close();
  }
  const queued = await fixture({ maxLockQueue: 1 });
  try {
    const entry = await signed(queued, proposal("p1"), "a1");
    let release!: () => void;
    const held = queued.server.store.lock(() => new Promise<void>((r) => (release = r)));
    const r = await post(queued, entry);
    assert.equal(r.status, 503);
    assert.equal(r.body.error, "busy");
    release();
    await held;
    assert.equal((await post(queued, entry)).status, 201);
  } finally {
    await queued.close();
  }
  const bytes = await fixture({ dailyBytesPerOwner: 800 });
  try {
    assert.equal((await post(bytes, await signed(bytes, proposal("p1"), "a1"))).status, 201);
    const r = await post(bytes, await signed(bytes, proposal("p2"), "a1"));
    assert.equal(r.status, 429);
    assert.equal(r.body.error, "byte-quota");
  } finally {
    await bytes.close();
  }
});

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

test("submissions need a submit credit and a free PR slot", async () => {
  const f = await fixture();
  try {
    f.credits.set("bob", 0);
    const noCredit = await post(f, await signed(f, submission("s0"), "b1"));
    assert.equal(noCredit.status, 403);
    assert.equal(noCredit.body.error, "no-submit-credit");

    // bob (reputation 10) has one slot.
    f.credits.set("bob", 5);
    assert.equal((await post(f, await signed(f, submission("s1"), "b1"))).status, 201);
    const second = await post(f, await signed(f, submission("s2"), "b1"));
    assert.equal(second.status, 403);
    assert.equal(second.body.error, "no-pr-slot");
    // A failed gate frees the slot.
    await f.server.store.appendAsCoordinator({ kind: "gateResult", submissionId: "s1", gate: "size", pass: false, details: "too big" });
    assert.equal((await post(f, await signed(f, submission("s2"), "b1"))).status, 201);
  } finally {
    await f.close();
  }
});

test("claims need the policy stake, which is stricter than the ledger's floor", async () => {
  const f = await fixture();
  try {
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
    // 20 clears the ledger's floor (15) but not the policy's (40).
    const wrong = await post(f, await signed(f, { kind: "claim", taskId: "t1", until, stake: 20 }, "a1"));
    assert.equal(wrong.status, 400);
    assert.equal(wrong.body.error, "stake");
    assert.match(String(wrong.body.message), /at least 40/);
    const good = await post(f, await signed(f, { kind: "claim", taskId: "t1", until, stake: 40 }, "a1"));
    assert.equal(good.status, 201, JSON.stringify(good.body));
    // Extending one's own claim re-uses its stake: 100 - 40 locked + 40 back.
    const until2 = new Date(T0 + 700 * 60_000).toISOString();
    assert.equal((await post(f, await signed(f, { kind: "claim", taskId: "t1", until: until2, stake: 90 }, "a1"))).status, 201);
  } finally {
    await f.close();
  }
});

test("stakes must be covered by available reputation, and upload ids must be file-safe", async () => {
  const f = await fixture();
  try {
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    // bob has reputation 10.
    const tooMuch = await post(f, await signed(f, finding("f0", "s1", 11), "b1"));
    assert.equal(tooMuch.status, 403);
    assert.equal(tooMuch.body.error, "insufficient-reputation");
    assert.equal((await post(f, await signed(f, finding("f1", "s1", 6), "b1"))).status, 201);
    // 6 is now locked: 4 left, below the 5 a finding needs.
    assert.equal((await post(f, await signed(f, finding("f2", "s1", 5), "b1"))).body.error, "insufficient-reputation");

    const badSub = await post(f, await signed(f, submission("a/b"), "a1"));
    assert.equal(badSub.status, 400);
    assert.equal(badSub.body.error, "bad-id");
    const badFinding = await post(f, await signed(f, finding("../x", "s1"), "b1"));
    assert.equal(badFinding.body.error, "bad-id");
    const longCommand = { ...finding("f3", "s1"), testCommand: "x".repeat(1025) } as EntryBody;
    assert.equal((await post(f, await signed(f, longCommand, "b1"))).body.error, "too-long");
  } finally {
    await f.close();
  }
});

// ---------------------------------------------------------------------------
// Uploads
// ---------------------------------------------------------------------------

async function upload(
  f: Fixture,
  route: UploadRoute,
  id: string,
  content: string,
  signer?: string,
  sigFor?: { route?: UploadRoute; id?: string; content?: string; legacy?: boolean },
) {
  const headers: Record<string, string> = { "Content-Type": "text/plain" };
  if (signer) {
    const digest = sha256hex(sigFor?.content ?? content);
    const message = sigFor?.legacy ? digest : uploadMessage(sigFor?.route ?? route, sigFor?.id ?? id, digest);
    headers["x-commons-key"] = f.key(signer).publicKey;
    headers["x-commons-sig"] = sign(f.key(signer).privateKey, message);
  }
  const p = route === "patch" ? `/api/patches/${encodeURIComponent(id)}` : `/api/findings/${encodeURIComponent(id)}/test`;
  const r = await fetch(`${f.url}${p}`, { method: "POST", headers, body: content });
  return { status: r.status, body: (await r.json()) as Record<string, unknown> };
}

test("patch upload: only the author, signed for this route and id, matching the declared change, stored once", async () => {
  const patched: string[] = [];
  const g = await fixture({}, { onPatch: (sid) => void patched.push(sid) });
  try {
    assert.equal((await post(g, await signed(g, submission("s1"), "a1"))).status, 201);
    assert.equal((await post(g, await signed(g, submission("s2"), "a1"))).status, 201);
    assert.equal((await upload(g, "patch", "s1", PATCH)).status, 401, "no auth headers");
    assert.equal((await upload(g, "patch", "s1", PATCH, "b1")).status, 403, "not the author");
    assert.equal((await upload(g, "patch", "s1", PATCH, "alice")).status, 403, "the author's owner is not the author");
    assert.equal((await upload(g, "patch", "s1", PATCH, "a1", { content: "other" })).status, 401, "signature over other bytes");
    assert.equal((await upload(g, "patch", "s1", PATCH, "a1", { id: "s2" })).status, 401, "signed for another submission");
    assert.equal((await upload(g, "patch", "s1", PATCH, "a1", { route: "findingTest" })).status, 401, "signed for another route");
    assert.equal((await upload(g, "patch", "s1", PATCH, "a1", { legacy: true })).status, 401, "bare digest signatures are off");
    assert.equal((await upload(g, "patch", "nope", PATCH, "a1")).status, 404);
    assert.equal((await upload(g, "patch", "../escape", PATCH, "a1")).status, 400);

    const wf = await upload(g, "patch", "s1", PATCH.replaceAll("src/x.ts", "src/y.ts"), "a1");
    assert.equal(wf.status, 422);
    assert.equal(wf.body.error, "files-mismatch");
    const extraLine = PATCH.replace("@@ -1,2 +1,2 @@", "@@ -1,2 +1,3 @@").replace(" export { a };", "+// x\n export { a };");
    assert.equal((await upload(g, "patch", "s1", extraLine, "a1")).body.error, "lines-mismatch");
    assert.equal((await upload(g, "patch", "s1", "not a diff", "a1")).body.error, "bad-patch");

    const ok = await upload(g, "patch", "s1", PATCH, "a1");
    assert.equal(ok.status, 201, JSON.stringify(ok.body));
    assert.equal(ok.body.created, true);
    assert.equal(fs.readFileSync(path.join(g.patchesDir, "s1.diff"), "utf8"), PATCH);
    assert.equal((await upload(g, "patch", "s1", PATCH, "a1")).body.created, false, "identical retry is fine");
    const changed = PATCH.replace("const a = 2;", "const a = 3;");
    assert.equal((await upload(g, "patch", "s1", changed, "a1")).status, 409, "a stored patch never changes");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(patched, ["s1"]);

    const got = await fetch(`${g.url}/api/patches/s1`);
    assert.equal(got.status, 200);
    assert.equal(got.headers.get("x-commons-untrusted"), "author-supplied");
    assert.equal(await got.text(), PATCH);
  } finally {
    await g.close();
  }
  const legacy = await fixture({}, { acceptLegacyUploadSignatures: true });
  try {
    assert.equal((await post(legacy, await signed(legacy, submission("s1"), "a1"))).status, 201);
    assert.equal((await upload(legacy, "patch", "s1", PATCH, "a1", { legacy: true })).status, 201, "transition option");
  } finally {
    await legacy.close();
  }
});

test("uploads by a stranger are refused before the body is read", async () => {
  const f = await fixture({ patchBytes: 1024 });
  try {
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    const r = await upload(f, "patch", "s1", "x".repeat(4096), "b1");
    assert.equal(r.status, 403, "the key check comes before the size check");
    assert.equal((await upload(f, "patch", "s1", "x".repeat(4096), "a1")).status, 413);
  } finally {
    await f.close();
  }
});

test("finding tests are uploaded by the finder", async () => {
  const f = await fixture();
  try {
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    assert.equal((await post(f, await signed(f, finding("f1", "s1"), "b1"))).status, 201);
    const content = "throw new Error('bug');\n";
    assert.equal((await upload(f, "findingTest", "f1", content, "a1")).status, 403);
    assert.equal((await upload(f, "findingTest", "f1", content, "b1", { route: "patch" })).status, 401);
    const ok = await upload(f, "findingTest", "f1", content, "b1");
    assert.equal(ok.status, 201);
    assert.equal(fs.readFileSync(path.join(f.patchesDir, "findings", "f1.test"), "utf8"), content);
  } finally {
    await f.close();
  }
});

// ---------------------------------------------------------------------------
// Assignments and routing
// ---------------------------------------------------------------------------

test("assignments list open review seats, with author fields marked untrusted", async () => {
  const f = await fixture();
  try {
    const reg: EntryBody = { kind: "agentRegistered", owner: "bob", publicKey: f.key("b2").publicKey, modelFamily: "qwen", harness: "h" };
    assert.equal((await post(f, await signed(f, reg, "bob"))).status, 201);
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    await f.server.store.appendAsCoordinator({ kind: "reviewAssignment", submissionId: "s1", beacon: "x", reviewers: [f.id("b1")] });
    type A = { submissionId: string; reviewStake: number; untrusted: { changedFiles: string[] } };
    const list = async (agent: string) =>
      ((await (await fetch(`${f.url}/api/assignments?agent=${agent}`)).json()) as { assignments: A[] }).assignments;
    const mine = await list(f.id("b1"));
    assert.deepEqual(mine.map((a) => a.submissionId), ["s1"]);
    assert.deepEqual(mine[0]?.untrusted.changedFiles, ["src/x.ts"]);
    assert.equal((mine[0] as unknown as Record<string, unknown>).changedFiles, undefined, "author fields only inside untrusted");
    assert.deepEqual(await list(f.id("a1")), []);
    const commitment = sha256hex("anything");
    assert.equal((await post(f, await signed(f, { kind: "reviewCommit", submissionId: "s1", commitment, stake: 5 }, "b1"))).status, 201);
    assert.deepEqual(await list(f.id("b1")), []);
    assert.equal((await fetch(`${f.url}/api/assignments`)).status, 400);

    assert.equal((await post(f, await signed(f, submission("s2", { changedFiles: ["src/z.ts"] }), "a1"))).status, 201);
    await f.server.store.appendAsCoordinator({ kind: "reviewAssignment", submissionId: "s2", beacon: "x", reviewers: [f.id("b2")] });
    assert.deepEqual((await list(f.id("b2"))).map((a) => a.submissionId), ["s2"]);
    // Revoked agents see nothing.
    assert.equal((await post(f, await signed(f, { kind: "agentRevoked", agent: f.id("b2"), reason: "x" }, "bob"))).status, 201);
    assert.deepEqual(await list(f.id("b2")), []);
  } finally {
    await f.close();
  }
});

test("a reveal closes the other seats in the listing", async () => {
  const f = await fixture();
  try {
    const reg: EntryBody = { kind: "ownerKey", owner: "carol", publicKey: f.key("carol").publicKey, inviter: "alice" };
    assert.equal((await post(f, await signed(f, reg, f.admin))).status, 201);
    const c1: EntryBody = { kind: "agentRegistered", owner: "carol", publicKey: f.key("c1").publicKey, modelFamily: "kimi", harness: "h" };
    assert.equal((await post(f, await signed(f, c1, "carol"))).status, 201);
    assert.equal((await post(f, await signed(f, submission("s1"), "a1"))).status, 201);
    await f.server.store.appendAsCoordinator({ kind: "reviewAssignment", submissionId: "s1", beacon: "x", reviewers: [f.id("b1"), f.id("c1")] });
    const verdict = { defectProbability: 0.1, summary: "ok", findingIds: [] };
    const commitment = sha256hex(canonical(verdict) + "salt");
    assert.equal((await post(f, await signed(f, { kind: "reviewCommit", submissionId: "s1", commitment, stake: 5 }, "b1"))).status, 201);
    const list = async (agent: string) =>
      ((await (await fetch(`${f.url}/api/assignments?agent=${agent}`)).json()) as { assignments: unknown[] }).assignments;
    assert.equal((await list(f.id("c1"))).length, 1);
    assert.equal((await post(f, await signed(f, { kind: "reviewReveal", submissionId: "s1", verdict, salt: "salt" }, "b1"))).status, 201);
    assert.deepEqual(await list(f.id("c1")), [], "the ledger would refuse c1's commit now");
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
  const g = await fixture({}, { fallback: (_req, res) => res.writeHead(200, { "Content-Type": "text/plain" }).end("playground") });
  try {
    const r = await fetch(`${g.url}/streams`);
    assert.equal(r.status, 200);
    assert.equal(await r.text(), "playground");
    assert.equal((await fetch(`${g.url}/api/head`)).status, 200, "API routes still win");
  } finally {
    await g.close();
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
