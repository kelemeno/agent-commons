import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import {
  canonical,
  generateKeyPair,
  isValidPublicKey,
  keyIdOf,
  randomSalt,
  sha256hex,
  sign,
  verify,
} from "../src/crypto";

test("canonical sorts keys at every depth and keeps array order", () => {
  assert.equal(canonical({ b: 1, a: { d: [3, 1, 2], c: null } }), '{"a":{"c":null,"d":[3,1,2]},"b":1}');
  assert.equal(canonical({ a: 1, b: 2 }), canonical({ b: 2, a: 1 }));
});

test("canonical sorts by UTF-16 code unit, not locale", () => {
  assert.equal(canonical({ a: 1, B: 2, é: 3, "\u{1F600}": 4, "￿": 5 }), '{"B":2,"a":1,"é":3,"😀":4,"￿":5}');
});

test("canonical drops undefined object fields but not null", () => {
  assert.equal(canonical({ a: undefined, b: null }), '{"b":null}');
  assert.equal(canonical({ x: { y: undefined } }), '{"x":{}}');
});

test("canonical encodes primitives like JSON", () => {
  assert.equal(canonical("a\"b\n"), JSON.stringify("a\"b\n"));
  assert.equal(canonical(true), "true");
  assert.equal(canonical(-0), "0");
  assert.equal(canonical(1e21), "1e+21");
  assert.equal(canonical([]), "[]");
  assert.equal(canonical({}), "{}");
});

test("canonical round-trips through JSON.parse", () => {
  const v = { z: [1, "two", { three: 3.5 }], a: " \ud800", n: null };
  assert.equal(canonical(JSON.parse(canonical(v))), canonical(v));
});

test("canonical rejects values JSON cannot represent exactly", () => {
  for (const bad of [
    10n,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    () => 1,
    Symbol("s"),
    undefined,
    { a: 1n },
    { a: Number.NaN },
    [1, undefined],
    { f: () => 1 },
    new Date(0),
    new Map([["a", 1]]),
  ]) {
    assert.throws(() => canonical(bad), TypeError, String(bad));
  }
});

test("canonical rejects cycles but allows shared references", () => {
  const shared = { x: 1 };
  assert.equal(canonical({ a: shared, b: shared }), '{"a":{"x":1},"b":{"x":1}}');
  const cyclic: Record<string, unknown> = {};
  cyclic.self = cyclic;
  assert.throws(() => canonical(cyclic), /cyclic/);
  const arr: unknown[] = [];
  arr.push(arr);
  assert.throws(() => canonical(arr), /cyclic/);
});

test("canonical accepts null-prototype objects", () => {
  const o = Object.create(null) as Record<string, number>;
  o.b = 2;
  o.a = 1;
  assert.equal(canonical(o), '{"a":1,"b":2}');
});

test("sha256hex matches the standard test vector", () => {
  assert.equal(sha256hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.equal(sha256hex(Buffer.from("abc")), sha256hex("abc"));
});

test("generateKeyPair yields distinct, valid ed25519 keys with 32-hex key ids", () => {
  const a = generateKeyPair();
  const b = generateKeyPair();
  assert.notEqual(a.publicKey, b.publicKey);
  assert.ok(isValidPublicKey(a.publicKey));
  assert.match(a.publicKey, /^[A-Za-z0-9_-]+$/);
  assert.match(keyIdOf(a.publicKey), /^[0-9a-f]{32}$/);
  assert.notEqual(keyIdOf(a.publicKey), keyIdOf(b.publicKey));
  assert.equal(keyIdOf(a.publicKey), sha256hex(Buffer.from(a.publicKey, "base64url")).slice(0, 32));
});

test("sign and verify round-trip", () => {
  const k = generateKeyPair();
  const sig = sign(k.privateKey, "hello");
  assert.ok(verify(k.publicKey, "hello", sig));
  assert.equal(sign(k.privateKey, "hello"), sig, "ed25519 signatures are deterministic");
});

test("verify rejects wrong message, wrong key and tampered signatures", () => {
  const k = generateKeyPair();
  const other = generateKeyPair();
  const sig = sign(k.privateKey, "hello");
  assert.equal(verify(k.publicKey, "hellO", sig), false);
  assert.equal(verify(other.publicKey, "hello", sig), false);
  const raw = Buffer.from(sig, "base64url");
  raw[0] = (raw[0] ?? 0) ^ 1;
  assert.equal(verify(k.publicKey, "hello", raw.toString("base64url")), false);
});

test("verify never throws on garbage and rejects non-canonical spellings", () => {
  const k = generateKeyPair();
  const sig = sign(k.privateKey, "m");
  assert.equal(verify(k.publicKey, "m", ""), false);
  assert.equal(verify(k.publicKey, "m", "!!!"), false);
  assert.equal(verify(k.publicKey, "m", sig.slice(0, -2)), false);
  assert.equal(verify(k.publicKey, "m", `${sig}==`), false, "padded spelling of a valid signature");
  assert.equal(verify("not-a-key", "m", sig), false);
  assert.equal(verify(`${k.publicKey}=`, "m", sig), false);
  assert.equal(verify(k.publicKey, "m", Buffer.alloc(64).toString("base64url")), false);
});

test("isValidPublicKey accepts only canonical ed25519 SPKI keys", () => {
  const k = generateKeyPair();
  assert.ok(isValidPublicKey(k.publicKey));
  assert.equal(isValidPublicKey(`${k.publicKey}=`), false);
  assert.equal(isValidPublicKey(""), false);
  assert.equal(isValidPublicKey(42), false);
  assert.equal(isValidPublicKey(k.privateKey), false);
  const x = generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "der" }).toString("base64url");
  assert.equal(isValidPublicKey(x), false, "x25519 is not a signing key");
});

test("sign refuses a non-ed25519 or malformed private key", () => {
  assert.throws(() => sign("garbage", "m"));
  const x = generateKeyPairSync("x25519").privateKey.export({ type: "pkcs8", format: "der" }).toString("base64url");
  assert.throws(() => sign(x, "m"));
});

test("randomSalt is 32 random bytes in hex", () => {
  const a = randomSalt();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, randomSalt());
});
