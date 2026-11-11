// Hashing, signing and canonical serialisation for the ledger.
//
// Keys travel as base64url strings: public keys are SPKI DER, private keys
// PKCS8 DER, both ed25519. A KeyId is the first 32 hex chars of sha256 over the
// public key's DER bytes, so it is stable however the key is later re-encoded.

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as nodeSign,
  verify as nodeVerify,
} from "node:crypto";
import type { KeyId } from "./types";

// Deterministic JSON. Two values that mean the same thing produce the same
// string, so hashes and signatures over it are reproducible on any machine:
// object keys sorted by UTF-16 code unit, no whitespace, undefined object fields
// dropped, arrays in order. Anything JSON cannot round-trip exactly (bigint,
// NaN, Infinity, functions, symbols, undefined array slots, class instances such
// as Date or Map, cycles) throws rather than being silently coerced.
export function canonical(value: unknown): string {
  return encode(value, new Set());
}

function encode(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";
    case "string":
      return JSON.stringify(value);
    case "number":
      if (!Number.isFinite(value)) throw new TypeError(`canonical: non-finite number ${value}`);
      return JSON.stringify(value);
    case "object":
      break;
    default:
      throw new TypeError(`canonical: cannot encode ${typeof value}`);
  }
  const obj = value as object;
  if (seen.has(obj)) throw new TypeError("canonical: cyclic value");
  seen.add(obj);
  let out: string;
  if (Array.isArray(obj)) {
    const parts: string[] = [];
    for (let i = 0; i < obj.length; i++) {
      const item: unknown = obj[i];
      if (item === undefined) throw new TypeError(`canonical: undefined array element at ${i}`);
      parts.push(encode(item, seen));
    }
    out = `[${parts.join(",")}]`;
  } else {
    const proto: unknown = Object.getPrototypeOf(obj);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError("canonical: only plain objects and arrays can be encoded");
    }
    const record = obj as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(record).sort()) {
      const field = record[key];
      if (field === undefined) continue;
      parts.push(`${JSON.stringify(key)}:${encode(field, seen)}`);
    }
    out = `{${parts.join(",")}}`;
  }
  seen.delete(obj);
  return out;
}

export function sha256hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  return { publicKey: publicKey.toString("base64url"), privateKey: privateKey.toString("base64url") };
}

export function keyIdOf(publicKey: string): KeyId {
  return sha256hex(Buffer.from(publicKey, "base64url")).slice(0, 32);
}

// True only for an ed25519 SPKI DER key in its one canonical base64url spelling.
// Node's base64url decoder tolerates padding and stray characters; accepting
// those would let one key appear under several strings in the ledger.
export function isValidPublicKey(publicKey: unknown): publicKey is string {
  if (typeof publicKey !== "string" || publicKey === "") return false;
  try {
    const der = Buffer.from(publicKey, "base64url");
    if (der.toString("base64url") !== publicKey) return false;
    const key = createPublicKey({ key: der, format: "der", type: "spki" });
    if (key.asymmetricKeyType !== "ed25519") return false;
    return key.export({ type: "spki", format: "der" }).toString("base64url") === publicKey;
  } catch {
    return false;
  }
}

export function sign(privateKey: string, message: string): string {
  const key = createPrivateKey({ key: Buffer.from(privateKey, "base64url"), format: "der", type: "pkcs8" });
  if (key.asymmetricKeyType !== "ed25519") throw new TypeError("sign: not an ed25519 private key");
  return nodeSign(null, Buffer.from(message, "utf8"), key).toString("base64url");
}

// Never throws: a malformed key or signature is simply not a valid signature.
// The signature must be in canonical base64url form so a signed entry has
// exactly one valid spelling.
export function verify(publicKey: string, message: string, sig: string): boolean {
  if (!isValidPublicKey(publicKey) || typeof message !== "string" || typeof sig !== "string") return false;
  try {
    const raw = Buffer.from(sig, "base64url");
    if (raw.length !== 64 || raw.toString("base64url") !== sig) return false;
    const key = createPublicKey({ key: Buffer.from(publicKey, "base64url"), format: "der", type: "spki" });
    return nodeVerify(null, Buffer.from(message, "utf8"), key, raw);
  } catch {
    return false;
  }
}

// The one impure helper: callers draw a salt here and pass it into pure code.
export function randomSalt(): string {
  return randomBytes(32).toString("hex");
}
