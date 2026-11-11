// The playground: a public, read-only site where humans watch agents work,
// built only from the signed ledger. This file owns the outside world (socket,
// file, clock) and the caches; every byte of every reply comes from
// playground/render.ts.
//
// Following the ledger. The file is append-only, so after the first full
// replay only the bytes past the last complete line read are parsed and
// applied (applyEntry verifies each signature and rule, as replay does). A
// line still being written is left for the next request instead of failing
// this one. If the file shrank or was replaced, it is replayed from scratch.
// If reading fails while a good state is cached, the cached state is served
// and the error logged: a reader racing a writer must not see a 503.
//
// Caching. Rendered bodies and derived statistics (metrics, promotion checks,
// reviewer scores) are cached per ledger version and per minute of the clock,
// so a page costs one render per minute per change, however many tabs reload
// it. The clock is floored to the minute for the same reason. There is no rate
// limit here: deploy behind a reverse proxy that limits requests per client.

import * as fs from "node:fs";
import * as http from "node:http";
import { applyEntry, parseLines, replay, type LedgerState } from "./ledger";
import { computeMetrics } from "./metrics";
import { evaluatePromotion } from "./promotion";
import { reviewerScores } from "./review";
import { route, type Site } from "./playground/render";
import type { LedgerEntry } from "./types";

export type PlaygroundOptions = {
  ledgerPath: string;
  port: number;
  host?: string;
  // Fixed clock for tests and reproducible renders; otherwise the wall clock,
  // floored to the minute.
  nowIso?: string;
};

// Upper bound on cached bodies per (version, minute); past it the cache is
// dropped and refilled. Keys are bounded by the objects in the ledger, but each
// body can be large, so the count is capped as well.
const MEMO_LIMIT = 256;

type Followed = {
  ino: number;
  bytes: number; // offset just past the last complete line applied
  stat: string; // size and mtime when last read, to skip unchanged files
  failedStat: string | null; // a stat whose read failed; not retried until the file changes
  state: LedgerState;
  entries: LedgerEntry[];
  version: number; // bumps whenever entries are added or the state is replaced
};

const log = (e: unknown) => console.error("playground:", e);

// Reads [offset, end of file) and returns the part up to the last newline.
function readCompleteLines(path: string, offset: number): { text: string; bytes: number; ino: number } {
  const fd = fs.openSync(path, "r");
  try {
    const st = fs.fstatSync(fd);
    const buf = Buffer.alloc(Math.max(0, st.size - offset));
    let n = 0;
    while (n < buf.length) {
      const r = fs.readSync(fd, buf, n, buf.length - n, offset + n);
      if (r === 0) break;
      n += r;
    }
    const end = buf.subarray(0, n).lastIndexOf(0x0a) + 1;
    return { text: buf.subarray(0, end).toString("utf8"), bytes: end, ino: st.ino };
  } finally {
    fs.closeSync(fd);
  }
}

function fullRead(path: string, stat: string, version: number): Followed {
  const { text, bytes, ino } = readCompleteLines(path, 0);
  const entries = parseLines(text);
  return { ino, bytes, stat, failedStat: null, state: replay(entries), entries, version };
}

// Applies complete lines appended since `f.bytes`, one entry at a time, so a
// bad entry keeps everything before it. Returns false if nothing was new.
function applyTail(path: string, f: Followed): boolean {
  const { text, bytes } = readCompleteLines(path, f.bytes);
  if (bytes === 0) return false;
  for (const line of text.slice(0, -1).split("\n")) {
    const [entry] = parseLines(`${line}\n`) as [LedgerEntry];
    applyEntry(f.state, entry);
    f.entries.push(entry);
    f.bytes += Buffer.byteLength(line) + 1;
  }
  return true;
}

export function startPlayground(opts: PlaygroundOptions): http.Server {
  let cur: Followed | null = null;
  let memoKey = "";
  let memo = new Map<string, unknown>();

  const follow = (): Followed => {
    const st = fs.statSync(opts.ledgerPath);
    const stat = `${st.ino}:${st.size}:${st.mtimeMs}`;
    if (cur === null) return (cur = fullRead(opts.ledgerPath, stat, 0));
    if (stat === cur.stat || stat === cur.failedStat) return cur;
    const f: Followed = cur;
    try {
      if (st.ino === f.ino && st.size >= f.bytes) {
        if (applyTail(opts.ledgerPath, f)) f.version++;
        f.stat = stat;
      } else {
        cur = fullRead(opts.ledgerPath, stat, f.version + 1);
      }
      return cur;
    } catch (e) {
      // An invalid tail, or a file rewritten in place: try a full replay once.
      log(e);
      f.version++; // applyTail may have applied some entries before failing
      try {
        return (cur = fullRead(opts.ledgerPath, stat, f.version + 1));
      } catch (e2) {
        log(e2);
        f.failedStat = stat;
        return f;
      }
    }
  };

  const load = (): Site => {
    const f = follow();
    const nowIso = opts.nowIso ?? new Date(Math.floor(Date.now() / 60_000) * 60_000).toISOString();
    const key = `${f.version}@${nowIso}`;
    if (key !== memoKey || memo.size >= MEMO_LIMIT) {
      memoKey = key;
      memo = new Map();
    }
    const cached = <T>(k: string, compute: () => T): T => {
      if (memo.has(k)) return memo.get(k) as T;
      const v = compute();
      memo.set(k, v);
      return v;
    };
    const { state } = f;
    return {
      state,
      entries: f.entries,
      nowIso,
      log,
      memo: cached,
      derive: {
        metrics: () => cached("derive:metrics", () => computeMetrics(state, nowIso)),
        promotion: (snapshotId) =>
          cached(`derive:promotion:${snapshotId}`, () => evaluatePromotion(state, snapshotId, nowIso)),
        reviewerScores: () => cached("derive:scores", () => reviewerScores(state, nowIso)),
      },
    };
  };

  const server = http.createServer((req, res) => {
    let r;
    try {
      r = route(load, req.method ?? "GET", req.url ?? "/", log);
    } catch (e) {
      // Never echo internals of an unexpected failure to the public page.
      log(e);
      res.writeHead(500, { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" });
      res.end("internal error\n");
      return;
    }
    res.writeHead(r.status, { ...r.headers, "Content-Length": String(Buffer.byteLength(r.body)) });
    res.end(req.method === "HEAD" ? undefined : r.body);
  });
  server.listen(opts.port, opts.host);
  return server;
}
