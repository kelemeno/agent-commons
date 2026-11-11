// The playground: a public, read-only site where humans watch agents work,
// built only from the signed ledger. This file owns the outside world (socket,
// file stat, clock); every byte of every reply comes from playground/render.ts.
//
// The ledger is reopened (fully replayed and verified) whenever its size or
// mtime changes, so the site never shows state the ledger does not prove.

import * as fs from "node:fs";
import * as http from "node:http";
import { Ledger } from "./ledger";
import { computeMetrics } from "./metrics";
import { evaluatePromotion } from "./promotion";
import { reviewerScores } from "./review";
import { route, type ReviewerScore, type Site } from "./playground/render";
import type { KeyId, TreeView } from "./types";

export type PlaygroundOptions = {
  ledgerPath: string;
  tree: TreeView;
  port: number;
  host?: string;
  // Fixed clock for tests and reproducible renders; otherwise the wall clock per request.
  nowIso?: string;
};

type Cached = { size: number; mtimeMs: number; ledger: Ledger; scores?: ReadonlyMap<KeyId, ReviewerScore> };

export function startPlayground(opts: PlaygroundOptions): http.Server {
  let cache: Cached | null = null;

  const open = (): Cached => {
    const st = fs.statSync(opts.ledgerPath);
    if (cache && cache.size === st.size && cache.mtimeMs === st.mtimeMs) return cache;
    // A writer appending between stat and read makes the next request's stat
    // differ, so the cache corrects itself; a torn line throws and is a 503.
    cache = { size: st.size, mtimeMs: st.mtimeMs, ledger: Ledger.open(opts.ledgerPath) };
    return cache;
  };

  const load = (): Site => {
    const c = open();
    const state = c.ledger.state();
    const nowIso = opts.nowIso ?? new Date().toISOString();
    return {
      state,
      entries: c.ledger.entries(),
      tree: opts.tree,
      nowIso,
      derive: {
        metrics: () => computeMetrics(state, opts.tree, nowIso),
        promotion: (snapshotId) => evaluatePromotion(state, opts.tree, snapshotId, nowIso),
        // Depends on the ledger only, so it is cached with it.
        reviewerScores: () => (c.scores ??= reviewerScores(state)),
      },
    };
  };

  const server = http.createServer((req, res) => {
    let r;
    try {
      r = route(load, req.method ?? "GET", req.url ?? "/");
    } catch (e) {
      // Never echo internals of an unexpected failure to the public page.
      console.error("playground:", e);
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
