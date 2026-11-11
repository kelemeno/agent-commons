// The playground site as a pure function: (ledger snapshot, request) -> reply.
//
// playground.ts owns the socket, the ledger cache and the clock; this file owns
// every byte that goes back. Keeping it pure means every route, header and
// escaping rule is testable without a server or the derived-statistics modules.
//
// Security contract. This page is public and renders attacker-controlled strings
// (titles, summaries, test paths, harness names, ids). Every interpolated value
// goes through `h`, whose only way to emit unescaped text is another `Html`
// value built by `h` itself (or the fixed CSS/JS constants below). Links are
// only ever built from internal paths with encodeURIComponent, never from
// ledger text, so no attacker string can become a URL scheme. Nothing here ever
// renders a sealed (committed, unrevealed) verdict: the ledger state holds no
// verdict until a reveal matched the commitment, and the pages only say that a
// commitment exists. Plants are shown only once plantReveal set
// `submission.planted`; plant commitments are only counted.

import { keyIdOf } from "../crypto";
import type {
  CommonsState,
  EntryBody,
  Evidence,
  FindingState,
  KeyId,
  LedgerEntry,
  OwnerId,
  ReviewState,
  SnapshotState,
  SubmissionState,
  TreeView,
} from "../types";

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

// Local mirrors of the shapes documented in ARCHITECTURE.md for metrics.ts,
// promotion.ts and review.ts. Structural, so the real return types assign to them.
export type MetricRow = { group: string; metric: string; value: unknown; bad: boolean; note: string };
export type PromotionReport = { pass: boolean; checks: { name: string; pass: boolean; detail: string }[] };
export type ReviewerScore = {
  reviews: number;
  scored: number;
  meanBrier: number;
  plantsSeen: number;
  plantsCaught: number;
};

// Derived statistics, computed on demand. A throwing function renders as an
// "unavailable" panel rather than taking the page down.
export type Derive = {
  metrics(): MetricRow[];
  promotion(snapshotId: string): PromotionReport;
  reviewerScores(): ReadonlyMap<KeyId, ReviewerScore>;
};

export type Site = {
  state: CommonsState;
  entries: readonly LedgerEntry[];
  tree: TreeView;
  nowIso: string;
  derive: Derive;
};

export type Reply = { status: number; headers: Record<string, string>; body: string };

export const STREAM_LENGTH = 100;
export const MAX_ENTRIES_PAGE = 500;

// ---------------------------------------------------------------------------
// Escaping: the one helper
// ---------------------------------------------------------------------------

export class Html {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

type Part = Html | string | number | boolean | null | undefined | readonly Part[];

const ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

export function esc(value: unknown): string {
  return String(value).replace(/[&<>"'`]/g, (c) => ESCAPES[c] ?? c);
}

function piece(p: Part): string {
  if (p instanceof Html) return p.value;
  if (Array.isArray(p)) return p.map(piece).join("");
  if (p === null || p === undefined || p === false) return "";
  return esc(p);
}

// Tagged template: literal parts are trusted markup, every ${value} is escaped
// unless it is itself Html. Attribute values must always be quoted with ".
export function h(strings: TemplateStringsArray, ...parts: Part[]): Html {
  let out = strings[0] ?? "";
  for (let i = 0; i < parts.length; i++) out += piece(parts[i] as Part) + (strings[i + 1] ?? "");
  return new Html(out);
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

const path = (...segments: string[]) => `/${segments.map(encodeURIComponent).join("/")}`;
const submissionHref = (id: string) => path("submissions", id);
const snapshotHref = (id: string) => path("snapshots", id);
const ownerHref = (id: string) => path("owners", id);
const agentHref = (id: string) => path("agents", id);
const anchor = (prefix: string, id: string) => `${prefix}-${encodeURIComponent(id)}`;

function short(id: string, n = 8): string {
  return id.length > n + 2 ? `${id.slice(0, n)}…` : id;
}

function idLink(href: string, id: string): Html {
  return h`<a class="id" href="${href}" title="${id}">${short(id, 12)}</a>`;
}

function code(text: string, full?: string): Html {
  return h`<code class="id" title="${full ?? text}">${text}</code>`;
}

type Tone = "ok" | "bad" | "warn" | "mut";
function badge(tone: Tone, label: string): Html {
  return h`<span class="b ${tone}">${label}</span>`;
}

function num(v: number, digits = 3): string {
  if (!Number.isFinite(v)) return String(v);
  if (Number.isInteger(v)) return String(v);
  return v.toFixed(digits).replace(/0+$/, "").replace(/\.$/, "");
}

function signed(v: number): string {
  return v > 0 ? `+${num(v)}` : num(v);
}

function fmtValue(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "number") return num(v);
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

function fmtTime(at: string): Html {
  const ms = Date.parse(at);
  if (Number.isNaN(ms)) return h`<time>${at}</time>`;
  const text = new Date(ms).toISOString().replace("T", " ").slice(0, 16) + "Z";
  return h`<time datetime="${at}" title="${at}">${text}</time>`;
}

function ago(at: string, nowIso: string): string {
  const d = Date.parse(nowIso) - Date.parse(at);
  if (!Number.isFinite(d)) return "";
  if (d < 0) return "just now";
  const m = Math.floor(d / 60_000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const hrs = Math.floor(m / 60);
  if (hrs < 48) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

function attempt<T>(f: () => T): { ok: true; value: T } | { ok: false; error: string } {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

function unavailable(what: string, error: string): Html {
  return h`<p class="note">${badge("warn", "unavailable")} ${what} could not be computed: ${error}</p>`;
}

function treeDistance(tree: TreeView, a: OwnerId | undefined, b: OwnerId | undefined): number | null {
  if (a === undefined || b === undefined) return null;
  try {
    return tree.has(a) && tree.has(b) ? tree.distance(a, b) : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// People
// ---------------------------------------------------------------------------

function ownerLink(id: OwnerId): Html {
  return h`<a href="${ownerHref(id)}">${id}</a>`;
}

function agentLabel(state: CommonsState, keyId: KeyId): Html {
  const a = state.agents.get(keyId);
  if (!a) return h`key ${code(short(keyId), keyId)}`;
  const revoked = a.active ? "" : h` ${badge("bad", "revoked")}`;
  return h`agent ${idLink(agentHref(keyId), keyId)} (owner ${ownerLink(a.owner)}, ${a.modelFamily})${revoked}`;
}

// Who signed an entry, as a phrase.
function actor(state: CommonsState, keyId: KeyId | ""): Html {
  if (keyId === "") return h`genesis`;
  if (state.agents.has(keyId)) return agentLabel(state, keyId);
  const owner = state.ownerByKey.get(keyId);
  if (owner !== undefined) return h`owner ${ownerLink(owner)}`;
  if (keyId === state.coordinatorKey) return h`the coordinator`;
  if (state.adminKeys.includes(keyId)) return h`an admin`;
  return h`key ${code(short(keyId), keyId)}`;
}

const ownerOfAgent = (state: CommonsState, keyId: KeyId) => state.agents.get(keyId)?.owner;

// ---------------------------------------------------------------------------
// Derived per-object status
// ---------------------------------------------------------------------------

function findingStatus(f: FindingState): Html {
  if (!f.result) return badge("warn", "awaiting reproduction");
  return f.result.reproduced ? badge("bad", "reproduced") : badge("mut", "did not reproduce");
}

function reproductionText(r: { failsOnHead: boolean; passesOnParent: boolean }): string {
  return `${r.failsOnHead ? "fails" : "passes"} on head, ${r.passesOnParent ? "passes" : "fails"} on parent`;
}

function submissionStatus(state: CommonsState, s: SubmissionState): Html {
  const parts: Html[] = [];
  if (s.planted) parts.push(badge("warn", "planted bug (revealed)"));
  const reproduced = s.findingIds.some((id) => state.findings.get(id)?.result?.reproduced === true);
  if (s.merged) parts.push(badge("ok", "merged"));
  else if (reproduced) parts.push(badge("bad", "blocked: reproduced finding"));
  else if (s.gates.some((g) => !g.pass)) parts.push(badge("bad", "blocked: gate failed"));
  else if (s.assignment) parts.push(badge("mut", "in review"));
  else parts.push(badge("mut", "open"));
  return h`${parts.map((p) => h`${p} `)}`;
}

function snapshotStatus(s: SnapshotState): Html {
  return s.promoted ? badge("ok", "promoted to main") : badge("mut", "release candidate");
}

function reviewCell(r: ReviewState): Html {
  if (!r.verdict) return h`${badge("mut", "sealed")} commitment recorded at #${r.committedSeq}`;
  const p = r.verdict.defectProbability;
  const tone: Tone = p >= 0.5 ? "bad" : p >= 0.2 ? "warn" : "ok";
  return h`${badge(tone, `defect p=${p.toFixed(2)}`)} ${r.verdict.summary}`;
}

function evidenceKinds(ev: readonly Evidence[]): string {
  const names = { failingTest: "failing test", diagnostic: "diagnostic", location: "location" } as const;
  return ev.map((e) => names[e.kind] ?? "evidence").join(", ");
}

function targetLink(state: CommonsState, target: FindingState["target"]): Html {
  if ("submissionId" in target) return h`PR ${idLink(submissionHref(target.submissionId), target.submissionId)}`;
  return state.snapshots.has(target.snapshotId)
    ? h`snapshot ${idLink(snapshotHref(target.snapshotId), target.snapshotId)}`
    : h`snapshot ${target.snapshotId}`;
}

function findingLink(state: CommonsState, id: string): Html {
  const f = state.findings.get(id);
  if (!f) return h`finding ${id}`;
  const page = "submissionId" in f.target ? submissionHref(f.target.submissionId) : snapshotHref(f.target.snapshotId);
  return h`finding <a class="id" href="${page}#${anchor("f", id)}" title="${id}">${short(id, 12)}</a>`;
}

// A settlement ref is free text; link it when it names a known object exactly.
function refLink(state: CommonsState, ref: string): Html {
  if (state.submissions.has(ref)) return h`PR ${idLink(submissionHref(ref), ref)}`;
  if (state.findings.has(ref)) return findingLink(state, ref);
  if (state.snapshots.has(ref)) return h`snapshot ${idLink(snapshotHref(ref), ref)}`;
  return code(short(ref, 24), ref);
}

// ---------------------------------------------------------------------------
// The stream: each ledger entry as one human sentence
// ---------------------------------------------------------------------------

export function sentence(state: CommonsState, entry: LedgerEntry): Html {
  const b: EntryBody = entry.body;
  const who = actor(state, entry.signer);
  const pr = (id: string) => h`PR ${idLink(submissionHref(id), id)}`;
  const snap = (id: string) => h`snapshot ${idLink(snapshotHref(id), id)}`;
  switch (b.kind) {
    case "genesis":
      return h`ledger opened for project ${code(b.project)} with ${plural(b.admins.length, "admin")} (rules v${b.rules.version})`;
    case "ownerKey":
      return b.inviter === null
        ? h`owner ${ownerLink(b.owner)} joined`
        : h`owner ${ownerLink(b.owner)} joined, invited by ${ownerLink(b.inviter)}`;
    case "agentRegistered": {
      const keyId = keyIdOf(b.publicKey);
      return h`owner ${ownerLink(b.owner)} registered agent ${idLink(agentHref(keyId), keyId)} (${b.modelFamily}, harness ${b.harness})`;
    }
    case "agentRevoked":
      return h`${agentLabel(state, b.agent)} was ${entry.signer === state.coordinatorKey ? "suspended by the coordinator" : "revoked by its owner"}: ${b.reason}`;
    case "proposal":
      return h`${who} proposed ${code(b.id)}: “${b.title}” (evidence: ${evidenceKinds(b.evidence)})`;
    case "task":
      return h`task ${code(b.id)} opened from proposal ${code(b.proposalId)}: ring ${b.ring}, ~${b.sizeEstimate} lines, spec by ${ownerLink(b.specAuthor)}`;
    case "claim":
      return h`${who} claimed task ${code(b.taskId)} until ${fmtTime(b.until)} (stake ${b.stake})`;
    case "submission":
      return h`${who} submitted ${pr(b.id)}${b.taskId === null ? "" : h` for task ${code(b.taskId)}`}: ${plural(b.changedFiles.length, "file")}, ${plural(b.linesChanged, "line")}`;
    case "gateResult":
      return b.pass
        ? h`gate ${code(b.gate)} ${badge("ok", "passed")} on ${pr(b.submissionId)}`
        : h`gate ${code(b.gate)} ${badge("bad", "failed")} on ${pr(b.submissionId)}: ${b.details}`;
    case "reviewAssignment":
      return h`reviewers drawn for ${pr(b.submissionId)}: ${b.reviewers.map((r, i) => h`${i > 0 ? ", " : ""}${agentLabel(state, r)}`)}`;
    case "reviewCommit":
      return h`${who} sealed a review of ${pr(b.submissionId)} (stake ${b.stake})`;
    case "reviewReveal":
      return h`${who} reviewed ${pr(b.submissionId)}: defect p=${b.verdict.defectProbability.toFixed(2)} — ${b.verdict.summary}`;
    case "finding":
      return h`${who} filed ${findingLink(state, b.id)} (${b.severity}) on ${targetLink(state, b.target)}: ${code(b.testPath)}`;
    case "findingResult": {
      const r = reproductionText(b);
      return b.reproduced
        ? h`${findingLink(state, b.findingId)} ${badge("bad", "reproduced")}: ${r}`
        : h`${findingLink(state, b.findingId)} ${badge("mut", "did not reproduce")}: ${r}`;
    }
    case "merge":
      return h`${pr(b.submissionId)} ${badge("ok", "merged")} into dev at ${code(short(b.commit, 10), b.commit)}`;
    case "snapshot":
      return h`${snap(b.id)} cut at ${code(short(b.commit, 10), b.commit)} with ${plural(b.submissionIds.length, "PR")}`;
    case "attestCommit":
      return h`${who} sealed an attestation of ${snap(b.snapshotId)} (stake ${b.stake})`;
    case "attestReveal":
      return h`${who} attested ${snap(b.snapshotId)}: defect p=${b.verdict.defectProbability.toFixed(2)} — ${b.verdict.summary}`;
    case "signoff": {
      const owner = state.ownerByKey.get(entry.signer);
      return h`kernel signer ${owner === undefined ? who : ownerLink(owner)} signed off ${snap(b.snapshotId)}`;
    }
    case "promotion":
      return h`${snap(b.snapshotId)} ${badge("ok", "promoted")} to main`;
    case "plantCommit":
      // Only the fact of a commitment: what it commits to is secret until the reveal.
      return h`the seeding custodian committed to a planted bug (sealed)`;
    case "plantReveal":
      return h`${pr(b.submissionId)} revealed as a ${badge("warn", "planted bug")} (${b.severity}): ${b.description}`;
    case "honeytokenTriggered":
      return h`${agentLabel(state, b.agent)} ${badge("bad", "triggered a honeytoken")} ${code(b.tokenId)}`;
    case "escape":
      return h`${badge("bad", "escape")}: ${findingLink(state, b.findingId)} reached main in ${snap(b.snapshotId)}`;
    case "settlement":
      return h`owner ${ownerLink(b.owner)} ${badge(b.delta < 0 ? "bad" : "ok", signed(b.delta))} (${b.reason}, ${refLink(state, b.ref)})`;
    case "rulesChange":
      return h`rules changed to v${b.rules.version} (poll ${code(b.pollId)})`;
    default: {
      const unknown: { kind?: unknown } = b;
      return h`entry of kind ${String(unknown.kind)}`;
    }
  }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

export const CSS = `
:root{color-scheme:light dark;--bg:#fbfbf9;--fg:#1f1f1c;--mut:#6c6b66;--line:#e5e3dd;--card:#fff;
--ok:#1d6b39;--okbg:#e3f2e7;--bad:#a3261c;--badbg:#fae6e3;--warn:#7d5300;--warnbg:#fbf0d6;--link:#2952b8}
@media (prefers-color-scheme:dark){:root{--bg:#151514;--fg:#e7e5df;--mut:#9a988f;--line:#2d2c29;--card:#1d1d1b;
--ok:#86d6a0;--okbg:#16301e;--bad:#ff9f94;--badbg:#3a1a17;--warn:#efc56f;--warnbg:#382c11;--link:#93b2ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
main{max-width:46rem;margin:0 auto;padding:1.25rem 1rem 4rem}
header.top{display:flex;gap:1rem;align-items:baseline;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:.6rem;margin-bottom:1rem}
header.top a.home{font-weight:600;color:var(--fg);text-decoration:none}
header.top .meta{color:var(--mut);font-size:.85rem}
header.top button{margin-left:auto;font:inherit;font-size:.8rem;color:var(--mut);background:none;border:1px solid var(--line);border-radius:4px;padding:.1rem .5rem;cursor:pointer}
h1{font-size:1.35rem;margin:.4rem 0 .6rem;line-height:1.3;overflow-wrap:anywhere}
h2{font-size:1rem;margin:1.8rem 0 .5rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
a{color:var(--link)}
code,.id{font:.82em/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}
a.id{text-decoration:none}
a.id:hover{text-decoration:underline}
.b{display:inline-block;font-size:.75rem;line-height:1.4;padding:0 .4rem;border-radius:3px;font-weight:600;white-space:nowrap}
.b.ok{color:var(--ok);background:var(--okbg)}.b.bad{color:var(--bad);background:var(--badbg)}
.b.warn{color:var(--warn);background:var(--warnbg)}.b.mut{color:var(--mut);background:var(--line)}
table{border-collapse:collapse;width:100%;font-size:.9rem;margin:.3rem 0}
th,td{text-align:left;vertical-align:top;padding:.35rem .5rem .35rem 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
th{font-weight:600;color:var(--mut);font-size:.8rem}
tr.bad td{background:var(--badbg)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem;margin:.3rem 0;font-size:.92rem}
dt{color:var(--mut)}dd{margin:0;overflow-wrap:anywhere}
ol.stream{list-style:none;padding:0;margin:0}
ol.stream li{padding:.45rem 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
ol.stream .when{color:var(--mut);font-size:.78rem;margin-right:.4rem;white-space:nowrap}
ol.stream .seq{color:var(--mut);font:.75rem ui-monospace,Menlo,Consolas,monospace;margin-right:.4rem}
.counts{display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;font-size:.9rem;color:var(--mut)}
.counts b{color:var(--fg);font-weight:600}
.note{color:var(--mut);font-size:.88rem}
ul.plain{padding-left:1.1rem;margin:.3rem 0}
footer{margin-top:3rem;color:var(--mut);font-size:.8rem}
`;

// Served from /static/refresh.js (script-src 'self'). Reloads every 10s while
// the tab is visible and nothing is selected; the header button pauses it.
export const REFRESH_JS = `(function () {
  "use strict";
  var KEY = "playground.paused";
  var button = document.getElementById("refresh-toggle");
  function paused() { try { return sessionStorage.getItem(KEY) === "1"; } catch (e) { return false; } }
  function show() { if (button) button.textContent = paused() ? "auto-refresh: paused" : "auto-refresh: on"; }
  if (button) {
    button.addEventListener("click", function () {
      try { sessionStorage.setItem(KEY, paused() ? "0" : "1"); } catch (e) {}
      show();
    });
  }
  show();
  function tick() {
    var selecting = window.getSelection && String(window.getSelection()) !== "";
    if (!paused() && document.visibilityState === "visible" && !selecting) location.reload();
    else setTimeout(tick, 10000);
  }
  setTimeout(tick, 10000);
})();
`;

function page(site: { state: CommonsState; nowIso: string } | null, title: string, body: Html): string {
  const meta = site
    ? h`<span class="meta">project ${code(site.state.project)} · ${plural(site.state.length, "entry", "entries")} · head ${code(short(site.state.headHash, 10), site.state.headHash)}</span>`
    : "";
  return h`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${title} · agent commons</title><style>${new Html(CSS)}</style></head>
<body><main>
<header class="top"><a class="home" href="/">agent commons</a>${meta}<button id="refresh-toggle" type="button">auto-refresh: on</button></header>
${body}
<footer>Everything on this page is derived from the signed ledger. Replay it yourself: <a href="/api/entries?since=0">/api/entries</a> · <a href="/api/state">/api/state</a> · <a href="/api/metrics">/api/metrics</a>${site ? h` · as of ${fmtTime(site.nowIso)}` : ""}</footer>
</main><script src="/static/refresh.js"></script></body></html>
`.value;
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

function overview(site: Site): string {
  const { state, entries, nowIso } = site;
  const subs = [...state.submissions.values()];
  const findings = [...state.findings.values()];
  const snaps = [...state.snapshots.values()];
  const activeAgents = [...state.agents.values()].filter((a) => a.active).length;
  const c = (n: number, label: string) => h`<span><b>${n}</b> ${label}</span>`;
  const counts = h`<div class="counts">
${c(state.owners.size, "owners")}${c(activeAgents, "active agents")}${c(state.proposals.size, "proposals")}${c(state.tasks.size, "tasks")}
${c(subs.length, "PRs")}${c(subs.filter((s) => s.merged).length, "merged")}
${c(findings.length, "findings")}${c(findings.filter((f) => f.result?.reproduced === true).length, "reproduced")}${c(findings.filter((f) => f.result?.reproduced === false).length, "false")}
${c(snaps.length, "snapshots")}${c(snaps.filter((s) => s.promoted).length, "promoted")}
${c(state.escapes.length, "escapes")}${c(state.settlements.length, "settlements")}
</div>`;

  const m = attempt(() => site.derive.metrics());
  const metrics = !m.ok
    ? unavailable("Metrics", m.error)
    : m.value.length === 0
      ? h`<p class="note">No metrics yet.</p>`
      : h`<table><thead><tr><th>group</th><th>metric</th><th>value</th><th>status</th><th>note</th></tr></thead><tbody>
${m.value.map(
  (r) =>
    h`<tr class="${r.bad ? "bad" : ""}"><td>${r.group}</td><td>${r.metric}</td><td><code>${fmtValue(r.value)}</code></td><td>${r.bad ? badge("bad", "attention") : badge("ok", "ok")}</td><td>${r.note}</td></tr>\n`,
)}</tbody></table>`;

  const latest = entries.slice(-STREAM_LENGTH).reverse();
  const stream = h`<ol class="stream">${latest.map(
    (e) =>
      h`<li><span class="seq">#${e.seq}</span><span class="when" title="${e.at}">${ago(e.at, nowIso)}</span>${attemptHtml(() => sentence(state, e))}</li>\n`,
  )}</ol>`;

  const openSubs = subs.filter((s) => !s.merged).slice(-20).reverse();
  const recentSnaps = snaps.slice(-10).reverse();
  const owners = [...state.owners.values()].sort((a, b) => b.reputationDelta - a.reputationDelta || cmp(a.id, b.id));

  const body = h`<h1>Agents at work</h1>
<p class="note">A live view of the commons ledger: proposals, PRs, sealed reviews, reproduced findings, snapshots and settlements, each one a signed entry.</p>
${counts}
<h2>Health</h2>${metrics}
<h2>Latest ${Math.min(STREAM_LENGTH, entries.length)} entries</h2>${stream}
<h2>Open PRs</h2>${
    openSubs.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${openSubs.map((s) => h`<li>${idLink(submissionHref(s.id), s.id)} ${submissionStatus(state, s)} by ${agentLabel(state, s.author)}</li>`)}</ul>`
  }
<h2>Snapshots</h2>${
    recentSnaps.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${recentSnaps.map((s) => h`<li>${idLink(snapshotHref(s.id), s.id)} ${snapshotStatus(s)} ${plural(s.submissionIds.length, "PR")}</li>`)}</ul>`
  }
<h2>Owners</h2>${
    owners.length === 0
      ? h`<p class="note">None.</p>`
      : h`<table><thead><tr><th>owner</th><th>reputation delta</th><th>locked stake</th><th>agents</th></tr></thead><tbody>${owners.map(
          (o) =>
            h`<tr><td>${ownerLink(o.id)}</td><td>${signed(o.reputationDelta)}</td><td>${o.lockedStake}</td><td>${agentsOf(state, o.id).length}</td></tr>`,
        )}</tbody></table>`
  }`;
  return page(site, "overview", body);
}

function attemptHtml(f: () => Html): Html {
  const r = attempt(f);
  return r.ok ? r.value : h`${badge("warn", "unrenderable entry")} ${r.error}`;
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function agentsOf(state: CommonsState, owner: OwnerId) {
  return [...state.agents.values()].filter((a) => a.owner === owner);
}

function submissionPage(site: Site, s: SubmissionState): string {
  const { state, tree } = site;
  const authorOwner = ownerOfAgent(state, s.author);
  const authorFamily = state.agents.get(s.author)?.modelFamily;
  const task = s.taskId === null ? undefined : state.tasks.get(s.taskId);
  const proposal = task ? state.proposals.get(task.proposalId) : undefined;

  const gates =
    s.gates.length === 0
      ? h`<p class="note">No gate results recorded yet.</p>`
      : h`<table><thead><tr><th>gate</th><th>result</th><th>details</th></tr></thead><tbody>${s.gates.map(
          (g) =>
            h`<tr class="${g.pass ? "" : "bad"}"><td><code>${g.gate}</code></td><td>${g.pass ? badge("ok", "pass") : badge("bad", "fail")}</td><td>${g.details}</td></tr>`,
        )}</tbody></table>`;

  // Assigned seats first (even if not yet committed), then open reviewers.
  const assigned = s.assignment?.reviewers ?? [];
  const byReviewer = new Map(s.reviews.map((r) => [r.reviewer, r]));
  const rows = [
    ...assigned.map((k) => ({ keyId: k, seat: "assigned", review: byReviewer.get(k) })),
    ...s.reviews.filter((r) => !assigned.includes(r.reviewer)).map((r) => ({ keyId: r.reviewer, seat: "open", review: r })),
  ];
  const otherFamily = rows.some((r) => {
    const f = state.agents.get(r.keyId)?.modelFamily;
    return f !== undefined && f !== authorFamily;
  });
  const reviewers =
    rows.length === 0
      ? h`<p class="note">No reviewers drawn yet.</p>`
      : h`<table><thead><tr><th>reviewer</th><th>model</th><th>tree distance</th><th>seat</th><th>review</th></tr></thead><tbody>${rows.map(
          (r) => {
            const agent = state.agents.get(r.keyId);
            const d = treeDistance(tree, authorOwner, agent?.owner);
            const sameFamily = agent !== undefined && agent.modelFamily === authorFamily;
            return h`<tr><td>${agentLabel(state, r.keyId)}</td><td>${agent?.modelFamily ?? "?"}${sameFamily ? h` ${badge("warn", "same as author")}` : ""}</td><td>${d === null ? h`<span class="note">not in tree</span>` : d}</td><td>${r.seat}</td><td>${r.review ? reviewCell(r.review) : badge("mut", "not committed")}</td></tr>`;
          },
        )}</tbody></table>
<p class="note">${otherFamily ? badge("ok", "other model family present") : badge("warn", "no other model family")} Sealed reviews show only that a commitment exists; the verdict appears once it is revealed and matches.</p>`;

  const findingRows = s.findingIds.map((id) => state.findings.get(id)).filter((f): f is FindingState => f !== undefined);
  const body = h`<h1>PR ${code(s.id)} ${submissionStatus(state, s)}</h1>
${proposal ? h`<p>“${proposal.title}”</p>` : ""}
<dl>
<dt>author</dt><dd>${agentLabel(state, s.author)}</dd>
<dt>task</dt><dd>${task ? h`${code(task.id)} · ring ${task.ring} · spec by ${ownerLink(task.specAuthor)}` : "none (untasked)"}</dd>
<dt>base → head</dt><dd>${code(short(s.baseCommit, 12), s.baseCommit)} → ${code(short(s.headCommit, 12), s.headCommit)}</dd>
<dt>size</dt><dd>${plural(s.changedFiles.length, "file")}, ${plural(s.linesChanged, "line")}</dd>
<dt>submitted</dt><dd>${fmtTime(s.submittedAt)} (#${s.submittedSeq})</dd>
${s.merged ? h`<dt>merged</dt><dd>${fmtTime(s.merged.at)} at ${code(short(s.merged.commit, 12), s.merged.commit)}</dd>` : ""}
${s.assignment ? h`<dt>beacon</dt><dd>${code(short(s.assignment.beacon, 16), s.assignment.beacon)} (#${s.assignment.seq})</dd>` : ""}
</dl>
${s.planted ? h`<p>${badge("warn", "planted bug")} revealed after the review window: (${s.planted.severity}) ${s.planted.description}</p>` : ""}
<h2>Changed files</h2><ul class="plain">${s.changedFiles.map((f) => h`<li><code>${f}</code></li>`)}</ul>
<h2>Gates</h2>${gates}
<h2>Reviewers</h2>${reviewers}
<h2>Findings</h2>${findingsTable(site, findingRows)}`;
  return page(site, `PR ${s.id}`, body);
}

function findingsTable(site: Site, findings: FindingState[]): Html {
  const { state } = site;
  if (findings.length === 0) return h`<p class="note">No findings filed.</p>`;
  return h`<table><thead><tr><th>finding</th><th>by</th><th>severity</th><th>test</th><th>reproduction</th></tr></thead><tbody>${findings.map(
    (f) =>
      h`<tr id="${anchor("f", f.id)}"><td>${code(short(f.id, 12), f.id)}</td><td>${agentLabel(state, f.finder)}</td><td>${f.severity}</td><td><code>${f.testPath}</code><br><span class="note">$ </span><code>${f.testCommand}</code></td><td>${findingStatus(f)}${
        f.result
          ? h`<br><span class="note">${reproductionText(f.result)}; log ${code(short(f.result.logDigest, 12), f.result.logDigest)}</span>`
          : ""
      }</td></tr>`,
  )}</tbody></table>`;
}

function snapshotPage(site: Site, snap: SnapshotState): string {
  const { state } = site;
  const ancestry: SnapshotState[] = [];
  for (let s: SnapshotState | undefined = snap; s && ancestry.length < 1000; ) {
    ancestry.push(s);
    s = s.previousSnapshotId === null ? undefined : state.snapshots.get(s.previousSnapshotId);
  }

  const coverageRows = snap.submissionIds.map((sid) => {
    const s = state.submissions.get(sid);
    if (!s) return h`<tr><td>${sid}</td><td colspan="4">unknown</td></tr>`;
    const revealed = s.reviews.filter((r) => r.verdict);
    const families = new Set(revealed.map((r) => state.agents.get(r.reviewer)?.modelFamily ?? "?"));
    const reproduced = s.findingIds.filter((id) => state.findings.get(id)?.result?.reproduced === true).length;
    const reviewTone: Tone = revealed.length === 0 ? "bad" : "ok";
    return h`<tr><td>${idLink(submissionHref(sid), sid)}</td><td>${badge(reviewTone, `${revealed.length}/${s.reviews.length} revealed`)}</td><td>${[...families].sort().join(", ") || "—"}</td><td>${s.findingIds.length} (${reproduced} reproduced)</td><td>${s.planted ? badge("warn", "plant") : ""}</td></tr>`;
  });
  const reviewed = snap.submissionIds.filter((sid) => state.submissions.get(sid)?.reviews.some((r) => r.verdict)).length;

  const revealedAtt = snap.attestations.filter((a) => a.verdict);
  const attFamilies = new Set(revealedAtt.map((a) => state.agents.get(a.reviewer)?.modelFamily ?? "?"));
  const attOwners = new Set(revealedAtt.map((a) => ownerOfAgent(state, a.reviewer) ?? "?"));
  const attestations =
    snap.attestations.length === 0
      ? h`<p class="note">No attestations yet.</p>`
      : h`<table><thead><tr><th>attester</th><th>attestation</th></tr></thead><tbody>${snap.attestations.map(
          (a) => h`<tr><td>${agentLabel(state, a.reviewer)}</td><td>${reviewCell(a)}</td></tr>`,
        )}</tbody></table>
<p class="note">Revealed attestations span ${plural(attFamilies.size, "model family", "model families")} and ${plural(attOwners.size, "owner")}.</p>`;

  const need = state.rules.promotion.kernelSignoffs;
  const signers = state.rules.kernelSigners;
  const signoffs = h`<p>${badge(snap.signoffs.length >= need ? "ok" : "warn", `${snap.signoffs.length} of ${need} required`)} ${
    snap.signoffs.length === 0 ? "no signoffs yet" : snap.signoffs.map((o, i) => h`${i > 0 ? ", " : ""}${ownerLink(o)}`)
  }</p><p class="note">Kernel signers: ${signers.length === 0 ? "none configured" : signers.map((o, i) => h`${i > 0 ? ", " : ""}${o}`)}</p>`;

  const p = attempt(() => site.derive.promotion(snap.id));
  const promotion = !p.ok
    ? unavailable("Promotion checks", p.error)
    : h`<p>${p.value.pass ? badge("ok", "all checks pass") : badge("bad", "not ready")}</p>
<table><thead><tr><th>check</th><th>result</th><th>detail</th></tr></thead><tbody>${p.value.checks.map(
        (c) =>
          h`<tr class="${c.pass ? "" : "bad"}"><td>${c.name}</td><td>${c.pass ? badge("ok", "pass") : badge("bad", "fail")}</td><td>${c.detail}</td></tr>`,
      )}</tbody></table>`;

  const snapFindings = [...state.findings.values()].filter((f) => "snapshotId" in f.target && f.target.snapshotId === snap.id);
  const escapes = state.escapes.filter((e) => e.snapshotId === snap.id);

  const body = h`<h1>Snapshot ${code(snap.id)} ${snapshotStatus(snap)}</h1>
<dl>
<dt>commit</dt><dd>${code(short(snap.commit, 12), snap.commit)}</dd>
<dt>cut</dt><dd>${fmtTime(snap.at)} (#${snap.seq})</dd>
<dt>previous</dt><dd>${snap.previousSnapshotId === null ? "none" : idLink(snapshotHref(snap.previousSnapshotId), snap.previousSnapshotId)}</dd>
<dt>ancestry</dt><dd>${ancestry.map((s, i) => h`${i > 0 ? " ← " : ""}${idLink(snapshotHref(s.id), s.id)}`)}</dd>
${snap.promoted ? h`<dt>promoted</dt><dd>${fmtTime(snap.promoted.at)} (#${snap.promoted.seq})</dd>` : ""}
</dl>
<h2>Promotion checks</h2>${promotion}
<h2>Review coverage</h2>
<p class="note">${reviewed} of ${plural(snap.submissionIds.length, "PR")} in this snapshot have at least one revealed review.</p>
<table><thead><tr><th>PR</th><th>reviews</th><th>reviewer models</th><th>findings</th><th></th></tr></thead><tbody>${coverageRows}</tbody></table>
<h2>Attestations</h2>${attestations}
<h2>Kernel signoffs</h2>${signoffs}
<h2>Findings on this snapshot</h2>${findingsTable(site, snapFindings)}
${escapes.length > 0 ? h`<h2>Escapes</h2><ul class="plain">${escapes.map((e) => h`<li>${findingLink(state, e.findingId)} at ${fmtTime(e.at)}</li>`)}</ul>` : ""}`;
  return page(site, `snapshot ${snap.id}`, body);
}

// Track record of a set of agents (one agent, or all of an owner's).
function trackRecord(site: Site, keys: KeyId[], owner: OwnerId): Html {
  const { state } = site;
  const mine = new Set(keys);
  const subs = [...state.submissions.values()].filter((s) => mine.has(s.author));
  const merged = subs.filter((s) => s.merged);
  const filed = [...state.findings.values()].filter((f) => mine.has(f.finder));
  const held = filed.filter((f) => f.result?.reproduced === true);
  const falseFindings = filed.filter((f) => f.result?.reproduced === false);
  const pending = filed.filter((f) => !f.result);

  const scores = attempt(() => site.derive.reviewerScores());
  const calibration = !scores.ok
    ? unavailable("Calibration", scores.error)
    : h`<table><thead><tr><th>agent</th><th>reviews</th><th>scored</th><th>mean Brier</th><th>plants caught</th></tr></thead><tbody>${keys.map(
        (k) => {
          const sc = scores.value.get(k);
          if (!sc) return h`<tr><td>${agentLabel(state, k)}</td><td colspan="4" class="note">no reviews</td></tr>`;
          return h`<tr><td>${agentLabel(state, k)}</td><td>${sc.reviews}</td><td>${sc.scored}</td><td>${sc.scored === 0 ? "—" : num(sc.meanBrier)}</td><td>${sc.plantsCaught} of ${sc.plantsSeen}</td></tr>`;
        },
      )}</tbody></table>
<p class="note">Brier score: mean squared error of the revealed defect probability against the outcome; 0 is perfect, 0.25 is a coin flip. Scored reviews are those whose PR's outcome is known.</p>`;

  const settlements = state.settlements.filter((s) => s.owner === owner);
  const total = settlements.reduce((a, s) => a + s.delta, 0);
  const list = (items: Html[]) => (items.length === 0 ? h`<p class="note">None.</p>` : h`<ul class="plain">${items}</ul>`);

  return h`<div class="counts"><span><b>${merged.length}</b> merged of ${subs.length} PRs</span><span><b>${held.length}</b> findings held up</span><span><b>${falseFindings.length}</b> false findings</span><span><b>${pending.length}</b> pending</span></div>
<h2>Merged changes</h2>${list(merged.map((s) => h`<li>${idLink(submissionHref(s.id), s.id)} ${s.merged ? fmtTime(s.merged.at) : ""} · ${plural(s.linesChanged, "line")}${s.planted ? h` ${badge("warn", "planted")}` : ""}</li>`))}
<h2>Other PRs</h2>${list(subs.filter((s) => !s.merged).map((s) => h`<li>${idLink(submissionHref(s.id), s.id)} ${submissionStatus(state, s)}</li>`))}
<h2>Findings that held up</h2>${list(held.map((f) => h`<li>${findingLink(state, f.id)} (${f.severity}) on ${targetLink(state, f.target)}</li>`))}
<h2>False findings</h2>${list(falseFindings.map((f) => h`<li>${findingLink(state, f.id)} (${f.severity}) on ${targetLink(state, f.target)}: ${f.result ? reproductionText(f.result) : ""}</li>`))}
<h2>Calibration</h2>${calibration}
<h2>Settlements for owner ${owner}</h2>${
    settlements.length === 0
      ? h`<p class="note">None.</p>`
      : h`<p class="note">Net ${signed(total)}. Settlements accrue to the owner, not to individual agents.</p><table><thead><tr><th>#</th><th>when</th><th>delta</th><th>reason</th><th>ref</th></tr></thead><tbody>${settlements.map(
          (s) =>
            h`<tr class="${s.delta < 0 ? "bad" : ""}"><td>${s.seq}</td><td>${fmtTime(s.at)}</td><td>${badge(s.delta < 0 ? "bad" : "ok", signed(s.delta))}</td><td>${s.reason}</td><td>${refLink(state, s.ref)}</td></tr>`,
        )}</tbody></table>`
  }`;
}

function ownerPage(site: Site, owner: OwnerId): string {
  const { state, tree } = site;
  const o = state.owners.get(owner);
  if (!o) return "";
  const agents = agentsOf(state, owner);
  const inTree = attempt(() => tree.has(owner));
  const member = inTree.ok && inTree.value;
  const parent = member ? attempt(() => tree.parent(owner)) : null;
  const rep = member ? attempt(() => tree.reputation(owner)) : null;
  const body = h`<h1>Owner ${owner}</h1>
<dl>
<dt>reputation delta</dt><dd>${signed(o.reputationDelta)} (this project)</dd>
<dt>Anthill reputation</dt><dd>${rep === null ? h`<span class="note">not in the tree</span>` : rep.ok ? rep.value : "?"}</dd>
<dt>tree parent</dt><dd>${parent && parent.ok ? (parent.value === null ? "root" : state.owners.has(parent.value) ? ownerLink(parent.value) : parent.value) : "—"}</dd>
<dt>locked stake</dt><dd>${o.lockedStake}</dd>
<dt>invited by</dt><dd>${o.inviter === null ? "nobody (founding owner)" : ownerLink(o.inviter)}</dd>
<dt>key</dt><dd>${code(short(o.keyId, 12), o.keyId)}</dd>
</dl>
<h2>Agents</h2>${
    agents.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${agents.map((a) => h`<li>${idLink(agentHref(a.keyId), a.keyId)} ${a.modelFamily} · harness ${a.harness} ${a.active ? badge("ok", "active") : h`${badge("bad", "revoked")} ${a.revokedReason ?? ""}`}</li>`)}</ul>`
  }
${trackRecord(site, agents.map((a) => a.keyId), owner)}`;
  return page(site, `owner ${owner}`, body);
}

function agentPage(site: Site, keyId: KeyId): string {
  const { state } = site;
  const a = state.agents.get(keyId);
  if (!a) return "";
  const honey = state.honeytokens.filter((t) => t.agent === keyId);
  const body = h`<h1>Agent ${code(short(keyId, 12), keyId)} ${a.active ? badge("ok", "active") : badge("bad", "revoked")}</h1>
<dl>
<dt>owner</dt><dd>${ownerLink(a.owner)}</dd>
<dt>model family</dt><dd>${a.modelFamily}</dd>
<dt>harness</dt><dd>${a.harness}</dd>
<dt>key id</dt><dd><code>${keyId}</code></dd>
${a.active ? "" : h`<dt>revoked</dt><dd>${a.revokedReason ?? ""}</dd>`}
${honey.length > 0 ? h`<dt>honeytokens</dt><dd>${badge("bad", `${honey.length} triggered`)}</dd>` : ""}
</dl>
${trackRecord(site, [keyId], a.owner)}`;
  return page(site, `agent ${short(keyId)}`, body);
}

// ---------------------------------------------------------------------------
// JSON API
// ---------------------------------------------------------------------------

function reviewJson(r: ReviewState) {
  // A sealed review exposes only that it exists. The commitment hash is public
  // in the ledger anyway; the verdict appears only after a matching reveal.
  return {
    reviewer: r.reviewer,
    stake: r.stake,
    committedSeq: r.committedSeq,
    revealed: r.verdict !== undefined,
    ...(r.verdict ? { revealedSeq: r.revealedSeq, verdict: r.verdict } : {}),
  };
}

export function stateJson(site: Site) {
  const { state } = site;
  const subs = [...state.submissions.values()];
  const findings = [...state.findings.values()];
  const snaps = [...state.snapshots.values()];
  return {
    project: state.project,
    length: state.length,
    headHash: state.headHash,
    asOf: site.nowIso,
    rules: state.rules,
    counts: {
      owners: state.owners.size,
      agents: state.agents.size,
      activeAgents: [...state.agents.values()].filter((a) => a.active).length,
      proposals: state.proposals.size,
      tasks: state.tasks.size,
      claims: state.claims.size,
      submissions: subs.length,
      merged: subs.filter((s) => s.merged).length,
      findings: findings.length,
      reproduced: findings.filter((f) => f.result?.reproduced === true).length,
      falseFindings: findings.filter((f) => f.result?.reproduced === false).length,
      snapshots: snaps.length,
      promoted: snaps.filter((s) => s.promoted).length,
      plantCommitments: state.plantCommitments.length,
      plantsRevealed: subs.filter((s) => s.planted).length,
      honeytokens: state.honeytokens.length,
      escapes: state.escapes.length,
      settlements: state.settlements.length,
    },
    owners: [...state.owners.values()].map((o) => ({ ...o, agents: agentsOf(state, o.id).map((a) => a.keyId) })),
    agents: [...state.agents.values()],
    proposals: [...state.proposals.values()],
    tasks: [...state.tasks.values()],
    claims: [...state.claims.values()],
    submissions: subs.map((s) => ({
      id: s.id,
      author: s.author,
      owner: ownerOfAgent(state, s.author) ?? null,
      taskId: s.taskId,
      baseCommit: s.baseCommit,
      headCommit: s.headCommit,
      changedFiles: s.changedFiles,
      linesChanged: s.linesChanged,
      submittedSeq: s.submittedSeq,
      submittedAt: s.submittedAt,
      gates: s.gates,
      assignment: s.assignment ?? null,
      reviews: s.reviews.map(reviewJson),
      findingIds: s.findingIds,
      merged: s.merged ?? null,
      planted: s.planted ?? null, // set only after plantReveal
    })),
    findings,
    snapshots: snaps.map((s) => ({ ...s, attestations: s.attestations.map(reviewJson), promoted: s.promoted ?? null })),
    escapes: state.escapes,
    honeytokens: state.honeytokens,
    settlements: state.settlements,
  };
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Cross-Origin-Resource-Policy": "same-origin",
};

function reply(status: number, type: string, body: string, extra: Record<string, string> = {}): Reply {
  return {
    status,
    headers: { ...SECURITY_HEADERS, "Content-Type": type, "Cache-Control": "no-store", ...extra },
    body,
  };
}

const HTML = "text/html; charset=utf-8";
const JSON_TYPE = "application/json; charset=utf-8";

// `<` is escaped so a JSON body can never be read as markup by anything.
function jsonReply(status: number, value: unknown): Reply {
  const body = JSON.stringify(value, (_k, v: unknown) => (v instanceof Map ? Object.fromEntries(v) : v), 2);
  return reply(status, JSON_TYPE, body.replace(/</g, "\\u003c"));
}

function htmlError(site: { state: CommonsState; nowIso: string } | null, status: number, message: string): Reply {
  const title = status === 404 ? "not found" : status === 400 ? "bad request" : "error";
  return reply(status, HTML, page(site, title, h`<h1>${title}</h1><p>${message}</p><p><a href="/">back to the overview</a></p>`));
}

// The whole site. `load` is called only for routes that need the ledger, so
// the refresh script is served even while the ledger cannot be read.
export function route(load: () => Site, method: string, rawUrl: string): Reply {
  if (method !== "GET" && method !== "HEAD") {
    return reply(405, "text/plain; charset=utf-8", "method not allowed\n", { Allow: "GET, HEAD" });
  }
  let url: URL;
  try {
    url = new URL(rawUrl, "http://playground.invalid");
  } catch {
    return htmlError(null, 400, "Malformed URL.");
  }
  let segs: string[];
  try {
    segs = url.pathname.split("/").slice(1).map(decodeURIComponent);
  } catch {
    return htmlError(null, 400, "Malformed path.");
  }
  const isApi = segs[0] === "api";

  if (segs.length === 2 && segs[0] === "static" && segs[1] === "refresh.js") {
    return reply(200, "text/javascript; charset=utf-8", REFRESH_JS, { "Cache-Control": "public, max-age=300" });
  }

  let site: Site;
  try {
    site = load();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return isApi
      ? jsonReply(503, { error: "ledger unavailable", detail: msg })
      : htmlError(null, 503, `The ledger could not be read: ${msg}`);
  }
  const notFound = (what: string) => (isApi ? jsonReply(404, { error: what }) : htmlError(site, 404, what));

  const [a, b] = segs;
  if (segs.length === 1 && a === "") return reply(200, HTML, overview(site));
  if (segs.length === 2 && b !== undefined && b !== "") {
    switch (a) {
      case "submissions": {
        const s = site.state.submissions.get(b);
        return s ? reply(200, HTML, submissionPage(site, s)) : notFound(`No submission ${b}.`);
      }
      case "snapshots": {
        const s = site.state.snapshots.get(b);
        return s ? reply(200, HTML, snapshotPage(site, s)) : notFound(`No snapshot ${b}.`);
      }
      case "owners":
        return site.state.owners.has(b) ? reply(200, HTML, ownerPage(site, b)) : notFound(`No owner ${b}.`);
      case "agents":
        return site.state.agents.has(b) ? reply(200, HTML, agentPage(site, b)) : notFound(`No agent ${b}.`);
      case "api":
        return api(site, b, url.searchParams);
    }
  }
  return notFound("No such page.");
}

function api(site: Site, name: string, params: URLSearchParams): Reply {
  switch (name) {
    case "state":
      return jsonReply(200, stateJson(site));
    case "metrics": {
      const m = attempt(() => site.derive.metrics());
      return m.ok
        ? jsonReply(200, { asOf: site.nowIso, length: site.state.length, rows: m.value })
        : jsonReply(500, { error: "metrics unavailable", detail: m.error });
    }
    case "entries": {
      const since = intParam(params.get("since"), 0);
      const limit = intParam(params.get("limit"), MAX_ENTRIES_PAGE);
      if (since === null || limit === null || limit < 1) {
        return jsonReply(400, { error: "since and limit must be non-negative integers; limit >= 1" });
      }
      const size = Math.min(limit, MAX_ENTRIES_PAGE);
      const page = site.entries.slice(since, since + size);
      const next = since + page.length < site.entries.length ? since + page.length : null;
      return jsonReply(200, {
        head: { length: site.state.length, hash: site.state.headHash },
        since,
        limit: size,
        next,
        entries: page,
      });
    }
  }
  return jsonReply(404, { error: "No such endpoint." });
}

function intParam(raw: string | null, fallback: number): number | null {
  if (raw === null || raw === "") return fallback;
  if (!/^\d{1,15}$/.test(raw)) return null;
  return Number(raw);
}
