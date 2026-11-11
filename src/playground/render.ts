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
// `submission.planted`. Plant commitments are not listed in the stream at all:
// where one sits relative to the submissions after it would point at the plant.
//
// Size contract. The ledger bounds no string or list length, so any agent can
// write megabyte titles or thousands of changed files. Every attacker string is
// clipped where it is displayed (`clip`, CLIP), every list is cut at MAX_LIST,
// and /api/entries is capped by bytes as well as entries. The full values stay
// in the signed entries, which /api/entries serves to anyone who wants them.
//
// Error contract. Exception text never reaches a reply: it can carry file
// paths and internals. Failures go to `log`; the reply says only what failed.

import { keyIdOf } from "../crypto";
import { LedgerError } from "../ledger";
import type {
  AgentState,
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
  // Reuses a rendered body for the same key while the ledger and `nowIso` are
  // unchanged. The caller owns invalidation; without it everything is rendered
  // per request.
  memo?: <T>(key: string, f: () => T) => T;
  // Where failures are reported instead of the reply. Defaults to console.error.
  log?: (error: unknown) => void;
};

export type Reply = { status: number; headers: Record<string, string>; body: string };

export const STREAM_LENGTH = 100;
export const MAX_ENTRIES_PAGE = 500;
// A page of /api/entries stops once its entries pass this many bytes (it always
// carries at least one entry, so a client can make progress past a huge one).
export const MAX_ENTRIES_BYTES = 4 * 1024 * 1024;
// Display limits for attacker-controlled text: `line` in the stream and lists,
// `text` on an object's own page, `id` for ids, names and paths.
export const CLIP = { line: 200, text: 2000, id: 256 } as const;
// Longest list rendered on any page; the rest is counted, not shown.
export const MAX_LIST = 200;

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

export function clip(value: string, n: number): string {
  return value.length <= n ? value : `${value.slice(0, n)}… [${value.length - n} more characters]`;
}

type ObjectKind = "submissions" | "snapshots" | "owners" | "agents";

// The ledger accepts any non-empty id. "." and ".." are dot segments that URL
// parsers (ours and every browser's) normalise away, and a huge id would make
// every link to it huge, so those objects are linked by query instead: by the
// seq of the entry that created them where there is one, else by id.
function objectHref(kind: ObjectKind, id: string, seq?: number): string {
  if (id.length <= CLIP.id && !/^\.{1,2}$/.test(id)) return `/${kind}/${encodeURIComponent(id)}`;
  return seq === undefined ? `/${kind}?id=${encodeURIComponent(id)}` : `/${kind}?seq=${seq}`;
}
const submissionHref = (state: CommonsState, id: string) =>
  objectHref("submissions", id, state.submissions.get(id)?.submittedSeq);
const snapshotHref = (state: CommonsState, id: string) => objectHref("snapshots", id, state.snapshots.get(id)?.seq);
const ownerHref = (id: string) => objectHref("owners", id);
const agentHref = (id: string) => objectHref("agents", id);
// Finding anchors use the filing seq: bounded, and unique like the id.
const findingAnchor = (f: FindingState) => `f-${f.seq}`;

function short(id: string, n = 8): string {
  return id.length > n + 2 ? `${id.slice(0, n)}…` : id;
}

function idLink(href: string, id: string): Html {
  return h`<a class="id" href="${href}" title="${clip(id, CLIP.id)}">${short(id, 12)}</a>`;
}

function code(text: string, full?: string): Html {
  return h`<code class="id" title="${clip(full ?? text, CLIP.id)}">${clip(text, CLIP.id)}</code>`;
}

// "and N more" under a list cut at `max`.
function more(total: number, max = MAX_LIST): Html {
  return total > max ? h`<p class="note">and ${total - max} more not shown; the full list is in the signed entries.</p>` : h``;
}

// Items rendered inline, comma-separated, cut at `max`.
function inline<T>(items: readonly T[], render: (x: T) => Html | string, max: number): Html {
  const shown = items.slice(0, max).map((x, i) => h`${i > 0 ? ", " : ""}${render(x)}`);
  return h`${shown}${items.length > max ? ` and ${items.length - max} more` : ""}`;
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
  if (typeof v === "string") return clip(v, CLIP.line);
  try {
    return clip(JSON.stringify(v), CLIP.line);
  } catch {
    return clip(String(v), CLIP.line);
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

const defaultLog = (e: unknown) => console.error("playground:", e);

// The error is logged, never returned: see the error contract above.
function attempt<T>(site: Pick<Site, "log">, f: () => T): { ok: true; value: T } | { ok: false } {
  try {
    return { ok: true, value: f() };
  } catch (e) {
    (site.log ?? defaultLog)(e);
    return { ok: false };
  }
}

function unavailable(what: string): Html {
  return h`<p class="note">${badge("warn", "unavailable")} ${what} could not be computed.</p>`;
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
  return h`<a href="${ownerHref(id)}">${clip(id, CLIP.id)}</a>`;
}

function agentLabel(state: CommonsState, keyId: KeyId): Html {
  const a = state.agents.get(keyId);
  if (!a) return h`key ${code(short(keyId), keyId)}`;
  const revoked = a.active ? "" : h` ${badge("bad", "revoked")}`;
  return h`agent ${idLink(agentHref(keyId), keyId)} (owner ${ownerLink(a.owner)}, ${clip(a.modelFamily, CLIP.id)})${revoked}`;
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

// The ledger refuses to merge a PR with any failed gate result (ledger.ts,
// "merge"), so a failure stays a block even if a later run of that gate passed.
// The label follows the ledger's rule rather than the latest run.
function statusOf(state: CommonsState, s: SubmissionState): { tone: Tone; label: string } {
  if (s.merged) return { tone: "ok", label: "merged" };
  if (s.findingIds.some((id) => state.findings.get(id)?.result?.reproduced === true)) {
    return { tone: "bad", label: "blocked: reproduced finding" };
  }
  if (s.gates.some((g) => !g.pass)) return { tone: "bad", label: "blocked: gate failed" };
  if (s.assignment) return { tone: "mut", label: "in review" };
  return { tone: "mut", label: "open" };
}

function submissionStatus(state: CommonsState, s: SubmissionState): Html {
  const { tone, label } = statusOf(state, s);
  return h`${s.planted ? h`${badge("warn", "planted bug (revealed)")} ` : ""}${badge(tone, label)} `;
}

function snapshotStatus(s: SnapshotState): Html {
  return s.promoted ? badge("ok", "promoted to main") : badge("mut", "release candidate");
}

function reviewCell(r: ReviewState): Html {
  if (!r.verdict) return h`${badge("mut", "sealed")} commitment recorded at #${r.committedSeq}`;
  const p = r.verdict.defectProbability;
  const tone: Tone = p >= 0.5 ? "bad" : p >= 0.2 ? "warn" : "ok";
  return h`${badge(tone, `defect p=${p.toFixed(2)}`)} ${clip(r.verdict.summary, CLIP.text)}`;
}

function evidenceKinds(ev: readonly Evidence[]): string {
  const names = { failingTest: "failing test", diagnostic: "diagnostic", location: "location" } as const;
  return [...new Set(ev.map((e) => names[e.kind] ?? "evidence"))].join(", ");
}

function targetLink(state: CommonsState, target: FindingState["target"]): Html {
  if ("submissionId" in target) return h`PR ${idLink(submissionHref(state, target.submissionId), target.submissionId)}`;
  return state.snapshots.has(target.snapshotId)
    ? h`snapshot ${idLink(snapshotHref(state, target.snapshotId), target.snapshotId)}`
    : h`snapshot ${code(target.snapshotId)}`;
}

function findingLink(state: CommonsState, id: string): Html {
  const f = state.findings.get(id);
  if (!f) return h`finding ${code(id)}`;
  const page =
    "submissionId" in f.target ? submissionHref(state, f.target.submissionId) : snapshotHref(state, f.target.snapshotId);
  return h`finding <a class="id" href="${page}#${findingAnchor(f)}" title="${clip(id, CLIP.id)}">${short(id, 12)}</a>`;
}

// A settlement ref is free text; link it when it names a known object exactly.
function refLink(state: CommonsState, ref: string): Html {
  if (state.submissions.has(ref)) return h`PR ${idLink(submissionHref(state, ref), ref)}`;
  if (state.findings.has(ref)) return findingLink(state, ref);
  if (state.snapshots.has(ref)) return h`snapshot ${idLink(snapshotHref(state, ref), ref)}`;
  return code(short(ref, 24), ref);
}

// ---------------------------------------------------------------------------
// The stream: each ledger entry as one human sentence
// ---------------------------------------------------------------------------

export function sentence(state: CommonsState, entry: LedgerEntry): Html {
  const b: EntryBody = entry.body;
  const who = actor(state, entry.signer);
  const pr = (id: string) => h`PR ${idLink(submissionHref(state, id), id)}`;
  const snap = (id: string) => h`snapshot ${idLink(snapshotHref(state, id), id)}`;
  const line = (text: string) => clip(text, CLIP.line);
  switch (b.kind) {
    case "genesis":
      return h`ledger opened for project ${code(b.project)} with ${plural(b.admins.length, "admin")} (rules v${b.rules.version})`;
    case "ownerKey":
      return b.inviter === null
        ? h`owner ${ownerLink(b.owner)} joined`
        : h`owner ${ownerLink(b.owner)} joined, invited by ${ownerLink(b.inviter)}`;
    case "agentRegistered": {
      const keyId = keyIdOf(b.publicKey);
      return h`owner ${ownerLink(b.owner)} registered agent ${idLink(agentHref(keyId), keyId)} (${line(b.modelFamily)}, harness ${line(b.harness)})`;
    }
    case "agentRevoked":
      return h`${agentLabel(state, b.agent)} was ${entry.signer === state.coordinatorKey ? "suspended by the coordinator" : "revoked by its owner"}: ${line(b.reason)}`;
    case "proposal":
      return h`${who} proposed ${code(b.id)}: “${line(b.title)}” (evidence: ${evidenceKinds(b.evidence)})`;
    case "task":
      return h`task ${code(b.id)} opened from proposal ${code(b.proposalId)}: ring ${b.ring}, ~${b.sizeEstimate} lines, spec by ${ownerLink(b.specAuthor)}`;
    case "claim":
      return h`${who} claimed task ${code(b.taskId)} until ${fmtTime(b.until)} (stake ${b.stake})`;
    case "submission":
      return h`${who} submitted ${pr(b.id)}${b.taskId === null ? "" : h` for task ${code(b.taskId)}`}: ${plural(b.changedFiles.length, "file")}, ${plural(b.linesChanged, "line")}`;
    case "gateResult":
      return b.pass
        ? h`gate ${code(b.gate)} ${badge("ok", "passed")} on ${pr(b.submissionId)}`
        : h`gate ${code(b.gate)} ${badge("bad", "failed")} on ${pr(b.submissionId)}: ${line(b.details)}`;
    case "reviewAssignment":
      return h`reviewers drawn for ${pr(b.submissionId)}: ${inline(b.reviewers, (r) => agentLabel(state, r), 10)}`;
    case "reviewCommit":
      return h`${who} sealed a review of ${pr(b.submissionId)} (stake ${b.stake})`;
    case "reviewReveal":
      return h`${who} reviewed ${pr(b.submissionId)}: defect p=${b.verdict.defectProbability.toFixed(2)} — ${line(b.verdict.summary)}`;
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
      return h`${who} attested ${snap(b.snapshotId)}: defect p=${b.verdict.defectProbability.toFixed(2)} — ${line(b.verdict.summary)}`;
    case "signoff": {
      const owner = state.ownerByKey.get(entry.signer);
      return h`kernel signer ${owner === undefined ? who : ownerLink(owner)} signed off ${snap(b.snapshotId)}`;
    }
    case "promotion":
      return h`${snap(b.snapshotId)} ${badge("ok", "promoted")} to main`;
    case "plantCommit":
      // Not shown in the overview stream (see the header); kept for completeness.
      return h`the seeding custodian committed to a planted bug (sealed)`;
    case "plantReveal":
      return h`${pr(b.submissionId)} revealed as a ${badge("warn", "planted bug")} (${b.severity}): ${line(b.description)}`;
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
      return h`entry of kind ${code(String(unknown.kind))}`;
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
<title>${clip(title, 80)} · agent commons</title><style>${new Html(CSS)}</style></head>
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

  const m = attempt(site, () => site.derive.metrics());
  const metrics = !m.ok
    ? unavailable("Metrics")
    : m.value.length === 0
      ? h`<p class="note">No metrics yet.</p>`
      : h`<table><thead><tr><th>group</th><th>metric</th><th>value</th><th>status</th><th>note</th></tr></thead><tbody>
${m.value.map(
  (r) =>
    h`<tr class="${r.bad ? "bad" : ""}"><td>${r.group}</td><td>${r.metric}</td><td><code>${fmtValue(r.value)}</code></td><td>${r.bad ? badge("bad", "attention") : badge("ok", "ok")}</td><td>${clip(r.note, CLIP.text)}</td></tr>\n`,
)}</tbody></table>`;

  // Plant commitments are left out: see the header.
  const latest: LedgerEntry[] = [];
  for (let i = entries.length - 1; i >= 0 && latest.length < STREAM_LENGTH; i--) {
    const e = entries[i] as LedgerEntry;
    if (e.body.kind !== "plantCommit") latest.push(e);
  }
  const stream = h`<ol class="stream">${latest.map(
    (e) =>
      h`<li><span class="seq">#${e.seq}</span><span class="when" title="${e.at}">${ago(e.at, nowIso)}</span>${attemptHtml(site, () => sentence(state, e))}</li>\n`,
  )}</ol>`;

  const openSubs = subs.filter((s) => !s.merged).slice(-20).reverse();
  const recentSnaps = snaps.slice(-10).reverse();
  const owners = [...state.owners.values()].sort((a, b) => b.reputationDelta - a.reputationDelta || cmp(a.id, b.id));
  const agentCount = agentsByOwner(state);

  const body = h`<h1>Agents at work</h1>
<p class="note">A live view of the commons ledger: proposals, PRs, sealed reviews, reproduced findings, snapshots and settlements, each one a signed entry.</p>
${counts}
<h2>Health</h2>${metrics}
<h2>Latest ${latest.length} entries</h2>${stream}
<p class="note">Plant commitments are not listed here, so their position cannot point at a plant; they are in the signed entries.</p>
<h2>Open PRs</h2>${
    openSubs.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${openSubs.map((s) => h`<li>${idLink(submissionHref(state, s.id), s.id)} ${submissionStatus(state, s)} by ${agentLabel(state, s.author)}</li>`)}</ul>`
  }
<h2>Snapshots</h2>${
    recentSnaps.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${recentSnaps.map((s) => h`<li>${idLink(snapshotHref(state, s.id), s.id)} ${snapshotStatus(s)} ${plural(s.submissionIds.length, "PR")}</li>`)}</ul>`
  }
<h2>Owners</h2>${
    owners.length === 0
      ? h`<p class="note">None.</p>`
      : h`<table><thead><tr><th>owner</th><th>reputation delta</th><th>locked stake</th><th>agents</th></tr></thead><tbody>${owners.slice(0, MAX_LIST).map(
          (o) =>
            h`<tr><td>${ownerLink(o.id)}</td><td>${signed(o.reputationDelta)}</td><td>${o.lockedStake}</td><td>${agentCount.get(o.id)?.length ?? 0}</td></tr>`,
        )}</tbody></table>${more(owners.length)}`
  }`;
  return page(site, "overview", body);
}

function attemptHtml(site: Site, f: () => Html): Html {
  const r = attempt(site, f);
  return r.ok ? r.value : badge("warn", "unrenderable entry");
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

// One pass over the agents; calling a per-owner filter in a loop is owners x agents.
function agentsByOwner(state: CommonsState): Map<OwnerId, AgentState[]> {
  const out = new Map<OwnerId, AgentState[]>();
  for (const a of state.agents.values()) {
    const list = out.get(a.owner);
    if (list) list.push(a);
    else out.set(a.owner, [a]);
  }
  return out;
}

function submissionPage(site: Site, s: SubmissionState): string {
  const { state, tree } = site;
  const authorOwner = ownerOfAgent(state, s.author);
  const authorFamily = state.agents.get(s.author)?.modelFamily;
  const task = s.taskId === null ? undefined : state.tasks.get(s.taskId);
  const proposal = task ? state.proposals.get(task.proposalId) : undefined;

  // Every gate result stays on the ledger and every failure blocks the merge
  // (see statusOf), so a failure a later run passed is shown, and said so.
  const laterPass = (i: number) => s.gates.some((g, j) => j > i && g.pass && g.gate === s.gates[i]?.gate);
  const gates =
    s.gates.length === 0
      ? h`<p class="note">No gate results recorded yet.</p>`
      : h`<table><thead><tr><th>gate</th><th>result</th><th>details</th></tr></thead><tbody>${s.gates.slice(0, MAX_LIST).map(
          (g, i) =>
            h`<tr class="${g.pass ? "" : "bad"}"><td>${code(g.gate)}</td><td>${g.pass ? badge("ok", "pass") : badge("bad", "fail")}${!g.pass && laterPass(i) ? h`<br><span class="note">a later run passed; the ledger still counts this failure</span>` : ""}</td><td>${clip(g.details, CLIP.text)}</td></tr>`,
        )}</tbody></table>${more(s.gates.length)}`;

  // Assigned seats first (even if not yet committed), then open reviewers.
  const assigned = s.assignment?.reviewers ?? [];
  const assignedSet = new Set(assigned);
  const byReviewer = new Map(s.reviews.map((r) => [r.reviewer, r]));
  const rows = [
    ...assigned.map((k) => ({ keyId: k, seat: "assigned", review: byReviewer.get(k) })),
    ...s.reviews.filter((r) => !assignedSet.has(r.reviewer)).map((r) => ({ keyId: r.reviewer, seat: "open", review: r })),
  ];
  const otherFamily = rows.some((r) => {
    const f = state.agents.get(r.keyId)?.modelFamily;
    return f !== undefined && f !== authorFamily;
  });
  const reviewers =
    rows.length === 0
      ? h`<p class="note">No reviewers drawn yet.</p>`
      : h`<table><thead><tr><th>reviewer</th><th>model</th><th>tree distance</th><th>seat</th><th>review</th></tr></thead><tbody>${rows.slice(0, MAX_LIST).map(
          (r) => {
            const agent = state.agents.get(r.keyId);
            const d = treeDistance(tree, authorOwner, agent?.owner);
            const sameFamily = agent !== undefined && agent.modelFamily === authorFamily;
            return h`<tr><td>${agentLabel(state, r.keyId)}</td><td>${clip(agent?.modelFamily ?? "?", CLIP.id)}${sameFamily ? h` ${badge("warn", "same as author")}` : ""}</td><td>${d === null ? h`<span class="note">not in tree</span>` : d}</td><td>${r.seat}</td><td>${r.review ? reviewCell(r.review) : badge("mut", "not committed")}</td></tr>`;
          },
        )}</tbody></table>${more(rows.length)}
<p class="note">${otherFamily ? badge("ok", "other model family present") : badge("warn", "no other model family")} Sealed reviews show only that a commitment exists; the verdict appears once it is revealed and matches.</p>`;

  const findingRows = s.findingIds.map((id) => state.findings.get(id)).filter((f): f is FindingState => f !== undefined);
  const body = h`<h1>PR ${code(s.id)} ${submissionStatus(state, s)}</h1>
${proposal ? h`<p>“${clip(proposal.title, CLIP.text)}”</p>` : ""}
<dl>
<dt>author</dt><dd>${agentLabel(state, s.author)}</dd>
<dt>task</dt><dd>${task ? h`${code(task.id)} · ring ${task.ring} · spec by ${ownerLink(task.specAuthor)}` : "none (untasked)"}</dd>
<dt>base → head</dt><dd>${code(short(s.baseCommit, 12), s.baseCommit)} → ${code(short(s.headCommit, 12), s.headCommit)}</dd>
<dt>size</dt><dd>${plural(s.changedFiles.length, "file")}, ${plural(s.linesChanged, "line")}</dd>
<dt>submitted</dt><dd>${fmtTime(s.submittedAt)} (#${s.submittedSeq})</dd>
${s.merged ? h`<dt>merged</dt><dd>${fmtTime(s.merged.at)} at ${code(short(s.merged.commit, 12), s.merged.commit)}</dd>` : ""}
${s.assignment ? h`<dt>beacon</dt><dd>${code(short(s.assignment.beacon, 16), s.assignment.beacon)} (#${s.assignment.seq})</dd>` : ""}
</dl>
${s.planted ? h`<p>${badge("warn", "planted bug")} revealed after the review window: (${s.planted.severity}) ${clip(s.planted.description, CLIP.text)}</p>` : ""}
<h2>Changed files</h2><ul class="plain">${s.changedFiles.slice(0, MAX_LIST).map((f) => h`<li>${code(f)}</li>`)}</ul>${more(s.changedFiles.length)}
<h2>Gates</h2>${gates}
<h2>Reviewers</h2>${reviewers}
<h2>Findings</h2>${findingsTable(site, findingRows)}`;
  return page(site, `PR ${s.id}`, body);
}

function findingsTable(site: Site, findings: FindingState[]): Html {
  const { state } = site;
  if (findings.length === 0) return h`<p class="note">No findings filed.</p>`;
  return h`<table><thead><tr><th>finding</th><th>by</th><th>severity</th><th>test</th><th>reproduction</th></tr></thead><tbody>${findings.slice(0, MAX_LIST).map(
    (f) =>
      h`<tr id="${findingAnchor(f)}"><td>${code(short(f.id, 12), f.id)}</td><td>${agentLabel(state, f.finder)}</td><td>${f.severity}</td><td>${code(f.testPath)}<br><span class="note">$ </span><code>${clip(f.testCommand, CLIP.text)}</code></td><td>${findingStatus(f)}${
        f.result
          ? h`<br><span class="note">${reproductionText(f.result)}; log ${code(short(f.result.logDigest, 12), f.result.logDigest)}</span>`
          : ""
      }</td></tr>`,
  )}</tbody></table>${more(findings.length)}`;
}

function snapshotPage(site: Site, snap: SnapshotState): string {
  const { state } = site;
  const ANCESTRY = 50;
  const ancestry: SnapshotState[] = [];
  let s: SnapshotState | undefined = snap;
  for (; s && ancestry.length < ANCESTRY; ) {
    ancestry.push(s);
    s = s.previousSnapshotId === null ? undefined : state.snapshots.get(s.previousSnapshotId);
  }
  const olderAncestors = s !== undefined;

  const coverageRows = snap.submissionIds.slice(0, MAX_LIST).map((sid) => {
    const s = state.submissions.get(sid);
    if (!s) return h`<tr><td>${code(sid)}</td><td colspan="4">unknown</td></tr>`;
    const revealed = s.reviews.filter((r) => r.verdict);
    const families = new Set(revealed.map((r) => clip(state.agents.get(r.reviewer)?.modelFamily ?? "?", CLIP.id)));
    const reproduced = s.findingIds.filter((id) => state.findings.get(id)?.result?.reproduced === true).length;
    const reviewTone: Tone = revealed.length === 0 ? "bad" : "ok";
    return h`<tr><td>${idLink(submissionHref(state, sid), sid)}</td><td>${badge(reviewTone, `${revealed.length}/${s.reviews.length} revealed`)}</td><td>${families.size === 0 ? "—" : inline([...families].sort(), (f) => f, 10)}</td><td>${s.findingIds.length} (${reproduced} reproduced)</td><td>${s.planted ? badge("warn", "plant") : ""}</td></tr>`;
  });
  const reviewed = snap.submissionIds.filter((sid) => state.submissions.get(sid)?.reviews.some((r) => r.verdict)).length;

  const revealedAtt = snap.attestations.filter((a) => a.verdict);
  const attFamilies = new Set(revealedAtt.map((a) => state.agents.get(a.reviewer)?.modelFamily ?? "?"));
  const attOwners = new Set(revealedAtt.map((a) => ownerOfAgent(state, a.reviewer) ?? "?"));
  const attestations =
    snap.attestations.length === 0
      ? h`<p class="note">No attestations yet.</p>`
      : h`<table><thead><tr><th>attester</th><th>attestation</th></tr></thead><tbody>${snap.attestations.slice(0, MAX_LIST).map(
          (a) => h`<tr><td>${agentLabel(state, a.reviewer)}</td><td>${reviewCell(a)}</td></tr>`,
        )}</tbody></table>${more(snap.attestations.length)}
<p class="note">Revealed attestations span ${plural(attFamilies.size, "model family", "model families")} and ${plural(attOwners.size, "owner")}. Sealed attestations show only that a commitment exists.</p>`;

  const need = state.rules.promotion.kernelSignoffs;
  const signers = state.rules.kernelSigners;
  const signoffs = h`<p>${badge(snap.signoffs.length >= need ? "ok" : "warn", `${snap.signoffs.length} of ${need} required`)} ${
    snap.signoffs.length === 0 ? "no signoffs yet" : inline(snap.signoffs, ownerLink, MAX_LIST)
  }</p><p class="note">Kernel signers: ${signers.length === 0 ? "none configured" : inline(signers, (o) => clip(o, CLIP.id), MAX_LIST)}</p>`;

  const p = attempt(site, () => site.derive.promotion(snap.id));
  const promotion = !p.ok
    ? unavailable("Promotion checks")
    : h`<p>${p.value.pass ? badge("ok", "all checks pass") : badge("bad", "not ready")}</p>
<table><thead><tr><th>check</th><th>result</th><th>detail</th></tr></thead><tbody>${p.value.checks.map(
        (c) =>
          h`<tr class="${c.pass ? "" : "bad"}"><td>${c.name}</td><td>${c.pass ? badge("ok", "pass") : badge("bad", "fail")}</td><td>${clip(c.detail, CLIP.text)}</td></tr>`,
      )}</tbody></table>`;

  const snapFindings = [...state.findings.values()].filter((f) => "snapshotId" in f.target && f.target.snapshotId === snap.id);
  const escapes = state.escapes.filter((e) => e.snapshotId === snap.id);

  const body = h`<h1>Snapshot ${code(snap.id)} ${snapshotStatus(snap)}</h1>
<dl>
<dt>commit</dt><dd>${code(short(snap.commit, 12), snap.commit)}</dd>
<dt>cut</dt><dd>${fmtTime(snap.at)} (#${snap.seq})</dd>
<dt>previous</dt><dd>${snap.previousSnapshotId === null ? "none" : idLink(snapshotHref(state, snap.previousSnapshotId), snap.previousSnapshotId)}</dd>
<dt>ancestry</dt><dd>${ancestry.map((s, i) => h`${i > 0 ? " ← " : ""}${idLink(snapshotHref(state, s.id), s.id)}`)}${olderAncestors ? " ← …" : ""}</dd>
${snap.promoted ? h`<dt>promoted</dt><dd>${fmtTime(snap.promoted.at)} (#${snap.promoted.seq})</dd>` : ""}
</dl>
<h2>Promotion checks</h2>${promotion}
<h2>Review coverage</h2>
<p class="note">${reviewed} of ${plural(snap.submissionIds.length, "PR")} in this snapshot have at least one revealed review.</p>
<table><thead><tr><th>PR</th><th>reviews</th><th>reviewer models</th><th>findings</th><th></th></tr></thead><tbody>${coverageRows}</tbody></table>${more(snap.submissionIds.length)}
<h2>Attestations</h2>${attestations}
<h2>Kernel signoffs</h2>${signoffs}
<h2>Findings on this snapshot</h2>${findingsTable(site, snapFindings)}
${escapes.length > 0 ? h`<h2>Escapes</h2><ul class="plain">${escapes.slice(0, MAX_LIST).map((e) => h`<li>${findingLink(state, e.findingId)} at ${fmtTime(e.at)}</li>`)}</ul>${more(escapes.length)}` : ""}`;
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

  const scores = attempt(site, () => site.derive.reviewerScores());
  const calibration = !scores.ok
    ? unavailable("Calibration")
    : h`<table><thead><tr><th>agent</th><th>reviews</th><th>scored</th><th>mean Brier</th><th>plants caught</th></tr></thead><tbody>${keys.slice(0, MAX_LIST).map(
        (k) => {
          const sc = scores.value.get(k);
          if (!sc) return h`<tr><td>${agentLabel(state, k)}</td><td colspan="4" class="note">no reviews</td></tr>`;
          return h`<tr><td>${agentLabel(state, k)}</td><td>${sc.reviews}</td><td>${sc.scored}</td><td>${sc.scored === 0 ? "—" : num(sc.meanBrier)}</td><td>${sc.plantsCaught} of ${sc.plantsSeen}</td></tr>`;
        },
      )}</tbody></table>${more(keys.length)}
<p class="note">Brier score: mean squared error of the revealed defect probability against the outcome; 0 is perfect, 0.25 is a coin flip. Scored reviews are those whose PR's outcome is known.</p>`;

  const settlements = state.settlements.filter((s) => s.owner === owner);
  const total = settlements.reduce((a, s) => a + s.delta, 0);
  // Newest last, as in the ledger; a long list keeps the newest MAX_LIST.
  const recentSettlements = settlements.slice(-MAX_LIST);
  const list = <T,>(items: readonly T[], render: (x: T) => Html) =>
    items.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${items.slice(0, MAX_LIST).map(render)}</ul>${more(items.length)}`;

  return h`<div class="counts"><span><b>${merged.length}</b> merged of ${subs.length} PRs</span><span><b>${held.length}</b> findings held up</span><span><b>${falseFindings.length}</b> false findings</span><span><b>${pending.length}</b> pending</span></div>
<h2>Merged changes</h2>${list(merged, (s) => h`<li>${idLink(submissionHref(state, s.id), s.id)} ${s.merged ? fmtTime(s.merged.at) : ""} · ${plural(s.linesChanged, "line")}${s.planted ? h` ${badge("warn", "planted")}` : ""}</li>`)}
<h2>Other PRs</h2>${list(subs.filter((s) => !s.merged), (s) => h`<li>${idLink(submissionHref(state, s.id), s.id)} ${submissionStatus(state, s)}</li>`)}
<h2>Findings that held up</h2>${list(held, (f) => h`<li>${findingLink(state, f.id)} (${f.severity}) on ${targetLink(state, f.target)}</li>`)}
<h2>False findings</h2>${list(falseFindings, (f) => h`<li>${findingLink(state, f.id)} (${f.severity}) on ${targetLink(state, f.target)}: ${f.result ? reproductionText(f.result) : ""}</li>`)}
<h2>Calibration</h2>${calibration}
<h2>Settlements for owner ${clip(owner, CLIP.id)}</h2>${
    settlements.length === 0
      ? h`<p class="note">None.</p>`
      : h`<p class="note">Net ${signed(total)}. Settlements accrue to the owner, not to individual agents.${settlements.length > MAX_LIST ? ` Showing the latest ${MAX_LIST} of ${settlements.length}.` : ""}</p><table><thead><tr><th>#</th><th>when</th><th>delta</th><th>reason</th><th>ref</th></tr></thead><tbody>${recentSettlements.map(
          (s) =>
            h`<tr class="${s.delta < 0 ? "bad" : ""}"><td>${s.seq}</td><td>${fmtTime(s.at)}</td><td>${badge(s.delta < 0 ? "bad" : "ok", signed(s.delta))}</td><td>${s.reason}</td><td>${refLink(state, s.ref)}</td></tr>`,
        )}</tbody></table>`
  }`;
}

function ownerPage(site: Site, owner: OwnerId): string {
  const { state, tree } = site;
  const o = state.owners.get(owner);
  if (!o) return "";
  const agents = agentsByOwner(state).get(owner) ?? [];
  const inTree = attempt(site, () => tree.has(owner));
  const member = inTree.ok && inTree.value;
  const parent = member ? attempt(site, () => tree.parent(owner)) : null;
  const rep = member ? attempt(site, () => tree.reputation(owner)) : null;
  const body = h`<h1>Owner ${clip(owner, CLIP.id)}</h1>
<dl>
<dt>reputation delta</dt><dd>${signed(o.reputationDelta)} (this project)</dd>
<dt>Anthill reputation</dt><dd>${rep === null ? h`<span class="note">not in the tree</span>` : rep.ok ? rep.value : "?"}</dd>
<dt>tree parent</dt><dd>${parent && parent.ok ? (parent.value === null ? "root" : state.owners.has(parent.value) ? ownerLink(parent.value) : clip(parent.value, CLIP.id)) : "—"}</dd>
<dt>locked stake</dt><dd>${o.lockedStake}</dd>
<dt>invited by</dt><dd>${o.inviter === null ? "nobody (founding owner)" : ownerLink(o.inviter)}</dd>
<dt>key</dt><dd>${code(short(o.keyId, 12), o.keyId)}</dd>
</dl>
<h2>Agents</h2>${
    agents.length === 0
      ? h`<p class="note">None.</p>`
      : h`<ul class="plain">${agents.slice(0, MAX_LIST).map((a) => h`<li>${idLink(agentHref(a.keyId), a.keyId)} ${clip(a.modelFamily, CLIP.id)} · harness ${clip(a.harness, CLIP.line)} ${a.active ? badge("ok", "active") : h`${badge("bad", "revoked")} ${clip(a.revokedReason ?? "", CLIP.line)}`}</li>`)}</ul>${more(agents.length)}`
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
<dt>model family</dt><dd>${clip(a.modelFamily, CLIP.id)}</dd>
<dt>harness</dt><dd>${clip(a.harness, CLIP.text)}</dd>
<dt>key id</dt><dd>${code(keyId)}</dd>
${a.active ? "" : h`<dt>revoked</dt><dd>${clip(a.revokedReason ?? "", CLIP.text)}</dd>`}
${honey.length > 0 ? h`<dt>honeytokens</dt><dd>${badge("bad", `${honey.length} triggered`)}</dd>` : ""}
</dl>
${trackRecord(site, [keyId], a.owner)}`;
  return page(site, `agent ${short(keyId)}`, body);
}

// ---------------------------------------------------------------------------
// JSON API
// ---------------------------------------------------------------------------

export const STATE_RECENT = 50;

// Counts and short summaries only: a size bounded by the caps above, not by
// the ledger. Everything else, including every revealed verdict, is in the
// signed entries (/api/entries), which are the record anyway. No sealed
// verdict can appear here because no verdict appears here at all. Outstanding
// plants are not counted: commitments minus reveals would tell reviewers how
// many plants are live.
export function stateJson(site: Site) {
  const { state } = site;
  const subs = [...state.submissions.values()];
  const findings = [...state.findings.values()];
  const snaps = [...state.snapshots.values()];
  const agentCount = agentsByOwner(state);
  const id = (v: string) => clip(v, CLIP.id);
  const owners = [...state.owners.values()].sort((a, b) => b.reputationDelta - a.reputationDelta || cmp(a.id, b.id));
  return {
    project: id(state.project),
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
      plantsRevealed: subs.filter((s) => s.planted).length,
      honeytokens: state.honeytokens.length,
      escapes: state.escapes.length,
      settlements: state.settlements.length,
    },
    // Highest reputation delta first.
    owners: owners.slice(0, MAX_LIST).map((o) => ({
      id: id(o.id),
      page: ownerHref(o.id),
      reputationDelta: o.reputationDelta,
      lockedStake: o.lockedStake,
      agents: agentCount.get(o.id)?.length ?? 0,
    })),
    // Newest first.
    recentSubmissions: subs
      .slice(-STATE_RECENT)
      .reverse()
      .map((s) => ({
        id: id(s.id),
        page: submissionHref(state, s.id),
        author: s.author,
        owner: id(ownerOfAgent(state, s.author) ?? ""),
        status: statusOf(state, s).label,
        planted: s.planted !== undefined, // set only after plantReveal
        submittedSeq: s.submittedSeq,
        files: s.changedFiles.length,
        linesChanged: s.linesChanged,
        gates: { passed: s.gates.filter((g) => g.pass).length, failed: s.gates.filter((g) => !g.pass).length },
        reviews: { committed: s.reviews.length, revealed: s.reviews.filter((r) => r.verdict).length },
        findings: s.findingIds.length,
      })),
    recentSnapshots: snaps
      .slice(-STATE_RECENT)
      .reverse()
      .map((s) => ({
        id: id(s.id),
        page: snapshotHref(state, s.id),
        seq: s.seq,
        commit: id(s.commit),
        submissions: s.submissionIds.length,
        attestations: { committed: s.attestations.length, revealed: s.attestations.filter((a) => a.verdict).length },
        signoffs: s.signoffs.length,
        promoted: s.promoted !== undefined,
      })),
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
const safeJson = (body: string) => body.replace(/</g, "\\u003c");

function toJson(value: unknown): string {
  return safeJson(JSON.stringify(value, (_k, v: unknown) => (v instanceof Map ? Object.fromEntries(v) : v)));
}

function jsonReply(status: number, value: unknown): Reply {
  return reply(status, JSON_TYPE, toJson(value));
}

function htmlError(site: { state: CommonsState; nowIso: string } | null, status: number, message: string): Reply {
  const title = status === 404 ? "not found" : status === 400 ? "bad request" : "error";
  return reply(status, HTML, page(site, title, h`<h1>${title}</h1><p>${message}</p><p><a href="/">back to the overview</a></p>`));
}

// Only a LedgerError's code is public: its message can name the ledger's path.
function unavailableReply(isApi: boolean, e: unknown): Reply {
  const code = e instanceof LedgerError ? e.code : null;
  const message = "The ledger is being written or failed verification; try again shortly.";
  return isApi
    ? jsonReply(503, { error: "ledger unavailable", code })
    : htmlError(null, 503, code === null ? message : `${message} (${code})`);
}

const OBJECT_KINDS: ReadonlySet<string> = new Set<ObjectKind>(["submissions", "snapshots", "owners", "agents"]);

// The id a request names: /<kind>/<id>, or the query fallbacks objectHref
// builds for ids a path cannot carry: ?id=<id>, or ?seq=<seq of the entry that
// created the submission or snapshot>.
function requestedId(site: Site, kind: string, segs: string[], params: URLSearchParams): string | undefined {
  if (segs.length === 2) return segs[1] === "" ? undefined : segs[1];
  const id = params.get("id");
  if (id !== null) return id === "" ? undefined : id;
  const seq = intParam(params.get("seq"), -1);
  if (seq === null || seq < 0) return undefined;
  const body = site.entries[seq]?.body;
  if (kind === "submissions" && body?.kind === "submission") return body.id;
  if (kind === "snapshots" && body?.kind === "snapshot") return body.id;
  return undefined;
}

// The whole site. `load` is called only for routes that need the ledger, so
// the refresh script is served even while the ledger cannot be read.
export function route(load: () => Site, method: string, rawUrl: string, log: (e: unknown) => void = defaultLog): Reply {
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
    const loaded = load();
    site = loaded.log ? loaded : { ...loaded, log };
  } catch (e) {
    log(e);
    return unavailableReply(isApi, e);
  }
  const memo = site.memo ?? (<T,>(_key: string, f: () => T): T => f());
  const notFound = (what: string) => (isApi ? jsonReply(404, { error: what }) : htmlError(site, 404, what));
  const html = (key: string, render: () => string) => reply(200, HTML, memo(key, render));

  const [a = "", b] = segs;
  if (segs.length === 1 && a === "") return html("overview", () => overview(site));
  if (a === "api") return segs.length === 2 && b !== undefined ? api(site, memo, b, url.searchParams) : notFound("No such endpoint.");
  if (OBJECT_KINDS.has(a) && segs.length <= 2) {
    const id = requestedId(site, a, segs, url.searchParams);
    const missing = () => notFound(`No ${a.slice(0, -1)} ${id === undefined ? "named" : clip(id, 80)}.`);
    if (id === undefined) return missing();
    const { state } = site;
    switch (a) {
      case "submissions": {
        const s = state.submissions.get(id);
        return s ? html(`submission:${s.submittedSeq}`, () => submissionPage(site, s)) : missing();
      }
      case "snapshots": {
        const s = state.snapshots.get(id);
        return s ? html(`snapshot:${s.seq}`, () => snapshotPage(site, s)) : missing();
      }
      case "owners":
        return state.owners.has(id) ? html(`owner:${id}`, () => ownerPage(site, id)) : missing();
      case "agents":
        return state.agents.has(id) ? html(`agent:${id}`, () => agentPage(site, id)) : missing();
    }
  }
  return notFound("No such page.");
}

function api(site: Site, memo: <T>(key: string, f: () => T) => T, name: string, params: URLSearchParams): Reply {
  switch (name) {
    case "state":
      return reply(200, JSON_TYPE, memo("api:state", () => toJson(stateJson(site))));
    case "metrics": {
      const body = memo("api:metrics", () => {
        const m = attempt(site, () => site.derive.metrics());
        return m.ok ? toJson({ asOf: site.nowIso, length: site.state.length, rows: m.value }) : null;
      });
      return body === null ? jsonReply(500, { error: "metrics could not be computed" }) : reply(200, JSON_TYPE, body);
    }
    case "entries": {
      const since = intParam(params.get("since"), 0);
      const limit = intParam(params.get("limit"), MAX_ENTRIES_PAGE);
      if (since === null || limit === null || limit < 1) {
        return jsonReply(400, { error: "since and limit must be non-negative integers; limit >= 1" });
      }
      const size = Math.min(limit, MAX_ENTRIES_PAGE);
      return reply(200, JSON_TYPE, memo(`api:entries:${since}:${size}`, () => entriesPage(site, since, size)));
    }
  }
  return jsonReply(404, { error: "No such endpoint." });
}

// Entries are indexed by seq. `since` is inclusive (seq >= since), so a client
// continues with since=next, not with the last seq it saw; the reply says so.
// Serialised by hand so each entry is stringified once while the byte cap is
// counted.
function entriesPage(site: Site, since: number, size: number): string {
  const parts: string[] = [];
  let bytes = 0;
  const end = Math.min(site.entries.length, since + size);
  for (let i = since; i < end; i++) {
    const json = JSON.stringify(site.entries[i]);
    const n = Buffer.byteLength(json);
    if (parts.length > 0 && bytes + n > MAX_ENTRIES_BYTES) break;
    parts.push(json);
    bytes += n + 1;
  }
  const next = since + parts.length < site.entries.length ? since + parts.length : null;
  const head = {
    head: { length: site.state.length, hash: site.state.headHash },
    since,
    limit: size,
    next,
    cursor: "since is inclusive (seq >= since); continue with since=next until next is null",
  };
  return safeJson(`${JSON.stringify(head).slice(0, -1)},"entries":[${parts.join(",")}]}`);
}

function intParam(raw: string | null, fallback: number): number | null {
  if (raw === null || raw === "") return fallback;
  if (!/^\d{1,15}$/.test(raw)) return null;
  return Number(raw);
}
