// The health table. Metrics inform people; nothing reads them to gate, mint
// work or move reputation (ARCHITECTURE.md). Organic counts live here and
// nowhere else (protocol.md §7.4). Pure: the caller passes `nowIso`.
//
// Each row carries `bad` from a threshold stated next to it. A rate with no
// denominator is the string "n/a"; whether that is bad is decided per row (an
// unmeasured recall is bad, an absent promotion lag is not).
//
// Time of entries. CommonsState stores `at` for submissions, merges,
// findings, snapshots, promotions, honeytokens, escapes and settlements (and
// a replayed LedgerState carries the head's time), but only `seq` for
// proposals, claims, reviews and attestations. Since `at` never decreases
// along the chain, an entry is no later than the next entry whose time is
// known; that upper bound stands in for the others. A lower bound would need
// an earlier anchor, and with none (a ledger of proposals only) everything
// would look infinitely old. The cost: "active in the last 7 days" can count
// an agent whose last entry came just before a stretch with no timed entries,
// and "older than 14 days" can miss a proposal in such a stretch.

import { CATCH_THRESHOLD, instantMs, plantStats } from "./plants";
import { isConfirmedDefect } from "./findingStatus";
import { submissionDead } from "./ledger";
import { isFalseFinding } from "./review";
import { firstShipped, seededRecall } from "./risk";
import { submissionRing as ringOfChange } from "./gates/rings";
import type { CommonsState, KeyId, OwnerId, Ring, SubmissionState } from "./types";

export type MetricRow = { group: string; metric: string; value: number | string; bad: boolean; note: string };

const DAY_MS = 86_400_000;
const HOUR_MS = 3_600_000;
const ACTIVE_DAYS = 7;
const STALE_PROPOSAL_DAYS = 14;
const NA = "n/a";

// Thresholds that are not in Rules: they flag, they never decide anything.
const MAX_FALSE_FINDING_RATE = 0.3; // most findings should reproduce; above this the harness is being flooded
const MAX_DEFECTIVE_APPROVAL_RATE = 0.1; // approvals of work a confirmed finding later hit
const MIN_MERGE_RATE = 0.3; // judged once there are this many submissions:
const MIN_SUBMISSIONS_FOR_RATE = 10;
const MAX_HOURS_TO_MERGE = 7 * 24;
const MAX_HOURS_TO_PROMOTION = 14 * 24;
const MAX_OPEN_PER_RING = 20; // a queue reviewers are not keeping up with
const MAX_GINI = 0.6; // one or two owners doing nearly everything; judged from:
const MIN_EVENTS_FOR_GINI = 10;
const MAX_RECIPROCITY = 0.3; // share of a pair's own open reviews that go to each other; judged from:
const MIN_REVIEWS_FOR_RECIPROCITY = 10; // open reviews given by the pair together
const MAX_CONCENTRATION = 0.8; // share of an owner's incoming open reviews from their top two reviewing owners; judged
const MIN_INCOMING_FOR_CONCENTRATION = 10; // per owner, and only once this many owners give open reviews:
const MIN_REVIEWING_OWNERS = 6; // below it, two reviewers per owner is all a small commons has
const MAX_AGENTS_PER_OWNER = 3; // active agents per active owner, on average and for any one owner
const MAX_FAMILIES_PER_OWNER = 2; // model families declared by one owner's unrevoked agents
const MAX_STALE_PROPOSALS = 5;
const MAX_GATE_FAILURE_RATE = 0.5; // a gate failing most runs is broken or being probed; judged from:
const MIN_GATE_RUNS = 10;

const round = (x: number, digits = 3): number => Number(x.toFixed(digits));
const ratio = (num: number, den: number): number | string => (den === 0 ? NA : round(num / den));

export function median(xs: readonly number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 === 1 ? (s[mid] as number) : ((s[mid - 1] as number) + (s[mid] as number)) / 2;
}

// Gini coefficient of non-negative amounts: 0 when equal, approaching 1 when
// one holder has everything. Zeros count: an owner who merged nothing is part
// of the distribution. Fewer than two holders, or nothing held, gives 0.
export function gini(xs: readonly number[]): number {
  const n = xs.length;
  const total = xs.reduce((a, b) => a + b, 0);
  if (n < 2 || total <= 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  let weighted = 0;
  s.forEach((x, i) => (weighted += (i + 1) * x));
  return (2 * weighted) / (n * total) - (n + 1) / n;
}

// Open reviews between owners: revealed reviews the reviewer chose to give,
// i.e. not drawn by the beacon (assigned seats cannot be steered to a friend),
// on organic work (a plant's reviewers did not choose its author, the
// custodian, as a friend; counting them would only dilute a ring). Keyed
// "reviewer\0author".
function openReviewEdges(state: CommonsState): Map<string, number> {
  const edges = new Map<string, number>();
  for (const s of state.submissions.values()) {
    if (s.planted !== undefined) continue;
    const author = state.agents.get(s.author)?.owner;
    const assigned = new Set(s.assignment?.reviewers ?? []);
    for (const r of s.reviews) {
      const reviewer = state.agents.get(r.reviewer)?.owner;
      if (r.verdict === undefined || assigned.has(r.reviewer)) continue;
      if (author === undefined || reviewer === undefined || reviewer === author) continue;
      const key = `${reviewer}\0${author}`;
      edges.set(key, (edges.get(key) ?? 0) + 1);
    }
  }
  return edges;
}

const byKey = <T>([a]: [string, T], [b]: [string, T]) => (a < b ? -1 : a > b ? 1 : 0);

// The most reciprocal owner pair: of the open reviews a and b gave in total,
// the share they gave each other, counting only the reciprocated part
// 2·min(a→b, b→a). Normalised by the pair's own reviews, not the commons', so
// a pair that reviews only each other scores 1 however large the commons is;
// one owner reviewing another a lot is just a busy reviewer and scores 0.
// Pairs that gave fewer than `minReviews` together are only reported when no
// pair has that many.
export function reciprocity(
  state: CommonsState,
  minReviews = MIN_REVIEWS_FOR_RECIPROCITY,
): { share: number; mutual: number; given: number; pair: [OwnerId, OwnerId] | null } {
  const edges = openReviewEdges(state);
  const given = new Map<OwnerId, number>();
  for (const [key, n] of edges) {
    const reviewer = key.split("\0")[0] as OwnerId;
    given.set(reviewer, (given.get(reviewer) ?? 0) + n);
  }
  let best = { share: 0, mutual: 0, given: 0, pair: null as [OwnerId, OwnerId] | null, judged: false };
  for (const [key, n] of [...edges].sort(byKey)) {
    const [a, b] = key.split("\0") as [OwnerId, OwnerId];
    if (!(a < b)) continue; // each unordered pair once
    const mutual = 2 * Math.min(n, edges.get(`${b}\0${a}`) ?? 0);
    if (mutual === 0) continue;
    const pairGiven = (given.get(a) ?? 0) + (given.get(b) ?? 0);
    const share = mutual / pairGiven;
    const judged = pairGiven >= minReviews;
    if ((judged && !best.judged) || (judged === best.judged && share > best.share)) {
      best = { share, mutual, given: pairGiven, pair: [a, b], judged };
    }
  }
  return { share: best.share, mutual: best.mutual, given: best.given, pair: best.pair };
}

// Rings larger than a pair: an owner whose incoming open reviews nearly all
// come from the same two owners, as in a 4-owner ring or a 5-owner round robin
// where nobody reviews back directly. Owners with fewer than `minIncoming`
// incoming open reviews are not judged.
export function reviewConcentration(
  state: CommonsState,
  minIncoming = MIN_INCOMING_FOR_CONCENTRATION,
): { share: number; owner: OwnerId | null; top: OwnerId[]; incoming: number; reviewingOwners: number } {
  const edges = openReviewEdges(state);
  const incoming = new Map<OwnerId, Map<OwnerId, number>>();
  const reviewingOwners = new Set<OwnerId>();
  for (const [key, n] of edges) {
    const [reviewer, author] = key.split("\0") as [OwnerId, OwnerId];
    reviewingOwners.add(reviewer);
    const m = incoming.get(author) ?? new Map<OwnerId, number>();
    m.set(reviewer, (m.get(reviewer) ?? 0) + n);
    incoming.set(author, m);
  }
  let best = { share: 0, owner: null as OwnerId | null, top: [] as OwnerId[], incoming: 0 };
  for (const [owner, from] of [...incoming].sort(byKey)) {
    const total = [...from.values()].reduce((a, b) => a + b, 0);
    if (total < minIncoming) continue;
    const ranked = [...from].sort(([a, x], [b, y]) => y - x || (a < b ? -1 : 1)).slice(0, 2);
    const share = ranked.reduce((a, [, n]) => a + n, 0) / total;
    if (share > best.share) best = { share, owner, top: ranked.map(([o]) => o), incoming: total };
  }
  return { ...best, reviewingOwners: reviewingOwners.size };
}

// Upper bound on the time of any seq, from the entries whose time the state
// keeps; `fallback` (the caller's now) past the last of them.
function seqTimes(state: CommonsState, fallback: number): (seq: number) => number {
  const anchors: [number, string][] = [];
  for (const s of state.submissions.values()) {
    anchors.push([s.submittedSeq, s.submittedAt]);
    if (s.merged) anchors.push([s.merged.seq, s.merged.at]);
  }
  for (const f of state.findings.values()) anchors.push([f.seq, f.at]);
  for (const s of state.snapshots.values()) {
    anchors.push([s.seq, s.at]);
    if (s.promoted) anchors.push([s.promoted.seq, s.promoted.at]);
  }
  for (const x of [...state.honeytokens, ...state.escapes, ...state.settlements]) anchors.push([x.seq, x.at]);
  const headAt = (state as { headAt?: unknown }).headAt;
  if (typeof headAt === "string") anchors.push([state.length - 1, headAt]);
  const sorted = anchors.map(([seq, at]) => [seq, instantMs(at)] as const).filter(([, ms]) => !Number.isNaN(ms));
  sorted.sort((a, b) => a[0] - b[0]);
  // Running minimum from the end, so one bad timestamp cannot push earlier bounds forwards.
  const seqs = sorted.map(([seq]) => seq);
  const bound: number[] = new Array<number>(sorted.length);
  for (let i = sorted.length - 1; i >= 0; i--) {
    bound[i] = Math.min((sorted[i] as readonly [number, number])[1], bound[i + 1] ?? fallback);
  }
  return (seq) => {
    let lo = 0;
    let hi = seqs.length; // first index with seqs[i] >= seq
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if ((seqs[mid] as number) < seq) lo = mid + 1;
      else hi = mid;
    }
    return bound[lo] ?? fallback;
  };
}

function submissionRing(s: SubmissionState, state: CommonsState): Ring {
  return ringOfChange(s.changedFiles, state.rules);
}

// Dead submissions can never merge (ledger.submissionDead): a failed gate
// (a later passing run does not erase it), a confirmed defect, or a revealed plant.
function isDead(state: CommonsState, s: SubmissionState): boolean {
  return !s.merged && submissionDead(state, s.id);
}


export function computeMetrics(state: CommonsState, nowIso: string): MetricRow[] {
  const now = instantMs(nowIso);
  if (Number.isNaN(now)) throw new RangeError(`invalid nowIso (need an ISO date-time with Z or ±HH:MM): ${nowIso}`);
  const rules = state.rules;
  const rows: MetricRow[] = [];
  const row = (group: string, metric: string, value: number | string, bad: boolean, note: string) =>
    rows.push({ group, metric, value, bad, note });
  const ownerOf = (k: KeyId): OwnerId | undefined => state.agents.get(k)?.owner;
  // Owners who can merge or review at all; kernel signers, the custodian and
  // fresh invitees without agents would add structural zeros to a Gini.
  const workers = [...new Set([...state.agents.values()].map((a) => a.owner))].sort();
  const subs = [...state.submissions.values()];
  // Revealed plants are the custodian's, not organic work; they stay out of
  // flow and trust counts. Unrevealed plants cannot be told apart and stay in.
  const organic = subs.filter((s) => s.planted === undefined);
  const timeOf = seqTimes(state, now);

  // --- reviewer quality ---------------------------------------------------
  const q = "reviewer quality";
  const since = new Date(now - rules.promotion.recallWindowDays * DAY_MS).toISOString();
  const plants = plantStats(state, since);
  const recall = seededRecall(state, since);
  // Bad below the promotion floor on recall's lower bound; unmeasured is bad.
  row(
    q,
    "plant catch rate",
    ratio(plants.caught, plants.seeds),
    plants.seeds === 0 || recall.lower90 < rules.promotion.minRecallLowerBound90,
    plants.seeds === 0
      ? `no revealed plants since ${since}: recall unmeasured`
      : `${plants.caught}/${plants.seeds} since ${since}; 90% lower bound ${round(recall.lower90)} (promotion needs ${rules.promotion.minRecallLowerBound90})`,
  );
  // Bad when a family's point estimate is below the same floor.
  for (const [family, t] of [...plants.byFamily].sort(([a], [b]) => (a < b ? -1 : 1))) {
    row(
      q,
      `plant catch rate (${family})`,
      ratio(t.caught, t.seen),
      t.caught / t.seen < rules.promotion.minRecallLowerBound90,
      `${t.caught}/${t.seen} plants seen by a ${family} agent were caught by one`,
    );
  }
  // A harness error judged nothing, so it is in neither count.
  const judged = [...state.findings.values()].filter((f) => f.result !== undefined && f.result.harnessError === undefined);
  const falseFindings = judged.filter(isFalseFinding).length;
  row(
    q,
    "false-finding rate",
    ratio(falseFindings, judged.length),
    judged.length > 0 && falseFindings / judged.length > MAX_FALSE_FINDING_RATE,
    `${falseFindings}/${judged.length} judged findings did not reproduce (bad above ${MAX_FALSE_FINDING_RATE})`,
  );
  // An approval is a revealed p below the catch threshold on organic work that
  // merged. It was defective if a confirmed finding hit that work, directly
  // or through the snapshot listing it (a snapshot finding is about that
  // snapshot's own diff; it cannot say which submission, so all are hit).
  // Escapes need a reproduced finding, so they are already among these.
  const hitSnapshots = new Set<string>();
  for (const f of state.findings.values()) {
    if (isConfirmedDefect(f) && "snapshotId" in f.target) hitSnapshots.add(f.target.snapshotId);
  }
  const hitViaSnapshot = new Set<string>();
  for (const snap of state.snapshots.values()) {
    if (hitSnapshots.has(snap.id)) for (const id of snap.submissionIds) hitViaSnapshot.add(id);
  }
  let approvals = 0;
  let defective = 0;
  for (const s of organic) {
    if (!s.merged) continue;
    const hit =
      hitViaSnapshot.has(s.id) ||
      s.findingIds.some((id) => {
        const f = state.findings.get(id);
        return f !== undefined && isConfirmedDefect(f);
      });
    for (const r of s.reviews) {
      if (r.verdict === undefined || r.verdict.defectProbability >= CATCH_THRESHOLD) continue;
      approvals += 1;
      if (hit) defective += 1;
    }
  }
  row(
    q,
    "approvals later found defective",
    ratio(defective, approvals),
    approvals > 0 && defective / approvals > MAX_DEFECTIVE_APPROVAL_RATE,
    `${defective}/${approvals} approvals of merged work were followed by a confirmed finding on it or its snapshot (bad above ${MAX_DEFECTIVE_APPROVAL_RATE})`,
  );

  // --- flow ---------------------------------------------------------------
  const fl = "flow";
  const merged = organic.filter((s) => s.merged !== undefined);
  row(fl, "proposals", state.proposals.size, false, "");
  row(fl, "tasks", state.tasks.size, false, "");
  row(fl, "submissions", organic.length, false, "excluding revealed plants");
  row(fl, "merged", merged.length, false, "");
  row(
    fl,
    "merge rate",
    ratio(merged.length, organic.length),
    organic.length >= MIN_SUBMISSIONS_FOR_RATE && merged.length / organic.length < MIN_MERGE_RATE,
    `bad below ${MIN_MERGE_RATE} once there are ${MIN_SUBMISSIONS_FOR_RATE} submissions`,
  );
  const toMerge = merged.map((s) => (instantMs(s.merged?.at ?? "") - instantMs(s.submittedAt)) / HOUR_MS);
  const mergeHours = median(toMerge.filter((h) => Number.isFinite(h)));
  row(
    fl,
    "median hours submission→merge",
    mergeHours === null ? NA : round(mergeHours, 1),
    mergeHours !== null && mergeHours > MAX_HOURS_TO_MERGE,
    `over ${merged.length} merges (bad above ${MAX_HOURS_TO_MERGE}h)`,
  );
  const shipped = firstShipped(state);
  const toPromotion: number[] = [];
  for (const snap of state.snapshots.values()) {
    const first = shipped.get(snap.id);
    if (first === undefined) continue;
    const at = instantMs(first.at);
    for (const id of snap.submissionIds) {
      const m = state.submissions.get(id)?.merged;
      const h = m ? (at - instantMs(m.at)) / HOUR_MS : Number.NaN;
      if (Number.isFinite(h)) toPromotion.push(h);
    }
  }
  const promoHours = median(toPromotion);
  row(
    fl,
    "median hours merge→promotion",
    promoHours === null ? NA : round(promoHours, 1),
    promoHours !== null && promoHours > MAX_HOURS_TO_PROMOTION,
    `over ${toPromotion.length} shipped submissions (bad above ${MAX_HOURS_TO_PROMOTION}h)`,
  );
  const open: Record<Ring, number> = { 0: 0, 1: 0, 2: 0 };
  for (const s of organic) if (!s.merged && !isDead(state, s)) open[submissionRing(s, state)] += 1;
  for (const r of [0, 1, 2] as const) {
    row(
      fl,
      `open submissions (ring ${r})`,
      open[r],
      open[r] > MAX_OPEN_PER_RING,
      `not merged and not dead (bad above ${MAX_OPEN_PER_RING})`,
    );
  }

  // --- trust --------------------------------------------------------------
  const tr = "trust";
  const locked = [...state.owners.values()].reduce((a, o) => a + o.lockedStake, 0);
  const slashed = state.settlements.reduce((a, s) => a + (s.delta < 0 ? -s.delta : 0), 0);
  const paid = state.settlements.reduce((a, s) => a + (s.delta > 0 ? s.delta : 0), 0);
  row(
    tr,
    "reputation staked (locked)",
    locked,
    false,
    "points locked in open claims, reviews, attestations and findings",
  );
  // Bad when the commons takes more than it pays: participating is then a losing bet.
  row(tr, "reputation slashed", slashed, slashed > paid, `sum of negative settlements; ${paid} paid out`);
  const mergesBy = new Map<OwnerId, number>(workers.map((o) => [o, 0]));
  for (const s of merged) {
    const o = ownerOf(s.author);
    if (o !== undefined) mergesBy.set(o, (mergesBy.get(o) ?? 0) + 1);
  }
  const revealsBy = new Map<OwnerId, number>(workers.map((o) => [o, 0]));
  let reveals = 0;
  for (const s of organic) {
    for (const r of s.reviews) {
      const o = ownerOf(r.reviewer);
      if (r.verdict === undefined || o === undefined) continue;
      reveals += 1;
      revealsBy.set(o, (revealsBy.get(o) ?? 0) + 1);
    }
  }
  for (const [metric, by, n] of [
    ["Gini of merges across owners", mergesBy, merged.length],
    ["Gini of review reveals across owners", revealsBy, reveals],
  ] as const) {
    const g = round(gini([...by.values()]));
    row(
      tr,
      metric,
      g,
      n >= MIN_EVENTS_FOR_GINI && g > MAX_GINI,
      `over the ${by.size} owners with an agent, ${n} events (bad above ${MAX_GINI} from ${MIN_EVENTS_FOR_GINI} events)`,
    );
  }
  const rec = reciprocity(state);
  row(
    tr,
    "reciprocity",
    round(rec.share),
    rec.given >= MIN_REVIEWS_FOR_RECIPROCITY && rec.share > MAX_RECIPROCITY,
    rec.pair === null
      ? "no owner pair gave each other open reviews"
      : `${rec.pair[0]} ↔ ${rec.pair[1]}: ${rec.mutual} of the ${rec.given} open reviews they gave went to each other (bad above ${MAX_RECIPROCITY} from ${MIN_REVIEWS_FOR_RECIPROCITY} reviews)`,
  );
  const conc = reviewConcentration(state);
  const judgedConc = conc.reviewingOwners >= MIN_REVIEWING_OWNERS;
  row(
    tr,
    "open-review concentration",
    conc.owner === null ? NA : round(conc.share),
    judgedConc && conc.share > MAX_CONCENTRATION,
    (conc.owner === null
      ? `no owner has ${MIN_INCOMING_FOR_CONCENTRATION} incoming open reviews`
      : `${round(conc.share)} of the ${conc.incoming} open reviews of ${conc.owner}'s work came from ${conc.top.join(" and ")}`) +
      ` (bad above ${MAX_CONCENTRATION} once ${MIN_REVIEWING_OWNERS} owners give open reviews; ${conc.reviewingOwners} do)`,
  );

  // --- cost & liveness ----------------------------------------------------
  const cl = "cost & liveness";
  const activeSince = now - ACTIVE_DAYS * DAY_MS;
  const actedAt = new Map<KeyId, number>(); // latest known lower-bound time per signer key
  const acted = (k: KeyId, t: number) => actedAt.set(k, Math.max(actedAt.get(k) ?? Number.NEGATIVE_INFINITY, t));
  for (const p of state.proposals.values()) acted(p.by, timeOf(p.seq));
  for (const c of state.claims.values()) acted(c.agent, timeOf(c.seq));
  for (const s of subs) {
    acted(s.author, instantMs(s.submittedAt));
    for (const r of s.reviews) acted(r.reviewer, timeOf(r.revealedSeq ?? r.committedSeq));
  }
  for (const snap of state.snapshots.values()) {
    for (const a of snap.attestations) acted(a.reviewer, timeOf(a.revealedSeq ?? a.committedSeq));
  }
  for (const f of state.findings.values()) acted(f.finder, instantMs(f.at));
  const recent = (k: KeyId) => (actedAt.get(k) ?? Number.NEGATIVE_INFINITY) >= activeSince;
  const activeAgents = [...state.agents.values()].filter((a) => a.active && recent(a.keyId));
  const activeOwners = new Set<OwnerId>(activeAgents.map((a) => a.owner));
  for (const o of state.owners.values()) if (recent(o.keyId)) activeOwners.add(o.id);
  row(
    cl,
    "active agents",
    activeAgents.length,
    activeAgents.length === 0,
    `signed an entry in the last ${ACTIVE_DAYS} days`,
  );
  // A full review panel needs assignedReviewers owners besides the author's.
  row(
    cl,
    "active owners",
    activeOwners.size,
    activeOwners.size < rules.assignedReviewers + 1,
    `bad below ${rules.assignedReviewers + 1}: fewer cannot staff a full review panel`,
  );
  row(
    cl,
    "agents per owner",
    ratio(activeAgents.length, activeOwners.size),
    activeOwners.size > 0 && activeAgents.length / activeOwners.size > MAX_AGENTS_PER_OWNER,
    `active agents per active owner (bad above ${MAX_AGENTS_PER_OWNER})`,
  );
  // The mean hides one owner with many agents. Coverage counts model families,
  // and a family is the owner's own claim at registration.
  const agentsOf = new Map<OwnerId, number>();
  for (const a of activeAgents) agentsOf.set(a.owner, (agentsOf.get(a.owner) ?? 0) + 1);
  const familiesOf = new Map<OwnerId, Set<string>>();
  for (const a of state.agents.values()) {
    if (!a.active) continue;
    const f = familiesOf.get(a.owner) ?? new Set<string>();
    f.add(a.modelFamily);
    familiesOf.set(a.owner, f);
  }
  const maxOf = <T>(m: Map<OwnerId, T>, size: (x: T) => number): [OwnerId | null, number] =>
    [...m].sort(byKey).reduce<[OwnerId | null, number]>((b, [o, x]) => (size(x) > b[1] ? [o, size(x)] : b), [null, 0]);
  const [busiest, most] = maxOf(agentsOf, (n) => n);
  row(
    cl,
    "most active agents of one owner",
    most,
    most > MAX_AGENTS_PER_OWNER,
    `${busiest ?? "nobody"} (bad above ${MAX_AGENTS_PER_OWNER})`,
  );
  const [widest, families] = maxOf(familiesOf, (f) => f.size);
  row(
    cl,
    "most model families of one owner",
    families,
    families > MAX_FAMILIES_PER_OWNER,
    `${widest ?? "nobody"}, over unrevoked agents (bad above ${MAX_FAMILIES_PER_OWNER})`,
  );

  // --- direction ----------------------------------------------------------
  const tasked = new Set([...state.tasks.values()].map((t) => t.proposalId));
  const staleBefore = now - STALE_PROPOSAL_DAYS * DAY_MS;
  const stale = [...state.proposals.values()].filter((p) => !tasked.has(p.id) && timeOf(p.seq) <= staleBefore);
  row(
    "direction",
    `open proposals older than ${STALE_PROPOSAL_DAYS} days`,
    stale.length,
    stale.length > MAX_STALE_PROPOSALS,
    `no task yet (bad above ${MAX_STALE_PROPOSALS})`,
  );

  // --- safety -------------------------------------------------------------
  const sa = "safety";
  // Windowed like reviewer quality, so one old event does not mark the table bad for ever.
  const inWindow = (at: string) => instantMs(at) >= now - rules.promotion.recallWindowDays * DAY_MS;
  for (const [metric, events, what] of [
    ["honeytoken triggers", state.honeytokens, "agents that obeyed a decoy instruction"],
    ["escapes", state.escapes, "reproduced defects found in main"],
  ] as const) {
    const recentN = events.filter((e) => inWindow(e.at)).length;
    row(sa, metric, recentN, recentN > 0, `${what} since ${since}; ${events.length} all time (bad above 0)`);
  }
  const gates = new Map<string, { runs: number; failed: number }>();
  for (const s of subs) {
    for (const g of s.gates) {
      const t = gates.get(g.gate) ?? { runs: 0, failed: 0 };
      t.runs += 1;
      if (!g.pass) t.failed += 1;
      gates.set(g.gate, t);
    }
  }
  if (gates.size === 0) row(sa, "failed gates", 0, false, "no gate results yet");
  for (const [gate, t] of [...gates].sort(([a], [b]) => (a < b ? -1 : 1))) {
    row(
      sa,
      `failed gates (${gate})`,
      t.failed,
      t.runs >= MIN_GATE_RUNS && t.failed / t.runs > MAX_GATE_FAILURE_RATE,
      `${t.failed}/${t.runs} runs failed (bad above ${MAX_GATE_FAILURE_RATE} from ${MIN_GATE_RUNS} runs)`,
    );
  }
  return rows;
}
