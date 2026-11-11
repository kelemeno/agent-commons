// The Anthill tree as the commons sees it: who is a member, who is whose parent,
// how far apart two owners are, and their Anthill reputation in points.
//
// Every TreeView is a frozen copy taken at construction. Later changes to the
// engine or the input objects are not reflected, so one selection or settlement
// run sees one consistent tree.
//
// Order is canonical: members() and children() are sorted by id, so the same tree
// read from a parent map, a snapshot file or a live engine yields the same view.
// Reviewer selection iterates these lists, and its result must not depend on
// where the tree came from.
//
// Structural queries (parent, children, depth, distance) throw NotAMemberError
// on an id that is not a member. Returning a default there would be dangerous: a
// made-up distance for an outsider could make them look far enough away to
// review. Callers check has() first and treat a non-member as ineligible for
// review and for tree-derived credit. Only reputation() defaults (to 0), as the
// contract says.
//
// Ids: views read from Anthill (treeFromSnapshot, treeFromEngine) hold addresses,
// which are case-insensitive hex. They are stored lowercase, as the engine stores
// them, and every query lowercases its argument, so a checksummed (EIP-55)
// address is the same member and cannot pose as a distant stranger. members()
// and children() return the lowercase form. treeFromParents takes ids exactly as
// given: its ids are arbitrary strings, and folding them would rename members.
//
// Reputation is never taken from a source's say-so. Both Anthill readers compute
// it from the DAG votes with the engine's formula; treeFromParents takes it from
// its (trusted, test or tool) caller. It is a non-negative safe integer number
// of points: downstream maths (PR slots, weights) would turn an Infinity or a
// negative into unlimited slots or NaN.

import type { OwnerId, TreeView } from "./types";

// The Anthill contract's virtual node above the root (the root's sentTreeVote).
export const VIRTUAL_ROOT = "0x0000000000000000000000000000000000000001";
// sentTreeVote of an address that is not in the tree.
const NOT_IN_TREE = "0x0000000000000000000000000000000000000000";
// The engine's placeholder during a tree move; never a member between calls
// (AnthillEngine.members() leaves it out).
export const TEMP_ADDRESS = "0x0000000000000000000000000000000099999999";
// The engine's locality bound: a DAG vote reaches at most this many levels up.
const MAX_REL_ROOT_DEPTH = 6;

const ONE_POINT = 10n ** 18n; // Anthill reputation has 18 decimals

// Thrown by structural queries on an id that is not in the tree, so callers can
// tell "this owner is an outsider" from "this tree is corrupt" (a plain Error).
export class NotAMemberError extends Error {
  constructor(readonly id: string) {
    super(`tree: unknown member ${id}`);
    this.name = "NotAMemberError";
  }
}

function canonicalAddress(id: string): OwnerId {
  return id.toLowerCase();
}

// Floor division of an 18-decimal reputation into whole points. Anthill
// reputation is a uint, so a negative value, or one too large to count exactly
// as a number, can only come from a corrupt or forged source.
export function reputationPoints(value: bigint): number {
  if (value < 0n) throw new Error("tree: reputation out of range (negative)");
  const points = value / ONE_POINT;
  if (points > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("tree: reputation out of range (too large)");
  return Number(points);
}

function compareIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// A validated parent map with depth precomputed, so distance() costs O(depth).
type Structure = {
  root: OwnerId;
  parents: Map<OwnerId, OwnerId | null>;
  children: Map<OwnerId, OwnerId[]>; // sorted
  depth: Map<OwnerId, number>;
};

function buildStructure(parents: Map<OwnerId, OwnerId | null>): Structure {
  const roots: OwnerId[] = [];
  const children = new Map<OwnerId, OwnerId[]>();
  for (const id of parents.keys()) children.set(id, []);
  for (const [id, parent] of parents) {
    if (parent === null) {
      roots.push(id);
      continue;
    }
    if (parent === id) throw new Error(`tree: ${id} is its own parent (cycle)`);
    const siblings = children.get(parent);
    if (siblings === undefined) throw new Error(`tree: parent ${parent} of ${id} is not a member`);
    siblings.push(id);
  }
  if (roots.length === 0) {
    throw new Error(parents.size === 0 ? "tree: no members" : "tree: no root (every member has a parent, so there is a cycle)");
  }
  if (roots.length > 1) throw new Error(`tree: more than one root: ${roots.sort(compareIds).join(", ")}`);
  const root = roots[0] as OwnerId;
  for (const list of children.values()) list.sort(compareIds);

  // Walking down from the root reaches exactly the members not on a cycle: with
  // every parent known and one root, an unreached member's ancestry never ends.
  const depth = new Map<OwnerId, number>([[root, 0]]);
  const queue: OwnerId[] = [root];
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i] as OwnerId;
    const d = depth.get(id) as number;
    for (const child of children.get(id) ?? []) {
      depth.set(child, d + 1);
      queue.push(child);
    }
  }
  if (depth.size !== parents.size) {
    const stuck = [...parents.keys()].filter((id) => !depth.has(id)).sort(compareIds);
    throw new Error(`tree: cycle: ${stuck.join(", ")} cannot reach the root ${root}`);
  }
  return { root, parents, children, depth };
}

// Both ids must be members.
function ancestor(s: Structure, id: OwnerId, steps: number): OwnerId {
  let x = id;
  for (let i = 0; i < steps; i++) x = s.parents.get(x) as OwnerId;
  return x;
}

function distanceIn(s: Structure, a: OwnerId, b: OwnerId): number {
  const da = s.depth.get(a) as number;
  const db = s.depth.get(b) as number;
  let x = ancestor(s, a, Math.max(0, da - db));
  let y = ancestor(s, b, Math.max(0, db - da));
  let edges = Math.abs(da - db);
  while (x !== y) {
    x = s.parents.get(x) as OwnerId;
    y = s.parents.get(y) as OwnerId;
    edges += 2;
  }
  return edges;
}

function makeView(s: Structure, reputation: Map<OwnerId, number>, canon: (id: string) => OwnerId): TreeView {
  const members = [...s.parents.keys()].sort(compareIds);
  const member = (raw: OwnerId): OwnerId => {
    const id = canon(raw);
    if (!s.parents.has(id)) throw new NotAMemberError(raw);
    return id;
  };
  return {
    root: () => s.root,
    has: (id) => s.parents.has(canon(id)),
    parent: (id) => s.parents.get(member(id)) ?? null,
    children: (id) => [...(s.children.get(member(id)) ?? [])],
    depth: (id) => s.depth.get(member(id)) as number,
    distance: (a, b) => distanceIn(s, member(a), member(b)),
    members: () => [...members],
    reputation: (id) => reputation.get(canon(id)) ?? 0,
  };
}

// One sent DAG vote, as the reputation formula needs it.
type DagVote = { to: OwnerId; weight: bigint };

// Anthill reputation for every member, in points:
//   rep(v) = 1e18 + Σ floor(rep(u) · w / totalWeight(u)) over votes u → v,
// the formula of AnthillEngine.calculateReputation and of the crawler that wrote
// anthillSnapshot.json. totalWeight(u) is the sum of u's sent weights, which the
// engine maintains as an invariant (and treeFromSnapshot checks).
//
// Every vote must point strictly up the tree (the engine only accepts those), so
// visiting members deepest first finalises each voter before it is used: one
// pass, linear in the number of votes. The engine's own recursion revisits a
// voter once per vote path, which is exponential in chain length; a few dozen
// sybils voting up a chain would stall anyone calling it once per member.
function computeReputation(s: Structure, sent: Map<OwnerId, DagVote[]>): Map<OwnerId, number> {
  const raw = new Map<OwnerId, bigint>();
  for (const id of s.parents.keys()) raw.set(id, ONE_POINT);
  for (const [from, votes] of sent) {
    if (!s.parents.has(from)) throw new Error(`tree: DAG votes from ${from}, which is not a member`);
    for (const { to, weight } of votes) {
      if (!s.parents.has(to)) throw new Error(`tree: DAG vote ${from} -> ${to} names a non-member`);
      if ((s.depth.get(to) as number) >= (s.depth.get(from) as number)) {
        throw new Error(`tree: DAG vote ${from} -> ${to} does not point up the tree`);
      }
      if (weight < 0n) throw new Error(`tree: DAG vote ${from} -> ${to} has a negative weight`);
    }
  }
  const order = [...s.parents.keys()].sort((a, b) => (s.depth.get(b) as number) - (s.depth.get(a) as number));
  for (const from of order) {
    const votes = sent.get(from) ?? [];
    if (votes.length === 0) continue;
    const total = votes.reduce((sum, v) => sum + v.weight, 0n);
    if (total === 0n) throw new Error(`tree: DAG votes of ${from} have zero total weight`);
    const rep = raw.get(from) as bigint;
    for (const { to, weight } of votes) raw.set(to, (raw.get(to) as bigint) + (rep * weight) / total);
  }
  const points = new Map<OwnerId, number>();
  for (const [id, value] of raw) points.set(id, reputationPoints(value));
  return points;
}

// For tests and tools. `null` marks the root. Ids are taken exactly as given.
// Reputation is in points and may only be given for members.
export function treeFromParents(
  parents: Record<OwnerId, OwnerId | null>,
  reputation: Record<OwnerId, number> = {},
): TreeView {
  const parentMap = new Map<OwnerId, OwnerId | null>();
  for (const [id, parent] of Object.entries(parents)) {
    if (parent !== null && typeof parent !== "string") throw new Error(`tree: parent of ${id} must be a string or null`);
    parentMap.set(id, parent);
  }
  const s = buildStructure(parentMap);
  const repMap = new Map<OwnerId, number>();
  for (const [id, points] of Object.entries(reputation)) {
    if (typeof points !== "number" || !Number.isSafeInteger(points) || points < 0) {
      throw new Error(`tree: reputation of ${id} must be a non-negative safe integer`);
    }
    if (!parentMap.has(id)) throw new Error(`tree: reputation given for ${id}, which is not a member`);
    repMap.set(id, points);
  }
  return makeView(s, repMap, (id) => id);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Accepts the file's {__bigint__: "..."} encoding, an already revived bigint,
// or a plain decimal string.
function snapshotBigint(value: unknown, where: string): bigint {
  const raw = isRecord(value) ? value["__bigint__"] : value;
  if (typeof raw === "bigint") return raw;
  if (typeof raw === "string" && /^\d+$/.test(raw)) return BigInt(raw);
  throw new Error(`tree: snapshot ${where} is not a bigint`);
}

type SnapshotVote = { id: OwnerId; weight: bigint; dist: number; posInOther: number };

function snapshotVotes(node: Record<string, unknown>, field: string, id: OwnerId): SnapshotVote[] {
  const list = node[field];
  if (!Array.isArray(list)) throw new Error(`tree: snapshot node ${id} has no ${field}`);
  return list.map((v: unknown, pos) => {
    const where = `${field}[${pos}] of ${id}`;
    if (!isRecord(v) || typeof v["id"] !== "string") throw new Error(`tree: snapshot ${where} is malformed`);
    const dist = v["dist"];
    const posInOther = v["posInOther"];
    if (!Number.isSafeInteger(dist) || !Number.isSafeInteger(posInOther)) {
      throw new Error(`tree: snapshot ${where} has malformed dist or posInOther`);
    }
    return {
      id: canonicalAddress(v["id"]),
      weight: snapshotBigint(v["weight"], `weight in ${where}`),
      dist: dist as number,
      posInOther: posInOther as number,
    };
  });
}

// The engine's sent-side dist of a vote from → to, or undefined if the engine
// would not hold that vote: `to` must be strictly higher and lie under from's
// relative root (MAX_REL_ROOT_DEPTH up, or the root). Mirrors
// AnthillEngine.findDistancesRecNotLower, which loadFromGraph checks.
function localUpwardDist(s: Structure, from: OwnerId, to: OwnerId): number | undefined {
  const df = s.depth.get(from) as number;
  const dt = s.depth.get(to) as number;
  const rel = df - dt;
  const reach = Math.min(MAX_REL_ROOT_DEPTH, df);
  if (rel <= 0 || rel > reach) return undefined;
  if (ancestor(s, to, reach - rel) !== ancestor(s, from, reach)) return undefined;
  return distanceIn(s, ancestor(s, from, rel), to) / 2 + rel;
}

// Reads anthillSnapshot.json: either its text or the parsed object (with or
// without the {__bigint__} values revived). Accepts only snapshots that
// AnthillEngine.loadFromGraph would load into the same tree, so a peer reading
// the file here and one loading it into an engine see the same view:
// - the virtual node is present, points at itself and lists exactly rootId;
// - every sentTreeVote has its recTreeVotes twin, and vice versa;
// - an address that is not in the tree (sentTreeVote 0x0) has no children and
//   no DAG votes;
// - every DAG vote is linked both ways (posInOther), with equal weights, is
//   local and points up, and carries the engine's dist; totalWeight is the sum
//   of the node's sent weights.
// Reputation is computed from the DAG votes. The cached `currentRep` and
// `reputation` fields are ignored: anyone who can edit the file could set them.
export function treeFromSnapshot(json: unknown): TreeView {
  const doc: unknown = typeof json === "string" ? JSON.parse(json) : json;
  const graph = isRecord(doc) ? doc["graph"] : undefined;
  if (!isRecord(graph) || typeof graph["rootId"] !== "string" || !isRecord(graph["dict"])) {
    throw new Error("tree: snapshot must look like {graph: {rootId, dict}}");
  }
  const rootId = canonicalAddress(graph["rootId"]);
  if (rootId === VIRTUAL_ROOT) throw new Error("tree: snapshot rootId is the virtual node");

  type Node = { listed: OwnerId[]; sent: SnapshotVote[]; rec: SnapshotVote[]; totalWeight: bigint };
  const parents = new Map<OwnerId, OwnerId | null>();
  const nodes = new Map<OwnerId, Node>();
  let virtualChildren: OwnerId[] | undefined;
  const seen = new Set<OwnerId>();
  for (const [key, node] of Object.entries(graph["dict"])) {
    if (!isRecord(node) || typeof node["sentTreeVote"] !== "string") {
      throw new Error(`tree: snapshot node ${key} has no sentTreeVote`);
    }
    const id = canonicalAddress(typeof node["id"] === "string" ? node["id"] : key);
    const sentTree = canonicalAddress(node["sentTreeVote"]);
    if (seen.has(id)) throw new Error(`tree: snapshot lists ${id} twice`);
    seen.add(id);
    const rawRec = node["recTreeVotes"];
    if (!Array.isArray(rawRec) || !rawRec.every((c): c is string => typeof c === "string")) {
      throw new Error(`tree: snapshot node ${id} has missing or malformed recTreeVotes`);
    }
    const listed = rawRec.map(canonicalAddress);

    // loadFromGraph reads only the virtual node's child list.
    if (id === VIRTUAL_ROOT) {
      if (sentTree !== VIRTUAL_ROOT) throw new Error("tree: snapshot virtual node does not point at itself");
      virtualChildren = listed;
      continue;
    }
    const sent = snapshotVotes(node, "sentDagVotes", id);
    const rec = snapshotVotes(node, "recDagVotes", id);
    const totalWeight = snapshotBigint(node["totalWeight"], `totalWeight of ${id}`);
    if (sentTree === NOT_IN_TREE) {
      // The engine still loads these lists; on a non-member they are hidden edges.
      if (listed.length > 0) throw new Error(`tree: snapshot node ${id} is not in the tree but lists children`);
      if (sent.length > 0 || rec.length > 0) throw new Error(`tree: snapshot node ${id} is not in the tree but has DAG votes`);
      continue;
    }
    if (id === NOT_IN_TREE || id === TEMP_ADDRESS) throw new Error(`tree: snapshot puts the reserved address ${id} in the tree`);
    parents.set(id, sentTree === VIRTUAL_ROOT ? null : sentTree);
    nodes.set(id, { listed, sent, rec, totalWeight });
  }

  if (virtualChildren === undefined) throw new Error("tree: snapshot has no virtual node");
  if (!sameList(virtualChildren, [rootId])) {
    throw new Error("tree: snapshot virtual node's recTreeVotes disagree with rootId");
  }
  const s = buildStructure(parents);
  if (s.root !== rootId) throw new Error(`tree: snapshot rootId ${rootId} but the tree's root is ${s.root}`);

  const sentVotes = new Map<OwnerId, DagVote[]>();
  for (const [id, node] of nodes) {
    // sentTreeVote and recTreeVotes are two copies of the same edges; a snapshot
    // where they disagree is corrupt, and guessing which copy is right would be worse.
    if (!sameList([...node.listed].sort(compareIds), s.children.get(id) ?? [])) {
      throw new Error(`tree: snapshot recTreeVotes of ${id} disagree with the children's sentTreeVote`);
    }
    // Votes, likewise, are stored on both ends. Checking each end against the
    // other from both sides makes the two lists a bijection, so the sent side
    // used below is exactly the received side the engine sums.
    let sum = 0n;
    node.sent.forEach((v, pos) => {
      const twin = nodes.get(v.id)?.rec[v.posInOther];
      if (twin === undefined || twin.id !== id || twin.posInOther !== pos || twin.weight !== v.weight) {
        throw new Error(`tree: snapshot DAG vote ${id} -> ${v.id} is not linked both ways`);
      }
      if (localUpwardDist(s, id, v.id) !== v.dist) {
        throw new Error(`tree: snapshot DAG vote ${id} -> ${v.id} is not local, not upward, or has a stale dist`);
      }
      sum += v.weight;
    });
    node.rec.forEach((v, pos) => {
      const twin = nodes.get(v.id)?.sent[v.posInOther];
      if (twin === undefined || twin.id !== id || twin.posInOther !== pos) {
        throw new Error(`tree: snapshot DAG vote ${v.id} -> ${id} is not linked both ways`);
      }
    });
    if (sum !== node.totalWeight) throw new Error(`tree: snapshot totalWeight of ${id} is not the sum of its sent weights`);
    sentVotes.set(
      id,
      node.sent.map((v) => ({ to: v.id, weight: v.weight })),
    );
  }
  return makeView(s, computeReputation(s, sentVotes), canonicalAddress);
}

// The subset of the Anthill backend's AnthillEngine that the commons reads. All
// of it is read-only: building a view never writes the engine's state (not even
// the reputation cache that calculateReputation fills), so a view can be taken of
// an engine that is later replayed or digested.
export interface EngineLike {
  root(): string;
  parent(id: string): string; // the virtual node for the root
  children(id: string): string[];
  members(): string[];
  endorsing(id: string): string[]; // recipients of id's sent DAG votes
  // The contract's finder: index 1 is whether the vote exists, index 5 the vote.
  findSentDagVote(
    voter: string,
    recipient: string,
  ): readonly [votable: boolean, voted: boolean, sDist: number, rDist: number, pos: number, vote: { readonly weight: bigint }];
}

// Reads an engine. Reputation is computed for every member now (see
// computeReputation for why not through engine.calculateReputation), so the
// view stays a consistent copy even if the engine changes afterwards.
export function treeFromEngine(engine: EngineLike): TreeView {
  const parents = new Map<OwnerId, OwnerId | null>();
  for (const raw of engine.members()) {
    const id = canonicalAddress(raw);
    if (parents.has(id)) throw new Error(`tree: engine lists member ${id} twice`);
    const parent = canonicalAddress(engine.parent(raw));
    parents.set(id, parent === VIRTUAL_ROOT ? null : parent);
  }
  const s = buildStructure(parents);
  const engineRoot = canonicalAddress(engine.root());
  if (s.root !== engineRoot) throw new Error(`tree: engine root ${engineRoot} but the tree's root is ${s.root}`);
  const sentVotes = new Map<OwnerId, DagVote[]>();
  for (const id of s.parents.keys()) {
    if (!sameList(engine.children(id).map(canonicalAddress).sort(compareIds), s.children.get(id) ?? [])) {
      throw new Error(`tree: engine children of ${id} disagree with their parents`);
    }
    const votes = engine.endorsing(id).map((to): DagVote => {
      const [, voted, , , , vote] = engine.findSentDagVote(id, to);
      if (!voted) throw new Error(`tree: engine lists a DAG vote ${id} -> ${to} it cannot find`);
      return { to: canonicalAddress(to), weight: vote.weight };
    });
    sentVotes.set(id, votes);
  }
  return makeView(s, computeReputation(s, sentVotes), canonicalAddress);
}
