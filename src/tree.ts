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
// Ids are canonically lowercase, as the Anthill engine stores them. Every
// constructor lowercases its input and every query lowercases its argument, so
// a checksummed (EIP-55) or otherwise re-cased address is the same member, at
// distance 0 from itself, and cannot pose as a distant stranger.
//
// Reputation is a non-negative safe integer number of points. Anything else is
// rejected at construction: downstream maths (PR slots, weights) would turn an
// Infinity or a negative into unlimited slots or NaN.

import type { OwnerId, TreeView } from "./types";

// The Anthill contract's virtual node above the root (the root's sentTreeVote).
export const VIRTUAL_ROOT = "0x0000000000000000000000000000000000000001";
// sentTreeVote of an address that is not in the tree.
const NOT_IN_TREE = "0x0000000000000000000000000000000000000000";

const ONE_POINT = 10n ** 18n; // Anthill reputation has 18 decimals

// Thrown by structural queries on an id that is not in the tree, so callers can
// tell "this owner is an outsider" from "this tree is corrupt" (a plain Error).
export class NotAMemberError extends Error {
  constructor(readonly id: string) {
    super(`tree: unknown member ${id}`);
    this.name = "NotAMemberError";
  }
}

export function canonicalId(id: string): OwnerId {
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

// Validates the parent map and precomputes depth, so distance() costs O(depth).
// Ids must already be canonical; only members may carry reputation.
function buildTree(parents: Map<OwnerId, OwnerId | null>, reputation: Map<OwnerId, number>): TreeView {
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

  for (const id of reputation.keys()) {
    if (!parents.has(id)) throw new Error(`tree: reputation given for ${id}, which is not a member`);
  }

  const members = [...parents.keys()].sort(compareIds);

  const member = (raw: OwnerId): OwnerId => {
    const id = canonicalId(raw);
    if (!parents.has(id)) throw new NotAMemberError(raw);
    return id;
  };
  const depthOf = (id: OwnerId): number => depth.get(id) as number; // id is a member
  const up = (id: OwnerId): OwnerId => parents.get(id) as OwnerId; // only called below the root

  return {
    root: () => root,
    has: (id) => parents.has(canonicalId(id)),
    parent: (id) => parents.get(member(id)) ?? null,
    children: (id) => [...(children.get(member(id)) ?? [])],
    depth: (id) => depthOf(member(id)),
    distance: (rawA, rawB) => {
      let x = member(rawA);
      let y = member(rawB);
      let da = depthOf(x);
      let db = depthOf(y);
      let edges = 0;
      while (da > db) {
        x = up(x);
        da--;
        edges++;
      }
      while (db > da) {
        y = up(y);
        db--;
        edges++;
      }
      while (x !== y) {
        x = up(x);
        y = up(y);
        edges += 2;
      }
      return edges;
    },
    members: () => [...members],
    reputation: (id) => reputation.get(canonicalId(id)) ?? 0,
  };
}

// For tests and tools. `null` marks the root. Reputation is in points and may
// only be given for members. Two keys that differ only in case are one member
// named twice, and are rejected.
export function treeFromParents(
  parents: Record<OwnerId, OwnerId | null>,
  reputation: Record<OwnerId, number> = {},
): TreeView {
  const parentMap = new Map<OwnerId, OwnerId | null>();
  for (const [key, parent] of Object.entries(parents)) {
    if (parent !== null && typeof parent !== "string") throw new Error(`tree: parent of ${key} must be a string or null`);
    const id = canonicalId(key);
    if (parentMap.has(id)) throw new Error(`tree: ${key} is listed twice (ids are case-insensitive)`);
    parentMap.set(id, parent === null ? null : canonicalId(parent));
  }
  const repMap = new Map<OwnerId, number>();
  for (const [key, points] of Object.entries(reputation)) {
    if (typeof points !== "number" || !Number.isSafeInteger(points) || points < 0) {
      throw new Error(`tree: reputation of ${key} must be a non-negative safe integer`);
    }
    const id = canonicalId(key);
    if (repMap.has(id)) throw new Error(`tree: reputation of ${key} is given twice (ids are case-insensitive)`);
    repMap.set(id, points);
  }
  return buildTree(parentMap, repMap);
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

// Reads anthillSnapshot.json: either its text or the parsed object (with or
// without the {__bigint__} values revived). Ids are lowercased, as the engine
// does on load, so both views name members the same way.
//
// Reputation: the node's `reputation` field if present, else `currentRep`. The
// crawled snapshot only stores `currentRep` on real members (`reputation` appears
// only on the virtual node), and both are 18-decimal values.
//
// The engine finds the root through the virtual node (root() is the virtual
// node's first recTreeVote), so the virtual node must be present and name
// exactly rootId; otherwise a peer reading this file through the engine would
// see a different tree from one reading it here.
export function treeFromSnapshot(json: unknown): TreeView {
  const doc: unknown = typeof json === "string" ? JSON.parse(json) : json;
  const graph = isRecord(doc) ? doc["graph"] : undefined;
  if (!isRecord(graph) || typeof graph["rootId"] !== "string" || !isRecord(graph["dict"])) {
    throw new Error("tree: snapshot must look like {graph: {rootId, dict}}");
  }
  const rootId = graph["rootId"].toLowerCase();
  if (rootId === VIRTUAL_ROOT) throw new Error("tree: snapshot rootId is the virtual node");

  const parents = new Map<OwnerId, OwnerId | null>();
  const listedChildren = new Map<OwnerId, OwnerId[]>();
  const reputation = new Map<OwnerId, number>();
  let virtualChildren: OwnerId[] | undefined;
  const seen = new Set<OwnerId>();
  for (const [key, node] of Object.entries(graph["dict"])) {
    if (!isRecord(node) || typeof node["sentTreeVote"] !== "string") {
      throw new Error(`tree: snapshot node ${key} has no sentTreeVote`);
    }
    const id = canonicalId(typeof node["id"] === "string" ? node["id"] : key);
    const sent = canonicalId(node["sentTreeVote"]);
    if (seen.has(id)) throw new Error(`tree: snapshot lists ${id} twice`);
    seen.add(id);
    const rawRec = node["recTreeVotes"] ?? [];
    if (!Array.isArray(rawRec) || !rawRec.every((c): c is string => typeof c === "string")) {
      throw new Error(`tree: snapshot node ${id} has malformed recTreeVotes`);
    }
    const rec = rawRec.map(canonicalId);

    if (id === VIRTUAL_ROOT) {
      if (sent !== VIRTUAL_ROOT) throw new Error("tree: snapshot virtual node does not point at itself");
      virtualChildren = rec;
      continue;
    }
    if (sent === NOT_IN_TREE) {
      // The engine still loads these child lists; a non-member claiming
      // children is a hidden edge.
      if (rec.length > 0) throw new Error(`tree: snapshot node ${id} is not in the tree but lists children`);
      continue;
    }
    parents.set(id, sent === VIRTUAL_ROOT ? null : sent);
    listedChildren.set(id, rec);
    const rep = node["reputation"] ?? node["currentRep"];
    if (rep !== undefined) reputation.set(id, reputationPoints(snapshotBigint(rep, `reputation of ${id}`)));
  }

  if (virtualChildren === undefined) throw new Error("tree: snapshot has no virtual node");
  if (!sameList(virtualChildren, [rootId])) {
    throw new Error("tree: snapshot virtual node's recTreeVotes disagree with rootId");
  }
  const tree = buildTree(parents, reputation);
  if (tree.root() !== rootId) throw new Error(`tree: snapshot rootId ${rootId} but the tree's root is ${tree.root()}`);
  // sentTreeVote and recTreeVotes are two copies of the same edges; a snapshot
  // where they disagree is corrupt, and guessing which copy is right would be worse.
  for (const id of tree.members()) {
    const listed = [...(listedChildren.get(id) ?? [])].sort(compareIds);
    if (!sameList(listed, tree.children(id))) {
      throw new Error(`tree: snapshot recTreeVotes of ${id} disagree with the children's sentTreeVote`);
    }
  }
  return tree;
}

function sameList(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// The subset of the Anthill backend's AnthillEngine that the commons reads.
export interface EngineLike {
  root(): string;
  parent(id: string): string; // the virtual node for the root
  children(id: string): string[];
  members(): string[];
  calculateReputation(id: string): bigint; // 18 decimals
  // Runs `call` and then rolls the engine's state back (AnthillEngine.simulate).
  simulate?(call: () => void): void;
}

// Reads an engine. Reputation is computed for every member now, so the view
// stays a consistent copy even if the engine changes afterwards.
//
// AnthillEngine.calculateReputation writes the engine's reputation cache, which
// engine.read.reputation exposes. When the engine offers simulate(), the
// computation runs inside it, so building a view leaves the engine's state
// exactly as it was. An engine without simulate() may be changed by the
// reputation calls; pass a throwaway copy, never one that is replayed or digested.
export function treeFromEngine(engine: EngineLike): TreeView {
  const parents = new Map<OwnerId, OwnerId | null>();
  for (const raw of engine.members()) {
    const id = canonicalId(raw);
    if (parents.has(id)) throw new Error(`tree: engine lists member ${id} twice`);
    const parent = canonicalId(engine.parent(raw));
    parents.set(id, parent === VIRTUAL_ROOT ? null : parent);
  }
  const reputation = new Map<OwnerId, number>();
  const computeAll = (): void => {
    for (const id of parents.keys()) reputation.set(id, reputationPoints(engine.calculateReputation(id)));
  };
  if (engine.simulate) engine.simulate(computeAll);
  else computeAll();

  const tree = buildTree(parents, reputation);
  const engineRoot = canonicalId(engine.root());
  if (tree.root() !== engineRoot) throw new Error(`tree: engine root ${engineRoot} but the tree's root is ${tree.root()}`);
  for (const id of tree.members()) {
    if (!sameList(engine.children(id).map(canonicalId).sort(compareIds), tree.children(id))) {
      throw new Error(`tree: engine children of ${id} disagree with their parents`);
    }
  }
  return tree;
}
