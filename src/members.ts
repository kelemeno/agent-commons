// The commons' own trust tree, derived from the ledger. Every ownerKey entry
// names the owner who vouched for the new one (its inviter) or null, and the
// ledger checks that the inviter is already an owner. So the owners and their
// inviters already form a forest; memberTree hangs every root of it (an owner
// with inviter null) under one virtual root, MEMBER_ROOT, which gives every
// pair of owners a path and a distance:
//
//   (commons) ─┬─ alice ─── bob      alice vouched for bob: distance 1
//              └─ carol              carol was added with no inviter: distance
//                                    2 from alice, 3 from bob
//
// This is what reviewer selection draws over, and what bounties and clean
// reviews check distance in: nothing outside the ledger decides who is close
// to whom. A Phase 1 group (the allowlist) is just the admin's ownerKey
// entries: inviter null puts every owner at distance 2 from every other one,
// and naming a vouching owner hangs the newcomer under it.
//
// The tree is a pure function of the owner set, and the ledger never changes
// an owner once registered, so the same ledger prefix always yields the same
// tree and the same treeDigest. Owners are only ever added, so distances
// between existing owners never change either; a newcomer only adds a leaf.
//
// Order is canonical: members() and children() are sorted by id, because
// reviewer selection iterates them and its result must not depend on Map
// insertion order.
//
// Structural queries (parent, children, depth, distance) throw on an id that
// is not a node. Every owner of a replayed state is a member, and every
// agent's owner is an owner, so only a corrupt, hand-built state reaches the
// throw; a made-up distance there could make an outsider look far enough
// away to review, so callers let it stop the draw or settlement.

import { canonical, sha256hex } from "./crypto";
import type { CommonsState, OwnerId, TreeView } from "./types";

// The virtual root above every owner whose inviter is null. It is a node of
// the view (root(), has() and members() include it) so that distances have
// somewhere to meet, but never an owner: the ledger's ID_RE requires an id to
// start with a letter or digit, so no ownerKey can name it (ledger.ts asserts
// this when it loads).
export const MEMBER_ROOT = "(commons)";

// The tree of the owners in `state`. A state from replay is always a valid
// forest; a hand-built one with an unknown inviter or a cycle throws.
export function memberTree(state: Pick<CommonsState, "owners">): TreeView {
  const parents = new Map<OwnerId, OwnerId | null>([[MEMBER_ROOT, null]]);
  for (const [id, o] of state.owners) {
    if (id === MEMBER_ROOT) throw new Error(`tree: ${MEMBER_ROOT} is reserved for the virtual root`);
    parents.set(id, o.inviter ?? MEMBER_ROOT);
  }
  return makeView(buildStructure(parents));
}

// What identifies a tree for reviewer selection: sha256hex of the canonical
// JSON of its parent map ({ node: parent | null }; canonical() sorts the
// keys). A reviewAssignment records it, and the ledger, selection and
// promotion check it against memberTree of the ledger before the assignment.
export function treeDigest(tree: TreeView): string {
  // fromEntries defines own properties, so even a member named "__proto__" is a key.
  return sha256hex(canonical(Object.fromEntries(tree.members().map((m) => [m, tree.parent(m)]))));
}

// treeDigest(memberTree(state)): the digest a draw over `state` records.
export function memberDigest(state: Pick<CommonsState, "owners">): string {
  return treeDigest(memberTree(state));
}

// For tests and tools: a tree from a plain parent map, `null` marking the
// root. Ids are taken exactly as given.
export function treeFromParents(parents: Record<OwnerId, OwnerId | null>): TreeView {
  const parentMap = new Map<OwnerId, OwnerId | null>();
  for (const [id, parent] of Object.entries(parents)) {
    if (parent !== null && typeof parent !== "string") throw new Error(`tree: parent of ${id} must be a string or null`);
    parentMap.set(id, parent);
  }
  return makeView(buildStructure(parentMap));
}

const compareIds = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

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

// Edges on the path through the lowest common ancestor. Both must be members.
function distanceIn(s: Structure, a: OwnerId, b: OwnerId): number {
  let x = a;
  let y = b;
  let dx = s.depth.get(a) as number;
  let dy = s.depth.get(b) as number;
  let edges = 0;
  for (; dx > dy; dx--, edges++) x = s.parents.get(x) as OwnerId;
  for (; dy > dx; dy--, edges++) y = s.parents.get(y) as OwnerId;
  while (x !== y) {
    x = s.parents.get(x) as OwnerId;
    y = s.parents.get(y) as OwnerId;
    edges += 2;
  }
  return edges;
}

// A frozen view: later changes to the inputs are not reflected, so one
// selection or settlement run sees one consistent tree.
function makeView(s: Structure): TreeView {
  const members = [...s.parents.keys()].sort(compareIds);
  const member = (id: OwnerId): OwnerId => {
    if (!s.parents.has(id)) throw new Error(`tree: unknown member ${id}`);
    return id;
  };
  return {
    root: () => s.root,
    has: (id) => s.parents.has(id),
    parent: (id) => s.parents.get(member(id)) ?? null,
    children: (id) => [...(s.children.get(member(id)) ?? [])],
    depth: (id) => s.depth.get(member(id)) as number,
    distance: (a, b) => distanceIn(s, member(a), member(b)),
    members: () => [...members],
  };
}
