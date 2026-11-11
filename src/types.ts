// Shared contracts for the agent commons. Every module imports its types from
// here so modules written in parallel agree on shapes. Change a type here, and
// every module that uses it changes in the same commit.
//
// Conventions:
// - Ids are strings. An OwnerId is an Anthill user id (the same id the Anthill
//   tree uses for a member). A KeyId is the hex sha256 of a raw ed25519 public
//   key, first 16 bytes (32 hex chars).
// - Time is an ISO-8601 string passed in by the caller. Core modules never read
//   the clock; the CLI stamps entries. This keeps replay deterministic.
// - Reputation amounts are integers (points). No floats in the ledger except
//   probabilities in reviews.

export type OwnerId = string;
export type KeyId = string;
export type ModelFamily = string; // e.g. "claude", "gpt", "qwen", "deepseek", "kimi", "glm"
export type CommitSha = string;

// Capability ring of a file or change. 0 = kernel (reputation maths, auth,
// ledger, coordinator), 1 = pure logic, 2 = UI that cannot touch state.
export type Ring = 0 | 1 | 2;

export type Severity = "low" | "medium" | "high" | "critical";

// Checkable evidence behind a proposal. A proposal without evidence is refused.
export type Evidence =
  | { kind: "failingTest"; testId: string; command: string }
  | { kind: "diagnostic"; tool: string; message: string; file: string; line: number }
  | { kind: "location"; file: string; line: number; note: string };

export type ReviewVerdict = {
  // probability, 0..1, that the change contains a defect of severity >= medium
  defectProbability: number;
  summary: string;
  findingIds: string[];
};

// ---------------------------------------------------------------------------
// Ledger entries. Each body kind lists who may sign it (enforced in ledger.ts):
//   admin       = a key listed in genesis.admins
//   coordinator = genesis.coordinator key
//   owner       = an owner key registered via ownerKey
//   agent       = an active agent key registered via agentRegistered
// ---------------------------------------------------------------------------

export type EntryBody =
  // signer: none (seq 0 only). Bootstraps trust.
  | {
      kind: "genesis";
      project: string; // Anthill community id this project belongs to
      admins: string[]; // raw ed25519 public keys, base64url (SPKI DER)
      coordinator: string; // raw public key, base64url (SPKI DER)
      rules: Rules;
    }
  // signer: admin. Binds an owner (Anthill user) to a signing key. In production
  // the admin is the Anthill backend, which checks the owner's passkey session.
  | { kind: "ownerKey"; owner: OwnerId; publicKey: string; inviter: OwnerId | null }
  // signer: owner (the owner named). Registers an agent key under the owner.
  | { kind: "agentRegistered"; owner: OwnerId; publicKey: string; modelFamily: ModelFamily; harness: string }
  // signer: the agent's owner, or coordinator (automatic suspension)
  | { kind: "agentRevoked"; agent: KeyId; reason: string }
  // signer: agent or owner
  | { kind: "proposal"; id: string; title: string; evidence: Evidence[] }
  // signer: coordinator. Turns a proposal into a claimable task.
  | {
      kind: "task";
      id: string;
      proposalId: string;
      ring: Ring;
      acceptanceTestPaths: string[];
      sizeEstimate: number; // changed lines
      specAuthor: OwnerId;
    }
  // signer: agent. Locks stake on the owner; expires at `until`.
  | { kind: "claim"; taskId: string; until: string; stake: number }
  // signer: agent. A PR. `id` is the coordinator-side PR id.
  | {
      kind: "submission";
      id: string;
      taskId: string | null;
      baseCommit: CommitSha;
      headCommit: CommitSha;
      changedFiles: string[];
      linesChanged: number;
      planted?: false; // never set by authors; plants are hidden (see plantCommit)
    }
  // signer: coordinator. Result of a mechanical gate on a submission.
  | { kind: "gateResult"; submissionId: string; gate: string; pass: boolean; details: string }
  // signer: coordinator. Reviewers drawn after the submission is fixed.
  | { kind: "reviewAssignment"; submissionId: string; beacon: string; reviewers: KeyId[] }
  // signer: agent (assigned or open reviewer). commitment = sha256hex(canonical(verdict) + salt)
  | { kind: "reviewCommit"; submissionId: string; commitment: string; stake: number }
  // signer: same agent as the commit
  | { kind: "reviewReveal"; submissionId: string; verdict: ReviewVerdict; salt: string }
  // signer: agent. A claimed defect, with the test that should reproduce it.
  | {
      kind: "finding";
      id: string;
      target: { submissionId: string } | { snapshotId: string };
      severity: Severity;
      testPath: string; // file added by the finding, e.g. test/finding-123.test.ts
      testCommand: string; // command run in the repo root, exit code != 0 means failing
      stake: number;
    }
  // signer: coordinator. Output of the reproduction harness.
  | {
      kind: "findingResult";
      findingId: string;
      reproduced: boolean; // failsOnHead && passesOnParent
      failsOnHead: boolean;
      passesOnParent: boolean;
      logDigest: string;
    }
  // signer: coordinator. Submission merged into dev.
  | { kind: "merge"; submissionId: string; commit: CommitSha }
  // signer: coordinator. A release candidate frozen at a dev commit.
  | { kind: "snapshot"; id: string; commit: CommitSha; previousSnapshotId: string | null; submissionIds: string[] }
  // signer: agent. Second-pass review of a snapshot's cumulative diff (commit-reveal like reviews)
  | { kind: "attestCommit"; snapshotId: string; commitment: string; stake: number }
  | { kind: "attestReveal"; snapshotId: string; verdict: ReviewVerdict; salt: string }
  // signer: owner who is a kernel signer (rules.kernelSigners)
  | { kind: "signoff"; snapshotId: string }
  // signer: coordinator. main advanced to this snapshot.
  | { kind: "promotion"; snapshotId: string; commit: CommitSha }
  // signer: admin (the seeding custodian). Commitment to a planted bug, made
  // before the plant is submitted. commitment = sha256hex(submissionId + ":" + salt)
  | { kind: "plantCommit"; commitment: string }
  // signer: admin. Reveals a plant after the review window closed.
  | { kind: "plantReveal"; submissionId: string; salt: string; description: string; severity: Severity }
  // signer: coordinator. An agent obeyed a decoy instruction.
  | { kind: "honeytokenTriggered"; agent: KeyId; tokenId: string }
  // signer: coordinator. An escape: a defect found in main.
  | { kind: "escape"; findingId: string; snapshotId: string }
  // signer: coordinator. A reputation movement computed by incentives.ts.
  | { kind: "settlement"; owner: OwnerId; delta: number; reason: SettlementReason; ref: string }
  // signer: admin. New rules version, ratified by an Anthill poll.
  | { kind: "rulesChange"; rules: Rules; pollId: string };

export type EntryKind = EntryBody["kind"];

export type SettlementReason =
  | "mergeVest"
  | "proposerCut"
  | "bounty"
  | "authorSlash"
  | "approverSlash"
  | "cleanReview"
  | "missedPlant"
  | "falseFinding"
  | "claimExpired"
  | "inviterSlash"
  | "honeytoken";

export type LedgerEntry = {
  seq: number; // 0-based, contiguous
  prev: string; // hash of previous entry, "" for seq 0
  at: string; // ISO time stamped by the writer
  signer: KeyId | ""; // "" only for genesis
  body: EntryBody;
  sig: string; // base64url ed25519 signature over canonical({seq, prev, at, signer, body}); "" for genesis
  hash: string; // sha256hex(canonical({seq, prev, at, signer, body, sig}))
};

// ---------------------------------------------------------------------------
// Rules: every threshold lives here, versioned, changed only by rulesChange.
// ---------------------------------------------------------------------------

export type Rules = {
  version: number;
  // ring classification: first matching glob wins; unmatched files are ring 1
  rings: { glob: string; ring: Ring }[];
  // paths that only the dependency track may change
  lockedPaths: string[];
  maxLinesPerSubmission: number; // 400
  minTreeDistance: number; // N: reviewers and bounty winners must be farther than this from the author
  assignedReviewers: number; // 2-3
  requireOtherModelFamily: boolean;
  plantRate: number; // 0.1..0.2, informational for the custodian
  stake: {
    base: number; // points locked per claim at 100 lines, ring 1
    exponent: number; // superlinear in lines, e.g. 1.5
    ringMultiplier: [number, number, number]; // ring 0, 1, 2
    review: number; // points locked per review commit
    finding: number; // points locked per finding
  };
  rewards: {
    merge: number; // total author reward per merged submission, vests in thirds
    proposerCutFraction: number; // share of author reward to the proposer
    bounty: Record<Severity, number>; // flat finder reward
    stageMultiplier: { dev: number; release: number; main: number }; // cost to author/approvers by stage
    cleanReview: number;
    missedPlantPenalty: number; // must exceed cleanReview
    falseFindingPenalty: number;
    duplicateDecay: number; // 0.9
    inviterShare: number; // fraction of an invitee's slash also charged to the inviter
    honeytokenPenalty: number;
  };
  vesting: { tailDays: number }; // third tranche vests this many days after release
  reviewsPerSubmitCredit: number; // 2
  promotion: {
    minModelFamilies: number; // 3
    minDistinctOwners: number; // 2
    recallWindowDays: number; // 28
    minSeeds: number; // 30
    minRecallLowerBound90: number; // 0.8
    maxCriticalUpperBound90: number; // 0.1
    soakFloorHours: number; // 72
    kernelSignoffs: number; // k
  };
  kernelSigners: OwnerId[]; // the n
};

// ---------------------------------------------------------------------------
// Derived state: what ledger.replay() builds. Read-only for other modules.
// ---------------------------------------------------------------------------

export type OwnerState = {
  id: OwnerId;
  keyId: KeyId;
  inviter: OwnerId | null;
  reputationDelta: number; // sum of settlements in this project (added to Anthill reputation)
  lockedStake: number;
};

export type AgentState = {
  keyId: KeyId;
  owner: OwnerId;
  modelFamily: ModelFamily;
  harness: string;
  active: boolean;
  revokedReason?: string;
};

export type ReviewState = {
  reviewer: KeyId;
  commitment: string;
  stake: number;
  committedSeq: number;
  verdict?: ReviewVerdict; // set on a valid reveal
  revealedSeq?: number;
};

export type SubmissionState = {
  id: string;
  author: KeyId;
  taskId: string | null;
  baseCommit: CommitSha;
  headCommit: CommitSha;
  changedFiles: string[];
  linesChanged: number;
  submittedSeq: number;
  submittedAt: string;
  gates: { gate: string; pass: boolean; details: string }[];
  assignment?: { beacon: string; reviewers: KeyId[]; seq: number };
  reviews: ReviewState[];
  findingIds: string[];
  merged?: { commit: CommitSha; seq: number; at: string };
  planted?: { severity: Severity; description: string }; // set only after plantReveal
};

export type FindingState = {
  id: string;
  finder: KeyId;
  target: { submissionId: string } | { snapshotId: string };
  severity: Severity;
  testPath: string;
  testCommand: string;
  stake: number;
  seq: number;
  at: string;
  result?: { reproduced: boolean; failsOnHead: boolean; passesOnParent: boolean; logDigest: string; seq: number };
};

export type SnapshotState = {
  id: string;
  commit: CommitSha;
  previousSnapshotId: string | null;
  submissionIds: string[];
  seq: number;
  at: string;
  attestations: ReviewState[];
  signoffs: OwnerId[];
  promoted?: { seq: number; at: string };
};

export type CommonsState = {
  project: string;
  rules: Rules;
  adminKeys: KeyId[];
  coordinatorKey: KeyId;
  publicKeys: Map<KeyId, string>; // keyId -> base64url SPKI DER
  owners: Map<OwnerId, OwnerState>;
  ownerByKey: Map<KeyId, OwnerId>;
  agents: Map<KeyId, AgentState>;
  proposals: Map<string, { id: string; title: string; evidence: Evidence[]; by: KeyId; seq: number }>;
  tasks: Map<string, Extract<EntryBody, { kind: "task" }> & { seq: number }>;
  claims: Map<string, { taskId: string; agent: KeyId; until: string; stake: number; seq: number }>; // by taskId, latest
  submissions: Map<string, SubmissionState>;
  findings: Map<string, FindingState>;
  snapshots: Map<string, SnapshotState>;
  plantCommitments: { commitment: string; seq: number }[];
  honeytokens: { agent: KeyId; tokenId: string; seq: number; at: string }[];
  escapes: { findingId: string; snapshotId: string; seq: number; at: string }[];
  settlements: { owner: OwnerId; delta: number; reason: SettlementReason; ref: string; seq: number; at: string }[];
  headHash: string;
  length: number;
};

// ---------------------------------------------------------------------------
// The Anthill tree, as seen by the commons. Built from the Anthill engine, a
// snapshot JSON, or a plain parent map (tests). See tree.ts.
// ---------------------------------------------------------------------------

export interface TreeView {
  root(): OwnerId;
  has(id: OwnerId): boolean;
  parent(id: OwnerId): OwnerId | null; // null for the root
  children(id: OwnerId): OwnerId[];
  depth(id: OwnerId): number; // root = 0
  // number of edges on the tree path between a and b (0 if a === b)
  distance(a: OwnerId, b: OwnerId): number;
  members(): OwnerId[];
  reputation(id: OwnerId): number; // Anthill reputation in points (0 if unknown)
}

// Result of any gate: pass/fail plus a reason a human can read.
export type GateReport = { gate: string; pass: boolean; details: string };
