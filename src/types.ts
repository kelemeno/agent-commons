// Shared contracts for the agent commons. Every module imports its types from
// here so modules written in parallel agree on shapes. Change a type here, and
// every module that uses it changes in the same commit.
//
// Conventions:
// - Ids are strings. An OwnerId names a person (or organisation) the admin
//   registered with an ownerKey entry; owners and their inviters form the
//   commons' trust tree (members.ts). A KeyId is the hex sha256 of a raw ed25519 public
//   key, first 16 bytes (32 hex chars).
// - Time is an ISO-8601 string passed in by the caller. Core modules never read
//   the clock; the CLI stamps entries. This keeps replay deterministic.
// - Reputation amounts are integers (points). No floats in the ledger except
//   probabilities in reviews.

export type OwnerId = string;
export type KeyId = string;
export type ModelFamily = string; // one of rules.modelFamilies (lowercase), e.g. "claude", "gpt", "qwen"
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
      project: string; // a free-form id of the project this ledger governs
      admins: string[]; // raw ed25519 public keys, base64url (SPKI DER)
      coordinator: string; // raw public key, base64url (SPKI DER)
      rules: Rules;
    }
  // signer: admin. Admits an owner and binds it to a signing key. `inviter` is
  // the existing owner who vouched for it, or null; it is the owner's parent
  // in the trust tree (members.memberTree). The admin's ownerKey entries are
  // the allowlist: nobody else can admit an owner.
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
  // beacon = review.assignmentBeacon(submissionId, the submission's headCommit,
  // entropy), recomputed and checked by the ledger. entropy must be
  // the public randomness round fixed by rule (docs/protocol.md §5.6);
  // treeDigest = members.memberDigest of the state before this entry (the
  // ledger checks it), so the tree the draw used is fixed by the ledger.
  | {
      kind: "reviewAssignment";
      submissionId: string;
      beacon: string;
      entropy: string;
      treeDigest: string;
      reviewers: KeyId[];
    }
  // signer: agent (assigned or open reviewer). commitment = review.commitmentFor(verdict, salt,
  // reviewer keyId, { submissionId }) = sha256hex(canonical({ verdict, salt, reviewer, subject }))
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
      // Set when the harness could not judge the test (timeouts and errors
      // past the retry limit). Then reproduced is false, and the result is
      // neither a reproduction nor a false finding: nobody is paid or slashed.
      harnessError?: string;
    }
  // signer: coordinator. One harness run that could not judge the finding
  // (timeout, crash). Counted on the ledger, so maxHarnessErrors survives
  // restarts and every coordinator replica agrees on it.
  | { kind: "findingAttempt"; findingId: string; harnessError: string }
  // signer: an operator (a genesis admin, or an owner in rules.kernelSigners
  // who owns neither the finding nor the work it targets). A reproduced
  // finding shows only that its test fails on head and passes on the parent,
  // which a test pinning the old behaviour does against any change. confirmed =
  // a real defect: only then does it pay, slash or record an escape. Dismissed
  // = it tests the intended change: it stops blocking and costs its finder
  // falseFindingPenalty. One decision per finding, after its result.
  | { kind: "findingDecision"; findingId: string; confirmed: boolean; reason: string }
  // signer: an operator who does not own the author's agent. A human approved
  // the merge (Phase 1 every merge; Phase 2 only one the reviewers flagged).
  | { kind: "mergeApproval"; submissionId: string }
  // signer: coordinator. The review window passed with a quorum of revealed
  // assigned reviews; `missing` never revealed. Closes the window on the
  // ledger (plants.reviewWindowCloseSeq) before any merge, so the plant
  // custodian can reveal in the grace that follows.
  | { kind: "reviewWindowClosed"; submissionId: string; missing: KeyId[] }
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
  // before the plant is submitted: in batches, well ahead, so the commit's
  // timing does not point at the submission (docs/protocol.md §7.1).
  // commitment = sha256hex(submissionId + ":" + salt)
  | { kind: "plantCommit"; commitment: string }
  // signer: admin. Reveals a plant after the review window closed.
  | { kind: "plantReveal"; submissionId: string; salt: string; description: string; severity: Severity }
  // signer: coordinator. An agent obeyed a decoy instruction.
  | { kind: "honeytokenTriggered"; agent: KeyId; tokenId: string }
  // signer: coordinator. An escape: a defect found in main.
  | { kind: "escape"; findingId: string; snapshotId: string }
  // signer: coordinator. A reputation movement computed by incentives.ts.
  | { kind: "settlement"; owner: OwnerId; delta: number; reason: SettlementReason; ref: string }
  // signer: admin. New rules version; pollId names the group decision behind it.
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
  // The closed list of model families an agent may declare, lowercase. A free
  // spelling ("Claude ", "anthropic") would let one family pass as two.
  modelFamilies: ModelFamily[];
  plantRate: number; // 0.1..0.2, informational for the custodian
  stake: {
    base: number; // points locked per claim at 100 lines, ring 1
    exponent: number; // superlinear in lines, e.g. 1.5
    ringMultiplier: [number, number, number]; // ring 0, 1, 2
    review: number; // points locked per review commit
    finding: number; // points locked per finding
    // Points of stake every owner may lock before earning any: the server
    // backs stakes with allowance + reputationDelta - lockedStake.
    allowance: number;
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
  // Commit phase: commits on a submission close commitHours after its
  // reviewAssignment (on a snapshot, after the snapshot entry), and reveals
  // wait for that deadline or for every assigned reviewer's commit. Without it
  // the first reveal, by anyone, would close commits for everyone.
  review: { commitHours: number };
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
  // Sum of settlements in this project: the owner's commons reputation. It
  // backs stakes (with rules.stake.allowance) and sizes PR slots.
  reputationDelta: number;
  lockedStake: number;
  // Seq of the ownerKey entry, so the tree an old draw used can be rebuilt
  // (selection.verifyAssignment). Always set by replay; optional only for
  // hand-built states.
  registeredSeq?: number;
};

export type AgentState = {
  keyId: KeyId;
  owner: OwnerId;
  modelFamily: ModelFamily;
  harness: string;
  active: boolean;
  revokedReason?: string;
  // Who revoked it: its owner (often key rotation) or the coordinator (a
  // suspension: honeytoken, leaked key). Set with revokedReason.
  revokedBy?: "owner" | "coordinator";
  // Seqs of the registration and the revocation, so an old draw can be
  // recomputed over the pool as it was (selection.verifyAssignment). Always set
  // by replay; optional only for hand-built states.
  registeredSeq?: number;
  revokedSeq?: number;
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
  assignment?: { beacon: string; entropy: string; treeDigest: string; reviewers: KeyId[]; seq: number; at?: string }; // at: always set by replay
  approval?: { by: KeyId; seq: number; at: string }; // mergeApproval
  windowClosed?: { missing: KeyId[]; seq: number; at: string }; // reviewWindowClosed
  reviews: ReviewState[];
  findingIds: string[];
  merged?: { commit: CommitSha; seq: number; at: string };
  planted?: { severity: Severity; description: string; seq?: number }; // set only after plantReveal; seq always set by replay
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
  result?: {
    reproduced: boolean;
    failsOnHead: boolean;
    passesOnParent: boolean;
    logDigest: string;
    harnessError?: string; // see findingResult
    seq: number;
    at?: string; // always set by replay
  };
  harnessErrors?: number; // findingAttempt entries so far (absent = 0)
  decision?: { confirmed: boolean; reason: string; by: KeyId; seq: number; at?: string }; // findingDecision; at always set by replay
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
  // Every rules value in force, oldest first, with the seq that set it (0 for
  // genesis), so a draw can be recomputed under the rules it used. Always set
  // by replay; absent in hand-built states, which then mean "never changed".
  rulesHistory?: { seq: number; rules: Rules }[];
  adminKeys: KeyId[];
  coordinatorKey: KeyId;
  publicKeys: Map<KeyId, string>; // keyId -> base64url SPKI DER
  owners: Map<OwnerId, OwnerState>;
  ownerByKey: Map<KeyId, OwnerId>;
  agents: Map<KeyId, AgentState>;
  proposals: Map<string, { id: string; title: string; evidence: Evidence[]; by: KeyId; seq: number }>;
  tasks: Map<string, Extract<EntryBody, { kind: "task" }> & { seq: number }>;
  // By taskId, the latest claim. `since` is the `at` of the first claim in the
  // holder's unbroken run of extensions (always set by replay).
  claims: Map<string, { taskId: string; agent: KeyId; until: string; stake: number; seq: number; since?: string }>;
  // Every claim entry, in ledger order, so a replaced claim can still be
  // settled (incentives.settleExpiredClaims). Always set by replay.
  claimHistory?: { taskId: string; agent: KeyId; until: string; stake: number; seq: number; at: string }[];
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
// The trust tree: owners under their inviters, derived from the ledger by
// members.memberTree (or from a plain parent map in tests). See members.ts.
// ---------------------------------------------------------------------------

export interface TreeView {
  root(): OwnerId;
  has(id: OwnerId): boolean;
  parent(id: OwnerId): OwnerId | null; // null for the root
  children(id: OwnerId): OwnerId[];
  depth(id: OwnerId): number; // root = 0
  // number of edges on the tree path between a and b (0 if a === b)
  distance(a: OwnerId, b: OwnerId): number;
  members(): OwnerId[]; // every node, sorted
}

// Result of any gate: pass/fail plus a reason a human can read.
export type GateReport = { gate: string; pass: boolean; details: string };
