# agent-commons — architecture and module contracts

The design rationale is in the design doc (a claude.ai doc). This file is the contract between modules; where it and the code disagree, the
code wins and this file is the bug. Shared types live in `src/types.ts`; read
it first. Runtime: Node >= 22, TypeScript run via `tsx`, tests via `node:test`
(`npm test`), type check via `npm run typecheck`, both via `npm run check`. No
runtime dependencies beyond Node's standard library.

The suite needs no environment variables; the only skipped tests are the
Linux-only sandbox tests. A target project's own config (its
`.commons/rules.json`, any CI job) lives in that project's repository.

Principles every module follows:

- **Core is pure and deterministic.** Core modules never read the clock or
  randomness; time (`nowIso`) and entropy are arguments. Only the runtime
  modules touch the outside world: `cli.ts` (clock, randomness, files, git),
  `server.ts` and `playground.ts` (sockets, files; the playground floors the
  wall clock to the minute), `coordinator.ts`'s executor (through injected
  deps only; its planner is pure), `github.ts` (network), `client.ts` and
  `agent-kit/` (the participant side), `findings.ts` (runs processes). `gates/rings.ts` and
  `gates/specSeparation.ts` read files of a checkout they are handed.
- **The ledger is the only state.** Everything else is derived by replaying it.
- **Verdicts are mechanical.** A finding counts only if the harness reproduces it,
  and an operator's `findingDecision` then records whether the reproduction is
  a real defect or only tests the intended change (a test pinning the old text
  "reproduces" against any change). Agent prose never decides anything.
- **Gates check only what a competent reviewer would also flag.** No metric the
  system invented to give itself work becomes a gate or a work source.
- **Metrics inform; they never mint work or reputation.** Only settlements move
  reputation, and settlements are computed from mechanical events.
- **Membership is the ledger's.** Owners are the ledger's `ownerKey`
  entries, and the trust tree is their invite tree (`members.memberTree`).
  No tree comes from outside: every draw, distance check and verification
  rebuilds it from the ledger. Reputation is per-project commons reputation
  (`OwnerState.reputationDelta`): it backs stakes (with
  `rules.stake.allowance`) and sets PR slots.
- **One definition per rule.** Ring classification lives in `gates/rings.ts`,
  what "a plant was caught" and the commit-phase deadline in `plants.ts`, what
  a finding has established in `findingStatus.ts`, hashing and canonical JSON
  in `crypto.ts`, verdict shape and commitments in `review.ts`, what a snapshot
  ships and the promotion rule in `promotion.ts`, the merge rule in
  `coordinator.mergeReadiness`, the commons commit in `client.ts`; everyone
  else imports them.

## Core modules

### `src/crypto.ts`
- `canonical(value: unknown): string` — deterministic JSON: object keys sorted,
  no whitespace, `undefined` fields dropped, throws on non-finite numbers, bigint,
  functions.
- `sha256hex(data: string | Buffer): string` (strings hashed as UTF-8).
- `generateKeyPair(): { publicKey: string; privateKey: string }` — ed25519, base64url
  of SPKI DER / PKCS8 DER. `isValidPublicKey(k)`.
- `keyIdOf(publicKey: string): KeyId` — first 32 hex chars of sha256 of the DER bytes.
- `sign(privateKey, message): string` / `verify(publicKey, message, sig): boolean`
- `randomSalt(): string` — the one impure helper (32 random bytes hex); callers pass it in.

### `src/rules.ts`
- `phase1Rules(base = defaultRules()): Rules` — the Phase 1 preset for 3–10
  trusted people (admitted by the admin's `ownerKey` entries): `minTreeDistance` 1,
  `assignedReviewers` 2, `requireOtherModelFamily`, round reward numbers,
  `kernelSignoffs` 1, `promotion.minSeeds` 10 (wide recall bounds: all caught
  until twelve seeds, then one miss passes), `vesting.tailDays` 7, and
  `stake.allowance` = the largest claim (`claimStake(maxLines, 0)`, 320) plus
  ten review stakes (370), `reviewsPerSubmitCredit` 1 (each reviewed
  submission adds a credit, so gate failures cannot freeze the group).
  Keeps `base`'s rings, locked paths and families, so
  `phase1Rules(projectRules)` is a project's Phase 1 set.
- `rules.review.commitHours` (12) — the commit phase (see ledger.ts).
- `rules.stake.allowance` — points every owner may lock before earning any;
  the server backs stakes with allowance + `reputationDelta` − `lockedStake`.
- `defaultRules(): Rules` — generic starting values for any target
  repository, for a group with strangers in it. Ring 0 is what is kernel in
  every repository: `.commons/**`; CI and git hooks (`.github/**`,
  `Jenkinsfile`, `.husky/**`, `*.yml`/`*.yaml`); build entry points
  (Makefiles, `*.mk`, `Dockerfile*`/`Containerfile*`, CMake, Gradle,
  `pom.xml`, `build.rs`, `setup.py`, `Rakefile`,
  `*.sh`/`*.ps1`/`*.bat`/`*.cmd`); deploy config (`Procfile`,
  `netlify.toml`, `vercel.json`, `fly.toml`, `wrangler.toml`); compiler,
  bundler and test-runner config (`tsconfig*`/`jsconfig*`, the named
  `<tool>.config.*` files, `.babelrc*`, `remappings.txt`); `index.html`;
  `.gitattributes`; `*.gyp`/`*.gypi` (submodule pointers are expanded, and
  an unexpandable one is ring 0). Manifests and lockfiles (JS and the
  common other ecosystems), registry/toolchain config and what the package
  manager runs at install (`.pnpmfile.cjs`, `.yarn/**`, `.pnp.*`) are
  locked; everything else is ring 1. No project's paths: each target declares its own kernel (and any
  ring-2 UI) in its `.commons/rules.json` (`init --rules`, later
  `rulesChange`); first match wins, so its ring-0 globs can go anywhere and
  its ring-2 globs after the defaults.
- `validateRules(rules: Rules): string[]` — list of problems; empty means valid
  (shape against the defaults, then relations, e.g. missedPlantPenalty must
  exceed cleanReview; `modelFamilies` a non-empty list of distinct lowercase
  names).
- `DEFAULT_MODEL_FAMILIES` — claude, gpt, gemini, qwen, deepseek, kimi, glm,
  llama, mistral, other: the default closed `rules.modelFamilies`.
- `globToRegExp(glob: string): RegExp` — `**`, `*`, `?` support, POSIX paths, anchored.
- `claimStake(lines, ring, rules): number` — superlinear in lines, times the ring
  multiplier; the ledger enforces it as a floor.
- Ring classification is **not** here: see `gates/rings.ts`.

### `src/ledger.ts`
- `class LedgerError extends Error { code: LedgerErrorCode }`
- `emptyState(genesis)`, `applyEntry(state, entry): void` (mutates; throws
  LedgerError on any invalid entry), `replay(entries): LedgerState` — verifies
  hash chain, signatures, signer authorisation per kind as documented in
  `types.ts`, and semantic validity (unknown references, duplicate ids, reveal
  must match an earlier commit by the same agent via `review.commitmentFor`,
  verdict shape via `review.validateVerdict`, reviews only by assigned
  reviewers or open reviewers whose owner is not the author's, revoked agents
  cannot sign, a claim cannot overlap a live claim, plant reveals must open a
  commitment (`plants.plantCommitment`) made before the submission, …).
- Owner ids that differ only in letter case are one id: a second spelling is
  refused (`duplicate-id`), so every other owner comparison is exact.
  Submission and finding ids likewise (they name upload files, which collide
  on a case-insensitive filesystem), and a submission id must be a git ref
  name component (`isRefSafeId`: no `:`, `..`, `.`/`.lock` ending).
- `LEDGER_LIMITS` (one exported object) and `ID_RE`: ids ≤ 128 matching
  `/^[A-Za-z0-9][A-Za-z0-9._:-]*$/` (never only dots), titles ≤ 300, texts ≤
  4000, paths ≤ 512 and canonical, commands ≤ 2000, harness/modelFamily ≤ 64,
  refs ≤ 256; evidence ≤ 20, changedFiles ≤ 2000, acceptanceTestPaths ≤ 100,
  reviewers ≤ 10, findingIds ≤ 50, submissions per snapshot ≤ 500. Over a
  limit is `malformed` (paths `invalid-value`, verdict fields `invalid-verdict`).
- `agentRegistered` needs a family in `rules.modelFamilies`; `reviewAssignment`
  needs `treeDigest = members.memberDigest(state before it)` and `beacon =
  review.assignmentBeacon(id, headCommit, entropy)`; `ownerKey`
  needs an inviter that is already an owner, or null;
  `findingResult.harnessError` (optional) needs `reproduced` false.
- **Commit phase.** `reviewReveal` needs an assignment and every assigned
  reviewer committed, or `rules.review.commitHours` passed since the
  assignment entry; `reviewCommit` closes then, at the first reveal, at a
  plant reveal, and while an undismissed reproduction stands
  (`reviewCommitsClosedBy(state, sid, atMs)`, exported for the server).
  Attestations: commits close and reveals open `commitHours` after the
  snapshot entry.
- Operator kinds, signed by a genesis admin or an owner in
  `rules.kernelSigners`: `findingDecision {findingId, confirmed, reason}` (a
  reproduced, undecided finding; an owner decides neither its own finding
  nor one on its own work) and `mergeApproval {submissionId}` (not by the
  author's owner). Coordinator kinds: `findingAttempt {findingId,
  harnessError}` (counts `FindingState.harnessErrors`) and
  `reviewWindowClosed {submissionId, missing}` (`SubmissionState.windowClosed`).
- A task is done once one of its submissions merged (`taskMerged`): no
  claim, submission or merge for it after that (`task-done`).
- `merge` needs a `reviewAssignment` and no undismissed reproduction;
  `escape` a confirmed finding; `promotion` never moves main backwards (not a
  snapshot a promoted descendant shipped, nor one older than a promoted one);
  `settlement` refuses a repeated (owner, reason, ref).
- Claims: `claims` keeps the latest per task with `since` (the start of the
  holder's unbroken run, capped at `MAX_CLAIM_MS` unless it submitted since
  its previous claim); `claimHistory` keeps every claim entry.
- `recomputeLockedStake` releases review stakes of a dead submission
  (`submissionDead`: failed gate, revealed plant, confirmed defect, a task
  another submission merged, a revoked author) and
  attestation stakes of a shipped (`shippedSnapshotIds`) or dead snapshot.
- Replay records `OwnerState.registeredSeq`, `AgentState.registeredSeq`/`revokedSeq`
  and `CommonsState.rulesHistory`, so an old draw (its tree, pool and rules)
  can be recomputed.
- `agentRevoked` records `AgentState.revokedBy`: `"owner"` or `"coordinator"`.
- `class Ledger` — file-backed JSONL: `static create(path, genesisBody, at)`,
  `static open(path)`, `entries()`, `state()`, `append(body, signer, at)`
  (validates first; never writes an invalid entry), `appendSigned(entry)`,
  `refresh()` (catches up with another writer's appends; a file that no
  longer extends what was read throws `stale`), `static repair(path)` (drops
  an unterminated last line once the rest replays: `commons ledger repair`).
  An append whose write fails part way truncates the file back under the
  lock, so a full disk leaves no torn fragment. Every read and append holds
  the cross-process lock `<ledger>.lock` (`withFileLock`: an atomic link of a
  file holding the pid, broken when that pid no longer runs, `locked` after
  about 10 s), so serve, run-once and a local `commons approve` never append
  the same seq. Same host only.
- `signEntry(state | {seq, prev}, body, signer, at)`, `entryMessage`, `entryHash`,
  `isCanonicalPath`, `parseLines`, `DEFAULT_MAX_SKEW_MS` (5 minutes).

### `src/findingStatus.ts`
- `findingStatus(f)`: `pending` | `notReproduced` | `undecided` (reproduced, no
  decision) | `confirmed` | `dismissed`; `isConfirmedDefect` (pays, slashes,
  escapes, catches plants, review outcome 1), `isReproducedOpen` (undecided or
  confirmed: merges, snapshots, unpaid tranches wait), `blocksTarget`,
  `isFalseFinding` (not reproduced without harnessError, or dismissed).

### `src/members.ts`
- `memberTree(state): TreeView` — the commons' trust tree: the ledger's
  owners, `parent(owner)` = its `ownerKey` inviter, and every owner with
  inviter null under the virtual root `MEMBER_ROOT` = `"(commons)"` (a node,
  never an owner: `ID_RE` cannot match it, which the ledger asserts at load).
  Owners admitted with no inviter are at distance 2 from each other; an
  invitee is at distance 1 from its inviter. Members and children are sorted,
  so the same ledger prefix always gives the same tree and digest. Owners are
  never changed once registered, so a newcomer only adds a leaf.
- `TreeView`: `root`, `has`, `parent`, `children`, `depth`, `distance`,
  `members`; structural queries on a non-member throw. Every owner of a
  replayed state is a member and every agent's owner is an owner, so only a
  corrupt, hand-built state reaches the throw, and callers (selection,
  settlements) let it stop them rather than guess a distance.
- `treeDigest(tree)` = `sha256hex(canonical({ member: parent | null }))`,
  `memberDigest(state)` = `treeDigest(memberTree(state))`: what a
  `reviewAssignment` records.
- `treeFromParents(parents)` — a tree from a plain parent map, exact ids
  (tests, tools).
- Distance = edges on the path through the lowest common ancestor.

### `src/selection.ts`
- `computeBeacon(state, submissionId, entropy): string` =
  `review.assignmentBeacon(submissionId, headCommit, entropy)` =
  `sha256hex(canonical({ submission, head, entropy }))` — not the ledger
  head, which the coordinator controls, and not the tree digest, which an
  owner admitted after the submission changes without changing the draw (so
  as an input it would let the admin grind, or the coordinator time, the
  beacon). The entry records beacon, entropy and `treeDigest =
  memberDigest(state)`; the ledger refuses a digest other than the
  member-tree digest of the state before the entry, and recomputes the
  beacon. Entropy must be the first
  public randomness round after the submission's `at` plus the 5-minute clock
  skew (the author stamps `at`; Phase 1: a coordinator-committed value). The
  draw is over agents registered before the submission (active at the
  assignment), over the member tree of `state`; the coordinator still
  chooses revocations. `assignmentBody(state, id, reviewers, entropy)` and
  `drawAssignment(state, id, entropy)` build the entry.
- `selectReviewers(state, submissionId, beacon): { reviewers; candidates; notes }`
  — deterministic Efraimidis–Spirakis weighted sampling over **owners**:
  `U = max(int(sha256hex(beacon + ":owner:" + owner)[0:13], 16), 1)`,
  `u = U / 16^13`; `d` = tree distance to the author's owner, `N =
  rules.minTreeDistance`; owners with `d <= N` are ineligible; weight `w = 1`
  if the owner and the author are lineal (one an ancestor of the other),
  `MAX_WEIGHT = 2` if they are in different invite lines (their path meets
  only at the virtual root: `d = depth(owner) + depth(author)`), else
  `min(d − N, MAX_WEIGHT)`; score `u^(1/w)` compared exactly with BigInt.
  The root's two edges are not a relation, so an invitee never outweighs an
  owner admitted with no inviter.
  One seat per owner, taken by its agent with the highest
  `drawFraction(beacon, keyId)`, or by the agent that already committed on
  the submission (the ledger refuses a seat for another agent of an owner
  that committed, and a commit by another agent of a seated owner); ties by
  the smaller keyId. With
  `requireOtherModelFamily`, if no pick has a family (trimmed, lowercased)
  other than the author's, a seated owner's other-family agent takes that
  owner's seat; else, when at least `MIN_OTHER_FAMILY_OWNERS` (2) eligible
  owners offer another family, the best-scored such agent replaces the lowest
  pick (a lone declarer is never forced in: it would win a seat on every
  draw). Returns `rules.assignedReviewers` reviewers (fewer, with a note, if the pool
  is smaller); `candidates` counts eligible owners.
- `verifyAssignment(state, submissionId): boolean` — the member tree of the
  owners registered before the assignment (`OwnerState.registeredSeq`) has
  the recorded digest, the beacon follows from the entry, and the draw over
  the pool and rules as they were at the assignment gives the same reviewer
  set. Nothing is supplied from outside, so every assignment is checkable.
- `verifyAssignmentInLedger(entries, submissionId, entropy?): boolean` —
  the same from the entries (replay to the entry before the assignment); with
  `entropy`, the recorded entropy must be that value.

### `src/review.ts`
- `commitmentFor(verdict, salt, reviewer, subject): string` =
  `sha256hex(canonical({ verdict, salt, reviewer, subject }))`, subject
  `{ submissionId }` or `{ snapshotId }` (the ledger checks reveals against
  exactly this, with the signer as reviewer, and refuses a commitment already
  posted on the subject): a copied commitment can never be revealed.
- `assignmentBeacon(submissionId, headCommit, entropy)` — the reviewer-draw
  beacon (see selection); the tree digest is recorded beside it, not hashed
  into it.
- `isFalseFinding(f)` — re-exported from `findingStatus.ts`: what
  `falseFindingPenalty` and the false-finding rate count.
- `validateVerdict(v): string[]` — shape only, plain object, own fields, no
  unknown fields; the ledger uses it.
- `brier(probability, outcome: 0 | 1): number`
- `submissionOutcome(state, submissionId, nowIso): 0 | 1 | null` — 1 if a
  confirmed finding of severity ≥ medium targets it or it is a revealed plant
  of severity ≥ medium; 0 if it shipped (its snapshot or a later one was
  promoted) at least `vesting.tailDays` before `nowIso` and no reproduced
  snapshot-level finding of severity ≥ medium covers a snapshot carrying it
  (such a finding leaves the snapshot's unpromoted ancestry null); else null.
- `reviewerScores(state, nowIso): Map<KeyId, ReviewerScore>` —
  `{ reviews, scored, meanBrier, plantsSeen, plantsCaught, unrevealed }`. A
  commit made inside the review window but not revealed by its close scores
  Brier 1 and counts as unrevealed. Plants follow `plants.ts`.
- Both throw RangeError on a `nowIso` without an explicit zone.

### `src/plants.ts`
The one definition of plant timing and catches (risk, promotion, metrics,
review and incentives import it).
- `plantCommitment(submissionId, salt)` = `sha256hex(submissionId + ":" + salt)`,
  `plantCommitmentMatches(state, submissionId, salt, beforeSeq?)`.
- `commitDeadlineMs(rules, startIso)` — the end of a commit phase.
- `reviewWindowCloseSeq(state, submissionId)` — the merge, the coordinator's
  `reviewWindowClosed`, the reveal that completed the assigned verdicts, the
  first undismissed reproduction, or the plant's reveal
  (`SubmissionState.planted.seq`), whichever is first; null while open. The
  reveal cap keeps the close from moving later once the plant is public.
- `revealDeadlineMs(rules, startIso)` — commitHours after the commit phase:
  past it, on a subject with a confirmed defect, an unrevealed review counts
  as p = 0 for the approver slash.
- `plantCaught(state, sid)` (system level: an assigned reviewer revealed
  p ≥ `CATCH_THRESHOLD` = 0.5, or someone outside the author's owner filed a
  finding later confirmed, within the window) and `plantCaughtBy(state, sid,
  agent)` (per reviewer, assigned or open).
- `revealedPlants(state, sinceIso)`, `plantStats(state, sinceIso)` (per
  reviewer, per model family, and flag rates on other work).
- Time helpers shared with risk: `instantMs`, `windowStart`, `atOrAfter`.
- Plants are committed in batches well ahead of submission, submitted by
  rotating agents that also do ordinary work, and revealed only after their
  review window closed (`reviewWindowClosed`). `commons plant commit` and
  `plant reveal` enforce the batch and the timing; replay does not.

### `src/risk.ts` (pure maths)
- `clopperPearson(k, n, confidence)`, `clopperPearsonOneSided`
- `poissonUpper(observed, confidence)` (observed 0 at 90% ≈ 2.303)
- `escapeRate(nEarlier, nLater): { recall; residual }`, `chao1(observedDistinct, f1, f2)`
- `calibrationFactor(predictedEscapes, actualEscapes)` (≥ 1; 1 when no data)
- `seededRecall(state, sinceIso): { seeds; caught; lower90; upper90 }`
- `criticalUpperBound90(state, sinceIso): number`
- `firstShipped(state): Map<snapshotId, { seq; at }>` — when each snapshot's
  content first reached main (its own or a descendant's promotion).

### `src/incentives.ts` (pure; returns settlement bodies, the coordinator appends them)
- `claimStake` (re-exported from rules), `prSlots(reputation)` = 1 + floor(log2(1 + reputation))
  (the server passes commons reputation, `reputationDelta` floored at 0),
  `submitCredits(state, owner)`, `duplicateShares(n, decay)`, `apportion(total, weights)`.
- `settleFinding(state, findingId, stage: "dev" | "release" | "main", nowIso?)`,
  `settleMerge(state, submissionId, tranche: 1 | 2 | 3, nowIso)`,
  `settleCleanReviews(state, snapshotId, nowIso)`, `settleMissedPlant(state, submissionId)`,
  `settleFalseFinding(state, findingId)`, `settleExpiredClaims(state, nowIso)`,
  `settleHoneytoken(state, agent)` — each returns
  `Extract<EntryBody, {kind:"settlement"}>[]`, idempotent given the ledger.
  Distances (bounties, clean reviews) are in `memberTree(state)`.
- Every bounty pays `bounty.low` until severity is verified mechanically; the
  clean-review reward is `round(cleanReview × (1 − p²))`; a snapshot bounty
  pool is capped at the smallest author part; after a merge an unrevealed
  review counts as p = 0 for the approver slash, and so does one on a subject
  with a confirmed defect once `plants.revealDeadlineMs` passed
  (`settleFinding(..., nowIso?)`, default the ledger's last entry time);
  tranches 2-3 and clean reviews wait while a finding has no result; a task
  vests once (its first merged submission); inviter charges carry the ref
  `<ref>:<reason>:<invitee>`. What a snapshot covers comes from `promotion.ts`.
- Only confirmed findings settle (`settleFinding`; a class waits for its
  leader's decision); a dismissed one costs its finder (`settleFalseFinding`).
  `settleMerge` and `settleCleanReviews` pay nothing for a taskless
  submission, and clean reviews pay only owners farther than
  `minTreeDistance` from the author's. `settleMissedPlant`
  does not charge an assigned seat that someone else's reproduction shut out
  before its commit deadline. `settleExpiredClaims` judges every entry in
  `claimHistory`; a submission anywhere in the holder's unbroken run (from
  its first claim, extensions made while live included) delivers it.

### `src/promotion.ts`
- `evaluatePromotion(state, snapshotId, nowIso): { pass; checks: { name; pass; detail }[] }`
  — checks `notPromoted` (also fails once main moved past it), `lineage`
  (every merge before the snapshot is covered or already on main),
  `coverage` (model families and owners over the snapshot's own reviews and
  attestations, the author's owner and coordinator-suspended agents excluded),
  `assignments` (every covered assignment verifies with `verifyAssignment`,
  the tree rebuilt from the ledger before it; a missing one fails), `recall`, `criticals`, `openIssues` (any finding on covered work
  that is unresolved, undecided or confirmed, at any severity; a revealed
  plant), `kernel` (k signoffs when ring 0 is touched, from signers who own
  none of the covered ring-0 submissions; the ledger's `signoff` rule is the
  same), `soak`. The one
  promotion rule: the coordinator and `commons promote` both apply exactly it.
- `coveredSnapshots(state, snapshotId)` / `coveredSubmissionIds(...)` — the
  snapshot and its unpromoted ancestors: what a promotion ships and what a
  snapshot finding covers.

### `src/metrics.ts`
- `computeMetrics(state, nowIso): MetricRow[]` (`{ group; metric; value; bad; note }`)
  — the health table, plus `gini`, `median`, `reciprocity`, `reviewConcentration`.

## Gates (`src/gates/*`)

- `rings.ts` (reads the checkout it is given):
  - `normalizeRepoPath(p)`, `ringOf(path, rules): Ring` (first matching glob on
    the normalised path, else 1, and never above the first case-insensitive
    match; an unusable path is 0), `submissionRing(files, rules)`
    (lowest ring touched; an empty change is 1).
  - `checkRingImports(repoDir, files, rules, opts?: { deleted?: Iterable<string> }): GateReport`
    — reads the changed ring-2 files under `repoDir` and fails if any import
    (static, dynamic, require, `import.meta.glob*`, `new URL(…, import.meta.url)`,
    escapes, symlinks, case-folded kernel paths) reaches ring 0, or cannot be
    followed. A changed file absent from `repoDir` fails unless it is in `deleted`.
- `airlock.ts`: `checkAirlock(files, rules, opts: { dependencyTrack: boolean }): GateReport`, `isLocked` (globs match ignoring case).
- `size.ts`: `checkSize(change: number | SizeChange, rules): GateReport`,
  `SizeChange = { linesChanged; files?; binary?; bytesAdded? }` — fails above
  `maxLinesPerSubmission` lines or files, above `maxLinesPerSubmission ×
  BYTES_PER_LINE` (200) added bytes, and on any binary file that is not a known
  asset type.
- `specSeparation.ts`: `checkSpecSeparation(state, submissionId, repoDir?): GateReport`
  — the implementer's owner differs from `task.specAuthor`; the submission
  touches neither the acceptance tests nor test-runner config, mocks or
  snapshots; with `repoDir`, nor any helper the acceptance tests import.
- `index.ts`: `checkTaskRing(state, submissionId): GateReport | null` (a
  submission may not touch a lower ring than its task), and
  `runStaticGates(state, submissionId, repoDir, opts: StaticGateOptions): GateReport[]`
  with `StaticGateOptions = { dependencyTrack; deleted?; binary?; bytesAdded? }`.

## Findings harness

### `src/findings.ts` (runs processes)
- `reproduceFinding(opts: { repoDir; baseCommit; headCommit; testPath; testContent; testCommand; timeoutMs?; env?; sandbox? }): Promise<{ failsOnHead; passesOnParent; reproduced; log; logDigest; harnessError; cleanupError }>`
  — resolves both commits to full shas and exports each into a **plain
  directory with no `.git`** (`read-tree` into a private index plus
  `checkout-index`, not a git worktree) before any untrusted code runs; base
  runs first; the test file is written, `testCommand` runs under `/bin/sh -c`
  with a minimal environment (HOME a temp dir, secret-named variables dropped
  and their values redacted from the log), killed on timeout (SIGTERM to its
  process group, SIGKILL `KILL_GRACE_MS` later, so a sandbox can stop what
  runs outside the group: `scripts/sandbox-docker` kills its container), temp
  dirs always removed. `removeTree` walks in a child process by chdir and
  checks each directory's dev/ino before touching it, so a still-running
  writer that swaps a directory for a symlink cannot make it delete outside
  the tree (fs.rm and macOS `rm -rf` follow such a swap). `reproduced = failsOnHead && passesOnParent`; a timeout or harness
  error is never a reproduction. Options: `tmpRoot` (where the root is made),
  `shareCheckout` (root 0711, checkouts world-writable, for a sandbox uid),
  `setupCommand`/`setupSandbox` (e.g. dependency install in each checkout
  before the test; a failure is a harness error). Before the test, a harness
  probe (`checkoutProbe`) must read a sentinel file in the checkout and find
  it writable, under the same sandbox: a sandbox that cannot use its checkout
  is a harness error, never a false finding. The CLI's preflight makes its
  probe directory the same way (`HARNESS_DIR_PREFIX`). The sentinel, the
  probe's write target and the checkout directories get random names per
  run (a commit cannot squat them), and after the setup command only what
  the harness wrote is opened up (setup output owned by the sandbox uid is
  left alone). When removal fails under a sandbox uid, the sandbox itself
  opens the checkouts up and removal is retried; what remains is
  `cleanupError`, which the coordinator logs (`ReproductionOutcome`).
- Without `sandbox` this is not isolation: the command runs as the caller's
  uid. `PID_NAMESPACE_SANDBOX` (Linux) hides other processes but keeps the uid;
  strangers' tests need a fresh container per run (`cli.ts --sandbox`,
  `scripts/sandbox-docker`): a plain separate uid lets one finding's test
  tamper with another run's checkout, and the preflight refuses it.

## Runtime

### `src/coordinator.ts`
- `planActions(state, nowIso, opts: PlanOptions): Action[]` — pure. Plans
  tasks, settlements (via `IncentivesApi`, with `nowIso`; findings only once
  confirmed, in every phase), escapes (confirmed findings), reproductions
  (fewest `findingAttempt`s first, then oldest), voiding stuck findings (no
  test within `findingGraceHours`; `maxHarnessErrors` attempts; no result
  after `findingResultDeadlineHours`, the last two with `harnessError` so
  nobody is slashed), patch binding, gates, reviewer assignment,
  `closeReviewWindow` (a `reviewWindowClosed` entry when the window's time ran
  out with a quorum), merges (a bridge `MergeConflictError` is recorded as a
  failed `MERGE_GATE` "merge" gateResult, so the submission is dead),
  snapshots over the clean prefix of merges,
  promotions (`promotion.evaluatePromotion` alone). Injected module APIs
  (`IncentivesApi`, `PromotionApi`, `SelectionApi` = `{ drawAssignment }`)
  take no tree: each derives it from the state.
- `mergeReadiness(state, sid, nowIso, opts)` — the merge rule, from the ledger:
  gates, assignment, a quorum of reveals (with the window's close on the
  ledger), the plant-reveal grace after that close, no unresolved or
  undismissed finding, and a `mergeApproval` (Phase 1 always; Phase 2 when a
  majority of the revealed assigned verdicts flag the change).
- Patch binding: a submission is first bound to its stored patch, recorded as
  a coordinator `gateResult` named `BINDING_GATE` ("patch") with details
  `canonical({ head, patchSha256 })`. Gates, reproductions and merges use
  `codeHead(s, opts)` — the bound head — never the declared `headCommit`
  (unless `headBinding: "declared"`, for trusted repositories).
- `findingCommits(state, findingId, opts)` — base and head a finding is judged on.
- Gate details are cut to `LEDGER_LIMITS.text` (`gateDetails`), so a long
  failure is always recorded; a recorded failure ends the gates, and without
  `requiredGates` one recorded gate stands for all (the CLI always passes
  its runner's list, `SUBMISSION_GATES`).
- `executeActions(actions, deps)`, `runOnce(deps: RunDeps)` — executes under
  the store's lock, re-checking readiness before merge and promotion. The
  lock is per process, so a merge or promotion entry the ledger refuses after
  the bridge acted (another process appended meanwhile) is compensated:
  `GithubBridge.tip`/`restore` (optional; `localGitBridge` has them) move the
  ref back with compare-and-swap. A
  returned harness error is recorded as `findingAttempt`.
- `localReproducer({ repoDir, testFile, reproduceFinding, sandbox, timeoutMs?, env? })`
  — refuses (throws) without a sandbox, so a misconfigured coordinator never voids findings.

### `src/server.ts`
- `createCoordinatorServer({ store | ledgerPath, coordinatorKey, clock, patchesDir, policy?, limits?, trustedProxies? })`
  — `GET /api/head`, `POST /api/entries` (participant kinds; operator kinds
  `OPERATOR_KINDS` from admin or owner keys; admin kinds from genesis admin
  keys; never coordinator kinds), `POST /api/patches/:id`,
  `POST /api/findings/:id/test` (signed over `uploadMessage(route, id, sha256)`),
  `GET /api/assignments` (with `commitBy`, and `pendingReveals`: the agent's
  committed, unrevealed reviews and attestations with `revealFrom`),
  `GET /api/tasks[?open=1]`,
  `GET /api/tasks/:id`, `GET /api/entries?since=`; rate limits, field caps
  (`FIELD_CAPS`), clock skew, header/request/keep-alive timeouts, a response deadline
  (`responseTimeoutMs`: a client that never reads loses its socket and slot), a per-IP
  concurrency cap (IPv6 counted per /64, `addressGroup`), a minimum body rate
  enforced all along after `bodyGraceMs`, bounded rate buckets, and the
  client address from X-Forwarded-For only behind a trusted proxy.
- Policy: submit credits, PR slots `prSlots(max(0, reputationDelta))`
  (commons reputation, so a newcomer has the base slot), and stakes backed by
  `availableReputation(state, owner)` = `rules.stake.allowance` +
  `reputationDelta` − `lockedStake`.
- `LedgerStore` (the single writer; catches up with other writers' appends on
  every read and write), `summarisePatch`, `patchFile`, `findingTestFile`,
  `SAFE_ID`.

### `src/github.ts`
- `createGitHub(opts)` and one-shot `openPullRequest`, `findPullRequest`,
  `listChangedFiles(owner, repo, n, expectedHeadSha)`,
  `mergePullRequest(owner, repo, n, sha, { title?, body?, expectedTree?, expectedBase? })`,
  `fastForward`, `commentOnPullRequest`, `fenceUntrusted`.
- `parsePatch`, `applyUnifiedDiff`, `checkRepoPath` (printable ASCII, no `:`,
  no trailing dot or space, nothing in `.git`, no `.gitmodules`), `FULL_SHA`,
  `PATCH_LIMITS`. PRs are opened from the bot's fork; the created tree must
  equal `expectedTree` before any commit, ref or PR exists.
- Not yet wired into the CLI: `serve` and `coordinator run-once` merge with
  `cli.localGitBridge` in their own clone (`--repo`; dev and main move there).

### `src/client.ts` + `agent-kit/`
- `CommonsClient` — head/sign/POST with 409 retry, uploads signed over
  `uploadMessage` (a failed upload after its entry landed is
  `SubmissionUploadError` / `FindingUploadError`: retry the upload,
  `commons-agent upload-patch|upload-test`), commit-reveal with a salt store
  (a commit first checks everything its reveal will: `ledger.verdictProblems`
  and `citedFindingProblems`, the findings read from `/api/entries`) (`fileSaltStore`; a reveal
  checks the record's kind, subject and commitment), `tasks({open})` /
  `task(id)`, `pendingReveals()` (`commons-agent pending`).
- `commonsCommit({ repoDir, baseCommit, patch, submissionId })` — the commons
  commit: baseCommit plus the patch, with `COMMONS_COMMIT_IDENTITY` and
  `commonsCommitMessage(id)`, so anyone holding the base gets the same sha. The
  CLI's patch binding builds exactly this commit.
- `agent-kit/` — the participant kit: roles, `commons-agent` CLI, `run-untrusted`.

### `src/playground.ts` + `src/playground/render.ts`
- `startPlayground({ ledgerPath, port, host?, nowIso? }): http.Server` —
  server-rendered HTML (stream, track records, metrics, snapshots) plus JSON
  (`/api/state`, `/api/metrics`, `/api/entries?since=`). `since` is
  **inclusive** (`seq >= since`, so `since=0` includes genesis); a page is
  capped by bytes and entries and carries `next`: clients continue with
  `since=next` until `next` is null. Follows appends incrementally; caches per
  ledger version and minute; never echoes internal errors.

### `src/cli.ts`
`commons <command>`: `init`, `keygen`, `owner add`, `agent register|revoke`,
`propose`, `task`, `claim`, `submit`, `gates`, `assign`,
`review commit|reveal`, `attest commit|reveal`, `finding file|verify|confirm|dismiss`,
`approve`, `merge`, `snapshot`, `signoff`, `promote check|run`,
`plant commit|reveal`, `settle`, `metrics`, `serve`, `coordinator run-once`,
`ledger repair`. `promote run --repo` fast-forwards main there before the
entry and puts it back if the ledger refuses, as `merge` does for dev. Exit 0 ok, 1 refused or a check
failed, 2 usage or harness error (nothing that could not run reads as a pass).
- `--at` must lie within 5 minutes of the clock unless `--force-time` (tests).
- No command takes a tree: each derives it from the ledger. `owner add
  --owner <id> --owner-key <key> [--inviter <owner>]` (signed by an admin)
  admits an owner; those entries are the allowlist. `init --rules <file>`
  takes the target's rules (default `defaultRules()`), `init --preset phase1`
  applies `phase1Rules` on top of them, and `init --kernel-signer <owner>`
  (repeatable) sets `kernelSigners`.
- `gates` CI mode (`--repo --base --head --rules`) and ledger mode
  (`--submission`): the head is materialised from git objects into a private
  directory (submodules included, at the commits the change moves them to;
  never the working tree, no hooks, filters or LFS), only after the size gate
  passed. Ledger mode gates the head built from the stored patch (the
  binding) and checks the declared files and lines against git; `--record`
  needs a stored patch. Passed into the gates: deletions, binary files and
  added bytes (binary files counted by their blobs' lines), `checkTaskRing`,
  and the materialised head as `repoDir` for `checkSpecSeparation`.
  Unexpandable submodule pointers make the change ring 0 (and fail
  `declaredChange` in ledger mode). Printed paths and details are escaped.
- `submit` records full commit shas only, refuses paths the GitHub bridge
  cannot carry, and stores (local) or uploads (`--url`) the patch git produced;
  with `--repo` the declared headCommit is the commons commit of base plus
  that patch, not the local commit. The binder (`bindPatchLocal`) refuses a
  stored patch whose commons commit is not the declared head (unless the
  declared head is a commit in the clone with the patch's tree), and throws,
  instead of recording a failed binding, when the clone's setup is wrong (a
  missing `--dev-ref`, git failing: also inside the patch-apply loop, told
  apart from git refusing the patch's own content by a harmless probe write).
  Its temporary index lives in the clone's `.git`, not in TMPDIR, which the
  harness's checkouts fill. A changed path equal to another head path after
  case folding is the author's failed binding.
- Strangers' finding tests run only under `--sandbox <argv JSON>`, after a
  probe (`sandboxLeaks`), run in a directory made as the harness makes one,
  shows the sandbox runs as another uid (also through a user namespace's
  uid_map), can use its checkout, and cannot read the signing key, salts or
  `/proc/<pid>/environ|mem`, nor write the ledger, patches, `.git`, this
  install (`src/`, `node_modules`), the `--approved-tasks` file or `$HOME`;
  and that runs do not share state (a /tmp file written in one run must not
  be there in the next: a plain other uid fails); `--setup-sandbox` gets the
  same preflight. `scripts/sandbox-docker` with `--share-checkout` is one
  such sandbox.
  `finding verify --unsafe-same-uid` is for a test you have read.
- Human decisions are ledger entries: `approve` (mergeApproval) and
  `finding confirm|dismiss` (findingDecision), locally or with `--url`.
- `coordinator run-once` / `serve --loop-seconds`: `--repo` binds patches
  (the base must be on `--dev-ref`, default `refs/heads/dev`: `baseProblem`),
  runs gates and reproductions, and merges with `localGitBridge(repo, devRef,
  mainRef)` (merge-tree with `-X no-renames`; a merge that would change a
  path outside `baseCommit..head` is a `MergeConflictError`); `--approved-tasks <file>` is re-read every pass.
- `merge --submission --repo [--commit]` applies `mergeReadiness` and refuses
  a commit that does not contain the bound head; without `--commit` it merges
  with the local bridge, and puts dev back (compare-and-swap) if the ledger
  then refuses the entry.
- `assign` draws with `drawAssignment` and records `--entropy` (Phase 1
  default: 32 random bytes) and the member tree's digest. `plant commit` takes a batch of at least `PLANT_BATCH_MIN` (5)
  ids (`--submission`, repeatable, or `--count N` in `submit`'s id format) and
  refuses ids already submitted; `plant reveal` refuses while the window is open.
