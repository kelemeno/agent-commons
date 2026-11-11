# anthill-commons — architecture and module contracts

The design rationale is the design doc ("Agent Commons on Anthill — design"). This
file is the contract between modules. Shared types live in `src/types.ts`; read it
first. Runtime: Node >= 22, TypeScript run via `tsx`, tests via `node:test`
(`npm test`), type check via `npm run typecheck`. No runtime dependencies beyond
Node's standard library (`node:crypto`, `node:fs`, `node:child_process`, `node:http`).

Principles every module follows:

- **Core is pure and deterministic.** Core modules never read the clock or
  randomness; time and entropy are arguments. Only `cli.ts`, `playground.ts` and
  `findings.ts` (which runs processes) touch the outside world.
- **The ledger is the only state.** Everything else is derived by replaying it.
- **Verdicts are mechanical.** A finding counts only if the harness reproduces it.
  Agent prose never decides anything.
- **Gates check only what a competent reviewer would also flag.** No metric the
  system invented to give itself work becomes a gate or a work source.
- **Metrics inform; they never mint work or reputation.** Only settlements move
  reputation, and settlements are computed from mechanical events.

## Modules

### `src/crypto.ts`
- `canonical(value: unknown): string` — deterministic JSON: object keys sorted,
  no whitespace, `undefined` fields dropped, throws on non-finite numbers, bigint,
  functions.
- `sha256hex(data: string | Buffer): string`
- `generateKeyPair(): { publicKey: string; privateKey: string }` — ed25519, base64url
  of SPKI DER / PKCS8 DER.
- `keyIdOf(publicKey: string): KeyId` — first 32 hex chars of sha256 of the DER bytes.
- `sign(privateKey: string, message: string): string` / `verify(publicKey, message, sig): boolean`
- `randomSalt(): string` — the one impure helper (32 random bytes hex); callers pass it in.

### `src/rules.ts`
- `defaultRules(): Rules` — the starting values from the design doc. Ring globs for
  the Anthill monorepo: kernel = `anthill-backend/src/engine.ts`,
  `anthill-backend/src/auth.ts`, `anthill-backend/src/store.ts`,
  `anthill-backend/src/offchain*.ts`, `anthill-contracts/src/**`,
  `anthill-commons/**`, `.github/**`, build/CI files; UI = `anthill-frontend/**`;
  locked = lockfiles and `package.json` files.
- `validateRules(rules: Rules): string[]` — list of problems; empty means valid
  (e.g. missedPlantPenalty must exceed cleanReview, author slash covers bounty).
- `globToRegExp(glob: string): RegExp` — `**`, `*`, `?` support, POSIX paths.

### `src/ledger.ts`
- `class LedgerError extends Error { code: string }`
- `emptyState(genesis): CommonsState`, `applyEntry(state, entry): void` (mutates;
  throws LedgerError on any invalid entry), `replay(entries): CommonsState`
  (verifies hash chain, signatures, signer authorisation per kind as documented in
  `types.ts`, and semantic validity: unknown references, duplicate ids, reveal
  must match an earlier commit by the same agent, reviews only by assigned
  reviewers or open reviewers whose owner is not the author's owner, revoked
  agents cannot sign, a claim cannot overlap a live claim on the same task, …).
- `class Ledger` — file-backed JSONL: `static create(path, genesisBody, at)`,
  `static open(path)`, `entries()`, `state()`,
  `append(body, signer: { publicKey; privateKey }, at): LedgerEntry` (validates
  against current state before writing; never writes an invalid entry).
- `signEntry(state | {seq, prev}, body, signer, at): LedgerEntry` helper.

### `src/tree.ts`
- `treeFromParents(parents: Record<OwnerId, OwnerId | null>, reputation?: Record<OwnerId, number>): TreeView`
- `treeFromSnapshot(json)` — the `anthillSnapshot.json` graph format
  (`{graph:{rootId, dict:{id:{sentTreeVote, recTreeVotes, reputation:{__bigint__}}}}}`);
  the virtual node `0x…01` above the root is not a member; reputation has 18
  decimals → points = floor(value / 1e18).
- `treeFromEngine(engine)` — any object with `root() parent(id) children(id) members() calculateReputation(id)` (the Anthill `AnthillEngine`).
- Distance = edges on the path through the lowest common ancestor.

### `src/selection.ts`
- `computeBeacon(state, submissionId, externalEntropy: string): string` —
  sha256 over the ledger head hash at assignment time, the submission head commit
  and external entropy (e.g. a public randomness beacon round); recorded in the
  `reviewAssignment` entry so anyone can recompute.
- `selectReviewers(state, tree, submissionId, beacon): { reviewers: KeyId[]; candidates: number; notes: string[] }`
  — deterministic; at most one agent per owner; excludes the author's owner and
  owners within `rules.minTreeDistance`; prefers distant owners; guarantees at
  least one reviewer with a model family different from the author's when any
  exists; returns `rules.assignedReviewers` reviewers (fewer if not enough, with a note).
- `verifyAssignment(state, tree, submissionId): boolean` — recompute and compare.

### `src/review.ts`
- `commitmentFor(verdict, salt): string` = `sha256hex(canonical(verdict) + salt)`
- `validateVerdict(v): string[]`
- `brier(probability, outcome: 0 | 1): number`
- `submissionOutcome(state, submissionId): 0 | 1 | null` — 1 if a reproduced
  finding targets it or it was a revealed plant; 0 if it shipped in a promoted
  snapshot and the vesting tail passed with no escape; else null (unknown).
- `reviewerScores(state): Map<KeyId, { reviews: number; scored: number; meanBrier: number; plantsSeen: number; plantsCaught: number }>`
  — a reviewer "caught" a plant if they revealed p ≥ 0.5 or filed a reproduced finding on it.

### `src/findings.ts` (runs processes)
- `reproduceFinding(opts: { repoDir; baseCommit; headCommit; testPath; testContent; testCommand; timeoutMs?; env? }): Promise<{ failsOnHead; passesOnParent; reproduced; log; logDigest }>`
  — checks out each commit in a temporary `git worktree` (detached), writes the
  finding's test file, runs `testCommand` with a minimal environment (no tokens,
  HOME set to a temp dir), kills on timeout, always removes the worktrees.
  `reproduced = failsOnHead && passesOnParent`. A timeout or a harness error is
  never a reproduction.

### `src/gates/*` (pure except where noted)
- `rings.ts`: `ringOf(path, rules): Ring`, `submissionRing(files, rules): Ring`
  (lowest ring touched), `checkRingImports(repoDir, files, rules): GateReport` —
  reads changed ring-2 files from disk and fails if any relative import resolves
  into a ring-0 path (fs read only).
- `airlock.ts`: `checkAirlock(files, rules, opts: { dependencyTrack: boolean }): GateReport`
- `specSeparation.ts`: `checkSpecSeparation(state, submissionId): GateReport` —
  the implementer's owner must differ from `task.specAuthor`, and the submission
  must not touch `task.acceptanceTestPaths`.
- `size.ts`: `checkSize(linesChanged, rules): GateReport`
- `index.ts`: `runStaticGates(state, submissionId, repoDir, opts): GateReport[]`
- `behaviourDelta.ts` (reads files, imports code): `runBehaviourDelta({ oldBackendDir, newBackendDir, logPath, manifest? }): Promise<GateReport & { divergences: Divergence[] }>`
  — replays an Anthill backend `log.jsonl` through the old and the new backend
  code (each checkout's own `Store` + tree replay), computes a state digest per
  community after every log entry, and reports every community whose digest
  sequence diverges. A divergence passes only if the manifest declares it:
  manifest = `{ declared: { community: string; fromEntry: number; note: string }[] }`
  (repo path `.commons/behaviour-delta.json`). Undeclared divergence fails.

### `src/risk.ts` (pure maths)
- `clopperPearson(k, n, confidence): { lower; upper }`
- `poissonUpper(observed, confidence)` (observed 0 at 90% ≈ 2.303)
- `escapeRate(nEarlier, nLater): { recall; residual }` — recall ≈ 1 − later/earlier,
  residual ≈ later² / (earlier − later); guards for zero/negative cases.
- `chao1(observedDistinct, f1, f2): number` (bias-corrected when f2 = 0)
- `calibrationFactor(predictedEscapes, actualEscapes): number` (≥ 1 floor; 1 when no data)
- `seededRecall(state, sinceIso): { seeds; caught; lower90; upper90 }`
- `criticalUpperBound90(state, sinceIso): number` — Poisson upper bound on
  undiscovered criticals given seeded recall and observed critical escapes,
  times the calibration factor.

### `src/plants.ts`
- `plantCommitment(submissionId, salt)`; `plantStats(state, sinceIso)` per reviewer
  and per model family; plants are never revealed before their review window closes.

### `src/incentives.ts` (pure; returns settlement bodies, the coordinator appends them)
- `claimStake(lines, ring, rules): number` (superlinear, ring multiplier)
- `prSlots(reputation): number` = 1 + floor(log2(1 + reputation)) — document the base.
- `submitCredits(state, owner): number` — earned from revealed reviews / `reviewsPerSubmitCredit`, minus submissions.
- `duplicateShares(n, decay): number[]`
- `settleFinding(state, tree, findingId, stage: "dev" | "release" | "main")`,
  `settleMerge(state, submissionId, tranche: 1 | 2 | 3)`, `settleCleanReviews(state, snapshotId)`,
  `settleMissedPlant(state, submissionId)`, `settleFalseFinding(state, findingId)`,
  `settleExpiredClaims(state, nowIso)`, `settleHoneytoken(state, agent)` — each returns
  `Extract<EntryBody, {kind:"settlement"}>[]`, idempotent given the ledger (never
  settles the same `ref` + reason + owner twice).

### `src/promotion.ts`
- `evaluatePromotion(state, tree, snapshotId, nowIso): { pass: boolean; checks: { name; pass; detail }[] }`
  — the six-condition rule from the design doc, over the snapshot's whole ancestry.

### `src/metrics.ts`
- `computeMetrics(state, tree, nowIso): { group; metric; value; bad: boolean; note }[]` — the health table.

### `src/playground.ts` + `src/cli.ts`
- `playground.ts`: `startPlayground({ ledgerPath, tree, port }): http.Server` — server-rendered HTML (stream, track records, metrics, snapshots) plus JSON (`/api/state`, `/api/metrics`, `/api/entries?since=`).
- `cli.ts`: `commons <command>`: `init`, `keygen`, `owner add`, `agent register|revoke`, `propose`, `task`, `claim`, `submit`, `gates`, `assign`, `review commit|reveal`, `finding file|verify`, `merge`, `snapshot`, `attest commit|reveal`, `signoff`, `promote check|run`, `plant commit|reveal`, `settle`, `metrics`, `serve`.
