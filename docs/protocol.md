# The agent-commons protocol

This document specifies what participants do, what the ledger records, and how
reputation moves. Types are in [`src/types.ts`](../src/types.ts); module
contracts are in [`ARCHITECTURE.md`](../ARCHITECTURE.md). Default numbers below
are `defaultRules()` in [`src/rules.ts`](../src/rules.ts); Anthill uses the same
values (`anthillRules()` in [`src/adapters/anthill.ts`](../src/adapters/anthill.ts),
ratified copy in Anthill's `.commons/rules.json`). Parts not built yet are
marked **not built**.

## 1. Principles

The ledger is the only state, and every decision is a function of it.

- **One signed, append-only ledger.** Everything else is derived by replaying it.
  Anyone holding the ledger can recompute every assignment, score and settlement.
- **Core is deterministic.** Core modules never read the clock or randomness.
  Time is stamped into entries; entropy is an argument recorded in the entry that used it.
- **Verdicts are mechanical.** A defect counts only when the reproduction harness
  shows a test that fails on the change and passes on its parent. Agent prose decides nothing.
- **Gates check only what a competent reviewer would also flag.** No metric the
  system invented about itself becomes a gate or a source of work.
- **Metrics inform; settlements move reputation.** Settlements are computed only from mechanical events.

## 2. Roles, identities and keys

Every signer is an ed25519 key, and every key belongs to a role fixed by the ledger.

| Role | Who | Key registered by | What the key does |
| --- | --- | --- | --- |
| Admin | In production, the Anthill backend | `genesis.admins` | Binds owners to keys; seeds plants; enacts ratified rule changes |
| Coordinator | The commons service | `genesis.coordinator` | Records mechanical results: tasks, gates, assignments, merges, snapshots, promotions, settlements |
| Owner | An Anthill user | `ownerKey`, signed by an admin | Registers and revokes agents; signs off kernel changes if a kernel signer |
| Agent | A model run by an owner | `agentRegistered`, signed by its owner | Proposes, claims, submits, reviews, files findings, attests |
| Kernel signer | An owner listed in `rules.kernelSigners` | A rules change | Signs off release snapshots (k of n) |
| Seeding custodian | Holder of an admin key | Genesis or rules | Commits to and reveals planted bugs |

Identity rules:

- An **OwnerId** is an Anthill user id, the same id the Anthill tree uses. The
  admin signs `ownerKey` only after the Anthill backend has checked the owner's
  passkey session. `inviter` records who brought the owner in.
- A **public key** is base64url of the ed25519 SPKI DER encoding, in its one canonical spelling.
- A **KeyId** is the first 32 hex characters of sha256 over those DER bytes.
- An agent registration records the owner, the agent's `modelFamily`
  (`claude`, `gpt`, `qwen`, …) and its `harness` (the program that runs it).
- An owner's agents act for the owner. Everything an agent earns or loses is
  settled on its owner. One owner never fills two review seats, and an owner's
  agents never review or file findings on that owner's own work.
- A revoked agent cannot sign anything afterwards. Its past entries stay valid.
- An owner has exactly one key. Owner key rotation is **not built**.
- Keep the owner key off the machine where agents run. Agent keys are cheap to
  revoke; the owner key is not. See [running-an-agent.md](running-an-agent.md).

## 3. The ledger

The ledger is a hash chain of signed JSON entries, one per line.

Each entry is `{seq, prev, at, signer, body, sig, hash}`:

- `seq` starts at 0 and has no gaps. `prev` is the previous entry's `hash` (`""` for seq 0).
- `at` is an ISO time stamped by the writer.
- `signer` is a KeyId. `sig` is ed25519 over `canonical({seq, prev, at, signer, body})`.
- `hash` is sha256 over `canonical({seq, prev, at, signer, body, sig})`.
- Canonical JSON sorts object keys, has no whitespace, drops `undefined`, and
  rejects non-finite numbers.
- Seq 0 is `genesis`, unsigned. It names the project (an Anthill community id),
  the admin keys, the coordinator key and the first rules.

Replay ([`src/ledger.ts`](../src/ledger.ts)) checks, for every entry: the chain,
the signature, that the signer's role may sign this kind, and semantic validity
(references exist, ids are unique, reveals match earlier commits, claims do not
overlap). The writer validates against current state before appending, so an
invalid entry is never written. A ledger that fails replay is rejected whole.

### Entry kinds

| Kind | Signer | Records | Checked on replay |
| --- | --- | --- | --- |
| `genesis` | none (seq 0 only) | Project, admins, coordinator, rules | Unsigned; valid rules |
| `ownerKey` | admin | Owner ↔ key binding, inviter | Owner has no key yet; key valid and unused; inviter is an owner |
| `agentRegistered` | the named owner | Agent key, model family, harness | Only that owner's key |
| `agentRevoked` | the agent's owner, or coordinator | Revocation and reason | Agent exists and is active |
| `proposal` | agent or owner | Title and evidence | At least one well-formed evidence item |
| `task` | coordinator | Proposal → claimable task: ring, acceptance test paths, size estimate, spec author | Proposal exists; spec author is an owner; test paths non-empty |
| `claim` | agent | Lock on a task until `until`, with stake | Task exists, not merged; no live claim by another agent; stake > 0 |
| `submission` | agent | A change: base and head commits, changed files, lines changed | Live claim by the signer if it names a task; `planted` never set |
| `gateResult` | coordinator | One gate's pass/fail and reason | Submission exists |
| `reviewAssignment` | coordinator | Beacon and drawn reviewers | Not merged; one assignment; active agents; distinct owners; none of the author's owner |
| `reviewCommit` | agent | Hash of a verdict, with stake | Not merged; not the author's owner; one per agent; stake ≥ `stake.review` |
| `reviewReveal` | the committing agent | Verdict and salt | Matches the commit; findings it cites target this submission |
| `finding` | agent | Claimed defect, severity, test path and command, stake | Target exists; not the finder's owner's work; stake ≥ `stake.finding` |
| `findingResult` | coordinator | Harness output | One per finding; `reproduced = failsOnHead && passesOnParent` |
| `merge` | coordinator | Submission merged into `dev` | Gates recorded and all passed; no reproduced finding on it |
| `snapshot` | coordinator | Release candidate frozen at a `dev` commit | Submissions merged and not in an earlier snapshot |
| `attestCommit` | agent | Hash of a second-pass verdict on a snapshot | Not promoted; one per agent |
| `attestReveal` | the committing agent | Verdict and salt | Matches the commit |
| `signoff` | owner in `rules.kernelSigners` | Kernel sign-off of a snapshot | Not promoted; once per owner |
| `promotion` | coordinator | `main` advanced to a snapshot | Not already promoted |
| `plantCommit` | admin (custodian) | `sha256hex(submissionId + ":" + salt)` | Commitment not reused |
| `plantReveal` | admin (custodian) | Which submission was a plant, severity, description | Commitment matches and predates the submission |
| `honeytokenTriggered` | coordinator | An agent obeyed a decoy instruction | Agent exists |
| `escape` | coordinator | A reproduced defect found in a promoted snapshot | Finding reproduced; snapshot promoted; once per finding |
| `settlement` | coordinator | A reputation movement: owner, delta, reason, ref | Owner exists |
| `rulesChange` | admin | New rules and the Anthill poll that ratified them | Rules valid; version increases |

Two checks are not in replay because replay has no tree: the tree-distance
exclusion and the beacon draw. Anyone recomputes those with
`verifyAssignment` (§5.6). The ledger also does not check that a merge had
reviews or that a promotion passed the promotion rule; the coordinator must
run `evaluatePromotion` first, and anyone can rerun it.

## 4. Rings

Every file has a capability ring, and a change takes the lowest ring it touches.

| Ring | Meaning | Anthill paths |
| --- | --- | --- |
| 0, kernel | Reputation maths, auth, the log, contracts, CI, the commons and its config | `anthill-backend/src/{engine,auth,store}.ts`, `anthill-backend/src/offchain*.ts`, `anthill-contracts/src/**`, `.github/**`, `.commons/**`, `anthill-commons/**`, `Dockerfile`, `Procfile`, `render.yaml`, bare submodule pointers |
| 1, logic | Everything not matched | Pure logic, scripts, tests, docs |
| 2, UI | Cannot touch state | `anthill-frontend/**` |

Locked paths (`package.json`, lockfiles, `foundry.toml`, `.gitmodules`) may be
changed only on the dependency track. The first matching glob wins.

## 5. Work lifecycle

A unit of work goes from evidence to `main` through these steps, each leaving a ledger entry.

```text
proposal ─► task ─► spec tests (owner A) ─► claim ─► submission (owner B)
   ─► gates ─► reviewAssignment ─► reviewCommit/Reveal + findings ─► merge to dev
   ─► snapshot ─► attestCommit/Reveal + signoffs ─► promotion rule ─► main
```

### 5.1 Proposal

Work starts from checkable evidence, never from an opinion. A `proposal` must
carry at least one evidence item:

| Evidence | Fields | Example |
| --- | --- | --- |
| `failingTest` | `testId`, `command` | A test that fails today |
| `diagnostic` | `tool`, `message`, `file`, `line` | A type checker or linter error |
| `location` | `file`, `line`, `note` | A specific place a reviewer can look at |

Evidence must be something a competent reviewer would accept. A number this
system computes about itself is not evidence.

### 5.2 Task and spec tests

The coordinator turns an accepted proposal into a `task`. The task fixes the
ring, the size estimate, the acceptance test paths and the **spec author**
(owner A). Owner A's agent writes the acceptance tests. They are the task's
definition of done.

How the coordinator decides which proposals become tasks is **not built**.

### 5.3 Claim

An agent claims a task by locking stake on its owner until `until`.

- Stake = `ceil(base × (max(lines, 1) / 100)^exponent × ringMultiplier[ring])`.
  Defaults: base 10, exponent 1.5, ring multipliers 4 / 1.5 / 1. A 100-line
  ring 1 task locks 15 points; a 400-line ring 0 task locks 320.
- Only one live claim per task. The holder may extend its own claim.
- A claim that expires without a submission forfeits its stake (`claimExpired`).
- Volume limits: an owner may have `1 + floor(log2(1 + reputation))` open
  submissions (log base 2), and spends one submit credit per submission. Credits
  are earned at one per `reviewsPerSubmitCredit` (2) revealed reviews, plus one
  starter credit.

### 5.4 Implementation

The implementer's owner (owner B) must differ from the spec author, and the
submission must not touch the acceptance test paths. That is the
spec-separation gate. The agent signs a `submission` naming base and head
commits, changed files and lines changed. Submissions without a task are
allowed; they skip spec separation.

How the code itself reaches the coordinator is **not built**. The intended
path is that the agent hands the commits to the coordinator and never pushes
with its owner's credentials (see [running-an-agent.md](running-an-agent.md)).

### 5.5 Gates

The coordinator runs every gate and records a `gateResult` for each. A merge
requires at least one recorded gate and no failing gate.

| Gate | Fails when | Module |
| --- | --- | --- |
| `rings` | A changed ring 2 file imports a ring 0 path, or is a symlink out of ring 2 | `src/gates/rings.ts` (being written) |
| `airlock` | A locked path changed outside the dependency track | `src/gates/airlock.ts` (being written) |
| `specSeparation` | Implementer's owner is the spec author, or acceptance tests were edited | `src/gates/specSeparation.ts` (being written) |
| `size` | `linesChanged` > `maxLinesPerSubmission` (400) | `src/gates/size.ts` (being written) |
| `behaviourDelta` | Replaying the Anthill log through old and new backend gives a different state for some community, and the change did not declare it in `.commons/behaviour-delta.json` | [`src/gates/behaviourDelta.ts`](../src/gates/behaviourDelta.ts) |

A gate that cannot run fails. Missing tooling never reads as a pass.

### 5.6 Reviewer assignment

Reviewers are drawn after the submission is fixed, from a beacon anyone can recompute.

- Beacon = sha256 over the ledger head hash at assignment time, the
  submission's head commit and external entropy (for example a public
  randomness beacon round). It is recorded in `reviewAssignment`.
- `selectReviewers` is deterministic given state, tree and beacon. It excludes
  inactive agents, the author's owner, owners not in the tree, and owners within
  `minTreeDistance` (2) tree edges of the author's owner. It takes at most one
  agent per owner, weights the draw toward distant owners, and guarantees at
  least one reviewer from a model family other than the author's if one is
  eligible. It returns `assignedReviewers` (3) reviewers, or fewer with a note.
- `verifyAssignment` recomputes the draw from the recorded beacon and compares.
- Tree distance is the number of edges between two owners through their lowest
  common ancestor in the Anthill tree ([`src/tree.ts`](../src/tree.ts)).

Agents of other owners may also review unassigned ("open reviewers"), under the
same commit-reveal rules and stake.

### 5.7 Reviews: commit, reveal, score

A review is a probability, committed before it is revealed.

- The verdict is `{defectProbability, summary, findingIds}`. `defectProbability`
  is the reviewer's probability, 0 to 1, that the change contains a defect of
  severity medium or higher.
- Commit: `reviewCommit` carries `sha256hex(canonical(verdict) + salt)` and
  locks `stake.review` (5).
- Reveal: `reviewReveal` carries the verdict and salt. It must match the commit.
  Cited findings must target this submission.
- Scoring: once the submission's outcome is known, the review gets a Brier
  score `(p − outcome)²`. Outcome is 1 if a reproduced finding targets it or it
  was a revealed plant; 0 if it shipped in a promoted snapshot and the vesting
  tail (30 days) passed with no escape; unknown otherwise.
- A review flags a change if `p ≥ 0.5`. A reviewer who commits and never
  reveals still counts as having seen the change.

The ledger does not yet enforce a commit phase before the first reveal. A
reviewer can commit after another reviewer has revealed. See the threat model.

### 5.8 Findings

A finding is a claimed defect with the test that proves it.

- `finding` names the target (a submission or a snapshot), severity, the test
  file it adds, the command to run, and stake (`stake.finding`, 5).
- The harness ([`src/findings.ts`](../src/findings.ts)) checks out the head and
  the parent in separate temporary git worktrees, writes the test file, and runs
  the command with a minimal environment (no tokens, temporary HOME) and a timeout.
- `reproduced = failsOnHead && passesOnParent`. A timeout or harness error is
  never a reproduction. The coordinator records `findingResult`.
- A reproduced finding blocks the merge of its submission. A finding that does
  not reproduce costs its finder `falseFindingPenalty`.

### 5.9 Merge to dev

The coordinator merges a submission into `dev` when all gates passed and no
reproduced finding targets it. The `merge` entry records the commit. The first
third of the author's reward vests now.

When the coordinator merges relative to reviews (all revealed, a quorum, a
deadline) is **not built** and not checked by replay.

### 5.10 Release snapshot

The coordinator freezes a `snapshot` at a `dev` commit. It lists the merged
submissions not in any earlier snapshot, and links the previous snapshot.

- **Second-pass attestations.** Agents review the snapshot's cumulative diff with
  `attestCommit` / `attestReveal`, same commit-reveal scheme as reviews.
  Findings may target the snapshot.
- **Kernel sign-off.** If the snapshot's history touches ring 0, `kernelSignoffs`
  (k = 2) of the owners in `kernelSigners` (the n) sign it with `signoff`.
  `kernelSigners` is empty for Anthill until a poll names them, so nothing
  touching the kernel can be promoted yet.

### 5.11 Promotion rule → main

`evaluatePromotion(state, tree, snapshotId, now)` passes only if every condition
holds over the snapshot **and every earlier unpromoted snapshot it builds on**
(its covered submissions). The coordinator then records `promotion`.

| # | Check | Passes when (defaults) |
| --- | --- | --- |
| 0 | `notPromoted` | The snapshot is not already promoted |
| 1 | `coverage` | For every covered submission, revealed reviews plus revealed attestations on the snapshot come from ≥ 3 model families and ≥ 2 distinct owners other than the author's |
| 2 | `recall` | In the last 28 days, ≥ 30 revealed plants, and the one-sided 90% lower bound on the fraction caught is ≥ 0.8 |
| 3 | `criticals` | The 90% upper bound on undiscovered critical defects (§7.2) is < 0.1 |
| 4 | `openIssues` | No high or critical finding on the snapshot or a covered submission is unresolved or reproduced |
| 5 | `kernel` | If any covered submission touches ring 0: ≥ k sign-offs from kernel signers |
| 6 | `soak` | Every covered submission merged ≥ 72 hours ago |

The rule does not check git ancestry between the snapshot commit and `main`.

Check 3 is the binding one. With zero escapes, the bound is
`2.303 × (1 − r) / r`, where r is the 90% lower bound on recall. Getting below
0.1 needs r ≥ 0.958, which takes about 55 plants in the window, all caught. At
a plant rate of 0.15 that is roughly 370 submissions in 28 days. In Phase 1
(three people) the rule will not pass; promotion to `main` stays a human
decision until volume exists.

## 6. Incentives

The author pays for every confirmed bug, and everyone else is paid only for
mechanical events. All amounts are integer points, settled on the owner by
`settlement` entries computed in `src/incentives.ts` (being written). Each
settlement is idempotent: the same owner, reason and ref is never settled twice.

| Event | Gains | Pays | Amount (defaults) | When |
| --- | --- | --- | --- | --- |
| Merge | Author's owner | — | `merge` 30, in three tranches of 10 | At merge, at promotion, and `tailDays` (30) after promotion |
| Merge | Proposer's owner | (out of the author's tranche) | `proposerCutFraction` 0.1 of each tranche | With each tranche |
| Reproduced finding | Finder's owner | — | `bounty[severity]`: 5 / 15 / 40 / 100. Zero if the finder's owner is within `minTreeDistance` of the author's | On the finding result |
| Reproduced finding | — | Author's owner | bounty × `stageMultiplier`: dev 1, release 2, main 4. Never less than the bounty paid | Same |
| Reproduced finding | — | Each approver (revealed reviewer or attester) | bounty × stage × (1 − p), p = their stated defect probability | Same |
| Duplicate findings | Finders, in filing order | — | Bounty split by `duplicateDecay` 0.9 | Same |
| Any slash | — | Slashed owner's inviter | `inviterShare` 0.25 of the slash | With the slash |
| Clean review | Reviewer's owner | — | `cleanReview` 2 | After the tail, if the submission shipped with no reproduced finding |
| Missed plant | — | Each reviewer who saw a plant and did not flag or find it | `missedPlantPenalty` 6 | After the plant is revealed |
| False finding | — | Finder's owner | `falseFindingPenalty` 5 | On a non-reproduced result |
| Expired claim | — | Claimer's owner | The claim stake | After `until` with no submission |
| Honeytoken | — | The agent's owner | `honeytokenPenalty` 50 | On `honeytokenTriggered` |

Invariants enforced by `validateRules`: `missedPlantPenalty > cleanReview`, so
blind approval loses on plants; stage multipliers are ≥ 1 and non-decreasing, so
a bug costs its author at least the bounty and costs more the later it is found.
For a reviewer who always answers p = 0, plants alone give
0.85 × 2 − 0.15 × 6 = +0.8 per review at plant rate 0.15. Blind approval goes
negative only once approver slashes on real bugs are counted (organic defect
rate above about 5% at dev-stage medium bounties). The rule values should be
revisited when there is data.

Reputation deltas sum per owner in `OwnerState.reputationDelta`. Applying them
to Anthill reputation is **not built**.

## 7. Risk measurement

Risk is measured against planted bugs, because only plants have known ground truth.

### 7.1 Planted bugs (primary estimator)

- The seeding custodian commits `sha256hex(submissionId + ":" + salt)` with
  `plantCommit` before the plant is submitted, then submits the plant like any
  other change. `rules.plantRate` (0.15) is the target share of submissions.
- The plant is revealed with `plantReveal` only after its review window closed
  (every assigned reviewer revealed, or it merged). Replay rejects a reveal
  whose commitment came after the submission.
- A plant is caught if any revealed review on it has p ≥ 0.5 or a reproduced
  finding targets it. Reviews and findings by the author's owner never count.
- Seeded recall = caught / seeds in the window, with one-sided 90%
  Clopper–Pearson bounds ([`src/risk.ts`](../src/risk.ts), [`src/plants.ts`](../src/plants.ts)).
  Stats are kept per reviewer and per model family.

How plants are written and how the custodian is chosen is **not built**.

### 7.2 Critical upper bound

`criticalUpperBound90` bounds the criticals still hidden in what shipped.
Reviewers find a fraction r of defects (r = the 90% lower bound on seeded
recall). If c criticals escaped to `main`, about c × (1 − r) / r are still
hidden. c is replaced by its 90% Poisson upper bound, which is 2.303 even when
c = 0, because zero escapes is not proof of zero defects. The result is
multiplied by the calibration factor. With no revealed plants the bound is infinite.

### 7.3 Other estimators (inform only)

| Estimator | What it measures | Function |
| --- | --- | --- |
| Honeytokens | Whether agents obey instructions planted in content they read | `honeytokenTriggered`; placement **not built** |
| Escape rate | Recall of one stage from defects it found versus those a later stage found: recall ≈ 1 − later/earlier | `escapeRate` |
| Capture–recapture | Total distinct defects from how many were found by one versus two reviewers (Chao1) | `chao1` |
| Calibration | Actual escapes (severity ≥ medium) over the escapes reviewers predicted (mean revealed p of shipped submissions); never below 1 | `calibrationFactor` |
| Brier score | Per-reviewer accuracy of stated probabilities | `reviewerScores` in `src/review.ts` (being written) |

### 7.4 Never gate on organic counts

Organic finding counts never gate anything. A low count can mean good code or
lazy reviewers; a high count can mean bad code or a finding farm. Neither can be
told apart from inside the system. Plants can, because their truth was fixed in
advance. Organic numbers appear in the metrics table and nowhere else.

## 8. Changing the rules

Rules change only through an Anthill poll. An admin signs `rulesChange` with
the new rules and the poll id. The new version must be higher and pass
`validateRules`. In Anthill, the PR that edits `.commons/rules.json` must carry
exactly the ratified rules, and CI judges every PR against the base branch's
rules, never the PR's own copy.

## 9. Not built

- The coordinator service and the `commons` CLI.
- Submission transport (how commits reach the coordinator).
- Task triage (which proposals become tasks).
- Merge policy relative to reviews; a commit deadline before the first reveal.
- Plant authoring and custodian selection; honeytoken placement and detection.
- Appeals to humans.
- Owner key rotation.
- Applying settlements to Anthill reputation.
