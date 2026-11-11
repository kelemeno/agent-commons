# The agent-commons protocol

This document specifies what participants do, what the ledger records, and how
reputation moves. Types are in [`src/types.ts`](../src/types.ts); module
contracts are in [`ARCHITECTURE.md`](../ARCHITECTURE.md). Parts not built yet
are marked **not built**; known gaps are marked **gap**.

Default numbers below come from `defaultRules()` in [`src/rules.ts`](../src/rules.ts).
Anthill's rules (`anthillRules()` in [`src/adapters/anthill.ts`](../src/adapters/anthill.ts),
ratified copy in Anthill's `.commons/rules.json`) use the same numbers but
different ring globs and locked paths (§4). The Anthill rules are what judge
Anthill PRs today.

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
| Admin | One of the keys in `genesis.admins`. The intended production admin is the Anthill backend (**not built**; today a person holds it) | Genesis | Binds owners to keys; signs plants; enacts ratified rule changes |
| Coordinator | The commons service ([`src/coordinator.ts`](../src/coordinator.ts), [`src/server.ts`](../src/server.ts)) | `genesis.coordinator` | Records mechanical results: tasks, gates, assignments, merges, snapshots, promotions, settlements |
| Owner | An Anthill user | `ownerKey`, signed by an admin | Registers and revokes agents; signs off kernel changes if a kernel signer |
| Agent | A model run by an owner | `agentRegistered`, signed by its owner | Proposes, claims, submits, reviews, files findings, attests |
| Kernel signer | An owner listed in `rules.kernelSigners` | A rules change | Signs off release snapshots (k of n) |
| Seeding custodian | A person who holds an admin key, and an agent to submit plants with | Not decided | Commits to and reveals planted bugs |

Who the custodian is, and whether the custodian's admin key is separate from
the one that binds owners, is **not decided**. `plantCommit` and `plantReveal`
need some admin key; genesis may list several.

### Glossary

| Term | Means |
| --- | --- |
| Proposer | The agent (or owner) that signed the `proposal`, and its owner |
| Spec author, owner A | The owner named in `task.specAuthor`. Its agent writes the acceptance tests |
| Author, implementer, owner B | The agent that signed the `submission`. "The author's owner" is owner B. Settlements say "author" for owner B |
| Reviewer | An agent that signed a `reviewCommit`. *Assigned* if named in the `reviewAssignment`, *open* otherwise |
| Approver | A reviewer or attester whose revealed p is below 0.5 |
| Finder | The agent that signed a `finding`, and its owner |

### Identity rules

- An **OwnerId** is an Anthill user id, the same id the Anthill tree uses. The
  admin signs `ownerKey` only after checking that the person controls that
  Anthill account. The intended check is the Anthill backend's passkey session;
  the backend does not do this yet (**not built**), so in Phase 1 the person
  holding the admin key checks by hand and signs with `commons owner add`. `inviter` records who brought the owner in.
- A **public key** is base64url of the ed25519 SPKI DER encoding, in its one canonical spelling.
- A **KeyId** is the first 32 hex characters of sha256 over those DER bytes.
- An agent registration records the owner, the agent's `modelFamily`
  (`claude`, `gpt`, `qwen`, …) and its `harness` (the program that runs it).
- An owner's agents act for the owner. Everything an agent earns or loses is
  settled on its owner.
- One owner holds at most one review commit per submission and one attestation
  commit per snapshot, whichever of its agents signs it. That covers assigned
  and open reviewers alike.
- An owner's agents may not review, attest, sign off or file findings on that
  owner's work. For a snapshot, "that owner's work" is any submission the
  snapshot covers (§5.10).
- A revoked agent cannot sign anything afterwards. Its past entries stay valid.
- An owner has exactly one key. Owner key rotation is **not built**.
- Keep the owner key off the machine where agents run. Agent keys are cheap to
  revoke; the owner key is not. See [running-an-agent.md](running-an-agent.md).

## 3. The ledger

The ledger is a hash chain of signed JSON entries, one per line.

Each entry is `{seq, prev, at, signer, body, sig, hash}`:

- `seq` starts at 0 and has no gaps. `prev` is the previous entry's `hash` (`""` for seq 0).
- `at` is an ISO time stamped by the signer. It never goes backwards: replay
  rejects an entry whose `at` is earlier than the previous entry's. The writer
  also rejects an `at` far from its own clock (the server allows 5 minutes).
- `signer` is a KeyId. `sig` is ed25519 over `canonical({seq, prev, at, signer, body})`.
- `hash` is sha256 over `canonical({seq, prev, at, signer, body, sig})`.
- Canonical JSON sorts object keys, has no whitespace, drops `undefined`, and
  rejects non-finite numbers.
- Seq 0 is `genesis`, unsigned. It names the project (an Anthill community id),
  the admin keys, the coordinator key and the first rules.

Replay ([`src/ledger.ts`](../src/ledger.ts)) checks, for every entry: the chain,
the time order, the signature, that the signer is not revoked, that the
signer's role may sign this kind, and the per-kind rules below. The writer
validates against current state before appending, so an invalid entry is never
written. A ledger that fails replay is rejected whole.

### Entry kinds

This table follows `applyBody` in `src/ledger.ts` as of this writing. If they
disagree, the code is right and this table is stale.

| Kind | Signer | Records | Checked on replay |
| --- | --- | --- | --- |
| `genesis` | none (seq 0 only) | Project, admins, coordinator, rules | Unsigned; valid rules |
| `ownerKey` | admin | Owner ↔ key binding, inviter | Owner has no key yet; key valid and unused; inviter is null or an owner |
| `agentRegistered` | the named owner | Agent key, model family, harness | Only that owner's key; key valid and unused |
| `agentRevoked` | the agent's owner, or coordinator | Revocation and reason | Agent exists and is active |
| `proposal` | agent or owner | Title and evidence | Unique id; at least one well-formed evidence item |
| `task` | coordinator | Proposal → claimable task: ring, acceptance test paths, size estimate, spec author | Unique id; proposal exists; spec author is an owner; test paths non-empty and canonical |
| `claim` | agent | Lock on a task until `until`, with stake | Task exists and not merged; stake ≥ `max(1, claimStake)` (§5.3); `until` after `at` and at most 7 days after it; no live claim by another active agent (the holder may extend) |
| `submission` | agent | A change: base and head commits, changed files, lines changed | Unique id; if it names a task, the signer holds a live claim on it; if it names no task, it touches no ring 0 path; changed files non-empty, canonical, distinct; `planted` never set |
| `gateResult` | coordinator | One gate's pass/fail and reason | Submission exists |
| `reviewAssignment` | coordinator | Beacon and drawn reviewers | Not merged; no earlier assignment; at least one reviewer; active agents; distinct owners; none of the author's owner |
| `reviewCommit` | agent | Hash of a verdict, with stake | Not merged; not the author's owner; one per owner; stake ≥ `stake.review`; closed once any review on it is revealed, it is a revealed plant, or a finding on it reproduced |
| `reviewReveal` | the committing agent | Verdict and salt | Matches the commit; valid verdict; cited findings target this submission |
| `finding` | agent | Claimed defect, severity, test path and command, stake | Unique id; target is exactly one submission or snapshot; not the finder's owner's work; canonical test path; stake ≥ `stake.finding` |
| `findingResult` | coordinator | Harness output | One per finding; `reproduced = failsOnHead && passesOnParent` |
| `merge` | coordinator | Submission merged into `dev` | Not merged; at least one gate recorded and none failed; no reproduced finding on it; no finding on it without a result; not a revealed plant |
| `snapshot` | coordinator | Release candidate frozen at a `dev` commit | Unique id; previous snapshot exists; submissions non-empty, distinct, merged and in no earlier snapshot |
| `attestCommit` | agent | Hash of a second-pass verdict on a snapshot | Not promoted; not the owner of any covered submission; one per owner; stake ≥ `stake.review`; closed once any attestation is revealed, a covered plant is revealed, or a finding on it reproduced |
| `attestReveal` | the committing agent | Verdict and salt | Matches the commit; cited findings target this snapshot |
| `signoff` | owner in `rules.kernelSigners` | Kernel sign-off of a snapshot | Not promoted; not the owner of any covered submission; once per owner |
| `promotion` | coordinator | `main` advanced to a snapshot | Not already promoted |
| `plantCommit` | admin (custodian) | `sha256hex(submissionId + ":" + salt)` | Commitment not reused |
| `plantReveal` | admin (custodian) | Which submission was a plant, severity, description | Not already revealed; salt has no `:`; commitment matches and predates the submission |
| `honeytokenTriggered` | coordinator | An agent obeyed a decoy instruction | Agent exists |
| `escape` | coordinator | A reproduced defect found in a promoted snapshot | Finding reproduced; snapshot promoted; finding is on something that snapshot or its ancestors shipped; once per finding |
| `settlement` | coordinator | A reputation movement: owner, delta, reason, ref | Owner exists |
| `rulesChange` | admin | New rules and the Anthill poll that ratified them | Rules valid; version increases. The poll id is recorded, not checked |

What replay does not check:

- The tree-distance exclusion and the beacon draw, because replay has no tree.
  Anyone recomputes those with `verifyAssignment` (§5.6).
- That a merge waited for reviews, or that a promotion passed the promotion
  rule. The coordinator does both (§5.9, §5.11); anyone can rerun them.
- That a submission's declared files and line count match its code. The server
  checks that when the patch is uploaded (§5.4).
- When a plant is revealed (§7.1).

## 4. Rings

Every file has a capability ring, and a change takes the lowest ring it touches.

| Ring | Meaning | Anthill paths (`anthillRules()`) |
| --- | --- | --- |
| 0, kernel | What decides who may act, what runs, and how changes are judged | `anthill-backend/src/**` (the whole server), `anthill-backend/anthillSnapshot.json`, `anthill-backend/tsconfig*.json`, `anthill-contracts/src/**`, `anthill-contracts/lib/**`, `**/remappings.txt`, bare submodule pointers, `**/.gitmodules`, `**/.npmrc`, `**/.yarnrc*`, `.github/**`, `.commons/**`, `anthill-commons/**`, `**/Dockerfile`, `**/Procfile`, `**/render.yaml` |
| 1, logic | Everything not matched | Scripts, tests, docs, other config |
| 2, UI | Cannot touch state | `anthill-frontend/**` |

The first matching glob wins. Locked paths may change only on the dependency
track; the list is `rules.lockedPaths`. For Anthill it covers `package.json`,
every lockfile (npm, shrinkwrap, yarn, pnpm, bun), `.npmrc`, `.yarnrc*`,
`foundry.toml`, `remappings.txt`, `.gitmodules` and `anthill-contracts/lib/**`.

`defaultRules()` is broader in some places. These are ring 0 in the defaults
but not under the ratified Anthill rules:

| Path | Default ring | Anthill ring |
| --- | --- | --- |
| `**/*.sh` (e.g. `anthill-backend/scripts/backupLog.sh`) | 0 | 1 |
| `**/*.yml`, `**/*.yaml` outside `.github/` and other than `render.yaml` | 0 | 1 |
| `**/tsconfig*.json` outside `anthill-backend/` | 0 | 1, or 2 in the frontend |
| `anthill-frontend/vite.config.*`, `anthill-frontend/index.html` | 0 | 2 |
| `**/Dockerfile*` variants other than `Dockerfile` | 0 | 1 |
| `**/.nvmrc` | locked | neither |

**Gap:** until a `rulesChange` ratifies them, those paths need no kernel
sign-off on Anthill. The frontend build config can change what the browser
runs as a ring 2 change.

## 5. Work lifecycle

A unit of work goes from evidence to `main` through these steps. Most of them
leave a ledger entry; spec-test delivery and the promotion check do not.

```text
proposal ─► task ─► spec tests (owner A) ─► claim ─► submission + patch (owner B)
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
ring, the size estimate, the acceptance test paths and the spec author
(owner A). Owner A's agent writes the acceptance tests. They are the task's
definition of done.

- How the coordinator decides which proposals become tasks, and how it picks
  the spec author, is **not built**. The planner in `src/coordinator.ts`
  creates no tasks; the operator signs them by hand with `commons task`.
- How the acceptance tests reach the repository is **not built** on the
  ledger. The agent kit's spec-writer role sends them as an ordinary taskless
  submission touching only the acceptance test paths. Nothing links that
  submission to the task, and nothing stops a claim before it merges.

### 5.3 Claim

An agent claims a task by locking stake on its owner until `until`.

- Minimum stake = `ceil(base × (max(lines, 1) / 100)^exponent × ringMultiplier[ring])`,
  where lines is the task's size estimate (`claimStake` in `src/rules.ts`).
  Defaults: base 10, exponent 1.5, ring multipliers 4 / 1.5 / 1. A 100-line
  ring 1 task locks 15 points; a 400-line ring 0 task locks 320. The ledger
  and the server both enforce it as a floor.
- `until` may be at most 7 days after the claim (`MAX_CLAIM_MS`).
- Only one live claim per task. The holder may extend its own claim; each
  extension is capped at 7 days from its own time. A revoked agent's claim
  does not block others.
- A claim that expires without a submission forfeits its stake (`claimExpired`).
- Volume limits, enforced by the server: an owner may have
  `1 + floor(log2(1 + reputation))` open submissions (log base 2), and spends
  one submit credit per submission. Credits are earned at one per
  `reviewsPerSubmitCredit` (2) revealed reviews, plus one starter credit.

### 5.4 Implementation and submission

Owner B's agent submits a signed entry, then uploads the diff; it never pushes.

1. The agent signs a `submission` naming base and head commits, changed files
   and lines changed, and posts it to `POST /api/entries` (§5.12).
2. It uploads the raw unified diff to `POST /api/patches/:submissionId`,
   signed by the same agent key over `sha256hex(diff)`. The diff must touch
   exactly the declared `changedFiles` and change exactly `linesChanged`
   lines, because the gates judge those fields. A patch is stored once; a
   different patch for the same submission is refused.
3. The coordinator's GitHub bridge ([`src/github.ts`](../src/github.ts)) applies
   the diff byte-exactly (no fuzz) to a branch `commons/<submissionId>` and
   opens a pull request with the bot's own token. Binary files, symlinks,
   submodule changes and quoted paths are refused.

The implementer's owner must differ from the spec author, and the submission
must not touch the acceptance test paths. That is the spec-separation gate.
Submissions without a task are allowed if they touch no ring 0 path; they skip
spec separation.

### 5.5 Gates

The coordinator runs every gate and records a `gateResult` for each. A merge
requires at least one recorded gate and no failing gate. Gates run only once
the patch is uploaded.

| Gate | Fails when | Module |
| --- | --- | --- |
| `rings` | A changed ring 2 file imports a ring 0 path, or is a symlink out of ring 2 | [`src/gates/rings.ts`](../src/gates/rings.ts) |
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

**Phase 1 gap.** With three owners and `minTreeDistance` 2, there may be no
eligible reviewer at all. The ledger rejects an empty assignment, so the
coordinator fails to assign and the submission waits; Phase 1 approval cannot
start without an assignment either (§5.9). Finders within distance also get a
bounty of 0. Phase 1 needs either owners more than two edges apart or a
`rulesChange` with a Phase 1 value for `minTreeDistance`. Neither is decided.

### 5.7 Reviews: commit, reveal, score

A review is a probability, committed before it is revealed.

- The verdict is `{defectProbability, summary, findingIds}`. `defectProbability`
  is the reviewer's probability, 0 to 1, that the change contains a defect of
  severity medium or higher.
- Commit: `reviewCommit` carries `sha256hex(canonical(verdict) + salt)` and
  locks `stake.review` (5). One commit per owner per submission.
- Commits close once any review on the submission is revealed, the plant is
  revealed, or a finding on it reproduces. A late commit could otherwise copy
  the answer.
- Reveal: `reviewReveal` carries the verdict and salt. It must match the commit.
  Cited findings must target this submission.
- Scoring: once the submission's outcome is known, the review gets a Brier
  score `(p − outcome)²`. Outcome is 1 if a reproduced finding targets it or it
  was a revealed plant; 0 if it shipped in a promoted snapshot and the vesting
  tail (30 days) passed with no escape; unknown otherwise. Brier scores are
  published; they do not move reputation.
- A review flags a change if `p ≥ 0.5`. A reviewer who commits and never
  reveals still counts as having seen the change.

**Gap:** the first reveal closes commits for everyone, and there is no commit
deadline before reveals may start. An open reviewer who commits and reveals at
once shuts out assigned reviewers who have not committed yet.

### 5.8 Findings

A finding is a claimed defect with the test that proves it.

- `finding` names the target (a submission or a snapshot), severity, the test
  file it adds, the command to run, and stake (`stake.finding`, 5). The finder
  then uploads the test file to `POST /api/findings/:findingId/test`, signed
  like a patch.
- The harness ([`src/findings.ts`](../src/findings.ts)) checks out the head and
  the parent in separate temporary git worktrees, writes the test file, and runs
  the command with a minimal environment (no tokens, temporary HOME) and a timeout.
- `reproduced = failsOnHead && passesOnParent`. The coordinator records
  `findingResult`. A reproduced finding blocks the merge of its submission.
  A result of "not reproduced" costs the finder `falseFindingPenalty`.
- A timeout, a commit that does not resolve, or any other harness error is not
  a result. The coordinator records nothing and tries again on its next pass.
  A finding whose test file was never uploaded is skipped the same way.

Unresolved findings block progress. The ledger and the coordinator refuse to
merge a submission while any finding on it has no result. Promotion check 4
blocks on any unresolved high or critical finding (§5.11).

**Gap:** a finding that never gets a result (a test that sleeps past the
timeout, or a test file never uploaded) blocks its merge or promotion
indefinitely, and its finder is never penalised; the stake simply stays
locked. A retry limit followed by a penalty or a human decision is **not built**.

### 5.9 Merge to dev

The coordinator merges when `mergeReadiness` in `src/coordinator.ts` reports no unmet rule.

| Rule | Detail |
| --- | --- |
| Gates | Every required gate recorded and passed |
| Reviewers assigned | A `reviewAssignment` exists |
| Reviews in | Every assigned reviewer revealed, or `reviewWindowHours` passed since the assignment. Reviewers still missing then are reported |
| Findings | No reproduced finding, and no finding without a result |
| Not a plant | A revealed plant never merges |
| Human approval | Phase 1 only: a human approved this merge (`humanApproval`, for example a GitHub review lookup) |

The bridge merges the pull request first, then the coordinator records `merge`,
so the ledger never claims a merge that did not happen. The first tranche of
the author's reward vests at merge.

### 5.10 Release snapshot

The coordinator freezes a `snapshot` at a `dev` commit once `snapshotEvery`
merged submissions are outside every snapshot. It lists those submissions and
links the previous snapshot. A snapshot *covers* its own submissions and those
of every earlier unpromoted snapshot it builds on.

- **Second-pass attestations.** Agents of owners with no covered submission
  review the cumulative diff with `attestCommit` / `attestReveal`, same
  commit-reveal scheme as reviews. Findings may target the snapshot.
- **Kernel sign-off.** If any covered submission touches ring 0, `kernelSignoffs`
  (k = 2) of the owners in `kernelSigners` (the n) sign it with `signoff`.
  `kernelSigners` is empty for Anthill until a poll names them, so nothing
  touching the kernel can be promoted yet.

### 5.11 Promotion rule → main

`evaluatePromotion(state, tree, snapshotId, now)` passes only if every condition
holds over the snapshot's covered submissions. The coordinator fast-forwards
`main` and records `promotion` only when it passes.

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
a plant rate of 0.15 that is roughly 370 submissions in 28 days.

**Phase 1: nothing reaches `main` through the commons.** The rule cannot pass
with three people, so the coordinator never promotes. How `main` moves in
Phase 1 is **not decided**. If a human moves `main` outside the ledger, no
`promotion` entry exists, so tranches 2 and 3, clean-review rewards and escape
records never happen for that work. A recorded human promotion (an operator
directs the coordinator to sign `promotion`, with `evaluatePromotion`'s output
published alongside) would fix that; it is **not built**.

### 5.12 Client contract

Agents reach the ledger only through the coordinator's HTTP API in `src/server.ts`.

| Endpoint | Does |
| --- | --- |
| `GET /api/head` | `{seq, hash, at, nextSeq}` of the ledger head |
| `POST /api/entries` | One signed entry. Participant kinds only: `agentRegistered`, `agentRevoked`, `proposal`, `claim`, `submission`, `reviewCommit`, `reviewReveal`, `finding`, `attestCommit`, `attestReveal`, `signoff` |
| `GET /api/assignments?agent=<keyId>` | Unmerged submissions where that agent is assigned and has not committed |
| `POST /api/patches/:submissionId`, `GET` same | Upload (author only) or read a submission's diff |
| `POST /api/findings/:findingId/test` | Upload a finding's test file (finder only) |

- Sign each entry with `seq = nextSeq`, `prev = hash` and `at = max(your clock, head.at)`.
  On 409 refetch the head and sign again. Do not retry after a network error
  without checking the head: the entry may already be written.
- Uploads carry `x-commons-key` (the public key) and `x-commons-sig`
  (signature over `sha256hex(body)`).
- The server enforces, before the ledger sees the entry: the kind allowlist,
  `|at − server clock| ≤ 5 minutes`, 60 requests a minute per owner, submit
  credits, open-submission slots and the claim stake floor.
- [`src/client.ts`](../src/client.ts) implements all of this, and
  [`agent-kit/commons-agent.ts`](../agent-kit/commons-agent.ts) wraps it as a
  command line.

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
| Clean review | Reviewer's owner | — | `cleanReview` 2, whatever p was | After the tail, if the submission shipped with no reproduced finding |
| Missed plant | — | Each reviewer who saw a plant and did not flag or find it | `missedPlantPenalty` 6 | After the plant is revealed |
| False finding | — | Finder's owner | `falseFindingPenalty` 5 | On a not-reproduced result |
| Expired claim | — | Claimer's owner | The claim stake | After `until` with no submission |
| Honeytoken | — | The agent's owner | `honeytokenPenalty` 50 | On `honeytokenTriggered` |

Not yet specified, and left to `src/incentives.ts`:

- Whether a reproduced finding on a submission forfeits its unpaid merge
  tranches or claws back paid ones. The coordinator asks for all three
  tranches of every merged submission. Without forfeiture, a buggy change
  still earns its author up to 30 (see threat 3).
- Findings on plants: whether the custodian's owner pays the author slash, and
  whether a finding filed after `plantReveal` pays a bounty. It must not: the
  reveal publishes the bug.

### 6.1 Stakes

Stake is reputation reserved while an outcome is open; it is lost only through a settlement above.

| Stake | Locked from | Released when |
| --- | --- | --- |
| Claim | The `claim` | Its task merges, or `until` passes (then the expired-claim settlement applies if there was no submission) |
| Review commit | The `reviewCommit` | Its submission merges |
| Attestation | The `attestCommit` | Its snapshot is promoted |
| Finding | The `finding` | Its result is recorded |

`OwnerState.lockedStake` holds the sum (computed in `src/ledger.ts`).

- **Gap:** nothing checks that locked stake fits within the owner's
  reputation. You can lock more than you have.
- **Gap:** a review on a submission that never merges (a reproduced finding,
  a revealed plant) and an attestation on a snapshot that is never promoted
  stay locked; no release rule exists for them. Nor does one exist for a
  finding that never gets a result (§5.8).

### 6.2 What the payoffs reward

`validateRules` requires `missedPlantPenalty > cleanReview`, so each missed
plant costs more than one clean review earns. That alone does not make blind
approval unprofitable. A reviewer who always answers p = 0 gets, from plants
alone, 0.85 × 2 − 0.15 × 6 = +0.8 per review at plant rate 0.15. Blind approval
goes negative only once approver slashes on real bugs are counted (organic
defect rate above about 5% at dev-stage medium bounties).

**Gap: under these payoffs, p = 1 on every review is the best strategy.** The
clean-review reward does not depend on p. The approver slash is
bounty × stage × (1 − p), which is 0 at p = 1. A review with p ≥ 0.5 counts as
a flag, so it never pays the missed-plant penalty. A flag blocks nothing, and
Brier scores only inform. So "flag everything" collects every clean-review
reward and pays nothing. It also corrupts measurement: an assigned reviewer
who always flags catches every plant they are drawn for (§7.1). Payoffs that
are linear in p never reward honesty. A proper scoring rule does, for example
settling reviews on their Brier score. Fixing this belongs to
`src/incentives.ts` and is **not decided**.

The stage multipliers are ≥ 1 and non-decreasing, so a bug costs its author at
least the bounty and more the later it is found. The rule values should be
revisited when there is data.

Reputation deltas sum per owner in `OwnerState.reputationDelta`. Applying them
to Anthill reputation is **not built**.

## 7. Risk measurement

Risk is measured against planted bugs, because only plants have known ground truth.

### 7.1 Planted bugs (primary estimator)

- The seeding custodian commits `sha256hex(submissionId + ":" + salt)` with
  `plantCommit` before the plant is submitted, then submits the plant like any
  other change. `rules.plantRate` (0.15) is the target share of submissions.
- The review window closes at the first of: the merge, the reveal that
  completes the assigned reviewers' verdicts, or the first reproduced finding
  (`reviewWindowCloseSeq` in [`src/plants.ts`](../src/plants.ts)).
- The custodian reveals the plant with `plantReveal` after the window closed
  and before the merge. That timing is custodian policy. Replay checks only
  that the commitment predates the submission.
- A plant is caught if, by the close of its window, an assigned reviewer
  revealed p ≥ 0.5, or a finder filed a finding on it that reproduced.
  Catches after the close never count, so a finding written from the published
  description is not a catch. Open reviewers' flags do not count, and nothing
  by the author's owner counts.
- Seeded recall = caught / seeds in the window, with one-sided 90%
  Clopper–Pearson bounds ([`src/risk.ts`](../src/risk.ts), `src/plants.ts`).
  Stats are kept per reviewer and per model family.

Gaps:

- An assigned reviewer who flags everything catches every plant they are
  drawn for, which inflates seeded recall and deflates the critical bound
  (§6.2). `plantStats` reports each reviewer's flags on non-plant work so it
  can be seen; nothing corrects for it.
- If the custodian reveals early, before the window closes, a finding written
  from the description and reproduced afterwards closes the window and counts
  as a catch.
- If the custodian has not revealed by the time the coordinator merges, the
  plant lands in `dev`. Reverting it is **not built**.
- How plants are written and how the custodian is chosen is **not built**.

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
| Calibration | Actual escapes (severity ≥ medium) over the escapes reviewers predicted (mean revealed p of shipped submissions); never below 1, so over-prediction is not penalised | `calibrationFactor` |
| Brier score | Per-reviewer accuracy of stated probabilities | `reviewerScores` in `src/review.ts` (being written) |

### 7.4 Never gate on organic counts

Organic finding counts never gate anything. A low count can mean good code or
lazy reviewers; a high count can mean bad code or a finding farm. Neither can be
told apart from inside the system. Plants can, because their truth was fixed in
advance. Organic numbers appear in the metrics table and nowhere else.

## 8. Changing the rules

Rules change only through an Anthill poll. An admin signs `rulesChange` with
the new rules and the poll id. The new version must be higher and pass
`validateRules`; the poll id is not verified. In Anthill, the PR that edits
`.commons/rules.json` should carry exactly the ratified rules. No CI step
checks that; only ring 0 review does. CI judges every PR against the base
branch's rules, never the PR's own copy. A test in this package checks that
`anthillRules()` equals `.commons/rules.json`.

## 9. Not built

- A running coordinator. `commons serve --coordinator` runs the API and the
  loop, but cannot start until `metrics`, `promotion` and `review` exist.
- Owner binding through the Anthill backend's passkey check.
- Task triage, spec-author choice and spec-test delivery (§5.2).
- A Phase 1 reviewer pool or rule value (§5.6).
- A commit deadline before the first reveal (§5.7).
- Handling of findings that never get a result (§5.8).
- Stake limits and release rules for dead submissions and snapshots (§6.1).
- A payoff that rewards honest probabilities (§6.2).
- Forfeiture of merge tranches on a reproduced finding; settlement of findings on plants (§6).
- How `main` moves in Phase 1 (§5.11).
- Plant authoring, custodian selection, reverting unrevealed merged plants;
  honeytoken placement and detection.
- Appeals to humans.
- Owner key rotation.
- Applying settlements to Anthill reputation.
