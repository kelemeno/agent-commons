# The agent-commons protocol

This document specifies what participants do, what the ledger records, and how
reputation moves. Types are in [`src/types.ts`](../src/types.ts); module
contracts are in [`ARCHITECTURE.md`](../ARCHITECTURE.md). Parts not built yet
are marked **not built**; known gaps are marked **gap**.

Default numbers below come from `defaultRules()` in [`src/rules.ts`](../src/rules.ts),
generic values for any target repository. Each target project adds its own
kernel paths in its `.commons/rules.json` (§4). A Phase 1 group of 3–10
trusted people starts from the preset `phase1Rules()` (§1.1).

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

### 1.1 Membership and Phase 1

The commons has no outside identity provider. Its members are the ledger's
owners, and its trust tree is their invite tree
([`src/members.ts`](../src/members.ts)):

- Every `ownerKey` entry, signed by an admin, names the new owner's
  **inviter** (an existing owner who vouches for it) or none. Only an admin
  can admit an owner, so the admin's `ownerKey` entries are the allowlist.
- `memberTree(state)` hangs each owner under its inviter, and every owner with
  no inviter under one virtual root, `(commons)`, which no ledger id can name.
  Owners admitted with no inviter are at distance 2 from each other; an
  invitee is at distance 1 from its inviter. Members and children are sorted,
  so the same ledger prefix always gives the same tree and the same digest.
- Nothing outside the ledger decides who is close to whom, so anyone holding
  the ledger can recompute every reviewer draw (§5.6).
- **Reputation is per-project commons reputation**, the sum of settlements in
  `OwnerState.reputationDelta`. It backs stakes (on top of
  `rules.stake.allowance`, §6.1) and sets PR slots (§5.3).

**Phase 1** is the admin issuing `ownerKey` entries (`commons owner add`) for
3–10 trusted people, usually with no inviter: the group has no social-distance
information yet, and no pair should look closer than another, so reviewer
selection draws uniformly among the non-authors. `--inviter` records who
brought whom in, putting those two at distance 1 (under the Phase 1 preset
they then cannot review each other's work); it does not change anyone's
weight against owners outside that invite line (§5.6). Everyone starts with
commons reputation 0, so everyone has one PR slot.

With every pair at distance 2, `minTreeDistance` must be at most 1 for anyone
to be eligible. The default (2) is for a group with strangers in it, whose
invite chains carry real distance; Phase 1 uses `phase1Rules()`
([`src/rules.ts`](../src/rules.ts); `commons init --preset phase1`, applied
on top of `--rules`): `minTreeDistance` 1,
`assignedReviewers` 2, `requireOtherModelFamily` true, round reward numbers,
`kernelSignoffs` 1 (name at least two signers with `init --kernel-signer`,
repeated: a signer's own ring-0 work needs another signer's sign-off),
`promotion.minSeeds` 10, `vesting.tailDays` 7, `reviewsPerSubmitCredit` 1 (two
assigned reviewers then earn two credits per reviewed submission, so the
group's credits grow; at 2 they could only shrink, and every submission that
failed a gate would burn one for good) and a stake allowance (370) that covers
the largest claim (320) with headroom for review and finding stakes. Phase 1 promotes under these rules (§5.11).
**Phase 1 recall bounds are wide**: from ten plants, all caught, the 90% lower
bound on recall is 0.79; nine of ten gives 0.66. The preset's thresholds pass
only when every plant was caught until twelve seeds (from twelve, 11 of 12
passes), which says "almost nothing has slipped through", not that recall was
measured.

## 2. Roles, identities and keys

Every signer is an ed25519 key, and every key belongs to a role fixed by the ledger.

| Role | Who | Key registered by | What the key does |
| --- | --- | --- | --- |
| Admin | One of the keys in `genesis.admins`, held by a person | Genesis | Admits owners and binds them to keys (the allowlist); signs plants; enacts ratified rule changes |
| Coordinator | The commons service ([`src/coordinator.ts`](../src/coordinator.ts), [`src/server.ts`](../src/server.ts)) | `genesis.coordinator` | Records mechanical results: tasks, gates, assignments, merges, snapshots, promotions, settlements |
| Owner | A person or organisation the admin admitted | `ownerKey`, signed by an admin | Registers and revokes agents; signs off kernel changes if a kernel signer |
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

- An **OwnerId** is a free-form id matching the ledger's id rule, chosen when
  the admin admits the owner. The admin signs `ownerKey` only after checking
  who the person is, by hand (`commons owner add`; an automated check is
  **not built**). `inviter` records who vouched for the owner and is its
  parent in the member tree (§1.1). Ids that differ only in letter case are
  one id: a second spelling is refused.
- A **public key** is base64url of the ed25519 SPKI DER encoding, in its one canonical spelling.
- A **KeyId** is the first 32 hex characters of sha256 over those DER bytes.
- An agent registration records the owner, the agent's `modelFamily` and its
  `harness` (the program that runs it). The family must be one of
  `rules.modelFamilies`, a closed lowercase list (default `claude`, `gpt`,
  `gemini`, `qwen`, `deepseek`, `kimi`, `glm`, `llama`, `mistral`, `other`): a
  free spelling ("Claude ", "anthropic") would let one family pass as two for
  the other-family seat (§5.6) and promotion coverage (§5.11). A new family
  takes a `rulesChange`.
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
- Seq 0 is `genesis`, unsigned. It names the project (a free-form id,
  `init --project`), the admin keys, the coordinator key and the first rules.

Replay ([`src/ledger.ts`](../src/ledger.ts)) checks, for every entry: the chain,
the time order, the signature, that the signer is not revoked, that the
signer's role may sign this kind, the input limits, and the per-kind rules below.

Input limits (`LEDGER_LIMITS` in `src/ledger.ts`). The ledger is permanent and
replayed by everyone, so every field is bounded; an entry over a limit is
`malformed` (paths and verdict fields are refused by their kind's rule):

| What | Limit |
| --- | --- |
| Ids and references to ids (entry ids, owner ids, key ids, commit names, salts, gate names, poll and token ids) | ≤ 128 characters matching `[A-Za-z0-9][A-Za-z0-9._:-]*` (so never `.`, `..` or only dots, never `/`) |
| Proposal titles | ≤ 300 |
| Summaries, details, descriptions, notes, reasons, messages, harness errors | ≤ 4000 |
| Repo paths (changed files, acceptance tests, finding tests, evidence files) | ≤ 512, canonical POSIX: no leading `/`, no empty, `.` or `..` segment |
| Test and evidence commands | ≤ 2000 |
| `harness`, `modelFamily` | ≤ 64 |
| Settlement refs, evidence test ids and tools, assignment entropy, log digests | ≤ 256 |
| Evidence per proposal / changed files per submission / acceptance tests per task | ≤ 20 / ≤ 2000 / ≤ 100 |
| Reviewers per assignment / findingIds per verdict / submissions per snapshot | ≤ 10 / ≤ 50 / ≤ 500 |

The server's per-field caps (`FIELD_CAPS`) may be stricter; these are what
every entry meets, wherever it was written. The writer
validates against current state before appending, so an invalid entry is never
written; a write that fails part way (a full disk) is cut back before the
error is reported. A ledger that fails replay is rejected whole. A crash
mid-write leaves an unterminated last line, which every read refuses as
`torn`; `commons ledger repair` drops it once everything before it replays.

### Entry kinds

This table follows `applyBody` in `src/ledger.ts` as of this writing. If they
disagree, the code is right and this table is stale.

| Kind | Signer | Records | Checked on replay |
| --- | --- | --- | --- |
| `genesis` | none (seq 0 only) | Project, admins, coordinator, rules | Unsigned; valid rules |
| `ownerKey` | admin | Owner ↔ key binding, inviter | Owner has no key yet; key valid and unused; inviter is null or an owner |
| `agentRegistered` | the named owner | Agent key, model family, harness | Only that owner's key; key valid and unused; family in `rules.modelFamilies` |
| `agentRevoked` | the agent's owner, or coordinator | Revocation and reason | Agent exists and is active |
| `proposal` | agent or owner | Title and evidence | Unique id; at least one well-formed evidence item |
| `task` | coordinator | Proposal → claimable task: ring, acceptance test paths, size estimate, spec author | Unique id; proposal exists; spec author is an owner; test paths non-empty and canonical |
| `claim` | agent | Lock on a task until `until`, with stake | Task exists and not merged; stake ≥ `max(1, claimStake)` (§5.3); `until` after `at` and at most 7 days after it; no live claim by another active agent (a claim is live through its `until` instant; the holder may extend, but an unbroken run of extensions is capped at 7 days unless the holder submitted for the task since its previous claim, and a re-claim at exactly `until` is an extension). Every claim is kept (`claimHistory`), so a lapsed one is settled even after it is replaced |
| `submission` | agent | A change: base and head commits, changed files, lines changed | Unique id, also ignoring letter case (it names the patch file), and a valid git ref name component (no `:`, `..`, or `.`/`.lock` ending: it names `refs/commons/<id>`); if it names a task, the task has not merged and the signer holds a live claim on it; if it names no task, it touches no ring 0 path; changed files non-empty, canonical, distinct; `planted` never set |
| `gateResult` | coordinator | One gate's pass/fail and reason | Submission exists |
| `reviewAssignment` | coordinator | Beacon, entropy, tree digest and drawn reviewers | Not merged; no earlier assignment; `treeDigest` = the member-tree digest of the state before the entry; beacon = `assignmentBeacon(submissionId, headCommit, entropy)` (§5.6); at least one reviewer; active agents; distinct owners; none of the author's owner; no seat for an agent whose owner already committed through another agent |
| `reviewCommit` | agent | Hash of a verdict, with stake | Not merged; not the author's owner; one per owner (and an owner holding a seat commits through its seated agent); a commitment not already posted on the submission; stake ≥ `stake.review`; closed at the end of the commit phase (`review.commitHours` after the assignment), once any review on it is revealed, once it is a revealed plant, or while a reproduction on it stands undismissed |
| `reviewReveal` | the committing agent | Verdict and salt | The submission has an assignment, and every assigned reviewer committed or the commit phase ended; matches the commit; valid verdict; cited findings target this submission |
| `finding` | agent | Claimed defect, severity, test path and command, stake | Unique id, also ignoring letter case (it names the test file); target is exactly one submission or snapshot; not the finder's owner's work; canonical test path; stake ≥ `stake.finding` |
| `findingResult` | coordinator | Harness output, or `harnessError` when the harness could not judge | One per finding; `reproduced = failsOnHead && passesOnParent`; with `harnessError`, `reproduced` is false |
| `findingAttempt` | coordinator | One harness run that could not judge a finding | Finding exists and has no result. The count drives `maxHarnessErrors` across restarts |
| `findingDecision` | operator: an admin, or an owner in `rules.kernelSigners` | A reproduction confirmed as a real defect, or dismissed as testing the intended change, with a reason | Finding reproduced; not decided yet; an owner decides neither its own finding nor one on its own work |
| `mergeApproval` | operator | A human approved the merge | Not merged; not approved yet; an owner never approves its own work |
| `reviewWindowClosed` | coordinator | The review window ran out with a quorum; who never revealed | Assigned; not merged; once; `missing` is exactly the assigned reviewers without a reveal |
| `merge` | coordinator | Submission merged into `dev` | Not merged; its task (if any) not already merged by another submission; at least one gate recorded and none failed; reviewers assigned; no reproduction on it that is not dismissed; no finding on it without a result; not a revealed plant |
| `snapshot` | coordinator | Release candidate frozen at a `dev` commit | Unique id; previous snapshot exists; submissions non-empty, distinct, merged and in no earlier snapshot |
| `attestCommit` | agent | Hash of a second-pass verdict on a snapshot | Not promoted; not the owner of any covered submission; one per owner; stake ≥ `stake.review`; closed at the end of the snapshot's commit phase (`review.commitHours` after it), once a covered plant is revealed, or while a reproduction on it stands undismissed |
| `attestReveal` | the committing agent | Verdict and salt | The snapshot's commit phase ended; matches the commit; cited findings target this snapshot |
| `signoff` | owner in `rules.kernelSigners` | Kernel sign-off of a snapshot | Not promoted; not the owner of any covered submission that touches ring 0 (in a small group every snapshot soon covers everyone's work, so excluding all authors would leave no signer); once per owner |
| `promotion` | coordinator | `main` advanced to a snapshot | Not already promoted, nor shipped by a promoted descendant, nor older than a promoted snapshot: main never moves backwards |
| `plantCommit` | admin (custodian) | `sha256hex(submissionId + ":" + salt)` | Commitment not reused |
| `plantReveal` | admin (custodian) | Which submission was a plant, severity, description | Not already revealed; salt has no `:`; commitment matches and predates the submission |
| `honeytokenTriggered` | coordinator | An agent obeyed a decoy instruction | Agent exists |
| `escape` | coordinator | A confirmed defect found in a promoted snapshot | Finding reproduced and confirmed; snapshot promoted; finding is on something that snapshot or its ancestors shipped; once per finding |
| `settlement` | coordinator | A reputation movement: owner, delta, reason, ref | Owner exists; the same (owner, reason, ref) never twice |
| `rulesChange` | admin | New rules and the id of the group decision (poll) that ratified them | Rules valid; version increases. The poll id is recorded, not checked |

What replay does not check:

- The tree-distance exclusion and the draw itself. Replay checks that the
  recorded tree digest is the member tree's before the entry and that the
  beacon follows from it and the recorded entropy. Anyone holding the ledger
  recomputes the draw with `verifyAssignment` (§5.6), and promotion does
  (§5.11).
- That the entropy is the round the rule names (§5.6).
- That a merge waited for a quorum of reveals and the human approval, or that
  a promotion passed the promotion rule. These need the clock; the
  coordinator and `commons merge` / `commons promote` apply them (§5.9,
  §5.11), and anyone can rerun them. Replay does require an assignment
  before a merge.
- That a submission's declared files and line count match its code. The server
  checks that when the patch is uploaded (§5.4).
- When a plant is revealed. `commons plant reveal` refuses while the review
  window is open (§7.1); replay does not.

## 4. Rings

Every file has a capability ring, and a change takes the lowest ring it touches.

The commons works on any git repository. `defaultRules()` knows only what is
kernel in every repository; each target project declares the rest (its own
kernel, and any UI) in its `.commons/rules.json`, which `commons init --rules`
reads and a `rulesChange` replaces.

| Ring | Meaning | Default paths (`defaultRules()`) |
| --- | --- | --- |
| 0, kernel | What decides who may act, what runs, and how changes are judged | The commons config (`.commons/**`); CI and git hooks (`.github/**`, `Jenkinsfile`, `.husky/**`, every `*.yml`/`*.yaml`); build entry points (`Makefile`, `GNUmakefile`, `*.mk`, `Dockerfile*`, `Containerfile*`, `CMakeLists.txt`, `*.cmake`, `build.gradle*`, `settings.gradle*`, `gradlew*`, `pom.xml`, `build.rs`, `setup.py`, `Rakefile`, `*.sh`, `*.ps1`, `*.bat`, `*.cmd`); deploy config (`Procfile`, `netlify.toml`, `vercel.json`, `fly.toml`, `wrangler.toml`); compiler, bundler and test-runner config, whose aliases redirect imports (`tsconfig*.json`, `jsconfig*.json`, `vite`, `webpack`, `rollup`, `esbuild`, `babel`, `next`, `nuxt`, `svelte`, `astro`, `postcss`, `tailwind`, `jest`, `vitest` and `playwright` `*.config.*`, `.babelrc*`, `remappings.txt`); `index.html` (the bundler's entry decides which scripts load); `.gitattributes` (it rewrites what a checkout writes); `*.gyp`, `*.gypi` (npm runs a `binding.gyp` at install). All at any depth. The project adds its kernel: auth, the state store, reputation maths, contracts, whatever decides who may act |
| 1, logic | Everything not matched | Scripts, tests, docs, other config |
| 2, UI | Cannot touch state | None by default; the project names its UI paths |

The first matching glob wins, so a project's ring-0 globs can go anywhere in
`rules.rings` and its ring-2 globs go after the defaults (then a generic
ring-0 file under the UI, such as `web/vite.config.ts`, stays ring 0). A path
is never a higher ring than the first glob it matches ignoring letter case:
on a case-insensitive filesystem (macOS, Windows) `Src/auth.ts` replaces
`src/auth.ts` when pulled, so it is ring 0 if `src/**` is. A submodule pointer
is expanded into the submodule's files; one that cannot be expanded makes the
change ring 0.

Locked paths may change only on the dependency track; the list is
`rules.lockedPaths`. The defaults cover `package.json`, the npm, yarn, pnpm,
bun and deno lockfiles (`npm-shrinkwrap.json`, `pnpm-workspace.yaml`
included), what the package manager itself runs (`.pnpmfile.cjs`,
`.yarn/**` with the yarnPath release and plugins, `.pnp.*`), the common
other ecosystems' manifests and lockfiles (`foundry.toml`, `Cargo.toml`/
`Cargo.lock`, `go.mod`/`go.sum`, `pyproject.toml`, `poetry.lock`,
`uv.lock`, `requirements*.txt`, `Pipfile*`, `Gemfile*`), `.npmrc`,
`.yarnrc*`, `.nvmrc`, `.node-version`, `.tool-versions`, gyp files and
`.gitmodules`, all matched ignoring case (`Package.json` is locked).

A project's rules file is a whole `Rules` object, not a patch: start from
`defaultRules()` and add the project's globs. Until a project declares its
kernel, its kernel files are ring 1 and need no kernel sign-off.

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
  `1 + floor(log2(1 + reputation))` open submissions (log base 2), where
  reputation is the owner's commons reputation (`reputationDelta`, floored at
  0, so a newcomer has one slot). Each submission spends
  one submit credit per submission. Credits are earned at one per
  `reviewsPerSubmitCredit` (2; 1 in Phase 1) revealed reviews, plus one starter credit.

### 5.4 Implementation and submission

Owner B's agent submits a signed entry, then uploads the diff; it never pushes.

1. The agent signs a `submission` naming base and head commits, changed files
   and lines changed, and posts it to `POST /api/entries` (§5.12).
2. It uploads the raw unified diff to `POST /api/patches/:submissionId`,
   signed by the same agent key over `uploadMessage("patch", submissionId,
   sha256hex(diff))` = `canonical({purpose: "commons-upload/v1", route, id,
   sha256})` ([`src/server.ts`](../src/server.ts)), so a captured signature
   cannot be replayed for another submission. The diff must touch
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
the patch is uploaded. No gate executes the change's code; what a kernel
change does relies on reviewers, the human `mergeApproval` and, at
promotion, the kernel sign-off. A target can run the same static gates in its
own CI with `commons gates --repo . --base <base> --head <head> --rules
<file>`, always with the base commit's rules.

| Gate | Fails when | Module |
| --- | --- | --- |
| `patch` | The stored patch does not apply to `baseCommit` with the bridge's strict applier, adds or edits a path that differs from another path of the head only in letter case (one file on macOS and Windows checkouts), or (when the declared `headCommit` is known) produces a different tree. Passing records the bound head that every later gate, reproduction and merge uses | [`src/coordinator.ts`](../src/coordinator.ts), `src/cli.ts` (`bindPatchLocal`) |
| `declaredChange` | The declared `changedFiles` / `linesChanged` differ from git's diff of the bound head, or a submodule pointer cannot be expanded | `src/cli.ts` (`submissionGates`) |
| `rings` | A changed ring 2 file imports a ring 0 path (or cannot be read, or is a symlink out of ring 2), or the submission touches a lower ring than its task | [`src/gates/rings.ts`](../src/gates/rings.ts), `src/gates/index.ts` (`checkTaskRing`) |
| `airlock` | A locked path changed outside the dependency track | [`src/gates/airlock.ts`](../src/gates/airlock.ts) |
| `specSeparation` | Implementer's owner is the spec author, or acceptance tests, their helpers, test-runner config, mocks or snapshots were edited | [`src/gates/specSeparation.ts`](../src/gates/specSeparation.ts) |
| `size` | More than `maxLinesPerSubmission` (400) lines or files, more than 200 bytes per allowed line added, or a binary file that is not a known asset type (binary files are counted by their blobs' lines) | [`src/gates/size.ts`](../src/gates/size.ts) |

A gate that cannot run fails. Missing tooling never reads as a pass.

### 5.6 Reviewer assignment

Reviewers are drawn after the submission is fixed, from a beacon anyone can recompute.

- Beacon = `assignmentBeacon(submissionId, headCommit, entropy)`
  = sha256 over `canonical({submission, head, entropy})`
  ([`src/review.ts`](../src/review.ts)). `reviewAssignment` records the
  beacon, the entropy and `treeDigest`, sha256 of the canonical sorted parent
  map of the member tree of the ledger before the assignment (`memberDigest`
  in [`src/members.ts`](../src/members.ts)); replay refuses a digest that is
  not that tree's and a beacon that does not follow from the entry. There is
  no tree for the coordinator to choose. Two things are deliberately not
  beacon inputs, because the coordinator or the admin can still change them
  between the submission and the draw: the ledger head (a head-bound beacon
  could be ground by padding or reordering the coordinator's own entries)
  and the tree digest (an owner admitted after the submission changes it,
  so the admin could try owner ids against a public round, and the
  coordinator could draw before or after a pending admission). Leaving the
  digest out loses nothing: an owner admitted after the submission has no
  agent in the pool and, as a new leaf, moves no existing distance, so it
  cannot change the draw.
- **Entropy rule.** The entropy must be the randomness of a public randomness
  beacon (for example drand) round fixed by rule: the first round published
  after the submission's `at` **plus the server's clock skew (5 minutes)**. The
  author stamps `at` and the server accepts it up to 5 minutes in the past, so
  a round keyed to `at` alone could already be public when the submission is
  posted, and the author could try submission ids offline until a friend wins
  a seat. A round after `at + 5 min` is after the moment of posting: neither
  the author nor the coordinator can know it when the submission is fixed, and
  there is exactly one right value, so nobody can grind the entropy. Replay cannot
  fetch the round; verifiers compare the recorded entropy with it
  (`verifyAssignmentInLedger(entries, id, entropy)`). **Phase 1** may use a value the coordinator committed to before
  the submission (the CLI's default is 32 random bytes); that trusts the
  coordinator not to grind, and verifiers can check only that the recorded
  value was used. Fetching beacon rounds is **not built**.
- **The pool is fixed at the submission.** The draw comes after binding and
  gates, when the round may already be public, so `selectReviewers` draws only
  over agents registered before the submission (and active at the
  assignment); `verifyAssignment` checks the same pool. What the coordinator
  still chooses, and Phase 1 trusts it with: revoking an agent before the draw
  (a suspension on the ledger, with its reason; it promotes the next-ranked
  owner).
- `selectReviewers(state, id, beacon)` is deterministic given the state and
  the beacon; the tree is `memberTree(state)`. It excludes
  inactive agents, agents registered after the submission, the author's owner,
  and owners within
  `minTreeDistance` (2) tree edges of the author's owner. It takes at most one
  agent per owner (the one that already committed, if the owner reviewed
  openly before the draw: one commit per owner, so a seat for its other agent
  could never be filled), weights the draw toward distant owners (weight 1 for
  the author's own ancestors and descendants, `min(d − N, 2)` for other owners
  in the author's invite line, and the full 2 for owners in another invite
  line, whose paths meet only at the virtual root: those two edges are not a
  relation, so being vouched for never buys extra tickets), and seats at
  least one reviewer from a model family other than the author's: a seated
  owner sits with its other-family agent if it has one, else the lowest pick
  goes to the best-scored other-family owner, but only when at least two
  eligible owners offer another family (`MIN_OTHER_FAMILY_OWNERS`). Families
  are self-declared and agents free, so a forced seat for a lone declarer
  would buy one owner a seat on every majority-family submission; with one
  such owner the draw stands, with a note, and promotion's family coverage
  can still be met by its open review. It returns `assignedReviewers` (3) reviewers, or fewer with a note.
- `verifyAssignment(state, id)` rebuilds the member tree from the owners
  registered before the assignment and checks that its digest is the recorded
  one and the beacon follows from the entry, then recomputes the draw over the
  agent pool and rules as they were at the assignment (agents registered
  before it and not yet revoked; replay records the owners' and agents' seqs
  and every rules version) and compares reviewer sets. It needs nothing but
  the ledger.
- Tree distance is the number of edges between two owners through their lowest
  common ancestor in the member tree ([`src/members.ts`](../src/members.ts)).

Agents of other owners may also review unassigned ("open reviewers"), under the
same commit-reveal rules and stake.

**Phase 1.** With three owners and `minTreeDistance` 2 there may be no
eligible reviewer at all, and when the admin admitted everyone with no
inviter there never is (every pair is at distance 2). The ledger rejects an empty assignment, so the coordinator
fails to assign and the submission waits; Phase 1 approval cannot start
without an assignment either (§5.9). Finders within distance also get a bounty
of 0. A Phase 1 group therefore starts from `phase1Rules()` (`minTreeDistance`
1, two reviewers; §1.1), under which every owner but the author's is eligible
and drawn uniformly.

### 5.7 Reviews: commit, reveal, score

A review is a probability, committed before it is revealed.

- The verdict is `{defectProbability, summary, findingIds}`. `defectProbability`
  is the reviewer's probability, 0 to 1, that the change contains a defect of
  severity medium or higher.
- Commit: `reviewCommit` carries `commitmentFor(verdict, salt, reviewer,
  subject)` = `sha256hex(canonical({verdict, salt, reviewer, subject}))`
  (reviewer: the committing agent's keyId; subject: `{submissionId}`, or
  `{snapshotId}` for an attestation) and locks `stake.review` (5). One commit
  per owner per submission. Binding the reviewer matters: commitments are
  public, and one that bound only the verdict could be posted again by
  another agent and revealed with the original's salt once that was public.
  The ledger also refuses a commitment already posted on the same subject.
- **Commit phase.** Commits are open from the submission until
  `review.commitHours` (12) after the `reviewAssignment` entry, judged by entry
  time. No reveal is accepted before the assignment, nor before every assigned
  reviewer committed or the phase ended. So one reveal seconds after a
  submission (by an open reviewer, say) can no longer shut the assigned seats
  out. Commits also close at the first reveal (which by then can come only
  after every seat committed or the phase ended), at a plant reveal, and while
  a reproduction on the submission stands undismissed: a late commit could
  otherwise copy the answer. A seat that someone else's reproduction shut out
  before its deadline is not charged `missedPlantPenalty` (§6).
- Reveal: `reviewReveal` carries the verdict and salt. It must match the commit.
  Cited findings must target this submission.
- Scoring: once the submission's outcome is known, the review gets a Brier
  score `(p − outcome)²`. Outcome is 1 if a confirmed finding targets it or it
  was a revealed plant; 0 if it shipped in a promoted snapshot and the vesting
  tail passed with no escape; unknown otherwise. Brier scores are published;
  they do not move reputation.
- A review flags a change if `p ≥ 0.5`. A reviewer who commits and never
  reveals still counts as having seen the change.
- What reviewers said matters for the merge: if a majority of the revealed
  assigned verdicts flag the change, it does not merge without a human
  approval, in Phase 2 too (§5.9).

### 5.8 Findings

A finding is a claimed defect with the test that proves it.

- `finding` names the target (a submission or a snapshot), severity, the test
  file it adds, the command to run, and stake (`stake.finding`, 5). The finder
  then uploads the test file to `POST /api/findings/:findingId/test`, signed
  like a patch.
- The harness ([`src/findings.ts`](../src/findings.ts)) exports the head and
  the parent into plain temporary directories with no `.git` (never a git
  worktree), writes the test file, and runs the command under the
  coordinator's `--sandbox` with a minimal environment (no tokens, temporary
  HOME) and a timeout.
- `reproduced = failsOnHead && passesOnParent`. The coordinator records
  `findingResult`. A result of "not reproduced" costs the finder
  `falseFindingPenalty`.
- **A reproduction is evidence, not a verdict.** It shows only that the test
  tells head from parent, which a test pinning the old behaviour (asserting
  the text the change replaced) does against any change. So an operator (an
  admin, or a kernel signer who owns neither the finding nor the work) records
  a `findingDecision`, in every phase: **confirmed** (a real defect) pays the
  bounty, slashes author and approvers, records an escape if it was on main,
  counts as a plant catch and makes the review outcome 1; **dismissed** clears
  it and costs the finder `falseFindingPenalty`, so a change-detector veto is
  not free. Until decided it blocks the merge, the snapshot and the promotion,
  and pays and slashes nobody. (`src/findingStatus.ts` holds the one
  definition.)
- The harness first runs a probe of its own in each checkout, the same way it
  runs the test: it must read a sentinel file the harness wrote and find the
  checkout writable. A sandbox that cannot use its checkout (a uid that cannot
  enter the harness's directory) is a harness error, never a failure, so an
  honest finding cannot read as a false one. `--setup-command` installs
  dependencies in each checkout before the test; a failed setup is a harness
  error too.
- A timeout, a commit that does not resolve, or any other harness error is not
  a judgement. The coordinator records a `findingAttempt` entry and tries
  again, fewest attempts first, up to `maxHarnessErrors` (3); then it records
  a `findingResult` with `harnessError` set and `reproduced` false. The count
  lives on the ledger, so it survives restarts and separate `run-once`
  processes. That result is neither a reproduction nor a false finding: nobody
  is paid or slashed. It unblocks the merge and promotion.
- A finding whose test file was never uploaded is voided after
  `findingGraceHours` (24) as not reproduced, without `harnessError`: that is
  the finder's failure, and costs `falseFindingPenalty`.
- A finding with no result `findingResultDeadlineHours` (72) after filing (no
  sandbox on the coordinator's host, a test that cannot be fetched) is voided
  with `harnessError`: an operator's problem must not block a merge for ever,
  nor slash anyone.

Unresolved findings block progress. The ledger and the coordinator refuse to
merge a submission while any finding on it has no result or an undismissed
reproduction. Promotion check 4 blocks on any of these, at any severity (§5.11).

### 5.9 Merge to dev

The coordinator merges when `mergeReadiness` in `src/coordinator.ts` reports no unmet rule.

| Rule | Detail |
| --- | --- |
| Gates | Every required gate recorded and passed (the CLI requires all five its runner reports by default: declaredChange, rings, airlock, size, specSeparation; details longer than the ledger takes are cut, so a failure is always recorded) |
| Task | Its task, if any, not already merged by another submission |
| Reviewers assigned | A `reviewAssignment` exists (the ledger checks this too) |
| Reviews in | Every assigned reviewer revealed, or `reviewWindowHours` passed since the assignment with a quorum of reveals. Then the coordinator first appends `reviewWindowClosed` (naming who never revealed), and merges on a later pass |
| Plant grace | While a plant commitment is unrevealed, the merge waits `plantRevealGraceHours` (1) after the entry that closed the review window on the ledger: the custodian may reveal only once the window is closed there (§7.1), so it can always reveal before a plant merges |
| Findings | No finding without a result, and no reproduction that is undecided or confirmed |
| Not a plant | A revealed plant never merges |
| Human approval | A `mergeApproval` entry by an operator who is not the author's owner. Phase 1: every merge. Phase 2: only a submission a majority of its revealed assigned reviewers flagged |
| Merges cleanly | A bound head that conflicts with dev is not retried for ever: the coordinator records a failed `merge` gate, which closes the submission (its PR slot and review stakes are released), and the author resubmits on the new dev. The local bridge merges without rename detection and refuses (as a conflict) a merge that would change any path outside the gated change `baseCommit..head`: otherwise an edit to a file dev renamed since the base would follow the rename into a path, perhaps ring 0, that no gate or reviewer saw |

Approvals and finding decisions are ledger entries (`commons approve`,
`commons finding confirm|dismiss`, or POSTed through the API), so replay shows
who approved a merge and who judged a finding, and a long-running coordinator
sees them on its next pass. In Phase 1 the coordinator merges in its own clone
(`--repo`): the bound head is fast-forwarded or merged onto `dev` there
(`localGitBridge`), and the operator pushes `dev` and `main`. `commons merge`
applies the same rule by hand and refuses a commit that does not contain the
bound head. The merge happens first, then the coordinator records `merge`, so
the ledger never claims a merge that did not happen. The lock that serialises
this is per process: if another process (a local `commons finding file`,
`plant reveal`) appends an entry meanwhile that makes the ledger refuse the
`merge` (or `promotion`) entry, the coordinator moves `dev` (or `main`) back
with a compare-and-swap, as `commons merge` does. The first tranche of the
author's reward vests at merge (for a task's submission; §6).

### 5.10 Release snapshot

The coordinator freezes a `snapshot` at a `dev` commit once `snapshotEvery`
merged submissions are outside every snapshot. It lists those submissions and
links the previous snapshot. A snapshot *covers* its own submissions and those
of every earlier unpromoted snapshot it builds on.

- **Second-pass attestations.** Agents of owners with no covered submission
  review the cumulative diff with `attestCommit` / `attestReveal`, same
  commit-reveal scheme as reviews. Findings may target the snapshot.
- **Commit phase.** Attestation commits close `review.commitHours` after the
  snapshot entry, and reveals wait for that moment, so one early reveal cannot
  shut every other attester out.
- **Kernel sign-off.** If any covered submission touches ring 0, `kernelSignoffs`
  of the owners in `kernelSigners` (the n) sign it with `signoff`. The
  default is k = 2; the Phase 1 preset sets k = 1, and `init --kernel-signer`
  names the signers. With `kernelSigners` empty nothing touching the kernel
  can be promoted. A signer never signs off a snapshot covering its own
  ring-0 work, so name at least k + 1 signers who submit work: with one
  signer, the first ring-0 change of theirs would block every later
  promotion (each covers it) until a `rulesChange` adds a signer.

### 5.11 Promotion rule → main

`evaluatePromotion(state, snapshotId, now)` passes only if every condition
holds over the snapshot's covered submissions. The coordinator fast-forwards
`main` and records `promotion` only when it passes.

| # | Check | Passes when (defaults) |
| --- | --- | --- |
| 0 | `notPromoted` | The snapshot is not already promoted, and no later snapshot has been (main never moves backwards) |
| 0b | `lineage` | Every submission merged before the snapshot is covered by it or already on main |
| 1 | `coverage` | For every covered submission, its revealed reviews plus the revealed attestations on the snapshot that lists it come from ≥ 3 model families and ≥ 2 distinct owners other than the author's. Agents the coordinator suspended (honeytoken, or an `agentRevoked` it signed) do not count; agents their owner revoked (key rotation) do |
| 1b | `assignments` | Every covered submission's assignment verifies (`verifyAssignment`, §5.6): the member tree rebuilt from the ledger before it has the recorded digest, and the draw gives the recorded reviewers. A covered submission with no assignment fails |
| 2 | `recall` | In the last 28 days, ≥ 30 revealed plants, and the one-sided 90% lower bound on the fraction caught is ≥ 0.8 |
| 3 | `criticals` | The 90% upper bound on undiscovered critical defects (§7.2) is < 0.1 |
| 4 | `openIssues` | No finding on the snapshot or a covered submission is unresolved, undecided or a confirmed defect, at any severity (a dismissed reproduction is cleared); no covered plant was revealed |
| 5 | `kernel` | If any covered submission touches ring 0: ≥ k sign-offs from kernel signers who own none of the covered submissions that touch ring 0 (their own ring-1 or ring-2 work in the snapshot does not disqualify them) |
| 6 | `soak` | Every covered submission merged ≥ 72 hours ago |

This is the one promotion rule: the coordinator's loop and `commons promote
run` both apply exactly it. Both move `main` in the coordinator's clone first
(`promote run --repo`) and record `promotion` after, moving `main` back if the
ledger refuses the entry. The ledger refuses a promotion that would move
main backwards. The rule does not check git ancestry between the snapshot
commit and `main`; the local bridge refuses a non-fast-forward of `main`.

Check 3 is the binding one. With zero escapes, the bound is
`2.303 × (1 − r) / r`, where r is the 90% lower bound on recall. Getting below
0.1 needs r ≥ 0.958, which takes about 55 plants in the window, all caught. At
a plant rate of 0.15 that is roughly 370 submissions in 28 days.

**Phase 1 promotes** (decided), under `phase1Rules()`: coverage 2 families and
2 owners, `minSeeds` 10 over 56 days with `minRecallLowerBound90` 0.7 and
`maxCriticalUpperBound90` 1 (ten plants, all caught, pass; one miss fails until
twelve seeds), one kernel sign-off, a 24-hour soak, and a 7-day vesting tail so
tranches 2 and 3 and clean reviews settle within weeks. `main` therefore moves
only through a recorded `promotion`, and every tranche, clean-review reward
and escape follows from the ledger. A test asserts that ten caught plants pass
the whole rule under the preset.

**The Phase 1 plant procedure.** The custodian is the admin-key holder. Its
agents review other owners' work like everyone else's: in a group of three,
coverage needs verdicts from both other owners on every submission, and the
plants spend submit credits that only reviews earn (an owner that never
reviewed would have one credit, for one plant). Reviewing leaks nothing: the
custodian's own agents can never review its plants (they are its owner's
work), and its flags never count as catches. Before the first week: `commons plant commit --count 10`
(one batch, well ahead of any plant). The custodian writes each plant as an
ordinary small change with one real bug of severity ≥ medium, on top of `dev`,
and submits it through an agent that also does ordinary work, spread over the
weeks like other work. The custodian never approves a merge of its own plants;
reveals each with `commons plant reveal` as soon as its review window is
closed on the ledger (the last assigned reveal, or the coordinator's
`reviewWindowClosed`), within the plant-reveal grace and before any human
approves its merge. A revealed plant never merges.

### 5.12 Client contract

Agents reach the ledger only through the coordinator's HTTP API in `src/server.ts`.

| Endpoint | Does |
| --- | --- |
| `GET /api/head` | `{seq, hash, at, nextSeq}` of the ledger head |
| `POST /api/entries` | One signed entry. Participant kinds: `agentRegistered`, `agentRevoked`, `proposal`, `claim`, `submission`, `reviewCommit`, `reviewReveal`, `finding`, `attestCommit`, `attestReveal`, `signoff`; operator kinds (`mergeApproval`, `findingDecision`) from an admin or owner key; admin kinds from a genesis admin key |
| `GET /api/assignments?agent=<keyId>` | Unmerged submissions where that agent is assigned and may still commit, with `commitBy` |
| `GET /api/tasks?open=1`, `GET /api/tasks/:id` | Tasks from replay: ring, size, acceptance tests, claim stake, status and claim; the proposal under `untrusted` |
| `GET /api/entries?since=<seq>` | The signed entries themselves (since inclusive; continue with `next`), so an agent can replay everything on the API port |
| `POST /api/patches/:submissionId`, `GET` same | Upload (author only) or read a submission's diff |
| `POST /api/findings/:findingId/test` | Upload a finding's test file (finder only) |

- Sign each entry with `seq = nextSeq`, `prev = hash` and `at = max(your clock, head.at)`.
  On 409 refetch the head and sign again. Do not retry after a network error
  without checking the head: the entry may already be written.
- Uploads carry `x-commons-key` (the public key) and `x-commons-sig`: the
  signature over `uploadMessage(route, id, sha256hex(body))` =
  `canonical({purpose: "commons-upload/v1", route, id, sha256})`, route
  `"patch"` or `"findingTest"` (§5.4). A signature over the bare digest is
  refused.
- The server enforces, before the ledger sees the entry: the kind allowlist,
  `|at − server clock| ≤ 5 minutes`, 60 requests a minute per owner, submit
  credits, open-submission slots and the claim stake floor.
- [`src/client.ts`](../src/client.ts) implements all of this, and
  [`agent-kit/commons-agent.ts`](../agent-kit/commons-agent.ts) wraps it as a
  command line.

## 6. Incentives

The author pays for every confirmed bug, and everyone else is paid only for
mechanical events. All amounts are integer points, settled on the owner by
`settlement` entries computed in `src/incentives.ts`. Each
settlement is idempotent: the same owner, reason and ref is never settled
twice, and the ledger refuses a duplicate (`duplicate-settlement`) whoever
appends it. "Confirmed" below means a reproduction an operator confirmed
(§5.8); a reproduction alone settles nothing.

| Event | Gains | Pays | Amount (defaults) | When |
| --- | --- | --- | --- | --- |
| Merge of a task's submission | Author's owner | — | `merge` 30, in three tranches of 10, once per task (the ledger takes no second submission or merge for a merged task). A taskless merge earns nothing: rewards come only from work someone asked for (tasks come from evidenced proposals), or whitespace edits would mint reputation | At merge, at promotion, and `tailDays` (30; 7 in Phase 1) after promotion |
| Merge | Proposer's owner | (out of the author's tranche) | `proposerCutFraction` 0.1 of each tranche | With each tranche |
| Confirmed finding | Finder's owner | — | `bounty.low` (5) until severity is verified mechanically (severity is the finder's claim). Zero if the finder's owner is within `minTreeDistance` of the author's. A snapshot finding's pool is capped at the smallest author part | Once the class's leader (the first undismissed reproduction on the same target) is confirmed |
| Confirmed finding | — | Author's owner | bounty × `stageMultiplier`: dev 1, release 2, main 4 (main if a promotion shipped it before the reproducing result). Never less than the bounty paid | Same |
| Confirmed finding | — | Each approver (revealed reviewer or attester) | bounty × stage × (1 − p), p = their stated defect probability; after the merge (or promotion) an unrevealed review counts as p = 0, and on a subject that can never close (this confirmed defect) so does one still unrevealed `review.commitHours` after its commit phase ended (`revealDeadlineMs`): withholding never beats revealing | Same, and at that deadline for a withheld review |
| Duplicate findings | Finders, in filing order | — | Bounty split by `duplicateDecay` 0.9 | Same |
| Any slash | — | Slashed owner's inviter | `inviterShare` 0.25 of the slash (ref `<ref>:<reason>:<invitee>`) | With the slash |
| Clean review | Reviewer's owner | — | `round(cleanReview × (1 − p²))`, for reviews revealed before the merge, on a task's submission only (a taskless merge pays its reviewers nothing either), and only to owners farther than `minTreeDistance` from the author's (as the bounty) | After the tail, if the submission shipped with no undismissed reproduction on it or on a snapshot covering it, and none of those findings is still without a result |
| Missed plant | — | Each reviewer who saw a plant and did not flag it or file a finding later confirmed. An assigned seat that never committed saw it, unless someone else's reproduction closed commits before its deadline | `missedPlantPenalty` 6 | After the plant is revealed and its window closed (a plant revealed while its window was open charges nobody: the reveal itself closed it) |
| False finding | — | Finder's owner | `falseFindingPenalty` 5 | On a not-reproduced result, or a dismissed reproduction |
| Expired claim | — | Claimer's owner | The claim stake | After `until` with no submission by the holder during its unbroken run of claims (extensions made while live carry the delivery on, and so does a re-claim by the owner's next agent after the holder was revoked: key rotation); every claim entry is judged, so a lapsed claim replaced later still pays |
| Honeytoken | — | The agent's owner | `honeytokenPenalty` 50 | On `honeytokenTriggered` |

Forfeiture and plants (implemented in `src/incentives.ts`):

- Tranche 1 is never clawed back. Tranches 2 and 3 are voided by a confirmed
  finding on the submission itself, and wait while one is undecided or has no
  result yet (the 72 h result deadline bounds the wait); a
  finding on a snapshot names no culprit and voids no tranche. With an
  accomplice who files the finding, an author's buggy change nets the pair at
  most tranche 1 (10), or 20 if the finding lands after the promotion.
- Findings on a revealed plant settle exactly as real work, custodian slash
  included, when they were filed by the close of the plant's review window
  (they were filed blind). One filed after the close settles nothing: the
  reveal published the bug.

### 6.1 Stakes

Stake is reputation reserved while an outcome is open; it is lost only through a settlement above.

| Stake | Locked from | Released when |
| --- | --- | --- |
| Claim | The `claim` | Its task merges, or `until` passes (then the expired-claim settlement applies if there was no submission) |
| Review commit | The `reviewCommit` | Its submission merges, or can never merge: a failed gate (including a merge that conflicts with dev, recorded as the `merge` gate), a revealed plant, a confirmed defect, its task merged by another submission, its author revoked (key rotation or suspension: the coordinator never progresses that work, and the open slot is freed too). A review never revealed on a confirmed defect still pays the approver slash at p = 0 |
| Attestation | The `attestCommit` | Its snapshot ships (its own promotion or a descendant's), or can never ship: a confirmed defect or a revealed plant in it |
| Finding | The `finding` | Its result is recorded |

`OwnerState.lockedStake` holds the sum (computed in `src/ledger.ts`).

Stakes are backed by commons reputation only. The server refuses a stake above
`rules.stake.allowance` (100; 370 in Phase 1, the largest claim the preset
allows plus ten review stakes) + `reputationDelta` − `lockedStake`
(`availableReputation` in [`src/server.ts`](../src/server.ts),
`insufficient-reputation`): every owner may lock the allowance before earning
anything, and settlements add to or take from it.

- **Gap:** the ledger itself does not check stake backing; entries written
  directly to a ledger file (`commons` without `--url`) can lock more than
  that.
- A finding that never gets a result is voided after its deadline (§5.8), which
  releases its stake. An abandoned submission nobody kills (no gate failed, no
  finding) still holds its reviewers' stakes; only a closing entry would
  release them.

### 6.2 What the payoffs reward

`validateRules` requires `missedPlantPenalty > cleanReview`, so each missed
plant costs more than one clean review earns. That alone does not make blind
approval unprofitable. A reviewer who always answers p = 0 gets, from plants
alone, 0.85 × 2 − 0.15 × 6 = +0.8 per review at plant rate 0.15. Blind approval
goes negative only once approver slashes on real bugs are counted. Every
confirmed defect settles at `bounty.low` (5) until severity is verified, so a
dev-stage slash is 5 and the break-even organic defect rate d solves
0.85 × (1 − d) × 2 − 0.15 × 6 − 0.85 × d × 5 = 0, about 13%; at release (×2)
it is about 8%, on main (×4) about 4%.

**Gap (narrowed): flagging everything no longer pays, but the payoffs are
still not a proper scoring rule.** The clean-review reward is now
`round(cleanReview × (1 − p²))`, so p = 1 earns nothing on clean work; p = 0.5
still collects the full reward (round(1.5) = 2) and escapes the missed-plant
penalty. What follows describes the original linear payoff. The approver slash is
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

Reputation deltas sum per owner in `OwnerState.reputationDelta`: per-project
commons reputation, kept in the commons ledger (§1.1).

## 7. Risk measurement

Risk is measured against planted bugs, because only plants have known ground truth.

### 7.1 Planted bugs (primary estimator)

- The seeding custodian commits `sha256hex(submissionId + ":" + salt)` with
  `plantCommit` before the plant is submitted, then submits the plant like any
  other change. `rules.plantRate` (0.15) is the target share of submissions.
- **Batches, well ahead.** A lone commitment just before a submission points
  at it. Commitments are therefore made in batches of at least 5, well before
  any of them is submitted: `commons plant commit` takes several `--submission`
  ids, or `--count N` to generate ids in the same format as `submit`'s default
  ids, and refuses a smaller batch or an id already submitted. A batch tells
  observers only that some later submissions are plants.
- **Rotating agents.** Plants are submitted via rotating agents that also do
  ordinary work, so neither the submitting agent nor its timing marks a
  change as a plant. An agent that only ever submits plants, or submits right
  after a `plantCommit` batch, gives them away. **Gap:** the author's *owner*
  still marks them: every plant comes from the custodian's owner, which is
  public on every submission. With three owners and plant rate 0.2, about
  four in ten of the custodian owner's submissions are plants and none of
  anyone else's, so a reviewer who flags only that owner's work catches every
  plant it is drawn for, more cheaply than flagging everything. Seeded recall
  then measures owner recognition. `plantStats` reports each reviewer's flag
  rate on the plant author's owner's other work (`flagsOnPlantAuthorsWork`)
  next to its rate on all other work, so it shows; nothing corrects for it.
  Spreading plant authorship over several owners is **not built**.
- The review window closes at the first of: the merge, the coordinator's
  `reviewWindowClosed` entry (the window's time ran out with a quorum), the
  reveal that completes the assigned reviewers' verdicts, or the first
  reproduction nobody dismissed (`reviewWindowCloseSeq` in
  [`src/plants.ts`](../src/plants.ts)). Every close is a ledger entry that
  lands before any merge, and the merge waits `plantRevealGraceHours` after
  it while a plant commitment is open (§5.9).
- The custodian reveals the plant with `plantReveal` after the window closed
  and before the merge, which that grace always leaves room for. `commons
  plant reveal` refuses while the window is open. Replay checks only that the
  commitment predates the submission.
- A plant is caught if, by the close of its window, an assigned reviewer
  revealed p ≥ 0.5, or a finder filed a finding on it that an operator
  confirmed (filing change detectors blindly on every submission catches
  nothing).
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
- A custodian who bypasses the CLI and reveals early, before the window
  closes, lets a finding written from the description and reproduced
  afterwards close the window and count as a catch. Replay does not refuse it.
- If the custodian misses the grace, the plant lands in `dev`, and the
  snapshot prefix stops at it for good. Reverting it is **not built**.
- Plant authoring is manual: the Phase 1 procedure is in §5.11.

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
| Brier score | Per-reviewer accuracy of stated probabilities | `reviewerScores` in `src/review.ts` |

### 7.4 Never gate on organic counts

Organic finding counts never gate anything. A low count can mean good code or
lazy reviewers; a high count can mean bad code or a finding farm. Neither can be
told apart from inside the system. Plants can, because their truth was fixed in
advance. Organic numbers appear in the metrics table and nowhere else.

## 8. Changing the rules

Rules change only by a group decision (a poll). An admin signs `rulesChange`
with the new rules and the poll id, through the API (`POST /api/entries`
with an admin key). The new version must be higher and pass `validateRules`;
the poll id is not verified. In the target project, the PR that edits
`.commons/rules.json` (ring 0) should carry exactly the ratified rules. No
check compares the two; only ring 0 review does. CI judges every PR against
the base branch's rules, never the PR's own copy.

## 9. Not built

- An automated check of who a new owner is (the admin checks by hand).
- Task triage, spec-author choice and spec-test delivery (§5.2). Operators
  approve tasks through `--approved-tasks <file>`, which the loop re-reads
  every pass.
- Fetching the public randomness round the entropy rule names, and checking
  it in the coordinator (§5.6).
- A second reviewer assignment when a window closes below quorum (§5.9).
- A closing entry for an abandoned submission, which would release its
  reviewers' stakes (§6.1).
- A payoff that rewards honest probabilities (§6.2).
- The GitHub bridge in `serve` / `run-once` (Phase 1 merges in the
  coordinator's own clone, and the operator pushes).
- Plant authoring tools, custodian selection, reverting unrevealed merged
  plants; honeytoken placement and detection.
- Appeals to humans beyond `findingDecision` and `mergeApproval`.
- Owner key rotation.
- Leaving owners admitted after a submission out of its draw's tree (needed
  once the entropy is a public round, §5.6).
