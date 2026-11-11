# Handoff — state of the agent-commons build

Last updated by the build session on 2026-11-11. Branch `wip-core` holds work in
progress; `main` gets a clean commit once the final integration pass is green.

## What this is

The coordinator for an open agent commons, for any git repository. Design
doc: a claude.ai doc. Contracts: `ARCHITECTURE.md`,
shared types: `src/types.ts`. A static demo of the playground (fake data) was
published as a private claude.ai artifact ("overview · agent commons").

## Decisions taken (do not relitigate)

- **The external identity provider and target project were removed
  entirely; the commons has its own ledger-derived membership tree.** No
  code, config, test, flag, env var or doc depends on an outside project
  (the old name survives only in the records under `handoff/` and in git
  history). Owners are the ledger's `ownerKey` entries, and the trust
  tree is their invite tree (`src/members.ts`: parent = inviter, owners with
  no inviter under one virtual root). Reviewer draws use only that tree, so
  every draw is verifiable from the ledger alone. Reputation is per-project
  commons reputation (settlements): it backs stakes (with
  `rules.stake.allowance`) and sets PR slots. Phase 1 is the admin issuing
  `ownerKey` entries for 3–10 trusted people (that is the allowlist).
- The commons is generic: `defaultRules()` names no project's paths, and each
  target project declares its own kernel rings in its `.commons/rules.json`.
- One dev branch + main; stages are per-commit state; signed release snapshots;
  human k-of-n sign-off on the kernel.
- Agents run in cloud sandboxes (Claude Code routines, open models via OpenRouter);
  never push with participants' credentials; coordinator bot opens PRs.
- Run incentives with simple numbers; do not tune until there are real participants.
- **Merge judgement is the reviews, not the gate** (owner decision, differs from samsara's
  deterministic approach): be probabilistic about the code, deterministic about the
  reviewers. As built, reviewer defect probabilities are only scored, never used to merge;
  change that. Merge when a calibration-weighted pooled risk (e.g. log-odds pooling, weights
  from each reviewer's Brier/plant record, new reviewers at a low default weight) is below a
  per-ring threshold in Rules; high disagreement or one well-calibrated "risky" verdict
  escalates to more reviewers instead of blocking; a reproduced finding still hard-blocks;
  kernel still needs human sign-off. Plants and escapes are what keep the reviewer weights
  honest, so they stay mandatory. Add this to coordinator.ts (mergeability), promotion.ts
  and Rules, with tests, in the final wave.

## Module status

| Module | Status |
|---|---|
| crypto, rules, ledger | built, reviewed (contract + adversary), fixed |
| members (ledger-derived trust tree; replaced the old tree module) | built, tested |
| risk, plants | built, reviewed, fixed |
| findings (reproduction harness) | built, reviewed, fixed — no git worktrees (exports plain dirs); same-uid /proc reach remains, needs container for strangers |
| playground (+ render) | built, reviewed, fixed |
| docs/ | written, reviewed |
| selection, review | built, reviewed, fixed |
| incentives | built, reviewed, fixed |
| gates (rings, airlock, specSeparation, size, index) | built, reviewed, fixed (cli wiring of new inputs pending) |
| promotion, metrics | built, reviewed, fixed |
| server, coordinator, github bridge, client + agent-kit | built, reviewed, fixed |
| cli | built, reviewed, fixed (the 19 issues in `handoff/runtime-result.json` `reviewIssues.cli`, verified with tests in the integration pass) |

## Continue on the Mac mini

```bash
git clone https://github.com/kelemeno/agent-commons && cd agent-commons && git checkout wip-core && npm install
```

Then `npm run check`. No environment variables are needed; the only skipped
tests are the Linux-only sandbox tests. `handoff/final-wave.js` is the
workflow script the final wave ran (a historical record).

Reports from every module's build, adversarial review and fix are in `handoff/`
(`*-result.txt`, `runtime-result.json`); their UNRESOLVED lists are the
cross-module work for the integration stage.

Integration pass (2026-11-11, on the Mac mini): the whole suite and the type
check are green; duplicated definitions are single-sourced (see ARCHITECTURE.md,
"One definition per rule").

## Final wave (to do after all modules land)

1. ~~Integration: single-source duplicated definitions; full `npm run check`
   green without weakening tests.~~ Done.
2. ~~Phase 1 without outside identity.~~ Done, and since superseded by the
   ledger-derived member tree (see "Own membership tree" below): `phase1Rules()`,
   `init --preset phase1 --kernel-signer`, README Phase 1 quickstart,
   protocol §1.1. Stakes are backed by commons reputation
   (`rules.stake.allowance` + settlements).
3. ~~Ledger input limits: max lengths/counts for titles, summaries, details, paths,
   commands, harness, refs, ids; reject ids made only of dots or containing `/`.~~
   Done (`LEDGER_LIMITS`, `ID_RE` in `src/ledger.ts`).
4. ~~Plant procedure: batch plant commitments well ahead of submission; submit via
   rotating agents that also do ordinary work (timing must not reveal plants).~~
   Done in the CLI and docs (protocol §7.1); replay still does not check reveal timing.
5. ~~Optional `harnessError` on findingResult so "could not run" ≠ "did not reproduce".~~ Done.
   Also done in the hardening pass: verifiable reviewer assignment (entropy and
   tree digest on `reviewAssignment`, beacon checked by the ledger, promotion
   `assignments` check) and a closed `rules.modelFamilies`. Still open:
   fetching the public randomness round the entropy rule names.
6. ~~ARCHITECTURE.md: findings uses exported plain dirs, not worktrees; `/api/entries`
   `since` is inclusive, clients continue with `next`.~~ Done.
7. ~~End-to-end lifecycle test on a temp git repo (propose → task → claim → submit →
   gates → assign → commit/reveal → finding reproduced → settlements → merge →
   snapshot → plants → promotion check).~~ Done: `test/e2e.test.ts` (real modules,
   coordinator loop, HTTP server + client, playground and CLI on one ledger; ~2 s).
   Spec tests reach dev as a direct commit there, not as their own submission.
8. Whole-system adversarial review and fix: done (2026-11-11), see below.
   Still to do: a clean commit to `main`.
9. Re-publish the playground demo on the real modules.

## Whole-system review: what changed

Four reviewers' findings were fixed with regression tests (suite: 747 tests,
744 pass, 0 fail, 3 skipped Linux sandbox tests). The protocol changes, in short:

- A reproduced finding is evidence, not a verdict: `findingDecision`
  (confirm/dismiss, by an admin or a kernel signer) decides it in every phase;
  undecided it blocks and pays nobody; dismissed it costs the finder.
- Commit phase: no reveal before the assignment or before every seat
  committed or `rules.review.commitHours` (12) passed; attestations likewise
  from the snapshot entry.
- Human approvals (`mergeApproval`), harness attempts (`findingAttempt`) and
  the review window's close (`reviewWindowClosed`) are ledger entries.
- Merges need an assignment (ledger), taskless merges vest nothing, a flagged
  merge needs a human in Phase 2 too, settlements are unique on the ledger,
  main never moves backwards, claims are capped per run and every claim is
  settled, dead work releases review stakes.
- One promotion rule (any unresolved finding blocks); unverifiable
  assignments fail it.
- The base must be on dev (`--dev-ref`); Phase 1 merges in the coordinator's
  clone (`localGitBridge`); `commons merge` applies the merge rule.
- The sandbox preflight refuses a same-uid sandbox; the harness probes its
  checkout first; `--share-checkout`, `--setup-command`; `scripts/sandbox-docker`.
- Server: timeouts, per-IP concurrency, trusted proxies, `/api/tasks`,
  `/api/entries`, operator kinds; the store catches up with local writes.
- Phase 1 promotes under `phase1Rules()` (tail 7 days, allowance 370: the largest claim, 320, plus headroom).

## Confirmed-issue fixes, round 1 (2026-11-11)

Suite after: 768 tests, 765 pass, 0 fail, 3 skipped. In short:

- Ledger: a cross-process file lock (`<ledger>.lock`) around every read and
  append; submission and finding ids unique ignoring case, submission ids
  git-ref safe; claims live through `until`; no submission, merge or second
  reward for a task that already merged.
- Reviews: commitments bind reviewer and subject (a copied commitment can
  never be revealed, and a repeated one is refused); a review withheld on a
  confirmed defect pays the approver slash at p = 0 after its reveal
  deadline; `GET /api/assignments` lists `pendingReveals`
  (`commons-agent pending`), and the kit's docs require durable salts.
- Incentives: Phase 1 `reviewsPerSubmitCredit` 1 and allowance 370; tranches
  and clean reviews wait for findings without a result; a claim run's
  submission covers its extensions.
- Gates and rules: `.gitattributes` and gyp files are ring 0 (gyp and
  Node-version files locked); ring-2 markup (`<script src>`, `<link href>`) is scanned; gate
  details are cut to the ledger's limit and the CLI requires its full gate
  list; a merge conflict is a failed `merge` gate.
- Binding and CLI: `commons submit --repo` declares the commons commit; the
  binder refuses a stored patch that is not the declared head and throws on a
  misconfigured `--dev-ref`; `commons merge` restores dev when the ledger
  refuses.
- Harness: random sentinel and checkout names; no re-chmod of setup output;
  the preflight refuses a sandbox whose runs share state and checks
  `--setup-sandbox`; leftovers are cleaned through the sandbox and
  `cleanupError` is logged.
- Selection: the pool is fixed at the submission; the entropy round is keyed
  to `at` + 5 minutes; the plant reveal caps the review window; a kernel
  signer is excluded only by its own ring-0 work.
- Server: IPv6 counted per /64; the minimum body rate holds all along.

## Confirmed-issue fixes, round 2 (2026-11-11)

Suite after: 787 tests, 784 pass, 0 fail, 3 skipped (Linux-only sandbox tests). In short:

- Harness: a timed-out run's group gets SIGTERM, then SIGKILL after
  `KILL_GRACE_MS`; `scripts/sandbox-docker` names its container and kills it
  on SIGTERM; `removeTree` walks by chdir with dev/ino checks in a child
  process (fs.rm and macOS `rm -rf` follow a symlink a still-running
  container swaps in).
- Merges: `localGitBridge` merges with `-X no-renames` and refuses a merge
  that changes paths outside `base..head`; a refused merge or promotion
  entry moves dev/main back (`GithubBridge.tip`/`restore`); `promote run`
  needs `--repo` and moves main itself; git failures in the binder throw;
  its temporary index lives in `.git`; case-twin paths never bind.
- Rings and airlock judge paths under case folding (`Src/x.ts` is ring 0,
  `Package.json` is locked).
- Selection: an owner that committed before the draw is seated through that
  agent (the ledger refuses an unfillable seat, and a second agent's commit
  on a seated owner); a lone other-family owner is no longer forced in.
- Incentives: taskless merges pay clean reviews nothing; clean reviews pay
  only owners beyond `minTreeDistance`; a revoked author's submission is dead
  (stakes and slot released); a claim run passes to the owner's next agent
  after key rotation.
- Client: commits check everything the reveal will (`verdictProblems`,
  `citedFindingProblems`); `FindingUploadError` and `commons-agent
  upload-test`. Server: a response deadline for clients that never read.
- Ledger: a partial append is cut back; `commons ledger repair`.
- Docs: the custodian reviews (Phase 1 coverage and credits need it); two
  kernel signers; the push identity under branch protection; the lockfile
  gap; bounty.low costs; the plant-owner gap; the upload signature in §5.12.

## Own membership tree (2026-11-11)

The outside identity provider and target project are gone. Suite after:
700 tests, 697 pass, 0 fail, 3 skipped (Linux-only sandbox tests), with no
environment variables set.

- `src/members.ts` replaces `src/tree.ts`: `memberTree(state)` is the
  ledger's owners under their inviters, owners with no inviter under the
  virtual root `(commons)`, sorted and deterministic; `memberDigest(state)`.
- `TreeView.reputation()` is gone; PR slots are `prSlots(max(0,
  reputationDelta))`.
- Selection takes no tree: `drawAssignment(state, id, entropy)`,
  `verifyAssignment(state, id)`. The ledger refuses a `reviewAssignment`
  whose `treeDigest` is not the member-tree digest of the state before it;
  verification rebuilds that tree from the owners registered before the
  assignment. The beacon is `assignmentBeacon(submissionId, headCommit,
  entropy)`: the digest is recorded and checked but is not a beacon input,
  so an owner admitted between the submission and the draw moves neither.
  Owners in different invite lines (meeting only at the virtual root) hold
  the full weight `MAX_WEIGHT`, so an invitee does not outweigh owners
  admitted with no inviter. `evaluatePromotion(state, snapshotId, nowIso)`.
- Deleted: `src/adapters/`, `src/gates/behaviourDelta.ts` and the `delta`
  command, `targets/`, the backend fixture script and tests, the backend
  checkout env var, and the CLI options `--tree`, `--allowlist`,
  `--drawn-over` and `--target`.
- `defaultRules()` is generic (commons config, CI, git hooks, build, deploy,
  bundler and compiler config and `index.html` are ring 0; manifests,
  lockfiles and what the package manager runs at install are locked);
  projects declare their kernel in `.commons/rules.json`, ring-2 globs after
  the defaults. The package is `agent-commons`.

## Phase 1 checklist (three people, real agents)

In dependency order. Code-side items are done unless marked **(operator)**.

1. **Target (operator).** Choose the target repository and commit its
   `.commons/rules.json`: `defaultRules()` plus the project's own kernel
   paths as ring 0 (whatever decides who may act or holds state) and any UI
   as ring 2; it is ring 0 itself. Optionally add a CI job that runs `commons
   gates --repo . --base <base> --head <head> --rules <the base commit's
   .commons/rules.json>` (always the base's rules, never the PR's copy).
   Protect `dev` and `main` with "Require review from Code Owners", "Dismiss
   stale pull request approvals", "Require approval of the most recent
   reviewable push" and "Do not allow bypassing" (and require the CI check
   if there is one). Those settings refuse every direct push, which step 2
   needs: give the coordinator's push identity (a dedicated machine user or
   deploy key, used for nothing else) a bypass for pull requests on `dev` and
   `main` only (a ruleset bypass list, or "Allow specified actors to bypass
   required pull requests"), so the commons' own gated, human-approved merges
   and its promotions reach GitHub; everyone else, admins included, still
   needs a code-owner-reviewed PR. Check that a push from that identity
   succeeds and one from your own account is refused. (Without a bypass, open
   a PR from the clone's `dev` instead and have code owners approve it.) If
   the repository has no `dev` branch, create one, or pass `--dev-ref
   <ref>` everywhere.
2. **Coordinator host (operator).** A clone of the target with a `dev`
   branch, the ledger, `commons init --project <id> --admin-key <admin>
   --coordinator-key <coord> --rules .commons/rules.json --preset phase1
   --kernel-signer <owner> --kernel-signer <another owner>` (two signers: a
   signer cannot sign off its own ring-0 work); `serve --coordinator --loop-seconds 60 --repo
   <clone> --sandbox '["<abs>/scripts/sandbox-docker"]' --share-checkout
   --snapshot-every 5` (without `--snapshot-every` nothing is snapshotted, so
   nothing is promoted and `main` never moves; TMPDIR on a small filesystem
   of its own, see the script's notes)
   (Docker installed; check the preflight passes with `finding verify` on a
   test you wrote); push `dev`/`main` from the clone after merges and
   promotions, as the push identity of step 1.
2b. **Lockfile (operator).** If the target commits no lockfile, `npm ci`
   (the kit's install with a lockfile) refuses to run there; until one lands
   through the dependency track, agents and `--setup-command` use `npm install
   --ignore-scripts --no-package-lock --no-audit --no-fund`, which resolves
   ranges at install time. Commit a lockfile before strangers join.
3. **Operator decisions.** `commons approve`, `commons finding
   confirm|dismiss` (or POST through the API); tasks via an `--approved-tasks`
   file the loop re-reads.
4. **People and keys (operator).** The admin admits 3 owners by hand
   (`commons owner add --owner <id> --owner-key <key>`, with `--inviter
   <owner>` when one vouched for the other); those entries are the allowlist
   and the member tree. Each owner registers at least 2 agents of different model
   families (requireOtherModelFamily and promotion `minModelFamilies` 2 fail
   if everyone runs one family). Check each agent's cloud sandbox allows
   `run-untrusted` (root + unshare), or use a Docker runner.
5. **Exposure (operator).** Put the API behind HTTPS (a reverse proxy, named
   with `serve --trusted-proxy <addr>`).
6. **Plants (operator).** The admin-key holder is the custodian:
   `plant commit --count 10` before the first week, then the procedure in
   protocol §5.11. The custodian's agents review other owners' work too
   (coverage needs both other owners in a group of three, and plants spend
   submit credits that reviews earn).
7. **Dry run (operator).** One Phase 1 day on a throwaway fork of the target
   before inviting the other two people.

Not done in code (reasons in the review report): the GitHub bridge in
`serve`/`run-once` (Phase 1 uses the local clone), a second reviewer
assignment below quorum, a closing entry
for abandoned submissions, fetching the public randomness round. Also open
after round 1: a harness error only on the head side still voids a finding
after `maxHarnessErrors` instead of going to an operator; the harness's
checkout bind mount has no size limit of its own (put TMPDIR on a small
filesystem).

## Access notes

- Push works for `kelemeno/agent-commons`.
- Build ran in a 4-CPU cloud container (2 concurrent agents per workflow). The
  final wave is faster on a bigger machine: clone, `git checkout wip-core`,
  `npm install`, `npm run check`, and give a new session this file.
