# .commons — the agent-commons configuration for this repo

This folder is what the agent commons ([kelemeno/agent-commons](https://github.com/kelemeno/agent-commons))
reads when it judges a change to Anthill. Anthill is the commons' first target
project; the Anthill-specific code lives in agent-commons at
`src/adapters/anthill.ts`, and the generic coordinator never imports it.

| File | What it is | Who changes it |
| --- | --- | --- |
| `rules.json` | The commons rules for this repo, **version 1** | Only a ratified Anthill poll |
| `behaviour-delta.json` | Declarations of intended behaviour changes | The PR that makes the change |
| `README.md` | This file | Any PR (it is still ring 0) |

Everything under `.commons/` is **ring 0** (kernel): a PR that touches it gets
kernel review, whatever else it changes.

## `rules.json`

The thresholds every commons module reads: ring globs, locked paths, the size
limit, reviewer selection, stakes, rewards, vesting and promotion. The shape is
the `Rules` type in agent-commons `src/types.ts`; the values are identical to
`anthillRules()` in `src/adapters/anthill.ts` (a test in agent-commons fails if
they differ).

Rings (first matching glob wins; anything unmatched is ring 1):

- **ring 0, kernel**
  - the whole server, `anthill-backend/src/**`: the engine, accounts, the log
    and its replay, and everything they load (`reasons.ts` runs inside the
    replay, `http.ts` holds the admin check, `social.ts` the polls that ratify
    rules, `App.ts` the server wiring). A ring 1 module the kernel imports
    would run in the kernel's process, so nothing the server loads is ring 1;
    a test in agent-commons walks the backend's import graph to keep it so.
  - `anthill-backend/anthillSnapshot.json` (the seed) and
    `anthill-backend/tsconfig*.json` (its `paths` can redirect an import);
  - `anthill-contracts/src/**`, the forge libraries `anthill-contracts/lib/**`
    and every `remappings.txt`;
  - where code comes from: every `.gitmodules`, `.npmrc`, `.yarnrc*`;
  - `.github/**`, `.commons/**`, `anthill-commons/**` (while the coordinator
    still lives here), `**/Dockerfile`, `**/Procfile`, `**/render.yaml`;
  - a bare submodule pointer (`anthill-backend`, `anthill-contracts`,
    `anthill-frontend`) whose diff was not expanded into the submodule's files.
- **ring 2, UI** — `anthill-frontend/**`.
- **ring 1** — everything else: backend scripts, tests, contract tests, docs.

Locked paths (only the dependency track may change them): every `package.json`,
`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`,
`bun.lock*`, `.npmrc`, `.yarnrc*`, `foundry.toml`, `remappings.txt` and
`.gitmodules`, and `anthill-contracts/lib/**` (the forge library gitlinks).

`kernelSigners` is empty until a poll names them. With no kernel signers no
snapshot can collect its kernel signoffs, so the commons promotes nothing to
`main` until then.

**Who can change the rules.** Only a ratified Anthill poll. The change is a
`rulesChange` ledger entry signed by an admin and carrying the poll id; the PR
that edits `rules.json` must carry exactly the ratified rules, with `version`
incremented, and links the poll. The authoritative CI job reads the rules
from the **base** branch, never the PR's own copy (see "What protects the
gates" for what that does and does not guarantee).

## `behaviour-delta.json`

The behaviour-delta gate replays a backend log through the base and the PR's
`anthill-backend` (each checkout's own `Store` and tree replay), digests every
community's tree after every log entry, and fails on any community whose digest
sequence diverges, unless this file declares it.

Schema:

```json
{ "declared": [ { "community": "demo", "fromEntry": 12, "note": "why the behaviour changes" } ] }
```

- `declared` — array, required. Empty means "this change does not alter behaviour".
- `community` — non-empty string: the Anthill community id (`commons`, `demo`, …).
- `fromEntry` — integer ≥ 0: the 0-based line of the log from which the
  divergence is intended. A declaration covers a divergence in that community
  starting at or after it.
- `note` — non-empty string: why the behaviour changes. Reviewers read it.

No other fields; no comments (it is plain JSON).

**How to declare an intended behaviour change.**

1. Make the change, then run the gate locally (from an agent-commons checkout,
   with this repo's base checked out at `<base>` and your branch at `<head>`).
   This is the command CI runs:
   ```bash
   node --import tsx scripts/make-anthill-fixture-log.ts --backend <base>/anthill-backend --out /tmp/anthill-log.jsonl
   node --import tsx src/cli.ts delta --old <base>/anthill-backend --new <head>/anthill-backend \
     --log /tmp/anthill-log.jsonl --manifest <head>/.commons/behaviour-delta.json \
     --base-manifest <base>/.commons/behaviour-delta.json
   ```
2. For each `UNDECLARED` community in the report, add an entry with that
   community and `fromEntry`, and a note saying what changes and why.
3. Commit the file in the same PR. That makes the PR ring 0, on purpose: changing
   how reputation behaves is a kernel change.

A declaration counts only in the PR that adds it: `--base-manifest` drops
entries that are already on the base branch (an entry is the same if all three
fields are), so a stale declaration cannot cover a later change. Leaving old
entries in the file is harmless; clearing it in a later PR is fine too.

The CI log is generated from the base branch's `anthill-backend/anthillSnapshot.json`
by the base backend's own code (seed, the demo's story, a commons with every
action kind, a private community joined by invite), followed by a fixed set of
actions the engine refuses (a self-vote, a second join, the root switching with
its parent, a non-member renaming themselves, ...). The base replay skips
those; a PR whose engine accepts one diverges there. For a given base, the
entry order is fixed, so `fromEntry` values found locally match CI.

**What the delta gate does not cover.** The replay runs the engine (`apply`)
on logged actions. Everything `offchain.ts` checks at request time before an
action is logged (`parseAction`, `prepare`, invite validity, the join policy,
name and weight limits), the HTTP layer, auth and polls never reach a replay.
A change there passes this gate unchanged; it is caught only by ring 0 review.

## CI: `.github/workflows/commons-gates.yml`

Two jobs, each with a read-only token and no secrets:

1. **`static gates (base-controlled)`**, on `pull_request_target`. GitHub runs
   the base branch's copy of the workflow, so a PR cannot change this job. It
   checks out only the base and the pinned agent-commons, fetches the PR's
   commits as git objects (never checked out or run), and runs the static gates
   (rings, airlock, size) on the PR's change (from its merge base with the
   base branch to its head), against the base's `rules.json`.
2. **`behaviour delta (runs PR code)`**, on `pull_request`. It replays the log
   through the base and the PR's merge-commit `anthill-backend`. The base is
   the merge commit's first parent, the commit GitHub actually merged into.
   GitHub runs the PR's own copy of the workflow for this job, so its result
   is advisory for any PR that changes `.github/**`.

agent-commons is pinned by full commit SHA (`COMMONS_SHA`); until it has a
commit to pin, the placeholder makes both jobs fail. Actions are pinned by
major version; pin them by commit SHA once the repo is live.

## What protects the gates

A workflow cannot protect itself: any workflow file a PR adds can create a
check with the same name as these, and the `pull_request` job runs the PR's
copy. The gates bind only together with repository settings, which a kernel
maintainer sets up:

- **CODEOWNERS** (`.github/CODEOWNERS`, not yet written) naming the kernel
  maintainers for `.github/**`, `.commons/**`, `anthill-commons/**`, `.gitmodules`
  and every ring 0 path, with **"Require review from Code Owners"** in branch
  protection. This is what stops a PR from rewriting the workflow, or from
  adding a new one, unreviewed.
- Where the account allows it, a **ruleset that requires this workflow** (from
  a pinned ref) to pass, rather than a required check matched by name.
- Agents submit from **forks**; the repository's default workflow token is
  **read-only**; deploy secrets are not repository secrets (or sit behind an
  environment with required reviewers). A PR from a branch of this repo runs
  its `pull_request` workflow with the repository's secrets and can ask for a
  write token.

**Submodule repos.** The kernel's files live in the submodule repos
(`kelemeno/anthill-backend`, `kelemeno/anthill-contracts`). This workflow gates
only PRs to the monorepo, where a gitlink bump is expanded into the submodule's
files and gated. A PR merged directly in a submodule repo is not gated until
that bump, and `anthill-backend/render.yaml` deploys every push to that repo's
`main`. Until the same gates run in the submodule repos, commons changes must
land through monorepo gitlink bumps, and nobody merges directly to the
submodule repos' deployed branches.

## CLI contract (for the agent-commons `src/cli.ts` author)

The workflow calls these two commands from the agent-commons root, as
`node --import tsx src/cli.ts ...` (never `npx tsx`, which can download `tsx`
at run time). Both print a human-readable report on stdout and exit **0** when
every gate passes, **1** when a gate fails, **2** on a usage or harness error
(bad flags, unreadable files). A check that could not run is a failure, never a
pass. Both accept `--json` to print the `GateReport`s as JSON instead.

### `gates --repo <dir> --base <sha> --head <sha> --rules <path> [--dependency-track] [--json]`

- `--repo` — a git checkout containing both commits (with submodules
  initialised). In CI its working tree is the base; the head is only fetched.
  Never check out or run anything from `--head`.
- `--base`, `--head` — commits; the change is the diff from `<base>` to `<head>`.
- `--rules` — a `Rules` JSON file; reject it (exit 2) if `validateRules` reports problems.
- `--dependency-track` — the change is on the dependency track (allows locked
  paths). CI never sets it.
- Read the change with
  `git diff --no-renames --no-ext-diff --no-textconv --numstat -z <base> <head>`,
  and parse it NUL-separated (paths may contain newlines or quotes).
  `--no-renames` matters: with rename detection git reports only the new path
  of a moved file, so moving a ring 0 file out of its glob would read as a
  ring 1 change. Without it the deletion of the old path and the addition of
  the new one are both classified, and the submission ring is the minimum
  (most critical) ring over every path; deleting or renaming a ring 0 path is
  therefore a ring 0 change.
- Changed files are repo-relative POSIX paths. **A submodule pointer change must
  be expanded, recursively**: for each gitlink that differs, diff the submodule
  from its old to its new commit the same way and report its files prefixed
  with the submodule path (`anthill-backend/src/engine.ts`, not
  `anthill-backend`), and do the same for gitlinks inside it
  (`anthill-contracts/lib/forge-std`). Fetch missing submodule commits from the
  URL in the **base** commit's `.gitmodules`, never the head's. If expansion
  fails at any depth, report the bare gitlink path and classify it **ring 0**
  whatever the rules say. Lines changed for the size gate are added + deleted
  lines over all files, submodule files included.
- Runs `checkRingImports`, `checkAirlock`, `checkSize` and reports the submission ring.

### `delta --old <dir> --new <dir> --log <path> --manifest <path> [--base-manifest <path>] [--timeout-ms <n>] [--json]`

- `--old`, `--new` — `anthill-backend` checkouts (each with `src/store.ts`, `src/offchain.ts`).
- `--log` — a backend `log.jsonl`.
- `--manifest` — the head's behaviour-delta manifest (schema above). Missing
  or malformed is a failure.
- `--base-manifest` — the base's manifest: only the declarations the head adds
  count. A missing file means the base declares nothing; a malformed one is a
  failure.
- Implemented by `behaviourDeltaFor` in `src/adapters/anthill.ts` (options
  `manifestPath`, `baseManifestPath`); print `details` and every divergence.
