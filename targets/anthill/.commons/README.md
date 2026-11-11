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

- **ring 0, kernel** — `anthill-backend/src/{engine,auth,store}.ts`,
  `anthill-backend/src/offchain*.ts`, `anthill-contracts/src/**`, `.github/**`,
  `.commons/**`, `anthill-commons/**` (while the coordinator still lives here),
  `**/Dockerfile`, `**/Procfile`, `**/render.yaml`, and a bare submodule pointer
  (`anthill-backend`, `anthill-contracts`, `anthill-frontend`) whose diff was not
  expanded into the submodule's files.
- **ring 2, UI** — `anthill-frontend/**`.
- **ring 1** — everything else (pure logic, scripts, tests, docs).

Locked paths (only the dependency track may change them): every `package.json`,
`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `foundry.toml`, and
`.gitmodules`.

`kernelSigners` is empty until a poll names them. With no kernel signers no
snapshot can collect its kernel signoffs, so the commons promotes nothing to
`main` until then.

**Who can change the rules.** Only a ratified Anthill poll. The change is a
`rulesChange` ledger entry signed by an admin and carrying the poll id; the PR
that edits `rules.json` must carry exactly the ratified rules, with `version`
incremented, and links the poll. CI judges every PR against the rules on the
**base** branch, never the PR's own copy, so a PR cannot loosen the rules it is
judged by.

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
   with this repo's base checked out at `<base>` and your branch at `<head>`):
   ```bash
   npx tsx scripts/make-anthill-fixture-log.ts --backend <base>/anthill-backend --out /tmp/anthill-log.jsonl
   npx tsx src/cli.ts delta --old <base>/anthill-backend --new <head>/anthill-backend \
     --log /tmp/anthill-log.jsonl --manifest <head>/.commons/behaviour-delta.json
   ```
2. For each `UNDECLARED` community in the report, add an entry with that
   community and `fromEntry`, and a note saying what changes and why.
3. Commit the file in the same PR. That makes the PR ring 0, on purpose: changing
   how reputation behaves is a kernel change.

A declaration counts only in the PR that adds it: CI drops entries that are
already on the base branch, so a stale declaration cannot cover a later change.
Leaving old entries in the file is harmless; clearing it in a later PR is fine too.

The CI log is generated from the base branch's `anthill-backend/anthillSnapshot.json`
by the base backend's own code (seed, the demo's story, a commons with every
action kind, a private community joined by invite). For a given base, its entry
order is fixed, so `fromEntry` values found locally match CI.

## CI: `.github/workflows/commons-gates.yml`

On every `pull_request` (read-only token, no secrets), the workflow checks out
the PR's merge commit and the base with submodules, checks out and installs
agent-commons, and runs:

1. **Static gates** (rings, airlock, size) on the PR's changed files, against
   the base's `rules.json`.
2. **Behaviour delta** of base vs PR `anthill-backend` on the generated log,
   with the declarations this PR adds.

## CLI contract (for the agent-commons `src/cli.ts` author)

The workflow calls these two commands from the agent-commons root. Both print a
human-readable report on stdout and exit **0** when every gate passes, **1**
when a gate fails, **2** on a usage or harness error (bad flags, unreadable
files). A check that could not run is a failure, never a pass. Both accept
`--json` to print the `GateReport`s as JSON instead.

### `gates --repo <dir> --base <sha> --head <sha> --rules <path> [--dependency-track] [--json]`

- `--repo` — a git checkout containing both commits (with submodules initialised).
- `--base`, `--head` — commits; the change is `git diff <base>..<head>`. CI
  passes the base tip and the PR's merge commit, whose first parent is the base.
- `--rules` — a `Rules` JSON file; reject it (exit 2) if `validateRules` reports problems.
- `--dependency-track` — the change is on the dependency track (allows locked
  paths). CI never sets it.
- Changed files are repo-relative POSIX paths. **A submodule pointer change must
  be expanded**: for each gitlink that differs, diff the submodule from its old
  to its new commit and report its files prefixed with the submodule path
  (`anthill-backend/src/engine.ts`, not `anthill-backend`); fetch the submodule
  commits if they are missing. If expansion fails, report the bare gitlink path,
  which the Anthill rules classify as ring 0. Lines changed for the size gate
  are added + deleted lines over all files, submodule files included.
- Runs `checkRingImports`, `checkAirlock`, `checkSize` and reports the submission ring.

### `delta --old <dir> --new <dir> --log <path> --manifest <path> [--timeout-ms <n>] [--json]`

- `--old`, `--new` — `anthill-backend` checkouts (each with `src/store.ts`, `src/offchain.ts`).
- `--log` — a backend `log.jsonl`.
- `--manifest` — a behaviour-delta manifest (schema above). Missing or malformed
  is a failure.
- Implemented by `behaviourDeltaFor` in `src/adapters/anthill.ts`; print
  `details` and every divergence.
