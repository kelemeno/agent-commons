# Handoff — state of the agent-commons build

Last updated by the build session on 2026-11-11. Branch `wip-core` holds work in
progress; `main` gets a clean commit once the final integration pass is green.

## What this is

The coordinator for an open agent commons on Anthill. Design doc:
"Agent Commons on Anthill — design" (claude.ai doc). Contracts: `ARCHITECTURE.md`,
shared types: `src/types.ts`. A static demo of the playground (fake data) was
published as a private claude.ai artifact ("overview · agent commons").

## Decisions taken (do not relitigate)

- Separate repo on top of Anthill; Anthill is the first target project, not the host.
- **Minimal Anthill integration for now:** Anthill provides login/vouching and the
  tree only. Commons settlements stay as per-project reputation in the commons
  ledger and do **not** flow back into Anthill reputation. Phase 1 must also work
  with a plain owner allowlist (tree optional). Deeper integration (tree-weighted
  selection that matters, poll-ratified rules, reputation-gated slots) is switched
  on when the first strangers join.
- One dev branch + main; stages are per-commit state; signed release snapshots;
  human k-of-n sign-off on the kernel.
- Agents run in cloud sandboxes (Claude Code routines, open models via OpenRouter);
  never push with participants' credentials; coordinator bot opens PRs.
- Run incentives with simple numbers; do not tune until there are real participants.

## Module status

| Module | Status |
|---|---|
| crypto, rules, ledger | built, reviewed (contract + adversary), fixed |
| tree | built, reviewed, fixed |
| risk, plants | built, reviewed, fixed |
| findings (reproduction harness) | built, reviewed, fixed — no git worktrees (exports plain dirs); same-uid /proc reach remains, needs container for strangers |
| gates/behaviourDelta | built, reviewed, fixed |
| playground (+ render) | built, reviewed, fixed |
| adapters/anthill + `targets/anthill/` (.commons config, CI workflow) | built, reviewed, fixed |
| docs/ | written, reviewed |
| selection, review | built, reviewed, fixed |
| incentives | built, reviewed, fixed |
| gates (rings, airlock, specSeparation, size, index) | built, reviewed, fixed (cli wiring of new inputs pending) |
| promotion, metrics | built, reviewed, fixed |
| server, coordinator, github bridge, client + agent-kit | built, reviewed, fixed |
| cli | built and reviewed; **fix pass never ran** — 19 issues in `handoff/runtime-result.json` (`reviewIssues.cli`) |

## Continue on the Mac mini

```bash
git clone https://github.com/kelemeno/agent-commons && cd agent-commons && git checkout wip-core && npm install
```

```bash
git clone --recurse-submodules https://github.com/kelemeno/anthill ../anthill && (cd ../anthill/anthill-backend && npm install)
```

```bash
export ANTHILL_BACKEND_DIR="$(cd ../anthill/anthill-backend && pwd)"
```

Then start `claude` in the agent-commons clone and say: "Read HANDOFF.md and run the
final wave". The final wave is scripted in `handoff/final-wave.js` (a Claude Code
workflow script): run it with `args: { root: <abs path of this clone>, anthill:
<abs path of the anthill clone> }`. Its first stage finishes the CLI fixes and makes
tests independent of the old cloud paths (tests that import the Anthill backend
must read ANTHILL_BACKEND_DIR and skip with a message when it is unset).

Reports from every module's build, adversarial review and fix are in `handoff/`
(`*-result.txt`, `runtime-result.json`); their UNRESOLVED lists are the
cross-module work for the integration stage.

Known at handoff: the suite was never run as a whole; expect type errors and
failing tests across module boundaries (e.g. playground calls
`reviewerScores(state)` without `nowIso`). Tests may reference paths like
`/home/user/anthill/...` or `../../anthill-backend` from the cloud layout.

## Final wave (to do after all modules land)

1. Integration: single-source duplicated definitions (plant-caught → plants.ts,
   ring classification → gates/rings.ts, sha256/canonical → crypto.ts); full
   `npm run check` green without weakening tests.
2. Minimal Anthill mode (owner allowlist; no settlement → Anthill flow).
3. Ledger input limits: max lengths/counts for titles, summaries, details, paths,
   commands, harness, refs, ids; reject ids made only of dots or containing `/`.
4. Plant procedure: batch plant commitments well ahead of submission; submit via
   rotating agents that also do ordinary work (timing must not reveal plants).
5. Optional `harnessError` on findingResult so "could not run" ≠ "did not reproduce".
6. ARCHITECTURE.md: findings uses exported plain dirs, not worktrees; `/api/entries`
   `since` is inclusive, clients continue with `next`.
7. End-to-end lifecycle test on a temp git repo (propose → task → claim → submit →
   gates → assign → commit/reveal → finding reproduced → settlements → merge →
   snapshot → plants → promotion check).
8. Whole-system adversarial review, fix, then clean commit to `main`.
9. Re-publish the playground demo on the real modules.

## Access notes

- Push works for `kelemeno/agent-commons`. Push to `kelemeno/anthill` was refused
  (Claude GitHub App not installed there); the Anthill target files live in
  `targets/anthill/` until they can be copied into the anthill repo.
- Build ran in a 4-CPU cloud container (2 concurrent agents per workflow). The
  final wave is faster on a bigger machine: clone, `git checkout wip-core`,
  `npm install`, `npm run check`, and give a new session this file.
