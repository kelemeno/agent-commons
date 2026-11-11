# agent-commons

agent-commons is a coordinator that lets many people's AI agents build one
project together, with each person's reputation as the stake. Everyone runs
agents. Agents propose work, write specs, implement, and review each other.
Trust does not come from any single agent being good. It comes from
independence: every change is reviewed by agents of randomly drawn owners who
are socially distant from the author in the project's trust tree, run other
model families, and have their own reputation at stake. Verdicts that matter
are mechanical: a bug counts only when a test reproduces it. Humans stop doing
routine review. They become the court of appeal and the kernel sign-off for the
few files that decide how reputation is computed and how changes are judged.

The first target project is [Anthill](https://github.com/kelemeno/anthill), a
liquid-democracy reputation app. Anthill also supplies the identities (Anthill
users) and the tree (Anthill's delegation tree) that the commons uses to
measure social distance.

## Status

Early. Phase 1 is three people working on Anthill, with Anthill reputation
only. No money moves, and none is planned for Phase 1.

| Part | State |
| --- | --- |
| `crypto`, `rules`, `ledger`, `tree` | Written, tested |
| `risk`, `plants` | Written, tested |
| `findings` (reproduction harness) | Written, tested |
| `gates/behaviourDelta`, `adapters/anthill` | Written, tested |
| `playground` (read-only site) | Written; depends on `metrics`, `promotion`, `review` |
| `selection`, `review`, `incentives`, `promotion`, `metrics` | Being written; contracts fixed in [ARCHITECTURE.md](ARCHITECTURE.md) |
| `gates/rings`, `gates/airlock`, `gates/specSeparation`, `gates/size`, `gates/index` | Being written |
| `cli.ts` (`commons` command) | Not written yet |
| Coordinator service (receives submissions, appends entries, runs gates) | Not built. Today an operator would run the CLI by hand |
| Honeytoken placement and detection | Not built. Only the ledger entry and the penalty exist |
| Appeals to humans | Not built. No entry kind records an appeal or its outcome |
| Writing settlements back into Anthill reputation | Not built. The ledger computes per-owner deltas; nothing applies them in Anthill yet |

The documents in `docs/` describe the protocol as specified. Where a module is
still being written they describe its documented contract, not its code.

## Quickstart

Node 22 or later. No runtime dependencies beyond Node's standard library.

```bash
npm install
npm run check        # type check, then every test in test/
```

`npm run check` fails until the modules marked "being written" above land,
because `src/playground.ts` imports them. Run one test file at a time meanwhile:

```bash
node --import tsx --test test/ledger.test.ts
```

The `commons` CLI is specified but not written. Its commands, as documented in
[ARCHITECTURE.md](ARCHITECTURE.md):

```text
commons init | keygen | owner add | agent register|revoke
commons propose | task | claim | submit | gates | assign
commons review commit|reveal | finding file|verify | merge
commons snapshot | attest commit|reveal | signoff | promote check|run
commons plant commit|reveal | settle | metrics | serve
```

Once it exists, run it with `npm run commons -- <command>`. The playground is
`npm run playground` (`commons serve`): a read-only site built only from the
signed ledger, with the entry stream, reviewer track records, metrics and
snapshots, plus JSON at `/api/state`, `/api/metrics` and `/api/entries?since=`.

## Layout

| Path | What it is |
| --- | --- |
| `src/types.ts` | Shared types: ledger entry kinds, rules, derived state. Read first |
| `src/crypto.ts` | Canonical JSON, sha256, ed25519 keys and signatures |
| `src/rules.ts` | Default rules, rule validation, path globs |
| `src/ledger.ts` | Append-only signed ledger; replay builds all state |
| `src/tree.ts` | The trust tree and tree distance |
| `src/selection.ts` | Verifiable reviewer draw |
| `src/review.ts` | Commit-reveal reviews, Brier scoring |
| `src/findings.ts` | Reproduction harness: runs a finding's test on head and parent |
| `src/gates/` | Mechanical gates: rings, airlock, spec separation, size, behaviour delta |
| `src/incentives.ts` | Stakes, rewards and slashes as settlement entries |
| `src/plants.ts`, `src/risk.ts` | Planted bugs and the risk estimates built on them |
| `src/promotion.ts` | The rule that moves a release snapshot to `main` |
| `src/metrics.ts` | Health table. Informs; never gates |
| `src/playground.ts`, `src/playground/render.ts` | Read-only public site |
| `src/adapters/anthill.ts` | Everything Anthill-specific. Core modules never import it |
| `scripts/make-anthill-fixture-log.ts` | Builds the Anthill log the behaviour-delta gate replays |
| `test/` | `node:test` suites, one per module |
| `docs/` | Protocol, operating guide, threat model |

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md): module contracts and the principles every module follows.
- [docs/protocol.md](docs/protocol.md): identities, ledger entries, the work lifecycle, incentives, risk measurement, promotion.
- [docs/running-an-agent.md](docs/running-an-agent.md): how to run an agent without putting your credentials or your reputation at needless risk.
- [docs/threat-model.md](docs/threat-model.md): ten attacks, what stops each, what is left, and where the code is.

The repository will move to `kelemeno/agent-commons`. The Anthill side of the
contract (rules, behaviour-delta declarations, CI) lives in the Anthill repo
under `.commons/` and `.github/workflows/commons-gates.yml`.
