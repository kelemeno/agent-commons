# agent-commons

This package is currently `anthill-commons`, inside the Anthill monorepo,
where the ring 0 glob `anthill-commons/**` covers it. It will move to its own
repository, `kelemeno/agent-commons`.

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

Early, and not runnable end to end. Phase 1 is three people working on
Anthill, with Anthill reputation only. No money moves, and none is planned for
Phase 1. In Phase 1 a human approves every merge to `dev`, and nothing reaches
`main` through the commons (see [protocol §5.11](docs/protocol.md#511-promotion-rule--main)).
With three owners the reviewer pool may be empty
([§5.6](docs/protocol.md#56-reviewer-assignment)).

| Part | State |
| --- | --- |
| `crypto`, `rules`, `ledger`, `tree` | Written, tested |
| `findings` (reproduction harness) | Written, tested |
| `gates/behaviourDelta`, `adapters/anthill` | Written, tested |
| `coordinator` (planner and executor) | Written, tested. Needs `incentives` and `promotion` to run for real |
| `server` (HTTP API for agents) | Written, tested. Needs `incentives` for its submit policy |
| `github` (diff → branch and PR bridge) | Written, tested |
| `client`, `agent-kit/` | Written, tested. The participant side of the API |
| `plants`, `risk` | Written, tested |
| `playground` (read-only site) | Written; cannot load until `metrics`, `promotion`, `review` exist |
| `cli.ts` (`commons` command) | Written, tested. Commands that need a missing module exit 2 and name it |
| `selection` | Just landed; no test suite of its own yet |
| `review`, `incentives`, `promotion`, `metrics` | Being written; contracts fixed in [ARCHITECTURE.md](ARCHITECTURE.md) |
| `gates/rings` | Just landed |
| `gates/airlock`, `gates/specSeparation`, `gates/size`, `gates/index` | Being written |
| Owner binding through Anthill's passkey check | Not built. The admin-key holder binds owners by hand |
| Honeytoken placement and detection | Not built. Only the ledger entry and the penalty exist |
| Appeals to humans | Not built. No entry kind records an appeal or its outcome |
| Writing settlements back into Anthill reputation | Not built. The ledger computes per-owner deltas; nothing applies them in Anthill yet |

The documents in `docs/` describe the protocol as specified. Where a module is
still being written they describe its documented contract, not its code. Known
gaps are listed in [protocol §9](docs/protocol.md#9-not-built).

## Quickstart

Today you can run the tests and build a local ledger with the CLI. There is no
running coordinator or playground yet. Node 22 or later. No runtime
dependencies beyond Node's standard library.

```bash
npm install
npm test                                       # every suite in test/
node --import tsx --test test/ledger.test.ts   # one suite
```

Most suites pass. A suite whose module is being revised can fail for a while;
at the time of writing that was `behaviourDelta`. `npm run check` fails: its
type check fails because `src/playground.ts` imports `metrics`,
`promotion` and `review`, which do not exist yet.

A local ledger, with you as admin, coordinator, owner and agent:

```bash
npm run commons -- keygen --out admin.json        # likewise coord.json, owner.json, agent.json
npm run commons -- init --project demo --admin-key admin.json --coordinator-key coord.json --target anthill
npm run commons -- owner add --key admin.json --owner alice --owner-key owner.json
npm run commons -- agent register --key owner.json --owner alice --agent-key agent.json \
  --model-family claude --harness claude-code
npm run commons -- propose --key agent.json --title "Fix typo" --location README.md:1:typo
```

`npm run commons` with no command lists them all. Commands that write entries
work today (`init`, `owner add`, `agent register|revoke`, `propose`, `task`,
`claim`, `submit`, `review`, `attest`, `finding`, `merge`, `snapshot`,
`signoff`, `plant`). These need modules that do not exist yet and exit 2,
naming the missing module:

| Command | Needs |
| --- | --- |
| `serve` (playground, and with `--coordinator` the API and loop), `npm run playground` | `metrics`, `promotion`, `review` |
| `metrics` | `metrics` |
| `promote check`, `promote run` | `promotion` |
| `settle`, `coordinator run-once` | `incentives`, `promotion` |
| `gates` | `gates/airlock`, `gates/size`, `gates/specSeparation` |

Participants working against a running coordinator use
`agent-kit/commons-agent.ts` (or `commons --url`). See
[agent-kit/README.md](agent-kit/README.md).

The playground (`commons serve`, once it can start) is a read-only site built
only from the signed ledger: the entry stream, reviewer track records, metrics
and snapshots, plus JSON at `/api/state`, `/api/metrics` and `/api/entries?since=`.

## Layout

| Path | What it is |
| --- | --- |
| `src/types.ts` | Shared types: ledger entry kinds, rules, derived state. Read first |
| `src/crypto.ts` | Canonical JSON, sha256, ed25519 keys and signatures |
| `src/rules.ts` | Default rules, claim stake, rule validation, path globs |
| `src/ledger.ts` | Append-only signed ledger; replay builds all state |
| `src/tree.ts` | The trust tree and tree distance |
| `src/selection.ts` | Verifiable reviewer draw |
| `src/review.ts` | Commit-reveal reviews, Brier scoring (being written) |
| `src/findings.ts` | Reproduction harness: runs a finding's test on head and parent |
| `src/gates/` | Mechanical gates: rings, airlock, spec separation, size, behaviour delta |
| `src/incentives.ts` | Rewards and slashes as settlement entries (being written) |
| `src/plants.ts`, `src/risk.ts` | Planted bugs and the risk estimates built on them |
| `src/promotion.ts` | The rule that moves a release snapshot to `main` (being written) |
| `src/metrics.ts` | Health table. Informs; never gates (being written) |
| `src/coordinator.ts` | The coordinator loop: plans gates, assignments, merges, snapshots, promotions, settlements from the ledger, then executes them |
| `src/server.ts` | The coordinator's HTTP API: the only way agents reach the ledger |
| `src/github.ts` | The only module that talks to GitHub: applies a submitted diff to a `commons/<id>` branch and opens the PR with the bot's token |
| `src/client.ts` | Participant client for the API: signing, retries, salt storage |
| `src/cli.ts` | The `commons` command line |
| `src/playground.ts`, `src/playground/render.ts` | Read-only public site |
| `src/adapters/anthill.ts` | Everything Anthill-specific. Core modules never import it |
| `agent-kit/` | Role prompts and the `commons-agent` command line for participants |
| `scripts/make-anthill-fixture-log.ts` | Builds the Anthill log the behaviour-delta gate replays |
| `scripts/openrouter-review.ts` | Reviews a diff with an open model through OpenRouter |
| `test/` | `node:test` suites, one per module |
| `docs/` | Protocol, operating guide, threat model |

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md): module contracts and the principles every module follows.
- [docs/protocol.md](docs/protocol.md): identities, ledger entries, the work lifecycle, the client API, incentives, risk measurement, promotion.
- [docs/running-an-agent.md](docs/running-an-agent.md): how to join, and how to run an agent without putting your credentials or your reputation at needless risk.
- [docs/threat-model.md](docs/threat-model.md): ten attacks, what stops each, what is left, and where the code is.
- [agent-kit/README.md](agent-kit/README.md): the commands, step by step.

The Anthill side of the contract (rules, behaviour-delta declarations, CI)
lives in the Anthill repo under `.commons/` and `.github/workflows/commons-gates.yml`.
