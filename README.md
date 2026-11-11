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

Identity is the commons' own: the ledger's `ownerKey` entries. Each one
names the owner who vouched for the newcomer (its inviter) or none, and those
invites form the trust tree that reviewer selection and bounties measure
distance in ([`src/members.ts`](src/members.ts)). Nothing outside the ledger
decides who is a member or who is close to whom, so anyone holding the ledger
can recompute every reviewer draw. Reputation is per-project commons
reputation (`OwnerState.reputationDelta`, the sum of settlements): it backs
stakes (on top of `rules.stake.allowance`) and sets PR slots.

The commons works on any git repository. Each target project declares its own
kernel (ring 0) paths in its `.commons/rules.json`
([protocol §4](docs/protocol.md#4-rings)); the built-in rules know only what is
kernel in every repository (the commons config, CI, build and deploy files).

## Status

Early. Phase 1 is 3–10 trusted people: the admin admits each one with an
`ownerKey` entry (`commons owner add`; those entries are the allowlist), and
the group runs the `phase1` rules preset. Reputation is commons reputation
only. No money moves, and none is planned for Phase 1. In Phase 1 a human
approves every merge to `dev` with a ledger entry (`commons approve`), an
operator confirms or dismisses every reproduced finding (`commons finding
confirm|dismiss`), and `main` moves when a snapshot passes the promotion rule
under the preset (see
[protocol §5.11](docs/protocol.md#511-promotion-rule--main)). Use the
`phase1` preset: owners admitted with no inviter are all at distance 2 from
each other, so under the default rules (`minTreeDistance` 2) nobody is
eligible to review ([§5.6](docs/protocol.md#56-reviewer-assignment)).
The checklist for a first Phase 1 week is in [HANDOFF.md](HANDOFF.md).

| Part | State |
| --- | --- |
| `crypto`, `rules`, `ledger`, `members` (the trust tree) | Written, tested |
| `findings` (reproduction harness) | Written, tested |
| `gates/*` (rings, airlock, size, specSeparation) | Written, tested |
| `selection`, `review`, `plants`, `risk` | Written, tested |
| `incentives`, `promotion`, `metrics` | Written, tested |
| `coordinator` (planner and executor), `server` (HTTP API for agents) | Written, tested |
| `github` (diff → branch and PR bridge) | Written, tested; not yet wired into `serve` / `coordinator run-once`, which merge in the coordinator's own clone (`--repo`: dev and main move there; the operator pushes them) |
| `client`, `agent-kit/` | Written, tested. The participant side of the API |
| `playground` (read-only site) | Written, tested |
| `cli.ts` (`commons` command) | Written, tested |
| Checking who a new owner is | Not built. The admin-key holder checks by hand and signs `owner add` |
| Honeytoken placement and detection | Not built. Only the ledger entry and the penalty exist |
| Appeals to humans | Not built. No entry kind records an appeal or its outcome |

The documents in `docs/` describe the protocol; where they and the code
disagree, the code wins. Known gaps are listed in
[protocol §9](docs/protocol.md#9-not-built).

## Quickstart

You can run the tests, build a local ledger with the CLI, and serve the
playground and the coordinator API from it. Node 22 or later. No runtime
dependencies beyond Node's standard library.

```bash
npm install
npm test                                       # every suite in test/
node --import tsx --test test/ledger.test.ts   # one suite
```

`npm run check` runs the type check and every suite. No environment variables
are needed; the only skipped tests are the Linux-only sandbox tests.

### Phase 1: three people

One person holds the admin and coordinator keys; each of the three holds an
owner key and runs an agent. Here everything is in one directory for brevity;
in real use each owner keeps their owner key to themselves
([docs/running-an-agent.md](docs/running-an-agent.md)).

```bash
mkdir -p keys
for k in admin coord alice bob carol alice-agent bob-agent carol-agent; do
  npm run -s commons -- keygen --out keys/$k.json
done

# The target project's rules: the generic defaults plus its own kernel. Here
# src/** is ring 0 (needs a task, a claim and a kernel signoff); a project
# usually commits this file as .commons/rules.json.
node --import tsx -e 'import("./src/rules.ts").then(({ defaultRules }) => {
  const r = defaultRules(); r.rings.unshift({ glob: "src/**", ring: 0 });
  console.log(JSON.stringify(r, null, 2)); })' > rules.json

# The Phase 1 preset on top: minTreeDistance 1, 2 reviewers, other model
# family required, 1 kernel signoff, a 7-day vesting tail. Name two kernel
# signers: a signer may not sign off a snapshot holding its own ring-0 work,
# and with one signer the first src/** change of theirs would freeze main.
npm run commons -- init --project demo --admin-key keys/admin.json --coordinator-key keys/coord.json \
  --rules rules.json --preset phase1 --kernel-signer alice --kernel-signer bob
# The admin's owner entries are the allowlist. With no --inviter every owner
# hangs under the commons root, so every pair is at distance 2 and the draw
# is uniform among the non-authors; --inviter alice would put the newcomer
# under alice (distance 1 from her: she can neither review its work nor win
# a bounty on it).
for o in alice bob carol; do
  npm run commons -- owner add --key keys/admin.json --owner $o --owner-key keys/$o.json
done
npm run commons -- agent register --key keys/alice.json --owner alice --agent-key keys/alice-agent.json --model-family claude --harness claude-code
npm run commons -- agent register --key keys/bob.json --owner bob --agent-key keys/bob-agent.json --model-family gpt --harness codex
npm run commons -- agent register --key keys/carol.json --owner carol --agent-key keys/carol-agent.json --model-family gemini --harness gemini-cli

# The coordinator's clone of the target, with a dev branch: every base must
# be on dev, and merges land there (the operator pushes dev and main).
git clone <target repository URL> ../target
git -C ../target branch dev origin/main

# alice's agent submits a change made on top of dev (here: a docs file,
# ring 1, so it needs no task; a src/** change is ring 0 and needs a task and
# a claim).
git -C ../target checkout -q -b fix-1 dev && echo "notes" > ../target/NOTES.md
git -C ../target add NOTES.md && git -C ../target commit -qm "add notes"
npm run commons -- submit --key keys/alice-agent.json --id fix-1 --repo ../target --base dev --head fix-1
# The coordinator binds the patch, gates it and draws reviewers over the
# ledger's member tree (bob's and carol's agents): run it until it says
# "nothing to do".
npm run commons -- coordinator run-once --key keys/coord.json --repo ../target
npm run commons -- review commit --key keys/bob-agent.json --submission fix-1 --probability 0.1 --summary "looks fine"
# ... carol commits too; reveals wait until both assigned reviewers committed
# (or 12 hours passed), so one early reveal cannot shut a seat out.
npm run commons -- review reveal --key keys/bob-agent.json --submission fix-1
# Then a human approves the merge (a ledger entry), and the next pass merges
# fix-1 onto dev in the coordinator's clone.
npm run commons -- approve --key keys/admin.json --submission fix-1   # the admin, or a kernel signer who is not the author's owner
# --snapshot-every N makes a snapshot once N merges are outside one: without
# it nothing is ever snapshotted, so nothing is promoted and main never moves.
npm run commons -- coordinator run-once --key keys/coord.json --repo ../target --snapshot-every 1
npm run commons -- serve   # the playground on :8080
```

Everyone starts with `rules.stake.allowance` points of stake (370 in the
Phase 1 preset: the largest claim, 320, plus headroom for reviews and
findings) and one open PR slot (slots grow with commons reputation). Phase 1
recall bounds are wide: ten plants, all caught, are the least that passes the
preset's recall and critical-bound checks; one miss fails them until there are
twelve seeds.

### A one-person local ledger

A local ledger, with you as admin, coordinator, owner and agent:

```bash
npm run commons -- keygen --out admin.json        # likewise coord.json, owner.json, agent.json
npm run commons -- init --project demo --admin-key admin.json --coordinator-key coord.json
npm run commons -- owner add --key admin.json --owner alice --owner-key owner.json
npm run commons -- agent register --key owner.json --owner alice --agent-key agent.json \
  --model-family claude --harness claude-code
npm run commons -- propose --key agent.json --title "Fix typo" --location README.md:1:typo
```

`npm run commons` with no command lists them all, and `commons <command> --help`
its flags. Every command works locally; `serve` starts the playground (and,
with `--coordinator`, the agents' API and loop, which also serves
`/api/tasks` and `/api/entries`). The coordinator does not merge through
GitHub yet: it merges in its own clone (`--repo`), and `commons merge` applies
the same merge rule by hand. Finding tests from others run only under
`--sandbox`, a runner under another uid and fresh for every run (a
container), which a preflight checks
([`scripts/sandbox-docker`](scripts/sandbox-docker) with `--share-checkout`
is one); see `commons finding verify --help`.

Participants working against a running coordinator use
`agent-kit/commons-agent.ts` (or `commons --url`). See
[agent-kit/README.md](agent-kit/README.md).

The playground (`commons serve`) is a read-only site built
only from the signed ledger: the entry stream, reviewer track records, metrics
and snapshots, plus JSON at `/api/state`, `/api/metrics` and `/api/entries?since=` (`since` is
inclusive; continue with the reply's `next`).

## Layout

| Path | What it is |
| --- | --- |
| `src/types.ts` | Shared types: ledger entry kinds, rules, derived state. Read first |
| `src/crypto.ts` | Canonical JSON, sha256, ed25519 keys and signatures |
| `src/rules.ts` | Generic default rules, the Phase 1 preset, claim stake, rule validation, path globs |
| `src/ledger.ts` | Append-only signed ledger; replay builds all state |
| `src/members.ts` | The trust tree, derived from the ledger's `ownerKey` invites, and tree distance |
| `src/selection.ts` | Verifiable reviewer draw over the member tree |
| `src/review.ts` | Commit-reveal reviews, Brier scoring |
| `src/findings.ts`, `src/findingStatus.ts` | Reproduction harness: runs a finding's test on head and parent; what a finding has established |
| `src/gates/` | Mechanical gates: rings, airlock, spec separation, size |
| `src/incentives.ts` | Rewards and slashes as settlement entries |
| `src/plants.ts`, `src/risk.ts` | Planted bugs and the risk estimates built on them |
| `src/promotion.ts` | The rule that moves a release snapshot to `main` |
| `src/metrics.ts` | Health table. Informs; never gates |
| `src/coordinator.ts` | The coordinator loop: plans gates, assignments, merges, snapshots, promotions, settlements from the ledger, then executes them |
| `src/server.ts` | The coordinator's HTTP API: the only way agents reach the ledger |
| `src/github.ts` | The only module that talks to GitHub: applies a submitted diff to a `commons/<id>` branch and opens the PR with the bot's token |
| `src/client.ts` | Participant client for the API: signing, retries, salt storage |
| `src/cli.ts` | The `commons` command line |
| `src/playground.ts`, `src/playground/render.ts` | Read-only public site |
| `agent-kit/` | Role prompts and the `commons-agent` command line for participants |
| `scripts/openrouter-review.ts` | Reviews a diff with an open model through OpenRouter |
| `scripts/sandbox-docker` | A finding-test sandbox: a fresh container per run, under another uid |
| `test/` | `node:test` suites, one per module, plus `e2e.test.ts` (the whole lifecycle) |
| `docs/` | Protocol, operating guide, threat model |

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md): module contracts and the principles every module follows.
- [docs/protocol.md](docs/protocol.md): identities, ledger entries, the work lifecycle, the client API, incentives, risk measurement, promotion.
- [docs/running-an-agent.md](docs/running-an-agent.md): how to join, and how to run an agent without putting your credentials or your reputation at needless risk.
- [docs/threat-model.md](docs/threat-model.md): ten attacks, what stops each, what is left, and where the code is.
- [agent-kit/README.md](agent-kit/README.md): the commands, step by step.

A target project keeps its side of the contract in its own repository: its
rules (with its kernel paths) in `.commons/rules.json`, and optionally a CI
job that runs `commons gates --repo . --base <base> --head <head> --rules
<the base commit's .commons/rules.json>` on pull requests.
