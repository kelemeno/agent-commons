# Handoff: agent review measurement for AAG

From: the agent-commons session, 2026-11-12. For: the agent working on AAG.

## Decision

agent-commons (https://github.com/kelemeno/agent-commons, branch `wip-core`) is being shelved as a standalone system. Its ledger, stakes, commit-reveal and random reviewer draws exist to handle untrusted strangers, which a 2–3 person team doesn't have. The part worth keeping is the **measurement**, and it should be built into AAG.

The goal, from Kalman's sync with Valera on Nov 12:

1. **Make the agents find nearly all the issues**, so humans rarely find anything. Humans then review a batched dev branch, not each PR one at a time.
2. **Measure how the agents run.** Use standard prompts per area or lens, record what each run found, and put more review where bugs slip through.

The intended setup is `dev-agent` (PRs merged after agent review only), then `dev-human` (reviewed by people), then `main`. An issue a human finds on `dev-human` is an **escape**. It means the agent review wasn't enough for that area or lens.

## What to build in AAG

1. **Run log.** Record every review run as one record:
   - PR and head commit;
   - model and provider (Opus, Fable, Argon…);
   - prompt or lens id and its version;
   - files or area covered;
   - findings, each with severity and a category: `security` / `correctness` / `taste`;
   - an optional stated defect probability;
   - tokens and cost, and wall time.
2. **Ground truth.** Without it, recall can't be measured.
   - **Plants:** seeded bugs. Put them in PRs on throwaway branches that never merge. Don't reveal a plant until its review is done. A plant counts as caught if a finding locates it.
   - **Escapes:** issues humans find after the agents passed the code. **Only `security` and `correctness` count.** Taste goes into a written style guide instead (Valera's point).
3. **Metrics,** per lens × model × area:
   - plant recall, with confidence bounds (the samples will be tiny);
   - escapes per PR;
   - false-finding rate;
   - cost per caught bug;
   - Brier calibration, if agents give probabilities.
   This turns the Argon-vs-Opus comparison into a number that keeps updating.
4. **Use the metrics:**
   - more review (lenses, models, tokens) where recall is low or escapes happen;
   - later, a rule for when a PR may go into `dev-agent` with no human.
5. **Baseline first.** Scrape last month's PRs: what agents flagged versus what humans flagged afterwards. That gives a "before" number to compare against.

## What to borrow from agent-commons

All of these are pure TypeScript with no I/O. Copy or adapt them; don't depend on the repo.

- [`src/risk.ts`](https://github.com/kelemeno/agent-commons/blob/wip-core/src/risk.ts) is the stats:
  - `clopperPearsonOneSided`: recall bounds from small samples;
  - `seededRecall`;
  - `escapeRate`: recall from earlier versus later finds;
  - `chao1`: an estimate of the bugs nobody found yet;
  - `poissonUpper` and `calibrationFactor`: predicted versus actual escapes.
- [`src/review.ts`](https://github.com/kelemeno/agent-commons/blob/wip-core/src/review.ts):
  - `brier`;
  - `reviewerScores`: per-reviewer Brier and plant record. Drop the "unrevealed commit is charged as worst-case" rule; it only matters against adversaries.
- [`src/plants.ts`](https://github.com/kelemeno/agent-commons/blob/wip-core/src/plants.ts):
  - the header explains why plant timing matters;
  - `CATCH_THRESHOLD`, where p ≥ 0.5 counts as flagged;
  - `plantStats`: recall split by model family.
- [`src/metrics.ts`](https://github.com/kelemeno/agent-commons/blob/wip-core/src/metrics.ts): the health-table pattern, with each metric carrying its "bad" threshold.
- [`src/judgement.ts`](https://github.com/kelemeno/agent-commons/blob/wip-core/src/judgement.ts) is the merge rule. It was committed unfinished: the coordinator never calls it, and 111 of 688 tests fail because of it.
  - `reviewerWeight`: weight = Brier skill shrunk toward a prior for new reviewers, × plant recall `(caught+1)/(seen+1)`.
  - `poolRisk`: log-odds pooling of verdicts, with a prior pseudo-reviewer, so reviewers with no record can't carry a merge.
  - `escalationTriggers`: when verdicts disagree, or a trusted reviewer is worried.
  - In AAG, a "reviewer" is a **model + lens**, not a person. The default thresholds in `src/rules.ts` (`judgement`) were never checked; treat them as placeholders.

**Don't port** these; they solve trust problems AAG doesn't have:
- the ledger, signatures and stakes;
- commit-reveal;
- the member tree;
- reviewer selection and escalation rounds.

## Background, if useful

- [`docs/protocol.md`](https://github.com/kelemeno/agent-commons/blob/wip-core/docs/protocol.md): plants, escapes and promotion gates in detail.
- [`docs/threat-model.md`](https://github.com/kelemeno/agent-commons/blob/wip-core/docs/threat-model.md)
