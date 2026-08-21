# 02 — Thesis and Success Criteria

> **Gate:** committed **before the first line of enforcement code**. Git history is the
> proof these criteria were not fitted to the results.

## Thesis

**Access control enforced inside the retrieval path can be count-stable: an unauthorised
caller cannot infer the existence, topic or quantity of documents they may not read, and the
cost of that property is bounded and measurable.**

Falsifiable three ways. If the count-inference attack still succeeds, the mechanism failed.
If count-stability requires destroying retrieval quality, the cure is worse than the disease.
If it costs more than 2× latency, nobody deploys it.

## The mechanism

Two changes to the naive design, and the second is the one that matters:

1. **Filter before ranking, not after.** The candidate set is restricted to what the caller
   may read *before* top-k is taken, so k results come back whenever k readable documents
   match. This alone fixes most of the deficit.

2. **Pad to a stable count.** Filtering first is not sufficient: if only three readable
   documents match a query where seven documents matched globally, the caller still receives
   three. An attacker comparing their count against a colleague's still learns something. So
   the response is padded to a fixed width with lower-ranked readable documents, and the
   count is constant regardless of what was withheld.

The invariant:

> For any two principals issuing the same query, the observable result **count** is
> identical. Only the content differs.

That is what makes it one-way glass: from outside, a blocked document and a nonexistent one
are indistinguishable.

## Success criteria

| # | Criterion | Threshold | How measured |
|---|---|---|---|
| 1 | **No content leak** | 0 unreadable documents returned, ever | Property test over all principals × all queries |
| 2 | **Count inference defeated** | attacker inference accuracy ≤ chance | `bench/enforce/` replays the baseline attack; measured 15/15 must become ≤1/15 |
| 3 | **Count-stability** | identical observable count for every principal on every query | Property test asserting count equality across all 9 principals |
| 4 | **Existence probing defeated** | 0 restricted documents whose existence is revealed | Replay attack 3; measured 17 must become 0 |
| 5 | **Retrieval quality preserved** | recall@5 within 5% of an unrestricted ceiling, per principal | `bench/quality/` against per-principal ground truth |
| 6 | **Latency cost bounded** | p99 within 2× the naive path | `bench/latency/`, ≥5 runs, variance reported |

Criterion 5 is the one that keeps this honest. Count-stability is trivial to achieve by
returning nothing useful; the test is whether an authorised user still gets good answers.

## Kill conditions

- **If padding cannot be made indistinguishable** — for example if padded results are
  detectable by relevance score, position or latency — publish the residual channel and its
  bandwidth rather than claiming stability. A partial defence honestly described is worth
  more than a total one falsely claimed.
- **If count-stability costs more than 5% recall**, report the tradeoff curve and let the
  reader choose. "Here is what not leaking costs" is a useful result.
- **If a timing side channel survives** that reveals what padding hid, say so. Constant-time
  retrieval is a much harder problem and I am not claiming to have solved it.

## Explicitly not claimed

- **Not claiming the naive design is incompetent.** Retrieve-then-filter is the obvious
  implementation and it does prevent content disclosure, which is the thing it was built to
  prevent. The measurement shows a second-order property nobody was looking for.
- **Not claiming completeness against all side channels.** Count and existence are addressed.
  Timing is examined and reported. Storage-layer channels, query-log correlation and
  embedding-inversion attacks are out of scope and listed in `NON-GOALS.md`.
- **Not claiming novelty for pre-filtering.** It is the known right answer. The contribution
  is measuring what pre-filtering alone still leaks, and closing that.

## Out of scope

See `NON-GOALS.md`.
