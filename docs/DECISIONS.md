# Decision Log — onewayglass

Appended **as decisions happen**, never reconstructed later. Short entries, 3–6 lines.
Format: date · decision · alternatives · why · what would change it.

Cross-project decisions live in the program-level `DECISIONS.md`.

---

## 2026-08-21 — Repo scaffolded

**Decision.** python project, nine-step pipeline structure, MIT licence.
**Why.** Standard scaffold per MASTER-PLAN.md §1/§3/§4.

## 2026-08-21 — Measure the leak before building the fix

**Decision.** `bench/baseline/` and `docs/01-problem.md`, `docs/02-thesis.md` committed
(`5d976d3`) before a line of `enforced.py` existed.
**Alternatives.** Build the defence, then write a benchmark that shows it working.
**Why.** A benchmark written after the fix gets written to fit the fix. Pre-registering the
criteria and the thresholds means the result can come out unfavourable.
**What would change it.** Nothing. This is the point of the nine-step pipeline.

## 2026-08-21 — Calibrate the attacker against matches, not against k

**Decision.** The attacker infers `matches_available − returned`, not `k − returned`.
**Alternatives.** Keep the simpler `k − returned` model.
**Why.** `k − returned` over-counts whenever a query simply matches few documents. It scored
0/15 and made a real vulnerability look unexploitable. Against actual matches the inference is
15/15 exact. A real attacker calibrates by probing with a query they know is unrestricted, or by
noticing the same query returns different counts for different colleagues.
**What would change it.** A deployment where corpus size and match counts are genuinely
unknowable to the attacker — then the weaker model would be the realistic one, and the leak
smaller than measured here.

## 2026-08-21 — Pad deterministically, and tell the caller

**Decision.** Filler ordered by document id; `padded: bool` on every result.
**Alternatives.** Random filler; hide the flag entirely.
**Why.** A random pad differs between two identical requests, which is itself a signal, and it
makes the stability property test flaky in the way that hides real failures. Hiding the flag
degrades results for the authorised caller with no security gain — the *count* must carry no
information, not the payload.
**What would change it.** Evidence that consumers echo the flag into something observable; then
a per-principal keyed shuffle, stable per principal.

## 2026-08-21 — Publish the timing channel rather than claim the guarantee

**Decision.** Kill condition 3 triggered. Median SNR 0.73, 1.8 µs. Reported in its own README
section, not in a footnote.
**Alternatives.** Pad the execution path first and publish a clean result. Or describe
count-stability as complete and mention timing as future work.
**Why.** `docs/02-thesis.md` pre-committed: "A partial defence honestly described is worth more
than a total one falsely claimed." The direction is also counterintuitive — the padded arm is
*faster* — which is worth more to a reader than a clean claim.
**What would change it.** Padding the execution path so a constant number of candidates is
scored regardless of readability. That is whole-corpus work per query, and constant-time
retrieval is a listed non-goal.

## 2026-08-21 — Report per-request p99 as unresolved rather than resolved to a passing run

**Decision.** Criterion 6 met on p50 (1.48×), p95 (1.50×) and batched p99 (1.37×). Per-request
p99 marked unresolved.
**Alternatives.** Report the run that gave worst-case 1.79× and call the criterion met on the
statistic it actually named.
**Why.** Two runs of identical code gave 1.79× and 2.79× — one passes, one fails. The A/A
control shows identical code differing by up to 1.15× at p99. The run-to-run swing exceeds the
effect, so choosing a run is choosing a result.
**What would change it.** A quiet dedicated host, or a corpus large enough that per-request cost
exceeds interrupt latency by an order of magnitude.

## 2026-08-21 — Compare against an optimised naive path, not the one as written

**Decision.** The latency denominator is naive-with-a-dict-lookup, semantics unchanged.
**Alternatives.** Use `NaiveRetriever` as written, which does an O(k·n) scan per result.
**Why.** Comparing against it credits enforcement for the baseline's sloppy bookkeeping, and the
bias runs toward the thing being sold. Worth 0.05–0.12× of ratio. Choosing the flattering
denominator because the difference turned out small is the same decision as choosing it because
it was large.
**What would change it.** Nothing. The as-written arm is still reported, so the adjustment is
visible rather than substituted.
