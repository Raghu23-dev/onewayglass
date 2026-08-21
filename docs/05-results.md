# 05 — Benchmarks and Results

> **Gate:** no number may be claimed anywhere (README, writeup, post) unless it comes from
> `bench/` and is reproducible by a stranger with one command.

## Method

**Harness:** `bench/` — five independent benchmarks, each with its own `results/` directory.
**Runs:** 7 repeats for every timing-sensitive measurement. The attack benchmarks are
deterministic (fixed corpus, fixed probes, BM25) and produce identical output on every run.
**Environment:** Python 3.13, macOS arm64, in-process, single machine. No network, no database.

```bash
python bench/baseline/leak.py      # the leak
python bench/enforce/replay.py     # criteria 1-4
python bench/quality/measure.py    # criterion 5
python bench/relevance/measure.py  # the relevance channel — found after the criteria passed
python bench/timing/measure.py     # kill condition 3
python bench/latency/measure.py    # criterion 6
pytest -q                          # 16 adversarial tests
```

## Results

| Metric | Baseline (naive) | Enforced | Delta | Runs | Variance |
|---|---|---|---|---|---|
| Count inference — probes leaking | 13/15 | **0/15** | −13 | deterministic | none |
| Count inference — attacker exactly correct | 15/15 | **0/15** | −15 | deterministic | none |
| Restricted documents revealed to exist | 17 | **0** | −17 | deterministic | none |
| Observable count stability | varies by principal | **5 for all 9 principals** | — | deterministic | none |
| Content violations (135 principal×query pairs) | 0 | **0** | 0 | deterministic | none |
| Mean recall@5 vs per-principal ideal | 0.923 | **1.000** | **+0.077** | deterministic | none |
| Latency p50 | 7.29 µs | 10.83 µs | **1.48×** | 7 | spread 0.031 |
| Latency p95 | 8.63 µs | 12.92 µs | **1.50×** | 7 | 1.49–1.52 |
| Latency batched p99 | 11.78 µs | 16.25 µs | **1.37×** | 7 | 1.33–1.47 |
| Latency per-request p99 | 11.29 µs | 17.16 µs | **unresolved** | 7 | verdict flipped between whole runs |
| Timing channel SNR (padded vs unpadded) | — | **0.73** | — | 7 | 0.42–1.12 |
| **Relevance-channel inference (attacker reads results)** | 15/15 | **15/15** | **0** | deterministic | none |

**Noise floor.** An A/A control times two instances of *identical* code through the same
protocol. It deviates from unity by up to **1.15× at p99** — so any p99 difference below that
is unmeasurable on this machine, in either direction. p50 and p95 deviate by under 0.03.

**Minimum detectable difference.** The latency comparison is not close (1.48× against a 1.15×
floor), so the p50 and p95 results stand. The per-request p99 comparison *is* inside the region
where run-to-run swing exceeds the effect, which is why it is reported as unresolved.

## Against the success criteria

| # | Criterion | Threshold | Result | Pass |
|---|---|---|---|---|
| 1 | No content leak | 0 unreadable documents returned, ever | 0 across 135 principal×query pairs and 16 property tests | **yes** |
| 2 | Count inference defeated | attacker accuracy ≤ 1/15 | 15/15 → **0/15** | **yes** |
| 3 | Count-stability | identical count, every principal, every query | 5 for all 9 principals on all 15 probes; 0 unstable queries | **yes** |
| 4 | Existence probing defeated | 17 revealed → 0 | **0** | **yes** |
| 5 | Retrieval quality preserved | recall@5 within 5% of per-principal ideal | **1.000** — enforcement *gains* 7.75 points over naive | **yes** |
| 6 | Latency cost bounded | p99 within 2× naive | p50 1.48×, p95 1.50×, batched p99 1.37×, all 7/7 repeats. Per-request p99 unresolved. | **on the statistics this harness resolves** |

**Kill condition 3 triggered.** "If a timing side channel survives that reveals what padding
hid, say so." One does: median SNR 0.73, 1.8 µs. Published rather than suppressed.

## The most important result is a limitation found after the criteria passed

**The relevance channel restores the full original inference: 15/15 exact, by reading.**

Every benchmark above measured an observer of the *count*. Against that observer, count-stability
works. But the threat model said the attacker **is the principal** — and the principal receives
the results and can read them. Padded results share no terms with the query, so a caller who sees
five results and no answers knows every matching document is one they cannot read.

One request. No statistics. No timing precision. No second principal.

It was found by sweeping the deployed instance, not by any test in `tests/` or benchmark in
`bench/` — all of which were built around the count. The threat model was framed too narrowly,
and that is a flaw in the framing rather than in the fix.

The narrower true claim:

> Count-stability defeats an observer of the count. It does not defeat the recipient of the
> results.

Criteria 1–6 remain met as written, because they measured the count channel and the count channel
is closed. Criterion 2's label, "count inference defeated", describes less than it sounds like it
does. Full report in `bench/relevance/results/2026-08-21.md`.

## What came out worse than expected

**The `padded` flag hands the attacker the number directly.** It was justified in
`docs/03-architecture.md` on the grounds that "the *count* must carry no information, not the
payload". That reasoning holds against an observer who sees the count and not the payload. Against
the recipient it is wrong, and it was wrong when it was written.

**A timing channel survives, and it points the wrong way.** The heavily-padded arm is
*faster*, because padding appends pre-sorted documents rather than scoring more candidates. So
the channel leaks *"this query had few readable matches for you"* — close to what the count used
to give away. Had I assumed padding would be slower, I would have timed the wrong arm and
reported a clean result. Count-stability is therefore a **partial** defence, and the README says
so in its own section rather than in a footnote.

**Per-request p99 cannot be measured honestly at this scale, and the criterion asked for p99.**
Two runs of identical code produced worst-case ratios of 1.79× and 2.79× — one passes the
threshold, one fails it. At ~11 µs per search a single scheduler interrupt *is* the 99th
percentile. Reporting the passing run would have been picking a result. So the criterion is met
on p50, p95 and a batched p99, and the statistic it actually named is marked unresolved.

**Six benchmark bugs, five of which produced a green or flattering result:**

| Bug | What it reported | Truth |
|---|---|---|
| Attacker model used `k − returned` | inference 0/15 — vulnerability looks unexploitable | Calibrating against actual matches gives **15/15** |
| Access model had no EXEC cross-cut | CEO read 13 documents, same as an engineer | CEO reads **35**; without this every later measurement was meaningless |
| Quality test compared against "rank the readable set" | enforced recall 1.000 | **Circular** — that is exactly what the enforced retriever computes. And ideal sets were *empty*, because attack probes target restricted documents. 1.000 of nothing. |
| Timing test, single run | verdict flipped 0.26–0.64 across the 0.5 threshold | 7 repeats, alternating arm order → stable median **0.73** |
| Latency test, unpaired arms | two repeats showed enforced **faster** than naive | Impossible for an arm doing strictly more work. The 4.13× that would have failed criterion 6 was the same noise inverted. |
| Batched arm at 25 searches/sample | worst case 1.99× against a 2.00× threshold | A pass by 0.5% is the same unresolved tail at lower amplitude. Raised to 120 → worst **1.47×** |

The pattern worth naming: **every one of these was found by a control, not by inspection.**
The impossible result (enforced faster than naive), the A/A control, the naive-path control
asserting the leak *does* vary by principal, the CEO-vs-engineer readable-count check. A test
that only confirms the expected direction cannot catch a harness that is measuring nothing.

**Enforcement improving recall was not the predicted outcome.** The thesis budgeted for up to
5% recall loss and treated the tradeoff curve as a publishable result. Instead recall went *up*
7.75 points, because retrieve-then-filter lets restricted documents consume top-k slots a readable
document could have used. The prediction was wrong in a favourable direction, which is still a
wrong prediction and is recorded as one.
