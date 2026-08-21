#!/usr/bin/env python3
"""What does count-stability cost in latency?

Criterion 6: p99 within 2x the naive path, over at least 5 runs, with variance reported.

The enforced path does strictly more work than the naive one — it tests readability against
every document before ranking rather than against k results after, then pads. If that costs
more than 2x, the defence is uneconomic and the rest of the result is academic.

TWO MEASUREMENT PROBLEMS, BOTH FOUND BEFORE THE NUMBER WAS BELIEVED

1. AN UNFAIR DENOMINATOR. `NaiveRetriever.search` resolves each result id with
   `next(d for d in documents if ...)` — a linear scan per result. `EnforcedRetriever` uses
   a dict built once. Comparing them directly measures partly the defence and partly the
   baseline's sloppy lookup, and that bias favours the thing being sold. So a third arm runs
   naive with the same dict lookup and nothing else changed. That is the honest denominator.

2. AN UNRESOLVABLE TAIL. The first version measured each arm in a separate block and
   compared p99s. Across 7 repeats the ratio ranged 0.88x to 4.13x — and two repeats put the
   enforced arm FASTER than naive, which cannot be true of an arm doing strictly more work.
   That is proof the tail was scheduler noise, not the code: at single-digit microseconds one
   context switch dominates the 99th percentile.

   Fixed two ways. Sampling is now PAIRED — the arms are timed adjacent to each other for the
   same principal and query, alternating which goes first, so an interruption lands on both.
   And an A/A CONTROL times two instances of the *same* arm through the identical protocol.
   Whatever ratio the A/A control reports is the harness's own noise floor; a difference
   smaller than that is not measurable here, whichever way it points.

Run:  python bench/latency/measure.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, Principal
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, NaiveRetriever

K = 5
#: Paired samples per principal per query. 9 principals x 8 queries x 60 = 4,320 pairs per
#: repeat, so p99 is the 44th worst value rather than an outlier of a handful.
PAIRS = 60
#: Five is the pre-registered minimum. Seven, because p99 is more outlier-sensitive than the
#: means the timing benchmark compared, and that one already needed repeats to stop flipping.
REPEATS = 7

#: Mixed deliberately. Latency depends on how many readable documents match: a query with
#: few matches pads more, one matching nothing skips most ranking. Averaging over a single
#: query shape would not represent deployment.
QUERIES: tuple[str, ...] = (
    "deployment runbook roll back previous image",
    "compensation bands senior engineering bonus",
    "acquisition discussions potential acquirers",
    "holiday allowance annual leave carry over",
    "security audit findings session handling",
    "commission accelerators quota rate",
    "redundancy planning reduction roles",
    "service architecture api gateway redis postgres",
)


def percentile(values: list[float], p: float) -> float:
    """Linear-interpolated percentile.

    Interpolated rather than nearest-rank: at thousands of samples the gap between
    neighbouring tail values is real, and rounding to one of them reports a number that was
    never measured.
    """
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


class OptimisedNaive:
    """The naive retriever with its linear id lookup replaced by a dict.

    Identical semantics — retrieve globally, then filter — so it leaks exactly as much. It
    exists only to stop the comparison crediting enforcement for a difference in bookkeeping.
    """

    def __init__(self, index: Index) -> None:
        self.index = index
        self._by_id = {d.id: d for d in index.documents}

    def search(self, principal: Principal, query: str, k: int = K) -> int:
        kept = 0
        for doc_id, _ in self.index.score(query)[:k]:
            if self._by_id[doc_id].readable_by(principal):
                kept += 1
        return kept


def paired(call_a, call_b, order_offset: int) -> tuple[list[float], list[float]]:
    """Time two arms adjacent to each other on identical work.

    Adjacency is the point. Scheduler noise, frequency scaling and cache state drift over
    the seconds a benchmark takes; measuring arm A for two seconds and then arm B for two
    seconds compares different machine conditions. Interleaving means both arms see the same
    conditions, and alternating which goes first cancels the small advantage of running
    second on a warm cache.
    """
    a_samples: list[float] = []
    b_samples: list[float] = []
    n = len(QUERIES)

    for principal in PRINCIPALS:
        for qi in range(n):
            query = QUERIES[(qi + order_offset) % n]
            for i in range(PAIRS):
                if i % 2 == 0:
                    t0 = time.perf_counter()
                    call_a(principal, query)
                    t1 = time.perf_counter()
                    call_b(principal, query)
                    t2 = time.perf_counter()
                    a_samples.append((t1 - t0) * 1_000_000)
                    b_samples.append((t2 - t1) * 1_000_000)
                else:
                    t0 = time.perf_counter()
                    call_b(principal, query)
                    t1 = time.perf_counter()
                    call_a(principal, query)
                    t2 = time.perf_counter()
                    b_samples.append((t1 - t0) * 1_000_000)
                    a_samples.append((t2 - t1) * 1_000_000)

    return a_samples, b_samples


def stats(samples: list[float]) -> dict[str, float]:
    return {
        "p50": percentile(samples, 0.50),
        "p95": percentile(samples, 0.95),
        "p99": percentile(samples, 0.99),
        "mean": statistics.fmean(samples) if samples else 0.0,
    }


def main() -> None:
    index = Index()
    naive_as_written = NaiveRetriever(index)
    naive_a = OptimisedNaive(index)
    #: A second instance for the A/A control. Distinct so neither shares the other's dict
    #: and one arm cannot look faster for having a warmer object.
    naive_b = OptimisedNaive(index)
    enforced = EnforcedRetriever(index)

    call_naive = lambda p, q: naive_a.search(p, q, k=K)  # noqa: E731
    call_naive2 = lambda p, q: naive_b.search(p, q, k=K)  # noqa: E731
    call_enforced = lambda p, q: enforced.search(p, q, k=K)  # noqa: E731
    call_naive_slow = lambda p, q: naive_as_written.search(p, q, k=K)  # noqa: E731

    # Warm every arm before any is measured, so no arm pays the one-off cost of interning
    # strings and filling caches while being timed.
    for call in (call_naive, call_naive2, call_enforced, call_naive_slow):
        paired(call, call, 0)

    print(f"{REPEATS} repeats, {PAIRS} paired samples per principal per query, microseconds")
    print(f"corpus {len(DOCUMENTS)} documents, {len(PRINCIPALS)} principals, k={K}")
    print(f"{len(PRINCIPALS) * len(QUERIES) * PAIRS:,} pairs per arm per repeat\n")

    aa_ratios: list[float] = []
    ab_ratios: list[float] = []
    ab_p50_ratios: list[float] = []
    slow_ratios: list[float] = []
    per_arm: dict[str, list[dict[str, float]]] = {
        "naive (as written)": [],
        "naive (dict lookup)": [],
        "enforced": [],
    }

    print("  repeat      A/A control      enforced vs naive      p50 ratio")
    print("  " + "-" * 62)
    for repeat in range(REPEATS):
        # A/A control first: what ratio does the harness report for two arms that are the
        # same code? Anything the A/B comparison shows below this is unmeasurable here.
        aa_a, aa_b = paired(call_naive, call_naive2, repeat)
        aa = percentile(aa_a, 0.99) / percentile(aa_b, 0.99)
        aa_ratios.append(aa)

        n_s, e_s = paired(call_naive, call_enforced, repeat)
        n_st, e_st = stats(n_s), stats(e_s)
        ab = e_st["p99"] / n_st["p99"] if n_st["p99"] else 0.0
        ab50 = e_st["p50"] / n_st["p50"] if n_st["p50"] else 0.0
        ab_ratios.append(ab)
        ab_p50_ratios.append(ab50)

        # The as-written baseline, kept because it is what the leak benchmark actually ran.
        sl_s, e2_s = paired(call_naive_slow, call_enforced, repeat)
        sl_st = stats(sl_s)
        slow_ratios.append(e_st["p99"] / sl_st["p99"] if sl_st["p99"] else 0.0)

        per_arm["naive (as written)"].append(sl_st)
        per_arm["naive (dict lookup)"].append(n_st)
        per_arm["enforced"].append(e_st)

        print(f"  {repeat + 1:<10}{aa:>9.2f}x{ab:>22.2f}x{ab50:>15.2f}x")

    print()
    print(f"{'arm':<22}{'p50':>9}{'p95':>9}{'p99':>9}{'mean':>9}   p99 spread")
    print("-" * 74)
    summary: dict[str, dict[str, float]] = {}
    for name, rows in per_arm.items():
        p99s = [r["p99"] for r in rows]
        row = {
            "p50": statistics.median(r["p50"] for r in rows),
            "p95": statistics.median(r["p95"] for r in rows),
            "p99": statistics.median(p99s),
            "mean": statistics.median(r["mean"] for r in rows),
            "p99_min": min(p99s),
            "p99_max": max(p99s),
            "p99_stdev": statistics.stdev(p99s) if len(p99s) > 1 else 0.0,
        }
        summary[name] = row
        print(
            f"{name:<22}{row['p50']:>9.2f}{row['p95']:>9.2f}{row['p99']:>9.2f}"
            f"{row['mean']:>9.2f}   {row['p99_min']:.1f}-{row['p99_max']:.1f} "
            f"(sd {row['p99_stdev']:.2f})"
        )

    aa_worst = max(aa_ratios)
    aa_median = statistics.median(aa_ratios)
    ab_worst = max(ab_ratios)
    ab_median = statistics.median(ab_ratios)

    print()
    print("=== noise floor: the A/A control ===")
    print(
        f"  two instances of the SAME arm, same protocol: median {aa_median:.2f}x, "
        f"worst {aa_worst:.2f}x"
    )
    if aa_worst <= 1.15:
        print("  The harness resolves the tail. The A/B ratio below is attributable to the code.")
    else:
        print("  The harness does NOT fully resolve the tail; treat A/B worst-case with that")
        print("  spread in mind rather than as a property of the defence.")

    print()
    print("=== criterion 6: p99 within 2x the naive path ===")
    print("  denominator: naive (dict lookup), so the ratio is not inflated by the")
    print("  baseline's O(k*n) id scan.")
    print(f"  p99 ratio: median {ab_median:.2f}x, worst of {REPEATS} repeats {ab_worst:.2f}x")
    print(f"  p50 ratio: median {statistics.median(ab_p50_ratios):.2f}x")
    print(f"  vs the as-written naive path: median {statistics.median(slow_ratios):.2f}x")

    # Worst case, not median. A latency budget is blown by the bad repeat, not the typical
    # one — and with the A/A control establishing the noise floor, the worst case is now a
    # statement about the code rather than about the machine.
    met = ab_worst <= 2.0
    print(
        f"  worst case is the number a latency budget cares about -> {'MET' if met else 'NOT MET'}"
    )

    print()
    print("=== why the enforced path costs more ===")
    print(f"  naive tests readability {K} times per query (on the top-k it already ranked)")
    print(f"  enforced tests it {len(DOCUMENTS)} times per query (before ranking anything)")
    print(f"  {len(DOCUMENTS) // K}x the permission checks, cheap next to the BM25 scoring")
    print("  both arms pay — which is why the ratio is well under the check-count ratio.")
    print("  The cost scales with CORPUS SIZE, not k. At 35 documents it is invisible; at a")
    print("  million it is a full scan per query, and this implementation would need a")
    print("  precomputed readable set or a permission-partitioned index. That is a real")
    print("  limit of the approach, not of the benchmark.")

    out = Path(__file__).parent / "results" / "latency.json"
    out.write_text(
        json.dumps(
            {
                "k": K,
                "pairs_per_principal_per_query": PAIRS,
                "repeats": REPEATS,
                "principals": len(PRINCIPALS),
                "corpus_size": len(DOCUMENTS),
                "queries": list(QUERIES),
                "unit": "microseconds",
                "paired_sampling": True,
                "arms": summary,
                "denominator": "naive (dict lookup)",
                "aa_control_p99_ratios": [round(r, 4) for r in aa_ratios],
                "aa_control_median": round(aa_median, 4),
                "aa_control_worst": round(aa_worst, 4),
                "p99_ratios": [round(r, 4) for r in ab_ratios],
                "p50_ratios": [round(r, 4) for r in ab_p50_ratios],
                "median_p99_ratio": round(ab_median, 4),
                "worst_p99_ratio": round(ab_worst, 4),
                "threshold": 2.0,
                "criterion_6_met": met,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw results -> {out}")


if __name__ == "__main__":
    main()
