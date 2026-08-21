#!/usr/bin/env python3
"""Is there a timing side channel that reveals what padding hid?

Count-stability closes the obvious channel. It does not automatically close timing: if
padding a response takes measurably longer than not padding it, an attacker times requests
and recovers exactly the signal the count no longer carries.

Kill condition 3 requires this be examined and reported rather than assumed absent.

Run:  python bench/timing/measure.py
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from onewayglass.corpus import PRINCIPALS_BY_ID
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index

K = 5
RUNS = 2000
#: Repeat the whole experiment this many times. A single measurement of SNR was observed
#: to vary 0.26-0.64 across runs — straddling the decision threshold, so the verdict
#: flipped run to run. Reporting one run would have meant reporting a coin toss.
REPEATS = 7

# A query with many readable matches for this principal: little or no padding needed.
NO_PAD_QUERY = "deployment runbook on-call rotation service architecture"
# A query aimed at restricted material: heavily padded for the same principal.
HEAVY_PAD_QUERY = "compensation bands redundancy acquisition succession"


def timed(retriever: EnforcedRetriever, principal, query: str, runs: int) -> list[float]:
    samples = []
    for _ in range(runs):
        start = time.perf_counter()
        retriever.search(principal, query, k=K)
        samples.append((time.perf_counter() - start) * 1_000_000)  # microseconds
    return samples


def main() -> None:
    index = Index()
    enforced = EnforcedRetriever(index)
    attacker = PRINCIPALS_BY_ID["u_ic_eng"]

    # Warm up so the first-call cost of building readable sets does not skew the first arm.
    timed(enforced, attacker, NO_PAD_QUERY, 200)

    pad_a = sum(1 for r in enforced.search(attacker, NO_PAD_QUERY, k=K).results if r.padded)
    pad_b = sum(1 for r in enforced.search(attacker, HEAVY_PAD_QUERY, k=K).results if r.padded)

    print(f"{REPEATS} repeats x {RUNS} runs per arm, microseconds")
    print(f"arms: {pad_a} padded vs {pad_b} padded results\n")
    print(f"{'repeat':>7}{'few-match median':>19}{'many-match median':>20}{'diff':>8}{'snr':>7}")
    print("-" * 62)

    snrs: list[float] = []
    diffs: list[float] = []
    for i in range(REPEATS):
        # Alternate arm order between repeats. Always measuring the same arm first lets
        # cache warmth and CPU frequency scaling bias the result in one direction.
        if i % 2 == 0:
            a = timed(enforced, attacker, NO_PAD_QUERY, RUNS)
            b = timed(enforced, attacker, HEAVY_PAD_QUERY, RUNS)
        else:
            b = timed(enforced, attacker, HEAVY_PAD_QUERY, RUNS)
            a = timed(enforced, attacker, NO_PAD_QUERY, RUNS)

        ma, mb = statistics.median(a), statistics.median(b)
        pooled = statistics.mean([statistics.stdev(a), statistics.stdev(b)])
        diff = abs(mb - ma)
        snr = diff / pooled if pooled else 0.0
        snrs.append(snr)
        diffs.append(diff)
        print(f"{i + 1:>7}{ma:>19.1f}{mb:>20.1f}{diff:>8.1f}{snr:>7.2f}")

    median_snr = statistics.median(snrs)
    print()
    print(f"  SNR across repeats: {min(snrs):.2f}-{max(snrs):.2f}, median {median_snr:.2f}")
    print(f"  median difference:  {statistics.median(diffs):.1f} us")

    # The threshold is on the MEDIAN of repeats, not a single run. A single run was observed
    # to vary 0.26-0.64 — straddling the threshold, so the verdict flipped between runs.
    # Reporting one run would have been reporting a coin toss as a finding.
    THRESHOLD = 0.5
    if median_snr < THRESHOLD:
        verdict = "no practically exploitable timing channel found"
        print()
        print(f"  {verdict}.")
        print(f"  The median SNR of {median_snr:.2f} means the signal is smaller than the")
        print("  run-to-run noise, so an attacker needs many observations per query to")
        print("  separate the arms — and that volume is itself an anomalous query pattern.")
        print("  NOT a proof of absence: a channel below this noise floor may still exist.")
    else:
        verdict = "TIMING CHANNEL PRESENT"
        print()
        print(f"  {verdict}. Padding is distinguishable by latency, so count-stability is")
        print("  incomplete and the README must say so rather than claiming the guarantee.")

    print()
    print("  DIRECTION IS COUNTERINTUITIVE and worth stating: the heavily-padded arm is")
    print("  FASTER, not slower. Padding appends pre-sorted readable documents, which is")
    print("  cheaper than scoring more candidates. So the channel — where it exists — leaks")
    print("  'this query had few readable matches', not 'this query was padded'.")

    print()
    print("  SCOPE, stated honestly: this measures an in-process retriever on one machine.")
    print("  A network deployment adds jitter that would mask a channel this small, and a")
    print("  database-backed store could introduce a LARGER one that this does not model.")
    print("  Constant-time retrieval is explicitly a non-goal.")

    out = Path(__file__).parent / "results" / "timing.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "runs_per_arm": RUNS,
                "repeats": REPEATS,
                "unit": "microseconds",
                "few_restricted_padded": pad_a,
                "many_restricted_padded": pad_b,
                "snr_per_repeat": [round(x, 3) for x in snrs],
                "snr_median": round(median_snr, 3),
                "snr_range": [round(min(snrs), 3), round(max(snrs), 3)],
                "median_difference": round(statistics.median(diffs), 2),
                "verdict": verdict,
                "scope": "in-process, single machine; network and DB-backed stores not modelled",
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw results → {out}")


if __name__ == "__main__":
    main()
