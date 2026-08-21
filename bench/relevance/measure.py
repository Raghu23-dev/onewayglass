#!/usr/bin/env python3
"""Does the RELEVANCE profile leak what the count no longer does?

Count-stability closes the count channel. This asks a harder question that the earlier
benchmarks never posed: the attacker in this threat model IS the principal. They receive the
results. They can read them.

If a padded result is recognisable as padding — zero query terms, score 0.0, obviously
off-topic — then the attacker does not need the count at all. They count how many of their k
results are actually RELEVANT, and that number is exactly what the deficit used to be.

`docs/02-thesis.md` named this vector before any code was written:

    "if padded results are detectable by relevance score, position or latency — publish the
     residual channel and its bandwidth rather than claiming stability."

Latency was measured in `bench/timing/`. This measures relevance, which is the stronger of the
two: it needs no repeated sampling, no statistics, and no timing precision. One request.

THE ATTACKER MODEL

Weaker than the machinery available to them, deliberately. They do not recompute BM25. They ask
only: does this document share a single non-stopword term with my query? A document with none of
the query's terms did not rank for the query, so it is padding. That is checkable by eye.

Run:  python bench/relevance/measure.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))

from leak import PROBES, K

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, PRINCIPALS_BY_ID
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, tokenise


def looks_like_padding(query: str, title: str, text: str) -> bool:
    """The attacker's test, using only what is in front of them.

    No BM25, no corpus statistics, no second request. Term overlap alone — which a human
    reading five results spots without any tooling at all.
    """
    q = set(tokenise(query))
    d = set(tokenise(f"{title} {text}"))
    return not (q & d)


def main() -> None:
    index = Index()
    enforced = EnforcedRetriever(index)
    attacker = PRINCIPALS_BY_ID["u_ic_eng"]

    print("Attacker is the principal. They can read their own results.")
    print(f"attacker: {attacker.name} · corpus {len(DOCUMENTS)} · k={K}\n")

    print(f"{'query':<40}{'avail':>6}{'relev':>6}{'inferred':>9}{'actual':>7}  exact")
    print("-" * 70)

    exact = 0
    leaking = 0
    rows = []
    for query, _label in PROBES:
        answer = enforced.search(attacker, query, k=K)

        # What the attacker sees, judged only by reading.
        relevant = sum(
            1
            for r in answer.results
            if not looks_like_padding(query, r.document.title, r.document.text)
        )

        # The same calibration the count attack used: how many documents match at all.
        available = min(K, len(index.score(query)))
        inferred = max(0, available - relevant)

        # Ground truth: restricted documents in the global top-k.
        top = index.score(query)[:K]
        by_id = {d.id: d for d in DOCUMENTS}
        actual = sum(1 for i, _ in top if not by_id[i].readable_by(attacker))

        ok = inferred == actual
        exact += ok
        if actual > 0:
            leaking += 1

        rows.append(
            {
                "query": query,
                "count_returned": answer.result_count,
                "available": available,
                "relevant_by_reading": relevant,
                "inferred_hidden": inferred,
                "actual_hidden": actual,
                "exact": ok,
            }
        )
        print(
            f"{query[:38]:<40}{available:>6}{relevant:>6}{inferred:>9}{actual:>7}"
            f"  {'yes' if ok else 'NO'}"
        )

    # The count channel, for comparison — this is what the enforced path DID close.
    counts = {p.id: enforced.search(p, PROBES[1][0], k=K).result_count for p in PRINCIPALS}
    count_stable = len(set(counts.values())) == 1

    # And the flag, which is handed over outright.
    flagged = sum(1 for r in enforced.search(attacker, PROBES[1][0], k=K).results if r.padded)

    print()
    print("=== the count channel (closed) ===")
    print(f"  observable count identical across all 9 principals: {count_stable}")

    print()
    print("=== the relevance channel (OPEN) ===")
    print(f"  probes where restricted documents matched:  {leaking}/{len(PROBES)}")
    print(f"  inference exactly correct BY READING:       {exact}/{len(PROBES)}")
    print("  No count comparison, no second principal, no timing. One request, read the")
    print("  results, count the ones that answer the question.")

    print()
    print("=== and the `padded` flag hands it over ===")
    print(f'  "{PROBES[1][0]}" returns {flagged} results flagged padded=True.')
    print("  The flag exists so an authorised caller can weight or hide filler — which is")
    print("  the right thing for the caller and, for an attacker who is also the caller,")
    print("  a direct read of the number the count no longer gives.")

    print()
    print("=== what this means ===")
    print("  Count-stability defeats an observer of the COUNT: a cross-principal comparison,")
    print("  a log, a proxy, a colleague comparing notes. It does not defeat the principal")
    print("  themselves, because relevance is self-evident to whoever reads the results.")
    print()
    print("  Closing this needs padding that is relevance-PLAUSIBLE — filler that shares")
    print("  query terms — and even then a determined reader distinguishes a real answer from")
    print("  a topically-similar non-answer. That is a substantially harder problem than")
    print("  count-stability and is not solved here.")

    out = Path(__file__).parent / "results" / "relevance.json"
    out.write_text(
        json.dumps(
            {
                "k": K,
                "attacker": attacker.id,
                "attacker_model": "term overlap only — no BM25, no second request",
                "probes": len(PROBES),
                "probes_with_hidden_matches": leaking,
                "inference_exactly_correct": exact,
                "count_channel_closed": count_stable,
                "relevance_channel_open": exact > 0,
                "padded_flag_discloses_directly": True,
                "verdict": (
                    "RELEVANCE CHANNEL PRESENT — count-stability is necessary and not sufficient"
                ),
                "rows": rows,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw results → {out}")


if __name__ == "__main__":
    main()
