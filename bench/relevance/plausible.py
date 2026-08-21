#!/usr/bin/env python3
"""Can relevance-plausible padding close the relevance channel?

The open channel: padded results share no terms with the query, so the principal reading five
non-answers knows every document that did match is one they cannot read. `bench/relevance/`
measures that at 15/15 exact.

The obvious fix is to choose filler that at least LOOKS on-topic — order the non-matching readable
documents by how many query terms they share, rather than by document id. This measures whether
that works.

WHAT IT FINDS, AND WHY IT IS STRUCTURAL RATHER THAN A TUNING PROBLEM

It does not work, and it cannot. For the attack queries, NO readable document shares a single term
with the query. There is nothing plausible to choose from: the filler pool is documents about
deployment runbooks and on-call rotations, and the query is about redundancy planning.

That is not a shortcoming of the ordering heuristic. It is a property of the situation the defence
is in — the caller is asking about a subject they have no access to, so every document they CAN
read is off-topic by definition. Plausible padding needs plausible material, and a principal
restricted from a topic has none.

Run:  python bench/relevance/plausible.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))

from leak import PROBES, K

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, PRINCIPALS_BY_ID, visible_to
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, tokenise


def detectable(query: str, results) -> int:
    """How many results a reader can identify as filler using term overlap alone."""
    q = set(tokenise(query))
    return sum(
        1 for r in results if not (q & set(tokenise(f"{r.document.title} {r.document.text}")))
    )


def main() -> None:
    index = Index()
    attacker = PRINCIPALS_BY_ID["u_ic_eng"]
    default = EnforcedRetriever(index, plausible_pad=False)
    plausible = EnforcedRetriever(index, plausible_pad=True)

    print("Can filler that shares query terms hide the fact that it is filler?")
    print(f"attacker: {attacker.name}, reads {len(visible_to(attacker))} of {len(DOCUMENTS)}\n")

    print(f"{'query':<42}{'default':>9}{'plausible':>11}{'best avail':>12}")
    print("-" * 74)

    rows = []
    readable = [d for d in DOCUMENTS if d.readable_by(attacker)]

    for query, _label in PROBES:
        d_ans = default.search(attacker, query, k=K)
        p_ans = plausible.search(attacker, query, k=K)
        d_det = detectable(query, d_ans.results)
        p_det = detectable(query, p_ans.results)

        # The ceiling: the most query terms ANY readable document shares. If this is zero, no
        # ordering heuristic can produce plausible filler, because none exists.
        q = set(tokenise(query))
        best = max(
            (len(q & set(tokenise(f"{doc.title} {doc.text}"))) for doc in readable),
            default=0,
        )

        rows.append(
            {
                "query": query,
                "default_detectable": d_det,
                "plausible_detectable": p_det,
                "best_available_overlap": best,
            }
        )
        print(f"{query[:40]:<42}{d_det:>7}/5{p_det:>9}/5{best:>12}")

    d_total = sum(r["default_detectable"] for r in rows)
    p_total = sum(r["plausible_detectable"] for r in rows)
    no_material = sum(1 for r in rows if r["best_available_overlap"] == 0)

    print()
    print("=== does plausible padding help? ===")
    print(f"  results detectable as filler, default pad:   {d_total}/{len(rows) * K}")
    print(f"  results detectable as filler, plausible pad: {p_total}/{len(rows) * K}")
    print(f"  improvement: {d_total - p_total}")

    print()
    print("=== why not ===")
    print(f"  queries where NO readable document shares a single term: {no_material}/{len(rows)}")
    print("  Plausible padding needs plausible material. A principal asking about a subject they")
    print("  have no access to can read nothing on that subject — every document available as")
    print("  filler is off-topic by definition. The ordering heuristic has nothing to order.")

    # Does more permission change it? If the failure is structural, the principal who can read
    # everything should be the only one with plausible material available.
    print()
    print("=== does it depend on how much the principal can read? ===")
    print(f"  {'principal':<20}{'readable':>9}{'queries with material':>24}")
    per_principal = []
    for p in PRINCIPALS:
        vis = [d for d in DOCUMENTS if d.readable_by(p)]
        with_material = 0
        for query, _ in PROBES:
            q = set(tokenise(query))
            if any(q & set(tokenise(f"{d.title} {d.text}")) for d in vis):
                with_material += 1
        per_principal.append(
            {"principal": p.id, "readable": len(vis), "queries_with_material": with_material}
        )
        print(f"  {p.name:<20}{len(vis):>9}{with_material:>20}/{len(PROBES)}")
    print("  Material becomes available only as permission rises — which is exactly backwards.")
    print("  The principals who most need the cover are the ones who cannot have it.")

    print()
    print("=== verdict ===")
    if p_total < d_total:
        print(f"  Plausible padding reduces detectable filler by {d_total - p_total}. Partial.")
    else:
        print("  NO IMPROVEMENT. The relevance channel is not closed by choosing better filler,")
        print("  and this is structural rather than a tuning failure. Closing it needs filler")
        print("  the caller is not entitled to see, which defeats the purpose, or synthetic")
        print("  filler, which is detectable as fabricated and useless to the caller.")
        print()
        print("  Recorded as a negative result. The relevance channel stays open and documented.")

    out = Path(__file__).parent / "results" / "plausible.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "k": K,
                "attacker": attacker.id,
                "probes": len(rows),
                "default_detectable_total": d_total,
                "plausible_detectable_total": p_total,
                "improvement": d_total - p_total,
                "queries_with_no_plausible_material": no_material,
                "verdict": (
                    "NO IMPROVEMENT — structural, not a tuning failure"
                    if p_total >= d_total
                    else "partial improvement"
                ),
                "rows": rows,
                "per_principal": per_principal,
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw → {out}")


if __name__ == "__main__":
    main()
