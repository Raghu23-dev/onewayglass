#!/usr/bin/env python3
"""Replay the leak attacks against the enforced retriever.

bench/baseline/leak.py measured 17 documents revealed and inference exact 15/15. This runs
the same attacks against the enforced path. The side-by-side is the headline result.

Run:  python bench/enforce/replay.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))

from leak import K, PROBES

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, PRINCIPALS_BY_ID, visible_to
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, NaiveRetriever


def main() -> None:
    index = Index()
    naive = NaiveRetriever(index)
    enforced = EnforcedRetriever(index)
    attacker = PRINCIPALS_BY_ID["u_ic_eng"]

    print(f"attacker: {attacker.name} · may read {len(visible_to(attacker))} of {len(DOCUMENTS)}")
    print(f"k = {K}\n")

    print(f"{'query':<44}{'naive':>7}{'enforced':>10}{'hidden':>8}{'inferable':>11}")
    print("-" * 80)

    naive_leaks = 0
    enforced_leaks = 0
    revealed_naive: set[str] = set()
    revealed_enforced: set[str] = set()

    for query, _ in PROBES:
        n = naive.search(attacker, query, k=K)
        e = enforced.search(attacker, query, k=K)

        global_top = index.score(query)[:K]
        hidden = [
            d
            for d, _ in global_top
            if not next(x for x in DOCUMENTS if x.id == d).readable_by(attacker)
        ]

        matches = min(K, len(index.score(query)))
        naive_inferred = matches - n.result_count
        enforced_inferred = matches - e.result_count

        if naive_inferred > 0 and hidden:
            naive_leaks += 1
            revealed_naive.update(hidden)
        if enforced_inferred > 0 and hidden:
            enforced_leaks += 1
            revealed_enforced.update(hidden)

        print(
            f"{query[:42]:<44}{n.result_count:>7}{e.result_count:>10}"
            f"{len(hidden):>8}{enforced_inferred:>11}"
        )

    print()
    print("=== attack 2: count inference ===")
    print(f"  naive:    {naive_leaks}/{len(PROBES)} probes leaked a count")
    print(f"  enforced: {enforced_leaks}/{len(PROBES)} probes leaked a count")

    print()
    print("=== attack 3: existence probing ===")
    print(f"  naive:    {len(revealed_naive)} restricted documents revealed to exist")
    print(f"  enforced: {len(revealed_enforced)} restricted documents revealed to exist")

    print()
    print("=== criterion 3: identical observable count for every principal ===")
    unstable = []
    for query, _ in PROBES:
        counts = {p.id: enforced.search(p, query, k=K).result_count for p in PRINCIPALS}
        distinct = sorted(set(counts.values()))
        if len(distinct) > 1:
            unstable.append((query, counts))
        print(f"  {query[:42]:<44}{str(distinct):>28}")

    print()
    if unstable:
        print(f"  UNSTABLE on {len(unstable)}/{len(PROBES)} queries — criterion 3 NOT met:")
        for q, c in unstable[:3]:
            print(f"    {q}")
            print(f"      {c}")
    else:
        print(f"  stable on all {len(PROBES)} queries")

    print()
    print("=== criterion 1: no unreadable document returned ===")
    violations = []
    for p in PRINCIPALS:
        for query, _ in PROBES:
            for r in enforced.search(p, query, k=K).results:
                if not r.document.readable_by(p):
                    violations.append((p.id, query, r.document.id))
    print(f"  checked {len(PRINCIPALS) * len(PROBES)} principal-query pairs")
    print(f"  violations: {len(violations)}")

    out = Path(__file__).parent / "results" / "replay.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "k": K,
                "attacker": attacker.id,
                "count_inference": {
                    "naive": naive_leaks,
                    "enforced": enforced_leaks,
                    "probes": len(PROBES),
                },
                "existence_probing": {
                    "naive": len(revealed_naive),
                    "enforced": len(revealed_enforced),
                },
                "count_stable": not unstable,
                "unstable_queries": [q for q, _ in unstable],
                "content_violations": len(violations),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw results → {out}")

    if unstable or violations:
        sys.exit(1)


if __name__ == "__main__":
    main()
