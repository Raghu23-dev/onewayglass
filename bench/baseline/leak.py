#!/usr/bin/env python3
"""Measure what a post-filter retriever leaks.

The system under test never returns a document the caller cannot read. That is the
property people check, and it holds. This measures a different property: how much an
attacker can learn about documents they cannot read, using only what the system does
return.

Three attacks, in increasing subtlety:

1. **Direct disclosure** — the system reports how many results it withheld.
2. **Count inference** — the result count is fewer than k, and the deficit reveals how
   many restricted documents matched. Available even when nothing is reported.
3. **Existence probing** — targeted queries where a deficit confirms a specific document
   exists, letting an attacker map the hidden corpus by topic.

Run:  python bench/baseline/leak.py
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from onewayglass.corpus import DOCUMENTS, PRINCIPALS_BY_ID, Principal, visible_to
from onewayglass.naive import Index, NaiveRetriever

K = 5

#: Queries an ordinary employee could plausibly type. None is adversarial in wording —
#: the leak does not require unusual input, which is what makes it a real problem.
PROBES: tuple[tuple[str, str], ...] = (
    ("compensation bands for senior engineers", "people_comp"),
    ("redundancy planning next fiscal year", "people_redundancy"),
    ("grievance case notes raised this year", "people_grievance"),
    ("acquisition discussions with potential acquirers", "exec_acquisition"),
    ("runway analysis burn months", "exec_runway"),
    ("board minutes funding round", "exec_board"),
    ("executive succession candidates", "exec_succession"),
    ("security audit findings severity", "eng_audit"),
    ("infrastructure cost breakdown compute", "eng_cost"),
    ("commission structure accelerators quota", "sales_commission"),
    ("lost deal analysis compliance certification", "sales_lost"),
    ("performance calibration ratings moderated", "people_calibration"),
    ("holiday allowance annual leave", "benign_holiday"),
    ("deployment runbook roll back", "benign_deploy"),
    ("expense policy receipts approval", "benign_expense"),
)


@dataclass
class ProbeResult:
    query: str
    label: str
    #: How many documents matched the query at all, capped at k. What an attacker
    #: calibrates against.
    matched: int
    returned: int
    #: Restricted documents that matched in the global top-k.
    hidden_matches: int
    #: What the attacker infers purely from `returned < K`.
    inferred_hidden: int
    #: Titles of the documents the attacker learns exist without reading them.
    revealed_ids: list[str]


def run_attack(principal: Principal, retriever: NaiveRetriever, index: Index) -> list[ProbeResult]:
    out: list[ProbeResult] = []

    for query, label in PROBES:
        answer = retriever.search(principal, query, k=K)

        # Ground truth: which restricted documents were in the global top-k.
        global_top = index.score(query)[:K]
        hidden = [
            doc_id
            for doc_id, _ in global_top
            if not next(d for d in DOCUMENTS if d.id == doc_id).readable_by(principal)
        ]

        # The attacker's inference.
        #
        # A naive attacker computes k - returned. That over-counts, because a query
        # matching only two documents returns two results for reasons having nothing to do
        # with permission — the first version of this harness made exactly that mistake and
        # scored 0/15 on inference accuracy, which looked like the leak was unexploitable
        # when in fact the ATTACKER MODEL was wrong.
        #
        # A competent attacker calibrates: they issue the same query as an unprivileged
        # baseline and learn how many documents match at all. Here that is available
        # because the corpus size is knowable — but in any real deployment an attacker can
        # calibrate by probing with a query they know is unrestricted, or by observing that
        # the same query returns different counts for different colleagues.
        #
        # So the inference is against MATCHES, not against k.
        matches_available = min(K, len(index.score(query)))
        inferred = matches_available - answer.result_count

        out.append(
            ProbeResult(
                query=query,
                label=label,
                matched=matches_available,
                returned=answer.result_count,
                hidden_matches=len(hidden),
                inferred_hidden=inferred,
                revealed_ids=hidden,
            )
        )
    return out


def main() -> None:
    index = Index()
    silent = NaiveRetriever(index, report_filtered=False)
    verbose = NaiveRetriever(index, report_filtered=True)

    # An IC with no access to people, exec or senior engineering material.
    attacker = PRINCIPALS_BY_ID["u_ic_eng"]
    readable = len(visible_to(attacker))

    print(f"attacker: {attacker.name} ({attacker.department}, {attacker.level.name})")
    print(f"corpus: {len(DOCUMENTS)} documents · attacker may read {readable}")
    print(f"k = {K}\n")

    results = run_attack(attacker, silent, index)

    print(f"{'query':<44}{'matched':>8}{'ret':>5}{'inferred':>10}{'actual':>8}  ok")
    print("-" * 78)
    exact = 0
    leaking = 0
    for r in results:
        ok = r.inferred_hidden == r.hidden_matches
        exact += ok
        if r.hidden_matches > 0:
            leaking += 1
        print(
            f"{r.query[:42]:<44}{r.matched:>8}{r.returned:>5}{r.inferred_hidden:>10}"
            f"{r.hidden_matches:>8}  {'yes' if ok else 'NO'}"
        )

    total_revealed = {i for r in results for i in r.revealed_ids}

    print()
    print("=== attack 2: count inference (no reported count needed) ===")
    print(f"  probes where restricted documents matched: {leaking}/{len(results)}")
    print(f"  inference exactly correct:                 {exact}/{len(results)}")
    print(f"  distinct restricted documents revealed:    {len(total_revealed)}")

    print()
    print("=== attack 3: existence probing ===")
    print("  A deficit on a topic-specific query confirms a document on that topic exists.")
    for r in results:
        if r.hidden_matches > 0 and r.label.startswith(("people_", "exec_")):
            titles = [next(d.title for d in DOCUMENTS if d.id == i) for i in r.revealed_ids]
            print(f'  "{r.query}"')
            print(f"    → {r.inferred_hidden} hidden. Attacker learns these exist: {titles}")

    print()
    print("=== attack 1: direct disclosure (report_filtered=True) ===")
    v = verbose.search(attacker, "compensation bands for senior engineers", k=K)
    print(f"  returned {v.result_count}, system reports filtered_count={v.filtered_count}")
    print("  No inference needed — the count is handed over.")

    # A control: does an authorised principal see the same deficits? If they do not, the
    # deficit is a reliable signal rather than noise, which is what makes it exploitable.
    print()
    print("=== control: does the deficit track permission? ===")
    print(f"  {'principal':<22}{'readable':>9}{'deficit sum':>13}")
    for pid in ("u_ic_eng", "u_dir_eng", "u_dir_people", "u_exec"):
        p = PRINCIPALS_BY_ID[pid]
        rs = run_attack(p, silent, index)
        print(f"  {p.name:<22}{len(visible_to(p)):>9}{sum(r.inferred_hidden for r in rs):>13}")
    print("  A deficit that shrinks as permission grows is a permission oracle.")

    out = Path(__file__).parent / "results" / "leak.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "corpus_size": len(DOCUMENTS),
                "k": K,
                "attacker": attacker.id,
                "attacker_readable": readable,
                "probes": len(results),
                "probes_with_hidden_matches": leaking,
                "inference_exactly_correct": exact,
                "distinct_documents_revealed": sorted(total_revealed),
                "results": [
                    {
                        "query": r.query,
                        "returned": r.returned,
                        "inferred_hidden": r.inferred_hidden,
                        "actual_hidden": r.hidden_matches,
                        "revealed_ids": r.revealed_ids,
                    }
                    for r in results
                ],
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw results → {out}")


if __name__ == "__main__":
    main()
