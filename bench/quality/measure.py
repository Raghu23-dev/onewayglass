#!/usr/bin/env python3
"""Criterion 5: does enforcement destroy retrieval quality?

Count-stability is trivial to achieve by returning nothing useful. This measures whether an
AUTHORISED caller still gets good answers.

Ground truth is per-principal: for each query, the relevant documents are those the
principal may read AND that a permission-blind index ranks highly. Comparing against a
global ceiling would penalise enforcement for correctly withholding documents, which would
measure the wrong thing.

Run:  python bench/quality/measure.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "baseline"))

from leak import K, PROBES

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, visible_to

#: Queries an authorised user would actually ask, targeting documents they CAN read.
#:
#: The attack probes in `leak.py` deliberately target restricted material, so for most
#: principals they have zero readable answers — measuring recall on them produced empty
#: ideal sets and a meaningless 1.000. Quality has to be measured on queries that have a
#: right answer for the caller.
QUALITY_PROBES: tuple[str, ...] = (
    "deployment runbook roll back previous image",
    "on-call rotation handover monday",
    "service architecture api gateway redis postgres",
    "holiday allowance annual leave carry over",
    "expense policy receipts pre-approval",
    "security multi-factor authentication credentials",
    "incident reporting postmortem outage",
    "remote work three days per week",
    "onboarding checklist security training",
    "pipeline review late stage opportunities",
    "objection handling total cost of ownership",
    "brand guidelines primary logo",
    "interview process four stages feedback",
    "code of conduct integrity retaliation",
    "data retention seven years backups",
    "vendor integration mutual TLS webhook secret",
    "load test saturates requests per second",
    "technical debt legacy billing module",
    "territory assignments northern europe",
    "discount approval matrix director sign-off",
)
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, NaiveRetriever


def ideal_for(index: Index, principal, query: str, k: int) -> list[str]:
    """The best possible readable answer: rank the readable set, take top k.

    NOTE ON CIRCULARITY, because the first version of this file was circular.

    The enforced retriever computes exactly this, so comparing it against this ideal
    yields 1.000 by construction — the test restates the implementation. That is why the
    interesting comparison below is NAIVE vs IDEAL: it measures how often
    retrieve-then-filter fails to surface a readable document that pre-filtering would
    have found, because a restricted document consumed a top-k slot.

    The enforced column is retained as a regression check (it must stay at 1.000; if it
    ever drops, pre-filtering has a bug), not as evidence of improvement.
    """
    readable = {d.id for d in DOCUMENTS if d.readable_by(principal)}
    return [doc_id for doc_id, _ in index.score(query) if doc_id in readable][:k]


def main() -> None:
    index = Index()
    naive = NaiveRetriever(index)
    enforced = EnforcedRetriever(index)

    print(f"queries: {len(QUALITY_PROBES)} chosen to have readable answers, k={K}\n")
    print(
        f"{'principal':<18}{'readable':>9}{'ideal':>7}{'naive recall':>14}{'enforced recall':>17}"
    )
    print("-" * 66)

    rows = []
    for p in PRINCIPALS:
        naive_hits = 0
        enforced_hits = 0
        ideal_total = 0

        for query in QUALITY_PROBES:
            ideal = ideal_for(index, p, query, K)
            if not ideal:
                continue
            ideal_total += len(ideal)

            n_ids = {d.id for d in naive.search(p, query, k=K).documents}
            # Padding is excluded: a padded result did not rank, so counting it as a hit
            # would flatter the number by rewarding the very thing that dilutes results.
            e_ids = {r.document.id for r in enforced.search(p, query, k=K).relevant}

            naive_hits += len(n_ids & set(ideal))
            enforced_hits += len(e_ids & set(ideal))

        n_recall = naive_hits / ideal_total if ideal_total else 0.0
        e_recall = enforced_hits / ideal_total if ideal_total else 0.0
        rows.append((p, n_recall, e_recall, ideal_total))
        print(
            f"{p.name:<18}{len(visible_to(p)):>9}{ideal_total:>7}{n_recall:>14.3f}{e_recall:>17.3f}"
        )

    naive_avg = sum(r[1] for r in rows) / len(rows)
    enforced_avg = sum(r[2] for r in rows) / len(rows)
    delta = enforced_avg - naive_avg

    print()
    print(f"  mean recall against per-principal ideal:")
    print(f"    naive (retrieve then filter):  {naive_avg:.3f}")
    print(f"    enforced (filter then rank):   {enforced_avg:.3f}")
    print(f"    delta:                         {delta:+.3f}")
    print()
    print("  The meaningful comparison is NAIVE vs 1.000. Pre-filtering is the ideal by")
    print("  definition, so the enforced column is a regression check — if it leaves 1.000,")
    print("  pre-filtering has a bug. The naive shortfall is the real cost of")
    print("  retrieve-then-filter: a restricted document occupying a top-k slot that a")
    print("  readable document could have used.")

    THRESHOLD = -0.05
    out = Path(__file__).parent / "results" / "quality.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "k": K,
                "naive_mean_recall": round(naive_avg, 4),
                "enforced_mean_recall": round(enforced_avg, 4),
                "delta": round(delta, 4),
                "threshold": THRESHOLD,
                "queries": len(QUALITY_PROBES),
                "per_principal": [
                    {
                        "principal": p.id,
                        "readable": len(visible_to(p)),
                        "naive_recall": round(n, 4),
                        "enforced_recall": round(e, 4),
                    }
                    for p, n, e, _ in rows
                ],
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nraw results → {out}")

    if delta < THRESHOLD:
        print(f"\nBELOW THRESHOLD: recall fell {delta:+.3f}, limit is {THRESHOLD:+.3f}")
        sys.exit(1)
    print(f"\nwithin threshold ({delta:+.3f} vs {THRESHOLD:+.3f} limit)")


if __name__ == "__main__":
    main()
