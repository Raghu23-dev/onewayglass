"""Enforced retrieval: pre-filter, then pad to a stable count.

Two changes from `naive.py`, and the second is the one that matters.

1. FILTER BEFORE RANKING. The candidate set is restricted to what the caller may read
   before top-k is taken, so k results come back whenever k readable documents match. This
   removes most of the deficit.

2. PAD TO A STABLE COUNT. Pre-filtering alone is not enough. If only three readable
   documents match a query where seven matched globally, the caller still receives three,
   and an attacker comparing their count against a colleague's still learns something. So
   the response is padded to a fixed width with lower-ranked readable documents.

THE INVARIANT

    For any two principals issuing the same query, the observable result COUNT is
    identical. Only the content differs.

That is what makes it one-way glass: from outside, a blocked document and a nonexistent one
are indistinguishable.

WHAT PADDING COSTS, STATED PLAINLY

A padded result is a real, readable document that is less relevant than the ones above it.
The caller sees k results where fewer were genuinely relevant. That is a deliberate trade:
slightly diluted results in exchange for a count that carries no information. Criterion 5
measures whether the dilution is acceptable, and `padded` is exposed on each result so a
consumer can weight or hide them — the information is available to the authorised caller
without being observable in the count.
"""

from __future__ import annotations

from dataclasses import dataclass

from .corpus import Document, Principal
from .naive import Index, tokenise


@dataclass(frozen=True, slots=True)
class Result:
    document: Document
    score: float
    #: True when this document was added to reach the stable count rather than because it
    #: ranked. Exposed to the caller, never inferable from the count.
    padded: bool


@dataclass(frozen=True, slots=True)
class Answer:
    results: tuple[Result, ...]

    @property
    def result_count(self) -> int:
        """Observable count. Must be identical across principals for the same query."""
        return len(self.results)

    @property
    def relevant(self) -> tuple[Result, ...]:
        """Results that actually ranked, for a caller that wants to ignore padding."""
        return tuple(r for r in self.results if not r.padded)


class EnforcedRetriever:
    """Count-stable, permission-aware retrieval."""

    def __init__(
        self,
        index: Index | None = None,
        *,
        pad: bool = True,
        plausible_pad: bool = False,
    ) -> None:
        self.index = index or Index()
        self.pad = pad
        #: Choose filler that shares terms with the query rather than the lowest document id.
        #: An attempt at closing the relevance channel — measured in `bench/relevance/`, and the
        #: measurement is the point rather than the assumption that it works.
        self.plausible_pad = plausible_pad
        # Precomputed per-principal readable sets would be the production choice. Computed
        # per call here because the corpus is 35 documents and a stale cache is a security
        # bug rather than a performance one — a principal whose access was revoked must not
        # keep reading from a warm cache.
        self._by_id = {d.id: d for d in self.index.documents}

    def search(self, principal: Principal, query: str, k: int = 5) -> Answer:
        # 1. Restrict the candidate set BEFORE ranking. The caller's permissions are an
        #    input to retrieval, not a filter applied to its output.
        readable = [d for d in self.index.documents if d.readable_by(principal)]
        readable_ids = {d.id for d in readable}

        # 2. Rank within the readable set only. Scores from the global index are reused so
        #    ranking quality is unchanged; what changes is which documents are eligible.
        scored = [(doc_id, s) for doc_id, s in self.index.score(query) if doc_id in readable_ids]

        results = [
            Result(document=self._by_id[doc_id], score=score, padded=False)
            for doc_id, score in scored[:k]
        ]

        if not self.pad:
            return Answer(tuple(results))

        # 3. Pad to k with readable documents that did not rank for this query.
        #
        #    Ordered deterministically by document id rather than randomly. A random pad
        #    would differ between two requests for the same query and principal, which is
        #    itself a signal — and would make the property test flaky in a way that hides
        #    real failures.
        if len(results) < k:
            chosen = {r.document.id for r in results}
            candidates = [d for d in readable if d.id not in chosen]

            if self.plausible_pad:
                #    RELEVANCE-PLAUSIBLE FILLER. The default pad is ordered by document id,
                #    which is deterministic but topically arbitrary — so a caller who reads
                #    five results and sees none of them mention the query's subject knows they
                #    are all filler, and can count backwards to how many real matches they were
                #    denied. That is the relevance channel measured in `bench/relevance/`.
                #
                #    This orders filler by how many query terms it shares, so the filler at
                #    least looks like it is about the right subject. Document id remains the
                #    tie-breaker, because two documents with equal overlap must still be ordered
                #    deterministically — a pad that varies between identical requests is itself
                #    a signal.
                #
                #    Whether this actually defeats a reader is an open question, and the
                #    honest answer is measured rather than assumed.
                query_terms = set(tokenise(query))
                candidates.sort(
                    key=lambda d: (
                        -len(query_terms & set(tokenise(f"{d.title} {d.text}"))),
                        d.id,
                    )
                )
            else:
                candidates.sort(key=lambda d: d.id)

            for doc in candidates[: k - len(results)]:
                results.append(Result(document=doc, score=0.0, padded=True))

        return Answer(tuple(results))

    def max_stable_k(self, principal: Principal) -> int:
        """Largest k this principal can be served at a stable count.

        A principal who may read only 10 documents cannot be served 12 results without
        either repeating a document or revealing the ceiling. Callers requesting more than
        this get their readable total — which is itself a disclosure of how much they can
        see, but that is information about their OWN access, not about what is hidden.

        Recorded because it is a genuine limit of the padding approach rather than
        something to be quietly clamped.
        """
        return sum(1 for d in self.index.documents if d.readable_by(principal))
