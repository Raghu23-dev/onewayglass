"""The naive implementation: retrieve, then filter.

This is how permission-aware RAG is usually built, and it is the thing being measured. It
is not a straw man — it returns only documents the caller may read, so it passes the
obvious test. Nobody's confidential text is disclosed.

What it leaks is the SHAPE of what it withheld.

Retrieve top-k globally, drop what the caller cannot see, return the remainder. The
remainder is smaller than k, and *how much* smaller is a function of how many restricted
documents matched the query. That number is information about documents the caller cannot
read, and it is returned to them on every request.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

from .corpus import DOCUMENTS, Document, Principal

_WORD = re.compile(r"[a-z0-9][a-z0-9'-]*")

_STOP = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "by",
        "for",
        "from",
        "in",
        "is",
        "it",
        "of",
        "on",
        "or",
        "that",
        "the",
        "to",
        "was",
        "were",
        "with",
    }
)


def tokenise(text: str) -> list[str]:
    return [t for t in _WORD.findall(text.lower()) if t not in _STOP and len(t) > 1]


class Index:
    """BM25 over the whole corpus, permission-blind by construction.

    Permission-blindness is the point: this index is what a system builds when access
    control is treated as a filtering concern rather than a retrieval concern.
    """

    K1 = 1.2
    B = 0.75

    def __init__(self, documents: tuple[Document, ...] = DOCUMENTS) -> None:
        self.documents = documents
        self._tf: dict[str, Counter[str]] = {}
        self._len: dict[str, int] = {}
        self._df: Counter[str] = Counter()

        for d in documents:
            terms = tokenise(f"{d.title} {d.text}")
            self._tf[d.id] = Counter(terms)
            self._len[d.id] = len(terms)
            for term in set(terms):
                self._df[term] += 1

        self._avg_len = (sum(self._len.values()) / len(documents)) if documents else 0.0

    def score(self, query: str) -> list[tuple[str, float]]:
        n = len(self.documents)
        scores: dict[str, float] = {}
        for term in tokenise(query):
            df = self._df.get(term, 0)
            if df == 0:
                continue
            idf = math.log(1 + (n - df + 0.5) / (df + 0.5))
            for doc_id, tf_counter in self._tf.items():
                tf = tf_counter.get(term, 0)
                if tf == 0:
                    continue
                norm = self._len[doc_id] / self._avg_len if self._avg_len else 1.0
                scores[doc_id] = scores.get(doc_id, 0.0) + idf * (
                    (tf * (self.K1 + 1)) / (tf + self.K1 * (1 - self.B + self.B * norm))
                )
        return sorted(scores.items(), key=lambda kv: (-kv[1], kv[0]))


@dataclass(frozen=True, slots=True)
class Answer:
    """What the caller receives."""

    documents: tuple[Document, ...]
    #: What the caller can observe. Every field here is a potential side channel.
    result_count: int
    #: Some systems helpfully report this. It is a direct disclosure.
    filtered_count: int | None = None


class NaiveRetriever:
    """Retrieve globally, then filter by permission.

    Two variants, because both exist in the wild:

    - `report_filtered=True` tells the caller how many results were withheld. Some
      systems do this deliberately, believing "3 results hidden" is more honest than
      silently returning fewer. It is a direct disclosure of restricted-document counts.
    - `report_filtered=False` withholds that number. This is the common case, and the one
      worth measuring — because the result count alone still leaks.
    """

    def __init__(self, index: Index | None = None, *, report_filtered: bool = False) -> None:
        self.index = index or Index()
        self.report_filtered = report_filtered

    def search(self, principal: Principal, query: str, k: int = 5) -> Answer:
        ranked = self.index.score(query)[:k]
        kept: list[Document] = []
        dropped = 0

        for doc_id, _ in ranked:
            doc = next(d for d in self.index.documents if d.id == doc_id)
            if doc.readable_by(principal):
                kept.append(doc)
            else:
                dropped += 1

        return Answer(
            documents=tuple(kept),
            result_count=len(kept),
            filtered_count=dropped if self.report_filtered else None,
        )
