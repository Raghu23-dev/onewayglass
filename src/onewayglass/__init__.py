"""onewayglass — retrieval whose result count cannot tell you what it hid.

Filtering permissioned documents *after* retrieval leaks: the gap between the requested count and
the returned count is a function of how many restricted documents matched, which is a fact about
documents the caller may not read.

This package filters by clearance *before* ranking, then pads every answer to a fixed width, so the
observable count carries no information.

    from onewayglass import EnforcedRetriever, Index, PRINCIPALS_BY_ID

    retriever = EnforcedRetriever(Index())
    answer = retriever.search(PRINCIPALS_BY_ID["u_ic_eng"], "redundancy planning", k=5)
    answer.result_count      # identical for every principal
    answer.relevant          # only the results that genuinely ranked

WHAT THIS DOES NOT DO, stated here because it is the most important thing about it:
count-stability defeats an observer of the *count* — a colleague comparing notes, a proxy
log. It does not defeat the recipient of the results, because padding shares no terms with
the query and is therefore obvious to whoever reads it. See docs/05-results.md.
"""

from .corpus import (
    DOCUMENTS,
    DOCUMENTS_BY_ID,
    PRINCIPALS,
    PRINCIPALS_BY_ID,
    Document,
    Level,
    Principal,
    access_summary,
    visible_to,
)
from .enforced import Answer as EnforcedAnswer
from .enforced import EnforcedRetriever, Result
from .naive import Answer as NaiveAnswer
from .naive import Index, NaiveRetriever, tokenise

__all__ = [
    "DOCUMENTS",
    "DOCUMENTS_BY_ID",
    "PRINCIPALS",
    "PRINCIPALS_BY_ID",
    "Document",
    "EnforcedAnswer",
    "EnforcedRetriever",
    "Index",
    "Level",
    "NaiveAnswer",
    "NaiveRetriever",
    "Principal",
    "Result",
    "access_summary",
    "tokenise",
    "visible_to",
]
