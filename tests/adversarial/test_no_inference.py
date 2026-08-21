"""ADVERSARIAL: try to learn what you may not read.

Every test attacks the invariant: for any two principals issuing the same query, the
observable result COUNT is identical, and no unreadable document is ever returned.

The baseline measured 17 restricted documents revealed and inference exact on 15/15 probes.
These tests exist so that cannot come back.
"""

from __future__ import annotations

import itertools

import pytest

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, PRINCIPALS_BY_ID, Level, visible_to
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, NaiveRetriever

K = 5

QUERIES = (
    "compensation bands senior engineers",
    "redundancy planning fiscal year",
    "acquisition discussions acquirers",
    "board minutes funding round",
    "grievance case notes",
    "runway analysis burn",
    "holiday allowance leave",
    "deployment runbook",
    "security audit findings",
    "commission structure quota",
)


@pytest.fixture(scope="module")
def index() -> Index:
    return Index()


@pytest.fixture(scope="module")
def enforced(index: Index) -> EnforcedRetriever:
    return EnforcedRetriever(index)


class TestNoContentLeak:
    """Criterion 1. The property everyone checks — asserted exhaustively."""

    def test_no_unreadable_document_is_ever_returned(self, enforced: EnforcedRetriever) -> None:
        for p, query in itertools.product(PRINCIPALS, QUERIES):
            for r in enforced.search(p, query, k=K).results:
                assert r.document.readable_by(p), (
                    f"{p.id} received {r.document.id} which they may not read"
                )

    def test_padding_never_introduces_an_unreadable_document(
        self, enforced: EnforcedRetriever
    ) -> None:
        """Padding is the most likely place to accidentally leak: it adds documents that
        did not rank, so a bug here would be invisible in relevance testing."""
        for p, query in itertools.product(PRINCIPALS, QUERIES):
            for r in enforced.search(p, query, k=K).results:
                if r.padded:
                    assert r.document.readable_by(p)


class TestCountStability:
    """Criterion 3. The novel property."""

    def test_every_principal_observes_the_same_count(self, enforced: EnforcedRetriever) -> None:
        for query in QUERIES:
            counts = {p.id: enforced.search(p, query, k=K).result_count for p in PRINCIPALS}
            assert len(set(counts.values())) == 1, (
                f"count differs by principal on {query!r}: {counts}"
            )

    def test_count_equals_k_regardless_of_what_was_withheld(
        self, enforced: EnforcedRetriever
    ) -> None:
        for p, query in itertools.product(PRINCIPALS, QUERIES):
            assert enforced.search(p, query, k=K).result_count == K

    def test_naive_count_does_vary_by_principal(self, index: Index) -> None:
        """Control: confirms the test would catch a leak if one existed.

        A stability test that passes against a leaky implementation proves nothing.
        """
        naive = NaiveRetriever(index)
        varied = 0
        for query in QUERIES:
            counts = {naive.search(p, query, k=K).result_count for p in PRINCIPALS}
            if len(counts) > 1:
                varied += 1
        assert varied > 0, "the naive path did not vary — the control is broken"


class TestCountInference:
    """Criterion 2. Replay the baseline attack."""

    def test_deficit_carries_no_information(self, enforced: EnforcedRetriever) -> None:
        """An attacker computes matches - returned. It must always be zero."""
        attacker = PRINCIPALS_BY_ID["u_ic_eng"]
        for query in QUERIES:
            answer = enforced.search(attacker, query, k=K)
            assert K - answer.result_count == 0

    def test_deficit_does_not_track_permission(self, enforced: EnforcedRetriever) -> None:
        """The baseline's deficit fell monotonically as permission rose — a clean oracle.

        Here every principal must show the same total, so the deficit reveals nothing about
        how much a principal can see.
        """
        totals = {}
        for p in PRINCIPALS:
            totals[p.id] = sum(K - enforced.search(p, q, k=K).result_count for q in QUERIES)
        assert len(set(totals.values())) == 1, f"deficit varies by principal: {totals}"


class TestExistenceProbing:
    """Criterion 4."""

    def test_a_targeted_query_reveals_nothing_about_restricted_documents(
        self, enforced: EnforcedRetriever
    ) -> None:
        attacker = PRINCIPALS_BY_ID["u_ic_eng"]
        # Queries aimed squarely at documents this principal cannot read.
        for query in (
            "compensation bands senior engineers",
            "redundancy planning fiscal year",
            "acquisition discussions acquirers",
            "executive succession candidates",
        ):
            answer = enforced.search(attacker, query, k=K)
            assert answer.result_count == K
            # Nothing returned may be restricted, and the count is uninformative, so the
            # only remaining channel would be content — checked here too.
            for r in answer.results:
                assert r.document.readable_by(attacker)


class TestPaddingProperties:
    def test_padding_is_deterministic(self, enforced: EnforcedRetriever) -> None:
        """A pad that varies between identical requests is itself a signal."""
        p = PRINCIPALS_BY_ID["u_ic_people"]
        first = [r.document.id for r in enforced.search(p, "acquisition discussions", k=K).results]
        second = [r.document.id for r in enforced.search(p, "acquisition discussions", k=K).results]
        assert first == second

    def test_padded_results_are_flagged_for_the_caller(self, enforced: EnforcedRetriever) -> None:
        """An authorised caller may distinguish padding; an observer of the count may not."""
        p = PRINCIPALS_BY_ID["u_ic_people"]
        answer = enforced.search(p, "acquisition discussions acquirers", k=K)
        assert any(r.padded for r in answer.results)
        assert len(answer.relevant) < answer.result_count

    def test_no_document_appears_twice(self, enforced: EnforcedRetriever) -> None:
        """Padding must not repeat a ranked result to reach the count."""
        for p, query in itertools.product(PRINCIPALS, QUERIES):
            ids = [r.document.id for r in enforced.search(p, query, k=K).results]
            assert len(ids) == len(set(ids))


class TestLimits:
    def test_max_stable_k_reports_the_real_ceiling(self, enforced: EnforcedRetriever) -> None:
        """A principal cannot be served more results than they can read."""
        for p in PRINCIPALS:
            assert enforced.max_stable_k(p) == len(visible_to(p))

    def test_requesting_more_than_readable_cannot_pad_to_k(
        self, enforced: EnforcedRetriever
    ) -> None:
        """Known limit, asserted rather than hidden.

        A principal who may read 10 documents cannot be served 12 at a stable count. The
        response is capped at their readable total, which discloses their own ceiling — not
        what is hidden from them.
        """
        p = PRINCIPALS_BY_ID["u_ic_people"]
        readable = len(visible_to(p))
        answer = enforced.search(p, "holiday allowance", k=readable + 5)
        assert answer.result_count == readable


class TestAccessModelIsSane:
    """The corpus is the test fixture. A wrong fixture invalidates everything above."""

    def test_seniority_widens_access_monotonically(self) -> None:
        """Caught a real bug: the CEO originally read fewer documents than an engineer."""
        eng = {
            level: len(
                visible_to(
                    next(
                        p for p in PRINCIPALS if p.department == "engineering" and p.level == level
                    )
                )
            )
            for level in (Level.IC, Level.LEAD, Level.DIRECTOR)
        }
        assert eng[Level.IC] < eng[Level.LEAD] < eng[Level.DIRECTOR]

    def test_exec_reads_everything(self) -> None:
        assert len(visible_to(PRINCIPALS_BY_ID["u_exec"])) == len(DOCUMENTS)

    def test_an_extra_grant_widens_access_by_exactly_one(self) -> None:
        contractor = PRINCIPALS_BY_ID["u_contractor"]
        visible = {d.id for d in visible_to(contractor)}
        company_wide = {d.id for d in DOCUMENTS if d.company_wide}
        assert visible == company_wide | {"doc_eng_04"}
