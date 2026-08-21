"""CORRECTNESS: the enforced retriever does its actual job.

The adversarial suite proves what an attacker CANNOT learn. That is the interesting half,
and it is also why this file was missing for so long: `tests/correctness/` held only a
README, so the `pytest tests/correctness` CI step exited 5 ("no tests ran") — a gate that
passed by testing nothing.

So these are the unglamorous properties. A retriever that leaks nothing because it returns
nothing useful would satisfy every adversarial test in the repo and be worthless. These
assert it still retrieves.
"""

from __future__ import annotations

import pytest

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, PRINCIPALS_BY_ID, visible_to
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index

K = 5


@pytest.fixture(scope="module")
def index() -> Index:
    return Index()


@pytest.fixture(scope="module")
def enforced(index: Index) -> EnforcedRetriever:
    return EnforcedRetriever(index)


class TestItActuallyRetrieves:
    """The property a count-stability test cannot see: relevance."""

    def test_a_principal_gets_their_own_relevant_document_first(
        self, enforced: EnforcedRetriever
    ) -> None:
        """The CEO reads everything, so the top hit must be a genuine match, not filler."""
        answer = enforced.search(PRINCIPALS_BY_ID["u_exec"], "board minutes funding round", k=K)
        assert answer.relevant, "an all-access principal must get at least one real match"
        assert not answer.results[0].padded, "the best result must not be padding"
        assert answer.results[0].score > 0.0

    def test_ranking_is_by_descending_score(self, enforced: EnforcedRetriever) -> None:
        answer = enforced.search(PRINCIPALS_BY_ID["u_exec"], "security audit findings", k=K)
        real = [r.score for r in answer.results if not r.padded]
        assert real == sorted(real, reverse=True)

    def test_padding_always_sorts_below_real_matches(self, enforced: EnforcedRetriever) -> None:
        """Filler must never displace a document the caller may read and asked for."""
        for principal in PRINCIPALS:
            answer = enforced.search(principal, "compensation bands senior engineers", k=K)
            seen_padding = False
            for r in answer.results:
                if r.padded:
                    seen_padding = True
                elif seen_padding:
                    pytest.fail(f"{principal.id}: a real match ranked below padding")

    def test_every_returned_document_is_readable_and_real(
        self, enforced: EnforcedRetriever
    ) -> None:
        """Results must be documents from the corpus, not fabricated placeholders."""
        by_id = {d.id: d for d in DOCUMENTS}
        for principal in PRINCIPALS:
            answer = enforced.search(principal, "runway analysis burn", k=K)
            for r in answer.results:
                assert r.document.id in by_id, "returned a document not in the corpus"
                assert r.document.readable_by(principal)
                assert r.document.title
                assert r.document.text


class TestKIsHonoured:
    @pytest.mark.parametrize("k", [1, 2, 3, 5, 10])
    def test_result_count_equals_k_for_every_principal(
        self, enforced: EnforcedRetriever, k: int
    ) -> None:
        for principal in PRINCIPALS:
            if k > enforced.max_stable_k(principal):
                continue
            answer = enforced.search(principal, "deployment runbook", k=k)
            assert answer.result_count == k, f"{principal.id} at k={k}"

    def test_k_above_the_stable_ceiling_degrades_to_readable_total(
        self, enforced: EnforcedRetriever
    ) -> None:
        """Documented behaviour, asserted so it cannot change silently.

        A principal reading 10 documents cannot be served 12 without repeating one. They
        get their readable total instead — a disclosure about their OWN access, not about
        what is hidden from them.
        """
        principal = PRINCIPALS_BY_ID["u_ic_people"]
        readable = len(visible_to(principal))
        answer = enforced.search(principal, "holiday allowance leave", k=readable + 5)
        assert answer.result_count == readable

    def test_no_document_is_returned_twice(self, enforced: EnforcedRetriever) -> None:
        for principal in PRINCIPALS:
            answer = enforced.search(principal, "grievance case notes", k=K)
            ids = [r.document.id for r in answer.results]
            assert len(ids) == len(set(ids))


class TestDeterminism:
    """Same principal, same query, same answer — or the count varies across retries."""

    def test_repeated_identical_searches_agree_exactly(self, enforced: EnforcedRetriever) -> None:
        principal = PRINCIPALS_BY_ID["u_lead_eng"]
        first = enforced.search(principal, "acquisition discussions acquirers", k=K)
        for _ in range(5):
            again = enforced.search(principal, "acquisition discussions acquirers", k=K)
            assert [r.document.id for r in again.results] == [r.document.id for r in first.results]


class TestEdgeCasesReturnStableCounts:
    """The count must not become an oracle at the boundaries."""

    def test_a_query_matching_nothing_still_returns_k(self, enforced: EnforcedRetriever) -> None:
        """Zero real matches is the case where padding carries the whole property."""
        counts = {
            p.id: enforced.search(p, "xylophone bassoon marzipan quokka", k=K).result_count
            for p in PRINCIPALS
        }
        assert set(counts.values()) == {K}, counts

    def test_an_empty_query_returns_a_stable_count(self, enforced: EnforcedRetriever) -> None:
        counts = {p.id: enforced.search(p, "", k=K).result_count for p in PRINCIPALS}
        assert len(set(counts.values())) == 1, counts

    def test_a_query_matching_everything_returns_k(self, enforced: EnforcedRetriever) -> None:
        counts = {p.id: enforced.search(p, "the and of a to", k=K).result_count for p in PRINCIPALS}
        assert set(counts.values()) == {K}, counts


class TestPaddingIsDisclosedNotHidden:
    """`padded` is deliberately exposed, and that is a published limitation.

    docs/05-results.md records that the flag hands the true match count to the caller. It
    stays exposed because a caller silently fed filler as if it ranked is worse. Asserted
    here so the disclosure cannot be quietly dropped to make a metric look better.
    """

    def test_padded_results_are_flagged(self, enforced: EnforcedRetriever) -> None:
        answer = enforced.search(PRINCIPALS_BY_ID["u_ic_eng"], "board minutes funding", k=K)
        padded = [r for r in answer.results if r.padded]
        assert padded, "this principal should need padding for this query"
        assert all(r.score == 0.0 for r in padded), "padding must not claim a relevance score"

    def test_relevant_excludes_padding(self, enforced: EnforcedRetriever) -> None:
        answer = enforced.search(PRINCIPALS_BY_ID["u_ic_eng"], "board minutes funding", k=K)
        assert len(answer.relevant) < answer.result_count
        assert all(not r.padded for r in answer.relevant)
