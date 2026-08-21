"""Tests for the deployed instance.

The property being tested is not "the endpoints return 200". It is that count-stability
survives an HTTP boundary and per-principal authentication — because a guarantee that holds
in-process and breaks behind a web framework is not a guarantee.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "api"))

from index import TOKENS, _index, app  # noqa: E402

from onewayglass.corpus import DOCUMENTS_BY_ID, PRINCIPALS, PRINCIPALS_BY_ID, visible_to

client = TestClient(app)

PROBES = (
    "compensation bands for senior engineers",
    "redundancy planning next fiscal year",
    "acquisition discussions potential acquirers",
    "security audit findings severity",
    "holiday allowance annual leave",
)


def auth(pid: str) -> dict[str, str]:
    return {"Authorization": f"Bearer demo-{pid}"}


class TestCountStabilityOverHTTP:
    """Criterion 3, at the transport boundary."""

    @pytest.mark.parametrize("query", PROBES)
    def test_count_identical_across_every_principal(self, query: str) -> None:
        counts = {
            p.id: client.get("/search", params={"q": query, "k": 5}, headers=auth(p.id)).json()[
                "result_count"
            ]
            for p in PRINCIPALS
        }
        assert len(set(counts.values())) == 1, f"count varies by principal: {counts}"

    def test_naive_endpoint_does_vary(self) -> None:
        """A control. If the naive path were also stable, the stable result would prove nothing.

        A test that only confirms the fix works cannot detect a harness measuring nothing.
        """
        counts = {
            p.id: client.get(
                "/search/naive",
                params={"q": "compensation bands redundancy acquisition", "k": 5},
                headers=auth(p.id),
            ).json()["result_count"]
            for p in PRINCIPALS
        }
        assert len(set(counts.values())) > 1, (
            "the naive endpoint must leak, or the control is broken"
        )


class TestNoContentLeak:
    """Criterion 1, at the transport boundary."""

    @pytest.mark.parametrize("query", PROBES)
    def test_no_unreadable_document_is_ever_returned(self, query: str) -> None:
        for p in PRINCIPALS:
            for route in ("/search", "/search/naive"):
                body = client.get(route, params={"q": query, "k": 5}, headers=auth(p.id)).json()
                for r in body["results"]:
                    doc = DOCUMENTS_BY_ID[r["id"]]
                    assert doc.readable_by(p), f"{route} leaked {r['id']} to {p.id}"


class TestAttackerModelMatchesTheBenchmark:
    """The deployed leak figure must not contradict `bench/baseline/leak.py`.

    An endpoint reporting `k - returned` would overstate the leak it demonstrates, using the
    exact over-counting model the benchmark documents as wrong.
    """

    @pytest.mark.parametrize("query", PROBES)
    def test_inferable_never_exceeds_available_matches(self, query: str) -> None:
        available = min(5, len(_index.score(query)))
        for p in PRINCIPALS:
            body = client.get(
                "/search/naive", params={"q": query, "k": 5}, headers=auth(p.id)
            ).json()
            assert body["inferable_hidden_matches"] <= available
            assert body["matches_available"] == available

    def test_inference_is_exact_for_the_attacker(self) -> None:
        """The reported figure must equal the true count of restricted matches."""
        query = "redundancy planning next fiscal year"
        p = PRINCIPALS_BY_ID["u_ic_eng"]
        top = _index.score(query)[:5]
        actual_hidden = sum(1 for i, _ in top if not DOCUMENTS_BY_ID[i].readable_by(p))
        body = client.get("/search/naive", params={"q": query, "k": 5}, headers=auth(p.id)).json()
        assert body["inferable_hidden_matches"] == actual_hidden

    def test_ceo_can_infer_nothing(self) -> None:
        for query in PROBES:
            body = client.get(
                "/search/naive", params={"q": query, "k": 5}, headers=auth("u_exec")
            ).json()
            assert body["inferable_hidden_matches"] == 0


class TestAuth:
    def test_no_token_is_rejected(self) -> None:
        assert client.get("/search", params={"q": "x"}).status_code == 401

    def test_unknown_token_is_rejected(self) -> None:
        assert (
            client.get(
                "/search", params={"q": "x"}, headers={"Authorization": "Bearer nope"}
            ).status_code
            == 401
        )

    def test_malformed_and_unknown_are_indistinguishable(self) -> None:
        """A distinct error for 'no such token' would be an enumeration oracle.

        Building one into a project about inference channels would be careless.
        """
        a = client.get("/search", params={"q": "x"}, headers={"Authorization": "Bearer nope"})
        b = client.get("/search", params={"q": "x"}, headers={"Authorization": "Bearer demo-u_x"})
        assert a.status_code == b.status_code == 401
        assert a.json() == b.json()

    def test_every_principal_has_exactly_one_token(self) -> None:
        assert sorted(TOKENS.values()) == sorted(p.id for p in PRINCIPALS)

    def test_whoami_reports_only_own_access(self) -> None:
        body = client.get("/whoami", headers=auth("u_ic_eng")).json()
        assert body["readable_documents"] == len(visible_to(PRINCIPALS_BY_ID["u_ic_eng"]))
        assert "hidden" not in str(body).lower()


class TestValidation:
    @pytest.mark.parametrize("k", [0, -1, 11, 999])
    def test_k_out_of_range_is_rejected(self, k: int) -> None:
        r = client.get("/search", params={"q": "x", "k": k}, headers=auth("u_exec"))
        assert r.status_code == 400

    @pytest.mark.parametrize("q", ["", "   "])
    def test_empty_query_is_rejected(self, q: str) -> None:
        assert client.get("/search", params={"q": q}, headers=auth("u_exec")).status_code == 400


class TestHealth:
    def test_health_asserts_the_invariant(self) -> None:
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["count_stable"] is True
        assert body["content_violations"] == 0
        assert body["corpus_documents"] == len(DOCUMENTS_BY_ID)

    def test_health_would_report_degraded_if_the_invariant_broke(self) -> None:
        """A health check that cannot fail is decoration.

        Monkeypatches the access rule so one principal sees less, and asserts the check notices.
        """
        import index as api

        original = api._enforced.search

        def leaky(principal, query, k=5):  # noqa: ANN001, ANN202
            answer = original(principal, query, k=k)
            if principal.id == "u_ic_eng":
                return type(answer)(answer.results[:-1])
            return answer

        api._enforced.search = leaky  # type: ignore[method-assign]
        try:
            body = client.get("/health").json()
            assert body["status"] == "degraded"
            assert body["count_stable"] is False
        finally:
            api._enforced.search = original  # type: ignore[method-assign]


class TestAttackEndpoint:
    def test_needs_no_token_and_returns_no_text(self) -> None:
        body = client.get("/attack", params={"q": "compensation bands redundancy"}).json()
        assert "text" not in str(body), "the unauthenticated endpoint must return counts only"

    def test_shows_naive_varying_and_enforced_stable(self) -> None:
        body = client.get(
            "/attack", params={"q": "compensation bands redundancy acquisition"}
        ).json()
        assert len(body["naive_distinct_counts"]) > 1
        assert body["enforced_distinct_counts"] == [5]
