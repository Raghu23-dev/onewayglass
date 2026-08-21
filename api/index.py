"""Live multi-tenant instance of onewayglass.

WHY THIS EXISTS

A benchmark in a repository proves the code does what the README says. It does not prove the
property survives contact with an HTTP boundary, authentication, or a stranger who did not
write the tests. So this deploys the same two retrievers behind per-principal bearer tokens
and lets anyone run the attack themselves.

The demo is adversarial by design: the naive endpoint is deployed alongside the enforced one,
unfixed, so a visitor can compare counts across two principals and watch the leak happen
rather than take a table's word for it.

WHAT IS AND IS NOT A SECRET HERE

The corpus is synthetic fiction and the tokens are printed in the response body of `/`. There
is nothing to protect. Tokens exist to demonstrate that count-stability holds across
*authenticated identities* — the property is about what different callers can observe, so a
single anonymous endpoint could not demonstrate it at all.

Nothing here reads a real credential, an environment secret or a database.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from collections import deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from onewayglass.corpus import DOCUMENTS, PRINCIPALS, PRINCIPALS_BY_ID, Principal, visible_to
from onewayglass.enforced import EnforcedRetriever
from onewayglass.naive import Index, NaiveRetriever

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
log = logging.getLogger("onewayglass")

VERSION = "0.2.1"
K_MAX = 10

# Built once at cold start. The index is immutable and shared; the readable set is still
# computed per request inside the retriever, because a cached readable set that outlives a
# revocation is a security bug.
_index = Index()
_enforced = EnforcedRetriever(_index)
_naive = NaiveRetriever(_index)

#: Demo tokens. Deliberately guessable and published — see the module docstring. A real
#: deployment would resolve a principal from a verified JWT; the retrieval property does not
#: depend on how identity is established, only that it is established before ranking.
TOKENS: dict[str, str] = {f"demo-{p.id}": p.id for p in PRINCIPALS}

#: Per-token sliding window. In-memory, so it resets on cold start and is per-instance — stated
#: rather than described as rate limiting, because on a serverless platform that is what it is.
_RATE_WINDOW_S = 60
_RATE_MAX = 120
_hits: dict[str, deque[float]] = {}


def _rate_limited(key: str) -> bool:
    now = time.time()
    window = _hits.setdefault(key, deque())
    while window and now - window[0] > _RATE_WINDOW_S:
        window.popleft()
    if len(window) >= _RATE_MAX:
        return True
    window.append(now)
    return False


def _inferable_hidden(query: str, k: int, returned: int) -> int:
    """What an attacker can infer about restricted matches from the count alone.

    Calibrated against how many documents match AT ALL, not against k. `k - returned`
    over-counts whenever a query simply matches few documents — the same mistake
    `bench/baseline/leak.py` documents making, where it scored 0/15 on inference accuracy and
    made a real vulnerability look unexploitable.

    A live endpoint reporting the over-counting figure would contradict its own benchmark, and
    would overstate the leak it is demonstrating. A real attacker calibrates by probing with a
    query they know is unrestricted, or by noticing the same query returns different counts for
    different colleagues.
    """
    return max(0, min(k, len(_index.score(query))) - returned)


def _principal(authorization: str | None) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401,
            detail="Bearer token required. GET / lists the demo tokens.",
        )
    token = authorization.split(" ", 1)[1].strip()
    pid = TOKENS.get(token)
    if pid is None:
        # Deliberately does not say whether the token was malformed or simply unknown. A
        # 'no such token' distinct from 'wrong token' is an enumeration oracle, and building
        # one into a project about inference channels would be careless.
        raise HTTPException(status_code=401, detail="Unknown token.")
    return PRINCIPALS_BY_ID[pid]


app = FastAPI(
    title="onewayglass",
    version=VERSION,
    description="Retrieval that cannot tell you what it hid.",
    docs_url="/docs",
)


@app.middleware("http")
async def guard(request: Request, call_next: Any) -> Any:
    """Rate limit, log, and never leak a stack trace.

    An unhandled exception whose message differs by principal would be its own side channel,
    so failures collapse to one opaque response.
    """
    start = time.perf_counter()
    key = request.headers.get("authorization", request.client.host if request.client else "-")

    if _rate_limited(key):
        log.warning("rate limited")
        return JSONResponse(
            {"error": "Rate limit exceeded", "limit": f"{_RATE_MAX}/{_RATE_WINDOW_S}s"},
            status_code=429,
        )

    try:
        response = await call_next(request)
    except HTTPException:
        raise
    except Exception:
        log.exception("unhandled")
        return JSONResponse({"error": "Internal error"}, status_code=500)

    elapsed_ms = (time.perf_counter() - start) * 1000
    log.info(
        "%s %s -> %s in %.2fms",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
    )
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"
    response.headers["X-Onewayglass-Version"] = VERSION
    return response


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness plus the two invariants worth asserting at runtime.

    A health check that only returns 200 tells you the process is up. These two say the
    thing the service exists to guarantee is still true on this instance.
    """
    probe = "compensation bands redundancy acquisition"
    counts = {
        p.id: _enforced.search(p, probe, k=5).result_count
        for p in PRINCIPALS
        if _enforced.max_stable_k(p) >= 5
    }
    stable = len(set(counts.values())) == 1

    leaks = [
        d.id
        for p in PRINCIPALS
        for r in _enforced.search(p, probe, k=5).results
        if not (d := r.document).readable_by(p)
    ]

    ok = stable and not leaks
    return {
        "status": "ok" if ok else "degraded",
        "version": VERSION,
        "corpus_documents": len(DOCUMENTS),
        "principals": len(PRINCIPALS),
        "count_stable": stable,
        "observed_counts": counts,
        "content_violations": len(leaks),
        "commit": os.environ.get("VERCEL_GIT_COMMIT_SHA", "local")[:7],
    }


@app.get("/whoami")
def whoami(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    """What this token can see.

    Reports the principal's own readable total — information about their own access, which
    they are entitled to. It is not information about what is hidden from them.
    """
    p = _principal(authorization)
    return {
        "principal": p.id,
        "name": p.name,
        "department": p.department,
        "level": p.level.name,
        "readable_documents": len(visible_to(p)),
        "corpus_documents": len(DOCUMENTS),
        "max_stable_k": _enforced.max_stable_k(p),
    }


@app.get("/search")
def search(
    q: str,
    k: int = 5,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """The enforced path. Count is identical for every principal on the same query."""
    p = _principal(authorization)
    if not q.strip():
        raise HTTPException(status_code=400, detail="q must not be empty")
    if not 1 <= k <= K_MAX:
        raise HTTPException(status_code=400, detail=f"k must be between 1 and {K_MAX}")

    answer = _enforced.search(p, q, k=k)
    ceiling = _enforced.max_stable_k(p)
    return {
        "principal": p.id,
        "query": q,
        "k": k,
        "result_count": answer.result_count,
        # Stated per response so a caller does not have to infer why a count is short.
        "count_stable": answer.result_count == k,
        "count_stable_note": (
            None
            if answer.result_count == k
            else f"This principal may read {ceiling} documents, fewer than k={k}. "
            "The count reveals their own ceiling, not what is hidden from them."
        ),
        "results": [
            {
                "id": r.document.id,
                "title": r.document.title,
                "text": r.document.text,
                "score": round(r.score, 4),
                "padded": r.padded,
            }
            for r in answer.results
        ],
    }


@app.get("/search/naive")
def search_naive(
    q: str,
    k: int = 5,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    """The leaking path, deployed unfixed and on purpose.

    Never returns an unreadable document — that is what makes it pass review. Compare
    `result_count` across two tokens on the same query and the deficit is the leak.
    """
    p = _principal(authorization)
    if not q.strip():
        raise HTTPException(status_code=400, detail="q must not be empty")
    if not 1 <= k <= K_MAX:
        raise HTTPException(status_code=400, detail=f"k must be between 1 and {K_MAX}")

    answer = _naive.search(p, q, k=k)
    return {
        "principal": p.id,
        "query": q,
        "k": k,
        "result_count": answer.result_count,
        "inferable_hidden_matches": _inferable_hidden(q, k, answer.result_count),
        "matches_available": min(k, len(_index.score(q))),
        "leak_note": (
            "No unreadable document was returned. But matches_available - result_count is the "
            "number of restricted documents that matched, which is a fact about documents this "
            "caller cannot read. Compare against another token to see it."
        ),
        "results": [{"id": d.id, "title": d.title, "text": d.text} for d in answer.documents],
    }


@app.get("/attack")
def attack(q: str = "compensation bands redundancy acquisition", k: int = 5) -> dict[str, Any]:
    """Run the attack across every principal at once. No token needed.

    Unauthenticated because it discloses nothing: it reports COUNTS for a corpus of synthetic
    fiction, never document text. It is the whole result in one request.
    """
    if not q.strip():
        raise HTTPException(status_code=400, detail="q must not be empty")
    if not 1 <= k <= K_MAX:
        raise HTTPException(status_code=400, detail=f"k must be between 1 and {K_MAX}")

    # Rows are heterogeneous (str and int values), so an untyped literal infers
    # dict[str, object] and `PRINCIPALS_BY_ID[r["principal"]]` below becomes an invalid
    # index. Keeping the principal id in a parallel list types cleanly and avoids casting a
    # value back to the type it already had.
    rows: list[dict[str, Any]] = []
    principal_ids: list[str] = []
    for p in PRINCIPALS:
        n = _naive.search(p, q, k=k)
        e = _enforced.search(p, q, k=k)
        principal_ids.append(p.id)
        rows.append(
            {
                "principal": p.id,
                "name": p.name,
                "readable_documents": len(visible_to(p)),
                "naive_count": n.result_count,
                "naive_inferable_hidden": _inferable_hidden(q, k, n.result_count),
                "enforced_count": e.result_count,
            }
        )

    naive_counts = {r["naive_count"] for r in rows}
    # Only principals who can reach k are comparable; one who cannot is disclosing their own
    # ceiling rather than leaking, and including them would understate stability.
    comparable = [
        row
        for row, pid in zip(rows, principal_ids, strict=True)
        if _enforced.max_stable_k(PRINCIPALS_BY_ID[pid]) >= k
    ]
    enforced_counts = {r["enforced_count"] for r in comparable}

    return {
        "query": q,
        "k": k,
        "rows": rows,
        "naive_distinct_counts": sorted(naive_counts),
        "enforced_distinct_counts": sorted(enforced_counts),
        "verdict": (
            "The naive counts differ between principals, so the count is a readout of what is "
            "hidden. The enforced counts are identical, so it is not."
            if len(naive_counts) > 1 and len(enforced_counts) == 1
            else "Try a query that matches restricted material, e.g. redundancy or acquisition."
        ),
        "excluded_from_stability_check": [r["principal"] for r in rows if r not in comparable],
    }


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    rows = "\n".join(
        f"<tr><td><code>demo-{p.id}</code></td><td>{p.name}</td>"
        f"<td>{p.department} / {p.level.name}</td><td>{len(visible_to(p))} of {len(DOCUMENTS)}</td></tr>"
        for p in PRINCIPALS
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>onewayglass — retrieval that cannot tell you what it hid</title>
<style>
 :root {{ color-scheme: dark }}
 body {{ background:#0b0d10; color:#e7e9ee; font:16px/1.65 ui-monospace,SFMono-Regular,Menlo,monospace;
        margin:0; padding:2.5rem 1.25rem }}
 main {{ max-width:62rem; margin:0 auto }}
 h1 {{ font-size:1.5rem; margin:0 0 .25rem }}
 h2 {{ font-size:1.05rem; margin:2.25rem 0 .6rem; color:#8fb6ff }}
 p.sub {{ color:#788092; margin:0 0 2rem }}
 table {{ border-collapse:collapse; width:100%; margin:.5rem 0 1rem; font-size:.875rem }}
 th,td {{ text-align:left; padding:.4rem .7rem; border-bottom:1px solid #1c212b }}
 th {{ color:#788092; font-weight:400 }}
 code {{ background:#151a21; padding:.1rem .35rem; border-radius:3px; font-size:.875em }}
 pre {{ background:#151a21; padding:.85rem 1rem; border-radius:6px; overflow-x:auto;
        font-size:.8125rem; border:1px solid #1c212b }}
 a {{ color:#8fb6ff }}
 .warn {{ border-left:2px solid #d4a24c; padding-left:1rem; color:#cfd3dc }}
</style></head><body><main>
<h1>onewayglass</h1>
<p class="sub">Retrieval that cannot tell you what it hid. v{VERSION} &middot;
<a href="/docs">API docs</a> &middot; <a href="/health">health</a></p>

<h2>The leak, in one request</h2>
<p>No token needed. Counts only, over a corpus of synthetic fiction.</p>
<pre>curl "{{HOST}}/attack?q=compensation+bands+redundancy+acquisition"</pre>
<p>The naive counts differ between principals. The enforced counts do not. That difference is
the entire result.</p>

<h2>Or run it yourself, as two different people</h2>
<pre>curl -H "Authorization: Bearer demo-u_ic_eng" \\
  "{{HOST}}/search/naive?q=redundancy+planning+next+fiscal+year"
# result_count: 0 of 5 requested. Three restricted documents matched.

curl -H "Authorization: Bearer demo-u_exec" \\
  "{{HOST}}/search/naive?q=redundancy+planning+next+fiscal+year"
# result_count: 5. The difference between these two numbers is the leak.

curl -H "Authorization: Bearer demo-u_ic_eng" \\
  "{{HOST}}/search?q=redundancy+planning+next+fiscal+year"
# result_count: 5. Identical to the CEO's. Content differs; the count does not.</pre>

<h2>Tokens</h2>
<p>Published deliberately &mdash; the corpus is fiction and there is nothing to protect. They
exist because count-stability is a claim about what <em>different authenticated callers</em>
can observe, so it cannot be demonstrated from one anonymous endpoint.</p>
<table><thead><tr><th>token</th><th>who</th><th>dept / level</th><th>may read</th></tr></thead>
<tbody>{rows}</tbody></table>

<h2 class="warn">A timing channel survives this</h2>
<p class="warn">Count-stability is a partial defence. The count channel is closed; a timing
channel of about 1.8&nbsp;µs remains, and the padded arm is <em>faster</em> &mdash; so it leaks
&ldquo;this query had few readable matches for you&rdquo;. Measured at median SNR 0.73 and
published rather than buried, because the project&rsquo;s own thesis committed to that before the
code was written.</p>

<h2>Endpoints</h2>
<table><thead><tr><th>route</th><th>auth</th><th>what</th></tr></thead><tbody>
<tr><td><code>GET /attack</code></td><td>none</td><td>the attack across all 9 principals</td></tr>
<tr><td><code>GET /search</code></td><td>bearer</td><td>enforced: count-stable</td></tr>
<tr><td><code>GET /search/naive</code></td><td>bearer</td><td>the leaking path, deployed unfixed</td></tr>
<tr><td><code>GET /whoami</code></td><td>bearer</td><td>this token&rsquo;s own access</td></tr>
<tr><td><code>GET /health</code></td><td>none</td><td>asserts count-stability at runtime</td></tr>
</tbody></table>
<p style="color:#788092;margin-top:2.5rem">Rate limit {_RATE_MAX} requests per
{_RATE_WINDOW_S}s per token, in-memory and per-instance.</p>
</main>
<script>
 document.body.innerHTML = document.body.innerHTML.replaceAll('{{HOST}}', location.origin);
</script>
</body></html>"""
