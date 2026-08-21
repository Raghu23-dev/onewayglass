# Deployment

> **Gate:** "published to a package registry" is not deployment. A stranger must be able to hit
> a running instance.

**Live:** https://onewayglass.vercel.app

Run the whole result in one request, no token required:

```bash
curl "https://onewayglass.vercel.app/attack?q=compensation+bands+redundancy+acquisition"
```

## Why there is a deployment at all

A benchmark proves the code does what the README says. It does not prove the property survives an
HTTP boundary, per-principal authentication, or a stranger who did not write the tests.

It earned that: **the relevance channel was found by sweeping this deployment**, not by any test
in `tests/` or benchmark in `bench/`. Seeing what a caller actually receives — five results, none
answering the question, all flagged as padding — made visible a channel that every count-focused
test was structurally unable to ask about. See `bench/relevance/results/2026-08-21.md`.

## Endpoints

| Route | Auth | What |
|---|---|---|
| `GET /` | none | Landing page, tokens, copy-pasteable curls |
| `GET /attack` | none | The comparison across all 9 principals. **Counts only** — a test asserts no document text can appear |
| `GET /search` | bearer | Enforced path: count-stable |
| `GET /search/naive` | bearer | **The leaking path, deployed unfixed and on purpose** |
| `GET /whoami` | bearer | This token's own access |
| `GET /health` | none | Asserts the invariant at runtime |
| `GET /docs` | none | OpenAPI |

The naive path is deployed **unfixed** so a visitor can compare counts across two tokens and watch
the leak happen rather than take a table's word for it.

## Operational surface

| Concern | Implementation |
|---|---|
| Health check | `/health` asserts the invariant, not liveness: count-stability across all 9 principals and 0 content violations, computed on the responding instance. A test monkeypatches the retriever to break it and asserts the check reports `degraded` — a health check that cannot fail is decoration. |
| Structured logs | JSON to stdout, one line per request, method/path/status/duration. No query text and no principal id: a log recording which principal asked what is the query-log correlation channel listed in `NON-GOALS.md`. |
| Metrics / traces | `X-Response-Time-Ms` and `X-Onewayglass-Version` per response. No tracing backend — a single stateless function has nothing to correlate across. |
| Configuration | None. No environment variables, no secrets, no database. The corpus is a Python literal. Nothing to misconfigure and nothing to leak. |
| Rate limiting | 120 requests / 60 s per token, in-memory sliding window. **Per-instance and resets on cold start** — stated plainly rather than described as rate limiting, because on serverless that is what it is. Adequate for a demo; not a control. |
| Failure / degradation mode | Unhandled exceptions collapse to one opaque `500`. An error message that differs by principal is its own side channel. Unknown and malformed tokens return an identical `401` — a distinct "no such token" would be an enumeration oracle, and building one into a project about inference channels would be careless. |
| Security headers | `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` denying camera/mic/geolocation, via `vercel.json`. |

## On the tokens being published

`demo-u_ic_eng`, `demo-u_exec` and seven more are printed on the landing page. There is nothing
to protect: the corpus is 35 documents of synthetic fiction and no endpoint touches a real
credential, an environment secret or a database.

They exist because count-stability is a claim about what **different authenticated callers** can
observe. A single anonymous endpoint could not demonstrate it at all.

A production system would resolve the principal from a verified JWT. The retrieval property does
not depend on how identity is established, only that it is established **before ranking** — which
is the whole thesis.

## Deploy

```bash
uv build --wheel        # catches packaging errors the platform would hit; see below
pytest -q               # 51 tests, incl. 33 against the deployed app
vercel --prod
```

`uv build --wheel` is in the list because the first deploy failed twice on causes invisible
locally: `fastapi` was declared only in `requirements.txt`, which Vercel's Python builder ignores
in favour of `pyproject.toml`; and hatchling could not determine what to ship, since the package
lives in `src/` and does not match the project name at the repo root. Both reproduce locally in
two seconds with that one command.

## Rollback

```bash
vercel rollback                                    # previous production deployment
vercel ls onewayglass && vercel promote <url>      # or a specific one
```

Stateless with no database and no migrations, so rollback is instant and carries no data risk.

## Verified in production

```
GET /health                    → count_stable: true, content_violations: 0, all 9 at 5
GET /attack                    → naive counts [0, 2, 3] · enforced counts [5]
45 principal × query pairs     → every one returned exactly 5
no token / bad token           → 401, identical bodies
k=99 / empty q                 → 400
```
