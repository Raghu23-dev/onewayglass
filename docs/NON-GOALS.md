# Non-Goals

| Not doing | Why | Would reconsider if |
|---|---|---|
| **Constant-time retrieval** | Defeating timing side channels properly means padding execution time as well as result count, which is a research problem. Timing is *measured and reported* instead of silently ignored. | A measured timing channel proves wide enough to be practically exploitable. |
| **Embedding-inversion defence** | Recovering source text from vectors is a live research area. Out of depth for this project, and pretending otherwise would be worse than omitting it. | — |
| **Query-log correlation attacks** | An attacker who can read the query logs of other principals has already won by a different route. | — |
| **A production ACL sync connector** (Google Drive, Notion, Confluence) | Each is weeks of API-specific work and none demonstrates the thesis better than a synthetic org with a clean hierarchy. | The mechanism is proven and someone needs a real connector. |
| **Multi-tenant billing / plans** | The thesis is about retrieval, not commerce. | — |
| **Its own vector database** | pgvector and hosted stores exist. Pre-filtering is expressible in both. | — |
| **Document-level encryption** | Orthogonal: encryption protects data at rest, and this protects the inference channel in retrieval. Both are needed; only one is the thesis. | — |
| **Row-level security via database policy alone** | Would work for the content leak but not for count-stability, since the count is computed above the database. Worth documenting as a partial measure. | — |
