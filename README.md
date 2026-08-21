# onewayglass

**Retrieval whose result count cannot tell you what it hid.**

RAG over permissioned documents leaks even when it never returns a document you may not read.
Filter after retrieval and the *result count* tells the caller how many restricted documents
matched. Absence is informative.

<!-- SCREENCAST: Act 1 — an engineer infers a redundancy plan exists, without reading a word
     of it. Act 2 — the same query, enforced, indistinguishable from a query with no hidden
     matches. Act 3 — the attack suite and the timing channel that survives. -->

**Live:** https://onewayglass.vercel.app — run the attack yourself, as two different people:

```bash
curl "https://onewayglass.vercel.app/attack?q=compensation+bands+redundancy+acquisition"
# naive counts differ by principal: [0, 2, 3]
# enforced counts are identical:    [5]
```

## The measured leak

35-document synthetic org, 5 departments, 4 seniority levels. Attacker is an engineering IC
who may read 13 of 35. Fifteen queries, all phrased as an ordinary employee would type them.

| Attack | Result |
|---|---|
| Probes where restricted documents matched | 13 / 15 |
| Attacker's inferred hidden count **exactly correct** | **15 / 15** |
| Restricted documents whose existence was revealed | **17** |

An engineer with no HR or exec access learns that a redundancy plan exists, that acquisition
talks are underway, and roughly how much material surrounds each. **No confidential text is
ever returned.**

The control proves it is an oracle, not noise — total deficit across the 15 probes:

| Principal | Readable | Deficit |
|---|---|---|
| Engineer (IC) | 13 | **23** |
| Eng Director | 20 | 18 |
| People Director | 14 | 18 |
| **CEO** | **35** | **0** |

Falls monotonically as permission rises, exactly zero for someone who reads everything.

```bash
python bench/baseline/leak.py      # reproduce the leak
python bench/enforce/replay.py     # the same attacks, enforced
```

## The result

| | Naive | Enforced |
|---|---|---|
| Count inference | 13/15 probes leaked | **0/15** |
| Documents revealed to exist | 17 | **0** |
| Observable count | varies by principal | **always k, for all 9 principals** |
| Content violations | 0 | **0** (135 principal-query pairs) |
| Recall vs per-principal ideal | 0.923 | **1.000** |

Enforcement **improves** recall by 7.7%, and the gain tracks permission: the CEO loses nothing
either way, the contractor gains most. Retrieve-then-filter costs quality precisely because
restricted documents occupy top-k slots a readable document could have used.

## How it works

```
naive:     rank all 35 → take top 5 → drop unreadable → return 2
                                                        └─ the deficit is the leak

enforced:  restrict to readable → rank those → take top 5 → pad to 5 → return 5
                                                            └─ count carries no information
```

Two changes, and the second is the one that matters:

1. **Filter before ranking.** Permissions are an input to retrieval, not a filter on its
   output. Removes most of the deficit.
2. **Pad to a stable count.** Pre-filtering alone is not enough — if only three readable
   documents match where seven matched globally, the caller still gets three, and comparing
   counts with a colleague still leaks. Padding makes the count constant.

The invariant every test attacks:

> For any two principals issuing the same query, the observable result **count** is identical.
> Only the content differs.

That is the one-way glass: from outside, a blocked document and a nonexistent one look the
same.

## Count-stability is necessary and not sufficient. Two channels survive.

`docs/02-thesis.md` pre-committed to publishing residual channels rather than claiming the
guarantee. Two were found, and the second is worse than the first.

### The relevance channel — the serious one

**Inference is 15/15 exact, recovered by reading the results.** One request, no statistics, no
cross-principal comparison, no timing.

Padded results are filler: they share no terms with the query. So a principal who receives five
results and sees that none of them answer the question knows every document that *did* match is
one they cannot read. That is the original inference, restored in full.

```
result_count: 5      ← stable, identical to the CEO's
results:      5 documents, none containing "redundancy", "planning" or "fiscal"
                    ← the count says nothing; the contents say everything
```

It was found **after** all six criteria passed, by looking at what the deployed instance actually
returns. The earlier benchmarks all measured an observer of the *count* — a colleague comparing
notes, a proxy log — and against that observer count-stability works. But in the original threat
model the attacker **is** the principal, and the principal can read.

So the honest claim is narrower than "count inference defeated":

> **Count-stability defeats an observer of the count. It does not defeat the recipient of the
> results.**

That is still worth something — a colleague comparing counts, an access log that records counts
but not payloads, an analytics pipeline aggregating per-principal result counts. It is not
protection against the reader.

**An attempt to fix it failed, and the failure is the more interesting result.** Ordering the
filler by query-term overlap — so it at least looks on-topic — produced **zero improvement**, 69/75
results still detectable as filler. For 11 of 15 attack queries *no readable document shares a
single term with the query*, so the heuristic has nothing to order.

That is structural, not a tuning problem: a caller asking about a subject they have no access to
can read nothing on that subject. And the availability of cover runs exactly backwards —

| Principal | May read | Queries with any plausible filler |
|---|---|---|
| Contractor | 10 | **3 / 15** |
| Engineer (IC) | 13 | 4 / 15 |
| **CEO** | **35** | **15 / 15** |

The CEO, who has nothing hidden and needs no cover, is the only principal who can always be given
it. **The defence is available in inverse proportion to the need for it.**

Full measurement: [`bench/relevance/results/2026-08-21.md`](bench/relevance/results/2026-08-21.md)
and [`bench/relevance/results/2026-08-21-plausible-padding.md`](bench/relevance/results/2026-08-21-plausible-padding.md)

### The timing channel — the weak one

7 repeats × 2,000 runs, arm order alternated: **median SNR 0.73** (range 0.42–1.12), median
difference **1.8 µs**. Above the 0.5 threshold, so the channel is present.

**The direction is counterintuitive.** The heavily-padded arm is *faster*, because padding
appends pre-sorted documents rather than scoring more candidates. So it leaks *"this query had
few readable matches for you"* — close to what the count used to give away. Had I assumed
padding would be slower, I would have tested the wrong arm and found nothing.

At 1.8 µs it is far below network jitter, so exploiting it over HTTP needs a large number of
observations — itself an anomalous query pattern. But it exists, it is measured, and
count-stability is therefore a **partial** defence.

Closing it means padding the execution path: scoring a constant number of candidates
regardless of how many are readable. That costs whole-corpus work per query, which is why
constant-time retrieval is a listed non-goal rather than a quick fix.

Full writeup: [`bench/timing/results/2026-08-21.md`](bench/timing/results/2026-08-21.md)

## Quickstart

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

python bench/baseline/leak.py      # the leak
python bench/enforce/replay.py     # the fix
python bench/quality/measure.py    # what it costs
python bench/relevance/measure.py  # what it does NOT fix, and this one matters
python bench/relevance/plausible.py # an attempted fix that failed, and why it had to
python bench/timing/measure.py     # a weaker residual channel
python bench/latency/measure.py    # what it costs
pytest -q                          # 16 adversarial tests
```

## Status against pre-registered criteria

| # | Criterion | Status |
|---|---|---|
| 1 | No content leak | **met** — 0 across 135 pairs |
| 2 | Count inference defeated | **met for the count channel** — 15/15 → 0/15. Restored to 15/15 via relevance, see above. |
| 3 | Count-stability | **met** — identical count, all principals, all queries |
| 4 | Existence probing defeated | **met** — 17 → 0 |
| 5 | Retrieval quality preserved | **met** — 0.923 → 1.000 |
| 6 | Latency within 2× naive | **met** — p50 1.48×, p95 1.50×, batched p99 1.37×, all 7/7 repeats |

Per-request p99 is reported as **unresolved**: two runs of identical code gave worst-case ratios
of 1.79× and 2.79×, and an A/A control shows identical code differing by up to 1.15× at p99. The
run-to-run swing exceeds the effect, so picking the passing run would be picking a result.

## What it costs

| | Naive | Enforced | |
|---|---|---|---|
| p50 | 7.29 µs | 10.83 µs | **1.48×** |
| p95 | 8.63 µs | 12.92 µs | **1.50×** |
| batched p99 | 11.78 µs | 16.25 µs | **1.37×** |

3.5 µs per search, and 7× the permission checks for 1.5× the latency — BM25 scoring dominates
both arms. The cost scales with **corpus size, not k**: 35 checks per query instead of 5. At a
million documents that is a full scan and this implementation would need a permission-partitioned
index.

The denominator is a naive path with the same dict lookup rather than the one as written, so the
ratio does not credit enforcement for the baseline's O(k·n) id scan.
[`bench/latency/results/2026-08-21.md`](bench/latency/results/2026-08-21.md) has the per-repeat
series, the A/A control and the three measurement bugs that had to be fixed before the number
meant anything.

## Limitations

- **The relevance channel is open** — inference 15/15 by reading the results. This is the
  significant limitation and it is not fixed. Count-stability protects against an observer of the
  count, not against the recipient.
- **A timing channel remains** (median SNR 0.73, 1.8 µs), far weaker than the relevance channel
  since it needs thousands of samples.
- **The `padded` flag discloses the count outright.** It exists so an authorised caller can
  weight or hide filler. When the caller is the attacker it hands over the number the count no
  longer gives, with no inference at all.
- **Padding dilutes results.** A padded result is a real readable document that did not rank.
  The caller gets k results where fewer were genuinely relevant. `padded` is exposed per result
  so a consumer can weight or hide them — available to the authorised caller, invisible in the
  count.
- **A principal cannot be served more results than they can read.** Someone with 10 readable
  documents asking for k=12 receives 10. That discloses their own ceiling — information about
  their access, not about what is hidden from them. Asserted in a test rather than clamped
  silently.
- **The corpus is synthetic and small** (35 documents). It was built so sensitivity is
  unambiguous and the count-inference attack is genuinely available; it is not a claim about
  behaviour at scale.
- **In-process only.** No database, no network. A pgvector or hosted-store implementation could
  introduce channels this does not model.
- **Query-log correlation, embedding inversion and storage-layer channels are out of scope**
  and listed in `docs/NON-GOALS.md`.

## Licence

MIT — see [LICENSE](LICENSE).
