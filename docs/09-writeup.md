# onewayglass — Technical Writeup

**Retrieval that cannot tell you what it hid.**

---

## 1. Problem

Retrieval-augmented generation over permissioned documents is usually judged by one question:
does it ever return a document the caller may not read? Answer that with "no" and the system
passes review.

It is the wrong question, and answering it correctly is not sufficient.

Consider an engineering IC on a 35-document corpus, of which they may read 13. They ask, in
ordinary words, *"redundancy planning next fiscal year"*. The system ranks all 35 documents,
takes the top 5, drops the ones the caller cannot read, and returns what remains. Two results
come back where five were requested.

No confidential text was disclosed. And the caller has just learned that three documents about
redundancy planning exist and are being kept from them.

**Absence is informative.** The gap between k and what came back is a function of how many
restricted documents matched the query — which is a fact about documents the caller cannot read,
returned to them on every request.

Measured against the naive implementation:

| | |
|---|---|
| Probes where restricted documents matched | 13 / 15 |
| Attacker's inferred hidden count **exactly correct** | **15 / 15** |
| Restricted documents whose existence was revealed | **17** |

Fifteen probes, none adversarially worded — the leak does not need unusual input, which is what
makes it a real problem rather than a curiosity. From them, an engineer with no HR or executive
access learns that a redundancy plan exists, that acquisition talks are underway, that executive
succession has been documented, and roughly how much material surrounds each.

The control is what establishes this is an oracle and not noise:

| Principal | May read | Total deficit across 15 probes |
|---|---|---|
| Engineer (IC) | 13 | **23** |
| Eng Director | 20 | 18 |
| People Director | 14 | 18 |
| **CEO** | **35** | **0** |

The deficit falls monotonically as permission rises and is exactly zero for someone who reads
everything. That is a permission oracle: a reliable readout of what is hidden from you,
available to anyone who can count.

## 2. Architecture

Permission-aware retrieval has two places to apply access control, and the choice determines
what leaks.

```
naive:     rank all 35 → take top 5 → drop unreadable → return 2
                                                        └─ the deficit is the leak

enforced:  restrict to readable → rank those → take top 5 → pad to 5 → return 5
                                                            └─ count carries no information
```

Two changes, and the second is the one that matters.

**Filter before ranking.** Permissions become an input to retrieval rather than a filter on its
output. This removes most of the deficit: k results come back whenever k readable documents
match.

**Pad to a stable count.** Pre-filtering alone is not enough. A principal with only three
readable matches still receives three, and comparing counts against a colleague still leaks.
Padding with lower-ranked readable documents makes the count constant.

The invariant every test attacks:

> For any two principals issuing the same query, the observable result **count** is identical.
> Only the content differs.

That is the one-way glass. From outside, a blocked document and a nonexistent one look the same.

**Rejected alternatives.** Padding with synthetic placeholders — detectable by content, and
useless to the caller. Over-fetching to always reach k — does nothing for a principal with fewer
than k readable matches, which is the case that leaks. Accepting a variable count — that is the
leak. Full detail and reversal conditions in `docs/03-architecture.md`.

## 3. Decisions

**The pad is deterministic, ordered by document id.** A random pad would differ between two
identical requests for the same query and principal, which is itself a signal — and it would make
the count-stability property test flaky in exactly the way that hides real failures.

**Padding is visible to the caller (`padded: bool`), not hidden.** Hiding it would degrade
results for the authorised user with no security benefit: they are entitled to know which results
are filler. What must carry no information is the *count*, not the payload. An `Answer.relevant`
accessor returns only results that genuinely ranked.

**The readable set is recomputed per call, not cached per principal.** A stale cache after a
revocation is a security bug, not a performance one. At 35 documents the cost is 3.5 µs. At a
million documents this is the scaling limit, and it is stated as such rather than left implied.

**BM25 rather than embeddings.** The leak is a property of *ranking then filtering* and is
independent of the ranker. BM25 is deterministic, so a count difference between two runs cannot
be blamed on model nondeterminism — which matters when the entire result is about count
differences.

**A synthetic corpus.** Real confidential documents are not acceptable to use. Public documents
relabelled as secret produce a demo nobody believes. The corpus is small enough to reason about
by hand and deliberately uneven — `people` holds few highly sensitive documents while
`engineering` holds many mundane ones — because that unevenness is what makes result counts
informative to an attacker in the first place.

**`Document.readable_by` is the single authoritative access rule.** Nothing re-implements it.
Every benchmark, test and retriever calls the same method, so a divergence between "what the
system enforces" and "what the tests believe it enforces" cannot open up.

## 4. Benchmarks

Five benchmarks. Attack benchmarks are deterministic — fixed corpus, fixed probes, BM25 — and
produce identical output on every run. Timing-sensitive measurements use 7 repeats.

```bash
python bench/baseline/leak.py      # the leak
python bench/enforce/replay.py     # criteria 1-4
python bench/quality/measure.py    # criterion 5
python bench/timing/measure.py     # kill condition 3
python bench/latency/measure.py    # criterion 6
```

**The enforced benchmark replays the same attacks with the same attacker and the same probes.**
A new attack suite would not be a comparison.

**The latency benchmark uses a fair denominator.** `NaiveRetriever` resolves each result id with
a linear scan, O(k·n); `EnforcedRetriever` uses a dict. Comparing them directly credits
enforcement for the baseline's sloppy bookkeeping, and that bias runs toward the thing being
sold. So a third arm runs naive with the same dict lookup, semantics untouched. It is worth
0.05–0.12× of ratio — small, but the size of a correction is only knowable after making it.

**The latency benchmark pairs its samples and carries an A/A control.** Both arms are timed
adjacent on the same principal and query, alternating order, so an interruption lands on both.
The A/A control times two instances of identical code through the same protocol; its ratio is the
harness's noise floor, and it is what makes any A/B number believable.

## 5. Results

| | Naive | Enforced |
|---|---|---|
| Count inference | 13/15 probes leaked, 15/15 exact | **0/15** |
| Documents revealed to exist | 17 | **0** |
| Observable count | varies by principal | **5, for all 9 principals** |
| Content violations | 0 | **0** (135 principal×query pairs) |
| Recall@5 vs per-principal ideal | 0.923 | **1.000** |
| Latency p50 | 7.29 µs | 10.83 µs (**1.48×**) |

All six pre-registered criteria met. Details and per-repeat series in `docs/05-results.md`.

**Enforcement improves recall by 7.7%, which was not predicted.** The thesis budgeted for up to
5% loss and planned to publish the tradeoff curve. Instead recall went up, because
retrieve-then-filter lets restricted documents consume top-k slots a readable document could have
used. The gain tracks permission: the CEO loses nothing either way, the contractor gains most
(0.850 → 1.000). A prediction wrong in a favourable direction is still a wrong prediction.

**A timing channel survives, and it points the wrong way.** Median SNR 0.73 over 7 repeats,
median difference 1.8 µs. The heavily-padded arm is *faster*, because padding appends pre-sorted
documents rather than scoring more candidates — so the channel leaks *"this query had few readable
matches for you"*, close to what the count used to give away. Had I assumed padding would be
slower, I would have timed the wrong arm and reported a clean result.

**Per-request p99 could not be measured honestly, and the criterion named p99.** Two runs of
identical code gave worst-case ratios of 1.79× and 2.79×; one passes the threshold, one fails it.
At ~11 µs per search one scheduler interrupt *is* the 99th percentile, and the A/A control
confirms it — identical code differs by up to 1.15× at p99. Reporting the passing run would have
been picking a result. The criterion is met on p50 (1.48×, 7/7 repeats), p95 (1.50×, 7/7) and a
batched p99 (1.37×, 7/7), and the statistic originally named is marked unresolved.

**Six benchmark bugs, five of which produced a green or flattering result.** The full table is in
`docs/05-results.md`. Two worth naming here:

The quality test was **circular**. It compared the enforced retriever against an "ideal" defined
as rank-the-readable-set-and-take-top-k — which is precisely what the enforced retriever computes,
so recall was 1.000 by construction. Worse, the attack probes deliberately target restricted
documents, so most principals had *empty* ideal sets. It was reporting 1.000 of nothing.

The first attacker model computed `k − returned`, which over-counts whenever a query simply
matches few documents. It scored 0/15 and made a real vulnerability look unexploitable. A
competent attacker calibrates against how many documents match at all; against that baseline the
inference is 15/15 exact. **The vulnerability was always there — the harness was too weak to see
it.**

The pattern: every one of these was caught by a **control**, never by reading the code. The
impossible result of enforced-faster-than-naive. The A/A control. A control asserting the naive
path *does* vary by principal — a stability test that passes against a leaky implementation
proves nothing. A control comparing readable counts against seniority, which caught the CEO
reading fewer documents than an engineer. A test that only confirms the expected direction cannot
detect a harness measuring nothing.

## 6. Limitations

**A timing channel remains.** Median SNR 0.73, 1.8 µs. Count-stability is a partial defence: the
count channel is closed, a timing channel is not. At 1.8 µs it sits far below network jitter, so
exploiting it over HTTP needs a large number of observations — itself an anomalous query pattern —
but it exists and it is measured. Closing it means padding the *execution path*: scoring a
constant number of candidates regardless of how many are readable. That costs whole-corpus work
per query, which is why constant-time retrieval is a listed non-goal rather than a quick fix.

**Padding dilutes results.** A padded result is a real readable document that did not rank. The
caller receives k results where fewer were genuinely relevant. `padded` is exposed per result so a
consumer can weight or hide them.

**A principal cannot be served more results than they can read.** Someone with 10 readable
documents asking for k=12 receives 10, which discloses their own ceiling. That is information
about their own access rather than about what is hidden from them — but it is a genuine limit, and
it is asserted in a test rather than silently clamped.

**The corpus is synthetic and small.** 35 documents, built so sensitivity is unambiguous and the
count-inference attack is genuinely available. It is not a claim about behaviour at scale.

**Latency scales with corpus size, not with k.** 35 permission checks per query instead of 5. At
35 documents that is 3.5 µs. At a million it is a full scan per query, and this implementation
would need a precomputed readable set or a permission-partitioned index. That is the first thing
requiring a solution before this ran anywhere real.

**In-process only.** No database, no network. A pgvector or hosted-vector-store implementation
could introduce channels this does not model — storage-layer access patterns, index-shape
disclosure, per-tenant cache timing.

**Out of scope and listed in `docs/NON-GOALS.md`:** query-log correlation across principals,
embedding inversion, and any channel below the retrieval layer.

**What I would do next**, in order: pad the execution path and re-measure the timing SNR, since
that is the one open honesty gap in the result; then move to a permission-partitioned index and
re-run the latency benchmark at 10⁵–10⁶ documents, since the scaling limit is the barrier to this
being usable rather than demonstrable.
