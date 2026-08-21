# Relevance-plausible padding does not work, and cannot

**Date:** 2026-08-21 · **Attempt:** choose filler that shares query terms instead of the lowest
document id · **Result:** **zero improvement**, and the reason is structural

## What was tried

The open channel: padded results share no terms with the query, so a principal reading five
non-answers knows every document that *did* match is one they cannot read. Measured at
**15/15 exact** in `bench/relevance/`.

The obvious fix is to make the filler look on-topic. `EnforcedRetriever(plausible_pad=True)` orders
the non-matching readable documents by how many query terms they share, keeping document id as the
tie-breaker so identical requests still produce identical pads.

## What it achieved

| | Detectable as filler |
|---|---|
| Default pad (by document id) | **69 / 75** |
| Plausible pad (by term overlap) | **69 / 75** |
| Improvement | **0** |

Not a small gain. Not a partial gain. Identical.

```bash
python bench/relevance/plausible.py
```

## Why it cannot work

**For 11 of 15 attack queries, no readable document shares a single term with the query.**

```
query:   "redundancy planning next fiscal year"
terms:   fiscal, next, planning, redundancy, year

best available filler, by overlap:
  0 terms   doc_eng_04   Vendor Integration Spec
  0 terms   doc_eng_03   On-call Rotation
  0 terms   doc_eng_02   Deployment Runbook
```

The ordering heuristic has nothing to order. Every candidate scores zero, so sorting by score
returns the same set the document-id ordering did.

This is not a tuning failure. It follows from the situation the defence is in: **the caller is
asking about a subject they have no access to, so every document they can read is off-topic by
definition.** Plausible padding needs plausible material, and a principal restricted from a topic
has none on that topic.

## The finding that matters more

Availability of plausible material tracks permission — in exactly the wrong direction:

| Principal | May read | Queries with any plausible filler |
|---|---|---|
| Contractor | 10 | **3 / 15** |
| People Partner | 10 | 3 / 15 |
| Engineer (IC) | 13 | 4 / 15 |
| Eng Director | 20 | 8 / 15 |
| **CEO** | **35** | **15 / 15** |

The CEO — who has nothing hidden from them and therefore needs no cover — is the only principal
for whom plausible padding is always possible. The contractor, who has the most hidden and the
most to gain from cover, can be given it on 3 queries of 15.

**The defence is available in inverse proportion to the need for it.** That is worth more than the
failed fix, and it generalises beyond this corpus: the amount of on-topic material a principal can
be shown is bounded by what they may already read, which is precisely what the channel leaks.

## What would close it, and why none of it was done

- **Filler from documents the caller may not read.** Closes the channel by committing the leak it
  exists to prevent.
- **Synthetic filler — generated text on the query's subject.** Detectable as fabricated by any
  reader who checks, useless to the authorised caller, and it makes the system assert things no
  document says. A retrieval system that invents documents to hide which ones exist has traded a
  side channel for a fabrication.
- **Returning nothing on restricted topics.** Uniform refusal is itself a signal — "this query hit
  something" — and it destroys the readable answers the query might legitimately have had.
- **Query-side rejection: refuse to answer queries about restricted subjects.** Requires knowing
  which subjects are restricted for this principal, which is the same oracle in a different place.

Each of these was considered and rejected on the record, rather than left as future work.

## Consequence

`plausible_pad` is kept as a **non-default option** and documented as ineffective. It stays because
the measurement is reproducible and someone will otherwise try the same thing; the flag and this
report together are cheaper than repeating the experiment.

The project's claim is unchanged and remains the narrowed one:

> Count-stability defeats an observer of the count. It does not defeat the recipient of the
> results.

Two channels are now published as open — timing at median SNR 0.73, and relevance at 15/15 — and
one attempted fix is published as having failed. That is the honest state of the work.
