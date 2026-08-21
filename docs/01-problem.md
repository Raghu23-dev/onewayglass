# 01 — The Problem

> **Gate:** contains a measurement I took myself. Harness: `bench/baseline/leak.py`.
> Raw results: `bench/baseline/results/leak.json`.

## Statement

**Retrieval-augmented generation over permissioned documents leaks, even when it never
returns a document the caller may not read.**

The usual implementation retrieves globally then filters by permission. It passes the
obvious test: no confidential text is disclosed. What it discloses is the *shape* of what it
withheld — and that is enough to map a corpus you cannot read.

## Why it matters

An internal assistant sits in front of HR files, board minutes and salary bands. The
control everyone checks is "can an engineer read the compensation document." The answer is
no, and everyone stops there.

Nobody checks whether an engineer can *learn that the document exists*, on what topic, and
roughly how many like it there are. That is a real disclosure: knowing there is a
"Redundancy Planning" document is materially harmful even without reading a word of it.

## The measured baseline

**Measured on:** 2026-08-21 · **Harness:** `python bench/baseline/leak.py`
**System under test:** BM25 retrieval, top-k global, post-filter by permission.
**Corpus:** 35 documents across 5 departments and 4 seniority levels.
**Attacker:** an engineering IC who may read 13 of 35 documents.
**Queries:** 15, all phrased as an ordinary employee would type them. None is adversarial.

### Attack 2 — count inference

| Result | Value |
|---|---|
| Probes where restricted documents matched | **13 / 15** |
| Attacker's inferred hidden count **exactly correct** | **15 / 15** |
| Distinct restricted documents whose existence was revealed | **17** |

The attacker learns the exact number of restricted documents matching every query, using
only the result count. **No confidential text is returned at any point.**

### Attack 3 — existence probing

A deficit on a topic-specific query confirms a document on that topic exists:

| Query | Hidden | Documents revealed to exist |
|---|---|---|
| "redundancy planning next fiscal year" | 3 | Redundancy Planning · Board Minutes · Grievance Case Notes |
| "acquisition discussions with potential acquirers" | 1 | Acquisition Discussions |
| "runway analysis burn months" | 2 | Runway Analysis · Lost Deal Analysis |
| "executive succession candidates" | 2 | Executive Succession · Hiring Scorecards |
| "compensation bands for senior engineers" | 2 | Compensation Bands · Platform Rewrite Proposal |

An engineer with no HR or exec access learns that a redundancy plan exists, that acquisition
talks are underway, and roughly how much material surrounds each. That is the whole point:
**absence is informative.**

### Attack 1 — direct disclosure

Some systems report the withheld count deliberately, reasoning that "3 results hidden" is
more honest than silently returning fewer. Measured: `returned 0, filtered_count=2`. No
inference required — the number is handed over.

### The control that proves it is an oracle, not noise

If the deficit were random it would be useless to an attacker. It is not:

| Principal | Readable documents | Total deficit across 15 probes |
|---|---|---|
| Engineer (IC) | 13 | **23** |
| Eng Director | 20 | 18 |
| People Director | 14 | 18 |
| **CEO** | **35** | **0** |

The deficit falls monotonically as permission rises and reaches **exactly zero** for a
principal who can read everything. It is a direct function of what the caller cannot see —
a permission oracle.

## Two bugs in my own measurement, fixed before publishing

**My attacker model was too weak.** The first version computed `k − returned`, which
over-counts whenever a query simply matches fewer than k documents. It scored **0/15** on
inference accuracy, making the leak look unexploitable. The real attacker calibrates against
how many documents match at all — trivially available by probing with a query known to be
unrestricted, or by comparing counts with a colleague. Corrected: **15/15**.

Reporting the 0/15 would have understated a real vulnerability.

**My access model was not a hierarchy.** A control comparing readable counts against
seniority showed the CEO reading **13** documents — fewer than an engineer — because the
department check excluded every non-exec department. An access model where seniority does not
monotonically widen access is not realistic, and would have invalidated every later
measurement. Fixed: CEO now reads all 35.

## Prior art

A SIGMOD'26 vision paper states that fine-grained access control "is not fully supported in
modern vector databases." GitHub search for `ACL sync RAG connector` returns zero
repositories. Commercial products in this space monetise exactly this capability, which is
evidence the problem is real; the open-source implementation is absent.

## Reproduce

```bash
python bench/baseline/leak.py
```
