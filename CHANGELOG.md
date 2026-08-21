# Changelog

Generated from Conventional Commits. Notable changes per release.

## [Unreleased]

## [0.2.1] — 2026-08-21

### Fixed
- **`mypy .` exited 2 without checking anything**: four `bench/*/measure.py` files collide as
  top-level modules ("Duplicate module named measure"), which aborts the run. Resolved with
  `explicit_package_bases`; fixing it surfaced 16 errors that had been invisible, including an
  invalid dict index in `api/index.py`.
- `/attack` indexed `PRINCIPALS_BY_ID` with a value typed `object`; the principal id is now
  tracked alongside the rows.

### Added
- `tests/correctness/` contained only a README, so the `pytest tests/correctness` CI step exited
  5 ("no tests ran") — a gate that passed by testing nothing. 17 tests covering what the
  adversarial suite structurally cannot: that the retriever still *retrieves* (relevance,
  ranking, k honoured, determinism, and the deliberately-disclosed `padded` flag). A retriever
  that leaked nothing because it returned nothing would satisfy every adversarial test here.
