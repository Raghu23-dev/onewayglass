"""The package must actually be importable, and expose what it documents.

WHY: `src/onewayglass/` had no `__init__.py`, so it installed as an implicit namespace package. A
wheel built from it imported without error — `import onewayglass` succeeded — while exposing
**nothing**. `from onewayglass import EnforcedRetriever` failed with "unknown location".

That is the worst shape of failure for a published package: the smoke test passes, and every real
use breaks. These tests are the smoke test that would have caught it.
"""

from __future__ import annotations

import importlib
import pathlib

import onewayglass


def test_it_is_a_real_package_not_a_namespace() -> None:
    """A namespace package has __file__ of None. It installs, imports, and exports nothing."""
    assert onewayglass.__file__ is not None, (
        "onewayglass installed as an implicit namespace package — src/onewayglass/__init__.py "
        "is missing, so the package exposes no public API"
    )


def test_the_init_file_exists_on_disk() -> None:
    root = pathlib.Path(onewayglass.__file__).parent
    assert (root / "__init__.py").is_file()


def test_every_name_in_all_is_actually_importable() -> None:
    """__all__ is a promise. An entry that does not resolve breaks `from onewayglass import *`."""
    missing = [name for name in onewayglass.__all__ if not hasattr(onewayglass, name)]
    assert missing == [], f"__all__ names that do not resolve: {missing}"


def test_the_documented_usage_from_the_docstring_runs() -> None:
    """The example in the module docstring is the first thing anyone tries."""
    from onewayglass import PRINCIPALS_BY_ID, EnforcedRetriever, Index

    answer = EnforcedRetriever(Index()).search(
        PRINCIPALS_BY_ID["u_ic_eng"], "redundancy planning", k=5
    )
    assert answer.result_count == 5
    assert hasattr(answer, "relevant")


def test_py_typed_ships_so_consumers_get_types() -> None:
    """Without this marker mypy treats the package as untyped, whatever annotations it carries."""
    root = pathlib.Path(onewayglass.__file__).parent
    assert (root / "py.typed").is_file()


def test_the_version_is_not_a_placeholder() -> None:
    """0.0.0 published to PyPI is permanent — a version can never be re-uploaded."""
    import tomllib

    root = pathlib.Path(__file__).resolve().parents[2]
    data = tomllib.loads((root / "pyproject.toml").read_text())
    version = data["project"]["version"]
    assert version != "0.0.0", "refusing to publish a placeholder version"
    assert importlib.import_module("onewayglass") is onewayglass
