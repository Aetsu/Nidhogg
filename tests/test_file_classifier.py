"""Tests for path-based file classification."""

from __future__ import annotations

from pathlib import Path

from nidhogg.analysis.file_classifier import classify_file
from nidhogg.core.models import FileTag

ROOT = Path("/pkg")


def test_readme_file_tagged_readme() -> None:
    assert FileTag.README in classify_file(ROOT / "README.md", ROOT)


def test_markdown_under_docs_tagged_docs() -> None:
    tags = classify_file(ROOT / "docs" / "guide.md", ROOT)
    assert FileTag.DOCS in tags


def test_test_prefixed_file_tagged_test() -> None:
    assert FileTag.TEST in classify_file(ROOT / "test_thing.py", ROOT)


def test_file_under_tests_dir_tagged_test() -> None:
    assert FileTag.TEST in classify_file(ROOT / "tests" / "helpers.py", ROOT)


def test_setup_py_tagged_packaging() -> None:
    assert FileTag.PACKAGING in classify_file(ROOT / "setup.py", ROOT)


def test_pyproject_tagged_packaging() -> None:
    assert FileTag.PACKAGING in classify_file(ROOT / "pyproject.toml", ROOT)


def test_init_tagged_init() -> None:
    assert FileTag.INIT in classify_file(ROOT / "pkg" / "__init__.py", ROOT)


def test_main_tagged_entrypoint() -> None:
    assert FileTag.ENTRYPOINT in classify_file(ROOT / "pkg" / "__main__.py", ROOT)


def test_hidden_dir_tagged_dotfile() -> None:
    assert FileTag.DOTFILE in classify_file(ROOT / ".github" / "x.py", ROOT)


def test_example_dir_tagged_example() -> None:
    assert FileTag.EXAMPLE in classify_file(ROOT / "examples" / "demo.py", ROOT)


def test_multiple_tags_combine() -> None:
    tags = classify_file(ROOT / "tests" / "__init__.py", ROOT)
    assert {FileTag.TEST, FileTag.INIT} <= tags


def test_plain_module_has_no_tags() -> None:
    assert classify_file(ROOT / "pkg" / "core.py", ROOT) == set()
