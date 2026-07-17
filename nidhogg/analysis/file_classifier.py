"""File classifier: derive context tags from a file's path and name."""

from __future__ import annotations

from typing import TYPE_CHECKING

from nidhogg.core.models import FileTag

if TYPE_CHECKING:
    from pathlib import Path

_DOC_SUFFIXES = frozenset({".md", ".rst", ".txt"})
_PACKAGING_NAMES = frozenset({"setup.py", "setup.cfg", "pyproject.toml", "manifest.in"})


def classify_file(path: Path, root: Path) -> set[FileTag]:
    """Return the context tags for *path*, based only on its name and location.

    Content is never read; :attr:`FileTag.DYNAMIC_EXEC` is assigned elsewhere.

    Args:
        path: Absolute path to the file being classified.
        root: Package root, used to interpret the file's relative location.
            If *path* is not under *root*, the full path is used instead of
            a relative one when checking directory-name and dotfile parts.

    Returns:
        The set of matching :class:`FileTag` values (possibly empty).
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path
    parts = [p.lower() for p in rel.parts]
    name = path.name.lower()
    tags: set[FileTag] = set()

    if name.startswith("readme"):
        tags.add(FileTag.README)
    if path.suffix.lower() in _DOC_SUFFIXES or "docs" in parts:
        tags.add(FileTag.DOCS)
    if (
        name.startswith("test_")
        or name.endswith(("_test.py", "_tests.py"))
        or "tests" in parts
        or "test" in parts
    ):
        tags.add(FileTag.TEST)
    if any(p.startswith(("example", "sample")) for p in parts):
        tags.add(FileTag.EXAMPLE)
    if name in _PACKAGING_NAMES:
        tags.add(FileTag.PACKAGING)
    if name == "__init__.py":
        tags.add(FileTag.INIT)
    if name == "__main__.py":
        tags.add(FileTag.ENTRYPOINT)
    if any(p.startswith(".") for p in parts):
        tags.add(FileTag.DOTFILE)

    return tags
