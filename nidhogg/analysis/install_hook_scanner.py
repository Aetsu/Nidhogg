"""Install-hook scanner: detect process/network calls in setup.py and __init__.py.

Walks a package for every setup.py and every __init__.py at any depth, and
flags AST Call nodes whose qualified name matches a known-dangerous prefix —
process execution or network access — code that runs on `pip install`
(setup.py, including custom cmdclass overrides defined in the same file) or
on the package's first import (__init__.py). Recursing for setup.py (rather
than only checking the root) is required because real PyPI sdists extract
into a wrapper directory (e.g. ``{name}-{version}/setup.py``), not straight
into the given root.
"""

from __future__ import annotations

import ast
import warnings
from typing import TYPE_CHECKING

from nidhogg.analysis.deobfuscate import qualified_name
from nidhogg.core.models import InstallHookFinding, InstallHookSource

if TYPE_CHECKING:
    from pathlib import Path

_DANGEROUS_PREFIXES = (
    "subprocess.",
    "os.system",
    "os.popen",
    "os.exec",
    "os.spawn",
    "socket.",
    "urllib.request.",
    "http.client.",
    "requests.",
)


def _is_dangerous(name: str | None) -> bool:
    """Return ``True`` if *name* (a qualified call name) matches a risky prefix."""
    return name is not None and name.startswith(_DANGEROUS_PREFIXES)


class _InstallHookVisitor(ast.NodeVisitor):
    """AST visitor that flags process/network calls, tracking enclosing scope."""

    def __init__(self, filepath: Path, source: InstallHookSource) -> None:
        self._filepath = filepath
        self._source = source
        self._scope_stack: list[str] = []
        self.findings: list[InstallHookFinding] = []

    def _context(self) -> str:
        return ".".join(self._scope_stack) if self._scope_stack else "module"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Push the class name onto the scope stack while visiting its body."""
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Push the function name onto the scope stack while visiting its body."""
        self._scope_stack.append(node.name)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        """Emit a finding when *node* calls a known-dangerous function."""
        name = qualified_name(node.func)
        if _is_dangerous(name):
            assert name is not None  # noqa: S101  # _is_dangerous guarantees this
            self.findings.append(
                InstallHookFinding(
                    filepath=self._filepath,
                    lineno=node.lineno,
                    call=name,
                    command=ast.unparse(node),
                    context=self._context(),
                    source=self._source,
                )
            )
        self.generic_visit(node)


def _collect_candidate_files(root: Path) -> list[tuple[Path, InstallHookSource]]:
    """Return ``(path, source)`` pairs for every setup.py and __init__.py under root."""
    candidates: list[tuple[Path, InstallHookSource]] = []
    candidates.extend(
        (p, InstallHookSource.SETUP_PY)
        for p in root.rglob("setup.py")
        if "__pycache__" not in p.parts
    )
    candidates.extend(
        (p, InstallHookSource.PACKAGE_INIT)
        for p in root.rglob("__init__.py")
        if "__pycache__" not in p.parts
    )
    return candidates


def _read_text(filepath: Path) -> str | None:
    """Read *filepath* as UTF-8, returning ``None`` if it cannot be read."""
    try:
        return filepath.read_text(encoding="utf-8")
    except UnicodeDecodeError, OSError:
        return None


def _scan_one(filepath: Path, source: InstallHookSource) -> list[InstallHookFinding]:
    """Parse *filepath* and return every dangerous-call finding in it."""
    text = _read_text(filepath)
    if text is None:
        return []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except SyntaxError:
        return []
    visitor = _InstallHookVisitor(filepath, source)
    visitor.visit(tree)
    return visitor.findings


def scan_install_hooks(root: Path) -> list[InstallHookFinding]:
    """Scan *root* for install/import-time process and network calls.

    Args:
        root: Package directory to scan.

    Returns:
        One :class:`InstallHookFinding` per dangerous call found in any
        ``setup.py`` or ``__init__.py`` under *root*.
    """
    findings: list[InstallHookFinding] = []
    for filepath, source in _collect_candidate_files(root):
        findings.extend(_scan_one(filepath, source))
    return findings
