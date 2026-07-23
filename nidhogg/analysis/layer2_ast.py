"""Layer 2: URL extraction via AST analysis with recursive deobfuscation."""

from __future__ import annotations

import ast
import re
import warnings
from typing import TYPE_CHECKING

from nidhogg.analysis.deobfuscate import (
    Scope,
    collect_module_scope,
    qualified_name,
    resolve_value,
)
from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag

if TYPE_CHECKING:
    from pathlib import Path

_URL_RE = re.compile(r"(?:https?|ftp|wss?)://(?:(?!(?:https?|ftp|wss?)://)\S)+")

# See layer1_regex.py's identical constants for the rationale: characters
# that are never valid unencoded inside a URL truncate the match at their
# first occurrence; everything else is just trailing prose punctuation.
_WEIRD_CHARS_RE = re.compile(r"""['"`<>{}|\\^]""")
_TRAILING_PUNCT = ".,;:!?()]"


def _clean(url: str) -> str:
    match = _WEIRD_CHARS_RE.search(url)
    truncated = url[: match.start()] if match else url
    return truncated.rstrip(_TRAILING_PUNCT)


def _urls_in(s: str) -> list[str]:
    return [_clean(m.group()) for m in _URL_RE.finditer(s) if _clean(m.group())]


def _as_text(value: str | bytes) -> str:
    """Return *value* as text, decoding bytes leniently for URL scanning."""
    return value if isinstance(value, str) else value.decode("utf-8", errors="replace")


class _UrlVisitor(ast.NodeVisitor):
    """AST visitor that collects URL findings and dynamic-exec usage."""

    _DYNAMIC_EXEC_NAMES = frozenset({"eval", "exec", "compile"})
    _DESERIALIZE_NAMES = frozenset(
        {"marshal.loads", "pickle.loads", "cPickle.loads", "_pickle.loads"}
    )

    def __init__(self, filepath: Path, scope: Scope) -> None:
        self._filepath = filepath
        self._scope = scope
        self.findings: list[UrlFinding] = []
        self.uses_dynamic_exec: bool = False

    def _emit(self, url: str, lineno: int, tags: set[UrlTag]) -> None:
        self.findings.append(
            UrlFinding(
                value=url,
                filepath=self._filepath,
                lineno=lineno,
                layer=AnalysisLayer.AST,
                tags=tags,
            )
        )

    def _try_resolve(self, node: ast.expr) -> bool:
        """Resolve *node* and emit any URLs it yields; report whether it resolved.

        Returns ``True`` when the node reduced to a concrete value (so the
        caller skips its children to avoid double-counting), ``False`` when the
        node is opaque and the caller should descend into it.
        """
        resolved = resolve_value(node, self._scope, node.lineno)
        if resolved is None:
            return False
        value, tags = resolved
        for url in _urls_in(_as_text(value)):
            self._emit(url, node.lineno, set(tags))
        return True

    def visit_Constant(self, node: ast.Constant) -> None:
        """Detect string constants that contain a URL."""
        if isinstance(node.value, str):
            for url in _urls_in(node.value):
                self._emit(url, node.lineno, set())
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Fold concatenations / percent-formats; else descend into children."""
        if not self._try_resolve(node):
            self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Resolve f-strings (literal or scope-assisted); else descend."""
        if not self._try_resolve(node):
            self.generic_visit(node)

    def _flag_dynamic(self, node: ast.Call) -> None:
        """Raise ``uses_dynamic_exec`` for eval/exec/compile and deserializers.

        ``marshal.loads``/``pickle.loads`` are never executed — their mere
        presence is treated as a dynamic-execution signal (see
        ``deobfuscate`` security notes).
        """
        func = node.func
        if isinstance(func, ast.Name) and func.id in self._DYNAMIC_EXEC_NAMES:
            self.uses_dynamic_exec = True
        if qualified_name(func) in self._DESERIALIZE_NAMES:
            self.uses_dynamic_exec = True

    def visit_Call(self, node: ast.Call) -> None:
        """Flag dynamic execution, then resolve decoder/composition calls."""
        self._flag_dynamic(node)
        if not self._try_resolve(node):
            self.generic_visit(node)


def extract_urls_ast(source: str, filepath: Path) -> tuple[list[UrlFinding], bool]:
    """Extract URL candidates from *source* by walking its AST.

    Resolves, recursively and in any nesting, the deobfuscation techniques
    attackers stack: string constants and concatenation, f-strings, scope
    tracking of module-level assignments, base64/hex/rot13/codecs decoding,
    zlib/gzip decompression, and string composition (``join``, ``format``,
    ``%``, ``replace``, reverse slice, ``chr``). See
    :mod:`nidhogg.analysis.deobfuscate` for the resolver and its security
    limits.

    ``marshal``/``pickle`` deserialisers are never executed; their presence,
    like ``eval``/``exec``/``compile``, sets the dynamic-execution flag.

    Args:
        source: Raw text content of a Python source file.
        filepath: Path to the file being analysed (stored in findings).

    Returns:
        A tuple ``(findings, uses_dynamic_exec)``.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except SyntaxError:
        return [], False

    scope = collect_module_scope(tree)
    visitor = _UrlVisitor(filepath, scope)
    visitor.visit(tree)
    return visitor.findings, visitor.uses_dynamic_exec
