"""Layer 2: URL extraction via AST analysis with constant folding."""

from __future__ import annotations

import ast
import base64
import re
import warnings
from typing import TYPE_CHECKING

from nidhogg.core.models import AnalysisLayer, UrlFinding, UrlTag

if TYPE_CHECKING:
    from pathlib import Path

_URL_RE = re.compile(r"(?:https?|ftp|wss?)://(?:(?!(?:https?|ftp|wss?)://)\S)+")

# See layer1_regex.py's identical constants for the rationale: characters
# that are never valid unencoded inside a URL truncate the match at their
# first occurrence; everything else is just trailing prose punctuation.
_WEIRD_CHARS_RE = re.compile(r"""['"`<>{}|\\^]""")
_TRAILING_PUNCT = ".,;:!?()]"

# name → (resolved_value, assignment_lineno)
type _Scope = dict[str, tuple[str, int]]


def _clean(url: str) -> str:
    match = _WEIRD_CHARS_RE.search(url)
    truncated = url[: match.start()] if match else url
    return truncated.rstrip(_TRAILING_PUNCT)


def _urls_in(s: str) -> list[str]:
    return [_clean(m.group()) for m in _URL_RE.finditer(s) if _clean(m.group())]


def _fold_binop(node: ast.BinOp) -> str | None:
    """Concatenate two string Constants joined by ``+``, or return None."""
    if not isinstance(node.op, ast.Add):
        return None
    left = node.left
    right = node.right
    if (
        isinstance(left, ast.Constant)
        and isinstance(right, ast.Constant)
        and isinstance(left.value, str)
        and isinstance(right.value, str)
    ):
        return left.value + right.value
    return None


def _try_b64decode(value: str | bytes) -> str | None:
    """Decode a base64 string/bytes constant, returning the UTF-8 text or None."""
    try:
        raw = value if isinstance(value, bytes) else value.encode("ascii")
        # Tolerate missing padding.
        pad = len(raw) % 4
        if pad:
            raw += b"=" * (4 - pad)
        return base64.b64decode(raw).decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None


def _resolve_fstring(node: ast.JoinedStr) -> str | None:
    """Reconstruct an f-string whose every interpolated part is a string Constant.

    Returns the resolved string, or ``None`` if any part is not statically
    resolvable without scope tracking.
    """
    parts: list[str] = []
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            parts.append(part.value)
        elif (
            isinstance(part, ast.FormattedValue)
            and isinstance(part.value, ast.Constant)
            and isinstance(part.value.value, str)
        ):
            parts.append(part.value.value)
        else:
            return None
    return "".join(parts)


def _resolve_to_str(node: ast.expr, scope: _Scope, at_lineno: int) -> str | None:
    """Resolve *node* to a string value, consulting *scope* for Name lookups.

    Only uses scope entries assigned strictly before *at_lineno*, so that
    variables used before their assignment are not resolved.  Handles
    ``Constant``, ``Name``, and ``BinOp(Add)`` nodes recursively.

    Args:
        node: The AST expression to resolve.
        scope: Mapping from variable name to ``(value, assignment_lineno)``.
        at_lineno: Line number of the expression being resolved.

    Returns:
        The resolved string, or ``None`` if resolution is not possible.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        entry = scope.get(node.id)
        if entry is not None:
            value, assign_lineno = entry
            if assign_lineno < at_lineno:
                return value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_to_str(node.left, scope, at_lineno)
        right = _resolve_to_str(node.right, scope, at_lineno)
        if left is not None and right is not None:
            return left + right
    return None


def _collect_scope(tree: ast.AST) -> _Scope:
    """Pre-pass: collect string-valued simple assignments, resolving chains.

    Processes ``ast.Assign`` nodes with a single ``Name`` target in line order
    so that later assignments can reference earlier ones
    (e.g. ``a = "x"; b = a + "y"``).

    Args:
        tree: The parsed AST of the source file.

    Returns:
        Mapping from variable name to ``(resolved_value, assignment_lineno)``.
    """
    assigns: list[tuple[int, str, ast.expr]] = sorted(
        (
            (node.lineno, node.targets[0].id, node.value)
            for node in ast.walk(tree)
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
            )
        ),
        key=lambda t: t[0],
    )
    scope: _Scope = {}
    for lineno, name, value_node in assigns:
        resolved = _resolve_to_str(value_node, scope, lineno)
        if resolved is not None:
            scope[name] = (resolved, lineno)
    return scope


def _resolve_fstring_scope(node: ast.JoinedStr, scope: _Scope) -> str | None:
    """Like ``_resolve_fstring`` but also resolves Name references from *scope*.

    Called only when ``_resolve_fstring`` has already returned ``None``,
    i.e. when there are variable interpolations that need scope tracking.

    Args:
        node: The f-string node to resolve.
        scope: Scope collected by ``_collect_scope``.

    Returns:
        The resolved string, or ``None`` if any part cannot be resolved.
    """
    parts: list[str] = []
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            parts.append(part.value)
        elif isinstance(part, ast.FormattedValue):
            resolved = _resolve_to_str(part.value, scope, node.lineno)
            if resolved is not None:
                parts.append(resolved)
            else:
                return None
        else:
            return None
    return "".join(parts)


class _UrlVisitor(ast.NodeVisitor):
    """AST visitor that collects URL findings and dynamic-exec usage."""

    _DYNAMIC_EXEC_NAMES = frozenset({"eval", "exec", "compile"})

    def __init__(self, filepath: Path, scope: _Scope) -> None:
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

    def visit_Constant(self, node: ast.Constant) -> None:
        """Detect string constants that contain a URL."""
        if isinstance(node.value, str):
            for url in _urls_in(node.value):
                self._emit(url, node.lineno, set())
        self.generic_visit(node)

    def visit_BinOp(self, node: ast.BinOp) -> None:
        """Fold string operands into a single value and check for URLs.

        Priority: pure Constant folding (VIA_CONCAT) → scope-assisted
        resolution (VIA_SCOPE) → descend into children.
        """
        folded = _fold_binop(node)
        if folded is not None:
            for url in _urls_in(folded):
                self._emit(url, node.lineno, {UrlTag.VIA_CONCAT})
            # Children already consumed — no need to descend.
            return
        resolved = _resolve_to_str(node, self._scope, node.lineno)
        if resolved is not None:
            for url in _urls_in(resolved):
                self._emit(url, node.lineno, {UrlTag.VIA_SCOPE})
            return
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect base64.b64decode() with a Constant arg and eval/exec/compile."""
        func = node.func
        if isinstance(func, ast.Name) and func.id in self._DYNAMIC_EXEC_NAMES:
            self.uses_dynamic_exec = True

        is_b64 = (isinstance(func, ast.Name) and func.id == "b64decode") or (
            isinstance(func, ast.Attribute) and func.attr == "b64decode"
        )
        if is_b64 and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str | bytes):
                decoded = _try_b64decode(arg.value)
                if decoded:
                    for url in _urls_in(decoded):
                        self._emit(url, node.lineno, {UrlTag.VIA_BASE64})

        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:
        """Resolve f-strings, falling back to scope tracking for Name interpolations."""
        resolved = _resolve_fstring(node)
        if resolved is not None:
            for url in _urls_in(resolved):
                self._emit(url, node.lineno, {UrlTag.VIA_FSTRING})
            # Parts already consumed — skip children to avoid duplicates.
            return
        resolved_scope = _resolve_fstring_scope(node, self._scope)
        if resolved_scope is not None:
            for url in _urls_in(resolved_scope):
                self._emit(url, node.lineno, {UrlTag.VIA_SCOPE})
            return
        self.generic_visit(node)


def extract_urls_ast(source: str, filepath: Path) -> tuple[list[UrlFinding], bool]:
    """Extract URL candidates from *source* by walking its AST.

    Resolves the following patterns (in order of complexity):

    * ``ast.Constant`` nodes whose string value contains a URL.
    * ``ast.BinOp`` concatenations between two ``Constant`` nodes.
    * ``base64.b64decode()`` / ``b64decode()`` calls with a ``Constant``
      argument — the decoded bytes are inspected for URLs.
    * ``ast.JoinedStr`` (f-strings) whose every interpolated part is a
      string ``Constant`` or a variable resolvable via scope tracking.
    * ``ast.Assign`` with a single ``Name`` target — collected in a pre-pass
      to enable scope tracking across the file.

    Args:
        source: Raw text content of a Python source file.
        filepath: Path to the file being analysed (stored in findings).

    Returns:
        A tuple ``(findings, uses_dynamic_exec)`` where ``uses_dynamic_exec``
        is ``True`` when the module calls ``eval``, ``exec``, or ``compile``.
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except SyntaxError:
        return [], False

    scope = _collect_scope(tree)
    visitor = _UrlVisitor(filepath, scope)
    visitor.visit(tree)
    return visitor.findings, visitor.uses_dynamic_exec
