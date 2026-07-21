"""Recursive value resolver: statically deobfuscate strings/bytes from an AST.

Pure module — no I/O, no execution of analysed code. Given an ``ast.expr``
node, it composes the deobfuscation techniques attackers stack (base64, hex,
rot13, zlib, string joins, f-strings, ...) and returns the resolved value
plus the set of extraction-method :class:`UrlTag` s that produced it.

Security invariants (see project ``CLAUDE.md``):

* Never deserialises ``marshal``/``pickle`` — those execute code on load.
* Decompression output is capped (:data:`_MAX_OUTPUT`) against zip bombs.
* Recursion is depth-limited (:data:`_MAX_DEPTH`).
* Every decoder swallows its own errors and yields ``None`` instead of raising.
"""

from __future__ import annotations

import ast
import base64
import binascii
import codecs
import dataclasses
import zlib
from typing import TYPE_CHECKING

from nidhogg.core.models import UrlTag

if TYPE_CHECKING:
    from collections.abc import Callable

type Scope = dict[str, tuple[str, int]]
type Resolved = tuple[str | bytes, frozenset[UrlTag]]

_MAX_DEPTH = 8
_MAX_OUTPUT = 5 * 1024 * 1024  # 5 MiB — decompression bomb ceiling.
_CODECS_DECODE_ARITY = 2  # codecs.decode(value, encoding)
_REPLACE_ARITY = 2  # str.replace(old, new)


@dataclasses.dataclass(frozen=True, slots=True)
class _Ctx:
    """Immutable resolution context threaded through the recursion."""

    scope: Scope
    at_lineno: int


def _b64decode(value: str | bytes) -> bytes | None:
    """Decode a base64 string/bytes constant, tolerating missing padding."""
    try:
        raw = value if isinstance(value, bytes) else value.encode("ascii")
        pad = len(raw) % 4
        if pad:
            raw += b"=" * (4 - pad)
        return base64.b64decode(raw)
    except binascii.Error, ValueError, UnicodeEncodeError:
        return None


def _from_hex(value: str | bytes) -> bytes | None:
    """Decode a hex string (``bytes.fromhex`` / ``binascii.unhexlify``)."""
    try:
        text = value.decode("ascii") if isinstance(value, bytes) else value
        return bytes.fromhex(text)
    except ValueError, UnicodeDecodeError:
        return None


def _decompress(value: str | bytes, wbits: int) -> bytes | None:
    """Inflate *value* with a size ceiling to defeat decompression bombs.

    Uses an incremental ``decompressobj`` bounded by :data:`_MAX_OUTPUT` so a
    bomb never materialises fully in memory before the size check.
    """
    if not isinstance(value, bytes):
        return None
    try:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(value, _MAX_OUTPUT + 1)
    except zlib.error:
        return None
    if len(out) > _MAX_OUTPUT:
        return None
    return out


def _zlib_decompress(value: str | bytes) -> bytes | None:
    """Inflate a raw zlib stream."""
    return _decompress(value, zlib.MAX_WBITS)


def _gzip_decompress(value: str | bytes) -> bytes | None:
    """Inflate a gzip stream (zlib window with the gzip header flag)."""
    return _decompress(value, zlib.MAX_WBITS | 16)


# Single-argument byte decoders keyed by their qualified call name.
_DECODERS: dict[str, Callable[[str | bytes], str | bytes | None]] = {
    "base64.b64decode": _b64decode,
    "b64decode": _b64decode,
    "bytes.fromhex": _from_hex,
    "binascii.unhexlify": _from_hex,
    "unhexlify": _from_hex,
    "zlib.decompress": _zlib_decompress,
    "gzip.decompress": _gzip_decompress,
}

# Decoders whose resulting tag stays VIA_BASE64 rather than the umbrella tag.
_BASE64_NAMES = frozenset({"base64.b64decode", "b64decode"})


def qualified_name(func: ast.expr) -> str | None:
    """Return the dotted name of a call target, or ``None`` if not a name path.

    ``base64.b64decode`` → ``"base64.b64decode"``; ``b64decode`` →
    ``"b64decode"``. Method calls on a computed value (``"x".join``) return
    just the attribute (``"join"``) since their receiver is not a simple name.
    """
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        parent = qualified_name(func.value)
        return f"{parent}.{func.attr}" if parent else func.attr
    return None


def _resolve_constant(node: ast.Constant, _ctx: _Ctx, _depth: int) -> Resolved | None:
    if isinstance(node.value, str | bytes):
        return node.value, frozenset()
    return None


def _resolve_name(node: ast.Name, ctx: _Ctx, _depth: int) -> Resolved | None:
    entry = ctx.scope.get(node.id)
    if entry is not None and entry[1] < ctx.at_lineno:
        return entry[0], frozenset({UrlTag.VIA_SCOPE})
    return None


def _resolve_binop(node: ast.BinOp, ctx: _Ctx, depth: int) -> Resolved | None:
    """Resolve ``a + b`` (concat) or ``fmt % args`` (percent-format)."""
    if isinstance(node.op, ast.Mod):
        return _resolve_percent_format(node, ctx, depth)
    if not isinstance(node.op, ast.Add):
        return None
    left = _dispatch(node.left, ctx, depth + 1)
    right = _dispatch(node.right, ctx, depth + 1)
    if left is None or right is None:
        return None
    lvalue, ltags = left
    rvalue, rtags = right
    if type(lvalue) is not type(rvalue):
        return None
    combined = ltags | rtags or frozenset({UrlTag.VIA_CONCAT})
    return lvalue + rvalue, combined  # type: ignore[operator]


def _resolve_percent_format(node: ast.BinOp, ctx: _Ctx, depth: int) -> Resolved | None:
    """Resolve ``"tmpl" % args`` where the template and every arg resolve."""
    template = _dispatch(node.left, ctx, depth + 1)
    if template is None or not isinstance(template[0], str):
        return None
    operands = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
    resolved = [_dispatch(e, ctx, depth + 1) for e in operands]
    if any(r is None for r in resolved):
        return None
    args = tuple(r[0] for r in resolved if r is not None)
    tags = template[1].union(*(r[1] for r in resolved if r is not None))
    try:
        return template[0] % args, tags | {UrlTag.VIA_DECODED}
    except TypeError, ValueError:
        return None


def _resolve_joined_str(node: ast.JoinedStr, ctx: _Ctx, depth: int) -> Resolved | None:
    """Resolve an f-string whose every part is a literal or scope-resolvable str.

    An all-literal f-string is tagged ``VIA_FSTRING``; any interpolated
    variable pulls in its own tag (e.g. ``VIA_SCOPE``), matching the
    extraction-method semantics of the original layer-2 visitor.
    """
    parts: list[str] = []
    tags: frozenset[UrlTag] = frozenset()
    for part in node.values:
        if isinstance(part, ast.Constant) and isinstance(part.value, str):
            parts.append(part.value)
        elif isinstance(part, ast.FormattedValue):
            resolved = _dispatch(part.value, ctx, depth + 1)
            if resolved is None or not isinstance(resolved[0], str):
                return None
            parts.append(resolved[0])
            tags = tags | resolved[1]
        else:
            return None
    return "".join(parts), tags or frozenset({UrlTag.VIA_FSTRING})


def _method_recode(
    attr: str, value: str | bytes, args: list[ast.expr]
) -> str | bytes | None:
    """Apply the no-argument ``.decode()`` / ``.encode()`` transforms."""
    if args:
        return None
    try:
        return value.decode() if attr == "decode" else value.encode()  # type: ignore[union-attr]
    except UnicodeDecodeError, UnicodeEncodeError, AttributeError:
        return None


def _method_join(
    value: str | bytes, args: list[ast.expr], ctx: _Ctx, depth: int
) -> str | bytes | None:
    """Apply ``sep.join([...])`` over a literal list/tuple of resolvable parts."""
    if (
        not isinstance(value, str)
        or len(args) != 1
        or not isinstance(args[0], ast.List | ast.Tuple)
    ):
        return None
    parts = [_dispatch(e, ctx, depth + 1) for e in args[0].elts]
    if any(p is None for p in parts):
        return None
    try:
        return value.join(p[0] for p in parts if p is not None)  # type: ignore[misc]
    except TypeError:
        return None


def _method_replace_format(
    attr: str, value: str | bytes, args: list[ast.expr], ctx: _Ctx, depth: int
) -> str | bytes | None:
    """Apply ``str.replace(old, new)`` or ``str.format(*parts)``."""
    if not isinstance(value, str):
        return None
    resolved = [_dispatch(a, ctx, depth + 1) for a in args]
    if any(r is None for r in resolved):
        return None
    argv = [r[0] for r in resolved if r is not None]
    try:
        if attr == "replace" and len(argv) == _REPLACE_ARITY:
            return value.replace(argv[0], argv[1])  # type: ignore[arg-type]
        if attr == "format":
            return value.format(*argv)
    except TypeError, ValueError, IndexError, KeyError:
        return None
    return None


def _resolve_method(
    attr: str, receiver: Resolved, args: list[ast.expr], ctx: _Ctx, depth: int
) -> Resolved | None:
    """Resolve a string/bytes method call on an already-resolved *receiver*."""
    value, tags = receiver
    if attr in ("decode", "encode"):
        result = _method_recode(attr, value, args)
    elif attr == "join":
        result = _method_join(value, args, ctx, depth)
    elif attr in ("replace", "format"):
        result = _method_replace_format(attr, value, args, ctx, depth)
    else:
        return None
    if result is None:
        return None
    return result, tags | {UrlTag.VIA_DECODED}


def _resolve_codecs_decode(node: ast.Call, ctx: _Ctx, depth: int) -> Resolved | None:
    """Resolve ``codecs.decode(x, encoding)`` for a literal encoding name."""
    encoding = node.args[1]
    if not isinstance(encoding, ast.Constant) or not isinstance(encoding.value, str):
        return None
    inner = _dispatch(node.args[0], ctx, depth + 1)
    if inner is None:
        return None
    value, tags = inner
    try:
        decoded = codecs.decode(value, encoding.value)  # type: ignore[arg-type]
    except ValueError, LookupError, TypeError, binascii.Error:
        return None
    if not isinstance(decoded, str | bytes):
        return None
    return decoded, tags | {UrlTag.VIA_DECODED}


def _call_chr(node: ast.Call, _ctx: _Ctx, _depth: int) -> Resolved | None:
    """Resolve ``chr(n)`` for a literal integer codepoint."""
    if not (isinstance(node.func, ast.Name) and node.func.id == "chr"):
        return None
    if len(node.args) != 1 or not isinstance(node.args[0], ast.Constant):
        return None
    codepoint = node.args[0].value
    if not isinstance(codepoint, int):
        return None
    try:
        return chr(codepoint), frozenset({UrlTag.VIA_DECODED})
    except ValueError, OverflowError:
        return None


def _call_codecs(node: ast.Call, ctx: _Ctx, depth: int) -> Resolved | None:
    """Dispatch ``codecs.decode`` / bare ``decode(x, enc)`` calls."""
    is_codecs = qualified_name(node.func) == "codecs.decode" or (
        isinstance(node.func, ast.Name) and node.func.id == "decode"
    )
    if is_codecs and len(node.args) >= _CODECS_DECODE_ARITY:
        return _resolve_codecs_decode(node, ctx, depth)
    return None


def _call_method(node: ast.Call, ctx: _Ctx, depth: int) -> Resolved | None:
    """Dispatch a method call whose receiver resolves to a str/bytes value."""
    if not isinstance(node.func, ast.Attribute):
        return None
    receiver = _dispatch(node.func.value, ctx, depth + 1)
    if receiver is None:
        return None
    return _resolve_method(node.func.attr, receiver, node.args, ctx, depth)


def _call_decoder(node: ast.Call, ctx: _Ctx, depth: int) -> Resolved | None:
    """Dispatch a module-level byte decoder keyed by its qualified name."""
    name = qualified_name(node.func)
    decoder = _DECODERS.get(name) if name is not None else None
    if decoder is None or not node.args:
        return None
    inner = _dispatch(node.args[0], ctx, depth + 1)
    if inner is None:
        return None
    decoded = decoder(inner[0])
    if decoded is None:
        return None
    tag = UrlTag.VIA_BASE64 if name in _BASE64_NAMES else UrlTag.VIA_DECODED
    return decoded, inner[1] | {tag}


_CALL_HANDLERS: tuple[Callable[[ast.Call, _Ctx, int], Resolved | None], ...] = (
    _call_chr,
    _call_codecs,
    _call_method,
    _call_decoder,
)


def _resolve_call(node: ast.Call, ctx: _Ctx, depth: int) -> Resolved | None:
    """Try each call handler in turn; first non-``None`` result wins."""
    for handler in _CALL_HANDLERS:
        result = handler(node, ctx, depth)
        if result is not None:
            return result
    return None


def _resolve_subscript(node: ast.Subscript, ctx: _Ctx, depth: int) -> Resolved | None:
    """Resolve a full reverse slice ``x[::-1]``."""
    if not _is_reverse_slice(node):
        return None
    inner = _dispatch(node.value, ctx, depth + 1)
    if inner is None:
        return None
    return inner[0][::-1], inner[1] | {UrlTag.VIA_DECODED}


def _is_reverse_slice(node: ast.Subscript) -> bool:
    """Return ``True`` when *node* is a full reverse slice ``x[::-1]``."""
    sl = node.slice
    if not isinstance(sl, ast.Slice) or sl.lower is not None or sl.upper is not None:
        return False
    step = sl.step
    if isinstance(step, ast.UnaryOp) and isinstance(step.op, ast.USub):
        return isinstance(step.operand, ast.Constant) and step.operand.value == 1
    return isinstance(step, ast.Constant) and step.value == -1


_HANDLERS: dict[type[ast.AST], Callable[..., Resolved | None]] = {
    ast.Constant: _resolve_constant,
    ast.Name: _resolve_name,
    ast.BinOp: _resolve_binop,
    ast.JoinedStr: _resolve_joined_str,
    ast.Call: _resolve_call,
    ast.Subscript: _resolve_subscript,
}


def _dispatch(node: ast.expr, ctx: _Ctx, depth: int) -> Resolved | None:
    """Resolve *node* under *ctx*, or ``None`` if unresolvable/too deep."""
    if depth > _MAX_DEPTH:
        return None
    handler = _HANDLERS.get(type(node))
    return handler(node, ctx, depth) if handler is not None else None


def resolve_value(
    node: ast.expr, scope: Scope, at_lineno: int, depth: int = 0
) -> Resolved | None:
    """Recursively resolve *node* to a concrete str/bytes value plus method tags.

    Args:
        node: The AST expression to resolve.
        scope: Mapping ``name -> (value, assignment_lineno)`` for module-level
            string assignments, as collected by the caller.
        at_lineno: Line of the expression being resolved; ``Name`` lookups only
            succeed for assignments strictly before this line.
        depth: Current recursion depth (internal; bounded by ``_MAX_DEPTH``).

    Returns:
        ``(value, tags)`` where *tags* is the set of extraction-method
        :class:`UrlTag` s involved, or ``None`` when the node cannot be
        resolved statically.
    """
    return _dispatch(node, _Ctx(scope, at_lineno), depth)
