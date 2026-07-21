"""Tests for analysis/deobfuscate.py — recursive value resolver."""

from __future__ import annotations

import ast

from nidhogg.analysis.deobfuscate import Scope, resolve_value
from nidhogg.core.models import UrlTag


def _expr(source: str) -> ast.expr:
    """Parse *source* as a single expression and return its AST node."""
    module = ast.parse(source, mode="eval")
    return module.body


def _resolve(
    source: str, scope: Scope | None = None
) -> tuple[str | bytes, set[UrlTag]] | None:
    node = _expr(source)
    result = resolve_value(node, scope or {}, at_lineno=10_000)
    if result is None:
        return None
    value, tags = result
    return value, set(tags)


# ---------------------------------------------------------------------------
# Base cases
# ---------------------------------------------------------------------------


def test_string_constant_resolves_to_itself():
    assert _resolve('"https://evil.example.com"') == ("https://evil.example.com", set())


def test_bytes_constant_resolves_to_itself():
    assert _resolve('b"payload"') == (b"payload", set())


def test_non_string_constant_returns_none():
    assert _resolve("42") is None


def test_constant_concat_tagged_via_concat():
    value, tags = _resolve('"https://" + "evil.com"')
    assert value == "https://evil.com"
    assert tags == {UrlTag.VIA_CONCAT}


def test_name_from_scope_tagged_via_scope():
    scope: Scope = {"host": ("evil.com", 1)}
    value, tags = _resolve("host", scope)
    assert value == "evil.com"
    assert tags == {UrlTag.VIA_SCOPE}


def test_name_not_in_scope_returns_none():
    assert _resolve("undefined_name") is None


def test_fstring_all_literal_tagged_via_fstring():
    value, tags = _resolve("f\"https://{'evil'}.com\"")
    assert value == "https://evil.com"
    assert tags == {UrlTag.VIA_FSTRING}


def test_fstring_with_scope_name_tagged_via_scope():
    scope: Scope = {"host": ("evil.com", 0)}  # assigned before the f-string's line
    value, tags = _resolve('f"https://{host}"', scope)
    assert value == "https://evil.com"
    assert tags == {UrlTag.VIA_SCOPE}


# ---------------------------------------------------------------------------
# Encodings
# ---------------------------------------------------------------------------


def test_hex_via_bytes_fromhex():
    payload = b"https://evil.com".hex()
    value, tags = _resolve(f'bytes.fromhex("{payload}")')
    assert value == b"https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_hex_via_binascii_unhexlify():
    payload = b"https://evil.com".hex()
    value, tags = _resolve(f'binascii.unhexlify("{payload}")')
    assert value == b"https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_rot13_via_codecs_decode():
    import codecs

    payload = codecs.encode("https://evil.com", "rot_13")
    value, tags = _resolve(f'codecs.decode("{payload}", "rot_13")')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_base64_keeps_via_base64_tag():
    import base64

    payload = base64.b64encode(b"https://evil.com").decode()
    value, tags = _resolve(f'base64.b64decode("{payload}")')
    assert value == b"https://evil.com"
    assert UrlTag.VIA_BASE64 in tags


def test_bytes_decode_method():
    payload = b"https://evil.com".hex()
    value, tags = _resolve(f'bytes.fromhex("{payload}").decode()')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


# ---------------------------------------------------------------------------
# Compression
# ---------------------------------------------------------------------------


def test_zlib_decompress():
    import zlib

    payload = zlib.compress(b"https://evil.com").hex()
    value, tags = _resolve(f'zlib.decompress(bytes.fromhex("{payload}"))')
    assert value == b"https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_gzip_decompress():
    import gzip

    payload = gzip.compress(b"https://evil.com").hex()
    value, tags = _resolve(f'gzip.decompress(bytes.fromhex("{payload}"))')
    assert value == b"https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_decompression_bomb_over_limit_returns_none():
    import zlib

    bomb = zlib.compress(b"A" * (6 * 1024 * 1024)).hex()
    assert _resolve(f'zlib.decompress(bytes.fromhex("{bomb}"))') is None


# ---------------------------------------------------------------------------
# String composition
# ---------------------------------------------------------------------------


def test_str_join_of_literals():
    value, tags = _resolve('"".join(["https:", "//evil", ".com"])')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_str_format():
    value, tags = _resolve('"https://{}.com".format("evil")')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_percent_format():
    value, tags = _resolve('"https://%s.com" % "evil"')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_str_replace():
    value, tags = _resolve('"https://evilXXcom".replace("XX", ".")')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_reverse_slice():
    value, tags = _resolve('"moc.live//:sptth"[::-1]')
    assert value == "https://evil.com"
    assert UrlTag.VIA_DECODED in tags


def test_chr_concatenation():
    value, tags = _resolve("chr(104) + chr(116) + chr(116) + chr(112)")
    assert value == "http"
    assert UrlTag.VIA_DECODED in tags


# ---------------------------------------------------------------------------
# Nesting
# ---------------------------------------------------------------------------


def test_nested_base64_over_rot13():
    import base64
    import codecs

    inner = codecs.encode("https://evil.com", "rot_13")
    payload = base64.b64encode(inner.encode()).decode()
    value, tags = _resolve(
        f'codecs.decode(base64.b64decode("{payload}").decode(), "rot_13")'
    )
    assert value == "https://evil.com"
    assert UrlTag.VIA_BASE64 in tags
    assert UrlTag.VIA_DECODED in tags


def test_depth_limit_stops_resolution():
    # Deeply nested concatenation beyond _MAX_DEPTH must not resolve.
    expr = '"a"' + ' + "a"' * 40
    # 40 nested BinOps > _MAX_DEPTH (8) → None rather than crashing.
    assert _resolve(expr) is None


# ---------------------------------------------------------------------------
# Security: never deserialize
# ---------------------------------------------------------------------------


def test_marshal_loads_never_resolved():
    assert _resolve('marshal.loads(b"anything")') is None


def test_pickle_loads_never_resolved():
    assert _resolve('pickle.loads(b"anything")') is None
