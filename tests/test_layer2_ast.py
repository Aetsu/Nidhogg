"""Tests for analysis/layer2_ast.py — basic and obfuscated AST patterns."""

from __future__ import annotations

from pathlib import Path

from nidhogg.analysis.layer2_ast import extract_urls_ast
from nidhogg.core.models import AnalysisLayer, UrlTag

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "pkg_basic"
OBFUSCATED_DIR = Path(__file__).parent / "fixtures" / "pkg_obfuscated"


def _findings(source: str, tmp_path: Path) -> list[str]:
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    return [f.value for f in findings]


# ---------------------------------------------------------------------------
# ast.Constant — string literal containing a URL
# ---------------------------------------------------------------------------


def test_constant_url_detected(tmp_path: Path):
    source = 'C2 = "https://evil.example.com/beacon"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert len(findings) == 1
    assert findings[0].value == "https://evil.example.com/beacon"


def test_constant_url_has_no_tags(tmp_path: Path):
    source = 'url = "https://evil.example.com"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert findings[0].tags == set()


def test_constant_url_layer_is_ast(tmp_path: Path):
    source = 'url = "https://evil.example.com"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert findings[0].layer is AnalysisLayer.AST


def test_constant_url_lineno(tmp_path: Path):
    source = "x = 1\nurl = 'https://evil.example.com'"
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert findings[0].lineno == 2


def test_constant_url_embedded_in_longer_string(tmp_path: Path):
    source = 'msg = "connecting to https://evil.example.com/api ok"'
    urls = _findings(source, tmp_path)
    assert "https://evil.example.com/api" in urls


def test_constant_no_url_returns_empty(tmp_path: Path):
    source = 'msg = "hello world"'
    assert _findings(source, tmp_path) == []


def test_fixture_constant_url(tmp_path: Path):
    source = (FIXTURE_DIR / "constant_url.py").read_text()
    urls = _findings(source, tmp_path)
    assert "https://c2.evil.example.com/beacon" in urls


def test_constant_url_truncated_at_glued_brace(tmp_path: Path):
    source = 'url = "https://api.telegram.org/bot{token}"'
    urls = _findings(source, tmp_path)
    assert urls == ["https://api.telegram.org/bot"]


def test_constant_url_truncated_at_glued_quote(tmp_path: Path):
    source = "msg = 'call feedparser.parse(\\'https://hnrss.org/frontpage\\').entries'"
    urls = _findings(source, tmp_path)
    assert urls == ["https://hnrss.org/frontpage"]


# ---------------------------------------------------------------------------
# ast.BinOp — constant folding of Constant + Constant
# ---------------------------------------------------------------------------


def test_concat_two_constants_detected(tmp_path: Path):
    source = 'ep = "https://evil.example.com" + "/exfil"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert len(findings) == 1
    assert findings[0].value == "https://evil.example.com/exfil"


def test_concat_url_tagged_via_concat(tmp_path: Path):
    source = 'ep = "https://evil.example.com" + "/exfil"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert UrlTag.VIA_CONCAT in findings[0].tags


def test_concat_no_double_count(tmp_path: Path):
    """The two partial strings must not appear as separate findings."""
    source = 'ep = "https://evil.example.com" + "/exfil"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    values = [f.value for f in findings]
    assert values == ["https://evil.example.com/exfil"]


def test_concat_non_url_strings_ignored(tmp_path: Path):
    source = 'x = "hello" + " world"'
    assert _findings(source, tmp_path) == []


def test_concat_right_side_not_constant_falls_through(tmp_path: Path):
    """If one operand is not a Constant, the folded result is not produced
    but the URL-bearing Constant side is still detected."""
    source = 'ep = "https://evil.example.com" + path'
    urls = _findings(source, tmp_path)
    # The left constant still contains a URL — detected via visit_Constant
    assert "https://evil.example.com" in urls


def test_fixture_concat_url(tmp_path: Path):
    source = (FIXTURE_DIR / "concat_url.py").read_text()
    urls = _findings(source, tmp_path)
    assert "https://c2.evil.example.com/exfil" in urls


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_syntax_error_returns_empty(tmp_path: Path):
    source = "def broken(:"
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert findings == []


def test_empty_source_returns_empty(tmp_path: Path):
    findings, _ = extract_urls_ast("", tmp_path / "f.py")
    assert findings == []


# ---------------------------------------------------------------------------
# base64.b64decode() — Phase 6
# ---------------------------------------------------------------------------


def test_base64_b64decode_attribute_detects_url(tmp_path: Path):
    source = 'import base64\nurl = base64.b64decode("aHR0cHM6Ly9ldmlsLmNvbQ==")'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert any(f.value == "https://evil.com" for f in findings)


def test_base64_b64decode_name_detects_url(tmp_path: Path):
    source = 'from base64 import b64decode\nurl = b64decode("aHR0cHM6Ly9ldmlsLmNvbQ==")'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert any(f.value == "https://evil.com" for f in findings)


def test_base64_bytes_constant_detects_url(tmp_path: Path):
    source = 'import base64\nurl = base64.b64decode(b"aHR0cHM6Ly9ldmlsLmNvbQ==")'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert any(f.value == "https://evil.com" for f in findings)


def test_base64_url_tagged_via_base64(tmp_path: Path):
    source = 'import base64\nurl = base64.b64decode("aHR0cHM6Ly9ldmlsLmNvbQ==")'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    b64_findings = [f for f in findings if UrlTag.VIA_BASE64 in f.tags]
    assert len(b64_findings) == 1


def test_base64_non_url_payload_ignored(tmp_path: Path):
    # base64 of "just some text"
    source = 'import base64\ndata = base64.b64decode("anVzdCBzb21lIHRleHQ=")'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    b64_findings = [f for f in findings if UrlTag.VIA_BASE64 in f.tags]
    assert b64_findings == []


def test_base64_invalid_encoding_ignored(tmp_path: Path):
    source = 'import base64\ndata = base64.b64decode("not-valid-base64!!!")'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert not any(UrlTag.VIA_BASE64 in f.tags for f in findings)


def test_fixture_base64_url(tmp_path: Path):
    source = (OBFUSCATED_DIR / "base64_url.py").read_text()
    findings, _ = extract_urls_ast(source, tmp_path / "base64_url.py")
    b64_findings = [f for f in findings if UrlTag.VIA_BASE64 in f.tags]
    assert any("exfiltrate" in f.value for f in b64_findings)


# ---------------------------------------------------------------------------
# ast.JoinedStr (f-strings) — Phase 6
# ---------------------------------------------------------------------------


def test_fstring_all_literal_parts_resolved(tmp_path: Path):
    source = "url = f\"{'https://evil.example.com'}{'/path'}\""
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    fstr_findings = [f for f in findings if UrlTag.VIA_FSTRING in f.tags]
    assert any(f.value == "https://evil.example.com/path" for f in fstr_findings)


def test_fstring_tagged_via_fstring(tmp_path: Path):
    source = "url = f\"{'https://evil.example.com'}{'/path'}\""
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert any(UrlTag.VIA_FSTRING in f.tags for f in findings)


def test_fstring_with_name_reference_not_resolved_as_fstring(tmp_path: Path):
    """f-strings with variable references are not resolvable in Phase 6."""
    source = 'host = "evil.example.com"\nurl = f"https://{host}/path"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    fstr_findings = [f for f in findings if UrlTag.VIA_FSTRING in f.tags]
    assert fstr_findings == []


def test_fstring_no_double_count(tmp_path: Path):
    """A resolved f-string must not also emit findings for its inner Constants."""
    source = "url = f\"{'https://evil.example.com'}{'/path'}\""
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    # Only the joined result should appear, not the partial strings
    assert sum(1 for f in findings if "evil.example.com" in f.value) == 1


def test_fixture_fstring_url(tmp_path: Path):
    source = (OBFUSCATED_DIR / "fstring_url.py").read_text()
    findings, _ = extract_urls_ast(source, tmp_path / "fstring_url.py")
    fstr_findings = [f for f in findings if UrlTag.VIA_FSTRING in f.tags]
    assert any("drop" in f.value for f in fstr_findings)


# ---------------------------------------------------------------------------
# Scope tracking — Phase 7
# ---------------------------------------------------------------------------


def test_scope_fstring_variable_assigned_before_use(tmp_path: Path):
    """Variable assigned before the f-string is resolved via scope tracking."""
    source = 'host = "c2.evil.example.com"\nurl = f"https://{host}/beacon"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    scope_findings = [f for f in findings if UrlTag.VIA_SCOPE in f.tags]
    assert any(f.value == "https://c2.evil.example.com/beacon" for f in scope_findings)


def test_scope_fstring_variable_before_assignment_not_resolved(tmp_path: Path):
    """Variable used before its assignment must not be resolved."""
    source = 'url = f"https://{host}/beacon"\nhost = "c2.evil.example.com"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    scope_findings = [f for f in findings if UrlTag.VIA_SCOPE in f.tags]
    assert scope_findings == []


def test_scope_chaining(tmp_path: Path):
    """``b = a + suffix`` where ``a`` is itself a resolved variable."""
    source = 'base = "https://c2.evil.example.com"\nurl = base + "/exfil"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    scope_findings = [f for f in findings if UrlTag.VIA_SCOPE in f.tags]
    assert any(f.value == "https://c2.evil.example.com/exfil" for f in scope_findings)


def test_scope_binop_name_plus_constant(tmp_path: Path):
    """``name + literal`` resolves when the name is in scope."""
    source = 'host = "c2.evil.example.com/path"\nurl = "https://" + host'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    scope_findings = [f for f in findings if UrlTag.VIA_SCOPE in f.tags]
    assert any("c2.evil.example.com" in f.value for f in scope_findings)


def test_scope_tagged_via_scope(tmp_path: Path):
    source = 'host = "c2.evil.example.com"\nurl = f"https://{host}/path"'
    findings, _ = extract_urls_ast(source, tmp_path / "f.py")
    assert any(UrlTag.VIA_SCOPE in f.tags for f in findings)


# ---------------------------------------------------------------------------
# Dynamic execution detection
# ---------------------------------------------------------------------------


def test_concat_url_tagged_via_concat_only_tag() -> None:
    findings, _ = extract_urls_ast('u = "http://evil" + ".test/x"\n', Path("a.py"))
    assert findings
    assert UrlTag.VIA_CONCAT in findings[0].tags


def test_plain_constant_url_has_no_tags() -> None:
    findings, _ = extract_urls_ast('u = "http://evil.test/x"\n', Path("a.py"))
    assert findings[0].tags == set()


def test_eval_sets_dynamic_exec_flag() -> None:
    _, dyn = extract_urls_ast('eval("1+1")\n', Path("a.py"))
    assert dyn is True


def test_exec_sets_dynamic_exec_flag() -> None:
    _, dyn = extract_urls_ast('exec("x=1")\n', Path("a.py"))
    assert dyn is True


def test_compile_sets_dynamic_exec_flag() -> None:
    _, dyn = extract_urls_ast('compile("x=1", "<string>", "exec")\n', Path("a.py"))
    assert dyn is True


def test_no_dynamic_exec_flag_when_absent() -> None:
    _, dyn = extract_urls_ast('u = "http://x.test"\n', Path("a.py"))
    assert dyn is False
