"""Tests for output/renderer.py."""

from __future__ import annotations

import io
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from unittest.mock import patch

from nidhogg.core.models import (
    AnalysisLayer,
    FileAnalysis,
    FileTag,
    PackageAnalysis,
    UrlFinding,
    UrlTag,
)
from nidhogg.output.renderer import (
    make_console,
    render_countdown,
    render_empty,
    render_file_block,
    render_package_header,
    render_package_result,
    render_progress,
    render_status,
)


def _pkg(
    tmp_path: Path,
    name: str = "testpkg",
    files: list[FileAnalysis] | None = None,
) -> PackageAnalysis:
    return PackageAnalysis(name=name, path=tmp_path, files=files or [])


def _capture(*renderables: object) -> str:
    stream = io.StringIO()
    console = make_console(stream)
    for r in renderables:
        console.print(r)
    return stream.getvalue()


def test_make_console_no_ansi_when_not_a_tty():
    console = make_console(io.StringIO())
    assert console.color_system is None


def test_render_empty_shows_name_and_message(tmp_path: Path):
    text = _capture(render_empty(_pkg(tmp_path, "evilpkg")))
    assert "evilpkg" in text
    assert "no URLs found" in text
    assert "●" in text


def test_render_empty_uses_display_name_override(tmp_path: Path):
    text = _capture(render_empty(_pkg(tmp_path), display_name="override"))
    assert "override" in text


def _finding(
    tmp_path: Path,
    url: str = "https://c2.evil.example.com/beacon",
    layer: AnalysisLayer = AnalysisLayer.AST,
    lineno: int = 1,
    tags: set[UrlTag] | None = None,
) -> UrlFinding:
    return UrlFinding(
        value=url,
        filepath=tmp_path / "module.py",
        lineno=lineno,
        layer=layer,
        tags=tags or set(),
    )


def test_render_file_block_shows_line_layer_url(tmp_path: Path):
    f = _finding(tmp_path)
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "module.py" in text
    assert "1" in text
    assert "ast" in text
    assert "https://c2.evil.example.com/beacon" in text


def test_render_file_block_shows_le_tag_for_lets_encrypt(tmp_path: Path):
    f = _finding(tmp_path)
    f.cert_issuer = "Let's Encrypt"
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "[LE]" in text


def test_render_file_block_omits_le_tag_for_other_issuer(tmp_path: Path):
    f = _finding(tmp_path)
    f.cert_issuer = "DigiCert Inc"
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "[LE]" not in text


def test_render_file_block_shows_threat_tag_in_own_column(tmp_path: Path):
    f = _finding(tmp_path, tags={UrlTag.SHORTENER})
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "shortener" in text
    assert "[SHORTENER]" not in text


def test_render_file_block_shows_method_tag_in_own_column(tmp_path: Path):
    f = _finding(tmp_path, tags={UrlTag.VIA_BASE64})
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "via_base64" in text


def test_render_file_block_shows_method_and_threat_together(tmp_path: Path):
    f = _finding(tmp_path, tags={UrlTag.VIA_CONCAT, UrlTag.PUNYCODE})
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "via_concat" in text
    assert "punycode" in text


def test_render_file_block_omits_bracket_tags_when_none(tmp_path: Path):
    f = _finding(tmp_path)
    f.cert_issuer = None
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "[" not in text


def test_render_file_block_sorts_by_layer_then_url(tmp_path: Path):
    a = _finding(tmp_path, url="https://b.example.com", layer=AnalysisLayer.REGEX)
    b = _finding(tmp_path, url="https://a.example.com", layer=AnalysisLayer.AST)
    fa = FileAnalysis(tmp_path / "module.py", findings=[a, b])
    text = _capture(render_file_block(fa, tmp_path))
    assert text.index("a.example.com") < text.index("b.example.com")


def test_render_file_block_shows_relative_path_and_file_tags(tmp_path: Path):
    f = _finding(tmp_path)
    fa = FileAnalysis(tmp_path / "module.py", tags={FileTag.ENTRYPOINT}, findings=[f])
    text = _capture(render_file_block(fa, tmp_path))
    assert "module.py" in text
    assert "entrypoint" in text
    assert str(tmp_path) not in text


def test_package_header_shows_name():
    text = _capture(render_package_header("evilpkg"))
    assert "evilpkg" in text
    assert "──" in text


def test_package_result_no_findings_returns_empty_line(tmp_path: Path):
    text = _capture(render_package_result(_pkg(tmp_path)))
    assert "●" in text
    assert "no URLs found" in text


def test_package_result_shows_header_fields(tmp_path: Path):
    f = _finding(tmp_path)
    fa = FileAnalysis(tmp_path / "module.py", findings=[f])
    analysis = _pkg(tmp_path, files=[fa])
    text = _capture(render_package_result(analysis))
    assert "package  testpkg" in text
    assert "path     " in text
    assert "findings 1" in text


def test_package_result_skips_files_with_no_findings(tmp_path: Path):
    f = _finding(tmp_path, url="https://c2.evil.example.com/beacon")
    fa_with = FileAnalysis(tmp_path / "module.py", findings=[f])
    fa_empty = FileAnalysis(tmp_path / "empty.py", tags={FileTag.TEST}, findings=[])
    analysis = _pkg(tmp_path, files=[fa_with, fa_empty])
    text = _capture(render_package_result(analysis))
    assert "module.py" in text
    assert "empty.py" not in text


def test_render_package_result_shows_file_and_url_tags() -> None:
    fp = Path("/pkg/README.md")
    finding = UrlFinding(
        "http://evil.test/x", fp, 2, AnalysisLayer.REGEX, {UrlTag.SHORTENER}
    )
    analysis = PackageAnalysis(
        "pkg", Path("/pkg"), [FileAnalysis(fp, {FileTag.README}, [finding])]
    )
    console = make_console()
    with console.capture() as cap:
        console.print(render_package_result(analysis))
    out = cap.get()
    assert "README.md" in out
    assert "readme" in out
    assert "shortener" in out.lower()
    assert "evil.test" in out


def test_render_package_result_empty_when_no_findings() -> None:
    analysis = PackageAnalysis("pkg", Path("/pkg"), [])
    console = make_console()
    with console.capture() as cap:
        console.print(render_package_result(analysis))
    assert "no URLs found" in cap.get()


def test_render_progress_returns_progress_with_console():
    console = make_console(io.StringIO())
    progress = render_progress(console=console)
    assert progress.console is console
    assert hasattr(progress, "add_task")


def test_render_status_yields_and_uses_console_status():
    console = make_console(io.StringIO())
    calls: list[str] = []

    @contextmanager
    def fake_status(msg: str) -> Iterator[None]:
        calls.append(msg)
        yield

    with (
        patch.object(console, "status", fake_status),
        render_status("Comprobando PyPI...", console=console),
    ):
        pass
    assert len(calls) == 1
    assert calls[0] == "Comprobando PyPI..."


def test_render_countdown_negative_interval_calls_sleep_once_and_returns():
    console = make_console(io.StringIO())
    calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)

    with patch("time.sleep", fake_sleep):
        render_countdown(-5, console=console)
    assert calls == [-5]


def test_render_countdown_zero_interval_calls_sleep_once():
    console = make_console(io.StringIO())
    calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)

    with patch("time.sleep", fake_sleep):
        render_countdown(0, console=console)
    assert calls == [0]


def test_render_countdown_positive_ticks_each_second():
    console = make_console(io.StringIO())
    calls: list[float] = []

    def fake_sleep(seconds: float) -> None:
        calls.append(seconds)
        if len(calls) >= 2:
            raise KeyboardInterrupt

    with patch("time.sleep", fake_sleep), suppress(KeyboardInterrupt):
        render_countdown(10, console=console)
    assert calls[0] == 1


def test_render_file_block_shows_http_status_and_title() -> None:
    from rich.console import Console

    pkg = Path("pkg")
    fa = FileAnalysis(
        filepath=pkg / "evil.py",
        findings=[
            UrlFinding(
                value="http://example.com",
                filepath=pkg / "evil.py",
                lineno=1,
                layer=AnalysisLayer.REGEX,
                http_status=200,
                http_title="Home Page",
            )
        ],
    )
    console = Console(color_system=None, width=200)
    with console.capture() as cap:
        console.print(render_file_block(fa, pkg))
    out = cap.get()
    assert "[200]" in out
    assert "Home Page" in out
