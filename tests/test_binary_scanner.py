"""Tests for analysis/binary_scanner.py."""

from __future__ import annotations

import datetime
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import lief
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from nidhogg.analysis.binary_scanner import (
    _macho_signature_blob,
    _macho_signer,
    _pe_signer,
    scan_binaries,
)
from nidhogg.core.models import BinaryFormat


def test_scan_binaries_ignores_non_binary_extensions(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text("hello")
    (tmp_path / "image.png").write_bytes(b"\x89PNG")

    result = scan_binaries(tmp_path)

    assert result == []


def test_scan_binaries_excludes_pycache(tmp_path: Path) -> None:
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    (cache / "cached.so").write_bytes(b"garbage")

    result = scan_binaries(tmp_path)

    assert result == []


def test_scan_binaries_finds_recursively(tmp_path: Path) -> None:
    sub = tmp_path / "native"
    sub.mkdir()
    (sub / "helper.dll").write_bytes(b"not a real pe, just bytes for hashing")

    result = scan_binaries(tmp_path)

    assert len(result) == 1
    assert result[0].name == "helper.dll"
    assert result[0].filepath == sub / "helper.dll"


def test_scan_binaries_computes_sha256(tmp_path: Path) -> None:
    import hashlib

    content = b"deterministic content for hashing"
    (tmp_path / "lib.so").write_bytes(content)

    result = scan_binaries(tmp_path)

    assert result[0].sha256 == hashlib.sha256(content).hexdigest()


def test_scan_binaries_unparseable_file_is_unknown_signed_none(
    tmp_path: Path,
) -> None:
    (tmp_path / "corrupt.dll").write_bytes(b"this is not a valid PE file at all")

    result = scan_binaries(tmp_path)

    assert result[0].format is BinaryFormat.UNKNOWN
    assert result[0].signed is None
    assert result[0].signer is None


def test_scan_binaries_unreadable_file_is_unknown_signed_none(tmp_path: Path) -> None:
    unreadable = tmp_path / "bad.dll"
    unreadable.write_bytes(b"secret bytes")
    unreadable.chmod(0o000)

    try:
        result = scan_binaries(tmp_path)
    finally:
        unreadable.chmod(0o644)

    assert len(result) == 1
    assert result[0].sha256 == ""
    assert result[0].format is BinaryFormat.UNKNOWN
    assert result[0].signed is None
    assert result[0].signer is None


def _fake_pe(
    *, has_signatures: bool, certificates: list | None = None
) -> SimpleNamespace:
    signature = SimpleNamespace(certificates=certificates or [])
    return SimpleNamespace(
        format=lief.Binary.FORMATS.PE,
        has_signatures=has_signatures,
        signatures=[signature] if has_signatures else [],
    )


def test_pe_signer_no_signature_returns_false_none() -> None:
    binary = _fake_pe(has_signatures=False)
    assert _pe_signer(binary) == (False, None)


def test_pe_signer_with_certificate_returns_subject() -> None:
    cert = SimpleNamespace(subject="CN=Example Corp")
    binary = _fake_pe(has_signatures=True, certificates=[cert])
    assert _pe_signer(binary) == (True, "CN=Example Corp")


def test_pe_signer_signed_but_no_certificates_returns_true_none() -> None:
    binary = _fake_pe(has_signatures=True, certificates=[])
    assert _pe_signer(binary) == (True, None)


def test_scan_binaries_pe_dispatches_to_pe_signer(tmp_path: Path) -> None:
    (tmp_path / "helper.dll").write_bytes(b"garbage")
    cert = SimpleNamespace(subject="CN=Example Corp")
    fake_binary = _fake_pe(has_signatures=True, certificates=[cert])

    with patch("nidhogg.analysis.binary_scanner.lief.parse", return_value=fake_binary):
        result = scan_binaries(tmp_path)

    assert result[0].format is BinaryFormat.PE
    assert result[0].signed is True
    assert result[0].signer == "CN=Example Corp"


def _fake_elf() -> SimpleNamespace:
    return SimpleNamespace(format=lief.Binary.FORMATS.ELF)


def test_scan_binaries_elf_always_unsigned(tmp_path: Path) -> None:
    (tmp_path / "libfoo.so").write_bytes(b"garbage")

    with patch("nidhogg.analysis.binary_scanner.lief.parse", return_value=_fake_elf()):
        result = scan_binaries(tmp_path)

    assert result[0].format is BinaryFormat.ELF
    assert result[0].signed is False
    assert result[0].signer is None


_SUPERBLOB_MAGIC = 0xFADE0CC0
_SIGNATURE_BLOB_MAGIC = 0xFADE0B01
_CSSLOT_SIGNATURESLOT = 0x10000
_CSSLOT_CODEDIRECTORY = 0x0


def _superblob(slots: dict[int, bytes]) -> bytes:
    """Build a minimal Mach-O SuperBlob with the given slot-type -> payload map."""
    header_size = 12 + 8 * len(slots)
    index = b""
    payload = b""
    offset = header_size
    for slot_type, data in slots.items():
        index += struct.pack(">II", slot_type, offset)
        payload += data
        offset += len(data)
    total_length = header_size + len(payload)
    header = struct.pack(">III", _SUPERBLOB_MAGIC, total_length, len(slots))
    return header + index + payload


def _signature_blob(der_cms: bytes) -> bytes:
    return struct.pack(">II", _SIGNATURE_BLOB_MAGIC, 8 + len(der_cms)) + der_cms


def _self_signed_cms() -> bytes:
    """Build a real DER PKCS7 SignedData embedding one self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Example Corp")]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1))  # noqa: DTZ001
        .not_valid_after(datetime.datetime(2030, 1, 1))  # noqa: DTZ001
        .sign(key, hashes.SHA256())
    )
    return (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(b"")
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.DetachedSignature])
    )


def _fake_macho(*, has_code_signature: bool, content: bytes = b"") -> SimpleNamespace:
    code_signature = SimpleNamespace(content=list(content))
    return SimpleNamespace(
        format=lief.Binary.FORMATS.MACHO,
        has_code_signature=has_code_signature,
        code_signature=code_signature,
    )


def test_macho_signature_blob_extracts_cms_bytes() -> None:
    cms = b"fake-der-cms-bytes"
    content = _superblob(
        {
            _CSSLOT_CODEDIRECTORY: b"cd-payload",
            _CSSLOT_SIGNATURESLOT: _signature_blob(cms),
        }
    )
    assert _macho_signature_blob(content) == cms


def test_macho_signature_blob_no_signature_slot_returns_none() -> None:
    content = _superblob({_CSSLOT_CODEDIRECTORY: b"cd-payload"})
    assert _macho_signature_blob(content) is None


def test_macho_signer_no_code_signature_returns_false_none() -> None:
    binary = _fake_macho(has_code_signature=False)
    assert _macho_signer(binary) == (False, None)


def test_macho_signer_empty_cms_is_ad_hoc() -> None:
    content = _superblob({_CSSLOT_SIGNATURESLOT: _signature_blob(b"")})
    binary = _fake_macho(has_code_signature=True, content=content)
    assert _macho_signer(binary) == (True, "ad-hoc")


def test_macho_signer_no_signature_slot_is_ad_hoc() -> None:
    content = _superblob({_CSSLOT_CODEDIRECTORY: b"cd-payload"})
    binary = _fake_macho(has_code_signature=True, content=content)
    assert _macho_signer(binary) == (True, "ad-hoc")


def test_macho_signer_real_cms_extracts_subject() -> None:
    cms = _self_signed_cms()
    content = _superblob({_CSSLOT_SIGNATURESLOT: _signature_blob(cms)})
    binary = _fake_macho(has_code_signature=True, content=content)

    signed, signer = _macho_signer(binary)

    assert signed is True
    assert "Example Corp" in signer


def test_scan_binaries_macho_dispatches_to_macho_signer(tmp_path: Path) -> None:
    (tmp_path / "helper.dylib").write_bytes(b"garbage")
    content = _superblob({_CSSLOT_SIGNATURESLOT: _signature_blob(b"")})
    fake_binary = _fake_macho(has_code_signature=True, content=content)

    with patch("nidhogg.analysis.binary_scanner.lief.parse", return_value=fake_binary):
        result = scan_binaries(tmp_path)

    assert result[0].format is BinaryFormat.MACHO
    assert result[0].signed is True
    assert result[0].signer == "ad-hoc"
