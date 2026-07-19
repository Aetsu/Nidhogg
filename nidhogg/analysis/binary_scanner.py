"""Binary scanner: detect native binaries in a package and check signatures.

Walks a package directory for known executable/library extensions, hashes
each file, and uses LIEF to detect its format (PE/Mach-O/ELF) and — where
possible — whether it carries an embedded signature.
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING, Any, cast

import lief
from cryptography.hazmat.primitives.serialization import pkcs7
from loguru import logger

from nidhogg.core.models import BinaryFinding, BinaryFormat

if TYPE_CHECKING:
    from pathlib import Path

_BINARY_SUFFIXES = frozenset({".exe", ".dll", ".pyd", ".so", ".dylib", ".a", ".o"})
_HASH_CHUNK_SIZE = 65536

_LIEF_FORMAT_MAP = {
    lief.Binary.FORMATS.PE: BinaryFormat.PE,
    lief.Binary.FORMATS.ELF: BinaryFormat.ELF,
    lief.Binary.FORMATS.MACHO: BinaryFormat.MACHO,
}


def _is_binary_whitelisted(path: Path) -> bool:
    """Return ``True`` if *path*'s extension is a known binary format."""
    return path.suffix.lower() in _BINARY_SUFFIXES


def _collect_binary_files(root: Path) -> list[Path]:
    """Return every whitelisted binary file under *root*, recursively."""
    return [
        p
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and _is_binary_whitelisted(p)
    ]


def _sha256_file(path: Path) -> str:
    """Compute the hex-encoded SHA-256 digest of *path*'s contents."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pe_signer(binary: Any) -> tuple[bool, str | None]:  # noqa: ANN401
    """Extract Authenticode signer info from a parsed PE binary.

    Takes the first certificate of the first signature — good enough for a
    static "is it signed and by whom" signal; no chain-of-trust validation.

    Args:
        binary: A parsed ``lief.PE.Binary``. Typed as ``Any`` because LIEF's
            C++-bound duck-typed objects don't map cleanly onto Python's
            static type system — the format-specific attributes accessed
            here (``has_signatures``, ``signatures``) aren't declared on any
            common base class.
    """
    if not binary.has_signatures:
        return False, None
    certificates = binary.signatures[0].certificates
    if not certificates:
        return True, None
    return True, str(certificates[0].subject)


_MACHO_SIGNATURE_SLOT = 0x10000


def _macho_signature_blob(content: bytes) -> bytes | None:
    """Extract the raw CMS bytes from a Mach-O code-signature SuperBlob.

    Args:
        content: Raw bytes of ``binary.code_signature.content``.

    Returns:
        The DER-encoded CMS payload, or ``None`` if the SuperBlob has no
        signature slot (or is too short to be a valid SuperBlob).
    """
    if len(content) < 12:  # noqa: PLR2004
        return None
    _magic, _length, count = struct.unpack(">III", content[:12])
    offset = 12
    for _ in range(count):
        if offset + 8 > len(content):
            return None
        slot_type, slot_offset = struct.unpack(">II", content[offset : offset + 8])
        offset += 8
        if slot_type == _MACHO_SIGNATURE_SLOT:
            if slot_offset + 8 > len(content):
                return None
            _blob_magic, blob_length = struct.unpack(
                ">II", content[slot_offset : slot_offset + 8]
            )
            return content[slot_offset + 8 : slot_offset + blob_length]
    return None


def _macho_signer(binary: Any) -> tuple[bool, str | None]:  # noqa: ANN401
    """Extract Mach-O code-signing info from a parsed binary.

    Ad-hoc signing (no real certificate — common for locally compiled
    binaries) is reported as ``signer="ad-hoc"``, distinct from a genuine
    certificate subject and from "not signed at all".

    Args:
        binary: A parsed ``lief.MachO.Binary``. Typed as ``Any`` for the
            same reason as :func:`_pe_signer` — ``has_code_signature`` and
            ``code_signature`` are Mach-O-specific, not on a shared base.
    """
    if not binary.has_code_signature:
        return False, None

    content = bytes(binary.code_signature.content)
    cms = _macho_signature_blob(content)
    if not cms:
        return True, "ad-hoc"

    try:
        certificates = pkcs7.load_der_pkcs7_certificates(cms)
    except Exception:  # noqa: BLE001
        return True, "ad-hoc"

    if not certificates:
        return True, "ad-hoc"
    return True, str(certificates[0].subject)


def _signature_for(binary: Any, fmt: BinaryFormat) -> tuple[bool | None, str | None]:  # noqa: ANN401
    """Dispatch to the per-format signature extractor.

    Args:
        binary: The parsed LIEF binary object (``lief.PE.Binary`` /
            ``lief.MachO.Binary`` / ``lief.ELF.Binary``). Typed as ``Any``
            because it's forwarded verbatim to :func:`_pe_signer` /
            :func:`_macho_signer`, which need ``Any`` themselves.
        fmt: The format already resolved from ``binary.format``.

    Returns:
        A ``(signed, signer)`` tuple. ``UNKNOWN`` format returns
        ``(None, None)`` — undetermined, not "unsigned".
    """
    if fmt is BinaryFormat.PE:
        return _pe_signer(binary)
    if fmt is BinaryFormat.MACHO:
        return _macho_signer(binary)
    if fmt is BinaryFormat.ELF:
        return False, None
    return None, None


def _scan_one(path: Path) -> BinaryFinding:
    """Hash and format-detect a single binary file."""
    try:
        sha256 = _sha256_file(path)
    except OSError as exc:
        logger.warning("Skipping unreadable binary {}: {}", path, exc)
        return BinaryFinding(
            name=path.name,
            filepath=path,
            sha256="",
            format=BinaryFormat.UNKNOWN,
            signed=None,
            signer=None,
        )

    try:
        binary = lief.parse(str(path))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not parse binary {}: {}", path, exc)
        binary = None

    if binary is None:
        return BinaryFinding(
            name=path.name,
            filepath=path,
            sha256=sha256,
            format=BinaryFormat.UNKNOWN,
            signed=None,
            signer=None,
        )

    fmt = _LIEF_FORMAT_MAP.get(cast("lief.Binary", binary).format, BinaryFormat.UNKNOWN)
    try:
        signed, signer = _signature_for(binary, fmt)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not read signature of {}: {}", path, exc)
        signed, signer = None, None

    return BinaryFinding(
        name=path.name,
        filepath=path,
        sha256=sha256,
        format=fmt,
        signed=signed,
        signer=signer,
    )


def scan_binaries(root: Path) -> list[BinaryFinding]:
    """Scan *root* for known binary files and analyse each one.

    Args:
        root: Package directory to scan, recursively.

    Returns:
        One :class:`BinaryFinding` per whitelisted binary file found.
    """
    return [_scan_one(p) for p in _collect_binary_files(root)]
