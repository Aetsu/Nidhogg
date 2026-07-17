"""Custom exceptions for the Nidhogg analysis pipeline."""

from __future__ import annotations


class NidhoggError(Exception):
    """Base exception for all Nidhogg errors."""


class PackageReadError(NidhoggError):
    """Raised when a package directory or file cannot be read."""


class ParseError(NidhoggError):
    """Raised when a source file cannot be parsed (syntax errors, encoding issues)."""
