"""PyPI changelog client for discovering newly published packages."""

from __future__ import annotations

import xmlrpc.client
from dataclasses import dataclass
from typing import Protocol

_PYPI_XMLRPC_URL = "https://pypi.org/pypi"
_TIMEOUT = 30.0


class _TimeoutTransport(xmlrpc.client.SafeTransport):
    """``SafeTransport`` that bounds the HTTPS connection with a timeout.

    ``xmlrpc.client.ServerProxy`` has no timeout kwarg of its own, and
    ``socket.setdefaulttimeout()`` would be a global side effect. Overriding
    ``make_connection`` to pass the timeout into the ``HTTPSConnection`` it
    creates keeps it scoped to this transport instance.
    """

    def __init__(self, timeout: float) -> None:
        super().__init__()
        self._timeout = timeout

    def make_connection(self, host: str) -> object:  # type: ignore[override]
        connection = super().make_connection(host)
        connection.timeout = self._timeout
        return connection


@dataclass(frozen=True)
class ChangelogEntry:
    """A single PyPI changelog event.

    Attributes:
        name: Package name the event applies to.
        version: Version string (empty for project-level events).
        timestamp: Unix timestamp of the event.
        action: PyPI's action label (e.g. ``"create"``, ``"new release"``).
        serial: Monotonically increasing changelog serial number.
    """

    name: str
    version: str
    timestamp: int
    action: str
    serial: int

    @property
    def is_new_project(self) -> bool:
        """Whether this event represents a brand-new project being created."""
        return self.action == "create"


class ChangelogSource(Protocol):
    """Interface for fetching PyPI changelog data (for test substitution)."""

    def current_serial(self) -> int:
        """Return the current changelog serial number."""
        ...

    def entries_since(self, serial: int) -> list[ChangelogEntry]:
        """Return every changelog event with serial greater than *serial*.

        Args:
            serial: The last known serial number.

        Returns:
            All changelog entries recorded after *serial*.
        """
        ...


class ChangelogClient:
    """Real ``ChangelogSource`` backed by the PyPI XML-RPC API."""

    def __init__(self, url: str = _PYPI_XMLRPC_URL, timeout: float = _TIMEOUT) -> None:
        """Create a client bound to *url* with a per-connection *timeout*.

        Args:
            url: PyPI XML-RPC endpoint.
            timeout: Per-connection timeout in seconds.
        """
        transport = _TimeoutTransport(timeout)
        self._proxy = xmlrpc.client.ServerProxy(url, transport=transport)

    def current_serial(self) -> int:
        """Return the current changelog serial number."""
        return int(self._proxy.changelog_last_serial())  # type: ignore[arg-type]

    def entries_since(self, serial: int) -> list[ChangelogEntry]:
        """Return every changelog event with serial greater than *serial*.

        Args:
            serial: The last known serial number.

        Returns:
            All changelog entries recorded after *serial*.
        """
        raw: list[tuple[str, str, int, str, int]] = self._proxy.changelog_since_serial(
            serial
        )  # type: ignore[assignment]
        return [ChangelogEntry(*entry) for entry in raw]
