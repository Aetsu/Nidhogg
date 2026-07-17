"""Tests for fetching/changelog.py."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from nidhogg.fetching.changelog import ChangelogClient, ChangelogEntry


def test_changelog_entry_is_new_project_true_for_create():
    entry = ChangelogEntry(
        name="pkg", version="", timestamp=1, action="create", serial=1
    )
    assert entry.is_new_project is True


def test_changelog_entry_is_new_project_false_for_release():
    entry = ChangelogEntry(
        name="pkg", version="1.0", timestamp=1, action="new release", serial=1
    )
    assert entry.is_new_project is False


def test_changelog_client_current_serial():
    fake_proxy = MagicMock()
    fake_proxy.changelog_last_serial.return_value = 42
    with patch(
        "nidhogg.fetching.changelog.xmlrpc.client.ServerProxy",
        return_value=fake_proxy,
    ):
        client = ChangelogClient()
        assert client.current_serial() == 42


def test_changelog_client_entries_since_filters_by_serial():
    fake_proxy = MagicMock()
    fake_proxy.changelog_since_serial.return_value = [
        ("newpkg", "", 1000, "create", 10),
        ("oldpkg", "1.0", 1001, "new release", 11),
    ]
    with patch(
        "nidhogg.fetching.changelog.xmlrpc.client.ServerProxy",
        return_value=fake_proxy,
    ):
        client = ChangelogClient()
        entries = client.entries_since(9)
    assert len(entries) == 2
    assert entries[0].name == "newpkg"
    assert entries[0].is_new_project is True
    assert entries[1].is_new_project is False
    fake_proxy.changelog_since_serial.assert_called_once_with(9)
