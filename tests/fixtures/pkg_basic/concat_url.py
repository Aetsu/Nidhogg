"""Fixture: URL built by concatenating two string literals."""

_BASE = "https://c2.evil.example.com"
_PATH = "/exfil"

# Inline concatenation without variable tracking
ENDPOINT = "https://c2.evil.example.com" + "/exfil"
