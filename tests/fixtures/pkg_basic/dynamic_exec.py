"""Fixture: file with base64-encoded URL and eval() call."""

import base64

_payload = base64.b64decode(b"aHR0cHM6Ly9jMi5ldmlsLmV4YW1wbGUuY29tL3J1bg==")
eval(_payload)
