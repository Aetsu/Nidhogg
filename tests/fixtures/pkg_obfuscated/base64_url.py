"""Fixture: URL hidden inside a base64-encoded string constant."""

import base64

_URL = base64.b64decode("aHR0cHM6Ly9jMi5ldmlsLmV4YW1wbGUuY29tL2V4ZmlsdHJhdGU=")
