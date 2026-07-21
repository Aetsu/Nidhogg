"""Fixture: a dropper hiding its C2 endpoint behind stacked decoders.

Every branch below resolves statically to the same C2 endpoint. The benign
documentation link is listed on a domain that ``benign_domains.txt`` treats as
noise and must NOT appear in the findings.
"""

import base64
import binascii
import codecs

# Benign docs URL — filtered out by the benign list (systemd.io).
DOCS = "https://systemd.io/CREDENTIALS"

# Hex-encoded, then decoded to text.
_C2_HEX = bytes.fromhex(
    "68747470733a2f2f63322e64726f707065722d746573742e6e65742f7061796c6f6164"
).decode()

# base64 wrapping a rot13 layer — a two-decoder chain.
_C2_NESTED = codecs.decode(
    base64.b64decode("dWdnY2Y6Ly9wMi5xZWJjY3JlLWdyZmcuYXJnL2NubHlibnE=").decode(),
    "rot_13",
)

# Assembled from a list of literal fragments (the join is the point — noqa).
_C2_JOINED = "".join(["https://", "c2.dropper", "-test.net", "/payload"])  # noqa: FLY002


def beacon() -> None:
    """Pretend to phone home; unused here beyond referencing the payloads."""
    for target in (_C2_HEX, _C2_NESTED, _C2_JOINED):
        _ = binascii.hexlify(target.encode())
