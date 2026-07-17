"""Fixture: URL assembled via f-string with embedded string constants."""

# All interpolated parts are string literals — statically resolvable.
_DROP_URL = f"{'https://c2.evil.example.com'}{'/drop'}"
