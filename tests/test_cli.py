from __future__ import annotations

from webcheck.cli import summary_line
from webcheck.models import Capture, Pair

_PHASH = "0123456789abcdef"


def _pair(verdict: str) -> Pair:
    host = Capture(
        url="https://example.com/",
        via="hostname",
        ok=True,
        title="Example",
        phash=_PHASH,
    )
    ip = Capture(
        url="https://93.184.216.34/",
        via="ip",
        ok=True,
        title="Example",
        phash=_PHASH,
    )
    return Pair(
        hostname="example.com",
        ip="93.184.216.34",
        by_hostname=host,
        by_ip=ip,
        verdict=verdict,
    )


def test_summary_line_counts_differs_and_exposed() -> None:
    pairs = [_pair("differs"), _pair("exposed"), _pair("same"), _pair("exposed")]
    assert summary_line(pairs) == "1 of 4 pair(s) flagged as differing, 2 as exposed."
