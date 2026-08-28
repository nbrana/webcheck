from __future__ import annotations

from pathlib import Path

from webcheck.models import Capture, Pair
from webcheck.report import build_report

_PHASH = "0123456789abcdef"


def test_report_surfaces_exposed_pairs(tmp_path: Path) -> None:
    pair = Pair(
        hostname="example.com",
        ip="93.184.216.34",
        by_hostname=Capture(
            url="https://example.com/",
            via="hostname",
            ok=True,
            title="Welcome to nginx",
            screenshot="host.png",
            phash=_PHASH,
        ),
        by_ip=Capture(
            url="https://93.184.216.34/",
            via="ip",
            ok=True,
            title="Welcome to nginx",
            screenshot="ip.png",
            phash=_PHASH,
        ),
        verdict="exposed",
        reasons=["hostname looks like a default page"],
        score=400,
    )
    path = build_report([pair], tmp_path)
    html = path.read_text()
    assert "--exposed:" in html
    assert 'data-filter="exposed"' in html
    assert 'class="tag exposed"' in html
    assert "exposed" in html
    assert '<details class="pair" data-verdict="exposed" open>' in html
