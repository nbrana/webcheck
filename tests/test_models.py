from __future__ import annotations

import json
from pathlib import Path

from webcheck.models import Capture, Pair, read_results, write_results

_PHASH = "0123456789abcdef"


def _capture(via: str, **overrides) -> Capture:
    url = "https://example.com/" if via == "hostname" else "https://93.184.216.34/"
    fields = dict(
        url=url,
        via=via,
        ok=True,
        status=200,
        final_url=url,
        title="Example Domain",
        screenshot=f"{via}.png",
        phash=_PHASH,
    )
    fields.update(overrides)
    return Capture(**fields)


def _pair(**overrides) -> Pair:
    return Pair(
        hostname="example.com",
        ip="93.184.216.34",
        by_hostname=_capture("hostname"),
        by_ip=_capture("ip"),
        **overrides,
    )


def test_roundtrip_preserves_page_signals(tmp_path: Path) -> None:
    original = _pair()
    original.by_hostname.has_password = True
    original.by_hostname.generator = "nginx"
    original.by_hostname.headings = ["Welcome"]
    original.by_hostname.text_excerpt = "If you see this page"
    original.by_ip.headings = []
    write_results([original], tmp_path)
    loaded = read_results(tmp_path)
    assert len(loaded) == 1
    host = loaded[0].by_hostname
    assert host.has_password is True
    assert host.generator == "nginx"
    assert host.headings == ["Welcome"]
    assert host.text_excerpt == "If you see this page"
    assert loaded[0].by_ip.has_password is False
    assert loaded[0].by_ip.headings == []


def test_read_results_legacy_json_without_signal_fields(tmp_path: Path) -> None:
    payload = {
        "pairs": [
            {
                "hostname": "example.com",
                "ip": "93.184.216.34",
                "by_hostname": {
                    "url": "https://example.com/",
                    "via": "hostname",
                    "ok": True,
                    "status": 200,
                    "final_url": "https://example.com/",
                    "title": "Example Domain",
                    "server": None,
                    "redirects": [],
                    "screenshot": "hostname.png",
                    "phash": _PHASH,
                    "error": None,
                    "tls_error": False,
                },
                "by_ip": {
                    "url": "https://93.184.216.34/",
                    "via": "ip",
                    "ok": True,
                    "status": 200,
                    "final_url": "https://93.184.216.34/",
                    "title": "Example Domain",
                    "server": None,
                    "redirects": [],
                    "screenshot": "ip.png",
                    "phash": _PHASH,
                    "error": None,
                    "tls_error": False,
                },
                "verdict": "same",
                "reasons": [],
                "score": 100,
            }
        ]
    }
    (tmp_path / "results.json").write_text(json.dumps(payload))
    loaded = read_results(tmp_path)
    host = loaded[0].by_hostname
    assert host.has_password is False
    assert host.generator is None
    assert host.headings == []
    assert host.text_excerpt is None
