from __future__ import annotations

from webcheck.capture import apply_signals
from webcheck.models import Capture


def _cap() -> Capture:
    return Capture(url="https://example.com/", via="hostname")


def test_apply_signals_copies_fields() -> None:
    cap = apply_signals(
        _cap(),
        {
            "has_password": True,
            "generator": "  nginx  ",
            "headings": ["Welcome"],
            "excerpt": "hello",
        },
    )
    assert cap.has_password is True
    assert cap.generator == "nginx"
    assert cap.headings == ["Welcome"]
    assert cap.text_excerpt == "hello"


def test_apply_signals_clips_headings_and_drops_blanks() -> None:
    cap = apply_signals(
        _cap(),
        {
            "has_password": False,
            "generator": "",
            "headings": ["", "  ", "a" * 200, "ok", 123, "two", "three", "four", "five", "six"],
            "excerpt": "x" * 3000,
        },
    )
    assert cap.generator is None
    assert cap.headings[0] == "a" * 120
    assert cap.headings == [cap.headings[0], "ok", "two", "three", "four"]
    assert len(cap.headings) == 5
    assert cap.text_excerpt == "x" * 2000


def test_apply_signals_ignores_non_dict_values() -> None:
    cap = apply_signals(_cap(), {"has_password": 1, "headings": None, "excerpt": None})
    assert cap.has_password is True
    assert cap.headings == []
    assert cap.text_excerpt is None
