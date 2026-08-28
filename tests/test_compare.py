from __future__ import annotations

from webcheck.compare import VERDICT_ORDER, classify, fingerprint
from webcheck.models import Capture, Pair

_PHASH = "0123456789abcdef"


def cap(via: str = "hostname", **overrides) -> Capture:
    url = "https://example.com/" if via == "hostname" else "https://93.184.216.34/"
    fields = dict(
        url=url,
        via=via,
        ok=True,
        status=200,
        final_url=url,
        title="Example Domain",
        server="nginx",
        screenshot=f"{via}.png",
        phash=_PHASH,
    )
    fields.update(overrides)
    return Capture(**fields)


def pair(host: Capture | None = None, ip: Capture | None = None) -> Pair:
    return Pair(
        hostname="example.com",
        ip="93.184.216.34",
        by_hostname=host or cap("hostname"),
        by_ip=ip or cap("ip"),
    )


def test_fingerprint_default_title() -> None:
    hits = fingerprint(cap(title="Welcome to nginx!"), "hostname")
    assert hits == [("hostname looks like a default page", 25)]


def test_fingerprint_default_heading() -> None:
    hits = fingerprint(cap(title="Home", headings=["Apache2 Ubuntu Default Page"]), "IP")
    assert hits == [("IP looks like a default page", 25)]


def test_fingerprint_default_generator() -> None:
    hits = fingerprint(cap(title="Home", generator="Welcome to nginx"), "hostname")
    assert hits == [("hostname looks like a default page", 25)]


def test_fingerprint_default_excerpt() -> None:
    hits = fingerprint(
        cap(text_excerpt="If you see this page, the nginx web server is successfully installed."),
        "hostname",
    )
    assert hits == [("hostname looks like a default page", 25)]


def test_fingerprint_login() -> None:
    hits = fingerprint(cap(has_password=True), "hostname")
    assert hits == [("hostname has a login form", 15)]


def test_fingerprint_login_ignores_title_only() -> None:
    assert fingerprint(cap(title="Login"), "hostname") == []


def test_fingerprint_listing_title() -> None:
    hits = fingerprint(cap(title="Index of /foo"), "IP")
    assert hits == [("IP looks like a directory listing", 20)]


def test_fingerprint_listing_excerpt() -> None:
    hits = fingerprint(cap(text_excerpt="Parent Directory\nfile.txt"), "hostname")
    assert hits == [("hostname looks like a directory listing", 20)]


def test_fingerprint_multiple_kinds_add() -> None:
    hits = fingerprint(
        cap(title="Index of /", has_password=True),
        "hostname",
    )
    assert ("hostname looks like a directory listing", 20) in hits
    assert ("hostname has a login form", 15) in hits
    assert len(hits) == 2


def test_fingerprint_ordinary_page() -> None:
    assert fingerprint(cap(), "hostname") == []


def test_classify_matching_default_pages_are_exposed() -> None:
    result = classify(
        pair(
            cap("hostname", title="Welcome to nginx"),
            cap("ip", title="Welcome to nginx"),
        )
    )
    assert result.verdict == "exposed"
    assert "hostname looks like a default page" in result.reasons
    assert "IP looks like a default page" in result.reasons
    assert result.score == VERDICT_ORDER["exposed"] + 25 + 25


def test_classify_differs_keeps_verdict_and_records_exposure() -> None:
    result = classify(
        pair(
            cap("hostname", title="Example Domain"),
            cap("ip", title="Welcome to nginx"),
        )
    )
    assert result.verdict == "differs"
    assert "IP looks like a default page" in result.reasons
    assert result.score == VERDICT_ORDER["differs"] + 25 + 25


def test_classify_cert_err_plus_password_is_exposed() -> None:
    result = classify(
        pair(
            cap("hostname", has_password=True),
            cap("ip", tls_error=True),
        )
    )
    assert result.verdict == "exposed"
    assert "hostname has a login form" in result.reasons
    assert result.score == VERDICT_ORDER["exposed"] + 5 + 15


def test_classify_cert_err_without_fingerprint_stays_cert_err() -> None:
    result = classify(pair(cap("hostname"), cap("ip", tls_error=True)))
    assert result.verdict == "cert-err"
    assert result.score == VERDICT_ORDER["cert-err"] + 5


def test_classify_unreachable_ignores_signals() -> None:
    result = classify(
        pair(
            cap("hostname", ok=False, error="net::ERR_CONNECTION_REFUSED", has_password=True),
            cap("ip", ok=False, error="net::ERR_CONNECTION_REFUSED"),
        )
    )
    assert result.verdict == "unreachable"
    assert result.reasons[-1].startswith("both failed:")
    assert "has a login form" not in "; ".join(result.reasons)
    assert result.score == VERDICT_ORDER["unreachable"]


def test_classify_ordinary_match_is_same() -> None:
    result = classify(pair())
    assert result.verdict == "same"
    assert result.score == VERDICT_ORDER["same"]


def test_classify_listing_is_exposed() -> None:
    result = classify(
        pair(
            cap("hostname", title="Index of /foo"),
            cap("ip", title="Index of /foo"),
        )
    )
    assert result.verdict == "exposed"
    assert "hostname looks like a directory listing" in result.reasons
    assert result.score == VERDICT_ORDER["exposed"] + 20 + 20


def test_classify_password_on_matching_pair_is_exposed() -> None:
    result = classify(
        pair(
            cap("hostname", has_password=True),
            cap("ip", has_password=True),
        )
    )
    assert result.verdict == "exposed"
    assert "hostname has a login form" in result.reasons
    assert "IP has a login form" in result.reasons
    assert result.score == VERDICT_ORDER["exposed"] + 15 + 15


def test_classify_one_sided_failure_stays_differs() -> None:
    result = classify(
        pair(
            cap("hostname", title="Welcome to nginx"),
            cap("ip", ok=False, error="net::ERR_CONNECTION_REFUSED"),
        )
    )
    assert result.verdict == "differs"
    assert "hostname looks like a default page" in result.reasons
    assert result.score == VERDICT_ORDER["differs"] + 40 + 25
