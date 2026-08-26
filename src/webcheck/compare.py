"""Turning a capture pair into a sortable verdict.

This layer deliberately flags rather than judges: it surfaces the pairs most
likely to be worth a human glance and explains why, but never decides that a
site is fine. Every pair still ends up in the report.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .models import Pair
from .phash import hamming

# dHash distance above which two screenshots are treated as different pages.
# 64 bits total; identical renders sit at 0-2, cosmetic drift under ~8.
PHASH_DIFFERENT = 12

VERDICT_ORDER = {"differs": 400, "cert-err": 300, "unreachable": 200, "same": 100, "unknown": 0}


def _host_of(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return (urlparse(url).hostname or "").lower() or None
    except ValueError:
        return None


def classify(pair: Pair) -> Pair:
    host_cap, ip_cap = pair.by_hostname, pair.by_ip
    reasons: list[str] = []
    score = 0

    if host_cap.tls_error:
        reasons.append("hostname: TLS certificate error")
        score += 20
    if ip_cap.tls_error:
        # Expected when hitting an IP -- worth noting, but not alarming on its own.
        reasons.append("IP: TLS certificate error (SNI mismatch is normal here)")
        score += 5

    # Reachability asymmetry is the strongest signal there is.
    if not host_cap.ok and not ip_cap.ok:
        pair.verdict = "unreachable"
        pair.reasons = reasons + [f"both failed: {host_cap.error or ip_cap.error}"]
        pair.score = VERDICT_ORDER["unreachable"]
        return pair

    if host_cap.ok != ip_cap.ok:
        live, dead = ("IP", "hostname") if ip_cap.ok else ("hostname", "IP")
        reasons.append(f"{live} loaded but {dead} did not")
        pair.verdict = "differs"
        pair.reasons = reasons
        pair.score = VERDICT_ORDER["differs"] + 40
        return pair

    # Both loaded. Did the IP visit just bounce back to the hostname?
    ip_landed_on_hostname = _host_of(ip_cap.final_url) == pair.hostname.lower()
    if ip_landed_on_hostname:
        reasons.append("IP redirected to the hostname")

    if host_cap.status != ip_cap.status:
        reasons.append(f"status {host_cap.status} vs {ip_cap.status}")
        score += 15

    host_title = (host_cap.title or "").strip()
    ip_title = (ip_cap.title or "").strip()
    if host_title != ip_title:
        reasons.append(f'title "{host_title or "-"}" vs "{ip_title or "-"}"')
        score += 25

    if host_cap.server != ip_cap.server and (host_cap.server or ip_cap.server):
        reasons.append(f"server {host_cap.server or '-'} vs {ip_cap.server or '-'}")
        score += 5

    distance = hamming(host_cap.phash, ip_cap.phash)
    if distance is not None:
        if distance >= PHASH_DIFFERENT:
            reasons.append(f"screenshots differ (phash distance {distance})")
            score += 30
        else:
            reasons.append(f"screenshots look alike (phash distance {distance})")

    # A bounce back to the hostname explains away most divergence.
    if ip_landed_on_hostname:
        score = max(0, score - 25)

    visually_different = distance is not None and distance >= PHASH_DIFFERENT
    textually_different = host_title != ip_title or host_cap.status != ip_cap.status

    if visually_different or textually_different:
        pair.verdict = "differs"
        pair.score = VERDICT_ORDER["differs"] + score
    elif host_cap.tls_error or ip_cap.tls_error:
        pair.verdict = "cert-err"
        pair.score = VERDICT_ORDER["cert-err"] + score
    else:
        pair.verdict = "same"
        pair.score = VERDICT_ORDER["same"] + score

    pair.reasons = reasons
    return pair


def classify_all(pairs: list[Pair]) -> list[Pair]:
    for pair in pairs:
        classify(pair)
    return sorted(pairs, key=lambda p: (-p.score, p.hostname))
