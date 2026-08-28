# Exposed Verdict Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an `exposed` verdict for landing pages that look like default installs, login forms, or directory listings, without changing hostname-vs-IP comparison.

**Architecture:** Capture stores compact DOM facts on each `Capture`. `compare.fingerprint` turns those facts into reasons and score bumps. `classify` upgrades `same` and `cert-err` to `exposed` when any fingerprint hits; `differs` and `unreachable` stay as they are. `webcheck report` can retune fingerprints without recapturing.

**Tech Stack:** Python 3.14, pytest, Playwright (capture only; no browser in tests), existing Pillow dHash pipeline.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-27-exposed-verdict-design.md`
- Tests run with `uv run pytest` and must not launch a browser
- Add pytest with `uv add --dev pytest`; do not hand-edit `uv.lock`
- Verdict string is exactly `exposed`
- `VERDICT_ORDER["exposed"]` is `350` (between `differs` 400 and `cert-err` 300)
- No `exposure` field on `Pair`; kind lives only in `reasons`
- Reason strings, verbatim:
  - `"{leg} looks like a default page"` (`leg` is `hostname` or `IP`)
  - `"{leg} has a login form"`
  - `"{leg} looks like a directory listing"`
- Score bumps: default-page +25, listing +20, login +15; apply on every hit, including `differs` pairs
- Fingerprint needles are case-insensitive; listing uses `startswith("index of")` on title and each heading
- Login is `has_password` only — a title of `Login` without a password field is not `exposed`
- Capture extraction is top-frame only; Playwright errors during extraction must not fail the capture
- Clip headings to 5 × 120 chars; clip excerpt to 2000 chars
- CLI summary line, verbatim: `"{n} of {m} pair(s) flagged as differing, {p} as exposed."`
- Do not probe extra paths, add HTTP captures, or classify at capture time

## File Structure

- `src/webcheck/models.py` — add four optional fields on `Capture`
- `src/webcheck/compare.py` — `fingerprint()`, `VERDICT_ORDER["exposed"]`, classify upgrade rules
- `src/webcheck/capture.py` — `apply_signals()`, `_SIGNALS_JS`, call from `_render`
- `src/webcheck/report.py` — purple `--exposed` color, filter order, start expanded
- `src/webcheck/cli.py` — `_MARK["exposed"]`, `summary_line()`
- `tests/test_models.py` — legacy JSON + roundtrip
- `tests/test_compare.py` — fingerprint needles and classify verdicts
- `tests/test_capture.py` — `apply_signals` clipping / coercion
- `tests/test_cli.py` — `summary_line`
- `tests/test_report.py` — HTML tag, filter, `open` attribute
- `README.md`, `CLAUDE.md` — document the new verdict

---

### Task 1: Capture fields and pytest

**Files:**
- Modify: `pyproject.toml` (via `uv add --dev pytest` only)
- Modify: `src/webcheck/models.py` (`Capture` dataclass)
- Create: `tests/test_models.py`

**Interfaces:**
- Consumes: existing `Capture`, `Pair`, `write_results`, `read_results`
- Produces: `Capture.has_password: bool = False`, `Capture.generator: str | None = None`, `Capture.headings: list[str]` (default empty), `Capture.text_excerpt: str | None = None`. `read_results` loads old JSON that lacks these keys.

- [ ] **Step 1: Add pytest**

Run:

```bash
uv add --dev pytest
```

Expected: `pyproject.toml` gains a `dependency-groups.dev` entry with pytest; `uv.lock` updates. Do not edit the lock by hand.

- [ ] **Step 2: Write the failing tests**

Create `tests/test_models.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_models.py -v
```

Expected: FAIL with `AttributeError: 'Capture' object has no attribute 'has_password'` (or `TypeError` if the test constructor already passes the new kwargs — in this file the roundtrip test sets attributes after construction, so `AttributeError`).

- [ ] **Step 4: Add the fields**

In `src/webcheck/models.py`, add these four fields at the end of `Capture` (after `tls_error`):

```python
    tls_error: bool = False
    has_password: bool = False
    generator: str | None = None
    headings: list[str] = field(default_factory=list)
    text_excerpt: str | None = None
```

Leave `read_results` / `write_results` unchanged. `asdict` picks up new fields automatically; missing keys in old JSON use the defaults.

- [ ] **Step 5: Run tests to verify they pass**

Run:

```bash
uv run pytest tests/test_models.py -v
```

Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml uv.lock src/webcheck/models.py tests/test_models.py
git commit -m "$(cat <<'EOF'
Add Capture page-signal fields so report can retune exposure heuristics.

EOF
)"
```

---

### Task 2: `fingerprint()`

**Files:**
- Modify: `src/webcheck/compare.py`
- Create: `tests/test_compare.py`

**Interfaces:**
- Consumes: `Capture` fields from Task 1
- Produces:

```python
def fingerprint(cap: Capture, leg: str) -> list[tuple[str, int]]:
    """Return (reason, score_bump) hits for one capture. `leg` is `hostname` or `IP`."""
```

Needles (substring, case-insensitive) against title, headings, and generator joined as one haystack, plus excerpt:

- Default title/heading/generator: `apache2 ubuntu default page`, `welcome to nginx`, `iis windows server`, `it works!`, `http server test page`, `welcome to centos`, `phpinfo()`
- Default excerpt: `if you see this page, the nginx web server is successfully installed`, `this page is used to test the proper operation of the apache`
- Login: `cap.has_password is True` → `("{leg} has a login form", 15)`
- Listing: title or any heading `.lower().startswith("index of")`, or `"parent directory"` in excerpt → `("{leg} looks like a directory listing", 20)`
- Default-page hit → `("{leg} looks like a default page", 25)`

Multiple kinds on one capture all append. No hits → `[]`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_compare.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_compare.py -v
```

Expected: FAIL with `ImportError: cannot import name 'fingerprint' from 'webcheck.compare'`.

- [ ] **Step 3: Implement `fingerprint`**

In `src/webcheck/compare.py`:

1. Change the models import to `from .models import Capture, Pair`.
2. Add `fingerprint` (and the needle tuples) above `classify`. Do not change `classify` yet.

```python
from .models import Capture, Pair
from .phash import hamming

# dHash distance above which two screenshots are treated as different pages.
# 64 bits total; identical renders sit at 0-2, cosmetic drift under ~8.
PHASH_DIFFERENT = 12

VERDICT_ORDER = {
    "differs": 400,
    "exposed": 350,
    "cert-err": 300,
    "unreachable": 200,
    "same": 100,
    "unknown": 0,
}

_DEFAULT_TITLE = (
    "apache2 ubuntu default page",
    "welcome to nginx",
    "iis windows server",
    "it works!",
    "http server test page",
    "welcome to centos",
    "phpinfo()",
)
_DEFAULT_EXCERPT = (
    "if you see this page, the nginx web server is successfully installed",
    "this page is used to test the proper operation of the apache",
)


def fingerprint(cap: Capture, leg: str) -> list[tuple[str, int]]:
    """Return (reason, score_bump) hits for one capture. `leg` is hostname or IP."""
    hits: list[tuple[str, int]] = []
    title = (cap.title or "").lower()
    headings = [h.lower() for h in cap.headings]
    generator = (cap.generator or "").lower()
    excerpt = (cap.text_excerpt or "").lower()
    title_hay = " ".join([title, generator, *headings])

    if any(needle in title_hay for needle in _DEFAULT_TITLE) or any(
        needle in excerpt for needle in _DEFAULT_EXCERPT
    ):
        hits.append((f"{leg} looks like a default page", 25))

    if cap.has_password:
        hits.append((f"{leg} has a login form", 15))

    listing_labels = [title, *headings]
    if any(label.startswith("index of") for label in listing_labels) or (
        "parent directory" in excerpt
    ):
        hits.append((f"{leg} looks like a directory listing", 20))

    return hits
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
uv run pytest tests/test_compare.py -v
```

Expected: PASS, 10 tests. (`classify` tests are not in this file yet.)

- [ ] **Step 5: Commit**

```bash
git add src/webcheck/compare.py tests/test_compare.py
git commit -m "$(cat <<'EOF'
Add page-signal fingerprints for default pages, logins, and listings.

EOF
)"
```

---

### Task 3: `classify` upgrades to `exposed`

**Files:**
- Modify: `src/webcheck/compare.py` (`classify`)
- Modify: `tests/test_compare.py` (append classify tests)

**Interfaces:**
- Consumes: `fingerprint(cap, leg) -> list[tuple[str, int]]`
- Produces: `classify` sets `pair.verdict = "exposed"` when both legs loaded, the pair would otherwise be `same` or `cert-err`, and either leg has a fingerprint hit. `differs` and `unreachable` never change. Hits always append to `reasons` (except `unreachable`, which does not fingerprint). `pair.score = VERDICT_ORDER[verdict] + accumulated` after the upgrade, so an `exposed` pair is never scored as `same` (100) or `cert-err` (300).

- [ ] **Step 1: Append the failing classify tests**

Add these to `tests/test_compare.py` (same `cap` / `pair` helpers already in the file):

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_compare.py -v
```

Expected: fingerprint tests PASS; classify tests FAIL with `assert result.verdict == "exposed"` (actual `same` or `cert-err`).

- [ ] **Step 3: Wire exposure into `classify`**

Replace `classify` in `src/webcheck/compare.py` with:

```python
def _exposure(pair: Pair) -> tuple[list[str], int]:
    reasons: list[str] = []
    bump = 0
    for cap, leg in ((pair.by_hostname, "hostname"), (pair.by_ip, "IP")):
        for reason, delta in fingerprint(cap, leg):
            reasons.append(reason)
            bump += delta
    return reasons, bump


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

    if not host_cap.ok and not ip_cap.ok:
        pair.verdict = "unreachable"
        pair.reasons = reasons + [f"both failed: {host_cap.error or ip_cap.error}"]
        pair.score = VERDICT_ORDER["unreachable"]
        return pair

    if host_cap.ok != ip_cap.ok:
        live, dead = ("IP", "hostname") if ip_cap.ok else ("hostname", "IP")
        reasons.append(f"{live} loaded but {dead} did not")
        exp_reasons, exp_score = _exposure(pair)
        reasons.extend(exp_reasons)
        pair.verdict = "differs"
        pair.reasons = reasons
        pair.score = VERDICT_ORDER["differs"] + 40 + exp_score
        return pair

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

    if ip_landed_on_hostname:
        score = max(0, score - 25)

    exp_reasons, exp_score = _exposure(pair)
    reasons.extend(exp_reasons)
    score += exp_score

    visually_different = distance is not None and distance >= PHASH_DIFFERENT
    textually_different = host_title != ip_title or host_cap.status != ip_cap.status

    if visually_different or textually_different:
        pair.verdict = "differs"
    elif exp_reasons:
        pair.verdict = "exposed"
    elif host_cap.tls_error or ip_cap.tls_error:
        pair.verdict = "cert-err"
    else:
        pair.verdict = "same"

    pair.score = VERDICT_ORDER[pair.verdict] + score
    pair.reasons = reasons
    return pair
```

Leave `classify_all` unchanged.

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
uv run pytest tests/test_compare.py tests/test_models.py -v
```

Expected: PASS, all tests in both files.

- [ ] **Step 5: Commit**

```bash
git add src/webcheck/compare.py tests/test_compare.py
git commit -m "$(cat <<'EOF'
Upgrade matching default, login, and listing pages to an exposed verdict.

EOF
)"
```

---

### Task 4: Capture DOM extraction

**Files:**
- Modify: `src/webcheck/capture.py`
- Create: `tests/test_capture.py`

**Interfaces:**
- Consumes: `Capture` signal fields from Task 1
- Produces:

```python
_SIGNALS_JS: str  # page.evaluate expression, top frame only

def apply_signals(cap: Capture, raw: dict) -> Capture:
    """Copy evaluate() output onto cap, clipping headings (5×120) and excerpt (2000)."""
```

`_render` calls `page.evaluate(_SIGNALS_JS)` on the success path **after** setting `title` and **before** taking the screenshot. On `PlaywrightError` or a non-dict result, leave defaults and continue. Navigation failures skip extraction (they never reach this code).

- [ ] **Step 1: Write the failing tests**

Create `tests/test_capture.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_capture.py -v
```

Expected: FAIL with `ImportError: cannot import name 'apply_signals' from 'webcheck.capture'`.

- [ ] **Step 3: Implement `apply_signals`, `_SIGNALS_JS`, and the `_render` hook**

Add to `src/webcheck/capture.py` (after `_shorten`, before `_render`):

```python
_SIGNALS_JS = """() => {
  const el = document.querySelector('meta[name="generator"]');
  const generator = el && el.content ? el.content : null;
  const headings = [...document.querySelectorAll('h1')]
    .map(h => (h.innerText || '').trim())
    .filter(Boolean)
    .slice(0, 5)
    .map(t => t.slice(0, 120));
  const text = (document.body && document.body.innerText) ? document.body.innerText : '';
  const excerpt = text.slice(0, 2000) || null;
  return {
    has_password: !!document.querySelector('input[type="password"]'),
    generator,
    headings,
    excerpt,
  };
}"""


def apply_signals(cap: Capture, raw: dict) -> Capture:
    """Copy a page.evaluate() payload onto cap, clipping to stored limits."""
    cap.has_password = bool(raw.get("has_password"))
    generator = raw.get("generator")
    if isinstance(generator, str):
        generator = generator.strip() or None
    else:
        generator = None
    cap.generator = generator

    headings: list[str] = []
    for item in raw.get("headings") or []:
        if not isinstance(item, str):
            continue
        text = item.strip()
        if not text:
            continue
        headings.append(text[:120])
        if len(headings) == 5:
            break
    cap.headings = headings

    excerpt = raw.get("excerpt")
    if isinstance(excerpt, str) and excerpt:
        cap.text_excerpt = excerpt[:2000]
    else:
        cap.text_excerpt = None
    return cap
```

Inside `_render`, after `cap.redirects = redirects` and **before** `shot_path.parent.mkdir`, insert:

```python
        cap.redirects = redirects

        try:
            raw = await page.evaluate(_SIGNALS_JS)
            if isinstance(raw, dict):
                apply_signals(cap, raw)
        except PlaywrightError:
            pass

        shot_path.parent.mkdir(parents=True, exist_ok=True)
```

- [ ] **Step 4: Run tests to verify they pass**

Run:

```bash
uv run pytest tests/test_capture.py tests/test_compare.py tests/test_models.py -v
```

Expected: PASS. Do not start Chromium.

- [ ] **Step 5: Commit**

```bash
git add src/webcheck/capture.py tests/test_capture.py
git commit -m "$(cat <<'EOF'
Capture landing-page DOM signals for exposure fingerprints.

EOF
)"
```

---

### Task 5: Report, CLI, and docs

**Files:**
- Modify: `src/webcheck/report.py`
- Modify: `src/webcheck/cli.py`
- Modify: `README.md`
- Modify: `CLAUDE.md`
- Create: `tests/test_report.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Consumes: `pair.verdict == "exposed"` from Task 3
- Produces:
  - CSS variables `--exposed: #7a3e9d` (light) and `--exposed: #c77dff` (dark)
  - `.tag.exposed { color: var(--exposed); }`
  - Filter order `["differs", "exposed", "cert-err", "unreachable", "same", "unknown"]`
  - `<details>` starts `open` for `differs`, `cert-err`, and `exposed`
  - `_MARK["exposed"] = "EXPOSED "`
  - `summary_line(pairs: list[Pair]) -> str` returns `{n} of {m} pair(s) flagged as differing, {p} as exposed.`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli.py`:

```python
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
```

Create `tests/test_report.py`:

```python
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
    assert "<details class=\"pair\" data-verdict=\"exposed\" open>" in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
uv run pytest tests/test_cli.py tests/test_report.py -v
```

Expected: FAIL with `ImportError: cannot import name 'summary_line' from 'webcheck.cli'` (and report assertions fail until CSS/`open` land).

- [ ] **Step 3: Implement CLI**

In `src/webcheck/cli.py`, update `_MARK` and add `summary_line`. Replace the capture summary `print` with a call to it.

```python
_MARK = {
    "differs": "DIFFERS ",
    "exposed": "EXPOSED ",
    "cert-err": "cert-err",
    "unreachable": "down    ",
    "same": "same    ",
    "unknown": "?       ",
}


def summary_line(pairs: list[Pair]) -> str:
    flagged = sum(1 for p in pairs if p.verdict == "differs")
    exposed = sum(1 for p in pairs if p.verdict == "exposed")
    return f"{flagged} of {len(pairs)} pair(s) flagged as differing, {exposed} as exposed."
```

In `_run_capture`, replace the two `flagged` lines with:

```python
    print(summary_line(pairs), file=sys.stderr)
```

- [ ] **Step 4: Implement report styling and filters**

In `src/webcheck/report.py`:

Light `:root` `--line` row, add `--exposed: #7a3e9d`:

```css
  --line: #dfe3e8; --differs: #b42318; --cert: #b54708; --exposed: #7a3e9d; --same: #067647;
```

Dark `:root`, add `--exposed: #c77dff`:

```css
    --line: #2d333b; --differs: #f97066; --cert: #fdb022; --exposed: #c77dff; --same: #47cd89;
```

Tag colors:

```css
.tag.differs { color: var(--differs); } .tag.cert-err { color: var(--cert); }
.tag.exposed { color: var(--exposed); }
.tag.same { color: var(--same); } .tag.unreachable, .tag.unknown { color: var(--unreachable); }
```

In `_pair_block`, start expanded for `exposed` too:

```python
    open_attr = " open" if pair.verdict in ("differs", "cert-err", "exposed") else ""
```

In `build_report`, put `exposed` in the filter order:

```python
    order = ["differs", "exposed", "cert-err", "unreachable", "same", "unknown"]
```

- [ ] **Step 5: Update README and CLAUDE.md**

In `README.md`, insert this row after `differs` in the verdicts table:

```markdown
| `exposed` | Pages match (or only a cert error), but a landing page looks like a default install, login form, or directory listing |
```

In `CLAUDE.md`, change the verdict list in **Verdict heuristics** from `differs` / `cert-err` / `unreachable` / `same` to `differs` / `exposed` / `cert-err` / `unreachable` / `same`, and add one sentence: an `exposed` pair is a question-1 finding (default page, login form, or directory listing) that did not already `differ`.

- [ ] **Step 6: Run the full suite**

Run:

```bash
uv run pytest -v
```

Expected: PASS, all tests in `tests/`. No Playwright browser launch.

- [ ] **Step 7: Commit**

```bash
git add src/webcheck/report.py src/webcheck/cli.py README.md CLAUDE.md tests/test_report.py tests/test_cli.py
git commit -m "$(cat <<'EOF'
Surface the exposed verdict in the report, CLI, and docs.

EOF
)"
```

---

## Self-review (plan vs spec)

| Spec requirement | Task |
| --- | --- |
| `Capture` four fields + old JSON loads | 1 |
| Fingerprint needles, login = password only, listing startswith / parent directory | 2 |
| `exposed` upgrades `same` and `cert-err`; never `differs` / `unreachable` | 3 |
| Reasons + score bumps on `differs` too | 3 (`test_classify_differs_keeps_verdict_and_records_exposure`, `test_classify_one_sided_failure_stays_differs`) |
| Both-failed ignores signals | 3 (`test_classify_unreachable_ignores_signals`) |
| `VERDICT_ORDER["exposed"] = 350` | 2 (constant) + 3 (score asserts) |
| Extract top-frame DOM, clip, don't fail capture | 4 |
| Purple tag, filter, start expanded | 5 |
| CLI counts both differs and exposed | 5 |
| Spec test list (nginx, differs+default, cert+password, cert stays, unreachable, same, listing, login, legacy JSON) | 1 and 3 |
| No extra-path probes, no HTTP, no capture-time label | not in any task |
