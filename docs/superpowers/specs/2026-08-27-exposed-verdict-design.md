# Exposed verdict: flag pages that look like they shouldn't be public

## Problem

webcheck answers two questions:

1. Does this site look like it should be public facing?
2. Does it render differently by hostname vs. by IP?

Today only question 2 is scored. A default nginx page served identically on both legs is verdict `same` and folded shut, so the report buries the finding question 1 cares about.

## Goal

Add an `exposed` verdict for landing pages that look like default installs, login panels, or directory listings. Hostname-vs-IP comparison stays the primary axis: `differs` still wins.

Tuning must stay on `webcheck report`. Capture stores page facts; `compare.py` owns the fingerprints.

## Non-goals

- Probing extra paths (`/admin`, `/phpmyadmin`, …)
- HTTP (port 80) captures
- A large CMS/product fingerprint database
- Visual-diff overlays or report search
- Capture-time classification that cannot be retuned without recapture

## Verdict rules

Existing verdicts keep their meaning. `exposed` is inserted between `differs` and `cert-err`:

| Verdict | When |
| --- | --- |
| `differs` | Hostname and IP disagree (title, status, or phash). Unchanged. |
| `exposed` | Both legs loaded, they do **not** `differ`, and at least one leg matches an exposure fingerprint. Replaces what would have been `same` or `cert-err`. |
| `cert-err` | Pages match, TLS error, no exposure fingerprint. |
| `unreachable` | Neither leg loaded. Unchanged — no page to judge. |
| `same` | Both legs loaded, match, no TLS error, no exposure fingerprint. |

`differs` and `unreachable` never become `exposed`. Exposure matches on those pairs still go into `reasons`.

`VERDICT_ORDER`: `differs` 400, `exposed` 350, `cert-err` 300, `unreachable` 200, `same` 100.

## Data model

New optional fields on `Capture` (defaults keep old `results.json` loadable):

- `has_password: bool = False`
- `generator: str | None = None` — `meta[name=generator]` content
- `headings: list[str]` — up to 5 `h1` texts, each clipped to 120 characters
- `text_excerpt: str | None = None` — `document.body.innerText`, clipped to 2000 characters

No `exposure` field on `Pair`. Kind (`default-page` / `login` / `listing`) lives only in `reasons`, e.g. `hostname looks like a default nginx page`.

## Capture

Run extraction in `_render`'s success path (page loaded; screenshot may still follow). Use Playwright locators/`evaluate` on the **top frame only**. Wrap in `PlaywrightError` handling: on failure leave the field defaults and still keep the screenshot. Do not fail a capture because the DOM was hostile.

Skip extraction when the navigation itself failed.

Take the first `meta[name=generator]` if several exist. Drop blank `h1`s before applying the cap of 5.

The lenient TLS retry already replaces the whole `Capture`; extraction runs on whichever pass produced the kept result.

## Fingerprints (`compare.py`)

Match against title, headings, generator, and excerpt. Case-insensitive substring unless noted. High precision over recall.

**Default page** — any of:

- Title or heading: `apache2 ubuntu default page`, `welcome to nginx`, `iis windows server`, `it works!`, `http server test page`, `welcome to centos`, `phpinfo()`
- Excerpt: `if you see this page, the nginx web server is successfully installed`, `this page is used to test the proper operation of the apache`

**Login** — `has_password` is true.

**Directory listing** — title or heading starts with `index of`, or excerpt contains `parent directory`.

Evaluate both legs. List every match in `reasons` with the leg name (`hostname` / `IP`). Score bumps apply whenever a fingerprint matches, including on `differs` pairs (so an exposed default vhost sorts above a benign title mismatch): default-page +25, listing +20, login +15. Multiple matches add; they do not replace each other.

A real site with a hostname cert error and no fingerprint stays `cert-err`. A default page with an IP cert error (normal SNI mismatch) becomes `exposed`.

## Report and CLI

- `--exposed` color: purple, distinct from `differs` (red), `cert-err` (orange), `same` (green)
- Filter button when the count is non-zero
- `exposed` pairs start expanded, same as `differs` and `cert-err`
- Tag text is `exposed`; the reason line says which kind and which leg
- CLI `_MARK` entry for `exposed`
- After capture, print both counts: `N of M pair(s) flagged as differing, P as exposed.`

## Tests

Add pytest (`uv add --dev pytest`). No browser in the suite.

- Both legs default nginx titles, otherwise identical → `exposed`
- `differs` + default page on the IP leg → still `differs`, reason includes the default-page match
- `cert-err` + `has_password` → `exposed`
- `cert-err` + ordinary titles, no password → `cert-err`
- Both failed → `unreachable`
- Ordinary matching site → `same`
- Title `Index of /foo` → `exposed` with a listing reason
- `has_password` on an otherwise matching pair → `exposed` with a login reason
- `read_results` loads JSON written before these fields existed

`classify` is tested with hand-built `Pair` / `Capture` objects.

## Compatibility

Old `results.json` loads: missing keys use dataclass defaults, so those pairs classify as they do today (no excerpt, no password). Re-capture is required before `exposed` can fire.
