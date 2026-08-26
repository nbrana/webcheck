# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A screenshot-based auditing tool. Given a list of hosts, it uses **Playwright** to render each site twice — once by hostname, once by its IP address directly — and produces output that makes the pairs easy to eyeball.

Two questions drive every design decision:

1. **Does this site look like it should be public facing?** (sketchy / default install / forgotten admin panel / parked domain)
2. **Does the site render differently by hostname vs. by raw IP?** A divergence usually means vhost routing, a TLS SNI mismatch, or a default server block that's exposing something unintended.

That second point is why captures are always taken in *pairs* and reviewed side by side — a single screenshot per host would defeat the purpose. Hitting the IP directly means the `Host` header and TLS SNI no longer match the certificate, so expect cert errors and redirects back to the hostname; both are signal, not bugs to paper over.

## Pipeline

`inputs` -> `capture` -> `compare` -> `report`, with `models` holding the shapes that pass between them. The stages are deliberately separable: capture is slow and networked, everything after it is cheap and pure, so `webcheck report` re-derives verdicts and rebuilds the HTML from `results.json` without touching the network. When tuning heuristics, iterate with `report`, not `capture`.

- **`inputs.py`** — parses `hostname,ip` CSV into `Target`s. Explicit IPs only; there is no DNS resolution anywhere in this codebase, by design (split-horizon DNS and the IP you want to audit often disagree with what a resolver returns).
- **`capture.py`** — Playwright/Chromium. Renders `https://<hostname>/` and `https://<ip>/` per target.
- **`phash.py`** — dHash over the PNGs. Dependency-light on purpose: Pillow only.
- **`compare.py`** — turns a `Pair` into a verdict (`differs` / `cert-err` / `unreachable` / `same`), a human-readable `reasons` list, and a `score` used purely for sort order.
- **`report.py`** — one HTML page, no build step, no external assets.

### The two-pass TLS trick

`capture.py` visits each URL first with `ignore_https_errors=False`. If that fails with a cert error it retries in a lenient context and keeps `tls_error=True`. This exists because the two facts are independent and both matter: *the certificate is invalid* and *here is the page behind it*. A single lenient pass would silently discard the first; a single strict pass would discard the second. Don't collapse it back into one pass.

### Verdict heuristics

`compare.py` flags, it never clears — every pair reaches the report regardless of verdict, and `score` only decides what floats to the top. An IP visit that redirects back to the hostname has its score reduced, since that explains away most divergence. `PHASH_DIFFERENT` (dHash distance out of 64) is the main tuning knob.

Cert errors on the IP leg are expected, not bugs — SNI can't match when you dial an IP — so they carry little weight alone. A cert error on the *hostname* leg is a real finding and scores higher.

## Status

Working end to end; verified against live hosts. No tests yet.

## Tooling

Managed by **uv** with the `uv_build` backend, `requires-python >= 3.14`. Do not hand-edit `uv.lock`; add dependencies with `uv add <pkg>` so the lock stays in sync.

```bash
uv sync                          # create/refresh .venv from pyproject + lock
uv run playwright install chromium   # one-time; browser lives in ~/.cache/ms-playwright
uv run webcheck capture hosts.csv -o out/
uv run webcheck report -o out/   # rebuild HTML from existing results.json
```

`capture` flags: `-c/--concurrency` (default 4), `-t/--timeout` seconds per page (default 20), `--no-report`.

The `webcheck` entry point maps to `webcheck:main`, so `main()` must stay re-exported from `src/webcheck/__init__.py` if it moves.

Output directory is a unit — `report.html` links `shots/*.png` relatively. Move or archive the whole directory, never the HTML alone.

## Tests

No test runner is configured. If adding one, prefer `uv add --dev pytest` and:

```bash
uv run pytest                               # full suite
uv run pytest tests/test_x.py::test_y -x    # single test
```

`inputs`, `phash`, and `compare` are pure and worth covering first. `compare` can be tested entirely on hand-built `Pair` objects with no browser involved.
