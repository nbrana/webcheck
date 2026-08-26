"""Rendering targets with Playwright.

Each target is rendered twice: once at `https://<hostname>` and once at
`https://<ip>`. The IP visit is deliberately plain -- no Host header override
and no SNI fixup -- because that is exactly what an outsider poking the IP
sees. Cert mismatches and default vhosts are the signal we are looking for,
so they are recorded rather than worked around.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from playwright.async_api import Error as PlaywrightError, async_playwright

from .models import Capture, Pair, Target
from .phash import phash_file

VIEWPORT = {"width": 1280, "height": 800}

# Substrings that mark a navigation failure as TLS-related rather than
# the host simply being down.
_TLS_MARKERS = (
    "ERR_CERT",
    "ERR_SSL",
    "SSL_ERROR",
    "ERR_TLS",
    "ERR_BAD_SSL",
)


def _is_tls_error(message: str) -> bool:
    return any(marker in message for marker in _TLS_MARKERS)


def _shorten(message: str) -> str:
    """Playwright errors carry a long call-log tail; keep the first line."""
    return message.strip().splitlines()[0][:300]


async def _render(context, url: str, via: str, shot_path: Path, timeout_ms: int) -> Capture:
    cap = Capture(url=url, via=via)
    page = await context.new_page()
    redirects: list[str] = []

    page.on("response", lambda r: asyncio.ensure_future(_note_redirect(r, redirects)))

    try:
        response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        # Give late-loading pages a moment to paint, but never block on a
        # page that keeps a socket open forever (analytics, websockets).
        try:
            await page.wait_for_load_state("networkidle", timeout=5000)
        except PlaywrightError:
            pass

        if response is not None:
            cap.status = response.status
            try:
                cap.server = await response.header_value("server")
            except PlaywrightError:
                cap.server = None
        cap.final_url = page.url
        cap.title = (await page.title()) or None
        cap.redirects = redirects

        shot_path.parent.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(shot_path), full_page=False)
        cap.screenshot = shot_path.name
        cap.phash = phash_file(shot_path)
        cap.ok = True
    except PlaywrightError as exc:
        cap.error = _shorten(str(exc))
        cap.tls_error = _is_tls_error(cap.error)
    finally:
        await page.close()

    return cap


async def _note_redirect(response, redirects: list[str]) -> None:
    try:
        if 300 <= response.status < 400 and response.request.is_navigation_request():
            location = await response.header_value("location")
            if location:
                redirects.append(location)
    except PlaywrightError:
        pass


async def _capture_one(browser, target: Target, out_dir: Path, timeout_ms: int) -> Pair:
    shots = out_dir / "shots"

    async def visit(url: str, via: str) -> Capture:
        shot = shots / f"{target.slug}__{via}.png"
        # Strict pass first so a genuine cert problem is recorded as such.
        strict = await browser.new_context(viewport=VIEWPORT, ignore_https_errors=False)
        try:
            cap = await _render(strict, url, via, shot, timeout_ms)
        finally:
            await strict.close()

        if cap.ok or not cap.tls_error:
            return cap

        # Cert was bad, but we still want to see the page behind it.
        lenient = await browser.new_context(viewport=VIEWPORT, ignore_https_errors=True)
        try:
            retry = await _render(lenient, url, via, shot, timeout_ms)
        finally:
            await lenient.close()
        retry.tls_error = True
        if retry.error is None:
            retry.error = cap.error
        return retry

    by_hostname = await visit(f"https://{target.hostname}/", "hostname")
    by_ip = await visit(f"https://{target.ip}/", "ip")
    return Pair(hostname=target.hostname, ip=target.ip, by_hostname=by_hostname, by_ip=by_ip)


async def capture_all(
    targets: list[Target],
    out_dir: Path,
    concurrency: int = 4,
    timeout_ms: int = 20000,
    on_done=None,
) -> list[Pair]:
    out_dir.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(concurrency)
    results: list[Pair | None] = [None] * len(targets)

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        try:

            async def worker(index: int, target: Target) -> None:
                async with semaphore:
                    pair = await _capture_one(browser, target, out_dir, timeout_ms)
                    results[index] = pair
                    if on_done:
                        on_done(pair)

            await asyncio.gather(
                *(worker(i, t) for i, t in enumerate(targets))
            )
        finally:
            await browser.close()

    return [p for p in results if p is not None]
