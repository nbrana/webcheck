"""Static HTML review page.

The report lives next to `shots/` and links the PNGs relatively rather than
inlining them -- a hundred full-page screenshots as base64 makes a file no
browser enjoys. Move the output directory as a unit.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from .models import Pair

_CSS = """
:root {
  --bg: #f6f7f9; --panel: #fff; --ink: #14171a; --muted: #5b6672;
  --line: #dfe3e8; --differs: #b42318; --cert: #b54708; --exposed: #7a3e9d; --same: #067647;
  --unreachable: #5b6672;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14171a; --panel: #1c2024; --ink: #e8eaed; --muted: #98a2b3;
    --line: #2d333b; --differs: #f97066; --cert: #fdb022; --exposed: #c77dff; --same: #47cd89;
    --unreachable: #98a2b3;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink);
  font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
header { padding: 24px 28px 16px; border-bottom: 1px solid var(--line); }
h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: -0.01em; }
.meta { color: var(--muted); font-size: 13px; }
.filters { padding: 14px 28px; display: flex; gap: 8px; flex-wrap: wrap;
  position: sticky; top: 0; background: var(--bg); border-bottom: 1px solid var(--line); z-index: 2; }
.filters button { font: inherit; cursor: pointer; padding: 5px 12px; border-radius: 999px;
  border: 1px solid var(--line); background: var(--panel); color: var(--ink); }
.filters button[aria-pressed="true"] { background: var(--ink); color: var(--bg); border-color: var(--ink); }
main { padding: 20px 28px 60px; display: flex; flex-direction: column; gap: 18px; }
.pair { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
.pair > summary { cursor: pointer; padding: 12px 16px; display: flex; gap: 12px;
  align-items: baseline; flex-wrap: wrap; }
.pair > summary::-webkit-details-marker { display: none; }
.host { font-weight: 650; font-size: 15px; }
.ip { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; }
.tag { font-size: 11px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase;
  padding: 2px 8px; border-radius: 4px; border: 1px solid currentColor; }
.tag.differs { color: var(--differs); } .tag.cert-err { color: var(--cert); }
.tag.exposed { color: var(--exposed); }
.tag.same { color: var(--same); } .tag.unreachable, .tag.unknown { color: var(--unreachable); }
.reasons { color: var(--muted); font-size: 12.5px; width: 100%; margin-top: 2px; }
.shots { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
  gap: 16px; padding: 0 16px 16px; }
.shot h3 { margin: 0 0 6px; font-size: 12px; text-transform: uppercase;
  letter-spacing: .06em; color: var(--muted); }
.shot img { width: 100%; border: 1px solid var(--line); border-radius: 6px;
  display: block; background: #fff; }
.facts { margin: 8px 0 0; font-size: 12.5px; color: var(--muted);
  display: grid; grid-template-columns: auto 1fr; gap: 2px 10px; }
.facts dt { font-weight: 600; }
.facts dd { margin: 0; overflow-wrap: anywhere; }
.err { color: var(--differs); }
.empty { color: var(--muted); padding: 40px; text-align: center;
  border: 1px dashed var(--line); border-radius: 10px; }
"""

_JS = """
const buttons = document.querySelectorAll('.filters button');
buttons.forEach(btn => btn.addEventListener('click', () => {
  const want = btn.dataset.filter;
  buttons.forEach(b => b.setAttribute('aria-pressed', String(b === btn)));
  document.querySelectorAll('.pair').forEach(el => {
    el.hidden = want !== 'all' && el.dataset.verdict !== want;
  });
}));
"""


def _esc(value) -> str:
    return html.escape(str(value)) if value not in (None, "") else "&mdash;"


def _shot_block(cap, title: str) -> str:
    if cap.screenshot:
        img = f'<a href="shots/{_esc(cap.screenshot)}"><img src="shots/{_esc(cap.screenshot)}" alt="{_esc(title)} render" loading="lazy"></a>'
    else:
        img = f'<p class="err">no screenshot &mdash; {_esc(cap.error)}</p>'

    facts = [
        ("URL", _esc(cap.url)),
        ("Status", _esc(cap.status)),
        ("Final URL", _esc(cap.final_url)),
        ("Title", _esc(cap.title)),
        ("Server", _esc(cap.server)),
    ]
    if cap.redirects:
        facts.append(("Redirects", _esc(" &rarr; ".join(cap.redirects))))
    if cap.tls_error:
        facts.append(("TLS", '<span class="err">certificate error</span>'))
    if cap.error and cap.screenshot:
        facts.append(("Note", f'<span class="err">{_esc(cap.error)}</span>'))

    rows = "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in facts)
    return f'<div class="shot"><h3>{_esc(title)}</h3>{img}<dl class="facts">{rows}</dl></div>'


def _pair_block(pair: Pair) -> str:
    reasons = (
        f'<div class="reasons">{_esc("; ".join(pair.reasons))}</div>' if pair.reasons else ""
    )
    # Pairs worth a look start expanded; the quiet ones stay folded away.
    open_attr = " open" if pair.verdict in ("differs", "cert-err", "exposed") else ""
    return f"""<details class="pair" data-verdict="{_esc(pair.verdict)}"{open_attr}>
  <summary>
    <span class="tag {_esc(pair.verdict)}">{_esc(pair.verdict)}</span>
    <span class="host">{_esc(pair.hostname)}</span>
    <span class="ip">{_esc(pair.ip)}</span>
    {reasons}
  </summary>
  <div class="shots">
    {_shot_block(pair.by_hostname, "by hostname")}
    {_shot_block(pair.by_ip, "by IP")}
  </div>
</details>"""


def build_report(pairs: list[Pair], out_dir: Path) -> Path:
    counts: dict[str, int] = {}
    for pair in pairs:
        counts[pair.verdict] = counts.get(pair.verdict, 0) + 1

    order = ["differs", "exposed", "cert-err", "unreachable", "same", "unknown"]
    filters = ['<button data-filter="all" aria-pressed="true">all ' f"({len(pairs)})</button>"]
    filters += [
        f'<button data-filter="{v}" aria-pressed="false">{v} ({counts[v]})</button>'
        for v in order
        if counts.get(v)
    ]

    body = "".join(_pair_block(p) for p in pairs) or (
        '<p class="empty">No results. Run a capture first.</p>'
    )
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>webcheck report</title>
<style>{_CSS}</style></head>
<body>
<header>
  <h1>webcheck</h1>
  <div class="meta">{len(pairs)} host(s) &middot; hostname vs. IP render &middot; generated {generated}</div>
</header>
<nav class="filters">{"".join(filters)}</nav>
<main>{body}</main>
<script>{_JS}</script>
</body></html>"""

    path = out_dir / "report.html"
    path.write_text(doc)
    return path
