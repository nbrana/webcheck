# webcheck

Render a list of sites twice — once by hostname, once by IP — and review the pairs side by side.

It answers two questions:

1. Does this site look like it should be public facing?
2. Does it render differently when reached by IP instead of by name? A divergence usually means vhost routing, a TLS SNI mismatch, or a default server block exposing something unintended.

## Setup

```bash
uv sync
uv run playwright install chromium
```

## Use

Write a CSV of the hosts you want to audit:

```csv
hostname,ip
intranet.corp.net,10.0.4.12
app.example.com,192.0.2.10
```

The IP is the address you intend to audit — this tool never looks it up. Then capture and review:

```bash
uv run webcheck capture hosts.csv -o out/
open out/report.html
```

The report shows both renders per host with status, title, server, redirect chain, and TLS state, sorted so the pairs most likely to differ come first. Filter buttons narrow by verdict. Nothing is hidden — the heuristics only decide ordering.

Re-run `uv run webcheck report -o out/` to rebuild the page from `out/results.json` without re-capturing.

## Reading the verdicts

| Verdict | Meaning |
| --- | --- |
| `differs` | The two renders disagree — different title, status, or visibly different page |
| `exposed` | Pages match (or only a cert error), but a landing page looks like a default install, login form, or directory listing |
| `cert-err` | Pages match, but a TLS certificate error was hit |
| `unreachable` | Neither leg loaded |
| `same` | Both legs look and report the same |

A certificate error on the IP leg is normal — SNI can't match a bare IP — and is weighted lightly. One on the hostname leg is a real finding.
