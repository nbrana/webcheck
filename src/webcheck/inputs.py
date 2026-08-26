"""Parsing of the hosts input file.

Accepts CSV with `hostname,ip`. A header row is optional and detected by
looking for the literal word "hostname" in the first cell. Blank lines and
`#` comments are skipped so the file stays hand-editable.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from .models import Target


class InputError(ValueError):
    pass


def parse_hosts(path: Path) -> list[Target]:
    rows = list(csv.reader(io.StringIO(path.read_text())))
    targets: list[Target] = []
    seen: set[tuple[str, str]] = set()

    for lineno, row in enumerate(rows, start=1):
        cells = [c.strip() for c in row]
        if not cells or not cells[0] or cells[0].startswith("#"):
            continue
        if lineno == 1 and cells[0].lower() == "hostname":
            continue
        if len(cells) < 2 or not cells[1]:
            raise InputError(
                f"{path}:{lineno}: expected `hostname,ip` but got {row!r}. "
                "Every row needs an explicit IP."
            )
        target = Target(hostname=cells[0], ip=cells[1])
        key = (target.hostname, target.ip)
        if key in seen:
            continue
        seen.add(key)
        targets.append(target)

    if not targets:
        raise InputError(f"{path}: no usable rows found.")
    return targets
