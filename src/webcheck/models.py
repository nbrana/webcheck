"""Core data shapes shared by capture, compare, and report."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from pathlib import Path


@dataclass(frozen=True)
class Target:
    """One host to audit, and the IP we were told to reach it at."""

    hostname: str
    ip: str

    @property
    def slug(self) -> str:
        """Filesystem-safe stem, unique per (hostname, ip) pair."""
        safe_host = "".join(c if c.isalnum() or c in "-._" else "_" for c in self.hostname)
        safe_ip = self.ip.replace(":", "-").replace(".", "-")
        return f"{safe_host}__{safe_ip}"


@dataclass
class Capture:
    """Result of rendering one URL. `error` set means the page never loaded."""

    url: str
    via: str  # "hostname" or "ip"
    ok: bool = False
    status: int | None = None
    final_url: str | None = None
    title: str | None = None
    server: str | None = None
    redirects: list[str] = field(default_factory=list)
    screenshot: str | None = None  # path relative to the output dir
    phash: str | None = None
    error: str | None = None
    tls_error: bool = False


@dataclass
class Pair:
    """Both captures for one target, plus the verdict comparing them."""

    hostname: str
    ip: str
    by_hostname: Capture
    by_ip: Capture
    verdict: str = "unknown"  # differs | same | cert-err | unreachable | unknown
    reasons: list[str] = field(default_factory=list)
    score: int = 0  # higher sorts earlier in the report

    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "ip": self.ip,
            "by_hostname": asdict(self.by_hostname),
            "by_ip": asdict(self.by_ip),
            "verdict": self.verdict,
            "reasons": self.reasons,
            "score": self.score,
        }


def write_results(pairs: list[Pair], out_dir: Path) -> Path:
    path = out_dir / "results.json"
    payload = {"pairs": [p.to_dict() for p in pairs]}
    path.write_text(json.dumps(payload, indent=2))
    return path


def read_results(out_dir: Path) -> list[Pair]:
    payload = json.loads((out_dir / "results.json").read_text())
    return [
        Pair(
            hostname=raw["hostname"],
            ip=raw["ip"],
            by_hostname=Capture(**raw["by_hostname"]),
            by_ip=Capture(**raw["by_ip"]),
            verdict=raw["verdict"],
            reasons=raw["reasons"],
            score=raw["score"],
        )
        for raw in payload["pairs"]
    ]
