"""Difference hash (dHash) over screenshots.

A dHash encodes the gradient direction between adjacent pixels of a heavily
downscaled greyscale image. It is stable against JPEG-ish noise, antialiasing,
and small layout shifts, but moves sharply when the page is genuinely a
different page -- which is the distinction the report cares about.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

HASH_SIZE = 8  # produces HASH_SIZE * HASH_SIZE bits


def phash_file(path: Path) -> str | None:
    try:
        with Image.open(path) as img:
            small = img.convert("L").resize(
                (HASH_SIZE + 1, HASH_SIZE), Image.Resampling.LANCZOS
            )
            pixels = list(small.getdata())
    except (OSError, ValueError):
        return None

    bits = 0
    for row in range(HASH_SIZE):
        offset = row * (HASH_SIZE + 1)
        for col in range(HASH_SIZE):
            left = pixels[offset + col]
            right = pixels[offset + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{HASH_SIZE * HASH_SIZE // 4}x}"


def hamming(a: str | None, b: str | None) -> int | None:
    """Bit distance between two hex dHashes, or None if either is missing."""
    if not a or not b:
        return None
    return bin(int(a, 16) ^ int(b, 16)).count("1")
