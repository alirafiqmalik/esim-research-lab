"""Seed corpus loading shared by the fuzzing modes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Seed:
    """One known-good APDU seed."""

    name: str
    apdu_hex: str


def load_seeds(seeds_dir: Path) -> list[Seed]:
    """Load every ``*.apdu`` seed file from a directory.

    Each file holds one hex APDU. Raises FileNotFoundError if the directory is
    missing and ValueError if it holds no seeds.
    """
    if not seeds_dir.is_dir():
        raise FileNotFoundError(f"seeds directory not found: {seeds_dir}")

    seeds: list[Seed] = []
    for path in sorted(seeds_dir.glob("*.apdu")):
        text = path.read_text().strip().replace(" ", "")
        if text:
            seeds.append(Seed(name=path.stem, apdu_hex=text))

    if not seeds:
        raise ValueError(f"no *.apdu seeds found in {seeds_dir}")
    return seeds
