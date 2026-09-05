"""The shipped lot digest (spec section "Lot digest")."""

import hashlib
from pathlib import Path


def canonical(unit_ids):
    """Sorted as byte strings, newline-joined, one trailing newline."""
    ids = sorted({u.strip() for u in unit_ids if u.strip()}, key=lambda s: s.encode())
    if len(ids) != len([u for u in unit_ids if u.strip()]):
        raise ValueError("duplicate unit identifiers")
    return ("\n".join(ids) + "\n").encode()


def lot_digest(unit_ids):
    return hashlib.sha256(canonical(unit_ids)).hexdigest()


def read_units(path):
    return [line for line in Path(path).read_text().splitlines() if line.strip()]


def write_units(path, unit_ids):
    Path(path).write_bytes(canonical(unit_ids))
