#!/usr/bin/env python3
"""Check fixed hashes, legal structure, exact gate tallies, and depths."""
from __future__ import annotations

import hashlib
from pathlib import Path

from verify_slp import depths, gate_counts, parse_slp, validate_structure

ROOT = Path(__file__).resolve().parents[1]
PRIMARY = ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp"
TRANSPARENT = ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp"
EXPECTED = {
    PRIMARY: (
        "f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3",
        {"AND": 29, "XOR": 195, "XNOR": 0, "NOT": 4},
        228,
        (35, 6),
    ),
    TRANSPARENT: (
        "cecd0c7abba9920ff2af7ec204fcd01f97db135a4c43d8afd7f83d65c2e382ca",
        {"AND": 29, "XOR": 422, "XNOR": 0, "NOT": 4},
        455,
        (35, 6),
    ),
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    for path, (expected_hash, expected_counts, expected_total, expected_depths) in EXPECTED.items():
        actual_hash = sha256(path)
        if actual_hash != expected_hash:
            raise SystemExit(f"FAIL: SHA-256 mismatch for {path.name}: {actual_hash}")
        circuit = parse_slp(path)
        validate_structure(circuit)
        counts = gate_counts(circuit)
        if counts != expected_counts or len(circuit.ops) != expected_total:
            raise SystemExit(
                f"FAIL: unexpected tally for {path.name}: {counts}, total {len(circuit.ops)}"
            )
        gate_depth, and_depth, _, _ = depths(circuit)
        if (gate_depth, and_depth) != expected_depths:
            raise SystemExit(
                f"FAIL: unexpected depths for {path.name}: gate {gate_depth}, AND {and_depth}"
            )
        print(
            f"PASS: {path.name}: {counts['AND']} AND + {counts['XOR']} XOR + "
            f"{counts['NOT']} NOT = {expected_total}; depth {gate_depth}; "
            f"AND-depth {and_depth}; fixed SHA-256"
        )


if __name__ == "__main__":
    main()
