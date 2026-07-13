#!/usr/bin/env python3
"""Evaluate every SLP wire as a 256-bit truth table."""
from pathlib import Path

from verify_slp import evaluate_bitparallel, expected_output_truth_tables, gate_counts, parse_slp

ROOT = Path(__file__).resolve().parents[1]
PATHS = (
    ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp",
    ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp",
)


def main() -> None:
    expected = expected_output_truth_tables()
    for path in PATHS:
        circuit = parse_slp(path)
        if gate_counts(circuit)["AND"] != 29:
            raise SystemExit(f"FAIL: {path.name} does not contain exactly 29 AND gates")
        values = evaluate_bitparallel(circuit)
        obtained = tuple(values[name] for name in circuit.outputs)
        if obtained != expected:
            bad = next(i for i, (a, b) in enumerate(zip(obtained, expected)) if a != b)
            raise SystemExit(f"FAIL: bit-parallel output S{bad} differs for {path.name}")
        print(f"PASS: {path.name}: 256-bit truth-table evaluation; 29 AND; all 256 inputs")


if __name__ == "__main__":
    main()
