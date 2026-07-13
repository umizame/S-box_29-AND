#!/usr/bin/env python3
"""Cross-check the FIPS algebraic definition, the FIPS table, and both SLPs."""
from pathlib import Path

from verify_slp import AES_SBOX_TABLE, aes_sbox_algebraic, evaluate_scalar, gate_counts, parse_slp

ROOT = Path(__file__).resolve().parents[1]
PATHS = (
    ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp",
    ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp",
    ROOT / "baseline" / "aes-sbox-fwd-g113-a32-d27-ad6.slp",
)


def main() -> None:
    circuits = [parse_slp(path, allow_xnor=(path.parent.name == "baseline")) for path in PATHS]
    expected_ands = (29, 29, 32)
    for circuit, expected in zip(circuits, expected_ands):
        actual = gate_counts(circuit)["AND"]
        if actual != expected:
            raise SystemExit(f"FAIL: {circuit.path.name} has {actual} AND gates, expected {expected}")

    for x, table_value in enumerate(AES_SBOX_TABLE):
        algebraic = aes_sbox_algebraic(x)
        if algebraic != table_value:
            raise SystemExit(
                f"FAIL: FIPS algebraic definition and fixed table disagree at {x:02x}: "
                f"{algebraic:02x} != {table_value:02x}"
            )
        for circuit in circuits:
            obtained = evaluate_scalar(circuit, x)
            if obtained != table_value:
                raise SystemExit(
                    f"FAIL: {circuit.path.name} mismatch at {x:02x}: "
                    f"{obtained:02x} != {table_value:02x}"
                )
    print("PASS: FIPS algebraic definition, fixed FIPS table, NIST baseline, and both 29-AND SLPs agree on all 256 inputs")


if __name__ == "__main__":
    main()
