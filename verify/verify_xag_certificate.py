#!/usr/bin/env python3
"""Verify the normalized 29-AND XOR-AND graph on all 256 inputs."""
from __future__ import annotations

import hashlib
from pathlib import Path

from verify_slp import AES_SBOX_TABLE, aes_sbox_algebraic

ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE = ROOT / "certificates" / "aes29.xag"
EXPECTED_SHA256 = "862446d12293b21bfafbd7e958502301619a596e6bf3cb7a3b22f3f830926264"


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def parse(path: Path) -> tuple[list[tuple[int, int]], list[int]]:
    fields = path.read_text(encoding="utf-8").split()
    pos = 0

    def take(expected: str | None = None) -> str:
        nonlocal pos
        if pos >= len(fields):
            fail("unexpected end of XAG certificate")
        value = fields[pos]
        pos += 1
        if expected is not None and value != expected:
            fail(f"expected {expected!r}, obtained {value!r}")
        return value

    take("AES29-XAG")
    take("1")
    take("AND_COUNT")
    and_count = int(take())
    if and_count != 29:
        fail(f"expected 29 AND records, obtained {and_count}")

    gates: list[tuple[int, int]] = []
    for index in range(and_count):
        take("AND")
        take(f"A{index + 1:02d}")
        a = int(take(), 16)
        b = int(take(), 16)
        allowed_bits = 9 + index  # constant, eight inputs, and preceding AND outputs
        if a >> allowed_bits or b >> allowed_bits:
            fail(f"A{index + 1:02d} refers to an unavailable AND output")
        gates.append((a, b))

    take("OUTPUT_COUNT")
    output_count = int(take())
    if output_count != 8:
        fail(f"expected 8 output records, obtained {output_count}")
    outputs: list[int] = []
    for index in range(output_count):
        take("OUTPUT")
        take(f"S{index}")
        mask = int(take(), 16)
        if mask >> (9 + and_count):
            fail(f"S{index} refers to an unavailable AND output")
        outputs.append(mask)
    take("END")
    if pos != len(fields):
        fail("unexpected trailing data after END")
    return gates, outputs


def affine(mask: int, wires: list[int]) -> int:
    value = mask & 1
    for index, bit in enumerate(wires):
        if (mask >> (index + 1)) & 1:
            value ^= bit
    return value


def main() -> None:
    digest = hashlib.sha256(CERTIFICATE.read_bytes()).hexdigest()
    if digest != EXPECTED_SHA256:
        fail(f"certificate SHA-256 mismatch: {digest}")
    gates, outputs = parse(CERTIFICATE)

    for x, table_value in enumerate(AES_SBOX_TABLE):
        if aes_sbox_algebraic(x) != table_value:
            fail(f"reference mismatch at input {x:02x}")
        wires = [(x >> (7 - i)) & 1 for i in range(8)]
        for a, b in gates:
            wires.append(affine(a, wires) & affine(b, wires))
        obtained = sum(affine(mask, wires) << (7 - i) for i, mask in enumerate(outputs))
        if obtained != table_value:
            fail(f"XAG mismatch at input {x:02x}: {obtained:02x} != {table_value:02x}")
    print("PASS: fixed normalized XAG certificate; 29 AND; all 256 inputs")


if __name__ == "__main__":
    main()
