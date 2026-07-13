#!/usr/bin/env python3
"""Shared, dependency-free verification utilities for AES S-box SLPs.

Bit convention: U0/S0 are the most significant bits of the input/output byte.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

MASK256 = (1 << 256) - 1
AES_SBOX_TABLE = (
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
)


@dataclass(frozen=True)
class Op:
    kind: str
    out: str
    a: str
    b: str | None = None
    line: int = 0


@dataclass(frozen=True)
class Circuit:
    path: Path
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    ops: tuple[Op, ...]


def _parse_wire_range(text: str) -> tuple[str, ...]:
    lo, hi = text.strip().split(":", 1)
    prefix_lo = lo.rstrip("0123456789")
    prefix_hi = hi.rstrip("0123456789")
    if prefix_lo != prefix_hi or not prefix_lo:
        raise ValueError(f"invalid wire range: {text!r}")
    a = int(lo[len(prefix_lo):])
    b = int(hi[len(prefix_hi):])
    if a > b:
        raise ValueError(f"descending wire range: {text!r}")
    return tuple(f"{prefix_lo}{i}" for i in range(a, b + 1))


def parse_slp(path: str | Path, *, allow_xnor: bool = False) -> Circuit:
    path = Path(path)
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    ops: list[Op] = []
    inside = False
    began = False
    ended = False
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        s = raw.split("#", 1)[0].strip()
        if not s:
            continue
        if s.startswith("Inputs:"):
            inputs = _parse_wire_range(s.split(":", 1)[1].strip())
            continue
        if s.startswith("Outputs:"):
            outputs = _parse_wire_range(s.split(":", 1)[1].strip())
            continue
        if s == "begin SLP":
            if began or inside:
                raise ValueError(f"line {lineno}: duplicate begin SLP")
            began = inside = True
            continue
        if s == "end SLP":
            if not inside:
                raise ValueError(f"line {lineno}: end SLP before begin SLP")
            inside = False
            ended = True
            continue
        if not inside:
            continue
        p = s.split()
        binary = {"XOR", "AND"} | ({"XNOR"} if allow_xnor else set())
        if len(p) == 4 and p[0] in binary:
            ops.append(Op(p[0], p[1], p[2], p[3], lineno))
        elif len(p) == 3 and p[0] == "NOT":
            ops.append(Op(p[0], p[1], p[2], None, lineno))
        else:
            raise ValueError(f"line {lineno}: illegal instruction {s!r}")
    if not began or not ended or inside:
        raise ValueError("missing or unbalanced SLP delimiters")
    if len(inputs) != 8 or len(outputs) != 8:
        raise ValueError(f"expected 8 inputs and 8 outputs, got {len(inputs)} and {len(outputs)}")
    if not ops:
        raise ValueError("empty SLP")
    return Circuit(path, inputs, outputs, tuple(ops))


def validate_structure(circuit: Circuit) -> None:
    defined = set(circuit.inputs)
    for op in circuit.ops:
        if op.out in defined:
            raise ValueError(f"line {op.line}: wire redefinition: {op.out}")
        if op.a not in defined:
            raise ValueError(f"line {op.line}: use before definition: {op.a}")
        if op.b is not None and op.b not in defined:
            raise ValueError(f"line {op.line}: use before definition: {op.b}")
        defined.add(op.out)
    missing = [name for name in circuit.outputs if name not in defined]
    if missing:
        raise ValueError(f"missing outputs: {', '.join(missing)}")


def gate_counts(circuit: Circuit) -> dict[str, int]:
    counts = {"AND": 0, "XOR": 0, "XNOR": 0, "NOT": 0}
    for op in circuit.ops:
        counts[op.kind] += 1
    return counts


def depths(circuit: Circuit) -> tuple[int, int, tuple[int, ...], tuple[int, ...]]:
    validate_structure(circuit)
    depth = {name: 0 for name in circuit.inputs}
    and_depth = {name: 0 for name in circuit.inputs}
    for op in circuit.ops:
        if op.b is None:
            depth[op.out] = depth[op.a] + 1
            and_depth[op.out] = and_depth[op.a]
        else:
            depth[op.out] = max(depth[op.a], depth[op.b]) + 1
            and_depth[op.out] = max(and_depth[op.a], and_depth[op.b]) + (op.kind == "AND")
    od = tuple(depth[name] for name in circuit.outputs)
    oad = tuple(and_depth[name] for name in circuit.outputs)
    return max(od), max(oad), od, oad


def gf256_mul(a: int, b: int) -> int:
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = ((a << 1) & 0xFF) ^ (0x1B if a & 0x80 else 0)
        b >>= 1
    return r


def aes_sbox_algebraic(x: int) -> int:
    if not 0 <= x < 256:
        raise ValueError(x)
    if x == 0:
        y = 0
    else:
        y, a, e = 1, x, 254
        while e:
            if e & 1:
                y = gf256_mul(y, a)
            a = gf256_mul(a, a)
            e >>= 1
    out = 0
    for i in range(8):
        bit = (
            ((y >> i) & 1)
            ^ ((y >> ((i + 4) & 7)) & 1)
            ^ ((y >> ((i + 5) & 7)) & 1)
            ^ ((y >> ((i + 6) & 7)) & 1)
            ^ ((y >> ((i + 7) & 7)) & 1)
            ^ ((0x63 >> i) & 1)
        )
        out |= bit << i
    return out


def evaluate_scalar(circuit: Circuit, x: int) -> int:
    validate_structure(circuit)
    values = {name: (x >> (7 - i)) & 1 for i, name in enumerate(circuit.inputs)}
    for op in circuit.ops:
        if op.kind == "XOR":
            values[op.out] = values[op.a] ^ values[op.b]  # type: ignore[index]
        elif op.kind == "XNOR":
            values[op.out] = values[op.a] ^ values[op.b] ^ 1  # type: ignore[index]
        elif op.kind == "AND":
            values[op.out] = values[op.a] & values[op.b]  # type: ignore[index]
        elif op.kind == "NOT":
            values[op.out] = values[op.a] ^ 1
        else:  # pragma: no cover - parser excludes this
            raise ValueError(op.kind)
    return sum(values[name] << (7 - i) for i, name in enumerate(circuit.outputs))


def input_truth_tables(inputs: Sequence[str]) -> dict[str, int]:
    return {
        name: sum((((x >> (7 - i)) & 1) << x) for x in range(256))
        for i, name in enumerate(inputs)
    }


def evaluate_bitparallel(circuit: Circuit) -> dict[str, int]:
    validate_structure(circuit)
    values = input_truth_tables(circuit.inputs)
    for op in circuit.ops:
        if op.kind == "XOR":
            values[op.out] = values[op.a] ^ values[op.b]  # type: ignore[index]
        elif op.kind == "XNOR":
            values[op.out] = values[op.a] ^ values[op.b] ^ MASK256  # type: ignore[index]
        elif op.kind == "AND":
            values[op.out] = values[op.a] & values[op.b]  # type: ignore[index]
        elif op.kind == "NOT":
            values[op.out] = values[op.a] ^ MASK256
    return values


def expected_output_truth_tables() -> tuple[int, ...]:
    tables = []
    for bit_index in range(8):
        bit = 7 - bit_index
        tables.append(sum((((AES_SBOX_TABLE[x] >> bit) & 1) << x) for x in range(256)))
    return tuple(tables)


def verify_all_inputs(circuit: Circuit, *, max_ands: int | None = None) -> None:
    validate_structure(circuit)
    counts = gate_counts(circuit)
    if max_ands is not None and counts["AND"] > max_ands:
        raise AssertionError(f"{counts['AND']} AND gates exceed bound {max_ands}")
    for x, expected in enumerate(AES_SBOX_TABLE):
        algebraic = aes_sbox_algebraic(x)
        if algebraic != expected:
            raise AssertionError(f"reference mismatch at {x:02x}: {algebraic:02x} != {expected:02x}")
        got = evaluate_scalar(circuit, x)
        if got != expected:
            raise AssertionError(f"SLP mismatch at {x:02x}: {got:02x} != {expected:02x}")


def affine_xag(circuit: Circuit) -> tuple[list[tuple[int, int]], list[int]]:
    """Return normalized AND-factor masks and output masks.

    Mask bit 0 is constant 1, bits 1..8 are U0..U7, and each subsequent
    bit is the output of a preceding AND gate. Linear gates are absorbed.
    """
    validate_structure(circuit)
    mask: dict[str, int] = {name: 1 << (1 + i) for i, name in enumerate(circuit.inputs)}
    ands: list[tuple[int, int]] = []
    for op in circuit.ops:
        if op.kind == "XOR":
            mask[op.out] = mask[op.a] ^ mask[op.b]  # type: ignore[index]
        elif op.kind == "XNOR":
            mask[op.out] = mask[op.a] ^ mask[op.b] ^ 1  # type: ignore[index]
        elif op.kind == "NOT":
            mask[op.out] = mask[op.a] ^ 1
        elif op.kind == "AND":
            ands.append((mask[op.a], mask[op.b]))  # type: ignore[index]
            mask[op.out] = 1 << (8 + len(ands))
    return ands, [mask[name] for name in circuit.outputs]


def xor_rank(vectors: Iterable[int]) -> int:
    pivots: dict[int, int] = {}
    for value in vectors:
        x = value
        while x:
            p = x.bit_length() - 1
            if p in pivots:
                x ^= pivots[p]
            else:
                pivots[p] = x
                break
    return len(pivots)
