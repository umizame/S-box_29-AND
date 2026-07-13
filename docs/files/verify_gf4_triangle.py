#!/usr/bin/env python3
"""Verify the exact filtered eight-product GF(4) triangle used by the witness.

Elements are written a0*omega+a1 with omega^2=omega+1.  Products p1,p2,p3
use only x and y; p4,...,p8 may also use z.  The formulas below are the
local form of each eight-row block in certificates/tower24_witness.txt.
"""
from __future__ import annotations


def gf4_mul(x: tuple[int, int], y: tuple[int, int]) -> tuple[int, int]:
    x0, x1 = x
    y0, y1 = y
    return (
        (x0 & y0) ^ (x0 & y1) ^ (x1 & y0),
        (x0 & y0) ^ (x1 & y1),
    )


def triangle(x: tuple[int, int], y: tuple[int, int], z: tuple[int, int]):
    x0, x1 = x
    y0, y1 = y
    z0, z1 = z

    p1 = x0 & y0
    p2 = x1 & y1
    p3 = (x0 ^ x1) & (y0 ^ y1)
    p4 = (x0 ^ y0 ^ y1 ^ z1) & (x1 ^ y0 ^ z0)
    p5 = (x1 ^ y0 ^ y1 ^ z1) & (x0 ^ x1 ^ y0 ^ z0)
    p6 = (x1 ^ y0 ^ y1 ^ z0 ^ z1) & (x0 ^ y1 ^ z0)
    p7 = (x1 ^ y0 ^ z1) & (x0 ^ x1 ^ y1 ^ z0)
    p8 = (x1 ^ y0 ^ z0 ^ z1) & (x0 ^ y0 ^ y1 ^ z0)

    xy = (p2 ^ p3, p1 ^ p2)
    yz = (
        y0 ^ y1 ^ p1 ^ p2 ^ p3 ^ p6 ^ p8,
        y1 ^ p5 ^ p6 ^ p7 ^ p8,
    )
    zx = (
        x1 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5,
        x1 ^ y1 ^ z0 ^ p1 ^ p2 ^ p3 ^ p6 ^ p7,
    )
    return (xy, yz, zx)


def anf_coefficients(function, variables: int) -> tuple[int, ...]:
    values = [function(mask) for mask in range(1 << variables)]
    for bit in range(variables):
        for mask in range(1 << variables):
            if mask & (1 << bit):
                values[mask] ^= values[mask ^ (1 << bit)]
    return tuple(index for index, coefficient in enumerate(values) if coefficient)


def format_monomial(mask: int) -> str:
    names = ("x0", "x1", "y0", "y1", "z0", "z1")
    return "*".join(names[i] for i in range(6) if mask & (1 << i)) or "1"


def main() -> None:
    for xv in range(4):
        x = ((xv >> 1) & 1, xv & 1)
        for yv in range(4):
            y = ((yv >> 1) & 1, yv & 1)
            for zv in range(4):
                z = ((zv >> 1) & 1, zv & 1)
                obtained = triangle(x, y, z)
                expected = (gf4_mul(x, y), gf4_mul(y, z), gf4_mul(z, x))
                if obtained != expected:
                    raise SystemExit(
                        f"FAIL: x={xv}, y={yv}, z={zv}: {obtained} != {expected}"
                    )

    expected_anf = (
        (0b000101, 0b000110, 0b001001),  # x0y0 + x1y0 + x0y1
        (0b000101, 0b001010),            # x0y0 + x1y1
        (0b010100, 0b011000, 0b100100),  # y0z0 + y1z0 + y0z1
        (0b010100, 0b101000),            # y0z0 + y1z1
        (0b010001, 0b010010, 0b100001),  # z0x0 + z0x1 + z1x0
        (0b010001, 0b100010),            # z0x0 + z1x1
    )

    def output_bit(mask: int, index: int) -> int:
        bits = tuple((mask >> i) & 1 for i in range(6))
        outputs = triangle((bits[0], bits[1]), (bits[2], bits[3]), (bits[4], bits[5]))
        flat = outputs[0] + outputs[1] + outputs[2]
        return flat[index]

    for index, expected in enumerate(expected_anf):
        obtained = anf_coefficients(lambda mask, i=index: output_bit(mask, i), 6)
        if obtained != expected:
            pretty = " + ".join(format_monomial(m) for m in obtained)
            raise SystemExit(f"FAIL: unexpected ANF for output bit {index}: {pretty}")

    print("PASS: exact GF(4) triangle formula; 8 binary products; all 64 triples")
    print("PASS: symbolic ANFs reduce to the six standard GF(4) product coordinates")


if __name__ == "__main__":
    main()
