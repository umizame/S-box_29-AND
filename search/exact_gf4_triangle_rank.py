#!/usr/bin/env python3
"""Exact rank calculation for a restricted GF(4)-triangle product model.

The model allows arbitrary affine postprocessing of products (u·x)(v·x) whose
factors are homogeneous linear forms in the six input bits.  The calculation
shows that seven such products cannot span the six quadratic output forms,
whereas verify/verify_gf4_triangle.py gives an eight-product construction.

This is deliberately *not* reported as a lower bound for unrestricted
XOR-AND-NOT circuits.  In the Boolean ring, nonlinear intermediate functions
can multiply and, by idempotence x_i^2=x_i, contribute lower-degree terms; the
linear-factor exterior-form argument does not cover that possibility.
"""
from __future__ import annotations

from itertools import combinations

PAIRS = tuple(combinations(range(6), 2))
PAIR_INDEX = {pair: index for index, pair in enumerate(PAIRS)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def wedge(u: int, v: int) -> int:
    result = 0
    for i, j in PAIRS:
        coefficient = (((u >> i) & 1) & ((v >> j) & 1)) ^ (((u >> j) & 1) & ((v >> i) & 1))
        if coefficient:
            result |= 1 << PAIR_INDEX[(i, j)]
    return result


def echelon(vectors) -> dict[int, int]:
    pivots: dict[int, int] = {}
    for value in vectors:
        x = value
        while x:
            pivot = x.bit_length() - 1
            if pivot in pivots:
                x ^= pivots[pivot]
            else:
                pivots[pivot] = x
                break
    return pivots


def reduce_vector(value: int, pivots: dict[int, int]) -> int:
    x = value
    while x:
        pivot = x.bit_length() - 1
        if pivot not in pivots:
            break
        x ^= pivots[pivot]
    return x


def rank(vectors) -> int:
    return len(echelon(vectors))


def gf4_mul_bits(a0: int, a1: int, b0: int, b1: int) -> tuple[int, int]:
    return (
        (a0 & b0) ^ (a0 & b1) ^ (a1 & b0),
        (a0 & b0) ^ (a1 & b1),
    )


def quadratic_anf(function) -> int:
    values = [function(x) for x in range(64)]
    for bit in range(6):
        for mask in range(64):
            if mask & (1 << bit):
                values[mask] ^= values[mask ^ (1 << bit)]
    result = 0
    for mask, coefficient in enumerate(values):
        if not coefficient:
            continue
        degree = mask.bit_count()
        require(degree <= 2, f"output has ANF degree {degree}")
        if degree == 2:
            pair = tuple(i for i in range(6) if mask & (1 << i))
            result |= 1 << PAIR_INDEX[pair]
    return result


def main() -> None:
    target = []
    for output_index in range(6):
        def output(mask: int, index: int = output_index) -> int:
            bits = [(mask >> i) & 1 for i in range(6)]
            x0, x1, y0, y1, z0, z1 = bits
            coordinates = (
                gf4_mul_bits(x0, x1, y0, y1)
                + gf4_mul_bits(y0, y1, z0, z1)
                + gf4_mul_bits(z0, z1, x0, x1)
            )
            return coordinates[index]
        target.append(quadratic_anf(output))

    require(rank(target) == 6, "the six output quadratic forms are not independent")
    decomposable = sorted(
        {wedge(u, v) for u in range(1, 64) for v in range(u + 1, 64)} - {0}
    )
    require(len(decomposable) == 651, f"expected 651 decomposable points, obtained {len(decomposable)}")

    target_echelon = echelon(target)
    inside_target = [d for d in decomposable if reduce_vector(d, target_echelon) == 0]
    inside_target_rank = rank(inside_target)

    # Extend an ordered basis of Q to a basis of the 15-dimensional ambient space.
    extended = dict(target_echelon)
    complement: list[int] = []
    for coordinate in range(15):
        unit = 1 << coordinate
        reduced = reduce_vector(unit, extended)
        if reduced:
            extended[reduced.bit_length() - 1] = reduced
            complement.append(unit)
    require(len(complement) == 9, f"expected a 9-dimensional quotient, obtained {len(complement)}")

    representatives = []
    for coefficient_mask in range(1, 1 << 9):
        representative = 0
        for index, vector in enumerate(complement):
            if (coefficient_mask >> index) & 1:
                representative ^= vector
        representatives.append(representative)
    require(len(representatives) == 511, "wrong number of seven-dimensional superspaces")

    best_rank = 0
    successful = 0
    best_representative = 0
    for representative in representatives:
        superspace = echelon(target + [representative])
        points = [d for d in decomposable if reduce_vector(d, superspace) == 0]
        point_rank = rank(points)
        if point_rank > best_rank:
            best_rank = point_rank
            best_representative = representative
        if point_rank >= 7:
            successful += 1

    print(
        f"Q rank 6; decomposable points 651; decomposable span inside Q {inside_target_rank}"
    )
    print(
        f"seven-dimensional superspaces 511; best decomposable span {best_rank}; "
        f"successful {successful}; representative 0x{best_representative:x}"
    )
    require(successful == 0 and inside_target_rank < 6, "seven linear-factor products may suffice")
    print("PASS: at least eight homogeneous linear-factor products are required in the stated restricted model")


if __name__ == "__main__":
    main()
