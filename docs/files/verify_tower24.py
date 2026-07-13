#!/usr/bin/env python3
"""Verify the complete 24-product, schedule-aware bridge to the NIST SLP.

The checker derives every target space from the archived NIST 32-AND circuit;
the witness supplies only 24 product factors and 12 reconstruction masks.
It checks exterior-form identities, all 4096 formal coordinate assignments,
and the actual staged realization on all 256 AES inputs.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import combinations
import hashlib
from pathlib import Path

from verify_slp import AES_SBOX_TABLE, Circuit, evaluate_bitparallel, gate_counts, parse_slp

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "baseline" / "aes-sbox-fwd-g113-a32-d27-ad6.slp"
CERTIFICATE = ROOT / "certificates" / "tower24_witness.txt"
BASELINE_SHA256 = "6ba4f63b832a1f4520a76cab5680e673fdd744ad2651918882eeecff7957698a"
MASK256 = (1 << 256) - 1
PAIRS = tuple(combinations(range(12), 2))
PAIR_INDEX = {pair: index for index, pair in enumerate(PAIRS)}
COORDINATE_NAMES = (
    "t8", "t11", "t2", "t10",      # L0,...,L3
    "t13", "t15", "t21", "t6",    # R0,...,R3
    "t66", "t59", "t65", "t62",   # Z0,...,Z3
)
EARLY_INDICES = (0, 1, 2, 8, 9, 10, 16, 17, 18)


@dataclass(frozen=True)
class Product:
    u: int
    v: int
    signature: int


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def xor_rank(vectors) -> int:
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
    return len(pivots)


def solve_xor(target: int, basis: list[int]) -> int | None:
    pivots: dict[int, tuple[int, int]] = {}
    for index, value in enumerate(basis):
        x = value
        coefficients = 1 << index
        while x:
            pivot = x.bit_length() - 1
            if pivot in pivots:
                x ^= pivots[pivot][0]
                coefficients ^= pivots[pivot][1]
            else:
                pivots[pivot] = (x, coefficients)
                break
    x = target
    coefficients = 0
    while x:
        pivot = x.bit_length() - 1
        if pivot not in pivots:
            return None
        x ^= pivots[pivot][0]
        coefficients ^= pivots[pivot][1]
    return coefficients


def combine(coefficients: int, basis: list[int]) -> int:
    value = 0
    for index, vector in enumerate(basis):
        if (coefficients >> index) & 1:
            value ^= vector
    return value


def independent_in_order(vectors) -> list[int]:
    pivots: dict[int, int] = {}
    result: list[int] = []
    for value in vectors:
        x = value
        while x:
            pivot = x.bit_length() - 1
            if pivot in pivots:
                x ^= pivots[pivot]
            else:
                pivots[pivot] = x
                result.append(value)
                break
    return result


def wedge(u: int, v: int) -> int:
    result = 0
    for i, j in PAIRS:
        coefficient = (((u >> i) & 1) & ((v >> j) & 1)) ^ (((u >> j) & 1) & ((v >> i) & 1))
        if coefficient:
            result |= 1 << PAIR_INDEX[(i, j)]
    return result


def quadratic_value(signature: int, assignment: int) -> int:
    value = 0
    for index, (i, j) in enumerate(PAIRS):
        if (signature >> index) & 1:
            value ^= ((assignment >> i) & 1) & ((assignment >> j) & 1)
    return value


def parse_certificate(path: Path) -> tuple[int, list[Product], list[int]]:
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    require(bool(lines), "empty tower certificate")
    header = lines[0].split()
    require(len(header) == 2 and header[0] == "A", "certificate must begin with 'A <hex>'")
    transform = int(header[1], 16)

    products: list[Product] = []
    position = 1
    while position < len(lines) and lines[position] != "COEFF":
        fields = lines[position].split()
        require(len(fields) == 3, f"bad product row {position}")
        u, v, signature = (int(field, 16) for field in fields)
        require(u < (1 << 12) and v < (1 << 12), f"factor mask outside 12 coordinates at row {position}")
        require(signature < (1 << 66), f"signature mask outside Lambda^2(F_2^12) at row {position}")
        products.append(Product(u, v, signature))
        position += 1
    require(position < len(lines) and lines[position] == "COEFF", "missing COEFF delimiter")
    coefficients = [int(line, 16) for line in lines[position + 1:]]
    require(len(products) == 24, f"expected 24 products, obtained {len(products)}")
    require(len(coefficients) == 12, f"expected 12 coefficient rows, obtained {len(coefficients)}")
    require(all(mask < (1 << 24) for mask in coefficients), "coefficient mask outside 24 products")
    return transform, products, coefficients


def baseline_data() -> tuple[Circuit, dict[str, int], dict[str, int], list]:
    digest = hashlib.sha256(BASELINE.read_bytes()).hexdigest()
    require(digest == BASELINE_SHA256, f"archived NIST baseline SHA-256 mismatch: {digest}")
    circuit = parse_slp(BASELINE, allow_xnor=True)
    counts = gate_counts(circuit)
    require(counts == {"AND": 32, "XOR": 77, "XNOR": 4, "NOT": 0}, f"unexpected baseline tally: {counts}")

    values = evaluate_bitparallel(circuit)
    for x, expected in enumerate(AES_SBOX_TABLE):
        obtained = sum(((values[f"S{i}"] >> x) & 1) << (7 - i) for i in range(8))
        require(obtained == expected, f"NIST baseline mismatch at input {x:02x}")

    affine_masks = {f"U{i}": 1 << (i + 1) for i in range(8)}
    and_operations = []
    for operation in circuit.ops:
        if operation.kind == "XOR":
            affine_masks[operation.out] = affine_masks[operation.a] ^ affine_masks[operation.b]  # type: ignore[index]
        elif operation.kind == "XNOR":
            affine_masks[operation.out] = 1 ^ affine_masks[operation.a] ^ affine_masks[operation.b]  # type: ignore[index]
        elif operation.kind == "NOT":
            affine_masks[operation.out] = 1 ^ affine_masks[operation.a]
        else:
            and_operations.append(operation)
            affine_masks[operation.out] = 1 << (8 + len(and_operations))
    require(len(and_operations) == 32, "baseline AND list has wrong length")
    return circuit, values, affine_masks, and_operations


def triangle_factor_pairs(local: tuple[int, int, int, int, int, int]) -> list[tuple[int, int]]:
    x0, x1, y0, y1, z0, z1 = local
    return [
        (y0, x0),
        (y1, x1),
        (y0 ^ y1, x0 ^ x1),
        (x0 ^ y0 ^ y1 ^ z1, x1 ^ y0 ^ z0),
        (x1 ^ y0 ^ y1 ^ z1, x0 ^ x1 ^ y0 ^ z0),
        (x1 ^ y0 ^ y1 ^ z0 ^ z1, x0 ^ y1 ^ z0),
        (x1 ^ y0 ^ z1, x0 ^ x1 ^ y1 ^ z0),
        (x1 ^ y0 ^ z0 ^ z1, x0 ^ y0 ^ y1 ^ z0),
    ]


def verify_transform_and_blocks(transform: int, products: list[Product]) -> None:
    require(transform == 0x128C, f"unexpected transform tag A={transform:04x}")
    rows = (0xC, 0x8, 0x2, 0x1)
    require(xor_rank(rows) == 4, "transform rows c,8,2,1 are not invertible")

    first = (0x00C, 0x008, 0x0C0, 0x080, 0xC00, 0x800)
    second = (0x002, 0x001, 0x020, 0x010, 0x200, 0x100)
    summed = tuple(a ^ b for a, b in zip(first, second))
    expected = triangle_factor_pairs(first) + triangle_factor_pairs(second) + triangle_factor_pairs(summed)
    actual = [(product.u, product.v) for product in products]
    require(actual == expected, "24 factor pairs are not the three stated GF(4)-triangle blocks")


def derive_targets(values: dict[str, int], affine_masks: dict[str, int], and_operations: list):
    coordinates = [values[name] for name in COORDINATE_NAMES]
    left_values, right_values, post_values = coordinates[:4], coordinates[4:8], coordinates[8:]
    require((xor_rank(left_values), xor_rank(right_values), xor_rank(post_values)) == (4, 4, 4), "L, R, or Z coordinates are singular")

    left_names = COORDINATE_NAMES[:4]
    right_names = COORDINATE_NAMES[4:8]
    post_names = COORDINATE_NAMES[8:]

    def coordinate_mask(name: str, basis_names: tuple[str, ...], shift: int) -> int:
        # Solve in the syntactic affine-mask space whose independent symbols are
        # the constant, inputs, and NIST AND outputs.  This is stronger than
        # merely fitting the 256-point truth table.
        basis_masks = [affine_masks[basis_name] for basis_name in basis_names]
        solution = solve_xor(affine_masks[name], basis_masks)
        require(solution is not None, f"wire {name} is outside the claimed formal coordinate span")
        truth_basis = [values[basis_name] for basis_name in basis_names]
        require(combine(solution, truth_basis) == values[name], f"coordinate identity for {name} fails as a truth table")  # type: ignore[arg-type]
        return solution << shift  # type: ignore[operator]

    outer_signatures: list[int] = []
    for operation in and_operations[:9]:
        outer_signatures.append(
            wedge(coordinate_mask(operation.a, left_names, 0), coordinate_mask(operation.b, right_names, 4))
        )
    for operation in and_operations[14:23]:
        outer_signatures.append(
            wedge(coordinate_mask(operation.a, post_names, 8), coordinate_mask(operation.b, right_names, 4))
        )
    for operation in and_operations[23:32]:
        outer_signatures.append(
            wedge(coordinate_mask(operation.a, post_names, 8), coordinate_mask(operation.b, left_names, 0))
        )
    require(len(outer_signatures) == 27 and xor_rank(outer_signatures) == 27, "NIST outer signatures do not have rank 27")

    outer_atom_numbers = list(range(1, 10)) + list(range(15, 33))

    def project(mask: int) -> int:
        result = 0
        for index, atom_number in enumerate(outer_atom_numbers):
            if (mask >> (8 + atom_number)) & 1:
                result |= 1 << index
        return result

    pre_requirements: list[int] = []
    for operation in and_operations[9:14]:
        pre_requirements.extend((project(affine_masks[operation.a]), project(affine_masks[operation.b])))
    all_requirements = pre_requirements + [project(affine_masks[f"S{i}"]) for i in range(8)]
    pre_coefficients = independent_in_order(pre_requirements)
    total_coefficients = independent_in_order(all_requirements)
    require(len(pre_coefficients) == 4, f"pre-middle target rank is {len(pre_coefficients)}, expected 4")
    require(len(total_coefficients) == 12, f"total target rank is {len(total_coefficients)}, expected 12")

    def map_to_signature(coefficients: int) -> int:
        result = 0
        for index, signature in enumerate(outer_signatures):
            if (coefficients >> index) & 1:
                result ^= signature
        return result

    q_pre = [map_to_signature(coefficients) for coefficients in pre_coefficients]
    q_total = [map_to_signature(coefficients) for coefficients in total_coefficients]
    require(q_total[:4] == q_pre, "ordered total basis does not begin with the pre-middle basis")
    require(xor_rank(q_pre) == 4 and xor_rank(q_total) == 12, "derived signature ranks are wrong")
    return coordinates, q_pre, q_total


def verify_certificate_identities(products: list[Product], coefficients: list[int], q_pre: list[int], q_total: list[int]) -> None:
    for index, product in enumerate(products, 1):
        require(wedge(product.u, product.v) == product.signature, f"product {index} has an incorrect exterior signature")
    require(xor_rank(product.signature for product in products) == 24, "24 product signatures are not independent")

    early = tuple(index for index, product in enumerate(products) if ((product.u | product.v) >> 8) == 0)
    require(early == EARLY_INDICES, f"wrong early schedule: {early}")

    for row, (target, coefficient_mask) in enumerate(zip(q_total, coefficients)):
        signature = 0
        linear_correction = 0
        for index, product in enumerate(products):
            if (coefficient_mask >> index) & 1:
                signature ^= product.signature
                linear_correction ^= product.u & product.v
        require(signature == target, f"exterior identity fails in row {row + 1}")
        if row < len(q_pre):
            late_use = coefficient_mask & ~sum(1 << index for index in EARLY_INDICES)
            require(late_use == 0, f"pre-middle row {row + 1} uses a late product")

        for assignment in range(1 << 12):
            right = (linear_correction & assignment).bit_count() & 1
            for index, product in enumerate(products):
                if (coefficient_mask >> index) & 1:
                    left_factor = (product.u & assignment).bit_count() & 1
                    right_factor = (product.v & assignment).bit_count() & 1
                    right ^= left_factor & right_factor
            expected = quadratic_value(target, assignment)
            require(right == expected, f"formal identity row {row + 1} fails at assignment {assignment:03x}")


def verify_staged_realization(values: dict[str, int], and_operations: list, coordinates: list[int], products: list[Product]) -> None:
    def product_truth_table(product: Product) -> int:
        left = 0
        right = 0
        for index, coordinate in enumerate(coordinates):
            if (product.u >> index) & 1:
                left ^= coordinate
            if (product.v >> index) & 1:
                right ^= coordinate
        return left & right

    product_values = [product_truth_table(product) for product in products]
    input_values = [values[f"U{i}"] for i in range(8)]
    early_values = [product_values[index] for index in EARLY_INDICES]
    middle_values: list[int] = []

    for middle_index, operation in enumerate(and_operations[9:14], 1):
        basis = [MASK256] + input_values + early_values + middle_values
        reconstructed_factors = []
        for factor_name in (operation.a, operation.b):
            solution = solve_xor(values[factor_name], basis)
            require(solution is not None, f"middle AND {middle_index} factor {factor_name} is unavailable")
            reconstructed = combine(solution, basis)  # type: ignore[arg-type]
            require(reconstructed == values[factor_name], f"middle AND {middle_index} factor reconstruction is wrong")
            reconstructed_factors.append(reconstructed)
        output = reconstructed_factors[0] & reconstructed_factors[1]
        require(output == values[operation.out], f"middle AND {middle_index} output differs from NIST")
        middle_values.append(output)

    post_basis = [MASK256] + input_values + early_values + middle_values
    for name in COORDINATE_NAMES[8:]:
        solution = solve_xor(values[name], post_basis)
        require(solution is not None, f"post-middle coordinate {name} is unavailable")
        require(combine(solution, post_basis) == values[name], f"post-middle coordinate {name} reconstructs incorrectly")  # type: ignore[arg-type]

    late_values = [product_values[index] for index in range(24) if index not in EARLY_INDICES]
    output_basis = post_basis + late_values
    for index in range(8):
        name = f"S{index}"
        solution = solve_xor(values[name], output_basis)
        require(solution is not None, f"output {name} is unavailable after the late products")
        require(combine(solution, output_basis) == values[name], f"output {name} reconstructs incorrectly")  # type: ignore[arg-type]


def main() -> None:
    _, values, affine_masks, and_operations = baseline_data()
    coordinates, q_pre, q_total = derive_targets(values, affine_masks, and_operations)
    transform, products, coefficients = parse_certificate(CERTIFICATE)
    verify_transform_and_blocks(transform, products)
    verify_certificate_identities(products, coefficients, q_pre, q_total)
    verify_staged_realization(values, and_operations, coordinates, products)

    print("PASS: fixed NIST baseline is the FIPS AES S-box and has nonlinear schedule 9 + 5 + 18")
    print("PASS: derived outer rank 27, pre-middle target rank 4, total target rank 12")
    print("PASS: transform A=128c is invertible and the witness is three exact eight-product GF(4) blocks")
    print("PASS: 24 product signatures have rank 24 and schedule 9 early + 15 late")
    print("PASS: all 12 reconstruction identities hold on all 4096 formal coordinate assignments")
    print("PASS: staged realization 9 + 5 + 15 = 29 reconstructs all middle factors, Z coordinates, and AES outputs")


if __name__ == "__main__":
    main()
