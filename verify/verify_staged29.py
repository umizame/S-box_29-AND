#!/usr/bin/env python3
"""Verify the compact staged 29-AND construction on the full AES domain.

This checker uses only the Python standard library.  It reads the 24 product
factors and the staged affine reconstruction masks, enforces the declared
availability filtration, and compares all 256 outputs with the literal FIPS
197 forward S-box table.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PRODUCT_CERTIFICATE = ROOT / "certificates" / "tower24_witness.txt"
STAGED_CERTIFICATE = ROOT / "certificates" / "staged29_witness.txt"
EXPECTED_PRODUCT_SHA256 = "1e847a85e3abe783d98e3d4c48a7d9eb845caab96903c175657cce06119c6925"
EXPECTED_STAGED_SHA256 = "d72ca4cd9617b365587a3b826ab3a0d37489187cdd67fca18ff50b1d3d5e0083"

FIPS_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)

COORD_NAMES = tuple(f"L{i}" for i in range(4)) + tuple(f"R{i}" for i in range(4))
POST_NAMES = tuple(f"Z{i}" for i in range(4))
MIDDLE_NAMES = tuple(f"M{i}" for i in range(1, 6))
OUTPUT_NAMES = tuple(f"S{i}" for i in range(8))
EXPECTED_EARLY = ("P01", "P02", "P03", "P09", "P10", "P11", "P17", "P18", "P19")
EXPECTED_LATE = ("P04", "P05", "P06", "P07", "P08", "P12", "P13", "P14", "P15", "P16", "P20", "P21", "P22", "P23", "P24")


@dataclass(frozen=True)
class Product:
    left: int
    right: int


@dataclass(frozen=True)
class StagedWitness:
    coordinates: tuple[int, ...]
    early: tuple[str, ...]
    middle: tuple[tuple[int, int], ...]
    post: tuple[int, ...]
    late: tuple[str, ...]
    outputs: tuple[int, ...]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_products(path: Path) -> tuple[Product, ...]:
    lines = [line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()]
    lines = [line for line in lines if line]
    require(lines and lines[0] == "A 128c", "unexpected product-certificate header")
    products: list[Product] = []
    position = 1
    while position < len(lines) and lines[position] != "COEFF":
        fields = lines[position].split()
        require(len(fields) == 3, f"bad product row {position}")
        left, right, signature = (int(field, 16) for field in fields)
        require(left < (1 << 12) and right < (1 << 12), f"product {position} factor outside 12 coordinates")
        require(signature < (1 << 66), f"product {position} signature outside 66 bits")
        products.append(Product(left, right))
        position += 1
    require(position < len(lines) and lines[position] == "COEFF", "missing product COEFF delimiter")
    require(len(products) == 24, f"expected 24 products, obtained {len(products)}")
    require(len(lines[position + 1:]) == 12, "expected twelve formal reconstruction rows")
    return tuple(products)


def parse_staged(path: Path) -> StagedWitness:
    lines = [line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()]
    lines = [line for line in lines if line]
    require(lines and lines[0] == "AES29-STAGED 1", "unexpected staged-certificate header")
    position = 1

    coordinates: list[int] = []
    for expected in COORD_NAMES:
        fields = lines[position].split()
        require(len(fields) == 3 and fields[:2] == ["COORD", expected], f"expected coordinate {expected}")
        mask = int(fields[2], 16)
        require(mask < (1 << 8), f"coordinate {expected} mask exceeds eight inputs")
        coordinates.append(mask)
        position += 1

    fields = lines[position].split()
    require(fields[0] == "EARLY" and tuple(fields[1:]) == EXPECTED_EARLY, "unexpected early-product order")
    early = tuple(fields[1:])
    position += 1

    middle: list[tuple[int, int]] = []
    for index, expected in enumerate(MIDDLE_NAMES, 1):
        fields = lines[position].split()
        require(len(fields) == 4 and fields[:2] == ["MIDDLE", expected], f"expected middle row {expected}")
        left, right = int(fields[2], 16), int(fields[3], 16)
        allowed_bits = 17 + index  # 1, eight inputs, nine early products, and M1,...,M_(index-1)
        require(left >> allowed_bits == 0 and right >> allowed_bits == 0, f"{expected} uses an unavailable middle output")
        middle.append((left, right))
        position += 1

    post: list[int] = []
    for expected in POST_NAMES:
        fields = lines[position].split()
        require(len(fields) == 3 and fields[:2] == ["POST", expected], f"expected post-coordinate {expected}")
        mask = int(fields[2], 16)
        require(mask < (1 << 23), f"post-coordinate {expected} mask exceeds the middle basis")
        post.append(mask)
        position += 1

    fields = lines[position].split()
    require(fields[0] == "LATE" and tuple(fields[1:]) == EXPECTED_LATE, "unexpected late-product order")
    late = tuple(fields[1:])
    position += 1

    outputs: list[int] = []
    for expected in OUTPUT_NAMES:
        fields = lines[position].split()
        require(len(fields) == 3 and fields[:2] == ["OUTPUT", expected], f"expected output row {expected}")
        mask = int(fields[2], 16)
        require(mask < (1 << 38), f"output {expected} mask exceeds the final affine basis")
        outputs.append(mask)
        position += 1

    require(position < len(lines) and lines[position] == "END", "missing staged-certificate END")
    require(position + 1 == len(lines), "trailing staged-certificate data")
    return StagedWitness(tuple(coordinates), early, tuple(middle), tuple(post), late, tuple(outputs))


def affine(mask: int, basis: list[int]) -> int:
    require(mask >> len(basis) == 0, "affine mask refers outside its basis")
    value = 0
    for index, bit in enumerate(basis):
        if (mask >> index) & 1:
            value ^= bit
    return value


def product_value(product: Product, coordinates: list[int]) -> int:
    return affine(product.left, coordinates) & affine(product.right, coordinates)


def evaluate(x: int, products: tuple[Product, ...], witness: StagedWitness) -> int:
    inputs = [(x >> (7 - index)) & 1 for index in range(8)]
    coordinates = [affine(mask, inputs) for mask in witness.coordinates]

    product_by_name: dict[str, int] = {}
    for name in witness.early:
        index = int(name[1:]) - 1
        product_by_name[name] = product_value(products[index], coordinates)

    middle_values: list[int] = []
    for left_mask, right_mask in witness.middle:
        basis = [1] + inputs + [product_by_name[name] for name in witness.early] + middle_values
        middle_values.append(affine(left_mask, basis) & affine(right_mask, basis))

    middle_basis = [1] + inputs + [product_by_name[name] for name in witness.early] + middle_values
    coordinates.extend(affine(mask, middle_basis) for mask in witness.post)
    require(len(coordinates) == 12, "coordinate construction did not produce twelve bits")

    for name in witness.late:
        index = int(name[1:]) - 1
        product_by_name[name] = product_value(products[index], coordinates)

    output_basis = middle_basis + [product_by_name[name] for name in witness.late]
    bits = [affine(mask, output_basis) for mask in witness.outputs]
    return sum(bit << (7 - index) for index, bit in enumerate(bits))


def main() -> None:
    require(sha256(PRODUCT_CERTIFICATE) == EXPECTED_PRODUCT_SHA256, "product certificate SHA-256 mismatch")
    require(sha256(STAGED_CERTIFICATE) == EXPECTED_STAGED_SHA256, "staged certificate SHA-256 mismatch")
    products = parse_products(PRODUCT_CERTIFICATE)
    witness = parse_staged(STAGED_CERTIFICATE)

    early_from_factors = tuple(
        f"P{index + 1:02d}" for index, product in enumerate(products)
        if ((product.left | product.right) >> 8) == 0
    )
    late_from_factors = tuple(
        f"P{index + 1:02d}" for index, product in enumerate(products)
        if ((product.left | product.right) >> 8) != 0
    )
    require(early_from_factors == witness.early, "early product list does not match product-factor availability")
    require(late_from_factors == witness.late, "late product list does not match product-factor availability")

    for x, expected in enumerate(FIPS_SBOX):
        obtained = evaluate(x, products, witness)
        require(obtained == expected, f"input {x:02x}: obtained {obtained:02x}, expected {expected:02x}")

    print("PASS: staged certificate; 9 early AND + 5 middle AND + 15 late AND = 29 AND")
    print("PASS: all affine masks obey their availability filtration; all 256 FIPS table entries agree")


if __name__ == "__main__":
    main()
