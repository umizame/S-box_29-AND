#!/usr/bin/env python3
"""Check the straight-line program and normalized XAG for the AES S-box."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parent
SLP_PATH = ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp"
XAG_PATH = ROOT / "certificates" / "aes29.xag"
SLP_SHA256 = "f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3"


class VerificationError(ValueError):
    """Raised when a circuit check fails."""


@dataclass(frozen=True)
class Operation:
    opcode: str
    output: str
    operands: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class Circuit:
    name: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    temporaries: tuple[str, ...]
    operations: tuple[Operation, ...]


@dataclass(frozen=True)
class CircuitStatistics:
    instructions: int
    gates: Counter[str]
    depth: int
    and_depth: int


@dataclass(frozen=True)
class XAG:
    """Affine factors of ordered AND atoms, followed by affine outputs."""

    and_factors: tuple[tuple[int, int], ...]
    outputs: tuple[int, ...]


def fail(message: str) -> None:
    raise VerificationError(message)


def _slp_records(path: Path) -> list[tuple[int, str]]:
    records: list[tuple[int, str]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            fail(f"line {line_number}: inline comments are not part of the SLP grammar")
        records.append((line_number, line))
    return records


def parse_slp(path: str | Path) -> Circuit:
    """Parse the SLP and require a well-defined acyclic circuit."""
    records = _slp_records(Path(path))
    position = 0

    def take() -> tuple[int, str]:
        nonlocal position
        if position == len(records):
            fail("unexpected end of SLP")
        record = records[position]
        position += 1
        return record

    def take_exact(expected: str, description: str) -> None:
        line_number, line = take()
        if line != expected:
            fail(
                f"line {line_number}: malformed {description}; "
                f"obtained {line!r}, expected {expected!r}"
            )

    take_exact("begin circuit AES-SBOX-FWD-A29-OPT", "circuit header")
    take_exact("Inputs: U0:U7", "input declaration")
    take_exact("Outputs: S0:S7", "output declaration")
    take_exact("Internal: t1:t220", "internal declaration")
    take_exact("GateSyntax: GateName Output Inputs", "gate-syntax declaration")
    take_exact("begin SLP", "SLP opening")

    operations: list[Operation] = []
    while position < len(records) and records[position][1] != "end SLP":
        line_number, line = take()
        fields = line.split()
        if len(fields) == 4 and fields[0] in {"XOR", "AND"}:
            operations.append(Operation(fields[0], fields[1], tuple(fields[2:]), line_number))
        elif len(fields) == 3 and fields[0] == "NOT":
            operations.append(Operation(fields[0], fields[1], (fields[2],), line_number))
        else:
            fail(f"line {line_number}: illegal instruction {line!r}")

    take_exact("end SLP", "SLP closing")
    take_exact("end circuit", "circuit closing")
    if position != len(records):
        line_number, line = records[position]
        fail(f"line {line_number}: trailing data after circuit: {line!r}")
    if not operations:
        fail("empty SLP")

    inputs = tuple(f"U{index}" for index in range(8))
    outputs = tuple(f"S{index}" for index in range(8))
    temporaries = tuple(f"t{index}" for index in range(1, 221))
    temporary_names = set(temporaries)
    output_names = set(outputs)
    declared_results = temporary_names | output_names
    produced_anywhere = {operation.output for operation in operations}
    defined = set(inputs)

    for operation in operations:
        if operation.output in defined:
            fail(f"line {operation.line}: wire redefinition {operation.output}")
        if operation.output not in declared_results:
            fail(f"line {operation.line}: undeclared output wire {operation.output}")
        for operand in operation.operands:
            if operand in defined:
                continue
            if operand in produced_anywhere:
                fail(f"line {operation.line}: future reference {operand}")
            fail(f"line {operation.line}: undefined operand {operand}")
        defined.add(operation.output)

    for temporary in temporaries:
        if temporary not in defined:
            fail(f"missing declared temporary {temporary}")
    for output in outputs:
        if output not in defined:
            fail(f"missing output {output}")

    return Circuit(
        "AES-SBOX-FWD-A29-OPT", inputs, outputs, temporaries, tuple(operations)
    )


def circuit_statistics(circuit: Circuit) -> CircuitStatistics:
    """Compute instruction counts, gate depth, and AND-depth from the DAG."""
    gates = Counter(operation.opcode for operation in circuit.operations)
    depth = {wire: 0 for wire in circuit.inputs}
    and_depth = dict(depth)
    for operation in circuit.operations:
        depth[operation.output] = 1 + max(depth[wire] for wire in operation.operands)
        nonlinear_step = 1 if operation.opcode == "AND" else 0
        and_depth[operation.output] = (
            max(and_depth[wire] for wire in operation.operands) + nonlinear_step
        )
    return CircuitStatistics(
        len(circuit.operations),
        gates,
        max(depth[wire] for wire in circuit.outputs),
        max(and_depth[wire] for wire in circuit.outputs),
    )


def _xag_records(path: Path) -> list[tuple[int, str]]:
    return [
        (line_number, raw.strip())
        for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if raw.strip()
    ]


def _hex_mask(token: str, description: str) -> int:
    if re.fullmatch(r"[0-9a-f]+", token) is None:
        fail(f"malformed hexadecimal {description}: {token!r}")
    return int(token, 16)


def parse_xag(path: str | Path) -> XAG:
    """Parse the normalized XAG and check every dependency bound."""
    records = _xag_records(Path(path))
    position = 0

    def take() -> tuple[int, str]:
        nonlocal position
        if position == len(records):
            fail("unexpected end of XAG")
        record = records[position]
        position += 1
        return record

    def take_exact(expected: str) -> None:
        line_number, line = take()
        if line != expected:
            fail(f"line {line_number}: obtained {line!r}, expected {expected!r}")

    take_exact("AES29-XAG 1")
    take_exact("AND_COUNT 29")
    factors: list[tuple[int, int]] = []
    for index in range(29):
        line_number, line = take()
        fields = line.split()
        label = f"A{index + 1:02d}"
        if len(fields) != 4 or fields[:2] != ["AND", label]:
            fail(f"line {line_number}: malformed AND {label} row: {line!r}")
        left = _hex_mask(fields[2], f"{label} left factor")
        right = _hex_mask(fields[3], f"{label} right factor")
        available_bits = 9 + index
        if left >> available_bits:
            fail(f"{label} left factor refers to an unavailable atom")
        if right >> available_bits:
            fail(f"{label} right factor refers to an unavailable atom")
        factors.append((left, right))

    take_exact("OUTPUT_COUNT 8")
    outputs: list[int] = []
    for index in range(8):
        line_number, line = take()
        fields = line.split()
        label = f"S{index}"
        if len(fields) != 3 or fields[:2] != ["OUTPUT", label]:
            fail(f"line {line_number}: malformed OUTPUT {label} row: {line!r}")
        mask = _hex_mask(fields[2], f"{label} output")
        if mask >> 38:
            fail(f"{label} output refers to an unavailable atom")
        outputs.append(mask)

    take_exact("END")
    if position != len(records):
        line_number, line = records[position]
        fail(f"line {line_number}: trailing XAG data: {line!r}")
    return XAG(tuple(factors), tuple(outputs))


def normalize_slp(circuit: Circuit) -> XAG:
    """Absorb affine gates into masks over 1, U0,...,U7, A01,...,A29."""
    forms = {
        wire: 1 << (index + 1) for index, wire in enumerate(circuit.inputs)
    }
    factors: list[tuple[int, int]] = []
    for operation in circuit.operations:
        if operation.opcode == "XOR":
            forms[operation.output] = (
                forms[operation.operands[0]] ^ forms[operation.operands[1]]
            )
        elif operation.opcode == "NOT":
            forms[operation.output] = forms[operation.operands[0]] ^ 1
        else:
            factors.append(
                (forms[operation.operands[0]], forms[operation.operands[1]])
            )
            forms[operation.output] = 1 << (8 + len(factors))
    return XAG(
        tuple(factors), tuple(forms[output] for output in circuit.outputs)
    )


def require_same_xag(actual: XAG, expected: XAG) -> None:
    """Require exact row order, factor orientation, and output affine forms."""
    if len(actual.and_factors) != len(expected.and_factors):
        fail(
            f"SLP normalization has {len(actual.and_factors)} AND rows; "
            f"the XAG has {len(expected.and_factors)}"
        )
    for index, (actual_pair, expected_pair) in enumerate(
        zip(actual.and_factors, expected.and_factors), 1
    ):
        for side, obtained, wanted in zip(
            ("left", "right"), actual_pair, expected_pair
        ):
            if obtained != wanted:
                fail(
                    f"SLP normalization A{index:02d} {side} factor: "
                    f"obtained {obtained:x}, expected {wanted:x}"
                )
    if len(actual.outputs) != len(expected.outputs):
        fail(
            f"SLP normalization has {len(actual.outputs)} outputs; "
            f"the XAG has {len(expected.outputs)}"
        )
    for index, (obtained, wanted) in enumerate(zip(actual.outputs, expected.outputs)):
        if obtained != wanted:
            fail(
                f"SLP normalization output S{index}: "
                f"obtained {obtained:x}, expected {wanted:x}"
            )


def evaluate_slp(circuit: Circuit, value: int) -> int:
    """Evaluate the SLP, with U0 and S0 denoting the most significant bits."""
    if not 0 <= value < 256:
        raise ValueError(value)
    wires = {
        wire: (value >> (7 - index)) & 1
        for index, wire in enumerate(circuit.inputs)
    }
    for operation in circuit.operations:
        operands = tuple(wires[wire] for wire in operation.operands)
        if operation.opcode == "XOR":
            wires[operation.output] = operands[0] ^ operands[1]
        elif operation.opcode == "AND":
            wires[operation.output] = operands[0] & operands[1]
        else:
            wires[operation.output] = operands[0] ^ 1
    return sum(
        wires[wire] << (7 - index) for index, wire in enumerate(circuit.outputs)
    )


def _affine_value(mask: int, basis: list[int]) -> int:
    result = mask & 1
    for index, bit in enumerate(basis, 1):
        if (mask >> index) & 1:
            result ^= bit
    return result


def evaluate_xag(xag: XAG, value: int) -> int:
    """Evaluate the normalized XAG, with U0 and S0 most significant."""
    if not 0 <= value < 256:
        raise ValueError(value)
    basis = [(value >> (7 - index)) & 1 for index in range(8)]
    for left, right in xag.and_factors:
        basis.append(_affine_value(left, basis) & _affine_value(right, basis))
    return sum(
        _affine_value(mask, basis) << (7 - index)
        for index, mask in enumerate(xag.outputs)
    )


def _aes_multiply(left: int, right: int) -> int:
    """Multiply in F_2[X]/(X^8 + X^4 + X^3 + X + 1)."""
    product = 0
    for _ in range(8):
        if right & 1:
            product ^= left
        left = ((left << 1) & 0xFF) ^ (0x1B if left & 0x80 else 0)
        right >>= 1
    return product


def _aes_power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _aes_multiply(result, value)
        value = _aes_multiply(value, value)
        exponent >>= 1
    return result


def fips_sbox(value: int) -> int:
    """Compute the FIPS 197 forward S-box from its field and affine definitions."""
    if not 0 <= value < 256:
        raise ValueError(value)
    inverse = _aes_power(value, 254) if value else 0
    result = 0
    for index in range(8):
        bit = ((0x63 >> index) & 1) ^ ((inverse >> index) & 1)
        for offset in (4, 5, 6, 7):
            bit ^= (inverse >> ((index + offset) & 7)) & 1
        result |= bit << index
    return result


def verify_fips_equivalence(circuit: Circuit, xag: XAG) -> None:
    """Compare the SLP and XAG with the FIPS definition on all input bytes."""
    for value in range(256):
        expected = fips_sbox(value)
        slp_value = evaluate_slp(circuit, value)
        if slp_value != expected:
            fail(
                f"SLP/FIPS mismatch at input {value:02x}: "
                f"obtained {slp_value:02x}, expected {expected:02x}"
            )
        xag_value = evaluate_xag(xag, value)
        if xag_value != expected:
            fail(
                f"XAG/FIPS mismatch at input {value:02x}: "
                f"obtained {xag_value:02x}, expected {expected:02x}"
            )


def require_digest(path: Path, expected: str, label: str) -> None:
    obtained = hashlib.sha256(path.read_bytes()).hexdigest()
    if obtained != expected:
        fail(f"{label} SHA-256 mismatch: obtained {obtained}, expected {expected}")


def verify_repository() -> str:
    """Check the SLP and its normalized XAG."""
    require_digest(SLP_PATH, SLP_SHA256, "SLP")

    circuit = parse_slp(SLP_PATH)
    statistics = circuit_statistics(circuit)
    expected_gates = Counter({"XOR": 195, "AND": 29, "NOT": 4})
    if statistics.instructions != 228:
        fail(
            f"instruction count: obtained {statistics.instructions}, expected 228"
        )
    if statistics.gates != expected_gates:
        fail(
            f"operation counts: obtained {dict(statistics.gates)}, "
            f"expected {dict(expected_gates)}"
        )
    if statistics.depth != 35:
        fail(f"gate depth: obtained {statistics.depth}, expected 35")
    if statistics.and_depth != 6:
        fail(f"AND-depth: obtained {statistics.and_depth}, expected 6")

    xag = parse_xag(XAG_PATH)
    require_same_xag(normalize_slp(circuit), xag)
    verify_fips_equivalence(circuit, xag)
    return (
        "228 instructions (195 XOR, 29 AND, 4 NOT); depth 35; AND-depth 6; "
        "SLP and XAG agree exactly; all 256 inputs match FIPS 197"
    )


def main(arguments: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        if arguments:
            fail("usage: python3 verify.py")
        print(f"PASS: {verify_repository()}")
        return 0
    except (VerificationError, OSError, UnicodeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
