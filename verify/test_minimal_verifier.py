#!/usr/bin/env python3
"""Negative tests for minimal_verify.py, including optimized Python (-O)."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "verify" / "minimal_verify.py"
PRIMARY = ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp"
BASE = PRIMARY.read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def run(text: str, optimized: bool) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile("w", suffix=".slp", encoding="utf-8", delete=False) as handle:
        handle.write(text)
        name = handle.name
    command = [sys.executable]
    if optimized:
        command.append("-O")
    command.extend((str(CHECKER), name))
    completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    Path(name).unlink()
    return completed.returncode, completed.stdout


def replace_once(old: str, new: str) -> str:
    require(BASE.count(old) == 1, f"mutation anchor occurs {BASE.count(old)} times: {old!r}")
    return BASE.replace(old, new, 1)


def main() -> None:
    cases = {
        "wrong_function": replace_once("AND t19 t16 t8", "AND t19 t16 U0"),
        "too_many_ands": replace_once("end SLP", "AND spare U0 U1\nend SLP"),
        "illegal_opcode": replace_once("XOR t1 U3 U5", "OR t1 U3 U5"),
        "use_before_definition": replace_once("XOR t1 U3 U5", "XOR t1 future U5"),
        "wire_redefinition": replace_once("XOR t2 U0 U6", "XOR t1 U0 U6"),
        "missing_delimiter": replace_once("end SLP", ""),
    }

    code, output = run(BASE, False)
    require(code == 0, f"valid certificate rejected: {output}")
    for label, text in cases.items():
        code, output = run(text, False)
        require(code != 0, f"malformed case {label} accepted: {output}")

    # Representative checks under -O ensure correctness does not depend on assert.
    code, output = run(BASE, True)
    require(code == 0, f"valid certificate rejected under -O: {output}")
    for label in ("too_many_ands", "use_before_definition"):
        code, output = run(cases[label], True)
        require(code != 0, f"malformed case {label} accepted under -O: {output}")
    print("PASS: minimal verifier accepts the certificate, rejects six malformed variants, and remains effective under Python -O")


if __name__ == "__main__":
    main()
