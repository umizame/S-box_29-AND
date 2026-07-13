#!/usr/bin/env python3
"""Run the complete finite audit with Python 3 and a C99 compiler."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PYTHON = sys.executable


def run(*command: str, cwd: Path = ROOT, stdout=None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, check=True, stdout=stdout)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def deterministic_rebuild() -> None:
    with tempfile.TemporaryDirectory(prefix="aes29-rebuild-") as temporary:
        copy = Path(temporary) / ROOT.name
        shutil.copytree(
            ROOT,
            copy,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.zip", "*.aux", "*.log"),
        )
        run(PYTHON, "construction/build_transparent.py", cwd=copy)
        run(PYTHON, "construction/affine_resynthesis.py", cwd=copy)
        generated_xag = Path(temporary) / "aes29.xag"
        with generated_xag.open("wb") as output:
            run(
                PYTHON,
                "construction/normalize_xag.py",
                "circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp",
                cwd=copy,
                stdout=output,
            )

        comparisons = (
            "circuits/aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp",
            "circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp",
        )
        for relative in comparisons:
            if (copy / relative).read_bytes() != (ROOT / relative).read_bytes():
                raise SystemExit(f"FAIL: deterministic rebuild differs for {relative}")
        if generated_xag.read_bytes() != (ROOT / "certificates" / "aes29.xag").read_bytes():
            raise SystemExit("FAIL: regenerated normalized XAG differs from certificates/aes29.xag")
        run(PYTHON, "verify/minimal_verify.py", cwd=copy)
        print("PASS: the tower certificate deterministically rebuilds both published SLPs and the normalized XAG")


def main() -> None:
    scripts = (
        "verify/minimal_verify.py",
        "verify/verify_structure.py",
        "verify/verify_fips_table.py",
        "verify/verify_bitparallel.py",
        "verify/verify_xag_certificate.py",
        "verify/compare_slp_xag.py",
        "verify/verify_gf4_triangle.py",
        "verify/verify_tower24.py",
        "verify/verify_staged29.py",
        "verify/test_minimal_verifier.py",
        "search/exact_gf4_triangle_rank.py",
    )
    for script in scripts:
        run(PYTHON, script)

    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        raise SystemExit("FAIL: no C99 compiler found")
    with tempfile.TemporaryDirectory(prefix="aes29-c-") as temporary:
        executable = Path(temporary) / "verify_slp"
        run(
            compiler,
            "-std=c99",
            "-O2",
            "-Wall",
            "-Wextra",
            "-pedantic",
            "verify/verify_slp.c",
            "-o",
            str(executable),
        )
        run(str(executable), "circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp")

    deterministic_rebuild()
    print("SHA-256 primary:    ", sha256(ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp"))
    print("SHA-256 transparent:", sha256(ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp"))
    print("SHA-256 XAG:        ", sha256(ROOT / "certificates" / "aes29.xag"))
    print("ALL CORE CHECKS PASSED")


if __name__ == "__main__":
    main()
