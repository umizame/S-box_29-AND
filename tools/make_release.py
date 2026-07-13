#!/usr/bin/env python3
"""Build the paper, audit the repository, and create a deterministic ZIP."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

sys.dont_write_bytecode = True

from release_common import (  # noqa: E402
    EXCLUDED_PARTS,
    EXCLUDED_SUFFIXES,
    MANIFEST,
    ROOT,
    manifest_bytes,
    release_files,
    sha256,
)

DEFAULT_ZIP = ROOT.parent / f"{ROOT.name}.zip"
ZIP_TIMESTAMP = (2026, 7, 12, 0, 0, 0)
SOURCE_DATE_EPOCH = "1783814400"
EXECUTABLE_SUFFIXES = {".py", ".sh"}


def run(*command: str, cwd: Path = ROOT, environment: dict[str, str] | None = None) -> None:
    print("+", " ".join(command), flush=True)
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def build_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
    environment["FORCE_SOURCE_DATE"] = "1"
    return environment


def inspect_latex_log() -> None:
    log = ROOT / "article" / "article.log"
    if not log.is_file():
        raise SystemExit("FAIL: LaTeX did not produce article/article.log")
    text = log.read_text(encoding="utf-8", errors="replace")
    forbidden = (
        "LaTeX Warning: There were undefined references",
        "LaTeX Warning: Citation",
        "Package biblatex Warning: Please (re)run Biber",
        "Package biblatex Warning: The following entry could not be found",
        "multiply-defined labels",
        "Overfull \\hbox",
        "Overfull \\vbox",
    )
    for phrase in forbidden:
        if phrase in text:
            raise SystemExit(f"FAIL: LaTeX log contains {phrase!r}")
    print("PASS: LaTeX log has no undefined references, unresolved citations, or overfull boxes")


def build_paper_and_site() -> None:
    environment = build_environment()
    run(sys.executable, "tools/build_article_sources.py", environment=environment)
    run(
        "latexmk",
        "-pdf",
        "-interaction=nonstopmode",
        "-halt-on-error",
        "article.tex",
        cwd=ROOT / "article",
        environment=environment,
    )
    inspect_latex_log()
    run(sys.executable, "tools/build_site.py", environment=environment)


def remove_generated_clutter() -> None:
    # latexmk -c leaves the released PDF but removes its auxiliary products.
    environment = build_environment()
    if shutil.which("latexmk"):
        run("latexmk", "-c", "article.tex", cwd=ROOT / "article", environment=environment)

    removable_suffixes = EXCLUDED_SUFFIXES - {".zip", ".tar", ".gz"}
    for path in sorted(ROOT.rglob("*"), reverse=True):
        if path.is_file() and any(path.name.endswith(suffix) for suffix in removable_suffixes):
            path.unlink()
        elif path.is_dir() and path.name in EXCLUDED_PARTS - {".git"}:
            shutil.rmtree(path)
    print("PASS: removed LaTeX auxiliaries, bytecode caches, and temporary build trees")


def write_manifest() -> None:
    data = manifest_bytes()
    MANIFEST.write_bytes(data)
    print(f"WROTE: MANIFEST.sha256 ({len(data.splitlines())} entries)")


def create_zip(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    prefix = ROOT.name
    files = release_files(include_manifest=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative in files:
            data = (ROOT / relative).read_bytes()
            info = zipfile.ZipInfo(f"{prefix}/{relative.as_posix()}", date_time=ZIP_TIMESTAMP)
            info.create_system = 3
            mode = 0o755 if relative.suffix in EXECUTABLE_SUFFIXES else 0o644
            info.external_attr = (mode & 0xFFFF) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    expected_names = [f"{prefix}/{relative.as_posix()}" for relative in files]
    with zipfile.ZipFile(output, "r") as archive:
        if archive.testzip() is not None:
            raise SystemExit("FAIL: ZIP CRC check failed")
        names = archive.namelist()
        if names != expected_names or len(names) != len(set(names)):
            raise SystemExit("FAIL: ZIP file set or ordering is incorrect")
        for relative, name in zip(files, names):
            if archive.read(name) != (ROOT / relative).read_bytes():
                raise SystemExit(f"FAIL: ZIP content differs for {name}")
    print(
        f"WROTE: {output} ({output.stat().st_size} bytes, {len(files)} files, "
        f"SHA-256 {sha256(output)})"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_ZIP)
    parser.add_argument("--skip-core-audit", action="store_true")
    args = parser.parse_args()

    environment = build_environment()
    if not args.skip_core_audit:
        run(sys.executable, "verify/run_all.py", environment=environment)
    build_paper_and_site()
    remove_generated_clutter()
    write_manifest()
    run(sys.executable, "tools/check_release.py", environment=environment)
    create_zip(args.output.resolve())


if __name__ == "__main__":
    main()
