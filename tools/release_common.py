#!/usr/bin/env python3
"""Shared deterministic file-set and hashing rules for the release tools."""
from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "MANIFEST.sha256"

EXCLUDED_PARTS = {".git", "__pycache__", "generated", "_build"}
EXCLUDED_SUFFIXES = {
    ".pyc", ".pyo", ".o", ".obj", ".zip", ".tar", ".gz",
    ".aux", ".bbl", ".bcf", ".blg", ".fdb_latexmk", ".fls",
    ".log", ".out", ".run.xml", ".toc", ".synctex.gz",
}
ALLOWED_HIDDEN = {".gitignore", ".gitattributes", ".nojekyll"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def is_release_file(path: Path, *, include_manifest: bool) -> bool:
    if not path.is_file():
        return False
    relative = path.relative_to(ROOT)
    if not include_manifest and relative.as_posix() == "MANIFEST.sha256":
        return False
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if any(path.name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return False
    if path.name.startswith(".") and path.name not in ALLOWED_HIDDEN:
        return False
    return True


def release_files(*, include_manifest: bool) -> list[Path]:
    files = [
        path.relative_to(ROOT)
        for path in ROOT.rglob("*")
        if is_release_file(path, include_manifest=include_manifest)
    ]
    return sorted(files, key=lambda path: path.as_posix())


def manifest_bytes() -> bytes:
    lines = [
        f"{sha256(ROOT / relative)}  {relative.as_posix()}"
        for relative in release_files(include_manifest=False)
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def generated_clutter() -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if ".git" in relative.parts:
            continue
        if any(part in {"__pycache__", "_build", "generated"} for part in relative.parts):
            result.append(relative)
            continue
        if any(path.name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES - {".zip", ".tar", ".gz"}):
            result.append(relative)
    return sorted(set(result), key=lambda path: path.as_posix())
