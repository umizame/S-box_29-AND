#!/usr/bin/env python3
"""Audit the released repository, paper, GitHub Pages tree, and manifest."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from html.parser import HTMLParser
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.dont_write_bytecode = True

from build_site import COPY_MAP  # noqa: E402
from release_common import (  # noqa: E402
    MANIFEST,
    ROOT,
    generated_clutter,
    manifest_bytes,
    release_files,
    sha256,
)

PRIMARY = ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp"
TRANSPARENT = ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp"
BASELINE = ROOT / "baseline" / "aes-sbox-fwd-g113-a32-d27-ad6.slp"
XAG = ROOT / "certificates" / "aes29.xag"
TOWER = ROOT / "certificates" / "tower24_witness.txt"
STAGED = ROOT / "certificates" / "staged29_witness.txt"
HTML = ROOT / "docs" / "index.html"
PDF = ROOT / "article" / "article.pdf"

EXPECTED_CIRCUITS = {
    PRIMARY: (
        "f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3",
        Counter({"AND": 29, "XOR": 195, "NOT": 4}),
        228,
        (35, 6),
        False,
    ),
    TRANSPARENT: (
        "cecd0c7abba9920ff2af7ec204fcd01f97db135a4c43d8afd7f83d65c2e382ca",
        Counter({"AND": 29, "XOR": 422, "NOT": 4}),
        455,
        (35, 6),
        False,
    ),
    BASELINE: (
        "6ba4f63b832a1f4520a76cab5680e673fdd744ad2651918882eeecff7957698a",
        Counter({"AND": 32, "XOR": 77, "XNOR": 4}),
        113,
        (27, 6),
        True,
    ),
}
EXPECTED_XAG_HASH = "862446d12293b21bfafbd7e958502301619a596e6bf3cb7a3b22f3f830926264"
EXPECTED_TOWER_HASH = "1e847a85e3abe783d98e3d4c48a7d9eb845caab96903c175657cce06119c6925"
EXPECTED_STAGED_HASH = "d72ca4cd9617b365587a3b826ab3a0d37489187cdd67fca18ff50b1d3d5e0083"
IMAGE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".bmp", ".tiff"}
ARCHIVE_SUFFIXES = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z"}


@dataclass(frozen=True)
class Operation:
    kind: str
    output: str
    inputs: tuple[str, ...]


class DocumentCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.tags: list[str] = []
        self.ids: list[str] = []
        self.metas: list[dict[str, str]] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered_tag = tag.lower()
        self.tags.append(lowered_tag)
        values = {name.lower(): value for name, value in attrs if value is not None}
        if "id" in values:
            self.ids.append(values["id"])
        for name in ("href", "src"):
            if name in values:
                self.links.append((name, values[name]))
        if lowered_tag == "meta":
            self.metas.append(values)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def run_check(*command: str) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run(command, cwd=ROOT, env=environment, check=True)


def parse_slp(path: Path, *, allow_xnor: bool) -> tuple[list[Operation], Counter[str], tuple[int, int]]:
    operations: list[Operation] = []
    inside = began = ended = False
    saw_inputs = saw_outputs = False
    allowed = {"XOR", "AND", "NOT"} | ({"XNOR"} if allow_xnor else set())

    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line == "Inputs: U0:U7":
            require(not saw_inputs, f"duplicate input declaration in {path.name} at line {lineno}")
            saw_inputs = True
            continue
        if line == "Outputs: S0:S7":
            require(not saw_outputs, f"duplicate output declaration in {path.name} at line {lineno}")
            saw_outputs = True
            continue
        if line == "begin SLP":
            require(not began and not inside and not ended, f"duplicate begin SLP in {path.name} at line {lineno}")
            began = inside = True
            continue
        if line == "end SLP":
            require(inside and not ended, f"unmatched end SLP in {path.name} at line {lineno}")
            inside = False
            ended = True
            continue
        if not inside:
            continue

        fields = line.split()
        kind = fields[0]
        require(kind in allowed, f"illegal operation {kind!r} in {path.name} at line {lineno}")
        if kind == "NOT":
            require(len(fields) == 3, f"wrong NOT arity in {path.name} at line {lineno}")
            operations.append(Operation(kind, fields[1], (fields[2],)))
        else:
            require(len(fields) == 4, f"wrong binary arity in {path.name} at line {lineno}")
            operations.append(Operation(kind, fields[1], (fields[2], fields[3])))

    require(saw_inputs and saw_outputs, f"missing exact input/output declaration in {path.name}")
    require(began and ended and not inside, f"unbalanced SLP delimiters in {path.name}")
    require(bool(operations), f"empty SLP in {path.name}")

    defined = {f"U{i}" for i in range(8)}
    depth = {name: 0 for name in defined}
    and_depth = dict(depth)
    counts: Counter[str] = Counter()
    for operation in operations:
        require(operation.output not in defined, f"wire redefinition {operation.output} in {path.name}")
        for operand in operation.inputs:
            require(operand in defined, f"use before definition {operand} in {path.name}")
        defined.add(operation.output)
        counts[operation.kind] += 1
        depth[operation.output] = 1 + max(depth[operand] for operand in operation.inputs)
        and_depth[operation.output] = max(and_depth[operand] for operand in operation.inputs) + (
            1 if operation.kind == "AND" else 0
        )

    outputs = tuple(f"S{i}" for i in range(8))
    require(all(output in defined for output in outputs), f"missing output in {path.name}")
    return operations, counts, (
        max(depth[output] for output in outputs),
        max(and_depth[output] for output in outputs),
    )


def check_fixed_certificates() -> None:
    for path, (expected_hash, expected_counts, expected_total, expected_depths, allow_xnor) in EXPECTED_CIRCUITS.items():
        require(path.is_file(), f"missing circuit {path.relative_to(ROOT)}")
        require(sha256(path) == expected_hash, f"fixed SHA-256 mismatch for {path.relative_to(ROOT)}")
        operations, counts, depths = parse_slp(path, allow_xnor=allow_xnor)
        require(counts == expected_counts, f"wrong operation tally for {path.name}: {dict(counts)}")
        require(len(operations) == expected_total, f"wrong instruction total for {path.name}: {len(operations)}")
        require(depths == expected_depths, f"wrong depths for {path.name}: {depths}")
        print(
            f"PASS: {path.name}: {expected_total} instructions, {dict(expected_counts)}, "
            f"depth {depths[0]}, AND-depth {depths[1]}, fixed SHA-256"
        )
    require(XAG.is_file() and sha256(XAG) == EXPECTED_XAG_HASH, "fixed SHA-256 mismatch for certificates/aes29.xag")
    require(TOWER.is_file() and sha256(TOWER) == EXPECTED_TOWER_HASH, "fixed SHA-256 mismatch for certificates/tower24_witness.txt")
    require(STAGED.is_file() and sha256(STAGED) == EXPECTED_STAGED_HASH, "fixed SHA-256 mismatch for certificates/staged29_witness.txt")
    print("PASS: XAG, 24-product witness, and staged witness have their fixed SHA-256 digests")


def normalized_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def check_html() -> None:
    require(HTML.is_file(), "docs/index.html is missing")
    source = HTML.read_text(encoding="utf-8")
    collector = DocumentCollector()
    collector.feed(source)

    forbidden_tags = {"img", "svg", "canvas", "picture"}
    present_forbidden = sorted(forbidden_tags & set(collector.tags))
    require(not present_forbidden, f"HTML contains drawing/image elements: {present_forbidden}")

    duplicate_ids = sorted(identifier for identifier, count in Counter(collector.ids).items() if count > 1)
    require(not duplicate_ids, f"duplicate HTML ids: {duplicate_ids}")
    identifiers = set(collector.ids)
    required_ids = {
        "abstract", "TOC", "sec:problem", "def:circuit-model", "eq:aes-field",
        "eq:fips-affine", "def:masks", "eq:mask", "sec:construction",
        "eq:coordinate-basis", "eq:outer-products", "eq:early-products",
        "eq:middle-basis", "eq:middle-products", "eq:late-products",
        "lem:availability", "sec:correctness", "lem:finite-domain", "thm:main",
        "cor:slp", "sec:baseline", "eq:LRZ", "sec:gf4", "eq:p123",
        "eq:p45678", "eq:xy", "eq:yz", "eq:zx", "prop:gf4", "eq:gf4mul",
        "eq:Phi", "sec:formal", "lem:wedge", "eq:wedge",
        "prop:formal-certificate", "sec:verification", "sec:conclusion",
        "app:decomposition", "tab:products", "tab:coordinates",
        "tab:middle-factors", "tab:post-coordinates",
        "tab:output-reconstruction", "tab:targets", "app:finite",
        "tab:evaluation", "lst:xag", "app:artifacts", "tab:artifacts",
        "lst:minimal", "refs",
    }
    require(required_ids <= identifiers, f"HTML is missing required anchors: {sorted(required_ids - identifiers)}")

    docs_root = HTML.parent.resolve()
    for attribute, value in collector.links:
        split = urlsplit(value)
        if split.scheme or split.netloc:
            require(split.scheme in {"http", "https", "mailto"}, f"unsupported external URL scheme: {value}")
            continue
        require(not value.startswith("//"), f"scheme-relative URL is not permitted: {value}")
        path_text = unquote(split.path)
        fragment = unquote(split.fragment)
        if not path_text:
            require(not fragment or fragment in identifiers, f"broken internal fragment: {value}")
            continue
        target = (HTML.parent / path_text).resolve()
        try:
            target.relative_to(docs_root)
        except ValueError as error:
            raise SystemExit(f"FAIL: relative {attribute} escapes docs/: {value}") from error
        require(target.is_file(), f"broken relative {attribute}: {value}")
        if target == HTML.resolve() and fragment:
            require(fragment in identifiers, f"broken same-document fragment: {value}")

    body_text = normalized_text(" ".join(collector.text))
    required_phrases = (
        "A 29-AND Circuit for the AES S-box",
        "Authors (unordered):",
        "Constructive 29-AND upper bound",
        "The explicit staged 29-AND construction",
        "Complete staged decomposition",
        "Complete finite evaluation and normalized graph",
        "Repository artifacts and standalone verification",
        "Standalone exhaustive implementation verifier",
    )
    for phrase in required_phrases:
        require(phrase in body_text, f"full-paper phrase missing from HTML: {phrase!r}")
    require("f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3" in source, "primary digest missing from HTML")
    require(EXPECTED_STAGED_HASH in source, "staged witness digest missing from HTML")
    require("no minimality claim is made" in body_text.lower() or "does not establish optimality" in body_text.lower(), "upper-bound-only qualification missing from HTML")
    require("{{" not in source and "$body$" not in source, "unexpanded HTML template marker remains")

    for meta in collector.metas:
        name = (meta.get("name") or meta.get("property") or "").lower()
        require("doi" not in name, f"DOI metadata is present in the GitHub Pages paper: {name}")

    for source_path, destination in COPY_MAP.items():
        public = ROOT / "docs" / "files" / destination
        require(public.is_file(), f"missing public artifact docs/files/{destination}")
        require(public.read_bytes() == source_path.read_bytes(), f"public copy differs from {source_path.relative_to(ROOT)}")
    require((ROOT / "docs" / ".nojekyll").is_file(), "docs/.nojekyll is missing")
    print(f"PASS: HTML has {len(collector.ids)} unique ids and {len(collector.links)} checked links; all public copies are exact")


def check_article_sources() -> None:
    tex = (ROOT / "article" / "article.tex").read_text(encoding="utf-8")
    bibliography = (ROOT / "article" / "references.bib").read_text(encoding="utf-8")
    template = (ROOT / "article" / "article.html.template").read_text(encoding="utf-8")
    require(r"\begin{figure}" not in tex and r"\includegraphics" not in tex, "article contains an unexplained figure")
    require(r"\MC(\AES)\leq 29" in tex, "main upper-bound formula is missing from the canonical TeX")
    require("no minimality claim is made" in tex.lower() and "does not establish optimality" in tex.lower(), "upper-bound-only scope is not stated precisely")
    require("citation_doi" not in template.lower(), "unwanted identifier metadata appears in the HTML template")
    require(r"\doi" not in tex.lower() and "doi =" not in bibliography.lower(), "article or bibliography contains an unintended identifier field")

    artifact_marker = r"\section{Repository artifacts and standalone verification}"
    require(artifact_marker in tex, "final artifact appendix is missing")
    main_text, artifact_appendix = tex.split(artifact_marker, 1)
    internal_markers = ("circuits/", "certificates/", "verify/", "baseline/", "article/", "docs/")
    require(not any(marker in main_text for marker in internal_markers), "repository path appears before the final artifact appendix")
    require(all(marker in artifact_appendix for marker in ("circuits/", "certificates/", "verify/", "baseline/", "article/", "docs/")), "artifact appendix omits a repository class")

    for generated in ("products.tex", "staged.tex", "targets.tex", "evaluation.tex", "xag.tex", "minimal-verifier.tex"):
        require(rf"\input{{{generated}}}" in tex, f"canonical TeX omits generated source {generated}")

    keys = set(re.findall(r"@\w+\{([^,\s]+)", bibliography))
    expected_keys = {
        "nistCircuitComplexity", "nistCircuitList", "nistAES32SLP",
        "fips197", "boyarMatthewsPeralta2013",
    }
    require(keys == expected_keys, f"bibliography keys differ from the audited source set: {sorted(keys)}")
    require("csrc.nist.gov/projects/circuit-complexity" in bibliography, "NIST problem source missing")
    require("github.com/usnistgov/Circuits" in bibliography, "official NIST SLP source missing")
    require("nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf" in bibliography, "official FIPS PDF source missing")
    require("Journal of Cryptology" in bibliography and "280--312" in bibliography, "historical journal citation is incomplete")
    print("PASS: canonical TeX is self-contained before its final artifact appendix and has the audited bibliography")


def parse_pdfinfo(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
    return result


def check_pdf() -> None:
    require(PDF.is_file(), "article/article.pdf is missing")
    data = PDF.read_bytes()
    require(data.startswith(b"%PDF-"), "article/article.pdf is not a PDF file")
    require(len(data) > 100_000, "article/article.pdf is unexpectedly small")

    pdfinfo = shutil.which("pdfinfo")
    if pdfinfo:
        completed = subprocess.run([pdfinfo, str(PDF)], check=True, capture_output=True, text=True)
        info = parse_pdfinfo(completed.stdout)
        require(info.get("Title") == "A 29-AND Circuit for the AES S-box", f"unexpected PDF title: {info.get('Title')!r}")
        author = info.get("Author", "")
        require("GPT-5.6 Pro" in author and "umizame" in author, f"unexpected PDF author metadata: {author!r}")
        pages = int(info.get("Pages", "0"))
        require(pages >= 10, f"paper has too few pages: {pages}")
        require("A4" in info.get("Page size", ""), f"PDF is not reported as A4: {info.get('Page size')!r}")
        require(info.get("Encrypted", "no").startswith("no"), "PDF is encrypted")
        print(f"PASS: PDF metadata, A4 page size, and {pages}-page paper structure")
    else:
        print("SKIP: pdfinfo is unavailable; basic PDF signature and size were checked")

    pdftotext = shutil.which("pdftotext")
    if pdftotext:
        completed = subprocess.run([pdftotext, "-layout", str(PDF), "-"], check=True, capture_output=True, text=True)
        text = normalized_text(completed.stdout)
        compact = re.sub(r"\s+", "", completed.stdout)
        for phrase in (
            "A 29-AND Circuit for the AES S-box",
            "Constructive 29-AND upper bound",
            "The explicit staged 29-AND construction",
            "Complete staged decomposition",
            "Complete finite evaluation and normalized graph",
            "Repository artifacts and standalone verification",
            "Standalone exhaustive implementation verifier",
            "References",
        ):
            require(phrase in text, f"paper phrase missing from PDF text: {phrase!r}")
        require("f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3" in compact, "primary digest missing from PDF text")
        require(EXPECTED_STAGED_HASH in compact, "staged witness digest missing from PDF text")
        print("PASS: PDF text contains the theorem, complete construction, finite table, artifact appendix, references, and fixed digests")
    else:
        print("SKIP: pdftotext is unavailable; PDF textual contents were not machine-inspected")


def check_repository_cleanliness() -> None:
    clutter = generated_clutter()
    require(not clutter, f"generated build clutter remains: {[path.as_posix() for path in clutter]}")
    images = [
        path.relative_to(ROOT)
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in IMAGE_SUFFIXES
    ]
    require(not images, f"unexpected image files remain: {[path.as_posix() for path in images]}")
    archives = [
        path.relative_to(ROOT)
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in ARCHIVE_SUFFIXES
    ]
    require(not archives, f"nested archive files remain in the repository: {[path.as_posix() for path in archives]}")
    symlinks = [path.relative_to(ROOT) for path in ROOT.rglob("*") if path.is_symlink()]
    require(not symlinks, f"symbolic links are not permitted in the release: {[path.as_posix() for path in symlinks]}")
    print("PASS: repository contains no build clutter, images, nested archives, or symbolic links")


def check_manifest(*, required: bool) -> None:
    if not MANIFEST.is_file():
        require(not required, "MANIFEST.sha256 is missing")
        print("SKIP: MANIFEST.sha256 has not yet been generated")
        return
    expected = manifest_bytes()
    require(MANIFEST.read_bytes() == expected, "MANIFEST.sha256 is stale or malformed")

    listed = MANIFEST.read_text(encoding="utf-8").splitlines()
    require(len(listed) == len(release_files(include_manifest=False)), "manifest entry count is inconsistent")
    for line in listed:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, f"malformed manifest line: {line!r}")
        digest, relative = match.groups()
        path = ROOT / relative
        require(path.is_file(), f"manifest names a missing file: {relative}")
        require(sha256(path) == digest, f"manifest digest mismatch: {relative}")
    print(f"PASS: MANIFEST.sha256 covers {len(listed)} exact release files")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-missing-manifest", action="store_true")
    args = parser.parse_args()

    check_fixed_certificates()
    run_check(sys.executable, "tools/build_article_sources.py", "--check")
    run_check(sys.executable, "tools/build_site.py", "--check")
    check_article_sources()
    check_html()
    check_pdf()
    check_repository_cleanliness()
    check_manifest(required=not args.allow_missing_manifest)
    print("ALL RELEASE CHECKS PASSED")


if __name__ == "__main__":
    main()
