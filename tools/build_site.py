#!/usr/bin/env python3
r"""Generate the complete GitHub Pages paper from article/article.tex.

The LaTeX source is canonical.  This script expands only its \input files,
replaces cleveref commands by explicit hyperlinks for Pandoc, runs Pandoc with
citeproc, performs deterministic HTML cleanup, and copies released artifacts.
"""
from __future__ import annotations

import argparse
import html as html_module
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTICLE = ROOT / "article"
SOURCE = ARTICLE / "article.tex"
TEMPLATE = ARTICLE / "article.html.template"
BIBLIOGRAPHY = ARTICLE / "references.bib"
CSL = ARTICLE / "ieee.csl"
OUTPUT = ROOT / "docs" / "index.html"
DOC_FILES = ROOT / "docs" / "files"

COPY_MAP = {
    ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp": "aes-sbox-fwd-g228-a29-d35-ad6.slp",
    ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp": "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp",
    ROOT / "certificates" / "aes29.xag": "aes29.xag",
    ROOT / "certificates" / "tower24_witness.txt": "tower24_witness.txt",
    ROOT / "certificates" / "staged29_witness.txt": "staged29_witness.txt",
    ROOT / "verify" / "minimal_verify.py": "minimal_verify.py",
    ROOT / "verify" / "verify_staged29.py": "verify_staged29.py",
    ROOT / "verify" / "verify_gf4_triangle.py": "verify_gf4_triangle.py",
    ROOT / "verify" / "verify_tower24.py": "verify_tower24.py",
    ROOT / "verify" / "verify_slp.c": "verify_slp.c",
    ROOT / "article" / "article.pdf": "article.pdf",
}


class Reference:
    def __init__(self, kind: str, number: str) -> None:
        self.kind = kind
        self.number = number


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def expand_inputs(text: str, directory: Path, seen: tuple[Path, ...] = ()) -> str:
    pattern = re.compile(r"\\input\{([^{}]+)\}")

    def replacement(match: re.Match[str]) -> str:
        name = match.group(1)
        path = (directory / name).resolve()
        if path.suffix == "":
            path = path.with_suffix(".tex")
        require(path.is_file(), f"missing LaTeX input {path}")
        require(path not in seen, f"recursive LaTeX input {path}")
        content = path.read_text(encoding="utf-8")
        return expand_inputs(content, path.parent, seen + (path,))

    while pattern.search(text):
        text = pattern.sub(replacement, text)
    return text


def section_references(tex: str) -> dict[str, Reference]:
    result: dict[str, Reference] = {}
    appendix = False
    section = 0
    subsection = 0
    appendix_index = 0
    pending: Reference | None = None
    token = re.compile(r"\\appendix|\\section\{|\\subsection\{|\\label\{([^{}]+)\}")
    for match in token.finditer(tex):
        item = match.group(0)
        if item == r"\appendix":
            appendix = True
            section = 0
            subsection = 0
            pending = None
        elif item.startswith(r"\section{"):
            subsection = 0
            if appendix:
                appendix_index += 1
                pending = Reference("appendix", chr(ord("A") + appendix_index - 1))
            else:
                section += 1
                pending = Reference("section", str(section))
        elif item.startswith(r"\subsection{"):
            subsection += 1
            pending = Reference("section", f"{section}.{subsection}")
        else:
            label = match.group(1)
            if pending is not None and (label.startswith("sec:") or label.startswith("app:")):
                result[label] = pending
                pending = None
    return result


def theorem_references(tex: str) -> dict[str, Reference]:
    result: dict[str, Reference] = {}
    counter = 0
    pattern = re.compile(
        r"\\begin\{(theorem|proposition|lemma|corollary|definition|remark)\}(?:\[[^\]]*\])?"
        r"(.*?)\\end\{\1\}",
        re.DOTALL,
    )
    for match in pattern.finditer(tex):
        counter += 1
        kind = match.group(1)
        prefixes = {
            "theorem": "thm:",
            "proposition": "prop:",
            "lemma": "lem:",
            "corollary": "cor:",
            "definition": "def:",
            "remark": "rem:",
        }
        for label in re.findall(r"\\label\{([^{}]+)\}", match.group(2)):
            if label.startswith(prefixes[kind]):
                result[label] = Reference(kind, str(counter))
    return result


def equation_references(tex: str) -> dict[str, Reference]:
    result: dict[str, Reference] = {}
    counter = 0
    pattern = re.compile(r"\\begin\{(equation|align)\}(.*?)\\end\{\1\}", re.DOTALL)
    for match in pattern.finditer(tex):
        environment, body = match.groups()
        if environment == "equation":
            counter += 1
            for label in re.findall(r"\\label\{([^{}]+)\}", body):
                result[label] = Reference("equation", str(counter))
            continue
        rows = re.split(r"\\\\(?:\[[^\]]*\])?", body)
        for row in rows:
            if not row.strip() or r"\nonumber" in row or r"\notag" in row:
                continue
            counter += 1
            for label in re.findall(r"\\label\{([^{}]+)\}", row):
                result[label] = Reference("equation", str(counter))
    return result


def table_references(tex: str) -> dict[str, Reference]:
    result: dict[str, Reference] = {}
    for index, label in enumerate(re.findall(r"\\label\{(tab:[^{}]+)\}", tex), 1):
        result[label] = Reference("table", str(index))
    return result


def reference_map(tex: str) -> dict[str, Reference]:
    result: dict[str, Reference] = {}
    for mapping in (
        section_references(tex),
        theorem_references(tex),
        equation_references(tex),
        table_references(tex),
    ):
        overlap = set(result) & set(mapping)
        require(not overlap, f"duplicate reference labels: {sorted(overlap)}")
        result.update(mapping)
    return result


def linked(label: str, text: str) -> str:
    return rf"\hyperref[{label}]{{{text}}}"


def format_cref(labels_text: str, references: dict[str, Reference]) -> str:
    labels = [item.strip() for item in labels_text.split(",")]
    require(all(label in references for label in labels), f"unknown cleveref label(s): {labels}")
    refs = [references[label] for label in labels]
    kinds = {ref.kind for ref in refs}
    require(len(kinds) == 1, f"mixed cleveref kinds are not supported: {labels}")
    kind = refs[0].kind

    if len(labels) == 1:
        ref = refs[0]
        if kind == "equation":
            return "equation~" + linked(labels[0], f"({ref.number})")
        word = kind
        return word + "~" + linked(labels[0], ref.number)

    plural = {
        "equation": "equations",
        "proposition": "propositions",
        "theorem": "theorems",
        "lemma": "lemmas",
        "corollary": "corollaries",
        "definition": "definitions",
        "remark": "remarks",
        "section": "sections",
        "appendix": "appendices",
        "table": "tables",
    }[kind]

    numeric = [int(ref.number) for ref in refs if ref.number.isdigit()]
    contiguous = len(numeric) == len(refs) and numeric == list(range(numeric[0], numeric[0] + len(numeric)))
    if len(labels) >= 3 and contiguous:
        if kind == "equation":
            return plural + "~" + linked(labels[0], f"({refs[0].number})") + "--" + linked(labels[-1], f"({refs[-1].number})")
        return plural + "~" + linked(labels[0], refs[0].number) + "--" + linked(labels[-1], refs[-1].number)

    pieces = []
    for label, ref in zip(labels, refs):
        text = f"({ref.number})" if kind == "equation" else ref.number
        pieces.append(linked(label, text))
    if len(pieces) == 2:
        joined = pieces[0] + " and~" + pieces[1]
    else:
        joined = ", ".join(pieces[:-1]) + ", and~" + pieces[-1]
    return plural + "~" + joined


def preprocess_tex() -> str:
    expanded = expand_inputs(SOURCE.read_text(encoding="utf-8"), ARTICLE, (SOURCE.resolve(),))
    references = reference_map(expanded)
    processed = re.sub(
        r"\\cref\{([^{}]+)\}",
        lambda match: format_cref(match.group(1), references),
        expanded,
    )
    require(r"\cref{" not in processed, "an unexpanded cleveref command remains")
    return processed


def normalized_cells(row: str) -> list[str]:
    cells = re.findall(r"<t[hd][^>]*>(.*?)</t[hd]>", row, re.DOTALL)
    result = []
    for cell in cells:
        text = re.sub(r"<[^>]+>", "", cell)
        text = html_module.unescape(text)
        text = re.sub(r"\s+", " ", text).strip()
        result.append(text)
    return result


def clean_table(block: str) -> str:
    header = re.search(r"<thead>.*?(<tr[^>]*>.*?</tr>).*?</thead>", block, re.DOTALL)
    body = re.search(r"(<tbody>\s*)(<tr[^>]*>.*?</tr>)", block, re.DOTALL)
    if header and body and normalized_cells(header.group(1)) == normalized_cells(body.group(2)):
        block = block[:body.start(2)] + block[body.end(2):]
    return '<div class="table-wrap">' + block + "</div>"


def postprocess_html(text: str) -> str:
    # Pandoc versions differ on this optional citeproc presentation attribute.
    text = re.sub(r' data-entry-spacing="[^"]*"', "", text)

    # Supply stable anchors for all labels retained inside MathJax source.
    display_pattern = re.compile(r'<span\b[^>]*\bclass="math display"[^>]*>(.*?)</span>', re.DOTALL)

    def display_replacement(match: re.Match[str]) -> str:
        body = match.group(1)
        labels = re.findall(r"\\label\s*\{([^{}]+)\}", body)
        anchors = "".join(
            f'<span id="{html_module.escape(label, quote=True)}" class="equation-anchor" aria-hidden="true"></span>'
            for label in labels
        )
        return anchors + match.group(0)

    text = display_pattern.sub(display_replacement, text)
    text = re.sub(r"<table>.*?</table>", lambda match: clean_table(match.group(0)), text, flags=re.DOTALL)

    # Pandoc numbers post-\appendix sections continuously; restore A, B, C.
    for identifier, new_number in (
        ("app:decomposition", "A"),
        ("app:finite", "B"),
        ("app:artifacts", "C"),
    ):
        heading = re.compile(
            rf'(<h1\s+data-number=")([^"]+)("\s+id="{re.escape(identifier)}"><span\s+class="header-section-number">)([^<]+)(</span>)'
        )

        def heading_replacement(match: re.Match[str]) -> str:
            require(match.group(2) == match.group(4), f"inconsistent Pandoc section number for {identifier}")
            return match.group(1) + new_number + match.group(3) + new_number + match.group(5)

        text, count = heading.subn(heading_replacement, text)
        require(count == 1, f"could not restore appendix number for {identifier}")
        toc = re.compile(
            rf'(<a\s+href="#{re.escape(identifier)}"[^>]*><span\s+class="toc-section-number">)([^<]+)(</span>)'
        )
        text, count = toc.subn(rf"\g<1>{new_number}\g<3>", text)
        require(count == 1, f"could not restore appendix TOC number for {identifier}")

    # Pandoc keeps lstlisting captions as data attributes; render them visibly.
    listing_number = 0

    def listing_replacement(match: re.Match[str]) -> str:
        nonlocal listing_number
        listing_number += 1
        caption = html_module.unescape(match.group(2))
        return f'<p class="listing-caption">Listing {listing_number}: {caption}</p>' + match.group(0)

    text = re.sub(
        r'(<div class="sourceCode"[^>]*data-caption="([^"]+)"[^>]*>)',
        listing_replacement,
        text,
    )

    require("[eq:" not in text and "[prop:" not in text and "[tab:" not in text, "unresolved cross-reference remains")
    require("f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3" in text, "primary digest missing from HTML")
    require("d72ca4cd9617b365587a3b826ab3a0d37489187cdd67fca18ff50b1d3d5e0083" in text, "staged-certificate digest missing from HTML")
    return text.rstrip() + "\n"


def render_html() -> str:
    pandoc = shutil.which("pandoc")
    require(pandoc is not None, "pandoc is required to generate docs/index.html")
    for required in (SOURCE, TEMPLATE, BIBLIOGRAPHY, CSL, ARTICLE / "article.pdf"):
        require(required.is_file(), f"missing paper source or compiled PDF {required}")

    with tempfile.TemporaryDirectory(prefix="aes29-pandoc-") as temporary:
        temp = Path(temporary)
        tex_path = temp / "article-expanded.tex"
        html_path = temp / "article.html"
        tex_path.write_text(preprocess_tex(), encoding="utf-8", newline="\n")
        command = [
            pandoc,
            str(tex_path),
            "--from=latex",
            "--to=html5",
            "--standalone",
            f"--template={TEMPLATE}",
            "--toc",
            "--number-sections",
            "--mathjax",
            "--citeproc",
            f"--csl={CSL}",
            f"--bibliography={BIBLIOGRAPHY}",
            f"--resource-path={ARTICLE}",
            "--metadata=pagetitle:A 29-AND Circuit for the AES S-box",
            "--metadata=link-citations:true",
            "--metadata=reference-section-title:References",
            f"--output={html_path}",
        ]
        completed = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if completed.returncode:
            raise SystemExit(f"FAIL: Pandoc failed\n{completed.stdout}{completed.stderr}")
        return postprocess_html(html_path.read_text(encoding="utf-8"))


def expected_files() -> dict[str, bytes]:
    files = {"index.html": render_html().encode("utf-8")}
    for source, destination in COPY_MAP.items():
        require(source.is_file(), f"missing public artifact {source}")
        files[f"files/{destination}"] = source.read_bytes()
    return files


def build() -> None:
    expected = expected_files()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    DOC_FILES.mkdir(parents=True, exist_ok=True)
    for relative, data in expected.items():
        path = ROOT / "docs" / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    expected_names = {Path(name).name for name in expected if name.startswith("files/")}
    for path in DOC_FILES.iterdir():
        if path.is_file() and path.name not in expected_names:
            path.unlink()
    (ROOT / "docs" / ".nojekyll").touch()
    print(f"BUILT: docs/index.html after article/article.pdf from the same TeX source, plus {len(COPY_MAP)} exact artifact copies")


def check() -> None:
    expected = expected_files()
    for relative, data in expected.items():
        path = ROOT / "docs" / relative
        require(path.is_file(), f"missing generated file {relative}")
        require(path.read_bytes() == data, f"stale generated file {relative}")
    actual_names = {path.name for path in DOC_FILES.iterdir() if path.is_file()} if DOC_FILES.is_dir() else set()
    expected_names = {Path(name).name for name in expected if name.startswith("files/")}
    require(actual_names == expected_names, f"docs/files set mismatch: {sorted(actual_names)} != {sorted(expected_names)}")
    require((ROOT / "docs" / ".nojekyll").is_file(), "docs/.nojekyll is missing")
    print("PASS: GitHub Pages paper is current and all public artifact copies are byte-identical")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="compare generated output without modifying files")
    args = parser.parse_args()
    check() if args.check else build()


if __name__ == "__main__":
    main()
