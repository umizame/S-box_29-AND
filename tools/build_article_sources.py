#!/usr/bin/env python3
"""Generate deterministic LaTeX appendices from the released certificates.

With ``--check`` the script compares every expected byte without modifying the
repository.  The generated material contains the complete staged decomposition,
the formal product masks, the normalized XAG, the exhaustive output table, and
the standalone verifier.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verify"))

from verify_slp import AES_SBOX_TABLE  # noqa: E402
from verify_staged29 import (  # noqa: E402
    COORD_NAMES,
    OUTPUT_NAMES,
    POST_NAMES,
    PRODUCT_CERTIFICATE,
    STAGED_CERTIFICATE,
    evaluate as evaluate_staged,
    parse_products as parse_staged_products,
    parse_staged,
)
from verify_tower24 import (  # noqa: E402
    CERTIFICATE,
    EARLY_INDICES,
    baseline_data,
    derive_targets,
    parse_certificate,
)

ARTICLE = ROOT / "article"
COORDINATES = (
    r"L_0", r"L_1", r"L_2", r"L_3",
    r"R_0", r"R_1", r"R_2", r"R_3",
    r"Z_0", r"Z_1", r"Z_2", r"Z_3",
)
INPUT_NAMES = tuple(rf"U_{i}" for i in range(8))
EARLY_NAMES = (
    r"P_{01}", r"P_{02}", r"P_{03}",
    r"P_{09}", r"P_{10}", r"P_{11}",
    r"P_{17}", r"P_{18}", r"P_{19}",
)
MIDDLE_MATH_NAMES = tuple(rf"M_{i}" for i in range(1, 6))
LATE_NAMES = (
    r"P_{04}", r"P_{05}", r"P_{06}", r"P_{07}", r"P_{08}",
    r"P_{12}", r"P_{13}", r"P_{14}", r"P_{15}", r"P_{16}",
    r"P_{20}", r"P_{21}", r"P_{22}", r"P_{23}", r"P_{24}",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def normalized(text: str) -> bytes:
    return (text.rstrip() + "\n").encode("utf-8")


def tex_row(*cells: str) -> str:
    return " & ".join(cells) + r" \\"


def xor_expression(terms: list[str]) -> str:
    if not terms:
        return "0"
    return (r"\mathbin{\oplus}\allowbreak ").join(terms)


def factor_expression(mask: int) -> str:
    return xor_expression([name for index, name in enumerate(COORDINATES) if (mask >> index) & 1])


def affine_expression(mask: int, names: tuple[str, ...]) -> str:
    require(mask >> len(names) == 0, "affine mask exceeds declared basis")
    return xor_expression([name for index, name in enumerate(names) if (mask >> index) & 1])


def products_tex(products) -> str:
    rows = [
        r"\begingroup\small",
        r"\begin{longtable}{@{}rcc>{\raggedright\arraybackslash}p{0.31\textwidth}>{\raggedright\arraybackslash}p{0.31\textwidth}@{}}",
        r"\caption{Complete 24-product certificate. A factor mask uses coordinate order $(L_0,\ldots,L_3,R_0,\ldots,R_3,Z_0,\ldots,Z_3)$. Multiplication is commutative, so the displayed factor order has no mathematical significance.}\label{tab:products}\\",
        r"\toprule",
        tex_row("product", "stage", "block", "first factor", "second factor"),
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        tex_row("product", "stage", "block", "first factor", "second factor"),
        r"\midrule",
        r"\endhead",
        r"\bottomrule",
        r"\endfoot",
    ]
    blocks = (r"0", r"1", r"0\mathbin{\oplus}1")
    for index, product in enumerate(products):
        stage = "early" if index in EARLY_INDICES else "late"
        rows.append(tex_row(
            rf"$P_{{{index + 1:02d}}}$",
            stage,
            rf"${blocks[index // 8]}$",
            rf"$\ell_{{\mathtt{{{product.u:03x}}}}}={factor_expression(product.u)}$",
            rf"$\ell_{{\mathtt{{{product.v:03x}}}}}={factor_expression(product.v)}$",
        ))
    rows.extend((r"\end{longtable}", r"\endgroup"))
    return "\n".join(rows)


def target_origins(affine_masks: dict[str, int], and_operations: list) -> list[str]:
    outer_atom_numbers = list(range(1, 10)) + list(range(15, 33))

    def project(mask: int) -> int:
        result = 0
        for index, atom_number in enumerate(outer_atom_numbers):
            if (mask >> (8 + atom_number)) & 1:
                result |= 1 << index
        return result

    requirements: list[tuple[str, int]] = []
    for index, operation in enumerate(and_operations[9:14], 1):
        requirements.append((rf"first factor of $M_{index}$", project(affine_masks[operation.a])))
        requirements.append((rf"second factor of $M_{index}$", project(affine_masks[operation.b])))
    requirements.extend((rf"output $S_{index}$", project(affine_masks[f"S{index}"])) for index in range(8))

    pivots: dict[int, int] = {}
    labels: list[str] = []
    for label, value in requirements:
        reduced = value
        while reduced:
            pivot = reduced.bit_length() - 1
            if pivot in pivots:
                reduced ^= pivots[pivot]
            else:
                pivots[pivot] = reduced
                labels.append(label)
                break
    require(len(labels) == 12, "formal target basis does not have twelve origins")
    return labels


def targets_tex(q_pre: list[int], q_total: list[int], coefficients: list[int], labels: list[str]) -> str:
    rows = [
        r"\begin{longtable}{@{}r>{\raggedright\arraybackslash}p{0.27\textwidth}ll@{}}",
        r"\caption{Formal quadratic reconstruction certificate derived from the NIST SLP. The first four rows form the pre-middle subspace.}\label{tab:targets}\\",
        r"\toprule",
        tex_row("row", "first independent requirement", "target signature", "selected products"),
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        tex_row("row", "first independent requirement", "target signature", "selected products"),
        r"\midrule",
        r"\endhead",
        r"\bottomrule",
        r"\endfoot",
    ]
    for index, (target, coefficient, label) in enumerate(zip(q_total, coefficients, labels)):
        role = r"$Q_{\mathrm{pre}}$" if index < len(q_pre) else r"$Q$"
        rows.append(tex_row(
            rf"{index + 1:02d} ({role})",
            label,
            rf"\texttt{{{target:017x}}}",
            rf"\texttt{{{coefficient:06x}}}",
        ))
    rows.append(r"\end{longtable}")
    return "\n".join(rows)


def staged_tex(witness) -> str:
    coordinate_basis = INPUT_NAMES
    middle_basis = ("1",) + INPUT_NAMES + EARLY_NAMES + MIDDLE_MATH_NAMES
    output_basis = middle_basis + LATE_NAMES

    rows = [
        r"\subsection{Input-linear coordinates}",
        r"The input bits are ordered $(U_0,\ldots,U_7)$, with $U_0$ the most significant bit.",
        r"\begin{longtable}{@{}rcl@{}}",
        r"\caption{The eight pre-middle coordinates as linear forms in $(U_0,\ldots,U_7)$.}\label{tab:coordinates}\\",
        r"\toprule",
        tex_row("coordinate", "mask", "linear form"),
        r"\midrule\endfirsthead",
        r"\toprule",
        tex_row("coordinate", "mask", "linear form"),
        r"\midrule\endhead",
        r"\bottomrule\endfoot",
    ]
    for name, mask in zip(COORD_NAMES, witness.coordinates):
        math_name = rf"{name[0]}_{name[1:]}"
        rows.append(tex_row(
            rf"${math_name}$",
            rf"\texttt{{{mask:02x}}}",
            rf"${affine_expression(mask, coordinate_basis)}$",
        ))
    rows.extend((r"\end{longtable}", ""))

    rows.extend((
        r"\subsection{Five retained middle products}",
        r"For this table the mask basis is",
        r"\[",
        r"(1,U_0,\ldots,U_7,P_{01},P_{02},P_{03},P_{09},P_{10},P_{11},P_{17},P_{18},P_{19},M_1,\ldots,M_5).",
        r"\]",
        r"A row defining $M_k$ has zero coefficients on $M_k,\ldots,M_5$; hence both factors are available before $M_k$ is formed.",
        r"\begingroup\small",
        r"\begin{longtable}{@{}r>{\raggedright\arraybackslash}p{0.41\textwidth}>{\raggedright\arraybackslash}p{0.41\textwidth}@{}}",
        r"\caption{Exact affine factors of the five middle AND gates.}\label{tab:middle-factors}\\",
        r"\toprule",
        tex_row("gate", "first factor", "second factor"),
        r"\midrule\endfirsthead",
        r"\toprule",
        tex_row("gate", "first factor", "second factor"),
        r"\midrule\endhead",
        r"\bottomrule\endfoot",
    ))
    for index, (left, right) in enumerate(witness.middle, 1):
        rows.append(tex_row(
            rf"$M_{index}$",
            rf"$\ell_{{\mathtt{{{left:x}}}}}={affine_expression(left, middle_basis)}$",
            rf"$\ell_{{\mathtt{{{right:x}}}}}={affine_expression(right, middle_basis)}$",
        ))
    rows.extend((r"\end{longtable}", r"\endgroup", ""))

    rows.extend((
        r"\subsection{Post-middle coordinates}",
        r"\begin{longtable}{@{}rc>{\raggedright\arraybackslash}p{0.72\textwidth}@{}}",
        r"\caption{The four post-middle coordinates in the same 23-element affine basis.}\label{tab:post-coordinates}\\",
        r"\toprule",
        tex_row("coordinate", "mask", "affine expression"),
        r"\midrule\endfirsthead",
        r"\toprule",
        tex_row("coordinate", "mask", "affine expression"),
        r"\midrule\endhead",
        r"\bottomrule\endfoot",
    ))
    for name, mask in zip(POST_NAMES, witness.post):
        math_name = rf"{name[0]}_{name[1:]}"
        rows.append(tex_row(
            rf"${math_name}$",
            rf"\texttt{{{mask:x}}}",
            rf"${affine_expression(mask, middle_basis)}$",
        ))
    rows.extend((r"\end{longtable}", ""))

    rows.extend((
        r"\subsection{Output reconstruction}",
        r"For the output rows, append the late products in the order",
        r"\[",
        r"(P_{04},P_{05},P_{06},P_{07},P_{08},P_{12},P_{13},P_{14},P_{15},P_{16},P_{20},P_{21},P_{22},P_{23},P_{24})",
        r"\]",
        r"to the 23-element middle basis.",
        r"\begingroup\small",
        r"\begin{longtable}{@{}rc>{\raggedright\arraybackslash}p{0.72\textwidth}@{}}",
        r"\caption{Exact affine reconstruction of the eight output bits.}\label{tab:output-reconstruction}\\",
        r"\toprule",
        tex_row("output", "mask", "affine expression"),
        r"\midrule\endfirsthead",
        r"\toprule",
        tex_row("output", "mask", "affine expression"),
        r"\midrule\endhead",
        r"\bottomrule\endfoot",
    ))
    for name, mask in zip(OUTPUT_NAMES, witness.outputs):
        math_name = rf"{name[0]}_{name[1:]}"
        rows.append(tex_row(
            rf"${math_name}$",
            rf"\texttt{{{mask:010x}}}",
            rf"${affine_expression(mask, output_basis)}$",
        ))
    rows.extend((r"\end{longtable}", r"\endgroup"))
    return "\n".join(rows)


def evaluation_tex(products, witness) -> str:
    obtained = tuple(evaluate_staged(x, products, witness) for x in range(256))
    require(obtained == AES_SBOX_TABLE, "staged certificate output table differs from FIPS")
    rows = [
        r"\begingroup\scriptsize",
        r"\setlength{\tabcolsep}{2.7pt}",
        r"\begin{longtable}{c*{16}{c}}",
        r"\caption{Complete evaluation of the staged 29-AND certificate. Row and column headers are hexadecimal input nibbles; each body entry is the hexadecimal output byte. This table is entrywise identical to FIPS 197, Table 4.}\label{tab:evaluation}\\",
        r"\toprule",
        tex_row("", *(rf"\texttt{{{value:x}}}" for value in range(16))),
        r"\midrule",
        r"\endfirsthead",
        r"\toprule",
        tex_row("", *(rf"\texttt{{{value:x}}}" for value in range(16))),
        r"\midrule",
        r"\endhead",
        r"\bottomrule",
        r"\endfoot",
    ]
    for high in range(16):
        values = [rf"\texttt{{{obtained[16 * high + low]:02x}}}" for low in range(16)]
        rows.append(tex_row(rf"\texttt{{{high:x}}}", *values))
    rows.extend((r"\end{longtable}", r"\endgroup"))
    return "\n".join(rows)


def listing_tex(path: Path, language: str, caption: str, label: str) -> str:
    content = path.read_text(encoding="utf-8").rstrip()
    return (
        f"\\begin{{lstlisting}}[language={language},caption={{{caption}}},label={{{label}}}]\n"
        + content
        + "\n\\end{lstlisting}\n"
    )


def expected_files() -> dict[Path, bytes]:
    _, values, affine_masks, and_operations = baseline_data()
    _, q_pre, q_total = derive_targets(values, affine_masks, and_operations)
    _, products, coefficients = parse_certificate(CERTIFICATE)
    staged_products = parse_staged_products(PRODUCT_CERTIFICATE)
    witness = parse_staged(STAGED_CERTIFICATE)
    require(
        tuple((product.u, product.v) for product in products)
        == tuple((product.left, product.right) for product in staged_products),
        "product parsers disagree",
    )
    return {
        ARTICLE / "products.tex": normalized(products_tex(products)),
        ARTICLE / "targets.tex": normalized(
            targets_tex(q_pre, q_total, coefficients, target_origins(affine_masks, and_operations))
        ),
        ARTICLE / "staged.tex": normalized(staged_tex(witness)),
        ARTICLE / "evaluation.tex": normalized(evaluation_tex(staged_products, witness)),
        ARTICLE / "xag.tex": normalized(
            listing_tex(
                ROOT / "certificates" / "aes29.xag",
                "bash",
                "Normalized 29-AND XAG certificate.",
                "lst:xag",
            )
        ),
        ARTICLE / "minimal-verifier.tex": normalized(
            listing_tex(
                ROOT / "verify" / "minimal_verify.py",
                "Python",
                "Standalone exhaustive verifier.",
                "lst:minimal",
            )
        ),
    }


def build() -> None:
    ARTICLE.mkdir(parents=True, exist_ok=True)
    expected = expected_files()
    for path, data in expected.items():
        path.write_bytes(data)
    names = ", ".join(str(path.relative_to(ROOT)) for path in expected)
    print(f"BUILT: {names}")


def check() -> None:
    expected = expected_files()
    for path, data in expected.items():
        require(path.is_file(), f"missing generated article source {path.relative_to(ROOT)}")
        require(path.read_bytes() == data, f"stale generated article source {path.relative_to(ROOT)}")
    print("PASS: all generated LaTeX appendices are current and byte-exact")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="compare generated files without modifying them")
    args = parser.parse_args()
    check() if args.check else build()


if __name__ == "__main__":
    main()
