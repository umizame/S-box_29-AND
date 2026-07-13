# A 29-AND Circuit for the AES S-box

**Authors (unordered): {GPT-5.6 Pro, [umizame](https://github.com/umizame)}**

This repository gives an explicit one-bit Boolean circuit for the standard forward AES S-box in the NIST basis `{AND, XOR, NOT}`. Its nonlinear schedule is

```text
9 early ANDs + 5 middle ANDs + 15 late ANDs = 29 ANDs
```

A resynthesized straight-line implementation has

```text
29 AND + 195 XOR + 4 NOT = 228 instructions
ordinary gate depth: 35
AND-depth: 6
```

Consequently,

```text
MC(AES S-box) <= 29.
```

This is a constructive upper bound. No claim that 29 is minimal is made.

## Complete staged certificate

The mathematical construction is recorded by two certificates:

- [`certificates/tower24_witness.txt`](certificates/tower24_witness.txt) contains the 24 products of linear forms and their formal reconstruction masks.
- [`certificates/staged29_witness.txt`](certificates/staged29_witness.txt) contains the eight input-linear coordinates, the two factors of each of the five recursively available middle AND gates, the four post-middle coordinates, and the eight output masks.

`U0` and `S0` are the most significant input and output bits. A hexadecimal affine mask is interpreted least-significant-mask-bit first in its explicitly declared basis; for example, mask `69` in basis `(U0,...,U7)` means `U0 XOR U3 XOR U5 XOR U6`.

The direct staged proof uses only Python 3:

```sh
python3 verify/verify_staged29.py
```

Expected output:

```text
PASS: staged certificate; 9 early AND + 5 middle AND + 15 late AND = 29 AND
PASS: all affine masks obey their availability filtration; all 256 FIPS table entries agree
```

The checker strictly parses both certificates, verifies that no middle factor uses a future middle value, verifies the early/late factor filtration, evaluates the explicitly staged construction for every input byte, and compares all 256 outputs with the literal FIPS 197 forward S-box table.

## Concrete straight-line implementation

The primary SLP is [`circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp`](circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp), with SHA-256 digest

```text
f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3
```

Its standalone verifier uses only the Python standard library:

```sh
python3 verify/minimal_verify.py
```

Expected output:

```text
PASS: 228 instructions; 29 AND, 195 XOR, 4 NOT; depth 35; AND-depth 6; all 256 FIPS entries; sha256 f41861c4b15bc78840708a5da2fab6ca9dd204c1e3e572cae49912c713bf18d3
```

The verifier strictly parses the complete circuit container, declarations, gate grammar, arities, data dependencies, temporary-wire range, and outputs. It checks the exact tally and depths. It independently checks the literal FIPS table against inversion in `GF(2^8)` modulo `x^8+x^4+x^3+x+1` followed by the specified affine map, then evaluates the SLP on all 256 inputs.

## Independent derivation and redundant audit

The archived baseline [`baseline/aes-sbox-fwd-g113-a32-d27-ad6.slp`](baseline/aes-sbox-fwd-g113-a32-d27-ad6.slp) is the exact official NIST SLP byte sequence, with SHA-256 digest

```text
6ba4f63b832a1f4520a76cab5680e673fdd744ad2651918882eeecff7957698a
```

Its nonlinear schedule is `9 + 5 + 18 = 32`. The derivation retains the five middle functions and replaces the 27 outer products by the schedule-aware 24-product certificate. [`verify/verify_tower24.py`](verify/verify_tower24.py) derives the required target from the NIST SLP rather than accepting it from the witness. It checks the three exact eight-product `GF(4)` blocks, all formal reconstruction identities on all `2^12 = 4096` coordinate assignments, and the actual sequential realization on all 256 AES inputs.

The complete redundant audit is

```sh
./verify/run_all.sh
```

It includes scalar, bit-parallel, and C99 evaluation; FIPS algebraic/table agreement; strict structural checks; malformed-circuit rejection under normal and optimized Python; XAG normalization; equality of the two SLP nonlinear normal forms; the exact `GF(4)` identity; the formal and staged NIST bridge; the restricted ancillary rank enumeration; and deterministic reconstruction.

## Deterministic reconstruction

The readable circuit is

```text
circuits/aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp
```

The transparent builder consumes the fixed product and staged certificates. It verifies every staged mask against the archived NIST truth tables before emitting the circuit; it does not discover or silently replace the published affine formulas during the build. The affine resynthesizer changes only the affine network and formally preserves every ordered AND-factor mask and every output mask.

Rebuild the transparent SLP, resynthesize the primary SLP, regenerate the normalized XAG, and run the full audit with

```sh
make rebuild
```

## Paper and GitHub Pages

The canonical paper source is [`article/article.tex`](article/article.tex). It contains the exact NIST/FIPS problem statement, a self-contained definition of the 29-AND construction, the proof, the complete decomposition, all 256 evaluated outputs, the formal bridge, the normalized XAG, and a standalone verifier listing.

The build order is canonical TeX source to PDF, followed by HTML generation from the same expanded TeX source:

```sh
make article
```

This produces [`article/article.pdf`](article/article.pdf) and [`docs/index.html`](docs/index.html). The latter is a mathematical GitHub Pages rendering of the paper, not a separate informal article. The release audit checks generated appendices, bibliography, cross-references, PDF metadata and layout conditions, HTML links and anchors, exact public artifact copies, fixed digests, and the release manifest:

```sh
make audit
```

## Repository layout

- `circuits/` — primary and readable 29-AND SLPs
- `certificates/` — staged construction, 24-product witness, and normalized XAG
- `verify/` — scalar, structural, bit-parallel, C99, XAG, staged, identity, and bridge verifiers
- `construction/` — deterministic transparent construction and affine resynthesis
- `search/` — ancillary restricted exact rank calculation
- `baseline/` — exact official NIST 32-AND SLP used for provenance
- `article/` — canonical TeX source, generated mathematical appendices, bibliography, CSL, and PDF
- `docs/` — complete GitHub Pages paper and byte-identical public artifacts
- `tools/` — paper/site generation, release checks, manifest handling, and deterministic ZIP creation

## Primary sources

- NIST Circuit Complexity: <https://csrc.nist.gov/projects/circuit-complexity>
- NIST list of circuits: <https://csrc.nist.gov/projects/circuit-complexity/list-of-circuits>
- Official NIST 32-AND SLP: <https://github.com/usnistgov/Circuits/blob/master/data/slp/aes/aes-sbox-fwd-g113-a32-d27-ad6.slp>
- FIPS 197-upd1: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf>
