# Deterministic construction of the 29-AND SLP

The construction is a reproducible derivation from three fixed inputs:

```text
baseline/aes-sbox-fwd-g113-a32-d27-ad6.slp
certificates/tower24_witness.txt
certificates/staged29_witness.txt
```

The baseline is the exact official NIST 32-AND forward AES S-box SLP. The product witness contains the transform tag `A 128c`, 24 linear-factor products, their exterior signatures, and twelve formal reconstruction masks. The staged witness contains the exact input-coordinate masks, five recursively available middle-factor pairs, four post-middle coordinate masks, and eight output masks.

The formal target used to audit the 24 products is not supplied by either witness. [`verify/verify_tower24.py`](../verify/verify_tower24.py) derives that target independently from the archived NIST SLP on every run.

## 1. Build the readable circuit

```sh
python3 construction/build_transparent.py
```

This writes

```text
circuits/aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp
```

The builder:

1. verifies the eight published input-coordinate masks against the NIST input-linear wires;
2. copies the NIST input-linear layer;
3. materializes the nine published products independent of `Z`;
4. interprets the two fixed masks for each middle AND in sequence, verifies each factor against the corresponding NIST truth table, and computes the AND;
5. interprets and verifies the four fixed `Z` masks;
6. materializes the fifteen published late products;
7. interprets and verifies the eight fixed output masks.

No Gaussian-elimination search is used to choose these emitted affine formulas. The fixed staged witness is the construction certificate; the NIST truth tables are used only to reject an incorrect certificate during reconstruction. The emitted circuit has 29 AND, 422 XOR, and 4 NOT instructions, ordinary depth 35, and AND-depth 6.

## 2. Resynthesize only the affine network

```sh
python3 construction/affine_resynthesis.py
```

This reads the readable circuit and writes

```text
circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp
```

The resynthesizer treats the constant, eight inputs, and preceding AND outputs as an affine basis. It removes or replaces only XOR/NOT computations and checks that every AND output, in order, has exactly the same two affine factor masks as in the readable circuit. It also checks that all eight output masks are unchanged. The result has 29 AND, 195 XOR, and 4 NOT instructions.

## 3. Normalize the nonlinear structure

```sh
python3 construction/normalize_xag.py \
  circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp \
  > certificates/aes29.xag
```

The normal form absorbs all XOR and NOT gates into affine masks. Each successive AND output becomes one new basis atom. The released XAG records exactly the 29 ordered factor-mask pairs and the eight final output masks.

## Complete rebuild and audit

From the repository root:

```sh
make rebuild
```

The audit compares regenerated files byte for byte with the released artifacts, checks their fixed SHA-256 digests, and exhaustively verifies the AES function.
