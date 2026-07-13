# Restricted GF(4)-triangle rank calculation

`exact_gf4_triangle_rank.py` is an exact finite calculation for one narrowly
specified model: products of two homogeneous linear forms in the six input
bits, followed by arbitrary affine recombination.  It enumerates all 651
nonzero decomposable points of `Lambda^2(F_2^6)` and all 511 seven-dimensional
superspaces containing the six-dimensional quadratic output space.  None is
spanned by its decomposable points.

Run:

```sh
python3 search/exact_gf4_triangle_rank.py
```

The result proves that the eight-product formula used by the certificate is
optimal **within this linear-factor product model**.  It is not used in the
29-AND AES upper-bound proof and is not claimed as a lower bound for arbitrary
layered XOR-AND-NOT circuits.  Boolean idempotence permits products involving
nonlinear intermediates to contribute terms of lower algebraic degree, which
is outside the enumerated model.
