# An Explicit 29-AND Circuit for the AES S-box

[umizame](https://github.com/umizame) · 12 July 2026; revised 27 August and 1 September 2026

This repository presents an explicit straight-line program for the forward AES S-box specified in FIPS 197. The [program](circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp) contains 228 instructions: 195 XOR, 29 AND, and 4 NOT. Its gate depth is 35 and its AND-depth is 6.

The construction and its proof are given in the complete [HTML paper](https://umizame.github.io/S-box_29-AND/) and [PDF](docs/paper.pdf). The corresponding [normalized XAG](certificates/aes29.xag) records the affine factors of the twenty-nine AND gates and the eight affine outputs.


NIST's [Circuit Complexity list of circuits](https://csrc.nist.gov/projects/circuit-complexity/list-of-circuits) links to this straight-line program.
