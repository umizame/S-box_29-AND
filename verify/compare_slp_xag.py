#!/usr/bin/env python3
"""Show that both published SLPs normalize to the released XAG certificate."""
from pathlib import Path

from verify_slp import affine_xag, parse_slp
from verify_xag_certificate import CERTIFICATE, parse

ROOT = Path(__file__).resolve().parents[1]
PATHS = (
    ROOT / "circuits" / "aes-sbox-fwd-g228-a29-d35-ad6.slp",
    ROOT / "circuits" / "aes-sbox-fwd-g455-a29-d35-ad6-transparent.slp",
)


def main() -> None:
    certificate = parse(CERTIFICATE)
    for path in PATHS:
        normalized = affine_xag(parse_slp(path))
        if normalized != certificate:
            raise SystemExit(f"FAIL: normalized XAG differs for {path.name}")
        print(f"PASS: {path.name} normalizes exactly to certificates/aes29.xag")
    print("PASS: affine resynthesis leaves all 29 AND factor functions and all output functions unchanged")


if __name__ == "__main__":
    main()
