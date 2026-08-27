SHELL := /bin/sh
.ONESHELL:

PYTHON ?= python3
LATEXMK ?= latexmk
LATEXMLC ?= latexmlc
QPDF ?= qpdf

SOURCE_DATE_EPOCH := 1787788800
FORCE_SOURCE_DATE := 1
TZ := UTC

export SOURCE_DATE_EPOCH FORCE_SOURCE_DATE TZ
export PYTHONDONTWRITEBYTECODE := 1

PAPER_SOURCE := paper/paper.tex
HTML_STYLESHEET := paper/html.xsl
XAG := certificates/aes29.xag
BUILD_DIR := build

.DEFAULT_GOAL := all

.PHONY: all verify publication paper html check-pdf check-html clean

all: verify publication

verify:
	$(PYTHON) verify.py

publication: check-pdf check-html

paper: $(PAPER_SOURCE) $(XAG)
	@set -eu
	mkdir -p $(BUILD_DIR) docs
	printf '%s\n' '\pdftrailerid{}' '\input{$(PAPER_SOURCE)}' > $(BUILD_DIR)/paper.tex
	$(LATEXMK) -pdf -interaction=nonstopmode -halt-on-error -file-line-error \
	  -outdir=$(BUILD_DIR) $(BUILD_DIR)/paper.tex
	cp $(BUILD_DIR)/paper.pdf docs/paper.pdf

html: $(PAPER_SOURCE) $(HTML_STYLESHEET) docs/article.css $(XAG)
	@set -eu
	mkdir -p $(BUILD_DIR) docs
	$(LATEXMLC) --VERSION 2>&1 | grep -F 'LaTeXML version 0.8.8'
	$(LATEXMLC) \
	  --strict \
	  --format=html5 \
	  --presentationmathml \
	  --mathtex \
	  --nocomments \
	  --nodefaultresources \
	  --css=../docs/article.css \
	  --stylesheet=$(HTML_STYLESHEET) \
	  --destination=docs/index.html \
	  --log=$(BUILD_DIR)/latexml.log \
	  $(PAPER_SOURCE)
	grep -Fx 'Status:conversion:0' $(BUILD_DIR)/latexml.log
	if LC_ALL=C grep -Eiq '^[[:space:]]*(Warning|Error|Fatal):|unresolved (reference|target)|undefined (citation|reference)' $(BUILD_DIR)/latexml.log; then
	  cat $(BUILD_DIR)/latexml.log
	  exit 1
	fi

check-pdf: paper
	@set -eu
	test -s docs/paper.pdf
	$(QPDF) --check docs/paper.pdf
	if LC_ALL=C grep -Eq 'LaTeX Warning: (Citation|Reference).*undefined|LaTeX Warning: There were undefined references|Overfull \\[hv]box' $(BUILD_DIR)/paper.log; then
	  cat $(BUILD_DIR)/paper.log
	  exit 1
	fi

check-html: html
	@set -eu
	find docs -mindepth 1 \
	  ! -path docs/.nojekyll \
	  ! -path docs/article.css \
	  ! -path docs/index.html \
	  ! -path docs/paper.pdf \
	  -print > $(BUILD_DIR)/unexpected-docs
	if test -s $(BUILD_DIR)/unexpected-docs; then
	  cat $(BUILD_DIR)/unexpected-docs
	  exit 1
	fi
	sed 's/^|//' <<'PY' | $(PYTHON) - docs/index.html $(XAG)
	|from base64 import b64decode
	|from html.parser import HTMLParser
	|from pathlib import Path
	|import re
	|import sys

	|class Publication(HTMLParser):
	|    def __init__(self):
	|        super().__init__(convert_charrefs=True)
	|        self.abstract = False
	|        self.forbidden = []
	|        self.google = False
	|        self.current_listing = []
	|        self.downloads = []
	|        self.listing_depth = 0
	|        self.listings = []
	|        self.links = set()
	|        self.math_count = 0
	|        self.proof = False
	|        self.scopes = set()
	|        self.semantics_count = 0
	|        self.stylesheet = False
	|        self.text = []
	|        self.theorem = False

	|    def handle_starttag(self, tag, attrs):
	|        attrs = dict(attrs)
	|        classes = set(attrs.get("class", "").split())
	|        if tag == "meta" and attrs.get("name") == "google-site-verification":
	|            self.google = attrs.get("content") == "me5mvseR6ptdS0BZ_wss6pUWq4Wjj3Tdhz166JAic_w"
	|        if tag == "link" and attrs.get("rel") == "stylesheet":
	|            self.stylesheet = attrs.get("href") == "article.css"
	|        if tag == "a" and attrs.get("href"):
	|            self.links.add(attrs["href"])
	|            if "download" in attrs:
	|                self.downloads.append((attrs["download"], attrs["href"]))
	|        if tag == "section" and "ltx_abstract" in classes:
	|            self.abstract = True
	|        if "ltx_theorem" in classes:
	|            self.theorem = True
	|        if "ltx_proof" in classes:
	|            self.proof = True
	|        if tag == "math":
	|            self.math_count += 1
	|        if tag == "semantics":
	|            self.semantics_count += 1
	|        if tag == "th" and attrs.get("scope"):
	|            self.scopes.add(attrs["scope"])
	|        if tag == "pre" and "ltx_listing_code" in classes:
	|            self.listing_depth = 1
	|        elif self.listing_depth:
	|            self.listing_depth += 1
	|        if tag in {"script", "iframe", "object", "embed"}:
	|            self.forbidden.append(tag)

	|    def handle_endtag(self, tag):
	|        if self.listing_depth:
	|            self.listing_depth -= 1
	|            if not self.listing_depth:
	|                self.listings.append("".join(self.current_listing))
	|                self.current_listing = []

	|    def handle_data(self, data):
	|        self.text.append(data)
	|        if self.listing_depth:
	|            self.current_listing.append(data)

	|html_path, xag_path = map(Path, sys.argv[1:])
	|parser = Publication()
	|parser.feed(html_path.read_text(encoding="utf-8"))
	|assert parser.google, "missing Google site-verification metadata"
	|assert parser.stylesheet, "HTML must use docs/article.css"
	|assert parser.abstract, "abstract must be a section"
	|assert parser.theorem and parser.proof, "theorem and proof structure is missing"
	|assert parser.math_count > 0, "native MathML is missing"
	|assert parser.semantics_count == parser.math_count, "each formula needs semantic MathML annotation"
	|assert {"col", "row"} <= parser.scopes, "table headings need column and row scope"
	|assert not parser.forbidden, f"embedded or scripted content found: {parser.forbidden}"
	|xag = xag_path.read_text(encoding="utf-8")
	|assert parser.listings.count(xag) == 1, "HTML must contain exactly one verbatim XAG listing"
	|assert "https://github.com/umizame/S-box_29-AND/blob/master/circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp" in parser.links, "SLP link differs"
	|assert len(parser.downloads) == 1, "HTML must contain exactly one listing download"
	|download_name, download_href = parser.downloads[0]
	|assert download_name == "certificates/aes29.xag", "XAG download name differs"
	|prefix = "data:text/plain;base64,"
	|assert download_href.startswith(prefix), "XAG download must be self-contained"
	|assert b64decode(download_href[len(prefix):], validate=True) == xag_path.read_bytes(), "XAG download differs"
	|text = re.sub(r"\s+", " ", "".join(parser.text))
	|assert "12 July 2026; revised 27 August 2026" in text, "publication dates differ"
	|assert "Download the listing ()" not in text, "anonymous listing download control found"
	PY

clean:
	@set -eu
	rm -rf $(BUILD_DIR)
