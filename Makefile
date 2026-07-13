SHELL := /bin/sh
PYTHON ?= python3
SOURCE_DATE_EPOCH ?= 1783814400

export PYTHONDONTWRITEBYTECODE := 1

.PHONY: verify rebuild article pages audit release clean

verify:
	./verify/run_all.sh

rebuild:
	$(PYTHON) construction/build_transparent.py
	$(PYTHON) construction/affine_resynthesis.py
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT INT TERM; \
	  $(PYTHON) construction/normalize_xag.py circuits/aes-sbox-fwd-g228-a29-d35-ad6.slp > "$$tmp"; \
	  cmp "$$tmp" certificates/aes29.xag
	./verify/run_all.sh

article:
	$(PYTHON) tools/build_article_sources.py
	cd article && SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) FORCE_SOURCE_DATE=1 \
	  latexmk -pdf -interaction=nonstopmode -halt-on-error article.tex
	$(PYTHON) tools/build_site.py

pages: article

# Full executable and release-tree audit.  MANIFEST.sha256 must be current.
audit: verify
	$(PYTHON) tools/build_article_sources.py --check
	$(PYTHON) tools/build_site.py --check
	$(PYTHON) tools/check_release.py

release:
	$(PYTHON) tools/make_release.py

clean:
	-cd article && latexmk -c article.tex
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type f \( -name '*.pyc' -o -name '*.pyo' -o -name '*.o' \) -delete
