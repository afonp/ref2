## Makefile for ref2.tex
## Requires: TeX Live / MacTeX (pdflatex, bibtex)

PAPER    = ref2
FIGS     = pipeline.pdf drift.pdf
TEXBIN   ?= /usr/local/texlive/2026/bin/universal-darwin
PDFLATEX = $(TEXBIN)/pdflatex
BIBTEX   = $(TEXBIN)/bibtex

.PHONY: all clean figs

all: $(PAPER).pdf

$(PAPER).pdf: $(PAPER).tex $(PAPER).bib $(FIGS)
	$(PDFLATEX) -interaction=nonstopmode $(PAPER)
	$(BIBTEX) $(PAPER)
	$(PDFLATEX) -interaction=nonstopmode $(PAPER)
	$(PDFLATEX) -interaction=nonstopmode $(PAPER)

figs: $(FIGS)

pipeline.pdf drift.pdf: make_figs.py
	python3 make_figs.py

clean:
	rm -f $(PAPER).aux $(PAPER).bbl $(PAPER).blg $(PAPER).log \
	       $(PAPER).out $(PAPER).pdf

cleanall: clean
	rm -f pipeline.pdf drift.pdf
