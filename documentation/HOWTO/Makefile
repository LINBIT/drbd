# Generates online and print versions of SGML source file.

BASENAME=DRBD-HOWTO

# SGML source file.
SGML_FILE=$(BASENAME).sgml

# Stylesheets
DSL_PRINT=$(SGML_SHARE)/dsssl-stylesheets/print/ldp.dsl\#print
DSL_HTML=$(SGML_SHARE)/dsssl-stylesheets/html/ldp.dsl\#html

# Generated files.
HTML_FILE=index.html
HTM_FILE=$(BASENAME).htm
TEX_FILE=$(BASENAME).tex
RTF_FILE=$(BASENAME).rtf
PDF_FILE=$(BASENAME).pdf
DVI_FILE=$(BASENAME).dvi
PS_FILE=$(BASENAME).ps


# Build rules.

html: $(HTML_FILE)

htm: $(HTM_FILE)

tex: $(TEX_FILE)

rtf: $(RTF_FILE)

pdf: $(PDF_FILE)

dvi: $(DVI_FILE)

ps: $(PS_FILE)

all: html htm tex rtf pdf dvi ps

clean:
	rm -f $(BASENAME).{htm,log,aux,ps,pdf,tex,dvi,rtf,fot}
	rm -f *.html

distclean: clean
	rm -f $(BASENAME).tgz

package:
	rm -f $(BASENAME).tgz
	tar -C .. -czf /tmp/$(BASENAME).tgz $(BASENAME)
	mv /tmp/$(BASENAME).tgz .

dist: clean package

distall: all package


# Compile rules.

$(HTML_FILE): $(SGML_FILE)
	openjade -t sgml -d $(DSL_HTML) $(SGML_FILE)

$(HTM_FILE): $(SGML_FILE)
	openjade -t sgml -V nochunks -d $(DSL_HTML) \
	$(SGML_FILE) > $(HTM_FILE)

$(TEX_FILE): $(SGML_FILE)
	openjade -t tex -d $(DSL_PRINT) $(SGML_FILE)

$(RTF_FILE): $(SGML_FILE)
	openjade -t rtf -d $(DSL_PRINT) $(SGML_FILE)

# [pdf]jadetex is run 3 times to resolve references.
#$(PDF_FILE): $(TEX_FILE)
#       pdfjadetex $(TEX_FILE)
#       pdfjadetex $(TEX_FILE)
#       pdfjadetex $(TEX_FILE)

# This *should* work, but htmldoc has bugs ...
#$(PDF_FILE): $(SGML_FILE)
#       openjade -t sgml -V nochunks -d $(DSL_HTML) \
#       $(SGML_FILE) | htmldoc -f $(PDF_FILE) -

# Have to use ldp_print to work around htmldoc bugs
# ldp_print can also do the ps file - see script
$(PDF_FILE): $(HTM_FILE)
	ldp_print $(HTM_FILE)

$(DVI_FILE): $(TEX_FILE)
	jadetex $(TEX_FILE)
	jadetex $(TEX_FILE)
	jadetex $(TEX_FILE)

$(PS_FILE): $(DVI_FILE)
	dvips $(DVI_FILE) -o $(PS_FILE)

#$(PS_FILE): $(SGML_FILE)
#       openjade -t sgml -V nochunks -d $(DSL_HTML) \
#       $(SGML_FILE) | htmldoc -f $(PS_FILE) -
