# Makefile in documentation directory
#
# This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
#
# drbd is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# drbd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with drbd; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

MANPAGES       := drbdsetup.8 drbd.conf.5 drbd.8 drbdadm.8 drbddisk.8 drbdmeta.8
SOURCES        := $(wildcard *.xml)

STYLESHEET_PREFIX ?= http://docbook.sourceforge.net/release/xsl/current
MANPAGES_STYLESHEET ?= $(STYLESHEET_PREFIX)/manpages/docbook.xsl
HTML_STYLESHEET ?= $(STYLESHEET_PREFIX)/xhtml/docbook.xsl
FO_STYLESHEET ?= $(STYLESHEET_PREFIX)/fo/docbook.xsl

XSLTPROC_OPTIONS ?= --xinclude
XSLTPROC_MANPAGES_OPTIONS ?= $(XSLTPROC_OPTIONS)
XSLTPROC_HTML_OPTIONS ?= $(XSLTPROC_OPTIONS)
XSLTPROC_FO_OPTIONS ?= $(XSLTPROC_OPTIONS)

all:
	@echo "To (re)make the documentation: make doc"

clean:
	@echo "To clean the documentation: make doc-clean"

doc:	man

doc-clean: distclean


####### Implicit rules

.SUFFIXES: .sgml .5 .8 .html .pdf .ps

%.5 %.8: %.xml 
	xsltproc \
	$(XSLTPROC_MANPAGES_OPTIONS) \
	$(MANPAGES_STYLESHEET) $<

%.html: %.xml
	xsltproc -o $@ \
	$(XSLTPROC_HTML_OPTIONS) \
	$(HTML_STYLESHEET) $<

%.fo: %.xml
	xsltproc -o $@ \
	$(XSLTPROC_FO_OPTIONS) \
	$(FO_STYLESHEET) $<

distclean:
	rm -f *.[58] manpage.links manpage.refs *~ manpage.log
	rm -f *.ps.gz *.pdf *.ps *.html pod2htm*

#######

man:	$(MANPAGES)

install:
	@ok=true; for f in $(MANPAGES) ; \
		do [ -e $$f ] || { echo $$f missing ; ok=false; } ; \
	done ; $$ok
	set -e; for f in $(MANPAGES) ; do \
		s=$${f##*.}; \
		install -v -D -m 644 $$f $(PREFIX)/usr/share/man/man$$s/$$f ; \
	done

uninstall:
	@ set -e; for f in $(MANPAGES) ; do \
		s=$${f##*.}; \
		rm -v $(PREFIX)/usr/share/man/man$$s/$$f ; \
	done

html:	$(SOURCES:.xml=.html)

pdf:	$(SOURCES:.xml=.pdf)

ps:	$(SOURCES:.xml=.ps)



