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
#
#
# For Debian:
# nsgmls drbdsetup.sgml | sgmlspl /usr/lib/perl5/sgmlspl-specs/docbook2man-spec.pl
# On RedHat it is at:
# /usr/share/sgml/docbook/utils-0.6/helpers/docbook2man-spec.pl
# the RedHat only way is docbook2man
# hmmm, nowadays docbook2man works also on Debian

MANPAGES       := drbdsetup.8 drbd.conf.5 drbd.8 drbdadm.8 drbddisk.8 drbdmeta.8

#
# Docbook Magic for SuSE, Worksforme...
# Needs to be explicitly enabled with make doc DIST=SuSE-9.0
# requires these packages and their dependencies:
#  docbook-dsssl-stylesheets docbook-toys
#  docbook-utils docbook-utils opensp perl-SGMLS
#
ifeq ($(DIST),SuSE-9.0)
  # dockbook2man just does not work.
  # this does:
  DB2MAN :=\
  @_db2man() { in=$$1		;\
   echo "  [DB2MAN] $$in"	;\
   nsgmls "$$in" |\
   sgmlspl /usr/share/sgml/docbook/utils-0.6.6/helpers/docbook2man-spec.pl;\
  }; _db2man

  # dockbook2html produces errors and swallows tables.
  # db2html works, but in contrast do dockbook2man creates
  # a subdirectory and some extra files ...
  # this works for me:
  DB2HTML :=\
  _db2html() { in=$$1; base=$${in%.sgml}		;\
   echo " [DB2HTML] $$in"			;\
   db2html "$$in"				;\
   ln -sf t1.html $$base/index.html		;\
   mv $$base/*.html .		                ;\
   rm -rf $$base/   		                ;\
  }; _db2html

else

 DB2MAN          := $(shell which 2>/dev/null docbook2man)
 DB2HTML         := $(shell which 2>/dev/null docbook2html)
 DB2PDF          := $(shell which 2>/dev/null docbook2pdf)
 DB2PS           := $(shell which 2>/dev/null docbook2ps)

endif


all:
	@echo "To (re)make the documentation: make doc"

clean:
	@echo "To clean the documentation: make doc-clean"

doc:	man

doc-clean: distclean


####### Implicit rules

.SUFFIXES: .sgml .5 .8 .html .pdf .ps

ifneq ($(DB2MAN)$(DB2HTML)$(DB2PDF)$(DB2PS),)

.sgml.5:
	$(DB2MAN) $<

.sgml.8:
	$(DB2MAN) $<

.sgml.html:
	$(DB2HTML) $<
	mv index.html $@

.sgml.pdf:
	$(DB2PDF) $<

.sgml.ps:
	$(DB2PS) $<
	gzip -c $@ > $@.gz

distclean:
	rm -f *.[58] manpage.links manpage.refs *~ manpage.log
	rm -f *.ps.gz *.pdf *.ps *.html pod2htm*

else

.sgml.5:
	@echo "could not find docbook tools, sorry." ; exit 1

.sgml.8:
	@echo "could not find docbook tools, sorry." ; exit 1

.sgml.html:
	@echo "could not find docbook tools, sorry." ; exit 1

.sgml.pdf:
	@echo "could not find docbook tools, sorry." ; exit 1

.sgml.ps:
	@echo "could not find docbook tools, sorry." ; exit 1

distclean:
	@echo "could not find docbook tools, sorry."

endif

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

html:	$(shell ls *.sgml | sed s/sgml/html/g)

pdf:	$(shell ls *.sgml | sed s/sgml/pdf/g)

ps:	$(shell ls *.sgml | sed s/sgml/ps/g)



