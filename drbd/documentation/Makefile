# Makefile in documentation directory
#
# This file is part of drbd by Philipp Reisner
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

include ../Makefile.vars
LANGS=ja pt_BR

####### Implicit rules

.SUFFIXES: .sgml .5 .8 .html .pdf .ps

.sgml.5:
	$(DB2MAN) $<

.sgml.8:
	$(DB2MAN) $<

.sgml.html:
	$(DB2HTML) $<
	mv index.html $@

.sgml.pdf:
	$(DB2PDF) $< 
	if [ $@ = drbd.conf.pdf ]; then mv drbd.pdf drbd.conf.pdf; fi 

.sgml.ps:
	$(DB2PS) $< 
	if [ $@ = drbd.conf.ps ]; then mv drbd.ps drbd.conf.ps; fi 
	gzip -c $@ > $@.gz

#######

all:
	@echo "To (re)make the documentation: make doc"

clean:
	@echo "To clean the documentation: make doc-clean"

ifneq ($(DB2MAN)$(DB2HTML)$(DB2PDF)$(DB2PS),)
doc:	prepare man HOWTO/index.html

doc-clean: distclean

else

doc:
	@echo "could not find docbook tools, sorry."

doc-clean:
	@echo "could not find docbook tools, leaving documentation in place."

endif

distclean:
	rm -f *.[58] manpage.links manpage.refs *~ manpage.log HOWTO/*.html
	rm -f *.ps.gz *.pdf *.ps *.html
	@ set -e; for i in $(LANGS); do ln -sf ../Makefile.lang $$i/Makefile ; $(MAKE) -C $$i clean ; rm $$i/Makefile ; done

prepare:
	@ set -e; for i in $(LANGS); do ln -sf ../Makefile.lang $$i/Makefile; done

man:	drbdsetup.8 drbd.conf.5 drbd.8 datadisk.8 drbdadm.8
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i man; done	

HOWTO/index.html: HOWTO/DRBD-HOWTO.sgml
	cd HOWTO ; $(DB2HTML) DRBD-HOWTO.sgml ; cd ..

install: drbdsetup.8 drbd.conf.5 drbd.8 datadisk.8
	install -d $(PREFIX)usr/share/man/man8
	install -m 644 drbdsetup.8 $(PREFIX)usr/share/man/man8
	install -d $(PREFIX)usr/share/man/man5
	install -m 644 drbd.conf.5 $(PREFIX)usr/share/man/man5
	install -d $(PREFIX)usr/share/man/man8
	install -m 644 drbd.8 $(PREFIX)usr/share/man/man8
	install -d $(PREFIX)usr/share/man/man8
	install -m 644 datadisk.8 $(PREFIX)usr/share/man/man8
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i install; done

uninstall:
	rm $(PREFIX)usr/share/man/man8/drbdsetup.8
	rm $(PREFIX)usr/share/man/man5/drbd.conf.5
	rm $(PREFIX)usr/share/man/man8/drbd.8
	rm $(PREFIX)usr/share/man/man8/datadisk.8
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i uninstall; done

html:	prepare $(shell ls *.sgml | sed s/sgml/html/g)	
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i html; done	
pdf:	prepare $(shell ls *.sgml | sed s/sgml/pdf/g)
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i pdf; done	
ps:	prepare $(shell ls *.sgml | sed s/sgml/ps/g)
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i ps; done	
