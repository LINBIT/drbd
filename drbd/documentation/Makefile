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

.SUFFIXES: .sgml .5 .8

.sgml.5:
	if [ "$(DB2MAN)" ]; then $(DB2MAN) $< ; fi

.sgml.8:
	if [ "$(DB2MAN)" ]; then $(DB2MAN) $< ; fi

#######

all:	drbdsetup.8 drbd.conf.5 drbd.8 datadisk.8 HOWTO/index.html
	@ set -e; for i in $(LANGS); do ln -sf ../Makefile.lang $$i/Makefile ; $(MAKE) -C $$i all; done

HOWTO/index.html: HOWTO/DRBD-HOWTO.sgml
	if [ "$(DB2HTML)" ]; then cd HOWTO ; $(DB2HTML) DRBD-HOWTO.sgml ; cd .. ; fi

clean:
	rm -f *.ps *.[58] manpage.links manpage.refs *~ manpage.log HOWTO/*.html
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i clean ; done

install: drbdsetup.8 drbd.conf.5 drbd.8 datadisk.8
	if [ -e drbdsetup.8 ]; then install drbdsetup.8 $(PREFIX)usr/share/man/man8; fi
	if [ -e drbd.conf.5 ]; then install drbd.conf.5 $(PREFIX)usr/share/man/man5; fi
	if [ -e drbd.8 ]; then install drbd.8 $(PREFIX)usr/share/man/man8; fi
	if [ -e datadisk.8 ]; then install datadisk.8 $(PREFIX)usr/share/man/man8; fi
	@ set -e; for i in $(LANGS); do $(MAKE) -C $$i install; done



