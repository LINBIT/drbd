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

include ../Makefile.vars

SPEC = $(shell for S in /usr/lib/perl5/sgmlspl-specs/docbook2man-spec.pl /usr/share/sgml/docbook/utils-0.6/helpers/docbook2man-spec.pl; do if [ -e $$S ]; then echo $$S; fi; done)
NSGMLS=$(shell which nsgmls)

all:	drbdsetup.8 drbd.conf.5

drbdsetup.8: drbdsetup.sgml
	if [ "$(NSGMLS)" ]; then nsgmls drbdsetup.sgml | sgmlspl $(SPEC); fi

drbd.conf.5: drbd.conf.sgml
	if [ "$(NSGMLS)" ]; then nsgmls drbd.conf.sgml | sgmlspl $(SPEC); fi

clean:
	rm -f drbdsetup.ps drbdsetup.8 drbd.conf.5 manpage.links manpage.refs *~ manpage.log

install: drbdsetup.8 drbd.conf.5
	if [ -e drbdsetup.8 ]; then install drbdsetup.8 $(PREFIX)usr/share/man/man8; fi
	if [ -e drbd.conf.5 ]; then install drbd.conf.5 $(PREFIX)usr/share/man/man5; fi
