# Makefile for drbd
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

include Makefile.vars

all:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i all; done

install:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

clean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~

uninstall:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall; done

tgz:    
	tar -czvf drbd-$(VERSION).tar.gz \
	--exclude *.o  --exclude CVS \
	--exclude *~ --exclude .deps --exclude *.tar.gz \
	--exclude drbdsetup --exclude dm --exclude config \
        --exclude report* -C .. drbd
