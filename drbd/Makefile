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

doc:
	$(MAKE) -C documentation doc

install:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

clean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~
	rm -rf dist

distclean:
	@ set -e; for i in $(ALLSUBDIRS); do $(MAKE) -C $$i distclean; done
	rm -f *~
	rm -rf dist
	

uninstall:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall; done

check_changelogs_up2date:
	@ up2date=true; \
	if ! grep "^Version: $(REL_VERSION)" >/dev/null 2>&1 drbd.spec; \
	then \
	   echo "You need to update the Version: tag in drbd.spec"; \
	   up2date=false; fi; \
	if ! sed -e '0,/^%changelog/d' drbd.spec \
	   | grep "^- drbd ($(REL_VERSION)-" >/dev/null 2>&1 ; \
	then \
	   echo "You need to update the %changelog in drbd.spec"; \
	   up2date=false; fi; \
	if ! grep "^drbd ($(REL_VERSION)-" >/dev/null 2>&1 debian/changelog; \
	then \
	   echo "You need to update debian/changelog"; \
	   up2date=false; fi ; \
	if ! grep "^drbd_$(REL_VERSION)-" >/dev/null 2>&1 debian/files; \
	then \
	   echo "You need to update debian/files"; \
	   up2date=false; fi ; \
	$$up2date

# maybe use a positive list intstead of exclude patterns?
#tgz: check_changelogs_up2date
tgz:
	cd scripts; ln -sf drbd datadisk
	rm -f drbd-$(REL_VERSION)
	ln -s . drbd-$(REL_VERSION)
	tar -czvf drbd-$(REL_VERSION).tar.gz \
	--exclude drbd-$(REL_VERSION)/drbd-$(REL_VERSION) \
	--exclude "*.o"  --exclude CVS --exclude ".*" \
	--exclude "*~"  --exclude "*.tar.gz" \
	--exclude drbdsetup --exclude dm --exclude config \
	--exclude "report*" drbd-$(REL_VERSION)/*
	rm drbd-$(REL_VERSION)

# maybe dist/RPMS/$(ARCH) instead of i386 ?
rpm: tgz
	mkdir -p dist/BUILD \
	         dist/RPMS/i386 \
	         dist/SPECS \
	         dist/SOURCES \
	         dist/install \
	         dist/SRPMS
	[ -h dist/SOURCES/drbd-$(REL_VERSION).tar.gz ] || \
	  $(LN_S) $(PWD)/drbd-$(REL_VERSION).tar.gz \
	          $(PWD)/dist/SOURCES/drbd-$(REL_VERSION).tar.gz
	[ -f dist/SPECS/drbd.spec ] || \
	  sed -e 's/^\(Packager:\).*/\1 ${USER}@${HOSTNAME}/;' drbd.spec \
	  > dist/SPECS/drbd.spec
	$(RPMBUILD) -bb \
	    --define "buildroot $(PWD)/dist/install" \
	    --define "_topdir $(PWD)/dist" \
	    $(PWD)/dist/SPECS/drbd.spec
