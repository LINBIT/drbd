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

#PREFIX      = /usr/local

SUBDIRS     = user drbd scripts benchmark documentation #testing
ALLSUBDIRS  = user drbd scripts benchmark documentation testing
REL_VERSION = $(word 3, $(shell grep REL_VERSION drbd/linux/drbd_config.h))

LN_S = ln -s
RPMBUILD=rpmbuild

all:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i ; done
	@ echo -e "\n\tBuild successful."

doc:
	$(MAKE) -C documentation doc

doc-clean:
	$(MAKE) -C documentation doc-clean

install:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

clean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~
	rm -rf dist

distclean:
	@ set -e; for i in $(ALLSUBDIRS); do $(MAKE) -C $$i distclean; done
	rm -f *~ .filelist
	rm -rf dist

uninstall:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall; done

DIST_VERSION=$(subst -,_,$(REL_VERSION))
check_changelogs_up2date:
	@ up2date=true; dver_re=$(DIST_VERSION); dver_re=$${dver_re//./\\.}; \
	in_changelog=$$(sed -n -e '0,/^%changelog/d' \
	                     -e '/^- *drbd ('"$$dver_re"'-/p' \
	                     -e '/^\*.* \['"$$dver_re"'-/p' < drbd.spec.in) ; \
	if test -z "$$in_changelog" ; \
	then \
	   echo "You need to update the %changelog in drbd.spec.in"; \
	   up2date=false; fi; \
	if ! grep "^drbd ($$dver_re-" >/dev/null 2>&1 debian/changelog; \
	then \
	   echo "You need to update debian/changelog"; \
	   up2date=false; fi ; \
	if ! grep "^drbd_$$dver_re-" >/dev/null 2>&1 debian/files; \
	then \
	   echo "You need to update debian/files"; \
	   up2date=false; fi ; \
	$$up2date

update.filelist:
	cvs status | grep -o "/drbd/drbd/[^,]*" | \
	sed "s/Attic\///;                  \
	     s/\/drbd\/drbd/drbd-$(DIST_VERSION)/;" > .filelist
	find documentation -name "[^.]*.[58]" -o -name "*.html" | \
	sed "s/^/drbd-$(DIST_VERSION)\//" >> .filelist
	echo drbd-$(DIST_VERSION)/drbd_config.h >> .filelist
	echo drbd-$(DIST_VERSION)/.filelist >> .filelist

.filelist:
	@ echo -e "\nto create the filelist:   make update.filelist\nyou need cvs access, though.\n"
	@ false

tgz: .filelist
	ln -sf drbd/linux/drbd_config.h drbd_config.h
	rm -f drbd-$(DIST_VERSION)
	ln -s . drbd-$(DIST_VERSION)
	tar --owner=0 --group=0 -czf drbd-$(DIST_VERSION).tar.gz -T .filelist
	rm drbd-$(DIST_VERSION)

ifeq ($(FORCE),)
tgz: check_changelogs_up2date doc
endif

KDIR := $(shell echo /lib/modules/`uname -r`/build)
KVER := $(shell \
	echo -e "\#include <linux/version.h>\ndrbd_kernel_release UTS_RELEASE" | \
        gcc -nostdinc -E -P -I$(KDIR)/include - 2>&1 | \
        sed -ne 's/^drbd_kernel_release "\(.*\)".*/\1/p')

kernel-patch:
	set -o noclobber; \
	d=patch-linux-$(KVER)-drbd-$(DIST_VERSION);\
	bash scripts/patch-kernel $(KDIR) . > $$d

# maybe even dist/RPMS/$(ARCH) ?
rpm: tgz
	mkdir -p dist/BUILD \
	         dist/RPMS  \
	         dist/SPECS \
	         dist/SOURCES \
	         dist/TMP \
	         dist/install \
	         dist/SRPMS
	[ -h dist/SOURCES/drbd-$(DIST_VERSION).tar.gz ] || \
	  $(LN_S) $(PWD)/drbd-$(DIST_VERSION).tar.gz \
	          $(PWD)/dist/SOURCES/drbd-$(DIST_VERSION).tar.gz
	if test drbd.spec.in -nt dist/SPECS/drbd.spec ; then \
	   sed -e "s/^\(Version:\).*/\1 $(DIST_VERSION)/;" \
	       -e "s/^\(Packager:\).*/\1 $(USER)@$(HOSTNAME)/;" < drbd.spec.in \
	   > dist/SPECS/drbd.spec ; \
	fi
	$(RPMBUILD) -ba \
	    --define "_topdir $(PWD)/dist" \
	    --define "buildroot $(PWD)/dist/install" \
	    --define "kernelversion $(KVER)" \
	    --define "kdir $(KDIR)" \
	    $(PWD)/dist/SPECS/drbd.spec
	@echo "You have now:" ; ls -l dist/*RPMS/*/*.rpm
