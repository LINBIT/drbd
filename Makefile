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

SUBDIRS     = user scripts benchmark documentation drbd #testing
ALLSUBDIRS  = user scripts benchmark documentation drbd testing

REL_VERSION := $(shell sed -ne '/REL_VERSION/{s/^.*"\(.*\) svn .*/\1/;p;q;}' drbd/linux/drbd_config.h)
ifdef FORCE
#
# NOTE to generate a tgz even if too lazy to update the changelogs,
# or to forcefully include the svn-last-changed-date in the tgz name:
#   make distclean doc tgz FORCE=1
#
REL_VERSION := $(REL_VERSION)-$(shell svn info| \
		  sed -ne 's/^Last Changed Date: \([0-9]*\)-\([0-9]*\)-\([0-9]*\).*/\1\2\3/p')
endif

DIST_VERSION := $(subst -,_,$(REL_VERSION))

LN_S = ln -s
RPMBUILD=rpmbuild

all:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i ; done
	@ echo -e "\n\tBuild successful."

tools:
	@ set -e; for i in $(patsubst drbd,,$(SUBDIRS)); do $(MAKE) -C $$i ; done
	@ echo -e "\n\tBuild successful."

doc:
	$(MAKE) -C documentation doc

doc-clean:
	$(MAKE) -C documentation doc-clean

install:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i install; done

install-tools:
	@ set -e; for i in $(patsubst drbd,,$(SUBDIRS)); do $(MAKE) -C $$i install; done

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

check_changelogs_up2date:
	@ up2date=true; dver_re=$(DIST_VERSION); dver_re=$${dver_re//./\\.}; \
	echo "checking for presence of $$dver_re in various changelog files"; \
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
	$$up2date

# update of .filelist is forced:
.PHONY: .filelist

.filelist:
	@ svn info >/dev/null || { echo "you need a svn checkout to do this." ; false ; }
	@find $$(svn st -v | sed '/^?/d;s/^.\{8\} \+[0-9]\+ \+[0-9]\+ [a-z]\+ *//;') \
	\! -type d -maxdepth 0 |\
	sed 's:^:drbd-$(DIST_VERSION)/:' > .filelist
	@[ -s .filelist ] # assert there is something in .filelist now
	@find documentation -name "[^.]*.[58]" -o -name "*.html" | \
	sed "s/^/drbd-$(DIST_VERSION)\//" >> .filelist           ;\
	echo drbd-$(DIST_VERSION)/drbd_config.h >> .filelist     ;\
	echo drbd-$(DIST_VERSION)/.filelist >> .filelist         ;\
	for d in documentation/{ja,pt_BR}; do test -e $$d/Makefile && echo drbd-$(DIST_VERSION)/$$d/Makefile >> .filelist ; done
	@echo "./.filelist updated."

update.filelist.cvs:
	cvs status | grep -o "/drbd/drbd/[^,]*" |                 \
	sed "s/Attic\///;                                         \
	     s/\/drbd\/drbd/drbd-$(DIST_VERSION)/;" > .filelist  ;\
	[ -s .filelist ] # assert there is something in .filelist now
	find documentation -name "[^.]*.[58]" -o -name "*.html" | \
	sed "s/^/drbd-$(DIST_VERSION)\//" >> .filelist           ;\
	echo drbd-$(DIST_VERSION)/drbd_config.h >> .filelist     ;\
	echo drbd-$(DIST_VERSION)/.filelist >> .filelist         ;\
	for d in documentation/{ja,pt_BR}; do test -e $$d/Makefile && echo drbd-$(DIST_VERSION)/$$d/Makefile >> .filelist ; done

tgz: .filelist
	ln -sf drbd/linux/drbd_config.h drbd_config.h
	rm -f drbd-$(DIST_VERSION)
	ln -s . drbd-$(DIST_VERSION)
	set -e ; for f in $$(<.filelist) ; do [ -e $$f ] ; done
	tar --owner=0 --group=0 -czf drbd-$(DIST_VERSION).tar.gz -T .filelist
	rm drbd-$(DIST_VERSION)

ifeq ($(FORCE),)
tgz: check_changelogs_up2date doc
endif

tarball: distclean doc tgz

KDIR := $(shell echo /lib/modules/`uname -r`/build)
KVER := $(shell \
	echo -e "\#include <linux/version.h>\ndrbd_kernel_release UTS_RELEASE" | \
        gcc -nostdinc -E -P -I$(KDIR)/include - 2>&1 | \
        sed -ne 's/^drbd_kernel_release "\(.*\)".*/\1/p')

kernel-patch:
	set -o errexit; \
	kbase=$$(basename $(KDIR)); \
	d=patch-$$kbase-drbd-$(DIST_VERSION); \
	test -e $$d && cp -fav --backup=numbered $$d $$d; \
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


# the INSTALL file is writen in lge-markup, which is basically
# wiki style plus some "conventions" :)
# why don't I write in or convert to HTML directly?
# editing INSTALL feels more natural this way ...

INSTALL.html: INSTALL.pod
	-pod2html --title "Howto Build and Install DRBD" \
		< INSTALL.pod > INSTALL.html ; rm -f pod2htm*
#	-w3m -T text/html -dump < INSTALL.html > INSTALL.txt

INSTALL.pod: INSTALL
	-@perl -pe 'BEGIN { print "=pod\n\n"; };                  \
	 	s/^= +(.*?) +=$$/=head1 $$1/;                     \
	 	s/^== +(.*?) +==$$/=head2 $$1/;                   \
		s/^(Last modi)/ $$1/ and next;                    \
	 	if(s/^ +([^#]*)$$/$$1/ or /^\S/) {                \
			s/(Note:)/B<$$1>/g;                       \
			s/"([^"]+)"/C<$$1>/g;                     \
	 		s,((^|[. ])/(`[^`]*`|\S)+),C<$$1>,g;      \
	 	}' \
	 	< INSTALL > INSTALL.pod
