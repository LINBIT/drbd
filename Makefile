# Makefile for drbd
#
# This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
#
# Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
# Copyright (C) 2001-2008, Philipp Reisner <philipp.reisner@linbit.com>.
# Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.
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
# along with drbd
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#

# TODO move some of the more cryptic bash scriptlets here into scripts/*
# and call those from here.	-- lge

# variables set by configure
GIT = git
LN_S = ln -s
RPMBUILD = rpmbuild

# default for KDIR/KVER
ifndef KVER
 ifndef KDIR
KVER = `uname -r`
KDIR = /lib/modules/$(KVER)/build
 else
KVER := $(shell make -s -C $(KDIR) kernelrelease)
 endif
endif
KDIR ?= /lib/modules/$(KVER)/build

# for some reason some of the commands below only work correctly in bash,
# and not in e.g. dash. I'm too lazy to fix it to be compatible.
SHELL=/bin/bash

SUBDIRS     = drbd

REL_VERSION := $(shell sed -ne '/^\#define REL_VERSION/{s/^[^"]*"\([^ "]*\).*/\1/;p;q;}' drbd/linux/drbd_config.h)
override GITHEAD := $(shell test -e .git && $(GIT) rev-parse HEAD)

ifdef FORCE
#
# NOTE to generate a tgz even if too lazy to update the changelogs,
# or to forcefully include the FIXME to be done: latest change date;
# for now, include the git hash of the latest commit
# in the tgz name:
#   make distclean tgz FORCE=1
#
REL_VERSION := $(REL_VERSION)-$(GITHEAD)
endif

DIST_VERSION := $(REL_VERSION)
ifeq ($(subst -,_,$(DIST_VERSION)),$(DIST_VERSION))
    DIST_VERSION := $(DIST_VERSION)-1
endif
FDIST_VERSION := $(shell test -s .filelist && sed -ne 's,^drbd-\([^/]*\)/.*,\1,p;q' < .filelist)
ifeq ($(FDIST_VERSION),)
FDIST_VERSION := $(DIST_VERSION)
endif

all: tools module

.PHONY: all tools module
tools:
	@cat README.drbd-utils
doc:
	@echo "Man page sources moved to http://git.linbit.com/drbd-utils.git"

.PHONY: check-kdir
check-kdir:
	@if ! test -e $(KDIR)/Makefile ; then \
		echo "    SORRY, kernel makefile not found." ;\
	        echo "    You need to tell me a correct KDIR," ;\
	        echo "    Or install the neccessary kernel source packages." ;\
	        echo "" ;\
		false;\
	fi

.PHONY: module
module: check-kdir
	@ $(MAKE) -C drbd KVER=$(KVER) KDIR=$(KDIR)
	@ echo -e "\n\tModule build was successful."

install:
	$(MAKE) -C drbd install

clean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~

distclean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i distclean; done
	rm -f *~ .filelist

uninstall:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall; done

.PHONY: check check_changelogs_up2date install uninstall distclean clean
check check_changelogs_up2date:
	@ up2date=true; dver_re=$(DIST_VERSION); dver_re=$${dver_re//./\\.};	\
	dver=$${dver_re%[-~]*}; 						\
	drel="$${dver_re#"$$dver"}"; drel="$${drel#[-~]}"; 			\
	test -z "$$drel" && drel=1 && dver_re=$$dver_re"\(-1\| \|$$\)"; 	\
	echo "checking for presence of $$dver_re in various changelog files"; 	\
	for f in drbd-km.spec drbd-kernel.spec ; do 				\
	v=$$(sed -ne 's/^Version: //p' $$f); 					\
	r=$$(sed -ne 's/^Release: //p' $$f); 					\
	if ! printf "%s-%s" "$$v" "$$r" | grep -H --label $$f "$$dver_re\>"; then \
	   printf "\n\t%s Version/Release: tags need update\n" $$f; 		\
	   grep -Hn "^Version: " $$f ; 						\
	   up2date=false; fi ; 							\
	   in_changelog=$$(sed -n -e '0,/^%changelog/d' 			\
			     -e '/- '"$$dver_re"'\>/p' < $$f) ; 		\
	   if test -z "$$in_changelog" ; then 					\
	   printf "\n\t%%changelog in %s needs update\n" $$f; 			\
	   grep -Hn "^%changelog" $$f ; 					\
	   up2date=false; fi; 							\
	done ; 									\
	if ! grep -H "^\($$dver_re\|$$dver\) (api:" ChangeLog; 			\
	then 									\
	   printf "\nChangeLog:3:\tneeds update\n"; 				\
	   up2date=false; fi ; 							\
	if test -e debian/changelog 						\
	&& ! grep -H "^drbd8 (2:$$dver\(+linbit\)\?[-~]$$drel" debian/changelog; \
	then 									\
	   printf "\n\tdebian/changelog:1: needs update\n"; 			\
	   up2date=false; fi ; 							\
	$$up2date

.PHONY: drbd/.drbd_git_revision
ifdef GITHEAD
override GITDIFF := $(shell $(GIT) diff --name-only HEAD 2>/dev/null |	\
			tr -s '\t\n' '  ' |		\
			sed -e 's/^/ /;s/ *$$//')
drbd/.drbd_git_revision:
	@echo GIT-hash: $(GITHEAD)$(GITDIFF) > $@
else
drbd/.drbd_git_revision:
	@echo >&2 "Need a git checkout to regenerate $@"; test -s $@
endif

# update of .filelist is forced:
.PHONY: .filelist
.filelist:
	@$(GIT) ls-files | sed '$(if $(PRESERVE_DEBIAN),,/^debian/d);s#^#drbd-$(DIST_VERSION)/#' > .filelist
	@[ -s .filelist ] # assert there is something in .filelist now
	echo drbd-$(DIST_VERSION)/.filelist               >> .filelist ; \
	echo drbd-$(DIST_VERSION)/drbd/.drbd_git_revision >> .filelist ; \
	echo "./.filelist updated."

# tgz will no longer automatically update .filelist,
# so the tgz and therefore rpm target will work within
# an extracted tarball, too.
# to generate a distribution tarball, use make tarball,
# which will regenerate .filelist
tgz:
	test -s .filelist
	rm -f drbd-$(FDIST_VERSION)
	$(LN_S) . drbd-$(FDIST_VERSION)
	for f in $$(<.filelist) ; do [ -e $$f ] && continue ; echo missing: $$f ; exit 1; done
	grep debian .filelist >/dev/null 2>&1 && _DEB=-debian || _DEB="" ; \
	tar --owner=0 --group=0 -czf - -T .filelist > drbd-$(FDIST_VERSION)$$_DEB.tar.gz
	rm drbd-$(FDIST_VERSION)

ifeq ($(FORCE),)
tgz: check_changelogs_up2date
endif

check_all_committed:
	@$(if $(FORCE),-,)modified=`$(GIT) ls-files -m -t`; 		\
	if test -n "$$modified" ; then	\
		echo "$$modified";	\
	       	false;			\
	fi

prepare_release:
	$(MAKE) tarball
	$(MAKE) tarball PRESERVE_DEBIAN=1

tarball: check_all_committed distclean drbd/.drbd_git_revision .filelist
	$(MAKE) tgz

module .filelist: drbd/.drbd_git_revision

ifdef RPMBUILD

.PHONY: km-rpm
km-rpm: check-kdir tgz drbd-km.spec
	cp drbd-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bb \
	    --define "kernelversion $(KVER)" \
	    --define "kdir $(KDIR)" \
	    $(RPMOPT) \
	    drbd-km.spec
	@echo "You have now:" ; find `rpm -E "%_rpmdir"` -name *.rpm

# kernel module package using the system macros.
# result is kABI aware and uses the weak-updates mechanism.
# Only define %kernel_version, it it was set outside of this file,
# i.e. was inherited from environment, or set explicitly on command line.
# If unset, the macro will figure it out internally, and not depend on
# uname -r, which may be wrong in a chroot build environment.
.PHONY: kmp-rpm
kmp-rpm: tgz drbd-kernel.spec
	cp drbd-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bb \
	    $(if $(filter file,$(origin KVER)), --define "kernel_version $(KVER)") \
	    $(RPMOPT) \
	    drbd-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_rpmdir"` -name *.rpm

.PHONY: srpm
srpm: tgz
	cp drbd-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bs \
	    --define "kernelversion $(KVER)" \
	    --define "kernel_version $(KVER)" \
	    --define "kdir $(KDIR)" \
		$(RPMOPT) \
		drbd-km.spec drbd-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_srcrpmdir"` -name *.src.rpm
endif
