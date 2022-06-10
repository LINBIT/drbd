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

GIT = git
LN_S = ln -s
RPMBUILD = rpmbuild
DEBBUILD = debuild

DOCKERREGISTRY := drbd.io
ARCH ?= amd64
ifneq ($(strip $(ARCH)),)
DOCKERREGISTRY := $(DOCKERREGISTRY)/$(ARCH)
endif
DOCKERIMAGES = rhel7 rhel8 bionic focal sles15sp1 flatcar
DOCKERIMAGESTARGETS = $(addprefix dockerimage.,$(DOCKERIMAGES))

# Use the SPAAS (spatch as a service) online service
# Have this as make variable for distributions.
SPAAS ?= true
SPAAS_URL ?= https://drbd.io:2020

# default for KDIR/KVER
ifndef KVER
 ifndef KDIR
KVER = `uname -r`
KDIR = /lib/modules/$(KVER)/build
 else
# Aand sles is more special than rhel this time.
# Others may be even more special than those two :-/
# Try "kernelrelease" first, then try "kernelversion".
# If the magic does not work out for you,
# explicitly set both KVER and KDIR to matching values.
# M=... set to hopefully avoid write-permission problems
# during cc-option test and similar
KVER := $(shell (make -s -C $(KDIR) M=$(PWD)/drbd kernelrelease || make -s -C $(KDIR) M=$(PWD)/drbd kernelversion) | tail -n1)
ifeq ($(KVER),)
	$(error could not guess kernel version string from kernel sources at "$(KDIR)")
endif
 endif
endif
KDIR ?= /lib/modules/$(KVER)/build

# for some reason some of the commands below only work correctly in bash,
# and not in e.g. dash. I'm too lazy to fix it to be compatible.
SHELL=/bin/bash

SUBDIRS     = drbd

REL_VERSION := $(shell sed -ne '/^\#define REL_VERSION/{s/^[^"]*"\([^ "]*\).*/\1/;p;q;}' drbd/linux/drbd_config.h)
override GITHEAD := $(shell test -e .git && $(GIT) rev-parse HEAD)

# container image version tag. 'TAG', becasue we have this (too) generic name in other projects already
TAG ?= v$(REL_VERSION)

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
FDIST_VERSION := $(shell test -s .filelist && sed -ne 's,^drbd-\([^/]*\)/.*,\1,p;q' < .filelist)
ifeq ($(FDIST_VERSION),)
FDIST_VERSION := $(DIST_VERSION)
endif

all: module tools

.PHONY: all tools module
tools: | $(if $(filter module all,$(if $(MAKECMDGOALS),,all)),module)
	@cat README.drbd-utils
doc:
	@echo "Man page sources moved to https://github.com/LINBIT/drbd-utils/"

# we cannot use 'git submodule foreach':
# foreach only works if submodule already checked out
.PHONY: check-submods
check-submods:
	@if test -d .git && test -s .gitmodules; then \
		for d in `grep "^\[submodule" .gitmodules | cut -f2 -d'"'`; do \
			if [ ! "`ls -A $$d`" ]; then \
				git submodule init; \
				git submodule update; \
				break; \
			fi; \
		done; \
	fi

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
module: check-kdir check-submods
	@ $(MAKE) -C drbd KVER=$(KVER) KDIR=$(KDIR) SPAAS=$(SPAAS)
	@ echo -e "\n\tModule build was successful."

install:
	$(MAKE) -C drbd install

unpatch:
	$(MAKE) -C drbd unpatch

clean: unpatch
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~

distclean: unpatch
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i distclean; done
	rm -f *~ .filelist

uninstall:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i uninstall; done

.PHONY: check check_changelogs_up2date install uninstall distclean clean unpatch
check check_changelogs_up2date:
	@ up2date=true; dver=$(DIST_VERSION); dver=$${dver//./\\.};		\
	packagever=$${dver//-/"~"};						\
	echo "checking for presence of $$dver ($$packagever for packaging) in various changelog files"; \
	for f in drbd-kernel.spec ; do 						\
	v=$$(sed -ne 's/^Version: //p' $$f); 					\
	if ! printf "%s" "$$v" | grep -H --label $$f "$$packagever\>"; then	\
	   printf "\n\t%s Version: tags need update\n" $$f;			\
	   grep -Hn "^Version: " $$f ; 						\
	   up2date=false; fi ; 							\
	   in_changelog=$$(sed -n -e '0,/^%changelog/d' 			\
			     -e '/- '"$$packagever"'\>/p' < $$f) ;		\
	   if test -z "$$in_changelog" ; then 					\
	   printf "\n\t%%changelog in %s needs update\n" $$f; 			\
	   grep -Hn "^%changelog" $$f ; 					\
	   up2date=false; fi; 							\
	done ; 									\
	if ! grep -H "^$$dver (api:" ChangeLog;					\
	then									\
	   printf "\nChangeLog:3:\tneeds update\n"; 				\
	   up2date=false; fi ; 							\
	for df in 7 8 ; do							\
	if ! grep "^ENV DRBD_VERSION $$dver" docker/Dockerfile.rhel$$df ;	\
	then 									\
		printf "\nDockerfile.rhel$$df: needs update\n"; 		\
	   up2date=false; fi ; 							\
	done ;									\
	if test -e debian/changelog 						\
	&& ! grep -H "^drbd ($$packagever\(+linbit\)\?" debian/changelog;	\
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
	@set -e ; submodules=`$(GIT) submodule foreach --quiet 'echo $$path'`; \
	$(GIT) ls-files | \
	  grep -vxF -e "$$submodules" | \
	  grep -v "^\.gitlab" | \
	  sed '$(if $(PRESERVE_DEBIAN),,/^debian/d);s#^#drbd-$(DIST_VERSION)/#' | \
	  grep -v "gitignore\|gitmodules" > .filelist
	@$(GIT) submodule foreach --quiet 'git ls-files | sed -e "s,^,drbd-$(DIST_VERSION)/$$path/,"' | \
	  grep -v "gitignore\|gitmodules" >> .filelist
	@mkdir -p drbd/drbd-kernel-compat/cocci_cache/
	@find drbd/drbd-kernel-compat/cocci_cache/ -type f -not -path '*/\.*' | \
	 sed -e 's,^,drbd-$(DIST_VERSION)/,' >> .filelist
	@[ -s .filelist ] # assert there is something in .filelist now
	@echo drbd-$(DIST_VERSION)/.filelist               >> .filelist ; \
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
	tar --owner=0 --group=0 -czf - -T .filelist > drbd-$(FDIST_VERSION).tar.gz
	rm drbd-$(FDIST_VERSION)

ifeq ($(FORCE),)
tgz: check_changelogs_up2date
endif

check_all_committed: unpatch
	@$(if $(FORCE),-,)modified=`$(GIT) diff --name-status HEAD`; 	\
	if test -n "$$modified" ; then	\
		echo "$$modified";	\
	       	false;			\
	fi

.PHONY: prepare_release
prepare_release:
	$(MAKE) tarball

.PHONY: release
release:
	$(MAKE) tarball

.PHONY: debrelease
debrelease:
	cd drbd/drbd-kernel-compat && bash collect_compat_h.sh
	$(MAKE) -C drbd compat
	$(MAKE) tarball PRESERVE_DEBIAN=1

.PHONY: tarball
tarball:
	$(MAKE) distclean
	$(MAKE) check-submods check_all_committed drbd/.drbd_git_revision
	$(MAKE) .filelist
	$(MAKE) tgz

module .filelist: drbd/.drbd_git_revision

ifdef RPMBUILD

# kernel module package using the system macros.
# result is kABI aware and uses the weak-updates mechanism.
# Only define %kernel_version, it it was set outside of this file,
# i.e. was inherited from environment, or set explicitly on command line.
# If unset, the macro will figure it out internally, and not depend on
# uname -r, which may be wrong in a chroot build environment.
.PHONY: kmp-rpm
kmp-rpm: tgz drbd-kernel.spec
	cp drbd-$(FDIST_VERSION).tar.gz `rpm -E "%_sourcedir"`
	KVER=$(KVER); flavors=; \
	case $$KVER in *.debug) flavors=debug; KVER=$${KVER%.debug};; esac; \
	$(RPMBUILD) -bb \
	    $(if $(filter file,$(origin KVER)), --define "kernel_version $$KVER") \
	    $${flavors:+ --define "lb_flavors $$flavors"} \
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
		drbd-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_srcrpmdir"` -name *.src.rpm
endif

ifdef DEBBUILD
.PHONY: km-deb
km-deb: check-submods distclean drbd/.drbd_git_revision
	D=$$(mktemp -p . -d); 					\
	( git ls-files --recurse-submodules ;			\
	  echo drbd/.drbd_git_revision ) | cpio -pvmd "$$D" ;	\
	( cd "$$D" && $(DEBBUILD) -i -us -uc -b ) && rm -rf "$$D"
endif

dockerimage.%: FORCE
	cd docker && docker build -f Dockerfile.$* -t $(DOCKERREGISTRY)/drbd9-$*:$(TAG) $(EXTRA_DOCKER_BUILDARGS) .
	docker tag $(DOCKERREGISTRY)/drbd9-$*:$(TAG) $(DOCKERREGISTRY)/drbd9-$*:latest

.PHONY: dockerimage
dockerimage: $(DOCKERIMAGESTARGETS)

# make does not consider implicit rules for PHONY targets.
# This is used as an explicit dependency instead.
# .PHONY xyz.foo
# xyz.%:
# 	body
# does not work as one would expect, it actually makes things worse.
.PHONY: FORCE
FORCE:

# used for --sync in lbbuild to decide which containers to push to which registry
dockerpath:
	@for d in $(DOCKERIMAGES); do \
		repo="$(DOCKERREGISTRY)/drbd9-$${d}" ;\
		: trailing space in format string necessary to separate output! ;\
		printf "%s:%s %s:latest " "$$repo" "$(TAG)" "$$repo" ;\
	done

ifndef MODE
MODE = report
endif

.PHONY: coccicheck
coccicheck: coccinelle/*.cocci
	@for file in $^ ; do \
		echo "  COCCICHECK $$(basename $${file} .cocci)"; \
		spatch --very-quiet drbd/drbd_*.c -D $(MODE) --sp-file $${file}; \
	done

.PHONY: check-compat
check-compat:
	@echo "  COMPATCHECK";
	@spatch --very-quiet --no-show-diff -D report \
		drbd/drbd-kernel-compat/check_patch_names.cocci \
		drbd/drbd-kernel-compat/gen_patch_names.c

Makefile: ;
