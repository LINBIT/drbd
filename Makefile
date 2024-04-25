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
DOCKERIMAGES = rhel7 rhel8 rhel9 focal jammy noble flatcar amzn2
DOCKERIMAGESTARGETS = $(addprefix dockerimage.,$(DOCKERIMAGES))

# Use the SPAAS (spatch as a service) online service
# Have this as make variable for distributions.
SPAAS ?= true
SPAAS_URL ?= https://spaas.drbd.io

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
ifndef REL_VERSION
$(error corrupt drbd/linux/drbd_config.h)
endif
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
FDIST_VERSION := $(strip $(shell test -s .fdist_version && cat .fdist_version))
ifndef FDIST_VERSION
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
		echo "    SORRY, kernel makefile not found in '$(KDIR)'." ;\
	        echo "    You need to tell me a correct KDIR," ;\
	        echo "    Or install the neccessary kernel source packages." ;\
	        echo "" ;\
		false;\
	fi

.PHONY: module
module: check-kdir check-submods
	@ $(MAKE) -C drbd KVER=$(KVER) KDIR=$(KDIR) SPAAS=$(SPAAS) SPAAS_URL=$(SPAAS_URL)
	@ echo -e "\n\tModule build was successful."

install:
	$(MAKE) -C drbd install

clean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i clean; done
	rm -f *~ ; rm -rf tmp.km-deb.*

distclean:
	@ set -e; for i in $(SUBDIRS); do $(MAKE) -C $$i distclean; done
	rm -f *~ .filelist .fdist_version

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
	for df in 7 8 9 ; do							\
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

ifdef GITHEAD
override GITDIFF := $(shell $(GIT) diff --name-only HEAD 2>/dev/null |	\
			tr -s '\t\n' '  ' |		\
			sed -e 's/^/ /;s/ *$$//')
drbd/.drbd_git_revision: FORCE
	@echo GIT-hash: $(GITHEAD)$(GITDIFF) > $@
else
drbd/.drbd_git_revision: FORCE
	@echo >&2 "Need a git checkout to regenerate $@"; test -s $@
endif

export define SPDX_TEMPLATE
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: drbd kernel module SBOM (software bill of materials)
DocumentNamespace: https://linbit.org/spdx-docs/drbd-kmod-$(SPDX_VERSION)-$(SPDX_UUID)
Creator: Person: Philipp Reisner (philipp.reisner@linbit.com)
Created: $(SPDX_DATE)

PackageName: $(SPDX_PKG_NAME)
SPDXID: SPDXRef-Package-$(SPDX_PKG_NAME)
PackageVersion: $(SPDX_VERSION)
PackageSupplier: Organization: LINBIT HA-Solutions GmbH
PackageDownloadLocation: https://github.com/LINBIT/drbd
FilesAnalyzed: false
PackageLicenseDeclared: GPL-2.0-only
Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-$(SPDX_PKG_NAME)
endef

# only call this wrapper from drbd-kmod_{sles,rhel}.spdx
.PHONY: spdx-file
spdx-file:
	@echo "$$SPDX_TEMPLATE" > $(SPDX_FILE_TMP)

.PHONY: drbd-kmod_rhel.spdx drbd-kmod_sles.spdx
drbd-kmod_rhel.spdx drbd-kmod_sles.spdx:
	@set -e; ( truncate -s0 $@.tmp; \
		SPDX_DATE="$$(date --utc +%FT%TZ)"; \
		SPDX_UUID="$$(cat /proc/sys/kernel/random/uuid)"; \
		SPDX_VERSION="$(REL_VERSION)"; \
		case "$@" in \
			drbd-kmod_rhel.spdx) SPDX_PKG_NAME=kmod-drbd;; \
			drbd-kmod_sles.spdx) SPDX_PKG_NAME=drbd-kmp-default;; \
			*) false;; \
		esac; \
		test -n "$$SPDX_TEMPLATE"; \
		test -n "$$SPDX_DATE"; \
		test -n "$$SPDX_UUID"; \
		test -n "$$SPDX_VERSION"; \
		$(MAKE) spdx-file SPDX_UUID="$$SPDX_UUID" \
			SPDX_DATE="$$SPDX_DATE" \
			SPDX_FILE_TMP="$@.tmp" \
			SPDX_PKG_NAME="$$SPDX_PKG_NAME" \
			SPDX_VERSION="$$SPDX_VERSION"; \
		mv $@.tmp $@; )

# update of .filelist is forced:
.fdist_version: FORCE
	@test -s $@ && test "$$(cat $@)" = "$(FDIST_VERSION)" || echo "$(FDIST_VERSION)" > $@

.filelist: .fdist_version FORCE
	@$(GIT) ls-files --recurse -- ':!:.git*' $(if $(PRESERVE_DEBIAN),,':!:debian') > $@.new
	@mkdir -p drbd/drbd-kernel-compat/cocci_cache/
	@find drbd/drbd-kernel-compat/cocci_cache/ -type f -not -path '*/\.*' >> $@.new
	@test -s $@.new # assert there is something in .filelist.new now
	@mv $@.new $@
	@echo "./.filelist updated."

# tgz will no longer automatically update .filelist,
# so the tgz and therefore rpm target will work within
# an extracted tarball, too.
# to generate a distribution tarball, use make tarball,
# which will regenerate .filelist.
# If we tar up a clean working directory,
# add a pax-option comment recognizable by git get-tar-commit-id,
# even though this is not a git-archive.
comma := ,
backslash_comma := \,
escape_comma = $(subst $(comma),$(backslash_comma),$(1))
tgz-extra-files := \
	.fdist_version drbd/.drbd_git_revision .filelist \
	drbd-kmod_rhel.spdx drbd-kmod_sles.spdx
tgz:
	test -s .filelist          # .filelist must be present
	test -n "$(FDIST_VERSION)" # FDIST_VERSION must be known
	sed -i -e 's,^drbd-$(FDIST_VERSION)/,,' .filelist # drbd-<version>/ prefix no longer expected
	@for f in $(tgz-extra-files); do test -s $$f && continue; echo missing content: $$f ; exit 1; done; \
	for f in $$(<.filelist); do test -e $$f && continue; echo missing: $$f ; exit 1; done
	tar --owner=0 --group=0 -czf - \
		$(if $(GITHEAD),$(if $(GITDIFF),,--pax-option=comment=$(GITHEAD))) \
		$(tgz-extra-files) \
		-T .filelist \
		--transform 's,^,drbd-$(FDIST_VERSION)/,' \
		> drbd-$(FDIST_VERSION).tar.gz

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
	$(MAKE) drbd-kmod_rhel.spdx drbd-kmod_sles.spdx
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
	KVER=$(KVER); flavors=; \
	case $$KVER in *.debug) flavors=debug; KVER=$${KVER%.debug};; esac; \
	$(RPMBUILD) --define "_sourcedir $$PWD" -bb \
	    $(if $(filter file,$(origin KVER)), --define "kernel_version $$KVER") \
	    $${flavors:+ --define "lb_flavors $$flavors"} \
	    $(RPMOPT) \
	    drbd-kernel.spec
	@echo "You have now:" ; find `rpm -E "%_rpmdir"` -name *.rpm

.PHONY: srpm
srpm: tgz
	$(RPMBUILD) --define "_sourcedir $$PWD" -bs \
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
	D=$$(mktemp -p . -d tmp.km-deb.XXXXXXXXXX); 		\
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
