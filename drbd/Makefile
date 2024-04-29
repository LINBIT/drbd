# makefile for drbd for linux 2.4 // 2.6
#
# By Lars Ellenberg.
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

# usage: make [ KDIR=/path/to/kernel/source ]
#
# this file is read twice:
# the first invocation calls out to the toplevel Makefile in the
# kernel source tree, which then in turn will call this file again
# as subdir Makefile, with all appropriate vars and macros set.
#
# note: if you get strange make errors when ARCH=um, you
# probably need to "make mrproper" in the KDIR first...

  Q := $(if $(V),,@)

current_build_symlink  := build-current
# We don't want a dangling symlink!
$(shell test -e $(current_build_symlink) || rm -f $(current_build_symlink) 2>/dev/null)

# The destination "root" directory. Meant to be overridden by
# packaging scripts.
DESTDIR ?= /

# Do not:
# o  use make's built-in rules and variables
#    (this increases performance and avoids hard-to-debug behaviour);
# o  print "Entering directory ...";
MAKEFLAGS += -rR --no-print-directory

# Use the SPAAS (spatch as a service) online service
# Have this as make variable for distributions.
SPAAS ?= true
SPAAS_URL ?= https://spaas.drbd.io
export SPAAS
export SPAAS_URL

# since 2.6.16, KERNELRELEASE may be empty,
# e.g. when building against some (broken?) linux-header package.
# Lets test on PATCHLEVEL, that won't change too soon...

ifdef PATCHLEVEL
 # suffifiently new kernel will include Kbuild directly
 ifneq ($(VERSION),3)
  ifneq ($(VERSION),2)
    $(error "won't compile with this kernel version")
  endif
  ifneq ($(PATCHLEVEL),6)
    $(error "won't compile with this kernel version")
  endif
 endif

  include $(src)/Kbuild

else
  # called from command line in current directory

#################################################################
install-target := $(filter install,$(MAKECMDGOALS))
non-install-targets := $(filter-out install,$(MAKECMDGOALS))
ifdef install-target
ifdef non-install-targets
   # mixed targets!
   # have to do one level of recursion :-(
   # If we "source" (shell level) or even "include" (make level)
   # the build-current/.drbd_kernelrelease,
   # things may get confusing with KERNELRELEASE or O not matching KDIR
   # (for example KDIR=/usr/src/linux-headers-6.1.0-18-amd64, but an
   #  earlier build now leaks:  KERNELRELEASE=6.1.0-17-amd64)
   # and subtly wrong compat.h / compat.patches generated.
   # Separate the install target into its own make invokation,
   # where it is then safe to just install whatever was built last.
   .PHONY: $(non-install-targets) $(install-target)
   $(non-install-targets):
	$(MAKE) -C $(CURDIR) $(non-install-targets)
   $(install-target): $(non-install-targets)
	$(MAKE) -C $(CURDIR) $(install-target)
else
  # "install" is the only goal this time.
  ifdef KDIR
    .PHONY: update-current-build-symlink
    install: update-current-build-symlink
    update-current-build-symlink:
	$(MAKE) -C $(CURDIR)
  else
    current_build_drbd_kernelrelease := $(current_build_symlink)/.drbd_kernelrelease
    -include $(current_build_drbd_kernelrelease)
  endif
  ifdef KDIR
    MODSUBDIR=updates
    INSTALL_MOD_PATH ?=   $(DESTDIR)
    INSTALL_MOD_DIR  ?= $(MODSUBDIR)
    export INSTALL_MOD_PATH INSTALL_MOD_DIR
    .PHONY: install
    # Use KDIR modules_install target, if available.
    # Otherwise, just copy over the .ko files.
    # Logic not completely in the recipe,
    # because recipes containing $(MAKE) are slightly special.
    install:
    ifneq ($(wildcard $(KDIR)),)
	test -d $(current_build_symlink) # assert that thing exists
	$(MAKE) -C $(KDIR) $(if $(O),O=$(O)) $(if $(V),V=$(V))	\
		M=$(CURDIR)/$(current_build_symlink)		\
		modules_install
    else
	cd $(current_build_symlink) && find -name "*.ko" |	\
	cpio -puvmd $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(INSTALL_MOD_DIR)/
    endif
  else
    $(error No KDIR in $(current_build_drbd_kernelrelease) found. Do you need to 'make' the module first?)
  endif
endif
else
#################################################################

  # for some reason some of the commands below only work correctly in bash,
  # and not in e.g. dash. I'm too lazy to fix it to be compatible.
  SHELL=/bin/bash

  DRBDSRC := $(shell pwd)

  ifneq ($(wildcard ../build-for-uml),)
    #### for Philipp's convenience :)
    ARCH_UM := "ARCH=um"
    KDIR := /usr/src/linux-um
  else
    ifeq ($(wildcard /lib/modules/$(shell uname -r)/source),)
      KDIR := /lib/modules/$(shell uname -r)/build
    else
      KDIR := /lib/modules/$(shell uname -r)/source
      ifneq ("$(origin KDIR)", "command line")
        ifneq ($(wildcard /lib/modules/$(shell uname -r)/build),)
          O := /lib/modules/$(shell uname -r)/build
        endif
      endif
    endif
  endif

  .PHONY: drbd.o default all greeting clean kbuild install tags cscope
  .PHONY: prep compat spatch report distclean mrproper
  .PHONY: compat.h

  drbd.o: greeting kbuild report
  default: drbd.o
  all:     drbd.o

  export KDIR O V
  # shorten kbuild invocations
  KBUILD = \
	-C $(if $(KDIR),$(KDIR),$(error missing KDIR)) \
	$(if $(V),V=$(V)) $(if $(O),O=$(O)) $(ARCH_UM)

  greeting:
	$(Q)echo "" ;\
	echo "    Calling toplevel makefile of kernel source tree, which I believe is in" ;\
	echo "    KDIR=$(KDIR)" ; \
	echo "";
	$(Q)if ! test -e $(KDIR)/Makefile ; then \
		echo -e "    SORRY, kernel makefile not found. You need to tell me a correct KDIR!\n" ;\
		false;\
	fi

  # compat.h is built by Kbuild; I think the most easy way to trigger that
  # without trying to re-implement all the Kbuild magic badly, is to simply
  # tell it to compile our smallest, least complex .c file which still
  # has a dependency on our compat.h
  # Old kernel trees need a C file present to even read our Kbuild file.
  # To avoid .ko generation and the rest of the modpost step, pretend to be a
  # module with two object files, but ask to generate only one part now.
  compat.h:
	$(Q)> dummy-for-compat-h.c
	$(MAKE) $(KBUILD) M=$(DRBDSRC) obj-m=dummy-for-compat.o dummy-for-compat-h.o

  # same trick to only "patch"
  prep: compat.h fix-tar-timestamps
	$(Q)diff -u /dev/null /dev/null || { echo >&2 'please install `diffutils`'; exit 127; }
	$(Q)patch -p0 </dev/null        || { echo >&2 'please install `patch`'; exit 127; }
	$(Q)perl -e1                    || { echo >&2 'please install `perl`'; exit 127; }
	$(Q)> dummy-for-patch.c
	$(MAKE) $(KBUILD) M=$(DRBDSRC) obj-m=dummy-for-prep.o dummy-for-patch.o

  # build the module(s) in the prep'd build directory
  kbuild: prep
	test -e $(current_build_symlink) && \
	$(MAKE) $(KBUILD) M=$(CURDIR)/$(current_build_symlink) modules

  # could also use "find"; whatever.
  expected-modules = $(patsubst \
		./$(current_build_symlink)/%,%,$(wildcard \
		./$(current_build_symlink)/*.ko))

  report: kbuild
	$(Q)-set -e; . $(current_build_symlink)/.drbd_kernelrelease; \
	printf ".%70s.\n" "" | tr ' ' '=';		\
	printf "#  %-66s  #\n"				\
		KDIR=$$KDIR 				\
		$${O:+O=$$O}				\
		KERNELVERSION=$$KERNELVERSION		\
		KERNELRELEASE=$$KERNELRELEASE		\
		""					\
		$(realpath $(current_build_symlink))/;	\
	printf "#    %-64s  #\n"			\
		$(expected-modules);			\
	printf "'%70s'\n" "" | tr ' ' '='

  # clean _inside_ the current build directory only
  # don't remove it yet, and don't remove too much,
  # some CI pipelines expect to collect results.
  clean-rf := .tmp_versions Module.markers Module.symvers modules.order
  clean-rf += .compat_test.* .cache.mk

  _clean-f  := *.[oas] *.ko .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernel*
  clean-f  := $(_clean-f)
  clean-f  += $(addprefix drbd-kernel-compat/,$(_clean-f))
  clean-f  += drbd-kernel-compat/compat.patch drbd-kernel-compat/.compat.cocci
  clean-f  += .tmp_[0-9]*
  clean:
	rm -rf $(addprefix $(current_build_symlink)/,$(clean-rf))
	rm -f $(addprefix $(current_build_symlink)/,$(clean-f))
	rm -f dummy-for-compat-h.c dummy-for-patch.c

  # in addition clean all build-*
  distclean: clean
	$(Q)rm $(if $(V),-v) -rf build-* compat.*.h compat.*.patch .compat_test.* tags cscope.out
	rm -f .timestamps_fixed

  # in addition clean the cocci_cache
  mrproper: distclean
	$(Q)rm $(if $(V),-v) -rf drbd-kernel-compat/cocci_cache

  tags:
	git ls-files --recurse | ctags -I__must_hold -L -

  cscope:
	git ls-files --recurse | cscope -b -i -

  compat_headers := $(wildcard drbd-kernel-compat/cocci_cache/*/compat.h)
  compat_patches := $(patsubst %.h,%.patch,$(compat_headers))
  current_compat_patch := $(current_build_symlink)/compat.patch
  $(current_compat_patch) $(compat_patches): FORCE
	$(MAKE) -f Makefile.spatch $@

  # re-generate compat.patch for all compat.h in cocci cache:
  compat: $(compat_patches)

  # re-generate compat.patch for the latest build only:
  cached_compat_patch := $(patsubst $(realpath $(CURDIR))/%,%,$(realpath $(wildcard $(current_compat_patch))))
  spatch: $(firstword $(cached_compat_patch) $(current_compat_patch))
	$(Q)echo $(if $<,$<,$(error No $(current_build_symlink)/compat.patch found; build it first. Or try make compat))

.PHONY: fix-tar-timestamps
fix-tar-timestamps:
	$(Q)-test -e ../.git || test -e .timestamps_fixed || \
	touch drbd-kernel-compat/cocci_cache/*/compat.patch .timestamps_fixed

uninstall:

spell:
	for f in $(wildcard *.c); do \
	 	aspell --save-repl --dont-backup --personal=./../documentation/aspell.en.per check $$f; \
	done

endif # install / non-install recursion

.PHONY: FORCE
FORCE:

endif # Kbuild or command line
