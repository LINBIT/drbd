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

ifeq ($(BUILD_OFED),1)
 OFED_KERNEL_DIR ?= $(firstword $(wildcard /usr/src/ofa_kernel/$(arch)/$(kernelver) /usr/src/ofa_kernel/default))
 ifneq ($(OFED_KERNEL_DIR),)
  OFED_CFLAGS := -I$(OFED_KERNEL_DIR)/include -include linux/compat-2.6.h
  OFED_MODULE_SYMVERS := $(OFED_KERNEL_DIR)/Module.symvers
  PRE_CFLAGS := $(OFED_CFLAGS)
 endif
 ifneq ($(shell test -e "$(OFED_KERNEL_DIR)/include/linux/compat-2.6.h" && test -e "$(OFED_MODULE_SYMVERS)" && echo ok),ok)
   $(error BUILD_OFED=1 set, but requirements not found)
 else
   $(info BUILDING FOR OFED:)
   $(info ==================)
   $(info : $(OFED_MODULE_SYMVERS))
   $(info : $(OFED_CFLAGS))
   $(info ===================================================================)

   # kernel has changed its way to deal with "additional symbols from other external modules" around here:
   # Linux 5.7-rc6
   # ce2ddd6d6ab3b (modpost: allow to pass -i option multiple times to remove -e option, 2020-06-01)
   # 52c3416db00d9 (modpost: track if the symbol origin is a dump file or ELF object, 2020-06-01)
   #
   # On older kernels,
   # adding more than one dump file to KBUILD_EXTRA_SYMBOLS breaks modpost,
   # but "accumulating" the external symbols in "our" Module.symvers works
   # (see cat ... > Module.symvers in the kbuild target below).
   #
   # On newer kernels,
   # accumulating like that is ineffective, but adding all external symbol
   # dump files to KBUILD_EXTRA_SYMBOLS is the way to go.
   #
   # For compat with a wide range of kernel versions, we keep doing both.
   #
   ifeq ($(KBUILD_EXTRA_SYMBOLS),)
     override KBUILD_EXTRA_SYMBOLS += $(OFED_MODULE_SYMVERS)
     export KBUILD_EXTRA_SYMBOLS
   else
     ifeq ($(filter $(OFED_MODULE_SYMVERS),$(KBUILD_EXTRA_SYMBOLS)),)
       $(warning KBUILD_EXTRA_SYMBOLS already set ($(KBUILD_EXTRA_SYMBOLS)), NOT adding $(OFED_MODULE_SYMVERS))
     endif
   endif

 endif
else
 ifneq ($(OFED_KERNEL_DIR)$(OFED_MODULE_SYMVERS)$(OFED_CFLAGS),)
  $(error "drop OFED_*, or set BUILD_OFED=1")
 endif
endif

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

ifneq ($(PATCHLEVEL),)
 # suffifiently new kernel will include Kbuild directly
 ifneq ($(VERSION),3)
  ifneq ($(VERSION),2)
    $(error "won't compile with this kernel version")
  endif
  ifneq ($(PATCHLEVEL),6)
    $(error "won't compile with this kernel version")
  endif
 endif

  CONFIG_BLK_DEV_DRBD := m

  include $(src)/Kbuild

else
  # called from command line in current directory

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

  .PHONY: drbd.o default all greeting clean kbuild install tags cscope unpatch compat

  drbd.o: greeting kbuild
  default: drbd.o
  all:     drbd.o

  greeting:
	@echo "" ;\
	echo "    Calling toplevel makefile of kernel source tree, which I believe is in" ;\
	echo "    KDIR=$(KDIR)" ; \
	echo "";
	@if ! test -e $(KDIR)/Makefile ; then \
		echo -e "    SORRY, kernel makefile not found. You need to tell me a correct KDIR!\n" ;\
		false;\
	fi

  unpatch:
	@if test -e .compat_patches_applied; then \
	    echo "Removing compat patches"; \
	    patch -R -p0 --batch --reject-file=- < .compat_patches_applied && \
	    rm -f .compat_patches_applied; \
	fi

  .PHONY: test-compile
  test-compile:
	$(MAKE)
	$(MAKE) unpatch

  # compat.h is built by Kbuild; I think the most easy way to trigger that
  # without trying to re-implement all the Kbuild magic badly, is to simply
  # tell it to compile our smallest, least complex .c file which still
  # has a dependency on our compat.h
  .PHONY: compat.h
  compat.h:
	@touch dummy-for-compat-h.c
	@mkdir .tmp_versions
	$(MAKE) -C $(KDIR)  $(if $(O),O=$(O),) M=$(DRBDSRC) $(ARCH_UM) "PRE_CFLAGS=$(PRE_CFLAGS)" \
		obj-m=dummy-for-compat-h.o dummy-for-compat-h.o

  kbuild: fix-tar-timestamps
	@rm -f .drbd_kernelrelease*
	cat /dev/null $(KBUILD_EXTRA_SYMBOLS) $(OFED_MODULE_SYMVERS) > Module.symvers
	$(MAKE) -C $(KDIR)  $(if $(O),O=$(O),) M=$(DRBDSRC) $(ARCH_UM) modules "PRE_CFLAGS=$(PRE_CFLAGS)"
	-mv .drbd_kernelrelease.new .drbd_kernelrelease
	@echo -n "Memorizing module configuration ... "
	@config=$$( (for x in $(KDIR)/.config $(O)/.config ; do \
	       if test -e $$x ; then echo $$x ; exit 0; fi ; \
	       done; echo $(KDIR)/.config) | sed -e 's,//,/,g') ; \
	{ echo -e "#\n# drbd.o was compiled with"          ; \
	  echo "#  `gcc -v 2>&1 | tail -1`"                 ; \
	  echo "# against this kernelrelease:"              ; \
	  sed 's/^/#  /' .drbd_kernelrelease                ; \
	  echo    "# kernel .config from"                   ; \
	  echo -n "#  $$config"                      ; \
	  test -L "$${config%/.config}" && echo "	alias"   &&           \
	  echo "#  $$(readlink $${config%/.config})/.config" || echo "" ; \
	  echo -e "# follows\n#\n"                          ; \
	  cat $$config ; } | gzip > .kernel.config.gz
	@echo "done."

  clean: unpatch
	rm -rf .tmp_versions Module.markers Module.symvers modules.order
	rm -f *.[oas] *.ko .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernel* *.mod
	rm -f drbd-kernel-compat/handshake/*.[oas] drbd-kernel-compat/handshake/*.ko drbd-kernel-compat/handshake/.*.cmd drbd-kernel-compat/handshake/.*.d drbd-kernel-compat/handshake/.*.tmp drbd-kernel-compat/handshake/*.mod.c drbd-kernel-compat/handshake/.*.flags drbd-kernel-compat/handshake/.depend drbd-kernel-compat/handshake/.kernel*
	rm -f dummy-for-compat-h.c
	rm -f drbd-kernel-compat/*.[oas] drbd-kernel-compat/.*.cmd
	rm -f drbd-kernel-compat/compat.patch drbd-kernel-compat/.compat.cocci
	rm -f .timestamps_fixed
	rm -rf .compat_test.* .cache.mk

  distclean: clean
	rm -f drbd_buildtag.c .config*.timestamp compat*.h

  tags:
	git ls-files --recurse | ctags -I__must_hold -L -

  cscope:
	git ls-files --recurse | cscope -b -i -


  compat_headers := $(wildcard drbd-kernel-compat/cocci_cache/*/compat.h)
  compat_patches := $(patsubst %.h,%.patch,$(compat_headers))

# files that are to be processed by coccinelle / spatch
include Makefile.cocci-sources

  $(compat_patches): $(sources)
	@. ./drbd-kernel-compat/gen_compat_patch.sh $@ $^

  compat: $(compat_patches)

  ifneq ($(wildcard .drbd_kernelrelease),)
    # for VERSION, PATCHLEVEL, SUBLEVEL, EXTRAVERSION, KERNELRELEASE
    include .drbd_kernelrelease
    MODOBJS := drbd.ko drbd_transport_tcp.ko drbd_transport_lb-tcp.ko drbd_transport_rdma.ko
    MODOBJS += $(wildcard drbd-kernel-compat/handshake/handshake.ko)
    MODSUBDIR := updates
    LINUX := $(wildcard /lib/modules/$(KERNELRELEASE)/build)

    install:
	@if ! [ -e $(MODOBJ) ] ; then \
	  echo "No $(MODOBJ): nothing to install??"; false ; \
	fi
	install -d $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
	set -e ; for ko in $(MODOBJS); do \
		install -m 644 $$ko $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR); \
	done
    ifeq ($(DESTDIR),/)
      ifeq ($(shell uname -r),$(KERNELRELEASE))
		/sbin/depmod -a || :
      else
		@echo "Don't forget to depmod."
      endif
    endif
  else
    install:
	@echo "No .drbd_kernelrelease found. Do you need to 'make' the module first?"
	@false
  endif
endif

.PHONY: fix-tar-timestamps
fix-tar-timestamps:
	@-test -e ../.git || test -e .timestamps_fixed || \
	touch drbd-kernel-compat/cocci_cache/*/compat.patch .timestamps_fixed

uninstall:

spell:
	for f in $(wildcard *.c); do \
	 	aspell --save-repl --dont-backup --personal=./../documentation/aspell.en.per check $$f; \
	done

