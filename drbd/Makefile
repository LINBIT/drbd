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

ifneq ($(KERNELRELEASE),)
  ifneq ($(VERSION),2)
    $(error "won't compile with this kernel version")
  endif
  ifeq ($(findstring $(PATCHLEVEL),46),$(PATCHLEVEL))
    include $(DRBDSRC)/Makefile-2.$(PATCHLEVEL)
  else
    $(error "won't compile with this kernel version")
  endif

  override CFLAGS += -I$(DRBDSRC)
  # remember KERNELRELEASE for install target
  # .kernelversion can be included in Makefile as well as
  # sourced from shell
  $(shell echo -e "VERSION=$(VERSION)\n"             \
                  "PATCHLEVEL=$(PATCHLEVEL)\n"       \
                  "SUBLEVEL=$(SUBLEVEL)\n"           \
                  "EXTRAVERSION=$(EXTRAVERSION)\n"   \
                  "KERNELRELEASE=$(KERNELRELEASE)" \
          > $(DRBDSRC)/.kernelrelease.new \
   )
else
  # called from command line in current directory
  DRBDSRC := $(shell pwd)
  CONFIG_BLK_DEV_DRBD := m
  export DRBDSRC CONFIG_BLK_DEV_DRBD

  KDIR_Makefile_PATCHLEVEL = $(shell grep "^PATCHLEVEL = " $(KDIR)/Makefile | cut -d " " -f 3)

  # to be overridden on command line:
  PREFIX := /
  ifeq ($(wildcard ../build-for-uml),../build-for-uml)
    #### for Philipp's convenience :) 
    ARCH_UM := "ARCH=um"
    KDIR := /usr/src/linux-um
  else
    KDIR := /lib/modules/$(shell uname -r)/build
  endif

  # shell ls, because some of them may be missing
  # inside a patched kernel source tree
  SRC_FILES := $(shell ls 2>/dev/null\
	linux/drbd_config.h linux/drbd.h drbd_actlog.c drbd_bitmap.c drbd_fs.c \
	drbd_main.c drbd_proc.c drbd_receiver.c drbd_req.c drbd_worker.c \
	lru_cache.c drbd_compat_types.h drbd_compat_wrappers.h drbd_int.h \
	lru_cache.h hlist.h mempool-2.4.c mempool.h)

  .PHONY: drbd.o default all greeting clean kbuild install dep

  drbd.o: greeting kbuild
  default: drbd.o
  all:     drbd.o

  greeting:
	@echo "" ;\
	echo "    Calling toplevel makefile of kernel source tree, which I believe is in" ;\
	echo "    KDIR=$(KDIR)" ; \
	echo ""

  drbd_buildtag.c: $(SRC_FILES)
	@if grep ^drbd/drbd_buildtag.c: ../Makefile &>/dev/null; then \
	  $(MAKE) -C .. drbd/drbd_buildtag.c ;\
	 else \
	  echo "drbd_buildtag.c outdated." ;\
	  echo "you probably need to do a 'make' in DRBDs toplevel directory.";\
	  false ;\
	 fi

  kbuild: drbd_buildtag.c
	@rm -f .kernelrelease*
	-test -f ../scripts/adjust_drbd_config_h.sh && \
	 KDIR=$(KDIR) $(SHELL) ../scripts/adjust_drbd_config_h.sh
  ifeq ($(KDIR_Makefile_PATCHLEVEL),4)
	$(MAKE) -C $(KDIR) SUBDIRS=$(DRBDSRC) $(ARCH_UM) modules
  else
    # since 2.6.6 (suse: 2.6.5-dunno), this should be:
    # $(MAKE) -C $(KDIR) M=$(DRBDSRC) $(ARCH_UM) modules
	$(MAKE) -C $(KDIR) SUBDIRS=$(DRBDSRC) $(ARCH_UM) modules
  endif
	@mv .kernelrelease.new .kernelrelease
	@echo -n "Memorizing module configuration ... "
	@{ echo -e "#\n# drbd.o was compiled with"          ; \
	  echo "#  `gcc -v 2>&1 | tail -1`"                 ; \
	  echo "# against this kernelrelease:"              ; \
	  sed 's/^/#  /' .kernelrelease                     ; \
          echo    "# kernel .config from"                   ; \
	  echo -n "#  $(KDIR)/.config"                      ; \
          test -L "$(KDIR)" && echo "	alias"   &&           \
	  echo "#  $$(readlink $(KDIR))/.config" || echo "" ; \
	  echo -e "# follows\n#\n"                             ; \
	  cat $(KDIR)/.config ; } | gzip > .kernel.config.gz
	@echo "done."

  ifneq ($(KDIR_Makefile_PATCHLEVEL),6)
    # obsolete in 2.6 ...
    dep:
	@echo "trying to make dep ..."
	@$(MAKE) -s -C $(KDIR) SUBDIRS=$(DRBDSRC) $(ARCH_UM) dep || \
         echo "I'll ignore this error, but this can cause inconsistencies!"

    kbuild: dep
  endif

  clean:
	rm -f *.[oas] *.ko .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernel*

  distclean: clean

  ifneq ($(wildcard .kernelrelease),)
    # for VERSION, PATCHLEVEL, SUBLEVEL, EXTRAVERSION, KERNELRELEASE
    include .kernelrelease
    MODOBJ-4 := drbd.o
    MODOBJ-6 := drbd.ko
    MODOBJ   := $(MODOBJ-$(PATCHLEVEL))
    MODSUBDIR := $(strip \
      $(if $(wildcard /lib/modules/$(KERNELRELEASE)/kernel),\
           kernel/drivers/block,\
           block))
    LINUX := $(wildcard /lib/modules/$(KERNELRELEASE)/build)

    install:
	@if ! [ -e $(MODOBJ) ] ; then \
	  echo "No $(MODOBJ): nothing to install??"; false ; \
	fi
# install -d $(PREFIX)/var/lib/drbd
	install -d $(PREFIX)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
	install -m 644 $(MODOBJ) $(PREFIX)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
    ifeq ($(shell uname -r),$(KERNELRELEASE))
	/sbin/depmod -a || /sbin/depmod -e $(MODOBJ) 2>&1 >/dev/null || true
    else
	[ -e $(LINUX)/System.map ] && \
	   /sbin/depmod -F $(LINUX)/System.map -e ./$(MODOBJ) 2>&1 >/dev/null || true
    endif
  else
    install:
	@echo "No .kernelrelease found. Do you need to 'make' the module first?"
	@false
  endif

  depmod:
	[ -e $(KDIR)/System.map ] && [ -e ./$(MODOBJ) ] && \
	   /sbin/depmod -F $(KDIR)/System.map -n -e ./$(MODOBJ) # 2>&1 >/dev/null
endif
