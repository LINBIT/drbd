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

  # linux 2.6 style:
  obj-m     += drbd.o
  drbd-objs := drbd_fs.o drbd_main.o drbd_proc.o drbd_dsender.o \
               drbd_receiver.o drbd_req-2.4.o drbd_actlog.o \
	       lru_cache.o

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

  # rest is magic for KERNEL_VERSION < 2.6
  ifneq ($(findstring $(PATCHLEVEL),24),)
    # linux 2.2//2.4 style needs in addition:
    drbd-objs  += mempool-2.4.o 
    list-multi := drbd.o

    ifeq ($(PATCHLEVEL),2)
      # include $(SUBDIRS)/Rules-2.2.x.make
      # this rules file would extract the 2.2 variables
      # from the 2.4+ obj-[ynm] ones; but since the code
      # no longer compiles with 2.2.x: sorry!
      $(error "won't compile with a 2.2.x kernel")
    else
      include $(TOPDIR)/Rules.make
    endif

    drbd.o: $(drbd-objs)
	$(LD) -r -o $@ $(drbd-objs)

  else
  ifneq ($(PATCHLEVEL),6)
    # we only compile for [-2.2,-] 2.4 and 2.6. sorry.
    $(error "won't compile with this kernel version")
  endif
  endif
else
  # called from command line in current directory
  DRBDSRC := $(shell pwd)
  export DRBDSRC
  # to be overridden on command line:
  PREFIX := /
  ifeq ($(wildcard ../build-for-uml),../build-for-uml)
    #### for Philipp's convenience :) 
    ARCH_UM := "ARCH=um"
    KDIR := /usr/src/linux-um
  else
    KDIR := /lib/modules/$(shell uname -r)/build
  endif

  .PHONY: drbd.o default all greeting clean kbuild install dep

  drbd.o: greeting dep kbuild
  default: drbd.o
  all:     drbd.o

  greeting:
	@echo "" ;\
	echo "    Calling toplevel makefile of kernel source tree, which I believe is in" ;\
	echo "    KDIR=$(KDIR)" ;\
	echo "    NOTE: please ignore warnings regarding overriding of SUBDIRS" ;\
	echo ""

  kbuild:
	@rm -f .kernelrelease*
	$(MAKE) -C $(KDIR) SUBDIRS=$(DRBDSRC) $(ARCH_UM) modules
	@mv .kernelrelease.new .kernelrelease

  # obsolete in 2.6 ...
  dep:
	@echo "make dep ..."
	@$(MAKE) -s -C $(KDIR) SUBDIRS=$(DRBDSRC) $(ARCH_UM) dep
	@echo "done."

  clean:
	rm -f *.[oas] *.ko .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernelrelease

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
	install -d $(PREFIX)var/lib/drbd
	install -d $(PREFIX)lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
	install -m 644 $(MODOBJ) $(PREFIX)lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
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
	[ -e $(KDIR)/System.map ] && [ -e ./drbd.o ] && \
	   /sbin/depmod -F $(KDIR)/System.map -e ./drbd.o 2>&1 >/dev/null
endif
