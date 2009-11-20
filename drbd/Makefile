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

# The destination "root" directory. Meant to be overridden by
# packaging scripts.
DESTDIR ?= /

# since 2.6.16, KERNELRELEASE may be empty,
# e.g. when building agains some (broken?) linux-header package.
# Lets test on PATCHLEVEL, that won't change too soon...

ifneq ($(PATCHLEVEL),)
  ifneq ($(VERSION),2)
    $(error "won't compile with this kernel version")
  endif
  ifneq ($(PATCHLEVEL),6)
    $(error "won't compile with this kernel version")
  endif

  CONFIG_BLK_DEV_DRBD := m
  CONFIG_DRBD_TRACE := $(shell test $${SUBLEVEL} -ge 30 && echo m || echo n)

  include $(DRBDSRC)/Makefile-2.6

  override EXTRA_CFLAGS += -I$(DRBDSRC)
  # remember KERNELRELEASE for install target
  # .kernelversion can be included in Makefile as well as
  # sourced from shell
  $(shell echo -e "VERSION=$(VERSION)\n"             \
                  "PATCHLEVEL=$(PATCHLEVEL)\n"       \
                  "SUBLEVEL=$(SUBLEVEL)\n"           \
                  "EXTRAVERSION=$(EXTRAVERSION)\n"   \
                  "LOCALVERSION=$(LOCALVERSION)\n"   \
                  "KERNELRELEASE=$(KERNELRELEASE)\n" \
                  "KERNELVERSION=$(KERNELVERSION)"   \
          > $(DRBDSRC)/.drbd_kernelrelease.new       \
   )
else
  # called from command line in current directory

  # for some reason some of the commands below only work correctly in bash,
  # and not in e.g. dash. I'm too lazy to fix it to be compatible.
  SHELL=/bin/bash

  DRBDSRC := $(shell pwd)
  export DRBDSRC

  # to be overridden on command line:
  PREFIX := /
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

  KDIR_Makefile_PATCHLEVEL = $(shell test -e $(KDIR)/Makefile && grep "^PATCHLEVEL = " $(KDIR)/Makefile | cut -d " " -f 3)
  ifneq ($(findstring $(KDIR_Makefile_PATCHLEVEL),12345),)
    $(error "won't compile with this kernel version")
  endif

  .PHONY: drbd.o default all greeting clean kbuild install dep tags

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

.PHONY: drbd_buildtag.c

  drbd_buildtag.c:
	@is_tarball=`test -e ../.git/. && echo false || echo true`;\
	set -e; exec > $@.new;							\
	echo -e "/* automatically generated. DO NOT EDIT. */";			\
	echo -e "#include <linux/drbd.h>";					\
	echo -e "const char *drbd_buildtag(void)\n{";				\
	if $$is_tarball; then							\
	  if ! test -e $@ ; then 						\
	  	echo >&2 "your DRBD source tree is broken. unpack again.";	\
		exit 1;								\
	  fi;									\
	  grep return $@ ;							\
	else									\
	  GITHEAD=$$(git rev-parse HEAD);					\
	  GITDIFF=$$(cd .. && git diff --name-only HEAD | tr -s '\t\n' '  ' |	\
	  	sed -e 's/^/ /;s/ *$$//');					\
	  echo -e "\treturn \"GIT-hash: $$GITHEAD$$GITDIFF\"";	 		\
	fi ;									\
	echo -e "\t\t\" build by $$USER@$$HOSTNAME, `date "+%F %T"`\";\n}";	\
	mv --force $@.new $@

  kbuild: drbd_buildtag.c
	@rm -f .drbd_kernelrelease*
	-test -f ../scripts/adjust_drbd_config_h.sh && \
	 KDIR=$(KDIR) O=$(O) $(SHELL) ../scripts/adjust_drbd_config_h.sh
    # previous to 2.6.6 (suse: 2.6.5-dunno), this should be:
	$(MAKE) -C $(KDIR)  $(if $(O),O=$(O),) SUBDIRS=$(DRBDSRC) $(ARCH_UM) modules
# $(MAKE) -C $(KDIR) M=$(DRBDSRC) $(ARCH_UM) modules
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

  clean:
	rm -rf .tmp_versions
	rm -f *.[oas] *.ko .*.cmd .*.d .*.tmp *.mod.c .*.flags .depend .kernel*

  distclean: clean
	@if git show HEAD:drbd/linux/drbd_config.h > linux/drbd_config.h.tmp \
	&& ! diff -s -U0 linux/drbd_config.h.tmp linux/drbd_config.h ; then \
		mv linux/drbd_config.h.tmp linux/drbd_config.h ; \
	else \
		rm -f linux/drbd_config.h.tmp ; \
	fi

  tags:
	ctags -R -I__initdata,__exitdata,__acquires,__releases \
		-I __must_hold,__protected_by,__protected_read_by,__protected_write_by \
		-I BIO_ENDIO_ARGS

  ifneq ($(wildcard .drbd_kernelrelease),)
    # for VERSION, PATCHLEVEL, SUBLEVEL, EXTRAVERSION, KERNELRELEASE
    include .drbd_kernelrelease
    MODOBJ := drbd.ko
    MODSUBDIR := kernel/drivers/block
    LINUX := $(wildcard /lib/modules/$(KERNELRELEASE)/build)

    install:
	@if ! [ -e $(MODOBJ) ] ; then \
	  echo "No $(MODOBJ): nothing to install??"; false ; \
	fi
# install -d $(DESTDIR)/var/lib/drbd
	install -d $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
	install -m 644 $(MODOBJ) $(DESTDIR)/lib/modules/$(KERNELRELEASE)/$(MODSUBDIR)
    ifeq ($(DESTDIR),/)
      ifeq ($(shell uname -r),$(KERNELRELEASE))
	/sbin/depmod -a || /sbin/depmod -e $(MODOBJ) 2>&1 >/dev/null || true
      else
	[ -e $(LINUX)/System.map ] && \
	   /sbin/depmod -F $(LINUX)/System.map -e ./$(MODOBJ) 2>&1 >/dev/null || true
      endif
    endif
  else
    install:
	@echo "No .drbd_kernelrelease found. Do you need to 'make' the module first?"
	@false
  endif

  depmod:
	[ -e $(KDIR)/System.map ] && [ -e ./$(MODOBJ) ] && \
	   /sbin/depmod -F $(KDIR)/System.map -n -e ./$(MODOBJ) # 2>&1 >/dev/null
endif

spell:
	for f in $(wildcard *.c); do \
	 	aspell --save-repl --dont-backup --personal=./../documentation/aspell.en.per check $$f; \
	done

