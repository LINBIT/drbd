# Makefile for drbd.o
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

include ../Makefile.vars

KSUBD := $(strip \
$(if $(wildcard /lib/modules/$(KERNVER)/kernel),\
  kernel/drivers/block,\
  block))


OBJS =  drbd_fs.o drbd_main.o drbd_proc.o drbd_receiver.o drbd_dsender.o
OBJS += drbd_req-2.4.o mempool-2.4.o drbd_actlog.o

ifeq ($(ARCH),sparc64)
	KCC=sparc64-linux-gcc
	LDFLAGS=-m elf64_sparc
else
	KCC=$(CC)
endif

####### Implicit rules

.SUFFIXES: .c .o

.PHONY: check_kernel_config

.c.o:
	$(KCC) -c $(KERNFLAGS) $(VERSIONFLAGS) $<

#######

# error, if we have no kernel source tree
define ERR_NO_KERNEL_SOURCE

Could not find kernel sources.
  Install them, or tell me where to find them with
  make LINUX=/path/to/kernel/source
endef
ifeq ($(LINUX),)
  $(warning $(ERR_NO_KERNEL_SOURCE)))
endif
ifneq ($(shell cd $(LINUX) 2>&1),)
  $(warning $(LINUX): no such directory. $(ERR_NO_KERNEL_SOURCE))
endif
# lge patent pending :-)
ifneq ($(shell ls $(LINUX)/Documentation/oops-tracing.txt 2>&1 >/dev/null),)
  $(warning $(LINUX) does not look like a kernel source tree)
endif

# which version is configured in the kernel source tree
# just "make" it, in case it is out of date.
CONFIGURED_KERNVER := $(shell \
   ( cd $(LINUX) && $(MAKE) include/linux/version.h > /dev/null 2>&1 ) && \
   $(CC) -nostdinc -E -P $(INCLUDE) check_kernel_config.c | \
   sed -e '/^drbd_configured_kernver/!d;s/[^"]*"//;s/".*//; q' )
# which version the current drbd.o was built for
COMPILED_KERNVER := $(shell test -e .flags && sed -e 's/;.*//;q' .flags)

ifeq ($(CONFIGURED_KERNVER),)
   $(warning kernel configuration seems to be not ok)
endif


NEED_SIGHAND_HACK := $(shell grep -q "^struct sighand_struct" \
	$(LINUX)/include/linux/sched.h && echo yes )
ifeq ($(NEED_SIGHAND_HACK),yes)
  override KERNFLAGS += -DSIGHAND_HACK
  $(warning adding -DREDHAT_2_4_20 sighand_struct hack)
endif

NEEDNEW := $(shell \
	if test -e .flags \
	&& test "$(CONFIGURED_KERNVER);$(KERNFLAGS);$(VERSIONFLAGS)" = "`cat .flags`"; \
	then \
		:; \
	else \
		echo clean; \
	fi)


#######

all: check_kernel_config $(NEEDNEW) drbd.o

# error, if running or commandline specified kernel version
# and version from the kernel source config do not match
check_kernel_config:
ifneq ($(CONFIGURED_KERNVER),$(KERNVER))
	@echo "Version of running kernel and kernel config differ:"
	@echo "  $(KERNVER) <uname -r or specified on command line>"
	@echo "  $(CONFIGURED_KERNVER) <$(LINUX)/include/linux/version.h>"
	@echo "  You may want to reconfigure to match the running kernel, or"
	@echo "  make KERNVER=2.4.XY LINUX=/path/to/kernel/source "
	@echo "  to override this"
	@false
endif

drbd.o: $(OBJS)
	$(LD) $(LDFLAGS) -r -o $@ $^

clean:
	rm -f *.o *~ .flags
	@echo "$(CONFIGURED_KERNVER);$(KERNFLAGS);$(VERSIONFLAGS)" >.flags

distclean: clean

install: drbd.o
	install -d $(PREFIX)lib/modules/$(KERNVER)/$(KSUBD)
	install -m 644 drbd.o $(PREFIX)lib/modules/$(KERNVER)/$(KSUBD)
	install -d $(PREFIX)var/lib/drbd
ifeq ($(shell uname -r),$(KERNVER))
	/sbin/depmod -a || depmod -e drbd.o 2>&1 >/dev/null || true
else
	[ -e $(LINUX)/System.map ] && \
	   /sbin/depmod -F $(LINUX)/System.map -e drbd.o 2>&1 >/dev/null || true
endif

uninstall:
	rm $(PREFIX)lib/modules/$(KERNVER)/$(KSUBD)/drbd.o
	/sbin/depmod -a || true

### dependencies:

$(OBJS): drbd_int.h drbd.h
