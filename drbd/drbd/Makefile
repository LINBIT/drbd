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

# usage: make

ifneq ($(KERNELRELEASE),)

ifneq ($(VERSION),2)
$(error "won't compile with this kernel version")
endif

# linux 2.6 style:
obj-m      += drbd.o
drbd-objs  := drbd_fs.o drbd_main.o drbd_proc.o drbd_dsender.o \
              drbd_receiver.o drbd_req-2.4.o mempool-2.4.o drbd_actlog.o

ifeq ($(PATCHLEVEL),4)
# linux 2.4 style needs in addition:

list-multi := drbd.o

include $(TOPDIR)/Rules.make

drbd.o: $(drbd-objs)
	$(LD) -r -o $@ $(drbd-objs)

else
ifneq ($(PATCHLEVEL),6)
$(error "won't compile with this kernel version")
endif
endif

else
# called from commandline in current directory
ifeq ($(wildcard ../build-for-uml),../build-for-uml)
#### for Philipp's convenience :) 
ARUM := "ARCH=um"
KDIR := /usr/src/linux-um
else
KDIR := /lib/modules/$(shell uname -r)/build
endif
PWD  := $(shell pwd)

default:
	@echo "" ;\
	echo "    Calling toplevel makefile of kernel source tree." ;\
	echo "    NOTE: please ignore the possible warning regarding overriding of SUBDIRS" ;\
	echo ""
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) $(ARUM) modules

clean:
	rm -f *.o *~

install:
	install -d $(PREFIX)lib/modules/$(KERNVER)/$(KSUBD)
	install -m 644 drbd.o $(PREFIX)lib/modules/$(KERNVER)/$(KSUBD)

endif
