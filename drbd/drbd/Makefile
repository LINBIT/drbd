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

KSUBD = $(shell if [ -e /lib/modules/$(KERNVER)/kernel ]; then echo "kernel/drivers/block"; else echo "block"; fi )

OBJS=drbd_fs.o drbd_main.o drbd_proc.o drbd_receiver.o drbd_syncer.o

####### Implicit rules

.SUFFIXES: .c .o

.c.o:
	$(CC) -c $(KERNFLAGS) -DMOD_VERSION=$(MOD_VERSION) -DEXPORT_SYMTAB $<

#######


all: drbd.o 

drbd.o: $(OBJS)
	$(LD) -r -o $@ $^

clean:
	rm -f *.o
	rm -f *~


install:
	install -d /lib/modules/$(KERNVER)/$(KSUBD)
	install -m 644 drbd.o /lib/modules/$(KERNVER)/$(KSUBD)
	/sbin/depmod -a

### dependencies:

$(OBJS): drbd_int.h drbd.h mbds.h

