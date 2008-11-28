# Makefile for drbd.o
#
# This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
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

KDIR := /lib/modules/$(shell uname -r)/build

CC = gcc
OPTFLAGS = -O2
CFLAGS = -g $(OPTFLAGS) -c -W -Wall -I../drbd
# for the netlink connector stuff <linux/connector.h>:
drbdsetup: CFLAGS += -I$(KDIR)/include
drbdsetup drbdmeta: CFLAGS += -fno-strict-aliasing

drbdadm-obj = drbdadm_scanner.o drbdadm_parser.o drbdadm_main.o \
	      drbdadm_adjust.o drbdtool_common.o drbdadm_usage_cnt.o \
	      drbd_buildtag.o drbdadm_minor_table.o

drbdsetup-obj = drbdsetup.o drbdtool_common.o drbd_buildtag.o \
	        drbd_strings.o

drbdmeta-obj = drbdmeta.o drbdmeta_scanner.o drbdtool_common.o drbd_buildtag.o

all: drbdadm drbdmeta drbdsetup

drbd_buildtag.c: ../drbd/drbd_buildtag.c
	cp $^ $@

drbd_strings.c: ../drbd/drbd_strings.c
	cp $^ $@

drbdadm: $(drbdadm-obj)
	$(CC) -o $@ $^

# for debugging:
# 	LANG=C LC_ALL=C flex -d -b -s -odrbdadm_scanner.c drbdadm_scanner.fl

drbdadm_scanner.c: drbdadm_scanner.fl drbdadm_parser.h
	flex -s -odrbdadm_scanner.c drbdadm_scanner.fl

drbdmeta_scanner.c: drbdmeta_scanner.fl drbdmeta_parser.h
	flex -s -odrbdmeta_scanner.c drbdmeta_scanner.fl

drbdsetup: $(drbdsetup-obj)
	$(CC) -o $@ $^

drbdmeta: $(drbdmeta-obj)
	$(CC) -o $@ $^

drbdmeta_unfinished_rewrite: CFLAGS += -fno-strict-aliasing
drbdmeta_unfinished_rewrite: drbdmeta_unfinished_rewrite.o drbdmeta_scanner.o drbdtool_common.o drbd_buildtag.o
	$(CC) -o $@ $^

clean:
	rm -f drbdadm_scanner.c drbdmeta_scanner.c
	rm -f drbdsetup drbdadm drbdmeta drbdmeta_unfinished_rewrite *.o
	rm -f drbd_buildtag.c drbd_strings.c
	rm -f *~

distclean: clean

install:
	install -d $(PREFIX)/sbin/
	if getent group haclient > /dev/null 2> /dev/null ; then	\
		install -g haclient -m 4750 drbdsetup $(PREFIX)/sbin/ ;	\
		install -g haclient -m 4750 drbdmeta $(PREFIX)/sbin/ ;	\
		install -m 755 drbdadm $(PREFIX)/sbin/ ;		\
	else								\
		install -m 755 drbdsetup $(PREFIX)/sbin/ ;		\
		install -m 755 drbdmeta $(PREFIX)/sbin/ ;		\
		install -m 755 drbdadm $(PREFIX)/sbin/ ; 		\
	fi
	mkdir -p $(PREFIX)/var/lib/drbd

uninstall:
	rm -f $(PREFIX)/sbin/drbdsetup
	rm -f $(PREFIX)/sbin/drbdadm

###dependencies
drbdsetup.o:       drbdtool_common.h ../drbd/linux/drbd_limits.h
drbdsetup.o:       ../drbd/linux/drbd_tag_magic.h ../drbd/linux/drbd.h
drbdsetup.o:       ../drbd/linux/drbd_config.h ../drbd/linux/drbd_nl.h
drbdtool_common.o: drbdtool_common.h
drbdadm_main.o:    drbdtool_common.h drbdadm.h
drbdadm_adjust.o:  drbdtool_common.h drbdadm.h
drbdadm_parser.o:  drbdtool_common.h drbdadm.h ../drbd/linux/drbd_limits.h
drbdadm_scanner.o:                   drbdadm.h               drbdadm_parser.h
drbdsetup.o:       drbdtool_common.h           ../drbd/linux/drbd_limits.h
drbdmeta.o:        drbdtool_common.h drbd_endian.h
drbdmeta_unfinished_rewrite.o:        drbdtool_common.h drbd_endian.h
drbdadm_usage_cnt.o: drbdadm.h drbd_endian.h
