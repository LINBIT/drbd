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

####### Implicit rules

.SUFFIXES: .c .o

.c.o:
	$(CC) -c $(USERFLAGS) $(VERSIONFLAGS) $<

#######


all: drbdsetup drbdadm

drbdadm: drbdadm_scanner.o drbdadm_parser.o drbdadm_main.o drbdadm_adjust.o
	$(CC) -o drbdadm drbdadm_scanner.o drbdadm_parser.o drbdadm_main.o \
	drbdadm_adjust.o

drbdadm_scanner.c: drbdadm_scanner.fl drbdadm_parser.h
	flex -odrbdadm_scanner.c drbdadm_scanner.fl

drbdadm_parser.h: drbdadm_parser.y
	bison -d -o drbdadm_parser.c drbdadm_parser.y

drbdadm_parser.c: drbdadm_parser.y
	bison -d -o drbdadm_parser.c drbdadm_parser.y

drbdsetup: drbdsetup.o
	$(CC) -o drbdsetup drbdsetup.o

clean:
	rm -f drbdadm_scanner.c
	rm -f drbdadm_parser.c
	rm -f drbdadm_parser.h
	rm -f drbdsetup drbdadm *.o 
	rm -f *~

install:
	install -d $(PREFIX)usr/sbin/
	install -m 755 drbdsetup $(PREFIX)usr/sbin/
