# Makefile for scripts
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
# for Debian:
#   update-rc.d drbd start 18 2 3 4 5 . stop 18 0 1 6 .
#

include ../Makefile.vars

all:

install:
	if [ -e /etc/init.d ]; then install drbd /etc/init.d/;\
		else install drbd /etc/rc.d/init.d/; fi
	mkdir -p /etc/ha.d/resource.d
	install datadisk /etc/ha.d/resource.d/
	mkdir -p /etc/sysconfig/drbd
	install drbd.example /etc/sysconfig/drbd/

clean:
	rm -f *~
