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

include ../Makefile.vars

all:

install:
	install drbd /etc/rc.d/init.d/
	install datadisk /etc/ha.d/resource.d/
	install -d /etc/sysconfig/drbd
	install drbd.example /etc/sysconfig/drbd/

clean:
	rm -f *~
