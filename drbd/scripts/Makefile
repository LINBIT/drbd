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
	mkdir -p /etc/ha.d/resource.d
	mkdir -p /etc/sysconfig/drbd
	mkdir -p /var/lib/drbd
	
	install drbd_commun /etc/ha.d/resource.d/
	install drbdc /etc/ha.d/resource.d/
	install drbd /etc/ha.d/resource.d/
	install datadisk /etc/ha.d/resource.d/
	install drbd.example /etc/sysconfig/drbd/

	@ if [ -e /etc/init.d ]; then \
		ln -sf /etc/ha.d/resource.d/drbd /etc/init.d/drbd ;\
		echo ln -sf /etc/ha.d/resource.d/drbd /etc/init.d/drbd;\
		ln -sf /etc/ha.d/resource.d/datadisk /etc/init.d/datadisk ;\
		echo ln -sf /etc/ha.d/resource.d/datadisk /etc/init.d/datadisk;\
	elif [ -e /etc/rc.d/init.d ]; then \
		ln -sf /etc/ha.d/resource.d/drbd /etc/rc.d/init.d/drbd ;\
		echo ln -sf /etc/ha.d/resource.d/drbd /etc/rc.d/init.d/drbd ;\
		ln -sf /etc/ha.d/resource.d/datadisk /etc/rc.d/init.d/datadisk ;\
		echo ln -sf /etc/ha.d/resource.d/datadisk /etc/rc.d/init.d/datadisk ;\
	else \
		echo "Can not install drbd and datadisk init.d script" ;\
	fi

	echo "don't forget to run chkconfig with drbd and datadisk"

clean:
	rm -f *~
