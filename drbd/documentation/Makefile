# Makefile in documentation directory
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

man:	drbdsetup.8 drbd.conf.5

drbdsetup.8: drbdsetup.sgml
	docbook2man drbdsetup.sgml

drbd.conf.5: drbd.conf.sgml
	docbook2man drbd.conf.sgml

clean:
	rm -f drbdsetup.ps drbdsetup.8 drbd.conf.5 manpage.links manpage.refs