# Makefile for scripts
#
# This file is part of DRBD by Philipp Reisner & Lars Ellenberg.
#
# Copright 2001-2008 LINBIT Information Technologies
# Philipp Reisner, Lars Ellenberg
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
#   update-rc.d drbd defaults 70 08
#

SCRIPT=drbd
DIST            :=$(strip \
  $(if $(wildcard /etc/gentoo-release),gentoo,\
  $(if $(wildcard /etc/redhat-release),redhat,\
  $(if $(wildcard /etc/slackware-version),slackware,\
  $(if $(wildcard /etc/debian_version),debian,\
  $(if $(wildcard /sbin/rcsyslog),suselike,))))))

ifeq ($(DIST),slackware)
  INITD=$(PREFIX)/etc/rc.d/
endif

ifeq ($(DIST),gentoo)
  INITD=$(PREFIX)/etc/init.d/
  SCRIPT=drbd.gentoo
endif

ifeq ($(DIST),redhat)
  INITD=$(PREFIX)/etc/rc.d/init.d/
endif

ifeq ($(INITD),)
   INITD=$(PREFIX)/etc/init.d/
   $(warning No special distribution INITD)
   $(warning setting INITD=$(INITD) according to LSB)
endif

ifeq ($(DIST),suselike)
   COMPLETION=drbdadm.sh
else
   COMPLETION=drbdadm
endif

all:

install: install-most install-udev-rules

install-most:
	mkdir -p $(PREFIX)/etc/ha.d/resource.d
	install -d $(INITD)
	install -m 755 $(SCRIPT) $(INITD)drbd
	@ if [ ! -e $(PREFIX)/etc/drbd.conf ]; then \
		install -d $(PREFIX)/etc/; \
		install -m 644 drbd.conf $(PREFIX)/etc/; \
	fi
	install -m 755 drbddisk $(PREFIX)/etc/ha.d/resource.d
	install -m 755 drbdupper $(PREFIX)/etc/ha.d/resource.d
	mkdir -p $(PREFIX)/usr/lib/ocf/resource.d/drbd
	install -m 755 drbd.ocf $(PREFIX)/usr/lib/ocf/resource.d/drbd
	install -d $(PREFIX)/usr/lib/drbd
	install -m 755 outdate-peer.sh $(PREFIX)/usr/lib/drbd
	install -m 755 snapshot-resync-target-lvm.sh $(PREFIX)/usr/lib/drbd
	( cd $(PREFIX)/usr/lib/drbd ;\
	  ln -sf snapshot-resync-target-lvm.sh unsnapshot-resync-target-lvm.sh )
	install -m 755 notify.sh $(PREFIX)/usr/lib/drbd
	( cd $(PREFIX)/usr/lib/drbd ;\
	  ln -sf notify.sh notify-split-brain.sh ;\
	  ln -sf notify.sh notify-io-error.sh ;\
	  ln -sf notify.sh notify-pri-on-incon-degr.sh ;\
	  ln -sf notify.sh notify-pri-lost.sh ;\
	  ln -sf notify.sh notify-pri-lost-after-sb.sh ;\
	  ln -sf notify.sh notify-emergency-reboot.sh ;\
	  ln -sf notify.sh notify-emergency-shutdown.sh ;\
	  ln -sf notify.sh notify-out-of-sync.sh; )
	mkdir -p $(PREFIX)/etc/xen/scripts
	install -m 755 block-drbd $(PREFIX)/etc/xen/scripts
	mkdir -p $(PREFIX)/etc/udev/rules.d
ifneq ($(DIST),redhat)
 ifneq ($(DIST),slackware)
	mkdir -p $(PREFIX)/etc/bash_completion.d
	install -m 644 drbdadm.bash_completion $(PREFIX)/etc/bash_completion.d/$(COMPLETION)
 endif
endif
	install -d $(PREFIX)/usr/sbin
	# strip .pl on install,
	# at some point we might reimplement similar functionality in non-perl
	install -m 755 drbd-overview.pl $(PREFIX)/usr/sbin/drbd-overview
ifeq ($(DIST),suselike)
	ln -sf ../etc/init.d/drbd $(PREFIX)/sbin/rcdrbd
endif
ifeq ($(DIST),redhat)
	mkdir -p $(PREFIX)/usr/share/cluster
	install -m 755 drbd.sh.rhcs $(PREFIX)/usr/share/cluster/drbd.sh
	install -m 644 drbd.metadata.rhcs $(PREFIX)/usr/share/cluster/drbd.metadata
endif
	@ echo
	@ echo "Don't forget to run update-rc.d or chkconfig"

# more install
# only install the udev rules file when udev is determined to be new enough.
# udevadm was introduced in 117, which is ok.
# if udevadm is not there, we still may work.
# try to ask the package data base (rpm/deb) for the udev version.
# IMPORT was introduced in 059.
# ETCH is 105, RHEL5 is 095, SLES10 is 085. test on >= 085.
#
# may be overridden from build environment,
# e.g. if you build in some changeroot without access to the package database,
# or without udev installed.
# 
install-udev-rules:
	disable=.disabled ; \
	v=$$(udevadm version 2>/dev/null) || \
	v=$$(rpm -q --qf '%{VERSION}' udev 2>/dev/null) || \
	v=$$(dpkg-query -W -f '$${Version}' udev 2>/dev/null); \
	v=$${v##*.} ; v=$${v%%-*} ; v=$${v#0} ; \
	if [ -n "$$DRBD_ENABLE_UDEV" ] ; then \
		disable="" ; \
	else case "$$v" in \
	"") :;; *[!0-9]*) :;; *) \
		if [ "$$v" -ge 85 ]; then \
			disable=""; \
		fi ;; \
	esac; fi ; \
	install -m 644 drbd.rules $(PREFIX)/etc/udev/rules.d/65-drbd.rules$$disable

clean:
	rm -f *~
	rm -f datadisk

distclean: clean

uninstall:
	rm $(INITD)drbd
	rm $(PREFIX)/etc/ha.d/resource.d/drbddisk
	rm $(PREFIX)/etc/ha.d/resource.d/drbdupper
	rm $(PREFIX)/etc/xen/scripts/block-drbd
	rm $(PREFIX)/etc/bash_completion.d/$(COMPLETION)
	! test -L $(PREFIX)/sbin/rcdrbd || rm $(PREFIX)/sbin/rcdrbd
