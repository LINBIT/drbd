
# we inherit some variables from our "parent" Makefile
THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
$(foreach v,REL_VERSION FDIST_VERSION,$(if $($(v)),,$(error "Do not use this Makefile ($(THIS_MAKEFILE)) directly! ($(v) missing))))

all: drbd-kmod.cdx.json drbd-kmod_rhel.spdx.json drbd-kmod_sles.spdx.json

export SPDX_VERSION SPDX_DATE SPDX_YEAR SPDX_UUID SPDX_PKG_NAME
SPDX_VERSION:=$(REL_VERSION)
SPDX_DATE:=$(shell date --utc +%FT%TZ)
SPDX_YEAR:=$(firstword $(subst -, ,$(SPDX_DATE)))
drbd-kmod_rhel.spdx.json drbd-kmod_sles.spdx.json: SPDX_UUID:=$(shell cat /proc/sys/kernel/random/uuid)
drbd-kmod_rhel.spdx.json: SPDX_PKG_NAME:=kmod-drbd
drbd-kmod_sles.spdx.json: SPDX_PKG_NAME:=drbd-kmp-default
drbd-kmod_rhel.spdx.json drbd-kmod_sles.spdx.json: FORCE
	@rm -f $@; jq -n -f drbd-kmod.spdx.json.in > $@.tmp && mv $@.tmp $@

# uses:
# SPDX_DATE from above and FDIST_VERSION from parent Makefile
drbd-kmod.cdx.json: FORCE
	@rm -f $@; jq -n -f drbd-kmod.cdx.json.in > $@.tmp && mv $@.tmp $@

.PHONY: FORCE
FORCE:
