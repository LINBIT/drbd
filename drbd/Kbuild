obj-m += drbd.o drbd_transport_tcp.o
# obj-$(CONFIG_BLK_DEV_DRBD)     += drbd.o drbd_transport_tcp.o

clean-files := compat.h $(wildcard .config.$(KERNELVERSION).timestamp)

LINUXINCLUDE := -I$(src) -I$(src)/drbd-headers $(LINUXINCLUDE)

# Files in the standard include directories take precendence over files
# in the drbd-kernel-compat directory.
#
# Add -I$(src) to EXTRA_CFLAGS again: some (rhel5, maybe other) kbuild does not
# yet use LINUXINCLUDE like we expect it to ;( fortunately it does not contain
# in-tree drbd either yet, so precedence of include files is not important.
#
# override: we absolutely need this, even if EXTRA_CFLAGS originates from make
# command line or environment
override EXTRA_CFLAGS += -I$(src) -I$(src)/drbd-kernel-compat

# The augmented rbtree helper functions are not exported at least until kernel
# version 2.6.38-rc2.
ifeq ($(shell grep -e '\<rb_augment_insert\>' \
		   -e '\<rb_augment_erase_begin\>' \
		   -e '\<rb_augment_erase_end\>' \
		   $(objtree)/Module.symvers | wc -l),3)
override EXTRA_CFLAGS += -DAUGMENTED_RBTREE_SYMBOLS_EXPORTED
endif

ifeq ($(shell grep -e '\<idr_get_next\>' \
		   $(objtree)/Module.symvers | wc -l),1)
override EXTRA_CFLAGS += -DIDR_GET_NEXT_EXPORTED
else
compat_objs += drbd-kernel-compat/idr.o
endif

ifeq ($(shell grep -e '\<blkdev_issue_zeroout\>' \
		   $(objtree)/Module.symvers | wc -l),1)
override EXTRA_CFLAGS += -DBLKDEV_ISSUE_ZEROOUT_EXPORTED
else
compat_objs += drbd-kernel-compat/blkdev_issue_zeroout.o
endif

ifneq ($(shell grep -e '\<nsecs_to_jiffies\>' \
		   $(objtree)/Module.symvers | wc -l),1)
compat_objs += drbd-kernel-compat/nsecs_to_jiffies.o
endif
compat_objs += drbd-kernel-compat/drbd_wrappers.o

ifdef CONFIG_DEV_DAX_PMEM
ifneq ($(shell grep -e '\<arch_wb_cache_pmem\>' $(objtree)/Module.symvers | wc -l),1)
override EXTRA_CFLAGS += -DDAX_PMEM_IS_INCOMPLETE
else
drbd-y += drbd_dax_pmem.o
endif
endif

drbd-$(CONFIG_DEBUG_FS) += drbd_debugfs.o
drbd-y += drbd_buildtag.o drbd_bitmap.o drbd_proc.o
drbd-y += drbd_sender.o drbd_receiver.o drbd_req.o drbd_actlog.o
drbd-y += lru_cache.o drbd_main.o drbd_strings.o drbd_nl.o
drbd-y += drbd_interval.o drbd_state.o $(compat_objs)
drbd-y += drbd_nla.o drbd_transport.o

ifdef CONFIG_KREF_DEBUG
      drbd-y += kref_debug.o drbd_kref_debug.o
endif

HOST_EXTRACFLAGS += -I$(src) -std=c11 $(EXTRA_CFLAGS)
hostprogs := drbd-kernel-compat/gen_patch_names
headers-to-apply-compat := drbd_int.h drbd_req.h drbd_interval.h

$(obj)/dummy-for-compat-h.o: $(obj)/compat.h
	@true
$(addprefix $(obj)/,$(drbd-y) drbd_transport_tcp.o): $(obj)/compat.h $(src)/.compat_patches_applied
$(obj)/drbd-kernel-compat/gen_patch_names: $(src)/drbd-kernel-compat/gen_patch_names.c $(obj)/compat.h

obj-$(CONFIG_BLK_DEV_DRBD)     += drbd.o

# ======================================================================

# Are we in stage 2 of the build (modpost)?

# Apparently GNU Make 4.0 strips leading ./ from MAKEFILE_LIST. Yay.

KBUILD_STAGE ?= $(if $(filter      scripts/Makefile.modpost \
			$(srctree)/scripts/Makefile.modpost,\
			$(MAKEFILE_LIST)),modpost)

ifneq ($(shell date -r $(objtree)/.config),$(shell date -r $(obj)/.config.$(KERNELVERSION).timestamp 2> /dev/null))
COMPAT_FORCE := FORCE
endif

# Red hat's kernel header files needs additional includes they
# miss to add to the files.
# E.g. linux/blk_types.h on RHEL 7.6 needs rh_kabi.h and errno.h
# otherwise the compat test already fails in processing linux/blk_types.h
RH_KABI_H := $(wildcard $(KDIR)/include/linux/rh_kabi.h)
ifneq ($(RH_KABI_H),)
      COMPAT_CFLAGS := -include"linux/rh_kabi.h" -include"linux/errno.h"
endif

ifneq ($(KBUILD_STAGE),modpost)
TEST_C := $(sort $(wildcard $(src)/drbd-kernel-compat/tests/*.c))
TEST_R := $(TEST_C:$(src)/drbd-kernel-compat/tests/%.c=$(obj)/.compat_test.$(KERNELVERSION)/%.result)
$(obj)/.compat_test.$(KERNELVERSION)/%.result: $(src)/drbd-kernel-compat/tests/%.c $(COMPAT_FORCE)
	$(call cmd,compat_test_result)

quiet_cmd_compat_test_result = COMPAT  $*
      cmd_compat_test_result = \
	mkdir -p $(@D)/ ; \
	var=`echo COMPAT_$* | tr -- -a-z _A-Z | tr -dc A-Z0-9_` ;		\
	if $(CC) $(c_flags) -Werror-implicit-function-declaration $(COMPAT_CFLAGS) \
		-c -o $(@D)/.$*.o $< > $(@D)/$*.stdout 2> $(@D)/$*.stderr	\
		-D"KBUILD_MODNAME=\"compat_dummy\"" ;				\
	then									\
		echo "\#define $$var" ;						\
	else									\
		echo "/* \#undef $$var */" ;					\
	fi > $@

filechk_compat.$(KERNELVERSION).h = cat $(TEST_R)
filechk_compat.h = cat $(obj)/compat.$(KERNELVERSION).h

$(src)/.compat_patches_applied: $(src)/drbd-kernel-compat/compat.patch
	@$(kecho) '  PATCH'
	@patch -d $(src) -p0 --batch --forward < $(src)/drbd-kernel-compat/compat.patch
	@cp -d $(src)/drbd-kernel-compat/compat.patch $(src)/.compat_patches_applied

$(src)/drbd-kernel-compat/compat.patch: $(obj)/compat.h
	$(eval chksum := $(word 1, $(shell md5sum $(obj)/compat.h)))
	$(eval dir := $(obj)/drbd-kernel-compat/cocci_cache/$(chksum))
	@mkdir -p $(dir)
	@test -e $(dir)/compat.h || cp -t $(dir) $(obj)/compat.h
	@echo $(KERNELRELEASE) > $(dir)/kernelrelease.txt
	@ln -f -s -T ../cocci_cache/$(chksum) $(obj)/drbd-kernel-compat/l/$(KERNELRELEASE)
	@PATCHLEVEL="" $(MAKE) -C $(src) drbd-kernel-compat/cocci_cache/$(chksum)/compat.patch
	@ln -f -s $(dir)/compat.patch $(src)/drbd-kernel-compat/compat.patch

$(obj)/compat.$(KERNELVERSION).h: $(TEST_R) $(COMPAT_FORCE)
	$(call filechk,compat.$(KERNELVERSION).h)

$(obj)/compat.h: $(obj)/compat.$(KERNELVERSION).h FORCE
	$(call filechk,compat.h)
	$(Q)touch -r $(objtree)/.config $(obj)/.config.$(KERNELVERSION).timestamp
else
# remember KERNELRELEASE for install target
# .kernelversion can be included in Makefile as well as
# sourced from shell
$(shell printf "%s\n"				\
	"VERSION=$(VERSION)"			\
	"PATCHLEVEL=$(PATCHLEVEL)"		\
	"SUBLEVEL=$(SUBLEVEL)"			\
	"EXTRAVERSION=$(EXTRAVERSION)"		\
	"LOCALVERSION=$(LOCALVERSION)"		\
	"KERNELRELEASE=$(KERNELRELEASE)"	\
	"KERNELVERSION=$(KERNELVERSION)"	\
	> $(src)/.drbd_kernelrelease.new	\
)
endif


# for some reason some of the commands below only work correctly in bash,
# and not in e.g. dash. I'm too lazy to fix it to be compatible.
SHELL=/bin/bash

$(obj)/drbd_buildtag.c: $(addprefix $(obj)/,$(filter-out drbd_buildtag.o,$(drbd-y)))
	@$(kecho) '  GEN     $@ $(echo-why)'
	@set -e; exec > $@.new;							\
	echo -e "/* automatically generated. DO NOT EDIT. */";			\
	echo -e "#include <linux/drbd.h>";					\
	echo -e "#include <linux/drbd_config.h>";				\
	echo -e "const char *drbd_buildtag(void)\n{";				\
	if test -e $(src)/../.git &&						\
	   GITHEAD=$$(cd $(src) && git rev-parse HEAD); then			\
		GITDIFF=$$(cd $(src)/.. && git diff --name-only HEAD |		\
			tr -s '\t\n' '  ' |					\
			sed -e 's/^/ /;s/ *$$//');				\
		echo -e "\treturn \"GIT-hash: $$GITHEAD$$GITDIFF\"";		\
	elif test -e $(src)/.drbd_git_revision ; then				\
		echo -e "\treturn \"$$(cat $(src)/.drbd_git_revision)\"";	\
	elif test -e $@ ; then							\
		grep return $@ ;						\
	else									\
		echo >&2 "Your DRBD source tree is broken. Unpack again.";      \
		exit 1;								\
	fi ;									\
	if [ -z "${WANT_DRBD_REPRODUCIBLE_BUILD}" ] || [ -z "${SOURCE_DATE_EPOCH}" ] ; then	\
		buildinfo="build by $$USER@$$HOSTNAME, `date "+%F %T"`" ;			\
	else 											\
		buildinfo="reproducible build, `date -u -d@${SOURCE_DATE_EPOCH} "+%F %T"`" ; 	\
	fi ; 											\
	echo -e "\t\t\" $$buildinfo\";\n}";							\
	mv -f $@.new $@
