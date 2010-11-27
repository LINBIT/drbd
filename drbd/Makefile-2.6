# Search the local directory before the standard include directories.
# This is needed for overriding files like <linux/drbd.h>.

LINUXINCLUDE := -I$(src) $(LINUXINCLUDE)

# Files in the standard include directories take precendence over files
# in the compat directory.
#
# Add -I$(src) to EXTRA_CFLAGS again: some (rhel5, maybe other) kbuild does not
# yet use LINUXINCLUDE like we expect it to ;( fortunately it does not contain
# in-tree drbd either yet, so precedence of include files is not important.
#
# override: we absolutely need this, even if EXTRA_CFLAGS originates from make
# command line or environment
override EXTRA_CFLAGS += -I$(src) -I$(src)/compat

drbd-y := drbd_buildtag.o drbd_bitmap.o drbd_proc.o
drbd-y += drbd_worker.o drbd_receiver.o drbd_req.o drbd_actlog.o
drbd-y += lru_cache.o drbd_main.o drbd_strings.o drbd_nl.o

ifndef CONFIG_CONNECTOR
	drbd-y += connector.o cn_queue.o
endif

drbd_trace-y := drbd_tracing.o

obj-$(CONFIG_BLK_DEV_DRBD)     += drbd.o
obj-$(CONFIG_DRBD_TRACE)       += drbd_trace.o
