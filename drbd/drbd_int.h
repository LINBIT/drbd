/*
  drbd_int.h

  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

  Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
  Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

  drbd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  drbd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with drbd; see the file COPYING.  If not, write to
  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#ifndef _DRBD_INT_H
#define _DRBD_INT_H

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/tcp.h>
#include <linux/mutex.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <net/tcp.h>
#include <linux/lru_cache.h>
#include <linux/prefetch.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd.h>
#include <linux/drbd_config.h>

#include "compat.h"
#include "drbd_state.h"
#include "drbd_protocol.h"

#ifdef __CHECKER__
# define __protected_by(x)       __attribute__((require_context(x,1,999,"rdwr")))
# define __protected_read_by(x)  __attribute__((require_context(x,1,999,"read")))
# define __protected_write_by(x) __attribute__((require_context(x,1,999,"write")))
# define __must_hold(x)       __attribute__((context(x,1,1), require_context(x,1,999,"call")))
#else
# define __protected_by(x)
# define __protected_read_by(x)
# define __protected_write_by(x)
# define __must_hold(x)
#endif

#define __no_warn(lock, stmt) do { __acquire(lock); stmt; __release(lock); } while (0)

/* Compatibility for older kernels */
#ifndef __acquires
# ifdef __CHECKER__
#  define __acquires(x)	__attribute__((context(x,0,1)))
#  define __releases(x)	__attribute__((context(x,1,0)))
#  define __acquire(x)	__context__(x,1)
#  define __release(x)	__context__(x,-1)
#  define __cond_lock(x,c)	((c) ? ({ __acquire(x); 1; }) : 0)
# else
#  define __acquires(x)
#  define __releases(x)
#  define __acquire(x)	(void)0
#  define __release(x)	(void)0
#  define __cond_lock(x,c) (c)
# endif
#endif

/* module parameter, defined in drbd_main.c */
extern unsigned int minor_count;
extern int disable_sendpage;
extern int allow_oos;

#ifdef DRBD_ENABLE_FAULTS
extern int enable_faults;
extern int fault_rate;
extern int fault_devs;
#endif

extern char usermode_helper[];

#include <linux/major.h>
#ifndef DRBD_MAJOR
# define DRBD_MAJOR 147
#endif

#include <linux/blkdev.h>
#include <linux/bio.h>

/* I don't remember why XCPU ...
 * This is used to wake the asender,
 * and to interrupt sending the sending task
 * on disconnect.
 */
#define DRBD_SIG SIGXCPU

/* This is used to stop/restart our threads.
 * Cannot use SIGTERM nor SIGKILL, since these
 * are sent out by init on runlevel changes
 * I choose SIGHUP for now.
 *
 * FIXME btw, we should register some reboot notifier.
 */
#define DRBD_SIGKILL SIGHUP

#define ID_IN_SYNC      (4711ULL)
#define ID_OUT_OF_SYNC  (4712ULL)
#define ID_SYNCER (-1ULL)

#define UUID_NEW_BM_OFFSET ((u64)0x0001000000000000ULL)

struct drbd_device;
struct drbd_connection;

#ifdef DBG_ALL_SYMBOLS
# define STATIC
#else
# define STATIC static
#endif

/*
 * dev_printk() and dev_dbg() exist since "forever".
 * dynamic_dev_dbg() and disk_to_dev() exists since v2.6.28-rc1.
 */
#if defined(disk_to_dev)
#define __drbd_printk_device(level, device, fmt, args...) \
	dev_printk(level, disk_to_dev((device)->vdisk), fmt, ## args)
#define __drbd_printk_peer_device(level, peer_device, fmt, args...) \
	dev_printk(level, disk_to_dev((peer_device)->device->vdisk), fmt, ## args)
#else
#define __drbd_printk_device(level, device, fmt, args...) \
	printk(level "block drbd%u: " fmt, (device)->minor, ## args)
#define __drbd_printk_peer_device(level, peer_device, fmt, args...) \
	printk(level "block drbd%u: " fmt, (peer_device)->device->minor, ## args)
#endif

#define __drbd_printk_resource(level, resource, fmt, args...) \
	printk(level "drbd %s: " fmt, (resource)->name, ## args)

#define __drbd_printk_connection(level, connection, fmt, args...) \
	printk(level "drbd %s: " fmt, (connection)->resource->name, ## args)

void drbd_printk_with_wrong_object_type(void);

#define __drbd_printk_if_same_type(obj, type, func, level, fmt, args...) \
	(__builtin_types_compatible_p(typeof(obj), type) || \
	 __builtin_types_compatible_p(typeof(obj), const type)), \
	func(level, (const type)(obj), fmt, ## args)

#define drbd_printk(level, obj, fmt, args...) \
	__builtin_choose_expr( \
	  __drbd_printk_if_same_type(obj, struct drbd_device *, \
			     __drbd_printk_device, level, fmt, ## args), \
	  __builtin_choose_expr( \
	    __drbd_printk_if_same_type(obj, struct drbd_resource *, \
			       __drbd_printk_resource, level, fmt, ## args), \
	    __builtin_choose_expr( \
	      __drbd_printk_if_same_type(obj, struct drbd_connection *, \
				 __drbd_printk_connection, level, fmt, ## args), \
	      __builtin_choose_expr( \
		__drbd_printk_if_same_type(obj, struct drbd_peer_device *, \
				 __drbd_printk_peer_device, level, fmt, ## args), \
	        drbd_printk_with_wrong_object_type()))))

#if defined(disk_to_dev)
#define drbd_dbg(device, fmt, args...) \
	dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#elif defined(DEBUG)
#define drbd_dbg(device, fmt, args...) \
	drbd_printk(KERN_DEBUG, device, fmt, ## args)
#else
#define drbd_dbg(device, fmt, args...) \
	do { if (0) drbd_printk(KERN_DEBUG, device, fmt, ## args); } while (0)
#endif

#if defined(dynamic_dev_dbg) && defined(disk_to_dev)
#define dynamic_drbd_dbg(device, fmt, args...) \
	dynamic_dev_dbg(disk_to_dev(device->vdisk), fmt, ## args)
#else
#define dynamic_drbd_dbg(device, fmt, args...) \
	drbd_dbg(device, fmt, ## args)
#endif

#define drbd_alert(device, fmt, args...) \
	drbd_printk(KERN_ALERT, device, fmt, ## args)
#define drbd_err(device, fmt, args...) \
	drbd_printk(KERN_ERR, device, fmt, ## args)
#define drbd_warn(device, fmt, args...) \
	drbd_printk(KERN_WARNING, device, fmt, ## args)
#define drbd_info(device, fmt, args...) \
	drbd_printk(KERN_INFO, device, fmt, ## args)

/* see kernel/printk.c:printk_ratelimit
 * macro, so it is easy do have independent rate limits at different locations
 * "initializer element not constant ..." with kernel 2.4 :(
 * so I initialize toks to something large
 */
#define DRBD_ratelimit(ratelimit_jiffies, ratelimit_burst)	\
({								\
	int __ret;						\
	static unsigned long toks = 0x80000000UL;		\
	static unsigned long last_msg;				\
	static int missed;					\
	unsigned long now = jiffies;				\
	toks += now - last_msg;					\
	last_msg = now;						\
	if (toks > (ratelimit_burst * ratelimit_jiffies))	\
		toks = ratelimit_burst * ratelimit_jiffies;	\
	if (toks >= ratelimit_jiffies) {			\
		int lost = missed;				\
		missed = 0;					\
		toks -= ratelimit_jiffies;			\
		if (lost)					\
			drbd_warn(device, "%d messages suppressed in %s:%d.\n", \
				lost, __FILE__, __LINE__);	\
		__ret = 1;					\
	} else {						\
		missed++;					\
		__ret = 0;					\
	}							\
	__ret;							\
})

# define D_ASSERT(device, exp)	if (!(exp)) \
	 drbd_err(device, "ASSERT( " #exp " ) in %s:%d\n", __FILE__, __LINE__)

/**
 * expect  -  Make an assertion
 *
 * Unlike the assert macro, this macro returns a boolean result.
 */
#define expect(exp) ({								\
		bool _bool = (exp);						\
		if (!_bool)							\
			drbd_err(device, "ASSERTION %s FAILED in %s\n",		\
			        #exp, __func__);				\
		_bool;								\
		})

/* Defines to control fault insertion */
enum {
	DRBD_FAULT_MD_WR = 0,	/* meta data write */
	DRBD_FAULT_MD_RD = 1,	/*           read  */
	DRBD_FAULT_RS_WR = 2,	/* resync          */
	DRBD_FAULT_RS_RD = 3,
	DRBD_FAULT_DT_WR = 4,	/* data            */
	DRBD_FAULT_DT_RD = 5,
	DRBD_FAULT_DT_RA = 6,	/* data read ahead */
	DRBD_FAULT_BM_ALLOC = 7,	/* bitmap allocation */
	DRBD_FAULT_AL_EE = 8,	/* alloc ee */
	DRBD_FAULT_RECEIVE = 9, /* Changes some bytes upon receiving a [rs]data block */

	DRBD_FAULT_MAX,
};

extern unsigned int
_drbd_insert_fault(struct drbd_device *device, unsigned int type);

static inline int
drbd_insert_fault(struct drbd_device *device, unsigned int type) {
#ifdef DRBD_ENABLE_FAULTS
	return fault_rate &&
		(enable_faults & (1<<type)) &&
		_drbd_insert_fault(device, type);
#else
	return 0;
#endif
}

/*
 * our structs
 *************************/

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct drbd_device*, x); \
	  (x)->magic = (long)(x) ^ DRBD_MAGIC; })
#define IS_VALID_MDEV(x)  \
	(typecheck(struct drbd_device*, x) && \
	  ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)) : 0))

extern struct idr drbd_devices; /* RCU, updates: genl_lock() */
extern struct list_head drbd_resources; /* RCU, updates: genl_lock() */

extern const char *cmdname(enum drbd_packet cmd);

/* for sending/receiving the bitmap,
 * possibly in some encoding scheme */
struct bm_xfer_ctx {
	/* "const"
	 * stores total bits and long words
	 * of the bitmap, so we don't need to
	 * call the accessor functions over and again. */
	unsigned long bm_bits;
	unsigned long bm_words;
	/* during xfer, current position within the bitmap */
	unsigned long bit_offset;
	unsigned long word_offset;

	/* statistics; index: (h->command == P_BITMAP) */
	unsigned packets[2];
	unsigned bytes[2];
};

extern void INFO_bm_xfer_stats(struct drbd_device *device,
		const char *direction, struct bm_xfer_ctx *c);

static inline void bm_xfer_ctx_bit_to_word_offset(struct bm_xfer_ctx *c)
{
	/* word_offset counts "native long words" (32 or 64 bit),
	 * aligned at 64 bit.
	 * Encoded packet may end at an unaligned bit offset.
	 * In case a fallback clear text packet is transmitted in
	 * between, we adjust this offset back to the last 64bit
	 * aligned "native long word", which makes coding and decoding
	 * the plain text bitmap much more convenient.  */
#if BITS_PER_LONG == 64
	c->word_offset = c->bit_offset >> 6;
#elif BITS_PER_LONG == 32
	c->word_offset = c->bit_offset >> 5;
	c->word_offset &= ~(1UL);
#else
# error "unsupported BITS_PER_LONG"
#endif
}

extern unsigned int drbd_header_size(struct drbd_connection *connection);

/**********************************************************************/
enum drbd_thread_state {
	NONE,
	RUNNING,
	EXITING,
	RESTARTING
};

struct drbd_thread {
	spinlock_t t_lock;
	struct task_struct *task;
	struct completion startstop;
	enum drbd_thread_state t_state;
	int (*function) (struct drbd_thread *);
	struct drbd_connection *connection;
	int reset_cpu_mask;
	char name[9];
};

static inline enum drbd_thread_state get_t_state(struct drbd_thread *thi)
{
	/* THINK testing the t_state seems to be uncritical in all cases
	 * (but thread_{start,stop}), so we can read it *without* the lock.
	 *	--lge */

	smp_rmb();
	return thi->t_state;
}

struct drbd_work {
	struct list_head list;
	int (*cb)(struct drbd_work *, int cancel);
	union {
		struct drbd_device *device;
		struct drbd_connection *connection;
	};
};

#include "drbd_interval.h"

extern int drbd_wait_misc(struct drbd_device *, struct drbd_interval *);
extern bool idr_is_empty(struct idr *idr);

struct drbd_request {
	struct drbd_work w;

	/* if local IO is not allowed, will be NULL.
	 * if local IO _is_ allowed, holds the locally submitted bio clone,
	 * or, after local IO completion, the ERR_PTR(error).
	 * see drbd_request_endio(). */
	struct bio *private_bio;

	struct drbd_interval i;
	unsigned int epoch; /* barrier_nr */

	/* barrier_nr: used to check on "completion" whether this req was in
	 * the current epoch, and we therefore have to close it,
	 * starting a new epoch...
	 */

	struct list_head tl_requests; /* ring list in the transfer log */
	struct bio *master_bio;       /* master bio pointer */
	unsigned long rq_state; /* see comments above _req_mod() */
	int seq_num;
	unsigned long start_time;
};

struct drbd_tl_epoch {
	struct drbd_work w;
	struct list_head requests; /* requests before */
	struct drbd_tl_epoch *next; /* pointer to the next barrier */
	unsigned int br_number;  /* the barriers identifier. */
	int n_writes;	/* number of requests attached before this barrier */
};

struct drbd_epoch {
	struct list_head list;
	unsigned int barrier_nr;
	atomic_t epoch_size; /* increased on every request added. */
	atomic_t active;     /* increased on every req. added, and dec on every finished. */
	unsigned long flags;
};

/* drbd_epoch flag bits */
enum {
	DE_BARRIER_IN_NEXT_EPOCH_ISSUED,
	DE_BARRIER_IN_NEXT_EPOCH_DONE,
	DE_CONTAINS_A_BARRIER,
	DE_HAVE_BARRIER_NUMBER,
	DE_IS_FINISHING,
};

enum epoch_event {
	EV_PUT,
	EV_GOT_BARRIER_NR,
	EV_BARRIER_DONE,
	EV_BECAME_LAST,
	EV_CLEANUP = 32, /* used as flag */
};

struct drbd_wq_barrier {
	struct drbd_work w;
	struct completion done;
};

struct digest_info {
	int digest_size;
	void *digest;
};

struct drbd_peer_request {
	struct drbd_work w;
	struct drbd_epoch *epoch; /* for writes */
	struct page *pages;
	atomic_t pending_bios;
	struct drbd_interval i;
	/* see comments on ee flag bits below */
	unsigned long flags;
	union {
		u64 block_id;
		struct digest_info *digest;
	};
};

/* ee flag bits.
 * While corresponding bios are in flight, the only modification will be
 * set_bit WAS_ERROR, which has to be atomic.
 * If no bios are in flight yet, or all have been completed,
 * non-atomic modification to ee->flags is ok.
 */
enum {
	__EE_CALL_AL_COMPLETE_IO,
	__EE_MAY_SET_IN_SYNC,

	/* This peer request closes an epoch using a barrier.
	 * On successful completion, the epoch is released,
	 * and the P_BARRIER_ACK send. */
	__EE_IS_BARRIER,

	/* In case a barrier failed,
	 * we need to resubmit without the barrier flag. */
	__EE_RESUBMITTED,

	/* we may have several bios per peer request.
	 * if any of those fail, we set this flag atomically
	 * from the endio callback */
	__EE_WAS_ERROR,

	/* This ee has a pointer to a digest instead of a block id */
	__EE_HAS_DIGEST,

	/* Conflicting local requests need to be restarted after this request */
	__EE_RESTART_REQUESTS,

	/* The peer wants a write ACK for this (wire proto C) */
	__EE_SEND_WRITE_ACK,

	/* Is set when net_conf had two_primaries set while creating this peer_req */
	__EE_IN_INTERVAL_TREE,
};
#define EE_CALL_AL_COMPLETE_IO (1<<__EE_CALL_AL_COMPLETE_IO)
#define EE_MAY_SET_IN_SYNC     (1<<__EE_MAY_SET_IN_SYNC)
#define EE_IS_BARRIER          (1<<__EE_IS_BARRIER)
#define	EE_RESUBMITTED         (1<<__EE_RESUBMITTED)
#define EE_WAS_ERROR           (1<<__EE_WAS_ERROR)
#define EE_HAS_DIGEST          (1<<__EE_HAS_DIGEST)
#define EE_RESTART_REQUESTS	(1<<__EE_RESTART_REQUESTS)
#define EE_SEND_WRITE_ACK	(1<<__EE_SEND_WRITE_ACK)
#define EE_IN_INTERVAL_TREE	(1<<__EE_IN_INTERVAL_TREE)

/* flag bits per device */
enum {
	CREATE_BARRIER,		/* next P_DATA is preceded by a P_BARRIER */
	UNPLUG_QUEUED,		/* only relevant with kernel 2.4 */
	UNPLUG_REMOTE,		/* sending a "UnplugRemote" could help */
	MD_DIRTY,		/* current uuids and flags not yet on disk */
	USE_DEGR_WFC_T,		/* degr-wfc-timeout instead of wfc-timeout. */
	CL_ST_CHG_SUCCESS,
	CL_ST_CHG_FAIL,
	CRASHED_PRIMARY,	/* This node was a crashed primary.
				 * Gets cleared when the state.conn
				 * goes into C_CONNECTED state. */
	NO_BARRIER_SUPP,	/* underlying block device doesn't implement barriers */
	CONSIDER_RESYNC,

	MD_NO_BARRIER,		/* meta data device does not support barriers,
				   so don't even try */
	SUSPEND_IO,		/* suspend application io */
	BITMAP_IO,		/* suspend application io;
				   once no more io in flight, start bitmap io */
	BITMAP_IO_QUEUED,       /* Started bitmap IO */
	GO_DISKLESS,		/* Disk is being detached, on io-error or admin request. */
	WAS_IO_ERROR,		/* Local disk failed returned IO error */
	RESYNC_AFTER_NEG,       /* Resync after online grow after the attach&negotiate finished. */
	RESIZE_PENDING,		/* Size change detected locally, waiting for the response from
				 * the peer, if it changed there as well. */
	NEW_CUR_UUID,		/* Create new current UUID when thawing IO */
	AL_SUSPENDED,		/* Activity logging is currently suspended. */
	AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */
	B_RS_H_DONE,		/* Before resync handler done (already executed) */
};

struct drbd_bitmap; /* opaque for drbd_device */

/* definition of bits in bm_flags to be used in drbd_bm_lock
 * and drbd_bitmap_io and friends. */
enum bm_flag {
	/* do we need to kfree, or vfree bm_pages? */
	BM_P_VMALLOCED = 0x10000, /* internal use only, will be masked out */

	/* currently locked for bulk operation */
	BM_LOCKED_MASK = 0x7,

	/* in detail, that is: */
	BM_DONT_CLEAR = 0x1,
	BM_DONT_SET   = 0x2,
	BM_DONT_TEST  = 0x4,

	/* (test bit, count bit) allowed (common case) */
	BM_LOCKED_TEST_ALLOWED = 0x3,

	/* testing bits, as well as setting new bits allowed, but clearing bits
	 * would be unexpected.  Used during bitmap receive.  Setting new bits
	 * requires sending of "out-of-sync" information, though. */
	BM_LOCKED_SET_ALLOWED = 0x1,

	/* clear is not expected while bitmap is locked for bulk operation */
};


/* TODO sort members for performance
 * MAYBE group them further */

/* THINK maybe we actually want to use the default "event/%s" worker threads
 * or similar in linux 2.6, which uses per cpu data and threads.
 */
struct drbd_work_queue {
	struct list_head q;
	struct semaphore s; /* producers up it, worker down()s it */
	spinlock_t q_lock;  /* to protect the list. */
};

/* If Philipp agrees, we remove the "mutex", and make_request will only
 * (throttle on "queue full" condition and) queue it to the worker thread...
 * which then is free to do whatever is needed, and has exclusive send access
 * to the data socket ...
 */
struct drbd_socket {
	struct drbd_work_queue work;
	struct mutex mutex;
	struct socket    *socket;
	/* this way we get our
	 * send/receive buffers off the stack */
	void *sbuf;
	void *rbuf;
};

struct drbd_md {
	u64 md_offset;		/* sector offset to 'super' block */

	u64 la_size_sect;	/* last agreed size, unit sectors */
	u64 uuid[UI_SIZE];
	u64 device_uuid;
	u32 flags;
	u32 md_size_sect;

	s32 al_offset;	/* signed relative sector offset to al area */
	s32 bm_offset;	/* signed relative sector offset to bitmap */

	/* u32 al_nr_extents;	   important for restoring the AL
	 * is stored into  ldev->dc.al_extents, which in turn
	 * gets applied to act_log->nr_elements
	 */
};

struct drbd_backing_dev {
	struct block_device *backing_bdev;
	struct block_device *md_bdev;
	struct drbd_md md;
	struct disk_conf *disk_conf; /* RCU, for updates: resource->conf_update */
	sector_t known_size; /* last known size of that backing device */
};

struct drbd_md_io {
	unsigned int done;
	int error;
};

struct bm_io_work {
	struct drbd_work w;
	char *why;
	enum bm_flag flags;
	int (*io_fn)(struct drbd_device *device);
	void (*done)(struct drbd_device *device, int rv);
};

enum write_ordering_e {
	WO_none,
	WO_drain_io,
	WO_bdev_flush,
	WO_bio_barrier
};

struct fifo_buffer {
	unsigned int head_index;
	unsigned int size;
	int total; /* sum of all values */
	int values[0];
};
extern struct fifo_buffer *fifo_alloc(int fifo_size);

/* flag bits per connection */
enum {
	NET_CONGESTED,		/* The data socket is congested */
	DISCARD_CONCURRENT,	/* Set on one node, cleared on the peer! */
	SEND_PING,		/* whether asender should send a ping asap */
	SIGNAL_ASENDER,		/* whether asender wants to be interrupted */
	GOT_PING_ACK,		/* set when we receive a ping_ack packet, ping_wait gets woken */
	CONN_WD_ST_CHG_OKAY,
	CONN_WD_ST_CHG_FAIL,
	CONN_DRY_RUN,		/* Expect disconnect after resync handshake. */
};

struct drbd_resource {
	char *name;
	struct kref kref;
	struct idr devices;		/* volume number to device mapping */
	struct list_head connections;
	struct list_head resources;
	struct res_opts res_opts;
	struct mutex conf_update;	/* mutex for ready-copy-update of net_conf and disk_conf */
	spinlock_t req_lock;

	unsigned susp:1;		/* IO suspended by user */
	unsigned susp_nod:1;		/* IO suspended because no data */
	unsigned susp_fen:1;		/* IO suspended because fence peer handler runs */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30) && !defined(cpumask_bits)
	cpumask_t cpu_mask[1];
#else
	cpumask_var_t cpu_mask;
#endif
};

struct drbd_connection {			/* is a resource from the config file */
	struct list_head connections;
	struct drbd_resource *resource;
	struct kref kref;
	struct idr peer_devices;	/* volume number to peer device mapping */
	enum drbd_conns cstate;		/* Only C_STANDALONE to C_WF_REPORT_PARAMS */
	struct mutex cstate_mutex;	/* Protects graceful disconnects */

	unsigned long flags;
	struct net_conf *net_conf;	/* content protected by rcu */
	wait_queue_head_t ping_wait;	/* Woken upon reception of a ping, and a state change */

	struct sockaddr_storage my_addr;
	int my_addr_len;
	struct sockaddr_storage peer_addr;
	int peer_addr_len;

	struct drbd_socket data;	/* data/barrier/cstate/parameter packets */
	struct drbd_socket meta;	/* ping/ack (metadata) packets */
	int agreed_pro_version;		/* actually used protocol version */
	unsigned long last_received;	/* in jiffies, either socket */
	unsigned int ko_count;

	struct drbd_tl_epoch *unused_spare_tle; /* for pre-allocation */
	struct drbd_tl_epoch *newest_tle;
	struct drbd_tl_epoch *oldest_tle;
	struct list_head out_of_sequence_requests;
	struct list_head barrier_acked_requests;

	struct crypto_hash *cram_hmac_tfm;
	struct crypto_hash *integrity_tfm;  /* checksums we compute, updates protected by connection->data->mutex */
	struct crypto_hash *peer_integrity_tfm;  /* checksums we verify, only accessed from receiver thread  */
	struct crypto_hash *csums_tfm;
	struct crypto_hash *verify_tfm;
	void *int_dig_in;
	void *int_dig_vv;

	struct drbd_thread receiver;
	struct drbd_thread worker;
	struct drbd_thread asender;
};

struct drbd_peer_device {
	struct list_head peer_devices;
	struct drbd_device *device;
	struct drbd_connection *connection;
};

struct drbd_device {
#ifdef PARANOIA
	long magic;
#endif
	struct drbd_resource *resource;
	struct list_head peer_devices;
	int vnr;			/* volume number within the connection */
	struct kref kref;

	/* things that are stored as / read from meta data on disk */
	unsigned long flags;

	/* configured by drbdsetup */
	struct drbd_backing_dev *ldev __protected_by(local);

	sector_t p_size;     /* partner's disk size */
	struct request_queue *rq_queue;
	struct block_device *this_bdev;
	struct gendisk	    *vdisk;

	struct drbd_work  resync_work,
			  unplug_work,
			  go_diskless,
			  md_sync_work,
			  start_resync_work;
	struct timer_list resync_timer;
	struct timer_list md_sync_timer;
	struct timer_list start_resync_timer;
	struct timer_list request_timer;
#ifdef DRBD_DEBUG_MD_SYNC
	struct {
		unsigned int line;
		const char* func;
	} last_md_mark_dirty;
#endif

	/* Used after attach while negotiating new disk state. */
	union drbd_state new_state_tmp;

	union drbd_dev_state state;
	wait_queue_head_t misc_wait;
	wait_queue_head_t state_wait;  /* upon each state change. */
	unsigned int send_cnt;
	unsigned int recv_cnt;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	unsigned int al_writ_cnt;
	unsigned int bm_writ_cnt;
	atomic_t ap_bio_cnt;	 /* Requests we need to complete */
	atomic_t ap_pending_cnt; /* AP data packets on the wire, ack expected */
	atomic_t rs_pending_cnt; /* RS request/data packets on the wire */
	atomic_t unacked_cnt;	 /* Need to send replies for */
	atomic_t local_cnt;	 /* Waiting for local completion */

	/* Interval trees of pending local requests */
	struct rb_root read_requests;
	struct rb_root write_requests;

	/* blocks to resync in this run [unit BM_BLOCK_SIZE] */
	unsigned long rs_total;
	/* number of resync blocks that failed in this run */
	unsigned long rs_failed;
	/* Syncer's start time [unit jiffies] */
	unsigned long rs_start;
	/* cumulated time in PausedSyncX state [unit jiffies] */
	unsigned long rs_paused;
	/* skipped because csum was equal [unit BM_BLOCK_SIZE] */
	unsigned long rs_same_csum;
#define DRBD_SYNC_MARKS 8
#define DRBD_SYNC_MARK_STEP (3*HZ)
	/* block not up-to-date at mark [unit BM_BLOCK_SIZE] */
	unsigned long rs_mark_left[DRBD_SYNC_MARKS];
	/* marks's time [unit jiffies] */
	unsigned long rs_mark_time[DRBD_SYNC_MARKS];
	/* current index into rs_mark_{left,time} */
	int rs_last_mark;

	/* where does the admin want us to start? (sector) */
	sector_t ov_start_sector;
	/* where are we now? (sector) */
	sector_t ov_position;
	/* Start sector of out of sync range (to merge printk reporting). */
	sector_t ov_last_oos_start;
	/* size of out-of-sync range in sectors. */
	sector_t ov_last_oos_size;
	unsigned long ov_left; /* in bits */

	struct drbd_bitmap *bitmap;
	unsigned long bm_resync_fo; /* bit offset for drbd_bm_find_next */

	/* Used to track operations of resync... */
	struct lru_cache *resync;
	/* Number of locked elements in resync LRU */
	unsigned int resync_locked;
	/* resync extent number waiting for application requests */
	unsigned int resync_wenr;

	int open_cnt;
	u64 *p_uuid;
	/* FIXME clean comments, restructure so it is more obvious which
	 * members are protected by what */
	struct drbd_epoch *current_epoch;
	spinlock_t epoch_lock;
	unsigned int epochs;
	enum write_ordering_e write_ordering;
	struct list_head active_ee; /* IO in progress (P_DATA gets written to disk) */
	struct list_head sync_ee;   /* IO in progress (P_RS_DATA_REPLY gets written to disk) */
	struct list_head done_ee;   /* need to send P_WRITE_ACK */
	struct list_head read_ee;   /* [RS]P_DATA_REQUEST being read */
	struct list_head net_ee;    /* zero-copy network send in progress */

	int next_barrier_nr;
	struct list_head resync_reads;
	atomic_t pp_in_use;		/* allocated from page pool */
	atomic_t pp_in_use_by_net;	/* sendpage()d, still referenced by tcp */
	wait_queue_head_t ee_wait;
	struct page *md_io_page;	/* one page buffer for md_io */
	struct drbd_md_io md_io;
	atomic_t md_io_in_use;		/* protects the md_io, md_io_page and md_io_tmpp */
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache *act_log;	/* activity log */
	unsigned int al_tr_number;
	int al_tr_cycle;
	int al_tr_pos;   /* position of the next transaction in the journal */
	wait_queue_head_t seq_wait;
	atomic_t packet_seq;
	unsigned int peer_seq;
	spinlock_t peer_seq_lock;
	unsigned int minor;
	unsigned long comm_bm_set; /* communicated number of set bits. */
	struct bm_io_work bm_io_work;
	u64 ed_uuid; /* UUID of the exposed data */
	struct mutex own_state_mutex;
	struct mutex *state_mutex; /* either own_state_mutex or first_peer_device(device)->connection->cstate_mutex */
	char congestion_reason;  /* Why we where congested... */
	atomic_t rs_sect_in; /* for incoming resync data rate, SyncTarget */
	atomic_t rs_sect_ev; /* for submitted resync data rate, both */
	int rs_last_sect_ev; /* counter to compare with */
	int rs_last_events;  /* counter of read or write "events" (unit sectors)
			      * on the lower level device when we last looked. */
	int c_sync_rate; /* current resync rate after syncer throttle magic */
	struct fifo_buffer *rs_plan_s; /* correction values of resync planer (RCU, connection->conn_update) */
	int rs_in_flight; /* resync sectors in flight (to proxy, in proxy and from proxy) */
	atomic_t ap_in_flight; /* App sectors in flight (waiting for ack) */
	int peer_max_bio_size;
	int local_max_bio_size;
};

static inline struct drbd_device *minor_to_mdev(unsigned int minor)
{
	return (struct drbd_device *)idr_find(&drbd_devices, minor);
}

static inline struct drbd_peer_device *first_peer_device(struct drbd_device *device)
{
	return list_first_entry(&device->peer_devices, struct drbd_peer_device, peer_devices);
}

#define for_each_resource(resource, _resources) \
	list_for_each_entry(resource, _resources, resources)

#define for_each_resource_rcu(resource, _resources) \
	list_for_each_entry_rcu(resource, _resources, resources)

#define for_each_resource_safe(resource, tmp, _resources) \
	list_for_each_entry_safe(resource, tmp, _resources, resources)

#define for_each_connection(connection, resource) \
	list_for_each_entry(connection, &resource->connections, connections)

#define for_each_connection_rcu(connection, resource) \
	list_for_each_entry_rcu(connection, &resource->connections, connections)

#define for_each_connection_safe(connection, tmp, resource) \
	list_for_each_entry_safe(connection, tmp, &resource->connections, connections)

#define for_each_peer_device(peer_device, device) \
	list_for_each_entry(peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_rcu(peer_device, device) \
	list_for_each_entry_rcu(peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_safe(peer_device, tmp, device) \
	list_for_each_entry_safe(peer_device, tmp, &device->peer_devices, peer_devices)

static inline unsigned int mdev_to_minor(struct drbd_device *device)
{
	return device->minor;
}

static inline struct drbd_device *vnr_to_mdev(struct drbd_connection *connection, int vnr)
{
	struct drbd_peer_device *peer_device;

	peer_device = idr_find(&connection->peer_devices, vnr);
	return peer_device ? peer_device->device : NULL;
}

/*
 * function declarations
 *************************/

/* drbd_main.c */

enum dds_flags {
	DDSF_FORCED    = 1,
	DDSF_NO_RESYNC = 2, /* Do not run a resync for the new space */
};

extern void drbd_init_set_defaults(struct drbd_device *device);
extern int  drbd_thread_start(struct drbd_thread *thi);
extern void _drbd_thread_stop(struct drbd_thread *thi, int restart, int wait);
extern char *drbd_task_to_thread_name(struct drbd_connection *connection, struct task_struct *task);
#ifdef CONFIG_SMP
extern void drbd_thread_current_set_cpu(struct drbd_thread *thi);
#else
#define drbd_thread_current_set_cpu(A) ({})
#endif
extern void tl_release(struct drbd_connection *, unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(struct drbd_connection *);
extern void _tl_add_barrier(struct drbd_connection *, struct drbd_tl_epoch *);
extern void drbd_free_sock(struct drbd_connection *connection);
extern int drbd_send(struct drbd_connection *connection, struct socket *sock,
		     void *buf, size_t size, unsigned msg_flags);
extern int drbd_send_all(struct drbd_connection *, struct socket *, void *, size_t,
			 unsigned);

extern int __drbd_send_protocol(struct drbd_connection *connection, enum drbd_packet cmd);
extern int drbd_send_protocol(struct drbd_connection *connection);
extern int drbd_send_uuids(struct drbd_device *device);
extern int drbd_send_uuids_skip_initial_sync(struct drbd_device *device);
extern void drbd_gen_and_send_sync_uuid(struct drbd_device *device);
extern int drbd_send_sizes(struct drbd_device *device, int trigger_reply, enum dds_flags flags);
extern int _conn_send_state_req(struct drbd_connection *, int vnr, enum drbd_packet cmd,
				union drbd_state, union drbd_state);
#define drbd_send_state(m) drbd_send_state_(m, __func__ , __LINE__ )
extern int drbd_send_state_(struct drbd_device *device, const char *func, unsigned int line);
extern int drbd_send_sync_param(struct drbd_device *device);
extern void drbd_send_b_ack(struct drbd_device *device, u32 barrier_nr,
			    u32 set_size);
extern int drbd_send_ack(struct drbd_device *, enum drbd_packet,
			 struct drbd_peer_request *);
extern void drbd_send_ack_rp(struct drbd_device *device, enum drbd_packet cmd,
			     struct p_block_req *rp);
extern void drbd_send_ack_dp(struct drbd_device *device, enum drbd_packet cmd,
			     struct p_data *dp, int data_size);
extern int drbd_send_ack_ex(struct drbd_device *device, enum drbd_packet cmd,
			    sector_t sector, int blksize, u64 block_id);
extern int drbd_send_out_of_sync(struct drbd_device *, struct drbd_request *);
extern int drbd_send_block(struct drbd_device *, enum drbd_packet,
			   struct drbd_peer_request *);
extern int drbd_send_dblock(struct drbd_device *device, struct drbd_request *req);
extern int drbd_send_drequest(struct drbd_device *device, int cmd,
			      sector_t sector, int size, u64 block_id);
extern int drbd_send_drequest_csum(struct drbd_device *device, sector_t sector,
				   int size, void *digest, int digest_size,
				   enum drbd_packet cmd);
extern int drbd_send_ov_request(struct drbd_device *device,sector_t sector,int size);

extern int drbd_send_bitmap(struct drbd_device *device);
extern void drbd_send_sr_reply(struct drbd_device *device, enum drbd_state_rv retcode);
extern void conn_send_sr_reply(struct drbd_connection *connection, enum drbd_state_rv retcode);
extern void drbd_free_bc(struct drbd_backing_dev *ldev);
extern void drbd_mdev_cleanup(struct drbd_device *device);
void drbd_print_uuids(struct drbd_device *device, const char *text);

extern void drbd_md_sync(struct drbd_device *device);
extern int  drbd_md_read(struct drbd_device *device, struct drbd_backing_dev *bdev);
extern void drbd_uuid_set(struct drbd_device *device, int idx, u64 val) __must_hold(local);
extern void _drbd_uuid_set(struct drbd_device *device, int idx, u64 val) __must_hold(local);
extern void drbd_uuid_new_current(struct drbd_device *device) __must_hold(local);
extern void _drbd_uuid_new_current(struct drbd_device *device) __must_hold(local);
extern void drbd_uuid_set_bm(struct drbd_device *device, u64 val) __must_hold(local);
extern void drbd_md_set_flag(struct drbd_device *device, int flags) __must_hold(local);
extern void drbd_md_clear_flag(struct drbd_device *device, int flags)__must_hold(local);
extern int drbd_md_test_flag(struct drbd_backing_dev *, int);
#ifndef DRBD_DEBUG_MD_SYNC
extern void drbd_md_mark_dirty(struct drbd_device *device);
#else
#define drbd_md_mark_dirty(m)	drbd_md_mark_dirty_(m, __LINE__ , __func__ )
extern void drbd_md_mark_dirty_(struct drbd_device *device,
		unsigned int line, const char *func);
#endif
extern void drbd_queue_bitmap_io(struct drbd_device *device,
				 int (*io_fn)(struct drbd_device *),
				 void (*done)(struct drbd_device *, int),
				 char *why, enum bm_flag flags);
extern int drbd_bitmap_io(struct drbd_device *device,
		int (*io_fn)(struct drbd_device *),
		char *why, enum bm_flag flags);
extern int drbd_bmio_set_n_write(struct drbd_device *device);
extern int drbd_bmio_clear_n_write(struct drbd_device *device);
extern void drbd_go_diskless(struct drbd_device *device);
extern void drbd_ldev_destroy(struct drbd_device *device);

/* Meta data layout
   We reserve a 128MB Block (4k aligned)
   * either at the end of the backing device
   * or on a separate meta data device. */

/* The following numbers are sectors */
/* Allows up to about 3.8TB, so if you want more,
 * you need to use the "flexible" meta data format. */
#define MD_RESERVED_SECT (128LU << 11)  /* 128 MB, unit sectors */
#define MD_AL_OFFSET	8    /* 8 Sectors after start of meta area */
#define MD_AL_SECTORS	64   /* = 32 kB on disk activity log ring buffer */
#define MD_BM_OFFSET (MD_AL_OFFSET + MD_AL_SECTORS)

/* we do all meta data IO in 4k blocks */
#define MD_BLOCK_SHIFT	12
#define MD_BLOCK_SIZE	(1<<MD_BLOCK_SHIFT)

/* One activity log extent represents 4M of storage */
#define AL_EXTENT_SHIFT 22
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SHIFT)

/* We could make these currently hardcoded constants configurable
 * variables at create-md time (or even re-configurable at runtime?).
 * Which will require some more changes to the DRBD "super block"
 * and attach code.
 *
 * updates per transaction:
 *   This many changes to the active set can be logged with one transaction.
 *   This number is arbitrary.
 * context per transaction:
 *   This many context extent numbers are logged with each transaction.
 *   This number is resulting from the transaction block size (4k), the layout
 *   of the transaction header, and the number of updates per transaction.
 *   See drbd_actlog.c:struct al_transaction_on_disk
 * */
#define AL_UPDATES_PER_TRANSACTION	 64	// arbitrary
#define AL_CONTEXT_PER_TRANSACTION	919	// (4096 - 36 - 6*64)/4

#if BITS_PER_LONG == 32
#define LN2_BPL 5
#define cpu_to_lel(A) cpu_to_le32(A)
#define lel_to_cpu(A) le32_to_cpu(A)
#elif BITS_PER_LONG == 64
#define LN2_BPL 6
#define cpu_to_lel(A) cpu_to_le64(A)
#define lel_to_cpu(A) le64_to_cpu(A)
#else
#error "LN2 of BITS_PER_LONG unknown!"
#endif

/* drbd_bitmap.c */
/*
 * We need to store one bit for a block.
 * Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
 * Bit 0 ==> local node thinks this block is binary identical on both nodes
 * Bit 1 ==> local node thinks this block needs to be synced.
 */

#define SLEEP_TIME (HZ/10)

/* We do bitmap IO in units of 4k blocks.
 * We also still have a hardcoded 4k per bit relation. */
#define BM_BLOCK_SHIFT	12			 /* 4k per bit */
#define BM_BLOCK_SIZE	 (1<<BM_BLOCK_SHIFT)
/* mostly arbitrarily set the represented size of one bitmap extent,
 * aka resync extent, to 16 MiB (which is also 512 Byte worth of bitmap
 * at 4k per bit resolution) */
#define BM_EXT_SHIFT	 24	/* 16 MiB per resync extent */
#define BM_EXT_SIZE	 (1<<BM_EXT_SHIFT)

#if (BM_EXT_SHIFT != 24) || (BM_BLOCK_SHIFT != 12)
#error "HAVE YOU FIXED drbdmeta AS WELL??"
#endif

/* thus many _storage_ sectors are described by one bit */
#define BM_SECT_TO_BIT(x)   ((x)>>(BM_BLOCK_SHIFT-9))
#define BM_BIT_TO_SECT(x)   ((sector_t)(x)<<(BM_BLOCK_SHIFT-9))
#define BM_SECT_PER_BIT     BM_BIT_TO_SECT(1)

/* bit to represented kilo byte conversion */
#define Bit2KB(bits) ((bits)<<(BM_BLOCK_SHIFT-10))

/* in which _bitmap_ extent (resp. sector) the bit for a certain
 * _storage_ sector is located in */
#define BM_SECT_TO_EXT(x)   ((x)>>(BM_EXT_SHIFT-9))

/* how much _storage_ sectors we have per bitmap sector */
#define BM_EXT_TO_SECT(x)   ((sector_t)(x) << (BM_EXT_SHIFT-9))
#define BM_SECT_PER_EXT     BM_EXT_TO_SECT(1)

/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SHIFT - AL_EXTENT_SHIFT))
#define BM_WORDS_PER_AL_EXT (1 << (AL_EXTENT_SHIFT-BM_BLOCK_SHIFT-LN2_BPL))

#define BM_BLOCKS_PER_BM_EXT_B (BM_EXT_SHIFT - BM_BLOCK_SHIFT)
#define BM_BLOCKS_PER_BM_EXT_MASK  ((1<<BM_BLOCKS_PER_BM_EXT_B) - 1)

/* the extent in "PER_EXTENT" below is an activity log extent
 * we need that many (long words/bytes) to store the bitmap
 *		     of one AL_EXTENT_SIZE chunk of storage.
 * we can store the bitmap for that many AL_EXTENTS within
 * one sector of the _on_disk_ bitmap:
 * bit	 0	  bit 37   bit 38	     bit (512*8)-1
 *	     ...|........|........|.. // ..|........|
 * sect. 0	 `296	  `304			   ^(512*8*8)-1
 *
#define BM_WORDS_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / BITS_PER_LONG )
#define BM_BYTES_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / 8 )  // 128
#define BM_EXT_PER_SECT	    ( 512 / BM_BYTES_PER_EXTENT )	 //   4
 */

#define DRBD_MAX_SECTORS_32 (0xffffffffLU)
#define DRBD_MAX_SECTORS_BM \
	  ((MD_RESERVED_SECT - MD_BM_OFFSET) * (1LL<<(BM_EXT_SHIFT-9)))
#if DRBD_MAX_SECTORS_BM < DRBD_MAX_SECTORS_32
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_BM
#define DRBD_MAX_SECTORS_FLEX DRBD_MAX_SECTORS_BM
#elif !defined(CONFIG_LBDAF) && !defined(CONFIG_LBD) && BITS_PER_LONG == 32
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_32
#define DRBD_MAX_SECTORS_FLEX DRBD_MAX_SECTORS_32
#else
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_BM
/* 16 TB in units of sectors */
#if BITS_PER_LONG == 32
/* adjust by one page worth of bitmap,
 * so we won't wrap around in drbd_bm_find_next_bit.
 * you should use 64bit OS for that much storage, anyways. */
#define DRBD_MAX_SECTORS_FLEX BM_BIT_TO_SECT(0xffff7fff)
#else
/* we allow up to 1 PiB now on 64bit architecture with "flexible" meta data */
#define DRBD_MAX_SECTORS_FLEX (1UL << 51)
/* corresponds to (1UL << 38) bits right now. */
#endif
#endif

/* BIO_MAX_SIZE is 256 * PAGE_CACHE_SIZE,
 * so for typical PAGE_CACHE_SIZE of 4k, that is (1<<20) Byte.
 * Since we may live in a mixed-platform cluster,
 * we limit us to a platform agnostic constant here for now.
 * A followup commit may allow even bigger BIO sizes,
 * once we thought that through. */
#define DRBD_MAX_BIO_SIZE (1 << 20)
#if DRBD_MAX_BIO_SIZE > BIO_MAX_SIZE
#error Architecture not supported: DRBD_MAX_BIO_SIZE > BIO_MAX_SIZE
#endif
#define DRBD_MAX_BIO_SIZE_SAFE (1 << 12)       /* Works always = 4k */

#define DRBD_MAX_SIZE_H80_PACKET (1 << 15) /* Header 80 only allows packets up to 32KiB data */
#define DRBD_MAX_BIO_SIZE_P95    (1 << 17) /* Protocol 95 to 99 allows bios up to 128KiB */

extern int  drbd_bm_init(struct drbd_device *device);
extern int  drbd_bm_resize(struct drbd_device *device, sector_t sectors, int set_new_bits);
extern void drbd_bm_cleanup(struct drbd_device *device);
extern void drbd_bm_set_all(struct drbd_device *device);
extern void drbd_bm_clear_all(struct drbd_device *device);
/* set/clear/test only a few bits at a time */
extern int  drbd_bm_set_bits(
		struct drbd_device *device, unsigned long s, unsigned long e);
extern int  drbd_bm_clear_bits(
		struct drbd_device *device, unsigned long s, unsigned long e);
extern int drbd_bm_count_bits(
	struct drbd_device *device, const unsigned long s, const unsigned long e);
/* bm_set_bits variant for use while holding drbd_bm_lock,
 * may process the whole bitmap in one go */
extern void _drbd_bm_set_bits(struct drbd_device *device,
		const unsigned long s, const unsigned long e);
extern int  drbd_bm_test_bit(struct drbd_device *device, unsigned long bitnr);
extern int  drbd_bm_e_weight(struct drbd_device *device, unsigned long enr);
extern int  drbd_bm_write_page(struct drbd_device *device, unsigned int idx) __must_hold(local);
extern int  drbd_bm_read(struct drbd_device *device) __must_hold(local);
extern void drbd_bm_mark_for_writeout(struct drbd_device *device, int page_nr);
extern int  drbd_bm_write(struct drbd_device *device) __must_hold(local);
extern int  drbd_bm_write_hinted(struct drbd_device *device) __must_hold(local);
extern unsigned long drbd_bm_ALe_set_all(struct drbd_device *device,
		unsigned long al_enr);
extern size_t	     drbd_bm_words(struct drbd_device *device);
extern unsigned long drbd_bm_bits(struct drbd_device *device);
extern sector_t      drbd_bm_capacity(struct drbd_device *device);

#define DRBD_END_OF_BITMAP	(~(unsigned long)0)
extern unsigned long drbd_bm_find_next(struct drbd_device *device, unsigned long bm_fo);
/* bm_find_next variants for use while you hold drbd_bm_lock() */
extern unsigned long _drbd_bm_find_next(struct drbd_device *device, unsigned long bm_fo);
extern unsigned long _drbd_bm_find_next_zero(struct drbd_device *device, unsigned long bm_fo);
extern unsigned long _drbd_bm_total_weight(struct drbd_device *device);
extern unsigned long drbd_bm_total_weight(struct drbd_device *device);
extern int drbd_bm_rs_done(struct drbd_device *device);
/* for receive_bitmap */
extern void drbd_bm_merge_lel(struct drbd_device *device, size_t offset,
		size_t number, unsigned long *buffer);
/* for _drbd_send_bitmap */
extern void drbd_bm_get_lel(struct drbd_device *device, size_t offset,
		size_t number, unsigned long *buffer);

extern void drbd_bm_lock(struct drbd_device *device, char *why, enum bm_flag flags);
extern void drbd_bm_unlock(struct drbd_device *device);
/* drbd_main.c */

/* needs to be included here,
 * because of kmem_cache_t weirdness */
#include "drbd_wrappers.h"

extern struct kmem_cache *drbd_request_cache;
extern struct kmem_cache *drbd_ee_cache;	/* peer requests */
extern struct kmem_cache *drbd_bm_ext_cache;	/* bitmap extents */
extern struct kmem_cache *drbd_al_ext_cache;	/* activity log extents */
extern mempool_t *drbd_request_mempool;
extern mempool_t *drbd_ee_mempool;

/* drbd's page pool, used to buffer data received from the peer,
 * or data requested by the peer.
 *
 * This does not have an emergency reserve.
 *
 * When allocating from this pool, it first takes pages from the pool.
 * Only if the pool is depleted will try to allocate from the system.
 *
 * The assumption is that pages taken from this pool will be processed,
 * and given back, "quickly", and then can be recycled, so we can avoid
 * frequent calls to alloc_page(), and still will be able to make progress even
 * under memory pressure.
 */
extern struct page *drbd_pp_pool;
extern spinlock_t   drbd_pp_lock;
extern int	    drbd_pp_vacant;
extern wait_queue_head_t drbd_pp_wait;

/* We also need a standard (emergency-reserve backed) page pool
 * for meta data IO (activity log, bitmap).
 * We can keep it global, as long as it is used as "N pages at a time".
 * 128 should be plenty, currently we probably can get away with as few as 1.
 */
#define DRBD_MIN_POOL_PAGES	128
extern mempool_t *drbd_md_io_page_pool;

/* We also need to make sure we get a bio
 * when we need it for housekeeping purposes */
extern struct bio_set *drbd_md_io_bio_set;
/* to allocate from that set */
extern struct bio *bio_alloc_drbd(gfp_t gfp_mask);

extern rwlock_t global_state_lock;

extern int conn_lowest_minor(struct drbd_connection *connection);
enum drbd_ret_code drbd_create_device(struct drbd_resource *resource, unsigned int minor, int vnr);
extern void drbd_destroy_device(struct kref *kref);
extern void drbd_delete_device(struct drbd_device *mdev);

extern struct drbd_resource *drbd_create_resource(const char *name);
extern void drbd_free_resource(struct drbd_resource *resource);

extern int set_resource_options(struct drbd_resource *resource, struct res_opts *res_opts);
extern struct drbd_connection *conn_create(const char *name, struct res_opts *res_opts);
extern void drbd_destroy_connection(struct kref *kref);
extern struct drbd_connection *conn_get_by_addrs(void *my_addr, int my_addr_len,
						 void *peer_addr, int peer_addr_len);
extern struct drbd_resource *drbd_find_resource(const char *name);
extern void drbd_destroy_resource(struct kref *kref);
extern void conn_free_crypto(struct drbd_connection *connection);

extern int proc_details;

/* drbd_req */
extern int __drbd_make_request(struct drbd_device *, struct bio *, unsigned long);
extern int drbd_make_request(struct request_queue *q, struct bio *bio);
extern int drbd_read_remote(struct drbd_device *device, struct drbd_request *req);
extern int drbd_merge_bvec(struct request_queue *q,
#ifdef HAVE_bvec_merge_data
		struct bvec_merge_data *bvm,
#else
		struct bio *bvm,
#endif
		struct bio_vec *bvec);
extern int is_valid_ar_handle(struct drbd_request *, sector_t);


/* drbd_nl.c */
extern int drbd_msg_put_info(const char *info);
extern void drbd_suspend_io(struct drbd_device *device);
extern void drbd_resume_io(struct drbd_device *device);
extern char *ppsize(char *buf, unsigned long long size);
extern sector_t drbd_new_dev_size(struct drbd_device *, struct drbd_backing_dev *, sector_t, int);
enum determine_dev_size { dev_size_error = -1, unchanged = 0, shrunk = 1, grew = 2 };
extern enum determine_dev_size drbd_determine_dev_size(struct drbd_device *, enum dds_flags) __must_hold(local);
extern void resync_after_online_grow(struct drbd_device *);
extern void drbd_reconsider_max_bio_size(struct drbd_device *device);
extern enum drbd_state_rv drbd_set_role(struct drbd_device *device,
					enum drbd_role new_role,
					int force);
extern bool conn_try_outdate_peer(struct drbd_connection *connection);
extern void conn_try_outdate_peer_async(struct drbd_connection *connection);
extern int drbd_khelper(struct drbd_device *device, char *cmd);

/* drbd_worker.c */
extern int drbd_worker(struct drbd_thread *thi);
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int o_minor);
void drbd_resync_after_changed(struct drbd_device *device);
extern void drbd_start_resync(struct drbd_device *device, enum drbd_conns side);
extern void resume_next_sg(struct drbd_device *device);
extern void suspend_other_sg(struct drbd_device *device);
extern int drbd_resync_finished(struct drbd_device *device);
/* maybe rather drbd_main.c ? */
extern void *drbd_md_get_buffer(struct drbd_device *device);
extern void drbd_md_put_buffer(struct drbd_device *device);
extern int drbd_md_sync_page_io(struct drbd_device *device,
		struct drbd_backing_dev *bdev, sector_t sector, int rw);
extern void drbd_ov_out_of_sync_found(struct drbd_device *, sector_t, int);
extern void wait_until_done_or_disk_failure(struct drbd_device *device, unsigned int *done);
extern void drbd_rs_controller_reset(struct drbd_device *device);

static inline void ov_out_of_sync_print(struct drbd_device *device)
{
	if (device->ov_last_oos_size) {
		drbd_err(device, "Out of sync: start=%llu, size=%lu (sectors)\n",
		     (unsigned long long)device->ov_last_oos_start,
		     (unsigned long)device->ov_last_oos_size);
	}
	device->ov_last_oos_size=0;
}


extern void drbd_csum_bio(struct drbd_device *, struct crypto_hash *, struct bio *, void *);
extern void drbd_csum_ee(struct drbd_device *, struct crypto_hash *,
			 struct drbd_peer_request *, void *);
/* worker callbacks */
extern int w_read_retry_remote(struct drbd_work *, int);
extern int w_e_end_data_req(struct drbd_work *, int);
extern int w_e_end_rsdata_req(struct drbd_work *, int);
extern int w_e_end_csum_rs_req(struct drbd_work *, int);
extern int w_e_end_ov_reply(struct drbd_work *, int);
extern int w_e_end_ov_req(struct drbd_work *, int);
extern int w_ov_finished(struct drbd_work *, int);
extern int w_resync_timer(struct drbd_work *, int);
extern int w_send_write_hint(struct drbd_work *, int);
extern int w_make_resync_request(struct drbd_work *, int);
extern int w_send_dblock(struct drbd_work *, int);
extern int w_send_barrier(struct drbd_work *, int);
extern int w_send_read_req(struct drbd_work *, int);
extern int w_prev_work_done(struct drbd_work *, int);
extern int w_e_reissue(struct drbd_work *, int);
extern int w_restart_disk_io(struct drbd_work *, int);
extern int w_send_out_of_sync(struct drbd_work *, int);
extern int w_start_resync(struct drbd_work *, int);

extern void resync_timer_fn(unsigned long data);
extern void start_resync_timer_fn(unsigned long data);

/* drbd_receiver.c */
extern int drbd_receiver(struct drbd_thread *thi);
extern int drbd_asender(struct drbd_thread *thi);
extern int drbd_rs_should_slow_down(struct drbd_device *device, sector_t sector);
extern int drbd_submit_peer_request(struct drbd_device *,
				    struct drbd_peer_request *, const unsigned,
				    const int);
extern int drbd_free_peer_reqs(struct drbd_device *, struct list_head *);
extern struct drbd_peer_request *drbd_alloc_peer_req(struct drbd_device *, u64,
						     sector_t, unsigned int,
						     gfp_t) __must_hold(local);
extern void __drbd_free_peer_req(struct drbd_device *, struct drbd_peer_request *,
				 int);
#define drbd_free_peer_req(m,e) __drbd_free_peer_req(m, e, 0)
#define drbd_free_net_peer_req(m,e) __drbd_free_peer_req(m, e, 1)
extern struct page *drbd_alloc_pages(struct drbd_device *, unsigned int, bool);
extern void drbd_set_recv_tcq(struct drbd_device *device, int tcq_enabled);
extern void _drbd_clear_done_ee(struct drbd_device *device, struct list_head *to_be_freed);
extern void conn_flush_workqueue(struct drbd_connection *connection);
extern int drbd_connected(struct drbd_device *device);
static inline void drbd_flush_workqueue(struct drbd_device *device)
{
	conn_flush_workqueue(first_peer_device(device)->connection);
}

/* Yes, there is kernel_setsockopt, but only since 2.6.18.
 * So we have our own copy of it here. */
static inline int drbd_setsockopt(struct socket *sock, int level, int optname,
				  char *optval, int optlen)
{
	mm_segment_t oldfs = get_fs();
	char __user *uoptval;
	int err;

	uoptval = (char __user __force *)optval;

	set_fs(KERNEL_DS);
	if (level == SOL_SOCKET)
		err = sock_setsockopt(sock, level, optname, uoptval, optlen);
	else
		err = sock->ops->setsockopt(sock, level, optname, uoptval,
					    optlen);
	set_fs(oldfs);
	return err;
}

static inline void drbd_tcp_cork(struct socket *sock)
{
	int val = 1;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_CORK,
			(char*)&val, sizeof(val));
}

static inline void drbd_tcp_uncork(struct socket *sock)
{
	int val = 0;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_CORK,
			(char*)&val, sizeof(val));
}

static inline void drbd_tcp_nodelay(struct socket *sock)
{
	int val = 1;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_NODELAY,
			(char*)&val, sizeof(val));
}

static inline void drbd_tcp_quickack(struct socket *sock)
{
	int val = 2;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_QUICKACK,
			(char*)&val, sizeof(val));
}

void drbd_bump_write_ordering(struct drbd_device *device, enum write_ordering_e wo);

/* drbd_proc.c */
extern struct proc_dir_entry *drbd_proc;
extern const struct file_operations drbd_proc_fops;
extern const char *drbd_conn_str(enum drbd_conns s);
extern const char *drbd_role_str(enum drbd_role s);

/* drbd_actlog.c */
extern void drbd_al_begin_io(struct drbd_device *device, struct drbd_interval *i);
extern void drbd_al_complete_io(struct drbd_device *device, struct drbd_interval *i);
extern void drbd_rs_complete_io(struct drbd_device *device, sector_t sector);
extern int drbd_rs_begin_io(struct drbd_device *device, sector_t sector);
extern int drbd_try_rs_begin_io(struct drbd_device *device, sector_t sector);
extern void drbd_rs_cancel_all(struct drbd_device *device);
extern int drbd_rs_del_all(struct drbd_device *device);
extern void drbd_rs_failed_io(struct drbd_device *device,
		sector_t sector, int size);
extern void drbd_advance_rs_marks(struct drbd_device *device, unsigned long still_to_go);
extern void drbd_set_in_sync(struct drbd_device *device, sector_t sector, int size);
extern int drbd_set_out_of_sync(struct drbd_device *device, sector_t sector, int size);
extern void drbd_al_shrink(struct drbd_device *device);

/* drbd_nl.c */
/* state info broadcast */
struct sib_info {
	enum drbd_state_info_bcast_reason sib_reason;
	union {
		struct {
			char *helper_name;
			unsigned helper_exit_code;
		};
		struct {
			union drbd_state os;
			union drbd_state ns;
		};
	};
};
void drbd_bcast_event(struct drbd_device *device, const struct sib_info *sib);


/*
 * inline helper functions
 *************************/

/* see also page_chain_add and friends in drbd_receiver.c */
static inline struct page *page_chain_next(struct page *page)
{
	return (struct page *)page_private(page);
}
#define page_chain_for_each(page) \
	for (; page && ({ prefetch(page_chain_next(page)); 1; }); \
			page = page_chain_next(page))
#define page_chain_for_each_safe(page, n) \
	for (; page && ({ n = page_chain_next(page); 1; }); page = n)

static inline int drbd_bio_has_active_page(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	__bio_for_each_segment(bvec, bio, i, 0) {
		if (page_count(bvec->bv_page) > 1)
			return 1;
	}

	return 0;
}

static inline int drbd_peer_req_has_active_page(struct drbd_peer_request *peer_req)
{
	struct page *page = peer_req->pages;
	page_chain_for_each(page) {
		if (page_count(page) > 1)
			return 1;
	}
	return 0;
}

static inline enum drbd_state_rv
_drbd_set_state(struct drbd_device *device, union drbd_state ns,
		enum chg_state_flags flags, struct completion *done)
{
	enum drbd_state_rv rv;

	read_lock(&global_state_lock);
	rv = __drbd_set_state(device, ns, flags, done);
	read_unlock(&global_state_lock);

	return rv;
}

static inline union drbd_state drbd_read_state(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	union drbd_state rv;

	rv.i = device->state.i;
	rv.susp = resource->susp;
	rv.susp_nod = resource->susp_nod;
	rv.susp_fen = resource->susp_fen;

	return rv;
}

#define __drbd_chk_io_error(m,f) __drbd_chk_io_error_(m,f, __func__)
static inline void __drbd_chk_io_error_(struct drbd_device *device, int forcedetach, const char *where)
{
	enum drbd_io_error_p ep;

	rcu_read_lock();
	ep = rcu_dereference(device->ldev->disk_conf)->on_io_error;
	rcu_read_unlock();
	switch (ep) {
	case EP_PASS_ON: /* FIXME would this be better named "Ignore"? */
		if (!forcedetach) {
			if (DRBD_ratelimit(5*HZ, 5))
				drbd_err(device, "Local IO failed in %s.\n", where);
			if (device->state.disk > D_INCONSISTENT)
				_drbd_set_state(_NS(device, disk, D_INCONSISTENT), CS_HARD, NULL);
			break;
		}
		/* NOTE fall through to detach case if forcedetach set */
	case EP_DETACH:
	case EP_CALL_HELPER:
		set_bit(WAS_IO_ERROR, &device->flags);
		if (device->state.disk > D_FAILED) {
			_drbd_set_state(_NS(device, disk, D_FAILED), CS_HARD, NULL);
			drbd_err(device,
				"Local IO failed in %s. Detaching...\n", where);
		}
		break;
	}
}

/**
 * drbd_chk_io_error: Handle the on_io_error setting, should be called from all io completion handlers
 * @device:	 DRBD device.
 * @error:	 Error code passed to the IO completion callback
 * @forcedetach: Force detach. I.e. the error happened while accessing the meta data
 *
 * See also drbd_main.c:after_state_ch() if (os.disk > D_FAILED && ns.disk == D_FAILED)
 */
#define drbd_chk_io_error(m,e,f) drbd_chk_io_error_(m,e,f, __func__)
static inline void drbd_chk_io_error_(struct drbd_device *device,
	int error, int forcedetach, const char *where)
{
	if (error) {
		unsigned long flags;
		spin_lock_irqsave(&device->resource->req_lock, flags);
		__drbd_chk_io_error_(device, forcedetach, where);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
	}
}


/**
 * drbd_md_first_sector() - Returns the first sector number of the meta data area
 * @bdev:	Meta data block device.
 *
 * BTW, for internal meta data, this happens to be the maximum capacity
 * we could agree upon with our peer node.
 */
static inline sector_t _drbd_md_first_sector(int meta_dev_idx, struct drbd_backing_dev *bdev)
{
	switch (meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + bdev->md.bm_offset;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset;
	}
}

static inline sector_t drbd_md_first_sector(struct drbd_backing_dev *bdev)
{
	int meta_dev_idx;

	rcu_read_lock();
	meta_dev_idx = rcu_dereference(bdev->disk_conf)->meta_dev_idx;
	rcu_read_unlock();

	return _drbd_md_first_sector(meta_dev_idx, bdev);
}

/**
 * drbd_md_last_sector() - Return the last sector number of the meta data area
 * @bdev:	Meta data block device.
 */
static inline sector_t drbd_md_last_sector(struct drbd_backing_dev *bdev)
{
	int meta_dev_idx;

	rcu_read_lock();
	meta_dev_idx = rcu_dereference(bdev->disk_conf)->meta_dev_idx;
	rcu_read_unlock();

	switch (meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + MD_AL_OFFSET - 1;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect;
	}
}

/**
 * drbd_get_max_capacity() - Returns the capacity we announce to out peer
 * @bdev:	Meta data block device.
 *
 * returns the capacity we announce to out peer.  we clip ourselves at the
 * various MAX_SECTORS, because if we don't, current implementation will
 * oops sooner or later
 */
static inline sector_t drbd_get_max_capacity(struct drbd_backing_dev *bdev)
{
	sector_t s;
	int meta_dev_idx;

	rcu_read_lock();
	meta_dev_idx = rcu_dereference(bdev->disk_conf)->meta_dev_idx;
	rcu_read_unlock();

	switch (meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		s = drbd_get_capacity(bdev->backing_bdev)
			? min_t(sector_t, DRBD_MAX_SECTORS_FLEX,
				_drbd_md_first_sector(meta_dev_idx, bdev))
			: 0;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		s = min_t(sector_t, DRBD_MAX_SECTORS_FLEX,
				drbd_get_capacity(bdev->backing_bdev));
		/* clip at maximum size the meta device can support */
		s = min_t(sector_t, s,
			BM_EXT_TO_SECT(bdev->md.md_size_sect
				     - bdev->md.bm_offset));
		break;
	default:
		s = min_t(sector_t, DRBD_MAX_SECTORS,
				drbd_get_capacity(bdev->backing_bdev));
	}
	return s;
}

/**
 * drbd_md_ss__() - Return the sector number of our meta data super block
 * @device:	DRBD device.
 * @bdev:	Meta data block device.
 */
static inline sector_t drbd_md_ss__(struct drbd_device *device,
				    struct drbd_backing_dev *bdev)
{
	int meta_dev_idx;

	rcu_read_lock();
	meta_dev_idx = rcu_dereference(bdev->disk_conf)->meta_dev_idx;
	rcu_read_unlock();

	switch (meta_dev_idx) {
	default: /* external, some index */
		return MD_RESERVED_SECT * meta_dev_idx;
	case DRBD_MD_INDEX_INTERNAL:
		/* with drbd08, internal meta data is always "flexible" */
	case DRBD_MD_INDEX_FLEX_INT:
		/* sizeof(struct md_on_disk_07) == 4k
		 * position: last 4k aligned block of 4k size */
		if (!bdev->backing_bdev) {
			if (DRBD_ratelimit(5*HZ, 5)) {
				drbd_err(device, "bdev->backing_bdev==NULL\n");
				dump_stack();
			}
			return 0;
		}
		return (drbd_get_capacity(bdev->backing_bdev) & ~7ULL)
			- MD_AL_OFFSET;
	case DRBD_MD_INDEX_FLEX_EXT:
		return 0;
	}
}

static inline void
drbd_queue_work_front(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	up(&q->s);
}

static inline void
drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	up(&q->s);
}

static inline void wake_asender(struct drbd_connection *connection)
{
	if (test_bit(SIGNAL_ASENDER, &connection->flags))
		force_sig(DRBD_SIG, connection->asender.task);
}

static inline void request_ping(struct drbd_connection *connection)
{
	set_bit(SEND_PING, &connection->flags);
	wake_asender(connection);
}

extern void *conn_prepare_command(struct drbd_connection *, struct drbd_socket *);
extern void *drbd_prepare_command(struct drbd_peer_device *, struct drbd_socket *);
extern int conn_send_command(struct drbd_connection *, struct drbd_socket *,
			     enum drbd_packet, unsigned int, void *,
			     unsigned int);
extern int drbd_send_command(struct drbd_peer_device *, struct drbd_socket *,
			     enum drbd_packet, unsigned int, void *,
			     unsigned int);

extern int drbd_send_ping(struct drbd_connection *connection);
extern int drbd_send_ping_ack(struct drbd_connection *connection);
extern int drbd_send_state_req(struct drbd_device *, union drbd_state, union drbd_state);
extern int conn_send_state_req(struct drbd_connection *, union drbd_state, union drbd_state);

static inline void drbd_thread_stop(struct drbd_thread *thi)
{
	_drbd_thread_stop(thi, false, true);
}

static inline void drbd_thread_stop_nowait(struct drbd_thread *thi)
{
	_drbd_thread_stop(thi, false, false);
}

static inline void drbd_thread_restart_nowait(struct drbd_thread *thi)
{
	_drbd_thread_stop(thi, true, false);
}

/* counts how many answer packets packets we expect from our peer,
 * for either explicit application requests,
 * or implicit barrier packets as necessary.
 * increased:
 *  w_send_barrier
 *  _req_mod(req, QUEUE_FOR_NET_WRITE or QUEUE_FOR_NET_READ);
 *    it is much easier and equally valid to count what we queue for the
 *    worker, even before it actually was queued or send.
 *    (drbd_make_request_common; recovery path on read io-error)
 * decreased:
 *  got_BarrierAck (respective tl_clear, tl_clear_barrier)
 *  _req_mod(req, DATA_RECEIVED)
 *     [from receive_DataReply]
 *  _req_mod(req, WRITE_ACKED_BY_PEER or RECV_ACKED_BY_PEER or NEG_ACKED)
 *     [from got_BlockAck (P_WRITE_ACK, P_RECV_ACK)]
 *     FIXME
 *     for some reason it is NOT decreased in got_NegAck,
 *     but in the resulting cleanup code from report_params.
 *     we should try to remember the reason for that...
 *  _req_mod(req, SEND_FAILED or SEND_CANCELED)
 *  _req_mod(req, CONNECTION_LOST_WHILE_PENDING)
 *     [from tl_clear_barrier]
 */
static inline void inc_ap_pending(struct drbd_device *device)
{
	atomic_inc(&device->ap_pending_cnt);
}

#define ERR_IF_CNT_IS_NEGATIVE(which, func, line)			\
	if (atomic_read(&device->which) < 0)				\
		drbd_err(device, "in %s:%d: " #which " = %d < 0 !\n",	\
			func, line,					\
			atomic_read(&device->which))

#define dec_ap_pending(device) _dec_ap_pending(device, __FUNCTION__, __LINE__)
static inline void _dec_ap_pending(struct drbd_device *device, const char *func, int line)
{
	if (atomic_dec_and_test(&device->ap_pending_cnt))
		wake_up(&device->misc_wait);
	ERR_IF_CNT_IS_NEGATIVE(ap_pending_cnt, func, line);
}

/* counts how many resync-related answers we still expect from the peer
 *		     increase			decrease
 * C_SYNC_TARGET sends P_RS_DATA_REQUEST (and expects P_RS_DATA_REPLY)
 * C_SYNC_SOURCE sends P_RS_DATA_REPLY   (and expects P_WRITE_ACK with ID_SYNCER)
 *					   (or P_NEG_ACK with ID_SYNCER)
 */
static inline void inc_rs_pending(struct drbd_device *device)
{
	atomic_inc(&device->rs_pending_cnt);
}

#define dec_rs_pending(device) _dec_rs_pending(device, __FUNCTION__, __LINE__)
static inline void _dec_rs_pending(struct drbd_device *device, const char *func, int line)
{
	atomic_dec(&device->rs_pending_cnt);
	ERR_IF_CNT_IS_NEGATIVE(rs_pending_cnt, func, line);
}

/* counts how many answers we still need to send to the peer.
 * increased on
 *  receive_Data	unless protocol A;
 *			we need to send a P_RECV_ACK (proto B)
 *			or P_WRITE_ACK (proto C)
 *  receive_RSDataReply (recv_resync_read) we need to send a P_WRITE_ACK
 *  receive_DataRequest (receive_RSDataRequest) we need to send back P_DATA
 *  receive_Barrier_*	we need to send a P_BARRIER_ACK
 */
static inline void inc_unacked(struct drbd_device *device)
{
	atomic_inc(&device->unacked_cnt);
}

#define dec_unacked(device) _dec_unacked(device, __FUNCTION__, __LINE__)
static inline void _dec_unacked(struct drbd_device *device, const char *func, int line)
{
	atomic_dec(&device->unacked_cnt);
	ERR_IF_CNT_IS_NEGATIVE(unacked_cnt, func, line);
}

#define sub_unacked(device, n) _sub_unacked(device, n, __FUNCTION__, __LINE__)
static inline void _sub_unacked(struct drbd_device *device, int n, const char *func, int line)
{
	atomic_sub(n, &device->unacked_cnt);
	ERR_IF_CNT_IS_NEGATIVE(unacked_cnt, func, line);
}

/**
 * get_ldev() - Increase the ref count on device->ldev. Returns 0 if there is no ldev
 * @M:		DRBD device.
 *
 * You have to call put_ldev() when finished working with device->ldev.
 */
#define get_ldev(M) __cond_lock(local, _get_ldev_if_state(M,D_INCONSISTENT))
#define get_ldev_if_state(M,MINS) __cond_lock(local, _get_ldev_if_state(M,MINS))

static inline void put_ldev(struct drbd_device *device)
{
	int i = atomic_dec_return(&device->local_cnt);

	/* This may be called from some endio handler,
	 * so we must not sleep here. */

	__release(local);
	D_ASSERT(device, i >= 0);
	if (i == 0) {
		if (device->state.disk == D_DISKLESS)
			/* even internal references gone, safe to destroy */
			drbd_ldev_destroy(device);
		if (device->state.disk == D_FAILED)
			/* all application IO references gone. */
			drbd_go_diskless(device);
		wake_up(&device->misc_wait);
	}
}

#ifndef __CHECKER__
static inline int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins)
{
	int io_allowed;

	/* never get a reference while D_DISKLESS */
	if (device->state.disk == D_DISKLESS)
		return 0;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->state.disk >= mins);
	if (!io_allowed)
		put_ldev(device);
	return io_allowed;
}
#else
extern int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins);
#endif

/* you must have an "get_ldev" reference */
static inline void drbd_get_syncer_progress(struct drbd_device *device,
		unsigned long *bits_left, unsigned int *per_mil_done)
{
	/* this is to break it at compile time when we change that, in case we
	 * want to support more than (1<<32) bits on a 32bit arch. */
	typecheck(unsigned long, device->rs_total);

	/* note: both rs_total and rs_left are in bits, i.e. in
	 * units of BM_BLOCK_SIZE.
	 * for the percentage, we don't care. */

	if (device->state.conn == C_VERIFY_S || device->state.conn == C_VERIFY_T)
		*bits_left = device->ov_left;
	else
		*bits_left = drbd_bm_total_weight(device) - device->rs_failed;
	/* >> 10 to prevent overflow,
	 * +1 to prevent division by zero */
	if (*bits_left > device->rs_total) {
		/* doh. maybe a logic bug somewhere.
		 * may also be just a race condition
		 * between this and a disconnect during sync.
		 * for now, just prevent in-kernel buffer overflow.
		 */
		smp_rmb();
		drbd_warn(device, "cs:%s rs_left=%lu > rs_total=%lu (rs_failed %lu)\n",
				drbd_conn_str(device->state.conn),
				*bits_left, device->rs_total, device->rs_failed);
		*per_mil_done = 0;
	} else {
		/* Make sure the division happens in long context.
		 * We allow up to one petabyte storage right now,
		 * at a granularity of 4k per bit that is 2**38 bits.
		 * After shift right and multiplication by 1000,
		 * this should still fit easily into a 32bit long,
		 * so we don't need a 64bit division on 32bit arch.
		 * Note: currently we don't support such large bitmaps on 32bit
		 * arch anyways, but no harm done to be prepared for it here.
		 */
		unsigned int shift = device->rs_total > UINT_MAX ? 16 : 10;
		unsigned long left = *bits_left >> shift;
		unsigned long total = 1UL + (device->rs_total >> shift);
		unsigned long tmp = 1000UL - left * 1000UL/total;
		*per_mil_done = tmp;
	}
}


/* this throttles on-the-fly application requests
 * according to max_buffers settings;
 * maybe re-implement using semaphores? */
static inline int drbd_get_max_buffers(struct drbd_device *device)
{
	struct net_conf *nc;
	int mxb;

	rcu_read_lock();
	nc = rcu_dereference(first_peer_device(device)->connection->net_conf);
	mxb = nc ? nc->max_buffers : 1000000;  /* arbitrary limit on open requests */
	rcu_read_unlock();

	return mxb;
}

static inline int drbd_state_is_stable(struct drbd_device *device)
{
	union drbd_dev_state s = device->state;

	/* DO NOT add a default clause, we want the compiler to warn us
	 * for any newly introduced state we may have forgotten to add here */

	switch ((enum drbd_conns)s.conn) {
	/* new io only accepted when there is no connection, ... */
	case C_STANDALONE:
	case C_WF_CONNECTION:
	/* ... or there is a well established connection. */
	case C_CONNECTED:
	case C_SYNC_SOURCE:
	case C_SYNC_TARGET:
	case C_VERIFY_S:
	case C_VERIFY_T:
	case C_PAUSED_SYNC_S:
	case C_PAUSED_SYNC_T:
	case C_AHEAD:
	case C_BEHIND:
		/* transitional states, IO allowed */
	case C_DISCONNECTING:
	case C_UNCONNECTED:
	case C_TIMEOUT:
	case C_BROKEN_PIPE:
	case C_NETWORK_FAILURE:
	case C_PROTOCOL_ERROR:
	case C_TEAR_DOWN:
	case C_WF_REPORT_PARAMS:
	case C_STARTING_SYNC_S:
	case C_STARTING_SYNC_T:
		break;

		/* Allow IO in BM exchange states with new protocols */
	case C_WF_BITMAP_S:
		if (first_peer_device(device)->connection->agreed_pro_version < 96)
			return 0;
		break;

		/* no new io accepted in these states */
	case C_WF_BITMAP_T:
	case C_WF_SYNC_UUID:
	case C_MASK:
		/* not "stable" */
		return 0;
	}

	switch ((enum drbd_disk_state)s.disk) {
	case D_DISKLESS:
	case D_INCONSISTENT:
	case D_OUTDATED:
	case D_CONSISTENT:
	case D_UP_TO_DATE:
	case D_FAILED:
		/* disk state is stable as well. */
		break;

	/* no new io accepted during transitional states */
	case D_ATTACHING:
	case D_NEGOTIATING:
	case D_UNKNOWN:
	case D_MASK:
		/* not "stable" */
		return 0;
	}

	return 1;
}

static inline int drbd_suspended(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;

	return resource->susp || resource->susp_fen || resource->susp_nod;
}

static inline bool may_inc_ap_bio(struct drbd_device *device)
{
	int mxb = drbd_get_max_buffers(device);

	if (drbd_suspended(device))
		return false;
	if (test_bit(SUSPEND_IO, &device->flags))
		return false;

	/* to avoid potential deadlock or bitmap corruption,
	 * in various places, we only allow new application io
	 * to start during "stable" states. */

	/* no new io accepted when attaching or detaching the disk */
	if (!drbd_state_is_stable(device))
		return false;

	/* since some older kernels don't have atomic_add_unless,
	 * and we are within the spinlock anyways, we have this workaround.  */
	if (atomic_read(&device->ap_bio_cnt) > mxb)
		return false;
	if (test_bit(BITMAP_IO, &device->flags))
		return false;
	return true;
}

static inline bool inc_ap_bio_cond(struct drbd_device *device)
{
	bool rv = false;

	spin_lock_irq(&device->resource->req_lock);
	rv = may_inc_ap_bio(device);
	if (rv)
		atomic_inc(&device->ap_bio_cnt);
	spin_unlock_irq(&device->resource->req_lock);

	return rv;
}

static inline void inc_ap_bio(struct drbd_device *device)
{
	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection
	 *    handshake as long as we would exceed the max_buffer limit.
	 *
	 * to avoid races with the reconnect code,
	 * we need to atomic_inc within the spinlock. */

	wait_event(device->misc_wait, inc_ap_bio_cond(device));
}

static inline void dec_ap_bio(struct drbd_device *device)
{
	int mxb = drbd_get_max_buffers(device);
	int ap_bio = atomic_dec_return(&device->ap_bio_cnt);

	D_ASSERT(device, ap_bio >= 0);
	/* this currently does wake_up for every dec_ap_bio!
	 * maybe rather introduce some type of hysteresis?
	 * e.g. (ap_bio == mxb/2 || ap_bio == 0) ? */
	if (ap_bio < mxb)
		wake_up(&device->misc_wait);
	if (ap_bio == 0 && test_bit(BITMAP_IO, &device->flags)) {
		if (!test_and_set_bit(BITMAP_IO_QUEUED, &device->flags))
			drbd_queue_work(&first_peer_device(device)->connection->data.work, &device->bm_io_work.w);
	}
}

static inline int drbd_set_ed_uuid(struct drbd_device *device, u64 val)
{
	int changed = device->ed_uuid != val;
	device->ed_uuid = val;
	return changed;
}

static inline int drbd_queue_order_type(struct drbd_device *device)
{
	/* sorry, we currently have no working implementation
	 * of distributed TCQ stuff */
#ifndef QUEUE_ORDERED_NONE
#define QUEUE_ORDERED_NONE 0
#endif
	return QUEUE_ORDERED_NONE;
}

static inline void drbd_md_flush(struct drbd_device *device)
{
	int r;

	if (test_bit(MD_NO_BARRIER, &device->flags))
		return;

	r = blkdev_issue_flush(device->ldev->md_bdev, GFP_KERNEL, NULL);
	if (r) {
		set_bit(MD_NO_BARRIER, &device->flags);
		drbd_err(device, "meta data flush failed with status %d, disabling md-flushes\n", r);
	}
}

/* resync bitmap */
/* 16MB sized 'bitmap extent' to track syncer usage */
struct bm_extent {
	int rs_left; /* number of bits set (out of sync) in this extent. */
	int rs_failed; /* number of failed resync requests in this extent. */
	unsigned long flags;
	struct lc_element lce;
};

#define BME_NO_WRITES  0  /* bm_extent.flags: no more requests on this one! */
#define BME_LOCKED     1  /* bm_extent.flags: syncer active on this one. */
#define BME_PRIORITY   2  /* finish resync IO on this extent ASAP! App IO waiting! */

/* should be moved to idr.h */
/**
 * idr_for_each_entry - iterate over an idr's elements of a given type
 * @idp:     idr handle
 * @entry:   the type * to use as cursor
 * @id:      id entry's key
 */
#define idr_for_each_entry(idp, entry, id)				\
	for (id = 0, entry = (typeof(entry))idr_get_next((idp), &(id)); \
	     entry != NULL;						\
	     ++id, entry = (typeof(entry))idr_get_next((idp), &(id)))

static inline struct drbd_connection *first_connection(struct drbd_resource *resource)
{
	return list_first_entry(&resource->connections, struct drbd_connection, connections);
}

#endif
