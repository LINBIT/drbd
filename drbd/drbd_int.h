/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
  drbd_int.h

  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

  Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
  Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.


*/

#ifndef _DRBD_INT_H
#define _DRBD_INT_H

#include <crypto/hash.h>
#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/ratelimit.h>
#include <linux/mutex.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/genhd.h>
#include <linux/idr.h>
#include <linux/lru_cache.h>
#include <linux/prefetch.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd.h>
#include <linux/drbd_config.h>

#include "drbd_wrappers.h"
#include "drbd_strings.h"
#include "drbd_state.h"
#include "drbd_protocol.h"
#include "drbd_kref_debug.h"
#include "drbd_transport.h"
#include "drbd_polymorph_printk.h"

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

/* module parameter, defined in drbd_main.c */
extern unsigned int drbd_minor_count;
extern unsigned int drbd_protocol_version_min;

#ifdef CONFIG_DRBD_FAULT_INJECTION
extern int drbd_enable_faults;
extern int drbd_fault_rate;
#endif

extern char drbd_usermode_helper[];
enum {
	/* drbd_khelper returns >= 0, we can use negative values as flags for drbd_maybe_khelper */
	DRBD_UMH_DISABLED = INT_MIN,
};

#ifndef DRBD_MAJOR
# define DRBD_MAJOR 147
#endif

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

/* I want to be able to grep for "drbd $resource_name"
 * and get all relevant log lines. */

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
#ifdef CONFIG_DRBD_FAULT_INJECTION
	return drbd_fault_rate &&
		(drbd_enable_faults & (1<<type)) &&
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
extern struct list_head drbd_resources; /* RCU, updates: resources_mutex */
extern struct mutex resources_mutex;

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

extern void INFO_bm_xfer_stats(struct drbd_peer_device *, const char *, struct bm_xfer_ctx *);

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
	struct completion stop;
	enum drbd_thread_state t_state;
	int (*function) (struct drbd_thread *);
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	int reset_cpu_mask;
	const char *name;
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
};

struct drbd_peer_device_work {
	struct drbd_work w;
	struct drbd_peer_device *peer_device;
};

enum drbd_stream;

#include "drbd_interval.h"

extern int drbd_wait_misc(struct drbd_device *, struct drbd_peer_device *, struct drbd_interval *);

extern void lock_all_resources(void);
extern void unlock_all_resources(void);

extern enum drbd_disk_state disk_state_from_md(struct drbd_device *);
extern bool want_bitmap(struct drbd_peer_device *peer_device);
extern long twopc_timeout(struct drbd_resource *);
extern long twopc_retry_timeout(struct drbd_resource *, int);
extern void twopc_connection_down(struct drbd_connection *);
extern u64 directly_connected_nodes(struct drbd_resource *, enum which_state);

/* sequence arithmetic for dagtag (data generation tag) sector numbers.
 * dagtag_newer_eq: true, if a is newer than b */
#define dagtag_newer_eq(a,b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) >= 0))

#define dagtag_newer(a,b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) > 0))

struct drbd_request {
	struct drbd_device *device;

	/* if local IO is not allowed, will be NULL.
	 * if local IO _is_ allowed, holds the locally submitted bio clone,
	 * or, after local IO completion, the ERR_PTR(error).
	 * see drbd_request_endio(). */
	struct bio *private_bio;

	struct drbd_interval i;

	/* epoch: used to check on "completion" whether this req was in
	 * the current epoch, and we therefore have to close it,
	 * causing a p_barrier packet to be send, starting a new epoch.
	 *
	 * This corresponds to "barrier" in struct p_barrier[_ack],
	 * and to "barrier_nr" in struct drbd_epoch (and various
	 * comments/function parameters/local variable names).
	 */
	unsigned int epoch;

	/* Position of this request in the serialized per-resource change
	 * stream. Can be used to serialize with other events when
	 * communicating the change stream via multiple connections.
	 * Assigned from device->resource->dagtag_sector.
	 *
	 * Given that some IO backends write several GB per second meanwhile,
	 * lets just use a 64bit sequence space. */
	u64 dagtag_sector;

	struct list_head tl_requests; /* ring list in the transfer log */
	struct bio *master_bio;       /* master bio pointer */

	/* see struct drbd_device */
	struct list_head req_pending_master_completion;
	struct list_head req_pending_local;

	/* for generic IO accounting */
	unsigned long start_jif;

	/* for request_timer_fn() */
	unsigned long pre_submit_jif;
	unsigned long pre_send_jif[DRBD_PEERS_MAX];

#ifdef CONFIG_DRBD_TIMING_STATS
	/* for DRBD internal statistics */
	ktime_t start_kt;

	/* before actual request processing */
	ktime_t in_actlog_kt;

	/* local disk */
	ktime_t pre_submit_kt;

	/* per connection */
	ktime_t pre_send_kt[DRBD_PEERS_MAX];
	ktime_t acked_kt[DRBD_PEERS_MAX];
	ktime_t net_done_kt[DRBD_PEERS_MAX];
#endif
	/* Possibly even more detail to track each phase:
	 *  master_completion_kt
	 *      how long did it take to complete the master bio
	 *      (application visible latency)
	 *  allocated_kt
	 *      how long the master bio was blocked until we finally allocated
	 *      a tracking struct
	 *  in_actlog_kt
	 *      how long did we wait for activity log transactions
	 *
	 *  net_queued_kt
	 *      when did we finally queue it for sending
	 *  pre_send_kt
	 *      when did we start sending it
	 *  post_send_kt
	 *      how long did we block in the network stack trying to send it
	 *  acked_kt
	 *      when did we receive (or fake, in protocol A) a remote ACK
	 *  net_done_kt
	 *      when did we receive final acknowledgement (P_BARRIER_ACK),
	 *      or decide, e.g. on connection loss, that we do no longer expect
	 *      anything from this peer for this request.
	 *
	 *  pre_submit_kt
	 *  post_sub_kt
	 *      when did we start submiting to the lower level device,
	 *      and how long did we block in that submit function
	 *  local_completion_kt
	 *      how long did it take the lower level device to complete this request
	 */


	/* once it hits 0, we may complete the master_bio */
	atomic_t completion_ref;
	/* once it hits 0, we may destroy this drbd_request object */
	struct kref kref;

	/* If not NULL, destruction of this drbd_request will
	 * cause kref_put() on ->destroy_next. */
	struct drbd_request *destroy_next;

	unsigned int local_rq_state;
	u16 net_rq_state[DRBD_NODE_ID_MAX];
};

struct drbd_epoch {
	struct drbd_connection *connection;
	struct drbd_peer_request *oldest_unconfirmed_peer_req;
	struct list_head list;
	unsigned int barrier_nr;
	atomic_t epoch_size; /* increased on every request added. */
	atomic_t active;     /* increased on every req. added, and dec on every finished. */
	atomic_t confirmed;  /* adjusted for every P_CONFIRM_STABLE */
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

struct digest_info {
	int digest_size;
	void *digest;
};

struct drbd_peer_request {
	struct drbd_work w;
	struct drbd_peer_device *peer_device;
	struct list_head recv_order; /* writes only */
	/* writes only, blocked on activity log;
	 * FIXME merge with rcv_order or w.list? */
	struct list_head wait_for_actlog;

	struct drbd_page_chain_head page_chain;
	unsigned int opf; /* to be used as bi_opf */
	atomic_t pending_bios;
	struct drbd_interval i;
	unsigned long flags;	/* see comments on ee flag bits below */
	union {
		struct { /* regular peer_request */
			struct drbd_epoch *epoch; /* for writes */
			unsigned long submit_jif;
			union {
				u64 block_id;
				struct digest_info *digest;
			};
			u64 dagtag_sector;

		};
		struct { /* reused object to queue send OOS to other nodes */
			u64 sent_oos_nodes; /* Used to notify L_SYNC_TARGETs about new out_of_sync bits */
			struct drbd_peer_device *send_oos_peer_device;
			u64 send_oos_in_sync;
		};
	};
};

/* Equivalent to bio_op and req_op. */
#define peer_req_op(peer_req) \
	((peer_req)->opf & REQ_OP_MASK)

/* ee flag bits.
 * While corresponding bios are in flight, the only modification will be
 * set_bit WAS_ERROR, which has to be atomic.
 * If no bios are in flight yet, or all have been completed,
 * non-atomic modification to ee->flags is ok.
 */
enum {
	/* If successfully written,
	 * we may clear the corresponding out-of-sync bits */
	__EE_MAY_SET_IN_SYNC,

	/* Peer did not write this one, we must set-out-of-sync
	 * before actually submitting ourselves */
	__EE_SET_OUT_OF_SYNC,

	/* This peer request closes an epoch using a barrier.
	 * On successful completion, the epoch is released,
	 * and the P_BARRIER_ACK send. */
	__EE_IS_BARRIER,

	/* is this a TRIM aka REQ_OP_DISCARD? */
	__EE_TRIM,
	/* explicit zero-out requested, or
	 * our lower level cannot handle trim,
	 * and we want to fall back to zeroout instead */
	__EE_ZEROOUT,

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

	/* for debugfs: */
	/* has this been submitted, or does it still wait for something else? */
	__EE_SUBMITTED,

	/* this is/was a write request */
	__EE_WRITE,

	/* this is/was a write same request */
	__EE_WRITE_SAME,

	/* this originates from application on peer
	 * (not some resync or verify or other DRBD internal request) */
	__EE_APPLICATION,

	/* If it contains only 0 bytes, send back P_RS_DEALLOCATED */
	__EE_RS_THIN_REQ,

	/* Hold reference in activity log */
	__EE_IN_ACTLOG,
};
#define EE_MAY_SET_IN_SYNC     (1<<__EE_MAY_SET_IN_SYNC)
#define EE_SET_OUT_OF_SYNC     (1<<__EE_SET_OUT_OF_SYNC)
#define EE_IS_BARRIER          (1<<__EE_IS_BARRIER)
#define EE_TRIM                (1<<__EE_TRIM)
#define EE_ZEROOUT             (1<<__EE_ZEROOUT)
#define EE_RESUBMITTED         (1<<__EE_RESUBMITTED)
#define EE_WAS_ERROR           (1<<__EE_WAS_ERROR)
#define EE_HAS_DIGEST          (1<<__EE_HAS_DIGEST)
#define EE_RESTART_REQUESTS	(1<<__EE_RESTART_REQUESTS)
#define EE_SEND_WRITE_ACK	(1<<__EE_SEND_WRITE_ACK)
#define EE_IN_INTERVAL_TREE	(1<<__EE_IN_INTERVAL_TREE)
#define EE_SUBMITTED		(1<<__EE_SUBMITTED)
#define EE_WRITE		(1<<__EE_WRITE)
#define EE_WRITE_SAME		(1<<__EE_WRITE_SAME)
#define EE_APPLICATION		(1<<__EE_APPLICATION)
#define EE_RS_THIN_REQ		(1<<__EE_RS_THIN_REQ)
#define EE_IN_ACTLOG		(1<<__EE_IN_ACTLOG)

/* flag bits per device */
enum device_flag {
	UNPLUG_QUEUED,		/* only relevant with kernel 2.4 */
	UNPLUG_REMOTE,		/* sending a "UnplugRemote" could help */
	MD_DIRTY,		/* current uuids and flags not yet on disk */
	CRASHED_PRIMARY,	/* This node was a crashed primary.
				 * Gets cleared when the state.conn
				 * goes into L_ESTABLISHED state. */
	MD_NO_FUA,		/* meta data device does not support barriers,
				   so don't even try */
	WAS_READ_ERROR,		/* Local disk READ failed, returned IO error */
	FORCE_DETACH,		/* Force-detach from local disk, aborting any pending local IO */
	NEW_CUR_UUID,		/* Create new current UUID when thawing IO or issuing local IO */
	__NEW_CUR_UUID,		/* Set NEW_CUR_UUID as soon as state change visible */
	WRITING_NEW_CUR_UUID,	/* Set while the new current ID gets generated. */
	AL_SUSPENDED,		/* Activity logging is currently suspended. */
	UNREGISTERED,
	FLUSH_PENDING,		/* if set, device->flush_jif is when we submitted that flush
				 * from drbd_flush_after_epoch() */

        /* cleared only after backing device related structures have been destroyed. */
        GOING_DISKLESS,         /* Disk is being detached, because of io-error, or admin request. */

        /* to be used in drbd_device_post_work() */
        GO_DISKLESS,            /* tell worker to schedule cleanup before detach */
        DESTROY_DISK,           /* tell worker to close backing devices and destroy related structures. */
	MD_SYNC,		/* tell worker to call drbd_md_sync() */
	MAKE_NEW_CUR_UUID,	/* tell worker to ping peers and eventually write new current uuid */

	STABLE_RESYNC,		/* One peer_device finished the resync stable! */
	READ_BALANCE_RR,
	PRIMARY_LOST_QUORUM,
	TIEBREAKER_QUORUM,	/* Tiebreaker keeps quorum; used to avoid too verbose logging */
	DESTROYING_DEV,
	TRY_TO_GET_RESYNC,
};

/* flag bits per peer device */
enum peer_device_flag {
	CONSIDER_RESYNC,
	RESYNC_AFTER_NEG,       /* Resync after online grow after the attach&negotiate finished. */
	RESIZE_PENDING,		/* Size change detected locally, waiting for the response from
				 * the peer, if it changed there as well. */
	RS_START,		/* tell worker to start resync/OV */
	RS_PROGRESS,		/* tell worker that resync made significant progress */
	RS_LAZY_BM_WRITE,	/*  -"- and bitmap writeout should be efficient now */
	RS_DONE,		/* tell worker that resync is done */
	B_RS_H_DONE,		/* Before resync handler done (already executed) */
	DISCARD_MY_DATA,	/* discard_my_data flag per volume */
	USE_DEGR_WFC_T,		/* degr-wfc-timeout instead of wfc-timeout. */
	INITIAL_STATE_SENT,
	INITIAL_STATE_RECEIVED,
	INITIAL_STATE_PROCESSED,
	RECONCILIATION_RESYNC,
	UNSTABLE_RESYNC,	/* Sync source went unstable during resync. */
	SEND_STATE_AFTER_AHEAD,
	GOT_NEG_ACK,		/* got a neg_ack while primary, wait until peer_disk is lower than
				   D_UP_TO_DATE before becoming secondary! */
	AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */
	SYNC_TARGET_TO_BEHIND,  /* SyncTarget, wait for Behind */
	HOLDING_UUID_READ_LOCK, /* did a down_read(&device->uuid_sem) */
	RS_SOURCE_MISSED_END,   /* SyncSource did not got P_UUIDS110 */
	RS_PEER_MISSED_END,     /* Peer (which was SyncSource) did not got P_UUIDS110 after resync */
	SYNC_SRC_CRASHED_PRI,   /* Source of this resync was a crashed primary */
	HAVE_SIZES,		/* Cleared when connection gets lost; set when sizes received */
};

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

/* definition of bits in bm_flags to be used in drbd_bm_lock
 * and drbd_bitmap_io and friends. */
enum bm_flag {
	/*
	 * The bitmap can be locked to prevent others from clearing, setting,
	 * and/or testing bits.  The following combinations of lock flags make
	 * sense:
	 *
	 *   BM_LOCK_CLEAR,
	 *   BM_LOCK_SET, | BM_LOCK_CLEAR,
	 *   BM_LOCK_TEST | BM_LOCK_SET | BM_LOCK_CLEAR.
	 */

	BM_LOCK_TEST = 0x1,
	BM_LOCK_SET = 0x2,
	BM_LOCK_CLEAR = 0x4,
	BM_LOCK_BULK = 0x8, /* locked for bulk operation, allow all non-bulk operations */

	BM_LOCK_ALL = BM_LOCK_TEST | BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,

	BM_LOCK_SINGLE_SLOT = 0x10,
	BM_ON_DAX_PMEM = 0x10000,
};

struct drbd_bitmap {
	union {
		struct page **bm_pages;
		void *bm_on_pmem;
	};
	spinlock_t bm_lock;

	unsigned long bm_set[DRBD_PEERS_MAX]; /* number of bits set */
	unsigned long bm_bits;  /* bits per peer */
	size_t   bm_words; /* platform specitif word size; not 32bit!! */
	size_t   bm_number_of_pages;
	sector_t bm_dev_capacity;
	struct mutex bm_change; /* serializes resize operations */

	wait_queue_head_t bm_io_wait; /* used to serialize IO of single pages */

	enum bm_flag bm_flags;
	unsigned int bm_max_peers;

	/* exclusively to be used by __al_write_transaction(),
	 * and drbd_bm_write_hinted() -> bm_rw() called from there.
	 * One activity log extent represents 4MB of storage, which are 1024
	 * bits (at 4k per bit), times at most DRBD_PEERS_MAX (currently 32).
	 * The bitmap is created interleaved, with a potentially odd number
	 * of peer slots determined at create-md time.  Which means that one
	 * AL-extent may be associated with one or two bitmap pages.
	 */
	unsigned int n_bitmap_hints;
	unsigned int al_bitmap_hints[2*AL_UPDATES_PER_TRANSACTION];

	/* debugging aid, in case we are still racy somewhere */
	char          *bm_why;
	char          bm_task_comm[TASK_COMM_LEN];
	pid_t         bm_task_pid;
	struct drbd_peer_device *bm_locked_peer;
};

struct drbd_work_queue {
	struct list_head q;
	spinlock_t q_lock;  /* to protect the list. */
	wait_queue_head_t q_wait;
};

struct drbd_peer_md {
	u64 bitmap_uuid;
	u64 bitmap_dagtag;
	u32 flags;
	s32 bitmap_index;
};

struct drbd_md {
	u64 md_offset;		/* sector offset to 'super' block */

	u64 effective_size;	/* last agreed size (sectors) */
	spinlock_t uuid_lock;
	u64 current_uuid;
	u64 device_uuid;
	u32 flags;
	s32 node_id;
	u32 md_size_sect;

	s32 al_offset;	/* signed relative sector offset to activity log */
	s32 bm_offset;	/* signed relative sector offset to bitmap */

	struct drbd_peer_md peers[DRBD_NODE_ID_MAX];
	u64 history_uuids[HISTORY_UUIDS];

	/* cached value of bdev->disk_conf->meta_dev_idx */
	s32 meta_dev_idx;

	/* see al_tr_number_to_on_disk_sector() */
	u32 al_stripes;
	u32 al_stripe_size_4k;
	u32 al_size_4k; /* cached product of the above */
};

struct drbd_backing_dev {
	struct block_device *backing_bdev;
	struct block_device *md_bdev;
	struct drbd_md md;
	struct disk_conf *disk_conf; /* RCU, for updates: resource->conf_update */
	sector_t known_size; /* last known size of that backing device */
#if IS_ENABLED(CONFIG_DEV_DAX_PMEM) && !defined(DAX_PMEM_IS_INCOMPLETE)
	struct dax_device *dax_dev;
	struct meta_data_on_disk_9 *md_on_pmem; /* address of md_offset */
	struct al_on_pmem *al_on_pmem;
#endif
};

struct drbd_md_io {
	struct page *page;
	unsigned long start_jif;	/* last call to drbd_md_get_buffer */
	unsigned long submit_jif;	/* last _drbd_md_sync_page_io() submit */
	const char *current_use;
	atomic_t in_use;
	unsigned int done;
	int error;
};

struct bm_io_work {
	struct drbd_work w;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device;
	char *why;
	enum bm_flag flags;
	int (*io_fn)(struct drbd_device *, struct drbd_peer_device *);
	void (*done)(struct drbd_device *device, struct drbd_peer_device *, int rv);
};

struct fifo_buffer {
	/* singly linked list to accumulate multiple such struct fifo_buffers,
	 * to be freed after a single syncronize_rcu(),
	 * outside a critical section. */
	struct fifo_buffer *next;
	unsigned int head_index;
	unsigned int size;
	int total; /* sum of all values */
	int values[];
};
extern struct fifo_buffer *fifo_alloc(unsigned int fifo_size);

/* flag bits per connection */
enum connection_flag {
	SEND_PING,
	GOT_PING_ACK,		/* set when we receive a ping_ack packet, state_wait gets woken */
	TWOPC_PREPARED,
	TWOPC_YES,
	TWOPC_NO,
	TWOPC_RETRY,
	CONN_DRY_RUN,		/* Expect disconnect after resync handshake. */
	CREATE_BARRIER,		/* next P_DATA is preceded by a P_BARRIER */
	DISCONNECT_EXPECTED,
	BARRIER_ACK_PENDING,
	CORKED,
	DATA_CORKED = CORKED,
	CONTROL_CORKED,
	C_UNREGISTERED,
	RECONNECT,
	CONN_DISCARD_MY_DATA,
	SEND_STATE_AFTER_AHEAD_C,
	NOTIFY_PEERS_LOST_PRIMARY,
	CHECKING_PEER,		/* used by make_new_urrent_uuid() to check liveliness */
	CONN_CONGESTED,
	CONN_HANDSHAKE_DISCONNECT,
	CONN_HANDSHAKE_RETRY,
	CONN_HANDSHAKE_READY,
};

/* flag bits per resource */
enum resource_flag {
	EXPLICIT_PRIMARY,
	CALLBACK_PENDING,	/* Whether we have a call_usermodehelper(, UMH_WAIT_PROC)
				 * pending, from drbd worker context.
				 * If set, bdi_write_congested() returns true,
				 * so shrink_page_list() would not recurse into,
				 * and potentially deadlock on, this drbd worker.
				 */
	TWOPC_ABORT_LOCAL,
	TWOPC_EXECUTED,         /* Commited or aborted */
	TWOPC_STATE_CHANGE_PENDING, /* set between sending commit and changing local state */
	DEVICE_WORK_PENDING,	/* tell worker that some device has pending work */
	PEER_DEVICE_WORK_PENDING,/* tell worker that some peer_device has pending work */
	RESOURCE_WORK_PENDING,  /* tell worker that some peer_device has pending work */

        /* to be used in drbd_post_work() */
	TRY_BECOME_UP_TO_DATE,  /* try to become D_UP_TO_DATE */
	R_UNREGISTERED,
	DOWN_IN_PROGRESS,
	CHECKING_PEERS,
};

enum which_state { NOW, OLD = NOW, NEW };

enum twopc_type {
	TWOPC_STATE_CHANGE,
	TWOPC_RESIZE,
};

struct twopc_reply {
	int vnr;
	unsigned int tid;  /* transaction identifier */
	int initiator_node_id;  /* initiator of the transaction */
	int target_node_id;  /* target of the transaction (or -1) */
	u64 target_reachable_nodes;  /* behind the target node */
	u64 reachable_nodes;  /* behind other nodes */
	union {
		struct { /* type == TWOPC_STATE_CHANGE */
			u64 primary_nodes;
			u64 weak_nodes;
		};
		struct { /* type == TWOPC_RESIZE */
			u64 diskful_primary_nodes;
			u64 max_possible_size;
		};
	};
	unsigned int is_disconnect:1;
	unsigned int is_connect:1;
	unsigned int is_aborted:1;
	/* Whether the state change on receiving the twopc failed. When this is
	 * a twopc for transitioning to C_CONNECTED, we cannot immediately
	 * reply with P_TWOPC_NO. The state handshake must complete first to
	 * decide the appropriate reply. */
	unsigned int state_change_failed:1;
};

struct drbd_thread_timing_details
{
	unsigned long start_jif;
	void *cb_addr;
	const char *caller_fn;
	unsigned int line;
	unsigned int cb_nr;
};
#define DRBD_THREAD_DETAILS_HIST	16

struct drbd_send_buffer {
	struct page *page;  /* current buffer page for sending data */
	char *unsent;  /* start of unsent area != pos if corked... */
	char *pos; /* position within that page */
	int allocated_size; /* currently allocated space */
	int additional_size;  /* additional space to be added to next packet's size */
};


struct drbd_resource {
	char *name;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_res;
	struct dentry *debugfs_res_volumes;
	struct dentry *debugfs_res_connections;
	struct dentry *debugfs_res_in_flight_summary;
	struct dentry *debugfs_res_state_twopc;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr devices;		/* volume number to device mapping */
	struct list_head connections;
	struct list_head resources;
	struct res_opts res_opts;
	int max_node_id;
	struct mutex conf_update;	/* for ready-copy-update of net_conf and disk_conf
					   and devices, connection and peer_devices lists */
	struct mutex adm_mutex;		/* mutex to serialize administrative requests */
	struct mutex open_release;	/* serialize open/release */
	spinlock_t req_lock;
	u64 dagtag_sector;		/* Protected by req_lock.
					 * See also dagtag_sector in
					 * &drbd_request */
	unsigned long flags;

	struct list_head transfer_log;	/* all requests not yet fully processed */

	struct list_head peer_ack_list;  /* requests to send peer acks for */
	u64 last_peer_acked_dagtag;  /* dagtag of last PEER_ACK'ed request */
	struct drbd_request *peer_ack_req;  /* last request not yet PEER_ACK'ed */

	struct semaphore state_sem;
	wait_queue_head_t state_wait;  /* upon each state change. */
	enum chg_state_flags state_change_flags;
	const char **state_change_err_str;
	bool remote_state_change;  /* remote state change in progress */
	enum twopc_type twopc_type; /* from prepare phase */
	enum drbd_packet twopc_prepare_reply_cmd; /* this node's answer to the prepare phase or 0 */
	struct list_head twopc_parents;  /* prepared on behalf of peer */
	u64 twopc_parent_nodes;
	struct twopc_reply twopc_reply;
	struct timer_list twopc_timer;
	struct drbd_work twopc_work;
	wait_queue_head_t twopc_wait;
	struct twopc_resize {
		int dds_flags;            /* from prepare phase */
		sector_t user_size;       /* from prepare phase */
		u64 diskful_primary_nodes;/* added in commit phase */
		u64 new_size;             /* added in commit phase */
	} twopc_resize;
	struct list_head queued_twopc;
	spinlock_t queued_twopc_lock;
	struct timer_list queued_twopc_timer;
	struct queued_twopc *starting_queued_twopc;

	enum drbd_role role[2];
	bool susp_user[2];			/* IO suspended by user */
	bool susp_nod[2];		/* IO suspended because no data */
	bool cached_susp;		/* cached result of looking at all different suspend bits */
	bool cached_all_devices_have_quorum;

	enum write_ordering_e write_ordering;
	atomic_t current_tle_nr;	/* transfer log epoch number */
	unsigned current_tle_writes;	/* writes seen within this tl epoch */

	unsigned cached_min_aggreed_protocol_version;

	cpumask_var_t cpu_mask;

	struct drbd_work_queue work;
	struct drbd_thread worker;

	struct list_head listeners;
	spinlock_t listeners_lock;

	struct timer_list peer_ack_timer; /* send a P_PEER_ACK after last completion */
	struct timer_list repost_up_to_date_timer;

	unsigned int w_cb_nr; /* keeps counting up */
	struct drbd_thread_timing_details w_timing_details[DRBD_THREAD_DETAILS_HIST];
	wait_queue_head_t barrier_wait;  /* upon each state change. */
	struct rcu_head rcu;

	/* drbd's page pool, used to buffer data received from the peer, or
	 * data requested by the peer.
	 *
	 * This does not have an emergency reserve.
	 *
	 * When allocating from this pool, it first takes pages from the pool.
	 * Only if the pool is depleted will try to allocate from the system.
	 *
	 * The assumption is that pages taken from this pool will be processed,
	 * and given back, "quickly", and then can be recycled, so we can avoid
	 * frequent calls to alloc_page(), and still will be able to make
	 * progress even under memory pressure.
	 *
	 * We do not use a standard mempool, because we want to hand out the
	 * pre-allocated objects first.
	 *
	 * Note: This is a single linked list, the next pointer is the private
	 *       member of struct page. */
	struct page *pp_pool;
	spinlock_t pp_lock;
	int pp_vacant;
	wait_queue_head_t pp_wait;
};

struct drbd_connection {
	struct list_head connections;
	struct drbd_resource *resource;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_conn;
	struct dentry *debugfs_conn_callback_history;
	struct dentry *debugfs_conn_oldest_requests;
	struct dentry *debugfs_conn_transport;
	struct dentry *debugfs_conn_debug;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr peer_devices;	/* volume number to peer device mapping */
	enum drbd_conn_state cstate[2];
	enum drbd_role peer_role[2];
	bool susp_fen[2];		/* IO suspended because fence peer handler runs */

	unsigned long flags;
	enum drbd_fencing_policy fencing_policy;

	struct drbd_send_buffer send_buffer[2];
	struct mutex mutex[2]; /* Protect assembling of new packet until sending it (in send_buffer) */
	/* scratch buffers for use while "owning" the DATA_STREAM send_buffer,
	 * to avoid larger on-stack temporary variables,
	 * introduced for holding digests in drbd_send_dblock() */
	union {
		/* MAX_DIGEST_SIZE in the linux kernel at this point is 64 byte, afaik */
		struct {
			char before[64];
			char after[64];
		} d;
	} scratch_buffer;

	int agreed_pro_version;		/* actually used protocol version */
	u32 agreed_features;
	unsigned long last_received;	/* in jiffies, either socket */
	atomic_t ap_in_flight; /* App sectors in flight (waiting for ack) */
	atomic_t rs_in_flight; /* Resync sectors in flight */

	struct drbd_work connect_timer_work;
	struct timer_list connect_timer;

	struct crypto_shash *cram_hmac_tfm;
	struct crypto_shash *integrity_tfm;  /* checksums we compute, updates protected by connection->mutex[DATA_STREAM] */
	struct crypto_shash *peer_integrity_tfm;  /* checksums we verify, only accessed from receiver thread  */
	struct crypto_shash *csums_tfm;
	struct crypto_shash *verify_tfm;

	void *int_dig_in;
	void *int_dig_vv;

	/* receiver side */
	struct drbd_epoch *current_epoch;
	spinlock_t epoch_lock;
	unsigned int epochs;

	unsigned long last_reconnect_jif;
	/* empty member on older kernels without blk_start_plug() */
	struct blk_plug receiver_plug;
	struct drbd_thread receiver;
	struct drbd_thread sender;
	struct drbd_thread ack_receiver;
	struct workqueue_struct *ack_sender;
	struct work_struct peer_ack_work;

	struct list_head peer_requests; /* All peer requests in the order we received them.. */
	u64 last_dagtag_sector;

	atomic_t active_ee_cnt;
	struct list_head active_ee; /* IO in progress (P_DATA gets written to disk) */
	struct list_head sync_ee;   /* IO in progress (P_RS_DATA_REPLY gets written to disk) */
	struct list_head read_ee;   /* [RS]P_DATA_REQUEST being read */
	struct list_head net_ee;    /* zero-copy network send in progress */
	struct list_head done_ee;   /* need to send P_WRITE_ACK */
	atomic_t done_ee_cnt;
	struct work_struct send_acks_work;
	wait_queue_head_t ee_wait;

	atomic_t pp_in_use;		/* allocated from page pool */
	atomic_t pp_in_use_by_net;	/* sendpage()d, still referenced by transport */
	/* sender side */
	struct drbd_work_queue sender_work;

	struct sender_todo {
		struct list_head work_list;

		/* If upper layers trigger an unplug on this side, we want to
		 * send and unplug hint over to the peer.  Sending it too
		 * early, or missing it completely, causes a potential latency
		 * penalty (requests idling too long in the remote queue).
		 * There is no harm done if we occasionally send one too many
		 * such unplug hints.
		 *
		 * We have two slots, which are used in an alternating fashion:
		 * If a new unplug event happens while the current pending one
		 * has not even been processed yet, we overwrite the next
		 * pending slot: there is not much point in unplugging on the
		 * remote side, if we have a full request queue to be send on
		 * this side still, and not even reached the position in the
		 * change stream when the previous local unplug happened.
		 */
		u64 unplug_dagtag_sector[2];
		unsigned int unplug_slot; /* 0 or 1 */

		/* the currently (or last) processed request,
		 * see process_sender_todo() */
		struct drbd_request *req;

		/* Points to the next request on the resource->transfer_log,
		 * which is RQ_NET_QUEUED for this connection, and so can
		 * safely be used as next starting point for the list walk
		 * in tl_next_request_for_connection().
		 *
		 * If it is NULL (we walked off the tail last time), it will be
		 * set by __req_mod( QUEUE_FOR.* ), so fast connections don't
		 * need to walk the full transfer_log list every time, even if
		 * the list is kept long by some slow connections.
		 *
		 * There is also a special value to reliably re-start
		 * the transfer log walk after having scheduled the requests
		 * for RESEND. */
#define TL_NEXT_REQUEST_RESEND	((void*)1)
		struct drbd_request *req_next;
	} todo;

	/* cached pointers,
	 * so we can look up the oldest pending requests more quickly.
	 * protected by resource->req_lock */
	struct drbd_request *req_ack_pending;
	struct drbd_request *req_not_net_done;

	unsigned int s_cb_nr; /* keeps counting up */
	unsigned int r_cb_nr; /* keeps counting up */
	struct drbd_thread_timing_details s_timing_details[DRBD_THREAD_DETAILS_HIST];
	struct drbd_thread_timing_details r_timing_details[DRBD_THREAD_DETAILS_HIST];

	struct {
		unsigned long last_sent_barrier_jif;
		int last_sent_epoch_nr;

		/* whether this sender thread
		 * has processed a single write yet. */
		bool seen_any_write_yet;

		/* Which barrier number to send with the next P_BARRIER */
		int current_epoch_nr;

		/* how many write requests have been sent
		 * with req->epoch == current_epoch_nr.
		 * If none, no P_BARRIER will be sent. */
		unsigned current_epoch_writes;

		/* position in change stream */
		u64 current_dagtag_sector;
	} send;

	struct {
		u64 dagtag_sector;
		int lost_node_id;
	} after_reconciliation;

	unsigned int peer_node_id;
	struct list_head twopc_parent_list;
	struct rcu_head rcu;

	struct drbd_transport transport; /* The transport needs to be the last member. The acutal
					    implementation might have more members than the
					    abstract one. */
};

/* used to get the next lower or next higher peer_device depending on device node-id */
enum drbd_neighbor {
	NEXT_LOWER,
	NEXT_HIGHER
};

struct drbd_peer_device {
	struct list_head peer_devices;
	struct drbd_device *device;
	struct drbd_connection *connection;
	struct peer_device_conf *conf; /* RCU, for updates: resource->conf_update */
	enum drbd_disk_state disk_state[2];
	enum drbd_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
	bool resync_susp_other_c[2];
	enum drbd_repl_state negotiation_result; /* To find disk state after attach */
	unsigned int send_cnt;
	unsigned int recv_cnt;
	atomic_t packet_seq;
	unsigned int peer_seq;
	spinlock_t peer_seq_lock;
	unsigned int max_bio_size;
	uint64_t d_size;  /* size of disk */
	uint64_t u_size;  /* user requested size */
	uint64_t c_size;  /* current exported size */
	uint64_t max_size;
	int bitmap_index;
	int node_id;

	unsigned long flags;

	enum drbd_repl_state start_resync_side;
	enum drbd_repl_state last_repl_state; /* What we received from the peer */
	struct timer_list start_resync_timer;
	struct drbd_work resync_work;
	struct timer_list resync_timer;
	struct drbd_work propagate_uuids_work;

	/* Used to track operations of resync... */
	struct lru_cache *resync_lru;
	/* Number of locked elements in resync LRU */
	unsigned int resync_locked;
	/* resync extent number waiting for application requests */
	unsigned int resync_wenr;
	enum drbd_disk_state resync_finished_pdsk; /* Finished while starting resync */
	int resync_again; /* decided to resync again while resync running */
	unsigned long resync_next_bit; /* bitmap bit to search from for next resync request */
	struct mutex resync_next_bit_mutex;

	atomic_t ap_pending_cnt; /* AP data packets on the wire, ack expected */
	atomic_t unacked_cnt;	 /* Need to send replies for */
	atomic_t rs_pending_cnt; /* RS request/data packets on the wire */

	/* use checksums for *this* resync */
	bool use_csums;
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
	unsigned long rs_last_writeout;

	/* where does the admin want us to start? (sector) */
	sector_t ov_start_sector;
	sector_t ov_stop_sector;
	/* where are we now? (sector) */
	sector_t ov_position;
	/* Start sector of out of sync range (to merge printk reporting). */
	sector_t ov_last_oos_start;
	/* size of out-of-sync range in sectors. */
	sector_t ov_last_oos_size;
	/* Start sector of skipped range (to merge printk reporting). */
	sector_t ov_last_skipped_start;
	/* size of skipped range in sectors. */
	sector_t ov_last_skipped_size;
	int c_sync_rate; /* current resync rate after syncer throttle magic */
	struct fifo_buffer *rs_plan_s; /* correction values of resync planer (RCU, connection->conn_update) */
	atomic_t rs_sect_in; /* for incoming resync data rate, SyncTarget */
	int rs_last_sect_ev; /* counter to compare with */
	int rs_last_events;  /* counter of read or write "events" (unit sectors)
			      * on the lower level device when we last looked. */
	int rs_in_flight; /* resync sectors in flight (to proxy, in proxy and from proxy) */
	ktime_t rs_last_mk_req_kt;
	unsigned long ov_left; /* in bits */
	unsigned long ov_skipped; /* in bits */
	u64 rs_start_uuid;

	u64 current_uuid;
	u64 bitmap_uuids[DRBD_PEERS_MAX];
	u64 history_uuids[HISTORY_UUIDS];
	u64 dirty_bits;
	u64 uuid_flags;
	u64 uuid_node_mask; /* might be authoritative_nodes or weak_nodes */
	bool uuids_received;

	unsigned long comm_bm_set; /* communicated number of set bits. */
	u64 comm_current_uuid; /* communicated current UUID */
	u64 comm_uuid_flags; /* communicated UUID flags */
	u64 comm_bitmap_uuid;
	union drbd_state comm_state;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_peer_dev;
	struct dentry *debugfs_peer_dev_resync_extents;
	struct dentry *debugfs_peer_dev_proc_drbd;
#endif
	ktime_t pre_send_kt;
	ktime_t acked_kt;
	ktime_t net_done_kt;

	struct {/* sender todo per peer_device */
		bool was_ahead;
	} todo;
	union drbd_state connect_state;
};

struct submit_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	/* protected by ..->resource->req_lock */
	struct list_head writes;
	struct list_head peer_writes;
};

struct opener {
	struct list_head list;
	char comm[TASK_COMM_LEN];
	pid_t pid;
	ktime_t opened;
};

struct drbd_device {
#ifdef PARANOIA
	long magic;
#endif
	struct drbd_resource *resource;
	struct list_head peer_devices;
	struct list_head pending_bitmap_io;

	struct opener openers;

	unsigned long flush_jif;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_minor;
	struct dentry *debugfs_vol;
	struct dentry *debugfs_vol_oldest_requests;
	struct dentry *debugfs_vol_act_log_extents;
	struct dentry *debugfs_vol_act_log_histogram;
	struct dentry *debugfs_vol_data_gen_id;
	struct dentry *debugfs_vol_io_frozen;
	struct dentry *debugfs_vol_ed_gen_id;
	struct dentry *debugfs_vol_openers;
	struct dentry *debugfs_vol_md_io;
#ifdef CONFIG_DRBD_TIMING_STATS
	struct dentry *debugfs_vol_req_timing;
#endif
#endif

	unsigned int vnr;	/* volume number within the connection */
	unsigned int minor;	/* device minor number */

	struct kref kref;
	struct kref_debug_info kref_debug;

	/* things that are stored as / read from meta data on disk */
	unsigned long flags;

	/* configured by drbdsetup */
	struct drbd_backing_dev *ldev __protected_by(local);

	struct request_queue *rq_queue;
	struct gendisk	    *vdisk;

	unsigned long last_reattach_jif;
	struct timer_list md_sync_timer;
	struct timer_list request_timer;

	enum drbd_disk_state disk_state[2];
	wait_queue_head_t misc_wait;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	unsigned int al_writ_cnt;
	unsigned int bm_writ_cnt;
	atomic_t ap_bio_cnt[2];	 /* Requests we need to complete. [READ] and [WRITE] */
	atomic_t local_cnt;	 /* Waiting for local completion */
	atomic_t ap_actlog_cnt;  /* Requests waiting for activity log */
	atomic_t wait_for_actlog; /* Peer requests waiting for activity log */
	/* worst case extent count needed to satisfy both requests and peer requests
	 * currently waiting for the activity log */
	atomic_t wait_for_actlog_ecnt;

	atomic_t suspend_cnt;	/* recursive suspend counter, if non-zero, IO will be blocked. */

	/* Interval trees of pending local requests */
	struct rb_root read_requests;
	struct rb_root write_requests;

	/* for statistics and timeouts */
	/* [0] read, [1] write */
	struct list_head pending_master_completion[2];
	struct list_head pending_completion[2];

	struct drbd_bitmap *bitmap;

	int open_rw_cnt, open_ro_cnt;
	/* FIXME clean comments, restructure so it is more obvious which
	 * members are protected by what */

	int next_barrier_nr;
	struct drbd_md_io md_io;
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache *act_log;	/* activity log */
	unsigned al_histogram[AL_UPDATES_PER_TRANSACTION+1];
	unsigned int al_tr_number;
	int al_tr_cycle;
	wait_queue_head_t seq_wait;
	u64 exposed_data_uuid; /* UUID of the exposed data */
	u64 next_exposed_data_uuid;
	struct rw_semaphore uuid_sem;
	atomic_t rs_sect_ev; /* for submitted resync data rate, both */
	struct pending_bitmap_work_s {
		atomic_t n;		/* inc when queued here, */
		spinlock_t q_lock;	/* dec only once finished. */
		struct list_head q;	/* n > 0 even if q already empty */
	} pending_bitmap_work;
	struct device_conf device_conf;

	/* any requests that would block in drbd_submit_bio()
	 * are deferred to this single-threaded work queue */
	struct submit_worker submit;
	u64 read_nodes; /* used for balancing read requests among peers */
	bool have_quorum[2];	/* no quorum -> suspend IO or error IO */
	bool cached_state_unstable; /* updates with each state change */
	bool cached_err_io; /* complete all IOs with error */

#ifdef CONFIG_DRBD_TIMING_STATS
	spinlock_t timing_lock;
	unsigned long reqs;
	ktime_t in_actlog_kt;
	ktime_t pre_submit_kt; /* sum over over all reqs */

	ktime_t before_queue_kt; /* sum over all al_misses */
	ktime_t before_al_begin_io_kt;

	ktime_t al_before_bm_write_hinted_kt; /* sum over all al_writ_cnt */
	ktime_t al_mid_kt;
	ktime_t al_after_sync_page_kt;
#endif

	struct rcu_head rcu;
	struct work_struct finalize_work;
};

struct drbd_bm_aio_ctx {
	struct drbd_device *device;
	struct list_head list; /* on device->pending_bitmap_io */
	unsigned long start_jif;
	atomic_t in_flight;
	unsigned int done;
	unsigned flags;
#define BM_AIO_COPY_PAGES	1
#define BM_AIO_WRITE_HINTED	2
#define BM_AIO_WRITE_ALL_PAGES	4
#define BM_AIO_READ	        8
#define BM_AIO_WRITE_LAZY      16
	int error;
	struct kref kref;
};

struct drbd_config_context {
	/* assigned from drbd_genlmsghdr */
	unsigned int minor;
	/* assigned from request attributes, if present */
	unsigned int volume;
#define VOLUME_UNSPECIFIED		(-1U)
	unsigned int peer_node_id;
#define PEER_NODE_ID_UNSPECIFIED	(-1U)
	/* pointer into the request skb,
	 * limited lifetime! */
	char *resource_name;
	struct nlattr *my_addr;
	struct nlattr *peer_addr;

	/* reply buffer */
	struct sk_buff *reply_skb;
	/* pointer into reply buffer */
	struct drbd_genlmsghdr *reply_dh;
	/* resolved from attributes, if possible */
	struct drbd_device *device;
	struct drbd_resource *resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;
};

static inline struct drbd_device *minor_to_device(unsigned int minor)
{
	return (struct drbd_device *)idr_find(&drbd_devices, minor);
}


static inline struct drbd_peer_device *
conn_peer_device(struct drbd_connection *connection, int volume_number)
{
	return idr_find(&connection->peer_devices, volume_number);
}

static inline unsigned drbd_req_state_by_peer_device(struct drbd_request *req,
		struct drbd_peer_device *peer_device)
{
	int idx = peer_device->node_id;
	if (idx < 0 || idx >= DRBD_NODE_ID_MAX) {
		drbd_warn(peer_device, "FIXME: node_id: %d\n", idx);
		/* WARN(1, "bitmap_index: %d", idx); */
		return 0;
	}
	return req->net_rq_state[idx];
}

#define for_each_resource(resource, _resources) \
	list_for_each_entry(resource, _resources, resources)

#define for_each_resource_rcu(resource, _resources) \
	list_for_each_entry_rcu(resource, _resources, resources)

#define for_each_resource_safe(resource, tmp, _resources) \
	list_for_each_entry_safe(resource, tmp, _resources, resources)

/* Each caller of for_each_connect() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#define for_each_connection(connection, resource) \
	list_for_each_entry(connection, &resource->connections, connections)

#define for_each_connection_rcu(connection, resource) \
	list_for_each_entry_rcu(connection, &resource->connections, connections)

#define for_each_connection_safe(connection, tmp, resource) \
	list_for_each_entry_safe(connection, tmp, &resource->connections, connections)

#define for_each_connection_ref(connection, m, resource)		\
	for (connection = __drbd_next_connection_ref(&m, NULL, resource); \
	     connection;						\
	     connection = __drbd_next_connection_ref(&m, connection, resource))

/* Each caller of for_each_peer_device() must hold req_lock or adm_mutex or conf_update.
   The update locations hold all three! */
#define for_each_peer_device(peer_device, device) \
	list_for_each_entry(peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_rcu(peer_device, device) \
	list_for_each_entry_rcu(peer_device, &device->peer_devices, peer_devices)

#define for_each_peer_device_safe(peer_device, tmp, device) \
	list_for_each_entry_safe(peer_device, tmp, &device->peer_devices, peer_devices)

#define for_each_peer_device_ref(peer_device, m, device)		\
	for (peer_device = __drbd_next_peer_device_ref(&m, NULL, device); \
	     peer_device;						\
	     peer_device = __drbd_next_peer_device_ref(&m, peer_device, device))

static inline unsigned int device_to_minor(struct drbd_device *device)
{
	return device->minor;
}

/*
 * function declarations
 *************************/

/* drbd_main.c */

enum dds_flags {
	/* This enum is part of the wire protocol!
	 * See P_SIZES, struct p_sizes; */
	DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE    = 1,
	DDSF_NO_RESYNC = 2, /* Do not run a resync for the new space */
	DDSF_IGNORE_PEER_CONSTRAINTS = 4,
	DDSF_2PC = 8, /* local only, not on the wire */
};
struct meta_data_on_disk_9;

extern int  drbd_thread_start(struct drbd_thread *thi);
extern void _drbd_thread_stop(struct drbd_thread *thi, int restart, int wait);
#ifdef CONFIG_SMP
extern void drbd_thread_current_set_cpu(struct drbd_thread *thi);
#else
#define drbd_thread_current_set_cpu(A) ({})
#endif
extern void tl_release(struct drbd_connection *,
			uint64_t o_block_id,
			uint64_t y_block_id,
			unsigned int barrier_nr,
			unsigned int set_size);
extern void drbd_free_sock(struct drbd_connection *connection);

extern int __drbd_send_protocol(struct drbd_connection *connection, enum drbd_packet cmd);
extern int drbd_send_protocol(struct drbd_connection *connection);
extern u64 drbd_collect_local_uuid_flags(struct drbd_peer_device *peer_device, u64 *authoritative_mask);
extern u64 drbd_resolved_uuid(struct drbd_peer_device *peer_device_base, u64 *uuid_flags);
extern int drbd_send_uuids(struct drbd_peer_device *, u64 uuid_flags, u64 weak_nodes);
extern void drbd_gen_and_send_sync_uuid(struct drbd_peer_device *);
extern int drbd_attach_peer_device(struct drbd_peer_device *);
extern int drbd_send_sizes(struct drbd_peer_device *, uint64_t u_size_diskless, enum dds_flags flags);
extern int conn_send_state(struct drbd_connection *, union drbd_state);
extern int drbd_send_state(struct drbd_peer_device *, union drbd_state);
extern int drbd_send_current_state(struct drbd_peer_device *);
extern int drbd_send_sync_param(struct drbd_peer_device *);
extern int drbd_send_out_of_sync(struct drbd_peer_device *, sector_t, unsigned int);
extern int drbd_send_block(struct drbd_peer_device *, enum drbd_packet,
			   struct drbd_peer_request *);
extern int drbd_send_dblock(struct drbd_peer_device *, struct drbd_request *req);
extern int drbd_send_drequest(struct drbd_peer_device *, int cmd,
			      sector_t sector, int size, u64 block_id);
extern void *drbd_prepare_drequest_csum(struct drbd_peer_request *peer_req, int digest_size);
extern int drbd_send_ov_request(struct drbd_peer_device *, sector_t sector, int size);

extern int drbd_send_bitmap(struct drbd_device *, struct drbd_peer_device *);
extern int drbd_send_dagtag(struct drbd_connection *connection, u64 dagtag);
extern void drbd_send_sr_reply(struct drbd_connection *connection, int vnr,
			       enum drbd_state_rv retcode);
extern int drbd_send_rs_deallocated(struct drbd_peer_device *, struct drbd_peer_request *);
extern void drbd_send_twopc_reply(struct drbd_connection *connection,
				  enum drbd_packet, struct twopc_reply *);
extern void drbd_send_peers_in_sync(struct drbd_peer_device *, u64, sector_t, int);
extern int drbd_send_peer_dagtag(struct drbd_connection *connection, struct drbd_connection *lost_peer);
extern int drbd_send_current_uuid(struct drbd_peer_device *peer_device, u64 current_uuid, u64 weak_nodes);
extern void drbd_backing_dev_free(struct drbd_device *device, struct drbd_backing_dev *ldev);
extern void drbd_cleanup_device(struct drbd_device *device);
extern void drbd_print_uuids(struct drbd_peer_device *peer_device, const char *text);
extern void drbd_queue_unplug(struct drbd_device *device);

extern u64 drbd_capacity_to_on_disk_bm_sect(u64 capacity_sect, unsigned int max_peers);
extern void drbd_md_set_sector_offsets(struct drbd_device *device,
				       struct drbd_backing_dev *bdev);
extern int drbd_md_write(struct drbd_device *device, struct meta_data_on_disk_9 *buffer);
extern int drbd_md_sync(struct drbd_device *device);
extern int drbd_md_sync_if_dirty(struct drbd_device *device);
extern void drbd_uuid_received_new_current(struct drbd_peer_device *, u64 , u64) __must_hold(local);
extern void drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local);
extern void _drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local);
extern void _drbd_uuid_set_current(struct drbd_device *device, u64 val) __must_hold(local);
extern void drbd_uuid_new_current(struct drbd_device *device, bool forced);
extern void drbd_uuid_new_current_by_user(struct drbd_device *device);
extern void _drbd_uuid_push_history(struct drbd_device *device, u64 val) __must_hold(local);
extern u64 _drbd_uuid_pull_history(struct drbd_peer_device *peer_device) __must_hold(local);
extern void drbd_uuid_resync_starting(struct drbd_peer_device *peer_device); __must_hold(local);
extern u64 drbd_uuid_resync_finished(struct drbd_peer_device *peer_device) __must_hold(local);
extern void drbd_uuid_detect_finished_resyncs(struct drbd_peer_device *peer_device) __must_hold(local);
extern u64 drbd_weak_nodes_device(struct drbd_device *device);
extern void drbd_md_set_flag(struct drbd_device *device, enum mdf_flag) __must_hold(local);
extern void drbd_md_clear_flag(struct drbd_device *device, enum mdf_flag)__must_hold(local);
extern int drbd_md_test_flag(struct drbd_backing_dev *, enum mdf_flag);
extern void drbd_md_set_peer_flag(struct drbd_peer_device *, enum mdf_peer_flag);
extern void drbd_md_clear_peer_flag(struct drbd_peer_device *, enum mdf_peer_flag);
extern bool drbd_md_test_peer_flag(struct drbd_peer_device *, enum mdf_peer_flag);
extern void drbd_md_mark_dirty(struct drbd_device *device);
extern void drbd_queue_bitmap_io(struct drbd_device *,
				 int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
				 void (*done)(struct drbd_device *, struct drbd_peer_device *, int),
				 char *why, enum bm_flag flags,
				 struct drbd_peer_device *);
extern int drbd_bitmap_io(struct drbd_device *,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *);
extern int drbd_bitmap_io_from_worker(struct drbd_device *,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *);
extern int drbd_bmio_set_n_write(struct drbd_device *device, struct drbd_peer_device *) __must_hold(local);
extern int drbd_bmio_clear_all_n_write(struct drbd_device *device, struct drbd_peer_device *) __must_hold(local);
extern int drbd_bmio_set_all_n_write(struct drbd_device *device, struct drbd_peer_device *) __must_hold(local);
extern int drbd_bmio_set_allocated_n_write(struct drbd_device *,struct drbd_peer_device *) __must_hold(local);
extern bool drbd_device_stable(struct drbd_device *device, u64 *authoritative);
extern void drbd_flush_peer_acks(struct drbd_resource *resource);
extern void drbd_cork(struct drbd_connection *connection, enum drbd_stream stream);
extern void drbd_uncork(struct drbd_connection *connection, enum drbd_stream stream);
extern void drbd_open_counts(struct drbd_resource *resource, int *rw_count_ptr, int *ro_count_ptr);

extern struct drbd_connection *
__drbd_next_connection_ref(u64 *, struct drbd_connection *, struct drbd_resource *);

extern struct drbd_peer_device *
__drbd_next_peer_device_ref(u64 *, struct drbd_peer_device *, struct drbd_device *);

extern void tl_abort_disk_io(struct drbd_device *device);

extern sector_t drbd_get_max_capacity(
		struct drbd_device *device, struct drbd_backing_dev *bdev, bool warn);

/* Meta data layout
 *
 * We currently have two possible layouts.
 * Offsets in (512 byte) sectors.
 * external:
 *   |----------- md_size_sect ------------------|
 *   [ 4k superblock ][ activity log ][  Bitmap  ]
 *   | al_offset == 8 |
 *   | bm_offset = al_offset + X      |
 *  ==> bitmap sectors = md_size_sect - bm_offset
 *
 *  Variants:
 *     old, indexed fixed size meta data:
 *
 * internal:
 *            |----------- md_size_sect ------------------|
 * [data.....][  Bitmap  ][ activity log ][ 4k superblock ][padding*]
 *                        | al_offset < 0 |
 *            | bm_offset = al_offset - Y |
 *  ==> bitmap sectors = Y = al_offset - bm_offset
 *
 *  [padding*] are zero or up to 7 unused 512 Byte sectors to the
 *  end of the device, so that the [4k superblock] will be 4k aligned.
 *
 *  The activity log consists of 4k transaction blocks,
 *  which are written in a ring-buffer, or striped ring-buffer like fashion,
 *  which are writtensize used to be fixed 32kB,
 *  but is about to become configurable.
 */

/* One activity log extent represents 4M of storage */
#define AL_EXTENT_SHIFT 22
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SHIFT)

/* drbd_bitmap.c */
/*
 * We need to store one bit for a block.
 * Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
 * Bit 0 ==> local node thinks this block is binary identical on both nodes
 * Bit 1 ==> local node thinks this block needs to be synced.
 */

#define RS_MAKE_REQS_INTV    (HZ/10)
#define RS_MAKE_REQS_INTV_NS (NSEC_PER_SEC/10)

/* We do bitmap IO in units of 4k blocks.
 * We also still have a hardcoded 4k per bit relation. */
#define BM_BLOCK_SHIFT	12			 /* 4k per bit */
#define BM_BLOCK_SIZE	 (1<<BM_BLOCK_SHIFT)
/* mostly arbitrarily set the represented size of one bitmap extent,
 * aka resync extent, to 128 MiB (which is also 4096 Byte worth of bitmap
 * at 4k per bit resolution) */
#define BM_EXT_SHIFT	 27	/* 128 MiB per resync extent */
#define BM_EXT_SIZE	 (1<<BM_EXT_SHIFT)

#if (BM_BLOCK_SHIFT != 12)
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
#define BM_BIT_TO_EXT(x)    ((x) >> (BM_EXT_SHIFT - BM_BLOCK_SHIFT))

/* first storage sector a bitmap extent corresponds to */
#define BM_EXT_TO_SECT(x)   ((sector_t)(x) << (BM_EXT_SHIFT-9))
/* how much _storage_ sectors we have per bitmap extent */
#define BM_SECT_PER_EXT     BM_EXT_TO_SECT(1)
/* how many bits are covered by one bitmap extent (resync extent) */
#define BM_BITS_PER_EXT     (1UL << (BM_EXT_SHIFT - BM_BLOCK_SHIFT))

#define BM_BLOCKS_PER_BM_EXT_MASK  (BM_BITS_PER_EXT - 1)


/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SHIFT - AL_EXTENT_SHIFT))

/* Indexed external meta data has a fixed on-disk size of 128MiB, of which
 * 4KiB are our "superblock", and 32KiB are the fixed size activity
 * log, leaving this many sectors for the bitmap.
 */
#define DRBD_BM_SECTORS_INDEXED \
	  (((128 << 20) - (32 << 10) - (4 << 10)) >> SECTOR_SHIFT)

#if BITS_PER_LONG == 32
#if !defined(CONFIG_LBDAF) && !defined(CONFIG_LBD)
#define DRBD_MAX_SECTORS (0xffffffffLU)
#else
/* With large block device support, the size is limited by the fact that we
 * want to be able to address bitmap bits with a long. Additionally adjust by
 * one page worth of bitmap, so we don't wrap around when iterating. */
#define DRBD_MAX_SECTORS BM_BIT_TO_SECT(0xffff7fff)
#endif
#else
/* We allow up to 1 PiB on 64 bit architectures as long as our meta data
 * is large enough. */
#define DRBD_MAX_SECTORS (1UL << (50 - SECTOR_SHIFT))
#endif

/* BIO_MAX_SIZE is 256 * PAGE_SIZE,
 * so for typical PAGE_SIZE of 4k, that is (1<<20) Byte.
 * Since we may live in a mixed-platform cluster,
 * we limit us to a platform agnostic constant here for now.
 * A followup commit may allow even bigger BIO sizes,
 * once we thought that through. */
#if DRBD_MAX_BIO_SIZE > (BIO_MAX_PAGES << PAGE_SHIFT)
#error Architecture not supported: DRBD_MAX_BIO_SIZE > (BIO_MAX_PAGES << PAGE_SHIFT)
#endif

#define DRBD_MAX_SIZE_H80_PACKET (1U << 15) /* Header 80 only allows packets up to 32KiB data */
#define DRBD_MAX_BIO_SIZE_P95    (1U << 17) /* Protocol 95 to 99 allows bios up to 128KiB */

/* For now, don't allow more than half of what we can "activate" in one
 * activity log transaction to be discarded in one go. We may need to rework
 * drbd_al_begin_io() to allow for even larger discard ranges */
#define DRBD_MAX_BATCH_BIO_SIZE	 (AL_UPDATES_PER_TRANSACTION/2*AL_EXTENT_SIZE)
#define DRBD_MAX_BBIO_SECTORS    (DRBD_MAX_BATCH_BIO_SIZE >> 9)

/* how many activity log extents are touched by this interval? */
static inline int interval_to_al_extents(struct drbd_interval *i)
{
	unsigned int first = i->sector >> (AL_EXTENT_SHIFT-9);
	unsigned int last = i->size == 0 ? first : (i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT-9);
	return 1 + last - first; /* worst case: all touched extends are cold. */
}

extern struct drbd_bitmap *drbd_bm_alloc(void);
extern int  drbd_bm_resize(struct drbd_device *device, sector_t sectors, bool set_new_bits);
void drbd_bm_free(struct drbd_bitmap *bitmap);
extern void drbd_bm_set_all(struct drbd_device *device);
extern void drbd_bm_clear_all(struct drbd_device *device);
/* set/clear/test only a few bits at a time */
extern unsigned int drbd_bm_set_bits(struct drbd_device *, unsigned int, unsigned long, unsigned long);
extern unsigned int drbd_bm_clear_bits(struct drbd_device *, unsigned int, unsigned long, unsigned long);
extern int drbd_bm_count_bits(struct drbd_device *, unsigned int, unsigned long, unsigned long);
/* bm_set_bits variant for use while holding drbd_bm_lock,
 * may process the whole bitmap in one go */
extern void drbd_bm_set_many_bits(struct drbd_peer_device *, unsigned long, unsigned long);
extern void drbd_bm_clear_many_bits(struct drbd_peer_device *, unsigned long, unsigned long);
extern void _drbd_bm_clear_many_bits(struct drbd_device *, int, unsigned long, unsigned long);
extern void _drbd_bm_set_many_bits(struct drbd_device *, int, unsigned long, unsigned long);
extern int drbd_bm_test_bit(struct drbd_peer_device *, unsigned long);
extern int  drbd_bm_read(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern void drbd_bm_reset_al_hints(struct drbd_device *device) __must_hold(local);
extern void drbd_bm_mark_range_for_writeout(struct drbd_device *, unsigned long, unsigned long);
extern int  drbd_bm_write(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern int  drbd_bm_write_hinted(struct drbd_device *device) __must_hold(local);
extern int  drbd_bm_write_lazy(struct drbd_device *device, unsigned upper_idx) __must_hold(local);
extern int drbd_bm_write_all(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern int drbd_bm_write_copy_pages(struct drbd_device *, struct drbd_peer_device *) __must_hold(local);
extern size_t	     drbd_bm_words(struct drbd_device *device);
extern unsigned long drbd_bm_bits(struct drbd_device *device);
extern sector_t      drbd_bm_capacity(struct drbd_device *device);

#define DRBD_END_OF_BITMAP	(~(unsigned long)0)
extern unsigned long drbd_bm_find_next(struct drbd_peer_device *, unsigned long);
/* bm_find_next variants for use while you hold drbd_bm_lock() */
extern unsigned long _drbd_bm_find_next(struct drbd_peer_device *, unsigned long);
extern unsigned long _drbd_bm_find_next_zero(struct drbd_peer_device *, unsigned long);
extern unsigned long _drbd_bm_total_weight(struct drbd_device *, int);
extern unsigned long drbd_bm_total_weight(struct drbd_peer_device *);
/* for receive_bitmap */
extern void drbd_bm_merge_lel(struct drbd_peer_device *peer_device, size_t offset,
		size_t number, unsigned long *buffer);
/* for _drbd_send_bitmap */
extern void drbd_bm_get_lel(struct drbd_peer_device *peer_device, size_t offset,
		size_t number, unsigned long *buffer);

extern void drbd_bm_lock(struct drbd_device *device, char *why, enum bm_flag flags);
extern void drbd_bm_unlock(struct drbd_device *device);
extern void drbd_bm_slot_lock(struct drbd_peer_device *peer_device, char *why, enum bm_flag flags);
extern void drbd_bm_slot_unlock(struct drbd_peer_device *peer_device);
extern void drbd_bm_copy_slot(struct drbd_device *device, unsigned int from_index, unsigned int to_index);
/* drbd_main.c */

extern struct kmem_cache *drbd_request_cache;
extern struct kmem_cache *drbd_ee_cache;	/* peer requests */
extern struct kmem_cache *drbd_bm_ext_cache;	/* bitmap extents */
extern struct kmem_cache *drbd_al_ext_cache;	/* activity log extents */
extern mempool_t drbd_request_mempool;
extern mempool_t drbd_ee_mempool;

/* We also need a standard (emergency-reserve backed) page pool
 * for meta data IO (activity log, bitmap).
 * We can keep it global, as long as it is used as "N pages at a time".
 * 128 should be plenty, currently we probably can get away with as few as 1.
 */
#define DRBD_MIN_POOL_PAGES	128
extern mempool_t drbd_md_io_page_pool;

/* We also need to make sure we get a bio
 * when we need it for housekeeping purposes */
extern struct bio_set drbd_md_io_bio_set;
/* to allocate from that set */
extern struct bio *bio_alloc_drbd(gfp_t gfp_mask);

/* And a bio_set for cloning */
extern struct bio_set drbd_io_bio_set;

extern struct drbd_peer_device *create_peer_device(struct drbd_device *, struct drbd_connection *);
extern enum drbd_ret_code drbd_create_device(struct drbd_config_context *adm_ctx, unsigned int minor,
					     struct device_conf *device_conf, struct drbd_device **p_device);
extern void drbd_unregister_device(struct drbd_device *);
extern void drbd_reclaim_device(struct rcu_head *);
extern void drbd_unregister_connection(struct drbd_connection *);
extern void drbd_reclaim_connection(struct rcu_head *);
void del_connect_timer(struct drbd_connection *connection);

extern struct drbd_resource *drbd_create_resource(const char *, struct res_opts *);
extern void drbd_reclaim_resource(struct rcu_head *rp);
extern struct drbd_resource *drbd_find_resource(const char *name);
extern void drbd_destroy_resource(struct kref *kref);

extern void drbd_destroy_device(struct kref *kref);

extern int set_resource_options(struct drbd_resource *resource, struct res_opts *res_opts);
extern struct drbd_connection *drbd_create_connection(struct drbd_resource *resource,
						      struct drbd_transport_class *tc);
extern void drbd_transport_shutdown(struct drbd_connection *connection, enum drbd_tr_free_op op);
extern void drbd_destroy_connection(struct kref *kref);
extern void conn_free_crypto(struct drbd_connection *connection);

/* drbd_req */
extern void do_submit(struct work_struct *ws);
#ifndef CONFIG_DRBD_TIMING_STATS
#define __drbd_make_request(d,b,k,j) __drbd_make_request(d,b,j)
#endif
extern void __drbd_make_request(struct drbd_device *, struct bio *, ktime_t, unsigned long);
extern blk_qc_t drbd_submit_bio(struct bio *bio);

/* drbd_nl.c */
enum suspend_scope {
	READ_AND_WRITE,
	WRITE_ONLY
};
extern void drbd_suspend_io(struct drbd_device *device, enum suspend_scope);
extern void drbd_resume_io(struct drbd_device *device);
extern char *ppsize(char *buf, unsigned long long size);
extern sector_t drbd_new_dev_size(struct drbd_device *,
		sector_t current_size, /* need at least this much */
		sector_t user_capped_size, /* want (at most) this much */
		enum dds_flags flags) __must_hold(local);
enum determine_dev_size {
	DS_2PC_ERR = -5,
	DS_2PC_NOT_SUPPORTED = -4,
	DS_ERROR_SHRINK = -3,
	DS_ERROR_SPACE_MD = -2,
	DS_ERROR = -1,
	DS_UNCHANGED = 0,
	DS_SHRUNK = 1,
	DS_GREW = 2,
	DS_GREW_FROM_ZERO = 3,
};
extern enum determine_dev_size
drbd_determine_dev_size(struct drbd_device *, sector_t peer_current_size,
			enum dds_flags, struct resize_parms *) __must_hold(local);
extern void resync_after_online_grow(struct drbd_peer_device *);
extern void drbd_reconsider_queue_parameters(struct drbd_device *device,
			struct drbd_backing_dev *bdev, struct o_qlim *o);
extern enum drbd_state_rv drbd_set_role(struct drbd_resource *, enum drbd_role, bool, struct sk_buff *);
extern bool conn_try_outdate_peer(struct drbd_connection *connection);
extern void conn_try_outdate_peer_async(struct drbd_connection *connection);
extern int drbd_maybe_khelper(struct drbd_device *, struct drbd_connection *, char *);
extern int drbd_create_peer_device_default_config(struct drbd_peer_device *peer_device);
extern int drbd_unallocated_index(struct drbd_backing_dev *bdev, int bm_max_peers);

/* drbd_sender.c */
extern int drbd_sender(struct drbd_thread *thi);
extern int drbd_worker(struct drbd_thread *thi);
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int o_minor);
void drbd_resync_after_changed(struct drbd_device *device);
extern bool drbd_stable_sync_source_present(struct drbd_peer_device *, enum which_state);
extern void drbd_start_resync(struct drbd_peer_device *, enum drbd_repl_state);
extern void resume_next_sg(struct drbd_device *device);
extern void suspend_other_sg(struct drbd_device *device);
extern int drbd_resync_finished(struct drbd_peer_device *, enum drbd_disk_state);
extern void verify_progress(struct drbd_peer_device *peer_device,
		const sector_t sector, const unsigned int size);
/* maybe rather drbd_main.c ? */
extern void *drbd_md_get_buffer(struct drbd_device *device, const char *intent);
extern void drbd_md_put_buffer(struct drbd_device *device);
extern int drbd_md_sync_page_io(struct drbd_device *device,
		struct drbd_backing_dev *bdev, sector_t sector, int op);
extern void drbd_ov_out_of_sync_found(struct drbd_peer_device *, sector_t, int);
extern void wait_until_done_or_force_detached(struct drbd_device *device,
		struct drbd_backing_dev *bdev, unsigned int *done);
extern void drbd_rs_controller_reset(struct drbd_peer_device *);
extern void drbd_check_peers(struct drbd_resource *resource);
extern void drbd_check_peers_new_current_uuid(struct drbd_device *);
extern void drbd_ping_peer(struct drbd_connection *connection);
extern struct drbd_peer_device *peer_device_by_node_id(struct drbd_device *, int);
extern void repost_up_to_date_fn(struct timer_list *t);

static inline void ov_out_of_sync_print(struct drbd_peer_device *peer_device)
{
	if (peer_device->ov_last_oos_size) {
		drbd_err(peer_device, "Out of sync: start=%llu, size=%lu (sectors)\n",
		     (unsigned long long)peer_device->ov_last_oos_start,
		     (unsigned long)peer_device->ov_last_oos_size);
	}
	peer_device->ov_last_oos_size = 0;
}

static inline void ov_skipped_print(struct drbd_peer_device *peer_device)
{
	if (peer_device->ov_last_skipped_size) {
		drbd_info(peer_device, "Skipped verify, too busy: start=%llu, size=%lu (sectors)\n",
		     (unsigned long long)peer_device->ov_last_skipped_start,
		     (unsigned long)peer_device->ov_last_skipped_size);
	}
	peer_device->ov_last_skipped_size = 0;
}

extern void drbd_csum_bio(struct crypto_shash *, struct bio *, void *);
extern void drbd_csum_pages(struct crypto_shash *, struct page *, void *);
/* worker callbacks */
extern int w_e_end_data_req(struct drbd_work *, int);
extern int w_e_end_rsdata_req(struct drbd_work *, int);
extern int w_e_end_csum_rs_req(struct drbd_work *, int);
extern int w_e_end_ov_reply(struct drbd_work *, int);
extern int w_e_end_ov_req(struct drbd_work *, int);
extern int w_resync_timer(struct drbd_work *, int);
extern int w_send_dblock(struct drbd_work *, int);
extern int w_send_read_req(struct drbd_work *, int);
extern int w_e_reissue(struct drbd_work *, int);
extern int w_restart_disk_io(struct drbd_work *, int);
extern int w_start_resync(struct drbd_work *, int);
extern int w_send_uuids(struct drbd_work *, int);

extern void resync_timer_fn(struct timer_list *t);
extern void start_resync_timer_fn(struct timer_list *t);

extern void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req);

/* bi_end_io handlers */
extern void drbd_md_endio(struct bio *bio);
extern void drbd_peer_request_endio(struct bio *bio);
extern void drbd_request_endio(struct bio *bio);

void __update_timing_details(
		struct drbd_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line);

#define update_sender_timing_details(c, cb) \
	__update_timing_details(c->s_timing_details, &c->s_cb_nr, cb, __func__ , __LINE__ )
#define update_receiver_timing_details(c, cb) \
	__update_timing_details(c->r_timing_details, &c->r_cb_nr, cb, __func__ , __LINE__ )
#define update_worker_timing_details(r, cb) \
	__update_timing_details(r->w_timing_details, &r->w_cb_nr, cb, __func__ , __LINE__ )

/* drbd_receiver.c */
struct packet_info {
	enum drbd_packet cmd;
	unsigned int size;
	int vnr;
	void *data;
};

/* packet_info->data is just a pointer into some temporary buffer
 * owned by the transport. As soon as we call into the transport for
 * any further receive operation, the data it points to is undefined.
 * The buffer may be freed/recycled/re-used already.
 * Convert and store the relevant information for any incoming data
 * in drbd_peer_request_detail.
 */

struct drbd_peer_request_details {
	uint64_t sector;	/* be64_to_cpu(p_data.sector) */
	uint64_t block_id;	/* unmodified p_data.block_id */
	uint32_t peer_seq;	/* be32_to_cpu(p_data.seq_num) */
	uint32_t dp_flags;	/* be32_to_cpu(p_data.dp_flags) */
	uint32_t length;	/* endian converted p_head*.length */
	uint32_t bi_size;	/* resulting bio size */
	/* for non-discards: bi_size = length - digest_size */
	uint32_t digest_size;
};

struct queued_twopc {
	struct drbd_work w;
	unsigned long start_jif;
	struct drbd_connection *connection;
	struct twopc_reply reply;
	struct packet_info packet_info;
	struct p_twopc_request packet_data;
};

extern int drbd_issue_discard_or_zero_out(struct drbd_device *device,
		sector_t start, unsigned int nr_sectors, int flags);
extern int drbd_send_ack(struct drbd_peer_device *, enum drbd_packet,
			 struct drbd_peer_request *);
extern int drbd_send_ack_ex(struct drbd_peer_device *, enum drbd_packet,
			    sector_t sector, int blksize, u64 block_id);
extern int drbd_receiver(struct drbd_thread *thi);
extern int drbd_ack_receiver(struct drbd_thread *thi);
extern void drbd_send_ping_wf(struct work_struct *ws);
extern void drbd_send_acks_wf(struct work_struct *ws);
extern void drbd_send_peer_ack_wf(struct work_struct *ws);
extern bool drbd_rs_c_min_rate_throttle(struct drbd_peer_device *);
extern bool drbd_rs_should_slow_down(struct drbd_peer_device *, sector_t,
				     bool throttle_if_app_is_waiting);
extern int drbd_submit_peer_request(struct drbd_peer_request *);
extern void drbd_cleanup_after_failed_submit_peer_request(struct drbd_peer_request *peer_req);
extern void drbd_cleanup_peer_requests_wfa(struct drbd_device *device, struct list_head *cleanup);
extern int drbd_free_peer_reqs(struct drbd_resource *, struct list_head *, bool is_net_ee);
extern struct drbd_peer_request *drbd_alloc_peer_req(struct drbd_peer_device *, gfp_t) __must_hold(local);
extern void __drbd_free_peer_req(struct drbd_peer_request *, int);
#define drbd_free_peer_req(pr) __drbd_free_peer_req(pr, 0)
#define drbd_free_net_peer_req(pr) __drbd_free_peer_req(pr, 1)
extern void _drbd_clear_done_ee(struct drbd_device *device, struct list_head *to_be_freed);
extern int drbd_connected(struct drbd_peer_device *);
extern void conn_connect2(struct drbd_connection *);
extern void wait_initial_states_received(struct drbd_connection *);
extern void abort_connect(struct drbd_connection *);
extern void apply_unacked_peer_requests(struct drbd_connection *connection);
extern struct drbd_connection *drbd_connection_by_node_id(struct drbd_resource *, int);
extern struct drbd_connection *drbd_get_connection_by_node_id(struct drbd_resource *, int);
extern void queue_queued_twopc(struct drbd_resource *resource);
extern void queued_twopc_timer_fn(struct timer_list *t);
extern bool drbd_have_local_disk(struct drbd_resource *resource);
extern enum drbd_state_rv drbd_support_2pc_resize(struct drbd_resource *resource);
extern enum determine_dev_size
drbd_commit_size_change(struct drbd_device *device, struct resize_parms *rs, u64 nodes_to_reach);
extern void drbd_try_to_get_resynced(struct drbd_device *device);

static inline sector_t drbd_get_capacity(struct block_device *bdev)
{
	/* return bdev ? get_capacity(bdev->bd_disk) : 0; */
	return bdev ? i_size_read(bdev->bd_inode) >> 9 : 0;
}

/* sets the number of 512 byte sectors of our virtual device */
void drbd_set_my_capacity(struct drbd_device *device, sector_t size);

/*
 * used to submit our private bio
 */
static inline void drbd_submit_bio_noacct(struct drbd_device *device,
					     int fault_type, struct bio *bio)
{
	__release(local);

	if (drbd_insert_fault(device, fault_type)) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
	} else {
		submit_bio_noacct(bio);
	}
}

void drbd_bump_write_ordering(struct drbd_resource *resource, struct drbd_backing_dev *bdev,
			      enum write_ordering_e wo);

extern void twopc_timer_fn(struct timer_list *t);
extern void connect_timer_fn(struct timer_list *t);

/* drbd_proc.c */
extern struct proc_dir_entry *drbd_proc;
int drbd_seq_show(struct seq_file *seq, void *v);

/* drbd_actlog.c */
extern bool drbd_al_try_lock(struct drbd_device *device);
extern bool drbd_al_try_lock_for_transaction(struct drbd_device *device);
extern int drbd_al_begin_io_nonblock(struct drbd_device *device, struct drbd_interval *i);
extern void drbd_al_begin_io_commit(struct drbd_device *device);
extern bool drbd_al_begin_io_fastpath(struct drbd_device *device, struct drbd_interval *i);
extern int drbd_al_begin_io_for_peer(struct drbd_peer_device *peer_device, struct drbd_interval *i);
extern bool drbd_al_complete_io(struct drbd_device *device, struct drbd_interval *i);
extern void drbd_rs_complete_io(struct drbd_peer_device *, sector_t);
extern int drbd_rs_begin_io(struct drbd_peer_device *, sector_t);
extern int drbd_try_rs_begin_io(struct drbd_peer_device *, sector_t, bool);
extern void drbd_rs_cancel_all(struct drbd_peer_device *);
extern int drbd_rs_del_all(struct drbd_peer_device *);
extern void drbd_rs_failed_io(struct drbd_peer_device *, sector_t, int);
extern void drbd_advance_rs_marks(struct drbd_peer_device *, unsigned long);
extern bool drbd_set_all_out_of_sync(struct drbd_device *, sector_t, int);
extern bool drbd_set_sync(struct drbd_device *, sector_t, int, unsigned long, unsigned long);
enum update_sync_bits_mode { RECORD_RS_FAILED, SET_OUT_OF_SYNC, SET_IN_SYNC };
extern int __drbd_change_sync(struct drbd_peer_device *peer_device, sector_t sector, int size,
		enum update_sync_bits_mode mode);
#define drbd_set_in_sync(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, SET_IN_SYNC)
#define drbd_set_out_of_sync(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, SET_OUT_OF_SYNC)
#define drbd_rs_failed_io(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, RECORD_RS_FAILED)
extern void drbd_al_shrink(struct drbd_device *device);
extern bool drbd_sector_has_priority(struct drbd_peer_device *, sector_t);
extern int drbd_al_initialize(struct drbd_device *, void *);

/* drbd_nl.c */

extern struct mutex notification_mutex;
extern atomic_t drbd_genl_seq;

extern void notify_resource_state(struct sk_buff *,
				  unsigned int,
				  struct drbd_resource *,
				  struct resource_info *,
				  struct rename_resource_info *,
				  enum drbd_notification_type);
extern void notify_device_state(struct sk_buff *,
				unsigned int,
				struct drbd_device *,
				struct device_info *,
				enum drbd_notification_type);
extern void notify_connection_state(struct sk_buff *,
				    unsigned int,
				    struct drbd_connection *,
				    struct connection_info *,
				    enum drbd_notification_type);
extern void notify_peer_device_state(struct sk_buff *,
				     unsigned int,
				     struct drbd_peer_device *,
				     struct peer_device_info *,
				     enum drbd_notification_type);
extern void notify_helper(enum drbd_notification_type, struct drbd_device *,
			  struct drbd_connection *, const char *, int);
extern void notify_path(struct drbd_connection *, struct drbd_path *,
			enum drbd_notification_type);
extern void drbd_broadcast_peer_device_state(struct drbd_peer_device *);

extern sector_t drbd_local_max_size(struct drbd_device *device) __must_hold(local);
extern int drbd_open_ro_count(struct drbd_resource *resource);
/*
 * inline helper functions
 *************************/

static inline int drbd_peer_req_has_active_page(struct drbd_peer_request *peer_req)
{
	struct page *page = peer_req->page_chain.head;
	page_chain_for_each(page) {
		if (page_count(page) > 1)
			return 1;
	}
	return 0;
}

/*
 * When a device has a replication state above L_OFF, it must be
 * connected.  Otherwise, we report the connection state, which has values up
 * to C_CONNECTED == L_OFF.
 */
static inline int combined_conn_state(struct drbd_peer_device *peer_device, enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	if (repl_state > L_OFF)
		return repl_state;
	else
		return peer_device->connection->cstate[which];
}

enum drbd_force_detach_flags {
	DRBD_READ_ERROR,
	DRBD_WRITE_ERROR,
	DRBD_META_IO_ERROR,
	DRBD_FORCE_DETACH,
};

#define __drbd_chk_io_error(m,f) __drbd_chk_io_error_(m,f, __func__)
static inline void __drbd_chk_io_error_(struct drbd_device *device,
					enum drbd_force_detach_flags df,
					const char *where)
{
	enum drbd_io_error_p ep;

	rcu_read_lock();
	ep = rcu_dereference(device->ldev->disk_conf)->on_io_error;
	rcu_read_unlock();
	switch (ep) {
	case EP_PASS_ON: /* FIXME would this be better named "Ignore"? */
		if (df == DRBD_READ_ERROR ||  df == DRBD_WRITE_ERROR) {
			if (drbd_ratelimit())
				drbd_err(device, "Local IO failed in %s.\n", where);
			if (device->disk_state[NOW] > D_INCONSISTENT) {
				begin_state_change_locked(device->resource, CS_HARD);
				__change_disk_state(device, D_INCONSISTENT);
				end_state_change_locked(device->resource);
			}
			break;
		}
		fallthrough;	/* for DRBD_META_IO_ERROR or DRBD_FORCE_DETACH */
	case EP_DETACH:
	case EP_CALL_HELPER:
		/* Remember whether we saw a READ or WRITE error.
		 *
		 * Recovery of the affected area for WRITE failure is covered
		 * by the activity log.
		 * READ errors may fall outside that area though. Certain READ
		 * errors can be "healed" by writing good data to the affected
		 * blocks, which triggers block re-allocation in lower layers.
		 *
		 * If we can not write the bitmap after a READ error,
		 * we may need to trigger a full sync (see w_go_diskless()).
		 *
		 * Force-detach is not really an IO error, but rather a
		 * desperate measure to try to deal with a completely
		 * unresponsive lower level IO stack.
		 * Still it should be treated as a WRITE error.
		 *
		 * Meta IO error is always WRITE error:
		 * we read meta data only once during attach,
		 * which will fail in case of errors.
		 */
		if (df == DRBD_READ_ERROR)
			set_bit(WAS_READ_ERROR, &device->flags);
		if (df == DRBD_FORCE_DETACH)
			set_bit(FORCE_DETACH, &device->flags);
		if (device->disk_state[NOW] > D_FAILED) {
			begin_state_change_locked(device->resource, CS_HARD);
			__change_disk_state(device, D_FAILED);
			end_state_change_locked(device->resource);
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
	int error, enum drbd_force_detach_flags forcedetach, const char *where)
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
static inline sector_t drbd_md_first_sector(struct drbd_backing_dev *bdev)
{
	switch (bdev->md.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + bdev->md.bm_offset;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset;
	}
}

/**
 * drbd_md_last_sector() - Return the last sector number of the meta data area
 * @bdev:	Meta data block device.
 */
static inline sector_t drbd_md_last_sector(struct drbd_backing_dev *bdev)
{
	switch (bdev->md.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + (4096 >> 9) -1;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect -1;
	}
}

/**
 * drbd_md_ss() - Return the sector number of our meta data super block
 * @bdev:	Meta data block device.
 */
static inline sector_t drbd_md_ss(struct drbd_backing_dev *bdev)
{
	const int meta_dev_idx = bdev->md.meta_dev_idx;

	if (meta_dev_idx == DRBD_MD_INDEX_FLEX_EXT)
		return 0;

	/* Since drbd08, internal meta data is always "flexible".
	 * position: last 4k aligned block of 4k size */
	if (meta_dev_idx == DRBD_MD_INDEX_INTERNAL ||
	    meta_dev_idx == DRBD_MD_INDEX_FLEX_INT)
		return (drbd_get_capacity(bdev->backing_bdev) & ~7ULL) - 8;

	/* external, some index; this is the old fixed size layout */
	return (128 << 20 >> 9) * bdev->md.meta_dev_idx;
}

void drbd_queue_work(struct drbd_work_queue *, struct drbd_work *);

static inline void
drbd_queue_work_if_unqueued(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	if (list_empty_careful(&w->list))
		list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

static inline void
drbd_device_post_work(struct drbd_device *device, int work_bit)
{
	if (!test_and_set_bit(work_bit, &device->flags)) {
		struct drbd_resource *resource = device->resource;
		struct drbd_work_queue *q = &resource->work;
		if (!test_and_set_bit(DEVICE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

static inline void
drbd_peer_device_post_work(struct drbd_peer_device *peer_device, int work_bit)
{
	if (!test_and_set_bit(work_bit, &peer_device->flags)) {
		struct drbd_resource *resource = peer_device->device->resource;
		struct drbd_work_queue *q = &resource->work;
		if (!test_and_set_bit(PEER_DEVICE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

static inline void
drbd_post_work(struct drbd_resource *resource, int work_bit)
{
	if (!test_and_set_bit(work_bit, &resource->flags)) {
		struct drbd_work_queue *q = &resource->work;
		if (!test_and_set_bit(RESOURCE_WORK_PENDING, &resource->flags))
			wake_up(&q->q_wait);
	}
}

extern void drbd_flush_workqueue(struct drbd_work_queue *work_queue);

/* To get the ack_receiver out of the blocking network stack,
 * so it can change its sk_rcvtimeo from idle- to ping-timeout,
 * and send a ping, we need to send a signal.
 * Which signal we send is irrelevant. */
static inline void wake_ack_receiver(struct drbd_connection *connection)
{
	struct task_struct *task = connection->ack_receiver.task;
	if (task && get_t_state(&connection->ack_receiver) == RUNNING)
		send_sig(SIGXCPU, task, 1);
}

static inline void request_ping(struct drbd_connection *connection)
{
	set_bit(SEND_PING, &connection->flags);
	wake_ack_receiver(connection);
}

extern void *__conn_prepare_command(struct drbd_connection *, int, enum drbd_stream);
extern void *conn_prepare_command(struct drbd_connection *, int, enum drbd_stream);
extern void *drbd_prepare_command(struct drbd_peer_device *, int, enum drbd_stream);
extern int __send_command(struct drbd_connection *, int, enum drbd_packet, enum drbd_stream);
extern int send_command(struct drbd_connection *, int, enum drbd_packet, enum drbd_stream);
extern int drbd_send_command(struct drbd_peer_device *, enum drbd_packet, enum drbd_stream);

extern int drbd_send_ping(struct drbd_connection *connection);
extern int drbd_send_ping_ack(struct drbd_connection *connection);
extern int conn_send_state_req(struct drbd_connection *, int vnr, enum drbd_packet, union drbd_state, union drbd_state);
extern int conn_send_twopc_request(struct drbd_connection *, int vnr, enum drbd_packet, struct p_twopc_request *);
extern int drbd_send_peer_ack(struct drbd_connection *, struct drbd_request *);

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
 *    sender, even before it actually was queued or sent.
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
static inline void inc_ap_pending(struct drbd_peer_device *peer_device)
{
	atomic_inc(&peer_device->ap_pending_cnt);
}

#define dec_ap_pending(peer_device) \
	((void)expect((peer_device), __dec_ap_pending(peer_device) >= 0))
static inline int __dec_ap_pending(struct drbd_peer_device *peer_device)
{
	int ap_pending_cnt = atomic_dec_return(&peer_device->ap_pending_cnt);
	if (ap_pending_cnt == 0)
		wake_up(&peer_device->device->misc_wait);
	return ap_pending_cnt;
}

/* counts how many resync-related answers we still expect from the peer
 *		     increase			decrease
 * L_SYNC_TARGET sends P_RS_DATA_REQUEST (and expects P_RS_DATA_REPLY)
 * L_SYNC_SOURCE sends P_RS_DATA_REPLY   (and expects P_WRITE_ACK with ID_SYNCER)
 *					   (or P_NEG_ACK with ID_SYNCER)
 */
static inline void inc_rs_pending(struct drbd_peer_device *peer_device)
{
	atomic_inc(&peer_device->rs_pending_cnt);
}

#define dec_rs_pending(peer_device) \
	((void)expect((peer_device), __dec_rs_pending(peer_device) >= 0))
static inline int __dec_rs_pending(struct drbd_peer_device *peer_device)
{
	return atomic_dec_return(&peer_device->rs_pending_cnt);
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
static inline void inc_unacked(struct drbd_peer_device *peer_device)
{
	atomic_inc(&peer_device->unacked_cnt);
}

#define dec_unacked(peer_device) \
	((void)expect(peer_device, __dec_unacked(peer_device) >= 0))
static inline int __dec_unacked(struct drbd_peer_device *peer_device)
{
	return atomic_dec_return(&peer_device->unacked_cnt);
}

#define sub_unacked(peer_device, n) \
	((void)expect(peer_device, __sub_unacked(peer_device) >= 0))
static inline int __sub_unacked(struct drbd_peer_device *peer_device, int n)
{
	return atomic_sub_return(n, &peer_device->unacked_cnt);
}

static inline bool is_sync_target_state(struct drbd_peer_device *peer_device,
					enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	return repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T;
}

static inline bool is_sync_source_state(struct drbd_peer_device *peer_device,
					enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];

	return repl_state == L_SYNC_SOURCE || repl_state == L_PAUSED_SYNC_S;
}

static inline bool is_sync_state(struct drbd_peer_device *peer_device,
				 enum which_state which)
{
	return is_sync_source_state(peer_device, which) ||
		is_sync_target_state(peer_device, which);
}

static inline bool is_verify_state(struct drbd_peer_device *peer_device,
				   enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];
	return repl_state == L_VERIFY_S || repl_state == L_VERIFY_T;
}

/**
 * get_ldev() - Increase the ref count on device->ldev. Returns 0 if there is no ldev
 * @_device:		DRBD device.
 * @_min_state:		Minimum device state required for success.
 *
 * You have to call put_ldev() when finished working with device->ldev.
 */
#define get_ldev_if_state(_device, _min_state)				\
	(_get_ldev_if_state((_device), (_min_state)) ?			\
	 ({ __acquire(x); true; }) : false)
#define get_ldev(_device) get_ldev_if_state(_device, D_INCONSISTENT)

static inline void put_ldev(struct drbd_device *device)
{
	enum drbd_disk_state disk_state = device->disk_state[NOW];
	/* We must check the state *before* the atomic_dec becomes visible,
	 * or we have a theoretical race where someone hitting zero,
	 * while state still D_FAILED, will then see D_DISKLESS in the
	 * condition below and calling into destroy, where he must not, yet. */
	int i = atomic_dec_return(&device->local_cnt);

	/* This may be called from some endio handler,
	 * so we must not sleep here. */

	__release(local);
	D_ASSERT(device, i >= 0);
	if (i == 0) {
		if (disk_state == D_DISKLESS)
			/* even internal references gone, safe to destroy */
			drbd_device_post_work(device, DESTROY_DISK);
		if (disk_state == D_FAILED || disk_state == D_DETACHING)
			/* all application IO references gone. */
			if (!test_and_set_bit(GOING_DISKLESS, &device->flags))
				drbd_device_post_work(device, GO_DISKLESS);
		wake_up(&device->misc_wait);
	}
}

#ifndef __CHECKER__
static inline int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins)
{
	int io_allowed;

	/* never get a reference while D_DISKLESS */
	if (device->disk_state[NOW] == D_DISKLESS)
		return 0;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->disk_state[NOW] >= mins);
	if (!io_allowed)
		put_ldev(device);
	return io_allowed;
}
#else
extern int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins);
#endif

extern void drbd_queue_pending_bitmap_work(struct drbd_device *);

/* rw = READ or WRITE (0 or 1); nothing else. */
static inline void dec_ap_bio(struct drbd_device *device, int rw)
{
	unsigned int nr_requests = device->resource->res_opts.nr_requests;
	int ap_bio = atomic_dec_return(&device->ap_bio_cnt[rw]);

	D_ASSERT(device, ap_bio >= 0);

	/* Check for list_empty outside the lock is ok.  Worst case it queues
	 * nothing because someone else just now did.  During list_add, both
	 * resource->req_lock *and* a refcount on ap_bio_cnt[WRITE] are held,
	 * a list_add cannot race with this code path.
	 * Checking pending_bitmap_work.n is not correct,
	 * it has a different lifetime. */
	if (ap_bio == 0 && rw == WRITE && !list_empty(&device->pending_bitmap_work.q))
		drbd_queue_pending_bitmap_work(device);

	if (ap_bio == 0 || ap_bio == nr_requests-1)
		wake_up(&device->misc_wait);
}

static inline bool drbd_suspended(struct drbd_device *device)
{
	return device->resource->cached_susp;
}

static inline bool may_inc_ap_bio(struct drbd_device *device)
{
	if (drbd_suspended(device))
		return false;
	if (atomic_read(&device->suspend_cnt))
		return false;

	/* to avoid potential deadlock or bitmap corruption,
	 * in various places, we only allow new application io
	 * to start during "stable" states. */

	/* no new io accepted when attaching or detaching the disk */
	if (device->cached_state_unstable)
		return false;

	if (atomic_read(&device->pending_bitmap_work.n))
		return false;
	return true;
}

static inline bool drbd_set_exposed_data_uuid(struct drbd_device *device, u64 val)
{
	bool changed = (device->exposed_data_uuid & ~UUID_PRIMARY) != (val & ~UUID_PRIMARY);
	device->exposed_data_uuid = val;
	return changed;
}

static inline u64 drbd_current_uuid(struct drbd_device *device)
{
	if (!device->ldev)
		return 0;
	return device->ldev->md.current_uuid;
}

static inline bool verify_can_do_stop_sector(struct drbd_peer_device *peer_device)
{
	return peer_device->connection->agreed_pro_version >= 97 &&
		peer_device->connection->agreed_pro_version != 100;
}

static inline u64 drbd_bitmap_uuid(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md;

	if (!device->ldev)
		return 0;

	peer_md = &device->ldev->md.peers[peer_device->node_id];
	return peer_md->bitmap_uuid;
}

static inline u64 drbd_history_uuid(struct drbd_device *device, int i)
{
	if (!device->ldev || i >= ARRAY_SIZE(device->ldev->md.history_uuids))
		return 0;

	return device->ldev->md.history_uuids[i];
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

/* resync bitmap */
/* 128MB sized 'bitmap extent' to track syncer usage */
struct bm_extent {
	int rs_left; /* number of bits set (out of sync) in this extent. */
	int rs_failed; /* number of failed resync requests in this extent. */
	unsigned long flags;
	struct lc_element lce;
};

#define BME_NO_WRITES  0  /* bm_extent.flags: no more requests on this one! */
#define BME_LOCKED     1  /* bm_extent.flags: syncer active on this one. */
#define BME_PRIORITY   2  /* finish resync IO on this extent ASAP! App IO waiting! */

static inline struct drbd_connection *first_connection(struct drbd_resource *resource)
{
	return list_first_entry_or_null(&resource->connections,
				struct drbd_connection, connections);
}

#define NODE_MASK(id) ((u64)1 << (id))

#ifdef CONFIG_DRBD_TIMING_STATS
#define ktime_aggregate_delta(D, ST, M) D->M = ktime_add(D->M, ktime_sub(ktime_get(), ST))
#define ktime_aggregate(D, R, M) D->M = ktime_add(D->M, ktime_sub(R->M, R->start_kt))
#define ktime_aggregate_pd(P, N, R, M) P->M = ktime_add(P->M, ktime_sub(R->M[N], R->start_kt))
#define ktime_get_accounting(V) V = ktime_get()
#define ktime_get_accounting_assign(V, T) V = T
#define ktime_var_for_accounting(V) ktime_t V = ktime_get()
#else
#define ktime_aggregate_delta(D, ST, M)
#define ktime_aggregate(D, R, M)
#define ktime_aggregate_pd(P, N, R, M)
#define ktime_get_accounting(V)
#define ktime_get_accounting_assign(V, T)
#define ktime_var_for_accounting(V)
#endif

#endif
