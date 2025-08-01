/* SPDX-License-Identifier: GPL-2.0-only */
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
#include <linux/idr.h>
#include <linux/lru_cache.h>
#include <linux/prefetch.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd.h>
#include <linux/drbd_config.h>

#include "drbd_strings.h"
#include "drbd_state.h"
#include "drbd_state_change.h"
#include "drbd_protocol.h"
#include "drbd_kref_debug.h"
#include "drbd_transport.h"
#include "drbd_polymorph_printk.h"

/* module parameter, defined in drbd_main.c */
extern unsigned int drbd_minor_count;
extern unsigned int drbd_protocol_version_min;
extern bool drbd_strict_names;

static inline bool drbd_protocol_version_acceptable(unsigned int pv)
{
	return	/* DRBD 9 */ (pv >= PRO_VERSION_MIN && pv <= PRO_VERSION_MAX) ||
		/* DRBD 8 */ (pv >= PRO_VERSION_8_MIN && pv <= PRO_VERSION_8_MAX);
}

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

/* For compatibility with protocol < 122 */
#define ID_SKIP         (4710ULL)
#define ID_IN_SYNC      (4711ULL)
#define ID_OUT_OF_SYNC  (4712ULL)
#define ID_SYNCER (-1ULL)

static inline enum ov_result drbd_block_id_to_ov_result(u64 block_id)
{
	switch (block_id) {
	case ID_IN_SYNC:
		return OV_RESULT_IN_SYNC;
	case ID_OUT_OF_SYNC:
		return OV_RESULT_OUT_OF_SYNC;
	default:
		return OV_RESULT_SKIP;
	}
}

static inline u64 drbd_ov_result_to_block_id(enum ov_result result)
{
	switch (result) {
	case OV_RESULT_IN_SYNC:
		return ID_IN_SYNC;
	case OV_RESULT_OUT_OF_SYNC:
		return ID_OUT_OF_SYNC;
	default:
		return ID_SKIP;
	}
}

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

unsigned int
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

extern struct idr drbd_devices; /* RCU, updates: drbd_devices_lock */
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

void INFO_bm_xfer_stats(struct drbd_peer_device *peer_device,
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

unsigned int drbd_header_size(struct drbd_connection *connection);

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
	int (*function)(struct drbd_thread *thi);
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
	int (*cb)(struct drbd_work *w, int cancel);
};

struct drbd_peer_device_work {
	struct drbd_work w;
	struct drbd_peer_device *peer_device;
};

enum drbd_stream;

#include "drbd_interval.h"

void lock_all_resources(void);
void unlock_all_resources(void);

enum drbd_disk_state disk_state_from_md(struct drbd_device *device);
bool want_bitmap(struct drbd_peer_device *peer_device);
long twopc_timeout(struct drbd_resource *resource);
long twopc_retry_timeout(struct drbd_resource *resource, int retries);
void twopc_connection_down(struct drbd_connection *connection);
u64 directly_connected_nodes(struct drbd_resource *resource,
			     enum which_state which);

/* sequence arithmetic for dagtag (data generation tag) sector numbers.
 * dagtag_newer_eq: true, if a is newer than b */
#define dagtag_newer_eq(a, b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) >= 0))

#define dagtag_newer(a, b)      \
	(typecheck(u64, a) && \
	 typecheck(u64, b) && \
	((s64)(a) - (s64)(b) > 0))

/* An application I/O request.
 *
 * Fields marked as "immutable" may only be modified when the request is
 * exclusively owned, e.g. when the request is created or is being retried.
 */
struct drbd_request {
	/* "immutable" */
	struct drbd_device *device;

	/* if local IO is not allowed, will be NULL.
	 * if local IO _is_ allowed, holds the locally submitted bio clone,
	 * or, after local IO completion, the ERR_PTR(error).
	 * see drbd_request_endio().
	 *
	 * Only accessed by app/submitter/endio - strictly sequential,
	 * no serialization required. */
	struct bio *private_bio;

	/* Fields sector and size are "immutable". Other fields protected
	 * by interval_lock. */
	struct drbd_interval i;

	/* epoch: used to check on "completion" whether this req was in
	 * the current epoch, and we therefore have to close it,
	 * causing a p_barrier packet to be send, starting a new epoch.
	 *
	 * This corresponds to "barrier" in struct p_barrier[_ack],
	 * and to "barrier_nr" in struct drbd_epoch (and various
	 * comments/function parameters/local variable names).
	 *
	 * "immutable"
	 */
	unsigned int epoch;

	/* Position of this request in the serialized per-resource change
	 * stream. Can be used to serialize with other events when
	 * communicating the change stream via multiple connections.
	 * Assigned from device->resource->dagtag_sector.
	 *
	 * Given that some IO backends write several GB per second meanwhile,
	 * lets just use a 64bit sequence space.
	 *
	 * "immutable"
	 */
	u64 dagtag_sector;

	/* list entry in transfer log (protected by RCU) */
	struct list_head tl_requests;

	/* list entry in submitter lists, peer ack list, or retry lists;
	 * protected by the locks for those lists */
	struct list_head list;

	/* master bio pointer; "immutable" */
	struct bio *master_bio;

	/* see struct drbd_device */
	struct list_head req_pending_master_completion;
	struct list_head req_pending_local;

	/* for generic IO accounting; "immutable" */
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

	/* Creates a dependency chain between writes so that we know that a
	 * peer ack can be sent when kref reaches zero.
	 *
	 * If not NULL, destruction of this drbd_request will
	 * cause kref_put() on ->destroy_next.
	 *
	 * "immutable" */
	struct drbd_request *destroy_next;

	/* lock to protect state flags */
	spinlock_t rq_lock;
	unsigned int local_rq_state;
	u16 net_rq_state[DRBD_NODE_ID_MAX];

	/* for reclaim from transfer log */
	struct rcu_head rcu;
};

/* Used to multicast peer acks. */
struct drbd_peer_ack {
	struct drbd_resource *resource;
	struct list_head list;
	/*
	 * Keeps track of which connections have not yet processed this peer
	 * ack. Peer acks are queued for connections on which they are not sent
	 * so that last_peer_ack_dagtag_seen is updated at the correct moment.
	 */
	u64 queued_mask;
	u64 pending_mask; /* Peer ack is sent to these nodes */
	u64 mask; /* Nodes which successfully wrote the requests covered by this peer ack */
	u64 dagtag_sector;
};

/* Tracks received writes grouped in epochs. Protected by epoch_lock. */
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
	struct list_head recv_order; /* see peer_requests, peer_reads, resync_requests */

	union {
		struct { /* read requests */
			unsigned int depend_dagtag_node_id;
			u64 depend_dagtag;
		};
		struct { /* resync target requests */
			unsigned int requested_size;
		};
	};

	struct drbd_page_chain_head page_chain;
	blk_opf_t opf; /* to be used as bi_opf */
	atomic_t pending_bios;
	struct drbd_interval i;
	unsigned long flags;	/* see comments on ee flag bits below */
	union {
		struct { /* regular peer_request */
			struct drbd_epoch *epoch; /* for writes */
			unsigned long submit_jif;
			u64 block_id;
			struct digest_info *digest;
			u64 dagtag_sector;
		};
		struct { /* reused object for sending OOS to other nodes */
			u64 send_oos_pending;
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

	/* The peer wants a write ACK for this (wire proto C) */
	__EE_SEND_WRITE_ACK,

	/* hand back using mempool_free(e, drbd_buffer_page_pool) */
	__EE_RELEASE_TO_MEMPOOL,

	/* this is/was a write same request */
	__EE_WRITE_SAME,

	/* On target: Send P_RS_THIN_REQ.
	 * On source: If it contains only 0 bytes, send back P_RS_DEALLOCATED. */
	__EE_RS_THIN_REQ,

	/* Hold reference in activity log */
	__EE_IN_ACTLOG,

	/* SyncTarget: This is the last resync request. */
	__EE_LAST_RESYNC_REQUEST,

	/* This peer_req->recv_order is on some list */
	__EE_ON_RECV_ORDER,
};
#define EE_MAY_SET_IN_SYNC     (1<<__EE_MAY_SET_IN_SYNC)
#define EE_SET_OUT_OF_SYNC     (1<<__EE_SET_OUT_OF_SYNC)
#define EE_IS_BARRIER          (1<<__EE_IS_BARRIER)
#define EE_TRIM                (1<<__EE_TRIM)
#define EE_ZEROOUT             (1<<__EE_ZEROOUT)
#define EE_RESUBMITTED         (1<<__EE_RESUBMITTED)
#define EE_WAS_ERROR           (1<<__EE_WAS_ERROR)
#define EE_HAS_DIGEST          (1<<__EE_HAS_DIGEST)
#define EE_SEND_WRITE_ACK	(1<<__EE_SEND_WRITE_ACK)
#define EE_RELEASE_TO_MEMPOOL	(1<<__EE_RELEASE_TO_MEMPOOL)
#define EE_WRITE_SAME		(1<<__EE_WRITE_SAME)
#define EE_RS_THIN_REQ		(1<<__EE_RS_THIN_REQ)
#define EE_IN_ACTLOG		(1<<__EE_IN_ACTLOG)
#define EE_LAST_RESYNC_REQUEST	(1<<__EE_LAST_RESYNC_REQUEST)
#define EE_ON_RECV_ORDER	(1<<__EE_ON_RECV_ORDER)

/* flag bits per device */
enum device_flag {
	MD_DIRTY,		/* current uuids and flags not yet on disk */
	CRASHED_PRIMARY,	/* This node was a crashed primary.
				 * Gets cleared when the state.conn
				 * goes into L_ESTABLISHED state. */
	MD_NO_FUA,		/* meta data device does not support barriers,
				   so don't even try */
	FORCE_DETACH,		/* Force-detach from local disk, aborting any pending local IO */
	ABORT_MDIO,		/* Interrupt ongoing meta-data I/O */
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
	MD_SYNC,		/* tell worker to call drbd_md_sync() */
	MAKE_NEW_CUR_UUID,	/* tell worker to ping peers and eventually write new current uuid */

	STABLE_RESYNC,		/* One peer_device finished the resync stable! */
	READ_BALANCE_RR,
	PRIMARY_LOST_QUORUM,
	TIEBREAKER_QUORUM,	/* Tiebreaker keeps quorum; used to avoid too verbose logging */
	DESTROYING_DEV,
	TRY_TO_GET_RESYNC,
	OUTDATE_ON_2PC_COMMIT,
	RESTORE_QUORUM,		/* Restore quorum when we have the same members as before */
	RESTORING_QUORUM,	/* sanitize_state() -> finish_state_change() */
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
	RECONCILIATION_RESYNC,
	UNSTABLE_RESYNC,	/* Sync source went unstable during resync. */
	SEND_STATE_AFTER_AHEAD,
	GOT_NEG_ACK,		/* got a neg_ack while primary, wait until peer_disk is lower than
				   D_UP_TO_DATE before becoming secondary! */
	AHEAD_TO_SYNC_SOURCE,   /* Ahead -> SyncSource queued */
	SYNC_TARGET_TO_BEHIND,  /* SyncTarget, wait for Behind */
	HANDLING_CONGESTION,    /* Set while testing for congestion and handling it */
	HANDLE_CONGESTION,      /* tell worker to change state due to congestion */
	HOLDING_UUID_READ_LOCK, /* did a down_read(&device->uuid_sem) */
	RS_SOURCE_MISSED_END,   /* SyncSource did not got P_UUIDS110 */
	RS_PEER_MISSED_END,     /* Peer (which was SyncSource) did not got P_UUIDS110 after resync */
	SYNC_SRC_CRASHED_PRI,   /* Source of this resync was a crashed primary */
	HAVE_SIZES,		/* Cleared when connection gets lost; set when sizes received */
	UUIDS_RECEIVED,		/* Have recent UUIDs from the peer */
	CURRENT_UUID_RECEIVED,	/* Got a p_current_uuid packet */
	PEER_QUORATE,		/* Peer has quorum */
	RS_REQUEST_UNSUCCESSFUL, /* Some resync request was unsuccessful in current cycle */
	REPLICATION_NEXT, /* If unset, do not replicate writes when next Inconsistent */
	PEER_REPLICATION_NEXT, /* We have instructed peer not to replicate writes */
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
	spinlock_t bm_lock;		/* fine-grain lock (TODO: per slot) */
	spinlock_t bm_all_slots_lock;	/* all bitmap slots lock */

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
	const char    *bm_why;
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
	u64 prev_members;	/* read from the meta-data */
	u64 members;		/* current member mask for writing meta-data */
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
	struct file *backing_bdev_file;
	struct block_device *md_bdev;
	struct file *f_md_bdev;
	struct drbd_md md;
	struct disk_conf __rcu *disk_conf; /* RCU, for updates: resource->conf_update */
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
	int (*io_fn)(struct drbd_device *device,
		     struct drbd_peer_device *peer_device);
	void (*done)(struct drbd_device *device,
		     struct drbd_peer_device *peer_device,
		     int rv);
};

struct fifo_buffer {
	/* singly linked list to accumulate multiple such struct fifo_buffers,
	 * to be freed after a single syncronize_rcu(),
	 * outside a critical section. */
	struct fifo_buffer *next;
	unsigned int head_index;
	unsigned int size;
	int total; /* sum of all values */
	int values[] __counted_by(size);
};
struct fifo_buffer *fifo_alloc(unsigned int fifo_size);

/* flag bits per connection */
enum connection_flag {
	PING_PENDING,		/* cleared upon receiveing a ping_ack packet, wakes state_wait */
	TWOPC_PREPARED,
	TWOPC_YES,
	TWOPC_NO,
	TWOPC_RETRY,
	CONN_DRY_RUN,		/* Expect disconnect after resync handshake. */
	DISCONNECT_EXPECTED,
	BARRIER_ACK_PENDING,
	CORKED,
	DATA_CORKED = CORKED,	/* used as computed value CORKED + DATA_STREAM */
	CONTROL_CORKED,		/* used as computed value CORKED + CONTROL_STREAM */
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
	RECEIVED_DAGTAG, /* Whether we received any write or dagtag since connecting. */
	PING_TIMEOUT_ACTIVE,
};

/* flag bits per resource */
enum resource_flag {
	EXPLICIT_PRIMARY,
	CALLBACK_PENDING,	/* Whether we have a call_usermodehelper(, UMH_WAIT_PROC)
				 * pending, from drbd worker context.
				 */
	TWOPC_ABORT_LOCAL,
	TWOPC_WORK_PENDING,     /* Set while work for sending reply is scheduled */
	TWOPC_EXECUTED,         /* Commited or aborted */
	TWOPC_STATE_CHANGE_PENDING, /* set between sending commit and changing local state */

	TRY_BECOME_UP_TO_DATE_PENDING,

	DEVICE_WORK_PENDING,	/* tell worker that some device has pending work */
	PEER_DEVICE_WORK_PENDING,/* tell worker that some peer_device has pending work */

	/* to be used in drbd_post_work() */
	R_UNREGISTERED,
	DOWN_IN_PROGRESS,
	CHECKING_PEERS,
	WRONG_MDF_EXISTS,	/* Warned about MDF_EXISTS flag on all peer slots */
	TWOPC_RECV_SIZES_ERR,	/* Error processing sizes packet during 2PC connect */
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

struct twopc_request {
	u64 nodes_to_reach;
	enum drbd_packet cmd;
	unsigned int tid;
	int initiator_node_id;
	int target_node_id;
	int vnr;
	u32 flags;
};

struct drbd_thread_timing_details {
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

struct drbd_mutable_buffer {
	u8 *buffer;
	unsigned int avail;
};

enum drbd_per_resource_ratelimit {
	D_RL_R_NOLIMIT = -1,
	D_RL_R_GENERIC,
};

struct drbd_resource {
	char *name;
#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_res;
	struct dentry *debugfs_res_volumes;
	struct dentry *debugfs_res_connections;
	struct dentry *debugfs_res_in_flight_summary;
	struct dentry *debugfs_res_state_twopc;
	struct dentry *debugfs_res_worker_pid;
	struct dentry *debugfs_res_members;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;

	/* Volume number to device mapping. Updates protected by conf_update. */
	struct idr devices;

	struct ratelimit_state ratelimit[1];

	/* RCU list. Updates protected by adm_mutex, conf_update and state_rwlock. */
	struct list_head connections;

	struct list_head resources;     /* list entry in global resources list */
	struct res_opts res_opts;
	int max_node_id;
	/*
	 * For read-copy-update of net_conf and disk_conf and devices,
	 * connection, peer_devices and paths lists.
	 */
	struct mutex conf_update;
	struct mutex adm_mutex;		/* mutex to serialize administrative requests */
	struct mutex open_release;	/* serialize open/release */
	struct {
		char comm[TASK_COMM_LEN];
		unsigned int minor;
		pid_t pid;
		ktime_t opened;
	} auto_promoted_by;

	rwlock_t state_rwlock;          /* serialize state changes */
	u64 dagtag_sector;		/* Protected by tl_update_lock.
					 * See also dagtag_sector in
					 * &drbd_request */
	u64 dagtag_from_backing_dev;
	u64 dagtag_before_attach;
	u64 members;			/* mask of online nodes */
	unsigned long flags;

	/* Protects updates to the transfer log and related counters. */
	spinlock_t tl_update_lock;
	struct list_head transfer_log;	/* all requests not yet fully processed */
	struct drbd_request *tl_previous_write;

	spinlock_t peer_ack_lock;
	struct list_head peer_ack_req_list;  /* requests to send peer acks for */
	struct list_head peer_ack_list;  /* peer acks to send */
	struct drbd_work peer_ack_work;
	u64 last_peer_acked_dagtag;  /* dagtag of last PEER_ACK'ed request */
	struct drbd_request *peer_ack_req;  /* last request not yet PEER_ACK'ed */

	/* Protects current_flush_sequence and pending_flush_mask (connection) */
	spinlock_t initiator_flush_lock;
	u64 current_flush_sequence;

	struct semaphore state_sem;
	wait_queue_head_t state_wait;  /* upon each state change. */
	enum chg_state_flags state_change_flags;
	const char **state_change_err_str;
	bool remote_state_change;  /* remote state change in progress */
	enum drbd_packet twopc_prepare_reply_cmd; /* this node's answer to the prepare phase or 0 */
	u64 twopc_parent_nodes;
	struct twopc_reply twopc_reply;
	struct timer_list twopc_timer;
	struct work_struct twopc_work;
	wait_queue_head_t twopc_wait;
	struct {
		enum twopc_type type;
		union {
			struct twopc_resize {
				int dds_flags;		   /* from prepare phase */
				sector_t user_size;	   /* from prepare phase */
				u64 diskful_primary_nodes; /* added in commit phase */
				u64 new_size;		   /* added in commit phase */
			} resize;
			struct twopc_state_change {
				union drbd_state mask;	/* from prepare phase */
				union drbd_state val;	/* from prepare phase */
				u64 primary_nodes;	/* added in commit phase */
				u64 reachable_nodes;	/* added in commit phase */
			} state_change;
		};
	} twopc;
	enum drbd_role role[2];
	bool susp_user[2];			/* IO suspended by user */
	bool susp_nod[2];		/* IO suspended because no data */
	bool susp_quorum[2];		/* IO suspended because no quorum */
	bool susp_uuid[2];		/* IO suspended because waiting new current UUID */
	bool fail_io[2];		/* Fail all IO requests because forced a demote */
	bool cached_susp;		/* cached result of looking at all different suspend bits */
	bool cached_all_devices_have_quorum;

	enum write_ordering_e write_ordering;

	/* Protects the current transfer log (tle) fields. */
	spinlock_t current_tle_lock;
	atomic_t current_tle_nr;	/* transfer log epoch number */
	unsigned current_tle_writes;	/* writes seen within this tl epoch */

	unsigned cached_min_aggreed_protocol_version;

	cpumask_var_t cpu_mask;

	struct drbd_work_queue work;
	struct drbd_thread worker;

	struct list_head listeners;
	spinlock_t listeners_lock;

	struct timer_list peer_ack_timer; /* send a P_PEER_ACK after last completion */

	unsigned int w_cb_nr; /* keeps counting up */
	struct drbd_thread_timing_details w_timing_details[DRBD_THREAD_DETAILS_HIST];
	wait_queue_head_t barrier_wait;  /* upon each state change. */
	struct rcu_head rcu;

	struct list_head suspended_reqs;
	/*
	 * The side effects of an empty state change two-phase commit are:
	 *
	 * * A local consistent disk can upgrade to up-to-date when no primary is reachable
	 *   (or become outdated if the prepare packets reach a primary).
	 *
	 * * resource->members are updates
	 *
	 * * Faraway nodes might outdate themselves if they learn about the existence of a primary
	 *   (with access to data) node.
	 */
	struct work_struct empty_twopc;
};

enum drbd_per_connection_ratelimit {
	D_RL_C_NOLIMIT = -1,
	D_RL_C_GENERIC,
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
	struct dentry *debugfs_conn_receiver_pid;
	struct dentry *debugfs_conn_sender_pid;
#endif
	struct kref kref;
	struct kref_debug_info kref_debug;
	struct idr peer_devices;	/* volume number to peer device mapping */
	enum drbd_conn_state cstate[2];
	enum drbd_role peer_role[2];
	bool susp_fen[2];		/* IO suspended because fence peer handler runs */

	struct ratelimit_state ratelimit[1];

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
	struct workqueue_struct *ack_sender;
	struct work_struct peer_ack_work;

	/* Work for sending P_OUT_OF_SYNC due to P_PEER_ACK */
	struct drbd_work send_oos_work;
	/*
	 * These peers have sent us a P_PEER_ACK for which we need to send
	 * P_OUT_OF_SYNC on this connection.
	 */
	unsigned long send_oos_from_mask;

	atomic64_t last_dagtag_sector;
	u64 last_peer_ack_dagtag_seen;

	/* Mask of nodes from which we are waiting for a flush ack corresponding to this Primary */
	u64 pending_flush_mask;

	/* Protects the flush members below for this connection */
	spinlock_t primary_flush_lock;
	/* For handling P_FLUSH_REQUESTS from this peer */
	u64 flush_requests_dagtag;
	u64 flush_sequence;
	u64 flush_forward_sent_mask;

	/* For handling forwarded flushes. On connection to initiator node. */
	spinlock_t flush_ack_lock;
	struct drbd_work flush_ack_work;
	/* For forwarded flushes. On connection to initiator node. Indexed by primary node ID */
	u64 flush_ack_sequence[DRBD_PEERS_MAX];

	atomic_t active_ee_cnt; /* Peer write requests waiting for activity log or backing disk. */
	atomic_t backing_ee_cnt; /* Other peer requests waiting for conflicts or backing disk. */
	atomic_t done_ee_cnt;
	spinlock_t peer_reqs_lock;
	spinlock_t send_oos_lock; /* Protects send_oos list */

	/* Lists using drbd_peer_request.recv_order (see also drbd_peer_device.resync_requests) */
	struct list_head peer_requests; /* All peer writes in the order we received them */
	struct list_head peer_reads; /* All reads in the order we received them */
	/*
	 * Peer writes for which we need to send some P_OUT_OF_SYNC. These peer
	 * writes continue to be stored on the connection over which the writes
	 * and the P_PEER_ACK are received. They are accessed by the sender for
	 * each relevant peer. Protected by send_oos_lock on this connection.
	 */
	struct list_head send_oos;

	/* Lists using drbd_peer_request.w.list */
	struct list_head done_ee;   /* Need to send P_WRITE_ACK/P_RS_WRITE_ACK */
	struct list_head dagtag_wait_ee; /* Resync read waiting for dagtag to be reached */
	struct list_head resync_ack_ee;   /* P_RS_DATA_REPLY sent, waiting for P_RS_WRITE_ACK */

	struct work_struct send_acks_work;
	struct work_struct send_ping_ack_work;
	struct work_struct send_ping_work;
	wait_queue_head_t ee_wait;

	atomic_t pp_in_use;		/* allocated from page pool */
	atomic_t pp_in_use_by_net;	/* sendpage()d, still referenced by transport */
	/* sender side */
	struct drbd_work_queue sender_work;

	struct drbd_work send_dagtag_work;
	u64 send_dagtag;

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
		 * req_next is only accessed by drbd_sender thread, in
		 * case of a resend from some worker, but then regular IO
		 * is suspended.
		 */
		struct drbd_request *req_next;
	} todo;

	/* cached pointers,
	 * so we can look up the oldest pending requests more quickly.
	 * TODO: RCU */
	struct drbd_request *req_ack_pending;
	/* The oldest request that is or was queued for this peer, but is not
	 * done towards it. */
	struct drbd_request *req_not_net_done;
	/* Protects the caching pointers from being advanced concurrently. */
	spinlock_t advance_cache_ptr_lock;

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

		/* Position in change stream of last write sent. */
		u64 current_dagtag_sector;

		/* Position in change stream of last queued request seen. */
		u64 seen_dagtag_sector;
	} send;

	struct {
		u64 dagtag_sector;
		int lost_node_id;
	} after_reconciliation;

	unsigned int peer_node_id;

	struct drbd_mutable_buffer reassemble_buffer;
	union {
		u8 bytes[8];
		struct p_block_ack block_ack;
		struct p_barrier_ack barrier_ack;
		struct p_confirm_stable confirm_stable;
		struct p_peer_ack peer_ack;
		struct p_peer_block_desc peer_block_desc;
		struct p_twopc_reply twopc_reply;
	} reassemble_buffer_bytes;

	/* Used when a network namespace is removed to track all connections
	 * that need disconnecting. */
	struct list_head remove_net_list;

	struct rcu_head rcu;

	unsigned int ctl_packets;
	unsigned int ctl_bytes;

	struct drbd_transport transport; /* The transport needs to be the last member. The acutal
					    implementation might have more members than the
					    abstract one. */
};

/* used to get the next lower or next higher peer_device depending on device node-id */
enum drbd_neighbor {
	NEXT_LOWER,
	NEXT_HIGHER
};

enum drbd_per_peer_device_ratelimit {
	D_RL_PD_NOLIMIT = -1,
	D_RL_PD_GENERIC,
};

struct drbd_peer_device {
	struct list_head peer_devices;
	struct drbd_device *device;
	struct drbd_connection *connection;
	struct peer_device_conf __rcu *conf; /* RCU, for updates: resource->conf_update */
	enum drbd_disk_state disk_state[2];
	enum drbd_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
	bool resync_susp_other_c[2];
	bool resync_active[2];
	bool replication[2]; /* Only while peer is Inconsistent: Is replication enabled? */
	bool peer_replication[2]; /* Whether we have instructed peer to replicate to us */
	enum drbd_repl_state negotiation_result; /* To find disk state after attach */
	unsigned int send_cnt;
	unsigned int recv_cnt;
	atomic_t packet_seq;
	unsigned int peer_seq;
	spinlock_t peer_seq_lock;
	uint64_t d_size;  /* size of disk */
	uint64_t u_size;  /* user requested size */
	uint64_t c_size;  /* current exported size */
	uint64_t max_size;
	int bitmap_index;
	int node_id;

	struct ratelimit_state ratelimit[1];

	unsigned long flags;

	enum drbd_repl_state start_resync_side;
	enum drbd_repl_state last_repl_state; /* What we received from the peer */
	struct timer_list start_resync_timer;
	struct drbd_work resync_work;
	struct timer_list resync_timer;
	struct drbd_work propagate_uuids_work;

	enum drbd_disk_state resync_finished_pdsk; /* Finished while starting resync */
	int resync_again; /* decided to resync again while resync running */
	sector_t last_peers_in_sync_end; /* sector after end of last scheduled peers-in-sync */
	unsigned long resync_next_bit; /* bitmap bit to search from for next resync request */
	unsigned long last_resync_pass_bits; /* bitmap weight at end of previous pass */

	atomic_t ap_pending_cnt; /* AP data packets on the wire, ack expected (RQ_NET_PENDING set) */
	atomic_t unacked_cnt;	 /* Need to send replies for */
	atomic_t rs_pending_cnt; /* RS request/data packets on the wire */

	/* Protected by connection->peer_reqs_lock */
	struct list_head resync_requests; /* Resync requests in the order we sent them */
	/*
	 * If not NULL, all requests in resync_requests until this one have
	 * been received. Discards are only counted as "received" once merging
	 * is complete.
	 */
	struct drbd_peer_request *received_last;
	/*
	 * If not NULL, all requests in resync_requests after received_last
	 * until this one are discards.
	 */
	struct drbd_peer_request *discard_last;

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
	unsigned long rs_last_progress_report_ts;
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
	struct fifo_buffer __rcu *rs_plan_s; /* correction values of resync planer (RCU, connection->conn_update) */
	atomic_t rs_sect_in; /* for incoming resync data rate, SyncTarget */
	int rs_last_events;  /* counter of read or write "events" (unit sectors)
			      * on the lower level device when we last looked. */
	int rs_in_flight; /* resync sectors in flight (to proxy, in proxy and from proxy) */
	ktime_t rs_last_mk_req_kt;
	atomic64_t ov_left; /* in bits */
	unsigned long ov_skipped; /* in bits */
	u64 rs_start_uuid;

	u64 current_uuid;
	u64 bitmap_uuids[DRBD_PEERS_MAX];
	u64 history_uuids[HISTORY_UUIDS];
	u64 dirty_bits;
	u64 uuid_flags;
	u64 uuid_node_mask; /* might be authoritative_nodes or weak_nodes */

	unsigned long comm_bm_set; /* communicated number of set bits. */
	u64 comm_current_uuid; /* communicated current UUID */
	u64 comm_uuid_flags; /* communicated UUID flags */
	u64 comm_bitmap_uuid;
	union drbd_state comm_state;

#ifdef CONFIG_DEBUG_FS
	struct dentry *debugfs_peer_dev;
	struct dentry *debugfs_peer_dev_proc_drbd;
#endif
	ktime_t pre_send_kt;
	ktime_t acked_kt;
	ktime_t net_done_kt;

	struct {/* sender todo per peer_device */
		bool was_sending_out_of_sync;
	} todo;
	union drbd_state connect_state;
	struct {
		unsigned int	physical_block_size;
		unsigned int	logical_block_size;
		unsigned int	alignment_offset;
		unsigned int	io_min;
		unsigned int	io_opt;
		unsigned int	max_bio_size;
	} q_limits;
};

struct conflict_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t lock;
	struct list_head resync_writes;
	struct list_head resync_reads;
	struct list_head writes;
	struct list_head peer_writes;
};

struct submit_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t lock;
	struct list_head writes;
	struct list_head peer_writes;
};

struct opener {
	struct list_head list;
	char comm[TASK_COMM_LEN];
	pid_t pid;
	ktime_t opened;
};

enum drbd_per_device_ratelimit {
	D_RL_D_NOLIMIT = -1,
	D_RL_D_GENERIC,
	D_RL_D_METADATA,
	D_RL_D_BACKEND,
	__D_RL_D_N
};

struct drbd_device {
	struct drbd_resource *resource;

	/* RCU list. Updates protected by adm_mutex, conf_update and state_rwlock. */
	struct list_head peer_devices;

	spinlock_t pending_bmio_lock;
	struct list_head pending_bitmap_io;

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
	struct dentry *debugfs_vol_interval_tree;
	struct dentry *debugfs_vol_al_updates;
#ifdef CONFIG_DRBD_TIMING_STATS
	struct dentry *debugfs_vol_req_timing;
#endif
#endif
	struct ratelimit_state ratelimit[__D_RL_D_N];

	unsigned int vnr;	/* volume number within the resource */
	unsigned int minor;	/* device minor number */

	struct kref kref;
	struct kref_debug_info kref_debug;

	/* things that are stored as / read from meta data on disk */
	unsigned long flags;

	/* configured by drbdsetup */
	struct drbd_backing_dev *ldev;

	/* Used to close backing devices and destroy related structures. */
	struct work_struct ldev_destroy_work;

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

	/* Interval trees of pending requests */
	spinlock_t interval_lock;
	struct rb_root read_requests; /* Local reads */
	struct rb_root requests; /* Local and peer writes, resync operations etc. */

	/* for statistics and timeouts */
	/* [0] read, [1] write */
	spinlock_t pending_completion_lock;
	struct list_head pending_master_completion[2];
	struct list_head pending_completion[2];

	struct drbd_bitmap *bitmap;

	int open_cnt;
	bool writable;
	/* FIXME clean comments, restructure so it is more obvious which
	 * members are protected by what */

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

	/* any requests that were blocked due to conflicts with other requests
	 * or resync are submitted on this ordered work queue */
	struct conflict_worker submit_conflict;
	/* any requests that would block due to the activity log
	 * are deferred to this ordered work queue */
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
	struct list_head openers;
	spinlock_t openers_lock;

	struct rcu_head rcu;
	struct work_struct finalize_work;
};

struct drbd_bm_aio_ctx {
	struct drbd_device *device;
	struct list_head list; /* on device->pending_bitmap_io */
	unsigned long start_jif;
	struct blk_plug bm_aio_plug;
	atomic_t in_flight;
	unsigned int done;
	unsigned flags;
#define BM_AIO_COPY_PAGES	1
#define BM_AIO_WRITE_HINTED	2
#define BM_AIO_WRITE_ALL_PAGES	4
#define BM_AIO_READ	        8
#define BM_AIO_WRITE_LAZY      16
	/* only report stats for global read, write, write all */
#define BM_AIO_NO_STATS (BM_AIO_COPY_PAGES\
			|BM_AIO_WRITE_HINTED\
			|BM_AIO_WRITE_LAZY)
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

	/* network namespace of the sending socket */
	struct net *net;
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

#define for_each_resource(resource, _resources) \
	list_for_each_entry(resource, _resources, resources)

#define for_each_resource_rcu(resource, _resources) \
	list_for_each_entry_rcu(resource, _resources, resources)

/* see drbd_resource.connections for locking requirements */
#define for_each_connection(connection, resource) \
	list_for_each_entry(connection, &resource->connections, connections)

#define for_each_connection_rcu(connection, resource) \
	list_for_each_entry_rcu(connection, &resource->connections, connections)

#define for_each_connection_ref(connection, m, resource)		\
	for (connection = __drbd_next_connection_ref(&m, NULL, resource); \
	     connection;						\
	     connection = __drbd_next_connection_ref(&m, connection, resource))

/* see drbd_device.peer_devices for locking requirements */
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

/*
 * function declarations
 *************************/

/* drbd_main.c */

enum dds_flags {
	/* This enum is part of the wire protocol!
	 * See P_SIZES, struct p_sizes; */
	DDSF_ASSUME_UNCONNECTED_PEER_HAS_SPACE    = 1,
	DDSF_NO_RESYNC = 2, /* Do not run a resync for the new space */
	DDSF_IGNORE_PEER_CONSTRAINTS = 4, /* no longer used */
	DDSF_2PC = 8, /* local only, not on the wire */
};
struct meta_data_on_disk_9;

int drbd_thread_start(struct drbd_thread *thi);
void _drbd_thread_stop(struct drbd_thread *thi, int restart, int wait);
#ifdef CONFIG_SMP
void drbd_thread_current_set_cpu(struct drbd_thread *thi);
#else
#define drbd_thread_current_set_cpu(A) ({})
#endif
int tl_release(struct drbd_connection *connection, uint64_t o_block_id,
	       uint64_t y_block_id, unsigned int barrier_nr,
	       unsigned int set_size);

int __drbd_send_protocol(struct drbd_connection *connection,
			 enum drbd_packet cmd);
u64 drbd_collect_local_uuid_flags(struct drbd_peer_device *peer_device,
				  u64 *authoritative_mask);
u64 drbd_resolved_uuid(struct drbd_peer_device *peer_device_base,
		       u64 *uuid_flags);
int drbd_send_uuids(struct drbd_peer_device *peer_device, u64 uuid_flags,
		    u64 node_mask);
void drbd_gen_and_send_sync_uuid(struct drbd_peer_device *peer_device);
int drbd_send_sizes(struct drbd_peer_device *peer_device,
		    uint64_t u_size_diskless, enum dds_flags flags);
int conn_send_state(struct drbd_connection *connection,
		    union drbd_state state);
int drbd_send_state(struct drbd_peer_device *peer_device,
		    union drbd_state state);
int drbd_send_current_state(struct drbd_peer_device *peer_device);
int drbd_send_sync_param(struct drbd_peer_device *peer_device);
int drbd_send_out_of_sync(struct drbd_peer_device *peer_device,
			  sector_t sector, unsigned int size);
int drbd_send_block(struct drbd_peer_device *peer_device,
		    enum drbd_packet cmd, struct drbd_peer_request *peer_req);
int drbd_send_dblock(struct drbd_peer_device *peer_device,
		     struct drbd_request *req);
int drbd_send_drequest(struct drbd_peer_device *peer_device, sector_t sector,
		       int size, u64 block_id);
int drbd_send_rs_request(struct drbd_peer_device *peer_device,
			 enum drbd_packet cmd, sector_t sector, int size,
			 u64 block_id, unsigned int dagtag_node_id,
			 u64 dagtag);
void *drbd_prepare_drequest_csum(struct drbd_peer_request *peer_req,
				 enum drbd_packet cmd, int digest_size,
				 unsigned int dagtag_node_id, u64 dagtag);

int drbd_send_bitmap(struct drbd_device *device,
		     struct drbd_peer_device *peer_device);
int drbd_send_dagtag(struct drbd_connection *connection, u64 dagtag);
void drbd_send_sr_reply(struct drbd_connection *connection, int vnr,
			enum drbd_state_rv retcode);
int drbd_send_rs_deallocated(struct drbd_peer_device *peer_device,
			     struct drbd_peer_request *peer_req);
void drbd_send_twopc_reply(struct drbd_connection *connection,
			   enum drbd_packet cmd, struct twopc_reply *reply);
void drbd_send_peers_in_sync(struct drbd_peer_device *peer_device, u64 mask,
			     sector_t sector, int size);
int drbd_send_peer_dagtag(struct drbd_connection *connection,
			  struct drbd_connection *lost_peer);
int drbd_send_flush_requests(struct drbd_connection *connection,
			     u64 flush_sequence);
int drbd_send_flush_forward(struct drbd_connection *connection,
			    u64 flush_sequence, int initiator_node_id);
int drbd_send_flush_requests_ack(struct drbd_connection *connection,
				 u64 flush_sequence, int primary_node_id);
int drbd_send_enable_replication_next(struct drbd_peer_device *peer_device);
int drbd_send_enable_replication(struct drbd_peer_device *peer_device, bool enable);
int drbd_send_current_uuid(struct drbd_peer_device *peer_device,
			   u64 current_uuid, u64 weak_nodes);
void drbd_backing_dev_free(struct drbd_device *device,
			   struct drbd_backing_dev *ldev);
void drbd_cleanup_device(struct drbd_device *device);
void drbd_print_uuids(struct drbd_peer_device *peer_device, const char *text);
void drbd_queue_unplug(struct drbd_device *device);

u64 drbd_capacity_to_on_disk_bm_sect(u64 capacity_sect,
				     unsigned int max_peers);
void drbd_md_set_sector_offsets(struct drbd_device *device,
				struct drbd_backing_dev *bdev);
int drbd_md_write(struct drbd_device *device,
		  struct meta_data_on_disk_9 *buffer);
int drbd_md_sync(struct drbd_device *device);
int drbd_md_sync_if_dirty(struct drbd_device *device);
void drbd_uuid_received_new_current(struct drbd_peer_device *from_pd, u64 val,
				    u64 weak_nodes) __must_hold(local);
void drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 uuid) __must_hold(local);
void _drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local);
void _drbd_uuid_set_current(struct drbd_device *device, u64 val) __must_hold(local);
void drbd_uuid_new_current(struct drbd_device *device, bool forced);
void drbd_uuid_new_current_by_user(struct drbd_device *device);
void _drbd_uuid_push_history(struct drbd_device *device, u64 val) __must_hold(local);
u64 _drbd_uuid_pull_history(struct drbd_peer_device *peer_device) __must_hold(local);
void drbd_uuid_resync_starting(struct drbd_peer_device *peer_device); __must_hold(local);
u64 drbd_uuid_resync_finished(struct drbd_peer_device *peer_device) __must_hold(local);
void drbd_uuid_detect_finished_resyncs(struct drbd_peer_device *peer_device) __must_hold(local);
bool drbd_uuid_set_exposed(struct drbd_device *device, u64 val, bool log);
u64 drbd_weak_nodes_device(struct drbd_device *device);
int drbd_md_test_flag(struct drbd_backing_dev *bdev, enum mdf_flag flag);
void drbd_md_set_peer_flag(struct drbd_peer_device *peer_device,
			   enum mdf_peer_flag flag);
void drbd_md_clear_peer_flag(struct drbd_peer_device *peer_device,
			     enum mdf_peer_flag flag);
bool drbd_md_test_peer_flag(struct drbd_peer_device *peer_device,
			    enum mdf_peer_flag flag);
void drbd_md_mark_dirty(struct drbd_device *device);
void drbd_queue_bitmap_io(struct drbd_device *device,
			  int (*io_fn)(struct drbd_device *device,
				       struct drbd_peer_device *peer_device),
			  void (*done)(struct drbd_device *device,
				       struct drbd_peer_device *peer_device,
				       int rv),
			  char *why, enum bm_flag flags,
			  struct drbd_peer_device *peer_device);
int drbd_bitmap_io(struct drbd_device *device,
		   int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		   char *why, enum bm_flag flags,
		   struct drbd_peer_device *peer_device);
int drbd_bitmap_io_from_worker(struct drbd_device *device,
			       int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
			       char *why, enum bm_flag flags,
			       struct drbd_peer_device *peer_device);
int drbd_bmio_set_n_write(struct drbd_device *device,
			  struct drbd_peer_device *peer_device) __must_hold(local);
int drbd_bmio_clear_all_n_write(struct drbd_device *device,
				struct drbd_peer_device *peer_device) __must_hold(local);
int drbd_bmio_set_all_n_write(struct drbd_device *device,
			      struct drbd_peer_device *peer_device) __must_hold(local);
int drbd_bmio_set_allocated_n_write(struct drbd_device *device,
				    struct drbd_peer_device *peer_device) __must_hold(local);
int drbd_bmio_clear_one_peer(struct drbd_device *device,
			     struct drbd_peer_device *peer_device) __must_hold(local);
bool drbd_device_stable(struct drbd_device *device, u64 *authoritative_ptr);
void drbd_flush_peer_acks(struct drbd_resource *resource);
void drbd_cork(struct drbd_connection *connection, enum drbd_stream stream);
void drbd_uncork(struct drbd_connection *connection, enum drbd_stream stream);
void drbd_open_counts(struct drbd_resource *resource, int *rw_count_ptr,
		      int *ro_count_ptr);

struct drbd_connection *
__drbd_next_connection_ref(u64 *visited, struct drbd_connection *connection,
			   struct drbd_resource *resource);

struct drbd_peer_device *
__drbd_next_peer_device_ref(u64 *visited,
			    struct drbd_peer_device *peer_device,
			    struct drbd_device *device);

void tl_abort_disk_io(struct drbd_device *device);

sector_t drbd_get_max_capacity(struct drbd_device *device,
			       struct drbd_backing_dev *bdev, bool warn);
sector_t drbd_partition_data_capacity(struct drbd_device *device);

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

#define LEGACY_BM_EXT_SHIFT	 27	/* 128 MiB per resync extent */
#define LEGACY_BM_EXT_SECT_MASK ((1UL << (LEGACY_BM_EXT_SHIFT - SECTOR_SHIFT)) - 1)

#if (BM_BLOCK_SHIFT != 12)
#error "HAVE YOU FIXED drbdmeta AS WELL??"
#endif

/* thus many _storage_ sectors are described by one bit */
#define BM_SECT_TO_BIT(x)   ((x)>>(BM_BLOCK_SHIFT-9))
#define BM_BIT_TO_SECT(x)   ((sector_t)(x)<<(BM_BLOCK_SHIFT-9))
#define BM_SECT_PER_BIT     BM_BIT_TO_SECT(1)

/* Send P_PEERS_IN_SYNC in steps defined by this shift. Set to the activity log
 * extent shift since the P_PEERS_IN_SYNC intervals are broken up based on
 * activity log extents anyway. */
#define PEERS_IN_SYNC_STEP_SHIFT AL_EXTENT_SHIFT
#define PEERS_IN_SYNC_STEP_SECT_MASK ((1UL << (PEERS_IN_SYNC_STEP_SHIFT - SECTOR_SHIFT)) - 1)

/* bit to represented kilo byte conversion */
#define Bit2KB(bits) ((bits)<<(BM_BLOCK_SHIFT-10))

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

#define DRBD_MAX_SIZE_H80_PACKET (1U << 15) /* Header 80 only allows packets up to 32KiB data */
#define DRBD_MAX_BIO_SIZE_P95    (1U << 17) /* Protocol 95 to 99 allows bios up to 128KiB */

/* For now, don't allow more than half of what we can "activate" in one
 * activity log transaction to be discarded in one go. We may need to rework
 * drbd_al_begin_io() to allow for even larger discard ranges */
#define DRBD_MAX_BATCH_BIO_SIZE	 (AL_UPDATES_PER_TRANSACTION/2*AL_EXTENT_SIZE)
#define DRBD_MAX_BBIO_SECTORS    (DRBD_MAX_BATCH_BIO_SIZE >> 9)

/* This gets ignored if the backing device has a larger discard granularity */
#define DRBD_MAX_RS_DISCARD_SIZE (1U << 27) /* 128MiB; arbitrary */

/* how many activity log extents are touched by this interval? */
static inline int interval_to_al_extents(struct drbd_interval *i)
{
	unsigned int first = i->sector >> (AL_EXTENT_SHIFT-9);
	unsigned int last = i->size == 0 ? first : (i->sector + (i->size >> 9) - 1) >> (AL_EXTENT_SHIFT-9);
	return 1 + last - first; /* worst case: all touched extends are cold. */
}

struct drbd_bitmap *drbd_bm_alloc(void);
int  drbd_bm_resize(struct drbd_device *device, sector_t capacity,
		    bool set_new_bits);
void drbd_bm_free(struct drbd_bitmap *bitmap);
void drbd_bm_set_all(struct drbd_device *device);
void drbd_bm_clear_all(struct drbd_device *device);
/* set/clear/test only a few bits at a time */
unsigned int drbd_bm_set_bits(struct drbd_device *device,
			      unsigned int bitmap_index, unsigned long start,
			      unsigned long end);
unsigned int drbd_bm_clear_bits(struct drbd_device *device,
				unsigned int bitmap_index,
				unsigned long start, unsigned long end);
int drbd_bm_count_bits(struct drbd_device *device, unsigned int bitmap_index,
		       unsigned long s, unsigned long e);
/* bm_set_bits variant for use while holding drbd_bm_lock,
 * may process the whole bitmap in one go */
void drbd_bm_set_many_bits(struct drbd_peer_device *peer_device,
			   unsigned long start, unsigned long end);
void drbd_bm_clear_many_bits(struct drbd_peer_device *peer_device,
			     unsigned long start, unsigned long end);
void _drbd_bm_clear_many_bits(struct drbd_device *device, int bitmap_index,
			      unsigned long start, unsigned long end);
void _drbd_bm_set_many_bits(struct drbd_device *device, int bitmap_index,
			    unsigned long start, unsigned long end);
int drbd_bm_test_bit(struct drbd_peer_device *peer_device,
		     const unsigned long bitnr);
int  drbd_bm_read(struct drbd_device *device,
		  struct drbd_peer_device *peer_device) __must_hold(local);
void drbd_bm_reset_al_hints(struct drbd_device *device) __must_hold(local);
void drbd_bm_mark_range_for_writeout(struct drbd_device *device,
				     unsigned long start, unsigned long end);
int  drbd_bm_write(struct drbd_device *device,
		   struct drbd_peer_device *peer_device) __must_hold(local);
int  drbd_bm_write_hinted(struct drbd_device *device) __must_hold(local);
int  drbd_bm_write_lazy(struct drbd_device *device, unsigned int upper_idx) __must_hold(local);
int drbd_bm_write_all(struct drbd_device *device,
		      struct drbd_peer_device *peer_device) __must_hold(local);
int drbd_bm_write_copy_pages(struct drbd_device *device,
			     struct drbd_peer_device *peer_device) __must_hold(local);
size_t	     drbd_bm_words(struct drbd_device *device);
unsigned long drbd_bm_bits(struct drbd_device *device);
sector_t      drbd_bm_capacity(struct drbd_device *device);

#define DRBD_END_OF_BITMAP	(~(unsigned long)0)
unsigned long drbd_bm_find_next(struct drbd_peer_device *peer_device,
				unsigned long start);
/* bm_find_next variants for use while you hold drbd_bm_lock() */
unsigned long _drbd_bm_find_next(struct drbd_peer_device *peer_device,
				 unsigned long start);
unsigned long _drbd_bm_find_next_zero(struct drbd_peer_device *peer_device,
				      unsigned long start);
unsigned long _drbd_bm_total_weight(struct drbd_device *device,
				    int bitmap_index);
unsigned long drbd_bm_total_weight(struct drbd_peer_device *peer_device);
/* for receive_bitmap */
void drbd_bm_merge_lel(struct drbd_peer_device *peer_device, size_t offset,
		       size_t number, unsigned long *buffer);
/* for _drbd_send_bitmap */
void drbd_bm_get_lel(struct drbd_peer_device *peer_device, size_t offset,
		     size_t number, unsigned long *buffer);

void drbd_bm_lock(struct drbd_device *device, const char *why,
		  enum bm_flag flags);
void drbd_bm_unlock(struct drbd_device *device);
void drbd_bm_slot_lock(struct drbd_peer_device *peer_device, char *why,
		       enum bm_flag flags);
void drbd_bm_slot_unlock(struct drbd_peer_device *peer_device);
void drbd_bm_copy_slot(struct drbd_device *device, unsigned int from_index,
		       unsigned int to_index);
/* drbd_main.c */

extern struct workqueue_struct *ping_ack_sender;
extern struct kmem_cache *drbd_request_cache;
extern struct kmem_cache *drbd_ee_cache;	/* peer requests */
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
extern mempool_t drbd_buffer_page_pool;

/* We also need to make sure we get a bio
 * when we need it for housekeeping purposes */
extern struct bio_set drbd_md_io_bio_set;

/* And a bio_set for cloning */
extern struct bio_set drbd_io_bio_set;

struct drbd_peer_device *create_peer_device(struct drbd_device *device,
					    struct drbd_connection *connection);
enum drbd_ret_code drbd_create_device(struct drbd_config_context *adm_ctx,
				      unsigned int minor,
				      struct device_conf *device_conf,
				      struct drbd_device **p_device);
void drbd_unregister_device(struct drbd_device *device);
void drbd_reclaim_device(struct rcu_head *rp);
void drbd_unregister_connection(struct drbd_connection *connection);
void drbd_reclaim_connection(struct rcu_head *rp);
void drbd_reclaim_path(struct rcu_head *rp);
void del_connect_timer(struct drbd_connection *connection);

struct drbd_resource *drbd_create_resource(const char *name,
					   struct res_opts *res_opts);
void drbd_reclaim_resource(struct rcu_head *rp);
void drbd_req_destroy_lock(struct kref *kref);
struct drbd_resource *drbd_find_resource(const char *name);
void drbd_destroy_resource(struct kref *kref);

void drbd_destroy_device(struct kref *kref);

int set_resource_options(struct drbd_resource *resource,
			 struct res_opts *res_opts, const char *tag);
struct drbd_connection *drbd_create_connection(struct drbd_resource *resource,
					       struct drbd_transport_class *tc);
void drbd_transport_shutdown(struct drbd_connection *connection,
			     enum drbd_tr_free_op op);
void drbd_destroy_connection(struct kref *kref);
void conn_free_crypto(struct drbd_connection *connection);

/* drbd_req */
void drbd_do_submit_conflict(struct work_struct *ws);
void do_submit(struct work_struct *ws);
#ifndef CONFIG_DRBD_TIMING_STATS
#define __drbd_make_request(d, b, k, j) __drbd_make_request(d, b, j)
#endif
void __drbd_make_request(struct drbd_device *device, struct bio *bio,
			 ktime_t start_kt, unsigned long start_jif);
void drbd_submit_bio(struct bio *bio);

enum drbd_force_detach_flags {
	DRBD_READ_ERROR,
	DRBD_WRITE_ERROR,
	DRBD_META_IO_ERROR,
	DRBD_FORCE_DETACH,
};
#define drbd_handle_io_error(m, f) drbd_handle_io_error_(m, f,  __func__)
void drbd_handle_io_error_(struct drbd_device *device,
			   enum drbd_force_detach_flags df, const char *where);

/* drbd_nl.c */
enum suspend_scope {
	READ_AND_WRITE,
	WRITE_ONLY
};
void drbd_suspend_io(struct drbd_device *device, enum suspend_scope ss);
void drbd_resume_io(struct drbd_device *device);
char *ppsize(char *buf, unsigned long long size);
sector_t drbd_new_dev_size(struct drbd_device *device, sector_t current_size,
			   sector_t user_capped_size, enum dds_flags flags) __must_hold(local);
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
enum determine_dev_size
drbd_determine_dev_size(struct drbd_device *device,
			sector_t peer_current_size, enum dds_flags flags,
			struct resize_parms *rs) __must_hold(local);
void resync_after_online_grow(struct drbd_peer_device *peer_device);
void drbd_reconsider_queue_parameters(struct drbd_device *device,
				      struct drbd_backing_dev *bdev);
bool barrier_pending(struct drbd_resource *resource);
enum drbd_state_rv
drbd_set_role(struct drbd_resource *resource, enum drbd_role role, bool force,
	      const char *tag, struct sk_buff *reply_skb);
void conn_try_outdate_peer_async(struct drbd_connection *connection);
int drbd_maybe_khelper(struct drbd_device *device,
		       struct drbd_connection *connection, char *cmd);
int drbd_create_peer_device_default_config(struct drbd_peer_device *peer_device);
int drbd_unallocated_index(struct drbd_backing_dev *bdev, int bm_max_peers);
void youngest_and_oldest_opener_to_str(struct drbd_device *device, char *buf,
				       size_t len);
int param_set_drbd_strict_names(const char *val,
				const struct kernel_param *kp);
void drbd_enable_netns(void);

/* drbd_sender.c */
int drbd_sender(struct drbd_thread *thi);
int drbd_worker(struct drbd_thread *thi);
enum drbd_ret_code drbd_resync_after_valid(struct drbd_device *device, int o_minor);
void drbd_resync_after_changed(struct drbd_device *device);
bool drbd_stable_sync_source_present(struct drbd_peer_device *except_peer_device,
				     enum which_state which);
void drbd_start_resync(struct drbd_peer_device *peer_device,
		       enum drbd_repl_state side, const char *tag);
void resume_next_sg(struct drbd_device *device);
void suspend_other_sg(struct drbd_device *device);
void drbd_resync_finished(struct drbd_peer_device *peer_device,
			  enum drbd_disk_state new_peer_disk_state);
void verify_progress(struct drbd_peer_device *peer_device,
		     const sector_t sector, const unsigned int size);
/* maybe rather drbd_main.c ? */
void *drbd_md_get_buffer(struct drbd_device *device, const char *intent);
void drbd_md_put_buffer(struct drbd_device *device);
int drbd_md_sync_page_io(struct drbd_device *device,
			 struct drbd_backing_dev *bdev, sector_t sector,
			 enum req_op op);
bool drbd_al_active(struct drbd_device *device, sector_t sector,
		    unsigned int size);
void drbd_ov_out_of_sync_found(struct drbd_peer_device *peer_device,
			       sector_t sector, int size);
void wait_until_done_or_force_detached(struct drbd_device *device,
				       struct drbd_backing_dev *bdev,
				       unsigned int *done);
void drbd_rs_controller_reset(struct drbd_peer_device *peer_device);
void drbd_rs_all_in_flight_came_back(struct drbd_peer_device *peer_device,
				     int rs_sect_in);
void drbd_check_peers(struct drbd_resource *resource);
void drbd_check_peers_new_current_uuid(struct drbd_device *device);
void drbd_conflict_send_resync_request(struct drbd_peer_request *peer_req);
void drbd_ping_peer(struct drbd_connection *connection);
struct drbd_peer_device *peer_device_by_node_id(struct drbd_device *device,
						int node_id);
void drbd_update_mdf_al_disabled(struct drbd_device *device,
				 enum which_state which);

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

void drbd_csum_bio(struct crypto_shash *tfm, struct bio *bio, void *digest);
void drbd_csum_pages(struct crypto_shash *tfm, struct page *page,
		     void *digest);
void drbd_resync_read_req_mod(struct drbd_peer_request *peer_req,
			      enum drbd_interval_flags bit_to_set);

/* worker callbacks */
int w_e_end_data_req(struct drbd_work *w, int cancel);
int w_e_end_rsdata_req(struct drbd_work *w, int cancel);
int w_e_end_ov_reply(struct drbd_work *w, int cancel);
int w_e_end_ov_req(struct drbd_work *w, int cancel);
int w_resync_timer(struct drbd_work *w, int cancel);
int w_e_reissue(struct drbd_work *w, int cancel);
int w_send_dagtag(struct drbd_work *w, int cancel);
int w_send_uuids(struct drbd_work *w, int cancel);

bool drbd_any_flush_pending(struct drbd_resource *resource);
void resync_timer_fn(struct timer_list *t);
void start_resync_timer_fn(struct timer_list *t);

int drbd_unmerge_discard(struct drbd_peer_request *peer_req_main,
			 struct list_head *list);
void drbd_endio_write_sec_final(struct drbd_peer_request *peer_req);

/* bi_end_io handlers */
void drbd_md_endio(struct bio *bio);
void drbd_peer_request_endio(struct bio *bio);
void drbd_request_endio(struct bio *bio);

void __update_timing_details(
		struct drbd_thread_timing_details *tdp,
		unsigned int *cb_nr,
		void *cb,
		const char *fn, const unsigned int line);

#define update_sender_timing_details(c, cb) \
	__update_timing_details(c->s_timing_details, &c->s_cb_nr, cb, __func__, __LINE__)
#define update_receiver_timing_details(c, cb) \
	__update_timing_details(c->r_timing_details, &c->r_cb_nr, cb, __func__, __LINE__)
#define update_worker_timing_details(r, cb) \
	__update_timing_details(r->w_timing_details, &r->w_cb_nr, cb, __func__, __LINE__)

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


void drbd_queue_update_peers(struct drbd_peer_device *peer_device,
			     sector_t sector_start, sector_t sector_end);
int drbd_issue_discard_or_zero_out(struct drbd_device *device, sector_t start,
				   unsigned int nr_sectors, int flags);
int drbd_send_ack_be(struct drbd_peer_device *peer_device,
		     enum drbd_packet cmd, sector_t sector, int size,
		     u64 block_id);
int drbd_send_ack(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		  struct drbd_peer_request *peer_req);
int drbd_send_ov_result(struct drbd_peer_device *peer_device, sector_t sector,
			int blksize, u64 block_id, enum ov_result result);
int drbd_receiver(struct drbd_thread *thi);
void drbd_unsuccessful_resync_request(struct drbd_peer_request *peer_req,
				      bool failed);
int drbd_send_out_of_sync_wf(struct drbd_work *w, int cancel);
int drbd_flush_ack_wf(struct drbd_work *w, int unused);
void drbd_send_ping_wf(struct work_struct *ws);
void drbd_send_acks_wf(struct work_struct *ws);
void drbd_send_peer_ack_wf(struct work_struct *ws);
bool drbd_rs_c_min_rate_throttle(struct drbd_peer_device *peer_device);
void drbd_verify_skipped_block(struct drbd_peer_device *peer_device,
			       const sector_t sector, const unsigned int size);
void drbd_conflict_submit_resync_request(struct drbd_peer_request *peer_req);
void drbd_conflict_submit_peer_read(struct drbd_peer_request *peer_req);
void drbd_conflict_submit_peer_write(struct drbd_peer_request *peer_req);
int drbd_submit_peer_request(struct drbd_peer_request *peer_req);
void drbd_cleanup_after_failed_submit_peer_write(struct drbd_peer_request *peer_req);
void drbd_cleanup_peer_requests_wfa(struct drbd_device *device,
				    struct list_head *cleanup);
void drbd_remove_peer_req_interval(struct drbd_peer_request *peer_req);
int drbd_free_peer_reqs(struct drbd_connection *connection,
			struct list_head *list);
struct drbd_peer_request *drbd_alloc_peer_req(struct drbd_peer_device *peer_device,
					      gfp_t gfp_mask) __must_hold(local);
void drbd_free_peer_req(struct drbd_peer_request *peer_req);
int drbd_connected(struct drbd_peer_device *peer_device);
void conn_connect2(struct drbd_connection *connection);
void wait_initial_states_received(struct drbd_connection *connection);
void abort_connect(struct drbd_connection *connection);
void drbd_print_cluster_wide_state_change(struct drbd_resource *resource,
					  const char *message,
					  unsigned int tid,
					  unsigned int initiator_node_id,
					  int target_node_id,
					  union drbd_state mask,
					  union drbd_state val);
void apply_unacked_peer_requests(struct drbd_connection *connection);
struct drbd_connection *drbd_connection_by_node_id(struct drbd_resource *resource,
						   int node_id);
struct drbd_connection *drbd_get_connection_by_node_id(struct drbd_resource *resource,
						       int node_id);
bool drbd_have_local_disk(struct drbd_resource *resource);
enum drbd_state_rv drbd_support_2pc_resize(struct drbd_resource *resource);
enum determine_dev_size
drbd_commit_size_change(struct drbd_device *device, struct resize_parms *rs,
			u64 nodes_to_reach);
void drbd_try_to_get_resynced(struct drbd_device *device);
void drbd_process_rs_discards(struct drbd_peer_device *peer_device,
			      bool submit_all);
void drbd_last_resync_request(struct drbd_peer_device *peer_device,
			      bool submit_all);
void drbd_init_connect_state(struct drbd_connection *connection);

static inline sector_t drbd_get_capacity(struct block_device *bdev)
{
	return bdev ? bdev_nr_sectors(bdev) : 0;
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

void twopc_timer_fn(struct timer_list *t);
void connect_timer_fn(struct timer_list *t);

/* drbd_proc.c */
extern struct proc_dir_entry *drbd_proc;
int drbd_seq_show(struct seq_file *seq, void *v);

/* drbd_actlog.c */
bool drbd_al_try_lock(struct drbd_device *device);
bool drbd_al_try_lock_for_transaction(struct drbd_device *device);
int drbd_al_begin_io_nonblock(struct drbd_device *device,
			      struct drbd_interval *i);
void drbd_al_begin_io_commit(struct drbd_device *device);
bool drbd_al_begin_io_fastpath(struct drbd_device *device,
			       struct drbd_interval *i);
bool drbd_al_complete_io(struct drbd_device *device, struct drbd_interval *i);
void drbd_advance_rs_marks(struct drbd_peer_device *peer_device,
			   unsigned long still_to_go);
bool drbd_lazy_bitmap_update_due(struct drbd_peer_device *peer_device);
int drbd_set_all_out_of_sync(struct drbd_device *device, sector_t sector,
			     int size);
int drbd_set_sync(struct drbd_device *device, sector_t sector, int size,
		  unsigned long bits, unsigned long mask);
enum update_sync_bits_mode { RECORD_RS_FAILED, SET_OUT_OF_SYNC, SET_IN_SYNC };
int __drbd_change_sync(struct drbd_peer_device *peer_device, sector_t sector,
		       int size, enum update_sync_bits_mode mode);
#define drbd_set_in_sync(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, SET_IN_SYNC)
#define drbd_set_out_of_sync(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, SET_OUT_OF_SYNC)
#define drbd_rs_failed_io(peer_device, sector, size) \
	__drbd_change_sync(peer_device, sector, size, RECORD_RS_FAILED)
void drbd_al_shrink(struct drbd_device *device);
int drbd_al_initialize(struct drbd_device *device, void *buffer);

/* drbd_nl.c */

extern struct mutex notification_mutex;
extern atomic_t drbd_genl_seq;

int notify_resource_state(struct sk_buff *skb, unsigned int seq,
			  struct drbd_resource *resource,
			  struct resource_info *resource_info,
			  struct rename_resource_info *rename_resource_info,
			  enum drbd_notification_type type);
int notify_device_state(struct sk_buff *skb, unsigned int seq,
			struct drbd_device *device,
			struct device_info *device_info,
			enum drbd_notification_type type);
int notify_connection_state(struct sk_buff *skb, unsigned int seq,
			    struct drbd_connection *connection,
			    struct connection_info *connection_info,
			    enum drbd_notification_type type);
int notify_peer_device_state(struct sk_buff *skb, unsigned int seq,
			     struct drbd_peer_device *peer_device,
			     struct peer_device_info *peer_device_info,
			     enum drbd_notification_type type);
void notify_helper(enum drbd_notification_type type,
		   struct drbd_device *device,
		   struct drbd_connection *connection, const char *name,
		   int status);
int notify_path(struct drbd_connection *connection, struct drbd_path *path,
		enum drbd_notification_type type);
void drbd_broadcast_peer_device_state(struct drbd_peer_device *peer_device);

sector_t drbd_local_max_size(struct drbd_device *device) __must_hold(local);
int drbd_open_ro_count(struct drbd_resource *resource);

void device_to_info(struct device_info *info, struct drbd_device *device);
void device_state_change_to_info(struct device_info *info,
				 struct drbd_device_state_change *state_change);
void peer_device_state_change_to_info(struct peer_device_info *info,
				      struct drbd_peer_device_state_change *state_change);
/*
 * inline helper functions
 *************************/

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
		return bdev->md.md_offset + (4096 >> 9) - 1;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect - 1;
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

void drbd_flush_workqueue(struct drbd_work_queue *work_queue);
void drbd_flush_workqueue_interruptible(struct drbd_device *device);

void *__conn_prepare_command(struct drbd_connection *connection, int size,
			     enum drbd_stream drbd_stream);
void *conn_prepare_command(struct drbd_connection *connection, int size,
			   enum drbd_stream drbd_stream);
void *drbd_prepare_command(struct drbd_peer_device *peer_device, int size,
			   enum drbd_stream drbd_stream);
int __send_command(struct drbd_connection *connection, int vnr,
		   enum drbd_packet cmd, int stream_and_flags);
int send_command(struct drbd_connection *connection, int vnr,
		 enum drbd_packet cmd, int stream_and_flags);
int drbd_send_command(struct drbd_peer_device *peer_device,
		      enum drbd_packet cmd, enum drbd_stream drbd_stream);

int drbd_send_ping(struct drbd_connection *connection);
int conn_send_state_req(struct drbd_connection *connection, int vnr,
			enum drbd_packet cmd, union drbd_state mask,
			union drbd_state val);
int conn_send_twopc_request(struct drbd_connection *connection,
			    struct twopc_request *request);
int drbd_send_peer_ack(struct drbd_connection *connection, u64 mask,
		       u64 dagtag_sector);

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
 *  receive_data_request etc we need to send back P_DATA
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

static inline bool repl_is_sync_target(enum drbd_repl_state repl_state)
{
	return repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T;
}

static inline bool repl_is_sync_source(enum drbd_repl_state repl_state)
{
	return repl_state == L_SYNC_SOURCE || repl_state == L_PAUSED_SYNC_S;
}

static inline bool repl_is_sync(enum drbd_repl_state repl_state)
{
	return repl_is_sync_source(repl_state) ||
		repl_is_sync_target(repl_state);
}

static inline bool is_sync_target_state(struct drbd_peer_device *peer_device,
					enum which_state which)
{
	return repl_is_sync_target(peer_device->repl_state[which]);
}

static inline bool is_sync_source_state(struct drbd_peer_device *peer_device,
					enum which_state which)
{
	return repl_is_sync_source(peer_device->repl_state[which]);
}

static inline bool is_sync_state(struct drbd_peer_device *peer_device,
				 enum which_state which)
{
	return repl_is_sync(peer_device->repl_state[which]);
}

static inline bool is_verify_state(struct drbd_peer_device *peer_device,
				   enum which_state which)
{
	enum drbd_repl_state repl_state = peer_device->repl_state[which];
	return repl_state == L_VERIFY_S || repl_state == L_VERIFY_T;
}

static inline bool resync_susp_comb_dep(struct drbd_peer_device *peer_device, enum which_state which)
{
	struct drbd_device *device = peer_device->device;

	return peer_device->resync_susp_dependency[which] || peer_device->resync_susp_other_c[which] ||
		(is_sync_source_state(peer_device, which) && device->disk_state[which] <= D_INCONSISTENT);
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
		if (disk_state == D_DISKLESS) {
			/* even internal references gone, safe to destroy */
			kref_get(&device->kref);
			schedule_work(&device->ldev_destroy_work);
		}
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
int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins);
#endif

void drbd_queue_pending_bitmap_work(struct drbd_device *device);

/* rw = READ or WRITE (0 or 1); nothing else. */
static inline void dec_ap_bio(struct drbd_device *device, int rw)
{
	unsigned int nr_requests = device->resource->res_opts.nr_requests;
	int ap_bio = atomic_dec_return(&device->ap_bio_cnt[rw]);

	D_ASSERT(device, ap_bio >= 0);

	/* Check for list_empty outside the lock is ok.  Worst case it queues
	 * nothing because someone else just now did.  During list_add, a
	 * refcount on ap_bio_cnt[WRITE] is held, so the bitmap work will be
	 * queued when that is released if we miss it here.
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
	if (device->cached_err_io)
		return true;
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

static inline struct drbd_connection *first_connection(struct drbd_resource *resource)
{
	return list_first_entry_or_null(&resource->connections,
				struct drbd_connection, connections);
}

static inline struct net *drbd_net_assigned_to_connection(struct drbd_connection *connection)
{
	struct drbd_path *path;
	struct net *net;

	rcu_read_lock();
	path = list_first_or_null_rcu(&connection->transport.paths, struct drbd_path, list);
	net = path ? path->net : NULL;
	rcu_read_unlock();

	return net;
}

#define NODE_MASK(id) ((u64)1 << (id))

static inline void drbd_list_del_resync_request(struct drbd_peer_request *peer_req)
{
	peer_req->flags &= ~EE_ON_RECV_ORDER;
	list_del(&peer_req->recv_order);

	if (peer_req == peer_req->peer_device->received_last)
		peer_req->peer_device->received_last = NULL;

	if (peer_req == peer_req->peer_device->discard_last)
		peer_req->peer_device->discard_last = NULL;
}

/*
 * drbd_interval_same_peer - determine whether "interval" is for the same peer as "i"
 *
 * "i" must be an interval corresponding to a drbd_peer_request.
 */
static inline bool drbd_interval_same_peer(struct drbd_interval *interval, struct drbd_interval *i)
{
	struct drbd_peer_request *interval_peer_req, *i_peer_req;

	/* Ensure we only call "container_of" if it is actually a peer request. */
	if (interval->type == INTERVAL_LOCAL_WRITE ||
			interval->type == INTERVAL_LOCAL_READ ||
			interval->type == INTERVAL_PEERS_IN_SYNC_LOCK)
		return false;

	interval_peer_req = container_of(interval, struct drbd_peer_request, i);
	i_peer_req = container_of(i, struct drbd_peer_request, i);
	return interval_peer_req->peer_device == i_peer_req->peer_device;
}

/*
 * drbd_should_defer_to_resync - determine whether "interval" should defer to
 * "i" in order to ensure that resync makes progress
 */
static inline bool drbd_should_defer_to_resync(struct drbd_interval *interval, struct drbd_interval *i)
{
	if (!drbd_interval_is_resync(i))
		return false;

	/* Always defer to resync requests once the reply has been received.
	 * These just need to wait for conflicting local I/O to complete. This
	 * is necessary to ensure that resync replies received before
	 * application writes are submitted first, so that the resync writes do
	 * not overwrite newer data. */
	if (test_bit(INTERVAL_RECEIVED, &i->flags))
		return true;

	/* If we are still waiting for a reply from the peer, only defer to the
	 * request if it is towards a different peer. The exclusivity between
	 * resync requests and application writes from another peer is
	 * necessary to avoid overwriting newer data with older in the resync.
	 * When the data in both cases is coming from the same peer, this is
	 * not necessary. The peer ensures that the data stream is correctly
	 * ordered. */
	return !drbd_interval_same_peer(interval, i);
}

/*
 * drbd_should_defer_to_interval - determine whether "interval" should defer to "i"
 */
static inline bool drbd_should_defer_to_interval(struct drbd_interval *interval,
		struct drbd_interval *i, bool defer_to_resync)
{
	if (test_bit(INTERVAL_SUBMITTED, &i->flags))
		return true;

	if (defer_to_resync && drbd_should_defer_to_resync(interval, i))
		return true;

	/*
	 * We do not send conflicting resync requests because that causes
	 * difficulties associating the replies to the requests.
	 */
	if (interval->type == INTERVAL_RESYNC_WRITE &&
			i->type == INTERVAL_RESYNC_WRITE && test_bit(INTERVAL_SENT, &i->flags))
		return true;

	return false;
}

/* Find conflicts at application level instead of at disk level. */
#define CONFLICT_FLAG_APPLICATION_ONLY (1 << 0)

/*
 * Ignore peer writes from the peer that this request relates to. This is only
 * used for determining whether to send a request. It must not be used for
 * determining whether to submit a request, because that would allow concurrent
 * writes to the backing disk.
 */
#define CONFLICT_FLAG_IGNORE_SAME_PEER (1 << 1)

/*
 * drbd_find_conflict - find conflicting interval, if any
 */
static inline struct drbd_interval *drbd_find_conflict(struct drbd_device *device,
		struct drbd_interval *interval, unsigned long flags)
{
	struct drbd_interval *i;
	sector_t sector = interval->sector;
	int size = interval->size;
	bool application_only = flags & CONFLICT_FLAG_APPLICATION_ONLY;
	bool defer_to_resync =
		(interval->type == INTERVAL_LOCAL_WRITE || interval->type == INTERVAL_PEER_WRITE) &&
		!application_only;
	bool exclusive_until_completed = interval->type == INTERVAL_LOCAL_WRITE || application_only;
	bool ignore_same_peer = flags & CONFLICT_FLAG_IGNORE_SAME_PEER;

	lockdep_assert_held(&device->interval_lock);

	drbd_for_each_overlap(i, &device->requests, sector, size) {
		/* Ignore the interval itself. */
		if (i == interval)
			continue;

		if (exclusive_until_completed) {
			/* Ignore, if already completed to upper layers. */
			if (test_bit(INTERVAL_COMPLETED, &i->flags))
				continue;
		} else {
			/* Ignore, if already completed by the backing disk. */
			if (test_bit(INTERVAL_BACKING_COMPLETED, &i->flags))
				continue;
		}

		/* Ignore, if there is no need to defer to it. */
		if (!drbd_should_defer_to_interval(interval, i, defer_to_resync))
			continue;

		/*
		 * Ignore peer writes from the peer that this request relates
		 * to, if requested.
		 */
		if (ignore_same_peer && i->type == INTERVAL_PEER_WRITE && drbd_interval_same_peer(interval, i))
			continue;

		if (unlikely(application_only)) {
			/* Ignore, if not an application request. */
			if (!drbd_interval_is_application(i))
				continue;
		}

		if (drbd_interval_is_write(interval)) {
			/*
			 * Mark verify requests as conflicting rather than
			 * treating them as conflicts for us.
			 */
			if (drbd_interval_is_verify(i)) {
				set_bit(INTERVAL_CONFLICT, &i->flags);
				continue;
			}
		} else {
			/* Ignore other resync reads. */
			if (i->type == INTERVAL_RESYNC_READ)
				continue;

			/* Ignore verify requests, since they are always reads. */
			if (drbd_interval_is_verify(i))
				continue;

			/* Ignore peers-in-sync intervals, since they are always reads. */
			if (i->type == INTERVAL_PEERS_IN_SYNC_LOCK)
				continue;
		}

		dynamic_drbd_dbg(device,
				"%s at %llus+%u conflicts with %s at %llus+%u\n",
				drbd_interval_type_str(interval),
				(unsigned long long) sector, size,
				drbd_interval_type_str(i),
				(unsigned long long) i->sector, i->size);

		break;
	}

	return i;
}

#ifdef CONFIG_DRBD_TIMING_STATS
#define ktime_aggregate_delta(D, ST, M) (D->M = ktime_add(D->M, ktime_sub(ktime_get(), ST)))
#define ktime_aggregate(D, R, M) (D->M = ktime_add(D->M, ktime_sub(R->M, R->start_kt)))
#define ktime_aggregate_pd(P, N, R, M) (P->M = ktime_add(P->M, ktime_sub(R->M[N], R->start_kt)))
#define ktime_get_accounting(V) (V = ktime_get())
#define ktime_get_accounting_assign(V, T) (V = T)
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
