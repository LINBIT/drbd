/*
  drbd_int.h
  Kernel module for 2.4.x/2.6.x Kernels

  This file is part of drbd by Philipp Reisner.

  Copyright (C) 1999-2004, Philipp Reisner <philipp.reisner@linbit.com>.
	main author.

  Copyright (C) 2002-2004, Lars Ellenberg <l.g.e@web.de>.
	main contributor.

  drbd is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2, or (at your option)
  any later version.

  drbd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with drbd; see the file COPYING.  If not, write to
  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <linux/compiler.h>
#include <linux/types.h>
#include <linux/version.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/slab.h> 
#include "lru_cache.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include "mempool.h"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,20)
static inline void __list_splice(struct list_head *list,
				 struct list_head *head)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;
	struct list_head *at = head->next;

	first->prev = head;
	head->next = first;

	last->next = at;
	at->prev = last;
}
static inline void list_splice_init(struct list_head *list,
				    struct list_head *head)
{
	if (!list_empty(list)) {
		__list_splice(list, head);
		INIT_LIST_HEAD(list);
	}
}
#endif

// module parameter, defined in drbd_main.c
extern int minor_count;
extern int disable_io_hints;
extern int major_nr;

// major == nbd_major ? "nbd" : "drbd";
extern char* drbd_devfs_name;

/* Using the major_nr of the network block device
   used to prevent us from deadlocking with no request entries
   left on all_requests... those where the days...
   look out for NBD_MAJOR in ll_rw_blk.c */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
/*lge: this hack is to get rid of the compiler warnings about
 * 'do_nbd_request declared static but never defined'
 * whilst forcing blk.h defines on
 * though we probably do not need them, we do not use them...
 * would not work without LOCAL_END_REQUEST
 */
# define MAJOR_NR DRBD_MAJOR
# define DEVICE_ON(device)
# define DEVICE_OFF(device)
# define DEVICE_NR(device) (MINOR(device))
# define LOCAL_END_REQUEST
# include <linux/blk.h>
# define DRBD_MAJOR major_nr
#else
# include <linux/blkdev.h>
# include <linux/bio.h>
# define MAJOR_NR major_nr
#endif

#undef DEVICE_NAME
#define DEVICE_NAME "drbd"

// XXX do we need this?
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define INITIAL_BLOCK_SIZE (1<<12)  // 4K

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

#define ID_SYNCER (-1LL)
#define ID_VACANT 0     // All EEs on the free list should have this value
                        // freshly allocated EEs get !ID_VACANT (== 1)
			// so if it says "cannot dereference null
			// pointer at adress 0x00000001, it is most
			// probably one of these :(

struct Drbd_Conf;
typedef struct Drbd_Conf drbd_dev;

#ifdef DBG_ALL_SYMBOLS
# define STATIC
#else
# define STATIC static
#endif

#ifdef PARANOIA
# define PARANOIA_BUG_ON(x) BUG_ON(x)
#else
# define PARANOIA_BUG_ON(x)
#endif

/*
 * Some Message Macros
 *************************/

// handy macro: DUMPP(somepointer)
#define DUMPP(A)   ERR( #A " = %p in %s:%d\n",  (A),__FILE__,__LINE__);
#define DUMPLU(A)  ERR( #A " = %lu in %s:%d\n", (A),__FILE__,__LINE__);
#define DUMPLLU(A) ERR( #A " = %llu in %s:%d\n",(A),__FILE__,__LINE__);
#define DUMPLX(A)  ERR( #A " = %lx in %s:%d\n", (A),__FILE__,__LINE__);
#define DUMPI(A)   ERR( #A " = %d in %s:%d\n",  (A),__FILE__,__LINE__);

#define DUMPST(A) DUMPLLU((unsigned long long)(A))


// Info: do not remove the spaces around the "," before ##
//       Otherwise this is not portable from gcc-2.95 to gcc-3.3
#define PRINTK(level,fmt,args...) \
	printk(level DEVICE_NAME "%d: " fmt, \
		(int)(mdev-drbd_conf) , ##args)

#define ALERT(fmt,args...) PRINTK(KERN_ALERT, fmt , ##args)
#define ERR(fmt,args...)  PRINTK(KERN_ERR, fmt , ##args)
#define WARN(fmt,args...) PRINTK(KERN_WARNING, fmt , ##args)
#define INFO(fmt,args...) PRINTK(KERN_INFO, fmt , ##args)
#define DBG(fmt,args...)  PRINTK(KERN_DEBUG, fmt , ##args)

/* see kernel/printk.c:printk_ratelimit
 * macro, so it is easy do have independend rate limits at different locations
 * "initializer element not constant ..." with kernel 2.4 :(
 * so I initialize toks to something large
 */
#define DRBD_ratelimit(ratelimit_jiffies,ratelimit_burst)	\
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
			WARN("%d messages suppressed in %s:%d.\n",\
				lost , __FILE__ , __LINE__ );	\
		__ret=1;					\
	} else {						\
		missed++;					\
		__ret=0;					\
	}							\
	__ret;							\
})


#ifdef DBG_ASSERTS
extern void drbd_assert_breakpoint(drbd_dev*, char *, char *, int );
# define D_ASSERT(exp)  if (!(exp)) \
	 drbd_assert_breakpoint(mdev,#exp,__FILE__,__LINE__)
#else
# define D_ASSERT(exp)  if (!(exp)) \
	 ERR("ASSERT( " #exp " ) in %s:%d\n", __FILE__,__LINE__)
#endif
#define ERR_IF(exp) if (({ \
	int _b = (exp)!=0; \
	if (_b) ERR("%s: (" #exp ") in %s:%d\n", __func__, __FILE__,__LINE__); \
	 _b; \
	}))

// to debug dec_*(), while we still have the <0!! issue
// to debug dec_*(), while we still have the <0!! issue
#include <linux/stringify.h>
#define HERE __stringify(__FILE__ __LINE__) // __FUNCTION__

// integer division, round _UP_ to the next integer
#define div_ceil(A,B) ( (A)/(B) + ((A)%(B) ? 1 : 0) )
// usual integer division
#define div_floor(A,B) ( (A)/(B) )

/*
 * Compatibility Section
 *************************/

#include "drbd_compat_types.h"

#ifdef SIGHAND_HACK
# define LOCK_SIGMASK(task,flags)   spin_lock_irqsave(&task->sighand->siglock, flags)
# define UNLOCK_SIGMASK(task,flags) spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define RECALC_SIGPENDING()        recalc_sigpending();
#else
# define LOCK_SIGMASK(task,flags)   spin_lock_irqsave(&task->sigmask_lock, flags)
# define UNLOCK_SIGMASK(task,flags) spin_unlock_irqrestore(&task->sigmask_lock, flags)
# define RECALC_SIGPENDING()        recalc_sigpending(current);
#endif

#if defined(DBG_SPINLOCKS) && defined(__SMP__)
# define MUST_HOLD(lock) if(!spin_is_locked(lock)) { ERR("Not holding lock! in %s\n", __FUNCTION__ ); }
#else
# define MUST_HOLD(lock)
#endif

/*
 * our structs
 *************************/

#ifndef typecheck
/*
 * Check at compile time that something is of a particular type.
 * Always evaluates to 1 so you may use it easily in comparisons.
 */
#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})
#endif

#define SET_MAGIC(x)       ((x)->magic = (long)(x) ^ DRBD_MAGIC)
#define VALID_POINTER(x)   ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)):0)
#define INVALIDATE_MAGIC(x) (x->magic--)

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct Drbd_Conf*,x); \
	  (x)->magic = (long)(x) ^ DRBD_MAGIC; })
#define IS_VALID_MDEV(x)  \
	( typecheck(struct Drbd_Conf*,x) && \
	  ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)):0))


/*
 * GFP_DRBD is used for allocations inside drbd_make_request,
 * and for the sk->allocation scheme.
 *
 * Try to get away with GFP_NOIO, which is
 * in 2.4.x:	(__GFP_HIGH | __GFP_WAIT) // HIGH == EMERGENCY, not HIGHMEM!
 * in 2.6.x:	             (__GFP_WAIT)
 *
 * As far as i can see we do not allocate from interrupt context...
 * if we do, we certainly should fix that.
 * - lge
 */
#define GFP_DRBD GFP_NOIO

/* these defines should go into blkdev.h
   (if it will be ever includet into linus' linux) */
#define RQ_DRBD_NOTHING	  0x0001
#define RQ_DRBD_SENT      0x0010
#define RQ_DRBD_LOCAL     0x0020
#define RQ_DRBD_DONE      0x0030
#define RQ_DRBD_IN_TL     0x0040

enum MetaDataFlags {
	__MDF_Consistent,
	__MDF_PrimaryInd,
	__MDF_ConnectedInd,
	__MDF_FullSync,
};
#define MDF_Consistent      (1<<__MDF_Consistent)
#define MDF_PrimaryInd      (1<<__MDF_PrimaryInd)
#define MDF_ConnectedInd    (1<<__MDF_ConnectedInd)
#define MDF_FullSync        (1<<__MDF_FullSync)

/* drbd_meta-data.c (still in drbd_main.c) */
enum MetaDataIndex {
	Flags,          /* Consistency flag,connected-ind,primary-ind */
	HumanCnt,       /* human-intervention-count */
	TimeoutCnt,     /* timout-count */
	ConnectedCnt,   /* connected-count */
	ArbitraryCnt,   /* arbitrary-count */
	GEN_CNT_SIZE	// MUST BE LAST! (and Flags must stay first...)
};

#define DRBD_MD_MAGIC (DRBD_MAGIC+3) // 3nd incarnation of the file format.

#define DRBD_PANIC 2
/* do_panic alternatives:
 *	0: panic();
 *	1: machine_halt; SORRY, this DOES NOT WORK
 *	2: prink(EMERG ), plus flag to fail all eventual drbd IO, plus panic()
 */

extern volatile int drbd_did_panic;

#if    DRBD_PANIC == 0
#define drbd_panic(fmt, args...) \
	panic(DEVICE_NAME "%d: " fmt, (int)(mdev-drbd_conf) , ##args)
#elif  DRBD_PANIC == 1
#error "sorry , this does not work, please contribute"
#else
#define drbd_panic(fmt, args...) do {					\
	printk(KERN_EMERG DEVICE_NAME "%d: " fmt,			\
			(int)(mdev-drbd_conf) , ##args);		\
	drbd_did_panic = DRBD_MAGIC;					\
	smp_mb();							\
	panic(DEVICE_NAME "%d: " fmt, (int)(mdev-drbd_conf) , ##args);	\
} while (0)
#endif
#undef DRBD_PANIC

/***
 * on the wire
 *********************************************************************/

typedef enum {
	Data,
	DataReply,     // Response to DataRequest
	RSDataReply,   // Response to RSDataRequest
	Barrier,
	ReportParams,
	ReportBitMap,
	BecomeSyncTarget,
	BecomeSyncSource,
	UnplugRemote,  // Used at various times to hint the peer to hurry up
	DataRequest,   // Used to ask for a data block
	RSDataRequest, // Used to ask for a data block
	SyncParam,

	Ping,         // These are sent on the meta socket...
	PingAck,
	RecvAck,      // Used in protocol B
	WriteAck,     // Used in protocol C
	NegAck,       // Sent if local disk is unusable
	NegDReply,    // Local disk is broken...
	NegRSDReply,  // Local disk is broken...
	BarrierAck,

	MAX_CMD,
	MayIgnore = 0x100, // Flag only to test if (cmd > MayIgnore) ...
	MAX_OPT_CMD,

	HandShake = 0xfffe // FIXED for the next century!
} Drbd_Packet_Cmd;

static inline const char* cmdname(Drbd_Packet_Cmd cmd)
{
	/* THINK may need to become several global tables
	 * when we want to support more than
	 * one PRO_VERSION */
	static const char *cmdnames[] = {
		[Data]             = "Data",
		[DataReply]        = "DataReply",
		[RSDataReply]      = "RSDataReply",
		[Barrier]          = "Barrier",
		[ReportParams]     = "ReportParams",
		[ReportBitMap]     = "ReportBitMap",
		[BecomeSyncTarget] = "BecomeSyncTarget",
		[BecomeSyncSource] = "BecomeSyncSource",
		[UnplugRemote]     = "UnplugRemote",
		[DataRequest]      = "DataRequest",
		[RSDataRequest]    = "RSDataRequest",
		[SyncParam]        = "SyncParam",
		[Ping]             = "Ping",
		[PingAck]          = "PingAck",
		[RecvAck]          = "RecvAck",
		[WriteAck]         = "WriteAck",
		[NegAck]           = "NegAck",
		[NegDReply]        = "NegDReply",
		[NegRSDReply]      = "NegRSDReply",
		[BarrierAck]       = "BarrierAck"
	};

	if (cmd == HandShake) return "HandShake";
	if (Data > cmd || cmd >= MAX_CMD) return "Unknown";
	return cmdnames[cmd];
}


/* This is the layout for a packet on the wire.
 * The byteorder is the network byte order.
 *     (except block_id and barrier fields.
 *      these are pointers to local structs
 *      and have no relevance for the partner,
 *      which just echoes them as received.)
 *
 * NOTE that the payload starts at a long aligned offset,
 * regardless of 32 or 64 bit arch!
 */
typedef struct {
	u32       magic;
	u16       command;
	u16       length;	// bytes of data after this header
	char      payload[0];
} __attribute((packed)) Drbd_Header;
// 8 bytes. packet FIXED for the next century!

/*
 * short commands, packets without payload, plain Drbd_Header:
 *   Ping
 *   PingAck
 *   BecomeSyncTarget
 *   BecomeSyncSource
 *   UnplugRemote
 */

/*
 * commands with out-of-struct payload:
 *   ReportBitMap    (no additional fields)
 *   Data, DataReply (see Drbd_Data_Packet)
 */
typedef struct {
	Drbd_Header head;
	u64         sector;    // 64 bits sector number
	u64         block_id;  // Used in protocol B&C for the address of the req.
} __attribute((packed)) Drbd_Data_Packet;

/*
 * commands which share a struct:
 *   RecvAck (proto B), WriteAck (proto C) (see Drbd_BlockAck_Packet)
 *   DataRequest, RSDataRequest  (see Drbd_BlockRequest_Packet)
 */
typedef struct {
	Drbd_Header head;
	u64         sector;
	u64         block_id;
	u32         blksize;
	u32         pad;	//make sure packet is a multiple of 8 Byte
} __attribute((packed)) Drbd_BlockAck_Packet;

typedef struct {
	Drbd_Header head;
	u64         sector;
	u64         block_id;
	u32         blksize;
	u32         pad;	//make sure packet is a multiple of 8 Byte
} __attribute((packed)) Drbd_BlockRequest_Packet;

/*
 * commands with their own struct for additional fields:
 *   HandShake
 *   Barrier
 *   BarrierAck
 *   SyncParam
 *   ReportParams
 */

typedef struct {
	Drbd_Header head;		// 8 bytes
	u32         protocol_version;
	u32         feature_flags;

	/* should be more than enough for future enhancements
	 * for now, feature_flags and the reserverd array shall be zero.
	 */

	u64         reserverd[8];
} __attribute((packed)) Drbd_HandShake_Packet;
// 80 bytes, FIXED for the next century

typedef struct {
	Drbd_Header head;
	u32         barrier;   // may be 0 or a barrier number
	u32         pad;	//make sure packet is a multiple of 8 Byte
} __attribute((packed)) Drbd_Barrier_Packet;

typedef struct {
	Drbd_Header head;
	u32         barrier;
	u32         set_size;
} __attribute((packed)) Drbd_BarrierAck_Packet;

typedef struct {
	Drbd_Header head;
	u32         rate;
	u32         use_csums;
	u32         skip;
	u32         group;
} __attribute((packed)) Drbd_SyncParam_Packet;

/* FIXME add more members here, until we introduce a new fixed size
 * protocol version handshake packet! */
typedef struct {
	Drbd_Header head;
	u64         p_size;  // size of disk
	u64         u_size;  // user requested size
	u32         state;
	u32         protocol;
	u32         version;
	u32         gen_cnt[GEN_CNT_SIZE];
	u32         sync_rate;
	u32         sync_use_csums;
	u32         skip_sync;
	u32         sync_group;
	u32         flags;   // flags & 1 -> reply call drbd_send_param(mdev);
	u32         magic;   //make sure packet is a multiple of 8 Byte
} __attribute((packed)) Drbd_Parameter_Packet;

typedef struct {
	u64       size;
	u32       state;
	u32       blksize;
	u32       protocol;
	u32       version;
	u32       gen_cnt[5];
	u32       bit_map_gen[5];
} __attribute((packed)) Drbd06_Parameter_P;

typedef union {
	Drbd_Header              head;
	Drbd_HandShake_Packet    HandShake;
	Drbd_Data_Packet         Data;
	Drbd_BlockAck_Packet     BlockAck;
	Drbd_Barrier_Packet      Barrier;
	Drbd_BarrierAck_Packet   BarrierAck;
	Drbd_SyncParam_Packet    SyncParam;
	Drbd_Parameter_Packet    Parameter;
	Drbd_BlockRequest_Packet BlockRequest;
} __attribute((packed)) Drbd_Polymorph_Packet;

/**********************************************************************/

typedef enum {
	None,
	Running,
	Exiting,
	Restarting
} Drbd_thread_state;

struct Drbd_thread {
	spinlock_t t_lock;
	struct task_struct *task;
	struct completion startstop;
	Drbd_thread_state t_state;
	int (*function) (struct Drbd_thread *);
	drbd_dev *mdev;
};

static inline Drbd_thread_state get_t_state(struct Drbd_thread *thi)
{
	/* THINK testing the t_state seems to be uncritical in all cases
	 * (but thread_{start,stop}), so we can read it *without* the lock.
	 * 	--lge */

	smp_rmb();
	return (volatile int)thi->t_state;
}


/*
 * Having this as the first member of a struct provides sort of "inheritance".
 * "derived" structs can be "drbd_queue_work()"ed.
 * The callback should know and cast back to the descendant struct.
 * drbd_request and Tl_epoch_entry are descendants of drbd_work.
 */
struct drbd_work;
typedef int (*drbd_work_cb)(drbd_dev*, struct drbd_work*, int cancel);
struct drbd_work {
	struct list_head list;
	drbd_work_cb cb;
};

/*
 * since we eventually don't want to "remap" any bhs, but allways need a
 * private bh, it may as well be part of the struct so we do not need to
 * allocate it separately.  it is only used as a clone, and since we own it, we
 * can abuse certain fields of if for our own needs.  and, since it is part of
 * the struct, we can use b_private for other things than the req, e.g. mdev,
 * since we get the request struct by means of the "container_of()" macro.
 *	-lge
 */

struct drbd_barrier;
struct drbd_request {
	struct drbd_work w;
	long magic;
	int rq_status;
	struct drbd_barrier *barrier; // The next barrier.
	drbd_bio_t *master_bio;       // master bio pointer
	drbd_bio_t private_bio;       // private bio struct
};

struct drbd_barrier {
	struct list_head requests; // requests before
	struct drbd_barrier *next; // pointer to the next barrier
	int br_number;  // the barriers identifier.
	int n_req;      // number of requests attached before this barrier
};

typedef struct drbd_request drbd_request_t;

/* These Tl_epoch_entries may be in one of 6 lists:
   free_ee   .. free entries
   active_ee .. data packet being written
   sync_ee   .. syncer block being written
   done_ee   .. block written, need to send WriteAck
   read_ee   .. [RS]DataRequest being read
*/

/* Since whenever we allocate a Tl_epoch_entry, we allocated a buffer_head,
 * at the same time, we might as well put it as member into the struct.
 * Yes, we may "waste" a little memory since the unused EEs on the free_ee list
 * are somewhat larger. For 2.6, this will be a struct_bio, which is fairly
 * small, and since we adopt the amount dynamically anyways, this is not an
 * issue.
 *
 * TODO
 * I'd like to "drop" the free list altogether, since we use mempools, which
 * are designed for this. We probably would still need a private "page pool"
 * to do the "bio_add_page" from.
 *	-lge
 */
struct Tl_epoch_entry {
	struct drbd_work    w;
	drbd_bio_t private_bio; // private bio struct, NOT a pointer
	u64    block_id;
	long magic;
	ONLY_IN_26(unsigned int ee_size;)
	ONLY_IN_26(sector_t ee_sector;)
	// THINK: maybe we rather want bio_alloc(GFP_*,1)
	ONLY_IN_26(struct bio_vec ee_bvec;)
};

/* flag bits */
enum {
	ISSUE_BARRIER,		// next Data is preceeded by a Barrier
	SIGNAL_ASENDER,		// whether asender wants to be interrupted
	SEND_PING,		// whether asender should send a ping asap
	WRITER_PRESENT,		// somebody opened us with write intent
	STOP_SYNC_TIMER,	// tell timer to cancel itself
	DO_NOT_INC_CONCNT,	// well, don't ...
	ON_PRI_INC_HUMAN,       // When we become primary increase human-count
	ON_PRI_INC_TIMEOUTEX,   // When " - "  increase timeout-count
	UNPLUG_QUEUED,		// only relevant with kernel 2.4
	UNPLUG_REMOTE,		// whether sending a "UnplugRemote" makes sense
	DISKLESS,		// no local disk
	PARTNER_DISKLESS,	// partner has no storage
	PARTNER_CONSISTENT,	// partner has consistent data
	PROCESS_EE_RUNNING,	// eek!
	MD_IO_ALLOWED,		// EXPLAIN
	SENT_DISK_FAILURE,	// sending it once is enough
	MD_DIRTY,		// current gen counts and flags not yet on disk
};

struct drbd_bitmap; // opaque for Drbd_Conf

// TODO sort members for performance
// MAYBE group them further

/* THINK maybe we actually want to use the default "event/%s" worker threads
 * or similar in linux 2.6, which uses per cpu data and threads.
 *
 * To be general, this might need a spin_lock member.
 * For now, please use the mdev->req_lock to protect list_head,
 * see drbd_queue_work below.
 */
struct drbd_work_queue {
	struct list_head q;
	struct semaphore s; // producers up it, worker down()s it
};

/* If Philipp agrees, we remove the "mutex", and make_request will only
 * (throttle on "queue full" condition and) queue it to the worker thread...
 * which then is free to do whatever is needed, and has exclusive send access
 * to the data socket ...
 */
struct drbd_socket {
	struct drbd_work_queue work;
	struct semaphore  mutex;
	struct socket    *socket;
	Drbd_Polymorph_Packet sbuf;  // this way we get our
	Drbd_Polymorph_Packet rbuf;  // send/receive buffers off the stack
};

struct Drbd_Conf {
#ifdef PARANOIA
	long magic;
#endif
	struct net_config conf;
	struct syncer_config sync_conf;
	enum io_error_handler on_io_error;
	struct semaphore device_mutex;
	struct drbd_socket data; // for data/barrier/cstate/parameter packets
	struct drbd_socket meta; // for ping/ack (metadata) packets
	volatile unsigned long last_received; // in jiffies, either socket
	volatile unsigned int ko_count;
	struct drbd_work  resync_work,
			  barrier_work,
			  unplug_work;
	struct timer_list resync_timer;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	kdev_t backing_bdev;  // backing device
	kdev_t this_bdev;
	kdev_t md_bdev;       // device for meta-data.
#else
	struct block_device *backing_bdev;
	struct block_device *this_bdev;
	struct block_device *md_bdev;
	struct gendisk      *vdisk;
	request_queue_t     *rq_queue;
#endif
	// THINK is this the same in 2.6.x ??
	struct file *lo_file;
	struct file *md_file;
	int md_index;
	unsigned long lo_usize;   /* user provided size */
	unsigned long p_size;     /* partner's disk size */
	Drbd_State state;
	volatile Drbd_CState cstate;
	wait_queue_head_t cstate_wait; // TODO Rename into "misc_wait". 
	Drbd_State o_state;
	unsigned long int la_size; // last agreed disk size
	unsigned int send_cnt;
	unsigned int recv_cnt;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	unsigned int al_writ_cnt;
	unsigned int bm_writ_cnt;
	atomic_t ap_bio_cnt;     // Requests we need to complete
	atomic_t ap_pending_cnt; // AP data packets on the wire, ack expected
	atomic_t rs_pending_cnt; // RS request/data packets on the wire
	atomic_t unacked_cnt;    // Need to send replys for
	atomic_t local_cnt;      // Waiting for local disk to signal completion
	spinlock_t req_lock;
	spinlock_t tl_lock;
	struct drbd_barrier* newest_barrier;
	struct drbd_barrier* oldest_barrier;
	unsigned long flags;
	struct task_struct *send_task; /* about pid calling drbd_send */
	spinlock_t send_task_lock;
	// sector_t rs_left;	   // blocks not up-to-date [unit BM_BLOCK_SIZE]
	// moved into bitmap->bm_set
	unsigned long rs_total;    // blocks to sync in this run [unit BM_BLOCK_SIZE]
	unsigned long rs_start;    // Syncer's start time [unit jiffies]
	unsigned long rs_paused;   // cumulated time in PausedSyncX state [unit jiffies]
	unsigned long rs_mark_left;// block not up-to-date at mark [unit BM_BLOCK_SIZE]
	unsigned long rs_mark_time;// marks's time [unit jiffies]
	struct Drbd_thread receiver;
	struct Drbd_thread worker;
	struct Drbd_thread asender;
	struct drbd_bitmap* bitmap;
	struct lru_cache* resync; // Used to track operations of resync...
	atomic_t resync_locked;   // Number of locked elements in resync LRU
	int open_cnt;
	u32 gen_cnt[GEN_CNT_SIZE];
	int epoch_size;
	spinlock_t ee_lock;
	struct list_head free_ee;   // available
	struct list_head active_ee; // IO in progress
	struct list_head sync_ee;   // IO in progress
	struct list_head done_ee;   // send ack
	struct list_head read_ee;   // IO in progress
	struct list_head net_ee;    // zero-copy network send in progress
	spinlock_t pr_lock;
	struct list_head app_reads;
	struct list_head resync_reads;
	int ee_vacant;
	int ee_in_use;
	wait_queue_head_t ee_wait;
	struct list_head busy_blocks;
	NOT_IN_26(struct tq_struct write_hint_tq;)
	struct page *md_io_page;      // one page buffer for md_io
	struct page *md_io_tmpp;     // in case hardsect != 512 [ s390 only? ]
	struct semaphore md_io_mutex; // protects the md_io_buffer
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache* act_log;     // activity log
	unsigned int al_tr_number;
	int al_tr_cycle;
	int al_tr_pos;     // position of the next transaction in the journal
};


/*
 * function declarations
 *************************/

// drbd_main.c
extern void _set_cstate(drbd_dev* mdev,Drbd_CState cs);
extern void drbd_thread_start(struct Drbd_thread *thi);
extern void _drbd_thread_stop(struct Drbd_thread *thi, int restart, int wait);
extern void drbd_free_resources(drbd_dev *mdev);
extern void tl_release(drbd_dev *mdev,unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(drbd_dev *mdev);
extern int tl_dependence(drbd_dev *mdev, drbd_request_t * item);
extern void drbd_free_sock(drbd_dev *mdev);
extern int drbd_send(drbd_dev *mdev, struct socket *sock,
		     void* buf, size_t size, unsigned msg_flags);
extern int drbd_send_param(drbd_dev *mdev, int flags);
extern int _drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h,
			  size_t size, unsigned msg_flags);
extern int drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h, size_t size);
extern int drbd_send_sync_param(drbd_dev *mdev, struct syncer_config *sc);
extern int drbd_send_b_ack(drbd_dev *mdev, u32 barrier_nr,
			   u32 set_size);
extern int drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			 struct Tl_epoch_entry *e);
extern int _drbd_send_page(drbd_dev *mdev, struct page *page,
			   int offset, size_t size);
extern int drbd_send_block(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			   struct Tl_epoch_entry *e);
extern int drbd_send_dblock(drbd_dev *mdev, drbd_request_t *req);
extern int _drbd_send_barrier(drbd_dev *mdev);
extern int drbd_send_drequest(drbd_dev *mdev, int cmd,
			      sector_t sector,int size, u64 block_id);
extern int drbd_send_bitmap(drbd_dev *mdev);
extern int _drbd_send_bitmap(drbd_dev *mdev);
extern void drbd_free_ll_dev(drbd_dev *mdev);
extern int drbd_io_error(drbd_dev* mdev);
extern void drbd_mdev_cleanup(drbd_dev *mdev);

// drbd_meta-data.c (still in drbd_main.c)
extern void drbd_md_write(drbd_dev *mdev);
extern int drbd_md_read(drbd_dev *mdev);
extern int drbd_md_compare(drbd_dev *mdev,Drbd_Parameter_Packet *partner);
extern void drbd_dump_md(drbd_dev *, Drbd_Parameter_Packet *, int );
// maybe define them below as inline?
extern void drbd_md_inc(drbd_dev *mdev, enum MetaDataIndex order);
extern void drbd_md_set_flag(drbd_dev *mdev, int flags);
extern void drbd_md_clear_flag(drbd_dev *mdev, int flags);
extern int drbd_md_test_flag(drbd_dev *mdev, int flag);

/* Meta data layout
   We reserve a 128MB Block (4k aligned)
   * either at the end of the backing device
   * or on a seperate meta data device. */

#define MD_RESERVED_SIZE ( 128 * (1<<10) )  // 128 MB  ( in units of kb )
// The following numbers are sectors
#define MD_GC_OFFSET 0
#define MD_AL_OFFSET 8      // 8 Sectors after start of meta area
#define MD_AL_MAX_SIZE 64   // = 32 kb LOG  ~ 3776 extents ~ 14 GB Storage
#define MD_BM_OFFSET (MD_AL_OFFSET + MD_AL_MAX_SIZE) //Allows up to about 3.8TB

#define MD_HARDSECT_B    9     // Since the smalles IO unit is usually 512 byte
#define MD_HARDSECT      (1<<MD_HARDSECT_B)

// activity log
#define AL_EXTENTS_PT    (MD_HARDSECT-12)/8-1 // 61 ; Extents per 512B sector
#define AL_EXTENT_SIZE_B 22      // One extent represents 4M Storage
#define AL_EXTENT_SIZE (1<<AL_EXTENT_SIZE_B)

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

// resync bitmap
// 16MB sized 'bitmap extent' to track syncer usage
struct bm_extent {
	struct lc_element lce;
	int rs_left; //number of bits set (out of sync) in this extent.
	unsigned long flags;
};

#define BME_NO_WRITES  0  // bm_extent.flags: no more requests on this one!
#define BME_LOCKED     1  // bm_extent.flags: syncer active on this one.

// drbd_bitmap.c
/*
 * We need to store one bit for a block.
 * Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
 * Bit 0 ==> local node thinks this block is binary identical on both nodes
 * Bit 1 ==> local node thinks this block needs to be synced.
 */

#define BM_BLOCK_SIZE_B  12			 //  4k per bit
#define BM_BLOCK_SIZE    (1<<BM_BLOCK_SIZE_B)
/* (9+3) : 512 bytes @ 8 bits; representing 16M storage
 * per sector of on disk bitmap */
#define BM_EXT_SIZE_B    (BM_BLOCK_SIZE_B + MD_HARDSECT_B + 3 )  // = 24
#define BM_EXT_SIZE      (1<<BM_EXT_SIZE_B)

/* thus many _storage_ sectors are described by one bit */
#define BM_SECT_TO_BIT(x)   ((x)>>(BM_BLOCK_SIZE_B-9))
#define BM_BIT_TO_SECT(x)   ((x)<<(BM_BLOCK_SIZE_B-9))
#define BM_SECT_PER_BIT     BM_BIT_TO_SECT(1)

/* in which _bitmap_ extent (resp. sector) the bit for a certain
 * _storage_ sector is located in */
#define BM_SECT_TO_EXT(x)   ((x)>>(BM_EXT_SIZE_B-9))

/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SIZE_B - AL_EXTENT_SIZE_B) )
#define BM_WORDS_PER_AL_EXT (1 << (AL_EXTENT_SIZE_B-BM_BLOCK_SIZE_B-LN2_BPL))


/* I want the packet to fit within one page
 * THINK maybe use a special bitmap header,
 * including offset and compression scheme and whatnot
 * Do not use PAGE_SIZE here! Use a architecture agnostic constant!
 */
#define BM_PACKET_WORDS     ((4096-sizeof(Drbd_Header))/sizeof(long))

/* the extent in "PER_EXTENT" below is an activity log extent
 * we need that many (long words/bytes) to store the bitmap
 *                   of one AL_EXTENT_SIZE chunk of storage.
 * we can store the bitmap for that many AL_EXTENTS within
 * one sector of the _on_disk_ bitmap:
 * bit   0        bit 37   bit 38            bit (512*8)-1
 *           ...|........|........|.. // ..|........|
 * sect. 0       `296     `304                     ^(512*8*8)-1
 *
#define BM_WORDS_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / BITS_PER_LONG )
#define BM_BYTES_PER_EXT    ( (AL_EXT_SIZE/BM_BLOCK_SIZE) / 8 )  // 128
#define BM_EXT_PER_SECT	    ( 512 / BM_BYTES_PER_EXTENT )        //   4
 */

extern int  drbd_bm_init      (drbd_dev *mdev);
extern int  drbd_bm_resize    (drbd_dev *mdev, sector_t sectors);
extern void drbd_bm_cleanup   (drbd_dev *mdev);
extern void drbd_bm_set_all   (drbd_dev *mdev);
extern void drbd_bm_clear_all (drbd_dev *mdev);
extern void drbd_bm_reset_find(drbd_dev *mdev);
extern int  drbd_bm_set_bit   (drbd_dev *mdev, unsigned long bitnr);
extern int  drbd_bm_test_bit  (drbd_dev *mdev, unsigned long bitnr);
extern int  drbd_bm_clear_bit (drbd_dev *mdev, unsigned long bitnr);
extern int  drbd_bm_e_weight  (drbd_dev *mdev, unsigned long enr);
extern int  drbd_bm_read_sect (drbd_dev *mdev, unsigned long enr);
extern int  drbd_bm_write_sect(drbd_dev *mdev, unsigned long enr);
extern void drbd_bm_read      (drbd_dev *mdev);
extern void drbd_bm_write     (drbd_dev *mdev);
extern unsigned long drbd_bm_ALe_set_all (drbd_dev *mdev, unsigned long al_enr);
extern size_t        drbd_bm_words       (drbd_dev *mdev);
extern unsigned long drbd_bm_find_next   (drbd_dev *mdev);
extern unsigned long drbd_bm_total_weight(drbd_dev *mdev);
extern int drbd_bm_rs_done(drbd_dev *mdev);
// for receive_bitmap
extern void drbd_bm_merge_lel (drbd_dev *mdev, size_t offset, size_t number,
				unsigned long* buffer);
// for _drbd_send_bitmap and drbd_bm_write_sect
extern void drbd_bm_get_lel   (drbd_dev *mdev, size_t offset, size_t number,
				unsigned long* buffer);
/*
 * only used by drbd_bm_read_sect
extern void drbd_bm_set_lel   (drbd_dev *mdev, size_t offset, size_t number,
				unsigned long* buffer);
*/

extern void __drbd_bm_lock    (drbd_dev *mdev, char* file, int line);
extern void drbd_bm_unlock    (drbd_dev *mdev);
#define drbd_bm_lock(mdev)    __drbd_bm_lock(mdev, __FILE__, __LINE__ )


// drbd_main.c
extern drbd_dev *drbd_conf;
extern int minor_count;
extern kmem_cache_t *drbd_request_cache;
extern kmem_cache_t *drbd_ee_cache;
extern mempool_t *drbd_request_mempool;

// drbd_req
#define ERF_NOTLD    2   /* do not call tl_dependence */
extern void drbd_end_req(drbd_request_t *, int, int, sector_t);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
extern int drbd_make_request_24(request_queue_t *q, int rw, struct buffer_head *bio);
#else
extern int drbd_make_request_26(request_queue_t *q, struct bio *bio);
#endif
extern int drbd_read_remote(drbd_dev *mdev, drbd_request_t *req);

// drbd_fs.c
extern int drbd_determin_dev_size(drbd_dev*);
extern int drbd_set_state(drbd_dev *mdev,Drbd_State newstate);
extern int drbd_ioctl(struct inode *inode, struct file *file,
		      unsigned int cmd, unsigned long arg);

// drbd_dsender.c
extern int drbd_worker(struct Drbd_thread *thi);
extern void drbd_alter_sg(drbd_dev *mdev, int ng);
extern void drbd_start_resync(drbd_dev *mdev, Drbd_CState side);
extern int drbd_resync_finished(drbd_dev *mdev);
// maybe rather drbd_main.c ?
extern int drbd_md_sync_page_io(drbd_dev *mdev, sector_t sector, int rw);
// worker callbacks
extern int w_is_app_read         (drbd_dev *, struct drbd_work *, int);
extern int w_is_resync_read      (drbd_dev *, struct drbd_work *, int);
extern int w_read_retry_remote   (drbd_dev *, struct drbd_work *, int);
extern int w_e_end_data_req      (drbd_dev *, struct drbd_work *, int);
extern int w_e_end_rsdata_req    (drbd_dev *, struct drbd_work *, int);
extern int w_resync_inactive     (drbd_dev *, struct drbd_work *, int);
extern int w_resume_next_sg      (drbd_dev *, struct drbd_work *, int);
extern int w_io_error            (drbd_dev *, struct drbd_work *, int);
extern int w_try_send_barrier    (drbd_dev *, struct drbd_work *, int);
extern int w_send_write_hint     (drbd_dev *, struct drbd_work *, int);
extern int w_make_resync_request (drbd_dev *, struct drbd_work *, int);

// drbd_receiver.c
extern int drbd_release_ee(drbd_dev* mdev,struct list_head* list);
extern int drbd_init_ee(drbd_dev* mdev);
extern void drbd_put_ee(drbd_dev* mdev,struct Tl_epoch_entry *e);
extern struct Tl_epoch_entry* drbd_get_ee(drbd_dev* mdev);
extern void drbd_wait_ee(drbd_dev *mdev,struct list_head *head);

// drbd_proc.c
extern struct proc_dir_entry *drbd_proc;
extern int drbd_proc_get_info(char *, char **, off_t, int, int *, void *);
extern const char* cstate_to_name(Drbd_CState s);
extern const char* nodestate_to_name(Drbd_State s);

// drbd_actlog.c
extern void drbd_al_begin_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_al_complete_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_rs_complete_io(struct Drbd_Conf *mdev, sector_t sector);
extern int drbd_rs_begin_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_rs_cancel_all(drbd_dev* mdev);
extern void drbd_al_read_log(struct Drbd_Conf *mdev);
extern void __drbd_set_in_sync(drbd_dev* mdev, sector_t sector, int size, const char* file, const unsigned int line);
#define drbd_set_in_sync(mdev,sector,size) \
	__drbd_set_in_sync(mdev,sector,size, __FILE__, __LINE__ )
extern void __drbd_set_out_of_sync(drbd_dev* mdev, sector_t sector, int size, const char* file, const unsigned int line);
#define drbd_set_out_of_sync(mdev,sector,size) \
	__drbd_set_out_of_sync(mdev,sector,size, __FILE__, __LINE__ )
extern void drbd_al_apply_to_bm(struct Drbd_Conf *mdev);
extern void drbd_al_to_on_disk_bm(struct Drbd_Conf *mdev);
extern void drbd_al_shrink(struct Drbd_Conf *mdev);

/*
 * event macros
 *************************/

// we use these within spin_lock_irq() ...
#ifndef wq_write_lock
#if USE_RW_WAIT_QUEUE_SPINLOCK
# define wq_write_lock write_lock
# define wq_write_unlock write_unlock
# define wq_write_unlock_irq write_unlock_irq
#else
# define wq_write_lock spin_lock
# define wq_write_unlock spin_unlock
# define wq_write_unlock_irq spin_unlock_irq
#endif
#endif

// sched.h does not have it with timeout, so here goes:

#ifndef wait_event_interruptible_timeout
#define __wait_event_interruptible_timeout(wq, condition, ret)		\
do {									\
	wait_queue_t __wait;						\
	init_waitqueue_entry(&__wait, current);				\
									\
	add_wait_queue(&wq, &__wait);					\
	for (;;) {							\
		set_current_state(TASK_INTERRUPTIBLE);			\
		if (condition)						\
			break;						\
		if (!signal_pending(current)) {				\
			ret = schedule_timeout(ret);			\
			if (!ret)					\
				break;					\
			continue;					\
		}							\
		ret = -EINTR;						\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_event_interruptible_timeout(wq, condition, timeout)	\
({									\
	long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#endif

/*
 * inline helper functions
 *************************/

#include "drbd_compat_wrappers.h"

static inline void
drbd_flush_signals(struct task_struct *t)
{
	NOT_IN_26(
	unsigned long flags;
	LOCK_SIGMASK(t,flags);
	)

	flush_signals(t);
	NOT_IN_26(UNLOCK_SIGMASK(t,flags));
}

static inline void set_cstate(drbd_dev* mdev,Drbd_CState ns)
{
	unsigned long flags;
	spin_lock_irqsave(&mdev->req_lock,flags);
	_set_cstate(mdev,ns);
	spin_unlock_irqrestore(&mdev->req_lock,flags);
}

/**
 * drbd_chk_io_error: Handles the on_io_error setting, should be called from
 * all io completion handlers. See also drbd_io_error().
 */
static inline void drbd_chk_io_error(drbd_dev* mdev, int error)
{
	if (error) {
		switch(mdev->on_io_error) {
		case PassOn:
			ERR("Ignoring local IO error!\n");
			break;
		case Panic:
			set_bit(DISKLESS,&mdev->flags);
			smp_mb(); // but why is there smp_mb__after_clear_bit() ?
			drbd_panic("IO error on backing device!\n");
			break;
		case Detach:
			/*lge:
			 *  I still do not fully grasp when to set or clear
			 *  this flag... but I want to be able to at least
			 *  still _try_ and write the "I am inconsistent, and
			 *  need full sync" information to the MD. */
			set_bit(MD_IO_ALLOWED,&mdev->flags);
			drbd_md_set_flag(mdev,MDF_FullSync);
			drbd_md_clear_flag(mdev,MDF_Consistent);
			if (!test_and_set_bit(DISKLESS,&mdev->flags)) {
				smp_mb(); // Nack is sent in w_e handlers.
				ERR("Local IO failed. Detaching...\n");
			}
			break;
		}
	}
}

static inline int semaphore_is_locked(struct semaphore* s) 
{
	if(!down_trylock(s)) {
		up(s);
		return 0;
	}
	return 1;
}
/* Returns the start sector for metadata, aligned to 4K
 * which happens to be the capacity we announce for
 * our lower level device if it includes the meta data
 */
static inline sector_t drbd_md_ss(drbd_dev *mdev)
{
	if( mdev->md_index == -1 ) {
		if (!mdev->backing_bdev) {
			if (DRBD_ratelimit(5*HZ,5)) {
				ERR("mdev->backing_bdev==NULL\n");
				dump_stack();
			}
			return 0;
		}
		return (  (drbd_get_capacity(mdev->backing_bdev) & ~7L)
			- (MD_RESERVED_SIZE<<1) );
	} else {
		return 2 * MD_RESERVED_SIZE * mdev->md_index;
	}
}

static inline void
_drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	list_add_tail(&w->list,&q->q);
	up(&q->s);
}

static inline void
_drbd_queue_work_front(struct drbd_work_queue *q, struct drbd_work *w)
{
	list_add(&w->list,&q->q);
	up(&q->s);
}

static inline void
drbd_queue_work_front(drbd_dev *mdev, struct drbd_work_queue *q,
			struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&mdev->req_lock,flags);
	list_add(&w->list,&q->q);
	spin_unlock_irqrestore(&mdev->req_lock,flags);
	up(&q->s);
}

static inline void
drbd_queue_work(drbd_dev *mdev, struct drbd_work_queue *q,
		  struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&mdev->req_lock,flags);
	list_add_tail(&w->list,&q->q);
	spin_unlock_irqrestore(&mdev->req_lock,flags);
	up(&q->s);
}

static inline void wake_asender(drbd_dev *mdev) {
	if(test_bit(SIGNAL_ASENDER, &mdev->flags)) {
		force_sig(DRBD_SIG, mdev->asender.task);
	}
}

static inline void request_ping(drbd_dev *mdev) {
	set_bit(SEND_PING,&mdev->flags);
	wake_asender(mdev);
}

static inline int drbd_send_short_cmd(drbd_dev *mdev, Drbd_Packet_Cmd cmd)
{
	Drbd_Header h;
	return drbd_send_cmd(mdev,mdev->data.socket,cmd,&h,sizeof(h));
}

static inline int drbd_send_ping(drbd_dev *mdev)
{
	Drbd_Header h;
	return drbd_send_cmd(mdev,mdev->meta.socket,Ping,&h,sizeof(h));
}

static inline int drbd_send_ping_ack(drbd_dev *mdev)
{
	Drbd_Header h;
	return drbd_send_cmd(mdev,mdev->meta.socket,PingAck,&h,sizeof(h));
}

static inline void drbd_thread_stop(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,FALSE,TRUE);
}

static inline void drbd_thread_stop_nowait(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,FALSE,FALSE);
}

static inline void drbd_thread_restart_nowait(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,TRUE,FALSE);
}

static inline void inc_ap_pending(drbd_dev* mdev)
{
	atomic_inc(&mdev->ap_pending_cnt);
}

static inline void dec_ap_pending(drbd_dev* mdev, const char* where)
{
	if(atomic_dec_and_test(&mdev->ap_pending_cnt))
		wake_up(&mdev->cstate_wait);

	if(atomic_read(&mdev->ap_pending_cnt)<0)
		ERR("in %s: pending_cnt = %d < 0 !\n",
		    where,
		    atomic_read(&mdev->ap_pending_cnt));
}

static inline void inc_rs_pending(drbd_dev* mdev)
{
	atomic_inc(&mdev->rs_pending_cnt);
}

static inline void dec_rs_pending(drbd_dev* mdev, const char* where)
{
	atomic_dec(&mdev->rs_pending_cnt);

	if(atomic_read(&mdev->rs_pending_cnt)<0) 
		ERR("in %s: rs_pending_cnt = %d < 0 !\n",
		    where,
		    atomic_read(&mdev->unacked_cnt));
}

static inline void inc_unacked(drbd_dev* mdev)
{
	atomic_inc(&mdev->unacked_cnt);
}

static inline void dec_unacked(drbd_dev* mdev,const char* where)
{
	atomic_dec(&mdev->unacked_cnt);

	if(atomic_read(&mdev->unacked_cnt)<0)
		ERR("in %s: unacked_cnt = %d < 0 !\n",
		    where,
		    atomic_read(&mdev->unacked_cnt));
}

/**
 * inc_local: Returns TRUE when local IO is possible. If it returns
 * TRUE you should call dec_local() after IO is completed.
 */
static inline int inc_local(drbd_dev* mdev)
{
	int io_allowed;

	atomic_inc(&mdev->local_cnt);
	io_allowed = !test_bit(DISKLESS,&mdev->flags);
	if( !io_allowed ) {
		atomic_dec(&mdev->local_cnt);
	}
	return io_allowed;
}

static inline int inc_local_md_only(drbd_dev* mdev)
{
	int io_allowed;

	atomic_inc(&mdev->local_cnt);
	io_allowed = !test_bit(DISKLESS,&mdev->flags) ||
		test_bit(MD_IO_ALLOWED,&mdev->flags);
	if( !io_allowed ) {
		atomic_dec(&mdev->local_cnt);
	}
	return io_allowed;
}

static inline void dec_local(drbd_dev* mdev)
{
	if(atomic_dec_and_test(&mdev->local_cnt) && 
	   test_bit(DISKLESS,&mdev->flags) &&
	   mdev->lo_file) {
		wake_up(&mdev->cstate_wait);
	}

	D_ASSERT(atomic_read(&mdev->local_cnt)>=0);
}

static inline void inc_ap_bio(drbd_dev* mdev)
{
	atomic_inc(&mdev->ap_bio_cnt);
}

static inline void dec_ap_bio(drbd_dev* mdev)
{
	if(atomic_dec_and_test(&mdev->ap_bio_cnt))
		wake_up(&mdev->cstate_wait);

	D_ASSERT(atomic_read(&mdev->ap_bio_cnt)>=0);
}

#ifdef DUMP_EACH_PACKET
/*
 * enable to dump information about every packet exchange.
 */
#define INFOP(fmt, args...) \
	INFO("%s:%d: %s [%d] %s %s " fmt , \
	     file, line, current->comm, current->pid, \
	     sockname, recv?"<<<":">>>" \
	     , ## args )
static inline void
dump_packet(drbd_dev *mdev, struct socket *sock,
	    int recv, Drbd_Polymorph_Packet *p, char* file, int line)
{
	char *sockname = sock == mdev->meta.socket ? "meta" : "data";
	int cmd = (recv == 2) ? p->head.command : be16_to_cpu(p->head.command);
	switch (cmd) {
	case HandShake:
		INFOP("%s (%u)\n", be32_to_cpu(p->HandShake.protocol_version));
		break;

	case Ping:
	case PingAck:
	case BecomeSyncTarget:
	case BecomeSyncSource:
	case UnplugRemote:

	case SyncParam:
	case ReportParams:
		INFOP("%s\n", cmdname(cmd));
		break;

	case ReportBitMap: /* don't report this */
		break;

	case Data:
	case DataReply:
	case RSDataReply:

	case RecvAck:   /* yes I know. but it is the same layout */
	case WriteAck:
	case NegAck:

	case DataRequest:
	case RSDataRequest:
		INFOP("%s (%lu,%llx)\n", cmdname(cmd),
		     (long)be64_to_cpu(p->Data.sector), (long long)p->Data.block_id
		);
		break;

	case Barrier:
	case BarrierAck:
		INFOP("%s (%u)\n", cmdname(cmd), p->Barrier.barrier);
		break;

	default:
		INFOP("%s (%u)\n",cmdname(cmd), cmd);
		break;
	}
}
#else
#define dump_packet(ignored...) ((void)0)
#endif


#ifndef sector_div
# define sector_div(n, b)( \
{ \
	int _res; \
	_res = (n) % (b); \
	(n) /= (b); \
	_res; \
} \
)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
// this is a direct copy from 2.6.6 include/linux/bitops.h

static inline unsigned long generic_hweight64(u64 w)
{
#if BITS_PER_LONG < 64
	return generic_hweight32((unsigned int)(w >> 32)) +
				generic_hweight32((unsigned int)w);
#else
	u64 res;
	res = (w & 0x5555555555555555ul) + ((w >> 1) & 0x5555555555555555ul);
	res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
	res = (res & 0x0F0F0F0F0F0F0F0Ful) + ((res >> 4) & 0x0F0F0F0F0F0F0F0Ful);
	res = (res & 0x00FF00FF00FF00FFul) + ((res >> 8) & 0x00FF00FF00FF00FFul);
	res = (res & 0x0000FFFF0000FFFFul) + ((res >> 16) & 0x0000FFFF0000FFFFul);
	return (res & 0x00000000FFFFFFFFul) + ((res >> 32) & 0x00000000FFFFFFFFul);
#endif
}

static inline unsigned long hweight_long(unsigned long w)
{
	return sizeof(w) == 4 ? generic_hweight32(w) : generic_hweight64(w);
}
#endif
