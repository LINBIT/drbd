/*
  drbd_int.h
  Kernel module for 2.2.x/2.4.x Kernels

  This file is part of drbd by Philipp Reisner.

  Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

  Copyright (C) 2002-2003, Lars Ellenberg <l.g.e@web.de>.
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
#include "mempool.h"
#include "lru_cache.h"

// module parameter, defined in drbd_main.c
extern int minor_count;
extern int disable_io_hints;

/* Using the major_nr of the network block device
   prevents us from deadlocking with no request entries
   left on all_requests...
   look out for NBD_MAJOR in ll_rw_blk.c */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
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
# define DRBD_MAJOR NBD_MAJOR
#else
# include <linux/blkdev.h>
# include <linux/bio.h>
# define MAJOR_NR NBD_MAJOR
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
#define DRBD_SIG SIGXCPU
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
#define DUMPP(A) ERR( #A " = %p in %s:%d\n",(A),__FILE__,__LINE__);
#define DUMPLU(A) ERR( #A " = %lu in %s:%d\n",(A),__FILE__,__LINE__);
#define DUMPLLU(A) ERR( #A " = %llu in %s:%d\n",(A),__FILE__,__LINE__);
#define DUMPLX(A) ERR( #A " = %lx in %s:%d\n",(A),__FILE__,__LINE__);
#define DUMPI(A) ERR( #A " = %d in %s:%d\n",(A),__FILE__,__LINE__);


// Info: do not remove the spaces around the "," before ##
//       Otherwise this is not portable from gcc-2.95 to gcc-3.3
#define PRINTK(level,fmt,args...) \
	printk(level DEVICE_NAME "%d: " fmt, \
		(int)(mdev-drbd_conf) , ##args)

#define ERR(fmt,args...)  PRINTK(KERN_ERR, fmt , ##args)
#define WARN(fmt,args...) PRINTK(KERN_WARNING, fmt , ##args)
#define INFO(fmt,args...) PRINTK(KERN_INFO, fmt , ##args)
#define DBG(fmt,args...)  PRINTK(KERN_DEBUG, fmt , ##args)

#ifdef DBG_ASSERTS
extern void drbd_assert_breakpoint(drbd_dev*, char *, char *, int );
# define D_ASSERT(exp)  if (!(exp)) \
	 drbd_assert_breakpoint(mdev,#exp,__FILE__,__LINE__)
#else
# define D_ASSERT(exp)  if (!(exp)) \
	 ERR("ASSERT( " #exp " ) in %s:%d\n", __FILE__,__LINE__)
#endif
#define ERR_IF(exp) if (({ \
	int _b = (exp); \
	if (_b) ERR("%s: (" #exp ") in %s:%d\n", __func__, __FILE__,__LINE__); \
	 _b; \
	}))

// to debug dec_*(), while we still have the <0!! issue
// to debug dec_*(), while we still have the <0!! issue
#include <linux/stringify.h>
#define HERE __stringify(__FUNCTION__ __LINE__) // __FUNCTION__

#if 1
#define C_DBG(r,x...)
#else
	// at most one DBG(x) per t seconds
#define C_DBG(t,x...) do { \
	static unsigned long _j; \
	if ((long)(jiffies-_j)< HZ*t) break; \
	_j=jiffies; \
	DBG(x); \
} while (0)
#endif

// integer division, round _UP_ to the next integer
#define div_ceil(A,B) ( (A)/(B) + ((A)%(B) ? 1 : 0) )
// usual integer division
#define div_floor(A,B) ( (A)/(B) )

/*
 * Compatibility Section
 *************************/

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
typedef unsigned long sector_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,7)
#define completion semaphore
#define init_completion(A) init_MUTEX_LOCKED(A)
#define wait_for_completion(A) down(A)
#define complete(A) up(A)
#else
#include <linux/completion.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10)
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#define MODULE_LICENSE(L)
#endif

#if !defined(CONFIG_HIGHMEM) && !defined(bh_kmap)
#define bh_kmap(bh)	((bh)->b_data)
#define bh_kunmap(bh)	do { } while (0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,19)
#define BH_Launder BH_launder
#endif

#ifndef list_for_each
#define list_for_each(pos, head) \
	for(pos = (head)->next; pos != (head); pos = pos->next)
#endif

#if defined(DBG_SPINLOCKS) && defined(__SMP__)
# define MUST_HOLD(lock) if(!spin_is_locked(lock)) { ERR("Not holding lock! in %s\n", __FUNCTION__ ); }
#else
# define MUST_HOLD(lock)
#endif

#ifdef SIGHAND_HACK
# define LOCK_SIGMASK(task,flags)   spin_lock_irqsave(&task->sighand->siglock, flags)
# define UNLOCK_SIGMASK(task,flags) spin_unlock_irqrestore(&task->sighand->siglock, flags)
# define RECALC_SIGPENDING(TSK)     (recalc_sigpending_tsk(TSK))
// defined in drbd_main.c,
// copied from redhat's kernel-2.4.20-13.9 kernel/signal.c
// to avoid a recompile of the redhat kernel
inline void recalc_sigpending_tsk(struct task_struct *t);
#else
# define LOCK_SIGMASK(task,flags)   spin_lock_irqsave(&task->sigmask_lock, flags)
# define UNLOCK_SIGMASK(task,flags) spin_unlock_irqrestore(&task->sigmask_lock, flags)
# define RECALC_SIGPENDING(TSK)     (recalc_sigpending(TSK))
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

// THINK: x->magic = &x; ??
#define SET_MAGIC(x) ((x)->magic = (int)(x) ^ DRBD_MAGIC)
// For some optimization crap, please test for NULL explicitly,
//	and not in this macro!
// #define VALID_POINTER(x) ((x) && (x)->magic == DRBD_MAGIC)
// #define VALID_POINTER(x) ((x)->magic == DRBD_MAGIC)
// hopefully this works:
#define VALID_POINTER(x) ((x) ? (((x)->magic ^ DRBD_MAGIC) == (int)(x)):0)
#define INVALIDATE_MAGIC(x) (x->magic--)

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct Drbd_Conf*,x); \
	  (x)->magic = (long)(x) ^ DRBD_MAGIC; })
#define IS_VALID_MDEV(x)  \
	( typecheck(struct Drbd_Conf*,x) && \
	  ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)):0))


/*
 * GFP_DRBD is used for allocations inside drbd_do_request.
 *
 * 2.4 kernels will probably remove the __GFP_IO check in the VM code,
 * so lets use GFP_ATOMIC for allocations.  For 2.2, we abuse the GFP_BUFFER
 * flag to avoid __GFP_IO, thus avoiding the use of the atomic queue and
 *  avoiding the deadlock.
 *
 * - marcelo
 *
 * try to get away with GFP_NOIO, which is (GFP_ATOMIC | __GFP_WAIT)
 * as far as i can see we do not allocate from interrupt context...
 * needs to be tested under memory pressure, though.
 * - lge
 */
#define GFP_DRBD GFP_NOIO

/* these defines should go into blkdev.h
   (if it will be ever includet into linus' linux) */
#define RQ_DRBD_NOTHING	  0x0001
#define RQ_DRBD_SENT	  0x0010
#define RQ_DRBD_WRITTEN   0x0020
#define RQ_DRBD_DONE      0x0030
#define RQ_DRBD_READ      0x0040

#define DRBD_PANIC 2
/* do_panic alternatives:
 *	0: panic();
 *	1: machine_halt;  FIXME does not work;
 *	2: prink(EMERG ), plus flag to fail all eventual drbd IO, plus panic()
 */

extern volatile int drbd_did_panic;

#include <linux/reboot.h>

#if    DRBD_PANIC == 0
#define drbd_panic(x...) panic(x)
#elif  DRBD_PANIC == 1
#error "THIS DRBD_PANIC SETTING DOES NOT WORK (yet)"
#define drbd_panic(x...) do {						\
	printk(KERN_EMERG x);						\
	notifier_call_chain(&reboot_notifier_list, SYS_HALT, NULL);	\
	printk(KERN_EMERG "System halted.\n");				\
	machine_halt();							\
	do_exit(0);							\
} while (0)
#else
#define drbd_panic(x...) do {		\
	printk(KERN_EMERG x);		\
	drbd_did_panic = DRBD_MD_MAGIC;	\
	smp_mb();			\
	panic(x);			\
} while (0)
#endif
#undef DRBD_PANIC

enum MetaDataFlags {
	MDF_Consistent   = 1,
	MDF_PrimaryInd   = 2,
	MDF_ConnectedInd = 4,
};
/* drbd_meta-data.c (still in drbd_main.c) */
enum MetaDataIndex {
	Flags,          /* Consistency flag,connected-ind,primary-ind */
	HumanCnt,       /* human-intervention-count */
	TimeoutCnt,     /* timout-count */
	ConnectedCnt,   /* connected-count */
	ArbitraryCnt    /* arbitrary-count */
};

#define GEN_CNT_SIZE 5
#define DRBD_MD_MAGIC (DRBD_MAGIC+3) // 3nd incarnation of the file format.


/***
 * on the wire
 *********************************************************************/

typedef enum {
	WakeAsender,  // interrupted drbd_receive_header fakes this
	Data,
	DataReply,
	RecvAck,      // Used in protocol B
	WriteAck,     // Used in protocol C
	Barrier,
	BarrierAck,
	ReportParams,
	ReportBitMap,
	Ping,
	PingAck,
	BecomeSyncTarget,
	BecomeSyncSource,
	BecomeSec,     // Secondary asking primary to become secondary
	WriteHint,     // Used in protocol C to hint the secondary to call tq_disk
	DataRequest,   // Used to ask for a data block
	RSDataRequest, // Used to ask for a data block
	SyncParam,
	SyncStop,
	SyncCont,
	MAX_CMD,
	MayIgnore = 0x100, // Flag only to test if (cmd > MayIgnore) ...
	MAX_OPT_CMD,
} Drbd_Packet_Cmd;

// FIXME we should be able to define this away
// no char* cmdname[], since I'm not sure the index is valid ...
static inline const char* cmdname(Drbd_Packet_Cmd cmd)
{
	switch (cmd) {
	case WakeAsender     : return "WakeAsender";
	case Data            : return "Data";
	case DataReply       : return "DataReply";
	case RecvAck         : return "RecvAck";
	case WriteAck        : return "WriteAck";
	case Barrier         : return "Barrier";
	case BarrierAck      : return "BarrierAck";
	case ReportParams    : return "ReportParams";
	case ReportBitMap    : return "ReportBitMap";
	case Ping            : return "Ping";
	case PingAck         : return "PingAck";
	case BecomeSyncTarget: return "BecomeSyncTarget";
	case BecomeSyncSource: return "BecomeSyncSource";
	case BecomeSec       : return "BecomeSec";
	case WriteHint       : return "WriteHint";
	case DataRequest     : return "DataRequest";
	case RSDataRequest   : return "RSDataRequest";
	case SyncParam       : return "SyncParam";
	case SyncStop        : return "SyncStop";
	case SyncCont        : return "SyncCont";
	case MAX_CMD         : return "MAX_CMD";
	case MayIgnore       : return "MayIgnore";
	case MAX_OPT_CMD     : return "MAX_OPT_CMD";
	default              : return "Unknown";
	}
}

/* This is the layout for a packet on the wire.
 * The byteorder is the network byte order.
 *     (except block_id and barrier fields.
 *      these are pointers to local structs
 *      and have no relevance for the partner,
 *      which just echoes them as received.)
 */
typedef struct {
	u32       magic;
	u16       command;
	u16       length;	// bytes of data after this header
	char      payload[0];
} Drbd_Header __attribute((packed));

/*
 * short commands, packets without payload, plain Drbd_Header:
 *   Ping
 *   PingAck
 *   BecomeSyncTarget
 *   BecomeSyncSource
 *   BecomeSec
 *   WriteHint
 *   SyncStop
 *   SyncCont
 *   SyncDone
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
} Drbd_Data_Packet  __attribute((packed));

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
} Drbd_BlockAck_Packet __attribute((packed));

typedef struct {
	Drbd_Header head;
	u64         sector;
	u64         block_id;
	u32         blksize;
} Drbd_BlockRequest_Packet __attribute((packed));

/*
 * commands with their own struct for additional fields:
 *   Barrier
 *   BarrierAck
 *   SyncParam
 *   ReportParams
 */
typedef struct {
	Drbd_Header head;
	u32         barrier;   // may be 0 or a barrier number
} Drbd_Barrier_Packet  __attribute((packed));

typedef struct {
	Drbd_Header head;
	u32         barrier;
	u32         set_size;
} Drbd_BarrierAck_Packet  __attribute((packed));

typedef struct {
	Drbd_Header head;
	u32         rate;
	u32         use_csums;
	u32         skip;
	u32         group;
} Drbd_SyncParam_Packet  __attribute((packed));

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
} Drbd_Parameter_Packet  __attribute((packed));

typedef union {
	Drbd_Header              head;
	Drbd_Data_Packet         Data;
	Drbd_BlockAck_Packet     BlockAck;
	Drbd_Barrier_Packet      Barrier;
	Drbd_BarrierAck_Packet   BarrierAck;
	Drbd_SyncParam_Packet    SyncParam;
	Drbd_Parameter_Packet    Parameter;
	Drbd_BlockRequest_Packet BlockRequest;
} Drbd_Polymorph_Packet __attribute((packed));

/**********************************************************************/

typedef enum {
	Running,
	Exiting,
	Restarting
} Drbd_thread_state;

struct Drbd_thread {
	struct task_struct *task;
	struct semaphore mutex;
	volatile Drbd_thread_state t_state;
	int (*function) (struct Drbd_thread *);
	drbd_dev *mdev;
};


/*
 * Having this as the first member of a struct provides sort of "inheritance".
 * "derived" structs can be "drbd_queue_work()"ed.
 * The callback should know and cast back to the descendant struct.
 * drbd_request, Pending_read and Tl_epoch_entry are descendants of drbd_work.
 * Pending_read will soon be merged into drbd_request, stay tuned ... -lge
 */
struct drbd_work;
typedef int (*drbd_work_cb)(drbd_dev*, struct drbd_work*);
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
	int magic;
	int rq_status;
	struct drbd_barrier *barrier; // The next barrier.
	struct buffer_head *bh;       // master buffer head pointer
	struct buffer_head  pbh;      // private buffer head struct
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
   rdone_ee  .. block read, need to send DataReply
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
 * to set the bh.b_page from.
 *	-lge
 */
struct Tl_epoch_entry {
	struct drbd_work    w;
	struct buffer_head  pbh; // private buffer head struct, NOT a pointer
	u64    block_id;
	int magic;
};

struct Pending_read {
	struct drbd_work w;
	int magic;
	union {
		struct buffer_head* bh;
		sector_t sector;
	} d;
	enum {
		Discard = 0,
		Application = 1,
		Resync = 2,
		AppAndResync = 3,
	} cause;
};

// bitfield? enum?
/* flag bits */
#define ISSUE_BARRIER      0
#define COLLECT_ZOMBIES    1
#define SEND_PING          2
#define WRITER_PRESENT     3
//#define START_SYNC         4
#define DO_NOT_INC_CONCNT  5
#define WRITE_HINT_QUEUED  6
#define PARTNER_DISKLESS   7
//#define SYNC_FINISHED      8
#define PROCESS_EE_RUNNING 9
//#define SYNC_CONTINUE     10

struct BitMap {
	unsigned long dev_size;
	unsigned long size;
	unsigned long* bm;
	unsigned long gs_bitnr;
	unsigned long gs_snr;
	spinlock_t bm_lock;
};

#define BM_EXTENT_SIZE_B 24       // One extent represents 16M Storage
#define BM_EXTENT_SIZE (1<<BM_EXTENT_SIZE_B)

struct bm_extent { // 16MB sized extents.
	struct lc_element lce;
	int rs_left; //number of sectors our of sync in this extent.
	unsigned long flags;
};

#define BME_NO_WRITES    0
#define BME_LOCKED       1

// TODO sort members for performance
// MAYBE group them further

/* THINK maybe we actually want to use the default "event/%s" worker threads
 * or similar in linux 2.6, which uses per cpu data and threads.
 *
 * To be general, this might need a spin_lock member.
 * For now, please use the mdev->req_lock to protect list_head,
 * see __drbd_queue_work below.
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
	int do_panic;
	struct semaphore device_mutex;
	struct drbd_socket data; // for data/barrier/cstate/parameter packets
	struct drbd_socket meta; // for ping/ack (metadata) packets
	volatile unsigned long last_received; // in jiffies, either socket
	struct drbd_work  resync_work;
	struct timer_list resync_timer;
	kdev_t lo_device;         // backing device
	struct file *lo_file;
	kdev_t md_device;         // device for meta-data.
	struct file *md_file;
	int md_index;
	unsigned long lo_usize;   /* user provided size */
	unsigned long p_size;     /* partner's disk size */
	Drbd_State state;
	Drbd_CState cstate;
	wait_queue_head_t cstate_wait;
	struct list_head  cstate_hook; // processed if cstate changes.
	wait_queue_head_t state_wait;  // TODO: Remove state_wait.
	Drbd_State o_state;
	unsigned long int la_size; // last agreed disk size
	unsigned int send_cnt;
	unsigned int recv_cnt;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	unsigned int al_writ_cnt;
	unsigned int bm_writ_cnt;
	atomic_t pending_cnt;
	atomic_t unacked_cnt;
	spinlock_t req_lock;
	spinlock_t tl_lock;
	struct drbd_barrier* newest_barrier;
	struct drbd_barrier* oldest_barrier;
	unsigned long flags;
	struct task_struct *send_task; /* about pid calling drbd_send */
	spinlock_t send_task_lock;
	sector_t rs_left;     // blocks not up-to-date [unit sectors]
	sector_t rs_total;    // blocks to sync in this run [unit sectors]
	unsigned long rs_start;    // Syncer's start time [unit jiffies]
	sector_t rs_mark_left;// block not up-to-date at mark [unit sect.]
	unsigned long rs_mark_time;// marks's time [unit jiffies]
	struct Drbd_thread receiver;
	struct Drbd_thread worker;
	struct Drbd_thread asender;
	struct BitMap* mbds_id;
	struct lru_cache* resync; // Used to track operations of resync...
	int open_cnt;
	u32 gen_cnt[GEN_CNT_SIZE];
	int epoch_size;
	spinlock_t ee_lock;
	struct list_head free_ee;   // available
	struct list_head active_ee; // IO in progress
	struct list_head sync_ee;   // IO in progress
	struct list_head done_ee;   // send ack
	struct list_head read_ee;   // IO in progress
	// struct list_head rdone_ee;  // send result or CondRequest
	spinlock_t pr_lock;
	struct list_head app_reads;
	struct list_head resync_reads;
	int ee_vacant;
	int ee_in_use;
	wait_queue_head_t ee_wait;
	struct list_head busy_blocks;
	struct tq_struct write_hint_tq;
	struct buffer_head md_io_bh; // a (one page) Byte buffer for md_io
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
extern void set_cstate(drbd_dev* mdev,Drbd_CState cs);
extern void drbd_thread_start(struct Drbd_thread *thi);
extern void _drbd_thread_stop(struct Drbd_thread *thi, int restart, int wait);
extern void drbd_free_resources(drbd_dev *mdev);
extern void tl_release(drbd_dev *mdev,unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(drbd_dev *mdev);
extern int tl_dependence(drbd_dev *mdev, drbd_request_t * item);
extern void drbd_free_sock(drbd_dev *mdev);
/* extern int drbd_send(drbd_dev *mdev, struct socket *sock,
	      void* buf, size_t size, unsigned msg_flags); */
extern int drbd_send_param(drbd_dev *mdev);
extern int drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h, size_t size);
extern int drbd_send_sync_param(drbd_dev *mdev);
extern int drbd_send_cstate(drbd_dev *mdev);
extern int drbd_send_b_ack(drbd_dev *mdev, u32 barrier_nr,
			   u32 set_size);
extern int drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			 struct Tl_epoch_entry *e);
extern int drbd_send_block(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			   struct Tl_epoch_entry *e);
extern int drbd_send_dblock(drbd_dev *mdev, drbd_request_t *req);
extern int _drbd_send_barrier(drbd_dev *mdev);
extern int drbd_send_drequest(drbd_dev *mdev, int cmd,
			      sector_t sector,int size, u64 block_id);
extern int drbd_send_insync(drbd_dev *mdev,sector_t sector,
			    u64 block_id);
extern int drbd_send_bitmap(drbd_dev *mdev);

// drbd_meta-data.c (still in drbd_main.c)
extern void drbd_generic_end_io(struct buffer_head *bh, int uptodate);
extern void drbd_md_write(drbd_dev *mdev);
extern void drbd_md_read(drbd_dev *mdev);
extern void drbd_md_inc(drbd_dev *mdev, enum MetaDataIndex order);
extern int drbd_md_compare(drbd_dev *mdev,Drbd_Parameter_Packet *partner);

// drbd_bitmap.c (still in drbd_main.c)
#define SS_OUT_OF_SYNC (1)
#define SS_IN_SYNC     (0)
#define MBDS_SYNC_ALL (-2)
#define MBDS_DONE     (-3)
// I want the packet to fit within one page
#define MBDS_PACKET_SIZE (PAGE_SIZE-sizeof(Drbd_Header))

#define BM_BLOCK_SIZE_B  12
#define BM_BLOCK_SIZE    (1<<BM_BLOCK_SIZE_B)

#define BM_IN_SYNC       0
#define BM_OUT_OF_SYNC   1


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

/* Returns the number of kb of a block device. */
static inline unsigned long capacity(kdev_t dev) {
	return blk_size[MAJOR(dev)][MINOR(dev)];
}

/* Returns the start sector for metadata */
static inline sector_t drbd_md_ss(drbd_dev *mdev) {
	if( mdev->md_index == -1 ) {
		return ( (capacity(mdev->lo_device) & ~3L) -
			 MD_RESERVED_SIZE ) * 2;
	} else {
		return 2 * MD_RESERVED_SIZE * mdev->md_index;
	}
}

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

struct BitMap;

// TODO I'd like to change these all to take the mdev as first argument
extern struct BitMap* bm_init(unsigned long size_kb);
extern int bm_resize(struct BitMap* sbm, unsigned long size_kb);
extern void bm_cleanup(struct BitMap* sbm);
extern int bm_set_bit(drbd_dev *mdev, sector_t sector, int size, int bit);
extern sector_t bm_get_sector(struct BitMap* sbm,int* size);
extern void bm_reset(struct BitMap* sbm);
extern void bm_fill_bm(struct BitMap* sbm,int value);
extern int bm_get_bit(struct BitMap* sbm, sector_t sector, int size);
extern int bm_count_sectors(struct BitMap* sbm, unsigned long enr);
extern int bm_end_of_dev_case(struct BitMap* sbm);

extern void drbd_queue_signal(int signal,struct task_struct *task);

extern drbd_dev *drbd_conf;
extern int minor_count;
extern kmem_cache_t *drbd_request_cache;
extern kmem_cache_t *drbd_pr_cache;
extern kmem_cache_t *drbd_ee_cache;
extern mempool_t *drbd_request_mempool;
extern mempool_t *drbd_pr_mempool;

// drbd_req
#define ERF_NOTLD    2   /* do not call tl_dependence */
extern void drbd_end_req(drbd_request_t *, int, int, sector_t);
extern int drbd_make_request(request_queue_t *,int ,struct buffer_head *);

// drbd_fs.c
extern int drbd_determin_dev_size(drbd_dev*);
extern int drbd_set_state(drbd_dev *mdev,Drbd_State newstate);
extern int drbd_ioctl(struct inode *inode, struct file *file,
		      unsigned int cmd, unsigned long arg);

// drbd_dsender.c
extern int drbd_worker(struct Drbd_thread *thi);
extern void enslaved_read_bh_end_io(struct buffer_head *bh, int uptodate);
extern void drbd_start_resync(drbd_dev *mdev, Drbd_CState side);
// worker callbacks
extern int w_e_end_data_req      (drbd_dev *mdev, struct drbd_work*w);
extern int w_e_end_rsdata_req    (drbd_dev *mdev, struct drbd_work*w);
extern int w_resync_finished     (drbd_dev *mdev, struct drbd_work*w);
extern int w_resync_inactive     (drbd_dev *mdev, struct drbd_work*w);

// drbd_receiver.c
extern int drbd_release_ee(drbd_dev* mdev,struct list_head* list);
extern void drbd_init_ee(drbd_dev* mdev);
extern void drbd_put_ee(drbd_dev* mdev,struct Tl_epoch_entry *e);
extern struct Tl_epoch_entry* drbd_get_ee(drbd_dev* mdev);
extern int recv_resync_read(drbd_dev* mdev, struct Pending_read *pr,
			    sector_t sector, int data_size);
extern int recv_dless_read(drbd_dev* mdev, struct Pending_read *pr,
			   sector_t sector, int data_size);

// drbd_proc.c
extern struct proc_dir_entry *drbd_proc;
extern int drbd_proc_get_info(char *, char **, off_t, int, int *, void *);

// drbd_actlog.c
extern void drbd_al_begin_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_al_complete_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_rs_complete_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_rs_begin_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_al_read_log(struct Drbd_Conf *mdev);
extern void drbd_set_in_sync(drbd_dev* mdev, sector_t sector,int blk_size);
extern void drbd_read_bm(struct Drbd_Conf *mdev);
extern void drbd_al_apply_to_bm(struct Drbd_Conf *mdev);
extern void drbd_al_to_on_disk_bm(struct Drbd_Conf *mdev);
extern void drbd_write_bm(struct Drbd_Conf *mdev);

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
	unsigned long __ret = timeout;						\
	if (!(condition))						\
		__wait_event_interruptible_timeout(wq, condition, __ret); \
	__ret;								\
})
#endif

// the same, without timeout,
// but with run_task_queue(&tq_disk) just before the schedule()
// THINK whether we want to be interruptible or not
#define __wait_disk_event_interruptible(wq, condition)			\
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
			run_task_queue(&tq_disk);			\
			schedule();					\
			continue;					\
		}							\
		ret = -ERESTARTSYS;					\
		break;							\
	}								\
	current->state = TASK_RUNNING;					\
	remove_wait_queue(&wq, &__wait);				\
} while (0)

#define wait_disk_event_interruptible(wq, condition)			\
do {									\
	if (condition)							\
		break;							\
	__wait_disk_event_interruptible(wq, condition);			\
} while (0)


/*
 * inline helper functions
 *************************/

static inline void
__drbd_queue_work(drbd_dev *mdev, struct drbd_work_queue *q,
		  struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&mdev->req_lock,flags);
	list_add_tail(&w->list,&q->q);
	spin_unlock_irqrestore(&mdev->req_lock,flags);
	up(&q->s);
}

static inline void wake_asender(drbd_dev *mdev) {
	drbd_queue_signal(DRBD_SIG, mdev->asender.task);
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

static inline void inc_pending(drbd_dev* mdev)
{
	atomic_inc(&mdev->pending_cnt);
}

static inline void dec_pending(drbd_dev* mdev, const char* where)
{
	if(atomic_dec_and_test(&mdev->pending_cnt))
		wake_up_interruptible(&mdev->state_wait);

	if(atomic_read(&mdev->pending_cnt)<0) /* CHK */
		ERR("in %s: pending_cnt = %d < 0 !\n",
		    where,
		    atomic_read(&mdev->pending_cnt));
}

static inline void inc_unacked(drbd_dev* mdev)
{
	atomic_inc(&mdev->unacked_cnt);
}

static inline void dec_unacked(drbd_dev* mdev,const char* where)
{
	if(atomic_dec_and_test(&mdev->unacked_cnt))
		wake_up_interruptible(&mdev->state_wait);

	if(atomic_read(&mdev->unacked_cnt)<0)  /* CHK */
		ERR("in %s: unacked_cnt = %d < 0 !\n",
		    where,
		    atomic_read(&mdev->unacked_cnt));
}

static inline void drbd_set_out_of_sync(drbd_dev* mdev,
					sector_t sector, int blk_size)
{
	mdev->rs_total +=
		bm_set_bit(mdev, sector, blk_size, SS_OUT_OF_SYNC);
}

static inline void drbd_init_bh(struct buffer_head *bh,
				int size)
{
	memset(bh, 0, sizeof(struct buffer_head));

	bh->b_list = BUF_LOCKED;
	init_waitqueue_head(&bh->b_wait);
	bh->b_size = size;
	atomic_set(&bh->b_count, 1);
	bh->b_state = (1 << BH_Mapped ); //has a disk mapping = dev & blocknr
}


static inline void drbd_set_md_bh(drbd_dev *mdev,
				  struct buffer_head *bh,
				  sector_t sector,
				  int size)
{
	bh->b_blocknr = sector;  // We abuse b_blocknr here.
	bh->b_size = size;
	// bh->b_dev = 0xab00 | (int)(mdev-drbd_conf);  // DRBD's magic mark
	bh->b_private = mdev;

	// we skip submit_bh, but use generic_make_request.
	set_bit(BH_Req, &bh->b_state);
	set_bit(BH_Launder, &bh->b_state);
	bh->b_rdev = mdev->md_device;
	bh->b_rsector = sector;
}

static inline void drbd_set_bh(drbd_dev *mdev,
			       struct buffer_head *bh,
			       sector_t sector,
			       int size)
{
	bh->b_blocknr = sector;  // We abuse b_blocknr here.
	bh->b_size = size;
	// bh->b_dev = 0xab00 | (int)(mdev-drbd_conf);  // DRBD's magic mark
	bh->b_private = mdev;

	// we skip submit_bh, but use generic_make_request.
	set_bit(BH_Req, &bh->b_state);
	set_bit(BH_Launder, &bh->b_state);
	bh->b_rdev = mdev->lo_device;
	bh->b_rsector = sector;
}

#ifdef DBG_BH_SECTOR
static inline sector_t DRBD_BH_SECTOR(struct buffer_head *bh)
{
	if(!IS_VALID_MDEV(bh->b_private)) {
		printk(KERN_ERR DEVICE_NAME" !IS_VALID_MDEV(bh->b_private)\n");
	}
	return bh->b_blocknr;
}
static inline sector_t APP_BH_SECTOR(struct buffer_head *bh)
{
	if(IS_VALID_MDEV(bh->b_private)) {
		printk(KERN_ERR DEVICE_NAME" IS_VALID_MDEV(bh->b_private)\n");
	}
	return bh->b_blocknr * (bh->b_size>>9) ;
}
#else
# define DRBD_BH_SECTOR(BH) ( (BH)->b_blocknr )
# define APP_BH_SECTOR(BH)  ( (BH)->b_blocknr * ((BH)->b_size>>9) )
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
# if (BITS_PER_LONG > 32)
static inline unsigned long hweight64(__u64 w)
{
	u64 res;
        res = (w & 0x5555555555555555) + ((w >> 1) & 0x5555555555555555);
        res = (res & 0x3333333333333333) + ((res >> 2) & 0x3333333333333333);
        res = (res & 0x0F0F0F0F0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F0F0F0F0F);
        res = (res & 0x00FF00FF00FF00FF) + ((res >> 8) & 0x00FF00FF00FF00FF);
        res = (res & 0x0000FFFF0000FFFF) + ((res >> 16) & 0x0000FFFF0000FFFF);
        return (res & 0x00000000FFFFFFFF) + ((res >> 32) & 0x00000000FFFFFFFF);
}
#  define hweight_long(x) hweight64(x)
# else
#  define hweight_long(x) hweight32(x)
# endif
#endif
