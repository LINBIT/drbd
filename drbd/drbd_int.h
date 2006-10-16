/*
  drbd_int.h
  Kernel module for 2.4.x/2.6.x Kernels

  This file is part of drbd by Philipp Reisner.

  Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
  Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

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
#include "lru_cache.h"

// module parameter, defined in drbd_main.c
extern int minor_count;
extern int disable_bd_claim;
extern int major_nr;
extern int use_nbd_major;

#ifdef DRBD_ENABLE_FAULTS
extern int enable_faults;
extern int fault_rate;
#endif

#include <linux/major.h>
#ifdef DRBD_MAJOR
# warning "FIXME. DRBD_MAJOR is now officially defined in major.h"
#endif

#include <linux/blkdev.h>
#include <linux/bio.h>
#define MAJOR_NR major_nr

#undef DEVICE_NAME
#define DEVICE_NAME "drbd"

// XXX do we need this?
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

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

#define ID_SYNCER (-1ULL)
#define ID_VACANT 0     // All EEs on the free list should have this value
                        // freshly allocated EEs get !ID_VACANT (== 1)
			// so if it says "cannot dereference null
			// pointer at adress 0x00000001, it is most
			// probably one of these :(
#define is_syncer_block_id(id) ((id)==ID_SYNCER)

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
#define DUMPLU(A)  ERR( #A " = %lu in %s:%d\n", (unsigned long)(A),__FILE__,__LINE__);
#define DUMPLLU(A) ERR( #A " = %llu in %s:%d\n",(unsigned long long)(A),__FILE__,__LINE__);
#define DUMPLX(A)  ERR( #A " = %lx in %s:%d\n", (A),__FILE__,__LINE__);
#define DUMPI(A)   ERR( #A " = %d in %s:%d\n",  (int)(A),__FILE__,__LINE__);

#define DUMPST(A) DUMPLLU((unsigned long long)(A))

#if 0
#define D_DUMPP(A)   DUMPP(A)
#define D_DUMPLU(A)  DUMPLU(A)
#define D_DUMPLLU(A) DUMPLLU(A)
#define D_DUMPLX(A)  DUMPLX(A)
#define D_DUMPI(A)   DUMPI(A)
#else
#define D_DUMPP(A)
#define D_DUMPLU(A)
#define D_DUMPLLU(A)
#define D_DUMPLX(A)
#define D_DUMPI(A)
#endif

// Info: do not remove the spaces around the "," before ##
//       Otherwise this is not portable from gcc-2.95 to gcc-3.3
#define PRINTK(level,fmt,args...) \
	printk(level DEVICE_NAME "%d: " fmt, \
		mdev->minor , ##args)

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

// Defines to control fault insertion
enum {
    DRBD_FAULT_MD_WR = 0,
    DRBD_FAULT_MD_RD,
    DRBD_FAULT_RS_WR,
    DRBD_FAULT_RS_RD,
    DRBD_FAULT_DT_WR,
    DRBD_FAULT_DT_RD,

    DRBD_FAULT_MAX,
};

#ifdef DRBD_ENABLE_FAULTS
#define FAULT_ACTIVE(_t) \
    (fault_rate && (enable_faults & (1<<(_t))) && _drbd_insert_fault(_t))

extern unsigned int _drbd_insert_fault(unsigned int type);
#else
#define FAULT_ACTIVE(_t) (0)
#endif

#include <linux/stringify.h>
// integer division, round _UP_ to the next integer
#define div_ceil(A,B) ( (A)/(B) + ((A)%(B) ? 1 : 0) )
// usual integer division
#define div_floor(A,B) ( (A)/(B) )

/*
 * Compatibility Section
 *************************/

#define LOCK_SIGMASK(task,flags)   spin_lock_irqsave(&task->sighand->siglock, flags)
#define UNLOCK_SIGMASK(task,flags) spin_unlock_irqrestore(&task->sighand->siglock, flags)
#define RECALC_SIGPENDING()        recalc_sigpending();

#if defined(DBG_SPINLOCKS) && defined(__SMP__)
# define MUST_HOLD(lock) if(!spin_is_locked(lock)) { ERR("Not holding lock! in %s\n", __FUNCTION__ ); }
#else
# define MUST_HOLD(lock)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
# define HAVE_KERNEL_SENDMSG 1
#else
# define HAVE_KERNEL_SENDMSG 0
#endif


/*
 * our structs
 *************************/

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct Drbd_Conf*,x); \
	  (x)->magic = (long)(x) ^ DRBD_MAGIC; })
#define IS_VALID_MDEV(x)  \
	( typecheck(struct Drbd_Conf*,x) && \
	  ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)):0))

/* drbd_meta-data.c (still in drbd_main.c) */
#define DRBD_MD_MAGIC (DRBD_MAGIC+4) // 4th incarnation of the disk layout.

extern struct Drbd_Conf **minor_table;

/***
 * on the wire
 *********************************************************************/

typedef enum {
	Data,
	DataReply,     // Response to DataRequest
	RSDataReply,   // Response to RSDataRequest
	Barrier,
	ReportBitMap,
	BecomeSyncTarget,
	BecomeSyncSource,
	UnplugRemote,  // Used at various times to hint the peer to hurry up
	DataRequest,   // Used to ask for a data block
	RSDataRequest, // Used to ask for a data block
	SyncParam,
	ReportProtocol,
	ReportUUIDs,
	ReportSizes,
	ReportState,
	ReportSyncUUID,
	AuthChallenge,
	AuthResponse,
	StateChgRequest,

	Ping,         // These are sent on the meta socket...
	PingAck,
	RecvAck,      // Used in protocol B
	WriteAck,     // Used in protocol C
	NegAck,       // Sent if local disk is unusable
	NegDReply,    // Local disk is broken...
	NegRSDReply,  // Local disk is broken...
	BarrierAck,
	DiscardNote,
	StateChgReply,

	MAX_CMD,
	MayIgnore = 0x100, // Flag only to test if (cmd > MayIgnore) ...
	MAX_OPT_CMD,

	HandShakeM = 0xfff1, // First Packet on the MetaSock
	HandShakeS = 0xfff2, // First Packet on the Socket
	HandShake  = 0xfffe  // FIXED for the next century!
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
		[ReportBitMap]     = "ReportBitMap",
		[BecomeSyncTarget] = "BecomeSyncTarget",
		[BecomeSyncSource] = "BecomeSyncSource",
		[UnplugRemote]     = "UnplugRemote",
		[DataRequest]      = "DataRequest",
		[RSDataRequest]    = "RSDataRequest",
		[SyncParam]        = "SyncParam",
		[ReportProtocol]   = "ReportProtocol",
		[ReportUUIDs]      = "ReportUUIDs",
		[ReportSizes]      = "ReportSizes",
		[ReportState]      = "ReportState",
		[ReportSyncUUID]   = "ReportSyncUUID",
		[AuthChallenge]    = "AuthChallenge",
		[AuthResponse]     = "AuthResponse",
		[Ping]             = "Ping",
		[PingAck]          = "PingAck",
		[RecvAck]          = "RecvAck",
		[WriteAck]         = "WriteAck",
		[NegAck]           = "NegAck",
		[NegDReply]        = "NegDReply",
		[NegRSDReply]      = "NegRSDReply",
		[BarrierAck]       = "BarrierAck",
		[DiscardNote]      = "DiscardNote",
		[StateChgRequest]  = "StateChgRequest",
		[StateChgReply]    = "StateChgReply"
	};

	if (Data > cmd || cmd >= MAX_CMD) {
	    switch (cmd) {
	    case HandShakeM:
		return "HandShakeM";
		break;
	    case HandShakeS:
		return "HandShakeS";
		break;
	    case HandShake:
		return "HandShake";
		break;
	    default:
		return "Unknown";
		break;
	    }
	}
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

#define DP_HARDBARRIER 1
/* FIXME map BIO_RW_SYNC, too ... */

typedef struct {
	Drbd_Header head;
	u64         sector;    // 64 bits sector number
	u64         block_id;  // Used in protocol B&C for the address of the req.
	u32         seq_num;
	u32         dp_flags;
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
	u32         seq_num;
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

/* FIXME do we actually send a barrier packet with "0" as barrier number?
 * what for?
 * couldn't we send the pointer as handle as well, as we do with block_id?
 */
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
} __attribute((packed)) Drbd_SyncParam_Packet;

typedef struct {
	Drbd_Header head;
	u32         protocol;
} __attribute((packed)) Drbd_Protocol_Packet;

typedef struct {
	Drbd_Header head;
	u64         uuid[EXT_UUID_SIZE];
} __attribute((packed)) Drbd_GenCnt_Packet;

typedef struct {
	Drbd_Header head;
	u64         uuid;
} __attribute((packed)) Drbd_SyncUUID_Packet;

typedef struct {
	Drbd_Header head;
	u64         d_size;  // size of disk
	u64         u_size;  // user requested size
	u64         c_size;  // current exported size
	u32         max_segment_size;  // Maximal size of a BIO
	u32         queue_order_type;
} __attribute((packed)) Drbd_Sizes_Packet;

typedef struct {
	Drbd_Header head;
	u32         state;
} __attribute((packed)) Drbd_State_Packet;

typedef struct {
	Drbd_Header head;
	u32         mask;
	u32         val;
} __attribute((packed)) Drbd_Req_State_Packet;

typedef struct {
	Drbd_Header head;
	u32         retcode;
} __attribute((packed)) Drbd_RqS_Reply_Packet;

typedef struct {
	u64       size;
	u32       state;
	u32       blksize;
	u32       protocol;
	u32       version;
	u32       gen_cnt[5];
	u32       bit_map_gen[5];
} __attribute((packed)) Drbd06_Parameter_P;

typedef struct {
	Drbd_Header head;
	u64         block_id;
	u32         seq_num;
	u32         pad;
} __attribute((packed)) Drbd_Discard_Packet;

typedef union {
	Drbd_Header              head;
	Drbd_HandShake_Packet    HandShake;
	Drbd_Data_Packet         Data;
	Drbd_BlockAck_Packet     BlockAck;
	Drbd_Barrier_Packet      Barrier;
	Drbd_BarrierAck_Packet   BarrierAck;
	Drbd_SyncParam_Packet    SyncParam;
	Drbd_Protocol_Packet     Protocol;
	Drbd_Sizes_Packet        Sizes;
	Drbd_GenCnt_Packet       GenCnt;
	Drbd_State_Packet        State;
	Drbd_Req_State_Packet	 ReqState;
	Drbd_RqS_Reply_Packet	 RqSReply;
	Drbd_BlockRequest_Packet BlockRequest;
	Drbd_Discard_Packet	 Discard;
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

struct drbd_barrier;
struct drbd_request {
	struct drbd_work w;
	drbd_dev *mdev;
	struct bio *private_bio;
	struct hlist_node colision;
	sector_t sector;
	unsigned int size;
	unsigned int epoch; /* barrier_nr */

	/* barrier_nr: used to check on "completion" whether this req was in
	 * the current epoch, and we therefore have to close it,
	 * starting a new epoch...
	 */

	/* up to here, the struct layout is identical to Tl_epoch_entry;
	 * we might be able to use that to our advantage...  */

	struct list_head tl_requests; /* ring list in the transfer log */
	struct bio *master_bio;       /* master bio pointer */
	unsigned long rq_state; /* see comments above _req_mod() */
	int seq_num;
};

struct drbd_barrier {
	struct drbd_work w;
	struct list_head requests; // requests before
	struct drbd_barrier *next; // pointer to the next barrier
	unsigned int br_number;  // the barriers identifier.
	int n_req;      // number of requests attached before this barrier
};

typedef struct drbd_request drbd_request_t;

/* These Tl_epoch_entries may be in one of 6 lists:
   active_ee .. data packet being written
   sync_ee   .. syncer block being written
   done_ee   .. block written, need to send WriteAck
   read_ee   .. [RS]DataRequest being read
*/

struct Tl_epoch_entry {
	struct drbd_work    w;
	drbd_dev *mdev;
	struct bio *private_bio;
	struct hlist_node colision;
	sector_t sector;
	unsigned int size;
	unsigned int barrier_nr;

	/* up to here, the struct layout is identical to drbd_request;
	 * we might be able to use that to our advantage...  */

	unsigned int barrier_nr2;
	/* If we issue the bio with BIO_RW_BARRIER we have to
	   send a barrier ACK before we send the ACK to this
	   write. We store the barrier number in here.
	   In case the barrier after this write has been coalesced
	   as well, we set it's barrier_nr into barrier_nr2 */

	unsigned int flags;
	u64    block_id;
};

/* ee flag bits */
enum {
	__CALL_AL_COMPLETE_IO,
};
#define CALL_AL_COMPLETE_IO (1<<__CALL_AL_COMPLETE_IO)


/* global flag bits */
enum {
	ISSUE_BARRIER,		// next Data is preceeded by a Barrier
	SIGNAL_ASENDER,		// whether asender wants to be interrupted
	SEND_PING,		// whether asender should send a ping asap
	WRITE_ACK_PENDING,	// so BarrierAck won't overtake WriteAck
	WORK_PENDING,		// completion flag for drbd_disconnect
	WRITER_PRESENT,		// somebody opened us with write intent
	STOP_SYNC_TIMER,	// tell timer to cancel itself
	UNPLUG_QUEUED,		// only relevant with kernel 2.4
	UNPLUG_REMOTE,		// whether sending a "UnplugRemote" makes sense
	MD_DIRTY,		// current gen counts and flags not yet on disk
	SYNC_STARTED,		// Needed to agree on the exact point in time..
	UNIQUE,                 // Set on one node, cleared on the peer!
	USE_DEGR_WFC_T,		// Use degr-wfc-timeout instead of wfc-timeout.
	CLUSTER_ST_CHANGE,      // Cluster wide state change going on...
	CL_ST_CHG_SUCCESS,
	CL_ST_CHG_FAIL,
	CRASHED_PRIMARY,	// This node was a crashed primary
	WRITE_BM_AFTER_RESYNC	// A kmalloc() during resync failed
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
	spinlock_t q_lock;  // to protect the list.
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

struct drbd_discard_note {
	struct list_head list;
	u64 block_id;
	int seq_num;
};

struct drbd_md {
	u64 md_offset;		/* sector offset to 'super' block */

	u64 la_size_sect;	/* last agreed size, unit sectors */
	u64 uuid[UUID_SIZE];
	u64 device_uuid;
	u32 flags;
	u32 md_size_sect;

	s32 al_offset;	/* signed relative sector offset to al area */
	s32 bm_offset;	/* signed relative sector offset to bitmap */

	/* u32 al_nr_extents;	   important for restoring the AL
	 * is stored into  sync_conf.al_extents, which in turn
	 * gets applied to act_log->nr_elements
	 */
};

// for sync_conf and other types...
#define PACKET(name, number, fields) struct name { fields };
#define INTEGER(pn,pr,member) int member;
#define INT64(pn,pr,member) __u64 member;
#define BIT(pn,pr,member)   unsigned member : 1;
#define STRING(pn,pr,member,len) unsigned char member[len]; int member ## _len;
#include "linux/drbd_nl.h"

struct drbd_backing_dev {
	struct block_device *backing_bdev;
	struct block_device *md_bdev;
	struct file *lo_file;
	struct file *md_file;
	struct drbd_md md;
	struct disk_conf dc; /* The user provided config... */
	merge_bvec_fn *bmbf; /* short cut to backing devices' merge_bvec_fn */
};

struct Drbd_Conf {
#ifdef PARANOIA
	long magic;
#endif
	/* things that are stored as / read from meta data on disk */
	unsigned long flags;

	/* configured by drbdsetup */
	struct net_conf *net_conf; // protected by inc_net() and dec_net()
	struct syncer_conf sync_conf;
	struct drbd_backing_dev *bc; // protected by inc_local() dec_local()

	sector_t p_size;     /* partner's disk size */
	request_queue_t     *rq_queue;
	struct block_device *this_bdev;
	struct gendisk      *vdisk;

	struct drbd_socket data; // for data/barrier/cstate/parameter packets
	struct drbd_socket meta; // for ping/ack (metadata) packets
	volatile unsigned long last_received; // in jiffies, either socket
	volatile unsigned int ko_count;
	struct drbd_work  resync_work,
			  unplug_work,
	                  md_sync_work;
	struct timer_list resync_timer;
	struct timer_list md_sync_timer;

	drbd_state_t new_state_tmp; // Used after attach while negotiating new disk state.
	drbd_state_t state;
	wait_queue_head_t cstate_wait; // TODO Rename into "misc_wait".
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
	atomic_t net_cnt;        // Users of net_conf
	spinlock_t req_lock;
	struct drbd_barrier* unused_spare_barrier; /* for pre-allocation */
	struct drbd_barrier* newest_barrier;
	struct drbd_barrier* oldest_barrier;
	struct hlist_head * tl_hash;
	unsigned int tl_hash_s;
	// sector_t rs_left;	   // blocks not up-to-date [unit BM_BLOCK_SIZE]
	// moved into bitmap->bm_set
	unsigned long rs_total;    // blocks to sync in this run [unit BM_BLOCK_SIZE]
	unsigned long rs_failed;   // number of sync IOs that failed in this run
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
	u64 *p_uuid;
	/* no more ee_lock
	 * we had to grab both req_lock _and_ ee_lock in almost every place we
	 * needed one of them. so why bother having too spinlocks?
	 * FIXME clean comments, restructure so it is more obvious which
	 * members areprotected by what */
	unsigned int epoch_size;
	struct list_head active_ee; // IO in progress
	struct list_head sync_ee;   // IO in progress
	struct list_head done_ee;   // send ack
	struct list_head read_ee;   // IO in progress
	struct list_head net_ee;    // zero-copy network send in progress
	struct hlist_head * ee_hash; // is proteced by req_lock!
	unsigned int ee_hash_s;
	struct Tl_epoch_entry * last_write_w_barrier; // ee_lock, single thread
	int next_barrier_nr;  // ee_lock, single thread
	struct hlist_head * app_reads_hash; // is proteced by req_lock
	struct list_head resync_reads;
	atomic_t pp_in_use;
	wait_queue_head_t ee_wait;
	struct page *md_io_page;      // one page buffer for md_io
	struct page *md_io_tmpp;     // in case hardsect != 512 [ s390 only? ]
	struct semaphore md_io_mutex; // protects the md_io_buffer
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache* act_log;     // activity log
	unsigned int al_tr_number;
	int al_tr_cycle;
	int al_tr_pos;     // position of the next transaction in the journal
	struct crypto_tfm* cram_hmac_tfm;
	atomic_t packet_seq;
	int peer_seq;
	spinlock_t peer_seq_lock;
	struct list_head discard;
	int minor;
};

static inline drbd_dev *minor_to_mdev(int minor)
{
	drbd_dev *mdev;

	mdev = minor < minor_count ? minor_table[minor] : NULL;

	return mdev;
}

static inline int mdev_to_minor(drbd_dev *mdev)
{
	return mdev->minor;
}

/* returns 1 if it was successfull,
 * returns 0 if there was no data socket.
 * so wherever you are going to use the data.socket, e.g. do
 * if (!drbd_get_data_sock(mdev))
 *	return 0;
 *	CODE();
 * drbd_put_data_sock(mdev);
 */
static inline int drbd_get_data_sock(drbd_dev *mdev)
{
	down(&mdev->data.mutex);
	/* drbd_disconnect() could have called drbd_free_sock()
	 * while we were waiting in down()... */
	if (unlikely(mdev->data.socket == NULL)) {
		up(&mdev->data.mutex);
		return 0;
	}
	return 1;
}

static inline void drbd_put_data_sock(drbd_dev *mdev)
{
	up(&mdev->data.mutex);
}


/*
 * function declarations
 *************************/

// drbd_main.c

enum chg_state_flags {
	ChgStateHard    = 1,
	ChgStateVerbose = 2,
	ScheduleAfter   = 4,
};

extern int drbd_change_state(drbd_dev* mdev, enum chg_state_flags f,
			     drbd_state_t mask, drbd_state_t val);
extern void drbd_force_state(drbd_dev*, drbd_state_t, drbd_state_t);
extern int _drbd_request_state(drbd_dev*, drbd_state_t, drbd_state_t, 
			       enum chg_state_flags);
extern int _drbd_set_state(drbd_dev*, drbd_state_t, enum chg_state_flags );
extern void print_st_err(drbd_dev*, drbd_state_t, drbd_state_t, int );
extern void after_state_ch(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns,
			   enum chg_state_flags);
extern int  drbd_thread_start(struct Drbd_thread *thi);
extern void _drbd_thread_stop(struct Drbd_thread *thi, int restart, int wait);
extern void drbd_free_resources(drbd_dev *mdev);
extern void tl_release(drbd_dev *mdev,unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(drbd_dev *mdev);
extern struct drbd_barrier *_tl_add_barrier(drbd_dev *,struct drbd_barrier *);
extern void drbd_free_sock(drbd_dev *mdev);
extern int drbd_send(drbd_dev *mdev, struct socket *sock,
		     void* buf, size_t size, unsigned msg_flags);
extern int drbd_send_protocol(drbd_dev *mdev);
extern int drbd_send_uuids(drbd_dev *mdev);
extern int drbd_send_sync_uuid(drbd_dev *mdev, u64 val);
extern int drbd_send_sizes(drbd_dev *mdev);
extern int drbd_send_state(drbd_dev *mdev);
extern int _drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h,
			  size_t size, unsigned msg_flags);
#define USE_DATA_SOCKET 1
#define USE_META_SOCKET 0
extern int drbd_send_cmd(drbd_dev *mdev, int use_data_socket,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h, size_t size);
extern int drbd_send_cmd2(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			  char* data, size_t size);
extern int drbd_send_sync_param(drbd_dev *mdev, struct syncer_conf *sc);
extern int drbd_send_b_ack(drbd_dev *mdev, u32 barrier_nr,
			   u32 set_size);
extern int drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			 struct Tl_epoch_entry *e);
extern int drbd_send_ack_rp(drbd_dev *mdev, Drbd_Packet_Cmd cmd, 
			    Drbd_BlockRequest_Packet *rp);
extern int drbd_send_ack_dp(drbd_dev *mdev, Drbd_Packet_Cmd cmd, 
			    Drbd_Data_Packet *dp);
extern int _drbd_send_page(drbd_dev *mdev, struct page *page,
			   int offset, size_t size);
extern int drbd_send_block(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			   struct Tl_epoch_entry *e);
extern int drbd_send_dblock(drbd_dev *mdev, drbd_request_t *req);
extern int _drbd_send_barrier(drbd_dev *mdev, struct drbd_barrier *barrier);
extern int drbd_send_drequest(drbd_dev *mdev, int cmd,
			      sector_t sector,int size, u64 block_id);
extern int drbd_send_bitmap(drbd_dev *mdev);
extern int _drbd_send_bitmap(drbd_dev *mdev);
extern int drbd_send_discard(drbd_dev *mdev, drbd_request_t *req);
extern int drbd_send_sr_reply(drbd_dev *mdev, int retcode);
extern void drbd_free_bc(struct drbd_backing_dev* bc);
extern int drbd_io_error(drbd_dev* mdev, int forcedetach);
extern void drbd_mdev_cleanup(drbd_dev *mdev);

// drbd_meta-data.c (still in drbd_main.c)
extern void drbd_md_sync(drbd_dev *mdev);
extern int  drbd_md_read(drbd_dev *mdev, struct drbd_backing_dev * bdev);
// maybe define them below as inline?
extern void drbd_uuid_set(drbd_dev *mdev,int idx, u64 val);
extern void _drbd_uuid_set(drbd_dev *mdev, int idx, u64 val);
extern void drbd_uuid_new_current(drbd_dev *mdev);
extern void drbd_uuid_set_bm(drbd_dev *mdev, u64 val);
extern void drbd_md_set_flag(drbd_dev *mdev, int flags);
extern void drbd_md_clear_flag(drbd_dev *mdev, int flags);
extern int drbd_md_test_flag(struct drbd_backing_dev *, int);
extern void drbd_md_mark_dirty(drbd_dev *mdev);

/* Meta data layout
   We reserve a 128MB Block (4k aligned)
   * either at the end of the backing device
   * or on a seperate meta data device. */

#define MD_RESERVED_SECT ( 128LU << 11 )  // 128 MB, unit sectors
// The following numbers are sectors
#define MD_AL_OFFSET 8      // 8 Sectors after start of meta area
#define MD_AL_MAX_SIZE 64   // = 32 kb LOG  ~ 3776 extents ~ 14 GB Storage
#define MD_BM_OFFSET (MD_AL_OFFSET + MD_AL_MAX_SIZE) //Allows up to about 3.8TB

#define MD_HARDSECT_B    9     // Since the smalles IO unit is usually 512 byte
#define MD_HARDSECT      (1<<MD_HARDSECT_B)

// activity log
#define AL_EXTENTS_PT    ((MD_HARDSECT-12)/8-1) // 61 ; Extents per 512B sector
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
	int rs_failed; // number of failed resync requests in this extent.
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

#if (BM_EXT_SIZE_B != 24) || (BM_BLOCK_SIZE_B != 12)
#error "HAVE YOU FIXED drbdmeta AS WELL??"
#endif

/* thus many _storage_ sectors are described by one bit */
#define BM_SECT_TO_BIT(x)   ((x)>>(BM_BLOCK_SIZE_B-9))
#define BM_BIT_TO_SECT(x)   ((sector_t)(x)<<(BM_BLOCK_SIZE_B-9))
#define BM_SECT_PER_BIT     BM_BIT_TO_SECT(1)

/* bit to represented kilo byte conversion */
#define Bit2KB(bits) ((bits)<<(BM_BLOCK_SIZE_B-10))

/* in which _bitmap_ extent (resp. sector) the bit for a certain
 * _storage_ sector is located in */
#define BM_SECT_TO_EXT(x)   ((x)>>(BM_EXT_SIZE_B-9))

/* who much _storage_ sectors we have per bitmap sector */
#define BM_SECT_PER_EXT     (1ULL << (BM_EXT_SIZE_B-9))

/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SIZE_B - AL_EXTENT_SIZE_B) )
#define BM_WORDS_PER_AL_EXT (1 << (AL_EXTENT_SIZE_B-BM_BLOCK_SIZE_B-LN2_BPL))


#define BM_BLOCKS_PER_BM_EXT_B ( BM_EXT_SIZE_B - BM_BLOCK_SIZE_B )
#define BM_BLOCKS_PER_BM_EXT_MASK  ( (1<<BM_BLOCKS_PER_BM_EXT_B) - 1 )

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

#define DRBD_MAX_SECTORS_32 (0xffffffffLU)
#define DRBD_MAX_SECTORS_BM \
          ( (MD_RESERVED_SECT - MD_BM_OFFSET) * (1LL<<(BM_EXT_SIZE_B-9)) )
#if DRBD_MAX_SECTORS_BM < DRBD_MAX_SECTORS_32
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_BM
#define DRBD_MAX_SECTORS_FLEX DRBD_MAX_SECTORS_BM
#elif ( !defined(CONFIG_LBD) ) && ( BITS_PER_LONG == 32 )
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_32
#define DRBD_MAX_SECTORS_FLEX DRBD_MAX_SECTORS_32
#else
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_BM
/* 16 TB in units of sectors */
#define DRBD_MAX_SECTORS_FLEX (1ULL<<(32+BM_BLOCK_SIZE_B-9))
#endif

/* Sector shift value for the "hash" functions of tl_hash and ee_hash tables.
 * With a value of 6 all IO in one 32K block make it to the same slot of the
 * hash table. */
#define HT_SHIFT 6
#define DRBD_MAX_SEGMENT_SIZE (1U<<(9+HT_SHIFT))

/* Number of elements in the app_reads_hash */
#define APP_R_HSIZE 15

extern int  drbd_bm_init      (drbd_dev *mdev);
extern int  drbd_bm_resize    (drbd_dev *mdev, sector_t sectors);
extern void drbd_bm_cleanup   (drbd_dev *mdev);
extern void drbd_bm_set_all   (drbd_dev *mdev);
extern void drbd_bm_clear_all (drbd_dev *mdev);
extern void drbd_bm_reset_find(drbd_dev *mdev);
extern int  drbd_bm_set_bit   (drbd_dev *mdev, unsigned long bitnr);
extern int  drbd_bm_set_bits_in_irq(
		drbd_dev *mdev, unsigned long s, unsigned long e);
extern int  drbd_bm_test_bit  (drbd_dev *mdev, unsigned long bitnr);
extern int  drbd_bm_clear_bit (drbd_dev *mdev, unsigned long bitnr);
extern int  drbd_bm_e_weight  (drbd_dev *mdev, unsigned long enr);
extern int  drbd_bm_read_sect (drbd_dev *mdev, unsigned long enr);
extern int  drbd_bm_write_sect(drbd_dev *mdev, unsigned long enr);
extern int  drbd_bm_read      (drbd_dev *mdev);
extern int  drbd_bm_write     (drbd_dev *mdev);
extern unsigned long drbd_bm_ALe_set_all (drbd_dev *mdev, unsigned long al_enr);
extern size_t        drbd_bm_words       (drbd_dev *mdev);
extern sector_t      drbd_bm_capacity    (drbd_dev *mdev);
extern unsigned long drbd_bm_find_next   (drbd_dev *mdev);
extern void drbd_bm_set_find(drbd_dev *mdev, unsigned long i);
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
extern int minor_count;
extern kmem_cache_t *drbd_request_cache;
extern kmem_cache_t *drbd_ee_cache;
extern mempool_t *drbd_request_mempool;
extern mempool_t *drbd_ee_mempool;

extern struct page* drbd_pp_pool; // drbd's page pool
extern spinlock_t   drbd_pp_lock;
extern int          drbd_pp_vacant;
extern wait_queue_head_t drbd_pp_wait;

extern drbd_dev *drbd_new_device(int minor);

// Dynamic tracing framework
#ifdef ENABLE_DYNAMIC_TRACE

extern int trace_type;
extern int trace_devs;
extern int trace_level;

enum {
	TraceLvlAlways = 0,
	TraceLvlSummary,
	TraceLvlMetrics,
	TraceLvlAll,
	TraceLvlMax
};

enum {
	TraceTypePacket = 0x00000001,
	TraceTypeRq     = 0x00000002,
	TraceTypeUuid	= 0x00000004,
	TraceTypeResync = 0x00000008,
	TraceTypeEE     = 0x00000010,
	TraceTypeUnplug = 0x00000020,
};

static inline int
is_trace(unsigned int type, unsigned int level) {
	return ((trace_level >= level) && (type & trace_type));
}
static inline int
is_mdev_trace(drbd_dev *mdev, unsigned int type, unsigned int level) {
	return (is_trace(type, level) && 
		( ( 1 << mdev_to_minor(mdev)) & trace_devs));
}

#define MTRACE(type,lvl,code...) \
do { \
	if (unlikely(is_mdev_trace(mdev,type,lvl))) { \
		code \
	} \
} while (0)

#define TRACE(type,lvl,code...) \
do { \
	if (unlikely(is_trace(type,lvl))) { \
		code \
	} \
} while (0)

// Buffer printing support
// DbgPrintFlags: used for Flags arg to DbgPrintBuffer
// - DBGPRINT_BUFFADDR; if set, each line starts with the
//       virtual address of the line being output. If clear,
//       each line starts with the offset from the beginning
//       of the buffer.
typedef enum {
    DBGPRINT_BUFFADDR = 0x0001,
}  DbgPrintFlags;

extern void drbd_print_uuid(drbd_dev *mdev, unsigned int idx);

extern void drbd_print_buffer(const char *prefix,unsigned int flags,int size,
			      const void *buffer,const void *buffer_va,
			      unsigned int length);

// Bio printing support
extern void _dump_bio(drbd_dev *mdev, struct bio *bio, int complete);

static inline void dump_bio(drbd_dev *mdev, struct bio *bio, int complete) {
	MTRACE(TraceTypeRq,TraceLvlSummary,
	       _dump_bio(mdev, bio, complete);
		);
}

// Packet dumping support
extern void _dump_packet(drbd_dev *mdev, struct socket *sock,
			 int recv, Drbd_Polymorph_Packet *p, char* file, int line);

static inline void
dump_packet(drbd_dev *mdev, struct socket *sock,
	    int recv, Drbd_Polymorph_Packet *p, char* file, int line)
{
	MTRACE(TraceTypePacket, TraceLvlSummary,
	       _dump_packet(mdev,sock,recv,p,file,line);
		);
}

#else

#define MTRACE(ignored...) ((void)0)
#define TRACE(ignored...) ((void)0)

#define dump_bio(ignored...) ((void)0)
#define dump_packet(ignored...) ((void)0)
#endif

// drbd_req
extern int drbd_make_request_26(request_queue_t *q, struct bio *bio);
extern int drbd_read_remote(drbd_dev *mdev, drbd_request_t *req);
extern int drbd_merge_bvec(request_queue_t *, struct bio *, struct bio_vec *);
extern int is_valid_ar_handle(drbd_request_t *, sector_t);


// drbd_nl.c
extern char* ppsize(char* buf, size_t size);
extern sector_t drbd_new_dev_size(struct Drbd_Conf*, struct drbd_backing_dev*);
extern int drbd_determin_dev_size(drbd_dev*);
extern void drbd_setup_queue_param(drbd_dev *mdev, unsigned int);
extern int drbd_set_role(drbd_dev *mdev, drbd_role_t new_role, int force);
extern int drbd_ioctl(struct inode *inode, struct file *file,
		      unsigned int cmd, unsigned long arg);
drbd_disks_t drbd_try_outdate_peer(drbd_dev *mdev);
extern long drbd_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg);
extern int drbd_khelper(drbd_dev *mdev, char* cmd);

// drbd_worker.c
extern int drbd_worker(struct Drbd_thread *thi);
extern void drbd_alter_sa(drbd_dev *mdev, int na);
extern void drbd_start_resync(drbd_dev *mdev, drbd_conns_t side);
extern void resume_next_sg(drbd_dev* mdev);
extern void suspend_other_sg(drbd_dev* mdev);
extern int drbd_resync_finished(drbd_dev *mdev);
// maybe rather drbd_main.c ?
extern int drbd_md_sync_page_io(drbd_dev *mdev, struct drbd_backing_dev *bdev,
				sector_t sector, int rw);
// worker callbacks
extern int w_req_cancel_conflict (drbd_dev *, struct drbd_work *, int);
extern int w_read_retry_remote   (drbd_dev *, struct drbd_work *, int);
extern int w_e_end_data_req      (drbd_dev *, struct drbd_work *, int);
extern int w_e_end_rsdata_req    (drbd_dev *, struct drbd_work *, int);
extern int w_resync_inactive     (drbd_dev *, struct drbd_work *, int);
extern int w_resume_next_sg      (drbd_dev *, struct drbd_work *, int);
extern int w_io_error            (drbd_dev *, struct drbd_work *, int);
extern int w_send_write_hint     (drbd_dev *, struct drbd_work *, int);
extern int w_make_resync_request (drbd_dev *, struct drbd_work *, int);
extern int w_send_dblock         (drbd_dev *, struct drbd_work *, int);
extern int w_send_barrier        (drbd_dev *, struct drbd_work *, int);
extern int w_send_read_req       (drbd_dev *, struct drbd_work *, int);
extern int w_prev_work_done      (drbd_dev *, struct drbd_work *, int);

extern void resync_timer_fn(unsigned long data);

// drbd_receiver.c
extern int drbd_release_ee(drbd_dev* mdev,struct list_head* list);
extern struct Tl_epoch_entry* drbd_alloc_ee(drbd_dev *mdev,
					    u64 id,
					    sector_t sector,
					    unsigned int data_size,
					    unsigned int gfp_mask);
extern void drbd_free_ee(drbd_dev *mdev, struct Tl_epoch_entry* e);
extern void drbd_wait_ee_list_empty(drbd_dev *mdev, struct list_head *head);
extern void _drbd_wait_ee_list_empty(drbd_dev *mdev, struct list_head *head);
extern void drbd_set_recv_tcq(drbd_dev *mdev, int tcq_enabled);
extern void _drbd_clear_done_ee(drbd_dev *mdev);

// drbd_proc.c
extern struct proc_dir_entry *drbd_proc;
extern struct file_operations drbd_proc_fops;
extern const char* conns_to_name(drbd_conns_t s);
extern const char* roles_to_name(drbd_role_t s);

// drbd_actlog.c
extern void drbd_al_begin_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_al_complete_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_rs_complete_io(struct Drbd_Conf *mdev, sector_t sector);
extern int drbd_rs_begin_io(struct Drbd_Conf *mdev, sector_t sector);
extern void drbd_rs_cancel_all(drbd_dev* mdev);
extern void drbd_rs_del_all(drbd_dev* mdev);
extern void drbd_rs_failed_io(drbd_dev* mdev, sector_t sector, int size);
extern int drbd_al_read_log(struct Drbd_Conf *mdev,struct drbd_backing_dev *);
extern void __drbd_set_in_sync(drbd_dev* mdev, sector_t sector, int size, const char* file, const unsigned int line);
#define drbd_set_in_sync(mdev,sector,size) \
	__drbd_set_in_sync(mdev,sector,size, __FILE__, __LINE__ )
extern void __drbd_set_out_of_sync(drbd_dev* mdev, sector_t sector, int size, const char* file, const unsigned int line);
#define drbd_set_out_of_sync(mdev,sector,size) \
	__drbd_set_out_of_sync(mdev,sector,size, __FILE__, __LINE__ )
extern void drbd_al_apply_to_bm(struct Drbd_Conf *mdev);
extern void drbd_al_to_on_disk_bm(struct Drbd_Conf *mdev);
extern void drbd_al_shrink(struct Drbd_Conf *mdev);


// drbd_nl.c

void drbd_nl_cleanup(void);
int __init drbd_nl_init(void);
void drbd_bcast_state(drbd_dev *mdev);

/*
 * inline helper functions
 *************************/

#include "drbd_compat_wrappers.h"

#define peer_mask role_mask
#define pdsk_mask disk_mask
#define susp_mask 1
#define user_isp_mask 1
#define aftr_isp_mask 1

#define NS(T,S) ({drbd_state_t mask; mask.i=0; mask.T = T##_mask; mask;}), \
                ({drbd_state_t val; val.i=0; val.T = (S); val;})
#define NS2(T1,S1,T2,S2) \
                ({drbd_state_t mask; mask.i=0; mask.T1 = T1##_mask; \
		  mask.T2 = T2##_mask; mask;}), \
                ({drbd_state_t val; val.i=0; val.T1 = (S1); \
                  val.T2 = (S2); val;})
#define NS3(T1,S1,T2,S2,T3,S3) \
                ({drbd_state_t mask; mask.i=0; mask.T1 = T1##_mask; \
		  mask.T2 = T2##_mask; mask.T3 = T3##_mask; mask;}), \
                ({drbd_state_t val; val.i=0; val.T1 = (S1); \
                  val.T2 = (S2); val.T3 = (S3); val;})

#define _NS(D,T,S) D,({drbd_state_t ns; ns.i = D->state.i; ns.T = (S); ns;})
#define _NS2(D,T1,S1,T2,S2) \
                D,({drbd_state_t ns; ns.i = D->state.i; ns.T1 = (S1); \
                ns.T2 = (S2); ns;})
#define _NS3(D,T1,S1,T2,S2,T3,S3) \
                D,({drbd_state_t ns; ns.i = D->state.i; ns.T1 = (S1); \
                ns.T2 = (S2); ns.T3 = (S3); ns;})

static inline void drbd_state_lock(drbd_dev *mdev)
{
	wait_event(mdev->cstate_wait,
		   !test_and_set_bit(CLUSTER_ST_CHANGE,&mdev->flags));
}

static inline void drbd_state_unlock(drbd_dev *mdev)
{
	clear_bit(CLUSTER_ST_CHANGE,&mdev->flags);
	wake_up(&mdev->cstate_wait);
}

static inline int drbd_request_state(drbd_dev* mdev, drbd_state_t mask,
				     drbd_state_t val)
{
	return _drbd_request_state(mdev, mask, val, ChgStateVerbose);
}

/**
 * drbd_chk_io_error: Handles the on_io_error setting, should be called from
 * all io completion handlers. See also drbd_io_error().
 */
static inline void __drbd_chk_io_error(drbd_dev* mdev, int forcedetach)
{
	switch(mdev->bc->dc.on_io_error) {
	case PassOn: /* FIXME would this be better named "Ignore"? */
		if (!forcedetach) {
			if (printk_ratelimit())
				ERR("Local IO failed. Passing error on...\n");
			break;
		}
		/* NOTE fall through to detach case if forcedetach set */
	case Detach:
		if (_drbd_set_state(_NS(mdev,disk,Failed),ChgStateHard) 
		    == SS_Success) {
			if (printk_ratelimit())
				ERR("Local IO failed. Detaching...\n");
		}
		break;
	case CallIOEHelper:
		_drbd_set_state(_NS(mdev,disk,Failed),ChgStateHard);
		break;
	}
}

static inline void drbd_chk_io_error(drbd_dev* mdev, int error, int forcedetach)
{
	if (error) {
		unsigned long flags;
		spin_lock_irqsave(&mdev->req_lock,flags);
		__drbd_chk_io_error(mdev,forcedetach);
		spin_unlock_irqrestore(&mdev->req_lock,flags);
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

/* Returns the first sector number of our meta data,
 * which, for internal meta data, happens to be the maximum capacity
 * we could agree upon with our peer
 */
static inline sector_t drbd_md_first_sector(struct drbd_backing_dev *bdev)
{
	switch (bdev->dc.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + bdev->md.bm_offset;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset;
	}
}

/* returns the last sector number of our meta data,
 * to be able to catch out of band md access */
static inline sector_t drbd_md_last_sector(struct drbd_backing_dev *bdev)
{
	switch (bdev->dc.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return bdev->md.md_offset + MD_AL_OFFSET -1;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect;
	}
}

/* returns the capacity we announce to out peer */
static inline sector_t drbd_get_max_capacity(struct drbd_backing_dev *bdev)
{
	switch (bdev->dc.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		return drbd_get_capacity(bdev->backing_bdev)
			? drbd_md_first_sector(bdev)
			: 0;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return drbd_get_capacity(bdev->backing_bdev);
	}
}

/* returns the sector number of our meta data 'super' block */
static inline sector_t drbd_md_ss__(drbd_dev *mdev,
				    struct drbd_backing_dev *bdev)
{
	switch (bdev->dc.meta_dev_idx) {
	default: /* external, some index */
		return MD_RESERVED_SECT * bdev->dc.meta_dev_idx;
	case DRBD_MD_INDEX_INTERNAL:
		/* with drbd08, internal meta data is always "flexible" */
	case DRBD_MD_INDEX_FLEX_INT:
		/* sizeof(struct md_on_disk_07) == 4k
		 * position: last 4k aligned block of 4k size */
		if (!bdev->backing_bdev) {
			if (DRBD_ratelimit(5*HZ,5)) {
				ERR("bdev->backing_bdev==NULL\n");
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
_drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	list_add_tail(&w->list,&q->q);
	up(&q->s);
}

static inline void
drbd_queue_work_front(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock,flags);
	list_add(&w->list,&q->q);
	up(&q->s); /* within the spinlock,
		      see comment near end of drbd_worker() */
	spin_unlock_irqrestore(&q->q_lock,flags);
}

static inline void
drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock,flags);
	list_add_tail(&w->list,&q->q);
	up(&q->s); /* within the spinlock,
		      see comment near end of drbd_worker() */
	spin_unlock_irqrestore(&q->q_lock,flags);
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
	return drbd_send_cmd(mdev,USE_DATA_SOCKET,cmd,&h,sizeof(h));
}

static inline int drbd_send_ping(drbd_dev *mdev)
{
	Drbd_Header h;
	return drbd_send_cmd(mdev,USE_META_SOCKET,Ping,&h,sizeof(h));
}

static inline int drbd_send_ping_ack(drbd_dev *mdev)
{
	Drbd_Header h;
	return drbd_send_cmd(mdev,USE_META_SOCKET,PingAck,&h,sizeof(h));
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

/* counts how many answer packets packets we expect from our peer,
 * for either explicit application requests,
 * or implicit barrier packets as necessary.
 * increased:
 *  w_send_barrier
 *  _req_mod(req, queue_for_net_write or queue_for_net_read);
 *    it is much easier and equally valid to count what we queue for the
 *    worker, even before it actually was queued or send.
 *    (drbd_make_request_common; recovery path on read io-error)
 * decreased:
 *  got_BarrierAck (respective tl_clear, tl_clear_barrier)
 *  _req_mod(req, data_received)
 *     [from receive_DataReply]
 *  _req_mod(req, write_acked_by_peer or recv_acked_by_peer or neg_acked)
 *     [from got_BlockAck (WriteAck, RecvAck)]
 *     FIXME
 *     for some reason it is NOT decreased in got_NegAck,
 *     but in the resulting cleanup code from report_params.
 *     we should try to remember the reason for that...
 *  _req_mod(req, send_failed or send_canceled)
 *  _req_mod(req, connection_lost_while_pending)
 *     [from tl_clear_barrier]
 */
static inline void inc_ap_pending(drbd_dev* mdev)
{
	atomic_inc(&mdev->ap_pending_cnt);
}

#define ERR_IF_CNT_IS_NEGATIVE(which)				\
	if(atomic_read(&mdev->which)<0)				\
		ERR("in %s:%d: " #which " = %d < 0 !\n",	\
		    __func__ , __LINE__ ,			\
		    atomic_read(&mdev->which))

#define dec_ap_pending(mdev)					\
	typecheck(drbd_dev*,mdev);				\
	if(atomic_dec_and_test(&mdev->ap_pending_cnt))		\
		wake_up(&mdev->cstate_wait);			\
	ERR_IF_CNT_IS_NEGATIVE(ap_pending_cnt)

/* counts how many resync-related answers we still expect from the peer
 *                   increase                   decrease
 * SyncTarget sends RSDataRequest (and expects RSDataReply)
 * SyncSource sends RSDataReply   (and expects WriteAck whith ID_SYNCER)
 *                                         (or NegAck with ID_SYNCER)
 */
static inline void inc_rs_pending(drbd_dev* mdev)
{
	atomic_inc(&mdev->rs_pending_cnt);
}

#define dec_rs_pending(mdev)					\
	typecheck(drbd_dev*,mdev);				\
	atomic_dec(&mdev->rs_pending_cnt);			\
	ERR_IF_CNT_IS_NEGATIVE(rs_pending_cnt)

/* counts how many answers we still need to send to the peer.
 * increased on
 *  receive_Data        unless protocol A;
 *                      we need to send a RecvAck (proto B)
 *                      or WriteAck (proto C)
 *  receive_RSDataReply (recv_resync_read) we need to send a WriteAck
 *  receive_DataRequest (receive_RSDataRequest) we need to send back Data
 *  receive_Barrier_*   we need to send a BarrierAck
 */ 
static inline void inc_unacked(drbd_dev* mdev)
{
	atomic_inc(&mdev->unacked_cnt);
}

#define dec_unacked(mdev)					\
	typecheck(drbd_dev*,mdev);				\
	atomic_dec(&mdev->unacked_cnt);				\
	ERR_IF_CNT_IS_NEGATIVE(unacked_cnt)

#define sub_unacked(mdev, n)					\
	typecheck(drbd_dev*,mdev);				\
	atomic_sub(n, &mdev->unacked_cnt);			\
	ERR_IF_CNT_IS_NEGATIVE(unacked_cnt)


static inline void dec_net(drbd_dev* mdev)
{
	if(atomic_dec_and_test(&mdev->net_cnt)) {
		wake_up(&mdev->cstate_wait);
	}
}

/**
 * inc_net: Returns TRUE when it is ok to access mdev->net_conf. You
 * should call dec_net() when finished looking at mdev->net_conf.
 */
static inline int inc_net(drbd_dev* mdev)
{
	int have_net_conf;

	atomic_inc(&mdev->net_cnt);
	have_net_conf = mdev->state.conn >= Unconnected;
	if(!have_net_conf) dec_net(mdev);
	return have_net_conf;
}

/* strictly speaking,
 * these would have to hold the req_lock while looking at
 * the disk state. But since we cannot submit within a spinlock,
 * this is mood...
 */

/**
 * inc_local: Returns TRUE when local IO is possible. If it returns
 * TRUE you should call dec_local() after IO is completed.
 */
static inline int inc_local_if_state(drbd_dev* mdev, drbd_disks_t mins)
{
	int io_allowed;

	atomic_inc(&mdev->local_cnt);
	io_allowed = (mdev->state.disk >= mins ); 
	if( !io_allowed ) {
		atomic_dec(&mdev->local_cnt);
	}
	return io_allowed;
}
static inline int inc_local(drbd_dev* mdev)
{
	return inc_local_if_state(mdev, Inconsistent);
}


static inline void dec_local(drbd_dev* mdev)
{
	if(atomic_dec_and_test(&mdev->local_cnt) &&
	   mdev->state.disk == Diskless && mdev->bc ) {
		wake_up(&mdev->cstate_wait);
	}

	D_ASSERT(atomic_read(&mdev->local_cnt)>=0);
}

/* this throttles on-the-fly application requests
 * according to max_buffers settings;
 * maybe re-implement using semaphores? */
static inline int drbd_get_max_buffers(drbd_dev* mdev)
{
	int mxb = 1000000; /* arbitrary limit on open requests */
	if(inc_net(mdev)) {
		mxb = mdev->net_conf->max_buffers;
		dec_net(mdev);
	}
	return mxb;
}

static inline int __inc_ap_bio_cond(drbd_dev* mdev) {
	int mxb = drbd_get_max_buffers(mdev);
	if (mdev->state.susp) return 0;
	if (mdev->state.conn == WFBitMapS) return 0;
	if (mdev->state.conn == WFBitMapT) return 0;
	/* since some older kernels don't have atomic_add_unless,
	 * and we are within the spinlock anyways, we have this workaround.  */
	if (atomic_read(&mdev->ap_bio_cnt) > mxb) return 0;
	atomic_inc(&mdev->ap_bio_cnt);
	return 1;
}

/* I'd like to use wait_event_lock_irq,
 * but I'm not sure when it got introduced,
 * and not sure when it has 3 or 4 arguments */
static inline void inc_ap_bio(drbd_dev* mdev)
{
	/* compare with after_state_ch,
	 * os.conn != WFBitMapS && ns.conn == WFBitMapS */
	DEFINE_WAIT(wait);

	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection handshake
	 *    as long as we would exeed the max_buffer limit.
	 *
	 * to avoid races with the reconnect code,
	 * we need to atomic_inc within the spinlock. */

	spin_lock_irq(&mdev->req_lock);
	while (!__inc_ap_bio_cond(mdev)) {
		prepare_to_wait(&mdev->cstate_wait,&wait,TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&mdev->req_lock);
		schedule();
		finish_wait(&mdev->cstate_wait, &wait);
		spin_lock_irq(&mdev->req_lock);
	}
	spin_unlock_irq(&mdev->req_lock);
}

static inline void dec_ap_bio(drbd_dev* mdev)
{
	int mxb = drbd_get_max_buffers(mdev);
	int ap_bio = atomic_dec_return(&mdev->ap_bio_cnt);

	D_ASSERT(ap_bio>=0);
	if (ap_bio < mxb) wake_up(&mdev->cstate_wait);
}

/* FIXME does not handle wrap around yet */
static inline void update_peer_seq(drbd_dev* mdev, int new_seq)
{
	spin_lock(&mdev->peer_seq_lock);
	mdev->peer_seq = max(mdev->peer_seq, new_seq);
	spin_unlock(&mdev->peer_seq_lock);
	wake_up(&mdev->cstate_wait);
	/* FIXME introduce seq_wait, no point in waking up a number of
	 * processes with each and every Ack received... */
}

static inline int peer_seq(drbd_dev* mdev)
{
	int seq;
	spin_lock(&mdev->peer_seq_lock);
	seq = mdev->peer_seq;
	spin_unlock(&mdev->peer_seq_lock);
	return seq;
}

static inline int drbd_queue_order_type(drbd_dev* mdev)
{
	int rv;
#if !defined(QUEUE_FLAG_ORDERED)
	ERR_IF(mdev->bc == NULL) return QUEUE_ORDERED_NONE;
	rv = bdev_get_queue(mdev->bc->backing_bdev)->ordered;
#else
# define QUEUE_ORDERED_NONE 0
# define QUEUE_ORDERED_TAG 1
# define QUEUE_ORDERED_FLUSH 2
# warning "TCQ code disabled at compile time."
	rv = QUEUE_ORDERED_NONE; // Kernels before 2.6.12 had not had TCQ support.
#endif
	return rv;
}

/*
 * FIXME investigate what makes most sense:
 * a) blk_run_queue(q);
 *
 * b) struct backing_dev_info *bdi;
 *    b1) bdi = &q->backing_dev_info;
 *    b2) bdi = mdev->bc->backing_bdev->bd_inode->i_mapping->backing_dev_info;
 *    blk_run_backing_dev(bdi,NULL);
 *
 * c) generic_unplug(q) ? __generic_unplug(q) ?
 *
 * d) q->unplug_fn(q), which is what all the drivers/md/ stuff uses...
 *
 */
static inline void drbd_blk_run_queue(request_queue_t *q)
{
	if (q && q->unplug_fn)
		q->unplug_fn(q);
}

static inline void drbd_kick_lo(drbd_dev *mdev)
{
	if (!mdev->bc->backing_bdev) {
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("backing_bdev==NULL in drbd_kick_lo! The following call trace is for debuggin purposes only. Don't worry.\n");
			dump_stack();
		}
	} else {
		drbd_blk_run_queue(bdev_get_queue(mdev->bc->backing_bdev));
	}
}
#endif
