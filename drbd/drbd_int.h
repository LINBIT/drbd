/*
  drbd_int.h
  Kernel module for 2.6.x Kernels

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
#include <net/tcp.h>
#include "lru_cache.h"

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
extern int allow_oos;
extern unsigned int cn_idx;

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

/* XXX do we need this? */
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

/* All EEs on the free list should have ID_VACANT (== 0)
 * freshly allocated EEs get !ID_VACANT (== 1)
 * so if it says "cannot dereference null pointer at adress 0x00000001",
 * it is most likely one of these :( */

#define ID_IN_SYNC      (4711ULL)
#define ID_OUT_OF_SYNC  (4712ULL)

#define ID_SYNCER (-1ULL)
#define ID_VACANT 0
#define is_syncer_block_id(id) ((id) == ID_SYNCER)

struct drbd_conf;

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

/* handy macro: DUMPP(somepointer) */
#define DUMPP(A)   ERR(#A " = %p in %s:%d\n", (A), __FILE__, __LINE__);
#define DUMPLU(A)  ERR(#A " = %lu in %s:%d\n", (unsigned long)(A), __FILE__, __LINE__);
#define DUMPLLU(A) ERR(#A " = %llu in %s:%d\n", (unsigned long long)(A), __FILE__, __LINE__);
#define DUMPLX(A)  ERR(#A " = %lx in %s:%d\n", (A), __FILE__, __LINE__);
#define DUMPI(A)   ERR(#A " = %d in %s:%d\n", (int)(A), __FILE__, __LINE__);

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

#define PRINTK(level, fmt, args...) \
	printk(level "drbd%d: " fmt, \
		mdev->minor , ##args)

#define ALERT(fmt, args...) PRINTK(KERN_ALERT, fmt , ##args)
#define ERR(fmt, args...)   PRINTK(KERN_ERR, fmt , ##args)
/* nowadays, WARN() is defined as BUG() without crash in bug.h */
#define drbd_WARN(fmt, args...)  PRINTK(KERN_WARNING, fmt , ##args)
#define INFO(fmt, args...)  PRINTK(KERN_INFO, fmt , ##args)
#define DBG(fmt, args...)   PRINTK(KERN_DEBUG, fmt , ##args)

/* see kernel/printk.c:printk_ratelimit
 * macro, so it is easy do have independend rate limits at different locations
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
			drbd_WARN("%d messages suppressed in %s:%d.\n", \
				lost, __FILE__, __LINE__);	\
		__ret = 1;					\
	} else {						\
		missed++;					\
		__ret = 0;					\
	}							\
	__ret;							\
})


#ifdef DBG_ASSERTS
extern void drbd_assert_breakpoint(struct drbd_conf *, char *, char *, int);
# define D_ASSERT(exp)	if (!(exp)) \
	 drbd_assert_breakpoint(mdev, #exp, __FILE__, __LINE__)
#else
# define D_ASSERT(exp)	if (!(exp)) \
	 ERR("ASSERT( " #exp " ) in %s:%d\n", __FILE__, __LINE__)
#endif
#define ERR_IF(exp) if (({				\
	int _b = (exp) != 0;				\
	if (_b) ERR("%s: (%s) in %s:%d\n",		\
		__func__, #exp, __FILE__, __LINE__);	\
	 _b;						\
	}))

/* Defines to control fault insertion */
enum {
    DRBD_FAULT_MD_WR = 0,	/* meta data write */
    DRBD_FAULT_MD_RD,		/*           read  */
    DRBD_FAULT_RS_WR,		/* resync          */
    DRBD_FAULT_RS_RD,
    DRBD_FAULT_DT_WR,		/* data            */
    DRBD_FAULT_DT_RD,
    DRBD_FAULT_DT_RA,		/* data read ahead */
    DRBD_FAULT_AL_EE,		/* alloc ee */

    DRBD_FAULT_MAX,
};

#ifdef DRBD_ENABLE_FAULTS
extern unsigned int
_drbd_insert_fault(struct drbd_conf *mdev, unsigned int type);
static inline int
drbd_insert_fault(struct drbd_conf *mdev, unsigned int type) {
    return fault_rate &&
	    (enable_faults & (1<<type)) &&
	    _drbd_insert_fault(mdev, type);
}
#define FAULT_ACTIVE(_m, _t) (drbd_insert_fault((_m), (_t)))

#else
#define FAULT_ACTIVE(_m, _t) (0)
#endif

#include <linux/stringify.h>
/* integer division, round _UP_ to the next integer */
#define div_ceil(A, B) ((A)/(B) + ((A)%(B) ? 1 : 0))
/* usual integer division */
#define div_floor(A, B) ((A)/(B))

/*
 * Compatibility Section
 *************************/

#define LOCK_SIGMASK(task, flags)   spin_lock_irqsave(&task->sighand->siglock, flags)
#define UNLOCK_SIGMASK(task, flags) spin_unlock_irqrestore(&task->sighand->siglock, flags)
#define RECALC_SIGPENDING()	    recalc_sigpending();

#if defined(DBG_SPINLOCKS) && defined(__SMP__)
# define MUST_HOLD(lock) if (!spin_is_locked(lock)) ERR("Not holding lock! in %s\n", __func__);
#else
# define MUST_HOLD(lock)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
# define HAVE_KERNEL_SENDMSG 1
#else
# define HAVE_KERNEL_SENDMSG 0
#endif

#ifndef uninitialized_var
/* in upstream since 9490991482a2091a828d997adbc088e24c310a4d
 * Date:   Sun May 6 14:49:17 2007 -0700 */
/*
 * A trick to suppress uninitialized variable warning without generating any
 * code
 */
#define uninitialized_var(x) x = x
#endif



/*
 * our structs
 *************************/

#define SET_MDEV_MAGIC(x) \
	({ typecheck(struct drbd_conf*, x); \
	  (x)->magic = (long)(x) ^ DRBD_MAGIC; })
#define IS_VALID_MDEV(x)  \
	(typecheck(struct drbd_conf*, x) && \
	  ((x) ? (((x)->magic ^ DRBD_MAGIC) == (long)(x)) : 0))

/* drbd_meta-data.c (still in drbd_main.c) */
/* 4th incarnation of the disk layout. */
#define DRBD_MD_MAGIC (DRBD_MAGIC+4)

extern struct drbd_conf **minor_table;

/***
 * on the wire
 *********************************************************************/

enum Drbd_Packet_Cmd {
	/* receiver (data socket) */
	Data              = 0x00,
	DataReply         = 0x01, /* Response to DataRequest */
	RSDataReply       = 0x02, /* Response to RSDataRequest */
	Barrier           = 0x03,
	ReportBitMap      = 0x04,
	BecomeSyncTarget  = 0x05,
	BecomeSyncSource  = 0x06,
	UnplugRemote      = 0x07, /* Used at various times to hint the peer */
	DataRequest       = 0x08, /* Used to ask for a data block */
	RSDataRequest     = 0x09, /* Used to ask for a data block for resync */
	SyncParam         = 0x0a,
	ReportProtocol    = 0x0b,
	ReportUUIDs       = 0x0c,
	ReportSizes       = 0x0d,
	ReportState       = 0x0e,
	ReportSyncUUID    = 0x0f,
	AuthChallenge     = 0x10,
	AuthResponse      = 0x11,
	StateChgRequest   = 0x12,

	/* asender (meta socket */
	Ping              = 0x13,
	PingAck           = 0x14,
	RecvAck           = 0x15, /* Used in protocol B */
	WriteAck          = 0x16, /* Used in protocol C */
	RSWriteAck        = 0x17, /* Is a WriteAck, additionally call set_in_sync(). */
	DiscardAck        = 0x18, /* Used in proto C, two-primaries conflict detection */
	NegAck            = 0x19, /* Sent if local disk is unusable */
	NegDReply         = 0x1a, /* Local disk is broken... */
	NegRSDReply       = 0x1b, /* Local disk is broken... */
	BarrierAck        = 0x1c,
	StateChgReply     = 0x1d,

	/* "new" commands, no longer fitting into the ordering scheme above */

	OVRequest         = 0x1e, /* data socket */
	OVReply           = 0x1f,
	OVResult          = 0x20, /* meta socket */
	CsumRSRequest     = 0x21, /* data socket */
	RSIsInSync        = 0x22, /* meta socket */
	SyncParam89       = 0x23, /* data socket, protocol version 89 replacement for SyncParam */

	MAX_CMD           = 0x24,
	MayIgnore         = 0x100, /* Flag to test if (cmd > MayIgnore) ... */
	MAX_OPT_CMD       = 0x101,

	/* special command ids for handshake */

	HandShakeM        = 0xfff1, /* First Packet on the MetaSock */
	HandShakeS        = 0xfff2, /* First Packet on the Socket */

	HandShake         = 0xfffe  /* FIXED for the next century! */
};

static inline const char *cmdname(enum Drbd_Packet_Cmd cmd)
{
	/* THINK may need to become several global tables
	 * when we want to support more than
	 * one PRO_VERSION */
	static const char *cmdnames[] = {
		[Data]		   = "Data",
		[DataReply]	   = "DataReply",
		[RSDataReply]	   = "RSDataReply",
		[Barrier]	   = "Barrier",
		[ReportBitMap]	   = "ReportBitMap",
		[BecomeSyncTarget] = "BecomeSyncTarget",
		[BecomeSyncSource] = "BecomeSyncSource",
		[UnplugRemote]	   = "UnplugRemote",
		[DataRequest]	   = "DataRequest",
		[RSDataRequest]    = "RSDataRequest",
		[SyncParam]	   = "SyncParam",
		[SyncParam89]	   = "SyncParam89",
		[ReportProtocol]   = "ReportProtocol",
		[ReportUUIDs]	   = "ReportUUIDs",
		[ReportSizes]	   = "ReportSizes",
		[ReportState]	   = "ReportState",
		[ReportSyncUUID]   = "ReportSyncUUID",
		[AuthChallenge]    = "AuthChallenge",
		[AuthResponse]	   = "AuthResponse",
		[Ping]		   = "Ping",
		[PingAck]	   = "PingAck",
		[RecvAck]	   = "RecvAck",
		[WriteAck]	   = "WriteAck",
		[RSWriteAck]	   = "RSWriteAck",
		[DiscardAck]	   = "DiscardAck",
		[NegAck]	   = "NegAck",
		[NegDReply]	   = "NegDReply",
		[NegRSDReply]	   = "NegRSDReply",
		[BarrierAck]	   = "BarrierAck",
		[StateChgRequest]  = "StateChgRequest",
		[StateChgReply]    = "StateChgReply",
		[OVRequest]        = "OVRequest",
		[OVReply]          = "OVReply",
		[OVResult]         = "OVResult",
		[CsumRSRequest]    = "CsumRSRequest",
		[RSIsInSync]       = "RSIsInSync",
		[MAX_CMD]	   = NULL,
	};

	if (cmd == HandShakeM)
		return "HandShakeM";
	if (cmd == HandShakeS)
		return "HandShakeS";
	if (cmd == HandShake)
		return "HandShake";
	if (cmd >= MAX_CMD)
		return "Unknown";
	return cmdnames[cmd];
}


/* This is the layout for a packet on the wire.
 * The byteorder is the network byte order.
 *     (except block_id and barrier fields.
 *	these are pointers to local structs
 *	and have no relevance for the partner,
 *	which just echoes them as received.)
 *
 * NOTE that the payload starts at a long aligned offset,
 * regardless of 32 or 64 bit arch!
 */
struct Drbd_Header {
	u32	  magic;
	u16	  command;
	u16	  length;	/* bytes of data after this header */
	char	  payload[0];
} __attribute((packed));
/* 8 bytes. packet FIXED for the next century! */

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

/* these defines must not be changed without changing the protocol version */
#define DP_HARDBARRIER	      1
#define DP_RW_SYNC	      2
#define DP_MAY_SET_IN_SYNC    4

struct Drbd_Data_Packet {
	struct Drbd_Header head;
	u64	    sector;    /* 64 bits sector number */
	u64	    block_id;  /* to identify the request in protocol B&C */
	u32	    seq_num;
	u32	    dp_flags;
} __attribute((packed));

/*
 * commands which share a struct:
 *  Drbd_BlockAck_Packet:
 *   RecvAck (proto B), WriteAck (proto C),
 *   DiscardAck (proto C, two-primaries conflict detection)
 *  Drbd_BlockRequest_Packet:
 *   DataRequest, RSDataRequest
 */
struct Drbd_BlockAck_Packet {
	struct Drbd_Header head;
	u64	    sector;
	u64	    block_id;
	u32	    blksize;
	u32	    seq_num;
} __attribute((packed));


struct Drbd_BlockRequest_Packet {
	struct Drbd_Header head;
	u64 sector;
	u64 block_id;
	u32 blksize;
	u32 pad;	/* to multiple of 8 Byte */
} __attribute((packed));

/*
 * commands with their own struct for additional fields:
 *   HandShake
 *   Barrier
 *   BarrierAck
 *   SyncParam
 *   ReportParams
 */

struct Drbd_HandShake_Packet {
	struct Drbd_Header head;	/* 8 bytes */
	u32 protocol_min;
	u32 feature_flags;
	u32 protocol_max;

	/* should be more than enough for future enhancements
	 * for now, feature_flags and the reserverd array shall be zero.
	 */

	u32 _pad;
	u64 reserverd[7];
} __attribute((packed));
/* 80 bytes, FIXED for the next century */

struct Drbd_Barrier_Packet {
	struct Drbd_Header head;
	u32 barrier;	/* barrier number _handle_ only */
	u32 pad;	/* to multiple of 8 Byte */
} __attribute((packed));

struct Drbd_BarrierAck_Packet {
	struct Drbd_Header head;
	u32 barrier;
	u32 set_size;
} __attribute((packed));

struct Drbd_SyncParam_Packet {
	struct Drbd_Header head;
	u32 rate;

	      /* Since protocol version 88 and higher. */
	char verify_alg[0];
} __attribute((packed));

struct Drbd_SyncParam89_Packet {
	struct Drbd_Header head;
	u32 rate;
        /* protocol version 89: */
	char verify_alg[SHARED_SECRET_MAX];
	char csums_alg[SHARED_SECRET_MAX];
} __attribute((packed));

struct Drbd_Protocol_Packet {
	struct Drbd_Header head;
	u32 protocol;
	u32 after_sb_0p;
	u32 after_sb_1p;
	u32 after_sb_2p;
	u32 want_lose;
	u32 two_primaries;

              /* Since protocol version 87 and higher. */
	char integrity_alg[0];

} __attribute((packed));

struct Drbd_GenCnt_Packet {
	struct Drbd_Header head;
	u64 uuid[EXT_UUID_SIZE];
} __attribute((packed));

struct Drbd_SyncUUID_Packet {
	struct Drbd_Header head;
	u64	    uuid;
} __attribute((packed));

struct Drbd_Sizes_Packet {
	struct Drbd_Header head;
	u64	    d_size;  /* size of disk */
	u64	    u_size;  /* user requested size */
	u64	    c_size;  /* current exported size */
	u32	    max_segment_size;  /* Maximal size of a BIO */
	u32	    queue_order_type;
} __attribute((packed));

struct Drbd_State_Packet {
	struct Drbd_Header head;
	u32	    state;
} __attribute((packed));

struct Drbd_Req_State_Packet {
	struct Drbd_Header head;
	u32	    mask;
	u32	    val;
} __attribute((packed));

struct Drbd_RqS_Reply_Packet {
	struct Drbd_Header head;
	u32	    retcode;
} __attribute((packed));

struct Drbd06_Parameter_P {
	u64	  size;
	u32	  state;
	u32	  blksize;
	u32	  protocol;
	u32	  version;
	u32	  gen_cnt[5];
	u32	  bit_map_gen[5];
} __attribute((packed));

struct Drbd_Discard_Packet {
	struct Drbd_Header head;
	u64	    block_id;
	u32	    seq_num;
	u32	    pad;
} __attribute((packed));

union Drbd_Polymorph_Packet {
	struct Drbd_Header		head;
	struct Drbd_HandShake_Packet	HandShake;
	struct Drbd_Data_Packet		Data;
	struct Drbd_BlockAck_Packet	BlockAck;
	struct Drbd_Barrier_Packet	Barrier;
	struct Drbd_BarrierAck_Packet	BarrierAck;
	struct Drbd_SyncParam89_Packet	SyncParam89;
	struct Drbd_Protocol_Packet	Protocol;
	struct Drbd_Sizes_Packet	Sizes;
	struct Drbd_GenCnt_Packet	GenCnt;
	struct Drbd_State_Packet	State;
	struct Drbd_Req_State_Packet	ReqState;
	struct Drbd_RqS_Reply_Packet	RqSReply;
	struct Drbd_BlockRequest_Packet	BlockRequest;
} __attribute((packed));

/**********************************************************************/
enum Drbd_thread_state {
	None,
	Running,
	Exiting,
	Restarting
};

struct Drbd_thread {
	spinlock_t t_lock;
	struct task_struct *task;
	struct completion startstop;
	enum Drbd_thread_state t_state;
	int (*function) (struct Drbd_thread *);
	struct drbd_conf *mdev;
	int reset_cpu_mask;
};

static inline enum Drbd_thread_state get_t_state(struct Drbd_thread *thi)
{
	/* THINK testing the t_state seems to be uncritical in all cases
	 * (but thread_{start,stop}), so we can read it *without* the lock.
	 *	--lge */

	smp_rmb();
	return thi->t_state;
}


/*
 * Having this as the first member of a struct provides sort of "inheritance".
 * "derived" structs can be "drbd_queue_work()"ed.
 * The callback should know and cast back to the descendant struct.
 * drbd_request and Tl_epoch_entry are descendants of drbd_work.
 */
struct drbd_work;
typedef int (*drbd_work_cb)(struct drbd_conf *, struct drbd_work *, int cancel);
struct drbd_work {
	struct list_head list;
	drbd_work_cb cb;
};

struct drbd_barrier;
struct drbd_request {
	struct drbd_work w;
	struct drbd_conf *mdev;
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
	unsigned long start_time;
};

struct drbd_barrier {
	struct drbd_work w;
	struct list_head requests; /* requests before */
	struct drbd_barrier *next; /* pointer to the next barrier */
	unsigned int br_number;  /* the barriers identifier. */
	int n_req;	/* number of requests attached before this barrier */
};

struct drbd_request;

/* These Tl_epoch_entries may be in one of 6 lists:
   active_ee .. data packet being written
   sync_ee   .. syncer block being written
   done_ee   .. block written, need to send WriteAck
   read_ee   .. [RS]DataRequest being read
*/

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

struct Tl_epoch_entry {
	struct drbd_work    w;
	struct drbd_conf *mdev;
	struct bio *private_bio;
	struct hlist_node colision;
	sector_t sector;
	unsigned int size;
	struct drbd_epoch *epoch;

	/* up to here, the struct layout is identical to drbd_request;
	 * we might be able to use that to our advantage...  */

	unsigned int flags;
	u64    block_id;
};

struct digest_info {
	int digest_size;
	void *digest;
};

/* ee flag bits */
enum {
	__EE_CALL_AL_COMPLETE_IO,
	__EE_CONFLICT_PENDING,
	__EE_MAY_SET_IN_SYNC,
	__EE_IS_BARRIER,
};
#define EE_CALL_AL_COMPLETE_IO (1<<__EE_CALL_AL_COMPLETE_IO)
#define EE_CONFLICT_PENDING    (1<<__EE_CONFLICT_PENDING)
#define EE_MAY_SET_IN_SYNC     (1<<__EE_MAY_SET_IN_SYNC)
#define EE_IS_BARRIER          (1<<__EE_IS_BARRIER)

/* global flag bits */
enum {
	CREATE_BARRIER,		/* next Data is preceeded by a Barrier */
	SIGNAL_ASENDER,		/* whether asender wants to be interrupted */
	SEND_PING,		/* whether asender should send a ping asap */
	WORK_PENDING,		/* completion flag for drbd_disconnect */
	STOP_SYNC_TIMER,	/* tell timer to cancel itself */
	UNPLUG_QUEUED,		/* only relevant with kernel 2.4 */
	UNPLUG_REMOTE,		/* sending a "UnplugRemote" could help */
	MD_DIRTY,		/* current uuids and flags not yet on disk */
	DISCARD_CONCURRENT,	/* Set on one node, cleared on the peer! */
	USE_DEGR_WFC_T,		/* degr-wfc-timeout instead of wfc-timeout. */
	CLUSTER_ST_CHANGE,	/* Cluster wide state change going on... */
	CL_ST_CHG_SUCCESS,
	CL_ST_CHG_FAIL,
	CRASHED_PRIMARY,	/* This node was a crashed primary.
				 * Gets cleared when the state.conn
				 * goes into Connected state. */
	WRITE_BM_AFTER_RESYNC,	/* A kmalloc() during resync failed */
	NO_BARRIER_SUPP,	/* underlying block device doesn't implement barriers */
	CONSIDER_RESYNC,

	MD_NO_BARRIER,		/* meta data device does not support barriers,
				   so don't even try */
	SUSPEND_IO,		/* suspend application io */
	BITMAP_IO,		/* suspend application io;
				   once no more io in flight, start bitmap io */
	BITMAP_IO_QUEUED,       /* Started bitmap IO */
	RESYNC_AFTER_NEG,       /* Resync after online grow after the attach&negotiate finished. */
	NET_CONGESTED,		/* The data socket is congested */
};

struct drbd_bitmap; /* opaque for drbd_conf */

/* TODO sort members for performance
 * MAYBE group them further */

/* THINK maybe we actually want to use the default "event/%s" worker threads
 * or similar in linux 2.6, which uses per cpu data and threads.
 *
 * To be general, this might need a spin_lock member.
 * For now, please use the mdev->req_lock to protect list_head,
 * see drbd_queue_work below.
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
	struct semaphore  mutex;
	struct socket    *socket;
	/* this way we get our
	 * send/receive buffers off the stack */
	union Drbd_Polymorph_Packet sbuf;
	union Drbd_Polymorph_Packet rbuf;
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

/* for sync_conf and other types... */
#define NL_PACKET(name, number, fields) struct name { fields };
#define NL_INTEGER(pn,pr,member) int member;
#define NL_INT64(pn,pr,member) __u64 member;
#define NL_BIT(pn,pr,member)   unsigned member:1;
#define NL_STRING(pn,pr,member,len) unsigned char member[len]; int member ## _len;
#include "linux/drbd_nl.h"

struct drbd_backing_dev {
	struct block_device *backing_bdev;
	struct block_device *md_bdev;
	struct file *lo_file;
	struct file *md_file;
	struct drbd_md md;
	struct disk_conf dc; /* The user provided config... */
	sector_t known_size; /* last known size of that backing device */
};

struct drbd_md_io {
	struct drbd_conf *mdev;
	struct completion event;
	int error;
};

struct bm_io_work {
	struct drbd_work w;
	char *why;
	int (*io_fn)(struct drbd_conf *mdev);
	void (*done)(struct drbd_conf *mdev, int rv);
};

enum write_ordering_e {
	WO_none,
	WO_drain_io,
	WO_bdev_flush,
	WO_bio_barrier
};

struct drbd_conf {
#ifdef PARANOIA
	long magic;
#endif
	/* things that are stored as / read from meta data on disk */
	unsigned long flags;

	/* configured by drbdsetup */
	struct net_conf *net_conf; /* protected by inc_net() and dec_net() */
	struct syncer_conf sync_conf;
	struct drbd_backing_dev *bc __protected_by(local);

	sector_t p_size;     /* partner's disk size */
	struct request_queue *rq_queue;
	struct block_device *this_bdev;
	struct gendisk	    *vdisk;

	struct drbd_socket data; /* data/barrier/cstate/parameter packets */
	struct drbd_socket meta; /* ping/ack (metadata) packets */
	int agreed_pro_version;  /* actually used protocol version */
	unsigned long last_received; /* in jiffies, either socket */
	unsigned int ko_count;
	struct drbd_work  resync_work,
			  unplug_work,
			  md_sync_work;
	struct timer_list resync_timer;
	struct timer_list md_sync_timer;

	/* Used after attach while negotiating new disk state. */
	union drbd_state_t new_state_tmp;

	union drbd_state_t state;
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
	atomic_t unacked_cnt;	 /* Need to send replys for */
	atomic_t local_cnt;	 /* Waiting for local completion */
	atomic_t net_cnt;	 /* Users of net_conf */
	spinlock_t req_lock;
	struct drbd_barrier *unused_spare_barrier; /* for pre-allocation */
	struct drbd_barrier *newest_barrier;
	struct drbd_barrier *oldest_barrier;
	struct list_head out_of_sequence_requests;
	struct hlist_head *tl_hash;
	unsigned int tl_hash_s;

	/* blocks to sync in this run [unit BM_BLOCK_SIZE] */
	unsigned long rs_total;
	/* number of sync IOs that failed in this run */
	unsigned long rs_failed;
	/* Syncer's start time [unit jiffies] */
	unsigned long rs_start;
	/* cumulated time in PausedSyncX state [unit jiffies] */
	unsigned long rs_paused;
	/* block not up-to-date at mark [unit BM_BLOCK_SIZE] */
	unsigned long rs_mark_left;
	/* marks's time [unit jiffies] */
	unsigned long rs_mark_time;
	/* skipped because csum was equeal [unit BM_BLOCK_SIZE] */
	unsigned long rs_same_csum;
	sector_t ov_position;
	/* Start sector of out of sync range. */
	sector_t ov_last_oos_start;
	/* size of out-of-sync range in sectors. */
	sector_t ov_last_oos_size;
	unsigned long ov_left;
	struct crypto_hash *csums_tfm;
	struct crypto_hash *verify_tfm;

	struct Drbd_thread receiver;
	struct Drbd_thread worker;
	struct Drbd_thread asender;
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
	struct list_head active_ee; /* IO in progress */
	struct list_head sync_ee;   /* IO in progress */
	struct list_head done_ee;   /* send ack */
	struct list_head read_ee;   /* IO in progress */
	struct list_head net_ee;    /* zero-copy network send in progress */
	struct hlist_head *ee_hash; /* is proteced by req_lock! */
	unsigned int ee_hash_s;

	/* this one is protected by ee_lock, single thread */
	struct Tl_epoch_entry *last_write_w_barrier;

	int next_barrier_nr;
	struct hlist_head *app_reads_hash; /* is proteced by req_lock */
	struct list_head resync_reads;
	atomic_t pp_in_use;
	wait_queue_head_t ee_wait;
	struct page *md_io_page;	/* one page buffer for md_io */
	struct page *md_io_tmpp;	/* for hardsect != 512 [s390 only?] */
	struct semaphore md_io_mutex;	/* protects the md_io_buffer */
	spinlock_t al_lock;
	wait_queue_head_t al_wait;
	struct lru_cache *act_log;	/* activity log */
	unsigned int al_tr_number;
	int al_tr_cycle;
	int al_tr_pos;   /* position of the next transaction in the journal */
	struct crypto_hash *cram_hmac_tfm;
	struct crypto_hash *integrity_w_tfm; /* to be used by the worker thread */
	struct crypto_hash *integrity_r_tfm; /* to be used by the receiver thread */
	void *int_dig_out;
	void *int_dig_in;
	void *int_dig_vv;
	wait_queue_head_t seq_wait;
	atomic_t packet_seq;
	unsigned int peer_seq;
	spinlock_t peer_seq_lock;
	unsigned int minor;
	unsigned long comm_bm_set; /* communicated number of set bits. */
	cpumask_t cpu_mask;
	struct bm_io_work bm_io_work;
	u64 ed_uuid; /* UUID of the exposed data */
	struct mutex state_mutex;
	char congestion_reason;  /* Why we where congested... */
};

static inline struct drbd_conf *minor_to_mdev(unsigned int minor)
{
	struct drbd_conf *mdev;

	mdev = minor < minor_count ? minor_table[minor] : NULL;

	return mdev;
}

static inline unsigned int mdev_to_minor(struct drbd_conf *mdev)
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
static inline int drbd_get_data_sock(struct drbd_conf *mdev)
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

static inline void drbd_put_data_sock(struct drbd_conf *mdev)
{
	up(&mdev->data.mutex);
}

/*
 * function declarations
 *************************/

/* drbd_main.c */

enum chg_state_flags {
	ChgStateHard	= 1,
	ChgStateVerbose = 2,
	ChgWaitComplete = 4,
	ChgSerialize    = 8,
	ChgOrdered      = ChgWaitComplete + ChgSerialize,
};

extern void drbd_init_set_defaults(struct drbd_conf *mdev);
extern int drbd_change_state(struct drbd_conf *mdev, enum chg_state_flags f,
			union drbd_state_t mask, union drbd_state_t val);
extern void drbd_force_state(struct drbd_conf *, union drbd_state_t,
			union drbd_state_t);
extern int _drbd_request_state(struct drbd_conf *, union drbd_state_t,
			union drbd_state_t, enum chg_state_flags);
extern int __drbd_set_state(struct drbd_conf *, union drbd_state_t,
			    enum chg_state_flags, struct completion *done);
extern void print_st_err(struct drbd_conf *, union drbd_state_t,
			union drbd_state_t, int);
extern int  drbd_thread_start(struct Drbd_thread *thi);
extern void _drbd_thread_stop(struct Drbd_thread *thi, int restart, int wait);
#ifdef CONFIG_SMP
extern void drbd_thread_current_set_cpu(struct drbd_conf *mdev);
extern cpumask_t drbd_calc_cpu_mask(struct drbd_conf *mdev);
#else
#define drbd_thread_current_set_cpu(A) ({})
#define drbd_calc_cpu_mask(A) CPU_MASK_ALL
#endif
extern void drbd_free_resources(struct drbd_conf *mdev);
extern void tl_release(struct drbd_conf *mdev, unsigned int barrier_nr,
		       unsigned int set_size);
extern void tl_clear(struct drbd_conf *mdev);
extern void _tl_add_barrier(struct drbd_conf *, struct drbd_barrier *);
extern void drbd_free_sock(struct drbd_conf *mdev);
extern int drbd_send(struct drbd_conf *mdev, struct socket *sock,
			void *buf, size_t size, unsigned msg_flags);
extern int drbd_send_protocol(struct drbd_conf *mdev);
extern int _drbd_send_uuids(struct drbd_conf *mdev);
extern int drbd_send_uuids(struct drbd_conf *mdev);
extern int drbd_send_sync_uuid(struct drbd_conf *mdev, u64 val);
extern int drbd_send_sizes(struct drbd_conf *mdev);
extern int _drbd_send_state(struct drbd_conf *mdev);
extern int drbd_send_state(struct drbd_conf *mdev);
extern int _drbd_send_cmd(struct drbd_conf *mdev, struct socket *sock,
			enum Drbd_Packet_Cmd cmd, struct Drbd_Header *h,
			size_t size, unsigned msg_flags);
#define USE_DATA_SOCKET 1
#define USE_META_SOCKET 0
extern int drbd_send_cmd(struct drbd_conf *mdev, int use_data_socket,
			enum Drbd_Packet_Cmd cmd, struct Drbd_Header *h,
			size_t size);
extern int drbd_send_cmd2(struct drbd_conf *mdev, enum Drbd_Packet_Cmd cmd,
			char *data, size_t size);
extern int drbd_send_sync_param(struct drbd_conf *mdev, struct syncer_conf *sc);
extern int drbd_send_b_ack(struct drbd_conf *mdev, u32 barrier_nr,
			u32 set_size);
extern int drbd_send_ack(struct drbd_conf *mdev, enum Drbd_Packet_Cmd cmd,
			struct Tl_epoch_entry *e);
extern int drbd_send_ack_rp(struct drbd_conf *mdev, enum Drbd_Packet_Cmd cmd,
			struct Drbd_BlockRequest_Packet *rp);
extern int drbd_send_ack_dp(struct drbd_conf *mdev, enum Drbd_Packet_Cmd cmd,
			struct Drbd_Data_Packet *dp);
extern int drbd_send_ack_ex(struct drbd_conf *mdev, enum Drbd_Packet_Cmd cmd,
			    sector_t sector, int blksize, u64 block_id);
extern int _drbd_send_page(struct drbd_conf *mdev, struct page *page,
			int offset, size_t size);
extern int drbd_send_block(struct drbd_conf *mdev, enum Drbd_Packet_Cmd cmd,
			   struct Tl_epoch_entry *e);
extern int drbd_send_dblock(struct drbd_conf *mdev, struct drbd_request *req);
extern int _drbd_send_barrier(struct drbd_conf *mdev,
			struct drbd_barrier *barrier);
extern int drbd_send_drequest(struct drbd_conf *mdev, int cmd,
			      sector_t sector, int size, u64 block_id);
extern int drbd_send_drequest_csum(struct drbd_conf *mdev,
				   sector_t sector,int size,
				   void *digest, int digest_size,
				   enum Drbd_Packet_Cmd cmd);
extern int drbd_send_ov_request(struct drbd_conf *mdev,sector_t sector,int size);

extern int drbd_send_bitmap(struct drbd_conf *mdev);
extern int _drbd_send_bitmap(struct drbd_conf *mdev);
extern int drbd_send_sr_reply(struct drbd_conf *mdev, int retcode);
extern void drbd_free_bc(struct drbd_backing_dev *bc);
extern int drbd_io_error(struct drbd_conf *mdev, int forcedetach);
extern void drbd_mdev_cleanup(struct drbd_conf *mdev);

/* drbd_meta-data.c (still in drbd_main.c) */
extern void drbd_md_sync(struct drbd_conf *mdev);
extern int  drbd_md_read(struct drbd_conf *mdev, struct drbd_backing_dev *bdev);
/* maybe define them below as inline? */
extern void drbd_uuid_set(struct drbd_conf *mdev, int idx, u64 val) __must_hold(local);
extern void _drbd_uuid_set(struct drbd_conf *mdev, int idx, u64 val) __must_hold(local);
extern void drbd_uuid_new_current(struct drbd_conf *mdev) __must_hold(local);
extern void _drbd_uuid_new_current(struct drbd_conf *mdev) __must_hold(local);
extern void drbd_uuid_set_bm(struct drbd_conf *mdev, u64 val) __must_hold(local);
extern void drbd_md_set_flag(struct drbd_conf *mdev, int flags) __must_hold(local);
extern void drbd_md_clear_flag(struct drbd_conf *mdev, int flags)__must_hold(local);
extern int drbd_md_test_flag(struct drbd_backing_dev *, int);
extern void drbd_md_mark_dirty(struct drbd_conf *mdev);
extern void drbd_queue_bitmap_io(struct drbd_conf *mdev,
				 int (*io_fn)(struct drbd_conf *),
				 void (*done)(struct drbd_conf *, int),
				 char *why);
extern int drbd_bmio_set_n_write(struct drbd_conf *mdev);
extern int drbd_bmio_clear_n_write(struct drbd_conf *mdev);
extern int drbd_bitmap_io(struct drbd_conf *mdev, int (*io_fn)(struct drbd_conf *), char *why);


/* Meta data layout
   We reserve a 128MB Block (4k aligned)
   * either at the end of the backing device
   * or on a seperate meta data device. */

#define MD_RESERVED_SECT (128LU << 11)  /* 128 MB, unit sectors */
/* The following numbers are sectors */
#define MD_AL_OFFSET 8	    /* 8 Sectors after start of meta area */
#define MD_AL_MAX_SIZE 64   /* = 32 kb LOG  ~ 3776 extents ~ 14 GB Storage */
/* Allows up to about 3.8TB */
#define MD_BM_OFFSET (MD_AL_OFFSET + MD_AL_MAX_SIZE)

/* Since the smalles IO unit is usually 512 byte */
#define MD_HARDSECT_B	 9
#define MD_HARDSECT	 (1<<MD_HARDSECT_B)

/* activity log */
#define AL_EXTENTS_PT ((MD_HARDSECT-12)/8-1) /* 61 ; Extents per 512B sector */
#define AL_EXTENT_SIZE_B 22		 /* One extent represents 4M Storage */
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

/* resync bitmap */
/* 16MB sized 'bitmap extent' to track syncer usage */
struct bm_extent {
	struct lc_element lce;
	int rs_left; /* number of bits set (out of sync) in this extent. */
	int rs_failed; /* number of failed resync requests in this extent. */
	unsigned long flags;
};

#define BME_NO_WRITES  0  /* bm_extent.flags: no more requests on this one! */
#define BME_LOCKED     1  /* bm_extent.flags: syncer active on this one. */

/* drbd_bitmap.c */
/*
 * We need to store one bit for a block.
 * Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
 * Bit 0 ==> local node thinks this block is binary identical on both nodes
 * Bit 1 ==> local node thinks this block needs to be synced.
 */

#define BM_BLOCK_SIZE_B  12			 /* 4k per bit */
#define BM_BLOCK_SIZE	 (1<<BM_BLOCK_SIZE_B)
/* (9+3) : 512 bytes @ 8 bits; representing 16M storage
 * per sector of on disk bitmap */
#define BM_EXT_SIZE_B	 (BM_BLOCK_SIZE_B + MD_HARDSECT_B + 3)  /* = 24 */
#define BM_EXT_SIZE	 (1<<BM_EXT_SIZE_B)

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

/* how much _storage_ sectors we have per bitmap sector */
#define BM_EXT_TO_SECT(x)   ((sector_t)(x) << (BM_EXT_SIZE_B-9))
#define BM_SECT_PER_EXT     BM_EXT_TO_SECT(1)

/* in one sector of the bitmap, we have this many activity_log extents. */
#define AL_EXT_PER_BM_SECT  (1 << (BM_EXT_SIZE_B - AL_EXTENT_SIZE_B))
#define BM_WORDS_PER_AL_EXT (1 << (AL_EXTENT_SIZE_B-BM_BLOCK_SIZE_B-LN2_BPL))


#define BM_BLOCKS_PER_BM_EXT_B (BM_EXT_SIZE_B - BM_BLOCK_SIZE_B)
#define BM_BLOCKS_PER_BM_EXT_MASK  ((1<<BM_BLOCKS_PER_BM_EXT_B) - 1)

/* I want the packet to fit within one page
 * THINK maybe use a special bitmap header,
 * including offset and compression scheme and whatnot
 * Do not use PAGE_SIZE here! Use a architecture agnostic constant!
 */
#define BM_PACKET_WORDS ((4096-sizeof(struct Drbd_Header))/sizeof(long))
#if (PAGE_SIZE < 4096)
/* drbd_send_bitmap / receive_bitmap would break horribly */
#error "PAGE_SIZE too small"
#endif

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
	  ((MD_RESERVED_SECT - MD_BM_OFFSET) * (1LL<<(BM_EXT_SIZE_B-9)))
#if DRBD_MAX_SECTORS_BM < DRBD_MAX_SECTORS_32
#define DRBD_MAX_SECTORS      DRBD_MAX_SECTORS_BM
#define DRBD_MAX_SECTORS_FLEX DRBD_MAX_SECTORS_BM
#elif !defined(CONFIG_LBD) && BITS_PER_LONG == 32
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
#define DRBD_MAX_SECTORS_FLEX BM_BIT_TO_SECT(0x1LU << 32)
#endif
#endif

/* Sector shift value for the "hash" functions of tl_hash and ee_hash tables.
 * With a value of 6 all IO in one 32K block make it to the same slot of the
 * hash table. */
#define HT_SHIFT 6
#define DRBD_MAX_SEGMENT_SIZE (1U<<(9+HT_SHIFT))

/* Number of elements in the app_reads_hash */
#define APP_R_HSIZE 15

extern int  drbd_bm_init(struct drbd_conf *mdev);
extern int  drbd_bm_resize(struct drbd_conf *mdev, sector_t sectors);
extern void drbd_bm_cleanup(struct drbd_conf *mdev);
extern void drbd_bm_set_all(struct drbd_conf *mdev);
extern void drbd_bm_clear_all(struct drbd_conf *mdev);
extern int  drbd_bm_set_bits(
		struct drbd_conf *mdev, unsigned long s, unsigned long e);
extern int  drbd_bm_clear_bits(
		struct drbd_conf *mdev, unsigned long s, unsigned long e);
/* bm_set_bits variant for use while holding drbd_bm_lock */
extern int _drbd_bm_set_bits(struct drbd_conf *mdev,
		const unsigned long s, const unsigned long e);
extern int  drbd_bm_test_bit(struct drbd_conf *mdev, unsigned long bitnr);
extern int  drbd_bm_e_weight(struct drbd_conf *mdev, unsigned long enr);
extern int  drbd_bm_write_sect(struct drbd_conf *mdev, unsigned long enr) __must_hold(local);
extern int  drbd_bm_read(struct drbd_conf *mdev) __must_hold(local);
extern int  drbd_bm_write(struct drbd_conf *mdev) __must_hold(local);
extern unsigned long drbd_bm_ALe_set_all(struct drbd_conf *mdev,
		unsigned long al_enr);
extern size_t	     drbd_bm_words(struct drbd_conf *mdev);
extern unsigned long drbd_bm_bits(struct drbd_conf *mdev);
extern sector_t      drbd_bm_capacity(struct drbd_conf *mdev);
extern unsigned long drbd_bm_find_next(struct drbd_conf *mdev, unsigned long bm_fo);
/* bm_find_next variants for use while you hold drbd_bm_lock() */
extern unsigned long _drbd_bm_find_next(struct drbd_conf *mdev, unsigned long bm_fo);
extern unsigned long _drbd_bm_find_next_zero(struct drbd_conf *mdev, unsigned long bm_fo);
extern unsigned long drbd_bm_total_weight(struct drbd_conf *mdev);
extern int drbd_bm_rs_done(struct drbd_conf *mdev);
/* for receive_bitmap */
extern void drbd_bm_merge_lel(struct drbd_conf *mdev, size_t offset,
		size_t number, unsigned long *buffer);
/* for _drbd_send_bitmap and drbd_bm_write_sect */
extern void drbd_bm_get_lel(struct drbd_conf *mdev, size_t offset,
		size_t number, unsigned long *buffer);

extern void drbd_bm_lock(struct drbd_conf *mdev, char *why);
extern void drbd_bm_unlock(struct drbd_conf *mdev);

extern void _drbd_bm_recount_bits(struct drbd_conf *mdev, char *file, int line);
#define drbd_bm_recount_bits(mdev) \
	_drbd_bm_recount_bits(mdev, __FILE__, __LINE__)
extern int drbd_bm_count_bits(struct drbd_conf *mdev, const unsigned long s, const unsigned long e);
/* drbd_main.c */

/* needs to be included here,
 * because of kmem_cache_t weirdness */
#include "drbd_wrappers.h"

extern struct kmem_cache *drbd_request_cache;
extern struct kmem_cache *drbd_ee_cache;
extern mempool_t *drbd_request_mempool;
extern mempool_t *drbd_ee_mempool;

extern struct page *drbd_pp_pool; /* drbd's page pool */
extern spinlock_t   drbd_pp_lock;
extern int	    drbd_pp_vacant;
extern wait_queue_head_t drbd_pp_wait;

extern rwlock_t global_state_lock;

extern struct drbd_conf *drbd_new_device(unsigned int minor);
extern void drbd_free_mdev(struct drbd_conf *mdev);

/* Dynamic tracing framework */
#ifdef ENABLE_DYNAMIC_TRACE

extern int proc_details;
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
	TraceTypeRq	= 0x00000002,
	TraceTypeUuid	= 0x00000004,
	TraceTypeResync = 0x00000008,
	TraceTypeEE	= 0x00000010,
	TraceTypeUnplug = 0x00000020,
	TraceTypeNl	= 0x00000040,
	TraceTypeALExts = 0x00000080,
	TraceTypeIntRq  = 0x00000100,
	TraceTypeMDIO   = 0x00000200,
	TraceTypeEpochs = 0x00000400,
};

static inline int
is_trace(unsigned int type, unsigned int level) {
	return (trace_level >= level) && (type & trace_type);
}
static inline int
is_mdev_trace(struct drbd_conf *mdev, unsigned int type, unsigned int level) {
	return is_trace(type, level) &&
		((1 << mdev_to_minor(mdev)) & trace_devs);
}

#define MTRACE(type, lvl, code...) \
do { \
	if (unlikely(is_mdev_trace(mdev, type, lvl))) { \
		code \
	} \
} while (0)

#define TRACE(type, lvl, code...) \
do { \
	if (unlikely(is_trace(type, lvl))) { \
		code \
	} \
} while (0)

/* Buffer printing support
 * dbg_print_flags: used for Flags arg to drbd_print_buffer
 * - DBGPRINT_BUFFADDR; if set, each line starts with the
 *	 virtual address of the line being output. If clear,
 *	 each line starts with the offset from the beginning
 *	 of the buffer. */
enum dbg_print_flags {
    DBGPRINT_BUFFADDR = 0x0001,
};

extern void drbd_print_uuid(struct drbd_conf *mdev, unsigned int idx);

extern void drbd_print_buffer(const char *prefix, unsigned int flags, int size,
			      const void *buffer, const void *buffer_va,
			      unsigned int length);

/* Bio printing support */
extern void _dump_bio(const char *pfx, struct drbd_conf *mdev, struct bio *bio, int complete, struct drbd_request *r);

static inline void dump_bio(struct drbd_conf *mdev,
		struct bio *bio, int complete, struct drbd_request *r)
{
	MTRACE(TraceTypeRq, TraceLvlSummary,
	       _dump_bio("Rq", mdev, bio, complete, r);
		);
}

static inline void dump_internal_bio(const char *pfx, struct drbd_conf *mdev, struct bio *bio, int complete)
{
	MTRACE(TraceTypeIntRq, TraceLvlSummary,
	       _dump_bio(pfx, mdev, bio, complete, NULL);
		);
}

/* Packet dumping support */
extern void _dump_packet(struct drbd_conf *mdev, struct socket *sock,
			 int recv, union Drbd_Polymorph_Packet *p,
			 char *file, int line);

static inline void
dump_packet(struct drbd_conf *mdev, struct socket *sock,
	    int recv, union Drbd_Polymorph_Packet *p, char *file, int line)
{
	MTRACE(TraceTypePacket, TraceLvlSummary,
	       _dump_packet(mdev, sock, recv, p, file, line);
		);
}

#else

#define MTRACE(ignored...) ((void)0)
#define TRACE(ignored...) ((void)0)

#define dump_bio(ignored...) ((void)0)
#define dump_internal_bio(ignored...) ((void)0)
#define dump_packet(ignored...) ((void)0)
#endif

/* drbd_req */
extern int drbd_make_request_26(struct request_queue *q, struct bio *bio);
extern int drbd_read_remote(struct drbd_conf *mdev, struct drbd_request *req);
extern int drbd_merge_bvec(struct request_queue *q,
#ifdef HAVE_bvec_merge_data
		struct bvec_merge_data *bvm,
#else
		struct bio *bvm,
#endif
		struct bio_vec *bvec);
extern int is_valid_ar_handle(struct drbd_request *, sector_t);


/* drbd_nl.c */
extern void drbd_suspend_io(struct drbd_conf *mdev);
extern void drbd_resume_io(struct drbd_conf *mdev);
extern char *ppsize(char *buf, unsigned long long size);
extern sector_t drbd_new_dev_size(struct drbd_conf *,
		struct drbd_backing_dev *);
enum determin_dev_size_enum { dev_size_error = -1, unchanged = 0, shrunk = 1, grew = 2 };
extern enum determin_dev_size_enum drbd_determin_dev_size(struct drbd_conf *) __must_hold(local);
extern void resync_after_online_grow(struct drbd_conf *);
extern void drbd_setup_queue_param(struct drbd_conf *mdev, unsigned int) __must_hold(local);
extern int drbd_set_role(struct drbd_conf *mdev, enum drbd_role new_role,
		int force);
enum drbd_disk_state drbd_try_outdate_peer(struct drbd_conf *mdev);
extern int drbd_khelper(struct drbd_conf *mdev, char *cmd);

/* drbd_worker.c */
extern int drbd_worker(struct Drbd_thread *thi);
extern void drbd_alter_sa(struct drbd_conf *mdev, int na);
extern void drbd_start_resync(struct drbd_conf *mdev, enum drbd_conns side);
extern void resume_next_sg(struct drbd_conf *mdev);
extern void suspend_other_sg(struct drbd_conf *mdev);
extern int drbd_resync_finished(struct drbd_conf *mdev);
/* maybe rather drbd_main.c ? */
extern int drbd_md_sync_page_io(struct drbd_conf *mdev,
		struct drbd_backing_dev *bdev, sector_t sector, int rw);
extern void drbd_ov_oos_found(struct drbd_conf*, sector_t, int);

static inline void ov_oos_print(struct drbd_conf *mdev)
{
	if (mdev->ov_last_oos_size) {
		ERR("Out of sync: start=%llu, size=%lu (sectors)\n",
		     (unsigned long long)mdev->ov_last_oos_start,
		     (unsigned long)mdev->ov_last_oos_size);
	}
	mdev->ov_last_oos_size=0;
}


void drbd_csum(struct drbd_conf *, struct crypto_hash *, struct bio *, void *);
/* worker callbacks */
extern int w_req_cancel_conflict(struct drbd_conf *, struct drbd_work *, int);
extern int w_read_retry_remote(struct drbd_conf *, struct drbd_work *, int);
extern int w_e_end_data_req(struct drbd_conf *, struct drbd_work *, int);
extern int w_e_end_rsdata_req(struct drbd_conf *, struct drbd_work *, int);
extern int w_e_end_csum_rs_req(struct drbd_conf *, struct drbd_work *, int);
extern int w_e_end_ov_reply(struct drbd_conf *, struct drbd_work *, int);
extern int w_e_end_ov_req(struct drbd_conf *, struct drbd_work *, int);
extern int w_ov_finished(struct drbd_conf *, struct drbd_work *, int);
extern int w_resync_inactive(struct drbd_conf *, struct drbd_work *, int);
extern int w_resume_next_sg(struct drbd_conf *, struct drbd_work *, int);
extern int w_io_error(struct drbd_conf *, struct drbd_work *, int);
extern int w_send_write_hint(struct drbd_conf *, struct drbd_work *, int);
extern int w_make_resync_request(struct drbd_conf *, struct drbd_work *, int);
extern int w_send_dblock(struct drbd_conf *, struct drbd_work *, int);
extern int w_send_barrier(struct drbd_conf *, struct drbd_work *, int);
extern int w_send_read_req(struct drbd_conf *, struct drbd_work *, int);
extern int w_prev_work_done(struct drbd_conf *, struct drbd_work *, int);
extern int w_e_reissue(struct drbd_conf *, struct drbd_work *, int);

extern void resync_timer_fn(unsigned long data);

/* drbd_receiver.c */
extern int drbd_release_ee(struct drbd_conf *mdev, struct list_head *list);
extern struct Tl_epoch_entry *drbd_alloc_ee(struct drbd_conf *mdev,
					    u64 id,
					    sector_t sector,
					    unsigned int data_size,
					    gfp_t gfp_mask) __must_hold(local);
extern void drbd_free_ee(struct drbd_conf *mdev, struct Tl_epoch_entry *e);
extern void drbd_wait_ee_list_empty(struct drbd_conf *mdev,
		struct list_head *head);
extern void _drbd_wait_ee_list_empty(struct drbd_conf *mdev,
		struct list_head *head);
extern void drbd_set_recv_tcq(struct drbd_conf *mdev, int tcq_enabled);
extern void _drbd_clear_done_ee(struct drbd_conf *mdev);

/* yes, there is kernel_setsockopt, but only since 2.6.18. we don't need to
 * mess with get_fs/set_fs, we know we are KERNEL_DS always. */
static inline int drbd_setsockopt(struct socket *sock, int level, int optname,
			char __user *optval, int optlen)
{
	int err;
	if (level == SOL_SOCKET)
		err = sock_setsockopt(sock, level, optname, optval, optlen);
	else
		err = sock->ops->setsockopt(sock, level, optname, optval,
					    optlen);
	return err;
}

static inline void drbd_tcp_cork(struct socket *sock)
{
	int __user val = 1;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_CORK,
			(char __user *)&val, sizeof(val));
}

static inline void drbd_tcp_uncork(struct socket *sock)
{
	int __user val = 0;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_CORK,
			(char __user *)&val, sizeof(val));
}

static inline void drbd_tcp_nodelay(struct socket *sock)
{
	int __user val = 1;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_NODELAY,
			(char __user *)&val, sizeof(val));
}

static inline void drbd_tcp_quickack(struct socket *sock)
{
	int __user val = 1;
	(void) drbd_setsockopt(sock, SOL_TCP, TCP_QUICKACK,
			(char __user *)&val, sizeof(val));
}

void drbd_bump_write_ordering(struct drbd_conf *mdev, enum write_ordering_e wo);

/* drbd_proc.c */
extern struct proc_dir_entry *drbd_proc;
extern struct file_operations drbd_proc_fops;
extern const char *conns_to_name(enum drbd_conns s);
extern const char *roles_to_name(enum drbd_role s);

/* drbd_actlog.c */
extern void drbd_al_begin_io(struct drbd_conf *mdev, sector_t sector);
extern void drbd_al_complete_io(struct drbd_conf *mdev, sector_t sector);
extern void drbd_rs_complete_io(struct drbd_conf *mdev, sector_t sector);
extern int drbd_rs_begin_io(struct drbd_conf *mdev, sector_t sector);
extern int drbd_try_rs_begin_io(struct drbd_conf *mdev, sector_t sector);
extern void drbd_rs_cancel_all(struct drbd_conf *mdev);
extern int drbd_rs_del_all(struct drbd_conf *mdev);
extern void drbd_rs_failed_io(struct drbd_conf *mdev,
		sector_t sector, int size);
extern int drbd_al_read_log(struct drbd_conf *mdev, struct drbd_backing_dev *);
extern void __drbd_set_in_sync(struct drbd_conf *mdev, sector_t sector,
		int size, const char *file, const unsigned int line);
#define drbd_set_in_sync(mdev, sector, size) \
	__drbd_set_in_sync(mdev, sector, size, __FILE__, __LINE__)
extern void __drbd_set_out_of_sync(struct drbd_conf *mdev, sector_t sector,
		int size, const char *file, const unsigned int line);
#define drbd_set_out_of_sync(mdev, sector, size) \
	__drbd_set_out_of_sync(mdev, sector, size, __FILE__, __LINE__)
extern void drbd_al_apply_to_bm(struct drbd_conf *mdev);
extern void drbd_al_to_on_disk_bm(struct drbd_conf *mdev);
extern void drbd_al_shrink(struct drbd_conf *mdev);


/* drbd_nl.c */

void drbd_nl_cleanup(void);
int __init drbd_nl_init(void);
void drbd_bcast_state(struct drbd_conf *mdev, union drbd_state_t);
void drbd_bcast_sync_progress(struct drbd_conf *mdev);
void drbd_bcast_ee(struct drbd_conf *mdev,
		const char *reason, const int dgs,
		const char* seen_hash, const char* calc_hash,
		const struct Tl_epoch_entry* e);

/*
 * inline helper functions
 *************************/

#define peer_mask role_mask
#define pdsk_mask disk_mask
#define susp_mask 1
#define user_isp_mask 1
#define aftr_isp_mask 1

/* drbd state debug */
#if DRBD_DEBUG_STATE_CHANGES
#define DRBD_STATE_DEBUG_INIT_VAL(s) ({ (s).line = __LINE__; (s).func = __func__; })
#else
#define DRBD_STATE_DEBUG_INIT_VAL(s) do { } while (0)
#endif

#define NS(T, S) \
	({ union drbd_state_t mask; mask.i = 0; mask.T = T##_mask; mask; }), \
	({ union drbd_state_t val; DRBD_STATE_DEBUG_INIT_VAL(val); val.i = 0; val.T = (S); val; })
#define NS2(T1, S1, T2, S2) \
	({ union drbd_state_t mask; mask.i = 0; mask.T1 = T1##_mask; \
	  mask.T2 = T2##_mask; mask; }), \
	({ union drbd_state_t val; DRBD_STATE_DEBUG_INIT_VAL(val); val.i = 0; val.T1 = (S1); \
	  val.T2 = (S2); val; })
#define NS3(T1, S1, T2, S2, T3, S3) \
	({ union drbd_state_t mask; mask.i = 0; mask.T1 = T1##_mask; \
	  mask.T2 = T2##_mask; mask.T3 = T3##_mask; mask; }), \
	({ union drbd_state_t val; DRBD_STATE_DEBUG_INIT_VAL(val); val.i = 0; val.T1 = (S1); \
	  val.T2 = (S2); val.T3 = (S3); val; })

#define _NS(D, T, S) \
	D, ({ union drbd_state_t __ns; DRBD_STATE_DEBUG_INIT_VAL(__ns); __ns.i = D->state.i; __ns.T = (S); __ns; })
#define _NS2(D, T1, S1, T2, S2) \
	D, ({ union drbd_state_t __ns; DRBD_STATE_DEBUG_INIT_VAL(__ns); __ns.i = D->state.i; __ns.T1 = (S1); \
	__ns.T2 = (S2); __ns; })
#define _NS3(D, T1, S1, T2, S2, T3, S3) \
	D, ({ union drbd_state_t __ns; DRBD_STATE_DEBUG_INIT_VAL(__ns); __ns.i = D->state.i; __ns.T1 = (S1); \
	__ns.T2 = (S2); __ns.T3 = (S3); __ns; })

static inline void drbd_state_lock(struct drbd_conf *mdev)
{
	wait_event(mdev->misc_wait,
		   !test_and_set_bit(CLUSTER_ST_CHANGE, &mdev->flags));
}

static inline void drbd_state_unlock(struct drbd_conf *mdev)
{
	clear_bit(CLUSTER_ST_CHANGE, &mdev->flags);
	wake_up(&mdev->misc_wait);
}

static inline int _drbd_set_state(struct drbd_conf *mdev,
				   union drbd_state_t ns, enum chg_state_flags flags,
				   struct completion *done)
{
	int rv;

	read_lock(&global_state_lock);
	rv = __drbd_set_state(mdev, ns, flags, done);
	read_unlock(&global_state_lock);

	return rv;
}

static inline int drbd_request_state(struct drbd_conf *mdev,
				     union drbd_state_t mask,
				     union drbd_state_t val)
{
	return _drbd_request_state(mdev, mask, val, ChgStateVerbose + ChgOrdered);
}

/**
 * drbd_chk_io_error: Handles the on_io_error setting, should be called from
 * all io completion handlers. See also drbd_io_error().
 */
static inline void __drbd_chk_io_error(struct drbd_conf *mdev, int forcedetach)
{
	switch (mdev->bc->dc.on_io_error) {
	case PassOn: /* FIXME would this be better named "Ignore"? */
		if (!forcedetach) {
			if (printk_ratelimit())
				ERR("Local IO failed. Passing error on...\n");
			break;
		}
		/* NOTE fall through to detach case if forcedetach set */
	case Detach:
	case CallIOEHelper:
		if (mdev->state.disk > Failed) {
			_drbd_set_state(_NS(mdev, disk, Failed), ChgStateHard, NULL);
			ERR("Local IO failed. Detaching...\n");
		}
		break;
	}
}

static inline void drbd_chk_io_error(struct drbd_conf *mdev,
	int error, int forcedetach)
{
	if (error) {
		unsigned long flags;
		spin_lock_irqsave(&mdev->req_lock, flags);
		__drbd_chk_io_error(mdev, forcedetach);
		spin_unlock_irqrestore(&mdev->req_lock, flags);
	}
}

static inline int semaphore_is_locked(struct semaphore *s)
{
	if (!down_trylock(s)) {
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
		return bdev->md.md_offset + MD_AL_OFFSET - 1;
	case DRBD_MD_INDEX_FLEX_EXT:
	default:
		return bdev->md.md_offset + bdev->md.md_size_sect;
	}
}

/* returns the capacity we announce to out peer.
 * we clip ourselves at the various MAX_SECTORS, because if we don't,
 * current implementation will oops sooner or later */
static inline sector_t drbd_get_max_capacity(struct drbd_backing_dev *bdev)
{
	sector_t s;
	switch (bdev->dc.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		s = drbd_get_capacity(bdev->backing_bdev)
			? min_t(sector_t, DRBD_MAX_SECTORS_FLEX,
					drbd_md_first_sector(bdev))
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

/* returns the sector number of our meta data 'super' block */
static inline sector_t drbd_md_ss__(struct drbd_conf *mdev,
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
			if (DRBD_ratelimit(5*HZ, 5)) {
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
	list_add_tail(&w->list, &q->q);
	up(&q->s);
}

static inline void
drbd_queue_work_front(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add(&w->list, &q->q);
	up(&q->s); /* within the spinlock,
		      see comment near end of drbd_worker() */
	spin_unlock_irqrestore(&q->q_lock, flags);
}

static inline void
drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;
	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	up(&q->s); /* within the spinlock,
		      see comment near end of drbd_worker() */
	spin_unlock_irqrestore(&q->q_lock, flags);
}

static inline void wake_asender(struct drbd_conf *mdev)
{
	if (test_bit(SIGNAL_ASENDER, &mdev->flags))
		force_sig(DRBD_SIG, mdev->asender.task);
}

static inline void request_ping(struct drbd_conf *mdev)
{
	set_bit(SEND_PING, &mdev->flags);
	wake_asender(mdev);
}

static inline int drbd_send_short_cmd(struct drbd_conf *mdev,
	enum Drbd_Packet_Cmd cmd)
{
	struct Drbd_Header h;
	return drbd_send_cmd(mdev, USE_DATA_SOCKET, cmd, &h, sizeof(h));
}

static inline int drbd_send_ping(struct drbd_conf *mdev)
{
	struct Drbd_Header h;
	return drbd_send_cmd(mdev, USE_META_SOCKET, Ping, &h, sizeof(h));
}

static inline int drbd_send_ping_ack(struct drbd_conf *mdev)
{
	struct Drbd_Header h;
	return drbd_send_cmd(mdev, USE_META_SOCKET, PingAck, &h, sizeof(h));
}

static inline void drbd_thread_stop(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi, FALSE, TRUE);
}

static inline void drbd_thread_stop_nowait(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi, FALSE, FALSE);
}

static inline void drbd_thread_restart_nowait(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi, TRUE, FALSE);
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
static inline void inc_ap_pending(struct drbd_conf *mdev)
{
	atomic_inc(&mdev->ap_pending_cnt);
}

#define ERR_IF_CNT_IS_NEGATIVE(which)				\
	if (atomic_read(&mdev->which) < 0)			\
		ERR("in %s:%d: " #which " = %d < 0 !\n",	\
		    __func__ , __LINE__ ,			\
		    atomic_read(&mdev->which))

#define dec_ap_pending(mdev)	do {				\
	typecheck(struct drbd_conf *, mdev);			\
	if (atomic_dec_and_test(&mdev->ap_pending_cnt))		\
		wake_up(&mdev->misc_wait);			\
	ERR_IF_CNT_IS_NEGATIVE(ap_pending_cnt); } while (0)

/* counts how many resync-related answers we still expect from the peer
 *		     increase			decrease
 * SyncTarget sends RSDataRequest (and expects RSDataReply)
 * SyncSource sends RSDataReply   (and expects WriteAck whith ID_SYNCER)
 *					   (or NegAck with ID_SYNCER)
 */
static inline void inc_rs_pending(struct drbd_conf *mdev)
{
	atomic_inc(&mdev->rs_pending_cnt);
}

#define dec_rs_pending(mdev)	do {				\
	typecheck(struct drbd_conf *, mdev);			\
	atomic_dec(&mdev->rs_pending_cnt);			\
	ERR_IF_CNT_IS_NEGATIVE(rs_pending_cnt); } while (0)

/* counts how many answers we still need to send to the peer.
 * increased on
 *  receive_Data	unless protocol A;
 *			we need to send a RecvAck (proto B)
 *			or WriteAck (proto C)
 *  receive_RSDataReply (recv_resync_read) we need to send a WriteAck
 *  receive_DataRequest (receive_RSDataRequest) we need to send back Data
 *  receive_Barrier_*	we need to send a BarrierAck
 */
static inline void inc_unacked(struct drbd_conf *mdev)
{
	atomic_inc(&mdev->unacked_cnt);
}

#define dec_unacked(mdev)	do {				\
	typecheck(struct drbd_conf *, mdev);			\
	atomic_dec(&mdev->unacked_cnt);				\
	ERR_IF_CNT_IS_NEGATIVE(unacked_cnt); } while (0)

#define sub_unacked(mdev, n)	do {				\
	typecheck(struct drbd_conf *, mdev);			\
	atomic_sub(n, &mdev->unacked_cnt);			\
	ERR_IF_CNT_IS_NEGATIVE(unacked_cnt); } while (0)


static inline void dec_net(struct drbd_conf *mdev)
{
	if (atomic_dec_and_test(&mdev->net_cnt))
		wake_up(&mdev->misc_wait);
}

/**
 * inc_net: Returns TRUE when it is ok to access mdev->net_conf. You
 * should call dec_net() when finished looking at mdev->net_conf.
 */
static inline int inc_net(struct drbd_conf *mdev)
{
	int have_net_conf;

	atomic_inc(&mdev->net_cnt);
	have_net_conf = mdev->state.conn >= Unconnected;
	if (!have_net_conf)
		dec_net(mdev);
	return have_net_conf;
}

/**
 * inc_local: Returns TRUE when local IO is possible. If it returns
 * TRUE you should call dec_local() after IO is completed.
 */
#define inc_local_if_state(M,MINS) __cond_lock(local, _inc_local_if_state(M,MINS))
#define inc_local(M) __cond_lock(local, _inc_local_if_state(M,Inconsistent))

static inline void dec_local(struct drbd_conf *mdev)
{
	__release(local);
	if (atomic_dec_and_test(&mdev->local_cnt))
		wake_up(&mdev->misc_wait);
	D_ASSERT(atomic_read(&mdev->local_cnt) >= 0);
}

#ifndef __CHECKER__
static inline int _inc_local_if_state(struct drbd_conf *mdev, enum drbd_disk_state mins)
{
	int io_allowed;

	atomic_inc(&mdev->local_cnt);
	io_allowed = (mdev->state.disk >= mins);
	if (!io_allowed)
		dec_local(mdev);
	return io_allowed;
}
#else
extern int _inc_local_if_state(struct drbd_conf *mdev, enum drbd_disk_state mins);
#endif

/* you must have an "inc_local" reference */
static inline void drbd_get_syncer_progress(struct drbd_conf *mdev,
		unsigned long *bits_left, unsigned int *per_mil_done)
{
	/*
	 * this is to break it at compile time when we change that
	 * (we may feel 4TB maximum storage per drbd is not enough)
	 */
	typecheck(unsigned long, mdev->rs_total);

	/* note: both rs_total and rs_left are in bits, i.e. in
	 * units of BM_BLOCK_SIZE.
	 * for the percentage, we don't care. */

	*bits_left = drbd_bm_total_weight(mdev) - mdev->rs_failed;
	/* >> 10 to prevent overflow,
	 * +1 to prevent division by zero */
	if (*bits_left > mdev->rs_total) {
		/* doh. maybe a logic bug somewhere.
		 * may also be just a race condition
		 * between this and a disconnect during sync.
		 * for now, just prevent in-kernel buffer overflow.
		 */
		smp_rmb();
		drbd_WARN("cs:%s rs_left=%lu > rs_total=%lu (rs_failed %lu)\n",
				conns_to_name(mdev->state.conn),
				*bits_left, mdev->rs_total, mdev->rs_failed);
		*per_mil_done = 0;
	} else {
		/* make sure the calculation happens in long context */
		unsigned long tmp = 1000UL -
				(*bits_left >> 10)*1000UL
				/ ((mdev->rs_total >> 10) + 1UL);
		*per_mil_done = tmp;
	}
}


/* this throttles on-the-fly application requests
 * according to max_buffers settings;
 * maybe re-implement using semaphores? */
static inline int drbd_get_max_buffers(struct drbd_conf *mdev)
{
	int mxb = 1000000; /* arbitrary limit on open requests */
	if (inc_net(mdev)) {
		mxb = mdev->net_conf->max_buffers;
		dec_net(mdev);
	}
	return mxb;
}

static inline int drbd_state_is_stable(union drbd_state_t s)
{

	/* DO NOT add a default clause, we want the compiler to warn us
	 * for any newly introduced state we may have forgotten to add here */

	switch ((enum drbd_conns)s.conn) {
	/* new io only accepted when there is no connection, ... */
	case StandAlone:
	case WFConnection:
	/* ... or there is a well established connection. */
	case Connected:
	case SyncSource:
	case SyncTarget:
	case VerifyS:
	case VerifyT:
	case PausedSyncS:
	case PausedSyncT:
		/* maybe stable, look at the disk state */
		break;

	/* no new io accepted during tansitional states
	 * like handshake or teardown */
	case Disconnecting:
	case Unconnected:
	case Timeout:
	case BrokenPipe:
	case NetworkFailure:
	case ProtocolError:
	case TearDown:
	case WFReportParams:
	case StartingSyncS:
	case StartingSyncT:
	case WFBitMapS:
	case WFBitMapT:
	case WFSyncUUID:
	case conn_mask:
		/* not "stable" */
		return 0;
	}

	switch ((enum drbd_disk_state)s.disk) {
	case Diskless:
	case Inconsistent:
	case Outdated:
	case Consistent:
	case UpToDate:
		/* disk state is stable as well. */
		break;

	/* no new io accepted during tansitional states */
	case Attaching:
	case Failed:
	case Negotiating:
	case DUnknown:
	case disk_mask:
		/* not "stable" */
		return 0;
	}

	return 1;
}

static inline int __inc_ap_bio_cond(struct drbd_conf *mdev)
{
	int mxb = drbd_get_max_buffers(mdev);

	if (mdev->state.susp)
		return 0;
	if (test_bit(SUSPEND_IO, &mdev->flags))
		return 0;

	/* to avoid potential deadlock or bitmap corruption,
	 * in various places, we only allow new application io
	 * to start during "stable" states. */

	/* no new io accepted when attaching or detaching the disk */
	if (!drbd_state_is_stable(mdev->state))
		return 0;

	/* since some older kernels don't have atomic_add_unless,
	 * and we are within the spinlock anyways, we have this workaround.  */
	if (atomic_read(&mdev->ap_bio_cnt) > mxb)
		return 0;
	if (test_bit(BITMAP_IO, &mdev->flags))
		return 0;
	return 1;
}

/* I'd like to use wait_event_lock_irq,
 * but I'm not sure when it got introduced,
 * and not sure when it has 3 or 4 arguments */
static inline void inc_ap_bio(struct drbd_conf *mdev, int one_or_two)
{
	/* compare with after_state_ch,
	 * os.conn != WFBitMapS && ns.conn == WFBitMapS */
	DEFINE_WAIT(wait);

	/* we wait here
	 *    as long as the device is suspended
	 *    until the bitmap is no longer on the fly during connection
	 *    handshake as long as we would exeed the max_buffer limit.
	 *
	 * to avoid races with the reconnect code,
	 * we need to atomic_inc within the spinlock. */

	spin_lock_irq(&mdev->req_lock);
	while (!__inc_ap_bio_cond(mdev)) {
		prepare_to_wait(&mdev->misc_wait, &wait, TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&mdev->req_lock);
		schedule();
		finish_wait(&mdev->misc_wait, &wait);
		spin_lock_irq(&mdev->req_lock);
	}
	atomic_add(one_or_two, &mdev->ap_bio_cnt);
	spin_unlock_irq(&mdev->req_lock);
}

static inline void dec_ap_bio(struct drbd_conf *mdev)
{
	int mxb = drbd_get_max_buffers(mdev);
	int ap_bio = atomic_dec_return(&mdev->ap_bio_cnt);

	D_ASSERT(ap_bio >= 0);
	/* this currently does wake_up for every dec_ap_bio!
	 * maybe rather introduce some type of hysteresis?
	 * e.g. (ap_bio == mxb/2 || ap_bio == 0) ? */
	if (ap_bio < mxb)
		wake_up(&mdev->misc_wait);
	if (ap_bio == 0 && test_bit(BITMAP_IO, &mdev->flags)) {
		if (!test_and_set_bit(BITMAP_IO_QUEUED, &mdev->flags))
			drbd_queue_work(&mdev->data.work, &mdev->bm_io_work.w);
	}
}

static inline void drbd_set_ed_uuid(struct drbd_conf *mdev, u64 val)
{
	mdev->ed_uuid = val;

	MTRACE(TraceTypeUuid, TraceLvlMetrics,
	       INFO(" exposed data uuid now %016llX\n",
		    (unsigned long long)val);
		);
}

static inline int seq_cmp(u32 a, u32 b)
{
	/* we assume wrap around at 32bit.
	 * for wrap around at 24bit (old atomic_t),
	 * we'd have to
	 *  a <<= 8; b <<= 8;
	 */
	return (s32)(a) - (s32)(b);
}
#define seq_lt(a, b) (seq_cmp((a), (b)) < 0)
#define seq_gt(a, b) (seq_cmp((a), (b)) > 0)
#define seq_ge(a, b) (seq_cmp((a), (b)) >= 0)
#define seq_le(a, b) (seq_cmp((a), (b)) <= 0)
/* CAUTION: please no side effects in arguments! */
#define seq_max(a, b) ((u32)(seq_gt((a), (b)) ? (a) : (b)))

static inline void update_peer_seq(struct drbd_conf *mdev, unsigned int new_seq)
{
	unsigned int m;
	spin_lock(&mdev->peer_seq_lock);
	m = seq_max(mdev->peer_seq, new_seq);
	mdev->peer_seq = m;
	spin_unlock(&mdev->peer_seq_lock);
	if (m == new_seq)
		wake_up(&mdev->seq_wait);
}

static inline void drbd_update_congested(struct drbd_conf *mdev)
{
	struct sock *sk = mdev->data.socket->sk;
	if (sk->sk_wmem_queued > sk->sk_sndbuf * 4 / 5)
		set_bit(NET_CONGESTED, &mdev->flags);
}

static inline int drbd_queue_order_type(struct drbd_conf *mdev)
{
	/* sorry, we currently have no working implementation
	 * of distributed TCQ stuff */
#ifndef QUEUE_ORDERED_NONE
#define QUEUE_ORDERED_NONE 0
#endif
	return QUEUE_ORDERED_NONE;
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
static inline void drbd_blk_run_queue(struct request_queue *q)
{
	if (q && q->unplug_fn)
		q->unplug_fn(q);
}

static inline void drbd_kick_lo(struct drbd_conf *mdev)
{
	if (inc_local(mdev)) {
		drbd_blk_run_queue(bdev_get_queue(mdev->bc->backing_bdev));
		dec_local(mdev);
	}
}

static inline void drbd_md_flush(struct drbd_conf *mdev)
{
	int r;

	if (test_bit(MD_NO_BARRIER, &mdev->flags))
		return;

	r = blkdev_issue_flush(mdev->bc->md_bdev, NULL);
	if (r) {
		set_bit(MD_NO_BARRIER, &mdev->flags);
		ERR("meta data flush failed with status %d, disabling md-flushes\n", r);
	}
}

#endif
