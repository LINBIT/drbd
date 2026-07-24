// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2014, LINBIT HA-Solutions GmbH.
 */

#undef pr_fmt
#define pr_fmt(fmt)	"drbd_rdma2: " fmt

#include <linux/module.h>
#include <linux/sched/signal.h>
#include <linux/bio.h>
#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_cm.h>
#include <linux/interrupt.h>
#include <linux/drbd.h>
#include <linux/drbd_genl.h>
#include <linux/drbd_nl_gen.h>
#include "drbd_protocol.h"
#include "drbd_transport.h"
#include "linux/drbd_config.h" /* for REL_VERSION */

/*
 * v6.8-rc1-3-g5e0a760b4441 ("mm, treewide: rename MAX_ORDER to MAX_PAGE_ORDER")
 * also changed the meaning: MAX_ORDER was exclusive (the largest allocatable
 * order was MAX_ORDER - 1), MAX_PAGE_ORDER is inclusive.
 */
#ifndef MAX_PAGE_ORDER
#define MAX_PAGE_ORDER (MAX_ORDER - 1)
#endif

/*
 * This transport carries both of DRBD's streams over one-sided RDMA WRITEs.
 *
 * Payload transfer
 * ================
 *
 * Each side registers per-stream receive regions (physically contiguous
 * runs of split order-0 pages, fast-reg MRs with REMOTE_WRITE) and
 * announces them to the peer as {addr, rkey, len, stride}. The sender
 * RDMA-WRITEs DATA and CONTROL packets straight into the peer's current
 * region with IB_WR_RDMA_WRITE_WITH_IMM; the immediate carries {stream,
 * sequence}. The receiver's recv WRs are buffer-less (num_sge = 0),
 * consumed only to deliver the immediates: the receiver never learns a
 * write's target address from the wire, it advances its own cursor through
 * the announced region by each write's size rounded up to the region's
 * stride (a cache line, or the alignment the receiver's backing devices
 * need -- see dtr_region_stride()), in completion order (which on an RC QP
 * equals posted order -- see dtr_reserve_and_post()). Neighbouring writes
 * may thus share a region page; the receiver reference-counts the pages.
 * The pages a payload landed in are handed up to DRBD without copying; a
 * fully consumed region is re-registered over fresh pages and re-announced.
 *
 * Flow control
 * ============
 *
 * Three mechanisms throttle a sender, per path:
 *  - WR credits: how many recv WRs the peer has posted per stream
 *    (peer_rx_descs), granted/replenished with dtr_flow_control records.
 *  - Region space: an RDMA WRITE needs room in the peer's announced
 *    receive region; when the window is empty the sender sleeps until the
 *    peer announces a recycled region.
 *  - The FLOW_CTRL pool: flow-control, region-announce and shutdown
 *    records ride a per-path one-page control ring (RDMA-written, slot =
 *    sequence % DTR_FLOW_CTRL_DESCS) bounded by its own credit pool, so
 *    they never compete with payload for credits. These records are
 *    consumed by the transport itself, never delivered to DRBD.
 *
 * Bootstrap
 * =========
 *
 * A fresh connection has no ring or regions yet: the first records
 * (flow-control, ring announce) travel as IB_WR_SEND_WITH_IMM into
 * page-backed bootstrap recv WRs. The first RDMA write seen on a path
 * proves the SEND phase is over (single RC QP, in-order delivery); from
 * then on recv WRs are posted buffer-less. See dtr_ring.rx_got_rdma_write.
 */

MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_AUTHOR("Philipp Reisner <philipp.reisner@linbit.com>");
MODULE_AUTHOR("Lars Ellenberg <lars.ellenberg@linbit.com>");
MODULE_DESCRIPTION("rdma2 (one-sided RDMA-WRITE) transport layer for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION(REL_VERSION);

/*
 * If no recvbuf_size or sendbuf_size is configured, use 1M plus two pages
 * for the DATA_STREAM. This is not actually a buffer size, but the number
 * of tx_descs or rx_descs we allow, comparable to the socket sendbuf and
 * recvbuf sizes.
 */
#define RDMA_DEF_BUFFER_SIZE (DRBD_MAX_BIO_SIZE + 2 * PAGE_SIZE)

/* If we can send less than 8 packets, we consider the transport as congested. */
#define DESCS_LOW_LEVEL 8

/*
 * Assuming that a single 4k write should be at most scattered over 8
 * pages, i.e. has no parts smaller than 512 bytes.
 * Arbitrary assumption. It seems that Mellanox hardware can do up to 29.
 * ppc64 page size might be 64k.
 */
#if (PAGE_SIZE / 512) > 28
# define DTR_MAX_TX_SGES 28
#else
# define DTR_MAX_TX_SGES (PAGE_SIZE / 512)
#endif

#define DTR_MAGIC ((u32)0x5257494E)

/*
 * These numbers are sent within the immediate data value to identify
 * if the packet is a data, control, or (transport private) flow_control
 * message.
 */
enum dtr_stream_nr {
	ST_DATA = DATA_STREAM,
	ST_CONTROL = CONTROL_STREAM,
	ST_FLOW_CTRL
};

/* Flow-control and announce records share a {magic, send_from_stream} header so
 * the tx-completion path can recover send_from_stream from either without
 * knowing the record type, and the rx path can disambiguate on the magic.
 */
struct dtr_flow_control {
	uint32_t magic;
	uint32_t send_from_stream;
	/* Receive-window grants, indexed by stream. [DATA]/[CONTROL] grant payload
	 * recv WRs as before; [ST_FLOW_CTRL] grants control-ring slots, returning
	 * the credit the peer's ring writer spends per flow-control / announce
	 * record (see the FLOW_CTRL credit pool below).
	 */
	uint32_t new_rx_descs[ST_FLOW_CTRL + 1];
} __packed;

#define DTR_ANNOUNCE_MAGIC ((u32)0x414E4E43) /* "ANNC" */

/* Announce one RDMA-WRITE receive region we registered to the peer: where and
 * with which rkey it may RDMA-WRITE into it, and which stream it serves. Sent
 * (like dtr_flow_control) as an ST_FLOW_CTRL message, so it carries the same
 * @send_from_stream credit-accounting role. One region per message keeps the
 * registration path simple (no partial-batch bookkeeping).
 */
struct dtr_announce_buffer {
	uint32_t magic;             /* DTR_ANNOUNCE_MAGIC */
	uint32_t send_from_stream;  /* same role as in dtr_flow_control */
	uint64_t addr;              /* remote VA of the region */
	uint32_t rkey;              /* MR rkey */
	uint32_t len;               /* region length in bytes */
	uint32_t region_stream;     /* stream this region serves (DATA/CONTROL) */
	uint32_t stride;            /* consume granularity, see dtr_region_stride() */
} __packed;

#define DTR_SHUTDOWN_MAGIC ((u32)0x53485554) /* "SHUT" */

/* Graceful path-removal marker -- the RDMA analog of a TCP FIN. RC QPs have no
 * half-close, so del-path announces "I will send no more payload on this path"
 * with this record instead. Sent (like dtr_announce_buffer) as an ST_FLOW_CTRL
 * record on the path's control ring, so it shares the {magic, send_from_stream}
 * header and the same credit-accounting role, and -- crucially -- rides the one
 * RC QP that also carries this path's DATA/CONTROL RDMA-writes, so it is
 * delivered in order after every payload already posted here. See
 * dtr_remove_path() / dtr_got_shutdown_msg().
 */
struct dtr_shutdown {
	uint32_t magic;             /* DTR_SHUTDOWN_MAGIC */
	uint32_t send_from_stream;  /* same role as in dtr_flow_control */
} __packed;

/* Size of the dedicated flow-control / announce credit pool: how many such
 * records may be in flight before the writer must wait. It also fixes the
 * number of slots in the control ring (one slot per credit), so the pool alone
 * bounds the ring writer and it can never lap an unread slot.
 */
#define DTR_FLOW_CTRL_DESCS 64

/* Floor for a stream's registered receive window. A single packet may be up to
 * DRBD_SOCKET_BUFFER_SIZE, and a region whose tail cannot take the next write
 * is abandoned there (see __dtr_find_remote_buffer()), so leave room for a
 * handful of maximum-sized packets per region.
 */
#define DTR_MIN_REGION_BYTES (8 * DRBD_SOCKET_BUFFER_SIZE)

/* Recv WRs to post per stream while the peer may still SEND. Every desc posted
 * in that phase has to carry a page (a SEND lands in whichever desc is at the
 * head of the QP's single receive queue, so there is no way to have only some
 * of them buffered), and the phase is short: a flow-control record, the peer's
 * ring announce and its first region announces, then its writes go one-sided
 * and the window is filled buffer-less. Post just enough to carry that
 * handshake and to grant the peer a credit on every stream.
 */
#define DTR_BOOTSTRAP_RX_DESCS 16

/* Control-ring slot size. 64 B holds either record (dtr_flow_control /
 * dtr_announce_buffer) with headroom; the whole ring is one page
 * (64 * 64 == PAGE_SIZE).
 */
#define DTR_RING_SLOT_SIZE 64

/*
 * IB_WR_SEND_WITH_IMM and IB_WR_RDMA_WRITE_WITH_IMM both transfer user data
 * and a 32-bit value which is delivered at the receiving end to the event
 * handler of the completion queue. This can be used to queue the incoming
 * messages to different streams.
 *
 * We pack a 2-bit stream identifier and a 30-bit sequence number into this
 * 32-bit immediate value:
 *
 *   Bits 31..30: stream (ST_DATA, ST_CONTROL, or ST_FLOW_CTRL)
 *   Bits 29..0:  sequence number for message ordering
 *
 * The stream field identifies which logical channel (data, control, or
 * transport-private flow control) a message belongs to, allowing us to fold
 * all three into a single RDMA connection. The sequence number lets the
 * receiver reorder messages before delivering them to upper layers.
 *
 * Byte order conversion happens at the wire boundary via cpu_to_be32() /
 * be32_to_cpu(), so these helpers operate on native CPU integers.
 */
#define DTR_IMM_SEQUENCE_BITS	30
#define DTR_IMM_SEQUENCE_MASK	((1U << DTR_IMM_SEQUENCE_BITS) - 1)
#define DTR_IMM_STREAM_SHIFT	DTR_IMM_SEQUENCE_BITS

static inline u32 dtr_imm_encode(unsigned int stream, unsigned int sequence)
{
	return (stream << DTR_IMM_STREAM_SHIFT) |
	       (sequence & DTR_IMM_SEQUENCE_MASK);
}

static inline unsigned int dtr_imm_stream(u32 imm)
{
	return imm >> DTR_IMM_STREAM_SHIFT;
}

static inline unsigned int dtr_imm_sequence(u32 imm)
{
	return imm & DTR_IMM_SEQUENCE_MASK;
}

/* Advance a sequence number by one, wrapping around at the 30-bit boundary. */
static inline unsigned int dtr_seq_next(unsigned int seq)
{
	return (seq + 1) & DTR_IMM_SEQUENCE_MASK;
}

/*
 * Return true if sequence number @a is ahead of @b in the circular
 * sequence space. Uses the sign bit of the difference to handle wrap.
 */
static inline bool dtr_seq_greater(unsigned int a, unsigned int b)
{
	unsigned int diff = a - b;

	return !(diff & (1U << (DTR_IMM_SEQUENCE_BITS - 1)));
}


enum dtr_state_bits {
	DSB_CONNECT_REQ,
	DSB_CONNECTING,
	DSB_CONNECTED,
	DSB_ERROR,
};

#define DSM_CONNECT_REQ   (1 << DSB_CONNECT_REQ)
#define DSM_CONNECTING    (1 << DSB_CONNECTING)
#define DSM_CONNECTED     (1 << DSB_CONNECTED)
#define DSM_ERROR         (1 << DSB_ERROR)

/* Out-of-band per-cm flags. Kept separate from cm->state because several
 * places compare cm->state for exact equality with DSM_CONNECTED, so they must
 * not see these bits.
 */
enum dtr_cm_flags {
	DCF_SUSPECT,		/* the path's link failed: stop selecting it and
				 * fail over (set from the IB async-event handler
				 * or the first tx completion error)
				 */
	DCF_IB_EVENT_REG,	/* the IB async-event handler is registered */
};

/* Per-path graceful-shutdown bits for hot path removal (drbdsetup del-path),
 * named after the lb-tcp transport's equivalents (DTL_*_SHUT_DOWN). Unlike
 * lb-tcp, which has one socket per stream and so splits the passive bit per
 * stream, an rdma2 path carries both streams on a single RC QP, so one
 * passive bit suffices. A path with either bit set is skipped for new payload
 * by dtr_select_and_get_cm_for_tx().
 */
enum dtr_path_flags {
	DTR_ACTIVE_SHUT_DOWN,	/* this side initiated the removal (dtr_remove_path) */
	DTR_PASSIVE_SHUT_DOWN,	/* the peer's shutdown marker has been received */
};

enum dtr_alloc_rdma_res_causes {
	IB_ALLOC_PD,
	IB_ALLOC_CQ_RX,
	IB_ALLOC_CQ_TX,
	RDMA_CREATE_QP,
	IB_GET_DMA_MR
};

struct dtr_rx_desc {
	/* Only the page-backed bootstrap descs (which catch the peer's pre-RDMA-write
	 * SENDs) carry a recv buffer here; steady-state descs post num_sge=0 and
	 * leave this NULL, since every inbound op is an RDMA_WRITE_WITH_IMM whose
	 * payload lands in a region (DATA/CONTROL) or the control ring (FLOW_CTRL).
	 * See rx_got_rdma_write for the buffered -> buffer-less transition.
	 */
	struct page *page;
	struct list_head list;
	int size;
	unsigned int sequence;
	struct dtr_cm *cm;
	struct ib_cqe cqe;
	struct ib_sge sge;

	/* For a payload delivered by RDMA-WRITE (IB_WC_RECV_RDMA_WITH_IMM) the
	 * data did not land in @page (the recv buffer is unused) but in a
	 * registered local_buffer region, starting @data_offset bytes into
	 * @data_page and spanning @data_nr_pages physically (and virtually)
	 * contiguous region pages. The desc holds one drbd_get_page() reference
	 * on each of them, since neighbouring writes may share a page (region
	 * consumption is stride-granular, not page-granular); dtr_recv_bio()
	 * transfers those references to the core with the bvec, the in-place
	 * readers drop them on recycle/free. NULL for SEND payloads.
	 */
	struct page *data_page;
	unsigned int data_offset;
	int data_nr_pages;
};

struct dtr_tx_desc {
	union {
		struct page *page;
		void *data;
		struct bio *bio;
	};
	enum {
		SEND_PAGE,
		SEND_MSG,
		SEND_BIO,
	} type;
	int nr_sges;
	u32 imm;
	/* When set, post IB_WR_RDMA_WRITE_WITH_IMM into the peer-registered
	 * buffer at @remote_addr/@rkey instead of IB_WR_SEND_WITH_IMM. The
	 * immediate still carries {stream, sequence} for ordering/demux. Used
	 * for control-ring records and DATA/CONTROL payload. The rkey is
	 * path-specific, so reposting such a desc on another path (failover)
	 * re-aims it at a chunk of that path's region first
	 * (dtr_repost_tx_desc()).
	 *
	 * @wr_pages, when non-NULL, holds the get_page()'d source pages
	 * (@nr_pages of them) that the multi-SGE bio write path (dtr_send_bio())
	 * builds and frees; one SGE may cover several contiguous pages, so
	 * @nr_pages >= @nr_sges. The single-page paths (SEND_PAGE/SEND_MSG) leave
	 * @wr_pages NULL and use the @page/@data union member.
	 */
	bool rdma_write;
	u64 remote_addr;
	u32 rkey;
	struct page **wr_pages;
	int nr_pages;
	/* Failover resend queue linkage (dtr_resend_work_fn). @resend_cm is the cm
	 * the desc is still DMA-mapped on (a ref is held while queued). Only used
	 * while on dtr_transport.resend_q.
	 */
	struct list_head resend_list;
	struct dtr_cm *resend_cm;
	struct ib_cqe cqe;
	struct ib_sge sge[]; /* must be last! */
};

struct dtr_flow {
	struct dtr_path *path;

	/* Byte windows derived from net_conf, set once in dtr_init_flow().
	 * rx_window_bytes: size of the local receive region the peer may
	 *   RDMA-WRITE into (DATA: rcvbuf-size, CONTROL: rdma-ctrl-rcvbuf-size).
	 * tx_window_bytes: how many bytes may be outstanding (un-acked) on the
	 *   wire before the sender must wait (DATA: sndbuf-size, CONTROL:
	 *   rdma-ctrl-sndbuf-size); tracks rx_window_bytes if unconfigured.
	 */
	unsigned int rx_window_bytes;
	unsigned int tx_window_bytes;

	atomic_t tx_descs_posted;
	int tx_descs_max; /* derived from net_conf->sndbuf_size. Do not change after alloc. */
	atomic_t peer_rx_descs; /* peer's receive window in number of rx descs */

	atomic_t rx_descs_posted;
	int rx_descs_max;  /* derived from net_conf->rcvbuf_size. Do not change after alloc. */

	atomic_t rx_descs_allocated;
	int rx_descs_want_posted;
	atomic_t rx_descs_known_to_peer;
};

enum connect_state_enum {
	PCS_INACTIVE,
	PCS_REQUEST_ABORT,
	PCS_FINISHING = PCS_REQUEST_ABORT,
	PCS_CONNECTING,
};

struct dtr_connect_state {
	struct delayed_work retry_connect_work;
	atomic_t active_state; /* trying to establish a connection*/
	atomic_t passive_state; /* listening for a connection */
	wait_queue_head_t wq;
	bool active; /* active = established by connect ; !active = established by accept */
};

/* A receive buffer the peer has registered and announced to us via
 * dtr_announce_buffer. We RDMA-WRITE payload into it, advancing @consumed; once
 * it equals @len the entry is exhausted and dropped.
 */
struct dtr_remote_buffer {
	struct list_head list;
	u64 addr;
	u32 rkey;
	u32 len;
	u32 consumed;
	u32 stride;  /* the peer consumes this region in multiples of this */
};

/* Headroom on the send queue for the unsignaled IB_WR_REG_MR / signaled
 * IB_WR_LOCAL_INV work requests that (re-)register receive regions. They retire
 * before the announce that follows them, so only a couple are ever in flight;
 * a small fixed reserve is plenty.
 */
#define DTR_REG_WR_HEADROOM 16

/* Failover resend: when a packet's path dies and it cannot immediately be placed
 * on a surviving path (that path's receive region is momentarily full), it is
 * queued rather than dropping the connection. A sender on the same stream drains
 * the queue (dtr_drain_resend) before issuing new sends, placing the stranded
 * (lower-sequence) descs ahead of the new, higher-sequence data that would
 * otherwise grab the survivor's region first; the peer can then fill its reorder
 * gap, deliver, and re-announce region. dtr_resend_work_fn is the backstop that
 * drains the queue when no sender is active on the stream; it retries
 * persistently while a path survives (no per-desc deadline -- that would
 * guillotine a still-recovering survivor; the give-up for a permanently stuck
 * survivor comes from the active sender's send timeout instead).
 */
#define DTR_RESEND_DELAY_MS 2

/* A receive region we registered for IB_ACCESS_REMOTE_WRITE and announced to
 * the peer. The peer RDMA-WRITEs payload into it; we hand the landed pages up
 * in BIOs and, once the region is fully consumed, re-register it over fresh
 * pages and announce the replacement. Region size is chosen at registration
 * time (largest physically-contiguous allocation that helps fill the receive
 * window), so it is stored per region rather than fixed.
 */
struct dtr_local_buffer {
	struct list_head list;
	struct dtr_cm *cm;        /* QP/PD the region is registered on; holds a kref */
	struct ib_mr *mr;
	struct page *head_page;   /* head of the split-page region */
	int nr_pages;             /* region size in pages (1 << allocated order) */
	struct scatterlist sg;
	u64 addr;                 /* device address (mr->iova) advertised to peer */
	u32 rkey;
	u32 len;                  /* nr_pages << PAGE_SHIFT */
	u32 consumed;             /* receive cursor within this region (bytes) */
	u32 stride;               /* consume granularity, announced to the peer */

	/* Completion of the signaled IB_WR_LOCAL_INV that returns the fast-reg MR
	 * to FREE state before it is re-registered for the next cycle. The MR must
	 * actually be FREE before ib_map_mr_sg()/REG_MR (rxe enforces this), so the
	 * re-arm waits for this.
	 */
	struct ib_cqe inv_cqe;
	struct completion inv_done;
};

/* The RDMA-WRITE receive regions for one stream of one path. The DATA and
 * CONTROL streams each get an independent set so control packets land in their
 * own regions and are consumed without contending with bulk payload.
 */
struct dtr_region_set {
	struct dtr_path *path;     /* owning path */
	enum drbd_stream stream;   /* which stream this set serves */

	/* Receive buffers the peer registered and announced to us (struct
	 * dtr_remote_buffer); our RDMA-WRITE targets. Consumed in FIFO order,
	 * matching the order the peer announced and reaps them.
	 */
	struct list_head remote_buffers;
	spinlock_t remote_buffers_lock;

	/* Receive regions we registered and announced to the peer (struct
	 * dtr_local_buffer). The peer RDMA-WRITEs payload into them.
	 */
	struct list_head local_buffers;
	spinlock_t local_buffers_lock;
	struct work_struct register_buffers_work;

	/* Fully-consumed local_buffers awaiting release. Filled from the rx
	 * completion softirq (where ib_dereg_mr() must not run); drained by
	 * register_buffers_work, which also tops the region pool back up.
	 */
	struct list_head exhausted_buffers;
};

/* Per-path control ring for flow-control / announce records. One per direction:
 * @local is our ring (a 1-page REMOTE_WRITE region the peer writes into);
 * @remote_* is the peer's ring we RDMA-WRITE into, learned from the peer's
 * ring-announce (region_stream == ST_FLOW_CTRL) after both sides are in RTS.
 */
struct dtr_ring {
	struct dtr_local_buffer *local; /* our ring (1 page); NULL until registered */
	u64 remote_addr;                /* peer's ring base address */
	u32 remote_rkey;
	/* Set when the peer's ring-announce arrives. The peer posts that announce
	 * only after its ring's REG_MR (same QP, so by RC send-queue ordering the
	 * REG_MR has completed by the time the announce is delivered), so
	 * remote_known also means the peer's ring MR is valid to RDMA-WRITE into.
	 */
	bool remote_known;
	u32 tx_seq;                     /* write cursor; slot = tx_seq % DTR_FLOW_CTRL_DESCS */
	spinlock_t lock;                /* serialises tx_seq / remote_* */

	/* Bootstrap recv phase. Until the peer switches from SEND to RDMA-WRITE we
	 * may receive a variable number of SEND records (first flow-control, then
	 * ring-announce, plus any flow-control grants in between), so recv WRs must
	 * be posted page-backed (num_sge=1) to catch them. The peer emits every
	 * SEND before its first RDMA-WRITE and the single RC QP delivers in order,
	 * so the first IB_WC_RECV_RDMA_WITH_IMM proves no SEND can follow: from then
	 * on recv WRs (and reposts) go buffer-less (num_sge=0). Reset per (re)connect
	 * in dtr_free_ring(); zero-initialised => page-backed for a fresh path.
	 */
	bool rx_got_rdma_write;
};

struct dtr_path {
	struct drbd_path path;

	struct dtr_connect_state cs;

	struct dtr_cm *cm; /* RCU'd and kref in cm */

	unsigned long flags; /* DTR_*_SHUT_DOWN bits */

	/* Echoes a graceful-shutdown marker back to a peer that initiated a path
	 * removal (dtr_got_shutdown_msg() schedules it). Deferred to process
	 * context so the marker send can use GFP_NOIO and not run in the rx softirq.
	 */
	struct work_struct shutdown_work;

	/* Indexed by enum dtr_stream_nr: [ST_DATA], [ST_CONTROL], and the
	 * dedicated [ST_FLOW_CTRL] pool that bounds the control-ring writer.
	 */
	struct dtr_flow flow[ST_FLOW_CTRL + 1];
	spinlock_t send_flow_control_lock;
	struct tasklet_struct flow_control_tasklet;
	struct work_struct refill_rx_descs_work;

	/* Per-stream RDMA-WRITE receive regions. Indexed by enum drbd_stream;
	 * DATA_STREAM carries bulk payload, CONTROL_STREAM small control packets.
	 */
	struct dtr_region_set regions[2];

	/* Control ring for flow-control / announce records. */
	struct dtr_ring ring;

	/* Registers + announces the control ring, deferred off the establishment
	 * critical path: the ring announce spends a FLOW_CTRL credit, and doing
	 * that inline would starve the first flow-control message out of the single
	 * initial credit. Kicked once flow-control is exchanged and re-kicked as
	 * credits arrive, until the ring is registered.
	 */
	struct work_struct ring_register_work;
};

struct dtr_stream {
	wait_queue_head_t send_wq;
	wait_queue_head_t recv_wq;

	/* for recv() to keep track of the current rx_desc:
	 * - whenever the bytes_left of the current rx_desc == 0, we know that all data
	 *   is consumed, and get a new rx_desc from the completion queue, and set
	 *   current rx_desc accordingly.
	 */
	struct {
		struct dtr_rx_desc *desc;
		void *pos;
		int bytes_left;
	} current_rx;

	unsigned long unread; /* unread received; unit: bytes */
	struct list_head rx_descs;
	spinlock_t rx_descs_lock;

	long send_timeout;
	long recv_timeout;

	unsigned int tx_sequence;
	unsigned int rx_sequence;
	struct dtr_transport *rdma_transport;
};

struct dtr_transport {
	struct drbd_transport transport;
	struct dtr_stream stream[2];
	int sges_max;
	int max_mr_pages; /* device's max pages per fast-reg MR; 0 until queried */
	/* Alignment the core needs for received DATA payload (its backing
	 * devices' dma_alignment), set via set_rx_alignment(); 0 if none. Feeds
	 * the stride of DATA regions registered from then on.
	 */
	unsigned int rx_align_hint;
	/* Region page references: taken in dtr_consume_local_buffer(), dropped by
	 * dtr_put_data_pages() or transferred to the core in dtr_recv_bio().
	 */
	atomic_t region_refs_taken;
	atomic_t region_refs_put;
	atomic_t region_refs_handed;
	bool active; /* connect() returned no error. I.e. C_CONNECTING or C_CONNECTED */

	/* per transport rate limit state for diagnostic messages.
	 * maybe: one for debug, one for warning, one for error?
	 * maybe: move into generic drbd_transport an tr_{warn,err,debug}().
	 */
	struct ratelimit_state rate_limit;

	struct timer_list control_timer;
	atomic_t first_path_connect_err;
	struct completion connected;

	struct tasklet_struct control_tasklet;

	/* Bounded asynchronous failover-resend queue: descriptors that could not be
	 * placed on a surviving path in the tx-completion softirq, awaiting a
	 * process-context retry. @resend_shutdown (under @resend_lock) stops new
	 * enqueues during teardown.
	 */
	struct list_head resend_q;
	spinlock_t resend_lock;
	bool resend_shutdown;
	struct delayed_work resend_work;
	/* Per-stream count of descs awaiting failover-resend. While > 0, a sender on
	 * that stream first drains the queued reposts (dtr_drain_resend, called from
	 * dtr_get_cm_reserve_credit/dtr_post_tx_desc) before issuing new sends, so the
	 * lower-sequence gap-fillers are placed ahead of new data competing for the
	 * survivor's region.
	 */
	atomic_t resend_pending[2];

	/* Woken when a graceful path removal makes progress: the peer's shutdown
	 * marker arrives (dtr_got_shutdown_msg) or in-flight payload on the path
	 * being removed completes (dtr_tx_cqe_done). dtr_remove_path() waits on it.
	 */
	wait_queue_head_t shutdown_wq;
};

struct dtr_cm {
	struct kref kref;
	struct rdma_cm_id *id;
	struct dtr_path *path;

	struct ib_cq *recv_cq;
	struct ib_cq *send_cq;
	struct ib_pd *pd;

	/* Shared completion anchor for the unsignaled IB_WR_REG_MR work requests
	 * that register RDMA-WRITE receive regions. Lives in the cm (not the
	 * buffer) so it outlives any single region's arm/consume/re-arm cycle.
	 */
	struct ib_cqe reg_cqe;

	unsigned long state; /* DSB bits / DSM masks */
	unsigned long flags; /* DCF_* bits */
	wait_queue_head_t state_wq;
	unsigned long last_sent_jif;
	atomic_t tx_descs_posted;
	struct timer_list tx_timeout;
	struct timer_list connect_timeout;

	/* Async-event handler for the cm's IB device; catches port-down
	 * (IB_EVENT_PORT_ERR, e.g. a pulled cable or `mlxlink --port_state dn`)
	 * so a dead path is detected immediately instead of waiting out the HCA
	 * retry timeout or the tx watchdog. Registered once the QP exists.
	 */
	struct ib_event_handler ib_event_handler;

	struct work_struct tx_timeout_work;
	struct work_struct suspect_work;
	struct work_struct connect_timeout_work;
	struct work_struct connect_work;
	struct work_struct establish_work;
	struct work_struct disconnect_work;

	struct list_head error_rx_descs;
	spinlock_t error_rx_descs_lock;
	struct work_struct end_rx_work;
	struct work_struct end_tx_work;

	struct dtr_transport *rdma_transport;
	struct rcu_head rcu;
};

struct dtr_listener {
	struct drbd_listener listener;

	struct dtr_cm cm;
};

static struct drbd_transport_class rdma2_transport_class;

static int dtr_create_cm_id(struct dtr_cm *cm_context, struct net *net);
static bool dtr_path_ok(struct dtr_path *path);
static bool dtr_transport_ok(struct drbd_transport *transport);
static int __dtr_post_tx_desc(struct dtr_cm *, struct dtr_tx_desc *);
static int dtr_post_tx_desc(struct dtr_transport *, struct dtr_tx_desc *, bool nonblock);
static int dtr_repost_tx_desc(struct dtr_cm *old_cm, struct dtr_tx_desc *tx_desc);
static bool dtr_resend_enqueue(struct dtr_transport *rdma_transport, struct dtr_cm *old_cm,
			       struct dtr_tx_desc *tx_desc);
static int dtr_failover_tx_desc(struct dtr_transport *rdma_transport, struct dtr_cm *old_cm,
				struct dtr_tx_desc *tx_desc);
static void dtr_resend_work_fn(struct work_struct *work);
static int dtr_repost_rx_desc(struct dtr_cm *cm, struct dtr_rx_desc *rx_desc);
static bool dtr_receive_rx_desc(struct dtr_transport *, enum drbd_stream,
				struct dtr_rx_desc **);
static void dtr_recycle_rx_desc(struct drbd_transport *transport,
				enum drbd_stream stream,
				struct dtr_rx_desc **pp_rx_desc,
				gfp_t gfp_mask);
static void dtr_refill_rx_desc(struct dtr_transport *rdma_transport,
			       enum drbd_stream stream);
static void dtr_free_tx_desc(struct dtr_cm *cm, struct dtr_tx_desc *tx_desc);
static void dtr_free_rx_desc(struct dtr_rx_desc *rx_desc);
static void dtr_cma_disconnect_work_fn(struct work_struct *work);
static void dtr_disconnect_path(struct dtr_path *path);
static void __dtr_modify_qp_to_err(struct dtr_cm *cm);
static void __dtr_disconnect_path(struct dtr_path *path);
static int dtr_init_flow(struct dtr_path *path, enum drbd_stream stream);
static void dtr_init_flow_control_flow(struct dtr_path *path);
static int dtr_cm_alloc_rdma_res(struct dtr_cm *cm);
static void __dtr_refill_rx_desc(struct dtr_path *path, enum drbd_stream stream);
static int dtr_send_flow_control_msg(struct dtr_path *path, gfp_t gfp_mask);
static struct dtr_cm *dtr_path_get_cm_connected(struct dtr_path *path);
static void dtr_destroy_cm(struct kref *kref);
static void dtr_destroy_cm_keep_id(struct kref *kref);
static int dtr_activate_path(struct dtr_path *path);
static int dtr_got_announce_buffer_msg(struct dtr_cm *cm, struct dtr_announce_buffer *msg);
static int dtr_got_shutdown_msg(struct dtr_path *path, struct dtr_shutdown *msg);
static int dtr_send_shutdown_msg(struct dtr_path *path, gfp_t gfp_mask);
static void dtr_shutdown_work_fn(struct work_struct *work);
static u32 dtr_remote_room(struct dtr_region_set *rs, unsigned int bytes);
static int dtr_reserve_and_post(struct dtr_cm *cm, struct dtr_region_set *rs,
				struct dtr_tx_desc *tx_desc, unsigned int bytes);
static bool dtr_any_remote_room(struct dtr_transport *rdma_transport, enum drbd_stream stream,
				unsigned int bytes);
static int dtr_wait_for_remote_buffer(struct dtr_transport *rdma_transport,
				      enum drbd_stream stream, unsigned int bytes);
static void dtr_put_data_pages(struct drbd_transport *transport, struct dtr_rx_desc *rx_desc);
static struct dtr_cm *dtr_get_cm_reserve_credit(struct dtr_transport *rdma_transport, int *err);
static void dtr_undo_credit(struct dtr_path *path);
static bool dtr_consume_local_buffer(struct dtr_region_set *rs, struct dtr_rx_desc *rx_desc,
				     unsigned int byte_len);
static void dtr_free_local_buffers(struct dtr_path *path);
static void dtr_free_remote_buffers(struct dtr_path *path);
static void dtr_drop_stale_path_buffers(struct dtr_path *path);
static int dtr_register_ring(struct dtr_path *path);
static void dtr_free_ring(struct dtr_path *path);
static void dtr_end_tx_work_fn(struct work_struct *work);
static void dtr_end_rx_work_fn(struct work_struct *work);
static void dtr_cma_retry_connect(struct dtr_path *path, struct dtr_cm *failed_cm);
static void dtr_tx_timeout_fn(struct timer_list *t);
static void dtr_connect_timeout_fn(struct timer_list *t);
static void dtr_control_timer_fn(struct timer_list *t);
static void dtr_tx_timeout_work_fn(struct work_struct *work);
static void dtr_suspect_work_fn(struct work_struct *work);
static void dtr_path_failover(struct dtr_cm *cm, const char *reason);
static void dtr_cm_set_suspect(struct dtr_cm *cm);
static void dtr_ib_event_handler(struct ib_event_handler *handler, struct ib_event *event);
static void dtr_connect_timeout_work_fn(struct work_struct *work);
static void dtr_arm_connect_timeout(struct dtr_cm *cm);
static void dtr_cancel_connect_timeout(struct dtr_cm *cm);
static void dtr_cma_connect_work_fn(struct work_struct *work);
static struct dtr_rx_desc *dtr_next_rx_desc(struct dtr_stream *rdma_stream);
static void dtr_control_tasklet_fn(struct tasklet_struct *t);
static int dtr_init_listener(struct drbd_transport *transport, const struct sockaddr *addr,
			     struct net *net, struct drbd_listener *drbd_listener);
static void dtr_destroy_listener(struct drbd_listener *generic_listener);


static struct rdma_conn_param dtr_conn_param = {
	.responder_resources = 1,
	.initiator_depth = 1,
	.retry_count = 10,
	.rnr_retry_count  = 7,
};

static u32 dtr_cm_to_lkey(struct dtr_cm *cm)
{
	return cm->pd->local_dma_lkey;
}

static void dtr_re_init_stream(struct dtr_stream *rdma_stream)
{
	struct drbd_transport *transport = &rdma_stream->rdma_transport->transport;

	rdma_stream->current_rx.pos = NULL;
	rdma_stream->current_rx.bytes_left = 0;

	rdma_stream->tx_sequence = 1;
	rdma_stream->rx_sequence = 1;
	rdma_stream->unread = 0;

	TR_ASSERT(transport, list_empty(&rdma_stream->rx_descs));
	TR_ASSERT(transport, rdma_stream->current_rx.desc == NULL);
}

static void dtr_init_stream(struct dtr_stream *rdma_stream,
			    struct drbd_transport *transport)
{
	rdma_stream->current_rx.desc = NULL;

	rdma_stream->recv_timeout = MAX_SCHEDULE_TIMEOUT;
	rdma_stream->send_timeout = MAX_SCHEDULE_TIMEOUT;

	init_waitqueue_head(&rdma_stream->recv_wq);
	init_waitqueue_head(&rdma_stream->send_wq);
	rdma_stream->rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	INIT_LIST_HEAD(&rdma_stream->rx_descs);
	spin_lock_init(&rdma_stream->rx_descs_lock);

	dtr_re_init_stream(rdma_stream);
}

static int dtr_init(struct drbd_transport *transport)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	int i;

	transport->class = &rdma2_transport_class;

	rdma_transport->active = false;
	rdma_transport->sges_max = DTR_MAX_TX_SGES;

	ratelimit_state_init(&rdma_transport->rate_limit, 5*HZ, 4);
	timer_setup(&rdma_transport->control_timer, dtr_control_timer_fn, 0);

	INIT_LIST_HEAD(&rdma_transport->resend_q);
	spin_lock_init(&rdma_transport->resend_lock);
	rdma_transport->resend_shutdown = false;
	atomic_set(&rdma_transport->resend_pending[DATA_STREAM], 0);
	atomic_set(&rdma_transport->resend_pending[CONTROL_STREAM], 0);
	INIT_DELAYED_WORK(&rdma_transport->resend_work, dtr_resend_work_fn);
	init_waitqueue_head(&rdma_transport->shutdown_wq);

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++)
		dtr_init_stream(&rdma_transport->stream[i], transport);

	tasklet_setup(&rdma_transport->control_tasklet, dtr_control_tasklet_fn);

	return 0;
}

static void dtr_free(struct drbd_transport *transport, enum drbd_tr_free_op free_op)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct drbd_path *drbd_path;
	int i;

	rdma_transport->active = false;

	/* Stop and drain the failover-resend queue: refuse new enqueues, cancel the
	 * retry worker, and free any queued descriptors (releasing the cm reference
	 * each holds). Refusing new enqueues makes the tx-completion path free+drop
	 * descs that flush during the path teardown below. Re-armed at the end for a
	 * transport that will be reused (CLOSE_CONNECTION).
	 */
	spin_lock_bh(&rdma_transport->resend_lock);
	rdma_transport->resend_shutdown = true;
	spin_unlock_bh(&rdma_transport->resend_lock);
	cancel_delayed_work_sync(&rdma_transport->resend_work);
	{
		struct dtr_tx_desc *tx_desc, *tmp;
		LIST_HEAD(batch);

		spin_lock_bh(&rdma_transport->resend_lock);
		list_splice_init(&rdma_transport->resend_q, &batch);
		spin_unlock_bh(&rdma_transport->resend_lock);
		list_for_each_entry_safe(tx_desc, tmp, &batch, resend_list) {
			struct dtr_cm *old_cm = tx_desc->resend_cm;

			list_del(&tx_desc->resend_list);
			dtr_free_tx_desc(old_cm, tx_desc);
			kref_put(&old_cm->kref, dtr_destroy_cm);
		}
		atomic_set(&rdma_transport->resend_pending[DATA_STREAM], 0);
		atomic_set(&rdma_transport->resend_pending[CONTROL_STREAM], 0);
	}

	list_for_each_entry(drbd_path, &transport->paths, list) {
		struct dtr_path *path = container_of(drbd_path, struct dtr_path, path);

		__dtr_disconnect_path(path);
		/* Also cancels shutdown_work, which a peer-initiated del-path may
		 * have scheduled; letting it run after the teardown below would be
		 * a use-after-free on DESTROY_TRANSPORT.
		 */
		dtr_drop_stale_path_buffers(path);
	}

	/* Free the rx_descs that where received and not consumed. */
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct dtr_stream *rdma_stream = &rdma_transport->stream[i];
		struct dtr_rx_desc *rx_desc, *tmp;
		LIST_HEAD(rx_descs);

		dtr_free_rx_desc(rdma_stream->current_rx.desc);
		rdma_stream->current_rx.desc = NULL;

		spin_lock_irq(&rdma_stream->rx_descs_lock);
		list_splice_init(&rdma_stream->rx_descs, &rx_descs);
		spin_unlock_irq(&rdma_stream->rx_descs_lock);

		list_for_each_entry_safe(rx_desc, tmp, &rx_descs, list)
			dtr_free_rx_desc(rx_desc);
	}

	list_for_each_entry(drbd_path, &transport->paths, list) {
		struct dtr_path *path = container_of(drbd_path, struct dtr_path, path);
		struct dtr_cm *cm;

		cm = xchg(&path->cm, NULL); // RCU xchg
		if (cm) {
			__dtr_modify_qp_to_err(cm);
			kref_put(&cm->kref, dtr_destroy_cm);
		}
	}

	timer_delete_sync(&rdma_transport->control_timer);

	if (free_op == DESTROY_TRANSPORT) {
		list_for_each_entry(drbd_path, &transport->paths, list) {
			struct dtr_path *path = container_of(drbd_path, struct dtr_path, path);

			cancel_work_sync(&path->refill_rx_descs_work);
			flush_delayed_work(&path->cs.retry_connect_work);
		}

		/*
		 * The transport object itself is embedded into a connection.
		 * Do not free it here! The function should better be called
		 * uninit.
		 */
	} else {
		/* CLOSE_CONNECTION: the transport object is reused for a reconnect
		 * (dtr_init() does not run again), so re-arm the resend queue.
		 */
		rdma_transport->resend_shutdown = false;
	}
}

static void dtr_control_timer_fn(struct timer_list *t)
{
	struct dtr_transport *rdma_transport = timer_container_of(rdma_transport, t, control_timer);
	struct drbd_transport *transport = &rdma_transport->transport;

	drbd_control_event(transport, TIMEOUT);
}

static bool atomic_inc_if_below(atomic_t *v, int limit)
{
	int old, cur;

	cur = atomic_read(v);
	do {
		old = cur;
		if (old >= limit)
			return false;

		cur = atomic_cmpxchg(v, old, old + 1);
	} while (cur != old);

	return true;
}

static int dtr_send(struct dtr_path *path, void *buf, size_t size, gfp_t gfp_mask)
{
	struct ib_device *device;
	struct dtr_tx_desc *tx_desc;
	struct dtr_cm *cm;
	void *send_buffer;
	int err = -ECONNRESET;

	cm = dtr_path_get_cm_connected(path);
	if (!cm)
		goto out;

	err = -ENOMEM;
	tx_desc = kzalloc_flex(*tx_desc, sge, 1, gfp_mask);
	if (!tx_desc)
		goto out_put;

	send_buffer = kmemdup(buf, size, gfp_mask);
	if (!send_buffer)
		goto out_free_desc;

	device = cm->id->device;
	tx_desc->type = SEND_MSG;
	tx_desc->data = send_buffer;
	tx_desc->nr_sges = 1;
	tx_desc->sge[0].addr = ib_dma_map_single(device, send_buffer, size, DMA_TO_DEVICE);
	err = ib_dma_mapping_error(device, tx_desc->sge[0].addr);
	if (err)
		goto out_free_buf;

	tx_desc->sge[0].lkey = dtr_cm_to_lkey(cm);
	tx_desc->sge[0].length = size;

	/* Once the peer has announced its control ring, RDMA-WRITE the record into
	 * the next ring slot instead of SEND_WITH_IMM -- the immediate still
	 * consumes one peer recv WR (the caller already charged the FLOW_CTRL
	 * pool), only the opcode and target differ. The slot is
	 * sequence % DTR_FLOW_CTRL_DESCS at both ends; the FLOW_CTRL credit pool
	 * caps outstanding records at DTR_FLOW_CTRL_DESCS == the slot count, so the
	 * writer can never lap an unread slot. Falls back to SEND until the ring is
	 * known (the bootstrap records are charged to the same pool).
	 */
	{
		unsigned long ring_flags;

		spin_lock_irqsave(&path->ring.lock, ring_flags);
		if (path->ring.remote_known) {
			u32 seq = path->ring.tx_seq++;
			unsigned int slot = seq % DTR_FLOW_CTRL_DESCS;

			tx_desc->rdma_write = true;
			tx_desc->remote_addr = path->ring.remote_addr +
					       (u64)slot * DTR_RING_SLOT_SIZE;
			tx_desc->rkey = path->ring.remote_rkey;
			tx_desc->imm = dtr_imm_encode(ST_FLOW_CTRL, seq);
		} else {
			tx_desc->imm = dtr_imm_encode(ST_FLOW_CTRL, 0);
		}
		spin_unlock_irqrestore(&path->ring.lock, ring_flags);
	}

	err = __dtr_post_tx_desc(cm, tx_desc);
	if (err)
		dtr_free_tx_desc(cm, tx_desc);

	goto out_put;

out_free_buf:
	kfree(send_buffer);
out_free_desc:
	kfree(tx_desc);
out_put:
	kref_put(&cm->kref, dtr_destroy_cm);
out:
	return err;
}


static int dtr_recv_bio(struct drbd_transport *transport, struct bio_list *bios, size_t size,
			unsigned int *misalign_bits)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_stream *rdma_stream = &rdma_transport->stream[DATA_STREAM];
	size_t remaining = size;
	struct page *page;
	int err;

	*misalign_bits = 0;
	if (!dtr_transport_ok(transport))
		return -ECONNRESET;

	TR_ASSERT(transport, rdma_stream->current_rx.bytes_left == 0);
	dtr_recycle_rx_desc(transport, DATA_STREAM, &rdma_stream->current_rx.desc, GFP_NOIO);
	dtr_refill_rx_desc(rdma_transport, DATA_STREAM);

	while (remaining) {
		struct dtr_rx_desc *rx_desc = NULL;
		long t;

		t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
					dtr_receive_rx_desc(rdma_transport, DATA_STREAM, &rx_desc),
					rdma_stream->recv_timeout);

		if (t <= 0)
			return t == 0 ? -EAGAIN : -EINTR;

		remaining -= rx_desc->size;

		if (rx_desc->data_page) {
			/* DATA was RDMA-written into a region: one rx_desc is one
			 * sender chunk (dtr_send_bio), a physically contiguous byte
			 * range starting @data_offset into @data_page. It goes into
			 * the bio as a single multi-page bvec of its own (never merged
			 * with the neighbouring chunk, which may share its first or
			 * last page), and the desc's page references go with it: the
			 * core releases one per touched page in
			 * drbd_peer_req_strip_bio().
			 */
			err = drbd_bio_add_page_nomerge(transport, bios, rx_desc->data_page,
							rx_desc->size, rx_desc->data_offset);
			if (err < 0)
				return err;
			*misalign_bits |= rx_desc->data_offset;
			if (remaining)
				*misalign_bits |= rx_desc->size;
			atomic_add(rx_desc->data_nr_pages, &rdma_transport->region_refs_handed);
			rx_desc->data_page = NULL;
			rx_desc->data_nr_pages = 0;
		} else {
			/* Pre-region SEND: payload is in the recv buffer itself. */
			page = rx_desc->page;
			rx_desc->page = NULL;
			err = drbd_bio_add_page(transport, bios, page, rx_desc->size, 0);
			if (err < 0)
				return err;
			if (remaining)
				*misalign_bits |= rx_desc->size;
		}

		atomic_dec(&rx_desc->cm->path->flow[DATA_STREAM].rx_descs_allocated);
		dtr_free_rx_desc(rx_desc);
		dtr_refill_rx_desc(rdma_transport, DATA_STREAM);
	}

	return size;
}

static int _dtr_recv(struct drbd_transport *transport, enum drbd_stream stream,
		     void **buf, size_t size, int flags)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];
	size_t done = 0;

	if (flags & GROW_BUFFER) {
		/*
		 * Since transport_rdma always returns the full, requested
		 * amount of data, DRBD should never call with GROW_BUFFER!
		 */
		tr_err(transport, "Called with GROW_BUFFER\n");
		return -EINVAL;
	}

	do {
		size_t n;

		if (rdma_stream->current_rx.bytes_left == 0) {
			struct dtr_rx_desc *rx_desc = NULL;
			long t;

			dtr_recycle_rx_desc(transport, stream, &rdma_stream->current_rx.desc,
					    GFP_NOIO);
			if (flags & MSG_DONTWAIT) {
				t = dtr_receive_rx_desc(rdma_transport, stream, &rx_desc);
			} else {
				t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
						dtr_receive_rx_desc(rdma_transport, stream,
								    &rx_desc),
						rdma_stream->recv_timeout);
			}

			if (t <= 0) {
				if (done)
					return done; /* short read, like a socket */
				return t == 0 ? -EAGAIN : -EINTR;
			}

			/* DATA arrives RDMA-written into a region (data_page +
			 * data_offset; a message larger than the region's stride may
			 * run into the next, contiguous region page). Pre-region SENDs
			 * land in the recv buffer.
			 */
			rdma_stream->current_rx.desc = rx_desc;
			if (rx_desc->data_page)
				rdma_stream->current_rx.pos =
					page_address(rx_desc->data_page) + rx_desc->data_offset;
			else
				rdma_stream->current_rx.pos = page_address(rx_desc->page);
			rdma_stream->current_rx.bytes_left = rx_desc->size;
		}

		if (!(flags & CALLER_BUFFER)) {
			/* A pointer into the transport's buffer cannot span two
			 * RDMA-WRITEs. Whole messages (headers, small packets) are sent
			 * as one write and lie within one desc; a fixed-size read of
			 * bio-chunked payload (ignore_remaining_packet()) may run into a
			 * chunk end -- return the short count, as a socket would, and
			 * the caller continues with the rest.
			 */
			n = min_t(size_t, size, rdma_stream->current_rx.bytes_left);
			*buf = rdma_stream->current_rx.pos;
			rdma_stream->current_rx.pos += n;
			rdma_stream->current_rx.bytes_left -= n;
			return n;
		}

		/* Copy into the caller's buffer, spanning descs as needed: payload
		 * read this way (recv_dless_read()) is chunked by the sender at
		 * region-room boundaries that need not match the caller's bvecs.
		 */
		n = min_t(size_t, size - done, rdma_stream->current_rx.bytes_left);
		memcpy((char *)*buf + done, rdma_stream->current_rx.pos, n);
		rdma_stream->current_rx.pos += n;
		rdma_stream->current_rx.bytes_left -= n;
		done += n;
	} while (done < size);

	return size;
}

static int dtr_recv(struct drbd_transport *transport, enum drbd_stream stream,
		    void **buf, size_t size, int flags)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	int err;

	if (!dtr_transport_ok(transport))
		return -ECONNRESET;

	err = _dtr_recv(transport, stream, buf, size, flags);

	dtr_refill_rx_desc(rdma_transport, stream);
	return err;
}

static void dtr_stats(struct drbd_transport *transport, struct drbd_transport_stats *stats)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_path *path;
	int sb_size = 0, sb_used = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &transport->paths, path.list) {
		struct dtr_flow *flow = &path->flow[DATA_STREAM];

		sb_size += flow->tx_descs_max;
		sb_used += atomic_read(&flow->tx_descs_posted);
	}
	rcu_read_unlock();

	/* send_buffer_half_full() uses these to pace resync requests */
	stats->send_buffer_size = sb_size * DRBD_SOCKET_BUFFER_SIZE;
	stats->send_buffer_used = sb_used * DRBD_SOCKET_BUFFER_SIZE;

	/* these two for debugfs */
	stats->unread_received = rdma_transport->stream[DATA_STREAM].unread;
	stats->unacked_send = stats->send_buffer_used;

}

/*
 * The following functions (at least)
 *   dtr_path_established_work_fn(),
 *   dtr_cma_accept(),
 *   dtr_cma_retry_connect_work_fn(),
 *   dtr_cma_retry_connect(),
 *   dtr_cma_connect_work_fn(),
 *   dtr_cma_disconnect_work_fn(), dtr_cma_disconnect(),
 *   dtr_cma_event_handler()
 *
 * are called from worker context or are callbacks from rdma_cm's context.
 *
 * We need to make sure the path does not go away in the meantime.
 */

static int dtr_path_prepare(struct dtr_path *path, struct dtr_cm *cm, bool active)
{
	struct dtr_cm *cm2;
	int i;

	cm2 = cmpxchg(&path->cm, NULL, cm);
	if (cm2) {
		/*
		 * The caller needs to hold a ref on cm. dtr_path_prepare()
		 * gifts that reference to the path. If setting the pointer in
		 * the path fails, we have to put one ref of cm.
		 */
		kref_put(&cm->kref, dtr_destroy_cm);
		return -ENOENT;
	}

	path->cs.active = active;
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++)
		dtr_init_flow(path, i);
	dtr_init_flow_control_flow(path);

	return dtr_cm_alloc_rdma_res(cm);
}

static struct dtr_cm *__dtr_path_get_cm(struct dtr_path *path)
{
	struct dtr_cm *cm;

	cm = rcu_dereference(path->cm);
	if (cm && !kref_get_unless_zero(&cm->kref))
		cm = NULL;
	return cm;
}

static struct dtr_cm *dtr_path_get_cm(struct dtr_path *path)
{
	struct dtr_cm *cm;

	rcu_read_lock();
	cm = __dtr_path_get_cm(path);
	rcu_read_unlock();
	return cm;
}

static struct dtr_cm *dtr_path_get_cm_connected(struct dtr_path *path)
{
	struct dtr_cm *cm;

	cm = dtr_path_get_cm(path);
	if (cm && cm->state != DSM_CONNECTED) {
		kref_put(&cm->kref, dtr_destroy_cm);
		cm = NULL;
	}
	return cm;
}

/* Kick the initial registration + announce of the DATA and CONTROL receive
 * regions. Region announces ride the control ring, so this is deferred until the
 * ring is usable (peer ring known); see dtr_path_established_work_fn(). Until at
 * least one DATA region is announced the peer's DATA sender blocks in
 * reserve-or-wait, so this must fire for the connection to carry any data.
 */
static void dtr_kick_register_buffers(struct dtr_path *path)
{
	schedule_work(&path->regions[DATA_STREAM].register_buffers_work);
	schedule_work(&path->regions[CONTROL_STREAM].register_buffers_work);
}

static void dtr_path_established_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, establish_work);
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_connect_state *cs = &path->cs;
	int i, p, err;

	/* ESTABLISHED arrived: the connect attempt resolved, disarm its watchdog. */
	dtr_cancel_connect_timeout(cm);

	err = cm != path->cm;
	if (err)
		goto out_put;

	p = atomic_cmpxchg(&cs->passive_state, PCS_CONNECTING, PCS_FINISHING);
	if (p < PCS_CONNECTING)
		goto out;

	kref_get(&cm->kref); /* connected -> expect a disconnect in the future */

	/* If this path is re-establishing after a failover, it still carries the
	 * dead QP's stale buffers (failover only forced the old QP to error). Drop
	 * them now, before the path becomes DSM_CONNECTED and thus selectable for
	 * tx, so it starts from a clean slate and uses only freshly re-announced
	 * regions -- otherwise a stale remote chunk (an rkey of an MR that died
	 * with the peer's old QP) is written into and faults the peer with a local
	 * access error, tripping the path back to ERROR (and leaking a cm_id on the
	 * retry). No-op on a first connect: the lists are empty.
	 */
	dtr_drop_stale_path_buffers(path);

	path->cm->state = DSM_CONNECTED;

	/* Post recv WRs for all three pools (DATA, CONTROL, and the FLOW_CTRL
	 * control-ring pool) before the first flow-control message, so it can
	 * grant the peer a credit on each. These are the page-backed bootstrap
	 * descs, so it is only a fraction of each window; the rest follows
	 * buffer-less once the peer's first RDMA-write ends the SEND phase.
	 */
	for (i = DATA_STREAM; i <= ST_FLOW_CTRL ; i++)
		__dtr_refill_rx_desc(path, i);
	err = dtr_send_flow_control_msg(path, GFP_NOIO);
	if (err > 0)
		err = 0;
	/* -ENOBUFS means a concurrent sender (dtr_receive_rx_desc() saw the
	 * freshly posted recv WRs) already spent the single bootstrap credit on
	 * an equivalent window grant -- the message this call is for. Common
	 * when a path (re-)establishes under load; not a failure.
	 */
	if (err == -ENOBUFS)
		err = 0;
	if (err)
		tr_err(transport, "sending first flow_control_msg() failed\n");

	/* The QP is in RTS: register + announce our control ring, but deferred so
	 * its announce does not spend the single initial FLOW_CTRL credit out from
	 * under the flow-control message above. Re-kicked from
	 * dtr_got_flow_control_msg() once the peer has granted a receive window.
	 */
	schedule_work(&path->ring_register_work);

	schedule_timeout(HZ / 4);
	if (!dtr_path_ok(path)) {
		if (path->cs.active)
			dtr_cma_retry_connect(path, path->cm);
		goto out_put;
	}

	p = atomic_cmpxchg(&rdma_transport->first_path_connect_err, 1, err);
	if (p == 1) {
		if (cs->active)
			set_bit(RESOLVE_CONFLICTS, &transport->flags);
		else
			clear_bit(RESOLVE_CONFLICTS, &transport->flags);
		complete(&rdma_transport->connected);
	}

	set_bit(TR_ESTABLISHED, &path->path.flags);
	drbd_path_event(transport, &path->path);

	/* NB: region registration is NOT kicked here. DATA/CONTROL region
	 * announces ride the control ring and charge the FLOW_CTRL pool, so they
	 * have to wait until the peer's ring is known. dtr_got_announce_buffer_msg()
	 * kicks dtr_kick_register_buffers() when the peer's ring announce arrives.
	 */

out:
	atomic_set(&cs->active_state, PCS_INACTIVE);
	p = atomic_xchg(&cs->passive_state, PCS_INACTIVE);
	if (p > PCS_INACTIVE)
		drbd_put_listener(&path->path);

	wake_up(&cs->wq);

out_put:
	kref_put(&cm->kref, dtr_destroy_cm);  /* for work */
}

static struct dtr_cm *dtr_alloc_cm(struct dtr_path *path)
{
	struct dtr_cm *cm;

	cm = kzalloc_obj(*cm);
	if (!cm)
		return NULL;

	kref_init(&cm->kref);
	INIT_WORK(&cm->connect_work, dtr_cma_connect_work_fn);
	INIT_WORK(&cm->establish_work, dtr_path_established_work_fn);
	INIT_WORK(&cm->disconnect_work, dtr_cma_disconnect_work_fn);
	INIT_WORK(&cm->end_rx_work, dtr_end_rx_work_fn);
	INIT_WORK(&cm->end_tx_work, dtr_end_tx_work_fn);
	INIT_WORK(&cm->tx_timeout_work, dtr_tx_timeout_work_fn);
	INIT_WORK(&cm->suspect_work, dtr_suspect_work_fn);
	INIT_WORK(&cm->connect_timeout_work, dtr_connect_timeout_work_fn);
	INIT_LIST_HEAD(&cm->error_rx_descs);
	spin_lock_init(&cm->error_rx_descs_lock);
	timer_setup(&cm->tx_timeout, dtr_tx_timeout_fn, 0);
	timer_setup(&cm->connect_timeout, dtr_connect_timeout_fn, 0);

	kref_get(&path->path.kref);
	cm->path = path;
	cm->rdma_transport = container_of(path->path.transport, struct dtr_transport, transport);

	/*
	 * We need this module in core as long as a dtr_tx_desc, a dtr_rx_desc
	 * or a dtr_cm object exists because they might have a callback
	 * registered in the RDMA code that will call back into this module. The
	 * rx and tx descs have a reference to the dtr_cm object, so taking an
	 * extra reference to the module for each dtr_cm object is sufficient.
	 */
	__module_get(THIS_MODULE);

	return cm;
}

static int dtr_cma_accept(struct dtr_listener *listener, struct rdma_cm_id *new_cm_id,
			  struct dtr_cm **ret_cm)
{
	struct sockaddr_storage *peer_addr;
	struct dtr_connect_state *cs;
	struct dtr_path *path;
	struct drbd_path *drbd_path;
	struct dtr_cm *cm;
	int err;

	*ret_cm = NULL;
	peer_addr = &new_cm_id->route.addr.dst_addr;

	spin_lock(&listener->listener.waiters_lock);
	drbd_path = drbd_find_path_by_addr(&listener->listener, peer_addr);
	if (drbd_path)
		kref_get(&drbd_path->kref);
	spin_unlock(&listener->listener.waiters_lock);

	if (!drbd_path) {
		struct sockaddr_in6 *from_sin6;
		struct sockaddr_in *from_sin;

		switch (peer_addr->ss_family) {
		case AF_INET6:
			from_sin6 = (struct sockaddr_in6 *)peer_addr;
			pr_warn("Closing unexpected connection from %pI6\n",
				&from_sin6->sin6_addr);
			break;
		case AF_INET:
			from_sin = (struct sockaddr_in *)peer_addr;
			pr_warn("Closing unexpected connection from %pI4\n",
				&from_sin->sin_addr);
			break;
		default:
			pr_warn("Closing unexpected connection family = %d\n",
				peer_addr->ss_family);
		}

		rdma_reject(new_cm_id, NULL, 0, IB_CM_REJ_CONSUMER_DEFINED);
		return -EAGAIN;
	}

	path = container_of(drbd_path, struct dtr_path, path);
	cs = &path->cs;
	if (atomic_read(&cs->passive_state) < PCS_CONNECTING)
		goto reject;

	cm = dtr_alloc_cm(path);
	if (!cm) {
		pr_err("rejecting connecting since -ENOMEM for cm\n");
		goto reject;
	}

	cm->state = DSM_CONNECT_REQ;
	init_waitqueue_head(&cm->state_wq);
	new_cm_id->context = cm;
	cm->id = new_cm_id;
	*ret_cm = cm;

	/*
	 * Expecting RDMA_CM_EVENT_ESTABLISHED, after rdma_accept(). Get
	 * the ref before dtr_path_prepare(), since that exposes the cm
	 * to the path, and the path might get destroyed, and with that
	 * going to put the cm.
	 */
	kref_get(&cm->kref);

	/* Gifting the initial kref to the path->cm pointer */
	err = dtr_path_prepare(path, cm, false);
	if (err) {
		/* Returning the cm via ret_cm and an error causes the caller to put one ref */
		goto reject;
	}
	kref_put(&drbd_path->kref, drbd_destroy_path);

	err = rdma_accept(new_cm_id, &dtr_conn_param);
	if (err)
		kref_put(&cm->kref, dtr_destroy_cm);
	else
		dtr_arm_connect_timeout(cm);

	return err;

reject:
	rdma_reject(new_cm_id, NULL, 0, IB_CM_REJ_CONSUMER_DEFINED);
	kref_put(&drbd_path->kref, drbd_destroy_path);
	return -EAGAIN;
}

static int dtr_start_try_connect(struct dtr_connect_state *cs)
{
	struct dtr_path *path = container_of(cs, struct dtr_path, cs);
	struct drbd_transport *transport = path->path.transport;
	struct dtr_cm *cm;
	int err = -ENOMEM;

	/* Never (re)connect a path this side is gracefully removing; dtr_remove_path
	 * owns its teardown, and a connect racing that teardown oopses in the
	 * rx-desc post against a half-set-up cm. The single chokepoint for all
	 * connect kickoffs (dtr_activate_path and the retry work).
	 */
	if (test_bit(DTR_ACTIVE_SHUT_DOWN, &path->flags))
		return 0;

	cm = dtr_alloc_cm(path);
	if (!cm)
		goto out;

	err = dtr_create_cm_id(cm, path->path.net);
	if (err) {
		tr_err(transport, "rdma_create_id() failed %d\n", err);
		goto out;
	}

	/* Holding the initial reference on cm, expecting RDMA_CM_EVENT_ADDR_RESOLVED */
	err = rdma_resolve_addr(cm->id, NULL,
				(struct sockaddr *)&path->path.peer_addr,
				2000);
	if (err) {
		tr_err(transport, "rdma_resolve_addr error %d\n", err);
		goto out;
	}

	return 0;
out:
	if (cm)
		kref_put(&cm->kref, dtr_destroy_cm);
	return err;
}

static void dtr_cma_retry_connect_work_fn(struct work_struct *work)
{
	struct dtr_connect_state *cs =
		container_of(work, struct dtr_connect_state, retry_connect_work.work);
	enum connect_state_enum p;
	int err;

	p = atomic_cmpxchg(&cs->active_state, PCS_REQUEST_ABORT, PCS_INACTIVE);
	if (p != PCS_CONNECTING) {
		wake_up(&cs->wq);
		return;
	}

	err = dtr_start_try_connect(cs);
	if (err) {
		struct dtr_path *path = container_of(cs, struct dtr_path, cs);
		struct drbd_transport *transport = path->path.transport;

		tr_err(transport, "dtr_start_try_connect failed  %d\n", err);
		schedule_delayed_work(&cs->retry_connect_work, HZ);
	}
}

/* Disarm the connect-attempt watchdog. timer_delete() (not the _sync variant)
 * is safe in any context: if it deactivates a pending timer we own and drop its
 * ref; if the timer already fired, the work owns that ref and drops it itself.
 */
static void dtr_cancel_connect_timeout(struct dtr_cm *cm)
{
	if (timer_delete(&cm->connect_timeout))
		kref_put(&cm->kref, dtr_destroy_cm); /* the armed-timer ref */
}

static void dtr_remove_cm_from_path(struct dtr_path *path, struct dtr_cm *failed_cm)
{
	struct dtr_cm *cm;

	if (!failed_cm)
		return;

	cm = cmpxchg(&path->cm, failed_cm, NULL); // RCU &path->cm
	if (cm == failed_cm) {
		__dtr_modify_qp_to_err(cm);
		kref_put(&cm->kref, dtr_destroy_cm);
	}
}

static void dtr_cma_retry_connect(struct dtr_path *path, struct dtr_cm *failed_cm)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_connect_state *cs = &path->cs;
	long connect_int = 10 * HZ;
	struct net_conf *nc;
	int a;

	dtr_cancel_connect_timeout(failed_cm);
	dtr_remove_cm_from_path(path, failed_cm);

	a = atomic_read(&cs->active_state);
	if (a == PCS_INACTIVE) {
		return;
	} else if (a == PCS_CONNECTING) {
		rcu_read_lock();
		nc = rcu_dereference(transport->net_conf);
		if (nc)
			connect_int = nc->connect_int * HZ;
		rcu_read_unlock();
	} else {
		connect_int = 1;
	}
	schedule_delayed_work(&cs->retry_connect_work, connect_int);
}

/* Arm the connect-attempt watchdog on a cm that has just issued rdma_connect()
 * (active) or rdma_accept() (passive) and is now waiting for an
 * RDMA_CM_EVENT_ESTABLISHED. Some providers (notably soft-RoCE / RXE) never
 * deliver a terminating CM event when the peer is unreachable, which would
 * otherwise leave the cm pinned in path->cm forever and dead-lock every later
 * reconnect (dtr_path_prepare() == -ENOENT). The watchdog synthesizes the
 * missing event; see dtr_connect_timeout_work_fn(). Uses the same one-ref-while-
 * armed discipline as the tx_timeout timer.
 */
static void dtr_arm_connect_timeout(struct dtr_cm *cm)
{
	struct drbd_transport *transport = cm->path->path.transport;
	long connect_int = 10 * HZ;
	struct net_conf *nc;
	bool was_active;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (nc)
		connect_int = nc->connect_int * HZ;
	rcu_read_unlock();

	kref_get(&cm->kref); /* for the armed connect-timeout timer */
	was_active = mod_timer(&cm->connect_timeout, jiffies + connect_int);
	if (was_active)
		kref_put(&cm->kref, dtr_destroy_cm);
}

static void dtr_connect_timeout_fn(struct timer_list *t)
{
	struct dtr_cm *cm = timer_container_of(cm, t, connect_timeout);

	/* the armed-timer ref becomes the work's ref */
	schedule_work(&cm->connect_timeout_work);
}

static void dtr_connect_timeout_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, connect_timeout_work);
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport;
	bool connecting;

	/* Lost the race to an ESTABLISHED / error event / teardown: the connect
	 * phase is already resolved, nothing to abort.
	 */
	if (!path || test_bit(DSB_CONNECTED, &cm->state))
		goto out;

	/* Claim the connect attempt. Whoever clears DSB_CONNECTING/DSB_CONNECT_REQ
	 * owns the "expecting ESTABLISHED" reference; if an event beat us to it we
	 * must not touch the cm.
	 */
	connecting = test_and_clear_bit(DSB_CONNECTING, &cm->state) ||
		test_and_clear_bit(DSB_CONNECT_REQ, &cm->state);
	if (!connecting)
		goto out;

	transport = path->path.transport;
	tr_warn(transport, "%pI4 - %pI4: connect timeout\n",
		&((struct sockaddr_in *)&path->path.my_addr)->sin_addr,
		&((struct sockaddr_in *)&path->path.peer_addr)->sin_addr);

	set_bit(DSB_ERROR, &cm->state);

	/* Drop the cm from path->cm and schedule a fresh attempt -- exactly what
	 * dtr_cma_event_handler() does for RDMA_CM_EVENT_UNREACHABLE. The work
	 * holds its own (armed-timer) ref plus the just-claimed expecting ref, so
	 * dtr_remove_cm_from_path() dropping the path->cm ref cannot free the cm
	 * under us.
	 */
	dtr_cma_retry_connect(path, cm);
	kref_put(&cm->kref, dtr_destroy_cm); /* the "expecting ESTABLISHED" ref */
out:
	kref_put(&cm->kref, dtr_destroy_cm); /* the armed-timer -> work ref */
}

static void dtr_cma_connect_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, connect_work);
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport = path->path.transport;
	enum connect_state_enum p;
	int err;

	p = atomic_cmpxchg(&path->cs.active_state, PCS_REQUEST_ABORT, PCS_INACTIVE);
	if (p != PCS_CONNECTING) {
		wake_up(&path->cs.wq);
		kref_put(&cm->kref, dtr_destroy_cm); /* for work */
		return;
	}

	kref_get(&cm->kref); /* for the path->cm pointer */
	err = dtr_path_prepare(path, cm, true);
	if (err) {
		tr_err(transport, "dtr_path_prepare() = %d\n", err);
		goto out;
	}

	kref_get(&cm->kref); /* Expecting RDMA_CM_EVENT_ESTABLISHED */
	set_bit(DSB_CONNECTING, &cm->state);
	err = rdma_connect(cm->id, &dtr_conn_param);
	if (err) {
		if (test_and_clear_bit(DSB_CONNECTING, &cm->state))
			kref_put(&cm->kref, dtr_destroy_cm); /* no _EVENT_ESTABLISHED */
		tr_err(transport, "rdma_connect error %d\n", err);
		goto out;
	}

	dtr_arm_connect_timeout(cm);

	kref_put(&cm->kref, dtr_destroy_cm); /* for work */
	return;
out:
	kref_put(&cm->kref, dtr_destroy_cm); /* for work */
	dtr_cma_retry_connect(path, cm);
}

static void dtr_cma_disconnect_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, disconnect_work);
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct drbd_path *drbd_path = &path->path;
	bool destroyed;
	int err;

	err = cm != path->cm;
	kref_put(&cm->kref, dtr_destroy_cm);
	if (err)
		return;

	destroyed = test_bit(TR_UNREGISTERED, &drbd_path->flags) || rdma_transport->active == false;
	if (test_and_clear_bit(TR_ESTABLISHED, &drbd_path->flags) && !destroyed)
		drbd_path_event(transport, drbd_path);

	if (!dtr_transport_ok(transport))
		drbd_control_event(transport, CLOSED_BY_PEER);

	if (destroyed)
		return;

	/* A path this side is gracefully removing owns its teardown in
	 * dtr_remove_path(); do not tear it down (and reconnect it) here too. Both
	 * ends running del-path makes the peer's disconnect land this work right
	 * while dtr_remove_path() is in its own dtr_disconnect_path(), and two
	 * concurrent teardowns double-free the path's buffers / reconnect a path
	 * that is going away.
	 */
	if (test_bit(DTR_ACTIVE_SHUT_DOWN, &path->flags))
		return;

	/*
	 * dtr_disconnect_path() drops the path's cm. That causes the
	 * reference on the path to be dropped. In dtr_activate_path() ->
	 * dtr_start_try_connect() we allocate a new cm, that holds a
	 * reference on the path again.
	 *
	 * Bridge the gap with a reference here!
	 */

	kref_get(&path->path.kref);
	dtr_disconnect_path(path);

	/* dtr_disconnect_path() may take time, recheck here... */
	if (test_bit(TR_UNREGISTERED, &drbd_path->flags) || rdma_transport->active == false)
		goto abort;

	if (!dtr_transport_ok(transport)) {
		/*
		 * If there is no other connected path, mark the connection
		 * as no longer active. Do not try to re-establish this path!
		 */
		rdma_transport->active = false;
		goto abort;
	}

	err = dtr_activate_path(path);
	if (err)
		tr_err(transport, "dtr_activate_path() = %d\n", err);
abort:
	kref_put(&path->path.kref, drbd_destroy_path);
}

static void dtr_cma_disconnect(struct dtr_cm *cm)
{
	kref_get(&cm->kref);
	schedule_work(&cm->disconnect_work);
}

static int dtr_cma_event_handler(struct rdma_cm_id *cm_id, struct rdma_cm_event *event)
{
	int err;
	/* context comes from rdma_create_id() */
	struct dtr_cm *cm = cm_id->context;
	struct dtr_listener *listener;
	bool connecting;

	if (!cm) {
		pr_err("id %p event %d, but no context!\n", cm_id, event->event);
		return 0;
	}

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		kref_get(&cm->kref); /* Expecting RDMA_CM_EVENT_ROUTE_RESOLVED */
		err = rdma_resolve_route(cm_id, 2000);
		if (err) {
			kref_put(&cm->kref, dtr_destroy_cm);
			pr_err("rdma_resolve_route error %d\n", err);
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:

		kref_get(&cm->kref);
		schedule_work(&cm->connect_work);
		break;

	case RDMA_CM_EVENT_CONNECT_REQUEST:
		/* for listener */

		listener = container_of(cm, struct dtr_listener, cm);
		err = dtr_cma_accept(listener, cm_id, &cm);

		/*
		 * When a new connection comes in, the callback gets called
		 * with a new rdma_cm_id. The new rdma_cm_id inherits its
		 * context pointer from the listening rdma_cm_id. The new
		 * context gets created in dtr_cma_accept() and is put into
		 * &cm here. cm now contains the accepted connection (no
		 * longer the listener).
		 */
		if (err) {
			if (!cm)
				return 1; /* caller destroy the cm_id */
			break; /* drop the last ref of cm at function exit */
		}
		return 0; /* do not touch kref of the new connection */

	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		/* cm->state = DSM_CONNECTED; is set later in the work item */
		/* This is called for active and passive connections */

		connecting = test_and_clear_bit(DSB_CONNECTING, &cm->state) ||
			test_and_clear_bit(DSB_CONNECT_REQ, &cm->state);
		kref_get(&cm->kref); /* for the work */
		schedule_work(&cm->establish_work);

		if (!connecting)
			return 0; /* keep ref; __dtr_disconnect_path() won */
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
	case RDMA_CM_EVENT_ROUTE_ERROR:
		set_bit(DSB_ERROR, &cm->state);

		dtr_cma_retry_connect(cm->path, cm);
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_REJECTED:
		set_bit(DSB_ERROR, &cm->state);

		/* shield ref: prevent the last kref put calling rdma_destroy_id() here */
		kref_get(&cm->kref);
		dtr_cma_retry_connect(cm->path, cm);
		connecting = test_and_clear_bit(DSB_CONNECTING, &cm->state) ||
			test_and_clear_bit(DSB_CONNECT_REQ, &cm->state);
		if (connecting) {
			/* Drop the "expecting ESTABLISHED" ref. Use the keep_id variant:
			 * if a racing teardown already dropped this cm's path->cm and timer
			 * refs while the connecting bit stayed set, this put can be the last
			 * one -- and rdma_destroy_id() must never run inside an rdma_cm event
			 * callback (it blocks on the id's handler_mutex, which this callback
			 * holds: self-deadlock, the cm_id then leaks and pins the port at
			 * bind -98). When it is the last put, return non-zero so the core
			 * destroys the id outside the callback, exactly as the tail put does.
			 * The shield above keeps this from being the last put in the balanced
			 * case, where the tail put at function exit does the final release.
			 */
			if (kref_put(&cm->kref, dtr_destroy_cm_keep_id))
				return 1;
		}
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		if (!test_and_clear_bit(DSB_CONNECTED, &cm->state))
			return 0; /* keep ref on cm; probably a tx_timeout */

		dtr_cma_disconnect(cm);
		break;

	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		return 0;

	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		return 0;

	default:
		pr_warn("id %p context %p unexpected event %d!\n",
				cm_id, cm, event->event);
		return 0;
	}
	wake_up(&cm->state_wq);

	/* A cm state change (e.g. the peer disconnecting the path) may release a
	 * dtr_remove_path() waiting for this path to quiesce: once the path is no
	 * longer connected its in-flight is settled, so the wait need not run out
	 * the ping-timeout. cm->path is set for every connection cm (NULL only for
	 * a listener, which never reaches here).
	 */
	if (cm->path) {
		struct dtr_transport *rdma_transport =
			container_of(cm->path->path.transport, struct dtr_transport, transport);

		wake_up_interruptible(&rdma_transport->shutdown_wq);
	}

	/*
	 * By returning 1 we instruct the caller to destroy the cm_id.
	 * We are not allowed to free it within the callback, since
	 * that deadlocks!
	 */
	return kref_put(&cm->kref, dtr_destroy_cm_keep_id);
}

static int dtr_create_cm_id(struct dtr_cm *cm, struct net *net)
{
	struct rdma_cm_id *id;

	cm->state = 0;
	init_waitqueue_head(&cm->state_wq);

	id = rdma_create_id(net, dtr_cma_event_handler, cm, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(id)) {
		cm->id = NULL;
		set_bit(DSB_ERROR, &cm->state);
		return PTR_ERR(id);
	}

	cm->id = id;
	return 0;
}

/* Number of rx_descs the peer does not know */
static int dtr_new_rx_descs(struct dtr_flow *flow)
{
	int posted, known;

	posted = atomic_read(&flow->rx_descs_posted);
	smp_rmb(); /* smp_wmb() is in dtr_rx_cqe_done() */
	known = atomic_read(&flow->rx_descs_known_to_peer);

	/* If the two decrements in dtr_rx_cqe_done() execute in
	 * parallel our result might be one too low, that does not matter.
	 * Only make sure to never return a -1 because that would matter!
	 */
	return max(posted - known, 0);
}

static struct dtr_rx_desc *dtr_next_rx_desc(struct dtr_stream *rdma_stream)
{
	struct dtr_rx_desc *rx_desc;

	spin_lock_irq(&rdma_stream->rx_descs_lock);
	rx_desc = list_first_entry_or_null(&rdma_stream->rx_descs, struct dtr_rx_desc, list);
	if (rx_desc) {
		if (rx_desc->sequence == rdma_stream->rx_sequence) {
			list_del(&rx_desc->list);
			rdma_stream->rx_sequence =
				dtr_seq_next(rdma_stream->rx_sequence);
			rdma_stream->unread -= rx_desc->size;
		} else {
			rx_desc = NULL;
		}
	}
	spin_unlock_irq(&rdma_stream->rx_descs_lock);

	return rx_desc;
}

static bool dtr_receive_rx_desc(struct dtr_transport *rdma_transport,
				enum drbd_stream stream,
				struct dtr_rx_desc **ptr_rx_desc)
{
	struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];
	struct dtr_rx_desc *rx_desc;
	struct dtr_path *path;

	rx_desc = dtr_next_rx_desc(rdma_stream);

	if (rx_desc) {
		struct dtr_cm *cm = rx_desc->cm;

		INIT_LIST_HEAD(&rx_desc->list);
		/* DATA is RDMA-written into a region page (data_page), already synced
		 * in dtr_consume_local_buffer(); the buffer-less recv desc has no
		 * mapping to sync. Only a pre-region SEND lands in the recv buffer.
		 */
		if (!rx_desc->data_page)
			ib_dma_sync_single_for_cpu(cm->id->device, rx_desc->sge.addr,
						   PAGE_SIZE, DMA_FROM_DEVICE);
		*ptr_rx_desc = rx_desc;
		return true;
	}

	/*
	 * The waiting thread gets woken up if a packet arrived, or if there is
	 * no new packet but we need to tell the peer about space in our receive
	 * window.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(path, &rdma_transport->transport.paths, path.list) {
		struct dtr_flow *flow = &path->flow[stream];

		if (atomic_read(&flow->rx_descs_known_to_peer) <
		    atomic_read(&flow->rx_descs_posted) / 8)
			dtr_send_flow_control_msg(path, GFP_ATOMIC);
	}
	rcu_read_unlock();

	return false;
}

static int dtr_send_flow_control_msg(struct dtr_path *path, gfp_t gfp_mask)
{
	struct dtr_flow *fc = &path->flow[ST_FLOW_CTRL];
	struct dtr_flow_control msg;
	struct dtr_flow *flow;
	int err, n[ST_FLOW_CTRL + 1], i, rx_descs = 0;
	bool charged;

	msg.magic = cpu_to_be32(DTR_MAGIC);

	spin_lock_bh(&path->send_flow_control_lock);
	/*
	 * dtr_send_flow_control_msg() is called from multiple threads (the
	 * receiver thread, the sender threads, softirq contexts).
	 * Determining the number of new rx_descs and adding this number
	 * to rx_descs_known_to_peer has to be atomic!
	 *
	 * Grant all three windows: DATA/CONTROL payload recv WRs, and the
	 * FLOW_CTRL control-ring slots (returning the credit a peer ring writer
	 * spends per record). The message itself is an ST_FLOW_CTRL record, so
	 * it is charged to the FLOW_CTRL pool (one credit == one ring slot ==
	 * one peer recv WR), not to DATA/CONTROL.
	 */
	for (i = DATA_STREAM; i <= ST_FLOW_CTRL; i++) {
		flow = &path->flow[i];

		n[i] = dtr_new_rx_descs(flow);
		atomic_add(n[i], &flow->rx_descs_known_to_peer);
		rx_descs += n[i];

		msg.new_rx_descs[i] = cpu_to_be32(n[i]);
	}
	charged = atomic_read(&fc->tx_descs_posted) < fc->tx_descs_max &&
		  atomic_dec_if_positive(&fc->peer_rx_descs) >= 0;
	spin_unlock_bh(&path->send_flow_control_lock);

	if (!charged) {
		/* No FLOW_CTRL credit right now. An expected transient: many
		 * triggers race for the single bootstrap credit while a path
		 * (re-)establishes under load, and a busy control ring throttles
		 * its writer by design. A later trigger (or the peer's next
		 * grant) retries; the flow counters are visible in debugfs.
		 */
		err = -ENOBUFS;
		goto out_undo;
	}

	if (rx_descs == 0 || !atomic_inc_if_below(&fc->tx_descs_posted, fc->tx_descs_max)) {
		atomic_inc(&fc->peer_rx_descs);
		return 0;
	}

	msg.send_from_stream = cpu_to_be32(ST_FLOW_CTRL);
	err = dtr_send(path, &msg, sizeof(msg), gfp_mask);
	if (err) {
		atomic_inc(&fc->peer_rx_descs);
		atomic_dec(&fc->tx_descs_posted);
out_undo:
		for (i = DATA_STREAM; i <= ST_FLOW_CTRL; i++) {
			flow = &path->flow[i];
			atomic_sub(n[i], &flow->rx_descs_known_to_peer);
		}
	}
	return err;
}

static void dtr_flow_control(struct dtr_flow *flow, gfp_t gfp_mask)
{
	int n, known_to_peer = atomic_read(&flow->rx_descs_known_to_peer);
	int tx_descs_max = flow->tx_descs_max;

	n = dtr_new_rx_descs(flow);
	if (n > tx_descs_max / 8 || known_to_peer < tx_descs_max / 8)
		dtr_send_flow_control_msg(flow->path, gfp_mask);
}

static int dtr_got_flow_control_msg(struct dtr_path *path,
				     struct dtr_flow_control *msg)
{
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	struct dtr_flow *flow;
	int i, n;

	/* The peer just granted a receive window; if our control ring still needs
	 * a send credit to announce itself, retry now.
	 */
	if (!path->ring.local && dtr_path_ok(path))
		schedule_work(&path->ring_register_work);

	for (i = CONTROL_STREAM; i >= DATA_STREAM; i--) {
		uint32_t new_rx_descs = be32_to_cpu(msg->new_rx_descs[i]);

		flow = &path->flow[i];

		n = atomic_add_return(new_rx_descs, &flow->peer_rx_descs);
		wake_up_interruptible(&rdma_transport->stream[i].send_wq);
	}

	/* The FLOW_CTRL window has no payload stream to wake; the grant frees
	 * control-ring slots, so re-kick any region announce that earlier ran out
	 * of credit (dtr_send_announce_buffer_msg() -> -ENOBUFS). The work is
	 * idempotent, so an unconditional kick on a non-zero grant is fine.
	 */
	if (be32_to_cpu(msg->new_rx_descs[ST_FLOW_CTRL])) {
		atomic_add(be32_to_cpu(msg->new_rx_descs[ST_FLOW_CTRL]),
			   &path->flow[ST_FLOW_CTRL].peer_rx_descs);
		if (dtr_path_ok(path)) {
			schedule_work(&path->regions[DATA_STREAM].register_buffers_work);
			schedule_work(&path->regions[CONTROL_STREAM].register_buffers_work);
		}
	}

	/* rdma_stream is the data_stream here... */
	if (n >= DESCS_LOW_LEVEL) {
		int tx_descs_posted = atomic_read(&flow->tx_descs_posted);

		if (flow->tx_descs_max - tx_descs_posted >= DESCS_LOW_LEVEL)
			clear_bit(NET_CONGESTED, &rdma_transport->transport.flags);
	}

	return be32_to_cpu(msg->send_from_stream);
}

static void dtr_flow_control_tasklet_fn(struct tasklet_struct *t)
{
	struct dtr_path *path = from_tasklet(path, t, flow_control_tasklet);

	dtr_send_flow_control_msg(path, GFP_ATOMIC);
}

static void dtr_maybe_trigger_flow_control_msg(struct dtr_path *path, int send_from_stream)
{
	struct dtr_flow *flow;
	int n;

	flow = &path->flow[send_from_stream];
	n = atomic_dec_return(&flow->rx_descs_known_to_peer);
	/* If we get a lot of flow control messages in, but no data on this
	 * path, we need to tell the peer that we recycled all these buffers
	 */
	if (n < atomic_read(&flow->rx_descs_posted) / 8)
		tasklet_schedule(&path->flow_control_tasklet);
}

/* Tear down a dead/suspect cm and either fail over to a surviving path or close
 * the connection. Idempotent via the DSB_CONNECTED test-and-clear: the tx-timeout
 * watchdog (dtr_tx_timeout_work_fn) and the link-down suspect path
 * (dtr_suspect_work_fn) may both target the same cm; only the first to clear
 * DSB_CONNECTED performs the teardown. @reason labels the log line.
 */
static void dtr_path_failover(struct dtr_cm *cm, const char *reason)
{
	struct drbd_transport *transport;
	struct dtr_path *path = cm->path;

	if (!test_and_clear_bit(DSB_CONNECTED, &cm->state) || !path)
		return;

	transport = path->path.transport;
	tr_warn(transport, "%pI4 - %pI4: %s\n",
		&((struct sockaddr_in *)&path->path.my_addr)->sin_addr,
		&((struct sockaddr_in *)&path->path.peer_addr)->sin_addr, reason);

	/* dtr_remove_cm_from_path() also puts the QP into the error state, so any
	 * WRs still posted on the dead path flush at once instead of waiting out
	 * the HCA retry timeout.
	 */
	dtr_remove_cm_from_path(path, cm);

	/* It is not sure that a RDMA_CM_EVENT_DISCONNECTED will be delivered.
	 * Dropping ref for that here. In case it is delivered we will not drop
	 * the ref in dtr_cma_event_handler() due to clearing DSB_CONNECTED
	 * from cm->state.
	 */
	kref_put(&cm->kref, dtr_destroy_cm);

	clear_bit(TR_ESTABLISHED, &path->path.flags);
	drbd_path_event(transport, &path->path);

	if (!dtr_transport_ok(transport)) {
		struct dtr_transport *rdma_transport =
			container_of(transport, struct dtr_transport, transport);

		drbd_control_event(transport, CLOSED_BY_PEER);
		rdma_transport->active = false;
	} else {
		dtr_activate_path(path);
	}
}

static void dtr_tx_timeout_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, tx_timeout_work);

	dtr_path_failover(cm, "tx timeout");
	kref_put(&cm->kref, dtr_destroy_cm); /* for work (armed timer) */
}

/* Runs from dtr_cm_set_suspect() after the IB async-event handler (or a tx
 * completion error) flagged the path's link as failed. Fails the path over
 * promptly rather than waiting for the tx watchdog.
 */
static void dtr_suspect_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, suspect_work);

	dtr_path_failover(cm, "link down");
	kref_put(&cm->kref, dtr_destroy_cm); /* for the suspect work */
}

static void dtr_tx_timeout_fn(struct timer_list *t)
{
	struct dtr_cm *cm = timer_container_of(cm, t, tx_timeout);

	/* cm->kref for armed timer becomes a ref for the work */
	schedule_work(&cm->tx_timeout_work);
}

/* (Re)arm the per-cm tx watchdog, holding exactly one cm reference for a pending
 * timer (the was_active dance keeps the count at one across re-arms). The
 * watchdog is armed when the first WR goes in flight and reset on each
 * completion, so it measures time since the last COMPLETION, not the last post:
 * a path that stops completing -- e.g. the peer's port went down and our WRs
 * black-hole -- is detected within ping_timeo even while we keep posting. This
 * is what catches the peer side of a one-sided link loss, whose own port stays
 * up so it gets no IB_EVENT_PORT_ERR and must infer the break from stuck WRs.
 */
static void dtr_arm_tx_timeout(struct dtr_cm *cm)
{
	struct drbd_transport *transport = &cm->rdma_transport->transport;
	struct net_conf *nc;
	unsigned int timeout;
	bool was_active;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = nc->ping_timeo;
	rcu_read_unlock();

	kref_get(&cm->kref);
	was_active = mod_timer(&cm->tx_timeout, jiffies + timeout * HZ / 20);
	if (was_active)
		kref_put(&cm->kref, dtr_destroy_cm);
}

/* Flag a path's cm as suspect so dtr_select_and_get_cm_for_tx() stops choosing
 * it for new sends, and kick dtr_suspect_work_fn() to fail it over. Idempotent
 * and safe from atomic context (IB async-event handler, tx-completion softirq):
 * only the first caller schedules the work and hands it the matching ref.
 */
static void dtr_cm_set_suspect(struct dtr_cm *cm)
{
	if (test_and_set_bit(DCF_SUSPECT, &cm->flags))
		return;

	kref_get(&cm->kref); /* for the suspect work */
	if (!schedule_work(&cm->suspect_work))
		kref_put(&cm->kref, dtr_destroy_cm);
}

/* IB device async-event handler. The interesting event is IB_EVENT_PORT_ERR
 * (the port this cm's QP rides on went down -- cable pull, switch port down, or
 * `mlxlink -d <dev> --port_state dn`); IB_EVENT_DEVICE_FATAL kills every path on
 * the device. Both are surfaced as a suspect so failover starts immediately,
 * without waiting for in-flight WRs to exhaust their HCA retries.
 */
static void dtr_ib_event_handler(struct ib_event_handler *handler, struct ib_event *event)
{
	struct dtr_cm *cm = container_of(handler, struct dtr_cm, ib_event_handler);

	switch (event->event) {
	case IB_EVENT_PORT_ERR:
		if (cm->id && event->element.port_num == cm->id->port_num)
			dtr_cm_set_suspect(cm);
		break;
	case IB_EVENT_DEVICE_FATAL:
		dtr_cm_set_suspect(cm);
		break;
	default:
		break;
	}
}



static void __dtr_order_rx_descs(struct dtr_stream *rdma_stream,
				 struct dtr_rx_desc *rx_desc)
{
	struct dtr_rx_desc *pos;
	unsigned int seq = rx_desc->sequence;

	list_for_each_entry_reverse(pos, &rdma_stream->rx_descs, list) {
		if (dtr_seq_greater(seq, pos->sequence)) {
			list_add(&rx_desc->list, &pos->list);
			return;
		}
	}
	list_add(&rx_desc->list, &rdma_stream->rx_descs);
}

static void dtr_order_rx_descs(struct dtr_stream *rdma_stream,
			       struct dtr_rx_desc *rx_desc)
{
	unsigned long flags;

	spin_lock_irqsave(&rdma_stream->rx_descs_lock, flags);
	__dtr_order_rx_descs(rdma_stream, rx_desc);
	rdma_stream->unread += rx_desc->size;
	spin_unlock_irqrestore(&rdma_stream->rx_descs_lock, flags);
}

static void dtr_dec_rx_descs(struct dtr_cm *cm)
{
	struct dtr_flow *flow = cm->path->flow;
	struct dtr_transport *rdma_transport = cm->rdma_transport;

	/* When we get the posted rx_descs back, we do not know if they
	 * were accounted for the data, the control, or the flow-control stream...
	 */
	if (atomic_dec_if_positive(&flow[DATA_STREAM].rx_descs_posted) >= 0)
		return;

	if (atomic_dec_if_positive(&flow[CONTROL_STREAM].rx_descs_posted) >= 0)
		return;

	if (atomic_dec_if_positive(&flow[ST_FLOW_CTRL].rx_descs_posted) >= 0)
		return;

	if (__ratelimit(&rdma_transport->rate_limit)) {
		struct drbd_transport *transport = &rdma_transport->transport;

		tr_warn(transport, "rx_descs_posted underflow avoided\n");
	}
}

static void dtr_control_data_ready(struct dtr_stream *rdma_stream, struct dtr_rx_desc *rx_desc)
{
	struct dtr_transport *rdma_transport = rdma_stream->rdma_transport;
	struct drbd_transport *transport = &rdma_transport->transport;
	struct drbd_const_buffer buffer;
	struct dtr_cm *cm = rx_desc->cm;
	struct dtr_path *path = cm->path;
	struct dtr_flow *flow = &path->flow[CONTROL_STREAM];

	if (atomic_read(&flow->rx_descs_known_to_peer) < atomic_read(&flow->rx_descs_posted) / 8)
		dtr_send_flow_control_msg(path, GFP_ATOMIC);

	/* CONTROL is RDMA-written into a region page (data_page); the dma sync of
	 * that page already happened in dtr_consume_local_buffer(). Pre-region
	 * SENDs land in the recv buffer, which still needs the sync here.
	 */
	if (!rx_desc->data_page)
		ib_dma_sync_single_for_cpu(cm->id->device, rx_desc->sge.addr,
					   PAGE_SIZE, DMA_FROM_DEVICE);

	if (rx_desc->data_page)
		buffer.buffer = page_address(rx_desc->data_page) + rx_desc->data_offset;
	else
		buffer.buffer = page_address(rx_desc->page);
	buffer.avail = rx_desc->size;
	drbd_control_data_ready(transport, &buffer);

	dtr_recycle_rx_desc(transport, CONTROL_STREAM, &rx_desc, GFP_ATOMIC);
}

static void __dtr_order_rx_descs_front(struct dtr_stream *rdma_stream,
				       struct dtr_rx_desc *rx_desc)
{
	struct dtr_rx_desc *pos;
	unsigned int seq = rx_desc->sequence;

	list_for_each_entry(pos, &rdma_stream->rx_descs, list) {
		if (dtr_seq_greater(seq, pos->sequence)) {
			list_add(&rx_desc->list, &pos->list);
			return;
		}
	}
	list_add(&rx_desc->list, &rdma_stream->rx_descs);
}

static void dtr_control_tasklet_fn(struct tasklet_struct *t)
{
	struct dtr_transport *rdma_transport =
		from_tasklet(rdma_transport, t, control_tasklet);
	struct dtr_stream *rdma_stream = &rdma_transport->stream[CONTROL_STREAM];
	struct dtr_rx_desc *rx_desc, *tmp;
	LIST_HEAD(rx_descs);

	spin_lock_irq(&rdma_stream->rx_descs_lock);
	list_splice_init(&rdma_stream->rx_descs, &rx_descs);
	spin_unlock_irq(&rdma_stream->rx_descs_lock);

	list_for_each_entry_safe(rx_desc, tmp, &rx_descs, list) {
		if (rx_desc->sequence != rdma_stream->rx_sequence)
			goto abort;
		list_del(&rx_desc->list);
		rdma_stream->rx_sequence =
			dtr_seq_next(rdma_stream->rx_sequence);
		rdma_stream->unread -= rx_desc->size;
		dtr_control_data_ready(rdma_stream, rx_desc);
	}
	return;

abort:
	spin_lock_irq(&rdma_stream->rx_descs_lock);
	list_for_each_entry_safe(rx_desc, tmp, &rx_descs, list) {
		list_del(&rx_desc->list);
		__dtr_order_rx_descs_front(rdma_stream, rx_desc);
	}
	spin_unlock_irq(&rdma_stream->rx_descs_lock);

	tasklet_schedule(&rdma_transport->control_tasklet);
}

static void dtr_rx_cqe_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct dtr_rx_desc *rx_desc = container_of(wc->wr_cqe, struct dtr_rx_desc, cqe);
	struct dtr_cm *cm = rx_desc->cm;
	struct dtr_path *path = cm->path;
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	u32 immediate;
	int err;

	if (wc->status != IB_WC_SUCCESS || !(wc->opcode & IB_WC_RECV)) {
		struct drbd_transport *transport = &rdma_transport->transport;
		unsigned long irq_flags;

		switch (wc->status) {
		case IB_WC_WR_FLUSH_ERR:
			/* "Work Request Flushed Error: A Work Request was in
			 * process or outstanding when the QP transitioned into
			 * the Error State."
			 *
			 * Which is not entirely unexpected...
			 */
			break;

		default:
			if (__ratelimit(&rdma_transport->rate_limit)) {
				tr_warn(transport,
					"wc.status = %d (%s), wc.opcode = %d (%s)\n",
					wc->status, wc->status == IB_WC_SUCCESS ? "ok" : "bad",
					wc->opcode, wc->opcode & IB_WC_RECV ? "ok" : "bad");

				tr_warn(transport,
					"wc.vendor_err = %d, wc.byte_len = %d wc.imm_data = %d\n",
					wc->vendor_err, wc->byte_len, wc->ex.imm_data);
			}
		}

		/* dtr_free_rx_desc() will call drbd_free_page(), and that function
		 * should not be called from softirq context.
		 */
		spin_lock_irqsave(&cm->error_rx_descs_lock, irq_flags);
		list_add_tail(&rx_desc->list, &cm->error_rx_descs);
		spin_unlock_irqrestore(&cm->error_rx_descs_lock, irq_flags);
		dtr_dec_rx_descs(cm);
		set_bit(DSB_ERROR, &cm->state);

		kref_get(&cm->kref);
		if (!schedule_work(&cm->end_rx_work))
			kref_put(&cm->kref, dtr_destroy_cm);

		return;
	}

	rx_desc->size = wc->byte_len;
	immediate = be32_to_cpu(wc->ex.imm_data);

	/* The first peer RDMA-write ends the bootstrap SEND phase: the peer emits
	 * all its SENDs before any RDMA-write and the single RC QP delivers in
	 * order, so from here recv WRs may post buffer-less. A SEND seen after this
	 * point would have no buffer to land in -- a protocol violation.
	 */
	if (wc->opcode == IB_WC_RECV_RDMA_WITH_IMM) {
		/* Fill the window now that the descs need no pages, and grant the
		 * peer the credits for it: the bootstrap posted a fraction of it.
		 */
		if (!READ_ONCE(path->ring.rx_got_rdma_write)) {
			WRITE_ONCE(path->ring.rx_got_rdma_write, true);
			schedule_work(&path->refill_rx_descs_work);
		}
	} else {
		WARN_ON_ONCE(READ_ONCE(path->ring.rx_got_rdma_write));
	}

	if (dtr_imm_stream(immediate) == ST_FLOW_CTRL) {
		struct dtr_local_buffer *ring = path->ring.local;
		int send_from_stream = -1; /* default: drop, no credit accounting */
		void *msg = NULL;

		if (wc->opcode == IB_WC_RECV_RDMA_WITH_IMM && ring) {
			/* Ring write: the record landed in our control ring at
			 * slot = sequence % DTR_FLOW_CTRL_DESCS. The recv buffer is
			 * unused; we only consumed the WR to take the immediate.
			 */
			unsigned int slot = dtr_imm_sequence(immediate) % DTR_FLOW_CTRL_DESCS;
			u64 off = (u64)slot * DTR_RING_SLOT_SIZE;

			ib_dma_sync_single_for_cpu(cm->id->device, ring->addr + off,
						   DTR_RING_SLOT_SIZE, DMA_FROM_DEVICE);
			msg = page_address(ring->head_page) + off;
		} else if (wc->opcode != IB_WC_RECV_RDMA_WITH_IMM) {
			/* SEND_WITH_IMM (pre-ring / fallback): record is in the
			 * recv buffer.
			 */
			ib_dma_sync_single_for_cpu(cm->id->device, rx_desc->sge.addr,
						   PAGE_SIZE, DMA_FROM_DEVICE);
			msg = page_address(rx_desc->page);
		}
		/* Flow-control and region-announce records share the ST_FLOW_CTRL
		 * immediate; both carry a leading magic, disambiguate on it. A ring
		 * slot that is stale/unwritten/raced carries neither magic -- drop it
		 * rather than parse garbage (and feed a garbage send_from_stream into
		 * flow[] indexing).
		 */
		if (msg) {
			u32 magic = be32_to_cpu(*(__be32 *)msg);

			if (magic == DTR_ANNOUNCE_MAGIC)
				send_from_stream = dtr_got_announce_buffer_msg(cm, msg);
			else if (magic == DTR_MAGIC)
				send_from_stream = dtr_got_flow_control_msg(path, msg);
			else if (magic == DTR_SHUTDOWN_MAGIC)
				send_from_stream = dtr_got_shutdown_msg(path, msg);
			else if (__ratelimit(&rdma_transport->rate_limit))
				tr_warn(&rdma_transport->transport,
					"control-ring: dropping record with bad magic 0x%x\n",
					magic);
		}
		err = dtr_repost_rx_desc(cm, rx_desc);
		if (err)
			tr_err(&rdma_transport->transport, "dtr_repost_rx_desc() failed %d", err);
		/* Range-check before flow[] indexing: send_from_stream comes from a
		 * record that may be stale/raced in the ring. Every well-formed record
		 * now charges the FLOW_CTRL pool (send_from_stream == ST_FLOW_CTRL);
		 * DATA/CONTROL remain valid for records still in flight from a peer that
		 * has not yet switched (none in rdma2, but the check stays cheap).
		 */
		if (send_from_stream >= DATA_STREAM && send_from_stream <= ST_FLOW_CTRL)
			dtr_maybe_trigger_flow_control_msg(path, send_from_stream);
	} else {
		unsigned int stream = dtr_imm_stream(immediate);
		struct dtr_flow *flow = &path->flow[stream];
		struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];

		atomic_dec(&flow->rx_descs_posted);
		smp_wmb(); /* smp_rmb() is in dtr_new_rx_descs() */
		atomic_dec(&flow->rx_descs_known_to_peer);

		/* DATA and CONTROL were RDMA-written into our receive region, not
		 * the recv buffer: take the page the payload landed in
		 * (rx_desc->data_page), which _dtr_recv()/dtr_recv_bio() (DATA) and
		 * dtr_control_data_ready() (CONTROL) hand up instead of rx_desc->page.
		 */
		if (wc->opcode == IB_WC_RECV_RDMA_WITH_IMM &&
		    !dtr_consume_local_buffer(&path->regions[stream], rx_desc,
					      wc->byte_len)) {
			unsigned long irq_flags;

			/* The receive region overran (replenishment could not keep up
			 * with a burst, e.g. the CONTROL-stream flood of online verify):
			 * the payload has no page to hand up. Dropping a packet would
			 * desync the reliable stream and handing a NULL page to the
			 * stream consumer would oops, so drop the connection instead --
			 * it reconnects. Dispose of the desc via the error list (freed at
			 * teardown); the rx_descs accounting above already ran.
			 */
			if (__ratelimit(&rdma_transport->rate_limit))
				tr_err(&rdma_transport->transport,
				       "%s payload with no receive region; dropping connection\n",
				       stream == ST_CONTROL ? "control" : "data");
			spin_lock_irqsave(&cm->error_rx_descs_lock, irq_flags);
			list_add_tail(&rx_desc->list, &cm->error_rx_descs);
			spin_unlock_irqrestore(&cm->error_rx_descs_lock, irq_flags);
			set_bit(DSB_ERROR, &cm->state);
			kref_get(&cm->kref);
			if (!schedule_work(&cm->end_rx_work))
				kref_put(&cm->kref, dtr_destroy_cm);
			return;
		}

		if (stream == ST_CONTROL)
			mod_timer(&rdma_transport->control_timer,
				  jiffies + rdma_stream->recv_timeout);

		rx_desc->sequence = dtr_imm_sequence(immediate);
		dtr_order_rx_descs(rdma_stream, rx_desc);

		if (stream == ST_CONTROL)
			tasklet_schedule(&rdma_transport->control_tasklet);
		else
			wake_up_interruptible(&rdma_stream->recv_wq);
	}

	if (dtr_path_ok(path)) {
		enum drbd_stream s;

		/* Repost recv WRs (and re-grant the peer's receive window) for any
		 * stream that runs low, not just DATA. CONTROL must be included: its
		 * recv WRs are otherwise only reposted from dtr_recv() after in-order
		 * delivery, so a sequence gap -- e.g. CONTROL packets stranded on a
		 * failed path -- stalls delivery, stops reposting, collapses
		 * rx_descs_known_to_peer, and throttles the peer to a single credit.
		 * The peer can then no longer send the gap-filling reposts that would
		 * let delivery resume: a deadlock that persists until the core's
		 * PingAck timeout tears the connection down. The refill work itself
		 * already replenishes every stream.
		 */
		for (s = DATA_STREAM; s <= CONTROL_STREAM; s++) {
			struct dtr_flow *flow = &path->flow[s];

			if (atomic_read(&flow->rx_descs_posted) < flow->rx_descs_want_posted / 2) {
				schedule_work(&path->refill_rx_descs_work);
				break;
			}
		}
	}
}

static void dtr_free_tx_desc(struct dtr_cm *cm, struct dtr_tx_desc *tx_desc)
{
	struct ib_device *device = cm->id->device;
	int i, nr_sges;

	/* Multi-SGE RDMA-WRITE chunk: drop the references and mappings taken per
	 * source page by dtr_send_bio(). Uses @wr_pages (always set for SEND_BIO),
	 * not the bio, since one bio may be split into several chunks each owning a
	 * subset of the pages. Keyed on the type, not on @wr_pages/@rdma_write: the
	 * single-page SEND_PAGE/SEND_MSG descriptors are also rdma_write for
	 * DATA/CONTROL and do not initialise @wr_pages.
	 */
	if (tx_desc->type == SEND_BIO) {
		nr_sges = tx_desc->nr_sges;
		for (i = 0; i < nr_sges; i++)
			ib_dma_unmap_page(device, tx_desc->sge[i].addr, tx_desc->sge[i].length,
					  DMA_TO_DEVICE);
		for (i = 0; i < tx_desc->nr_pages; i++)
			put_page(tx_desc->wr_pages[i]);
		kfree(tx_desc->wr_pages);
		kfree(tx_desc);
		return;
	}

	switch (tx_desc->type) {
	case SEND_PAGE:
		ib_dma_unmap_page(device, tx_desc->sge[0].addr,
				  tx_desc->sge[0].length, DMA_TO_DEVICE);
		put_page(tx_desc->page);
		break;
	case SEND_MSG:
		ib_dma_unmap_single(device, tx_desc->sge[0].addr,
				    tx_desc->sge[0].length, DMA_TO_DEVICE);
		kfree(tx_desc->data);
		break;
	case SEND_BIO:
		break;
	}
	kfree(tx_desc);
}

static void dtr_tx_cqe_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct dtr_tx_desc *tx_desc = container_of(wc->wr_cqe, struct dtr_tx_desc, cqe);
	struct dtr_cm *cm = cq->cq_context;
	struct dtr_path *path = cm->path;
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	struct dtr_flow *flow;
	/*
	 * Only DATA/CONTROL have a payload stream whose send_wq waits for tx
	 * completions; FLOW_CTRL records (charged to the FLOW_CTRL pool) have
	 * none, so rdma_stream stays NULL and the wake below is skipped for
	 * them.
	 */
	struct dtr_stream *rdma_stream = NULL;
	enum dtr_stream_nr stream_nr = dtr_imm_stream(tx_desc->imm);
	int err;

	if (stream_nr != ST_FLOW_CTRL) {
		flow = &path->flow[stream_nr];
		rdma_stream = &rdma_transport->stream[stream_nr];
	} else {
		struct dtr_flow_control *msg = (struct dtr_flow_control *)tx_desc->data;
		enum dtr_stream_nr send_from_stream = be32_to_cpu(msg->send_from_stream);

		flow = &path->flow[send_from_stream];
		if (send_from_stream != ST_FLOW_CTRL)
			rdma_stream = &rdma_transport->stream[send_from_stream];
	}

	if (wc->status != IB_WC_SUCCESS ||
	    (wc->opcode != IB_WC_SEND && wc->opcode != IB_WC_RDMA_WRITE)) {
		struct drbd_transport *transport = &rdma_transport->transport;

		if (wc->status == IB_WC_RNR_RETRY_EXC_ERR) {
			tr_err(transport, "tx_event: wc.status = IB_WC_RNR_RETRY_EXC_ERR\n");
			tr_info(transport, "peer_rx_descs = %d", atomic_read(&flow->peer_rx_descs));
		} else if (wc->status != IB_WC_WR_FLUSH_ERR) {
			tr_err(transport, "tx_event: wc.status != IB_WC_SUCCESS %d\n", wc->status);
			tr_err(transport, "wc.vendor_err = %d, wc.byte_len = %d wc.imm_data = %d\n",
			       wc->vendor_err, wc->byte_len, wc->ex.imm_data);
		}

		atomic_inc(&flow->peer_rx_descs);
		set_bit(DSB_ERROR, &cm->state);

		/* A non-flush error means the RC QP has gone to the error state:
		 * every later WR on it will flush, so stop selecting this path for
		 * new sends and fail it over now. (A flush error is the consequence
		 * of a teardown already under way -- nothing to flag.) This is the
		 * generic/RXE backstop for the IB_EVENT_PORT_ERR async event, which
		 * soft-RoCE does not deliver reliably.
		 */
		if (wc->status != IB_WC_WR_FLUSH_ERR)
			dtr_cm_set_suspect(cm);

		/* Fail the packet over to a surviving path, re-aiming an RDMA-WRITE at
		 * a fresh chunk in that path's region and keeping its stream sequence
		 * number, so the peer's in-order reorder queue does not stall on the
		 * gap (which would otherwise hang the stream until the connection
		 * resets). FLOW_CTRL records are not reposted -- they are ring writes
		 * regenerated by the flow-control machinery. If the survivor is
		 * momentarily out of room (-EAGAIN), queue the desc for a bounded async
		 * retry rather than dropping; only a hard failure (or an exhausted
		 * budget, later) tears the connection down.
		 */
		if (stream_nr != ST_FLOW_CTRL) {
			err = dtr_failover_tx_desc(rdma_transport, cm, tx_desc);
			tx_desc = NULL; /* placed, queued, or freed by the helper */
			if (err && __ratelimit(&rdma_transport->rate_limit)) {
				tr_warn(transport, "repost of tx_desc failed! %d\n", err);
				drbd_control_event(transport, CLOSED_BY_PEER);
			}
		}
	}

	atomic_dec(&flow->tx_descs_posted);
	if (rdma_stream) {
		wake_up_interruptible(&rdma_stream->send_wq);
		/* A DATA/CONTROL completion on a path being gracefully removed may
		 * be the last in-flight payload dtr_remove_path() is waiting to
		 * drain before it tears the QP down.
		 */
		if (test_bit(DTR_ACTIVE_SHUT_DOWN, &path->flags))
			wake_up_interruptible(&rdma_transport->shutdown_wq);
	}

	if (tx_desc)
		dtr_free_tx_desc(cm, tx_desc);
	if (atomic_dec_and_test(&cm->tx_descs_posted)) {
		bool was_active = timer_delete(&cm->tx_timeout);

		if (was_active)
			kref_put(&cm->kref, dtr_destroy_cm);

		if (cm->state == DSM_CONNECTED)
			kref_put(&cm->kref, dtr_destroy_cm); /* this is _not_ the last ref */
		else /* the last ref might be put in this work */
			schedule_work(&cm->end_tx_work);
	} else {
		/* Progress on this path: a WR completed but others are still in flight.
		 * Reset the watchdog so it measures time since this completion -- a path
		 * that subsequently stops completing is detected within ping_timeo.
		 */
		dtr_arm_tx_timeout(cm);
	}
}

static int dtr_create_qp(struct dtr_cm *cm, int rx_descs_max, int tx_descs_max)
{
	struct dtr_transport *rdma_transport =
		container_of(cm->path->path.transport, struct dtr_transport, transport);
	int err;

	struct ib_qp_init_attr init_attr = {
		.cap.max_send_wr = tx_descs_max,
		.cap.max_recv_wr = rx_descs_max,
		.cap.max_recv_sge = 1, /* one page for bootstrap recvs; steady-state posts none */
		.cap.max_send_sge = rdma_transport->sges_max,
		.qp_type = IB_QPT_RC,
		.send_cq = cm->send_cq,
		.recv_cq = cm->recv_cq,
		.sq_sig_type = IB_SIGNAL_REQ_WR
	};

	err = rdma_create_qp(cm->id, cm->pd, &init_attr);

	return err;
}

static int dtr_post_rx_desc(struct dtr_cm *cm, struct dtr_rx_desc *rx_desc)
{
	struct dtr_transport *rdma_transport =
		container_of(cm->path->path.transport, struct dtr_transport, transport);
	struct ib_recv_wr recv_wr;
	const struct ib_recv_wr *recv_wr_failed;
	int err = -EIO;

	recv_wr.next = NULL;
	rx_desc->cqe.done = dtr_rx_cqe_done;
	recv_wr.wr_cqe = &rx_desc->cqe;

	/* Steady-state recv WRs carry no buffer (num_sge=0): every inbound op is
	 * RDMA_WRITE_WITH_IMM, whose payload lands in a peer-known region (or the
	 * control ring), so the WR only has to deliver the immediate. Only the
	 * page-backed bootstrap descs (catching the peer's pre-RDMA-write SENDs)
	 * post a sge.
	 */
	if (rx_desc->page) {
		recv_wr.sg_list = &rx_desc->sge;
		recv_wr.num_sge = 1;
		ib_dma_sync_single_for_device(cm->id->device,
					      rx_desc->sge.addr, PAGE_SIZE, DMA_FROM_DEVICE);
	} else {
		recv_wr.sg_list = NULL;
		recv_wr.num_sge = 0;
	}

	err = ib_post_recv(cm->id->qp, &recv_wr, &recv_wr_failed);
	if (err)
		tr_err(&rdma_transport->transport, "ib_post_recv error %d\n", err);

	return err;
}

static void dtr_free_rx_desc(struct dtr_rx_desc *rx_desc)
{
	struct dtr_transport *rdma_transport;
	struct dtr_path *path;
	struct ib_device *device;
	struct dtr_cm *cm;

	if (!rx_desc)
		return; /* Allow call with NULL */

	cm = rx_desc->cm;
	device = cm->id->device;
	path = cm->path;
	rdma_transport = container_of(path->path.transport, struct dtr_transport, transport);
	kref_put(&cm->kref, dtr_destroy_cm);

	/* Only the page-backed bootstrap descs were DMA-mapped; buffer-less
	 * (num_sge=0) steady-state descs have no mapping and no page to free.
	 */
	if (rx_desc->page) {
		struct drbd_transport *transport = &rdma_transport->transport;

		ib_dma_unmap_single(device, rx_desc->sge.addr, PAGE_SIZE, DMA_FROM_DEVICE);
		/*
		 * put_page(), if we had more than one rx_desc per page,
		 * but see comments in dtr_create_rx_desc.
		 */
		drbd_free_page(transport, rx_desc->page);
	}
	/* Region pages still referenced here were read in place (a DATA header
	 * via _dtr_recv) rather than handed up in a BIO; dtr_recv_bio() clears
	 * data_page after transferring the references to the core.
	 */
	dtr_put_data_pages(&rdma_transport->transport, rx_desc);
	kfree(rx_desc);
}

/* Drop the references a desc holds on the region pages its payload occupies
 * (taken in dtr_consume_local_buffer()). The region itself keeps its own
 * reference on every page until it is disarmed, so a page shared with a
 * neighbouring write stays valid for that write's holder. drbd_free_page() is
 * a put_page() or an order-0 mempool_free(), safe from the softirq recycle path.
 */
static void dtr_put_data_pages(struct drbd_transport *transport, struct dtr_rx_desc *rx_desc)
{
	int i;

	if (!rx_desc->data_page)
		return;
	for (i = 0; i < rx_desc->data_nr_pages; i++)
		drbd_free_page(transport, rx_desc->data_page + i);
	atomic_add(rx_desc->data_nr_pages,
		   &container_of(transport, struct dtr_transport, transport)->region_refs_put);
	rx_desc->data_page = NULL;
	rx_desc->data_nr_pages = 0;
}

static int dtr_create_rx_desc(struct dtr_flow *flow, gfp_t gfp_mask, bool connected_only)
{
	struct dtr_path *path = flow->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_rx_desc *rx_desc;
	struct page *page = NULL;
	/* Page-backed only while the peer may still SEND (bootstrap phase); once a
	 * peer RDMA-write has been seen, every desc posts num_sge=0. See rx_got_rdma_write.
	 */
	bool buffered = !READ_ONCE(path->ring.rx_got_rdma_write);
	int err;
	struct dtr_cm *cm;

	rx_desc = kzalloc_obj(*rx_desc, gfp_mask);
	if (!rx_desc)
		return -ENOMEM;

	/* Buffer-less descs (the steady state) post num_sge=0 and need no page;
	 * only the bootstrap descs that catch the peer's SENDs carry one.
	 */
	if (buffered) {
		page = drbd_alloc_pages(transport, gfp_mask, PAGE_SIZE);
		if (!page) {
			kfree(rx_desc);
			return -ENOMEM;
		}
		if (WARN_ON_ONCE(PageHighMem(page))) {
			drbd_free_page(transport, page);
			kfree(rx_desc);
			return -EINVAL;
		}
	}

	err = -ECONNRESET;
	cm = dtr_path_get_cm(path);
	if (!cm)
		goto out;
	if (connected_only && cm->state != DSM_CONNECTED)
		goto out_put;

	rx_desc->cm = cm;
	rx_desc->size = 0;
	if (buffered) {
		rx_desc->page = page;
		rx_desc->sge.lkey = dtr_cm_to_lkey(cm);
		rx_desc->sge.addr = ib_dma_map_single(cm->id->device, page_address(page),
						      PAGE_SIZE, DMA_FROM_DEVICE);
		err = ib_dma_mapping_error(cm->id->device, rx_desc->sge.addr);
		if (err) {
			tr_err(transport, "ib_dma_map_single() failed %d\n", err);
			goto out_put;
		}
		rx_desc->sge.length = PAGE_SIZE;
	}

	atomic_inc(&flow->rx_descs_allocated);
	atomic_inc(&flow->rx_descs_posted);
	err = dtr_post_rx_desc(cm, rx_desc);
	if (err) {
		tr_err(transport, "dtr_post_rx_desc() returned %d\n", err);
		atomic_dec(&flow->rx_descs_posted);
		atomic_dec(&flow->rx_descs_allocated);
		dtr_free_rx_desc(rx_desc);
	}
	return err;

out_put:
	kref_put(&cm->kref, dtr_destroy_cm);
out:
	kfree(rx_desc);
	if (page)
		drbd_free_page(transport, page);
	return err;
}

static void dtr_refill_rx_descs_work_fn(struct work_struct *work)
{
	struct dtr_path *path = container_of(work, struct dtr_path, refill_rx_descs_work);
	int i;

	if (!dtr_path_ok(path))
		return;

	for (i = DATA_STREAM; i <= ST_FLOW_CTRL ; i++) {
		struct dtr_flow *flow = &path->flow[i];

		if (atomic_read(&flow->rx_descs_posted) < flow->rx_descs_want_posted / 2)
			__dtr_refill_rx_desc(path, i);
		dtr_flow_control(flow, GFP_NOIO);
	}
}

static void __dtr_refill_rx_desc(struct dtr_path *path, enum drbd_stream stream)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_flow *flow = &path->flow[stream];
	int descs_want_posted, descs_max;

	descs_max = flow->rx_descs_max;
	descs_want_posted = flow->rx_descs_want_posted;

	/* Bootstrap phase: these descs are page-backed, so post only the few the
	 * handshake needs. dtr_rx_cqe_done() re-kicks the refill once the first
	 * peer RDMA-write ends the phase, and the window then fills buffer-less.
	 */
	if (!READ_ONCE(path->ring.rx_got_rdma_write))
		descs_want_posted = min(descs_want_posted, DTR_BOOTSTRAP_RX_DESCS);

	while (atomic_read(&flow->rx_descs_posted) < descs_want_posted &&
	       atomic_read(&flow->rx_descs_allocated) < descs_max) {
		int err;

		err = dtr_create_rx_desc(flow, (GFP_NOIO & ~__GFP_RECLAIM) | __GFP_NOWARN, true);
		/*
		 * drbd_alloc_pages() goes over the configured max_buffers, but throttles the
		 * caller with sleeping 100ms for each of those excess pages.  By calling
		 * without __GFP_RECLAIM we request to get a -ENOMEM instead of sleeping.
		 * We simply stop refilling then.
		 */
		if (err == -ENOMEM) {
			break;
		} else if (err) {
			tr_err(transport, "dtr_create_rx_desc() = %d\n", err);
			break;
		}
	}
}

static void dtr_refill_rx_desc(struct dtr_transport *rdma_transport,
			       enum drbd_stream stream)
{
	struct drbd_transport *transport = &rdma_transport->transport;
	struct drbd_path *drbd_path;

	for_each_path_ref(drbd_path, transport) {
		struct dtr_path *path = container_of(drbd_path, struct dtr_path, path);

		schedule_work(&path->refill_rx_descs_work);
	}
}

static int dtr_repost_rx_desc(struct dtr_cm *cm, struct dtr_rx_desc *rx_desc)
{
	/* Recycling a desc whose region bytes were read in place (a DATA header
	 * via _dtr_recv, or any CONTROL packet) rather than handed up in a BIO:
	 * drop its page references before the recv WR is reposted.
	 */
	dtr_put_data_pages(cm->path->path.transport, rx_desc);

	/* Once the SEND phase is over (a peer RDMA-write was seen, so by the single
	 * RC QP's in-order delivery no SEND can follow), drop a bootstrap desc's
	 * recv buffer and repost it num_sge=0 like every steady-state desc. While
	 * still in the SEND phase the page is kept so the desc can catch another
	 * SEND. drbd_free_page() on an order-0 page is just mempool_free(), safe
	 * from the softirq recycle path too.
	 */
	if (rx_desc->page && READ_ONCE(cm->path->ring.rx_got_rdma_write)) {
		ib_dma_unmap_single(cm->id->device, rx_desc->sge.addr,
				    PAGE_SIZE, DMA_FROM_DEVICE);
		drbd_free_page(cm->path->path.transport, rx_desc->page);
		rx_desc->page = NULL;
	}

	rx_desc->size = 0;
	return dtr_post_rx_desc(cm, rx_desc);
}

static void dtr_recycle_rx_desc(struct drbd_transport *transport,
				enum drbd_stream stream,
				struct dtr_rx_desc **pp_rx_desc,
				gfp_t gfp_mask)
{
	struct dtr_rx_desc *rx_desc = *pp_rx_desc;
	struct dtr_cm *cm;
	struct dtr_path *path;
	struct dtr_flow *flow;
	int err;

	if (!rx_desc)
		return;

	cm = rx_desc->cm;
	path = cm->path;
	flow = &path->flow[stream];

	err = dtr_repost_rx_desc(cm, rx_desc);

	if (err) {
		dtr_free_rx_desc(rx_desc);
	} else {
		atomic_inc(&flow->rx_descs_posted);
		dtr_flow_control(flow, gfp_mask);
	}

	*pp_rx_desc = NULL;
}

static int __dtr_post_tx_desc(struct dtr_cm *cm, struct dtr_tx_desc *tx_desc)
{
	struct dtr_transport *rdma_transport =
		container_of(cm->path->path.transport, struct dtr_transport, transport);
	struct ib_rdma_wr rdma_wr = {};
	const struct ib_send_wr *send_wr_failed;
	struct ib_device *device = cm->id->device;
	int i, err = -EIO;

	rdma_wr.wr.next = NULL;
	tx_desc->cqe.done = dtr_tx_cqe_done;
	rdma_wr.wr.wr_cqe = &tx_desc->cqe;
	rdma_wr.wr.sg_list = tx_desc->sge;
	rdma_wr.wr.num_sge = tx_desc->nr_sges;
	rdma_wr.wr.ex.imm_data = cpu_to_be32(tx_desc->imm);
	rdma_wr.wr.send_flags = IB_SEND_SIGNALED;
	if (tx_desc->rdma_write) {
		/* One-sided write straight into the peer's registered buffer;
		 * the immediate still carries {stream, sequence} for ordering.
		 */
		rdma_wr.wr.opcode = IB_WR_RDMA_WRITE_WITH_IMM;
		rdma_wr.remote_addr = tx_desc->remote_addr;
		rdma_wr.rkey = tx_desc->rkey;
	} else {
		rdma_wr.wr.opcode = IB_WR_SEND_WITH_IMM;
	}

	for (i = 0; i < tx_desc->nr_sges; i++)
		ib_dma_sync_single_for_device(device, tx_desc->sge[i].addr,
					      tx_desc->sge[i].length, DMA_TO_DEVICE);

	/* Arm the tx watchdog only for the first in-flight WR; it is reset on each
	 * completion (dtr_tx_cqe_done), so it tracks time since the last completion
	 * rather than the last post -- a stalled (black-holing) path is then caught
	 * within ping_timeo even under a steady post rate.
	 */
	if (atomic_inc_return(&cm->tx_descs_posted) == 1) {
		kref_get(&cm->kref); /* keep one extra ref as long as one tx is posted */
		dtr_arm_tx_timeout(cm);
	}

	err = ib_post_send(cm->id->qp, &rdma_wr.wr, &send_wr_failed);
	if (err) {
		tr_err(&rdma_transport->transport, "ib_post_send() failed %d\n", err);
		/* The WR never went out; mirror a completion. Only when the in-flight
		 * count reaches zero do we tear down the watchdog and drop the extra
		 * ref -- with other WRs still in flight the timer stays armed for them.
		 * This runs in softirq context on the failover-repost path, so no
		 * cancel_work_sync() here: if the watchdog already fired, its work owns
		 * the timer ref and drops it itself (as in dtr_tx_cqe_done()); neither
		 * put below can be the last one, the caller still holds a cm ref.
		 */
		if (atomic_dec_and_test(&cm->tx_descs_posted)) {
			bool was_active = timer_delete(&cm->tx_timeout);

			if (was_active)
				kref_put(&cm->kref, dtr_destroy_cm); /* timer ref */
			kref_put(&cm->kref, dtr_destroy_cm); /* the 0->1 extra ref */
		}
	}

	return err;
}

/* Pick a connected path to transmit one @stream packet on, and return its cm
 * (kref'd). DATA and CONTROL are both RDMA-written into a peer-announced receive
 * region, so a path also needs free region space: peek it here purely as a
 * scheduling gate, so the send_wq sleep wakes only when a usable path exists
 * rather than spinning on a credit-only path. The authoritative reservation
 * happens in the caller via dtr_reserve_and_post(); a peek that loses a race
 * to a concurrent reservation just makes the caller retry.
 */
static struct dtr_cm *dtr_select_and_get_cm_for_tx(struct dtr_transport *rdma_transport,
						     enum drbd_stream stream, unsigned int bytes)
{
	struct drbd_transport *transport = &rdma_transport->transport;
	struct dtr_path *path, *candidate = NULL;
	unsigned long last_sent_jif = -1UL;
	struct dtr_cm *cm;

	/*
	 * Within 16 jiffies use one path; in case we switch to another
	 * one, use the one that was used longest ago.
	 */

	rcu_read_lock();
	list_for_each_entry_rcu(path, &transport->paths, path.list) {
		struct dtr_flow *flow = &path->flow[stream];
		unsigned long ls;

		cm = rcu_dereference(path->cm);
		if (!cm || cm->state != DSM_CONNECTED || test_bit(DCF_SUSPECT, &cm->flags))
			continue;

		/* A path being gracefully removed (del-path) takes no new payload:
		 * the in-flight is drained and a shutdown marker handed to the peer
		 * before the QP is torn down. See dtr_remove_path().
		 */
		if (path->flags & (BIT(DTR_ACTIVE_SHUT_DOWN) | BIT(DTR_PASSIVE_SHUT_DOWN)))
			continue;

		/*
		 * Normal packets are not allowed to consume all of the
		 * peer's rx_descs; the last one is reserved for
		 * flow-control messages.
		 */
		if (atomic_read(&flow->tx_descs_posted) >= flow->tx_descs_max ||
		    atomic_read(&flow->peer_rx_descs) <= 1)
			continue;

		/* The packet RDMA-writes into a peer region; skip paths with no room
		 * for it.
		 */
		if (!dtr_remote_room(&path->regions[stream], bytes))
			continue;

		ls = cm->last_sent_jif;
		if ((ls & ~0xfUL) == (jiffies & ~0xfUL) && kref_get_unless_zero(&cm->kref)) {
			rcu_read_unlock();
			return cm;
		}
		if (ls < last_sent_jif) {
			last_sent_jif = ls;
			candidate = path;
		}
	}

	if (candidate) {
		/* The candidate's cm may be gone by now: a failover xchg()s path->cm
		 * to NULL and the last ref can drop at any instant after the loop
		 * examined it. NULL here just means no usable path this round; the
		 * caller sleeps and retries.
		 */
		cm = __dtr_path_get_cm(candidate);
		if (cm)
			cm->last_sent_jif = jiffies;
	} else {
		cm = NULL;
	}
	rcu_read_unlock();

	return cm;
}

/* Re-DMA-map a tx_desc from @old_cm's device onto @cm's device so it can be
 * reposted on a different path. The source pages/data are unchanged (for a
 * SEND_BIO they are pinned in tx_desc->wr_pages); only the DMA addresses and
 * lkeys change. Returns 0, or -EIO if a mapping failed (nothing left mapped on
 * the new device).
 */
static int dtr_remap_tx_desc(struct dtr_cm *old_cm, struct dtr_cm *cm,
			      struct dtr_tx_desc *tx_desc)
{
	struct ib_device *old_device = old_cm->id->device;
	struct ib_device *device = cm->id->device;
	u32 lkey = dtr_cm_to_lkey(cm);
	dma_addr_t a, old[DTR_MAX_TX_SGES];
	int i, pg;

	/* Map onto the new device first and drop the old mapping only once the new
	 * one is in place. A mapping failure then leaves the descriptor exactly as
	 * it was -- still mapped on @old_cm -- so the caller frees it normally with
	 * no double-unmap.
	 */
	switch (tx_desc->type) {
	case SEND_PAGE:
		a = ib_dma_map_page(device, tx_desc->page, tx_desc->sge[0].addr & ~PAGE_MASK,
				    tx_desc->sge[0].length, DMA_TO_DEVICE);
		if (ib_dma_mapping_error(device, a))
			return -EIO;
		ib_dma_unmap_page(old_device, tx_desc->sge[0].addr, tx_desc->sge[0].length,
				  DMA_TO_DEVICE);
		break;
	case SEND_MSG:
		a = ib_dma_map_single(device, tx_desc->data, tx_desc->sge[0].length, DMA_TO_DEVICE);
		if (ib_dma_mapping_error(device, a))
			return -EIO;
		ib_dma_unmap_single(old_device, tx_desc->sge[0].addr, tx_desc->sge[0].length,
				    DMA_TO_DEVICE);
		break;
	case SEND_BIO:
		/* Re-map every SGE against the new device, remembering the old DMA
		 * addresses. ib_dma_map_page() keeps the source page offset in the low
		 * bits of the address, so recover off/len from the (still-old) sge and
		 * walk wr_pages[] in lockstep: SGE i spans ceil(off + len) pages from
		 * the running page cursor (as dtr_add_bvec_sge() filled wr_pages[]).
		 * Back the whole batch out on failure so nothing is half-migrated.
		 */
		for (i = 0, pg = 0; i < tx_desc->nr_sges; i++) {
			unsigned int off = tx_desc->sge[i].addr & ~PAGE_MASK;
			unsigned int len = tx_desc->sge[i].length;
			unsigned int npages = DIV_ROUND_UP(off + len, PAGE_SIZE);

			a = ib_dma_map_page(device, tx_desc->wr_pages[pg], off, len, DMA_TO_DEVICE);
			if (ib_dma_mapping_error(device, a)) {
				while (--i >= 0) {
					ib_dma_unmap_page(device, tx_desc->sge[i].addr,
							  tx_desc->sge[i].length, DMA_TO_DEVICE);
					tx_desc->sge[i].addr = old[i];
				}
				return -EIO;
			}
			old[i] = tx_desc->sge[i].addr;
			tx_desc->sge[i].addr = a;
			tx_desc->sge[i].lkey = lkey;
			pg += npages;
		}
		for (i = 0; i < tx_desc->nr_sges; i++)
			ib_dma_unmap_page(old_device, old[i], tx_desc->sge[i].length,
					  DMA_TO_DEVICE);
		return 0;
	default:
		return -EINVAL;
	}

	tx_desc->sge[0].addr = a;
	tx_desc->sge[0].lkey = lkey;

	return 0;
}


/* Payload bytes of a desc: what its RDMA-WRITE occupies in the peer's region
 * before stride rounding.
 */
static unsigned int dtr_tx_desc_bytes(struct dtr_tx_desc *tx_desc)
{
	unsigned int bytes = 0;
	int i;

	for (i = 0; i < tx_desc->nr_sges; i++)
		bytes += tx_desc->sge[i].length;
	return bytes;
}

/* Attempt, once, to place a tx_desc whose path died onto a surviving path,
 * preserving its stream sequence number so the peer's in-order reorder queue
 * does not stall on the gap. For an rdma_write desc the new path's region is
 * path-specific, so a fresh contiguous chunk is reserved here and the descriptor
 * re-aimed at it; legacy SENDs need no region. Runs in the tx-completion softirq
 * (and from dtr_resend_work_fn()), so it never waits.
 *
 * Returns:
 *   0          -- placed and posted on a surviving path (desc now owned by it);
 *   -EAGAIN    -- no path could take it right now (none connected, or the
 *                 picked path is out of credit/region); @tx_desc is untouched,
 *                 still DMA-mapped on @old_cm, and may be retried later;
 *   -ECONNRESET-- the post failed after remapping (the picked path just went
 *                 bad); @tx_desc has been freed here.
 */
static int dtr_repost_tx_desc(struct dtr_cm *old_cm, struct dtr_tx_desc *tx_desc)
{
	struct dtr_transport *rdma_transport =
		container_of(old_cm->path->path.transport, struct dtr_transport, transport);
	enum drbd_stream stream = dtr_imm_stream(tx_desc->imm);
	unsigned int bytes = dtr_tx_desc_bytes(tx_desc);
	struct dtr_flow *flow;
	struct dtr_cm *cm;
	int err;

	cm = dtr_select_and_get_cm_for_tx(rdma_transport, stream, bytes);
	if (!cm)
		return -EAGAIN;

	flow = &cm->path->flow[stream];
	if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0)
		goto again_cm;
	if (!atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max))
		goto again_peer;

	/* Remap onto the new path's device first: the reserve and the post must
	 * be one atomic step (dtr_reserve_and_post), so no work may sit between
	 * them. A remap failure leaves the desc untouched on old_cm (remap
	 * maps-new-first).
	 */
	err = dtr_remap_tx_desc(old_cm, cm, tx_desc);
	if (err)
		goto again_tx;

	if (tx_desc->rdma_write) {
		/* The original region died with old_cm; aim the RDMA-WRITE at a
		 * fresh, contiguous chunk in the new path's region and post it in
		 * the same atomic step, so a concurrent sender on this path cannot
		 * slip a post between our reservation and our post.
		 */
		err = dtr_reserve_and_post(cm, &cm->path->regions[stream], tx_desc, bytes);
		if (err == -ENOBUFS) {
			/* Survivor momentarily out of region. Restore the desc onto
			 * old_cm, as the retry bookkeeping (resend_cm) requires; on
			 * the rare remap-back failure (it leaves the desc mapped on
			 * cm) the desc is unusable for a retry -- terminal.
			 */
			if (dtr_remap_tx_desc(cm, old_cm, tx_desc) == 0)
				goto again_tx;
			err = -ECONNRESET;
		}
	} else {
		err = __dtr_post_tx_desc(cm, tx_desc);
	}
	if (err) {
		/* The post failed (or the desc could not be restored): the desc is
		 * mapped on cm and cannot stay on old_cm for a retry -- terminal,
		 * free it.
		 */
		atomic_dec(&flow->tx_descs_posted);
		atomic_inc(&flow->peer_rx_descs);
		kref_put(&cm->kref, dtr_destroy_cm);
		dtr_free_tx_desc(cm, tx_desc);
		return -ECONNRESET;
	}

	kref_put(&cm->kref, dtr_destroy_cm);
	return 0;

again_tx:
	atomic_dec(&flow->tx_descs_posted);
again_peer:
	atomic_inc(&flow->peer_rx_descs);
again_cm:
	kref_put(&cm->kref, dtr_destroy_cm);
	return -EAGAIN;
}

/* Queue a tx_desc that dtr_repost_tx_desc() could not place right now for a
 * bounded, short-spaced retry from process context (dtr_resend_work_fn), instead
 * of dropping the connection on a transient survivor-region-full condition. The
 * desc stays DMA-mapped on @old_cm, so a reference on @old_cm is held until the
 * desc is finally placed or freed. Called from the tx-completion softirq.
 * Returns false (refusing the desc) once teardown has begun.
 */
static bool dtr_resend_enqueue(struct dtr_transport *rdma_transport, struct dtr_cm *old_cm,
			       struct dtr_tx_desc *tx_desc)
{
	/* Called from the tx-completion softirq and from the synchronous send path
	 * (dtr_flush_chunk), so the lock must disable bottom halves.
	 */
	spin_lock_bh(&rdma_transport->resend_lock);
	if (rdma_transport->resend_shutdown) {
		spin_unlock_bh(&rdma_transport->resend_lock);
		return false;
	}
	kref_get(&old_cm->kref);
	tx_desc->resend_cm = old_cm;
	atomic_inc(&rdma_transport->resend_pending[dtr_imm_stream(tx_desc->imm)]);
	list_add_tail(&tx_desc->resend_list, &rdma_transport->resend_q);
	spin_unlock_bh(&rdma_transport->resend_lock);

	schedule_delayed_work(&rdma_transport->resend_work, msecs_to_jiffies(DTR_RESEND_DELAY_MS));
	return true;
}

/* Hand a tx_desc whose path (@old_cm) just went bad to a surviving path:
 * re-aim it at a fresh chunk in that path's region (keeping its stream sequence
 * number so the peer's reorder queue does not stall) or, if no path can take it
 * this instant, queue it for a bounded async retry. Used both from the
 * tx-completion softirq (an in-flight WR errored) and from the synchronous send
 * path (__dtr_post_tx_desc() failed at post time -- the path died between
 * selection and post). Consumes @tx_desc in every case (placed, queued, or
 * freed); does not touch @old_cm's kref. FLOW_CTRL records must not be passed
 * here (they are regenerated by the flow-control machinery, not reposted).
 * Returns 0 if the connection survives (placed or queued), else a negative errno
 * (the caller should surface CLOSED_BY_PEER -- no path could take the desc).
 */
static int dtr_failover_tx_desc(struct dtr_transport *rdma_transport, struct dtr_cm *old_cm,
				struct dtr_tx_desc *tx_desc)
{
	int err = dtr_repost_tx_desc(old_cm, tx_desc);

	if (err == 0)
		return 0; /* placed on a surviving path */
	if (err == -EAGAIN && dtr_resend_enqueue(rdma_transport, old_cm, tx_desc))
		return 0; /* queued for a bounded async retry */

	/* -ECONNRESET: dtr_repost_tx_desc() already freed it.
	 * -EAGAIN with enqueue refused (teardown under way): still on old_cm.
	 */
	if (err == -EAGAIN)
		dtr_free_tx_desc(old_cm, tx_desc);
	return err;
}

static void dtr_resend_work_fn(struct work_struct *work)
{
	struct dtr_transport *rdma_transport =
		container_of(to_delayed_work(work), struct dtr_transport, resend_work);
	struct drbd_transport *transport = &rdma_transport->transport;
	struct dtr_tx_desc *tx_desc, *tmp;
	bool drop = false, more = false, shutdown;
	bool drained[2] = { false, false };
	LIST_HEAD(batch);
	int i;

	spin_lock_bh(&rdma_transport->resend_lock);
	list_splice_init(&rdma_transport->resend_q, &batch);
	shutdown = rdma_transport->resend_shutdown;
	spin_unlock_bh(&rdma_transport->resend_lock);

	list_for_each_entry_safe(tx_desc, tmp, &batch, resend_list) {
		struct dtr_cm *old_cm = tx_desc->resend_cm;
		enum drbd_stream stream = dtr_imm_stream(tx_desc->imm);
		int err;

		list_del(&tx_desc->resend_list);

		/* Backstop drainer for reposts left unplaced when no sender is active
		 * on the stream (an active sender drains them itself, ahead of its new
		 * sends, via dtr_drain_resend). Retry persistently while a path
		 * survives -- give up only on teardown or an all-paths-down transport.
		 * A per-desc deadline here would guillotine the connection out from
		 * under an inline drain that is still making progress on a saturated
		 * but recovering survivor; the genuine give-up for a permanently stuck
		 * survivor comes instead from the active sender's send timeout
		 * (dtr_wait_for_remote_buffer), the same bound a normal send has.
		 */
		if (shutdown || !dtr_transport_ok(transport)) {
			dtr_free_tx_desc(old_cm, tx_desc); /* still mapped on old_cm */
			kref_put(&old_cm->kref, dtr_destroy_cm);
			if (atomic_dec_and_test(&rdma_transport->resend_pending[stream]))
				drained[stream] = true;
			drop = true;
			continue;
		}

		err = dtr_repost_tx_desc(old_cm, tx_desc);
		if (err == 0) {
			kref_put(&old_cm->kref, dtr_destroy_cm); /* placed; release queue ref */
			if (atomic_dec_and_test(&rdma_transport->resend_pending[stream]))
				drained[stream] = true;
		} else if (err == -EAGAIN) {
			/* Survivor momentarily out of room; keep it queued and retry. */
			spin_lock_bh(&rdma_transport->resend_lock);
			list_add_tail(&tx_desc->resend_list, &rdma_transport->resend_q);
			spin_unlock_bh(&rdma_transport->resend_lock);
			more = true;
		} else {
			/* -ECONNRESET: dtr_repost_tx_desc() already freed it. */
			kref_put(&old_cm->kref, dtr_destroy_cm);
			if (atomic_dec_and_test(&rdma_transport->resend_pending[stream]))
				drained[stream] = true;
			drop = true;
		}
	}

	/* A stream whose queue just emptied may have senders blocked waiting for it. */
	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++)
		if (drained[i])
			wake_up_interruptible(&rdma_transport->stream[i].send_wq);

	if (more && !shutdown)
		schedule_delayed_work(&rdma_transport->resend_work,
				      msecs_to_jiffies(DTR_RESEND_DELAY_MS));
	if (drop)
		drbd_control_event(transport, CLOSED_BY_PEER);
}

/* True if any connected path has announced receive region room for a @bytes
 * RDMA-WRITE on @stream. Racy read, used only as a wait condition; the
 * authoritative reservation rechecks under remote_buffers_lock.
 */
static bool dtr_any_remote_room(struct dtr_transport *rdma_transport, enum drbd_stream stream,
				unsigned int bytes)
{
	struct drbd_transport *transport = &rdma_transport->transport;
	struct dtr_path *path;
	bool found = false;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &transport->paths, path.list) {
		if (dtr_remote_room(&path->regions[stream], bytes)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found;
}

/* Block until the peer announces @stream region space (or the connection goes
 * away). DATA and CONTROL are RDMA-written straight into a peer-announced
 * region, so region bytes -- not just WR credits -- are the back-pressure: when
 * the window is momentarily empty the sender waits here rather than spinning the
 * reserve-retry loop (which under a high control-rate workload like online
 * verify degenerates into a flow-control message storm). Woken by
 * dtr_got_announce_buffer_msg() (new region) and dtr_tx_cqe_done() (slot freed).
 * Returns 0 to retry, -EAGAIN once the send timeout is exhausted (the ko-count
 * then drops the connection, as for any stalled send), -EINTR on signal,
 * -ECONNRESET if the transport went away.
 */
static int dtr_wait_for_remote_buffer(struct dtr_transport *rdma_transport,
				      enum drbd_stream stream, unsigned int bytes)
{
	struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];
	struct drbd_transport *transport = &rdma_transport->transport;
	long t;

	t = wait_event_interruptible_timeout(rdma_stream->send_wq,
			dtr_any_remote_room(rdma_transport, stream, bytes) ||
				!dtr_transport_ok(transport),
			rdma_stream->send_timeout);
	if (t < 0)
		return -EINTR;
	if (!dtr_transport_ok(transport))
		return -ECONNRESET;
	if (t == 0 && drbd_stream_send_timed_out(transport, stream))
		return -EAGAIN;
	return 0;
}

/* Place this stream's queued failover reposts from the caller's process context
 * before it issues new sends. Reposts carry the dead path's LOWER sequence
 * numbers -- the gap the peer's reorder queue is stalled on. Sending them ahead
 * of new, higher-sequence data (which competes for the same survivor receive
 * region) lets the peer fill the gap, deliver, and re-announce region, which in
 * turn frees space for the remaining reposts; the new sends that follow
 * immediately keep that region cycling. This priority-then-resume ordering is
 * what a plain yield (stall the survivor -> peer stops re-announcing -> reposts
 * starve for region) and a plain no-yield (new high-seq sends grab the region
 * first) each fail to achieve. Crucially, placing a repost is itself survivor
 * traffic, so -- unlike a yield -- this drives the peer's re-announce rather than
 * starving it. Waits for region when the survivor is momentarily full, bounded
 * by the send timeout (the same back-pressure a normal send sees).
 *
 * A pulled desc is held on-stack (off the queue) across the retry/wait, so it
 * cannot race teardown's queue drain. Returns 0 once @stream's resend queue is
 * drained (caller may send), or a negative errno the caller should surface as a
 * connection drop: -ECONNRESET (transport gone), -EAGAIN (send timeout
 * exhausted), -EINTR (signal).
 */
static int dtr_drain_resend(struct dtr_transport *rdma_transport, enum drbd_stream stream)
{
	struct drbd_transport *transport = &rdma_transport->transport;

	while (atomic_read(&rdma_transport->resend_pending[stream])) {
		struct dtr_tx_desc *tx_desc = NULL, *iter;
		struct dtr_cm *old_cm;
		int err;

		spin_lock_bh(&rdma_transport->resend_lock);
		list_for_each_entry(iter, &rdma_transport->resend_q, resend_list) {
			if (dtr_imm_stream(iter->imm) == stream) {
				tx_desc = iter;
				list_del(&tx_desc->resend_list);
				break;
			}
		}
		spin_unlock_bh(&rdma_transport->resend_lock);

		/* pending > 0 but nothing queued for this stream: another drainer
		 * (the resend worker, or a concurrent sender) holds the desc
		 * mid-placement -- it is being prioritized there -- so let this
		 * caller proceed rather than spin.
		 */
		if (!tx_desc)
			return 0;

		old_cm = tx_desc->resend_cm;

		/* Retry THIS desc until it lands or we must give up; it stays
		 * on-stack (off the queue) the whole time.
		 */
		for (;;) {
			if (!dtr_transport_ok(transport)) {
				dtr_free_tx_desc(old_cm, tx_desc); /* still mapped on old_cm */
				kref_put(&old_cm->kref, dtr_destroy_cm);
				atomic_dec(&rdma_transport->resend_pending[stream]);
				return -ECONNRESET;
			}

			err = dtr_repost_tx_desc(old_cm, tx_desc);
			if (err == 0) {
				/* placed; release the queue's ref on old_cm */
				kref_put(&old_cm->kref, dtr_destroy_cm);
				atomic_dec(&rdma_transport->resend_pending[stream]);
				break;
			}
			if (err != -EAGAIN) {
				/* -ECONNRESET: dtr_repost_tx_desc() already freed it. */
				kref_put(&old_cm->kref, dtr_destroy_cm);
				atomic_dec(&rdma_transport->resend_pending[stream]);
				return err;
			}

			/* Survivor momentarily out of region: wait for an announce
			 * (the peer frees region as it consumes the reposts already
			 * placed), then retry this same desc.
			 */
			err = dtr_wait_for_remote_buffer(rdma_transport, stream,
							 dtr_tx_desc_bytes(tx_desc));
			if (err) {
				dtr_free_tx_desc(old_cm, tx_desc); /* still mapped on old_cm */
				kref_put(&old_cm->kref, dtr_destroy_cm);
				atomic_dec(&rdma_transport->resend_pending[stream]);
				return err;
			}
		}
	}
	return 0;
}

static int dtr_post_tx_desc(struct dtr_transport *rdma_transport,
			    struct dtr_tx_desc *tx_desc, bool nonblock)
{
	enum drbd_stream stream = dtr_imm_stream(tx_desc->imm);
	struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];
	struct ib_device *device;
	struct dtr_flow *flow;
	struct dtr_cm *cm = NULL;
	int offset, err;
	long t;

	/* SEND_PAGE stashes the page offset in sge[0].lkey (overwritten with the
	 * real lkey on each post attempt); read it once so a retry on a different
	 * path re-maps at the correct offset. dtr_post_tx_desc() only handles
	 * SEND_PAGE -- SEND_MSG/SEND_BIO BUG() below.
	 */
	offset = tx_desc->sge[0].lkey;

retry:
	/* @nonblock is set for a teardown flush (flush_send_buffer() passes
	 * MSG_DONTWAIT once cstate < C_CONNECTING). The peer is gone, so the
	 * credit/region this send needs will never be granted; waiting for it
	 * wedges the sender in flush_send_buffer() while it holds
	 * connection->mutex[stream], and conn_disconnect()'s
	 * drbd_transport_shutdown() then blocks behind it (both threads D-state,
	 * requiring a reboot). Make a single non-blocking attempt and return
	 * -EAGAIN instead -- both flush_send_buffer() callers discard the buffer
	 * on error during teardown. Skip the failover drain too (it waits, and a
	 * dying connection's reposts are moot).
	 */
	if (!nonblock && atomic_read(&rdma_transport->resend_pending[stream])) {
		/* Drain this stream's reposts (placing the lower-sequence
		 * gap-fillers ahead of this new send) before competing for the
		 * survivor's region.
		 */
		err = dtr_drain_resend(rdma_transport, stream);
		if (err)
			return err;
	}
	if (nonblock) {
		cm = dtr_select_and_get_cm_for_tx(rdma_transport, stream, tx_desc->sge[0].length);
		if (!cm)
			return -EAGAIN;
	} else {
		t = wait_event_interruptible_timeout(rdma_stream->send_wq,
				(cm = dtr_select_and_get_cm_for_tx(rdma_transport, stream,
								   tx_desc->sge[0].length)),
				rdma_stream->send_timeout);

		if (t == 0) {
			if (drbd_stream_send_timed_out(&rdma_transport->transport, stream))
				return -EAGAIN;
			goto retry;
		} else if (t < 0)
			return -EINTR;
	}

	flow = &cm->path->flow[stream];
	if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0) {
		kref_put(&cm->kref, dtr_destroy_cm);
		if (nonblock)
			return -EAGAIN;
		goto retry;
	}
	if (!atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max)) {
		atomic_inc(&flow->peer_rx_descs);
		kref_put(&cm->kref, dtr_destroy_cm);
		if (nonblock)
			return -EAGAIN;
		goto retry;
	}

	/* Map the source page before the reserve: the region reservation and the
	 * post must be one atomic step (dtr_reserve_and_post), so nothing may sit
	 * between them.
	 */
	device = cm->id->device;
	switch (tx_desc->type) {
	case SEND_PAGE:
		tx_desc->sge[0].addr = ib_dma_map_page(device, tx_desc->page, offset,
						      tx_desc->sge[0].length, DMA_TO_DEVICE);
		err = ib_dma_mapping_error(device, tx_desc->sge[0].addr);
		if (err) {
			atomic_inc(&flow->peer_rx_descs);
			atomic_dec(&flow->tx_descs_posted);
			goto out;
		}

		tx_desc->sge[0].lkey = dtr_cm_to_lkey(cm);
		break;
	case SEND_MSG:
	case SEND_BIO:
		WARN_ON_ONCE(1);
		atomic_inc(&flow->peer_rx_descs);
		atomic_dec(&flow->tx_descs_posted);
		err = -EINVAL;
		goto out;
	}

	/* DATA and CONTROL are RDMA-written straight into the peer's receive
	 * region: reserve a chunk and post at it atomically (the room check in
	 * path selection only gated the sleep). The chunk is the message size
	 * rounded up to the region's stride, matching the receiver's consume.
	 */
	err = dtr_reserve_and_post(cm, &cm->path->regions[stream], tx_desc,
				   tx_desc->sge[0].length);
	if (err) {
		atomic_inc(&flow->peer_rx_descs);
		atomic_dec(&flow->tx_descs_posted);
		ib_dma_unmap_page(device, tx_desc->sge[0].addr,
				  tx_desc->sge[0].length, DMA_TO_DEVICE);
		kref_put(&cm->kref, dtr_destroy_cm);
		if (err == -ENOBUFS) {
			/* Lost the region space to a concurrent (failover)
			 * reservation, or the peer has not yet re-announced a
			 * consumed region. Block on region space rather than
			 * busy-retrying the select loop.
			 */
			if (nonblock)
				return -EAGAIN;
			err = dtr_wait_for_remote_buffer(rdma_transport, stream,
							 tx_desc->sge[0].length);
			if (err)
				return err;
		}
		/* Otherwise the post itself failed: the path went bad between
		 * selection and post and is suspect now (dtr_reserve_and_post);
		 * retry on a surviving path rather than returning an error that
		 * tears the whole connection down; send_timeout bounds the retry.
		 * The chunk consumed on this path's region dies with the path.
		 */
		goto retry;
	}

out:
	kref_put(&cm->kref, dtr_destroy_cm);
	return err;
}

/* Reserve one send credit for an announce message from the FLOW_CTRL pool: one
 * control-ring slot == one peer recv WR == one tx slot. Announce, like
 * flow-control, is an ST_FLOW_CTRL record and charges the dedicated FLOW_CTRL
 * credit pool, so the writer can have at most DTR_FLOW_CTRL_DESCS records
 * outstanding and never laps an unread ring slot. Returns ST_FLOW_CTRL (the
 * record's send_from_stream), or -1 if no credit is free right now.
 */
static int dtr_reserve_send_credit(struct dtr_path *path)
{
	struct dtr_flow *flow = &path->flow[ST_FLOW_CTRL];

	if (atomic_read(&flow->tx_descs_posted) >= flow->tx_descs_max)
		return -1;
	if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0)
		return -1;
	if (atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max))
		return ST_FLOW_CTRL;
	atomic_inc(&flow->peer_rx_descs); /* undo */
	return -1;
}

static int dtr_send_announce_buffer_msg(struct dtr_path *path, enum dtr_stream_nr stream,
					struct dtr_local_buffer *buf, gfp_t gfp_mask)
{
	struct dtr_announce_buffer msg = {};
	struct dtr_flow *flow;
	int send_from_stream, err;

	msg.magic = cpu_to_be32(DTR_ANNOUNCE_MAGIC);
	msg.addr = cpu_to_be64(buf->addr);
	msg.rkey = cpu_to_be32(buf->rkey);
	msg.len = cpu_to_be32(buf->len);
	msg.region_stream = cpu_to_be32(stream);
	msg.stride = cpu_to_be32(buf->stride);

	send_from_stream = dtr_reserve_send_credit(path);
	if (send_from_stream < 0)
		return -ENOBUFS;
	msg.send_from_stream = cpu_to_be32(send_from_stream);

	err = dtr_send(path, &msg, sizeof(msg), gfp_mask);
	if (err) {
		flow = &path->flow[send_from_stream];
		atomic_inc(&flow->peer_rx_descs);
		atomic_dec(&flow->tx_descs_posted);
	}
	return err;
}

static int dtr_got_announce_buffer_msg(struct dtr_cm *cm, struct dtr_announce_buffer *msg)
{
	struct dtr_path *path = cm->path;
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	struct drbd_transport *transport = &rdma_transport->transport;
	u32 len = be32_to_cpu(msg->len);
	u32 stride = be32_to_cpu(msg->stride);
	enum dtr_stream_nr stream = be32_to_cpu(msg->region_stream);
	struct dtr_region_set *rs;
	struct dtr_remote_buffer *rb;
	unsigned long flags;

	if (stream == ST_FLOW_CTRL) {
		/* Bootstrap announce of the peer's control ring: record where to
		 * RDMA-WRITE our flow-control / announce records. Not a payload
		 * region. The peer posted the ring's REG_MR before this announce on
		 * the same QP, so by RC ordering the ring MR is valid now.
		 */
		spin_lock_irqsave(&path->ring.lock, flags);
		path->ring.remote_addr = be64_to_cpu(msg->addr);
		path->ring.remote_rkey = be32_to_cpu(msg->rkey);
		path->ring.remote_known = true;
		spin_unlock_irqrestore(&path->ring.lock, flags);

		/* The control ring can now carry announces: register and announce
		 * the DATA/CONTROL receive regions (the deferred kick promised in
		 * dtr_path_established_work_fn()).
		 */
		dtr_kick_register_buffers(path);
		return be32_to_cpu(msg->send_from_stream);
	}

	if (stream != ST_DATA && stream != ST_CONTROL) {
		if (__ratelimit(&rdma_transport->rate_limit))
			tr_err(transport, "announce for bad stream %u\n", stream);
		return be32_to_cpu(msg->send_from_stream);
	}
	rs = &path->regions[stream];

	/* Sender and receiver consume a region in lockstep by its stride (see
	 * dtr_reserve_and_post()); a stride we cannot mirror -- or a region we
	 * cannot record -- would make the cursors diverge and hand up wrong data.
	 * Drop the connection instead of using the region.
	 */
	if (len && (!stride || !is_power_of_2(stride) || stride > PAGE_SIZE ||
		    len % stride)) {
		if (__ratelimit(&rdma_transport->rate_limit))
			tr_err(transport, "announce with bad stride %u (len %u); dropping connection\n",
			       stride, len);
		goto drop;
	}

	if (len) {
		rb = kzalloc_obj(*rb, GFP_ATOMIC);
		if (!rb) {
			if (__ratelimit(&rdma_transport->rate_limit))
				tr_err(transport, "no memory for remote buffer; dropping connection\n");
			goto drop;
		}
		rb->addr = be64_to_cpu(msg->addr);
		rb->rkey = be32_to_cpu(msg->rkey);
		rb->len = len;
		rb->stride = stride;

		spin_lock_irqsave(&rs->remote_buffers_lock, flags);
		list_add_tail(&rb->list, &rs->remote_buffers);
		spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);
	}

	wake_up_interruptible(&rdma_transport->stream[stream].send_wq);

	return be32_to_cpu(msg->send_from_stream);

drop:
	set_bit(DSB_ERROR, &cm->state);
	kref_get(&cm->kref);
	if (!schedule_work(&cm->end_rx_work))
		kref_put(&cm->kref, dtr_destroy_cm);

	wake_up_interruptible(&rdma_transport->stream[stream].send_wq);

	return be32_to_cpu(msg->send_from_stream);
}

/* Send the graceful-shutdown marker (the RDMA FIN) on @path. Modeled on
 * dtr_send_announce_buffer_msg(): reserve an ST_FLOW_CTRL credit, ride the
 * control ring. Because it shares the path's single RC QP with all payload, it
 * is delivered in order after every DATA/CONTROL write already posted here.
 */
static int dtr_send_shutdown_msg(struct dtr_path *path, gfp_t gfp_mask)
{
	struct dtr_shutdown msg = {};
	struct dtr_flow *flow;
	int send_from_stream, err;

	msg.magic = cpu_to_be32(DTR_SHUTDOWN_MAGIC);

	send_from_stream = dtr_reserve_send_credit(path);
	if (send_from_stream < 0)
		return -ENOBUFS;
	msg.send_from_stream = cpu_to_be32(send_from_stream);

	err = dtr_send(path, &msg, sizeof(msg), gfp_mask);
	if (err) {
		flow = &path->flow[send_from_stream];
		atomic_inc(&flow->peer_rx_descs);
		atomic_dec(&flow->tx_descs_posted);
	}
	return err;
}

/* Echo a shutdown marker back to a peer that initiated a path removal, in
 * process context (the rx softirq scheduled us). Best effort: if it cannot be
 * placed the initiator's bounded wait falls back to an abrupt teardown.
 */
static void dtr_shutdown_work_fn(struct work_struct *work)
{
	struct dtr_path *path = container_of(work, struct dtr_path, shutdown_work);
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	unsigned long deadline = jiffies + HZ;
	int err;

	/* Echo the marker back so the initiator can confirm our payload drained.
	 * Retry for a FLOW_CTRL credit under load (see dtr_remove_path); the
	 * initiator times out and tears down abruptly if our echo never lands.
	 */
	for (;;) {
		err = dtr_send_shutdown_msg(path, GFP_NOIO);
		if ((err != -ENOBUFS && err != -ENOMEM) ||
		    !dtr_path_ok(path) || time_after_eq(jiffies, deadline))
			break;
		msleep(20);
	}
	if (err && err != -ENOBUFS && __ratelimit(&rdma_transport->rate_limit))
		tr_warn(transport, "echo of shutdown marker failed %d\n", err);
}

/* The peer announced it will send no more payload on this path (its FIN). Since
 * the marker rode the same RC QP as the peer's payload, every DATA/CONTROL
 * write the peer posted on this path has already been delivered to our rx
 * completion (placed in the reorder queue or consumed) by the time we see this.
 * Record it (DTR_PASSIVE_SHUT_DOWN also stops us selecting the path for new
 * payload), and -- unless we initiated the removal ourselves -- echo a marker
 * back so the initiator can confirm OUR payload drained too. Wake any
 * dtr_remove_path() waiting on this path.
 */
static int dtr_got_shutdown_msg(struct dtr_path *path, struct dtr_shutdown *msg)
{
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);

	if (!test_and_set_bit(DTR_PASSIVE_SHUT_DOWN, &path->flags)) {
		if (!test_bit(DTR_ACTIVE_SHUT_DOWN, &path->flags))
			schedule_work(&path->shutdown_work);
	}
	wake_up_interruptible(&rdma_transport->shutdown_wq);

	return be32_to_cpu(msg->send_from_stream);
}

static void dtr_free_remote_buffers(struct dtr_path *path)
{
	struct dtr_remote_buffer *rb, *tmp;
	unsigned long flags;
	LIST_HEAD(buffers);
	int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		struct dtr_region_set *rs = &path->regions[i];

		spin_lock_irqsave(&rs->remote_buffers_lock, flags);
		list_splice_tail_init(&rs->remote_buffers, &buffers);
		spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);
	}

	list_for_each_entry_safe(rb, tmp, &buffers, list) {
		list_del(&rb->list);
		kfree(rb);
	}
}

/* Bytes a @bytes write occupies in a region with @stride: the receiver advances
 * its cursor by exactly this (dtr_consume_local_buffer()), so both sides must
 * compute it identically from nothing but the write's length.
 */
static u32 dtr_chunk_size(unsigned int bytes, u32 stride)
{
	return round_up(max(bytes, 1U), stride);
}

/* Find the remote buffer a @bytes write goes into: the first one, in announce
 * order, whose remaining tail can take it. Buffers before it are too small for
 * this write and are abandoned when the write is placed (the "tail rule"): the
 * receiver, seeing a write that does not fit its head region, retires that
 * region and consumes from the next -- so as long as both sides walk the same
 * region sequence with the same write lengths, their cursors agree without any
 * address on the wire. Caller holds remote_buffers_lock. Returns NULL if no
 * announced buffer can take the write (nothing is changed then: the caller may
 * wait for an announce, and a smaller write may still use the tail).
 */
static struct dtr_remote_buffer *
__dtr_find_remote_buffer(struct dtr_region_set *rs, unsigned int bytes)
{
	struct dtr_remote_buffer *rb;

	list_for_each_entry(rb, &rs->remote_buffers, list) {
		if (dtr_chunk_size(bytes, rb->stride) <= rb->len - rb->consumed)
			return rb;
	}
	return NULL;
}

/* Reserve room for a @bytes RDMA-WRITE in the peer's remote buffers and post
 * @tx_desc aimed at it, in one atomic step under remote_buffers_lock.
 *
 * Why atomic: the receiver never learns a write's target address from the wire.
 * dtr_consume_local_buffer() advances its own region cursor by the write's
 * stride-rounded byte count in completion order, and RC completions arrive in
 * posted order -- so region space must be consumed in exactly the order the
 * writes are posted to the QP. With concurrent reservers on one region (a
 * payload sender and a failover repost from the tx-completion softirq or the
 * resend worker, see dtr_repost_tx_desc()), a separate reserve-then-post-later
 * scheme can invert post order against cursor order; the writes then land where
 * the receiver's cursor no longer points and the stream hands up wrong data.
 *
 * All-or-nothing: -ENOBUFS if no announced buffer can take the write right now
 * (@tx_desc untouched, nothing posted, nothing consumed, no buffer abandoned) --
 * a partial grant cannot help the single-WR caller. Consumption is
 * stride-granular (the region's announced stride, a cache line or the core's
 * dma_alignment), so neighbouring writes may share a region page; the receiver
 * reference-counts the pages accordingly.
 *
 * On a post failure the path is marked suspect: its cursor has advanced past a
 * write the peer will never receive, so no further payload may be posted on
 * this path (its buffers are dropped and re-announced on the re-establish).
 * Returns the ib_post_send() error in that case; @tx_desc is not freed.
 */
static int dtr_reserve_and_post(struct dtr_cm *cm, struct dtr_region_set *rs,
				struct dtr_tx_desc *tx_desc, unsigned int bytes)
{
	struct dtr_remote_buffer *rb, *tmp;
	unsigned long flags;
	int err;

	spin_lock_irqsave(&rs->remote_buffers_lock, flags);
	rb = __dtr_find_remote_buffer(rs, bytes);
	if (!rb) {
		spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);
		return -ENOBUFS;
	}
	/* Tail rule: the buffers ahead of @rb cannot take this write; the
	 * receiver retires them when the write arrives, so do the same here.
	 */
	for (;;) {
		tmp = list_first_entry(&rs->remote_buffers, struct dtr_remote_buffer, list);
		if (tmp == rb)
			break;
		list_del(&tmp->list);
		kfree(tmp);
	}
	tx_desc->rdma_write = true;
	tx_desc->remote_addr = rb->addr + rb->consumed;
	tx_desc->rkey = rb->rkey;
	rb->consumed += dtr_chunk_size(bytes, rb->stride);
	if (rb->consumed >= rb->len) {
		list_del(&rb->list);
		kfree(rb);
	}
	err = __dtr_post_tx_desc(cm, tx_desc);
	spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);

	if (err) {
		set_bit(DSB_ERROR, &cm->state);
		dtr_cm_set_suspect(cm);
	}
	return err;
}

/* Room for a @bytes write: the bytes remaining in the remote buffer it would go
 * into (see __dtr_find_remote_buffer()), without consuming anything. Advisory
 * only -- used to gate path selection, as a wait condition, and to size a bio
 * chunk (pass @bytes == 1 for "any room at all"); the authoritative consume is
 * the atomic dtr_reserve_and_post(), which may race ahead (e.g. a failover
 * repost from tx-completion), so the caller handles coming up short there.
 * Returns 0 if no announced region can take the write.
 */
static u32 dtr_remote_room(struct dtr_region_set *rs, unsigned int bytes)
{
	struct dtr_remote_buffer *rb;
	unsigned long flags;
	u32 room = 0;

	spin_lock_irqsave(&rs->remote_buffers_lock, flags);
	rb = __dtr_find_remote_buffer(rs, bytes);
	if (rb)
		room = rb->len - rb->consumed;
	spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);

	return room;
}

/* Total bytes of RDMA-WRITE receive region to keep registered for @rs, given
 * the @stride its regions will be consumed at: the stream's net_conf receive
 * window (rx_window_bytes), decoupled from the QP/rx_desc count so it can be
 * large. Capped so it stays usable and safe:
 *   - at half the peer's WR-credit capacity (rx_descs_max WRs, each carrying up
 *     to sges_max pages) so the credit window never becomes the binding
 *     resource and control/flow messages keep headroom, and
 *   - at half of max_buffers, since region pages are charged to pp_in_use and
 *     allocating them must not trip the drbd_alloc_pages() throttle against
 *     in-flight payload.
 */
static u32 dtr_local_buffer_target_bytes(struct dtr_region_set *rs, u32 stride)
{
	struct dtr_path *path = rs->path;
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	struct dtr_flow *flow = &path->flow[rs->stream];
	u32 want = flow->rx_window_bytes;
	u32 credit_cap, mxb_cap;
	struct net_conf *nc;

	credit_cap = (u32)flow->rx_descs_max / 2 * rdma_transport->sges_max * PAGE_SIZE;

	rcu_read_lock();
	nc = rcu_dereference(rdma_transport->transport.net_conf);
	mxb_cap = nc ? (u32)nc->max_buffers / 2 * PAGE_SIZE : want;

	/* CONTROL carries packets of tens of bytes and consumes region space at
	 * @stride, so unlike DATA it does not need a PAGE_SIZE slot per WR
	 * credit: room for two credit windows of stride-sized packets keeps one
	 * region taking writes while the other cycles. The credit window itself
	 * stays as wide as DATA's (see dtr_init_flow()) -- a CONTROL window that
	 * cannot hold the acks for the writes in flight on a path deadlocks that
	 * path's failover. An explicit rdma-ctrl-rcvbuf-size still means what it
	 * says.
	 */
	if (rs->stream == CONTROL_STREAM && nc && !nc->rdma_ctrl_rcvbuf_size)
		want = clamp_t(u32, 2 * flow->rx_descs_max * stride,
			       DTR_MIN_REGION_BYTES, want);
	rcu_read_unlock();

	return min3(want, credit_cap, mxb_cap);
}

/* Largest region order to try for the next registration: big enough to cover
 * the still-missing window bytes in one region, capped by the device's
 * fast-reg MR page-list limit and MAX_PAGE_ORDER. drbd_alloc_pages_split()
 * falls back to smaller orders if the contiguous allocation fails.
 */
static int dtr_region_order(struct dtr_transport *rdma_transport, u32 want_bytes)
{
	int want_order = ilog2(max(want_bytes >> PAGE_SHIFT, 1U));
	int dev_order = ilog2(max(rdma_transport->max_mr_pages, 1));

	return min3(want_order, dev_order, (int)MAX_PAGE_ORDER);
}

/* Pages an MR's page list is sized for. Pooled region MRs are allocated for the
 * device maximum so a region of any order (re-)mapped into the same MR fits,
 * and the MR is reused across the region's whole arm/consume/re-arm life --
 * never reallocated per cycle.
 */
static int dtr_max_region_pages(struct dtr_transport *rdma_transport)
{
	return min(rdma_transport->max_mr_pages, 1 << MAX_PAGE_ORDER);
}

/* Drop the region's own reference on each of its pages. Pages a consumer still
 * references (an rx_desc read in place, or a bvec handed up to the core) stay
 * alive until that holder's drbd_free_page(); the last reference returns the
 * order-0 split page through the buffer mempool.
 */
static void dtr_free_region_pages(struct drbd_transport *transport,
				  struct page *head, int nr_pages)
{
	int i;

	for (i = 0; i < nr_pages; i++)
		drbd_free_page(transport, head + i);
}

/* Granularity at which a region of @rs is consumed. Every RDMA-WRITE into it
 * occupies its length rounded up to this, on both sides, so it is a property
 * of the region and travels with its announce. Only the receiver's constraints
 * matter (the writes land in its memory): the DMA cache-line requirement
 * (dma_get_cache_alignment(), 1 on coherent architectures), a cache line as a
 * performance floor (no partial-line DMA writes, no CPU/NIC false sharing
 * between neighbouring messages; packing tighter gains nothing since WR
 * credits, not region bytes, bound the messages in flight), and for DATA the
 * alignment the core's backing devices demand of the payload it hands up
 * (set_rx_alignment). A power of two, at most PAGE_SIZE.
 */
static u32 dtr_region_stride(struct dtr_region_set *rs)
{
	struct dtr_transport *rdma_transport =
		container_of(rs->path->path.transport, struct dtr_transport, transport);
	u32 stride = max_t(u32, SMP_CACHE_BYTES, dma_get_cache_alignment());

	if (rs->stream == DATA_STREAM)
		stride = max(stride, READ_ONCE(rdma_transport->rx_align_hint));

	return min_t(u32, roundup_pow_of_two(stride), PAGE_SIZE);
}

static void dtr_reg_mr_cqe_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct dtr_cm *cm = cq->cq_context;

	/* IB_WR_REG_MR is posted unsignaled; a completion here means it was
	 * flushed because the QP went to error. The region is freed in the
	 * teardown path; just mark the connection bad. Deliberately does not
	 * touch any dtr_local_buffer, which may already be freed by the time
	 * this flush completion is drained.
	 */
	if (wc->status != IB_WC_SUCCESS && wc->status != IB_WC_WR_FLUSH_ERR) {
		struct dtr_transport *rdma_transport =
			container_of(cm->path->path.transport, struct dtr_transport, transport);

		if (__ratelimit(&rdma_transport->rate_limit))
			tr_warn(&rdma_transport->transport,
				"REG_MR failed, wc.status = %d\n", wc->status);
	}
	set_bit(DSB_ERROR, &cm->state);
}

static void dtr_inv_cqe_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct dtr_local_buffer *buf = container_of(wc->wr_cqe, struct dtr_local_buffer, inv_cqe);

	complete(&buf->inv_done);
}

static void dtr_release_local_buffer(struct dtr_path *path, struct dtr_local_buffer *buf);

/* Allocate a region descriptor and its reusable fast-registration MR, with no
 * backing pages yet (dtr_arm_local_buffer() attaches those). The MR lives for
 * the whole pooled lifetime of the buffer; only dtr_release_local_buffer()
 * frees it. Holds a cm kref. Returns NULL on failure.
 */
static struct dtr_local_buffer *dtr_alloc_local_buffer(struct dtr_path *path)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_local_buffer *buf;
	struct dtr_cm *cm;

	cm = dtr_path_get_cm_connected(path);
	if (!cm)
		return NULL;

	buf = kzalloc_obj(*buf, GFP_NOIO);
	if (!buf)
		goto out_put_cm;

	buf->mr = ib_alloc_mr(cm->pd, IB_MR_TYPE_MEM_REG,
			      dtr_max_region_pages(rdma_transport));
	if (IS_ERR(buf->mr)) {
		tr_err(transport, "ib_alloc_mr() failed %ld\n", PTR_ERR(buf->mr));
		buf->mr = NULL;
		goto out_free_buf;
	}

	buf->cm = cm; /* transfer the ref; released in dtr_release_local_buffer() */
	return buf;

out_free_buf:
	kfree(buf);
out_put_cm:
	kref_put(&cm->kref, dtr_destroy_cm);
	return NULL;
}

/* Post the unsignaled IB_WR_REG_MR that makes @mr's current mapping usable for
 * remote access. Ordered before any announce/write posted right after it, so
 * the rkey is valid by the time the peer can reach it. Requires the QP to be
 * postable (RTS), which holds for both regions and the ring since both register
 * post-establishment. ib_post_send() copies the WR, so a stack reg_wr is fine;
 * the completion anchor (cm->reg_cqe) outlives the buffer.
 */
static int dtr_post_reg_mr(struct dtr_cm *cm, struct ib_mr *mr)
{
	struct ib_reg_wr mr_reg_wr = {};

	mr_reg_wr.wr.next = NULL;
	mr_reg_wr.wr.wr_cqe = &cm->reg_cqe;
	mr_reg_wr.wr.num_sge = 0;
	mr_reg_wr.wr.opcode = IB_WR_REG_MR;
	mr_reg_wr.wr.send_flags = 0; /* unsignaled, ordered before the announce */
	mr_reg_wr.mr = mr;
	mr_reg_wr.key = mr->rkey;
	mr_reg_wr.access = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE;

	return ib_post_send(cm->id->qp, &mr_reg_wr.wr, NULL);
}

/* Attach a freshly allocated split-page region to @buf, (re-)register @buf->mr
 * over it for REMOTE_WRITE, and post the unsignaled IB_WR_REG_MR. The caller
 * announces the region right after, so it is ordered behind the REG_MR and the
 * rkey is valid before the peer can write. The MR is reused -- no
 * ib_alloc_mr()/ib_dereg_mr() per cycle. Returns 0, or a negative errno with
 * @buf left disarmed (no pages attached).
 */
static int dtr_arm_local_buffer(struct dtr_path *path, struct dtr_local_buffer *buf,
				int max_order, u32 stride)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_cm *cm = buf->cm;
	struct ib_device *device = cm->id->device;
	int order = max_order, n, err;
	struct page *head_page;

	/* Largest contiguous region we can get up to max_order; the actual order
	 * (possibly smaller, on fragmentation) comes back in @order.
	 */
	head_page = drbd_alloc_pages_split(transport,
					   (GFP_NOIO & ~__GFP_RECLAIM) | __GFP_NOWARN,
					   &order);
	if (!head_page)
		return -ENOMEM;

	buf->head_page = head_page;
	buf->nr_pages = 1 << order;
	buf->len = buf->nr_pages << PAGE_SHIFT;
	buf->consumed = 0;
	buf->stride = stride;
	sg_init_table(&buf->sg, 1);
	sg_set_page(&buf->sg, head_page, buf->len, 0);

	n = ib_dma_map_sg(device, &buf->sg, 1, DMA_FROM_DEVICE);
	if (n != 1) {
		tr_err(transport, "ib_dma_map_sg() failed\n");
		err = -EIO;
		goto out_free_pages;
	}

	n = ib_map_mr_sg(buf->mr, &buf->sg, 1, NULL, PAGE_SIZE);
	if (n != 1) {
		tr_err(transport, "ib_map_mr_sg() = %d\n", n);
		err = -EIO;
		goto out_unmap_sg;
	}

	/* Rotate the key portion of the rkey, as fast-registration users do. */
	ib_update_fast_reg_key(buf->mr, (u8)(buf->mr->rkey & 0xff) + 1);
	buf->addr = buf->mr->iova;
	buf->rkey = buf->mr->rkey;

	err = dtr_post_reg_mr(cm, buf->mr);
	if (err) {
		tr_err(transport, "ib_post_send(REG_MR) = %d\n", err);
		goto out_unmap_sg;
	}

	return 0;

out_unmap_sg:
	ib_dma_unmap_sg(device, &buf->sg, 1, DMA_FROM_DEVICE);
out_free_pages:
	dtr_free_region_pages(transport, head_page, buf->nr_pages);
	buf->head_page = NULL;
	return err;
}

/* Detach the current backing region from @buf: unmap the MR's scatterlist and
 * drop the region's references on its pages (consumers hold their own). Leaves
 * @buf->mr allocated for reuse by a subsequent dtr_arm_local_buffer().
 */
static void dtr_disarm_local_buffer(struct dtr_path *path, struct dtr_local_buffer *buf)
{
	struct drbd_transport *transport = path->path.transport;

	if (!buf->head_page)
		return;
	ib_dma_unmap_sg(buf->cm->id->device, &buf->sg, 1, DMA_FROM_DEVICE);
	dtr_free_region_pages(transport, buf->head_page, buf->nr_pages);
	buf->head_page = NULL;
}

/* Return @buf->mr to the FREE state so dtr_arm_local_buffer() can re-register
 * it. A fast-reg MR must actually be FREE (not merely have a posted invalidate)
 * before it is re-mapped -- rxe rejects re-mapping a VALID MR -- so post a
 * signaled IB_WR_LOCAL_INV and wait for its completion (we are in the
 * register_buffers work, which may sleep). Returns 0 on success.
 */
static int dtr_invalidate_local_buffer(struct dtr_path *path, struct dtr_local_buffer *buf)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_cm *cm = buf->cm;
	struct ib_send_wr inv_wr = {
		.opcode = IB_WR_LOCAL_INV,
		.send_flags = IB_SEND_SIGNALED,
		.ex.invalidate_rkey = buf->mr->rkey,
		.wr_cqe = &buf->inv_cqe,
	};
	int err;

	buf->inv_cqe.done = dtr_inv_cqe_done;
	init_completion(&buf->inv_done);

	err = ib_post_send(cm->id->qp, &inv_wr, NULL);
	if (err) {
		tr_err(transport, "ib_post_send(LOCAL_INV) = %d\n", err);
		return err;
	}

	if (!wait_for_completion_timeout(&buf->inv_done, 10 * HZ)) {
		tr_err(transport, "LOCAL_INV did not complete\n");
		return -ETIMEDOUT;
	}
	return 0;
}

/* Allocate and arm a brand-new region (grows the pool). Steady-state recycling
 * re-arms existing buffers via dtr_arm_local_buffer() to reuse their MR; this
 * is only for filling the window with additional regions. Returns NULL on
 * failure (nothing left allocated).
 */
static struct dtr_local_buffer *dtr_register_local_buffer(struct dtr_path *path, int max_order,
							  u32 stride)
{
	struct dtr_local_buffer *buf;

	buf = dtr_alloc_local_buffer(path);
	if (!buf)
		return NULL;

	if (dtr_arm_local_buffer(path, buf, max_order, stride)) {
		dtr_release_local_buffer(path, buf);
		return NULL;
	}
	return buf;
}

static void dtr_release_local_buffer(struct dtr_path *path, struct dtr_local_buffer *buf)
{
	struct dtr_cm *cm = buf->cm;

	dtr_disarm_local_buffer(path, buf); /* unmap + free; ib_dereg_mr invalidates */
	ib_dereg_mr(buf->mr);
	kref_put(&cm->kref, dtr_destroy_cm);
	kfree(buf);
}

static void dtr_free_local_buffers(struct dtr_path *path)
{
	struct dtr_local_buffer *buf, *tmp;
	unsigned long flags;
	LIST_HEAD(buffers);
	int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		struct dtr_region_set *rs = &path->regions[i];

		spin_lock_irqsave(&rs->local_buffers_lock, flags);
		list_splice_tail_init(&rs->local_buffers, &buffers);
		list_splice_tail_init(&rs->exhausted_buffers, &buffers);
		spin_unlock_irqrestore(&rs->local_buffers_lock, flags);
	}

	list_for_each_entry_safe(buf, tmp, &buffers, list) {
		list_del(&buf->list);
		dtr_release_local_buffer(path, buf);
	}
}

/* Register this path's control ring (one page of DTR_FLOW_CTRL_DESCS slots) for
 * REMOTE_WRITE and announce it to the peer. region_stream == ST_FLOW_CTRL in the
 * announce marks it as the ring rather than a payload region. The REG_MR is
 * posted (by dtr_register_local_buffer) before the announce on the same QP, so
 * by RC send-queue ordering the ring MR is valid by the time the peer receives
 * the announce and starts writing into it. Runs post-RTS in the established
 * work; idempotent, retried on the next establish if allocation fails. Returns
 * 0 on success.
 */
static int dtr_register_ring(struct dtr_path *path)
{
	struct dtr_local_buffer *buf;
	int err;

	BUILD_BUG_ON(DTR_FLOW_CTRL_DESCS * DTR_RING_SLOT_SIZE > PAGE_SIZE);

	if (path->ring.local)
		return 0;

	/* Order 0: one page of slots. The ring is consumed by slot, not by cursor,
	 * so its stride is nominal.
	 */
	buf = dtr_register_local_buffer(path, 0, DTR_RING_SLOT_SIZE);
	if (!buf)
		return -ECONNRESET;

	err = dtr_send_announce_buffer_msg(path, ST_FLOW_CTRL, buf, GFP_NOIO);
	if (err) {
		dtr_release_local_buffer(path, buf);
		return err;
	}
	path->ring.local = buf;
	return 0;
}

static void dtr_ring_register_work_fn(struct work_struct *work)
{
	struct dtr_path *path = container_of(work, struct dtr_path, ring_register_work);
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	int err;

	if (!dtr_path_ok(path) || path->ring.local)
		return;

	err = dtr_register_ring(path);
	/* -ENOBUFS just means no send credit yet; a later flow-control re-kicks us.
	 * Anything else is a real failure worth a (rate-limited) note.
	 */
	if (err && err != -ENOBUFS && __ratelimit(&rdma_transport->rate_limit))
		tr_warn(&rdma_transport->transport, "dtr_register_ring() = %d\n", err);
}

static void dtr_free_ring(struct dtr_path *path)
{
	struct dtr_local_buffer *buf = path->ring.local;

	if (buf) {
		path->ring.local = NULL;
		dtr_release_local_buffer(path, buf);
	}
	path->ring.remote_known = false;
	path->ring.remote_addr = 0;
	path->ring.remote_rkey = 0;
	path->ring.tx_seq = 0;
	path->ring.rx_got_rdma_write = false;
}

/* A payload of @byte_len bytes was just RDMA-written into our receive region at
 * its consume cursor. Mirror the sender's reservation (dtr_reserve_and_post()):
 * the write went into the first region, in announce order, whose tail could
 * take its stride-rounded size; regions ahead of it were abandoned by the
 * sender and are retired here (the tail rule). Point @rx_desc->data_page /
 * data_offset at the payload so the consumer (dtr_recv_bio() for DATA payload,
 * _dtr_recv() for DATA headers, dtr_control_data_ready() for CONTROL) uses it
 * instead of the recv buffer, take a reference on every region page it touches
 * (neighbouring writes may share a page), and advance the cursor by the same
 * stride-rounded amount. A fully consumed region moves to the exhausted list for
 * deferred release + replacement. Runs in the rx completion softirq.
 */
static bool
dtr_consume_local_buffer(struct dtr_region_set *rs, struct dtr_rx_desc *rx_desc,
			 unsigned int byte_len)
{
	struct dtr_path *path = rs->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_local_buffer *buf;
	bool exhausted = false;
	unsigned long flags;
	u32 need, first, last;
	int i;

	spin_lock_irqsave(&rs->local_buffers_lock, flags);
	for (;;) {
		buf = list_first_entry_or_null(&rs->local_buffers, struct dtr_local_buffer, list);
		if (!buf) {
			spin_unlock_irqrestore(&rs->local_buffers_lock, flags);
			if (__ratelimit(&rdma_transport->rate_limit))
				tr_err(transport, "RDMA-WRITE arrived with no registered buffer\n");
			return false;
		}
		need = dtr_chunk_size(byte_len, buf->stride);
		if (need <= buf->len - buf->consumed)
			break;
		/* Tail rule: this write did not fit here, the sender moved on. */
		list_move_tail(&buf->list, &rs->exhausted_buffers);
		exhausted = true;
	}

	/* Make the just-written bytes visible to the CPU (no-op on direct-map
	 * systems; needed where the mapping bounces).
	 */
	ib_dma_sync_single_for_cpu(buf->cm->id->device, buf->addr + buf->consumed,
				   byte_len, DMA_FROM_DEVICE);

	first = buf->consumed >> PAGE_SHIFT;
	last = (buf->consumed + max(byte_len, 1U) - 1) >> PAGE_SHIFT;
	rx_desc->data_page = buf->head_page + first;
	rx_desc->data_offset = buf->consumed & ~PAGE_MASK;
	rx_desc->data_nr_pages = last - first + 1;
	for (i = 0; i < rx_desc->data_nr_pages; i++)
		drbd_get_page(transport, rx_desc->data_page + i);
	atomic_add(rx_desc->data_nr_pages, &rdma_transport->region_refs_taken);

	buf->consumed += need;
	if (buf->consumed >= buf->len) {
		list_move_tail(&buf->list, &rs->exhausted_buffers);
		exhausted = true;
	}
	spin_unlock_irqrestore(&rs->local_buffers_lock, flags);

	if (exhausted)
		schedule_work(&rs->register_buffers_work);

	return true;
}

/* Fill a stream's receive window with as few, as-large-as-possible registered
 * regions, announcing each (one region per announce message) as it is
 * registered. Runs once the path is established, and again whenever a region is
 * fully consumed (to release it and top the window back up).
 */
static void dtr_register_buffers_work_fn(struct work_struct *work)
{
	struct dtr_region_set *rs =
		container_of(work, struct dtr_region_set, register_buffers_work);
	struct dtr_path *path = rs->path;
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	enum dtr_stream_nr stream_nr = (enum dtr_stream_nr)rs->stream;
	struct dtr_local_buffer *buf, *tmp;
	u32 registered, target, stride;
	unsigned long flags;
	LIST_HEAD(exhausted);

	/* Take the regions the peer finished writing (deferred here out of the
	 * rx softirq because the verbs below may sleep).
	 */
	spin_lock_irqsave(&rs->local_buffers_lock, flags);
	list_splice_init(&rs->exhausted_buffers, &exhausted);
	spin_unlock_irqrestore(&rs->local_buffers_lock, flags);

	if (!dtr_path_ok(path)) {
		/* Connection going away: free the exhausted regions outright. */
		list_for_each_entry_safe(buf, tmp, &exhausted, list) {
			list_del(&buf->list);
			dtr_release_local_buffer(path, buf);
		}
		return;
	}

	stride = dtr_region_stride(rs);
	target = dtr_local_buffer_target_bytes(rs, stride);

	/* Bytes still armed and in the window right now. */
	spin_lock_irqsave(&rs->local_buffers_lock, flags);
	registered = 0;
	list_for_each_entry(buf, &rs->local_buffers, list)
		registered += buf->len;
	spin_unlock_irqrestore(&rs->local_buffers_lock, flags);

	/* Steady-state recycle: re-arm each fully-consumed region by reusing its
	 * MR (no ib_alloc_mr()/ib_dereg_mr() churn -- the expensive verbs that
	 * could not keep up), announce it, and return it to the window. Re-arm
	 * only up to @target; release any excess MR outright so the pool shrinks
	 * back rather than overshooting. A region must end up either
	 * announced+listed or released, never dropped, or its pages and cm
	 * reference leak.
	 *
	 * Add the armed region to local_buffers BEFORE announcing it: the announce
	 * is what lets the peer RDMA-WRITE into it, so once it is on the wire the
	 * peer may write at any instant. If the announce preceded the list_add, a
	 * write could arrive (and be consumed in the rx softirq) while
	 * local_buffers is still empty -- the "RDMA-WRITE arrived with no
	 * registered buffer" overrun. The region is consumed head-first and this
	 * one is at the tail behind any still-draining region, so listing it early
	 * cannot reorder consumption; the peer simply cannot reach it until the
	 * announce lands.
	 */
	list_for_each_entry_safe(buf, tmp, &exhausted, list) {
		list_del(&buf->list);

		if (registered < target && dtr_invalidate_local_buffer(path, buf) == 0) {
			int order = dtr_region_order(rdma_transport, target - registered);

			dtr_disarm_local_buffer(path, buf);
			if (!dtr_arm_local_buffer(path, buf, order, stride)) {
				spin_lock_irqsave(&rs->local_buffers_lock, flags);
				list_add_tail(&buf->list, &rs->local_buffers);
				spin_unlock_irqrestore(&rs->local_buffers_lock, flags);
				if (!dtr_send_announce_buffer_msg(path, stream_nr, buf, GFP_NOIO)) {
					registered += buf->len;
					continue;
				}
				spin_lock_irqsave(&rs->local_buffers_lock, flags);
				list_del(&buf->list);
				spin_unlock_irqrestore(&rs->local_buffers_lock, flags);
			}
		}
		dtr_release_local_buffer(path, buf);
	}

	/* Grow the pool with brand-new regions until the window is filled (the
	 * initial fill, or to make up for any region released above). As in the
	 * recycle path, list the region before announcing it so the peer can never
	 * write into a region this side has not yet armed in local_buffers.
	 */
	while (registered < target) {
		int order = dtr_region_order(rdma_transport, target - registered);

		buf = dtr_register_local_buffer(path, order, stride);
		if (!buf)
			break; /* -ENOMEM or disconnected: stop, retry later */

		spin_lock_irqsave(&rs->local_buffers_lock, flags);
		list_add_tail(&buf->list, &rs->local_buffers);
		spin_unlock_irqrestore(&rs->local_buffers_lock, flags);

		if (dtr_send_announce_buffer_msg(path, stream_nr, buf, GFP_NOIO)) {
			spin_lock_irqsave(&rs->local_buffers_lock, flags);
			list_del(&buf->list);
			spin_unlock_irqrestore(&rs->local_buffers_lock, flags);
			dtr_release_local_buffer(path, buf);
			break;
		}

		registered += buf->len;
	}
}

/* Derive the per-stream receive-region and tx-credit windows (in bytes) from
 * net_conf. DATA uses rcvbuf-size/sndbuf-size; CONTROL uses
 * rdma-ctrl-rcvbuf-size/rdma-ctrl-sndbuf-size, defaulting to a small fraction
 * of the DATA windows. An unset sndbuf tracks the matching rcvbuf, so the
 * sender may keep a full receive window in flight.
 */
static void dtr_window_bytes(struct net_conf *nc, enum drbd_stream stream,
			     unsigned int *rx_bytes, unsigned int *tx_bytes)
{
	unsigned int rcvbuf = nc->rcvbuf_size ?: RDMA_DEF_BUFFER_SIZE;
	unsigned int sndbuf = nc->sndbuf_size ?: rcvbuf;

	if (stream == CONTROL_STREAM) {
		/* Under protocol C the CONTROL stream carries one write-ack per
		 * write, so its volume tracks the DATA stream's, not the low rate
		 * a control channel is usually sized for. A CONTROL window smaller
		 * than the DATA window cannot hold the acks for the writes in
		 * flight on a path: when that path fails over, the stranded
		 * lower-sequence acks leave an in-order-delivery gap whose
		 * higher-sequence descs fill the whole CONTROL receive window
		 * (every reorder-held desc still counts against rx_descs_max), so
		 * recv WRs can no longer be reposted, the credit granted to the
		 * peer collapses to one, and the peer can never send the
		 * gap-fillers that would let delivery resume -- a deadlock that
		 * persists until the core's PingAck timeout tears the connection
		 * down. Size CONTROL like DATA by default (the old rcvbuf/64
		 * undersized it by 64x); an explicit rdma-ctrl-rcvbuf-size /
		 * rdma-ctrl-sndbuf-size still overrides.
		 */
		rcvbuf = nc->rdma_ctrl_rcvbuf_size ?:
			max_t(unsigned int, rcvbuf, 8 * PAGE_SIZE);
		sndbuf = nc->rdma_ctrl_sndbuf_size ?: rcvbuf;
	}

	*rx_bytes = rcvbuf;
	*tx_bytes = sndbuf;
}

static int dtr_init_flow(struct dtr_path *path, enum drbd_stream stream)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_flow *flow = &path->flow[stream];
	unsigned int rx_bytes, tx_bytes;
	struct net_conf *nc;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	if (!nc) {
		rcu_read_unlock();
		tr_err(transport, "need net_conf\n");
		return -EINVAL;
	}

	dtr_window_bytes(nc, stream, &rx_bytes, &tx_bytes);

	if (rx_bytes / DRBD_SOCKET_BUFFER_SIZE > nc->max_buffers) {
		tr_err(transport, "Set max-buffers at least to %d, (right now it is %d).\n",
		       rx_bytes / DRBD_SOCKET_BUFFER_SIZE, nc->max_buffers);
		tr_err(transport, "This is due to rcvbuf-size = %d.\n", rx_bytes);
		rcu_read_unlock();
		return -EINVAL;
	}

	rcu_read_unlock();

	flow->path = path;
	flow->rx_window_bytes = rx_bytes;
	flow->tx_window_bytes = tx_bytes;
	flow->tx_descs_max = tx_bytes / DRBD_SOCKET_BUFFER_SIZE;
	flow->rx_descs_max = rx_bytes / DRBD_SOCKET_BUFFER_SIZE;

	atomic_set(&flow->tx_descs_posted, 0);
	atomic_set(&flow->peer_rx_descs, stream == CONTROL_STREAM ? 1 : 0);
	atomic_set(&flow->rx_descs_known_to_peer, stream == CONTROL_STREAM ? 1 : 0);

	atomic_set(&flow->rx_descs_posted, 0);
	atomic_set(&flow->rx_descs_allocated, 0);

	flow->rx_descs_want_posted = flow->rx_descs_max / 2;

	return 0;
}

/* The FLOW_CTRL flow is the credit pool for control-ring records (flow-control +
 * announce), not a payload stream, so its window is the fixed ring size rather
 * than anything from net_conf. One credit == one ring slot == one recv WR the
 * peer's writer consumes per record, so a sender can have at most
 * DTR_FLOW_CTRL_DESCS records outstanding and can never lap an unread slot. Keep
 * all DTR_FLOW_CTRL_DESCS recv WRs posted (want == max). peer_rx_descs /
 * rx_descs_known_to_peer start at 1, as for CONTROL, so the bootstrap
 * flow-control message can be sent before the peer's first window grant arrives.
 */
static void dtr_init_flow_control_flow(struct dtr_path *path)
{
	struct dtr_flow *flow = &path->flow[ST_FLOW_CTRL];

	flow->path = path;
	flow->rx_window_bytes = DTR_FLOW_CTRL_DESCS * DTR_RING_SLOT_SIZE;
	flow->tx_window_bytes = DTR_FLOW_CTRL_DESCS * DTR_RING_SLOT_SIZE;
	flow->tx_descs_max = DTR_FLOW_CTRL_DESCS;
	flow->rx_descs_max = DTR_FLOW_CTRL_DESCS;

	atomic_set(&flow->tx_descs_posted, 0);
	atomic_set(&flow->peer_rx_descs, 1);
	atomic_set(&flow->rx_descs_known_to_peer, 1);

	atomic_set(&flow->rx_descs_posted, 0);
	atomic_set(&flow->rx_descs_allocated, 0);

	flow->rx_descs_want_posted = flow->rx_descs_max;
}

static int _dtr_cm_alloc_rdma_res(struct dtr_cm *cm,
				    enum dtr_alloc_rdma_res_causes *cause)
{
	int err, i, rx_descs_max = 0, tx_descs_max = 0;
	struct dtr_path *path = cm->path;

	/*
	 * Each path might be the sole path, therefore it must be able
	 * to support both streams. ST_FLOW_CTRL adds its control-ring credit
	 * pool (recv WRs for inbound records, send WRs for outbound ones).
	 */
	for (i = DATA_STREAM; i <= ST_FLOW_CTRL ; i++) {
		rx_descs_max += path->flow[i].rx_descs_max;
		tx_descs_max += path->flow[i].tx_descs_max;
	}

	/* Headroom on the send queue for the IB_WR_REG_MR / IB_WR_LOCAL_INV work
	 * requests that (re-)register RDMA-WRITE receive regions.
	 */
	tx_descs_max += DTR_REG_WR_HEADROOM;

	/* Anchor for the unsignaled REG_MR completions (flush on QP error). */
	cm->reg_cqe.done = dtr_reg_mr_cqe_done;

	/* alloc protection domain (PD) */
	cm->pd = ib_alloc_pd(cm->id->device, 0);
	if (IS_ERR(cm->pd)) {
		*cause = IB_ALLOC_PD;
		err = PTR_ERR(cm->pd);
		goto pd_failed;
	}

	/* allocate recv completion queue (CQ) */
	cm->recv_cq = ib_alloc_cq_any(cm->id->device, cm, rx_descs_max, IB_POLL_SOFTIRQ);
	if (IS_ERR(cm->recv_cq)) {
		*cause = IB_ALLOC_CQ_RX;
		err = PTR_ERR(cm->recv_cq);
		goto recv_cq_failed;
	}

	/* allocate send completion queue (CQ) */
	cm->send_cq = ib_alloc_cq_any(cm->id->device, cm, tx_descs_max, IB_POLL_SOFTIRQ);
	if (IS_ERR(cm->send_cq)) {
		*cause = IB_ALLOC_CQ_TX;
		err = PTR_ERR(cm->send_cq);
		goto send_cq_failed;
	}

	/* create a queue pair (QP) */
	err = dtr_create_qp(cm, rx_descs_max, tx_descs_max);
	if (err) {
		*cause = RDMA_CREATE_QP;
		goto createqp_failed;
	}

	/* Some RDMA transports need at least one rx desc for establishing a
	 * connection. These are posted page-backed: they precede every
	 * steady-state desc in the RC recv FIFO and absorb the peer's bootstrap
	 * SENDs (flow-control / ring announce). Page-backing depends on
	 * rx_got_rdma_write being false -- true on a first connect, but on a
	 * reconnect the path object survives with it still true from the prior
	 * incarnation: failover (dtr_remove_cm_from_path) does not reset it, and
	 * dtr_free_ring() runs only later in dtr_path_established_work_fn(). Posting
	 * the bootstrap descs with the stale-true flag makes them buffer-less
	 * (num_sge=0), so the peer's re-sent bootstrap SEND has no buffer to land
	 * in and faults the recv with a local length error. Reset it here, before
	 * the descs are posted, so a re-establishing QP bootstraps exactly like a
	 * first connect.
	 */
	WRITE_ONCE(path->ring.rx_got_rdma_write, false);

	for (i = DATA_STREAM; i <= ST_FLOW_CTRL ; i++)
		dtr_create_rx_desc(&path->flow[i], GFP_NOIO, false);

	/* Now that the QP exists, watch the device for port-down events so a link
	 * failure on this path is detected immediately. Unregistered in
	 * __dtr_destroy_cm() (both run in process context).
	 */
	INIT_IB_EVENT_HANDLER(&cm->ib_event_handler, cm->id->device, dtr_ib_event_handler);
	ib_register_event_handler(&cm->ib_event_handler);
	set_bit(DCF_IB_EVENT_REG, &cm->flags);

	return 0;

createqp_failed:
	ib_free_cq(cm->send_cq);
	cm->send_cq = NULL;
send_cq_failed:
	ib_free_cq(cm->recv_cq);
	cm->recv_cq = NULL;
recv_cq_failed:
	ib_dealloc_pd(cm->pd);
	cm->pd = NULL;
pd_failed:
	return err;
}


static int dtr_cm_alloc_rdma_res(struct dtr_cm *cm)
{
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	enum dtr_alloc_rdma_res_causes cause;
	struct ib_device_attr dev_attr;
	struct ib_udata uhw = {.outlen = 0, .inlen = 0};
	struct ib_device *device = cm->id->device;
	int rx_descs_max = 0, tx_descs_max = 0;
	bool reduced = false;
	int i, hca_max, err, dev_sge;

	static const char * const err_txt[] = {
		[IB_ALLOC_PD] = "ib_alloc_pd()",
		[IB_ALLOC_CQ_RX] = "ib_alloc_cq_any() rx",
		[IB_ALLOC_CQ_TX] = "ib_alloc_cq_any() tx",
		[RDMA_CREATE_QP] = "rdma_create_qp()",
		[IB_GET_DMA_MR] = "ib_get_dma_mr()",
	};

	err = device->ops.query_device(device, &dev_attr, &uhw);
	if (err) {
		tr_err(transport, "ib_query_device: %d\n", err);
		return err;
	}

	dev_sge = min(dev_attr.max_send_sge, dev_attr.max_recv_sge);
	if (rdma_transport->sges_max > dev_sge)
		rdma_transport->sges_max = dev_sge;

	/* Upper bound on pages a single fast-reg MR (a receive region) can map.
	 * Fall back to a sane value if the device does not report one.
	 */
	rdma_transport->max_mr_pages = dev_attr.max_fast_reg_page_list_len ?: 256;

	hca_max = min(dev_attr.max_qp_wr, dev_attr.max_cqe);

	for (i = DATA_STREAM; i <= ST_FLOW_CTRL ; i++) {
		rx_descs_max += path->flow[i].rx_descs_max;
		tx_descs_max += path->flow[i].tx_descs_max;
	}

	if (tx_descs_max > hca_max || rx_descs_max > hca_max) {
		int rx_correction = 0, tx_correction = 0;

		reduced = true;

		if (tx_descs_max > hca_max)
			tx_correction = hca_max - tx_descs_max;

		if (rx_descs_max > hca_max)
			rx_correction = hca_max - rx_descs_max;

		path->flow[DATA_STREAM].rx_descs_max -= rx_correction;
		path->flow[DATA_STREAM].tx_descs_max -= tx_correction;

		rx_descs_max -= rx_correction;
		tx_descs_max -= tx_correction;
	}

	for (;;) {
		err = _dtr_cm_alloc_rdma_res(cm, &cause);

		if (err == 0 || cause != RDMA_CREATE_QP || err != -ENOMEM)
			break;

		reduced = true;
		if (path->flow[DATA_STREAM].rx_descs_max <= 64)
			break;
		path->flow[DATA_STREAM].rx_descs_max -= 64;
		if (path->flow[DATA_STREAM].tx_descs_max <= 64)
			break;
		path->flow[DATA_STREAM].tx_descs_max -= 64;
		if (path->flow[CONTROL_STREAM].rx_descs_max > 8)
			path->flow[CONTROL_STREAM].rx_descs_max -= 1;
		if (path->flow[CONTROL_STREAM].tx_descs_max > 8)
			path->flow[CONTROL_STREAM].tx_descs_max -= 1;
	}

	if (err) {
		tr_err(transport, "%s failed with err = %d\n", err_txt[cause], err);
	} else if (reduced) {
		/*
		 * ib_create_qp() may return -ENOMEM if max_send_wr or
		 * max_recv_wr are too big. Unfortunately there is no way
		 * to find the working maxima. Trial and error is suggested
		 * to find the maximal number.
		 */

		tr_warn(transport, "Needed to adjust buffer sizes for HCA\n");
		tr_warn(transport, "rcvbuf = %d sndbuf = %d\n",
			path->flow[DATA_STREAM].rx_descs_max * DRBD_SOCKET_BUFFER_SIZE,
			path->flow[DATA_STREAM].tx_descs_max * DRBD_SOCKET_BUFFER_SIZE);
		tr_warn(transport, "It is recommended to apply this change to the configuration\n");
	}

	return err;
}

static void dtr_end_rx_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, end_rx_work);
	struct dtr_rx_desc *rx_desc, *tmp;
	unsigned long irq_flags;
	LIST_HEAD(rx_descs);

	spin_lock_irqsave(&cm->error_rx_descs_lock, irq_flags);
	list_splice_init(&cm->error_rx_descs, &rx_descs);
	spin_unlock_irqrestore(&cm->error_rx_descs_lock, irq_flags);
	list_for_each_entry_safe(rx_desc, tmp, &rx_descs, list)
		dtr_free_rx_desc(rx_desc);
	kref_put(&cm->kref, dtr_destroy_cm);
}

static void dtr_end_tx_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, end_tx_work);

	kref_put(&cm->kref, dtr_destroy_cm);
}

static void __dtr_modify_qp_to_err(struct dtr_cm *cm)
{
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport = path->path.transport;
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	int err;

	/* between dtr_alloc_cm() and dtr_cm_alloc_rdma_res() cm->id->qp is NULL */
	if (!cm->id || !cm->id->qp)
		return;

	/* With putting the QP into error state, it has to hand back all posted rx_descs */
	err = ib_modify_qp(cm->id->qp, &attr, IB_QP_STATE);
	if (err)
		tr_err(transport, "ib_modify_qp failed %d\n", err);
}

static void __dtr_disconnect_path(struct dtr_path *path)
{
	struct drbd_transport *transport;
	enum connect_state_enum a, p;
	bool was_scheduled;
	struct dtr_cm *cm;
	long t;
	int err;

	if (!path)
		return;

	transport = path->path.transport;

	a = atomic_cmpxchg(&path->cs.active_state, PCS_CONNECTING, PCS_REQUEST_ABORT);
	p = atomic_cmpxchg(&path->cs.passive_state, PCS_CONNECTING, PCS_INACTIVE);

	switch (p) {
	case PCS_CONNECTING:
		drbd_put_listener(&path->path);
		break;
	case PCS_FINISHING:
		t = wait_event_timeout(path->cs.wq,
				       atomic_read(&path->cs.passive_state) == PCS_INACTIVE,
				       HZ * 60);
		if (t == 0)
			tr_warn(transport, "passive_state still %d\n",
				atomic_read(&path->cs.passive_state));
		fallthrough;
	case PCS_INACTIVE:
		break;
	}

	switch (a) {
	case PCS_CONNECTING:
		was_scheduled = flush_delayed_work(&path->cs.retry_connect_work);
		if (!was_scheduled) {
			atomic_set(&path->cs.active_state, PCS_INACTIVE);
			break;
		}
		fallthrough;
	case PCS_REQUEST_ABORT:
		t = wait_event_timeout(path->cs.wq,
				       atomic_read(&path->cs.active_state) == PCS_INACTIVE,
				       HZ * 60);
		if (t == 0)
			tr_warn(transport, "active_state still %d\n",
				atomic_read(&path->cs.active_state));
		fallthrough;
	case PCS_INACTIVE:
		break;
	}

	cm = dtr_path_get_cm(path);
	if (!cm)
		return;

	err = rdma_disconnect(cm->id);
	if (err) {
		tr_warn(transport, "failed to disconnect, id %p context %p err %d\n",
			cm->id, cm->id->context, err);
		/* We are ignoring errors here on purpose */
		goto out;
	}

	/* There might be a signal pending here. Not incorruptible! */
	wait_event_timeout(cm->state_wq,
			   !test_bit(DSB_CONNECTED, &cm->state),
			   HZ);

	if (test_bit(DSB_CONNECTED, &cm->state))
		tr_warn(transport, "WARN: not properly disconnected, state = %lu\n",
			cm->state);

 out:
	dtr_cancel_connect_timeout(cm);
	__dtr_modify_qp_to_err(cm);
	/*
	 * We are expecting one of RDMA_CM_EVENT_ESTABLISHED, _UNREACHABLE,
	 * _CONNECT_ERROR, or _REJECTED on this cm. Some RDMA drivers report
	 * these error events after unexpectedly long timeouts, while others do
	 * not report it at all. We are no longer interested in these
	 * events. Destroy the cm and cm_id to avoid leaking it.
	 * This is racing with the event delivery, which drops a reference.
	 */
	if (test_and_clear_bit(DSB_CONNECTING, &cm->state) ||
	    test_and_clear_bit(DSB_CONNECT_REQ, &cm->state))
		kref_put(&cm->kref, dtr_destroy_cm);

	/* Drop the "connected" reference taken at establish (the kref_get in
	 * dtr_path_established_work_fn that "expects a disconnect in the future").
	 * Normally the RDMA_CM_EVENT_DISCONNECTED handler clears DSB_CONNECTED and
	 * drops it, but that event is not guaranteed to be delivered for a
	 * locally-initiated rdma_disconnect (the wait above can time out with
	 * DSB_CONNECTED still set). Drop it here in that case; the test_and_clear
	 * keeps it from being dropped twice should the event still arrive (the
	 * handler then sees DSB_CONNECTED already clear and keeps its ref). Mirrors
	 * dtr_path_failover(); without it every del-path leaks one cm and the
	 * transport module refcount never returns to 0.
	 */
	if (test_and_clear_bit(DSB_CONNECTED, &cm->state))
		kref_put(&cm->kref, dtr_destroy_cm);

	kref_put(&cm->kref, dtr_destroy_cm);
}

static void dtr_reclaim_cm(struct rcu_head *rcu_head)
{
	struct dtr_cm *cm = container_of(rcu_head, struct dtr_cm, rcu);

	kfree(cm);
	module_put(THIS_MODULE);
}

/* dtr_destroy_cm() might run after the transport was destroyed */
static void __dtr_destroy_cm(struct kref *kref, bool destroy_id)
{
	struct dtr_cm *cm = container_of(kref, struct dtr_cm, kref);

	/* Pairs with the ib_register_event_handler() in _dtr_cm_alloc_rdma_res().
	 * ib_unregister_event_handler() may sleep (rwsem); __dtr_destroy_cm()
	 * already sleeps here (ib_dealloc_pd/rdma_destroy_id), so this is safe.
	 */
	if (test_and_clear_bit(DCF_IB_EVENT_REG, &cm->flags))
		ib_unregister_event_handler(&cm->ib_event_handler);

	if (cm->id) {
		if (cm->id->qp)
			rdma_destroy_qp(cm->id);
		cm->id->qp = NULL;
	}

	if (cm->send_cq) {
		ib_free_cq(cm->send_cq);
		cm->send_cq = NULL;
	}

	if (cm->recv_cq) {
		ib_free_cq(cm->recv_cq);
		cm->recv_cq = NULL;
	}

	if (cm->pd) {
		ib_dealloc_pd(cm->pd);
		cm->pd = NULL;
	}

	if (cm->id) {
		/*
		 * Just in case some callback is still triggered
		 * after we kfree'd path.
		 */
		cm->id->context = NULL;
		if (destroy_id)
			rdma_destroy_id(cm->id);
		cm->id = NULL;
	}
	if (cm->path) {
		kref_put(&cm->path->path.kref, drbd_destroy_path);
		cm->path = NULL;
	}

	call_rcu(&cm->rcu, dtr_reclaim_cm);
}

static void dtr_destroy_cm(struct kref *kref)
{
	__dtr_destroy_cm(kref, true);
}

static void dtr_destroy_cm_keep_id(struct kref *kref)
{
	__dtr_destroy_cm(kref, false);
}

/* Free the per-path buffers tied to a QP that is gone: the peer's announced
 * remote chunks (their rkeys died with the peer's MRs), our registered receive
 * regions (our MRs died with our QP), and the control ring. Cancels the workers
 * that would otherwise re-arm them. Called both on an explicit path disconnect
 * and -- crucially -- when a path re-establishes after a failover, which only
 * forces the old QP to error and does NOT free these (so without this the
 * re-established path keeps the dead incarnation's stale buffers: a remote chunk
 * with a dead rkey yields a local access error at the peer when written, and a
 * still-set ring.local makes dtr_register_ring() skip re-registration).
 */
static void dtr_drop_stale_path_buffers(struct dtr_path *path)
{
	cancel_work_sync(&path->shutdown_work);
	cancel_work_sync(&path->ring_register_work);
	cancel_work_sync(&path->regions[DATA_STREAM].register_buffers_work);
	cancel_work_sync(&path->regions[CONTROL_STREAM].register_buffers_work);

	dtr_free_remote_buffers(path);
	dtr_free_local_buffers(path);
	dtr_free_ring(path);
}

static void dtr_disconnect_path(struct dtr_path *path)
{
	struct dtr_cm *cm;

	if (!path)
		return;

	__dtr_disconnect_path(path);
	cancel_work_sync(&path->refill_rx_descs_work);
	dtr_drop_stale_path_buffers(path);

	cm = xchg(&path->cm, NULL); // RCU xchg
	if (cm) {
		__dtr_modify_qp_to_err(cm);
		kref_put(&cm->kref, dtr_destroy_cm);
	}
}

static void dtr_destroy_listener(struct drbd_listener *generic_listener)
{
	struct dtr_listener *listener =
		container_of(generic_listener, struct dtr_listener, listener);

	if (listener->cm.id)
		rdma_destroy_id(listener->cm.id);
}

static int dtr_init_listener(struct drbd_transport *transport, const struct sockaddr *addr,
			     struct net *net, struct drbd_listener *drbd_listener)
{
	struct dtr_listener *listener = container_of(drbd_listener, struct dtr_listener, listener);
	struct sockaddr_storage my_addr;
	int err = -ENOMEM;

	my_addr = *(struct sockaddr_storage *)addr;

	err = dtr_create_cm_id(&listener->cm, net);
	if (err) {
		tr_err(transport, "rdma_create_id() failed\n");
		goto out;
	}
	listener->cm.state = 0; /* listening */

	err = rdma_bind_addr(listener->cm.id, (struct sockaddr *)&my_addr);
	if (err) {
		tr_err(transport, "rdma_bind_addr error %d\n", err);
		goto out;
	}

	err = rdma_listen(listener->cm.id, 1);
	if (err) {
		tr_err(transport, "rdma_listen error %d\n", err);
		goto out;
	}

	listener->listener.listen_addr = *(struct sockaddr_storage *)addr;

	return 0;
out:
	if (listener->cm.id) {
		rdma_destroy_id(listener->cm.id);
		listener->cm.id = NULL;
	}

	return err;
}

static int dtr_activate_path(struct dtr_path *path)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_connect_state *cs;
	int err = -ENOMEM;

	cs = &path->cs;

	/* A path this side is gracefully removing (dtr_remove_path set
	 * DTR_ACTIVE_SHUT_DOWN) must not be reconnected: dtr_remove_path owns its
	 * teardown, and racing a fresh connect against that teardown reconnects a
	 * path that is going away -- the rx-desc post then runs against a
	 * half-set-up cm (NULL pd) and oopses. A peer-initiated removal leaves only
	 * DTR_PASSIVE_SHUT_DOWN set (this side keeps the path), so it still
	 * reconnects; the flag clear below resets that for the fresh connection.
	 */
	if (test_bit(DTR_ACTIVE_SHUT_DOWN, &path->flags))
		return 0;

	init_waitqueue_head(&cs->wq);

	/* A path re-establishing after a passive graceful shutdown (the peer ran
	 * del-path) carries a stale DTR_PASSIVE_SHUT_DOWN bit; clear it so the fresh
	 * connection is selectable for tx again.
	 */
	path->flags = 0;

	atomic_set(&cs->passive_state, PCS_CONNECTING);
	atomic_set(&cs->active_state, PCS_CONNECTING);

	if (path->path.listener) {
		tr_warn(transport, "ASSERTION FAILED: in %s() found listener, dropping it\n",
				__func__);
		drbd_put_listener(&path->path);
	}
	err = drbd_get_listener(&path->path);
	if (err)
		goto out_no_put;

	/*
	 * Check passive_state after drbd_get_listener() completed.
	 * __dtr_disconnect_path() sets passive_state before calling
	 * drbd_put_listener(). That drbd_put_listner() might return
	 * before the drbd_get_listner() here started.
	 */
	if (atomic_read(&cs->passive_state) != PCS_CONNECTING ||
	    atomic_read(&cs->active_state) != PCS_CONNECTING)
		goto out;

	err = dtr_start_try_connect(cs);
	if (err)
		goto out;

	return 0;

out:
	drbd_put_listener(&path->path);
out_no_put:
	atomic_set(&cs->passive_state, PCS_INACTIVE);
	atomic_set(&cs->active_state, PCS_INACTIVE);
	wake_up(&cs->wq);

	return err;
}

static int dtr_prepare_connect(struct drbd_transport *transport)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	struct dtr_stream *data_stream = NULL, *control_stream = NULL;
	struct dtr_path *path;
	struct net_conf *nc;
	int timeout, err = -ENOMEM;

	flush_signals(current);

	if (!list_first_or_null_rcu(&transport->paths, struct drbd_path, list))
		return -EDESTADDRREQ;

	data_stream = &rdma_transport->stream[DATA_STREAM];
	dtr_re_init_stream(data_stream);

	control_stream = &rdma_transport->stream[CONTROL_STREAM];
	dtr_re_init_stream(control_stream);

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);

	timeout = nc->timeout * HZ / 10;
	rcu_read_unlock();

	data_stream->send_timeout = timeout;
	control_stream->send_timeout = timeout;

	atomic_set(&rdma_transport->first_path_connect_err, 1);
	init_completion(&rdma_transport->connected);

	rdma_transport->active = true;

	list_for_each_entry(path, &transport->paths, path.list) {
		err = dtr_activate_path(path);
		if (err)
			goto abort;
	}

	return 0;

abort:
	rdma_transport->active = false;
	return err;
}

static int dtr_connect(struct drbd_transport *transport)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	int i, err = -ENOMEM;

	err = wait_for_completion_interruptible(&rdma_transport->connected);
	if (err) {
		flush_signals(current);
		goto abort;
	}

	err = atomic_read(&rdma_transport->first_path_connect_err);
	if (err == 1)
		err = -EAGAIN;
	if (err)
		goto abort;


	/* Make sure at least one path has rx_descs... */
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++)
		dtr_refill_rx_desc(rdma_transport, i);

	/* make sure the other side had time to create rx_descs */
	schedule_timeout(HZ / 4);

	return 0;

abort:
	rdma_transport->active = false;

	return err;
}

static void dtr_finish_connect(struct drbd_transport *transport)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	if (!rdma_transport->active) {
		struct dtr_path *path;

		list_for_each_entry(path, &transport->paths, path.list)
			dtr_disconnect_path(path);
	}
}

static int dtr_net_conf_change(struct drbd_transport *transport, struct net_conf *new_net_conf)
{
	struct net_conf *old_net_conf;
	struct dtr_transport *dtr_transport = container_of(transport,
		struct dtr_transport, transport);
	int ret = 0;

	rcu_read_lock();
	old_net_conf = rcu_dereference(transport->net_conf);
	if (old_net_conf && dtr_transport->active) {
		if (old_net_conf->sndbuf_size != new_net_conf->sndbuf_size) {
			tr_warn(transport, "online change of sndbuf_size not supported\n");
			ret = -EINVAL;
		}
		if (old_net_conf->rcvbuf_size != new_net_conf->rcvbuf_size) {
			tr_warn(transport, "online change of rcvbuf_size not supported\n");
			ret = -EINVAL;
		}
	}
	rcu_read_unlock();

	return ret;
}

static void dtr_set_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream,
			     long timeout)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	rdma_transport->stream[stream].recv_timeout = timeout;

	if (stream == CONTROL_STREAM)
		mod_timer(&rdma_transport->control_timer, jiffies + timeout);
}

static long dtr_get_rcvtimeo(struct drbd_transport *transport, enum drbd_stream stream)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	return rdma_transport->stream[stream].recv_timeout;
}

static bool dtr_path_ok(struct dtr_path *path)
{
	bool r = false;
	struct dtr_cm *cm = path->cm;

	rcu_read_lock();
	cm = rcu_dereference(path->cm);
	if (cm)
		r = cm->id && cm->state == DSM_CONNECTED;
	rcu_read_unlock();

	return r;
}

static bool dtr_transport_ok(struct drbd_transport *transport)
{
	struct dtr_path *path;
	bool r = false;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &transport->paths, path.list) {
		r = dtr_path_ok(path);
		if (r)
			break;
	}
	rcu_read_unlock();

	return r;
}

static bool dtr_stream_ok(struct drbd_transport *transport, enum drbd_stream stream)
{
	return dtr_transport_ok(transport);
}

static void dtr_update_congested(struct drbd_transport *transport)
{
	struct dtr_path *path;
	bool congested = true;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &transport->paths, path.list) {
		struct dtr_flow *flow = &path->flow[DATA_STREAM];
		bool path_congested = false;
		int tx_descs_posted;

		if (!dtr_path_ok(path))
			continue;

		tx_descs_posted = atomic_read(&flow->tx_descs_posted);
		path_congested |= flow->tx_descs_max - tx_descs_posted < DESCS_LOW_LEVEL;
		path_congested |= atomic_read(&flow->peer_rx_descs) < DESCS_LOW_LEVEL;

		if (!path_congested) {
			congested = false;
			break;
		}
	}
	rcu_read_unlock();

	if (congested)
		set_bit(NET_CONGESTED, &transport->flags);
}

static int dtr_send_page(struct drbd_transport *transport, enum drbd_stream stream,
			 struct page *caller_page, int offset, size_t size, unsigned int msg_flags)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_tx_desc *tx_desc;
	struct page *page;
	int err;


	if (!dtr_transport_ok(transport))
		return -ECONNRESET;

	tx_desc = kmalloc_flex(*tx_desc, sge, 1, GFP_NOIO);
	if (!tx_desc)
		return -ENOMEM;

	if (msg_flags & MSG_SPLICE_PAGES) {
		page = caller_page;
		get_page(page); /* The put_page() is in dtr_free_tx_desc() */
	} else {
		void *from;

		/*
		 * Allocate a page outside of DRBD's managed page pool, as
		 * the TCP transport does implicitly by handing the caller's
		 * page to the socket layer. Backpressure against unbounded
		 * allocations comes from dtr_post_tx_desc(), which respects
		 * tx_descs_max (derived from sndbuf_size).
		 */
		page = alloc_page(GFP_NOIO);
		if (!page) {
			kfree(tx_desc);
			return -ENOMEM;
		}
		from = kmap_local_page(caller_page);
		memcpy(page_address(page), from + offset, size);
		kunmap_local(from);
		offset = 0;
	}

	tx_desc->type = SEND_PAGE;
	tx_desc->page = page;
	tx_desc->nr_sges = 1;
	/* Defensive init of the kmalloc'd descriptor; dtr_post_tx_desc() sets the
	 * RDMA-WRITE target for both DATA and CONTROL before posting. @wr_pages must
	 * be NULL on any non-SEND_BIO descriptor (dtr_free_tx_desc() keys on the
	 * type, but keep the documented invariant explicit).
	 */
	tx_desc->rdma_write = false;
	tx_desc->wr_pages = NULL;
	tx_desc->imm = dtr_imm_encode(stream,
				      rdma_transport->stream[stream].tx_sequence++);
	tx_desc->sge[0].length = size;
	tx_desc->sge[0].lkey = offset; /* abusing the lkey field. See dtr_post_tx_desc() */

	err = dtr_post_tx_desc(rdma_transport, tx_desc, (msg_flags & MSG_DONTWAIT) != 0);
	if (err) {
		put_page(page);
		kfree(tx_desc);

		/* A non-blocking teardown flush (MSG_DONTWAIT) returning -EAGAIN
		 * is the connection already going away, not a send failure -- do
		 * not log it or re-trigger the teardown it is part of.
		 */
		if (!((msg_flags & MSG_DONTWAIT) && err == -EAGAIN)) {
			tr_err(transport, "dtr_post_tx_desc() failed %d\n", err);
			drbd_control_event(transport, CLOSED_BY_PEER);
		}
	}

	if (stream == DATA_STREAM)
		dtr_update_congested(transport);

	return err;
}

/* Wait for a DATA path with credit and an announced region chunk, then reserve
 * one tx credit (one peer recv WR == one RDMA-WRITE chunk) on it. Returns the
 * chosen cm (kref'd, credit reserved) or NULL with *err set
 * (-EAGAIN once the send timeout expires, -EINTR on signal). The credit is
 * released with dtr_undo_credit() if the chunk is not posted.
 */
static struct dtr_cm *dtr_get_cm_reserve_credit(struct dtr_transport *rdma_transport, int *err)
{
	struct dtr_stream *rdma_stream = &rdma_transport->stream[DATA_STREAM];
	struct dtr_flow *flow;
	struct dtr_cm *cm = NULL;
	long t;

	*err = 0;
retry:
	/* Drain DATA reposts (priority gap-fillers) before this new send competes
	 * for the survivor's region (see dtr_drain_resend / dtr_post_tx_desc).
	 */
	if (atomic_read(&rdma_transport->resend_pending[DATA_STREAM])) {
		*err = dtr_drain_resend(rdma_transport, DATA_STREAM);
		if (*err)
			return NULL;
	}
	t = wait_event_interruptible_timeout(rdma_stream->send_wq,
			(cm = dtr_select_and_get_cm_for_tx(rdma_transport, DATA_STREAM, 1)),
			rdma_stream->send_timeout);
	if (t == 0) {
		if (drbd_stream_send_timed_out(&rdma_transport->transport, DATA_STREAM)) {
			*err = -EAGAIN;
			return NULL;
		}
		goto retry;
	} else if (t < 0) {
		*err = -EINTR;
		return NULL;
	}

	flow = &cm->path->flow[DATA_STREAM];
	if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0) {
		kref_put(&cm->kref, dtr_destroy_cm);
		goto retry;
	}
	if (!atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max)) {
		atomic_inc(&flow->peer_rx_descs);
		kref_put(&cm->kref, dtr_destroy_cm);
		goto retry;
	}
	return cm;
}

static void dtr_undo_credit(struct dtr_path *path)
{
	struct dtr_flow *flow = &path->flow[DATA_STREAM];

	atomic_inc(&flow->peer_rx_descs);
	atomic_dec(&flow->tx_descs_posted);
}

/* Map @len bytes starting at @off within the physically-contiguous page run
 * that begins at @page as one source SGE on @tx_desc, taking a reference on
 * each page the run spans (released by dtr_free_tx_desc()). @len may exceed
 * PAGE_SIZE for a multi-page bvec: one SGE then covers several pages, gathered
 * into a contiguous RDMA-WRITE. Returns 0, or -EIO on a DMA mapping error with
 * nothing left behind.
 */
static int dtr_add_bvec_sge(struct dtr_cm *cm, struct dtr_tx_desc *tx_desc,
			    struct page *page, unsigned int off, unsigned int len)
{
	struct ib_device *device = cm->id->device;
	unsigned int npages = DIV_ROUND_UP(off + len, PAGE_SIZE);
	int s = tx_desc->nr_sges;
	dma_addr_t addr;
	unsigned int p;

	addr = ib_dma_map_page(device, page, off, len, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(device, addr))
		return -EIO;

	for (p = 0; p < npages; p++) {
		/*
		 * nth_page() was removed in newer kernels; walking the pfn is
		 * its universal equivalent, correct on both the discontiguous
		 * (SPARSEMEM) and the contiguous memory models.
		 */
		struct page *pg = pfn_to_page(page_to_pfn(page) + p);

		get_page(pg);
		tx_desc->wr_pages[tx_desc->nr_pages++] = pg;
	}
	tx_desc->sge[s].addr = addr;
	tx_desc->sge[s].length = len;
	tx_desc->sge[s].lkey = dtr_cm_to_lkey(cm);
	tx_desc->nr_sges = s + 1;

	return 0;
}

/* Post a fully-built chunk as one RDMA-WRITE: reserve the region room it
 * occupies (chunk_bytes rounded up to the region's stride -- the receiver
 * advances its cursor by the same) and post at it, in one atomic step
 * (dtr_reserve_and_post).
 * The chunk was sized at open time against a peek of this path's head region,
 * but a concurrent failover repost may have consumed that space since
 * (-ENOBUFS), or the path may have died (post error, path now suspect). In
 * both cases nothing reached the peer and the cursor is untouched or dies with
 * the path: hand the chunk to the failover machinery, which places it on any
 * path with room (possibly this one, once the peer re-announces) or queues it
 * for a bounded async retry, preserving its stream sequence number --
 * dtr_send_bio() then continues the bio, draining the queue first. Consumes
 * the caller's @cm credit reference either way. Returns 0 if the chunk was
 * posted or failed over, a negative errno only if no path could take it.
 */
static int dtr_flush_chunk(struct dtr_cm *cm, struct dtr_tx_desc *tx_desc,
			   unsigned int chunk_bytes)
{
	int err;

	err = dtr_reserve_and_post(cm, &cm->path->regions[DATA_STREAM], tx_desc, chunk_bytes);
	if (err) {
		struct dtr_transport *rdma_transport =
			container_of(cm->path->path.transport, struct dtr_transport, transport);

		dtr_undo_credit(cm->path);
		err = dtr_failover_tx_desc(rdma_transport, cm, tx_desc);
	}
	kref_put(&cm->kref, dtr_destroy_cm);

	return err;
}

/* Send @bio's payload on DATA_STREAM via one-sided RDMA-WRITE, iterating the
 * bio by bvec: each (multi-page) bvec becomes one source SGE, so a physically
 * contiguous 1 MiB bio can go in a single WR, and an arbitrarily offset/sized
 * bvec is handled directly -- no per-page copy. A chunk (one WR) packs up to
 * sges_max bvecs, bounded by the room available in the peer's head region; a
 * bvec larger than that is split and continues in the next chunk. The receiver
 * lands each chunk at its region cursor (stride-aligned, so possibly mid-page)
 * and reassembles the sequenced chunks in dtr_recv_bio() regardless of how the
 * bio was split. When
 * the peer's window is momentarily empty the sender waits for a region announce
 * (region bytes are the bulk back-pressure) rather than spinning.
 */
static int dtr_send_bio(struct drbd_transport *transport, struct bio *bio, unsigned int msg_flags)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_stream *ds = &rdma_transport->stream[DATA_STREAM];
	int sges_max = rdma_transport->sges_max;
	struct dtr_tx_desc *tx_desc = NULL;
	struct dtr_cm *cm = NULL;
	struct dtr_path *path = NULL;
	unsigned int chunk_bytes = 0;
	unsigned int chunk_max_bytes = 0;
	struct bvec_iter iter;
	struct bio_vec bvec;
	int err = 0;

	if (!dtr_transport_ok(transport))
		return -ECONNRESET;

	bio_for_each_bvec(bvec, bio, iter) {
		unsigned int done = 0;

		while (done < bvec.bv_len) {
			unsigned int boff = bvec.bv_offset + done;
			struct page *page = pfn_to_page(page_to_pfn(bvec.bv_page) +
							(boff >> PAGE_SHIFT));
			unsigned int off = boff & (PAGE_SIZE - 1);
			unsigned int remain = bvec.bv_len - done;
			unsigned int room, take;

			if (!tx_desc) {
				/* Open a chunk: secure a path with credit, peek its
				 * head region, size the descriptor. The peek only
				 * sizes the chunk; the region space itself is
				 * reserved atomically with the post, at flush time
				 * (dtr_flush_chunk -> dtr_reserve_and_post).
				 */
				unsigned int rem_bytes = iter.bi_size - done;

				cm = dtr_get_cm_reserve_credit(rdma_transport, &err);
				if (!cm)
					goto out; /* -EAGAIN / -EINTR */
				path = cm->path;

				chunk_max_bytes =
					dtr_remote_room(&path->regions[DATA_STREAM], 1);
				if (chunk_max_bytes == 0) {
					/* Window momentarily empty: wait for an announce
					 * and retry rather than spinning.
					 */
					dtr_undo_credit(path);
					kref_put(&cm->kref, dtr_destroy_cm);
					cm = NULL;
					err = dtr_wait_for_remote_buffer(rdma_transport,
									 DATA_STREAM, 1);
					if (err)
						goto out;
					continue;
				}
				/* No chunk needs more region room than the rest of the
				 * bio occupies; cap so the descriptor stays bio-sized.
				 * (The room is a multiple of the region's stride, so any
				 * chunk up to it fits once rounded.)
				 */
				chunk_max_bytes = min(chunk_max_bytes, rem_bytes);

				tx_desc = kzalloc_flex(*tx_desc, sge, sges_max, GFP_NOIO);
				if (tx_desc) {
					/* Each SGE spans ceil(off+len) pages; a sub-page SGE
					 * straddling a boundary touches 2, so bound the
					 * per-page ref array generously.
					 */
					int nr_pages = DIV_ROUND_UP(chunk_max_bytes, PAGE_SIZE) +
						       2 * sges_max;

					tx_desc->wr_pages =
						kmalloc_array(nr_pages, sizeof(struct page *),
							      GFP_NOIO);
				}
				if (!tx_desc || !tx_desc->wr_pages) {
					kfree(tx_desc);
					tx_desc = NULL;
					dtr_undo_credit(path);
					kref_put(&cm->kref, dtr_destroy_cm);
					cm = NULL;
					err = -ENOMEM;
					goto out;
				}
				tx_desc->type = SEND_BIO;
				/* Marks the desc as a region write for the failover
				 * repost; the actual target (remote_addr/rkey) is
				 * assigned by dtr_reserve_and_post() at flush time.
				 */
				tx_desc->rdma_write = true;
				tx_desc->imm = dtr_imm_encode(DATA_STREAM, ds->tx_sequence++);
				chunk_bytes = 0;
			}

			/* Bytes the chunk can still take, bounded by the region room
			 * it was sized for; the SGE count is bounded separately below.
			 */
			room = chunk_max_bytes - chunk_bytes;
			take = min(remain, room);

			err = dtr_add_bvec_sge(cm, tx_desc, page, off, take);
			if (err)
				goto out;
			chunk_bytes += take;
			done += take;

			if (tx_desc->nr_sges == sges_max || chunk_bytes >= chunk_max_bytes) {
				err = dtr_flush_chunk(cm, tx_desc, chunk_bytes);
				tx_desc = NULL;
				cm = NULL;
				if (err)
					goto out;
			}
		}
	}

	if (tx_desc) {
		err = dtr_flush_chunk(cm, tx_desc, chunk_bytes);
		tx_desc = NULL;
		cm = NULL;
	}

out:
	/* Reached only with a half-built chunk on error (region not yet
	 * committed); drop it and its credit.
	 */
	if (tx_desc) {
		dtr_free_tx_desc(cm, tx_desc);
		dtr_undo_credit(cm->path);
		kref_put(&cm->kref, dtr_destroy_cm);
	}
	dtr_update_congested(transport);

	if (err)
		drbd_control_event(transport, CLOSED_BY_PEER);

	return err;
}

/* The alignment the core needs for the DATA payload we hand up (its backing
 * devices' dma_alignment). Taken into the stride of DATA regions registered
 * from now on; regions already announced keep theirs (the core copies payload
 * that arrives misaligned for one of those, see peer_req_align_bios()).
 */
static void dtr_set_rx_alignment(struct drbd_transport *transport, unsigned int bytes)
{
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	WRITE_ONCE(rdma_transport->rx_align_hint, min_t(unsigned int, bytes, PAGE_SIZE));
}

static bool dtr_hint(struct drbd_transport *transport, enum drbd_stream stream,
		enum drbd_tr_hints hint)
{
	switch (hint) {
	default: /* not implemented, but should not trigger error handling */
		return true;
	}
	return true;
}

static void dtr_debugfs_show_flow(struct dtr_flow *flow, const char *name, struct seq_file *m)
{
	seq_printf(m,    " %-7s field:  posted\t alloc\tdesired\t  max\n", name);
	seq_printf(m, "      tx_descs: %5d\t\t\t%5d\n",
		   atomic_read(&flow->tx_descs_posted), flow->tx_descs_max);
	seq_printf(m, " peer_rx_descs: %5d (receive window at peer)\n",
		   atomic_read(&flow->peer_rx_descs));
	seq_printf(m, "      rx_descs: %5d\t%5d\t%5d\t%5d\n", atomic_read(&flow->rx_descs_posted),
		   atomic_read(&flow->rx_descs_allocated),
		   flow->rx_descs_want_posted, flow->rx_descs_max);
	seq_printf(m, " rx_peer_knows: %5d (what the peer knows about my receive window)\n\n",
		   atomic_read(&flow->rx_descs_known_to_peer));
}

static void dtr_debugfs_show_path(struct dtr_path *path, struct seq_file *m)
{
	static const char * const stream_names[] = {
		[ST_DATA] = "data",
		[ST_CONTROL] = "control",
		[ST_FLOW_CTRL] = "flowctl",
	};
	static const char * const state_names[] = {
		[0] = "not connected",
		[DSM_CONNECT_REQ] = "CONNECT_REQ",
		[DSM_CONNECTING] = "CONNECTING",
		[DSM_CONNECTING|DSM_CONNECT_REQ] = "CONNECTING|DSM_CONNECT_REQ",
		[DSM_CONNECTED] = "CONNECTED",
		[DSM_CONNECTED|DSM_CONNECT_REQ] = "CONNECTED|CONNECT_REQ",
		[DSM_CONNECTED|DSM_CONNECTING] = "CONNECTED|CONNECTING",
		[DSM_CONNECTED|DSM_CONNECTING|DSM_CONNECT_REQ] =
			"CONNECTED|CONNECTING|DSM_CONNECT_REQ",
		[DSM_ERROR] = "ERROR",
		[DSM_ERROR|DSM_CONNECT_REQ] = "ERROR|CONNECT_REQ",
		[DSM_ERROR|DSM_CONNECTING] = "ERROR|CONNECTING",
		[DSM_ERROR|DSM_CONNECTING|DSM_CONNECT_REQ] = "ERROR|CONNECTING|CONNECT_REQ",
		[DSM_ERROR|DSM_CONNECTED] = "ERROR|CONNECTED",
		[DSM_ERROR|DSM_CONNECTED|DSM_CONNECT_REQ] = "ERROR|CONNECTED|CONNECT_REQ",
		[DSM_ERROR|DSM_CONNECTED|DSM_CONNECTING] = "ERROR|CONNECTED|CONNECTING|",
		[DSM_ERROR|DSM_CONNECTED|DSM_CONNECTING|DSM_CONNECT_REQ] =
			"ERROR|CONNECTED|CONNECTING|CONNECT_REQ",
	};

	enum drbd_stream i;
	unsigned long s = 0;
	struct dtr_cm *cm;

	rcu_read_lock();
	cm = rcu_dereference(path->cm);
	if (cm)
		s = cm->state;
	rcu_read_unlock();

	seq_printf(m, "%pI4 - %pI4: %s\n",
		   &((struct sockaddr_in *)&path->path.my_addr)->sin_addr,
		   &((struct sockaddr_in *)&path->path.peer_addr)->sin_addr,
		   state_names[s]);

	if (dtr_path_ok(path)) {
		for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
			struct dtr_region_set *rs = &path->regions[i];
			struct dtr_local_buffer *lb;
			struct dtr_remote_buffer *rb;
			int local = 0, remote = 0;
			u32 armed = 0;
			unsigned long flags;

			dtr_debugfs_show_flow(&path->flow[i], stream_names[i], m);

			spin_lock_irqsave(&rs->local_buffers_lock, flags);
			list_for_each_entry(lb, &rs->local_buffers, list) {
				local++;
				armed += lb->len;
			}
			spin_unlock_irqrestore(&rs->local_buffers_lock, flags);

			spin_lock_irqsave(&rs->remote_buffers_lock, flags);
			list_for_each_entry(rb, &rs->remote_buffers, list)
				remote++;
			spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);

			seq_printf(m, "    %s regions: local %d (%u KiB armed), remote %d\n",
				   stream_names[i], local, armed >> 10, remote);
		}

		dtr_debugfs_show_flow(&path->flow[ST_FLOW_CTRL],
				      stream_names[ST_FLOW_CTRL], m);
		seq_printf(m, "    control ring: local %s, remote %s (tx_seq %u)\n",
			   path->ring.local ? "registered" : "none",
			   path->ring.remote_known ? "known" : "unknown",
			   path->ring.tx_seq);
	}
}

static void dtr_debugfs_show(struct drbd_transport *transport, struct seq_file *m)
{
	struct dtr_path *path;

	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 2);

	seq_printf(m, "rx_align_hint: %u\n", READ_ONCE(rdma_transport->rx_align_hint));
	seq_printf(m, "region_page_refs: taken %d put %d handed_to_core %d\n\n",
		   atomic_read(&rdma_transport->region_refs_taken),
		   atomic_read(&rdma_transport->region_refs_put),
		   atomic_read(&rdma_transport->region_refs_handed));

	rcu_read_lock();
	list_for_each_entry_rcu(path, &transport->paths, path.list)
		dtr_debugfs_show_path(path, m);
	rcu_read_unlock();
}

static int dtr_add_path(struct drbd_path *add_path)
{
	struct drbd_transport *transport = add_path->transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_path *path;
	int i;

	path = container_of(add_path, struct dtr_path, path);

	/* initialize private parts of path */
	atomic_set(&path->cs.passive_state, PCS_INACTIVE);
	atomic_set(&path->cs.active_state, PCS_INACTIVE);
	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		struct dtr_region_set *rs = &path->regions[i];

		rs->path = path;
		rs->stream = i;
		INIT_LIST_HEAD(&rs->remote_buffers);
		spin_lock_init(&rs->remote_buffers_lock);
		INIT_LIST_HEAD(&rs->local_buffers);
		INIT_LIST_HEAD(&rs->exhausted_buffers);
		spin_lock_init(&rs->local_buffers_lock);
		INIT_WORK(&rs->register_buffers_work, dtr_register_buffers_work_fn);
	}
	path->flags = 0;
	INIT_WORK(&path->shutdown_work, dtr_shutdown_work_fn);
	spin_lock_init(&path->ring.lock);
	INIT_WORK(&path->ring_register_work, dtr_ring_register_work_fn);
	spin_lock_init(&path->send_flow_control_lock);
	tasklet_setup(&path->flow_control_tasklet, dtr_flow_control_tasklet_fn);
	INIT_WORK(&path->refill_rx_descs_work, dtr_refill_rx_descs_work_fn);
	INIT_DELAYED_WORK(&path->cs.retry_connect_work, dtr_cma_retry_connect_work_fn);

	if (!rdma_transport->active)
		return 0;

	return dtr_activate_path(path);
}

static bool dtr_may_remove_path(struct drbd_path *del_path)
{
	struct drbd_transport *transport = del_path->transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct drbd_path *drbd_path, *connected_path = NULL;
	int connected = 0;

	if (!rdma_transport->active)
		return true;

	list_for_each_entry(drbd_path, &transport->paths, list) {
		struct dtr_path *path = container_of(drbd_path, struct dtr_path, path);

		if (dtr_path_ok(path)) {
			connected++;
			connected_path = drbd_path;
		}
	}

	return connected > 1 || connected_path != del_path;
}

/* Is some path other than @path connected? Such a survivor must exist for a
 * graceful removal to make sense: it carries the connection while @path drains
 * and fills the global per-stream reorder gaps as both ends finish in flight.
 */
static bool dtr_other_path_connected(struct dtr_path *path)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_path *p;
	bool found = false;

	rcu_read_lock();
	list_for_each_entry_rcu(p, &transport->paths, path.list) {
		if (p != path && dtr_path_ok(p)) {
			found = true;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

/* The graceful-shutdown handshake for @path is complete: the peer's marker has
 * arrived (so all of its payload on this path is in) AND our own in-flight
 * DATA/CONTROL payload has all completed (SUCCESS, not flushed). FLOW_CTRL
 * records -- including the shutdown markers -- are charged to a separate pool
 * and are intentionally not counted here. Now the QP can be torn down without
 * losing or flushing any payload.
 */
static bool dtr_path_drained_for_removal(struct dtr_path *path)
{
	return test_bit(DTR_PASSIVE_SHUT_DOWN, &path->flags) &&
	       atomic_read(&path->flow[DATA_STREAM].tx_descs_posted) == 0 &&
	       atomic_read(&path->flow[CONTROL_STREAM].tx_descs_posted) == 0;
}

/* Hot path removal (drbdsetup del-path). Modeled on the lb-tcp transport's
 * dtl_remove_path() coordinated half-close: stop sending payload on the path,
 * hand the peer an in-band marker that all our payload has been sent, and wait
 * (bounded by ping_timeo) for the peer to drain and echo a marker back, before
 * tearing the QP down. RC QPs have no TCP-style half-close, so the marker is a
 * control-ring record (DTR_SHUTDOWN_MAGIC) delivered in order after all payload
 * on the path's single QP -- the FIN guarantee. This avoids dtr_disconnect_path()
 * flushing payload still in flight (which strands a per-stream reorder gap and
 * bounces the connection into a +12s ping timeout and a resync).
 *
 * Only meaningful while connected with a survivor to carry the connection;
 * otherwise the connection is going down regardless -- tear down directly.
 */
static void dtr_remove_path(struct drbd_path *del_path)
{
	struct dtr_path *path = container_of(del_path, struct dtr_path, path);
	struct drbd_transport *transport = del_path->transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);

	if (test_bit(TR_ESTABLISHED, &del_path->flags) && dtr_other_path_connected(path)) {
		long timeout = HZ; /* fallback if net_conf went away */
		unsigned long deadline;
		struct net_conf *nc;
		long remaining;
		int err;

		/* Divert new payload to the survivor (dtr_select_and_get_cm_for_tx
		 * skips a DTR_ACTIVE_SHUT_DOWN path); already-posted in-flight stays
		 * on the live QP and completes normally.
		 */
		set_bit(DTR_ACTIVE_SHUT_DOWN, &path->flags);

		rcu_read_lock();
		nc = rcu_dereference(transport->net_conf);
		if (nc)
			timeout = nc->ping_timeo * HZ;
		rcu_read_unlock();
		deadline = jiffies + timeout;

		/* Our FIN, the last record we post on this path. It MUST reach the
		 * peer for the handshake to complete; under load the FLOW_CTRL credit
		 * pool is momentarily exhausted (-ENOBUFS) often enough that a single
		 * attempt regularly fails -- which would silently degrade to the
		 * abrupt teardown that bounces the connection. Retry within the
		 * deadline (a tx completion or a peer grant frees a credit in
		 * milliseconds); stop early if the path goes down (peer disconnected).
		 */
		for (;;) {
			err = dtr_send_shutdown_msg(path, GFP_NOIO);
			if ((err != -ENOBUFS && err != -ENOMEM) ||
			    !dtr_path_ok(path) || time_after_eq(jiffies, deadline))
				break;
			msleep(20);
		}
		if (err && err != -ENOBUFS && __ratelimit(&rdma_transport->rate_limit))
			tr_warn(transport, "graceful path removal: marker send failed %d\n", err);

		/* Waits on the survivor delivering the peer's marker + our in-flight
		 * completing -- never on the dead path's own tx -- so concurrent
		 * two-sided del-path cannot deadlock it. No transport lock is held
		 * across the wait, so the survivor's data path is not stalled. Also
		 * completes if the peer disconnects the path first (the common case
		 * when both ends run del-path: the peer finishes its handshake and
		 * disconnects before its marker reaches us; the path is then settled
		 * -- our payload has drained -- so there is nothing left to wait for).
		 */
		remaining = (long)(deadline - jiffies);
		if (remaining < 1)
			remaining = 1;
		wait_event_timeout(rdma_transport->shutdown_wq,
				   dtr_path_drained_for_removal(path) || !dtr_path_ok(path),
				   remaining);

		if (dtr_path_ok(path) && !dtr_path_drained_for_removal(path))
			tr_warn(transport, "graceful path removal timed out, closing anyway\n");
	}

	dtr_disconnect_path(path);
}

static struct drbd_transport_class rdma2_transport_class = {
	.name = "rdma2",
	.instance_size = sizeof(struct dtr_transport),
	.path_instance_size = sizeof(struct dtr_path),
	.listener_instance_size = sizeof(struct dtr_listener),
	.ops = {
		.init = dtr_init,
		.free = dtr_free,
		.init_listener = dtr_init_listener,
		.release_listener = dtr_destroy_listener,
		.prepare_connect = dtr_prepare_connect,
		.connect = dtr_connect,
		.finish_connect = dtr_finish_connect,
		.recv = dtr_recv,
		.stats = dtr_stats,
		.net_conf_change = dtr_net_conf_change,
		.set_rcvtimeo = dtr_set_rcvtimeo,
		.get_rcvtimeo = dtr_get_rcvtimeo,
		.send_page = dtr_send_page,
		.send_bio = dtr_send_bio,
		.recv_bio = dtr_recv_bio,
		.stream_ok = dtr_stream_ok,
		.hint = dtr_hint,
		.set_rx_alignment = dtr_set_rx_alignment,
		.debugfs_show = dtr_debugfs_show,
		.add_path = dtr_add_path,
		.may_remove_path = dtr_may_remove_path,
		.remove_path = dtr_remove_path,
	},
	.module = THIS_MODULE,
	.list = LIST_HEAD_INIT(rdma2_transport_class.list),
};

static int __init dtr2_initialize(void)
{
	return drbd_register_transport_class(&rdma2_transport_class,
					     DRBD_TRANSPORT_API_VERSION,
					     sizeof(struct drbd_transport));
}

static void __exit dtr2_cleanup(void)
{
	drbd_unregister_transport_class(&rdma2_transport_class);
}

module_init(dtr2_initialize)
module_exit(dtr2_cleanup)
