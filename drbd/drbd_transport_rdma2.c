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
 * Nearly all data transfer uses the send/receive semantics. No need to
 * actually use RDMA WRITE / READ.
 *
 * Only for DRBD's remote read (P_DATA_REQUEST and P_DATA_REPLY) an
 * RDMA WRITE would make a lot of sense:
 *   Right now the recv_dless_read() function in DRBD is one of the few
 *   remaining callers of recv(,,CALLER_BUFFER). This in turn needs a
 *   memcpy().
 *
 * The block_id field (64 bit) could be re-labelled to be the RKEY for
 * an RDMA WRITE. The P_DATA_REPLY packet will then only deliver the
 * news that the RDMA WRITE was executed...
 *
 * Flow Control
 * ============
 *
 * If the receiving machine cannot keep up with the data rate it needs to
 * slow down the sending machine. In order to do so we keep track of the
 * number of rx_descs the peer has posted (peer_rx_descs).
 *
 * If one player posts new rx_descs it tells the peer about it with a
 * dtr_flow_control packet. Those packets never get delivered to the
 * DRBD above us.
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

struct dtr_flow_control {
	uint32_t magic;
	uint32_t new_rx_descs[2];
	uint32_t send_from_stream;
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

/* Floor for a stream's registered receive window. A single packet may be up to
 * DRBD_SOCKET_BUFFER_SIZE, and a region whose tail cannot take the next write
 * is abandoned there (see __dtr_find_remote_buffer()), so leave room for a
 * handful of maximum-sized packets per region.
 */
#define DTR_MIN_REGION_BYTES (8 * DRBD_SOCKET_BUFFER_SIZE)

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

enum dtr_alloc_rdma_res_causes {
	IB_ALLOC_PD,
	IB_ALLOC_CQ_RX,
	IB_ALLOC_CQ_TX,
	RDMA_CREATE_QP,
	IB_GET_DMA_MR
};

struct dtr_rx_desc {
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

struct dtr_path {
	struct drbd_path path;

	struct dtr_connect_state cs;

	struct dtr_cm *cm; /* RCU'd and kref in cm */

	struct dtr_flow flow[2];
	spinlock_t send_flow_control_lock;
	struct tasklet_struct flow_control_tasklet;
	struct work_struct refill_rx_descs_work;

	/* Per-stream RDMA-WRITE receive regions. Indexed by enum drbd_stream;
	 * DATA_STREAM carries bulk payload, CONTROL_STREAM small control packets.
	 */
	struct dtr_region_set regions[2];
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
	wait_queue_head_t state_wq;
	unsigned long last_sent_jif;
	atomic_t tx_descs_posted;
	struct timer_list tx_timeout;

	struct work_struct tx_timeout_work;
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
static int dtr_post_tx_desc(struct dtr_transport *, struct dtr_tx_desc *);
static int dtr_repost_tx_desc(struct dtr_cm *old_cm, struct dtr_tx_desc *tx_desc);
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
static int dtr_cm_alloc_rdma_res(struct dtr_cm *cm);
static void __dtr_refill_rx_desc(struct dtr_path *path, enum drbd_stream stream);
static int dtr_send_flow_control_msg(struct dtr_path *path, gfp_t gfp_mask);
static struct dtr_cm *dtr_path_get_cm_connected(struct dtr_path *path);
static void dtr_destroy_cm(struct kref *kref);
static void dtr_destroy_cm_keep_id(struct kref *kref);
static int dtr_activate_path(struct dtr_path *path);
static int dtr_got_announce_buffer_msg(struct dtr_path *path, struct dtr_announce_buffer *msg);
static void dtr_free_local_buffers(struct dtr_path *path);
static void dtr_free_remote_buffers(struct dtr_path *path);
static void dtr_end_tx_work_fn(struct work_struct *work);
static void dtr_end_rx_work_fn(struct work_struct *work);
static void dtr_cma_retry_connect(struct dtr_path *path, struct dtr_cm *failed_cm);
static void dtr_tx_timeout_fn(struct timer_list *t);
static void dtr_control_timer_fn(struct timer_list *t);
static void dtr_tx_timeout_work_fn(struct work_struct *work);
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

	list_for_each_entry(drbd_path, &transport->paths, list) {
		struct dtr_path *path = container_of(drbd_path, struct dtr_path, path);

		__dtr_disconnect_path(path);
		cancel_work_sync(&path->regions[DATA_STREAM].register_buffers_work);
		cancel_work_sync(&path->regions[CONTROL_STREAM].register_buffers_work);
		dtr_free_remote_buffers(path);
		dtr_free_local_buffers(path);
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
	tx_desc->imm = dtr_imm_encode(ST_FLOW_CTRL, 0);

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

		page = rx_desc->page;
		/* put_page() if we would get_page() in
		 * dtr_create_rx_desc().  but we don't. We return the page
		 * chain to the user, which is supposed to give it back to
		 * drbd_free_pages() eventually.
		 */
		rx_desc->page = NULL;
		remaining -= rx_desc->size;

		/* If the sender did dtr_send_page every bvec of a bio with
		 * unaligned bvecs (as xfs often creates), rx_desc->size and
		 * offset may well be not the PAGE_SIZE and 0 we hope for.
		 */

		err = drbd_bio_add_page(transport, bios, page, rx_desc->size, 0);
		if (err < 0)
			return err;
		if (remaining)
			*misalign_bits |= rx_desc->size;

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
	struct dtr_rx_desc *rx_desc = NULL;
	void *buffer;

	if (flags & GROW_BUFFER) {
		/*
		 * Since transport_rdma always returns the full, requested
		 * amount of data, DRBD should never call with GROW_BUFFER!
		 */
		tr_err(transport, "Called with GROW_BUFFER\n");
		return -EINVAL;
	} else if (rdma_stream->current_rx.bytes_left == 0) {
		long t;

		dtr_recycle_rx_desc(transport, stream, &rdma_stream->current_rx.desc, GFP_NOIO);
		if (flags & MSG_DONTWAIT) {
			t = dtr_receive_rx_desc(rdma_transport, stream, &rx_desc);
		} else {
			t = wait_event_interruptible_timeout(rdma_stream->recv_wq,
					dtr_receive_rx_desc(rdma_transport, stream,
							    &rx_desc),
					rdma_stream->recv_timeout);
		}

		if (t <= 0)
			return t == 0 ? -EAGAIN : -EINTR;

		buffer = page_address(rx_desc->page);
		rdma_stream->current_rx.desc = rx_desc;
		rdma_stream->current_rx.pos = buffer + size;
		rdma_stream->current_rx.bytes_left = rx_desc->size - size;
		if (rdma_stream->current_rx.bytes_left < 0)
			tr_warn(transport,
				"new, requesting more (%zu) than available (%d)\n",
				size, rx_desc->size);

		if (flags & CALLER_BUFFER)
			memcpy(*buf, buffer, size);
		else
			*buf = buffer;


		return size;
	}

	/* return next part */
	buffer = rdma_stream->current_rx.pos;
	rdma_stream->current_rx.pos += size;

	if (rdma_stream->current_rx.bytes_left < size) {
		tr_err(transport,
		       "requested more than left! bytes_left = %d, size = %zu\n",
		       rdma_stream->current_rx.bytes_left, size);
		rdma_stream->current_rx.bytes_left = 0; /* 0 left == get new entry */
	} else {
		rdma_stream->current_rx.bytes_left -= size;
	}

	if (flags & CALLER_BUFFER)
		memcpy(*buf, buffer, size);
	else
		*buf = buffer;

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

static void dtr_path_established_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, establish_work);
	struct dtr_path *path = cm->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_transport *rdma_transport =
		container_of(transport, struct dtr_transport, transport);
	struct dtr_connect_state *cs = &path->cs;
	int i, p, err;

	err = cm != path->cm;
	if (err)
		goto out_put;

	p = atomic_cmpxchg(&cs->passive_state, PCS_CONNECTING, PCS_FINISHING);
	if (p < PCS_CONNECTING)
		goto out;

	kref_get(&cm->kref); /* connected -> expect a disconnect in the future */
	path->cm->state = DSM_CONNECTED;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++)
		__dtr_refill_rx_desc(path, i);
	err = dtr_send_flow_control_msg(path, GFP_NOIO);
	if (err > 0)
		err = 0;
	if (err)
		tr_err(transport, "sending first flow_control_msg() failed\n");

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

	/* NB: region registration is NOT kicked here. Announcing regions over
	 * an in-band SEND would borrow the scarce initial CONTROL credit and
	 * starve DRBD's own handshake. The clean design announces regions over
	 * the control ring bootstrapped via CM private_data; the kick lands with
	 * that ring. Until then the machinery below stays dormant.
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
	INIT_LIST_HEAD(&cm->error_rx_descs);
	spin_lock_init(&cm->error_rx_descs_lock);
	timer_setup(&cm->tx_timeout, dtr_tx_timeout_fn, 0);

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
		if (connecting)
			kref_put(&cm->kref, dtr_destroy_cm);
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
	struct dtr_flow_control msg;
	struct dtr_flow *flow;
	enum drbd_stream i;
	int err, n[2], send_from_stream = -1, rx_descs = 0;

	msg.magic = cpu_to_be32(DTR_MAGIC);

	spin_lock_bh(&path->send_flow_control_lock);
	/*
	 * dtr_send_flow_control_msg() is called from multiple threads (the
	 * receiver thread, the sender threads, softirq contexts).
	 * Determining the number of new rx_descs and adding this number
	 * to rx_descs_known_to_peer has to be atomic!
	 */
	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		flow = &path->flow[i];

		n[i] = dtr_new_rx_descs(flow);
		atomic_add(n[i], &flow->rx_descs_known_to_peer);
		rx_descs += n[i];

		msg.new_rx_descs[i] = cpu_to_be32(n[i]);
		if (send_from_stream == -1 &&
			atomic_read(&flow->tx_descs_posted) < flow->tx_descs_max &&
			atomic_dec_if_positive(&flow->peer_rx_descs) >= 0)
			send_from_stream = i;
	}
	spin_unlock_bh(&path->send_flow_control_lock);

	if (send_from_stream == -1) {
		struct drbd_transport *transport = path->path.transport;
		struct dtr_transport *rdma_transport =
			container_of(transport, struct dtr_transport, transport);

		if (__ratelimit(&rdma_transport->rate_limit))
			tr_err(transport, "Not sending flow_control msg, no receive window!\n");
		err = -ENOBUFS;
		goto out_undo;
	}

	flow = &path->flow[send_from_stream];
	if (rx_descs == 0 || !atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max)) {
		atomic_inc(&flow->peer_rx_descs);
		return 0;
	}

	msg.send_from_stream = cpu_to_be32(send_from_stream);
	err = dtr_send(path, &msg, sizeof(msg), gfp_mask);
	if (err) {
		atomic_inc(&flow->peer_rx_descs);
		atomic_dec(&flow->tx_descs_posted);
out_undo:
		for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
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

	for (i = CONTROL_STREAM; i >= DATA_STREAM; i--) {
		uint32_t new_rx_descs = be32_to_cpu(msg->new_rx_descs[i]);

		flow = &path->flow[i];

		n = atomic_add_return(new_rx_descs, &flow->peer_rx_descs);
		wake_up_interruptible(&rdma_transport->stream[i].send_wq);
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

static void dtr_tx_timeout_work_fn(struct work_struct *work)
{
	struct dtr_cm *cm = container_of(work, struct dtr_cm, tx_timeout_work);
	struct drbd_transport *transport;
	struct dtr_path *path = cm->path;

	if (!test_and_clear_bit(DSB_CONNECTED, &cm->state) || !path)
		goto out;

	transport = path->path.transport;
	tr_warn(transport, "%pI4 - %pI4: tx timeout\n",
		&((struct sockaddr_in *)&path->path.my_addr)->sin_addr,
		&((struct sockaddr_in *)&path->path.peer_addr)->sin_addr);

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

out:
	kref_put(&cm->kref, dtr_destroy_cm); /* for work (armed timer) */
}

static void dtr_tx_timeout_fn(struct timer_list *t)
{
	struct dtr_cm *cm = timer_container_of(cm, t, tx_timeout);

	/* cm->kref for armed timer becomes a ref for the work */
	schedule_work(&cm->tx_timeout_work);
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
	 * were accounted for the data stream or the control stream...
	 */
	if (atomic_dec_if_positive(&flow[DATA_STREAM].rx_descs_posted) >= 0)
		return;

	if (atomic_dec_if_positive(&flow[CONTROL_STREAM].rx_descs_posted) >= 0)
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

	ib_dma_sync_single_for_cpu(cm->id->device, rx_desc->sge.addr,
				   PAGE_SIZE, DMA_FROM_DEVICE);

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
	if (dtr_imm_stream(immediate) == ST_FLOW_CTRL) {
		void *msg = page_address(rx_desc->page);
		int send_from_stream;

		ib_dma_sync_single_for_cpu(cm->id->device, rx_desc->sge.addr,
					   PAGE_SIZE, DMA_FROM_DEVICE);
		/* Flow-control and region-announce records share the ST_FLOW_CTRL
		 * stream; tell them apart by their leading magic.
		 */
		if (be32_to_cpu(*(__be32 *)msg) == DTR_ANNOUNCE_MAGIC)
			send_from_stream = dtr_got_announce_buffer_msg(path, msg);
		else
			send_from_stream = dtr_got_flow_control_msg(path, msg);
		err = dtr_repost_rx_desc(cm, rx_desc);
		if (err)
			tr_err(&rdma_transport->transport, "dtr_repost_rx_desc() failed %d", err);
		dtr_maybe_trigger_flow_control_msg(path, send_from_stream);
	} else {
		unsigned int stream = dtr_imm_stream(immediate);
		struct dtr_flow *flow = &path->flow[stream];
		struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];

		atomic_dec(&flow->rx_descs_posted);
		smp_wmb(); /* smp_rmb() is in dtr_new_rx_descs() */
		atomic_dec(&flow->rx_descs_known_to_peer);

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
		struct dtr_flow *flow = &path->flow[DATA_STREAM];

		if (atomic_read(&flow->rx_descs_posted) < flow->rx_descs_want_posted / 2)
			schedule_work(&path->refill_rx_descs_work);
	}
}

static void dtr_free_tx_desc(struct dtr_cm *cm, struct dtr_tx_desc *tx_desc)
{
	struct ib_device *device = cm->id->device;
	struct bio_vec bvec;
	struct bvec_iter iter;
	int i, nr_sges;

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
		nr_sges = tx_desc->nr_sges;
		for (i = 0; i < nr_sges; i++)
			ib_dma_unmap_page(device, tx_desc->sge[i].addr, tx_desc->sge[i].length,
					  DMA_TO_DEVICE);
		bio_for_each_segment(bvec, tx_desc->bio, iter) {
			put_page(bvec.bv_page);
		}
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
	struct dtr_stream *rdma_stream;
	enum dtr_stream_nr stream_nr = dtr_imm_stream(tx_desc->imm);
	int err;

	if (stream_nr != ST_FLOW_CTRL) {
		flow = &path->flow[stream_nr];
		rdma_stream = &rdma_transport->stream[stream_nr];
	} else {
		struct dtr_flow_control *msg = (struct dtr_flow_control *)tx_desc->data;
		enum dtr_stream_nr send_from_stream = be32_to_cpu(msg->send_from_stream);

		flow = &path->flow[send_from_stream];
		rdma_stream = &rdma_transport->stream[send_from_stream];
	}

	if (wc->status != IB_WC_SUCCESS || wc->opcode != IB_WC_SEND) {
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

		if (stream_nr != ST_FLOW_CTRL) {
			err = dtr_repost_tx_desc(cm, tx_desc);
			if (!err)
				tx_desc = NULL; /* it is in the air again! Fly! */
			else if (__ratelimit(&rdma_transport->rate_limit)) {
				tr_warn(transport, "repost of tx_desc failed! %d\n", err);
				drbd_control_event(transport, CLOSED_BY_PEER);
			}
		}
	}

	atomic_dec(&flow->tx_descs_posted);
	wake_up_interruptible(&rdma_stream->send_wq);

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
		.cap.max_recv_sge = 1, /* We only receive into single pages */
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
	recv_wr.sg_list = &rx_desc->sge;
	recv_wr.num_sge = 1;

	ib_dma_sync_single_for_device(cm->id->device,
				      rx_desc->sge.addr, PAGE_SIZE, DMA_FROM_DEVICE);

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
	ib_dma_unmap_single(device, rx_desc->sge.addr, PAGE_SIZE, DMA_FROM_DEVICE);
	kref_put(&cm->kref, dtr_destroy_cm);

	if (rx_desc->page) {
		struct drbd_transport *transport = &rdma_transport->transport;

		/*
		 * put_page(), if we had more than one rx_desc per page,
		 * but see comments in dtr_create_rx_desc.
		 */
		drbd_free_page(transport, rx_desc->page);
	}
	kfree(rx_desc);
}

static int dtr_create_rx_desc(struct dtr_flow *flow, gfp_t gfp_mask, bool connected_only)
{
	struct dtr_path *path = flow->path;
	struct drbd_transport *transport = path->path.transport;
	struct dtr_rx_desc *rx_desc;
	struct page *page;
	int err;
	struct dtr_cm *cm;

	rx_desc = kzalloc_obj(*rx_desc, gfp_mask);
	if (!rx_desc)
		return -ENOMEM;

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

	err = -ECONNRESET;
	cm = dtr_path_get_cm(path);
	if (!cm)
		goto out;
	if (connected_only && cm->state != DSM_CONNECTED)
		goto out_put;

	rx_desc->cm = cm;
	rx_desc->page = page;
	rx_desc->size = 0;
	rx_desc->sge.lkey = dtr_cm_to_lkey(cm);
	rx_desc->sge.addr = ib_dma_map_single(cm->id->device, page_address(page), PAGE_SIZE,
					      DMA_FROM_DEVICE);
	err = ib_dma_mapping_error(cm->id->device, rx_desc->sge.addr);
	if (err) {
		tr_err(transport, "ib_dma_map_single() failed %d\n", err);
		goto out_put;
	}
	rx_desc->sge.length = PAGE_SIZE;

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
	drbd_free_page(transport, page);
	return err;
}

static void dtr_refill_rx_descs_work_fn(struct work_struct *work)
{
	struct dtr_path *path = container_of(work, struct dtr_path, refill_rx_descs_work);
	int i;

	if (!dtr_path_ok(path))
		return;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
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
	rx_desc->size = 0;
	rx_desc->sge.lkey = dtr_cm_to_lkey(cm);
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
	struct drbd_transport *transport = &rdma_transport->transport;
	struct ib_send_wr send_wr;
	const struct ib_send_wr *send_wr_failed;
	struct ib_device *device = cm->id->device;
	unsigned long timeout;
	struct net_conf *nc;
	int i, err = -EIO;
	bool was_active;

	send_wr.next = NULL;
	tx_desc->cqe.done = dtr_tx_cqe_done;
	send_wr.wr_cqe = &tx_desc->cqe;
	send_wr.sg_list = tx_desc->sge;
	send_wr.num_sge = tx_desc->nr_sges;
	send_wr.ex.imm_data = cpu_to_be32(tx_desc->imm);
	send_wr.opcode = IB_WR_SEND_WITH_IMM;
	send_wr.send_flags = IB_SEND_SIGNALED;

	rcu_read_lock();
	nc = rcu_dereference(transport->net_conf);
	timeout = nc->ping_timeo;
	rcu_read_unlock();

	for (i = 0; i < tx_desc->nr_sges; i++)
		ib_dma_sync_single_for_device(device, tx_desc->sge[i].addr,
					      tx_desc->sge[i].length, DMA_TO_DEVICE);

	if (atomic_inc_return(&cm->tx_descs_posted) == 1)
		kref_get(&cm->kref); /* keep one extra ref as long as one tx is posted */

	kref_get(&cm->kref);
	was_active = mod_timer(&cm->tx_timeout, jiffies + timeout * HZ / 20);
	if (was_active)
		kref_put(&cm->kref, dtr_destroy_cm);

	err = ib_post_send(cm->id->qp, &send_wr, &send_wr_failed);
	if (err) {
		tr_err(&rdma_transport->transport, "ib_post_send() failed %d\n", err);
		was_active = timer_delete(&cm->tx_timeout);
		if (!was_active)
			was_active = cancel_work_sync(&cm->tx_timeout_work);
		if (was_active)
			kref_put(&cm->kref, dtr_destroy_cm);
		if (atomic_dec_and_test(&cm->tx_descs_posted))
			kref_put(&cm->kref, dtr_destroy_cm);
	}

	return err;
}

static struct dtr_cm *dtr_select_and_get_cm_for_tx(struct dtr_transport *rdma_transport,
						     enum drbd_stream stream)
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
		if (!cm || cm->state != DSM_CONNECTED)
			continue;

		/*
		 * Normal packets are not allowed to consume all of the
		 * peer's rx_descs; the last one is reserved for
		 * flow-control messages.
		 */
		if (atomic_read(&flow->tx_descs_posted) >= flow->tx_descs_max ||
		    atomic_read(&flow->peer_rx_descs) <= 1)
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
		cm = __dtr_path_get_cm(candidate);
		cm->last_sent_jif = jiffies;
	} else {
		cm = NULL;
	}
	rcu_read_unlock();

	return cm;
}

static int dtr_remap_tx_desc(struct dtr_cm *old_cm, struct dtr_cm *cm,
			      struct dtr_tx_desc *tx_desc)
{
	struct ib_device *device = old_cm->id->device;
	int i, nr_sges, err;
	dma_addr_t a = 0;

	switch (tx_desc->type) {
	case SEND_PAGE:
		ib_dma_unmap_page(device, tx_desc->sge[0].addr,
				  tx_desc->sge[0].length, DMA_TO_DEVICE);
		break;
	case SEND_MSG:
		ib_dma_unmap_single(device, tx_desc->sge[0].addr,
				    tx_desc->sge[0].length, DMA_TO_DEVICE);
		break;
	case SEND_BIO:
		nr_sges = tx_desc->nr_sges;
		for (i = 0; i < nr_sges; i++)
			ib_dma_unmap_page(device, tx_desc->sge[i].addr, tx_desc->sge[i].length,
					  DMA_TO_DEVICE);
		break;
	}

	device = cm->id->device;
	switch (tx_desc->type) {
	case SEND_PAGE:
		a = ib_dma_map_page(device, tx_desc->page, tx_desc->sge[0].addr & ~PAGE_MASK,
				    tx_desc->sge[0].length, DMA_TO_DEVICE);
		break;
	case SEND_MSG:
		a = ib_dma_map_single(device, tx_desc->data, tx_desc->sge[0].length, DMA_TO_DEVICE);
		break;
	case SEND_BIO:
		break;
	}
	err = ib_dma_mapping_error(device, a);

	tx_desc->sge[0].addr = a;
	tx_desc->sge[0].lkey = dtr_cm_to_lkey(cm);

	return err;
}


static int dtr_repost_tx_desc(struct dtr_cm *old_cm, struct dtr_tx_desc *tx_desc)
{
	struct dtr_transport *rdma_transport =
		container_of(old_cm->path->path.transport, struct dtr_transport, transport);
	enum drbd_stream stream = dtr_imm_stream(tx_desc->imm);
	struct dtr_cm *cm;
	struct dtr_flow *flow;
	int err;

	do {
		cm = dtr_select_and_get_cm_for_tx(rdma_transport, stream);
		if (!cm)
			return -ECONNRESET;

		err = dtr_remap_tx_desc(old_cm, cm, tx_desc);
		if (err) {
			tr_err(&rdma_transport->transport, "dtr_remap_tx_desc failed: %d\n", err);
			kref_put(&cm->kref, dtr_destroy_cm);
			continue;
		}

		flow = &cm->path->flow[stream];
		if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0) {
			kref_put(&cm->kref, dtr_destroy_cm);
			continue;
		}
		if (!atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max)) {
			atomic_inc(&flow->peer_rx_descs);
			kref_put(&cm->kref, dtr_destroy_cm);
			continue;
		}

		err = __dtr_post_tx_desc(cm, tx_desc);
		if (err) {
			atomic_inc(&flow->peer_rx_descs);
			atomic_dec(&flow->tx_descs_posted);
		}
		kref_put(&cm->kref, dtr_destroy_cm);
	} while (err);

	return err;
}

static int dtr_post_tx_desc(struct dtr_transport *rdma_transport,
			    struct dtr_tx_desc *tx_desc)
{
	enum drbd_stream stream = dtr_imm_stream(tx_desc->imm);
	struct dtr_stream *rdma_stream = &rdma_transport->stream[stream];
	struct ib_device *device;
	struct dtr_flow *flow;
	struct dtr_cm *cm;
	int offset, err;
	long t;

retry:
	t = wait_event_interruptible_timeout(rdma_stream->send_wq,
			(cm = dtr_select_and_get_cm_for_tx(rdma_transport, stream)),
			rdma_stream->send_timeout);

	if (t == 0) {
		struct dtr_transport *rdma_transport = rdma_stream->rdma_transport;

		if (drbd_stream_send_timed_out(&rdma_transport->transport, stream))
			return -EAGAIN;
		goto retry;
	} else if (t < 0)
		return -EINTR;

	flow = &cm->path->flow[stream];
	if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0) {
		kref_put(&cm->kref, dtr_destroy_cm);
		goto retry;
	}
	if (!atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max)) {
		atomic_inc(&flow->peer_rx_descs);
		kref_put(&cm->kref, dtr_destroy_cm);
		goto retry;
	}

	device = cm->id->device;
	switch (tx_desc->type) {
	case SEND_PAGE:
		offset = tx_desc->sge[0].lkey;
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

	err = __dtr_post_tx_desc(cm, tx_desc);
	if (err) {
		atomic_inc(&flow->peer_rx_descs);
		atomic_dec(&flow->tx_descs_posted);
		ib_dma_unmap_page(device, tx_desc->sge[0].addr,
				  tx_desc->sge[0].length, DMA_TO_DEVICE);
	}


out:
	kref_put(&cm->kref, dtr_destroy_cm);
	return err;
}

/* Reserve one send credit for an announce message: a peer rx_desc plus a tx
 * slot. Announce, like flow-control, is sent as an ST_FLOW_CTRL message that
 * borrows a DATA or CONTROL credit (rdma2 has no separate FLOW_CTRL credit pool
 * yet). Returns the borrowed stream (the announce's send_from_stream), or -1 if
 * no stream has a free credit right now.
 */
static int dtr_reserve_send_credit(struct dtr_path *path)
{
	enum drbd_stream i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		struct dtr_flow *flow = &path->flow[i];

		if (atomic_read(&flow->tx_descs_posted) >= flow->tx_descs_max)
			continue;
		if (atomic_dec_if_positive(&flow->peer_rx_descs) < 0)
			continue;
		if (atomic_inc_if_below(&flow->tx_descs_posted, flow->tx_descs_max))
			return i;
		atomic_inc(&flow->peer_rx_descs); /* undo */
	}
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

static int dtr_got_announce_buffer_msg(struct dtr_path *path, struct dtr_announce_buffer *msg)
{
	struct dtr_transport *rdma_transport =
		container_of(path->path.transport, struct dtr_transport, transport);
	struct drbd_transport *transport = &rdma_transport->transport;
	u32 len = be32_to_cpu(msg->len);
	u32 stride = be32_to_cpu(msg->stride);
	enum dtr_stream_nr stream = be32_to_cpu(msg->region_stream);
	struct dtr_region_set *rs;
	struct dtr_remote_buffer *rb;
	unsigned long flags;

	if (stream != ST_DATA && stream != ST_CONTROL) {
		if (__ratelimit(&rdma_transport->rate_limit))
			tr_err(transport, "announce for bad stream %u\n", stream);
		return be32_to_cpu(msg->send_from_stream);
	}
	rs = &path->regions[stream];

	if (len) {
		rb = kzalloc_obj(*rb, GFP_ATOMIC);
		if (!rb) {
			if (__ratelimit(&rdma_transport->rate_limit))
				tr_err(transport, "no memory for remote buffer\n");
		} else {
			rb->addr = be64_to_cpu(msg->addr);
			rb->rkey = be32_to_cpu(msg->rkey);
			rb->len = len;
			rb->stride = stride;

			spin_lock_irqsave(&rs->remote_buffers_lock, flags);
			list_add_tail(&rb->list, &rs->remote_buffers);
			spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);
		}
	}

	wake_up_interruptible(&rdma_transport->stream[stream].send_wq);

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

/* Reserve region room for one @bytes RDMA-WRITE in the peer's remote buffers
 * and report the remote address and rkey to write to. Consumption is
 * stride-granular (the region's announced stride), so neighbouring writes may
 * share a region page; the receiver reference-counts the pages accordingly.
 *
 * All-or-nothing: false if no announced buffer can take the write right now
 * (nothing consumed, no buffer abandoned) -- a partial grant cannot help the
 * single-WR caller.
 */
static bool __maybe_unused
dtr_reserve_remote_chunk(struct dtr_region_set *rs, unsigned int bytes, u64 *addr, u32 *rkey)
{
	struct dtr_remote_buffer *rb, *tmp;
	unsigned long flags;

	spin_lock_irqsave(&rs->remote_buffers_lock, flags);
	rb = __dtr_find_remote_buffer(rs, bytes);
	if (!rb) {
		spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);
		return false;
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
	*addr = rb->addr + rb->consumed;
	*rkey = rb->rkey;
	rb->consumed += dtr_chunk_size(bytes, rb->stride);
	if (rb->consumed >= rb->len) {
		list_del(&rb->list);
		kfree(rb);
	}
	spin_unlock_irqrestore(&rs->remote_buffers_lock, flags);

	return true;
}

/* Room for a @bytes write: the bytes remaining in the remote buffer it would go
 * into (see __dtr_find_remote_buffer()), and the addr/rkey there, without
 * consuming anything. Advisory only -- the authoritative consume is the atomic
 * dtr_reserve_remote_chunk(), which may race ahead of a peek, so a caller
 * acting on a peek retries. Returns 0 if no announced region can take the
 * write (pass @bytes == 1 for "any room at all").
 */
static u32 __maybe_unused
dtr_peek_remote_chunk(struct dtr_region_set *rs, unsigned int bytes, u64 *addr, u32 *rkey)
{
	struct dtr_remote_buffer *rb;
	unsigned long flags;
	u32 room = 0;

	spin_lock_irqsave(&rs->remote_buffers_lock, flags);
	rb = __dtr_find_remote_buffer(rs, bytes);
	if (rb) {
		room = rb->len - rb->consumed;
		*addr = rb->addr + rb->consumed;
		*rkey = rb->rkey;
	}
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

/* Attach a freshly allocated split-page region to @buf, (re-)register @buf->mr
 * over it for REMOTE_WRITE, and post the unsignaled IB_WR_REG_MR. The caller
 * announces the region on the same QP right after (so the announce is ordered
 * behind the REG_MR and the rkey is valid before the peer can write). The MR is
 * reused -- no ib_alloc_mr()/ib_dereg_mr() per cycle. Returns 0, or a negative
 * errno with @buf left disarmed (no pages attached).
 */
static int dtr_arm_local_buffer(struct dtr_path *path, struct dtr_local_buffer *buf,
				int max_order, u32 stride)
{
	struct drbd_transport *transport = path->path.transport;
	struct dtr_cm *cm = buf->cm;
	struct ib_device *device = cm->id->device;
	struct ib_reg_wr mr_reg_wr = {};
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

	/* ib_post_send() copies the WR, so a stack reg_wr is fine; the completion
	 * anchor (cm->reg_cqe) outlives the buffer.
	 */
	mr_reg_wr.wr.next = NULL;
	mr_reg_wr.wr.wr_cqe = &cm->reg_cqe;
	mr_reg_wr.wr.num_sge = 0;
	mr_reg_wr.wr.opcode = IB_WR_REG_MR;
	mr_reg_wr.wr.send_flags = 0; /* unsignaled, ordered before the announce */
	mr_reg_wr.mr = buf->mr;
	mr_reg_wr.key = buf->mr->rkey;
	mr_reg_wr.access = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE;

	err = ib_post_send(cm->id->qp, &mr_reg_wr.wr, NULL);
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

/* A payload of @byte_len bytes was just RDMA-written into our receive region at
 * its consume cursor. Mirror the sender's reservation
 * (dtr_reserve_remote_chunk()): the write went into the first region, in
 * announce order, whose tail could take its stride-rounded size; regions ahead
 * of it were abandoned by the sender and are retired here (the tail rule).
 * Point @rx_desc->data_page / data_offset at the payload so dtr_recv_bio() can
 * hand it up as one (multi-page) bvec, take a reference on every region page it
 * touches (neighbouring writes may share a page), and advance the cursor by the
 * same stride-rounded amount. A fully consumed region moves to the exhausted
 * list for deferred release + replacement. Runs in the rx completion softirq.
 */
static void __maybe_unused
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
			return;
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

static int _dtr_cm_alloc_rdma_res(struct dtr_cm *cm,
				    enum dtr_alloc_rdma_res_causes *cause)
{
	int err, i, rx_descs_max = 0, tx_descs_max = 0;
	struct dtr_path *path = cm->path;

	/*
	 * Each path might be the sole path, therefore it must be able
	 * to support both streams.
	 */
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
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

	/* some RDMA transports need at least one rx desc for establishing a connection */
	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++)
		dtr_create_rx_desc(&path->flow[i], GFP_NOIO, false);

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

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
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

static void dtr_disconnect_path(struct dtr_path *path)
{
	struct dtr_cm *cm;

	if (!path)
		return;

	__dtr_disconnect_path(path);
	cancel_work_sync(&path->refill_rx_descs_work);
	cancel_work_sync(&path->regions[DATA_STREAM].register_buffers_work);
	cancel_work_sync(&path->regions[CONTROL_STREAM].register_buffers_work);

	/* The peer's announced buffers refer to a connection that is gone. */
	dtr_free_remote_buffers(path);
	/* Our registered regions belong to the QP we are dropping. */
	dtr_free_local_buffers(path);

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

	init_waitqueue_head(&cs->wq);

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
	tx_desc->imm = dtr_imm_encode(stream,
				      rdma_transport->stream[stream].tx_sequence++);
	tx_desc->sge[0].length = size;
	tx_desc->sge[0].lkey = offset; /* abusing the lkey field. See dtr_post_tx_desc() */

	err = dtr_post_tx_desc(rdma_transport, tx_desc);
	if (err) {
		put_page(page);
		kfree(tx_desc);

		tr_err(transport, "dtr_post_tx_desc() failed %d\n", err);
		drbd_control_event(transport, CLOSED_BY_PEER);
	}

	if (stream == DATA_STREAM)
		dtr_update_congested(transport);

	return err;
}

static int dtr_send_bio(struct drbd_transport *transport, struct bio *bio, unsigned int msg_flags)
{
	int err = -EINVAL;
	struct bio_vec bvec;
	struct bvec_iter iter;

	if (!dtr_transport_ok(transport))
		return -ECONNRESET;

	bio_for_each_segment(bvec, bio, iter) {
		err = dtr_send_page(transport, DATA_STREAM,
			bvec.bv_page, bvec.bv_offset, bvec.bv_len, msg_flags);
		if (err)
			break;
	}

	dtr_update_congested(transport);

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

static void dtr_remove_path(struct drbd_path *del_path)
{
	struct dtr_path *path = container_of(del_path, struct dtr_path, path);

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
