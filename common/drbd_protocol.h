#ifndef __DRBD_PROTOCOL_H
#define __DRBD_PROTOCOL_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum drbd_packet {
	/* receiver (data socket) */
	P_DATA		      = 0x00,
	P_DATA_REPLY	      = 0x01, /* Response to P_DATA_REQUEST */
	P_RS_DATA_REPLY	      = 0x02, /* Response to P_RS_DATA_REQUEST */
	P_BARRIER	      = 0x03,
	P_BITMAP	      = 0x04,
	P_BECOME_SYNC_TARGET  = 0x05,
	P_BECOME_SYNC_SOURCE  = 0x06,
	P_UNPLUG_REMOTE	      = 0x07, /* Used at various times to hint the peer */
	P_DATA_REQUEST	      = 0x08, /* Used to ask for a data block */
	P_RS_DATA_REQUEST     = 0x09, /* Used to ask for a data block for resync */
	P_SYNC_PARAM	      = 0x0a,
	P_PROTOCOL	      = 0x0b,
	P_UUIDS		      = 0x0c,
	P_SIZES		      = 0x0d,
	P_STATE		      = 0x0e,
	P_SYNC_UUID	      = 0x0f,
	P_AUTH_CHALLENGE      = 0x10,
	P_AUTH_RESPONSE	      = 0x11,
	P_STATE_CHG_REQ	      = 0x12,

	/* asender (meta socket */
	P_PING		      = 0x13,
	P_PING_ACK	      = 0x14,
	P_RECV_ACK	      = 0x15, /* Used in protocol B */
	P_WRITE_ACK	      = 0x16, /* Used in protocol C */
	P_RS_WRITE_ACK	      = 0x17, /* Is a P_WRITE_ACK, additionally call set_in_sync(). */
	P_SUPERSEDED	      = 0x18, /* Used in proto C, two-primaries conflict detection */
	P_NEG_ACK	      = 0x19, /* Sent if local disk is unusable */
	P_NEG_DREPLY	      = 0x1a, /* Local disk is broken... */
	P_NEG_RS_DREPLY	      = 0x1b, /* Local disk is broken... */
	P_BARRIER_ACK	      = 0x1c,
	P_STATE_CHG_REPLY     = 0x1d,

	/* "new" commands, no longer fitting into the ordering scheme above */

	P_OV_REQUEST	      = 0x1e, /* data socket */
	P_OV_REPLY	      = 0x1f,
	P_OV_RESULT	      = 0x20, /* meta socket */
	P_CSUM_RS_REQUEST     = 0x21, /* data socket */
	P_RS_IS_IN_SYNC	      = 0x22, /* meta socket */
	P_SYNC_PARAM89	      = 0x23, /* data socket, protocol version 89 replacement for P_SYNC_PARAM */
	P_COMPRESSED_BITMAP   = 0x24, /* compressed or otherwise encoded bitmap transfer */
	/* P_CKPT_FENCE_REQ      = 0x25, * currently reserved for protocol D */
	/* P_CKPT_DISABLE_REQ    = 0x26, * currently reserved for protocol D */
	P_DELAY_PROBE         = 0x27, /* is used on BOTH sockets */
	P_OUT_OF_SYNC         = 0x28, /* Mark as out of sync (Outrunning), data socket */
	P_RS_CANCEL           = 0x29, /* meta: Used to cancel RS_DATA_REQUEST packet by SyncSource */
	P_CONN_ST_CHG_REQ     = 0x2a, /* data sock: state change request */
	P_CONN_ST_CHG_REPLY   = 0x2b, /* meta sock: state change reply */
	P_RETRY_WRITE	      = 0x2c, /* Protocol C: retry conflicting write request */
	P_PROTOCOL_UPDATE     = 0x2d, /* data sock: is used in established connections */
	P_TWOPC_PREPARE       = 0x2e, /* data sock: prepare state change */
	P_TWOPC_ABORT         = 0x2f, /* data sock: abort state change */

	P_DAGTAG	      = 0x30, /* data sock: set the current dagtag */

	/* REQ_DISCARD. We used "discard" in different contexts before,
	 * which is why I chose TRIM here, to disambiguate. */
	P_TRIM                = 0x31,

	P_PEER_ACK            = 0x40, /* meta sock: tell which nodes have acked a request */
	P_PEERS_IN_SYNC       = 0x41, /* data sock: Mark area as in sync */

	P_UUIDS110	      = 0x42, /* data socket */
	P_PEER_DAGTAG         = 0x43, /* data socket, used to trigger reconciliation resync */
	P_CURRENT_UUID	      = 0x44, /* data socket */

	P_TWOPC_YES           = 0x45, /* meta sock: allow two-phase commit */
	P_TWOPC_NO            = 0x46, /* meta sock: reject two-phase commit */
	P_TWOPC_COMMIT        = 0x47, /* data sock: commit state change */
	P_TWOPC_RETRY         = 0x48, /* meta sock: retry two-phase commit */

	P_MAY_IGNORE	      = 0x100, /* Flag to test if (cmd > P_MAY_IGNORE) ... */

	/* special command ids for handshake */

	P_INITIAL_META	      = 0xfff1, /* First Packet on the MetaSock */
	P_INITIAL_DATA	      = 0xfff2, /* First Packet on the Socket */

	P_CONNECTION_FEATURES = 0xfffe	/* FIXED for the next century! */
};

#ifndef __packed
#define __packed __attribute__((packed))
#endif

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
struct p_header80 {
	uint32_t magic;
	uint16_t command;
	uint16_t length;	/* bytes of data after this header */
} __packed;

/* Header for big packets, Used for data packets exceeding 64kB */
struct p_header95 {
	uint16_t magic;	/* use DRBD_MAGIC_BIG here */
	uint16_t command;
	uint32_t length;
} __packed;

struct p_header100 {
	uint32_t magic;
	uint16_t volume;
	uint16_t command;
	uint32_t length;
	uint32_t pad;
} __packed;

/* these defines must not be changed without changing the protocol version */
#define DP_HARDBARRIER	      1 /* no longer used */
#define DP_RW_SYNC	      2 /* equals REQ_SYNC    */
#define DP_MAY_SET_IN_SYNC    4
#define DP_UNPLUG             8 /* equals REQ_UNPLUG (compat) */
#define DP_FUA               16 /* equals REQ_FUA     */
#define DP_FLUSH             32 /* equals REQ_FLUSH   */
#define DP_DISCARD           64 /* equals REQ_DISCARD */
#define DP_SEND_RECEIVE_ACK 128 /* This is a proto B write request */
#define DP_SEND_WRITE_ACK   256 /* This is a proto C write request */

struct p_data {
	uint64_t sector;    /* 64 bits sector number */
	uint64_t block_id;  /* to identify the request in protocol B&C */
	uint32_t seq_num;
	uint32_t dp_flags;
} __packed;

struct p_trim {
	struct p_data p_data;
	uint32_t size;	/* == bio->bi_size */
} __packed;

/*
 * commands which share a struct:
 *  p_block_ack:
 *   P_RECV_ACK (proto B), P_WRITE_ACK (proto C),
 *   P_SUPERSEDED (proto C, two-primaries conflict detection)
 *  p_block_req:
 *   P_DATA_REQUEST, P_RS_DATA_REQUEST
 */
struct p_block_ack {
	uint64_t sector;
	uint64_t block_id;
	uint32_t blksize;
	uint32_t seq_num;
} __packed;

struct p_block_req {
	uint64_t sector;
	uint64_t block_id;
	uint32_t blksize;
	uint32_t pad;	/* to multiple of 8 Byte */
} __packed;

/*
 * commands with their own struct for additional fields:
 *   P_CONNECTION_FEATURES
 *   P_BARRIER
 *   P_BARRIER_ACK
 *   P_SYNC_PARAM
 *   ReportParams
 */

#define FF_TRIM      1

struct p_connection_features {
	uint32_t protocol_min;
	uint32_t feature_flags;
	uint32_t protocol_max;
	uint32_t sender_node_id;
	uint32_t receiver_node_id;

	/* should be more than enough for future enhancements
	 * for now, feature_flags and the reserved array shall be zero.
	 */

	uint32_t _pad;
	uint64_t reserved[6];
} __packed;

struct p_barrier {
	uint32_t barrier;	/* barrier number _handle_ only */
	uint32_t pad;	/* to multiple of 8 Byte */
} __packed;

struct p_barrier_ack {
	uint32_t barrier;
	uint32_t set_size;
} __packed;

struct p_rs_param {
	uint32_t resync_rate;

	      /* Since protocol version 88 and higher. */
	char verify_alg[0];
} __packed;

struct p_rs_param_89 {
	uint32_t resync_rate;
        /* protocol version 89: */
	char verify_alg[SHARED_SECRET_MAX];
	char csums_alg[SHARED_SECRET_MAX];
} __packed;

struct p_rs_param_95 {
	uint32_t resync_rate;
	char verify_alg[SHARED_SECRET_MAX];
	char csums_alg[SHARED_SECRET_MAX];
	uint32_t c_plan_ahead;
	uint32_t c_delay_target;
	uint32_t c_fill_target;
	uint32_t c_max_rate;
} __packed;

enum drbd_conn_flags {
	CF_DISCARD_MY_DATA = 1,
	CF_DRY_RUN = 2,
};

struct p_protocol {
	uint32_t protocol;
	uint32_t after_sb_0p;
	uint32_t after_sb_1p;
	uint32_t after_sb_2p;
	uint32_t conn_flags;
	uint32_t two_primaries;

              /* Since protocol version 87 and higher. */
	char integrity_alg[0];

} __packed;

#define UUID_FLAG_DISCARD_MY_DATA 1
#define UUID_FLAG_CRASHED_PRIMARY 2
#define UUID_FLAG_INCONSISTENT 4
#define UUID_FLAG_SKIP_INITIAL_SYNC 8
#define UUID_FLAG_NEW_DATAGEN 16
#define UUID_FLAG_STABLE 32
#define UUID_FLAG_GOT_STABLE 64 /* send UUIDs */
#define UUID_FLAG_RESYNC 128    /* compare UUIDs and eventually start resync */

struct p_uuids {
	uint64_t current_uuid;
	uint64_t bitmap_uuid;
	uint64_t history_uuids[HISTORY_UUIDS_V08];
	uint64_t dirty_bits;
	uint64_t uuid_flags;
} __packed;

struct p_uuids110 {
	uint64_t current_uuid;
	uint64_t dirty_bits;
	uint64_t uuid_flags;
	uint64_t weak_nodes;
	uint64_t bitmap_uuids_mask; /* non zero bitmap UUIDS for these nodes */
	uint64_t other_uuids[0]; /* the first hweight(bitmap_uuids_mask) slots carry bitmap uuids.
				    The node with the lowest node_id first.
				    The remaining slots carry history uuids */
} __packed;

struct p_uuid {
	uint64_t	    uuid;
} __packed;

struct p_sizes {
	uint64_t d_size;  /* size of disk */
	uint64_t u_size;  /* user requested size */
	uint64_t c_size;  /* current exported size */
	uint32_t max_bio_size;  /* Maximal size of a BIO */
	uint16_t queue_order_type;  /* not yet implemented in DRBD*/
	uint16_t dds_flags; /* use enum dds_flags here. */
} __packed;

struct p_state {
	uint32_t state;
} __packed;

struct p_req_state {
	uint32_t mask;
	uint32_t val;
} __packed;

struct p_req_state_reply {
	uint32_t retcode;
} __packed;

struct p_twopc_request {
	uint32_t tid;  /* transaction identifier */
	uint32_t initiator_node_id;  /* initiator of the transaction */
	uint32_t target_node_id;  /* target of the transaction (or -1) */
	uint64_t nodes_to_reach;
	uint64_t primary_nodes;
	uint32_t mask;
	uint32_t val;
} __packed;

struct p_twopc_reply {
	uint32_t tid;  /* transaction identifier */
	uint32_t initiator_node_id;  /* initiator of the transaction */
	uint64_t reachable_nodes;
	uint64_t primary_nodes;
	uint64_t weak_nodes;
} __packed;

struct p_drbd06_param {
	uint64_t size;
	uint32_t state;
	uint32_t blksize;
	uint32_t protocol;
	uint32_t version;
	uint32_t gen_cnt[5];
	uint32_t bit_map_gen[5];
} __packed;

struct p_block_desc {
	uint64_t sector;
	uint32_t blksize;
	uint32_t pad;	/* to multiple of 8 Byte */
} __packed;

/* Valid values for the encoding field.
 * Bump proto version when changing this. */
enum drbd_bitmap_code {
	/* RLE_VLI_Bytes = 0,
	 * and other bit variants had been defined during
	 * algorithm evaluation. */
	RLE_VLI_Bits = 2,
};

struct p_compressed_bm {
	/* (encoding & 0x0f): actual encoding, see enum drbd_bitmap_code
	 * (encoding & 0x80): polarity (set/unset) of first runlength
	 * ((encoding >> 4) & 0x07): pad_bits, number of trailing zero bits
	 * used to pad up to head.length bytes
	 */
	uint8_t encoding;

	uint8_t code[0];
} __packed;

struct p_delay_probe93 {
	uint32_t seq_num; /* sequence number to match the two probe packets */
	uint32_t offset;  /* usecs the probe got sent after the reference time point */
} __packed;

struct p_dagtag {
	uint64_t dagtag;
} __packed;

struct p_peer_ack {
	uint64_t mask;
	uint64_t dagtag;
} __packed;

struct p_peer_block_desc {
	uint64_t sector;
	uint64_t mask;
	uint32_t size;
	uint32_t pad;	/* to multiple of 8 Byte */
} __packed;

struct p_peer_dagtag {
	uint64_t dagtag;
	uint32_t node_id;
} __packed;

/*
 * Bitmap packets need to fit within a single page on the sender and receiver,
 * so we are limited to 4 KiB (and not to PAGE_SIZE, which can be bigger).
 */
#define DRBD_SOCKET_BUFFER_SIZE 4096

#endif  /* __DRBD_PROTOCOL_H */
