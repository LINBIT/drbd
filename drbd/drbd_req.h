/* SPDX-License-Identifier: GPL-2.0-only */
/*
   drbd_req.h

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2006-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2006-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2006-2008, Philipp Reisner <philipp.reisner@linbit.com>.

 */

#ifndef _DRBD_REQ_H
#define _DRBD_REQ_H

#include <linux/module.h>

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"

/* The request callbacks will be called in irq context by the IDE drivers,
   and in Softirqs/Tasklets/BH context by the SCSI drivers,
   and by the receiver and worker in kernel-thread context.
   Try to get the locking right :) */

/*
 * Objects of type struct drbd_request do only exist on a R_PRIMARY node, and are
 * associated with IO requests originating from the block layer above us.
 *
 * There are quite a few things that may happen to a drbd request
 * during its lifetime.
 *
 *  It will be created.
 *  It will be marked with the intention to be
 *    submitted to local disk and/or
 *    send via the network.
 *
 *  It has to be placed on the transfer log and other housekeeping lists,
 *  In case we have a network connection.
 *
 *  It may be identified as a concurrent (write) request
 *    and be handled accordingly.
 *
 *  It may me handed over to the local disk subsystem.
 *  It may be completed by the local disk subsystem,
 *    either successfully or with io-error.
 *  In case it is a READ request, and it failed locally,
 *    it may be retried remotely.
 *
 *  It may be queued for sending.
 *  It may be handed over to the network stack,
 *    which may fail.
 *  It may be acknowledged by the "peer" according to the wire_protocol in use.
 *    this may be a negative ack.
 *  It may receive a faked ack when the network connection is lost and the
 *  transfer log is cleaned up.
 *  Sending may be canceled due to network connection loss.
 *  When it finally has outlived its time,
 *    corresponding dirty bits in the resync-bitmap may be cleared or set,
 *    it will be destroyed,
 *    and completion will be signalled to the originator,
 *      with or without "success".
 */

enum drbd_req_event {
	TO_BE_SUBMITTED,

	NEW_NET_READ,
	NEW_NET_WRITE,
	NEW_NET_OOS,
	READY_FOR_NET,

	/* For an empty flush, mark that a corresponding barrier has been sent
	 * to this peer. This causes it to complete "successfully", even if the
	 * local disk flush failed.
	 *
	 * Just like "real" requests, empty flushes (blkdev_issue_flush()) will
	 * only see an error if neither local nor remote data is reachable. */
	BARRIER_SENT,

	SEND_CANCELED,
	SEND_FAILED,
	HANDED_OVER_TO_NETWORK,
	OOS_HANDED_TO_NETWORK,
	CONNECTION_LOST,
	CONNECTION_LOST_WHILE_SUSPENDED,
	RECV_ACKED_BY_PEER,
	WRITE_ACKED_BY_PEER,
	WRITE_ACKED_BY_PEER_AND_SIS, /* and set_in_sync */
	NEG_ACKED,
	BARRIER_ACKED, /* in protocol A and B */
	DATA_RECEIVED, /* (remote read) */

	COMPLETED_OK,
	READ_COMPLETED_WITH_ERROR,
	READ_AHEAD_COMPLETED_WITH_ERROR,
	WRITE_COMPLETED_WITH_ERROR,
	DISCARD_COMPLETED_NOTSUPP,
	DISCARD_COMPLETED_WITH_ERROR,

	ABORT_DISK_IO,
	RESEND,
	CANCEL_SUSPENDED_IO,
	COMPLETION_RESUMED,
	NOTHING,
};

/*
 * Encoding of request states. Modifications are protected by rq_lock. We don't
 * do atomic bit operations.
 */
enum drbd_req_state_bits {
	/*
	 * Here are the possible combinations of the core net flags pending, pending-oos,
	 * queued, ready, sent, done, ok.
	 *
	 * <none>:
	 *   No network required, or not yet processed.
	 * pending,queued:
	 *   To be sent, must not be processed yet.
	 * pending,queued,ready:
	 *   To be sent, processing allowed.
	 * pending,ready,sent:
	 *   Sent, expecting P_RECV_ACK (B) or P_WRITE_ACK (C).
	 * queued,ready,ok:
	 *   P_RECV_ACK (B) or P_WRITE_ACK (C) received before request marked
	 *   as having been sent.
	 * ready,sent,ok:
	 *   Sent, implicit "ack" (A), P_RECV_ACK (B) or P_WRITE_ACK (C) received.
	 *   Still waiting for the barrier ack.
	 *   master_bio may already be completed and invalidated.
	 * pending:
	 *   Intended for this peer, but connection lost before processing
	 *   allowed.
	 * pending,ready:
	 *   Intended for this peer, but connection lost. If
	 *   IO is suspended, it will stay in this state until the connection
	 *   is restored or IO is resumed.
	 * ready,sent,done,ok:
	 *   Data received (for remote read, any protocol),
	 *   or finally the barrier ack has arrived.
	 * ready,sent,done:
	 *   Received P_NEG_ACK for write (protocol C, or we are SyncSource),
	 *   or P_NEG_DREPLY for read (any protocol).
	 *   Or cleaned up after connection loss after send.
	 * pending-oos,queued,done:
	 *   P_OUT_OF_SYNC to be sent, must not be processed yet.
	 * pending-oos,queued,ready,done:
	 *   P_OUT_OF_SYNC to be sent, processing allowed.
	 * done:
	 *   P_OUT_OF_SYNC was intended, but connection lost before processing
	 *   allowed.
	 * ready,done:
	 *   P_OUT_OF_SYNC sent.
	 *   Or cleaned up after connection loss, either before send or when
	 *   only P_OUT_OF_SYNC was intended.
	 */

	/* Pending some network interaction towards the peer apart from
	 * barriers or P_OUT_OF_SYNC.
	 * If "sent" is not yet set, this can still fail or be canceled.
	 * While set, the master_bio may not be completed. */
	__RQ_NET_PENDING,

	/* Pending send of P_OUT_OF_SYNC */
	__RQ_NET_PENDING_OOS,

	/* The sender might store pointers to it */
	__RQ_NET_QUEUED,

	/* Ready for processing by the sender */
	__RQ_NET_READY,

	/* Well, actually only "handed over to the network stack". */
	__RQ_NET_SENT,

	/* When set, the data stage is done, as far as interaction with this
	 * peer is concerned. Basically this means the corresponding
	 * P_BARRIER_ACK was received. */
	__RQ_NET_DONE,

	/* Set when the request was successful. That is, the corresponding
	 * condition is fulfilled:
	 * - The write was sent (A)
	 * - Receipt of the write was acknowledged (B)
	 * - The write was successfully written on the peer (C)
	 * - Read data was received
	 */
	__RQ_NET_OK,

	/* peer called drbd_set_in_sync() for this write */
	__RQ_NET_SIS,

	/* keep this last, its for the RQ_NET_MASK */
	__RQ_NET_MAX,

	/* We expect a receive ACK (wire proto B) */
	__RQ_EXP_RECEIVE_ACK,

	/* We expect a write ACK (wite proto C) */
	__RQ_EXP_WRITE_ACK,

	/* waiting for a barrier ack, did an extra kref_get */
	__RQ_EXP_BARR_ACK,

	/* 4321
	 * 0000: no local possible
	 * 0001: to be submitted
	 *    UNUSED, we could map: 011: submitted, completion still pending
	 * 0110: completed ok
	 * 0010: completed with error
	 * 1001: Aborted (before completion)
	 * 1x10: Aborted and completed -> free
	 */
	__RQ_LOCAL_PENDING,
	__RQ_LOCAL_COMPLETED,
	__RQ_LOCAL_OK,
	__RQ_LOCAL_ABORTED,

	/* Set when this is a write, clear for a read */
	__RQ_WRITE,
	__RQ_WSAME,
	__RQ_UNMAP,
	__RQ_ZEROES,

	/* Should call drbd_al_complete_io() for this request... */
	__RQ_IN_ACT_LOG,

	/* This was the most recent request during some blk_finish_plug()
	 * or its implicit from-schedule equivalent.
	 * We may use it as hint to send a P_UNPLUG_REMOTE */
	__RQ_UNPLUG,

	/* The peer has sent a retry ACK */
	__RQ_POSTPONED,

	/* would have been completed,
	 * but was not, because of drbd_suspended() */
	__RQ_COMPLETION_SUSP,
};
#define RQ_NET_PENDING     (1UL << __RQ_NET_PENDING)
#define RQ_NET_PENDING_OOS (1UL << __RQ_NET_PENDING_OOS)
#define RQ_NET_QUEUED      (1UL << __RQ_NET_QUEUED)
#define RQ_NET_READY       (1UL << __RQ_NET_READY)
#define RQ_NET_SENT        (1UL << __RQ_NET_SENT)
#define RQ_NET_DONE        (1UL << __RQ_NET_DONE)
#define RQ_NET_OK          (1UL << __RQ_NET_OK)
#define RQ_NET_SIS         (1UL << __RQ_NET_SIS)

#define RQ_NET_MASK        (((1UL << __RQ_NET_MAX)-1) & ~RQ_LOCAL_MASK)

#define RQ_EXP_RECEIVE_ACK (1UL << __RQ_EXP_RECEIVE_ACK)
#define RQ_EXP_WRITE_ACK   (1UL << __RQ_EXP_WRITE_ACK)
#define RQ_EXP_BARR_ACK    (1UL << __RQ_EXP_BARR_ACK)

#define RQ_LOCAL_PENDING   (1UL << __RQ_LOCAL_PENDING)
#define RQ_LOCAL_COMPLETED (1UL << __RQ_LOCAL_COMPLETED)
#define RQ_LOCAL_OK        (1UL << __RQ_LOCAL_OK)
#define RQ_LOCAL_ABORTED   (1UL << __RQ_LOCAL_ABORTED)

#define RQ_LOCAL_MASK      \
	(RQ_LOCAL_ABORTED | RQ_LOCAL_OK | RQ_LOCAL_COMPLETED | RQ_LOCAL_PENDING)

#define RQ_WRITE           (1UL << __RQ_WRITE)
#define RQ_WSAME           (1UL << __RQ_WSAME)
#define RQ_UNMAP           (1UL << __RQ_UNMAP)
#define RQ_ZEROES          (1UL << __RQ_ZEROES)
#define RQ_IN_ACT_LOG      (1UL << __RQ_IN_ACT_LOG)
#define RQ_UNPLUG          (1UL << __RQ_UNPLUG)
#define RQ_POSTPONED	   (1UL << __RQ_POSTPONED)
#define RQ_COMPLETION_SUSP (1UL << __RQ_COMPLETION_SUSP)


/* these flags go into local_rq_state,
 * orhter flags go into their respective net_rq_state[idx] */
#define RQ_STATE_0_MASK	\
	(RQ_LOCAL_MASK  |\
	 RQ_WRITE       |\
	 RQ_WSAME       |\
	 RQ_UNMAP       |\
	 RQ_ZEROES      |\
	 RQ_IN_ACT_LOG  |\
	 RQ_UNPLUG      |\
	 RQ_POSTPONED   |\
	 RQ_COMPLETION_SUSP)

static inline bool drbd_req_is_write(struct drbd_request *req)
{
	return req->local_rq_state & RQ_WRITE;
}

/* Short lived temporary struct on the stack.
 * We could squirrel the error to be returned into
 * bio->bi_iter.bi_size, or similar. But that would be too ugly. */
struct bio_and_error {
	struct bio *bio;
	int error;
};

bool start_new_tl_epoch(struct drbd_resource *resource);
void drbd_req_destroy(struct kref *kref);
void __req_mod(struct drbd_request *req, enum drbd_req_event what,
	       struct drbd_peer_device *peer_device, struct bio_and_error *m);
void complete_master_bio(struct drbd_device *device, struct bio_and_error *m);
void drbd_release_conflicts(struct drbd_device *device,
			    struct drbd_interval *release_interval);
void drbd_put_ref_tl_walk(struct drbd_request *req, int done_put, int oos_send_put);
void drbd_set_pending_out_of_sync(struct drbd_peer_device *peer_device);
void request_timer_fn(struct timer_list *t);
void tl_walk(struct drbd_connection *connection,
	     struct drbd_request **from_req, enum drbd_req_event what);
void __tl_walk(struct drbd_resource * const resource,
	       struct drbd_connection * const connection,
	       struct drbd_request **from_req, const enum drbd_req_event what);
void drbd_destroy_peer_ack_if_done(struct drbd_peer_ack *peer_ack);
int w_queue_peer_ack(struct drbd_work *w, int cancel);
void drbd_queue_peer_ack(struct drbd_resource *resource,
			 struct drbd_request *req);
bool drbd_should_do_remote(struct drbd_peer_device *peer_device,
			   enum which_state which);
void drbd_reclaim_req(struct rcu_head *rp);

/* this is in drbd_main.c */
void drbd_restart_request(struct drbd_request *req);
void drbd_restart_suspended_reqs(struct drbd_resource *resource);

/* use this if you don't want to deal with calling complete_master_bio()
 * outside the spinlock, e.g. when walking some list on cleanup. */
static inline void _req_mod(struct drbd_request *req, enum drbd_req_event what,
		struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = req->device;
	struct bio_and_error m;

	/* __req_mod possibly frees req, do not touch req after that! */
	__req_mod(req, what, peer_device, &m);
	if (m.bio)
		complete_master_bio(device, &m);
}

/* completion of master bio is outside of spinlock.
 * If you need it irqsave, do it your self!
 * Which means: don't use from bio endio callback. */
static inline void req_mod(struct drbd_request *req,
		enum drbd_req_event what,
		struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = req->device;
	struct bio_and_error m;

	read_lock_irq(&device->resource->state_rwlock);
	__req_mod(req, what, peer_device, &m);
	read_unlock_irq(&device->resource->state_rwlock);

	if (m.bio)
		complete_master_bio(device, &m);
}

#endif
