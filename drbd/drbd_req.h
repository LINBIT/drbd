/*
   drbd_req.h
   Kernel module for 2.6.x Kernels

   This file is part of DRBD

   Copyright (C) 2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2006, LINBIT Information Technologies GmbH.

   DRBD is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   DRBD is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _DRBD_REQ_H
#define _DRBD_REQ_H

#include <linux/autoconf.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/drbd.h>
#include "drbd_int.h"

/* The request callbacks will be called in irq context by the IDE drivers,
   and in Softirqs/Tasklets/BH context by the SCSI drivers,
   and by the receiver and worker in kernel-thread context.
   Try to get the locking right :) */

/*
 * Objects of type drbd_request_t do only exist on a Primary node, and are
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
 *    FIXME I believe that for consistency we should place even READ requests
 *    on these lists, so we can moan when we detect that the other node is
 *    writing to an area that we currently read from (when this happens, our
 *    users are broken).
 *
 *  It may be identified as a concurrent (write) request
 *    and be handled accordingly.
 *
 *  It may me handed over to the local disk subsystem.
 *  It may be completed by the local disk subsystem,
 *    either sucessfully or with io-error.
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
 *
 * See also documentation/drbd-request-state-overview.dot
 *  (dot -Tps2 documentation/drbd-request-state-overview.dot | display -)
 */

typedef enum {
	created,
	to_be_send,
	to_be_submitted,

	/* XXX yes, now I am inconsistent...
	 * these two are not "events" but "actions"
	 * oh, well... */
	queue_for_net_write,
	queue_for_net_read,

	send_canceled,
	send_failed,
	handed_over_to_network,
	connection_lost_while_pending,
	recv_acked_by_peer,
	write_acked_by_peer,
	write_acked_by_peer_and_sis, // and set_in_sync
	conflict_discarded_by_peer,
	neg_acked,
	barrier_acked, /* in protocol A and B */
	data_received, /* (remote read) */

	read_completed_with_error,
	write_completed_with_error,
	completed_ok,
} drbd_req_event_t;

/* encoding of request states for now.  we don't actually need that many bits.
 * we don't need to do atomic bit operations either, since most of the time we
 * need to look at the connection state and/or manipulate some lists at the
 * same time, so we should hold the request lock anyways.
 */
enum drbd_req_state_bits {
	/* 210
	 * 000: no local possible
	 * 001: to be submitted
	 *    UNUSED, we could map: 011: submitted, completion still pending
	 * 110: completed ok
	 * 010: completed with error
	 */
	__RQ_LOCAL_PENDING,
	__RQ_LOCAL_COMPLETED,
	__RQ_LOCAL_OK,

	/* 76543
	 * 00000: no network possible
	 * 00001: to be send
	 * 00011: to be send, on worker queue
	 * 00101: sent, expecting recv_ack (B) or write_ack (C)
	 * 11101: sent,
	 *        recv_ack (B) or implicit "ack" (A),
	 *        still waiting for the barrier ack.
	 *        master_bio may already be completed and invalidated.
	 * 11100: write_acked (C),
	 *        data_received (for remote read, any protocol)
	 *        or finally the barrier ack has arrived (B,A)...
	 *        request can be freed
	 * 01100: neg-acked (write, protocol C)
	 *        or neg-d-acked (read, any protocol)
	 *        or killed from the transfer log
	 *        during cleanup after connection loss
	 *        request can be freed
	 * 01000: canceled or send failed...
	 *        request can be freed
	 */

	/* if "SENT" is not set, yet, this can still fail or be canceled.
	 * if "SENT" is set already, we still wait for an Ack packet.
	 * when cleared, the master_bio may be completed.
	 * in (B,A) the request object may still linger on the transaction log
	 * until the corresponding barrier ack comes in */
	__RQ_NET_PENDING,

	/* If it is QUEUED, and it is a WRITE, it is also registered in the
	 * transfer log. Currently we need this flag to avoid conflicts between
	 * worker canceling the request and tl_clear_barrier killing it from
	 * transfer log.  We should restructure the code so this conflict does
	 * no longer occur. */
	__RQ_NET_QUEUED,

	/* well, actually only "handed over to the network stack" */
	__RQ_NET_SENT,

	/* when set, the request may be freed.
	 * in (C) this happens when WriteAck is received,
	 * in (B,A) when the corresponding BarrierAck is received */
	__RQ_NET_DONE,

	/* whether or not we know (C) or pretend (B,A) that the write
	 * was successfully written on the peer.
	 */
	__RQ_NET_OK,
	
	/* peer called drbd_set_in_sync() for this write */
	__RQ_NET_SIS,
};

#define RQ_LOCAL_PENDING   (1UL << __RQ_LOCAL_PENDING)
#define RQ_LOCAL_COMPLETED (1UL << __RQ_LOCAL_COMPLETED)
#define RQ_LOCAL_OK        (1UL << __RQ_LOCAL_OK)

#define RQ_LOCAL_MASK      ((RQ_LOCAL_OK << 1)-1) /* 0x07 */

#define RQ_NET_PENDING     (1UL << __RQ_NET_PENDING)
#define RQ_NET_QUEUED      (1UL << __RQ_NET_QUEUED)
#define RQ_NET_SENT        (1UL << __RQ_NET_SENT)
#define RQ_NET_DONE        (1UL << __RQ_NET_DONE)
#define RQ_NET_OK          (1UL << __RQ_NET_OK)
#define RQ_NET_SIS         (1UL << __RQ_NET_SIS)

#define RQ_NET_MASK        (((RQ_NET_OK << 1)-1) & ~RQ_LOCAL_MASK) /* 0xf8 */

/* epoch entries */
static inline struct hlist_head* ee_hash_slot(drbd_dev *mdev, sector_t sector)
{
	BUG_ON(mdev->ee_hash_s == 0);
	return mdev->ee_hash + ((unsigned int)(sector>>HT_SHIFT) % mdev->ee_hash_s);
}

/* transfer log (drbd_request objects) */
static inline struct hlist_head* tl_hash_slot(drbd_dev *mdev, sector_t sector)
{
	BUG_ON(mdev->tl_hash_s == 0);
	return mdev->tl_hash +
		((unsigned int)(sector>>HT_SHIFT) % mdev->tl_hash_s);
}

/* when we receive the answer for a read request,
 * verify that we actually know about it */
static inline drbd_request_t* _ack_id_to_req(drbd_dev *mdev,u64 id, sector_t sector)
{
	struct hlist_head *slot = tl_hash_slot(mdev,sector);
	struct hlist_node *n;
	drbd_request_t * req;

	hlist_for_each_entry(req, n, slot, colision) {
		if ((unsigned long)req == (unsigned long)id) {
			if (req->sector != sector) {
				ERR("_ack_id_to_req: found req %p but it has "
				    "wrong sector (%llus versus %llus)\n", req,
				    (unsigned long long)req->sector,
				    (unsigned long long)sector);
				break;
			}
			return req;
		}
	}
	ERR("_ack_id_to_req: failed to find req %p, sector %llus in list\n", 
		(void*)(unsigned long)id, (unsigned long long)sector);
	return NULL;
}

/* application reads (drbd_request objects) */
static struct hlist_head* ar_hash_slot(drbd_dev *mdev, sector_t sector)
{
	return mdev->app_reads_hash
		+ ((unsigned int)(sector) % APP_R_HSIZE);
}

/* when we receive the answer for a read request,
 * verify that we actually know about it */
static inline drbd_request_t* _ar_id_to_req(drbd_dev *mdev,u64 id, sector_t sector)
{
	struct hlist_head *slot = ar_hash_slot(mdev,sector);
	struct hlist_node *n;
	drbd_request_t * req;

	hlist_for_each_entry(req, n, slot, colision) {
		if ((unsigned long)req == (unsigned long)id) {
			D_ASSERT(req->sector == sector);
			return req;
		}
	}
	return NULL;
}

static inline drbd_request_t* drbd_req_new(drbd_dev *mdev, struct bio *bio_src)
{
	struct bio *bio;
	drbd_request_t *req = mempool_alloc(drbd_request_mempool, GFP_NOIO);
	if (likely(req)) {
		bio = bio_clone(bio_src, GFP_NOIO); /* XXX cannot fail?? */

		req->rq_state    = 0;
		req->mdev        = mdev;
		req->master_bio  = bio_src;
		req->private_bio = bio;
		req->epoch       = 0;
		req->sector      = bio->bi_sector;
		req->size        = bio->bi_size;
		INIT_HLIST_NODE(&req->colision);
		INIT_LIST_HEAD(&req->tl_requests);

		bio->bi_private  = req;
		bio->bi_end_io   = drbd_endio_pri;
		bio->bi_next    = 0;
	}
	return req;
}

static inline void drbd_req_free(drbd_request_t *req)
{
	mempool_free(req,drbd_request_mempool);
}

static inline int overlaps(sector_t s1, int l1, sector_t s2, int l2)
{
	return !( ( s1 + (l1>>9) <= s2 ) || ( s1 >= s2 + (l2>>9) ) );
}

/* aparently too large to be inlined...
 * moved to drbd_req.c */
extern void _req_may_be_done(drbd_request_t *req, int error);
extern void _req_mod(drbd_request_t *req, drbd_req_event_t what, int error);

/* If you need it irqsave, do it your self! */
static inline void req_mod(drbd_request_t *req, drbd_req_event_t what, int error)
{
	drbd_dev *mdev = req->mdev;
	spin_lock_irq(&mdev->req_lock);
	_req_mod(req,what,error);
	spin_unlock_irq(&mdev->req_lock);
}
#endif
