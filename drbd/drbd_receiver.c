/*
-*- linux-c -*-
   drbd_receiver.c
   Kernel module for 2.6.x Kernels

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2007, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2007, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2007, Lars Ellenberg <lars.ellenberg@linbit.com>.

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


#include <linux/autoconf.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <net/sock.h>

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/drbd_config.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/pkt_sched.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/random.h>
#include <linux/drbd.h>
#include "drbd_int.h"
#include "drbd_req.h"

#if defined(__arch_um__) && !defined(HAVE_UML_TO_VIRT)
static inline void *to_virt(unsigned long phys)
{
	return((void *) uml_physmem + phys);
}
#endif

#ifdef DBG_ASSERTS
void drbd_assert_breakpoint(drbd_dev *mdev, char *exp,
			    char *file, int line)
{
	ERR("ASSERT( %s ) in %s:%d\n", exp, file, line);
}
#endif


#if 0
#define CHECK_LIST_LIMIT 1000
void check_list(drbd_dev *mdev,struct list_head *list,char *t)
{
	struct list_head *le,*la;
	int forward=0,backward=0;

	le=list;
	do {
		la=le;
		le=le->next;
		if( le->prev != la ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: %s list fucked.\n",
			       mdev_to_minor(mdev),t);
			break;
		}
		if( forward++ > CHECK_LIST_LIMIT ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: %s forward > 1000\n",
			       mdev_to_minor(mdev),t);
			break;
		}
	} while(le != list);

	le=list;
	do {
		la=le;
		le=le->prev;
		if( le->next != la ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: %s list fucked.\n",
			       mdev_to_minor(mdev),t);
			break;
		}
		if( backward++ > CHECK_LIST_LIMIT ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: %s backward > 1000\n",
			       mdev_to_minor(mdev),t);
			break;
		}
	} while(le != list);

	if(forward != backward) {
		printk(KERN_ERR DEVICE_NAME "%d: forward=%d, backward=%d\n",
		       mdev_to_minor(mdev),forward,backward);
	}
}
#endif

#define GFP_TRY	( __GFP_HIGHMEM | __GFP_NOWARN )

/**
 * drbd_bp_alloc: Returns a page. Fails only if a signal comes in.
 */
STATIC struct page * drbd_pp_alloc(drbd_dev *mdev, unsigned int gfp_mask)
{
	unsigned long flags=0;
	struct page *page;
	DEFINE_WAIT(wait);

	/* FIXME Add some usefull watermark again to "kick_lo", if pages get
	 * used up too quickly. The watermark that had been in place here did
	 * not make sense.
	 */

	spin_lock_irqsave(&drbd_pp_lock,flags);
	/* This lock needs to lock out irq because we might call drbd_pp_free()
	   from IRQ context.
	   FIXME but why irq _save_ ?
	   this is only called from drbd_alloc_ee,
	   and that is strictly process context! */
	if ( (page = drbd_pp_pool) ) {
		drbd_pp_pool = (struct page*)page_private(page);
		set_page_private(page, 0); /* just to be polite */
		drbd_pp_vacant--;
	}
	spin_unlock_irqrestore(&drbd_pp_lock,flags);
	if (page) goto got_page;

	drbd_kick_lo(mdev);

	for (;;) {
		prepare_to_wait(&drbd_pp_wait, &wait, TASK_INTERRUPTIBLE);

		/* try the pool again, maybe the drbd_kick_lo set some free */
		spin_lock_irqsave(&drbd_pp_lock,flags);
		if ( (page = drbd_pp_pool) ) {
			drbd_pp_pool = (struct page*)page_private(page);
			drbd_pp_vacant--;
		}
		spin_unlock_irqrestore(&drbd_pp_lock,flags);

		if (page) break;

		/* hm. pool was empty. try to allocate from kernel.
		 * don't wait, if none is available, though.
		 */
		if ( atomic_read(&mdev->pp_in_use) < mdev->net_conf->max_buffers ) {
			if( (page = alloc_page(GFP_TRY)) )
				break;
		}

		/* doh. still no page.
		 * either used up the configured maximum number,
		 * or we are low on memory.
		 * wait for someone to return a page into the pool.
		 * unless, of course, someone signalled us.
		 */
		if (signal_pending(current)) {
			WARN("drbd_pp_alloc interrupted!\n");
			finish_wait(&drbd_pp_wait, &wait);
			return NULL;
		}
		drbd_kick_lo(mdev);
		schedule();
	}
	finish_wait(&drbd_pp_wait, &wait);

 got_page:
	atomic_inc(&mdev->pp_in_use);
	return page;
}

STATIC void drbd_pp_free(drbd_dev *mdev,struct page *page)
{
	unsigned long flags=0;
	int free_it;

	spin_lock_irqsave(&drbd_pp_lock,flags);
	if (drbd_pp_vacant > (DRBD_MAX_SEGMENT_SIZE/PAGE_SIZE)*minor_count) {
		free_it = 1;
	} else {
		set_page_private(page, (unsigned long)drbd_pp_pool);
		drbd_pp_pool = page;
		drbd_pp_vacant++;
		free_it = 0;
	}
	spin_unlock_irqrestore(&drbd_pp_lock,flags);

	atomic_dec(&mdev->pp_in_use);

	if(free_it) __free_page(page);

	/*
	 * FIXME
	 * typically there are no waiters.
	 * we should try to avoid any unnecessary call to wake_up.
	 */
	wake_up(&drbd_pp_wait);
}

/*
You need to hold the req_lock:
 drbd_free_ee()
 _drbd_wait_ee_list_empty()

You must not have the req_lock:
 drbd_alloc_ee()
 drbd_init_ee()
 drbd_release_ee()
 drbd_ee_fix_bhs()
 drbd_process_done_ee()
 drbd_clear_done_ee()
 drbd_wait_ee_list_empty()
*/

struct Tl_epoch_entry* drbd_alloc_ee(drbd_dev *mdev,
				     u64 id,
				     sector_t sector,
				     unsigned int data_size,
				     unsigned int gfp_mask)
{
	struct request_queue *q;
	struct Tl_epoch_entry* e;
	struct bio_vec *bvec;
	struct page *page;
	struct bio *bio;
	unsigned int ds;
	int i;

	e = mempool_alloc(drbd_ee_mempool, gfp_mask);
	if (!e) {
		ERR("alloc_ee: Allocation of an EE failed\n");
		return NULL;
	}

	bio = bio_alloc(GFP_KERNEL, div_ceil(data_size,PAGE_SIZE));
	if (!bio) {
		ERR("alloc_ee: Allocation of a bio failed\n");
		goto fail1;
	}

	bio->bi_bdev = mdev->bc->backing_bdev;
	bio->bi_sector = sector;

	ds = data_size;
	while(ds) {
		page = drbd_pp_alloc(mdev, gfp_mask);
		if (!page) {
			ERR("alloc_ee: Allocation of a page failed\n");
			goto fail2;
		}
		if (!bio_add_page(bio, page, min_t(int, ds, PAGE_SIZE), 0)) {
			drbd_pp_free(mdev,page);
			ERR("alloc_ee: bio_add_page(s=%llu,"
			    "data_size=%u,ds=%u) failed\n",
			    (unsigned long long)sector, data_size, ds);

			q = bdev_get_queue(bio->bi_bdev);
			if (q->merge_bvec_fn) {
				ERR("merge_bvec_fn() = %d\n",
				    q->merge_bvec_fn(q, bio, 
					  &bio->bi_io_vec[bio->bi_vcnt]));
			}

			/* dump more of the bio. */
			DUMPI(bio->bi_max_vecs);
			DUMPI(bio->bi_vcnt);
			DUMPI(bio->bi_size);
			DUMPI(bio->bi_phys_segments);
			DUMPI(bio->bi_hw_segments);

			goto fail2;
			break;
		}
		ds -= min_t(int, ds, PAGE_SIZE);
	}

	D_ASSERT( data_size == bio->bi_size);

	bio->bi_private = e;
	e->mdev = mdev;
	e->sector = sector;
	e->size = bio->bi_size;

	e->private_bio = bio;
	e->block_id = id;
	INIT_HLIST_NODE(&e->colision);
	e->barrier_nr = 0;
	e->barrier_nr2 = 0;
	e->flags = 0;

	MTRACE(TraceTypeEE,TraceLvlAll,
	       INFO("allocated EE sec=%llus size=%u ee=%p\n",
		    (unsigned long long)sector,data_size,e);
	       );

	return e;

 fail2:
	__bio_for_each_segment(bvec, bio, i, 0) {
		drbd_pp_free(mdev,bvec->bv_page);
	}
	bio_put(bio);
 fail1:
	mempool_free(e, drbd_ee_mempool);

	return NULL;
}

void drbd_free_ee(drbd_dev *mdev, struct Tl_epoch_entry* e)
{
	struct bio *bio=e->private_bio;
	struct bio_vec *bvec;
	int i;

	MTRACE(TraceTypeEE,TraceLvlAll,
	       INFO("Free EE sec=%llus size=%u ee=%p\n",
		    (unsigned long long)e->sector,e->size,e);
	       );

	__bio_for_each_segment(bvec, bio, i, 0) {
		drbd_pp_free(mdev,bvec->bv_page);
	}

	bio_put(bio);

	D_ASSERT(hlist_unhashed(&e->colision));

	mempool_free(e, drbd_ee_mempool);
}

/* currently on module unload only */
int drbd_release_ee(drbd_dev *mdev,struct list_head* list)
{
	int count=0;
	struct Tl_epoch_entry* e;
	struct list_head *le;

	spin_lock_irq(&mdev->req_lock);
	while(!list_empty(list)) {
		le = list->next;
		list_del(le);
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		drbd_free_ee(mdev,e);
		count++;
	}
	spin_unlock_irq(&mdev->req_lock);

	return count;
}


STATIC void reclaim_net_ee(drbd_dev *mdev)
{
	struct Tl_epoch_entry *e;
	struct list_head *le,*tle;

	/* The EEs are always appended to the end of the list. Since
	   they are sent in order over the wire, they have to finish
	   in order. As soon as we see the first not finished we can
	   stop to examine the list... */

	list_for_each_safe(le, tle, &mdev->net_ee) {
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		if( drbd_bio_has_active_page(e->private_bio) ) break;
		list_del(le);
		drbd_free_ee(mdev,e);
	}
}


/*
 * This function is called from _asender only_
 * but see also comments in _req_mod(,barrier_acked)
 * and receive_Barrier_no_tcq.
 *
 * Move entries from net_ee to done_ee, if ready.
 * Grab done_ee, call all callbacks, free the entries.
 * The callbacks typically send out ACKs.
 */
STATIC int drbd_process_done_ee(drbd_dev *mdev)
{
	LIST_HEAD(work_list);
	struct Tl_epoch_entry *e, *t;
	int ok=1;
	int do_clear_bit = test_bit(WRITE_ACK_PENDING,&mdev->flags);

	spin_lock_irq(&mdev->req_lock);
	reclaim_net_ee(mdev);
	list_splice_init(&mdev->done_ee,&work_list);
	spin_unlock_irq(&mdev->req_lock);

	/* possible callbacks here:
	 * e_end_block, and e_end_resync_block, e_send_discard_ack.
	 * all ignore the last argument.
	 */
	list_for_each_entry_safe(e, t, &work_list, w.list) {
		MTRACE(TraceTypeEE,TraceLvlAll,
		       INFO("Process EE on done_ee sec=%llus size=%u ee=%p\n",
			    (unsigned long long)e->sector,e->size,e);
			);
		// list_del not necessary, next/prev members not touched
		if (e->w.cb(mdev,&e->w,0) == 0) ok = 0;
		drbd_free_ee(mdev,e);
	}
	if (do_clear_bit)
		clear_bit(WRITE_ACK_PENDING,&mdev->flags);
	wake_up(&mdev->ee_wait);

	return ok;
}



/* clean-up helper for drbd_disconnect */
void _drbd_clear_done_ee(drbd_dev *mdev)
{
	struct list_head *le;
	struct Tl_epoch_entry *e;
	int n = 0;

	MUST_HOLD(&mdev->req_lock);

	reclaim_net_ee(mdev);

	while(!list_empty(&mdev->done_ee)) {
		le = mdev->done_ee.next;
		list_del(le);
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		if(mdev->net_conf->wire_protocol == DRBD_PROT_C ||
		   is_syncer_block_id(e->block_id)) {
			++n;
		}
		if(!hlist_unhashed(&e->colision)) hlist_del_init(&e->colision);
		drbd_free_ee(mdev,e);
	}

	sub_unacked(mdev, n);
}

void _drbd_wait_ee_list_empty(drbd_dev *mdev,struct list_head *head)
{
	DEFINE_WAIT(wait);
	MUST_HOLD(&mdev->req_lock);

	/* avoids spin_lock/unlock and calling prepare_to_wait in the fast path */
	while (!list_empty(head)) {
		prepare_to_wait(&mdev->ee_wait,&wait,TASK_UNINTERRUPTIBLE);
		spin_unlock_irq(&mdev->req_lock);
		drbd_kick_lo(mdev);
		schedule();
		finish_wait(&mdev->ee_wait, &wait);
		spin_lock_irq(&mdev->req_lock);
	}
}

void drbd_wait_ee_list_empty(drbd_dev *mdev,struct list_head *head)
{
	spin_lock_irq(&mdev->req_lock);
	_drbd_wait_ee_list_empty(mdev, head);
	spin_unlock_irq(&mdev->req_lock);
}

STATIC struct socket* drbd_accept(drbd_dev *mdev,struct socket* sock)
{
	struct socket *newsock;
	int err = 0;

	err = sock->ops->listen(sock, 5);
	if (err)
		goto out;

	if (sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &newsock))
		goto out;

	newsock->type = sock->type;
	newsock->ops  = sock->ops;

	err = newsock->ops->accept(sock, newsock, 0);
	if (err < 0)
		goto out_release;

	return newsock;

      out_release:
	sock_release(newsock);
      out:
	if(err != -EAGAIN && err != -EINTR)
		ERR("accept failed! %d\n", err);
	return 0;
}

STATIC int drbd_recv_short(drbd_dev *mdev, struct socket *sock,
			   void *buf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	int rv;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = size;
	iov.iov_base = buf;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	rv = sock_recvmsg(sock, &msg, size, msg.msg_flags);

	set_fs(oldfs);

	return rv;
}

int drbd_recv(drbd_dev *mdev,void *buf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	int rv;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = size;
	iov.iov_base = buf;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	for(;;) {
		rv = sock_recvmsg(mdev->data.socket,&msg,size,msg.msg_flags);
		if (rv == size) break;

		/* Note:
		 * ECONNRESET   other side closed the connection
		 * ERESTARTSYS  (on  sock) we got a signal
		 */

		if (rv < 0) {
			if (rv == -ECONNRESET)
				INFO("sock was reset by peer\n");
			else if (rv != -ERESTARTSYS)
				ERR("sock_recvmsg returned %d\n",rv);
			break;
		} else if (rv == 0) {
			INFO("sock was shut down by peer\n");
			break;
		} else  {
			/* signal came in, or peer/link went down,
			 * after we read a partial message
			 */
			// D_ASSERT(signal_pending(current));
			break;
		}
	};

	set_fs(oldfs);

	if(rv != size) drbd_force_state(mdev,NS(conn,BrokenPipe));

	return rv;
}

STATIC struct socket *drbd_try_connect(drbd_dev *mdev)
{
	int err;
	struct socket *sock;
	struct sockaddr_in src_in;

	if (!inc_net(mdev)) return NULL;

	err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (err) {
		dec_net(mdev);
		ERR("sock_creat(..)=%d\n", err);
		return NULL;
	}

	sock->sk->sk_rcvtimeo =
	sock->sk->sk_sndtimeo =  mdev->net_conf->try_connect_int*HZ;

       /* explicitly bind to the configured IP as source IP
	   for the outgoing connections.
	   This is needed for multihomed hosts and to be
	   able to use lo: interfaces for drbd.
          Make sure to use 0 as portnumber, so linux selects
	   a free one dynamically.
	*/
	memcpy (&src_in, &(mdev->net_conf->my_addr), sizeof(struct sockaddr_in));
	src_in.sin_port = 0;

	err = sock->ops->bind(sock,
			      (struct sockaddr * ) &src_in,
			      sizeof (struct sockaddr_in));
	if (err) {
		ERR("Unable to bind source sock (%d)\n", err);
		sock_release(sock);
		sock = NULL;
		dec_net(mdev);
		return sock;
	}

	err = sock->ops->connect(sock,
				 (struct sockaddr *)mdev->net_conf->peer_addr,
				 mdev->net_conf->peer_addr_len, 0);

	if (err) {
		sock_release(sock);
		sock = NULL;
	}

	dec_net(mdev);
	return sock;
}

STATIC struct socket *drbd_wait_for_connect(drbd_dev *mdev)
{
	int err;
	struct socket *sock,*sock2;

	if (!inc_net(mdev)) return NULL;

	err = sock_create_kern(AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock2);
	if (err) {
		dec_net(mdev);
		ERR("sock_creat(..)=%d\n", err);
		return NULL;
	}

	sock2->sk->sk_reuse    = 1; /* SO_REUSEADDR */
	sock2->sk->sk_rcvtimeo =
	sock2->sk->sk_sndtimeo =  mdev->net_conf->try_connect_int*HZ;

	err = sock2->ops->bind(sock2,
			      (struct sockaddr *) mdev->net_conf->my_addr,
			      mdev->net_conf->my_addr_len);
	dec_net(mdev);

	if (err) {
		ERR("Unable to bind sock2 (%d)\n", err);
		sock_release(sock2);
		drbd_force_state(mdev,NS(conn,Disconnecting));
		return NULL;
	}

	sock = drbd_accept(mdev,sock2);
	sock_release(sock2);

	return sock;
}

STATIC int drbd_do_handshake(drbd_dev *mdev);
STATIC int drbd_do_auth(drbd_dev *mdev);

STATIC int drbd_send_fp(drbd_dev *mdev,struct socket *sock,Drbd_Packet_Cmd cmd)
{
	Drbd_Header *h = (Drbd_Header *) &mdev->data.sbuf.head;

	return _drbd_send_cmd(mdev,sock,cmd,h,sizeof(*h),0);
}

STATIC Drbd_Packet_Cmd drbd_recv_fp(drbd_dev *mdev,struct socket *sock)
{
	Drbd_Header *h = (Drbd_Header *) &mdev->data.sbuf.head;
	int rr;

	rr = drbd_recv_short(mdev, sock, h, sizeof(*h));

	if( rr==sizeof(*h) && h->magic==BE_DRBD_MAGIC ) {
		return be16_to_cpu(h->command);
	}

	return 0xffff;
}

/*
 * return values:
 *   1 yess, we have a valid connection
 *   0 oops, did not work out, please try again
 *  -1 peer talks different language,
 *     no point in trying again, please go standalone.
 *  -2 We do not have a network config...
 */
int drbd_connect(drbd_dev *mdev)
{
	struct socket *s, *sock,*msock;
	int try,h;

	D_ASSERT(!mdev->data.socket);

	if (_drbd_request_state(mdev,NS(conn,WFConnection),0) < SS_Success )
		return -2;

	clear_bit(DISCARD_CONCURRENT, &mdev->flags);

	sock  = NULL;
	msock = NULL;

	do {
		for(try=0;;) { // 3 tries, this should take less than a second!
			s=drbd_try_connect(mdev);
			if(s || ++try >= 3 ) break;
			// give the other side time to call bind() & listen()
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}

		if(s) {
			if( !sock ) {
				if( drbd_send_fp(mdev, s, HandShakeS) ) {
					sock = s;
					s = NULL;
				}
			} else if( !msock ) {
				if( drbd_send_fp(mdev, s, HandShakeM) ) {
					msock = s;
					s = NULL;
				}
			} else {
				ERR("Logic error in drbd_connect()\n");
				return -1;
			}
			if(s) {
				ERR("Error during sending initial packet.\n");
				sock_release(s);
			}
		}

		if(sock && msock) break;

		s=drbd_wait_for_connect(mdev);
		if(s) {
			switch(drbd_recv_fp(mdev,s)) {
			case HandShakeS:
				if(sock) sock_release(sock);
				sock = s;
				break;
			case HandShakeM:
				if(msock) sock_release(msock);
				msock = s;
				set_bit(DISCARD_CONCURRENT, &mdev->flags);
				break;
			default:
				WARN("Error receiving initial packet\n");
				sock_release(s);
			}
		}

		if(mdev->state.conn <= Disconnecting) return -1;
		if(signal_pending(current)) {
			flush_signals(current);
			smp_rmb();
			if (get_t_state(&mdev->receiver) == Exiting) {
				if(sock) sock_release(sock);
				if(msock) sock_release(msock);
				return -1;
			}
		}

	} while( !sock || !msock );

	msock->sk->sk_reuse=1; /* SO_REUSEADDR */
	sock->sk->sk_reuse=1; /* SO_REUSEADDR */

	sock->sk->sk_allocation = GFP_NOIO;
	msock->sk->sk_allocation = GFP_NOIO;

	sock->sk->sk_priority=TC_PRIO_BULK;
	// FIXME fold to limits. should be done in drbd_ioctl
	sock->sk->sk_sndbuf = mdev->net_conf->sndbuf_size;
	sock->sk->sk_rcvbuf = mdev->net_conf->sndbuf_size;
	/* NOT YET ...
	 * sock->sk->sk_sndtimeo = mdev->net_conf->timeout*HZ/10;
	 * sock->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the HandShake timeout, wich is hardcoded for now: */
	sock->sk->sk_sndtimeo =
	sock->sk->sk_rcvtimeo = 2*HZ;
	sock->sk->sk_userlocks |= SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK;

	msock->sk->sk_priority=TC_PRIO_INTERACTIVE;
	msock->sk->sk_sndbuf = 2*32767;
	msock->sk->sk_sndtimeo = mdev->net_conf->timeout*HZ/10;
	msock->sk->sk_rcvtimeo = mdev->net_conf->ping_int*HZ;

	mdev->data.socket = sock;
	mdev->meta.socket = msock;
	mdev->last_received = jiffies;

	D_ASSERT(mdev->asender.task == NULL);

	h = drbd_do_handshake(mdev);
	if (h <= 0) return h;

	if ( mdev->cram_hmac_tfm ) {
		/* drbd_request_state(mdev, NS(conn, WFAuth)); */
		if (!drbd_do_auth(mdev)) {
			ERR("Authentication of peer failed\n");
			return -1;
		}
	}

	if (drbd_request_state(mdev, NS(conn, WFReportParams)) < SS_Success) return 0;

	sock->sk->sk_sndtimeo = mdev->net_conf->timeout*HZ/10;
	sock->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;

	atomic_set(&mdev->packet_seq,0);
	mdev->peer_seq=0;

	drbd_thread_start(&mdev->asender);

	drbd_send_protocol(mdev);
	drbd_send_sync_param(mdev,&mdev->sync_conf);
	drbd_send_sizes(mdev);
	drbd_send_uuids(mdev);
	drbd_send_state(mdev);
	clear_bit(USE_DEGR_WFC_T,&mdev->flags);

	return 1;
}

STATIC int drbd_recv_header(drbd_dev *mdev, Drbd_Header *h)
{
	int r;

	r = drbd_recv(mdev,h,sizeof(*h));

	if (unlikely( r != sizeof(*h) )) {
		ERR("short read expecting header on sock: r=%d\n",r);
		return FALSE;
	};
	h->command = be16_to_cpu(h->command);
	h->length  = be16_to_cpu(h->length);
	if (unlikely( h->magic != BE_DRBD_MAGIC )) {
		ERR("magic?? on data m: 0x%lx c: %d l: %d\n",
		    (long)be32_to_cpu(h->magic),
		    h->command, h->length);
		return FALSE;
	}
	mdev->last_received = jiffies;

	return TRUE;
}

#if 0
STATIC int receive_Barrier_tcq(drbd_dev *mdev, Drbd_Header* h)
{
	int rv;
	int epoch_size=0;
	Drbd_Barrier_Packet *p = (Drbd_Barrier_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, h->payload, h->length);
	ERR_IF(rv != h->length) return FALSE;

	inc_unacked(mdev);

	spin_lock_irq(&mdev->ee_lock);
	if(list_empty(&mdev->active_ee)) {
		epoch_size = mdev->epoch_size;
		mdev->epoch_size = 0;
	} else if (mdev->last_write_w_barrier) {
		mdev->last_write_w_barrier->barrier_nr2 = be32_to_cpu(p->barrier);
	} else {
		mdev->next_barrier_nr = be32_to_cpu(p->barrier);
	}
	spin_unlock_irq(&mdev->ee_lock);

	if(epoch_size) {
		rv = drbd_send_b_ack(mdev, p->barrier, epoch_size);
		dec_unacked(mdev);
	}

	return rv;
}
#endif

STATIC int receive_Barrier_no_tcq(drbd_dev *mdev, Drbd_Header* h)
{
	int rv;
	int epoch_size;
	Drbd_Barrier_Packet *p = (Drbd_Barrier_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, h->payload, h->length);
	ERR_IF(rv != h->length) return FALSE;

	inc_unacked(mdev);

	if (mdev->net_conf->wire_protocol != DRBD_PROT_C)
		drbd_kick_lo(mdev);

	spin_lock_irq(&mdev->req_lock);
	_drbd_wait_ee_list_empty(mdev,&mdev->active_ee);
	epoch_size = mdev->epoch_size;
	mdev->epoch_size = 0;
	spin_unlock_irq(&mdev->req_lock);

	/* FIXME CAUTION! receiver thread sending via msock.
	 * to make sure this BarrierAck will not be received before the asender
	 * had a chance to send all the write acks corresponding to this epoch,
	 * wait_for that bit to clear... */
	set_bit(WRITE_ACK_PENDING,&mdev->flags);
	wake_asender(mdev);
	rv = wait_event_interruptible(mdev->ee_wait,
			      !test_bit(WRITE_ACK_PENDING,&mdev->flags));

	if (rv == 0 && mdev->state.conn >= Connected)
		rv = drbd_send_b_ack(mdev, p->barrier, epoch_size);
	else
		rv = 0;
	dec_unacked(mdev);

	return rv;
}

/* used from receive_RSDataReply (recv_resync_read)
 * and from receive_Data */
STATIC struct Tl_epoch_entry *
read_in_block(drbd_dev *mdev, u64 id, sector_t sector, int data_size)
{
	struct Tl_epoch_entry *e;
	struct bio_vec *bvec;
	struct page *page;
	struct bio *bio;
	int ds,i,rr;

	e = drbd_alloc_ee(mdev,id,sector,data_size,GFP_KERNEL);
	if(!e) return 0;
	bio = e->private_bio;
	ds = data_size;
	bio_for_each_segment(bvec, bio, i) {
		page = bvec->bv_page;
		rr = drbd_recv(mdev,kmap(page),min_t(int,ds,PAGE_SIZE));
		kunmap(page);
		if( rr != min_t(int,ds,PAGE_SIZE) ) {
			drbd_free_ee(mdev,e);
			WARN("short read receiving data: read %d expected %d\n",
			     rr, min_t(int,ds,PAGE_SIZE));
			return 0;
		}
		ds -= rr;
	}

	mdev->recv_cnt+=data_size>>9;
	return e;
}

/* drbd_drain_block() just takes a data block
 * out of the socket input buffer, and discards it.
 */
STATIC int
drbd_drain_block(drbd_dev *mdev, int data_size)
{
	struct page *page;
	int rr, rv=1;
	void* data;

	page = drbd_pp_alloc(mdev, GFP_KERNEL);

	data=kmap(page);
	while(data_size) {
		rr = drbd_recv(mdev,data,min_t(int,data_size,PAGE_SIZE));
		if( rr != min_t(int,data_size,PAGE_SIZE) ) {
			rv = 0;
			WARN("short read receiving data: read %d expected %d\n",
			     rr, min_t(int,data_size,PAGE_SIZE));
			break;
		}
		data_size -= rr;
	}
	kunmap(page);
	drbd_pp_free(mdev,page);
	return rv;
}

/* kick lower level device, if we have more than (arbitrary number)
 * reference counts on it, which typically are locally submitted io
 * requests.  don't use unacked_cnt, so we speed up proto A and B, too. */
static void maybe_kick_lo(drbd_dev *mdev)
{
	if (atomic_read(&mdev->local_cnt) >= mdev->net_conf->unplug_watermark ) {
		/* FIXME hysteresis ?? */
		drbd_kick_lo(mdev);
	}
}

STATIC int recv_dless_read(drbd_dev *mdev, drbd_request_t *req,
			   sector_t sector, int data_size)
{
	struct bio_vec *bvec;
	struct bio *bio;
	int rr,i,expect;

	bio = req->master_bio;
	D_ASSERT( sector == bio->bi_sector );

	bio_for_each_segment(bvec, bio, i) {
		expect = min_t(int,data_size,bvec->bv_len);
		rr=drbd_recv(mdev,
			     kmap(bvec->bv_page)+bvec->bv_offset,
			     expect);
		kunmap(bvec->bv_page);
		if (rr != expect) {
			WARN("short read receiving data reply: read %d expected %d\n",
			     rr, expect);
			return 0;
		}
		data_size -= rr;
	}

	D_ASSERT(data_size == 0);
	/* FIXME recv_cnt accounting ?? */
	return 1;
}

/* e_end_resync_block() is called via
 * drbd_process_done_ee() by asender only */
STATIC int e_end_resync_block(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	sector_t sector = e->sector;
	int ok;

	D_ASSERT(hlist_unhashed(&e->colision));

	if (likely( drbd_bio_uptodate(e->private_bio) )) {
		drbd_set_in_sync(mdev, sector, e->size);
		ok = drbd_send_ack(mdev,RSWriteAck,e);
	} else {
		// Record failure to sync
		drbd_rs_failed_io(mdev, sector, e->size);

		ok = drbd_send_ack(mdev,NegAck,e);
		ok&= drbd_io_error(mdev, FALSE);
	}
	dec_unacked(mdev);

	return ok;
}

STATIC int recv_resync_read(drbd_dev *mdev,sector_t sector,int data_size)
{
	struct Tl_epoch_entry *e;

	e = read_in_block(mdev,ID_SYNCER,sector,data_size);
	if(!e) return FALSE;

	dec_rs_pending(mdev);

	e->private_bio->bi_end_io = drbd_endio_write_sec;
	e->private_bio->bi_rw = WRITE;
	e->w.cb = e_end_resync_block;

	inc_unacked(mdev);
	/* corresponding dec_unacked() in e_end_resync_block()
	 * respective _drbd_clear_done_ee */

	spin_lock_irq(&mdev->req_lock);
	list_add(&e->w.list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->req_lock);

	MTRACE(TraceTypeEE,TraceLvlAll,
	       INFO("submit EE (RS)WRITE sec=%llus size=%u ee=%p\n",
		    (unsigned long long)e->sector,e->size,e);
	       );
	drbd_generic_make_request(mdev, DRBD_FAULT_RS_WR, e->private_bio);
	/* accounting done in endio */

	maybe_kick_lo(mdev);
	return TRUE;
}

STATIC int receive_DataReply(drbd_dev *mdev,Drbd_Header* h)
{
	drbd_request_t *req;
	sector_t sector;
	unsigned int header_size,data_size;
	int ok;
	Drbd_Data_Packet *p = (Drbd_Data_Packet*)h;

	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	/* I expect a block to be a multiple of 512 byte,
	 * and no more than DRBD_MAX_SEGMENT_SIZE.
	 * is this too restrictive?  */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0x1ff) return FALSE;
	ERR_IF(data_size >  DRBD_MAX_SEGMENT_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);

	spin_lock_irq(&mdev->req_lock);
	req = _ar_id_to_req(mdev,p->block_id, sector);
	spin_unlock_irq(&mdev->req_lock);
	if (unlikely(!req)) {
		ERR("Got a corrupt block_id/sector pair(1).\n");
		return FALSE;
	}

	/* hlist_del(&req->colision) is done in _req_may_be_done, to avoid
	 * special casing it there for the various failure cases.
	 * still no race with drbd_fail_pending_reads */
	ok = recv_dless_read(mdev,req,sector,data_size);

	if (ok) req_mod(req, data_received, 0);
	/* else: nothing. handled from drbd_disconnect...
	 * I don't think we may complete this just yet
	 * in case we are "on-disconnect: freeze" */

	return ok;
}

STATIC int receive_RSDataReply(drbd_dev *mdev,Drbd_Header* h)
{
	sector_t sector;
	unsigned int header_size,data_size;
	int ok;
	Drbd_Data_Packet *p = (Drbd_Data_Packet*)h;

	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	/* I expect a block to be a multiple of 512 byte,
	 * and no more than DRBD_MAX_SEGMENT_SIZE.
	 * is this too restrictive?  */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0x1ff) return FALSE;
	ERR_IF(data_size >  DRBD_MAX_SEGMENT_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);
	D_ASSERT(p->block_id == ID_SYNCER);

	if(inc_local(mdev)) {
		/* data is submitted to disk within recv_resync_read.
		 * corresponding dec_local done below on error,
		 * or in drbd_endio_write_sec. */
		/* FIXME paranoia:
		 * verify that the corresponding bit is set.
		 * in case we are Primary SyncTarget,
		 * verify there are no pending write request to that area.
		 */
		ok = recv_resync_read(mdev,sector,data_size);
		if (!ok) dec_local(mdev);
	} else {
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Can not write resync data to local disk.\n");

		ok = drbd_drain_block(mdev,data_size);

		drbd_send_ack_dp(mdev,NegAck,p);
	}

	return ok;
}

/* e_end_block() is called via drbd_process_done_ee().
 * this means this function only runs in the asender thread
 *
 * for a broken example implementation of the TCQ barrier version of
 * e_end_block see older revisions...
 */
STATIC int e_end_block(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	sector_t sector = e->sector;
	// unsigned int epoch_size;
	int ok=1,pcmd;

	if(mdev->net_conf->wire_protocol == DRBD_PROT_C) {
		if(likely(drbd_bio_uptodate(e->private_bio))) {
			pcmd = (mdev->state.conn >= SyncSource &&
				mdev->state.conn <= PausedSyncT &&
				e->flags & EE_MAY_SET_IN_SYNC) ?
				RSWriteAck : WriteAck;
			ok &= drbd_send_ack(mdev,pcmd,e);
			if(pcmd==RSWriteAck)
				drbd_set_in_sync(mdev,sector,e->size);
		} else {
			/* FIXME I think we should send a NegAck regardless of
			 * which protocol is in effect.
			 * In which case we would need to make sure that any
			 * NegAck is sent. basically that means that drbd_process_done_ee
			 * may not list_del() the ee before this callback did run...
			 * maybe even move the list_del(e) in here... */
			ok = drbd_send_ack(mdev,NegAck,e);
			ok&= drbd_io_error(mdev, FALSE);
			/* we expect it to be marked out of sync anyways...
			 * maybe assert this?  */
		}
		dec_unacked(mdev);
	} else if(unlikely(!drbd_bio_uptodate(e->private_bio))) {
		ok = drbd_io_error(mdev, FALSE);
	}

	/* we delete from the conflict detection hash _after_ we sent out the
	 * WriteAck / NegAck, to get the sequence number right.  */
	if (mdev->net_conf->two_primaries) {
		spin_lock_irq(&mdev->req_lock);
		D_ASSERT(!hlist_unhashed(&e->colision));
		hlist_del_init(&e->colision);
		spin_unlock_irq(&mdev->req_lock);
	} else {
		D_ASSERT(hlist_unhashed(&e->colision));
	}

	return ok;
}

STATIC int e_send_discard_ack(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	int ok=1;

	D_ASSERT(mdev->net_conf->wire_protocol == DRBD_PROT_C);
	ok = drbd_send_ack(mdev,DiscardAck,e);

	spin_lock_irq(&mdev->req_lock);
	D_ASSERT(!hlist_unhashed(&e->colision));
	hlist_del_init(&e->colision);
	spin_unlock_irq(&mdev->req_lock);

	dec_unacked(mdev);

	return ok;
}

/* Called from receive_Data.
 * Synchronize packets on sock with packets on msock.
 *
 * This is here so even when a Data packet traveling via sock overtook an Ack
 * packet traveling on msock, they are still processed in the order they have
 * been sent.
 *
 * Note: we don't care for Ack packets overtaking Data packets.
 *
 * In case packet_seq is larger than mdev->peer_seq number, there are
 * outstanding packets on the msock. We wait for them to arrive.
 * In case we are the logically next packet, we update mdev->peer_seq
 * ourselves. Correctly handles 32bit wrap around.
 * FIXME verify that atomic_t guarantees 32bit wrap around,
 * otherwise we have to play tricks with << ...
 *
 * Assume we have a 10 GBit connection, that is about 1<<30 byte per second,
 * about 1<<21 sectors per second. So "worst" case, we have 1<<3 == 8 seconds
 * for the 24bit wrap (historical atomic_t guarantee on some archs), and we have
 * 1<<9 == 512 seconds aka ages for the 32bit wrap around...
 *
 * returns 0 if we may process the packet,
 * -ERESTARTSYS if we were interrupted (by disconnect signal). */
static int drbd_wait_peer_seq(drbd_dev *mdev, const u32 packet_seq)
{
	DEFINE_WAIT(wait);
	int ret = 0;
	spin_lock(&mdev->peer_seq_lock);
	for (;;) {
		prepare_to_wait(&mdev->seq_wait,&wait,TASK_INTERRUPTIBLE);
		if (seq_le(packet_seq,mdev->peer_seq+1))
			break;
		spin_unlock(&mdev->peer_seq_lock);
		if (signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}
		schedule();
		spin_lock(&mdev->peer_seq_lock);
	}
	finish_wait(&mdev->seq_wait, &wait);
	if (mdev->peer_seq+1 == packet_seq)
		mdev->peer_seq++;
	spin_unlock(&mdev->peer_seq_lock);
	return ret;
}

// mirrored write
STATIC int receive_Data(drbd_dev *mdev,Drbd_Header* h)
{
	sector_t sector;
	struct Tl_epoch_entry *e;
	Drbd_Data_Packet *p = (Drbd_Data_Packet*)h;
	int header_size, data_size;
	unsigned int barrier_nr = 0;
	unsigned int epoch_size = 0;
	u32 dp_flags;

	// FIXME merge this code dups into some helper function
	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0x1ff) return FALSE;
	ERR_IF(data_size >  DRBD_MAX_SEGMENT_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	if(!inc_local(mdev)) {
		/* data is submitted to disk at the end of this function.
		 * corresponding dec_local done either below (on error),
		 * or in drbd_endio_write_sec. */
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Can not write mirrored data block to local disk.\n");
		spin_lock(&mdev->peer_seq_lock);
		if (mdev->peer_seq+1 == be32_to_cpu(p->seq_num))
			mdev->peer_seq++;
		spin_unlock(&mdev->peer_seq_lock);

		drbd_send_ack_dp(mdev,NegAck,p);
		mdev->epoch_size++; // spin lock ?
		return drbd_drain_block(mdev,data_size);
	}

	sector = be64_to_cpu(p->sector);
	e = read_in_block(mdev,p->block_id,sector,data_size);
	if (!e) {
		dec_local(mdev);
		return FALSE;
	}

	e->private_bio->bi_end_io = drbd_endio_write_sec;
	e->private_bio->bi_rw = WRITE;
	e->w.cb = e_end_block;

	dp_flags = be32_to_cpu(p->dp_flags);
	if (dp_flags & DP_HARDBARRIER)
		e->private_bio->bi_rw |= (1 << BIO_RW_BARRIER);
	if (dp_flags & DP_RW_SYNC)
		e->private_bio->bi_rw |= (1 << BIO_RW_SYNC);
	if (dp_flags & DP_MAY_SET_IN_SYNC)
		e->flags |= EE_MAY_SET_IN_SYNC;

	/* I'm the receiver, I do hold a net_cnt reference. */
	if (!mdev->net_conf->two_primaries) {
		spin_lock_irq(&mdev->req_lock);
	} else {
		/* don't get the req_lock yet,
		 * we may sleep in drbd_wait_peer_seq */
		const sector_t sector = e->sector;
		const int size = e->size;
		const int discard = test_bit(DISCARD_CONCURRENT,&mdev->flags);
		DEFINE_WAIT(wait);
		drbd_request_t *i;
		struct hlist_node *n;
		struct hlist_head *slot;
		int first;

		D_ASSERT(mdev->net_conf->wire_protocol == DRBD_PROT_C);
		BUG_ON(mdev->ee_hash == NULL);
		BUG_ON(mdev->tl_hash == NULL);

		/* conflict detection and handling:
		 * 1. wait on the sequence number,
		 *    in case this data packet overtook ACK packets.
		 * 2. check our hash tables for conflicting requests.
		 *    we only need to walk the tl_hash, since an ee can not
		 *    have a conflict with an other ee: on the submitting
		 *    node, the corresponding req had already been conflicting,
		 *    and a conflicting req is never sent.
		 *
		 * Note: for two_primaries, we are protocol C,
		 * so there cannot be any request that is DONE
		 * but still on the transfer log.
		 *
		 * unconditionally add to the ee_hash.
		 *
		 * if no conflicting request is found:
		 *    submit.
		 *
		 * if any conflicting request is found that has not yet been acked,
		 * AND I have the "discard concurrent writes" flag:
		 *       queue (via done_ee) the DiscardAck; OUT.
		 *
		 * if any conflicting request is found:
		 *       block the receiver, waiting on misc_wait
		 *       until no more conflicting requests are there,
		 *       or we get interrupted (disconnect).
		 *
		 *       we do not just write after local io completion of those
		 *       requests, but only after req is done completely, i.e.
		 *       we wait for the DiscardAck to arrive!
		 *
		 *       then proceed normally, i.e. submit.
		 */
		if (drbd_wait_peer_seq(mdev, be32_to_cpu(p->seq_num)))
			goto out_interrupted;

		spin_lock_irq(&mdev->req_lock);

		hlist_add_head(&e->colision,ee_hash_slot(mdev,sector));

#define OVERLAPS overlaps(i->sector, i->size, sector, size)
		slot = tl_hash_slot(mdev,sector);
		first = 1;
		for(;;) {
			int have_unacked = 0;
			int have_conflict = 0;
			prepare_to_wait(&mdev->misc_wait,&wait,TASK_INTERRUPTIBLE);
			hlist_for_each_entry(i, n, slot, colision) {
				if (OVERLAPS) {
					if (first) {
						/* only ALERT on first iteration,
						 * we may be woken up early... */
						ALERT("%s[%u] Concurrent local write detected!"
						      "	new: %llus +%u; pending: %llus +%u\n",
						      current->comm, current->pid,
						      (unsigned long long)sector, size,
						      (unsigned long long)i->sector, i->size);
					}
					if (i->rq_state & RQ_NET_PENDING) ++have_unacked;
					++have_conflict;
				}
			}
#undef OVERLAPS
			if (!have_conflict) break;

			/* Discard Ack only for the _first_ iteration */
			if (first && discard && have_unacked) {
				ALERT("Concurrent write! [DISCARD BY FLAG] sec=%llus\n",
				     (unsigned long long)sector);
				inc_unacked(mdev);
				mdev->epoch_size++;
				e->w.cb = e_send_discard_ack;
				list_add_tail(&e->w.list,&mdev->done_ee);

				spin_unlock_irq(&mdev->req_lock);

				/* we could probably send that DiscardAck ourselves,
				 * but I don't like the receiver using the msock */

				dec_local(mdev);
				wake_asender(mdev);
				finish_wait(&mdev->misc_wait, &wait);
				return TRUE;
			}

			if (signal_pending(current)) {
				hlist_del_init(&e->colision);

				spin_unlock_irq(&mdev->req_lock);

				finish_wait(&mdev->misc_wait, &wait);
				goto out_interrupted;
			}

			spin_unlock_irq(&mdev->req_lock);
			if (first) {
				first = 0;
				ALERT("Concurrent write! [W AFTERWARDS] "
				     "sec=%llus\n",(unsigned long long)sector);
			} else if (discard) {
				/* we had none on the first iteration.
				 * there must be none now. */
				D_ASSERT(have_unacked == 0);
			}
			schedule();
			spin_lock_irq(&mdev->req_lock);
		}
		finish_wait(&mdev->misc_wait, &wait);
	}

	/* when using TCQ:
	 * note that, when using tagged command queuing, we may
	 * have more than one reorder domain "active" at a time.
	 *
	 * THINK:
	 * do we have any guarantees that we get the completion
	 * events of the different reorder domains in order?
	 * or does the api only "guarantee" that the events
	 * _happened_ in order, but eventually the completion
	 * callbacks are shuffeled again?
	 *
	 * note that I wonder about the order in which the
	 * callbacks are run, I am reasonable confident that the
	 * actual completion happens in order.
	 *
	 * - can it happen that the tagged write completion is
	 *   called even though not all of the writes before it
	 *   have run their completion callback?
	 * - can it happen that some completion callback of some
	 *   write after the tagged one is run, even though the
	 *   callback of the tagged one itself is still pending?
	 *
	 * if this can happen, we either need to drop our "debug
	 * assertion" about the epoch size and just trust our code
	 * and the layers below us (nah, won't do that).
	 *
	 * or we need to replace the "active_ee" list by some sort
	 * of "transfer log" on the receiving side, too, which
	 * uses epoch counters per reorder domain.
	 */

	/* when using tcq:
	 * if we got a barrier packet before, but at that time the active_ee
	 * was not yet empty, we just "remembered" this barrier request.
	 *
	 * if this is the first data packet since that barrier, maybe meanwhile
	 * all previously active writes have been completed?
	 * if so, send the b_ack right now
	 * (though, maybe rather move it into the e_end_block callback,
	 * where it would be sent as soon as possible).
	 *
	 * otherwise, tag the write with the barrier number, so it
	 * will trigger the b_ack before its own ack.
	 */
	if (mdev->next_barrier_nr) {
		/* only when using TCQ */
		if (list_empty(&mdev->active_ee)) {
			barrier_nr = mdev->next_barrier_nr;
			epoch_size = mdev->epoch_size;
			mdev->epoch_size = 0;
		} else {
			e->barrier_nr = mdev->next_barrier_nr;
		}
		e->private_bio->bi_rw |= (1 << BIO_RW_BARRIER);
		mdev->next_barrier_nr = 0;
	}
	list_add(&e->w.list,&mdev->active_ee);
	spin_unlock_irq(&mdev->req_lock);

	if (barrier_nr) {
		/* only when using TCQ
		 * maybe rather move it into the e_end_block callback,
		 * where it would be sent as soon as possible).
		 */
		(void)drbd_send_b_ack(mdev, cpu_to_be32(barrier_nr), epoch_size);
	}

	switch(mdev->net_conf->wire_protocol) {
	case DRBD_PROT_C:
		inc_unacked(mdev);
		/* corresponding dec_unacked() in e_end_block()
		 * respective _drbd_clear_done_ee */
		break;
	case DRBD_PROT_B:
		/* I really don't like it that the receiver thread
		 * sends on the msock, but anyways */
		drbd_send_ack(mdev, RecvAck, e);
		break;
	case DRBD_PROT_A:
		// nothing to do
		break;
	}

	if(mdev->state.pdsk == Diskless) {
		// In case we have the only disk of the cluster,
		drbd_set_out_of_sync(mdev,e->sector,e->size);
		e->flags |= EE_CALL_AL_COMPLETE_IO;
		drbd_al_begin_io(mdev, e->sector);
	}

	MTRACE(TraceTypeEE,TraceLvlAll,
	       INFO("submit EE (DATA)WRITE sec=%llus size=%u ee=%p\n",
		    (unsigned long long)e->sector,e->size,e);
	       );
	/* FIXME drbd_al_begin_io in case we have two primaries... */
	drbd_generic_make_request(mdev, DRBD_FAULT_DT_WR, e->private_bio);
	/* accounting done in endio */

	maybe_kick_lo(mdev);
	return TRUE;

  out_interrupted:
	/* yes, the epoch_size now is imbalanced.
	 * but we drop the connection anyways, so we don't have a chance to
	 * receive a barrier... atomic_inc(&mdev->epoch_size); */
	dec_local(mdev);
	drbd_free_ee(mdev,e);
	return FALSE;
}

STATIC int receive_DataRequest(drbd_dev *mdev,Drbd_Header *h)
{
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(mdev->this_bdev);
	struct Tl_epoch_entry *e;
	int size;
	unsigned int fault_type;
	Drbd_BlockRequest_Packet *p = (Drbd_BlockRequest_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	sector = be64_to_cpu(p->sector);
	size   = be32_to_cpu(p->blksize);

	if (size <= 0 || (size & 0x1ff) != 0 || size > DRBD_MAX_SEGMENT_SIZE) {
		ERR("%s:%d: sector: %llus, size: %u\n", __FILE__, __LINE__,
				(unsigned long long)sector,size);
		return FALSE;
	}
	if ( sector + (size>>9) > capacity) {
		ERR("%s:%d: sector: %llus, size: %u\n", __FILE__, __LINE__,
				(unsigned long long)sector,size);
		return FALSE;
	}

	if(!inc_local_if_state(mdev, UpToDate)) {
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Can not satisfy peer's read request, no local data.\n");
		drbd_send_ack_rp(mdev,h->command == DataRequest ? NegDReply :
				 NegRSDReply ,p);
		return TRUE;
	}

	e = drbd_alloc_ee(mdev,p->block_id,sector,size,GFP_KERNEL);
	if (!e) {
		dec_local(mdev);
		return FALSE;
	}

	/* FIXME actually, it could be a READA originating from the peer,
	 * also it could have set some flags (e.g. BIO_RW_SYNC) ... */
	e->private_bio->bi_rw = READ;
	e->private_bio->bi_end_io = drbd_endio_read_sec;

	switch (h->command) {
	case DataRequest:
		e->w.cb = w_e_end_data_req;
		fault_type = DRBD_FAULT_DT_RD;
		break;
	case RSDataRequest:
		e->w.cb = w_e_end_rsdata_req;
		fault_type = DRBD_FAULT_RS_RD;
		/* Eventually this should become asynchrously. Currently it
		 * blocks the whole receiver just to delay the reading of a
		 * resync data block.
		 * the drbd_work_queue mechanism is made for this...
		 */
		if (!drbd_rs_begin_io(mdev,sector)) {
			/* we have been interrupted,
			 * probably connection lost! */
			D_ASSERT(signal_pending(current));
			dec_local(mdev);
			drbd_free_ee(mdev,e);
			return 0;
		}
		break;
	default:; /* avoid compiler warning */
		fault_type = DRBD_FAULT_MAX;
	}

	spin_lock_irq(&mdev->req_lock);
	list_add(&e->w.list,&mdev->read_ee);
	spin_unlock_irq(&mdev->req_lock);

	inc_unacked(mdev);

	MTRACE(TraceTypeEE,TraceLvlAll,
	       INFO("submit EE READ sec=%llus size=%u ee=%p\n",
		    (unsigned long long)e->sector,e->size,e);
	       );

	drbd_generic_make_request(mdev, fault_type, e->private_bio);
	maybe_kick_lo(mdev);

	return TRUE;
}

STATIC int drbd_asb_recover_0p(drbd_dev *mdev)
{
	int self, peer, rv=-100;
	unsigned long ch_self, ch_peer;

	self = mdev->bc->md.uuid[Bitmap] & 1;
	peer = mdev->p_uuid[Bitmap] & 1;

	ch_peer = mdev->p_uuid[UUID_SIZE];
	ch_self = mdev->comm_bm_set;

	switch ( mdev->net_conf->after_sb_0p ) {
	case Consensus:
	case DiscardSecondary:
	case CallHelper:
		ERR("Configuration error.\n");
		break;
	case Disconnect:
		break;
	case DiscardYoungerPri:
		if (self == 0 && peer == 1) { rv = -1; break; }
		if (self == 1 && peer == 0) { rv =  1; break; }
		/* Else fall through to one of the other strategies... */
	case DiscardOlderPri:
		if (self == 0 && peer == 1) { rv =  1; break; }
		if (self == 1 && peer == 0) { rv = -1; break; }
		/* Else fall through to one of the other strategies... */
		WARN("Discard younger/older primary did not found a decision\n"
		     "Using discard-least-changes instead\n");
	case DiscardZeroChg:
		if( ch_peer == 0 && ch_self == 0) {
			rv=test_bit(DISCARD_CONCURRENT,&mdev->flags) ? -1 : 1;
			break;
		} else {
			if ( ch_peer == 0 ) { rv =  1; break; }
			if ( ch_self == 0 ) { rv = -1; break; }
		}
		if( mdev->net_conf->after_sb_0p == DiscardZeroChg ) break;
	case DiscardLeastChg:
		if      ( ch_self < ch_peer ) rv = -1;
		else if ( ch_self > ch_peer ) rv =  1;
		else /* ( ch_self == ch_peer ) */ {
			// Well, then use something else.
			rv=test_bit(DISCARD_CONCURRENT,&mdev->flags) ? -1 : 1;
		}
		break;
	case DiscardLocal:
		rv = -1;
		break;
	case DiscardRemote:
		rv =  1;
	}

	return rv;
}

STATIC int drbd_asb_recover_1p(drbd_dev *mdev)
{
	int self, peer, hg, rv=-100;

	self = mdev->bc->md.uuid[Bitmap] & 1;
	peer = mdev->p_uuid[Bitmap] & 1;

	switch ( mdev->net_conf->after_sb_1p ) {
	case DiscardYoungerPri:
	case DiscardOlderPri:
	case DiscardLeastChg:
	case DiscardLocal:
	case DiscardRemote:
		ERR("Configuration error.\n");
		break;
	case Disconnect:
		break;
	case Consensus:
		hg = drbd_asb_recover_0p(mdev);
		if( hg == -1 && mdev->state.role==Secondary) rv=hg;
		if( hg == 1  && mdev->state.role==Primary)   rv=hg;
		break;
	case Violently:
		rv = drbd_asb_recover_0p(mdev);
		break;
	case DiscardSecondary:
		return mdev->state.role==Primary ? 1 : -1;
	case CallHelper:
		hg = drbd_asb_recover_0p(mdev);
		if( hg == -1 && mdev->state.role==Primary) {
			self = drbd_set_role(mdev,Secondary,0);
			if (self != SS_Success) {
				drbd_khelper(mdev,"pri-lost-after-sb");
			} else {
				WARN("Sucessfully gave up primary role.\n");
				rv = hg;
			}
		} else rv = hg;
	}

	return rv;
}

STATIC int drbd_asb_recover_2p(drbd_dev *mdev)
{
	int self, peer, hg, rv=-100;

	self = mdev->bc->md.uuid[Bitmap] & 1;
	peer = mdev->p_uuid[Bitmap] & 1;

	switch ( mdev->net_conf->after_sb_2p ) {
	case DiscardYoungerPri:
	case DiscardOlderPri:
	case DiscardLeastChg:
	case DiscardLocal:
	case DiscardRemote:
	case Consensus:
	case DiscardSecondary:
		ERR("Configuration error.\n");
		break;
	case Violently:
		rv = drbd_asb_recover_0p(mdev);
		break;
	case Disconnect:
		break;
	case CallHelper:
		hg = drbd_asb_recover_0p(mdev);
		if( hg == -1 ) {
			self = drbd_set_role(mdev,Secondary,0);
			if (self != SS_Success) {
				drbd_khelper(mdev,"pri-lost-after-sb");
			} else {
				WARN("Sucessfully gave up primary role.\n");
				rv = hg;
			}
		} else rv = hg;
	}

	return rv;
}

STATIC void drbd_uuid_dump(drbd_dev *mdev,char* text,u64* uuid)
{
	INFO("%s %016llX:%016llX:%016llX:%016llX\n",
	     text,
	     uuid[Current],
	     uuid[Bitmap],
	     uuid[History_start],
	     uuid[History_end]);
}

/*
  100   after split brain try auto recover
    2   SyncSource set BitMap
    1   SyncSource use BitMap
    0   no Sync
   -1   SyncTarget use BitMap
   -2   SyncTarget set BitMap
 -100   after split brain, disconnect
-1000   unrelated data
 */
STATIC int drbd_uuid_compare(drbd_dev *mdev, int *rule_nr)
{
	u64 self, peer;
	int i,j;

	self = mdev->bc->md.uuid[Current] & ~((u64)1);
	peer = mdev->p_uuid[Current] & ~((u64)1);

	*rule_nr = 1;
	if (self == UUID_JUST_CREATED &&
	    peer == UUID_JUST_CREATED) return 0;

	*rule_nr = 2;
	if ( (self == UUID_JUST_CREATED || self == (u64)0) &&
	     peer != UUID_JUST_CREATED) return -2;

	*rule_nr = 3;
	if ( self != UUID_JUST_CREATED &&
	     (peer == UUID_JUST_CREATED || peer == (u64)0) ) return 2;

	*rule_nr = 4;
	if (self == peer) { // Common power [off|failure]
		int rct,dc; // roles at crash time

		rct = (test_bit(CRASHED_PRIMARY, &mdev->flags) ? 1 : 0) +
			( mdev->p_uuid[UUID_FLAGS] & 2 );
		// lowest bit is set when we were primary
		// next bit (weight 2) is set when peer was primary

		MTRACE(TraceTypeUuid,TraceLvlMetrics, DUMPI(rct); );

		switch(rct) {
		case 0: /* !self_pri && !peer_pri */ return 0;
		case 1: /*  self_pri && !peer_pri */ return 1;
		case 2: /* !self_pri &&  peer_pri */ return -1;
		case 3: /*  self_pri &&  peer_pri */
			dc = test_bit(DISCARD_CONCURRENT,&mdev->flags);
			MTRACE(TraceTypeUuid,TraceLvlMetrics, DUMPI(dc); );
			return dc ? -1 : 1;
		}
	}

	*rule_nr = 5;
	peer = mdev->p_uuid[Bitmap] & ~((u64)1);
	if (self == peer) return -1;

	*rule_nr = 6;
	for ( i=History_start ; i<=History_end ; i++ ) {
		peer = mdev->p_uuid[i] & ~((u64)1);
		if (self == peer) return -2;
	}

	*rule_nr = 7;
	self = mdev->bc->md.uuid[Bitmap] & ~((u64)1);
	peer = mdev->p_uuid[Current] & ~((u64)1);
	if (self == peer) return 1;

	*rule_nr = 8;
	for ( i=History_start ; i<=History_end ; i++ ) {
		self = mdev->bc->md.uuid[i] & ~((u64)1);
		if (self == peer) return 2;
	}

	*rule_nr = 9;
	self = mdev->bc->md.uuid[Bitmap] & ~((u64)1);
	peer = mdev->p_uuid[Bitmap] & ~((u64)1);
	if (self == peer && self != ((u64)0) ) return 100;

	*rule_nr = 10;
	for ( i=History_start ; i<=History_end ; i++ ) {
		self = mdev->p_uuid[i] & ~((u64)1);
		for ( j=History_start ; j<=History_end ; j++ ) {
			peer = mdev->p_uuid[j] & ~((u64)1);
			if (self == peer) return -100;
		}
	}

	return -1000;
}

/* drbd_sync_handshake() returns the new conn state on success, or
   conn_mask (-1) on failure.
 */
STATIC drbd_conns_t drbd_sync_handshake(drbd_dev *mdev, drbd_role_t peer_role,
					drbd_disks_t peer_disk)
{
	int hg,rule_nr;
	drbd_conns_t rv = conn_mask;
	drbd_disks_t mydisk;

	mydisk = mdev->state.disk;
	if( mydisk == Negotiating ) mydisk = mdev->new_state_tmp.disk;

	hg = drbd_uuid_compare(mdev,&rule_nr);

	MTRACE(TraceTypeUuid,TraceLvlSummary,
	       INFO("drbd_sync_handshake:\n");
	       drbd_uuid_dump(mdev,"self",mdev->bc->md.uuid);
	       drbd_uuid_dump(mdev,"peer",mdev->p_uuid);
	       INFO("uuid_compare()=%d by rule %d\n",hg,rule_nr);
	    );

	if (hg == -1000) {
		ALERT("Unrelated data, dropping connection!\n");
		drbd_force_state(mdev,NS(conn,Disconnecting));
		return conn_mask;
	}

	if( (mydisk==Inconsistent && peer_disk>Inconsistent) ||
	    (peer_disk==Inconsistent && mydisk>Inconsistent) )  {
		int f = (hg == -100) || abs(hg) == 2;
		hg = mydisk > Inconsistent ? 1 : -1;
		if(f) hg=hg*2;
		INFO("Becoming sync %s due to disk states.\n",
		     hg > 0 ? "source" : "target");
	}

	if (hg == 100 || (hg == -100 && mdev->net_conf->always_asbp) ) {
		int pcount = (mdev->state.role==Primary) + (peer_role==Primary);
		int forced = (hg == -100);

		switch (pcount) {
		case 0:
			hg = drbd_asb_recover_0p(mdev);
			break;
		case 1:
			hg = drbd_asb_recover_1p(mdev);
			break;
		case 2:
			hg = drbd_asb_recover_2p(mdev);
			break;
		}
		if ( abs(hg) < 100 ) {
			WARN("Split-Brain detected, %d primaries, automatically solved. Sync from %s node\n",
			     pcount, (hg < 0) ? "peer":"this");
			if(forced) {
				WARN("Doing a full sync, since"
				     " UUIDs where ambiguous.\n");
				drbd_uuid_dump(mdev,"self",mdev->bc->md.uuid);
				drbd_uuid_dump(mdev,"peer",mdev->p_uuid);
				hg=hg*2;
			}
		}
	}

	if ( hg == -100 ) {
		if(mdev->net_conf->want_lose && !(mdev->p_uuid[UUID_FLAGS]&1)){
			hg = -1;
		}
		if(!mdev->net_conf->want_lose && (mdev->p_uuid[UUID_FLAGS]&1)){
			hg = 1;
		}

		if ( abs(hg) < 100 ) {
			WARN("Split-Brain detected, manually solved. Sync from %s node\n",
			     (hg < 0) ? "peer":"this");
		}
	}

	if (hg == -100) {
		ALERT("Split-Brain detected, dropping connection!\n");
		drbd_uuid_dump(mdev,"self",mdev->bc->md.uuid);
		drbd_uuid_dump(mdev,"peer",mdev->p_uuid);
		drbd_force_state(mdev,NS(conn,Disconnecting));
		drbd_khelper(mdev,"split-brain");
		return conn_mask;
	}

	if (hg > 0 && mydisk <= Inconsistent ) {
		ERR("I shall become SyncSource, but I am inconsistent!\n");
		drbd_force_state(mdev,NS(conn,Disconnecting));
		return conn_mask;
	}

	if (hg < 0 && // by intention we do not use mydisk here.
	    mdev->state.role == Primary && mdev->state.disk >= Consistent ) {
		switch(mdev->net_conf->rr_conflict) {
		case CallHelper:
			drbd_khelper(mdev,"pri-lost");
			// fall through
		case Disconnect:
			ERR("I shall become SyncTarget, but I am primary!\n");
			drbd_force_state(mdev,NS(conn,Disconnecting));
			return conn_mask;
		case Violently:
			WARN("Becoming SyncTarget, violating the stable-data"
			     "assumption\n");
		}
	}

	if (abs(hg) >= 2) {
		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);

		drbd_bm_set_all(mdev);

		if (unlikely(drbd_bm_write(mdev) < 0)) {
			return conn_mask;
		}

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);
	}

	if (hg > 0) { // become sync source.
		rv = WFBitMapS;
	} else if (hg < 0) { // become sync target
		rv = WFBitMapT;
	} else {
		rv = Connected;
		if(drbd_bm_total_weight(mdev)) {
			INFO("No resync, but %lu bits in bitmap!\n",
			     drbd_bm_total_weight(mdev));
		}
	}

	drbd_bm_recount_bits(mdev);

	return rv;
}

/* returns 1 if invalid */
STATIC int cmp_after_sb(enum after_sb_handler peer, enum after_sb_handler self)
{
	// DiscardRemote - DiscardLocal is valid
	if( (peer == DiscardRemote && self == DiscardLocal) ||
	    (self == DiscardRemote && peer == DiscardLocal) ) return 0;

	// any other things with DiscardRemote or DiscardLocal are invalid
	if( peer == DiscardRemote || peer == DiscardLocal ||
	    self == DiscardRemote || self == DiscardLocal ) return 1;

	// everything else is valid if they are equal on both sides.
	if( peer == self ) return 0;

	// everything es is invalid.
	return 1;
}

STATIC int receive_protocol(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Protocol_Packet *p = (Drbd_Protocol_Packet*)h;

	int p_proto, p_after_sb_0p, p_after_sb_1p, p_after_sb_2p;
	int p_want_lose, p_two_primaries;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	p_proto         = be32_to_cpu(p->protocol);
	p_after_sb_0p   = be32_to_cpu(p->after_sb_0p);
	p_after_sb_1p   = be32_to_cpu(p->after_sb_1p);
	p_after_sb_2p   = be32_to_cpu(p->after_sb_2p);
	p_want_lose     = be32_to_cpu(p->want_lose);
	p_two_primaries = be32_to_cpu(p->two_primaries);

	if( p_proto != mdev->net_conf->wire_protocol) {
		ERR("incompatible communication protocols\n");
		goto disconnect;
	}

	if( cmp_after_sb(p_after_sb_0p, mdev->net_conf->after_sb_0p) ) {
		ERR("incompatible after-sb-0pri settings\n");
		goto disconnect;
	}

	if( cmp_after_sb(p_after_sb_1p, mdev->net_conf->after_sb_1p) ) {
		ERR("incompatible after-sb-1pri settings\n");
		goto disconnect;
	}

	if( cmp_after_sb(p_after_sb_2p, mdev->net_conf->after_sb_2p) ) {
		ERR("incompatible after-sb-2pri settings\n");
		goto disconnect;
	}

	if( p_want_lose && mdev->net_conf->want_lose ) {
		ERR("both sides have the 'want_lose' flag set\n");
		goto disconnect;
	}

	if( p_two_primaries != mdev->net_conf->two_primaries ) {
		ERR("incompatible setting of the two-primaries options\n");
		goto disconnect;
	}

	return TRUE;

 disconnect:
	drbd_force_state(mdev,NS(conn,Disconnecting));
	return FALSE;
}

STATIC int receive_SyncParam(drbd_dev *mdev,Drbd_Header *h)
{
	int ok = TRUE;
	Drbd_SyncParam_Packet *p = (Drbd_SyncParam_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	// XXX harmless race with ioctl ...
	mdev->sync_conf.rate      = be32_to_cpu(p->rate);

	return ok;
}

STATIC void drbd_setup_order_type(drbd_dev *mdev, int peer)
{
#if 0
	int self = drbd_queue_order_type(mdev);
	int type;

	static char *order_txt[] = {
		[QUEUE_ORDERED_NONE]  = "none - oldIDE",
		[QUEUE_ORDERED_FLUSH] = "flush - IDE",
		[QUEUE_ORDERED_TAG]   = "tag - TCQ",
	};

	if(self == QUEUE_ORDERED_NONE ||
	   peer == QUEUE_ORDERED_NONE) {
		type = QUEUE_ORDERED_NONE;
	} else if (self == QUEUE_ORDERED_FLUSH ||
		   peer == QUEUE_ORDERED_FLUSH) {
		type = QUEUE_ORDERED_FLUSH;
	} else if(self == QUEUE_ORDERED_TAG ||
		  peer == QUEUE_ORDERED_TAG) {
		type = QUEUE_ORDERED_TAG;
	} else {
		D_ASSERT(0);
		type = QUEUE_ORDERED_NONE;
	}

	if (type != self ) {
		INFO("Exposing an order type of '%s' to the kernel\n",
		     order_txt[type]);
		blk_queue_ordered(mdev->rq_queue,type);
	}
#endif
}

/* warn if the arguments differ by more than 12.5% */
static void warn_if_differ_considerably(drbd_dev *mdev, const char *s, sector_t a, sector_t b)
{
	sector_t d;
	if (a == 0 || b == 0) return;
	d = (a > b) ? (a - b) : (b - a);
	if ( d > (a>>3) || d > (b>>3)) {
		WARN("Considerable difference in %s: %llus vs. %llus\n", s,
		     (unsigned long long)a, (unsigned long long)b);
	}
}

STATIC int receive_sizes(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Sizes_Packet *p = (Drbd_Sizes_Packet*)h;
	unsigned int max_seg_s;
	sector_t p_size, p_usize, my_usize;
	drbd_conns_t nconn;
	int dd;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	p_size=be64_to_cpu(p->d_size);
	p_usize=be64_to_cpu(p->u_size);

	if(p_size == 0 && mdev->state.disk == Diskless ) {
		ERR("some backing storage is needed\n");
		drbd_force_state(mdev,NS(conn,Disconnecting));
		return FALSE;
	}

#define min_not_zero(l, r) (l == 0) ? r : ((r == 0) ? l : min(l, r))
	if(inc_local(mdev)) {
		warn_if_differ_considerably(mdev, "lower level device sizes",
			   p_size, drbd_get_capacity(mdev->bc->backing_bdev));
		warn_if_differ_considerably(mdev, "user requested size",
					    p_usize, mdev->bc->dc.disk_size);

		if (mdev->state.conn == WFReportParams) {
			/* this is first connect, or an otherwise expected
			   param exchange.  choose the minimum */
			p_usize=min_not_zero((sector_t)mdev->bc->dc.disk_size,
					     p_usize);
		}

		my_usize = mdev->bc->dc.disk_size;

		if( mdev->bc->dc.disk_size != p_usize ) {
			mdev->bc->dc.disk_size = p_usize;
			INFO("Peer sets u_size to %lu KB\n",
			     (unsigned long)mdev->bc->dc.disk_size);
		}

		/* Never shrink a device with usable data during connect.
		   But allow online shrinking if we are connected. */
		if(drbd_new_dev_size(mdev,mdev->bc) <
		   drbd_get_capacity(mdev->this_bdev) &&
		   mdev->state.disk >= Outdated &&
		   mdev->state.conn < Connected ) {
			dec_local(mdev);
			ERR("The peer's disk size is too small!\n");
			drbd_force_state(mdev,NS(conn,Disconnecting));
			mdev->bc->dc.disk_size = my_usize;
			return FALSE;
		}
		dec_local(mdev);
	}
#undef min_not_zero

	mdev->p_size=p_size;
	if(inc_local(mdev)) {
		drbd_bm_lock(mdev); // {
		dd = drbd_determin_dev_size(mdev);
		drbd_bm_unlock(mdev); // }
		dec_local(mdev);
		if (dd < 0) return FALSE;
		if (dd == grew && mdev->state.conn == Connected &&
		    mdev->state.pdsk >= Inconsistent &&
		    mdev->state.disk >= Inconsistent) {
			/* With disk >= Inconsistent we take care to not get
			   here during an attach while we are connected. */
			resync_after_online_grow(mdev);
		}
		drbd_md_sync(mdev);
	} else {
		// I am diskless, need to accept the peer's size.
		drbd_set_my_capacity(mdev,p_size);
	}

	if (mdev->p_uuid && mdev->state.conn <= Connected && inc_local(mdev)) {
		nconn=drbd_sync_handshake(mdev,mdev->state.peer,mdev->state.pdsk);
		dec_local(mdev);

		if(nconn == conn_mask) return FALSE;

		if(drbd_request_state(mdev,NS(conn,nconn)) < SS_Success) {
			drbd_force_state(mdev,NS(conn,Disconnecting));
			return FALSE;
		}
	}

	if(inc_local(mdev)) {
		max_seg_s = be32_to_cpu(p->max_segment_size);
		if( max_seg_s != mdev->rq_queue->max_segment_size ) {
			drbd_setup_queue_param(mdev, max_seg_s);
		}

		drbd_setup_order_type(mdev,be32_to_cpu(p->queue_order_type));
		dec_local(mdev);
	}

	if (mdev->state.conn > WFReportParams ) {
		if( be64_to_cpu(p->c_size) !=
		    drbd_get_capacity(mdev->this_bdev) ) {
			// we have different sizes, probabely peer
			// needs to know my new size...
			drbd_send_sizes(mdev);
		}
	}

	return TRUE;
}

STATIC int receive_uuids(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_GenCnt_Packet *p = (Drbd_GenCnt_Packet*)h;
	u64 *p_uuid;
	int i;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	p_uuid = kmalloc(sizeof(u64)*EXT_UUID_SIZE, GFP_KERNEL);

	for (i = Current; i < EXT_UUID_SIZE; i++) {
		p_uuid[i] = be64_to_cpu(p->uuid[i]);
	}

	if ( mdev->p_uuid ) kfree(mdev->p_uuid);
	mdev->p_uuid = p_uuid;

	return TRUE;
}

/**
 * convert_state:
 * Switches the view of the state.
 */
STATIC drbd_state_t convert_state(drbd_state_t ps)
{
	drbd_state_t ms;

	static drbd_conns_t c_tab[] = {
		[Connected] = Connected,

		[StartingSyncS] = StartingSyncT,
		[StartingSyncT] = StartingSyncS,
		[Disconnecting] = TearDown, // NetworkFailure,

		[conn_mask]   = conn_mask,
	};

	ms.i = ps.i;

	ms.conn = c_tab[ps.conn];
	ms.peer = ps.role;
	ms.role = ps.peer;
	ms.pdsk = ps.disk;
	ms.disk = ps.pdsk;
	ms.peer_isp = ( ps.aftr_isp | ps.user_isp );

	return ms;
}

STATIC int receive_req_state(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Req_State_Packet *p = (Drbd_Req_State_Packet*)h;
	drbd_state_t mask,val;
	int rv;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	mask.i = be32_to_cpu(p->mask);
	val.i = be32_to_cpu(p->val);

	if (test_bit(DISCARD_CONCURRENT,&mdev->flags)) drbd_state_lock(mdev);

	mask = convert_state(mask);
	val = convert_state(val);

	rv = drbd_change_state(mdev,ChgStateVerbose,mask,val);

	if (test_bit(DISCARD_CONCURRENT,&mdev->flags)) drbd_state_unlock(mdev);

	drbd_send_sr_reply(mdev,rv);
	drbd_md_sync(mdev);

	return TRUE;
}

STATIC int receive_state(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_State_Packet *p = (Drbd_State_Packet*)h;
	drbd_conns_t nconn,oconn;
	drbd_state_t os,ns,peer_state;
	int rv;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	peer_state.i = be32_to_cpu(p->state);

	spin_lock_irq(&mdev->req_lock);
 retry:
	oconn = nconn = mdev->state.conn;
	spin_unlock_irq(&mdev->req_lock);

	if (nconn == WFReportParams ) nconn = Connected;

	if (mdev->p_uuid &&
	    (oconn < Connected ||
	     (oconn == Connected &&
	      (peer_state.disk == Negotiating || mdev->state.disk == Negotiating))) &&
	    peer_state.disk >= Negotiating &&
	    inc_local_if_state(mdev,Negotiating) ) {
		nconn=drbd_sync_handshake(mdev,peer_state.role,peer_state.disk);
		dec_local(mdev);

		if(nconn == conn_mask) return FALSE;
	}

	spin_lock_irq(&mdev->req_lock);
	if( mdev->state.conn != oconn ) goto retry;
	os = mdev->state;
	ns.i = mdev->state.i;
	ns.conn = nconn;
	ns.peer = peer_state.role;
	ns.pdsk = peer_state.disk;
	ns.peer_isp = ( peer_state.aftr_isp | peer_state.user_isp );
	if((nconn == Connected || nconn == WFBitMapS) &&
	   ns.disk == Negotiating ) ns.disk = UpToDate;
	if((nconn == Connected || nconn == WFBitMapT) &&
	   ns.pdsk == Negotiating ) ns.pdsk = UpToDate;
	rv = _drbd_set_state(mdev,ns,ChgStateVerbose | ChgStateHard);
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);

	if(rv < SS_Success) {
		drbd_force_state(mdev,NS(conn,Disconnecting));
		return FALSE;
	}

	if (oconn > WFReportParams ) {
		if( nconn > Connected && peer_state.conn <= Connected) {
			// we want resync, peer has not yet decided to sync...
			drbd_send_uuids(mdev);
			drbd_send_state(mdev);
		}
		else if (nconn == Connected && peer_state.disk == Negotiating) {
			// peer is waiting for us to respond...
			drbd_send_state(mdev);
		}
	}

	if (rv==SS_Success) {
		after_state_ch(mdev,os,ns,ChgStateVerbose | ChgStateHard);
	}

	mdev->net_conf->want_lose = 0;

	/* FIXME assertion for (gencounts do not diverge) */
	drbd_md_sync(mdev); // update connected indicator, la_size, ...

	return TRUE;
}

STATIC int receive_sync_uuid(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_SyncUUID_Packet *p = (Drbd_SyncUUID_Packet*)h;

	wait_event( mdev->misc_wait,
		    mdev->state.conn < Connected || mdev->state.conn == WFSyncUUID);

	// D_ASSERT( mdev->state.conn == WFSyncUUID );

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	/* Here the _drbd_uuid_ functions are right, current should
	   _not_ be rotated into the history */
	_drbd_uuid_set(mdev,Current,be64_to_cpu(p->uuid));
	_drbd_uuid_set(mdev,Bitmap,0UL);

	drbd_start_resync(mdev,SyncTarget);

	return TRUE;
}

/* Since we are processing the bitfild from lower addresses to higher,
   it does not matter if the process it in 32 bit chunks or 64 bit
   chunks as long as it is little endian. (Understand it as byte stream,
   beginning with the lowest byte...) If we would use big endian
   we would need to process it from the highest address to the lowest,
   in order to be agnostic to the 32 vs 64 bits issue.

   returns 0 on failure, 1 if we suceessfully received it. */
STATIC int receive_bitmap(drbd_dev *mdev, Drbd_Header *h)
{
	size_t bm_words, bm_i, want, num_words;
	unsigned long *buffer;
	int ok=FALSE;

	drbd_bm_lock(mdev);  // {

	bm_words = drbd_bm_words(mdev);
	bm_i     = 0;
	buffer   = vmalloc(BM_PACKET_WORDS*sizeof(long));

	while (1) {
		num_words = min_t(size_t, BM_PACKET_WORDS, bm_words-bm_i );
		want = num_words * sizeof(long);
		ERR_IF(want != h->length) goto out;
		if (want==0) break;
		if (drbd_recv(mdev, buffer, want) != want)
			goto out;

		drbd_bm_merge_lel(mdev, bm_i, num_words, buffer);
		bm_i += num_words;

		if (!drbd_recv_header(mdev,h))
			goto out;
		D_ASSERT(h->command == ReportBitMap);
	}

	if (mdev->state.conn == WFBitMapS) {
		drbd_start_resync(mdev,SyncSource);
	} else if (mdev->state.conn == WFBitMapT) {
		ok = drbd_send_bitmap(mdev);
		if (!ok) goto out;
		ok = drbd_request_state(mdev,NS(conn,WFSyncUUID));
		D_ASSERT( ok == SS_Success );
	} else {
		ERR("unexpected cstate (%s) in receive_bitmap\n",
		    conns_to_name(mdev->state.conn));
	}

	ok=TRUE;
 out:
	drbd_bm_unlock(mdev); // }
	vfree(buffer);
	return ok;
}

STATIC int receive_skip(drbd_dev *mdev,Drbd_Header *h)
{
	// TODO zero copy sink :)
	static char sink[128];
	int size,want,r;

	WARN("skipping unknown optional packet type %d, l: %d!\n",
	     h->command, h->length );

	size = h->length;
	while (size > 0) {
		want = min_t(int,size,sizeof(sink));
		r = drbd_recv(mdev,sink,want);
		ERR_IF(r < 0) break;
		size -= r;
	}
	return (size == 0);
}

STATIC int receive_UnplugRemote(drbd_dev *mdev, Drbd_Header *h)
{
	if (mdev->state.disk >= Inconsistent) drbd_kick_lo(mdev);
	return TRUE; // cannot fail.
}

typedef int (*drbd_cmd_handler_f)(drbd_dev*,Drbd_Header*);

static drbd_cmd_handler_f drbd_default_handler[] = {
	[Data]             = receive_Data,
	[DataReply]        = receive_DataReply,
	[RSDataReply]      = receive_RSDataReply,
	[RecvAck]          = NULL, // via msock: got_RecvAck,
	[WriteAck]         = NULL, // via msock: got_WriteAck,
	[Barrier]          = receive_Barrier_no_tcq,
	[BarrierAck]       = NULL, // via msock: got_BarrierAck,
	[ReportBitMap]     = receive_bitmap,
	[Ping]             = NULL, // via msock: got_Ping,
	[PingAck]          = NULL, // via msock: got_PingAck,
	[UnplugRemote]     = receive_UnplugRemote,
	[DataRequest]      = receive_DataRequest,
	[RSDataRequest]    = receive_DataRequest, //receive_RSDataRequest,
	[SyncParam]        = receive_SyncParam,
	[ReportProtocol]   = receive_protocol,
	[ReportUUIDs]      = receive_uuids,
	[ReportSizes]      = receive_sizes,
	[ReportState]      = receive_state,
	[StateChgRequest]  = receive_req_state,
	[ReportSyncUUID]   = receive_sync_uuid,
};

static drbd_cmd_handler_f *drbd_cmd_handler = drbd_default_handler;
static drbd_cmd_handler_f *drbd_opt_cmd_handler = NULL;

#if 0
	/* FIXME lge thinks the implementation of barrier handling via
	 * tcq is currently broken */
void drbd_set_recv_tcq(drbd_dev * mdev, int tcq_enabled)
{
// warning LGE "FIXME make drbd_cmd_handler a member of mdev"
	if(tcq_enabled &&
	   drbd_default_handler[Barrier] != receive_Barrier_tcq) {
		INFO("Enabling TCQ for barrier processing on backend.\n");
		drbd_default_handler[Barrier] = receive_Barrier_tcq;
	}

	if(!tcq_enabled &&
	   drbd_default_handler[Barrier] != receive_Barrier_usual) {
		INFO("Using conventional (non TCQ) barrier processing"
		     " on backend.\n");
		drbd_default_handler[Barrier] = receive_Barrier_usual;
	}
}
#endif

STATIC void drbdd(drbd_dev *mdev)
{
	drbd_cmd_handler_f handler;
	Drbd_Header *header = &mdev->data.rbuf.head;

	while (get_t_state(&mdev->receiver) == Running) {
		if (!drbd_recv_header(mdev,header))
			break;

		if (header->command < MAX_CMD)
			handler = drbd_cmd_handler[header->command];
		else if (MayIgnore < header->command && header->command < MAX_OPT_CMD)
			handler = drbd_opt_cmd_handler[header->command-MayIgnore];
		else if (header->command > MAX_OPT_CMD)
			handler = receive_skip;
		else
			handler = NULL;

		if (unlikely(!handler)) {
			ERR("unknown packet type %d, l: %d!\n",
			    header->command, header->length);
			drbd_force_state(mdev,NS(conn,ProtocolError));
			break;
		}
		if (unlikely(!handler(mdev,header))) {
			ERR("error receiving %s, l: %d!\n",
			    cmdname(header->command), header->length);
			drbd_force_state(mdev,NS(conn,ProtocolError));
			break;
		}

		dump_packet(mdev,mdev->data.socket,2,&mdev->data.rbuf, __FILE__, __LINE__);
	}
}

/* FIXME how should freeze-io be handled? */
STATIC void drbd_fail_pending_reads(drbd_dev *mdev)
{
	struct hlist_head *slot;
	struct hlist_node *n;
	drbd_request_t * req;
	struct list_head *le;
	LIST_HEAD(workset);
	int i;

	/*
	 * Application READ requests
	 */
	spin_lock_irq(&mdev->req_lock);
	for(i=0;i<APP_R_HSIZE;i++) {
		slot = mdev->app_reads_hash+i;
		hlist_for_each_entry(req, n, slot, colision) {
			list_add(&req->w.list, &workset);
		}
	}
	memset(mdev->app_reads_hash,0,APP_R_HSIZE*sizeof(void*));

	while(!list_empty(&workset)) {
		le = workset.next;
		req = list_entry(le, drbd_request_t, w.list);
		list_del(le);

		_req_mod(req, connection_lost_while_pending, 0);
	}
	spin_unlock_irq(&mdev->req_lock);
}

STATIC void drbd_disconnect(drbd_dev *mdev)
{
	struct drbd_work prev_work_done;
	enum fencing_policy fp;
	drbd_state_t os,ns;
	int rv=SS_UnknownError;

	D_ASSERT(mdev->state.conn < Connected);
	if (mdev->state.conn == StandAlone) return;
	/* FIXME verify that:
	 * the state change magic prevents us from becoming >= Connected again
	 * while we are still cleaning up.
	 */

	/* asender does not clean up anything. it must not interfere, either */
	drbd_thread_stop(&mdev->asender);

	down(&mdev->data.mutex);
	drbd_free_sock(mdev);
	up(&mdev->data.mutex);

	spin_lock_irq(&mdev->req_lock);
	_drbd_wait_ee_list_empty(mdev,&mdev->active_ee);
	_drbd_wait_ee_list_empty(mdev,&mdev->sync_ee);
	_drbd_clear_done_ee(mdev);
	_drbd_wait_ee_list_empty(mdev,&mdev->read_ee);
	reclaim_net_ee(mdev);
	spin_unlock_irq(&mdev->req_lock);

	/* FIXME: fail pending reads?
	 * when we are configured for freeze io,
	 * we could retry them once we un-freeze. */
	drbd_fail_pending_reads(mdev);

	/* We do not have data structures that would allow us to
	   get the rs_pending_cnt down to 0 again.
	   * On SyncTarget we do not have any data structures describing
	     the pending RSDataRequest's we have sent.
	   * On SyncSource there is no data structure that tracks
	     the RSDataReply blocks that we sent to the SyncTarget.
	   And no, it is not the sum of the reference counts in the
	   resync_LRU. The resync_LRU tracks the whole operation including
           the disk-IO, while the rs_pending_cnt only tracks the blocks
	   on the fly. */
	drbd_rs_cancel_all(mdev);
	mdev->rs_total=0;
	mdev->rs_failed=0;
	atomic_set(&mdev->rs_pending_cnt,0);
	wake_up(&mdev->misc_wait);

	/* make sure syncer is stopped and w_resume_next_sg queued */
	del_timer_sync(&mdev->resync_timer);
	set_bit(STOP_SYNC_TIMER,&mdev->flags);
	resync_timer_fn((unsigned long)mdev);

	/* wait for all w_e_end_data_req, w_e_end_rsdata_req, w_send_barrier,
	 * w_make_resync_request etc. which may still be on the worker queue
	 * to be "canceled" */
	set_bit(WORK_PENDING,&mdev->flags);
	prev_work_done.cb = w_prev_work_done;
	drbd_queue_work(&mdev->data.work,&prev_work_done);
	wait_event(mdev->misc_wait, !test_bit(WORK_PENDING,&mdev->flags));

	if ( mdev->p_uuid ) {
		kfree(mdev->p_uuid);
		mdev->p_uuid = NULL;
	}

	/* queue cleanup for the worker.
	 * FIXME this should go into after_state_ch  */
	if (!mdev->state.susp)
		tl_clear(mdev);

	INFO("Connection closed\n");

	drbd_md_sync(mdev);

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->dc.fencing;
		dec_local(mdev);
	}

	if ( mdev->state.role == Primary ) {
		if( fp >= Resource &&
		    mdev->state.pdsk >= DUnknown ) {
			drbd_disks_t nps = drbd_try_outdate_peer(mdev);
			drbd_request_state(mdev,NS(pdsk,nps));
		}
	}

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	if ( os.conn >= Unconnected ) {
		// Do not restart in case we are Disconnecting
		ns = os;
		ns.conn = Unconnected;
		rv=_drbd_set_state(mdev,ns,ChgStateVerbose);
		ns = mdev->state;
	}
	spin_unlock_irq(&mdev->req_lock);
	if (rv == SS_Success) {
		after_state_ch(mdev,os,ns,ChgStateVerbose);
	}

	if(os.conn == Disconnecting) {
		wait_event( mdev->misc_wait,atomic_read(&mdev->net_cnt) == 0 );
		if(mdev->ee_hash) {
			kfree(mdev->ee_hash);
			mdev->ee_hash = NULL;
			mdev->ee_hash_s = 0;
		}

		if(mdev->tl_hash) {
			kfree(mdev->tl_hash);
			mdev->tl_hash = NULL;
			mdev->tl_hash_s = 0;
		}
		if(mdev->cram_hmac_tfm) {
			crypto_free_hash(mdev->cram_hmac_tfm);
			mdev->cram_hmac_tfm = NULL;
		}
		kfree(mdev->net_conf);
		mdev->net_conf=NULL;
		drbd_request_state(mdev, NS(conn,StandAlone));
	}

	/* they do trigger all the time.
	 * hm. why won't tcp release the page references,
	 * we already released the socket!?
	D_ASSERT(atomic_read(&mdev->pp_in_use) == 0);
	D_ASSERT(list_empty(&mdev->net_ee));
	 */
	D_ASSERT(list_empty(&mdev->read_ee));
	D_ASSERT(list_empty(&mdev->active_ee));
	D_ASSERT(list_empty(&mdev->sync_ee));
	D_ASSERT(list_empty(&mdev->done_ee));

	/* ok, no more ee's on the fly, it is safe to reset the epoch_size */
	mdev->epoch_size = 0;
}

/*
 * we hereby assure that we always support the drbd dialects
 * PRO_VERSION and (PRO_VERSION -1), allowing for rolling upgrades
 *
 * feature flags and the reserved array should be enough room for future
 * enhancements of the handshake protocol, and possible plugins...
 *
 * for now, they are expected to be zero, but ignored.
 */
int drbd_send_handshake(drbd_dev *mdev)
{
	// ASSERT current == mdev->receiver ...
	Drbd_HandShake_Packet *p = &mdev->data.sbuf.HandShake;
	int ok;

	if (down_interruptible(&mdev->data.mutex)) {
		ERR("interrupted during initial handshake\n");
		return 0; /* interrupted. not ok. */
	}
	/* FIXME do we need to verify this here? */
	if (mdev->data.socket == NULL) {
		up(&mdev->data.mutex);
		return 0;
	}

	memset(p,0,sizeof(*p));
	p->protocol_version = cpu_to_be32(PRO_VERSION);
	ok = _drbd_send_cmd( mdev, mdev->data.socket, HandShake,
	                     (Drbd_Header *)p, sizeof(*p), 0 );
	up(&mdev->data.mutex);
	return ok;
}

/*
 * return values:
 *   1 yess, we have a valid connection
 *   0 oops, did not work out, please try again
 *  -1 peer talks different language,
 *     no point in trying again, please go standalone.
 */
STATIC int drbd_do_handshake(drbd_dev *mdev)
{
	// ASSERT current == mdev->receiver ...
	Drbd_HandShake_Packet *p = &mdev->data.rbuf.HandShake;
	const int expect = sizeof(Drbd_HandShake_Packet)-sizeof(Drbd_Header);
	int rv;

	rv = drbd_send_handshake(mdev);
	if (!rv) return 0;

	rv = drbd_recv_header(mdev,&p->head);
	if (!rv) return 0;

	if (p->head.command != HandShake) {
		ERR( "expected HandShake packet, received: %s (0x%04x)\n",
		     cmdname(p->head.command), p->head.command );
		return -1;
	}

	if (p->head.length != expect) {
		ERR( "expected HandShake length: %u, received: %u\n",
		     expect, p->head.length );
		return -1;
	}

	rv = drbd_recv(mdev, &p->head.payload, expect);

	if (rv != expect) {
		ERR("short read receiving handshake packet: l=%u\n", rv);
		return 0;
	}

	dump_packet(mdev,mdev->data.socket,2,&mdev->data.rbuf, __FILE__, __LINE__);

	p->protocol_version = be32_to_cpu(p->protocol_version);

	if ( p->protocol_version == PRO_VERSION ||
	     p->protocol_version == (PRO_VERSION+1) ) {
		if (p->protocol_version == (PRO_VERSION+1)) {
			WARN( "You should upgrade me! "
			      "Peer wants protocol version: %u\n",
			      p->protocol_version );
		}
		INFO( "Handshake successful: DRBD Network Protocol version %u\n",
		      PRO_VERSION );
	} /* else if ( p->protocol_version == (PRO_VERSION-1) ) {
		// not yet; but next time :)
		INFO( "Handshake successful: DRBD Protocol version %u\n",
		      (PRO_VERSION-1) );
		... do some remapping of defaults and jump tables here ...
	} */ else {
		ERR( "incompatible DRBD dialects: "
		     "I support %u, peer wants %u\n",
		     PRO_VERSION, p->protocol_version );
		return -1;
	}

	return 1;
}

#if !defined(CONFIG_CRYPTO_HMAC) && !defined(CONFIG_CRYPTO_HMAC_MODULE)
STATIC int drbd_do_auth(drbd_dev *mdev)
{
	ERR( "This kernel was build without CONFIG_CRYPTO_HMAC.\n");
	ERR( "You need to disable 'cram-hmac-alg' in drbd.conf.\n");
	return 0;
}
#else
#define CHALLENGE_LEN 64
STATIC int drbd_do_auth(drbd_dev *mdev)
{
	char my_challenge[CHALLENGE_LEN];  /* 64 Bytes... */
	struct scatterlist sg;
	char *response = NULL;
	char *right_response = NULL;
	char *peers_ch = NULL;
	Drbd_Header p;
	unsigned int key_len = strlen(mdev->net_conf->shared_secret);
	unsigned int resp_size;
	struct hash_desc desc;
	int rv;

	desc.tfm=mdev->cram_hmac_tfm;
	desc.flags=0;

	rv = crypto_hash_setkey(mdev->cram_hmac_tfm,
				(u8*)mdev->net_conf->shared_secret, key_len);
	if(rv) {
		ERR("crypto_hash_setkey() failed with %d\n",rv);
		rv = 0;
		goto fail;
	}

	get_random_bytes(my_challenge, CHALLENGE_LEN);

	rv = drbd_send_cmd2(mdev,AuthChallenge,my_challenge,CHALLENGE_LEN);
	if (!rv) goto fail;

	rv = drbd_recv_header(mdev,&p);
	if (!rv) goto fail;

	if (p.command != AuthChallenge) {
		ERR( "expected AuthChallenge packet, received: %s (0x%04x)\n",
		     cmdname(p.command), p.command );
		rv = 0;
		goto fail;
	}

	if (p.length > CHALLENGE_LEN*2 ) {
		ERR( "expected AuthChallenge payload too big.\n");
		rv = 0;
		goto fail;
	}

	peers_ch = kmalloc(p.length,GFP_KERNEL);
	if(peers_ch == NULL) {
		ERR("kmalloc of peers_ch failed\n");
		rv = 0;
		goto fail;
	}

	rv = drbd_recv(mdev, peers_ch, p.length);

	if (rv != p.length) {
		ERR("short read AuthChallenge: l=%u\n", rv);
		rv = 0;
		goto fail;
	}

	resp_size = crypto_hash_digestsize(mdev->cram_hmac_tfm);
	response = kmalloc(resp_size,GFP_KERNEL);
	if(response == NULL) {
		ERR("kmalloc of response failed\n");
		rv = 0;
		goto fail;
	}

	sg_init_table(&sg, 1);
	sg_set_buf(&sg, peers_ch, p.length);

	rv = crypto_hash_digest(&desc, &sg, sg.length, response);
	if(rv) {
		ERR( "crypto_hash_digest() failed with %d\n",rv);
		rv = 0;
		goto fail;
	}

	rv = drbd_send_cmd2(mdev,AuthResponse,response,resp_size);
	if (!rv) goto fail;

	rv = drbd_recv_header(mdev,&p);
	if (!rv) goto fail;

	if (p.command != AuthResponse) {
		ERR( "expected AuthResponse packet, received: %s (0x%04x)\n",
		     cmdname(p.command), p.command );
		rv = 0;
		goto fail;
	}

	if (p.length != resp_size ) {
		ERR( "expected AuthResponse payload of wrong size\n" );
		rv = 0;
		goto fail;
	}

	rv = drbd_recv(mdev, response , resp_size);

	if (rv != resp_size) {
		ERR("short read receiving AuthResponse: l=%u\n", rv);
		rv = 0;
		goto fail;
	}

	right_response = kmalloc(resp_size,GFP_KERNEL);
	if(response == NULL) {
		ERR("kmalloc of right_response failed\n");
		rv = 0;
		goto fail;
	}

	sg_set_buf(&sg, my_challenge, CHALLENGE_LEN);

	rv = crypto_hash_digest(&desc, &sg, sg.length, right_response);
	if(rv) {
		ERR( "crypto_hash_digest() failed with %d\n",rv);
		rv = 0;
		goto fail;
	}

	rv = ! memcmp(response,right_response,resp_size);

	if(rv) {
		INFO("Peer authenticated using %d bytes of '%s' HMAC\n",
		     resp_size,mdev->net_conf->cram_hmac_alg);
	}

 fail:
	if(peers_ch) kfree(peers_ch);
	if(response) kfree(response);
	if(right_response) kfree(right_response);

	return rv;
}
#endif

int drbdd_init(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	int minor = mdev_to_minor(mdev);
	int h;

	sprintf(current->comm, "drbd%d_receiver", minor);

	INFO("receiver (re)started\n");

	do {
		h = drbd_connect(mdev);
		if (h == 0) {
			drbd_disconnect(mdev);
			schedule_timeout(HZ);
		}
		if( h == -1 ) {
			WARN("Discarding network configuration.\n");
			drbd_force_state(mdev,NS(conn,Disconnecting));
		}
	} while ( h == 0 );

	if( h > 0 ) {
		if(inc_net(mdev)) {
			drbdd(mdev);
			dec_net(mdev);
		}
	}

	drbd_disconnect(mdev);

	// Ensure that the thread state fits to our connection state.
	if( mdev->state.conn == Unconnected ) {
		ERR_IF( mdev->receiver.t_state != Restarting )
			drbd_thread_restart_nowait(&mdev->receiver);
	} else if( mdev->state.conn == StandAlone ) {
		ERR_IF( mdev->receiver.t_state != Exiting )
			drbd_thread_stop_nowait(&mdev->receiver);
	}

	INFO("receiver terminated\n");
	return 0;
}

/* ********* acknowledge sender ******** */

STATIC int got_RqSReply(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_RqS_Reply_Packet *p = (Drbd_RqS_Reply_Packet*)h;

	int retcode = be32_to_cpu(p->retcode);

	if(retcode >= SS_Success) {
		set_bit(CL_ST_CHG_SUCCESS,&mdev->flags);
	} else {
		set_bit(CL_ST_CHG_FAIL,&mdev->flags);
		ERR("Requested state change failed by peer: %s\n",
		    set_st_err_name(retcode));
	}
	wake_up(&mdev->state_wait);

	return TRUE;
}

STATIC int got_Ping(drbd_dev *mdev, Drbd_Header* h)
{
	return drbd_send_ping_ack(mdev);

}

STATIC int got_PingAck(drbd_dev *mdev, Drbd_Header* h)
{
	// restore idle timeout
	mdev->meta.socket->sk->sk_rcvtimeo = mdev->net_conf->ping_int*HZ;

	return TRUE;
}

STATIC int got_BlockAck(drbd_dev *mdev, Drbd_Header* h)
{
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);

	update_peer_seq(mdev,be32_to_cpu(p->seq_num));

	if( is_syncer_block_id(p->block_id)) {
		drbd_set_in_sync(mdev,sector,blksize);
		dec_rs_pending(mdev);
	} else {
		spin_lock_irq(&mdev->req_lock);
		req = _ack_id_to_req(mdev, p->block_id, sector);

		if (unlikely(!req)) {
			spin_unlock_irq(&mdev->req_lock);
			ERR("Got a corrupt block_id/sector pair(2).\n");
			return FALSE;
		}

		switch (be16_to_cpu(h->command)) {
		case RSWriteAck:
			D_ASSERT(mdev->net_conf->wire_protocol == DRBD_PROT_C);
			_req_mod(req,write_acked_by_peer_and_sis,0);
			break;
		case WriteAck:
			D_ASSERT(mdev->net_conf->wire_protocol == DRBD_PROT_C);
			_req_mod(req,write_acked_by_peer,0);
			break;
		case RecvAck:
			D_ASSERT(mdev->net_conf->wire_protocol == DRBD_PROT_B);
			_req_mod(req,recv_acked_by_peer,0);
			break;
		case DiscardAck:
			D_ASSERT(mdev->net_conf->wire_protocol == DRBD_PROT_C);
			ALERT("Got DiscardAck packet %llus +%u!"
			      " DRBD is not a random data generator!\n",
			      (unsigned long long)req->sector, req->size);
			_req_mod(req, conflict_discarded_by_peer, 0);
			break;
		default:
			D_ASSERT(0);
		}
		spin_unlock_irq(&mdev->req_lock);
	}
	/* dec_ap_pending is handled within _req_mod */

	return TRUE;
}

STATIC int got_NegAck(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;
	sector_t sector = be64_to_cpu(p->sector);
	drbd_request_t *req;

	if (DRBD_ratelimit(5*HZ,5))
		WARN("Got NegAck packet. Peer is in troubles?\n");

	update_peer_seq(mdev,be32_to_cpu(p->seq_num));

	if(is_syncer_block_id(p->block_id)) {
		sector_t sector = be64_to_cpu(p->sector);
		int size = be32_to_cpu(p->blksize);

		dec_rs_pending(mdev);

		drbd_rs_failed_io(mdev, sector, size);
	} else {
		req = _ack_id_to_req(mdev, p->block_id, sector);

		if (unlikely(!req)) {
			spin_unlock_irq(&mdev->req_lock);
			ERR("Got a corrupt block_id/sector pair(2).\n");
			return FALSE;
		}

		req_mod(req, neg_acked, 0);
	}

	return TRUE;
}

STATIC int got_NegDReply(drbd_dev *mdev, Drbd_Header* h)
{
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;
	sector_t sector = be64_to_cpu(p->sector);

	spin_lock_irq(&mdev->req_lock);
	req = _ar_id_to_req(mdev,p->block_id, sector);
	if (unlikely(!req)) {
		spin_unlock_irq(&mdev->req_lock);
		ERR("Got a corrupt block_id/sector pair(3).\n");
		return FALSE;
	}

	/* FIXME explicitly warn if protocol != C */

	ERR("Got NegDReply; Sector %llus, len %u; Fail original request.\n",
	    (unsigned long long)sector,be32_to_cpu(p->blksize));

	_req_mod(req, neg_acked, 0);
	spin_unlock_irq(&mdev->req_lock);

// warning LGE "ugly and wrong"
	drbd_khelper(mdev,"pri-on-incon-degr");

	return TRUE;
}

STATIC int got_NegRSDReply(drbd_dev *mdev, Drbd_Header* h)
{
	sector_t sector;
	int size;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	sector = be64_to_cpu(p->sector);
	size = be32_to_cpu(p->blksize);
	D_ASSERT(p->block_id == ID_SYNCER);

	dec_rs_pending(mdev);

	if(inc_local_if_state(mdev,Failed)) {
		drbd_rs_complete_io(mdev,sector);
		drbd_rs_failed_io(mdev, sector, size);
		dec_local(mdev);
	}

	return TRUE;
}

STATIC int got_BarrierAck(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_BarrierAck_Packet *p = (Drbd_BarrierAck_Packet*)h;

	tl_release(mdev,p->barrier,be32_to_cpu(p->set_size));
	dec_ap_pending(mdev);

	return TRUE;
}

struct asender_cmd {
	size_t pkt_size;
	int (*process)(drbd_dev *mdev, Drbd_Header* h);
};

int drbd_asender(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	Drbd_Header *h = &mdev->meta.rbuf.head;

	int rv,len;
	void *buf    = h;
	int received = 0;
	int expect   = sizeof(Drbd_Header);
	int cmd      = -1;
	int empty;

	static struct asender_cmd asender_tbl[] = {
		[Ping]      ={ sizeof(Drbd_Header),           got_Ping },
		[PingAck]   ={ sizeof(Drbd_Header),           got_PingAck },
		[RecvAck]   ={ sizeof(Drbd_BlockAck_Packet),  got_BlockAck },
		[WriteAck]  ={ sizeof(Drbd_BlockAck_Packet),  got_BlockAck },
		[RSWriteAck]={ sizeof(Drbd_BlockAck_Packet),  got_BlockAck },
		[DiscardAck]={ sizeof(Drbd_BlockAck_Packet),  got_BlockAck },
		[NegAck]    ={ sizeof(Drbd_BlockAck_Packet),  got_NegAck },
		[NegDReply] ={ sizeof(Drbd_BlockAck_Packet),  got_NegDReply },
		[NegRSDReply]={sizeof(Drbd_BlockAck_Packet),  got_NegRSDReply},
		[BarrierAck]={ sizeof(Drbd_BarrierAck_Packet),got_BarrierAck },
		[StateChgReply]={sizeof(Drbd_RqS_Reply_Packet),got_RqSReply },
	};

	sprintf(current->comm, "drbd%d_asender", mdev_to_minor(mdev));

	current->policy = SCHED_RR;  /* Make this a realtime task! */
	current->rt_priority = 2;    /* more important than all other tasks */

	while (get_t_state(thi) == Running) {
		if (test_and_clear_bit(SEND_PING, &mdev->flags)) {
			ERR_IF(!drbd_send_ping(mdev)) goto err;
			mdev->meta.socket->sk->sk_rcvtimeo =
				mdev->net_conf->ping_timeo*HZ/10;
		}

		while(1) {
			if (!drbd_process_done_ee(mdev)) {
				ERR("process_done_ee() = NOT_OK\n");
				goto err;
			}
			set_bit(SIGNAL_ASENDER, &mdev->flags);
			spin_lock_irq(&mdev->req_lock);
			empty = list_empty(&mdev->done_ee);
			spin_unlock_irq(&mdev->req_lock);
			if(empty) break;
			clear_bit(SIGNAL_ASENDER, &mdev->flags);
			flush_signals(current);
		}
		drbd_tcp_flush(mdev->meta.socket);

		rv = drbd_recv_short(mdev, mdev->meta.socket,
				     buf,expect-received);
		clear_bit(SIGNAL_ASENDER, &mdev->flags);

		flush_signals(current);

		drbd_tcp_cork(mdev->meta.socket);

		/* Note:
		 * -EINTR        (on meta) we got a signal
		 * -EAGAIN       (on meta) rcvtimeo expired
		 * -ECONNRESET   other side closed the connection
		 * -ERESTARTSYS  (on data) we got a signal
		 * rv <  0       other than above: unexpected error!
		 * rv == expected: full header or command
		 * rv <  expected: "woken" by signal during receive
		 * rv == 0       : "connection shut down by peer"
		 */
		if (likely(rv > 0)) {
			received += rv;
			buf      += rv;
		} else if (rv == 0) {
			ERR("meta connection shut down by peer.\n");
			goto err;
		} else if (rv == -EAGAIN) {
			if( mdev->meta.socket->sk->sk_rcvtimeo ==
			    mdev->net_conf->ping_timeo*HZ/10 ) {
				ERR("PingAck did not arrive in time.\n");
				goto err;
			}
			set_bit(SEND_PING,&mdev->flags);
			continue;
		} else if (rv == -EINTR) {
			continue;
		} else {
			ERR("sock_recvmsg returned %d\n", rv);
			goto err;
		}

		if (received == expect && cmd == -1 ) {
			cmd = be16_to_cpu(h->command);
			len = be16_to_cpu(h->length);
			if (unlikely( h->magic != BE_DRBD_MAGIC )) {
				ERR("magic?? on meta m: 0x%lx c: %d l: %d\n",
				    (long)be32_to_cpu(h->magic),
				    h->command, h->length);
				goto err;
			}
			expect = asender_tbl[cmd].pkt_size;
			ERR_IF(len != expect-sizeof(Drbd_Header)) {
				dump_packet(mdev,mdev->meta.socket,1,(void*)h, __FILE__, __LINE__);
				DUMPI(expect);
			}
		}
		if(received == expect) {
			D_ASSERT(cmd != -1);
			dump_packet(mdev,mdev->meta.socket,1,(void*)h, __FILE__, __LINE__);
			if(!asender_tbl[cmd].process(mdev,h)) goto err;

			buf      = h;
			received = 0;
			expect   = sizeof(Drbd_Header);
			cmd      = -1;
		}
	} //while

	if(0) {
	err:
		clear_bit(SIGNAL_ASENDER, &mdev->flags);
		drbd_force_state(mdev,NS(conn,NetworkFailure));
	}

	D_ASSERT(mdev->state.conn < Connected);
	INFO("asender terminated\n");

	return 0;
}
