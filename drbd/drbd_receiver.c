/*
-*- linux-c -*-
   drbd_receiver.c
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


#include <linux/config.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <net/sock.h>

#include <linux/tcp.h>

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
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

#define is_syncer_blk(A,B) ((B)==ID_SYNCER)

#ifdef __arch_um__
void *to_virt(unsigned long phys)
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
			       (int)(mdev-drbd_conf),t);
			break;
		}
		if( forward++ > CHECK_LIST_LIMIT ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: %s forward > 1000\n",
			       (int)(mdev-drbd_conf),t);
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
			       (int)(mdev-drbd_conf),t);
			break;
		}
		if( backward++ > CHECK_LIST_LIMIT ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: %s backward > 1000\n",
			       (int)(mdev-drbd_conf),t);
			break;
		}
	} while(le != list);

	if(forward != backward) {
		printk(KERN_ERR DEVICE_NAME "%d: forward=%d, backward=%d\n",
		       (int)(mdev-drbd_conf),forward,backward);
	}
}
#endif

#if 0
STATIC inline int is_syncer_blk(drbd_dev *mdev, u64 block_id)
{
	if ( block_id == ID_SYNCER ) return 1;
	/* Use this code if you are working with a VIA based mboard :) */
	if ( (long)block_id == (long)-1) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: strange block_id %lx%lx\n",(int)(mdev-drbd_conf),
		       (unsigned long)(block_id>>32),
		       (unsigned long)block_id);
		return 1;
	}
	return 0;
}
#endif //PARANOIA

#define GFP_TRY	( __GFP_HIGHMEM | __GFP_NOWARN )

STATIC int drbd_process_ee(drbd_dev *mdev, int be_sleepy);

/**
 * drbd_bp_alloc: Returns a page. Fails only if a signal comes in.
 */
STATIC struct page * drbd_pp_alloc(drbd_dev *mdev, unsigned int gfp_mask)
{
	struct page *page;
	DEFINE_WAIT(wait);

	if ( drbd_pp_vacant == 
	     (DRBD_MAX_SEGMENT_SIZE/PAGE_SIZE)*minor_count/2 ) {
		drbd_kick_lo(mdev);
	}

	spin_lock(&drbd_pp_lock);
	if ( (page = drbd_pp_pool) ) {
		drbd_pp_pool = (struct page*)page->private;
		drbd_pp_vacant--;
	}
	spin_unlock(&drbd_pp_lock);
	if ( page ) goto got_page;

	drbd_process_ee(mdev,1);
 
	spin_lock(&drbd_pp_lock);
	if ( (page = drbd_pp_pool) ) {
		drbd_pp_pool = (struct page*)page->private;
		drbd_pp_vacant--;
	}
	spin_unlock(&drbd_pp_lock);
	if ( page ) goto got_page;

	for (;;) {
		prepare_to_wait(&drbd_pp_wait, &wait, TASK_INTERRUPTIBLE);

		spin_lock(&drbd_pp_lock);
		if ( (page = drbd_pp_pool) ) {
			drbd_pp_pool = (struct page*)page->private;
			drbd_pp_vacant--;
		}
		spin_unlock(&drbd_pp_lock);
		if ( page ) break;

		if ( atomic_read(&mdev->pp_in_use) < mdev->conf.max_buffers ) {
			if( (page = alloc_page(GFP_TRY)) ) break;
		}
		drbd_kick_lo(mdev);
		schedule();
		finish_wait(&drbd_pp_wait, &wait);
		if (signal_pending(current)) {
			WARN("drbd_pp_alloc interrupted!\n");
			return NULL;
		}
		// finish wait is inside, so that we are TASK_RUNNING 
		// in _drbd_process_ee (which might sleep by itself.)
		drbd_process_ee(mdev,1);
	}
	finish_wait(&drbd_pp_wait, &wait); 

 got_page:
	atomic_inc(&mdev->pp_in_use);

	return page;
}

STATIC void drbd_pp_free(drbd_dev *mdev,struct page *page)
{
	atomic_dec(&mdev->pp_in_use);

	spin_lock(&drbd_pp_lock);
	if (drbd_pp_vacant > (DRBD_MAX_SEGMENT_SIZE/PAGE_SIZE)*minor_count) {
		__free_page(page);
	} else {
		page->private = (unsigned long)drbd_pp_pool;
		drbd_pp_pool = page;
		drbd_pp_vacant++;
	}
	spin_unlock(&drbd_pp_lock);

	wake_up(&drbd_pp_wait);
}

/*
You need to hold the ee_lock:
 drbd_free_ee()
 _drbd_process_ee()

You must not have the ee_lock:
 _drbd_alloc_ee()
 drbd_alloc_ee()
 drbd_init_ee()
 drbd_release_ee()
 drbd_ee_fix_bhs()
 drbd_process_ee()
 drbd_clear_done_ee()
 drbd_wait_ee()
*/

struct Tl_epoch_entry* drbd_alloc_ee(drbd_dev *mdev, 
				     sector_t sector,
				     unsigned int data_size,
				     unsigned int gfp_mask)
{
	struct Tl_epoch_entry* e;
	struct bio_vec *bvec;
	struct page *page;
	struct bio *bio;
	unsigned int ds;
	int bio_add,i;

	e = kmem_cache_alloc(drbd_ee_cache, gfp_mask);
	if (!e) return NULL;

	bio = bio_alloc(GFP_KERNEL, div_ceil(data_size,PAGE_SIZE));
	if (!bio) goto fail1;

	bio->bi_bdev = mdev->backing_bdev;
	bio->bi_sector = sector;

	ds = data_size;
	while(ds) {
		page = drbd_pp_alloc(mdev, gfp_mask);
		if (!page) goto fail2;
		bio_add=bio_add_page(bio, page, min_t(int, ds, PAGE_SIZE), 0);
		D_ASSERT(bio_add);
		ds -= min_t(int, ds, PAGE_SIZE);
	}

	bio->bi_private = e;
	e->mdev = mdev;
	e->ee_sector = sector;
	e->ee_size = bio->bi_size;
	D_ASSERT( data_size == bio->bi_size);
	e->private_bio = bio;
	e->block_id = ID_VACANT;
	INIT_HLIST_NODE(&e->colision);

	return e;
 fail2:
	__bio_for_each_segment(bvec, bio, i, 0) {
		drbd_pp_free(mdev,bvec->bv_page);
	}
	bio_put(bio);
 fail1:
	kmem_cache_free(drbd_ee_cache, e);
	
	return NULL;
}

void drbd_free_ee(drbd_dev *mdev, struct Tl_epoch_entry* e)
{
	struct bio *bio=e->private_bio;
	struct bio_vec *bvec;
	int i;

	__bio_for_each_segment(bvec, bio, i, 0) {
		drbd_pp_free(mdev,bvec->bv_page);
	}

	bio_put(bio);

	kmem_cache_free(drbd_ee_cache, e);
}

int drbd_release_ee(drbd_dev *mdev,struct list_head* list)
{
	int count=0;
	struct Tl_epoch_entry* e;
	struct list_head *le;

	spin_lock_irq(&mdev->ee_lock);
	while(!list_empty(list)) {
		le = list->next;
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		drbd_free_ee(mdev,e);
		count++;
	}
	spin_unlock_irq(&mdev->ee_lock);

	return count;
}

STATIC void reclaim_net_ee(drbd_dev *mdev)
{
	struct Tl_epoch_entry *e;
	struct list_head *le,*tle;

	/* The EEs are always appended to the end of the list, since
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


/* It is important that the head list is really empty when returning,
   from this function. Note, this function is called from all three
   threads (receiver, worker and asender). To ensure this I only allow
   one thread at a time in the body of the function */
STATIC int _drbd_process_ee(drbd_dev *mdev, int be_sleepy)
{
	struct Tl_epoch_entry *e;
	struct list_head *head = &mdev->done_ee;
	struct list_head *le;
	int ok=1;
	int got_sig;

	MUST_HOLD(&mdev->ee_lock);

	reclaim_net_ee(mdev);

	if( test_and_set_bit(PROCESS_EE_RUNNING,&mdev->flags) ) {
		if(!be_sleepy) {
			clear_bit(PROCESS_EE_RUNNING,&mdev->flags);
			return 3;
		}
		spin_unlock_irq(&mdev->ee_lock);
		got_sig = wait_event_interruptible(mdev->ee_wait,
		       test_and_set_bit(PROCESS_EE_RUNNING,&mdev->flags) == 0);
		spin_lock_irq(&mdev->ee_lock);
		if(got_sig) return 2;
	}

	while(!list_empty(head)) {
		le = head->next;
		list_del(le);
		spin_unlock_irq(&mdev->ee_lock);
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		ok = ok && e->w.cb(mdev,&e->w,0);
		drbd_free_ee(mdev,e);
		spin_lock_irq(&mdev->ee_lock);
	}

	clear_bit(PROCESS_EE_RUNNING,&mdev->flags);
	wake_up(&mdev->ee_wait);

	return ok;
}

STATIC int drbd_process_ee(drbd_dev *mdev, int be_sleepy)
{
	int rv;
	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_ee(mdev,be_sleepy);
	spin_unlock_irq(&mdev->ee_lock);
	return rv;
}

STATIC void drbd_clear_done_ee(drbd_dev *mdev)
{
	struct list_head *le;
	struct Tl_epoch_entry *e;
	int n = 0;

	spin_lock_irq(&mdev->ee_lock);

	reclaim_net_ee(mdev);

	while(!list_empty(&mdev->done_ee)) {
		le = mdev->done_ee.next;
		list_del(le);
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   is_syncer_blk(mdev,e->block_id)) {
			++n;
		}
		drbd_free_ee(mdev,e);
	}

	spin_unlock_irq(&mdev->ee_lock);

	sub_unacked(mdev, n);
}


static inline int _wait_ee_cond(struct Drbd_Conf* mdev,struct list_head *head)
{
	int rv;
	spin_lock_irq(&mdev->ee_lock);
	rv = list_empty(head);
	spin_unlock_irq(&mdev->ee_lock);
	if(!rv) drbd_kick_lo(mdev);
	return rv;
}

void drbd_wait_ee(drbd_dev *mdev,struct list_head *head)
{
	wait_event(mdev->ee_wait,_wait_ee_cond(mdev,head));
}

STATIC struct socket* drbd_accept(drbd_dev *mdev,struct socket* sock)
{
	struct socket *newsock;
	int err = 0;

	err = sock->ops->listen(sock, 5);
	if (err)
		goto out;

	if (sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &newsock))
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

STATIC int drbd_recv_short(drbd_dev *mdev, void *buf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	int rv;

	if (unlikely(drbd_did_panic == DRBD_MAGIC)) {
		drbd_suicide();
	}

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

	rv = sock_recvmsg(mdev->meta.socket, &msg, size, msg.msg_flags);

	set_fs(oldfs);

	return rv;
}

int drbd_recv(drbd_dev *mdev,void *buf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	int rv;

	if (unlikely(drbd_did_panic == DRBD_MAGIC)) {
		drbd_suicide();
	}

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

	if(rv != size) {
		drbd_force_state(mdev,NS(conn,BrokenPipe));
		drbd_thread_restart_nowait(&mdev->receiver);
	}

	return rv;
}

STATIC struct socket *drbd_try_connect(drbd_dev *mdev)
{
	int err;
	struct socket *sock;

	err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
	if (err) {
		ERR("sock_creat(..)=%d\n", err);
	}
	sock->sk->sk_rcvtimeo =
	sock->sk->sk_sndtimeo =  mdev->conf.try_connect_int*HZ;

	err = sock->ops->connect(sock,
				 (struct sockaddr *) mdev->conf.other_addr,
				 mdev->conf.other_addr_len, 0);

	if (err) {
		sock_release(sock);
		sock = NULL;
	}
	return sock;
}

STATIC struct socket *drbd_wait_for_connect(drbd_dev *mdev)
{
	int err;
	struct socket *sock,*sock2;

	err = sock_create(AF_INET, SOCK_STREAM, 0, &sock2);
	if (err) {
		ERR("sock_creat(..)=%d\n", err);
		// FIXME return NULL ?
	}

	sock2->sk->sk_reuse    = 1; /* SO_REUSEADDR */
	sock2->sk->sk_rcvtimeo =
	sock2->sk->sk_sndtimeo =  mdev->conf.try_connect_int*HZ;

	err = sock2->ops->bind(sock2,
			      (struct sockaddr *) mdev->conf.my_addr,
			      mdev->conf.my_addr_len);
	if (err) {
		ERR("Unable to bind (%d)\n", err);
		sock_release(sock2);
		drbd_force_state(mdev,NS(conn,Unconnected));
		return 0;
	}

	sock = drbd_accept(mdev,sock2);
	sock_release(sock2);

	return sock;
}

STATIC int drbd_do_handshake(drbd_dev *mdev);
STATIC int drbd_do_auth(drbd_dev *mdev);

int drbd_connect(drbd_dev *mdev)
{
	struct socket *sock,*msock;

	D_ASSERT(mdev->state.s.conn > StandAlone);
	D_ASSERT(!mdev->data.socket);

	if(drbd_request_state(mdev,NS(conn,WFConnection)) <= 0 ) return 0;

	clear_bit(UNIQUE, &mdev->flags);
	while(1) {
		sock=drbd_try_connect(mdev);
		if(sock) {
			msock=drbd_wait_for_connect(mdev);
			if(msock) {
				set_bit(UNIQUE, &mdev->flags);
				break;
			}
			else sock_release(sock);
		} else {
			sock=drbd_wait_for_connect(mdev);
			if(sock) {
				int retry;
				for (retry=1; retry <= 10; retry++) {
					// give the other side time to call
					// bind() & listen()
					set_current_state(TASK_INTERRUPTIBLE);
					schedule_timeout(HZ / 10);
					msock=drbd_try_connect(mdev);
					if(msock) goto connected;
					ERR("msock try_connect %d\n",retry);
				}
				sock_release(sock);
			}
		}
		if(mdev->state.s.conn == Unconnected) return 0;
		if(signal_pending(current)) {
			flush_signals(current);
			smp_rmb();
			if (get_t_state(&mdev->receiver) == Exiting)
				return 0;
		}
	}

 connected:

	msock->sk->sk_reuse=1; /* SO_REUSEADDR */
	sock->sk->sk_reuse=1; /* SO_REUSEADDR */

	/* to prevent oom deadlock... */
	/* The default allocation priority was GFP_KERNEL */
	sock->sk->sk_allocation = GFP_DRBD;
	msock->sk->sk_allocation = GFP_DRBD;

	sock->sk->sk_priority=TC_PRIO_BULK;
	tcp_sk(sock->sk)->nonagle = 0;
	// FIXME fold to limits. should be done in drbd_ioctl
	sock->sk->sk_sndbuf = mdev->conf.sndbuf_size;
	sock->sk->sk_rcvbuf = mdev->conf.sndbuf_size;
	/* NOT YET ...
	 * sock->sk->sk_sndtimeo = mdev->conf.timeout*HZ/20;
	 * sock->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;
	 * first set it to the HandShake timeout, wich is hardcoded for now: */
	sock->sk->sk_sndtimeo =
	sock->sk->sk_rcvtimeo = 2*HZ;
	sock->sk->sk_userlocks |= SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK;

	msock->sk->sk_priority=TC_PRIO_INTERACTIVE;
	tcp_sk(sock->sk)->nonagle = 1;
	msock->sk->sk_sndbuf = 2*32767;
	msock->sk->sk_sndtimeo = mdev->conf.timeout*HZ/20;
	msock->sk->sk_rcvtimeo = mdev->conf.ping_int*HZ;

	mdev->data.socket = sock;
	mdev->meta.socket = msock;
	mdev->last_received = jiffies;

	if(drbd_request_state(mdev,NS(conn,WFReportParams)) <= 0) return 0;
	D_ASSERT(mdev->asender.task == NULL);

	if (!drbd_do_handshake(mdev)) {
		return 0;
	}

	if ( mdev->cram_hmac_tfm ) {
		if (!drbd_do_auth(mdev)) {
			ERR("Authentication of peer failed\n");
			return 0;
		}
	}

	sock->sk->sk_sndtimeo = mdev->conf.timeout*HZ/20;
	sock->sk->sk_rcvtimeo = MAX_SCHEDULE_TIMEOUT;

	atomic_set(&mdev->packet_seq,0);
	mdev->peer_seq=0;

	drbd_thread_start(&mdev->asender);

	drbd_send_protocol(mdev);
	drbd_send_sync_param(mdev,&mdev->sync_conf);
	drbd_send_sizes(mdev);
	drbd_send_uuids(mdev);
	drbd_send_state(mdev);

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
		ERR("magic?? m: 0x%lx c: %d l: %d\n",
		    (long)be32_to_cpu(h->magic),
		    h->command, h->length);
		return FALSE;
	}
	mdev->last_received = jiffies;

	return TRUE;
}

STATIC int receive_Barrier(drbd_dev *mdev, Drbd_Header* h)
{
	int rv;
	int epoch_size;
	Drbd_Barrier_Packet *p = (Drbd_Barrier_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, h->payload, h->length);
	ERR_IF(rv != h->length) return FALSE;

	inc_unacked(mdev);

	// DBG("got Barrier\n");

	if (mdev->conf.wire_protocol != DRBD_PROT_C)
		drbd_kick_lo(mdev);

	drbd_wait_ee(mdev,&mdev->active_ee);

	spin_lock_irq(&mdev->ee_lock);
	rv = _drbd_process_ee(mdev,1);

	epoch_size=atomic_read(&mdev->epoch_size);
	atomic_set(&mdev->epoch_size,0);
	spin_unlock_irq(&mdev->ee_lock);

	rv &= drbd_send_b_ack(mdev, p->barrier, epoch_size);
	dec_unacked(mdev);

	return rv;
}

STATIC struct Tl_epoch_entry *
read_in_block(drbd_dev *mdev, sector_t sector, int data_size)
{
	struct Tl_epoch_entry *e;
	struct bio_vec *bvec;
	struct page *page;
	struct bio *bio;
	int ds,i,rr;

	e = drbd_alloc_ee(mdev,sector,data_size,GFP_KERNEL);
	if(!e) return 0;
	bio = e->private_bio;
	ds = data_size;
	bio_for_each_segment(bvec, bio, i) {
		page = bvec->bv_page;
		rr = drbd_recv(mdev,kmap(page),min_t(int,ds,PAGE_SIZE));
		kunmap(page);
		if( rr != min_t(int,ds,PAGE_SIZE) ) {
			drbd_free_ee(mdev,e);
			WARN("short read recev data: read %d expected %d\n",
			     rr, min_t(int,ds,PAGE_SIZE));
			return 0;
		}
		ds -= rr;
	}

	mdev->recv_cnt+=data_size>>9;
	return e;
}

STATIC void receive_data_tail(drbd_dev *mdev,int data_size)
{
	/* kick lower level device, if we have more than (arbitrary number)
	 * reference counts on it, which typically are locally submitted io
	 * requests.  don't use unacked_cnt, so we speed up proto A and B, too.
	 *
	 * XXX maybe: make that arbitrary number configurable.
	 * for now, I choose 1/16 of max-epoch-size.
	 */
	if (atomic_read(&mdev->local_cnt) >= (mdev->conf.max_epoch_size>>4) ) {
		drbd_kick_lo(mdev);
	}
	mdev->writ_cnt+=data_size>>9;
}

STATIC int recv_dless_read(drbd_dev *mdev, drbd_request_t *req,
			   sector_t sector, int data_size)
{
	struct bio_vec *bvec;
	struct bio *bio;
	int rr,i,expect,ok=1;

	bio = req->master_bio;
	D_ASSERT( sector == drbd_req_get_sector(req) );
	
	bio_for_each_segment(bvec, bio, i) {
		expect = min_t(int,data_size,bvec->bv_len);
		rr=drbd_recv(mdev,
			     kmap(bvec->bv_page)+bvec->bv_offset,
			     expect);	
		kunmap(bvec->bv_page);
		if (rr != expect) {
			ok = 0;
			break;
		}
		data_size -= rr;
	}

	D_ASSERT(data_size == 0 || !ok);
	drbd_bio_endio(bio,ok);
	dec_ap_bio(mdev);
	dec_ap_pending(mdev);
	return ok;
}

STATIC int e_end_resync_block(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	sector_t sector = drbd_ee_get_sector(e);
	int ok;

	drbd_rs_complete_io(mdev,sector); // before set_in_sync() !
	if (likely( drbd_bio_uptodate(e->private_bio) )) {
		ok = mdev->state.s.disk >= Inconsistent &&
			mdev->state.s.pdsk >= Inconsistent;
		if (likely( ok )) {
			drbd_set_in_sync(mdev, sector, drbd_ee_get_size(e));
			/* THINK maybe don't send ack either
			 * when we are suddenly diskless?
			 * Dropping it here should do no harm,
			 * since peer has no structs referencing this.
			 */
		}
		ok = drbd_send_ack(mdev,WriteAck,e);
		__set_bit(SYNC_STARTED,&mdev->flags);
	} else {
		ok = drbd_send_ack(mdev,NegAck,e);
		ok&= drbd_io_error(mdev);
	}
	dec_unacked(mdev);

	return ok;
}

STATIC int recv_resync_read(drbd_dev *mdev,sector_t sector, int data_size)
{
	struct Tl_epoch_entry *e;

	e = read_in_block(mdev,sector,data_size);
	if(!e) return FALSE;

	dec_rs_pending(mdev);

	e->block_id = ID_SYNCER;
	if(!inc_local(mdev)) {
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Can not write resync data to local disk.\n");
		drbd_send_ack(mdev,NegAck,e);
		drbd_free_ee(mdev,e);
		return TRUE;
	}

	drbd_ee_prepare_write(mdev,e);
	e->w.cb     = e_end_resync_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->w.list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->ee_lock);

	inc_unacked(mdev);

	drbd_generic_make_request(WRITE,e->private_bio);

	receive_data_tail(mdev,data_size);
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

	/* I expect a block to be a multiple of 512 byte, and
	 * no more than 4K (PAGE_SIZE). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0x1ff) return FALSE;
	ERR_IF(data_size >  PAGE_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);

	req = (drbd_request_t *)(long)p->block_id;
	D_ASSERT(req->w.cb == w_is_app_read);

	spin_lock(&mdev->pr_lock);
	list_del(&req->w.list);
	spin_unlock(&mdev->pr_lock);

	ok = recv_dless_read(mdev,req,sector,data_size);

	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

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

	/* I expect a block to be a multiple of 512 byte, and
	 * no more than 4K (PAGE_SIZE). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0x1ff) return FALSE;
	ERR_IF(data_size >  PAGE_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);
	D_ASSERT(p->block_id == ID_SYNCER);

	ok = recv_resync_read(mdev,sector,data_size);

	return ok;
}

STATIC int e_end_block(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	sector_t sector = drbd_ee_get_sector(e);
	int ok=1;

	atomic_inc(&mdev->epoch_size);
	if(mdev->conf.wire_protocol == DRBD_PROT_C) {
		if(likely(drbd_bio_uptodate(e->private_bio))) {
			ok=drbd_send_ack(mdev,WriteAck,e);
			if (ok && test_bit(SYNC_STARTED,&mdev->flags) )
				drbd_set_in_sync(mdev,sector,drbd_ee_get_size(e));
		} else {
			ok = drbd_send_ack(mdev,NegAck,e);
			ok&= drbd_io_error(mdev);
			/* we expect it to be marked out of sync anyways...
			 * maybe assert this?
			 */
		}
		dec_unacked(mdev);

		return ok;
	}

	if(unlikely(!drbd_bio_uptodate(e->private_bio))) {
		ok = drbd_io_error(mdev);
	}

	return ok;
}

STATIC int drbd_chk_discard(drbd_dev *mdev,struct Tl_epoch_entry *e)
{
	struct drbd_discard_note *dn;
	struct list_head *le;

	MUST_HOLD(&mdev->peer_seq_lock);
 start_over:
	list_for_each(le,&mdev->discard) {
		dn = list_entry(le, struct drbd_discard_note, list);
		if( dn->seq_num == mdev->peer_seq ) {
			D_ASSERT( dn->block_id == e->block_id );
			list_del(le);
			kfree(dn);
			return 1;
		}
		if( dn->seq_num < mdev->peer_seq ) {
			list_del(le);
			kfree(dn);
			goto start_over;
		}
	}
	return 0;
}

// mirrored write
STATIC int receive_Data(drbd_dev *mdev,Drbd_Header* h)
{
	sector_t sector;
	struct Tl_epoch_entry *e;
	drbd_request_t * req;
	Drbd_Data_Packet *p = (Drbd_Data_Packet*)h;
	int header_size, data_size, packet_seq, discard, rv;

	// FIXME merge this code dups into some helper function
	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	if( data_size > 4096 ) INFO("data_size=%d\n",data_size);
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0x1ff) return FALSE;
	ERR_IF(data_size >  DRBD_MAX_SEGMENT_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);
	e = read_in_block(mdev,sector,data_size);
	if (!e) return FALSE;

	if(!inc_local(mdev)) {
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Can not write mirrored data block to local disk.\n");
		drbd_send_ack(mdev,NegAck,e);
		rv = TRUE;
		goto out1;
	}

	e->block_id = p->block_id; // no meaning on this side, e* on partner
	drbd_ee_prepare_write(mdev, e);
	e->w.cb     = e_end_block;

	/* This wait_event is here to make sure that never ever an
	   DATA packet traveling via sock can overtake an ACK packet
	   traveling on msock 
	   PRE TODO: Wrap around of seq_num !!! 
	*/
	if (mdev->conf.two_primaries) {
		packet_seq = be32_to_cpu(p->seq_num);
		/* if( packet_seq > peer_seq(mdev)+1 ) {
			WARN(" will wait till (packet_seq) %d <= %d\n",
			     packet_seq,peer_seq(mdev)+1);
			     } */
		if( wait_event_interruptible(mdev->cstate_wait, 
					     packet_seq <= peer_seq(mdev)+1)) {
			rv = FALSE;
			goto out2;
		}

		spin_lock(&mdev->peer_seq_lock); 
		mdev->peer_seq = max(mdev->peer_seq, packet_seq);
		/* is update_peer_seq(mdev,packet_seq); */
		discard = drbd_chk_discard(mdev,e);
		spin_unlock(&mdev->peer_seq_lock);

		if(discard) {
			WARN("Concurrent write! [DISCARD BY LIST] sec=%lu\n",
			     (unsigned long)sector);
			rv = TRUE;
			goto out2;
		}

		req = req_have_write(mdev, e);
		
		if(req) {
			if( req->rq_status & RQ_DRBD_SENT ) {
				/* Conflicting write, got ACK */
				/* write afterwards ...*/
				WARN("Concurrent write! [W AFTERWARDS1] "
				     "sec=%lu\n",(unsigned long)sector);
				if( wait_event_interruptible(mdev->cstate_wait,
					       !req_have_write(mdev,e))) {
					rv = FALSE;
					goto out2;
				}
			} else {
				/* Conflicting write, no ACK by now*/
				if (test_bit(UNIQUE,&mdev->flags)) {
					WARN("Concurrent write! [DISCARD BY FLAG] sec=%lu\n",
					     (unsigned long)sector);
					rv = TRUE;
					goto out2;
				} else {
					/* write afterwards do not exp ACK */
					WARN("Concurrent write! [W AFTERWARDS2] sec=%lu\n",
					     (unsigned long)sector);
					drbd_send_discard(mdev,req);
					drbd_end_req(req, RQ_DRBD_SENT, 1, sector);
					dec_ap_pending(mdev);
					if( wait_event_interruptible(mdev->cstate_wait,
								     !req_have_write(mdev,e))) {
						rv = FALSE;
						goto out2;
					}
				}
			}
		}
	}

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->w.list,&mdev->active_ee);
	spin_unlock_irq(&mdev->ee_lock);

	switch(mdev->conf.wire_protocol) {
	case DRBD_PROT_C:
		inc_unacked(mdev);
		break;
	case DRBD_PROT_B:
		drbd_send_ack(mdev, RecvAck, e);
		break;
	case DRBD_PROT_A:
		// nothing to do
		break;
	}

	drbd_generic_make_request(WRITE,e->private_bio);

	receive_data_tail(mdev,data_size);
	return TRUE;

 out2:
	atomic_inc(&mdev->epoch_size);
	dec_local(mdev);
 out1:
	drbd_free_ee(mdev,e);
	return rv;
}

STATIC int receive_DataRequest(drbd_dev *mdev,Drbd_Header *h)
{
	sector_t sector;
	const sector_t capacity = drbd_get_capacity(mdev->this_bdev);
	struct Tl_epoch_entry *e;
	int size;
	Drbd_BlockRequest_Packet *p = (Drbd_BlockRequest_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	sector = be64_to_cpu(p->sector);
	size   = be32_to_cpu(p->blksize);

	/*
	 * handled by NegDReply below ...
	ERR_IF (test_bit(DISKLESS,&mdev->flags)) {
		return FALSE;
	ERR_IF ( (mdev->gen_cnt[Flags] & MDF_Consistent) == 0 )
		return FALSE;
	*/

	if (size <= 0 || (size & 0x1ff) != 0 || size > DRBD_MAX_SEGMENT_SIZE) {
		ERR("%s:%d: sector: %lu, size: %d\n", __FILE__, __LINE__,
				(unsigned long)sector,size);
		return FALSE;
	}
	if ( sector + (size>>9) > capacity) {
		ERR("%s:%d: sector: %lu, size: %d\n", __FILE__, __LINE__,
				(unsigned long)sector,size);
		return FALSE;
	}

	e = drbd_alloc_ee(mdev,sector,size,GFP_KERNEL);
	if (!e) return FALSE;

	e->block_id = p->block_id; // no meaning on this side, pr* on partner
	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->w.list,&mdev->read_ee);
	spin_unlock_irq(&mdev->ee_lock);

	if(!inc_local(mdev) || mdev->state.s.disk < UpToDate ) {
		if (DRBD_ratelimit(5*HZ,5))
			ERR("Can not satisfy peer's read request, no local data.\n");
		drbd_send_ack(mdev,NegDReply,e);
		drbd_free_ee(mdev,e);
		return TRUE;
	}

	drbd_ee_prepare_read(mdev,e);

	switch (h->command) {
	case DataRequest:
		e->w.cb = w_e_end_data_req;
		break;
	case RSDataRequest:
		e->w.cb = w_e_end_rsdata_req;
		/* Eventually this should become asynchrously. Currently it
		 * blocks the whole receiver just to delay the reading of a
		 * resync data block.
		 * the drbd_work_queue mechanism is made for this...
		 */
		if (!drbd_rs_begin_io(mdev,sector)) {
			// we have been interrupted, probably connection lost!
			D_ASSERT(signal_pending(current));
			drbd_free_ee(mdev,e);
			return 0;
		}
		break;
	default:
		ERR("unexpected command (%s) in receive_DataRequest\n",
		    cmdname(h->command));
	}

	mdev->read_cnt += size >> 9;
	inc_unacked(mdev);
	drbd_generic_make_request(READ,e->private_bio);
	if (atomic_read(&mdev->local_cnt) >= (mdev->conf.max_epoch_size>>4) ) {
		drbd_kick_lo(mdev);
	}


	return TRUE;
}

STATIC int drbd_asb_recover_0p(drbd_dev *mdev)
{
	int self, peer, rv=-100;

	self = mdev->uuid[Bitmap] & 1;
	peer = mdev->p_uuid[Bitmap] & 1;

	switch ( mdev->conf.after_sb_0p ) {
	case Consensus:
	case DiscardSecondary:
	case PanicPrimary:
		ERR("Configuration error.\n");
		break;
	case Disconnect: 
		break;
	case DiscardYoungerPri: 
		if (self == 0 && peer == 1) rv = -1;
		if (self == 1 && peer == 0) rv =  1;
		D_ASSERT(self != peer);
		break;
	case DiscardOlderPri:
		if (self == 0 && peer == 1) rv =  1;
		if (self == 1 && peer == 0) rv = -1;
		D_ASSERT(self != peer);
		break;
	case DiscardLeastChg:
		ERR("Not yet implemented.\n");
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

	self = mdev->uuid[Bitmap] & 1;
	peer = mdev->p_uuid[Bitmap] & 1;

	switch ( mdev->conf.after_sb_1p ) {
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
		if( hg == -1 && mdev->state.s.role==Secondary) rv=hg;
		if( hg == 1  && mdev->state.s.role==Primary)   rv=hg;
		break;
	case DiscardSecondary:
		return mdev->state.s.role==Primary ? 1 : -1;
	case PanicPrimary:
		hg = drbd_asb_recover_0p(mdev);
		if( hg == -1 && mdev->state.s.role==Primary) {
			int sec = Secondary;
			if(drbd_set_role(mdev,&sec)) {
				drbd_panic("Panic by after-sb-1pri handler.");
			} else rv = hg;
		} else rv = hg;
	}
	return rv;
}

STATIC int drbd_asb_recover_2p(drbd_dev *mdev)
{
	int self, peer, hg, rv=-100;

	self = mdev->uuid[Bitmap] & 1;
	peer = mdev->p_uuid[Bitmap] & 1;

	switch ( mdev->conf.after_sb_1p ) {
	case DiscardYoungerPri:
	case DiscardOlderPri:
	case DiscardLeastChg:
	case DiscardLocal:
	case DiscardRemote:
	case Consensus:
	case DiscardSecondary:
		ERR("Configuration error.\n");
		break;
	case Disconnect:
		break;
	case PanicPrimary:
		hg = drbd_asb_recover_0p(mdev);
		if( hg == -1 ) {
			int sec = Secondary;
			if(drbd_set_role(mdev,&sec)) {
				drbd_panic("Panic by after-sb-2pri handler.");
			} else rv = hg;
		} else rv = hg;
	}
	return rv;
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
static int drbd_uuid_compare(drbd_dev *mdev)
{
	u64 self, peer;
	int i,j;

	self = mdev->uuid[Current] & ~((u64)1);
	peer = mdev->p_uuid[Current] & ~((u64)1);

	if (self == UUID_JUST_CREATED &&
	    peer == UUID_JUST_CREATED) return 0;

	if (self == UUID_JUST_CREATED && 
	    peer != UUID_JUST_CREATED) return -2;

	if (self != UUID_JUST_CREATED && 
	    peer == UUID_JUST_CREATED) return 2;

	if (self == peer) return 0;

	peer = mdev->p_uuid[Bitmap] & ~((u64)1);
	if (self == peer) return -1;

	for ( i=History_start ; i<=History_end ; i++ ) {
		peer = mdev->p_uuid[i] & ~((u64)1);
		if (self == peer) return -2;
	}

	self = mdev->uuid[Bitmap] & ~((u64)1);
	peer = mdev->p_uuid[Current] & ~((u64)1);

	if (self == peer) return 1;
	
	for ( i=History_start ; i<=History_end ; i++ ) {
		self = mdev->uuid[i] & ~((u64)1);
		if (self == peer) return 2;
	}

	self = mdev->uuid[Bitmap] & ~((u64)1);
	peer = mdev->p_uuid[Bitmap] & ~((u64)1);

	if (self == peer) return 100;

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
STATIC drbd_conns_t drbd_sync_handshake(drbd_dev *mdev, drbd_role_t peer_role)
{
	int hg;
	drbd_conns_t rv = conn_mask;

	hg = drbd_uuid_compare(mdev);

	if (hg == 100) {
		if ( mdev->state.s.role==Secondary && peer_role==Secondary ) {
			hg = drbd_asb_recover_0p(mdev);
		} else if (mdev->state.s.role==Primary && peer_role==Primary) {
			hg = drbd_asb_recover_2p(mdev);
		} else {
			hg = drbd_asb_recover_1p(mdev);
		}
		/* PRE TODO: consider want_loose here
		if ( hg == -100 && mdev->conf.want_loose ) {
			hg = -1;
		}*/
		if( hg != -100 ) {
			WARN("Split-Brain detected, automatically solved.\n");
		}
	}

	if (hg == -1000) {
		ALERT("Unrelated data, dropping connection!\n");
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return conn_mask;
	}

	if (hg == -100) {
		ALERT("Split-Brain detected, dropping connection!\n");
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return conn_mask;
	}

	if (hg > 0 && mdev->state.s.disk <= Inconsistent ) {
		ERR("I shall become SyncSource, but I am inconsistent!\n");
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return conn_mask;
	}
	if (hg < 0 && mdev->state.s.role == Primary ) {
		ERR("I shall become SyncTarget, but I am primary!\n");
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return conn_mask;
	}

	if (abs(hg) >= 2) {
		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);
	}

	if (hg > 0) { // become sync source.
		D_ASSERT(drbd_md_test_flag(mdev,MDF_Consistent));
		rv = WFBitMapS;
		wait_event(mdev->cstate_wait,
			   atomic_read(&mdev->ap_bio_cnt)==0);
		drbd_bm_lock(mdev);   // {
		drbd_send_bitmap(mdev);
		drbd_bm_unlock(mdev); // }
	} else if (hg < 0) { // become sync target
		drbd_md_clear_flag(mdev,MDF_Consistent);
		drbd_uuid_set(mdev,Current,mdev->p_uuid[Bitmap]);
		mdev->as_c_uuid = mdev->p_uuid[Current];
		rv = WFBitMapT;		
	} else {
		rv = Connected;
		drbd_bm_lock(mdev);   // {
		if(drbd_bm_total_weight(mdev)) {
			INFO("No resync -> clearing bit map.\n");
			drbd_bm_clear_all(mdev);
			drbd_bm_write(mdev);
		}
		drbd_bm_unlock(mdev); // }
	}

	return rv;
}

STATIC int receive_protocol(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Protocol_Packet *p = (Drbd_Protocol_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	if(be32_to_cpu(p->protocol)!=mdev->conf.wire_protocol) {
		int peer_proto = be32_to_cpu(p->protocol);
		if (DRBD_PROT_A <= peer_proto && peer_proto <= DRBD_PROT_C) {
			ERR("incompatible communication protocols: "
			    "me %c, peer %c\n",
				'A'-1+mdev->conf.wire_protocol,
				'A'-1+peer_proto);
		} else {
			ERR("incompatible communication protocols: "
			    "me %c, peer [%d]\n",
				'A'-1+mdev->conf.wire_protocol,
				peer_proto);
		}
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}

	return TRUE;
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
	mdev->sync_conf.use_csums = be32_to_cpu(p->use_csums);
	mdev->sync_conf.skip      = be32_to_cpu(p->skip);
	drbd_alter_sg(mdev, be32_to_cpu(p->group));

	return ok;
}

STATIC int receive_sizes(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Sizes_Packet *p = (Drbd_Sizes_Packet*)h;
	unsigned int max_seg_s;
	sector_t p_size;
	drbd_conns_t nconn;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	p_size=be64_to_cpu(p->d_size);

	if(p_size == 0 && mdev->state.s.disk == Diskless ) {
		ERR("some backing storage is needed\n");
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}

	drbd_bm_lock(mdev); // {
	mdev->p_size=p_size;
	if( mdev->lo_usize != be64_to_cpu(p->u_size) ) {
		mdev->lo_usize = be64_to_cpu(p->u_size);
		INFO("Peer sets u_size to %lu KB\n",
		     (unsigned long)mdev->lo_usize);
	}
	drbd_determin_dev_size(mdev);
	drbd_bm_unlock(mdev); // }
	
	if (mdev->p_uuid) {
		nconn=drbd_sync_handshake(mdev,mdev->state.s.peer);
		kfree(mdev->p_uuid);
		mdev->p_uuid = 0;
		if(nconn == conn_mask) return FALSE;

		if(drbd_request_state(mdev,NS(conn,nconn)) <= 0) {
			drbd_force_state(mdev,NS(conn,StandAlone));
			drbd_thread_stop_nowait(&mdev->receiver);
			return FALSE;
		}
	}

	max_seg_s = be32_to_cpu(p->max_segment_size);
	if( max_seg_s != mdev->rq_queue->max_segment_size ) {
		drbd_setup_queue_param(mdev, max_seg_s);
	}

	if (mdev->state.s.conn > WFReportParams ) {
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

	p_uuid = kmalloc(sizeof(u64)*UUID_SIZE, GFP_KERNEL);

	for (i = Current; i < UUID_SIZE; i++) {
		p_uuid[i] = be64_to_cpu(p->uuid[i]);
	}

	if ( mdev->p_uuid ) kfree(mdev->p_uuid);
	mdev->p_uuid = p_uuid;

	return TRUE;
}


STATIC int receive_state(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_State_Packet *p = (Drbd_State_Packet*)h;
	drbd_conns_t nconn;
	drbd_state_t ns,peer_state;
	int rv;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;
	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	nconn = mdev->state.s.conn;
	if (nconn == WFReportParams ) nconn = Connected;

	peer_state.i = be32_to_cpu(p->state);

	if (mdev->p_uuid) {
		nconn=drbd_sync_handshake(mdev,peer_state.s.role);
		kfree(mdev->p_uuid);
		mdev->p_uuid = 0;
		if(nconn == conn_mask) return FALSE;
	}

	if (mdev->state.s.conn > WFReportParams ) {
		if( nconn > Connected && peer_state.s.conn == Connected) {
			// we want resync, peer has not yet decided to sync...
			drbd_send_uuids(mdev);
			drbd_send_state(mdev);
		}
	}

	spin_lock_irq(&mdev->req_lock);
	ns.i = mdev->state.i;
	ns.s.conn = nconn;
	ns.s.peer = peer_state.s.role;
	ns.s.pdsk = peer_state.s.disk;
	rv = _drbd_set_state(mdev,ns,ChgStateVerbose);
	spin_unlock_irq(&mdev->req_lock);

	if(rv <= 0) {
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}

	/* FIXME assertion for (gencounts do not diverge) */
	drbd_md_write(mdev); // update connected indicator, la_size, ...

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

	if (mdev->state.s.conn == WFBitMapS) {
		drbd_start_resync(mdev,SyncSource);
	} else if (mdev->state.s.conn == WFBitMapT) {
		ok = drbd_send_bitmap(mdev);
		if (!ok) goto out;
		drbd_start_resync(mdev,SyncTarget); // XXX cannot fail ???
	} else {
		ERR("unexpected cstate (%s) in receive_bitmap\n",
		    conns_to_name(mdev->state.s.conn));
	}

	// We just started resync. Now we can be sure that local disk IO is okay.

	/* no, actually we can't. failures happen asynchronously, anytime.
	 * we can never be sure. disk may have failed while we where busy shaking hands...
	 */
/*
 *  FIXME this should only be D_ASSERT here.
 *        *doing* it here masks a logic bug elsewhere, I think.
 */
	D_ASSERT(mdev->state.s.disk >= Inconsistent);
	D_ASSERT(mdev->state.s.pdsk >= Inconsistent);
// EXPLAIN:
	clear_bit(MD_IO_ALLOWED,&mdev->flags);

	ok=TRUE;
 out:
	drbd_bm_unlock(mdev); // }
	vfree(buffer);
	return ok;
}

STATIC void drbd_fail_pending_reads(drbd_dev *mdev)
{
	struct list_head *le;
	struct bio *bio;
	LIST_HEAD(workset);

	/*
	 * Application READ requests
	 */
	spin_lock(&mdev->pr_lock);
	list_splice_init(&mdev->app_reads,&workset);
	spin_unlock(&mdev->pr_lock);

	while(!list_empty(&workset)) {
		drbd_request_t *req;
		le = workset.next;
		req = list_entry(le, drbd_request_t, w.list);
		list_del(le);

		bio = req->master_bio;

		drbd_bio_IO_error(bio);
		dec_ap_bio(mdev);
		dec_ap_pending(mdev);

		INVALIDATE_MAGIC(req);
		mempool_free(req,drbd_request_mempool);
	}
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

STATIC int receive_BecomeSyncTarget(drbd_dev *mdev, Drbd_Header *h)
{
	ERR_IF(!mdev->bitmap) return FALSE;

	drbd_bm_lock(mdev);
	drbd_bm_set_all(mdev);
	drbd_bm_write(mdev);
	drbd_start_resync(mdev,SyncTarget);
	drbd_bm_unlock(mdev);
	return TRUE; // cannot fail ?
}

STATIC int receive_BecomeSyncSource(drbd_dev *mdev, Drbd_Header *h)
{
	// FIXME asserts ?
	drbd_bm_lock(mdev);
	drbd_bm_set_all(mdev);
	drbd_bm_write(mdev);
	drbd_start_resync(mdev,SyncSource);
	drbd_bm_unlock(mdev);
	return TRUE; // cannot fail ?
}

STATIC int receive_UnplugRemote(drbd_dev *mdev, Drbd_Header *h)
{
	if (mdev->state.s.disk >= Inconsistent) drbd_kick_lo(mdev);
	return TRUE; // cannot fail.
}

STATIC int receive_outdate(drbd_dev *mdev, Drbd_Header *h)
{
	drbd_state_t os,ns;
	int r;

	WARN("OutdateRequest\n");

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	if( os.s.disk < Outdated ) { 
		r=-999;
	} else {
		r = _drbd_set_state(mdev, _NS2(disk,Outdated,conn,TearDown),
				    ChgStateVerbose);
	}
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);
	after_state_ch(mdev,os,ns);

	if( r >= 0 ) {
		drbd_md_write(mdev);
		drbd_send_short_cmd(mdev, OutdatedReply);
		return TRUE;
	}
	
	return FALSE;
}

STATIC int receive_outdated(drbd_dev *mdev, Drbd_Header *h)
{
	int r;

	WARN("OutdatedReply\n");

	drbd_uuid_new_current(mdev);
	drbd_md_write(mdev);

	r = drbd_request_state(mdev,NS2(pdsk,Outdated,conn,TearDown));
	WARN("r=%d\n",r);
	D_ASSERT(r >= 0);

	return TRUE;
}

typedef int (*drbd_cmd_handler_f)(drbd_dev*,Drbd_Header*);

static drbd_cmd_handler_f drbd_default_handler[] = {
	[Data]             = receive_Data,
	[DataReply]        = receive_DataReply,
	[RSDataReply]      = receive_RSDataReply,
	[RecvAck]          = NULL, //receive_RecvAck,
	[WriteAck]         = NULL, //receive_WriteAck,
	[Barrier]          = receive_Barrier,
	[BarrierAck]       = NULL, //receive_BarrierAck,
	[ReportBitMap]     = receive_bitmap,
	[Ping]             = NULL, //receive_Ping,
	[PingAck]          = NULL, //receive_PingAck,
	[BecomeSyncTarget] = receive_BecomeSyncTarget,
	[BecomeSyncSource] = receive_BecomeSyncSource,
	[UnplugRemote]     = receive_UnplugRemote,
	[DataRequest]      = receive_DataRequest,
	[RSDataRequest]    = receive_DataRequest, //receive_RSDataRequest,
	[SyncParam]        = receive_SyncParam,
	[ReportProtocol]   = receive_protocol,
	[ReportUUIDs]      = receive_uuids,
	[ReportSizes]      = receive_sizes,
	[ReportState]      = receive_state,
	[OutdateRequest]   = receive_outdate,
	[OutdatedReply]    = receive_outdated,
};

static drbd_cmd_handler_f *drbd_cmd_handler = drbd_default_handler;
static drbd_cmd_handler_f *drbd_opt_cmd_handler = NULL;

STATIC void drbdd(drbd_dev *mdev)
{
	drbd_cmd_handler_f handler;
	Drbd_Header *header = &mdev->data.rbuf.head;

	for (;;) {
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
			break;
		}
		if (unlikely(!handler(mdev,header))) {
			ERR("error receiving %s, l: %d!\n",
			    cmdname(header->command), header->length);
			break;
		}
		dump_packet(mdev,mdev->data.socket,2,&mdev->data.rbuf, __FILE__, __LINE__);
	}
}

STATIC void drbd_disconnect(drbd_dev *mdev)
{
	D_ASSERT(mdev->state.s.conn < Connected);

	/* in case we have been syncing, and then we drop the connection,
	 * we need to "w_resume_next_sg", which we try to achieve by
	 * setting the STOP_SYNC_TIMER bit, and schedulung the timer for
	 * immediate execution.
	 * unfortunately we cannot be sure that the timer already triggered.
	 *
	 * so we del_timer_sync here, and check that bit.
	 * if it is still set, we queue w_resume_next_sg anyways,
	 * just to be sure.
	 */

	del_timer_sync(&mdev->resync_timer);
	spin_lock_irq(&mdev->req_lock);
	if (test_and_clear_bit(STOP_SYNC_TIMER,&mdev->flags)) {
		mdev->resync_work.cb = w_resume_next_sg;
		if (list_empty(&mdev->resync_work.list))
			_drbd_queue_work(&mdev->data.work,&mdev->resync_work);
		// else: already queued, we only need to release the lock.
	} else {
		D_ASSERT(mdev->resync_work.cb == w_resync_inactive);
	}
	spin_unlock_irq(&mdev->req_lock);


	drbd_thread_stop_nowait(&mdev->worker);
	drbd_thread_stop(&mdev->asender);

	while(down_trylock(&mdev->data.mutex)) {
		struct task_struct *task;
		spin_lock(&mdev->send_task_lock);
		if((task=mdev->send_task)) {
			force_sig(DRBD_SIG, task);
			spin_unlock(&mdev->send_task_lock);
			down(&mdev->data.mutex);
			break;
		} else {
			spin_unlock(&mdev->send_task_lock);
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(HZ / 10);
		}
	}
	/* By grabbing the sock_mutex we make sure that no one
	   uses the socket right now. */
	drbd_free_sock(mdev);
	up(&mdev->data.mutex);

	drbd_fail_pending_reads(mdev);
	drbd_thread_stop(&mdev->worker);
	drbd_rs_cancel_all(mdev);

	// secondary
	drbd_wait_ee(mdev,&mdev->active_ee);
	drbd_wait_ee(mdev,&mdev->sync_ee);
	drbd_clear_done_ee(mdev);

	// primary
	tl_clear(mdev);
	clear_bit(ISSUE_BARRIER,&mdev->flags);
	wait_event( mdev->cstate_wait, atomic_read(&mdev->ap_pending_cnt)==0 );
	D_ASSERT(mdev->oldest_barrier->n_req == 0);

	D_ASSERT(atomic_read(&mdev->pp_in_use) == 0);
	D_ASSERT(list_empty(&mdev->read_ee)); // done by termination of worker
	D_ASSERT(list_empty(&mdev->active_ee)); // done here
	D_ASSERT(list_empty(&mdev->sync_ee)); // done here
	D_ASSERT(list_empty(&mdev->done_ee)); // done here

	atomic_set(&mdev->epoch_size,0);
	mdev->rs_total=0;

	if(atomic_read(&mdev->unacked_cnt)) {
		ERR("unacked_cnt = %d\n",atomic_read(&mdev->unacked_cnt));
		atomic_set(&mdev->unacked_cnt,0);
	}

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
	atomic_set(&mdev->rs_pending_cnt,0);

	if(atomic_read(&mdev->ap_pending_cnt)) {
		ERR("ap_pending_cnt = %d\n",atomic_read(&mdev->ap_pending_cnt));
		atomic_set(&mdev->ap_pending_cnt,0);
	}

	wake_up(&mdev->cstate_wait);

	if (get_t_state(&mdev->receiver) == Exiting) {
		drbd_force_state(mdev,NS(conn,StandAlone));
		drbd_thread_start(&mdev->worker);
	} else {
		drbd_force_state(mdev,NS(conn,Unconnected));
		drbd_thread_start(&mdev->worker);
	}

	if ( mdev->state.s.role == Primary ) {
		if ( mdev->state.s.pdsk >= DUnknown &&
		     mdev->uuid[Bitmap] == 0 ) {
			/* We only create a new UUID if the peer might
			   possibly be UpToDate. Since the connection is
			   already gone it is DUnknown by now. 
			   In case we already created a BitMap there is
			   no need to create a new UUID.
			*/
			drbd_uuid_new_current(mdev);
		}
		if ( test_bit(SPLIT_BRAIN_FIX,&mdev->flags) &&
		     mdev->state.s.pdsk >= DUnknown ) {
			drbd_disks_t nps = drbd_try_outdate_peer(mdev);
			drbd_request_state(mdev,NS(pdsk,nps));
		}
		drbd_md_write(mdev);
	}

	INFO("Connection lost.\n");
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
	memset(p,0,sizeof(*p));
	p->protocol_version = cpu_to_be32(PRO_VERSION);
	ok = _drbd_send_cmd( mdev, mdev->data.socket, HandShake,
	                     (Drbd_Header *)p, sizeof(*p), 0 );
	up(&mdev->data.mutex);
	return ok;
}

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
		return 0;
	}

	if (p->head.length != expect) {
		ERR( "expected HandShake length: %u, received: %u\n",
		     expect, p->head.length );
		return 0;
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
		return 0;
	}

	return 1;
}

#ifndef CONFIG_CRYPTO_HMAC
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
	unsigned int key_len = strlen(mdev->conf.shared_secret);
	unsigned int resp_size;
	int rv;
	
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

	resp_size = crypto_tfm_alg_digestsize(mdev->cram_hmac_tfm);
	response = kmalloc(resp_size,GFP_KERNEL);
	if(response == NULL) {
		ERR("kmalloc of response failed\n");
		rv = 0;
		goto fail;
	}

	sg.page   = virt_to_page(peers_ch);
	sg.offset = offset_in_page(peers_ch);
	sg.length = p.length;
	crypto_hmac(mdev->cram_hmac_tfm, (u8*)mdev->conf.shared_secret,
		    &key_len, &sg, 1, response);

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
	
	sg.page   = virt_to_page(my_challenge);
	sg.offset = offset_in_page(my_challenge);
	sg.length = CHALLENGE_LEN;
	crypto_hmac(mdev->cram_hmac_tfm, (u8*)mdev->conf.shared_secret,
		    &key_len, &sg, 1, right_response);

	rv = ! memcmp(response,right_response,resp_size);
	
	if(rv) {
		INFO("Peer authenticated usind %d bytes of '%s' HMAC\n",
		     resp_size,mdev->conf.cram_hmac_alg);
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
	int minor = (int)(mdev-drbd_conf);

	sprintf(current->comm, "drbd%d_receiver", minor);

	/* printk(KERN_INFO DEVICE_NAME ": receiver living/m=%d\n", minor); */

	while (TRUE) {
		if (!drbd_connect(mdev)) {
			WARN("Discarding network configuration.\n");
			/* FIXME DISKLESS StandAlone
			 * does not make much sense...
			 * drbd_disconnect should set cstate properly...
			 */
			drbd_disconnect(mdev);
			drbd_force_state(mdev,NS(conn,StandAlone));
			break;
		}
		if (get_t_state(thi) == Exiting) break;
		drbdd(mdev);
		drbd_disconnect(mdev);
		if (get_t_state(thi) == Exiting) break;
		if(mdev->conf.on_disconnect == DropNetConf) {
			drbd_force_state(mdev,NS(conn,StandAlone));
			break;
		}
		else {
			if (signal_pending(current)) {
				flush_signals(current);
			}
			spin_lock(&thi->t_lock);
			D_ASSERT(thi->t_state == Restarting);
			thi->t_state = Running;
			spin_unlock(&thi->t_lock);
		}
	}

	INFO("receiver terminated\n");

	return 0;
}

/* ********* acknowledge sender ******** */

STATIC int got_Ping(drbd_dev *mdev, Drbd_Header* h)
{
	return drbd_send_ping_ack(mdev);

}

STATIC int got_PingAck(drbd_dev *mdev, Drbd_Header* h)
{
	// restore idle timeout
	mdev->meta.socket->sk->sk_rcvtimeo = mdev->conf.ping_int*HZ;

	return TRUE;
}

STATIC int got_BlockAck(drbd_dev *mdev, Drbd_Header* h)
{
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);

	update_peer_seq(mdev,be32_to_cpu(p->seq_num));

	smp_rmb();
	if(likely(mdev->state.s.pdsk >= Inconsistent )) {
		// test_bit(PARTNER_DISKLESS,&mdev->flags)
		// This happens if one a few IO requests on the peer
		// failed, and some subsequest completed sucessfull
		// afterwards.

		// But we killed everything out of the transferlog
		// as we got the news hat IO is broken on the peer.

		if( is_syncer_blk(mdev,p->block_id)) {
			drbd_set_in_sync(mdev,sector,blksize);
			__set_bit(SYNC_STARTED,&mdev->flags);
		} else {
			req=(drbd_request_t*)(unsigned long)p->block_id;

			if (unlikely(!tl_verify(mdev,req,sector))) {
				ERR("Got a corrupt block_id/sector pair.\n");
				return FALSE;
			}

			drbd_end_req(req, RQ_DRBD_SENT, 1, sector);

			if (test_bit(SYNC_STARTED,&mdev->flags) &&
			    mdev->conf.wire_protocol == DRBD_PROT_C)
				drbd_set_in_sync(mdev,sector,blksize);
		}
	}

	if(is_syncer_blk(mdev,p->block_id)) {
		dec_rs_pending(mdev);
	} else {
		D_ASSERT(mdev->conf.wire_protocol != DRBD_PROT_A);
		dec_ap_pending(mdev);
	}
	return TRUE;
}

STATIC int got_NegAck(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	update_peer_seq(mdev,be32_to_cpu(p->seq_num));

	/* do nothing here.
	 * we expect to get a "report param" on the data socket soon,
	 * and will do the cleanup then and there.
	 */
	if(is_syncer_blk(mdev,p->block_id)) {
		dec_rs_pending(mdev);
	}
	if (DRBD_ratelimit(5*HZ,5))
		WARN("Got NegAck packet. Peer is in troubles?\n");

	return TRUE;
}

STATIC int got_NegDReply(drbd_dev *mdev, Drbd_Header* h)
{
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	req = (drbd_request_t *)(unsigned long)p->block_id;
	D_ASSERT(req->w.cb == w_is_app_read);

	spin_lock(&mdev->pr_lock);
	list_del(&req->w.list);
	spin_unlock(&mdev->pr_lock);

	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

	drbd_panic("Got NegDReply. WE ARE LOST. We lost our up-to-date disk.\n");

	// THINK do we have other options, but panic?
	//       what about bio_endio, in case we don't panic ??

	return TRUE;
}

STATIC int got_NegRSDReply(drbd_dev *mdev, Drbd_Header* h)
{
	sector_t sector;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	sector = be64_to_cpu(p->sector);
	D_ASSERT(p->block_id == ID_SYNCER);

	drbd_rs_complete_io(mdev,sector);

	drbd_panic("Got NegRSDReply. WE ARE LOST. We lost our up-to-date disk.\n");

	// THINK do we have other options, but panic?
	//       what about bio_endio, in case we don't panic ??

	return TRUE;
}

STATIC int got_BarrierAck(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_BarrierAck_Packet *p = (Drbd_BarrierAck_Packet*)h;

	smp_rmb();
	if(unlikely(mdev->state.s.pdsk <= Diskless)) return TRUE;

	tl_release(mdev,p->barrier,be32_to_cpu(p->set_size));
	dec_ap_pending(mdev);

	return TRUE;
}

STATIC int got_Discard(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_Discard_Packet *p = (Drbd_Discard_Packet*)h;
	struct drbd_discard_note *dn;

	dn = kmalloc(sizeof(struct drbd_discard_note),GFP_KERNEL);
	if(!dn) {
		ERR("kmalloc(drbd_discard_note) failed.");
		return FALSE;
	}

	dn->block_id = p->block_id;
	dn->seq_num = be32_to_cpu(p->seq_num);

	spin_lock(&mdev->peer_seq_lock);
	list_add(&dn->list,&mdev->discard);
	spin_unlock(&mdev->peer_seq_lock);

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

	static struct asender_cmd asender_tbl[] = {
		[Ping]      ={ sizeof(Drbd_Header),           got_Ping },
		[PingAck]   ={ sizeof(Drbd_Header),           got_PingAck },
		[RecvAck]   ={ sizeof(Drbd_BlockAck_Packet),  got_BlockAck },
		[WriteAck]  ={ sizeof(Drbd_BlockAck_Packet),  got_BlockAck },
		[NegAck]    ={ sizeof(Drbd_BlockAck_Packet),  got_NegAck },
		[NegDReply] ={ sizeof(Drbd_BlockAck_Packet),  got_NegDReply },
		[NegRSDReply]={sizeof(Drbd_BlockAck_Packet),  got_NegRSDReply},
		[BarrierAck]={ sizeof(Drbd_BarrierAck_Packet),got_BarrierAck },
		[DiscardNote]={sizeof(Drbd_Discard_Packet),   got_Discard },
	};

	sprintf(current->comm, "drbd%d_asender", (int)(mdev-drbd_conf));

	current->policy = SCHED_RR;  /* Make this a realtime task! */
	current->rt_priority = 2;    /* more important than all other tasks */

	while (get_t_state(thi) == Running) {
		if (test_and_clear_bit(SEND_PING, &mdev->flags)) {
			ERR_IF(!drbd_send_ping(mdev)) goto err;
			// half ack timeout only,
			// since sendmsg waited the other half already
			mdev->meta.socket->sk->sk_rcvtimeo =
				mdev->conf.timeout*HZ/20;
		}

		/* FIXME this *should* be below drbd_process_ee,
		 * but that leads to some distributed deadlock :-(
		 * this needs to be fixed properly, I'd vote for a separate
		 * msock sender thread, but others will frown upon yet an other
		 * kernel thread...
		 *	-- lge
		 */
		set_bit(SIGNAL_ASENDER, &mdev->flags);

		if (!drbd_process_ee(mdev,0)) goto err;

		rv = drbd_recv_short(mdev,buf,expect-received);
		clear_bit(SIGNAL_ASENDER, &mdev->flags);

		flush_signals(current);

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
			    mdev->conf.timeout*HZ/20) {
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
				ERR("magic?? m: 0x%lx c: %d l: %d\n",
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
		if (mdev->state.s.conn >= Connected)
			drbd_force_state(mdev,NS(conn,NetworkFailure));
		drbd_thread_restart_nowait(&mdev->receiver);
	}

	INFO("asender terminated\n");

	return 0;
}
