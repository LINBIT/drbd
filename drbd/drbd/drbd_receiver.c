/*
-*- linux-c -*-
   drbd_receiver.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

   Copyright (C) 2002-2003, Lars Ellenberg <l.g.e@web.de>.
	main contributor.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
	Code to prevent zombie threads.

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


#ifdef HAVE_AUTOCONF
#include <linux/autoconf.h>
#endif
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif

#include <asm/uaccess.h>
#include <net/sock.h>

#include <linux/tcp.h>

#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/pkt_sched.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/drbd.h>
#include "drbd_int.h"

#define EE_MININUM 32    // @4k pages => 128 KByte

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

/*
You need to hold the ee_lock:
 drbd_free_ee()
 drbd_get_ee()
 drbd_put_ee()
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

STATIC int _drbd_alloc_ee(drbd_dev *mdev,struct page* page,int mask)
{
	struct Tl_epoch_entry* e;

	e = kmem_cache_alloc(drbd_ee_cache, mask);
	if( e == NULL ) return FALSE;

	drbd_ee_init(e,page);
	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->w.list,&mdev->free_ee);
	mdev->ee_vacant++;
	spin_unlock_irq(&mdev->ee_lock);

	return TRUE;
}

/* bool */
STATIC int drbd_alloc_ee(drbd_dev *mdev,int mask)
{
	struct page *page;

	page=alloc_page(mask);
	if(!page) return FALSE;

	if(!_drbd_alloc_ee(mdev,page,GFP_KERNEL)) {
		__free_page(page);
		return FALSE;
	}

	return TRUE;
}

STATIC struct page* drbd_free_ee(drbd_dev *mdev, struct list_head *list)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;
	struct page* page;

	MUST_HOLD(&mdev->ee_lock);

	D_ASSERT(!list_empty(list));
	le = list->next;
	e = list_entry(le, struct Tl_epoch_entry, w.list);
	list_del(le);

	page = drbd_bio_get_page(&e->private_bio);
	kmem_cache_free(drbd_ee_cache, e);
	mdev->ee_vacant--;

	return page;
}

int drbd_init_ee(drbd_dev *mdev)
{
	while(mdev->ee_vacant < EE_MININUM ) {
		if(!drbd_alloc_ee(mdev,GFP_USER)) {
			ERR("Failed to allocate %d EEs !\n",EE_MININUM);
			return 0;
		}
	}
	return 1;
}

int drbd_release_ee(drbd_dev *mdev,struct list_head* list)
{
	int count=0;

	spin_lock_irq(&mdev->ee_lock);
	while(!list_empty(list)) {
		__free_page(drbd_free_ee(mdev,list));
		count++;
	}
	spin_unlock_irq(&mdev->ee_lock);

	return count;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0)
#define GFP_TRY	( __GFP_HIGHMEM | __GFP_NOWARN )
#else
#define GFP_TRY	( __GFP_HIGHMEM )
#endif

STATIC int _drbd_process_ee(drbd_dev *mdev,struct list_head *head);

/**
 * drbd_get_ee: Returns an Tl_epoch_entry; might sleep. Fails only if
 * a signal comes in.
 */
struct Tl_epoch_entry* drbd_get_ee(drbd_dev *mdev)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;
	DEFINE_WAIT(wait);

	MUST_HOLD(&mdev->ee_lock);

	if(mdev->ee_vacant == EE_MININUM / 2) {
		spin_unlock_irq(&mdev->ee_lock);
		drbd_kick_lo(mdev);
		spin_lock_irq(&mdev->ee_lock);
	}

	if(list_empty(&mdev->free_ee)) _drbd_process_ee(mdev,&mdev->done_ee);

	if(list_empty(&mdev->free_ee)) {
		for (;;) {
			prepare_to_wait(&mdev->ee_wait, &wait, 
					TASK_INTERRUPTIBLE);
			if(!list_empty(&mdev->free_ee)) break;
			if( ( mdev->ee_vacant+mdev->ee_in_use) < 
			      mdev->conf.max_buffers ) {
				if(drbd_alloc_ee(mdev,GFP_TRY)) break;
			}
			spin_unlock_irq(&mdev->ee_lock);
			drbd_kick_lo(mdev);
			schedule();
			spin_lock_irq(&mdev->ee_lock);
			finish_wait(&mdev->al_wait, &wait);
			if (signal_pending(current)) return 0;
			// finish wait is inside, so that we are TASK_RUNNING 
			// in _drbd_process_ee (which might sleep by itself.)
			_drbd_process_ee(mdev,&mdev->done_ee);
		}
		finish_wait(&mdev->al_wait, &wait); 
	}

	le=mdev->free_ee.next;
	list_del(le);
	mdev->ee_vacant--;
	mdev->ee_in_use++;
	e=list_entry(le, struct Tl_epoch_entry, w.list);
	e->block_id = !ID_VACANT;
	SET_MAGIC(e);
	return e;
}

void drbd_put_ee(drbd_dev *mdev,struct Tl_epoch_entry *e)
{
	struct page* page;

	MUST_HOLD(&mdev->ee_lock);

	mdev->ee_in_use--;
	mdev->ee_vacant++;
	e->block_id = ID_VACANT;
	INVALIDATE_MAGIC(e);
	list_add(&e->w.list,&mdev->free_ee);

	if((mdev->ee_vacant * 2 > mdev->ee_in_use ) &&
	   ( mdev->ee_vacant + mdev->ee_in_use > EE_MININUM) ) {
		// FIXME cleanup: never returns NULL anymore
		page=drbd_free_ee(mdev,&mdev->free_ee);
		if( page ) __free_page(page);
	}
	if(mdev->ee_in_use == 0) {
		while( mdev->ee_vacant > EE_MININUM ) {
			__free_page(drbd_free_ee(mdev,&mdev->free_ee));
		}
	}

	wake_up(&mdev->ee_wait);
}

/* It is important that the head list is really empty when returning,
   from this function. Note, this function is called from all three
   threads (receiver, worker and asender). To ensure this I only allow
   one thread at a time in the body of the function */
STATIC int _drbd_process_ee(drbd_dev *mdev,struct list_head *head)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int ok=1;
	int got_sig;

	MUST_HOLD(&mdev->ee_lock);

	if( test_and_set_bit(PROCESS_EE_RUNNING,&mdev->flags) ) {
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
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
	}

	clear_bit(PROCESS_EE_RUNNING,&mdev->flags);
	wake_up(&mdev->ee_wait);

	return ok;
}

STATIC int drbd_process_ee(drbd_dev *mdev,struct list_head *head)
{
	int rv;
	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_ee(mdev,head);
	spin_unlock_irq(&mdev->ee_lock);
	return rv;
}

STATIC void drbd_clear_done_ee(drbd_dev *mdev)
{
	struct list_head *le;
	struct Tl_epoch_entry *e;

	spin_lock_irq(&mdev->ee_lock);

	while(!list_empty(&mdev->done_ee)) {
		le = mdev->done_ee.next;
		list_del(le);
		e = list_entry(le, struct Tl_epoch_entry, w.list);
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   is_syncer_blk(mdev,e->block_id)) {
			dec_unacked(mdev,HERE);
		}
		drbd_put_ee(mdev,e);
	}

	spin_unlock_irq(&mdev->ee_lock);
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

	if (!(newsock = sock_alloc()))
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
		set_current_state(TASK_ZOMBIE);
		schedule(); // commit suicide
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
# define SK_(x)		x
#else
# define SK_(x)		sk_ ## x
#endif

int drbd_recv(drbd_dev *mdev,void *buf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	int rv;

	if (unlikely(drbd_did_panic == DRBD_MAGIC)) {
		set_current_state(TASK_ZOMBIE);
		schedule(); // commit suicide
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
			/* signal came in after we read a partial message */
			D_ASSERT(signal_pending(current));
			break;
		}
	};

	set_fs(oldfs);

	if(rv != size) {
		set_cstate(mdev,BrokenPipe);
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

	sock->sk->SK_(rcvtimeo) =
	sock->sk->SK_(sndtimeo) =  mdev->conf.try_connect_int*HZ;

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

	sock2->sk->SK_(reuse)    = 1; /* SO_REUSEADDR */
	sock2->sk->SK_(rcvtimeo) =
	sock2->sk->SK_(sndtimeo) =  mdev->conf.try_connect_int*HZ;

	err = sock2->ops->bind(sock2,
			      (struct sockaddr *) mdev->conf.my_addr,
			      mdev->conf.my_addr_len);
	if (err) {
		ERR("Unable to bind (%d)\n", err);
		sock_release(sock2);
		set_cstate(mdev,Unconnected);
		return 0;
	}

	sock = drbd_accept(mdev,sock2);
	sock_release(sock2);

	return sock;
}

int drbd_connect(drbd_dev *mdev)
{
	struct socket *sock,*msock;

	D_ASSERT(mdev->cstate!=Unconfigured);
	D_ASSERT(!mdev->data.socket);

	set_cstate(mdev,WFConnection);

	while(1) {
		sock=drbd_try_connect(mdev);
		if(sock) {
			msock=drbd_wait_for_connect(mdev);
			if(msock) break;
			else sock_release(sock);
		} else {
			sock=drbd_wait_for_connect(mdev);
			if(sock) {
				int retry;
				for (retry=1; retry <= 10; retry++) {
					// give the other side time to call
					// bind() & listen()
					current->state = TASK_INTERRUPTIBLE;
					schedule_timeout(HZ / 10);
					msock=drbd_try_connect(mdev);
					if(msock) goto connected;
					ERR("msock try_connect %d\n",retry);
				}
				sock_release(sock);
			}
		}
		if(mdev->cstate==Unconnected) return 0;
		if(signal_pending(current)) {
			drbd_flush_signals(current);
			smp_rmb();
			if (get_t_state(&mdev->receiver) == Exiting)
				return 0;
		}
	}

 connected:

	msock->sk->SK_(reuse)=1; /* SO_REUSEADDR */
	sock->sk->SK_(reuse)=1; /* SO_REUSEADDR */

	/* to prevent oom deadlock... */
	/* The default allocation priority was GFP_KERNEL */
	sock->sk->SK_(allocation) = GFP_DRBD;
	msock->sk->SK_(allocation) = GFP_DRBD;

	sock->sk->SK_(priority)=TC_PRIO_BULK;
	NOT_IN_26(sock->sk->tp_pinfo.af_tcp.nonagle=0;)
	ONLY_IN_26( tcp_sk(sock->sk)->nonagle = 0;)
	// FIXME fold to limits. should be done in drbd_ioctl
	sock->sk->SK_(sndbuf) = mdev->conf.sndbuf_size;
	sock->sk->SK_(rcvbuf) = mdev->conf.sndbuf_size;
	sock->sk->SK_(sndtimeo) = mdev->conf.timeout*HZ/20;
	sock->sk->SK_(rcvtimeo) = MAX_SCHEDULE_TIMEOUT;
	sock->sk->SK_(userlocks) |= SOCK_SNDBUF_LOCK | SOCK_RCVBUF_LOCK;

	msock->sk->SK_(priority)=TC_PRIO_INTERACTIVE;
	NOT_IN_26(sock->sk->tp_pinfo.af_tcp.nonagle=1;)
	ONLY_IN_26(tcp_sk(sock->sk)->nonagle = 1;)
	msock->sk->SK_(sndbuf) = 2*32767;
	msock->sk->SK_(sndtimeo) = mdev->conf.timeout*HZ/20;
	msock->sk->SK_(rcvtimeo) = mdev->conf.ping_int*HZ;

	mdev->data.socket = sock;
	mdev->meta.socket = msock;
	mdev->last_received = jiffies;

	set_cstate(mdev,WFReportParams);

	/* in case one of the other threads said: restart_nowait(receiver),
	 * it may still hang around itself.  make sure threads are
	 * really stopped before trying to restart them.
	 * drbd_disconnect should have taken care of that, but I still
	 * get these "resync inactive, but callback triggered".
	 *
	 * and I saw "connection lost... established", and no more
	 * worker thread :(
	 */
	D_ASSERT(mdev->asender.task == NULL);

	drbd_thread_start(&mdev->asender);

	drbd_send_param(mdev,0);

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

	ERR_IF(mdev->state != Secondary) return FALSE;
	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, h->payload, h->length);
	ERR_IF(rv != h->length) return FALSE;

	inc_unacked(mdev);

	// DBG("got Barrier\n");

	if (mdev->conf.wire_protocol != DRBD_PROT_C)
		drbd_kick_lo(mdev);

	drbd_wait_ee(mdev,&mdev->active_ee);

	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_ee(mdev,&mdev->done_ee);
	// FIXME no error check here?

	epoch_size=mdev->epoch_size;
	mdev->epoch_size=0;
	spin_unlock_irq(&mdev->ee_lock);

	// FIXME no error check here?
	drbd_send_b_ack(mdev, p->barrier, epoch_size);
	dec_unacked(mdev,HERE);

	return TRUE;
}

STATIC struct Tl_epoch_entry *
read_in_block(drbd_dev *mdev, int data_size)
{
	struct Tl_epoch_entry *e;
	drbd_bio_t *bio;
	int rr;

	spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev);
	spin_unlock_irq(&mdev->ee_lock);
	if(!e) return 0;

	bio = &e->private_bio;

	rr=drbd_recv(mdev, drbd_bio_kmap(bio), data_size);
	drbd_bio_kunmap(bio);

	if ( rr != data_size) {
		NOT_IN_26(clear_bit(BH_Lock, &bio->b_state);)
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		return 0;
	}
	mdev->recv_cnt+=data_size>>9;

	return e;
}

STATIC void receive_data_tail(drbd_dev *mdev,int data_size)
{
	/* Actually the primary can send up to NR_REQUEST / 3 blocks,
	 * but we already start when we have NR_REQUEST / 4 blocks.
	 *
	 * This code is only with protocol C relevant.
	 */
#define NUMBER 24
	if(atomic_read(&mdev->unacked_cnt) >= NUMBER ) {
		drbd_kick_lo(mdev);
	}
#undef NUMBER

	mdev->writ_cnt+=data_size>>9;
}

STATIC int recv_dless_read(drbd_dev *mdev, drbd_request_t *req,
			   sector_t sector, int data_size)
{
	drbd_bio_t *bio;
	int ok,rr;

	bio = req->master_bio;

	D_ASSERT( sector == drbd_req_get_sector(req) );

	rr=drbd_recv(mdev,drbd_bio_kmap(bio),data_size);
	drbd_bio_kunmap(bio);

	ok=(rr==data_size);
	drbd_bio_endio(bio,ok);

	dec_ap_pending(mdev,HERE);
	return ok;
}

STATIC int e_end_resync_block(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct Tl_epoch_entry *e = (struct Tl_epoch_entry*)w;
	sector_t sector = drbd_ee_get_sector(e);
	int ok;

	drbd_rs_complete_io(mdev,sector); // before set_in_sync() !
	if(likely(drbd_bio_uptodate(&e->private_bio))) {
		drbd_set_in_sync(mdev, sector, drbd_ee_get_size(e));
		ok = drbd_send_ack(mdev,WriteAck,e);
	} else {
		ok = drbd_send_ack(mdev,NegAck,e);
		ok&= drbd_io_error(mdev);
	}

	dec_unacked(mdev,HERE);
	return ok;
}

STATIC int recv_resync_read(drbd_dev *mdev,sector_t sector, int data_size)
{
	struct Tl_epoch_entry *e;

	e = read_in_block(mdev,data_size);
	ERR_IF(!e) return FALSE;

	dec_rs_pending(mdev,HERE);

	e->block_id = ID_SYNCER;
	if(!inc_local(mdev)) {
		ERR("Can not write resync data to local disk.\n");
		drbd_send_ack(mdev,NegAck,e);
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		return TRUE;
	}

	drbd_ee_prepare_write(mdev,e,sector,data_size);
	e->w.cb     = e_end_resync_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->w.list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->ee_lock);

	inc_unacked(mdev);

	drbd_generic_make_request(WRITE,&e->private_bio);

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
	 * no more than 4K (8K). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0xff) return FALSE;
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
	 * no more than 4K (8K). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0xff) return FALSE;
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

	mdev->epoch_size++;
	if(mdev->conf.wire_protocol == DRBD_PROT_C) {
		if(likely(drbd_bio_uptodate(&e->private_bio))) {
			ok=drbd_send_ack(mdev,WriteAck,e);
			if(ok && mdev->rs_left)
				drbd_set_in_sync(mdev,sector,drbd_ee_get_size(e));
		} else {
			ok = drbd_send_ack(mdev,NegAck,e);
			ok&= drbd_io_error(mdev);
		}
		dec_unacked(mdev,HERE);

		return ok;
	}

	if(unlikely(!drbd_bio_uptodate(&e->private_bio))) {
		ok = drbd_io_error(mdev);
	}

	return ok;
}

// mirrored write
STATIC int receive_Data(drbd_dev *mdev,Drbd_Header* h)
{
	sector_t sector;
	struct Tl_epoch_entry *e;
	Drbd_Data_Packet *p = (Drbd_Data_Packet*)h;
	int header_size,data_size;

	// FIXME merge this code dups into some helper function
	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	/* I expect a block to be a multiple of 512 byte, and
	 * no more than 4K (8K). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0xff) return FALSE;
	ERR_IF(data_size >  PAGE_SIZE) return FALSE;

	if (drbd_recv(mdev, h->payload, header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);

	e = read_in_block(mdev,data_size);
	ERR_IF(!e) return FALSE;
	e->block_id = p->block_id; // no meaning on this side, e* on partner

	if(!inc_local(mdev)) {
		ERR("Can not write mirrored data block to local disk.\n");
		drbd_send_ack(mdev,NegAck,e);
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		return TRUE;
	}

	drbd_ee_prepare_write(mdev, e, sector, data_size);
	e->w.cb     = e_end_block;

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

	drbd_generic_make_request(WRITE,&e->private_bio);

	receive_data_tail(mdev,data_size);
	return TRUE;
}

STATIC int receive_DataRequest(drbd_dev *mdev,Drbd_Header *h)
{
	sector_t sector;
	struct Tl_epoch_entry *e;
	int data_size;
	Drbd_BlockRequest_Packet *p = (Drbd_BlockRequest_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	sector    = be64_to_cpu(p->sector);
	data_size = be32_to_cpu(p->blksize);

	spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev);
	if(!e) {
		spin_unlock_irq(&mdev->ee_lock);
		return FALSE;
	}
	e->block_id = p->block_id; // no meaning on this side, pr* on partner
	list_add(&e->w.list,&mdev->read_ee);
	spin_unlock_irq(&mdev->ee_lock);

	if(!inc_local(mdev)) {
		ERR("Can not satisfy peer's read request, no local disk.\n");
		drbd_send_ack(mdev,NegDReply,e);
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		return TRUE;
	}

	drbd_ee_prepare_read(mdev,e,sector,data_size);

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
		drbd_rs_begin_io(mdev,sector);
		break;
	default:
		D_ASSERT(0);
	}

	mdev->read_cnt += data_size >> 9;
	inc_unacked(mdev);
	drbd_generic_make_request(READ,&e->private_bio);

	return TRUE;
}

STATIC int receive_SyncParam(drbd_dev *mdev,Drbd_Header *h)
{
	int ok = TRUE;
	Drbd_SyncParam_Packet *p = (Drbd_SyncParam_Packet*)h;

	// FIXME move into helper
	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	// XXX harmless race with ioctl ...
	mdev->sync_conf.rate      = be32_to_cpu(p->rate);
	mdev->sync_conf.use_csums = be32_to_cpu(p->use_csums);
	mdev->sync_conf.skip      = be32_to_cpu(p->skip);
	drbd_alter_sg(mdev, be32_to_cpu(p->group));

	if (   (mdev->cstate == SkippedSyncS || mdev->cstate == SkippedSyncT)
	    && !mdev->sync_conf.skip )
	{
		set_cstate(mdev,WFReportParams);
		ok = drbd_send_param(mdev,0);
	}

	return ok;
}

STATIC int receive_param(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Parameter_Packet *p = (Drbd_Parameter_Packet*)h;
	int consider_sync;
	int oo_state;
	unsigned long p_size;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, h->payload, h->length) != h->length)
		return FALSE;

	if(be32_to_cpu(p->state) == Primary && mdev->state == Primary ) {
		ERR("incompatible states\n");
		set_cstate(mdev,StandAlone);
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}

	if(be32_to_cpu(p->version)!=PRO_VERSION) {
		ERR("incompatible releases\n");
		set_cstate(mdev,StandAlone);
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}

	if(be32_to_cpu(p->protocol)!=mdev->conf.wire_protocol) {
		ERR("incompatible protocols\n");
		set_cstate(mdev,StandAlone);
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}

	p_size=be64_to_cpu(p->p_size);

	if(p_size == 0 && test_bit(DISKLESS,&mdev->flags)) {
		ERR("some backing storage is needed\n");
		drbd_thread_stop_nowait(&mdev->receiver);
		return FALSE;
	}
	mdev->p_size=p_size;

	consider_sync = (mdev->cstate == WFReportParams);
	if(drbd_determin_dev_size(mdev)) consider_sync=0;

	if(be32_to_cpu(p->flags)&1) {
		consider_sync=1;
		drbd_send_param(mdev,2);
	}
	if(be32_to_cpu(p->flags)&2) consider_sync=1;

	// XXX harmless race with ioctl ...
	mdev->sync_conf.rate  =
		max_t(int,mdev->sync_conf.rate, be32_to_cpu(p->sync_rate));

	// if one of them wants to skip, both of them should skip.
	mdev->sync_conf.skip  =
		mdev->sync_conf.skip != 0 || p->skip_sync != 0;
	mdev->sync_conf.group =
		min_t(int,mdev->sync_conf.group,be32_to_cpu(p->sync_group));

	if( mdev->lo_usize != be64_to_cpu(p->u_size) ) {
		mdev->lo_usize = be64_to_cpu(p->u_size);
		INFO("Peer sets u_size to %ld KB\n",mdev->lo_usize);
	}

	if(!p_size) {
		set_bit(PARTNER_DISKLESS, &mdev->flags);
		if(mdev->cstate >= Connected ) {
			if(mdev->state == Primary) tl_clear(mdev);
			if(mdev->state == Primary ||
			   be32_to_cpu(p->state) == Primary ) {
				drbd_md_inc(mdev,ConnectedCnt);
			}
		}
		if(mdev->cstate > Connected ) {
			WARN("Resync aborted.\n");
			if(mdev->cstate == SyncTarget)
				set_bit(STOP_SYNC_TIMER,&mdev->flags);
			set_cstate(mdev,Connected);
		}
	}

	if (mdev->cstate == WFReportParams) {
		INFO("Connection established.\n");
	}

	if (consider_sync) {
		int have_good,sync;

		have_good = drbd_md_compare(mdev,p);

		if(have_good==0) sync=0;
		else sync=1;

		drbd_dump_md(mdev,p,0);
		//INFO("have_good=%d sync=%d\n", have_good, sync);

		if ( mdev->sync_conf.skip && sync ) {
			if (have_good == 1)
				set_cstate(mdev,SkippedSyncS);
			else // have_good == -1
				set_cstate(mdev,SkippedSyncT);
			goto skipped;
		}

		if( sync ) {
			if(have_good == 1) {
				drbd_send_bitmap(mdev);
				set_cstate(mdev,WFBitMapS);
			} else { // have_good == -1
				if (mdev->state == Primary) {
					ERR("Current Primary shall become sync TARGET! Aborting to prevent data corruption.\n");
					set_cstate(mdev,StandAlone);
					drbd_thread_stop_nowait(&mdev->receiver);
					return FALSE;
				}
				mdev->gen_cnt[Flags] &= ~MDF_Consistent;
				set_cstate(mdev,WFBitMapT);
			}
		} else {
			set_cstate(mdev,Connected);
			if(mdev->rs_total) {
				/* We are not going to do a resync but there
				   are marks in the bitmap.
				   (Could be from the AL, or someone used
				   the write_gc.pl program)
				   Clean the bitmap...
				 */
				INFO("No resync -> clearing bit map.\n");
				bm_fill_bm(mdev->mbds_id,0);
				mdev->rs_total = 0;
				drbd_write_bm(mdev);
			}
		}

		if (have_good == -1) {
			/* Sync-Target has to adopt source's gen_cnt. */
			int i;
			for(i=HumanCnt;i<=ArbitraryCnt;i++) {
				mdev->gen_cnt[i]=be32_to_cpu(p->gen_cnt[i]);
			}
		}
	}

skipped:	// do not adopt gen counts when sync was skipped ...

	if (mdev->cstate == WFReportParams) set_cstate(mdev,Connected);
	if (p_size && mdev->cstate==Connected) clear_bit(PARTNER_DISKLESS,&mdev->flags);

	oo_state = mdev->o_state;
	mdev->o_state = be32_to_cpu(p->state);
	if(oo_state == Secondary && mdev->o_state == Primary) {
		drbd_md_inc(mdev,ConnectedCnt);
	}

	drbd_md_write(mdev); // update connected indicator, la_size, ...

	return TRUE;
}

/* Since we are processing the bitfild from lower addresses to higher,
   it does not matter if the process it in 32 bit chunks or 64 bit
   chunks as long as it is little endian. (Understand it as byte stream,
   beginning with the lowest byte...) If we would use big endian
   we would need to process it from the highest address to the lowest,
   in order to be agnostic to the 32 vs 64 bits issue. */
STATIC int receive_bitmap(drbd_dev *mdev, Drbd_Header *h)
{
	size_t bm_words;
	unsigned long *buffer, *bm, word;
	int buf_i,want;
	int ok=FALSE, bm_i=0;
	unsigned long bits=0;

	bm_words=mdev->mbds_id->size/sizeof(long);
	bm=mdev->mbds_id->bm;
	buffer=vmalloc(MBDS_PACKET_SIZE);

	while (1) {
		want=min_t(int,MBDS_PACKET_SIZE,(bm_words-bm_i)*sizeof(word));
		ERR_IF(want != h->length) goto out;
		if (want==0) break;
		if (drbd_recv(mdev, buffer, want) != want)
			goto out;
		for(buf_i=0;buf_i<want/sizeof(long);buf_i++) {
			word = lel_to_cpu(buffer[buf_i]) | bm[bm_i];
			bits += hweight_long(word);
			bm[bm_i++] = word;
		}
		if (!drbd_recv_header(mdev,h))
			goto out;
		D_ASSERT(h->command == ReportBitMap);
	}

	bits = bits << (BM_BLOCK_SIZE_B - 9); // in sectors

	mdev->rs_total = bits + bm_end_of_dev_case(mdev->mbds_id);

	if (mdev->cstate == WFBitMapS) {
		drbd_start_resync(mdev,SyncSource);
	} else if (mdev->cstate == WFBitMapT) {
		if (!drbd_send_bitmap(mdev))
			goto out;
		drbd_start_resync(mdev,SyncTarget); // XXX cannot fail ???
	} else {
		D_ASSERT(0);
	}

	// We just started resync. Now we can be sure that local disk IO is okay.
/*
 *  FIXME this should only be D_ASSERT here.
 *        *doing* it here masks a logic bug elsewhere, I think.
 */
	clear_bit(PARTNER_DISKLESS,&mdev->flags);
	clear_bit(DISKLESS,&mdev->flags);
	smp_wmb();
	clear_bit(MD_IO_ALLOWED,&mdev->flags);

	ok=TRUE;
 out:
	vfree(buffer);
	return ok;
}

STATIC void drbd_fail_pending_reads(drbd_dev *mdev)
{
	struct list_head *le;
	drbd_bio_t *bio;
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
		dec_ap_pending(mdev,HERE);

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
	ERR_IF(!mdev->mbds_id)
		return FALSE;
	bm_fill_bm(mdev->mbds_id,-1);
	mdev->rs_total = drbd_get_capacity(mdev->this_bdev);
	drbd_write_bm(mdev);
	drbd_start_resync(mdev,SyncTarget);
	return TRUE; // cannot fail ?
}

STATIC int receive_BecomeSyncSource(drbd_dev *mdev, Drbd_Header *h)
{
	bm_fill_bm(mdev->mbds_id,-1);
	mdev->rs_total = drbd_get_capacity(mdev->this_bdev);
	drbd_write_bm(mdev);
	drbd_start_resync(mdev,SyncSource);
	return TRUE; // cannot fail ?
}

STATIC int receive_WriteHint(drbd_dev *mdev, Drbd_Header *h)
{
	drbd_kick_lo(mdev);
	return TRUE; // cannot fail.
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
	[ReportParams]     = receive_param,
	[ReportBitMap]     = receive_bitmap,
	[Ping]             = NULL, //receive_Ping,
	[PingAck]          = NULL, //receive_PingAck,
	[BecomeSyncTarget] = receive_BecomeSyncTarget,
	[BecomeSyncSource] = receive_BecomeSyncSource,
	[WriteHint]        = receive_WriteHint,
	[DataRequest]      = receive_DataRequest,
	[RSDataRequest]    = receive_DataRequest, //receive_RSDataRequest,
	[SyncParam]        = receive_SyncParam,
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
	D_ASSERT(mdev->cstate < Connected);
	mdev->o_state = Unknown;
	drbd_thread_stop_nowait(&mdev->worker);
	drbd_thread_stop(&mdev->asender);

	while(down_trylock(&mdev->data.mutex))
	{
		struct task_struct *task;
		spin_lock(&mdev->send_task_lock);
		if((task=mdev->send_task)) {
			force_sig(DRBD_SIG, task);
			spin_unlock(&mdev->send_task_lock);
			down(&mdev->data.mutex);
			break;
		} else {
			spin_unlock(&mdev->send_task_lock);
			schedule_timeout(HZ / 10);
		}
	}
	/* By grabbing the sock_mutex we make sure that no one
	   uses the socket right now. */
	drbd_free_sock(mdev);
	up(&mdev->data.mutex);

	drbd_thread_stop(&mdev->worker);

	drbd_fail_pending_reads(mdev);
	drbd_rs_cancel_all(mdev);

	tl_clear(mdev);
	clear_bit(ISSUE_BARRIER,&mdev->flags);
	drbd_wait_ee(mdev,&mdev->active_ee);
	drbd_wait_ee(mdev,&mdev->sync_ee);
	drbd_clear_done_ee(mdev);

	D_ASSERT(mdev->ee_in_use == 0);
	D_ASSERT(list_empty(&mdev->read_ee)); // done by termination of worker
	D_ASSERT(list_empty(&mdev->active_ee)); // done here
	D_ASSERT(list_empty(&mdev->sync_ee)); // done here
	D_ASSERT(list_empty(&mdev->done_ee)); // done here

	mdev->epoch_size=0;

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

	ERR_IF(atomic_read(&mdev->ap_pending_cnt))
		atomic_set(&mdev->ap_pending_cnt,0);

	wake_up_interruptible(&mdev->cstate_wait);

	if ( mdev->state == Primary &&
	    ( test_bit(DISKLESS,&mdev->flags)
	    || !(mdev->gen_cnt[Flags] & MDF_Consistent) ) ) {
		drbd_panic("Sorry, I have no access to good data anymore.\n");
	}

	if (get_t_state(&mdev->receiver) == Exiting) {
		if (test_bit(DISKLESS,&mdev->flags)) {
			// Secondary
			set_cstate(mdev,Unconfigured);
			drbd_mdev_cleanup(mdev);
		} else {
			set_cstate(mdev,StandAlone);
			drbd_thread_start(&mdev->worker);
		}
	} else {
		set_cstate(mdev,Unconnected);
		drbd_thread_start(&mdev->worker);
	}

	if (mdev->state == Primary) {
		if(!test_bit(DO_NOT_INC_CONCNT,&mdev->flags))
			drbd_md_inc(mdev,ConnectedCnt);
		drbd_md_write(mdev);
	}
	clear_bit(DO_NOT_INC_CONCNT,&mdev->flags);

	INFO("Connection lost.\n");
}

int drbdd_init(struct Drbd_thread *thi)
{
	drbd_dev *mdev = thi->mdev;
	int minor = (int)(mdev-drbd_conf);

	sprintf(current->comm, "drbd%d_receiver", minor);

	/* printk(KERN_INFO DEVICE_NAME ": receiver living/m=%d\n", minor); */

	while (TRUE) {
		if (!drbd_connect(mdev)) {
			WARN("Discarding network configuration.\n");
			break;
		}
		if (get_t_state(thi) == Exiting) break;
		drbdd(mdev);
		drbd_disconnect(mdev);
		if (get_t_state(thi) == Exiting) break;
		else {
			if (signal_pending(current)) {
				drbd_flush_signals(current);
			}
			spin_lock(&thi->t_lock);
			D_ASSERT(thi->t_state == Restarting);
			thi->t_state = Running;
			spin_unlock(&thi->t_lock);
		}
	}

	INFO("receiver exiting\n");

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
	mdev->meta.socket->sk->SK_(rcvtimeo) = mdev->conf.ping_int*HZ;

	return TRUE;
}

STATIC int got_BlockAck(drbd_dev *mdev, Drbd_Header* h)
{
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;
	sector_t sector = be64_to_cpu(p->sector);
	int blksize = be32_to_cpu(p->blksize);

	smp_rmb();
	if(likely(!test_bit(PARTNER_DISKLESS,&mdev->flags))) {
		// test_bit(PARTNER_DISKLESS,&mdev->flags)
		// This happens if one a few IO requests on the peer
		// failed, and some subsequest completed sucessfull
		// afterwards.

		// But we killed everything out of the transferlog
		// as we got the news hat IO is broken on the peer.

		if( is_syncer_blk(mdev,p->block_id)) {
			drbd_set_in_sync(mdev,sector,blksize);
		} else {
			req=(drbd_request_t*)(long)p->block_id;

			ERR_IF (!VALID_POINTER(req)) return FALSE;

			drbd_end_req(req, RQ_DRBD_SENT, 1, sector);

			if(mdev->conf.wire_protocol == DRBD_PROT_C && 
			   mdev->rs_left)
				drbd_set_in_sync(mdev,sector,blksize);
		}
	}

	if(is_syncer_blk(mdev,p->block_id)) {
		dec_rs_pending(mdev,HERE);
	} else {
		D_ASSERT(mdev->conf.wire_protocol != DRBD_PROT_A);
		dec_ap_pending(mdev,HERE);
	}
	return TRUE;
}

STATIC int got_NegAck(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;
	sector_t sector = be64_to_cpu(p->sector);
	int size = be32_to_cpu(p->blksize);

	WARN("Got NegAck packet. Peer is in troubles?\n");

	if(!is_syncer_blk(mdev,p->block_id)) {
		D_ASSERT(bm_get_bit(mdev->mbds_id,sector,size));
		// tl_clear() must have set this out of sync!
	}

	if(is_syncer_blk(mdev,p->block_id)) {
		dec_rs_pending(mdev,HERE);
	} else {
		D_ASSERT(mdev->conf.wire_protocol != DRBD_PROT_A);
		dec_ap_pending(mdev,HERE);
	}
	return TRUE;
}

STATIC int got_NegDReply(drbd_dev *mdev, Drbd_Header* h)
{
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	req = (drbd_request_t *)(long)p->block_id;
	D_ASSERT(req->w.cb == w_is_app_read);

	spin_lock(&mdev->pr_lock);
	list_del(&req->w.list);
	spin_unlock(&mdev->pr_lock);

	INVALIDATE_MAGIC(req);
	mempool_free(req,drbd_request_mempool);

	ERR("Get NegDReply. WE ARE LOST. We lost our up-to-date disk.\n");
	// TODO: Do something like panic() or shut_down_cluster(). 
	return TRUE;
}

STATIC int got_NegRSDReply(drbd_dev *mdev, Drbd_Header* h)
{
	sector_t sector;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	sector = be64_to_cpu(p->sector);
	D_ASSERT(p->block_id == ID_SYNCER);

	drbd_rs_complete_io(mdev,sector);

	ERR("Get NegRSDReply. WE ARE LOST. We lost our up-to-date disk.\n");
	// TODO: Do something like panic() or shut_down_cluster(). 
	return TRUE;
}

STATIC int got_BarrierAck(drbd_dev *mdev, Drbd_Header* h)
{
	Drbd_BarrierAck_Packet *p = (Drbd_BarrierAck_Packet*)h;

	smp_rmb();
	if(unlikely(test_bit(PARTNER_DISKLESS,&mdev->flags))) return TRUE;

	tl_release(mdev,p->barrier,be32_to_cpu(p->set_size));
	dec_ap_pending(mdev,HERE);

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
	};

	sprintf(current->comm, "drbd%d_asender", (int)(mdev-drbd_conf));

	current->policy = SCHED_RR;  /* Make this a realtime task! */
	current->rt_priority = 2;    /* more important than all other tasks */

	while (get_t_state(thi) == Running) {
		if (test_and_clear_bit(SEND_PING, &mdev->flags)) {
			ERR_IF(!drbd_send_ping(mdev)) goto err;
			// half ack timeout only,
			// since sendmsg waited the other half already
			mdev->meta.socket->sk->SK_(rcvtimeo) =
				mdev->conf.timeout*HZ/20;
		}

		set_bit(SIGNAL_ASENDER, &mdev->flags);

		if (!drbd_process_ee(mdev,&mdev->done_ee)) goto err;

		rv = drbd_recv_short(mdev,buf,expect-received);

		clear_bit(SIGNAL_ASENDER, &mdev->flags);

		drbd_flush_signals(current);

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
			if( mdev->meta.socket->sk->SK_(rcvtimeo) ==
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
		if (mdev->cstate >= Connected)
			set_cstate(mdev,NetworkFailure);
		drbd_thread_restart_nowait(&mdev->receiver);
	}

	INFO("asender terminated\n");

	return 0;
}
