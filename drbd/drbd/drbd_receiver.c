/*
  Mess: drbd_set_in_sync(), bm_set_bit(), bm_get_bit()
*/
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
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/smp_lock.h>
#include <linux/pkt_sched.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include "drbd.h"
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

STATIC void drbd_dio_end_sec(struct buffer_head *bh, int uptodate)
{
	/* This callback will be called in irq context by the IDE drivers,
	   and in Softirqs/Tasklets/BH context by the SCSI drivers.
	   Try to get the locking right :) */
  //	int wake_asender=0;
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=drbd_mdev_of_bh(bh);

	/*
	printk(KERN_ERR DEVICE_NAME "%d: dio_end_sec in_irq()=%d\n",
	       (int)(mdev-drbd_conf),in_irq());

	printk(KERN_ERR DEVICE_NAME "%d: dio_end_sec in_softirq()=%d\n",
	       (int)(mdev-drbd_conf),in_softirq());
	*/

	/*
	printk(KERN_ERR DEVICE_NAME "%d: drbd_dio_end_sec(%ld)\n",
	       (int)(mdev-drbd_conf),bh->b_blocknr);
	*/

	e=bh->b_private;
	D_ASSERT(e->bh == bh);
	D_ASSERT(e->block_id != ID_VACANT);

	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);

	clear_bit(BH_Dirty, &bh->b_state);
	clear_bit(BH_Lock, &bh->b_state);
	smp_mb__after_clear_bit();

	/* Do not move a BH if someone is in wait_on_buffer */
	if(atomic_read(&bh->b_count) == 0) {
		list_del(&e->list);
		list_add(&e->list,&mdev->done_ee);
	}

	if (waitqueue_active(&bh->b_wait))
		wake_up(&bh->b_wait); //must be within the lock!

	//	if(mdev->conf.wire_protocol == DRBD_PROT_C ||
	//	   e->block_id == ID_SYNCER ) wake_asender=1;

	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	if( mdev->do_panic && !uptodate) {
		panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	drbd_al_complete_io(mdev,DRBD_BH_SECTOR(bh));

	//	if(wake_asender) {
	wake_asender(mdev);
	//	}
	// TODO: Think if we should implement a short-cut here.
}

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

STATIC void _drbd_alloc_ee(drbd_dev *mdev,struct page* page)
{
	struct Tl_epoch_entry* e;
	struct buffer_head *bh,*lbh,*fbh;
	int number,buffer_size,i;

	buffer_size=BM_BLOCK_SIZE;
	number=PAGE_SIZE/buffer_size;
	lbh=NULL;
	bh=NULL;
	fbh=NULL;

	for(i=0;i<number;i++) {

		e = kmem_cache_alloc(drbd_ee_cache, GFP_KERNEL);
		bh = kmem_cache_alloc(bh_cachep, GFP_KERNEL);

		if( e == NULL || bh == NULL ) {
			ERR("could not kmalloc() new ee\n");
			BUG();
		}

		drbd_init_bh(bh, buffer_size);
		set_bh_page(bh,page,i*buffer_size); // sets b_data and b_page

		e->bh=bh;
		bh->b_private=e;

		e->block_id = ID_VACANT;
		spin_lock_irq(&mdev->ee_lock);
		list_add(&e->list,&mdev->free_ee);
		mdev->ee_vacant++;
		spin_unlock_irq(&mdev->ee_lock);
		if (lbh) {
			lbh->b_this_page = bh;
		} else {
			fbh = bh;
		}
		lbh=bh;
	}
	bh->b_this_page=fbh;
}

/* bool */
STATIC int drbd_alloc_ee(drbd_dev *mdev,int mask)
{
	struct page *page;

	page=alloc_page(mask);
	ERR_IF(!page) return FALSE;

	_drbd_alloc_ee(mdev,page);
	/*
	printk(KERN_ERR DEVICE_NAME "%d: vacant=%d in_use=%d sum=%d\n",
	       (int)(mdev-drbd_conf),mdev->ee_vacant,mdev->ee_in_use,
	       mdev->ee_vacant+mdev->ee_in_use);
	*/
	return TRUE;
}

STATIC struct page* drbd_free_ee(drbd_dev *mdev, struct list_head *list)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;
	struct buffer_head *bh,*nbh;
	int freeable=0;
	struct page* page;

	MUST_HOLD(&mdev->ee_lock);

	list_for_each(le,list) {
		bh=list_entry(le, struct Tl_epoch_entry,list)->bh;
		nbh=bh->b_this_page;
		freeable=1;
		while( nbh != bh ) {
			e=nbh->b_private;
			if(e->block_id != ID_VACANT) freeable=0;
			nbh=nbh->b_this_page;
		}
		if(freeable) goto free_it;
	}
	return 0;
 free_it:
	nbh=bh;
	page=bh->b_page;
	do {
		e=nbh->b_private;
		list_del(&e->list);
		mdev->ee_vacant--;
		D_ASSERT(nbh->b_page == page);
		nbh=nbh->b_this_page;
		/*printk(KERN_ERR DEVICE_NAME "%d: kfree(%p)\n",
		  (int)(mdev-drbd_conf),e);*/
		kmem_cache_free(bh_cachep, e->bh);
		kmem_cache_free(drbd_ee_cache, e);
	} while(nbh != bh);

	return page;
}

void drbd_init_ee(drbd_dev *mdev)
{
	while(mdev->ee_vacant < EE_MININUM ) {
		drbd_alloc_ee(mdev,GFP_USER);
	}
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

#define GFP_TRY	( __GFP_HIGHMEM )

struct Tl_epoch_entry* drbd_get_ee(drbd_dev *mdev,int may_sleep)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;

	MUST_HOLD(&mdev->ee_lock);

	if(mdev->ee_vacant == EE_MININUM / 2) {
		spin_unlock_irq(&mdev->ee_lock);
		run_task_queue(&tq_disk);
		spin_lock_irq(&mdev->ee_lock);
	}

	while(list_empty(&mdev->free_ee)) {
		_drbd_process_ee(mdev,&mdev->done_ee);
		if(!list_empty(&mdev->free_ee)) break;
		spin_unlock_irq(&mdev->ee_lock);
		if((mdev->ee_vacant+mdev->ee_in_use)<mdev->conf.max_buffers) {
			if(drbd_alloc_ee(mdev,GFP_TRY)) {
				spin_lock_irq(&mdev->ee_lock);
				break;
			}
		}

		if(!may_sleep) {
			spin_lock_irq(&mdev->ee_lock);
			return 0;
		}

		wake_up_interruptible(&mdev->dsender_wait);
		run_task_queue(&tq_disk);
		interruptible_sleep_on(&mdev->ee_wait);
		spin_lock_irq(&mdev->ee_lock);
	}
	le=mdev->free_ee.next;
	list_del(le);
	mdev->ee_vacant--;
	mdev->ee_in_use++;
	e=list_entry(le, struct Tl_epoch_entry,list);
	e->block_id = !ID_VACANT;
	return e;
}

void drbd_put_ee(drbd_dev *mdev,struct Tl_epoch_entry *e)
{
	struct page* page;

	MUST_HOLD(&mdev->ee_lock);

	mdev->ee_in_use--;
	mdev->ee_vacant++;
	e->block_id = ID_VACANT;
	list_add(&e->list,&mdev->free_ee);

	if((mdev->ee_vacant * 2 > mdev->ee_in_use ) &&
	   ( mdev->ee_vacant + mdev->ee_in_use > EE_MININUM) ) {
		page=drbd_free_ee(mdev,&mdev->free_ee);
		if( page ) __free_page(page);
	}
	if(mdev->ee_in_use == 0) {
		while( mdev->ee_vacant > EE_MININUM ) {
			__free_page(drbd_free_ee(mdev,&mdev->free_ee));
		}
	}
}

/* It is important that the head list is really empty when returning,
   from this function. Note, this function is called from all three
   threads (receiver, dsender and asender). To ensure this I only allow
   one thread at a time in the body of the function */
int _drbd_process_ee(drbd_dev *mdev,struct list_head *head)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int ok=1;

	MUST_HOLD(&mdev->ee_lock);

	while( test_and_set_bit(PROCESS_EE_RUNNING,&mdev->flags) ) {
		spin_unlock_irq(&mdev->ee_lock);
		interruptible_sleep_on(&mdev->ee_wait);
		spin_lock_irq(&mdev->ee_lock);
	}

	while(!list_empty(head)) {
		le = head->next;
		list_del(le);
		spin_unlock_irq(&mdev->ee_lock);
		e = list_entry(le, struct Tl_epoch_entry,list);
		ok = ok && e->e_end_io(mdev,e);
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
	}

	clear_bit(PROCESS_EE_RUNNING,&mdev->flags);
	wake_up_interruptible(&mdev->ee_wait);

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
		e = list_entry(le,struct Tl_epoch_entry,list);
		drbd_put_ee(mdev,e);
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   is_syncer_blk(mdev,e->block_id)) {
			dec_unacked(mdev,HERE);
		}

	}

	spin_unlock_irq(&mdev->ee_lock);
}


STATIC void drbd_wait_ee(drbd_dev *mdev,struct list_head *head,
			 struct list_head *to)
{
	wait_queue_t wait;
	struct Tl_epoch_entry *e;
	struct list_head *le;

	spin_lock_irq(&mdev->ee_lock);
	while(!list_empty(head)) {
		le = head->next;
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(!buffer_locked(e->bh)) {
			ERR( "unlocked bh in ative_ee/sync_ee/read_ee\n"
			     "(BUG?) Moving bh=%p to done_ee/rdone_ee\n",
			     e->bh );
			list_del(le);
			list_add(le,to);
			continue;
		}
		get_bh(e->bh);
		init_waitqueue_entry(&wait, current);
		current->state = TASK_UNINTERRUPTIBLE;

		spin_lock(&e->bh->b_wait.lock);
		__add_wait_queue(&e->bh->b_wait, &wait);
		spin_unlock(&e->bh->b_wait.lock);

		spin_unlock_irq(&mdev->ee_lock);

		schedule();

		spin_lock_irq(&mdev->ee_lock);

		spin_lock(&e->bh->b_wait.lock);
		__remove_wait_queue(&e->bh->b_wait, &wait);
		spin_unlock(&e->bh->b_wait.lock);

		put_bh(e->bh);
		/* The IRQ handler does not move a list entry if someone is
		   in wait_on_buffer for that entry, therefore we have to
		   move it here. */
		D_ASSERT(!buffer_locked(e->bh)); // IO is finished now!

		list_del(le);
		list_add(le,to);
	}
	spin_unlock_irq(&mdev->ee_lock);
}

STATIC struct socket* drbd_accept(drbd_dev *mdev,struct socket* sock)
{
	struct socket *newsock;
	int err = 0;

	//lock_kernel(); tcp stack has per socket locks now

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

	// unlock_kernel();
	return newsock;

      out_release:
	sock_release(newsock);
      out:
	unlock_kernel();
	if(err != -EAGAIN && err != -EINTR)
		ERR("accept failed! %d\n", err);
	return 0;
}

int drbd_recv(drbd_dev *mdev, struct socket* sock,
	      void *buf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	char * sockname = (sock == mdev->msock ? "msock" : "sock");
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

	// lock_kernel(); // SMP only. Do we need still need this ?
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	for(;;) {
		rv = sock_recvmsg(sock, &msg, size, msg.msg_flags);
		if (rv == size) break;

		/* Note:
		 * ECONNRESET   other side closed the connection
		 * ERESTARTSYS  (on  sock) we got a signal
		 * EINTR        (on msock) we got a signal
		 * EAGAIN       (on msock) rcvtimeo expired
		 */
		if (rv == -EAGAIN) {
			D_ASSERT(sock == mdev->msock);
			D_ASSERT(current == mdev->asender.task);

			// FIXME decide this more elegantly
			if ( mdev->msock->sk->rcvtimeo == mdev->conf.ping_int*HZ) {
				//DUMPLU(jiffies - mdev->last_received);
				C_DBG(0,"recv_header timed out, sending ping\n");
				// goto do_ping;
			} else {
				ERR("PingAck did not arrive\n");
				break;
			}
		} else if (rv == -EINTR) {
			D_ASSERT(sock == mdev->msock);
			D_ASSERT(current == mdev->asender.task);

			unsigned long flags = 0;
			LOCK_SIGMASK(current,flags);
			if (sigismember(&current->pending.signal, DRBD_SIG)) {
				sigdelset(&current->pending.signal, DRBD_SIG);
				RECALC_SIGPENDING(current);
			}
			UNLOCK_SIGMASK(current,flags);
			break;
		} else if (rv < 0) {
			if (rv == -ECONNRESET)
				INFO("%s was reset by peer\n",sockname);
			else if (rv != -ERESTARTSYS)
				ERR("%s_recvmsg returned %d\n",sockname,rv);
			break;
		} else if (rv == 0) {
			INFO("%s was shut down by peer\n",sockname);
			break;
		} else {
			ERR("logic error: %s_recvmsg returned %d\n",
			    sockname, rv);
			break;
		}

		// actually no goto needed, but it makes it more obvious
		// do_ping:
		if (!drbd_send_ping(mdev))
			break;
		// full ack timeout
		mdev->msock->sk->rcvtimeo = mdev->conf.timeout*HZ/10;

	};

	set_fs(oldfs);
	// unlock_kernel();

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

	sock->sk->rcvtimeo =
	sock->sk->sndtimeo =  mdev->conf.try_connect_int*HZ;

	//lock_kernel(); no No NO! connect may sleep!
	err = sock->ops->connect(sock,
				 (struct sockaddr *) mdev->conf.other_addr,
				 mdev->conf.other_addr_len, 0);
	//unlock_kernel();

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

	sock2->sk->reuse=1; /* SO_REUSEADDR */
	sock2->sk->rcvtimeo =
	sock2->sk->sndtimeo =  mdev->conf.try_connect_int*HZ;

	//lock_kernel(); tcp stack has per socket locks now
	err = sock2->ops->bind(sock2,
			      (struct sockaddr *) mdev->conf.my_addr,
			      mdev->conf.my_addr_len);
	//unlock_kernel();
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


	if (mdev->cstate==Unconfigured) return 0;

	if (mdev->sock) {
		ERR("There is already a socket!!\n");
		return 0;
	}

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
		if(signal_pending(current)) return 0;
	}

 connected:

	msock->sk->reuse=1; /* SO_REUSEADDR */
	sock->sk->reuse=1; /* SO_REUSEADDR */

	/* to prevent oom deadlock... */
	/* The default allocation priority was GFP_KERNEL */
	sock->sk->allocation = GFP_DRBD;
	msock->sk->allocation = GFP_DRBD;

	sock->sk->priority=TC_PRIO_BULK;
	sock->sk->tp_pinfo.af_tcp.nonagle=0;
	// FIXME fold to limits. should be done in drbd_ioctl
	sock->sk->sndbuf = mdev->conf.sndbuf_size;
	sock->sk->rcvbuf = mdev->conf.sndbuf_size;
	sock->sk->sndtimeo = mdev->conf.timeout*HZ/20;
	sock->sk->rcvtimeo = MAX_SCHEDULE_TIMEOUT;

	msock->sk->priority=TC_PRIO_INTERACTIVE;
	msock->sk->tp_pinfo.af_tcp.nonagle=1;
	msock->sk->sndbuf = 2*32767;
	msock->sk->sndtimeo = mdev->conf.timeout*HZ/20;
	msock->sk->rcvtimeo = mdev->conf.ping_int*HZ;

	mdev->sock = sock;
	mdev->msock = msock;
	mdev->last_received = jiffies;

	set_cstate(mdev,WFReportParams);

	drbd_thread_start(&mdev->asender);
	drbd_thread_start(&mdev->dsender);

	drbd_send_param(mdev);

	return 1;
}

STATIC int drbd_recv_header(drbd_dev *mdev,struct socket* sock, Drbd_Header *h)
{
	int r;

	if (signal_pending(current) && current == mdev->asender.task) {
		// shortcut only, same effect as if we first go up and
		// down the helper function calls.
		unsigned long flags = 0;
		int still_pending = FALSE;
		LOCK_SIGMASK(current,flags);
		// XXX maybe rather flush_signals() ?
		if (sigismember(&current->pending.signal, DRBD_SIG)) {
			sigdelset(&current->pending.signal, DRBD_SIG);
			RECALC_SIGPENDING(current);
			still_pending = signal_pending(current);
		}
		UNLOCK_SIGMASK(current,flags);

		DBG("Signal Pending in %s\n",__func__);

		h->command = WakeAsender;
		h->length  = 0;
		// fail if it was not our private signal.
		return !still_pending;
	}

	r = drbd_recv(mdev,sock,h,sizeof(*h));
	if (r == -EINTR && sock == mdev->msock) {
		h->command = WakeAsender;
		h->length  = 0;
		return TRUE;
	}

	if (unlikely( r != sizeof(*h) )) {
		ERR("short read expecting header on %s: r=%d\n",
		    sock == mdev->msock ? "msock" : "sock",
		    r);
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
	if (sock == mdev->msock) {
		// restore idle timeout
		mdev->msock->sk->rcvtimeo = mdev->conf.ping_int*HZ;
	}
	C_DBG(5,"on %s <<< %s l: %d\n",
	    sock == mdev->msock ? "msock" : "sock",
	    cmdname(h->command), h->length);
	return TRUE;
}

STATIC int receive_BlockAck(drbd_dev *mdev, Drbd_Header* h)
{
	int rv;
	drbd_request_t *req;
	Drbd_BlockAck_Packet *p = (Drbd_BlockAck_Packet*)h;

	ERR_IF (h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, mdev->msock, PAYLOAD_P(h), h->length);
	ERR_IF (rv != h->length) return FALSE;

	if( is_syncer_blk(mdev,p->block_id)) {
		drbd_set_in_sync(mdev,
				 be64_to_cpu(p->sector),
				 be32_to_cpu(p->blksize));
	} else {
		req=(drbd_request_t*)(long)p->block_id;

		ERR_IF ((unsigned long)req <= 1) return FALSE;
		ERR_IF (!VALID_POINTER(req)) return FALSE;

		drbd_end_req(req, RQ_DRBD_SENT, 1);
	}
	/*WARN("BlockAck: %lx %lx %x\n",
	    (long) p->block_id,
	    (long) be64_to_cpu(p->sector),
	    be32_to_cpu(p->blksize));*/

	// TODO: Make sure that the block is in an active epoch!!
	if(mdev->conf.wire_protocol != DRBD_PROT_A ||
	   is_syncer_blk(mdev,p->block_id)) {
		dec_pending(mdev,HERE);
	}

	return TRUE;
}

STATIC int receive_Barrier(drbd_dev *mdev, Drbd_Header* h)
{
	int rv;
	int epoch_size;
	Drbd_Barrier_Packet *p = (Drbd_Barrier_Packet*)h;

	ERR_IF(mdev->state != Secondary) return FALSE;
	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, mdev->sock, PAYLOAD_P(h), h->length);
	ERR_IF(rv != h->length) return FALSE;

	inc_unacked(mdev);

	// DBG("got Barrier\n");

	if (mdev->conf.wire_protocol != DRBD_PROT_C)
		run_task_queue(&tq_disk);

	drbd_wait_ee(mdev,&mdev->active_ee,&mdev->done_ee);

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

STATIC int receive_BarrierAck(drbd_dev *mdev, Drbd_Header* h)
{
	int rv;
	Drbd_BarrierAck_Packet *p = (Drbd_BarrierAck_Packet*)h;

	ERR_IF(mdev->state != Primary) return FALSE;
	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	rv = drbd_recv(mdev, mdev->msock, PAYLOAD_P(h), h->length);
	ERR_IF(rv != h->length) return FALSE;

	tl_release(mdev,p->barrier,be32_to_cpu(p->set_size));
	dec_pending(mdev,HERE);

	return TRUE;
}

STATIC struct Tl_epoch_entry *
read_in_block(drbd_dev *mdev,int data_size)
{
	struct Tl_epoch_entry *e;
	struct buffer_head *bh;
	int rr;

	spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev,TRUE);
	spin_unlock_irq(&mdev->ee_lock);
	bh=e->bh;

	rr=drbd_recv(mdev,mdev->sock,bh_kmap(bh),data_size);
	bh_kunmap(bh);

	if ( rr != data_size) {
		clear_bit(BH_Lock, &bh->b_state);
		spin_lock_irq(&mdev->ee_lock);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);
		return 0;
	}

	/* do not use mark_buffer_dirty() since it would call refile_buffer()*/
	bh=e->bh;
	set_bit(BH_Dirty, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state); // since using generic_make_request()
	bh->b_end_io = drbd_dio_end_sec;
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
		run_task_queue(&tq_disk);
	}
#undef NUMBER

	mdev->writ_cnt+=data_size>>9;
}

int recv_dless_read(drbd_dev *mdev, struct Pending_read *pr,
		    sector_t sector, int data_size)
{
	struct buffer_head *bh;
	int ok,rr;

	// DBG("%s\n", __func__);

	bh = pr->d.bh;

	D_ASSERT( sector == APP_BH_SECTOR(bh) );

	rr=drbd_recv(mdev,mdev->sock,bh_kmap(bh),data_size);
	bh_kunmap(bh);

	ok=(rr==data_size);
	bh->b_end_io(bh,ok);

	dec_pending(mdev,HERE);
	return ok;
}

STATIC int e_end_resync_block(drbd_dev *mdev, struct Tl_epoch_entry *e)
{
	drbd_set_in_sync(mdev,DRBD_BH_SECTOR(e->bh),e->bh->b_size);
	drbd_send_ack(mdev,WriteAck,e);
	dec_unacked(mdev,HERE); // FIXME unconditional ??
	return TRUE;
}

int recv_resync_read(drbd_dev *mdev, struct Pending_read *pr,
		     sector_t sector, int data_size)
{
	struct Tl_epoch_entry *e;

	// DBG("%s\n", __func__);

	D_ASSERT( pr->d.sector == sector);

	e = read_in_block(mdev,data_size);
	ERR_IF(!e) return FALSE;
	drbd_set_bh(mdev, e->bh, sector ,data_size);
	e->block_id = ID_SYNCER;
	e->e_end_io = e_end_resync_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->ee_lock);

	dec_pending(mdev,HERE);
	inc_unacked(mdev);

	drbd_al_begin_io(mdev, sector);
	generic_make_request(WRITE,e->bh);

	receive_data_tail(mdev,data_size);
	return TRUE;
}


int recv_both_read(drbd_dev *mdev, struct Pending_read *pr,
		   sector_t sector, int data_size)
{
	struct Tl_epoch_entry *e;
	struct buffer_head *bh;

	// DBG("%s\n", __func__);

	bh = pr->d.bh;

	D_ASSERT( sector == bh->b_blocknr * (bh->b_size >> 9) );

	e = read_in_block(mdev,data_size);

	if(!e) {
		bh->b_end_io(bh,0);
		return FALSE;
	}

	// XXX can't we share it somehow?
	memcpy(bh_kmap(bh),bh_kmap(e->bh),data_size);
	bh_kunmap(bh);
	bh_kunmap(e->bh);

	bh->b_end_io(bh,1);

	drbd_set_bh(mdev, e->bh, sector, data_size);
	e->block_id = ID_SYNCER;
	e->e_end_io = e_end_resync_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->ee_lock);

	dec_pending(mdev,HERE);
	inc_unacked(mdev);

	drbd_al_begin_io(mdev, sector);
	generic_make_request(WRITE,e->bh);

	receive_data_tail(mdev,data_size);
	return TRUE;
}

int recv_discard(drbd_dev *mdev, struct Pending_read *pr /* ignored */,
		 sector_t sector, int data_size)
{
	// THINK maybe ignore this block without using EEs ?
	struct Tl_epoch_entry *e;

	// DBG("%s\n", __func__);

	e = read_in_block(mdev,data_size);
	ERR_IF(!e) return FALSE;

	drbd_set_bh(mdev, e->bh, sector ,data_size);
	drbd_send_ack(mdev,WriteAck,e);

	spin_lock_irq(&mdev->ee_lock);
	drbd_put_ee(mdev,e);
	spin_unlock_irq(&mdev->ee_lock);

	dec_pending(mdev,HERE);

	return TRUE;
}

STATIC int receive_DataReply(drbd_dev *mdev,Drbd_Header* h)
{
	struct Pending_read *pr;
	sector_t sector;
	unsigned int header_size,data_size;
	int ok;
	Drbd_Data_Packet *p = (Drbd_Data_Packet*)h;

	static int (*funcs[])(struct Drbd_Conf* , struct Pending_read*,
		      unsigned long,int) = {
			      [Discard]      = recv_discard,
			      [Application]  = recv_dless_read,
			      [Resync]       = recv_resync_read,
			      [AppAndResync] = recv_both_read
		      };

	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	/* I expect a block to be a multiple of 512 byte, and
	 * no more than 4K (8K). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0xff) return FALSE;
	ERR_IF(data_size >  PAGE_SIZE) return FALSE;

	if (drbd_recv(mdev, mdev->sock, PAYLOAD_P(h), header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);

	pr = (struct Pending_read *)(long)p->block_id;

	// these would be BUG()s ...
	ERR_IF(!VALID_POINTER(pr)) return FALSE;

	// XXX are enums unsigned by default?
	ERR_IF((unsigned)pr->cause > AppAndResync) {
		return FALSE;
	}

	/* Take it out of the list before calling the handler, since the
	   handler could be changed by make_req as long as it is on the list
	*/
	spin_lock(&mdev->pr_lock);
	list_del(&pr->list);
	spin_unlock(&mdev->pr_lock);

	ok = funcs[pr->cause](mdev,pr,sector,data_size);
	INVALIDATE_MAGIC(pr);
	mempool_free(pr,drbd_pr_mempool);
	return ok;
}

STATIC int e_end_block(drbd_dev *mdev, struct Tl_epoch_entry *e)
{
	int ok=TRUE;

	mdev->epoch_size++;
	if(mdev->conf.wire_protocol == DRBD_PROT_C) {
		ok=drbd_send_ack(mdev,WriteAck,e);
		dec_unacked(mdev,HERE); // FIXME unconditional ??
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

	// DBG("%s\n", __func__);

	// FIXME merge this code dups into some helper function
	header_size = sizeof(*p) - sizeof(*h);
	data_size   = h->length  - header_size;

	/* I expect a block to be a multiple of 512 byte, and
	 * no more than 4K (8K). is this too restrictive?
	 */
	ERR_IF(data_size == 0) return FALSE;
	ERR_IF(data_size &  0xff) return FALSE;
	ERR_IF(data_size >  PAGE_SIZE) return FALSE;

	if (drbd_recv(mdev, mdev->sock, PAYLOAD_P(h), header_size) != header_size)
		return FALSE;

	sector = be64_to_cpu(p->sector);

	e = read_in_block(mdev,data_size);
	ERR_IF(!e) return FALSE;

	drbd_set_bh(mdev, e->bh, sector, data_size);
	e->block_id = p->block_id; // no meaning on this side, e* on partner
	e->e_end_io = e_end_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->list,&mdev->active_ee);
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

	drbd_al_begin_io(mdev, sector);
	generic_make_request(WRITE,e->bh);

	receive_data_tail(mdev,data_size);
	return TRUE;
}

STATIC int e_end_data_req(drbd_dev *mdev, struct Tl_epoch_entry *e)
{
	int ok;
	ok=drbd_send_block(mdev, DataReply, e);
	dec_unacked(mdev,HERE); // THINK unconditional?
	return ok;
}

STATIC int e_end_rsdata_req(drbd_dev *mdev, struct Tl_epoch_entry *e)
{
	int ok;
	inc_pending(mdev);
	ok=drbd_send_block(mdev, DataReply, e);
	dec_unacked(mdev,HERE); // THINK unconditional?
	return ok;
}

STATIC int receive_DataRequest(drbd_dev *mdev,Drbd_Header *h)
{
	sector_t sector;
	struct Tl_epoch_entry *e;
	struct buffer_head *bh;
	int data_size;
	Drbd_BlockRequest_Packet *p = (Drbd_BlockRequest_Packet*)h;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, mdev->sock, PAYLOAD_P(h), h->length) != h->length)
		return FALSE;

	sector    = be64_to_cpu(p->sector);
	data_size = be32_to_cpu(p->blksize);

	spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev,TRUE);
	drbd_set_bh(mdev, e->bh, sector, data_size);
	e->block_id = p->block_id; // no meaning on this side, pr* on partner
	list_add(&e->list,&mdev->read_ee);
	spin_unlock_irq(&mdev->ee_lock);

	switch(h->command) {
	case DataRequest:     e->e_end_io = e_end_data_req; break;
	case RSDataRequest:   e->e_end_io = e_end_rsdata_req; break;
	default:
	      D_ASSERT(0);
	}

	bh=e->bh;
	clear_bit(BH_Uptodate, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state);
	e->bh->b_end_io = drbd_dio_end_read;

	spin_lock_irq(&mdev->bb_lock);
	if(tl_check_sector(mdev,sector)) {
		struct busy_block bl;
		bb_wait_prepare(mdev,sector,&bl);
		spin_unlock_irq(&mdev->bb_lock);
		bb_wait(&bl);
	} else spin_unlock_irq(&mdev->bb_lock);

	mdev->read_cnt += bh->b_size >> 9;
	inc_unacked(mdev);
	generic_make_request(READ,e->bh);

	return TRUE;
}

STATIC int receive_SyncParam(drbd_dev *mdev,Drbd_Header *h)
{
	int ok = TRUE;
	Drbd_SyncParam_Packet *p = (Drbd_SyncParam_Packet*)h;

	// FIXME move into helper
	ERR_IF(h->length == (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, mdev->sock, PAYLOAD_P(h), h->length) != h->length)
		return FALSE;

	// XXX harmless race with ioctl ...
	mdev->sync_conf.rate      = be32_to_cpu(p->rate);
	mdev->sync_conf.use_csums = be32_to_cpu(p->use_csums);
	mdev->sync_conf.skip      = be32_to_cpu(p->skip);
	mdev->sync_conf.group     = be32_to_cpu(p->group);

	if (   (mdev->cstate == SkippedSyncS || mdev->cstate == SkippedSyncT)
	    && !mdev->sync_conf.skip )
	{
		set_cstate(mdev,WFReportParams);
		ok = drbd_send_param(mdev);
	}

	return ok;
}

STATIC int receive_param(drbd_dev *mdev, Drbd_Header *h)
{
	Drbd_Parameter_Packet *p = (Drbd_Parameter_Packet*)h;
	int minor=(int)(mdev-drbd_conf);
	int no_sync=0;
	int oo_state;
	unsigned long p_size;

	ERR_IF(h->length != (sizeof(*p)-sizeof(*h))) return FALSE;

	if (drbd_recv(mdev, mdev->sock, PAYLOAD_P(h), h->length) != h->length)
		return FALSE;

	if(be32_to_cpu(p->state) == Primary && mdev->state == Primary ) {
		ERR("incompatible states\n");
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(p->version)!=PRO_VERSION) {
		ERR("incompatible releases \n");
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(p->protocol)!=mdev->conf.wire_protocol) {
		ERR("incompatible protocols \n");
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	// XXX harmless race with ioctl ...
	mdev->sync_conf.rate  =
		max_t(int,mdev->sync_conf.rate, be32_to_cpu(p->sync_rate));
	/* FIXME how to decide when use_csums differs??
		mdev->sync_conf.use_csums  = ???
	 */
	// if one of them wants to skip, both of them should skip.
	mdev->sync_conf.skip  =
		mdev->sync_conf.skip != 0 || p->skip_sync != 0;
	mdev->sync_conf.group =
		min_t(int,mdev->sync_conf.group,be32_to_cpu(p->sync_group));

	/* should be removed ?
	if(be64_to_cpu(param.protocol)!=mdev->lo_usize) {
		printk(KERN_ERR DEVICE_NAME"%d: Size hints inconsistent \n",
		       minor);
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}
	*/

	p_size=be64_to_cpu(p->p_size);
	mdev->p_size=p_size;
	mdev->p_usize=be64_to_cpu(p->u_size);
	if(p_size) clear_bit(PARTNER_DISKLESS, &mdev->flags);
	else set_bit(PARTNER_DISKLESS, &mdev->flags);

	no_sync=drbd_determin_dev_size(mdev);

	if( blk_size[MAJOR_NR][minor] == 0) {
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	if (mdev->cstate == WFReportParams) {
		int have_good,quick,sync;
		INFO("Connection established.\n");

		have_good=drbd_md_compare(mdev,p);

		if(have_good==0) sync=0;
		else sync=1;

		quick=drbd_md_syncq_ok(mdev,p,have_good==1);

		INFO("have_good=%d sync=%d quick=%d\n",
		     have_good, sync, quick);

		if ( mdev->sync_conf.skip && sync && !no_sync ) {
			if (have_good == 1)
				set_cstate(mdev,SkippedSyncS);
			else // have_good == -1
				set_cstate(mdev,SkippedSyncT);
			goto skipped;
		}

		if( sync && !no_sync ) {
			if(have_good == 1) {
				if(quick) {
					drbd_send_bitmap(mdev);
				} else {
					mdev->rs_total=
						blk_size[MAJOR_NR][minor]<<1;
				}
				drbd_start_resync(mdev,SyncSource);
			} else { // have_good == -1
				mdev->gen_cnt[Flags] &= ~MDF_Consistent;
				if(!quick) {
					ERR_IF(!mdev->mbds_id)
						return FALSE;
					bm_fill_bm(mdev->mbds_id,-1);
					mdev->rs_total=
						blk_size[MAJOR_NR][minor]<<1;
					drbd_start_resync(mdev,SyncTarget);
				} else {
					set_cstate(mdev,WFBitMap);
				}
			}
		} else set_cstate(mdev,Connected);

		if (have_good == -1) {
			/* Sync-Target has to adopt source's gen_cnt. */
			int i;
			for(i=HumanCnt;i<=ArbitraryCnt;i++) {
				mdev->gen_cnt[i]=be32_to_cpu(p->gen_cnt[i]);
			}
		}
	}
	drbd_md_write(mdev); // update connected indicator, la_size, ...

	// do not adopt gen counts when sync was skipped ...
skipped:

	oo_state = mdev->o_state;
	mdev->o_state = be32_to_cpu(p->state);
	if(oo_state == Secondary && mdev->o_state == Primary) {
		drbd_md_inc(mdev,ConnectedCnt);
		drbd_md_write(mdev);
	}

	return TRUE;
}

/* Author: Gurmeet Singh Manku    (manku@cs.stanford.edu)

   Parallel   Count   carries   out    bit   counting   in   a   parallel
   fashion.   Consider   n   after    the   first   line   has   finished
   executing. Imagine splitting n into  pairs of bits. Each pair contains
   the <em>number of ones</em> in those two bit positions in the original
   n.  After the second line has finished executing, each nibble contains
   the  <em>number of  ones</em>  in  those four  bits  positions in  the
   original n. Continuing  this for five iterations, the  64 bits contain
   the  number  of ones  among  these  sixty-four  bit positions  in  the
   original n. That is what we wanted to compute. */

#define TWO(c) (0x1lu << (c))
#define MASK(c) (((unsigned long)(-1)) / (TWO(TWO(c)) + 1lu))
#define COUNT(x,c) ((x) & MASK(c)) + (((x) >> (TWO(c))) & MASK(c))

static inline unsigned long parallel_bitcount (unsigned long n)
{
	n = COUNT(n, 0); //MASK(c)=01010101 // (n&mask)+((n>>1)&mask)
	n = COUNT(n, 1); //MASK(c)=00110011 // (n&mask)+((n>>2)&mask)
	n = COUNT(n, 2); //MASK(c)=00001111 // (n&mask)+((n>>4)&mask)
	n = COUNT(n, 3); // ...etc...
	n = COUNT(n, 4);
#if BITS_PER_LONG == 64
	n = COUNT(n, 5);
#endif
	return n ;
}

#undef TWO
#undef MASK
#undef COUNT

STATIC int receive_bitmap(drbd_dev *mdev, Drbd_Header *h)
{
	size_t bm_words;
	u32 *buffer,*bm,word;
	int buf_i,want;
	int ok=FALSE, bm_i=0;
	unsigned long bits=0;

	bm_words=mdev->mbds_id->size/sizeof(u32);
	bm=(u32*)mdev->mbds_id->bm;
	buffer=vmalloc(MBDS_PACKET_SIZE);

	while (1) {
		want=min_t(int,MBDS_PACKET_SIZE,(bm_words-bm_i)*sizeof(u32));
		D_ASSERT(want == h->length);
		if (want != h->length) goto out;
		if (want==0) break;
		if (drbd_recv(mdev, mdev->sock, buffer, want) != want)
			goto out;
		for(buf_i=0;buf_i<want/sizeof(u32);buf_i++) {
			word = be32_to_cpu(buffer[buf_i]);
			bits += parallel_bitcount(word);
			bm[bm_i++] = word;
		}
		if (!drbd_recv_header(mdev,mdev->sock,h))
			goto out;
		D_ASSERT(h->command == ReportBitMap);
	}

	mdev->rs_total = bits << (BM_BLOCK_SIZE_B - 9); // in sectors
	drbd_start_resync(mdev,SyncTarget);
	ok=TRUE;
 out:
	vfree(buffer);
	return ok;
}

STATIC void drbd_collect_zombies(drbd_dev *mdev)
{
	if(test_and_clear_bit(COLLECT_ZOMBIES,&mdev->flags)) {
		while( waitpid(-1, NULL, __WCLONE|WNOHANG) > 0 );
	}
}

STATIC void drbd_fail_pending_reads(drbd_dev *mdev)
{
	struct Pending_read *pr;
	struct list_head workset,*le;
	struct buffer_head *bh;

	spin_lock(&mdev->pr_lock);
	list_add(&workset,&mdev->app_reads);
	list_del(&mdev->app_reads);
	INIT_LIST_HEAD(&mdev->app_reads);
	spin_unlock(&mdev->pr_lock);

	while(!list_empty(&workset)) {
		le = workset.next;
		pr = list_entry(le, struct Pending_read, list);
		bh = pr->d.bh;
		list_del(le);

		bh->b_end_io(bh,0);
		dec_pending(mdev,HERE);

		INVALIDATE_MAGIC(pr);
		mempool_free(pr,drbd_pr_mempool);
	}

	spin_lock(&mdev->pr_lock);
	list_add(&workset,&mdev->resync_reads);
	list_del(&mdev->resync_reads);
	INIT_LIST_HEAD(&mdev->resync_reads);
	spin_unlock(&mdev->pr_lock);

	while(!list_empty(&workset)) {
		le = workset.next;
		list_del(le);
		pr = list_entry(le, struct Pending_read, list);
		mempool_free(pr,drbd_pr_mempool);
		INVALIDATE_MAGIC(pr);
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
		r = drbd_recv(mdev,mdev->sock,sink,want);
		D_ASSERT(r >= 0);
		if (r < 0) break;
		size -= r;
	}
	return (size == 0);
}

STATIC int receive_BecomeSyncTarget(drbd_dev *mdev, Drbd_Header *h)
{
	ERR_IF(!mdev->mbds_id)
		return FALSE;
	bm_fill_bm(mdev->mbds_id,-1);
	mdev->rs_total = blk_size[MAJOR_NR][(int)(mdev-drbd_conf)]<<1;
	drbd_start_resync(mdev,SyncTarget);
	return TRUE; // cannot fail ?
}

STATIC int receive_BecomeSyncSource(drbd_dev *mdev, Drbd_Header *h)
{
	mdev->rs_total = blk_size[MAJOR_NR][(int)(mdev-drbd_conf)]<<1;
	drbd_start_resync(mdev,SyncSource);
	return TRUE; // cannot fail ?
}

STATIC int receive_BecomeSec(drbd_dev *mdev, Drbd_Header *h)
{
	drbd_set_state(mdev,Secondary);
	return TRUE; // cannot fail ?
}

STATIC int receive_WriteHint(drbd_dev *mdev, Drbd_Header *h)
{
	run_task_queue(&tq_disk);
	return TRUE; // cannot fail, only deadlock :)
}

STATIC int receive_SyncStop(drbd_dev *mdev, Drbd_Header *h)
{
	D_ASSERT(mdev->cstate == SyncSource);
	set_cstate(mdev,PausedSyncS);
	return TRUE; // cannot fail ?
}

STATIC int receive_SyncCont(drbd_dev *mdev, Drbd_Header *h)
{
	D_ASSERT(mdev->cstate == PausedSyncS);
	set_cstate(mdev,SyncSource);
	return TRUE; // cannot fail ?
}

typedef int (*drbd_cmd_handler_f)(drbd_dev*,Drbd_Header*);

static drbd_cmd_handler_f drbd_default_handler[] = {
	[WakeAsender]      = NULL, // this is never seen on the net
	[Data]             = receive_Data,
	[DataReply]        = receive_DataReply,
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
	[BecomeSec]        = receive_BecomeSec,
	[WriteHint]        = receive_WriteHint,
	[DataRequest]      = receive_DataRequest,
	[RSDataRequest]    = receive_DataRequest, //receive_RSDataRequest,
	[SyncParam]        = receive_SyncParam,
	[SyncStop]         = receive_SyncStop,
	[SyncCont]         = receive_SyncCont,
};

static drbd_cmd_handler_f *drbd_cmd_handler = drbd_default_handler;
static drbd_cmd_handler_f *drbd_opt_cmd_handler = NULL;

STATIC void drbdd(drbd_dev *mdev)
{
	drbd_cmd_handler_f handler;
	/* now I have enough space on the stack for the biggest packet
	 * (ReportParams). Data and Bitmap are handled different
	 * anyways. Maybe this should be allocated nevertheless?
	 */
	Drbd_Polymorph_Packet packet;
	Drbd_Header *header = (Drbd_Header*)&packet;

	for (;;) {
		drbd_collect_zombies(mdev); // in case a syncer exited.
		if (!drbd_recv_header(mdev,mdev->sock,header))
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
	}
}

void drbd_disconnect(drbd_dev *mdev)
{
	int i;

	mdev->o_state = Unknown;
	drbd_thread_stop_nowait(&mdev->dsender);
	drbd_thread_stop(&mdev->asender);

	while(down_trylock(&mdev->sock_mutex))
	{
		struct task_struct *task;
		spin_lock(&mdev->send_task_lock);
		if((task=mdev->send_task)) {
			drbd_queue_signal(DRBD_SIG, task);
			spin_unlock(&mdev->send_task_lock);
			down(&mdev->sock_mutex);
			break;
		} else {
			spin_unlock(&mdev->send_task_lock);
			schedule_timeout(HZ / 10);
		}
	}
	/* By grabbing the sock_mutex we make sure that no one
	   uses the socket right now. */
	drbd_free_sock(mdev);
	up(&mdev->sock_mutex);

	drbd_thread_stop(&mdev->dsender);
	drbd_collect_zombies(mdev);

	if(mdev->cstate != StandAlone)
		set_cstate(mdev,Unconnected);

	for(i=0;i<=ArbitraryCnt;i++) {
		mdev->bit_map_gen[i]=mdev->gen_cnt[i];
	}

	drbd_fail_pending_reads(mdev);

	switch(mdev->state) {
	case Primary:
		tl_clear(mdev);
		clear_bit(ISSUE_BARRIER,&mdev->flags);
		if(!test_bit(DO_NOT_INC_CONCNT,&mdev->flags))
			drbd_md_inc(mdev,ConnectedCnt);
		drbd_md_write(mdev);
		break;
	case Secondary:
		drbd_wait_ee(mdev,&mdev->active_ee, &mdev->done_ee);
		drbd_wait_ee(mdev,&mdev->sync_ee, &mdev->done_ee);
		drbd_clear_done_ee(mdev);
		mdev->epoch_size=0;
		break;
	default:
		D_ASSERT(0);
	}

	if(atomic_read(&mdev->unacked_cnt)) {
		ERR("unacked_cnt!=0\n");
		atomic_set(&mdev->unacked_cnt,0);
	}

	/* Since syncer's blocks are also counted, there is no hope that
	   pending_cnt is zero. */
	atomic_set(&mdev->pending_cnt,0);
	wake_up_interruptible(&mdev->state_wait);

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
		if (!drbd_connect(mdev)) break;
		if (thi->t_state == Exiting) break;
		drbdd(mdev);
		drbd_disconnect(mdev);
		if (thi->t_state == Exiting) break;
		if (thi->t_state == Restarting) {
			unsigned long flags;
			thi->t_state = Running;

			LOCK_SIGMASK(current,flags);
			if (sigismember(&current->pending.signal, SIGTERM)) {
				sigdelset(&current->pending.signal, SIGTERM);
				RECALC_SIGPENDING(current);
			}
			UNLOCK_SIGMASK(current,flags);
		}
	}

	INFO("receiver exiting\n");

	/* set_cstate(mdev,StandAlone); */

	return 0;
}

/* ********* acknowledge sender ******** */

STATIC int drbd_try_send_barrier(drbd_dev *mdev)
{
	int rv=TRUE;
	if(down_trylock(&mdev->sock_mutex)==0) {
		if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
			if(! _drbd_send_barrier(mdev)) rv=FALSE;
		}
		up(&mdev->sock_mutex);
	}
	return rv;
}

int drbd_asender(struct Drbd_thread *thi)
{
	int ok;
	unsigned long flags = 0;
	drbd_dev *mdev = thi->mdev;
	Drbd_Polymorph_Packet p; // XXX BarrierAck_Packet should be enough ...
	Drbd_Header *header = (Drbd_Header*)&p;

	sprintf(current->comm, "drbd%d_asender", (int)(mdev-drbd_conf));

	current->policy = SCHED_RR;  /* Make this a realtime task! */
	current->rt_priority = 2;    /* more important than all other tasks */

	while(thi->t_state == Running) {
		if (test_and_clear_bit(SEND_PING, &mdev->flags)) {
			ERR_IF(!drbd_send_ping(mdev)) goto err;
			// half ack timeout only,
			// since sendmsg waited the other half already
			mdev->msock->sk->rcvtimeo =
				mdev->conf.timeout*HZ/20;
		}

		set_bit(MAY_WAKE_ASENDER,&mdev->flags);
		ok = drbd_recv_header(mdev,mdev->msock,header);

		ERR_IF(!ok)
			goto err;

		/* we don't want to be "woken up" by DRBD_SIG while
		 * receiving payload data, nor while sending out pings
		 * and acks!  SIGTERM is unaffected...
		 */
		clear_bit(MAY_WAKE_ASENDER,&mdev->flags);
		LOCK_SIGMASK(current,flags); // implicit wmb()
		if (sigismember(&current->pending.signal, DRBD_SIG)) {
			sigdelset(&current->pending.signal, DRBD_SIG);
			RECALC_SIGPENDING(current);
		}
		UNLOCK_SIGMASK(current,flags);


		// MAYBE use jump table

		switch (header->command) {
		case WakeAsender:
			// we were just woken up
			break;
		case Ping:
			ERR_IF(!drbd_send_ping_ack(mdev))
				goto err;
			// If partner pings me, maybe its time to kick IO
			//run_task_queue(&tq_disk);
			break;
		case PingAck:
			// restore idle timeout
			mdev->msock->sk->rcvtimeo =
				mdev->conf.ping_int*HZ;
			break;
		case RecvAck:
		case WriteAck:
			ERR_IF(!receive_BlockAck(mdev,header))
				goto err;
			break;
		case BarrierAck:
			ERR_IF(!receive_BarrierAck(mdev, header))
				goto err;
			break;
		default:
			D_ASSERT(0);
		}


		if( mdev->state == Primary ) {
			ERR_IF(!drbd_try_send_barrier(mdev))
				goto err;
		}

		ERR_IF(!drbd_process_ee(mdev,&mdev->done_ee))
			goto err;
	} //while

	if(0) {
	err:
		drbd_thread_restart_nowait(&mdev->receiver);
	}

	INFO("asender terminated\n");

	return 0;
}

