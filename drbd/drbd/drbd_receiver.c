/*
-*- linux-c -*-
   drbd_receiver.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2002, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
        Code to prevent zombie threads.

   Copyright (C) 2002, Lars Ellenberg <l.g.e@web.de>.
        some SMP fixes; syncer progress

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
#include <asm/types.h>
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
#define EE_MAXIMUM 2048  // @4k pages => 8   MByte

#define is_syncer_blk(A,B) ((B)==ID_SYNCER)

#if 0
STATIC inline int is_syncer_blk(struct Drbd_Conf* mdev, u64 block_id) 
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
	int wake_asender=0;
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=drbd_lldev_to_mdev(bh->b_dev);

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
	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);

	clear_bit(BH_Dirty, &bh->b_state);
	clear_bit(BH_Lock, &bh->b_state);

	/* Do not move a BH if someone is in wait_on_buffer */
	if(atomic_read(&bh->b_count) == 0) {
		list_del(&e->list);
		list_add(&e->list,&mdev->done_ee);
	}
	spin_unlock_irqrestore(&mdev->ee_lock,flags);

	if (waitqueue_active(&bh->b_wait))
		wake_up(&bh->b_wait);

	if(mdev->conf.wire_protocol == DRBD_PROT_C ||
	   e->block_id == ID_SYNCER ) wake_asender=1;

	if( mdev->do_panic && !uptodate) {
		panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	if(wake_asender) {
		drbd_queue_signal(DRBD_SIG, mdev->asender.task);
	}
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

STATIC void _drbd_alloc_ee(struct Drbd_Conf* mdev,struct page* page)
{
	struct Tl_epoch_entry* e;
	struct buffer_head *bh,*lbh,*fbh;
	int number,buffer_size,i;

	buffer_size=1<<mdev->blk_size_b;
	number=PAGE_SIZE/buffer_size;
	lbh=NULL;
	bh=NULL;
	fbh=NULL;

	for(i=0;i<number;i++) {
		e=kmalloc(sizeof(struct Tl_epoch_entry)+
			  sizeof(struct buffer_head),GFP_KERNEL);

		if( e == NULL ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: could not kmalloc() new ee\n",
			       (int)(mdev-drbd_conf));
			BUG();
		}
		
		bh=(struct buffer_head*)(((char*)e)+
					 sizeof(struct Tl_epoch_entry));

		drbd_init_bh(bh, buffer_size);
		set_bh_page(bh,page,i*buffer_size); // sets b_data and b_page

		e->bh=bh;
		bh->b_private=e;

		e->block_id=0; //all entries on the free_ee should have 0 here
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

STATIC int drbd_alloc_ee(struct Drbd_Conf* mdev,int mask)
{
	struct page *page;

	page=alloc_page(mask);
	if(!page) return FALSE;

	_drbd_alloc_ee(mdev,page);
	/*
	printk(KERN_ERR DEVICE_NAME "%d: vacant=%d in_use=%d sum=%d\n",
	       (int)(mdev-drbd_conf),mdev->ee_vacant,mdev->ee_in_use,
	       mdev->ee_vacant+mdev->ee_in_use);
	*/
	return TRUE;
}

STATIC struct page* drbd_free_ee(struct Drbd_Conf* mdev, struct list_head *list)
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
			if(e->block_id) freeable=0;
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
		nbh=nbh->b_this_page;
		/*printk(KERN_ERR DEVICE_NAME "%d: kfree(%p)\n",
		  (int)(mdev-drbd_conf),e);*/
		kfree(e);
	} while(nbh != bh);

	return page;
}

void drbd_init_ee(struct Drbd_Conf* mdev)
{
	while(mdev->ee_vacant < EE_MININUM ) {
		drbd_alloc_ee(mdev,GFP_USER);
	}
}

int drbd_release_ee(struct Drbd_Conf* mdev,struct list_head* list)
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

STATIC void drbd_ee_fix_bhs(struct Drbd_Conf* mdev)
{
	struct list_head workset;
	struct page* page;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&workset,&mdev->free_ee); // insert the new head
	list_del(&mdev->free_ee);          // remove the old head
	INIT_LIST_HEAD(&mdev->free_ee); 
	// now all elements are in the "workset" list, free_ee is empty!

	while(!list_empty(&workset)) {
		page=drbd_free_ee(mdev,&workset);
		if(page) {
			spin_unlock_irq(&mdev->ee_lock);
			_drbd_alloc_ee(mdev,page);
			spin_lock_irq(&mdev->ee_lock);
		}
	}
	spin_unlock_irq(&mdev->ee_lock);
}

#define GFP_TRY	( __GFP_HIGHMEM )

struct Tl_epoch_entry* drbd_get_ee(struct Drbd_Conf* mdev,int may_sleep)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;

	MUST_HOLD(&mdev->ee_lock);

	if(test_bit(BLKSIZE_CHANGING,&mdev->flags)) return 0;

	if(mdev->ee_vacant == EE_MININUM / 2) {
		spin_unlock_irq(&mdev->ee_lock);
		run_task_queue(&tq_disk);
		spin_lock_irq(&mdev->ee_lock);
	}

	while(list_empty(&mdev->free_ee)) {
		_drbd_process_ee(mdev,&mdev->done_ee);
		if(!list_empty(&mdev->free_ee)) break;
		spin_unlock_irq(&mdev->ee_lock);
		if((mdev->ee_vacant+mdev->ee_in_use) < EE_MAXIMUM) {
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
	e->block_id=1;//the entries not on free_ee should not have 0 here.
	return e;
}

void drbd_put_ee(struct Drbd_Conf* mdev,struct Tl_epoch_entry *e)
{
	struct page* page;

	MUST_HOLD(&mdev->ee_lock);

	mdev->ee_in_use--;
	mdev->ee_vacant++;
	e->block_id=0; //all entries on the free_ee should have 0 here
	list_add(&e->list,&mdev->free_ee);

	if(mdev->ee_vacant * 2 > mdev->ee_in_use) {
		page=drbd_free_ee(mdev,&mdev->free_ee);
		if( page ) __free_page(page);
	}
	if(mdev->ee_in_use == 0) {
		while( mdev->ee_vacant > EE_MININUM ) {
			__free_page(drbd_free_ee(mdev,&mdev->free_ee));
		}
	}
}

int _drbd_process_ee(struct Drbd_Conf* mdev,struct list_head *head)
{
	struct list_head workset;
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int ok=1;

	MUST_HOLD(&mdev->ee_lock);

	while(!list_empty(head)) {
		list_add(&workset,head);
		list_del(head);
		INIT_LIST_HEAD(head);
		spin_unlock_irq(&mdev->ee_lock);
		while(!list_empty(&workset)) {
			le = workset.next;
			list_del(le);
			e = list_entry(le, struct Tl_epoch_entry,list);
			ok = ok && e->e_end_io(mdev,e);
			spin_lock_irq(&mdev->ee_lock);
			drbd_put_ee(mdev,e);
			spin_unlock_irq(&mdev->ee_lock);
		}
		spin_lock_irq(&mdev->ee_lock);
	}

	wake_up_interruptible(&mdev->ee_wait);

	return ok;
}

STATIC int drbd_process_ee(struct Drbd_Conf* mdev,struct list_head *head)
{
	int rv;
	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_ee(mdev,head);
	spin_unlock_irq(&mdev->ee_lock);
	return rv;
}

STATIC inline void drbd_clear_done_ee(struct Drbd_Conf *mdev)
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
			dec_unacked(mdev);
		}

	}

	spin_unlock_irq(&mdev->ee_lock);
}


STATIC void drbd_wait_ee(struct Drbd_Conf* mdev,struct list_head *head,
			 struct list_head *to)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;

	spin_lock_irq(&mdev->ee_lock);
	while(!list_empty(head)) {
		le = head->next;
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(!buffer_locked(e->bh)) {
			printk(KERN_ERR DEVICE_NAME 
			       "%d: unlocked bh in ative_ee/sync_ee/read_ee\n"
			       "(BUG?) Moving bh=%p to done_ee/rdone_ee\n",
			       (int)(mdev-drbd_conf),e->bh);
			list_del(le);
			list_add(le,to);
			continue;
		}
		get_bh(e->bh); 
		spin_unlock_irq(&mdev->ee_lock);
		wait_on_buffer(e->bh);
		spin_lock_irq(&mdev->ee_lock);
		put_bh(e->bh);
		/* The IRQ handler does not move a list entry if someone is 
		   in wait_on_buffer for that entry, therefore we have to
		   move it here. */
		list_del(le); 
		list_add(le,to);
	}
	spin_unlock_irq(&mdev->ee_lock);
}

STATIC void drbd_c_timeout(unsigned long arg)
{
	struct task_struct *p = (struct task_struct *) arg;

	/*
	printk(KERN_INFO DEVICE_NAME" : retrying to connect(pid=%d)\n",p->pid);
	*/

	drbd_queue_signal(DRBD_SIG,p);

}

STATIC struct socket* drbd_accept(struct socket* sock)
{
	struct socket *newsock;
	int err = 0;

	lock_kernel();

	err = sock->ops->listen(sock, 5);
	if (err)
		goto out;

	if (!(newsock = sock_alloc()))
		goto out;

	newsock->type = sock->type;

	newsock->ops = sock->ops;

	if (err < 0)
		goto out_release;

	err = newsock->ops->accept(sock, newsock, 0);
	if (err < 0)
		goto out_release;

	unlock_kernel();
	return newsock;

      out_release:
	sock_release(newsock);
      out:
	unlock_kernel();
	if(err != -ERESTARTSYS)
		printk(KERN_ERR DEVICE_NAME " : accept failed! %d\n", err);
	return 0;
}

struct idle_timer_info {
	struct Drbd_Conf *mdev;
	struct timer_list idle_timeout;
	int restart;
};


STATIC void drbd_idle_timeout(unsigned long arg)
{
	struct idle_timer_info* ti = (struct idle_timer_info *)arg;

	set_bit(SEND_PING,&ti->mdev->flags);
	drbd_queue_signal(DRBD_SIG, ti->mdev->asender.task);
	if(ti->restart) {
		ti->idle_timeout.expires = jiffies + 
			ti->mdev->conf.ping_int * HZ;
		add_timer(&ti->idle_timeout);
	}
}

int drbd_recv(struct Drbd_Conf* mdev, void *ubuf, size_t size, int via_msock)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	struct idle_timer_info ti;
	int rv;
	struct socket *sock = via_msock ? mdev->msock : mdev->sock;
	
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = size;
	iov.iov_base = ubuf;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_flags = MSG_WAITALL | MSG_NOSIGNAL;

	lock_kernel();
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	if (mdev->conf.ping_int && !via_msock ) {
		init_timer(&ti.idle_timeout);
		ti.idle_timeout.function = drbd_idle_timeout;
		ti.idle_timeout.data = (unsigned long) &ti;
		ti.idle_timeout.expires =
		    jiffies + mdev->conf.ping_int * HZ;
		ti.mdev=mdev;
		ti.restart=1;
		add_timer(&ti.idle_timeout);
	}

	rv = sock_recvmsg(sock, &msg, size, msg.msg_flags);
	
	set_fs(oldfs);
	unlock_kernel();

	if (mdev->conf.ping_int && !via_msock) {
		ti.restart=0;
		del_timer_sync(&ti.idle_timeout);
		ti.idle_timeout.function=0;
	}

	/* ECONNRESET = other side closed the connection
	   ERESTARTSYS = we got a signal. */
	if (rv < 0 && rv != -ECONNRESET && rv != -ERESTARTSYS) {
		printk(KERN_ERR DEVICE_NAME "%d: sock_recvmsg returned %d\n",
		       (int)(mdev-drbd_conf),rv);
	}
	
	return rv;
}


STATIC struct socket *drbd_try_connect(struct Drbd_Conf* mdev)
{
	int err;
	struct socket *sock;

	err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
	if (err) {
		printk(KERN_ERR DEVICE_NAME "%d: sock_creat(..)=%d\n", 
		       (int)(mdev-drbd_conf), err);
	}

	lock_kernel();	
	err = sock->ops->connect(sock,
				 (struct sockaddr *) mdev->conf.other_addr,
				 mdev->conf.other_addr_len, 0);
	unlock_kernel();

	if (err) {
		sock_release(sock);
		sock = NULL;
	}
	return sock;
}

STATIC struct socket *drbd_wait_for_connect(struct Drbd_Conf* mdev)
{
	int err;
	struct socket *sock,*sock2;
	struct timer_list accept_timeout;

	err = sock_create(AF_INET, SOCK_STREAM, 0, &sock2);
	if (err) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: sock_creat(..)=%d\n",(int)(mdev-drbd_conf),err);
	}

	sock2->sk->reuse=1; /* SO_REUSEADDR */

	lock_kernel();
	err = sock2->ops->bind(sock2,
			      (struct sockaddr *) mdev->conf.my_addr,
			      mdev->conf.my_addr_len);
	unlock_kernel();
	if (err) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: Unable to bind (%d)\n",(int)(mdev-drbd_conf),err);
		sock_release(sock2);
		set_cstate(mdev,Unconnected);
		return 0;
	}
	
	if(mdev->conf.try_connect_int) {
		init_timer(&accept_timeout);
		accept_timeout.function = drbd_c_timeout;
		accept_timeout.data = (unsigned long) current;
		accept_timeout.expires = jiffies +
			mdev->conf.try_connect_int * HZ;
		add_timer(&accept_timeout);
	}			

	sock = drbd_accept(sock2);
	sock_release(sock2);
	
	if(mdev->conf.try_connect_int) {
		unsigned long flags;
		del_timer_sync(&accept_timeout);
		spin_lock_irqsave(&current->sigmask_lock,flags);
		if (sigismember(&current->pending.signal, DRBD_SIG)) {
			sigdelset(&current->pending.signal, DRBD_SIG);
			recalc_sigpending(current);
			spin_unlock_irqrestore(&current->sigmask_lock,
					       flags);
			if(sock) sock_release(sock);
			return 0;
		}
		spin_unlock_irqrestore(&current->sigmask_lock,flags);
	}
	
	return sock;
}

int drbd_connect(struct Drbd_Conf* mdev)
{
	struct socket *sock,*msock;


	if (mdev->cstate==Unconfigured) return 0;

	if (mdev->sock) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: There is already a socket!! \n",
		       (int)(mdev-drbd_conf));
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
				/* this break is necessary to give the other 
				   side time to call bind() & listen() */
				current->state = TASK_INTERRUPTIBLE;
				schedule_timeout(HZ / 10);
				msock=drbd_try_connect(mdev);
				if(msock) break;
				else sock_release(sock);
			}			
		}
		if(mdev->cstate==Unconnected) return 0;
		if(signal_pending(current)) return 0;
	}

	msock->sk->reuse=1; /* SO_REUSEADDR */
	sock->sk->reuse=1; /* SO_REUSEADDR */  

	/* to prevent oom deadlock... */
	/* The default allocation priority was GFP_KERNEL */
	sock->sk->allocation = GFP_DRBD;
	msock->sk->allocation = GFP_DRBD;

	sock->sk->priority=TC_PRIO_BULK;

	sock->sk->tp_pinfo.af_tcp.nonagle=0;

	// This boosts the performance of the syncer to 6M/s max
	sock->sk->sndbuf = 2*65535; 

	msock->sk->priority=TC_PRIO_INTERACTIVE;

	msock->sk->tp_pinfo.af_tcp.nonagle=1;

	msock->sk->sndbuf = 2*32767;

	mdev->sock = sock;
	mdev->msock = msock;

	drbd_thread_start(&mdev->asender);
	drbd_thread_start(&mdev->dsender);

	set_cstate(mdev,WFReportParams);
	drbd_send_param(mdev);

	return 1;
}

STATIC inline int receive_barrier(struct Drbd_Conf* mdev)
{
  	Drbd_Barrier_P header;
	int rv;
	int epoch_size;

	if(mdev->state != Secondary) /* CHK */
		printk(KERN_ERR DEVICE_NAME"%d: got barrier while not SEC!!\n",
		       (int)(mdev-drbd_conf));

	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;

	inc_unacked(mdev);

	/* printk(KERN_DEBUG DEVICE_NAME ": got Barrier\n"); */

	drbd_wait_ee(mdev,&mdev->active_ee,&mdev->done_ee);

	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_ee(mdev,&mdev->done_ee);

	epoch_size=mdev->epoch_size;
	mdev->epoch_size=0;
	spin_unlock_irq(&mdev->ee_lock);

	drbd_send_b_ack(mdev, header.barrier, epoch_size );

	dec_unacked(mdev);

	return rv;
}

STATIC void ensure_blocksize(struct Drbd_Conf* mdev,int data_size)
{
	if (data_size != (1 << mdev->blk_size_b)) {
		if(mdev->state == Primary) {
			printk(KERN_ERR DEVICE_NAME 
			       "%d: Bklsize change on Primary!\n",
			       (int)(mdev-drbd_conf));
		}

		set_bit(BLKSIZE_CHANGING,&mdev->flags);
		// dsender does not get any ee from now on :)
		drbd_wait_ee(mdev,&mdev->active_ee,&mdev->done_ee);
		drbd_wait_ee(mdev,&mdev->sync_ee,&mdev->done_ee);
		drbd_process_ee(mdev,&mdev->done_ee);

		// Wait until dsender has given all ees back.
		while( mdev->ee_in_use ) {
			interruptible_sleep_on(&mdev->ee_wait);
		}

		mdev->blk_size_b = drbd_log2(data_size);
		printk(KERN_INFO DEVICE_NAME "%d: blksize=%d B\n",
		       (int)(mdev-drbd_conf),
		       data_size);
		drbd_ee_fix_bhs(mdev);
		clear_bit(BLKSIZE_CHANGING,&mdev->flags);
	}
}

STATIC inline struct Tl_epoch_entry *
read_in_block(struct Drbd_Conf* mdev,int data_size)
{
	struct Tl_epoch_entry *e;
        struct buffer_head *bh;
	int rr;

        spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev,TRUE);
        spin_unlock_irq(&mdev->ee_lock);
	bh=e->bh;

        rr=drbd_recv(mdev,bh_kmap(bh),data_size,0);
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
        set_bit(BH_Lock, &bh->b_state); // since using submit_bh()
	bh->b_end_io = drbd_dio_end_sec;
	mdev->recv_cnt+=data_size>>10;
	
	return e;
}

STATIC inline void receive_data_tail(struct Drbd_Conf* mdev,int data_size)
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

	mdev->writ_cnt+=data_size>>10;
	
}

int recv_dless_read(struct Drbd_Conf* mdev, struct Pending_read *pr, 
		    unsigned long block_nr, int data_size)
{
	struct buffer_head *bh;
	int ok,rr;

	spin_lock(&mdev->pr_lock); 
	bh = pr->d.bh;
	pr->d.bh = 0; 
	spin_unlock(&mdev->pr_lock); 

        if(block_nr != bh->b_blocknr) {
                printk(KERN_ERR DEVICE_NAME "%d: blocknr inconsitent!\n",
                       (int)(mdev-drbd_conf));
        }

	rr=drbd_recv(mdev,bh_kmap(bh),data_size,0);
	bh_kunmap(bh);

	ok=(rr==data_size);
	bh->b_end_io(bh,ok);

	dec_pending(mdev);
	return ok;
}

STATIC int e_end_resync_block(struct Drbd_Conf* mdev, struct Tl_epoch_entry *e)
{
	drbd_set_in_sync(mdev,e->bh->b_blocknr,drbd_log2(e->bh->b_size));
	drbd_send_ack(mdev,WriteAck,e->bh->b_blocknr,ID_SYNCER);
	dec_unacked(mdev);

	return TRUE;
}

int recv_resync_read(struct Drbd_Conf* mdev, struct Pending_read *pr, 
		     unsigned long block_nr, int data_size)
{
	struct Tl_epoch_entry *e;

	e = read_in_block(mdev,data_size);
	if(!e) return FALSE;
	drbd_set_bh(e->bh,block_nr,mdev->lo_device);
        e->block_id = ID_SYNCER;
	e->e_end_io = e_end_resync_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->ee_lock);

	submit_bh(WRITE,e->bh);

	dec_pending(mdev);
	inc_unacked(mdev);

	receive_data_tail(mdev,data_size);
	return TRUE;
	
}


int recv_both_read(struct Drbd_Conf* mdev, struct Pending_read *pr, 
		   unsigned long block_nr, int data_size)
{
	struct Tl_epoch_entry *e;
	struct buffer_head *bh;

	e = read_in_block(mdev,data_size);

	spin_lock(&mdev->pr_lock); 
	bh = pr->d.bh;
	pr->d.bh = 0; 
	spin_unlock(&mdev->pr_lock); 

	if(!e) {
		return FALSE;
		bh->b_end_io(bh,0);
	}

        if(block_nr != bh->b_blocknr) {
                printk(KERN_ERR DEVICE_NAME "%d: blocknr inconsitent!\n",
                       (int)(mdev-drbd_conf));
        }

	memcpy(bh_kmap(bh),bh_kmap(e->bh),data_size);
	bh_kunmap(bh);
	bh_kunmap(e->bh);

	bh->b_end_io(bh,1);

	drbd_set_bh(e->bh,block_nr,mdev->lo_device);
        e->block_id = ID_SYNCER;
	e->e_end_io = e_end_resync_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->list,&mdev->sync_ee);
	spin_unlock_irq(&mdev->ee_lock);

	submit_bh(WRITE,e->bh);

	dec_pending(mdev);
	inc_unacked(mdev);

	receive_data_tail(mdev,data_size);
	return TRUE;
	
}

int recv_discard(struct Drbd_Conf* mdev, struct Pending_read *pr, 
		 unsigned long block_nr, int data_size)
{
	struct Tl_epoch_entry *e;

	e = read_in_block(mdev,data_size);
	if(!e)	return FALSE;
	
	drbd_send_ack(mdev,WriteAck,block_nr,ID_SYNCER);

	spin_lock_irq(&mdev->ee_lock);
	drbd_put_ee(mdev,e);
	spin_unlock_irq(&mdev->ee_lock);

	return TRUE;
}

STATIC int receive_data_reply(struct Drbd_Conf* mdev,int data_size)
{
	struct Pending_read *pr;
	unsigned long block_nr;
	Drbd_Data_P header;
	int ok;

	int (*funcs[])(struct Drbd_Conf* , struct Pending_read*,
		      unsigned long,int) = {
			      [Discard]      = recv_discard,
			      [Application]  = recv_dless_read,
			      [Resync]       = recv_resync_read,
			      [AppAndResync] = recv_both_read
		      };
	
	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;
 
	ensure_blocksize(mdev,data_size);
      
	block_nr = be64_to_cpu(header.block_nr);

	pr = (struct Pending_read *)(long)header.block_id;

	ok = funcs[pr->cause](mdev,pr,block_nr,data_size);

	spin_lock(&mdev->pr_lock); 
	list_del(&pr->list);
	spin_unlock(&mdev->pr_lock);

	kfree(pr);

	if(ok) mdev->recv_cnt+=data_size>>10;	
	return ok;
}

STATIC int e_end_block(struct Drbd_Conf* mdev, struct Tl_epoch_entry *e)
{
	int ok=TRUE;

	mdev->epoch_size++;
	if(mdev->conf.wire_protocol == DRBD_PROT_C) {
		ok=drbd_send_ack(mdev,WriteAck,e->bh->b_blocknr,e->block_id);
		dec_unacked(mdev);
	}

	return ok;
}

STATIC int receive_data(struct Drbd_Conf* mdev,int data_size)
{
	unsigned long block_nr;
	struct Tl_epoch_entry *e;
	Drbd_Data_P header;

	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;
       
	ensure_blocksize(mdev,data_size);

	block_nr = be64_to_cpu(header.block_nr);	

	e = read_in_block(mdev,data_size);
	if(!e) return FALSE;
	drbd_set_bh(e->bh,block_nr,mdev->lo_device);
        e->block_id=header.block_id;
	e->e_end_io = e_end_block;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&e->list,&mdev->active_ee);
	spin_unlock_irq(&mdev->ee_lock);

	submit_bh(WRITE,e->bh);

	switch(mdev->conf.wire_protocol) {
	case DRBD_PROT_C:
		inc_unacked(mdev);
		break;
	case DRBD_PROT_B:
		drbd_send_ack(mdev, RecvAck, block_nr,header.block_id);
		break;
	case DRBD_PROT_A:
		// nothing to do
		break;
	}

	receive_data_tail(mdev,data_size);
	return TRUE;
}

STATIC int e_end_data_req(struct Drbd_Conf* mdev, struct Tl_epoch_entry *e)
{
	int ok;

	ok=drbd_send_block(mdev, DataReply ,e->bh, e->block_id);
	dec_unacked(mdev);

	return ok;
}

STATIC int e_end_rsdata_req(struct Drbd_Conf* mdev, struct Tl_epoch_entry *e)
{
	int ok;

	ok=drbd_send_block(mdev, DataReply ,e->bh, e->block_id);
	dec_unacked(mdev);
	inc_pending(mdev);

	return ok;
}

STATIC inline int receive_drequest(struct Drbd_Conf* mdev,int command)
{
	Drbd_BlockRequest_P header;
	unsigned long block_nr;
	struct Tl_epoch_entry *e;
        struct buffer_head *bh;
	int data_size;

	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;

	data_size = be32_to_cpu(header.blksize);

	ensure_blocksize(mdev,data_size);

	if (be32_to_cpu(header.blksize) != (1 << mdev->blk_size_b)) {
		printk(KERN_ERR DEVICE_NAME "%d: DR he=%d me=%d\n",
		       (int)(mdev-drbd_conf),
		       be32_to_cpu(header.blksize),
		       (1 << mdev->blk_size_b));
		return FALSE;
	}

	block_nr = be64_to_cpu(header.block_nr);

	spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev,TRUE);
	drbd_set_bh(e->bh,block_nr,mdev->lo_device);
	e->block_id=header.block_id;
	list_add(&e->list,&mdev->read_ee);
	spin_unlock_irq(&mdev->ee_lock);

	switch(command) {
	case DataRequest:     e->e_end_io = e_end_data_req; break;
	case RSDataRequest:   e->e_end_io = e_end_rsdata_req; break;
	}

	bh=e->bh;
	clear_bit(BH_Uptodate, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state);
	e->bh->b_end_io = drbd_dio_end_read;	

	spin_lock_irq(&mdev->bb_lock);
	// TODO: Rethink mdev->blk_size_b
	if(tl_check_sector(mdev,block_nr << (mdev->blk_size_b))) {
		struct busy_block bl;
		bb_wait_prepare(mdev,block_nr,&bl);
		spin_unlock_irq(&mdev->bb_lock);
		bb_wait(&bl);
	} else spin_unlock_irq(&mdev->bb_lock);

	mdev->read_cnt+=(1<<(mdev->blk_size_b-10)); //reconsider blk_size_b
	submit_bh(READ,e->bh);
	inc_unacked(mdev);
	
	return TRUE;
}

STATIC inline int receive_param(struct Drbd_Conf* mdev)
{
        Drbd_Parameter_P param;
	int blksize;
	int minor=(int)(mdev-drbd_conf);
	int no_sync=0;
	int oo_state;
	unsigned long p_size;

	/*printk(KERN_DEBUG DEVICE_NAME
	  ": recv ReportParams/m=%d\n",(int)(mdev-drbd_conf));*/

	if (drbd_recv(mdev, &param, sizeof(param),0) != sizeof(param))
	        return FALSE;

	if(be32_to_cpu(param.state) == Primary && mdev->state == Primary ) {
		printk(KERN_ERR DEVICE_NAME"%d: incompatible states \n",minor);
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(param.version)!=PRO_VERSION) {
	        printk(KERN_ERR DEVICE_NAME"%d: incompatible releases \n",
		       minor);
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(param.protocol)!=mdev->conf.wire_protocol) {
	        printk(KERN_ERR DEVICE_NAME"%d: incompatible protocols \n",
		       minor);
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}

	/* should be removed ?
	if(be64_to_cpu(param.protocol)!=mdev->lo_usize) {
	        printk(KERN_ERR DEVICE_NAME"%d: Size hints inconsistent \n",
		       minor);
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;
	}
	*/

	p_size=be64_to_cpu(param.p_size);
	mdev->p_size=p_size;
	mdev->p_usize=be64_to_cpu(param.u_size);
	if(p_size) clear_bit(PARTNER_DISKLESS, &mdev->flags);
	else set_bit(PARTNER_DISKLESS, &mdev->flags);

	no_sync=drbd_determin_dev_size(mdev);

	if( blk_size[MAJOR_NR][minor] == 0) {
		set_cstate(mdev,StandAlone);
		mdev->receiver.t_state = Exiting;
		return FALSE;		
	}

	if(mdev->state == Primary)
		blksize = (1 << mdev->blk_size_b);
	else if(be32_to_cpu(param.state) == Primary)
		blksize = be32_to_cpu(param.blksize);
	else 
		blksize = max_t(int,be32_to_cpu(param.blksize),
				(1 << mdev->blk_size_b));

	if( mdev->blk_size_b != drbd_log2(blksize)) {
		set_blocksize(MKDEV(MAJOR_NR, minor),blksize);
		set_blocksize(mdev->lo_device,blksize);
		mdev->blk_size_b = drbd_log2(blksize);
		drbd_ee_fix_bhs(mdev);
	}

	if (!mdev->mbds_id) {
		mdev->mbds_id = bm_init(MKDEV(MAJOR_NR, minor));
	}
	
	if (mdev->cstate == WFReportParams) {
		int have_good,quick,sync;
		printk(KERN_INFO DEVICE_NAME "%d: Connection established. "
		       "blksize=%d B\n",minor,blksize);

		have_good=drbd_md_compare(minor,&param);

		if(have_good==0) sync=0;
		else sync=1;

		quick=drbd_md_syncq_ok(minor,&param,have_good==1);

		printk(KERN_INFO DEVICE_NAME 
		       "%d: have_good=%d sync=%d quick=%d\n",
		       minor,have_good,sync,quick);

		if( sync && !mdev->sync_conf.skip && !no_sync) {
			if(have_good == 1) {
				if(quick) {
					drbd_send_bitmap(mdev);
				} else {
					mdev->rs_total=
						blk_size[MAJOR_NR][minor] & 
						~((1<<(mdev->blk_size_b-10))-1);					
				}
				drbd_start_resync(mdev,SyncSource);
			} else { // have_good == -1
				mdev->gen_cnt[Flags] &= ~MDF_Consistent;
				if(!quick) {
					bm_fill_bm(mdev->mbds_id,-1);
					mdev->rs_total=
						blk_size[MAJOR_NR][minor] & 
						~((1<<(mdev->blk_size_b-10))-1);
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
				mdev->gen_cnt[i]=be32_to_cpu(param.gen_cnt[i]);
			}
		}
		drbd_md_write(mdev); // Need to update connected indicator.
	}

	oo_state = mdev->o_state;
	mdev->o_state = be32_to_cpu(param.state);
	if(oo_state == Secondary && mdev->o_state == Primary) {
		drbd_md_inc(minor,ConnectedCnt);
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

#define TWO(c) (0x1u << (c))
#define MASK(c) (((unsigned int)(-1)) / (TWO(TWO(c)) + 1u))
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

STATIC inline int receive_bitmap(struct Drbd_Conf* mdev)
{
	size_t bm_words;
	u32 *buffer,*bm,word;
	int ret,buf_i,want,bm_i=0;
	unsigned long bits=0;
	Drbd_Packet header;

	bm_words=mdev->mbds_id->size/sizeof(u32);
	bm=(u32*)mdev->mbds_id->bm;
	buffer=vmalloc(MBDS_PACKET_SIZE);

	want=min_t(int,MBDS_PACKET_SIZE,(bm_words-bm_i)*sizeof(long));
	goto start;

	while(1) {
		want=min_t(int,MBDS_PACKET_SIZE,(bm_words-bm_i)*sizeof(long));
		if(want==0) break;

		if (drbd_recv(mdev,&header,sizeof(Drbd_Packet),0) !=
		    sizeof(Drbd_Packet)) {
			ret=FALSE;
			goto out;
		}		
	start:
		if (drbd_recv(mdev, buffer, want,0) != want) {
			ret=FALSE;
			goto out;
		}

		for(buf_i=0;buf_i<want/sizeof(long);buf_i++) {
			word = be32_to_cpu(buffer[buf_i]);
			bits += parallel_bitcount(word);
			bm[bm_i++] = word;
		}
	}
	
	mdev->rs_total = bits << (BM_BLOCK_SIZE_B - 10); // in Kilobyte!
	drbd_start_resync(mdev,SyncTarget);
	ret=TRUE;
 out:
	vfree(buffer);
	return ret;
}

STATIC inline int receive_in_sync(struct Drbd_Conf* mdev)
{     
	Drbd_Data_P header;
	struct Pending_read *pr;
	
	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
		return FALSE;

	pr = (struct Pending_read *)(long)header.block_id;
	spin_lock(&mdev->pr_lock);
	list_del(&pr->list);
	spin_unlock(&mdev->pr_lock);
	kfree(pr);

	dec_pending(mdev);
	
	drbd_set_in_sync(mdev,be64_to_cpu(header.block_nr),mdev->blk_size_b);

	return TRUE;
}


STATIC inline void drbd_collect_zombies(int minor)
{
	if(test_and_clear_bit(COLLECT_ZOMBIES,&drbd_conf[minor].flags)) {
		while( waitpid(-1, NULL, __WCLONE|WNOHANG) > 0 );
	}
}

STATIC void drbd_fail_pending_reads(struct Drbd_Conf* mdev)
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
		dec_pending(mdev);

		kfree(pr);
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
		kfree(pr);
	}
}

STATIC void drbdd(int minor)
{
	Drbd_Packet header;
	struct Drbd_Conf* mdev;
	int i,length,cmd,rr;

	mdev=drbd_conf+minor;

	while (TRUE) {
		drbd_collect_zombies(minor); // in case a syncer exited.

		rr = drbd_recv(mdev,&header,sizeof(Drbd_Packet),0);
		if( rr != sizeof(Drbd_Packet)) break;
		
		length = (int) be16_to_cpu(header.length);
		cmd = (int) be16_to_cpu(header.command);

		if (be32_to_cpu(header.magic) != DRBD_MAGIC) {
			printk(KERN_ERR DEVICE_NAME "%d: magic?? m: %ld "
			       "c: %d "
			       "l: %d \n",
			       minor,
			       (long) be32_to_cpu(header.magic),cmd,length);

			break;
		}
		switch (cmd) {
		case Barrier:
       		        if (!receive_barrier(mdev)) goto err;
			break;

		case Data:    // mirrored write
		        if (!receive_data(mdev,length)) goto err;
			break;

		case DataReply: // response to a read request
		        if (!receive_data_reply(mdev,length)) goto err;
			break;
			
		case ReportParams:
		        if (!receive_param(mdev)) goto err;
			break;

		case ReportBitMap:
			if (!receive_bitmap(mdev)) goto err;
			break;

		case BecomeSyncSource:
			mdev->rs_total=blk_size[MAJOR_NR][minor]&
				~((1<<(mdev->blk_size_b-10))-1);
			drbd_start_resync(mdev,SyncSource);
			break;

		case BecomeSyncTarget:
			bm_fill_bm(mdev->mbds_id,-1);
			mdev->rs_total=blk_size[MAJOR_NR][minor]&
				~((1<<(mdev->blk_size_b-10))-1);
			drbd_start_resync(mdev,SyncTarget);
			break;

		case BecomeSec:
			drbd_set_state(minor,Secondary);
			break;

		case WriteHint:
			run_task_queue(&tq_disk);
			break;

		case DataRequest:
		case RSDataRequest:
			if(!receive_drequest(mdev,
					     be16_to_cpu(header.command))) 
				goto err;
			break;
		case BlockInSync:
			if(!receive_in_sync(mdev))
				goto err;
			break;

		default:
			printk(KERN_ERR DEVICE_NAME
			       "%d: unknown packet type %d!\n", minor,
			       be16_to_cpu(header.command));
			goto out;
		}
	}

	if(0) {
	err:
		printk(KERN_ERR DEVICE_NAME
		       "%d: receiving cmd=%d failed\n", minor, cmd);
	}

      out:

	del_timer_sync(&mdev->a_timeout);

	drbd_thread_stop(&mdev->asender);

	while(down_trylock(&mdev->sock_mutex))
	{
		struct send_timer_info *ti;
		spin_lock(&mdev->send_proc_lock);
		if((ti=mdev->send_proc)) {
			ti->timeout_happened=1;
			drbd_queue_signal(DRBD_SIG, ti->task);
			spin_unlock(&mdev->send_proc_lock);
			down(&mdev->sock_mutex);
			break;
		} else {
			spin_unlock(&mdev->send_proc_lock);
			schedule_timeout(HZ / 10);
		}
	}
	/* By grabbing the sock_mutex we make shure that no one 
	   uses the socket right now. */
	drbd_free_sock(minor);
	up(&mdev->sock_mutex);

	drbd_thread_stop(&mdev->dsender);
	drbd_collect_zombies(minor);

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
			drbd_md_inc(minor,ConnectedCnt);
		drbd_md_write(mdev);
		break;
	case Secondary: 
		drbd_wait_ee(mdev,&mdev->active_ee, &mdev->done_ee);
		drbd_wait_ee(mdev,&mdev->sync_ee, &mdev->done_ee);
		drbd_clear_done_ee(mdev);
		mdev->epoch_size=0;
		break;
	default:
		/* should not happen */
	}

	if(atomic_read(&mdev->unacked_cnt)) {
		printk(KERN_ERR DEVICE_NAME "%d: unacked_cnt!=0\n",minor);
		atomic_set(&mdev->unacked_cnt,0);
	}		

	/* Since syncer's blocks are also counted, there is no hope that
	   pending_cnt is zero. */
	atomic_set(&mdev->pending_cnt,0); 
	wake_up_interruptible(&mdev->state_wait);

	clear_bit(DO_NOT_INC_CONCNT,&mdev->flags);

	printk(KERN_INFO DEVICE_NAME "%d: Connection lost.\n",minor);
}

int drbdd_init(struct Drbd_thread *thi)
{
	int minor = thi->minor;

	sprintf(current->comm, "drbd_receiver_%d", minor);
	
	/* printk(KERN_INFO DEVICE_NAME ": receiver living/m=%d\n", minor); */
	
	while (TRUE) {
		if (!drbd_connect(drbd_conf+minor)) break;
		if (thi->t_state == Exiting) break;
		drbdd(minor);
		if (thi->t_state == Exiting) break;
		if (thi->t_state == Restarting) {
			unsigned long flags;
			thi->t_state = Running;

			spin_lock_irqsave(&current->sigmask_lock,flags);
			if (sigismember(&current->pending.signal, SIGTERM)) {
				sigdelset(&current->pending.signal, SIGTERM);
				recalc_sigpending(current);
			}
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
		}
	}

	printk(KERN_DEBUG DEVICE_NAME "%d: receiver exiting\n", minor);

	/* set_cstate(drbd_conf+minor,StandAlone); */

	return 0;
}

/* ********* acknowledge sender ******** */

STATIC void got_block_ack(struct Drbd_Conf* mdev,Drbd_BlockAck_Packet* pkt)
{     
        drbd_request_t *req;
	
	// TODO: Make sure that the block is in an active epoch!!
	if(mdev->conf.wire_protocol != DRBD_PROT_A ||
	   is_syncer_blk(mdev,pkt->h.block_id)) {
		dec_pending(mdev);
	}

	if( is_syncer_blk(mdev,pkt->h.block_id)) {
		drbd_set_in_sync(mdev,
				 be64_to_cpu(pkt->h.block_nr),
				 mdev->blk_size_b);
	} else {
		req=(drbd_request_t*)(long)pkt->h.block_id;
		drbd_end_req(req, RQ_DRBD_SENT, 1);
	}
}

inline void got_barrier_ack(struct Drbd_Conf* mdev,Drbd_BarrierAck_Packet* pkt)
{
	if(mdev->state != Primary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got barrier-ack while not"
		       " PRI!!\n",(int)(mdev-drbd_conf));

        tl_release(mdev,pkt->h.barrier,be32_to_cpu(pkt->h.set_size));

	dec_pending(mdev);

}


inline int drbd_try_send_barrier(struct Drbd_Conf *mdev)
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

void drbd_ping_timeout(unsigned long arg)
{
	struct Drbd_Conf* mdev = (struct Drbd_Conf*)arg;

	printk(KERN_DEBUG DEVICE_NAME"%d: ping ack did not arrive\n",
	       (int)(mdev-drbd_conf));

	drbd_thread_restart_nowait(&mdev->receiver);
}


int drbd_asender(struct Drbd_thread *thi)
{
	Drbd_BlockAck_Packet pkt;
	struct Drbd_Conf *mdev=drbd_conf+thi->minor;
	struct timer_list ping_timeout;
	unsigned long ping_sent_at,flags;
	int rtt=0,rr,rsize=0,expect;

	expect=sizeof(Drbd_Packet);

	sprintf(current->comm, "drbd_asender_%d", (int)(mdev-drbd_conf));

	current->policy = SCHED_RR;  /* Make this a realtime task! */
	current->rt_priority = 2;    /* more important than all other tasks */

	init_timer(&ping_timeout);
	ping_timeout.function = drbd_ping_timeout;
	ping_timeout.data = (unsigned long) mdev;

	ping_sent_at=0;

	while(thi->t_state == Running) {
		rr=drbd_recv(mdev,((char*)&pkt)+rsize,expect-rsize,1);
		if(rr == -ERESTARTSYS) {
			spin_lock_irqsave(&current->sigmask_lock,flags);
			sigemptyset(&current->pending.signal);
			recalc_sigpending(current);
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
			rr=0;
		} else if(rr <= 0) break;

		rsize+=rr;		
			
		if(rsize == expect) {
			if (be32_to_cpu(pkt.p.magic) != DRBD_MAGIC) {
				printk(KERN_ERR DEVICE_NAME "%d: magic?? "
				       "m: %ld c: %d l: %d \n",
				       (int)(mdev-drbd_conf),
				       (long) be32_to_cpu(pkt.p.magic),
				       (int) be16_to_cpu(pkt.p.command),
				       (int) be16_to_cpu(pkt.p.length));
				goto err;
			}
			switch (be16_to_cpu(pkt.p.command)) {
			case Ping:
        			if(!drbd_send_cmd(mdev,PingAck,1)) goto err;
				break;
			case PingAck:
				del_timer(&ping_timeout);
				
				rtt = jiffies-ping_sent_at;
				ping_sent_at=0;
				break;
			case RecvAck:
			case WriteAck:
				if(expect != sizeof(Drbd_BlockAck_Packet)) {
					expect=sizeof(Drbd_BlockAck_Packet);
					goto get_more;
				}
				got_block_ack(mdev,&pkt);
				expect = sizeof(Drbd_Packet);
				break;

			case BarrierAck:
				if(expect != sizeof(Drbd_BarrierAck_Packet)) {
					expect=sizeof(Drbd_BarrierAck_Packet);
					goto get_more;
				}
				got_barrier_ack(mdev,(Drbd_BarrierAck_Packet *)
						&pkt);
				expect = sizeof(Drbd_Packet);
				break;
			}
			rsize=0;
		get_more:
		}
	  
		if(ping_sent_at==0) {
			if(test_and_clear_bit(SEND_PING,&mdev->flags)) {
				if(!drbd_send_cmd(mdev,Ping,1)) goto err;
				ping_timeout.expires = 
					jiffies + mdev->conf.timeout*HZ/20;
				add_timer(&ping_timeout);
				ping_sent_at=jiffies;
				if(ping_sent_at==0) ping_sent_at=1;
			}
		}

		if( mdev->state == Primary ) {
			if(!drbd_try_send_barrier(mdev)) goto err;
		} else { //Secondary
			if(!drbd_process_ee(mdev,&mdev->done_ee)) goto err;
		}
	} //while

	if(0) {
	err:
		drbd_thread_restart_nowait(&mdev->receiver);
	}

	del_timer_sync(&ping_timeout);

	/* printk(KERN_ERR DEVICE_NAME"%d: asender terminated\n",
	   (int)(mdev-drbd_conf)); */

	return 0;
}

