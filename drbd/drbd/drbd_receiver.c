/*
-*- linux-c -*-
   drbd_receiver.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

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
#include "drbd.h"
#include "drbd_int.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define mark_buffer_dirty(A)   mark_buffer_dirty(A , 1)
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,0)
#define BH_PRIVATE(A) ((A)->b_private)
#else
#define BH_PRIVATE(A) ((A)->b_dev_id)
#endif


#define EE_MININUM 32    // @4k pages => 128 KByte
#define EE_MAXIMUM 2048  // @4k pages => 8   MByte
/*static */int _drbd_process_done_ee(struct Drbd_Conf* mdev);

/*static */inline void inc_unacked(struct Drbd_Conf* mdev)
{
	atomic_inc(&mdev->unacked_cnt);
}

/*static */inline void dec_unacked(struct Drbd_Conf* mdev)
{
	if(atomic_dec_and_test(&mdev->unacked_cnt))
		wake_up_interruptible(&mdev->state_wait);

	if(atomic_read(&mdev->unacked_cnt)<0)  /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: unacked_cnt <0 !!!\n",
		       (int)(mdev-drbd_conf));
}

#define is_syncer_blk(A,B) ((B)==ID_SYNCER)

#if 0
/*static */inline int is_syncer_blk(struct Drbd_Conf* mdev, u64 block_id) 
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

/*static */inline struct Drbd_Conf* drbd_lldev_to_mdev(kdev_t dev)
{
	int i;

	for (i=0; i<minor_count; i++) {
		if(drbd_conf[i].lo_device == dev) {
			return drbd_conf+i;
		}
	}
	printk(KERN_ERR DEVICE_NAME "X: lodev_to_mdev !!\n");
	return drbd_conf;
}

/*static */void drbd_dio_end_sec(struct buffer_head *bh, int uptodate)
{
	/* This callback will be called in irq context by the IDE drivers,
	   and in Softirqs/Tasklets/BH context by the SCSI drivers.
	   Try to get the locking right :) */
	int wake_asender=0;
	unsigned long flags=0;
	struct Tl_epoch_entry *e=NULL;
	struct Drbd_Conf* mdev;

	mdev=drbd_lldev_to_mdev(bh->b_rdev);

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

	e=BH_PRIVATE(bh);
	spin_lock_irqsave(&mdev->ee_lock,flags);

	mark_buffer_uptodate(bh, uptodate);

	clear_bit(BH_Dirty, &bh->b_state);
	clear_bit(BH_Lock, &bh->b_state);

	/* Do not move a BH if someone is in wait_on_buffer */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,3,0)
	if(bh->b_count == 0)
#else
	if(atomic_read(&bh->b_count) == 0)
#endif
	{
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
 _drbd_alloc_ee()
 drbd_alloc_ee()
 drbd_free_ee()
 drbd_get_ee()
 drbd_put_ee()
 _drbd_process_done_ee()

You must not have the ee_lock:
 drbd_init_ee()
 drbd_release_ee()
 drbd_ee_fix_bhs()
 drbd_process_done_ee()
 drbd_clear_done_ee()
 _drbd_wait_ee()
 drbd_wait_active_ee()
 drbd_wait_sync_ee()
*/

/*static */void _drbd_alloc_ee(struct Drbd_Conf* mdev,page_t* page)
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
		
		bh=(struct buffer_head*)(((char*)e)+
					 sizeof(struct Tl_epoch_entry));

		/*printk(KERN_ERR DEVICE_NAME "%d: kmalloc()=%p\n",
		  (int)(mdev-drbd_conf),e);*/

		drbd_init_bh(bh, buffer_size, drbd_dio_end_sec);
		set_bh_page(bh,page,i*buffer_size); // sets b_data and b_page

		e->bh=bh;
		BH_PRIVATE(bh)=e;

		e->block_id=0; //all entries on the free_ee should have 0 here
		list_add(&e->list,&mdev->free_ee);
		mdev->ee_vacant++;
		if (lbh) {
			lbh->b_this_page = bh;
		} else {
			fbh = bh;
		}
		lbh=bh;
	}
	bh->b_this_page=fbh;
}

/*static */int drbd_alloc_ee(struct Drbd_Conf* mdev,int mask)
{
	page_t *page;

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

/*static */page_t* drbd_free_ee(struct Drbd_Conf* mdev, struct list_head *list)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;
	struct buffer_head *bh,*nbh;
	int freeable=0;
	page_t* page;

	list_for_each(le,list) {
		bh=list_entry(le, struct Tl_epoch_entry,list)->bh;
		nbh=bh->b_this_page;
		freeable=1;
		while( nbh != bh ) {
			e=BH_PRIVATE(nbh);
			if(e->block_id) freeable=0;
			nbh=nbh->b_this_page;
		}
		if(freeable) goto free_it;
	}
	return 0;
 free_it:
	nbh=bh;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
	page=(page_t*)bh->b_data;
#else
	page=bh->b_page;
#endif
	do {
		e=BH_PRIVATE(nbh);
		list_del(&e->list);
		mdev->ee_vacant--;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
		if((page_t*)nbh->b_data<page) 
			page=(page_t*)nbh->b_data;
#endif
		nbh=nbh->b_this_page;
		/*printk(KERN_ERR DEVICE_NAME "%d: kfree(%p)\n",
		  (int)(mdev-drbd_conf),e);*/
		kfree(e);
	} while(nbh != bh);

	return page;
}

void drbd_init_ee(struct Drbd_Conf* mdev)
{
	spin_lock_irq(&mdev->ee_lock);
	while(mdev->ee_vacant < EE_MININUM ) {
		drbd_alloc_ee(mdev,GFP_USER);
	}
	spin_unlock_irq(&mdev->ee_lock);
}

int drbd_release_ee(struct Drbd_Conf* mdev,struct list_head* list)
{
	int count=0;

	spin_lock_irq(&mdev->ee_lock);
	while(!list_empty(list)) {
		drbd_free_page(drbd_free_ee(mdev,list));
		count++;
	}
	spin_unlock_irq(&mdev->ee_lock);

	return count;
}

/*static */void drbd_ee_fix_bhs(struct Drbd_Conf* mdev)
{
	struct list_head workset;
	page_t* page;

	spin_lock_irq(&mdev->ee_lock);
	list_add(&workset,&mdev->free_ee); // insert the new head
	list_del(&mdev->free_ee);          // remove the old head
	INIT_LIST_HEAD(&mdev->free_ee); 
	// now all elements are in the "workset" list, free_ee is empty!

	while(!list_empty(&workset)) {
		page=drbd_free_ee(mdev,&workset);
		if(page) _drbd_alloc_ee(mdev,page);
	}
	spin_unlock_irq(&mdev->ee_lock);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define GFP_TRY ( __GFP_LOW     )
#else
#define GFP_TRY	( __GFP_HIGHMEM )
#endif

/*static */struct Tl_epoch_entry* drbd_get_ee(struct Drbd_Conf* mdev,
					  unsigned long block)
{
	struct list_head *le;
	struct Tl_epoch_entry* e;

	if(mdev->ee_vacant == EE_MININUM / 2) run_task_queue(&tq_disk);

	while(list_empty(&mdev->free_ee)) {
		_drbd_process_done_ee(mdev);
		if(!list_empty(&mdev->free_ee)) break;
		if((mdev->ee_vacant+mdev->ee_in_use) < EE_MAXIMUM) {
			if(drbd_alloc_ee(mdev,GFP_TRY)) break;
		}
		spin_unlock_irq(&mdev->ee_lock);
		run_task_queue(&tq_disk);
		interruptible_sleep_on(&mdev->ee_wait);
		spin_lock_irq(&mdev->ee_lock);
	}
	le=mdev->free_ee.next;
	list_del(le);
	e->block_id=1;//the entries not on free_ee should not have 0 here.
	mdev->ee_vacant--;
	mdev->ee_in_use++;
	e=list_entry(le, struct Tl_epoch_entry,list);
	drbd_set_bh(e->bh,block,mdev->lo_device);
	return e;
}

/*static */void drbd_put_ee(struct Drbd_Conf* mdev,struct Tl_epoch_entry *e)
{
	page_t* page;

	mdev->ee_in_use--;
	mdev->ee_vacant++;
	e->block_id=0;//all entries on the free_ee should have 0 here
	list_add(&e->list,&mdev->free_ee);

	if(mdev->ee_vacant * 2 > mdev->ee_in_use) {
		page=drbd_free_ee(mdev,&mdev->free_ee);
		if( page ) drbd_free_page(page);
	}
	if(mdev->ee_in_use == 0) {
		while( mdev->ee_vacant > EE_MININUM ) {
			drbd_free_page(drbd_free_ee(mdev,&mdev->free_ee));
		}
	}
}

/*static */int _drbd_process_done_ee(struct Drbd_Conf* mdev)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int r=sizeof(Drbd_BlockAck_Packet); // for protocol A/B case.

	while(!list_empty(&mdev->done_ee)) {
		le = mdev->done_ee.next;
		list_del(le);
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(!is_syncer_blk(mdev,e->block_id)) mdev->epoch_size++;
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   is_syncer_blk(mdev,e->block_id) ) {
			spin_unlock_irq(&mdev->ee_lock);
			r=drbd_send_ack(mdev, WriteAck,e->bh->b_blocknr,
					e->block_id);
			dec_unacked(mdev);
			spin_lock_irq(&mdev->ee_lock);
		}
		drbd_put_ee(mdev,e);
		if(r != sizeof(Drbd_BlockAck_Packet )) return FALSE;
	}

	wake_up_interruptible(&mdev->ee_wait);

	return TRUE;
}

/*static */inline int drbd_process_done_ee(struct Drbd_Conf* mdev)
{
	int rv;
	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_done_ee(mdev);
	spin_unlock_irq(&mdev->ee_lock);
	return rv;
}

/*static */inline void drbd_clear_done_ee(struct Drbd_Conf *mdev)
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


/*static */void _drbd_wait_ee(struct Drbd_Conf* mdev,struct list_head *head)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;

	spin_lock_irq(&mdev->ee_lock);
	while(!list_empty(head)) {
		le = head->next;
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(!buffer_locked(e->bh)) {
			printk(KERN_ERR DEVICE_NAME 
			       "%d: unlocked bh in ative_ee/sync_ee\n"
			       "(BUG?) Moving bh=%p to done_ee\n",
			       (int)(mdev-drbd_conf),e->bh);
			list_del(le);
			list_add(le,&mdev->done_ee);
			continue;
		}
		spin_unlock_irq(&mdev->ee_lock);
		wait_on_buffer(e->bh);
		spin_lock_irq(&mdev->ee_lock);
		/* The IRQ handler does not move a list entry if someone is 
		   in wait_on_buffer for that entry, therefore we have to
		   move it here. */
		list_del(le); 
		list_add(le,&mdev->done_ee);
	}
	spin_unlock_irq(&mdev->ee_lock);
}

/*static */inline void drbd_wait_active_ee(struct Drbd_Conf* mdev)
{
	_drbd_wait_ee(mdev,&mdev->active_ee);
}

/*static */inline void drbd_wait_sync_ee(struct Drbd_Conf* mdev)
{
	_drbd_wait_ee(mdev,&mdev->sync_ee);
}

/*static */void drbd_c_timeout(unsigned long arg)
{
	struct task_struct *p = (struct task_struct *) arg;

	/*
	printk(KERN_INFO DEVICE_NAME" : retrying to connect(pid=%d)\n",p->pid);
	*/

	drbd_queue_signal(DRBD_SIG,p);

}

/*static */struct socket* drbd_accept(struct socket* sock)
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
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	newsock->ops = sock->ops;
#else
	err = sock->ops->dup(newsock, sock);
#endif
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


/*static */void drbd_idle_timeout(unsigned long arg)
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


/*static */struct socket *drbd_try_connect(struct Drbd_Conf* mdev)
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

/*static */struct socket *drbd_wait_for_connect(struct Drbd_Conf* mdev)
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
		if (sigismember(SIGSET_OF(current), DRBD_SIG)) {
			sigdelset(SIGSET_OF(current), DRBD_SIG);
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
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	sock->sk->tp_pinfo.af_tcp.nonagle=0;
#else
	sock->sk->nonagle=0;
#endif
	// This boosts the performance of the syncer to 6M/s max
	sock->sk->sndbuf = 2*65535; 

	msock->sk->priority=TC_PRIO_INTERACTIVE;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	msock->sk->tp_pinfo.af_tcp.nonagle=1;
#else
	msock->sk->nonagle=1;
#endif
	msock->sk->sndbuf = 2*32767;

	mdev->sock = sock;
	mdev->msock = msock;

	drbd_thread_start(&mdev->asender);

	set_cstate(mdev,WFReportParams);
	drbd_send_param(mdev);

	return 1;
}

inline int receive_cstate(struct Drbd_Conf* mdev)
{
	Drbd_CState_P header;

	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;
	
	set_cstate(mdev,be32_to_cpu(header.cstate));

	/* Clear consistency flag if a syncronisation has started */
	if(mdev->state == Secondary && 
	   (mdev->cstate==SyncingAll || 
	    mdev->cstate==SyncingQuick) ) {
		mdev->gen_cnt[Consistent]=0;
		drbd_md_write((int)(mdev-drbd_conf));
	}

	return TRUE;
}

inline int receive_barrier(struct Drbd_Conf* mdev)
{
  	Drbd_Barrier_P header;
	int rv;
	int epoch_size;

	if(mdev->state != Secondary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got barrier while not SEC!!\n"
		      ,(int)(mdev-drbd_conf));

	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;

	inc_unacked(mdev);

	/* printk(KERN_DEBUG DEVICE_NAME ": got Barrier\n"); */

	/* TODO: use run_task_queue(&tq_disk); here */
	drbd_wait_active_ee(mdev);

	spin_lock_irq(&mdev->ee_lock);
	rv=_drbd_process_done_ee(mdev);

	epoch_size=mdev->epoch_size;
	mdev->epoch_size=0;
	spin_unlock_irq(&mdev->ee_lock);

	drbd_send_b_ack(mdev, header.barrier, epoch_size );

	dec_unacked(mdev);

	return rv;
}

inline int receive_data(struct Drbd_Conf* mdev,int data_size)
{
        struct buffer_head *bh;
	unsigned long block_nr;
	struct Tl_epoch_entry *e;
	Drbd_Data_P header;
	int rr;

	if(mdev->state != Secondary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got data while not SEC!!\n",
		       (int)(mdev-drbd_conf));

	if (drbd_recv(mdev, &header, sizeof(header),0) != 
	    sizeof(header))
	        return FALSE;
       
	/*
	printk(KERN_ERR DEVICE_NAME "%d: recv Data "
	       "block_nr=%ld\n",
	       minor,(unsigned long)be64_to_cpu(header.block_nr));
	*/

	block_nr = be64_to_cpu(header.block_nr);

	if (data_size != (1 << mdev->blk_size_b)) {
		drbd_wait_active_ee(mdev);
		drbd_wait_sync_ee(mdev);
		mdev->blk_size_b = drbd_log2(data_size);
		printk(KERN_ERR DEVICE_NAME "%d: blksize=%d B\n",
		       (int)(mdev-drbd_conf),
		       data_size);
		drbd_ee_fix_bhs(mdev);
	}

	spin_lock_irq(&mdev->ee_lock);
	e=drbd_get_ee(mdev,block_nr);
	e->block_id=header.block_id;
	if( is_syncer_blk(mdev,header.block_id) ) {
		list_add(&e->list,&mdev->sync_ee);
	} else {
		list_add(&e->list,&mdev->active_ee);
	}

	/* do not use mark_buffer_diry() since it would call refile_buffer() */
	bh=e->bh;
	set_bit(BH_Dirty, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state); // since using submit_bh()

	spin_unlock_irq(&mdev->ee_lock);

	rr=drbd_recv(mdev,bh_kmap(bh),data_size,0);
	bh_kunmap(bh);

	if ( rr != data_size) {
		spin_lock_irq(&mdev->ee_lock);
		list_del(&e->list);
		clear_bit(BH_Lock, &bh->b_state);
		drbd_put_ee(mdev,e);
		spin_unlock_irq(&mdev->ee_lock);

		return FALSE;
	}

	mdev->writ_cnt+=data_size/1024;
	submit_bh(WRITE,bh);

	if(mdev->conf.wire_protocol != DRBD_PROT_A || 
	   is_syncer_blk(mdev,header.block_id)) {
		inc_unacked(mdev);
	}

	if (mdev->conf.wire_protocol == DRBD_PROT_B &&
	     !is_syncer_blk(mdev,header.block_id)) {
	        /*  printk(KERN_DEBUG DEVICE_NAME": Sending RecvAck"
		    " %ld\n",header.block_id); */
	        drbd_send_ack(mdev, RecvAck,
			      block_nr,header.block_id);
		dec_unacked(mdev);
	}


	/* Actually the primary can send up to NR_REQUEST / 3 blocks,
	 * but we already start when we have NR_REQUEST / 4 blocks.
	 * 
	 * This code is only with protocol C relevant.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define NUMBER (NR_REQUEST/4)	
#else
#define NUMBER 24 
#endif
	if(atomic_read(&mdev->unacked_cnt) >= NUMBER ) {
		run_task_queue(&tq_disk);
	}
#undef NUMBER

	mdev->recv_cnt+=data_size>>10;
	
	return TRUE;
}     

inline int receive_block_ack(struct Drbd_Conf* mdev)
{     
        drbd_request_t *req;
	Drbd_BlockAck_P header;
	
	// TODO: Make sure that the block is in an active epoch!!
	if(mdev->state != Primary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got blk-ack while not PRI!!\n"
		       ,(int)(mdev-drbd_conf));

	if (drbd_recv(mdev, &header, sizeof(header),0) != 
	    sizeof(header))
	        return FALSE;

	if(mdev->conf.wire_protocol != DRBD_PROT_A ||
	   is_syncer_blk(mdev,header.block_id)) {
		dec_pending(mdev);
	}

	if( is_syncer_blk(mdev,header.block_id)) {
		bm_set_bit(mdev->mbds_id,
			   be64_to_cpu(header.block_nr), 
			   mdev->blk_size_b, 
			   SS_IN_SYNC);
	} else {
		req=(drbd_request_t*)(long)header.block_id;
		drbd_end_req(req, RQ_DRBD_SENT, 1);
	}

	return TRUE;
}

inline int receive_barrier_ack(struct Drbd_Conf* mdev)
{
	Drbd_BarrierAck_P header;

	if(mdev->state != Primary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got barrier-ack while not"
		       " PRI!!\n",(int)(mdev-drbd_conf));

	if (drbd_recv(mdev, &header, sizeof(header),0) != sizeof(header))
	        return FALSE;

        tl_release(mdev,header.barrier,be32_to_cpu(header.set_size));

	dec_pending(mdev);

	return TRUE;
}


inline int receive_param(struct Drbd_Conf* mdev,int command)
{
	kdev_t ll_dev =	mdev->lo_device;
        Drbd_Parameter_P param;
	int blksize;
	int minor=(int)(mdev-drbd_conf);

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

        if (!blk_size[MAJOR(ll_dev)]) {
		blk_size[MAJOR_NR][minor] = 0;
		printk(KERN_ERR DEVICE_NAME"%d: LL dev(%d,%d) has no size!\n",
		       (int)(mdev-drbd_conf),MAJOR(ll_dev),MINOR(ll_dev));
		return FALSE;
	}


	blk_size[MAJOR_NR][minor] =
		min_t(int,blk_size[MAJOR(ll_dev)][MINOR(ll_dev)],
		      be64_to_cpu(param.size));

	if(mdev->lo_usize &&
	   (mdev->lo_usize != blk_size[MAJOR_NR][minor])) {
		printk(KERN_ERR DEVICE_NAME"%d: Your size hint is bogus!"
		       "change it to %d\n",(int)(mdev-drbd_conf),
		       blk_size[MAJOR_NR][minor]);
		blk_size[MAJOR_NR][minor]=mdev->lo_usize;
		set_cstate(mdev,StandAlone);
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
		int pri,method,sync;
		printk(KERN_INFO DEVICE_NAME "%d: Connection established. "
		       "size=%d KB / blksize=%d B\n",
		       minor,blk_size[MAJOR_NR][minor],blksize);

		pri=drbd_md_compare(minor,&param);

		if(pri==0) sync=0;
		else sync=1;

		if(be32_to_cpu(param.state) == Secondary &&
		   mdev->state == Secondary ) {
			if(pri==1) drbd_set_state(minor,Primary);
		} else {
			if( ( pri == 1 ) == 
			    (mdev->state == Secondary) ) {
				printk(KERN_WARNING DEVICE_NAME 
				       "%d: predetermined"
				       " states are in contradiction to GC's\n"
				       ,minor);
			}
		}

		method=drbd_md_syncq_ok(minor,&param,
					mdev->state == Primary) ? 
			SyncingQuick : SyncingAll;

/*
		printk(KERN_INFO DEVICE_NAME "%d: pri=%d sync=%d meth=%c\n",
		       minor,pri,sync,method==SyncingAll?'a':'q');
*/
		if( sync && !mdev->conf.skip_sync ) {
			set_cstate(mdev,method);
			if(mdev->state == Primary) {
				//drbd_send_cstate(mdev);
				drbd_thread_start(&mdev->syncer);
			} else {
				mdev->gen_cnt[Consistent]=0;
				//drbd_md_write(minor); is there anyway.
			}
		} else set_cstate(mdev,Connected);
	}

	mdev->o_state = be32_to_cpu(param.state);

	if (mdev->state == Secondary) {
		/* Secondary has to adopt primary's gen_cnt. */
		int i;
		for(i=HumanCnt;i<=PrimaryInd;i++) {
			mdev->gen_cnt[i]=
				be32_to_cpu(param.gen_cnt[i]);
		}
		drbd_md_write(minor);
	}

	return TRUE;
}


inline void drbd_collect_zombies(int minor)
{
	if(test_and_clear_bit(COLLECT_ZOMBIES,&drbd_conf[minor].flags)) {
		while( waitpid(-1, NULL, __WCLONE|WNOHANG) > 0 );
	}
}

void drbdd(int minor)
{
	Drbd_Packet header;
	int i;

	while (TRUE) {
		drbd_collect_zombies(minor); // in case a syncer exited.
		if (drbd_recv(drbd_conf+minor,&header,sizeof(Drbd_Packet),0)
		    != sizeof(Drbd_Packet)) 
			break;

		if (be32_to_cpu(header.magic) != DRBD_MAGIC) {
			printk(KERN_ERR DEVICE_NAME "%d: magic?? m: %ld "
			       "c: %d "
			       "l: %d \n",
			       minor,
			       (long) be32_to_cpu(header.magic),
			       (int) be16_to_cpu(header.command),
			       (int) be16_to_cpu(header.length));

			break;
		}
		switch (be16_to_cpu(header.command)) {
		case Barrier:
       		        if (!receive_barrier(drbd_conf+minor)) goto out;
			break;

		case Data: 
		        if (!receive_data(drbd_conf+minor,be16_to_cpu(header.length)))
			        goto out;
			break;

		case RecvAck:
		case WriteAck:
		        if (!receive_block_ack(drbd_conf+minor)) goto out;
			break;

		case BarrierAck:
		        if (!receive_barrier_ack(drbd_conf+minor)) goto out;
			break;

		case ReportParams:
		        if (!receive_param(drbd_conf+minor,
					   be16_to_cpu(header.command)))
			        goto out;
			break;

		case CStateChanged:
			if (!receive_cstate(drbd_conf+minor)) goto out;
			break;

		case StartSync:
			set_cstate(drbd_conf+minor,SyncingAll);
			drbd_send_cstate(drbd_conf+minor);
			drbd_thread_start(&drbd_conf[minor].syncer);
			break;

		case BecomeSec:
			drbd_set_state(minor,Secondary);
			break;
		case SetConsistent:
			drbd_conf[minor].gen_cnt[Consistent]=1;
			drbd_md_write(minor);
			break;
		case WriteHint:
			run_task_queue(&tq_disk);
			break;

		default:
			printk(KERN_ERR DEVICE_NAME
			       "%d: unknown packet type!\n", minor);
			goto out;
		}
	}

      out:

	del_timer_sync(&drbd_conf[minor].a_timeout);

	drbd_thread_stop(&drbd_conf[minor].syncer);
	drbd_thread_stop(&drbd_conf[minor].asender);
	drbd_collect_zombies(minor);

	while(down_trylock(&drbd_conf[minor].send_mutex))
	{
		struct send_timer_info *ti;
		spin_lock(&drbd_conf[minor].send_proc_lock);
		if((ti=drbd_conf[minor].send_proc)) {
			ti->timeout_happened=1;
			drbd_queue_signal(DRBD_SIG, ti->task);
			spin_unlock(&drbd_conf[minor].send_proc_lock);
			down(&drbd_conf[minor].send_mutex);
			break;
		} else {
			spin_unlock(&drbd_conf[minor].send_proc_lock);
			schedule_timeout(HZ / 10);
		}
	}
	/* By grabbing the send_mutex we make shure that no one 
	   uses the socket right now. */
	drbd_free_sock(minor);
	up(&drbd_conf[minor].send_mutex);

	if(drbd_conf[minor].cstate != StandAlone) 
	        set_cstate(drbd_conf+minor,Unconnected);

	for(i=0;i<=PrimaryInd;i++) {
		drbd_conf[minor].bit_map_gen[i]=drbd_conf[minor].gen_cnt[i];
	}

	switch(drbd_conf[minor].state) {
	case Primary:   
		tl_clear(drbd_conf+minor);
		clear_bit(ISSUE_BARRIER,&drbd_conf[minor].flags);
		if(!test_bit(DO_NOT_INC_CONCNT,&drbd_conf[minor].flags))
			drbd_md_inc(minor,ConnectedCnt);
		drbd_md_write(minor);
		break;
	case Secondary: 
		drbd_wait_active_ee(drbd_conf+minor);
		drbd_wait_sync_ee(drbd_conf+minor);
		drbd_clear_done_ee(drbd_conf+minor);
		drbd_conf[minor].epoch_size=0;
		break;
	case Unknown:
	}

	if(atomic_read(&drbd_conf[minor].unacked_cnt)) {
		printk(KERN_ERR DEVICE_NAME "%d: unacked_cnt!=0\n",minor);
		atomic_set(&drbd_conf[minor].unacked_cnt,0);
	}		

	/* Since syncer's blocks are also counted, there is no hope that
	   pending_cnt is zero. */
	atomic_set(&drbd_conf[minor].pending_cnt,0); 
	wake_up_interruptible(&drbd_conf[minor].state_wait);

	clear_bit(DO_NOT_INC_CONCNT,&drbd_conf[minor].flags);

	printk(KERN_INFO DEVICE_NAME "%d: Connection lost.\n",minor);
}

int drbdd_init(struct Drbd_thread *thi)
{
	int minor = thi->minor;

	sprintf(current->comm, "drbdd_%d", minor);
	
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
			if (sigismember(SIGSET_OF(current), SIGTERM)) {
				sigdelset(SIGSET_OF(current), SIGTERM);
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

inline int drbd_try_send_barrier(struct Drbd_Conf *mdev)
{
	int rv=TRUE;
	if(down_trylock(&mdev->send_mutex)==0) {
		if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
			if( _drbd_send_barrier(mdev) != 
			    sizeof(Drbd_Barrier_Packet)) rv=FALSE;
		}
		up(&mdev->send_mutex);
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
	Drbd_Packet pkt;
	struct Drbd_Conf *mdev=drbd_conf+thi->minor;
	struct timer_list ping_timeout;
	unsigned long ping_sent_at,flags;
	int rtt=0,rr,rsize=0;

	sprintf(current->comm, "drbd_asender_%d", (int)(mdev-drbd_conf));

	current->policy = SCHED_RR;  /* Make this a realtime task! */
	current->rt_priority = 2;    /* more important than all other tasks */

	init_timer(&ping_timeout);
	ping_timeout.function = drbd_ping_timeout;
	ping_timeout.data = (unsigned long) mdev;

	ping_sent_at=0;

	while(thi->t_state == Running) {
		rr=drbd_recv(mdev,((char*)&pkt)+rsize,sizeof(pkt)-rsize,1);
		if(rr == -ERESTARTSYS) {
			spin_lock_irqsave(&current->sigmask_lock,flags);
			sigemptyset(SIGSET_OF(current));
			recalc_sigpending(current);
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
			rr=0;
		} else if(rr <= 0) break;

		rsize+=rr;		
			
		if(rsize == sizeof(pkt)) {
			if (be32_to_cpu(pkt.magic) != DRBD_MAGIC) {
				printk(KERN_ERR DEVICE_NAME "%d: magic?? "
				       "m: %ld c: %d l: %d \n",
				       (int)(mdev-drbd_conf),
				       (long) be32_to_cpu(pkt.magic),
				       (int) be16_to_cpu(pkt.command),
				       (int) be16_to_cpu(pkt.length));
				goto err;
			}
			switch (be16_to_cpu(pkt.command)) {
			case Ping:
        			if(drbd_send_cmd(mdev,PingAck,1) != 
				   sizeof(Drbd_Packet) ) goto err;
				break;
			case PingAck:
				del_timer(&ping_timeout);
				
				rtt = jiffies-ping_sent_at;
				ping_sent_at=0;
				break;
			}
			rsize=0;
		}
	  
		if(ping_sent_at==0) {
			if(test_and_clear_bit(SEND_PING,&mdev->flags)) {
				if(drbd_send_cmd(mdev,Ping,1)
				   != sizeof(Drbd_Packet) ) goto err;
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
			if(!drbd_process_done_ee(mdev)) goto err;
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

