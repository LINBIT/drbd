/*
-*- linux-c -*-
   drbd_receiver.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
        Added sanity checks in IOCTL_SET_STATE.
		Added code to prevent zombie threads.

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
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include "drbd.h"
#include "drbd_int.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#define mark_buffer_dirty(A)   mark_buffer_dirty(A , 1)
#endif


struct Tl_epoch_entry* drbd_get_ee(struct Drbd_Conf* mdev);

inline void inc_unacked(int minor)
{
	drbd_conf[minor].unacked_cnt++;	
	if(drbd_conf[minor].conf.timeout) {
		mod_timer(&drbd_conf[minor].p_timeout,
			  jiffies + drbd_conf[minor].conf.timeout * HZ / 20);
	}
}

inline void dec_unacked(int minor)
{
	drbd_conf[minor].unacked_cnt--;
	if(drbd_conf[minor].unacked_cnt<0)  /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: unacked_cnt <0 !!!\n",
		       minor);

	if(drbd_conf[minor].conf.timeout) {
		if(drbd_conf[minor].unacked_cnt > 0) {
			mod_timer(&drbd_conf[minor].p_timeout,
				  jiffies + drbd_conf[minor].conf.timeout 
				  * HZ / 20);
		} else {
			del_timer(&drbd_conf[minor].p_timeout);
		}
	}
	if(drbd_conf[minor].unacked_cnt==0)
		wake_up_interruptible(&drbd_conf[minor].state_wait);
}

inline int is_syncer_blk(struct Drbd_Conf* mdev, u64 block_id) 
{
	if ( block_id == ID_SYNCER ) return 1;
	if ( (long)block_id == (long)-1) {
		printk(KERN_ERR DEVICE_NAME 
		       "%d: strange block_id %llx\n",(int)(mdev-drbd_conf),
		       block_id);
		return 1;
	}
	return 0;
}

int drbd_process_done_ee(struct Drbd_Conf* mdev)
{
	struct Tl_epoch_entry *e;
	struct list_head *le;
	int r=sizeof(Drbd_BlockAck_Packet); // for protocol A/B case.
 
	spin_lock_irq(&mdev->ee_lock);

	while(!list_empty(&mdev->done_ee)) {
		le = mdev->done_ee.next;
		list_del(le);
		e = list_entry(le, struct Tl_epoch_entry,list);
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   is_syncer_blk(mdev,e->block_id) ) {
			spin_unlock_irq(&mdev->ee_lock);
			r=drbd_send_ack(mdev, WriteAck,e->bh->b_blocknr,
					e->block_id);
			dec_unacked((int)(mdev-drbd_conf));
			spin_lock_irq(&mdev->ee_lock);
		}
		if(!is_syncer_blk(mdev,e->block_id)) mdev->epoch_size++;
		bforget(e->bh);
		list_add(le,&mdev->free_ee);
		if(r != sizeof(Drbd_BlockAck_Packet )) {
			spin_unlock_irq(&mdev->ee_lock);
			return FALSE;
		}
	}

	spin_unlock_irq(&mdev->ee_lock);

	return TRUE;
}

static inline void drbd_clear_done_ee(struct Drbd_Conf *mdev)
{
	struct list_head *le;
	struct Tl_epoch_entry *e;

	spin_lock_irq(&mdev->ee_lock);

	while(!list_empty(&mdev->done_ee)) {
		le = mdev->done_ee.next;
		list_del(le);
		e = list_entry(le,struct Tl_epoch_entry,list);
		bforget(e->bh);		
		list_add(le,&mdev->free_ee);
		if(mdev->conf.wire_protocol == DRBD_PROT_C ||
		   is_syncer_blk(mdev,e->block_id)) {
			dec_unacked((int)(mdev-drbd_conf));
		}

	}

	spin_unlock_irq(&mdev->ee_lock);
}


void _drbd_wait_ee(struct Drbd_Conf* mdev,struct list_head *head)
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
		/*
		printk(KERN_ERR DEVICE_NAME 
		       "%d: Waiting for bh=%p, blocknr=%ld\n",
		       (int)(mdev-drbd_conf),e->bh,e->bh->b_blocknr);
		*/
		wait_on_buffer(e->bh);
		spin_lock_irq(&mdev->ee_lock);
	}
	spin_unlock_irq(&mdev->ee_lock);
}

static inline void drbd_wait_active_ee(struct Drbd_Conf* mdev)
{
	_drbd_wait_ee(mdev,&mdev->active_ee);
}

static inline void drbd_wait_sync_ee(struct Drbd_Conf* mdev)
{
	_drbd_wait_ee(mdev,&mdev->sync_ee);
}

void drbd_p_timeout(unsigned long arg)
{
	struct Drbd_Conf* mdev = (struct Drbd_Conf*)arg;

	printk(KERN_ERR DEVICE_NAME "%d: it's getting late\n", 
	       (int)(mdev-drbd_conf));

	set_bit(SEND_POSTPONE,&mdev->flags);

	wake_up_interruptible(&mdev->asender_wait);


}

void drbd_c_timeout(unsigned long arg)
{
	struct task_struct *p = (struct task_struct *) arg;

	/*
	printk(KERN_INFO DEVICE_NAME" : retrying to connect(pid=%d)\n",p->pid);
	*/

	drbd_queue_signal(DRBD_SIG,p->pid);

}

struct socket* drbd_accept(struct socket* sock)
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

void drbd_ping_timeout(unsigned long arg)
{
	struct Drbd_Conf* mdev = (struct Drbd_Conf*)arg;

	set_bit(SEND_PING,&mdev->flags);
	wake_up_interruptible(&mdev->asender_wait);
	
}


int drbd_recv(struct Drbd_Conf* mdev, void *ubuf, size_t size)
{
	mm_segment_t oldfs;
	struct iovec iov;
	struct msghdr msg;
	struct timer_list idle_timeout;
	int err = 0;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_iovlen = 1;
	msg.msg_iov = &iov;
	iov.iov_len = size;
	iov.iov_base = ubuf;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_flags = 0;



	if (mdev->conf.ping_int) {
		init_timer(&idle_timeout);
		idle_timeout.function = drbd_ping_timeout;
		idle_timeout.data = (unsigned long) mdev;
		idle_timeout.expires =
		    jiffies + mdev->conf.ping_int * HZ;
		add_timer(&idle_timeout);
	}


	lock_kernel();
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	/* Check if this get_fs() / set_fs stuff is needed for a kernel_thread */
	err = sock_recvmsg(mdev->sock, &msg, size, MSG_WAITALL);

	set_fs(oldfs);
	unlock_kernel();
	if (err != size && err != -ERESTARTSYS && err != 0)
		printk(KERN_ERR DEVICE_NAME "%d: sock_recvmsg returned %d\n",
		       (int)(mdev-drbd_conf),err);

	if (mdev->conf.ping_int) {
		del_timer(&idle_timeout);
	}
	

	return err;
}

/* I do not know why, but this prototype is missing in the net.h includefile:
   int sock_setsockopt(struct socket *sock, int level, int optname,
   char *optval, int optlen);
*/
int drbd_connect(int minor)
{
	int err;
	struct socket *sock;

 retry:

	if (drbd_conf[minor].cstate==Unconfigured) return 0;

	if (drbd_conf[minor].sock) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: There is already a socket!! \n",minor);
		return 0;
	}
	err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
	if (err) {
		printk(KERN_ERR DEVICE_NAME "%d: sock_creat(..)=%d\n", minor,
		       err);
	}

	lock_kernel();	
	err = sock->ops->connect(sock,
				 (struct sockaddr *) drbd_conf[minor].conf.
				 other_addr,
				 drbd_conf[minor].conf.other_addr_len, 0);
	unlock_kernel();

	if (err) {
		struct socket *sock2;
		struct timer_list accept_timeout;

		sock_release(sock);
		/* printk(KERN_INFO DEVICE_NAME
		   ": Unable to connec to server (%d)\n", err); */

		err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
		if (err) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: sock_creat(..)=%d\n", minor,err);
		}

		sock->sk->reuse=1; /* SO_REUSEADDR */

		lock_kernel();
		err = sock->ops->bind(sock,
				      (struct sockaddr *) drbd_conf[minor].
				      conf.my_addr,
				      drbd_conf[minor].conf.my_addr_len);
		unlock_kernel();
		if (err) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: Unable to bind (%d)\n", minor,err);
			sock_release(sock);
			set_cstate(&drbd_conf[minor],Unconnected);
			return 0;
		}

		set_cstate(&drbd_conf[minor],WFConnection);
		sock2 = sock;
		
		if(drbd_conf[minor].conf.try_connect_int) {
			init_timer(&accept_timeout);
			accept_timeout.function = drbd_c_timeout;
			accept_timeout.data = (unsigned long) current;
			accept_timeout.expires = jiffies +
				drbd_conf[minor].conf.try_connect_int * HZ;
			add_timer(&accept_timeout);
		}			

		sock = drbd_accept(sock2);
		sock_release(sock2);

		if(drbd_conf[minor].conf.try_connect_int) {
			unsigned long flags;
			del_timer(&accept_timeout);
			spin_lock_irqsave(&current->sigmask_lock,flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
			if (sigismember(&current->signal, DRBD_SIG)) {
				sigdelset(&current->signal, DRBD_SIG);
#else
			if (sigismember(&current->pending.signal, DRBD_SIG)) {
				sigdelset(&current->pending.signal, DRBD_SIG);
#endif
				recalc_sigpending(current);
				spin_unlock_irqrestore(&current->sigmask_lock,
						       flags);
				if(sock) sock_release(sock);
				goto retry;
			}
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
		}

		if (!sock) {
			set_cstate(&drbd_conf[minor],Unconnected);
			return 0;
		}
	}

	sock->sk->reuse=1;    /* SO_REUSEADDR */

	drbd_conf[minor].sock = sock;

	drbd_setup_sock(&drbd_conf[minor]);

	drbd_thread_start(&drbd_conf[minor].asender);

	set_cstate(&drbd_conf[minor],WFReportParams);
	err = drbd_send_param(minor);

	return 1;
}

inline int receive_cstate(int minor)
{
	Drbd_CState_P header;

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) 
	    != sizeof(header))
	        return FALSE;
	
	set_cstate(&drbd_conf[minor],be32_to_cpu(header.cstate));

	/* Clear consistency flag if a syncronisation has started */
	if(drbd_conf[minor].state == Secondary && 
	   (drbd_conf[minor].cstate==SyncingAll || 
	    drbd_conf[minor].cstate==SyncingQuick) ) {
		drbd_conf[minor].gen_cnt[Consistent]=0;
		drbd_md_write(minor);
	}

	return TRUE;
}

inline int receive_barrier(int minor)
{
  	Drbd_Barrier_P header;
	int rv;

	if(drbd_conf[minor].state != Secondary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got barrier while not SEC!!\n",
		       minor);

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) 
	    != sizeof(header))
	        return FALSE;

	inc_unacked(minor);

	/* printk(KERN_DEBUG DEVICE_NAME ": got Barrier\n"); */

	drbd_wait_active_ee(drbd_conf+minor);
	rv=drbd_process_done_ee(drbd_conf+minor);

	drbd_send_b_ack(&drbd_conf[minor], header.barrier,
			drbd_conf[minor].epoch_size );
	drbd_conf[minor].epoch_size=0;
	dec_unacked(minor);

	return rv;
}

inline int receive_data(int minor,int data_size)
{
        struct buffer_head *bh;
	unsigned long block_nr;
	struct Tl_epoch_entry *e;
	Drbd_Data_P header;

	if(drbd_conf[minor].state != Secondary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got data while not SEC!!\n",
		       minor);

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) != 
	    sizeof(header))
	        return FALSE;
       
	/*
	  printk(KERN_DEBUG DEVICE_NAME ": recv Data "
	  "block_nr=%ld len=%d/m=%d bs_bits=%d\n",
	  be64_to_cpu(header.block_nr),
	  (int)be16_to_cpu(header.length),
	  minor,drbd_conf[minor].blk_size_b); 
	*/
	block_nr = be64_to_cpu(header.block_nr);

	if (data_size != (1 << drbd_conf[minor].blk_size_b)) {
		set_blocksize(MKDEV(MAJOR_NR, minor), data_size);
		set_blocksize(drbd_conf[minor].lo_device,data_size);
		drbd_conf[minor].blk_size_b = drbd_log2(data_size);
		printk(KERN_INFO DEVICE_NAME "%d: blksize=%d B\n",minor,
		       data_size);
	}

	bh = getblk(MKDEV(MAJOR_NR, minor), block_nr,data_size);

	if (!bh) {
	        printk(KERN_ERR DEVICE_NAME"%d: getblk()=0\n",minor);
	        return FALSE;
	}

	if (drbd_recv(&drbd_conf[minor], bh->b_data, data_size) 
	    != data_size) {
		bforget(bh);
		return FALSE;
	}

	spin_lock_irq(&drbd_conf[minor].ee_lock);
	e=drbd_get_ee(drbd_conf+minor);
	e->bh=bh;
	e->block_id=header.block_id;
	if( is_syncer_blk(drbd_conf+minor,header.block_id) ) {
		list_add(&e->list,&drbd_conf[minor].sync_ee);
	} else {
		list_add(&e->list,&drbd_conf[minor].active_ee);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
	bh->b_dev_id = e;
#else
	bh->b_private = e;
#endif
	spin_unlock_irq(&drbd_conf[minor].ee_lock);

	/* When you call mark_buffer_diry() before drbd_recv() (which 
	   can sleep) you risk, that the system writes the
	   buffer while you are sleeping. --> and the b_private
	   field of the buffer head is not set... oops 	*/
	mark_buffer_dirty(bh);     
	mark_buffer_uptodate(bh, 0);

//	generic_make_request(WRITE,bh);
	ll_rw_block(WRITE, 1, &bh);

	if(drbd_conf[minor].conf.wire_protocol != DRBD_PROT_A || 
	   is_syncer_blk(drbd_conf+minor,header.block_id)) {
		inc_unacked(minor);
	}

	if (drbd_conf[minor].conf.wire_protocol == DRBD_PROT_B &&
	     !is_syncer_blk(drbd_conf+minor,header.block_id)) {
	        /*  printk(KERN_DEBUG DEVICE_NAME": Sending RecvAck"
		    " %ld\n",header.block_id); */
	        drbd_send_ack(&drbd_conf[minor], RecvAck,
			      block_nr,header.block_id);
		dec_unacked(minor);
	}


	/* <HACK>
	 * This is needed to get reasonable performance with protocol C
	 * while there is no other IO activitiy on the secondary machine.
	 *
	 * With the other protocols blocks keep rolling in, and 
	 * tq_disk is started from __get_request_wait. Since in protocol C
	 * the PRIMARY machine can not send more blocks because the secondary
	 * has to finish IO first, we need this.
	 *
	 * Actually the primary can send up to NR_REQUESTS / 3 blocks,
	 * but we already start when we have NR_REQUESTS / 4 blocks.
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
	if (drbd_conf[minor].conf.wire_protocol == DRBD_PROT_C) {
		if (drbd_conf[minor].unacked_cnt >= (NR_REQUEST / 4)) {
			run_task_queue(&tq_disk);
		}
	}
#endif
	/* </HACK> */

	drbd_conf[minor].recv_cnt+=data_size>>10;
	
	return TRUE;
}     

inline int receive_block_ack(int minor)
{     
        drbd_request_t *req;
	Drbd_BlockAck_P header;
	
	if(drbd_conf[minor].state != Primary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got blk-ack while not PRI!!\n",
		       minor);

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) != 
	    sizeof(header))
	        return FALSE;

	if( is_syncer_blk(drbd_conf+minor,header.block_id)) {
	syncer_blk:
		bm_set_bit(drbd_conf[minor].mbds_id,
			   be64_to_cpu(header.block_nr), 
			   drbd_conf[minor].blk_size_b, 
			   SS_IN_SYNC);
	} else {
		req=(drbd_request_t*)(long)header.block_id;
		if(req == (drbd_request_t*)-1) { // REMOVE THIS LATER
			printk(KERN_ERR DEVICE_NAME 
			       "%d: strange block_id2 %llx\n",minor,
			       header.block_id);
			goto syncer_blk;
		}
		drbd_end_req(req, RQ_DRBD_SENT, 1);

		if(drbd_conf[minor].conf.wire_protocol != DRBD_PROT_A)
			dec_pending(minor);
	}

	return TRUE;
}

inline int receive_barrier_ack(int minor)
{
	Drbd_BarrierAck_P header;

	if(drbd_conf[minor].state != Primary) /* CHK */
		printk(KERN_ERR DEVICE_NAME "%d: got barrier-ack while not"
		       " PRI!!\n",minor);

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) != 
	    sizeof(header))
	        return FALSE;

        tl_release(&drbd_conf[minor],header.barrier,
		   be32_to_cpu(header.set_size));

	dec_pending(minor);

	return TRUE;
}


inline int receive_param(int minor,int command)
{
	kdev_t ll_dev =	drbd_conf[minor].lo_device;
        Drbd_Parameter_P param;
	int blksize;

	/*printk(KERN_DEBUG DEVICE_NAME
	  ": recv ReportParams/m=%d\n",minor);*/

	if (drbd_recv(&drbd_conf[minor], &param, sizeof(param)) != 
	    sizeof(param))
	        return FALSE;

	if(be32_to_cpu(param.state) == Primary &&
	   drbd_conf[minor].state == Primary ) {
		printk(KERN_ERR DEVICE_NAME"%d: incompatible states \n",minor);
		set_cstate(&drbd_conf[minor],StandAlone);
		drbd_conf[minor].receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(param.version)!=PRO_VERSION) {
	        printk(KERN_ERR DEVICE_NAME"%d: incompatible releases \n",
		       minor);
		set_cstate(&drbd_conf[minor],StandAlone);
		drbd_conf[minor].receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(param.protocol)!=drbd_conf[minor].conf.wire_protocol) {
	        printk(KERN_ERR DEVICE_NAME"%d: incompatible protocols \n",
		       minor);
		set_cstate(&drbd_conf[minor],StandAlone);
		drbd_conf[minor].receiver.t_state = Exiting;
		return FALSE;
	}

        if (!blk_size[MAJOR(ll_dev)]) {
		blk_size[MAJOR_NR][minor] = 0;
		printk(KERN_ERR DEVICE_NAME"%d: LL dev(%d,%d) has no size!\n",
		       minor,MAJOR(ll_dev),MINOR(ll_dev));
		return FALSE;
	}

	drbd_conf[minor].o_state = be32_to_cpu(param.state);

	blk_size[MAJOR_NR][minor] =
		min(int,blk_size[MAJOR(ll_dev)][MINOR(ll_dev)],
		    be64_to_cpu(param.size));

	if(drbd_conf[minor].lo_usize &&
	   (drbd_conf[minor].lo_usize != blk_size[MAJOR_NR][minor])) {
		printk(KERN_ERR DEVICE_NAME"%d: Your size hint is bogus!"
		       "change it to %d\n",minor,blk_size[MAJOR_NR][minor]);
		blk_size[MAJOR_NR][minor]=drbd_conf[minor].lo_usize;
		set_cstate(&drbd_conf[minor],StandAlone);
		return FALSE;
	}

	if(drbd_conf[minor].state == Primary)
		blksize = (1 << drbd_conf[minor].blk_size_b);
	else if(be32_to_cpu(param.state) == Primary)
		blksize = be32_to_cpu(param.blksize);
	else 
		blksize = max(int,be32_to_cpu(param.blksize),
			      (1 << drbd_conf[minor].blk_size_b));

	set_blocksize(MKDEV(MAJOR_NR, minor),blksize);
	set_blocksize(drbd_conf[minor].lo_device,blksize);
	drbd_conf[minor].blk_size_b = drbd_log2(blksize);

	/* Do we need to adjust the device size to end on block 
	   boundary ?? I do not think so ! */

	if (!drbd_conf[minor].mbds_id) {
		drbd_conf[minor].mbds_id = bm_init(MKDEV(MAJOR_NR, minor));
	}
	
	if (drbd_conf[minor].cstate == WFReportParams) {
		int pri,method,sync;
		printk(KERN_INFO DEVICE_NAME "%d: Connection established.\n",
		       minor);
		printk(KERN_INFO DEVICE_NAME "%d: size=%d KB / blksize=%d B\n",
		       minor,blk_size[MAJOR_NR][minor],blksize);

		pri=drbd_md_compare(minor,&param);
		method=drbd_md_syncq_ok(minor,&param)?SyncingQuick:SyncingAll;
		sync=(drbd_conf[minor].state!=drbd_conf[minor].o_state);

		if(be32_to_cpu(param.state) == Secondary &&
		   drbd_conf[minor].state == Secondary ) {
			switch(pri) {
			case 1: drbd_set_state(minor,Primary);
			case -1:sync=1;
				break;
			case 0: sync=0;
				break;
			}
		}

		if( sync && !drbd_conf[minor].conf.skip_sync ) {
			set_cstate(&drbd_conf[minor],method);
			if(pri==1) {
				drbd_send_cstate(&drbd_conf[minor]);
				drbd_thread_start(&drbd_conf[minor].syncer);
			}
		} else set_cstate(&drbd_conf[minor],Connected);
	}

	if (drbd_conf[minor].state == Secondary) {
		/* Secondary has to adopt primary's gen_cnt. */
		int i;
		for(i=0;i<=PrimaryInd;i++) {
			drbd_conf[minor].gen_cnt[i]=
				be32_to_cpu(param.gen_cnt[i]);
		}
		drbd_md_write(minor);
	}

	return TRUE;
}

inline void receive_postpone(int minor)
{
	printk(KERN_ERR DEVICE_NAME"%d: got Postpone\n",minor);

	if(timer_pending(&drbd_conf[minor].a_timeout)) {
		printk(KERN_ERR DEVICE_NAME"%d: ack timeout: %ld\n",minor,
		       drbd_conf[minor].a_timeout.expires);
		mod_timer(&drbd_conf[minor].a_timeout,
			  jiffies +
			  /* drbd_conf[minor].a_timeout.expires + */
			  drbd_conf[minor].conf.timeout * HZ / 10);
		printk(KERN_ERR DEVICE_NAME"%d: ack timeout: %ld\n",minor,
		       drbd_conf[minor].a_timeout.expires);
	}

	if(timer_pending(&drbd_conf[minor].s_timeout)) {
		printk(KERN_ERR DEVICE_NAME"%d: send timeout: %ld\n",minor,
		       drbd_conf[minor].s_timeout.expires);
		mod_timer(&drbd_conf[minor].s_timeout,
			  jiffies +
			  /* drbd_conf[minor].s_timeout.expires + */
			  drbd_conf[minor].conf.timeout * HZ / 10);
		printk(KERN_ERR DEVICE_NAME"%d: send timeout: %ld\n",minor,
		       drbd_conf[minor].s_timeout.expires);
	}
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
		drbd_collect_zombies(minor);

		if (drbd_recv(&drbd_conf[minor],&header,sizeof(Drbd_Packet))!= 
		     sizeof(Drbd_Packet)) 
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
       		        if (!receive_barrier(minor)) goto out;
			break;

		case Data: 
		        if (!receive_data(minor,be16_to_cpu(header.length)))
			        goto out;
			break;

		case Ping:
			drbd_send_cmd(minor,PingAck);
			break;
		case PingAck:
			dec_pending(minor);
			break;

		case RecvAck:
		case WriteAck:
		        if (!receive_block_ack(minor)) goto out;
			break;

		case BarrierAck:
		        if (!receive_barrier_ack(minor)) goto out;
			break;

		case ReportParams:
		        if (!receive_param(minor,be16_to_cpu(header.command)))
			        goto out;
			break;

		case CStateChanged:
			if (!receive_cstate(minor)) goto out;
			break;

		case StartSync:
			set_cstate(&drbd_conf[minor],SyncingAll);
			drbd_send_cstate(&drbd_conf[minor]);
			drbd_thread_start(&drbd_conf[minor].syncer);
			break;

		case Postpone:
			receive_postpone(minor);
			break;
		case BecomeSec:
			drbd_set_state(minor,Secondary);
			break;
		case SetConsistent:
			drbd_conf[minor].gen_cnt[Consistent]=1;
			drbd_md_write(minor);
			break;
		default:
			printk(KERN_ERR DEVICE_NAME
			       "%d: unknown packet type!\n", minor);
			goto out;
		}
	}

      out:
	del_timer(&drbd_conf[minor].a_timeout);

	if (drbd_conf[minor].sock) {
	        drbd_thread_stop(&drbd_conf[minor].syncer);
	        drbd_thread_stop(&drbd_conf[minor].asender);
		sock_release(drbd_conf[minor].sock);
		drbd_conf[minor].sock = 0;
	}

	printk(KERN_INFO DEVICE_NAME "%d: Connection lost."
	       "(pc=%d,uc=%d)\n",minor,drbd_conf[minor].pending_cnt,
	       drbd_conf[minor].unacked_cnt);

	if(drbd_conf[minor].cstate != StandAlone) 
	        set_cstate(&drbd_conf[minor],Unconnected);

	for(i=0;i<=PrimaryInd;i++) {
		drbd_conf[minor].bit_map_gen[i]=drbd_conf[minor].gen_cnt[i];
	}

	switch(drbd_conf[minor].state) {
	case Primary:   
		tl_clear(&drbd_conf[minor]);
		clear_bit(ISSUE_BARRIER,&drbd_conf[minor].flags);
		drbd_md_inc(minor,ConnectedCnt);
		drbd_md_write(minor);
		break;
	case Secondary: 
		drbd_wait_active_ee(drbd_conf+minor);
		drbd_wait_sync_ee(drbd_conf+minor);
		drbd_clear_done_ee(drbd_conf+minor);
		drbd_conf[minor].unacked_cnt=0;		
		del_timer(&drbd_conf[minor].p_timeout);
		wake_up_interruptible(&drbd_conf[minor].state_wait);
		break;
	case Unknown:
	}
	drbd_conf[minor].pending_cnt = 0;
	del_timer(&drbd_conf[minor].a_timeout);
}

int drbdd_init(struct Drbd_thread *thi)
{
	int minor = thi->minor;

	sprintf(current->comm, "drbdd_%d", minor);
	
	/* printk(KERN_INFO DEVICE_NAME ": receiver living/m=%d\n", minor); */
	
	while (TRUE) {
		if (!drbd_connect(minor)) break;
		if (thi->t_state == Exiting) break;
		drbdd(minor);
		if (thi->t_state == Exiting) break;
		if (thi->t_state == Restarting) {
			unsigned long flags;
			thi->t_state = Running;
			wake_up(&thi->wait);
			spin_lock_irqsave(&current->sigmask_lock,flags);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
			if (sigismember(&current->signal, SIGTERM)) {
				sigdelset(&current->signal, SIGTERM);
#else
			if (sigismember(&current->pending.signal, SIGTERM)) {
				sigdelset(&current->pending.signal, SIGTERM);
#endif
				recalc_sigpending(current);
			}
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
		}
	}

	printk(KERN_DEBUG DEVICE_NAME "%d: receiver exiting\n", minor);

	/* set_cstate(&drbd_conf[minor],StandAlone); */

	return 0;
}

/* ********* acknowledge sender for protocol C ******** */

inline void drbd_try_send_barrier(struct Drbd_Conf *mdev)
{
	down(&mdev->send_mutex);
	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
	        _drbd_send_barrier(mdev);
	}
	up(&mdev->send_mutex);
}     

int drbd_asender(struct Drbd_thread *thi)
{
	int minor = thi->minor;

	sprintf(current->comm, "drbd_asender_%d", minor);

	while(thi->t_state == Running) {

	  interruptible_sleep_on(&drbd_conf[minor].asender_wait);
	  if(signal_pending(current)) break;
	  
	  if(thi->t_state == Exiting) break;

	  if(test_and_clear_bit(SEND_PING,&drbd_conf[minor].flags)) {
		  if(drbd_send_cmd(minor,Ping)==sizeof(Drbd_Packet))
			  inc_pending(minor);
	  }

	  if(test_and_clear_bit(SEND_POSTPONE,&drbd_conf[minor].flags)) {
		  printk(KERN_INFO DEVICE_NAME"%d: sending postpone packet!\n",
			 minor);

		  mod_timer(&drbd_conf[minor].p_timeout, jiffies + 
			    drbd_conf[minor].conf.timeout * HZ / 20);

		  /*
		  printk(KERN_ERR DEVICE_NAME"%d: expire=%ld now=%ld\n",
			 minor,drbd_conf[minor].p_timeout.expires,
			 jiffies);
		  
		  if( timer_pending(&drbd_conf[minor].p_timeout)) {
			  printk(KERN_ERR DEVICE_NAME"%d: p_timeout is act.\n",
				 minor);
			  
		  }
		  */
		  drbd_send_cmd(minor,Postpone);

	  }

	  if( drbd_conf[minor].state == Primary ) {
		  drbd_try_send_barrier(&drbd_conf[minor]);
		  continue;
	  }

	  drbd_process_done_ee(drbd_conf+minor);

	  //TODO: should asender exit if sending fails ?

	}

	return 0;
}

struct Tl_epoch_entry* drbd_get_ee(struct Drbd_Conf* mdev)
{
	struct Tl_epoch_entry* e;

	if(list_empty(&mdev->free_ee)) drbd_process_done_ee(mdev);

	if(list_empty(&mdev->free_ee)) {
		e=kmalloc(sizeof(struct Tl_epoch_entry),GFP_USER);
		if (!e) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: could not kmalloc() \n",
			       (int)(mdev-drbd_conf));
		}
	} else {
		struct list_head *le; 	
		le=mdev->free_ee.next;
		list_del(le);
		e=list_entry(le, struct Tl_epoch_entry, list);
	}

	return e;
}
