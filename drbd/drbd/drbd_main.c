/*
-*- Linux-c -*-
   drbd.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

   Copyright (C) 2000, Marcelo Tosatti <marcelo@conectiva.com.br>.
        Early 2.3.x work.

   Copyright (C) 2001, Lelik P.Korchagin <lelik@price.ru>.
        Initial devfs support.

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


/*
  By introducing a "Shared" state beside "Primary" and "Secondary" for
  use with GFS at least the following items need to be done.
  *) transfer_log and epoch_set reside in the same memory now.
  *) writes on the receiver side must be done with a temporary
     buffer_head directly to the lower level device. 
     Otherwise we would get in an endless loop sending the same 
     block over all the time.
  *) All occurences of "Primary" or "Secondary" must be reviewed.
*/

#ifdef HAVE_AUTOCONF
#include <linux/autoconf.h>
#endif
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif

#include <asm/uaccess.h>
#include <asm/bitops.h> 
#include <asm/types.h>
#include <net/sock.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/slab.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#include "drbd.h"
#include "drbd_int.h"

#ifdef CONFIG_DEVFS_FS
#include <linux/devfs_fs_kernel.h>
static devfs_handle_t devfs_handle;
#endif

/* #define ES_SIZE_STATS 50 */

int drbdd_init(struct Drbd_thread*);
int drbd_syncer(struct Drbd_thread*);
int drbd_asender(struct Drbd_thread*);

int drbd_init(void);
STATIC int drbd_open(struct inode *inode, struct file *file);
STATIC int drbd_close(struct inode *inode, struct file *file);

int drbd_send(struct Drbd_Conf *, Drbd_Packet*, size_t , void* , size_t,int );

#ifdef DEVICE_REQUEST
#undef DEVICE_REQUEST
#endif
#define DEVICE_REQUEST drbd_do_request

MODULE_AUTHOR("Philipp Reisner <philipp.reisner@gmx.at>");
MODULE_DESCRIPTION("drbd - Distributed Replicated Block Device");
MODULE_LICENSE("GPL");
MODULE_PARM(minor_count,"i");
MODULE_PARM(disable_io_hints,"i");
MODULE_PARM_DESC(minor_count, "Maximum number of drbd devices (1-255)");
MODULE_PARM_DESC(disable_io_hints, "Necessary if loopback devices are used for DRBD" );

STATIC int *drbd_blocksizes;
STATIC int *drbd_sizes;
struct Drbd_Conf *drbd_conf;
int minor_count=2;
int disable_io_hints=0;

STATIC struct block_device_operations drbd_ops = {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,4,10)
	.owner =   THIS_MODULE,
#endif
	.open =    drbd_open,
	.release = drbd_close,
	.ioctl =   drbd_ioctl
};

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

static int errno;

int drbd_log2(int i)
{
	int bits = 0;
	int add_one=0; /* In case there is not a whole-numbered solution,
			  round up */
	while (i != 1) {
		bits++;
		if ( (i & 1) == 1) add_one=1;
		i >>= 1;
	}
	return bits+add_one;
}



/************************* The transfer log start */
STATIC inline void tl_init(struct Drbd_Conf *mdev)
{
	struct drbd_barrier *b;

	b=kmalloc(sizeof(struct drbd_barrier),GFP_KERNEL);
	INIT_LIST_HEAD(&b->requests);
	b->next=0;
	b->br_number=4711;
	b->n_req=0;

	mdev->oldest_barrier = b;
	mdev->newest_barrier = b;
}

STATIC void tl_cleanup(struct Drbd_Conf *mdev)
{
	D_ASSERT(mdev->oldest_barrier == mdev->newest_barrier);

	kfree(mdev->oldest_barrier);
}

STATIC inline void tl_add(struct Drbd_Conf *mdev, drbd_request_t * new_item)
{
	struct drbd_barrier *b;

 	spin_lock_irq(&mdev->tl_lock);

	b=mdev->newest_barrier;

	new_item->sector = GET_SECTOR(new_item);
	new_item->barrier = b;
	list_add(&new_item->list,&b->requests);

	if( b->n_req++ > mdev->conf.max_epoch_size ) {
		set_bit(ISSUE_BARRIER,&mdev->flags);
	}

	spin_unlock_irq(&mdev->tl_lock);
}

STATIC inline unsigned int tl_add_barrier(struct Drbd_Conf *mdev)
{
	unsigned int bnr;
	static int barrier_nr_issue=1;
	struct drbd_barrier *b;

	barrier_nr_issue++; 

	b=kmalloc(sizeof(struct drbd_barrier),GFP_KERNEL);
	INIT_LIST_HEAD(&b->requests);
	b->next=0;
	b->br_number=barrier_nr_issue;
	b->n_req=0;
	
	spin_lock_irq(&mdev->tl_lock);

	bnr = mdev->newest_barrier->br_number;
	mdev->newest_barrier->next = b;
	mdev->newest_barrier = b;

	spin_unlock_irq(&mdev->tl_lock);

	return bnr;
}

void tl_release(struct Drbd_Conf *mdev,unsigned int barrier_nr,
		       unsigned int set_size)
{
	struct drbd_barrier *b;

	spin_lock_irq(&mdev->tl_lock);

	b = mdev->oldest_barrier;
	mdev->oldest_barrier = b->next;

	list_del(&b->requests); 
	/* There could be requests on the list waiting for completion 
	   of the write to the local disk, to avoid corruptions of 
	   slab's data structures we have to remove the lists head */

	spin_unlock_irq(&mdev->tl_lock);

	D_ASSERT(b->br_number == barrier_nr);
	D_ASSERT(b->n_req == set_size);

	kfree(b);
}

/* tl_dependence reports if this sector was present in the current
   epoch. 
   As side effect it clears also the pointer to the request if it
   was present in the transfert log. (Since tl_dependence indicates
   that IO is complete and that drbd_end_req() should not be called
   in case tl_clear has to be called due to interruption of the 
   communication) 
*/
int tl_dependence(struct Drbd_Conf *mdev, drbd_request_t * item)
{
	unsigned long flags;
	int r=TRUE;

	spin_lock_irqsave(&mdev->tl_lock,flags);

	r = ( item->barrier == mdev->newest_barrier );
	list_del(&item->list);

	spin_unlock_irqrestore(&mdev->tl_lock,flags);
	return r;
}

// Returns true if this sector is currently on the fly to our ll_disk
int tl_check_sector(struct Drbd_Conf *mdev, sector_t sector)
{
	struct list_head *le;
	struct drbd_barrier *b;
	struct drbd_request *r;
	int rv=FALSE;

	if(mdev->send_sector == sector) return TRUE;

	spin_lock_irq(&mdev->tl_lock);
	b=mdev->oldest_barrier;
	while ( b ) {
		list_for_each(le,&b->requests) {
			r=list_entry(le, struct drbd_request,list);
			if( r->sector == sector &&
			    (r->rq_status&0xfffe) != RQ_DRBD_WRITTEN ) {
				rv=TRUE;
				goto found;
			}
		}
		b=b->next;
	}
 found:
	spin_unlock_irq(&mdev->tl_lock);
	return rv;
}

void tl_clear(struct Drbd_Conf *mdev)
{
	struct list_head *le,*tle;
	struct drbd_barrier *b,*f,*new_first;
	struct drbd_request *r;

	new_first=kmalloc(sizeof(struct drbd_barrier),GFP_KERNEL);
	INIT_LIST_HEAD(&new_first->requests);
	new_first->next=0;
	new_first->br_number=4711;
	new_first->n_req=0;

	spin_lock_irq(&mdev->tl_lock);

	b=mdev->oldest_barrier;
	while ( b ) {
		list_for_each_safe(le, tle, &b->requests) {
			r = list_entry(le, struct drbd_request,list);
			if( (r->rq_status&0xfffe) != RQ_DRBD_SENT ) {
				drbd_end_req(r,RQ_DRBD_SENT,ERF_NOTLD|1);
				goto mark;
			}
			if(mdev->conf.wire_protocol != DRBD_PROT_C ) {
			mark:
				drbd_set_out_of_sync(mdev,r->sector);
			}
		}
		f=b;
		b=b->next;
		list_del(&f->requests);
		kfree(f);
	}

	mdev->oldest_barrier = new_first;
	mdev->newest_barrier = new_first;

	spin_unlock_irq(&mdev->tl_lock);
}     

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,14) 
// Check when daemonize was introduced.
void daemonize(void)
{
        struct fs_struct *fs;

        exit_mm(current);

        current->session = 1;
        current->pgrp = 1;
        current->tty = NULL;

        exit_fs(current);       /* current->fs->count--; */
        fs = init_task.fs;
        current->fs = fs;
        atomic_inc(&fs->count);
        exit_files(current);
        current->files = init_task.files;
        atomic_inc(&current->files->count);
}
#endif


STATIC int drbd_thread_setup(void* arg)
{
	struct Drbd_thread *thi = (struct Drbd_thread *) arg;
	int retval;

	daemonize();

	down(&thi->mutex); //ensures that thi->task is set.

	retval = thi->function(thi);

	thi->task = 0;
	set_bit(COLLECT_ZOMBIES,&drbd_conf[thi->minor].flags);
	up(&thi->mutex); //allow thread_stop to proceed

	return retval;
}

STATIC void drbd_thread_init(int minor, struct Drbd_thread *thi,
		      int (*func) (struct Drbd_thread *))
{
	thi->task = NULL;
	init_MUTEX(&thi->mutex);
	thi->function = func;
	thi->minor = minor;
}

void drbd_thread_start(struct Drbd_thread *thi)
{
	int pid;

	if (thi->task == NULL) {
		thi->t_state = Running;

		down(&thi->mutex);
		pid = kernel_thread(drbd_thread_setup, (void *) thi, CLONE_FS);

		if (pid < 0) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: Couldn't start thread (%d)\n", thi->minor,
			       pid);
			return;
		}
		/* printk(KERN_DEBUG DEVICE_NAME ": pid = %d\n", pid); */
		read_lock(&tasklist_lock);
		thi->task = find_task_by_pid(pid);
		read_unlock(&tasklist_lock);
		up(&thi->mutex);
	}
}


void _drbd_thread_stop(struct Drbd_thread *thi, int restart,int wait)
{
	if (!thi->task) return;

	if (restart)
		thi->t_state = Restarting;
	else
		thi->t_state = Exiting;

	drbd_queue_signal(SIGTERM,thi->task);

	if(wait) {
		down(&thi->mutex); // wait until thread has exited
		up(&thi->mutex);

		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(HZ / 10);
	}
}

int drbd_send_cmd(struct Drbd_Conf *mdev,Drbd_Packet_Cmd cmd, int via_msock)
{
	int err;
	Drbd_Packet head;

	head.command = cpu_to_be16(cmd);
	down( via_msock ? &mdev->msock_mutex : &mdev->sock_mutex);
	err = drbd_send(mdev, &head,sizeof(head),0,0,via_msock);
	up( via_msock ? &mdev->msock_mutex : &mdev->sock_mutex);

	return (err == sizeof(head));
}

int drbd_send_param(struct Drbd_Conf *mdev)
{
	Drbd_Parameter_Packet param;
	int err,i;
	kdev_t ll_dev = mdev->lo_device;

	param.h.u_size=cpu_to_be64(mdev->lo_usize);
	param.h.p_size=cpu_to_be64(ll_dev ? 
				   blk_size[MAJOR(ll_dev)][MINOR(ll_dev)]:0);

	param.p.command = cpu_to_be16(ReportParams);
	param.h.blksize = cpu_to_be32(1 << mdev->blk_size_b);
	param.h.state = cpu_to_be32(mdev->state);
	param.h.protocol = cpu_to_be32(mdev->conf.wire_protocol);
	param.h.version = cpu_to_be32(PRO_VERSION);

	for(i=Flags;i<=ArbitraryCnt;i++) {
		param.h.gen_cnt[i]=cpu_to_be32(mdev->gen_cnt[i]);
		param.h.bit_map_gen[i]=cpu_to_be32(mdev->bit_map_gen[i]);
	}

	down(&mdev->sock_mutex);
	err = drbd_send(mdev, (Drbd_Packet*)&param,sizeof(param),0,0,0);
	up(&mdev->sock_mutex);
	
	D_ASSERT(err == sizeof(param));

	return (err == sizeof(param));
}

int drbd_send_bitmap(struct Drbd_Conf *mdev)
{
	Drbd_Packet head;
	int ret,buf_i,want,bm_i=0;
	size_t bm_words;
	u32 *buffer,*bm;

	if(!mdev->mbds_id) return FALSE;

	bm_words=mdev->mbds_id->size/sizeof(u32);
	bm=(u32*)mdev->mbds_id->bm;
	buffer=vmalloc(MBDS_PACKET_SIZE);
	head.command = cpu_to_be16(ReportBitMap);

	while(1) {
		want=min_t(int,MBDS_PACKET_SIZE,(bm_words-bm_i)*sizeof(long));
		if(want==0) break;

		for(buf_i=0;buf_i<want/sizeof(long);buf_i++) {
			buffer[buf_i] = cpu_to_be32(bm[bm_i++]);
		}

		down(&mdev->sock_mutex);
		ret=drbd_send(mdev,&head,sizeof(head),buffer,want,0);
		up(&mdev->sock_mutex);
		if(ret != want + sizeof(head) ) {
			ret=FALSE;
			printk(KERN_ERR DEVICE_NAME 
			       "%d: short send ret=%d want=%d head=%d\n",
			       (int)(mdev-drbd_conf),
			       ret,want,(int)sizeof(head));
			goto out;
		}
	}

	ret=TRUE;
 out:
	vfree(buffer);
	return ret;
}

int _drbd_send_barrier(struct Drbd_Conf *mdev)
{
	int r;
        Drbd_Barrier_Packet head;

	/* tl_add_barrier() must be called with the sock_mutex aquired */
	head.p.command = cpu_to_be16(Barrier);
	head.h.barrier=tl_add_barrier(mdev); 

	/* printk(KERN_DEBUG DEVICE_NAME": issuing a barrier\n"); */
       
	r=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),0,0,0);

	inc_pending(mdev);

	return (r == sizeof(head));
}

int drbd_send_b_ack(struct Drbd_Conf *mdev, u32 barrier_nr,u32 set_size)
{
        Drbd_BarrierAck_Packet head;
	int ret;
       
	head.p.command = cpu_to_be16(BarrierAck);
        head.h.barrier = barrier_nr;
	head.h.set_size = cpu_to_be32(set_size);
	down(&mdev->msock_mutex);
	ret=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),0,0,1);
	up(&mdev->msock_mutex);
	return (ret == sizeof(head));
}


int drbd_send_ack(struct Drbd_Conf *mdev, int cmd, 
		  sector_t sector,u64 block_id)
{
        Drbd_BlockAck_Packet head;
	int ret;

	head.p.command = cpu_to_be16(cmd);
	head.h.sector = cpu_to_be64(sector);
        head.h.block_id = block_id;
	down(&mdev->msock_mutex);
	ret=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),0,0,1);
	up(&mdev->msock_mutex);
	return (ret == sizeof(head));
}

int drbd_send_drequest(struct Drbd_Conf *mdev, int cmd, 
		       sector_t sector, u64 block_id)
{
        Drbd_BlockRequest_Packet head;
	int ret;

	head.p.command = cpu_to_be16(cmd);
	head.h.sector = cpu_to_be64(sector);
        head.h.block_id = block_id;
	head.h.blksize = cpu_to_be32(1 << mdev->blk_size_b);

	down(&mdev->sock_mutex);
	ret=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),0,0,0);
	up(&mdev->sock_mutex);
	return (ret == sizeof(head));
}

int drbd_send_insync(struct Drbd_Conf *mdev,sector_t sector,u64 block_id)
{
	Drbd_Data_Packet head;
	int ret;

	head.p.command = cpu_to_be16(BlockInSync);
	head.h.sector = cpu_to_be64(sector);
	head.h.block_id = block_id;

	down(&mdev->sock_mutex);
	ret=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),0,0,0);
	up(&mdev->sock_mutex);

	return (ret == sizeof(head));
}

int drbd_send_dblock(struct Drbd_Conf *mdev, struct buffer_head *bh,
		     u64 block_id)
{
        Drbd_Data_Packet head;
	int ret,ok;

	head.p.command = cpu_to_be16(Data);
	head.h.sector = cpu_to_be64(bh->b_rsector);
	head.h.block_id = block_id;

	down(&mdev->sock_mutex);
	
	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
	        _drbd_send_barrier(mdev);
	}
	
	ret=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),bh_kmap(bh),
		      bh->b_size,0);
	bh_kunmap(bh);
	ok=(ret == bh->b_size + sizeof(head));

	if( ok ) {
		mdev->send_cnt+=bh->b_size>>9;
		/* This must be within the semaphore */
		//UGGLY UGGLY casting it back to a drbd_request_t
		tl_add(mdev,(drbd_request_t*)(unsigned long)block_id);
	}

	up(&mdev->sock_mutex);

	return ok;  
}

int drbd_send_block(struct Drbd_Conf *mdev, int cmd, struct buffer_head *bh, 
		    u64 block_id)
{
        Drbd_Data_Packet head;
	int ret,ok;

	head.p.command = cpu_to_be16(cmd);
	head.h.sector = cpu_to_be64(bh->b_rsector);
	head.h.block_id = block_id;

	down(&mdev->sock_mutex);
	
	ret=drbd_send(mdev,(Drbd_Packet*)&head,sizeof(head),bh_kmap(bh),
		      bh->b_size,0);
	bh_kunmap(bh);
	ok=(ret == bh->b_size + sizeof(head));

	up(&mdev->sock_mutex);

	if( ok ) mdev->send_cnt+=bh->b_size>>9;

	return ok;
}

STATIC void drbd_timeout(unsigned long arg)
{
	struct send_timer_info *ti = (struct send_timer_info *) arg;
	//	int i;

	if(ti->via_msock) {
		printk(KERN_ERR DEVICE_NAME"%d: sock_sendmsg time expired"
		       " on msock\n",
		       (int)(ti->mdev-drbd_conf));

		ti->timeout_happened=1;
		drbd_queue_signal(DRBD_SIG, ti->task);
		spin_lock(&ti->mdev->send_proc_lock);		
		if((ti=ti->mdev->send_proc)) {
			ti->timeout_happened=1;
			drbd_queue_signal(DRBD_SIG, ti->task);
		}
		spin_unlock(&ti->mdev->send_proc_lock);		
	} else {
		/*
		printk(KERN_ERR DEVICE_NAME"%d: sock_sendmsg time expired"
		       " (pid=%d) requesting ping\n",
		       (int)(ti->mdev-drbd_conf),ti->task->pid);
		*/
		set_bit(SEND_PING,&ti->mdev->flags);
		drbd_queue_signal(DRBD_SIG, ti->mdev->asender.task);

		if(ti->restart) {
			ti->s_timeout.expires = jiffies +
				(ti->mdev->conf.timeout * HZ / 10);
			add_timer(&ti->s_timeout);
		}
	}
}

STATIC void drbd_a_timeout(unsigned long arg)
{
	struct Drbd_Conf *mdev = (struct Drbd_Conf *) arg;

	/*
	printk(KERN_ERR DEVICE_NAME "%d: ack timeout detected (pc=%d)"
	       " requesting ping\n",
	       (int)(mdev-drbd_conf),atomic_read(&mdev->pending_cnt));
	*/
	set_bit(SEND_PING,&mdev->flags);
	drbd_queue_signal(DRBD_SIG, mdev->asender.task);
}

/*
  drbd_send distinqushes two cases:

  Packets sent via the data socket "sock"
  and packets sent via the meta data socket "msock"

                    sock                      msock
  -----------------+-------------------------+------------------------------
  timeout           conf.timeout              avg round trip time(artt) x 4
  timeout action    send a ping via msock     Abort communication
                                              and close all sockets
*/
int drbd_send(struct Drbd_Conf *mdev, Drbd_Packet* header, size_t header_size,
	      void* data, size_t data_size, int via_msock)
{
	mm_segment_t oldfs;
	sigset_t oldset;
	struct msghdr msg;
	struct iovec iov[2];
	unsigned long flags;
	int rv,sent=0;
	int app_got_sig=0;
	struct send_timer_info ti;
	struct socket *sock = via_msock ? mdev->msock : mdev->sock;
	
	if (!sock) return -1000;
	if (mdev->cstate < WFReportParams) return -1001;

	header->magic  =  cpu_to_be32(DRBD_MAGIC);
	header->length  = cpu_to_be16(data_size);

	sock->sk->allocation = GFP_DRBD;

	iov[0].iov_base = header;
	iov[0].iov_len = header_size;
	iov[1].iov_base = data;
	iov[1].iov_len = data_size;

	msg.msg_iov = iov;
	msg.msg_iovlen = data_size > 0 ? 2 : 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_name = 0;
	msg.msg_namelen = 0;
	msg.msg_flags = MSG_NOSIGNAL;

	ti.mdev=mdev;
	ti.timeout_happened=0;
	ti.via_msock=via_msock;
	ti.task=current;
	ti.restart=1;
	if(!via_msock) {
		spin_lock(&mdev->send_proc_lock); 
		mdev->send_proc=&ti; 
		spin_unlock(&mdev->send_proc_lock);		
	}

	if (mdev->conf.timeout) {
		init_timer(&ti.s_timeout);
		ti.s_timeout.function = drbd_timeout;
		ti.s_timeout.data = (unsigned long) &ti;
		ti.s_timeout.expires = jiffies + mdev->conf.timeout*HZ/20;
		add_timer(&ti.s_timeout);
	}

	lock_kernel();  //  check if this is still necessary
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	spin_lock_irqsave(&current->sigmask_lock, flags);
	oldset = current->blocked;
	sigfillset(&current->blocked);
	sigdelset(&current->blocked,DRBD_SIG); 
	recalc_sigpending(current);
	spin_unlock_irqrestore(&current->sigmask_lock, flags);

	while(1) {
		rv = sock_sendmsg(sock, &msg, header_size+data_size);
		if ( rv == -ERESTARTSYS) {
			spin_lock_irqsave(&current->sigmask_lock,flags);
			if (sigismember(&current->pending.signal, DRBD_SIG)) {
				sigdelset(&current->pending.signal, DRBD_SIG);
				recalc_sigpending(current);
				spin_unlock_irqrestore(&current->sigmask_lock,
						       flags);
				if(ti.timeout_happened) {
					break;
				} else {
					app_got_sig=1;
					continue;
				}
			}
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
		}
		if (rv <= 0) break;
		sent += rv;
		if (sent == header_size+data_size) break;

		/*printk(KERN_ERR DEVICE_NAME
		       "%d: calling sock_sendmsg again\n",
		       (int)(mdev-drbd_conf));*/

		if( rv < header_size ) {
			iov[0].iov_base += rv;
			iov[0].iov_len  -= rv;
			header_size -= rv;
		} else /* rv >= header_size */ {
			if (header_size) {
				iov[0].iov_base = iov[1].iov_base;
				iov[0].iov_len = iov[1].iov_len;
				msg.msg_iovlen = 1;
				rv -= header_size;
				header_size = 0;
			}
			iov[0].iov_base += rv;
			iov[0].iov_len  -= rv;
			data_size -= rv;
		}
	}

	set_fs(oldfs);
	unlock_kernel();

	ti.restart=0;

	if (mdev->conf.timeout) {
		del_timer_sync(&ti.s_timeout);
	}

	if(!via_msock) {
		spin_lock(&mdev->send_proc_lock);		
		mdev->send_proc=NULL;
		spin_unlock(&mdev->send_proc_lock);		
	}


	spin_lock_irqsave(&current->sigmask_lock, flags);
	current->blocked = oldset;
	if(app_got_sig) {
		sigaddset(&current->pending.signal, DRBD_SIG);
	} else {
		sigdelset(&current->pending.signal, DRBD_SIG);
	}
	recalc_sigpending(current);
	spin_unlock_irqrestore(&current->sigmask_lock, flags);

	if (/*rv == -ERESTARTSYS &&*/ ti.timeout_happened) {
		printk(KERN_DEBUG DEVICE_NAME
		       "%d: send timed out!! (pid=%d)\n",
		       (int)(mdev-drbd_conf),current->pid);

		set_cstate(mdev,Timeout);
		
		drbd_thread_restart_nowait(&mdev->receiver);
		
		return -1002;
	}

	if (rv <= 0) {
		printk(KERN_ERR DEVICE_NAME "%d: sock_sendmsg returned %d\n",
		       (int)(mdev-drbd_conf),rv);

		set_cstate(mdev,BrokenPipe);
		drbd_thread_restart_nowait(&mdev->receiver);	  
	}

	return sent;
}

STATIC int drbd_open(struct inode *inode, struct file *file)
{
	int minor;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;

	if (file->f_mode & FMODE_WRITE) {
		if( drbd_conf[minor].state == Secondary) {
			return -EROFS;
		}
		set_bit(WRITER_PRESENT, &drbd_conf[minor].flags);
	}

	drbd_conf[minor].open_cnt++;

	MOD_INC_USE_COUNT;

	return 0;
}

STATIC int drbd_close(struct inode *inode, struct file *file)
{
	/* do not use *file (May be NULL, in case of a unmount :-) */
	int minor;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;

	/*
	printk(KERN_ERR DEVICE_NAME ": close(inode=%p,file=%p)"
	       "current=%p,minor=%d,wc=%d\n", inode, file, current, minor,
	       inode->i_writecount);
	*/

	if (--drbd_conf[minor].open_cnt == 0) {
		clear_bit(WRITER_PRESENT, &drbd_conf[minor].flags);
	}

	MOD_DEC_USE_COUNT;

	return 0;
}

STATIC void drbd_send_write_hint(void *data)
{
	struct Drbd_Conf* mdev = (struct Drbd_Conf*)data;
	int i;

	/* In case the receiver calls run_task_queue(&tq_disk) itself,
	   in order to flush blocks to the ll_dev (for a device in
	   secondary state), it could happen that it has to send the
 	   WRITE_HINT for an other device (which is in primary state). 
	   This could lead to a distributed deadlock!!

	   To avoid the deadlock we requeue the WRITE_HINT. */

	for (i = 0; i < minor_count; i++) {
		if(current == drbd_conf[i].receiver.task) {
			queue_task(&mdev->write_hint_tq, &tq_disk);
			return;
		}
	}
       
	drbd_send_cmd(mdev,WriteHint,0);
	clear_bit(WRITE_HINT_QUEUED, &mdev->flags);
}

int __init drbd_init(void)
{

	int i;
	drbd_proc = create_proc_read_entry("drbd", 0, &proc_root,
					   drbd_proc_get_info, NULL);
	if (!drbd_proc)	{
		printk(KERN_ERR DEVICE_NAME": unable to register proc file\n");
		return -EIO;
	}

	drbd_proc->owner = THIS_MODULE;

	if (register_blkdev(MAJOR_NR, DEVICE_NAME, &drbd_ops)) {

		printk(KERN_ERR DEVICE_NAME ": Unable to get major %d\n",
		       MAJOR_NR);

		if (drbd_proc) remove_proc_entry("drbd", &proc_root);

		return -EBUSY;
	}


#ifdef CONFIG_DEVFS_FS
	devfs_handle = devfs_mk_dir (NULL, "nbd", NULL);
	devfs_register_series(devfs_handle, "%u", minor_count,
			      DEVFS_FL_DEFAULT, MAJOR_NR, 0,
			      S_IFBLK | S_IRUSR | S_IWUSR,
		     	      &drbd_ops, NULL);
# endif

	drbd_blocksizes = kmalloc(sizeof(int)*minor_count,GFP_KERNEL);
	drbd_sizes = kmalloc(sizeof(int)*minor_count,GFP_KERNEL);
	drbd_conf = kmalloc(sizeof(struct Drbd_Conf)*minor_count,GFP_KERNEL);

	/* Initialize size arrays. */

	for (i = 0; i < minor_count; i++) {
		drbd_conf[i].sync_conf.rate=250;
		drbd_conf[i].sync_conf.use_csums=0;
		drbd_conf[i].sync_conf.skip=0;
		drbd_blocksizes[i] = INITIAL_BLOCK_SIZE;
		drbd_conf[i].blk_size_b = drbd_log2(INITIAL_BLOCK_SIZE);
		drbd_sizes[i] = 0;
		set_device_ro(MKDEV(MAJOR_NR, i), TRUE );
		drbd_conf[i].do_panic = 0;
		drbd_conf[i].sock = 0;
		drbd_conf[i].msock = 0;
		drbd_conf[i].lo_file = 0;
		drbd_conf[i].lo_device = 0;
		drbd_conf[i].lo_usize = 0;
		drbd_conf[i].state = Secondary;
		init_waitqueue_head(&drbd_conf[i].state_wait);
		drbd_conf[i].o_state = Unknown;
		drbd_conf[i].la_size = 0;
		drbd_conf[i].cstate = Unconfigured;
		drbd_conf[i].send_cnt = 0;
		drbd_conf[i].recv_cnt = 0;
		drbd_conf[i].writ_cnt = 0;
		drbd_conf[i].read_cnt = 0;
		atomic_set(&drbd_conf[i].pending_cnt,0);
		atomic_set(&drbd_conf[i].unacked_cnt,0);
		drbd_conf[i].mbds_id = 0;
 		/* If the WRITE_HINT_QUEUED flag is set but it is not
 		   actually queued the functionality is completely disabled */
 		if(disable_io_hints) drbd_conf[i].flags=WRITE_HINT_QUEUED;
 		else drbd_conf[i].flags=0;
		drbd_conf[i].rs_total=0;
		//drbd_conf[i].rs_left=0;
		//drbd_conf[i].rs_start=0;
		//drbd_conf[i].rs_mark_left=0;
		//drbd_conf[i].rs_mark_time=0;
		drbd_conf[i].rs_lock = SPIN_LOCK_UNLOCKED;
		tl_init(&drbd_conf[i]);
		drbd_conf[i].a_timeout.function = drbd_a_timeout;
		drbd_conf[i].a_timeout.data = (unsigned long)(drbd_conf+i);
		init_timer(&drbd_conf[i].a_timeout);
		init_MUTEX(&drbd_conf[i].sock_mutex);
		init_MUTEX(&drbd_conf[i].msock_mutex);
 		init_MUTEX(&drbd_conf[i].ctl_mutex);
		drbd_conf[i].send_proc=NULL;
		drbd_conf[i].send_proc_lock = SPIN_LOCK_UNLOCKED;
		drbd_thread_init(i, &drbd_conf[i].receiver, drbdd_init);
		drbd_thread_init(i, &drbd_conf[i].dsender, drbd_dsender);
		drbd_thread_init(i, &drbd_conf[i].asender, drbd_asender);
		init_waitqueue_head(&drbd_conf[i].dsender_wait);
		drbd_conf[i].tl_lock = SPIN_LOCK_UNLOCKED;
		drbd_conf[i].ee_lock = SPIN_LOCK_UNLOCKED;
		drbd_conf[i].req_lock = SPIN_LOCK_UNLOCKED;
		drbd_conf[i].bb_lock = SPIN_LOCK_UNLOCKED;
		drbd_conf[i].pr_lock = SPIN_LOCK_UNLOCKED;
		init_waitqueue_head(&drbd_conf[i].cstate_wait);
		drbd_conf[i].open_cnt = 0;
		drbd_conf[i].epoch_size=0;
		drbd_conf[i].send_sector=-1;
		INIT_LIST_HEAD(&drbd_conf[i].free_ee);
		INIT_LIST_HEAD(&drbd_conf[i].active_ee);
		INIT_LIST_HEAD(&drbd_conf[i].sync_ee);
		INIT_LIST_HEAD(&drbd_conf[i].done_ee);
		INIT_LIST_HEAD(&drbd_conf[i].read_ee);
		INIT_LIST_HEAD(&drbd_conf[i].rdone_ee);
		INIT_LIST_HEAD(&drbd_conf[i].busy_blocks);
		INIT_LIST_HEAD(&drbd_conf[i].app_reads);
		INIT_LIST_HEAD(&drbd_conf[i].resync_reads);
		drbd_conf[i].ee_vacant=0;
		drbd_conf[i].ee_in_use=0;
		drbd_init_ee(drbd_conf+i);
		init_waitqueue_head(&drbd_conf[i].ee_wait);
		drbd_conf[i].write_hint_tq.sync	= 0;
		drbd_conf[i].write_hint_tq.routine = &drbd_send_write_hint;
		drbd_conf[i].write_hint_tq.data = drbd_conf+i;

		{
			int j;
			for(j=0;j<=ArbitraryCnt;j++) drbd_conf[i].gen_cnt[j]=0;
			for(j=0;j<=ArbitraryCnt;j++) 
				drbd_conf[i].bit_map_gen[j]=0;
#ifdef ES_SIZE_STATS
			for(j=0;j<ES_SIZE_STATS;j++) drbd_conf[i].essss[j]=0;
#endif  
		}
	}

	blk_queue_make_request(BLK_DEFAULT_QUEUE(MAJOR_NR),drbd_make_request);
	/*   blk_init_queue(BLK_DEFAULT_QUEUE(MAJOR_NR), NULL); */

	blksize_size[MAJOR_NR] = drbd_blocksizes;
	blk_size[MAJOR_NR] = drbd_sizes;	/* Size in Kb */

	return 0;
}

int __init init_module()
{
	printk(KERN_INFO DEVICE_NAME ": initialised. "
	       "Version: " REL_VERSION " (api:%d/proto:%d)\n",
	       API_VERSION,PRO_VERSION);

	return drbd_init();

}

void cleanup_module()
{
	int i;

#ifdef CONFIG_DEVFS_FS
	devfs_unregister(devfs_handle);
#endif

	for (i = 0; i < minor_count; i++) {
		drbd_set_state(i,Secondary);
		fsync_dev(MKDEV(MAJOR_NR, i));
		set_bit(DO_NOT_INC_CONCNT,&drbd_conf[i].flags);
		drbd_thread_stop(&drbd_conf[i].dsender);
		drbd_thread_stop(&drbd_conf[i].receiver);
		drbd_thread_stop(&drbd_conf[i].asender);
		drbd_free_resources(i);
		tl_cleanup(drbd_conf+i);
		if (drbd_conf[i].mbds_id) bm_cleanup(drbd_conf[i].mbds_id);
		// free the receiver's stuff

		drbd_release_ee(drbd_conf+i,&drbd_conf[i].free_ee);
		if(drbd_release_ee(drbd_conf+i,&drbd_conf[i].active_ee) || 
		   drbd_release_ee(drbd_conf+i,&drbd_conf[i].sync_ee)   ||
		   drbd_release_ee(drbd_conf+i,&drbd_conf[i].done_ee) ) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: EEs in active/sync/done list found!\n",i);
		}
	}

	if (unregister_blkdev(MAJOR_NR, DEVICE_NAME) != 0)
		printk(KERN_ERR DEVICE_NAME": unregister of device failed\n");


	blksize_size[MAJOR_NR] = NULL;
	blk_size[MAJOR_NR] = NULL;

	if (drbd_proc)
		remove_proc_entry("drbd", &proc_root);

	kfree(drbd_blocksizes);
	kfree(drbd_sizes);
	kfree(drbd_conf);
}



void drbd_free_ll_dev(int minor)
{
	if (drbd_conf[minor].lo_file) {
		blkdev_put(drbd_conf[minor].lo_file->f_dentry->d_inode->i_bdev,
			   BDEV_FILE);

		fput(drbd_conf[minor].lo_file);
		drbd_conf[minor].lo_file = 0;
		drbd_conf[minor].lo_device = 0;
	}
}

void drbd_free_sock(int minor)
{
	if (drbd_conf[minor].sock) {
		sock_release(drbd_conf[minor].sock);
		drbd_conf[minor].sock = 0;
	}
	if (drbd_conf[minor].msock) {
		sock_release(drbd_conf[minor].msock);
		drbd_conf[minor].msock = 0;
	}

}


void drbd_free_resources(int minor)
{
	drbd_free_sock(minor);
	drbd_free_ll_dev(minor);
}

/*********************************/

/*** The bitmap stuff. ***/
/*
  We need to store one bit for a block. 
  Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
  Bit 0 ==> Primary and secondary nodes are in sync.
  Bit 1 ==> secondary node's block must be updated. (')

  A wicked bug was found and pointed out by 
                     Guzovsky, Eduard <EGuzovsky@crossbeamsys.com>
*/


// Shift right with round up. :)
#define SR_RU(A,B) ( ((A)>>(B)) + ( ((A) & ((1<<(B))-1)) > 0 ? 1 : 0 ) )

int bm_resize(struct BitMap* sbm, unsigned long size_kb)
{
        unsigned long *obm,*nbm;
	unsigned long size;
	
	if(!sbm) return 1; // Nothing to do 

	size = SR_RU(size_kb,(BM_BLOCK_SIZE_B - (10-LN2_BPL))) << (LN2_BPL-3);
	/* 10 => blk_size is KB ; 3 -> 2^3=8 Bits per Byte */
	// Calculate the number of long words needed, round it up, and
	// finally convert it to bytes.

	if(size == 0) return 0;

	obm = sbm->bm;
	nbm = vmalloc(size);
	if(!nbm) {
		printk(KERN_ERR DEVICE_NAME"X: Failed to allocate BitMap\n");
		return 0;
	}
	memset(nbm,0,size);

 	spin_lock(&sbm->bm_lock);
	if(obm) {
		memcpy(nbm,obm,min_t(unsigned long,sbm->size,size));
	}
	sbm->size = size;
	sbm->bm = nbm;
	spin_unlock(&sbm->bm_lock);

	if(obm) vfree(obm);

	return 1;
}

struct BitMap* bm_init(kdev_t dev)
{
        struct BitMap* sbm;

	sbm = kmalloc(sizeof(struct BitMap),GFP_KERNEL);
	if(!sbm) {
		printk(KERN_ERR DEVICE_NAME"X: Failed to allocate BM desc\n");
		return 0;
	}

	sbm->dev = dev;
	sbm->sb_bitnr=0;
	sbm->sb_mask=0;
	sbm->gb_bitnr=0;
	sbm->gb_snr=0;
	sbm->bm_lock = SPIN_LOCK_UNLOCKED;

	sbm->size = 0;
	sbm->bm = NULL;

	if(!bm_resize(sbm,blk_size[MAJOR(dev)][MINOR(dev)])) {
		kfree(sbm);
		return 0;
	}

	return sbm;
}     

void bm_cleanup(struct BitMap* sbm)
{
        vfree(sbm->bm);
	kfree(sbm);
}

#define BM_SS (BM_BLOCK_SIZE_B-9)
#define BM_MM ((1L<<CB)-1)


/* secot_t and size have a higher resolution (512 Byte) than
   the bitmap (4K). In case we have to set a bit, we 'round up',
   in case we have to clear a bit we do the opposit. */
void bm_set_bit(struct BitMap* sbm, sector_t sector, int size, int bit)
{
        unsigned long* bm;
	unsigned long sbnr,ebnr,bnr;
	int ret=0;
	sector_t esector = ( sector + (size>>9) - 1 );


	if(sbm == NULL) {
		printk(KERN_ERR DEVICE_NAME"X: You need to specify the "
		       "device size!\n");
		return 0;
	}

 	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;
	sbnr = sector >> CM_SS;
	ebnr = esector >> CM_SS;

	if(bit) {
		for(bnr=sbnr; bnr <= ebnr; bnr++) {
			bm[bnr>>LN2_BPL] |= ( 1L << (bnr & ((1L<<LN2_BPL)-1)));
		}
	} else { // bit == 0
		if(  sector & BM_MM   != 0 )     sbnr++;
		if( (esector & BM_MM) != BM_MM ) ebnr--;

		for(bnr=sbnr; bnr <= ebnr; bnr++) {
			bm[bnr>>LN2_BPL]&= ~( 1L << (bnr & ((1L<<LN2_BPL)-1)));
		}
	}
 	spin_unlock(&sbm->bm_lock);
}

// bm_get_bit is still broken....

int bm_get_bit(struct BitMap* sbm, sector_t sector)
{
        unsigned long* bm;
	unsigned long bitnr;
	int bit;

	if(sbm == NULL) {
		printk(KERN_ERR DEVICE_NAME"X: You need to specify the "
		       "device size!\n");
		return 0;
	}

 	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;
	bitnr = blocknr >> CM_SS;

	bit=(bm[bitnr>>LN2_BPL]&( 1L << (bitnr & ((1L<<LN2_BPL)-1)))) ? 1 : 0;
	spin_unlock(&sbm->bm_lock);
				     
	return bit;
}

static inline int bm_get_bn(unsigned long word,int nr)
{
	if(nr == BITS_PER_LONG-1) return -1;
	word >>= ++nr;
	while (! (word & 1)) {
                word >>= 1;
		if (++nr == BITS_PER_LONG) return -1;
	}
	return nr;
}

sector_t bm_get_sector(struct BitMap* sbm,int ln2_block_size)
{
        unsigned long* bm;
	unsigned long wnr;
	unsigned long nw = sbm->size/sizeof(unsigned long);
	unsigned long rv;
	int cb = (BM_BLOCK_SIZE_B-ln2_block_size);

 	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;

	if(sbm->gb_snr >= (1L<<cb)) {	  
		for(wnr=sbm->gb_bitnr>>LN2_BPL;wnr<nw;wnr++) {
	                if (bm[wnr]) {
				int bnr;
				if (wnr == sbm->gb_bitnr>>LN2_BPL)
					bnr = sbm->gb_bitnr & ((1<<LN2_BPL)-1);
				else bnr = -1;
				bnr = bm_get_bn(bm[wnr],bnr);
				if (bnr == -1) continue; 
			        sbm->gb_bitnr = (wnr<<LN2_BPL) + bnr;
				sbm->gb_snr = 0;
				goto out;
			}
		}
		rv = MBDS_DONE;
		goto r_out;
	}
 out:
	rv = (sbm->gb_bitnr<<cb) + sbm->gb_snr++;

	// Since the bitmap has to have more bits than the device blocks,
	// we must ensure not to return a blocknumbe bejond end of device.
	if( (rv+1)*(1<<(ln2_block_size-10)) > 
	    blk_size[MAJOR(sbm->dev)][MINOR(sbm->dev)] ) rv = MBDS_DONE;
 r_out:
 	spin_unlock(&sbm->bm_lock);	
	return rv << (ln2_block_size-9);
}

void bm_reset(struct BitMap* sbm,int ln2_block_size)
{
 	spin_lock(&sbm->bm_lock);

	sbm->gb_bitnr=0;
	if (sbm->bm[0] & 1) sbm->gb_snr=0;
	else sbm->gb_snr = 1L<<(BM_BLOCK_SIZE_B-ln2_block_size);

 	spin_unlock(&sbm->bm_lock);	
}

void bm_fill_bm(struct BitMap* sbm,int value)
{
 	spin_lock(&sbm->bm_lock);

	memset(sbm->bm,value,sbm->size);

 	spin_unlock(&sbm->bm_lock);		
}

/*********************************/
/* meta data management */

struct meta_data_on_disk {
	__u64 la_size;           // last agreed size.
	__u32 gc[GEN_CNT_SIZE];  // generation counter
	__u32 magic;      
};

void drbd_md_write(struct Drbd_Conf *mdev)
{
	struct meta_data_on_disk buffer;
	__u32 flags;
	mm_segment_t oldfs;
	struct inode* inode;
	struct file* fp;
	char fname[25];
	int i;

	flags=mdev->gen_cnt[Flags] & 
		~(MDF_PrimaryInd|MDF_ConnectedInd);
	if(mdev->state==Primary) flags |= MDF_PrimaryInd;
	if(mdev->cstate>=WFReportParams) flags |= MDF_ConnectedInd;
	mdev->gen_cnt[Flags]=flags;
	
	for(i=Flags;i<=ArbitraryCnt;i++) 
		buffer.gc[i]=cpu_to_be32(mdev->gen_cnt[i]);
	buffer.la_size=cpu_to_be64(blk_size[MAJOR_NR][(int)(mdev-drbd_conf)]);
	buffer.magic=cpu_to_be32(DRBD_MD_MAGIC);
	
	sprintf(fname,DRBD_MD_FILES,(int)(mdev-drbd_conf));
	fp=filp_open(fname,O_WRONLY|O_CREAT|O_TRUNC|O_SYNC,00600);
	if(IS_ERR(fp)) goto err;
        oldfs = get_fs();
        set_fs(get_ds());
	inode = fp->f_dentry->d_inode;
	i=fp->f_op->write(fp,(const char*)&buffer,sizeof(buffer),&fp->f_pos);
	set_fs(oldfs);
	filp_close(fp,NULL);
	if (i==sizeof(buffer)) return;
 err:
	printk(KERN_ERR DEVICE_NAME "%d: Error writing state file\n\"%s\"\n",
	       (int)(mdev-drbd_conf),fname);
	return;
}

void drbd_md_read(struct Drbd_Conf *mdev)
{
	struct meta_data_on_disk buffer;
	mm_segment_t oldfs;
	struct inode* inode;
	struct file* fp;
	char fname[25];
	int i;		

	sprintf(fname,DRBD_MD_FILES,(int)(mdev-drbd_conf));
	fp=filp_open(fname,O_RDONLY,0);
	if(IS_ERR(fp)) goto err;
        oldfs = get_fs();
        set_fs(get_ds());
	inode = fp->f_dentry->d_inode;
	i=fp->f_op->read(fp,(char*)&buffer,sizeof(buffer),&fp->f_pos);
	set_fs(oldfs);
	filp_close(fp,NULL);

	if(i != sizeof(buffer)) goto err;
	if(be32_to_cpu(buffer.magic) != DRBD_MD_MAGIC) goto err;
	for(i=Flags;i<=ArbitraryCnt;i++) 
		mdev->gen_cnt[i]=be32_to_cpu(buffer.gc[i]);
	mdev->la_size = be64_to_cpu(buffer.la_size);
	return;
 err:
	printk(KERN_INFO DEVICE_NAME "%d: Creating state file\n\"%s\"\n",
	       (int)(mdev-drbd_conf),fname);
	for(i=HumanCnt;i<=ArbitraryCnt;i++) mdev->gen_cnt[i]=1;
	mdev->gen_cnt[Flags]=MDF_Consistent;
	drbd_md_write(mdev);
	return;
}


/* Returns  1 if I have the good bits,
            0 if both are nice
	   -1 if the partner has the good bits.
*/
int drbd_md_compare(int minor,Drbd_Parameter_P* partner)
{
	int i;
	u32 me,other;
	
	me=drbd_conf[minor].gen_cnt[Flags] & MDF_Consistent;
	other=be32_to_cpu(partner->gen_cnt[Flags]) & MDF_Consistent;
	if( me > other ) return 1;
	if( me < other ) return -1;

	for(i=HumanCnt;i<=ArbitraryCnt;i++) {
		me=drbd_conf[minor].gen_cnt[i];
		other=be32_to_cpu(partner->gen_cnt[i]);
		if( me > other ) return 1;
		if( me < other ) return -1;
	}

	me=drbd_conf[minor].gen_cnt[Flags] & MDF_PrimaryInd;
	other=be32_to_cpu(partner->gen_cnt[Flags]) & MDF_PrimaryInd;
	if( me > other ) return 1;
	if( me < other ) return -1;

	return 0;
}

/* Returns  1 if SyncingQuick is sufficient
            0 if SyncAll is needed.
*/
int drbd_md_syncq_ok(int minor,Drbd_Parameter_P* partner,int i_am_pri)
{
	int i;
	u32 me,other;

	me=drbd_conf[minor].gen_cnt[Flags];
	other=be32_to_cpu(partner->gen_cnt[Flags]);
	// crash during sync forces SyncAll:
	if( (i_am_pri && !(other & MDF_Consistent) ) ||
	    (!i_am_pri && !(me & MDF_Consistent) ) ) return 0;

	// primary crash forces SyncAll:
	if( (i_am_pri && (other & MDF_PrimaryInd) ) ||
	    (!i_am_pri && (me & MDF_PrimaryInd) ) ) return 0;

	// If partner's GC not equal our bitmap's GC force SyncAll
	if( i_am_pri ) {
		for(i=HumanCnt;i<=ArbitraryCnt;i++) {
			me=drbd_conf[minor].bit_map_gen[i];
			other=be32_to_cpu(partner->gen_cnt[i]);
			if( me != other ) return 0;
		}
	} else { // !i_am_pri 
		for(i=HumanCnt;i<=ArbitraryCnt;i++) {
			me=drbd_conf[minor].gen_cnt[i];
			other=be32_to_cpu(partner->bit_map_gen[i]);
			if( me != other ) return 0;
		}
	}

	// SyncQuick sufficient
	return 1;
}

void drbd_md_inc(int minor, enum MetaDataIndex order)
{
	drbd_conf[minor].gen_cnt[order]++;
}

void drbd_queue_signal(int signal,struct task_struct *task)
{
	unsigned long flags;

  	read_lock(&tasklist_lock);
	if (task) {
		spin_lock_irqsave(&task->sigmask_lock, flags);
		sigaddset(&task->pending.signal, signal);
		recalc_sigpending(task);
		spin_unlock_irqrestore(&task->sigmask_lock, flags);
		if (task->state & TASK_INTERRUPTIBLE) wake_up_process(task);
	}
	read_unlock(&tasklist_lock);
}

