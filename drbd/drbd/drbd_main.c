/*
-*- Linux-c -*-
   drbd.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

   Copyright (C) 2003, Lars Ellenberg <l.g.e@web.de>.
	main contributor.

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

#if defined(CONFIG_PPC64) || defined(CONFIG_SPARC64) || defined(CONFIG_X86_64)
extern int register_ioctl32_conversion(unsigned int cmd,
				       int (*handler)(unsigned int,
						      unsigned int,
						      unsigned long,
						      struct file *));
extern int unregister_ioctl32_conversion(unsigned int cmd);
extern asmlinkage int sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
#endif

#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#include "drbd.h"
#include "drbd_int.h"

#ifdef CONFIG_DEVFS_FS
#include <linux/devfs_fs_kernel.h>
static devfs_handle_t devfs_handle;
#endif

int drbdd_init(struct Drbd_thread*);
int drbd_dsender(struct Drbd_thread*);
int drbd_asender(struct Drbd_thread*);

int drbd_init(void);
STATIC int drbd_open(struct inode *inode, struct file *file);
STATIC int drbd_close(struct inode *inode, struct file *file);

STATIC int drbd_send(drbd_dev*,struct socket*,void*,size_t,unsigned);

#ifdef DEVICE_REQUEST
#undef DEVICE_REQUEST
#endif
#define DEVICE_REQUEST drbd_do_request

MODULE_AUTHOR("Philipp Reisner <philipp.reisner@gmx.at>");
MODULE_DESCRIPTION("drbd - Distributed Replicated Block Device v" REL_VERSION);
MODULE_LICENSE("GPL");
MODULE_PARM(minor_count,"i");
MODULE_PARM(disable_io_hints,"i");
MODULE_PARM_DESC(minor_count, "Maximum number of drbd devices (1-255)");
MODULE_PARM_DESC(disable_io_hints, "Necessary if loopback devices are used for DRBD" );

// module parameter, defined
int minor_count = 2;
int disable_io_hints = 0;

STATIC int *drbd_blocksizes;
STATIC int *drbd_sizes;
struct Drbd_Conf *drbd_conf;
kmem_cache_t *drbd_request_cache;
kmem_cache_t *drbd_pr_cache;
kmem_cache_t *drbd_ee_cache;
mempool_t *drbd_request_mempool;
mempool_t *drbd_pr_mempool;

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
STATIC void tl_init(drbd_dev *mdev)
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

STATIC void tl_cleanup(drbd_dev *mdev)
{
	D_ASSERT(mdev->oldest_barrier == mdev->newest_barrier);
	kfree(mdev->oldest_barrier);
}

STATIC void tl_add(drbd_dev *mdev, drbd_request_t * new_item)
{
	struct drbd_barrier *b;

	spin_lock_irq(&mdev->tl_lock);

	b=mdev->newest_barrier;

	new_item->sector = new_item->bh->b_rsector;
	new_item->size = new_item->bh->b_size;
	new_item->barrier = b;
	list_add(&new_item->list,&b->requests);

	if( b->n_req++ > mdev->conf.max_epoch_size ) {
		set_bit(ISSUE_BARRIER,&mdev->flags);
	}

	spin_unlock_irq(&mdev->tl_lock);
}

STATIC unsigned int tl_add_barrier(drbd_dev *mdev)
{
	unsigned int bnr;
	static int barrier_nr_issue=1;
	struct drbd_barrier *b;

	barrier_nr_issue++;

	// THINK this is called in the IO path with the send_mutex held
	// and GFP_KERNEL may itself start IO. set it to GFP_NOIO.
	b=kmalloc(sizeof(struct drbd_barrier),GFP_NOIO);
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

void tl_release(drbd_dev *mdev,unsigned int barrier_nr,
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
/* bool */
int tl_dependence(drbd_dev *mdev, drbd_request_t * item)
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
/* bool */
int tl_check_sector(drbd_dev *mdev, sector_t sector)
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

void tl_clear(drbd_dev *mdev)
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
				drbd_end_req(r,RQ_DRBD_SENT,ERF_NOTLD|1,
					     r->sector);
				goto mark;
			}
			if(mdev->conf.wire_protocol != DRBD_PROT_C ) {
			mark:
				drbd_set_out_of_sync(mdev,r->sector,r->size);
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
	set_bit(COLLECT_ZOMBIES,&(thi->mdev->flags));
	up(&thi->mutex); //allow thread_stop to proceed

	return retval;
}

STATIC void drbd_thread_init(drbd_dev *mdev, struct Drbd_thread *thi,
		      int (*func) (struct Drbd_thread *))
{
	thi->task = NULL;
	init_MUTEX(&thi->mutex);
	thi->function = func;
	thi->mdev = mdev;
}

void drbd_thread_start(struct Drbd_thread *thi)
{
	int pid;
	drbd_dev *mdev = thi->mdev;

	if (thi->task == NULL) {
		thi->t_state = Running;

		down(&thi->mutex);
		pid = kernel_thread(drbd_thread_setup, (void *) thi, CLONE_FS);

		if (pid < 0) {
			ERR("Couldn't start thread (%d)\n", pid);
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
	if (thi->task->state == -1
	    || thi->task->state == TASK_ZOMBIE
	    || thi->task->flags & PF_EXITING   ) {
		// unexpected death... clean up.
		if (thi->mdev)
			set_bit(COLLECT_ZOMBIES,&thi->mdev->flags);
		init_MUTEX(&thi->mutex);
		thi->task = NULL;
		return;
	}

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

inline sigset_t block_sigs_but(unsigned long mask)
{
	unsigned long flags;
	sigset_t oldset;
	LOCK_SIGMASK(current,flags);
	oldset = current->blocked;
	siginitsetinv(&current->blocked,mask);
	RECALC_SIGPENDING(current);
	UNLOCK_SIGMASK(current,flags);
	return oldset;
}

inline void restore_old_sigset(sigset_t oldset)
{
	unsigned long flags;
	LOCK_SIGMASK(current,flags);
	// _never_ propagate this to anywhere...
	sigdelset(&current->pending.signal, DRBD_SIG);
	current->blocked = oldset;
	RECALC_SIGPENDING(current);
	UNLOCK_SIGMASK(current,flags);
}

STATIC int _drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h,
			  size_t size, unsigned msg_flags)
{
	int sent,ok;
	sigset_t old_blocked;

	ERR_IF(!h) return FALSE;
	ERR_IF(!size) return FALSE;

	h->magic   = BE_DRBD_MAGIC;
	h->command = cpu_to_be16(cmd);
	h->length  = cpu_to_be16(size-sizeof(Drbd_Header));

	/* as long as we send directly from make_request, I'd like to
	 * allow KILL, so the user can kill -9 hanging write processes.
	 * if it does not succeed, it _should_ timeout anyways, but...
	 */
	old_blocked = block_sigs_but(SIGKILL);
	sent = drbd_send(mdev,sock,h,size,msg_flags);
	restore_old_sigset(old_blocked);

	D_ASSERT(sent == size);
	ok = ( sent == size );
	if(!ok) {
		ERR("short sent %s size=%d sent=%d\n",
		    cmdname(cmd), size, sent);
	}
	C_DBG(5,"on %s >>> %s l: %d\n",
	    sock == mdev->msock ? "msock" : "sock",
	    cmdname(cmd), size-sizeof(Drbd_Header));
	return ok;
}

int drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
		  Drbd_Packet_Cmd cmd, Drbd_Header* h, size_t size)
{
	int ok;
	if (sock == mdev->sock) {
		down(&mdev->sock_mutex);
		spin_lock(&mdev->send_task_lock);
		mdev->send_task=current;
		spin_unlock(&mdev->send_task_lock);
	} else
		down(&mdev->msock_mutex);

	ok = _drbd_send_cmd(mdev,sock,cmd,h,size,0);

	if (sock == mdev->sock) {
		up(&mdev->sock_mutex);
		spin_lock(&mdev->send_task_lock);
		mdev->send_task=NULL;
		spin_unlock(&mdev->send_task_lock);
	} else
		up(&mdev->msock_mutex);
	return ok;
}

/* for WriteHint, maybe others.
 * returns
 *   1 if nonblocking send was succesfull,
 *   0 if nonblocking send failed,
 * -EAGAIN if we did not get the send mutex
 */
STATIC int drbd_send_cmd_dontwait(drbd_dev *mdev, struct socket *sock,
		  Drbd_Packet_Cmd cmd, Drbd_Header* h, size_t size)
{
	int ok;
	struct semaphore *mutex = sock == mdev->msock ?
		&mdev->msock_mutex : &mdev->sock_mutex;
	if (down_trylock(mutex)) return -EAGAIN;
	ok = _drbd_send_cmd(mdev,sock,cmd,h,size, MSG_DONTWAIT);
	up  (mutex);
	return ok;
}

int drbd_send_sync_param(drbd_dev *mdev)
{
	Drbd_SyncParam_Packet p;
	int ok;

	p.rate      = cpu_to_be32(mdev->sync_conf.rate);
	p.use_csums = cpu_to_be32(mdev->sync_conf.use_csums);
	p.skip      = cpu_to_be32(mdev->sync_conf.skip);
	p.group     = cpu_to_be32(mdev->sync_conf.group);

	ok = drbd_send_cmd(mdev,mdev->sock,SyncParam,(Drbd_Header*)&p,sizeof(p));
	if ( ok
	    && (mdev->cstate == SkippedSyncS || mdev->cstate == SkippedSyncT)
	    && !mdev->sync_conf.skip )
	{
		set_cstate(mdev,WFReportParams);
		ok = drbd_send_param(mdev);
	}
	return ok;
}

int drbd_send_param(drbd_dev *mdev)
{
	Drbd_Parameter_Packet p;
	int ok,i;
	kdev_t ll_dev = mdev->lo_device;

	p.u_size = cpu_to_be64(mdev->lo_usize);
	p.p_size = cpu_to_be64(ll_dev ?
			       blk_size[MAJOR(ll_dev)][MINOR(ll_dev)]:0);

	p.state    = cpu_to_be32(mdev->state);
	p.protocol = cpu_to_be32(mdev->conf.wire_protocol);
	p.version  = cpu_to_be32(PRO_VERSION);

	for(i=Flags;i<=ArbitraryCnt;i++) {
		p.gen_cnt[i]     = cpu_to_be32(mdev->gen_cnt[i]);
	}
	p.sync_rate      = cpu_to_be32(mdev->sync_conf.rate);
	p.sync_use_csums = cpu_to_be32(mdev->sync_conf.use_csums);
	p.skip_sync      = cpu_to_be32(mdev->sync_conf.skip);
	p.sync_group     = cpu_to_be32(mdev->sync_conf.group);

	ok = drbd_send_cmd(mdev,mdev->sock,ReportParams,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

/* See the comment at receive_bitmap() */
int drbd_send_bitmap(drbd_dev *mdev)
{
	int buf_i,want;
	int ok=TRUE, bm_i=0;
	size_t bm_words;
	unsigned long *buffer,*bm;
	Drbd_Header *p;

	ERR_IF(!mdev->mbds_id) return FALSE;

	bm_words = mdev->mbds_id->size/sizeof(unsigned long);
	bm = mdev->mbds_id->bm;
	p  = vmalloc(PAGE_SIZE); // sleeps. cannot fail.
	buffer = (unsigned long*)PAYLOAD_P(p);

	/*
	 * maybe TODO use some simple compression scheme, nowadays there are
	 * some such algorithms in the kernel anyways.
	 */
	do {
		want=min_t(int,MBDS_PACKET_SIZE,(bm_words-bm_i)*sizeof(long));
		for(buf_i=0;buf_i<want/sizeof(unsigned long);buf_i++)
			buffer[buf_i] = cpu_to_lel(bm[bm_i++]);
		ok = drbd_send_cmd(mdev,mdev->sock,ReportBitMap,
				   p, sizeof(*p) + want);
	} while (ok && want);
	vfree(p);
	return ok;
}

int _drbd_send_barrier(drbd_dev *mdev)
{
	int ok;
	Drbd_Barrier_Packet p;

	/* printk(KERN_DEBUG DEVICE_NAME": issuing a barrier\n"); */
	/* tl_add_barrier() must be called with the sock_mutex aquired */
	p.barrier=tl_add_barrier(mdev);

	inc_pending(mdev);
	ok = _drbd_send_cmd(mdev,mdev->sock,Barrier,(Drbd_Header*)&p,sizeof(p),0);
	if (!ok) dec_pending(mdev,HERE);
	return ok;
}

int drbd_send_b_ack(drbd_dev *mdev, u32 barrier_nr,u32 set_size)
{
	int ok;
	Drbd_BarrierAck_Packet p;

	p.barrier  = barrier_nr;
	p.set_size = cpu_to_be32(set_size);

	ok = drbd_send_cmd(mdev,mdev->msock,BarrierAck,(Drbd_Header*)&p,sizeof(p));
	return ok;
}


int drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd, struct Tl_epoch_entry *e)
{
	int ok;
	Drbd_BlockAck_Packet p;

	p.sector   = cpu_to_be64(DRBD_BH_SECTOR(e->bh));
	p.block_id = e->block_id;
	p.blksize  = cpu_to_be32(e->bh->b_size);

	// YES, this happens. There is some race with the syncer!
	if ((unsigned long)e->block_id <= 1) {
		ERR("%s: e->block_id == %lx\n",__func__,(long)e->block_id);
		return FALSE;
	}

	if (!mdev->msock || mdev->cstate < Connected) return FALSE;
	ok = drbd_send_cmd(mdev,mdev->msock,cmd,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

int drbd_send_drequest(drbd_dev *mdev, int cmd,
		       sector_t sector,int size, u64 block_id)
{
	int ok;
	Drbd_BlockRequest_Packet p;

	p.sector   = cpu_to_be64(sector);
	p.block_id = block_id;
	p.blksize  = cpu_to_be32(size);

	ok = drbd_send_cmd(mdev,mdev->sock,cmd,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

int _drbd_send_zc_bh(drbd_dev *mdev, struct buffer_head *bh)
{
	int sent,ok;
	struct page *page = bh->b_page;
	size_t size = bh->b_size;
	int offset;

	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	/*
	 * CAUTION I do not yet understand this completely.
	 * I thought I have to kmap the page first... ?
	 */
	if (PageHighMem(page))
		offset = (int)bh->b_data;
	else
		offset = (int)bh->b_data - (int)page_address(page);
	do {
		sent = mdev->sock->ops->sendpage(mdev->sock, page, offset, size, MSG_NOSIGNAL);
		if (sent <= 0) break;
		size   -= sent;
		offset += sent;
	} while(size > 0 /* THINK && mdev->cstate >= Connected*/);

	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);

	if (sent < 0)
		WARN("%s: size=%d sent==%d\n",__func__,size,sent);

	ok = (size == 0);
	if(likely(ok))
		mdev->send_cnt+=bh->b_size>>9;
	return ok;
}

// Used to send write requests: bh->b_rsector !!
int drbd_send_dblock(drbd_dev *mdev, drbd_request_t *req)
{
	int ok;
	sigset_t old_blocked;
	Drbd_Data_Packet p;

	ERR_IF(!req || !req->bh) return FALSE;
	ERR_IF(req->bh->b_reqnext != NULL) return FALSE;

	p.head.magic   = BE_DRBD_MAGIC;
	p.head.command = cpu_to_be16(Data);
	p.head.length  = cpu_to_be16( sizeof(p)-sizeof(Drbd_Header)
				     + req->bh->b_size );

	p.sector   = cpu_to_be64(req->bh->b_rsector);
	p.block_id = (unsigned long)req;

	/* About tl_add():
	1. This must be within the semaphor,
	   to ensure right order in tl_ data structure and to
	   ensure right order of packets on the write
	2. This must happen before sending, otherwise we might
	   get in the BlockAck packet before we have it on the
	   tl_ datastructure (=> We would want to remove it before it
	   is there!)
	3. Q: Why can we add it to tl_ even when drbd_send() might fail ?
	      There could be a tl_cancel() to remove it within the semaphore!
	   A: If drbd_send fails, we will loose the connection. Then
	      tl_cear() will simulate a RQ_DRBD_SEND and set it out of sync
	      for everything in the data structure.
	*/
	// SIGKILL: see comment in _drbd_send_cmd
	old_blocked = block_sigs_but(SIGKILL);
	down(&mdev->sock_mutex);
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags))
		_drbd_send_barrier(mdev);
	// THINK swap with the if() above?
	tl_add(mdev,req);
	ok =  (drbd_send(mdev,mdev->sock,&p,sizeof(p),MSG_MORE) == sizeof(p))
	   && _drbd_send_zc_bh(mdev,req->bh);

	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);
	up(&mdev->sock_mutex);
	restore_old_sigset(old_blocked);
	return ok;
}

// Used to send answer to read requests, DRBD_BH_SECTOR(bh) !!
int drbd_send_block(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
		    struct Tl_epoch_entry *e)
{
	int ok;
	sigset_t old_blocked;
	Drbd_Data_Packet p;

	// D_ASSERT(FIXME)

	p.head.magic   = BE_DRBD_MAGIC;
	p.head.command = cpu_to_be16(cmd);
	p.head.length  = cpu_to_be16( sizeof(p)-sizeof(Drbd_Header)
				     + e->bh->b_size );

	p.sector   = cpu_to_be64(DRBD_BH_SECTOR(e->bh));
	p.block_id = e->block_id;

	/* only called by our kernel thread.
	 * that one might get stopped by SIGTERM in responst to
	 * ioctl or module unload
	 */
	old_blocked = block_sigs_but(SIGTERM);
	down(&mdev->sock_mutex);
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	ok =  (drbd_send(mdev,mdev->sock,&p,sizeof(p),MSG_MORE) == sizeof(p))
	   && _drbd_send_zc_bh(mdev,e->bh);

	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);
	up(&mdev->sock_mutex);
	restore_old_sigset(old_blocked);
	return ok;
}

/*
  drbd_send distinguishes two cases:

  Packets sent via the data socket "sock"
  and packets sent via the meta data socket "msock"

		    sock                      msock
  -----------------+-------------------------+------------------------------
  timeout           conf.timeout / 2          conf.timeout / 2
  timeout action    send a ping via msock     Abort communication
					      and close all sockets
*/

/* called on sndtimeo
 * returns TRUE if we should retry,
 * FALSE if we think connection is dead,
 * or someone signaled us.
 */
STATIC int drbd_retry_send(drbd_dev *mdev, struct socket *sock)
{
	long elapsed = (long)(jiffies - mdev->last_received);
	DUMPLU(elapsed);
	if ( signal_pending(current) || mdev->cstate <= WFConnection )
		return FALSE;
	if ( elapsed < mdev->conf.timeout*HZ/20 )
		return TRUE;
	if ( current != mdev->asender.task ) {
		DBG("sock_sendmsg timed out, requesting ping\n");
		/* FIXME can I safely send it myself right here,
		 * or do I need to kill asender, and let it do this?
		 */
		request_ping(mdev);
		return TRUE;
	}
	ERR("sock_sendmsg timed out, aborting connection\n");
	return FALSE;
}

/*
 * you should have down()ed the appropriate [m]sock_mutex elsewhere!
 */
int drbd_send(drbd_dev *mdev, struct socket *sock,
	      void* buf, size_t size, unsigned msg_flags)
{
	mm_segment_t oldfs;
	struct msghdr msg;
	struct iovec iov;
	int rv,sent=0;
	int retry = 10;

	if (!sock) return -1000;
	if (mdev->cstate < WFReportParams) return -1001;

	// THINK  if (signal_pending) return ... ?

	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = 0;
	msg.msg_namelen    = 0;
	msg.msg_iov        = &iov;
	msg.msg_iovlen     = 1;
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

	/* FIXME remove. since nbd does not do this either,
	 * it seems to be safe ... well, or *they* have a bug there :-)
	 * lock_kernel();  //  check if this is still necessary
	 */
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ???
		 */
		rv = sock_sendmsg(sock, &msg, iov.iov_len );
		if (rv == -EINTR) {
			if (drbd_retry_send(mdev,sock) && retry--)
				continue;
			else
				break;
		}
		D_ASSERT(rv != 0);
		if (rv < 0) break;
		sent += rv;
		iov.iov_base += rv;
		iov.iov_len  -= rv;
	} while(sent < size);

	set_fs(oldfs);
	// unlock_kernel();

	if (rv <= 0) {
		if (rv != -EINTR) {
			ERR("%s_sendmsg returned %d\n",
			    sock == mdev->msock ? "msock" : "sock",
			    rv);
			set_cstate(mdev, BrokenPipe);
		} else
			set_cstate(mdev, Timeout);
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
	struct Drbd_Conf* mdev = (drbd_dev*)data;
	Drbd_Header h;
	int i;

	/* In case the receiver calls run_task_queue(&tq_disk) itself,
	   in order to flush blocks to the ll_dev (for a device in
	   secondary state), it could happen that it has to send the
	   WRITE_HINT for an other device (which is in primary state).
	   This could lead to a distributed deadlock!!

	   To avoid the deadlock we requeue the WRITE_HINT.
	UPDATE:
	   since "dontwait" this would no longer deadlock, but probably
	   create a useless loop echoing WriteHints back and forth ...
	THINK:
	   Why not set an other bit, so the write hint is sent asap
	   by one of our threads?
	 */

	for (i = 0; i < minor_count; i++) {
		if(current == drbd_conf[i].receiver.task) {
			queue_task(&mdev->write_hint_tq, &tq_disk);
			return;
		}
	}

	// THINK: sock or msock ?
	if (drbd_send_cmd_dontwait(mdev,mdev->sock,WriteHint,&h,sizeof(h))==1){
		clear_bit(WRITE_HINT_QUEUED, &mdev->flags);
	} else {
		if(mdev->cstate < Connected) {
			clear_bit(WRITE_HINT_QUEUED, &mdev->flags);
		} else queue_task(&mdev->write_hint_tq, &tq_disk);
	}
}

void drbd_init_set_defaults(drbd_dev *mdev)
{
	// the implicit memset(,0,) of kcalloc did most of this
	// note: only assignments, no allocation in here

#ifdef PARANOIA
	mdev->magic = (DRBD_MAGIC ^ (long)mdev);
#endif

	/* If the WRITE_HINT_QUEUED flag is set but it is not
	   actually queued the functionality is completely disabled */
	if (disable_io_hints) mdev->flags=1<<WRITE_HINT_QUEUED;

	mdev->sync_conf.rate       = 250;
	mdev->sync_conf.al_extents = 128; // 512 MB active set
	mdev->state                = Secondary;
	mdev->o_state              = Unknown;
	mdev->cstate               = Unconfigured;

	atomic_set(&mdev->pending_cnt,0);
	atomic_set(&mdev->unacked_cnt,0);

	init_MUTEX(&mdev->sock_mutex);
	init_MUTEX(&mdev->msock_mutex);
	init_MUTEX(&mdev->ctl_mutex);
	init_MUTEX(&mdev->md_io_mutex);

	mdev->rs_lock        = SPIN_LOCK_UNLOCKED;
	mdev->al_lock        = SPIN_LOCK_UNLOCKED;
	mdev->tl_lock        = SPIN_LOCK_UNLOCKED;
	mdev->ee_lock        = SPIN_LOCK_UNLOCKED;
	mdev->req_lock       = SPIN_LOCK_UNLOCKED;
	mdev->bb_lock        = SPIN_LOCK_UNLOCKED;
	mdev->pr_lock        = SPIN_LOCK_UNLOCKED;
	mdev->send_task_lock = SPIN_LOCK_UNLOCKED;

	mdev->send_sector=-1;
	INIT_LIST_HEAD(&mdev->free_ee);
	INIT_LIST_HEAD(&mdev->active_ee);
	INIT_LIST_HEAD(&mdev->sync_ee);
	INIT_LIST_HEAD(&mdev->done_ee);
	INIT_LIST_HEAD(&mdev->read_ee);
	INIT_LIST_HEAD(&mdev->rdone_ee);
	INIT_LIST_HEAD(&mdev->busy_blocks);
	INIT_LIST_HEAD(&mdev->app_reads);
	INIT_LIST_HEAD(&mdev->resync_reads);

	init_waitqueue_head(&mdev->state_wait);
	init_waitqueue_head(&mdev->cstate_wait);
	init_waitqueue_head(&mdev->dsender_wait);
	init_waitqueue_head(&mdev->ee_wait);
	init_waitqueue_head(&mdev->al_wait);

	drbd_thread_init(mdev, &mdev->receiver, drbdd_init);
	drbd_thread_init(mdev, &mdev->dsender, drbd_dsender);
	drbd_thread_init(mdev, &mdev->asender, drbd_asender);

	mdev->write_hint_tq.routine = &drbd_send_write_hint;
	mdev->write_hint_tq.data    = mdev;

#ifdef __arch_um__
	INFO("mdev = 0x%p\n",mdev);
#endif
}

void drbd_destroy_mempools(void)
{
	if (drbd_pr_mempool)
		mempool_destroy(drbd_pr_mempool);
	if (drbd_request_mempool)
		mempool_destroy(drbd_request_mempool);
	if (drbd_ee_cache && kmem_cache_destroy(drbd_ee_cache))
		printk(KERN_ERR DEVICE_NAME
		       ": kmem_cache_destroy(drbd_ee_cache) FAILED\n");
	if (drbd_pr_cache && kmem_cache_destroy(drbd_pr_cache))
		printk(KERN_ERR DEVICE_NAME
		       ": kmem_cache_destroy(drbd_pr_cache) FAILED\n");
	if (drbd_request_cache && kmem_cache_destroy(drbd_request_cache))
		printk(KERN_ERR DEVICE_NAME
		       ": kmem_cache_destroy(drbd_request_cache) FAILED\n");
	// FIXME what can we do if we fail to destroy them?

	drbd_pr_mempool      = NULL;
	drbd_request_mempool = NULL;
	drbd_ee_cache        = NULL;
	drbd_pr_cache        = NULL;
	drbd_request_cache   = NULL;

	return;
}

int drbd_create_mempools(void)
{
	// prepare our caches and mempools
	drbd_pr_mempool      = NULL;
	drbd_request_mempool = NULL;
	drbd_ee_cache        = NULL;
	drbd_pr_cache        = NULL;
	drbd_request_cache   = NULL;

	// caches
	drbd_request_cache = kmem_cache_create(
		"drbd_req_cache", sizeof(drbd_request_t),
		0, SLAB_NO_REAP, NULL, NULL);
	if (drbd_request_cache == NULL)
		goto Enomem;

	drbd_pr_cache = kmem_cache_create(
		"drbd_pr_cache", sizeof(struct Pending_read),
		0, SLAB_NO_REAP, NULL, NULL);
	if (drbd_pr_cache == NULL)
		goto Enomem;

	drbd_ee_cache = kmem_cache_create(
		"drbd_ee_cache", sizeof(struct Tl_epoch_entry),
		0, SLAB_NO_REAP, NULL, NULL);
	if (drbd_ee_cache == NULL)
		goto Enomem;

	// mempools
	drbd_request_mempool = mempool_create(16, //TODO; reasonable value
		mempool_alloc_slab, mempool_free_slab, drbd_request_cache);
	if (drbd_request_mempool == NULL)
		goto Enomem;

	drbd_pr_mempool = mempool_create(16, //TODO; reasonable value
		mempool_alloc_slab, mempool_free_slab, drbd_pr_cache);
	if (drbd_pr_mempool == NULL)
		goto Enomem;

		return 0;

  Enomem:
	drbd_destroy_mempools(); // in case we allocated some
	return -ENOMEM;
}

void drbd_cleanup(void)
{
	int i, rr;
	if (drbd_conf) {
		if (drbd_proc)
			remove_proc_entry("drbd",&proc_root);
		drbd_destroy_mempools();
		i=minor_count;
		while (i--) {
			drbd_dev        *mdev  = &drbd_conf[i];

			drbd_free_resources(mdev);
			tl_cleanup(mdev);
			if (mdev->mbds_id) bm_cleanup(mdev->mbds_id);
			if (mdev->resync) lc_free(mdev->resync);

			drbd_release_ee(mdev,&mdev->free_ee);
			rr = drbd_release_ee(mdev,&mdev->active_ee);
			if(rr) printk(KERN_ERR DEVICE_NAME
				       "%d: %d EEs in active list found!\n",i,rr);

			rr = drbd_release_ee(mdev,&mdev->sync_ee);
			if(rr) printk(KERN_ERR DEVICE_NAME
				       "%d: %d EEs in sync list found!\n",i,rr);

			rr = drbd_release_ee(mdev,&mdev->done_ee);
			if(rr) printk(KERN_ERR DEVICE_NAME
				       "%d: %d EEs in done list found!\n",i,rr);

			rr = drbd_release_ee(mdev,&mdev->rdone_ee);
			if(rr) printk(KERN_ERR DEVICE_NAME
				       "%d: %d EEs in rdone list found!\n",i,rr);

			rr = drbd_release_ee(mdev,&mdev->read_ee);
			if(rr) printk(KERN_ERR DEVICE_NAME
				       "%d: %d EEs in read list found!\n",i,rr);

			if(mdev->md_io_bh) {
				__free_page(mdev->md_io_bh->b_page);
				kmem_cache_free(bh_cachep, mdev->md_io_bh);
			}

			if (mdev->act_log) lc_free(mdev->act_log);
		}
	}

	// kfree(NULL) is noop
	blksize_size[MAJOR_NR] = NULL;
	blk_size[MAJOR_NR]     = NULL;
	kfree(drbd_conf);
	kfree(drbd_blocksizes);
	kfree(drbd_sizes);

	if (unregister_blkdev(MAJOR_NR, DEVICE_NAME) != 0)
		printk(KERN_ERR DEVICE_NAME": unregister of device failed\n");

}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
void *
kcalloc(size_t size, int type)
{
	void *addr;
	addr = kmalloc(size, type);
	if (addr)
		memset(addr, 0, size);
	return addr;
}
#endif

int __init drbd_init(void)
{

	int i,err;

	if (register_blkdev(MAJOR_NR, DEVICE_NAME, &drbd_ops))
		return -EBUSY;

	/*
	 * allocate all necessary structs
	 */
	err = -ENOMEM;

	drbd_proc       = NULL; // play safe for drbd_cleanup
	drbd_conf       = kcalloc(sizeof(drbd_dev)*minor_count,GFP_KERNEL);
	drbd_sizes      = kcalloc(sizeof(int)*minor_count,GFP_KERNEL);
	drbd_blocksizes = kmalloc(sizeof(int)*minor_count,GFP_KERNEL);
	if (!drbd_conf || !drbd_blocksizes || !drbd_sizes)
		goto Enomem;

	if ((err = drbd_create_mempools()))
		goto Enomem;

	for (i = 0; i < minor_count; i++) {
		drbd_dev    *mdev = &drbd_conf[i];
		struct page *page = alloc_page(GFP_KERNEL);

		drbd_blocksizes[i] = INITIAL_BLOCK_SIZE;
		set_device_ro( MKDEV(MAJOR_NR, i), TRUE );

		if(!page) goto Enomem;
		mdev->md_io_bh = kmem_cache_alloc(bh_cachep, GFP_KERNEL);
		if(!mdev->md_io_bh) {
			__free_page(page);
			goto Enomem;
		}
		drbd_init_bh(mdev->md_io_bh,512);
		set_bh_page(mdev->md_io_bh,page,0);

		mdev->mbds_id = bm_init(0);
		if (!mdev->mbds_id) goto Enomem;
		// no need to lock access, we are still initializing the module.
		mdev->resync = lc_alloc(5, sizeof(struct bm_extent),NULL,NULL);
		if (!mdev->resync) goto Enomem;
		mdev->act_log = lc_alloc(mdev->sync_conf.al_extents,
					 sizeof(struct lc_element),
					 drbd_al_changing, mdev);
		if (!mdev->act_log) goto Enomem;

		tl_init(mdev);
		drbd_init_ee(mdev);

		drbd_init_set_defaults(mdev);
	}

#if CONFIG_PROC_FS
	/*
	 * register with procfs
	 */
	// XXX maybe move to a seq_file interface
	drbd_proc = create_proc_read_entry("drbd", 0, &proc_root,
					   drbd_proc_get_info, NULL);
	if (!drbd_proc)	{
		printk(KERN_ERR DEVICE_NAME": unable to register proc file\n");
		goto Enomem;
	}
	drbd_proc->owner = THIS_MODULE;
#else
# error "Currently drbd depends on the proc file system (CONFIG_PROC_FS)"
#endif

#ifdef CONFIG_DEVFS_FS
	devfs_handle = devfs_mk_dir (NULL, "nbd", NULL);
	devfs_register_series(devfs_handle, "%u", minor_count,
			      DEVFS_FL_DEFAULT, MAJOR_NR, 0,
			      S_IFBLK | S_IRUSR | S_IWUSR,
			      &drbd_ops, NULL);
# endif

	blk_queue_make_request(BLK_DEFAULT_QUEUE(MAJOR_NR),drbd_make_request);

#if defined(CONFIG_PPC64) || defined(CONFIG_SPARC64) || defined(CONFIG_X86_64)
	// tell the kernel that we think our ioctls are 64bit clean
	lock_kernel();
	register_ioctl32_conversion(DRBD_IOCTL_GET_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_GET_VERSION,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_INVALIDATE,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_INVALIDATE_REM,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SECONDARY_REM,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_DISK_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_DISK_SIZE,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_NET_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_STATE,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_SYNC_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_BOTH,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_NET,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_WAIT_CONNECT,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_WAIT_SYNC,NULL);
	unlock_kernel();
#endif

	return 0; // Success!

  Enomem:
	drbd_cleanup();
	if (err == -ENOMEM) // currently always the case
		printk(KERN_ERR DEVICE_NAME ": ran out of memory\n");
	return err;
}

int __init init_module(void)
{
	if (1 > minor_count||minor_count > 255) {
		printk(KERN_ERR DEVICE_NAME
			": invalid minor_count (%d)\n",minor_count);
		return -EINVAL;
	}

	printk(KERN_INFO DEVICE_NAME ": initialised. "
	       "Version: " REL_VERSION " (api:%d/proto:%d)\n",
	       API_VERSION,PRO_VERSION);

	return drbd_init();
}

void cleanup_module(void)
{
	int i;

#ifdef CONFIG_DEVFS_FS
	devfs_unregister(devfs_handle);
#endif

	for (i = 0; i < minor_count; i++) {
		drbd_set_state(drbd_conf+i,Secondary);
		fsync_dev(MKDEV(MAJOR_NR, i));
		set_bit(DO_NOT_INC_CONCNT,&drbd_conf[i].flags);
		drbd_thread_stop(&drbd_conf[i].dsender);
		drbd_thread_stop(&drbd_conf[i].receiver);
		drbd_thread_stop(&drbd_conf[i].asender);
	}

#if defined(CONFIG_PPC64) || defined(CONFIG_SPARC64) || defined(CONFIG_X86_64)
	lock_kernel();
	unregister_ioctl32_conversion(DRBD_IOCTL_GET_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_GET_VERSION);
	unregister_ioctl32_conversion(DRBD_IOCTL_INVALIDATE);
	unregister_ioctl32_conversion(DRBD_IOCTL_INVALIDATE_REM);
	unregister_ioctl32_conversion(DRBD_IOCTL_SECONDARY_REM);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_DISK_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_DISK_SIZE);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_NET_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_STATE);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_SYNC_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_BOTH);
	unregister_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_NET);
	unregister_ioctl32_conversion(DRBD_IOCTL_WAIT_CONNECT);
	unregister_ioctl32_conversion(DRBD_IOCTL_WAIT_SYNC);
	unlock_kernel();
#endif

	drbd_cleanup();
}

void drbd_free_ll_dev(drbd_dev *mdev)
{
	if (mdev->lo_file) {
		blkdev_put(mdev->lo_file->f_dentry->d_inode->i_bdev,BDEV_FILE);
		blkdev_put(mdev->md_file->f_dentry->d_inode->i_bdev,BDEV_FILE);
		fput(mdev->lo_file);
		fput(mdev->md_file);
		mdev->lo_file = 0;
		mdev->lo_device = 0;
		mdev->md_file = 0;
		mdev->md_device = 0;
	}
}

void drbd_free_sock(drbd_dev *mdev)
{
	if (mdev->sock) {
		sock_release(mdev->sock);
		mdev->sock = 0;
	}
	if (mdev->msock) {
		sock_release(mdev->msock);
		mdev->msock = 0;
	}
}


void drbd_free_resources(drbd_dev *mdev)
{
	drbd_free_sock(mdev);
	drbd_free_ll_dev(mdev);
}

/*********************************/

/*** The bitmap stuff. ***/
/*
  We need to store one bit for a block.
  Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
  Bit 0 ==> Primary and secondary nodes are in sync.
  Bit 1 ==> secondary node's block must be updated. (')
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

	if(size == 0) {
		sbm->size = size;
		vfree(sbm->bm);
		sbm->bm = 0;
		return 1;
	}

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
	sbm->dev_size = size_kb;
	sbm->size = size;
	sbm->bm = nbm;
	spin_unlock(&sbm->bm_lock);

	if(obm) vfree(obm);

	return 1;
}

struct BitMap* bm_init(unsigned long size_kb)
{
	struct BitMap* sbm;

	sbm = kmalloc(sizeof(struct BitMap),GFP_KERNEL);
	if(!sbm) {
		printk(KERN_ERR DEVICE_NAME"X: Failed to allocate BM desc\n");
		return 0;
	}

	sbm->dev_size = size_kb;
	sbm->gs_bitnr=0;
	sbm->bm_lock = SPIN_LOCK_UNLOCKED;

	sbm->size = 0;
	sbm->bm = NULL;

	if(!bm_resize(sbm,size_kb)) {
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

#define BM_SS (BM_BLOCK_SIZE_B-9)     // 3
#define BM_NS (1<<BM_SS)              // 8
#define BM_MM ((1L<<BM_SS)-1)         // 7 = 111bin
#define BPLM (BITS_PER_LONG-1)
#define BM_BPS (BM_BLOCK_SIZE/1024)   // 4

/* sector_t and size have a higher resolution (512 Byte) than
   the bitmap (4K). In case we have to set a bit, we 'round up',
   in case we have to clear a bit we do the opposit.
   It returns the number of sectors that where marked dirty, or
   marked clean.
*/
int bm_set_bit(drbd_dev *mdev, sector_t sector, int size, int bit)
{
	struct BitMap* sbm = mdev->mbds_id;
	unsigned long* bm;
	unsigned long sbnr,ebnr,bnr;
	sector_t esector = ( sector + (size>>9) - 1 );
	int ret=0;

	if(sbm == NULL) {
		printk(KERN_ERR DEVICE_NAME"X: No BitMap !?\n");
		return 0;
	}

	if(sector >= sbm->dev_size*2) return 0;
	if(esector >= sbm->dev_size*2) esector = sbm->dev_size*2 - 1;

	sbnr = sector >> BM_SS;
	ebnr = esector >> BM_SS;

	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;

	if(bit) {
		for(bnr=sbnr; bnr <= ebnr; bnr++) {
			if(!test_bit(bnr&BPLM,bm+(bnr>>LN2_BPL))) ret+=BM_NS;
			__set_bit(bnr & BPLM, bm + (bnr>>LN2_BPL));
			ret += bm_end_of_dev_case(sbm);
		}
	} else { // bit == 0
		sector_t dev_size;

		dev_size=sbm->dev_size;

		if(  (sector & BM_MM) != 0 )     sbnr++;
		if( (esector & BM_MM) != BM_MM ) {
			ebnr--;

			// There is this one special case at the
			// end of the device...
			if(unlikely(dev_size<<1 == esector+1)) {
				ebnr++;
				if(test_bit(ebnr&BPLM,bm+(ebnr>>LN2_BPL))) {
					ret = (esector-sector+1)-BM_NS;
				}
			}
		}

		for(bnr=sbnr; bnr <= ebnr; bnr++) {
			if(test_bit(bnr&BPLM,bm+(bnr>>LN2_BPL))) ret+=BM_NS;
			clear_bit(bnr & BPLM, bm + (bnr>>LN2_BPL));
		}
	}
	spin_unlock(&sbm->bm_lock);

	return ret;
}

static inline unsigned long bitmask(int o)
{
	return o >= BITS_PER_LONG ? -1 : ((1<<o)-1);
}

/* In case the device's size is not divisible by 4, the last bit
   does not count for 8 sectors but something less. This function
   returns this 'something less' iff the last bit is set.
   0               in case the device's size is divisible by 4
   -2,-4 or -6     in the other cases
   If the bits beyond the device's size are set, they are cleared
   and their weight (-8 per bit) is added to the return value.
 */
int bm_end_of_dev_case(struct BitMap* sbm)
{
	unsigned long bnr;
	unsigned long* bm;
	int rv=0;
	int used_bits;      // number ob bits used in last word
	unsigned long mask;

	bm = sbm->bm;

	if( sbm->dev_size % BM_BPS ) {
		bnr = sbm->dev_size / BM_BPS;
		if(test_bit(bnr&BPLM,bm+(bnr>>LN2_BPL))) {
			rv = (sbm->dev_size*2) % BM_NS - BM_NS;
		}
	}
	used_bits = BITS_PER_LONG -
		( sbm->size*8 - div_ceil(sbm->dev_size,BM_BPS) );
	mask = ~ bitmask(used_bits); // mask of bits to clear;
	mask &= bm[sbm->size/sizeof(long)-1];
	if( mask ) {
		rv = -8 * parallel_bitcount(mask);
		bm[sbm->size/sizeof(long)-1] &= ~mask;
	}

	return rv;
}

#define WORDS ( ( BM_EXTENT_SIZE / BM_BLOCK_SIZE ) / BITS_PER_LONG )
int bm_count_sectors(struct BitMap* sbm, unsigned long enr)
{
	unsigned long* bm;
	int i,max,bits=0;

	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;

	max = min_t(int, (enr+1)*WORDS, sbm->size/sizeof(long));

	for(i = enr * WORDS ; i < max ; i++) {
		bits += parallel_bitcount(bm[i]);
	}

	bits = bits << (BM_BLOCK_SIZE_B - 9); // in sectors

	// Special case at the end of the device
	if( max == sbm->size/sizeof(long) ) {
		bits += bm_end_of_dev_case(sbm);
	}

	spin_unlock(&sbm->bm_lock);

	return bits;
}
#undef WORDS

int bm_get_bit(struct BitMap* sbm, sector_t sector, int size)
{
	unsigned long* bm;
	unsigned long sbnr,ebnr,bnr;
	sector_t esector = ( sector + (size>>9) - 1 );
	int ret=0;

	if(sbm == NULL) {
		printk(KERN_ERR DEVICE_NAME"X: No BitMap !?\n");
		return 0;
	}

	sbnr = sector >> BM_SS;
	ebnr = esector >> BM_SS;

	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;

	for(bnr=sbnr; bnr <= ebnr; bnr++) {
		if(test_bit(bnr & BPLM, bm + (bnr>>LN2_BPL))) ret=1;
	}

	spin_unlock(&sbm->bm_lock);

	return ret;
}

sector_t bm_get_sector(struct BitMap* sbm,int* size)
{
	sector_t bnr;
	unsigned long* bm;
	sector_t dev_size;
	sector_t ret;

	if(*size != BM_BLOCK_SIZE) BUG(); // Other cases are not needed

	if(sbm->gs_bitnr == -1) {
		return MBDS_DONE;
	}

	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;
	bnr = sbm->gs_bitnr;

	// optimization possible, search word != 0 first...
	while (!test_bit(bnr & BPLM, bm + (bnr>>LN2_BPL))) {
		bnr++;
		if((bnr>>3) >= sbm->size) break;
	}

	ret=bnr<<BM_SS;

	dev_size=sbm->dev_size;
	if( ret+((1<<BM_SS)-1) > dev_size<<1 ) {
		int ns = dev_size % (1<<(BM_BLOCK_SIZE_B-10));
		sbm->gs_bitnr = -1;
		if(ns) *size = ns<<10;
		else ret=MBDS_DONE;
	} else {
		sbm->gs_bitnr = bnr+1;
	}

	spin_unlock(&sbm->bm_lock);

	return ret;
}

void bm_reset(struct BitMap* sbm)
{
	spin_lock(&sbm->bm_lock);

	sbm->gs_bitnr=0;

	spin_unlock(&sbm->bm_lock);
}


void bm_fill_bm(struct BitMap* sbm,int value)
{
	unsigned long* bm;
	unsigned long bnr;

	spin_lock(&sbm->bm_lock);
	bm = sbm->bm;

	memset(sbm->bm,value,sbm->size);

	// Special case at end of device...
	bnr = sbm->dev_size / BM_BPS + ( sbm->dev_size % BM_BPS ? 1 : 0 );
	bm[bnr / BITS_PER_LONG] &= ( ( 1 << (bnr % BITS_PER_LONG) ) - 1 );

	spin_unlock(&sbm->bm_lock);
}

/*********************************/
/* meta data management */

/* Simply disabled for now...
struct meta_data_on_disk {
	__u64 la_size;           // last agreed size.
	__u32 gc[GEN_CNT_SIZE];  // generation counter
	__u32 magic;
};

void drbd_md_write(drbd_dev *mdev)
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
	ERR("Error writing state file\n\"%s\"\n", fname);
	return;
}

void drbd_md_read(drbd_dev *mdev)
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
	INFO("Creating state file\n\"%s\"\n",fname);
	for(i=HumanCnt;i<=ArbitraryCnt;i++) mdev->gen_cnt[i]=1;
	mdev->gen_cnt[Flags]=MDF_Consistent;
	drbd_md_write(mdev);
	return;
}
*/

struct meta_data_on_disk {
	u64 la_size;           // last agreed size.
	u32 gc[GEN_CNT_SIZE];  // generation counter
	u32 magic;
	u32 md_size;
	u32 al_offset;         // offset to this block
	u32 al_nr_extents;     // important for restoring the AL
	u32 bm_offset;         // offset to the bitmap, from here
};

void drbd_generic_end_io(struct buffer_head *bh, int uptodate)
{ // This is a rough copy of end_buffer_io_sync
	mark_buffer_uptodate(bh, uptodate);
	unlock_buffer(bh);
}

void drbd_md_write(drbd_dev *mdev)
{
	struct meta_data_on_disk * buffer;
	u32 flags;
	sector_t sector;
	int i;

	if( mdev->lo_device == 0) return;

	down(&mdev->md_io_mutex);
	buffer = (struct meta_data_on_disk *)bh_kmap(mdev->md_io_bh);

	flags=mdev->gen_cnt[Flags] & ~(MDF_PrimaryInd|MDF_ConnectedInd);
	if(mdev->state==Primary) flags |= MDF_PrimaryInd;
	if(mdev->cstate>=WFReportParams) flags |= MDF_ConnectedInd;
	mdev->gen_cnt[Flags]=flags;

	for(i=Flags;i<=ArbitraryCnt;i++)
		buffer->gc[i]=cpu_to_be32(mdev->gen_cnt[i]);
	buffer->la_size=cpu_to_be64(blk_size[MAJOR_NR][(int)(mdev-drbd_conf)]);
	buffer->magic=cpu_to_be32(DRBD_MD_MAGIC);

	buffer->md_size = __constant_cpu_to_be32(MD_RESERVED_SIZE);
	buffer->al_offset = __constant_cpu_to_be32(MD_AL_OFFSET);
	buffer->al_nr_extents = cpu_to_be32(mdev->act_log->nr_elements);

	buffer->bm_offset = __constant_cpu_to_be32(MD_BM_OFFSET);

	bh_kunmap(mdev->md_io_bh);
	sector = drbd_md_ss(mdev) + MD_GC_OFFSET;
	drbd_set_bh(mdev, mdev->md_io_bh, sector, 512);
	set_bit(BH_Dirty, &mdev->md_io_bh->b_state);
	set_bit(BH_Lock, &mdev->md_io_bh->b_state);
	mdev->md_io_bh->b_end_io = drbd_generic_end_io;
	generic_make_request(WRITE,mdev->md_io_bh);
	wait_on_buffer(mdev->md_io_bh);

	up(&mdev->md_io_mutex);
}

void drbd_md_read(drbd_dev *mdev)
{
	struct meta_data_on_disk * buffer;
	sector_t sector;
	int i;

	if( mdev->lo_device == 0) return;

	down(&mdev->md_io_mutex);

	sector = drbd_md_ss(mdev) + MD_GC_OFFSET;
	drbd_set_bh(mdev, mdev->md_io_bh, sector, 512);
	clear_bit(BH_Uptodate, &mdev->md_io_bh->b_state);
	set_bit(BH_Lock, &mdev->md_io_bh->b_state);
	mdev->md_io_bh->b_end_io = drbd_generic_end_io;
	generic_make_request(READ,mdev->md_io_bh);
	wait_on_buffer(mdev->md_io_bh);
	ERR_IF( ! buffer_uptodate(mdev->md_io_bh) ) goto err;

	buffer = (struct meta_data_on_disk *)bh_kmap(mdev->md_io_bh);

	if(be32_to_cpu(buffer->magic) != DRBD_MD_MAGIC) goto err;

	for(i=Flags;i<=ArbitraryCnt;i++)
		mdev->gen_cnt[i]=be32_to_cpu(buffer->gc[i]);
	mdev->la_size = be64_to_cpu(buffer->la_size);
	mdev->sync_conf.al_extents = be32_to_cpu(buffer->al_nr_extents);

	bh_kunmap(mdev->md_io_bh);
	up(&mdev->md_io_mutex);
	return;

 err:
	bh_kunmap(mdev->md_io_bh);
	up(&mdev->md_io_mutex);

	INFO("Creating state block\n");

	for(i=HumanCnt;i<=ArbitraryCnt;i++) mdev->gen_cnt[i]=1;
	mdev->gen_cnt[Flags]=MDF_Consistent;

	drbd_md_write(mdev);

	return;
}


//  Returns  1 if I have the good bits,
//           0 if both are nice
//          -1 if the partner has the good bits.
int drbd_md_compare(drbd_dev *mdev,Drbd_Parameter_Packet *partner)
{
	int i;
	u32 me,other;

	me=mdev->gen_cnt[Flags] & MDF_Consistent;
	other=be32_to_cpu(partner->gen_cnt[Flags]) & MDF_Consistent;
	if( me > other ) return 1;
	if( me < other ) return -1;

	for(i=HumanCnt;i<=ArbitraryCnt;i++) {
		me=mdev->gen_cnt[i];
		other=be32_to_cpu(partner->gen_cnt[i]);
		if( me > other ) return 1;
		if( me < other ) return -1;
	}

	me=mdev->gen_cnt[Flags] & MDF_PrimaryInd;
	other=be32_to_cpu(partner->gen_cnt[Flags]) & MDF_PrimaryInd;
	if( me > other ) return 1;
	if( me < other ) return -1;

	return 0;
}

void drbd_md_inc(drbd_dev *mdev, enum MetaDataIndex order)
{
	mdev->gen_cnt[order]++;
}

// XXX maybe use one of the functions from signal.h
void drbd_queue_signal(int signal,struct task_struct *task)
{
	unsigned long flags;

	read_lock(&tasklist_lock);
	if (task) {
		LOCK_SIGMASK(task,flags);
		sigaddset(&task->pending.signal, signal);
		RECALC_SIGPENDING(task);
		spin_unlock_irqrestore(&task->sigmask_lock, flags);
		UNLOCK_SIGMASK(task,flags);
		if (task->state & TASK_INTERRUPTIBLE) wake_up_process(task);
	}
	read_unlock(&tasklist_lock);
}

#ifdef SIGHAND_HACK

// copied from redhat's kernel-2.4.20-13.9 kernel/signal.c
// to avoid a recompile of the redhat kernel

#include <asm/signal.h> // for _NSIG_WORDS

/*
 * Re-calculate pending state from the set of locally pending
 * signals, globally pending signals, and blocked signals.
 */
static inline int has_pending_signals(sigset_t *signal, sigset_t *blocked)
{
        unsigned long ready;
        long i;

        switch (_NSIG_WORDS) {
        default:
                for (i = _NSIG_WORDS, ready = 0; --i >= 0 ;)
                        ready |= signal->sig[i] &~ blocked->sig[i];
                break;

        case 4: ready  = signal->sig[3] &~ blocked->sig[3];
                ready |= signal->sig[2] &~ blocked->sig[2];
                ready |= signal->sig[1] &~ blocked->sig[1];
                ready |= signal->sig[0] &~ blocked->sig[0];
                break;

        case 2: ready  = signal->sig[1] &~ blocked->sig[1];
                ready |= signal->sig[0] &~ blocked->sig[0];
                break;

        case 1: ready  = signal->sig[0] &~ blocked->sig[0];
        }
        return ready != 0;
}

#define PENDING(p,b) has_pending_signals(&(p)->signal, (b))

inline void recalc_sigpending_tsk(struct task_struct *t)
{
        if (t->signal->group_stop_count > 0 ||
            PENDING(&t->pending, &t->blocked) ||
            PENDING(&t->signal->shared_pending, &t->blocked))
                t->sigpending = 1;
        else
                t->sigpending = 0;
}

#endif
