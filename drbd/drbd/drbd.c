/*
-*- linux-c -*-
   drbd.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999 2000, Philipp Reisner <philipp@linuxfreak.com>.
        Initial author.

   Copyright (C) 2000, Marcelo Tosatti <marcelo@conectiva.com.br>.
        Added code for Linux 2.3.x
	Pointed out a deadlock on SMP.

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
#include <net/sock.h>
#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/pkt_sched.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>

#include "drbd.h"
#include "mbds.h"

static int errno;

/* This maches BM_BLOCK_SIZE */
#define INITIAL_BLOCK_SIZE (1<<12)

/* #define MAJOR_NR 240 */
#define MAJOR_NR 43
/* Using the major_nr of the network block device
   prevents us from deadlocking with no request entries
   left on all_requests...
   look out for NBD_MAJOR in ll_rw_blk.c */

#define DEVICE_ON(device)
#define DEVICE_OFF(device)
#define DEVICE_NR(device) (MINOR(device))
#define LOCAL_END_REQUEST
#include <linux/blk.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
#include <linux/blkpg.h>
#else
#define init_MUTEX_LOCKED( A )    (*(A)=MUTEX_LOCKED)
#define init_MUTEX( A )           (*(A)=MUTEX)
#define init_waitqueue_head( A )  (*(A)=0)
typedef struct wait_queue*  wait_queue_head_t;
#define blkdev_dequeue_request(A) CURRENT=(A)->next
#endif

#ifdef DEVICE_NAME
#undef DEVICE_NAME
#endif
#define DEVICE_NAME "drbd"

#define DRBD_SIG SIGXCPU
#define SYNC_LOG_S 60

typedef enum { 
	Running,
	Exiting,
	Restarting
} Drbd_thread_state; 

struct Drbd_thread {
	int pid;
        wait_queue_head_t wait;  
	int t_state;
	int (*function) (struct Drbd_thread *);
	int minor;
};

struct Tl_entry {
        struct request* req;
        unsigned long sector_nr;
};

struct Tl_epoch_entry {
	struct buffer_head* bh;
	u64    block_id;
};

#define ISSUE_BARRIER     0
#define COLLECT_ZOMBIES   1
#define SEND_PING         2
#define WRITER_PRESENT    3

/* #define ES_SIZE_STATS 50 */

struct Drbd_Conf {
	struct drbd_config conf;
	struct socket *sock;
	kdev_t lo_device;
	struct file *lo_file;
	int blk_size_b;
	Drbd_State state;
	Drbd_CState cstate;
	unsigned int send_cnt;
	unsigned int recv_cnt;
	unsigned int read_cnt;
	unsigned int writ_cnt;
	unsigned int pending_cnt;
	unsigned int unacked_cnt;
	spinlock_t req_lock;
	rwlock_t tl_lock;
	struct Tl_entry* tl_end;
	struct Tl_entry* tl_begin;
	struct Tl_entry* transfer_log;
        int    flags;
        int    epoch_size;
	spinlock_t es_lock;
	struct timer_list a_timeout;
	struct semaphore send_mutex;
	unsigned long synced_to;	/* Unit: sectors (512 Bytes) */
	struct buffer_head* sync_log[SYNC_LOG_S];
	spinlock_t sl_lock;
	struct Drbd_thread receiver;
	struct Drbd_thread syncer;
        struct Drbd_thread asender;
        struct mbds_operations* mops;
	void* mbds_id;
        wait_queue_head_t asender_wait;  
	wait_queue_head_t cstate_wait;
	int open_cnt;
#ifdef ES_SIZE_STATS
	unsigned int essss[ES_SIZE_STATS];
#endif  
};

int drbd_send(struct Drbd_Conf *mdev, Drbd_Packet_Cmd cmd, 
	      Drbd_Packet* header, size_t header_size, 
	      void* data, size_t data_size);
int drbd_send_param(int minor);
void drbd_thread_start(struct Drbd_thread *thi);
void _drbd_thread_stop(struct Drbd_thread *thi, int restart, int wait);

int drbdd_init(struct Drbd_thread*);
int drbd_syncer(struct Drbd_thread*);
int drbd_asender(struct Drbd_thread*);
void drbd_free_resources(int minor);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
/*static */ int drbd_proc_get_info(char *, char **, off_t, int, int *,
				   void *);
/*static */ void drbd_do_request(request_queue_t *);
#else
/*static */ int drbd_proc_get_info(char *, char **, off_t, int, int);
/*static */ void drbd_do_request(void);
#endif
/*static */ void drbd_dio_end(struct buffer_head *bh, int uptodate);

int drbd_init(void);
/*static */ int drbd_open(struct inode *inode, struct file *file);
/*static */ int drbd_close(struct inode *inode, struct file *file);
/*static */ int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg);
/*static */ int drbd_fsync(struct file *file, struct dentry *dentry);
/*static */ void drbd_end_req(struct request *req, int nextstate,int uptodate);
struct mbds_operations bm_mops;

/* these defines should go into blkdev.h 
   (if it will be ever includet into linus'es linux) */
#define RQ_DRBD_NOTHING	  0xf100
#define RQ_DRBD_SENT	  0xf200
#define RQ_DRBD_WRITTEN   0xf300
#define RQ_DRBD_SEC_WRITE 0xf400
#define RQ_DRBD_READ      0xf500

#ifdef DEVICE_REQUEST
#undef DEVICE_REQUEST
#endif
#define DEVICE_REQUEST drbd_do_request

#define ID_SYNCER (-1LL)

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

int minor_count=2;

MODULE_AUTHOR("Philipp Reisner <e9525415@stud2.tuwien.ac.at>");
MODULE_DESCRIPTION("drbd - Network block device");
MODULE_PARM(minor_count,"i");
MODULE_PARM_DESC(minor_count, "Maximum number of drbd devices (1-255)");

/*static */ int *drbd_blocksizes;
/*static */ int *drbd_sizes;
/*static */ struct Drbd_Conf *drbd_conf;
/*static */ struct fs_struct dummy_fs;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,40)
/*static */ struct block_device_operations drbd_ops = {
	open:		drbd_open,
	release:	drbd_close,
	ioctl:          drbd_ioctl
};
#else
/*static */ struct file_operations drbd_ops =
{
	NULL,			/* lseek - default */
	block_read,		/* read - general block-dev read */
	block_write,		/* write - general block-dev write */
	NULL,			/* readdir - bad */
	NULL,			/* poll */
	drbd_ioctl,		/* ioctl */
	NULL,			/* mmap */
	drbd_open,		/* open */
	NULL,			/* flush */
	drbd_close,		/* release */
	block_fsync,		/* fsync */
	NULL,			/* fasync */
	NULL,			/* check_media_change */
	NULL,			/* revalidate */
	NULL			/* lock */
};
#endif

#define min(a,b) ( (a) < (b) ? (a) : (b) )
#define max(a,b) ( (a) > (b) ? (a) : (b) )

/************************* PROC FS stuff begin */
#include <linux/proc_fs.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
struct proc_dir_entry *drbd_proc;
#else
struct proc_dir_entry drbd_proc_dir =
{
	0, 4, "drbd",
	S_IFREG | S_IRUGO, 1, 0, 0,
	0, NULL,
	&drbd_proc_get_info, NULL,
	NULL,
	NULL, NULL
};
#endif


struct request *my_all_requests = NULL;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
/*static */ int drbd_proc_get_info(char *buf, char **start, off_t offset,
				   int len, int *unused, void *data)
#else
/*static */ int drbd_proc_get_info(char *buf, char **start, off_t offset,
				   int len, int unused)
#endif
{
	int rlen, i;

	static const char *cstate_names[] =
	{
		"Unconfigured",
		"Unconnected",
		"Timeout",
		"BrokenPipe",
		"WFConnection",
		"WFReportParams",
		"Connected",
		"SyncingAll",
		"SyncingQuick"
	};
	static const char *state_names[2] =
	{
		"Primary",
		"Secondary"
	};


	rlen = sprintf(buf, "version       : %d\n\n", MOD_VERSION);

	/*
	  cs .. connection state
	   st .. mode state
	   ns .. network send
	   nr .. network receive
	   dw .. disk write
	   dr .. disk read
	   of .. block's on the fly 
	*/

	for (i = 0; i < minor_count; i++) {
		rlen =
		    rlen + sprintf(buf + rlen,
				   "%d: cs:%s st:%s ns:%u nr:%u dw:%u dr:%u "
				   "of:%u\n",
				   i,
				   cstate_names[drbd_conf[i].cstate],
				   state_names[drbd_conf[i].state],
				   drbd_conf[i].send_cnt,
				   drbd_conf[i].recv_cnt,
				   drbd_conf[i].writ_cnt,
				   drbd_conf[i].read_cnt,
				   drbd_conf[i].pending_cnt);

	}

	/* DEBUG & profile stuff */
#if 1

	if (my_all_requests != NULL) {
		char major_to_letter[256];
		char current_letter = 'a', l;
		int m;

		for (i = 0; i < 256; i++) {
			major_to_letter[i] = 0;
		}

		rlen = rlen + sprintf(buf + rlen, "\n");

		for (i = 0; i < NR_REQUEST; i++) {
			if (my_all_requests[i].rq_status == RQ_INACTIVE) {
				l = 'E';
			} else {
				m = MAJOR(my_all_requests[i].rq_dev);
				l = major_to_letter[m];
				if (l == 0) {
					l = major_to_letter[m] =
					    current_letter++;
				}
			}
			rlen = rlen + sprintf(buf + rlen, "%c", l);
		}

		rlen = rlen + sprintf(buf + rlen, "\n");

		for (i = 0; i < 256; i++) {
			l = major_to_letter[i];
			if (l != 0)
				rlen =
				    rlen + sprintf(buf + rlen, "%c: %d\n",
						   l, i);
		}
	}
#endif

#ifdef ES_SIZE_STATS
	for(i=0;i<ES_SIZE_STATS;i++) {
		int j;
		rlen=rlen+sprintf(buf+rlen,"\n%d: ",i);
		for (j = 0; j < minor_count; j++) {
			rlen=rlen+sprintf(buf+rlen,"%4d ",
					  drbd_conf[j].essss[i]);
		}
	}
	rlen=rlen+sprintf(buf+rlen,"\n");
#endif  

	/* DEBUG & profile stuff end */

	return rlen;
}

/* PROC FS stuff end */

int drbd_log2(int i)
{
	int bits = 0;
	while (i != 1) {
		bits++;
		i >>= 1;
	}
	return bits;
}


/************************* The transfer log start */
#define TL_BARRIER    0
/* spinlock readme:
   tl_dependence() only needs a read-lock and is called from interrupt time.
   See Documentation/spinlocks.txt why this is valid.
*/

inline void tl_add(struct Drbd_Conf *mdev, struct request * new_item)
{
	unsigned long flags;

	write_lock_irqsave(&mdev->tl_lock,flags);

	/* printk(KERN_ERR DEVICE_NAME ": tl_add(%ld)\n",new_item->sector);*/

	mdev->tl_end->req = new_item;
	mdev->tl_end->sector_nr = new_item->sector;

	mdev->tl_end++;

	if (mdev->tl_end == mdev->transfer_log + mdev->conf.tl_size)
		mdev->tl_end = mdev->transfer_log;

	if (mdev->tl_end == mdev->tl_begin)
		printk(KERN_CRIT DEVICE_NAME ": transferlog too small!! \n");

	write_unlock_irqrestore(&mdev->tl_lock,flags);
}

inline unsigned int tl_add_barrier(struct Drbd_Conf *mdev)
{
        static unsigned int br_cnt=0;
	unsigned long flags;

	write_lock_irqsave(&mdev->tl_lock,flags);

	/* printk(KERN_DEBUG DEVICE_NAME ": tl_add(TL_BARRIER)\n");*/

	br_cnt++;
	if(br_cnt == 0) br_cnt = 1;

	mdev->tl_end->req = TL_BARRIER;
	mdev->tl_end->sector_nr = br_cnt;

	mdev->tl_end++;

	if (mdev->tl_end == mdev->transfer_log + mdev->conf.tl_size)
		mdev->tl_end = mdev->transfer_log;

	if (mdev->tl_end == mdev->tl_begin)
		printk(KERN_CRIT DEVICE_NAME ": transferlog too small!! \n");

	write_unlock_irqrestore(&mdev->tl_lock,flags);

	return br_cnt;
}


inline void tl_init(struct Drbd_Conf *mdev)
{
	mdev->tl_begin = mdev->transfer_log;
	mdev->tl_end = mdev->transfer_log;
}

inline void tl_release(struct Drbd_Conf *mdev,unsigned int barrier_nr,
		       unsigned int set_size)
{
        int epoch_size=0; 
	unsigned long flags;
	write_lock_irqsave(&mdev->tl_lock,flags);

	/* printk(KERN_DEBUG DEVICE_NAME ": tl_release(%u)\n",barrier_nr); */

	if (mdev->tl_begin->req == TL_BARRIER) epoch_size--;

	do {
		mdev->tl_begin++;

		if (mdev->tl_begin == mdev->transfer_log + mdev->conf.tl_size)
			mdev->tl_begin = mdev->transfer_log;

		if (mdev->tl_begin == mdev->tl_end)
			printk(KERN_ERR DEVICE_NAME ": tl messed up!\n");
		epoch_size++;
	} while (mdev->tl_begin->req != TL_BARRIER);

	if(mdev->tl_begin->sector_nr != barrier_nr) 
		printk(KERN_ERR DEVICE_NAME ": invalid barrier number!!"
		       "found=%u, reported=%u\n",
		       (unsigned int)mdev->tl_begin->sector_nr,barrier_nr);

	if(epoch_size != set_size) 
		printk(KERN_ERR DEVICE_NAME ": Epoch set size wrong!!"
		       "found=%d reported=%d \n",epoch_size,set_size);
	
	write_unlock_irqrestore(&mdev->tl_lock,flags);

#ifdef ES_SIZE_STATS
	mdev->essss[set_size]++;
#endif  

}

inline int tl_dependence(struct Drbd_Conf *mdev, unsigned long sect_nr)
{
	struct Tl_entry* p;
	int r;

	read_lock(&mdev->tl_lock);

	p = mdev->tl_end;
	while( TRUE ) {
		if ( p==mdev->tl_begin ) {r=FALSE; break;}
	        if ( p==mdev->transfer_log) {
			p = p + mdev->conf.tl_size;
			if ( p==mdev->tl_begin ) {r=FALSE; break;}
		}
		p--;
		if ( p->req==TL_BARRIER) {r=FALSE; break;}
		if ( p->sector_nr == sect_nr) {r=TRUE; break;}
	}

	read_unlock(&mdev->tl_lock);
	return r;
}

inline void tl_clear(struct Drbd_Conf *mdev)
{
	struct Tl_entry* p = mdev->tl_begin;
	kdev_t dev = MKDEV(MAJOR_NR,mdev-drbd_conf);
	int end_them = mdev->conf.wire_protocol == DRBD_PROT_B || 
                       mdev->conf.wire_protocol == DRBD_PROT_C;
	unsigned long flags;
	write_lock_irqsave(&mdev->tl_lock,flags);

	while(p != mdev->tl_end) {
	        if(p->req != TL_BARRIER) {
	                mdev->mops->set_block_status(mdev->mbds_id,
				     p->sector_nr >> (mdev->blk_size_b-9),
				     mdev->blk_size_b, SS_OUT_OF_SYNC);
			if(end_them && 
			   p->req->rq_status != RQ_INACTIVE &&
			   p->req->rq_dev == dev &&
			   p->req->sector == p->sector_nr ) {
		                drbd_end_req(p->req,RQ_DRBD_SENT,1);
				mdev->pending_cnt--;
			}
		}
		p++;
		if (p == mdev->transfer_log + mdev->conf.tl_size)
		        p = mdev->transfer_log;	    
	}
	tl_init(mdev);
	write_unlock_irqrestore(&mdev->tl_lock,flags);
}     

inline void drbd_collect_zombies(int minor)
{
	if(test_and_clear_bit(COLLECT_ZOMBIES,&drbd_conf[minor].flags)) {
		while( waitpid(-1, NULL, __WCLONE|WNOHANG) > 0 );
	}
}

int drbd_thread_setup(void* arg)
{
	struct Drbd_thread *thi = (struct Drbd_thread *) arg;
	int retval;

	lock_kernel();
	exit_mm(current);	/* give up UL-memory context */
	exit_files(current);	/* give up open filedescriptors */

	exit_fs(current);      /* give up filesystem context (root,pwd) */
	current->fs=&dummy_fs; /* point fs context to dummy fs context,
				  is needed for further calls to do_fork() */
	atomic_set(&dummy_fs.count,10);
	                       /* Since childs are decrementing dummy_fs's 
                                  refcount (by calling exit_fs(), every child 
				  resets the count back to 10 :)
			       */
	current->session = 1;
	current->pgrp = 1;

	if (!thi->pid) sleep_on(&thi->wait);

	retval = thi->function(thi);

	thi->pid = 0;
	wake_up(&thi->wait);
	set_bit(COLLECT_ZOMBIES,&drbd_conf[thi->minor].flags);

	return retval;
}

void drbd_thread_init(int minor, struct Drbd_thread *thi,
		      int (*func) (struct Drbd_thread *))
{
	thi->pid = 0;
	init_waitqueue_head(&thi->wait);
	thi->function = func;
	thi->minor = minor;
}

void drbd_thread_start(struct Drbd_thread *thi)
{
	int pid;

	if (thi->pid == 0) {
		thi->t_state = Running;

		pid = kernel_thread(drbd_thread_setup, (void *) thi, CLONE_FS);

		if (pid < 0) {
			printk(KERN_ERR DEVICE_NAME
			       ": Couldn't start thread (%d)\n", pid);
			return;
		}
		/* printk(KERN_DEBUG DEVICE_NAME ": pid = %d\n", pid); */
		thi->pid = pid;
		wake_up(&thi->wait);
	}
}


void _drbd_thread_stop(struct Drbd_thread *thi, int restart,int wait)
{
        int err;
	if (!thi->pid) return;

	if (restart)
		thi->t_state = Restarting;
	else
		thi->t_state = Exiting;

	err = kill_proc_info(SIGTERM, NULL, thi->pid);

	if (err == 0) {
		if(wait) {
			sleep_on(&thi->wait);	/* wait until the thread
						   has closed the socket */

			/*
			  This would be the *nice* solution, but it crashed
			  my machine...
			  
			  struct task_struct *p;
			  read_lock(&tasklist_lock);
			  p = find_task_by_pid(drbd_conf[minor].rpid);
			  p->p_pptr = current;
			  errno = send_sig_info(SIGTERM, NULL, p);
			  read_unlock(&tasklist_lock);
			  interruptible_sleep_on(&current->wait_chldexit);
			*/

			current->state = TASK_INTERRUPTIBLE;
			schedule_timeout(HZ / 10);
		}
	} else {
		printk(KERN_ERR DEVICE_NAME ": could not send signal\n");
	}
}

inline void drbd_thread_stop(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,FALSE,TRUE);
}

inline void drbd_thread_restart(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,TRUE,TRUE);
}

inline void drbd_thread_restart_nowait(struct Drbd_thread *thi)
{
	_drbd_thread_stop(thi,TRUE,FALSE);
}

inline void set_cstate(struct Drbd_Conf* mdev,Drbd_CState cs)
{
	mdev->cstate = cs;
	wake_up_interruptible(&mdev->cstate_wait);	
}

int drbd_ll_blocksize(int minor)
{
	int size = 0;
	kdev_t ll_dev = drbd_conf[minor].lo_device;

	if (blksize_size[MAJOR(ll_dev)])
		size = blksize_size[MAJOR(ll_dev)][MINOR(ll_dev)];
	else
		printk(KERN_ERR DEVICE_NAME
		       ": LL device has no block size ?!?\n\n");

	if (size == 0)
		size = BLOCK_SIZE;

	/*printk(KERN_DEBUG DEVICE_NAME ": my ll_dev block size=%d/m=%d\n",
	  size, minor); */

	return size;
}

int drbd_send_ping(int minor)
{
	int err;
	Drbd_Packet head;

	down(&drbd_conf[minor].send_mutex);
	err = drbd_send(&drbd_conf[minor], Ping,&head,sizeof(head),0,0);
	up(&drbd_conf[minor].send_mutex);

	if(drbd_conf[minor].conf.timeout) {
		drbd_conf[minor].pending_cnt++;
		mod_timer(&drbd_conf[minor].a_timeout,
			  jiffies + drbd_conf[minor].conf.timeout * HZ / 10);
	}

	return err;
}

int drbd_send_ping_ack(int minor)
{
	int err;
	Drbd_Packet head;

	down(&drbd_conf[minor].send_mutex);
	err = drbd_send(&drbd_conf[minor], PingAck,&head,sizeof(head),0,0);
	up(&drbd_conf[minor].send_mutex);
	
	return err;
}

int drbd_send_param(int minor)
{
	Drbd_Parameter_Packet param;
	int err;
	kdev_t ll_dev = drbd_conf[minor].lo_device;

	if (blk_size[MAJOR(ll_dev)]) {
		param.h.size =
		    cpu_to_be64(blk_size[MAJOR(ll_dev)][MINOR(ll_dev)]);
	} else
		printk(KERN_ERR DEVICE_NAME
		       ": LL device has no size ?!?\n\n");

	param.h.blksize = cpu_to_be32(drbd_ll_blocksize(minor));
	param.h.state = cpu_to_be32(drbd_conf[minor].state);
	param.h.protocol = cpu_to_be32(drbd_conf[minor].conf.wire_protocol);
	param.h.version = cpu_to_be32(MOD_VERSION);

	down(&drbd_conf[minor].send_mutex);
	err = drbd_send(&drbd_conf[minor], ReportParams, (Drbd_Packet*)&param, 
			sizeof(param),0,0);
	up(&drbd_conf[minor].send_mutex);
	
	if(err < sizeof(Drbd_Parameter_Packet))
		printk(KERN_ERR DEVICE_NAME
		       ": Sending of parameter block failed!!\n");	  

	return err;
}

int drbd_send_cstate(struct Drbd_Conf *mdev)
{
	Drbd_CState_Packet head;
	int ret;
	
	head.h.cstate = cpu_to_be32(mdev->cstate);

	down(&mdev->send_mutex);
	ret=drbd_send(mdev,CStateChanged,(Drbd_Packet*)&head,sizeof(head),0,0);
	up(&mdev->send_mutex);
	return ret;

}

int _drbd_send_barrier(struct Drbd_Conf *mdev)
{
        Drbd_Barrier_Packet head;

	/* tl_add_barrier() must be called witth the send_mutex aquired */
	head.h.barrier=tl_add_barrier(mdev); 

	/* printk(KERN_DEBUG DEVICE_NAME": issuing a barrier\n"); */
       
	return drbd_send(mdev,Barrier,(Drbd_Packet*)&head,sizeof(head),0,0);
}

inline void drbd_try_send_barrier(struct Drbd_Conf *mdev)
{
	down(&mdev->send_mutex);
	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
	        _drbd_send_barrier(mdev);
	}
	up(&mdev->send_mutex);
}     

int drbd_send_b_ack(struct Drbd_Conf *mdev, u32 barrier_nr,u32 set_size)
{
        Drbd_BarrierAck_Packet head;
	int ret;
       
        head.h.barrier = barrier_nr;
	head.h.set_size = cpu_to_be32(set_size);
	down(&mdev->send_mutex);
	ret=drbd_send(mdev,BarrierAck,(Drbd_Packet*)&head,sizeof(head),0,0);
	up(&mdev->send_mutex);
	return ret;
}


int drbd_send_ack(struct Drbd_Conf *mdev, int cmd, unsigned long block_nr,
		  u64 block_id)
{
        Drbd_BlockAck_Packet head;
	int ret;

	head.h.block_nr = cpu_to_be64(block_nr);
        head.h.block_id = block_id;
	down(&mdev->send_mutex);
	ret=drbd_send(mdev,cmd,(Drbd_Packet*)&head,sizeof(head),0,0);
	up(&mdev->send_mutex);
	return ret;
}

int drbd_send_data(struct Drbd_Conf *mdev, void* data, size_t data_size,
		   unsigned long block_nr, u64 block_id)
{
        Drbd_Data_Packet head;
	int ret;

	head.h.block_nr = cpu_to_be64(block_nr);
	head.h.block_id = block_id;

	down(&mdev->send_mutex);
	
	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags)) {
	        _drbd_send_barrier(mdev);
	}
	
	ret=drbd_send(mdev,Data,(Drbd_Packet*)&head,sizeof(head),data,
		      data_size);

	if(head.h.block_id != ID_SYNCER) {
		if( ret == data_size + sizeof(head)) {
			/* This must be within the semaphore */
			tl_add(mdev,(struct request*)(unsigned long)block_id);
		} else {
			mdev->mops->set_block_status(mdev->mbds_id,
			      block_nr,mdev->blk_size_b,SS_OUT_OF_SYNC);
			ret=0;
		}
	}

	up(&mdev->send_mutex);

	if( ret == data_size + sizeof(head) &&
	    mdev->conf.wire_protocol != DRBD_PROT_A && 
	    mdev->conf.timeout)   {
		mdev->pending_cnt++;
		mod_timer(&mdev->a_timeout,
			  jiffies + mdev->conf.timeout * HZ / 10);
	}

	return ret;
}

void drbd_c_timeout(unsigned long arg)
{
	struct task_struct *p = (struct task_struct *) arg;

	printk(KERN_INFO DEVICE_NAME ": retrying to connect(pid=%d)\n",p->pid);

	send_sig_info(DRBD_SIG, NULL, p);

}


void drbd_timeout(unsigned long arg)
{
	struct task_struct *p = (struct task_struct *) arg;

	printk(KERN_ERR DEVICE_NAME ": timeout detected! (pid=%d)\n",p->pid);

	send_sig_info(DRBD_SIG, NULL, p);

}

void drbd_a_timeout(unsigned long arg)
{
	struct Drbd_thread* thi = (struct Drbd_thread* ) arg;

	printk(KERN_ERR DEVICE_NAME ": ack timeout detected!\n");

	if(drbd_conf[thi->minor].cstate >= Connected) {
		set_cstate(&drbd_conf[thi->minor],Timeout);
		drbd_thread_restart_nowait(thi);
	}
}

int drbd_send(struct Drbd_Conf *mdev, Drbd_Packet_Cmd cmd, 
	      Drbd_Packet* header, size_t header_size, 
	      void* data, size_t data_size)
{
	mm_segment_t oldfs;
	struct msghdr msg;
	struct iovec iov[2];
	struct timer_list s_timeout;

	int err;

	if (!mdev->sock) return -1000;
	if (mdev->cstate < WFReportParams) return -1001;

	header->magic  =  cpu_to_be32(DRBD_MAGIC);
	header->command = cpu_to_be16(cmd);
	header->length  = cpu_to_be16(data_size);

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

	if (mdev->conf.timeout) {
		init_timer(&s_timeout);
		s_timeout.function = drbd_timeout;
		s_timeout.data = (unsigned long) current;
		s_timeout.expires =
		    jiffies + mdev->conf.timeout * HZ / 10;
		add_timer(&s_timeout);
	}
	lock_kernel();
	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sock_sendmsg(mdev->sock, &msg, header_size+data_size);
	set_fs(oldfs);
	unlock_kernel();

	if (mdev->conf.timeout) {
		unsigned long flags;
		del_timer(&s_timeout);
		spin_lock_irqsave(&current->sigmask_lock,flags);
		if (sigismember(&current->signal, DRBD_SIG)) {
			sigdelset(&current->signal, DRBD_SIG);
			recalc_sigpending(current);
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
			printk(KERN_ERR DEVICE_NAME
			       ": send timed out!! (pid=%d)\n",current->pid);

			set_cstate(mdev,Timeout);

			drbd_thread_restart_nowait(&mdev->receiver);

			return -1002;
		} else spin_unlock_irqrestore(&current->sigmask_lock,flags);
	}
	if (err != header_size+data_size) {
		printk(KERN_ERR DEVICE_NAME ": sock_sendmsg returned %d\n",
		       err);
	}
	if (err < 0) {
		set_cstate(mdev,BrokenPipe);
		drbd_thread_restart_nowait(&mdev->receiver);	  
		return -1003;
	}

	return err;
}

void drbd_set_sock_prio(struct Drbd_Conf *mdev)
{

	/*
	  We could also use TC_PRIO_CONTROL / TC_PRIO_BESTEFFORT
	*/

	switch(mdev->state) {
	case Primary: 
		mdev->sock->sk->priority=TC_PRIO_BULK;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
		mdev->sock->sk->tp_pinfo.af_tcp.nonagle=0;
#else
		mdev->sock->sk->nonagle=0;
#endif
		break;
	case Secondary:
		mdev->sock->sk->priority=TC_PRIO_INTERACTIVE;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
		mdev->sock->sk->tp_pinfo.af_tcp.nonagle=1;
#else
		mdev->sock->sk->nonagle=1;
#endif
		break;
	}
}

void drbd_end_req(struct request *req, int nextstate, int uptodate)
{
	int wake_asender=0;
	unsigned long flags=0;
	struct Drbd_Conf* mdev = &drbd_conf[MINOR(req->rq_dev)];

	if (req->cmd == READ)
		goto end_it_unlocked;

	/* This was a hard one! Can you see the race?
	   (It hit me about once out of 20000 blocks) 

	   switch(status) {
	   ..: status = ...;
	   }
	*/

	spin_lock_irqsave(&mdev->req_lock,flags);

	switch (req->rq_status & 0xfffe) {
	case RQ_DRBD_SEC_WRITE:
	        wake_asender=1;
		goto end_it;
	case RQ_DRBD_NOTHING:
		req->rq_status = nextstate | (uptodate ? 1 : 0);
		break;
	case RQ_DRBD_SENT:
		if (nextstate == RQ_DRBD_WRITTEN)
			goto end_it;
		printk(KERN_ERR DEVICE_NAME ": request state error(A)\n");
		break;
	case RQ_DRBD_WRITTEN:
		if (nextstate == RQ_DRBD_SENT)
			goto end_it;
		printk(KERN_ERR DEVICE_NAME ": request state error(B)\n");
		break;
	default:
		printk(KERN_ERR DEVICE_NAME ": request state error(%X)\n",
		       req->rq_status);
	}

	spin_unlock_irqrestore(&mdev->req_lock,flags);

	return;

/* We only report uptodate == TRUE if both operations (WRITE && SEND)
   reported uptodate == TRUE 
 */

	end_it:
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	end_it_unlocked:

	if(mdev->state == Primary && mdev->cstate >= Connected) {
	  /* If we are unconnected we may not call tl_dependece, since
	     then this call could be from tl_clear(). => spinlock deadlock!
	  */
	        if(tl_dependence(mdev,req->sector)) {
	                set_bit(ISSUE_BARRIER,&mdev->flags);
			wake_asender=1;
		}
	}

	if(!end_that_request_first(req, uptodate & req->rq_status,DEVICE_NAME))
	        end_that_request_last(req);


	if( mdev->conf.do_panic && !(uptodate & req->rq_status) ) {
		panic(DEVICE_NAME": The lower-level device had an error.\n");
	}

	/* TODO: It would be nice if we could AND this condition.
	   But we must also wake the asender if we are receiving 
	   syncer blocks! */
	if(wake_asender /*&& mdev->conf.wire_protocol == DRBD_PROT_C*/ ) {
	        wake_up_interruptible(&mdev->asender_wait);
	}
}

void drbd_dio_end(struct buffer_head *bh, int uptodate)
{
	struct request *req = bh->b_dev_id;

	// READs are sorted out in drbd_end_req().
	drbd_end_req(req, RQ_DRBD_WRITTEN, uptodate);
	
	kfree(bh);
}

/*
  We should _nerver_ sleep with the io_request_lock aquired. (See ll_rw_block)
  Up to now I have considered these ways out:
  * 1) unlock the io_request_lock for the time of the send 
         Not possible, because I do not have the flags for the unlock.
           -> Forget the flags, look at the loop block device!!
  * 2) postpone the send to some point in time when the request lock
       is not hold. 
         Maybe using the tq_scheduler task queue, or an dedicated
         execution context (kernel thread).

         I am not sure if tq_schedule is a good idea, because we
         could send some process to sleep, which would not sleep
	 otherwise.
	   -> tq_schedule is a bad idea, sometimes sock_sendmsg
	      behaves *bad* ( return value does not indicate
	      an error, but ... )

  Non atomic things, that need to be done are:
  sock_sendmsg(), kmalloc(,GFP_KERNEL) and ll_rw_block().
*/

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
/*static */ void drbd_do_request(request_queue_t * q)
#else
/*static */ void drbd_do_request()
#endif
{
	int minor = 0;
	struct request *req;
	int sending;

	minor = MINOR(CURRENT->rq_dev);

	if (blksize_size[MAJOR_NR][minor] !=
	    (1 << drbd_conf[minor].blk_size_b)) {
		/* If someone called set_blocksize() from fs/buffer.c ... */
		int new_blksize;

		spin_unlock_irq(&io_request_lock);

		new_blksize = blksize_size[MAJOR_NR][minor];
		set_blocksize(drbd_conf[minor].lo_device, new_blksize);
		drbd_conf[minor].blk_size_b = drbd_log2(new_blksize);

		printk(KERN_INFO DEVICE_NAME
		       ": Block size change detected! (%d)\n",new_blksize);

		spin_lock_irq(&io_request_lock);
	}
	while (TRUE) {
		INIT_REQUEST;
		req=CURRENT;
		blkdev_dequeue_request(req);

		/*
		   {
		   static const char *strs[2] = 
		   {
		   "READ",
		   "WRITE"
		   };

		   printk(KERN_DEBUG DEVICE_NAME ": do_request(cmd=%s,sec=%ld,"
		   "nr_sec=%ld,cnr_sec=%ld,buf=%p,min=%d)",
		   strs[req->cmd == READ ? 0 : 1],req->sector,
		   req->nr_sectors,
		   req->current_nr_sectors,
		   req->buffer,minor);
		   }
		 */

		spin_unlock_irq(&io_request_lock);

		sending = 0;

		if (req->cmd == WRITE && drbd_conf[minor].state == Primary) {
			if ( drbd_conf[minor].cstate >= Connected
			     && req->sector > drbd_conf[minor].synced_to) 
				sending = 1;
		}

		/* Do disk - IO */
		{
			struct buffer_head *bh;
			bh = kmalloc(sizeof(struct buffer_head),GFP_KERNEL);
			if (!bh) {
				printk(KERN_ERR DEVICE_NAME
				       ": could not kmalloc()\n");
				return;
			}

			memcpy(bh, req->bh, sizeof(struct buffer_head));

			bh->b_dev = drbd_conf[minor].lo_device;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
			bh->b_state = (1 << BH_Req) | (1 << BH_Mapped);
#else
			bh->b_state = (1 << BH_Req) | (1 << BH_Dirty);
#endif
			
#ifdef BH_JWrite
			if (test_bit(BH_JWrite, &req->bh->b_state))
				set_bit(BH_JWrite, &bh->b_state);
#endif			

			bh->b_list = BUF_LOCKED;
			bh->b_dev_id = req;
			bh->b_end_io = drbd_dio_end;
			
			if(req->cmd == WRITE) drbd_conf[minor].writ_cnt++;
			else drbd_conf[minor].read_cnt++;

			if (sending)
				req->rq_status = RQ_DRBD_NOTHING;
			else if (req->cmd == WRITE) {
			        if(drbd_conf[minor].state == Secondary)
				  req->rq_status = RQ_DRBD_SEC_WRITE | 0x0001;
				else {
				  req->rq_status = RQ_DRBD_SENT | 0x0001;
				  drbd_conf[minor].mops->
				    set_block_status(drbd_conf[minor].mbds_id,
			               req->sector >> 
					  (drbd_conf[minor].blk_size_b-9),
				       drbd_conf[minor].blk_size_b, 
				       SS_OUT_OF_SYNC);
				}
			}
			else
				req->rq_status = RQ_DRBD_READ | 0x0001;

			ll_rw_block(req->cmd, 1, &bh);
		}

		/* Send it out to the network */
		if (sending) {
			int bnr;
			int send_ok;
			bnr = req->sector >> (drbd_conf[minor].blk_size_b - 9);
     		        send_ok=drbd_send_data(&drbd_conf[minor], req->buffer,
					   req->current_nr_sectors << 9,
					   bnr,(unsigned long)req);

			if(send_ok) {
			        drbd_conf[minor].send_cnt++;
			} 

			if( drbd_conf[minor].conf.wire_protocol==DRBD_PROT_A ||
			    (!send_ok) ) {
				/* If sending failed, we can not expect
				   an ack packet. */
			         drbd_end_req(req, RQ_DRBD_SENT, 1);
			}
				
		}
		spin_lock_irq(&io_request_lock);
	}
}

/*static */ int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	int err;
	int minor,i;
	struct file *filp;
	struct drbd_config new_conf;
	enum ret_codes retcode;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;

	switch (cmd) {
	case BLKGETSIZE:
		if ((err=put_user(blk_size[MAJOR_NR][minor]<<1, (long *)arg)))
			return err;
		break;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	case BLKROSET:
	case BLKROGET:
	case BLKFLSBUF:
	case BLKSSZGET:
	case BLKPG:
		return blk_ioctl(inode->i_rdev, cmd, arg);
#else
	 RO_IOCTLS(inode->i_rdev, arg);
#endif

	case DRBD_IOCTL_GET_VERSION:
		if ((err = put_user(MOD_VERSION, (int *) arg)))
			return err;
		break;

	case DRBD_IOCTL_SET_STATE:
		if (arg != Primary && arg != Secondary)
			return -EINVAL;
		
		if (drbd_conf[minor].cstate == SyncingAll
		    || drbd_conf[minor].cstate == SyncingQuick)
			return -EINPROGRESS;

		if(test_bit(WRITER_PRESENT, &drbd_conf[minor].flags)
		   && arg == Secondary)
			return -EBUSY;

		fsync_dev(MKDEV(MAJOR_NR, minor));
		drbd_conf[minor].state = (Drbd_State) arg;

		if (drbd_conf[minor].sock )
			drbd_set_sock_prio(&drbd_conf[minor]);

		if (drbd_conf[minor].cstate >= Connected)
			drbd_send_param(minor);

		        /*printk(KERN_DEBUG DEVICE_NAME ": set_state(%d)\n",
			  drbd_conf[minor].state);*/
		break;

	case DRBD_IOCTL_SET_CONFIG:
	        /* printk(KERN_DEBUG DEVICE_NAME ": set_config()\n"); */

		if (drbd_conf[minor].open_cnt > 1)
			return -EBUSY;

		if ((err = copy_from_user(&new_conf, 
				    &((struct ioctl_drbd_config *)arg)->config,
				    sizeof(struct drbd_config))))
			return err;

#define M_ADDR(A) (((struct sockaddr_in *)&A##.my_addr)->sin_addr.s_addr)
#define M_PORT(A) (((struct sockaddr_in *)&A##.my_addr)->sin_port)
#define O_ADDR(A) (((struct sockaddr_in *)&A##.other_addr)->sin_addr.s_addr)
#define O_PORT(A) (((struct sockaddr_in *)&A##.other_addr)->sin_port)
		for(i=0;i<minor_count;i++) {		  
			if( i!=minor && drbd_conf[i].cstate!=Unconfigured &&
			    M_ADDR(new_conf) == M_ADDR(drbd_conf[i].conf) &&
			    M_PORT(new_conf) == M_PORT(drbd_conf[i].conf) ) {
				retcode=LAAlreadyInUse;
				goto fail_ioctl;
			}
			if( i!=minor && drbd_conf[i].cstate!=Unconfigured &&
			    O_ADDR(new_conf) == O_ADDR(drbd_conf[i].conf) &&
			    O_PORT(new_conf) == O_PORT(drbd_conf[i].conf) ) {
				retcode=OAAlreadyInUse;
				goto fail_ioctl;
			}
		}
#undef M_ADDR
#undef M_PORT
#undef O_ADDR
#undef O_PORT

		filp = fget(new_conf.lower_device);
		if (!filp) {
			retcode=LDFDInvalid;
			goto fail_ioctl;
		}

		inode = filp->f_dentry->d_inode;

		for(i=0;i<minor_count;i++) {
			if( i != minor && 
			    inode->i_rdev == drbd_conf[i].lo_device) {
				retcode=LDAlreadyInUse;
				goto fail_ioctl;
			}
		}

		if (!S_ISBLK(inode->i_mode)) {			
			fput(filp);
			retcode=LDNoBlockDev;
			goto fail_ioctl;
		}

		if ((err = blkdev_open(inode, filp))) {
			printk(KERN_ERR DEVICE_NAME
			       ": blkdev_open( %d:%d ,) returned %d\n",
			       MAJOR(inode->i_rdev), MINOR(inode->i_rdev),err);
			fput(filp);
			retcode=LDOpenFailed;
			/* goto fail_ioctl; */
		fail_ioctl:
			if ((err=put_user(retcode, 
				&((struct ioctl_drbd_config *)arg)->ret_code)))
				return err;
			return -EINVAL;
		}

		/* TODO: 
		         We should warn the user if the LL_DEV is
			 used already. E.g. some FS mounted on it.
		*/

		fsync_dev(MKDEV(MAJOR_NR, minor));
		drbd_thread_stop(&drbd_conf[minor].syncer);
		drbd_thread_stop(&drbd_conf[minor].asender);
		drbd_thread_stop(&drbd_conf[minor].receiver);
		drbd_free_resources(minor);

		memcpy(&drbd_conf[minor].conf,&new_conf,
		       sizeof(struct drbd_config));

		drbd_conf[minor].lo_device = inode->i_rdev;
		drbd_conf[minor].lo_file = filp;

		if (!drbd_conf[minor].transfer_log) {
			drbd_conf[minor].transfer_log =
			    kmalloc(sizeof(struct Tl_entry) * 
				    drbd_conf[minor].conf.tl_size,
				    GFP_KERNEL);
			tl_init(&drbd_conf[minor]);
		}

		if (drbd_conf[minor].conf.disk_size) {
		        kdev_t ll_dev = drbd_conf[minor].lo_device;
			blk_size[MAJOR_NR][minor] =
			  min(blk_size[MAJOR(ll_dev)][MINOR(ll_dev)],
			      drbd_conf[minor].conf.disk_size);
		        printk(KERN_INFO DEVICE_NAME
			       ": user provided size = %d KB\n",
			       blk_size[MAJOR_NR][minor]);

			if (!drbd_conf[minor].mbds_id) {
			       drbd_conf[minor].mbds_id = 
				 drbd_conf[minor].mops->init(MKDEV(MAJOR_NR, 
								   minor));
			}
		}		

		set_blocksize(MKDEV(MAJOR_NR, minor), INITIAL_BLOCK_SIZE);
		drbd_conf[minor].blk_size_b = drbd_log2(INITIAL_BLOCK_SIZE);
		set_blocksize(drbd_conf[minor].lo_device, INITIAL_BLOCK_SIZE);

		set_cstate(&drbd_conf[minor],Unconnected);

		drbd_thread_start(&drbd_conf[minor].receiver);

		break;

	case DRBD_IOCTL_UNCONFIG:

		if( drbd_conf[minor].state == Unconfigured)
			return -ENXIO;

		if (drbd_conf[minor].open_cnt > 1)
			return -EBUSY;

		fsync_dev(MKDEV(MAJOR_NR, minor));
		drbd_thread_stop(&drbd_conf[minor].syncer);
		drbd_thread_stop(&drbd_conf[minor].asender);
		drbd_thread_stop(&drbd_conf[minor].receiver);
		drbd_free_resources(minor);
		if (drbd_conf[minor].mbds_id) {
			drbd_conf[minor].mops->cleanup(drbd_conf[minor].mbds_id);
			drbd_conf[minor].mbds_id=0;
		}

		break;

	case DRBD_IOCTL_WAIT_SYNC:
		while (drbd_conf[minor].cstate == SyncingAll ||
		       drbd_conf[minor].cstate == SyncingQuick ) {
			interruptible_sleep_on(&drbd_conf[minor].cstate_wait);
			if(signal_pending(current)) return -EINTR;
		}
			
		if ((err = put_user(drbd_conf[minor].cstate == Connected, 
				    (int *) arg)))
			return err;
		break;

	case DRBD_IOCTL_DO_SYNC_ALL:
		if( drbd_conf[minor].state != Primary)
			return -EINPROGRESS;

		if( drbd_conf[minor].cstate != Connected)
		        return -ENXIO;

		set_cstate(&drbd_conf[minor],SyncingAll);
		drbd_send_cstate(&drbd_conf[minor]);
		drbd_thread_start(&drbd_conf[minor].syncer);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}


/*static */ int drbd_open(struct inode *inode, struct file *file)
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

/*static */ int drbd_close(struct inode *inode, struct file *file)
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


int __init drbd_init(void)
{

	int i;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	drbd_proc = create_proc_read_entry("drbd", 0, &proc_root,
					   drbd_proc_get_info, NULL);
	if (!drbd_proc)
#else
	if (proc_register(&proc_root, &drbd_proc_dir))
#endif
	{
		printk(KERN_ERR DEVICE_NAME "unable to register proc file.\n");
		return -EIO;
	}

	if (register_blkdev(MAJOR_NR, DEVICE_NAME, &drbd_ops)) {

		printk(KERN_ERR DEVICE_NAME ": Unable to get major %d\n",
		       MAJOR_NR);

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
		if (drbd_proc)
			remove_proc_entry("drbd", &proc_root);
#else
		proc_unregister(&proc_root, drbd_proc_dir.low_ino);
#endif

		return -EBUSY;
	}


	drbd_blocksizes = kmalloc(sizeof(int)*minor_count,GFP_KERNEL);
	drbd_sizes = kmalloc(sizeof(int)*minor_count,GFP_KERNEL);
	drbd_conf = kmalloc(sizeof(struct Drbd_Conf)*minor_count,GFP_KERNEL);

	/* Initialize size arrays. */

	for (i = 0; i < minor_count; i++) {
		drbd_blocksizes[i] = INITIAL_BLOCK_SIZE;
		drbd_conf[i].blk_size_b = drbd_log2(INITIAL_BLOCK_SIZE);
		drbd_sizes[i] = 0;
		set_device_ro(MKDEV(MAJOR_NR, i), FALSE /*TRUE */ );
		drbd_conf[i].sock = 0;
		drbd_conf[i].lo_file = 0;
		drbd_conf[i].lo_device = 0;
		drbd_conf[i].state = Secondary;
		drbd_conf[i].cstate = Unconfigured;
		drbd_conf[i].send_cnt = 0;
		drbd_conf[i].recv_cnt = 0;
		drbd_conf[i].writ_cnt = 0;
		drbd_conf[i].read_cnt = 0;
		drbd_conf[i].pending_cnt = 0;
		drbd_conf[i].unacked_cnt = 0;
		drbd_conf[i].transfer_log = 0;
		drbd_conf[i].mops = &bm_mops;
		drbd_conf[i].mbds_id = 0;
		drbd_conf[i].flags=0;
		tl_init(&drbd_conf[i]);
		drbd_conf[i].epoch_size=0;
		drbd_conf[i].a_timeout.function = drbd_a_timeout;
		drbd_conf[i].a_timeout.data = (unsigned long) 
			&drbd_conf[i].receiver;
		init_timer(&drbd_conf[i].a_timeout);
		drbd_conf[i].synced_to=0;
		init_MUTEX(&drbd_conf[i].send_mutex);
		drbd_thread_init(i, &drbd_conf[i].receiver, drbdd_init);
		drbd_thread_init(i, &drbd_conf[i].syncer, drbd_syncer);
		drbd_thread_init(i, &drbd_conf[i].asender, drbd_asender);
		drbd_conf[i].tl_lock = RW_LOCK_UNLOCKED;
		drbd_conf[i].es_lock = SPIN_LOCK_UNLOCKED;
		drbd_conf[i].req_lock = SPIN_LOCK_UNLOCKED;
		drbd_conf[i].sl_lock = SPIN_LOCK_UNLOCKED;
		init_waitqueue_head(&drbd_conf[i].asender_wait);
		init_waitqueue_head(&drbd_conf[i].cstate_wait);
		drbd_conf[i].open_cnt = 0;
		{
			int j;
			for(j=0;j<SYNC_LOG_S;j++) drbd_conf[i].sync_log[j]=0;

#ifdef ES_SIZE_STATS
			for(j=0;j<ES_SIZE_STATS;j++) drbd_conf[i].essss[j]=0;
#endif  
		}
	}
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	blk_init_queue(BLK_DEFAULT_QUEUE(MAJOR_NR), DEVICE_REQUEST);
#else
	blk_dev[MAJOR_NR].request_fn = DEVICE_REQUEST;
#endif
	blksize_size[MAJOR_NR] = drbd_blocksizes;
	blk_size[MAJOR_NR] = drbd_sizes;	/* Size in Kb */

	atomic_set(&dummy_fs.count,10);
	dummy_fs.umask=0;
	dummy_fs.root=0;
	dummy_fs.pwd=0;

	return 0;
}

int __init init_module()
{
	printk(KERN_INFO DEVICE_NAME ": module initialised. Version: %d\n",
	       MOD_VERSION);

	return drbd_init();

}

void cleanup_module()
{
	int i;

	for (i = 0; i < minor_count; i++) {
		fsync_dev(MKDEV(MAJOR_NR, i));
		drbd_thread_stop(&drbd_conf[i].syncer);
		drbd_thread_stop(&drbd_conf[i].receiver);
		drbd_thread_stop(&drbd_conf[i].asender);
		drbd_free_resources(i);
		if (drbd_conf[i].transfer_log)
			kfree(drbd_conf[i].transfer_log);		    
		if (drbd_conf[i].mbds_id)
			drbd_conf[i].mops->cleanup(drbd_conf[i].mbds_id);
	}

	if (unregister_blkdev(MAJOR_NR, DEVICE_NAME) != 0)
		printk(KERN_ERR DEVICE_NAME": unregister of device failed\n");


#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	blk_cleanup_queue(BLK_DEFAULT_QUEUE(MAJOR_NR));
#else
	blk_dev[MAJOR_NR].request_fn = NULL;
#endif

	blksize_size[MAJOR_NR] = NULL;
	blk_size[MAJOR_NR] = NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	if (drbd_proc)
		remove_proc_entry("drbd", &proc_root);
#else
	proc_unregister(&proc_root, drbd_proc_dir.low_ino);
#endif

	kfree(drbd_blocksizes);
	kfree(drbd_sizes);
	kfree(drbd_conf);
}


/************************* Receiving part */
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
		printk(KERN_ERR DEVICE_NAME ": accept failed! %d\n", err);
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
		printk(KERN_ERR DEVICE_NAME ": sock_recvmsg returned %d\n",
		       err);

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
		       ": There is already a socket!! \n");
		return 0;
	}
	err = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
	if (err) {
		printk(KERN_ERR DEVICE_NAME ": sock_creat(..)=%d\n", err);
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
			       ": sock_creat(..)=%d\n", err);
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
			       ": Unable to bind (%d)\n", err);
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
			if (sigismember(&current->signal, DRBD_SIG)) {
				sigdelset(&current->signal, DRBD_SIG);
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

	drbd_set_sock_prio(&drbd_conf[minor]);

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

	return TRUE;
}

inline int receive_barrier(int minor)
{
	struct Tl_epoch_entry *epoch = 
	  (struct Tl_epoch_entry *)drbd_conf[minor].transfer_log;
  	Drbd_Barrier_P header;
	int ep_size,i;

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) 
	    != sizeof(header))
	        return FALSE;

	spin_lock(&drbd_conf[minor].es_lock);

	ep_size=drbd_conf[minor].epoch_size;
	
	/* printk(KERN_DEBUG DEVICE_NAME ": got Barrier\n"); */

	if(drbd_conf[minor].conf.wire_protocol==DRBD_PROT_C) {
	        for(i=0;i<ep_size;i++) {
			if(!buffer_uptodate(epoch[i].bh)) 
				wait_on_buffer(epoch[i].bh);
		        if(epoch[i].block_id) {
				u64 block_id = epoch[i].block_id;
				epoch[i].block_id=0;
				spin_unlock(&drbd_conf[minor].es_lock);
				drbd_send_ack(&drbd_conf[minor], WriteAck,
					      epoch[i].bh->b_blocknr,
					      block_id);
				drbd_conf[minor].unacked_cnt--;
				spin_lock(&drbd_conf[minor].es_lock);
				ep_size=drbd_conf[minor].epoch_size;
			}
			brelse(epoch[i].bh); /* Can I use bforget() here ? */
		}
	} else {
		for(i=0;i<ep_size;i++) {
			if(!buffer_uptodate(epoch[i].bh)) 
				wait_on_buffer(epoch[i].bh);
			brelse(epoch[i].bh); /* Can I use bforget() here ? */
		}
	}

	drbd_conf[minor].epoch_size=0;
	spin_unlock(&drbd_conf[minor].es_lock);
	drbd_send_b_ack(&drbd_conf[minor], header.barrier,ep_size );

	return TRUE;
}

inline int receive_data(int minor,int data_size)
{
        struct buffer_head *bh;
	unsigned long block_nr;
	struct Tl_epoch_entry *epoch = 
	  (struct Tl_epoch_entry *)drbd_conf[minor].transfer_log;
	int ep_size;
	Drbd_Data_P header;

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
	}

	bh = getblk(MKDEV(MAJOR_NR, minor), block_nr,data_size);

	if (!bh) {
	        printk(KERN_ERR DEVICE_NAME": getblk()=0/m=%d\n",minor);
	        return FALSE;
	}

	/* Blocks from syncer are not going into the epoch set */
	if(header.block_id != ID_SYNCER) {
	        spin_lock(&drbd_conf[minor].es_lock);
	        ep_size=drbd_conf[minor].epoch_size;

	        epoch[ep_size].bh = bh;
		epoch[ep_size].block_id = header.block_id;
		ep_size++;

		drbd_conf[minor].epoch_size=ep_size;
	        spin_unlock(&drbd_conf[minor].es_lock);
		if (ep_size > drbd_conf[minor].conf.tl_size)
			printk(KERN_ERR DEVICE_NAME ": tl_size too small"
			       " (ep_size > tl_size)\n");
	} else {	       
		int i;
		struct buffer_head ** sync_log = drbd_conf[minor].sync_log;
		spin_lock(&drbd_conf[minor].sl_lock);
		for(i=0;i<SYNC_LOG_S;i++) {
			if(sync_log[i]) {
				if(buffer_uptodate(sync_log[i])) {
					unsigned long bnr;
					bnr = sync_log[i]->b_blocknr;
					brelse(sync_log[i]);
					sync_log[i]=bh;
					spin_unlock(&drbd_conf[minor].sl_lock);
					drbd_send_ack(&drbd_conf[minor],
						      WriteAck,bnr,ID_SYNCER);
					goto exit_for_unlocked;
				}				
			} else {
				sync_log[i]=bh;
				goto exit_for;
			}
		}
		printk(KERN_ERR DEVICE_NAME ": SYNC_LOG_S too small\n");
	exit_for:
		spin_unlock(&drbd_conf[minor].sl_lock);
	exit_for_unlocked:
	}


	if (drbd_recv(&drbd_conf[minor], bh->b_data, data_size) 
	    != data_size)
	        return FALSE;

	mark_buffer_uptodate(bh, 0);
	mark_buffer_dirty(bh, 1);

	if (drbd_conf[minor].conf.wire_protocol == DRBD_PROT_B
	    && header.block_id != ID_SYNCER) {
	        /*  printk(KERN_DEBUG DEVICE_NAME": Sending RecvAck"
		    " %ld\n",header.block_id); */
	        drbd_send_ack(&drbd_conf[minor], RecvAck,
			      block_nr,header.block_id);
	}

	ll_rw_block(WRITE, 1, &bh);

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
	if (drbd_conf[minor].conf.wire_protocol == DRBD_PROT_C) {
		if (drbd_conf[minor].unacked_cnt++ >= (NR_REQUEST / 4)) {
			run_task_queue(&tq_disk);
		}
	}
	/* </HACK> */

	drbd_conf[minor].recv_cnt++;
	
	return TRUE;
}     

inline void receive_ping_ack(int minor)
{
	if(drbd_conf[minor].conf.timeout ) {
		if(--drbd_conf[minor].pending_cnt > 0) {
			mod_timer(&drbd_conf[minor].a_timeout,
				  jiffies + drbd_conf[minor].conf.timeout 
				  * HZ / 10);
		} else {
			del_timer(&drbd_conf[minor].a_timeout);
		}
	}	
}

inline int receive_block_ack(int minor)
{     
        struct request *req;
	Drbd_BlockAck_P header;

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) != 
	    sizeof(header))
	        return FALSE;
	
	if(drbd_conf[minor].conf.wire_protocol != DRBD_PROT_A &&
	   drbd_conf[minor].conf.timeout ) {
		if(--drbd_conf[minor].pending_cnt > 0) {
			mod_timer(&drbd_conf[minor].a_timeout,
				  jiffies + drbd_conf[minor].conf.timeout 
				  * HZ / 10);
		} else {
			del_timer(&drbd_conf[minor].a_timeout);
		}
	}


	if( header.block_id == ID_SYNCER) {
		drbd_conf[minor].mops->
		set_block_status(drbd_conf[minor].mbds_id,
				 be64_to_cpu(header.block_nr), 
				 drbd_conf[minor].blk_size_b, 
				 SS_IN_SYNC);
	} else {
		req=(struct request*)(long)header.block_id;
		drbd_end_req(req, RQ_DRBD_SENT, 1);
	}

	return TRUE;
}

inline int receive_barrier_ack(int minor)
{
	Drbd_BarrierAck_P header;

	if (drbd_recv(&drbd_conf[minor], &header, sizeof(header)) != 
	    sizeof(header))
	        return FALSE;

        tl_release(&drbd_conf[minor],header.barrier,
		   be32_to_cpu(header.set_size));
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
		printk(KERN_ERR DEVICE_NAME": incompatible states \n");
		drbd_conf[minor].receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(param.version)!=MOD_VERSION) {
	        printk(KERN_ERR DEVICE_NAME": incompatible releases \n");
		drbd_conf[minor].receiver.t_state = Exiting;
		return FALSE;
	}

	if(be32_to_cpu(param.protocol)!=drbd_conf[minor].conf.wire_protocol) {
	        printk(KERN_ERR DEVICE_NAME": incompatible protocols \n");
		drbd_conf[minor].receiver.t_state = Exiting;
		return FALSE;
	}

        if (!blk_size[MAJOR(ll_dev)]) {
		blk_size[MAJOR_NR][minor] = 0;
		printk(KERN_ERR DEVICE_NAME": LL Device has no size!\n");
		return FALSE;
	}

	blk_size[MAJOR_NR][minor] =
		min(blk_size[MAJOR(ll_dev)][MINOR(ll_dev)],
		    be64_to_cpu(param.size));

	if(drbd_conf[minor].conf.disk_size &&
	   (drbd_conf[minor].conf.disk_size != blk_size[MAJOR_NR][minor])) {
		printk(KERN_ERR DEVICE_NAME": Your size hint is bogus!"
		       "change it to %d\n",blk_size[MAJOR_NR][minor]);
		blk_size[MAJOR_NR][minor]=drbd_conf[minor].conf.disk_size;
		set_cstate(&drbd_conf[minor],Unconfigured);
		return FALSE;
	}

	printk(KERN_INFO DEVICE_NAME ": agreed size = %d KB\n",
	       blk_size[MAJOR_NR][minor]);

	blksize = max(be32_to_cpu(param.blksize),drbd_ll_blocksize(minor));

	set_blocksize(MKDEV(MAJOR_NR, minor),blksize);
	set_blocksize(drbd_conf[minor].lo_device,blksize);
	drbd_conf[minor].blk_size_b = drbd_log2(blksize);

	printk(KERN_INFO DEVICE_NAME": agreed blksize = %d B\n", blksize);

	/* Do we need to adjust the device size to end on block 
	   boundary ?? I do not think so ! */

	if (!drbd_conf[minor].mbds_id) {
		drbd_conf[minor].mbds_id = 
			drbd_conf[minor].mops->init(MKDEV(MAJOR_NR, minor));
	}
	
	if (drbd_conf[minor].cstate == WFReportParams) {
	        if (drbd_conf[minor].state == Primary
		    && !drbd_conf[minor].conf.skip_sync) {
		        set_cstate(&drbd_conf[minor],SyncingQuick);
			drbd_send_cstate(&drbd_conf[minor]);
			drbd_thread_start(&drbd_conf[minor].syncer);
		} else set_cstate(&drbd_conf[minor],Connected);
	}
	return TRUE;
}


void drbdd(int minor)
{
	Drbd_Packet header;

	while (TRUE) {
		drbd_collect_zombies(minor);

		if (drbd_recv(&drbd_conf[minor],&header,sizeof(Drbd_Packet))!= 
		     sizeof(Drbd_Packet)) 
			break;

		if (be32_to_cpu(header.magic) != DRBD_MAGIC) {
			printk(KERN_ERR DEVICE_NAME ": magic?? m: %ld "
			       "c: %d "
			       "l: %d \n",
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
			drbd_send_ping_ack(minor);
			break;
		case PingAck:
			receive_ping_ack(minor);
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

		default:
			printk(KERN_ERR DEVICE_NAME
			       ": unknown packet type!/m=%d\n", minor);
			goto out;
		}
	}

      out:
	del_timer(&drbd_conf[minor].a_timeout);
	drbd_conf[minor].pending_cnt = 0;

	if (drbd_conf[minor].sock) {
	        drbd_thread_stop(&drbd_conf[minor].syncer);
	        drbd_thread_stop(&drbd_conf[minor].asender);
		sock_release(drbd_conf[minor].sock);
		drbd_conf[minor].sock = 0;
	}

	if(drbd_conf[minor].cstate != Unconfigured)
	        set_cstate(&drbd_conf[minor],Unconnected);

	switch(drbd_conf[minor].state) {
	case Primary:   
		tl_clear(&drbd_conf[minor]);
		clear_bit(ISSUE_BARRIER,&drbd_conf[minor].flags);
		break;
	case Secondary: 
		drbd_conf[minor].epoch_size=0; 
		break;
	}
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
			if (sigismember(&current->signal, SIGTERM)) {
				sigdelset(&current->signal, SIGTERM);
				recalc_sigpending(current);
			}
			spin_unlock_irqrestore(&current->sigmask_lock,flags);
		}
	}

	printk(KERN_DEBUG DEVICE_NAME ": receiver exiting/m=%d\n", minor);

	set_cstate(&drbd_conf[minor],Unconfigured);

	return 0;
}

void drbd_free_resources(int minor)
{
	if (drbd_conf[minor].sock) {
		sock_release(drbd_conf[minor].sock);
		drbd_conf[minor].sock = 0;
	}
	if (drbd_conf[minor].lo_file) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
		blkdev_put(drbd_conf[minor].lo_file->f_dentry->d_inode->i_bdev,
			   BDEV_FILE);
#else
		blkdev_release(drbd_conf[minor].lo_file->f_dentry->
			       d_inode);
#endif
		fput(drbd_conf[minor].lo_file);
		drbd_conf[minor].lo_file = 0;
		drbd_conf[minor].lo_device = 0;
	}
	set_cstate(&drbd_conf[minor],Unconfigured);
}


/* ********* the syncer ******** */

/*
  We can not use getblk()/brelse() here, because we can not
  send (maybe dirty) blocks of the buffer cache.
  We really need to read in the data from our disk.
*/

int drbd_syncer(struct Drbd_thread *thi)
{
	int minor = thi->minor;
	int interval,wait;
	unsigned long before;
	int amount;
	int blocks;
	int blocksize;
	void* page;
	struct buffer_head rbh,*bh;


	sprintf(current->comm, "drbd_syncer_%d", minor);


	amount=drbd_conf[minor].sock->sk->sndbuf >> (1+10);
	/* We want to fill half of the send buffer, we need the size
	   in KB */

	page = (void*)__get_free_page(GFP_USER);

	/* printk(KERN_DEBUG DEVICE_NAME ": syncer living/m=%d\n", minor); */

 cstate_change:
	if(drbd_conf[minor].cstate == SyncingAll) {
		drbd_conf[minor].synced_to=
			(blk_size[MAJOR_NR][minor] -
			 (blksize_size[MAJOR_NR][minor] >> 10)) << 1;
	} else {
		drbd_conf[minor].mops->reset(drbd_conf[minor].mbds_id,
					     drbd_conf[minor].blk_size_b);
	}
restart:
        blocksize = blksize_size[MAJOR_NR][minor];
	/* TODO: Ensure that ll_dev also has the new block-size! */

	/* align synced_to to blocksize */
	if(drbd_conf[minor].cstate == SyncingAll)
		drbd_conf[minor].synced_to=
			drbd_conf[minor].synced_to & ~((blocksize >> 9) - 1);

	interval = amount * HZ / drbd_conf[minor].conf.sync_rate;
	blocks = (amount << 10) / blocksize;

	printk(KERN_INFO DEVICE_NAME ": Synchronisation started "
	       "blks=%d int=%d \n",blocks, interval);

	bh = getblk(MKDEV(MAJOR_NR, minor), 1,blocksize);
	memcpy(&rbh,bh,sizeof(struct buffer_head));
	brelse(bh); /* hehe this is the way to initialize a BH :)  */

	rbh.b_dev = drbd_conf[minor].lo_device;
#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	rbh.b_state = (1 << BH_Req) | (1 << BH_Mapped);
#else
	rbh.b_state = (1 << BH_Req) | (1 << BH_Dirty);
#endif
	rbh.b_list = BUF_LOCKED;
	rbh.b_data = page;
	init_waitqueue_head(&rbh.b_wait);

	rbh.b_next = 0;
	rbh.b_this_page = 0;
	rbh.b_next_free = 0;
	rbh.b_pprev = 0;

	bh=&rbh;

	before = jiffies;

	while (TRUE) {
		int i, rr;
		unsigned long block_nr, new_sector;

		wait = max( interval - (int)(jiffies - before) , 1 );
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(wait);
		before = jiffies;

		for (i = 0; i < blocks; i++) {
			if (thi->t_state == Exiting) goto out;
			if (blocksize != blksize_size[MAJOR_NR][minor])
				goto restart;

			if(drbd_conf[minor].cstate == SyncingAll) {
				block_nr=drbd_conf[minor].synced_to >> 
					(drbd_conf[minor].blk_size_b - 9);
			} else {
				block_nr=drbd_conf[minor].mops->
					get_block(drbd_conf[minor].mbds_id,
						  drbd_conf[minor].blk_size_b);
				if(block_nr == MBDS_DONE) goto done;
				if(block_nr == MBDS_SYNC_ALL) {
					set_cstate(&drbd_conf[minor],
						   SyncingAll);
					drbd_send_cstate(&drbd_conf[minor]);
					goto cstate_change;
				}					
			}

			rbh.b_blocknr=block_nr;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
			rbh.b_state = (1 << BH_Req) | (1 << BH_Mapped);
#else
			rbh.b_state = (1 << BH_Req) | (1 << BH_Dirty);
#endif
			init_waitqueue_head(&rbh.b_wait);
			  /* Hmmm, why do I need this ? */

			ll_rw_block(READ, 1, &bh);
		        if (!buffer_uptodate(bh)) wait_on_buffer(bh);
			if (!buffer_uptodate(bh)) {
                                printk(KERN_ERR DEVICE_NAME ": !uptodate\n");
			        goto out;
			}

			rr = drbd_send_data(&drbd_conf[minor], page,
				       blocksize, block_nr, ID_SYNCER);

			if (rr > 0) {
				drbd_conf[minor].send_cnt++;
			} else {
				printk(KERN_ERR DEVICE_NAME
				       ": syncer send failed!!\n");
				goto out;
			}


			/*
			   printk(KERN_DEBUG DEVICE_NAME ": syncer send: "
			   "block_nr=%ld len=%d\n",
			   block_nr,
			   blocksize);
			 */

			if(drbd_conf[minor].cstate == SyncingAll) {
				new_sector = drbd_conf[minor].synced_to -
					(blocksize >> 9);
				if (new_sector > drbd_conf[minor].synced_to)
					goto done;
				drbd_conf[minor].synced_to=new_sector;
			} 			
		}
	}
 done:
	if(drbd_conf[minor].cstate == SyncingAll ||
           drbd_conf[minor].cstate == SyncingQuick) {
		set_cstate(&drbd_conf[minor],Connected);
		drbd_send_cstate(&drbd_conf[minor]);
	}

 out:
	free_page((unsigned long)page);
	
	drbd_conf[minor].synced_to=0; /* this is ok. */
	printk(KERN_INFO DEVICE_NAME ": Synchronisation done./m=%d\n", minor);

	return 0;
}

/* ********* acknowledge sender for protocol C ******** */
int drbd_asender(struct Drbd_thread *thi)
{
	int minor = thi->minor;
	struct Tl_epoch_entry *epoch = 
	  (struct Tl_epoch_entry *)drbd_conf[minor].transfer_log;

	struct buffer_head **sync_log = drbd_conf[minor].sync_log;


	sprintf(current->comm, "drbd_asender_%d", minor);


	while(thi->t_state == Running) {
	  int i;

	  interruptible_sleep_on(&drbd_conf[minor].asender_wait);	  
	  
	  if(thi->t_state == Exiting) break;

	  if(test_and_clear_bit(SEND_PING,&drbd_conf[minor].flags)) {
		  drbd_send_ping(minor);
	  }

	  if( drbd_conf[minor].state == Primary ) {
		  drbd_try_send_barrier(&drbd_conf[minor]);
		  continue;
	  }

	  spin_lock(&drbd_conf[minor].sl_lock);
	  for(i=0;i<SYNC_LOG_S;i++) {
		  if(sync_log[i]) {
			  if(buffer_uptodate(sync_log[i])) {
				  unsigned long bnr;
				  bnr = sync_log[i]->b_blocknr;
				  brelse(sync_log[i]);
				  sync_log[i]=0;
				  spin_unlock(&drbd_conf[minor].sl_lock);
				  drbd_send_ack(&drbd_conf[minor],WriteAck,
						bnr,ID_SYNCER);
				  spin_lock(&drbd_conf[minor].sl_lock);
			  }
		  }		  
	  }
	  spin_unlock(&drbd_conf[minor].sl_lock);

	  if(drbd_conf[minor].conf.wire_protocol != DRBD_PROT_C) continue;

	  spin_lock(&drbd_conf[minor].es_lock);

	  for(i=0;i<drbd_conf[minor].epoch_size;i++) {
		  if(epoch[i].block_id) {
			  if(buffer_uptodate(epoch[i].bh)) {
				  u64 block_id = epoch[i].block_id;
				  epoch[i].block_id=0;
				  spin_unlock(&drbd_conf[minor].es_lock);
				  drbd_send_ack(&drbd_conf[minor],WriteAck,
						epoch[i].bh->b_blocknr,
						block_id);
				  drbd_conf[minor].unacked_cnt--;
				  spin_lock(&drbd_conf[minor].es_lock);
			  }
		  }
	  }
	  spin_unlock(&drbd_conf[minor].es_lock);

	}

	return 0;
}


/*********************************/

/*** The bitmap stuff. ***/
/*
  We need to store one bit for a block. 
  Example: 1GB disk @ 4096 byte blocks ==> we need 32 KB bitmap.
  Bit 0 ==> Primary and secondary nodes are in sync.
  Bit 1 ==> secondary node's block must be updated.
*/

#include <asm/types.h>
#include <linux/vmalloc.h>

#define BM_BLOCK_SIZE_B  12  
#define BM_BLOCK_SIZE    (1<<12)

#define BM_IN_SYNC       0
#define BM_OUT_OF_SYNC   1

#if BITS_PER_LONG == 32
#define LN2_BPL 5
#elif BITS_PER_LONG == 64
#define LN2_BPL 6
#else
#error "LN2 of BITS_PER_LONG unknown!"
#endif

struct BitMap {
	kdev_t dev;
	unsigned long size;
	unsigned long* bm;
	unsigned long sb_bitnr;
	unsigned long sb_mask;
	unsigned long gb_bitnr;
	unsigned long gb_snr;
	spinlock_t bm_lock;
};

void* bm_init(kdev_t dev)
{
        struct BitMap* sbm;
	unsigned long size;

	size = blk_size[MAJOR(dev)][MINOR(dev)]>>(BM_BLOCK_SIZE_B-7);
	/* 7 = 10 - 3 ; 10 => blk_size is KB ; 3 -> 2^3=8 Bits per Byte */

	if(size == 0) return 0;

	sbm = vmalloc(size + sizeof(struct BitMap));

	sbm->dev = dev;
	sbm->size = size;
	sbm->bm = (unsigned long*)((char*)sbm + sizeof(struct BitMap));
	sbm->sb_bitnr=0;
	sbm->sb_mask=0;
	sbm->gb_bitnr=0;
	sbm->gb_snr=0;
	sbm->bm_lock = SPIN_LOCK_UNLOCKED;

	memset(sbm->bm,0,size);

	printk(KERN_INFO DEVICE_NAME ": vmallocing %ld B for bitmap."
	       " @%p\n",size,sbm->bm);
  
	return sbm;
}     

void bm_cleanup(void* bm_id)
{
        vfree(bm_id);
}

/* THINK:
   What happens when the block_size (ln2_block_size) changes between
   calls 
*/

void bm_set_bit(void* bm_id,unsigned long blocknr,int ln2_block_size, int bit)
{
        struct BitMap* sbm = (struct BitMap*) bm_id;
        unsigned long* bm = sbm->bm;
	unsigned long bitnr;
	int cb = (BM_BLOCK_SIZE_B-ln2_block_size);

	//if(bit) printk("Block %ld out of sync\n",blocknr);
	//else    printk("Block %ld now in sync\n",blocknr);
		

	bitnr = blocknr >> cb;

 	spin_lock(&sbm->bm_lock);

	if(!bit && cb) {
		if(sbm->sb_bitnr == bitnr) {
		        sbm->sb_mask |= 1 << (blocknr & ((1<<cb)-1));
			if(sbm->sb_mask != (1<<(1<<cb))-1) goto out;
		} else {
	                sbm->sb_bitnr = bitnr;
			sbm->sb_mask = 1 << (blocknr & ((1<<cb)-1));
			goto out;
		}
	}

	if(bitnr>>LN2_BPL >= sbm->size) {
		printk(KERN_ERR DEVICE_NAME": BitMap too small!\n");	  
		goto out;
	}

	bm[bitnr>>LN2_BPL] = bit ?
	  bm[bitnr>>LN2_BPL] |  ( 1 << (bitnr & ((1<<LN2_BPL)-1)) ) :
	  bm[bitnr>>LN2_BPL] & ~( 1 << (bitnr & ((1<<LN2_BPL)-1)) );

 out:
	spin_unlock(&sbm->bm_lock);
}

inline int bm_get_bn(unsigned long word,int nr)
{
	if(nr == BITS_PER_LONG-1) return -1;
	word >>= ++nr;
	while (! (word & 1)) {
                word >>= 1;
		if (++nr == BITS_PER_LONG) return -1;
	}
	return nr;
}

unsigned long bm_get_blocknr(void* bm_id,int ln2_block_size)
{
        struct BitMap* sbm = (struct BitMap*) bm_id;
        unsigned long* bm = sbm->bm;
	unsigned long wnr;
	unsigned long nw = sbm->size/sizeof(unsigned long);
	unsigned long rv;
	int cb = (BM_BLOCK_SIZE_B-ln2_block_size);

 	spin_lock(&sbm->bm_lock);

	if(sbm->gb_snr >= (1<<cb)) {	  
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
 r_out:
 	spin_unlock(&sbm->bm_lock);	
	return rv;
}

void bm_reset(void* bm_id,int ln2_block_size)
{
	struct BitMap* sbm = (struct BitMap*) bm_id;

 	spin_lock(&sbm->bm_lock);

	sbm->gb_bitnr=0;
	if (sbm->bm[0] & 1) sbm->gb_snr=0;
	else sbm->gb_snr = 1<<(BM_BLOCK_SIZE_B-ln2_block_size);

 	spin_unlock(&sbm->bm_lock);	
}

struct mbds_operations bm_mops = {
	bm_init,
	bm_cleanup,
	bm_reset,
	bm_set_bit,
	bm_get_blocknr
};
