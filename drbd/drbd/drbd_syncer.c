/*
-*- linux-c -*-
   drbd_syncer.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

   Copyright (C) 2002, Lars Ellenberg <l.g.e@web.de>.
        changed scheduling algorithm
        keep track of syncer progress

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
#include <asm/bitops.h> 
#include <net/sock.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/pkt_sched.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>

#include "drbd.h"
#include "drbd_int.h"


/*
  We can not use getblk()/bforget() here, because we can not
  send (maybe dirty) blocks of the buffer cache.
  We really need to read in the data from our disk.
*/

struct ds_buffer {
	page_t* buffers;
	unsigned long *blnr;
	struct buffer_head *bhs;
	int number;
	int io_pending_number;
	int b_size;
};

int ds_check_block(struct Drbd_Conf *mdev, unsigned long bnr)
{
	struct ds_buffer *buffer;

	buffer=mdev->syncer_b;
	if(buffer) {
		int i,j,pending;
		for(j=0;j<2;j++) {
			pending=buffer[j].io_pending_number;
			for(i=0;i<pending;i++) {
				if( buffer[j].blnr[i] == bnr ) 
				{ return TRUE; }
			}
		}
	}
	return FALSE;
}

STATIC void ds_end_dio(struct buffer_head *bh, int uptodate)
{
	mark_buffer_uptodate(bh, uptodate);
	clear_bit(BH_Lock, &bh->b_state);

	if (waitqueue_active(&bh->b_wait))
		wake_up(&bh->b_wait);
}

STATIC void ds_buffer_init(struct ds_buffer *this,int minor)
{
	int i;
	int bpp = PAGE_SIZE/this->b_size; // buffers per page

	for (i=0;i<this->number;i++) {
		drbd_init_bh(this->bhs+i,
			     this->b_size,
			     ds_end_dio);
		set_bh_page(this->bhs+i,
			    this->buffers + i/bpp,
			    (i % bpp) * this->b_size);// sets b_data and b_page
	}
}

STATIC void ds_buffer_alloc(struct ds_buffer *this,int minor)
{
	int amount,amount_blks,blocksize,size;
	unsigned char* mem;

	amount=drbd_conf[minor].sock->sk->sndbuf >> 1;
	/* We want to fill half of the send buffer*/
	blocksize=blksize_size[MAJOR_NR][minor];
	amount_blks=amount/blocksize;
	this->number=amount_blks;
	this->io_pending_number=0;
	this->b_size=blocksize;

	this->buffers=alloc_pages(GFP_USER,drbd_log2(amount>>PAGE_SHIFT));
	if(this->buffers == NULL) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: could not get free pages\n",minor);
		BUG();
	}

	size = 	sizeof(unsigned long)*amount_blks + 
		sizeof(struct buffer_head)*amount_blks;

	mem = kmalloc(size,GFP_USER);
	if( mem == NULL ) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: could not kmalloc() in ds_buffer_alloc\n",minor);
		BUG();
	} 

	this->blnr = (unsigned long*) mem;
	mem = mem + sizeof(unsigned long)*amount_blks;
	this->bhs = (struct buffer_head*) mem;

	ds_buffer_init(this,minor);
}

STATIC void ds_buffer_free(struct ds_buffer *this)
{
	int amount;

	amount=this->number*this->b_size;
	drbd_free_pages(this->buffers,drbd_log2(amount>>PAGE_SHIFT));
	kfree(this->blnr);
}

STATIC int ds_buffer_read(struct ds_buffer *this,
		   unsigned long (*get_blk)(void*,int),
		   void* id,
		   int minor)
{
	int count=0;
	int amount_blks=this->number;
	int ln2_bs = drbd_log2(this->b_size);
	unsigned long flags;

	spin_lock_irqsave(&drbd_conf[minor].bb_lock,flags);
	while (count < amount_blks) {
		unsigned long block_nr;

		block_nr=get_blk(id,ln2_bs);
		if(block_nr == MBDS_DONE) break;

                // because bb_wait releases bb_lock
		this->io_pending_number=count; 

		this->blnr[count]=block_nr;
				
		if(tl_check_sector(drbd_conf+minor,block_nr << (ln2_bs-9))) {
			bb_wait(drbd_conf+minor,block_nr,&flags);
		}

		drbd_set_bh(this->bhs+count,
			    block_nr,
			    drbd_conf[minor].lo_device);
		clear_bit(BH_Uptodate, &this->bhs[count].b_state);
		set_bit(BH_Lock, &this->bhs[count].b_state);
		submit_bh(READ,this->bhs+count);
		count++;
	}
	this->io_pending_number=count; 
	spin_unlock_irqrestore(&drbd_conf[minor].bb_lock,flags);

	if(count) {
		run_task_queue(&tq_disk);
	}
	return count;
}

STATIC int ds_buffer_reread(struct ds_buffer *this,int minor)
{
	int i,count;
	unsigned long flags;
	unsigned long block_nr;
	int ln2_bs = drbd_log2(this->b_size);
	
	count=this->io_pending_number;

	spin_lock_irqsave(&drbd_conf[minor].bb_lock,flags);
	for(i=0;i<count;i++) {

		block_nr = this->blnr[i];

		if(tl_check_sector(drbd_conf+minor,block_nr << (ln2_bs-9))) {
			bb_wait(drbd_conf+minor,block_nr,&flags);
		}

		drbd_set_bh(this->bhs+i, block_nr,
			    drbd_conf[minor].lo_device);

		clear_bit(BH_Uptodate, &this->bhs[i].b_state);
		set_bit(BH_Lock, &this->bhs[i].b_state);
		submit_bh(READ,this->bhs+i);
	}
	spin_unlock_irqrestore(&drbd_conf[minor].bb_lock,flags);

	if(count) {
		run_task_queue(&tq_disk);
	}

	return count;
}

STATIC int ds_buffer_wait_on(struct ds_buffer *this,int minor)
{
	int i;
	int pending=this->io_pending_number;
	int size_kb=blksize_size[MAJOR_NR][minor]>>10;
	
	for(i=0;i<pending;i++) {
		struct buffer_head *bh;
		bh=&this->bhs[i];		
		if (!buffer_uptodate(bh)) wait_on_buffer(bh);
		if (!buffer_uptodate(bh)) {
			printk(KERN_ERR DEVICE_NAME "%d: !uptodate\n", minor);
			return -1;
		}
		drbd_conf[minor].read_cnt+=size_kb;
	}
	return pending;
}

STATIC inline void ds_buffer_done(struct ds_buffer *this,int minor)
{
	int i,pending=this->io_pending_number;

	this->io_pending_number=0;
	for(i=0;i<pending;i++) {
		bb_done(drbd_conf+minor,this->blnr[i]);
	}
}

STATIC int ds_buffer_send(struct ds_buffer *this,int minor)
{
	int i,blocksize,rr,rv=TRUE;
	int pending=this->io_pending_number;
	unsigned long flags;

	blocksize=blksize_size[MAJOR_NR][minor];

	for(i=0;i<pending;i++) {
		rr=drbd_send_block(&drbd_conf[minor],&this->bhs[i],ID_SYNCER);

		if(rr < blocksize) {
			printk(KERN_ERR DEVICE_NAME 
			       "%d: syncer send failed!!\n",minor);
			rv=FALSE;
			break;
		}
	}

	spin_lock_irqsave(&drbd_conf[minor].bb_lock,flags);
	ds_buffer_done(this,minor);
	spin_unlock_irqrestore(&drbd_conf[minor].bb_lock,flags);

	return rv;
}

STATIC unsigned long ds_sync_all_get_blk(void* id, int ln2_bs)
{
	struct Drbd_Conf *mdev=(struct Drbd_Conf *)id;
	int shift=ln2_bs - 9;
	
	if(mdev->synced_to == 0) {
		return MBDS_DONE;
	}
	
	mdev->synced_to -= (1L<<shift);
	return mdev->synced_to >> shift;
}

#define swap(a,b) { tmp=a; a=b; b=tmp; }

/*lge
 * progress bars shamelessly adapted from drivers/md/md.c
 */
/* hardcoded for now */
#define SPEED_MAX (mdev->conf.sync_rate)
#define SPEED_MIN 150
#define SYNC_MARKS      10
#define SYNC_MARK_STEP  (3*HZ)
#ifdef CONFIG_MAX_USER_RT_PRIO
	/* this should work for the O(1) scheduler */
#define drbd_set_user_nice(current,x) set_user_nice(current,(x))
#else
	/* FIXME which kernel introduced ->nice ? */
# if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
	/* for 2.2 kernel */
#  define drbd_set_user_nice(current,x) (current->priority = 20-(x))
# else
	/* 2.4 */
#  define drbd_set_user_nice(current,x) (current->nice = (x))
# endif
#endif

int drbd_syncer(struct Drbd_thread *thi)
{
	int minor = thi->minor;
	struct ds_buffer buffers[2];
	struct ds_buffer *disk_b, *net_b, *tmp;
	int amount,amount_blks;
	int my_blksize,ln2_bs,retry;
	unsigned long (*get_blk)(void*,int);
	void* id;
	unsigned long flags;
	unsigned long mark[SYNC_MARKS];
	unsigned long mark_cnt[SYNC_MARKS];
	unsigned int currspeed;
	int last_mark,m;

	sprintf(current->comm, "drbd_syncer_%d", minor);

	amount=drbd_conf[minor].sock->sk->sndbuf >> (1+10);
	/* We want to fill half of the send buffer in KB */
	my_blksize=blksize_size[MAJOR_NR][minor];
	ln2_bs = drbd_log2(my_blksize);
	amount_blks=(amount<<10)/my_blksize;

	printk(KERN_INFO DEVICE_NAME "%d: Synchronisation started blks=%d\n",
		minor,amount_blks);

	if(drbd_conf[minor].cstate == SyncingAll) {
		drbd_conf[minor].synced_to =
			( (blk_size[MAJOR_NR][minor] >> (ln2_bs-10))
			  << (ln2_bs-9) );
		// truncate to full blocks; convert to sectors;
		get_blk=&ds_sync_all_get_blk;
		id=drbd_conf+minor;
        } else if(drbd_conf[minor].cstate == SyncingQuick) {
		bm_reset(drbd_conf[minor].mbds_id,
			 drbd_conf[minor].blk_size_b);
		get_blk=(unsigned long (*)(void*,int))&bm_get_blocknr;
		id=drbd_conf[minor].mbds_id;
        } else { 
                /* print warning/error ? */
		return 0;
	}

	for (m = 0; m < SYNC_MARKS; m++) {
		mark[m] = jiffies;
		mark_cnt[m] = drbd_conf[minor].synced_to;
	}
	last_mark = 0;
	drbd_conf[minor].resync_mark_start = mark[last_mark];
	drbd_conf[minor].resync_mark = mark[last_mark];
	drbd_conf[minor].resync_mark_cnt = mark_cnt[last_mark];

	ds_buffer_alloc(&buffers[0],minor);
	ds_buffer_alloc(&buffers[1],minor);
	disk_b=buffers;
	net_b=buffers+1;
	
	spin_lock_irqsave(&drbd_conf[minor].bb_lock,flags);
	drbd_conf[minor].syncer_b = buffers;
	spin_unlock_irqrestore(&drbd_conf[minor].bb_lock,flags);
	
	ds_buffer_read(disk_b,get_blk,id,minor);

	/*
	 * Resync has low priority.
	 */
	drbd_set_user_nice(current,19);

	while (TRUE) {
		struct Drbd_Conf *mdev = drbd_conf+minor;
		retry=0;
	retry:
		if (jiffies >= mark[last_mark] + SYNC_MARK_STEP) {
			/* step marks */
			int next = (last_mark+1) % SYNC_MARKS;

			mdev->resync_mark = mark[next];
			mdev->resync_mark_cnt = mark_cnt[next];
			mark[next] = jiffies;
		/*
		 * there may be an issue due to non atomic_t of synced_to, etc.
		 * could even be related to "access beyond end of device"
		 * please tell me I'm wrong.             lge
		 */
			mark_cnt[next] = mdev->synced_to;
			last_mark = next;
		}
		/*
		 * FIXME what to do with signal_pending ?
		 */
		if (current->need_resched)
			schedule();

		currspeed = (mdev->resync_mark_cnt - mdev->synced_to)/2
		          / ((jiffies - mdev->resync_mark)/HZ +1)         +1;
		
		if (currspeed > SPEED_MIN) {
			drbd_set_user_nice(current,19);
			                          
			if ((currspeed > SPEED_MAX)
				/* what to do with this one?
				|| !is_mddev_idle(mddev) */
				)
			{
				current->state = TASK_INTERRUPTIBLE;
				schedule_timeout(HZ/2);
				goto retry;
				/* this is no retry++, but slowdown */
			}
		} else
			drbd_set_user_nice(current,-20);

		switch(ds_buffer_wait_on(disk_b,minor)) {
		case 0: goto done;  /* finished */
		case -1:
			if(my_blksize != blksize_size[MAJOR_NR][minor]) {
				printk(KERN_ERR DEVICE_NAME 
				       "%d: Changing blksize not supported\n"
				       "Please consider contributing it!\n",
				       minor);
			} else {
				printk(KERN_ERR DEVICE_NAME 
				       "%d: Syncer reread.\n",minor);
				ds_buffer_init(disk_b,minor);
				ds_buffer_reread(disk_b,minor);
			}
			if(retry++ < 5) goto retry;
			printk(KERN_ERR DEVICE_NAME 
			       "%d: Syncer read failed.\n",minor);
			goto err;
		}
		swap(disk_b,net_b);
		if(thi->t_state == Exiting) {
			ds_buffer_send(net_b,minor);
			printk(KERN_ERR DEVICE_NAME 
			       "%d: Syncer aborted.\n",minor);
			goto err;
		}
		ds_buffer_read(disk_b,get_blk,id,minor);       
		if(!ds_buffer_send(net_b,minor)) {
			ds_buffer_wait_on(disk_b,minor);
			printk(KERN_ERR DEVICE_NAME 
			       "%d: Syncer send failed.\n",minor);
			goto err;
		}
	}
	
 done:
	drbd_send_cmd(drbd_conf+minor,SetConsistent,0);
	printk(KERN_INFO DEVICE_NAME "%d: Synchronisation done.\n",minor);

 err:
	if(drbd_conf[minor].cstate == SyncingAll || 
	   drbd_conf[minor].cstate == SyncingQuick) {
		set_cstate(&drbd_conf[minor],Connected);
		drbd_send_cstate(&drbd_conf[minor]);
	}

	spin_lock_irqsave(&drbd_conf[minor].bb_lock,flags);
	drbd_conf[minor].syncer_b = 0;
	ds_buffer_done(disk_b,minor);
	ds_buffer_done(net_b,minor);
	spin_unlock_irqrestore(&drbd_conf[minor].bb_lock,flags);

	ds_buffer_free(&buffers[0]);
	ds_buffer_free(&buffers[1]);

	drbd_conf[minor].synced_to=0; /* this is ok. */

	return 0;
}
#undef SPEED_MIN
#undef SPEED_MAX
#undef SYNC_MARKS
#undef SYNC_MARK_STEP
#undef drbd_set_user_nice
