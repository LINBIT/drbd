/*
-*- linux-c -*-
   drbd_syncer.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

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
	void* buffers;
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

/*static */void ds_end_dio(struct buffer_head *bh, int uptodate)
{
	mark_buffer_uptodate(bh, uptodate);
	clear_bit(BH_Lock, &bh->b_state);

	if (waitqueue_active(&bh->b_wait))
		wake_up(&bh->b_wait);
}


void ds_buffer_init(struct ds_buffer *this,int minor)
{
	int i;

	for (i=0;i<this->number;i++) {
		drbd_init_bh(this->bhs+i,
			     this->b_size,
			     this->buffers + i*this->b_size,
			     ds_end_dio);
	}
}

void ds_buffer_alloc(struct ds_buffer *this,int minor)
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

	this->buffers = (void*)__get_free_pages(GFP_USER,
					      drbd_log2(amount>>PAGE_SHIFT));

	size = 	sizeof(unsigned long)*amount_blks + 
		sizeof(struct buffer_head)*amount_blks;

	mem = kmalloc(size,GFP_USER);
	this->blnr = (unsigned long*) mem;
	mem = mem + sizeof(unsigned long)*amount_blks;
	this->bhs = (struct buffer_head*) mem;

	ds_buffer_init(this,minor);
}

void ds_buffer_free(struct ds_buffer *this)
{
	int amount;

	amount=this->number*this->b_size;
	free_pages((unsigned long)this->buffers,drbd_log2(amount>>PAGE_SHIFT));
	kfree(this->blnr);
}

int ds_buffer_read(struct ds_buffer *this,
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

int ds_buffer_reread(struct ds_buffer *this,int minor)
{
	//TODO: Is the busy-blocks check missing here ?
	int i,count;
	
	count=this->io_pending_number;

	for(i=0;i<count;i++) {
		drbd_set_bh(this->bhs+count,
			    this->blnr[i],
			    drbd_conf[minor].lo_device);

		clear_bit(BH_Uptodate, &this->bhs[count].b_state);
		set_bit(BH_Lock, &this->bhs[count].b_state);
		submit_bh(READ,this->bhs+count);
	}
		
	if(count) {
		run_task_queue(&tq_disk);
	}

	return count;
}

int ds_buffer_wait_on(struct ds_buffer *this,int minor)
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

inline void ds_buffer_done(struct ds_buffer *this,int minor)
{
	int i,pending=this->io_pending_number;

	this->io_pending_number=0;
	for(i=0;i<pending;i++) {
		bb_done(drbd_conf+minor,this->blnr[i]);
	}
}

int ds_buffer_send(struct ds_buffer *this,int minor)
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

unsigned long ds_sync_all_get_blk(void* id, int ln2_bs)
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

int drbd_syncer(struct Drbd_thread *thi)
{
	int minor = thi->minor;
	struct ds_buffer buffers[2];
	struct ds_buffer *disk_b, *net_b, *tmp;
	int amount,amount_blks,interval;
	int my_blksize,ln2_bs,retry;
	unsigned long (*get_blk)(void*,int);
	void* id;
	unsigned long flags;

	sprintf(current->comm, "drbd_syncer_%d", minor);

	amount=drbd_conf[minor].sock->sk->sndbuf >> (1+10);
	/* We want to fill half of the send buffer in KB */
	interval = max_t(int, amount*HZ/drbd_conf[minor].conf.sync_rate, 1);
	my_blksize=blksize_size[MAJOR_NR][minor];
	ln2_bs = drbd_log2(my_blksize);
	amount_blks=(amount<<10)/my_blksize;

	printk(KERN_INFO DEVICE_NAME "%d: Synchronisation started "
	       "blks=%d int=%d \n",minor,amount_blks,interval);

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


	ds_buffer_alloc(&buffers[0],minor);
	ds_buffer_alloc(&buffers[1],minor);
	disk_b=buffers;
	net_b=buffers+1;
	
	spin_lock_irqsave(&drbd_conf[minor].bb_lock,flags);
	drbd_conf[minor].syncer_b = buffers;
	spin_unlock_irqrestore(&drbd_conf[minor].bb_lock,flags);
	
	ds_buffer_read(disk_b,get_blk,id,minor);
	while (TRUE) {
		retry=0;
	retry:
		current->state = TASK_INTERRUPTIBLE;
		schedule_timeout(interval);
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
	drbd_send_cmd(minor,SetConsistent,0);
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

