/*
-*- linux-c -*-
   drbd_proc.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2004, Philipp Reisner <philipp.reisner@linbit.com>.
	main author.

   Copyright (C) 2002-2004, Lars Ellenberg <l.g.e@web.de>.
	main contributor.

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

#include <linux/config.h>
#include <linux/module.h>

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/drbd.h>
#include "drbd_int.h"
#include "lru_cache.h" /* for lc_sprintf_stats */

STATIC int drbd_proc_open(struct inode *inode, struct file *file);


struct proc_dir_entry *drbd_proc;
struct file_operations drbd_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= drbd_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*lge
 * progress bars shamelessly adapted from driver/md/md.c
 * output looks like
 *	[=====>..............] 33.5% (23456/123456)
 *	finish: 2:20:20 speed: 6,345 (6,456) K/sec
 */
STATIC void drbd_syncer_progress(struct Drbd_Conf* mdev, struct seq_file *seq)
{
	unsigned long res , db, dt, dbdt, rt, rs_left;

	/* the whole sector_div thingy was wrong (did overflow,
	 * did not use correctly typed parameters), and is not even
	 * neccessary as long as rs_total and drbd_bm_total_weight
	 * are both unsigned long.
	 *
	 * this is to break it at compile time when we change that
	 * (we may feel 4TB maximum storage per drbd is not enough)
	 */
	typecheck(unsigned long, mdev->rs_total);

	/* note: both rs_total and rs_left are in bits, i.e. in
	 * units of BM_BLOCK_SIZE.
	 * for the percentage, we don't care. */

	rs_left = drbd_bm_total_weight(mdev);
	/* >> 10 to prevent overflow,
	 * +1 to prevent division by zero */
	if (rs_left > mdev->rs_total) {
		/* doh. logic bug somewhere.
		 * for now, just try to prevent in-kernel buffer overflow.
		 */
		ERR("logic bug? rs_left=%lu > rs_total=%lu\n",
				rs_left, mdev->rs_total);
		res = 1000;
	} else {
		res = (rs_left >> 10)*1000/((mdev->rs_total >> 10) + 1);
	}
	{
		int i, y = res/50, x = 20-y;
		seq_printf(seq, "\t[");
		for (i = 1; i < x; i++)
			seq_printf(seq, "=");
		seq_printf(seq, ">");
		for (i = 0; i < y; i++)
			seq_printf(seq, ".");
		seq_printf(seq, "] ");
	}
	res = 1000L - res;
	seq_printf(seq,"sync'ed:%3lu.%lu%% ", res / 10, res % 10);
	/* if more than 1 GB display in MB */
	if (mdev->rs_total > 0x100000L) {
		seq_printf(seq,"(%lu/%lu)M\n\t",
			    (unsigned long) Bit2KB(rs_left) >> 10,
			    (unsigned long) Bit2KB(mdev->rs_total) >> 10 );
	} else {
		seq_printf(seq,"(%lu/%lu)K\n\t",
			    (unsigned long) Bit2KB(rs_left),
			    (unsigned long) Bit2KB(mdev->rs_total) );
	}

	/* see drivers/md/md.c
	 * We do not want to overflow, so the order of operands and
	 * the * 100 / 100 trick are important. We do a +1 to be
	 * safe against division by zero. We only estimate anyway.
	 *
	 * dt: time from mark until now
	 * db: blocks written from mark until now
	 * rt: remaining time
	 */
	dt = (jiffies - mdev->rs_mark_time) / HZ;

	if (dt > 20) {
		/* if we made no update to rs_mark_time for too long,
		 * we are stalled. show that. */
		seq_printf(seq, "stalled\n");
		return;
	}

	if (!dt) dt++;
	db = mdev->rs_mark_left - rs_left;
	rt = (dt * (rs_left / (db/100+1)))/100; /* seconds */

	seq_printf(seq, "finish: %lu:%02lu:%02lu",
		rt / 3600, (rt % 3600) / 60, rt % 60);

	/* current speed average over (SYNC_MARKS * SYNC_MARK_STEP) jiffies */
	dbdt = Bit2KB(db/dt);
	if (dbdt > 1000)
		seq_printf(seq, " speed: %ld,%03ld",
			dbdt/1000,dbdt % 1000);
	else
		seq_printf(seq, " speed: %ld", dbdt);

	/* mean speed since syncer started
	 * we do account for PausedSync periods */
	dt = (jiffies - mdev->rs_start - mdev->rs_paused) / HZ;
	if (dt <= 0) dt=1;
	db = mdev->rs_total - rs_left;
	dbdt = Bit2KB(db/dt);
	if (dbdt > 1000)
		seq_printf(seq, " (%ld,%03ld)",
			dbdt/1000,dbdt % 1000);
	else
		seq_printf(seq, " (%ld)", dbdt);

	seq_printf(seq," K/sec\n");
}

#if 0
STATIC void resync_dump_detail(struct seq_file *seq, struct lc_element * e)
{
	struct bm_extent *bme = (struct bm_extent *)e;

	seq_printf(seq,"%5d %s %s\n",bme->rs_left,
		   bme->flags & BME_NO_WRITES ? "NO_WRITES" : "---------",
		   bme->flags & BME_LOCKED ? "LOCKED" : "------"
		   );
}
#endif

STATIC int drbd_seq_show(struct seq_file *seq, void *v)
{
	int i;
	const char *sn;

	seq_printf(seq, "version: " REL_VERSION " (api:%d/proto:%d)\n%s\n",
		    API_VERSION,PRO_VERSION, drbd_buildtag());

	/*
	  cs .. connection state
	  st .. node state (local/remote)
	  ld .. local data consistentency
	  ns .. network send
	  nr .. network receive
	  dw .. disk write
	  dr .. disk read
	  pe .. pending (waiting for ack)
	  ua .. unack'd (still need to send ack)
	  al .. access log write count
	*/

	for (i = 0; i < minor_count; i++) {
		sn = conns_to_name(drbd_conf[i].state.conn);

		if ( drbd_conf[i].state.conn == StandAlone &&
		     drbd_conf[i].state.disk == Diskless) {
			seq_printf( seq, "%2d: cs:Unconfigured\n", i);
		} else {
			seq_printf( seq,
			   "%2d: cs:%s st:%s/%s ds:%s/%s\n"
			   "    ns:%u nr:%u dw:%u dr:%u al:%u bm:%u "
			   "lo:%d pe:%d ua:%d ap:%d\n",
			   i, sn,
			   roles_to_name(drbd_conf[i].state.role),
			   roles_to_name(drbd_conf[i].state.peer),
			   disks_to_name(drbd_conf[i].state.disk),
			   disks_to_name(drbd_conf[i].state.pdsk),
			   drbd_conf[i].send_cnt/2,
			   drbd_conf[i].recv_cnt/2,
			   drbd_conf[i].writ_cnt/2,
			   drbd_conf[i].read_cnt/2,
			   drbd_conf[i].al_writ_cnt,
			   drbd_conf[i].bm_writ_cnt,
			   atomic_read(&drbd_conf[i].local_cnt),
			   atomic_read(&drbd_conf[i].ap_pending_cnt) +
			   atomic_read(&drbd_conf[i].rs_pending_cnt),
			   atomic_read(&drbd_conf[i].unacked_cnt),
			   atomic_read(&drbd_conf[i].ap_bio_cnt)
			);
		}
		if ( drbd_conf[i].state.conn == SyncSource ||
		     drbd_conf[i].state.conn == SyncTarget ) {
			drbd_syncer_progress(drbd_conf+i,seq);
		}
		if(drbd_conf[i].resync) {
			lc_printf_stats(seq,drbd_conf[i].resync);
		}
		if(drbd_conf[i].act_log) {
			lc_printf_stats(seq,drbd_conf[i].act_log);
		}
#if 0
		if(drbd_conf[i].resync) {
			lc_dump(drbd_conf[i].resync,seq,"rs_left",
				resync_dump_detail);
		}
#endif

	}

	return 0;
}

STATIC int drbd_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, drbd_seq_show, PDE(inode)->data);
}

/* PROC FS stuff end */
