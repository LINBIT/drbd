/*
-*- linux-c -*-
   drbd_proc.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

   Copyright (C) 2002-2003, Lars Ellenberg <l.g.e@web.de>.
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

#ifdef HAVE_AUTOCONF
#include <linux/autoconf.h>
#endif
#ifdef CONFIG_MODVERSIONS
#include <linux/modversions.h>
#endif

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/drbd.h>
#include "drbd_int.h"

int drbd_proc_get_info(char *, char **, off_t, int, int *, void *);

struct proc_dir_entry *drbd_proc;

/*lge
 * progress bars shamelessly adapted from driver/md/md.c
 * output looks like
 *	[=====>..............] 33.5% (23456/123456)
 *	finish: 2:20:20 speed: 6,345 (6,456) K/sec
 */
STATIC int drbd_syncer_progress(struct Drbd_Conf* mdev,char *buf)
{
	int sz = 0;
	unsigned long res , db, dt, dbdt, rt;
	sector_t n;

	n = (mdev->rs_left>>11)*1000;
	sector_div(n,((mdev->rs_total>>11) + 1));
	res = n;
	{
		int i, y = res/50, x = 20-y;
		sz += sprintf(buf + sz, "\t[");
		for (i = 1; i < x; i++)
			sz += sprintf(buf + sz, "=");
		sz += sprintf(buf + sz, ">");
		for (i = 0; i < y; i++)
			sz += sprintf(buf + sz, ".");
		sz += sprintf(buf + sz, "] ");
	}
	res = 1000L - res;
	sz+=sprintf(buf+sz,"sync'ed:%3lu.%lu%% ", res / 10, res % 10);
	if (mdev->rs_total > 0x100000L) /* if more than 1 GB display in MB */
		sz+=sprintf(buf+sz,"(%lu/%lu)M\n\t",
			    (unsigned long) mdev->rs_left>>11, 
			    (unsigned long) mdev->rs_total>>11);
	else
		sz+=sprintf(buf+sz,"(%lu/%lu)K\n\t", 
			    (unsigned long) mdev->rs_left>>1, 
			    (unsigned long) mdev->rs_total>>1);

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
	if (!dt) dt++;
	db = (mdev->rs_mark_left - mdev->rs_left)>>1;
	n = mdev->rs_left>>1;
	sector_div(n,(db/100+1));
	rt = ( dt * (unsigned long) n ) / 100; /* seconds */

	sz += sprintf(buf + sz, "finish: %lu:%02lu:%02lu",
		rt / 3600, (rt % 3600) / 60, rt % 60);


	/* current speed average over (SYNC_MARKS * SYNC_MARK_STEP) jiffies */
	if ((dbdt=db/dt) > 1000)
		sz += sprintf(buf + sz, " speed: %ld,%03ld",
			dbdt/1000,dbdt % 1000);
	else
		sz += sprintf(buf + sz, " speed: %ld", dbdt);

	/* mean speed since syncer started */
	dt = (jiffies - mdev->rs_start) / HZ;
	if (!dt) dt++;
	db = (mdev->rs_total - mdev->rs_left)>>1;
	if ((dbdt=db/dt) > 1000)
		sz += sprintf(buf + sz, " (%ld,%03ld)",
			dbdt/1000,dbdt % 1000);
	else
		sz += sprintf(buf + sz, " (%ld)", dbdt);

	sz += sprintf(buf+sz," K/sec\n");

	return sz;
}

int drbd_proc_get_info(char *buf, char **start, off_t offset,
		       int len, int *unused, void *data)
{
	int rlen, i;
	const char *sn;

	static const char *cstate_names[] = {
		[Unconfigured]   = "Unconfigured",
		[StandAlone]     = "StandAlone",
		[Unconnected]    = "Unconnected",
		[Timeout]        = "Timeout",
		[BrokenPipe]     = "BrokenPipe",
		[WFConnection]   = "WFConnection",
		[WFReportParams] = "WFReportParams",
		[Connected]      = "Connected",
		[SkippedSyncS]   = "SkippedSyncS",
		[SkippedSyncT]   = "SkippedSyncT",
		[WFBitMapS]      = "WFBitMapS",
		[WFBitMapT]      = "WFBitMapT",
		[SyncSource]     = "SyncSource",
		[SyncTarget]     = "SyncTarget",
		[PausedSyncS]    = "PausedSyncS",
		[PausedSyncT]    = "PausedSyncT",
	};
	static const char *state_names[] = {
		[Primary]   = "Primary",
		[Secondary] = "Secondary",
		[Unknown]   = "Unknown"
	};


	rlen = sprintf(buf, "version: " REL_VERSION " (api:%d/proto:%d)\n\n",
		       API_VERSION,PRO_VERSION);

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
		sn = cstate_names[drbd_conf[i].cstate];
		if(drbd_conf[i].cstate == Connected) {
			if(test_bit(DISKLESS,&drbd_conf[i].flags)) 
				sn = "DiskLessClient";
			if(test_bit(PARTNER_DISKLESS,&drbd_conf[i].flags))
				sn = "ServerForDLess";
		}
		if ( drbd_conf[i].cstate == Unconfigured )
			rlen += sprintf( buf + rlen,
			   "%2d: cs:Unconfigured\n", i);
		else
			rlen += sprintf( buf + rlen,
			   "%2d: cs:%s st:%s/%s ld:%s\n"
			   "    ns:%u nr:%u dw:%u dr:%u al:%u bm:%u "
			   "lo:%d pe:%d ua:%d\n",
			   i, sn,
			   state_names[drbd_conf[i].state],
			   state_names[drbd_conf[i].o_state],
			   (drbd_conf[i].gen_cnt[Flags]
			    & MDF_Consistent) ? "Consistent" : "Inconsistent",
			   drbd_conf[i].send_cnt/2,
			   drbd_conf[i].recv_cnt/2,
			   drbd_conf[i].writ_cnt/2,
			   drbd_conf[i].read_cnt/2,
			   drbd_conf[i].al_writ_cnt,
			   drbd_conf[i].bm_writ_cnt,
			   atomic_read(&drbd_conf[i].local_cnt),
			   atomic_read(&drbd_conf[i].ap_pending_cnt) +
			   atomic_read(&drbd_conf[i].rs_pending_cnt),
			   atomic_read(&drbd_conf[i].unacked_cnt)
			);

		if ( drbd_conf[i].cstate == SyncSource ||
		     drbd_conf[i].cstate == SyncTarget )
			rlen += drbd_syncer_progress(drbd_conf+i,buf+rlen);
	}

	/* DEBUG & profile stuff end */

	return rlen;
}

/* PROC FS stuff end */
