/*
-*- linux-c -*-
   drbd_proc.c
   Kernel module for 2.4.x/2.6.x Kernels

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

#include <linux/config.h>
#include <linux/module.h>

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
#define Bit2KB(bits) ((bits)<<(BM_BLOCK_SIZE_B-10))
STATIC int drbd_syncer_progress(struct Drbd_Conf* mdev,char *buf)
{
	int sz = 0;
	unsigned long res , db, dt, dbdt, rt, rs_left;
	sector_t n;

	rs_left = drbd_bm_total_weight(mdev);
	n = rs_left*1000;
	sector_div(n,mdev->rs_total + 1);
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
	/* if more than 1 GB display in MB */
	if (mdev->rs_total > 0x100000L) {
		sz+=sprintf(buf+sz,"(%lu/%lu)M\n\t",
			    (unsigned long) Bit2KB(rs_left) >> 10,
			    (unsigned long) Bit2KB(mdev->rs_total) >> 10 );
	} else {
		sz+=sprintf(buf+sz,"(%lu/%lu)K\n\t",
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
	if (!dt) dt++;
	db = Bit2KB(mdev->rs_mark_left - rs_left);
	n = Bit2KB(rs_left);
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
	db = Bit2KB(mdev->rs_total - rs_left);
	if ((dbdt=db/dt) > 1000)
		sz += sprintf(buf + sz, " (%ld,%03ld)",
			dbdt/1000,dbdt % 1000);
	else
		sz += sprintf(buf + sz, " (%ld)", dbdt);

	sz += sprintf(buf+sz," K/sec\n");

	return sz;
}

const char* cstate_to_name(Drbd_CState s) {
	static const char *cstate_names[] = {
		[Unconfigured]   = "Unconfigured",
		[StandAlone]     = "StandAlone",
		[Unconnected]    = "Unconnected",
		[Timeout]        = "Timeout",
		[BrokenPipe]     = "BrokenPipe",
		[NetworkFailure] = "NetworkFailure",
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

	return s < Unconfigured ? "TO_SMALL" :
	       s > PausedSyncT  ? "TO_LARGE"
		                : cstate_names[s];
}

const char* nodestate_to_name(Drbd_State s) {
	static const char *state_names[] = {
		[Primary]   = "Primary",
		[Secondary] = "Secondary",
		[Unknown]   = "Unknown"
	};

	return s < Unknown    ? "TO_SMALL" :
	       s > Secondary  ? "TO_LARGE"
		              : state_names[s];
}

int drbd_proc_get_info(char *buf, char **start, off_t offset,
		       int len, int *unused, void *data)
{
	int rlen, i;
	const char *sn;

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
		sn = cstate_to_name(drbd_conf[i].cstate);
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
			   "lo:%d pe:%d ua:%d ap:%d\n",
			   i, sn,
			   nodestate_to_name(drbd_conf[i].state),
			   nodestate_to_name(drbd_conf[i].o_state),
			   (drbd_conf[i].gen_cnt[Flags]
			    & MDF_Consistent) ? "Consistent" : "Inconsistent",
			// FIXME partner consistent?
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

		if ( drbd_conf[i].cstate == SyncSource ||
		     drbd_conf[i].cstate == SyncTarget )
			rlen += drbd_syncer_progress(drbd_conf+i,buf+rlen);
	}

	/* DEBUG & profile stuff end */

	return rlen;
}

/* PROC FS stuff end */
