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
#include "drbd.h"
#include "drbd_int.h"

STATIC int drbd_proc_get_info(char *, char **, off_t, int, int *,
				   void *);

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

	res = (mdev->rs_left/2048)*1000/(mdev->rs_total/2048 + 1);
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
			mdev->rs_left/2048L, mdev->rs_total/2048L);
	else
		sz+=sprintf(buf+sz,"(%lu/%lu)K\n\t", mdev->rs_left/2, mdev->rs_total/2);

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
	db = (mdev->rs_mark_left - mdev->rs_left)/2;
	rt = (dt * ((mdev->rs_left/2) / (db/100+1)))/100; /* seconds */

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
	db = (mdev->rs_total - mdev->rs_left)/2;
	if ((dbdt=db/dt) > 1000)
		sz += sprintf(buf + sz, " (%ld,%03ld)",
			dbdt/1000,dbdt % 1000);
	else
		sz += sprintf(buf + sz, " (%ld)", dbdt);

	sz += sprintf(buf+sz," K/sec\n");

	return sz;
}

STATIC int drbd_proc_get_info(char *buf, char **start, off_t offset,
				   int len, int *unused, void *data)
{
	int rlen, i;

	static const char *cstate_names[] =
	{
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
		[WFBitMap]       = "WFBitMap",
		[SyncSource]     = "SyncSource",
		[SyncTarget]     = "SyncTarget",
		[PausedSyncS]    = "PausedSyncS",
		[PausedSyncT]    = "PausedSyncT",
	};
	static const char *state_names[] =
	{
		[Primary]   = "Primary",
		[Secondary] = "Secondary",
		[Unknown]   = "Unknown"
	};


	rlen = sprintf(buf, "version: " REL_VERSION " (api:%d/proto:%d)\n\n",
		       API_VERSION,PRO_VERSION);

	/*
	  cs .. connection state
	  st .. node state
	  ns .. network send
	  nr .. network receive
	  dw .. disk write
	  dr .. disk read
	  pe .. pending (waiting for ack)
	  ua .. unack'd (still need to send ack)
	*/
	for (i = 0; i < minor_count; i++) {
		rlen += sprintf(buf + rlen,
			   "%d: cs:%s st:%s/%s %c ns:%u nr:%u dw:%u dr:%u"
			   " pe:%u ua:%u\n",
			   i,
			   cstate_names[drbd_conf[i].cstate],
			   state_names[drbd_conf[i].state],
			   state_names[drbd_conf[i].o_state],
			   (drbd_conf[i].gen_cnt[Flags]
			    & MDF_Consistent) ? 'C' : 'I',
			   drbd_conf[i].send_cnt/2,
			   drbd_conf[i].recv_cnt/2,
			   drbd_conf[i].writ_cnt/2,
			   drbd_conf[i].read_cnt/2,
			   atomic_read(&drbd_conf[i].pending_cnt),
			   atomic_read(&drbd_conf[i].unacked_cnt)
		);

		if ( drbd_conf[i].cstate == SyncSource ||
		     drbd_conf[i].cstate == SyncTarget )
			rlen += drbd_syncer_progress(drbd_conf+i,buf+rlen);
	}

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
