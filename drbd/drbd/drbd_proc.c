/*
-*- linux-c -*-
   drbd_proc.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

   Copyright (C) 2002, Lars Ellenberg <l.g.e@web.de>.
        Show syncer progress

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

/*lge
 * progress bars shamelessly adapted from driver/md/md.c
 * output looks like
 *	[=====>..............] 33.5% (23456/123456)
 *	finish: 2:20h speed: 6,345 (6,456) K/sec
 */
STATIC int drbd_syncer_progress(char *buf,int minor)
{
	int sz = 0;
	unsigned long total_kb, left_kb, res , db, dt, dbdt, rt;
	/* unit 1024 bytes */
	total_kb = blk_size[MAJOR_NR][minor];
	/* synced_to unit 512 bytes */
	left_kb = drbd_conf[minor].synced_to / 2;

	res = (left_kb/1024)*1000/(total_kb/1024 + 1);
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
	if (total_kb > 0x100000L) /* if more than 1 GB display in MB */
		sz+=sprintf(buf+sz,"(%lu/%lu)M\n\t",
			left_kb/1024L, total_kb/1024L);
	else
		sz+=sprintf(buf+sz,"(%lu/%lu)K\n\t", left_kb, total_kb);

	/* see driver/md/md.c
	 * We do not want to overflow, so the order of operands and
	 * the * 100 / 100 trick are important. We do a +1 to be
	 * safe against division by zero. We only estimate anyway.
	 *
	 * dt: time from mark until now
	 * db: blocks written from mark until now
	 * rt: remaining time
	 */
	dt = ((jiffies - drbd_conf[minor].resync_mark) / HZ);
	if (!dt) dt++;
	db = (drbd_conf[minor].resync_mark_cnt/2) - left_kb;
	rt = (dt * (left_kb / (db/100+1)))/100; /* seconds */

	if (rt > 3600) {
		rt = (rt+59)/60; /* rounded up minutes */
		sz += sprintf(buf + sz, "finish: %lu:%02luh",
			rt / 60, rt % 60);
	}
	else 
		sz += sprintf(buf + sz, "finish: %lu:%02lumin",
			rt / 60, rt % 60);

	/* current speed average over (SYNC_MARKS * SYNC_MARK_STEP) jiffies */
	if ((dbdt=db/dt) > 1000)
		sz += sprintf(buf + sz, " speed: %ld,%03ld",
			dbdt/1000,dbdt % 1000);
	else
		sz += sprintf(buf + sz, " speed: %ld", dbdt);

	/* mean speed since syncer started */
	dt = ((jiffies - drbd_conf[minor].resync_mark_start) / HZ);
	if (!dt) dt++;
	db = total_kb - left_kb;
	if ((dbdt=db/dt) > 1000)
		sz += sprintf(buf + sz, " (%ld,%03ld)",
			dbdt/1000,dbdt % 1000);
	else
		sz += sprintf(buf + sz, " (%ld)", dbdt);

	sz += sprintf(buf+sz," K/sec\n");

	return sz;
}

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
		[Unconfigured] = "Unconfigured",
		[StandAlone]  =  "StandAlone",
		[Unconnected] =  "Unconnected",
		[Timeout] =      "Timeout",
		[BrokenPipe] =   "BrokenPipe",
		[WFConnection] = "WFConnection",
		[WFReportParams] = "WFReportParams",
		[Connected] =    "Connected",
		[SyncingAll] =   "SyncingAll",
		[SyncingQuick] = "SyncingQuick"
	};
	static const char *state_names[] =
	{
		[Primary] = "Primary",
		[Secondary] = "Secondary",
		[Unknown] = "Unknown"
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
	   of .. block's on the fly 
	   gc .. generation count 
	*/

	for (i = 0; i < minor_count; i++) {
		if( drbd_conf[i].cstate < Connected ) 
			drbd_conf[i].o_state = Unknown;
		rlen = 
		    rlen + sprintf(buf + rlen,
				   "%d: cs:%s st:%s/%s ns:%u nr:%u dw:%u dr:%u"
				   " pe:%u ua:%u\n",
				   i,
				   cstate_names[drbd_conf[i].cstate],
				   state_names[drbd_conf[i].state],
				   state_names[drbd_conf[i].o_state],
				   drbd_conf[i].send_cnt,
				   drbd_conf[i].recv_cnt,
				   drbd_conf[i].writ_cnt,
				   drbd_conf[i].read_cnt,
				   atomic_read(&drbd_conf[i].pending_cnt),
				   atomic_read(&drbd_conf[i].unacked_cnt));

		if (drbd_conf[i].synced_to != 0)
			rlen += drbd_syncer_progress(buf+rlen,i);
	}

	/* DEBUG & profile stuff */
#if 0

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
