/*
-*- linux-c -*-
   drbd_proc.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2001, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

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
/*static */ int drbd_proc_get_info(char *, char **, off_t, int, int *,
				   void *);
/*static */ void drbd_do_request(request_queue_t *);
#else
/*static */ int drbd_proc_get_info(char *, char **, off_t, int, int);
/*static */ void drbd_do_request(void);
#endif


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
				   " gc:%u,%u,%u\n",
				   i,
				   cstate_names[drbd_conf[i].cstate],
				   state_names[drbd_conf[i].state],
				   state_names[drbd_conf[i].o_state],
				   drbd_conf[i].send_cnt,
				   drbd_conf[i].recv_cnt,
				   drbd_conf[i].writ_cnt,
				   drbd_conf[i].read_cnt,
				   /*  drbd_conf[i].pending_cnt, */
				   drbd_conf[i].gen_cnt[1],
				   drbd_conf[i].gen_cnt[2],
				   drbd_conf[i].gen_cnt[3]);
				   

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
