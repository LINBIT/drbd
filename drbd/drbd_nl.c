/*
-*- linux-c -*-
   drbd_nl.c
   Kernel module for 2.6.x Kernels

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/connector.h>
#include <linux/drbd.h>
#include <linux/blkpg.h>

#include "drbd_int.h"
#include <linux/drbd_tag_magic.h>
#include <linux/drbd_limits.h>

/* see get_sb_bdev and bd_claim */
char *drbd_d_holder = "Hands off! this is DRBD's data storage device.";
char *drbd_m_holder = "Hands off! this is DRBD's meta data device.";


// Generate the tag_list to struct functions
#define NL_PACKET(name, number, fields) \
int name ## _from_tags (drbd_dev *mdev, unsigned short* tags, struct name * arg) \
{ \
	int tag; \
	int dlen; \
	\
	while( (tag = *tags++) != TT_END ) { \
		dlen = *tags++; \
		switch( tag_number(tag) ) { \
		fields \
		default: \
			if( tag & T_MANDATORY ) { \
				ERR("Unknown tag: %d\n",tag_number(tag)); \
				return 0; \
			} \
		} \
		tags = (unsigned short*)((char*)tags + dlen); \
	} \
	return 1; \
}
#define NL_INTEGER(pn,pr,member) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_INTEGER ); */ \
		 arg->member = *(int*)(tags); \
		 break;
#define NL_INT64(pn,pr,member) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_INT64 ); */ \
		 arg->member = *(u64*)(tags); \
		 break;
#define NL_BIT(pn,pr,member) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_BIT ); */ \
		 arg->member = *(char*)(tags) ? 1 : 0; \
		 break;
#define NL_STRING(pn,pr,member,len) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_STRING ); */ \
		 arg->member ## _len = dlen; \
		 memcpy(arg->member,tags,min_t(size_t,dlen,len)); \
		 break;
#include "linux/drbd_nl.h"

// Generate the struct to tag_list functions
#define NL_PACKET(name, number, fields) \
unsigned short* \
name ## _to_tags (drbd_dev *mdev, struct name * arg, unsigned short* tags) \
{ \
	fields \
	return tags; \
}

#define NL_INTEGER(pn,pr,member) \
	*tags++ = pn | pr | TT_INTEGER; \
	*tags++ = sizeof(int); \
	*(int*)tags = arg->member; \
	tags = (unsigned short*)((char*)tags+sizeof(int));
#define NL_INT64(pn,pr,member) \
	*tags++ = pn | pr | TT_INT64; \
	*tags++ = sizeof(u64); \
	*(u64*)tags = arg->member; \
	tags = (unsigned short*)((char*)tags+sizeof(u64));
#define NL_BIT(pn,pr,member) \
	*tags++ = pn | pr | TT_BIT; \
	*tags++ = sizeof(char); \
	*(char*)tags = arg->member; \
	tags = (unsigned short*)((char*)tags+sizeof(char));
#define NL_STRING(pn,pr,member,len) \
	*tags++ = pn | pr | TT_STRING; \
	*tags++ = arg->member ## _len; \
	memcpy(tags,arg->member, arg->member ## _len); \
	tags = (unsigned short*)((char*)tags + arg->member ## _len);
#include "linux/drbd_nl.h"

extern void drbd_init_set_defaults(drbd_dev *mdev);
void drbd_bcast_ev_helper(drbd_dev *mdev, char* helper_name);
void drbd_nl_send_reply(struct cn_msg *, int);

char *nl_packet_name(int packet_type) {
// Generate packet type strings
#define NL_PACKET(name, number, fields) \
	[ P_ ## name ] = # name,
#define NL_INTEGER Argh!
#define NL_BIT Argh!
#define NL_INT64 Argh!
#define NL_STRING Argh!

	static char *nl_tag_name[P_nl_after_last_packet] = {
#include "linux/drbd_nl.h"
	};

	return (packet_type < sizeof(nl_tag_name)/sizeof(nl_tag_name[0])) ?
	    nl_tag_name[packet_type] : "*Unknown*";
}

void nl_trace_packet(void *data) {
	struct cn_msg *req = data;
	struct drbd_nl_cfg_req *nlp = (struct drbd_nl_cfg_req*)req->data;

	printk(KERN_INFO DEVICE_NAME "%d: "
	       "Netlink: << %s (%d) - seq: %x, ack: %x, len: %x\n",
	       nlp->drbd_minor,
	       nl_packet_name(nlp->packet_type),
	       nlp->packet_type,
	       req->seq, req->ack, req->len);
}

void nl_trace_reply(void *data) {
	struct cn_msg *req = data;
	struct drbd_nl_cfg_reply *nlp = (struct drbd_nl_cfg_reply*)req->data;

	printk(KERN_INFO DEVICE_NAME "%d: "
	       "Netlink: >> %s (%d) - seq: %x, ack: %x, len: %x\n",
	       nlp->minor,
	       nlp->packet_type==P_nl_after_last_packet?
	           "Empty-Reply" : nl_packet_name(nlp->packet_type),
	       nlp->packet_type,
	       req->seq, req->ack, req->len);
}

int drbd_khelper(drbd_dev *mdev, char* cmd)
{
	char mb[12];
	char *argv[] = {usermode_helper, cmd, mb, NULL };
	static char *envp[] = { "HOME=/",
				"TERM=linux",
				"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
				NULL };

	snprintf(mb,12,"minor-%d",mdev_to_minor(mdev));

	INFO("helper command: %s %s\n",usermode_helper,cmd);

	drbd_bcast_ev_helper(mdev,cmd);
	return call_usermodehelper(usermode_helper,argv,envp,1);
}

drbd_disks_t drbd_try_outdate_peer(drbd_dev *mdev)
{
	int r;
	drbd_disks_t nps;
	enum fencing_policy fp;

	D_ASSERT(mdev->state.pdsk == DUnknown);

	if (inc_local_if_state(mdev,UpToDate)) {
		fp = mdev->bc->dc.fencing;
		dec_local(mdev);
	} else {
		WARN("Not outdating peer, since I am diskless.");
		return mdev->state.pdsk;
	}

	if( fp == Stonith ) drbd_request_state(mdev,NS(susp,1));

	r=drbd_khelper(mdev,"outdate-peer");

	switch( (r>>8) & 0xff ) {
	case 3: /* peer is inconsistent */
		nps = Inconsistent;
		break;
	case 4: /* peer is outdated */
		nps = Outdated;
		break;
	case 5: /* peer was down, we will(have) create(d) a new UUID anyways... */
		/* If we would be more strict, we would return DUnknown here. */
		nps = Outdated;
		break;
	case 6: /* Peer is primary, voluntarily outdate myself */
		WARN("Peer is primary, outdating myself.\n");
		nps = DUnknown;
		drbd_request_state(mdev,NS(disk,Outdated));
		break;
	case 7:
		if( fp != Stonith ) {
			ERR("outdate-peer() = 7 && fencing != Stonith !!!\n");
		}
		nps = Outdated;
		break;
	default:
		/* The script is broken ... */
		nps = DUnknown;
		ERR("outdate-peer helper broken, returned %d \n",(r>>8)&0xff);
		return nps;
	}

	INFO("outdate-peer helper returned %d \n",(r>>8)&0xff);
	return nps;
}


int drbd_set_role(drbd_dev *mdev, drbd_role_t new_role, int force)
{
	int r=0,forced = 0, try=0;
	drbd_state_t mask, val;
	drbd_disks_t nps;

	if ( new_role == Primary ) {
		request_ping(mdev); // Detect a dead peer ASAP
	}

	mask.i = 0; mask.role = role_mask;
	val.i  = 0; val.role  = new_role;

	while (try++ < 3) {
		r = _drbd_request_state(mdev,mask,val,0);
		if( r == SS_NoUpToDateDisk && force &&
		    ( mdev->state.disk == Inconsistent ||
		      mdev->state.disk == Outdated ) ) {
			mask.disk = disk_mask;
			val.disk  = UpToDate;
			forced = 1;
			continue;
		}

		if( r == SS_NoUpToDateDisk &&
		    mdev->state.disk == Consistent ) {
			D_ASSERT(mdev->state.pdsk == DUnknown);
			nps = drbd_try_outdate_peer(mdev);

			if(nps == Outdated) {
				val.disk = UpToDate;
				mask.disk = disk_mask;
			}

			val.pdsk = nps;
			mask.pdsk = disk_mask;

			continue;
		}

		if ( r == SS_NothingToDo ) goto fail;
		if ( r == SS_PrimaryNOP ) {
			nps = drbd_try_outdate_peer(mdev);

			if ( force && nps > Outdated ) {
				WARN("Forced into split brain situation!\n");
				nps = Outdated;
			}

			mask.pdsk = disk_mask;
			val.pdsk  = nps;

			continue;
		}
		if( r == SS_TwoPrimaries ) {
			// Maybe the peer is detected as dead very soon...
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((mdev->net_conf->ping_timeo+1)*HZ/10);
			if(try == 1) try++; // only a single retry in this case.
			continue;
		}
		if ( r < SS_Success ) {
			r = drbd_request_state(mdev,mask,val); // Be verbose.
			if( r < SS_Success ) goto fail;
		}
		break;
	}

	if(forced) WARN("Forced to consider local data as UpToDate!\n");

	drbd_sync_me(mdev);

	/* Wait until nothing is on the fly :) */
	if ( wait_event_interruptible( mdev->misc_wait,
			         atomic_read(&mdev->ap_pending_cnt) == 0 ) ) {
		r = GotSignal;
		goto fail;
	}

	/* FIXME RACE here: if our direct user is not using bd_claim (i.e.
	 *  not a filesystem) since cstate might still be >= Connected, new
	 * ap requests may come in and increase ap_pending_cnt again!
	 * but that means someone is misusing DRBD...
	 * */

	if (new_role == Secondary) {
		set_disk_ro(mdev->vdisk, TRUE );
		if ( inc_local(mdev) ) {
			mdev->bc->md.uuid[Current] &= ~(u64)1;
			dec_local(mdev);
		}
	} else {
		if(inc_net(mdev)) {
			mdev->net_conf->want_lose = 0;
			dec_net(mdev);
		}
		set_disk_ro(mdev->vdisk, FALSE );
		/* why?? what for??
		mdev->this_bdev->bd_disk = mdev->vdisk;
		 */

		if ( inc_local(mdev) ) {
			if ( ( ( mdev->state.conn < Connected ||
				 mdev->state.pdsk <= Failed ) &&
			       mdev->bc->md.uuid[Bitmap] == 0) || forced ) {
				drbd_uuid_new_current(mdev);
			}
			mdev->bc->md.uuid[Current] |=  (u64)1;
			dec_local(mdev);
		}
	}

	if((new_role == Secondary) && inc_local(mdev) ) {
		drbd_al_to_on_disk_bm(mdev);
		dec_local(mdev);
	}

	if (mdev->state.conn >= WFReportParams) {
		/* if this was forced, we should consider sync */
		if(forced) drbd_send_uuids(mdev);
		drbd_send_state(mdev);
	}

	drbd_md_sync(mdev);

	return r;

 fail:
	return r;
}


STATIC int drbd_nl_primary(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			   struct drbd_nl_cfg_reply *reply)
{
	struct primary primary_args;

	memset(&primary_args, 0, sizeof(struct primary));
	if(!primary_from_tags(mdev,nlp->tag_list,&primary_args)) {
		reply->ret_code=UnknownMandatoryTag;
		return 0;
	}

	reply->ret_code = drbd_set_role(mdev, Primary, primary_args.overwrite_peer);

	return 0;
}

STATIC int drbd_nl_secondary(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_set_role(mdev, Secondary, 0);

	return 0;
}

/* initializes the md.*_offset members, so we are able to find
 * the on disk meta data */
STATIC void drbd_md_set_sector_offsets(drbd_dev *mdev,
				       struct drbd_backing_dev *bdev)
{
	sector_t md_size_sect = 0;
	switch(bdev->dc.meta_dev_idx) {
	default:
		/* v07 style fixed size indexed meta data */
		bdev->md.md_size_sect = MD_RESERVED_SECT;
		bdev->md.md_offset = drbd_md_ss__(mdev,bdev);
		bdev->md.al_offset = MD_AL_OFFSET;
		bdev->md.bm_offset = MD_BM_OFFSET;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
		bdev->md.md_size_sect = drbd_get_capacity(bdev->md_bdev);
		bdev->md.md_offset = 0;
		bdev->md.al_offset = MD_AL_OFFSET;
		bdev->md.bm_offset = MD_BM_OFFSET;
		break;
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		bdev->md.md_offset = drbd_md_ss__(mdev,bdev);
		/* al size is still fixed */
		bdev->md.al_offset = -MD_AL_MAX_SIZE;
                //LGE FIXME max size check missing.
		/* we need (slightly less than) ~ this much bitmap sectors: */
		md_size_sect = drbd_get_capacity(bdev->backing_bdev);
		md_size_sect = ALIGN(md_size_sect,BM_SECT_PER_EXT);
		md_size_sect = BM_SECT_TO_EXT(md_size_sect);
		md_size_sect = ALIGN(md_size_sect,8);

		/* plus the "drbd meta data super block",
		 * and the activity log; */
		md_size_sect += MD_BM_OFFSET;

		bdev->md.md_size_sect = md_size_sect;
		/* bitmap offset is adjusted by 'super' block size */
		bdev->md.bm_offset   = -md_size_sect + MD_AL_OFFSET;
		break;
	}
}

char* ppsize(char* buf, unsigned long long size)
{
	// Needs 9 bytes at max.
	static char units[] = { 'K','M','G','T','P','E' };
	int base = 0;
	while (size >= 10000 ) {
		size = size >> 10;
		base++;
	}
	sprintf(buf,"%lu %cB",(long)size,units[base]);

	return buf;
}

/**
 * drbd_determin_dev_size:
 * Evaluates all constraints and sets our correct device size.
 * Negative return values indicate errors. 0 and positive values
 * indicate success.
 * You should call drbd_md_sync() after calling this function.
 */
enum determin_dev_size_enum drbd_determin_dev_size(drbd_dev* mdev)
{
	sector_t prev_first_sect, prev_size; // previous meta location
	sector_t la_size;
	sector_t size;
	char ppb[10];

	int md_moved, la_size_changed;
	enum determin_dev_size_enum rv=unchanged;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));

	prev_first_sect = drbd_md_first_sector(mdev->bc);
	prev_size = mdev->bc->md.md_size_sect;
	la_size = mdev->bc->md.la_size_sect;

	// TODO: should only be some assert here, not (re)init...
	drbd_md_set_sector_offsets(mdev,mdev->bc);

	size = drbd_new_dev_size(mdev,mdev->bc);

	if( drbd_get_capacity(mdev->this_bdev) != size ||
	    drbd_bm_capacity(mdev) != size ) {
		int err;
		err = drbd_bm_resize(mdev,size);
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = drbd_bm_capacity(mdev)>>1;
			if (size == 0) {
				ERR("OUT OF MEMORY! Could not allocate bitmap!\n");
			} else {
				/* FIXME this is problematic,
				 * if we in fact are smaller now! */
				ERR("BM resizing failed. "
				    "Leaving size unchanged at size = %lu KB\n",
				    (unsigned long)size);
			}
			rv = dev_size_error;
		}
		// racy, see comments above.
		drbd_set_my_capacity(mdev,size);
		mdev->bc->md.la_size_sect = size;
		INFO("size = %s (%llu KB)\n",ppsize(ppb,size>>1),
		     (unsigned long long)size>>1);
	}
	if (rv == dev_size_error) goto out;

	la_size_changed = (la_size != mdev->bc->md.la_size_sect);

	//LGE: flexible device size!! is this the right thing to test?
	md_moved = prev_first_sect != drbd_md_first_sector(mdev->bc)
		|| prev_size       != mdev->bc->md.md_size_sect;

	if ( md_moved ) {
		WARN("Moving meta-data.\n");
		/* assert: (flexible) internal meta data */
	}

	if ( la_size_changed || md_moved ) {
		if( inc_local_if_state(mdev,Attaching) ) {
			drbd_al_shrink(mdev); // All extents inactive.
			rv = drbd_bm_write(mdev);  // write bitmap
			// Write mdev->la_size to on disk.
			drbd_md_mark_dirty(mdev);
			dec_local(mdev);
		}
	}

	if (size > la_size) rv = grew;
	if (size < la_size) rv = shrunk;
  out:
	lc_unlock(mdev->act_log);

	return rv;
}

sector_t
drbd_new_dev_size(struct Drbd_Conf* mdev, struct drbd_backing_dev *bdev)
{
	sector_t p_size = mdev->p_size;   // partner's disk size.
	sector_t la_size = bdev->md.la_size_sect; // last agreed size.
	sector_t m_size; // my size
	sector_t u_size = bdev->dc.disk_size; // size requested by user.
	sector_t size=0;

	m_size = drbd_get_max_capacity(bdev);

	if(p_size && m_size) {
		size=min_t(sector_t,p_size,m_size);
	} else {
		if(la_size) {
			size=la_size;
			if(m_size && m_size < size) size=m_size;
			if(p_size && p_size < size) size=p_size;
		} else {
			if(m_size) size=m_size;
			if(p_size) size=p_size;
		}
	}

	if(size == 0) {
		ERR("Both nodes diskless!\n");
	}

	if(u_size) {
		if(u_size > size) {
			ERR("Requested disk size is too big (%lu > %lu)\n",
			    (unsigned long)u_size>>1, (unsigned long)size>>1);
		} else {
			size = u_size;
		}
	}

	return size;
}

/**
 * drbd_check_al_size:
 * checks that the al lru is of requested size, and if neccessary tries to
 * allocate a new one. returns -EBUSY if current al lru is still used,
 * -ENOMEM when allocation failed, and 0 on success. You should call
 * drbd_md_sync() after you called this function.
 */
STATIC int drbd_check_al_size(drbd_dev *mdev)
{
	struct lru_cache *n,*t;
	struct lc_element *e;
	unsigned int in_use;
	int i;

	ERR_IF(mdev->sync_conf.al_extents < 7)
		mdev->sync_conf.al_extents = 127;

	if ( mdev->act_log &&
	     mdev->act_log->nr_elements == mdev->sync_conf.al_extents )
		return 0;

	in_use = 0;
	t = mdev->act_log;
	n = lc_alloc("act_log", mdev->sync_conf.al_extents,
		     sizeof(struct lc_element), mdev);

	if (n==NULL) {
		ERR("Cannot allocate act_log lru!\n");
		return -ENOMEM;
	}
	spin_lock_irq(&mdev->al_lock);
	if (t) {
		for (i=0; i < t->nr_elements; i++) {
			e = lc_entry(t,i);
			if (e->refcnt)
				ERR("refcnt(%d)==%d\n",
				    e->lc_number, e->refcnt);
			in_use += e->refcnt;
		}
	}
	if (!in_use) {
		mdev->act_log = n;
	}
	spin_unlock_irq(&mdev->al_lock);
	if (in_use) {
		ERR("Activity log still in use!\n");
		lc_free(n);
		return -EBUSY;
	} else {
		if (t) lc_free(t);
	}
	drbd_md_mark_dirty(mdev);	//we changed mdev->act_log->nr_elemens
	return 0;
}

void drbd_setup_queue_param(drbd_dev *mdev, unsigned int max_seg_s)
{
	struct request_queue * const q = mdev->rq_queue;
	struct request_queue * const b = mdev->bc->backing_bdev->bd_disk->queue;
	//unsigned int old_max_seg_s = q->max_segment_size;

	if (b->merge_bvec_fn && !mdev->bc->dc.use_bmbv)
		max_seg_s = PAGE_SIZE;

	max_seg_s = min(b->max_sectors * b->hardsect_size, max_seg_s);

	MTRACE(TraceTypeRq,TraceLvlSummary,
	       DUMPI(b->max_sectors);
	       DUMPI(b->max_phys_segments);
	       DUMPI(b->max_hw_segments);
	       DUMPI(b->max_segment_size);
	       DUMPI(b->hardsect_size);
	       DUMPI(b->seg_boundary_mask);
	       );

	q->max_sectors       = max_seg_s >> 9;
	q->max_phys_segments = max_seg_s >> PAGE_SHIFT;
	q->max_hw_segments   = max_seg_s >> PAGE_SHIFT;
	q->max_segment_size  = max_seg_s;
	q->hardsect_size     = 512;
	q->seg_boundary_mask = PAGE_SIZE-1;
	blk_queue_stack_limits(q, b);

	// KERNEL BUG. in ll_rw_blk.c
	// t->max_segment_size = min(t->max_segment_size,b->max_segment_size);
	// should be
	// t->max_segment_size = min_not_zero(...,...)

	// workaround here:
	if(q->max_segment_size == 0) q->max_segment_size = max_seg_s;

	MTRACE(TraceTypeRq,TraceLvlSummary,
	       DUMPI(q->max_sectors);
	       DUMPI(q->max_phys_segments);
	       DUMPI(q->max_hw_segments);
	       DUMPI(q->max_segment_size);
	       DUMPI(q->hardsect_size);
	       DUMPI(q->seg_boundary_mask);
	       );

	if(b->merge_bvec_fn) {
		WARN("Backing device's merge_bvec_fn() = %p\n",
		     b->merge_bvec_fn);
	}
	INFO("max_segment_size ( = BIO size ) = %u\n", q->max_segment_size);

	if( q->backing_dev_info.ra_pages != b->backing_dev_info.ra_pages) {
		INFO("Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
		     q->backing_dev_info.ra_pages,
		     b->backing_dev_info.ra_pages);
		q->backing_dev_info.ra_pages = b->backing_dev_info.ra_pages;
	}
}

/* does always return 0;
 * interesting return code is in reply->ret_code */
STATIC int drbd_nl_disk_conf(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	enum ret_codes retcode;
	struct drbd_backing_dev* nbc=NULL; // new_backing_conf
	struct inode *inode, *inode2;
	struct lru_cache* resync_lru = NULL;
	drbd_state_t ns,os;
	int rv,ntries=0;

	/* if you want to reconfigure, please tear down first */
	if (mdev->state.disk > Diskless) {
		retcode=HaveDiskConfig;
		goto fail;
	}

       /* 
        * We may have gotten here very quickly from a detach. Wait for a bit
        * then fail.
        */
	while(mdev->bc != NULL) {
		if(ntries++ >= 5) {
			WARN("drbd_nl_disk_conf: mdev->bc not NULL.\n");
			retcode=HaveDiskConfig;
			goto fail;
		}
		set_current_state(TASK_INTERRUPTIBLE);
		schedule_timeout(HZ/10);
	}

	nbc = kmalloc(sizeof(struct drbd_backing_dev),GFP_KERNEL);
	if(!nbc) {
		retcode=KMallocFailed;
		goto fail;
	}

	if( !(nlp->flags & DRBD_NL_SET_DEFAULTS) && inc_local(mdev) ) {
		memcpy(&nbc->dc,&mdev->bc->dc,sizeof(struct disk_conf));
		dec_local(mdev);
	} else {
		memset(&nbc->dc,0,sizeof(struct disk_conf));
		nbc->dc.disk_size   = DRBD_DISK_SIZE_SECT_DEF;
		nbc->dc.on_io_error = DRBD_ON_IO_ERROR_DEF;
		nbc->dc.fencing     = DRBD_FENCING_DEF;
	}

	if(!disk_conf_from_tags(mdev,nlp->tag_list,&nbc->dc)) {
		retcode=UnknownMandatoryTag;
		goto fail;
	}

	nbc->lo_file = NULL;
	nbc->md_file = NULL;

	if ( nbc->dc.meta_dev_idx < DRBD_MD_INDEX_FLEX_INT) {
		retcode=LDMDInvalid;
		goto fail;
	}

	nbc->lo_file = filp_open(nbc->dc.backing_dev,O_RDWR,0);
	if (IS_ERR(nbc->lo_file)) {
		ERR("open(\"%s\") failed with %ld\n", nbc->dc.backing_dev,
		    PTR_ERR(nbc->lo_file));
		nbc->lo_file=NULL;
		retcode=LDNameInvalid;
		goto fail;
	}

	inode = nbc->lo_file->f_dentry->d_inode;

	if (!S_ISBLK(inode->i_mode)) {
		retcode=LDNoBlockDev;
		goto fail;
	}

	nbc->md_file = filp_open(nbc->dc.meta_dev,O_RDWR,0);
	if (IS_ERR(nbc->md_file)) {
		ERR("open(\"%s\") failed with %ld\n", nbc->dc.meta_dev,
		    PTR_ERR(nbc->md_file));
		nbc->md_file=NULL;
		retcode=MDNameInvalid;
		goto fail;
	}

	inode2 = nbc->md_file->f_dentry->d_inode;

	if (!S_ISBLK(inode2->i_mode)) {
		retcode=MDNoBlockDev;
		goto fail;
	}

	nbc->backing_bdev = inode->i_bdev;
	if (BD_CLAIM(nbc->backing_bdev, mdev)) {
		printk(KERN_ERR "drbd: bd_claim(%p,%p); failed [%p;%p;%u]\n",
		       nbc->backing_bdev, mdev, 
		       nbc->backing_bdev->bd_holder,
		       nbc->backing_bdev->bd_contains->bd_holder,
		       nbc->backing_bdev->bd_holders);
		retcode=LDMounted;
		goto fail;
	}

	resync_lru = lc_alloc("resync",31, sizeof(struct bm_extent),mdev);
	if(!resync_lru) {
		retcode=KMallocFailed;
		goto fail;
	}

	nbc->md_bdev = inode2->i_bdev;
	if (BD_CLAIM(nbc->md_bdev,
		     (nbc->dc.meta_dev_idx==DRBD_MD_INDEX_INTERNAL ||
		      nbc->dc.meta_dev_idx==DRBD_MD_INDEX_FLEX_INT) ?
		     (void *)mdev : (void*) drbd_m_holder )) {
		retcode=MDMounted;
		goto release_bdev_fail;
	}

	if ( (nbc->backing_bdev==nbc->md_bdev) !=
	     (nbc->dc.meta_dev_idx==DRBD_MD_INDEX_INTERNAL ||
	      nbc->dc.meta_dev_idx==DRBD_MD_INDEX_FLEX_INT) ) {
		retcode=LDMDInvalid;
		goto release_bdev2_fail;
	}

	if ((drbd_get_capacity(nbc->backing_bdev)) < nbc->dc.disk_size) {
		retcode = LDDeviceTooSmall;
		goto release_bdev2_fail;
	}

// warning LGE checks below no longer valid
// --- rewrite
#if 0
	if (drbd_get_capacity(nbc->backing_bdev) >= (sector_t)DRBD_MAX_SECTORS) {
		retcode = LDDeviceTooLarge;
		goto release_bdev2_fail;
	}

	if ( nbc->dc.meta_dev_idx == -1 ) i = 1;
	else i = nbc->dc.meta_dev_idx+1;

	/* for internal, we need to check agains <= (then we have a drbd with
	 * zero size, but meta data...) to be on the safe side, I require 32MB
	 * minimal data storage area for drbd with internal meta data (thats
	 * 160 total).  if someone wants to use that small devices, she can use
	 * drbd 0.6 anyways...
	 *
	 * FIXME this is arbitrary and needs to be reconsidered as soon as we
	 * move to flexible size meta data.
	 */
	if( drbd_get_capacity(nbc->md_bdev) < 2*MD_RESERVED_SIZE*i
				+ (nbc->dc.meta_dev_idx == -1) ? (1<<16) : 0 )
	{
		retcode = MDDeviceTooSmall;
		goto release_bdev2_fail;
	}
#endif
// -- up to here

	// Make sure the new disk is big enough
	if (drbd_get_capacity(nbc->backing_bdev) <
	    drbd_get_capacity(mdev->this_bdev) ) {
		retcode = LDDeviceTooSmall;
		goto release_bdev2_fail;
	}

	nbc->known_size = drbd_get_capacity(nbc->backing_bdev);

	if((retcode = drbd_request_state(mdev,NS(disk,Attaching))) < SS_Success ) {
		goto release_bdev2_fail;
	}

	drbd_thread_start(&mdev->worker);
	drbd_md_set_sector_offsets(mdev,nbc);

	retcode = drbd_md_read(mdev,nbc);
	if ( retcode != NoError ) {
		goto force_diskless;
	}

	// Since we are diskless, fix the AL first...
	if (drbd_check_al_size(mdev)) {
		retcode = KMallocFailed;
		goto force_diskless;
	}

	// Prevent shrinking of consistent devices !
	if(drbd_md_test_flag(nbc,MDF_Consistent) &&
	   drbd_new_dev_size(mdev,nbc) < nbc->md.la_size_sect) {
		retcode = LDDeviceTooSmall;
		goto force_diskless;
	}

	if(!drbd_al_read_log(mdev,nbc)) {
		retcode = MDIOError;
		goto force_diskless;
	}

	/* Point of no return reached.
	 * Devices and memory are no longer released by error cleanup below.
	 * now mdev takes over responsibility, and the state engine should
	 * clean it up somewhere.  */
	D_ASSERT(mdev->bc == NULL);
	mdev->bc = nbc;
	mdev->resync = resync_lru;
	nbc = NULL;
	resync_lru = NULL;

	if(drbd_md_test_flag(mdev->bc,MDF_PrimaryInd)) {
		set_bit(CRASHED_PRIMARY, &mdev->flags);
	} else {
		clear_bit(CRASHED_PRIMARY, &mdev->flags);
	}

	mdev->send_cnt = 0;
	mdev->recv_cnt = 0;
	mdev->read_cnt = 0;
	mdev->writ_cnt = 0;

	drbd_setup_queue_param(mdev, DRBD_MAX_SEGMENT_SIZE);
	/*
	 * FIXME currently broken.
	 * drbd_set_recv_tcq(mdev,drbd_queue_order_type(mdev)==QUEUE_ORDERED_TAG);
	 */

	/* If I am currently not Primary,
	 * but meta data primary indicator is set,
	 * I just now recover from a hard crash,
	 * and have been Primary before that crash.
	 *
	 * Now, if I had no connection before that crash
	 * (have been degraded Primary), chances are that
	 * I won't find my peer now either.
	 *
	 * In that case, and _only_ in that case,
	 * we use the degr-wfc-timeout instead of the default,
	 * so we can automatically recover from a crash of a
	 * degraded but active "cluster" after a certain timeout.
	 */
	clear_bit(USE_DEGR_WFC_T,&mdev->flags);
	if ( mdev->state.role != Primary &&
	     drbd_md_test_flag(mdev->bc,MDF_PrimaryInd) &&
	    !drbd_md_test_flag(mdev->bc,MDF_ConnectedInd) ) {
		set_bit(USE_DEGR_WFC_T,&mdev->flags);
	}

	drbd_bm_lock(mdev); // racy...
	if (drbd_determin_dev_size(mdev) == dev_size_error) {
		retcode = VMallocFailed;
		goto unlock_bm;
	}

	if (drbd_md_test_flag(mdev->bc,MDF_FullSync)) {
		INFO("Assuming that all blocks are out of sync (aka FullSync)\n");
		drbd_bm_set_all(mdev);
		if (unlikely(drbd_bm_write(mdev) < 0)) {
			retcode = MDIOError;
			goto unlock_bm;
		}
		drbd_md_clear_flag(mdev,MDF_FullSync);
	} else {
		if (unlikely(drbd_bm_read(mdev) < 0)) {
			retcode = MDIOError;
			goto unlock_bm;
		}
	}

	if(test_bit(CRASHED_PRIMARY, &mdev->flags)) {
		drbd_al_apply_to_bm(mdev);
		drbd_al_to_on_disk_bm(mdev);
	}
	/* else {
	     FIXME wipe out on disk al!
	} */

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	ns.i = os.i;
	/* If MDF_Consistent is not set go into inconsistent state,
	   otherwise investige MDF_WasUpToDate...
	   If MDF_WasUpToDate is not set go into Outdated disk state,
	   otherwise into Consistent state.
	*/
	if(drbd_md_test_flag(mdev->bc,MDF_Consistent)) {
		if(drbd_md_test_flag(mdev->bc,MDF_WasUpToDate)) {
			ns.disk = Consistent;
		} else {
			ns.disk = Outdated;
		}
	} else {
		ns.disk = Inconsistent;
	}

	if(drbd_md_test_flag(mdev->bc,MDF_PeerOutDated)) {
		ns.pdsk = Outdated;
	}

	if( ns.disk == Consistent &&
	    ( ns.pdsk == Outdated || mdev->bc->dc.fencing == DontCare ) ) {
		ns.disk = UpToDate;
	}

	/* All tests on MDF_PrimaryInd, MDF_ConnectedInd,
	   MDF_Consistent and MDF_WasUpToDate must happen before
	   this point, because drbd_request_state() modifies these
	   flags. */

	/* In case we are Connected postpone any desicion on the new disk
	   state after the negotiation phase. */
	if(mdev->state.conn == Connected) {
		mdev->new_state_tmp.i = ns.i;
		ns.i = os.i;
		ns.disk = Negotiating;
	}

	rv = _drbd_set_state(mdev, ns, ChgStateVerbose);
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);

	if (rv < SS_Success) {
		goto unlock_bm;
	}

	drbd_bm_unlock(mdev);

	if(inc_local_if_state(mdev,Attaching)) {
		if(mdev->state.role == Primary) mdev->bc->md.uuid[Current] |=  (u64)1;
		else                            mdev->bc->md.uuid[Current] &= ~(u64)1;
		dec_local(mdev);
	}

	/* Reset the "barriers don't work" bits here, then force meta data to
	 * be written, to ensure we determine if barriers are supported. */
	clear_bit(LL_DEV_NO_FLUSH,&mdev->flags);
	clear_bit(MD_NO_BARRIER,&mdev->flags);
	drbd_md_mark_dirty(mdev);
	drbd_md_sync(mdev);

	reply->ret_code = retcode;
	return 0;

 unlock_bm:
	drbd_bm_unlock(mdev);
 force_diskless:
	drbd_force_state(mdev,NS(disk,Diskless));
	drbd_md_sync(mdev);
 release_bdev2_fail:
	if (nbc) BD_RELEASE(nbc->md_bdev);
 release_bdev_fail:
	if (nbc) BD_RELEASE(nbc->backing_bdev);
 fail:
	if (nbc) {
		if (nbc->lo_file) fput(nbc->lo_file);
		if (nbc->md_file) fput(nbc->md_file);
		kfree(nbc);
	}
	if (resync_lru) lc_free(resync_lru);

	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_detach(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			  struct drbd_nl_cfg_reply *reply)
{
	drbd_sync_me(mdev);
	reply->ret_code = drbd_request_state(mdev,NS(disk,Diskless));

	return 0;
}

#define HMAC_NAME_L 20

STATIC int drbd_nl_net_conf(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			    struct drbd_nl_cfg_reply *reply)
{
	int i,ns;
	enum ret_codes retcode;
	struct net_conf *new_conf = NULL;
	struct crypto_hash *tfm = NULL;
	struct hlist_head *new_tl_hash = NULL;
	struct hlist_head *new_ee_hash = NULL;
	drbd_dev *odev;
	char hmac_name[HMAC_NAME_L];

	if (mdev->state.conn > StandAlone) {
		retcode=HaveNetConfig;
		goto fail;
	}

	new_conf = kmalloc(sizeof(struct net_conf),GFP_KERNEL);
	if(!new_conf) {
		retcode=KMallocFailed;
		goto fail;
	}

	if( !(nlp->flags & DRBD_NL_SET_DEFAULTS) && inc_net(mdev)) {
		memcpy(new_conf,mdev->net_conf,sizeof(struct net_conf));
		dec_local(mdev);
	} else {
		memset(new_conf,0,sizeof(struct net_conf));
		new_conf->timeout         = DRBD_TIMEOUT_DEF;
		new_conf->try_connect_int = DRBD_CONNECT_INT_DEF;
		new_conf->ping_int        = DRBD_PING_INT_DEF;
		new_conf->max_epoch_size  = DRBD_MAX_EPOCH_SIZE_DEF;
		new_conf->max_buffers     = DRBD_MAX_BUFFERS_DEF;
		new_conf->unplug_watermark= DRBD_UNPLUG_WATERMARK_DEF;
		new_conf->sndbuf_size     = DRBD_SNDBUF_SIZE_DEF;
		new_conf->ko_count        = DRBD_KO_COUNT_DEF;
		new_conf->after_sb_0p     = DRBD_AFTER_SB_0P_DEF;
		new_conf->after_sb_1p     = DRBD_AFTER_SB_1P_DEF;
		new_conf->after_sb_2p     = DRBD_AFTER_SB_2P_DEF;
		new_conf->want_lose       = 0;
		new_conf->two_primaries   = 0;
		new_conf->wire_protocol   = DRBD_PROT_C;
		new_conf->ping_timeo      = DRBD_PING_TIMEO_DEF;
		new_conf->rr_conflict     = DRBD_RR_CONFLICT_DEF;
	}

	if (!net_conf_from_tags(mdev,nlp->tag_list,new_conf)) {
		retcode=UnknownMandatoryTag;
		goto fail;
	}

	if (new_conf->two_primaries && (new_conf->wire_protocol != DRBD_PROT_C)) {
		retcode=ProtocolCRequired;
		goto fail;
	};

	if( mdev->state.role == Primary && new_conf->want_lose ) {
		retcode=DiscardNotAllowed;
		goto fail;
	}

#define M_ADDR(A) (((struct sockaddr_in *)&A->my_addr)->sin_addr.s_addr)
#define M_PORT(A) (((struct sockaddr_in *)&A->my_addr)->sin_port)
#define O_ADDR(A) (((struct sockaddr_in *)&A->peer_addr)->sin_addr.s_addr)
#define O_PORT(A) (((struct sockaddr_in *)&A->peer_addr)->sin_port)
	retcode = NoError;
	for(i=0;i<minor_count;i++) {
		odev = minor_to_mdev(i);
		if(!odev || odev == mdev) continue;
		if( inc_net(odev)) {
			if( M_ADDR(new_conf) == M_ADDR(odev->net_conf) &&
			    M_PORT(new_conf) == M_PORT(odev->net_conf) ) {
				retcode=LAAlreadyInUse;
			}
			if(O_ADDR(new_conf) == O_ADDR(odev->net_conf) &&
			   O_PORT(new_conf) == O_PORT(odev->net_conf) ) {
				retcode=OAAlreadyInUse;
			}
			dec_net(odev);
			if(retcode != NoError) goto fail;
		}
	}
#undef M_ADDR
#undef M_PORT
#undef O_ADDR
#undef O_PORT

	if( new_conf->cram_hmac_alg[0] != 0) {
		snprintf(hmac_name,HMAC_NAME_L,"hmac(%s)",new_conf->cram_hmac_alg);
		tfm = crypto_alloc_hash(hmac_name, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(tfm)) {
			tfm = NULL;
			retcode=CRAMAlgNotAvail;
			goto fail;
		}

		if (crypto_tfm_alg_type(crypto_hash_tfm(tfm)) != CRYPTO_ALG_TYPE_HASH ) {
			retcode=CRAMAlgNotDigest;
			goto fail;
		}
	}


	ns = new_conf->max_epoch_size/8;
	if (mdev->tl_hash_s != ns) {
		new_tl_hash=kzalloc(ns*sizeof(void*), GFP_KERNEL);
		if(!new_tl_hash) {
			retcode=KMallocFailed;
			goto fail;
		}
	}

	ns = new_conf->max_buffers/8;
	if (new_conf->two_primaries && ( mdev->ee_hash_s != ns ) ) {
		new_ee_hash=kzalloc(ns*sizeof(void*), GFP_KERNEL);
		if(!new_ee_hash) {
			retcode=KMallocFailed;
			goto fail;
		}
	}

	((char*)new_conf->shared_secret)[SHARED_SECRET_MAX-1]=0;

#if 0
FIXME LGE
	/* for the connection loss logic in drbd_recv
	 * I _need_ the resulting timeo in jiffies to be
	 * non-zero and different
	 *
	 * XXX maybe rather store the value scaled to jiffies?
	 * Note: MAX_SCHEDULE_TIMEOUT/HZ*HZ != MAX_SCHEDULE_TIMEOUT
	 *       and HZ > 10; which is unlikely to change...
	 *       Thus, if interrupted by a signal,
	 *       sock_{send,recv}msg returns -EINTR,
	 *       if the timeout expires, -EAGAIN.
	 */
	// unlikely: someone disabled the timeouts ...
	// just put some huge values in there.
	if (!new_conf->ping_int)
		new_conf->ping_int = MAX_SCHEDULE_TIMEOUT/HZ;
	if (!new_conf->timeout)
		new_conf->timeout = MAX_SCHEDULE_TIMEOUT/HZ*10;
	if (new_conf->ping_int*10 < new_conf->timeout)
		new_conf->timeout = new_conf->ping_int*10/6;
	if (new_conf->ping_int*10 == new_conf->timeout)
		new_conf->ping_int = new_conf->ping_int+1;
#endif

	D_ASSERT(mdev->net_conf==NULL);
	mdev->net_conf = new_conf;

	mdev->send_cnt = 0;
	mdev->recv_cnt = 0;

	if(new_tl_hash) {
		if (mdev->tl_hash) kfree(mdev->tl_hash);
		mdev->tl_hash_s = mdev->net_conf->max_epoch_size/8;
		mdev->tl_hash = new_tl_hash;
	}

	if(new_ee_hash) {
		if (mdev->ee_hash) kfree(mdev->ee_hash);
		mdev->ee_hash_s = mdev->net_conf->max_buffers/8;
		mdev->ee_hash = new_ee_hash;
	}

	if ( mdev->cram_hmac_tfm ) {
		crypto_free_hash(mdev->cram_hmac_tfm);
	}
	mdev->cram_hmac_tfm = tfm;

	retcode = drbd_request_state(mdev,NS(conn,Unconnected));

	if (retcode >= SS_Success)
		drbd_thread_start(&mdev->worker);

	reply->ret_code = retcode;
	return 0;

  fail:
	if (tfm) crypto_free_hash(tfm);
	if (new_tl_hash) kfree(new_tl_hash);
	if (new_ee_hash) kfree(new_ee_hash);
	if (new_conf) kfree(new_conf);

	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_disconnect(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	int retcode;

	retcode = _drbd_request_state(mdev,NS(conn,Disconnecting),0);	// silently.

	if ( retcode == SS_NothingToDo ) goto done;
	else if ( retcode == SS_AlreadyStandAlone ) goto done;
	else if ( retcode == SS_PrimaryNOP ) {
		// Our statche checking code wants to see the peer outdated.
		retcode = drbd_request_state(mdev,NS2(conn,Disconnecting,
						      pdsk,Outdated));
	} else if (retcode == SS_CW_FailedByPeer) {
		// The peer probabely wants to see us outdated.
		retcode = _drbd_request_state(mdev,NS2(conn,Disconnecting,
						       disk,Outdated),0);
		if( retcode == SS_IsDiskLess ) {
			// We are diskless and our peer wants to outdate us.
			// So, simply go away, and let the peer try to
			// outdate us with its 'outdate-peer' handler later.
			retcode = drbd_request_state(mdev,NS(conn,StandAlone));
		}
	}

	if( retcode < SS_Success ) goto fail;

	if( wait_event_interruptible( mdev->misc_wait,
				      mdev->state.conn==StandAlone) ) {
		retcode = GotSignal;
		goto fail;
	}

 done:
	retcode = NoError;
 fail:
	drbd_md_sync(mdev);
	reply->ret_code = retcode;
	return 0;
}

void resync_after_online_grow(drbd_dev *mdev)
{
	int iass; /* I am sync source */

	INFO("Resync of new storage after online grow\n");
	if (mdev->state.role != mdev->state.peer)
		iass = (mdev->state.role == Primary);
	else
		iass = test_bit(DISCARD_CONCURRENT,&mdev->flags);

	if (iass)
		drbd_start_resync(mdev,SyncSource);
	else
		drbd_request_state(mdev,NS(conn,WFSyncUUID));
}

STATIC int drbd_nl_resize(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			  struct drbd_nl_cfg_reply *reply)
{
	struct resize rs;
	int retcode=NoError;
	int ldsc = 0; /* local disk size changed */
	enum determin_dev_size_enum dd;

	memset(&rs, 0, sizeof(struct resize));
	if (!resize_from_tags(mdev,nlp->tag_list,&rs)) {
		retcode=UnknownMandatoryTag;
		goto fail;
	}

	if (mdev->state.conn > Connected) {
		retcode = NoResizeDuringResync;
		goto fail;
	}

	if ( mdev->state.role == Secondary &&
	     mdev->state.peer == Secondary) {
		retcode = APrimaryNodeNeeded;
		goto fail;
	}

	if(!inc_local(mdev)) {
		retcode = HaveNoDiskConfig;
		goto fail;
	}

	if (mdev->bc->known_size != drbd_get_capacity(mdev->bc->backing_bdev)) {
		mdev->bc->known_size = drbd_get_capacity(mdev->bc->backing_bdev);
		ldsc = 1;
	}

	mdev->bc->dc.disk_size = (sector_t)rs.resize_size;
	drbd_bm_lock(mdev);
	dd = drbd_determin_dev_size(mdev);
	drbd_md_sync(mdev);
	drbd_bm_unlock(mdev);
	dec_local(mdev);
	if (dd == dev_size_error) {
		retcode = VMallocFailed;
		goto fail;
	}

	if (mdev->state.conn == Connected && ( dd != unchanged || ldsc) ) {
		drbd_send_uuids(mdev);
		drbd_send_sizes(mdev);
		if (dd == grew)
			resync_after_online_grow(mdev);
	}

 fail:
	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_syncer_conf(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			       struct drbd_nl_cfg_reply *reply)
{
	int retcode=NoError;
	struct syncer_conf sc;
	drbd_dev *odev;
	int err;

	memcpy(&sc,&mdev->sync_conf,sizeof(struct syncer_conf));

	if(nlp->flags & DRBD_NL_SET_DEFAULTS) {
		sc.rate       = DRBD_RATE_DEF;
		sc.after      = DRBD_AFTER_DEF;
		sc.al_extents = DRBD_AL_EXTENTS_DEF;
	}

	if (!syncer_conf_from_tags(mdev,nlp->tag_list,&sc)) {
		retcode=UnknownMandatoryTag;
		goto fail;
	}

	if( sc.after != -1) {
		if( sc.after < -1 || minor_to_mdev(sc.after) == NULL ) {
			retcode=SyncAfterInvalid;
			goto fail;
		}
		odev = minor_to_mdev(sc.after); // check against loops in
		while(1) {
			if( odev == mdev ) {
				retcode=SyncAfterCycle;
				goto fail;
			}
			if( odev->sync_conf.after == -1 ) break; // no cycles.
			odev = minor_to_mdev(odev->sync_conf.after);
		}
	}

	ERR_IF (sc.rate < 1) sc.rate = 1;
	ERR_IF (sc.al_extents < 7) sc.al_extents = 127; // arbitrary minimum
#define AL_MAX ((MD_AL_MAX_SIZE-1) * AL_EXTENTS_PT)
	if(sc.al_extents > AL_MAX) {
		ERR("sc.al_extents > %d\n",AL_MAX);
		sc.al_extents = AL_MAX;
	}
#undef AL_MAX

	mdev->sync_conf = sc;

	if(inc_local(mdev)) {
		err = drbd_check_al_size(mdev);
		dec_local(mdev);
		drbd_md_sync(mdev);

		if (err) {
			retcode = KMallocFailed;
			goto fail;
		}
	}

	if (mdev->state.conn >= Connected)
		drbd_send_sync_param(mdev,&sc);

	drbd_alter_sa(mdev, sc.after);

 fail:
	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_invalidate(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev,NS2(conn,StartingSyncT,
						      disk,Inconsistent));
	return 0;
}

STATIC int drbd_nl_invalidate_peer(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
				   struct drbd_nl_cfg_reply *reply)
{

	reply->ret_code = drbd_request_state(mdev,NS2(conn,StartingSyncS,
						      pdsk,Inconsistent));

	return 0;
}

STATIC int drbd_nl_pause_sync(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	int retcode=NoError;

	if(drbd_request_state(mdev,NS(user_isp,1)) == SS_NothingToDo)
		retcode = PauseFlagAlreadySet;

	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_resume_sync(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			       struct drbd_nl_cfg_reply *reply)
{
	int retcode=NoError;

	if(drbd_request_state(mdev,NS(user_isp,0)) == SS_NothingToDo)
		retcode = PauseFlagAlreadyClear;

	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_suspend_io(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev,NS(susp,1));

	return 0;
}

STATIC int drbd_nl_resume_io(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev,NS(susp,0));
	return 0;
}

STATIC int drbd_nl_outdate(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			   struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev,NS(disk,Outdated));
	return 0;
}

STATIC int drbd_nl_get_config(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			   struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	if(inc_local(mdev)) {
		tl = disk_conf_to_tags(mdev,&mdev->bc->dc,tl);
		dec_local(mdev);
	}

	if(inc_net(mdev)) {
		tl = net_conf_to_tags(mdev,mdev->net_conf,tl);
		dec_net(mdev);
	}
	tl = syncer_conf_to_tags(mdev,&mdev->sync_conf,tl);

	*tl++ = TT_END; /* Close the tag list */

	return (int)((char*)tl - (char*)reply->tag_list);
}

STATIC int drbd_nl_get_state(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	tl = get_state_to_tags(mdev,(struct get_state*)&mdev->state,tl);
	*tl++ = TT_END; /* Close the tag list */

	return (int)((char*)tl - (char*)reply->tag_list);
}

STATIC int drbd_nl_get_uuids(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	if(inc_local(mdev)) {
		// This is a hand crafted add tag ;)
		*tl++ = T_uuids;
		*tl++ = UUID_SIZE*sizeof(u64);
		memcpy(tl,mdev->bc->md.uuid,UUID_SIZE*sizeof(u64));
		tl=(unsigned short*)((char*)tl + UUID_SIZE*sizeof(u64));
		dec_local(mdev);
		*tl++ = T_uuids_flags;
		*tl++ = sizeof(int);
		memcpy(tl,&mdev->bc->md.flags,sizeof(int));
		tl=(unsigned short*)((char*)tl + sizeof(int));
	}
	*tl++ = TT_END; /* Close the tag list */

	return (int)((char*)tl - (char*)reply->tag_list);
}


STATIC int drbd_nl_get_timeout_flag(drbd_dev *mdev, struct drbd_nl_cfg_req *nlp,
				    struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	// This is a hand crafted add tag ;)
	*tl++ = T_use_degraded;
	*tl++ = sizeof(char);
	*((char*)tl) = test_bit(USE_DEGR_WFC_T,&mdev->flags) ? 1 : 0 ;
	tl=(unsigned short*)((char*)tl + sizeof(char));
	*tl++ = TT_END;

	return (int)((char*)tl - (char*)reply->tag_list);
}

STATIC drbd_dev *ensure_mdev(struct drbd_nl_cfg_req *nlp)
{
	drbd_dev *mdev;

	mdev = minor_to_mdev(nlp->drbd_minor);

	if(!mdev && (nlp->flags & DRBD_NL_CREATE_DEVICE)) {
		mdev = drbd_new_device(nlp->drbd_minor);

		spin_lock_irq(&drbd_pp_lock);
		if( minor_table[nlp->drbd_minor] == NULL) {
			minor_table[nlp->drbd_minor] = mdev;
			mdev = NULL;
		}
		spin_unlock_irq(&drbd_pp_lock);

		if(mdev) {
			if(mdev->app_reads_hash) kfree(mdev->app_reads_hash);
			if(mdev->md_io_page) __free_page(mdev->md_io_page);
			kfree(mdev);
			mdev = NULL;
		}

		mdev = minor_to_mdev(nlp->drbd_minor);
	}

	return mdev;
}

struct cn_handler_struct {
	int (*function)(drbd_dev *,
			 struct drbd_nl_cfg_req *,
			 struct drbd_nl_cfg_reply* );
	int reply_body_size;
};

static struct cn_handler_struct cnd_table[] = {
	[ P_primary ]		= { &drbd_nl_primary,		0 },
	[ P_secondary ]		= { &drbd_nl_secondary,		0 },
	[ P_disk_conf ]		= { &drbd_nl_disk_conf,		0 },
	[ P_detach ]		= { &drbd_nl_detach,		0 },
	[ P_net_conf ]		= { &drbd_nl_net_conf,		0 },
	[ P_disconnect ]	= { &drbd_nl_disconnect,	0 },
	[ P_resize ]		= { &drbd_nl_resize,		0 },
	[ P_syncer_conf ]	= { &drbd_nl_syncer_conf,	0 },
	[ P_invalidate ]	= { &drbd_nl_invalidate,	0 },
	[ P_invalidate_peer ]	= { &drbd_nl_invalidate_peer,	0 },
	[ P_pause_sync ]	= { &drbd_nl_pause_sync,	0 },
	[ P_resume_sync ]	= { &drbd_nl_resume_sync,	0 },
	[ P_suspend_io ]	= { &drbd_nl_suspend_io,	0 },
	[ P_resume_io ]		= { &drbd_nl_resume_io,		0 },
	[ P_outdate ]		= { &drbd_nl_outdate,		0 },
	[ P_get_config ]	= { &drbd_nl_get_config,
				    sizeof(struct syncer_conf_tag_len_struct) +
				    sizeof(struct disk_conf_tag_len_struct) +
				    sizeof(struct net_conf_tag_len_struct) },
	[ P_get_state ]		= { &drbd_nl_get_state,
				    sizeof(struct get_state_tag_len_struct) },
	[ P_get_uuids ]		= { &drbd_nl_get_uuids,
				    sizeof(struct get_uuids_tag_len_struct) },
	[ P_get_timeout_flag ]	= { &drbd_nl_get_timeout_flag,
				    sizeof(struct get_timeout_flag_tag_len_struct)},

};

void drbd_connector_callback(void *data)
{
	struct cn_msg *req = data;
	struct drbd_nl_cfg_req *nlp = (struct drbd_nl_cfg_req*)req->data;
	struct cn_handler_struct *cm;
	struct cn_msg *cn_reply;
	struct drbd_nl_cfg_reply* reply;
	drbd_dev *mdev;
	int retcode,rr;
	int reply_size = sizeof(struct cn_msg)
		+ sizeof(struct drbd_nl_cfg_reply)
		+ sizeof(short int);

	if(!try_module_get(THIS_MODULE)) {
		printk(KERN_ERR DEVICE_NAME "try_module_get() failed!\n");
		return;
	}

	if( !(mdev = ensure_mdev(nlp)) ) {
		retcode=MinorNotKnown;
		goto fail;
	}

	TRACE(TraceTypeNl, TraceLvlSummary, nl_trace_packet(data););

	if( nlp->packet_type >= P_nl_after_last_packet ) {
		retcode=UnknownNetLinkPacket;
		goto fail;
	}

	cm = cnd_table + nlp->packet_type;
	reply_size += cm->reply_body_size;

	if( !(cn_reply = kmalloc(reply_size,GFP_KERNEL)) ) {
		retcode=KMallocFailed;
		goto fail;
	}
	reply = (struct drbd_nl_cfg_reply*) cn_reply->data;

	reply->packet_type = cm->reply_body_size ? nlp->packet_type : P_nl_after_last_packet;
	reply->minor = nlp->drbd_minor;
	reply->ret_code = NoError; // Might by modified by cm->function.
	// reply->tag_list; might be modified by cm->fucntion.

	rr = cm->function(mdev,nlp,reply);

	cn_reply->id = req->id;
	cn_reply->seq = req->seq;
	cn_reply->ack = req->ack  + 1;
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) + rr;
	cn_reply->flags = 0;

	TRACE(TraceTypeNl, TraceLvlSummary, nl_trace_reply(cn_reply););

	rr = cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
	if(rr && rr != -ESRCH) {
		printk(KERN_INFO DEVICE_NAME " cn_netlink_send()=%d\n",rr);
	}
	kfree(cn_reply);
	module_put(THIS_MODULE);
	return;
 fail:
	drbd_nl_send_reply(req, retcode);
	module_put(THIS_MODULE);
}

atomic_t drbd_nl_seq = ATOMIC_INIT(2); // two.

void drbd_bcast_state(drbd_dev *mdev, drbd_state_t state)
{
	char buffer[sizeof(struct cn_msg)+
		    sizeof(struct drbd_nl_cfg_reply)+
		    sizeof(struct get_state_tag_len_struct)+
		    sizeof(short int)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply* reply = (struct drbd_nl_cfg_reply*)cn_reply->data;
	unsigned short *tl = reply->tag_list;

	// WARN("drbd_bcast_state() got called\n");

	tl = get_state_to_tags(mdev,(struct get_state*)&state,tl);
	*tl++ = TT_END; /* Close the tag list */

	cn_reply->id.idx = CN_IDX_DRBD;
	cn_reply->id.val = CN_VAL_DRBD;

	cn_reply->seq = atomic_add_return(1,&drbd_nl_seq);
	cn_reply->ack = 0; // not used here.
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) +
		(int)((char*)tl - (char*)reply->tag_list);
	cn_reply->flags = 0;

	reply->packet_type = P_get_state;
	reply->minor = mdev_to_minor(mdev);
	reply->ret_code = NoError;

	TRACE(TraceTypeNl, TraceLvlSummary, nl_trace_reply(cn_reply););

	cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
}

void drbd_bcast_ev_helper(drbd_dev *mdev, char* helper_name)
{
	char buffer[sizeof(struct cn_msg)+
		    sizeof(struct drbd_nl_cfg_reply)+
		    sizeof(struct call_helper_tag_len_struct)+
		    sizeof(short int)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply* reply = (struct drbd_nl_cfg_reply*)cn_reply->data;
	unsigned short *tl = reply->tag_list;
	int str_len;

	// WARN("drbd_bcast_state() got called\n");

	str_len = strlen(helper_name)+1;
	*tl++ = T_helper;
	*tl++ = str_len;
	memcpy(tl,helper_name,str_len);
	tl=(unsigned short*)((char*)tl + str_len);
	*tl++ = TT_END; /* Close the tag list */

	cn_reply->id.idx = CN_IDX_DRBD;
	cn_reply->id.val = CN_VAL_DRBD;

	cn_reply->seq = atomic_add_return(1,&drbd_nl_seq);
	cn_reply->ack = 0; // not used here.
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) +
		(int)((char*)tl - (char*)reply->tag_list);
	cn_reply->flags = 0;

	reply->packet_type = P_call_helper;
	reply->minor = mdev_to_minor(mdev);
	reply->ret_code = NoError;

	TRACE(TraceTypeNl, TraceLvlSummary, nl_trace_reply(cn_reply););

	cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
}

void drbd_bcast_sync_progress(drbd_dev *mdev)
{
	char buffer[sizeof(struct cn_msg)+
		    sizeof(struct drbd_nl_cfg_reply)+
		    sizeof(struct sync_progress_tag_len_struct)+
		    sizeof(short int)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply* reply = (struct drbd_nl_cfg_reply*)cn_reply->data;
	unsigned short *tl = reply->tag_list;
	unsigned long rs_left;
	unsigned int res;

	/* no local ref, no bitmap, no syncer progress, no broadcast. */
	if (!inc_local(mdev))
		return;
	drbd_get_syncer_progress(mdev, &rs_left, &res);
	dec_local(mdev);

	*tl++ = T_sync_progress;
	*tl++ = sizeof(int);
	memcpy(tl, &res, sizeof(int));
	tl=(unsigned short*)((char*)tl + sizeof(int));
	*tl++ = TT_END; /* Close the tag list */

	cn_reply->id.idx = CN_IDX_DRBD;
	cn_reply->id.val = CN_VAL_DRBD;

	cn_reply->seq = atomic_add_return(1,&drbd_nl_seq);
	cn_reply->ack = 0; // not used here.
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) +
		(int)((char*)tl - (char*)reply->tag_list);
	cn_reply->flags = 0;

	reply->packet_type = P_sync_progress;
	reply->minor = mdev_to_minor(mdev);
	reply->ret_code = NoError;

	TRACE(TraceTypeNl, TraceLvlSummary, nl_trace_reply(cn_reply););

	cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
}

#ifdef NETLINK_ROUTE6
int __init cn_init(void);
void __exit cn_fini(void);
#endif

int __init drbd_nl_init()
{
	static struct cb_id cn_id_drbd = { CN_IDX_DRBD, CN_VAL_DRBD };
	int err;

#ifdef NETLINK_ROUTE6
	/* pre 2.6.16 */
	err = cn_init();
	if(err) return err;
#endif
	err = cn_add_callback(&cn_id_drbd,"cn_drbd",&drbd_connector_callback);
	if(err) {
		printk(KERN_ERR DEVICE_NAME "cn_drbd failed to register\n");
		return err;
	}

	return 0;
}

void drbd_nl_cleanup()
{
	static struct cb_id cn_id_drbd = { CN_IDX_DRBD, CN_VAL_DRBD };

	cn_del_callback(&cn_id_drbd);

#ifdef NETLINK_ROUTE6
	/* pre 2.6.16 */
	cn_fini();
#endif
}

void drbd_nl_send_reply( struct cn_msg *req,
			 int ret_code)
{
	char buffer[sizeof(struct cn_msg)+sizeof(struct drbd_nl_cfg_reply)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply* reply = (struct drbd_nl_cfg_reply*)cn_reply->data;
	int rr;

	cn_reply->id = req->id;

	cn_reply->seq = req->seq;
	cn_reply->ack = req->ack  + 1;
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply);
	cn_reply->flags = 0;

	reply->minor = ((struct drbd_nl_cfg_req *)req->data)->drbd_minor;
	reply->ret_code = ret_code;

	TRACE(TraceTypeNl, TraceLvlSummary, nl_trace_reply(cn_reply););

	rr = cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
	if(rr && rr != -ESRCH) {
		printk(KERN_INFO DEVICE_NAME " cn_netlink_send()=%d\n",rr);
	}
}

