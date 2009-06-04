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
static char *drbd_m_holder = "Hands off! this is DRBD's meta data device.";

/* Generate the tag_list to struct functions */
#define NL_PACKET(name, number, fields) \
STATIC int name ## _from_tags (struct drbd_conf *mdev, \
	unsigned short *tags, struct name *arg) \
{ \
	int tag; \
	int dlen; \
	\
	while ((tag = *tags++) != TT_END) { \
		dlen = *tags++; \
		switch (tag_number(tag)) { \
		fields \
		default: \
			if (tag & T_MANDATORY) { \
				ERR("Unknown tag: %d\n", tag_number(tag)); \
				return 0; \
			} \
		} \
		tags = (unsigned short *)((char *)tags + dlen); \
	} \
	return 1; \
}
#define NL_INTEGER(pn, pr, member) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_INTEGER ); */ \
		 arg->member = *(int *)(tags); \
		 break;
#define NL_INT64(pn, pr, member) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_INT64 ); */ \
		 arg->member = *(u64 *)(tags); \
		 break;
#define NL_BIT(pn, pr, member) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_BIT ); */ \
		 arg->member = *(char *)(tags) ? 1 : 0; \
		 break;
#define NL_STRING(pn, pr, member, len) \
	case pn: /* D_ASSERT( tag_type(tag) == TT_STRING ); */ \
		if (dlen > len) { \
			ERR("arg too long: %s (%u wanted, max len: %u bytes)\n", \
				#member, dlen, (unsigned int)len); \
			return 0; \
		} \
		 arg->member ## _len = dlen; \
		 memcpy(arg->member, tags, min_t(size_t, dlen, len)); \
		 break;
#include "linux/drbd_nl.h"

/* Generate the struct to tag_list functions */
#define NL_PACKET(name, number, fields) \
STATIC unsigned short* \
name ## _to_tags (struct drbd_conf *mdev, \
	struct name *arg, unsigned short *tags) \
{ \
	fields \
	return tags; \
}

#define NL_INTEGER(pn, pr, member) \
	*tags++ = pn | pr | TT_INTEGER; \
	*tags++ = sizeof(int); \
	*(int *)tags = arg->member; \
	tags = (unsigned short *)((char *)tags+sizeof(int));
#define NL_INT64(pn, pr, member) \
	*tags++ = pn | pr | TT_INT64; \
	*tags++ = sizeof(u64); \
	*(u64 *)tags = arg->member; \
	tags = (unsigned short *)((char *)tags+sizeof(u64));
#define NL_BIT(pn, pr, member) \
	*tags++ = pn | pr | TT_BIT; \
	*tags++ = sizeof(char); \
	*(char *)tags = arg->member; \
	tags = (unsigned short *)((char *)tags+sizeof(char));
#define NL_STRING(pn, pr, member, len) \
	*tags++ = pn | pr | TT_STRING; \
	*tags++ = arg->member ## _len; \
	memcpy(tags, arg->member, arg->member ## _len); \
	tags = (unsigned short *)((char *)tags + arg->member ## _len);
#include "linux/drbd_nl.h"

void drbd_bcast_ev_helper(struct drbd_conf *mdev, char *helper_name);
void drbd_nl_send_reply(struct cn_msg *, int);

STATIC char *nl_packet_name(int packet_type)
{
/* Generate packet type strings */
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

STATIC void nl_trace_packet(void *data)
{
	struct cn_msg *req = data;
	struct drbd_nl_cfg_req *nlp = (struct drbd_nl_cfg_req *)req->data;

	printk(KERN_INFO "drbd%d: "
	       "Netlink: << %s (%d) - seq: %x, ack: %x, len: %x\n",
	       nlp->drbd_minor,
	       nl_packet_name(nlp->packet_type),
	       nlp->packet_type,
	       req->seq, req->ack, req->len);
}

STATIC void nl_trace_reply(void *data)
{
	struct cn_msg *req = data;
	struct drbd_nl_cfg_reply *nlp = (struct drbd_nl_cfg_reply *)req->data;

	printk(KERN_INFO "drbd%d: "
	       "Netlink: >> %s (%d) - seq: %x, ack: %x, len: %x\n",
	       nlp->minor,
	       nlp->packet_type == P_nl_after_last_packet ?
		   "Empty-Reply" : nl_packet_name(nlp->packet_type),
	       nlp->packet_type,
	       req->seq, req->ack, req->len);
}

int drbd_khelper(struct drbd_conf *mdev, char *cmd)
{
	char mb[12];
	char *argv[] = {usermode_helper, cmd, mb, NULL };
	int ret;
	static char *envp[] = { "HOME=/",
				"TERM=linux",
				"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
				NULL };

	snprintf(mb, 12, "minor-%d", mdev_to_minor(mdev));

	INFO("helper command: %s %s %s\n", usermode_helper, cmd, mb);

	drbd_bcast_ev_helper(mdev, cmd);
	ret = call_usermodehelper(usermode_helper, argv, envp, 1);
	if (ret)
		drbd_WARN("helper command: %s %s %s exit code %u (0x%x)\n",
				usermode_helper, cmd, mb,
				(ret >> 8) & 0xff, ret);
	else
		INFO("helper command: %s %s %s exit code %u (0x%x)\n",
				usermode_helper, cmd, mb,
				(ret >> 8) & 0xff, ret);

	if (ret < 0) /* Ignore any ERRNOs we got. */
		ret = 0;

	return ret;
}

enum drbd_disk_state drbd_try_outdate_peer(struct drbd_conf *mdev)
{
	char *ex_to_string;
	int r;
	enum drbd_disk_state nps;
	enum drbd_fencing_p fp;

	D_ASSERT(mdev->state.pdsk == D_UNKNOWN);

	if (get_ldev_if_state(mdev, D_CONSISTENT)) {
		fp = mdev->ldev->dc.fencing;
		put_ldev(mdev);
	} else {
		drbd_WARN("Not outdating peer, I'm not even Consistent myself.\n");
		return mdev->state.pdsk;
	}

	if (fp == FP_STONITH)
		_drbd_request_state(mdev, NS(susp, 1), CS_WAIT_COMPLETE);

	r = drbd_khelper(mdev, "outdate-peer");

	switch ((r>>8) & 0xff) {
	case 3: /* peer is inconsistent */
		ex_to_string = "peer is inconsistent or worse";
		nps = D_INCONSISTENT;
		break;
	case 4:
		ex_to_string = "peer is outdated";
		nps = D_OUTDATED;
		break;
	case 5: /* peer was down, we will(have) create(d) a new UUID anyways... */
		/* If we would be more strict, we would return D_UNKNOWN here. */
		ex_to_string = "peer is unreachable, assumed to be dead";
		nps = D_OUTDATED;
		break;
	case 6: /* Peer is primary, voluntarily outdate myself.
		 * This is useful when an unconnected R_SECONDARY is asked to
		 * become R_PRIMARY, but findes the other peer being active. */
		ex_to_string = "peer is active";
		drbd_WARN("Peer is primary, outdating myself.\n");
		nps = D_UNKNOWN;
		_drbd_request_state(mdev, NS(disk, D_OUTDATED), CS_WAIT_COMPLETE);
		break;
	case 7:
		if (fp != FP_STONITH)
			ERR("outdate-peer() = 7 && fencing != Stonith !!!\n");
		ex_to_string = "peer was stonithed";
		nps = D_OUTDATED;
		break;
	default:
		/* The script is broken ... */
		nps = D_UNKNOWN;
		ERR("outdate-peer helper broken, returned %d\n", (r>>8)&0xff);
		return nps;
	}

	INFO("outdate-peer helper returned %d (%s)\n",
			(r>>8) & 0xff, ex_to_string);
	return nps;
}


int drbd_set_role(struct drbd_conf *mdev, enum drbd_role new_role, int force)
{
	const int max_tries = 4;
	int r = 0;
	int try = 0;
	int forced = 0;
	union drbd_state mask, val;
	enum drbd_disk_state nps;

	if (new_role == R_PRIMARY)
		request_ping(mdev); /* Detect a dead peer ASAP */

	mutex_lock(&mdev->state_mutex);

	mask.i = 0; mask.role = R_MASK;
	val.i  = 0; val.role  = new_role;

	while (try++ < max_tries) {
		r = _drbd_request_state(mdev, mask, val, CS_WAIT_COMPLETE);

		/* in case we first succeeded to outdate,
		 * but now suddenly could establish a connection */
		if (r == SS_CW_FAILED_BY_PEER && mask.pdsk != 0) {
			val.pdsk = 0;
			mask.pdsk = 0;
			continue;
		}

		if (r == SS_NO_UP_TO_DATE_DISK && force &&
		    (mdev->state.disk == D_INCONSISTENT ||
		     mdev->state.disk == D_OUTDATED)) {
			mask.disk = D_MASK;
			val.disk  = D_UP_TO_DATE;
			forced = 1;
			continue;
		}

		if (r == SS_NO_UP_TO_DATE_DISK &&
		    mdev->state.disk == D_CONSISTENT) {
			D_ASSERT(mdev->state.pdsk == D_UNKNOWN);
			nps = drbd_try_outdate_peer(mdev);

			if (nps == D_OUTDATED) {
				val.disk = D_UP_TO_DATE;
				mask.disk = D_MASK;
			}

			val.pdsk = nps;
			mask.pdsk = D_MASK;

			continue;
		}

		if (r == SS_NOTHING_TO_DO)
			goto fail;
		if (r == SS_PRIMARY_NOP) {
			nps = drbd_try_outdate_peer(mdev);

			if (force && nps > D_OUTDATED) {
				drbd_WARN("Forced into split brain situation!\n");
				nps = D_OUTDATED;
			}

			mask.pdsk = D_MASK;
			val.pdsk  = nps;

			continue;
		}
		if (r == SS_TWO_PRIMARIES) {
			/* Maybe the peer is detected as dead very soon...
			   retry at most once more in this case. */
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout((mdev->net_conf->ping_timeo+1)*HZ/10);
			if (try < max_tries)
				try = max_tries - 1;
			continue;
		}
		if (r < SS_SUCCESS) {
			r = _drbd_request_state(mdev, mask, val,
						CS_VERBOSE + CS_WAIT_COMPLETE);
			if (r < SS_SUCCESS)
				goto fail;
		}
		break;
	}

	if (forced)
		drbd_WARN("Forced to consider local data as UpToDate!\n");

	/* Wait until nothing is on the fly :) */
	wait_event(mdev->misc_wait, atomic_read(&mdev->ap_pending_cnt) == 0);

	/* FIXME RACE here: if our direct user is not using bd_claim (i.e.
	 *  not a filesystem) since cstate might still be >= C_CONNECTED, new
	 * ap requests may come in and increase ap_pending_cnt again!
	 * but that means someone is misusing DRBD...
	 * */

	if (new_role == R_SECONDARY) {
		set_disk_ro(mdev->vdisk, TRUE);
		if (get_ldev(mdev)) {
			mdev->ldev->md.uuid[UI_CURRENT] &= ~(u64)1;
			put_ldev(mdev);
		}
	} else {
		if (get_net_conf(mdev)) {
			mdev->net_conf->want_lose = 0;
			put_net_conf(mdev);
		}
		set_disk_ro(mdev->vdisk, FALSE);
		if (get_ldev(mdev)) {
			if (((mdev->state.conn < C_CONNECTED ||
			       mdev->state.pdsk <= D_FAILED)
			      && mdev->ldev->md.uuid[UI_BITMAP] == 0) || forced)
				drbd_uuid_new_current(mdev);

			mdev->ldev->md.uuid[UI_CURRENT] |=  (u64)1;
			put_ldev(mdev);
		}
	}

	if ((new_role == R_SECONDARY) && get_ldev(mdev)) {
		drbd_al_to_on_disk_bm(mdev);
		put_ldev(mdev);
	}

	if (mdev->state.conn >= C_WF_REPORT_PARAMS) {
		/* if this was forced, we should consider sync */
		if (forced)
			drbd_send_uuids(mdev);
		drbd_send_state(mdev);
	}

	drbd_md_sync(mdev);

 fail:
	mutex_unlock(&mdev->state_mutex);
	return r;
}


STATIC int drbd_nl_primary(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			   struct drbd_nl_cfg_reply *reply)
{
	struct primary primary_args;

	memset(&primary_args, 0, sizeof(struct primary));
	if (!primary_from_tags(mdev, nlp->tag_list, &primary_args)) {
		reply->ret_code = ERR_MANDATORY_TAG;
		return 0;
	}

	reply->ret_code =
		drbd_set_role(mdev, R_PRIMARY, primary_args.overwrite_peer);

	return 0;
}

STATIC int drbd_nl_secondary(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_set_role(mdev, R_SECONDARY, 0);

	return 0;
}

/* initializes the md.*_offset members, so we are able to find
 * the on disk meta data */
STATIC void drbd_md_set_sector_offsets(struct drbd_conf *mdev,
				       struct drbd_backing_dev *bdev)
{
	sector_t md_size_sect = 0;
	switch (bdev->dc.meta_dev_idx) {
	default:
		/* v07 style fixed size indexed meta data */
		bdev->md.md_size_sect = MD_RESERVED_SECT;
		bdev->md.md_offset = drbd_md_ss__(mdev, bdev);
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
		bdev->md.md_offset = drbd_md_ss__(mdev, bdev);
		/* al size is still fixed */
		bdev->md.al_offset = -MD_AL_MAX_SIZE;
		/* LGE FIXME max size check missing. */
		/* we need (slightly less than) ~ this much bitmap sectors: */
		md_size_sect = drbd_get_capacity(bdev->backing_bdev);
		md_size_sect = ALIGN(md_size_sect, BM_SECT_PER_EXT);
		md_size_sect = BM_SECT_TO_EXT(md_size_sect);
		md_size_sect = ALIGN(md_size_sect, 8);

		/* plus the "drbd meta data super block",
		 * and the activity log; */
		md_size_sect += MD_BM_OFFSET;

		bdev->md.md_size_sect = md_size_sect;
		/* bitmap offset is adjusted by 'super' block size */
		bdev->md.bm_offset   = -md_size_sect + MD_AL_OFFSET;
		break;
	}
}

char *ppsize(char *buf, unsigned long long size)
{
	/* Needs 9 bytes at max. */
	static char units[] = { 'K', 'M', 'G', 'T', 'P', 'E' };
	int base = 0;
	while (size >= 10000) {
		/* shift + round */
		size = (size >> 10) + !!(size & (1<<9));
		base++;
	}
	sprintf(buf, "%lu %cB", (long)size, units[base]);

	return buf;
}

/* there is still a theoretical deadlock when called from receiver
 * on an D_INCONSISTENT R_PRIMARY:
 *  remote READ does inc_ap_bio, receiver would need to receive answer
 *  packet from remote to dec_ap_bio again.
 *  receiver receive_sizes(), comes here,
 *  waits for ap_bio_cnt == 0. -> deadlock.
 * but this cannot happen, actually, because:
 *  R_PRIMARY D_INCONSISTENT, and peer's disk is unreachable
 *  (not connected, or bad/no disk on peer):
 *  see drbd_fail_request_early, ap_bio_cnt is zero.
 *  R_PRIMARY D_INCONSISTENT, and C_SYNC_TARGET:
 *  peer may not initiate a resize.
 */
void drbd_suspend_io(struct drbd_conf *mdev)
{
	set_bit(SUSPEND_IO, &mdev->flags);
	wait_event(mdev->misc_wait, !atomic_read(&mdev->ap_bio_cnt));
}

void drbd_resume_io(struct drbd_conf *mdev)
{
	clear_bit(SUSPEND_IO, &mdev->flags);
	wake_up(&mdev->misc_wait);
}

/**
 * drbd_determin_dev_size:
 * Evaluates all constraints and sets our correct device size.
 * Negative return values indicate errors. 0 and positive values
 * indicate success.
 * You should call drbd_md_sync() after calling this function.
 */
enum determine_dev_size drbd_determin_dev_size(struct drbd_conf *mdev) __must_hold(local)
{
	sector_t prev_first_sect, prev_size; /* previous meta location */
	sector_t la_size;
	sector_t size;
	char ppb[10];

	int md_moved, la_size_changed;
	enum determine_dev_size rv = unchanged;

	/* race:
	 * application request passes inc_ap_bio,
	 * but then cannot get an AL-reference.
	 * this function later may wait on ap_bio_cnt == 0. -> deadlock.
	 *
	 * to avoid that:
	 * Suspend IO right here.
	 * still lock the act_log to not trigger ASSERTs there.
	 */
	drbd_suspend_io(mdev);

	/* no wait necessary anymore, actually we could assert that */
	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));

	prev_first_sect = drbd_md_first_sector(mdev->ldev);
	prev_size = mdev->ldev->md.md_size_sect;
	la_size = mdev->ldev->md.la_size_sect;

	/* TODO: should only be some assert here, not (re)init... */
	drbd_md_set_sector_offsets(mdev, mdev->ldev);

	size = drbd_new_dev_size(mdev, mdev->ldev);

	if (drbd_get_capacity(mdev->this_bdev) != size ||
	    drbd_bm_capacity(mdev) != size) {
		int err;
		err = drbd_bm_resize(mdev, size);
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = drbd_bm_capacity(mdev)>>1;
			if (size == 0) {
				ERR("OUT OF MEMORY! "
				    "Could not allocate bitmap!\n");
			} else {
				/* FIXME this is problematic,
				 * if we in fact are smaller now! */
				ERR("BM resizing failed. "
				    "Leaving size unchanged at size = %lu KB\n",
				    (unsigned long)size);
			}
			rv = dev_size_error;
		}
		/* racy, see comments above. */
		drbd_set_my_capacity(mdev, size);
		mdev->ldev->md.la_size_sect = size;
		INFO("size = %s (%llu KB)\n", ppsize(ppb, size>>1),
		     (unsigned long long)size>>1);
	}
	if (rv == dev_size_error)
		goto out;

	la_size_changed = (la_size != mdev->ldev->md.la_size_sect);

	md_moved = prev_first_sect != drbd_md_first_sector(mdev->ldev)
		|| prev_size	   != mdev->ldev->md.md_size_sect;

	if (md_moved) {
		drbd_WARN("Moving meta-data.\n");
		/* assert: (flexible) internal meta data */
	}

	if (la_size_changed || md_moved) {
		drbd_al_shrink(mdev); /* All extents inactive. */
		INFO("Writing the whole bitmap, size changed\n");
		rv = drbd_bitmap_io(mdev, &drbd_bm_write, "size changed");
		drbd_md_mark_dirty(mdev);
	}

	if (size > la_size)
		rv = grew;
	if (size < la_size)
		rv = shrunk;
out:
	lc_unlock(mdev->act_log);
	wake_up(&mdev->al_wait);
	drbd_resume_io(mdev);

	return rv;
}

sector_t
drbd_new_dev_size(struct drbd_conf *mdev, struct drbd_backing_dev *bdev)
{
	sector_t p_size = mdev->p_size;   /* partner's disk size. */
	sector_t la_size = bdev->md.la_size_sect; /* last agreed size. */
	sector_t m_size; /* my size */
	sector_t u_size = bdev->dc.disk_size; /* size requested by user. */
	sector_t size = 0;

	m_size = drbd_get_max_capacity(bdev);

	if (p_size && m_size) {
		size = min_t(sector_t, p_size, m_size);
	} else {
		if (la_size) {
			size = la_size;
			if (m_size && m_size < size)
				size = m_size;
			if (p_size && p_size < size)
				size = p_size;
		} else {
			if (m_size)
				size = m_size;
			if (p_size)
				size = p_size;
		}
	}

	if (size == 0)
		ERR("Both nodes diskless!\n");

	if (u_size) {
		if (u_size > size)
			ERR("Requested disk size is too big (%lu > %lu)\n",
			    (unsigned long)u_size>>1, (unsigned long)size>>1);
		else
			size = u_size;
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
STATIC int drbd_check_al_size(struct drbd_conf *mdev)
{
	struct lru_cache *n, *t;
	struct lc_element *e;
	unsigned int in_use;
	int i;

	ERR_IF(mdev->sync_conf.al_extents < 7)
		mdev->sync_conf.al_extents = 127;

	if (mdev->act_log &&
	    mdev->act_log->nr_elements == mdev->sync_conf.al_extents)
		return 0;

	in_use = 0;
	t = mdev->act_log;
	n = lc_alloc("act_log", mdev->sync_conf.al_extents,
		     sizeof(struct lc_element), mdev);

	if (n == NULL) {
		ERR("Cannot allocate act_log lru!\n");
		return -ENOMEM;
	}
	spin_lock_irq(&mdev->al_lock);
	if (t) {
		for (i = 0; i < t->nr_elements; i++) {
			e = lc_entry(t, i);
			if (e->refcnt)
				ERR("refcnt(%d)==%d\n",
				    e->lc_number, e->refcnt);
			in_use += e->refcnt;
		}
	}
	if (!in_use)
		mdev->act_log = n;
	spin_unlock_irq(&mdev->al_lock);
	if (in_use) {
		ERR("Activity log still in use!\n");
		lc_free(n);
		return -EBUSY;
	} else {
		if (t)
			lc_free(t);
	}
	drbd_md_mark_dirty(mdev); /* we changed mdev->act_log->nr_elemens */
	return 0;
}

void drbd_setup_queue_param(struct drbd_conf *mdev, unsigned int max_seg_s) __must_hold(local)
{
	struct request_queue * const q = mdev->rq_queue;
	struct request_queue * const b = mdev->ldev->backing_bdev->bd_disk->queue;
	/* unsigned int old_max_seg_s = q->max_segment_size; */

	if (b->merge_bvec_fn && !mdev->ldev->dc.use_bmbv)
		max_seg_s = PAGE_SIZE;

	max_seg_s = min(b->max_sectors * b->hardsect_size, max_seg_s);

	MTRACE(TRACE_TYPE_RQ, TRACE_LVL_SUMMARY,
	       DUMPI(b->max_sectors);
	       DUMPI(b->max_phys_segments);
	       DUMPI(b->max_hw_segments);
	       DUMPI(b->max_segment_size);
	       DUMPI(b->hardsect_size);
	       DUMPI(b->seg_boundary_mask);
	       );

	q->max_sectors	     = max_seg_s >> 9;
	q->max_phys_segments = max_seg_s >> PAGE_SHIFT;
	q->max_hw_segments   = max_seg_s >> PAGE_SHIFT;
	q->max_segment_size  = max_seg_s;
	q->hardsect_size     = 512;
	q->seg_boundary_mask = PAGE_SIZE-1;
	blk_queue_stack_limits(q, b);

	/* KERNEL BUG. in ll_rw_blk.c ??
	 * t->max_segment_size = min(t->max_segment_size,b->max_segment_size);
	 * should be
	 * t->max_segment_size = min_not_zero(...,...)
	 * workaround here: */
	if (q->max_segment_size == 0)
		q->max_segment_size = max_seg_s;

	MTRACE(TRACE_TYPE_RQ, TRACE_LVL_SUMMARY,
	       DUMPI(q->max_sectors);
	       DUMPI(q->max_phys_segments);
	       DUMPI(q->max_hw_segments);
	       DUMPI(q->max_segment_size);
	       DUMPI(q->hardsect_size);
	       DUMPI(q->seg_boundary_mask);
	       );

	if (b->merge_bvec_fn)
		drbd_WARN("Backing device's merge_bvec_fn() = %p\n",
		     b->merge_bvec_fn);
	INFO("max_segment_size ( = BIO size ) = %u\n", q->max_segment_size);

	if (q->backing_dev_info.ra_pages != b->backing_dev_info.ra_pages) {
		INFO("Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
		     q->backing_dev_info.ra_pages,
		     b->backing_dev_info.ra_pages);
		q->backing_dev_info.ra_pages = b->backing_dev_info.ra_pages;
	}
}

/* serialize deconfig (worker exiting, doing cleanup)
 * and reconfig (drbdsetup disk, drbdsetup net)
 *
 * wait for a potentially exiting worker, then restart it,
 * or start a new one.
 */
static void drbd_reconfig_start(struct drbd_conf *mdev)
{
	wait_event(mdev->state_wait, test_and_set_bit(CONFIG_PENDING, &mdev->flags));
	wait_event(mdev->state_wait, !test_bit(DEVICE_DYING, &mdev->flags));
	drbd_thread_start(&mdev->worker);
}

/* if still unconfigured, stops worker again.
 * if configured now, clears CONFIG_PENDING.
 * wakes potential waiters */
static void drbd_reconfig_done(struct drbd_conf *mdev)
{
	spin_lock_irq(&mdev->req_lock);
	if (mdev->state.disk == D_DISKLESS &&
	    mdev->state.conn == C_STANDALONE &&
	    mdev->state.role == R_SECONDARY) {
		set_bit(DEVICE_DYING, &mdev->flags);
		drbd_thread_stop_nowait(&mdev->worker);
	} else
		clear_bit(CONFIG_PENDING, &mdev->flags);
	spin_unlock_irq(&mdev->req_lock);
	wake_up(&mdev->state_wait);
}

/* does always return 0;
 * interesting return code is in reply->ret_code */
STATIC int drbd_nl_disk_conf(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	enum drbd_ret_codes retcode;
	enum determine_dev_size dd;
	sector_t max_possible_sectors;
	sector_t min_md_device_sectors;
	struct drbd_backing_dev *nbc = NULL; /* new_backing_conf */
	struct inode *inode, *inode2;
	struct lru_cache *resync_lru = NULL;
	union drbd_state ns, os;
	int rv;

	drbd_reconfig_start(mdev);

	/* if you want to reconfigure, please tear down first */
	if (mdev->state.disk > D_DISKLESS) {
		retcode = ERR_DISK_CONFIGURED;
		goto fail;
	}

	nbc = kmalloc(sizeof(struct drbd_backing_dev), GFP_KERNEL);
	if (!nbc) {
		retcode = ERR_NOMEM;
		goto fail;
	}

	memset(&nbc->md, 0, sizeof(struct drbd_md));
	memset(&nbc->dc, 0, sizeof(struct disk_conf));
	nbc->dc.disk_size   = DRBD_DISK_SIZE_SECT_DEF;
	nbc->dc.on_io_error = DRBD_ON_IO_ERROR_DEF;
	nbc->dc.fencing     = DRBD_FENCING_DEF;

	if (!disk_conf_from_tags(mdev, nlp->tag_list, &nbc->dc)) {
		retcode = ERR_MANDATORY_TAG;
		goto fail;
	}

	nbc->lo_file = NULL;
	nbc->md_file = NULL;

	if (nbc->dc.meta_dev_idx < DRBD_MD_INDEX_FLEX_INT) {
		retcode = ERR_MD_IDX_INVALID;
		goto fail;
	}

	nbc->lo_file = filp_open(nbc->dc.backing_dev, O_RDWR, 0);
	if (IS_ERR(nbc->lo_file)) {
		ERR("open(\"%s\") failed with %ld\n", nbc->dc.backing_dev,
		    PTR_ERR(nbc->lo_file));
		nbc->lo_file = NULL;
		retcode = ERR_OPEN_DISK;
		goto fail;
	}

	inode = nbc->lo_file->f_dentry->d_inode;

	if (!S_ISBLK(inode->i_mode)) {
		retcode = ERR_DISK_NOT_BDEV;
		goto fail;
	}

	nbc->md_file = filp_open(nbc->dc.meta_dev, O_RDWR, 0);
	if (IS_ERR(nbc->md_file)) {
		ERR("open(\"%s\") failed with %ld\n", nbc->dc.meta_dev,
		    PTR_ERR(nbc->md_file));
		nbc->md_file = NULL;
		retcode = ERR_OPEN_MD_DISK;
		goto fail;
	}

	inode2 = nbc->md_file->f_dentry->d_inode;

	if (!S_ISBLK(inode2->i_mode)) {
		retcode = ERR_MD_NOT_BDEV;
		goto fail;
	}

	nbc->backing_bdev = inode->i_bdev;
	if (bd_claim(nbc->backing_bdev, mdev)) {
		printk(KERN_ERR "drbd: bd_claim(%p,%p); failed [%p;%p;%u]\n",
		       nbc->backing_bdev, mdev,
		       nbc->backing_bdev->bd_holder,
		       nbc->backing_bdev->bd_contains->bd_holder,
		       nbc->backing_bdev->bd_holders);
		retcode = ERR_BDCLAIM_DISK;
		goto fail;
	}

	resync_lru = lc_alloc("resync", 61, sizeof(struct bm_extent), mdev);
	if (!resync_lru) {
		retcode = ERR_NOMEM;
		goto release_bdev_fail;
	}

	/* meta_dev_idx >= 0: external fixed size,
	 * possibly multiple drbd sharing one meta device.
	 * TODO in that case, paranoia check that [md_bdev, meta_dev_idx] is
	 * not yet used by some other drbd minor!
	 * (if you use drbd.conf + drbdadm,
	 * that should check it for you already; but if you don't, or someone
	 * fooled it, we need to double check here) */
	nbc->md_bdev = inode2->i_bdev;
	if (bd_claim(nbc->md_bdev, (nbc->dc.meta_dev_idx < 0) ? (void *)mdev
				: (void *) drbd_m_holder)) {
		retcode = ERR_BDCLAIM_MD_DISK;
		goto release_bdev_fail;
	}

	if ((nbc->backing_bdev == nbc->md_bdev) !=
	    (nbc->dc.meta_dev_idx == DRBD_MD_INDEX_INTERNAL ||
	     nbc->dc.meta_dev_idx == DRBD_MD_INDEX_FLEX_INT)) {
		retcode = ERR_MD_IDX_INVALID;
		goto release_bdev2_fail;
	}

	/* RT - for drbd_get_max_capacity() DRBD_MD_INDEX_FLEX_INT */
	drbd_md_set_sector_offsets(mdev, nbc);

	if (drbd_get_max_capacity(nbc) < nbc->dc.disk_size) {
		ERR("max capacity %llu smaller than disk size %llu\n",
			(unsigned long long) drbd_get_max_capacity(nbc),
			(unsigned long long) nbc->dc.disk_size);
		retcode = ERR_DISK_TO_SMALL;
		goto release_bdev2_fail;
	}

	if (nbc->dc.meta_dev_idx < 0) {
		max_possible_sectors = DRBD_MAX_SECTORS_FLEX;
		/* at least one MB, otherwise it does not make sense */
		min_md_device_sectors = (2<<10);
	} else {
		max_possible_sectors = DRBD_MAX_SECTORS;
		min_md_device_sectors = MD_RESERVED_SECT * (nbc->dc.meta_dev_idx + 1);
	}

	if (drbd_get_capacity(nbc->md_bdev) > max_possible_sectors)
		drbd_WARN("truncating very big lower level device "
		     "to currently maximum possible %llu sectors\n",
		     (unsigned long long) max_possible_sectors);

	if (drbd_get_capacity(nbc->md_bdev) < min_md_device_sectors) {
		retcode = ERR_MD_DISK_TO_SMALL;
		drbd_WARN("refusing attach: md-device too small, "
		     "at least %llu sectors needed for this meta-disk type\n",
		     (unsigned long long) min_md_device_sectors);
		goto release_bdev2_fail;
	}

	/* Make sure the new disk is big enough
	 * (we may currently be R_PRIMARY with no local disk...) */
	if (drbd_get_max_capacity(nbc) <
	    drbd_get_capacity(mdev->this_bdev)) {
		retcode = ERR_DISK_TO_SMALL;
		goto release_bdev2_fail;
	}

	nbc->known_size = drbd_get_capacity(nbc->backing_bdev);

	drbd_suspend_io(mdev);
	/* also wait for the last barrier ack. */
	wait_event(mdev->misc_wait, !atomic_read(&mdev->ap_pending_cnt));

	retcode = _drbd_request_state(mdev, NS(disk, D_ATTACHING), CS_VERBOSE);
	drbd_resume_io(mdev);
	if (retcode < SS_SUCCESS)
		goto release_bdev2_fail;

	if (!get_ldev_if_state(mdev, D_ATTACHING))
		goto force_diskless;

	drbd_md_set_sector_offsets(mdev, nbc);

	if (!mdev->bitmap) {
		if (drbd_bm_init(mdev)) {
			retcode = ERR_NOMEM;
			goto force_diskless_dec;
		}
	}

	retcode = drbd_md_read(mdev, nbc);
	if (retcode != NO_ERROR)
		goto force_diskless_dec;

	if (mdev->state.conn < C_CONNECTED &&
	    mdev->state.role == R_PRIMARY &&
	    (mdev->ed_uuid & ~((u64)1)) != (nbc->md.uuid[UI_CURRENT] & ~((u64)1))) {
		ERR("Can only attach to data with current UUID=%016llX\n",
		    (unsigned long long)mdev->ed_uuid);
		retcode = ERR_DATA_NOT_CURRENT;
		goto force_diskless_dec;
	}

	/* Since we are diskless, fix the activity log first... */
	if (drbd_check_al_size(mdev)) {
		retcode = ERR_NOMEM;
		goto force_diskless_dec;
	}

	/* Prevent shrinking of consistent devices ! */
	if (drbd_md_test_flag(nbc, MDF_CONSISTENT) &&
	   drbd_new_dev_size(mdev, nbc) < nbc->md.la_size_sect) {
		drbd_WARN("refusing to truncate a consistent device\n");
		retcode = ERR_DISK_TO_SMALL;
		goto force_diskless_dec;
	}

	if (!drbd_al_read_log(mdev, nbc)) {
		retcode = ERR_IO_MD_DISK;
		goto force_diskless_dec;
	}

	/* Reset the "barriers don't work" bits here, then force meta data to
	 * be written, to ensure we determine if barriers are supported. */
	if (nbc->dc.no_disk_flush)
		set_bit(LL_DEV_NO_FLUSH, &mdev->flags);
	else
		clear_bit(LL_DEV_NO_FLUSH, &mdev->flags);

	if (nbc->dc.no_md_flush)
		set_bit(MD_NO_BARRIER, &mdev->flags);
	else
		clear_bit(MD_NO_BARRIER, &mdev->flags);

	/* Point of no return reached.
	 * Devices and memory are no longer released by error cleanup below.
	 * now mdev takes over responsibility, and the state engine should
	 * clean it up somewhere.  */
	D_ASSERT(mdev->ldev == NULL);
	mdev->ldev = nbc;
	mdev->resync = resync_lru;
	nbc = NULL;
	resync_lru = NULL;

	if (drbd_md_test_flag(mdev->ldev, MDF_PRIMARY_IND))
		set_bit(CRASHED_PRIMARY, &mdev->flags);
	else
		clear_bit(CRASHED_PRIMARY, &mdev->flags);

	mdev->send_cnt = 0;
	mdev->recv_cnt = 0;
	mdev->read_cnt = 0;
	mdev->writ_cnt = 0;

	drbd_setup_queue_param(mdev, DRBD_MAX_SEGMENT_SIZE);
	/*
	 * FIXME currently broken.
	 * drbd_set_recv_tcq(mdev,
	 *	drbd_queue_order_type(mdev)==QUEUE_ORDERED_TAG);
	 */

	/* If I am currently not R_PRIMARY,
	 * but meta data primary indicator is set,
	 * I just now recover from a hard crash,
	 * and have been R_PRIMARY before that crash.
	 *
	 * Now, if I had no connection before that crash
	 * (have been degraded R_PRIMARY), chances are that
	 * I won't find my peer now either.
	 *
	 * In that case, and _only_ in that case,
	 * we use the degr-wfc-timeout instead of the default,
	 * so we can automatically recover from a crash of a
	 * degraded but active "cluster" after a certain timeout.
	 */
	clear_bit(USE_DEGR_WFC_T, &mdev->flags);
	if (mdev->state.role != R_PRIMARY &&
	     drbd_md_test_flag(mdev->ldev, MDF_PRIMARY_IND) &&
	    !drbd_md_test_flag(mdev->ldev, MDF_CONNECTED_IND))
		set_bit(USE_DEGR_WFC_T, &mdev->flags);

	dd = drbd_determin_dev_size(mdev);
	if (dd == dev_size_error) {
		retcode = ERR_NOMEM_BITMAP;
		goto force_diskless_dec;
	} else if (dd == grew)
		set_bit(RESYNC_AFTER_NEG, &mdev->flags);

	if (drbd_md_test_flag(mdev->ldev, MDF_FULL_SYNC)) {
		INFO("Assuming that all blocks are out of sync "
		     "(aka FullSync)\n");
		if (drbd_bitmap_io(mdev, &drbd_bmio_set_n_write, "set_n_write from attaching")) {
			retcode = ERR_IO_MD_DISK;
			goto force_diskless_dec;
		}
	} else {
		if (drbd_bitmap_io(mdev, &drbd_bm_read, "read from attaching") < 0) {
			retcode = ERR_IO_MD_DISK;
			goto force_diskless_dec;
		}
	}

	if (test_bit(CRASHED_PRIMARY, &mdev->flags)) {
		drbd_al_apply_to_bm(mdev);
		drbd_al_to_on_disk_bm(mdev);
	}
	/* else {
	     FIXME wipe out on disk al!
	} */

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	ns.i = os.i;
	/* If MDF_CONSISTENT is not set go into inconsistent state,
	   otherwise investige MDF_WasUpToDate...
	   If MDF_WAS_UP_TO_DATE is not set go into D_OUTDATED disk state,
	   otherwise into D_CONSISTENT state.
	*/
	if (drbd_md_test_flag(mdev->ldev, MDF_CONSISTENT)) {
		if (drbd_md_test_flag(mdev->ldev, MDF_WAS_UP_TO_DATE))
			ns.disk = D_CONSISTENT;
		else
			ns.disk = D_OUTDATED;
	} else {
		ns.disk = D_INCONSISTENT;
	}

	if (drbd_md_test_flag(mdev->ldev, MDF_PEER_OUT_DATED))
		ns.pdsk = D_OUTDATED;

	if ( ns.disk == D_CONSISTENT &&
	    (ns.pdsk == D_OUTDATED || mdev->ldev->dc.fencing == FP_DONT_CARE))
		ns.disk = D_UP_TO_DATE;

	/* All tests on MDF_PRIMARY_IND, MDF_CONNECTED_IND,
	   MDF_CONSISTENT and MDF_WAS_UP_TO_DATE must happen before
	   this point, because drbd_request_state() modifies these
	   flags. */

	/* In case we are C_CONNECTED postpone any desicion on the new disk
	   state after the negotiation phase. */
	if (mdev->state.conn == C_CONNECTED) {
		mdev->new_state_tmp.i = ns.i;
		ns.i = os.i;
		ns.disk = D_NEGOTIATING;
	}

	rv = _drbd_set_state(mdev, ns, CS_VERBOSE, NULL);
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);

	if (rv < SS_SUCCESS)
		goto force_diskless_dec;

	if (mdev->state.role == R_PRIMARY)
		mdev->ldev->md.uuid[UI_CURRENT] |=  (u64)1;
	else
		mdev->ldev->md.uuid[UI_CURRENT] &= ~(u64)1;

	drbd_md_mark_dirty(mdev);
	drbd_md_sync(mdev);

	put_ldev(mdev);
	reply->ret_code = retcode;
	drbd_reconfig_done(mdev);
	return 0;

 force_diskless_dec:
	put_ldev(mdev);
 force_diskless:
	drbd_force_state(mdev, NS(disk, D_DISKLESS));
	drbd_md_sync(mdev);
 release_bdev2_fail:
	if (nbc)
		bd_release(nbc->md_bdev);
 release_bdev_fail:
	if (nbc)
		bd_release(nbc->backing_bdev);
 fail:
	if (nbc) {
		if (nbc->lo_file)
			fput(nbc->lo_file);
		if (nbc->md_file)
			fput(nbc->md_file);
		kfree(nbc);
	}
	if (resync_lru)
		lc_free(resync_lru);

	reply->ret_code = retcode;
	drbd_reconfig_done(mdev);
	return 0;
}

STATIC int drbd_nl_detach(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			  struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev, NS(disk, D_DISKLESS));
	return 0;
}

STATIC int drbd_nl_net_conf(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			    struct drbd_nl_cfg_reply *reply)
{
	int i, ns;
	enum drbd_ret_codes retcode;
	struct net_conf *new_conf = NULL;
	struct crypto_hash *tfm = NULL;
	struct hlist_head *new_tl_hash = NULL;
	struct hlist_head *new_ee_hash = NULL;
	struct drbd_conf *odev;
	char hmac_name[CRYPTO_MAX_ALG_NAME];

	drbd_reconfig_start(mdev);

	if (mdev->state.conn > C_STANDALONE) {
		retcode = ERR_NET_CONFIGURED;
		goto fail;
	}

	new_conf = kmalloc(sizeof(struct net_conf), GFP_KERNEL);
	if (!new_conf) {
		retcode = ERR_NOMEM;
		goto fail;
	}

	memset(new_conf, 0, sizeof(struct net_conf));
	new_conf->timeout	   = DRBD_TIMEOUT_DEF;
	new_conf->try_connect_int  = DRBD_CONNECT_INT_DEF;
	new_conf->ping_int	   = DRBD_PING_INT_DEF;
	new_conf->max_epoch_size   = DRBD_MAX_EPOCH_SIZE_DEF;
	new_conf->max_buffers	   = DRBD_MAX_BUFFERS_DEF;
	new_conf->unplug_watermark = DRBD_UNPLUG_WATERMARK_DEF;
	new_conf->sndbuf_size	   = DRBD_SNDBUF_SIZE_DEF;
	new_conf->ko_count	   = DRBD_KO_COUNT_DEF;
	new_conf->after_sb_0p	   = DRBD_AFTER_SB_0P_DEF;
	new_conf->after_sb_1p	   = DRBD_AFTER_SB_1P_DEF;
	new_conf->after_sb_2p	   = DRBD_AFTER_SB_2P_DEF;
	new_conf->want_lose	   = 0;
	new_conf->two_primaries    = 0;
	new_conf->wire_protocol    = DRBD_PROT_C;
	new_conf->ping_timeo	   = DRBD_PING_TIMEO_DEF;
	new_conf->rr_conflict	   = DRBD_RR_CONFLICT_DEF;

	if (!net_conf_from_tags(mdev, nlp->tag_list, new_conf)) {
		retcode = ERR_MANDATORY_TAG;
		goto fail;
	}

	if (new_conf->two_primaries
	&& (new_conf->wire_protocol != DRBD_PROT_C)) {
		retcode = ERR_NOT_PROTO_C;
		goto fail;
	};

	if (mdev->state.role == R_PRIMARY && new_conf->want_lose) {
		retcode = ERR_DISCARD;
		goto fail;
	}

#define M_ADDR(A) (((struct sockaddr_in *)&A->my_addr)->sin_addr.s_addr)
#define M_PORT(A) (((struct sockaddr_in *)&A->my_addr)->sin_port)
#define O_ADDR(A) (((struct sockaddr_in *)&A->peer_addr)->sin_addr.s_addr)
#define O_PORT(A) (((struct sockaddr_in *)&A->peer_addr)->sin_port)
	retcode = NO_ERROR;
	for (i = 0; i < minor_count; i++) {
		odev = minor_to_mdev(i);
		if (!odev || odev == mdev)
			continue;
		if (get_net_conf(odev)) {
			if (M_ADDR(new_conf) == M_ADDR(odev->net_conf) &&
			    M_PORT(new_conf) == M_PORT(odev->net_conf))
				retcode = ERR_LOCAL_ADDR;

			if (O_ADDR(new_conf) == O_ADDR(odev->net_conf) &&
			    O_PORT(new_conf) == O_PORT(odev->net_conf))
				retcode = ERR_PEER_ADDR;

			put_net_conf(odev);
			if (retcode != NO_ERROR)
				goto fail;
		}
	}
#undef M_ADDR
#undef M_PORT
#undef O_ADDR
#undef O_PORT

	if (new_conf->cram_hmac_alg[0] != 0) {
		snprintf(hmac_name, CRYPTO_MAX_ALG_NAME, "hmac(%s)",
			new_conf->cram_hmac_alg);
		tfm = crypto_alloc_hash(hmac_name, 0, CRYPTO_ALG_ASYNC);
		if (IS_ERR(tfm)) {
			tfm = NULL;
			retcode = ERR_AUTH_ALG;
			goto fail;
		}

		if (crypto_tfm_alg_type(crypto_hash_tfm(tfm))
						!= CRYPTO_ALG_TYPE_HASH) {
			retcode = ERR_AUTH_ALG_ND;
			goto fail;
		}
	}


	ns = new_conf->max_epoch_size/8;
	if (mdev->tl_hash_s != ns) {
		new_tl_hash = kzalloc(ns*sizeof(void *), GFP_KERNEL);
		if (!new_tl_hash) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	ns = new_conf->max_buffers/8;
	if (new_conf->two_primaries && (mdev->ee_hash_s != ns)) {
		new_ee_hash = kzalloc(ns*sizeof(void *), GFP_KERNEL);
		if (!new_ee_hash) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	((char *)new_conf->shared_secret)[SHARED_SECRET_MAX-1] = 0;

#if 0
	/* for the connection loss logic in drbd_recv
	 * I _need_ the resulting timeo in jiffies to be
	 * non-zero and different
	 *
	 * XXX maybe rather store the value scaled to jiffies?
	 * Note: MAX_SCHEDULE_TIMEOUT/HZ*HZ != MAX_SCHEDULE_TIMEOUT
	 *	 and HZ > 10; which is unlikely to change...
	 *	 Thus, if interrupted by a signal,
	 *	 sock_{send,recv}msg returns -EINTR,
	 *	 if the timeout expires, -EAGAIN.
	 */
	/* unlikely: someone disabled the timeouts ...
	 * just put some huge values in there. */
	if (!new_conf->ping_int)
		new_conf->ping_int = MAX_SCHEDULE_TIMEOUT/HZ;
	if (!new_conf->timeout)
		new_conf->timeout = MAX_SCHEDULE_TIMEOUT/HZ*10;
	if (new_conf->ping_int*10 < new_conf->timeout)
		new_conf->timeout = new_conf->ping_int*10/6;
	if (new_conf->ping_int*10 == new_conf->timeout)
		new_conf->ping_int = new_conf->ping_int+1;
#endif

	if (!mdev->bitmap) {
		if (drbd_bm_init(mdev)) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	spin_lock_irq(&mdev->req_lock);
	if (mdev->net_conf != NULL) {
		retcode = ERR_NET_CONFIGURED;
		spin_unlock_irq(&mdev->req_lock);
		goto fail;
	}
	mdev->net_conf = new_conf;

	mdev->send_cnt = 0;
	mdev->recv_cnt = 0;

	if (new_tl_hash) {
		kfree(mdev->tl_hash);
		mdev->tl_hash_s = mdev->net_conf->max_epoch_size/8;
		mdev->tl_hash = new_tl_hash;
	}

	if (new_ee_hash) {
		kfree(mdev->ee_hash);
		mdev->ee_hash_s = mdev->net_conf->max_buffers/8;
		mdev->ee_hash = new_ee_hash;
	}

	crypto_free_hash(mdev->cram_hmac_tfm);
	mdev->cram_hmac_tfm = tfm;
	spin_unlock_irq(&mdev->req_lock);

	retcode = _drbd_request_state(mdev, NS(conn, C_UNCONNECTED), CS_VERBOSE);
	reply->ret_code = retcode;
	drbd_reconfig_done(mdev);
	return 0;

fail:
	crypto_free_hash(tfm);
	kfree(new_tl_hash);
	kfree(new_ee_hash);
	kfree(new_conf);

	reply->ret_code = retcode;
	drbd_reconfig_done(mdev);
	return 0;
}

STATIC int drbd_nl_disconnect(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	int retcode;

	retcode = _drbd_request_state(mdev, NS(conn, C_DISCONNECTING), CS_ORDERED);

	if (retcode == SS_NOTHING_TO_DO)
		goto done;
	else if (retcode == SS_ALREADY_STANDALONE)
		goto done;
	else if (retcode == SS_PRIMARY_NOP) {
		/* Our statche checking code wants to see the peer outdated. */
		retcode = drbd_request_state(mdev, NS2(conn, C_DISCONNECTING,
						      pdsk, D_OUTDATED));
	} else if (retcode == SS_CW_FAILED_BY_PEER) {
		/* The peer probabely wants to see us outdated. */
		retcode = _drbd_request_state(mdev, NS2(conn, C_DISCONNECTING,
							disk, D_OUTDATED),
					      CS_ORDERED);
		if (retcode == SS_IS_DISKLESS || retcode == SS_LOWER_THAN_OUTDATED) {
			drbd_force_state(mdev, NS(conn, C_DISCONNECTING));
			retcode = SS_SUCCESS;
		}
	}

	if (retcode < SS_SUCCESS)
		goto fail;

	if (wait_event_interruptible(mdev->state_wait,
				     mdev->state.conn != C_DISCONNECTING)) {
		/* Do not test for mdev->state.conn == C_STANDALONE, since
		   someone else might connect us in the mean time! */
		retcode = ERR_INTR;
		goto fail;
	}

 done:
	retcode = NO_ERROR;
 fail:
	drbd_md_sync(mdev);
	reply->ret_code = retcode;
	return 0;
}

void resync_after_online_grow(struct drbd_conf *mdev)
{
	int iass; /* I am sync source */

	INFO("Resync of new storage after online grow\n");
	if (mdev->state.role != mdev->state.peer)
		iass = (mdev->state.role == R_PRIMARY);
	else
		iass = test_bit(DISCARD_CONCURRENT, &mdev->flags);

	if (iass)
		drbd_start_resync(mdev, C_SYNC_SOURCE);
	else
		_drbd_request_state(mdev, NS(conn, C_WF_SYNC_UUID), CS_VERBOSE + CS_SERIALIZE);
}

STATIC int drbd_nl_resize(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			  struct drbd_nl_cfg_reply *reply)
{
	struct resize rs;
	int retcode = NO_ERROR;
	int ldsc = 0; /* local disk size changed */
	enum determine_dev_size dd;

	memset(&rs, 0, sizeof(struct resize));
	if (!resize_from_tags(mdev, nlp->tag_list, &rs)) {
		retcode = ERR_MANDATORY_TAG;
		goto fail;
	}

	if (mdev->state.conn > C_CONNECTED) {
		retcode = ERR_RESIZE_RESYNC;
		goto fail;
	}

	if (mdev->state.role == R_SECONDARY &&
	    mdev->state.peer == R_SECONDARY) {
		retcode = ERR_NO_PRIMARY;
		goto fail;
	}

	if (!get_ldev(mdev)) {
		retcode = ERR_NO_DISK;
		goto fail;
	}

	if (mdev->ldev->known_size != drbd_get_capacity(mdev->ldev->backing_bdev)) {
		mdev->ldev->known_size = drbd_get_capacity(mdev->ldev->backing_bdev);
		ldsc = 1;
	}

	mdev->ldev->dc.disk_size = (sector_t)rs.resize_size;
	dd = drbd_determin_dev_size(mdev);
	drbd_md_sync(mdev);
	put_ldev(mdev);
	if (dd == dev_size_error) {
		retcode = ERR_NOMEM_BITMAP;
		goto fail;
	}

	if (mdev->state.conn == C_CONNECTED && (dd != unchanged || ldsc)) {
		drbd_send_uuids(mdev);
		drbd_send_sizes(mdev);
		if (dd == grew)
			resync_after_online_grow(mdev);
	}

 fail:
	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_syncer_conf(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			       struct drbd_nl_cfg_reply *reply)
{
	int retcode = NO_ERROR;
	struct syncer_conf sc;
	int err;

	memcpy(&sc, &mdev->sync_conf, sizeof(struct syncer_conf));

	if (nlp->flags & DRBD_NL_SET_DEFAULTS) {
		memset(&sc, 0, sizeof(struct syncer_conf));
		sc.rate       = DRBD_RATE_DEF;
		sc.after      = DRBD_AFTER_DEF;
		sc.al_extents = DRBD_AL_EXTENTS_DEF;
	}

	if (!syncer_conf_from_tags(mdev, nlp->tag_list, &sc)) {
		retcode = ERR_MANDATORY_TAG;
		goto fail;
	}

	ERR_IF (sc.rate < 1) sc.rate = 1;
	ERR_IF (sc.al_extents < 7) sc.al_extents = 127; /* arbitrary minimum */
#define AL_MAX ((MD_AL_MAX_SIZE-1) * AL_EXTENTS_PT)
	if (sc.al_extents > AL_MAX) {
		ERR("sc.al_extents > %d\n", AL_MAX);
		sc.al_extents = AL_MAX;
	}
#undef AL_MAX

	/* most sanity checks done, try to assign the new sync-after
	 * dependency.  need to hold the global lock in there,
	 * to avoid a race in the dependency loop check. */
	retcode = drbd_alter_sa(mdev, sc.after);
	if (retcode != NO_ERROR)
		goto fail;

	/* ok, assign the rest of it as well.
	 * lock against receive_SyncParam() */
	spin_lock(&mdev->peer_seq_lock);
	mdev->sync_conf = sc;
	spin_unlock(&mdev->peer_seq_lock);

	if (get_ldev(mdev)) {
		wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));
		drbd_al_shrink(mdev);
		err = drbd_check_al_size(mdev);
		lc_unlock(mdev->act_log);
		wake_up(&mdev->al_wait);

		put_ldev(mdev);
		drbd_md_sync(mdev);

		if (err) {
			retcode = ERR_NOMEM;
			goto fail;
		}
	}

	if (mdev->state.conn >= C_CONNECTED)
		drbd_send_sync_param(mdev, &sc);

fail:
	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_invalidate(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev, NS2(conn, C_STARTING_SYNC_T,
						      disk, D_INCONSISTENT));
	return 0;
}

STATIC int drbd_nl_invalidate_peer(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
				   struct drbd_nl_cfg_reply *reply)
{

	reply->ret_code = drbd_request_state(mdev, NS2(conn, C_STARTING_SYNC_S,
						      pdsk, D_INCONSISTENT));

	return 0;
}

STATIC int drbd_nl_pause_sync(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	int retcode = NO_ERROR;

	if (drbd_request_state(mdev, NS(user_isp, 1)) == SS_NOTHING_TO_DO)
		retcode = ERR_PAUSE_IS_SET;

	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_resume_sync(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			       struct drbd_nl_cfg_reply *reply)
{
	int retcode = NO_ERROR;

	if (drbd_request_state(mdev, NS(user_isp, 0)) == SS_NOTHING_TO_DO)
		retcode = ERR_PAUSE_IS_CLEAR;

	reply->ret_code = retcode;
	return 0;
}

STATIC int drbd_nl_suspend_io(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			      struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev, NS(susp, 1));

	return 0;
}

STATIC int drbd_nl_resume_io(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev, NS(susp, 0));
	return 0;
}

STATIC int drbd_nl_outdate(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			   struct drbd_nl_cfg_reply *reply)
{
	reply->ret_code = drbd_request_state(mdev, NS(disk, D_OUTDATED));
	return 0;
}

STATIC int drbd_nl_get_config(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			   struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	if (get_ldev(mdev)) {
		tl = disk_conf_to_tags(mdev, &mdev->ldev->dc, tl);
		put_ldev(mdev);
	}

	if (get_net_conf(mdev)) {
		tl = net_conf_to_tags(mdev, mdev->net_conf, tl);
		put_net_conf(mdev);
	}
	tl = syncer_conf_to_tags(mdev, &mdev->sync_conf, tl);

	*tl++ = TT_END; /* Close the tag list */

	return (int)((char *)tl - (char *)reply->tag_list);
}

STATIC int drbd_nl_get_state(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	tl = get_state_to_tags(mdev, (struct get_state *)&mdev->state, tl);
	*tl++ = TT_END; /* Close the tag list */

	return (int)((char *)tl - (char *)reply->tag_list);
}

STATIC int drbd_nl_get_uuids(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
			     struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	if (get_ldev(mdev)) {
		/* This is a hand crafted add tag ;) */
		*tl++ = T_uuids;
		*tl++ = UI_SIZE*sizeof(u64);
		memcpy(tl, mdev->ldev->md.uuid, UI_SIZE*sizeof(u64));
		tl = (unsigned short *)((char *)tl + UI_SIZE*sizeof(u64));
		*tl++ = T_uuids_flags;
		*tl++ = sizeof(int);
		memcpy(tl, &mdev->ldev->md.flags, sizeof(int));
		tl = (unsigned short *)((char *)tl + sizeof(int));
		put_ldev(mdev);
	}
	*tl++ = TT_END; /* Close the tag list */

	return (int)((char *)tl - (char *)reply->tag_list);
}


STATIC int drbd_nl_get_timeout_flag(struct drbd_conf *mdev, struct drbd_nl_cfg_req *nlp,
				    struct drbd_nl_cfg_reply *reply)
{
	unsigned short *tl;

	tl = reply->tag_list;

	/* This is a hand crafted add tag ;) */
	*tl++ = T_use_degraded;
	*tl++ = sizeof(char);
	*((char *)tl) = test_bit(USE_DEGR_WFC_T, &mdev->flags) ? 1 : 0 ;
	tl = (unsigned short *)((char *)tl + sizeof(char));
	*tl++ = TT_END;

	return (int)((char *)tl - (char *)reply->tag_list);
}

STATIC struct drbd_conf *ensure_mdev(struct drbd_nl_cfg_req *nlp)
{
	struct drbd_conf *mdev;

	if (nlp->drbd_minor >= minor_count)
		return NULL;

	mdev = minor_to_mdev(nlp->drbd_minor);

	if (!mdev && (nlp->flags & DRBD_NL_CREATE_DEVICE)) {
		struct gendisk *disk = NULL;
		mdev = drbd_new_device(nlp->drbd_minor);

		spin_lock_irq(&drbd_pp_lock);
		if (minor_table[nlp->drbd_minor] == NULL) {
			minor_table[nlp->drbd_minor] = mdev;
			disk = mdev->vdisk;
			mdev = NULL;
		} /* else: we lost the race */
		spin_unlock_irq(&drbd_pp_lock);

		if (disk) /* we won the race above */
			/* in case we ever add a drbd_delete_device(),
			 * don't forget the del_gendisk! */
			add_disk(disk);
		else /* we lost the race above */
			drbd_free_mdev(mdev);

		mdev = minor_to_mdev(nlp->drbd_minor);
	}

	return mdev;
}

struct cn_handler_struct {
	int (*function)(struct drbd_conf *,
			 struct drbd_nl_cfg_req *,
			 struct drbd_nl_cfg_reply *);
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
	[ P_get_timeout_flag ]	=
		{ &drbd_nl_get_timeout_flag,
		  sizeof(struct get_timeout_flag_tag_len_struct)},

};

STATIC void drbd_connector_callback(void *data)
{
	struct cn_msg *req = data;
	struct drbd_nl_cfg_req *nlp = (struct drbd_nl_cfg_req *)req->data;
	struct cn_handler_struct *cm;
	struct cn_msg *cn_reply;
	struct drbd_nl_cfg_reply *reply;
	struct drbd_conf *mdev;
	int retcode, rr;
	int reply_size = sizeof(struct cn_msg)
		+ sizeof(struct drbd_nl_cfg_reply)
		+ sizeof(short int);

	if (!try_module_get(THIS_MODULE)) {
		printk(KERN_ERR "drbd: try_module_get() failed!\n");
		return;
	}

	mdev = ensure_mdev(nlp);
	if (!mdev) {
		retcode = ERR_MINOR_INVALID;
		goto fail;
	}

	TRACE(TRACE_TYPE_NL, TRACE_LVL_SUMMARY, nl_trace_packet(data););

	if (nlp->packet_type >= P_nl_after_last_packet) {
		retcode = ERR_PACKET_NR;
		goto fail;
	}

	cm = cnd_table + nlp->packet_type;

	/* This may happen if packet number is 0: */
	if (cm->function == NULL) {
		retcode = ERR_PACKET_NR;
		goto fail;
	}

	reply_size += cm->reply_body_size;

	cn_reply = kmalloc(reply_size, GFP_KERNEL);
	if (!cn_reply) {
		retcode = ERR_NOMEM;
		goto fail;
	}
	reply = (struct drbd_nl_cfg_reply *) cn_reply->data;

	reply->packet_type =
		cm->reply_body_size ? nlp->packet_type : P_nl_after_last_packet;
	reply->minor = nlp->drbd_minor;
	reply->ret_code = NO_ERROR; /* Might by modified by cm->function. */
	/* reply->tag_list; might be modified by cm->fucntion. */

	rr = cm->function(mdev, nlp, reply);

	cn_reply->id = req->id;
	cn_reply->seq = req->seq;
	cn_reply->ack = req->ack  + 1;
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) + rr;
	cn_reply->flags = 0;

	TRACE(TRACE_TYPE_NL, TRACE_LVL_SUMMARY, nl_trace_reply(cn_reply););

	rr = cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
	if (rr && rr != -ESRCH)
		printk(KERN_INFO "drbd: cn_netlink_send()=%d\n", rr);

	kfree(cn_reply);
	module_put(THIS_MODULE);
	return;
 fail:
	drbd_nl_send_reply(req, retcode);
	module_put(THIS_MODULE);
}

static atomic_t drbd_nl_seq = ATOMIC_INIT(2); /* two. */

void drbd_bcast_state(struct drbd_conf *mdev, union drbd_state state)
{
	char buffer[sizeof(struct cn_msg)+
		    sizeof(struct drbd_nl_cfg_reply)+
		    sizeof(struct get_state_tag_len_struct)+
		    sizeof(short int)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply *reply =
		(struct drbd_nl_cfg_reply *)cn_reply->data;
	unsigned short *tl = reply->tag_list;

	/* drbd_WARN("drbd_bcast_state() got called\n"); */

	tl = get_state_to_tags(mdev, (struct get_state *)&state, tl);
	*tl++ = TT_END; /* Close the tag list */

	cn_reply->id.idx = CN_IDX_DRBD;
	cn_reply->id.val = CN_VAL_DRBD;

	cn_reply->seq = atomic_add_return(1, &drbd_nl_seq);
	cn_reply->ack = 0; /* not used here. */
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) +
		(int)((char *)tl - (char *)reply->tag_list);
	cn_reply->flags = 0;

	reply->packet_type = P_get_state;
	reply->minor = mdev_to_minor(mdev);
	reply->ret_code = NO_ERROR;

	TRACE(TRACE_TYPE_NL, TRACE_LVL_SUMMARY, nl_trace_reply(cn_reply););

	cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
}

void drbd_bcast_ev_helper(struct drbd_conf *mdev, char *helper_name)
{
	char buffer[sizeof(struct cn_msg)+
		    sizeof(struct drbd_nl_cfg_reply)+
		    sizeof(struct call_helper_tag_len_struct)+
		    sizeof(short int)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply *reply =
		(struct drbd_nl_cfg_reply *)cn_reply->data;
	unsigned short *tl = reply->tag_list;
	int str_len;

	/* drbd_WARN("drbd_bcast_state() got called\n"); */

	str_len = strlen(helper_name)+1;
	*tl++ = T_helper;
	*tl++ = str_len;
	memcpy(tl, helper_name, str_len);
	tl = (unsigned short *)((char *)tl + str_len);
	*tl++ = TT_END; /* Close the tag list */

	cn_reply->id.idx = CN_IDX_DRBD;
	cn_reply->id.val = CN_VAL_DRBD;

	cn_reply->seq = atomic_add_return(1, &drbd_nl_seq);
	cn_reply->ack = 0; /* not used here. */
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) +
		(int)((char *)tl - (char *)reply->tag_list);
	cn_reply->flags = 0;

	reply->packet_type = P_call_helper;
	reply->minor = mdev_to_minor(mdev);
	reply->ret_code = NO_ERROR;

	TRACE(TRACE_TYPE_NL, TRACE_LVL_SUMMARY, nl_trace_reply(cn_reply););

	cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
}

void drbd_bcast_sync_progress(struct drbd_conf *mdev)
{
	char buffer[sizeof(struct cn_msg)+
		    sizeof(struct drbd_nl_cfg_reply)+
		    sizeof(struct sync_progress_tag_len_struct)+
		    sizeof(short int)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply *reply =
		(struct drbd_nl_cfg_reply *)cn_reply->data;
	unsigned short *tl = reply->tag_list;
	unsigned long rs_left;
	unsigned int res;

	/* no local ref, no bitmap, no syncer progress, no broadcast. */
	if (!get_ldev(mdev))
		return;
	drbd_get_syncer_progress(mdev, &rs_left, &res);
	put_ldev(mdev);

	*tl++ = T_sync_progress;
	*tl++ = sizeof(int);
	memcpy(tl, &res, sizeof(int));
	tl = (unsigned short *)((char *)tl + sizeof(int));
	*tl++ = TT_END; /* Close the tag list */

	cn_reply->id.idx = CN_IDX_DRBD;
	cn_reply->id.val = CN_VAL_DRBD;

	cn_reply->seq = atomic_add_return(1, &drbd_nl_seq);
	cn_reply->ack = 0; /* not used here. */
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply) +
		(int)((char *)tl - (char *)reply->tag_list);
	cn_reply->flags = 0;

	reply->packet_type = P_sync_progress;
	reply->minor = mdev_to_minor(mdev);
	reply->ret_code = NO_ERROR;

	TRACE(TRACE_TYPE_NL, TRACE_LVL_SUMMARY, nl_trace_reply(cn_reply););

	cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
}

#ifdef NETLINK_ROUTE6
int __init cn_init(void);
void __exit cn_fini(void);
#endif

int __init drbd_nl_init(void)
{
	static struct cb_id cn_id_drbd;
	int err, try=10;

#ifdef NETLINK_ROUTE6
	/* pre 2.6.16 */
	err = cn_init();
	if (err)
		return err;
#endif
	cn_id_drbd.val = CN_VAL_DRBD;
	do {
		cn_id_drbd.idx = cn_idx;
		err = cn_add_callback(&cn_id_drbd, "cn_drbd", &drbd_connector_callback);
		if (!err)
			break;
		cn_idx = (cn_idx + CN_IDX_STEP);
	} while (try--);

	if (err) {
		printk(KERN_ERR "drbd: cn_drbd failed to register\n");
		return err;
	}

	return 0;
}

void drbd_nl_cleanup(void)
{
	static struct cb_id cn_id_drbd;

	cn_id_drbd.idx = cn_idx;
	cn_id_drbd.val = CN_VAL_DRBD;

	cn_del_callback(&cn_id_drbd);

#ifdef NETLINK_ROUTE6
	/* pre 2.6.16 */
	cn_fini();
#endif
}

void drbd_nl_send_reply(struct cn_msg *req, int ret_code)
{
	char buffer[sizeof(struct cn_msg)+sizeof(struct drbd_nl_cfg_reply)];
	struct cn_msg *cn_reply = (struct cn_msg *) buffer;
	struct drbd_nl_cfg_reply *reply =
		(struct drbd_nl_cfg_reply *)cn_reply->data;
	int rr;

	cn_reply->id = req->id;

	cn_reply->seq = req->seq;
	cn_reply->ack = req->ack  + 1;
	cn_reply->len = sizeof(struct drbd_nl_cfg_reply);
	cn_reply->flags = 0;

	reply->minor = ((struct drbd_nl_cfg_req *)req->data)->drbd_minor;
	reply->ret_code = ret_code;

	TRACE(TRACE_TYPE_NL, TRACE_LVL_SUMMARY, nl_trace_reply(cn_reply););

	rr = cn_netlink_send(cn_reply, CN_IDX_DRBD, GFP_KERNEL);
	if (rr && rr != -ESRCH)
		printk(KERN_INFO "drbd: cn_netlink_send()=%d\n", rr);
}

