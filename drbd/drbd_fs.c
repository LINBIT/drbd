/*
-*- linux-c -*-
   drbd_fs.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
	Some sanity checks in IOCTL_SET_STATE.

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
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/drbd.h>
#include "drbd_int.h"

#include <linux/blkpg.h>

/* see get_sb_bdev and bd_claim */
char *drbd_sec_holder = "Secondary DRBD cannot be bd_claimed ;)";
char *drbd_m_holder = "Hands off! this is DRBD's meta data device.";



/* initializes the md.*_offset members, so we are able to find
 * the on disk meta data */
STATIC void drbd_md_set_sector_offsets(drbd_dev *mdev,
				       struct drbd_backing_dev *bdev)
{
	sector_t md_size_sect = 0;
	switch(bdev->md_index) {
	default:
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

char* ppsize(char* buf, size_t size)
{
	// Needs 9 bytes at max.
	static char units[] = { 'K','M','G','T','P','E' };
	int base = 0;
	while (size >= 10000 ) {
		size = size >> 10;
		base++;
	}
	sprintf(buf,"%ld %cB",(long)size,units[base]);

	return buf;
}

/* You should call drbd_md_sync() after calling this.
 */
int drbd_determin_dev_size(struct Drbd_Conf* mdev)
{
	sector_t prev_first_sect, prev_size; // previous meta location
	sector_t la_size;
	sector_t size;
	char ppb[10];

	int md_moved, la_size_changed;
	int rv=0;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));

	prev_first_sect = drbd_md_first_sector(mdev->bc);
	prev_size = mdev->bc->md.md_size_sect;
	la_size = mdev->bc->md.la_size_sect;

	// TODO: should only be some assert here, not (re)init...
	drbd_md_set_sector_offsets(mdev,mdev->bc);

	size = drbd_new_dev_size(mdev,mdev->bc);

	if( drbd_get_capacity(mdev->this_bdev) != size ) {
		int err;
		err = drbd_bm_resize(mdev,size);
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = drbd_bm_capacity(mdev)>>1;
			if (size == 0) {
				ERR("OUT OF MEMORY! Could not allocate bitmap! Set device size => 0\n");
			} else {
				/* FIXME this is problematic,
				 * if we in fact are smaller now! */
				ERR("BM resizing failed. "
				    "Leaving size unchanged at size = %lu KB\n",
				    (unsigned long)size);
			}
			rv = err;
		}
		// racy, see comments above.
		drbd_set_my_capacity(mdev,size);
		mdev->bc->md.la_size_sect = size;
		INFO("size = %s (%lu KB)\n",ppsize(ppb,size>>1),
		     (unsigned long)size>>1);
	}
	if (rv < 0) goto out;

	la_size_changed = (la_size != mdev->bc->md.la_size_sect);

	//LGE: flexible device size!! is this the right thing to test?
	md_moved = prev_first_sect != drbd_md_first_sector(mdev->bc)
		|| prev_size       != mdev->bc->md.md_size_sect;

	if ( md_moved ) {
		WARN("Moving meta-data.\n");
		/* assert: (flexible) internal meta data */
	}

	if ( la_size_changed || md_moved ) {
		if( inc_md_only(mdev,Attaching) ) {
			drbd_al_shrink(mdev); // All extents inactive.
			drbd_bm_write(mdev);  // write bitmap
			// Write mdev->la_size to on disk.
			drbd_md_mark_dirty(mdev);
			dec_local(mdev);
		}
	}
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
	sector_t u_size = bdev->u_size; // size requested by user.
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
		if(u_size<<1 > size) {
			ERR("Requested disk size is too big (%lu > %lu)\n",
			    (unsigned long)u_size, (unsigned long)size>>1);
		} else {
			size = u_size<<1;
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
	request_queue_t * const q = mdev->rq_queue;
	request_queue_t * const b = mdev->bc->backing_bdev->bd_disk->queue;

	unsigned int old_max_seg_s = q->max_segment_size;

	if(b->merge_bvec_fn) {
		max_seg_s = PAGE_SIZE;
	}

	q->max_sectors       = max_seg_s >> 9;
	q->max_phys_segments = max_seg_s >> PAGE_SHIFT;
	q->max_hw_segments   = max_seg_s >> PAGE_SHIFT;
	q->max_segment_size  = max_seg_s;
	q->hardsect_size     = 512;
	q->seg_boundary_mask = PAGE_SIZE-1;
	blk_queue_stack_limits(q, b);

	if( old_max_seg_s != q->max_segment_size ) {
		if(b->merge_bvec_fn) {
			WARN("Backing device has merge_bvec_fn()!\n");
		}
		INFO("max_segment_size ( = BIO size ) = %u\n",
		     q->max_segment_size);
	}

	if( q->backing_dev_info.ra_pages != b->backing_dev_info.ra_pages) {
		INFO("Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
		     q->backing_dev_info.ra_pages,
		     b->backing_dev_info.ra_pages);
		q->backing_dev_info.ra_pages = b->backing_dev_info.ra_pages;
	}
}

STATIC
int drbd_ioctl_set_disk(drbd_dev *mdev, struct ioctl_disk_config * arg)
{
	int minor;
	enum ret_codes retcode;
	struct disk_config new_conf;  // local copy of ioctl() args.
	struct drbd_backing_dev* nbc; // new_backing_conf
	struct inode *inode, *inode2;
	struct lru_cache* resync_lru = NULL;
	drbd_state_t ns,os;
	int rv;

	minor=(int)(mdev-drbd_conf);

	/* if you want to reconfigure, please tear down first */
	if (mdev->state.disk > Diskless)
		return -EBUSY;

	if (copy_from_user(&new_conf, &arg->config,sizeof(struct disk_config)))
		return -EFAULT;

	nbc = kmalloc(sizeof(struct drbd_backing_dev),GFP_KERNEL);
	if(!nbc) {			
		retcode=KMallocFailed;
		goto fail_ioctl;
	}
	nbc->lo_file = NULL;
	nbc->md_file = NULL;

	if ( new_conf.meta_index < DRBD_MD_INDEX_FLEX_INT) {
		retcode=LDMDInvalid;
		goto fail_ioctl;
	}

	nbc->lo_file = fget(new_conf.lower_device);
	if (!nbc->lo_file) {
		retcode=LDFDInvalid;
		goto fail_ioctl;
	}

	inode = nbc->lo_file->f_dentry->d_inode;

	if (!S_ISBLK(inode->i_mode)) {
		retcode=LDNoBlockDev;
		goto fail_ioctl;
	}

	nbc->md_file = fget(new_conf.meta_device);

	if (!nbc->md_file) {
		retcode=MDFDInvalid;
		goto fail_ioctl;
	}

	inode2 = nbc->md_file->f_dentry->d_inode;

	if (!S_ISBLK(inode2->i_mode)) {
		retcode=MDNoBlockDev;
		goto fail_ioctl;
	}

	nbc->backing_bdev = inode->i_bdev;
	if (bd_claim(nbc->backing_bdev, mdev)) {
		retcode=LDMounted;
		goto fail_ioctl;
	}

	resync_lru = lc_alloc("resync",7, sizeof(struct bm_extent),mdev);
	if(!resync_lru) {
		retcode=KMallocFailed;
		goto fail_ioctl;
	}

	nbc->md_bdev = inode2->i_bdev;
	if (bd_claim(nbc->md_bdev,
		     (new_conf.meta_index==DRBD_MD_INDEX_INTERNAL ||
		      new_conf.meta_index==DRBD_MD_INDEX_FLEX_INT) ?
		     (void *)mdev : (void*) drbd_m_holder )) {
		retcode=MDMounted;
		goto release_bdev_fail_ioctl;
	}

	if ( (nbc->backing_bdev==nbc->md_bdev) != 
	     (new_conf.meta_index==DRBD_MD_INDEX_INTERNAL ||
	      new_conf.meta_index==DRBD_MD_INDEX_FLEX_INT) ) {
		retcode=LDMDInvalid;
		goto release_bdev2_fail_ioctl;
	}

	if ((drbd_get_capacity(nbc->backing_bdev)>>1) < new_conf.disk_size) {
		retcode = LDDeviceTooSmall;
		goto release_bdev2_fail_ioctl;
	}

#warning checks below no longer valid
// --- rewrite
#if 0
	if (drbd_get_capacity(nbc->backing_bdev) >= (sector_t)DRBD_MAX_SECTORS) {
		retcode = LDDeviceTooLarge;
		goto release_bdev2_fail_ioctl;
	}

	if ( new_conf.meta_index == -1 ) i = 1;
	else i = new_conf.meta_index+1;

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
				+ (new_conf.meta_index == -1) ? (1<<16) : 0 )
	{
		retcode = MDDeviceTooSmall;
		goto release_bdev2_fail_ioctl;
	}
#endif
// -- up to here

	// Make sure the new disk is big enough
	if (drbd_get_capacity(nbc->backing_bdev) < 
	    drbd_get_capacity(mdev->this_bdev) ) {
		retcode = LDDeviceTooSmall;
		goto release_bdev2_fail_ioctl;
	}

	if(drbd_request_state(mdev,NS(disk,Attaching)) < SS_Success ) {
		retcode = StateNotAllowed;
		goto release_bdev2_fail_ioctl;
	}

	nbc->md_index = new_conf.meta_index;
	nbc->u_size = new_conf.disk_size;
	nbc->on_io_error = new_conf.on_io_error;
	nbc->fencing = new_conf.fencing;
	drbd_md_set_sector_offsets(mdev,nbc);

	retcode = drbd_md_read(mdev,nbc);
	if ( retcode != NoError ) {
		goto release_bdev3_fail_ioctl;
	}

	// Since ware are diskless, fix the AL first...
	if (drbd_check_al_size(mdev)) {
		retcode = KMallocFailed;
		goto release_bdev3_fail_ioctl;
	}

	// Prevent shrinking of consistent devices !
	if(drbd_md_test_flag(nbc,MDF_Consistent) &&
	   drbd_new_dev_size(mdev,nbc) < nbc->md.la_size_sect) {
		retcode = LDDeviceTooSmall;
		goto release_bdev3_fail_ioctl;
	}

	if(!drbd_al_read_log(mdev,nbc)) {
		retcode = MDIOError;
		goto release_bdev3_fail_ioctl;		
	}

	// Point of no return reached.

	if(drbd_md_test_flag(nbc,MDF_PrimaryInd)) {
		set_bit(CRASHED_PRIMARY, &mdev->flags);
	} else {		
		clear_bit(CRASHED_PRIMARY, &mdev->flags);
	}

	D_ASSERT(mdev->bc == NULL);
	mdev->bc = nbc;
	mdev->resync = resync_lru;

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
	drbd_determin_dev_size(mdev);

	if (drbd_md_test_flag(mdev->bc,MDF_FullSync)) {
		INFO("Assuming that all blocks are out of sync (aka FullSync)\n");
		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);
		drbd_md_clear_flag(mdev,MDF_FullSync);
	} else {
		/* FIXME this still does not propagate io errors! */
		drbd_bm_read(mdev);
	}

	if(test_bit(CRASHED_PRIMARY, &mdev->flags)) {
		drbd_al_apply_to_bm(mdev);
		drbd_al_to_on_disk_bm(mdev);
	}
	/* else {
	     FIXME wipe out on disk al!
	} */


	if(mdev->state.conn == Connected) {
		drbd_send_sizes(mdev);  // to start sync...
		drbd_send_uuids(mdev);
		drbd_send_state(mdev);
	} else {
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
		    ( ns.pdsk == Outdated || nbc->fencing == DontCare ) ) {
			ns.disk = UpToDate;
		}
		
		/* All tests on MDF_PrimaryInd, MDF_ConnectedInd, 
		   MDF_Consistent and MDF_WasUpToDate must happen before 
		   this point, because drbd_request_state() modifies these
		   flags. */

		rv = _drbd_set_state(mdev, ns, ChgStateVerbose);
		ns = mdev->state;
		spin_unlock_irq(&mdev->req_lock);
		after_state_ch(mdev,os,ns,ChgStateVerbose);

		if(rv < SS_Success ) {
			drbd_bm_unlock(mdev);
			goto  release_bdev3_fail_ioctl;
		}
	}

	drbd_bm_unlock(mdev);
	drbd_md_sync(mdev);

	return 0;

 release_bdev3_fail_ioctl:
	drbd_force_state(mdev,NS(disk,Diskless));
	drbd_md_sync(mdev);
 release_bdev2_fail_ioctl:
	bd_release(nbc->md_bdev);
 release_bdev_fail_ioctl:
	bd_release(nbc->backing_bdev);
 fail_ioctl:
	if (nbc->lo_file) fput(nbc->lo_file);
	if (nbc->md_file) fput(nbc->md_file);
	if (nbc) kfree(nbc);
	if (resync_lru) lc_free(resync_lru);
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

STATIC
int drbd_ioctl_get_conf(struct Drbd_Conf *mdev, struct ioctl_get_config* arg)
{
	struct ioctl_get_config cn;
	memset(&cn,0,sizeof(cn));

	if(inc_local(mdev)) {
		cn.lower_device_major = MAJOR(mdev->bc->backing_bdev->bd_dev);
		cn.lower_device_minor = MINOR(mdev->bc->backing_bdev->bd_dev);
		bdevname(mdev->bc->backing_bdev,cn.lower_device_name);
		cn.meta_device_major  = MAJOR(mdev->bc->md_bdev->bd_dev);
		cn.meta_device_minor  = MINOR(mdev->bc->md_bdev->bd_dev);
		bdevname(mdev->bc->md_bdev,cn.meta_device_name);
		cn.meta_index=mdev->bc->md_index;
		cn.on_io_error=mdev->bc->on_io_error;
		cn.fencing=mdev->bc->fencing;
		dec_local(mdev);
	}
	cn.state=mdev->state;
	if(inc_net(mdev)) {
		memcpy(&cn.nconf, mdev->net_conf, sizeof(struct net_config));
		dec_net(mdev);
	}
	memcpy(&cn.sconf, &mdev->sync_conf, sizeof(struct syncer_config));

	if (copy_to_user(arg,&cn,sizeof(struct ioctl_get_config)))
		return -EFAULT;

	return 0;
}


STATIC
int drbd_ioctl_set_net(struct Drbd_Conf *mdev, struct ioctl_net_config * arg)
{
	int i,minor,ns;
	enum ret_codes retcode;
	struct net_config *new_conf = NULL;
	struct crypto_tfm* tfm = NULL;
	struct hlist_head *new_tl_hash = NULL;
	struct hlist_head *new_ee_hash = NULL;

	minor=(int)(mdev-drbd_conf);

	new_conf = kmalloc(sizeof(struct net_config),GFP_KERNEL);
	if(!new_conf) {			
		retcode=KMallocFailed;
		goto fail_ioctl;
	}

	if (copy_from_user(new_conf, &arg->config,sizeof(struct net_config)))
		return -EFAULT;

	if( mdev->state.role == Primary && new_conf->want_lose ) {
		retcode=DiscardNotAllowed;
		goto fail_ioctl;
	}

#define M_ADDR(A) (((struct sockaddr_in *)&A->my_addr)->sin_addr.s_addr)
#define M_PORT(A) (((struct sockaddr_in *)&A->my_addr)->sin_port)
#define O_ADDR(A) (((struct sockaddr_in *)&A->other_addr)->sin_addr.s_addr)
#define O_PORT(A) (((struct sockaddr_in *)&A->other_addr)->sin_port)
	for(i=0;i<minor_count;i++) {
		if( i!=minor && drbd_conf[i].state.conn > StandAlone &&
		    M_ADDR(new_conf) == M_ADDR(drbd_conf[i].net_conf) &&
		    M_PORT(new_conf) == M_PORT(drbd_conf[i].net_conf) ) {
			retcode=LAAlreadyInUse;
			goto fail_ioctl;
		}
		if( i!=minor && drbd_conf[i].state.conn > StandAlone &&
		    O_ADDR(new_conf) == O_ADDR(drbd_conf[i].net_conf) &&
		    O_PORT(new_conf) == O_PORT(drbd_conf[i].net_conf) ) {
			retcode=OAAlreadyInUse;
			goto fail_ioctl;
		}
	}
#undef M_ADDR
#undef M_PORT
#undef O_ADDR
#undef O_PORT

	if( new_conf->cram_hmac_alg[0] != 0) {
		tfm = crypto_alloc_tfm(new_conf->cram_hmac_alg, 0);
		if (tfm == NULL) {
			retcode=CRAMAlgNotAvail;
			goto fail_ioctl;
		}

		if (crypto_tfm_alg_type(tfm) != CRYPTO_ALG_TYPE_DIGEST) {
			retcode=CRAMAlgNotDigest;
			goto fail_ioctl;
		}
	}


	ns = new_conf->max_epoch_size/8;
	if (mdev->tl_hash_s != ns) {
		new_tl_hash=kmalloc(ns*sizeof(void*), GFP_KERNEL);
		if(!new_tl_hash) {
			retcode=KMallocFailed;
			goto fail_ioctl;
		}
		memset(new_tl_hash, 0, ns*sizeof(void*));
	}

	ns = new_conf->max_buffers/8;
	if (new_conf->two_primaries && ( mdev->ee_hash_s != ns ) ) {
		new_ee_hash=kmalloc(ns*sizeof(void*), GFP_KERNEL);
		if(!new_ee_hash) {
			retcode=KMallocFailed;
			goto fail_ioctl;
		}
		memset(new_ee_hash, 0, ns*sizeof(void*));
	}

	/* IMPROVE:
	   We should warn the user if the LL_DEV is
	   used already. E.g. some FS mounted on it.
	*/

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

	drbd_sync_me(mdev);
	drbd_thread_stop(&mdev->receiver); // conn = StadAlone afterwards
	drbd_free_sock(mdev);

	/* As soon as mdev->state.conn < Unconnected nobody can increase
	   the net_cnt. Wait until the net_cnt is 0. */
	if ( wait_event_interruptible( mdev->cstate_wait,
				       atomic_read(&mdev->net_cnt) == 0 ) ) {
		retcode=GotSignal;
		goto fail_ioctl;
	}

	/* Now we may touch net_conf */
	if (mdev->net_conf) kfree(mdev->net_conf);
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
		crypto_free_tfm(mdev->cram_hmac_tfm);
	}
	mdev->cram_hmac_tfm = tfm;

	drbd_request_state(mdev,NS(conn,Unconnected));

	return 0;

  fail_ioctl:
	if (tfm) crypto_free_tfm(tfm);
	if (new_tl_hash) kfree(new_tl_hash);
	if (new_ee_hash) kfree(new_ee_hash);
	if (new_conf) kfree(new_conf);
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

int drbd_khelper(drbd_dev *mdev, char* cmd)
{
	char mb[12];
	char *argv[] = {"/sbin/drbdadm", cmd, mb, NULL };
	static char *envp[] = { "HOME=/",
				"TERM=linux",
				"PATH=/sbin:/usr/sbin:/bin:/usr/bin",
				NULL };

	snprintf(mb,12,"minor-%d",(int)(mdev-drbd_conf));
	return call_usermodehelper("/sbin/drbdadm",argv,envp,1);
}

drbd_disks_t drbd_try_outdate_peer(drbd_dev *mdev)
{
	int r;
	drbd_disks_t nps;
	enum fencing_policy fp;

	D_ASSERT(mdev->state.pdsk == DUnknown);

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->fencing;
		dec_local(mdev);
	}

	D_ASSERT( fp > DontCare );

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
		drbd_request_state(mdev,NS(disk,Outdated));
		ERR("outdate-peer helper broken, returned %d \n",(r>>8)&0xff);
		return nps;
	}

	INFO("outdate-peer helper returned %d \n",(r>>8)&0xff);
	return nps;
}

int drbd_set_role(drbd_dev *mdev, int* arg)
{
	drbd_role_t newstate = *arg;
	int rv,r=0,forced = 0, try=0;
	drbd_state_t mask, val;
	drbd_disks_t nps;

	D_ASSERT(semaphore_is_locked(&mdev->device_mutex));

	// exactly one of sec or pri. not both.
	if ( !((newstate ^ (newstate >> 1)) & 1) ) return -EINVAL;

	ERR_IF (mdev->this_bdev->bd_contains == 0) {
		// FIXME this masks a bug somewhere else!
		mdev->this_bdev->bd_contains = mdev->this_bdev;
	}

	if ( newstate & Secondary ) {
		/* If I got here, I am Primary. I claim me for myself. If that
		 * does not succeed, someone other has claimed me, so I cannot
		 * become Secondary. */
		if (bd_claim(mdev->this_bdev,drbd_sec_holder))
			return -EBUSY;
		if (disable_bd_claim)
			bd_release(mdev->this_bdev);
	}

	mask.i = 0; mask.role = role_mask;
	val.i  = 0; val.role  = newstate & role_mask;

	while (try++ < 3) {
		r = _drbd_request_state(mdev,mask,val,0);
		if( r == SS_NoUpToDateDisk && (newstate & DontBlameDrbd) && 
		    ( mdev->state.disk == Inconsistent || 
		      mdev->state.disk == Outdated ) ) {
			mask.disk = disk_mask;
			val.disk  = UpToDate;
			forced = 1;
			continue;
		}
		if ( r == SS_NothingToDo ) { rv = 0; goto fail; }
		if ( r == SS_PrimaryNOP ) {
			nps = drbd_try_outdate_peer(mdev);

			if ( newstate & DontBlameDrbd && nps > Outdated ) {
				WARN("Forced into split brain situation!\n");
				nps = Outdated;
			}

			mask.pdsk = disk_mask;
			val.pdsk  = nps;

			continue;
		}

		if ( r < SS_Success ) {
			r = drbd_request_state(mdev,mask,val); // Be verbose.
			if( r < SS_Success ) {
				rv = -EIO;
				goto fail;
			}
		}
		break;
	}

	if(forced) WARN("Forced to conisder local data as UpToDate!\n");

	drbd_sync_me(mdev);

	/* Wait until nothing is on the fly :) */
	if ( wait_event_interruptible( mdev->cstate_wait,
			         atomic_read(&mdev->ap_pending_cnt) == 0 ) ) {
		rv = -EINTR;
		goto fail;
	}

	/* FIXME RACE here: if our direct user is not using bd_claim (i.e.
	 *  not a filesystem) since cstate might still be >= Connected, new
	 * ap requests may come in and increase ap_pending_cnt again!
	 * but that means someone is misusing DRBD...
	 * */

	if (newstate & Secondary) {
		set_disk_ro(mdev->vdisk, TRUE );
	} else {
		if(inc_net(mdev)) {
			mdev->net_conf->want_lose = 0;
			dec_net(mdev);
		}
		set_disk_ro(mdev->vdisk, FALSE );
		D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
		bd_release(mdev->this_bdev);
		mdev->this_bdev->bd_disk = mdev->vdisk;

		if ( ( ( mdev->state.conn < Connected ||
			 mdev->state.pdsk <= Attaching ) &&
		       mdev->bc->md.uuid[Bitmap] == 0) || forced ) {
			drbd_uuid_new_current(mdev);
		}
	}

	if(mdev->state.disk > Diskless && (newstate & Secondary)) {
		drbd_al_to_on_disk_bm(mdev);
	}

	if (mdev->state.conn >= WFReportParams) {
		/* if this was forced, we should consider sync */
		if(forced) drbd_send_uuids(mdev);
		drbd_send_state(mdev);
	}

	drbd_md_sync(mdev);

	return 0;

 fail:
	if ( newstate & Secondary ) {
		D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
		bd_release(mdev->this_bdev);
	}
	*arg = r;
	return rv;
}

static int drbd_get_wait_time(long *tp, struct Drbd_Conf *mdev,
			      struct ioctl_wait *arg)
{
	long time;
	struct ioctl_wait p;

	if(copy_from_user(&p,arg,sizeof(p))) {
		return -EFAULT;
	}
	if ( test_bit(USE_DEGR_WFC_T,&mdev->flags) ) {
		time=p.degr_wfc_timeout;
		if (time) WARN("using degr_wfc_timeout=%ld seconds\n", time);
	} else {
		time=p.wfc_timeout;
	}

	time=time*HZ;
	if(time==0) time=MAX_SCHEDULE_TIMEOUT;

	*tp=time;

	return 0;
}

STATIC int drbd_ioctl_set_syncer(struct Drbd_Conf *mdev,
				 struct ioctl_syncer_config* arg)
{
	struct syncer_config sc;
	drbd_dev *odev;

	int err;

	if(copy_from_user(&sc,&arg->config,sizeof(sc))) return -EFAULT;

	if( sc.after != -1) {
		if( sc.after < -1 || sc.after > minor_count ) return -ERANGE;
		odev = drbd_conf + sc.after; // check against loops in
		while(1) {
			if( odev == mdev ) return -EBADMSG; // cycle found.
			if( odev->sync_conf.after == -1 ) break; // no cycles.
			odev = drbd_conf + odev->sync_conf.after;
		}
	}

	sc.use_csums = 0; // TODO, NYI
	ERR_IF (sc.rate < 1) sc.rate = 1;
	ERR_IF (sc.skip & ~1) sc.skip = !!sc.skip;
	ERR_IF (sc.al_extents < 7) sc.al_extents = 127; // arbitrary minimum
#define AL_MAX ((MD_AL_MAX_SIZE-1) * AL_EXTENTS_PT)
	if(sc.al_extents > AL_MAX) {
		ERR("sc.al_extents > %d\n",AL_MAX);
		sc.al_extents = AL_MAX;
	}
#undef AL_MAX

	mdev->sync_conf.rate       = sc.rate;
	mdev->sync_conf.use_csums  = sc.use_csums;
	mdev->sync_conf.skip       = sc.skip;
	mdev->sync_conf.al_extents = sc.al_extents;

	err = drbd_check_al_size(mdev);
	drbd_md_sync(mdev);
	if (err) return err;

	if (mdev->state.conn >= Connected)
		drbd_send_sync_param(mdev,&sc);

	drbd_alter_sa(mdev, sc.after);

	return 0;
}

STATIC int drbd_detach_ioctl(drbd_dev *mdev)
{
	int r;

	r = drbd_request_state(mdev,NS(disk,Diskless));

	if( r == SS_NothingToDo ) { return 0; }
	if( r < SS_Success ) {
		return -ENETRESET;
	}

	return 0;
}

STATIC int drbd_outdate_ioctl(drbd_dev *mdev, int *reason)
{
	drbd_state_t os,ns;
	int err,r;

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	if( mdev->state.disk < Outdated ) {
		r=-999;
	} else {
		r = _drbd_set_state(mdev, _NS(disk,Outdated), ChgStateVerbose);
	}
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);
	after_state_ch(mdev,os,ns, ChgStateVerbose);

	if( r == SS_NothingToDo ) return 0;
	if( r == -999 ) {
		return -EINVAL;
	}

	drbd_md_sync(mdev);
	
	if( r < SS_Success ) {
		err = put_user(r, reason);
		if(!err) err=-EIO;
		return err;
	}

	return 0;
}

STATIC int drbd_ioctl_get_uuids(struct Drbd_Conf *mdev,
				struct ioctl_get_uuids* arg)
{
	struct ioctl_get_uuids cn;
	int i;

	if( mdev->state.disk <= Failed ) {
		return -EIO;
	}

	memset(&cn,0,sizeof(cn));

	for (i = Current; i < UUID_SIZE; i++) {
		cn.uuid[i]=mdev->bc->md.uuid[i];
	}
	cn.flags = mdev->bc->md.flags;
	cn.bits_set = drbd_bm_total_weight(mdev);
	cn.current_size = drbd_get_capacity(mdev->this_bdev);

	if (copy_to_user(arg,&cn,sizeof(cn)))
		return -EFAULT;

	return 0;
}

STATIC int drbd_ioctl_unconfig_net(struct Drbd_Conf *mdev)
{
	int r;

	r = _drbd_request_state(mdev,NS(conn,StandAlone),0);	// silently.

	if ( r == SS_NothingToDo )  return 0;
	if ( r == SS_PrimaryNOP ) {
		drbd_send_short_cmd(mdev, OutdateRequest);
		wait_event(mdev->cstate_wait,
			   mdev->state.pdsk <= Outdated ||
			   mdev->state.conn < TearDown );
		if( mdev->state.conn < TearDown ) return 0;

		r = drbd_request_state(mdev,NS(conn,StandAlone));
	}

	if( r < SS_Success ) return -ENODATA;

	if ( mdev->cram_hmac_tfm ) {
		crypto_free_tfm(mdev->cram_hmac_tfm);
		mdev->cram_hmac_tfm = NULL;
	}

	drbd_md_sync(mdev);

	return 0;
}

#ifdef CONFIG_COMPAT
long drbd_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	int ret;
	ret = drbd_ioctl(f->f_dentry->d_inode, f, cmd, arg);
	/* need to map "unknown" to ENOIOCTLCMD
	 * to get the generic fallback path going */
	if (ret == -ENOTTY) ret = -ENOIOCTLCMD;
	return ret;
}
#endif

int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	int r,minor,err=0,io_suspend=0;
	long time;
	struct Drbd_Conf *mdev;
	struct ioctl_wait* wp;
	struct block_device *bdev = inode->i_bdev;
	struct gendisk *disk = bdev->bd_disk;

	minor = MINOR(inode->i_rdev);
	if (minor >= minor_count) return -ENODEV;
	mdev = drbd_conf + minor;

	D_ASSERT(MAJOR(inode->i_rdev) == MAJOR_NR);

	/*
	 * check whether we can permit this ioctl, and whether is makes sense.
	 * we don't care for the BLK* ioctls, with 2.6 they never end up here.
	 *
	 * for non-sysadmins, we only allow GET_CONFIG (and GET_VERSION)
	 * all other things need CAP_SYS_ADMIN.
	 *
	 * on an Unconfigured device, only configure requests make sense.
	 * still we silently ignore requests to become secondary or to
	 * unconfigure. other requests are invalid.
	 *
	 * I chose to have an additional switch statement for it
	 * because I think this makes it more obvious.
	 *
	 * because we look at mdev->cstate, it should be inside the lock
	 * (once we serialize cstate changes, it has to be...)
	 *
	 */
	if (!capable(CAP_SYS_ADMIN)
	    && cmd != DRBD_IOCTL_GET_CONFIG
	    && cmd != DRBD_IOCTL_GET_VERSION) {
		err = -EPERM;
		goto out_unlocked;
	}

	if (unlikely(drbd_did_panic == DRBD_MAGIC))
		return -EBUSY;

	if( (err=down_interruptible(&mdev->device_mutex)) ) return err;
	/*
	 * please no 'return', use 'err = -ERRNO; goto out;'
	 * we hold the device_mutex
	 */

	D_ASSERT(bdev == mdev->this_bdev);
	D_ASSERT(disk == mdev->vdisk);

	smp_rmb();
	switch (cmd) {
	case DRBD_IOCTL_GET_VERSION:
		err = put_user(API_VERSION, (int *) arg);
		break;

	case DRBD_IOCTL_SET_STATE:
		if (copy_from_user(&r, (int *) arg, sizeof(int)))
			return -EFAULT;

		if (r & ~(Primary|Secondary|DontBlameDrbd) ) {
			err = -EINVAL;
		} else {
			err = drbd_set_role(mdev, &r);
			if ( err == -EIO ) {
				err = put_user(r, (int *) arg);
				if(err == 0) err=-EIO;
			}
		}
		break;

	case DRBD_IOCTL_SET_DISK_CONFIG:
		err = drbd_ioctl_set_disk(mdev,(struct ioctl_disk_config*)arg);
		break;

	case DRBD_IOCTL_SET_DISK_SIZE:
		if (mdev->state.conn > Connected) {
			err = -EBUSY;
			break;
		}
		if ( mdev->state.role == Secondary &&
		     mdev->state.peer == Secondary) {
			err = -EINPROGRESS;
			break;
		}
		err=0;
		mdev->bc->u_size = (sector_t)(u64)arg;
		drbd_bm_lock(mdev);
		drbd_determin_dev_size(mdev);
		drbd_md_sync(mdev);
		drbd_bm_unlock(mdev);
		if (mdev->state.conn == Connected) {
			drbd_send_uuids(mdev); // to start sync...
			drbd_send_sizes(mdev);
		}
		break;

	case DRBD_IOCTL_SET_NET_CONFIG:
		err = drbd_ioctl_set_net(mdev,(struct ioctl_net_config*) arg);
		break;

	case DRBD_IOCTL_SET_SYNC_CONFIG:
		err = drbd_ioctl_set_syncer(mdev,
					    (struct ioctl_syncer_config*) arg);
		break;

	case DRBD_IOCTL_GET_CONFIG:
		err = drbd_ioctl_get_conf(mdev,(struct ioctl_get_config*) arg);
		break;

	case DRBD_IOCTL_UNCONFIG_NET:
		err = drbd_ioctl_unconfig_net(mdev);
		break;

	case DRBD_IOCTL_UNCONFIG_DISK:
		if (mdev->state.disk == Diskless) break;
		err = drbd_detach_ioctl(mdev);
		break;

	case DRBD_IOCTL_WAIT_CONNECT:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		// We can drop the mutex, we do not touch anything in mdev.
		up(&mdev->device_mutex);

		time = wait_event_interruptible_timeout(
			mdev->cstate_wait,
			mdev->state.conn < Unconnected
			|| mdev->state.conn >= Connected,
			time );
		if (time < 0) {
			err = time;
			goto out_unlocked;
		}
		if (time == 0) {
			err = -ETIME;
			goto out_unlocked;
		}
		err=0; // no error

		if(put_user(mdev->state.conn>=Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_WAIT_SYNC:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		up(&mdev->device_mutex);

		do {
			time = wait_event_interruptible_timeout(
				mdev->cstate_wait,
				mdev->state.conn == Connected
				|| mdev->state.conn < Unconnected,
				time );

			if (time < 0 ) {
				err = time;
				goto out_unlocked;
			}

			if (mdev->state.conn > Connected) {
				time=MAX_SCHEDULE_TIMEOUT;
			}

			if (time == 0) {
				err = -ETIME;
				goto out_unlocked;
			}
		} while ( mdev->state.conn != Connected
			  && mdev->state.conn >= Unconnected );

		err=0; // no error

		if(put_user(mdev->state.conn==Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_INVALIDATE:
		r = drbd_request_state(mdev,NS2(conn,StartingSyncT,
						disk,Inconsistent));
		if ( r != SS_Success) err = -EINPROGRESS;
		break;

	case DRBD_IOCTL_INVALIDATE_REM:
		r = drbd_request_state(mdev,NS2(conn,StartingSyncS,
						pdsk,Inconsistent));
		if ( r != SS_Success) err = -EINPROGRESS;
		break;

	case DRBD_IOCTL_OUTDATE_DISK:
		err = drbd_outdate_ioctl(mdev,(int *) arg);
		break;

	case DRBD_IOCTL_GET_UUIDS:
		err=drbd_ioctl_get_uuids(mdev,(void *)arg);
		break;

	case DRBD_IOCTL_PAUSE_SYNC:
		if(!drbd_resync_pause(mdev, UserImposed)) err = -EINPROGRESS;
		break;

	case DRBD_IOCTL_RESUME_SYNC:
		if(!drbd_resync_resume(mdev, UserImposed)) err = -EINPROGRESS;
		break;
		
	case DRBD_IOCTL_SUSPEND_IO:
		io_suspend=1;
	case DRBD_IOCTL_RESUME_IO:
		r = drbd_request_state(mdev,NS(susp,io_suspend));
		if( r < SS_Success ) {
			err = put_user(r, (int *) arg);
			if(!err) err=-EIO;
			else err=-EINVAL;
		}
		break;

	default:
		err = -ENOTTY;
	}
 /* out: */
	up(&mdev->device_mutex);
 out_unlocked:
	return err;
}
