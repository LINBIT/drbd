/*
-*- linux-c -*-
   drbd_fs.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2004, Philipp Reisner <philipp.reisner@linbit.com>.
	main author.

   Copyright (C) 2002-2004, Lars Ellenberg <l.g.e@web.de>.
	main contributor.

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

STATIC int do_determin_dev_size(struct Drbd_Conf* mdev);
int drbd_determin_dev_size(struct Drbd_Conf* mdev)
{
	sector_t pmdss; // previous meta data start sector
	int rv;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));
	pmdss = drbd_md_ss(mdev);
	rv = do_determin_dev_size(mdev);
	if ( pmdss != drbd_md_ss(mdev) && mdev->md_index == -1 ) {
		WARN("Moving meta-data.\n");
		drbd_al_shrink(mdev); // All extents inactive.
		drbd_bm_write(mdev);  // write bitmap
		drbd_md_write(mdev);  // Write mdev->la_size to disk.
	}
	lc_unlock(mdev->act_log);

	return rv;
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


/* Returns 1 if there is a disk-less node, 0 if both nodes have a disk. */
/*
 * *_size is in sectors.
 *
 * FIXME
 * since this is done by drbd receiver as well as from drbdsetup,
 * this actually needs proper locking!
 * drbd_bm_resize already protects itself with a mutex.
 * but again, this is a state change, and thus should be serialized with other
 * state changes on a more general level already.
 */
STATIC int do_determin_dev_size(struct Drbd_Conf* mdev)
{
	sector_t p_size = mdev->p_size;   // partner's disk size.
	sector_t la_size = mdev->la_size; // last agreed size.
	sector_t m_size; // my size
	sector_t u_size = mdev->lo_usize; // size requested by user.
	sector_t size=0;
	int rv;
	char ppb[10];

	m_size = drbd_get_capacity(mdev->backing_bdev);

	if (mdev->md_index == -1 && m_size) {// internal metadata
		D_ASSERT(m_size > MD_RESERVED_SIZE);
		m_size = drbd_md_ss(mdev);
	}

	if(p_size && m_size) {
		rv=0;
		size=min_t(sector_t,p_size,m_size);
	} else {
		rv=1;
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

	if( drbd_get_capacity(mdev->this_bdev) != size ) {
		int err;
		err = drbd_bm_resize(mdev,size);
		if (unlikely(err)) {
			/* currently there is only one error: ENOMEM! */
			size = drbd_bm_capacity(mdev)>>1;
			if (size == 0) {
				ERR("Could not allocate bitmap! Set device size => 0\n");
			} else {
				/* FIXME this is problematic,
				 * if we in fact are smaller now! */
				ERR("BM resizing failed. "
				    "Leaving size unchanged at size = %lu KB\n", 
				    (unsigned long)size);
			}
		}
		// racy, see comments above.
		drbd_set_my_capacity(mdev,size);
		mdev->la_size = size;
		INFO("size = %s (%lu KB)\n",ppsize(ppb,size>>1),
		     (unsigned long)size>>1);
	}

	return rv;
}

/* checks that the al lru is of requested size, and if neccessary tries to
 * allocate a new one. returns -EBUSY if current al lru is still used,
 * -ENOMEM when allocation failed, and 0 on success.
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
	return 0;
}

void drbd_setup_queue_param(drbd_dev *mdev, unsigned int max_seg_s)
{
	request_queue_t * const q = mdev->rq_queue;
	request_queue_t * const b = mdev->backing_bdev->bd_disk->queue;

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
}

STATIC
int drbd_ioctl_set_disk(drbd_dev *mdev, struct ioctl_disk_config * arg)
{
	int i, md_gc_valid, minor;
	enum ret_codes retcode;
	struct disk_config new_conf;
	struct file *filp = 0;
	struct file *filp2 = 0;
	struct inode *inode, *inode2;
	struct block_device *bdev, *bdev2;
	drbd_disks_t nds;

	minor=(int)(mdev-drbd_conf);

	/* if you want to reconfigure, please tear down first */
	smp_rmb();
	if (mdev->state.s.disk > Diskless)
		return -EBUSY;

	/* if this was "adding" a lo dev to a previously "diskless" node,
	 * there still could be requests comming in right now. brrks.
	 * if it was mounted, we had an open_cnt > 1,
	 * so it would be BUSY anyways...
	 */
	ERR_IF (mdev->state.s.role != Secondary)
		return -EBUSY;

	if (mdev->open_cnt > 1)
		return -EBUSY;

	if (copy_from_user(&new_conf, &arg->config,sizeof(struct disk_config)))
		return -EFAULT;

	/* FIXME
	 * I'd like to do it here, so I can just fail this ioctl with ENOMEM.
	 * but drbd_md_read below might change the al_nr_extens again, so need
	 * to do it there again anyways...
	 * but then I already changed it all and cannot easily undo it..
	 * for now, do it there, but then if it fails, rather panic than later
	 * have a NULL pointer dereference.
	 *
	i = drbd_check_al_size(mdev);
	if (i) return i;
	 *
	 */


	/* FIXME allow reattach while connected,
	 * and allow it in Primary/Diskless state...
	 * currently there are strange races leading to a distributed
	 * deadlock in that case...
	 */
	if ( mdev->state.s.conn > StandAlone ) {
		return -EBUSY;
	}

	if ( new_conf.meta_index < -1) {
		retcode=LDMDInvalid;
		goto fail_ioctl;
	}

	filp = fget(new_conf.lower_device);
	if (!filp) {
		retcode=LDFDInvalid;
		goto fail_ioctl;
	}

	inode = filp->f_dentry->d_inode;

	if (!S_ISBLK(inode->i_mode)) {
		retcode=LDNoBlockDev;
		goto fail_ioctl;
	}

	filp2 = fget(new_conf.meta_device);

	if (!filp2) {
		retcode=MDFDInvalid;
		goto fail_ioctl;
	}

	inode2 = filp2->f_dentry->d_inode;

	if (!S_ISBLK(inode2->i_mode)) {
		retcode=MDNoBlockDev;
		goto fail_ioctl;
	}

	bdev = inode->i_bdev;
	if (bd_claim(bdev, mdev)) {
		retcode=LDMounted;
		goto fail_ioctl;
	}

	bdev2 = inode2->i_bdev;
	if (bd_claim(bdev2, new_conf.meta_index== - 1 ? 
		     (void *)mdev : (void*) drbd_m_holder )) {
		retcode=MDMounted;
		goto release_bdev_fail_ioctl;
	}

	if ( (bdev == bdev2) != (new_conf.meta_index == -1) ) {
		retcode=LDMDInvalid;
		goto release_bdev2_fail_ioctl;
	}

	if ((drbd_get_capacity(bdev)>>1) < new_conf.disk_size) {
		/* FIXME maybe still allow,
		 * but leave only DRBD_MAX_SECTORS usable */
		retcode = LDDeviceTooSmall;
		goto release_bdev2_fail_ioctl;
	}

	if (drbd_get_capacity(bdev) >= (sector_t)DRBD_MAX_SECTORS) {
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
	if( drbd_get_capacity(bdev2) < 2*MD_RESERVED_SIZE*i
				+ (new_conf.meta_index == -1) ? (1<<16) : 0 )
	{
		retcode = MDDeviceTooSmall;
		goto release_bdev2_fail_ioctl;
	}

	drbd_free_ll_dev(mdev);

	if(new_conf.split_brain_fix) __set_bit(SPLIT_BRAIN_FIX,&mdev->flags);
	else __clear_bit(SPLIT_BRAIN_FIX,&mdev->flags);

	mdev->md_bdev  = bdev2;
	mdev->md_file  = filp2;
	mdev->md_index = new_conf.meta_index;

	mdev->backing_bdev = bdev;
	mdev->lo_file  = filp;
	mdev->lo_usize = new_conf.disk_size;
	mdev->on_io_error = new_conf.on_io_error;

	mdev->send_cnt = 0;
	mdev->recv_cnt = 0;
	mdev->read_cnt = 0;
	mdev->writ_cnt = 0;

	drbd_setup_queue_param(mdev, DRBD_MAX_SEGMENT_SIZE);

	set_bit(MD_IO_ALLOWED,&mdev->flags);

	md_gc_valid = drbd_md_read(mdev);

	if (md_gc_valid != NoError) {
		retcode = md_gc_valid;
		goto unset_fail_ioctl;
	}

	/* We reach this only if we have a valid meta data block,
	 * so we no longer create one here, if we don't find one.
	 * That means that initially, you HAVE to use the drbdmeta
	 * command to create one in user space.
	 */

	drbd_bm_lock(mdev); // racy...
	drbd_determin_dev_size(mdev);
	/* FIXME
	 * what if we now have la_size == 0 ?? eh?
	 */

	if (drbd_md_test_flag(mdev,MDF_FullSync)) {
		INFO("Assuming that all blocks are out of sync (aka FullSync)\n");
		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);
		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);
	} else {
		/* FIXME this still does not propagate io errors! */
		drbd_bm_read(mdev);
	}

	i = drbd_check_al_size(mdev);
	if (i) {
// FATAL!
		/* FIXME see the comment above.
		 * if this fails I need to undo all changes,
		 * go back into Unconfigured,
		 * and fail the ioctl with ENOMEM...
		 */
		// return i;
		drbd_panic("Cannot allocate act_log\n");
		drbd_suicide();
	}

	if (md_gc_valid > 0) {
		drbd_al_read_log(mdev);
		if (drbd_md_test_flag(mdev,MDF_PrimaryInd)) {
			drbd_al_apply_to_bm(mdev);
			drbd_al_to_on_disk_bm(mdev);
		}
	} /* else {
	     FIXME wipe out on disk al!
	} */

	drbd_set_blocksize(mdev,INITIAL_BLOCK_SIZE);

	/* If MDF_Consistent is not set go into inconsistent state, otherwise
	   investige MDF_WasUpToDate...
	   If MDF_WasUpToDate is not set go into Outdated disk state, otherwise
	   into Consistent state.
	*/
	if(drbd_md_test_flag(mdev,MDF_Consistent)) {
		if(drbd_md_test_flag(mdev,MDF_WasUpToDate)) {
			nds = Consistent;
		} else {
			nds = Outdated;
		}
	} else {
		nds = Inconsistent;
	}

	if(drbd_request_state(mdev,NS(disk,nds)) > 0) {
		drbd_thread_start(&mdev->worker);
	}

// FIXME EXPLAIN:
	clear_bit(MD_IO_ALLOWED,&mdev->flags);

	drbd_bm_unlock(mdev);

	return 0;

 unset_fail_ioctl:
	mdev->md_bdev  = 0;
	mdev->md_file  = 0;
	mdev->md_index = 0;

	mdev->backing_bdev = 0;
	mdev->lo_file  = 0;
	mdev->lo_usize = 0;
	mdev->on_io_error = 0;
 release_bdev2_fail_ioctl:
	bd_release(bdev2);
 release_bdev_fail_ioctl:
	bd_release(bdev);
 fail_ioctl:
	if (filp) fput(filp);
	if (filp2) fput(filp2);
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

STATIC
int drbd_ioctl_get_conf(struct Drbd_Conf *mdev, struct ioctl_get_config* arg)
{
	struct ioctl_get_config cn;
	memset(&cn,0,sizeof(cn));

	if (mdev->backing_bdev) {
		cn.lower_device_major = MAJOR(mdev->backing_bdev->bd_dev);
		cn.lower_device_minor = MINOR(mdev->backing_bdev->bd_dev);
		bdevname(mdev->backing_bdev,cn.lower_device_name);
	}
	if (mdev->md_bdev) {
		cn.meta_device_major  = MAJOR(mdev->md_bdev->bd_dev);
		cn.meta_device_minor  = MINOR(mdev->md_bdev->bd_dev);
		bdevname(mdev->md_bdev,cn.meta_device_name);
	}
	cn.state=mdev->state;
	cn.meta_index=mdev->md_index;
	cn.on_io_error=mdev->on_io_error;
	memcpy(&cn.nconf, &mdev->conf, sizeof(struct net_config));
	memcpy(&cn.sconf, &mdev->sync_conf, sizeof(struct syncer_config));

	if (copy_to_user(arg,&cn,sizeof(struct ioctl_get_config)))
		return -EFAULT;

	return 0;
}


STATIC
int drbd_ioctl_set_net(struct Drbd_Conf *mdev, struct ioctl_net_config * arg)
{
	int i,minor;
	enum ret_codes retcode;
	struct net_config new_conf;
	struct crypto_tfm* tfm = NULL;
	struct hlist_head *new_tl_hash = NULL;
	struct hlist_head *new_ee_hash = NULL;

	minor=(int)(mdev-drbd_conf);

	// FIXME plausibility check
	if (copy_from_user(&new_conf, &arg->config,sizeof(struct net_config)))
		return -EFAULT;

#define M_ADDR(A) (((struct sockaddr_in *)&A.my_addr)->sin_addr.s_addr)
#define M_PORT(A) (((struct sockaddr_in *)&A.my_addr)->sin_port)
#define O_ADDR(A) (((struct sockaddr_in *)&A.other_addr)->sin_addr.s_addr)
#define O_PORT(A) (((struct sockaddr_in *)&A.other_addr)->sin_port)
	for(i=0;i<minor_count;i++) {
		if( i!=minor && drbd_conf[i].state.s.conn==Unconfigured &&
		    M_ADDR(new_conf) == M_ADDR(drbd_conf[i].conf) &&
		    M_PORT(new_conf) == M_PORT(drbd_conf[i].conf) ) {
			retcode=LAAlreadyInUse;
			goto fail_ioctl;
		}
		if( i!=minor && drbd_conf[i].state.s.conn!=Unconfigured &&
		    O_ADDR(new_conf) == O_ADDR(drbd_conf[i].conf) &&
		    O_PORT(new_conf) == O_PORT(drbd_conf[i].conf) ) {
			retcode=OAAlreadyInUse;
			goto fail_ioctl;
		}
	}
#undef M_ADDR
#undef M_PORT
#undef O_ADDR
#undef O_PORT

	if( new_conf.cram_hmac_alg[0] != 0) {
		tfm = crypto_alloc_tfm(new_conf.cram_hmac_alg, 0);
		if (tfm == NULL) {
			retcode=CRAMAlgNotAvail;
			goto fail_ioctl;
		}

		if (crypto_tfm_alg_type(tfm) != CRYPTO_ALG_TYPE_DIGEST) {
			retcode=CRAMAlgNotDigest;
			goto fail_ioctl;
		}
	}


	if (mdev->tl_hash_s != new_conf.max_epoch_size/8 ) {
		new_tl_hash=kmalloc((new_conf.max_epoch_size/8)*sizeof(void*),
				    GFP_KERNEL);
		if(!new_tl_hash) {
			retcode=KMallocFailed;
			goto fail_ioctl;
		}
	}

	if (new_conf.two_primaries &&
	    ( mdev->ee_hash_s != new_conf.max_buffers/8 ) ) {
		new_ee_hash=kmalloc((new_conf.max_buffers/8)*sizeof(void*),
				    GFP_KERNEL);
		if(!new_ee_hash) {
			retcode=KMallocFailed;
			goto fail_ioctl;
		}
	}

	/* IMPROVE:
	   We should warn the user if the LL_DEV is
	   used already. E.g. some FS mounted on it.
	*/

	drbd_sync_me(mdev);
	drbd_thread_stop(&mdev->receiver);
	drbd_free_sock(mdev);

	// TODO plausibility check ...
	memcpy(&mdev->conf,&new_conf,sizeof(struct net_config));

	((char*)mdev->conf.shared_secret)[SHARED_SECRET_MAX-1]=0;
#if 0
FIXME
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
	if (!mdev->conf.ping_int)
		mdev->conf.ping_int = MAX_SCHEDULE_TIMEOUT/HZ;
	if (!mdev->conf.timeout)
		mdev->conf.timeout = MAX_SCHEDULE_TIMEOUT/HZ*10;
	if (mdev->conf.ping_int*10 < mdev->conf.timeout)
		mdev->conf.timeout = mdev->conf.ping_int*10/6;
	if (mdev->conf.ping_int*10 == mdev->conf.timeout)
		mdev->conf.ping_int = mdev->conf.ping_int+1;
#endif

	mdev->send_cnt = 0;
	mdev->recv_cnt = 0;

	if(new_tl_hash) {
		if (mdev->tl_hash) kfree(mdev->tl_hash);
		mdev->tl_hash_s = mdev->conf.max_epoch_size/8;
		mdev->tl_hash = new_tl_hash;
		memset(mdev->tl_hash, 0, mdev->tl_hash_s * sizeof(void*));
	}

	if(new_ee_hash) {
		if (mdev->ee_hash) kfree(mdev->ee_hash);
		mdev->ee_hash_s = mdev->conf.max_buffers/8;
		mdev->ee_hash = new_ee_hash;
		memset(mdev->ee_hash, 0, mdev->ee_hash_s * sizeof(void*));
	}

	if ( mdev->cram_hmac_tfm ) {
		crypto_free_tfm(mdev->cram_hmac_tfm);
	}

	mdev->cram_hmac_tfm = tfm;

	drbd_thread_start(&mdev->worker);
	if( drbd_request_state(mdev,NS(conn,Unconnected)) > 0) {
		drbd_thread_start(&mdev->receiver);
	}

	return 0;

  fail_ioctl:
	if (tfm) crypto_free_tfm(tfm);
	if (new_tl_hash) kfree(new_tl_hash);
	if (new_ee_hash) kfree(new_ee_hash);
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

	D_ASSERT(mdev->state.s.pdsk == DUnknown);

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
		nps = DUnknown;
		drbd_request_state(mdev,NS(disk,Outdated));
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

int drbd_set_role(drbd_dev *mdev,drbd_role_t newstate)
{
	int r,forced = 0;
	drbd_state_t os,ns;

	D_ASSERT(semaphore_is_locked(&mdev->device_mutex));

	if ( (newstate & role_mask) == mdev->state.s.role ) return 0; /* nothing to do */

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
	}

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	r = _drbd_set_state(mdev, _NS(role,newstate & role_mask), 0);
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);
	after_state_ch(mdev,os,ns);

	if ( r == 2 ) { return 0; }
	if ( r == -2 ) {
		/* request state does not like the new state. */
		if (! (newstate & DontBlameDrbd)) {
			print_st_err(mdev,os,ns,r);
			return -EIO;
		}

		/* --do-what-I-say*/
		if (mdev->state.s.disk < UpToDate) {
			WARN("Forcefully set to UpToDate!\n");
			r = drbd_request_state(mdev,NS2(role,newstate & role_mask,
							disk,UpToDate));
			if(r<=0) return -EIO;

			forced = 1;
		}
	}
	if ( r == -7 ) {
		drbd_disks_t nps = drbd_try_outdate_peer(mdev);
		r = drbd_request_state(mdev,NS2(role,newstate & role_mask,pdsk,nps));
	} else if ( r <= 0 ) print_st_err(mdev,os,ns,r);

	if ( r <= 0 ) return -EACCES; 

	drbd_sync_me(mdev);

	/* Wait until nothing is on the fly :) */
	if ( wait_event_interruptible( mdev->cstate_wait,
			atomic_read(&mdev->ap_pending_cnt) == 0 ) ) {
		if ( newstate & Secondary ) {
			D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
			bd_release(mdev->this_bdev);
		}
		return -EINTR;
	}

	/* FIXME RACE here: if our direct user is not using bd_claim (i.e. 
	 *  not a filesystem) since cstate might still be >= Connected, new 
	 * ap requests may come in and increase ap_pending_cnt again!
	 * but that means someone is misusing DRBD...
	 * */

	set_bit(MD_DIRTY,&mdev->flags); // we are changing state!

	if (newstate & Secondary) {
		set_disk_ro(mdev->vdisk, TRUE );
	} else {
		set_disk_ro(mdev->vdisk, FALSE );
		D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
		bd_release(mdev->this_bdev);
		mdev->this_bdev->bd_disk = mdev->vdisk;

		if ( (mdev->state.s.conn < WFReportParams &&
		      mdev->uuid[Bitmap] == 0) || forced ) {
			drbd_uuid_new_current(mdev);
		}
	}

	if(mdev->state.s.disk > Diskless && (newstate & Secondary)) {
		drbd_al_to_on_disk_bm(mdev);
	}
	/* Primary indicator has changed in any case. */
	drbd_md_write(mdev);

	if (mdev->state.s.conn >= WFReportParams) {
		/* if this was forced, we should consider sync */
		if(forced) drbd_send_uuids(mdev);
		drbd_send_state(mdev);
	}

	return 0;
}

static int drbd_get_wait_time(long *tp, struct Drbd_Conf *mdev,
			      struct ioctl_wait *arg)
{
	long time;
	struct ioctl_wait p;

	if(copy_from_user(&p,arg,sizeof(p))) {
		return -EFAULT;
	}

	if( drbd_md_test_flag(mdev,MDF_ConnectedInd) ) {
		time=p.wfc_timeout;
		//ERR("using wfc_timeout.\n");
	} else {
		time=p.degr_wfc_timeout;
		//ERR("using degr_wfc_timeout.\n");
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
	int err;

	if(copy_from_user(&sc,&arg->config,sizeof(sc))) return -EFAULT;

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
	if (err) return err;

	if (mdev->state.s.conn >= Connected)
		drbd_send_sync_param(mdev,&sc);

	drbd_alter_sg(mdev, sc.group);

	return 0;
}

/* new */
STATIC int drbd_detach_ioctl(drbd_dev *mdev)
{
	int interrupted,r;
	drbd_state_t os,ns;

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	r = _drbd_set_state(mdev,_NS(disk,Diskless),ChgStateVerbose);
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);

	if( r == 2 ) { return 0; }
	if( r <= 0 ) { 
		return -ENETRESET; 
	}

	drbd_sync_me(mdev);

	interrupted = wait_event_interruptible(mdev->cstate_wait,
				      atomic_read(&mdev->local_cnt)==0);
	if ( interrupted ) {
		drbd_force_state(mdev,NS(disk,os.s.disk));
		return -EINTR;
	}

	drbd_free_ll_dev(mdev);
	after_state_ch(mdev, os, ns);

/* FIXME
* if you detach while connected, you are *at least* inconsistent now,
* and should clear MDF_Consistent in metadata, and maybe even set the bitmap
* out of sync.
* since if you reattach, this might be a different lo dev, and then it needs
* to receive a sync!
*/
	return 0;
}

STATIC int drbd_outdate_ioctl(drbd_dev *mdev, int *reason)
{
	drbd_state_t os,ns;
	int err,r;

	spin_lock_irq(&mdev->req_lock);
	os = mdev->state;
	if( mdev->state.s.disk < Outdated ) { 
		r=-999;
	} else {
		r = _drbd_set_state(mdev, _NS(disk,Outdated), ChgStateVerbose);
	}
	ns = mdev->state;
	spin_unlock_irq(&mdev->req_lock);
	
	if( r == 2 ) return 0;
	if( r == -999 ) {
		return -EINVAL;
	}
	after_state_ch(mdev,os,ns); // TODO decide if neccesarry.
	
	if( r <= 0 ) {
		err = put_user(r, reason);
		if(!err) err=-EIO;
		return err;
	}
	
	drbd_md_write(mdev);

	return 0;
}

STATIC int drbd_ioctl_get_uuids(struct Drbd_Conf *mdev, 
				struct ioctl_get_uuids* arg)
{
	struct ioctl_get_uuids cn;
	int i;

	if( mdev->state.s.disk <= Failed ) {
		return -EIO;
	}

	memset(&cn,0,sizeof(cn));

	for (i = Current; i < UUID_SIZE; i++) {
		cn.uuid[i]=mdev->uuid[i];
	}
	cn.flags = mdev->md_flags;
	cn.bits_set = drbd_bm_total_weight(mdev);
	cn.current_size = drbd_get_capacity(mdev->this_bdev);

	if (copy_to_user(arg,&cn,sizeof(cn)))
		return -EFAULT;

	return 0;
}


int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	int r,minor,err=0;
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
		if (arg & ~(Primary|Secondary|DontBlameDrbd) ) {
			err = -EINVAL;
		} else {
			err = drbd_set_role(mdev,arg);
		}
		break;

	case DRBD_IOCTL_SET_DISK_CONFIG:
		err = drbd_ioctl_set_disk(mdev,(struct ioctl_disk_config*)arg);
		break;

	case DRBD_IOCTL_SET_DISK_SIZE:
		if (mdev->state.s.conn > Connected) {
			err = -EBUSY;
			break;
		}
		if ( mdev->state.s.role == Secondary && 
		     mdev->state.s.peer == Secondary) {
			err = -EINPROGRESS;
			break;
		}
		err=0;
		mdev->lo_usize = (sector_t)(u64)arg;
		drbd_bm_lock(mdev);
		drbd_determin_dev_size(mdev);
		drbd_md_write(mdev); // Write mdev->la_size to disk.
		drbd_bm_unlock(mdev);
		if (mdev->state.s.conn == Connected) {
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
		if ( mdev->state.s.conn == Unconfigured) break;

		r = drbd_request_state(mdev,NS(conn,StandAlone));
		if( r == 2 ) { break; }
		if( r <= 0 ) {
			err=-ENODATA;
			break;
		} 
		/* r == 1 which means that we changed the state... */

		if ( mdev->cram_hmac_tfm ) {
			crypto_free_tfm(mdev->cram_hmac_tfm);
			mdev->cram_hmac_tfm = NULL;
		}

		drbd_sync_me(mdev); /* FIXME what if fsync returns error */

		drbd_thread_stop(&mdev->receiver);

		if ( mdev->state.s.conn == StandAlone && 
		     mdev->state.s.disk == Diskless ) {
			drbd_mdev_cleanup(mdev);  // Move to after_state_ch() ?
			module_put(THIS_MODULE);
		}

		break;

	case DRBD_IOCTL_UNCONFIG_DISK:
		if (mdev->state.s.disk == Diskless) break;
		err = drbd_detach_ioctl(mdev);
		break;

	case DRBD_IOCTL_WAIT_CONNECT:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		// We can drop the mutex, we do not touch anything in mdev.
		up(&mdev->device_mutex);

		time = wait_event_interruptible_timeout(
			mdev->cstate_wait,
			mdev->state.s.conn < Unconnected
			|| mdev->state.s.conn >= Connected,
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

		if(put_user(mdev->state.s.conn>=Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_WAIT_SYNC:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		up(&mdev->device_mutex);

		do {
			time = wait_event_interruptible_timeout(
				mdev->cstate_wait,
				mdev->state.s.conn == Connected
				|| mdev->state.s.conn < Unconnected,
				time );

			if (time < 0 ) {
				err = time;
				goto out_unlocked;
			}

			if (mdev->state.s.conn > Connected) {
				time=MAX_SCHEDULE_TIMEOUT;
			}

			if (time == 0) {
				err = -ETIME;
				goto out_unlocked;
			}
		} while ( mdev->state.s.conn != Connected
			  && mdev->state.s.conn >= Unconnected );

		err=0; // no error

		if(put_user(mdev->state.s.conn==Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_INVALIDATE:
		/* TODO
		 * differentiate between different error cases,
		 * or report the current connection state and flags back
		 * to userspace */

		/* disallow "invalidation" of local replica
		 * when currently in primary state (would be a Bad Idea),
		 * or during a running sync (won't make any sense) */

		/* PRE TODO disallow invalidate if we are primary */
		r = drbd_request_state(mdev,NS2(disk,Inconsistent,
					        conn,WFBitMapT));

		if( r == 2 ) { break; }
		if( r <= 0 ) {
			err = -EINPROGRESS;
			break;
		} 

		/* avoid races with set_in_sync
		 * for successfull mirrored writes
		 */
		wait_event(mdev->cstate_wait,
			   atomic_read(&mdev->ap_bio_cnt)==0);

		drbd_bm_lock(mdev); // racy...

		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		if (drbd_send_short_cmd(mdev,BecomeSyncSource)) {
			drbd_start_resync(mdev,SyncTarget);
		}

		drbd_bm_unlock(mdev);

		break;

	case DRBD_IOCTL_INVALIDATE_REM:

		/* PRE TODO disallow invalidate if we peer is primary */
		/* remove EINVAL from error output... */
		r = drbd_request_state(mdev,NS2(pdsk,Inconsistent,
					        conn,WFBitMapS));

		if( r == 2 ) { break; }
		if( r <= 0 ) {
			err = -EINPROGRESS;
			break;
		} 

		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		/* avoid races with set_in_sync
		 * for successfull mirrored writes
		 */
		wait_event(mdev->cstate_wait,
		     atomic_read(&mdev->ap_bio_cnt)==0);

		drbd_bm_lock(mdev); // racy...

		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		drbd_send_short_cmd(mdev,BecomeSyncTarget);
		drbd_start_resync(mdev,SyncSource);

		drbd_bm_unlock(mdev);

		break;

	case DRBD_IOCTL_OUTDATE_DISK:
		err = drbd_outdate_ioctl(mdev,(int *) arg);
		break;

	case DRBD_IOCTL_GET_UUIDS:
		err=drbd_ioctl_get_uuids(mdev,(void *)arg);
		break;

	default:
		err = -EINVAL;
	}
 /* out: */
	up(&mdev->device_mutex);
 out_unlocked:
	return err;
}

