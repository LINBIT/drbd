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

ONLY_IN_26(
/* see get_sb_bdev and bd_claim */
char *drbd_sec_holder = "Secondary DRBD cannot be bd_claimed ;)";
char *drbd_m_holder = "Hands off! this is DRBD's meta data device.";
)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
STATIC enum { NotMounted=0,MountedRO,MountedRW } drbd_is_mounted(int minor)
{
       struct super_block *sb;

       sb = get_super(MKDEV(MAJOR_NR, minor));
       if(!sb) return NotMounted;

       if(sb->s_flags & MS_RDONLY) {
	       drop_super(sb);
	       return MountedRO;
       }

       drop_super(sb);
       return MountedRW;
}
#endif

char* ppsize(char* buf, size_t size) 
{
	// Needs 9 bytes at max.
	static char units[] = { 'K','M','G','T' };
	int base = 0;
	while (size >= 10000 ) {
		size = size >> 10;
		base++;
	}
	sprintf(buf,"%ld %cB",(long)size,units[base]);

	return buf;
}

/* Returns -ENOMEM if we could not allocate the bitmap
 *
 * currently *_size is in KB.
 *
 * FIXME
 * since this is done by drbd receiver as well as from drbdsetup,
 * this actually needs proper locking!
 * drbd_bm_resize already protects itself with a mutex.
 * but again, this is a state change, and thus should be serialized with other
 * state changes on a more general level already.
 */
int drbd_determin_dev_size(struct Drbd_Conf* mdev)
{
	sector_t pmdss; // previous meta data start sector
	sector_t la_size;
	sector_t size;
	char ppb[10];

	int md_moved, la_size_changed;
	int rv=0;

	wait_event(mdev->al_wait, lc_try_lock(mdev->act_log));
	pmdss = drbd_md_ss(mdev);
	la_size = mdev->la_size;

	size = drbd_new_dev_size(mdev);

	if( (drbd_get_capacity(mdev->this_bdev)>>1) != size ) {
		int err;
		err = drbd_bm_resize(mdev,size<<1); // wants sectors
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
		drbd_set_my_capacity(mdev,size<<1);
		mdev->la_size = size;
		INFO("size = %s (%lu KB)\n",ppsize(ppb,size),
		     (unsigned long)size);
	}
	if (rv < 0) goto out;

	la_size_changed = (la_size != mdev->la_size);
	md_moved = pmdss != drbd_md_ss(mdev) /* && mdev->md_index == -1 */;

	if ( md_moved ) {
		WARN("Moving meta-data.\n");
		D_ASSERT(mdev->md_index == -1);
	}

	if ( la_size_changed || md_moved ) {
		if( inc_local_md_only(mdev)) {
			drbd_al_shrink(mdev); // All extents inactive.
			drbd_bm_write(mdev);  // write bitmap
			// Write mdev->la_size to on disk.
			drbd_md_write(mdev);
			dec_local(mdev);
		}
	}
  out:
	lc_unlock(mdev->act_log);

	return rv;
}

/*
 * currently *_size is in KB.
 */
sector_t drbd_new_dev_size(struct Drbd_Conf* mdev)
{
	sector_t p_size = mdev->p_size;  // partner's disk size.
	sector_t la_size = mdev->la_size; // last agreed size.
	sector_t m_size; // my size
	sector_t u_size = mdev->lo_usize; // size requested by user.
	sector_t size=0;

	m_size = drbd_get_capacity(mdev->backing_bdev)>>1;

	if (mdev->md_index == -1 && m_size) {// internal metadata
		D_ASSERT(m_size > MD_RESERVED_SIZE);
		m_size = drbd_md_ss(mdev)>>1;
	}

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
			    (unsigned long)u_size, (unsigned long)size);
		} else {
			size = u_size;
		}
	}

	return size;
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
	n = lc_alloc(mdev->sync_conf.al_extents,
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
	drbd_md_write(mdev);
	return 0;
}

STATIC int drbd_detach_ioctl(drbd_dev *mdev);

STATIC
int drbd_ioctl_set_disk(struct Drbd_Conf *mdev,
			struct ioctl_disk_config * arg)
{
	NOT_IN_26(int err;) // unused in 26 ?? cannot believe it ...
	int i, md_gc_valid, minor, mput=0, apply_al;
	enum ret_codes retcode;
	struct disk_config new_conf;
	struct file *filp = 0;
	struct file *filp2 = 0;
	struct inode *inode, *inode2;
	NOT_IN_26(kdev_t bdev, bdev2;)
	ONLY_IN_26(struct block_device *bdev, *bdev2;)

	minor=(int)(mdev-drbd_conf);

	/* if you want to reconfigure, please tear down first */
	smp_rmb();
	if (!test_bit(DISKLESS,&mdev->flags))
		return -EBUSY;

	/* if this was "adding" a lo dev to a previously "diskless" node,
	 * there still could be requests comming in right now. brrks.
	 * if it was mounted, we had an open_cnt > 1,
	 * so it would be BUSY anyways...
	 */
	ERR_IF (mdev->state != Secondary)
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

	if (mdev->cstate == Unconfigured) {
		// ioctl already has a refcnt
		__module_get(THIS_MODULE);
		mput = 1;
	} else {
		/* We currently cannot handle reattach while connected */
		return -EBUSY;

		/* FIXME allow reattach while connected,
		 * and allow it in Primary/Diskless state...
		 * currently there are strange races leading to a distributed
		 * deadlock in that case...
		 */
		if ( mdev->cstate != StandAlone /* &&
		    mdev->cstate != Connected */) {
			return -EBUSY;
		}
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

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0)
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
#else
	for(i=0;i<minor_count;i++) {
		if( i != minor &&
		    inode->i_rdev == drbd_conf[i].backing_bdev) {
			retcode=LDAlreadyInUse;
			goto fail_ioctl;
		}
	}

	if (drbd_is_mounted(inode->i_rdev)) {
		WARN("can not configure %d:%d, has active inodes!\n",
		     MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
		retcode=LDMounted;
		goto fail_ioctl;
	}

	if ((err = blkdev_open(inode, filp))) {
		ERR("blkdev_open( %d:%d ,) returned %d\n",
		    MAJOR(inode->i_rdev), MINOR(inode->i_rdev), err);
		retcode=LDOpenFailed;
		goto fail_ioctl;
	}
	bdev = inode->i_rdev;

	if ((err = blkdev_open(inode2, filp2))) {
		ERR("blkdev_open( %d:%d ,) returned %d\n",
		    MAJOR(inode->i_rdev), MINOR(inode->i_rdev), err);
		retcode=MDOpenFailed;
		goto release_bdev_fail_ioctl;
	}
	bdev2 = inode2->i_rdev;
#endif

	if ( (bdev == bdev2) != (new_conf.meta_index == -1) ) {
		retcode=LDMDInvalid;
		goto release_bdev2_fail_ioctl;
	}

	if ((drbd_get_capacity(bdev)>>1) < new_conf.disk_size) {
		retcode = LDDeviceTooSmall;
		goto release_bdev2_fail_ioctl;
	}

	if (drbd_get_capacity(bdev) > DRBD_MAX_SECTORS) {
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

// FIXME unclutter the code again ;)
/*
 * Returns the minimum that is _not_ zero, unless both are zero.
 */
#define min_not_zero(l, r) (l == 0) ? r : ((r == 0) ? l : min(l, r))
ONLY_IN_26({
	request_queue_t * const q = mdev->rq_queue;
	request_queue_t * const b = bdev->bd_disk->queue;

	q->max_sectors = min_not_zero((typeof(q->max_sectors))(PAGE_SIZE >> 9), b->max_sectors);
	q->max_phys_segments = 1;
	q->max_hw_segments   = 1;
	q->max_segment_size  = min((unsigned)PAGE_SIZE,b->max_segment_size);
	q->hardsect_size     = max((unsigned short)512,b->hardsect_size);
	q->seg_boundary_mask = PAGE_SIZE-1;
	D_ASSERT(q->hardsect_size <= PAGE_SIZE); // or we are really screwed ;-)

	if( q->backing_dev_info.ra_pages != b->backing_dev_info.ra_pages) {
		INFO("Adjusting my ra_pages to backing device's (%lu -> %lu)\n",
		     q->backing_dev_info.ra_pages,
		     b->backing_dev_info.ra_pages);
		q->backing_dev_info.ra_pages = b->backing_dev_info.ra_pages;
	}

})
#undef min_not_zero

	clear_bit(SENT_DISK_FAILURE,&mdev->flags);
	set_bit(MD_IO_ALLOWED,&mdev->flags);

/* FIXME I think inc_local_md_only within drbd_md_read is misplaced.
 * should go here, and the corresponding dec_local, too.
 */

	md_gc_valid = drbd_md_read(mdev);

/* FIXME if (md_gc_valid < 0) META DATA IO NOT POSSIBLE! */

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
	if ( mdev->state != Primary &&
	     drbd_md_test_flag(mdev,MDF_PrimaryInd) &&
	    !drbd_md_test_flag(mdev,MDF_ConnectedInd) ) {
		set_bit(USE_DEGR_WFC_T,&mdev->flags);
	}

	drbd_bm_lock(mdev); // racy...

	if(drbd_md_test_flag(mdev,MDF_Consistent) &&
	   drbd_new_dev_size(mdev) < mdev->la_size ) {
		D_ASSERT(mdev->cstate == Unconfigured);
		D_ASSERT(mput == 1);
		/* Do not attach a too small disk.*/
		drbd_bm_unlock(mdev);
		ERR("Lower device smaller than last agreed size!\n");
		drbd_free_ll_dev(mdev);
		set_cstate(mdev,Unconfigured);
		retcode = LDDeviceTooSmall;
		module_put(THIS_MODULE);
		if (put_user(retcode, &arg->ret_code)) return -EFAULT;
		return -EINVAL;
	}

	apply_al = drbd_md_test_flag(mdev,MDF_PrimaryInd);
	/* All tests on MDF_PrimaryInd and MDF_ConnectedInd must happen before 
	   this point, because determin_dev_size() might call drbd_md_write(), 
	   which in turn modifies these flags. Exceptions are where, we want
	   to test the current state (drbd_md_compare(), drbd_send_param()). */

	if (drbd_determin_dev_size(mdev) < 0) {
		/* could not allocate bitmap.
		 * try to undo ... */
		D_ASSERT(mdev->cstate == Unconfigured);
		D_ASSERT(mput == 1);

		drbd_bm_unlock(mdev);

		/* from drbd_detach_ioctl */
		drbd_free_ll_dev(mdev);

		set_cstate(mdev,Unconfigured);
		drbd_mdev_cleanup(mdev);
		module_put(THIS_MODULE);
		return -ENOMEM;
	}

	if (md_gc_valid <= 0) {
		INFO("Assuming that all blocks are out of sync (aka FullSync)\n");
		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);
		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);
	} else { // md_gc_valid > 0
		/* FIXME this still does not propagate io errors! */
		drbd_bm_read(mdev);
	}

	i = drbd_check_al_size(mdev);
	if (i) {
		/* FIXME see the comment above.
		 * if this fails I need to undo all changes,
		 * go back into Unconfigured,
		 * and fail the ioctl with ENOMEM...
		 */
		// return i;
		drbd_panic("Cannot allocate act_log\n");
	}

	if (md_gc_valid > 0) {
		i = drbd_al_read_log(mdev);
		if (apply_al && i) {
			drbd_al_apply_to_bm(mdev);
			drbd_al_to_on_disk_bm(mdev);
		}
		if(!i) {
			ERR("IO error on meta device while reading AL\n");
			drbd_free_ll_dev(mdev);
			set_cstate(mdev,Unconfigured);
			retcode = MDIOError;
			module_put(THIS_MODULE);
			if (put_user(retcode, &arg->ret_code)) return -EFAULT;
			return -EINVAL;
		}
	} /* else {
	     FIXME wipe out on disk al!
	} */

	drbd_set_blocksize(mdev,INITIAL_BLOCK_SIZE);

	if(mdev->cstate == Unconfigured ) {
		drbd_thread_start(&mdev->worker);
		set_cstate(mdev,StandAlone);
	}


	clear_bit(DISKLESS,&mdev->flags);
	smp_wmb();
// FIXME EXPLAIN:
	clear_bit(MD_IO_ALLOWED,&mdev->flags);

	/* FIXME currently only StandAlone here...
	 * Connected is not possible, since
	 * above we return -EBUSY in that case  */
	D_ASSERT(mdev->cstate <= Connected);
	if(mdev->cstate == Connected ) {
		drbd_send_param(mdev,1);
	}
	drbd_bm_unlock(mdev);

	return 0;

 release_bdev2_fail_ioctl:
	NOT_IN_26(blkdev_put(filp2->f_dentry->d_inode->i_bdev,BDEV_FILE);)
	ONLY_IN_26(bd_release(bdev2);)
 release_bdev_fail_ioctl:
	NOT_IN_26(blkdev_put(filp->f_dentry->d_inode->i_bdev,BDEV_FILE);)
	ONLY_IN_26(bd_release(bdev);)
 fail_ioctl:
	if (mput) module_put(THIS_MODULE);
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
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
#else
	cn.lower_device_major=MAJOR(mdev->backing_bdev);
	cn.lower_device_minor=MINOR(mdev->backing_bdev);
	cn.meta_device_major=MAJOR(mdev->md_bdev);
	cn.meta_device_minor=MINOR(mdev->md_bdev);
	if (mdev->backing_bdev) {
		strncpy(cn.lower_device_name,
				bdevname(mdev->backing_bdev), BDEVNAME_SIZE);
	}
	if (mdev->md_bdev) {
		strncpy(cn.meta_device_name,
				bdevname(mdev->md_bdev), BDEVNAME_SIZE);
	}
#endif
	cn.cstate=mdev->cstate;
	cn.state=mdev->state;
	cn.peer_state=mdev->o_state;
	cn.disk_size_user=mdev->lo_usize;
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
	int i,minor, mput=0;
	enum ret_codes retcode;
	struct net_config new_conf;

	minor=(int)(mdev-drbd_conf);

	// FIXME plausibility check
	if (copy_from_user(&new_conf, &arg->config,sizeof(struct net_config)))
		return -EFAULT;

	if (mdev->cstate == Unconfigured) {
		// ioctl already has a refcnt
		__module_get(THIS_MODULE);
		mput = 1;
	}

#define M_ADDR(A) (((struct sockaddr_in *)&A.my_addr)->sin_addr.s_addr)
#define M_PORT(A) (((struct sockaddr_in *)&A.my_addr)->sin_port)
#define O_ADDR(A) (((struct sockaddr_in *)&A.other_addr)->sin_addr.s_addr)
#define O_PORT(A) (((struct sockaddr_in *)&A.other_addr)->sin_port)
	for(i=0;i<minor_count;i++) {
		if( i!=minor && drbd_conf[i].cstate!=Unconfigured &&
		    M_ADDR(new_conf) == M_ADDR(drbd_conf[i].conf) &&
		    M_PORT(new_conf) == M_PORT(drbd_conf[i].conf) ) {
			retcode=LAAlreadyInUse;
			goto fail_ioctl;
		}
		if( i!=minor && drbd_conf[i].cstate!=Unconfigured &&
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

	/* IMPROVE:
	   We should warn the user if the LL_DEV is
	   used already. E.g. some FS mounted on it.
	*/

	drbd_sync_me(mdev);
	drbd_thread_stop(&mdev->receiver);
	drbd_free_sock(mdev);

	// TODO plausibility check ...
	memcpy(&mdev->conf,&new_conf,sizeof(struct net_config));

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

	drbd_thread_start(&mdev->worker);
	set_cstate(mdev,Unconnected);
	drbd_thread_start(&mdev->receiver);

	return 0;

  fail_ioctl:
	if (mput) module_put(THIS_MODULE);
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

int drbd_set_state(drbd_dev *mdev,Drbd_State newstate)
{
	int forced = 0;
	int dont_have_good_data;
	NOT_IN_26(int minor = mdev-drbd_conf;)

	D_ASSERT(semaphore_is_locked(&mdev->device_mutex));

	if ( (newstate & 0x3) == mdev->state ) return 0; /* nothing to do */

	// exactly one of sec or pri. not both.
	if ( !((newstate ^ (newstate >> 1)) & 1) ) return -EINVAL;

	if(mdev->cstate == Unconfigured)
		return -ENXIO;

	if ( (newstate & Primary) && (mdev->o_state == Primary) )
		return -EACCES;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	smp_rmb();
	if ( (newstate & Secondary) &&
	   (test_bit(WRITER_PRESENT,&mdev->flags) ||
	    drbd_is_mounted(minor) == MountedRW))
		return -EBUSY;
#else
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
#endif


	/* I dont have access to good data anywhere, if:
	 *  ( I am diskless OR inconsistent )
	 *  AND
	 *  ( not connected, or partner has no consistent data either )
	 */
	dont_have_good_data =
		(    test_bit(DISKLESS, &mdev->flags)
		  || !drbd_md_test_flag(mdev,MDF_Consistent) )
		&&
		( mdev->cstate < Connected
		  || test_bit(PARTNER_DISKLESS, &mdev->flags)
		  || !test_bit(PARTNER_CONSISTENT, &mdev->flags) );

	if (newstate & Primary) {
		if ( test_bit(DISKLESS,&mdev->flags)
		    && mdev->cstate < Connected ) {
			/* not even brute force can find data without disk.
			 * FIXME choose a usefull Error,
			 * and update drbsetup accordingly */
			return -EIO;
		} else if (dont_have_good_data) {
			/* ok, either we have a disk (which may be inconsistent)
			 * or we have a connection */
			if (newstate & DontBlameDrbd) {
				forced = 1;
				/* make sure the Human count is increased if
				 * we got here only because it was forced.
				 * maybe we want to force a FullSync? */
				newstate |= Human;
			} else {
				return -EIO;
			}
		} else if (mdev->cstate >= Connected) {
			/* do NOT increase the Human count if we are connected,
			 * and there is no reason for it.  See
			 * drbd_lk9.pdf middle of Page 7
			 */
			newstate &= ~(Human|DontBlameDrbd);
		}
	}

	drbd_sync_me(mdev);

	/* Wait until nothing is on the fly :) */
	if ( wait_event_interruptible( mdev->cstate_wait,
			atomic_read(&mdev->ap_pending_cnt) == 0 ) ) {
ONLY_IN_26(
		if ( newstate & Secondary ) {
			D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
			bd_release(mdev->this_bdev);
		}
)
		return -EINTR;
	}

	/* FIXME RACE here: if our direct user is not using bd_claim (i.e. 
	 *  not a filesystem) since cstate might still be >= Connected, new 
	 * ap requests may come in and increase ap_pending_cnt again!
	 * but that means someone is misusing DRBD...
	 * */

	if (forced) { /* this was --do-what-I-say ... */
		int i;
		// drbd_dump_md(mdev,0,0);
		for (i=HumanCnt; i < GEN_CNT_SIZE ; i++) {
			if (mdev->gen_cnt[i] != 1) {
				WARN("Forcefully set consistent! "
				     "If this screws your data, don't blame DRBD!\n");
				break;
			}
		}
		drbd_md_set_flag(mdev,MDF_Consistent);
	}
	set_bit(MD_DIRTY,&mdev->flags); // we are changing state!
	INFO( "%s/%s --> %s/%s\n",
	      nodestate_to_name(mdev->state),
	      nodestate_to_name(mdev->o_state),
	      nodestate_to_name(newstate & 0x03),
	      nodestate_to_name(mdev->o_state)   );
	mdev->state = (Drbd_State) newstate & 0x03;
	if(newstate & Primary) {
		NOT_IN_26( set_device_ro(MKDEV(MAJOR_NR, minor), FALSE ); )

ONLY_IN_26(
		set_disk_ro(mdev->vdisk, FALSE );
		D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
		bd_release(mdev->this_bdev);
		mdev->this_bdev->bd_disk = mdev->vdisk;
)

		if(test_bit(ON_PRI_INC_HUMAN,&mdev->flags)) {
			newstate |= Human;
			clear_bit(ON_PRI_INC_HUMAN,&mdev->flags);
		}

		if(test_bit(ON_PRI_INC_TIMEOUTEX,&mdev->flags)) {
			newstate |= TimeoutExpired;
			clear_bit(ON_PRI_INC_TIMEOUTEX,&mdev->flags);
		}

		if(newstate & Human) {
			drbd_md_inc(mdev,HumanCnt);
		} else if(newstate & TimeoutExpired ) {
			drbd_md_inc(mdev,TimeoutCnt);
		} else {
			drbd_md_inc(mdev,
			    mdev->cstate >= Connected ?
			    ConnectedCnt : ArbitraryCnt);
		}
	} else {
		NOT_IN_26( set_device_ro(MKDEV(MAJOR_NR, minor), TRUE ); )
		ONLY_IN_26( set_disk_ro(mdev->vdisk, TRUE ); )
	}

	if(!test_bit(DISKLESS,&mdev->flags) && (newstate & Secondary)) {
		drbd_al_to_on_disk_bm(mdev);
	}
	/* Primary indicator has changed in any case. */
	drbd_md_write(mdev);

	if (mdev->cstate >= WFReportParams) {
		/* if this was forced, we should consider sync */
		drbd_send_param(mdev,forced);
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

	if (mdev->cstate > WFConnection)
		drbd_send_sync_param(mdev,&sc);

	drbd_alter_sg(mdev, sc.group);

	return 0;
}

STATIC int drbd_detach_ioctl(drbd_dev *mdev)
{
	int would_discard_last_good_data;
	int interrupted;

	// not during resync. no.
	if (mdev->cstate > Connected) return -EBUSY;

	/* this was the last good data copy, if:
	 *  (I am Primary, and not connected ),
	 *  OR
	 *  (we are connected, and Peer has no good data himself)
	 */
	would_discard_last_good_data =
		( mdev->state == Primary && mdev->cstate < Connected )
		||
		( mdev->cstate >= Connected
		  && (    test_bit(PARTNER_DISKLESS, &mdev->flags)
		      || !test_bit(PARTNER_CONSISTENT, &mdev->flags) ) );

	if ( would_discard_last_good_data ) {
		return -ENETRESET;
	}
	if (test_bit(DISKLESS,&mdev->flags) ||
	    test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
		return -ENXIO;
	}

	drbd_sync_me(mdev);

	set_bit(DISKLESS,&mdev->flags);
	smp_wmb();

	interrupted = wait_event_interruptible(mdev->cstate_wait,
				      atomic_read(&mdev->local_cnt)==0);
	if ( interrupted ) {
		clear_bit(DISKLESS,&mdev->flags);
		return -EINTR;
	}

	drbd_free_ll_dev(mdev);

/* FIXME race with sync start
*/
	if (mdev->cstate == Connected) drbd_send_param(mdev,0);
/* FIXME
* if you detach while connected, you are *at least* inconsistent now,
* and should clear MDF_Consistent in metadata, and maybe even set the bitmap
* out of sync.
* since if you reattach, this might be a different lo dev, and then it needs
* to receive a sync!
*/
	if (mdev->cstate == StandAlone) {
		// maybe  < Connected is better?
		set_cstate(mdev,Unconfigured);
		drbd_mdev_cleanup(mdev);
		module_put(THIS_MODULE);
	}
	return 0;
}

#ifdef CONFIG_COMPAT
long drbd_compat_ioctl(struct file *f, unsigned cmd, unsigned long arg)
{
	int ret;
	// lock_kernel(); Not needed, since we have mdev->device_mutex
	ret = drbd_ioctl(f->f_dentry->d_inode, f, cmd, arg);
	// unlock_kernel();
	return ret;
}
#endif

int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	int minor,err=0;
	long time;
	struct Drbd_Conf *mdev;
	struct ioctl_wait* wp;
ONLY_IN_26(
	struct block_device *bdev = inode->i_bdev;
	struct gendisk *disk = bdev->bd_disk;
)

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

	if (mdev->cstate == Unconfigured) {
		switch (cmd) {
		default:
			/* oops, unknown IOCTL ?? */
			err = -EINVAL;
			goto out_unlocked;

		case DRBD_IOCTL_GET_CONFIG:
		case DRBD_IOCTL_GET_VERSION:
			break;		/* always allowed */

		case DRBD_IOCTL_SET_DISK_CONFIG:
		case DRBD_IOCTL_SET_NET_CONFIG:
			break;		/* no restriction here */

		case DRBD_IOCTL_UNCONFIG_DISK:
		case DRBD_IOCTL_UNCONFIG_NET:
			/* no op, so "drbdadm down all" does not fail */
			err = 0;
			goto out_unlocked;

		/* the rest of them don't make sense if Unconfigured.
		 * still, set an Unconfigured device Secondary
		 * is allowed, so "drbdadm down all" does not fail */
		case DRBD_IOCTL_SET_STATE:
		case DRBD_IOCTL_INVALIDATE:
		case DRBD_IOCTL_INVALIDATE_REM:
		case DRBD_IOCTL_SET_DISK_SIZE:
		case DRBD_IOCTL_SET_STATE_FLAGS:
		case DRBD_IOCTL_SET_SYNC_CONFIG:
		case DRBD_IOCTL_WAIT_CONNECT:
		case DRBD_IOCTL_WAIT_SYNC:
			err = (cmd == DRBD_IOCTL_SET_STATE && arg == Secondary)
				    ? 0 : -ENXIO;
			goto out_unlocked;
		}
	}

	if (unlikely(drbd_did_panic == DRBD_MAGIC))
		return -EBUSY;

	if( (err=down_interruptible(&mdev->device_mutex)) ) return err;
	/*
	 * please no 'return', use 'err = -ERRNO; goto out;'
	 * we hold the device_mutex
	 */

ONLY_IN_26(
	D_ASSERT(bdev == mdev->this_bdev);
	D_ASSERT(disk == mdev->vdisk);
);

	smp_rmb();
	switch (cmd) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
/* see how sys_ioctl and blkdev_ioctl handle it in 2.6 .
 * If I understand correctly, only "private" ioctl end up here.
 */
	case BLKGETSIZE:
		err = put_user(drbd_get_capacity(mdev->this_bdev),(long *)arg);
		break;

#ifdef BLKGETSIZE64
	case BLKGETSIZE64: /* see ./drivers/block/loop.c */
		err = put_user((u64)drbd_get_capacity(mdev->this_bdev)<<9, 
			       (u64*)arg);
		break;
#endif

	case BLKROSET:  // THINK do we want to intercept this one ?
	case BLKROGET:
	case BLKFLSBUF:
	case BLKSSZGET:
	case BLKBSZGET:
	case BLKBSZSET: // THINK do we want to intercept this one ?
	case BLKPG:
		err=blk_ioctl(inode->i_rdev, cmd, arg);
		break;
#endif
	case DRBD_IOCTL_GET_VERSION:
		err = put_user(API_VERSION, (int *) arg);
		break;

	case DRBD_IOCTL_SET_STATE:
		if (arg & ~(Primary|Secondary|Human|TimeoutExpired|
			    DontBlameDrbd) ) {
			err = -EINVAL;
		} else {
			err = drbd_set_state(mdev,arg);
		}
		break;

	case DRBD_IOCTL_SET_STATE_FLAGS:
		if (arg & ~(Human|TimeoutExpired) ) {
			err = -EINVAL;
		} else {
			clear_bit(ON_PRI_INC_HUMAN,&mdev->flags);
			clear_bit(ON_PRI_INC_TIMEOUTEX,&mdev->flags);
			if (arg == 0) break;

			// XXX reduce race: don't set it,
			// if we have a connection.
			// this does not avoid the race completely, though.
			if (mdev->cstate > WFConnection) {
				WARN("race avoidance: did not set "
				     "the state flags (%s), cstate=%s\n",
				        arg == (Human|TimeoutExpired)
				     ?  "Human|TimeoutExpired"
				     : arg == Human
				     ? "Human"
				     : "TimeoutExpired",
				     cstate_to_name(mdev->cstate));
				break;
			}

			if (arg & Human)
				set_bit(ON_PRI_INC_HUMAN,&mdev->flags);
			if (arg & TimeoutExpired)
				set_bit(ON_PRI_INC_TIMEOUTEX,&mdev->flags);
		}
		break;

	case DRBD_IOCTL_SET_DISK_CONFIG:
		err = drbd_ioctl_set_disk(mdev,(struct ioctl_disk_config*)arg);
		break;

	case DRBD_IOCTL_SET_DISK_SIZE:
		if (mdev->cstate > Connected) {
			err = -EBUSY;
			break;
		}
		if ( mdev->state == Secondary && mdev->o_state == Secondary) {
			err = -EINPROGRESS;
			break;
		}
		err=0;
		mdev->lo_usize = (unsigned long)arg;
		drbd_bm_lock(mdev);
		drbd_determin_dev_size(mdev);
		drbd_md_write(mdev); // Write mdev->la_size to disk.
		drbd_bm_unlock(mdev);
		if (mdev->cstate == Connected) drbd_send_param(mdev,1);
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
		if ( mdev->cstate == Unconfigured) break;
		if (  (   mdev->state  == Primary
		       && test_bit(DISKLESS,&mdev->flags) )
		   || (   mdev->o_state == Primary
		       && !test_bit(PARTNER_CONSISTENT,&mdev->flags) ) )
		{
			err=-ENODATA;
			break;
		}
		/* FIXME what if fsync returns error */
		drbd_sync_me(mdev);
		set_bit(DO_NOT_INC_CONCNT,&mdev->flags);
		set_cstate(mdev,Unconnected);
		drbd_thread_stop(&mdev->receiver);

		if (test_bit(DISKLESS,&mdev->flags)) {
			set_cstate(mdev,Unconfigured);
			drbd_mdev_cleanup(mdev);
			module_put(THIS_MODULE);
		} else set_cstate(mdev,StandAlone);

		break;

	case DRBD_IOCTL_UNCONFIG_DISK:
		if (mdev->cstate == Unconfigured) break;
		err = drbd_detach_ioctl(mdev);
		break;

	case DRBD_IOCTL_WAIT_CONNECT:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		// We can drop the mutex, we do not touch anything in mdev.
		up(&mdev->device_mutex);

		time = wait_event_interruptible_timeout(
			mdev->cstate_wait,
			mdev->cstate < Unconnected
			|| mdev->cstate >= Connected,
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

		if(put_user(mdev->cstate>=Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_WAIT_SYNC:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		up(&mdev->device_mutex);

		do {
			time = wait_event_interruptible_timeout(
				mdev->cstate_wait,
				mdev->cstate == Connected
				|| mdev->cstate < Unconnected,
				time );

			if (time < 0 ) {
				err = time;
				goto out_unlocked;
			}

			if (mdev->cstate > Connected) {
				time=MAX_SCHEDULE_TIMEOUT;
			}

			if (time == 0) {
				err = -ETIME;
				goto out_unlocked;
			}
		} while ( mdev->cstate != Connected
			  && mdev->cstate >= Unconnected );

		err=0; // no error

		if(put_user(mdev->cstate==Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_INVALIDATE:
		/* TODO
		 * differentiate between different error cases,
		 * or report the current connection state and flags back
		 * to userspace */

		/* disallow "invalidation" of local replica
		 * when currently in primary state (would be a Bad Idea),
		 * or during a running sync (won't make any sense) */
		if( (mdev->state == Primary ||
		      (mdev->cstate != Connected &&
		       mdev->cstate != StandAlone)) ||
		    test_bit(DISKLESS,&mdev->flags) ||
		    test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
			err = -EINPROGRESS;
			break;
		}

		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_clear_flag(mdev,MDF_Consistent);
		drbd_md_write(mdev);

		if (mdev->cstate == Connected) {
			/* avoid races with set_in_sync
			 * for successfull mirrored writes
			 */
			set_cstate(mdev,WFBitMapT);
			wait_event(mdev->cstate_wait,
				   atomic_read(&mdev->ap_bio_cnt)==0);
		}

		drbd_bm_lock(mdev); // racy...

		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		if (mdev->cstate >= Connected) {
			drbd_send_short_cmd(mdev,BecomeSyncSource);
			drbd_start_resync(mdev,SyncTarget);
		}

		drbd_bm_unlock(mdev);

		break;

	case DRBD_IOCTL_INVALIDATE_REM:
		if( mdev->o_state == Primary ||
		    mdev->cstate != Connected ||
		    test_bit(DISKLESS,&mdev->flags) ||
		    test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
			err = -EINPROGRESS;
			break;
		}
		if ( !drbd_md_test_flag(mdev,MDF_Consistent) ) {
			// FIXME use a more descriptive error number
			err = -EINVAL;
			break;
		}

		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_write(mdev);

		/* avoid races with set_in_sync
		 * for successfull mirrored writes
		 */
		set_cstate(mdev,WFBitMapS);
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

	default:
		err = -EINVAL;
	}
 /* out: */
	up(&mdev->device_mutex);
 out_unlocked:
	return err;
}
