/*
-*- linux-c -*-
   drbd_fs.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
	Some sanity checks in IOCTL_SET_STATE.

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
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/drbd.h>
#include "drbd_int.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
#include <linux/blkpg.h>
#endif

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
		drbd_write_bm(mdev);  // 
		drbd_md_write(mdev);  // Write mdev->la_size to disk.
	}
	lc_unlock(mdev->act_log);

	return rv;
}

/* Returns 1 if there is a disk-less node, 0 if both nodes have a disk. */
/*
 * THINK do we want the size to be KB or sectors ?
 * note, *_capacity operates in 512 byte sectors!!
 *
 * currently *_size is in KB.
 */
STATIC int do_determin_dev_size(struct Drbd_Conf* mdev)
{
	unsigned long p_size = mdev->p_size;  // partner's disk size.
	unsigned long la_size = mdev->la_size; // last agreed size.
	unsigned long m_size; // my size
	unsigned long u_size = mdev->lo_usize; // size requested by user.
	unsigned long size=0;
	int rv;

	m_size = drbd_get_capacity(mdev->backing_bdev)>>1;

	if (mdev->md_index == -1 && m_size) {// internal metadata
		D_ASSERT(m_size > MD_RESERVED_SIZE);
		m_size = drbd_md_ss(mdev)>>1;
	}

	if(p_size && m_size) {
		rv=0;
		size=min_t(unsigned long,p_size,m_size);
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
		if(u_size > size) {
			ERR("Requested disk size is too big (%lu > %lu)\n",
			    u_size, size);
		} else {
			size = u_size;
		}
	}

	if( (drbd_get_capacity(mdev->this_bdev)>>1) != size ) {
		if(bm_resize(mdev->mbds_id,size)) {
			drbd_set_my_capacity(mdev,size<<1);
			mdev->la_size = size;
			INFO("size = %lu KB\n",size);
		} else ERR("BM resizing failed. Leaving size unchanged\n");
	}

	return rv;
}

STATIC
int drbd_ioctl_set_disk(struct Drbd_Conf *mdev,
			struct ioctl_disk_config * arg)
{
	NOT_IN_26(int err;) // unused in 26 ?? cannot believe it ...
	int i, md_gc_valid, minor;
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

	/* FIXME if this was "adding" a lo dev to a previously "diskless" node,
	 * there still could be requests comming in right now. brrks.
	 */
	D_ASSERT(mdev->state == Secondary);

	if (mdev->open_cnt > 1)
		return -EBUSY;

	if (copy_from_user(&new_conf, &arg->config,sizeof(struct disk_config)))
		return -EFAULT;

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

	if ( new_conf.meta_index == -1 ) i = 1;
	else i = new_conf.meta_index+1;

	if( drbd_get_capacity(bdev2) < 2*MD_RESERVED_SIZE*i ) {
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

	q->max_sectors = min_not_zero((unsigned short)(PAGE_SIZE >> 9), b->max_sectors);
	q->max_phys_segments = 1;
	q->max_hw_segments   = 1;
	q->max_segment_size  = min((unsigned)PAGE_SIZE,b->max_segment_size);
	q->hardsect_size     = max((unsigned short)512,b->hardsect_size);
	q->seg_boundary_mask = b->seg_boundary_mask;
	q->merge_bvec_fn     = drbd_merge_bvec_fn;
	D_ASSERT(q->hardsect_size <= PAGE_SIZE); // or we are really screwed ;-)
})
#undef min_not_zero

	clear_bit(SENT_DISK_FAILURE,&mdev->flags);
	set_bit(MD_IO_ALLOWED,&mdev->flags);

/* FIXME I think inc_local_md_only within drbd_md_read is misplaced.
 * should go here, and the corresponding dec_local, too.
 */

	md_gc_valid = drbd_md_read(mdev);

/* FIXME if (md_gc_valid < 0) META DATA IO NOT POSSIBLE! */

	drbd_determin_dev_size(mdev);

	if(md_gc_valid) drbd_read_bm(mdev);
	else {
		INFO("Assuming that all blocks are out of sync (aka FullSync)\n");
		bm_fill_bm(mdev->mbds_id,-1);
		mdev->rs_total = drbd_get_capacity(mdev->this_bdev);
		drbd_write_bm(mdev);
	}

	if ( !mdev->act_log ||
	     mdev->act_log->nr_elements != mdev->sync_conf.al_extents )
	{
		struct lru_cache *n,*t;
		n = lc_alloc(mdev->sync_conf.al_extents,
			     sizeof(struct lc_element), mdev);
		// FIXME if (n==NULL) scream out loud ...
		// FIXME if (still_in_use) BUG();
		spin_lock_irq(&mdev->al_lock);
		t = mdev->act_log;
		mdev->act_log = n;
		spin_unlock_irq(&mdev->al_lock);
		if (t) lc_free(t);
	}

	drbd_al_read_log(mdev);
	if(mdev->gen_cnt[Flags] & MDF_PrimaryInd) {
		drbd_al_apply_to_bm(mdev);
		drbd_al_to_on_disk_bm(mdev);
	}

	drbd_set_blocksize(mdev,INITIAL_BLOCK_SIZE);

	if(mdev->cstate == Unconfigured ) {
		drbd_thread_start(&mdev->worker);
		set_cstate(mdev,StandAlone);
	}
	if(mdev->cstate >= Connected ) {
		drbd_send_param(mdev,1);
	} else {
		clear_bit(DISKLESS,&mdev->flags);
		smp_wmb();
		clear_bit(MD_IO_ALLOWED,&mdev->flags);
	}

	return 0;

 release_bdev2_fail_ioctl:
	NOT_IN_26(blkdev_put(filp2->f_dentry->d_inode->i_bdev,BDEV_FILE);)
	ONLY_IN_26(bd_release(bdev2);)
 release_bdev_fail_ioctl:
	NOT_IN_26(blkdev_put(filp->f_dentry->d_inode->i_bdev,BDEV_FILE);)
	ONLY_IN_26(bd_release(bdev);)
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

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
	cn.lower_device_major = MAJOR(mdev->backing_bdev ?
				      mdev->backing_bdev->bd_dev : 0);
	cn.lower_device_minor = MINOR(mdev->backing_bdev ?
				      mdev->backing_bdev->bd_dev : 0);
	cn.meta_device_major  = MAJOR(mdev->md_bdev ?
				      mdev->md_bdev->bd_dev : 0);
	cn.meta_device_minor  = MINOR(mdev->md_bdev ?
				      mdev->md_bdev->bd_dev : 0);
#else
	cn.lower_device_major=MAJOR(mdev->backing_bdev);
	cn.lower_device_minor=MINOR(mdev->backing_bdev);
	cn.meta_device_major=MAJOR(mdev->md_bdev);
	cn.meta_device_minor=MINOR(mdev->md_bdev);
#endif
	cn.cstate=mdev->cstate;
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
	int i,minor;
	enum ret_codes retcode;
	struct net_config new_conf;

	minor=(int)(mdev-drbd_conf);

	// FIXME plausibility check
	if (copy_from_user(&new_conf, &arg->config,sizeof(struct net_config)))
		return -EFAULT;

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
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

int drbd_set_state(drbd_dev *mdev,Drbd_State newstate)
{
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
	if(newstate == Secondary &&
	   (test_bit(WRITER_PRESENT,&mdev->flags) ||
	    drbd_is_mounted(minor) == MountedRW))
		return -EBUSY;
#else
	if(mdev->this_bdev->bd_contains == 0) {
		mdev->this_bdev->bd_contains = mdev->this_bdev;
	}

	if ( newstate & Secondary ) {
		/* If I got here, I am Primary. I claim me for myself. If that
		 * does not succeed, someone other has claimed me, so I cannot
		 * become Secondary. */
		if (bd_claim(mdev->this_bdev,drbd_sec_holder))
			return -EBUSY;
	}
#endif

	if( (newstate & Primary) &&
	    !(mdev->gen_cnt[Flags] & MDF_Consistent) &&
	    (mdev->cstate < Connected) &&
	    !(newstate & DontBlameDrbd) )
		return -EIO;

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

	mdev->state = (Drbd_State) newstate & 0x03;
	if(newstate & Primary) {
		NOT_IN_26( set_device_ro(MKDEV(MAJOR_NR, minor), FALSE ); )

ONLY_IN_26(
		set_disk_ro(mdev->vdisk, FALSE );
		D_ASSERT(mdev->this_bdev->bd_holder == drbd_sec_holder);
		bd_release(mdev->this_bdev);
		mdev->this_bdev->bd_disk = mdev->vdisk;
)

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

	if(newstate & Secondary && mdev->rs_total) {
		drbd_al_to_on_disk_bm(mdev);
	}
	/* Primary indicator has changed in any case. */
	drbd_md_write(mdev);

	if (mdev->cstate >= WFReportParams)
		drbd_send_param(mdev,0);

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

	if( mdev->gen_cnt[Flags] & MDF_ConnectedInd) {
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

	if(copy_from_user(&sc,&arg->config,sizeof(sc))) return -EFAULT;

	mdev->sync_conf.rate       = sc.rate;
	mdev->sync_conf.use_csums  = sc.use_csums;
	mdev->sync_conf.skip       = sc.skip;
	mdev->sync_conf.al_extents = sc.al_extents;

	if ( !mdev->act_log ||
	     mdev->act_log->nr_elements != mdev->sync_conf.al_extents )	{
		struct lru_cache *n,*t;
		n = lc_alloc(mdev->sync_conf.al_extents,
			     sizeof(struct lc_element), mdev);
		// FIXME if (n==NULL) scream out loud ...
		// FIXME if (still_in_use) BUG();
		spin_lock_irq(&mdev->al_lock);
		t = mdev->act_log;
		mdev->act_log = n;
		spin_unlock_irq(&mdev->al_lock);
		if (t) lc_free(t);
	}

	if (mdev->cstate > WFConnection)
		drbd_send_sync_param(mdev,&sc);

	drbd_alter_sg(mdev, sc.group);

	return 0;
}

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
			    DontBlameDrbd) )
			return -EINVAL;

		err = drbd_set_state(mdev,arg);
		break;

	case DRBD_IOCTL_SET_DISK_CONFIG:
		err = drbd_ioctl_set_disk(mdev,(struct ioctl_disk_config*)arg);
		break;

	case DRBD_IOCTL_SET_DISK_SIZE:
		if (mdev->cstate > Connected) {
			err = -EBUSY;
			break;
		}
		err=0;
		mdev->lo_usize = (unsigned long)arg;
		drbd_determin_dev_size(mdev);
		drbd_md_write(mdev); // Write mdev->la_size to disk.
		if (mdev->cstate == Connected) drbd_send_param(mdev,0);
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
		       && test_bit(PARTNER_DISKLESS,&mdev->flags) ) )
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
		} else set_cstate(mdev,StandAlone);

		break;

	case DRBD_IOCTL_UNCONFIG_DISK:
		if (mdev->cstate == Unconfigured) break;

		if ( mdev->state == Primary && mdev->cstate < Connected) {
			err=-ENETRESET;
			break;
		}
		/*
		if (mdev->open_cnt > 1) {
			err=-EBUSY;
			break;
		}
		*/
		if (mdev->cstate > Connected) {
			err=-EBUSY;
			break;
		}
		if (test_bit(DISKLESS,&mdev->flags) ||
		    test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
			err=-ENXIO;
			break;
		}
		drbd_sync_me(mdev);

		set_bit(DISKLESS,&mdev->flags);
		smp_wmb();
		if ( wait_event_interruptible(mdev->cstate_wait,
					      atomic_read(&mdev->local_cnt)==0) ) {
			clear_bit(DISKLESS,&mdev->flags);
			err=-EINTR;
			break;
		}

		drbd_free_ll_dev(mdev);

/* FIXME race with sync start
 */
		if (mdev->cstate == Connected) drbd_send_param(mdev,0);
		if (mdev->cstate == StandAlone) {
			set_cstate(mdev,Unconfigured);
			drbd_mdev_cleanup(mdev);
		}

		break;

	case DRBD_IOCTL_WAIT_CONNECT:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		// We can drop the mutex, we do not touch anything in mdev.
		up(&mdev->device_mutex);

		err = wait_event_interruptible_timeout(
			mdev->cstate_wait,
			mdev->cstate < Unconnected
			|| mdev->cstate >= Connected,
			time );
		if (err == 0) err = -ETIME;
		if (err < 0) goto out_unlocked;
		err=0; // no error

		if(put_user(mdev->cstate>=Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_WAIT_SYNC:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		up(&mdev->device_mutex);

		do {
			if (mdev->cstate > Connected)
				time=MAX_SCHEDULE_TIMEOUT;
			// XXX else back to user supplied timeout ??
			err = wait_event_interruptible_timeout(
				mdev->cstate_wait,
				mdev->cstate == Connected
				|| mdev->cstate < Unconnected,
				time );
			if (err == 0) err = -ETIME;
			if (err < 0) goto out_unlocked;
		} while (err > 0
			 && mdev->cstate != Connected
			 && mdev->cstate >= Unconnected);
		err=0; // no error

		if(put_user(mdev->cstate==Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_INVALIDATE:
		if( mdev->cstate != Connected ||
		    test_bit(DISKLESS,&mdev->flags) || 
		    test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
			err = -EINPROGRESS;
			break;
		}

		bm_fill_bm(mdev->mbds_id,-1);
		mdev->rs_total = drbd_get_capacity(mdev->this_bdev);
		drbd_write_bm(mdev);
		drbd_send_short_cmd(mdev,BecomeSyncSource);
		drbd_start_resync(mdev,SyncTarget);
		break;

	case DRBD_IOCTL_INVALIDATE_REM:
		if( mdev->cstate != Connected ||
		    test_bit(DISKLESS,&mdev->flags) || 
		    test_bit(PARTNER_DISKLESS,&mdev->flags) ) {
			err = -EINPROGRESS;
			break;
		}

		bm_fill_bm(mdev->mbds_id,-1);
		mdev->rs_total = drbd_get_capacity(mdev->this_bdev);
		drbd_write_bm(mdev);
		drbd_send_short_cmd(mdev,BecomeSyncTarget);
		drbd_start_resync(mdev,SyncSource);
		break;

	default:
		err = -EINVAL;
	}
 //out:
	up(&mdev->device_mutex);
 out_unlocked:
	return err;
}

