/*
-*- linux-c -*-
   drbd_fs.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2002, Philipp Reisner <philipp.reisner@gmx.at>.
	main author.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
	Some sanity checks in IOCTL_SET_STATE.

   Copyright (C) 2002, Lars Ellenberg <l.g.e@web.de>.
	drbd_is_mounted() for IOCTL_SET_STATE, and IOCTL_SET_DISK_CONFIG.
	Some sanity checks in IOCTL, ctl_mutex

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
#include "drbd.h"
#include "drbd_int.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
#include <linux/blkpg.h>
#endif

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

//#define DEBUG_LU(A) printk(KERN_ERR DEVICE_NAME"%d: " #A "=%lu\n",minor,A);

/* Returns 1 if there is a disk-less node, 0 if both nodes have a disk. */
int drbd_determin_dev_size(struct Drbd_Conf* mdev)
{
	unsigned long p_size = mdev->p_size;  // partner's disk size.
	unsigned long pu_size = mdev->p_usize; //partner's user requested size
	unsigned long la_size = mdev->la_size; // last agreed size.
	unsigned long m_size; // my size
	unsigned long mu_size = mdev->lo_usize; // size requested by user.
	unsigned long u_size=0; // agreed user requested size.
	unsigned long size=0;
	kdev_t ll_dev = mdev->lo_device;
	int rv,minor=(int)(mdev-drbd_conf);

	m_size = ll_dev ? blk_size[MAJOR(ll_dev)][MINOR(ll_dev)] : 0;

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
		printk(KERN_ERR DEVICE_NAME"%d: Both nodes diskless!\n",minor);
	}

	if(mu_size && pu_size) {
		u_size=min_t(unsigned long,mu_size,pu_size);
	} else {
		if(mu_size) u_size=mu_size;
		if(pu_size) u_size=pu_size;
	}

	if(u_size) {
		if(u_size > size) {
			printk(KERN_ERR DEVICE_NAME
			       "%d: Requested disk size is too big\n",minor);
		} else {
			size = u_size;
		}
	}

	if( blk_size[MAJOR_NR][minor] != size ) {
		if(bm_resize(mdev->mbds_id,size)) {
			blk_size[MAJOR_NR][minor] = size;
			mdev->la_size = size;
			printk(KERN_INFO DEVICE_NAME "%d: size = %lu KB\n",
			       minor,size);
		}
	}

	return rv;
}

STATIC
int drbd_ioctl_set_disk(struct Drbd_Conf *mdev,
			struct ioctl_disk_config * arg)
{
	int err,i,minor;
	enum ret_codes retcode;
	struct disk_config new_conf;
	struct file *filp;
	struct inode *inode;
	kdev_t ll_dev;

	if (!capable(CAP_SYS_ADMIN)) //MAYBE: Move this to the drbd_ioctl()
		return -EACCES;

	minor=(int)(mdev-drbd_conf);

	if (mdev->open_cnt > 1)
		return -EBUSY;

	if (copy_from_user(&new_conf, &arg->config,sizeof(struct disk_config)))
		return -EFAULT;

	filp = fget(new_conf.lower_device);
	if (!filp) {
		retcode=LDFDInvalid;
		goto fail_ioctl;
	}

	inode = filp->f_dentry->d_inode;

	for(i=0;i<minor_count;i++) {
		if( i != minor &&
		    inode->i_rdev == drbd_conf[i].lo_device) {
			retcode=LDAlreadyInUse;
			goto fail_ioctl;
		}
	}

	if (!S_ISBLK(inode->i_mode)) {
		fput(filp);
		retcode=LDNoBlockDev;
		goto fail_ioctl;
	}

	if (drbd_is_mounted(inode->i_rdev)) {
		printk(KERN_WARNING DEVICE_NAME
			"%d: can not configure %d:%d, has active inodes!\n",
			minor, MAJOR(inode->i_rdev), MINOR(inode->i_rdev));
		retcode=LDMounted;
		goto fail_ioctl;
	}

	if ((err = blkdev_open(inode, filp))) {
		printk(KERN_ERR DEVICE_NAME
		       "%d: blkdev_open( %d:%d ,) returned %d\n", minor,
		       MAJOR(inode->i_rdev), MINOR(inode->i_rdev),err);
		fput(filp);
		retcode=LDOpenFailed;
		goto fail_ioctl;
	}

	ll_dev = inode->i_rdev;

	if (blk_size[MAJOR(ll_dev)][MINOR(ll_dev)] < new_conf.disk_size ) {
		retcode=LDDeviceTooSmall;
		goto fail_ioctl;
	}


	fsync_dev(MKDEV(MAJOR_NR, minor));
	drbd_thread_stop(&mdev->dsender);
	drbd_thread_stop(&mdev->asender);
	drbd_thread_stop(&mdev->receiver);
	drbd_free_resources(minor);

	mdev->lo_device = ll_dev;
	mdev->lo_file = filp;
	mdev->lo_usize = new_conf.disk_size;
	mdev->do_panic = new_conf.do_panic;

	drbd_md_read(mdev);
	drbd_determin_dev_size(mdev);

	set_blocksize(MKDEV(MAJOR_NR, minor), INITIAL_BLOCK_SIZE);
	set_blocksize(mdev->lo_device, INITIAL_BLOCK_SIZE);

	set_cstate(mdev,StandAlone);

	return 0;

 fail_ioctl:
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

STATIC
int drbd_ioctl_get_conf(struct Drbd_Conf *mdev, struct ioctl_get_config* arg)
{
	struct ioctl_get_config cn;

	cn.cstate=mdev->cstate;
	cn.lower_device_major=MAJOR(mdev->lo_device);
	cn.lower_device_minor=MINOR(mdev->lo_device);
	cn.disk_size_user=mdev->lo_usize;
	cn.do_panic=mdev->do_panic;
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

	fsync_dev(MKDEV(MAJOR_NR, minor));
	drbd_thread_stop(&mdev->dsender);
	drbd_thread_stop(&mdev->asender);
	drbd_thread_stop(&mdev->receiver);
	drbd_free_sock(minor);

	memcpy(&mdev->conf,&new_conf,sizeof(struct net_config));

	set_cstate(&drbd_conf[minor],Unconnected);
	drbd_thread_start(&mdev->receiver);

	return 0;

	fail_ioctl:
	if (put_user(retcode, &arg->ret_code)) return -EFAULT;
	return -EINVAL;
}

int drbd_set_state(int minor,Drbd_State newstate)
{
	if(newstate == drbd_conf[minor].state) return 0; /* nothing to do */

	if(drbd_conf[minor].cstate == Unconfigured)
		return -ENXIO;

	if ( (newstate & Primary) && (drbd_conf[minor].o_state == Primary) )
		return -EACCES;

	if(newstate == Secondary &&
	   (test_bit(WRITER_PRESENT, &drbd_conf[minor].flags) ||
	    drbd_is_mounted(minor) == MountedRW))
		return -EBUSY;

	if( (newstate & Primary) &&
	    !(drbd_conf[minor].gen_cnt[Flags] & MDF_Consistent) &&
	    (drbd_conf[minor].cstate < Connected) &&
	    !(newstate & DontBlameDrbd) )
		return -EIO;

	fsync_dev(MKDEV(MAJOR_NR, minor));

		/* Wait until nothing is on the fly :) */
		/* PRI -> SEC : TL is empty || cstate < connected
		   SEC -> PRI : ES is empty || cstate < connected
		     -> this should be the case anyway, becuase the
			other one should be already in SEC state

		   FIXME:
		     The current implementation is full of races.
		     Will do the right thing in 2.4 (using a rw-semaphore),
		     for now it is good enough. (Do not panic, these races
		     are not harmfull)
		*/
		/*
		printk(KERN_ERR DEVICE_NAME "%d: set_state(%d,%d,%d,%d,%d)\n",
		       minor,
		       drbd_conf[minor].state,
		       drbd_conf[minor].pending_cnt,
		       drbd_conf[minor].unacked_cnt,
		       drbd_conf[minor].epoch_size);
		*/
	while (atomic_read(&drbd_conf[minor].pending_cnt) > 0 ||
	       atomic_read(&drbd_conf[minor].unacked_cnt) > 0 ) {

		printk(KERN_ERR DEVICE_NAME
		       "%d: set_state(st:%d,pe:%d,ua:%d)\n",
		       minor,
		       drbd_conf[minor].state,
		       atomic_read(&drbd_conf[minor].pending_cnt),
		       atomic_read(&drbd_conf[minor].unacked_cnt));

		interruptible_sleep_on(&drbd_conf[minor].state_wait);
		if(signal_pending(current)) {
			return -EINTR;
		}
	}
	drbd_conf[minor].state = (Drbd_State) newstate & 0x03;
	if(newstate & Primary) {
		set_device_ro(MKDEV(MAJOR_NR, minor), FALSE );
		if(newstate & Human) {
			drbd_md_inc(minor,HumanCnt);
		} else if(newstate & TimeoutExpired ) {
			drbd_md_inc(minor,TimeoutCnt);
		} else {
			drbd_md_inc(minor,
			    drbd_conf[minor].cstate >= Connected ?
			    ConnectedCnt : ArbitraryCnt);
		}
	} else {
		set_device_ro(MKDEV(MAJOR_NR, minor), TRUE );
	}

	/* Primary indicator has changed in any case. */
	drbd_md_write(drbd_conf+minor);

	if (drbd_conf[minor].cstate >= WFReportParams)
		drbd_send_param(drbd_conf+minor);

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
		printk(KERN_ERR DEVICE_NAME
		       "%d: using wfc_timeout.\n",(int)(mdev-drbd_conf));
	} else {
		time=p.degr_wfc_timeout;
		printk(KERN_ERR DEVICE_NAME
		       "%d: using degr_wfc_timeout.\n",(int)(mdev-drbd_conf));
	}

	time=time*HZ;
	if(time==0) time=MAX_SCHEDULE_TIMEOUT;

	*tp=time;

	return 0;
}

int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	int minor,err=0;
	long time;
	struct Drbd_Conf *mdev;
	struct ioctl_wait* wp;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;
	mdev = &drbd_conf[minor];

	if( (err=down_interruptible(&mdev->ctl_mutex)) ) return err;
	/*
	 * please no 'return', use 'err = -ERRNO; break;'
	 * we hold the ctl_mutex
	 */
	switch (cmd) {
	case BLKGETSIZE:
		err = put_user(blk_size[MAJOR_NR][minor]<<1, (long *)arg);
		break;

#ifdef BLKGETSIZE64
	case BLKGETSIZE64: /* see ./drivers/block/loop.c */
		err = put_user((u64)blk_size[MAJOR_NR][minor]<<10, (u64*)arg);
		break;
#endif

	case BLKROSET:
	case BLKROGET:
	case BLKFLSBUF:
	case BLKSSZGET:
	case BLKBSZGET:
	case BLKBSZSET:
	case BLKPG:
		err=blk_ioctl(inode->i_rdev, cmd, arg);
		break;
	case DRBD_IOCTL_GET_VERSION:
		err = put_user(API_VERSION, (int *) arg);
		break;

	case DRBD_IOCTL_SET_STATE:
		if (arg & ~(Primary|Secondary|Human|TimeoutExpired|
			    DontBlameDrbd) )
			return -EINVAL;

		err = drbd_set_state(minor,arg);
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
		drbd_send_param(mdev);
		break;

	case DRBD_IOCTL_SET_NET_CONFIG:
		err = drbd_ioctl_set_net(mdev,(struct ioctl_net_config*) arg);
		break;

	case DRBD_IOCTL_SET_SYNC_CONFIG:
		err = copy_from_user(&drbd_conf[minor].sync_conf,
			   &(((struct ioctl_syncer_config*)arg)->config),
				     sizeof(struct syncer_config));
		// TODO Need to signal dsender() ?
		break;

	case DRBD_IOCTL_GET_CONFIG:
		err = drbd_ioctl_get_conf(mdev,(struct ioctl_get_config*) arg);
		break;

	case DRBD_IOCTL_UNCONFIG_NET:
		if( mdev->cstate == Unconfigured) break;
		/* FIXME what if fsync returns error */
		fsync_dev(MKDEV(MAJOR_NR, minor));
		set_bit(DO_NOT_INC_CONCNT,&mdev->flags);
		drbd_thread_stop(&mdev->dsender);
		drbd_thread_stop(&mdev->asender);
		drbd_thread_stop(&mdev->receiver);

		set_cstate(mdev,StandAlone);
		break;

	case DRBD_IOCTL_UNCONFIG_BOTH:
		if (mdev->cstate == Unconfigured) break;

		if (mdev->open_cnt > 1) {
			err=-EBUSY;
			break;
		}

		fsync_dev(MKDEV(MAJOR_NR, minor));
		set_bit(DO_NOT_INC_CONCNT,&mdev->flags);
		drbd_thread_stop(&mdev->dsender);
		drbd_thread_stop(&mdev->asender);
		drbd_thread_stop(&mdev->receiver);
		drbd_free_resources(minor);
		if (mdev->mbds_id) {
			bm_cleanup(mdev->mbds_id);
			mdev->mbds_id=0;
		}

		set_cstate(mdev,Unconfigured);

		break;

	case DRBD_IOCTL_WAIT_CONNECT:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		// We can drop the mutex, we do not touch anything in mdev.
		up(&mdev->ctl_mutex);

		while (mdev->cstate >= Unconnected &&
		       mdev->cstate < Connected &&
		       time > 0 ) {

			time = interruptible_sleep_on_timeout(
				&mdev->cstate_wait, time);

			if(signal_pending(current)) {
				err = -EINTR;
				goto out_unlocked;
			}
		}

		if(put_user(mdev->cstate>=Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_WAIT_SYNC:
		wp=(struct ioctl_wait*)arg;
		if( (err=drbd_get_wait_time(&time,mdev,wp)) ) break;

		up(&mdev->ctl_mutex);

		while (mdev->cstate >= Unconnected &&
		       mdev->cstate != Connected &&
		       time > 0 ) {

			if (mdev->cstate == SyncSource ||
			    mdev->cstate == SyncTarget )
				time=MAX_SCHEDULE_TIMEOUT;

			time = interruptible_sleep_on_timeout(
				&mdev->cstate_wait, time);

			if(signal_pending(current)) {
				err = -EINTR;
				goto out_unlocked;
			}
		}

		if(put_user(mdev->cstate==Connected,&wp->ret_code))err=-EFAULT;
		goto out_unlocked;

	case DRBD_IOCTL_INVALIDATE:
		if( mdev->cstate != Connected) {
			err = -ENXIO;
			break;
		}

		bm_fill_bm(mdev->mbds_id,-1);
		mdev->rs_total=blk_size[MAJOR_NR][minor]<<1;
		drbd_start_resync(mdev,SyncTarget);
		drbd_send_cmd(drbd_conf+minor,BecomeSyncSource,0);
		break;

	case DRBD_IOCTL_INVALIDATE_REM:
		if( mdev->cstate != Connected) {
			err = -ENXIO;
			break;
		}

		mdev->rs_total=blk_size[MAJOR_NR][minor]<<1;
		drbd_start_resync(mdev,SyncSource);
		drbd_send_cmd(drbd_conf+minor,BecomeSyncTarget,0);
		break;

	case DRBD_IOCTL_SECONDARY_REM:
		if (mdev->cstate != Connected) {
			err = -ENXIO;
			break;
		}

		if (mdev->o_state == Primary) {
			drbd_send_cmd(drbd_conf+minor,BecomeSec,0);
		} else err = -ESRCH;

		break;

	default:
		err = -EINVAL;
	}
//out:
	up(&mdev->ctl_mutex);
 out_unlocked:
	return err;
}

