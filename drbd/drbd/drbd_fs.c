/*
-*- linux-c -*-
   drbd_fs.c
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
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/slab.h>
#include "drbd.h"
#include "drbd_int.h"

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
#include <linux/blkpg.h>
#endif 

/*static */
int drbd_ioctl_set_disk(struct Drbd_Conf *mdev, 
			struct ioctl_disk_config * arg)
{
	int err,i,minor;
	enum ret_codes retcode;
	struct disk_config new_conf;
	struct file *filp;
	struct inode *inode;
	kdev_t ll_dev;

	minor=(int)(mdev-drbd_conf);

	if (mdev->open_cnt > 1)
		return -EBUSY;

	if ((err = copy_from_user(&new_conf, &arg->config,
				  sizeof(struct disk_config))))
		return err;

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
	drbd_thread_stop(&mdev->syncer);
	drbd_thread_stop(&mdev->asender);
	drbd_thread_stop(&mdev->receiver);
	drbd_free_resources(minor);

	mdev->lo_device = ll_dev;
	mdev->lo_file = filp;
	mdev->lo_usize = new_conf.disk_size;
        mdev->do_panic = new_conf.do_panic;

	if (mdev->lo_usize) {
		blk_size[MAJOR_NR][minor] = mdev->lo_usize;
		printk(KERN_INFO DEVICE_NAME"%d: user provided size = %d KB\n",
		       minor,blk_size[MAJOR_NR][minor]);

		if (!mdev->mbds_id) {
			mdev->mbds_id = bm_init(MKDEV(MAJOR_NR, minor));
		}
	}		

	set_blocksize(MKDEV(MAJOR_NR, minor), INITIAL_BLOCK_SIZE);
	set_blocksize(mdev->lo_device, INITIAL_BLOCK_SIZE);
	mdev->blk_size_b = drbd_log2(INITIAL_BLOCK_SIZE);
	
	set_cstate(mdev,StandAllone);
	drbd_md_read(minor);

	return 0;
	
 fail_ioctl:
	if ((err=put_user(retcode, &arg->ret_code))) return err;
	return -EINVAL;
}

/*static */
int drbd_ioctl_get_conf(struct Drbd_Conf *mdev, struct ioctl_get_config* arg)
{
	struct ioctl_get_config cn;
	int err;

	cn.cstate=mdev->cstate;
	cn.lower_device_major=MAJOR(mdev->lo_device);
	cn.lower_device_minor=MINOR(mdev->lo_device);
	cn.disk_size_user=mdev->lo_usize;
	cn.do_panic=mdev->do_panic;
	memcpy(&cn.nconf, &mdev->conf, sizeof(struct net_config));

	if ((err = copy_to_user(arg,&cn,sizeof(struct ioctl_get_config))))
		return err;

	return 0;
}


/*static */
int drbd_ioctl_set_net(struct Drbd_Conf *mdev, struct ioctl_net_config * arg)
{
	int err,i,minor;
	enum ret_codes retcode;
	struct net_config new_conf;

	minor=(int)(mdev-drbd_conf);

	if ((err = copy_from_user(&new_conf, &arg->config,
				  sizeof(struct net_config))))
		return err;

	if( mdev->lo_file == 0 || mdev->lo_device == 0 ) {
		retcode=LDNoConfig;
		goto fail_ioctl;
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

	fsync_dev(MKDEV(MAJOR_NR, minor));
	drbd_thread_stop(&mdev->syncer);
	drbd_thread_stop(&mdev->asender);
	drbd_thread_stop(&mdev->receiver);
	drbd_free_sock(minor);

	memcpy(&mdev->conf,&new_conf,
	       sizeof(struct net_config));

	if (!mdev->transfer_log) {
		mdev->transfer_log = kmalloc(sizeof(drbd_request_t*) * 
					     mdev->conf.tl_size, GFP_KERNEL);
		tl_init(&drbd_conf[minor]);
	}

	set_cstate(&drbd_conf[minor],Unconnected);
	drbd_thread_start(&mdev->receiver);

	return 0;

	fail_ioctl:
	if ((err=put_user(retcode, &arg->ret_code))) return err;
	return -EINVAL;
}


int drbd_set_state(int minor,Drbd_State newstate)
{
	if(newstate == drbd_conf[minor].state) return 0; /* nothing to do */
		
	if (drbd_conf[minor].cstate == SyncingAll
	    || drbd_conf[minor].cstate == SyncingQuick)
		return -EINPROGRESS;

	if(test_bit(WRITER_PRESENT, &drbd_conf[minor].flags)
	   && newstate == Secondary)
		return -EBUSY;
			
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
	while (drbd_conf[minor].pending_cnt > 0 ||
	       drbd_conf[minor].unacked_cnt > 0 ) {
		
		printk(KERN_ERR DEVICE_NAME
		       "%d: set_state(%d,%d,%d)\n",
		       minor,
		       drbd_conf[minor].state,
		       drbd_conf[minor].pending_cnt,
		       drbd_conf[minor].unacked_cnt);
		
		interruptible_sleep_on(&drbd_conf[minor].state_wait);
		if(signal_pending(current)) { 
			return -EINTR;
		}
	}
	drbd_conf[minor].state = (Drbd_State) newstate & 0x03;
	if(newstate == PRIMARY_PLUS) drbd_md_inc(minor,HumanCnt);
	if(newstate == Primary) {
		drbd_md_inc(minor, drbd_conf[minor].cstate >= Connected ? 
			    ConnectedCnt : ArbitraryCnt);
	}
	drbd_md_write(minor); /* Primary indicator has changed in any case. */

	if (drbd_conf[minor].sock )
		drbd_setup_sock(&drbd_conf[minor]);
	
	if (drbd_conf[minor].cstate >= WFReportParams) 
		drbd_send_param(minor);

	return 0;
}

/*static */ int drbd_ioctl(struct inode *inode, struct file *file,
			   unsigned int cmd, unsigned long arg)
{
	int err;
	int minor;
	long time;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;

	switch (cmd) {
	case BLKGETSIZE:
		if ((err=put_user(blk_size[MAJOR_NR][minor]<<1, (long *)arg)))
			return err;
		break;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,3,0)
	case BLKROSET:
	case BLKROGET:
	case BLKFLSBUF:
	case BLKSSZGET:
	case BLKPG:
		return blk_ioctl(inode->i_rdev, cmd, arg);
#else
	 RO_IOCTLS(inode->i_rdev, arg);
#endif

	case DRBD_IOCTL_GET_VERSION:
		if ((err = put_user(API_VERSION, (int *) arg)))
			return err;
		break;

	case DRBD_IOCTL_SET_STATE:
		if (arg != Primary && arg != Secondary && arg != PRIMARY_PLUS)
			return -EINVAL;

		return drbd_set_state(minor,arg);

	case DRBD_IOCTL_SET_DISK_CONFIG:
		return drbd_ioctl_set_disk(&drbd_conf[minor],
					   (struct ioctl_disk_config*) arg);
	case DRBD_IOCTL_SET_NET_CONFIG:
		return drbd_ioctl_set_net(&drbd_conf[minor],
					   (struct ioctl_net_config*) arg);

	case DRBD_IOCTL_GET_CONFIG:
		return drbd_ioctl_get_conf(&drbd_conf[minor],
					   (struct ioctl_get_config*) arg);

	case DRBD_IOCTL_UNCONFIG_NET:

		if( drbd_conf[minor].cstate == Unconfigured)
			return -ENXIO;

		fsync_dev(MKDEV(MAJOR_NR, minor));
		drbd_thread_stop(&drbd_conf[minor].syncer);
		drbd_thread_stop(&drbd_conf[minor].asender);
		drbd_thread_stop(&drbd_conf[minor].receiver);

		set_cstate(&drbd_conf[minor],StandAllone);
		break;

	case DRBD_IOCTL_UNCONFIG_BOTH:

		if( drbd_conf[minor].cstate == Unconfigured)
			return -ENXIO;

		if (drbd_conf[minor].open_cnt > 1)
			return -EBUSY;

		fsync_dev(MKDEV(MAJOR_NR, minor));
		drbd_thread_stop(&drbd_conf[minor].syncer);
		drbd_thread_stop(&drbd_conf[minor].asender);
		drbd_thread_stop(&drbd_conf[minor].receiver);
		drbd_free_resources(minor);
		if (drbd_conf[minor].mbds_id) {
			bm_cleanup(drbd_conf[minor].mbds_id);
			drbd_conf[minor].mbds_id=0;
		}

		break;

	case DRBD_IOCTL_WAIT_CONNECT:
		if ((err = get_user(time, (int *) arg)))
			return err;

		time=time*HZ;
		if(time==0) time=MAX_SCHEDULE_TIMEOUT;
		
		while (drbd_conf[minor].cstate >= Unconnected && 
		       drbd_conf[minor].cstate < Connected &&
		       time > 0 ) {

			time = interruptible_sleep_on_timeout(
				&drbd_conf[minor].cstate_wait, time);

			if(signal_pending(current)) return -EINTR;
		}
			
		if ((err = put_user(drbd_conf[minor].cstate >= Connected, 
				    (int *) arg)))
			return err;
		break;


	case DRBD_IOCTL_WAIT_SYNC:
		if ((err = get_user(time, (int *) arg)))
			return err;

		time=time*HZ;
		if(time==0) time=MAX_SCHEDULE_TIMEOUT;
		
		while (drbd_conf[minor].cstate >= Unconnected && 
		       drbd_conf[minor].cstate != Connected &&
		       time > 0 ) {

			time = interruptible_sleep_on_timeout(
				&drbd_conf[minor].cstate_wait, time);

			if (drbd_conf[minor].cstate == SyncingQuick ||
			    drbd_conf[minor].cstate == SyncingAll ) 
				time=MAX_SCHEDULE_TIMEOUT;

			if(signal_pending(current)) return -EINTR;
		}
			
		if ((err = put_user(drbd_conf[minor].cstate == Connected, 
				    (int *) arg)))
			return err;
		break;

	case DRBD_IOCTL_DO_SYNC_ALL:
		if( drbd_conf[minor].cstate != Connected) return -ENXIO;

		if( drbd_conf[minor].state == Primary) {
			set_cstate(&drbd_conf[minor],SyncingAll);
			drbd_send_cstate(&drbd_conf[minor]);
			drbd_thread_start(&drbd_conf[minor].syncer);
		} else if (drbd_conf[minor].o_state == Primary) {
			drbd_send_cmd(minor,StartSync);
		} else return -EINPROGRESS;
		
		break;

	case DRBD_IOCTL_SECONDARY_REM:
		if( drbd_conf[minor].cstate != Connected) return -ENXIO;

		if (drbd_conf[minor].o_state == Primary) {
			drbd_send_cmd(minor,BecomeSec);
		} else return -ESRCH;
		
		break;

	default:
		return -EINVAL;
	}
	return 0;
}


