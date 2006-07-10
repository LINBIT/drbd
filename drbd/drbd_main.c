/*
-*- Linux-c -*-
   drbd.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

   Copyright (C) 2000, Marcelo Tosatti <marcelo@conectiva.com.br>.
	Early 2.3.x work.

   Copyright (C) 2001, Lelik P.Korchagin <lelik@price.ru>.
	Initial devfs support.

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
#include <linux/version.h>

#include <asm/uaccess.h>
#include <asm/types.h>
#include <net/sock.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/drbd_config.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/devfs_fs_kernel.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/notifier.h>

#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#include <linux/drbd.h>
#include "drbd_int.h"

/* YES. We got an official device major from lanana
 */
#define LANANA_DRBD_MAJOR 147

#ifdef CONFIG_COMPAT
# if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,10)
    /* FIXME on which thing could we test instead of the KERNEL_VERSION
     * again?  register_ioctl32_conversion was deprecated in 2.6.10, got
     * "officially" deprecated somewhen in 2.6.12, and removed in 2.6.14.
     * so lets assume all vendor kernels did the transition.  */
#   define HAVE_COMPAT_IOCTL_MEMBER
# else
#  include <linux/ioctl32.h>
# endif
#endif

struct after_state_chg_work {
	struct drbd_work w;
	drbd_state_t os;
	drbd_state_t ns;
};

int drbdd_init(struct Drbd_thread*);
int drbd_worker(struct Drbd_thread*);
int drbd_asender(struct Drbd_thread*);

int drbd_init(void);
STATIC int drbd_open(struct inode *inode, struct file *file);
STATIC int drbd_close(struct inode *inode, struct file *file);
STATIC int w_after_state_ch(drbd_dev *mdev, struct drbd_work *w, int unused);
STATIC int w_md_sync(drbd_dev *mdev, struct drbd_work *w, int unused);
STATIC void md_sync_timer_fn(unsigned long data);

MODULE_AUTHOR("Philipp Reisner <phil@linbit.com>, Lars Ellenberg <lars@linbit.com>");
MODULE_DESCRIPTION("drbd - Distributed Replicated Block Device v" REL_VERSION);
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(minor_count, "Maximum number of drbd devices (1-255)");
MODULE_ALIAS_BLOCKDEV_MAJOR(LANANA_DRBD_MAJOR);

#include <linux/moduleparam.h>
MODULE_PARM_DESC(disable_bd_claim, "DONT USE! disables block device claiming" );
/*
 * please somebody explain to me what the "perm" of the module_param
 * macro is good for (yes, permission for it in the "driverfs", but what
 * do we need to do for them to show up, to begin with?)
 * once I understand this, and the rest of the sysfs stuff, I probably
 * be able to understand how we can move from our ioctl interface to a
 * proper sysfs based one.
 *	-- lge
 */

/* thanks to these macros, if compiled into the kernel (not-module),
 * this becomes the boot parameter drbd.minor_count
 */
module_param(minor_count,      int,0);
module_param(disable_bd_claim,bool,0);

// module parameter, defined
int major_nr = LANANA_DRBD_MAJOR;
#ifdef MODULE
int minor_count = 2;
#else
int minor_count = 8;
#endif
int disable_bd_claim = 0;

// devfs name
char* drbd_devfs_name = "drbd";


// global panic flag
volatile int drbd_did_panic = 0;

/* in 2.6.x, our device mapping and config info contains our virtual gendisks
 * as member "struct gendisk *vdisk;"
 */
struct Drbd_Conf *drbd_conf;
kmem_cache_t *drbd_request_cache;
kmem_cache_t *drbd_ee_cache;
mempool_t *drbd_request_mempool;
mempool_t *drbd_ee_mempool;

/* I do not use a standard mempool, because:
   1) I want to hand out the preallocated objects first.
   2) I want to be able to interrupt sleeping allocation with a signal.
   Note: This is a single linked list, the next pointer is the private
         member of struct page.
 */
struct page* drbd_pp_pool;
spinlock_t   drbd_pp_lock;
int          drbd_pp_vacant;
wait_queue_head_t drbd_pp_wait;


STATIC struct block_device_operations drbd_ops = {
	.owner =   THIS_MODULE,
	.open =    drbd_open,
	.release = drbd_close,
	.ioctl =   drbd_ioctl,
#ifdef HAVE_COMPAT_IOCTL_MEMBER
	.compat_ioctl = drbd_compat_ioctl,
#endif
};

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

/************************* The transfer log start */
STATIC int tl_init(drbd_dev *mdev)
{
	struct drbd_barrier *b;

	b=kmalloc(sizeof(struct drbd_barrier),GFP_KERNEL);
	if(!b) return 0;
	INIT_LIST_HEAD(&b->requests);
	b->next=0;
	b->br_number=4711;
	b->n_req=0;

	mdev->oldest_barrier = b;
	mdev->newest_barrier = b;

	mdev->tl_hash = NULL;
	mdev->tl_hash_s = 0;

	return 1;
}

STATIC void tl_cleanup(drbd_dev *mdev)
{
	D_ASSERT(mdev->oldest_barrier == mdev->newest_barrier);
	kfree(mdev->oldest_barrier);
	if(mdev->tl_hash) {
		kfree(mdev->tl_hash);
		mdev->tl_hash_s = 0;
	}
}

STATIC unsigned int tl_hash_fn(drbd_dev *mdev, sector_t sector)
{
	BUG_ON(mdev->tl_hash_s == 0);
	return (unsigned int)(sector>>HT_SHIFT) % mdev->tl_hash_s;
}


STATIC void _tl_add(drbd_dev *mdev, drbd_request_t *req)
{
	struct drbd_barrier *b;

	b=mdev->newest_barrier;

	req->barrier = b;
	req->rq_status |= RQ_DRBD_IN_TL;
	list_add(&req->w.list,&b->requests);

	if( b->n_req++ > mdev->net_conf->max_epoch_size ) {
		set_bit(ISSUE_BARRIER,&mdev->flags);
	}

	INIT_HLIST_NODE(&req->colision);
	hlist_add_head( &req->colision, mdev->tl_hash +
			tl_hash_fn(mdev, drbd_req_get_sector(req) ));
}

STATIC void tl_add(drbd_dev *mdev, drbd_request_t * req)
{
	spin_lock_irq(&mdev->tl_lock);
	_tl_add(mdev,req);
	spin_unlock_irq(&mdev->tl_lock);
}

STATIC void tl_cancel(drbd_dev *mdev, drbd_request_t *req)
{
	struct drbd_barrier *b;

	spin_lock_irq(&mdev->tl_lock);

	b=req->barrier;
	b->n_req--;

	list_del(&req->w.list);
	hlist_del(&req->colision);
	req->rq_status &= ~RQ_DRBD_IN_TL;

	spin_unlock_irq(&mdev->tl_lock);
}

STATIC unsigned int tl_add_barrier(drbd_dev *mdev)
{
	unsigned int bnr;
	struct drbd_barrier *b;

	b=kmalloc(sizeof(struct drbd_barrier),GFP_NOIO);
	if(!b) {
		ERR("could not kmalloc() barrier\n");
		return 0;
	}
	INIT_LIST_HEAD(&b->requests);
	b->next=0;
	b->n_req=0;

	spin_lock_irq(&mdev->tl_lock);
	/* mdev->newest_barrier == NULL "cannot happen". but anyways... */
	bnr = mdev->newest_barrier ? mdev->newest_barrier->br_number : 1;
	/* never send a barrier number == 0 */
	b->br_number = (bnr+1) ?: 1;
	mdev->newest_barrier->next = b;
	mdev->newest_barrier = b;
	spin_unlock_irq(&mdev->tl_lock);

	return bnr;
}

void tl_release(drbd_dev *mdev,unsigned int barrier_nr,
		       unsigned int set_size)
{
	struct drbd_barrier *b;

	spin_lock_irq(&mdev->tl_lock);

	b = mdev->oldest_barrier;
	mdev->oldest_barrier = b->next;

	list_del(&b->requests);
	/* There could be requests on the list waiting for completion
	   of the write to the local disk, to avoid corruptions of
	   slab's data structures we have to remove the lists head */

	spin_unlock_irq(&mdev->tl_lock);

	D_ASSERT(b->br_number == barrier_nr);
	D_ASSERT(b->n_req == set_size);

	kfree(b);
}

int tl_verify(drbd_dev *mdev, drbd_request_t * req, sector_t sector)
{
	struct hlist_head *slot = mdev->tl_hash + tl_hash_fn(mdev,sector);
	struct hlist_node *n;
	drbd_request_t * i;
	int rv=0;

	spin_lock_irq(&mdev->tl_lock);

	hlist_for_each_entry(i, n, slot, colision) {
		if (i==req) {
			D_ASSERT(drbd_req_get_sector(i) == sector);
			rv=1;
			break;
		}
	}

	spin_unlock_irq(&mdev->tl_lock);

	return rv;
}

/* tl_dependence reports if this sector was present in the current
   epoch.
   As side effect it clears also the pointer to the request if it
   was present in the transfert log. (Since tl_dependence indicates
   that IO is complete and that drbd_end_req() should not be called
   in case tl_clear has to be called due to interruption of the
   communication)
*/
/* bool */
int tl_dependence(drbd_dev *mdev, drbd_request_t * req)
{
	unsigned long flags;
	int r=TRUE;

	spin_lock_irqsave(&mdev->tl_lock,flags);

	r = ( req->barrier == mdev->newest_barrier );
	list_del(&req->w.list);
	hlist_del(&req->colision);

	if( req->rq_status & RQ_DRBD_RECVW ) wake_up(&mdev->cstate_wait);

	spin_unlock_irqrestore(&mdev->tl_lock,flags);
	return r;
}

void tl_clear(drbd_dev *mdev)
{
	struct list_head *le,*tle;
	struct drbd_barrier *b,*f,*new_first;
	struct drbd_request *r;
	sector_t sector;
	unsigned int size;

	new_first=kmalloc(sizeof(struct drbd_barrier),GFP_NOIO);
	if(!new_first) {
		ERR("could not kmalloc() barrier\n");
	}

	/* FIXME if indeed we could not kmalloc, this will Oops!
	 * can we somehow just recycle one of the existing barriers?
	 */
	INIT_LIST_HEAD(&new_first->requests);
	new_first->next=0;
	new_first->br_number=4711;
	new_first->n_req=0;

	spin_lock_irq(&mdev->tl_lock);

	b=mdev->oldest_barrier;
	mdev->oldest_barrier = new_first;
	mdev->newest_barrier = new_first;

	spin_unlock_irq(&mdev->tl_lock);

	inc_ap_pending(mdev); // Since we count the old first as well...

	while ( b ) {
		list_for_each_safe(le, tle, &b->requests) {
			r = list_entry(le, struct drbd_request,w.list);
			// bi_size and bi_sector are modified in bio_endio!
			sector = drbd_req_get_sector(r);
			size   = drbd_req_get_size(r);
			if( !(r->rq_status & RQ_DRBD_SENT) ) {
				if(mdev->net_conf->wire_protocol != DRBD_PROT_A )
					dec_ap_pending(mdev);
				drbd_end_req(r,RQ_DRBD_SENT,ERF_NOTLD|1, sector);
				goto mark;
			}
			if(mdev->net_conf->wire_protocol != DRBD_PROT_C ) {
			mark:
				drbd_set_out_of_sync(mdev, sector, size);
			}
		}
		f=b;
		b=b->next;
		list_del(&f->requests);
		kfree(f);
		dec_ap_pending(mdev); // for the barrier
	}
}

STATIC unsigned int ee_hash_fn(drbd_dev *mdev, sector_t sector)
{
	BUG_ON(mdev->ee_hash_s == 0);
	return (unsigned int)(sector>>HT_SHIFT) % mdev->ee_hash_s;
}

STATIC int overlaps(sector_t s1, int l1, sector_t s2, int l2)
{
	return !( ( s1 + (l1>>9) <= s2 ) || ( s1 >= s2 + (l2>>9) ) );
}

drbd_request_t * req_have_write(drbd_dev *mdev, struct Tl_epoch_entry *e)
{
	struct hlist_head *slot;
	struct hlist_node *n;
	drbd_request_t * req;
	sector_t sector = drbd_ee_get_sector(e);
	int size = drbd_ee_get_size(e);
	int i;

	D_ASSERT(size <= 1<<(HT_SHIFT+9) );

	spin_lock_irq(&mdev->tl_lock);

	for(i=-1;i<=1;i++ ) {
		slot = mdev->tl_hash + tl_hash_fn(mdev,
						  sector + i*(1<<(HT_SHIFT)));
		hlist_for_each_entry(req, n, slot, colision) {
			if( overlaps(drbd_req_get_sector(req),
				     drbd_req_get_size(req),
				     sector,
				     size) ) goto out;
		} // hlist_for_each_entry()
	}
	req = NULL;
	// Good, no conflict found
	INIT_HLIST_NODE(&e->colision);
	hlist_add_head( &e->colision, mdev->ee_hash +
			ee_hash_fn(mdev, sector) );
 out:
	spin_unlock_irq(&mdev->tl_lock);

	return req;
}

STATIC struct Tl_epoch_entry * ee_have_write(drbd_dev *mdev,
					     drbd_request_t * req)
{
	struct hlist_head *slot;
	struct hlist_node *n;
	struct Tl_epoch_entry *ee;
	sector_t sector = drbd_req_get_sector(req);
	int size = drbd_req_get_size(req);
	int i;

	D_ASSERT(size <= 1<<(HT_SHIFT+9) );

	spin_lock_irq(&mdev->tl_lock);

	for(i=-1;i<=1;i++ ) {
		slot = mdev->ee_hash + ee_hash_fn(mdev,
						  sector + i*(1<<(HT_SHIFT)));
		hlist_for_each_entry(ee, n, slot, colision) {
			if( overlaps(drbd_ee_get_sector(ee),
				     drbd_ee_get_size(ee),
				     sector,
				     size) ) goto out;
		} // hlist_for_each_entry()
	}
	ee = NULL;
	// Good, no conflict found
	_tl_add(mdev,req);
 out:
	spin_unlock_irq(&mdev->tl_lock);

	return ee;
}

/**
 * drbd_io_error: Handles the on_io_error setting, should be called in the
 * unlikely(!drbd_bio_uptodate(e->bio)) case from kernel thread context.
 * See also drbd_chk_io_error
 *
 * NOTE: we set ourselves DISKLESS here.
 * But we try to write the "need full sync bit" here anyways.  This is to make sure
 * that you get a resynchronisation of the full device the next time you
 * connect.
 */
int drbd_io_error(drbd_dev* mdev)
{
	unsigned long flags;
	int send,ok=1;

	if(mdev->bc->on_io_error != Panic && mdev->bc->on_io_error != Detach) return 1;

	spin_lock_irqsave(&mdev->req_lock,flags);
	if( (send = (mdev->state.disk == Failed)) ) {
		_drbd_set_state(mdev,_NS(disk,Diskless),ChgStateHard);
	}
	D_ASSERT(mdev->state.disk <= Failed);
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	if(!send) return ok;

	ok = drbd_send_state(mdev);
	WARN("Notified peer that my disk is broken.\n");

	D_ASSERT(drbd_md_test_flag(mdev->bc,MDF_FullSync));
	D_ASSERT(!drbd_md_test_flag(mdev->bc,MDF_Consistent));
	drbd_md_sync(mdev);

	if ( wait_event_interruptible_timeout(mdev->cstate_wait,
		     atomic_read(&mdev->local_cnt) == 0 , HZ ) <= 0) {
		WARN("Not releasing backing storage device.\n");
		/* FIXME if there *are* still references,
		 * we should be here again soon enough.
		 * but what if not?
		 * we still should free our ll and md devices */
	} else {
		/* no race. since the DISKLESS bit is set first,
		 * further references to local_cnt are shortlived,
		 * and no real references on the device. */
		WARN("Releasing backing storage device.\n");
		drbd_free_bc(mdev->bc);
		mdev->bc=NULL;
	}

	return ok;
}

/** 
 * cl_wide_st_chg:
 * Returns TRUE if this state change should be preformed as a cluster wide
 * transaction. Of courese it returns 0 as soon as the connection is lost.
 */ 
STATIC int cl_wide_st_chg(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns)
{
	return ( ns.conn >= Connected &&
		 ( ( os.role != Primary && ns.role == Primary ) ||
		   // ( os.conn != SyncSource && ns.role == SyncSource ) ||
		   // ( os.conn != SyncTarget && ns.role == SyncTarget ) ||
		   // ( os.disk != Diskless && ns.role == Diskless ) ||
		   // ( os.conn != TearDown && ns.conn == TearDown ) ||
		   0
		   ) );
}

int drbd_change_state(drbd_dev* mdev, enum chg_state_flags f,
		      drbd_state_t mask, drbd_state_t val)
{
	unsigned long flags;
	drbd_state_t os,ns;
	int rv;

	spin_lock_irqsave(&mdev->req_lock,flags);
	os = mdev->state;
	ns.i = (os.i & ~mask.i) | val.i;
	rv = _drbd_set_state(mdev, ns, f);
	ns = mdev->state;
	spin_unlock_irqrestore(&mdev->req_lock,flags);
	after_state_ch(mdev,os,ns);

	return rv;
}

void drbd_force_state(drbd_dev* mdev, drbd_state_t mask, drbd_state_t val)
{
	drbd_change_state(mdev,ChgStateHard,mask,val);
}

STATIC int pre_state_checks(drbd_dev* mdev, drbd_state_t ns);
STATIC int drbd_send_state_req(drbd_dev *, drbd_state_t, drbd_state_t);

set_st_err_t _req_st_cond(drbd_dev* mdev,drbd_state_t mask, drbd_state_t val)
{
	drbd_state_t os,ns;
	unsigned long flags;
	int rv;

	if(test_and_clear_bit(CL_ST_CHG_SUCCESS,&mdev->flags)) 
		return SS_CW_Success;

	if(test_and_clear_bit(CL_ST_CHG_FAIL,&mdev->flags)) 
		return SS_CW_FailedByPeer;

	rv=0;
	spin_lock_irqsave(&mdev->req_lock,flags);
	os = mdev->state;
	ns.i = (os.i & ~mask.i) | val.i;
	if( !cl_wide_st_chg(mdev,os,ns) ) rv = SS_CW_NoNeed;
	if( !rv ) {
		rv = pre_state_checks(mdev,ns);
		if(rv==SS_Success) rv = 0; // cont waiting, otherwise fail.
	}
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	return rv;
}

/** 
 * _drbd_request_state:
 * This function is the most gracefull way to change state. For some state
 * transition this function even does a cluster wide transaction.
 * It has a cousin named drbd_request_state(), which is always verbose.
 */ 
int _drbd_request_state(drbd_dev* mdev, drbd_state_t mask, drbd_state_t val,
		       enum chg_state_flags f)
{
	unsigned long flags;
	drbd_state_t os,ns;
	int rv;

	spin_lock_irqsave(&mdev->req_lock,flags);
	os = mdev->state;
	ns.i = (os.i & ~mask.i) | val.i;

	if(cl_wide_st_chg(mdev,os,ns)) {
		rv = pre_state_checks(mdev,ns);
		spin_unlock_irqrestore(&mdev->req_lock,flags);

		if( rv < SS_Success ) {
			if( f & ChgStateVerbose ) print_st_err(mdev,os,ns,rv);
			return rv;
		}

		drbd_state_lock(mdev);
		drbd_send_state_req(mdev,mask,val);

		wait_event(mdev->cstate_wait,(rv=_req_st_cond(mdev,mask,val)));

		if( rv < SS_Success ) {
			// nearly dead code.
			drbd_state_unlock(mdev);
			if( f & ChgStateVerbose ) print_st_err(mdev,os,ns,rv);
			return rv;
		}
		spin_lock_irqsave(&mdev->req_lock,flags);
		os = mdev->state;
		ns.i = (os.i & ~mask.i) | val.i;
		drbd_state_unlock(mdev);
	}

	rv = _drbd_set_state(mdev, ns, f);
	ns = mdev->state;
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	if (rv == SS_Success) after_state_ch(mdev,os,ns);

	return rv;
}


static void print_st(drbd_dev* mdev, char *name, drbd_state_t ns)
{
	ERR(" %s = { cs:%s st:%s/%s ds:%s/%s %c%c%c%c }\n",
	    name,
	    conns_to_name(ns.conn),
	    roles_to_name(ns.role),
	    roles_to_name(ns.peer),
	    disks_to_name(ns.disk),
	    disks_to_name(ns.pdsk),
	    ns.susp ? 's' : 'r',
	    ns.aftr_isp ? 'a' : '-',
	    ns.peer_isp ? 'p' : '-',
	    ns.user_isp ? 'u' : '-'
	    );
}

void print_st_err(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns, int err)
{
	ERR("State change failed: %s\n",set_st_err_name(err));
	print_st(mdev," state",os);
	print_st(mdev,"wanted",ns);
}


#define peers_to_name roles_to_name
#define pdsks_to_name disks_to_name

#define susps_to_name(A) ( (A) ? "1" : "0" )
#define aftr_isps_to_name(A) ( (A) ? "1" : "0" )
#define peer_isps_to_name(A) ( (A) ? "1" : "0" )
#define user_isps_to_name(A) ( (A) ? "1" : "0" )

#define PSC(A) \
	({ if( ns.A != os.A ) { \
		pbp += sprintf(pbp, #A "( %s -> %s ) ", \
		              A##s_to_name(os.A), \
		              A##s_to_name(ns.A)); \
	} })

STATIC int pre_state_checks(drbd_dev* mdev, drbd_state_t ns)
{
	/* See drbd_state_sw_errors in drbd_strings.c */

	enum fencing_policy fp;
	int rv=SS_Success;

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->fencing;
		dec_local(mdev);
	}

	if(inc_net(mdev)) {
		if( !mdev->net_conf->two_primaries &&
		    ns.role == Primary && ns.peer == Primary ) 
			rv=SS_TowPrimaries;
		dec_net(mdev);
	}

	if( rv <= 0 ) /* already found a reason to abort */;
	else if( ns.role == Primary && ns.conn < Connected &&
		 ns.disk < UpToDate ) rv=SS_NoUpToDateDisk;

	else if( fp >= Resource &&
		 ns.role == Primary && ns.conn < Connected &&
		 ns.pdsk >= DUnknown ) rv=SS_PrimaryNOP;

	else if( ns.role == Primary && ns.disk <= Inconsistent &&
		 ns.pdsk <= Inconsistent ) rv=SS_NoUpToDateDisk;
	
	else if( ns.conn > Connected &&
		 ns.disk < UpToDate && ns.pdsk < UpToDate ) 
		rv=SS_BothInconsistent;

	else if( ns.conn > Connected &&
		 (ns.disk == Diskless || ns.pdsk == Diskless ) )
		rv=SS_SyncingDiskless;

	else if( (ns.conn == Connected ||
		  ns.conn == SkippedSyncS ||
		  ns.conn == WFBitMapS ||
		  ns.conn == SyncSource ||
		  ns.conn == PausedSyncS) &&
		 ns.disk == Outdated ) rv=SS_ConnectedOutdates;

	return rv;
}

int _drbd_set_state(drbd_dev* mdev, drbd_state_t ns,enum chg_state_flags flags)
{
	drbd_state_t os;
	int rv=SS_Success, warn_sync_abort=0;
	enum fencing_policy fp;

	MUST_HOLD(&mdev->req_lock);

	os = mdev->state;

	if( ns.i == os.i ) return SS_NothingToDo;

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->fencing;
		dec_local(mdev);
	}

	/*  State sanitising  */
	if( ns.conn < Connected ) {
		ns.peer = Unknown;
		if ( ns.pdsk > DUnknown ) ns.pdsk = DUnknown;
	}

	if( ns.conn == StandAlone && ns.disk == Diskless ) {
		ns.pdsk = DUnknown;
	}

	if( ns.conn > Connected && ns.disk <= Failed ) {
		warn_sync_abort=1;
		ns.conn = Connected;
	}

	if( ns.conn >= Connected &&
	    ( ns.disk == Consistent || ns.disk == Outdated ) ) {
		switch(ns.conn) {
		case SkippedSyncT:
		case WFBitMapT:
		case PausedSyncT:
			ns.disk = Outdated;
			break;
		case Connected:
		case SkippedSyncS:
		case WFBitMapS:
		case SyncSource:
		case PausedSyncS:
			ns.disk = UpToDate;
			break;
		case SyncTarget:
			ns.disk = Inconsistent;
			WARN("Implicit set disk state Inconsistent!\n");
			break;
		}
		if( os.disk == Outdated && ns.disk == UpToDate ) {
			WARN("Implicit set disk from Outdate to UpToDate\n");
		}
	}

	if( ns.conn >= Connected &&
	    ( ns.pdsk == Consistent || ns.pdsk == Outdated ) ) {
		switch(ns.conn) {
		case Connected:
		case SkippedSyncT:
		case WFBitMapT:
		case PausedSyncT:
		case SyncTarget:
			ns.pdsk = UpToDate;
			break;
		case SkippedSyncS:
		case WFBitMapS:
		case PausedSyncS:
			ns.pdsk = Outdated;
			break;
		case SyncSource:
			ns.pdsk = Inconsistent;
			WARN("Implicit set pdsk Inconsistent!\n");
			break;
		}
		if( os.pdsk == Outdated && ns.pdsk == UpToDate ) {
			WARN("Implicit set pdsk from Outdate to UpToDate\n");
		}
	}

	if( fp == Stonith ) {
		if(ns.role == Primary &&
		   ns.conn < Connected &&
		   ns.pdsk > Outdated ) {
			ns.susp = 1;
		}
	}
	
	if( !(flags & ChgStateHard) ) {
		/*  pre-state-change checks ; only look at ns  */
		/* See drbd_state_sw_errors in drbd_strings.c */

		rv = pre_state_checks(mdev,ns);
		if(rv < SS_Success) {
			/* If the old state was illegal as well, then let
			   this happen...*/

			if( pre_state_checks(mdev,os) == rv ) {
				ERR("State change from bad state. "
				    "Error would be: '%s'\n", 
				    set_st_err_name(rv));
				print_st(mdev,"old",os);
				print_st(mdev,"new",ns);
				rv = SS_Success;
			}
		}
	}

	if(rv < SS_Success) {
		if( flags & ChgStateVerbose ) print_st_err(mdev,os,ns,rv);
		return rv;
	}

	if(warn_sync_abort) {
		WARN("Resync aborted.\n");
	}

#if DUMP_MD >= 2
	char *pbp,pb[300];
	pbp = pb;
	*pbp=0;
	PSC(role);
	PSC(peer);
	PSC(conn);
	PSC(disk);
	PSC(pdsk);
	PSC(susp);
	PSC(aftr_isp);
	PSC(peer_isp);
	PSC(user_isp);
	INFO("%s\n", pb);
#endif

	mdev->state.i = ns.i;
	wake_up(&mdev->cstate_wait);

	/**   post-state-change actions   **/
	if ( os.conn >= SyncSource   && ns.conn <= Connected ) {
		clear_bit(SYNC_STARTED,&mdev->flags);
		set_bit(STOP_SYNC_TIMER,&mdev->flags);
		mod_timer(&mdev->resync_timer,jiffies);
	}

	if ( os.disk == Diskless && os.conn == StandAlone &&
	     (ns.disk > Diskless || ns.conn > StandAlone) ) {
		__module_get(THIS_MODULE);
	}

	if ( ns.role == Primary && ns.conn < Connected &&
	     ns.disk < Consistent ) {
		drbd_panic("No access to good data anymore.\n");
	}

	if( flags & ScheduleAfter ) {
		struct after_state_chg_work* ascw;

		ascw = kmalloc(sizeof(*ascw), GFP_ATOMIC);
		if(ascw) {
			ascw->os = os;
			ascw->ns = ns;
			ascw->w.cb = w_after_state_ch;
			_drbd_queue_work_front(&mdev->data.work,&ascw->w);
		} else {
			WARN("Could not kmalloc an ascw\n");
		}
	}

	return rv;
}

STATIC int w_after_state_ch(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct after_state_chg_work* ascw;

	ascw = (struct after_state_chg_work*) w;
	after_state_ch(mdev, ascw->os, ascw->ns);
	kfree(ascw);

	return 1;
}

void after_state_ch(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns)
{
	enum fencing_policy fp;
	u32 mdf;

	if ( (os.role != Primary && ns.role == Primary)    ||
	     (os.conn != Connected && ns.conn == Connected) ) {
		clear_bit(CRASHED_PRIMARY, &mdev->flags);
	}

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->fencing;
		dec_local(mdev);
	}

	if(mdev->bc) {
		mdf = mdev->bc->md.flags & ~(MDF_Consistent|MDF_PrimaryInd|
					     MDF_ConnectedInd|MDF_WasUpToDate|
					     MDF_PeerOutDated );
		if (test_bit(CRASHED_PRIMARY,&mdev->flags) ||
		    mdev->state.role == Primary)       mdf |= MDF_PrimaryInd;
		if (mdev->state.conn > WFReportParams) mdf |= MDF_ConnectedInd;
		if (mdev->state.disk > Inconsistent)   mdf |= MDF_Consistent;
		if (mdev->state.disk > Outdated)       mdf |= MDF_WasUpToDate;
		if (mdev->state.pdsk <= Outdated)      mdf |= MDF_PeerOutDated;

		if( mdf != mdev->bc->md.flags) {
			mdev->bc->md.flags = mdf;
			drbd_md_mark_dirty(mdev);
		}
	}

	/* Here we have the actions that are performed after a
	   state change. This function might sleep */

	if( fp == Stonith && ns.susp ) {
		// case1: The outdate peer handler is successfull:
		// case2: The connection was established again:
		if ( (os.pdsk > Outdated  && ns.pdsk <= Outdated) || // case1
		     (os.conn < Connected && ns.conn >= Connected) ) {
			tl_clear(mdev);
			spin_lock_irq(&mdev->req_lock);
			_drbd_set_state(mdev,_NS(susp,0), 
					ChgStateVerbose | ScheduleAfter );
			spin_unlock_irq(&mdev->req_lock);
		}
	}
	// Do not change the order of the if above and below...
	if (os.conn != WFBitMapS && ns.conn == WFBitMapS) {
		wait_event(mdev->cstate_wait,!atomic_read(&mdev->ap_bio_cnt));
		drbd_bm_lock(mdev);   // {
		drbd_send_bitmap(mdev);
		drbd_bm_unlock(mdev); // }
	}

	/*  Lost contact to peer's copy of the data  */
	if ( os.pdsk > DUnknown && ns.pdsk <= DUnknown ) {
		if ( mdev->p_uuid ) {
			kfree(mdev->p_uuid);
			mdev->p_uuid = NULL;
		}
		if (ns.role == Primary && mdev->bc->md.uuid[Bitmap] == 0 ) {
			/* Only do it if we have not yet done it... */
			INFO("Creating new current UUID\n");
			drbd_uuid_new_current(mdev);
		}
		if (ns.peer == Primary ) { 
 			/* Note: The condition ns.peer == Primary implies
			         that we are connected. Otherwise it would
				 be ns.peer == Unknown. */
 			/* Our peer lost its disk.
			   Not rotation into BitMap-UUID! A FullSync is 
			   required after a primary detached from it disk! */
			u64 uuid;
			INFO("Creating new current UUID [no BitMap]\n");
			get_random_bytes(&uuid, sizeof(u64));
			drbd_uuid_set(mdev, Current, uuid);
		}
	}

	/*  Removed disk, tell peer.  */
	if ( os.disk >= Inconsistent && ns.disk == Diskless &&
	     ns.conn >= Connected ) {
		drbd_send_state(mdev);
	}

	/* We want to pause resync, tell peer. */
	if (  ( os.aftr_isp == 0 && ns.aftr_isp == 1 ) ||
	      ( os.user_isp == 0 && ns.user_isp == 1 ) ) {
		drbd_send_short_cmd(mdev,PauseResync);
	}

	/* We want to continue resync, tell peer. */
	if (  ( os.aftr_isp == 1 || os.user_isp == 1 ) &&
	        ns.aftr_isp == 0 && ns.user_isp == 0   ) {
		drbd_send_short_cmd(mdev,ResumeResync);
	}

	/* it feels better to have the module_put last ... */
	if ( (os.disk > Diskless || os.conn > StandAlone) &&
	     ns.disk == Diskless && ns.conn == StandAlone ) {
		drbd_mdev_cleanup(mdev);
		module_put(THIS_MODULE);
	}
}


STATIC int drbd_thread_setup(void* arg)
{
	struct Drbd_thread *thi = (struct Drbd_thread *) arg;
	drbd_dev *mdev = thi->mdev;
	int retval;

	daemonize("drbd_thread");
	D_ASSERT(get_t_state(thi) == Running);
	D_ASSERT(thi->task == NULL);
	spin_lock(&thi->t_lock);
	thi->task = current;
	smp_mb();
	spin_unlock(&thi->t_lock);
	complete(&thi->startstop); // notify: thi->task is set.

	retval = thi->function(thi);

	spin_lock(&thi->t_lock);
	thi->task = 0;
	thi->t_state = Exiting;
	smp_mb();
	spin_unlock(&thi->t_lock);

	// THINK maybe two different completions?
	complete(&thi->startstop); // notify: thi->task unset.

	return retval;
}

STATIC void drbd_thread_init(drbd_dev *mdev, struct Drbd_thread *thi,
		      int (*func) (struct Drbd_thread *))
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = None;
	init_completion(&thi->startstop);

	thi->function = func;
	thi->mdev = mdev;
}

void drbd_thread_start(struct Drbd_thread *thi)
{
	int pid;
	drbd_dev *mdev = thi->mdev;

	spin_lock(&thi->t_lock);

	/* INFO("%s [%d]: %s %d -> Running\n",
	     current->comm, current->pid,
	     thi == &mdev->receiver ? "receiver" :
             thi == &mdev->asender  ? "asender"  :
             thi == &mdev->worker   ? "worker"   : "NONSENSE",
	     thi->t_state); */

	if (thi->t_state == None) {
		D_ASSERT(thi->task == NULL);
		thi->t_state = Running;
		spin_unlock(&thi->t_lock);
		flush_signals(current); // otherw. may get -ERESTARTNOINTR
		pid = kernel_thread(drbd_thread_setup, (void *) thi, CLONE_FS);
		if (pid < 0) {
			ERR("Couldn't start thread (%d)\n", pid);
			return;
		}
		wait_for_completion(&thi->startstop); // waits until thi->task is set
		D_ASSERT(thi->task);
		D_ASSERT(get_t_state(thi) == Running);
	} else {
		spin_unlock(&thi->t_lock);
	}
}


void _drbd_thread_stop(struct Drbd_thread *thi, int restart,int wait)
{
	drbd_dev *mdev = thi->mdev;
	Drbd_thread_state ns = restart ? Restarting : Exiting;

	spin_lock(&thi->t_lock);

	/* INFO("%s [%d]: %s %d -> %d; %d\n",
	     current->comm, current->pid,
	     thi->task ? thi->task->comm : "NULL", thi->t_state, ns, wait); */


	if (thi->t_state == None) {
		spin_unlock(&thi->t_lock);
		return;
	}

	if (thi->t_state != ns) {
		ERR_IF (thi->task == NULL) {
			spin_unlock(&thi->t_lock);
			return;
		}

		if (ns == Restarting && thi->t_state == Exiting) {
			// Already Exiting. Cannot restart!
			spin_unlock(&thi->t_lock);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		if (thi->task != current)
			force_sig(DRBD_SIGKILL,thi->task);
		else
			D_ASSERT(!wait);

	}
	spin_unlock(&thi->t_lock);

	if (wait) {
		D_ASSERT(thi->t_state == Exiting);
		wait_for_completion(&thi->startstop);
		spin_lock(&thi->t_lock);
		thi->t_state = None;
		smp_mb();
		D_ASSERT(thi->task == NULL);
		spin_unlock(&thi->t_lock);
	}
}

inline sigset_t drbd_block_all_signals(void)
{
	unsigned long flags;
	sigset_t oldset;
	LOCK_SIGMASK(current,flags);
	oldset = current->blocked;
	sigfillset(&current->blocked);
	RECALC_SIGPENDING();
	UNLOCK_SIGMASK(current,flags);
	return oldset;
}

inline void restore_old_sigset(sigset_t oldset)
{
	unsigned long flags;
	LOCK_SIGMASK(current,flags);
	// _never_ propagate this to anywhere...
	sigdelset(&current->pending.signal, DRBD_SIG);
	current->blocked = oldset;
	RECALC_SIGPENDING();
	UNLOCK_SIGMASK(current,flags);
}

int _drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
			  Drbd_Packet_Cmd cmd, Drbd_Header *h,
			  size_t size, unsigned msg_flags)
{
	int sent,ok;

	ERR_IF(!h) return FALSE;
	ERR_IF(!size) return FALSE;

	h->magic   = BE_DRBD_MAGIC;
	h->command = cpu_to_be16(cmd);
	h->length  = cpu_to_be16(size-sizeof(Drbd_Header));

	dump_packet(mdev,sock,0,(void*)h, __FILE__, __LINE__);
	sent = drbd_send(mdev,sock,h,size,msg_flags);

	ok = ( sent == size );
	if(!ok) {
		ERR("short sent %s size=%d sent=%d\n",
		    cmdname(cmd), (int)size, sent);
	}
	return ok;
}

int drbd_send_cmd(drbd_dev *mdev, struct socket *sock,
		  Drbd_Packet_Cmd cmd, Drbd_Header* h, size_t size)
{
	int ok;
	sigset_t old_blocked;

	if (sock == mdev->data.socket) {
		down(&mdev->data.mutex);
		spin_lock(&mdev->send_task_lock);
		mdev->send_task=current;
		spin_unlock(&mdev->send_task_lock);
	} else
		down(&mdev->meta.mutex);

	old_blocked = drbd_block_all_signals();
	ok = _drbd_send_cmd(mdev,sock,cmd,h,size,0);
	restore_old_sigset(old_blocked);

	if (sock == mdev->data.socket) {
		spin_lock(&mdev->send_task_lock);
		mdev->send_task=NULL;
		spin_unlock(&mdev->send_task_lock);
		up(&mdev->data.mutex);
	} else
		up(&mdev->meta.mutex);
	return ok;
}

int drbd_send_cmd2(drbd_dev *mdev, Drbd_Packet_Cmd cmd, char* data,
		   size_t size)
{
	sigset_t old_blocked;
	Drbd_Header h;
	int ok;

	h.magic   = BE_DRBD_MAGIC;
	h.command = cpu_to_be16(cmd);
	h.length  = cpu_to_be16(size);

	down(&mdev->data.mutex);
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	old_blocked = drbd_block_all_signals();

	ok = ( sizeof(h) == drbd_send(mdev,mdev->data.socket,&h,sizeof(h),0) );
	ok = ok && ( size == drbd_send(mdev,mdev->data.socket,data,size,0) );

	restore_old_sigset(old_blocked);

	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);
	up(&mdev->data.mutex);

	return ok;
}

int drbd_send_sync_param(drbd_dev *mdev, struct syncer_config *sc)
{
	Drbd_SyncParam_Packet p;

	p.rate      = cpu_to_be32(sc->rate);
	p.use_csums = cpu_to_be32(sc->use_csums);
	p.skip      = cpu_to_be32(sc->skip);
	p.after     = cpu_to_be32(sc->after);

	return drbd_send_cmd(mdev,mdev->data.socket,SyncParam,(Drbd_Header*)&p,sizeof(p));
}

int drbd_send_protocol(drbd_dev *mdev)
{
	Drbd_Protocol_Packet p;

	p.protocol = cpu_to_be32(mdev->net_conf->wire_protocol);

	return drbd_send_cmd(mdev,mdev->data.socket,ReportProtocol,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_uuids(drbd_dev *mdev)
{
	Drbd_GenCnt_Packet p;
	int i;

	for (i = Current; i < UUID_SIZE; i++) {
		p.uuid[i] = cpu_to_be64(mdev->bc->md.uuid[i]);
	}

	p.uuid[UUID_SIZE] = cpu_to_be64(drbd_bm_total_weight(mdev));
	p.uuid[UUID_FLAGS] = cpu_to_be64(mdev->net_conf->want_lose);

	return drbd_send_cmd(mdev,mdev->data.socket,ReportUUIDs,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_sync_uuid(drbd_dev *mdev, u64 val)
{
	Drbd_SyncUUID_Packet p;

	p.uuid = cpu_to_be64(val);

	return drbd_send_cmd(mdev,mdev->data.socket,ReportSyncUUID,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_sizes(drbd_dev *mdev)
{
	Drbd_Sizes_Packet p;
	sector_t d_size;
	int ok;

	if(inc_md_only(mdev,Attaching)) {
		D_ASSERT(mdev->bc->backing_bdev);
		d_size = drbd_get_max_capacity(mdev->bc);
		p.u_size = cpu_to_be64(mdev->bc->u_size);
		dec_local(mdev);
	} else d_size = 0;

	p.d_size = cpu_to_be64(d_size);
	p.c_size = cpu_to_be64(drbd_get_capacity(mdev->this_bdev));
	p.max_segment_size = cpu_to_be32(mdev->rq_queue->max_segment_size);
	p.queue_order_type = cpu_to_be32(drbd_queue_order_type(mdev));

	ok = drbd_send_cmd(mdev,mdev->data.socket,ReportSizes,
			   (Drbd_Header*)&p,sizeof(p));
	return ok;
}

int drbd_send_discard(drbd_dev *mdev, drbd_request_t *req)
{
	Drbd_Discard_Packet p;

	p.block_id = (unsigned long)req;
	p.seq_num  = cpu_to_be32(req->seq_num);

	return drbd_send_cmd(mdev,mdev->meta.socket,DiscardNote,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_state(drbd_dev *mdev)
{
	Drbd_State_Packet p;

	p.state    = cpu_to_be32(mdev->state.i);

	return drbd_send_cmd(mdev,mdev->data.socket,ReportState,
			     (Drbd_Header*)&p,sizeof(p));
}

STATIC int drbd_send_state_req(drbd_dev *mdev, drbd_state_t mask, drbd_state_t val)
{
	Drbd_Req_State_Packet p;

	p.mask    = cpu_to_be32(mask.i);
	p.val     = cpu_to_be32(val.i);

	return drbd_send_cmd(mdev,mdev->data.socket,StateChgRequest,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_sr_reply(drbd_dev *mdev, int retcode)
{
	Drbd_RqS_Reply_Packet p;

	p.retcode    = cpu_to_be32(retcode);

	return drbd_send_cmd(mdev,mdev->meta.socket,StateChgReply,
			     (Drbd_Header*)&p,sizeof(p));
}


/* See the comment at receive_bitmap() */
int _drbd_send_bitmap(drbd_dev *mdev)
{
	int want;
	int ok=TRUE, bm_i=0;
	size_t bm_words, num_words;
	unsigned long *buffer;
	Drbd_Header *p;

	ERR_IF(!mdev->bitmap) return FALSE;

	bm_words = drbd_bm_words(mdev);
	p  = vmalloc(PAGE_SIZE); // sleeps. cannot fail.
	buffer = (unsigned long*)p->payload;

	if (drbd_md_test_flag(mdev->bc,MDF_FullSync)) {
		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);
		if (unlikely(mdev->state.disk <= Failed )) {
			/* write_bm did fail! panic.
			 * FIXME can we do something better than panic?
			 */
			drbd_panic("Failed to write bitmap to disk\n!");
			ok = FALSE;
			goto out;
		}
		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);
	}

	/*
	 * maybe TODO use some simple compression scheme, nowadays there are
	 * some such algorithms in the kernel anyways.
	 */
	do {
		num_words = min_t(size_t, BM_PACKET_WORDS, bm_words-bm_i );
		want = num_words * sizeof(long);
		if (want) {
			drbd_bm_get_lel(mdev, bm_i, num_words, buffer);
		}
		ok = _drbd_send_cmd(mdev,mdev->data.socket,ReportBitMap,
				   p, sizeof(*p) + want, 0);
		bm_i += num_words;
	} while (ok && want);

  out:
	vfree(p);
	return ok;
}

int drbd_send_bitmap(drbd_dev *mdev)
{
	int ok;

	down(&mdev->data.mutex);
	ok=_drbd_send_bitmap(mdev);
	up(&mdev->data.mutex);
	return ok;
}

int _drbd_send_barrier(drbd_dev *mdev)
{
	int ok;
	Drbd_Barrier_Packet p;

	/* printk(KERN_DEBUG DEVICE_NAME": issuing a barrier\n"); */
	/* tl_add_barrier() must be called with the sock_mutex aquired */
	p.barrier=tl_add_barrier(mdev);

	inc_ap_pending(mdev);
	ok = _drbd_send_cmd(mdev,mdev->data.socket,Barrier,(Drbd_Header*)&p,sizeof(p),0);

//	if (!ok) dec_ap_pending(mdev); // is done in tl_clear()
	return ok;
}

int drbd_send_b_ack(drbd_dev *mdev, u32 barrier_nr,u32 set_size)
{
	int ok;
	Drbd_BarrierAck_Packet p;

	p.barrier  = barrier_nr;
	p.set_size = cpu_to_be32(set_size);

	ok = drbd_send_cmd(mdev,mdev->meta.socket,BarrierAck,(Drbd_Header*)&p,sizeof(p));
	return ok;
}


int drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd, struct Tl_epoch_entry *e)
{
	int ok;
	Drbd_BlockAck_Packet p;

	p.sector   = cpu_to_be64(drbd_ee_get_sector(e));
	p.block_id = e->block_id;
	p.blksize  = cpu_to_be32(drbd_ee_get_size(e));
/*
 * FIXME kernel source <= 2.6.8 don't have atomic_add_return!
 */
#if 0
#warning "YES I KNOW. JUST SO IT COMPILES NOW."
	atomic_inc(&mdev->packet_seq);
	p.seq_num = atomic_read(&mdev->packet_seq);
#else
	p.seq_num  = cpu_to_be32(atomic_add_return(1,&mdev->packet_seq));
#endif

	if (!mdev->meta.socket || mdev->state.conn < Connected) return FALSE;
	ok=drbd_send_cmd(mdev,mdev->meta.socket,cmd,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

int drbd_send_drequest(drbd_dev *mdev, int cmd,
		       sector_t sector,int size, u64 block_id)
{
	int ok;
	Drbd_BlockRequest_Packet p;

	p.sector   = cpu_to_be64(sector);
	p.block_id = block_id;
	p.blksize  = cpu_to_be32(size);

	ok = drbd_send_cmd(mdev,mdev->data.socket,cmd,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

/* called on sndtimeo
 * returns FALSE if we should retry,
 * TRUE if we think connection is dead
 */
STATIC int we_should_drop_the_connection(drbd_dev *mdev, struct socket *sock)
{
	int drop_it;
	// long elapsed = (long)(jiffies - mdev->last_received);
	// DUMPLU(elapsed); // elapsed ignored for now.

	drop_it =   mdev->meta.socket == sock
		|| !mdev->asender.task
		|| get_t_state(&mdev->asender) != Running
		|| (volatile int)mdev->state.conn < Connected;

	if (drop_it)
		return TRUE;

	drop_it = !--mdev->ko_count;
	if ( !drop_it ) {
		ERR("[%s/%d] sock_sendmsg time expired, ko = %u\n",
		       current->comm, current->pid, mdev->ko_count);
		request_ping(mdev);
	}

	return drop_it; /* && (mdev->state == Primary) */;
}

/* The idea of sendpage seems to be to put some kind of reference
   to the page into the skb, and to hand it over to the NIC. In
   this process get_page() gets called.

   As soon as the page was really sent over the network put_page()
   gets called by some part of the network layer. [ NIC driver? ]

   [ get_page() / put_page() increment/decrement the count. If count
     reaches 0 the page will be freed. ]

   This works nicely with pages from FSs.
   But this means that in protocol A we might signal IO completion too early !

   In order not to corrupt data during a resync we must make sure
   that we do not reuse our own buffer pages (EEs) to early, therefore
   we have the net_ee list.

   XFS seems to have problems, still, it submits pages with page_count == 0!
   As a workaround, we disable sendpage on pages with page_count == 0 or PageSlab.
*/
int _drbd_no_send_page(drbd_dev *mdev, struct page *page,
                   int offset, size_t size)
{
       int ret;
       ret = drbd_send(mdev, mdev->data.socket, kmap(page) + offset, size, 0);
       kunmap(page);
       return ret;
}

int _drbd_send_page(drbd_dev *mdev, struct page *page,
		    int offset, size_t size)
{
	mm_segment_t oldfs = get_fs();
	int sent,ok;
	int len   = size;

#ifdef SHOW_SENDPAGE_USAGE
	unsigned long now = jiffies;
	static unsigned long total = 0;
	static unsigned long fallback = 0;
	static unsigned long last_rep = 0;

	/* report statistics every hour,
	 * if we had at least one fallback.
	 */
	++total;
	if (fallback && time_before(last_rep+3600*HZ, now)) {
		last_rep = now;
		printk(KERN_INFO DEVICE_NAME
		       ": sendpage() omitted: %lu/%lu\n", fallback, total);
	}
#endif


	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	/* PARANOIA. if this ever triggers,
	 * something in the layers above us is really kaputt.
	 *one roundtrip later:
	 * doh. it triggered. so XFS _IS_ really kaputt ...
	 * oh well...
	 */
	if ( (page_count(page) < 1) || PageSlab(page) ) {
		/* e.g. XFS meta- & log-data is in slab pages, which have a
		 * page_count of 0 and/or have PageSlab() set...
		 */
#ifdef SHOW_SENDPAGE_USAGE
		++fallback;
#endif
		sent =  _drbd_no_send_page(mdev, page, offset, size);
		if (likely(sent > 0)) len -= sent;
		goto out;
	}

	set_fs(KERNEL_DS);
	do {
		sent = mdev->data.socket->ops->sendpage(mdev->data.socket,page,
							offset,len,
							MSG_NOSIGNAL);
		if (sent == -EAGAIN) {
			if (we_should_drop_the_connection(mdev,
							  mdev->data.socket))
				break;
			else
				continue;
		}
		if (sent <= 0) {
			WARN("%s: size=%d len=%d sent=%d\n",
			     __func__,(int)size,len,sent);
			break;
		}
		len    -= sent;
		offset += sent;
		// FIXME test "last_received" ...
	} while(len > 0 /* THINK && mdev->cstate >= Connected*/);
	set_fs(oldfs);

  out:
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);

	ok = (len == 0);
	if (likely(ok))
		mdev->send_cnt += size>>9;
	return ok;
}

STATIC int _drbd_send_zc_bio(drbd_dev *mdev, struct bio *bio)
{
	struct bio_vec *bvec;
	int i;
	__bio_for_each_segment(bvec, bio, i, 0) {
		if (! _drbd_send_page(mdev, bvec->bv_page, bvec->bv_offset,
				      bvec->bv_len) ) {
			return 0;
		}
	}

	return 1;
}

/* Used to send write requests
 * Primary -> Peer	(Data)
 */
int drbd_send_dblock(drbd_dev *mdev, drbd_request_t *req)
{
	int ok=1;
	sigset_t old_blocked;
	Drbd_Data_Packet p;
	unsigned int dp_flags=0;

	/* About tl_add():
	1. This must be within the semaphor,
	   to ensure right order in tl_ data structure and to
	   ensure right order of packets on the write
	2. This must happen before sending, otherwise we might
	   get in the BlockAck packet before we have it on the
	   tl_ datastructure (=> We would want to remove it before it
	   is there!)
	3. Q: Why can we add it to tl_ even when drbd_send() might fail ?
	      There could be a tl_cancel() to remove it within the semaphore!
	   A: If drbd_send fails, we will lose the connection. Then
	      tl_cear() will simulate a RQ_DRBD_SEND and set it out of sync
	      for everything in the data structure.
	*/

	/* Still called directly by drbd_make_request,
	 * so all sorts of processes may end up here.
	 * They may be interrupted by DRBD_SIG in response to
	 * ioctl or some other "connection lost" event.
	 * This is not propagated.
	 */

	old_blocked = drbd_block_all_signals();
	down(&mdev->data.mutex);
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	if(test_and_clear_bit(ISSUE_BARRIER,&mdev->flags))
		ok = _drbd_send_barrier(mdev);
	if(ok) {
		if (mdev->net_conf->two_primaries) {
			if(ee_have_write(mdev,req)) {
				ok=-1;
				goto out;
			}
		} else {
			tl_add(mdev,req);
		}

		p.head.magic   = BE_DRBD_MAGIC;
		p.head.command = cpu_to_be16(Data);
		p.head.length  = cpu_to_be16( sizeof(p)-sizeof(Drbd_Header)
					      + drbd_req_get_size(req) );

		p.sector   = cpu_to_be64(drbd_req_get_sector(req));
		p.block_id = (unsigned long)req;
#if 0
#warning "YES I KNOW. JUST SO IT COMPILES NOW."
		atomic_inc(&mdev->packet_seq);
		p.seq_num = atomic_read(&mdev->packet_seq);
#else
		p.seq_num  = cpu_to_be32( req->seq_num =
				     atomic_add_return(1,&mdev->packet_seq) );
#endif
		if(req->master_bio->bi_rw & BIO_RW_BARRIER) {
			dp_flags = DP_HARDBARRIER;
		}
		p.dp_flags = cpu_to_be32(dp_flags);
		dump_packet(mdev,mdev->data.socket,0,(void*)&p, __FILE__, __LINE__);
		set_bit(UNPLUG_REMOTE,&mdev->flags);
		ok = sizeof(p) == drbd_send(mdev,mdev->data.socket,&p,sizeof(p),MSG_MORE);
		if(ok) {
			if(mdev->net_conf->wire_protocol == DRBD_PROT_A) {
				ok = _drbd_send_bio(mdev,drbd_req_private_bio(req));
			} else {
				ok = _drbd_send_zc_bio(mdev,drbd_req_private_bio(req));
			}
		}
		if(!ok) tl_cancel(mdev,req);
	}
	if (!ok) {
		drbd_set_out_of_sync(mdev,
				     drbd_req_get_sector(req),
				     drbd_req_get_size(req));
		drbd_end_req(req,RQ_DRBD_SENT,ERF_NOTLD|1,
			     drbd_req_get_sector(req));
	}
 out:
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);

	up(&mdev->data.mutex);
	restore_old_sigset(old_blocked);
	return ok;
}

/* answer packet, used to send data back for read requests:
 *  Peer       -> (diskless) Primary   (DataReply)
 *  SyncSource -> SyncTarget         (RSDataReply)
 */
int drbd_send_block(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
		    struct Tl_epoch_entry *e)
{
	int ok;
	sigset_t old_blocked;
	Drbd_Data_Packet p;

	p.head.magic   = BE_DRBD_MAGIC;
	p.head.command = cpu_to_be16(cmd);
	p.head.length  = cpu_to_be16( sizeof(p)-sizeof(Drbd_Header)
				     + drbd_ee_get_size(e) );

	p.sector   = cpu_to_be64(drbd_ee_get_sector(e));
	p.block_id = e->block_id;
	/* p.seq_num  = 0;    No sequence numbers here.. */

	/* Only called by our kernel thread.
	 * This one may be interupted by DRBD_SIG and/or DRBD_SIGKILL
	 * in response to ioctl or module unload.
	 */
	old_blocked = drbd_block_all_signals();
	down(&mdev->data.mutex);
	spin_lock(&mdev->send_task_lock);
	mdev->send_task=current;
	spin_unlock(&mdev->send_task_lock);

	dump_packet(mdev,mdev->data.socket,0,(void*)&p, __FILE__, __LINE__);
	ok = sizeof(p) == drbd_send(mdev,mdev->data.socket,&p,sizeof(p),MSG_MORE);
	if (ok) ok = _drbd_send_zc_bio(mdev,e->private_bio);

	spin_lock(&mdev->send_task_lock);
	mdev->send_task=NULL;
	spin_unlock(&mdev->send_task_lock);
	up(&mdev->data.mutex);
	restore_old_sigset(old_blocked);
	return ok;
}

/*
  drbd_send distinguishes two cases:

  Packets sent via the data socket "sock"
  and packets sent via the meta data socket "msock"

		    sock                      msock
  -----------------+-------------------------+------------------------------
  timeout           conf.timeout / 2          conf.timeout / 2
  timeout action    send a ping via msock     Abort communication
					      and close all sockets
*/

/*
 * you should have down()ed the appropriate [m]sock_mutex elsewhere!
 */
int drbd_send(drbd_dev *mdev, struct socket *sock,
	      void* buf, size_t size, unsigned msg_flags)
{
#if !HAVE_KERNEL_SENDMSG
	mm_segment_t oldfs;
	struct iovec iov;
#else
	struct kvec iov;
#endif
	struct msghdr msg;
	int rv,sent=0;

	if (!sock) return -1000;

	// THINK  if (signal_pending) return ... ?

	iov.iov_base = buf;
	iov.iov_len  = size;

	msg.msg_name       = 0;
	msg.msg_namelen    = 0;
#if !HAVE_KERNEL_SENDMSG
	msg.msg_iov        = &iov;
	msg.msg_iovlen     = 1;
#endif
	msg.msg_control    = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags      = msg_flags | MSG_NOSIGNAL;

#if !HAVE_KERNEL_SENDMSG
	oldfs = get_fs();
	set_fs(KERNEL_DS);
#endif

	if (sock == mdev->data.socket)
		mdev->ko_count = mdev->net_conf->ko_count;
	do {
		/* STRANGE
		 * tcp_sendmsg does _not_ use its size parameter at all ?
		 *
		 * -EAGAIN on timeout, -EINTR on signal.
		 */
/* THINK
 * do we need to block DRBD_SIG if sock == &meta.socket ??
 * otherwise wake_asender() might interrupt some send_*Ack !
 */
#if !HAVE_KERNEL_SENDMSG
		rv = sock_sendmsg(sock, &msg, iov.iov_len );
#else
		rv = kernel_sendmsg(sock, &msg, &iov, 1, size);
#endif
		if (rv == -EAGAIN) {
			if (we_should_drop_the_connection(mdev,sock))
				break;
			else
				continue;
		}
		D_ASSERT(rv != 0);
		if (rv == -EINTR ) {
#if 0
			/* FIXME this happens all the time.
			 * we don't care for now!
			 * eventually this should be sorted out be the proper
			 * use of the SIGNAL_ASENDER bit... */
			if (DRBD_ratelimit(5*HZ,5)) {
				DBG("Got a signal in drbd_send(,%c,)!\n",
				    sock == mdev->meta.socket ? 'm' : 's');
				// dump_stack();
			}
#endif
			flush_signals(current);
			rv = 0;
		}
		if (rv < 0) break;
		sent += rv;
		iov.iov_base += rv;
		iov.iov_len  -= rv;
	} while(sent < size);

#if !HAVE_KERNEL_SENDMSG
	set_fs(oldfs);
#endif

	if (rv <= 0) {
		if (rv != -EAGAIN) {
			ERR("%s_sendmsg returned %d\n",
			    sock == mdev->meta.socket ? "msock" : "sock",
			    rv);
			drbd_force_state(mdev, NS(conn,BrokenPipe));
		} else
			drbd_force_state(mdev, NS(conn,Timeout));
		drbd_thread_restart_nowait(&mdev->receiver);
	}

	return sent;
}

STATIC int drbd_open(struct inode *inode, struct file *file)
{
	int minor;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;

	if (file->f_mode & FMODE_WRITE) {
		if( drbd_conf[minor].state.role == Secondary) {
			return -EROFS;
		}
		set_bit(WRITER_PRESENT, &drbd_conf[minor].flags);
	}

	drbd_conf[minor].open_cnt++;

	return 0;
}

STATIC int drbd_close(struct inode *inode, struct file *file)
{
	/* do not use *file (May be NULL, in case of a unmount :-) */
	int minor;

	minor = MINOR(inode->i_rdev);
	if(minor >= minor_count) return -ENODEV;

	/*
	printk(KERN_ERR DEVICE_NAME ": close(inode=%p,file=%p)"
	       "current=%p,minor=%d,wc=%d\n", inode, file, current, minor,
	       inode->i_writecount);
	*/

	if (--drbd_conf[minor].open_cnt == 0) {
		clear_bit(WRITER_PRESENT, &drbd_conf[minor].flags);
	}

	return 0;
}

STATIC void drbd_unplug_fn(request_queue_t *q)
{
	drbd_dev *mdev = q->queuedata;

	/* unplug FIRST */
	spin_lock_irq(q->queue_lock);
	blk_remove_plug(q);
	spin_unlock_irq(q->queue_lock);

	/* only if connected */
	spin_lock_irq(&mdev->req_lock);
	if (mdev->state.pdsk >= Inconsistent) /* implies cs >= Connected */ {
		D_ASSERT(mdev->state.role == Primary);
		if (test_and_clear_bit(UNPLUG_REMOTE,&mdev->flags)) {
			/* add to the front of the data.work queue,
			 * unless already queued.
			 * XXX this might be a good addition to drbd_queue_work
			 * anyways, to detect "double queuing" ... */
			if (list_empty(&mdev->unplug_work.list))
				_drbd_queue_work_front(&mdev->data.work,&mdev->unplug_work);
		}
	}
	spin_unlock_irq(&mdev->req_lock);

	if(mdev->state.disk >= Inconsistent) drbd_kick_lo(mdev);
}

void drbd_set_defaults(drbd_dev *mdev)
{
	mdev->sync_conf.after      = -1;
	mdev->sync_conf.rate       = 250;
	mdev->sync_conf.al_extents = 127; // 512 MB active set
	mdev->state = (drbd_state_t){ { Secondary,
					Unknown,
					StandAlone,
					Diskless,
					DUnknown,
					0 } };
}

void drbd_init_set_defaults(drbd_dev *mdev)
{
	// the memset(,0,) did most of this
	// note: only assignments, no allocation in here

#ifdef PARANOIA
	SET_MDEV_MAGIC(mdev);
#endif

	drbd_set_defaults(mdev);

	atomic_set(&mdev->ap_bio_cnt,0);
	atomic_set(&mdev->ap_pending_cnt,0);
	atomic_set(&mdev->rs_pending_cnt,0);
	atomic_set(&mdev->unacked_cnt,0);
	atomic_set(&mdev->local_cnt,0);
	atomic_set(&mdev->net_cnt,0);
	atomic_set(&mdev->resync_locked,0);
	atomic_set(&mdev->packet_seq,0);
	atomic_set(&mdev->pp_in_use, 0);

	init_MUTEX(&mdev->md_io_mutex);
	init_MUTEX(&mdev->data.mutex);
	init_MUTEX(&mdev->meta.mutex);
	sema_init(&mdev->data.work.s,0);
	sema_init(&mdev->meta.work.s,0);

	spin_lock_init(&mdev->al_lock);
	spin_lock_init(&mdev->tl_lock);
	spin_lock_init(&mdev->ee_lock);
	spin_lock_init(&mdev->req_lock);
	spin_lock_init(&mdev->pr_lock);
	spin_lock_init(&mdev->send_task_lock);
	spin_lock_init(&mdev->peer_seq_lock);

	INIT_LIST_HEAD(&mdev->active_ee);
	INIT_LIST_HEAD(&mdev->sync_ee);
	INIT_LIST_HEAD(&mdev->done_ee);
	INIT_LIST_HEAD(&mdev->read_ee);
	INIT_LIST_HEAD(&mdev->net_ee);
	INIT_LIST_HEAD(&mdev->resync_reads);
	INIT_LIST_HEAD(&mdev->data.work.q);
	INIT_LIST_HEAD(&mdev->meta.work.q);
	INIT_LIST_HEAD(&mdev->resync_work.list);
	INIT_LIST_HEAD(&mdev->barrier_work.list);
	INIT_LIST_HEAD(&mdev->unplug_work.list);
	INIT_LIST_HEAD(&mdev->md_sync_work.list);
	INIT_LIST_HEAD(&mdev->discard);
	mdev->resync_work.cb  = w_resync_inactive;
	mdev->barrier_work.cb = w_try_send_barrier;
	mdev->unplug_work.cb  = w_send_write_hint;
	mdev->md_sync_work.cb = w_md_sync;
	init_timer(&mdev->resync_timer);
	init_timer(&mdev->md_sync_timer);
	mdev->resync_timer.function = resync_timer_fn;
	mdev->resync_timer.data = (unsigned long) mdev;
	mdev->md_sync_timer.function = md_sync_timer_fn;
	mdev->md_sync_timer.data = (unsigned long) mdev;

	init_waitqueue_head(&mdev->cstate_wait);
	init_waitqueue_head(&mdev->ee_wait);
	init_waitqueue_head(&mdev->al_wait);

	drbd_thread_init(mdev, &mdev->receiver, drbdd_init);
	drbd_thread_init(mdev, &mdev->worker, drbd_worker);
	drbd_thread_init(mdev, &mdev->asender, drbd_asender);

#ifdef __arch_um__
	INFO("mdev = 0x%p\n",mdev);
#endif
}

void drbd_mdev_cleanup(drbd_dev *mdev)
{
	/* I'd like to cleanup completely, and memset(,0,) it.
	 * but I'd have to reinit it.
	 * FIXME: do the right thing...
	 */

	/* list of things that may still
	 * hold data of the previous config

	 * act_log        ** re-initialized in set_disk
	 * on_io_error

	 * al_tr_cycle    ** re-initialized in ... FIXME??
	 * al_tr_number
	 * al_tr_pos

	 * backing_bdev   ** re-initialized in drbd_free_ll_dev
	 * lo_file
	 * md_bdev
	 * md_file
	 * md_index

	 * ko_count       ** re-initialized in set_net

	 * last_received  ** currently ignored

	 * mbds_id        ** re-initialized in ... FIXME??

	 * resync         ** re-initialized in ... FIXME??

	*** no re-init necessary (?) ***
	 * md_io_page
	 * this_bdev

	 * vdisk             ?

	 * rq_queue       ** FIXME ASSERT ??
	 * newest_barrier
	 * oldest_barrier
	 */

	drbd_thread_stop(&mdev->worker);

	/* no need to lock it, I'm the only thread alive */
	if ( mdev->epoch_size !=  0)
		ERR("epoch_size:%d\n",mdev->epoch_size);
#define ZAP(x) memset(&x,0,sizeof(x))
	ZAP(mdev->sync_conf);
	// ZAP(mdev->data); Not yet!
	// ZAP(mdev->meta); Not yet!
#undef ZAP
	mdev->al_writ_cnt  =
	mdev->bm_writ_cnt  =
	mdev->read_cnt     =
	mdev->recv_cnt     =
	mdev->send_cnt     =
	mdev->writ_cnt     =
	mdev->p_size       =
	mdev->rs_start     =
	mdev->rs_total     =
	mdev->rs_mark_left =
	mdev->rs_mark_time = 0;
	mdev->net_conf     = NULL;
	mdev->send_task    = NULL;
	drbd_set_my_capacity(mdev,0);
	drbd_bm_resize(mdev,0);

	// just in case
	drbd_free_resources(mdev);

	/*
	 * currently we drbd_init_ee only on module load, so
	 * we may do drbd_release_ee only on module unload!
	 * drbd_release_ee(&mdev->free_ee);
	 * D_ASSERT(list_emptry(&mdev->free_ee));
	 *
	 */
	D_ASSERT(list_empty(&mdev->active_ee));
	D_ASSERT(list_empty(&mdev->sync_ee));
	D_ASSERT(list_empty(&mdev->done_ee));
	D_ASSERT(list_empty(&mdev->read_ee));
	D_ASSERT(list_empty(&mdev->net_ee));
	D_ASSERT(list_empty(&mdev->resync_reads));
	D_ASSERT(list_empty(&mdev->data.work.q));
	D_ASSERT(list_empty(&mdev->meta.work.q));
	D_ASSERT(list_empty(&mdev->resync_work.list));
	D_ASSERT(list_empty(&mdev->barrier_work.list));
	D_ASSERT(list_empty(&mdev->unplug_work.list));

	drbd_set_defaults(mdev);
}


void drbd_destroy_mempools(void)
{
	struct page *page;

	while(drbd_pp_pool) {
		page = drbd_pp_pool;
		drbd_pp_pool = (struct page*)page->U_PRIVATE;
		__free_page(page);
		drbd_pp_vacant--;
	}

	/* D_ASSERT(atomic_read(&drbd_pp_vacant)==0); */

	if (drbd_ee_mempool)
		mempool_destroy(drbd_ee_mempool);
	if (drbd_request_mempool)
		mempool_destroy(drbd_request_mempool);
	if (drbd_ee_cache && kmem_cache_destroy(drbd_ee_cache))
		printk(KERN_ERR DEVICE_NAME
		       ": kmem_cache_destroy(drbd_ee_cache) FAILED\n");
	if (drbd_request_cache && kmem_cache_destroy(drbd_request_cache))
		printk(KERN_ERR DEVICE_NAME
		       ": kmem_cache_destroy(drbd_request_cache) FAILED\n");
	// FIXME what can we do if we fail to destroy them?

	drbd_ee_mempool      = NULL;
	drbd_request_mempool = NULL;
	drbd_ee_cache        = NULL;
	drbd_request_cache   = NULL;

	return;
}

int drbd_create_mempools(void)
{
	struct page *page;
	const int number = (DRBD_MAX_SEGMENT_SIZE/PAGE_SIZE) * minor_count;
	int i;

	// prepare our caches and mempools
	drbd_request_mempool = NULL;
	drbd_ee_cache        = NULL;
	drbd_request_cache   = NULL;
	drbd_pp_pool         = NULL;

	// caches
	drbd_request_cache = kmem_cache_create(
		"drbd_req_cache", sizeof(drbd_request_t),
		0, 0, NULL, NULL);
	if (drbd_request_cache == NULL)
		goto Enomem;

	drbd_ee_cache = kmem_cache_create(
		"drbd_ee_cache", sizeof(struct Tl_epoch_entry),
		0, 0, NULL, NULL);
	if (drbd_ee_cache == NULL)
		goto Enomem;

	// mempools
	drbd_request_mempool = mempool_create( number,
		mempool_alloc_slab, mempool_free_slab, drbd_request_cache);
	if (drbd_request_mempool == NULL)
		goto Enomem;

	drbd_ee_mempool = mempool_create( number,
		mempool_alloc_slab, mempool_free_slab, drbd_ee_cache);
	if (drbd_request_mempool == NULL)
		goto Enomem;

	// drbd's page pool
	spin_lock_init(&drbd_pp_lock);

	for (i=0;i< number;i++) {
		page = alloc_page(GFP_HIGHUSER);
		if(!page) goto Enomem;
		page->U_PRIVATE = (unsigned long)drbd_pp_pool;
		drbd_pp_pool = page;
	}
	drbd_pp_vacant = number;

	return 0;

  Enomem:
	drbd_destroy_mempools(); // in case we allocated some
	return -ENOMEM;
}

static int drbd_notify_sys(struct notifier_block *this, unsigned long code,
	void *unused)
{
	/* just so we have it.  you never know what interessting things we
	 * might want to do here some day...
	 */

	return NOTIFY_DONE;
}

static struct notifier_block drbd_notifier = {
	.notifier_call = drbd_notify_sys,
};


static void __exit drbd_cleanup(void)
{
	int i, rr;

	unregister_reboot_notifier(&drbd_notifier);

	if (drbd_conf) {
		for (i = 0; i < minor_count; i++) {
			drbd_dev    *mdev = drbd_conf + i;

			if (mdev) {
				down(&mdev->device_mutex);
				rr = Secondary;
				drbd_set_role(mdev,&rr);
				up(&mdev->device_mutex);
				drbd_sync_me(mdev);
				drbd_thread_stop(&mdev->receiver);
				drbd_thread_stop(&mdev->worker);
			}
		}

		if (drbd_proc)
			remove_proc_entry("drbd",&proc_root);
		i=minor_count;
		while (i--) {
			drbd_dev        *mdev  = drbd_conf+i;
			struct gendisk  **disk = &mdev->vdisk;
			request_queue_t **q    = &mdev->rq_queue;

			drbd_free_resources(mdev);

			if (*disk) {
				del_gendisk(*disk);
				put_disk(*disk);
				*disk = NULL;
			}
			if (*q) blk_put_queue(*q);
			*q = NULL;

			if (mdev->this_bdev->bd_holder == drbd_sec_holder) {
				mdev->this_bdev->bd_contains = mdev->this_bdev;
				bd_release(mdev->this_bdev);
			}
			if (mdev->this_bdev) bdput(mdev->this_bdev);

			tl_cleanup(mdev);
			if (mdev->bitmap) drbd_bm_cleanup(mdev);
			if (mdev->resync) lc_free(mdev->resync);

			rr = drbd_release_ee(mdev,&mdev->active_ee);
			if(rr) ERR("%d EEs in active list found!\n",rr);

			rr = drbd_release_ee(mdev,&mdev->sync_ee);
			if(rr) ERR("%d EEs in sync list found!\n",rr);

			rr = drbd_release_ee(mdev,&mdev->read_ee);
			if(rr) ERR("%d EEs in read list found!\n",rr);

			rr = drbd_release_ee(mdev,&mdev->done_ee);
			if(rr) ERR("%d EEs in done list found!\n",rr);

			rr = drbd_release_ee(mdev,&mdev->net_ee);
			if(rr) ERR("%d EEs in net list found!\n",rr);

			ERR_IF (!list_empty(&mdev->data.work.q)) {
				struct list_head *lp;
				list_for_each(lp,&mdev->data.work.q) {
					DUMPP(lp);
				}
			};

			if (mdev->md_io_page)
				__free_page(mdev->md_io_page);

			if (mdev->md_io_tmpp)
				__free_page(mdev->md_io_tmpp);

			if (mdev->act_log) lc_free(mdev->act_log);

			if(mdev->ee_hash) {
				kfree(mdev->ee_hash);
				mdev->ee_hash_s = 0;
			}
			if(mdev->app_reads_hash) {
				kfree(mdev->app_reads_hash);
				mdev->app_reads_hash = 0;
			}
			if ( mdev->p_uuid ) {
				kfree(mdev->p_uuid);
				mdev->p_uuid = NULL;
			}
		}
		drbd_destroy_mempools();
	}

#ifndef HAVE_COMPAT_IOCTL_MEMBER
#if defined(CONFIG_PPC64) || defined(CONFIG_SPARC64) || defined(CONFIG_X86_64)
	lock_kernel();
	unregister_ioctl32_conversion(DRBD_IOCTL_GET_VERSION);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_STATE);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_DISK_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_NET_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_NET);
	unregister_ioctl32_conversion(DRBD_IOCTL_GET_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_INVALIDATE);
	unregister_ioctl32_conversion(DRBD_IOCTL_INVALIDATE_REM);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_SYNC_CONFIG);
	unregister_ioctl32_conversion(DRBD_IOCTL_SET_DISK_SIZE);
	unregister_ioctl32_conversion(DRBD_IOCTL_WAIT_CONNECT);
	unregister_ioctl32_conversion(DRBD_IOCTL_WAIT_SYNC);
	unregister_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_DISK);
	unlock_kernel();
#endif
#endif
	kfree(drbd_conf);

	devfs_remove(drbd_devfs_name);

	if (unregister_blkdev(MAJOR_NR, DEVICE_NAME) != 0)
		printk(KERN_ERR DEVICE_NAME": unregister of device failed\n");

	printk(KERN_INFO DEVICE_NAME": module cleanup done.\n");
}

int __init drbd_init(void)
{
	int i,err;

#if 0
#warning "DEBUGGING"
/* I am too lazy to calculate this by hand	-lge
 */
#define SZO(x) printk(KERN_ERR "sizeof(" #x ") = %d\n", sizeof(x))
	SZO(struct Drbd_Conf);
	SZO(struct buffer_head);
	SZO(Drbd_Polymorph_Packet);
	SZO(struct drbd_socket);
	SZO(struct bm_extent);
	SZO(struct lc_element);
	SZO(struct semaphore);
	SZO(struct drbd_request);
	SZO(struct bio);
	SZO(wait_queue_head_t);
	SZO(spinlock_t);
	SZO(Drbd_Header);
	SZO(Drbd_HandShake_Packet);
	SZO(Drbd_Barrier_Packet);
	SZO(Drbd_BarrierAck_Packet);
	SZO(Drbd_SyncParam_Packet);
	SZO(Drbd06_Parameter_P);
	SZO(Drbd_Data_Packet);
	SZO(Drbd_BlockAck_Packet);
	printk(KERN_ERR "AL_EXTENTS_PT = %d\n",AL_EXTENTS_PT);
	printk(KERN_ERR "DRBD_MAX_SECTORS = %llu\n",DRBD_MAX_SECTORS);
	printk(KERN_ERR "DRBD_MAX_SECTORS_FLEX = %llu\n",DRBD_MAX_SECTORS_FLEX);
#define OOF(t,m) printk(KERN_ERR "offsetof("#t","#m") = %d\n", offsetof(t,m))
	OOF(struct Drbd_Conf,bitmap);
	//OOF(struct drbd_bitmap,bm_set);
	return -EBUSY;
#endif
#ifdef __arch_um__
	printk(KERN_INFO "drbd_module = 0x%p core = 0x%p\n",
	       THIS_MODULE,THIS_MODULE->module_core);
#endif

	if (sizeof(Drbd_HandShake_Packet) != 80) {
		printk(KERN_ERR DEVICE_NAME
		       ": never change the size or layout of the HandShake packet.\n");
		return -EINVAL;
	}

	if (1 > minor_count||minor_count > 255) {
		printk(KERN_ERR DEVICE_NAME
			": invalid minor_count (%d)\n",minor_count);
#ifdef MODULE
		return -EINVAL;
#else
		minor_count = 8;
#endif
	}

	err = register_blkdev(MAJOR_NR, DEVICE_NAME);
	if (err) {
		printk(KERN_ERR DEVICE_NAME
		       ": unable to register block device major %d\n",
		       MAJOR_NR);
		return err;
	}
	register_reboot_notifier(&drbd_notifier);

	drbd_devfs_name = (major_nr == NBD_MAJOR) ? "nbd" : "drbd";

	/*
	 * allocate all necessary structs
	 */
	err = -ENOMEM;

	init_waitqueue_head(&drbd_pp_wait);

	drbd_proc = NULL; // play safe for drbd_cleanup
	drbd_conf = kmalloc(sizeof(drbd_dev)*minor_count,GFP_KERNEL);
	if (likely(drbd_conf!=NULL))
		memset(drbd_conf,0,sizeof(drbd_dev)*minor_count);
	else goto Enomem;

	devfs_mk_dir(drbd_devfs_name);

	for (i = 0; i < minor_count; i++) {
		drbd_dev    *mdev = drbd_conf + i;
		struct gendisk         *disk;
		request_queue_t        *q;

		q = blk_alloc_queue(GFP_KERNEL);
		if (!q) goto Enomem;
		mdev->rq_queue = q;
		q->queuedata   = mdev;
		q->max_segment_size = DRBD_MAX_SEGMENT_SIZE;

		disk = alloc_disk(1);
		if (!disk) goto Enomem;
		mdev->vdisk = disk;

		set_disk_ro( disk, TRUE );

		disk->queue = q;
		disk->major = MAJOR_NR;
		disk->first_minor = i;
		disk->fops = &drbd_ops;
		sprintf(disk->disk_name, DEVICE_NAME "%d", i);
		sprintf(disk->devfs_name, "%s/%d", drbd_devfs_name, i);
		disk->private_data = mdev;
		add_disk(disk);

		mdev->this_bdev = bdget(MKDEV(MAJOR_NR,i));
		// we have no partitions. we contain only ourselves.
		mdev->this_bdev->bd_contains = mdev->this_bdev;
		if (bd_claim(mdev->this_bdev,drbd_sec_holder)) {
			// Initial we are Secondary -> should claim myself.
			WARN("Could not bd_claim() myself.");
		} else if (disable_bd_claim) {
			bd_release(mdev->this_bdev);
		}

		blk_queue_make_request(q, drbd_make_request_26);
		blk_queue_merge_bvec(q, drbd_merge_bvec);
		q->queue_lock = &mdev->req_lock; // needed since we use
		// plugging on a queue, that actually has no requests!
		q->unplug_fn = drbd_unplug_fn;
	}

	if ((err = drbd_create_mempools()))
		goto Enomem;

	for (i = 0; i < minor_count; i++) {
		drbd_dev    *mdev = &drbd_conf[i];
		struct page *page = alloc_page(GFP_KERNEL);

		drbd_init_set_defaults(mdev);

		if(!page) goto Enomem;
		mdev->md_io_page = page;

		if (drbd_bm_init(mdev)) goto Enomem;
		// no need to lock access, we are still initializing the module.
		init_MUTEX(&mdev->device_mutex);
		if (!tl_init(mdev)) goto Enomem;

		mdev->app_reads_hash=kmalloc(APP_R_HSIZE*sizeof(void*),
					     GFP_KERNEL);
		if (!mdev->app_reads_hash) goto Enomem;
		memset(mdev->app_reads_hash,0,APP_R_HSIZE*sizeof(void*));
	}

#if CONFIG_PROC_FS
	/*
	 * register with procfs
	 */
	drbd_proc = create_proc_entry("drbd",  S_IFREG | S_IRUGO , &proc_root);

	if (!drbd_proc)	{
		printk(KERN_ERR DEVICE_NAME": unable to register proc file\n");
		goto Enomem;
	}
	
	drbd_proc->proc_fops = &drbd_proc_fops;
	drbd_proc->owner = THIS_MODULE;
#else
# error "Currently drbd depends on the proc file system (CONFIG_PROC_FS)"
#endif

#ifndef HAVE_COMPAT_IOCTL_MEMBER
#if defined(CONFIG_PPC64) || defined(CONFIG_SPARC64) || defined(CONFIG_X86_64)
	// tell the kernel that we think our ioctls are 64bit clean
	lock_kernel();
	register_ioctl32_conversion(DRBD_IOCTL_GET_VERSION,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_STATE,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_DISK_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_NET_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_NET,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_GET_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_INVALIDATE,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_INVALIDATE_REM,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_SYNC_CONFIG,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_SET_DISK_SIZE,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_WAIT_CONNECT,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_WAIT_SYNC,NULL);
	register_ioctl32_conversion(DRBD_IOCTL_UNCONFIG_DISK,NULL);
	unlock_kernel();
#endif
#endif

	printk(KERN_INFO DEVICE_NAME ": initialised. "
	       "Version: " REL_VERSION " (api:%d/proto:%d)\n",
	       API_VERSION,PRO_VERSION);
	printk(KERN_INFO DEVICE_NAME ": %s\n", drbd_buildtag());
	printk(KERN_INFO DEVICE_NAME": registered as block device major %d\n", MAJOR_NR);

	return 0; // Success!

  Enomem:
	drbd_cleanup();
	if (err == -ENOMEM) // currently always the case
		printk(KERN_ERR DEVICE_NAME ": ran out of memory\n");
	else
		printk(KERN_ERR DEVICE_NAME ": initialization failure\n");
	return err;
}

void drbd_free_bc(struct drbd_backing_dev* bc)
{
	if(bc == NULL) return;

	bd_release(bc->backing_bdev);
	bd_release(bc->md_bdev);

	fput(bc->lo_file);
	fput(bc->md_file);

	kfree(bc);
}

void drbd_free_sock(drbd_dev *mdev)
{
	if (mdev->data.socket) {
		sock_release(mdev->data.socket);
		mdev->data.socket = 0;
	}
	if (mdev->meta.socket) {
		sock_release(mdev->meta.socket);
		mdev->meta.socket = 0;
	}
}


void drbd_free_resources(drbd_dev *mdev)
{
	if ( mdev->cram_hmac_tfm ) {
		crypto_free_tfm(mdev->cram_hmac_tfm);
		mdev->cram_hmac_tfm = NULL;
	}
	drbd_free_sock(mdev);
	drbd_free_bc(mdev->bc);
	mdev->bc=0;
}

/*********************************/
/* meta data management */

struct meta_data_on_disk {
	u64 la_size;           // last agreed size.
	u64 uuid[UUID_SIZE];   // UUIDs.
	u64 device_uuid;
	u64 reserved_u64_1;
	u32 flags;             // MDF
	u32 magic;
	u32 md_size_sect;
	u32 al_offset;         // offset to this block
	u32 al_nr_extents;     // important for restoring the AL
	      // `-- act_log->nr_elements <-- sync_conf.al_extents
	u32 bm_offset;         // offset to the bitmap, from here
	u32 bm_bytes_per_bit;  // BM_BLOCK_SIZE
	u32 reserved_u32[4];

} __attribute((packed));

/** 
 * drbd_md_sync:
 * Writes the meta data super block if the MD_DIRTY flag bit is set.
 */ 
void drbd_md_sync(drbd_dev *mdev)
{
	struct meta_data_on_disk * buffer;
	sector_t sector;
	int i;

	if (!test_and_clear_bit(MD_DIRTY,&mdev->flags)) return;
	del_timer(&mdev->md_sync_timer);
	INFO("Writing meta data super block now.\n");
	ERR_IF(!inc_md_only(mdev,Attaching)) return;

	down(&mdev->md_io_mutex);
	buffer = (struct meta_data_on_disk *)page_address(mdev->md_io_page);
	memset(buffer,0,512);

	buffer->la_size=cpu_to_be64(drbd_get_capacity(mdev->this_bdev));
	for (i = Current; i < UUID_SIZE; i++)
		buffer->uuid[i]=cpu_to_be64(mdev->bc->md.uuid[i]);
	buffer->flags = cpu_to_be32(mdev->bc->md.flags);
	buffer->magic = cpu_to_be32(DRBD_MD_MAGIC);

	buffer->md_size_sect  = cpu_to_be32(mdev->bc->md.md_size_sect);
	buffer->al_offset     = cpu_to_be32(mdev->bc->md.al_offset);
	buffer->al_nr_extents = cpu_to_be32(mdev->act_log->nr_elements);
	buffer->bm_bytes_per_bit = cpu_to_be32(BM_BLOCK_SIZE);
	buffer->device_uuid = cpu_to_be64(mdev->bc->md.device_uuid);

	buffer->bm_offset = cpu_to_be32(mdev->bc->md.bm_offset);

	D_ASSERT(drbd_md_ss__(mdev,mdev->bc) == mdev->bc->md.md_offset);
	sector = mdev->bc->md.md_offset;

#if 0
	/* FIXME sooner or later I'd like to use the MD_DIRTY flag everywhere,
	 * so we can avoid unneccessary md writes.
	 */
	ERR_IF (!test_bit(MD_DIRTY,&mdev->flags)) {
		dump_stack();
	}
#endif

	if (drbd_md_sync_page_io(mdev,mdev->bc,sector,WRITE)) {
		clear_bit(MD_DIRTY,&mdev->flags);
	} else {
		if (mdev->state.disk <= Failed) {
			/* this was a try anyways ... */
			ERR("meta data update failed!\n");
		} else {
			/* If we cannot write our meta data,
			 * but we are supposed to be able to,
			 * tough!
			 */
			drbd_panic("meta data update failed!\n");
		}
	}

	// Update mdev->bc->md.la_size_sect, since we updated it on metadata.
	mdev->bc->md.la_size_sect = drbd_get_capacity(mdev->this_bdev);

	up(&mdev->md_io_mutex);
	dec_local(mdev);
}

/** 
 * drbd_md_read:
 * @bdev: describes the backing storage and the meta-data storage
 * Reads the meta data from bdev. Return 0 (NoError) on success, and an 
 * enum ret_codes in case something goes wrong. 
 * Currently only: MDIOError, MDInvalid.
 */ 
int drbd_md_read(drbd_dev *mdev, struct drbd_backing_dev *bdev)
{
	struct meta_data_on_disk * buffer;
	int i,rv = NoError;

	if(!inc_md_only(mdev,Attaching)) return MDIOError;

	down(&mdev->md_io_mutex);
	buffer = (struct meta_data_on_disk *)page_address(mdev->md_io_page);

	if ( ! drbd_md_sync_page_io(mdev,bdev,bdev->md.md_offset,READ) ) {
		ERR("Error while reading metadata.\n");
		rv = MDIOError;
		goto err;
	}

	if(be32_to_cpu(buffer->magic) != DRBD_MD_MAGIC) {
		ERR("Error while reading metadata, magic not found.\n");
		rv = MDInvalid;
		goto err;
	}
	if (be32_to_cpu(buffer->al_offset) != bdev->md.al_offset) {
		ERR("unexpected al_offset: %d (expected %d)\n",
		    be32_to_cpu(buffer->al_offset), bdev->md.al_offset);
		rv = MDInvalid;
		goto err;
	}
	if (be32_to_cpu(buffer->bm_offset) != bdev->md.bm_offset) {
		ERR("unexpected bm_offset: %d (expected %d)\n",
		    be32_to_cpu(buffer->bm_offset), bdev->md.bm_offset);
		rv = MDInvalid;
		goto err;
	}
	if (be32_to_cpu(buffer->md_size_sect) != bdev->md.md_size_sect) {
		ERR("unexpected md_size: %u (expected %u)\n",
		    be32_to_cpu(buffer->md_size_sect), bdev->md.md_size_sect);
		rv = MDInvalid;
		goto err;
	}

	if (be32_to_cpu(buffer->bm_bytes_per_bit) != BM_BLOCK_SIZE) {
		ERR("unexpected bm_bytes_per_bit: %u (expected %u)\n",
		    be32_to_cpu(buffer->bm_bytes_per_bit), BM_BLOCK_SIZE);
		rv = MDInvalid;
		goto err;
	}

	bdev->md.la_size_sect = be64_to_cpu(buffer->la_size);
	for (i = Current; i < UUID_SIZE; i++)
		bdev->md.uuid[i]=be64_to_cpu(buffer->uuid[i]);
	bdev->md.flags = be32_to_cpu(buffer->flags);
	mdev->sync_conf.al_extents = be32_to_cpu(buffer->al_nr_extents);
	bdev->md.device_uuid = be64_to_cpu(buffer->device_uuid);

	if (mdev->sync_conf.al_extents < 7)
		mdev->sync_conf.al_extents = 127;
		/* FIXME if this ever happens when reading meta data,
		 * it possibly screws up reading of the activity log?
		 */

 err:
	up(&mdev->md_io_mutex);
	dec_local(mdev);

	return rv;
}

/** 
 * drbd_md_mark_dirty:
 * Call this function if you change enything that should be written to
 * the meta-data super block. This function sets MD_DIRTY, and starts a 
 * timer that ensures that within five seconds you have to call drbd_md_sync().
 */
void drbd_md_mark_dirty(drbd_dev *mdev)
{
	set_bit(MD_DIRTY,&mdev->flags);
	mod_timer(&mdev->md_sync_timer,jiffies + 5*HZ );
}

static void drbd_uuid_move_history(drbd_dev *mdev)
{
	int i;

	for ( i=History_start ; i<History_end ; i++ ) {
		mdev->bc->md.uuid[i+1] = mdev->bc->md.uuid[i];
	}
}

void _drbd_uuid_set(drbd_dev *mdev, int idx, u64 val)
{
	if (mdev->state.role == Primary) {
		mdev->bc->md.uuid[idx] = val | 1;
	} else {
		mdev->bc->md.uuid[idx] = val & ~((u64)1);
	}
	drbd_md_mark_dirty(mdev);
}


void drbd_uuid_set(drbd_dev *mdev, int idx, u64 val)
{
	if(mdev->bc->md.uuid[idx]) {
		drbd_uuid_move_history(mdev);
		mdev->bc->md.uuid[History_start]=mdev->bc->md.uuid[idx];
	}
	_drbd_uuid_set(mdev,idx,val);
}

void drbd_uuid_new_current(drbd_dev *mdev)
{
	D_ASSERT(mdev->bc->md.uuid[Bitmap] == 0);
	mdev->bc->md.uuid[Bitmap] = mdev->bc->md.uuid[Current];
	get_random_bytes(&mdev->bc->md.uuid[Current], sizeof(u64));
	if (mdev->state.role == Primary) {
		mdev->bc->md.uuid[Current] |= 1;
	} else {
		mdev->bc->md.uuid[Current] &= ~((u64)1);
	}
	drbd_md_mark_dirty(mdev);
}

void drbd_uuid_set_bm(drbd_dev *mdev, u64 val)
{
	if( mdev->bc->md.uuid[Bitmap]==0 && val==0 ) return;

	if(val==0) {
		drbd_uuid_move_history(mdev);
		mdev->bc->md.uuid[History_start]=mdev->bc->md.uuid[Bitmap];
		mdev->bc->md.uuid[Bitmap]=0;
	} else {
		if( mdev->bc->md.uuid[Bitmap] ) WARN("bm UUID already set");

		mdev->bc->md.uuid[Bitmap] = val;
		mdev->bc->md.uuid[Bitmap] &= ~((u64)1);
	}
	drbd_md_mark_dirty(mdev);
}


void drbd_md_set_flag(drbd_dev *mdev, int flag)
{
	MUST_HOLD(mdev->req_lock);
	if ( (mdev->bc->md.flags & flag) != flag) {
		drbd_md_mark_dirty(mdev);
		mdev->bc->md.flags |= flag;
	}
}
void drbd_md_clear_flag(drbd_dev *mdev, int flag)
{
	MUST_HOLD(mdev->req_lock);
	if ( (mdev->bc->md.flags & flag) != 0 ) {
		drbd_md_mark_dirty(mdev);
		mdev->bc->md.flags &= ~flag;
	}
}
int drbd_md_test_flag(struct drbd_backing_dev *bdev, int flag)
{
	return ((bdev->md.flags & flag) != 0);
}

STATIC void md_sync_timer_fn(unsigned long data)
{
	drbd_dev* mdev = (drbd_dev*) data;

	drbd_queue_work_front(mdev,&mdev->data.work,&mdev->md_sync_work);
}

STATIC int w_md_sync(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	WARN("BUG! md_sync_timer expired! Worker calls drbd_md_sync().\n");
	drbd_md_sync(mdev);

	return 1;
}

module_init(drbd_init)
module_exit(drbd_cleanup)
