/*
-*- Linux-c -*-
   drbd.c
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
#include <linux/version.h>

#include <asm/uaccess.h>
#include <asm/types.h>
#include <net/sock.h>
#include <linux/ctype.h>
#include <linux/smp_lock.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/drbd_config.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/byteorder/swabb.h>

#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>

#include <linux/drbd.h>
#include <linux/drbd_limits.h>
#include "drbd_int.h"
#include "drbd_req.h" /* only for _req_mod in tl_release and tl_clear */

/* YES. We got an official device major from lanana
 */
#define LANANA_DRBD_MAJOR 147

struct after_state_chg_work {
	struct drbd_work w;
	drbd_state_t os;
	drbd_state_t ns;
	enum chg_state_flags flags;
};

int drbdd_init(struct Drbd_thread*);
int drbd_worker(struct Drbd_thread*);
int drbd_asender(struct Drbd_thread*);

int drbd_init(void);
STATIC int drbd_open(struct inode *inode, struct file *file);
STATIC int drbd_close(struct inode *inode, struct file *file);
STATIC int w_after_state_ch(drbd_dev *mdev, struct drbd_work *w, int unused);
STATIC void after_state_ch(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns,
			   enum chg_state_flags flags);
STATIC int w_md_sync(drbd_dev *mdev, struct drbd_work *w, int unused);
STATIC void md_sync_timer_fn(unsigned long data);

MODULE_AUTHOR("Philipp Reisner <phil@linbit.com>, Lars Ellenberg <lars@linbit.com>");
MODULE_DESCRIPTION("drbd - Distributed Replicated Block Device v" REL_VERSION);
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(minor_count, "Maximum number of drbd devices (1-255)");
MODULE_ALIAS_BLOCKDEV_MAJOR(LANANA_DRBD_MAJOR);

#include <linux/moduleparam.h>
/* allow_open_on_secondary */
MODULE_PARM_DESC(allow_oos, "DONT USE!");
/* thanks to these macros, if compiled into the kernel (not-module),
 * this becomes the boot parameter drbd.minor_count */
module_param(minor_count, int,0444);
module_param(allow_oos, bool,0);

#ifdef DRBD_ENABLE_FAULTS
int enable_faults = 0;
int fault_rate;
int fault_count;
int fault_devs;
module_param(enable_faults,int,0664);	// bitmap of enabled faults
module_param(fault_rate,int,0664);	// fault rate % value - applies to all enabled faults
module_param(fault_count,int,0664);	// count of faults inserted
module_param(fault_devs,int,0644);      // bitmap of devices to insert faults on
#endif

// module parameter, defined
int major_nr = LANANA_DRBD_MAJOR;
int minor_count = 32;

int allow_oos = 0;

#ifdef ENABLE_DYNAMIC_TRACE
int trace_type = 0;	// Bitmap of trace types to enable
int trace_level= 0;	// Current trace level
int trace_devs = 0;	// Bitmap of devices to trace

module_param(trace_level,int,0644);
module_param(trace_type,int,0644);
module_param(trace_devs,int,0644);
#endif


// Module parameter for setting the user mode helper program
// to run. Default is /sbin/drbdadm

char usermode_helper[80] = "/sbin/drbdadm";

module_param_string(usermode_helper, usermode_helper, sizeof(usermode_helper), 0644);

// global panic flag
volatile int drbd_did_panic = 0;

/* in 2.6.x, our device mapping and config info contains our virtual gendisks
 * as member "struct gendisk *vdisk;"
 */
struct Drbd_Conf **minor_table = NULL;

struct kmem_cache *drbd_request_cache;
struct kmem_cache *drbd_ee_cache;
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
};

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

/************************* The transfer log start */
STATIC int tl_init(drbd_dev *mdev)
{
	struct drbd_barrier *b;

	b=kmalloc(sizeof(struct drbd_barrier),GFP_KERNEL);
	if(!b) return 0;
	INIT_LIST_HEAD(&b->requests);
	INIT_LIST_HEAD(&b->w.list);
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

/**
 * _tl_add_barrier: Adds a barrier to the TL.
 */
void _tl_add_barrier(drbd_dev *mdev, struct drbd_barrier *new)
{
	struct drbd_barrier *newest_before;

	INIT_LIST_HEAD(&new->requests);
	INIT_LIST_HEAD(&new->w.list);
	new->next=0;
	new->n_req=0;

	newest_before = mdev->newest_barrier;
	/* never send a barrier number == 0, because that is special-cased
	 * when using TCQ for our write ordering code */
	new->br_number = (newest_before->br_number+1) ?: 1;
	if (mdev->newest_barrier != new) {
		mdev->newest_barrier->next = new;
		mdev->newest_barrier = new;
	}
}

/* when we receive a barrier ack */
void tl_release(drbd_dev *mdev,unsigned int barrier_nr,
		       unsigned int set_size)
{
	struct drbd_barrier *b, *nob; /* next old barrier */
	struct list_head *le, *tle;
	struct drbd_request *r;

	spin_lock_irq(&mdev->req_lock);

	b = mdev->oldest_barrier;

	/* Clean up list of requests processed during current epoch */
	list_for_each_safe(le, tle, &b->requests) {
		r = list_entry(le, struct drbd_request,tl_requests);
		_req_mod(r, barrier_acked, 0);
	}
	list_del(&b->requests);
	/* There could be requests on the list waiting for completion
	   of the write to the local disk, to avoid corruptions of
	   slab's data structures we have to remove the lists head */

	D_ASSERT(b->br_number == barrier_nr);
	D_ASSERT(b->n_req == set_size);

#if 1
	if(b->br_number != barrier_nr) {
		DUMPI(b->br_number);
		DUMPI(barrier_nr);
	}
	if(b->n_req != set_size) {
		DUMPI(b->n_req);
		DUMPI(set_size);
	}
#endif

	nob = b->next;
	if (test_and_clear_bit(CREATE_BARRIER, &mdev->flags)) {
		_tl_add_barrier(mdev, b);
		if (nob)
			mdev->oldest_barrier = nob;
		/* if nob == NULL b was the only barrier, and becomes the new
		   barrer. Threfore mdev->oldest_barrier points already to b */
	} else {
		D_ASSERT(nob != NULL);
		mdev->oldest_barrier = nob;
		kfree(b);
	}

	spin_unlock_irq(&mdev->req_lock);
}


/* called by drbd_disconnect (exiting receiver thread)
 * or from some after_state_ch */
void tl_clear(drbd_dev *mdev)
{
	struct drbd_barrier *b, *tmp;

	WARN("tl_clear()\n");

	spin_lock_irq(&mdev->req_lock);

	b = mdev->oldest_barrier;
	while ( b ) {
		struct list_head *le, *tle;
		struct drbd_request *r;

		list_for_each_safe(le, tle, &b->requests) {
			r = list_entry(le, struct drbd_request,tl_requests);
			_req_mod(r, connection_lost_while_pending, 0);
		}
		tmp = b->next;

		/* there could still be requests on that ring list,
		 * in case local io is still pending */
		list_del(&b->requests);

		if (b == mdev->newest_barrier) {
			D_ASSERT(tmp == NULL);
			b->br_number=4711;
			b->n_req=0;
			INIT_LIST_HEAD(&b->requests);
			mdev->oldest_barrier = b;
			break;
		}
		kfree(b);
		b = tmp;
		/* dec_ap_pending corresponding to _drbd_send_barrier;
		 * note: the barrier for the current epoch (newest_barrier)
		 * has not been sent yet, so we don't dec_ap_pending for it
		 * here, either */
		dec_ap_pending(mdev);
	}
	D_ASSERT(mdev->newest_barrier == mdev->oldest_barrier);
	D_ASSERT(mdev->newest_barrier->br_number == 4711);

	/* ensure bit indicating barrier is required is clear */
	clear_bit(CREATE_BARRIER, &mdev->flags);

	spin_unlock_irq(&mdev->req_lock);
}

/**
 * drbd_io_error: Handles the on_io_error setting, should be called in the
 * unlikely(!drbd_bio_uptodate(e->bio)) case from kernel thread context.
 * See also drbd_chk_io_error
 *
 * NOTE: we set ourselves FAILED here if on_io_error is Detach or Panic OR
 *	 if the forcedetach flag is set. This flag is set when failures
 *	 occur writing the meta data portion of the disk as they are
 *	 not recoverable. We also try to write the "need full sync bit" here
 *	 anyways.  This is to make sure that you get a resynchronisation of
 *	 the full device the next time you connect.
 */
int drbd_io_error(drbd_dev* mdev, int forcedetach)
{
	enum io_error_handler eh;
	unsigned long flags;
	int send,ok=1;

	eh = PassOn;
	if(inc_local_if_state(mdev,Failed)) {
		eh = mdev->bc->dc.on_io_error;
		dec_local(mdev);
	}

	if(!forcedetach && eh == PassOn)
		return 1;

	spin_lock_irqsave(&mdev->req_lock,flags);
	if( (send = (mdev->state.disk == Failed)) ) {
		_drbd_set_state(_NS(mdev,disk,Diskless),ChgStateHard);
	}
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	if(!send) return ok;

	if (mdev->state.conn >= Connected) {
		ok = drbd_send_state(mdev);
		if (ok) WARN("Notified peer that my disk is broken.\n");
		else ERR("Sending state in drbd_io_error() failed\n");
	}

	// Make sure we try to flush meta-data to disk - we come
	// in here because of a local disk error so it might fail
	// but we still need to try -- both because the error might
	// be in the data portion of the disk and because we need
	// to ensure the md-sync-timer is stopped if running.
	drbd_md_sync(mdev);

	/* Releasing the backing device is done in after_state_ch() */

	if(eh == CallIOEHelper) {
		drbd_khelper(mdev,"local-io-error");
	}

	return ok;
}

/**
 * cl_wide_st_chg:
 * Returns TRUE if this state change should be preformed as a cluster wide
 * transaction. Of course it returns 0 as soon as the connection is lost.
 */
STATIC int cl_wide_st_chg(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns)
{
	return ( os.conn >= Connected && ns.conn >= Connected &&
		 ( ( os.role != Primary && ns.role == Primary ) ||
		   ( os.conn != StartingSyncT && ns.conn == StartingSyncT ) ||
		   ( os.conn != StartingSyncS && ns.conn == StartingSyncS ) ||
		   ( os.disk != Diskless && ns.disk == Diskless ) ) ) ||
		(os.conn >= Connected && ns.conn == Disconnecting);
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

	return rv;
}

void drbd_force_state(drbd_dev* mdev, drbd_state_t mask, drbd_state_t val)
{
	drbd_change_state(mdev, ChgStateHard, mask, val);
}

STATIC int is_valid_state(drbd_dev* mdev, drbd_state_t ns);
STATIC int is_valid_state_transition(drbd_dev*, drbd_state_t, drbd_state_t);
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
		rv = is_valid_state(mdev,ns);
		if(rv==SS_Success) {
			rv = is_valid_state_transition(mdev,ns,os);
			if(rv==SS_Success) rv = 0; // cont waiting, otherwise fail.
		}
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
		rv = is_valid_state(mdev,ns);
		if(rv == SS_Success ) rv = is_valid_state_transition(mdev,ns,os);
		spin_unlock_irqrestore(&mdev->req_lock,flags);

		if( rv < SS_Success ) {
			if( f & ChgStateVerbose ) print_st_err(mdev,os,ns,rv);
			return rv;
		}

		drbd_state_lock(mdev);
		if( !drbd_send_state_req(mdev,mask,val) ) {
			drbd_state_unlock(mdev);
			rv = SS_CW_FailedByPeer;
			if( f & ChgStateVerbose ) print_st_err(mdev,os,ns,rv);
			return rv;
		}

		wait_event(mdev->state_wait,(rv=_req_st_cond(mdev,mask,val)));

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

	return rv;
}


STATIC void print_st(drbd_dev* mdev, char *name, drbd_state_t ns)
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

STATIC int is_valid_state(drbd_dev* mdev, drbd_state_t ns)
{
	/* See drbd_state_sw_errors in drbd_strings.c */

	enum fencing_policy fp;
	int rv=SS_Success;

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->dc.fencing;
		dec_local(mdev);
	}

	if(inc_net(mdev)) {
		if( !mdev->net_conf->two_primaries &&
		    ns.role == Primary && ns.peer == Primary )
			rv=SS_TwoPrimaries;
		dec_net(mdev);
	}

	if( rv <= 0 ) /* already found a reason to abort */;
	else if( ns.role == Secondary && mdev->open_cnt )
		rv=SS_DeviceInUse;

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
		  ns.conn == WFBitMapS ||
		  ns.conn == SyncSource ||
		  ns.conn == PausedSyncS) &&
		 ns.disk == Outdated ) rv=SS_ConnectedOutdates;

	return rv;
}

STATIC int is_valid_state_transition(drbd_dev* mdev,drbd_state_t ns,drbd_state_t os)
{
	int rv=SS_Success;

	if( (ns.conn == StartingSyncT || ns.conn == StartingSyncS ) &&
	    os.conn > Connected) rv=SS_ResyncRunning;

	if( ns.conn == Disconnecting && os.conn == StandAlone)
		rv=SS_AlreadyStandAlone;

	if( ns.disk > Attaching && os.disk == Diskless)
		rv=SS_IsDiskLess;

	if ( ns.conn == WFConnection && os.conn < Unconnected )
		rv=SS_NoNetConfig;

	if ( ns.disk == Outdated && os.disk < Outdated && os.disk != Attaching)
		rv=SS_LowerThanOutdated;

	return rv;
}

int _drbd_set_state(drbd_dev* mdev, drbd_state_t ns,enum chg_state_flags flags)
{
	drbd_state_t os;
	int rv=SS_Success, warn_sync_abort=0;
	enum fencing_policy fp;
	struct after_state_chg_work* ascw;

	MUST_HOLD(&mdev->req_lock);

	os = mdev->state;

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->dc.fencing;
		dec_local(mdev);
	}

	/* Early state sanitising. Dissalow the invalidate ioctl to connect  */
	if( (ns.conn == StartingSyncS || ns.conn == StartingSyncT) &&
		os.conn < Connected ) {
		ns.conn = os.conn;
		ns.pdsk = os.pdsk;
	}

	/* Dissalow Network errors to configure a device's network part */
	if( (ns.conn >= Timeout && ns.conn <= TearDown ) &&
	    os.conn <= Disconnecting ) {
		ns.conn = os.conn;
	}

	/* Dissalow network errors (+TearDown) to overwrite each other.
	   Dissalow network errors to overwrite the Disconnecting state. */
	if( ( (os.conn >= Timeout && os.conn <= TearDown)
	      || os.conn == Disconnecting ) &&
	    ns.conn >= Timeout && ns.conn <= TearDown ) {
		ns.conn = os.conn;
	}

	if( ns.conn < Connected ) {
		ns.peer_isp = 0;
		ns.peer = Unknown;
		if ( ns.pdsk > DUnknown ||
		     ns.pdsk < Inconsistent ) ns.pdsk = DUnknown;
	}

	if( ns.conn <= Disconnecting && ns.disk == Diskless ) {
		ns.pdsk = DUnknown;
	}

	if( ns.conn > Connected && (ns.disk <= Failed || ns.pdsk <= Failed )) {
		warn_sync_abort=1;
		ns.conn = Connected;
	}

	if( ns.conn >= Connected &&
	    ( ns.disk == Consistent || ns.disk == Outdated ) ) {
		switch(ns.conn) {
		case WFBitMapT:
		case PausedSyncT:
			ns.disk = Outdated;
			break;
		case Connected:
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
		case WFBitMapT:
		case PausedSyncT:
		case SyncTarget:
			ns.pdsk = UpToDate;
			break;
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

	/* Connection breaks down before we finished "Negotiating" */
	if (ns.conn < Connected && ns.disk == Negotiating ) {
		ns.disk = mdev->new_state_tmp.disk;
		ns.pdsk = mdev->new_state_tmp.pdsk;
	}

	if( fp == Stonith ) {
		if(ns.role == Primary &&
		   ns.conn < Connected &&
		   ns.pdsk > Outdated ) {
			ns.susp = 1;
		}
	}

	if( ns.aftr_isp || ns.peer_isp || ns.user_isp ) {
		if(ns.conn == SyncSource) ns.conn=PausedSyncS;
		if(ns.conn == SyncTarget) ns.conn=PausedSyncT;
	} else {
		if(ns.conn == PausedSyncS) ns.conn=SyncSource;
		if(ns.conn == PausedSyncT) ns.conn=SyncTarget;
	}

	if( ns.i == os.i ) return SS_NothingToDo;

	if( !(flags & ChgStateHard) ) {
		/*  pre-state-change checks ; only look at ns  */
		/* See drbd_state_sw_errors in drbd_strings.c */

		rv = is_valid_state(mdev,ns);
		if(rv < SS_Success) {
			/* If the old state was illegal as well, then let
			   this happen...*/
			if( is_valid_state(mdev,os) == rv ) {
				ERR("Considering state change from bad state. "
				    "Error would be: '%s'\n",
				    set_st_err_name(rv));
				print_st(mdev,"old",os);
				print_st(mdev,"new",ns);
				rv = is_valid_state_transition(mdev,ns,os);
			}
		} else rv = is_valid_state_transition(mdev,ns,os);
	}

	if(rv < SS_Success) {
		if( flags & ChgStateVerbose ) print_st_err(mdev,os,ns,rv);
		return rv;
	}

	if(warn_sync_abort) {
		WARN("Resync aborted.\n");
	}

#if DUMP_MD >= 2
	{
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
	}
#endif

	mdev->state.i = ns.i;
	wake_up(&mdev->misc_wait);
	wake_up(&mdev->state_wait);

	/**   post-state-change actions   **/
	if ( os.conn >= SyncSource   && ns.conn <= Connected ) {
		set_bit(STOP_SYNC_TIMER,&mdev->flags);
		mod_timer(&mdev->resync_timer,jiffies);
	}

	if( (os.conn == PausedSyncT || os.conn == PausedSyncS) &&
	    (ns.conn == SyncTarget  || ns.conn == SyncSource) ) {
		INFO("Syncer continues.\n");
		mdev->rs_paused += (long)jiffies-(long)mdev->rs_mark_time;
		if (ns.conn == SyncTarget) {
			if (!test_and_clear_bit(STOP_SYNC_TIMER,&mdev->flags)) {
				mod_timer(&mdev->resync_timer,jiffies);
			}
			/* This if (!test_bit) is only needed for the case
			   that a device that has ceased to used its timer,
			   i.e. it is already in drbd_resync_finished() gets
			   paused and resumed. */
		}
	}

	if( (os.conn == SyncTarget  || os.conn == SyncSource) &&
	    (ns.conn == PausedSyncT || ns.conn == PausedSyncS) ) {
		INFO("Resync suspended\n");
		mdev->rs_mark_time = jiffies;
		if( ns.conn == PausedSyncT ) {
			set_bit(STOP_SYNC_TIMER,&mdev->flags);
		}
	}

	if(inc_local(mdev)) {
		u32 mdf = mdev->bc->md.flags & ~(MDF_Consistent|MDF_PrimaryInd|
						 MDF_ConnectedInd|MDF_WasUpToDate|
						 MDF_PeerOutDated );

		if (test_bit(CRASHED_PRIMARY,&mdev->flags) ||
		    mdev->state.role == Primary ||
		    ( mdev->state.pdsk < Inconsistent &&
		      mdev->state.peer == Primary ) )  mdf |= MDF_PrimaryInd;
		if (mdev->state.conn > WFReportParams) mdf |= MDF_ConnectedInd;
		if (mdev->state.disk > Inconsistent)   mdf |= MDF_Consistent;
		if (mdev->state.disk > Outdated)       mdf |= MDF_WasUpToDate;
		if (mdev->state.pdsk <= Outdated &&
		    mdev->state.pdsk >= Inconsistent)  mdf |= MDF_PeerOutDated;
		if( mdf != mdev->bc->md.flags) {
			mdev->bc->md.flags = mdf;
			drbd_md_mark_dirty(mdev);
		}
		dec_local(mdev);
	}

	/* Peer was forced UpToDate & Primary, consider to resync */
	if (os.disk == Inconsistent && os.pdsk == Inconsistent &&
	    os.peer == Secondary && ns.peer == Primary)
		set_bit(CONSIDER_RESYNC, &mdev->flags);

	// Receiver should clean up itself
	if (os.conn != Disconnecting && ns.conn == Disconnecting)
		drbd_thread_signal(&mdev->receiver);

	// Now the receiver finished cleaning up itself, it should die
	if (os.conn != StandAlone && ns.conn == StandAlone)
		drbd_thread_stop_nowait(&mdev->receiver);

	// Upon network failure, we need to restart the receiver.
	if (os.conn > TearDown &&
	    ns.conn <= TearDown && ns.conn >= Timeout)
		drbd_thread_restart_nowait(&mdev->receiver);

	ascw = kmalloc(sizeof(*ascw), GFP_ATOMIC);
	if (ascw) {
		ascw->os = os;
		ascw->ns = ns;
		ascw->flags = flags;
		ascw->w.cb = w_after_state_ch;
		drbd_queue_work(&mdev->data.work, &ascw->w);
	} else {
		WARN("Could not kmalloc an ascw\n");
	}

	return rv;
}

STATIC int w_after_state_ch(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	struct after_state_chg_work* ascw;

	ascw = (struct after_state_chg_work*) w;
	after_state_ch(mdev, ascw->os, ascw->ns, ascw->flags);
	kfree(ascw);

	return 1;
}

STATIC void after_state_ch(drbd_dev* mdev, drbd_state_t os, drbd_state_t ns,
			   enum chg_state_flags flags)
{
	enum fencing_policy fp;

	if ( (os.conn != Connected && ns.conn == Connected) ) {
		clear_bit(CRASHED_PRIMARY, &mdev->flags);
		if( mdev->p_uuid ) {
			mdev->p_uuid[UUID_FLAGS] &= ~((u64)2);
		}
	}

	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->dc.fencing;
		dec_local(mdev);
	}

	/* Inform userspace about the change... */
	drbd_bcast_state(mdev, ns);

	/* Here we have the actions that are performed after a
	   state change. This function might sleep */

	if( fp == Stonith && ns.susp ) {
		// case1: The outdate peer handler is successfull:
		// case2: The connection was established again:
		if ( (os.pdsk > Outdated  && ns.pdsk <= Outdated) || // case1
		     (os.conn < Connected && ns.conn >= Connected) ) {
			tl_clear(mdev);
			spin_lock_irq(&mdev->req_lock);
			_drbd_set_state(_NS(mdev,susp,0),ChgStateVerbose);
			spin_unlock_irq(&mdev->req_lock);
		}
	}
	// Do not change the order of the if above and below...
	if (os.conn != WFBitMapS && ns.conn == WFBitMapS) {
		/* compare with drbd_make_request_common,
		 * wait_event and inc_ap_bio.
		 * Note: we may lose connection whilst waiting here.
		 * no worries though, should work out ok... */
		wait_event(mdev->misc_wait,
			mdev->state.conn != WFBitMapS ||
			!atomic_read(&mdev->ap_bio_cnt));
		drbd_bm_lock(mdev);   // {
		drbd_send_bitmap(mdev);
		drbd_bm_unlock(mdev); // }
	}

	/* Lost contact to peer's copy of the data */
	if ( (os.pdsk>=Inconsistent && os.pdsk!=DUnknown && os.pdsk!=Outdated) &&
	     (ns.pdsk<Inconsistent || ns.pdsk==DUnknown || ns.pdsk==Outdated) ) {
		if ( mdev->p_uuid ) {
			kfree(mdev->p_uuid);
			mdev->p_uuid = NULL;
		}
		if (inc_local(mdev)) {
			if (ns.role == Primary && mdev->bc->md.uuid[Bitmap] == 0 ) {
				/* Only do it if we have not yet done it... */
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
			dec_local(mdev);
		}
	}

	if (ns.pdsk < Inconsistent && inc_local(mdev)) {
		/* Diskless Peer becomes primary */
		if (os.peer == Secondary && ns.peer == Primary &&
		    mdev->bc->md.uuid[Bitmap] == 0) {
			drbd_uuid_new_current(mdev);
		}
		/* Diskless Peer becomes secondary */
		if (os.peer == Primary && ns.peer == Secondary ) {
			drbd_al_to_on_disk_bm(mdev);
		}
		dec_local(mdev);
	}

	/* Last part of the attaching process ... */
	if ( ns.conn >= Connected &&
	     os.disk == Attaching && ns.disk == Negotiating ) {
		kfree(mdev->p_uuid); /* We expect to receive up-to-date UUIDs soon. */
		mdev->p_uuid = NULL; /* ...to not use the old ones in the mean time */
		drbd_send_sizes(mdev);  // to start sync...
		drbd_send_uuids(mdev);
		drbd_send_state(mdev);
	}

	/* We want to pause/continue resync, tell peer. */
	if ( ns.conn >= Connected &&
	     (( os.aftr_isp != ns.aftr_isp ) ||
	      ( os.user_isp != ns.user_isp )) ) {
		drbd_send_state(mdev);
	}

	/* In case one of the isp bits got set, suspend other devices. */
	if ( ( !os.aftr_isp && !os.peer_isp && !os.user_isp) &&
	     ( ns.aftr_isp || ns.peer_isp || ns.user_isp) ) {
		suspend_other_sg(mdev);
	}

	/* Make sure the peer gets informed about eventual state
	   changes (ISP bits) while we were in WFReportParams. */
	if (os.conn == WFReportParams && ns.conn >= Connected) {
		drbd_send_state(mdev);
	}

	/* We are in the progress to start a full sync... */
	if ( ( os.conn != StartingSyncT && ns.conn == StartingSyncT ) ||
	     ( os.conn != StartingSyncS && ns.conn == StartingSyncS ) ) {

		drbd_bm_lock(mdev); // racy...

		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);

		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);

		drbd_bm_unlock(mdev);

		if (ns.conn == StartingSyncT) {
			spin_lock_irq(&mdev->req_lock);
			_drbd_set_state(_NS(mdev,conn,WFSyncUUID),ChgStateVerbose);
			spin_unlock_irq(&mdev->req_lock);
		} else /* StartingSyncS */ {
			drbd_start_resync(mdev,SyncSource);
		}
	}

	/* We are invalidating our self... */
	if ( os.conn < Connected && ns.conn < Connected &&
	       os.disk > Inconsistent && ns.disk == Inconsistent ) {
		drbd_bm_lock(mdev); // racy...

		drbd_md_set_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);

		drbd_bm_set_all(mdev);
		drbd_bm_write(mdev);

		drbd_md_clear_flag(mdev,MDF_FullSync);
		drbd_md_sync(mdev);

		drbd_bm_unlock(mdev);
	}

	if ( os.disk > Diskless && ns.disk == Diskless ) {
		/* since inc_local() only works as long as disk>=Inconsistent,
		   and it is Diskless here, local_cnt can only go down, it can
		   not increase... It will reach zero */
		wait_event(mdev->misc_wait, !atomic_read(&mdev->local_cnt));

		drbd_free_bc(mdev->bc);	mdev->bc = NULL;
		lc_free(mdev->resync);  mdev->resync = NULL;
		lc_free(mdev->act_log); mdev->act_log = NULL;
	}

	// A resync finished or aborted, wake paused devices...
	if ( (os.conn > Connected && ns.conn <= Connected) ||
	     (os.peer_isp && !ns.peer_isp) ||
	     (os.user_isp && !ns.user_isp) ) {
		resume_next_sg(mdev);
	}

	// Upon network connection, we need to start the received
	if ( os.conn == StandAlone && ns.conn == Unconnected) {
		drbd_thread_start(&mdev->receiver);
	}

	// Terminate worker thread if we are unconfigured - it will be
	// restarted as needed...
	if (ns.disk == Diskless && ns.conn == StandAlone) {
		drbd_thread_stop_nowait(&mdev->worker);
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

	while(1) {
		retval = thi->function(thi);
		if(get_t_state(thi) != Restarting) break;
		thi->t_state = Running;
	}

	spin_lock(&thi->t_lock);
	thi->task = NULL;
	thi->t_state = None;
	smp_mb();
	spin_unlock(&thi->t_lock);

	// THINK maybe two different completions?
	complete(&thi->startstop); // notify: thi->task unset.

	INFO("Terminating %s thread\n",
	     thi == &mdev->receiver ? "receiver" :
	     thi == &mdev->asender  ? "asender"  :
	     thi == &mdev->worker   ? "worker"   : "NONSENSE");

	// Release mod reference taken when thread was started
	module_put(THIS_MODULE);
	return retval;
}

STATIC void drbd_thread_init(drbd_dev *mdev, struct Drbd_thread *thi,
		      int (*func) (struct Drbd_thread *))
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = None;
	thi->function = func;
	thi->mdev = mdev;
}

int drbd_thread_start(struct Drbd_thread *thi)
{
	int pid;
	drbd_dev *mdev = thi->mdev;

	spin_lock(&thi->t_lock);

	if (thi->t_state == None) {
		INFO("Starting %s thread (from %s [%d])\n",
		     thi == &mdev->receiver ? "receiver" :
		     thi == &mdev->asender  ? "asender"  :
		     thi == &mdev->worker   ? "worker"   : "NONSENSE",
		     current->comm, current->pid);

		// Get ref on module for thread - this is released when thread exits
		if (!try_module_get(THIS_MODULE)) {
			ERR("Failed to get module reference in drbd_thread_start\n");
			spin_unlock(&thi->t_lock);
			return FALSE;
		}

		init_completion(&thi->startstop);
		D_ASSERT(thi->task == NULL);
		thi->t_state = Running;
		spin_unlock(&thi->t_lock);

		flush_signals(current); // otherw. may get -ERESTARTNOINTR
		pid = kernel_thread(drbd_thread_setup, (void *) thi, CLONE_FS);
		if (pid < 0) {
			ERR("Couldn't start thread (%d)\n", pid);

			module_put(THIS_MODULE);
			return FALSE;
		}

		wait_for_completion(&thi->startstop); // waits until thi->task is set

		D_ASSERT(thi->task);
		D_ASSERT(get_t_state(thi) == Running);
	} else {
		spin_unlock(&thi->t_lock);
	}

	return TRUE;
}


void _drbd_thread_stop(struct Drbd_thread *thi, int restart,int wait)
{
	drbd_dev *mdev = thi->mdev;
	Drbd_thread_state ns = restart ? Restarting : Exiting;

	spin_lock(&thi->t_lock);

	/* INFO("drbd_thread_stop: %s [%d]: %s %d -> %d; %d\n",
	     current->comm, current->pid,
	     thi->task ? thi->task->comm : "NULL", thi->t_state, ns, wait); */

	if (thi->t_state == None) {
		spin_unlock(&thi->t_lock);
		if(restart) drbd_thread_start(thi);
		return;
	}

	if (thi->t_state != ns) {
		if (thi->task == NULL) {
			spin_unlock(&thi->t_lock);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		if (thi->task != current) {
			if(wait) init_completion(&thi->startstop);
			force_sig(DRBD_SIGKILL,thi->task);
		} else D_ASSERT(!wait);
	}
	spin_unlock(&thi->t_lock);

	if (wait) {
		D_ASSERT(thi->task != current);
		wait_for_completion(&thi->startstop);
		spin_lock(&thi->t_lock);
		D_ASSERT(thi->task == NULL);
		D_ASSERT(thi->t_state == None);
		spin_unlock(&thi->t_lock);
	}
}

void drbd_thread_signal(struct Drbd_thread *thi)
{
	spin_lock(&thi->t_lock);

	if (thi->t_state == None) {
		spin_unlock(&thi->t_lock);
		return;
	}

	if (thi->task != current) {
		force_sig(DRBD_SIGKILL,thi->task);
	}

	spin_unlock(&thi->t_lock);
}

/* the appropriate socket mutex must be held already */
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

/* don't pass the socket. we may only look at it
 * when we hold the appropriate socket mutex.
 */
int drbd_send_cmd(drbd_dev *mdev, int use_data_socket,
		  Drbd_Packet_Cmd cmd, Drbd_Header* h, size_t size)
{
	int ok = 0;
	struct socket *sock;

	if (use_data_socket) {
		down(&mdev->data.mutex);
		sock = mdev->data.socket;
	} else {
		down(&mdev->meta.mutex);
		sock = mdev->meta.socket;
	}

	/* drbd_disconnect() could have called drbd_free_sock()
	 * while we were waiting in down()... */
	if (likely(sock != NULL)) {
		ok = _drbd_send_cmd(mdev, sock, cmd, h, size, 0);
	}

	if (use_data_socket) {
		up(&mdev->data.mutex);
	} else
		up(&mdev->meta.mutex);
	return ok;
}

int drbd_send_cmd2(drbd_dev *mdev, Drbd_Packet_Cmd cmd, char* data,
		   size_t size)
{
	Drbd_Header h;
	int ok;

	h.magic   = BE_DRBD_MAGIC;
	h.command = cpu_to_be16(cmd);
	h.length  = cpu_to_be16(size);

	if (!drbd_get_data_sock(mdev))
		return 0;

	dump_packet(mdev,mdev->data.socket,0,(void*)&h, __FILE__, __LINE__);

	ok = ( sizeof(h) == drbd_send(mdev,mdev->data.socket,&h,sizeof(h),0) );
	ok = ok && ( size == drbd_send(mdev,mdev->data.socket,data,size,0) );

	drbd_put_data_sock(mdev);

	return ok;
}

int drbd_send_sync_param(drbd_dev *mdev, struct syncer_conf *sc)
{
	Drbd_SyncParam_Packet p;

	p.rate      = cpu_to_be32(sc->rate);

	return drbd_send_cmd(mdev,USE_DATA_SOCKET,SyncParam,(Drbd_Header*)&p,sizeof(p));
}

int drbd_send_protocol(drbd_dev *mdev)
{
	Drbd_Protocol_Packet p;

	p.protocol      = cpu_to_be32(mdev->net_conf->wire_protocol);
	p.after_sb_0p   = cpu_to_be32(mdev->net_conf->after_sb_0p);
	p.after_sb_1p   = cpu_to_be32(mdev->net_conf->after_sb_1p);
	p.after_sb_2p   = cpu_to_be32(mdev->net_conf->after_sb_2p);
	p.want_lose     = cpu_to_be32(mdev->net_conf->want_lose);
	p.two_primaries = cpu_to_be32(mdev->net_conf->two_primaries);

	return drbd_send_cmd(mdev,USE_DATA_SOCKET,ReportProtocol,
			     (Drbd_Header*)&p,sizeof(p));
}

/* Hold sock mutex before calling this */
int _drbd_send_uuids(drbd_dev *mdev)
{
	Drbd_GenCnt_Packet p;
	int i, ok=0;
	u64 uuid_flags = 0;
	struct socket *sock = mdev->data.socket;

	if(!inc_local_if_state(mdev,Negotiating)) return 1; // ok.

	for (i = Current; i < UUID_SIZE; i++) {
		/* FIXME howto handle diskless ? */
		p.uuid[i] = mdev->bc
			? cpu_to_be64(mdev->bc->md.uuid[i])
			: 0;
	}

	mdev->comm_bm_set = drbd_bm_total_weight(mdev);
	p.uuid[UUID_SIZE] = cpu_to_be64(mdev->comm_bm_set);
	uuid_flags |= mdev->net_conf->want_lose ? 1 : 0;
	uuid_flags |= test_bit(CRASHED_PRIMARY, &mdev->flags) ? 2 : 0;
	p.uuid[UUID_FLAGS] = cpu_to_be64(uuid_flags);

	dec_local(mdev);

	if (likely(sock != NULL))
		ok = _drbd_send_cmd(mdev, sock, ReportUUIDs,
				   (Drbd_Header*)&p, sizeof(p), 0);

	return ok;
}

int drbd_send_uuids(drbd_dev *mdev)
{
	int ok;
	down(&mdev->data.mutex);
	ok = _drbd_send_uuids(mdev);
	up(&mdev->data.mutex);

	return ok;
}

int drbd_send_sync_uuid(drbd_dev *mdev, u64 val)
{
	Drbd_SyncUUID_Packet p;

	p.uuid = cpu_to_be64(val);

	return drbd_send_cmd(mdev,USE_DATA_SOCKET,ReportSyncUUID,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_sizes(drbd_dev *mdev)
{
	Drbd_Sizes_Packet p;
	sector_t d_size, u_size;
	int q_order_type;
	int ok;

	if(inc_local_if_state(mdev,Negotiating)) {
		D_ASSERT(mdev->bc->backing_bdev);
		d_size = drbd_get_max_capacity(mdev->bc);
		u_size = mdev->bc->dc.disk_size;
		q_order_type = drbd_queue_order_type(mdev);
		p.queue_order_type = cpu_to_be32(drbd_queue_order_type(mdev));
		dec_local(mdev);
	} else {
		d_size = 0;
		u_size = 0;
		q_order_type = QUEUE_ORDERED_NONE;
	}

	p.d_size = cpu_to_be64(d_size);
	p.u_size = cpu_to_be64(u_size);
	p.c_size = cpu_to_be64(drbd_get_capacity(mdev->this_bdev));
	p.max_segment_size = cpu_to_be32(mdev->rq_queue->max_segment_size);
	p.queue_order_type = cpu_to_be32(q_order_type);

	ok = drbd_send_cmd(mdev,USE_DATA_SOCKET,ReportSizes,
			   (Drbd_Header*)&p,sizeof(p));
	return ok;
}

/* Hold socket mutex before calling this */
int _drbd_send_state(drbd_dev *mdev)
{
	struct socket *sock = mdev->data.socket;
	Drbd_State_Packet p;
	int ok = 0;

	p.state    = cpu_to_be32(mdev->state.i);

	if (likely(sock != NULL))
		ok = _drbd_send_cmd(mdev, sock, ReportState,
				   (Drbd_Header*)&p, sizeof(p), 0);

	return ok;
}

/**
 * drbd_send_state:
 * Informs the peer about our state. Only call it when
 * mdev->state.conn >= Connected (I.e. you may not call it while in
 * WFReportParams. Though there is one valid and necessary exception,
 * drbd_connect() calls drbd_send_state() while in it WFReportParams.
 */
int drbd_send_state(drbd_dev *mdev)
{
	int ok;

	down(&mdev->data.mutex);
	ok = _drbd_send_state(mdev);
	up(&mdev->data.mutex);

	return ok;
}

STATIC int drbd_send_state_req(drbd_dev *mdev, drbd_state_t mask, drbd_state_t val)
{
	Drbd_Req_State_Packet p;

	p.mask    = cpu_to_be32(mask.i);
	p.val     = cpu_to_be32(val.i);

	return drbd_send_cmd(mdev,USE_DATA_SOCKET,StateChgRequest,
			     (Drbd_Header*)&p,sizeof(p));
}

int drbd_send_sr_reply(drbd_dev *mdev, int retcode)
{
	Drbd_RqS_Reply_Packet p;

	p.retcode    = cpu_to_be32(retcode);

	return drbd_send_cmd(mdev,USE_META_SOCKET,StateChgReply,
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
			/* write_bm did fail! Leave full sync flag set in Meta Data
			 * but otherwise process as per normal - need to tell other
			 * side that a full resync is required! */
			ERR("Failed to write bitmap to disk!\n");
		}
		else {
			drbd_md_clear_flag(mdev,MDF_FullSync);
			drbd_md_sync(mdev);
		}
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

	vfree(p);
	return ok;
}

int drbd_send_bitmap(drbd_dev *mdev)
{
	int ok;

	if (!drbd_get_data_sock(mdev))
		return 0;
	ok=_drbd_send_bitmap(mdev);
	drbd_put_data_sock(mdev);
	return ok;
}

int drbd_send_b_ack(drbd_dev *mdev, u32 barrier_nr,u32 set_size)
{
	int ok;
	Drbd_BarrierAck_Packet p;

	p.barrier  = barrier_nr;
	p.set_size = cpu_to_be32(set_size);

	ok = drbd_send_cmd(mdev,USE_META_SOCKET,BarrierAck,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

/**
 * _drbd_send_ack:
 * This helper function expects the sector and block_id parameter already
 * in big endian!
 */
STATIC int _drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
			  u64 sector,
			  u32 blksize,
			  u64 block_id)
{
	int ok;
	Drbd_BlockAck_Packet p;

	p.sector   = sector;
	p.block_id = block_id;
	p.blksize  = blksize;
	p.seq_num  = cpu_to_be32(atomic_add_return(1,&mdev->packet_seq));

	if (!mdev->meta.socket || mdev->state.conn < Connected) return FALSE;
	ok=drbd_send_cmd(mdev,USE_META_SOCKET,cmd,(Drbd_Header*)&p,sizeof(p));
	return ok;
}

int drbd_send_ack_dp(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
		     Drbd_Data_Packet *dp)
{
	const int header_size = sizeof(Drbd_Data_Packet) - sizeof(Drbd_Header);
	int data_size  = ((Drbd_Header*)dp)->length - header_size;

	return _drbd_send_ack(mdev,cmd,dp->sector,cpu_to_be32(data_size),
			      dp->block_id);
}

int drbd_send_ack_rp(drbd_dev *mdev, Drbd_Packet_Cmd cmd,
		     Drbd_BlockRequest_Packet *rp)
{
	return _drbd_send_ack(mdev,cmd,rp->sector,rp->blksize,rp->block_id);
}

int drbd_send_ack(drbd_dev *mdev, Drbd_Packet_Cmd cmd, struct Tl_epoch_entry *e)
{
	return _drbd_send_ack(mdev,cmd,
			      cpu_to_be64(e->sector),
			      cpu_to_be32(e->size),
			      e->block_id);
}

int drbd_send_drequest(drbd_dev *mdev, int cmd,
		       sector_t sector,int size, u64 block_id)
{
	int ok;
	Drbd_BlockRequest_Packet p;

	p.sector   = cpu_to_be64(sector);
	p.block_id = block_id;
	p.blksize  = cpu_to_be32(size);

	/* FIXME BIO_RW_SYNC ? */

	ok = drbd_send_cmd(mdev,USE_DATA_SOCKET,cmd,(Drbd_Header*)&p,sizeof(p));
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
	ok = (len == 0);
	if (likely(ok))
		mdev->send_cnt += size>>9;
	return ok;
}

static inline int _drbd_send_bio(drbd_dev *mdev, struct bio *bio)
{
	struct bio_vec *bvec;
	int i;
	__bio_for_each_segment(bvec, bio, i, 0) {
		if (!_drbd_no_send_page(mdev, bvec->bv_page,
				     bvec->bv_offset, bvec->bv_len))
			return 0;
	}
	return 1;
}

static inline int _drbd_send_zc_bio(drbd_dev *mdev, struct bio *bio)
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
	Drbd_Data_Packet p;
	unsigned int dp_flags=0;

	if (!drbd_get_data_sock(mdev))
		return 0;

	p.head.magic   = BE_DRBD_MAGIC;
	p.head.command = cpu_to_be16(Data);
	p.head.length  = cpu_to_be16(sizeof(p)-sizeof(Drbd_Header)+req->size);

	p.sector   = cpu_to_be64(req->sector);
	p.block_id = (unsigned long)req;
	p.seq_num  = cpu_to_be32( req->seq_num =
				  atomic_add_return(1,&mdev->packet_seq) );
	dp_flags = 0;

	/* NOTE: no need to check if barriers supported here as we would
	 *       not pass the test in make_request_common in that case
	 */
	if (bio_barrier(req->master_bio))
		dp_flags |= DP_HARDBARRIER;
	if (bio_sync(req->master_bio))
		dp_flags |= DP_RW_SYNC;
	if (mdev->state.conn >= SyncSource &&
	    mdev->state.conn <= PausedSyncT)
		dp_flags |= DP_MAY_SET_IN_SYNC;

	p.dp_flags = cpu_to_be32(dp_flags);
	dump_packet(mdev,mdev->data.socket,0,(void*)&p, __FILE__, __LINE__);
	set_bit(UNPLUG_REMOTE,&mdev->flags);
	ok = sizeof(p) == drbd_send(mdev,mdev->data.socket,&p,sizeof(p),MSG_MORE);
	if (ok) {
		if (mdev->net_conf->wire_protocol == DRBD_PROT_A)
			ok = _drbd_send_bio(mdev,req->master_bio);
		else
			ok = _drbd_send_zc_bio(mdev,req->master_bio);
	}

	drbd_put_data_sock(mdev);
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
	Drbd_Data_Packet p;

	p.head.magic   = BE_DRBD_MAGIC;
	p.head.command = cpu_to_be16(cmd);
	p.head.length  = cpu_to_be16( sizeof(p)-sizeof(Drbd_Header) + e->size);

	p.sector   = cpu_to_be64(e->sector);
	p.block_id = e->block_id;
	/* p.seq_num  = 0;    No sequence numbers here.. */

	/* Only called by our kernel thread.
	 * This one may be interupted by DRBD_SIG and/or DRBD_SIGKILL
	 * in response to ioctl or module unload.
	 */
	if (!drbd_get_data_sock(mdev))
		return 0;

	dump_packet(mdev,mdev->data.socket,0,(void*)&p, __FILE__, __LINE__);
	ok = sizeof(p) == drbd_send(mdev,mdev->data.socket,&p,sizeof(p),MSG_MORE);
	if (ok) ok = _drbd_send_zc_bio(mdev,e->private_bio);

	drbd_put_data_sock(mdev);
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
 * you must have down()ed the appropriate [m]sock_mutex elsewhere!
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
	}

	return sent;
}

STATIC int drbd_open(struct inode *inode, struct file *file)
{
	drbd_dev *mdev;
	unsigned long flags;
	int rv=0;

	mdev = minor_to_mdev(MINOR(inode->i_rdev));
	if(!mdev) return -ENODEV;

	spin_lock_irqsave(&mdev->req_lock,flags);
	/* to have a stable mdev->state.role and no race with updating open_cnt */

	if (mdev->state.role != Primary) {
		if (file->f_mode & FMODE_WRITE) {
			rv = -EROFS;
		} else if (!allow_oos) {
			rv = -EMEDIUMTYPE;
		}
	}

	if(!rv) mdev->open_cnt++;
	spin_unlock_irqrestore(&mdev->req_lock,flags);

	return rv;
}

STATIC int drbd_close(struct inode *inode, struct file *file)
{
	/* do not use *file (May be NULL, in case of a unmount :-) */
	drbd_dev *mdev;

	mdev = minor_to_mdev(MINOR(inode->i_rdev));
	if(!mdev) return -ENODEV;

	/*
	printk(KERN_ERR DEVICE_NAME ": close(inode=%p,file=%p)"
	       "current=%p,minor=%d,wc=%d\n", inode, file, current, minor,
	       inode->i_writecount);
	*/

	mdev->open_cnt--;

	return 0;
}

STATIC void drbd_unplug_fn(struct request_queue *q)
{
	drbd_dev *mdev = q->queuedata;

	MTRACE(TraceTypeUnplug,TraceLvlSummary,
	       INFO("got unplugged ap_bio_count=%d\n",
		    atomic_read(&mdev->ap_bio_cnt));
	       );

	/* unplug FIRST */
	spin_lock_irq(q->queue_lock);
	blk_remove_plug(q);
	spin_unlock_irq(q->queue_lock);

	/* only if connected */
	spin_lock_irq(&mdev->req_lock);
	if (mdev->state.pdsk >= Inconsistent && mdev->state.conn >= Connected) {
		D_ASSERT(mdev->state.role == Primary);
		if (test_and_clear_bit(UNPLUG_REMOTE,&mdev->flags)) {
			/* add to the data.work queue,
			 * unless already queued.
			 * XXX this might be a good addition to drbd_queue_work
			 * anyways, to detect "double queuing" ... */
			if (list_empty(&mdev->unplug_work.list))
				drbd_queue_work(&mdev->data.work,&mdev->unplug_work);
		}
	}
	spin_unlock_irq(&mdev->req_lock);

	if(mdev->state.disk >= Inconsistent) drbd_kick_lo(mdev);
}

void drbd_set_defaults(drbd_dev *mdev)
{
	mdev->sync_conf.after      = DRBD_AFTER_DEF;
	mdev->sync_conf.rate       = DRBD_RATE_DEF;
	mdev->sync_conf.al_extents = DRBD_AL_EXTENTS_DEF; // 512 MB active set
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

	/* for now, we do NOT yet support it,
	 * even though we start some framework
	 * to eventually support barriers */
	set_bit(NO_BARRIER_SUPP,&mdev->flags);

	atomic_set(&mdev->ap_bio_cnt,0);
	atomic_set(&mdev->ap_pending_cnt,0);
	atomic_set(&mdev->rs_pending_cnt,0);
	atomic_set(&mdev->unacked_cnt,0);
	atomic_set(&mdev->local_cnt,0);
	atomic_set(&mdev->net_cnt,0);
	atomic_set(&mdev->packet_seq,0);
	atomic_set(&mdev->pp_in_use, 0);

	init_MUTEX(&mdev->md_io_mutex);
	init_MUTEX(&mdev->data.mutex);
	init_MUTEX(&mdev->meta.mutex);
	sema_init(&mdev->data.work.s,0);
	sema_init(&mdev->meta.work.s,0);

	spin_lock_init(&mdev->data.work.q_lock);
	spin_lock_init(&mdev->meta.work.q_lock);

	spin_lock_init(&mdev->al_lock);
	spin_lock_init(&mdev->req_lock);
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
	INIT_LIST_HEAD(&mdev->unplug_work.list);
	INIT_LIST_HEAD(&mdev->md_sync_work.list);
	mdev->resync_work.cb  = w_resync_inactive;
	mdev->unplug_work.cb  = w_send_write_hint;
	mdev->md_sync_work.cb = w_md_sync;
	init_timer(&mdev->resync_timer);
	init_timer(&mdev->md_sync_timer);
	mdev->resync_timer.function = resync_timer_fn;
	mdev->resync_timer.data = (unsigned long) mdev;
	mdev->md_sync_timer.function = md_sync_timer_fn;
	mdev->md_sync_timer.data = (unsigned long) mdev;

	init_waitqueue_head(&mdev->misc_wait);
	init_waitqueue_head(&mdev->state_wait);
	init_waitqueue_head(&mdev->ee_wait);
	init_waitqueue_head(&mdev->al_wait);
	init_waitqueue_head(&mdev->seq_wait);

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

	drbd_thread_stop(&mdev->receiver);

	/* no need to lock it, I'm the only thread alive */
	if ( mdev->epoch_size !=  0)
		ERR("epoch_size:%d\n",mdev->epoch_size);
	mdev->al_writ_cnt  =
	mdev->bm_writ_cnt  =
	mdev->read_cnt     =
	mdev->recv_cnt     =
	mdev->send_cnt     =
	mdev->writ_cnt     =
	mdev->p_size       =
	mdev->rs_start     =
	mdev->rs_total     =
	mdev->rs_failed    =
	mdev->rs_mark_left =
	mdev->rs_mark_time = 0;
	D_ASSERT(mdev->net_conf == NULL);
	drbd_set_my_capacity(mdev,0);
	drbd_bm_resize(mdev,0);

	// just in case
	drbd_free_resources(mdev);

	/*
	 * currently we drbd_init_ee only on module load, so
	 * we may do drbd_release_ee only on module unload!
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
	D_ASSERT(list_empty(&mdev->unplug_work.list));

}


void drbd_destroy_mempools(void)
{
	struct page *page;

	while(drbd_pp_pool) {
		page = drbd_pp_pool;
		drbd_pp_pool = (struct page*)page_private(page);
		__free_page(page);
		drbd_pp_vacant--;
	}

	/* D_ASSERT(atomic_read(&drbd_pp_vacant)==0); */

	if (drbd_ee_mempool) mempool_destroy(drbd_ee_mempool);
	if (drbd_request_mempool) mempool_destroy(drbd_request_mempool);
	if (drbd_ee_cache) kmem_cache_destroy(drbd_ee_cache);
	if (drbd_request_cache) kmem_cache_destroy(drbd_request_cache);

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
		"drbd_req_cache", sizeof(drbd_request_t), 0, 0, NULL);
	if (drbd_request_cache == NULL)
		goto Enomem;

	drbd_ee_cache = kmem_cache_create(
		"drbd_ee_cache", sizeof(struct Tl_epoch_entry), 0, 0, NULL);
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
		set_page_private(page,(unsigned long)drbd_pp_pool);
		drbd_pp_pool = page;
	}
	drbd_pp_vacant = number;

	return 0;

  Enomem:
	drbd_destroy_mempools(); // in case we allocated some
	return -ENOMEM;
}

STATIC int drbd_notify_sys(struct notifier_block *this, unsigned long code,
	void *unused)
{
	/* just so we have it.  you never know what interessting things we
	 * might want to do here some day...
	 */

	return NOTIFY_DONE;
}

STATIC struct notifier_block drbd_notifier = {
	.notifier_call = drbd_notify_sys,
};


STATIC void __exit drbd_cleanup(void)
{
	int i, rr;

	unregister_reboot_notifier(&drbd_notifier);

	drbd_nl_cleanup();

	if (minor_table) {
		if (drbd_proc)
			remove_proc_entry("drbd",&proc_root);
		i=minor_count;
		while (i--) {
			drbd_dev        *mdev  = minor_to_mdev(i);
			struct gendisk  **disk = &mdev->vdisk;
			struct request_queue **q = &mdev->rq_queue;

			if(!mdev) continue;
			drbd_free_resources(mdev);

			if (*disk) {
				del_gendisk(*disk);
				put_disk(*disk);
				*disk = NULL;
			}
			if (*q) blk_put_queue(*q);
			*q = NULL;

			D_ASSERT(mdev->open_cnt == 0);
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
				mdev->ee_hash = NULL;
			}
			if(mdev->tl_hash) {
				kfree(mdev->tl_hash);
				mdev->tl_hash_s = 0;
				mdev->tl_hash = NULL;
			}
			if(mdev->app_reads_hash) {
				kfree(mdev->app_reads_hash);
				mdev->app_reads_hash = NULL;
			}
			if ( mdev->p_uuid ) {
				kfree(mdev->p_uuid);
				mdev->p_uuid = NULL;
			}
		}
		drbd_destroy_mempools();
	}

	kfree(minor_table);

	drbd_unregister_blkdev(LANANA_DRBD_MAJOR, DEVICE_NAME);

	printk(KERN_INFO DEVICE_NAME": module cleanup done.\n");
}

drbd_dev *drbd_new_device(int minor)
{
	drbd_dev *mdev = NULL;
	struct gendisk *disk;
	struct request_queue *q;

	mdev = kzalloc(sizeof(drbd_dev),GFP_KERNEL);
	if(!mdev) goto Enomem;

	mdev->minor = minor;

	drbd_init_set_defaults(mdev);

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
	disk->first_minor = minor;
	disk->fops = &drbd_ops;
	sprintf(disk->disk_name, DEVICE_NAME "%d", minor);
	disk->private_data = mdev;
	add_disk(disk);

	mdev->this_bdev = bdget(MKDEV(MAJOR_NR,minor));
	// we have no partitions. we contain only ourselves.
	mdev->this_bdev->bd_contains = mdev->this_bdev;

	blk_queue_make_request(q, drbd_make_request_26);
	blk_queue_merge_bvec(q, drbd_merge_bvec);
	q->queue_lock = &mdev->req_lock; // needed since we use
		// plugging on a queue, that actually has no requests!
	q->unplug_fn = drbd_unplug_fn;

	mdev->md_io_page = alloc_page(GFP_KERNEL);
	if(!mdev->md_io_page) goto Enomem;

	if (drbd_bm_init(mdev)) goto Enomem;
	// no need to lock access, we are still initializing the module.
	if (!tl_init(mdev)) goto Enomem;

	mdev->app_reads_hash=kzalloc(APP_R_HSIZE*sizeof(void*),GFP_KERNEL);
	if (!mdev->app_reads_hash) goto Enomem;

	return mdev;

 Enomem:
	if(mdev) {
		if(mdev->app_reads_hash) kfree(mdev->app_reads_hash);
		if(mdev->md_io_page) __free_page(mdev->md_io_page);
		kfree(mdev);
	}
	return NULL;
}

int __init drbd_init(void)
{
	int err;

#if 0
// warning LGE "DEBUGGING"
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

	if( (err = drbd_nl_init()) ) {
		return err;
	}

	err = register_blkdev(MAJOR_NR, DEVICE_NAME);
	if (err) {
		printk(KERN_ERR DEVICE_NAME
		       ": unable to register block device major %d\n",
		       MAJOR_NR);
		return err;
	}

	register_reboot_notifier(&drbd_notifier);

	/*
	 * allocate all necessary structs
	 */
	err = -ENOMEM;

	init_waitqueue_head(&drbd_pp_wait);

	drbd_proc = NULL; // play safe for drbd_cleanup
	minor_table = kzalloc(sizeof(drbd_dev *)*minor_count,GFP_KERNEL);
	if(!minor_table) goto Enomem;

	if ((err = drbd_create_mempools()))
		goto Enomem;

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

	printk(KERN_INFO DEVICE_NAME ": initialised. "
	       "Version: " REL_VERSION " (api:%d/proto:%d)\n",
	       API_VERSION,PRO_VERSION);
	printk(KERN_INFO DEVICE_NAME ": %s\n", drbd_buildtag());
	printk(KERN_INFO DEVICE_NAME": registered as block device major %d\n", MAJOR_NR);
	printk(KERN_INFO DEVICE_NAME": minor_table @ 0x%p\n", minor_table);

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

	BD_RELEASE(bc->backing_bdev);
	BD_RELEASE(bc->md_bdev);

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
		crypto_free_hash(mdev->cram_hmac_tfm);
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

	// We use here Failed and not Attaching because we try to write
	// metadata even if we detach due to a disk failure!
	if(!inc_local_if_state(mdev,Failed)) return;

	INFO("Writing meta data super block now.\n");

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
		/* this was a try anyways ... */
		ERR("meta data update failed!\n");

		drbd_chk_io_error(mdev, 1, TRUE);
		drbd_io_error(mdev, TRUE);
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

	if(!inc_local_if_state(mdev,Attaching)) return MDIOError;

	down(&mdev->md_io_mutex);
	buffer = (struct meta_data_on_disk *)page_address(mdev->md_io_page);

	if ( ! drbd_md_sync_page_io(mdev,bdev,bdev->md.md_offset,READ) ) {
		/* NOTE: cant do normal error processing here as this is
		   called BEFORE disk is attached */
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


STATIC void drbd_uuid_move_history(drbd_dev *mdev)
{
	int i;

	for ( i=History_start ; i<History_end ; i++ ) {
		mdev->bc->md.uuid[i+1] = mdev->bc->md.uuid[i];

		MTRACE(TraceTypeUuid,TraceLvlAll,
		       drbd_print_uuid(mdev,i+1);
			);
	}
}

void _drbd_uuid_set(drbd_dev *mdev, int idx, u64 val)
{
	if(idx == Current) {
		if (mdev->state.role == Primary) {
			val |= 1;
		} else {
			val &= ~((u64)1);
		}
	}

	mdev->bc->md.uuid[idx] = val;

	MTRACE(TraceTypeUuid,TraceLvlSummary,
	       drbd_print_uuid(mdev,idx);
		);

	drbd_md_mark_dirty(mdev);
}


void drbd_uuid_set(drbd_dev *mdev, int idx, u64 val)
{
	if(mdev->bc->md.uuid[idx]) {
		drbd_uuid_move_history(mdev);
		mdev->bc->md.uuid[History_start]=mdev->bc->md.uuid[idx];
		MTRACE(TraceTypeUuid,TraceLvlMetrics,
		       drbd_print_uuid(mdev,History_start);
			);
	}
	_drbd_uuid_set(mdev,idx,val);
}

void drbd_uuid_new_current(drbd_dev *mdev)
{
	INFO("Creating new current UUID\n");
	D_ASSERT(mdev->bc->md.uuid[Bitmap] == 0);
	mdev->bc->md.uuid[Bitmap] = mdev->bc->md.uuid[Current];
	MTRACE(TraceTypeUuid,TraceLvlMetrics,
	       drbd_print_uuid(mdev,Bitmap);
		);

	get_random_bytes(&mdev->bc->md.uuid[Current], sizeof(u64));
	if (mdev->state.role == Primary) {
		mdev->bc->md.uuid[Current] |= 1;
	} else {
		mdev->bc->md.uuid[Current] &= ~((u64)1);
	}

	MTRACE(TraceTypeUuid,TraceLvlSummary,
	       drbd_print_uuid(mdev,Current);
		);

	drbd_md_mark_dirty(mdev);
}

void drbd_uuid_set_bm(drbd_dev *mdev, u64 val)
{
	if( mdev->bc->md.uuid[Bitmap]==0 && val==0 ) return;

	if(val==0) {
		drbd_uuid_move_history(mdev);
		mdev->bc->md.uuid[History_start]=mdev->bc->md.uuid[Bitmap];
		mdev->bc->md.uuid[Bitmap]=0;

		MTRACE(TraceTypeUuid,TraceLvlMetrics,
		       drbd_print_uuid(mdev,History_start);
		       drbd_print_uuid(mdev,Bitmap);
			);
	} else {
		if( mdev->bc->md.uuid[Bitmap] ) WARN("bm UUID already set");

		mdev->bc->md.uuid[Bitmap] = val;
		mdev->bc->md.uuid[Bitmap] &= ~((u64)1);

		MTRACE(TraceTypeUuid,TraceLvlMetrics,
		       drbd_print_uuid(mdev,Bitmap);
			);
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

	drbd_queue_work_front(&mdev->data.work,&mdev->md_sync_work);
}

STATIC int w_md_sync(drbd_dev *mdev, struct drbd_work *w, int unused)
{
	WARN("md_sync_timer expired! Worker calls drbd_md_sync().\n");
	drbd_md_sync(mdev);

	return 1;
}

#ifdef DRBD_ENABLE_FAULTS
// Fault insertion support including random number generator shamelessly
// stolen from kernel/rcutorture.c
struct fault_random_state {
	unsigned long state;
	unsigned long count;
};

#define FAULT_RANDOM_MULT 39916801  /* prime */
#define FAULT_RANDOM_ADD	479001701 /* prime */
#define FAULT_RANDOM_REFRESH 10000

/*
 * Crude but fast random-number generator.  Uses a linear congruential
 * generator, with occasional help from get_random_bytes().
 */
STATIC unsigned long
_drbd_fault_random(struct fault_random_state *rsp)
{
	long refresh;

	if (--rsp->count < 0) {
		get_random_bytes(&refresh, sizeof(refresh));
		rsp->state += refresh;
		rsp->count = FAULT_RANDOM_REFRESH;
	}
	rsp->state = rsp->state * FAULT_RANDOM_MULT + FAULT_RANDOM_ADD;
	return swahw32(rsp->state);
}

STATIC char *
_drbd_fault_str(unsigned int type) {
	static char *_faults[] = {
		"Meta-data write",
		"Meta-data read",
		"Resync write",
		"Resync read",
		"Data write",
		"Data read",
		"Data read ahead",
	};

	return (type < DRBD_FAULT_MAX)? _faults[type] : "**Unknown**";
}

unsigned int
_drbd_insert_fault(drbd_dev *mdev, unsigned int type)
{
	static struct fault_random_state rrs = {0,0};

	unsigned int ret = (
		(fault_devs == 0 || ((1 << mdev_to_minor(mdev)) & fault_devs) != 0) &&
		(((_drbd_fault_random(&rrs) % 100) + 1) <= fault_rate));

	if (ret) {
		fault_count++;

		if (printk_ratelimit())
			WARN("***Simulating %s failure\n", _drbd_fault_str(type));
	}

	return ret;
}
#endif

#ifdef ENABLE_DYNAMIC_TRACE

STATIC char *_drbd_uuid_str(unsigned int idx) {
	static char *uuid_str[] = {
		"Current",
		"Bitmap",
		"History_start",
		"History_end",
		"UUID_SIZE",
		"UUID_FLAGS",
	};

	return (idx < EXT_UUID_SIZE) ? uuid_str[idx] : "*Unknown UUID index*";
}

/* Pretty print a UUID value */
void
drbd_print_uuid(drbd_dev *mdev, unsigned int idx) {
	INFO(" uuid[%s] now %016llX\n",_drbd_uuid_str(idx),mdev->bc->md.uuid[idx]);
}


/*

drbd_print_buffer

This routine dumps binary data to the debugging output. Can be
called at interrupt level.

Arguments:

    prefix      - String is output at the beginning of each line output
    flags       - Control operation of the routine. Currently defined
                  Flags are:
                  DBGPRINT_BUFFADDR; if set, each line starts with the
                      virtual address of the line being outupt. If clear,
                      each line starts with the offset from the beginning
                      of the buffer.
    size        - Indicates the size of each entry in the buffer. Supported
                  values are sizeof(char), sizeof(short) and sizeof(int)
    buffer      - Start address of buffer
    buffer_va   - Virtual address of start of buffer (normally the same
                  as Buffer, but having it separate allows it to hold
                  file address for example)
    length      - length of buffer

*/
void
drbd_print_buffer(const char *prefix,unsigned int flags,int size,
		  const void *buffer,const void *buffer_va,
		  unsigned int length)

#define LINE_SIZE       16
#define LINE_ENTRIES    (int)(LINE_SIZE/size)
{
	const unsigned char *pstart;
	const unsigned char *pstart_va;
	const unsigned char *pend;
	char bytes_str[LINE_SIZE*3+8],ascii_str[LINE_SIZE+8];
	char *pbytes=bytes_str,*pascii=ascii_str;
	int  offset=0;
	long sizemask;
	int  field_width;
	int  index;
	const unsigned char *pend_str;
	const unsigned char *p;
	int count;

	// verify size parameter
	if (size != sizeof(char) && size != sizeof(short) && size != sizeof(int)) {
		printk(KERN_DEBUG "drbd_print_buffer: ERROR invalid size %d\n", size);
		return;
	}

	sizemask = size-1;
	field_width = size*2;

	// Adjust start/end to be on appropriate boundary for size
	buffer = (const char *)((long)buffer & ~sizemask);
	pend   = (const unsigned char *)(((long)buffer + length + sizemask) & ~sizemask);

	if (flags & DBGPRINT_BUFFADDR) {
		// Move start back to nearest multiple of line size if printing address
		// This results in nicely formatted output with addresses being on
		// line size (16) byte boundaries
		pstart = (const unsigned char *)((long)buffer & ~(LINE_SIZE-1));
	}
	else {
		pstart = (const unsigned char *)buffer;
	}

	// Set value of start VA to print if addresses asked for
	pstart_va = (const unsigned char *)buffer_va - ((const unsigned char *)buffer-pstart);

	// Calculate end position to nicely align right hand side
	pend_str = pstart + (((pend-pstart) + LINE_SIZE-1) & ~(LINE_SIZE-1));

	// Init strings
	*pbytes = *pascii = '\0';

	// Start at beginning of first line
	p = pstart;
	count=0;

	while (p < pend_str) {
		if (p < (const unsigned char *)buffer || p >= pend) {
			// Before start of buffer or after end- print spaces
			pbytes += sprintf(pbytes,"%*c ",field_width,' ');
			pascii += sprintf(pascii,"%*c",size,' ');
			p += size;
		}
		else {
			// Add hex and ascii to strings
			int val;
			switch (size) {
			default:
			case 1:
				val = *(unsigned char *)p;
				break;
			case 2:
				val = *(unsigned short *)p;
				break;
			case 4:
				val = *(unsigned int *)p;
				break;
			}

			pbytes += sprintf(pbytes,"%0*x ",field_width,val);

			for (index = size; index; index--) {
				*pascii++ = isprint(*p) ? *p : '.';
				p++;
			}
		}

		count++;

		if (count == LINE_ENTRIES || p >= pend_str) {
			// Null terminate and print record
			*pascii = '\0';
			printk(KERN_DEBUG "%s%8.8lx: %*s|%*s|\n",
			       prefix,
			       (flags & DBGPRINT_BUFFADDR)
			       ? (long)pstart_va : (long)offset,
			       LINE_ENTRIES*(field_width+1),bytes_str,
			       LINE_SIZE,ascii_str);

			// Move onto next line
			pstart_va += (p-pstart);
			pstart = p;
			count  = 0;
			offset+= LINE_SIZE;

			// Re-init strings
			pbytes = bytes_str;
			pascii = ascii_str;
			*pbytes = *pascii = '\0';
		}
	}
}

#define PSM(A) \
do { \
	if( mask.A ) { \
		int i = snprintf(p, len, " " #A "( %s )", \
				A##s_to_name(val.A)); \
		if (i >= len) return op; \
		p += i; \
		len -= i; \
	} \
} while (0)

STATIC char *dump_st(char *p, int len, drbd_state_t mask, drbd_state_t val)
{
	char *op=p;
	*p = '\0';
	PSM(role);
	PSM(peer);
	PSM(conn);
	PSM(disk);
	PSM(pdsk);

	return op;
}

#define INFOP(fmt, args...) \
do { \
	if (trace_level >= TraceLvlAll) { \
		INFO("%s:%d: %s [%d] %s %s " fmt , \
		     file, line, current->comm, current->pid, \
		     sockname, recv?"<<<":">>>", \
		     ## args ); \
	} \
	else { \
		INFO("%s %s " fmt, sockname, \
		     recv?"<<<":">>>", \
		     ## args ); \
	} \
} while (0)

char *_dump_block_id(u64 block_id, char *buff) {
    if (is_syncer_block_id(block_id))
	strcpy(buff,"SyncerId");
    else
	sprintf(buff,"%llx",block_id);

    return buff;
}

void
_dump_packet(drbd_dev *mdev, struct socket *sock,
	    int recv, Drbd_Polymorph_Packet *p, char* file, int line)
{
	char *sockname = sock == mdev->meta.socket ? "meta" : "data";
	int cmd = (recv == 2) ? p->head.command : be16_to_cpu(p->head.command);
	char tmp[300];
	drbd_state_t m,v;

	switch (cmd) {
	case HandShake:
		INFOP("%s (protocol %u)\n", cmdname(cmd), be32_to_cpu(p->HandShake.protocol_version));
		break;

	case ReportBitMap: /* don't report this */
		break;

	case Data:
		INFOP("%s (sector %llus, id %s, seq %u, f %x)\n", cmdname(cmd),
		      (unsigned long long)be64_to_cpu(p->Data.sector),
		      _dump_block_id(p->Data.block_id,tmp),
		      be32_to_cpu(p->Data.seq_num),
		      be32_to_cpu(p->Data.dp_flags)
			);
		break;

	case DataReply:
	case RSDataReply:
		INFOP("%s (sector %llus, id %s)\n", cmdname(cmd),
		      (unsigned long long)be64_to_cpu(p->Data.sector),
		      _dump_block_id(p->Data.block_id,tmp)
			);
		break;

	case RecvAck:
	case WriteAck:
	case RSWriteAck:
	case DiscardAck:
	case NegAck:
	case NegRSDReply:
		INFOP("%s (sector %llus, size %u, id %s, seq %u)\n", cmdname(cmd),
		      (long long)be64_to_cpu(p->BlockAck.sector),
		      be32_to_cpu(p->BlockAck.blksize),
		      _dump_block_id(p->BlockAck.block_id,tmp),
		      be32_to_cpu(p->BlockAck.seq_num)
			);
		break;

	case DataRequest:
	case RSDataRequest:
		INFOP("%s (sector %llus, size %u, id %s)\n", cmdname(cmd),
		      (long long)be64_to_cpu(p->BlockRequest.sector),
		      be32_to_cpu(p->BlockRequest.blksize),
		      _dump_block_id(p->BlockRequest.block_id,tmp)
			);
		break;

	case Barrier:
	case BarrierAck:
		INFOP("%s (barrier %u)\n", cmdname(cmd), p->Barrier.barrier);
		break;

	case ReportUUIDs:
		INFOP("%s Curr:%016llX, Bitmap:%016llX, HisSt:%016llX, HisEnd:%016llX\n", cmdname(cmd),
		      be64_to_cpu(p->GenCnt.uuid[Current]),
		      be64_to_cpu(p->GenCnt.uuid[Bitmap]),
		      be64_to_cpu(p->GenCnt.uuid[History_start]),
		      be64_to_cpu(p->GenCnt.uuid[History_end]));
		break;

	case ReportSizes:
		INFOP("%s (d %lluMiB, u %lluMiB, c %lldMiB, max bio %x, q order %x)\n", cmdname(cmd),
		      (long long)(be64_to_cpu(p->Sizes.d_size)>>(20-9)),
		      (long long)(be64_to_cpu(p->Sizes.u_size)>>(20-9)),
		      (long long)(be64_to_cpu(p->Sizes.c_size)>>(20-9)),
		      be32_to_cpu(p->Sizes.max_segment_size),
		      be32_to_cpu(p->Sizes.queue_order_type));
		break;

	case ReportState:
		v.i = be32_to_cpu(p->State.state);
		m.i = 0xffffffff;
		dump_st(tmp,sizeof(tmp),m,v);
		INFOP("%s (s %x {%s})\n", cmdname(cmd), v.i, tmp);
		break;

	case StateChgRequest:
		m.i = be32_to_cpu(p->ReqState.mask);
		v.i = be32_to_cpu(p->ReqState.val);
		dump_st(tmp,sizeof(tmp),m,v);
		INFOP("%s (m %x v %x {%s})\n", cmdname(cmd), m.i, v.i, tmp);
		break;

	case StateChgReply:
		INFOP("%s (ret %x)\n", cmdname(cmd),
		      be32_to_cpu(p->RqSReply.retcode));
		break;

	case Ping:
	case PingAck:
		/*
		 * Dont trace pings at summary level
		 */
		if (trace_level < TraceLvlAll)
			break;
		/* fall through... */
	default:
		INFOP("%s (%u)\n",cmdname(cmd), cmd);
		break;
	}
}

// Debug routine to dump info about bio

void _dump_bio(const char *pfx, drbd_dev *mdev, struct bio *bio, int complete)
{
#ifdef CONFIG_LBD
#define SECTOR_FORMAT "%Lx"
#else
#define SECTOR_FORMAT "%lx"
#endif
#define SECTOR_SHIFT 9

	unsigned long lowaddr = (unsigned long)(bio->bi_sector << SECTOR_SHIFT);
	char *faddr = (char *)(lowaddr);
	struct bio_vec *bvec;
	int segno;

	const int rw = bio->bi_rw;
	const int biorw      = (rw & (RW_MASK|RWA_MASK));
	const int biobarrier = (rw & (1<<BIO_RW_BARRIER));
	const int biosync    = (rw & (1<<BIO_RW_SYNC));

	INFO("%s %s:%s%s%s Bio:%p - %soffset " SECTOR_FORMAT ", size %x\n",
	     complete? "<<<":">>>",
	     pfx,
	     biorw==WRITE?"Write":"Read",
	     biobarrier?":B":"",
	     biosync?":S":"",
	     bio,
	     complete? (drbd_bio_uptodate(bio)? "Success, ":"Failed, ") : "",
	     bio->bi_sector << SECTOR_SHIFT,
	     bio->bi_size);

	if (trace_level >= TraceLvlMetrics &&
	    ((biorw == WRITE) ^ complete) ) {
		printk(KERN_DEBUG "  ind     page   offset   length\n");
		__bio_for_each_segment(bvec, bio, segno, 0) {
			printk(KERN_DEBUG "  [%d] %p %8.8x %8.8x\n",segno,
			       bvec->bv_page, bvec->bv_offset, bvec->bv_len);

			if (trace_level >= TraceLvlAll) {
				char *bvec_buf;
				unsigned long flags;

				bvec_buf = bvec_kmap_irq(bvec, &flags);

				drbd_print_buffer("    ",DBGPRINT_BUFFADDR,1,
						  bvec_buf,
						  faddr,
						  (bvec->bv_len <= 0x80)? bvec->bv_len : 0x80);

				bvec_kunmap_irq(bvec_buf, &flags);

				if (bvec->bv_len > 0x40)
					printk(KERN_DEBUG "    ....\n");

				faddr += bvec->bv_len;
			}
		}
	}
}
#endif

module_init(drbd_init)
module_exit(drbd_cleanup)
