/*
   drbd_main.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   Thanks to Carter Burden, Bart Grantham and Gennadiy Nerubayev
   from Logicworks, Inc. for making SDP replication support possible.


 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/jiffies.h>
#include <linux/drbd.h>
#include <linux/uaccess.h>
#include <asm/types.h>
#include <net/sock.h>
#include <linux/ctype.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/mm_inline.h>
#include <linux/slab.h>
#include <linux/crc32c.h>
#include <linux/reboot.h>
#include <linux/notifier.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#define __KERNEL_SYSCALLS__
#include <linux/unistd.h>
#include <linux/vmalloc.h>
#include <linux/device.h>
#include <linux/dynamic_debug.h>
#include <linux/libnvdimm.h>
#include <linux/swab.h>

#include <linux/drbd_limits.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_vli.h"
#include "drbd_debugfs.h"
#include "drbd_meta_data.h"
#include "drbd_dax_pmem.h"

static int drbd_open(struct block_device *bdev, fmode_t mode);
static void drbd_release(struct gendisk *gd, fmode_t mode);
static void md_sync_timer_fn(struct timer_list *t);
static int w_bitmap_io(struct drbd_work *w, int unused);
static int flush_send_buffer(struct drbd_connection *connection, enum drbd_stream drbd_stream);
static u64 __set_bitmap_slots(struct drbd_device *device, u64 bitmap_uuid, u64 do_nodes) __must_hold(local);
static u64 __test_bitmap_slots(struct drbd_device *device) __must_hold(local);

MODULE_AUTHOR("Philipp Reisner <phil@linbit.com>, "
	      "Lars Ellenberg <lars@linbit.com>");
MODULE_DESCRIPTION("drbd - Distributed Replicated Block Device v" REL_VERSION);
MODULE_VERSION(REL_VERSION);
MODULE_LICENSE("GPL");
MODULE_PARM_DESC(minor_count, "Approximate number of drbd devices ("
		 __stringify(DRBD_MINOR_COUNT_MIN) "-" __stringify(DRBD_MINOR_COUNT_MAX) ")");
MODULE_ALIAS_BLOCKDEV_MAJOR(DRBD_MAJOR);

#include <linux/moduleparam.h>

#ifdef CONFIG_DRBD_FAULT_INJECTION
int drbd_enable_faults;
int drbd_fault_rate;
static int drbd_fault_count;
static int drbd_fault_devs;

/* bitmap of enabled faults */
module_param_named(enable_faults, drbd_enable_faults, int, 0664);
/* fault rate % value - applies to all enabled faults */
module_param_named(fault_rate, drbd_fault_rate, int, 0664);
/* count of faults inserted */
module_param_named(fault_count, drbd_fault_count, int, 0664);
/* bitmap of devices to insert faults on */
module_param_named(fault_devs, drbd_fault_devs, int, 0644);
#endif

/* module parameters we can keep static */
static bool drbd_disable_sendpage;
static bool drbd_allow_oos; /* allow_open_on_secondary */
MODULE_PARM_DESC(allow_oos, "DONT USE!");
module_param_named(disable_sendpage, drbd_disable_sendpage, bool, 0644);
module_param_named(allow_oos, drbd_allow_oos, bool, 0);

/* module parameters shared with defaults */
unsigned int drbd_minor_count = DRBD_MINOR_COUNT_DEF;
/* Module parameter for setting the user mode helper program
 * to run. Default is /sbin/drbdadm */
char drbd_usermode_helper[80] = "/sbin/drbdadm";
module_param_named(minor_count, drbd_minor_count, uint, 0444);
module_param_string(usermode_helper, drbd_usermode_helper, sizeof(drbd_usermode_helper), 0644);

static int param_set_drbd_protocol_version(const char *s, const struct kernel_param *kp)
{
	unsigned long long tmp;
	unsigned int *res = kp->arg;
	int rv;

	rv = kstrtoull(s, 0, &tmp);
	if (rv < 0)
		return rv;
	if (tmp < PRO_VERSION_MIN || tmp > PRO_VERSION_MAX)
		return -ERANGE;
	*res = tmp;
	return 0;
}

#define param_check_drbd_protocol_version	param_check_uint
#define param_get_drbd_protocol_version		param_get_uint

const struct kernel_param_ops param_ops_drbd_protocol_version = {
	.set = param_set_drbd_protocol_version,
	.get = param_get_drbd_protocol_version,
};

unsigned int drbd_protocol_version_min = PRO_VERSION_MIN;
module_param_named(protocol_version_min, drbd_protocol_version_min, drbd_protocol_version, 0644);


/* in 2.6.x, our device mapping and config info contains our virtual gendisks
 * as member "struct gendisk *vdisk;"
 */
struct idr drbd_devices;
struct list_head drbd_resources;

struct kmem_cache *drbd_request_cache;
struct kmem_cache *drbd_ee_cache;	/* peer requests */
struct kmem_cache *drbd_bm_ext_cache;	/* bitmap extents */
struct kmem_cache *drbd_al_ext_cache;	/* activity log extents */
mempool_t drbd_request_mempool;
mempool_t drbd_ee_mempool;
mempool_t drbd_md_io_page_pool;
struct bio_set drbd_md_io_bio_set;
struct bio_set drbd_io_bio_set;

static const struct block_device_operations drbd_ops = {
	.owner		= THIS_MODULE,
	.submit_bio	= drbd_submit_bio,
	.open		= drbd_open,
	.release	= drbd_release,
};

struct bio *bio_alloc_drbd(gfp_t gfp_mask)
{
	if (!bioset_initialized(&drbd_md_io_bio_set))
		return bio_alloc(gfp_mask, 1);

	return bio_alloc_bioset(gfp_mask, 1, &drbd_md_io_bio_set);
}

#ifdef __CHECKER__
/* When checking with sparse, and this is an inline function, sparse will
   give tons of false positives. When this is a real functions sparse works.
 */
int _get_ldev_if_state(struct drbd_device *device, enum drbd_disk_state mins)
{
	int io_allowed;

	atomic_inc(&device->local_cnt);
	io_allowed = (device->disk_state[NOW] >= mins);
	if (!io_allowed) {
		if (atomic_dec_and_test(&device->local_cnt))
			wake_up(&device->misc_wait);
	}
	return io_allowed;
}

#endif

struct drbd_connection *__drbd_next_connection_ref(u64 *visited,
						   struct drbd_connection *connection,
						   struct drbd_resource *resource)
{
	int node_id;

	rcu_read_lock();
	if (!connection) {
		connection = list_first_or_null_rcu(&resource->connections,
						    struct drbd_connection,
						    connections);
		*visited = 0;
	} else {
		struct list_head *pos;
		bool previous_visible; /* on the resources connections list */

		pos = list_next_rcu(&connection->connections);
		/* follow the pointer first, then check if the previous element was
		   still an element on the list of visible connections. */
		smp_rmb();
		previous_visible = !test_bit(C_UNREGISTERED, &connection->flags);

		kref_debug_put(&connection->kref_debug, 13);
		kref_put(&connection->kref, drbd_destroy_connection);

		if (pos == &resource->connections) {
			connection = NULL;
		} else if (previous_visible) {	/* visible -> we are now on a vital element */
			connection = list_entry_rcu(pos, struct drbd_connection, connections);
		} else { /* not visible -> pos might point to a dead element now */
			for_each_connection_rcu(connection, resource) {
				node_id = connection->peer_node_id;
				if (!(*visited & NODE_MASK(node_id)))
					goto found;
			}
			connection = NULL;
		}
	}

	if (connection) {
	found:
		node_id = connection->peer_node_id;
		*visited |= NODE_MASK(node_id);

		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 13);
	}

	rcu_read_unlock();
	return connection;
}


struct drbd_peer_device *__drbd_next_peer_device_ref(u64 *visited,
						     struct drbd_peer_device *peer_device,
						     struct drbd_device *device)
{
	rcu_read_lock();
	if (!peer_device) {
		peer_device = list_first_or_null_rcu(&device->peer_devices,
						    struct drbd_peer_device,
						    peer_devices);
		*visited = 0;
	} else {
		struct list_head *pos;
		bool previous_visible;

		pos = list_next_rcu(&peer_device->peer_devices);
		smp_rmb();
		previous_visible = !test_bit(C_UNREGISTERED, &peer_device->connection->flags);

		kref_debug_put(&peer_device->connection->kref_debug, 15);
		kref_put(&peer_device->connection->kref, drbd_destroy_connection);

		if (pos == &device->peer_devices) {
			peer_device = NULL;
		} else if (previous_visible) {
			peer_device = list_entry_rcu(pos, struct drbd_peer_device, peer_devices);
		} else {
			for_each_peer_device_rcu(peer_device, device) {
				if (!(*visited & NODE_MASK(peer_device->node_id)))
					goto found;
			}
			peer_device = NULL;
		}
	}

	if (peer_device) {
	found:
		*visited |= NODE_MASK(peer_device->node_id);

		kref_get(&peer_device->connection->kref);
		kref_debug_get(&peer_device->connection->kref_debug, 15);
	}

	rcu_read_unlock();
	return peer_device;
}

/* This is a list walk that holds a reference on the next element! The
   reason for that is that one of the requests might hold a reference to a
   following request. A _req_mod() that destroys the current req might drop
   the references on the next request as well! I.e. the "save" of a
   list_for_each_entry_safe() element gets destroyed! -- With holding a
   reference that destroy gets delayed as necessary */

#define tl_for_each_req_ref_from(req, next, tl)		\
	for (req = __tl_first_req_ref(&next, req, tl);	\
	     req;					\
	     req = __tl_next_req_ref(&next, req, tl))

#define tl_for_each_req_ref(req, next, tl)				\
	for (req = __tl_first_req_ref(&next,				\
	list_first_entry_or_null(tl, struct drbd_request, tl_requests), \
				      tl);				\
	     req;							\
	     req = __tl_next_req_ref(&next, req, tl))

static struct drbd_request *__tl_first_req_ref(struct drbd_request **pnext,
					       struct drbd_request *req,
					       struct list_head *transfer_log)
{
	if (req) {
		struct drbd_request *next = list_next_entry(req, tl_requests);
		if (&next->tl_requests != transfer_log)
			kref_get(&next->kref);
		*pnext = next;
	}
	return req;
}

static struct drbd_request *__tl_next_req_ref(struct drbd_request **pnext,
					      struct drbd_request *req,
					      struct list_head *transfer_log)
{
	struct drbd_request *next = *pnext;
	bool next_is_head = (&next->tl_requests == transfer_log);

	do {
		if (next_is_head)
			return NULL;
		req = next;
		next = list_next_entry(req, tl_requests);
		next_is_head = (&next->tl_requests == transfer_log);
		if (!next_is_head)
			kref_get(&next->kref);
	} while (kref_put(&req->kref, drbd_req_destroy));
	*pnext = next;
	return req;
}

static void tl_abort_for_each_req_ref(struct drbd_request *next, struct list_head *transfer_log)
{
	if (&next->tl_requests != transfer_log)
		kref_put(&next->kref, drbd_req_destroy);
}

/**
 * tl_release() - mark as BARRIER_ACKED all requests in the corresponding transfer log epoch
 * @device:	DRBD device.
 * @o_block_id: "block id" aka expected pointer address of the oldest request
 * @y_block_id: "block id" aka expected pointer address of the youngest request
 *		confirmed to be on stable storage.
 * @barrier_nr:	Expected identifier of the DRBD write barrier packet.
 * @set_size:	Expected number of requests before that barrier, respectively
 *		number of requests in the interval [o_block_id;y_block_id]
 *
 * Called for both P_BARRIER_ACK and P_CONFIRM_STABLE,
 * which is similar to an unsolicited partial barrier ack.
 *
 * Either barrier_nr (for barrier acks) or both o_block_id and y_blockid (for
 * confirm stable) are given.  For barrier acks, all requests in the epoch
 * designated by "barrier_nr" are confirmed to be on stable storage.
 *
 * For confirm stable, both o_block_id and y_block_id are given, barrier_nr is
 * ignored, and all requests from "o_block_id" up to and including y_block_id
 * are confirmed to be on stable storage on the reporting peer.
 *
 * In case the passed barrier_nr or set_size does not match the oldest
 * epoch of not yet barrier-acked requests, this function will cause a
 * termination of the connection.
 */
void tl_release(struct drbd_connection *connection,
		uint64_t o_block_id,
		uint64_t y_block_id,
		unsigned int barrier_nr,
		unsigned int set_size)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_request *r;
	struct drbd_request *req = NULL;
	struct drbd_request *req_y = NULL;
	int expect_epoch = 0;
	int expect_size = 0;
	const int idx = connection->peer_node_id;

	spin_lock_irq(&resource->req_lock);

	/* find oldest not yet barrier-acked write request,
	 * count writes in its epoch. */
	list_for_each_entry(r, &resource->transfer_log, tl_requests) {
		if (!req) {
			if (!(r->local_rq_state & RQ_WRITE))
				continue;
			if (!(r->net_rq_state[idx] & RQ_NET_MASK))
				continue;
			if (r->net_rq_state[idx] & RQ_NET_DONE)
				continue;
			req = r;
			expect_epoch = req->epoch;
			expect_size ++;
		} else {
			const u16 s = r->net_rq_state[idx];
			if (r->epoch != expect_epoch)
				break;
			if (!(r->local_rq_state & RQ_WRITE))
				continue;
			/* probably a "send_out_of_sync", during Ahead/Behind mode,
			 * while at least one volume already started to resync again.
			 * I'd very much prefer these to be in their own epoch,
			 * or better yet, "simultaneously" go from Ahead/Behind -> SyncSource/SyncTarget
			 * but that is currently not the case. FIXME.
			 */
			if ((s & RQ_NET_MASK) && !(s & RQ_EXP_BARR_ACK))
				continue;
			if (s & RQ_NET_DONE || (s & RQ_NET_MASK) == 0) {
				drbd_warn(connection, "unexpected state flags: 0x%x during BarrierAck #%u\n",
					s, barrier_nr);
			}
			expect_size++;
		}
		if (y_block_id && (struct drbd_request*)(unsigned long)y_block_id == r) {
			req_y = r;
			break;
		}
	}

	/* first some paranoia code */
	if (o_block_id) {
		if ((struct drbd_request*)(unsigned long)o_block_id != req) {
			drbd_err(connection, "BAD! ConfirmedStable: expected %p, found %p\n",
				(struct drbd_request*)(unsigned long)o_block_id, req);
			goto bail;
		}
		if (!req_y) {
			drbd_err(connection, "BAD! ConfirmedStable: expected youngest request %p NOT found\n",
				(struct drbd_req*)(unsigned long)y_block_id);
			goto bail;
		}
		/* A P_CONFIRM_STABLE cannot tell me the to-be-expected barrier nr,
		 * it does not know it yet. But we just confirmed it knew the
		 * expected request, so just use that one. */
		barrier_nr = expect_epoch;
		/* Both requests referenced must be in the same epoch. */
		if (req_y->epoch != expect_epoch) {
			drbd_err(connection, "BAD! ConfirmedStable: reported requests not in the same epoch (%u != %u)\n",
				req->epoch, req_y->epoch);
			goto bail;
		}
	}
	if (req == NULL) {
		drbd_err(connection, "BAD! BarrierAck #%u received, but no epoch in tl!?\n",
			 barrier_nr);
		goto bail;
	}
	if (expect_epoch != barrier_nr) {
		drbd_err(connection, "BAD! BarrierAck #%u received, expected #%u!\n",
			 barrier_nr, expect_epoch);
		goto bail;
	}

	if (expect_size != set_size) {
		if (!o_block_id) {
			drbd_err(connection, "BAD! BarrierAck #%u received with n_writes=%u, expected n_writes=%u!\n",
				 barrier_nr, set_size, expect_size);
#if 0
/* DEBUGGING AID */
			list_for_each_entry(req, &resource->transfer_log, tl_requests)
				if (req->epoch == expect_epoch)
					break;
			list_for_each_entry_from(req, &resource->transfer_log, tl_requests) {
				if (req->epoch != expect_epoch)
					break;
				drbd_info(req->device, "XXX %u %llu+%u 0x%x 0x%x\n",
					req->epoch,
					(unsigned long long)req->i.sector, req->i.size >> 9,
					req->local_rq_state, req->net_rq_state[idx]
				);
			}
#endif
		} else
			drbd_err(connection, "BAD! ConfirmedStable [%p,%p] received with n_writes=%u, expected n_writes=%u!\n",
				 req, req_y, set_size, expect_size);
		goto bail;
	}

	/* Clean up list of requests processed during current epoch. */
	/* this extra list walk restart is paranoia,
	 * to catch requests being barrier-acked "unexpectedly".
	 * It usually should find the same req again, or some READ preceding it. */
	list_for_each_entry(req, &resource->transfer_log, tl_requests)
		if (req->epoch == expect_epoch)
			break;
	tl_for_each_req_ref_from(req, r, &resource->transfer_log) {
		struct drbd_peer_device *peer_device;
		if (req->epoch != expect_epoch) {
			tl_abort_for_each_req_ref(r, &resource->transfer_log);
			break;
		}
		peer_device = conn_peer_device(connection, req->device->vnr);
		_req_mod(req, BARRIER_ACKED, peer_device);
		if (req == req_y) {
			tl_abort_for_each_req_ref(r, &resource->transfer_log);
			break;
		}
	}
	spin_unlock_irq(&resource->req_lock);

	/* urgently flush out peer acks for P_CONFIRM_STABLE */
	if (req_y) {
		drbd_flush_peer_acks(resource);
	} else if (barrier_nr == connection->send.last_sent_epoch_nr) {
		clear_bit(BARRIER_ACK_PENDING, &connection->flags);
		wake_up(&resource->barrier_wait);
	}

	return;

bail:
	spin_unlock_irq(&resource->req_lock);
	change_cstate(connection, C_PROTOCOL_ERROR, CS_HARD);
}


/**
 * _tl_walk() - Walks the transfer log, and applies an action to all requests
 * @connection:	DRBD connection to operate on.
 * @what:       The action/event to perform with all request objects
 *
 * @what might be one of CONNECTION_LOST_WHILE_PENDING, RESEND, FAIL_FROZEN_DISK_IO,
 * COMPLETION_RESUMED.
 */
/* must hold resource->req_lock */
void __tl_walk(struct drbd_resource *const resource,
		struct drbd_connection *const connection,
		const enum drbd_req_event what)
{
	struct drbd_peer_device *peer_device;
	struct drbd_request *req, *r;

	tl_for_each_req_ref(req, r, &resource->transfer_log) {
		peer_device = connection == NULL ? NULL :
			conn_peer_device(connection, req->device->vnr);
		_req_mod(req, what, peer_device);
	}
}

void _tl_walk(struct drbd_connection *connection, enum drbd_req_event what)
{
	__tl_walk(connection->resource, connection, what);
}

void tl_walk(struct drbd_connection *connection, enum drbd_req_event what)
{
	struct drbd_resource *resource = connection->resource;

	spin_lock_irq(&resource->req_lock);
	_tl_walk(connection, what);
	spin_unlock_irq(&resource->req_lock);
}

/**
 * tl_abort_disk_io() - Abort disk I/O for all requests for a certain device in the TL
 * @device:     DRBD device.
 */
void tl_abort_disk_io(struct drbd_device *device)
{
        struct drbd_resource *resource = device->resource;
        struct drbd_request *req, *r;

        spin_lock_irq(&resource->req_lock);
        tl_for_each_req_ref(req, r, &resource->transfer_log) {
                if (!(req->local_rq_state & RQ_LOCAL_PENDING))
                        continue;
                if (req->device != device)
                        continue;
                _req_mod(req, ABORT_DISK_IO, NULL);
        }
        spin_unlock_irq(&resource->req_lock);
}

static int drbd_thread_setup(void *arg)
{
	struct drbd_thread *thi = (struct drbd_thread *) arg;
	struct drbd_resource *resource = thi->resource;
	struct drbd_connection *connection = thi->connection;
	unsigned long flags;
	int retval;

	allow_kernel_signal(DRBD_SIGKILL);
	allow_kernel_signal(SIGXCPU);

	if (connection)
		kref_get(&connection->kref);
	else
		kref_get(&resource->kref);
restart:
	retval = thi->function(thi);

	spin_lock_irqsave(&thi->t_lock, flags);

	/* if the receiver has been "EXITING", the last thing it did
	 * was set the conn state to "StandAlone",
	 * if now a re-connect request comes in, conn state goes C_UNCONNECTED,
	 * and receiver thread will be "started".
	 * drbd_thread_start needs to set "RESTARTING" in that case.
	 * t_state check and assignment needs to be within the same spinlock,
	 * so either thread_start sees EXITING, and can remap to RESTARTING,
	 * or thread_start see NONE, and can proceed as normal.
	 */

	if (thi->t_state == RESTARTING) {
		if (connection)
			drbd_info(connection, "Restarting %s thread\n", thi->name);
		else
			drbd_info(resource, "Restarting %s thread\n", thi->name);
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		flush_signals(current); /* likely it got a signal to look at t_state... */
		goto restart;
	}

	thi->task = NULL;
	thi->t_state = NONE;
	smp_mb();

	if (connection)
		drbd_info(connection, "Terminating %s thread\n", thi->name);
	else
		drbd_info(resource, "Terminating %s thread\n", thi->name);

	complete(&thi->stop);
	spin_unlock_irqrestore(&thi->t_lock, flags);

	if (connection)
		kref_put(&connection->kref, drbd_destroy_connection);
	else
		kref_put(&resource->kref, drbd_destroy_resource);

	return retval;
}

static void drbd_thread_init(struct drbd_resource *resource, struct drbd_thread *thi,
			     int (*func) (struct drbd_thread *), const char *name)
{
	spin_lock_init(&thi->t_lock);
	thi->task    = NULL;
	thi->t_state = NONE;
	thi->function = func;
	thi->resource = resource;
	thi->connection = NULL;
	thi->name = name;
}

int drbd_thread_start(struct drbd_thread *thi)
{
	struct drbd_resource *resource = thi->resource;
	struct drbd_connection *connection = thi->connection;
	struct task_struct *nt;
	unsigned long flags;

	/* is used from state engine doing drbd_thread_stop_nowait,
	 * while holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	switch (thi->t_state) {
	case NONE:
		if (connection)
			drbd_info(connection, "Starting %s thread (from %s [%d])\n",
				 thi->name, current->comm, current->pid);
		else
			drbd_info(resource, "Starting %s thread (from %s [%d])\n",
				 thi->name, current->comm, current->pid);

		init_completion(&thi->stop);
		D_ASSERT(resource, thi->task == NULL);
		thi->reset_cpu_mask = 1;
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		flush_signals(current); /* otherw. may get -ERESTARTNOINTR */

		nt = kthread_create(drbd_thread_setup, (void *) thi,
				    "drbd_%c_%s", thi->name[0], resource->name);

		if (IS_ERR(nt)) {
			if (connection)
				drbd_err(connection, "Couldn't start thread\n");
			else
				drbd_err(resource, "Couldn't start thread\n");

			return false;
		}
		spin_lock_irqsave(&thi->t_lock, flags);
		thi->task = nt;
		thi->t_state = RUNNING;
		spin_unlock_irqrestore(&thi->t_lock, flags);
		wake_up_process(nt);
		break;
	case EXITING:
		thi->t_state = RESTARTING;
		if (connection)
			drbd_info(connection, "Restarting %s thread (from %s [%d])\n",
					thi->name, current->comm, current->pid);
		else
			drbd_info(resource, "Restarting %s thread (from %s [%d])\n",
					thi->name, current->comm, current->pid);
		fallthrough;
	case RUNNING:
	case RESTARTING:
	default:
		spin_unlock_irqrestore(&thi->t_lock, flags);
		break;
	}

	return true;
}


void _drbd_thread_stop(struct drbd_thread *thi, int restart, int wait)
{
	unsigned long flags;

	enum drbd_thread_state ns = restart ? RESTARTING : EXITING;

	/* may be called from state engine, holding the req lock irqsave */
	spin_lock_irqsave(&thi->t_lock, flags);

	if (thi->t_state == NONE) {
		spin_unlock_irqrestore(&thi->t_lock, flags);
		if (restart)
			drbd_thread_start(thi);
		return;
	}

	if (thi->t_state == EXITING && ns == RESTARTING) {
		/* Do not abort a stop request, otherwise a waiter might never wake up */
		spin_unlock_irqrestore(&thi->t_lock, flags);
		return;
	}

	if (thi->t_state != ns) {
		if (thi->task == NULL) {
			spin_unlock_irqrestore(&thi->t_lock, flags);
			return;
		}

		thi->t_state = ns;
		smp_mb();
		init_completion(&thi->stop);
		if (thi->task != current)
			send_sig(DRBD_SIGKILL, thi->task, 1);
	}
	spin_unlock_irqrestore(&thi->t_lock, flags);

	if (wait)
		wait_for_completion(&thi->stop);
}

#ifdef CONFIG_SMP
/**
 * drbd_calc_cpu_mask() - Generate CPU masks, spread over all CPUs
 *
 * Forces all threads of a resource onto the same CPU. This is beneficial for
 * DRBD's performance. May be overwritten by user's configuration.
 */
static void drbd_calc_cpu_mask(cpumask_var_t *cpu_mask)
{
	unsigned int *resources_per_cpu, min_index = ~0;

	resources_per_cpu = kzalloc(nr_cpu_ids * sizeof(*resources_per_cpu), GFP_KERNEL);
	if (resources_per_cpu) {
		struct drbd_resource *resource;
		unsigned int cpu, min = ~0;

		rcu_read_lock();
		for_each_resource_rcu(resource, &drbd_resources) {
			for_each_cpu(cpu, resource->cpu_mask)
				resources_per_cpu[cpu]++;
		}
		rcu_read_unlock();
		for_each_online_cpu(cpu) {
			if (resources_per_cpu[cpu] < min) {
				min = resources_per_cpu[cpu];
				min_index = cpu;
			}
		}
		kfree(resources_per_cpu);
	}
	if (min_index == ~0) {
		cpumask_setall(*cpu_mask);
		return;
	}
	cpumask_set_cpu(min_index, *cpu_mask);
}

/**
 * drbd_thread_current_set_cpu() - modifies the cpu mask of the _current_ thread
 * @device:	DRBD device.
 * @thi:	drbd_thread object
 *
 * call in the "main loop" of _all_ threads, no need for any mutex, current won't die
 * prematurely.
 */
void drbd_thread_current_set_cpu(struct drbd_thread *thi)
{
	struct drbd_resource *resource = thi->resource;
	struct task_struct *p = current;

	if (!thi->reset_cpu_mask)
		return;
	thi->reset_cpu_mask = 0;
	set_cpus_allowed_ptr(p, resource->cpu_mask);
}
#else
#define drbd_calc_cpu_mask(A) ({})
#endif

static bool drbd_all_neighbor_secondary(struct drbd_device *device, u64 *authoritative_ptr)
{
	struct drbd_peer_device *peer_device;
	bool all_secondary = true;
	u64 authoritative = 0;
	int id;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED &&
		    peer_device->connection->peer_role[NOW] == R_PRIMARY) {
			all_secondary = false;
			id = peer_device->node_id;
			authoritative |= NODE_MASK(id);
		}
	}
	rcu_read_unlock();
	if (authoritative_ptr)
		*authoritative_ptr = authoritative;
	return all_secondary;
}

/* This function is supposed to have the same semantics as calc_device_stable() in drbd_state.c
   A primary is stable since it is authoritative.
   Unstable are neighbors of a primary and resync target nodes.
   Nodes further away from a primary are stable! */
bool drbd_device_stable(struct drbd_device *device, u64 *authoritative_ptr)
{
	struct drbd_resource *resource = device->resource;
	bool device_stable = true;

	if (resource->role[NOW] == R_PRIMARY)
		return true;

	if (!drbd_all_neighbor_secondary(device, authoritative_ptr))
		return false;

	return device_stable;
}

/**
 * drbd_header_size  -  size of a packet header
 *
 * The header size is a multiple of 8, so any payload following the header is
 * word aligned on 64-bit architectures.  (The bitmap send and receive code
 * relies on this.)
 */
unsigned int drbd_header_size(struct drbd_connection *connection)
{
	if (connection->agreed_pro_version >= 100) {
		BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct p_header100), 8));
		return sizeof(struct p_header100);
	} else {
		BUILD_BUG_ON(sizeof(struct p_header80) !=
			     sizeof(struct p_header95));
		BUILD_BUG_ON(!IS_ALIGNED(sizeof(struct p_header80), 8));
		return sizeof(struct p_header80);
	}
}

static void prepare_header80(struct p_header80 *h, enum drbd_packet cmd, int size)
{
	h->magic   = cpu_to_be32(DRBD_MAGIC);
	h->command = cpu_to_be16(cmd);
	h->length  = cpu_to_be16(size - sizeof(struct p_header80));
}

static void prepare_header95(struct p_header95 *h, enum drbd_packet cmd, int size)
{
	h->magic   = cpu_to_be16(DRBD_MAGIC_BIG);
	h->command = cpu_to_be16(cmd);
	h->length = cpu_to_be32(size - sizeof(struct p_header95));
}

static void prepare_header100(struct p_header100 *h, enum drbd_packet cmd,
				      int size, int vnr)
{
	h->magic = cpu_to_be32(DRBD_MAGIC_100);
	h->volume = cpu_to_be16(vnr);
	h->command = cpu_to_be16(cmd);
	h->length = cpu_to_be32(size - sizeof(struct p_header100));
	h->pad = 0;
}

static void prepare_header(struct drbd_connection *connection, int vnr,
			   void *buffer, enum drbd_packet cmd, int size)
{
	if (connection->agreed_pro_version >= 100)
		prepare_header100(buffer, cmd, size, vnr);
	else if (connection->agreed_pro_version >= 95 &&
		 size > DRBD_MAX_SIZE_H80_PACKET)
		prepare_header95(buffer, cmd, size);
	else
		prepare_header80(buffer, cmd, size);
}

static void new_or_recycle_send_buffer_page(struct drbd_send_buffer *sbuf)
{
	while (1) {
		struct page *page;
		int count = page_count(sbuf->page);

		BUG_ON(count == 0);
		if (count == 1)
			goto have_page;

		page = alloc_page(GFP_NOIO | __GFP_NORETRY | __GFP_NOWARN);
		if (page) {
			put_page(sbuf->page);
			sbuf->page = page;
			goto have_page;
		}

		schedule_timeout_uninterruptible(HZ / 10);
	}
have_page:
	sbuf->unsent =
	sbuf->pos = page_address(sbuf->page);
}

static char *alloc_send_buffer(struct drbd_connection *connection, int size,
			       enum drbd_stream drbd_stream)
{
	struct drbd_send_buffer *sbuf = &connection->send_buffer[drbd_stream];
	char *page_start = page_address(sbuf->page);

	if (sbuf->pos - page_start + size > PAGE_SIZE) {
		flush_send_buffer(connection, drbd_stream);
		new_or_recycle_send_buffer_page(sbuf);
	}

	sbuf->allocated_size = size;
	sbuf->additional_size = 0;

	return sbuf->pos;
}

/* Only used the shrink the previously allocated size. */
static void resize_prepared_command(struct drbd_connection *connection,
				    enum drbd_stream drbd_stream,
				    int size)
{
	connection->send_buffer[drbd_stream].allocated_size =
		size + drbd_header_size(connection);
}

static void additional_size_command(struct drbd_connection *connection,
				    enum drbd_stream drbd_stream,
				    int additional_size)
{
	connection->send_buffer[drbd_stream].additional_size = additional_size;
}

void *__conn_prepare_command(struct drbd_connection *connection, int size,
				    enum drbd_stream drbd_stream)
{
	struct drbd_transport *transport = &connection->transport;
	int header_size;

	if (connection->cstate[NOW] < C_CONNECTING)
		return NULL;

	if (!transport->ops->stream_ok(transport, drbd_stream))
		return NULL;

	header_size = drbd_header_size(connection);
	return alloc_send_buffer(connection, header_size + size, drbd_stream) + header_size;
}

/**
 * conn_prepare_command() - Allocate a send buffer for a packet/command
 * @connection:	the connections the packet will be sent through
 * @size:	number of bytes to allocate
 * @stream:	DATA_STREAM or CONTROL_STREAM
 *
 * This allocates a buffer with capacity to hold the header, and
 * the requested size. Upon success is return a pointer that points
 * to the first byte behind the header. The caller is expected to
 * call xxx_send_command() soon.
 */
void *conn_prepare_command(struct drbd_connection *connection, int size,
			   enum drbd_stream drbd_stream)
{
	void *p;

	mutex_lock(&connection->mutex[drbd_stream]);
	p = __conn_prepare_command(connection, size, drbd_stream);
	if (!p)
		mutex_unlock(&connection->mutex[drbd_stream]);

	return p;
}

/**
 * drbd_prepare_command() - Allocate a send buffer for a packet/command
 * @connection:	the connections the packet will be sent through
 * @size:	number of bytes to allocate
 * @stream:	DATA_STREAM or CONTROL_STREAM
 *
 * This allocates a buffer with capacity to hold the header, and
 * the requested size. Upon success is return a pointer that points
 * to the first byte behind the header. The caller is expected to
 * call xxx_send_command() soon.
 */
void *drbd_prepare_command(struct drbd_peer_device *peer_device, int size, enum drbd_stream drbd_stream)
{
	return conn_prepare_command(peer_device->connection, size, drbd_stream);
}

static int flush_send_buffer(struct drbd_connection *connection, enum drbd_stream drbd_stream)
{
	struct drbd_send_buffer *sbuf = &connection->send_buffer[drbd_stream];
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	int msg_flags, err, offset, size;

	size = sbuf->pos - sbuf->unsent + sbuf->allocated_size;
	if (size == 0)
		return 0;

	if (drbd_stream == DATA_STREAM) {
		rcu_read_lock();
		connection->transport.ko_count = rcu_dereference(connection->transport.net_conf)->ko_count;
		rcu_read_unlock();
	}

	msg_flags = sbuf->additional_size ? MSG_MORE : 0;
	offset = sbuf->unsent - (char *)page_address(sbuf->page);
	err = tr_ops->send_page(transport, drbd_stream, sbuf->page, offset, size, msg_flags);
	if (!err) {
		sbuf->unsent =
		sbuf->pos += sbuf->allocated_size;      /* send buffer submitted! */
	}

	sbuf->allocated_size = 0;

	return err;
}

int __send_command(struct drbd_connection *connection, int vnr,
			  enum drbd_packet cmd, enum drbd_stream drbd_stream)
{
	struct drbd_send_buffer *sbuf = &connection->send_buffer[drbd_stream];
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	bool corked = test_bit(CORKED + drbd_stream, &connection->flags);
	bool flush = (cmd == P_PING || cmd == P_PING_ACK || cmd == P_TWOPC_PREPARE);
	int err;

	/* send P_PING and P_PING_ACK immediately, they need to be delivered as
	   fast as possible.
	   P_TWOPC_PREPARE might be used from the worker context while corked.
	   The work item (connect_work) calls change_cluster_wide_state() which
	   in turn waits for reply packets. -> Need to send it regardless of
	   corking.  */

	if (connection->cstate[NOW] < C_CONNECTING)
		return -EIO;
	prepare_header(connection, vnr, sbuf->pos, cmd,
		       sbuf->allocated_size + sbuf->additional_size);

	if (corked && !flush) {
		sbuf->pos += sbuf->allocated_size;
		sbuf->allocated_size = 0;
		err = 0;
	} else {
		err = flush_send_buffer(connection, drbd_stream);

		/* DRBD protocol "pings" are latency critical.
		 * This is supposed to trigger tcp_push_pending_frames() */
		if (!err && flush)
			tr_ops->hint(transport, drbd_stream, NODELAY);

	}

	return err;
}

void drbd_cork(struct drbd_connection *connection, enum drbd_stream stream)
{
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;

	mutex_lock(&connection->mutex[stream]);
	set_bit(CORKED + stream, &connection->flags);
	/* only call into transport, if we expect it to work */
	if (connection->cstate[NOW] >= C_CONNECTING)
		tr_ops->hint(transport, stream, CORK);
	mutex_unlock(&connection->mutex[stream]);
}

void drbd_uncork(struct drbd_connection *connection, enum drbd_stream stream)
{
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;


	mutex_lock(&connection->mutex[stream]);
	flush_send_buffer(connection, stream);

	clear_bit(CORKED + stream, &connection->flags);
	/* only call into transport, if we expect it to work */
	if (connection->cstate[NOW] >= C_CONNECTING)
		tr_ops->hint(transport, stream, UNCORK);
	mutex_unlock(&connection->mutex[stream]);
}

int send_command(struct drbd_connection *connection, int vnr,
		 enum drbd_packet cmd, enum drbd_stream drbd_stream)
{
	int err;

	err = __send_command(connection, vnr, cmd, drbd_stream);
	mutex_unlock(&connection->mutex[drbd_stream]);
	return err;
}

int drbd_send_command(struct drbd_peer_device *peer_device,
		      enum drbd_packet cmd, enum drbd_stream drbd_stream)
{
	return send_command(peer_device->connection, peer_device->device->vnr,
			    cmd, drbd_stream);
}

int drbd_send_ping(struct drbd_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_PING, CONTROL_STREAM);
}

int drbd_send_ping_ack(struct drbd_connection *connection)
{
	if (!conn_prepare_command(connection, 0, CONTROL_STREAM))
		return -EIO;
	return send_command(connection, -1, P_PING_ACK, CONTROL_STREAM);
}

int drbd_send_peer_ack(struct drbd_connection *connection,
			      struct drbd_request *req)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_connection *c;
	struct p_peer_ack *p;
	u64 mask = 0;

	if (req->local_rq_state & RQ_LOCAL_OK)
		mask |= NODE_MASK(resource->res_opts.node_id);

	rcu_read_lock();
	for_each_connection_rcu(c, resource) {
		int node_id = c->peer_node_id;

		if (req->net_rq_state[node_id] & RQ_NET_OK)
			mask |= NODE_MASK(node_id);
	}
	rcu_read_unlock();

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (!p)
		return -EIO;
	p->mask = cpu_to_be64(mask);
	p->dagtag = cpu_to_be64(req->dagtag_sector);

	return send_command(connection, -1, P_PEER_ACK, CONTROL_STREAM);
}

int drbd_send_sync_param(struct drbd_peer_device *peer_device)
{
	struct p_rs_param_95 *p;
	int size;
	const int apv = peer_device->connection->agreed_pro_version;
	enum drbd_packet cmd;
	struct net_conf *nc;
	struct peer_device_conf *pdc;

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	size = apv <= 87 ? sizeof(struct p_rs_param)
		: apv == 88 ? sizeof(struct p_rs_param)
			+ strlen(nc->verify_alg) + 1
		: apv <= 94 ? sizeof(struct p_rs_param_89)
		: /* apv >= 95 */ sizeof(struct p_rs_param_95);

	cmd = apv >= 89 ? P_SYNC_PARAM89 : P_SYNC_PARAM;
	rcu_read_unlock();

	p = drbd_prepare_command(peer_device, size, DATA_STREAM);
	if (!p)
		return -EIO;

	/* initialize verify_alg and csums_alg */
	memset(p->verify_alg, 0, 2 * SHARED_SECRET_MAX);

	rcu_read_lock();
	nc = rcu_dereference(peer_device->connection->transport.net_conf);

	if (get_ldev(peer_device->device)) {
		pdc = rcu_dereference(peer_device->conf);
		p->resync_rate = cpu_to_be32(pdc->resync_rate);
		p->c_plan_ahead = cpu_to_be32(pdc->c_plan_ahead);
		p->c_delay_target = cpu_to_be32(pdc->c_delay_target);
		p->c_fill_target = cpu_to_be32(pdc->c_fill_target);
		p->c_max_rate = cpu_to_be32(pdc->c_max_rate);
		put_ldev(peer_device->device);
	} else {
		p->resync_rate = cpu_to_be32(DRBD_RESYNC_RATE_DEF);
		p->c_plan_ahead = cpu_to_be32(DRBD_C_PLAN_AHEAD_DEF);
		p->c_delay_target = cpu_to_be32(DRBD_C_DELAY_TARGET_DEF);
		p->c_fill_target = cpu_to_be32(DRBD_C_FILL_TARGET_DEF);
		p->c_max_rate = cpu_to_be32(DRBD_C_MAX_RATE_DEF);
	}

	if (apv >= 88)
		strcpy(p->verify_alg, nc->verify_alg);
	if (apv >= 89)
		strcpy(p->csums_alg, nc->csums_alg);
	rcu_read_unlock();

	return drbd_send_command(peer_device, cmd, DATA_STREAM);
}

int __drbd_send_protocol(struct drbd_connection *connection, enum drbd_packet cmd)
{
	struct p_protocol *p;
	struct net_conf *nc;
	int size, cf;

	if (test_bit(CONN_DRY_RUN, &connection->flags) && connection->agreed_pro_version < 92) {
		clear_bit(CONN_DRY_RUN, &connection->flags);
		drbd_err(connection, "--dry-run is not supported by peer");
		return -EOPNOTSUPP;
	}

	size = sizeof(*p);
	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);
	if (connection->agreed_pro_version >= 87)
		size += strlen(nc->integrity_alg) + 1;
	rcu_read_unlock();

	p = __conn_prepare_command(connection, size, DATA_STREAM);
	if (!p)
		return -EIO;

	rcu_read_lock();
	nc = rcu_dereference(connection->transport.net_conf);

	p->protocol      = cpu_to_be32(nc->wire_protocol);
	p->after_sb_0p   = cpu_to_be32(nc->after_sb_0p);
	p->after_sb_1p   = cpu_to_be32(nc->after_sb_1p);
	p->after_sb_2p   = cpu_to_be32(nc->after_sb_2p);
	p->two_primaries = cpu_to_be32(nc->two_primaries);
	cf = 0;
	if (test_bit(CONN_DISCARD_MY_DATA, &connection->flags))
		cf |= CF_DISCARD_MY_DATA;
	if (test_bit(CONN_DRY_RUN, &connection->flags))
		cf |= CF_DRY_RUN;
	p->conn_flags    = cpu_to_be32(cf);

	if (connection->agreed_pro_version >= 87)
		strcpy(p->integrity_alg, nc->integrity_alg);
	rcu_read_unlock();

	return __send_command(connection, -1, cmd, DATA_STREAM);
}

int drbd_send_protocol(struct drbd_connection *connection)
{
	int err;

	mutex_lock(&connection->mutex[DATA_STREAM]);
	err = __drbd_send_protocol(connection, P_PROTOCOL);
	mutex_unlock(&connection->mutex[DATA_STREAM]);

	return err;
}

static int _drbd_send_uuids(struct drbd_peer_device *peer_device, u64 uuid_flags)
{
	struct drbd_device *device = peer_device->device;
	struct p_uuids *p;
	int i;

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return 0;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p) {
		put_ldev(device);
		return -EIO;
	}

	spin_lock_irq(&device->ldev->md.uuid_lock);
	peer_device->comm_current_uuid = drbd_current_uuid(device);
	p->current_uuid = cpu_to_be64(peer_device->comm_current_uuid);
	p->bitmap_uuid = cpu_to_be64(drbd_bitmap_uuid(peer_device));
	for (i = 0; i < ARRAY_SIZE(p->history_uuids); i++)
		p->history_uuids[i] = cpu_to_be64(drbd_history_uuid(device, i));
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	peer_device->comm_bm_set = drbd_bm_total_weight(peer_device);
	p->dirty_bits = cpu_to_be64(peer_device->comm_bm_set);

	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
		uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;
	if (test_bit(CRASHED_PRIMARY, &device->flags))
		uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;
	if (!drbd_md_test_flag(device->ldev, MDF_CONSISTENT))
		uuid_flags |= UUID_FLAG_INCONSISTENT;

	/* Silently mask out any "too recent" flags,
	 * we cannot communicate those in old DRBD
	 * protocol versions. */
	uuid_flags &= UUID_FLAG_MASK_COMPAT_84;

	peer_device->comm_uuid_flags = uuid_flags;
	p->uuid_flags = cpu_to_be64(uuid_flags);

	put_ldev(device);

	return drbd_send_command(peer_device, P_UUIDS, DATA_STREAM);
}

static u64 __bitmap_uuid(struct drbd_device *device, int node_id) __must_hold(local)
{
	struct drbd_peer_device *peer_device;
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	u64 bitmap_uuid = peer_md[node_id].bitmap_uuid;

	/* Sending a bitmap_uuid of 0 means that we are in sync with that peer.
	   The recipient of this message might use this assumption to throw away it's
	   bitmap to that peer.

	   Send -1 instead if we are (resync target from that peer) not at the same
	   current uuid.
	   This corner case is relevant if we finish resync from an UpToDate peer first,
	   and the second resync (which was paused first) is from an Outdated node.
	   And that second resync gets canceled by the resync target due to the first
	   resync finished successfully.

	   Exceptions to the above are when the peer's UUID is not known yet
	 */

	rcu_read_lock();
	peer_device = peer_device_by_node_id(device, node_id);
	if (peer_device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[NOW];
		if (bitmap_uuid == 0 &&
		    (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
		    peer_device->current_uuid != 0 &&
		    (peer_device->current_uuid & ~UUID_PRIMARY) !=
		    (drbd_current_uuid(device) & ~UUID_PRIMARY))
			bitmap_uuid = -1;
	}
	rcu_read_unlock();

	return bitmap_uuid;
}

u64 drbd_collect_local_uuid_flags(struct drbd_peer_device *peer_device, u64 *authoritative_mask)
{
	struct drbd_device *device = peer_device->device;
	u64 uuid_flags = 0;

	if (test_bit(DISCARD_MY_DATA, &peer_device->flags))
		uuid_flags |= UUID_FLAG_DISCARD_MY_DATA;
	if (test_bit(CRASHED_PRIMARY, &device->flags))
		uuid_flags |= UUID_FLAG_CRASHED_PRIMARY;
	if (!drbd_md_test_flag(device->ldev, MDF_CONSISTENT))
		uuid_flags |= UUID_FLAG_INCONSISTENT;
	if (test_bit(RECONNECT, &peer_device->connection->flags))
		uuid_flags |= UUID_FLAG_RECONNECT;
	if (test_bit(PRIMARY_LOST_QUORUM, &device->flags))
		uuid_flags |= UUID_FLAG_PRIMARY_LOST_QUORUM;
	if (drbd_device_stable(device, authoritative_mask))
		uuid_flags |= UUID_FLAG_STABLE;

	return uuid_flags;
}

/* sets UUID_FLAG_SYNC_TARGET on uuid_flags as appropriate (may be NULL) */
u64 drbd_resolved_uuid(struct drbd_peer_device *peer_device_base, u64 *uuid_flags)
{
	struct drbd_device *device = peer_device_base->device;
	struct drbd_peer_device *peer_device;
	u64 uuid = drbd_current_uuid(device);

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->node_id == peer_device_base->node_id)
			continue;
		if (peer_device->repl_state[NOW] == L_SYNC_TARGET) {
			uuid = peer_device->current_uuid;
			if (uuid_flags)
				*uuid_flags |= UUID_FLAG_SYNC_TARGET;
			break;
		}
	}
	rcu_read_unlock();

	return uuid;
}

static int _drbd_send_uuids110(struct drbd_peer_device *peer_device, u64 uuid_flags, u64 node_mask)
{
	struct drbd_device *device = peer_device->device;
	const int my_node_id = device->resource->res_opts.node_id;
	struct drbd_peer_md *peer_md;
	struct p_uuids110 *p;
	bool sent_one_unallocated;
	int i, pos = 0;
	u64 bitmap_uuids_mask = 0;
	u64 authoritative_mask;
	int p_size = sizeof(*p);

	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return drbd_send_current_uuid(peer_device, device->exposed_data_uuid,
					      drbd_weak_nodes_device(device));

	peer_md = device->ldev->md.peers;

	p_size += (DRBD_PEERS_MAX + HISTORY_UUIDS) * sizeof(p->other_uuids[0]);
	p = drbd_prepare_command(peer_device, p_size, DATA_STREAM);
	if (!p) {
		put_ldev(device);
		return -EIO;
	}

	spin_lock_irq(&device->ldev->md.uuid_lock);
	peer_device->comm_current_uuid = drbd_resolved_uuid(peer_device, &uuid_flags);
	p->current_uuid = cpu_to_be64(peer_device->comm_current_uuid);

	sent_one_unallocated = peer_device->connection->agreed_pro_version < 116;
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		bool send_this =
			peer_md[i].flags & MDF_HAVE_BITMAP || peer_md[i].flags & MDF_NODE_EXISTS;
		if (!send_this && !sent_one_unallocated &&
		    i != my_node_id && i != peer_device->node_id) {
			send_this = true;
			sent_one_unallocated = true;
			uuid_flags |= (u64)i << UUID_FLAG_UNALLOC_SHIFT;
			uuid_flags |= UUID_FLAG_HAS_UNALLOC;
		}
		if (send_this) {
			u64 val = __bitmap_uuid(device, i);
			bitmap_uuids_mask |= NODE_MASK(i);
			p->other_uuids[pos++] = cpu_to_be64(val);
			if (i == peer_device->node_id)
				peer_device->comm_bitmap_uuid = val;
		}
	}

	for (i = 0; i < HISTORY_UUIDS; i++)
		p->other_uuids[pos++] = cpu_to_be64(drbd_history_uuid(device, i));
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	p->bitmap_uuids_mask = cpu_to_be64(bitmap_uuids_mask);

	peer_device->comm_bm_set = drbd_bm_total_weight(peer_device);
	p->dirty_bits = cpu_to_be64(peer_device->comm_bm_set);
	uuid_flags |= drbd_collect_local_uuid_flags(peer_device, &authoritative_mask);
	if (uuid_flags & UUID_FLAG_STABLE) {
		p->node_mask = cpu_to_be64(node_mask);
	} else {
		D_ASSERT(peer_device, node_mask == 0);
		p->node_mask = cpu_to_be64(authoritative_mask);
	}

	peer_device->comm_uuid_flags = uuid_flags & ~UUID_FLAG_UNALLOC_MASK & ~UUID_FLAG_HAS_UNALLOC;
	p->uuid_flags = cpu_to_be64(uuid_flags);

	put_ldev(device);

	p_size = sizeof(*p) +
		(hweight64(bitmap_uuids_mask) + HISTORY_UUIDS) * sizeof(p->other_uuids[0]);
	resize_prepared_command(peer_device->connection, DATA_STREAM, p_size);
	return drbd_send_command(peer_device, P_UUIDS110, DATA_STREAM);
}

int drbd_send_uuids(struct drbd_peer_device *peer_device, u64 uuid_flags, u64 node_mask)
{
	if (peer_device->connection->agreed_pro_version >= 110)
		return _drbd_send_uuids110(peer_device, uuid_flags, node_mask);
	else
		return _drbd_send_uuids(peer_device, uuid_flags);
}

void drbd_print_uuids(struct drbd_peer_device *peer_device, const char *text)
{
	struct drbd_device *device = peer_device->device;

	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		drbd_info(peer_device, "%s %016llX:%016llX:%016llX:%016llX\n",
			  text,
			  (unsigned long long)drbd_current_uuid(device),
			  (unsigned long long)drbd_bitmap_uuid(peer_device),
			  (unsigned long long)drbd_history_uuid(device, 0),
			  (unsigned long long)drbd_history_uuid(device, 1));
		put_ldev(device);
	} else {
		drbd_info(device, "%s exposed data uuid: %016llX\n",
			  text,
			  (unsigned long long)device->exposed_data_uuid);
	}
}

int drbd_send_current_uuid(struct drbd_peer_device *peer_device, u64 current_uuid, u64 weak_nodes)
{
	struct p_current_uuid *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->uuid = cpu_to_be64(current_uuid);
	p->weak_nodes = cpu_to_be64(weak_nodes);
	return drbd_send_command(peer_device, P_CURRENT_UUID, DATA_STREAM);
}

void drbd_gen_and_send_sync_uuid(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct p_uuid *p;
	u64 uuid;

	D_ASSERT(device, device->disk_state[NOW] == D_UP_TO_DATE);

	down_write(&device->uuid_sem);
	uuid = drbd_bitmap_uuid(peer_device);
	if (uuid && uuid != UUID_JUST_CREATED)
		uuid = uuid + UUID_NEW_BM_OFFSET;
	else
		get_random_bytes(&uuid, sizeof(u64));
	drbd_uuid_set_bitmap(peer_device, uuid);
	drbd_print_uuids(peer_device, "updated sync UUID");
	drbd_md_sync(device);
	downgrade_write(&device->uuid_sem);

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (p) {
		p->uuid = cpu_to_be64(uuid);
		drbd_send_command(peer_device, P_SYNC_UUID, DATA_STREAM);
	}
	up_read(&device->uuid_sem);
}

/* All callers hold resource->conf_update */
int drbd_attach_peer_device(struct drbd_peer_device *const peer_device) __must_hold(local)
{
	struct lru_cache *resync_lru = NULL;
	int err = -ENOMEM;

	resync_lru = lc_create("resync", drbd_bm_ext_cache,
	                       1, 61, sizeof(struct bm_extent),
	                       offsetof(struct bm_extent, lce));
	if (resync_lru != NULL) {
		peer_device->resync_lru = resync_lru;
		err = 0;
	}

	return err;
}

/* communicated if (agreed_features & DRBD_FF_WSAME) */
static void assign_p_sizes_qlim(struct drbd_device *device, struct p_sizes *p, struct request_queue *q)
{
	if (q) {
		p->qlim->physical_block_size = cpu_to_be32(queue_physical_block_size(q));
		p->qlim->logical_block_size = cpu_to_be32(queue_logical_block_size(q));
		p->qlim->alignment_offset = cpu_to_be32(queue_alignment_offset(q));
		p->qlim->io_min = cpu_to_be32(queue_io_min(q));
		p->qlim->io_opt = cpu_to_be32(queue_io_opt(q));
		p->qlim->discard_enabled = blk_queue_discard(q);
		p->qlim->discard_zeroes_data = queue_discard_zeroes_data(q);
		p->qlim->write_same_capable = !!q->limits.max_write_same_sectors;
	} else {
		q = device->rq_queue;
		p->qlim->physical_block_size = cpu_to_be32(queue_physical_block_size(q));
		p->qlim->logical_block_size = cpu_to_be32(queue_logical_block_size(q));
		p->qlim->alignment_offset = 0;
		p->qlim->io_min = cpu_to_be32(queue_io_min(q));
		p->qlim->io_opt = cpu_to_be32(queue_io_opt(q));
		p->qlim->discard_enabled = 0;
		p->qlim->discard_zeroes_data = 0;
		p->qlim->write_same_capable = 0;
	}
}

int drbd_send_sizes(struct drbd_peer_device *peer_device,
		    uint64_t u_size_diskless, enum dds_flags flags)
{
	struct drbd_device *device = peer_device->device;
	struct p_sizes *p;
	sector_t d_size, u_size;
	int q_order_type;
	unsigned int max_bio_size;
	unsigned int packet_size;

	packet_size = sizeof(*p);
	if (peer_device->connection->agreed_features & DRBD_FF_WSAME)
		packet_size += sizeof(p->qlim[0]);

	p = drbd_prepare_command(peer_device, packet_size, DATA_STREAM);
	if (!p)
		return -EIO;

	memset(p, 0, packet_size);
	if (get_ldev_if_state(device, D_NEGOTIATING)) {
		struct request_queue *q = bdev_get_queue(device->ldev->backing_bdev);
		d_size = drbd_get_max_capacity(device, device->ldev, false);
		rcu_read_lock();
		u_size = rcu_dereference(device->ldev->disk_conf)->disk_size;
		rcu_read_unlock();
		q_order_type = drbd_queue_order_type(device);
		max_bio_size = queue_max_hw_sectors(q) << 9;
		max_bio_size = min(max_bio_size, DRBD_MAX_BIO_SIZE);
		assign_p_sizes_qlim(device, p, q);
		put_ldev(device);
	} else {
		d_size = 0;
		u_size = u_size_diskless;
		q_order_type = QUEUE_ORDERED_NONE;
		max_bio_size = DRBD_MAX_BIO_SIZE; /* ... multiple BIOs per peer_request */
		assign_p_sizes_qlim(device, p, NULL);
	}

	if (peer_device->connection->agreed_pro_version <= 94)
		max_bio_size = min(max_bio_size, DRBD_MAX_SIZE_H80_PACKET);
	else if (peer_device->connection->agreed_pro_version < 100)
		max_bio_size = min(max_bio_size, DRBD_MAX_BIO_SIZE_P95);

	p->d_size = cpu_to_be64(d_size);
	p->u_size = cpu_to_be64(u_size);
	/*
	TODO verify: this may be needed for v8 compatibility still.
	p->c_size = cpu_to_be64(trigger_reply ? 0 : get_capacity(device->vdisk));
	*/
	p->c_size = cpu_to_be64(get_capacity(device->vdisk));
	p->max_bio_size = cpu_to_be32(max_bio_size);
	p->queue_order_type = cpu_to_be16(q_order_type);
	p->dds_flags = cpu_to_be16(flags);

	return drbd_send_command(peer_device, P_SIZES, DATA_STREAM);
}

int drbd_send_current_state(struct drbd_peer_device *peer_device)
{
	return drbd_send_state(peer_device, drbd_get_peer_device_state(peer_device, NOW));
}

static int send_state(struct drbd_connection *connection, int vnr, union drbd_state state)
{
	struct p_state *p;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	if (connection->agreed_pro_version < 110) {
		/* D_DETACHING was introduced with drbd-9.0 */
		if (state.disk > D_DETACHING)
			state.disk--;
		if (state.pdsk > D_DETACHING)
			state.pdsk--;
	}

	p->state = cpu_to_be32(state.i); /* Within the send mutex */
	return send_command(connection, vnr, P_STATE, DATA_STREAM);
}

int conn_send_state(struct drbd_connection *connection, union drbd_state state)
{
	BUG_ON(connection->agreed_pro_version < 100);
	return send_state(connection, -1, state);
}

/**
 * drbd_send_state() - Sends the drbd state to the peer
 * @device:	DRBD device.
 * @state:	state to send
 */
int drbd_send_state(struct drbd_peer_device *peer_device, union drbd_state state)
{
	peer_device->comm_state = state;
	return send_state(peer_device->connection, peer_device->device->vnr, state);
}

int conn_send_state_req(struct drbd_connection *connection, int vnr, enum drbd_packet cmd,
			union drbd_state mask, union drbd_state val)
{
	struct p_req_state *p;

	/* Protocols before version 100 only support one volume and connection.
	 * All state change requests are via P_STATE_CHG_REQ. */
	if (connection->agreed_pro_version < 100)
		cmd = P_STATE_CHG_REQ;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->mask = cpu_to_be32(mask.i);
	p->val = cpu_to_be32(val.i);

	return send_command(connection, vnr, cmd, DATA_STREAM);
}

int conn_send_twopc_request(struct drbd_connection *connection, int vnr, enum drbd_packet cmd,
			    struct p_twopc_request *request)
{
	struct p_twopc_request *p;

	drbd_debug(connection, "Sending %s request for state change %u\n",
		   drbd_packet_name(cmd),
		   be32_to_cpu(request->tid));

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	memcpy(p, request, sizeof(*request));

	return send_command(connection, vnr, cmd, DATA_STREAM);
}

void drbd_send_sr_reply(struct drbd_connection *connection, int vnr, enum drbd_state_rv retcode)
{
	struct p_req_state_reply *p;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (p) {
		enum drbd_packet cmd = P_STATE_CHG_REPLY;

		if (connection->agreed_pro_version >= 100 && vnr < 0)
			cmd = P_CONN_ST_CHG_REPLY;

		p->retcode = cpu_to_be32(retcode);
		send_command(connection, vnr, cmd, CONTROL_STREAM);
	}
}

void drbd_send_twopc_reply(struct drbd_connection *connection,
			   enum drbd_packet cmd, struct twopc_reply *reply)
{
	struct p_twopc_reply *p;

	p = conn_prepare_command(connection, sizeof(*p), CONTROL_STREAM);
	if (p) {
		p->tid = cpu_to_be32(reply->tid);
		p->initiator_node_id = cpu_to_be32(reply->initiator_node_id);
		p->reachable_nodes = cpu_to_be64(reply->reachable_nodes);
		switch (connection->resource->twopc_type) {
		case TWOPC_STATE_CHANGE:
			p->primary_nodes = cpu_to_be64(reply->primary_nodes);
			p->weak_nodes = cpu_to_be64(reply->weak_nodes);
			break;
		case TWOPC_RESIZE:
			p->diskful_primary_nodes = cpu_to_be64(reply->diskful_primary_nodes);
			p->max_possible_size = cpu_to_be64(reply->max_possible_size);
			break;
		}
		send_command(connection, reply->vnr, cmd, CONTROL_STREAM);
	}
}

void drbd_send_peers_in_sync(struct drbd_peer_device *peer_device, u64 mask, sector_t sector, int size)
{
	struct p_peer_block_desc *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), CONTROL_STREAM);
	if (p) {
		p->sector = cpu_to_be64(sector);
		p->mask = cpu_to_be64(mask);
		p->size = cpu_to_be32(size);
		p->pad = 0;
		drbd_send_command(peer_device, P_PEERS_IN_SYNC, CONTROL_STREAM);
	}
}

int drbd_send_peer_dagtag(struct drbd_connection *connection, struct drbd_connection *lost_peer)
{
	struct p_peer_dagtag *p;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;

	p->dagtag = cpu_to_be64(lost_peer->last_dagtag_sector);
	p->node_id = cpu_to_be32(lost_peer->peer_node_id);

	return send_command(connection, -1, P_PEER_DAGTAG, DATA_STREAM);
}

static void dcbp_set_code(struct p_compressed_bm *p, enum drbd_bitmap_code code)
{
	BUG_ON(code & ~0xf);
	p->encoding = (p->encoding & ~0xf) | code;
}

static void dcbp_set_start(struct p_compressed_bm *p, int set)
{
	p->encoding = (p->encoding & ~0x80) | (set ? 0x80 : 0);
}

static void dcbp_set_pad_bits(struct p_compressed_bm *p, int n)
{
	BUG_ON(n & ~0x7);
	p->encoding = (p->encoding & (~0x7 << 4)) | (n << 4);
}

static int fill_bitmap_rle_bits(struct drbd_peer_device *peer_device,
				struct p_compressed_bm *p,
				unsigned int size,
				struct bm_xfer_ctx *c)
{
	struct bitstream bs;
	unsigned long plain_bits;
	unsigned long tmp;
	unsigned long rl;
	unsigned len;
	unsigned toggle;
	int bits, use_rle;

	/* may we use this feature? */
	rcu_read_lock();
	use_rle = rcu_dereference(peer_device->connection->transport.net_conf)->use_rle;
	rcu_read_unlock();
	if (!use_rle || peer_device->connection->agreed_pro_version < 90)
		return 0;

	if (c->bit_offset >= c->bm_bits)
		return 0; /* nothing to do. */

	/* use at most thus many bytes */
	bitstream_init(&bs, p->code, size, 0);
	memset(p->code, 0, size);
	/* plain bits covered in this code string */
	plain_bits = 0;

	/* p->encoding & 0x80 stores whether the first run length is set.
	 * bit offset is implicit.
	 * start with toggle == 2 to be able to tell the first iteration */
	toggle = 2;

	/* see how much plain bits we can stuff into one packet
	 * using RLE and VLI. */
	do {
		tmp = (toggle == 0) ? _drbd_bm_find_next_zero(peer_device, c->bit_offset)
				    : _drbd_bm_find_next(peer_device, c->bit_offset);
		if (tmp == -1UL)
			tmp = c->bm_bits;
		rl = tmp - c->bit_offset;

		if (toggle == 2) { /* first iteration */
			if (rl == 0) {
				/* the first checked bit was set,
				 * store start value, */
				dcbp_set_start(p, 1);
				/* but skip encoding of zero run length */
				toggle = !toggle;
				continue;
			}
			dcbp_set_start(p, 0);
		}

		/* paranoia: catch zero runlength.
		 * can only happen if bitmap is modified while we scan it. */
		if (rl == 0) {
			drbd_err(peer_device, "unexpected zero runlength while encoding bitmap "
			    "t:%u bo:%lu\n", toggle, c->bit_offset);
			return -1;
		}

		bits = vli_encode_bits(&bs, rl);
		if (bits == -ENOBUFS) /* buffer full */
			break;
		if (bits <= 0) {
			drbd_err(peer_device, "error while encoding bitmap: %d\n", bits);
			return 0;
		}

		toggle = !toggle;
		plain_bits += rl;
		c->bit_offset = tmp;
	} while (c->bit_offset < c->bm_bits);

	len = bs.cur.b - p->code + !!bs.cur.bit;

	if (plain_bits < (len << 3)) {
		/* incompressible with this method.
		 * we need to rewind both word and bit position. */
		c->bit_offset -= plain_bits;
		bm_xfer_ctx_bit_to_word_offset(c);
		c->bit_offset = c->word_offset * BITS_PER_LONG;
		return 0;
	}

	/* RLE + VLI was able to compress it just fine.
	 * update c->word_offset. */
	bm_xfer_ctx_bit_to_word_offset(c);

	/* store pad_bits */
	dcbp_set_pad_bits(p, (8 - bs.cur.bit) & 0x7);

	return len;
}

/**
 * send_bitmap_rle_or_plain
 *
 * Return 0 when done, 1 when another iteration is needed, and a negative error
 * code upon failure.
 */
static int
send_bitmap_rle_or_plain(struct drbd_peer_device *peer_device, struct bm_xfer_ctx *c)
{
	struct drbd_device *device = peer_device->device;
	unsigned int header_size = drbd_header_size(peer_device->connection);
	struct p_compressed_bm *pc;
	int len, err;

	pc = (struct p_compressed_bm *)
		(alloc_send_buffer(peer_device->connection, DRBD_SOCKET_BUFFER_SIZE, DATA_STREAM) + header_size);

	len = fill_bitmap_rle_bits(peer_device, pc,
			DRBD_SOCKET_BUFFER_SIZE - header_size - sizeof(*pc), c);
	if (len < 0)
		return -EIO;

	if (len) {
		dcbp_set_code(pc, RLE_VLI_Bits);
		resize_prepared_command(peer_device->connection, DATA_STREAM, sizeof(*pc) + len);
		err = __send_command(peer_device->connection, device->vnr,
				     P_COMPRESSED_BITMAP, DATA_STREAM);
		c->packets[0]++;
		c->bytes[0] += header_size + sizeof(*pc) + len;

		if (c->bit_offset >= c->bm_bits)
			len = 0; /* DONE */
	} else {
		/* was not compressible.
		 * send a buffer full of plain text bits instead. */
		unsigned int data_size;
		unsigned long num_words;
		unsigned long *pu = (unsigned long *)pc;

		data_size = DRBD_SOCKET_BUFFER_SIZE - header_size;
		num_words = min_t(size_t, data_size / sizeof(*pu),
				  c->bm_words - c->word_offset);
		len = num_words * sizeof(*pu);
		if (len)
			drbd_bm_get_lel(peer_device, c->word_offset, num_words, pu);

		resize_prepared_command(peer_device->connection, DATA_STREAM, len);
		err = __send_command(peer_device->connection, device->vnr, P_BITMAP, DATA_STREAM);

		c->word_offset += num_words;
		c->bit_offset = c->word_offset * BITS_PER_LONG;

		c->packets[1]++;
		c->bytes[1] += header_size + len;

		if (c->bit_offset > c->bm_bits)
			c->bit_offset = c->bm_bits;
	}
	if (!err) {
		if (len == 0) {
			INFO_bm_xfer_stats(peer_device, "send", c);
			return 0;
		} else
			return 1;
	}
	return -EIO;
}

/* See the comment at receive_bitmap() */
static int _drbd_send_bitmap(struct drbd_device *device,
			     struct drbd_peer_device *peer_device)
{
	struct bm_xfer_ctx c;
	int err;

	if (!expect(device, device->bitmap))
		return false;

	if (get_ldev(device)) {
		if (drbd_md_test_peer_flag(peer_device, MDF_PEER_FULL_SYNC)) {
			drbd_info(device, "Writing the whole bitmap, MDF_FullSync was set.\n");
			drbd_bm_set_many_bits(peer_device, 0, -1UL);
			if (drbd_bm_write(device, NULL)) {
				/* write_bm did fail! Leave full sync flag set in Meta P_DATA
				 * but otherwise process as per normal - need to tell other
				 * side that a full resync is required! */
				drbd_err(device, "Failed to write bitmap to disk!\n");
			} else {
				drbd_md_clear_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
				drbd_md_sync(device);
			}
		}
		put_ldev(device);
	}

	c = (struct bm_xfer_ctx) {
		.bm_bits = drbd_bm_bits(device),
		.bm_words = drbd_bm_words(device),
	};

	do {
		err = send_bitmap_rle_or_plain(peer_device, &c);
	} while (err > 0);

	return err == 0;
}

int drbd_send_bitmap(struct drbd_device *device, struct drbd_peer_device *peer_device)
{
	struct drbd_transport *peer_transport = &peer_device->connection->transport;
	int err = -1;

	if (peer_device->bitmap_index == -1) {
		drbd_err(peer_device, "No bitmap allocated in drbd_send_bitmap()!\n");
		return -EIO;
	}

	mutex_lock(&peer_device->connection->mutex[DATA_STREAM]);
	if (peer_transport->ops->stream_ok(peer_transport, DATA_STREAM))
		err = !_drbd_send_bitmap(device, peer_device);
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

int drbd_send_rs_deallocated(struct drbd_peer_device *peer_device,
			     struct drbd_peer_request *peer_req)
{
	struct p_block_desc *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(peer_req->i.sector);
	p->blksize = cpu_to_be32(peer_req->i.size);
	p->pad = 0;
	return drbd_send_command(peer_device, P_RS_DEALLOCATED, DATA_STREAM);
}

int drbd_send_drequest(struct drbd_peer_device *peer_device, int cmd,
		       sector_t sector, int size, u64 block_id)
{
	struct p_block_req *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->block_id = block_id;
	p->pad = 0;
	p->blksize = cpu_to_be32(size);
	return drbd_send_command(peer_device, cmd, DATA_STREAM);
}

void *drbd_prepare_drequest_csum(struct drbd_peer_request *peer_req, int digest_size)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct p_block_req *p;

	p = drbd_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);
	if (!p)
		return NULL;

	p->sector = cpu_to_be64(peer_req->i.sector);
	p->block_id = ID_SYNCER /* unused */;
	p->blksize = cpu_to_be32(peer_req->i.size);

	return p + 1; /* digest should be placed behind the struct */
}

int drbd_send_ov_request(struct drbd_peer_device *peer_device, sector_t sector, int size)
{
	struct p_block_req *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->block_id = ID_SYNCER /* unused */;
	p->blksize = cpu_to_be32(size);
	return drbd_send_command(peer_device, P_OV_REQUEST, DATA_STREAM);
}

/* The idea of sendpage seems to be to put some kind of reference
 * to the page into the skb, and to hand it over to the NIC. In
 * this process get_page() gets called.
 *
 * As soon as the page was really sent over the network put_page()
 * gets called by some part of the network layer. [ NIC driver? ]
 *
 * [ get_page() / put_page() increment/decrement the count. If count
 *   reaches 0 the page will be freed. ]
 *
 * This works nicely with pages from FSs.
 * But this means that in protocol A we might signal IO completion too early!
 *
 * In order not to corrupt data during a resync we must make sure
 * that we do not reuse our own buffer pages (EEs) to early, therefore
 * we have the net_ee list.
 *
 * XFS seems to have problems, still, it submits pages with page_count == 0!
 * As a workaround, we disable sendpage on pages
 * with page_count == 0 or PageSlab.
 */
static int _drbd_send_page(struct drbd_peer_device *peer_device, struct page *page,
			    int offset, size_t size, unsigned msg_flags)
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = transport->ops;
	int err;

	err = tr_ops->send_page(transport, DATA_STREAM, page, offset, size, msg_flags);
	if (!err)
		peer_device->send_cnt += size >> 9;

	return err;
}

static int _drbd_no_send_page(struct drbd_peer_device *peer_device, struct page *page,
			      int offset, size_t size, unsigned msg_flags)
/* kmap compat: KM_USER0 */
{
	struct drbd_connection *connection = peer_device->connection;
	struct drbd_send_buffer *sbuf = &connection->send_buffer[DATA_STREAM];
	char *from_base;
	void *buffer2;
	int err;

	buffer2 = alloc_send_buffer(connection, size, DATA_STREAM);
	from_base = kmap_atomic(page);
	memcpy(buffer2, from_base + offset, size);
	kunmap_atomic(from_base);

	if (msg_flags & MSG_MORE) {
		sbuf->pos += sbuf->allocated_size;
		sbuf->allocated_size = 0;
		err = 0;
	} else {
		err = flush_send_buffer(connection, DATA_STREAM);
	}

	return err;
}

static int _drbd_send_bio(struct drbd_peer_device *peer_device, struct bio *bio)
{
	struct drbd_connection *connection = peer_device->connection;
	struct bio_vec bvec;
	struct bvec_iter iter;

	/* Flush send buffer and make sure PAGE_SIZE is available... */
	alloc_send_buffer(connection, PAGE_SIZE, DATA_STREAM);
	connection->send_buffer[DATA_STREAM].allocated_size = 0;

	/* hint all but last page with MSG_MORE */
	bio_for_each_segment(bvec, bio, iter) {
		int err;

		err = _drbd_no_send_page(peer_device, bvec.bv_page,
					 bvec.bv_offset, bvec.bv_len,
					 bio_iter_last(bvec, iter) ? 0 : MSG_MORE);
		if (err)
			return err;
		/* WRITE_SAME has only one segment */
		if (bio_op(bio) == REQ_OP_WRITE_SAME)
			break;

		peer_device->send_cnt += bvec.bv_len >> 9;
	}
	return 0;
}

static int _drbd_send_zc_bio(struct drbd_peer_device *peer_device, struct bio *bio)
{
	struct bio_vec bvec;
	struct bvec_iter iter;
	bool no_zc = drbd_disable_sendpage;

	/* e.g. XFS meta- & log-data is in slab pages, which have a
	 * page_count of 0 and/or have PageSlab() set.
	 * we cannot use send_page for those, as that does get_page();
	 * put_page(); and would cause either a VM_BUG directly, or
	 * __page_cache_release a page that would actually still be referenced
	 * by someone, leading to some obscure delayed Oops somewhere else. */
	if (!no_zc)
		bio_for_each_segment(bvec, bio, iter) {
			struct page *page = bvec.bv_page;

			if (!sendpage_ok(page)) {
				no_zc = true;
				break;
			}
		}

	if (no_zc) {
		return _drbd_send_bio(peer_device, bio);
	} else {
		struct drbd_connection *connection = peer_device->connection;
		struct drbd_transport *transport = &connection->transport;
		struct drbd_transport_ops *tr_ops = transport->ops;
		int err;

		flush_send_buffer(connection, DATA_STREAM);

		err = tr_ops->send_zc_bio(transport, bio);
		if (!err)
			peer_device->send_cnt += bio->bi_iter.bi_size >> 9;

		return err;
	}
}

static int _drbd_send_zc_ee(struct drbd_peer_device *peer_device,
			    struct drbd_peer_request *peer_req)
{
	struct page *page = peer_req->page_chain.head;
	unsigned len = peer_req->i.size;
	int err;

	flush_send_buffer(peer_device->connection, DATA_STREAM);
	/* hint all but last page with MSG_MORE */
	page_chain_for_each(page) {
		unsigned l = min_t(unsigned, len, PAGE_SIZE);
		if (page_chain_offset(page) != 0 ||
		    page_chain_size(page) != l) {
			drbd_err(peer_device, "FIXME page %p offset %u len %u\n",
				page, page_chain_offset(page), page_chain_size(page));
		}

		err = _drbd_send_page(peer_device, page, 0, l,
				      page_chain_next(page) ? MSG_MORE : 0);
		if (err)
			return err;
		len -= l;
	}
	return 0;
}

/* see also wire_flags_to_bio() */
static u32 bio_flags_to_wire(struct drbd_connection *connection, struct bio *bio)
{
	if (connection->agreed_pro_version >= 95)
		return  (bio->bi_opf & REQ_SYNC ? DP_RW_SYNC : 0) |
			(bio->bi_opf & REQ_FUA ? DP_FUA : 0) |
			(bio->bi_opf & REQ_PREFLUSH ? DP_FLUSH : 0) |
			(bio_op(bio) == REQ_OP_WRITE_SAME ? DP_WSAME : 0) |
			(bio_op(bio) == REQ_OP_DISCARD ? DP_DISCARD : 0) |
			(bio_op(bio) == REQ_OP_WRITE_ZEROES ?
			  ((connection->agreed_features & DRBD_FF_WZEROES) ?
			   (DP_ZEROES |(!(bio->bi_opf & REQ_NOUNMAP) ? DP_DISCARD : 0))
			   : DP_DISCARD)
			: 0);

	/* else: we used to communicate one bit only in older DRBD */
	return bio->bi_opf & REQ_SYNC ? DP_RW_SYNC : 0;
}

/* Used to send write or TRIM aka REQ_OP_DISCARD requests
 * R_PRIMARY -> Peer	(P_DATA, P_TRIM)
 */
int drbd_send_dblock(struct drbd_peer_device *peer_device, struct drbd_request *req)
{
	struct drbd_device *device = peer_device->device;
	char *const before = peer_device->connection->scratch_buffer.d.before;
	char *const after = peer_device->connection->scratch_buffer.d.after;
	struct p_trim *trim = NULL;
	struct p_data *p;
	struct p_wsame *wsame = NULL;
	void *digest_out = NULL;
	unsigned int dp_flags = 0;
	int digest_size = 0;
	int err;
	const unsigned s = drbd_req_state_by_peer_device(req, peer_device);
	const int op = bio_op(req->master_bio);

	if (op == REQ_OP_DISCARD || op == REQ_OP_WRITE_ZEROES) {
		trim = drbd_prepare_command(peer_device, sizeof(*trim), DATA_STREAM);
		if (!trim)
			return -EIO;
		p = &trim->p_data;
		trim->size = cpu_to_be32(req->i.size);
	} else {
		if (peer_device->connection->integrity_tfm)
			digest_size = crypto_shash_digestsize(peer_device->connection->integrity_tfm);

		if (op == REQ_OP_WRITE_SAME) {
			wsame = drbd_prepare_command(peer_device, sizeof(*wsame) + digest_size, DATA_STREAM);
			if (!wsame)
				return -EIO;
			p = &wsame->p_data;
			wsame->size = cpu_to_be32(req->i.size);
			digest_out = wsame + 1;
		} else {
			p = drbd_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);
			if (!p)
				return -EIO;
			digest_out = p + 1;
		}
	}

	p->sector = cpu_to_be64(req->i.sector);
	p->block_id = (unsigned long)req;
	p->seq_num = cpu_to_be32(atomic_inc_return(&peer_device->packet_seq));
	dp_flags = bio_flags_to_wire(peer_device->connection, req->master_bio);
	if (peer_device->repl_state[NOW] >= L_SYNC_SOURCE && peer_device->repl_state[NOW] <= L_PAUSED_SYNC_T)
		dp_flags |= DP_MAY_SET_IN_SYNC;
	if (peer_device->connection->agreed_pro_version >= 100) {
		if (s & RQ_EXP_RECEIVE_ACK)
			dp_flags |= DP_SEND_RECEIVE_ACK;
		if (s & RQ_EXP_WRITE_ACK || dp_flags & DP_MAY_SET_IN_SYNC)
			dp_flags |= DP_SEND_WRITE_ACK;
	}
	p->dp_flags = cpu_to_be32(dp_flags);

	if (trim) {
		err = __send_command(peer_device->connection, device->vnr,
				(dp_flags & DP_ZEROES) ? P_ZEROES : P_TRIM, DATA_STREAM);
		goto out;
	}

	if (digest_size && digest_out) {
		BUG_ON(digest_size > sizeof(peer_device->connection->scratch_buffer.d.before));
		drbd_csum_bio(peer_device->connection->integrity_tfm, req->master_bio, before);
		memcpy(digest_out, before, digest_size);
	}

	if (wsame) {
		additional_size_command(peer_device->connection, DATA_STREAM,
					bio_iovec(req->master_bio).bv_len);
		err = __send_command(peer_device->connection, device->vnr, P_WSAME, DATA_STREAM);
	} else {
		additional_size_command(peer_device->connection, DATA_STREAM, req->i.size);
		err = __send_command(peer_device->connection, device->vnr, P_DATA, DATA_STREAM);
	}
	if (!err) {
		/* For protocol A, we have to memcpy the payload into
		 * socket buffers, as we may complete right away
		 * as soon as we handed it over to tcp, at which point the data
		 * pages may become invalid.
		 *
		 * For data-integrity enabled, we copy it as well, so we can be
		 * sure that even if the bio pages may still be modified, it
		 * won't change the data on the wire, thus if the digest checks
		 * out ok after sending on this side, but does not fit on the
		 * receiving side, we sure have detected corruption elsewhere.
		 */
		if (!(s & (RQ_EXP_RECEIVE_ACK | RQ_EXP_WRITE_ACK)) || digest_size)
			err = _drbd_send_bio(peer_device, req->master_bio);
		else
			err = _drbd_send_zc_bio(peer_device, req->master_bio);

		/* double check digest, sometimes buffers have been modified in flight. */
		if (digest_size > 0) {
			drbd_csum_bio(peer_device->connection->integrity_tfm, req->master_bio, after);
			if (memcmp(before, after, digest_size)) {
				drbd_warn(device,
					"Digest mismatch, buffer modified by upper layers during write: %llus +%u\n",
					(unsigned long long)req->i.sector, req->i.size);
			}
		}
	}
out:
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

/* answer packet, used to send data back for read requests:
 *  Peer       -> (diskless) R_PRIMARY   (P_DATA_REPLY)
 *  L_SYNC_SOURCE -> L_SYNC_TARGET         (P_RS_DATA_REPLY)
 */
int drbd_send_block(struct drbd_peer_device *peer_device, enum drbd_packet cmd,
		    struct drbd_peer_request *peer_req)
{
	struct p_data *p;
	int err;
	int digest_size;

	digest_size = peer_device->connection->integrity_tfm ?
		      crypto_shash_digestsize(peer_device->connection->integrity_tfm) : 0;

	p = drbd_prepare_command(peer_device, sizeof(*p) + digest_size, DATA_STREAM);

	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(peer_req->i.sector);
	p->block_id = peer_req->block_id;
	p->seq_num = 0;  /* unused */
	p->dp_flags = 0;
	if (digest_size)
		drbd_csum_pages(peer_device->connection->integrity_tfm, peer_req->page_chain.head, p + 1);
	additional_size_command(peer_device->connection, DATA_STREAM, peer_req->i.size);
	err = __send_command(peer_device->connection,
			     peer_device->device->vnr, cmd, DATA_STREAM);
	if (!err)
		err = _drbd_send_zc_ee(peer_device, peer_req);
	mutex_unlock(&peer_device->connection->mutex[DATA_STREAM]);

	return err;
}

int drbd_send_out_of_sync(struct drbd_peer_device *peer_device, sector_t sector, unsigned int size)
{
	struct p_block_desc *p;

	p = drbd_prepare_command(peer_device, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->sector = cpu_to_be64(sector);
	p->blksize = cpu_to_be32(size);
	return drbd_send_command(peer_device, P_OUT_OF_SYNC, DATA_STREAM);
}

int drbd_send_dagtag(struct drbd_connection *connection, u64 dagtag)
{
	struct p_dagtag *p;

	if (connection->agreed_pro_version < 110)
		return 0;

	p = conn_prepare_command(connection, sizeof(*p), DATA_STREAM);
	if (!p)
		return -EIO;
	p->dagtag = cpu_to_be64(dagtag);
	return send_command(connection, -1, P_DAGTAG, DATA_STREAM);
}

/* primary_peer_present_and_not_two_primaries_allowed() */
static bool primary_peer_present(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	struct net_conf *nc;
	bool two_primaries, rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		nc = rcu_dereference(connection->transport.net_conf);
		two_primaries = nc ? nc->two_primaries : false;

		if (connection->peer_role[NOW] == R_PRIMARY && !two_primaries) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool any_disk_is_uptodate(struct drbd_device *device)
{
	bool ret = false;

	rcu_read_lock();
	if (device->disk_state[NOW] == D_UP_TO_DATE)
		ret = true;
	else {
		struct drbd_peer_device *peer_device;

		for_each_peer_device_rcu(peer_device, device) {
			if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
				ret = true;
				break;
			}
		}
	}
	rcu_read_unlock();

	return ret;
}

static int try_to_promote(struct drbd_device *device, long timeout, bool ndelay)
{
	struct drbd_resource *resource = device->resource;
	int rv, retry = timeout / (HZ / 5); /* One try every 200ms */
	do {
		rv = drbd_set_role(resource, R_PRIMARY, false, NULL);
		if (ndelay)
			break;
		if (rv >= SS_SUCCESS || timeout == 0) {
			return rv;
		} else if (rv == SS_CW_FAILED_BY_PEER) {
			/* Probably udev has it open read-only on one of the peers */
			long t = schedule_timeout_interruptible(HZ / 5);
			if (t < 0)
				break;
			timeout -= HZ / 5;
		} else if (rv == SS_TWO_PRIMARIES) {
			/* Wait till the peer demoted itself */
			timeout = wait_event_interruptible_timeout(resource->state_wait,
				resource->role[NOW] == R_PRIMARY ||
				(!primary_peer_present(resource) && any_disk_is_uptodate(device)),
				timeout);
			if (timeout <= 0)
				break;
		} else if (rv == SS_NO_UP_TO_DATE_DISK) {
			/* Wait until we get a connection established */
			timeout = wait_event_interruptible_timeout(resource->state_wait,
				any_disk_is_uptodate(device), timeout);
			if (timeout <= 0)
				break;
		} else {
			return rv;
		}
	} while (--retry);
	return rv;
}

static int ro_open_cond(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;

	if (!device->have_quorum[NOW])
		return -ENODATA;
	else if (resource->role[NOW] != R_PRIMARY &&
		primary_peer_present(resource) && !drbd_allow_oos)
		return -EMEDIUMTYPE;
	else if (any_disk_is_uptodate(device))
		return 0;
	else
		return -EAGAIN;
}

enum ioc_rv {
	IOC_SLEEP = 0,
	IOC_OK = 1,
	IOC_ABORT = 2,
};

static enum ioc_rv inc_open_count(struct drbd_device *device, fmode_t mode)
{
	struct drbd_resource *resource = device->resource;
	enum ioc_rv r = mode & FMODE_NDELAY ? IOC_ABORT : IOC_SLEEP;

	if (test_bit(DOWN_IN_PROGRESS, &resource->flags))
		return IOC_ABORT;

	spin_lock_irq(&resource->req_lock);
	if (test_bit(UNREGISTERED, &device->flags))
		r = IOC_ABORT;
	else if (!resource->remote_state_change) {
		r = IOC_OK;
		if (mode & FMODE_WRITE)
			device->open_rw_cnt++;
		else
			device->open_ro_cnt++;
	}
	spin_unlock_irq(&resource->req_lock);

	return r;
}

static void __prune_or_free_openers(struct drbd_device *device, pid_t pid)
{
	struct opener *pos, *tmp;

	list_for_each_entry_safe(pos, tmp, &device->openers.list, list) {
		// if pid == 0, i.e., counts were 0, delete all entries, else the matching one
		if (pid == 0 || pid == pos->pid) {
			dynamic_drbd_dbg(device, "%sopeners del: %s(%d)\n", pid == 0 ? "" : "all ",
					pos->comm, pos->pid);
			list_del(&pos->list);
			kfree(pos);

			/* in case we remove a real process, stop here, there might be multiple openers with the same pid */
			/* this assumes that the oldest opener with the same pid releases first. "as good as it gets" */
			if (pid != 0)
				return;
		}
	}
}

static void free_openers(struct drbd_device *device) {
	__prune_or_free_openers(device, 0);
}

/* caller needs to hold the the open_release_lock */
static void add_opener(struct drbd_device *device)
{
	struct opener *opener;
	int len = 0;

	list_for_each_entry(opener, &device->openers.list, list)
		if (++len > 100) { /* 100 ought to be enough for everybody */
			dynamic_drbd_dbg(device, "openers: list full, do not add new opener\n");
			return;
		}

	opener = kmalloc(sizeof(*opener), GFP_NOIO);
	if (!opener) {
		return;
	}

	get_task_comm(opener->comm, current);
	opener->pid = task_pid_nr(current);
	opener->opened = ktime_get_real();
	list_add(&opener->list, &device->openers.list);
	dynamic_drbd_dbg(device, "openers add: %s(%d)\n", opener->comm, opener->pid);
}

static int drbd_open(struct block_device *bdev, fmode_t mode)
{
	struct drbd_device *device = bdev->bd_disk->private_data;
	struct drbd_resource *resource = device->resource;
	long timeout = resource->res_opts.auto_promote_timeout * HZ / 10;
	enum ioc_rv r;
	int err = 0;

	/* Fail read-only open from systemd-udev (version <= 238) */
	if (resource->role[NOW] != R_PRIMARY && !(mode & FMODE_WRITE) && !drbd_allow_oos) {
		char comm[TASK_COMM_LEN];
		get_task_comm(comm, current);
		if (!strcmp("systemd-udevd", comm))
			return -EACCES;
	}

	/* Fail read-write open early,
	 * in case someone explicitly set us read-only (blockdev --setro) */
	if (bdev_read_only(bdev) && (mode & FMODE_WRITE))
		return -EACCES;

	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 3);

	mutex_lock(&resource->open_release);

	timeout = wait_event_interruptible_timeout(resource->twopc_wait,
						   (r = inc_open_count(device, mode)),
						   timeout);

	if (r == IOC_ABORT || (r == IOC_SLEEP && timeout <= 0)) {
		mutex_unlock(&resource->open_release);

		kref_debug_put(&device->kref_debug, 3);
		kref_put(&device->kref, drbd_destroy_device);
		return -EAGAIN;
	}

	if (resource->res_opts.auto_promote) {
		enum drbd_state_rv rv;
		/* Allow opening in read-only mode on an unconnected secondary.
		   This avoids split brain when the drbd volume gets opened
		   temporarily by udev while it scans for PV signatures. */

		if (mode & FMODE_WRITE) {
			if (resource->role[NOW] == R_SECONDARY) {
				rv = try_to_promote(device, timeout, (mode & FMODE_NDELAY));
				if (rv < SS_SUCCESS)
					drbd_info(resource, "Auto-promote failed: %s\n",
						  drbd_set_st_err_str(rv));
			}
		} else if ((mode & FMODE_NDELAY) == 0) {
			wait_event_interruptible_timeout(resource->state_wait,
				ro_open_cond(device) != -EAGAIN,
				resource->res_opts.auto_promote_timeout * HZ / 10);
		}
	} else if (resource->role[NOW] != R_PRIMARY &&
			!(mode & FMODE_WRITE) && !drbd_allow_oos) {
		err = -EMEDIUMTYPE;
		goto out;
	}

	if (test_bit(UNREGISTERED, &device->flags)) {
		err = -ENODEV;
	} else if (mode & FMODE_WRITE) {
		if (resource->role[NOW] != R_PRIMARY)
			err = -EROFS;
	} else /* READ access only */ {
		err = ro_open_cond(device);
	}
out:
	/* still keep mutex, but release ASAP */
	if (!err)
		add_opener(device);

	mutex_unlock(&resource->open_release);
	if (err) {
		drbd_release(bdev->bd_disk, mode);
		if (err == -EAGAIN && !(mode & FMODE_NDELAY))
			err = -EMEDIUMTYPE;
	}

	return err;
}

void drbd_open_counts(struct drbd_resource *resource, int *rw_count_ptr, int *ro_count_ptr)
{
	struct drbd_device *device;
	int vnr, rw_count = 0, ro_count = 0;

	idr_for_each_entry(&resource->devices, device, vnr) {
		rw_count += device->open_rw_cnt;
		ro_count += device->open_ro_cnt;
	}
	*rw_count_ptr = rw_count;
	*ro_count_ptr = ro_count;
}

static void drbd_release(struct gendisk *gd, fmode_t mode)
{
	struct drbd_device *device = gd->private_data;
	struct drbd_resource *resource = device->resource;
	int open_rw_cnt, open_ro_cnt;

	mutex_lock(&resource->open_release);
	if (mode & FMODE_WRITE)
		device->open_rw_cnt--;
	else
		device->open_ro_cnt--;

	drbd_open_counts(resource, &open_rw_cnt, &open_ro_cnt);

	if (open_ro_cnt == 0)
		wake_up_all(&resource->state_wait);

	if (test_bit(UNREGISTERED, &device->flags) &&
	    device->open_rw_cnt == 0 && device->open_ro_cnt == 0 &&
	    !test_and_set_bit(DESTROYING_DEV, &device->flags))
		call_rcu(&device->rcu, drbd_reclaim_device);

	if (resource->res_opts.auto_promote) {
		enum drbd_state_rv rv;

		if (mode & FMODE_WRITE &&
		    open_rw_cnt == 0 &&
		    resource->role[NOW] == R_PRIMARY &&
		    !test_bit(EXPLICIT_PRIMARY, &resource->flags)) {
			rv = drbd_set_role(resource, R_SECONDARY, false, NULL);
			if (rv < SS_SUCCESS)
				drbd_warn(resource, "Auto-demote failed: %s\n",
					  drbd_set_st_err_str(rv));
		}
	}

	/* if the open counts are 0, we free the whole list, otherwise we remove the specific pid */
	__prune_or_free_openers(device,
			(open_ro_cnt == 0 && open_rw_cnt == 0) ? 0 : task_pid_nr(current));

	mutex_unlock(&resource->open_release);

	kref_debug_put(&device->kref_debug, 3);
	kref_put(&device->kref, drbd_destroy_device);  /* might destroy the resource as well */
}

/* need to hold resource->req_lock */
void drbd_queue_unplug(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	u64 dagtag_sector;

	dagtag_sector = resource->dagtag_sector;

	for_each_connection(connection, resource) {
		/* use the "next" slot */
		unsigned int i = !connection->todo.unplug_slot;
		connection->todo.unplug_dagtag_sector[i] = dagtag_sector;
		wake_up(&connection->sender_work.q_wait);
	}
}

static void drbd_set_defaults(struct drbd_device *device)
{
	device->disk_state[NOW] = D_DISKLESS;
}

void drbd_cleanup_device(struct drbd_device *device)
{
	device->al_writ_cnt = 0;
	device->bm_writ_cnt = 0;
	device->read_cnt = 0;
	device->writ_cnt = 0;

	if (device->bitmap) {
		/* maybe never allocated. */
		drbd_bm_resize(device, 0, 1);
		drbd_bm_free(device->bitmap);
		device->bitmap = NULL;
	}

	clear_bit(AL_SUSPENDED, &device->flags);
	drbd_set_defaults(device);
}


static void drbd_destroy_mempools(void)
{
	bioset_exit(&drbd_io_bio_set);
	bioset_exit(&drbd_md_io_bio_set);
	mempool_exit(&drbd_md_io_page_pool);
	mempool_exit(&drbd_ee_mempool);
	mempool_exit(&drbd_request_mempool);
	if (drbd_ee_cache)
		kmem_cache_destroy(drbd_ee_cache);
	if (drbd_request_cache)
		kmem_cache_destroy(drbd_request_cache);
	if (drbd_bm_ext_cache)
		kmem_cache_destroy(drbd_bm_ext_cache);
	if (drbd_al_ext_cache)
		kmem_cache_destroy(drbd_al_ext_cache);

	drbd_ee_cache        = NULL;
	drbd_request_cache   = NULL;
	drbd_bm_ext_cache    = NULL;
	drbd_al_ext_cache    = NULL;

	return;
}

static int drbd_create_mempools(void)
{
	const int number = (DRBD_MAX_BIO_SIZE/PAGE_SIZE) * drbd_minor_count;
	int ret;

	/* caches */
	drbd_request_cache = kmem_cache_create(
		"drbd_req", sizeof(struct drbd_request), 0, 0, NULL);
	if (drbd_request_cache == NULL)
		goto Enomem;

	drbd_ee_cache = kmem_cache_create(
		"drbd_ee", sizeof(struct drbd_peer_request), 0, 0, NULL);
	if (drbd_ee_cache == NULL)
		goto Enomem;

	drbd_bm_ext_cache = kmem_cache_create(
		"drbd_bm", sizeof(struct bm_extent), 0, 0, NULL);
	if (drbd_bm_ext_cache == NULL)
		goto Enomem;

	drbd_al_ext_cache = kmem_cache_create(
		"drbd_al", sizeof(struct lc_element), 0, 0, NULL);
	if (drbd_al_ext_cache == NULL)
		goto Enomem;

	/* mempools */
	ret = bioset_init(&drbd_io_bio_set, BIO_POOL_SIZE, 0, 0);
	if (ret)
		goto Enomem;

	ret = bioset_init(&drbd_md_io_bio_set, DRBD_MIN_POOL_PAGES, 0,
			  BIOSET_NEED_BVECS);
	if (ret)
		goto Enomem;

	ret = mempool_init_page_pool(&drbd_md_io_page_pool, DRBD_MIN_POOL_PAGES, 0);
	if (ret)
		goto Enomem;

	ret = mempool_init_slab_pool(&drbd_request_mempool, number,
				     drbd_request_cache);
	if (ret)
		goto Enomem;

	ret = mempool_init_slab_pool(&drbd_ee_mempool, number, drbd_ee_cache);
	if (ret)
		goto Enomem;

	return 0;

Enomem:
	drbd_destroy_mempools(); /* in case we allocated some */
	return -ENOMEM;
}

static void free_peer_device(struct drbd_peer_device *peer_device)
{
	if (test_and_clear_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags))
		up_read_non_owner(&peer_device->device->uuid_sem);

	lc_destroy(peer_device->resync_lru);
	kfree(peer_device->rs_plan_s);
	kfree(peer_device->conf);
	kfree(peer_device);
}

static void drbd_device_finalize_work_fn(struct work_struct *work)
{
	struct drbd_device *device = container_of(work, struct drbd_device, finalize_work);
	struct drbd_resource *resource = device->resource;

	if (device->bitmap) {
		drbd_bm_free(device->bitmap);
		device->bitmap = NULL;
	}

	put_disk(device->vdisk);
	blk_cleanup_queue(device->rq_queue);

	kfree(device);

	kref_debug_put(&resource->kref_debug, 4);
	kref_put(&resource->kref, drbd_destroy_resource);
}

/* may not sleep, called from call_rcu. */
void drbd_destroy_device(struct kref *kref)
{
	struct drbd_device *device = container_of(kref, struct drbd_device, kref);
	struct drbd_peer_device *peer_device, *tmp;

	/* cleanup stuff that may have been allocated during
	 * device (re-)configuration or state changes */

	free_openers(device);

	lc_destroy(device->act_log);
	for_each_peer_device_safe(peer_device, tmp, device) {
		kref_debug_put(&peer_device->connection->kref_debug, 3);
		kref_put(&peer_device->connection->kref, drbd_destroy_connection);
		free_peer_device(peer_device);
	}

	__free_page(device->md_io.page);
	kref_debug_destroy(&device->kref_debug);

	INIT_WORK(&device->finalize_work, drbd_device_finalize_work_fn);
	schedule_work(&device->finalize_work);
}

static void free_page_pool(struct drbd_resource *resource)
{
	struct page *page;

	while (resource->pp_pool) {
		page = resource->pp_pool;
		resource->pp_pool = page_chain_next(page);
		__free_page(page);
		resource->pp_vacant--;
	}
}

void drbd_destroy_resource(struct kref *kref)
{
	struct drbd_resource *resource = container_of(kref, struct drbd_resource, kref);

	free_page_pool(resource);
	idr_destroy(&resource->devices);
	free_cpumask_var(resource->cpu_mask);
	kfree(resource->name);
	kref_debug_destroy(&resource->kref_debug);
	kfree(resource);
	module_put(THIS_MODULE);
}

void drbd_reclaim_resource(struct rcu_head *rp)
{
	struct drbd_resource *resource = container_of(rp, struct drbd_resource, rcu);
	struct queued_twopc *q, *q1;
	struct drbd_connection *connection, *tmp;

	spin_lock_irq(&resource->queued_twopc_lock);
	list_for_each_entry_safe(q, q1, &resource->queued_twopc, w.list) {
		list_del(&q->w.list);
		kref_put(&q->connection->kref, drbd_destroy_connection);
		kfree(q);
	}
	spin_unlock_irq(&resource->queued_twopc_lock);

	drbd_thread_stop_nowait(&resource->worker);

	list_for_each_entry_safe(connection, tmp, &resource->twopc_parents, twopc_parent_list) {
		kref_debug_put(&connection->kref_debug, 9);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
	mempool_free(resource->peer_ack_req, &drbd_request_mempool);
	kref_debug_put(&resource->kref_debug, 8);
	kref_put(&resource->kref, drbd_destroy_resource);
}

/* One global retry thread, if we need to push back some bio and have it
 * reinserted through our make request function.
 */
static struct retry_worker {
	struct workqueue_struct *wq;
	struct work_struct worker;

	spinlock_t lock;
	struct list_head writes;
} retry;

static void drbd_req_destroy_lock(struct kref *kref)
{
	struct drbd_request *req = container_of(kref, struct drbd_request, kref);
	struct drbd_resource *resource = req->device->resource;

	spin_lock_irq(&resource->req_lock);
	drbd_req_destroy(kref);
	spin_unlock_irq(&resource->req_lock);
}

static void do_retry(struct work_struct *ws)
{
	struct retry_worker *retry = container_of(ws, struct retry_worker, worker);
	LIST_HEAD(writes);
	struct drbd_request *req, *tmp;

	spin_lock_irq(&retry->lock);
	list_splice_init(&retry->writes, &writes);
	spin_unlock_irq(&retry->lock);

	list_for_each_entry_safe(req, tmp, &writes, tl_requests) {
		struct drbd_device *device = req->device;
		struct bio *bio = req->master_bio;
		unsigned long start_jif = req->start_jif;
		bool expected;
		ktime_get_accounting_assign(ktime_t start_kt, req->start_kt);


		expected =
			expect(device, atomic_read(&req->completion_ref) == 0) &&
			expect(device, req->local_rq_state & RQ_POSTPONED) &&
			expect(device, (req->local_rq_state & RQ_LOCAL_PENDING) == 0 ||
			       (req->local_rq_state & RQ_LOCAL_ABORTED) != 0);

		if (!expected)
			drbd_err(device, "req=%p completion_ref=%d rq_state=%x\n",
				req, atomic_read(&req->completion_ref),
				req->local_rq_state);

		/* We still need to put one kref associated with the
		 * "completion_ref" going zero in the code path that queued it
		 * here.  The request object may still be referenced by a
		 * frozen local req->private_bio, in case we force-detached.
		 */
		kref_put(&req->kref, drbd_req_destroy_lock);

		/* A single suspended or otherwise blocking device may stall
		 * all others as well.  Fortunately, this code path is to
		 * recover from a situation that "should not happen":
		 * concurrent writes in multi-primary setup.
		 * In a "normal" lifecycle, this workqueue is supposed to be
		 * destroyed without ever doing anything.
		 * If it turns out to be an issue anyways, we can do per
		 * resource (replication group) or per device (minor) retry
		 * workqueues instead.
		 */

		/* We are not just doing submit_bio_noacct(),
		 * as we want to keep the start_time information. */
		__drbd_make_request(device, bio, start_kt, start_jif);
	}
}

/* called via drbd_req_put_completion_ref(),
 * holds resource->req_lock */
void drbd_restart_request(struct drbd_request *req)
{
	unsigned long flags;
	spin_lock_irqsave(&retry.lock, flags);
	list_move_tail(&req->tl_requests, &retry.writes);
	spin_unlock_irqrestore(&retry.lock, flags);

	/* Drop the extra reference that would otherwise
	 * have been dropped by complete_master_bio.
	 * do_retry() needs to grab a new one. */
	dec_ap_bio(req->device, bio_data_dir(req->master_bio));

	queue_work(retry.wq, &retry.worker);
}


static void drbd_cleanup(void)
{
	/* first remove proc,
	 * drbdsetup uses its presence to detect
	 * whether DRBD is loaded.
	 * If we would get stuck in proc removal,
	 * but have netlink already deregistered,
	 * some drbdsetup commands may wait forever
	 * for an answer.
	 */
	if (drbd_proc)
		remove_proc_entry("drbd", NULL);

	if (retry.wq)
		destroy_workqueue(retry.wq);

	drbd_genl_unregister();
	drbd_debugfs_cleanup();

	drbd_destroy_mempools();
	unregister_blkdev(DRBD_MAJOR, "drbd");

	idr_destroy(&drbd_devices);

	pr_info("module cleanup done.\n");
}

static void drbd_init_workqueue(struct drbd_work_queue* wq)
{
	spin_lock_init(&wq->q_lock);
	INIT_LIST_HEAD(&wq->q);
	init_waitqueue_head(&wq->q_wait);
}

struct completion_work {
	struct drbd_work w;
	struct completion done;
};

static int w_complete(struct drbd_work *w, int cancel)
{
	struct completion_work *completion_work =
		container_of(w, struct completion_work, w);

	complete(&completion_work->done);
	return 0;
}

void drbd_queue_work(struct drbd_work_queue *q, struct drbd_work *w)
{
	unsigned long flags;

	spin_lock_irqsave(&q->q_lock, flags);
	list_add_tail(&w->list, &q->q);
	spin_unlock_irqrestore(&q->q_lock, flags);
	wake_up(&q->q_wait);
}

void drbd_flush_workqueue(struct drbd_work_queue *work_queue)
{
	struct completion_work completion_work;

	completion_work.w.cb = w_complete;
	init_completion(&completion_work.done);
	drbd_queue_work(work_queue, &completion_work.w);
	wait_for_completion(&completion_work.done);
}

struct drbd_resource *drbd_find_resource(const char *name)
{
	struct drbd_resource *resource;

	if (!name || !name[0])
		return NULL;

	rcu_read_lock();
	for_each_resource_rcu(resource, &drbd_resources) {
		if (!strcmp(resource->name, name)) {
			kref_get(&resource->kref);
			goto found;
		}
	}
	resource = NULL;
found:
	rcu_read_unlock();
	return resource;
}

static void drbd_put_send_buffers(struct drbd_connection *connection)
{
	unsigned int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		if (connection->send_buffer[i].page) {
			put_page(connection->send_buffer[i].page);
			connection->send_buffer[i].page = NULL;
		}
	}
}

static int drbd_alloc_send_buffers(struct drbd_connection *connection)
{
	unsigned int i;

	for (i = DATA_STREAM; i <= CONTROL_STREAM ; i++) {
		struct page *page;

		page = alloc_page(GFP_KERNEL);
		if (!page) {
			drbd_put_send_buffers(connection);
			return -ENOMEM;
		}
		connection->send_buffer[i].page = page;
		connection->send_buffer[i].unsent =
		connection->send_buffer[i].pos = page_address(page);
	}

	return 0;
}

void drbd_flush_peer_acks(struct drbd_resource *resource)
{
	spin_lock_irq(&resource->req_lock);
	if (resource->peer_ack_req) {
		resource->last_peer_acked_dagtag = resource->peer_ack_req->dagtag_sector;
		drbd_queue_peer_ack(resource, resource->peer_ack_req);
		resource->peer_ack_req = NULL;
	}
	spin_unlock_irq(&resource->req_lock);
}

static void peer_ack_timer_fn(struct timer_list *t)
{
	struct drbd_resource *resource = from_timer(resource, t, peer_ack_timer);

	drbd_flush_peer_acks(resource);
}

void conn_free_crypto(struct drbd_connection *connection)
{
	crypto_free_shash(connection->csums_tfm);
	crypto_free_shash(connection->verify_tfm);
	crypto_free_shash(connection->cram_hmac_tfm);
	crypto_free_shash(connection->integrity_tfm);
	crypto_free_shash(connection->peer_integrity_tfm);
	kfree(connection->int_dig_in);
	kfree(connection->int_dig_vv);

	connection->csums_tfm = NULL;
	connection->verify_tfm = NULL;
	connection->cram_hmac_tfm = NULL;
	connection->integrity_tfm = NULL;
	connection->peer_integrity_tfm = NULL;
	connection->int_dig_in = NULL;
	connection->int_dig_vv = NULL;
}

static void wake_all_device_misc(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr)
		wake_up(&device->misc_wait);
	rcu_read_unlock();
}

int set_resource_options(struct drbd_resource *resource, struct res_opts *res_opts)
{
	struct drbd_connection *connection;
	cpumask_var_t new_cpu_mask;
	int err;
	bool wake_device_misc = false;
	bool force_state_recalc = false;
	unsigned long irq_flags;

	if (!zalloc_cpumask_var(&new_cpu_mask, GFP_KERNEL))
		return -ENOMEM;

	/* silently ignore cpu mask on UP kernel */
	if (nr_cpu_ids > 1 && res_opts->cpu_mask[0] != 0) {
		err = bitmap_parse(res_opts->cpu_mask, DRBD_CPU_MASK_SIZE,
				   cpumask_bits(new_cpu_mask), nr_cpu_ids);
		if (err == -EOVERFLOW) {
			/* So what. mask it out. */
			cpumask_var_t tmp_cpu_mask;
			if (zalloc_cpumask_var(&tmp_cpu_mask, GFP_KERNEL)) {
				cpumask_setall(tmp_cpu_mask);
				cpumask_and(new_cpu_mask, new_cpu_mask, tmp_cpu_mask);
				drbd_warn(resource, "Overflow in bitmap_parse(%.12s%s), truncating to %u bits\n",
					res_opts->cpu_mask,
					strlen(res_opts->cpu_mask) > 12 ? "..." : "",
					nr_cpu_ids);
				free_cpumask_var(tmp_cpu_mask);
				err = 0;
			}
		}
		if (err) {
			drbd_warn(resource, "bitmap_parse() failed with %d\n", err);
			/* retcode = ERR_CPU_MASK_PARSE; */
			goto fail;
		}
	}
	if (res_opts->nr_requests < DRBD_NR_REQUESTS_MIN)
		res_opts->nr_requests = DRBD_NR_REQUESTS_MIN;

	if (resource->res_opts.on_no_quorum == ONQ_SUSPEND_IO &&
	    res_opts->on_no_quorum == ONQ_IO_ERROR) {
		/* when changing from suspend-io to io-error, we need
		 * to wake all waitqueues which are blocking io. we also
		 * need to cancel all pending requests with an io error. */
		force_state_recalc = true;
		wake_device_misc = true;

		for_each_connection(connection, resource) {
			tl_walk(connection, COMPLETION_RESUMED);
		}
	}

	if (resource->res_opts.nr_requests < res_opts->nr_requests)
		wake_device_misc = true;

	resource->res_opts = *res_opts;
	if (cpumask_empty(new_cpu_mask))
		drbd_calc_cpu_mask(&new_cpu_mask);
	if (!cpumask_equal(resource->cpu_mask, new_cpu_mask)) {
		cpumask_copy(resource->cpu_mask, new_cpu_mask);
		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			connection->receiver.reset_cpu_mask = 1;
			connection->ack_receiver.reset_cpu_mask = 1;
			connection->sender.reset_cpu_mask = 1;
		}
		rcu_read_unlock();
	}
	err = 0;

	if (force_state_recalc) {
		begin_state_change(resource, &irq_flags, CS_VERBOSE | CS_FORCE_RECALC);
		end_state_change(resource, &irq_flags);
	}

	if (wake_device_misc)
		wake_all_device_misc(resource);

fail:
	free_cpumask_var(new_cpu_mask);
	return err;

}

struct drbd_resource *drbd_create_resource(const char *name,
					   struct res_opts *res_opts)
{
	struct drbd_resource *resource;
	struct page *page;
	const int page_pool_count = DRBD_MAX_BIO_SIZE/PAGE_SIZE;
	int i;

	resource = kzalloc(sizeof(struct drbd_resource), GFP_KERNEL);
	if (!resource)
		goto fail;
	resource->name = kstrdup(name, GFP_KERNEL);
	if (!resource->name)
		goto fail_free_resource;
	if (!zalloc_cpumask_var(&resource->cpu_mask, GFP_KERNEL))
		goto fail_free_name;
	kref_init(&resource->kref);
	kref_debug_init(&resource->kref_debug, &resource->kref, &kref_class_resource);
	idr_init(&resource->devices);
	INIT_LIST_HEAD(&resource->connections);
	INIT_LIST_HEAD(&resource->transfer_log);
	INIT_LIST_HEAD(&resource->peer_ack_list);
	timer_setup(&resource->peer_ack_timer, peer_ack_timer_fn, 0);
	timer_setup(&resource->repost_up_to_date_timer, repost_up_to_date_fn, 0);
	sema_init(&resource->state_sem, 1);
	resource->role[NOW] = R_SECONDARY;
	if (set_resource_options(resource, res_opts))
		goto fail_free_name;
	resource->max_node_id = res_opts->node_id;
	resource->twopc_reply.initiator_node_id = -1;
	mutex_init(&resource->conf_update);
	mutex_init(&resource->adm_mutex);
	mutex_init(&resource->open_release);
	spin_lock_init(&resource->req_lock);
	INIT_LIST_HEAD(&resource->listeners);
	spin_lock_init(&resource->listeners_lock);
	init_waitqueue_head(&resource->state_wait);
	init_waitqueue_head(&resource->twopc_wait);
	init_waitqueue_head(&resource->barrier_wait);
	INIT_LIST_HEAD(&resource->twopc_parents);
	timer_setup(&resource->twopc_timer, twopc_timer_fn, 0);
	INIT_LIST_HEAD(&resource->twopc_work.list);
	INIT_LIST_HEAD(&resource->queued_twopc);
	spin_lock_init(&resource->queued_twopc_lock);
	timer_setup(&resource->queued_twopc_timer, queued_twopc_timer_fn, 0);
	drbd_init_workqueue(&resource->work);
	drbd_thread_init(resource, &resource->worker, drbd_worker, "worker");
	drbd_thread_start(&resource->worker);
	drbd_debugfs_resource_add(resource);
	resource->cached_min_aggreed_protocol_version = drbd_protocol_version_min;

	/* drbd's page pool */
	init_waitqueue_head(&resource->pp_wait);

	spin_lock_init(&resource->pp_lock);

	for (i = 0; i < page_pool_count; i++) {
		page = alloc_page(GFP_HIGHUSER);
		if (!page)
			goto fail_free_pages;
		set_page_chain_next_offset_size(page, resource->pp_pool, 0, 0);
		resource->pp_pool = page;
	}
	resource->pp_vacant = page_pool_count;

	list_add_tail_rcu(&resource->resources, &drbd_resources);

	return resource;

fail_free_pages:
	free_page_pool(resource);
fail_free_name:
	kfree(resource->name);
fail_free_resource:
	kfree(resource);
fail:
	return NULL;
}

/* caller must be under adm_mutex */
struct drbd_connection *drbd_create_connection(struct drbd_resource *resource,
					       struct drbd_transport_class *tc)
{
	struct drbd_connection *connection;
	int size;

	size = sizeof(*connection) - sizeof(connection->transport) + tc->instance_size;
	connection = kzalloc(size, GFP_KERNEL);
	if (!connection)
		return NULL;

	if (drbd_alloc_send_buffers(connection))
		goto fail;

	connection->current_epoch = kzalloc(sizeof(struct drbd_epoch), GFP_KERNEL);
	if (!connection->current_epoch)
		goto fail;

	INIT_LIST_HEAD(&connection->current_epoch->list);
	connection->epochs = 1;
	spin_lock_init(&connection->epoch_lock);

	INIT_LIST_HEAD(&connection->todo.work_list);
	connection->todo.req = NULL;

	atomic_set(&connection->ap_in_flight, 0);
	atomic_set(&connection->rs_in_flight, 0);
	connection->send.seen_any_write_yet = false;
	connection->send.current_epoch_nr = 0;
	connection->send.current_epoch_writes = 0;
	connection->send.current_dagtag_sector = 0;

	connection->cstate[NOW] = C_STANDALONE;
	connection->peer_role[NOW] = R_UNKNOWN;
	idr_init(&connection->peer_devices);

	drbd_init_workqueue(&connection->sender_work);
	mutex_init(&connection->mutex[DATA_STREAM]);
	mutex_init(&connection->mutex[CONTROL_STREAM]);

	INIT_LIST_HEAD(&connection->connect_timer_work.list);
	timer_setup(&connection->connect_timer, connect_timer_fn, 0);

	drbd_thread_init(resource, &connection->receiver, drbd_receiver, "receiver");
	connection->receiver.connection = connection;
	drbd_thread_init(resource, &connection->sender, drbd_sender, "sender");
	connection->sender.connection = connection;
	drbd_thread_init(resource, &connection->ack_receiver, drbd_ack_receiver, "ack_recv");
	connection->ack_receiver.connection = connection;
	INIT_LIST_HEAD(&connection->peer_requests);
	INIT_LIST_HEAD(&connection->connections);
	INIT_LIST_HEAD(&connection->active_ee);
	INIT_LIST_HEAD(&connection->sync_ee);
	INIT_LIST_HEAD(&connection->read_ee);
	INIT_LIST_HEAD(&connection->net_ee);
	INIT_LIST_HEAD(&connection->done_ee);
	init_waitqueue_head(&connection->ee_wait);

	kref_init(&connection->kref);
	kref_debug_init(&connection->kref_debug, &connection->kref, &kref_class_connection);

	INIT_WORK(&connection->peer_ack_work, drbd_send_peer_ack_wf);
	INIT_WORK(&connection->send_acks_work, drbd_send_acks_wf);

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 3);
	connection->resource = resource;
	connection->after_reconciliation.lost_node_id = -1;

	INIT_LIST_HEAD(&connection->transport.paths);
	connection->transport.log_prefix = resource->name;
	if (tc->init(&connection->transport))
		goto fail;

	return connection;

fail:
	drbd_put_send_buffers(connection);
	kfree(connection->current_epoch);
	kfree(connection);

	return NULL;
}

/* free the transport specific members (e.g., sockets) of a connection */
void drbd_transport_shutdown(struct drbd_connection *connection, enum drbd_tr_free_op op)
{
	mutex_lock(&connection->mutex[DATA_STREAM]);
	mutex_lock(&connection->mutex[CONTROL_STREAM]);

	flush_send_buffer(connection, DATA_STREAM);
	flush_send_buffer(connection, CONTROL_STREAM);

	connection->transport.ops->free(&connection->transport, op);
	if (op == DESTROY_TRANSPORT)
		drbd_put_transport_class(connection->transport.class);

	mutex_unlock(&connection->mutex[CONTROL_STREAM]);
	mutex_unlock(&connection->mutex[DATA_STREAM]);
}

void drbd_destroy_path(struct kref *kref)
{
	struct drbd_path *path = container_of(kref, struct drbd_path, kref);

	kfree(path);
}

void drbd_destroy_connection(struct kref *kref)
{
	struct drbd_connection *connection = container_of(kref, struct drbd_connection, kref);
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	int vnr;

	if (atomic_read(&connection->current_epoch->epoch_size) !=  0)
		drbd_err(connection, "epoch_size:%d\n", atomic_read(&connection->current_epoch->epoch_size));
	kfree(connection->current_epoch);

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		free_peer_device(peer_device);
		kref_debug_put(&device->kref_debug, 1);
		kref_put(&device->kref, drbd_destroy_device);
	}
	idr_destroy(&connection->peer_devices);

	kfree(connection->transport.net_conf);
	kref_debug_destroy(&connection->kref_debug);
	kfree(connection);
	kref_debug_put(&resource->kref_debug, 3);
	kref_put(&resource->kref, drbd_destroy_resource);
}

struct drbd_peer_device *create_peer_device(struct drbd_device *device, struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int err;

	peer_device = kzalloc(sizeof(struct drbd_peer_device), GFP_KERNEL);
	if (!peer_device)
		return NULL;

	peer_device->connection = connection;
	peer_device->device = device;
	peer_device->disk_state[NOW] = D_UNKNOWN;
	peer_device->repl_state[NOW] = L_OFF;
	spin_lock_init(&peer_device->peer_seq_lock);

	err = drbd_create_peer_device_default_config(peer_device);
	if (err) {
		kfree(peer_device);
		return NULL;
	}

	timer_setup(&peer_device->start_resync_timer, start_resync_timer_fn, 0);

	INIT_LIST_HEAD(&peer_device->resync_work.list);
	peer_device->resync_work.cb  = w_resync_timer;
	timer_setup(&peer_device->resync_timer, resync_timer_fn, 0);

	INIT_LIST_HEAD(&peer_device->propagate_uuids_work.list);
	peer_device->propagate_uuids_work.cb = w_send_uuids;

	mutex_init(&peer_device->resync_next_bit_mutex);

	atomic_set(&peer_device->ap_pending_cnt, 0);
	atomic_set(&peer_device->unacked_cnt, 0);
	atomic_set(&peer_device->rs_pending_cnt, 0);
	atomic_set(&peer_device->rs_sect_in, 0);

	peer_device->bitmap_index = -1;
	peer_device->resync_wenr = LC_FREE;
	peer_device->resync_finished_pdsk = D_UNKNOWN;

	return peer_device;
}

static int init_submitter(struct drbd_device *device)
{
	/* opencoded create_singlethread_workqueue(),
	 * to be able to use format string arguments */
	device->submit.wq =
		alloc_ordered_workqueue("drbd%u_submit", WQ_MEM_RECLAIM, device->minor);
	if (!device->submit.wq)
		return -ENOMEM;
	INIT_WORK(&device->submit.worker, do_submit);
	INIT_LIST_HEAD(&device->submit.writes);
	INIT_LIST_HEAD(&device->submit.peer_writes);
	return 0;
}

enum drbd_ret_code drbd_create_device(struct drbd_config_context *adm_ctx, unsigned int minor,
				      struct device_conf *device_conf, struct drbd_device **p_device)
{
	struct drbd_resource *resource = adm_ctx->resource;
	struct drbd_connection *connection;
	struct drbd_device *device;
	struct drbd_peer_device *peer_device, *tmp_peer_device;
	struct gendisk *disk;
	struct request_queue *q;
	LIST_HEAD(peer_devices);
	LIST_HEAD(tmp);
	int id;
	int vnr = adm_ctx->volume;
	enum drbd_ret_code err = ERR_NOMEM;
	bool locked = false;

	device = minor_to_device(minor);
	if (device)
		return ERR_MINOR_OR_VOLUME_EXISTS;

	/* GFP_KERNEL, we are outside of all write-out paths */
	device = kzalloc(sizeof(struct drbd_device), GFP_KERNEL);
	if (!device)
		return ERR_NOMEM;
	kref_init(&device->kref);
	kref_debug_init(&device->kref_debug, &device->kref, &kref_class_device);

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 4);
	device->resource = resource;
	device->minor = minor;
	device->vnr = vnr;
	device->device_conf = *device_conf;
#ifdef PARANOIA
	SET_MDEV_MAGIC(device);
#endif

	drbd_set_defaults(device);

	atomic_set(&device->ap_bio_cnt[READ], 0);
	atomic_set(&device->ap_bio_cnt[WRITE], 0);
	atomic_set(&device->ap_actlog_cnt, 0);
	atomic_set(&device->wait_for_actlog, 0);
	atomic_set(&device->wait_for_actlog_ecnt, 0);
	atomic_set(&device->local_cnt, 0);
	atomic_set(&device->rs_sect_ev, 0);
	atomic_set(&device->md_io.in_use, 0);

#ifdef CONFIG_DRBD_TIMING_STATS
	spin_lock_init(&device->timing_lock);
#endif
	spin_lock_init(&device->al_lock);

	INIT_LIST_HEAD(&device->pending_master_completion[0]);
	INIT_LIST_HEAD(&device->pending_master_completion[1]);
	INIT_LIST_HEAD(&device->pending_completion[0]);
	INIT_LIST_HEAD(&device->pending_completion[1]);
	INIT_LIST_HEAD(&device->openers.list);

	atomic_set(&device->pending_bitmap_work.n, 0);
	spin_lock_init(&device->pending_bitmap_work.q_lock);
	INIT_LIST_HEAD(&device->pending_bitmap_work.q);

	timer_setup(&device->md_sync_timer, md_sync_timer_fn, 0);
	timer_setup(&device->request_timer, request_timer_fn, 0);

	init_waitqueue_head(&device->misc_wait);
	init_waitqueue_head(&device->al_wait);
	init_waitqueue_head(&device->seq_wait);

	init_rwsem(&device->uuid_sem);

	q = blk_alloc_queue(NUMA_NO_NODE);
	if (!q)
		goto out_no_q;
	device->rq_queue = q;
	q->queuedata   = device;

	disk = alloc_disk(1);
	if (!disk)
		goto out_no_disk;
	device->vdisk = disk;

	disk->queue = q;
	disk->major = DRBD_MAJOR;
	disk->first_minor = minor;
	disk->fops = &drbd_ops;
	sprintf(disk->disk_name, "drbd%d", minor);
	disk->private_data = device;

	blk_queue_flag_set(QUEUE_FLAG_STABLE_WRITES, q);
	blk_queue_write_cache(q, true, true);

	device->md_io.page = alloc_page(GFP_KERNEL);
	if (!device->md_io.page)
		goto out_no_io_page;

	device->bitmap = drbd_bm_alloc();
	if (!device->bitmap)
		goto out_no_bitmap;
	device->read_requests = RB_ROOT;
	device->write_requests = RB_ROOT;

	BUG_ON(!mutex_is_locked(&resource->conf_update));
	for_each_connection(connection, resource) {
		peer_device = create_peer_device(device, connection);
		if (!peer_device)
			goto out_no_peer_device;
		list_add(&peer_device->peer_devices, &peer_devices);
	}

	/* Insert the new device into all idrs under req_lock
	   to guarantee a consistent object model. idr_preload() doesn't help
	   because it can only guarantee that a single idr_alloc() will
	   succeed. This fails (and will be retried) if no memory is
	   immediately available.
	   Keep in mid that RCU readers might find the device in the moment
	   we add it to the resources->devices IDR!
	*/

	INIT_LIST_HEAD(&device->peer_devices);
	INIT_LIST_HEAD(&device->pending_bitmap_io);

	locked = true;
	spin_lock_irq(&resource->req_lock);
	id = idr_alloc(&drbd_devices, device, minor, minor + 1, GFP_NOWAIT);
	if (id < 0) {
		if (id == -ENOSPC)
			err = ERR_MINOR_OR_VOLUME_EXISTS;
		goto out_no_minor_idr;
	}
	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 1);

	id = idr_alloc(&resource->devices, device, vnr, vnr + 1, GFP_NOWAIT);
	if (id < 0) {
		if (id == -ENOSPC)
			err = ERR_MINOR_OR_VOLUME_EXISTS;
		goto out_idr_remove_minor;
	}
	kref_get(&device->kref);
	kref_debug_get(&device->kref_debug, 1);

	list_for_each_entry_safe(peer_device, tmp_peer_device, &peer_devices, peer_devices) {
		connection = peer_device->connection;
		id = idr_alloc(&connection->peer_devices, peer_device,
			       device->vnr, device->vnr + 1, GFP_NOWAIT);
		if (id < 0)
			goto out_remove_peer_device;
		list_del(&peer_device->peer_devices);
		list_add_rcu(&peer_device->peer_devices, &device->peer_devices);
		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 3);
		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 1);
	}
	spin_unlock_irq(&resource->req_lock);
	locked = false;

	if (init_submitter(device)) {
		err = ERR_NOMEM;
		goto out_remove_peer_device;
	}

	add_disk(disk);
	device->have_quorum[OLD] =
	device->have_quorum[NEW] =
		(resource->res_opts.quorum == QOU_OFF);

	for_each_peer_device(peer_device, device) {
		connection = peer_device->connection;
		peer_device->node_id = connection->peer_node_id;

		if (connection->cstate[NOW] >= C_CONNECTED)
			drbd_connected(peer_device);
	}

	drbd_debugfs_device_add(device);
	*p_device = device;
	return NO_ERROR;

out_remove_peer_device:
	list_add_rcu(&tmp, &device->peer_devices);
	list_del_init(&device->peer_devices);
	synchronize_rcu();
	list_for_each_entry_safe(peer_device, tmp_peer_device, &tmp, peer_devices) {
		struct drbd_connection *connection = peer_device->connection;

		idr_remove(&connection->peer_devices, device->vnr);
		list_del(&peer_device->peer_devices);
		kfree(peer_device);
		kref_debug_put(&connection->kref_debug, 3);
		kref_put(&connection->kref, drbd_destroy_connection);
		kref_debug_put(&device->kref_debug, 1);
	}
	idr_remove(&resource->devices, vnr);
	kref_debug_put(&device->kref_debug, 1);

out_idr_remove_minor:
	idr_remove(&drbd_devices, minor);
	kref_debug_put(&device->kref_debug, 1);
out_no_minor_idr:
	if (locked)
		spin_unlock_irq(&resource->req_lock);
	synchronize_rcu();

out_no_peer_device:
	list_for_each_entry_safe(peer_device, tmp_peer_device, &peer_devices, peer_devices) {
		list_del(&peer_device->peer_devices);
		kfree(peer_device);
	}

	drbd_bm_free(device->bitmap);
out_no_bitmap:
	__free_page(device->md_io.page);
out_no_io_page:
	put_disk(disk);
out_no_disk:
	blk_cleanup_queue(q);
out_no_q:
	kref_put(&resource->kref, drbd_destroy_resource);
	kref_debug_put(&resource->kref_debug, 4);
		/* kref debugging wants an extra put, see has_refs() */
	kref_debug_put(&device->kref_debug, 4);
	kref_debug_destroy(&device->kref_debug);
	kfree(device);
	return err;
}

/**
 * drbd_unregister_device()  -  make a device "invisible"
 *
 * Remove the device from the drbd object model and unregister it in the
 * kernel.  Keep reference counts on device->kref; they are dropped in
 * drbd_reclaim_device().
 */
void drbd_unregister_device(struct drbd_device *device)
{
	struct drbd_resource *resource = device->resource;
	struct drbd_connection *connection;
	struct drbd_peer_device *peer_device;

	spin_lock_irq(&resource->req_lock);
	for_each_connection(connection, resource) {
		idr_remove(&connection->peer_devices, device->vnr);
	}
	idr_remove(&resource->devices, device->vnr);
	idr_remove(&drbd_devices, device_to_minor(device));
	spin_unlock_irq(&resource->req_lock);

	for_each_peer_device(peer_device, device)
		drbd_debugfs_peer_device_cleanup(peer_device);
	drbd_debugfs_device_cleanup(device);
	del_gendisk(device->vdisk);

	destroy_workqueue(device->submit.wq);
	device->submit.wq = NULL;
	del_timer_sync(&device->request_timer);
}

void drbd_reclaim_device(struct rcu_head *rp)
{
	struct drbd_device *device = container_of(rp, struct drbd_device, rcu);
	struct drbd_peer_device *peer_device;
	int i;

	for_each_peer_device(peer_device, device) {
		kref_debug_put(&device->kref_debug, 1);
		kref_put(&device->kref, drbd_destroy_device);
	}

	for (i = 0; i < 3; i++) {
		kref_debug_put(&device->kref_debug, 1);
		kref_put(&device->kref, drbd_destroy_device);
	}
}

/**
 * drbd_unregister_connection()  -  make a connection "invisible"
 *
 * Remove the connection from the drbd object model.  Keep reference counts on
 * connection->kref; they are dropped in drbd_reclaim_connection().
 */
void drbd_unregister_connection(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	LIST_HEAD(work_list);
	int vnr, rr;

	spin_lock_irq(&resource->req_lock);
	set_bit(C_UNREGISTERED, &connection->flags);
	smp_wmb();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		list_del_rcu(&peer_device->peer_devices);
		list_add(&peer_device->peer_devices, &work_list);
	}
	list_del_rcu(&connection->connections);
	spin_unlock_irq(&resource->req_lock);

	list_for_each_entry(peer_device, &work_list, peer_devices)
		drbd_debugfs_peer_device_cleanup(peer_device);
	drbd_debugfs_connection_cleanup(connection);

	del_connect_timer(connection);

	rr = drbd_free_peer_reqs(connection->resource, &connection->done_ee, false);
	if (rr)
		drbd_err(connection, "%d EEs in done list found!\n", rr);

	rr = drbd_free_peer_reqs(connection->resource, &connection->net_ee, true);
	if (rr)
		drbd_err(connection, "%d EEs in net list found!\n", rr);

	drbd_transport_shutdown(connection, DESTROY_TRANSPORT);
	drbd_put_send_buffers(connection);
	conn_free_crypto(connection);
}

void del_connect_timer(struct drbd_connection *connection)
{
	if (del_timer_sync(&connection->connect_timer)) {
		kref_debug_put(&connection->kref_debug, 11);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
}

void drbd_reclaim_connection(struct rcu_head *rp)
{
	struct drbd_connection *connection =
		container_of(rp, struct drbd_connection, rcu);
	struct drbd_peer_device *peer_device;
	int vnr;

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		kref_debug_put(&connection->kref_debug, 3);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
	kref_debug_put(&connection->kref_debug, 10);
	kref_put(&connection->kref, drbd_destroy_connection);
}

static int __init drbd_init(void)
{
	int err;

	initialize_kref_debugging();

	if (drbd_minor_count < DRBD_MINOR_COUNT_MIN
	||  drbd_minor_count > DRBD_MINOR_COUNT_MAX) {
		pr_err("invalid minor_count (%d)\n", drbd_minor_count);
#ifdef MODULE
		return -EINVAL;
#else
		drbd_minor_count = DRBD_MINOR_COUNT_DEF;
#endif
	}

	err = register_blkdev(DRBD_MAJOR, "drbd");
	if (err) {
		pr_err("unable to register block device major %d\n",
		       DRBD_MAJOR);
		return err;
	}

	/*
	 * allocate all necessary structs
	 */
	drbd_proc = NULL; /* play safe for drbd_cleanup */
	idr_init(&drbd_devices);

	mutex_init(&resources_mutex);
	INIT_LIST_HEAD(&drbd_resources);

	err = drbd_genl_register();
	if (err) {
		pr_err("unable to register generic netlink family\n");
		goto fail;
	}

	err = drbd_create_mempools();
	if (err)
		goto fail;

	err = -ENOMEM;
	drbd_proc = proc_create_single("drbd", S_IFREG | 0444 , NULL,
			drbd_seq_show);

	if (!drbd_proc)	{
		pr_err("unable to register proc file\n");
		goto fail;
	}

	retry.wq = create_singlethread_workqueue("drbd-reissue");
	if (!retry.wq) {
		pr_err("unable to create retry workqueue\n");
		goto fail;
	}
	INIT_WORK(&retry.worker, do_retry);
	spin_lock_init(&retry.lock);
	INIT_LIST_HEAD(&retry.writes);

	drbd_debugfs_init();

	pr_info("initialized. "
	       "Version: " REL_VERSION " (api:%d/proto:%d-%d)\n",
	       GENL_MAGIC_VERSION, PRO_VERSION_MIN, PRO_VERSION_MAX);
	pr_info("%s\n", drbd_buildtag());
	pr_info("registered as block device major %d\n", DRBD_MAJOR);
	return 0; /* Success! */

fail:
	drbd_cleanup();
	if (err == -ENOMEM)
		pr_err("ran out of memory\n");
	else
		pr_err("initialization failure\n");
	return err;
}

/* meta data management */

static
void drbd_md_encode(struct drbd_device *device, struct meta_data_on_disk_9 *buffer)
{
	int i;

	buffer->effective_size = cpu_to_be64(device->ldev->md.effective_size);
	buffer->current_uuid = cpu_to_be64(device->ldev->md.current_uuid);
	buffer->flags = cpu_to_be32(device->ldev->md.flags);
	buffer->magic = cpu_to_be32(DRBD_MD_MAGIC_09);

	buffer->md_size_sect  = cpu_to_be32(device->ldev->md.md_size_sect);
	buffer->al_offset     = cpu_to_be32(device->ldev->md.al_offset);
	buffer->al_nr_extents = cpu_to_be32(device->act_log->nr_elements);
	buffer->bm_bytes_per_bit = cpu_to_be32(BM_BLOCK_SIZE);
	buffer->device_uuid = cpu_to_be64(device->ldev->md.device_uuid);

	buffer->bm_offset = cpu_to_be32(device->ldev->md.bm_offset);
	buffer->la_peer_max_bio_size = cpu_to_be32(device->device_conf.max_bio_size);
	buffer->bm_max_peers = cpu_to_be32(device->bitmap->bm_max_peers);
	buffer->node_id = cpu_to_be32(device->ldev->md.node_id);
	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		struct drbd_peer_md *peer_md = &device->ldev->md.peers[i];

		buffer->peers[i].bitmap_uuid = cpu_to_be64(peer_md->bitmap_uuid);
		buffer->peers[i].bitmap_dagtag = cpu_to_be64(peer_md->bitmap_dagtag);
		buffer->peers[i].flags = cpu_to_be32(peer_md->flags & ~MDF_HAVE_BITMAP);
		buffer->peers[i].bitmap_index = cpu_to_be32(peer_md->bitmap_index);
	}
	BUILD_BUG_ON(ARRAY_SIZE(device->ldev->md.history_uuids) != ARRAY_SIZE(buffer->history_uuids));
	for (i = 0; i < ARRAY_SIZE(buffer->history_uuids); i++)
		buffer->history_uuids[i] = cpu_to_be64(device->ldev->md.history_uuids[i]);

	buffer->al_stripes = cpu_to_be32(device->ldev->md.al_stripes);
	buffer->al_stripe_size_4k = cpu_to_be32(device->ldev->md.al_stripe_size_4k);
}

int drbd_md_write(struct drbd_device *device, struct meta_data_on_disk_9 *buffer)
{
	sector_t sector;
	int err;

	if (drbd_md_dax_active(device->ldev)) {
		drbd_md_encode(device, drbd_dax_md_addr(device->ldev));
		arch_wb_cache_pmem(drbd_dax_md_addr(device->ldev),
				   sizeof(struct meta_data_on_disk_9));
		return 0;
	}

	memset(buffer, 0, sizeof(*buffer));

	drbd_md_encode(device, buffer);

	D_ASSERT(device, drbd_md_ss(device->ldev) == device->ldev->md.md_offset);
	sector = device->ldev->md.md_offset;

	err = drbd_md_sync_page_io(device, device->ldev, sector, REQ_OP_WRITE);
	if (err) {
		drbd_err(device, "meta data update failed!\n");
		drbd_chk_io_error(device, err, DRBD_META_IO_ERROR);
	}

	return err;
}

/**
 * __drbd_md_sync() - Writes the meta data super block (conditionally) if the MD_DIRTY flag bit is set
 * @device:	DRBD device.
 * @maybe:	meta data may in fact be "clean", the actual write may be skipped.
 */
static int __drbd_md_sync(struct drbd_device *device, bool maybe)
{
	struct meta_data_on_disk_9 *buffer;
	int err = -EIO;

	/* Don't accidentally change the DRBD meta data layout. */
	BUILD_BUG_ON(DRBD_PEERS_MAX != 32);
	BUILD_BUG_ON(HISTORY_UUIDS != 32);
	BUILD_BUG_ON(sizeof(struct meta_data_on_disk_9) != 4096);

	del_timer(&device->md_sync_timer);
	/* timer may be rearmed by drbd_md_mark_dirty() now. */
	if (!test_and_clear_bit(MD_DIRTY, &device->flags) && maybe)
		return 0;

	/* We use here D_FAILED and not D_ATTACHING because we try to write
	 * metadata even if we detach due to a disk failure! */
	if (!get_ldev_if_state(device, D_DETACHING))
		return -EIO;

	buffer = drbd_md_get_buffer(device, __func__);
	if (!buffer)
		goto out;

	err = drbd_md_write(device, buffer);

	drbd_md_put_buffer(device);
out:
	put_ldev(device);

	return err;
}

int drbd_md_sync(struct drbd_device *device)
{
	return __drbd_md_sync(device, false);
}

int drbd_md_sync_if_dirty(struct drbd_device *device)
{
	return __drbd_md_sync(device, true);
}

/**
 * drbd_md_mark_dirty() - Mark meta data super block as dirty
 * @device:	DRBD device.
 *
 * Call this function if you change anything that should be written to
 * the meta-data super block. This function sets MD_DIRTY, and starts a
 * timer that ensures that within five seconds you have to call drbd_md_sync().
 */
void drbd_md_mark_dirty(struct drbd_device *device)
{
	if (!test_and_set_bit(MD_DIRTY, &device->flags))
		mod_timer(&device->md_sync_timer, jiffies + 5*HZ);
}

void _drbd_uuid_push_history(struct drbd_device *device, u64 val) __must_hold(local)
{
	struct drbd_md *md = &device->ldev->md;
	int node_id, i;

	if (val == UUID_JUST_CREATED)
		return;

	val &= ~UUID_PRIMARY;

	if (val == (md->current_uuid & ~UUID_PRIMARY))
		return;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == md->node_id)
			continue;
		if (val == (md->peers[node_id].bitmap_uuid & ~UUID_PRIMARY))
			return;
	}

	for (i = 0; i < ARRAY_SIZE(md->history_uuids); i++) {
		if (md->history_uuids[i] == val)
			return;
	}

	for (i = ARRAY_SIZE(md->history_uuids) - 1; i > 0; i--)
		md->history_uuids[i] = md->history_uuids[i - 1];
	md->history_uuids[i] = val;
}

u64 _drbd_uuid_pull_history(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_md *md = &device->ldev->md;
	u64 first_history_uuid;
	int i;

	first_history_uuid = md->history_uuids[0];
	for (i = 0; i < ARRAY_SIZE(md->history_uuids) - 1; i++)
		md->history_uuids[i] = md->history_uuids[i + 1];
	md->history_uuids[i] = 0;

	return first_history_uuid;
}

static void __drbd_uuid_set_current(struct drbd_device *device, u64 val)
{
	drbd_md_mark_dirty(device);
	if (device->resource->role[NOW] == R_PRIMARY)
		val |= UUID_PRIMARY;
	else
		val &= ~UUID_PRIMARY;

	device->ldev->md.current_uuid = val;
	drbd_set_exposed_data_uuid(device, val);
}

static void __drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md = &device->ldev->md.peers[peer_device->node_id];

	drbd_md_mark_dirty(device);
	peer_md->bitmap_uuid = val;
	peer_md->bitmap_dagtag = val ? device->resource->dagtag_sector : 0;
}

void _drbd_uuid_set_current(struct drbd_device *device, u64 val) __must_hold(local)
{
	unsigned long flags;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	__drbd_uuid_set_current(device, val);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

void _drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 val) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	unsigned long flags;

	down_write(&device->uuid_sem);
	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	__drbd_uuid_set_bitmap(peer_device, val);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
	up_write(&device->uuid_sem);
}

/* call holding down_write(uuid_sem) */
void drbd_uuid_set_bitmap(struct drbd_peer_device *peer_device, u64 uuid) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	unsigned long flags;
	u64 previous_uuid;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	previous_uuid = drbd_bitmap_uuid(peer_device);
	if (previous_uuid)
		_drbd_uuid_push_history(device, previous_uuid);
	__drbd_uuid_set_bitmap(peer_device, uuid);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);
}

static u64 rotate_current_into_bitmap(struct drbd_device *device, u64 weak_nodes, u64 dagtag) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	struct drbd_peer_device *peer_device;
	int node_id;
	u64 bm_uuid, prev_c_uuid;
	u64 node_mask = 0;  /* bit mask of node-ids processed */
	u64 slot_mask = 0;  /* bit mask of on-disk bitmap slots processed */
	/* return value, bit mask of node-ids for which we
	 * actually set a new bitmap uuid */
	u64 got_new_bitmap_uuid = 0;

	if (device->ldev->md.current_uuid != UUID_JUST_CREATED)
		prev_c_uuid = device->ldev->md.current_uuid;
	else
		get_random_bytes(&prev_c_uuid, sizeof(u64));

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_disk_state pdsk;
		node_id = peer_device->node_id;
		if (peer_device->bitmap_index == -1) {
			struct peer_device_conf *pdc;
			pdc = rcu_dereference(peer_device->conf);
			if (pdc && !pdc->bitmap)
				node_mask |= NODE_MASK(node_id); /* ign intentional diskless */
			continue;
		}
		node_mask |= NODE_MASK(node_id);
		__set_bit(peer_device->bitmap_index, (unsigned long*)&slot_mask);
		bm_uuid = peer_md[node_id].bitmap_uuid;
		if (bm_uuid && bm_uuid != prev_c_uuid)
			continue;

		pdsk = peer_device->disk_state[NOW];
		if ((pdsk <= D_UNKNOWN && pdsk != D_NEGOTIATING) ||
		    (NODE_MASK(node_id) & weak_nodes)) {
			peer_md[node_id].bitmap_uuid = prev_c_uuid;
			peer_md[node_id].bitmap_dagtag = dagtag;
			drbd_md_mark_dirty(device);
			got_new_bitmap_uuid |= NODE_MASK(node_id);
		}
	}
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		int slot_nr;
		if (node_id == device->ldev->md.node_id)
			continue;
		if (node_mask & NODE_MASK(node_id))
			continue;
		slot_nr = peer_md[node_id].bitmap_index;
		if (slot_nr != -1) {
			if (test_bit(slot_nr, (unsigned long*)&slot_mask))
				continue;
			__set_bit(slot_nr, (unsigned long*)&slot_mask);
		}
		bm_uuid = peer_md[node_id].bitmap_uuid;
		if (bm_uuid && bm_uuid != prev_c_uuid)
			continue;
		if (slot_nr == -1) {
			slot_nr = find_first_zero_bit((unsigned long*)&slot_mask, sizeof(slot_mask) * BITS_PER_BYTE);
			__set_bit(slot_nr, (unsigned long*)&slot_mask);
		}
		peer_md[node_id].bitmap_uuid = prev_c_uuid;
		peer_md[node_id].bitmap_dagtag = dagtag;
		drbd_md_mark_dirty(device);
		/* count, but only if that bitmap index exists. */
		if (slot_nr < device->bitmap->bm_max_peers)
			got_new_bitmap_uuid |= NODE_MASK(node_id);
	}
	rcu_read_unlock();

	return got_new_bitmap_uuid;
}

static u64 initial_resync_nodes(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 nodes = 0;

	for_each_peer_device(peer_device, device) {
		if (peer_device->disk_state[NOW] == D_INCONSISTENT &&
		    peer_device->repl_state[NOW] == L_ESTABLISHED)
			nodes |= NODE_MASK(peer_device->node_id);
	}

	return nodes;
}

u64 drbd_weak_nodes_device(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 not_weak = 0;

	if (device->disk_state[NOW] == D_UP_TO_DATE)
		not_weak = NODE_MASK(device->resource->res_opts.node_id);

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_disk_state pdsk = peer_device->disk_state[NOW];
		if (!(pdsk <= D_FAILED || pdsk == D_UNKNOWN || pdsk == D_OUTDATED))
			not_weak |= NODE_MASK(peer_device->node_id);

	}
	rcu_read_unlock();

	return ~not_weak;
}


static bool __new_current_uuid_prepare(struct drbd_device *device, bool forced) __must_hold(local)
{
	u64 got_new_bitmap_uuid, val, old_current_uuid;
	int err;

	spin_lock_irq(&device->ldev->md.uuid_lock);
	got_new_bitmap_uuid = rotate_current_into_bitmap(device,
					forced ? initial_resync_nodes(device) : 0,
					device->resource->dagtag_sector);

	if (!got_new_bitmap_uuid) {
		spin_unlock_irq(&device->ldev->md.uuid_lock);
		return false;
	}

	old_current_uuid = device->ldev->md.current_uuid;
	get_random_bytes(&val, sizeof(u64));
	__drbd_uuid_set_current(device, val);
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	/* get it to stable storage _now_ */
	err = drbd_md_sync(device);
	if (err) {
		_drbd_uuid_set_current(device, old_current_uuid);
		return false;
	}

	return true;
}

static void __new_current_uuid_info(struct drbd_device *device, u64 weak_nodes)
{
	drbd_info(device, "new current UUID: %016llX weak: %016llX\n",
		  device->ldev->md.current_uuid, weak_nodes);
}

static void __new_current_uuid_send(struct drbd_device *device, u64 weak_nodes, bool forced) __must_hold(local)
{
	struct drbd_peer_device *peer_device;
	u64 im;

	for_each_peer_device_ref(peer_device, im, device) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			drbd_send_uuids(peer_device, forced ? 0 : UUID_FLAG_NEW_DATAGEN, weak_nodes);
	}
}

static void __drbd_uuid_new_current_send(struct drbd_device *device, bool forced) __must_hold(local)
{
	u64 weak_nodes;

	down_write(&device->uuid_sem);
	if (!__new_current_uuid_prepare(device, forced)) {
		up_write(&device->uuid_sem);
		return;
	}
	downgrade_write(&device->uuid_sem);
	weak_nodes = drbd_weak_nodes_device(device);
	__new_current_uuid_info(device, weak_nodes);
	__new_current_uuid_send(device, weak_nodes, forced);
	up_read(&device->uuid_sem);
}

static void __drbd_uuid_new_current_holding_uuid_sem(struct drbd_device *device) __must_hold(local)
{
	u64 weak_nodes;

	if (!__new_current_uuid_prepare(device, false))
		return;
	weak_nodes = drbd_weak_nodes_device(device);
	__new_current_uuid_info(device, weak_nodes);
}

static bool peer_can_fill_a_bitmap_slot(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	const bool intentional_diskless = device->device_conf.intentional_diskless;
	const int my_node_id = device->resource->res_opts.node_id;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == peer_device->node_id)
			continue;
		if (peer_device->bitmap_uuids[node_id] == 0) {
			struct drbd_peer_device *p2;
			p2 = peer_device_by_node_id(peer_device->device, node_id);
			if (p2 && !want_bitmap(p2))
				continue;

			if (node_id == my_node_id && intentional_diskless)
				continue;

			return true;
		}
	}

	return false;
}

static bool diskfull_peers_need_new_cur_uuid(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		/* Only an up-to-date peer persists a new current uuid! */
		if (peer_device->disk_state[NOW] < D_UP_TO_DATE)
			continue;
		if (peer_can_fill_a_bitmap_slot(peer_device)) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static bool a_lost_peer_is_on_same_cur_uuid(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_disk_state pdsk = peer_device->disk_state[NOW];

		if (pdsk >= D_INCONSISTENT && pdsk <= D_UNKNOWN &&
		    (device->exposed_data_uuid & ~UUID_PRIMARY) ==
		    (peer_device->current_uuid & ~UUID_PRIMARY) &&
		    !(peer_device->uuid_flags & UUID_FLAG_SYNC_TARGET)) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

/**
 * drbd_uuid_new_current() - Creates a new current UUID
 * @device:	DRBD device.
 *
 * Creates a new current UUID, and rotates the old current UUID into
 * the bitmap slot. Causes an incremental resync upon next connect.
 */
void drbd_uuid_new_current(struct drbd_device *device, bool forced)
{
	if (get_ldev_if_state(device, D_UP_TO_DATE)) {
		__drbd_uuid_new_current_send(device, forced);
		put_ldev(device);
	} else if (diskfull_peers_need_new_cur_uuid(device) ||
		   a_lost_peer_is_on_same_cur_uuid(device)) {
		struct drbd_peer_device *peer_device;
		/* The peers will store the new current UUID... */
		u64 current_uuid, weak_nodes;
		get_random_bytes(&current_uuid, sizeof(u64));
		if (device->resource->role[NOW] == R_PRIMARY)
			current_uuid |= UUID_PRIMARY;
		else
			current_uuid &= ~UUID_PRIMARY;
		drbd_set_exposed_data_uuid(device, current_uuid);
		drbd_info(device, "sending new current UUID: %016llX\n", current_uuid);

		weak_nodes = drbd_weak_nodes_device(device);
		for_each_peer_device(peer_device, device) {
			if (peer_device->repl_state[NOW] >= L_ESTABLISHED) {
				drbd_send_current_uuid(peer_device, current_uuid, weak_nodes);
				peer_device->current_uuid = current_uuid;
			}
		}
	}
}

void drbd_uuid_new_current_by_user(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	down_write(&device->uuid_sem);
	for_each_peer_device(peer_device, device)
		drbd_uuid_set_bitmap(peer_device, 0); /* Rotate UI_BITMAP to History 1, etc... */

	if (get_ldev(device)) {
		__drbd_uuid_new_current_holding_uuid_sem(device);
		put_ldev(device);
	}
	up_write(&device->uuid_sem);
}

static void drbd_propagate_uuids(struct drbd_device *device, u64 nodes)
{
	struct drbd_peer_device *peer_device;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (!(nodes & NODE_MASK(peer_device->node_id)))
			continue;

		if (peer_device->repl_state[NOW] < L_ESTABLISHED)
			continue;

		if (list_empty(&peer_device->propagate_uuids_work.list))
			drbd_queue_work(&peer_device->connection->sender_work,
					&peer_device->propagate_uuids_work);
	}
	rcu_read_unlock();
}

void drbd_uuid_received_new_current(struct drbd_peer_device *from_pd, u64 val, u64 weak_nodes) __must_hold(local)
{
	struct drbd_device *device = from_pd->device;
	u64 dagtag = from_pd->connection->last_dagtag_sector;
	struct drbd_peer_device *peer_device;
	u64 receipients = 0;
	bool set_current = true;

	down_write(&device->uuid_sem);
	spin_lock_irq(&device->ldev->md.uuid_lock);

	for_each_peer_device(peer_device, device) {
		if (peer_device->repl_state[NOW] == L_SYNC_TARGET ||
		    peer_device->repl_state[NOW] == L_BEHIND      ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_T) {
			peer_device->current_uuid = val;
			set_current = false;
		}
		if (peer_device->repl_state[NOW] == L_SYNC_SOURCE ||
		    peer_device->repl_state[NOW] == L_PAUSED_SYNC_S)
			receipients |= NODE_MASK(peer_device->node_id);

		if (peer_device != from_pd &&
		    peer_device->disk_state[NOW] == D_DISKLESS &&
		    peer_device->current_uuid != drbd_current_uuid(device))
			receipients |= NODE_MASK(peer_device->node_id);
	}

	if (set_current) {
		u64 old_current = device->ldev->md.current_uuid;
		u64 upd;

		if (device->disk_state[NOW] == D_UP_TO_DATE)
			receipients |= rotate_current_into_bitmap(device, weak_nodes, dagtag);

		upd = ~weak_nodes; /* These nodes are connected to the primary */
		upd &= __test_bitmap_slots(device); /* of those, I have a bitmap for */
		__set_bitmap_slots(device, val, upd);
		/* Setting bitmap to the (new) current-UUID, means, at this moment
		   we know that we are at the same data as this not connected peer. */

		__drbd_uuid_set_current(device, val);

		/* Even when the old current UUID was not used as any bitmap
		 * UUID, we still add it to the history. This is relevant, in
		 * particular, when we afterwards perform a sync handshake with
		 * a peer which is not one of the "weak_nodes", but hasn't
		 * received the new current UUID. If we do not add the current
		 * UUID to the history, we will end up with a spurious
		 * unrelated data or split-brain decision. */
		_drbd_uuid_push_history(device, old_current);
	}

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	downgrade_write(&device->uuid_sem);
	if (set_current)
		drbd_propagate_uuids(device, receipients);
	up_read(&device->uuid_sem);
}

static u64 __set_bitmap_slots(struct drbd_device *device, u64 bitmap_uuid, u64 do_nodes) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	u64 modified = 0;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == device->ldev->md.node_id)
			continue;
		if (!(do_nodes & NODE_MASK(node_id)))
			continue;
		if (!(peer_md[node_id].flags & MDF_HAVE_BITMAP))
			continue;
		if (peer_md[node_id].bitmap_uuid != bitmap_uuid) {
			u64 previous_bitmap_uuid = peer_md[node_id].bitmap_uuid;
			/* drbd_info(device, "XXX bitmap[node_id=%d] = %llX\n", node_id, bitmap_uuid); */
			peer_md[node_id].bitmap_uuid = bitmap_uuid;
			peer_md[node_id].bitmap_dagtag =
				bitmap_uuid ? device->resource->dagtag_sector : 0;
			_drbd_uuid_push_history(device, previous_bitmap_uuid);
			drbd_md_mark_dirty(device);
			modified |= NODE_MASK(node_id);
		}
	}

	return modified;
}

static u64 __test_bitmap_slots(struct drbd_device *device) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	int node_id;
	u64 rv = 0;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (peer_md[node_id].bitmap_uuid)
			rv |= NODE_MASK(node_id);
	}

	return rv;
}

/* __test_bitmap_slots_of_peer() operates on view of the world I know the
   SyncSource had. It might be that in the mean time some peers sent more
   recent UUIDs to me. Remove all peers that are on the same UUID as I am
   now from the set of nodes */
static u64 __test_bitmap_slots_of_peer(struct drbd_peer_device *peer_device) __must_hold(local)
{
	u64 set_bitmap_slots = 0;
	int node_id;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		u64 bitmap_uuid = peer_device->bitmap_uuids[node_id];

		if (bitmap_uuid != 0 && bitmap_uuid != -1)
			set_bitmap_slots |= NODE_MASK(node_id);
	}

	return set_bitmap_slots;
}

static u64
peers_with_current_uuid(struct drbd_device *device, u64 current_uuid)
{
	struct drbd_peer_device *peer_device;
	u64 nodes = 0;

	current_uuid &= ~UUID_PRIMARY;
	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_disk_state peer_disk_state = peer_device->disk_state[NOW];
		if (peer_disk_state < D_INCONSISTENT || peer_disk_state == D_UNKNOWN)
			continue;
		if (current_uuid == (peer_device->current_uuid & ~UUID_PRIMARY))
			nodes |= NODE_MASK(peer_device->node_id);
	}
	rcu_read_unlock();

	return nodes;
}

void drbd_uuid_resync_starting(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;

	peer_device->rs_start_uuid = drbd_current_uuid(device);
	if (peer_device->uuid_flags & UUID_FLAG_CRASHED_PRIMARY)
		set_bit(SYNC_SRC_CRASHED_PRI, &peer_device->flags);
	rotate_current_into_bitmap(device, false, device->resource->dagtag_sector);
}

u64 drbd_uuid_resync_finished(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	unsigned long flags;
	u64 ss_nz_bm; /* sync_source has non zero bitmap for. expressed as nodemask */
	u64 pwcu; /* peers with current uuid */
	u64 newer;

	spin_lock_irqsave(&device->ldev->md.uuid_lock, flags);
	ss_nz_bm = __test_bitmap_slots_of_peer(peer_device);
	pwcu = peers_with_current_uuid(device, peer_device->current_uuid);

	newer = __set_bitmap_slots(device, peer_device->rs_start_uuid, ss_nz_bm & ~pwcu);
	__set_bitmap_slots(device, 0, ~ss_nz_bm | pwcu);
	_drbd_uuid_push_history(device, drbd_current_uuid(device));
	__drbd_uuid_set_current(device, peer_device->current_uuid);
	spin_unlock_irqrestore(&device->ldev->md.uuid_lock, flags);

	return newer;
}

static const char* name_of_node_id(struct drbd_resource *resource, int node_id)
{
	/* Caller need to hold rcu_read_lock */
	struct drbd_connection *connection = drbd_connection_by_node_id(resource, node_id);

	return connection ? rcu_dereference(connection->transport.net_conf)->name : "";
}

static void forget_bitmap(struct drbd_device *device, int node_id) __must_hold(local)
{
	int bitmap_index = device->ldev->md.peers[node_id].bitmap_index;
	const char* name;

	if (_drbd_bm_total_weight(device, bitmap_index) == 0)
		return;

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	rcu_read_lock();
	name = name_of_node_id(device->resource, node_id);
	drbd_info(device, "clearing bitmap UUID and content (%lu bits) for node %d (%s)(slot %d)\n",
		  _drbd_bm_total_weight(device, bitmap_index), node_id, name, bitmap_index);
	rcu_read_unlock();
	drbd_suspend_io(device, WRITE_ONLY);
	drbd_bm_lock(device, "forget_bitmap()", BM_LOCK_TEST | BM_LOCK_SET);
	_drbd_bm_clear_many_bits(device, bitmap_index, 0, -1UL);
	drbd_bm_unlock(device);
	drbd_resume_io(device);
	drbd_md_mark_dirty(device);
	spin_lock_irq(&device->ldev->md.uuid_lock);
}

static void copy_bitmap(struct drbd_device *device, int from_id, int to_id) __must_hold(local)
{
	int from_index = device->ldev->md.peers[from_id].bitmap_index;
	int to_index = device->ldev->md.peers[to_id].bitmap_index;
	const char *from_name, *to_name;

	spin_unlock_irq(&device->ldev->md.uuid_lock);
	rcu_read_lock();
	from_name = name_of_node_id(device->resource, from_id);
	to_name = name_of_node_id(device->resource, to_id);
	drbd_info(device, "Node %d (%s) synced up to node %d (%s). copying bitmap slot %d to %d.\n",
		  to_id, to_name, from_id, from_name, from_index, to_index);
	rcu_read_unlock();
	drbd_suspend_io(device, WRITE_ONLY);
	drbd_bm_lock(device, "copy_bitmap()", BM_LOCK_ALL);
	drbd_bm_copy_slot(device, from_index, to_index);
	drbd_bm_unlock(device);
	drbd_resume_io(device);
	drbd_md_mark_dirty(device);
	spin_lock_irq(&device->ldev->md.uuid_lock);
}

static int find_node_id_by_bitmap_uuid(struct drbd_device *device, u64 bm_uuid) __must_hold(local)
{
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	int node_id;

	bm_uuid &= ~UUID_PRIMARY;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if ((peer_md[node_id].bitmap_uuid & ~UUID_PRIMARY) == bm_uuid &&
		    peer_md[node_id].flags & MDF_HAVE_BITMAP)
			return node_id;
	}

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if ((peer_md[node_id].bitmap_uuid & ~UUID_PRIMARY) == bm_uuid)
			return node_id;
	}

	return -1;
}

static bool node_connected(struct drbd_resource *resource, int node_id)
{
	struct drbd_connection *connection;
	bool r = false;

	rcu_read_lock();
	connection = drbd_connection_by_node_id(resource, node_id);
	if (connection)
		r = connection->cstate[NOW] == C_CONNECTED;
	rcu_read_unlock();

	return r;
}

static bool detect_copy_ops_on_peer(struct drbd_peer_device *peer_device) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	struct drbd_resource *resource = device->resource;
	int node_id1, node_id2, from_id;
	u64 peer_bm_uuid;
	bool modified = false;

	for (node_id1 = 0; node_id1 < DRBD_NODE_ID_MAX; node_id1++) {
		if (device->ldev->md.peers[node_id1].bitmap_index == -1)
			continue;

		if (node_connected(resource, node_id1))
			continue;

		peer_bm_uuid = peer_device->bitmap_uuids[node_id1];
		if (peer_bm_uuid == 0 || peer_bm_uuid == -1ULL)
			continue;

		peer_bm_uuid &= ~UUID_PRIMARY;
		for (node_id2 = node_id1 + 1; node_id2 < DRBD_NODE_ID_MAX; node_id2++) {
			if (device->ldev->md.peers[node_id2].bitmap_index == -1)
				continue;

			if (node_connected(resource, node_id2))
				continue;

			if (peer_bm_uuid == (peer_device->bitmap_uuids[node_id2] & ~UUID_PRIMARY))
				goto found;
		}
	}
	return false;

found:
	from_id = find_node_id_by_bitmap_uuid(device, peer_bm_uuid);
	if (from_id == -1) {
		if (peer_md[node_id1].bitmap_uuid == 0 && peer_md[node_id2].bitmap_uuid == 0)
			return false;
		drbd_err(peer_device, "unexpected\n");
		drbd_err(peer_device, "In UUIDs from node %d found equal UUID (%llX) for nodes %d %d\n",
			 peer_device->node_id, peer_bm_uuid, node_id1, node_id2);
		drbd_err(peer_device, "I have %llX for node_id=%d\n",
			 peer_md[node_id1].bitmap_uuid, node_id1);
		drbd_err(peer_device, "I have %llX for node_id=%d\n",
			 peer_md[node_id2].bitmap_uuid, node_id2);
		return false;
	}

	if (!(peer_md[from_id].flags & MDF_HAVE_BITMAP))
		return false;

	if (from_id != node_id1 &&
	    peer_md[node_id1].bitmap_uuid != peer_bm_uuid) {
		peer_md[node_id1].bitmap_uuid = peer_bm_uuid;
		peer_md[node_id1].bitmap_dagtag = peer_md[from_id].bitmap_dagtag;
		copy_bitmap(device, from_id, node_id1);
		modified = true;

	}
	if (from_id != node_id2 &&
	    peer_md[node_id2].bitmap_uuid != peer_bm_uuid) {
		peer_md[node_id2].bitmap_uuid = peer_bm_uuid;
		peer_md[node_id2].bitmap_dagtag = peer_md[from_id].bitmap_dagtag;
		copy_bitmap(device, from_id, node_id2);
		modified = true;
	}

	return modified;
}

void drbd_uuid_detect_finished_resyncs(struct drbd_peer_device *peer_device) __must_hold(local)
{
	u64 peer_current_uuid = peer_device->current_uuid & ~UUID_PRIMARY;
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_md *peer_md = device->ldev->md.peers;
	const int my_node_id = device->resource->res_opts.node_id;
	bool write_bm = false;
	bool filled = false;
	bool current_equal;
	int node_id;

	current_equal = peer_current_uuid == (drbd_current_uuid(device) & ~UUID_PRIMARY) &&
		!(peer_device->uuid_flags & UUID_FLAG_SYNC_TARGET);

	spin_lock_irq(&device->ldev->md.uuid_lock);

	if (!test_bit(INITIAL_STATE_PROCESSED, &peer_device->flags) && current_equal) {
		u64 bm_to_peer = peer_device->comm_bitmap_uuid & ~UUID_PRIMARY;
		u64 bm_towards_me = peer_device->bitmap_uuids[my_node_id] & ~UUID_PRIMARY;

		if (bm_towards_me != 0 && bm_to_peer == 0 &&
		    bm_towards_me != peer_current_uuid) {
			drbd_info(peer_device, "Peer missed end of resync\n");
			set_bit(RS_PEER_MISSED_END, &peer_device->flags);
		}
		if (bm_towards_me == 0 && bm_to_peer != 0 &&
		    bm_to_peer != peer_current_uuid) {
			drbd_info(peer_device, "Missed end of resync as sync-source\n");
			set_bit(RS_SOURCE_MISSED_END, &peer_device->flags);
		}
		spin_unlock_irq(&device->ldev->md.uuid_lock);
		return;
	}

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_device *pd2;

		if (node_id == device->ldev->md.node_id)
			continue;

		if (!(peer_md[node_id].flags & MDF_HAVE_BITMAP) && !(peer_md[node_id].flags & MDF_NODE_EXISTS))
			continue;

		pd2 = peer_device_by_node_id(device, node_id);
		if (pd2 && pd2 != peer_device && pd2->repl_state[NOW] > L_ESTABLISHED)
			continue;

		if (peer_device->bitmap_uuids[node_id] == 0 && peer_md[node_id].bitmap_uuid != 0) {
			int from_node_id;

			if (current_equal) {
				_drbd_uuid_push_history(device, peer_md[node_id].bitmap_uuid);
				peer_md[node_id].bitmap_uuid = 0;
				if (node_id == peer_device->node_id)
					drbd_print_uuids(peer_device, "updated UUIDs");
				else if (peer_md[node_id].flags & MDF_HAVE_BITMAP)
					forget_bitmap(device, node_id);
				else
					drbd_info(device, "Clearing bitmap UUID for node %d\n",
						  node_id);
				drbd_md_mark_dirty(device);
				write_bm = true;
			}

			from_node_id = find_node_id_by_bitmap_uuid(device, peer_current_uuid);
			if (from_node_id != -1 && node_id != from_node_id &&
			    dagtag_newer(peer_md[from_node_id].bitmap_dagtag,
					 peer_md[node_id].bitmap_dagtag)) {
				_drbd_uuid_push_history(device, peer_md[node_id].bitmap_uuid);
				peer_md[node_id].bitmap_uuid = peer_md[from_node_id].bitmap_uuid;
				peer_md[node_id].bitmap_dagtag = peer_md[from_node_id].bitmap_dagtag;
				if (peer_md[node_id].flags & MDF_HAVE_BITMAP &&
				    peer_md[from_node_id].flags & MDF_HAVE_BITMAP)
					copy_bitmap(device, from_node_id, node_id);
				else
					drbd_info(device, "Node %d synced up to node %d.\n",
						  node_id, from_node_id);
				drbd_md_mark_dirty(device);
				filled = true;
			}
		}
	}

	write_bm |= detect_copy_ops_on_peer(peer_device);
	spin_unlock_irq(&device->ldev->md.uuid_lock);

	if (write_bm || filled) {
		u64 to_nodes = filled ? -1 : ~NODE_MASK(peer_device->node_id);
		drbd_propagate_uuids(device, to_nodes);
		drbd_suspend_io(device, WRITE_ONLY);
		drbd_bm_lock(device, "detect_finished_resyncs()", BM_LOCK_BULK);
		drbd_bm_write(device, NULL);
		drbd_bm_unlock(device);
		drbd_resume_io(device);
	}
}

int drbd_bmio_set_all_n_write(struct drbd_device *device,
			      struct drbd_peer_device *peer_device) __must_hold(local)
{
	drbd_bm_set_all(device);
	return drbd_bm_write(device, NULL);
}

/**
 * drbd_bmio_set_n_write() - io_fn for drbd_queue_bitmap_io() or drbd_bitmap_io()
 * @device:	DRBD device.
 *
 * Sets all bits in the bitmap towards one peer and writes the whole bitmap to stable storage.
 */
int drbd_bmio_set_n_write(struct drbd_device *device,
			  struct drbd_peer_device *peer_device) __must_hold(local)
{
	int rv = -EIO;

	drbd_md_set_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
	drbd_md_sync(device);
	drbd_bm_set_many_bits(peer_device, 0, -1UL);

	rv = drbd_bm_write(device, NULL);

	if (!rv) {
		drbd_md_clear_peer_flag(peer_device, MDF_PEER_FULL_SYNC);
		drbd_md_sync(device);
	}

	return rv;
}

/**
 * drbd_bmio_set_allocated_n_write() - io_fn for drbd_queue_bitmap_io() or drbd_bitmap_io()
 * @device:	DRBD device.
 *
 * Sets all bits in all allocated bitmap slots and writes it to stable storage.
 */
int drbd_bmio_set_allocated_n_write(struct drbd_device *device,
				    struct drbd_peer_device *peer_device) __must_hold(local)
{
	const int my_node_id = device->resource->res_opts.node_id;
	struct drbd_md *md = &device->ldev->md;
	int rv = -EIO;
	int node_id, bitmap_index;

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (node_id == my_node_id)
			continue;
		bitmap_index = md->peers[node_id].bitmap_index;
		if (bitmap_index == -1)
			continue;
		_drbd_bm_set_many_bits(device, bitmap_index, 0, -1UL);
	}
	rv = drbd_bm_write(device, NULL);

	return rv;
}

/**
 * drbd_bmio_clear_all_n_write() - io_fn for drbd_queue_bitmap_io() or drbd_bitmap_io()
 * @device:	DRBD device.
 *
 * Clears all bits in the bitmap and writes the whole bitmap to stable storage.
 */
int drbd_bmio_clear_all_n_write(struct drbd_device *device,
			    struct drbd_peer_device *peer_device) __must_hold(local)
{
	drbd_resume_al(device);
	drbd_bm_clear_all(device);
	return drbd_bm_write(device, NULL);
}

static int w_bitmap_io(struct drbd_work *w, int unused)
{
	struct bm_io_work *work =
		container_of(w, struct bm_io_work, w);
	struct drbd_device *device = work->device;
	int rv = -EIO;

	if (get_ldev(device)) {
		if (work->flags & BM_LOCK_SINGLE_SLOT)
			drbd_bm_slot_lock(work->peer_device, work->why, work->flags);
		else
			drbd_bm_lock(device, work->why, work->flags);
		rv = work->io_fn(device, work->peer_device);
		if (work->flags & BM_LOCK_SINGLE_SLOT)
			drbd_bm_slot_unlock(work->peer_device);
		else
			drbd_bm_unlock(device);
		put_ldev(device);
	}

	if (work->done)
		work->done(device, work->peer_device, rv);

	if (atomic_dec_and_test(&device->pending_bitmap_work.n))
		wake_up(&device->misc_wait);
	kfree(work);

	return 0;
}

void drbd_queue_pending_bitmap_work(struct drbd_device *device)
{
	unsigned long flags;

	spin_lock_irqsave(&device->pending_bitmap_work.q_lock, flags);
	spin_lock(&device->resource->work.q_lock);
	list_splice_tail_init(&device->pending_bitmap_work.q, &device->resource->work.q);
	spin_unlock(&device->resource->work.q_lock);
	spin_unlock_irqrestore(&device->pending_bitmap_work.q_lock, flags);
	wake_up(&device->resource->work.q_wait);
}

/**
 * drbd_queue_bitmap_io() - Queues an IO operation on the whole bitmap
 * @device:	DRBD device.
 * @io_fn:	IO callback to be called when bitmap IO is possible
 * @done:	callback to be called after the bitmap IO was performed
 * @why:	Descriptive text of the reason for doing the IO
 *
 * While IO on the bitmap happens we freeze application IO thus we ensure
 * that drbd_set_out_of_sync() can not be called. This function MAY ONLY be
 * called from sender context. It MUST NOT be used while a previous such
 * work is still pending!
 *
 * Its worker function encloses the call of io_fn() by get_ldev() and
 * put_ldev().
 */
void drbd_queue_bitmap_io(struct drbd_device *device,
			  int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
			  void (*done)(struct drbd_device *, struct drbd_peer_device *, int),
			  char *why, enum bm_flag flags,
			  struct drbd_peer_device *peer_device)
{
	struct bm_io_work *bm_io_work;

	D_ASSERT(device, current == device->resource->worker.task);

	bm_io_work = kmalloc(sizeof(*bm_io_work), GFP_NOIO);
	if (!bm_io_work) {
		done(device, peer_device, -ENOMEM);
		return;
	}
	bm_io_work->w.cb = w_bitmap_io;
	bm_io_work->device = device;
	bm_io_work->peer_device = peer_device;
	bm_io_work->io_fn = io_fn;
	bm_io_work->done = done;
	bm_io_work->why = why;
	bm_io_work->flags = flags;

	/*
	 * Whole-bitmap operations can only take place when there is no
	 * concurrent application I/O.  We ensure exclusion between the two
	 * types of I/O  with the following mechanism:
	 *
	 *  - device->ap_bio_cnt keeps track of the number of application I/O
	 *    requests in progress.
	 *
	 *  - A non-empty device->pending_bitmap_work list indicates that
	 *    whole-bitmap I/O operations are pending, and no new application
	 *    I/O should be started.  We make sure that the list doesn't appear
	 *    empty system wide before trying to queue the whole-bitmap I/O.
	 *
	 *  - In dec_ap_bio(), we decrement device->ap_bio_cnt.  If it reaches
	 *    zero and the device->pending_bitmap_work list is non-empty, we
	 *    queue the whole-bitmap operations.
	 *
	 *  - In inc_ap_bio(), we increment device->ap_bio_cnt before checking
	 *    if the device->pending_bitmap_work list is non-empty.  If
	 *    device->pending_bitmap_work is non-empty, we immediately call
	 *    dec_ap_bio().
	 *
	 * This ensures that whenever there is pending whole-bitmap I/O, we
	 * realize in dec_ap_bio().
	 *
	 */

	/* no one should accidentally schedule the next bitmap IO
	 * when it is only half-queued yet */
	atomic_inc(&device->ap_bio_cnt[WRITE]);
	atomic_inc(&device->pending_bitmap_work.n);
	spin_lock_irq(&device->pending_bitmap_work.q_lock);
	list_add_tail(&bm_io_work->w.list, &device->pending_bitmap_work.q);
	spin_unlock_irq(&device->pending_bitmap_work.q_lock);
	dec_ap_bio(device, WRITE);  /* may move to actual work queue */
}

/**
 * drbd_bitmap_io() -  Does an IO operation on the whole bitmap
 * @device:	DRBD device.
 * @io_fn:	IO callback to be called when bitmap IO is possible
 * @why:	Descriptive text of the reason for doing the IO
 *
 * freezes application IO while that the actual IO operations runs. This
 * functions MAY NOT be called from sender context.
 */
int drbd_bitmap_io(struct drbd_device *device,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *peer_device)
{
	/* Only suspend io, if some operation is supposed to be locked out */
	const bool do_suspend_io = flags & (BM_LOCK_CLEAR|BM_LOCK_SET|BM_LOCK_TEST);
	int rv;

	D_ASSERT(device, current != device->resource->worker.task);

	if (do_suspend_io)
		drbd_suspend_io(device, WRITE_ONLY);

	if (flags & BM_LOCK_SINGLE_SLOT)
		drbd_bm_slot_lock(peer_device, why, flags);
	else
		drbd_bm_lock(device, why, flags);

	rv = io_fn(device, peer_device);

	if (flags & BM_LOCK_SINGLE_SLOT)
		drbd_bm_slot_unlock(peer_device);
	else
		drbd_bm_unlock(device);

	if (do_suspend_io)
		drbd_resume_io(device);

	return rv;
}

void drbd_md_set_flag(struct drbd_device *device, enum mdf_flag flag) __must_hold(local)
{
	if ((device->ldev->md.flags & flag) != flag) {
		drbd_md_mark_dirty(device);
		device->ldev->md.flags |= flag;
	}
}

void drbd_md_set_peer_flag(struct drbd_peer_device *peer_device,
			   enum mdf_peer_flag flag) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_md *md = &device->ldev->md;

	if (!(md->peers[peer_device->node_id].flags & flag)) {
		drbd_md_mark_dirty(device);
		md->peers[peer_device->node_id].flags |= flag;
	}
}

void drbd_md_clear_flag(struct drbd_device *device, enum mdf_flag flag) __must_hold(local)
{
	if ((device->ldev->md.flags & flag) != 0) {
		drbd_md_mark_dirty(device);
		device->ldev->md.flags &= ~flag;
	}
}

void drbd_md_clear_peer_flag(struct drbd_peer_device *peer_device,
			     enum mdf_peer_flag flag) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_md *md = &device->ldev->md;

	if (md->peers[peer_device->node_id].flags & flag) {
		drbd_md_mark_dirty(device);
		md->peers[peer_device->node_id].flags &= ~flag;
	}
}

int drbd_md_test_flag(struct drbd_backing_dev *bdev, enum mdf_flag flag)
{
	return (bdev->md.flags & flag) != 0;
}

bool drbd_md_test_peer_flag(struct drbd_peer_device *peer_device, enum mdf_peer_flag flag)
{
	struct drbd_md *md = &peer_device->device->ldev->md;

	if (peer_device->bitmap_index == -1)
		return false;

	return md->peers[peer_device->node_id].flags & flag;
}

static void md_sync_timer_fn(struct timer_list *t)
{
	struct drbd_device *device = from_timer(device, t, md_sync_timer);
	drbd_device_post_work(device, MD_SYNC);
}

/**
 * drbd_wait_misc  -  wait for a request or peer request to make progress
 * @device:	device associated with the request or peer request
 * @peer_device: NULL when waiting for a request; the peer device of the peer
 *		 request when waiting for a peer request
 * @i:		the struct drbd_interval embedded in struct drbd_request or
 *		struct drbd_peer_request
 */
int drbd_wait_misc(struct drbd_device *device, struct drbd_peer_device *peer_device, struct drbd_interval *i)
{
	DEFINE_WAIT(wait);
	long timeout;

	rcu_read_lock();
	if (peer_device) {
		struct net_conf *net_conf = rcu_dereference(peer_device->connection->transport.net_conf);
		if (!net_conf) {
			rcu_read_unlock();
			return -ETIMEDOUT;
		}
		timeout = net_conf->ko_count ? net_conf->timeout * HZ / 10 * net_conf->ko_count :
					       MAX_SCHEDULE_TIMEOUT;
	} else {
		struct disk_conf *disk_conf = rcu_dereference(device->ldev->disk_conf);
		timeout = disk_conf->disk_timeout * HZ / 10;
	}
	rcu_read_unlock();

	/* Indicate to wake up device->misc_wait on progress.  */
	i->waiting = true;
	prepare_to_wait(&device->misc_wait, &wait, TASK_INTERRUPTIBLE);
	spin_unlock_irq(&device->resource->req_lock);
	timeout = schedule_timeout(timeout);
	finish_wait(&device->misc_wait, &wait);
	spin_lock_irq(&device->resource->req_lock);
	if (!timeout || (peer_device && peer_device->repl_state[NOW] < L_ESTABLISHED))
		return -ETIMEDOUT;
	if (signal_pending(current))
		return -ERESTARTSYS;
	return 0;
}

void lock_all_resources(void)
{
	struct drbd_resource *resource;
	int __maybe_unused i = 0;

	mutex_lock(&resources_mutex);
	local_irq_disable();
	for_each_resource(resource, &drbd_resources)
		spin_lock_nested(&resource->req_lock, i++);
}

void unlock_all_resources(void)
{
	struct drbd_resource *resource;

	for_each_resource(resource, &drbd_resources)
		spin_unlock(&resource->req_lock);
	local_irq_enable();
	mutex_unlock(&resources_mutex);
}

long twopc_timeout(struct drbd_resource *resource)
{
	return resource->res_opts.twopc_timeout * HZ/10;
}

u64 directly_connected_nodes(struct drbd_resource *resource, enum which_state which)
{
	u64 directly_connected = 0;
	struct drbd_connection *connection;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[which] < C_CONNECTED)
			continue;
		directly_connected |= NODE_MASK(connection->peer_node_id);
	}
	rcu_read_unlock();

	return directly_connected;
}

static sector_t bm_sect_to_max_capacity(unsigned int bm_max_peers, sector_t bm_sect)
{
	u64 bm_pages = bm_sect >> (PAGE_SHIFT - SECTOR_SHIFT);
	u64 bm_bytes = bm_pages << PAGE_SHIFT;
	u64 bm_bytes_per_peer = div_u64(bm_bytes, bm_max_peers);
	u64 bm_bits_per_peer = bm_bytes_per_peer * BITS_PER_BYTE;
	return BM_BIT_TO_SECT(bm_bits_per_peer);
}

/**
 * drbd_get_max_capacity() - Returns the capacity we announce to out peer
 * @device: The DRBD device.
 * @bdev: Meta data block device.
 * @warn: Whether to warn when size is clipped.
 *
 * returns the capacity we announce to out peer.  we clip ourselves at the
 * various MAX_SECTORS, because if we don't, current implementation will
 * oops sooner or later
 */
sector_t drbd_get_max_capacity(
		struct drbd_device *device, struct drbd_backing_dev *bdev, bool warn)
{
	unsigned int bm_max_peers = device->bitmap->bm_max_peers;
	sector_t backing_bdev_capacity = drbd_get_capacity(bdev->backing_bdev);
	sector_t bm_sect;
	sector_t backing_capacity_remaining;
	sector_t metadata_limit;
	sector_t max_capacity;

	switch (bdev->md.meta_dev_idx) {
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_INT:
		bm_sect = bdev->md.al_offset - bdev->md.bm_offset;
		backing_capacity_remaining = drbd_md_first_sector(bdev);
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		bm_sect = bdev->md.md_size_sect - bdev->md.bm_offset;
		backing_capacity_remaining = backing_bdev_capacity;
		break;
	default:
		bm_sect = DRBD_BM_SECTORS_INDEXED;
		backing_capacity_remaining = backing_bdev_capacity;
	}

	metadata_limit = bm_sect_to_max_capacity(bm_max_peers, bm_sect);

	dynamic_drbd_dbg(device,
			"Backing device capacity: %llus, remaining: %llus, bitmap sectors: %llus\n",
			(unsigned long long) backing_bdev_capacity,
			(unsigned long long) backing_capacity_remaining,
			(unsigned long long) bm_sect);
	dynamic_drbd_dbg(device,
			"Max peers: %u, metadata limit: %llus, hard limit: %llus\n",
			bm_max_peers,
			(unsigned long long) metadata_limit,
			(unsigned long long) DRBD_MAX_SECTORS);

	max_capacity = backing_capacity_remaining;
	if (max_capacity > DRBD_MAX_SECTORS) {
		if (warn)
			drbd_warn(device, "Device size clipped from %llus to %llus due to DRBD limitations\n",
					(unsigned long long) max_capacity,
					(unsigned long long) DRBD_MAX_SECTORS);
		max_capacity = DRBD_MAX_SECTORS;
	}
	if (max_capacity > metadata_limit) {
		if (warn)
			drbd_warn(device, "Device size clipped from %llus to %llus due to metadata size\n",
					(unsigned long long) max_capacity,
					(unsigned long long) metadata_limit);
		max_capacity = metadata_limit;
	}
	return max_capacity;
}

#ifdef CONFIG_DRBD_FAULT_INJECTION
/* Fault insertion support including random number generator shamelessly
 * stolen from kernel/rcutorture.c */
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
static unsigned long
_drbd_fault_random(struct fault_random_state *rsp)
{
	long refresh;

	if (!rsp->count--) {
		get_random_bytes(&refresh, sizeof(refresh));
		rsp->state += refresh;
		rsp->count = FAULT_RANDOM_REFRESH;
	}
	rsp->state = rsp->state * FAULT_RANDOM_MULT + FAULT_RANDOM_ADD;
	return swahw32(rsp->state);
}

static char *
_drbd_fault_str(unsigned int type) {
	static char *_faults[] = {
		[DRBD_FAULT_MD_WR] = "Meta-data write",
		[DRBD_FAULT_MD_RD] = "Meta-data read",
		[DRBD_FAULT_RS_WR] = "Resync write",
		[DRBD_FAULT_RS_RD] = "Resync read",
		[DRBD_FAULT_DT_WR] = "Data write",
		[DRBD_FAULT_DT_RD] = "Data read",
		[DRBD_FAULT_DT_RA] = "Data read ahead",
		[DRBD_FAULT_BM_ALLOC] = "BM allocation",
		[DRBD_FAULT_AL_EE] = "EE allocation",
		[DRBD_FAULT_RECEIVE] = "receive data corruption",
	};

	return (type < DRBD_FAULT_MAX) ? _faults[type] : "**Unknown**";
}

unsigned int
_drbd_insert_fault(struct drbd_device *device, unsigned int type)
{
	static struct fault_random_state rrs = {0, 0};

	unsigned int ret = (
		(drbd_fault_devs == 0 ||
			((1 << device_to_minor(device)) & drbd_fault_devs) != 0) &&
		(((_drbd_fault_random(&rrs) % 100) + 1) <= drbd_fault_rate));

	if (ret) {
		drbd_fault_count++;

		if (drbd_ratelimit())
			drbd_warn(device, "***Simulating %s failure\n",
				_drbd_fault_str(type));
	}

	return ret;
}
#endif

module_init(drbd_init)
module_exit(drbd_cleanup)

/* For transport layer */
EXPORT_SYMBOL(drbd_destroy_connection);
EXPORT_SYMBOL(drbd_destroy_path);
