// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt)	KBUILD_MODNAME " debugfs: " fmt
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <generated/utsrelease.h>

#include "drbd_int.h"
#include "drbd_req.h"
#include "drbd_debugfs.h"
#include "drbd_transport.h"
#include "drbd_dax_pmem.h"

/**********************************************************************
 * Whenever you change the file format, remember to bump the version. *
 **********************************************************************/

static struct dentry *drbd_debugfs_root;
static struct dentry *drbd_debugfs_version;
static struct dentry *drbd_debugfs_refcounts;
static struct dentry *drbd_debugfs_resources;
static struct dentry *drbd_debugfs_minors;
static struct dentry *drbd_debugfs_compat;

static void seq_print_node_mask(struct seq_file *m, struct drbd_resource *resource, u64 nodes)
{
	struct drbd_connection *connection;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (NODE_MASK(connection->peer_node_id) & nodes) {
			char *name = rcu_dereference((connection)->transport.net_conf)->name;

			seq_printf(m, "%s, ", name);
		}
	}
	rcu_read_unlock();
	seq_puts(m, "\n");
}

#ifdef CONFIG_DRBD_TIMING_STATS
static void seq_print_age_or_dash(struct seq_file *m, bool valid, ktime_t dt)
{
	if (valid)
		seq_printf(m, "\t%d", (int)ktime_to_ms(dt));
	else
		seq_puts(m, "\t-");
}
#endif

static void __seq_print_rq_state_bit(struct seq_file *m,
	bool is_set, char *sep, const char *set_name, const char *unset_name)
{
	if (is_set && set_name) {
		if (*sep)
			seq_putc(m, *sep);
		seq_puts(m, set_name);
		*sep = '|';
	} else if (!is_set && unset_name) {
		if (*sep)
			seq_putc(m, *sep);
		seq_puts(m, unset_name);
		*sep = '|';
	}
}

static void seq_print_rq_state_bit(struct seq_file *m,
	bool is_set, char *sep, const char *set_name)
{
	__seq_print_rq_state_bit(m, is_set, sep, set_name, NULL);
}

/* pretty print enum drbd_req_state_bits req->rq_state */
static void seq_print_request_state(struct seq_file *m, struct drbd_request *req)
{
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;
	unsigned int s = req->local_rq_state;
	char sep = ' ';
	seq_printf(m, "\t0x%08x", s);
	seq_puts(m, "\tmaster:");
	__seq_print_rq_state_bit(m, req->master_bio, &sep, "pending", "completed");
	seq_print_rq_state_bit(m, s & RQ_POSTPONED, &sep, "postponed");
	seq_print_rq_state_bit(m, s & RQ_COMPLETION_SUSP, &sep, "suspended");

	/* RQ_WRITE ignored, already reported */
	seq_puts(m, "\tlocal:");
	sep = ' ';
	seq_print_rq_state_bit(m, s & RQ_IN_ACT_LOG, &sep, "in-AL");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_PENDING, &sep, "pending");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_COMPLETED, &sep, "completed");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_ABORTED, &sep, "aborted");
	seq_print_rq_state_bit(m, s & RQ_LOCAL_OK, &sep, "ok");
	if (sep == ' ')
		seq_puts(m, " -");

	for_each_peer_device(peer_device, device) {
		s = req->net_rq_state[peer_device->node_id];
		seq_printf(m, "\tnet[%d]:", peer_device->node_id);
		sep = ' ';
		seq_print_rq_state_bit(m, s & RQ_NET_PENDING, &sep, "pending");
		seq_print_rq_state_bit(m, s & RQ_NET_QUEUED, &sep, "queued");
		seq_print_rq_state_bit(m, s & RQ_NET_READY, &sep, "ready");
		seq_print_rq_state_bit(m, s & RQ_NET_SENT, &sep, "sent");
		seq_print_rq_state_bit(m, s & RQ_NET_DONE, &sep, "done");
		seq_print_rq_state_bit(m, s & RQ_NET_SIS, &sep, "sis");
		seq_print_rq_state_bit(m, s & RQ_NET_OK, &sep, "ok");
		if (sep == ' ')
			seq_puts(m, " -");

		seq_puts(m, " :");
		sep = ' ';
		seq_print_rq_state_bit(m, s & RQ_EXP_RECEIVE_ACK, &sep, "B");
		seq_print_rq_state_bit(m, s & RQ_EXP_WRITE_ACK, &sep, "C");
		seq_print_rq_state_bit(m, s & RQ_EXP_BARR_ACK, &sep, "barr");
		if (sep == ' ')
			seq_puts(m, " -");
	}
	seq_putc(m, '\n');
}

#define memberat(PTR, TYPE, OFFSET) (*(TYPE *)((char *)PTR + OFFSET))

#ifdef CONFIG_DRBD_TIMING_STATS
static void print_one_age_or_dash(struct seq_file *m, struct drbd_request *req,
				  unsigned int set_mask, unsigned int clear_mask,
				  ktime_t now, size_t offset)
{
	struct drbd_device *device = req->device;
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		unsigned int s = req->net_rq_state[peer_device->node_id];

		if (s & set_mask && !(s & clear_mask)) {
			ktime_t ktime = ktime_sub(now, memberat(req, ktime_t, offset));
			seq_printf(m, "\t[%d]%d", peer_device->node_id, (int)ktime_to_ms(ktime));
			return;
		}
	}
	seq_puts(m, "\t-");
}
#endif

static void seq_print_one_request(struct seq_file *m, struct drbd_request *req, ktime_t now, unsigned long jif)
{
	/* change anything here, fixup header below! */
	unsigned int s = req->local_rq_state;
	unsigned long flags;

	spin_lock_irqsave(&req->rq_lock, flags);
#define RQ_HDR_1 "epoch\tsector\tsize\trw"
	seq_printf(m, "0x%x\t%llu\t%u\t%s",
		req->epoch,
		(unsigned long long)req->i.sector, req->i.size >> 9,
		(s & RQ_WRITE) ? "W" : "R");

#ifdef CONFIG_DRBD_TIMING_STATS
#define RQ_HDR_2 "\tstart\tin AL\tsubmit"
	seq_printf(m, "\t%d", (int)ktime_to_ms(ktime_sub(now, req->start_kt)));
	seq_print_age_or_dash(m, s & RQ_IN_ACT_LOG, ktime_sub(now, req->in_actlog_kt));
	seq_print_age_or_dash(m, s & RQ_LOCAL_PENDING, ktime_sub(now, req->pre_submit_kt));

#define RQ_HDR_3 "\tsent\tacked\tdone"
	print_one_age_or_dash(m, req, RQ_NET_SENT, 0, now, offsetof(typeof(*req), pre_send_kt));
	print_one_age_or_dash(m, req, RQ_NET_SENT, RQ_NET_PENDING, now, offsetof(typeof(*req), acked_kt));
	print_one_age_or_dash(m, req, RQ_NET_DONE, 0, now, offsetof(typeof(*req), net_done_kt));
#else
#define RQ_HDR_2 "\tstart"
#define RQ_HDR_3 ""
	seq_printf(m, "\t%d", (int)jiffies_to_msecs(jif - req->start_jif));
#endif
#define RQ_HDR_4 "\tstate\n"
	seq_print_request_state(m, req);
	spin_unlock_irqrestore(&req->rq_lock, flags);
}
#define RQ_HDR RQ_HDR_1 RQ_HDR_2 RQ_HDR_3 RQ_HDR_4

static void seq_print_minor_vnr_req(struct seq_file *m, struct drbd_request *req, ktime_t now, unsigned long jif)
{
	seq_printf(m, "%u\t%u\t", req->device->minor, req->device->vnr);
	seq_print_one_request(m, req, now, jif);
}

static void seq_print_resource_pending_meta_io(struct seq_file *m, struct drbd_resource *resource, unsigned long jif)
{
	struct drbd_device *device;
	int i;

	seq_puts(m, "minor\tvnr\tstart\tsubmit\tintent\n");
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, i) {
		struct drbd_md_io tmp;
		/* In theory this is racy,
		 * in the sense that there could have been a
		 * drbd_md_put_buffer(); drbd_md_get_buffer();
		 * between accessing these members here.  */
		tmp = device->md_io;
		if (atomic_read(&tmp.in_use)) {
			seq_printf(m, "%u\t%u\t%d\t",
				device->minor, device->vnr,
				jiffies_to_msecs(jif - tmp.start_jif));
			if (time_before(tmp.submit_jif, tmp.start_jif))
				seq_puts(m, "-\t");
			else
				seq_printf(m, "%d\t", jiffies_to_msecs(jif - tmp.submit_jif));
			seq_printf(m, "%s\n", tmp.current_use);
		}
	}
	rcu_read_unlock();
}

static void seq_print_waiting_for_AL(struct seq_file *m, struct drbd_resource *resource, ktime_t now, unsigned long jif)
{
	struct drbd_device *device;
	int i;

	seq_puts(m, "minor\tvnr\tage\t#waiting\n");
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, i) {
		struct drbd_request *req;
		int n = atomic_read(&device->ap_actlog_cnt);
		if (n) {
			spin_lock_irq(&device->pending_completion_lock);
			req = list_first_entry_or_null(&device->pending_master_completion[1],
				struct drbd_request, req_pending_master_completion);
			/* if the oldest request does not wait for the activity log
			 * it is not interesting for us here */
			if (req && (req->local_rq_state & RQ_IN_ACT_LOG))
				req = NULL;
			spin_unlock_irq(&device->pending_completion_lock);
		}
		if (n) {
			seq_printf(m, "%u\t%u\t", device->minor, device->vnr);
			if (req) {
#ifdef CONFIG_DRBD_TIMING_STATS
				seq_printf(m, "%d\t", (int)ktime_to_ms(ktime_sub(now, req->start_kt)));
#else
				seq_printf(m, "%d\t", (int)jiffies_to_msecs(jif - req->start_jif));
#endif
			} else
				seq_puts(m, "-\t");
			seq_printf(m, "%u\n", n);
		}
	}
	rcu_read_unlock();
}

static void seq_print_device_bitmap_io(struct seq_file *m, struct drbd_device *device, unsigned long jif)
{
	struct drbd_bm_aio_ctx *ctx;
	unsigned long start_jif;
	unsigned int in_flight;
	unsigned int flags;
	spin_lock_irq(&device->pending_bmio_lock);
	ctx = list_first_entry_or_null(&device->pending_bitmap_io, struct drbd_bm_aio_ctx, list);
	if (ctx && ctx->done)
		ctx = NULL;
	if (ctx) {
		start_jif = ctx->start_jif;
		in_flight = atomic_read(&ctx->in_flight);
		flags = ctx->flags;
	}
	spin_unlock_irq(&device->pending_bmio_lock);
	if (ctx) {
		seq_printf(m, "%u\t%u\t%c\t%u\t%u\n",
			device->minor, device->vnr,
			(flags & BM_AIO_READ) ? 'R' : 'W',
			jiffies_to_msecs(jif - start_jif),
			in_flight);
	}
}

static void seq_print_resource_pending_bitmap_io(struct seq_file *m, struct drbd_resource *resource, unsigned long jif)
{
	struct drbd_device *device;
	int i;

	seq_puts(m, "minor\tvnr\trw\tage\t#in-flight\n");
	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, i) {
		seq_print_device_bitmap_io(m, device, jif);
	}
	rcu_read_unlock();
}

/* pretty print enum peer_req->flags */
static void seq_print_peer_request_flags(struct seq_file *m, struct drbd_peer_request *peer_req)
{
	unsigned long f = peer_req->flags;
	char sep = 0;

	seq_print_rq_state_bit(m, test_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &peer_req->i.flags),
			&sep, "submit-conflict-queued");
	seq_print_rq_state_bit(m, test_bit(INTERVAL_SUBMITTED, &peer_req->i.flags),
			&sep, "submitted");
	seq_print_rq_state_bit(m, test_bit(INTERVAL_CONFLICT, &peer_req->i.flags),
			&sep, "conflict");
	seq_print_rq_state_bit(m, test_bit(INTERVAL_SENT, &peer_req->i.flags),
			&sep, "sent");
	seq_print_rq_state_bit(m, test_bit(INTERVAL_RECEIVED, &peer_req->i.flags),
			&sep, "received");
	seq_print_rq_state_bit(m, test_bit(INTERVAL_BACKING_COMPLETED, &peer_req->i.flags),
			&sep, "backing-completed");
	seq_print_rq_state_bit(m, test_bit(INTERVAL_COMPLETED, &peer_req->i.flags),
			&sep, "completed");
	seq_print_rq_state_bit(m, f & EE_IS_BARRIER, &sep, "barr");
	seq_print_rq_state_bit(m, f & EE_SEND_WRITE_ACK, &sep, "C");
	seq_print_rq_state_bit(m, f & EE_MAY_SET_IN_SYNC, &sep, "set-in-sync");
	seq_print_rq_state_bit(m, f & EE_SET_OUT_OF_SYNC, &sep, "set-out-of-sync");
	seq_print_rq_state_bit(m, peer_req->i.type == INTERVAL_PEER_WRITE && !(f & EE_IN_ACTLOG), &sep, "blocked-on-al");
	seq_print_rq_state_bit(m, f & EE_TRIM, &sep, "trim");
	seq_print_rq_state_bit(m, f & EE_ZEROOUT, &sep, "zero-out");
	seq_print_rq_state_bit(m, f & EE_WRITE_SAME, &sep, "write-same");
	seq_putc(m, '\n');
}

enum drbd_peer_request_state {
	PRS_NEW,
	PRS_SENT,
	PRS_SUBMITTED,
	PRS_LAST,
};

static enum drbd_peer_request_state drbd_get_peer_request_state(struct drbd_peer_request *peer_req)
{
	unsigned long interval_flags = peer_req->i.flags;

	if (interval_flags & INTERVAL_SUBMITTED)
		return PRS_SUBMITTED;

	if (interval_flags & INTERVAL_SENT)
		return PRS_SENT;

	return PRS_NEW;
}

static void seq_print_peer_request_one(struct seq_file *m,
	struct drbd_peer_request *peer_req,
	const char *list_name, unsigned long jif)
{
	struct drbd_peer_device *peer_device = peer_req->peer_device;
	struct drbd_device *device = peer_device ? peer_device->device : NULL;

	seq_printf(m, "%s\t", list_name);

	if (device)
		seq_printf(m, "%u\t%u\t", device->minor, device->vnr);

	seq_printf(m, "%llu\t%u\t%s\t%u\t",
			(unsigned long long)peer_req->i.sector, peer_req->i.size >> 9,
			drbd_interval_type_str(&peer_req->i),
			jiffies_to_msecs(jif - peer_req->submit_jif));
	seq_print_peer_request_flags(m, peer_req);
}

static void seq_print_peer_request_w(struct seq_file *m,
	struct drbd_connection *connection, struct list_head *lh,
	const char *list_name, unsigned long jif)
{
	int count[PRS_LAST] = {0};
	struct drbd_peer_request *peer_req;

	list_for_each_entry(peer_req, lh, w.list) {
		enum drbd_peer_request_state state = drbd_get_peer_request_state(peer_req);

		count[state]++;
		if (count[state] <= 16)
			seq_print_peer_request_one(m, peer_req, list_name, jif);
	}
}

static void seq_print_peer_request(struct seq_file *m,
	struct drbd_connection *connection, struct list_head *lh,
	const char *list_name, unsigned long jif)
{
	int count = 0;
	struct drbd_peer_request *peer_req;

	list_for_each_entry(peer_req, lh, recv_order) {
		count++;
		if (count <= 16)
			seq_print_peer_request_one(m, peer_req, list_name, jif);
	}
}

static void seq_print_connection_peer_requests(struct seq_file *m,
	struct drbd_connection *connection, unsigned long jif)
{
	struct drbd_peer_device *peer_device;
	int i;

	seq_printf(m, "list\t\tminor\tvnr\tsector\tsize\ttype\t\tage\tflags\n");
	spin_lock_irq(&connection->peer_reqs_lock);
	seq_print_peer_request_w(m, connection, &connection->done_ee, "done\t", jif);
	seq_print_peer_request_w(m, connection, &connection->dagtag_wait_ee, "dagtag_wait", jif);
	seq_print_peer_request_w(m, connection, &connection->resync_ack_ee, "resync_ack", jif);
	seq_print_peer_request(m, connection, &connection->peer_requests, "peer_requests", jif);
	seq_print_peer_request(m, connection, &connection->peer_reads, "peer_reads", jif);
	idr_for_each_entry(&connection->peer_devices, peer_device, i)
		seq_print_peer_request(m, connection, &peer_device->resync_requests,
				"resync_requests", jif);
	spin_unlock_irq(&connection->peer_reqs_lock);
}

static void seq_print_device_peer_flushes(struct seq_file *m,
	struct drbd_device *device, unsigned long jif)
{
	if (test_bit(FLUSH_PENDING, &device->flags)) {
		seq_printf(m, "%u\t%u\t-\t-\tF\t%u\tflush\n",
			device->minor, device->vnr,
			jiffies_to_msecs(jif - device->flush_jif));
	}
}

static void seq_print_resource_pending_peer_requests(struct seq_file *m,
	struct drbd_resource *resource, unsigned long jif)
{
	struct drbd_connection *connection;
	struct drbd_device *device;
	int i;

	rcu_read_lock();

	for_each_connection_rcu(connection, resource) {
		seq_printf(m, "oldest peer requests (peer: %s)\n",
			rcu_dereference(connection->transport.net_conf)->name);
		seq_print_connection_peer_requests(m, connection, jif);
		seq_putc(m, '\n');
	}

	seq_puts(m, "flushes\n");
	idr_for_each_entry(&resource->devices, device, i) {
		seq_print_device_peer_flushes(m, device, jif);
	}
	seq_putc(m, '\n');

	rcu_read_unlock();
}

static void seq_print_resource_transfer_log_summary(struct seq_file *m,
	struct drbd_resource *resource,
	ktime_t now, unsigned long jif)
{
	struct drbd_request *req;
	unsigned int count = 0;
	unsigned int show_state = 0;

	seq_puts(m, "n\tdevice\tvnr\t" RQ_HDR);
	rcu_read_lock();
	list_for_each_entry_rcu(req, &resource->transfer_log, tl_requests) {
		struct drbd_device *device = req->device;
		struct drbd_peer_device *peer_device;
		unsigned int tmp = 0;
		unsigned int s;

		/* don't disable preemption "forever" */
		if ((count & 0x1ff) == 0x1ff) {
			struct list_head *next_hdr;
			/* Only get if the request hasn't already been destroyed. */
			if (!kref_get_unless_zero(&req->kref))
				continue;
			rcu_read_unlock();
			cond_resched();
			rcu_read_lock();
			next_hdr = rcu_dereference(list_next_rcu(&req->tl_requests));
			if (kref_put(&req->kref, drbd_req_destroy_lock)) {
				if (next_hdr == &resource->transfer_log)
					break;
				req = list_entry_rcu(next_hdr,
						     struct drbd_request,
						     tl_requests);
			}
		}
		++count;

		spin_lock_irq(&req->rq_lock);
		s = req->local_rq_state;

		/* This is meant to summarize timing issues, to be able to tell
		 * local disk problems from network problems.
		 * Skip requests, if we have shown an even older request with
		 * similar aspects already.  */
		if (req->master_bio == NULL)
			tmp |= 1;
		if ((s & RQ_LOCAL_MASK) && (s & RQ_LOCAL_PENDING))
			tmp |= 2;

		for_each_peer_device_rcu(peer_device, device) {
			s = READ_ONCE(req->net_rq_state[peer_device->node_id]);
			if (s & RQ_NET_MASK) {
				if (!(s & RQ_NET_SENT))
					tmp |= 4;
				if (s & RQ_NET_PENDING)
					tmp |= 8;
				if (!(s & RQ_NET_DONE))
					tmp |= 16;
			}
		}
		spin_unlock_irq(&req->rq_lock);

		if ((tmp & show_state) == tmp)
			continue;
		show_state |= tmp;
		seq_printf(m, "%u\t", count);
		seq_print_minor_vnr_req(m, req, now, jif);
		if (show_state == 0x1f)
			break;
	}
	rcu_read_unlock();
	seq_printf(m, "%u total\n", count);
}

static int resource_in_flight_summary_show(struct seq_file *m, void *pos)
{
	struct drbd_resource *resource = m->private;
	struct drbd_connection *connection;
	struct drbd_transport *transport;
	struct drbd_transport_stats transport_stats;
	ktime_t now = ktime_get();
	unsigned long jif = jiffies;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 1);

	seq_puts(m, "oldest bitmap IO\n");
	seq_print_resource_pending_bitmap_io(m, resource, jif);
	seq_putc(m, '\n');

	seq_puts(m, "meta data IO\n");
	seq_print_resource_pending_meta_io(m, resource, jif);
	seq_putc(m, '\n');

	seq_puts(m, "transport buffer stats\n");
	seq_puts(m, "peer\ttransport class\tunread receive buffer\tunacked send buffer\n");
	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		char *name;

		transport = &connection->transport;
		name = rcu_dereference(transport->net_conf)->name;
		seq_printf(m, "%s\t%s\t", name, transport->class->name);

		if (transport->class->ops.stream_ok(transport, DATA_STREAM)) {
			transport->class->ops.stats(transport, &transport_stats);
			seq_printf(m, "%u\t%u\n",
				transport_stats.unread_received,
				transport_stats.unacked_send);
		} else {
			seq_printf(m, "-\t-\n");
		}
	}
	rcu_read_unlock();
	seq_putc(m, '\n');

	seq_print_resource_pending_peer_requests(m, resource, jif);

	seq_puts(m, "application requests waiting for activity log\n");
	seq_print_waiting_for_AL(m, resource, now, jif);
	seq_putc(m, '\n');

	seq_puts(m, "oldest application requests\n");
	seq_print_resource_transfer_log_summary(m, resource, now, jif);
	seq_putc(m, '\n');

	jif = jiffies - jif;
	if (jif)
		seq_printf(m, "generated in %d ms\n", jiffies_to_msecs(jif));
	return 0;
}

static int resource_state_twopc_show(struct seq_file *m, void *pos)
{
	struct drbd_resource *resource = m->private;
	struct twopc_reply twopc;
	bool active = false;
	unsigned long jif;

	read_lock_irq(&resource->state_rwlock);
	if (resource->remote_state_change) {
		twopc = resource->twopc_reply;
		active = true;
	}
	read_unlock_irq(&resource->state_rwlock);

	seq_printf(m, "v: %u\n\n", 1);
	if (active) {
		struct drbd_connection *connection;

		seq_printf(m,
			   "Executing tid: %u\n"
			   "  initiator_node_id: %d\n"
			   "  target_node_id: %d\n",
			   twopc.tid, twopc.initiator_node_id,
			   twopc.target_node_id);

		if (twopc.initiator_node_id != resource->res_opts.node_id) {
			seq_puts(m, "  parent node mask: ");
			seq_print_node_mask(m, resource, resource->twopc_parent_nodes);

			if (resource->twopc_prepare_reply_cmd)
				seq_printf(m,
					   "  Reply sent: %s\n",
					   resource->twopc_prepare_reply_cmd == P_TWOPC_YES ? "yes" :
					   resource->twopc_prepare_reply_cmd == P_TWOPC_NO ? "no" :
					   resource->twopc_prepare_reply_cmd == P_TWOPC_RETRY ? "retry" :
					   "else!?!");
		}

		seq_puts(m, "  received replies: ");
		rcu_read_lock();
		for_each_connection_rcu(connection, resource) {
			char *name = rcu_dereference((connection)->transport.net_conf)->name;

			if (!test_bit(TWOPC_PREPARED, &connection->flags))
				/* seq_printf(m, "%s n.p., ", name) * print nothing! */;
			else if (test_bit(TWOPC_NO, &connection->flags))
				seq_printf(m, "%s no, ", name);
			else if (test_bit(TWOPC_RETRY, &connection->flags))
				seq_printf(m, "%s ret, ", name);
			else if (test_bit(TWOPC_YES, &connection->flags))
				seq_printf(m, "%s yes, ", name);
			else
				seq_printf(m, "%s ___, ", name);
		}
		rcu_read_unlock();
		seq_puts(m, "\n");
		if (twopc.initiator_node_id != resource->res_opts.node_id) {
			/* The timer is only relevant for twopcs initiated by other nodes */
			jif = resource->twopc_timer.expires - jiffies;
			seq_printf(m, "  timer expires in: %d ms\n", jiffies_to_msecs(jif));
		}
	} else {
		seq_puts(m, "No ongoing two phase state transaction\n");
	}

	return 0;
}

static int resource_worker_pid_show(struct seq_file *m, void *pos)
{
	struct drbd_resource *resource = m->private;
	if (resource->worker.task)
		seq_printf(m, "%d\n", resource->worker.task->pid);
	return 0;
}

static int resource_members_show(struct seq_file *m, void *pos)
{
	struct drbd_resource *resource = m->private;

	seq_printf(m, "0x%016llX\n", resource->members);
	return 0;
}

/* make sure at *open* time that the respective object won't go away. */
static int drbd_single_open(struct file *file, int (*show)(struct seq_file *, void *),
		                void *data, struct kref *kref,
				void (*release)(struct kref *))
{
	struct dentry *parent;
	int ret = -ESTALE;

	/* Are we still linked,
	 * or has debugfs_remove() already been called? */
	parent = file->f_path.dentry->d_parent;
	/* not sure if this can happen: */
	if (!parent || !parent->d_inode)
		goto out;
	/* serialize with d_delete() */
	inode_lock(d_inode(parent));
	/* Make sure the object is still alive */
	if (simple_positive(file->f_path.dentry)
	&& kref_get_unless_zero(kref))
		ret = 0;
	inode_unlock(d_inode(parent));
	if (!ret) {
		ret = single_open(file, show, data);
		if (ret)
			kref_put(kref, release);
	}
out:
	return ret;
}

static int resource_attr_release(struct inode *inode, struct file *file)
{
	struct drbd_resource *resource = inode->i_private;
	kref_put(&resource->kref, drbd_destroy_resource);
	return single_release(inode, file);
}

#define drbd_debugfs_resource_attr(name)				\
static int resource_ ## name ## _open(struct inode *inode, struct file *file) \
{									\
	struct drbd_resource *resource = inode->i_private;		\
	return drbd_single_open(file, resource_ ## name ## _show, resource, \
				&resource->kref, drbd_destroy_resource); \
}									\
static const struct file_operations resource_ ## name ## _fops = {	\
	.owner		= THIS_MODULE,					\
	.open		= resource_ ## name ## _open,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= resource_attr_release,			\
};

drbd_debugfs_resource_attr(in_flight_summary)
drbd_debugfs_resource_attr(state_twopc)
drbd_debugfs_resource_attr(worker_pid)
drbd_debugfs_resource_attr(members)

#define drbd_dcf(top, obj, attr, perm) do {			\
	dentry = debugfs_create_file(#attr, perm,		\
			top, obj, &obj ## _ ## attr ## _fops);	\
	top ## _ ## attr = dentry;				\
	} while (0)

#define res_dcf(attr) \
	drbd_dcf(resource->debugfs_res, resource, attr, 0400)

#define conn_dcf(attr) \
	drbd_dcf(connection->debugfs_conn, connection, attr, 0400)

#define vol_dcf(attr) \
	drbd_dcf(device->debugfs_vol, device, attr, 0400)

#define peer_dev_dcf(attr) \
	drbd_dcf(peer_device->debugfs_peer_dev, peer_device, attr, 0400)

void drbd_debugfs_resource_add(struct drbd_resource *resource)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir(resource->name, drbd_debugfs_resources);
	resource->debugfs_res = dentry;

	dentry = debugfs_create_dir("volumes", resource->debugfs_res);
	resource->debugfs_res_volumes = dentry;

	dentry = debugfs_create_dir("connections", resource->debugfs_res);
	resource->debugfs_res_connections = dentry;

	/* debugfs create file */
	res_dcf(in_flight_summary);
	res_dcf(state_twopc);
	res_dcf(worker_pid);
	res_dcf(members);
}

static void drbd_debugfs_remove(struct dentry **dp)
{
	debugfs_remove(*dp);
	*dp = NULL;
}

void drbd_debugfs_resource_cleanup(struct drbd_resource *resource)
{
	/* Older kernels have a broken implementation of
	 * debugfs_remove_recursive (prior to upstream commit 776164c1f)
	 * That unfortunately includes a number of "enterprise" kernels.
	 * Even older kernels do not even have the _recursive() helper at all.
	 * For now, remember all debugfs nodes we created,
	 * and call debugfs_remove on all of them separately.
	 */
	/* it is ok to call debugfs_remove(NULL) */
	drbd_debugfs_remove(&resource->debugfs_res_members);
	drbd_debugfs_remove(&resource->debugfs_res_worker_pid);
	drbd_debugfs_remove(&resource->debugfs_res_state_twopc);
	drbd_debugfs_remove(&resource->debugfs_res_in_flight_summary);
	drbd_debugfs_remove(&resource->debugfs_res_connections);
	drbd_debugfs_remove(&resource->debugfs_res_volumes);
	drbd_debugfs_remove(&resource->debugfs_res);
}

void drbd_debugfs_resource_rename(struct drbd_resource *resource, const char *new_name)
{
	int err;

	err = debugfs_change_name(resource->debugfs_res, "%s", new_name);
	if (err)
		drbd_err(resource, "failed to rename debugfs entry for resource\n");
}

static void seq_print_one_timing_detail(struct seq_file *m,
	const struct drbd_thread_timing_details *tdp,
	unsigned long jif)
{
	struct drbd_thread_timing_details td;
	/* No locking...
	 * use temporary assignment to get at consistent data. */
	do {
		td = *tdp;
	} while (td.cb_nr != tdp->cb_nr);
	if (!td.cb_addr)
		return;
	seq_printf(m, "%u\t%d\t%s:%u\t%ps\n",
			td.cb_nr,
			jiffies_to_msecs(jif - td.start_jif),
			td.caller_fn, td.line,
			td.cb_addr);
}

static void seq_print_timing_details(struct seq_file *m,
		const char *title,
		unsigned int cb_nr, struct drbd_thread_timing_details *tdp, unsigned long jif)
{
	unsigned int start_idx;
	unsigned int i;

	seq_printf(m, "%s\n", title);
	/* If not much is going on, this will result in natural ordering.
	 * If it is very busy, we will possibly skip events, or even see wrap
	 * arounds, which could only be avoided with locking.
	 */
	start_idx = cb_nr % DRBD_THREAD_DETAILS_HIST;
	for (i = start_idx; i < DRBD_THREAD_DETAILS_HIST; i++)
		seq_print_one_timing_detail(m, tdp+i, jif);
	for (i = 0; i < start_idx; i++)
		seq_print_one_timing_detail(m, tdp+i, jif);
}

static int connection_callback_history_show(struct seq_file *m, void *ignored)
{
	struct drbd_connection *connection = m->private;
	struct drbd_resource *resource = connection->resource;
	unsigned long jif = jiffies;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	seq_puts(m, "n\tage\tcallsite\tfn\n");
	seq_print_timing_details(m, "sender", connection->s_cb_nr, connection->s_timing_details, jif);
	seq_print_timing_details(m, "receiver", connection->r_cb_nr, connection->r_timing_details, jif);
	seq_print_timing_details(m, "worker", resource->w_cb_nr, resource->w_timing_details, jif);
	return 0;
}

static int connection_oldest_requests_show(struct seq_file *m, void *ignored)
{
	struct drbd_connection *connection = m->private;
	ktime_t now = ktime_get();
	unsigned long jif = jiffies;
	struct drbd_request *r1, *r2;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	rcu_read_lock();
	r1 = READ_ONCE(connection->todo.req_next);
	if (r1)
		seq_print_minor_vnr_req(m, r1, now, jif);
	r2 = READ_ONCE(connection->req_ack_pending);
	if (r2 && r2 != r1) {
		r1 = r2;
		seq_print_minor_vnr_req(m, r1, now, jif);
	}
	r2 = READ_ONCE(connection->req_not_net_done);
	if (r2 && r2 != r1)
		seq_print_minor_vnr_req(m, r2, now, jif);
	rcu_read_unlock();
	return 0;
}

static int connection_transport_show(struct seq_file *m, void *ignored)
{
	struct drbd_connection *connection = m->private;
	struct drbd_transport *transport = &connection->transport;
	struct drbd_transport_ops *tr_ops = &transport->class->ops;
	enum drbd_stream i;

	seq_printf(m, "v: %u\n\n", 0);

	for (i = DATA_STREAM; i <= CONTROL_STREAM; i++) {
		struct drbd_send_buffer *sbuf = &connection->send_buffer[i];
		seq_printf(m, "%s stream\n", i == DATA_STREAM ? "data" : "control");
		seq_printf(m, "  corked: %d\n", test_bit(CORKED + i, &connection->flags));
		seq_printf(m, "  unsent: %ld bytes\n", (long)(sbuf->pos - sbuf->unsent));
		seq_printf(m, "  allocated: %d bytes\n", sbuf->allocated_size);
	}

	seq_printf(m, "\ntransport_type: %s\n", transport->class->name);

	tr_ops->debugfs_show(transport, m);

	return 0;
}

static int connection_debug_show(struct seq_file *m, void *ignored)
{
	struct drbd_connection *connection = m->private;
	struct drbd_resource *resource = connection->resource;
	unsigned long flags = connection->flags;
	unsigned int u1, u2;
	unsigned long long ull1, ull2;
	int in_flight;
	char sep = ' ';

	seq_puts(m, "content and format of this will change without notice\n");

	seq_printf(m, "flags: 0x%04lx :", flags);
#define pretty_print_bit(n) \
	seq_print_rq_state_bit(m, test_bit(n, &flags), &sep, #n);
	pretty_print_bit(PING_PENDING);
	pretty_print_bit(TWOPC_PREPARED);
	pretty_print_bit(TWOPC_YES);
	pretty_print_bit(TWOPC_NO);
	pretty_print_bit(TWOPC_RETRY);
	pretty_print_bit(CONN_DRY_RUN);
	pretty_print_bit(DISCONNECT_EXPECTED);
	pretty_print_bit(BARRIER_ACK_PENDING);
	pretty_print_bit(DATA_CORKED);
	pretty_print_bit(CONTROL_CORKED);
	pretty_print_bit(C_UNREGISTERED);
	pretty_print_bit(RECONNECT);
	pretty_print_bit(CONN_DISCARD_MY_DATA);
	pretty_print_bit(SEND_STATE_AFTER_AHEAD_C);
	pretty_print_bit(NOTIFY_PEERS_LOST_PRIMARY);
	pretty_print_bit(CHECKING_PEER);
	pretty_print_bit(CONN_CONGESTED);
	pretty_print_bit(CONN_HANDSHAKE_DISCONNECT);
	pretty_print_bit(CONN_HANDSHAKE_RETRY);
	pretty_print_bit(CONN_HANDSHAKE_READY);
#undef pretty_print_bit
	seq_putc(m, '\n');

	u1 = atomic_read(&resource->current_tle_nr);
	u2 = connection->send.current_epoch_nr;
	seq_printf(m, "resource->current_tle_nr: %u\n", u1);
	seq_printf(m, "   send.current_epoch_nr: %u (%d)\n", u2, (int)(u2 - u1));

	ull1 = resource->dagtag_sector;
	ull2 = resource->last_peer_acked_dagtag;
	seq_printf(m, " resource->dagtag_sector: %llu\n", ull1);
	seq_printf(m, "  last_peer_acked_dagtag: %llu (%lld)\n", ull2, (long long)(ull2 - ull1));
	ull2 = connection->send.current_dagtag_sector;
	seq_printf(m, " send.current_dagtag_sec: %llu (%lld)\n", ull2, (long long)(ull2 - ull1));
	ull2 = atomic64_read(&connection->last_dagtag_sector);
	seq_printf(m, "      last_dagtag_sector: %llu\n", ull2);
	seq_printf(m, "last_peer_ack_dagtag_seen: %llu\n",
			(unsigned long long) connection->last_peer_ack_dagtag_seen);

	spin_lock_irq(&resource->initiator_flush_lock);
	seq_printf(m, "resource->current_flush_sequence: %llu\n",
			(unsigned long long) resource->current_flush_sequence);
	seq_puts(m, "      pending_flush_mask: ");
	seq_print_node_mask(m, resource, connection->pending_flush_mask);
	spin_unlock_irq(&resource->initiator_flush_lock);

	spin_lock_irq(&connection->primary_flush_lock);
	seq_printf(m, "   flush_requests_dagtag: %llu\n",
			(unsigned long long) connection->flush_requests_dagtag);
	seq_printf(m, "          flush_sequence: %llu\n",
			(unsigned long long) connection->flush_sequence);
	seq_puts(m, " flush_forward_sent_mask: ");
	seq_print_node_mask(m, resource, connection->flush_forward_sent_mask);
	spin_unlock_irq(&connection->primary_flush_lock);

	spin_lock_irq(&connection->flush_ack_lock);
	for (u1 = 0; u1 < DRBD_PEERS_MAX; u1++) {
		if (connection->flush_ack_sequence[u1])
			seq_printf(m, "      flush_ack_sequence[%u]: %llu\n", u1,
					(unsigned long long) connection->flush_ack_sequence[u1]);
	}
	spin_unlock_irq(&connection->flush_ack_lock);

	in_flight = atomic_read(&connection->ap_in_flight);
	seq_printf(m, "            ap_in_flight: %d KiB (%d sectors)\n", in_flight / 2, in_flight);

	in_flight = atomic_read(&connection->rs_in_flight);
	seq_printf(m, "            rs_in_flight: %d KiB (%d sectors)\n", in_flight / 2, in_flight);

	seq_printf(m, "             done_ee_cnt: %d\n"
			"          backing_ee_cnt: %d\n"
			"           active_ee_cnt: %d\n",
			atomic_read(&connection->done_ee_cnt),
			atomic_read(&connection->backing_ee_cnt),
			atomic_read(&connection->active_ee_cnt));
	seq_printf(m, "      agreed_pro_version: %d\n", connection->agreed_pro_version);
	seq_printf(m, "            send control: %u bytes/pckt (%u bytes, %u pckts)\n",
		   connection->ctl_bytes / (connection->ctl_packets ?: 1),
		   connection->ctl_bytes, connection->ctl_packets);
	return 0;
}

static void pid_show(struct seq_file *m, struct drbd_thread *thi)
{
	struct task_struct *task = NULL;
	pid_t pid;

	spin_lock_irq(&thi->t_lock);
	task = thi->task;
	if (task)
		pid = task->pid;
	spin_unlock_irq(&thi->t_lock);
	if (task)
		seq_printf(m, "%d\n", pid);
}

static int connection_receiver_pid_show(struct seq_file *m, void *pos)
{
	struct drbd_connection *connection = m->private;
	pid_show(m, &connection->receiver);
	return 0;
}

static int connection_sender_pid_show(struct seq_file *m, void *pos)
{
	struct drbd_connection *connection = m->private;
	pid_show(m, &connection->sender);
	return 0;
}

static int connection_attr_release(struct inode *inode, struct file *file)
{
	struct drbd_connection *connection = inode->i_private;
	kref_put(&connection->kref, drbd_destroy_connection);
	return single_release(inode, file);
}

#define drbd_debugfs_connection_attr(name)				\
static int connection_ ## name ## _open(struct inode *inode, struct file *file) \
{									\
	struct drbd_connection *connection = inode->i_private;		\
	return drbd_single_open(file, connection_ ## name ## _show,	\
				connection, &connection->kref,		\
				drbd_destroy_connection);		\
}									\
static const struct file_operations connection_ ## name ## _fops = {	\
	.owner		= THIS_MODULE,				      	\
	.open		= connection_ ## name ##_open,			\
	.read		= seq_read,					\
	.llseek		= seq_lseek,					\
	.release	= connection_attr_release,			\
};

drbd_debugfs_connection_attr(oldest_requests)
drbd_debugfs_connection_attr(callback_history)
drbd_debugfs_connection_attr(transport)
drbd_debugfs_connection_attr(debug)
drbd_debugfs_connection_attr(receiver_pid)
drbd_debugfs_connection_attr(sender_pid)

void drbd_debugfs_connection_add(struct drbd_connection *connection)
{
	struct dentry *conns_dir = connection->resource->debugfs_res_connections;
	struct drbd_peer_device *peer_device;
	char conn_name[SHARED_SECRET_MAX];
	struct dentry *dentry;
	int vnr;

	rcu_read_lock();
	strcpy(conn_name, rcu_dereference(connection->transport.net_conf)->name);
	rcu_read_unlock();

	dentry = debugfs_create_dir(conn_name, conns_dir);
	connection->debugfs_conn = dentry;

	/* debugfs create file */
	conn_dcf(callback_history);
	conn_dcf(oldest_requests);
	conn_dcf(transport);
	conn_dcf(debug);
	conn_dcf(receiver_pid);
	conn_dcf(sender_pid);

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (!peer_device->debugfs_peer_dev)
			drbd_debugfs_peer_device_add(peer_device);
	}
}

void drbd_debugfs_connection_cleanup(struct drbd_connection *connection)
{
	drbd_debugfs_remove(&connection->debugfs_conn_sender_pid);
	drbd_debugfs_remove(&connection->debugfs_conn_receiver_pid);
	drbd_debugfs_remove(&connection->debugfs_conn_debug);
	drbd_debugfs_remove(&connection->debugfs_conn_transport);
	drbd_debugfs_remove(&connection->debugfs_conn_callback_history);
	drbd_debugfs_remove(&connection->debugfs_conn_oldest_requests);
	drbd_debugfs_remove(&connection->debugfs_conn);
}

static void seq_printf_nice_histogram(struct seq_file *m, unsigned *hist, unsigned const n)
{
	unsigned i;
	unsigned max = 0;
	unsigned n_transactions = 0;
	unsigned long n_updates = 0;

	for (i = 1; i <= n; i++) {
		if (hist[i] > max)
			max = hist[i];
		n_updates += i * hist[i];
		n_transactions += hist[i];
	}

	seq_puts(m, "updates per activity log transaction\n");
	seq_printf(m, "avg: %lu\n", n_transactions == 0 ? 0 : n_updates / n_transactions);

	if (!max)
		return;

	for (i = 0; i <= n; i++) {
		unsigned v = (hist[i] * 60UL + max-1) / max;
		seq_printf(m, "%2u : %10u : %-60.*s\n", i, hist[i], v,
			"############################################################");
	}
}


static int device_act_log_histogram_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	if (get_ldev_if_state(device, D_FAILED)) {
		seq_printf_nice_histogram(m, device->al_histogram, AL_UPDATES_PER_TRANSACTION);
		put_ldev(device);
	}
	return 0;
}

static int device_act_log_extents_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	if (get_ldev_if_state(device, D_FAILED)) {
		lc_seq_printf_stats(m, device->act_log);
		lc_seq_dump_details(m, device->act_log, "", NULL);
		put_ldev(device);
	}
	return 0;
}

static int device_oldest_requests_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	ktime_t now = ktime_get();
	unsigned long jif = jiffies;
	struct drbd_request *r1, *r2;
	int i;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	seq_puts(m, RQ_HDR);
	spin_lock_irq(&device->pending_completion_lock);
	/* WRITE, then READ */
	for (i = 1; i >= 0; --i) {
		r1 = list_first_entry_or_null(&device->pending_master_completion[i],
			struct drbd_request, req_pending_master_completion);
		r2 = list_first_entry_or_null(&device->pending_completion[i],
			struct drbd_request, req_pending_local);
		if (r1)
			seq_print_one_request(m, r1, now, jif);
		if (r2 && r2 != r1)
			seq_print_one_request(m, r2, now, jif);
	}
	spin_unlock_irq(&device->pending_completion_lock);
	return 0;
}

static int device_openers_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	struct drbd_resource *resource = device->resource;
	ktime_t now = ktime_get_real();
	struct opener *tmp;

	spin_lock(&device->openers_lock);
	list_for_each_entry(tmp, &device->openers, list)
		seq_printf(m, "%s\t%d\t%lld\n", tmp->comm, tmp->pid,
			ktime_to_ms(ktime_sub(now, tmp->opened)));
	spin_unlock(&device->openers_lock);
	if (mutex_trylock(&resource->open_release)) {
		if (resource->auto_promoted_by.pid != 0
		&&  device->minor == resource->auto_promoted_by.minor) {
			seq_printf(m, "+%s\t%d\t%lld\n",
				resource->auto_promoted_by.comm,
				resource->auto_promoted_by.pid,
				ktime_to_ms(ktime_sub(now, resource->auto_promoted_by.opened)));
		}
		mutex_unlock(&resource->open_release);
	}

	return 0;
}

static int device_md_io_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;

	if (get_ldev_if_state(device, D_FAILED)) {
		seq_puts(m, drbd_md_dax_active(device->ldev) ? "dax-pmem\n" : "blk-bio\n");
		put_ldev(device);
	}

	return 0;
}

static void seq_printf_interval_tree(struct seq_file *m, struct rb_root *root)
{
	struct rb_node *node;

	node = rb_first(root);
	while (node) {
		struct drbd_interval *i = rb_entry(node, struct drbd_interval, rb);
		char sep = ' ';

		seq_printf(m, "%llus+%u %s", (unsigned long long) i->sector, i->size, drbd_interval_type_str(i));
		seq_print_rq_state_bit(m, test_bit(INTERVAL_SENT, &i->flags), &sep, "sent");
		seq_print_rq_state_bit(m, test_bit(INTERVAL_RECEIVED, &i->flags), &sep, "received");
		seq_print_rq_state_bit(m, test_bit(INTERVAL_SUBMIT_CONFLICT_QUEUED, &i->flags), &sep, "submit-conflict-queued");
		seq_print_rq_state_bit(m, test_bit(INTERVAL_SUBMITTED, &i->flags), &sep, "submitted");
		seq_print_rq_state_bit(m, test_bit(INTERVAL_BACKING_COMPLETED, &i->flags), &sep, "backing-completed");
		seq_print_rq_state_bit(m, test_bit(INTERVAL_COMPLETED, &i->flags), &sep, "completed");
		seq_print_rq_state_bit(m, test_bit(INTERVAL_CANCELED, &i->flags), &sep, "canceled");
		seq_putc(m, '\n');

		node = rb_next(node);
	}
}

static int device_interval_tree_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;

	spin_lock_irq(&device->interval_lock);
	seq_puts(m, "Write requests:\n");
	seq_printf_interval_tree(m, &device->requests);
	seq_putc(m, '\n');
	seq_puts(m, "Read requests:\n");
	seq_printf_interval_tree(m, &device->read_requests);
	spin_unlock_irq(&device->interval_lock);

	return 0;
}

static int device_data_gen_id_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	struct drbd_md *md;
	int node_id, i = 0;

	if (!get_ldev_if_state(device, D_FAILED))
		return -ENODEV;

	md = &device->ldev->md;

	spin_lock_irq(&md->uuid_lock);
	seq_printf(m, "0x%016llX\n", drbd_current_uuid(device));

	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		if (!(md->peers[node_id].flags & MDF_HAVE_BITMAP))
			continue;
		seq_printf(m, "%s[%d]0x%016llX", i++ ? " " : "", node_id,
			   md->peers[node_id].bitmap_uuid);
	}
	seq_putc(m, '\n');

	for (i = 0; i < HISTORY_UUIDS; i++)
		seq_printf(m, "0x%016llX\n", drbd_history_uuid(device, i));
	spin_unlock_irq(&md->uuid_lock);
	put_ldev(device);
	return 0;
}

static int device_io_frozen_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	unsigned long flags = device->flags;
	char sep = ' ';

	if (!get_ldev_if_state(device, D_FAILED))
		return -ENODEV;

	/* BUMP me if you change the file format/content/presentation */
	seq_printf(m, "v: %u\n\n", 0);

	seq_printf(m, "drbd_suspended(): %d\n", drbd_suspended(device));
	seq_printf(m, "suspend_cnt: %d\n", atomic_read(&device->suspend_cnt));
	seq_printf(m, "!drbd_state_is_stable(): %d\n", device->cached_state_unstable);
	seq_printf(m, "ap_bio_cnt[READ]: %d\n", atomic_read(&device->ap_bio_cnt[READ]));
	seq_printf(m, "ap_bio_cnt[WRITE]: %d\n", atomic_read(&device->ap_bio_cnt[WRITE]));
	seq_printf(m, "device->pending_bitmap_work.n: %d\n", atomic_read(&device->pending_bitmap_work.n));
	seq_printf(m, "may_inc_ap_bio(): %d\n", may_inc_ap_bio(device));
	seq_printf(m, "flags: 0x%04lx :", flags);
#define pretty_print_bit(n) \
	seq_print_rq_state_bit(m, test_bit(n, &flags), &sep, #n)
	pretty_print_bit(NEW_CUR_UUID);
	pretty_print_bit(WRITING_NEW_CUR_UUID);
	pretty_print_bit(MAKE_NEW_CUR_UUID);
#undef pretty_print_bit
	seq_putc(m, '\n');
	put_ldev(device);

	return 0;
}

static int device_al_updates_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	bool al_updates, cfg_al_updates;

	if (!get_ldev_if_state(device, D_FAILED))
		return -ENODEV;

	al_updates = !(device->ldev->md.flags & MDF_AL_DISABLED);
	rcu_read_lock();
	cfg_al_updates = rcu_dereference(device->ldev->disk_conf)->al_updates;
	rcu_read_unlock();
	put_ldev(device);

	seq_printf(m, "%s\n",
		    al_updates &&  cfg_al_updates ? "yes" :
		   !al_updates &&  cfg_al_updates ? "no (optimized)" :
		   !al_updates && !cfg_al_updates ? "no" :
		   "?");
	return 0;
}

static int device_ed_gen_id_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	seq_printf(m, "0x%016llX\n", (unsigned long long)device->exposed_data_uuid);
	return 0;
}

#define show_per_peer(M) do {							\
		seq_printf(m, "%-16s", #M ":");					\
		for_each_peer_device(peer_device, device)			\
			seq_printf(m, " %12lld", ktime_to_ns(peer_device->M));	\
		seq_printf(m, "\n");						\
	} while (0);

#define PRId64 "lld"

#ifdef CONFIG_DRBD_TIMING_STATS
static int device_req_timing_show(struct seq_file *m, void *ignored)
{
	struct drbd_device *device = m->private;
	struct drbd_peer_device *peer_device;

	seq_printf(m,
		   "timing values are nanoseconds; write an 'r' to reset all to 0\n\n"
		   "requests:        %12lu\n"
		   "before_queue:    %12" PRId64 "\n"
		   "before_al_begin  %12" PRId64 "\n"
		   "in_actlog:       %12" PRId64 "\n"
		   "pre_submit:      %12" PRId64 "\n\n"
		   "al_updates:      %12u\n"
		   "before_bm_write  %12" PRId64 "\n"
		   "mid              %12" PRId64 "\n"
		   "after_sync_page  %12" PRId64 "\n",
		   device->reqs,
		   ktime_to_ns(device->before_queue_kt),
		   ktime_to_ns(device->before_al_begin_io_kt),
		   ktime_to_ns(device->in_actlog_kt),
		   ktime_to_ns(device->pre_submit_kt),
		   device->al_writ_cnt,
		   ktime_to_ns(device->al_before_bm_write_hinted_kt),
		   ktime_to_ns(device->al_mid_kt),
		   ktime_to_ns(device->al_after_sync_page_kt));

	seq_puts(m, "\npeer:           ");
	for_each_peer_device(peer_device, device) {
		struct drbd_connection *connection = peer_device->connection;
		seq_printf(m, " %12.12s", rcu_dereference(connection->transport.net_conf)->name);
	}
	seq_puts(m, "\n");
	show_per_peer(pre_send_kt);
	show_per_peer(acked_kt);
	show_per_peer(net_done_kt);

	return 0;
}

static ssize_t device_req_timing_write(struct file *file, const char __user *ubuf,
				       size_t cnt, loff_t *ppos)
{
	struct drbd_device *device = file_inode(file)->i_private;
	char buffer;

	if (copy_from_user(&buffer, ubuf, 1))
		return -EFAULT;

	if (buffer == 'r' || buffer == 'R') {
		struct drbd_peer_device *peer_device;
		unsigned long flags;

		spin_lock_irqsave(&device->timing_lock, flags);
		device->reqs = 0;
		device->in_actlog_kt = ns_to_ktime(0);
		device->pre_submit_kt = ns_to_ktime(0);

		device->before_queue_kt = ns_to_ktime(0);
		device->before_al_begin_io_kt = ns_to_ktime(0);
		device->al_writ_cnt = 0;
		device->al_before_bm_write_hinted_kt = ns_to_ktime(0);
		device->al_mid_kt = ns_to_ktime(0);
		device->al_after_sync_page_kt = ns_to_ktime(0);

		for_each_peer_device(peer_device, device) {
			peer_device->pre_send_kt = ns_to_ktime(0);
			peer_device->acked_kt = ns_to_ktime(0);
			peer_device->net_done_kt = ns_to_ktime(0);
		}
		spin_unlock_irqrestore(&device->timing_lock, flags);
	}

	*ppos += cnt;
	return cnt;
}
#endif

static int device_attr_release(struct inode *inode, struct file *file)
{
	struct drbd_device *device = inode->i_private;
	kref_put(&device->kref, drbd_destroy_device);
	return single_release(inode, file);
}

#define __drbd_debugfs_device_attr(name, write_fn)				\
static int device_ ## name ## _open(struct inode *inode, struct file *file)	\
{										\
	struct drbd_device *device = inode->i_private;				\
	return drbd_single_open(file, device_ ## name ## _show, device,		\
				&device->kref, drbd_destroy_device);		\
}										\
static const struct file_operations device_ ## name ## _fops = {		\
	.owner		= THIS_MODULE,						\
	.open		= device_ ## name ## _open,				\
	.write          = write_fn,						\
	.read		= seq_read,						\
	.llseek		= seq_lseek,						\
	.release	= device_attr_release,					\
};
#define drbd_debugfs_device_attr(name) __drbd_debugfs_device_attr(name, NULL)

drbd_debugfs_device_attr(oldest_requests)
drbd_debugfs_device_attr(act_log_extents)
drbd_debugfs_device_attr(act_log_histogram)
drbd_debugfs_device_attr(data_gen_id)
drbd_debugfs_device_attr(io_frozen)
drbd_debugfs_device_attr(ed_gen_id)
drbd_debugfs_device_attr(openers)
drbd_debugfs_device_attr(md_io)
drbd_debugfs_device_attr(interval_tree)
drbd_debugfs_device_attr(al_updates)
#ifdef CONFIG_DRBD_TIMING_STATS
__drbd_debugfs_device_attr(req_timing, device_req_timing_write)
#endif

void drbd_debugfs_device_add(struct drbd_device *device)
{
	struct dentry *vols_dir = device->resource->debugfs_res_volumes;
	struct drbd_peer_device *peer_device;
	char minor_buf[8]; /* MINORMASK, MINORBITS == 20; */
	char vnr_buf[8];   /* volume number vnr is even 16 bit only; */
	char *slink_name = NULL;

	struct dentry *dentry;
	if (!vols_dir || !drbd_debugfs_minors)
		return;

	snprintf(vnr_buf, sizeof(vnr_buf), "%u", device->vnr);
	dentry = debugfs_create_dir(vnr_buf, vols_dir);
	device->debugfs_vol = dentry;

	snprintf(minor_buf, sizeof(minor_buf), "%u", device->minor);
	slink_name = kasprintf(GFP_KERNEL, "../resources/%s/volumes/%u",
			device->resource->name, device->vnr);
	if (!slink_name)
		goto fail;
	dentry = debugfs_create_symlink(minor_buf, drbd_debugfs_minors, slink_name);
	device->debugfs_minor = dentry;
	kfree(slink_name);
	slink_name = NULL;

	/* debugfs create file */
	vol_dcf(oldest_requests);
	vol_dcf(act_log_extents);
	vol_dcf(act_log_histogram);
	vol_dcf(data_gen_id);
	vol_dcf(io_frozen);
	vol_dcf(ed_gen_id);
	vol_dcf(openers);
	vol_dcf(md_io);
	vol_dcf(interval_tree);
	vol_dcf(al_updates);
#ifdef CONFIG_DRBD_TIMING_STATS
	drbd_dcf(device->debugfs_vol, device, req_timing, 0600);
#endif

	/* Caller holds conf_update */
	for_each_peer_device(peer_device, device) {
		if (!peer_device->debugfs_peer_dev)
			drbd_debugfs_peer_device_add(peer_device);
	}

	return;

fail:
	drbd_debugfs_device_cleanup(device);
	drbd_err(device, "failed to create debugfs entries\n");
}

void drbd_debugfs_device_cleanup(struct drbd_device *device)
{
	drbd_debugfs_remove(&device->debugfs_minor);
	drbd_debugfs_remove(&device->debugfs_vol_oldest_requests);
	drbd_debugfs_remove(&device->debugfs_vol_act_log_extents);
	drbd_debugfs_remove(&device->debugfs_vol_act_log_histogram);
	drbd_debugfs_remove(&device->debugfs_vol_data_gen_id);
	drbd_debugfs_remove(&device->debugfs_vol_io_frozen);
	drbd_debugfs_remove(&device->debugfs_vol_ed_gen_id);
	drbd_debugfs_remove(&device->debugfs_vol_openers);
	drbd_debugfs_remove(&device->debugfs_vol_md_io);
	drbd_debugfs_remove(&device->debugfs_vol_interval_tree);
	drbd_debugfs_remove(&device->debugfs_vol_al_updates);
#ifdef CONFIG_DRBD_TIMING_STATS
	drbd_debugfs_remove(&device->debugfs_vol_req_timing);
#endif
	drbd_debugfs_remove(&device->debugfs_vol);
}

static int drbd_single_open_peer_device(struct file *file,
					int (*show)(struct seq_file *, void *),
					struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	bool got_connection, got_device;
	struct dentry *parent;

	parent = file->f_path.dentry->d_parent;
	if (!parent || !parent->d_inode)
		goto out;
	inode_lock(d_inode(parent));
	if (!simple_positive(file->f_path.dentry))
		goto out_unlock;

	got_connection = kref_get_unless_zero(&connection->kref);
	got_device = kref_get_unless_zero(&device->kref);

	if (got_connection && got_device) {
		int ret;
		inode_unlock(d_inode(parent));
		ret = single_open(file, show, peer_device);
		if (ret) {
			kref_put(&connection->kref, drbd_destroy_connection);
			kref_put(&device->kref, drbd_destroy_device);
		}
		return ret;
	}

	if (got_connection)
		kref_put(&connection->kref, drbd_destroy_connection);
	if (got_device)
		kref_put(&device->kref, drbd_destroy_device);
out_unlock:
	inode_unlock(d_inode(parent));
out:
	return -ESTALE;
}

static void seq_printf_with_thousands_grouping(struct seq_file *seq, long v)
{
	/* v is in kB/sec. We don't expect TiByte/sec yet. */
	if (unlikely(v >= 1000000)) {
		/* cool: > GiByte/s */
		seq_printf(seq, "%ld,", v / 1000000);
		v %= 1000000;
		seq_printf(seq, "%03ld,%03ld", v/1000, v % 1000);
	} else if (likely(v >= 1000))
		seq_printf(seq, "%ld,%03ld", v/1000, v % 1000);
	else
		seq_printf(seq, "%ld", v);
}

static void drbd_get_syncer_progress(struct drbd_peer_device *pd,
		enum drbd_repl_state repl_state, unsigned long *rs_total,
		unsigned long *bits_left, unsigned int *per_mil_done)
{
	/* this is to break it at compile time when we change that, in case we
	 * want to support more than (1<<32) bits on a 32bit arch. */
	typecheck(unsigned long, pd->rs_total);
	*rs_total = pd->rs_total;

	/* note: both rs_total and rs_left are in bits, i.e. in
	 * units of BM_BLOCK_SIZE.
	 * for the percentage, we don't care. */

	if (repl_state == L_VERIFY_S || repl_state == L_VERIFY_T)
		*bits_left = atomic64_read(&pd->ov_left);
	else
		*bits_left = drbd_bm_total_weight(pd) - pd->rs_failed;
	/* >> 10 to prevent overflow,
	 * +1 to prevent division by zero */
	if (*bits_left > *rs_total) {
		/* D'oh. Maybe a logic bug somewhere.  More likely just a race
		 * between state change and reset of rs_total.
		 */
		*bits_left = *rs_total;
		*per_mil_done = *rs_total ? 0 : 1000;
	} else {
		/* Make sure the division happens in long context.
		 * We allow up to one petabyte storage right now,
		 * at a granularity of 4k per bit that is 2**38 bits.
		 * After shift right and multiplication by 1000,
		 * this should still fit easily into a 32bit long,
		 * so we don't need a 64bit division on 32bit arch.
		 * Note: currently we don't support such large bitmaps on 32bit
		 * arch anyways, but no harm done to be prepared for it here.
		 */
		unsigned int shift = *rs_total > UINT_MAX ? 16 : 10;
		unsigned long left = *bits_left >> shift;
		unsigned long total = 1UL + (*rs_total >> shift);
		unsigned long tmp = 1000UL - left * 1000UL/total;
		*per_mil_done = tmp;
	}
}

static void drbd_syncer_progress(struct drbd_peer_device *pd, struct seq_file *seq,
		enum drbd_repl_state repl_state)
{
	unsigned long db, dt, dbdt, rt, rs_total, rs_left;
	unsigned int res;
	int i, x, y;
	int stalled = 0;

	drbd_get_syncer_progress(pd, repl_state, &rs_total, &rs_left, &res);

	x = res/50;
	y = 20-x;
	seq_puts(seq, "\t[");
	for (i = 1; i < x; i++)
		seq_putc(seq, '=');
	seq_putc(seq, '>');
	for (i = 0; i < y; i++)
		seq_putc(seq, '.');
	seq_puts(seq, "] ");

	if (repl_state == L_VERIFY_S || repl_state == L_VERIFY_T)
		seq_puts(seq, "verified:");
	else
		seq_puts(seq, "sync'ed:");
	seq_printf(seq, "%3u.%u%% ", res / 10, res % 10);

	/* if more than a few GB, display in MB */
	if (rs_total > (4UL << (30 - BM_BLOCK_SHIFT)))
		seq_printf(seq, "(%lu/%lu)M",
			    (unsigned long) Bit2KB(rs_left >> 10),
			    (unsigned long) Bit2KB(rs_total >> 10));
	else
		seq_printf(seq, "(%lu/%lu)K",
			    (unsigned long) Bit2KB(rs_left),
			    (unsigned long) Bit2KB(rs_total));

	seq_puts(seq, "\n\t");

	/* see drivers/md/md.c
	 * We do not want to overflow, so the order of operands and
	 * the * 100 / 100 trick are important. We do a +1 to be
	 * safe against division by zero. We only estimate anyway.
	 *
	 * dt: time from mark until now
	 * db: blocks written from mark until now
	 * rt: remaining time
	 */
	/* Rolling marks. last_mark+1 may just now be modified.  last_mark+2 is
	 * at least (DRBD_SYNC_MARKS-2)*DRBD_SYNC_MARK_STEP old, and has at
	 * least DRBD_SYNC_MARK_STEP time before it will be modified. */
	/* ------------------------ ~18s average ------------------------ */
	i = (pd->rs_last_mark + 2) % DRBD_SYNC_MARKS;
	dt = (jiffies - pd->rs_mark_time[i]) / HZ;
	if (dt > 180)
		stalled = 1;

	if (!dt)
		dt++;
	db = pd->rs_mark_left[i] - rs_left;
	rt = (dt * (rs_left / (db/100+1)))/100; /* seconds */

	seq_printf(seq, "finish: %lu:%02lu:%02lu",
		rt / 3600, (rt % 3600) / 60, rt % 60);

	dbdt = Bit2KB(db/dt);
	seq_puts(seq, " speed: ");
	seq_printf_with_thousands_grouping(seq, dbdt);
	seq_puts(seq, " (");
	/* ------------------------- ~3s average ------------------------ */
	if (1) {
		/* this is what drbd_rs_should_slow_down() uses */
		i = (pd->rs_last_mark + DRBD_SYNC_MARKS-1) % DRBD_SYNC_MARKS;
		dt = (jiffies - pd->rs_mark_time[i]) / HZ;
		if (!dt)
			dt++;
		db = pd->rs_mark_left[i] - rs_left;
		dbdt = Bit2KB(db/dt);
		seq_printf_with_thousands_grouping(seq, dbdt);
		seq_puts(seq, " -- ");
	}

	/* --------------------- long term average ---------------------- */
	/* mean speed since syncer started
	 * we do account for PausedSync periods */
	dt = (jiffies - pd->rs_start - pd->rs_paused) / HZ;
	if (dt == 0)
		dt = 1;
	db = rs_total - rs_left;
	dbdt = Bit2KB(db/dt);
	seq_printf_with_thousands_grouping(seq, dbdt);
	seq_putc(seq, ')');

	if (repl_state == L_SYNC_TARGET ||
	    repl_state == L_VERIFY_S) {
		seq_puts(seq, " want: ");
		seq_printf_with_thousands_grouping(seq, pd->c_sync_rate);
	}
	seq_printf(seq, " K/sec%s\n", stalled ? " (stalled)" : "");

	{
		/* 64 bit:
		 * we convert to sectors in the display below. */
		unsigned long bm_bits = drbd_bm_bits(pd->device);
		unsigned long bit_pos;
		unsigned long long stop_sector = 0;
		if (repl_state == L_VERIFY_S ||
		    repl_state == L_VERIFY_T) {
			bit_pos = bm_bits - (unsigned long)atomic64_read(&pd->ov_left);
			if (verify_can_do_stop_sector(pd))
				stop_sector = pd->ov_stop_sector;
		} else
			bit_pos = pd->resync_next_bit;
		/* Total sectors may be slightly off for oddly
		 * sized devices. So what. */
		seq_printf(seq,
			"\t%3d%% sector pos: %llu/%llu",
			(int)(bit_pos / (bm_bits/100+1)),
			(unsigned long long)bit_pos * BM_SECT_PER_BIT,
			(unsigned long long)bm_bits * BM_SECT_PER_BIT);
		if (stop_sector != 0 && stop_sector != ULLONG_MAX)
			seq_printf(seq, " stop sector: %llu", stop_sector);
		seq_putc(seq, '\n');
	}
}

static int peer_device_proc_drbd_show(struct seq_file *m, void *ignored)
{
	struct drbd_peer_device *peer_device = m->private;
	struct drbd_device *device = peer_device->device;
	union drbd_state state;
	const char *sn;
	struct net_conf *nc;
	char wp;

	state.disk = device->disk_state[NOW];
	state.pdsk = peer_device->disk_state[NOW];
	state.conn = peer_device->repl_state[NOW];
	state.role = device->resource->role[NOW];
	state.peer = peer_device->connection->peer_role[NOW];

	state.user_isp = peer_device->resync_susp_user[NOW];
	state.peer_isp = peer_device->resync_susp_peer[NOW];
	state.aftr_isp = peer_device->resync_susp_dependency[NOW];

	sn = drbd_repl_str(state.conn);

	rcu_read_lock();
	{
		/* reset device->congestion_reason */

		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		wp = nc ? nc->wire_protocol - DRBD_PROT_A + 'A' : ' ';
		seq_printf(m,
		   "%2d: cs:%s ro:%s/%s ds:%s/%s %c %c%c%c%c%c%c\n"
		   "    ns:%u nr:%u dw:%u dr:%u al:%u bm:%u "
		   "lo:%d pe:[%d;%d] ua:%d ap:[%d;%d] ep:%d wo:%d",
		   device->minor, sn,
		   drbd_role_str(state.role),
		   drbd_role_str(state.peer),
		   drbd_disk_str(state.disk),
		   drbd_disk_str(state.pdsk),
		   wp,
		   drbd_suspended(device) ? 's' : 'r',
		   state.aftr_isp ? 'a' : '-',
		   state.peer_isp ? 'p' : '-',
		   state.user_isp ? 'u' : '-',
		   '-' /* congestion reason... FIXME */,
		   test_bit(AL_SUSPENDED, &device->flags) ? 's' : '-',
		   peer_device->send_cnt/2,
		   peer_device->recv_cnt/2,
		   device->writ_cnt/2,
		   device->read_cnt/2,
		   device->al_writ_cnt,
		   device->bm_writ_cnt,
		   atomic_read(&device->local_cnt),
		   atomic_read(&peer_device->ap_pending_cnt),
		   atomic_read(&peer_device->rs_pending_cnt),
		   atomic_read(&peer_device->unacked_cnt),
		   atomic_read(&device->ap_bio_cnt[WRITE]),
		   atomic_read(&device->ap_bio_cnt[READ]),
		   peer_device->connection->epochs,
		   device->resource->write_ordering
		);
		seq_printf(m, " oos:%llu\n",
			   Bit2KB((unsigned long long)
				   drbd_bm_total_weight(peer_device)));
	}
	if (state.conn == L_SYNC_SOURCE ||
	    state.conn == L_SYNC_TARGET ||
	    state.conn == L_VERIFY_S ||
	    state.conn == L_VERIFY_T)
		drbd_syncer_progress(peer_device, m, state.conn);

	if (get_ldev_if_state(device, D_FAILED)) {
		lc_seq_printf_stats(m, device->act_log);
		put_ldev(device);
	}

	seq_printf(m, "\tblocked on activity log: %d/%d/%d\n",
		atomic_read(&device->ap_actlog_cnt),	/* requests */
		atomic_read(&device->wait_for_actlog),	/* peer_requests */
		/* nr extents needed to satisfy the above in the worst case */
		atomic_read(&device->wait_for_actlog_ecnt));

	rcu_read_unlock();

	return 0;
}

#define drbd_debugfs_peer_device_attr(name)					\
static int peer_device_ ## name ## _open(struct inode *inode, struct file *file)\
{										\
	struct drbd_peer_device *peer_device = inode->i_private;		\
	return drbd_single_open_peer_device(file,				\
					    peer_device_ ## name ## _show,	\
					    peer_device);			\
}										\
static int peer_device_ ## name ## _release(struct inode *inode, struct file *file)\
{										\
	struct drbd_peer_device *peer_device = inode->i_private;		\
	kref_put(&peer_device->connection->kref, drbd_destroy_connection);	\
	kref_put(&peer_device->device->kref, drbd_destroy_device);		\
	return single_release(inode, file);					\
}										\
static const struct file_operations peer_device_ ## name ## _fops = {		\
	.owner		= THIS_MODULE,						\
	.open		= peer_device_ ## name ## _open,			\
	.read		= seq_read,						\
	.llseek		= seq_lseek,						\
	.release	= peer_device_ ## name ## _release,			\
};

drbd_debugfs_peer_device_attr(proc_drbd)

void drbd_debugfs_peer_device_add(struct drbd_peer_device *peer_device)
{
	struct dentry *conn_dir = peer_device->connection->debugfs_conn;
	struct dentry *dentry;
	char vnr_buf[8];

	snprintf(vnr_buf, sizeof(vnr_buf), "%u", peer_device->device->vnr);
	dentry = debugfs_create_dir(vnr_buf, conn_dir);
	peer_device->debugfs_peer_dev = dentry;

	/* debugfs create file */
	peer_dev_dcf(proc_drbd);
}

void drbd_debugfs_peer_device_cleanup(struct drbd_peer_device *peer_device)
{
	drbd_debugfs_remove(&peer_device->debugfs_peer_dev_proc_drbd);
	drbd_debugfs_remove(&peer_device->debugfs_peer_dev);
}

static int drbd_version_show(struct seq_file *m, void *ignored)
{
	seq_printf(m, "# %s\n", drbd_buildtag());
	seq_printf(m, "VERSION=%s\n", REL_VERSION);
	seq_printf(m, "API_VERSION=%u\n", GENL_MAGIC_VERSION);
	seq_printf(m, "PRO_VERSION_MIN=%u\n", PRO_VERSION_MIN);
	seq_printf(m, "PRO_VERSION_MAX=%u\n", PRO_VERSION_MAX);
#ifdef UTS_RELEASE
	/* the UTS_RELEASE string of the prepared kernel source tree this
	 * module was built against */
	seq_printf(m, "UTS_RELEASE=%s\n", UTS_RELEASE);
#endif
	return 0;
}

static int drbd_version_open(struct inode *inode, struct file *file)
{
	return single_open(file, drbd_version_show, NULL);
}

static const struct file_operations drbd_version_fops = {
	.owner = THIS_MODULE,
	.open = drbd_version_open,
	.llseek = seq_lseek,
	.read = seq_read,
	.release = single_release,
};

static int drbd_refcounts_show(struct seq_file *m, void *ignored)
{
	seq_printf(m, "v: %u\n\n", 0);

	print_kref_debug_info(m);
	return 0;
}

static int drbd_refcounts_open(struct inode *inode, struct file *file)
{
	return single_open(file, drbd_refcounts_show, NULL);
}

static const struct file_operations drbd_refcounts_fops = {
	.owner = THIS_MODULE,
	.open = drbd_refcounts_open,
	.llseek = seq_lseek,
	.read = seq_read,
	.release = single_release,
};

static int drbd_compat_show(struct seq_file *m, void *ignored)
{
	return 0;
}

static int drbd_compat_open(struct inode *inode, struct file *file)
{
	return single_open(file, drbd_compat_show, NULL);
}

static const struct file_operations drbd_compat_fops = {
	.owner = THIS_MODULE,
	.open = drbd_compat_open,
	.llseek = seq_lseek,
	.read = seq_read,
	.release = single_release,
};

/* not __exit, may be indirectly called
 * from the module-load-failure path as well. */
void drbd_debugfs_cleanup(void)
{
	drbd_debugfs_remove(&drbd_debugfs_compat);
	drbd_debugfs_remove(&drbd_debugfs_resources);
	drbd_debugfs_remove(&drbd_debugfs_minors);
	drbd_debugfs_remove(&drbd_debugfs_version);
	drbd_debugfs_remove(&drbd_debugfs_refcounts);
	drbd_debugfs_remove(&drbd_debugfs_root);
}

void __init drbd_debugfs_init(void)
{
	struct dentry *dentry;

	dentry = debugfs_create_dir("drbd", NULL);
	drbd_debugfs_root = dentry;

	dentry = debugfs_create_file("version", 0444, drbd_debugfs_root, NULL, &drbd_version_fops);
	drbd_debugfs_version = dentry;

	dentry = debugfs_create_file("reference_counts", 0444, drbd_debugfs_root, NULL, &drbd_refcounts_fops);
	drbd_debugfs_refcounts = dentry;

	dentry = debugfs_create_dir("resources", drbd_debugfs_root);
	drbd_debugfs_resources = dentry;

	dentry = debugfs_create_dir("minors", drbd_debugfs_root);
	drbd_debugfs_minors = dentry;

	dentry = debugfs_create_file("compat", 0444, drbd_debugfs_root, NULL, &drbd_compat_fops);
	drbd_debugfs_compat = dentry;
}
