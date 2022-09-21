// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_state.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   Thanks to Carter Burden, Bart Grantham and Gennadiy Nerubayev
   from Logicworks, Inc. for making SDP replication support possible.

 */

#include <linux/drbd_limits.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"
#include "drbd_state_change.h"


struct after_state_change_work {
	struct drbd_work w;
	struct drbd_state_change *state_change;
	struct completion *done;
};

struct quorum_info {
	int up_to_date;
	int present;
	int voters;
	int quorum_at;
	int diskless_majority_at;
	int min_redundancy_at;
};

struct quorum_detail {
	int up_to_date;
	int present;
	int outdated;
	int diskless;
	int missing_diskless;
	int unknown;
};

struct change_context {
	struct drbd_resource *resource;
	int vnr;
	union drbd_state mask;
	union drbd_state val;
	int target_node_id;
	enum chg_state_flags flags;
	bool change_local_state_last;
	const char **err_str;
};

enum change_phase {
	PH_LOCAL_COMMIT,
	PH_PREPARE,
	PH_84_COMMIT,
	PH_COMMIT,
};

struct change_disk_state_context {
	struct change_context context;
	struct drbd_device *device;
};

static bool lost_contact_to_peer_data(enum drbd_disk_state *peer_disk_state);
static bool peer_returns_diskless(struct drbd_peer_device *peer_device,
				  enum drbd_disk_state os, enum drbd_disk_state ns);
static void print_state_change(struct drbd_resource *resource, const char *prefix);
static void finish_state_change(struct drbd_resource *);
static int w_after_state_change(struct drbd_work *w, int unused);
static enum drbd_state_rv is_valid_soft_transition(struct drbd_resource *);
static enum drbd_state_rv is_valid_transition(struct drbd_resource *resource);
static void sanitize_state(struct drbd_resource *resource);
static void ensure_exposed_data_uuid(struct drbd_device *device);
static enum drbd_state_rv change_peer_state(struct drbd_connection *, int, union drbd_state,
					    union drbd_state, unsigned long *);

/* We need to stay consistent if we are neighbor of a diskless primary with
   different UUID. This function should be used if the device was D_UP_TO_DATE
   before.
 */
static bool may_return_to_up_to_date(struct drbd_device *device, enum which_state which)
{
	struct drbd_peer_device *peer_device;
	bool rv = true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->disk_state[which] == D_DISKLESS &&
		    peer_device->connection->peer_role[which] == R_PRIMARY &&
		    peer_device->current_uuid != drbd_current_uuid(device)) {
			rv = false;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

/**
 * may_be_up_to_date()  -  check if transition from D_CONSISTENT to D_UP_TO_DATE is allowed
 *
 * When fencing is enabled, it may only transition from D_CONSISTENT to D_UP_TO_DATE
 * when ether all peers are connected, or outdated.
 */
static bool may_be_up_to_date(struct drbd_device *device, enum which_state which) __must_hold(local)
{
	bool all_peers_outdated = true;
	int node_id;

	if (!may_return_to_up_to_date(device, which))
		return false;

	rcu_read_lock();
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &device->ldev->md.peers[node_id];
		struct drbd_peer_device *peer_device;
		enum drbd_disk_state peer_disk_state;
		bool want_bitmap = true;

		if (node_id == device->ldev->md.node_id)
			continue;

		if (!(peer_md->flags & MDF_HAVE_BITMAP) && !(peer_md->flags & MDF_NODE_EXISTS))
			continue;

		if (!(peer_md->flags & MDF_PEER_FENCING))
			continue;
		peer_device = peer_device_by_node_id(device, node_id);
		if (peer_device) {
			struct peer_device_conf *pdc = rcu_dereference(peer_device->conf);
			want_bitmap = pdc->bitmap;
			peer_disk_state = peer_device->disk_state[NEW];
		} else {
			peer_disk_state = D_UNKNOWN;
		}

		switch (peer_disk_state) {
		case D_DISKLESS:
			if (!(peer_md->flags & MDF_PEER_DEVICE_SEEN))
				continue;
			fallthrough;
		case D_ATTACHING:
		case D_DETACHING:
		case D_FAILED:
		case D_NEGOTIATING:
		case D_UNKNOWN:
			if (!want_bitmap)
				continue;
			if ((peer_md->flags & MDF_PEER_OUTDATED))
				continue;
			break;
		case D_INCONSISTENT:
		case D_OUTDATED:
			continue;
		case D_CONSISTENT:
		case D_UP_TO_DATE:
			/* These states imply that there is a connection. If there is
			   a connection we do not need to insist that the peer was
			   outdated. */
			continue;
		case D_MASK: ;
		}

		all_peers_outdated = false;
	}
	rcu_read_unlock();
	return all_peers_outdated;
}

static bool stable_up_to_date_neighbor(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->disk_state[NEW] == D_UP_TO_DATE &&
		    peer_device->uuid_flags & UUID_FLAG_STABLE && /* primary is also stable */
		    peer_device->current_uuid == drbd_current_uuid(device)) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

/**
 * disk_state_from_md()  -  determine initial disk state
 *
 * When a disk is attached to a device, we set the disk state to D_NEGOTIATING.
 * We then wait for all connected peers to send the peer disk state.  Once that
 * has happened, we can determine the actual disk state based on the peer disk
 * states and the state of the disk itself.
 *
 * The initial disk state becomes D_UP_TO_DATE without fencing or when we know
 * that all peers have been outdated, and D_CONSISTENT otherwise.
 *
 * The caller either needs to have a get_ldev() reference, or need to call
 * this function only if disk_state[NOW] >= D_NEGOTIATING and holding the
 * state_rwlock.
 */
enum drbd_disk_state disk_state_from_md(struct drbd_device *device) __must_hold(local)
{
	enum drbd_disk_state disk_state;

	if (!drbd_md_test_flag(device->ldev, MDF_CONSISTENT))
		disk_state = D_INCONSISTENT;
	else if (!drbd_md_test_flag(device->ldev, MDF_WAS_UP_TO_DATE))
		disk_state = D_OUTDATED;
	else
		disk_state = may_be_up_to_date(device, NOW) ? D_UP_TO_DATE : D_CONSISTENT;

	return disk_state;
}

bool is_suspended_fen(struct drbd_resource *resource, enum which_state which)
{
	struct drbd_connection *connection;
	bool rv = false;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->susp_fen[which]) {
			rv = true;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

bool resource_is_suspended(struct drbd_resource *resource, enum which_state which)
{
	bool rv = resource->susp_user[which] || resource->susp_nod[which] ||
		resource->susp_quorum[which] ||	resource->susp_uuid[which];

	if (rv)
		return rv;

	return is_suspended_fen(resource, which);
}

static void count_objects(struct drbd_resource *resource,
			  struct drbd_state_change_object_count *ocnt)
{
	struct drbd_path *path;
	struct drbd_device *device;
	struct drbd_connection *connection;
	int vnr;

	lockdep_assert_held(&resource->state_rwlock);

	ocnt->n_devices = 0;
	ocnt->n_connections = 0;
	ocnt->n_paths = 0;

	idr_for_each_entry(&resource->devices, device, vnr)
		ocnt->n_devices++;
	for_each_connection(connection, resource) {
		ocnt->n_connections++;
		list_for_each_entry(path, &connection->transport.paths, list) {
			ocnt->n_paths++;
		}
	}
}

static struct drbd_state_change *alloc_state_change(struct drbd_state_change_object_count *ocnt, gfp_t flags)
{
	struct drbd_state_change *state_change;
	unsigned int size;

	size = sizeof(struct drbd_state_change) +
	       ocnt->n_devices * sizeof(struct drbd_device_state_change) +
	       ocnt->n_connections * sizeof(struct drbd_connection_state_change) +
	       ocnt->n_devices * ocnt->n_connections * sizeof(struct drbd_peer_device_state_change) +
	       ocnt->n_paths * sizeof(struct drbd_path_state);
	state_change = kzalloc(size, flags);
	if (!state_change)
		return NULL;
	state_change->n_connections = ocnt->n_connections;
	state_change->n_devices = ocnt->n_devices;
	state_change->n_paths = ocnt->n_paths;
	state_change->devices = (void *)(state_change + 1);
	state_change->connections = (void *)&state_change->devices[ocnt->n_devices];
	state_change->peer_devices = (void *)&state_change->connections[ocnt->n_connections];
	state_change->paths = (void*)&state_change->peer_devices[ocnt->n_devices*ocnt->n_connections];
	return state_change;
}

struct drbd_state_change *remember_state_change(struct drbd_resource *resource, gfp_t gfp)
{
	struct drbd_state_change *state_change;
	struct drbd_device *device;
	struct drbd_connection *connection;
	struct drbd_state_change_object_count ocnt;
	int vnr;

	struct drbd_device_state_change *device_state_change;
	struct drbd_peer_device_state_change *peer_device_state_change;
	struct drbd_connection_state_change *connection_state_change;
	struct drbd_path_state *path_state; /* yes, not a _change :-( */

	lockdep_assert_held(&resource->state_rwlock);

	count_objects(resource, &ocnt);
	state_change = alloc_state_change(&ocnt, gfp);
	if (!state_change)
		return NULL;

	kref_get(&resource->kref);
	kref_debug_get(&resource->kref_debug, 5);
	state_change->resource->resource = resource;
	memcpy(state_change->resource->role,
	       resource->role, sizeof(resource->role));
	memcpy(state_change->resource->susp,
	       resource->susp_user, sizeof(resource->susp_user));
	memcpy(state_change->resource->susp_nod,
	       resource->susp_nod, sizeof(resource->susp_nod));
	memcpy(state_change->resource->susp_uuid,
	       resource->susp_uuid, sizeof(resource->susp_uuid));
	memcpy(state_change->resource->fail_io,
	       resource->fail_io, sizeof(resource->fail_io));

	device_state_change = state_change->devices;
	peer_device_state_change = state_change->peer_devices;
	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;

		kref_get(&device->kref);
		kref_debug_get(&device->kref_debug, 2);
		device_state_change->device = device;
		memcpy(device_state_change->disk_state,
		       device->disk_state, sizeof(device->disk_state));
		memcpy(device_state_change->have_quorum,
		       device->have_quorum, sizeof(device->have_quorum));

		/* The peer_devices for each device have to be enumerated in
		   the order of the connections. We may not use for_each_peer_device() here. */
		for_each_connection(connection, resource) {
			peer_device = conn_peer_device(connection, device->vnr);

			peer_device_state_change->peer_device = peer_device;
			memcpy(peer_device_state_change->disk_state,
			       peer_device->disk_state, sizeof(peer_device->disk_state));
			memcpy(peer_device_state_change->repl_state,
			       peer_device->repl_state, sizeof(peer_device->repl_state));
			memcpy(peer_device_state_change->resync_susp_user,
			       peer_device->resync_susp_user,
			       sizeof(peer_device->resync_susp_user));
			memcpy(peer_device_state_change->resync_susp_peer,
			       peer_device->resync_susp_peer,
			       sizeof(peer_device->resync_susp_peer));
			memcpy(peer_device_state_change->resync_susp_dependency,
			       peer_device->resync_susp_dependency,
			       sizeof(peer_device->resync_susp_dependency));
			memcpy(peer_device_state_change->resync_susp_other_c,
			       peer_device->resync_susp_other_c,
			       sizeof(peer_device->resync_susp_other_c));
			memcpy(peer_device_state_change->resync_active,
			       peer_device->resync_active,
			       sizeof(peer_device->resync_active));
			peer_device_state_change++;
		}
		device_state_change++;
	}

	connection_state_change = state_change->connections;
	path_state = state_change->paths;
	for_each_connection(connection, resource) {
		struct drbd_path *path;

		kref_get(&connection->kref);
		kref_debug_get(&connection->kref_debug, 7);
		connection_state_change->connection = connection;
		memcpy(connection_state_change->cstate,
		       connection->cstate, sizeof(connection->cstate));
		memcpy(connection_state_change->peer_role,
		       connection->peer_role, sizeof(connection->peer_role));
		memcpy(connection_state_change->susp_fen,
		       connection->susp_fen, sizeof(connection->susp_fen));

		list_for_each_entry(path, &connection->transport.paths, list) {
			/* Share the connection kref with above.
			 * Could also share the pointer, but would then need to
			 * remember an additional n_paths per connection
			 * count/offset (connection_state_change->n_paths++)
			 * to be able to associate the paths with its connection.
			 * So why not directly store the pointer here again. */
			path_state->connection = connection;
			kref_get(&path->kref);
			path_state->path = path;
			path_state->path_established = path->established;

			path_state++;
		}

		connection_state_change++;
	}

	return state_change;
}

void copy_old_to_new_state_change(struct drbd_state_change *state_change)
{
	struct drbd_resource_state_change *resource_state_change = &state_change->resource[0];
	unsigned int n_device, n_connection, n_peer_device, n_peer_devices;

#define OLD_TO_NEW(x) \
	(x[NEW] = x[OLD])

	OLD_TO_NEW(resource_state_change->role);
	OLD_TO_NEW(resource_state_change->susp);
	OLD_TO_NEW(resource_state_change->susp_nod);
	OLD_TO_NEW(resource_state_change->susp_uuid);
	OLD_TO_NEW(resource_state_change->fail_io);

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change =
				&state_change->connections[n_connection];

		OLD_TO_NEW(connection_state_change->peer_role);
		OLD_TO_NEW(connection_state_change->cstate);
		OLD_TO_NEW(connection_state_change->susp_fen);
	}

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_device_state_change *device_state_change =
			&state_change->devices[n_device];

		OLD_TO_NEW(device_state_change->disk_state);
		OLD_TO_NEW(device_state_change->have_quorum);
	}

	n_peer_devices = state_change->n_devices * state_change->n_connections;
	for (n_peer_device = 0; n_peer_device < n_peer_devices; n_peer_device++) {
		struct drbd_peer_device_state_change *p =
			&state_change->peer_devices[n_peer_device];

		OLD_TO_NEW(p->disk_state);
		OLD_TO_NEW(p->repl_state);
		OLD_TO_NEW(p->resync_susp_user);
		OLD_TO_NEW(p->resync_susp_peer);
		OLD_TO_NEW(p->resync_susp_dependency);
		OLD_TO_NEW(p->resync_susp_other_c);
		OLD_TO_NEW(p->resync_active);
	}

#undef OLD_TO_NEW
}

void forget_state_change(struct drbd_state_change *state_change)
{
	unsigned int n;

	if (!state_change)
		return;

	if (state_change->resource->resource) {
		kref_debug_put(&state_change->resource->resource->kref_debug, 5);
		kref_put(&state_change->resource->resource->kref, drbd_destroy_resource);
	}
	for (n = 0; n < state_change->n_devices; n++) {
		struct drbd_device *device = state_change->devices[n].device;

		if (device) {
			kref_debug_put(&device->kref_debug, 2);
			kref_put(&device->kref, drbd_destroy_device);
		}
	}
	for (n = 0; n < state_change->n_connections; n++) {
		struct drbd_connection *connection =
			state_change->connections[n].connection;

		if (connection) {
			kref_debug_put(&connection->kref_debug, 7);
			kref_put(&connection->kref, drbd_destroy_connection);
		}
	}
	for (n = 0; n < state_change->n_paths; n++) {
		struct drbd_path *path = state_change->paths[n].path;
		if (path) {
			kref_put(&path->kref, drbd_destroy_path);
		}
	}
	kfree(state_change);
}

static bool state_has_changed(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	struct drbd_device *device;
	int vnr;

	if (resource->state_change_flags & CS_FORCE_RECALC)
		return true;

	if (resource->role[OLD] != resource->role[NEW] ||
	    resource->susp_user[OLD] != resource->susp_user[NEW] ||
	    resource->susp_nod[OLD] != resource->susp_nod[NEW] ||
	    resource->susp_quorum[OLD] != resource->susp_quorum[NEW] ||
	    resource->susp_uuid[OLD] != resource->susp_uuid[NEW] ||
	    resource->fail_io[OLD] != resource->fail_io[NEW])
		return true;

	for_each_connection(connection, resource) {
		if (connection->cstate[OLD] != connection->cstate[NEW] ||
		    connection->peer_role[OLD] != connection->peer_role[NEW] ||
		    connection->susp_fen[OLD] != connection->susp_fen[NEW])
			return true;
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;

		if (device->disk_state[OLD] != device->disk_state[NEW] ||
		    device->have_quorum[OLD] != device->have_quorum[NEW])
			return true;

		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[OLD] != peer_device->disk_state[NEW] ||
			    peer_device->repl_state[OLD] != peer_device->repl_state[NEW] ||
			    peer_device->resync_susp_user[OLD] !=
				peer_device->resync_susp_user[NEW] ||
			    peer_device->resync_susp_peer[OLD] !=
				peer_device->resync_susp_peer[NEW] ||
			    peer_device->resync_susp_dependency[OLD] !=
				peer_device->resync_susp_dependency[NEW] ||
			    peer_device->resync_susp_other_c[OLD] !=
				peer_device->resync_susp_other_c[NEW] ||
			    peer_device->resync_active[OLD] !=
				peer_device->resync_active[NEW] ||
			    peer_device->uuid_flags & UUID_FLAG_GOT_STABLE)
				return true;
		}
	}
	return false;
}

static void ___begin_state_change(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	struct drbd_device *device;
	int vnr;

	resource->role[NEW] = resource->role[NOW];
	resource->susp_user[NEW] = resource->susp_user[NOW];
	resource->susp_nod[NEW] = resource->susp_nod[NOW];
	resource->susp_quorum[NEW] = resource->susp_quorum[NOW];
	resource->susp_uuid[NEW] = resource->susp_uuid[NOW];
	resource->fail_io[NEW] = resource->fail_io[NOW];

	for_each_connection_rcu(connection, resource) {
		connection->cstate[NEW] = connection->cstate[NOW];
		connection->peer_role[NEW] = connection->peer_role[NOW];
		connection->susp_fen[NEW] = connection->susp_fen[NOW];
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;

		device->disk_state[NEW] = device->disk_state[NOW];
		device->have_quorum[NEW] = device->have_quorum[NOW];

		for_each_peer_device_rcu(peer_device, device) {
			peer_device->disk_state[NEW] = peer_device->disk_state[NOW];
			peer_device->repl_state[NEW] = peer_device->repl_state[NOW];
			peer_device->resync_susp_user[NEW] =
				peer_device->resync_susp_user[NOW];
			peer_device->resync_susp_peer[NEW] =
				peer_device->resync_susp_peer[NOW];
			peer_device->resync_susp_dependency[NEW] =
				peer_device->resync_susp_dependency[NOW];
			peer_device->resync_susp_other_c[NEW] =
				peer_device->resync_susp_other_c[NOW];
			peer_device->resync_active[NEW] =
				peer_device->resync_active[NOW];
		}
	}
}

static void __begin_state_change(struct drbd_resource *resource)
{
	rcu_read_lock();
	___begin_state_change(resource);
}

static enum drbd_state_rv try_state_change(struct drbd_resource *resource)
{
	enum drbd_state_rv rv;

	if (!state_has_changed(resource))
		return SS_NOTHING_TO_DO;
	sanitize_state(resource);
	rv = is_valid_transition(resource);
	if (rv >= SS_SUCCESS && !(resource->state_change_flags & CS_HARD))
		rv = is_valid_soft_transition(resource);
	return rv;
}

static void apply_update_to_exposed_data_uuid(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	idr_for_each_entry(&resource->devices, device, vnr) {
		u64 nedu = device->next_exposed_data_uuid;
		int changed = 0;

		if (!nedu)
			continue;
		if (device->disk_state[NOW] < D_INCONSISTENT)
			changed = drbd_set_exposed_data_uuid(device, nedu);

		device->next_exposed_data_uuid = 0;
		if (changed)
			drbd_info(device, "Executing delayed exposed data uuid update: %016llX\n",
				  (unsigned long long)device->exposed_data_uuid);
		else
			drbd_info(device, "Canceling delayed exposed data uuid update\n");
	}
}

void __clear_remote_state_change(struct drbd_resource *resource)
{
	struct drbd_connection *connection, *tmp;
	bool is_connect = resource->twopc_reply.is_connect;
	int initiator_node_id = resource->twopc_reply.initiator_node_id;

	resource->remote_state_change = false;
	resource->twopc_reply.initiator_node_id = -1;
	resource->twopc_reply.tid = 0;

	list_for_each_entry_safe(connection, tmp, &resource->twopc_parents, twopc_parent_list) {
		if (is_connect && connection->peer_node_id == initiator_node_id)
			abort_connect(connection);
		kref_debug_put(&connection->kref_debug, 9);
		kref_put(&connection->kref, drbd_destroy_connection);
	}
	INIT_LIST_HEAD(&resource->twopc_parents);

	wake_up(&resource->twopc_wait);

	/* Do things that where postponed to after two-phase commits finished */
	apply_update_to_exposed_data_uuid(resource);
}

static bool state_is_stable(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool stable = true;

	/* DO NOT add a default clause, we want the compiler to warn us
	 * for any newly introduced state we may have forgotten to add here */

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		switch (peer_device->repl_state[NOW]) {
		/* New io is only accepted when the peer device is unknown or there is
		 * a well-established connection. */
		case L_OFF:
		case L_ESTABLISHED:
		case L_SYNC_SOURCE:
		case L_SYNC_TARGET:
		case L_VERIFY_S:
		case L_VERIFY_T:
		case L_PAUSED_SYNC_S:
		case L_PAUSED_SYNC_T:
		case L_AHEAD:
		case L_BEHIND:
		case L_STARTING_SYNC_S:
		case L_STARTING_SYNC_T:
			break;

			/* Allow IO in BM exchange states with new protocols */
		case L_WF_BITMAP_S:
			if (peer_device->connection->agreed_pro_version < 96)
				stable = false;
			break;

			/* no new io accepted in these states */
		case L_WF_BITMAP_T:
		case L_WF_SYNC_UUID:
			stable = false;
			break;
		}
		if (!stable)
			break;
	}
	rcu_read_unlock();

	switch (device->disk_state[NOW]) {
	case D_DISKLESS:
	case D_INCONSISTENT:
	case D_OUTDATED:
	case D_CONSISTENT:
	case D_UP_TO_DATE:
	case D_FAILED:
	case D_DETACHING:
		/* disk state is stable as well. */
		break;

	/* no new io accepted during transitional states */
	case D_ATTACHING:
	case D_NEGOTIATING:
	case D_UNKNOWN:
	case D_MASK:
		stable = false;
	}

	return stable;
}

static struct after_state_change_work *alloc_after_state_change_work(struct drbd_resource *resource)
{
	struct after_state_change_work *work;

	lockdep_assert_held(&resource->state_rwlock);

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (work) {
		work->state_change = remember_state_change(resource, GFP_ATOMIC);
		if (!work->state_change) {
			kfree(work);
			work = NULL;
		}
	}
	if (!work)
		drbd_err(resource, "Could not allocate after state change work\n");

	return work;
}

static void queue_after_state_change_work(struct drbd_resource *resource,
					  struct completion *done,
					  struct after_state_change_work *work)
{
	if (work) {
		work->w.cb = w_after_state_change;
		work->done = done;
		drbd_queue_work(&resource->work, &work->w);
	} else if (done) {
		complete(done);
	}
}

static enum drbd_state_rv ___end_state_change(struct drbd_resource *resource, struct completion *done,
					      enum drbd_state_rv rv)
{
	enum chg_state_flags flags = resource->state_change_flags;
	struct drbd_connection *connection;
	struct drbd_device *device;
	unsigned int pro_ver;
	int vnr;
	bool all_devs_have_quorum = true;
	struct after_state_change_work *work;

	if (flags & CS_ABORT)
		goto out;
	if (rv >= SS_SUCCESS)
		rv = try_state_change(resource);
	if (rv < SS_SUCCESS) {
		if (flags & CS_VERBOSE) {
			drbd_err(resource, "State change failed: %s\n", drbd_set_st_err_str(rv));
			print_state_change(resource, "Failed: ");
		}
		goto out;
	}
	if (flags & CS_PREPARE)
		goto out;

	finish_state_change(resource);

	/* This remembers the state change, so call before applying the change. */
	work = alloc_after_state_change_work(resource);

	/* changes to local_cnt and device flags should be visible before
	 * changes to state, which again should be visible before anything else
	 * depending on that change happens. */
	smp_wmb();
	resource->role[NOW] = resource->role[NEW];
	resource->susp_user[NOW] = resource->susp_user[NEW];
	resource->susp_nod[NOW] = resource->susp_nod[NEW];
	resource->susp_quorum[NOW] = resource->susp_quorum[NEW];
	resource->susp_uuid[NOW] = resource->susp_uuid[NEW];
	resource->fail_io[NOW] = resource->fail_io[NEW];
	resource->cached_susp = resource_is_suspended(resource, NEW);

	pro_ver = PRO_VERSION_MAX;
	for_each_connection(connection, resource) {
		connection->cstate[NOW] = connection->cstate[NEW];
		connection->peer_role[NOW] = connection->peer_role[NEW];
		connection->susp_fen[NOW] = connection->susp_fen[NEW];

		pro_ver = min_t(unsigned int, pro_ver,
			connection->agreed_pro_version);

		wake_up(&connection->ee_wait);
	}
	resource->cached_min_aggreed_protocol_version = pro_ver;

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct res_opts *o = &resource->res_opts;
		struct drbd_peer_device *peer_device;

		device->disk_state[NOW] = device->disk_state[NEW];
		device->have_quorum[NOW] = device->have_quorum[NEW];

		if (!device->have_quorum[NOW])
			all_devs_have_quorum = false;

		for_each_peer_device(peer_device, device) {
			peer_device->disk_state[NOW] = peer_device->disk_state[NEW];
			peer_device->repl_state[NOW] = peer_device->repl_state[NEW];
			peer_device->resync_susp_user[NOW] =
				peer_device->resync_susp_user[NEW];
			peer_device->resync_susp_peer[NOW] =
				peer_device->resync_susp_peer[NEW];
			peer_device->resync_susp_dependency[NOW] =
				peer_device->resync_susp_dependency[NEW];
			peer_device->resync_susp_other_c[NOW] =
				peer_device->resync_susp_other_c[NEW];
			peer_device->resync_active[NOW] =
				peer_device->resync_active[NEW];
		}
		device->cached_state_unstable = !state_is_stable(device);
		device->cached_err_io =
			(o->on_no_quorum == ONQ_IO_ERROR && !device->have_quorum[NOW]) ||
			(o->on_no_data == OND_IO_ERROR && !drbd_data_accessible(device, NOW)) ||
			resource->fail_io[NEW];
	}
	resource->cached_all_devices_have_quorum = all_devs_have_quorum;
	smp_wmb(); /* Make the NEW_CUR_UUID bit visible after the state change! */

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;
		if (test_bit(__NEW_CUR_UUID, &device->flags)) {
			clear_bit(__NEW_CUR_UUID, &device->flags);
			set_bit(NEW_CUR_UUID, &device->flags);
		}

		wake_up(&device->al_wait);
		wake_up(&device->misc_wait);

		for_each_peer_device(peer_device, device) {
			if (test_and_clear_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags))
				up_read_non_owner(&device->uuid_sem);
		}
	}

	wake_up_all(&resource->state_wait);

	/* Call this after applying the state change from NEW to NOW. */
	queue_after_state_change_work(resource, done, work);
out:
	rcu_read_unlock();

	if ((flags & CS_TWOPC) && !(flags & CS_PREPARE))
		__clear_remote_state_change(resource);

	resource->state_change_err_str = NULL;
	return rv;
}

void state_change_lock(struct drbd_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	if ((flags & CS_SERIALIZE) && !(flags & (CS_ALREADY_SERIALIZED | CS_PREPARED))) {
		WARN_ONCE(current == resource->worker.task,
			"worker should not initiate state changes with CS_SERIALIZE\n");
		down(&resource->state_sem);
	}
	write_lock_irqsave(&resource->state_rwlock, *irq_flags);
	resource->state_change_flags = flags;
}

static void __state_change_unlock(struct drbd_resource *resource, unsigned long *irq_flags, struct completion *done)
{
	enum chg_state_flags flags = resource->state_change_flags;

	resource->state_change_flags = 0;
	write_unlock_irqrestore(&resource->state_rwlock, *irq_flags);
	if (done && expect(resource, current != resource->worker.task))
		wait_for_completion(done);
	if ((flags & CS_SERIALIZE) && !(flags & (CS_ALREADY_SERIALIZED | CS_PREPARE)))
		up(&resource->state_sem);
}

void state_change_unlock(struct drbd_resource *resource, unsigned long *irq_flags)
{
	__state_change_unlock(resource, irq_flags, NULL);
}

/**
 * abort_prepared_state_change
 *
 * Use when a remote state change request was prepared but neither committed
 * nor aborted; the remote state change still "holds the state mutex".
 */
void abort_prepared_state_change(struct drbd_resource *resource)
{
	up(&resource->state_sem);
}

void begin_state_change_locked(struct drbd_resource *resource, enum chg_state_flags flags)
{
	BUG_ON(flags & (CS_SERIALIZE | CS_WAIT_COMPLETE | CS_PREPARE | CS_ABORT));
	resource->state_change_flags = flags;
	__begin_state_change(resource);
}

enum drbd_state_rv end_state_change_locked(struct drbd_resource *resource)
{
	return ___end_state_change(resource, NULL, SS_SUCCESS);
}

void begin_state_change(struct drbd_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	state_change_lock(resource, irq_flags, flags);
	__begin_state_change(resource);
}

static enum drbd_state_rv __end_state_change(struct drbd_resource *resource,
					     unsigned long *irq_flags,
					     enum drbd_state_rv rv)
{
	enum chg_state_flags flags = resource->state_change_flags;
	struct completion __done, *done = NULL;

	if ((flags & CS_WAIT_COMPLETE) && !(flags & (CS_PREPARE | CS_ABORT))) {
		done = &__done;
		init_completion(done);
	}
	rv = ___end_state_change(resource, done, rv);
	__state_change_unlock(resource, irq_flags, rv >= SS_SUCCESS ? done : NULL);
	return rv;
}

enum drbd_state_rv end_state_change(struct drbd_resource *resource, unsigned long *irq_flags)
{
	return __end_state_change(resource, irq_flags, SS_SUCCESS);
}

void abort_state_change(struct drbd_resource *resource, unsigned long *irq_flags)
{
	resource->state_change_flags &= ~CS_VERBOSE;
	__end_state_change(resource, irq_flags, SS_UNKNOWN_ERROR);
}

void abort_state_change_locked(struct drbd_resource *resource)
{
	resource->state_change_flags &= ~CS_VERBOSE;
	___end_state_change(resource, NULL, SS_UNKNOWN_ERROR);
}

static void begin_remote_state_change(struct drbd_resource *resource, unsigned long *irq_flags)
{
	rcu_read_unlock();
	write_unlock_irqrestore(&resource->state_rwlock, *irq_flags);
}

static void __end_remote_state_change(struct drbd_resource *resource, enum chg_state_flags flags)
{
	rcu_read_lock();
	resource->state_change_flags = flags;
	___begin_state_change(resource);
}

static void end_remote_state_change(struct drbd_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	write_lock_irqsave(&resource->state_rwlock, *irq_flags);
	__end_remote_state_change(resource, flags);
}

void clear_remote_state_change(struct drbd_resource *resource) {
	unsigned long irq_flags;

	write_lock_irqsave(&resource->state_rwlock, irq_flags);
	__clear_remote_state_change(resource);
	write_unlock_irqrestore(&resource->state_rwlock, irq_flags);
}

static union drbd_state drbd_get_resource_state(struct drbd_resource *resource, enum which_state which)
{
	union drbd_state rv = { {
		.conn = C_STANDALONE,  /* really: undefined */
		/* (user_isp, peer_isp, and aftr_isp are undefined as well.) */
		.disk = D_UNKNOWN,  /* really: undefined */
		.role = resource->role[which],
		.peer = R_UNKNOWN,  /* really: undefined */
		.susp = resource->susp_user[which] || resource->susp_quorum[which] || resource->susp_uuid[which],
		.susp_nod = resource->susp_nod[which],
		.susp_fen = is_suspended_fen(resource, which),
		.pdsk = D_UNKNOWN,  /* really: undefined */
	} };

	return rv;
}

union drbd_state drbd_get_device_state(struct drbd_device *device, enum which_state which)
{
	union drbd_state rv = drbd_get_resource_state(device->resource, which);

	rv.disk = device->disk_state[which];
	rv.quorum = device->have_quorum[which];

	return rv;
}

union drbd_state drbd_get_peer_device_state(struct drbd_peer_device *peer_device, enum which_state which)
{
	struct drbd_connection *connection = peer_device->connection;
	union drbd_state rv;

	rv = drbd_get_device_state(peer_device->device, which);
	rv.user_isp = peer_device->resync_susp_user[which];
	rv.peer_isp = peer_device->resync_susp_peer[which];
	rv.aftr_isp = resync_susp_comb_dep(peer_device, which);
	rv.conn = combined_conn_state(peer_device, which);
	rv.peer = connection->peer_role[which];
	rv.pdsk = peer_device->disk_state[which];

	return rv;
}

union drbd_state drbd_get_connection_state(struct drbd_connection *connection, enum which_state which)
{
	union drbd_state rv = drbd_get_resource_state(connection->resource, which);

	rv.conn = connection->cstate[which];
	rv.peer = connection->peer_role[which];

	return rv;
}

enum drbd_disk_state conn_highest_disk(struct drbd_connection *connection)
{
	enum drbd_disk_state disk_state = D_DISKLESS;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		disk_state = max_t(enum drbd_disk_state, disk_state, device->disk_state[NOW]);
	}
	rcu_read_unlock();

	return disk_state;
}

enum drbd_disk_state conn_highest_pdsk(struct drbd_connection *connection)
{
	enum drbd_disk_state disk_state = D_DISKLESS;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
		disk_state = max_t(enum drbd_disk_state, disk_state, peer_device->disk_state[NOW]);
	rcu_read_unlock();

	return disk_state;
}

static bool suspend_reason_changed(struct drbd_resource *resource)
{
	return resource->susp_user[OLD] != resource->susp_user[NEW] ||
		resource->susp_nod[OLD] != resource->susp_nod[NEW] ||
		resource->susp_quorum[OLD] != resource->susp_quorum[NEW] ||
		resource->susp_uuid[OLD] != resource->susp_uuid[NEW] ||
		is_suspended_fen(resource, OLD) != is_suspended_fen(resource, NEW);
}

static bool resync_suspended(struct drbd_peer_device *peer_device, enum which_state which)
{
	return peer_device->resync_susp_user[which] ||
	       peer_device->resync_susp_peer[which] ||
	       resync_susp_comb_dep(peer_device, which);
}

static int scnprintf_resync_suspend_flags(char *buffer, size_t size,
					  struct drbd_peer_device *peer_device,
					  enum which_state which)
{
	struct drbd_device *device = peer_device->device;
	char *b = buffer, *end = buffer + size;

	if (!resync_suspended(peer_device, which))
		return scnprintf(buffer, size, "no");

	if (peer_device->resync_susp_user[which])
		b += scnprintf(b, end - b, "user,");
	if (peer_device->resync_susp_peer[which])
		b += scnprintf(b, end - b, "peer,");
	if (peer_device->resync_susp_dependency[which])
		b += scnprintf(b, end - b, "after dependency,");
	if (peer_device->resync_susp_other_c[which])
		b += scnprintf(b, end - b, "connection dependency,");
	if (is_sync_source_state(peer_device, which) && device->disk_state[which] <= D_INCONSISTENT)
		b += scnprintf(b, end - b, "disk inconsistent,");

	*(--b) = 0;

	return b - buffer;
}

static int scnprintf_io_suspend_flags(char *buffer, size_t size,
				      struct drbd_resource *resource,
				      enum which_state which)
{
	char *b = buffer, *end = buffer + size;

	if (!resource_is_suspended(resource, which))
		return scnprintf(buffer, size, "no");

	if (resource->susp_user[which])
		b += scnprintf(b, end - b, "user,");
	if (resource->susp_nod[which])
		b += scnprintf(b, end - b, "no-disk,");
	if (is_suspended_fen(resource, which))
		b += scnprintf(b, end - b, "fencing,");
	if (resource->susp_quorum[which])
		b += scnprintf(b, end - b, "quorum,");
	if (resource->susp_uuid[which])
		b += scnprintf(b, end - b, "uuid,");
	*(--b) = 0;

	return b - buffer;
}

static void print_state_change(struct drbd_resource *resource, const char *prefix)
{
	char buffer[150], *b, *end = buffer + sizeof(buffer);
	struct drbd_connection *connection;
	struct drbd_device *device;
	enum drbd_role *role = resource->role;
	bool *fail_io = resource->fail_io;
	int vnr;

	b = buffer;
	if (role[OLD] != role[NEW])
		b += scnprintf(b, end - b, "role( %s -> %s ) ",
			       drbd_role_str(role[OLD]),
			       drbd_role_str(role[NEW]));
	if (suspend_reason_changed(resource)) {
		b += scnprintf(b, end - b, "susp-io( ");
		b += scnprintf_io_suspend_flags(b, end - b, resource, OLD);
		b += scnprintf(b, end - b, " -> ");
		b += scnprintf_io_suspend_flags(b, end - b, resource, NEW);
		b += scnprintf(b, end - b, " ) ");
	}
	if (fail_io[OLD] != fail_io[NEW])
		b += scnprintf(b, end - b, "force-io-failures( %s -> %s ) ",
			       fail_io[OLD] ? "yes" : "no",
			       fail_io[NEW] ? "yes" : "no");
	if (b != buffer) {
		*(b-1) = 0;
		drbd_info(resource, "%s%s\n", prefix, buffer);
	}

	for_each_connection(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;
		enum drbd_role *peer_role = connection->peer_role;

		b = buffer;
		if (cstate[OLD] != cstate[NEW])
			b += scnprintf(b, end - b, "conn( %s -> %s ) ",
				       drbd_conn_str(cstate[OLD]),
				       drbd_conn_str(cstate[NEW]));
		if (peer_role[OLD] != peer_role[NEW])
			b += scnprintf(b, end - b, "peer( %s -> %s ) ",
				       drbd_role_str(peer_role[OLD]),
				       drbd_role_str(peer_role[NEW]));

		if (b != buffer) {
			*(b-1) = 0;
			drbd_info(connection, "%s%s\n", prefix, buffer);
		}
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;
		enum drbd_disk_state *disk_state = device->disk_state;
		bool *have_quorum = device->have_quorum;

		b = buffer;
		if (disk_state[OLD] != disk_state[NEW])
			b += scnprintf(b, end - b, "disk( %s -> %s ) ",
				       drbd_disk_str(disk_state[OLD]),
				       drbd_disk_str(disk_state[NEW]));
		if (have_quorum[OLD] != have_quorum[NEW])
			b += scnprintf(b, end - b, "quorum( %s -> %s ) ",
				       have_quorum[OLD] ? "yes" : "no",
				       have_quorum[NEW] ? "yes" : "no");
		if (b != buffer) {
			*(b-1) = 0;
			drbd_info(device, "%s%s\n", prefix, buffer);
		}

		for_each_peer_device(peer_device, device) {
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			enum drbd_repl_state *repl_state = peer_device->repl_state;

			b = buffer;
			if (peer_disk_state[OLD] != peer_disk_state[NEW])
				b += scnprintf(b, end - b, "pdsk( %s -> %s ) ",
					       drbd_disk_str(peer_disk_state[OLD]),
					       drbd_disk_str(peer_disk_state[NEW]));
			if (repl_state[OLD] != repl_state[NEW])
				b += scnprintf(b, end - b, "repl( %s -> %s ) ",
					       drbd_repl_str(repl_state[OLD]),
					       drbd_repl_str(repl_state[NEW]));

			if (resync_suspended(peer_device, OLD) !=
			    resync_suspended(peer_device, NEW)) {
				b += scnprintf(b, end - b, "resync-susp( ");
				b += scnprintf_resync_suspend_flags(b, end - b, peer_device, OLD);
				b += scnprintf(b, end - b, " -> ");
				b += scnprintf_resync_suspend_flags(b, end - b, peer_device, NEW);
				b += scnprintf(b, end - b, " ) ");
			}

			if (b != buffer) {
				*(b-1) = 0;
				drbd_info(peer_device, "%s%s\n", prefix, buffer);
			}
		}
	}
}

static bool local_disk_may_be_outdated(struct drbd_device *device, enum which_state which)
{
	struct drbd_peer_device *peer_device;

	if (device->resource->role[which] == R_PRIMARY) {
		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[which] == D_UP_TO_DATE &&
			    peer_device->repl_state[which] == L_WF_BITMAP_T)
				return true;
		}
		return false;
	}

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->peer_role[which] == R_PRIMARY &&
		    peer_device->repl_state[which] > L_OFF)
			goto have_primary_neighbor;
	}

	return true;	/* No neighbor primary, I might be outdated*/

have_primary_neighbor:
	for_each_peer_device(peer_device, device) {
		enum drbd_repl_state repl_state = peer_device->repl_state[which];
		switch(repl_state) {
		case L_WF_BITMAP_S:
		case L_STARTING_SYNC_S:
		case L_SYNC_SOURCE:
		case L_PAUSED_SYNC_S:
		case L_AHEAD:
		case L_ESTABLISHED:
		case L_VERIFY_S:
		case L_VERIFY_T:
		case L_OFF:
			continue;
		case L_WF_SYNC_UUID:
		case L_WF_BITMAP_T:
		case L_STARTING_SYNC_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
		case L_BEHIND:
			return true;
		}
	}

	return false;
}

static int calc_quorum_at(s32 setting, int voters)
{
	int quorum_at;

	switch (setting) {
	case QOU_MAJORITY:
		quorum_at = voters / 2 + 1;
		break;
	case QOU_ALL:
		quorum_at = voters;
		break;
	default:
		quorum_at = setting;
	}

	return quorum_at;
}

static void __calc_quorum_with_disk(struct drbd_device *device, struct quorum_detail *qd)
{
	const int my_node_id = device->resource->res_opts.node_id;
	int node_id, up_to_date = 0, present = 0, outdated = 0, diskless = 0;
	int missing_diskless = 0, unknown = 0;

	rcu_read_lock();
	for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
		struct drbd_peer_md *peer_md = &device->ldev->md.peers[node_id];
		struct drbd_peer_device *peer_device;
		enum drbd_disk_state disk_state;
		enum drbd_repl_state repl_state;
		bool is_intentional_diskless;
		struct net_conf *nc;

		if (node_id == my_node_id) {
			disk_state = device->disk_state[NEW];
			if (disk_state > D_DISKLESS) {
				if (disk_state == D_UP_TO_DATE)
					up_to_date++;
				else
					present++;
			}
			continue;
		}

		peer_device = peer_device_by_node_id(device, node_id);
		is_intentional_diskless = peer_device && !want_bitmap(peer_device);

		if (peer_device) {
			nc = rcu_dereference(peer_device->connection->transport.net_conf);
			if (nc && !nc->allow_remote_read) {
				dynamic_drbd_dbg(peer_device,
						 "Excluding from quorum calculation because allow-remote-read = no\n");
				continue;
			}
		}

		if (!(peer_md->flags & MDF_HAVE_BITMAP) && !(peer_md->flags & MDF_NODE_EXISTS) &&
		    !is_intentional_diskless) {
			continue;
		}

		if (!(peer_md->flags & MDF_PEER_DEVICE_SEEN) && !is_intentional_diskless)
			continue;

		repl_state = peer_device ? peer_device->repl_state[NEW] : L_OFF;
		disk_state = peer_device ? peer_device->disk_state[NEW] : D_UNKNOWN;

		if (repl_state == L_OFF) {
			if (is_intentional_diskless)
				/* device should be diskless but is absent */
				missing_diskless++;
			else if (disk_state <= D_OUTDATED || peer_md->flags & MDF_PEER_OUTDATED)
				outdated++;
			else
				unknown++;
		} else {
			if (disk_state == D_DISKLESS && is_intentional_diskless)
				diskless++;
			else if (disk_state == D_UP_TO_DATE)
				up_to_date++;
			else
				present++;
		}
	}
	rcu_read_unlock();

	qd->up_to_date = up_to_date;
	qd->present = present;
	qd->outdated = outdated;
	qd->diskless = diskless;
	qd->missing_diskless = missing_diskless;
	qd->unknown = unknown;
}

static void __calc_quorum_no_disk(struct drbd_device *device, struct quorum_detail *qd)
{
	int up_to_date = 0, present = 0, outdated = 0, unknown = 0, diskless = 0;
	int missing_diskless = 0;
	bool is_intentional_diskless;
	struct drbd_peer_device *peer_device;

	if (device->disk_state[NEW] == D_DISKLESS) {
		/* We only want to consider ourselves as a diskless node when
		 * we actually intended to be diskless in the config. Otherwise,
		 * we shouldn't get a vote in the quorum process, so count
		 * ourselves as unknown. */
		if (device->device_conf.intentional_diskless)
			diskless++;
		else
			unknown++;
	}

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_disk_state disk_state;
		enum drbd_repl_state repl_state;
		struct net_conf *nc;

		repl_state = peer_device->repl_state[NEW];
		disk_state = peer_device->disk_state[NEW];

		is_intentional_diskless = !want_bitmap(peer_device);
		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		if (nc && !nc->allow_remote_read) {
			dynamic_drbd_dbg(peer_device,
					 "Excluding from quorum calculation because allow-remote-read = no\n");
			continue;
		}

		if (repl_state == L_OFF) {
			if (is_intentional_diskless)
				/* device should be diskless but is absent */
				missing_diskless++;
			else if (disk_state <= D_OUTDATED)
				outdated++;
			else
				unknown++;
		} else {
			if (disk_state == D_DISKLESS && is_intentional_diskless)
				diskless++;
			else if (disk_state == D_UP_TO_DATE)
				up_to_date++;
			else
				present++;
		}

	}
	rcu_read_unlock();

	qd->up_to_date = up_to_date;
	qd->present = present;
	qd->outdated = outdated;
	qd->diskless = diskless;
	qd->missing_diskless = missing_diskless;
	qd->unknown = unknown;
}

static bool calc_quorum(struct drbd_device *device, struct quorum_info *qi)
{
	struct drbd_resource *resource = device->resource;
	int voters, quorum_at, diskless_majority_at, min_redundancy_at;
	struct quorum_detail qd = {};
	bool have_quorum;

	if (device->disk_state[NEW] > D_ATTACHING && get_ldev_if_state(device, D_ATTACHING)) {
		__calc_quorum_with_disk(device, &qd);
		put_ldev(device);
	} else {
		__calc_quorum_no_disk(device, &qd);
	}

	/* When all the absent nodes are D_OUTDATED (no one D_UNKNOWN), we can be
	   sure that the other partition is not able to promote. ->
	   We remove them from the voters. -> We have quorum */
	if (qd.unknown)
		voters = qd.outdated + qd.unknown + qd.up_to_date + qd.present;
	else
		voters = qd.up_to_date + qd.present;

	quorum_at = calc_quorum_at(resource->res_opts.quorum, voters);
	diskless_majority_at = calc_quorum_at(QOU_MAJORITY, qd.diskless + qd.missing_diskless);
	min_redundancy_at = calc_quorum_at(resource->res_opts.quorum_min_redundancy, voters);

	if (qi) {
		qi->voters = voters;
		qi->up_to_date = qd.up_to_date;
		qi->present = qd.present;
		qi->quorum_at = quorum_at;
		qi->diskless_majority_at = diskless_majority_at;
		qi->min_redundancy_at = min_redundancy_at;
	}

	have_quorum = (qd.up_to_date + qd.present) >= quorum_at && qd.up_to_date >= min_redundancy_at;

	if (!have_quorum && voters != 0 && voters % 2 == 0 && qd.up_to_date + qd.present == quorum_at - 1 &&
		/* It is an even number of nodes (think 2) and we failed by one vote.
		   Check if we have majority of the diskless nodes connected.
		   Using the diskless nodes a tie-breaker! */
	    qd.diskless >= diskless_majority_at && device->have_quorum[NOW]) {
		have_quorum = true;
		if (!test_bit(TIEBREAKER_QUORUM, &device->flags)) {
			set_bit(TIEBREAKER_QUORUM, &device->flags);
			drbd_info(device, "Would lose quorum, but using tiebreaker logic to keep\n");
		}
	} else {
		clear_bit(TIEBREAKER_QUORUM, &device->flags);
	}

	return have_quorum;
}

static __printf(2, 3) void _drbd_state_err(struct change_context *context, const char *fmt, ...)
{
	struct drbd_resource *resource = context->resource;
	const char *err_str;
	va_list args;

	va_start(args, fmt);
	err_str = kvasprintf(GFP_ATOMIC, fmt, args);
	va_end(args);
	if (!err_str)
		return;
	if (context->err_str)
		*context->err_str = err_str;
	if (context->flags & CS_VERBOSE)
		drbd_err(resource, "%s\n", err_str);
}

static __printf(2, 3) void drbd_state_err(struct drbd_resource *resource, const char *fmt, ...)
{
	const char *err_str;
	va_list args;

	va_start(args, fmt);
	err_str = kvasprintf(GFP_ATOMIC, fmt, args);
	va_end(args);
	if (!err_str)
		return;
	if (resource->state_change_err_str)
		*resource->state_change_err_str = err_str;
	if (resource->state_change_flags & CS_VERBOSE)
		drbd_err(resource, "%s\n", err_str);
}

static enum drbd_state_rv __is_valid_soft_transition(struct drbd_resource *resource)
{
	enum drbd_role *role = resource->role;
	bool *fail_io = resource->fail_io;
	struct drbd_connection *connection;
	struct drbd_device *device;
	bool in_handshake = false;
	int vnr;

	/* See drbd_state_sw_errors in drbd_strings.c */

	if (role[OLD] != R_PRIMARY && role[NEW] == R_PRIMARY) {
		for_each_connection_rcu(connection, resource) {
			struct net_conf *nc;

			nc = rcu_dereference(connection->transport.net_conf);
			if (!nc || nc->two_primaries)
				continue;
			if (connection->peer_role[NEW] == R_PRIMARY)
				return SS_TWO_PRIMARIES;
		}
	}

	for_each_connection_rcu(connection, resource) {
		struct drbd_peer_device *peer_device;

		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
			if (test_bit(INITIAL_STATE_SENT, &peer_device->flags) &&
			    peer_device->repl_state[NOW] == L_OFF) {
				in_handshake = true;
				goto handshake_found;
			}
		}
	}
handshake_found:

	if (in_handshake && role[OLD] != role[NEW])
		return SS_IN_TRANSIENT_STATE;

	if (role[OLD] == R_SECONDARY && role[NEW] == R_PRIMARY && fail_io[NEW])
		return SS_DEVICE_IN_USE;

	for_each_connection_rcu(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;
		enum drbd_role *peer_role = connection->peer_role;
		struct net_conf *nc;
		bool two_primaries;

		if (cstate[NEW] == C_DISCONNECTING && cstate[OLD] == C_STANDALONE)
			return SS_ALREADY_STANDALONE;

		if (cstate[NEW] == C_CONNECTING && cstate[OLD] < C_UNCONNECTED)
			return SS_NO_NET_CONFIG;

		if (cstate[NEW] == C_DISCONNECTING && cstate[OLD] == C_UNCONNECTED)
			return SS_IN_TRANSIENT_STATE;

		nc = rcu_dereference(connection->transport.net_conf);
		two_primaries = nc ? nc->two_primaries : false;
		if (peer_role[NEW] == R_PRIMARY && peer_role[OLD] != R_PRIMARY && !two_primaries) {
			if (role[NOW] == R_PRIMARY)
				return SS_TWO_PRIMARIES;
			if (!fail_io[NEW]) {
				idr_for_each_entry(&resource->devices, device, vnr) {
					if (device->open_ro_cnt || device->open_rw_cnt)
						return SS_PRIMARY_READER;
				}
			}
		}
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		enum drbd_disk_state *disk_state = device->disk_state;
		struct drbd_peer_device *peer_device;
		bool any_disk_up_to_date[2];
		enum which_state which;
		int nr_negotiating = 0;

		if (in_handshake &&
		    ((disk_state[OLD] < D_ATTACHING && disk_state[NEW] == D_ATTACHING) ||
		     (disk_state[OLD] > D_DETACHING && disk_state[NEW] == D_DETACHING)))
			return SS_IN_TRANSIENT_STATE;

		if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY && device->open_rw_cnt &&
		    !(resource->state_change_flags & CS_FS_IGN_OPENERS))
			return SS_DEVICE_IN_USE;

		if (disk_state[NEW] > D_ATTACHING && disk_state[OLD] == D_DISKLESS)
			return SS_IS_DISKLESS;

		if (disk_state[NEW] == D_OUTDATED && disk_state[OLD] < D_OUTDATED &&
		    disk_state[OLD] != D_ATTACHING) {
			/* Do not allow outdate of inconsistent or diskless.
			   But we have to allow Inconsistent -> Outdated if a resync
			   finishes over one connection, and is paused on other connections */

			for_each_peer_device_rcu(peer_device, device) {
				enum drbd_repl_state *repl_state = peer_device->repl_state;
				if (repl_state[OLD] == L_SYNC_TARGET && repl_state[NEW] == L_ESTABLISHED)
					goto allow;
			}
			return SS_LOWER_THAN_OUTDATED;
		}
		allow:

		for (which = OLD; which <= NEW; which++)
			any_disk_up_to_date[which] = drbd_data_accessible(device, which);

		/* Prevent becoming primary while there is not data accessible
		   and prevent detach or disconnect while primary */
		if (!(role[OLD] == R_PRIMARY && !any_disk_up_to_date[OLD]) &&
		     (role[NEW] == R_PRIMARY && !any_disk_up_to_date[NEW]))
			return SS_NO_UP_TO_DATE_DISK;

		/* Prevent detach or disconnect while held open read only */
		if (device->open_ro_cnt && any_disk_up_to_date[OLD] && !any_disk_up_to_date[NEW])
			return SS_NO_UP_TO_DATE_DISK;

		if (disk_state[NEW] == D_NEGOTIATING)
			nr_negotiating++;

		if (role[OLD] == R_SECONDARY && role[NEW] == R_PRIMARY && !device->have_quorum[NEW]) {
			struct quorum_info qi;

			calc_quorum(device, &qi);

			if (qi.up_to_date + qi.present < qi.quorum_at)
				drbd_state_err(resource, "%d of %d nodes visible, need %d for quorum",
					       qi.up_to_date + qi.present, qi.voters, qi.quorum_at);
			else if (qi.up_to_date < qi.min_redundancy_at)
				drbd_state_err(resource, "%d of %d nodes up_to_date, need %d for "
					       "quorum-minimum-redundancy",
					       qi.up_to_date, qi.voters, qi.min_redundancy_at);
			return SS_NO_QUORUM;
		}

		for_each_peer_device_rcu(peer_device, device) {
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			enum drbd_repl_state *repl_state = peer_device->repl_state;

			if (peer_disk_state[NEW] == D_NEGOTIATING)
				nr_negotiating++;

			if (nr_negotiating > 1)
				return SS_IN_TRANSIENT_STATE;

			if (peer_device->connection->fencing_policy >= FP_RESOURCE &&
			    !(role[OLD] == R_PRIMARY && repl_state[OLD] < L_ESTABLISHED && !(peer_disk_state[OLD] <= D_OUTDATED)) &&
			     (role[NEW] == R_PRIMARY && repl_state[NEW] < L_ESTABLISHED && !(peer_disk_state[NEW] <= D_OUTDATED)))
				return SS_PRIMARY_NOP;

			if (!(repl_state[OLD] > L_ESTABLISHED && disk_state[OLD] < D_INCONSISTENT) &&
			     (repl_state[NEW] > L_ESTABLISHED && disk_state[NEW] < D_INCONSISTENT))
				return SS_NO_LOCAL_DISK;

			if (!(repl_state[OLD] > L_ESTABLISHED && peer_disk_state[OLD] < D_INCONSISTENT) &&
			     (repl_state[NEW] > L_ESTABLISHED && peer_disk_state[NEW] < D_INCONSISTENT))
				return SS_NO_REMOTE_DISK;

			if (disk_state[OLD] > D_OUTDATED && disk_state[NEW] == D_OUTDATED &&
			    !local_disk_may_be_outdated(device, NEW))
				return SS_CONNECTED_OUTDATES;

			if (!(repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			     (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T)) {
				struct net_conf *nc = rcu_dereference(peer_device->connection->transport.net_conf);

				if (!nc || nc->verify_alg[0] == 0)
					return SS_NO_VERIFY_ALG;
			}

			if (!(repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			     (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) &&
				  peer_device->connection->agreed_pro_version < 88)
				return SS_NOT_SUPPORTED;

			if (repl_state[OLD] == L_SYNC_SOURCE && repl_state[NEW] == L_WF_BITMAP_S)
				return SS_RESYNC_RUNNING;

			if (repl_state[OLD] == L_SYNC_TARGET && repl_state[NEW] == L_WF_BITMAP_T)
				return SS_RESYNC_RUNNING;

			if (repl_state[NEW] != repl_state[OLD] &&
			    (repl_state[NEW] == L_STARTING_SYNC_T || repl_state[NEW] == L_STARTING_SYNC_S) &&
			    repl_state[OLD] > L_ESTABLISHED )
				return SS_RESYNC_RUNNING;

			if ((repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) && repl_state[OLD] < L_ESTABLISHED)
				return SS_NEED_CONNECTION;

			if ((repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) &&
			    repl_state[NEW] != repl_state[OLD] && repl_state[OLD] > L_ESTABLISHED)
				return SS_RESYNC_RUNNING;

			if ((repl_state[NEW] == L_STARTING_SYNC_S || repl_state[NEW] == L_STARTING_SYNC_T) &&
			    repl_state[OLD] < L_ESTABLISHED)
				return SS_NEED_CONNECTION;

			if ((repl_state[NEW] == L_SYNC_TARGET || repl_state[NEW] == L_SYNC_SOURCE)
			    && repl_state[OLD] < L_OFF)
				return SS_NEED_CONNECTION; /* No NetworkFailure -> SyncTarget etc... */

			if ((peer_disk_state[NEW] > D_DISKLESS && peer_disk_state[NEW] != D_UNKNOWN) &&
			    peer_disk_state[OLD] == D_DISKLESS && !want_bitmap(peer_device))
				return SS_ATTACH_NO_BITMAP;  /* peer with --bitmap=no wannts to attach ??? */
		}
	}

	return SS_SUCCESS;
}

/**
 * is_valid_soft_transition() - Returns an SS_ error code if state[NEW] is not valid
 *
 * "Soft" transitions are voluntary state changes which drbd may decline, such
 * as a user request to promote a resource to primary.  Opposed to that are
 * involuntary or "hard" transitions like a network connection loss.
 *
 * When deciding if a "soft" transition should be allowed, "hard" transitions
 * may already have forced the resource into a critical state.  It may take
 * several "soft" transitions to get the resource back to normal.  To allow
 * those, rather than checking if the desired new state is valid, we can only
 * check if the desired new state is "at least as good" as the current state.
 *
 * @resource:	DRBD resource
 */
static enum drbd_state_rv is_valid_soft_transition(struct drbd_resource *resource)
{
	enum drbd_state_rv rv;

	rcu_read_lock();
	rv = __is_valid_soft_transition(resource);
	rcu_read_unlock();

	return rv;
}

static enum drbd_state_rv
is_valid_conn_transition(enum drbd_conn_state oc, enum drbd_conn_state nc)
{
	/* no change -> nothing to do, at least for the connection part */
	if (oc == nc)
		return SS_NOTHING_TO_DO;

	/* disconnect of an unconfigured connection does not make sense */
	if (oc == C_STANDALONE && nc == C_DISCONNECTING)
		return SS_ALREADY_STANDALONE;

	/* from C_STANDALONE, we start with C_UNCONNECTED */
	if (oc == C_STANDALONE && nc != C_UNCONNECTED)
		return SS_NEED_CONNECTION;

	/* After a network error only C_UNCONNECTED or C_DISCONNECTING may follow. */
	if (oc >= C_TIMEOUT && oc <= C_TEAR_DOWN && nc != C_UNCONNECTED && nc != C_DISCONNECTING)
		return SS_IN_TRANSIENT_STATE;

	/* After C_DISCONNECTING only C_STANDALONE may follow */
	if (oc == C_DISCONNECTING && nc != C_STANDALONE)
		return SS_IN_TRANSIENT_STATE;

	return SS_SUCCESS;
}


/**
 * is_valid_transition() - Returns an SS_ error code if the state transition is not possible
 * This limits hard state transitions. Hard state transitions are facts there are
 * imposed on DRBD by the environment. E.g. disk broke or network broke down.
 * But those hard state transitions are still not allowed to do everything.
 */
static enum drbd_state_rv is_valid_transition(struct drbd_resource *resource)
{
	enum drbd_state_rv rv;
	struct drbd_connection *connection;
	struct drbd_device *device;
	int vnr;

	for_each_connection(connection, resource) {
		rv = is_valid_conn_transition(connection->cstate[OLD], connection->cstate[NEW]);
		if (rv < SS_SUCCESS)
			return rv;
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		/* we cannot fail (again) if we already detached */
		if ((device->disk_state[NEW] == D_FAILED || device->disk_state[NEW] == D_DETACHING) &&
		    device->disk_state[OLD] == D_DISKLESS) {
			return SS_IS_DISKLESS;
		}
	}

	return SS_SUCCESS;
}

static bool is_sync_target_other_c(struct drbd_peer_device *ign_peer_device)
{
	struct drbd_device *device = ign_peer_device->device;
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		enum drbd_repl_state r;

		if (peer_device == ign_peer_device)
			continue;

		r = peer_device->repl_state[NEW];
		if (r == L_SYNC_TARGET || r == L_PAUSED_SYNC_T)
			return true;
	}

	return false;
}

static void drbd_start_other_targets_paused(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_peer_device *p;

	for_each_peer_device(p, device) {
		if (p == peer_device)
			continue;

		if (p->disk_state[NEW] >= D_INCONSISTENT && p->repl_state[NEW] == L_ESTABLISHED)
			p->repl_state[NEW] = L_PAUSED_SYNC_T;
	}
}

static bool drbd_is_sync_target_candidate(struct drbd_peer_device *peer_device)
{
	if (!repl_is_sync_target(peer_device->repl_state[NEW]))
		return false;

	if (peer_device->resync_susp_dependency[NEW] ||
			peer_device->resync_susp_peer[NEW] ||
			peer_device->resync_susp_user[NEW])
		return false;

	if (peer_device->disk_state[NEW] < D_OUTDATED)
		return false;

	return true;

}

static void drbd_select_sync_target(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	struct drbd_peer_device *target_current = NULL;
	struct drbd_peer_device *target_active = NULL;
	struct drbd_peer_device *target_desired = NULL;

	/* Find current and active resync peers. */
	for_each_peer_device_rcu(peer_device, device) {
		if (peer_device->repl_state[OLD] == L_SYNC_TARGET && drbd_is_sync_target_candidate(peer_device))
			target_current = peer_device;

		if (peer_device->resync_active[NEW])
			target_active = peer_device;
	}

	/* Choose desired resync peer. */
	for_each_peer_device_rcu(peer_device, device) {
		if (!drbd_is_sync_target_candidate(peer_device))
			continue;

		if (target_desired && drbd_bm_total_weight(peer_device) > drbd_bm_total_weight(target_desired))
			continue;

		target_desired = peer_device;
	}

	/* Keep current resync target if the alternative has less than 1MiB
	 * storage (256 bits) less to resync. */
	if (target_current && target_desired &&
			drbd_bm_total_weight(target_current) < drbd_bm_total_weight(target_desired) + 256UL)
		target_desired = target_current;

	/* Do not activate/unpause a resync if some other is still active. */
	if (target_desired && target_active && target_desired != target_active)
		target_desired = NULL;

	/* Activate resync (if not already active). */
	if (target_desired)
		target_desired->resync_active[NEW] = true;

	/* Make sure that the targets are correctly paused/unpaused. */
	for_each_peer_device_rcu(peer_device, device) {
		enum drbd_repl_state *repl_state = peer_device->repl_state;

		peer_device->resync_susp_other_c[NEW] = target_desired && peer_device != target_desired;

		if (!repl_is_sync_target(repl_state[NEW]))
			continue;

		peer_device->repl_state[NEW] = peer_device == target_desired ? L_SYNC_TARGET : L_PAUSED_SYNC_T;
	}
}

static void sanitize_state(struct drbd_resource *resource)
{
	enum drbd_role *role = resource->role;
	struct drbd_connection *connection;
	struct drbd_device *device;
	bool maybe_crashed_primary = false;
	bool volume_lost_data_access = false;
	bool volumes_have_data_access = true;
	bool resource_has_quorum = true;
	int connected_primaries = 0;
	int vnr;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;

		if (cstate[NEW] < C_CONNECTED)
			connection->peer_role[NEW] = R_UNKNOWN;

		if (connection->peer_role[OLD] == R_PRIMARY && cstate[OLD] == C_CONNECTED &&
		    ((cstate[NEW] >= C_TIMEOUT && cstate[NEW] <= C_PROTOCOL_ERROR) ||
		     (cstate[NEW] == C_DISCONNECTING && resource->state_change_flags & CS_HARD)))
			/* implies also C_BROKEN_PIPE and C_NETWORK_FAILURE */
			maybe_crashed_primary = true;

		if (connection->peer_role[NEW] == R_PRIMARY)
			connected_primaries++;
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;
		enum drbd_disk_state *disk_state = device->disk_state;
		bool lost_connection = false;

		if (disk_state[OLD] == D_DISKLESS && disk_state[NEW] == D_DETACHING)
			disk_state[NEW] = D_DISKLESS;

		if ((resource->state_change_flags & CS_IGN_OUTD_FAIL) &&
		    disk_state[OLD] < D_OUTDATED && disk_state[NEW] == D_OUTDATED)
			disk_state[NEW] = disk_state[OLD];

		/* Is disk state negotiation finished? */
		if (disk_state[OLD] == D_NEGOTIATING && disk_state[NEW] == D_NEGOTIATING) {
			int all = 0, target = 0, no_result = 0;
			bool up_to_date_neighbor = false;

			for_each_peer_device_rcu(peer_device, device) {
				enum drbd_conn_state cstate = peer_device->connection->cstate[NEW];
				enum drbd_repl_state nr = peer_device->negotiation_result;
				enum drbd_disk_state pdsk = peer_device->disk_state[NEW];

				if (pdsk < D_NEGOTIATING || cstate < C_CONNECTED)
					continue;

				if (pdsk == D_UP_TO_DATE)
					up_to_date_neighbor = true;

				all++;
				if (nr == L_NEG_NO_RESULT)
					no_result++;
				else if (nr == L_NEGOTIATING)
					goto stay_negotiating;
				else if (nr == L_WF_BITMAP_T)
					target++;
				else if (nr != L_ESTABLISHED && nr != L_WF_BITMAP_S)
					drbd_err(peer_device, "Unexpected nr = %s\n", drbd_repl_str(nr));
			}

			/* negotiation finished */
			if (no_result > 0 && no_result == all)
				disk_state[NEW] = D_DETACHING;
			else if (target)
				disk_state[NEW] = D_INCONSISTENT;
			else
				disk_state[NEW] = up_to_date_neighbor ? D_UP_TO_DATE :
					disk_state_from_md(device);

			for_each_peer_device_rcu(peer_device, device) {
				enum drbd_repl_state nr = peer_device->negotiation_result;

				if (peer_device->connection->cstate[NEW] < C_CONNECTED ||
				    nr == L_NEGOTIATING)
					continue;

				if (nr == L_NEG_NO_RESULT)
					nr = L_ESTABLISHED;

				if (nr == L_WF_BITMAP_S && disk_state[NEW] == D_INCONSISTENT) {
					/* Should be sync source for one peer and sync
					   target for an other peer. Delay the sync source
					   role */
					nr = L_PAUSED_SYNC_S;
					peer_device->resync_susp_other_c[NEW] = true;
					drbd_warn(peer_device, "Finish me\n");
				}
				peer_device->repl_state[NEW] = nr;
			}
		}
	stay_negotiating:

		for_each_peer_device_rcu(peer_device, device) {
			enum drbd_repl_state *repl_state = peer_device->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			struct drbd_connection *connection = peer_device->connection;
			enum drbd_conn_state *cstate = connection->cstate;

			if (repl_state[NEW] < L_ESTABLISHED) {
				peer_device->resync_susp_peer[NEW] = false;
				if (peer_disk_state[NEW] > D_UNKNOWN ||
				    peer_disk_state[NEW] < D_INCONSISTENT)
					peer_disk_state[NEW] = D_UNKNOWN;
			}
			if (repl_state[OLD] >= L_ESTABLISHED && repl_state[NEW] < L_ESTABLISHED) {
				lost_connection = true;
				peer_device->resync_active[NEW] = false;
			}

			/* Clear the aftr_isp when becoming unconfigured */
			if (cstate[NEW] == C_STANDALONE &&
			    disk_state[NEW] == D_DISKLESS &&
			    role[NEW] == R_SECONDARY)
				peer_device->resync_susp_dependency[NEW] = false;

			/* Abort resync if a disk fails/detaches */
			if (repl_state[NEW] > L_ESTABLISHED &&
			    (disk_state[NEW] <= D_FAILED ||
			     peer_disk_state[NEW] <= D_FAILED)) {
				repl_state[NEW] = L_ESTABLISHED;
				clear_bit(RECONCILIATION_RESYNC, &peer_device->flags);
				peer_device->resync_active[NEW] = false;
			}

			/* Suspend IO while fence-peer handler runs (peer lost) */
			if (connection->fencing_policy == FP_STONITH &&
			    (role[NEW] == R_PRIMARY &&
			     repl_state[NEW] < L_ESTABLISHED &&
			     peer_disk_state[NEW] == D_UNKNOWN) &&
			    (role[OLD] != R_PRIMARY ||
			     peer_disk_state[OLD] != D_UNKNOWN))
				connection->susp_fen[NEW] = true;
		}

		drbd_select_sync_target(device);

		for_each_peer_device_rcu(peer_device, device) {
			enum drbd_repl_state *repl_state = peer_device->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			struct drbd_connection *connection = peer_device->connection;
			enum drbd_disk_state min_disk_state, max_disk_state;
			enum drbd_disk_state min_peer_disk_state, max_peer_disk_state;
			enum drbd_role *peer_role = connection->peer_role;
			bool uuids_match;

			/* Pause a SyncSource until it finishes resync as target on other connections */
			if (repl_state[OLD] != L_SYNC_SOURCE && repl_state[NEW] == L_SYNC_SOURCE &&
			    is_sync_target_other_c(peer_device))
				peer_device->resync_susp_other_c[NEW] = true;

			if (resync_suspended(peer_device, NEW)) {
				if (repl_state[NEW] == L_SYNC_SOURCE)
					repl_state[NEW] = L_PAUSED_SYNC_S;
			} else {
				if (repl_state[NEW] == L_PAUSED_SYNC_S)
					repl_state[NEW] = L_SYNC_SOURCE;
			}

			/* Implication of the repl state on other peer's repl state */
			if (repl_state[OLD] != L_STARTING_SYNC_T && repl_state[NEW] == L_STARTING_SYNC_T)
				drbd_start_other_targets_paused(peer_device);

			/* D_CONSISTENT vanish when we get connected (pre 9.0) */
			if (connection->agreed_pro_version < 110 &&
			    repl_state[NEW] >= L_ESTABLISHED && repl_state[NEW] < L_AHEAD) {
				if (disk_state[NEW] == D_CONSISTENT)
					disk_state[NEW] = D_UP_TO_DATE;
				if (peer_disk_state[NEW] == D_CONSISTENT)
					peer_disk_state[NEW] = D_UP_TO_DATE;
			}

			/* Implications of the repl state on the disk states */
			min_disk_state = D_DISKLESS;
			max_disk_state = D_UP_TO_DATE;
			min_peer_disk_state = D_INCONSISTENT;
			max_peer_disk_state = D_UNKNOWN;
			switch (repl_state[NEW]) {
			case L_OFF:
				/* values from above */
				break;
			case L_WF_BITMAP_T:
			case L_STARTING_SYNC_T:
			case L_WF_SYNC_UUID:
			case L_BEHIND:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_OUTDATED;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_VERIFY_S:
			case L_VERIFY_T:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_ESTABLISHED:
				min_disk_state = D_DISKLESS;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_DISKLESS;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_WF_BITMAP_S:
			case L_PAUSED_SYNC_S:
			case L_STARTING_SYNC_S:
			case L_AHEAD:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_CONSISTENT; /* D_OUTDATED would be nice. But explicit outdate necessary*/
				break;
			case L_PAUSED_SYNC_T:
			case L_SYNC_TARGET:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_INCONSISTENT;
				min_peer_disk_state = D_OUTDATED;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_SYNC_SOURCE:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_INCONSISTENT;
				break;
			}

			/* Implications of the repl state on the disk states */
			if (disk_state[NEW] > max_disk_state)
				disk_state[NEW] = max_disk_state;

			if (disk_state[NEW] < min_disk_state)
				disk_state[NEW] = min_disk_state;

			if (peer_disk_state[NEW] > max_peer_disk_state)
				peer_disk_state[NEW] = max_peer_disk_state;

			if (peer_disk_state[NEW] < min_peer_disk_state)
				peer_disk_state[NEW] = min_peer_disk_state;

			/* A detach is a cluster wide transaction. The peer_disk_state updates
			   are coming in while we have it prepared. When the cluster wide
			   state change gets committed prevent D_DISKLESS -> D_FAILED */
			if (peer_disk_state[OLD] == D_DISKLESS &&
			    (peer_disk_state[NEW] == D_FAILED || peer_disk_state[NEW] == D_DETACHING))
				peer_disk_state[NEW] = D_DISKLESS;

			/* Upgrade myself from D_OUTDATED if..
			   1) We connect to stable D_UP_TO_DATE(or D_CONSISTENT) peer without resync
			   2) The peer just became stable
			   3) the peer was stable and just became D_UP_TO_DATE */
			if (repl_state[NEW] == L_ESTABLISHED && disk_state[NEW] == D_OUTDATED &&
			    peer_disk_state[NEW] >= D_CONSISTENT && test_bit(UUIDS_RECEIVED, &peer_device->flags) &&
			    peer_device->uuid_flags & UUID_FLAG_STABLE &&
			    (repl_state[OLD] < L_ESTABLISHED ||
			     peer_device->uuid_flags & UUID_FLAG_GOT_STABLE ||
			     peer_disk_state[OLD] == D_OUTDATED))
				disk_state[NEW] = peer_disk_state[NEW];

			/* The attempted resync made us D_OUTDATED, roll that back in case */
			if (repl_state[OLD] == L_WF_BITMAP_T && repl_state[NEW] == L_OFF &&
			    disk_state[NEW] == D_OUTDATED &&
			    stable_up_to_date_neighbor(device) && may_be_up_to_date(device, NEW))
				disk_state[NEW] = D_UP_TO_DATE;

			/* clause intentional here, the D_CONSISTENT form above might trigger this */
			if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED &&
			    disk_state[NEW] == D_CONSISTENT && may_be_up_to_date(device, NEW))
				disk_state[NEW] = D_UP_TO_DATE;

			/* Follow a neighbor that goes from D_CONSISTENT TO D_UP_TO_DATE */
			if (disk_state[NEW] == D_CONSISTENT &&
			    peer_disk_state[OLD] == D_CONSISTENT && peer_disk_state[NEW] == D_UP_TO_DATE &&
			    peer_device->uuid_flags & UUID_FLAG_STABLE)
				disk_state[NEW] = D_UP_TO_DATE;

			peer_device->uuid_flags &= ~UUID_FLAG_GOT_STABLE;

			uuids_match =
				(peer_device->current_uuid & ~UUID_PRIMARY) ==
				(drbd_current_uuid(device) & ~UUID_PRIMARY);

			if (peer_role[OLD] == R_UNKNOWN && peer_role[NEW] == R_PRIMARY &&
			    peer_disk_state[NEW] == D_DISKLESS && disk_state[NEW] >= D_NEGOTIATING) {
				/* Got connected to a diskless primary */
				if (uuids_match && !is_sync_target_other_c(peer_device)) {
					if (device->disk_state[NOW] < D_UP_TO_DATE) {
						drbd_info(peer_device, "Upgrading local disk to D_UP_TO_DATE since current UUID matches.\n");
						disk_state[NEW] = D_UP_TO_DATE;
					}
				} else {
					set_bit(TRY_TO_GET_RESYNC, &device->flags);
					if (disk_state[NEW] == D_UP_TO_DATE) {
						drbd_info(peer_device, "Downgrading local disk to D_CONSISTENT since current UUID differs.\n");
						disk_state[NEW] = D_CONSISTENT;
						/* This is a "safety net"; it can only happen if fencing and quorum
						   are both disabled. This alone would be racy, look for
						   "Do not trust this guy!" (see also may_return_to_up_to_date()) */
					}
				}
			}
			if (peer_disk_state[OLD] == D_UNKNOWN && peer_disk_state[NEW] == D_UP_TO_DATE &&
			    role[NEW] == R_PRIMARY && disk_state[NEW] == D_DISKLESS && !uuids_match) {
				/* Do not trust this guy!
				   He pretends to be D_UP_TO_DATE, but has a different current UUID. Do not
				   accept him as D_UP_TO_DATE but downgrade that to D_CONSISTENT here. He will
				   do the same. We need to do it here to avoid that the peer is visible as
				   D_UP_TO_DATE at all. Otherwise we could ship read requests to it!
				*/
				peer_disk_state[NEW] = D_CONSISTENT;
			}
		}

		if (resource->res_opts.quorum != QOU_OFF)
			device->have_quorum[NEW] = calc_quorum(device, NULL);
		else
			device->have_quorum[NEW] = true;

		if (!device->have_quorum[NEW])
			resource_has_quorum = false;

		/* Suspend IO if we have no accessible data available.
		 * Policy may be extended later to be able to suspend
		 * if redundancy falls below a certain level. */
		if (role[NEW] == R_PRIMARY && !drbd_data_accessible(device, NEW)) {
			volumes_have_data_access = false;
			if (role[OLD] != R_PRIMARY || drbd_data_accessible(device, OLD))
				volume_lost_data_access = true;
		}

		if (lost_connection && disk_state[NEW] == D_NEGOTIATING)
			disk_state[NEW] = disk_state_from_md(device);

		if (maybe_crashed_primary && !connected_primaries &&
		    disk_state[NEW] == D_UP_TO_DATE && role[NOW] == R_SECONDARY)
			disk_state[NEW] = D_CONSISTENT;
	}
	rcu_read_unlock();

	if (volumes_have_data_access)
		resource->susp_nod[NEW] = false;
	if (volume_lost_data_access && resource->res_opts.on_no_data == OND_SUSPEND_IO)
		resource->susp_nod[NEW] = true;

	resource->susp_quorum[NEW] =
		resource->res_opts.on_no_quorum == ONQ_SUSPEND_IO ? !resource_has_quorum : false;

	if (resource_is_suspended(resource, OLD) && !resource_is_suspended(resource, NEW)) {
		idr_for_each_entry(&resource->devices, device, vnr) {
			if (test_bit(NEW_CUR_UUID, &device->flags)) {
				resource->susp_uuid[NEW] = true;
				break;
			}
		}
	}

	if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY &&
	    (resource->state_change_flags & CS_FS_IGN_OPENERS)) {
		int rw_count, ro_count;
		drbd_open_counts(resource, &rw_count, &ro_count);
		if (rw_count)
			resource->fail_io[NEW] = true;
	}
}

void drbd_resume_al(struct drbd_device *device)
{
	if (test_and_clear_bit(AL_SUSPENDED, &device->flags))
		drbd_info(device, "Resumed AL updates\n");
}

static void set_ov_position(struct drbd_peer_device *peer_device,
			    enum drbd_repl_state repl_state)
{
	struct drbd_device *device = peer_device->device;
	if (peer_device->connection->agreed_pro_version < 90)
		peer_device->ov_start_sector = 0;
	peer_device->rs_total = drbd_bm_bits(device);
	peer_device->ov_position = 0;
	if (repl_state == L_VERIFY_T) {
		/* starting online verify from an arbitrary position
		 * does not fit well into the existing protocol.
		 * on L_VERIFY_T, we initialize ov_left and friends
		 * implicitly in receive_DataRequest once the
		 * first P_OV_REQUEST is received */
		peer_device->ov_start_sector = ~(sector_t)0;
	} else {
		unsigned long bit = BM_SECT_TO_BIT(peer_device->ov_start_sector);
		if (bit >= peer_device->rs_total) {
			peer_device->ov_start_sector =
				BM_BIT_TO_SECT(peer_device->rs_total - 1);
			peer_device->rs_total = 1;
		} else
			peer_device->rs_total -= bit;
		peer_device->ov_position = peer_device->ov_start_sector;
	}
	atomic64_set(&peer_device->ov_left, peer_device->rs_total);
	peer_device->ov_skipped = 0;
}

static void initialize_resync_progress_marks(struct drbd_peer_device *peer_device)
{
	unsigned long tw = drbd_bm_total_weight(peer_device);
	unsigned long now = jiffies;
	int i;

	for (i = 0; i < DRBD_SYNC_MARKS; i++) {
		peer_device->rs_mark_left[i] = tw;
		peer_device->rs_mark_time[i] = now;
	}
}

static void initialize_resync(struct drbd_peer_device *peer_device)
{
	unsigned long tw = drbd_bm_total_weight(peer_device);
	unsigned long now = jiffies;

	peer_device->resync_next_bit = 0;
	peer_device->last_resync_next_bit = 0;
	peer_device->rs_failed = 0;
	peer_device->rs_paused = 0;
	peer_device->rs_same_csum = 0;
	peer_device->rs_last_sect_ev = 0;
	peer_device->rs_total = tw;
	peer_device->rs_start = now;
	peer_device->rs_last_writeout = now;
	initialize_resync_progress_marks(peer_device);
	drbd_rs_controller_reset(peer_device);
}

/* Is there a primary with access to up to date data known */
static bool primary_and_data_present(struct drbd_device *device)
{
	bool up_to_date_data = device->disk_state[NOW] == D_UP_TO_DATE;
	bool primary = device->resource->role[NOW] == R_PRIMARY;
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->peer_role[NOW] == R_PRIMARY)
			primary = true;

		if (peer_device->disk_state[NOW] == D_UP_TO_DATE)
			up_to_date_data = true;
	}

	return primary && up_to_date_data;
}

static bool extra_ldev_ref_for_after_state_chg(enum drbd_disk_state *disk_state)
{
	return (disk_state[OLD] != D_FAILED && disk_state[NEW] == D_FAILED) ||
	       (disk_state[OLD] != D_DETACHING && disk_state[NEW] == D_DETACHING) ||
	       (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS);
}

static bool has_starting_resyncs(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NEW] > L_ESTABLISHED)
			return true;
	}
	return false;
}

/**
 * finish_state_change  -  carry out actions triggered by a state change
 */
static void finish_state_change(struct drbd_resource *resource)
{
	enum drbd_role *role = resource->role;
	struct drbd_device *device;
	struct drbd_connection *connection;
	bool starting_resync = false;
	bool start_new_epoch = false;
	bool lost_a_primary_peer = false;
	bool some_peer_is_primary = false;
	bool some_peer_request_in_flight = false;
	bool resource_suspended[2];
	bool unfreeze_io = false;
	int vnr;

	print_state_change(resource, "");

	resource_suspended[OLD] = resource_is_suspended(resource, OLD);
	resource_suspended[NEW] = resource_is_suspended(resource, NEW);

	idr_for_each_entry(&resource->devices, device, vnr) {
		bool *have_quorum = device->have_quorum;
		struct drbd_peer_device *peer_device;

		for_each_peer_device(peer_device, device) {
			bool did, should;

			did = drbd_should_do_remote(peer_device, NOW);
			should = drbd_should_do_remote(peer_device, NEW);

			if (did != should)
				start_new_epoch = true;

			if (!is_sync_state(peer_device, NOW) &&
			    is_sync_state(peer_device, NEW)) {
				clear_bit(RS_DONE, &peer_device->flags);
				clear_bit(B_RS_H_DONE, &peer_device->flags);
				clear_bit(SYNC_TARGET_TO_BEHIND, &peer_device->flags);
			}
		}

		if (role[NEW] == R_PRIMARY && !have_quorum[NEW])
			set_bit(PRIMARY_LOST_QUORUM, &device->flags);
	}
	if (start_new_epoch)
		start_new_tl_epoch(resource);

	if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY && resource->peer_ack_req) {
		resource->last_peer_acked_dagtag = resource->peer_ack_req->dagtag_sector;
		drbd_queue_peer_ack(resource, resource->peer_ack_req);
		resource->peer_ack_req = NULL;
	}

	if (!resource->fail_io[OLD] && resource->fail_io[NEW])
		drbd_warn(resource, "Failing IOs\n");

	idr_for_each_entry(&resource->devices, device, vnr) {
		enum drbd_disk_state *disk_state = device->disk_state;
		struct drbd_peer_device *peer_device;
		bool create_new_uuid = false;

		if (disk_state[OLD] != D_NEGOTIATING && disk_state[NEW] == D_NEGOTIATING) {
			for_each_peer_device(peer_device, device)
				peer_device->negotiation_result = L_NEGOTIATING;
		}

		/* if we are going -> D_FAILED or D_DISKLESS, grab one extra reference
		 * on the ldev here, to be sure the transition -> D_DISKLESS resp.
		 * drbd_ldev_destroy() won't happen before our corresponding
		 * w_after_state_change works run, where we put_ldev again. */
		if (extra_ldev_ref_for_after_state_chg(disk_state))
			atomic_inc(&device->local_cnt);

		if (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS) {
			/* who knows if we are ever going to be attached again,
			 * and whether that will be the same device, or a newly
			 * initialized one. */
			for_each_peer_device(peer_device, device)
				peer_device->bitmap_index = -1;
		}

		if (disk_state[OLD] == D_ATTACHING && disk_state[NEW] >= D_NEGOTIATING)
			drbd_info(device, "attached to current UUID: %016llX\n", device->ldev->md.current_uuid);

		for_each_peer_device(peer_device, device) {
			enum drbd_repl_state *repl_state = peer_device->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			struct drbd_connection *connection = peer_device->connection;
			enum drbd_role *peer_role = connection->peer_role;

			if (repl_state[OLD] <= L_ESTABLISHED && repl_state[NEW] == L_WF_BITMAP_S)
				starting_resync = true;

			if ((disk_state[OLD] != D_UP_TO_DATE || peer_disk_state[OLD] != D_UP_TO_DATE) &&
			    (disk_state[NEW] == D_UP_TO_DATE && peer_disk_state[NEW] == D_UP_TO_DATE)) {
				clear_bit(CRASHED_PRIMARY, &device->flags);
				if (test_bit(UUIDS_RECEIVED, &peer_device->flags))
					peer_device->uuid_flags &= ~((u64)UUID_FLAG_CRASHED_PRIMARY);
			}

			/* Aborted verify run, or we reached the stop sector.
			 * Log the last position, unless end-of-device. */
			if ((repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			    repl_state[NEW] <= L_ESTABLISHED) {
				unsigned long ov_left = atomic64_read(&peer_device->ov_left);

				peer_device->ov_start_sector =
					BM_BIT_TO_SECT(drbd_bm_bits(device) - ov_left);
				if (ov_left)
					drbd_info(peer_device, "Online Verify reached sector %llu\n",
						  (unsigned long long)peer_device->ov_start_sector);
			}

			if ((repl_state[OLD] == L_PAUSED_SYNC_T || repl_state[OLD] == L_PAUSED_SYNC_S) &&
			    (repl_state[NEW] == L_SYNC_TARGET  || repl_state[NEW] == L_SYNC_SOURCE)) {
				drbd_info(peer_device, "Syncer continues.\n");
				peer_device->rs_paused += (long)jiffies
						  -(long)peer_device->rs_mark_time[peer_device->rs_last_mark];
				initialize_resync_progress_marks(peer_device);
				peer_device->resync_next_bit = 0;
				peer_device->last_resync_next_bit = 0;
			}

			if ((repl_state[OLD] == L_SYNC_TARGET  || repl_state[OLD] == L_SYNC_SOURCE) &&
			    (repl_state[NEW] == L_PAUSED_SYNC_T || repl_state[NEW] == L_PAUSED_SYNC_S)) {
				drbd_info(peer_device, "Resync suspended\n");
				peer_device->rs_mark_time[peer_device->rs_last_mark] = jiffies;
			}


			if (repl_state[OLD] > L_ESTABLISHED && repl_state[NEW] <= L_ESTABLISHED)
				clear_bit(RECONCILIATION_RESYNC, &peer_device->flags);

			if (repl_state[OLD] >= L_ESTABLISHED && repl_state[NEW] < L_ESTABLISHED)
				clear_bit(AHEAD_TO_SYNC_SOURCE, &peer_device->flags);

			if (repl_state[OLD] == L_ESTABLISHED &&
			    (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T)) {
				unsigned long now = jiffies;
				int i;

				set_ov_position(peer_device, repl_state[NEW]);
				peer_device->rs_start = now;
				peer_device->rs_last_sect_ev = 0;
				peer_device->ov_last_oos_size = 0;
				peer_device->ov_last_oos_start = 0;
				peer_device->ov_last_skipped_size = 0;
				peer_device->ov_last_skipped_start = 0;
				peer_device->rs_last_writeout = now;
				for (i = 0; i < DRBD_SYNC_MARKS; i++) {
					peer_device->rs_mark_left[i] = peer_device->rs_total;
					peer_device->rs_mark_time[i] = now;
				}

				drbd_rs_controller_reset(peer_device);
			} else if (!(repl_state[OLD] >= L_SYNC_SOURCE && repl_state[OLD] <= L_PAUSED_SYNC_T) &&
				   (repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T)) {
				initialize_resync(peer_device);
			}

			if (disk_state[NEW] != D_NEGOTIATING && get_ldev(device)) {
				if (peer_device->bitmap_index != -1) {
					enum drbd_disk_state pdsk = peer_device->disk_state[NEW];
					u32 mdf = device->ldev->md.peers[peer_device->node_id].flags;
					/* Do NOT clear MDF_PEER_DEVICE_SEEN.
					 * We want to be able to refuse a resize beyond "last agreed" size,
					 * even if the peer is currently detached.
					 */
					mdf &= ~(MDF_PEER_CONNECTED | MDF_PEER_OUTDATED | MDF_PEER_FENCING);
					if (repl_state[NEW] > L_OFF)
						mdf |= MDF_PEER_CONNECTED;
					if (pdsk >= D_INCONSISTENT) {
						if (pdsk <= D_OUTDATED)
							mdf |= MDF_PEER_OUTDATED;
						if (pdsk != D_UNKNOWN)
							mdf |= MDF_PEER_DEVICE_SEEN;
					}
					if (peer_device->connection->fencing_policy != FP_DONT_CARE)
						mdf |= MDF_PEER_FENCING;
					if (mdf != device->ldev->md.peers[peer_device->node_id].flags) {
						device->ldev->md.peers[peer_device->node_id].flags = mdf;
						drbd_md_mark_dirty(device);
					}
				}

				/* Peer was forced D_UP_TO_DATE & R_PRIMARY, consider to resync */
				if (disk_state[OLD] == D_INCONSISTENT &&
				    peer_disk_state[OLD] == D_INCONSISTENT && peer_disk_state[NEW] == D_UP_TO_DATE &&
				    peer_role[OLD] == R_SECONDARY && peer_role[NEW] == R_PRIMARY)
					set_bit(CONSIDER_RESYNC, &peer_device->flags);

				/* Resume AL writing if we get a connection */
				if (repl_state[OLD] < L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED)
					drbd_resume_al(device);
				put_ldev(device);
			}

			if (repl_state[OLD] == L_AHEAD && repl_state[NEW] == L_SYNC_SOURCE) {
				set_bit(SEND_STATE_AFTER_AHEAD, &peer_device->flags);
				set_bit(SEND_STATE_AFTER_AHEAD_C, &connection->flags);

				clear_bit(CONN_CONGESTED, &connection->flags);
				wake_up(&connection->sender_work.q_wait);
			}

			/* We start writing locally without replicating the changes,
			 * better start a new data generation */
			if (repl_state[OLD] != L_AHEAD && repl_state[NEW] == L_AHEAD)
				create_new_uuid = true;

			if (lost_contact_to_peer_data(peer_disk_state)) {
				if (role[NEW] == R_PRIMARY && !test_bit(UNREGISTERED, &device->flags) &&
				    drbd_data_accessible(device, NEW))
					create_new_uuid = true;

				if (connection->agreed_pro_version < 110 &&
				    peer_role[NEW] == R_PRIMARY &&
				    disk_state[NEW] >= D_UP_TO_DATE)
					create_new_uuid = true;
			}
			if (peer_returns_diskless(peer_device, peer_disk_state[OLD], peer_disk_state[NEW])) {
				if (role[NEW] == R_PRIMARY && !test_bit(UNREGISTERED, &device->flags) &&
				    disk_state[NEW] == D_UP_TO_DATE)
					create_new_uuid = true;
			}

			if (disk_state[OLD] > D_FAILED && disk_state[NEW] == D_FAILED &&
			    role[NEW] == R_PRIMARY && drbd_data_accessible(device, NEW))
				create_new_uuid = true;

			if (peer_disk_state[NEW] < D_UP_TO_DATE && test_bit(GOT_NEG_ACK, &peer_device->flags))
				clear_bit(GOT_NEG_ACK, &peer_device->flags);

			if (repl_state[OLD] > L_ESTABLISHED && repl_state[NEW] <= L_ESTABLISHED)
				clear_bit(SYNC_SRC_CRASHED_PRI, &peer_device->flags);
		}

		for_each_connection(connection, resource) {
			enum drbd_role *peer_role = connection->peer_role;
			enum drbd_conn_state *cstate = connection->cstate;
			if (peer_role[NEW] == R_PRIMARY)
				some_peer_is_primary = true;
			switch (cstate[NEW]) {
			case C_CONNECTED:
				if (atomic_read(&connection->active_ee_cnt)
				 || atomic_read(&connection->done_ee_cnt))
					some_peer_request_in_flight = true;
				break;
			case C_STANDALONE:
			case C_UNCONNECTED:
			case C_CONNECTING:
				/* maybe others are safe as well? which ones? */
				break;
			default:
				/* if we are connected, or just now disconnected,
				 * there may still be some request in flight. */
				some_peer_request_in_flight = true;
			}
			if (some_peer_is_primary && some_peer_request_in_flight)
				break;
		}

		if (disk_state[OLD] >= D_INCONSISTENT && disk_state[NEW] < D_INCONSISTENT &&
		    role[NEW] == R_PRIMARY && drbd_data_accessible(device, NEW))
			create_new_uuid = true;

		if (role[OLD] == R_SECONDARY && role[NEW] == R_PRIMARY)
			create_new_uuid = true;

		if (create_new_uuid)
			set_bit(__NEW_CUR_UUID, &device->flags);

		if (!(role[OLD] == R_PRIMARY && disk_state[OLD] < D_INCONSISTENT) &&
		     (role[NEW] == R_PRIMARY && disk_state[NEW] < D_INCONSISTENT))
			ensure_exposed_data_uuid(device);

		if (disk_state[NEW] != D_NEGOTIATING && get_ldev_if_state(device, D_DETACHING)) {
			u32 mdf = device->ldev->md.flags;
			bool graceful_detach = disk_state[NEW] == D_DETACHING && !test_bit(FORCE_DETACH, &device->flags);

			/* For now, always require a drbdmeta apply-al run,
			 * even if that ends up only re-initializing the AL */
			mdf &= ~MDF_AL_CLEAN;
			/* reset some flags to what we know now */
			mdf &= ~MDF_CRASHED_PRIMARY;
			if (test_bit(CRASHED_PRIMARY, &device->flags) ||
			    (role[NEW] == R_PRIMARY && !graceful_detach))
				mdf |= MDF_CRASHED_PRIMARY;
			mdf &= ~MDF_PRIMARY_LOST_QUORUM;
			if (test_bit(PRIMARY_LOST_QUORUM, &device->flags))
				mdf |= MDF_PRIMARY_LOST_QUORUM;
			/* Do not touch MDF_CONSISTENT if we are D_FAILED */
			if (disk_state[NEW] >= D_INCONSISTENT) {
				mdf &= ~(MDF_CONSISTENT | MDF_WAS_UP_TO_DATE);

				if (disk_state[NEW] > D_INCONSISTENT)
					mdf |= MDF_CONSISTENT;
				if (disk_state[NEW] > D_OUTDATED)
					mdf |= MDF_WAS_UP_TO_DATE;
			} else if ((disk_state[NEW] == D_FAILED || disk_state[NEW] == D_DETACHING) &&
				   mdf & MDF_WAS_UP_TO_DATE &&
				   primary_and_data_present(device)) {
				/* There are cases when we still can update meta-data even if disk
				   state is failed.... Clear MDF_WAS_UP_TO_DATE if appropriate */
				mdf &= ~MDF_WAS_UP_TO_DATE;
			}

/*
 * MDF_PRIMARY_IND  IS set: apply activity log after crash
 * MDF_PRIMARY_IND NOT set: do not apply, forget and re-initialize activity log after crash.
 * We want the MDF_PRIMARY_IND set *always* before our backend could possibly
 * be target of write requests, whether we are Secondary or Primary ourselves.
 *
 * We want to avoid to clear that flag just because we lost the connection to a
 * detached Primary, but before all in-flight IO was drained, because we may
 * have some dirty bits not yet persisted.
 *
 * We want it cleared only once we are *certain* that we no longer see any Primary,
 * are not Primary ourselves, AND all previously received WRITE (peer-) requests
 * have been processed, NOTHING is in flight against our backend anymore,
 * AND we have successfully written out any dirty bitmap pages.
 */
			/* set, if someone is/becomes primary */
			if (role[NEW] == R_PRIMARY || some_peer_is_primary)
				mdf |= MDF_PRIMARY_IND;
			/* clear, if */
			else if (/* NO peer requests in flight, AND */
			    !some_peer_request_in_flight &&
			    (graceful_detach ||
			     /* or everyone secondary ... */
			     (role[NEW] == R_SECONDARY && !some_peer_is_primary &&
			        /* ... and not detaching because of IO error. */
			      disk_state[NEW] >= D_INCONSISTENT)))
				mdf &= ~MDF_PRIMARY_IND;

			/* apply changed flags to md.flags,
			 * and "schedule" for write-out */
			if (mdf != device->ldev->md.flags) {
				device->ldev->md.flags = mdf;
				drbd_md_mark_dirty(device);
			}
			if (disk_state[OLD] < D_CONSISTENT && disk_state[NEW] >= D_CONSISTENT)
				drbd_set_exposed_data_uuid(device, device->ldev->md.current_uuid);
			put_ldev(device);
		}

		/* remember last attach time so request_timer_fn() won't
		 * kill newly established sessions while we are still trying to thaw
		 * previously frozen IO */
		if ((disk_state[OLD] == D_ATTACHING || disk_state[OLD] == D_NEGOTIATING) &&
		    disk_state[NEW] > D_NEGOTIATING)
			device->last_reattach_jif = jiffies;

		if (!device->have_quorum[OLD] && device->have_quorum[NEW])
			clear_bit(PRIMARY_LOST_QUORUM, &device->flags);

		if (resource_suspended[NEW] &&
		    !(role[OLD] == R_PRIMARY && !drbd_data_accessible(device, OLD)) &&
		     (role[NEW] == R_PRIMARY && !drbd_data_accessible(device, NEW)) &&
		    resource->res_opts.on_no_data == OND_IO_ERROR)
			unfreeze_io = true;

		if (!resource->fail_io[OLD] && resource->fail_io[NEW])
			unfreeze_io = true;

		if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY)
			clear_bit(NEW_CUR_UUID, &device->flags);
	}

	for_each_connection(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;
		enum drbd_role *peer_role = connection->peer_role;

		/* Receiver should clean up itself */
		if (cstate[OLD] != C_DISCONNECTING && cstate[NEW] == C_DISCONNECTING)
			drbd_thread_stop_nowait(&connection->receiver);

		/* Now the receiver finished cleaning up itself, it should die */
		if (cstate[OLD] != C_STANDALONE && cstate[NEW] == C_STANDALONE)
			drbd_thread_stop_nowait(&connection->receiver);

		/* Upon network failure, we need to restart the receiver. */
		if (cstate[OLD] >= C_CONNECTING &&
		    cstate[NEW] <= C_TEAR_DOWN && cstate[NEW] >= C_TIMEOUT)
			drbd_thread_restart_nowait(&connection->receiver);

		if (cstate[OLD] == C_CONNECTED && cstate[NEW] < C_CONNECTED)
			twopc_connection_down(connection);

		/* remember last connect time so request_timer_fn() won't
		 * kill newly established sessions while we are still trying to thaw
		 * previously frozen IO */
		if (cstate[OLD] < C_CONNECTED && cstate[NEW] == C_CONNECTED)
			connection->last_reconnect_jif = jiffies;

		if (resource_suspended[OLD]) {
			enum drbd_req_event walk_event = -1;

			/* If we resume IO without this connection, then we
			 * need to cancel suspended requests. */
			if ((!resource_suspended[NEW] || unfreeze_io) && cstate[NEW] < C_CONNECTED)
				walk_event = CANCEL_SUSPENDED_IO;
			/* On reconnection when we have been suspended we need
			 * to process suspended requests. If there are resyncs,
			 * that means that it was not a simple disconnect and
			 * reconnect, so we cannot resend. We must cancel
			 * instead. */
			else if (cstate[OLD] < C_CONNECTED && cstate[NEW] == C_CONNECTED)
				walk_event = has_starting_resyncs(connection) ? CANCEL_SUSPENDED_IO : RESEND;

			if (walk_event != -1)
				__tl_walk(resource, connection, &connection->req_not_net_done, walk_event);

			/* Since we are in finish_state_change(), and the state
			 * was previously not C_CONNECTED, the sender cannot
			 * have received any requests yet. So it will find any
			 * requests to resend when it rescans the transfer log. */
			if (walk_event == RESEND)
				wake_up(&connection->sender_work.q_wait);
		}

		if (cstate[OLD] == C_CONNECTED && cstate[NEW] < C_CONNECTED)
			set_bit(RECONNECT, &connection->flags);

		if (starting_resync && peer_role[NEW] == R_PRIMARY)
			apply_unacked_peer_requests(connection);

		if (peer_role[OLD] == R_PRIMARY && peer_role[NEW] == R_UNKNOWN)
			lost_a_primary_peer = true;

		if (cstate[OLD] == C_CONNECTED && cstate[NEW] < C_CONNECTED) {
			clear_bit(BARRIER_ACK_PENDING, &connection->flags);
			wake_up(&resource->barrier_wait);
		}
	}

	if (lost_a_primary_peer) {
		idr_for_each_entry(&resource->devices, device, vnr) {
			struct drbd_peer_device *peer_device;

			for_each_peer_device(peer_device, device) {
				enum drbd_repl_state repl_state = peer_device->repl_state[NEW];

				if (!test_bit(UNSTABLE_RESYNC, &peer_device->flags) &&
				    (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T) &&
				    !(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
				    !drbd_stable_sync_source_present(peer_device, NEW))
					set_bit(UNSTABLE_RESYNC, &peer_device->flags);
			}
		}
	}

	if ((resource_suspended[OLD] && !resource_suspended[NEW]) || unfreeze_io)
		__tl_walk(resource, NULL, NULL, COMPLETION_RESUMED);
}

static void abw_start_sync(struct drbd_device *device,
			   struct drbd_peer_device *peer_device, int rv)
{
	struct drbd_peer_device *pd;

	if (rv) {
		drbd_err(device, "Writing the bitmap failed not starting resync.\n");
		stable_change_repl_state(peer_device, L_ESTABLISHED, CS_VERBOSE);
		return;
	}

	switch (peer_device->repl_state[NOW]) {
	case L_STARTING_SYNC_T:
		/* Since the number of set bits changed and the other peer_devices are
		   lready in L_PAUSED_SYNC_T state, we need to set rs_total here */
		rcu_read_lock();
		for_each_peer_device_rcu(pd, device)
			initialize_resync(pd);
		rcu_read_unlock();

		if (peer_device->connection->agreed_pro_version < 110)
			stable_change_repl_state(peer_device, L_WF_SYNC_UUID, CS_VERBOSE);
		else
			drbd_start_resync(peer_device, L_SYNC_TARGET);
		break;
	case L_STARTING_SYNC_S:
		drbd_start_resync(peer_device, L_SYNC_SOURCE);
		break;
	default:
		break;
	}
}

int drbd_bitmap_io_from_worker(struct drbd_device *device,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *peer_device)
{
	int rv;

	D_ASSERT(device, current == device->resource->worker.task);

	/* open coded non-blocking drbd_suspend_io(device); */
	atomic_inc(&device->suspend_cnt);

	if (flags & BM_LOCK_SINGLE_SLOT)
		drbd_bm_slot_lock(peer_device, why, flags);
	else
		drbd_bm_lock(device, why, flags);
	rv = io_fn(device, peer_device);
	if (flags & BM_LOCK_SINGLE_SLOT)
		drbd_bm_slot_unlock(peer_device);
	else
		drbd_bm_unlock(device);

	drbd_resume_io(device);

	return rv;
}

static bool state_change_is_susp_fen(struct drbd_state_change *state_change,
					    enum which_state which)
{
	int n_connection;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change =
				&state_change->connections[n_connection];

		if (connection_state_change->susp_fen[which])
			return true;
	}

	return false;
}

static bool state_change_is_susp_quorum(struct drbd_state_change *state_change,
					       enum which_state which)
{
	struct drbd_resource *resource = state_change->resource[0].resource;
	int n_device;

	if (resource->res_opts.on_no_quorum != ONQ_SUSPEND_IO)
		return false;

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_device_state_change *device_state_change =
				&state_change->devices[n_device];

		if (!device_state_change->have_quorum[which])
			return true;
	}

	return false;
}

static bool resync_susp_comb_dep_sc(struct drbd_state_change *state_change,
				    unsigned int n_device, int n_connection,
				    enum which_state which)
{
	struct drbd_peer_device_state_change *peer_device_state_change =
		&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
	struct drbd_device_state_change *device_state_change = &state_change->devices[n_device];
	bool resync_susp_dependency = peer_device_state_change->resync_susp_dependency[which];
	bool resync_susp_other_c = peer_device_state_change->resync_susp_other_c[which];
	enum drbd_repl_state repl_state = peer_device_state_change->repl_state[which];
	enum drbd_disk_state disk_state = device_state_change->disk_state[which];

	return resync_susp_dependency || resync_susp_other_c ||
		((repl_state == L_SYNC_SOURCE || repl_state == L_PAUSED_SYNC_S)
		 && disk_state <= D_INCONSISTENT);
}

static union drbd_state state_change_word(struct drbd_state_change *state_change,
					  unsigned int n_device, int n_connection,
					  enum which_state which)
{
	struct drbd_resource_state_change *resource_state_change =
		&state_change->resource[0];
	struct drbd_device_state_change *device_state_change =
		&state_change->devices[n_device];
	union drbd_state state = { {
		.role = R_UNKNOWN,
		.peer = R_UNKNOWN,
		.conn = C_STANDALONE,
		.disk = D_UNKNOWN,
		.pdsk = D_UNKNOWN,
	} };

	state.role = resource_state_change->role[which];
	state.susp = resource_state_change->susp[which] || state_change_is_susp_quorum(state_change, which) ||
		resource_state_change->susp_uuid[which];
	state.susp_nod = resource_state_change->susp_nod[which];
	state.susp_fen = state_change_is_susp_fen(state_change, which);
	state.quorum = device_state_change->have_quorum[which];
	state.disk = device_state_change->disk_state[which];
	if (n_connection != -1) {
		struct drbd_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		struct drbd_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];

		state.peer = connection_state_change->peer_role[which];
		state.conn = peer_device_state_change->repl_state[which];
		if (state.conn <= L_OFF)
			state.conn = connection_state_change->cstate[which];
		state.pdsk = peer_device_state_change->disk_state[which];
		state.aftr_isp = resync_susp_comb_dep_sc(state_change, n_device, n_connection, which);
		state.peer_isp = peer_device_state_change->resync_susp_peer[which];
		state.user_isp = peer_device_state_change->resync_susp_user[which];
	}
	return state;
}

void notify_resource_state_change(struct sk_buff *skb,
				  unsigned int seq,
				  struct drbd_state_change *state_change,
				  enum drbd_notification_type type)
{
	struct drbd_resource_state_change *resource_state_change = state_change->resource;
	struct drbd_resource *resource = resource_state_change->resource;
	struct resource_info resource_info = {
		.res_role = resource_state_change->role[NEW],
		.res_susp = resource_state_change->susp[NEW],
		.res_susp_nod = resource_state_change->susp_nod[NEW],
		.res_susp_fen = state_change_is_susp_fen(state_change, NEW),
		.res_susp_quorum = state_change_is_susp_quorum(state_change, NEW) ||
			resource_state_change->susp_uuid[NEW],
		.res_fail_io = resource_state_change->fail_io[NEW],
	};

	notify_resource_state(skb, seq, resource, &resource_info, NULL, type);
}

void notify_connection_state_change(struct sk_buff *skb,
				    unsigned int seq,
				    struct drbd_connection_state_change *connection_state_change,
				    enum drbd_notification_type type)
{
	struct drbd_connection *connection = connection_state_change->connection;
	struct connection_info connection_info = {
		.conn_connection_state = connection_state_change->cstate[NEW],
		.conn_role = connection_state_change->peer_role[NEW],
	};

	notify_connection_state(skb, seq, connection, &connection_info, type);
}

void notify_device_state_change(struct sk_buff *skb,
				unsigned int seq,
				struct drbd_device_state_change *device_state_change,
				enum drbd_notification_type type)
{
	struct drbd_device *device = device_state_change->device;
	struct device_info device_info;
	device_state_change_to_info(&device_info, device_state_change);

	notify_device_state(skb, seq, device, &device_info, type);
}

void notify_peer_device_state_change(struct sk_buff *skb,
				     unsigned int seq,
				     struct drbd_peer_device_state_change *state_change,
				     enum drbd_notification_type type)
{
	struct drbd_peer_device *peer_device = state_change->peer_device;
	struct peer_device_info peer_device_info;
	peer_device_state_change_to_info(&peer_device_info, state_change);

	notify_peer_device_state(skb, seq, peer_device, &peer_device_info, type);
}

static void notify_state_change(struct drbd_state_change *state_change)
{
	struct drbd_resource_state_change *resource_state_change = &state_change->resource[0];
	bool resource_state_has_changed;
	unsigned int n_device, n_connection, n_peer_device, n_peer_devices;
	void (*last_func)(struct sk_buff *, unsigned int, void *,
			  enum drbd_notification_type) = NULL;
	void *last_arg = NULL;

#define HAS_CHANGED(state) ((state)[OLD] != (state)[NEW])
#define FINAL_STATE_CHANGE(type) \
	({ if (last_func) \
		last_func(NULL, 0, last_arg, type); \
	})
#define REMEMBER_STATE_CHANGE(func, arg, type) \
	({ FINAL_STATE_CHANGE(type | NOTIFY_CONTINUES); \
	   last_func = (typeof(last_func))func; \
	   last_arg = arg; \
	 })

	mutex_lock(&notification_mutex);

	resource_state_has_changed =
		HAS_CHANGED(resource_state_change->role) ||
		HAS_CHANGED(resource_state_change->susp) ||
		HAS_CHANGED(resource_state_change->susp_nod) ||
		HAS_CHANGED(resource_state_change->susp_uuid) ||
		state_change_is_susp_fen(state_change, OLD) !=
		state_change_is_susp_fen(state_change, NEW) ||
		state_change_is_susp_quorum(state_change, OLD) !=
		state_change_is_susp_quorum(state_change, NEW) ||
		HAS_CHANGED(resource_state_change->fail_io);

	if (resource_state_has_changed)
		REMEMBER_STATE_CHANGE(notify_resource_state_change,
				      state_change, NOTIFY_CHANGE);

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change =
				&state_change->connections[n_connection];

		if (HAS_CHANGED(connection_state_change->peer_role) ||
		    HAS_CHANGED(connection_state_change->cstate))
			REMEMBER_STATE_CHANGE(notify_connection_state_change,
					      connection_state_change, NOTIFY_CHANGE);
	}

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_device_state_change *device_state_change =
			&state_change->devices[n_device];

		if (HAS_CHANGED(device_state_change->disk_state) ||
		    HAS_CHANGED(device_state_change->have_quorum))
			REMEMBER_STATE_CHANGE(notify_device_state_change,
					      device_state_change, NOTIFY_CHANGE);
	}

	n_peer_devices = state_change->n_devices * state_change->n_connections;
	for (n_peer_device = 0; n_peer_device < n_peer_devices; n_peer_device++) {
		struct drbd_peer_device_state_change *p =
			&state_change->peer_devices[n_peer_device];

		if (HAS_CHANGED(p->disk_state) ||
		    HAS_CHANGED(p->repl_state) ||
		    HAS_CHANGED(p->resync_susp_user) ||
		    HAS_CHANGED(p->resync_susp_peer) ||
		    HAS_CHANGED(p->resync_susp_dependency) ||
		    HAS_CHANGED(p->resync_susp_other_c))
			REMEMBER_STATE_CHANGE(notify_peer_device_state_change,
					      p, NOTIFY_CHANGE);
	}

	FINAL_STATE_CHANGE(NOTIFY_CHANGE);
	mutex_unlock(&notification_mutex);

#undef HAS_CHANGED
#undef FINAL_STATE_CHANGE
#undef REMEMBER_STATE_CHANGE
}

static void send_role_to_all_peers(struct drbd_state_change *state_change)
{
	unsigned int n_connection;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		struct drbd_connection *connection = connection_state_change->connection;
		enum drbd_conn_state new_cstate = connection_state_change->cstate[NEW];

		if (new_cstate < C_CONNECTED)
			continue;

		if (connection->agreed_pro_version < 110) {
			unsigned int n_device;

			/* Before DRBD 9, the role is a device attribute
			 * instead of a resource attribute. */
			for (n_device = 0; n_device < state_change->n_devices; n_device++) {
				struct drbd_peer_device *peer_device =
					state_change->peer_devices[n_connection].peer_device;
				union drbd_state state =
					state_change_word(state_change, n_device, n_connection, NEW);

				drbd_send_state(peer_device, state);
			}
		} else {
			union drbd_state state = { {
				.role = state_change->resource[0].role[NEW],
			} };

			conn_send_state(connection, state);
		}
	}
}

static void send_new_state_to_all_peer_devices(struct drbd_state_change *state_change, int n_device)
{
	unsigned int n_connection;

	BUG_ON(state_change->n_devices <= n_device);
	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		struct drbd_peer_device *peer_device = peer_device_state_change->peer_device;
		union drbd_state new_state = state_change_word(state_change, n_device, n_connection, NEW);

		if (new_state.conn >= C_CONNECTED)
			drbd_send_state(peer_device, new_state);
	}
}

static bool receiver_exited_main_loop(struct drbd_connection *connection)
{
	enum drbd_conn_state cstate = connection->cstate[NOW];

	return cstate == C_STANDALONE || cstate == C_UNCONNECTED ||
		cstate == C_CONNECTING || cstate == C_CONNECTED;
}

void drbd_notify_peers_lost_primary(struct drbd_resource *resource)
{
	struct drbd_connection *connection, *lost_peer;
	u64 im;

	rcu_read_lock();
	for_each_connection_rcu(lost_peer, resource) {
		if (test_and_clear_bit(NOTIFY_PEERS_LOST_PRIMARY, &lost_peer->flags)) {
			rcu_read_unlock();
			goto found;
		}
	}
	rcu_read_unlock();
	return;
found:

	wait_event(resource->state_wait, receiver_exited_main_loop(lost_peer));
	for_each_connection_ref(connection, im, resource) {
		if (connection == lost_peer)
			continue;
		if (connection->cstate[NOW] == C_CONNECTED) {
			struct drbd_peer_device *peer_device;
			bool send_dagtag = false;
			int vnr;

			idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
				struct drbd_device *device = peer_device->device;
				u64 current_uuid = drbd_current_uuid(device);
				u64 weak_nodes = drbd_weak_nodes_device(device);

				if (device->disk_state[NOW] < D_INCONSISTENT ||
				    peer_device->disk_state[NOW] < D_INCONSISTENT)
					continue; /* Ignore if one side is diskless */

				drbd_send_current_uuid(peer_device, current_uuid, weak_nodes);
				send_dagtag = true;
			}

			if (send_dagtag)
				drbd_send_peer_dagtag(connection, lost_peer);
		}
	}
}

/* This function is supposed to have the same semantics as drbd_device_stable() in drbd_main.c
   A primary is stable since it is authoritative.
   Unstable are neighbors of a primary and resync target nodes.
   Nodes further away from a primary are stable! Do no confuse with "weak".*/
static bool calc_device_stable(struct drbd_state_change *state_change, int n_device, enum which_state which)
{
	int n_connection;

	if (state_change->resource->role[which] == R_PRIMARY)
		return true;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		enum drbd_role *peer_role = connection_state_change->peer_role;

		if (peer_role[which] == R_PRIMARY)
			return false;
	}

	return true;
}

static bool calc_resync_target(struct drbd_state_change *state_change, int n_device, enum which_state which)
{
	int n_connection;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		enum drbd_repl_state *repl_state = peer_device_state_change->repl_state;

		switch (repl_state[which]) {
		case L_WF_BITMAP_T:
		case L_SYNC_TARGET:
		case L_PAUSED_SYNC_T:
			return true;
		default:
			continue;
		}
	}

	return false;
}

/* takes old and new peer disk state */
static bool lost_contact_to_peer_data(enum drbd_disk_state *peer_disk_state)
{
	enum drbd_disk_state os = peer_disk_state[OLD];
	enum drbd_disk_state ns = peer_disk_state[NEW];

	return (os >= D_INCONSISTENT && os != D_UNKNOWN && os != D_OUTDATED)
		&& (ns < D_INCONSISTENT || ns == D_UNKNOWN || ns == D_OUTDATED);
}

static bool peer_returns_diskless(struct drbd_peer_device *peer_device,
				  enum drbd_disk_state os, enum drbd_disk_state ns)
{
	struct drbd_device *device = peer_device->device;
	bool rv = false;

	/* Scenario, starting with normal operation
	 * Connected Primary/Secondary UpToDate/UpToDate
	 * NetworkFailure Primary/Unknown UpToDate/DUnknown (frozen)
	 * ...
	 * Connected Primary/Secondary UpToDate/Diskless (resumed; needs to bump uuid!)
	 */

	if (get_ldev(device)) {
		if (os == D_UNKNOWN && (ns == D_DISKLESS || ns == D_FAILED || ns == D_OUTDATED) &&
		    drbd_bitmap_uuid(peer_device) == 0)
			rv = true;
		put_ldev(device);
	}
	return rv;
}

static void check_may_resume_io_after_fencing(struct drbd_state_change *state_change, int n_connection)
{
	struct drbd_connection_state_change *connection_state_change = &state_change->connections[n_connection];
	struct drbd_resource_state_change *resource_state_change = &state_change->resource[0];
	struct drbd_connection *connection = connection_state_change->connection;
	struct drbd_resource *resource = resource_state_change->resource;
	bool all_peer_disks_outdated = true;
	bool all_peer_disks_connected = true;
	struct drbd_peer_device *peer_device;
	unsigned long irq_flags;
	int vnr, n_device;

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		enum drbd_repl_state *repl_state = peer_device_state_change->repl_state;
		enum drbd_disk_state *peer_disk_state = peer_device_state_change->disk_state;

		if (peer_disk_state[NEW] > D_OUTDATED)
			all_peer_disks_outdated = false;
		if (repl_state[NEW] < L_ESTABLISHED)
			all_peer_disks_connected = false;
	}

	/* case1: The outdate peer handler is successful: */
	if (all_peer_disks_outdated) {
		rcu_read_lock();
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
			struct drbd_device *device = peer_device->device;
			if (test_and_clear_bit(NEW_CUR_UUID, &device->flags)) {
				kref_get(&device->kref);
				rcu_read_unlock();
				drbd_uuid_new_current(device, false);
				kref_put(&device->kref, drbd_destroy_device);
				rcu_read_lock();
			}
		}
		rcu_read_unlock();
		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		__change_io_susp_fencing(connection, false);
		end_state_change(resource, &irq_flags);
	}
	/* case2: The connection was established again: */
	if (all_peer_disks_connected) {
		rcu_read_lock();
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
			struct drbd_device *device = peer_device->device;
			clear_bit(NEW_CUR_UUID, &device->flags);
		}
		rcu_read_unlock();
		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		__change_io_susp_fencing(connection, false);
		end_state_change(resource, &irq_flags);
	}
}

static bool use_checksum_based_resync(struct drbd_connection *connection, struct drbd_device *device)
{
	bool csums_after_crash_only;
	rcu_read_lock();
	csums_after_crash_only = rcu_dereference(connection->transport.net_conf)->csums_after_crash_only;
	rcu_read_unlock();
	return connection->agreed_pro_version >= 89 &&		/* supported? */
		connection->csums_tfm &&			/* configured? */
		(csums_after_crash_only == false		/* use for each resync? */
		 || test_bit(CRASHED_PRIMARY, &device->flags));	/* or only after Primary crash? */
}

static void drbd_run_resync(struct drbd_peer_device *peer_device, enum drbd_repl_state repl_state)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_connection *connection = peer_device->connection;
	enum drbd_repl_state side = repl_is_sync_target(repl_state) ? L_SYNC_TARGET : L_SYNC_SOURCE;

	drbd_info(peer_device, "Began resync as %s (will sync %lu KB [%lu bits set]).\n",
			drbd_repl_str(repl_state),
			(unsigned long) peer_device->rs_total << (BM_BLOCK_SHIFT-10),
			(unsigned long) peer_device->rs_total);

	if (side == L_SYNC_TARGET)
		drbd_set_exposed_data_uuid(device, peer_device->current_uuid);

	/* Forget potentially stale cached per resync extent bit-counts. */
	drbd_rs_cancel_all(peer_device);

	peer_device->use_csums = side == L_SYNC_TARGET ?
		use_checksum_based_resync(connection, device) : false;

	if (side == L_SYNC_TARGET &&
			!(peer_device->uuid_flags & UUID_FLAG_STABLE) &&
			!drbd_stable_sync_source_present(peer_device, NOW))
		set_bit(UNSTABLE_RESYNC, &peer_device->flags);

	/* Since protocol 96, we must serialize drbd_gen_and_send_sync_uuid
	 * with w_send_oos, or the sync target will get confused as to
	 * how much bits to resync.  We cannot do that always, because for an
	 * empty resync and protocol < 95, we need to do it here, as we call
	 * drbd_resync_finished from here in that case.
	 * We drbd_gen_and_send_sync_uuid here for protocol < 96,
	 * and from after_state_ch otherwise. */
	if (side == L_SYNC_SOURCE && connection->agreed_pro_version < 96)
		drbd_gen_and_send_sync_uuid(peer_device);

	if (connection->agreed_pro_version < 95 && peer_device->rs_total == 0) {
		/* This still has a race (about when exactly the peers
		 * detect connection loss) that can lead to a full sync
		 * on next handshake. In 8.3.9 we fixed this with explicit
		 * resync-finished notifications, but the fix
		 * introduces a protocol change.  Sleeping for some
		 * time longer than the ping interval + timeout on the
		 * SyncSource, to give the SyncTarget the chance to
		 * detect connection loss, then waiting for a ping
		 * response (implicit in drbd_resync_finished) reduces
		 * the race considerably, but does not solve it. */
		if (side == L_SYNC_SOURCE) {
			struct net_conf *nc;
			int timeo;

			rcu_read_lock();
			nc = rcu_dereference(connection->transport.net_conf);
			timeo = nc->ping_int * HZ + nc->ping_timeo * HZ / 9;
			rcu_read_unlock();
			schedule_timeout_interruptible(timeo);
		}
		drbd_resync_finished(peer_device, D_MASK);
	}

	/* ns.conn may already be != peer_device->repl_state[NOW],
	 * we may have been paused in between, or become paused until
	 * the timer triggers.
	 * No matter, that is handled in resync_timer_fn() */
	if (repl_state == L_SYNC_TARGET || repl_state == L_PAUSED_SYNC_T)
		drbd_uuid_resync_starting(peer_device);

	drbd_md_sync_if_dirty(device);
}


/*
 * Perform after state change actions that may sleep.
 */
static int w_after_state_change(struct drbd_work *w, int unused)
{
	struct after_state_change_work *work =
		container_of(w, struct after_state_change_work, w);
	struct drbd_state_change *state_change = work->state_change;
	struct drbd_resource_state_change *resource_state_change = &state_change->resource[0];
	struct drbd_resource *resource = resource_state_change->resource;
	enum drbd_role *role = resource_state_change->role;
	bool *susp_uuid = resource_state_change->susp_uuid;
	struct drbd_peer_device *send_state_others = NULL;
	int n_device, n_connection;
	bool still_connected = false;
	bool try_become_up_to_date = false;

	notify_state_change(state_change);

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_device_state_change *device_state_change = &state_change->devices[n_device];
		struct drbd_device *device = device_state_change->device;
		enum drbd_disk_state *disk_state = device_state_change->disk_state;
		bool have_ldev = extra_ldev_ref_for_after_state_chg(disk_state);
		bool *have_quorum = device_state_change->have_quorum;
		bool effective_disk_size_determined = false;
		bool device_stable[2], resync_target[2];
		bool resync_finished = false;
		bool some_peer_demoted = false;
		bool new_current_uuid = false;
		enum which_state which;

		for (which = OLD; which <= NEW; which++) {
			device_stable[which] = calc_device_stable(state_change, n_device, which);
			resync_target[which] = calc_resync_target(state_change, n_device, which);
		}

		if (disk_state[NEW] == D_UP_TO_DATE)
			effective_disk_size_determined = true;

		for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
			struct drbd_peer_device_state_change *peer_device_state_change =
				&state_change->peer_devices[
					n_device * state_change->n_connections + n_connection];
			struct drbd_peer_device *peer_device = peer_device_state_change->peer_device;
			enum drbd_disk_state *peer_disk_state = peer_device_state_change->disk_state;
			enum drbd_repl_state *repl_state = peer_device_state_change->repl_state;

			if ((repl_state[OLD] == L_SYNC_TARGET || repl_state[OLD] == L_PAUSED_SYNC_T) &&
			    repl_state[NEW] == L_ESTABLISHED)
				resync_finished = true;

			if (disk_state[OLD] == D_INCONSISTENT && disk_state[NEW] == D_UP_TO_DATE &&
			    peer_disk_state[OLD] == D_INCONSISTENT && peer_disk_state[NEW] == D_UP_TO_DATE)
				send_state_others = peer_device;

			/* connect without resync or remote attach without resync */
			if (disk_state[NOW] >= D_OUTDATED && repl_state[NEW] == L_ESTABLISHED &&
			    ((repl_state[OLD] == L_OFF &&
			      (peer_disk_state[NEW] >= D_OUTDATED ||
			       (peer_disk_state[NEW] == D_DISKLESS && !want_bitmap(peer_device)))) ||
			     (peer_disk_state[OLD] == D_DISKLESS && peer_disk_state[NEW] >= D_OUTDATED))) {
				u64 peer_current_uuid = peer_device->current_uuid & ~UUID_PRIMARY;
				u64 my_current_uuid = drbd_current_uuid(device) & ~UUID_PRIMARY;

				if (peer_current_uuid == my_current_uuid && get_ldev(device)) {
					down_write(&device->uuid_sem);
					drbd_uuid_set_bitmap(peer_device, 0);
					up_write(&device->uuid_sem);
					drbd_print_uuids(peer_device, "cleared bm UUID and bitmap");
					drbd_bitmap_io_from_worker(device, &drbd_bmio_clear_one_peer,
								   "clearing bm one peer", BM_LOCK_CLEAR | BM_LOCK_BULK,
								   peer_device);
					put_ldev(device);
				}
			}
		}

		for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
			struct drbd_connection_state_change *connection_state_change = &state_change->connections[n_connection];
			struct drbd_connection *connection = connection_state_change->connection;
			enum drbd_conn_state *cstate = connection_state_change->cstate;
			enum drbd_role *peer_role = connection_state_change->peer_role;
			struct drbd_peer_device_state_change *peer_device_state_change =
				&state_change->peer_devices[
					n_device * state_change->n_connections + n_connection];
			struct drbd_peer_device *peer_device = peer_device_state_change->peer_device;
			enum drbd_repl_state *repl_state = peer_device_state_change->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device_state_change->disk_state;
			bool *resync_susp_user = peer_device_state_change->resync_susp_user;
			bool *resync_susp_peer = peer_device_state_change->resync_susp_peer;
			bool *resync_susp_dependency = peer_device_state_change->resync_susp_dependency;
			union drbd_state new_state =
				state_change_word(state_change, n_device, n_connection, NEW);
			bool send_uuids, send_state = false;

			/* In case we finished a resync as resync-target update all neighbors
			 * about having a bitmap_uuid of 0 towards the previous sync-source.
			 * That needs to go out before sending the new disk state
			 * to avoid a race where the other node might downgrade our disk
			 * state due to old UUID values.
			 *
			 * Also check the replication state to ensure that we
			 * do not send these extra UUIDs before the initial
			 * handshake. */
			send_uuids = resync_finished &&
				peer_disk_state[NEW] != D_UNKNOWN &&
				repl_state[NEW] > L_OFF;

			/* Send UUIDs again if they changed while establishing the connection */
			if (repl_state[OLD] == L_OFF && repl_state[NEW] > L_OFF &&
			    peer_device->comm_current_uuid != drbd_resolved_uuid(peer_device, NULL))
				send_uuids = true;

			if (calc_device_stable(state_change, n_device, OLD) !=
					calc_device_stable(state_change, n_device, NEW))
				send_uuids = true;

			if (send_uuids)
				drbd_send_uuids(peer_device, 0, 0);

			if (peer_disk_state[NEW] == D_UP_TO_DATE)
				effective_disk_size_determined = true;

			if (!(role[OLD] == R_PRIMARY && !drbd_data_accessible(device, OLD)) &&
			     (role[NEW] == R_PRIMARY && !drbd_data_accessible(device, NEW)) &&
			    !test_bit(UNREGISTERED, &device->flags))
				drbd_maybe_khelper(device, connection, "pri-on-incon-degr");

			/* Became sync source.  With protocol >= 96, we still need to send out
			 * the sync uuid now. Need to do that before any drbd_send_state, or
			 * the other side may go "paused sync" before receiving the sync uuids,
			 * which is unexpected. */
			if (!(repl_state[OLD] == L_SYNC_SOURCE || repl_state[OLD] == L_PAUSED_SYNC_S) &&
			     (repl_state[NEW] == L_SYNC_SOURCE || repl_state[NEW] == L_PAUSED_SYNC_S) &&
			    connection->agreed_pro_version >= 96 && connection->agreed_pro_version < 110 &&
			    get_ldev(device)) {
				drbd_gen_and_send_sync_uuid(peer_device);
				put_ldev(device);
			}

			/* Do not change the order of the if above and the two below... */
			if (peer_disk_state[OLD] < D_NEGOTIATING &&
			    peer_disk_state[NEW] == D_NEGOTIATING) { /* attach on the peer */
				/* we probably will start a resync soon.
				 * make sure those things are properly reset. */
				peer_device->rs_total = 0;
				peer_device->rs_failed = 0;
				atomic_set(&peer_device->rs_pending_cnt, 0);
				drbd_rs_cancel_all(peer_device);

				drbd_send_uuids(peer_device, 0, 0);
				drbd_send_state(peer_device, new_state);
			}
			/* No point in queuing send_bitmap if we don't have a connection
			 * anymore, so check also the _current_ state, not only the new state
			 * at the time this work was queued. */
			if (repl_state[OLD] != L_WF_BITMAP_S && repl_state[NEW] == L_WF_BITMAP_S &&
			    peer_device->repl_state[NOW] == L_WF_BITMAP_S)
				drbd_queue_bitmap_io(device, &drbd_send_bitmap, NULL,
						"send_bitmap (WFBitMapS)",
						BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK | BM_LOCK_SINGLE_SLOT,
						peer_device);

			if (peer_role[OLD] == R_PRIMARY && peer_role[NEW] == R_SECONDARY)
				some_peer_demoted = true;

			/* Last part of the attaching process ... */
			if (repl_state[NEW] >= L_ESTABLISHED &&
			    disk_state[OLD] == D_ATTACHING && disk_state[NEW] >= D_NEGOTIATING) {
				drbd_send_sizes(peer_device, 0, 0);  /* to start sync... */
				drbd_send_uuids(peer_device, 0, 0);
				drbd_send_state(peer_device, new_state);
			}

			/* Started resync, tell peer if drbd9 */
			if (repl_state[NEW] >= L_SYNC_SOURCE && repl_state[NEW] <= L_PAUSED_SYNC_T &&
			    (repl_state[OLD] < L_SYNC_SOURCE || repl_state[OLD] > L_PAUSED_SYNC_T))
				send_state = true;

			/* We want to pause/continue resync, tell peer. */
			if (repl_state[NEW] >= L_ESTABLISHED &&
			    ((resync_susp_comb_dep_sc(state_change, n_device, n_connection, OLD) !=
			      resync_susp_comb_dep_sc(state_change, n_device, n_connection, NEW)) ||
			     (resync_susp_user[OLD] != resync_susp_user[NEW])))
				send_state = true;

			/* finished resync, tell sync source */
			if ((repl_state[OLD] == L_SYNC_TARGET || repl_state[OLD] == L_PAUSED_SYNC_T) &&
			    repl_state[NEW] == L_ESTABLISHED)
				send_state = true;

			/* In case one of the isp bits got set, suspend other devices. */
			if (!(resync_susp_dependency[OLD] || resync_susp_peer[OLD] || resync_susp_user[OLD]) &&
			     (resync_susp_dependency[NEW] || resync_susp_peer[NEW] || resync_susp_user[NEW]))
				suspend_other_sg(device);

			/* Make sure the peer gets informed about eventual state
			   changes (ISP bits) while we were in L_OFF. */
			if (repl_state[OLD] == L_OFF && repl_state[NEW] >= L_ESTABLISHED)
				send_state = true;

			if (repl_state[OLD] != L_AHEAD && repl_state[NEW] == L_AHEAD)
				send_state = true;

			/* We are in the progress to start a full sync. SyncTarget sets all slots. */
			if (repl_state[OLD] != L_STARTING_SYNC_T && repl_state[NEW] == L_STARTING_SYNC_T)
				drbd_queue_bitmap_io(device,
					&drbd_bmio_set_all_n_write, &abw_start_sync,
					"set_n_write from StartingSync",
					BM_LOCK_CLEAR | BM_LOCK_BULK,
					peer_device);

			/* We are in the progress to start a full sync. SyncSource one slot. */
			if (repl_state[OLD] != L_STARTING_SYNC_S && repl_state[NEW] == L_STARTING_SYNC_S)
				drbd_queue_bitmap_io(device,
					&drbd_bmio_set_n_write, &abw_start_sync,
					"set_n_write from StartingSync",
					BM_LOCK_CLEAR | BM_LOCK_BULK,
					peer_device);

			/* Disks got bigger while they were detached */
			if (disk_state[NEW] > D_NEGOTIATING && peer_disk_state[NEW] > D_NEGOTIATING &&
			    test_and_clear_bit(RESYNC_AFTER_NEG, &peer_device->flags)) {
				if (repl_state[NEW] == L_ESTABLISHED)
					resync_after_online_grow(peer_device);
			}

			/* A resync finished or aborted, wake paused devices... */
			if ((repl_state[OLD] > L_ESTABLISHED && repl_state[NEW] <= L_ESTABLISHED) ||
			    (resync_susp_peer[OLD] && !resync_susp_peer[NEW]) ||
			    (resync_susp_user[OLD] && !resync_susp_user[NEW]))
				resume_next_sg(device);

			/* sync target done with resync. Explicitly notify all peers. Our sync
			   source should even know by himself, but the others need that info. */
			if (disk_state[OLD] < D_UP_TO_DATE && repl_state[OLD] >= L_SYNC_SOURCE && repl_state[NEW] == L_ESTABLISHED)
				send_new_state_to_all_peer_devices(state_change, n_device);

			/* Outdated myself, or became D_UP_TO_DATE tell peers
			 * Do not do it, when the local node was forced from R_SECONDARY to R_PRIMARY,
			 * because that is part of the 2-phase-commit and that is necessary to trigger
			 * the initial resync. */
			if ((disk_state[NEW] >= D_INCONSISTENT && disk_state[NEW] != disk_state[OLD] &&
			     repl_state[OLD] >= L_ESTABLISHED && repl_state[NEW] >= L_ESTABLISHED) &&
			    !(role[OLD] == R_SECONDARY && role[NEW] == R_PRIMARY))
				send_state = true;

			/* Skipped resync with peer_device, tell others... */
			if (send_state_others && send_state_others != peer_device)
				send_state = true;

			/* This triggers bitmap writeout of potentially still unwritten pages
			 * if the resync finished cleanly, or aborted because of peer disk
			 * failure, or on transition from resync back to AHEAD/BEHIND.
			 *
			 * Connection loss is handled in conn_disconnect() by the receiver.
			 *
			 * For resync aborted because of local disk failure, we cannot do
			 * any bitmap writeout anymore.
			 *
			 * No harm done if some bits change during this phase.
			 */
			if ((repl_state[OLD] > L_ESTABLISHED && repl_state[OLD] < L_AHEAD) &&
			    (repl_state[NEW] == L_ESTABLISHED || repl_state[NEW] >= L_AHEAD) &&
			    get_ldev(device)) {
				drbd_queue_bitmap_io(device, &drbd_bm_write_copy_pages, NULL,
					"write from resync_finished", BM_LOCK_BULK,
					NULL);
				put_ldev(device);
			}

			/* Verify finished, or reached stop sector.  Peer did not know about
			 * the stop sector, and we may even have changed the stop sector during
			 * verify to interrupt/stop early.  Send the new state. */
			if (repl_state[OLD] == L_VERIFY_S && repl_state[NEW] == L_ESTABLISHED
			    && verify_can_do_stop_sector(peer_device))
				send_new_state_to_all_peer_devices(state_change, n_device);

			if (disk_state[NEW] == D_DISKLESS &&
			    cstate[NEW] == C_STANDALONE &&
			    role[NEW] == R_SECONDARY) {
				if (resync_susp_dependency[OLD] != resync_susp_dependency[NEW])
					resume_next_sg(device);
			}

			if (device_stable[OLD] && !device_stable[NEW] &&
			    repl_state[NEW] >= L_ESTABLISHED && get_ldev(device)) {
				/* Inform peers about being unstable...
				   Maybe it would be a better idea to have the stable bit as
				   part of the state (and being sent with the state) */
				drbd_send_uuids(peer_device, 0, 0);
				put_ldev(device);
			}

			if (send_state)
				drbd_send_state(peer_device, new_state);

			if (((!device_stable[OLD] && device_stable[NEW]) ||
			     (resync_target[OLD] && !resync_target[NEW] && device_stable[NEW])) &&
			    !(repl_state[OLD] == L_SYNC_TARGET || repl_state[OLD] == L_PAUSED_SYNC_T) &&
			    !(peer_role[OLD] == R_PRIMARY) && disk_state[NEW] >= D_OUTDATED &&
			    repl_state[NEW] >= L_ESTABLISHED &&
			    get_ldev(device)) {
				/* Offer all peers a resync, with the exception of ...
				   ... the node that made me up-to-date (with a resync)
				   ... I was primary
				   ... the peer that transitioned from primary to secondary
				*/
				drbd_send_uuids(peer_device, UUID_FLAG_GOT_STABLE, 0);
				put_ldev(device);
			}

			if (peer_disk_state[OLD] == D_UP_TO_DATE &&
			    (peer_disk_state[NEW] == D_FAILED || peer_disk_state[NEW] == D_INCONSISTENT) &&
			    test_and_clear_bit(NEW_CUR_UUID, &device->flags))
				/* When a peer disk goes from D_UP_TO_DATE to D_FAILED or D_INCONSISTENT
				   we know that a write failed on that node. Therefore we need to create
				   the new UUID right now (not wait for the next write to come in) */
				new_current_uuid = true;

			if (disk_state[OLD] > D_FAILED && disk_state[NEW] == D_FAILED &&
			    role[NEW] == R_PRIMARY && test_and_clear_bit(NEW_CUR_UUID, &device->flags))
				new_current_uuid = true;

			if (repl_state[OLD] != L_VERIFY_S && repl_state[NEW] == L_VERIFY_S) {
				drbd_info(peer_device, "Starting Online Verify from sector %llu\n",
						(unsigned long long)peer_device->ov_position);
				drbd_queue_work_if_unqueued(
						&peer_device->connection->sender_work,
						&peer_device->resync_work);
			}

			if (!repl_is_sync(repl_state[OLD]) && repl_is_sync(repl_state[NEW]))
				drbd_run_resync(peer_device, repl_state[NEW]);

			if (!peer_device_state_change->resync_active[OLD] && peer_device_state_change->resync_active[NEW])
				drbd_queue_work_if_unqueued(
						&peer_device->connection->sender_work,
						&peer_device->resync_work);
		}

		if (((role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY) || some_peer_demoted) &&
		    get_ldev(device)) {
			/* The some_peer_demoted case is superseded by
			 * handle_neighbor_demotion(). We keep this call for
			 * compatibility until support for protocol version 121
			 * is removed.
			 *
			 * No changes to the bitmap expected after this point, so write out any
			 * changes up to now to ensure that the metadata disk has the full
			 * bitmap content. Even if the bitmap changes (e.g. it was dual primary)
			 * no harm was done if it did change. */
			drbd_bitmap_io_from_worker(device, &drbd_bm_write,
						   "demote", BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,
						   NULL);
			put_ldev(device);
		}

		/* Make sure the effective disk size is stored in the metadata
		 * if a local disk is attached and either the local disk state
		 * or a peer disk state is D_UP_TO_DATE.  */
		if (effective_disk_size_determined && get_ldev(device)) {
			sector_t size = get_capacity(device->vdisk);
			if (device->ldev->md.effective_size != size) {
				char ppb[10];

				drbd_info(device, "size = %s (%llu KB)\n", ppsize(ppb, size >> 1),
				     (unsigned long long)size >> 1);
				device->ldev->md.effective_size = size;
				drbd_md_mark_dirty(device);
			}
			put_ldev(device);
		}

		/* first half of local IO error, failure to attach,
		 * or administrative detach */
		if ((disk_state[OLD] != D_FAILED && disk_state[NEW] == D_FAILED) ||
		    (disk_state[OLD] != D_DETACHING && disk_state[NEW] == D_DETACHING)) {
			enum drbd_io_error_p eh = EP_PASS_ON;
			int was_io_error = 0;

			/* Our cleanup here with the transition to D_DISKLESS.
			 * It is still not safe to dereference ldev here, since
			 * we might come from an failed Attach before ldev was set. */
			if (have_ldev && device->ldev) {
				rcu_read_lock();
				eh = rcu_dereference(device->ldev->disk_conf)->on_io_error;
				rcu_read_unlock();

				was_io_error = disk_state[NEW] == D_FAILED;

				/* Intentionally call this handler first, before drbd_send_state().
				 * See: 2932204 drbd: call local-io-error handler early
				 * People may chose to hard-reset the box from this handler.
				 * It is useful if this looks like a "regular node crash". */
				if (was_io_error && eh == EP_CALL_HELPER)
					drbd_maybe_khelper(device, NULL, "local-io-error");

				/* Immediately allow completion of all application IO,
				 * that waits for completion from the local disk,
				 * if this was a force-detach due to disk_timeout
				 * or administrator request (drbdsetup detach --force).
				 * Do NOT abort otherwise.
				 * Aborting local requests may cause serious problems,
				 * if requests are completed to upper layers already,
				 * and then later the already submitted local bio completes.
				 * This can cause DMA into former bio pages that meanwhile
				 * have been re-used for other things.
				 * So aborting local requests may cause crashes,
				 * or even worse, silent data corruption.
				 */
				if (test_and_clear_bit(FORCE_DETACH, &device->flags))
					tl_abort_disk_io(device);

				send_new_state_to_all_peer_devices(state_change, n_device);

				for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
					struct drbd_peer_device_state_change *peer_device_state_change =
						&state_change->peer_devices[
							n_device * state_change->n_connections + n_connection];
					struct drbd_peer_device *peer_device = peer_device_state_change->peer_device;
					drbd_rs_cancel_all(peer_device);
				}

				/* In case we want to get something to stable storage still,
				 * this may be the last chance.
				 * Following put_ldev may transition to D_DISKLESS. */
				drbd_bitmap_io_from_worker(device, &drbd_bm_write,
						"detach", BM_LOCK_SET | BM_LOCK_CLEAR | BM_LOCK_BULK,
						NULL);
				drbd_md_sync_if_dirty(device);
			}
		}

		/* second half of local IO error, failure to attach,
		 * or administrative detach,
		 * after local_cnt references have reached zero again */
		if (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS) {
			/* We must still be diskless,
			 * re-attach has to be serialized with this! */
			if (device->disk_state[NOW] != D_DISKLESS)
				drbd_err(device,
					"ASSERT FAILED: disk is %s while going diskless\n",
					drbd_disk_str(device->disk_state[NOW]));

			/* we may need to cancel the md_sync timer */
			del_timer_sync(&device->md_sync_timer);

			if (have_ldev)
				send_new_state_to_all_peer_devices(state_change, n_device);
		}

		if (have_ldev)
			put_ldev(device);

		/* Notify peers that I had a local IO error and did not detach. */
		if (disk_state[OLD] == D_UP_TO_DATE && disk_state[NEW] == D_INCONSISTENT)
			send_new_state_to_all_peer_devices(state_change, n_device);

		if (disk_state[OLD] == D_UP_TO_DATE && disk_state[NEW] == D_CONSISTENT &&
		    may_return_to_up_to_date(device, NOW))
			try_become_up_to_date = true;

		if (test_bit(TRY_TO_GET_RESYNC, &device->flags)) {
			/* Got connected to a diskless primary */
			clear_bit(TRY_TO_GET_RESYNC, &device->flags);
			drbd_try_to_get_resynced(device);
		}

		drbd_md_sync_if_dirty(device);

		if (role[NEW] == R_PRIMARY && have_quorum[OLD] && !have_quorum[NEW])
			drbd_maybe_khelper(device, NULL, "quorum-lost");

		if (!susp_uuid[OLD] && susp_uuid[NEW] &&
		    test_and_clear_bit(NEW_CUR_UUID, &device->flags))
			new_current_uuid = true;

		if (new_current_uuid)
			drbd_uuid_new_current(device, false);
	}

	if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY)
		send_role_to_all_peers(state_change);

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change = &state_change->connections[n_connection];
		struct drbd_connection *connection = connection_state_change->connection;
		enum drbd_conn_state *cstate = connection_state_change->cstate;
		enum drbd_role *peer_role = connection_state_change->peer_role;
		bool *susp_fen = connection_state_change->susp_fen;

		/* Upon network configuration, we need to start the receiver */
		if (cstate[OLD] == C_STANDALONE && cstate[NEW] == C_UNCONNECTED)
			drbd_thread_start(&connection->receiver);

		if (susp_fen[NEW])
			check_may_resume_io_after_fencing(state_change, n_connection);

		if (peer_role[OLD] == R_PRIMARY &&
		    cstate[OLD] == C_CONNECTED && cstate[NEW] < C_CONNECTED) {
			/* A connection to a primary went down, notify other peers about that */
			set_bit(NOTIFY_PEERS_LOST_PRIMARY, &connection->flags);
		}
	}

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change = &state_change->connections[n_connection];
		enum drbd_conn_state *cstate = connection_state_change->cstate;

		if (cstate[NEW] == C_CONNECTED || cstate[NEW] == C_CONNECTING)
			still_connected = true;
	}

	if (!susp_uuid[OLD] && susp_uuid[NEW]) {
		unsigned long irq_flags;

		begin_state_change(resource, &irq_flags, CS_VERBOSE);
		resource->susp_uuid[NEW] = false;
		end_state_change(resource, &irq_flags);
	}

	if (try_become_up_to_date)
		drbd_post_work(resource, TRY_BECOME_UP_TO_DATE);
	else
		drbd_notify_peers_lost_primary(resource);

	if (!still_connected)
		mod_timer_pending(&resource->twopc_timer, jiffies);

	if (work->done)
		complete(work->done);
	forget_state_change(state_change);
	kfree(work);

	return 0;
}

static bool local_state_change(enum chg_state_flags flags)
{
	return flags & (CS_HARD | CS_LOCAL_ONLY);
}

static enum drbd_state_rv
__peer_request(struct drbd_connection *connection, int vnr,
	       union drbd_state mask, union drbd_state val)
{
	enum drbd_state_rv rv = SS_SUCCESS;

	if (connection->cstate[NOW] == C_CONNECTED) {
		enum drbd_packet cmd = (vnr == -1) ? P_CONN_ST_CHG_REQ : P_STATE_CHG_REQ;
		if (!conn_send_state_req(connection, vnr, cmd, mask, val)) {
			set_bit(TWOPC_PREPARED, &connection->flags);
			rv = SS_CW_SUCCESS;
		}
	}
	return rv;
}

static enum drbd_state_rv __peer_reply(struct drbd_connection *connection)
{
	if (test_and_clear_bit(TWOPC_NO, &connection->flags))
		return SS_CW_FAILED_BY_PEER;
	if (test_and_clear_bit(TWOPC_YES, &connection->flags) ||
	    !test_bit(TWOPC_PREPARED, &connection->flags))
		return SS_CW_SUCCESS;

	/* This is DRBD 9.x <-> 8.4 compat code.
	 * Consistent with __peer_request() above:
	 * No more connection: fake success. */
	if (connection->cstate[NOW] != C_CONNECTED)
		return SS_SUCCESS;
	return SS_UNKNOWN_ERROR;
}

static bool when_done_lock(struct drbd_resource *resource,
			   unsigned long *irq_flags)
{
	write_lock_irqsave(&resource->state_rwlock, *irq_flags);
	if (!resource->remote_state_change && resource->twopc_work.cb == NULL)
		return true;
	write_unlock_irqrestore(&resource->state_rwlock, *irq_flags);
	return false;
}

/**
 * complete_remote_state_change  -  Wait for other remote state changes to complete
 */
static void complete_remote_state_change(struct drbd_resource *resource,
					 unsigned long *irq_flags)
{
	if (resource->remote_state_change) {
		enum chg_state_flags flags = resource->state_change_flags;

		begin_remote_state_change(resource, irq_flags);
		for(;;) {
			long t = twopc_timeout(resource);

			t = wait_event_timeout(resource->twopc_wait,
				   when_done_lock(resource, irq_flags), t);
			if (t)
				break;
			if (when_done_lock(resource, irq_flags)) {
				drbd_info(resource, "Two-phase commit: "
					  "not woken up in time\n");
				break;
			}
		}
		__end_remote_state_change(resource, flags);
	}
}

static enum drbd_state_rv
change_peer_state(struct drbd_connection *connection, int vnr,
		  union drbd_state mask, union drbd_state val, unsigned long *irq_flags)
{
	struct drbd_resource *resource = connection->resource;
	enum chg_state_flags flags = resource->state_change_flags | CS_TWOPC;
	enum drbd_state_rv rv;

	if (!expect(resource, flags & CS_SERIALIZE))
		return SS_CW_FAILED_BY_PEER;

	complete_remote_state_change(resource, irq_flags);

	resource->remote_state_change = true;
	resource->twopc_reply.initiator_node_id = resource->res_opts.node_id;
	resource->twopc_reply.tid = 0;
	begin_remote_state_change(resource, irq_flags);
	rv = __peer_request(connection, vnr, mask, val);
	if (rv == SS_CW_SUCCESS) {
		wait_event(resource->state_wait,
			((rv = __peer_reply(connection)) != SS_UNKNOWN_ERROR));
		clear_bit(TWOPC_PREPARED, &connection->flags);
	}
	end_remote_state_change(resource, irq_flags, flags);
	return rv;
}

static enum drbd_state_rv
__cluster_wide_request(struct drbd_resource *resource, int vnr, enum drbd_packet cmd,
		       struct p_twopc_request *request, u64 reach_immediately)
{
	struct drbd_connection *connection;
	enum drbd_state_rv rv = SS_SUCCESS;
	u64 im;

	for_each_connection_ref(connection, im, resource) {
		u64 mask;
		int err;

		clear_bit(TWOPC_PREPARED, &connection->flags);

		if (connection->agreed_pro_version < 110)
			continue;
		mask = NODE_MASK(connection->peer_node_id);
		if (reach_immediately & mask)
			set_bit(TWOPC_PREPARED, &connection->flags);
		else
			continue;

		clear_bit(TWOPC_YES, &connection->flags);
		clear_bit(TWOPC_NO, &connection->flags);
		clear_bit(TWOPC_RETRY, &connection->flags);

		err = conn_send_twopc_request(connection, vnr, cmd, request);
		if (err) {
			clear_bit(TWOPC_PREPARED, &connection->flags);
			wake_up(&resource->work.q_wait);
			continue;
		}
		if (cmd == P_TWOPC_PREPARE || cmd == P_TWOPC_PREP_RSZ)
			request_ping(connection);
		rv = SS_CW_SUCCESS;
	}
	return rv;
}

bool drbd_twopc_between_peer_and_me(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	struct twopc_reply *o = &resource->twopc_reply;

	return (o->target_node_id == resource->res_opts.node_id &&
		o->initiator_node_id == connection->peer_node_id) ||
		(o->target_node_id == connection->peer_node_id &&
		 o->initiator_node_id == resource->res_opts.node_id);
}

bool cluster_wide_reply_ready(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool connect_ready = true;
	bool have_no = resource->twopc_reply.state_change_failed;
	bool have_retry = false;
	bool all_yes = true;

	if (test_bit(TWOPC_ABORT_LOCAL, &resource->flags))
		return true;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->agreed_pro_version >= 118 &&
				!idr_is_empty(&resource->devices) &&
				resource->twopc_reply.is_connect &&
				drbd_twopc_between_peer_and_me(connection) &&
				!test_bit(CONN_HANDSHAKE_READY, &connection->flags))
			connect_ready = false;

		if (!test_bit(TWOPC_PREPARED, &connection->flags))
			continue;
		if (test_bit(TWOPC_NO, &connection->flags))
			have_no = true;
		if (test_bit(TWOPC_RETRY, &connection->flags))
			have_retry = true;
		if (!test_bit(TWOPC_YES, &connection->flags))
			all_yes = false;
	}
	rcu_read_unlock();

	return have_retry || (connect_ready && (have_no || all_yes));
}

static enum drbd_state_rv get_cluster_wide_reply(struct drbd_resource *resource,
						 struct change_context *context)
{
	struct drbd_connection *connection, *failed_by = NULL;
	bool handshake_disconnect = false;
	bool handshake_retry = false;
	bool have_no = resource->twopc_reply.state_change_failed;
	bool have_retry = false;
	enum drbd_state_rv rv = SS_CW_SUCCESS;

	if (test_bit(TWOPC_ABORT_LOCAL, &resource->flags))
		return SS_CONCURRENT_ST_CHG;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (resource->twopc_reply.is_connect &&
				drbd_twopc_between_peer_and_me(connection)) {
			if (test_bit(CONN_HANDSHAKE_DISCONNECT, &connection->flags))
				handshake_disconnect = true;
			if (test_bit(CONN_HANDSHAKE_RETRY, &connection->flags))
				handshake_retry = true;
		}

		if (!test_bit(TWOPC_PREPARED, &connection->flags))
			continue;
		if (test_bit(TWOPC_NO, &connection->flags)) {
			failed_by = connection;
			have_no = true;
		}
		if (test_bit(TWOPC_RETRY, &connection->flags))
			have_retry = true;
	}

	if (have_retry)
		rv = SS_CONCURRENT_ST_CHG;
	else if (handshake_retry)
		rv = SS_HANDSHAKE_RETRY;
	else if (handshake_disconnect)
		rv = SS_HANDSHAKE_DISCONNECT;
	else if (have_no) {
		if (context && failed_by)
			_drbd_state_err(context, "Declined by peer %s (id: %d), see the kernel log there",
					rcu_dereference(failed_by->transport.net_conf)->name,
					failed_by->peer_node_id);
		rv = SS_CW_FAILED_BY_PEER;
	}
	rcu_read_unlock();
	return rv;
}

static bool supports_two_phase_commit(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool supported = true;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] != C_CONNECTED)
			continue;
		if (connection->agreed_pro_version < 110) {
			supported = false;
			break;
		}
	}
	rcu_read_unlock();

	return supported;
}

static struct drbd_connection *get_first_connection(struct drbd_resource *resource)
{
	struct drbd_connection *connection = NULL;

	rcu_read_lock();
	if (!list_empty(&resource->connections)) {
		connection = first_connection(resource);
		kref_get(&connection->kref);
	}
	rcu_read_unlock();
	return connection;
}

/* That two_primaries is a connection option is one of those things of
   the past, that should be cleaned up!! it should be a resource config!
   Here is a inaccurate heuristic */
static bool multiple_primaries_allowed(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	bool allowed = false;
	struct net_conf *nc;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		nc = rcu_dereference(connection->transport.net_conf);
		if (nc && nc->two_primaries) {
			allowed = true;
			break;
		}
	}
	rcu_read_unlock();

	return allowed;
}

static enum drbd_state_rv
check_primaries_distances(struct drbd_resource *resource)
{
	struct twopc_reply *reply = &resource->twopc_reply;
	int nr_primaries = hweight64(reply->primary_nodes);
	u64 common_server;

	if (nr_primaries <= 1)
		return SS_SUCCESS;
	if (nr_primaries > 1 && !multiple_primaries_allowed(resource))
		return SS_TWO_PRIMARIES;
	/* All primaries directly connected. Good */
	if (!(reply->primary_nodes & reply->weak_nodes))
		return SS_SUCCESS;

	/* For virtualization setups with diskless hypervisors (R_PRIMARY) and one
	   or multiple storage servers (R_SECONDARY) allow live-migration between the
	   hypervisors. */
	common_server = ~reply->weak_nodes;
	if (common_server) {
		int node_id;
		/* Only allow if the new primary is diskless. See also far_away_change()
		   in drbd_receiver.c for the diskless check on the other primary */
		if ((reply->primary_nodes & NODE_MASK(resource->res_opts.node_id)) &&
		    drbd_have_local_disk(resource))
			return SS_WEAKLY_CONNECTED;

		for (node_id = 0; node_id < DRBD_NODE_ID_MAX; node_id++) {
			struct drbd_connection *connection;
			struct net_conf *nc;
			bool two_primaries;

			if (!(common_server & NODE_MASK(node_id)))
				continue;
			connection = drbd_connection_by_node_id(resource, node_id);
			if (!connection)
				continue;

			rcu_read_lock();
			nc = rcu_dereference(connection->transport.net_conf);
			two_primaries = nc ? nc->two_primaries : false;
			rcu_read_unlock();

			if (!two_primaries)
				return SS_TWO_PRIMARIES;
		}

		return SS_SUCCESS;
	}
	return SS_WEAKLY_CONNECTED;
}

static enum drbd_state_rv
check_ro_cnt_and_primary(struct drbd_resource *resource)
{
	struct twopc_reply *reply = &resource->twopc_reply;
	struct drbd_connection *connection;
	enum drbd_state_rv rv = SS_SUCCESS;
	int rw_count, ro_count;
	struct net_conf *nc;

	drbd_open_counts(resource, &rw_count, &ro_count);

	if (!rw_count && !ro_count)
		return rv;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		nc = rcu_dereference(connection->transport.net_conf);
		if (!nc->two_primaries &&
		    NODE_MASK(connection->peer_node_id) & reply->primary_nodes) {
			rv = SS_PRIMARY_READER;
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

long twopc_retry_timeout(struct drbd_resource *resource, int retries)
{
	struct drbd_connection *connection;
	int connections = 0;
	long timeout = 0;

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (connection->cstate[NOW] < C_CONNECTING)
			continue;
		connections++;
	}
	rcu_read_unlock();

	if (connections > 0) {
		if (retries > 5)
			retries = 5;
		timeout = resource->res_opts.twopc_retry_timeout *
			  HZ / 10 * connections * (1 << retries);
		timeout = prandom_u32() % timeout;
	}
	return timeout;
}

void abort_connect(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (test_and_clear_bit(HOLDING_UUID_READ_LOCK, &peer_device->flags))
			up_read_non_owner(&peer_device->device->uuid_sem);
		clear_bit(INITIAL_STATE_SENT, &peer_device->flags);
		clear_bit(INITIAL_STATE_RECEIVED, &peer_device->flags);
		clear_bit(UUIDS_RECEIVED, &peer_device->flags);
		clear_bit(CURRENT_UUID_RECEIVED, &peer_device->flags);
	}
	rcu_read_unlock();
}

static void twopc_phase2(struct drbd_resource *resource, int vnr,
			 bool success,
			 struct p_twopc_request *request,
			 u64 reach_immediately)
{
	enum drbd_packet twopc_cmd = success ? P_TWOPC_COMMIT : P_TWOPC_ABORT;
	struct drbd_connection *connection;
	u64 im;

	for_each_connection_ref(connection, im, resource) {
		u64 mask = NODE_MASK(connection->peer_node_id);
		if (!(reach_immediately & mask))
			continue;

		conn_send_twopc_request(connection, vnr, twopc_cmd, request);
	}
}

/**
 * change_cluster_wide_state  -  Cluster-wide two-phase commit
 *
 * Perform a two-phase commit transaction among all (reachable) nodes in the
 * cluster.  In our transaction model, the initiator of a transaction is also
 * the coordinator.
 *
 * In phase one of the transaction, the coordinator sends all nodes in the
 * cluster a P_TWOPC_PREPARE packet.  Each node replies with either P_TWOPC_YES
 * if it consents or with P_TWOPC_NO if it denies the transaction.  Once all
 * replies have been received, the coordinator sends all nodes in the cluster a
 * P_TWOPC_COMMIT or P_TWOPC_ABORT packet to finish the transaction.
 *
 * When a node in the cluster is busy with another transaction, it replies with
 * P_TWOPC_NO.  The coordinator is then responsible for retrying the
 * transaction.
 *
 * Since a cluster is not guaranteed to always be fully connected, some nodes
 * will not be directly reachable from other nodes.  In order to still reach
 * all nodes in the cluster, participants will forward requests to nodes which
 * haven't received the request yet:
 *
 * The nodes_to_reach field in requests indicates which nodes have received the
 * request already.  Before forwarding a request to a peer, a node removes
 * itself from nodes_to_reach; it then sends the request to all directly
 * connected nodes in nodes_to_reach.
 *
 * If there are redundant paths in the cluster, requests will reach some nodes
 * more than once.  Nodes remember when they are taking part in a transaction;
 * they detect duplicate requests and reply to them with P_TWOPC_YES packets.
 * (Transactions are identified by the node id of the initiator and a random,
 * unique-enough transaction identifier.)
 *
 * A configurable timeout determines how long a coordinator or participant will
 * wait for a transaction to finish.  A transaction that times out is assumed
 * to have aborted.
 */
static enum drbd_state_rv
change_cluster_wide_state(bool (*change)(struct change_context *, enum change_phase),
			  struct change_context *context)
{
	struct drbd_resource *resource = context->resource;
	unsigned long irq_flags;
	struct p_twopc_request request;
	struct twopc_reply *reply = &resource->twopc_reply;
	struct drbd_connection *connection, *target_connection = NULL;
	enum drbd_state_rv rv;
	u64 reach_immediately;
	int retries = 1;
	unsigned long start_time;
	bool have_peers;

	begin_state_change(resource, &irq_flags, context->flags | CS_LOCAL_ONLY);
	resource->state_change_err_str = context->err_str;

	if (local_state_change(context->flags)) {
		/* Not a cluster-wide state change. */
		change(context, PH_LOCAL_COMMIT);
		return end_state_change(resource, &irq_flags);
	} else {
		if (!change(context, PH_PREPARE)) {
			/* Not a cluster-wide state change. */
			return end_state_change(resource, &irq_flags);
		}
		rv = try_state_change(resource);
		if (rv != SS_SUCCESS) {
			/* Failure or nothing to do. */
			/* abort_state_change(resource, &irq_flags); */
			if (rv == SS_NOTHING_TO_DO)
				resource->state_change_flags &= ~CS_VERBOSE;
			return __end_state_change(resource, &irq_flags, rv);
		}
		/* Really a cluster-wide state change. */
	}

	if (!supports_two_phase_commit(resource)) {
		connection = get_first_connection(resource);
		rv = SS_SUCCESS;
		if (connection) {
			kref_debug_get(&connection->kref_debug, 6);
			rv = change_peer_state(connection, context->vnr, context->mask, context->val, &irq_flags);
			kref_debug_put(&connection->kref_debug, 6);
			kref_put(&connection->kref, drbd_destroy_connection);
		}
		if (rv >= SS_SUCCESS)
			change(context, PH_84_COMMIT);
		return __end_state_change(resource, &irq_flags, rv);
	}

	if (!expect(resource, context->flags & CS_SERIALIZE)) {
		rv = SS_CW_FAILED_BY_PEER;
		return __end_state_change(resource, &irq_flags, rv);
	}

	rcu_read_lock();
	for_each_connection_rcu(connection, resource) {
		if (!expect(connection, current != connection->receiver.task) ||
		    !expect(connection, current != connection->ack_receiver.task)) {
			rcu_read_unlock();
			BUG();
		}
	}
	rcu_read_unlock();

    retry:
	if (current == resource->worker.task && resource->remote_state_change)
		return __end_state_change(resource, &irq_flags, SS_CONCURRENT_ST_CHG);

	complete_remote_state_change(resource, &irq_flags);
	start_time = jiffies;
	resource->state_change_err_str = context->err_str;

	*reply = (struct twopc_reply) { 0 };

	reach_immediately = directly_connected_nodes(resource, NOW);
	if (context->target_node_id != -1) {
		struct drbd_connection *connection;

		/* Fail if the target node is no longer directly reachable. */
		connection = drbd_get_connection_by_node_id(resource, context->target_node_id);
		if (!connection) {
			rv = SS_CW_FAILED_BY_PEER;
			return __end_state_change(resource, &irq_flags, rv);
		}
		kref_debug_get(&connection->kref_debug, 8);

		if (!(connection->cstate[NOW] == C_CONNECTED ||
		      (connection->cstate[NOW] == C_CONNECTING &&
		       context->mask.conn == conn_MASK &&
		       context->val.conn == C_CONNECTED))) {
			rv = SS_CW_FAILED_BY_PEER;

			kref_debug_put(&connection->kref_debug, 8);
			kref_put(&connection->kref, drbd_destroy_connection);
			return __end_state_change(resource, &irq_flags, rv);
		}
		target_connection = connection;

		/* For connect transactions, add the target node id. */
		reach_immediately |= NODE_MASK(context->target_node_id);
	}

	do
		reply->tid = prandom_u32();
	while (!reply->tid);

	request.tid = cpu_to_be32(reply->tid);
	request.initiator_node_id = cpu_to_be32(resource->res_opts.node_id);
	request.target_node_id = cpu_to_be32(context->target_node_id);
	request.nodes_to_reach = cpu_to_be64(
		~(reach_immediately | NODE_MASK(resource->res_opts.node_id)));
	request.primary_nodes = 0;  /* Computed in phase 1. */
	request.mask = cpu_to_be32(context->mask.i);
	request.val = cpu_to_be32(context->val.i);

	drbd_info(resource, "Preparing cluster-wide state change %u (%u->%d %u/%u)\n",
		  be32_to_cpu(request.tid),
		  resource->res_opts.node_id,
		  context->target_node_id,
		  context->mask.i,
		  context->val.i);
	resource->remote_state_change = true;
	resource->twopc_parent_nodes = 0;
	resource->twopc_type = TWOPC_STATE_CHANGE;
	reply->initiator_node_id = resource->res_opts.node_id;
	reply->target_node_id = context->target_node_id;

	reply->reachable_nodes = directly_connected_nodes(resource, NOW) |
				       NODE_MASK(resource->res_opts.node_id);
	if (context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED) {
		reply->reachable_nodes |= NODE_MASK(context->target_node_id);
		reply->target_reachable_nodes = reply->reachable_nodes;
		reply->is_connect = 1;
		clear_bit(CONN_HANDSHAKE_DISCONNECT, &target_connection->flags);
		clear_bit(CONN_HANDSHAKE_RETRY, &target_connection->flags);
		clear_bit(CONN_HANDSHAKE_READY, &target_connection->flags);
	} else if (context->mask.conn == conn_MASK && context->val.conn == C_DISCONNECTING) {
		reply->target_reachable_nodes = NODE_MASK(context->target_node_id);
		reply->reachable_nodes &= ~reply->target_reachable_nodes;
	} else {
		reply->target_reachable_nodes = reply->reachable_nodes;
	}

	D_ASSERT(resource, resource->twopc_work.cb == NULL);
	begin_remote_state_change(resource, &irq_flags);
	rv = __cluster_wide_request(resource, context->vnr, P_TWOPC_PREPARE,
				    &request, reach_immediately);

	/* If we are changing state attached to a particular connection then we
	 * expect that connection to remain connected. A failure to send
	 * P_TWOPC_PREPARE on that connection is a failure for the whole
	 * cluster-wide state change. */
	if (target_connection && !test_bit(TWOPC_PREPARED, &target_connection->flags))
		rv = SS_NEED_CONNECTION;

	have_peers = rv == SS_CW_SUCCESS;
	if (have_peers) {
		long t;

		if (context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED &&
		    target_connection->agreed_pro_version >= 118)
			conn_connect2(target_connection);

		t = wait_event_interruptible_timeout(resource->state_wait,
						     cluster_wide_reply_ready(resource),
						     twopc_timeout(resource));
		if (t > 0)
			rv = get_cluster_wide_reply(resource, context);
		else
			rv = t == 0 ? SS_TIMEOUT : SS_INTERRUPTED;

		/* while waiting for the replies, reach_immediately might have changed. */
		reach_immediately = directly_connected_nodes(resource, NOW);
		if (target_connection && target_connection->cstate[NOW] == C_CONNECTING)
			reach_immediately |= NODE_MASK(context->target_node_id);
		request.nodes_to_reach = cpu_to_be64(
			~(reach_immediately | NODE_MASK(resource->res_opts.node_id)));

		if (rv == SS_CW_SUCCESS) {
			u64 directly_reachable = reach_immediately |
				NODE_MASK(resource->res_opts.node_id);

			if (context->mask.conn == conn_MASK && context->val.conn == C_DISCONNECTING)
				directly_reachable &= ~NODE_MASK(context->target_node_id);

			if ((context->mask.role == role_MASK && context->val.role == R_PRIMARY) ||
			    (context->mask.role != role_MASK && resource->role[NOW] == R_PRIMARY)) {
				reply->primary_nodes |=
					NODE_MASK(resource->res_opts.node_id);
				reply->weak_nodes |= ~directly_reachable;
			}
			drbd_info(resource, "State change %u: primary_nodes=%lX, weak_nodes=%lX\n",
				  reply->tid, (unsigned long)reply->primary_nodes,
				  (unsigned long)reply->weak_nodes);

			if ((context->mask.role == role_MASK && context->val.role == R_PRIMARY) ||
			    (context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED))
				rv = check_primaries_distances(resource);

			if (rv >= SS_SUCCESS &&
			    context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED)
				rv = check_ro_cnt_and_primary(resource);

			if (!(context->mask.conn == conn_MASK && context->val.conn == C_DISCONNECTING) ||
			    (reply->reachable_nodes & reply->target_reachable_nodes)) {
				/* The cluster is still connected after this
				 * transaction: either this transaction does
				 * not disconnect a connection, or there are
				 * redundant connections.  */

				u64 m;

				m = reply->reachable_nodes | reply->target_reachable_nodes;
				reply->reachable_nodes = m;
				reply->target_reachable_nodes = m;
			} else {
				rcu_read_lock();
				for_each_connection_rcu(connection, resource) {
					int node_id = connection->peer_node_id;

					if (node_id == context->target_node_id) {
						drbd_info(connection, "Cluster is now split\n");
						break;
					}
				}
				rcu_read_unlock();
			}

			request.primary_nodes = cpu_to_be64(reply->primary_nodes);
		}

		if (context->mask.conn == conn_MASK && context->val.conn == C_CONNECTED &&
		    target_connection->agreed_pro_version >= 118)
			wait_initial_states_received(target_connection);
	}

	if (rv < SS_SUCCESS && target_connection)
		abort_connect(target_connection);

	if ((rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) &&
	    !(context->flags & CS_DONT_RETRY)) {
		long timeout = twopc_retry_timeout(resource, retries++);
		drbd_info(resource, "Retrying cluster-wide state change after %ums\n",
			  jiffies_to_msecs(timeout));
		if (have_peers)
			twopc_phase2(resource, context->vnr, 0, &request, reach_immediately);
		if (target_connection) {
			kref_debug_put(&target_connection->kref_debug, 8);
			kref_put(&target_connection->kref, drbd_destroy_connection);
			target_connection = NULL;
		}
		clear_remote_state_change(resource);
		schedule_timeout_interruptible(timeout);
		end_remote_state_change(resource, &irq_flags, context->flags | CS_TWOPC);
		goto retry;
	}

	if (rv >= SS_SUCCESS)
		drbd_info(resource, "Committing cluster-wide state change %u (%ums)\n",
			  be32_to_cpu(request.tid),
			  jiffies_to_msecs(jiffies - start_time));
	else
		drbd_info(resource, "Aborting cluster-wide state change %u (%ums) rv = %d\n",
			  be32_to_cpu(request.tid),
			  jiffies_to_msecs(jiffies - start_time),
			  rv);

	if (have_peers && context->change_local_state_last) {
		set_bit(TWOPC_STATE_CHANGE_PENDING, &resource->flags);
		twopc_phase2(resource, context->vnr, rv >= SS_SUCCESS, &request, reach_immediately);
	}

	end_remote_state_change(resource, &irq_flags, context->flags | CS_TWOPC);
	clear_bit(TWOPC_STATE_CHANGE_PENDING, &resource->flags);
	if (rv >= SS_SUCCESS) {
		change(context, PH_COMMIT);
		if (target_connection &&
		    target_connection->peer_role[NOW] == R_UNKNOWN) {
			enum drbd_role target_role =
				(reply->primary_nodes & NODE_MASK(context->target_node_id)) ?
				R_PRIMARY : R_SECONDARY;
			__change_peer_role(target_connection, target_role);
		}
		rv = end_state_change(resource, &irq_flags);
		if (rv < SS_SUCCESS)
			drbd_err(resource, "FATAL: Local commit of already committed %u failed! \n",
				 be32_to_cpu(request.tid));
	} else {
		abort_state_change(resource, &irq_flags);
	}

	if (have_peers && !context->change_local_state_last)
		twopc_phase2(resource, context->vnr, rv >= SS_SUCCESS, &request, reach_immediately);

	if (target_connection) {
		kref_debug_put(&target_connection->kref_debug, 8);
		kref_put(&target_connection->kref, drbd_destroy_connection);
	}
	return rv;
}

enum determine_dev_size
change_cluster_wide_device_size(struct drbd_device *device,
				sector_t local_max_size,
				uint64_t new_user_size,
				enum dds_flags dds_flags,
				struct resize_parms * rs)
{
	struct drbd_resource *resource = device->resource;
	struct twopc_reply *reply = &resource->twopc_reply;
	struct p_twopc_request request;
	unsigned long start_time;
	unsigned long irq_flags;
	enum drbd_state_rv rv;
	enum determine_dev_size dd;
	u64 reach_immediately;
	bool have_peers, commit_it;
	sector_t new_size = 0;
	int retries = 1;

retry:
	rv = drbd_support_2pc_resize(resource);
	if (rv < SS_SUCCESS)
		return DS_2PC_NOT_SUPPORTED;

	state_change_lock(resource, &irq_flags, CS_VERBOSE | CS_LOCAL_ONLY);
	rcu_read_lock();
	complete_remote_state_change(resource, &irq_flags);
	start_time = jiffies;
	reach_immediately = directly_connected_nodes(resource, NOW);

	*reply = (struct twopc_reply) { 0 };

	do
		reply->tid = prandom_u32();
	while (!reply->tid);

	request.tid = cpu_to_be32(reply->tid);
	request.initiator_node_id = cpu_to_be32(resource->res_opts.node_id);
	request.target_node_id = -1;
	request.nodes_to_reach = cpu_to_be64(
		~(reach_immediately | NODE_MASK(resource->res_opts.node_id)));
	request.dds_flags = cpu_to_be16(dds_flags);
	request.user_size = cpu_to_be64(new_user_size);

	resource->remote_state_change = true;
	resource->twopc_parent_nodes = 0;
	resource->twopc_type = TWOPC_RESIZE;

	reply->initiator_node_id = resource->res_opts.node_id;
	reply->target_node_id = -1;
	reply->max_possible_size = local_max_size;
	reply->reachable_nodes = reach_immediately | NODE_MASK(resource->res_opts.node_id);
	reply->target_reachable_nodes = reply->reachable_nodes;
	if (resource->role[NOW] == R_PRIMARY)
		reply->diskful_primary_nodes = NODE_MASK(resource->res_opts.node_id);
	rcu_read_unlock();
	state_change_unlock(resource, &irq_flags);

	drbd_info(resource, "Preparing cluster-wide state change %u "
		  "(local_max_size = %llu KB, user_cap = %llu KB)\n",
		  be32_to_cpu(request.tid),
		  (unsigned long long)local_max_size >> 1,
		  (unsigned long long)new_user_size >> 1);

	rv = __cluster_wide_request(resource, device->vnr, P_TWOPC_PREP_RSZ,
				    &request, reach_immediately);

	have_peers = rv == SS_CW_SUCCESS;
	if (have_peers) {
		if (wait_event_timeout(resource->state_wait,
				       cluster_wide_reply_ready(resource),
				       twopc_timeout(resource)))
			rv = get_cluster_wide_reply(resource, NULL);
		else
			rv = SS_TIMEOUT;

		if (rv == SS_TIMEOUT || rv == SS_CONCURRENT_ST_CHG) {
			long timeout = twopc_retry_timeout(resource, retries++);

			drbd_info(resource, "Retrying cluster-wide state change after %ums\n",
				  jiffies_to_msecs(timeout));

			twopc_phase2(resource, device->vnr, 0, &request, reach_immediately);

			clear_remote_state_change(resource);
			schedule_timeout_interruptible(timeout);
			goto retry;
		}
	}

	if (rv >= SS_SUCCESS) {
		new_size = min_not_zero(reply->max_possible_size, new_user_size);
		commit_it = new_size != get_capacity(device->vdisk);

		if (commit_it) {
			request.exposed_size = cpu_to_be64(new_size);
			request.diskful_primary_nodes = cpu_to_be64(reply->diskful_primary_nodes);
			drbd_info(resource, "Committing cluster-wide state change %u (%ums)\n",
				  be32_to_cpu(request.tid),
				  jiffies_to_msecs(jiffies - start_time));
		} else {
			drbd_info(resource, "Aborting cluster-wide state change %u (%ums) size unchanged\n",
				  be32_to_cpu(request.tid),
				  jiffies_to_msecs(jiffies - start_time));
		}
	} else {
		commit_it = false;
		drbd_info(resource, "Aborting cluster-wide state change %u (%ums) rv = %d\n",
			  be32_to_cpu(request.tid),
			  jiffies_to_msecs(jiffies - start_time),
			  rv);
	}

	if (have_peers)
		twopc_phase2(resource, device->vnr, commit_it, &request, reach_immediately);

	if (commit_it) {
		struct twopc_resize *tr = &resource->twopc_resize;

		tr->diskful_primary_nodes = reply->diskful_primary_nodes;
		tr->new_size = new_size;
		tr->dds_flags = dds_flags;
		tr->user_size = new_user_size;

		dd = drbd_commit_size_change(device, rs, reach_immediately);
	} else {
		if (rv == SS_CW_FAILED_BY_PEER)
			dd = DS_2PC_NOT_SUPPORTED;
		else if (rv >= SS_SUCCESS)
			dd = DS_UNCHANGED;
		else
			dd = DS_2PC_ERR;
	}

	clear_remote_state_change(resource);
	return dd;
}

static void twopc_end_nested(struct drbd_resource *resource, enum drbd_packet cmd, bool as_work)
{
	struct drbd_connection *twopc_parent, *tmp;
	struct twopc_reply twopc_reply;
	LIST_HEAD(parents);

	write_lock_irq(&resource->state_rwlock);
	twopc_reply = resource->twopc_reply;
	if (twopc_reply.tid) {
		resource->twopc_prepare_reply_cmd = cmd;
		list_splice_init(&resource->twopc_parents, &parents);
	}
	if (as_work)
		resource->twopc_work.cb = NULL;
	write_unlock_irq(&resource->state_rwlock);

	if (!twopc_reply.tid)
		return;

	list_for_each_entry_safe(twopc_parent, tmp, &parents, twopc_parent_list) {
		if (twopc_reply.is_disconnect)
			set_bit(DISCONNECT_EXPECTED, &twopc_parent->flags);

		dynamic_drbd_dbg(twopc_parent, "Nested state change %u result: %s\n",
			   twopc_reply.tid, drbd_packet_name(cmd));

		drbd_send_twopc_reply(twopc_parent, cmd, &twopc_reply);
		kref_debug_put(&twopc_parent->kref_debug, 9);
		kref_put(&twopc_parent->kref, drbd_destroy_connection);
	}
	wake_up(&resource->twopc_wait);
}

static void __nested_twopc_work(struct drbd_work *work, bool as_work)
{
	struct drbd_resource *resource =
		container_of(work, struct drbd_resource, twopc_work);
	enum drbd_state_rv rv;
	enum drbd_packet cmd;

	rv = get_cluster_wide_reply(resource, NULL);
	if (rv >= SS_SUCCESS)
		cmd = P_TWOPC_YES;
	else if (rv == SS_CONCURRENT_ST_CHG || rv == SS_HANDSHAKE_RETRY)
		cmd = P_TWOPC_RETRY;
	else
		cmd = P_TWOPC_NO;
	twopc_end_nested(resource, cmd, as_work);
}

int nested_twopc_work(struct drbd_work *work, int cancel)
{
	__nested_twopc_work(work, true);
	return 0;
}

enum drbd_state_rv
nested_twopc_request(struct drbd_resource *resource, int vnr, enum drbd_packet cmd,
		     struct p_twopc_request *request)
{
	enum drbd_state_rv rv;
	u64 nodes_to_reach, reach_immediately;
	bool have_peers;

	write_lock_irq(&resource->state_rwlock);
	nodes_to_reach = be64_to_cpu(request->nodes_to_reach);
	reach_immediately = directly_connected_nodes(resource, NOW) & nodes_to_reach;
	nodes_to_reach &= ~(reach_immediately | NODE_MASK(resource->res_opts.node_id));
	request->nodes_to_reach = cpu_to_be64(nodes_to_reach);
	write_unlock_irq(&resource->state_rwlock);

	rv = __cluster_wide_request(resource, vnr, cmd, request, reach_immediately);
	have_peers = rv == SS_CW_SUCCESS;
	if (cmd == P_TWOPC_PREPARE || cmd == P_TWOPC_PREP_RSZ) {
		if (rv < SS_SUCCESS)
			twopc_end_nested(resource, P_TWOPC_NO, false);
		else if (!have_peers && cluster_wide_reply_ready(resource)) /* no nested nodes */
			__nested_twopc_work(&resource->twopc_work, false);
	}
	return rv;
}

static bool has_up_to_date_peer_disks(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device)
		if (peer_device->disk_state[NEW] == D_UP_TO_DATE)
			return true;
	return false;
}

static void disconnect_where_resync_target(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device)
		if (is_sync_target_state(peer_device, NEW))
			__change_cstate(peer_device->connection, C_TEAR_DOWN);
}

static bool do_change_role(struct change_context *context, enum change_phase phase)
{
	struct drbd_resource *resource = context->resource;
	enum drbd_role role = context->val.role;
	int flags = context->flags;
	struct drbd_device *device;
	int vnr;

	resource->role[NEW] = role;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		if (role == R_PRIMARY && (flags & CS_FP_LOCAL_UP_TO_DATE)) {
			if (device->disk_state[NEW] < D_UP_TO_DATE &&
			    device->disk_state[NEW] >= D_INCONSISTENT &&
			    !has_up_to_date_peer_disks(device)) {
				device->disk_state[NEW] = D_UP_TO_DATE;
				/* adding it to the context so that it gets sent to the peers */
				context->mask.disk |= disk_MASK;
				context->val.disk |= D_UP_TO_DATE;
				disconnect_where_resync_target(device);
			}
		}

		if (role == R_PRIMARY && (flags & CS_FP_OUTDATE_PEERS)) {
			struct drbd_peer_device *peer_device;
			for_each_peer_device_rcu(peer_device, device) {
				if (peer_device->disk_state[NEW] == D_UNKNOWN)
					__change_peer_disk_state(peer_device, D_OUTDATED);
			}
		}
	}
	rcu_read_unlock();

	return phase != PH_PREPARE ||
		context->resource->role[NOW] != context->val.role;
}

enum drbd_state_rv change_role(struct drbd_resource *resource,
			       enum drbd_role role,
			       enum chg_state_flags flags,
			       const char **err_str)
{
	struct change_context role_context = {
		.resource = resource,
		.vnr = -1,
		.mask = { { .role = role_MASK } },
		.val = { { .role = role } },
		.target_node_id = -1,
		.flags = flags | CS_SERIALIZE,
		.err_str = err_str,
	};
	enum drbd_state_rv rv;
	bool got_state_sem = false;

	if (role == R_SECONDARY) {
		struct drbd_device *device;
		int vnr;

		if (!(flags & CS_ALREADY_SERIALIZED)) {
			down(&resource->state_sem);
			got_state_sem = true;
			role_context.flags |= CS_ALREADY_SERIALIZED;
		}
		idr_for_each_entry(&resource->devices, device, vnr) {
			long t = wait_event_interruptible_timeout(device->misc_wait,
						!atomic_read(&device->ap_bio_cnt[WRITE]),
						twopc_timeout(resource));
			if (t <= 0) {
				rv = t == 0 ? SS_TIMEOUT : SS_INTERRUPTED;
				goto out;
			}
		}
		role_context.change_local_state_last = true;
	}
	rv = change_cluster_wide_state(do_change_role, &role_context);
out:
	if (got_state_sem)
		up(&resource->state_sem);
	return rv;
}

void __change_io_susp_user(struct drbd_resource *resource, bool value)
{
	resource->susp_user[NEW] = value;
}

enum drbd_state_rv change_io_susp_user(struct drbd_resource *resource,
				       bool value,
				       enum chg_state_flags flags)
{
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags);
	__change_io_susp_user(resource, value);
	return end_state_change(resource, &irq_flags);
}

void __change_io_susp_no_data(struct drbd_resource *resource, bool value)
{
	resource->susp_nod[NEW] = value;
}

void __change_io_susp_fencing(struct drbd_connection *connection, bool value)
{
	connection->susp_fen[NEW] = value;
}

void __change_io_susp_quorum(struct drbd_resource *resource, bool value)
{
	resource->susp_quorum[NEW] = value;
}

void __change_disk_state(struct drbd_device *device, enum drbd_disk_state disk_state)
{
	device->disk_state[NEW] = disk_state;
}

void __downgrade_disk_states(struct drbd_resource *resource, enum drbd_disk_state disk_state)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr) {
		if (device->disk_state[NEW] > disk_state)
			__change_disk_state(device, disk_state);
	}
	rcu_read_unlock();
}

void __outdate_myself(struct drbd_resource *resource)
{
	struct drbd_device *device;
	int vnr;

	idr_for_each_entry(&resource->devices, device, vnr) {
		if (device->disk_state[NOW] > D_OUTDATED)
			__change_disk_state(device, D_OUTDATED);
	}
}

static bool device_has_connected_peer_devices(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device)
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			return true;
	return false;
}

static bool device_has_peer_devices_with_disk(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	bool rv = false;

	for_each_peer_device(peer_device, device) {
		if (peer_device->connection->cstate[NOW] == C_CONNECTED) {
			/* We expect to receive up-to-date UUIDs soon.
			   To avoid a race in receive_state, "clear" uuids while
			   holding state_rwlock. I.e. atomic with the state change */
			clear_bit(UUIDS_RECEIVED, &peer_device->flags);
			if (peer_device->disk_state[NOW] > D_DISKLESS &&
			    peer_device->disk_state[NOW] != D_UNKNOWN)
				rv = true;
		}
	}

	return rv;
}

static void restore_outdated_in_pdsk(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	if (!get_ldev_if_state(device, D_ATTACHING))
		return;

	for_each_peer_device(peer_device, device) {
		int node_id = peer_device->connection->peer_node_id;
		struct drbd_peer_md *peer_md = &device->ldev->md.peers[node_id];

		if ((peer_md->flags & MDF_PEER_OUTDATED) &&
		    peer_device->disk_state[NEW] == D_UNKNOWN)
			__change_peer_disk_state(peer_device, D_OUTDATED);
	}

	put_ldev(device);
}

static bool do_change_from_consistent(struct change_context *context, enum change_phase phase)
{
	struct drbd_resource *resource = context->resource;
	struct twopc_reply *reply = &resource->twopc_reply;
	u64 directly_reachable = directly_connected_nodes(resource, NEW) |
		NODE_MASK(resource->res_opts.node_id);

	if (phase == PH_COMMIT && (reply->primary_nodes & ~directly_reachable)) {
		__outdate_myself(resource);
	} else {
		struct drbd_device *device;
		int vnr;

		idr_for_each_entry(&resource->devices, device, vnr) {
			if (device->disk_state[NOW] == D_CONSISTENT &&
			    may_return_to_up_to_date(device, NOW))
				__change_disk_state(device, D_UP_TO_DATE);
		}
	}

	return phase != PH_PREPARE || reply->reachable_nodes != NODE_MASK(resource->res_opts.node_id);
}

enum drbd_state_rv change_from_consistent(struct drbd_resource *resource,
					  enum chg_state_flags flags)
{
	struct change_context context = {
		.resource = resource,
		.vnr = -1,
		.mask = { },
		.val = { },
		.target_node_id = -1,
		.flags = flags,
		.change_local_state_last = false,
	};

	/* The other nodes get the request for an empty state change. I.e. they
	   will agree to this change request. At commit time we know where to
	   go from the D_CONSISTENT, since we got the primary mask. */
	return change_cluster_wide_state(do_change_from_consistent, &context);
}

static bool do_change_disk_state(struct change_context *context, enum change_phase phase)
{
	struct drbd_device *device =
		container_of(context, struct change_disk_state_context, context)->device;
	bool cluster_wide_state_change = false;

	if (device->disk_state[NOW] == D_ATTACHING &&
	    context->val.disk == D_NEGOTIATING) {
		if (device_has_peer_devices_with_disk(device)) {
			cluster_wide_state_change =
				supports_two_phase_commit(device->resource);
		} else {
			/* very last part of attach */
			context->val.disk = disk_state_from_md(device);
			restore_outdated_in_pdsk(device);
		}
	} else if (device->disk_state[NOW] != D_DETACHING &&
		   context->val.disk == D_DETACHING &&
		   device_has_connected_peer_devices(device)) {
		cluster_wide_state_change = true;
	}
	__change_disk_state(device, context->val.disk);
	return phase != PH_PREPARE || cluster_wide_state_change;
}

enum drbd_state_rv change_disk_state(struct drbd_device *device,
				     enum drbd_disk_state disk_state,
				     enum chg_state_flags flags,
				     const char **err_str)
{
	struct change_disk_state_context disk_state_context = {
		.context = {
			.resource = device->resource,
			.vnr = device->vnr,
			.mask = { { .disk = disk_MASK } },
			.val = { { .disk = disk_state } },
			.target_node_id = -1,
			.flags = flags,
			.change_local_state_last = true,
			.err_str = err_str,
		},
		.device = device,
	};

	return change_cluster_wide_state(do_change_disk_state,
					 &disk_state_context.context);
}

void __change_cstate(struct drbd_connection *connection, enum drbd_conn_state cstate)
{
	if (cstate == C_DISCONNECTING)
		set_bit(DISCONNECT_EXPECTED, &connection->flags);

	connection->cstate[NEW] = cstate;
	if (cstate < C_CONNECTED) {
		struct drbd_peer_device *peer_device;
		int vnr;

		rcu_read_lock();
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
			__change_repl_state(peer_device, L_OFF);
		rcu_read_unlock();
	}
}

static bool connection_has_connected_peer_devices(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] >= L_ESTABLISHED)
			return true;
	}
	return false;
}

enum outdate_what { OUTDATE_NOTHING, OUTDATE_DISKS, OUTDATE_PEER_DISKS };

static enum outdate_what outdate_on_disconnect(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;

	if ((connection->fencing_policy >= FP_RESOURCE ||
	     connection->resource->res_opts.quorum != QOU_OFF) &&
	    resource->role[NOW] != connection->peer_role[NOW]) {
		/* primary politely disconnects from secondary,
		 * tells peer to please outdate itself */
		if (resource->role[NOW] == R_PRIMARY)
			return OUTDATE_PEER_DISKS;

		/* secondary politely disconnect from primary,
		 * proposes to outdate itself. */
		if (connection->peer_role[NOW] == R_PRIMARY)
			return OUTDATE_DISKS;
	}
	return OUTDATE_NOTHING;
}

static void __change_cstate_and_outdate(struct drbd_connection *connection,
					enum drbd_conn_state cstate,
					enum outdate_what outdate_what)
{
	__change_cstate(connection, cstate);
	switch(outdate_what) {
		case OUTDATE_DISKS:
			__downgrade_disk_states(connection->resource, D_OUTDATED);
			break;
		case OUTDATE_PEER_DISKS:
			__downgrade_peer_disk_states(connection, D_OUTDATED);
			break;
		case OUTDATE_NOTHING:
			break;
	}
}

void apply_connect(struct drbd_connection *connection, bool commit)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	if (!commit || connection->cstate[NEW] != C_CONNECTED)
		return;

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		union drbd_state s = peer_device->connect_state;

		if (s.disk != D_MASK)
			__change_disk_state(device, s.disk);
		if (device->disk_state[NOW] != D_NEGOTIATING)
			__change_repl_state(peer_device, s.conn);
		__change_peer_disk_state(peer_device, s.pdsk);
		__change_resync_susp_peer(peer_device, s.peer_isp);

		if (s.conn == L_OFF)
			__change_cstate(connection, C_DISCONNECTING);

		if (commit)
			clear_bit(DISCARD_MY_DATA, &peer_device->flags);
	}
}

struct change_cstate_context {
	struct change_context context;
	struct drbd_connection *connection;
	enum outdate_what outdate_what;
};

static bool do_change_cstate(struct change_context *context, enum change_phase phase)
{
	struct change_cstate_context *cstate_context =
		container_of(context, struct change_cstate_context, context);
	struct drbd_connection *connection = cstate_context->connection;

	if (phase == PH_PREPARE) {
		cstate_context->outdate_what = OUTDATE_NOTHING;
		if (context->val.conn == C_DISCONNECTING && !(context->flags & CS_HARD)) {
			cstate_context->outdate_what =
				outdate_on_disconnect(connection);
			switch(cstate_context->outdate_what) {
			case OUTDATE_DISKS:
				context->mask.disk = disk_MASK;
				context->val.disk = D_OUTDATED;
				break;
			case OUTDATE_PEER_DISKS:
				context->mask.pdsk = pdsk_MASK;
				context->val.pdsk = D_OUTDATED;
				break;
			case OUTDATE_NOTHING:
				break;
			}
		}
	}
	if ((context->val.conn == C_CONNECTED && connection->cstate[NEW] == C_CONNECTING) ||
	    context->val.conn != C_CONNECTED)
		__change_cstate_and_outdate(connection,
					    context->val.conn,
					    cstate_context->outdate_what);

	if (context->val.conn == C_CONNECTED &&
	    connection->agreed_pro_version >= 117)
		apply_connect(connection, phase == PH_COMMIT);

	if (phase == PH_COMMIT) {
		struct drbd_resource *resource = context->resource;
		struct twopc_reply *reply = &resource->twopc_reply;
		u64 directly_reachable = directly_connected_nodes(resource, NEW) |
			NODE_MASK(resource->res_opts.node_id);

		if (reply->primary_nodes & ~directly_reachable)
			__outdate_myself(resource);
	}

	return phase != PH_PREPARE ||
	       context->val.conn == C_CONNECTED ||
	       (context->val.conn == C_DISCONNECTING &&
		connection_has_connected_peer_devices(connection));
}

/**
 * change_cstate()  -  change the connection state of a connection
 *
 * When disconnecting from a peer, we may also need to outdate the local or
 * peer disks depending on the fencing policy.  This cannot easily be split
 * into two state changes.
 */
enum drbd_state_rv change_cstate_es(struct drbd_connection *connection,
				    enum drbd_conn_state cstate,
				    enum chg_state_flags flags,
				    const char **err_str
	)
{
	struct change_cstate_context cstate_context = {
		.context = {
			.resource = connection->resource,
			.vnr = -1,
			.mask = { { .conn = conn_MASK } },
			.val = { { .conn = cstate } },
			.target_node_id = connection->peer_node_id,
			.flags = flags,
			.change_local_state_last = true,
			.err_str = err_str,
		},
		.connection = connection,
	};

	if (cstate == C_CONNECTED) {
		cstate_context.context.mask.role = role_MASK;
		cstate_context.context.val.role = connection->resource->role[NOW];
	}

	/*
	 * Hard connection state changes like a protocol error or forced
	 * disconnect may occur while we are holding resource->state_sem.  In
	 * that case, omit CS_SERIALIZE so that we don't deadlock trying to
	 * grab that mutex again.
	 */
	if (!(flags & CS_HARD))
		cstate_context.context.flags |= CS_SERIALIZE;

	return change_cluster_wide_state(do_change_cstate, &cstate_context.context);
}

void __change_peer_role(struct drbd_connection *connection, enum drbd_role peer_role)
{
	connection->peer_role[NEW] = peer_role;
}

void __change_repl_state(struct drbd_peer_device *peer_device, enum drbd_repl_state repl_state)
{
	peer_device->repl_state[NEW] = repl_state;
	if (repl_state > L_OFF)
		peer_device->connection->cstate[NEW] = C_CONNECTED;
}

struct change_repl_context {
	struct change_context context;
	struct drbd_peer_device *peer_device;
};

static bool do_change_repl_state(struct change_context *context, enum change_phase phase)
{
	struct change_repl_context *repl_context =
		container_of(context, struct change_repl_context, context);
	struct drbd_peer_device *peer_device = repl_context->peer_device;
	enum drbd_repl_state *repl_state = peer_device->repl_state;
	enum drbd_repl_state new_repl_state = context->val.conn;
	bool cluster_wide = context->flags & CS_CLUSTER_WIDE;

	__change_repl_state(peer_device, new_repl_state);

	return phase != PH_PREPARE ||
		((repl_state[NOW] >= L_ESTABLISHED &&
		  (new_repl_state == L_STARTING_SYNC_S || new_repl_state == L_STARTING_SYNC_T)) ||
		 (repl_state[NOW] == L_ESTABLISHED &&
		  (new_repl_state == L_VERIFY_S || new_repl_state == L_OFF)) ||
		 (repl_state[NOW] == L_ESTABLISHED && cluster_wide &&
		  (new_repl_state == L_WF_BITMAP_S || new_repl_state == L_WF_BITMAP_T)));
}

enum drbd_state_rv change_repl_state(struct drbd_peer_device *peer_device,
				     enum drbd_repl_state new_repl_state,
				     enum chg_state_flags flags)
{
	struct change_repl_context repl_context = {
		.context = {
			.resource = peer_device->device->resource,
			.vnr = peer_device->device->vnr,
			.mask = { { .conn = conn_MASK } },
			.val = { { .conn = new_repl_state } },
			.target_node_id = peer_device->node_id,
			.flags = flags
		},
		.peer_device = peer_device
	};

	if (new_repl_state == L_WF_BITMAP_S || new_repl_state == L_VERIFY_S)
		repl_context.context.change_local_state_last = true;

	return change_cluster_wide_state(do_change_repl_state, &repl_context.context);
}

enum drbd_state_rv stable_change_repl_state(struct drbd_peer_device *peer_device,
					    enum drbd_repl_state repl_state,
					    enum chg_state_flags flags)
{
	return stable_state_change(peer_device->device->resource,
		change_repl_state(peer_device, repl_state, flags));
}

void __change_peer_disk_state(struct drbd_peer_device *peer_device, enum drbd_disk_state disk_state)
{
	peer_device->disk_state[NEW] = disk_state;
}

void __downgrade_peer_disk_states(struct drbd_connection *connection, enum drbd_disk_state disk_state)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->disk_state[NEW] > disk_state)
			__change_peer_disk_state(peer_device, disk_state);
	}
	rcu_read_unlock();
}

enum drbd_state_rv change_peer_disk_state(struct drbd_peer_device *peer_device,
					  enum drbd_disk_state disk_state,
					  enum chg_state_flags flags)
{
	struct drbd_resource *resource = peer_device->device->resource;
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags);
	__change_peer_disk_state(peer_device, disk_state);
	return end_state_change(resource, &irq_flags);
}

void __change_resync_susp_user(struct drbd_peer_device *peer_device,
				       bool value)
{
	peer_device->resync_susp_user[NEW] = value;
}

enum drbd_state_rv change_resync_susp_user(struct drbd_peer_device *peer_device,
						   bool value,
						   enum chg_state_flags flags)
{
	struct drbd_resource *resource = peer_device->device->resource;
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags);
	__change_resync_susp_user(peer_device, value);
	return end_state_change(resource, &irq_flags);
}

void __change_resync_susp_peer(struct drbd_peer_device *peer_device,
				       bool value)
{
	peer_device->resync_susp_peer[NEW] = value;
}

void __change_resync_susp_dependency(struct drbd_peer_device *peer_device,
					     bool value)
{
	peer_device->resync_susp_dependency[NEW] = value;
}

bool drbd_data_accessible(struct drbd_device *device, enum which_state which)
{
	struct drbd_peer_device *peer_device;
	bool data_accessible = false;

	if (device->disk_state[which] == D_UP_TO_DATE)
		return true;

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		struct net_conf *nc;
		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		if (nc && !nc->allow_remote_read)
			continue;
		if (peer_device->disk_state[which] == D_UP_TO_DATE) {
			data_accessible = true;
			break;
		}
	}
	rcu_read_unlock();

	return data_accessible;
}
/* drbd_data_accessible() and exposable_data_uuid() have the same structure. By intention. */
static u64 exposable_data_uuid(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;
	u64 uuid = 0;

	if (device->disk_state[NOW] == D_UP_TO_DATE && get_ldev(device)) {
		uuid = device->ldev->md.current_uuid;
		put_ldev(device);
		return uuid;
	}

	rcu_read_lock();
	for_each_peer_device_rcu(peer_device, device) {
		struct net_conf *nc;
		nc = rcu_dereference(peer_device->connection->transport.net_conf);
		if (nc && !nc->allow_remote_read)
			continue;
		if (peer_device->disk_state[NOW] == D_UP_TO_DATE) {
			uuid = peer_device->current_uuid;
			break;
		}
	}
	rcu_read_unlock();

	return uuid;
}

static void ensure_exposed_data_uuid(struct drbd_device *device)
{
	u64 uuid = exposable_data_uuid(device);
	bool changed = false;

	if (uuid)
		changed = drbd_set_exposed_data_uuid(device, uuid);

	if (changed)
		drbd_info(device, "Setting exposed data uuid: %016llX\n",
			  (unsigned long long)device->exposed_data_uuid);
}
