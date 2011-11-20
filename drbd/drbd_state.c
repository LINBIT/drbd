/*
   drbd_state.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   Thanks to Carter Burden, Bart Grantham and Gennadiy Nerubayev
   from Logicworks, Inc. for making SDP replication support possible.

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

#include <linux/drbd_limits.h>
#include "drbd_int.h"
#include "drbd_protocol.h"
#include "drbd_req.h"

/* in drbd_main.c */
extern void tl_abort_disk_io(struct drbd_device *device);

struct after_state_change_work {
	struct drbd_work w;
	struct drbd_state_change *state_change;
	struct completion *done;
};

struct drbd_resource_state_change {
	struct drbd_resource *resource;
	enum drbd_role role[2];
	bool susp[2];
	bool susp_nod[2];
	bool susp_fen[2];
};

struct drbd_device_state_change {
	struct drbd_device *device;
	enum drbd_disk_state disk_state[2];
};

struct drbd_connection_state_change {
	struct drbd_connection *connection;
	enum drbd_conn_state cstate[2];
	enum drbd_role peer_role[2];
};

struct drbd_peer_device_state_change {
	struct drbd_peer_device *peer_device;
	enum drbd_disk_state disk_state[2];
	enum drbd_repl_state repl_state[2];
	bool resync_susp_user[2];
	bool resync_susp_peer[2];
	bool resync_susp_dependency[2];
};

struct drbd_state_change {
	unsigned int n_devices;
	unsigned int n_connections;
	struct drbd_resource_state_change resource[1];
	struct drbd_device_state_change *devices;
	struct drbd_connection_state_change *connections;
	struct drbd_peer_device_state_change *peer_devices;
};

static struct drbd_state_change *alloc_state_change(struct drbd_resource *resource, gfp_t flags)
{
	struct drbd_state_change *state_change;
	unsigned int n_devices = 0, n_connections = 0, size, n;
	struct drbd_device *device;
	struct drbd_connection *connection;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr)
		n_devices++;
	for_each_connection(connection, resource)
		n_connections++;
	rcu_read_unlock();

	size = sizeof(struct drbd_state_change) +
	       n_devices * sizeof(struct drbd_device_state_change) +
	       n_connections * sizeof(struct drbd_connection_state_change) +
	       n_devices * n_connections * sizeof(struct drbd_peer_device_state_change);
	state_change = kmalloc(size, flags);
	if (!state_change)
		return NULL;
	state_change->n_devices = n_devices;
	state_change->n_connections = n_connections;
	state_change->devices = (void *)(state_change + 1);
	state_change->connections = (void *)&state_change->devices[n_devices];
	state_change->peer_devices = (void *)&state_change->connections[n_connections];
	state_change->resource->resource = NULL;
	for (n = 0; n < n_devices; n++)
		state_change->devices[n].device = NULL;
	for (n = 0; n < n_connections; n++)
		state_change->connections[n].connection = NULL;
	return state_change;
}

static struct drbd_state_change *remember_state_change(struct drbd_resource *resource, gfp_t gfp)
{
	struct drbd_state_change *state_change;
	struct drbd_device *device;
	unsigned int n_devices = 0;
	struct drbd_connection *connection;
	unsigned int n_connections = 0;
	int vnr;

	struct drbd_device_state_change *device_state_change;
	struct drbd_peer_device_state_change *peer_device_state_change;
	struct drbd_connection_state_change *connection_state_change;

retry:
	state_change = alloc_state_change(resource, gfp);
	if (!state_change)
		return NULL;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr)
		n_devices++;
	for_each_connection(connection, resource)
		n_connections++;
	if (n_devices != state_change->n_devices ||
	    n_connections != state_change->n_connections) {
		kfree(state_change);
		rcu_read_unlock();
		goto retry;
	}

	kref_get(&resource->kref);
	state_change->resource->resource = resource;
	memcpy(state_change->resource->role,
	       resource->role, sizeof(resource->role));
	memcpy(state_change->resource->susp,
	       resource->susp, sizeof(resource->susp));
	memcpy(state_change->resource->susp_nod,
	       resource->susp_nod, sizeof(resource->susp_nod));
	memcpy(state_change->resource->susp_fen,
	       resource->susp_fen, sizeof(resource->susp_fen));

	device_state_change = state_change->devices;
	peer_device_state_change = state_change->peer_devices;
	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;

		kref_get(&device->kref);
		device_state_change->device = device;
		memcpy(device_state_change->disk_state,
		       device->disk_state, sizeof(device->disk_state));

		for_each_peer_device(peer_device, device) {
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
			peer_device_state_change++;
		}
		device_state_change++;
	}

	connection_state_change = state_change->connections;
	for_each_connection(connection, resource) {
		kref_get(&connection->kref);
		connection_state_change->connection = connection;
		memcpy(connection_state_change->cstate,
		       connection->cstate, sizeof(connection->cstate));
		memcpy(connection_state_change->peer_role,
		       connection->peer_role, sizeof(connection->peer_role));
	}
	rcu_read_unlock();

	return state_change;
}

static void forget_state_change(struct drbd_state_change *state_change)
{
	unsigned int n;

	if (!state_change)
		return;

	if (state_change->resource->resource)
		kref_put(&state_change->resource->resource->kref, drbd_destroy_resource);
	for (n = 0; n < state_change->n_devices; n++) {
		struct drbd_device *device = state_change->devices[n].device;

		if (device)
			kref_put(&device->kref, drbd_destroy_device);
	}
	for (n = 0; n < state_change->n_connections; n++) {
		struct drbd_connection *connection =
			state_change->connections[n].connection;

		if (connection)
			kref_put(&connection->kref, drbd_destroy_connection);
	}
	kfree(state_change);
}

static void print_state_change(struct drbd_resource *resource, const char *prefix);
static void finish_state_change(struct drbd_resource *, struct completion *);
STATIC int w_after_state_change(struct drbd_work *w, int unused);
static enum drbd_state_rv is_valid_soft_transition(struct drbd_resource *);
static enum drbd_state_rv is_valid_transition(struct drbd_resource *resource);
static void sanitize_state(struct drbd_resource *resource);
static enum drbd_state_rv change_peer_state(struct drbd_connection *, int, union drbd_state,
					    union drbd_state, unsigned long *);

static bool state_has_changed(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	struct drbd_device *device;
	int minor;

	if (resource->role[OLD] != resource->role[NEW] ||
	    resource->susp[OLD] != resource->susp[NEW] ||
	    resource->susp_nod[OLD] != resource->susp_nod[NEW] ||
	    resource->susp_fen[OLD] != resource->susp_fen[NEW])
		return true;

	for_each_connection(connection, resource) {
		if (connection->cstate[OLD] != connection->cstate[NEW] ||
		    connection->peer_role[OLD] != connection->peer_role[NEW])
			return true;
	}

	idr_for_each_entry(&resource->devices, device, minor) {
		struct drbd_peer_device *peer_device;

		if (device->disk_state[OLD] != device->disk_state[NEW])
			return true;

		for_each_peer_device(peer_device, device) {
			if (peer_device->disk_state[OLD] != peer_device->disk_state[NEW] ||
			    peer_device->repl_state[OLD] != peer_device->repl_state[NEW] ||
			    peer_device->resync_susp_user[OLD] !=
				peer_device->resync_susp_user[NEW] ||
			    peer_device->resync_susp_peer[OLD] !=
				peer_device->resync_susp_peer[NEW] ||
			    peer_device->resync_susp_dependency[OLD] !=
				peer_device->resync_susp_dependency[NEW])
				return true;
		}
	}
	return false;
}

static void ___begin_state_change(struct drbd_resource *resource, enum chg_state_flags flags)
{
	struct drbd_connection *connection;
	struct drbd_device *device;
	int minor;

	resource->state_change_flags = flags;

	resource->role[NEW] = resource->role[NOW];
	resource->susp[NEW] = resource->susp[NOW];
	resource->susp_nod[NEW] = resource->susp_nod[NOW];
	resource->susp_fen[NEW] = resource->susp_fen[NOW];

	for_each_connection(connection, resource) {
		connection->cstate[NEW] = connection->cstate[NOW];
		connection->peer_role[NEW] = connection->peer_role[NOW];
	}

	idr_for_each_entry(&resource->devices, device, minor) {
		struct drbd_peer_device *peer_device;

		device->disk_state[NEW] = device->disk_state[NOW];

		for_each_peer_device(peer_device, device) {
			peer_device->disk_state[NEW] = peer_device->disk_state[NOW];
			peer_device->repl_state[NEW] = peer_device->repl_state[NOW];
			peer_device->resync_susp_user[NEW] =
				peer_device->resync_susp_user[NOW];
			peer_device->resync_susp_peer[NEW] =
				peer_device->resync_susp_peer[NOW];
			peer_device->resync_susp_dependency[NEW] =
				peer_device->resync_susp_dependency[NOW];
		}
	}
}

static void __begin_state_change(struct drbd_resource *resource, enum chg_state_flags flags)
{
	if (!(flags & CS_GLOBAL_LOCKED))
		read_lock(&global_state_lock);
	rcu_read_lock();
	___begin_state_change(resource, flags);
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

static enum drbd_state_rv ___end_state_change(struct drbd_resource *resource, struct completion *done,
					      enum drbd_state_rv rv)
{
	enum chg_state_flags flags = resource->state_change_flags;
	struct drbd_connection *connection;
	struct drbd_device *device;
	int minor;

	if (rv >= SS_SUCCESS)
		rv = try_state_change(resource);
	if (rv < SS_SUCCESS) {
		if (flags & CS_VERBOSE) {
			drbd_err(resource, "State change failed: %s\n", drbd_set_st_err_str(rv));
			print_state_change(resource, "Failed: ");
		}
		goto out;
	}

	finish_state_change(resource, done);

	resource->role[NOW] = resource->role[NEW];
	resource->susp[NOW] = resource->susp[NEW];
	resource->susp_nod[NOW] = resource->susp_nod[NEW];
	resource->susp_fen[NOW] = resource->susp_fen[NEW];

	for_each_connection(connection, resource) {
		connection->cstate[NOW] = connection->cstate[NEW];
		connection->peer_role[NOW] = connection->peer_role[NEW];
	}

	idr_for_each_entry(&resource->devices, device, minor) {
		struct drbd_peer_device *peer_device;

		device->disk_state[NOW] = device->disk_state[NEW];

		for_each_peer_device(peer_device, device) {
			peer_device->disk_state[NOW] = peer_device->disk_state[NEW];
			peer_device->repl_state[NOW] = peer_device->repl_state[NEW];
			peer_device->resync_susp_user[NOW] =
				peer_device->resync_susp_user[NEW];
			peer_device->resync_susp_peer[NOW] =
				peer_device->resync_susp_peer[NEW];
			peer_device->resync_susp_dependency[NOW] =
				peer_device->resync_susp_dependency[NEW];
		}
	}
out:
	rcu_read_unlock();
	if (!(flags & CS_GLOBAL_LOCKED))
		read_unlock(&global_state_lock);
	return rv;
}

void begin_state_change_locked(struct drbd_resource *resource, enum chg_state_flags flags)
{
	BUG_ON(flags & (CS_SERIALIZE | CS_WAIT_COMPLETE));
	__begin_state_change(resource, flags);
}

enum drbd_state_rv end_state_change_locked(struct drbd_resource *resource)
{
	return ___end_state_change(resource, NULL, SS_SUCCESS);
}

void begin_state_change(struct drbd_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	if ((flags & CS_SERIALIZE) && !(flags & CS_ALREADY_SERIALIZED))
		mutex_lock(&resource->state_mutex);
	spin_lock_irqsave(&resource->req_lock, *irq_flags);
	__begin_state_change(resource, flags);
}

static enum drbd_state_rv __end_state_change(struct drbd_resource *resource,
					     unsigned long *irq_flags,
					     enum drbd_state_rv rv)
{
	enum chg_state_flags flags = resource->state_change_flags;
	struct completion __done, *done = NULL;

	if (flags & CS_WAIT_COMPLETE) {
		done = &__done;
		init_completion(done);
	}
	rv = ___end_state_change(resource, done, rv);
	spin_unlock_irqrestore(&resource->req_lock, *irq_flags);
	if (done && rv >= SS_SUCCESS &&
	    expect(resource, current != resource->worker.task))
		wait_for_completion(done);
	if ((flags & CS_SERIALIZE) && !(flags & CS_ALREADY_SERIALIZED))
		mutex_unlock(&resource->state_mutex);
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
	if (!(resource->state_change_flags & CS_GLOBAL_LOCKED))
		read_unlock(&global_state_lock);
	spin_unlock_irqrestore(&resource->req_lock, *irq_flags);
}

static void end_remote_state_change(struct drbd_resource *resource, unsigned long *irq_flags, enum chg_state_flags flags)
{
	spin_lock_irqsave(&resource->req_lock, *irq_flags);
	if (!(flags & CS_GLOBAL_LOCKED))
		read_lock(&global_state_lock);
	rcu_read_lock();
	___begin_state_change(resource, flags);
}

union drbd_state drbd_get_device_state(struct drbd_device *device, enum which_state which)
{
	struct drbd_resource *resource = device->resource;
	union drbd_state rv = { {
		.conn = C_STANDALONE,  /* really: undefined */
		/* (user_isp, peer_isp, and aftr_isp are undefined as well.) */
		.disk = device->disk_state[which],
		.role = resource->role[which],
		.peer = R_UNKNOWN,  /* really: undefined */
		.susp = resource->susp[which],
		.susp_nod = resource->susp_nod[which],
		.susp_fen = resource->susp_fen[which],
		.pdsk = D_UNKNOWN,  /* really: undefined */
	} };

	return rv;
}

union drbd_state drbd_get_peer_device_state(struct drbd_peer_device *peer_device, enum which_state which)
{
	struct drbd_connection *connection = peer_device->connection;
	union drbd_state rv;

	rv = drbd_get_device_state(peer_device->device, which);
	rv.user_isp = peer_device->resync_susp_user[which];
	rv.peer_isp = peer_device->resync_susp_peer[which];
	rv.aftr_isp = peer_device->resync_susp_dependency[which];
	rv.conn = combined_conn_state(peer_device, which);
	rv.peer = connection->peer_role[which];
	rv.pdsk = peer_device->disk_state[which];

	return rv;
}

void drbd_set_new_device_state(struct drbd_device *device, union drbd_state state)
{
	struct drbd_resource *resource = device->resource;

	device->disk_state[NEW] = state.disk;
	resource->role[NEW] = state.role;
	resource->susp[NEW] = state.susp;
	resource->susp_nod[NEW] = state.susp_nod;
	resource->susp_fen[NEW] = state.susp_fen;
}

void drbd_set_new_peer_device_state(struct drbd_peer_device *peer_device, union drbd_state state)
{
	struct drbd_connection *connection = peer_device->connection;

	drbd_set_new_device_state(peer_device->device, state);
	peer_device->resync_susp_user[NEW] = state.user_isp;
	peer_device->resync_susp_peer[NEW] = state.peer_isp;
	peer_device->resync_susp_dependency[NEW] = state.aftr_isp;
	peer_device->repl_state[NEW] = max_t(unsigned, state.conn, L_STANDALONE);
	peer_device->disk_state[NEW] = state.pdsk;
	connection->cstate[NEW] = min_t(unsigned, state.conn, C_CONNECTED);
	connection->peer_role[NEW] = state.peer;
}

static inline bool is_susp(union drbd_state s)
{
        return s.susp || s.susp_nod || s.susp_fen;
}

enum drbd_role highest_peer_role(struct drbd_resource *resource)
{
	struct drbd_connection *connection;
	enum drbd_role role = R_UNKNOWN;

	for_each_connection(connection, resource) {
		if (connection->peer_role[NOW] == R_PRIMARY)
			return R_PRIMARY;
		if (connection->peer_role[NOW] == R_SECONDARY)
			role = R_SECONDARY;
	}
	return role;
}

enum drbd_disk_state conn_highest_disk(struct drbd_connection *connection)
{
	enum drbd_disk_state ds = D_DISKLESS;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		ds = max_t(enum drbd_disk_state, ds, device->disk_state[NOW]);
	}
	rcu_read_unlock();

	return ds;
}

enum drbd_disk_state conn_lowest_disk(struct drbd_connection *connection)
{
	enum drbd_disk_state ds = D_MASK;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		ds = min_t(enum drbd_disk_state, ds, device->disk_state[NOW]);
	}
	rcu_read_unlock();

	return ds;
}

enum drbd_disk_state conn_highest_pdsk(struct drbd_connection *connection)
{
	enum drbd_disk_state ds = D_DISKLESS;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
		ds = max_t(enum drbd_disk_state, ds, peer_device->disk_state[NOW]);
	rcu_read_unlock();

	return ds;
}

static enum drbd_repl_state conn_lowest_repl_state(struct drbd_connection *connection)
{
	unsigned int repl_state = -1U;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] < repl_state)
			repl_state = peer_device->repl_state[NOW];
	}
	rcu_read_unlock();

	if (repl_state == -1U)
		return L_STANDALONE;

	return repl_state;
}

static union drbd_state
apply_mask_val(union drbd_state os, union drbd_state mask, union drbd_state val)
{
	union drbd_state ns;
	ns.i = (os.i & ~mask.i) | val.i;
	return ns;
}

enum drbd_state_rv
drbd_change_state(struct drbd_device *device, enum chg_state_flags f,
		  union drbd_state mask, union drbd_state val)
{
	unsigned long irq_flags;
	union drbd_state ns;
	enum drbd_state_rv rv;

	begin_state_change(device->resource, &irq_flags, f);
	ns = apply_mask_val(drbd_get_peer_device_state(first_peer_device(device), NOW), mask, val);
	__drbd_set_state(device, ns);
	rv = end_state_change(device->resource, &irq_flags);

	return rv;
}

/**
 * drbd_req_state() - Perform a state change
 * @device:	DRBD device.
 * @mask:	mask of state bits to change.
 * @val:	value of new state bits.
 * @f:		flags
 *
 * Should not be called directly, use drbd_request_state() or
 * _drbd_request_state().
 */
STATIC enum drbd_state_rv
drbd_req_state(struct drbd_device *device, union drbd_state mask,
	       union drbd_state val, enum chg_state_flags f)
{
	unsigned long irq_flags;
	union drbd_state os, ns;
	enum drbd_state_rv rv;

	begin_state_change(device->resource, &irq_flags, f);
	os = drbd_get_peer_device_state(first_peer_device(device), NOW);
	ns = apply_mask_val(os, mask, val);
	drbd_set_new_peer_device_state(first_peer_device(device), ns);
	rv = end_state_change(device->resource, &irq_flags);

	return rv;
}

/**
 * _drbd_request_state() - Request a state change (with flags)
 * @device:	DRBD device.
 * @mask:	mask of state bits to change.
 * @val:	value of new state bits.
 * @f:		flags
 *
 * Cousin of drbd_request_state(), useful with the CS_WAIT_COMPLETE
 * flag, or when logging of failed state change requests is not desired.
 */
enum drbd_state_rv
_drbd_request_state(struct drbd_device *device, union drbd_state mask,
		    union drbd_state val, enum chg_state_flags f)
{
	enum drbd_state_rv rv;

	wait_event(device->resource->state_wait,
		   (rv = drbd_req_state(device, mask, val, f)) != SS_IN_TRANSIENT_STATE);

	return rv;
}

static bool resync_suspended(struct drbd_peer_device *peer_device, enum which_state which)
{
	return peer_device->resync_susp_user[which] ||
	       peer_device->resync_susp_peer[which] ||
	       peer_device->resync_susp_dependency[which];
}

static int scnprintf_resync_suspend_flags(char *buffer, size_t size,
					  struct drbd_peer_device *peer_device,
					  enum which_state which)
{
	char *b = buffer, *end = buffer + size;

	if (!resync_suspended(peer_device, which))
		return scnprintf(buffer, size, "no");

	if (peer_device->resync_susp_user[which])
		b += scnprintf(b, end - b, "user,");
	if (peer_device->resync_susp_peer[which])
		b += scnprintf(b, end - b, "peer,");
	if (peer_device->resync_susp_dependency[which])
		b += scnprintf(b, end - b, "dependency,");
	*(--b) = 0;

	return b - buffer;
}

static bool io_suspended(struct drbd_resource *resource, enum which_state which)
{
	return resource->susp[which] ||
	       resource->susp_nod[which] ||
	       resource->susp_fen[which];
}

static int scnprintf_io_suspend_flags(char *buffer, size_t size,
				      struct drbd_resource *resource,
				      enum which_state which)
{
	char *b = buffer, *end = buffer + size;

	if (!io_suspended(resource, which))
		return scnprintf(buffer, size, "no");

	if (resource->susp[which])
		b += scnprintf(b, end - b, "user,");
	if (resource->susp_nod[which])
		b += scnprintf(b, end - b, "no-disk,");
	if (resource->susp_fen[which])
		b += scnprintf(b, end - b, "fencing,");
	*(--b) = 0;

	return b - buffer;
}

static void print_state_change(struct drbd_resource *resource, const char *prefix)
{
	char buffer[150], *b, *end = buffer + sizeof(buffer);
	struct drbd_connection *connection;
	struct drbd_device *device;
	enum drbd_role *role = resource->role;
	int vnr;

	b = buffer;
	if (role[OLD] != role[NEW])
		b += scnprintf(b, end - b, "role( %s -> %s ) ",
			       drbd_role_str(role[OLD]),
			       drbd_role_str(role[NEW]));
	if (io_suspended(resource, OLD) != io_suspended(resource, NEW)) {
		b += scnprintf(b, end - b, "susp-io( ");
		b += scnprintf_io_suspend_flags(b, end - b, resource, OLD);
		b += scnprintf(b, end - b, " -> ");
		b += scnprintf_io_suspend_flags(b, end - b, resource, NEW);
		b += scnprintf(b, end - b, ") ");
	}
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

		if (disk_state[OLD] != disk_state[NEW])
			drbd_info(device, "%sdisk( %s -> %s )\n",
				  prefix,
				  drbd_disk_str(disk_state[OLD]),
				  drbd_disk_str(disk_state[NEW]));

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
					       drbd_conn_str(repl_state[OLD]),
					       drbd_conn_str(repl_state[NEW]));

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

static bool local_disk_may_be_outdated(enum drbd_repl_state repl_state)
{
	switch(repl_state) {
	case L_CONNECTED:
	case L_WF_BITMAP_S:
	case L_SYNC_SOURCE:
	case L_PAUSED_SYNC_S:
		return false;
	default:
		return true;
	}
}

static enum drbd_state_rv __is_valid_soft_transition(struct drbd_resource *resource)
{
	enum drbd_role *role = resource->role;
	struct drbd_connection *connection;
	struct drbd_device *device;
	int vnr;

	/* See drbd_state_sw_errors in drbd_strings.c */

	if (role[OLD] != R_PRIMARY && role[NEW] == R_PRIMARY) {
		for_each_connection(connection, resource) {
			struct net_conf *nc;

			nc = rcu_dereference(connection->net_conf);
			if (!nc || nc->two_primaries)
				continue;
			if (connection->peer_role[NEW] == R_PRIMARY)
				return SS_TWO_PRIMARIES;
		}
	}

	for_each_connection(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;

		if (cstate[NEW] == C_DISCONNECTING && cstate[OLD] == C_STANDALONE)
			return SS_ALREADY_STANDALONE;

		if (cstate[NEW] == C_WF_CONNECTION && cstate[OLD] < C_UNCONNECTED)
			return SS_NO_NET_CONFIG;

		if (cstate[NEW] == C_DISCONNECTING && cstate[OLD] == C_UNCONNECTED)
			return SS_IN_TRANSIENT_STATE;

	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		enum drbd_disk_state *disk_state = device->disk_state;
		struct drbd_peer_device *peer_device;

		enum drbd_fencing_policy fencing_policy;

		fencing_policy = FP_DONT_CARE;
		if (get_ldev(device)) {
			fencing_policy = rcu_dereference(device->ldev->disk_conf)->fencing_policy;
			put_ldev(device);
		}

		if (role[OLD] != R_SECONDARY && role[NEW] == R_SECONDARY && device->open_cnt)
			return SS_DEVICE_IN_USE;

		if (disk_state[NEW] > D_ATTACHING && disk_state[OLD] == D_DISKLESS)
			return SS_IS_DISKLESS;

		if (disk_state[NEW] == D_OUTDATED && disk_state[OLD] < D_OUTDATED && disk_state[OLD] != D_ATTACHING)
			return SS_LOWER_THAN_OUTDATED;

		for_each_peer_device(peer_device, device) {
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			enum drbd_repl_state *repl_state = peer_device->repl_state;

			if (!(role[OLD] == R_PRIMARY && repl_state[OLD] < L_CONNECTED && disk_state[OLD] < D_UP_TO_DATE) &&
			     (role[NEW] == R_PRIMARY && repl_state[NEW] < L_CONNECTED && disk_state[NEW] < D_UP_TO_DATE))
				return SS_NO_UP_TO_DATE_DISK;

			if (fencing_policy >= FP_RESOURCE &&
			    !(role[OLD] == R_PRIMARY && repl_state[OLD] < L_CONNECTED && !(peer_disk_state[OLD] <= D_OUTDATED)) &&
			     (role[NEW] == R_PRIMARY && repl_state[NEW] < L_CONNECTED && !(peer_disk_state[NEW] <= D_OUTDATED)))
				return SS_PRIMARY_NOP;

			if (!(role[OLD] == R_PRIMARY && disk_state[OLD] <= D_INCONSISTENT && peer_disk_state[OLD] <= D_INCONSISTENT) &&
			     (role[NEW] == R_PRIMARY && disk_state[NEW] <= D_INCONSISTENT && peer_disk_state[NEW] <= D_INCONSISTENT))
				return SS_NO_UP_TO_DATE_DISK;

			if (!(repl_state[OLD] > L_CONNECTED && disk_state[OLD] < D_INCONSISTENT) &&
			     (repl_state[NEW] > L_CONNECTED && disk_state[NEW] < D_INCONSISTENT))
				return SS_NO_LOCAL_DISK;

			if (!(repl_state[OLD] > L_CONNECTED && peer_disk_state[OLD] < D_INCONSISTENT) &&
			     (repl_state[NEW] > L_CONNECTED && peer_disk_state[NEW] < D_INCONSISTENT))
				return SS_NO_REMOTE_DISK;

			if (!(repl_state[OLD] > L_CONNECTED && disk_state[OLD] < D_UP_TO_DATE && peer_disk_state[OLD] < D_UP_TO_DATE) &&
			     (repl_state[NEW] > L_CONNECTED && disk_state[NEW] < D_UP_TO_DATE && peer_disk_state[NEW] < D_UP_TO_DATE))
				return SS_NO_UP_TO_DATE_DISK;

			if (!(disk_state[OLD] == D_OUTDATED && !local_disk_may_be_outdated(repl_state[OLD])) &&
			     (disk_state[NEW] == D_OUTDATED && !local_disk_may_be_outdated(repl_state[NEW])))
				return SS_CONNECTED_OUTDATES;

			if (!(repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			     (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T)) {
				struct net_conf *nc = rcu_dereference(peer_device->connection->net_conf);

				if (!nc || nc->verify_alg[0] == 0)
					return SS_NO_VERIFY_ALG;
			}

			if (!(repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			     (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) &&
				  peer_device->connection->agreed_pro_version < 88)
				return SS_NOT_SUPPORTED;

			if (!(repl_state[OLD] >= L_CONNECTED && peer_disk_state[OLD] == D_UNKNOWN) &&
			     (repl_state[NEW] >= L_CONNECTED && peer_disk_state[NEW] == D_UNKNOWN))
				return SS_CONNECTED_OUTDATES;

			if ((repl_state[NEW] == L_STARTING_SYNC_T || repl_state[NEW] == L_STARTING_SYNC_S) &&
			    repl_state[OLD] > L_CONNECTED)
				return SS_RESYNC_RUNNING;

			/* if (repl_state[NEW] == repl_state[OLD] && repl_state[NEW] == L_STANDALONE)
				return SS_IN_TRANSIENT_STATE; */

			if ((repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) && repl_state[OLD] < L_CONNECTED)
				return SS_NEED_CONNECTION;

			if ((repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T) &&
			    repl_state[NEW] != repl_state[OLD] && repl_state[OLD] > L_CONNECTED)
				return SS_RESYNC_RUNNING;

			if ((repl_state[NEW] == L_STARTING_SYNC_S || repl_state[NEW] == L_STARTING_SYNC_T) &&
			    repl_state[OLD] < L_CONNECTED)
				return SS_NEED_CONNECTION;

			if ((repl_state[NEW] == L_SYNC_TARGET || repl_state[NEW] == L_SYNC_SOURCE)
			    && repl_state[OLD] < L_STANDALONE)
				return SS_NEED_CONNECTION; /* No NetworkFailure -> SyncTarget etc... */
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
 */
static enum drbd_state_rv is_valid_soft_transition(struct drbd_resource *resource)
{
	enum drbd_state_rv rv;

	rcu_read_lock();
	rv = __is_valid_soft_transition(resource);
	rcu_read_unlock();

	return rv;
}

STATIC enum drbd_state_rv
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
	enum drbd_state_rv rv = SS_SUCCESS;
	struct drbd_connection *connection;
	struct drbd_device *device;
	int vnr;

	for_each_connection(connection, resource) {
		rv = is_valid_conn_transition(connection->cstate[OLD], connection->cstate[NEW]);
		if (rv != SS_SUCCESS)
			break;
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		/* we cannot fail (again) if we already detached */
		if (device->disk_state[NEW] == D_FAILED && device->disk_state[OLD] == D_DISKLESS) {
			rv = SS_IS_DISKLESS;
			break;
		}
	}

	return rv;
}

static void sanitize_state(struct drbd_resource *resource)
{
	enum drbd_role *role = resource->role;
	struct drbd_connection *connection;
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	for_each_connection(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;

		if (cstate[NEW] < C_CONNECTED)
			connection->peer_role[NEW] = R_UNKNOWN;
	}

	idr_for_each_entry(&resource->devices, device, vnr) {
		struct drbd_peer_device *peer_device;
		enum drbd_disk_state *disk_state = device->disk_state;
		enum drbd_fencing_policy fencing_policy;

		fencing_policy = FP_DONT_CARE;
		if (get_ldev(device)) {
			fencing_policy = rcu_dereference(device->ldev->disk_conf)->fencing_policy;
			put_ldev(device);
		}

		if ((resource->state_change_flags & CS_IGN_OUTD_FAIL) &&
		    disk_state[OLD] < D_OUTDATED && disk_state[NEW] == D_OUTDATED)
			disk_state[NEW] = disk_state[OLD];

		for_each_peer_device(peer_device, device) {
			enum drbd_repl_state *repl_state = peer_device->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			struct drbd_connection *connection = peer_device->connection;
			enum drbd_conn_state *cstate = connection->cstate;
			enum drbd_disk_state min_disk_state, max_disk_state;
			enum drbd_disk_state min_peer_disk_state, max_peer_disk_state;

			if (repl_state[NEW] < L_CONNECTED) {
				peer_device->resync_susp_peer[NEW] = false;
				if (peer_disk_state[NEW] > D_UNKNOWN ||
				    peer_disk_state[NEW] < D_INCONSISTENT)
					peer_disk_state[NEW] = D_UNKNOWN;

				if (disk_state[NEW] == D_NEGOTIATING &&
				    get_ldev_if_state(device, D_NEGOTIATING)) {
					disk_state[NEW] = D_DISKLESS;
					peer_disk_state[NEW] = D_UNKNOWN;
					if (device->ed_uuid == device->ldev->md.uuid[UI_CURRENT]) {
						disk_state[NEW] = device->disk_state_from_metadata;
						peer_disk_state[NEW] = device->peer_disk_state_from_metadata;
					}
					put_ldev(device);
				}
			}

			/* Clear the aftr_isp when becoming unconfigured */
			if (cstate[NEW] == C_STANDALONE &&
			    disk_state[NEW] == D_DISKLESS &&
			    role[NEW] == R_SECONDARY)
				peer_device->resync_susp_dependency[NEW] = false;

			/* Abort resync if a disk fails/detaches */
			if (repl_state[NEW] > L_CONNECTED &&
			    (disk_state[NEW] <= D_FAILED ||
			     peer_disk_state[NEW] <= D_FAILED))
				repl_state[NEW] = L_CONNECTED;

			/* D_CONSISTENT and D_OUTDATED vanish when we get connected */
			if (repl_state[NEW] >= L_CONNECTED && repl_state[NEW] < L_AHEAD) {
				if (disk_state[NEW] == D_CONSISTENT ||
				    disk_state[NEW] == D_OUTDATED)
					disk_state[NEW] = D_UP_TO_DATE;
				if (peer_disk_state[NEW] == D_CONSISTENT ||
				    peer_disk_state[NEW] == D_OUTDATED)
					peer_disk_state[NEW] = D_UP_TO_DATE;
			}

			/* Implications of the repl state on the disk states */
			min_disk_state = D_DISKLESS;
			max_disk_state = D_UP_TO_DATE;
			min_peer_disk_state = D_INCONSISTENT;
			max_peer_disk_state = D_UNKNOWN;
			switch (repl_state[NEW]) {
			case L_STANDALONE:
				/* values from above */
				break;
			case L_WF_BITMAP_T:
			case L_PAUSED_SYNC_T:
			case L_STARTING_SYNC_T:
			case L_WF_SYNC_UUID:
			case L_BEHIND:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_OUTDATED;
				min_peer_disk_state = D_UP_TO_DATE;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_VERIFY_S:
			case L_VERIFY_T:
				min_disk_state = D_UP_TO_DATE;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_UP_TO_DATE;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_CONNECTED:
				min_disk_state = D_DISKLESS;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_DISKLESS;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_WF_BITMAP_S:
			case L_PAUSED_SYNC_S:
			case L_STARTING_SYNC_S:
			case L_AHEAD:
				min_disk_state = D_UP_TO_DATE;
				max_disk_state = D_UP_TO_DATE;
				min_peer_disk_state = D_INCONSISTENT;
				max_peer_disk_state = D_CONSISTENT; /* D_OUTDATED would be nice. But explicit outdate necessary*/
				break;
			case L_SYNC_TARGET:
				min_disk_state = D_INCONSISTENT;
				max_disk_state = D_INCONSISTENT;
				min_peer_disk_state = D_UP_TO_DATE;
				max_peer_disk_state = D_UP_TO_DATE;
				break;
			case L_SYNC_SOURCE:
				min_disk_state = D_UP_TO_DATE;
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

			/* Suspend IO while fence-peer handler runs (peer lost) */
			if (fencing_policy == FP_STONITH &&
			    (role[NEW] == R_PRIMARY &&
			     repl_state[NEW] < L_CONNECTED &&
			     peer_disk_state[NEW] > D_OUTDATED)) {
				resource->susp_fen[NEW] = true;
			}

			/* Suspend IO while no data available (no accessible data available) */
			if (resource->res_opts.on_no_data == OND_SUSPEND_IO &&
			    (role[NEW] == R_PRIMARY &&
			     disk_state[NEW] < D_UP_TO_DATE &&
			     peer_disk_state[NEW] < D_UP_TO_DATE))
				resource->susp_nod[NEW] = true;

			if (resync_suspended(peer_device, NEW)) {
				if (repl_state[NEW] == L_SYNC_SOURCE)
					repl_state[NEW] = L_PAUSED_SYNC_S;
				if (repl_state[NEW] == L_SYNC_TARGET)
					repl_state[NEW] = L_PAUSED_SYNC_T;
				if (repl_state[NEW] == L_PAUSED_SYNC_S)
					repl_state[NEW] = L_SYNC_SOURCE;
				if (repl_state[NEW] == L_PAUSED_SYNC_T)
					repl_state[NEW] = L_SYNC_TARGET;
			}
		}
	}
	rcu_read_unlock();
}

void drbd_resume_al(struct drbd_device *device)
{
	if (test_and_clear_bit(AL_SUSPENDED, &device->flags))
		drbd_info(device, "Resumed AL updates\n");
}

/* helper for __drbd_set_state */
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
	peer_device->ov_left = peer_device->rs_total;
}

static void queue_after_state_change_work(struct drbd_resource *resource,
					  struct completion *done, gfp_t gfp)
{
	struct after_state_change_work *work;

	work = kmalloc(sizeof(*work), gfp);
	if (work)
		work->state_change = remember_state_change(resource, gfp);
	if (work && work->state_change) {
		work->w.cb = w_after_state_change;
		work->done = done;
		drbd_queue_work(&resource->work, &work->w);
	} else {
		if (work)
			forget_state_change(work->state_change);
		drbd_err(resource, "Could not allocate after state change work\n");
	}
}

/**
 * finish_state_change  -  carry out actions triggered by a state change
 */
static void finish_state_change(struct drbd_resource *resource, struct completion *done)
{
	struct drbd_device *device;
	struct drbd_connection *connection;
	int vnr;

	print_state_change(resource, "");

	idr_for_each_entry(&resource->devices, device, vnr) {
		enum drbd_disk_state *disk_state = device->disk_state;
		struct drbd_peer_device *peer_device;

		/* if we are going -> D_FAILED or D_DISKLESS, grab one extra reference
		 * on the ldev here, to be sure the transition -> D_DISKLESS resp.
		 * drbd_ldev_destroy() won't happen before our corresponding
		 * w_after_state_change works run, where we put_ldev again. */
		if ((disk_state[OLD] != D_FAILED && disk_state[NEW] == D_FAILED) ||
		    (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS))
			atomic_inc(&device->local_cnt);

		if (disk_state[OLD] == D_ATTACHING && disk_state[NEW] >= D_NEGOTIATING)
			drbd_print_uuids(device, "attached to UUIDs");

		wake_up(&device->misc_wait);
		wake_up(&device->resource->state_wait);

		for_each_peer_device(peer_device, device) {
			enum drbd_repl_state *repl_state = peer_device->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device->disk_state;
			struct drbd_connection *connection = peer_device->connection;
			enum drbd_role *peer_role = connection->peer_role;

			/* aborted verify run. log the last position */
			if ((repl_state[OLD] == L_VERIFY_S || repl_state[OLD] == L_VERIFY_T) &&
			    repl_state[NEW] < L_CONNECTED) {
				peer_device->ov_start_sector =
					BM_BIT_TO_SECT(drbd_bm_bits(device) - peer_device->ov_left);
				drbd_info(peer_device, "Online Verify reached sector %llu\n",
					(unsigned long long)peer_device->ov_start_sector);
			}

			if ((repl_state[OLD] == L_PAUSED_SYNC_T || repl_state[OLD] == L_PAUSED_SYNC_S) &&
			    (repl_state[NEW] == L_SYNC_TARGET  || repl_state[NEW] == L_SYNC_SOURCE)) {
				drbd_info(peer_device, "Syncer continues.\n");
				peer_device->rs_paused += (long)jiffies
						  -(long)peer_device->rs_mark_time[peer_device->rs_last_mark];
				if (repl_state[NEW] == L_SYNC_TARGET)
					mod_timer(&peer_device->resync_timer, jiffies);
			}

			if ((repl_state[OLD] == L_SYNC_TARGET  || repl_state[OLD] == L_SYNC_SOURCE) &&
			    (repl_state[NEW] == L_PAUSED_SYNC_T || repl_state[NEW] == L_PAUSED_SYNC_S)) {
				drbd_info(peer_device, "Resync suspended\n");
				peer_device->rs_mark_time[peer_device->rs_last_mark] = jiffies;
			}

			if (repl_state[OLD] == L_CONNECTED &&
			    (repl_state[NEW] == L_VERIFY_S || repl_state[NEW] == L_VERIFY_T)) {
				unsigned long now = jiffies;
				int i;

				set_ov_position(peer_device, repl_state[NEW]);
				peer_device->rs_start = now;
				peer_device->rs_last_events = 0;
				peer_device->rs_last_sect_ev = 0;
				peer_device->ov_last_oos_size = 0;
				peer_device->ov_last_oos_start = 0;

				for (i = 0; i < DRBD_SYNC_MARKS; i++) {
					peer_device->rs_mark_left[i] = peer_device->ov_left;
					peer_device->rs_mark_time[i] = now;
				}

				drbd_rs_controller_reset(peer_device);

				if (repl_state[NEW] == L_VERIFY_S) {
					drbd_info(peer_device, "Starting Online Verify from sector %llu\n",
							(unsigned long long)peer_device->ov_position);
					mod_timer(&peer_device->resync_timer, jiffies);
				}
			}

			if (get_ldev(device)) {
				u32 mdf = device->ldev->md.flags & ~(MDF_CONSISTENT|MDF_PRIMARY_IND|
								 MDF_CONNECTED_IND|MDF_WAS_UP_TO_DATE|
								 MDF_PEER_OUT_DATED|MDF_CRASHED_PRIMARY);
				mdf &= ~MDF_AL_CLEAN;
				if (test_bit(CRASHED_PRIMARY, &device->flags))
					mdf |= MDF_CRASHED_PRIMARY;
				if (device->resource->role[NEW] == R_PRIMARY ||
				    (peer_device->disk_state[NEW] < D_INCONSISTENT &&
				     highest_peer_role(device->resource) == R_PRIMARY))
					mdf |= MDF_PRIMARY_IND;
				if (peer_device->repl_state[NEW] > L_STANDALONE)
					mdf |= MDF_CONNECTED_IND;
				if (disk_state[NEW] > D_INCONSISTENT)
					mdf |= MDF_CONSISTENT;
				if (disk_state[NEW] > D_OUTDATED)
					mdf |= MDF_WAS_UP_TO_DATE;
				if (peer_device->disk_state[NEW] <= D_OUTDATED &&
				    peer_device->disk_state[NEW] >= D_INCONSISTENT)
					mdf |= MDF_PEER_OUT_DATED;
				if (mdf != device->ldev->md.flags) {
					device->ldev->md.flags = mdf;
					drbd_md_mark_dirty(device);
				}
				if (disk_state[OLD] < D_CONSISTENT && disk_state[NEW] >= D_CONSISTENT)
					drbd_set_ed_uuid(device, device->ldev->md.uuid[UI_CURRENT]);
				put_ldev(device);

				/* Peer was forced D_UP_TO_DATE & R_PRIMARY, consider to resync */
				if (disk_state[OLD] == D_INCONSISTENT && peer_disk_state[OLD] == D_INCONSISTENT &&
				    peer_role[OLD] == R_SECONDARY && peer_role[NEW] == R_PRIMARY)
					set_bit(CONSIDER_RESYNC, &peer_device->flags);

				/* Resume AL writing if we get a connection */
				if (repl_state[OLD] < L_CONNECTED && repl_state[NEW] >= L_CONNECTED)
					drbd_resume_al(device);
			}
		}
	}

	for_each_connection(connection, resource) {
		enum drbd_conn_state *cstate = connection->cstate;

		if (cstate[OLD] == C_CONNECTED && cstate[NEW] != C_CONNECTED &&
		    test_and_clear_bit(CONN_WD_ST_CHG_REQ, &connection->flags))
			wake_up(&resource->state_wait);

		wake_up(&connection->ping_wait);

		/* Receiver should clean up itself */
		if (cstate[OLD] != C_DISCONNECTING && cstate[NEW] == C_DISCONNECTING)
			drbd_thread_stop_nowait(&connection->receiver);

		/* Now the receiver finished cleaning up itself, it should die */
		if (cstate[OLD] != C_STANDALONE && cstate[NEW] == C_STANDALONE)
			drbd_thread_stop_nowait(&connection->receiver);

		/* Upon network failure, we need to restart the receiver. */
		if (cstate[OLD] > C_WF_CONNECTION &&
		    cstate[NEW] <= C_TEAR_DOWN && cstate[NEW] >= C_TIMEOUT)
			drbd_thread_restart_nowait(&connection->receiver);
	}

	queue_after_state_change_work(resource, done, GFP_ATOMIC);
}

/**
 * __drbd_set_state() - Set a new DRBD state
 * @device:	DRBD device.
 * @ns:		new state.
 * @flags:	Flags
 *
 * Caller needs to hold req_lock, and global_state_lock. Do not call directly.
 */
void __drbd_set_state(struct drbd_device *device, union drbd_state ns)
{
	drbd_set_new_peer_device_state(first_peer_device(device), ns);
}

static void abw_start_sync(struct drbd_device *device, int rv)
{
	if (rv) {
		drbd_err(device, "Writing the bitmap failed not starting resync.\n");
		_drbd_request_state(device, NS(conn, L_CONNECTED), CS_VERBOSE);
		return;
	}

	switch (first_peer_device(device)->repl_state[NOW]) {
	case L_STARTING_SYNC_T:
		_drbd_request_state(device, NS(conn, L_WF_SYNC_UUID), CS_VERBOSE);
		break;
	case L_STARTING_SYNC_S:
		drbd_start_resync(device, L_SYNC_SOURCE);
		break;
	default:
		break;
	}
}

static int drbd_bitmap_io_from_worker(struct drbd_device *device,
		int (*io_fn)(struct drbd_device *, struct drbd_peer_device *),
		char *why, enum bm_flag flags,
		struct drbd_peer_device *peer_device)
{
	int rv;

	D_ASSERT(device, current == device->resource->worker.task);

	/* open coded non-blocking drbd_suspend_io(device); */
	set_bit(SUSPEND_IO, &device->flags);

	drbd_bm_lock(device, why, flags);
	rv = io_fn(device, peer_device);
	drbd_bm_unlock(device);

	drbd_resume_io(device);

	return rv;
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
	state.susp = resource_state_change->susp[which];
	state.susp_nod = resource_state_change->susp_nod[which];
	state.susp_fen = resource_state_change->susp_fen[which];
	state.disk = device_state_change->disk_state[which];
	if (n_connection != -1) {
		struct drbd_connection_state_change *connection_state_change =
			&state_change->connections[n_connection];
		struct drbd_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];

		state.peer = connection_state_change->peer_role[which];
		state.conn = peer_device_state_change->repl_state[which];
		if (state.conn <= L_STANDALONE)
			state.conn = connection_state_change->cstate[which];
		state.pdsk = peer_device_state_change->disk_state[which];
		state.aftr_isp = peer_device_state_change->resync_susp_dependency[which];
		state.peer_isp = peer_device_state_change->resync_susp_peer[which];
		state.user_isp = peer_device_state_change->resync_susp_user[which];
	}
	return state;
}

static void broadcast_state_change(struct drbd_state_change *state_change)
{
	struct drbd_resource_state_change *resource_state_change = &state_change->resource[0];
	bool resource_state_has_changed;
	unsigned int n_device;

#define HAS_CHANGED(state) ((state)[OLD] != (state)[NEW])

	resource_state_has_changed =
	    HAS_CHANGED(resource_state_change->role) ||
	    HAS_CHANGED(resource_state_change->susp) ||
	    HAS_CHANGED(resource_state_change->susp_nod) ||
	    HAS_CHANGED(resource_state_change->susp_fen);

	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_device_state_change *device_state_change =
			&state_change->devices[n_device];
		struct drbd_peer_device_state_change *peer_device_state_change = NULL;
		struct drbd_connection_state_change *connection_state_change = NULL;
		int n_connection = -1;

		if (state_change->n_connections == 1) {
			connection_state_change = &state_change->connections[0];
			peer_device_state_change = &state_change->peer_devices[n_device];
			n_connection = 0;
		}

		if (resource_state_has_changed ||
		    HAS_CHANGED(device_state_change->disk_state) ||
		    (connection_state_change &&
		     (HAS_CHANGED(connection_state_change->peer_role) ||
		      HAS_CHANGED(connection_state_change->cstate))) ||
		    (peer_device_state_change &&
		     (HAS_CHANGED(peer_device_state_change->disk_state) ||
		      HAS_CHANGED(peer_device_state_change->repl_state) ||
		      HAS_CHANGED(peer_device_state_change->resync_susp_user) ||
		      HAS_CHANGED(peer_device_state_change->resync_susp_peer) ||
		      HAS_CHANGED(peer_device_state_change->resync_susp_dependency)))) {
			struct sib_info sib;

			sib.sib_reason = SIB_STATE_CHANGE;
			sib.os = state_change_word(state_change, n_device, n_connection, OLD);
			sib.ns = state_change_word(state_change, n_device, n_connection, NEW);
			drbd_bcast_event(device_state_change->device, &sib);
		}
	}

#undef HAS_CHANGED
}

static void send_new_state_to_all_peer_devices(struct drbd_state_change *state_change, unsigned int n_device)
{
	unsigned int n_connection;

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_peer_device_state_change *peer_device_state_change =
			&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
		struct drbd_peer_device *peer_device = peer_device_state_change->peer_device;
		union drbd_state new_state = state_change_word(state_change, n_device, n_connection, NEW);

		drbd_send_state(peer_device, new_state);
	}
}

/*
 * Perform after state change actions that may sleep.
 */
STATIC int w_after_state_change(struct drbd_work *w, int unused)
{
	struct after_state_change_work *work =
		container_of(w, struct after_state_change_work, w);
	struct drbd_state_change *state_change = work->state_change;
	struct drbd_resource_state_change *resource_state_change = &state_change->resource[0];
	struct drbd_resource *resource = resource_state_change->resource;
	enum drbd_role *role = resource_state_change->role;
	bool *susp_nod = resource_state_change->susp_nod;
	bool *susp_fen = resource_state_change->susp_fen;
	struct drbd_peer_device_state_change *peer_device_state_change;
	int n_device, n_connection;

	broadcast_state_change(state_change);

	peer_device_state_change = &state_change->peer_devices[0];
	for (n_device = 0; n_device < state_change->n_devices; n_device++) {
		struct drbd_device_state_change *device_state_change = &state_change->devices[n_device];
		struct drbd_device *device = device_state_change->device;
		enum drbd_disk_state *disk_state = device_state_change->disk_state;

		for (n_connection = 0; n_connection < state_change->n_connections; n_connection++, peer_device_state_change++) {
			struct drbd_connection_state_change *connection_state_change = &state_change->connections[n_connection];
			struct drbd_connection *connection = connection_state_change->connection;
			enum drbd_conn_state *cstate = connection_state_change->cstate;
			enum drbd_role *peer_role = connection_state_change->peer_role;
			struct drbd_peer_device *peer_device = peer_device_state_change->peer_device;
			enum drbd_repl_state *repl_state = peer_device_state_change->repl_state;
			enum drbd_disk_state *peer_disk_state = peer_device_state_change->disk_state;
			bool *resync_susp_user = peer_device_state_change->resync_susp_user;
			bool *resync_susp_peer = peer_device_state_change->resync_susp_peer;
			bool *resync_susp_dependency = peer_device_state_change->resync_susp_dependency;
			union drbd_state new_state =
				state_change_word(state_change, n_device, n_connection, NEW);

			if (repl_state[OLD] != L_CONNECTED && repl_state[NEW] == L_CONNECTED) {
				clear_bit(CRASHED_PRIMARY, &device->flags);
				if (device->p_uuid)
					device->p_uuid[UI_FLAGS] &= ~((u64)2);
			}

			if (!(role[OLD] == R_PRIMARY && disk_state[OLD] < D_UP_TO_DATE && peer_disk_state[OLD] < D_UP_TO_DATE) &&
			     (role[NEW] == R_PRIMARY && disk_state[NEW] < D_UP_TO_DATE && peer_disk_state[NEW] < D_UP_TO_DATE))
				drbd_khelper(device, "pri-on-incon-degr");

			if (susp_nod[NEW]) {
				enum drbd_req_event what = NOTHING;

				if (repl_state[OLD] < L_CONNECTED &&
				    conn_lowest_repl_state(connection) >= L_CONNECTED)
					what = RESEND;

				if ((disk_state[OLD] == D_ATTACHING || disk_state[OLD] == D_NEGOTIATING) &&
				    conn_lowest_disk(connection) > D_NEGOTIATING)
					what = RESTART_FROZEN_DISK_IO;

				if (what != NOTHING) {
					unsigned long irq_flags;

					begin_state_change(resource, &irq_flags, CS_VERBOSE);
					_tl_restart(connection, what);
					__drbd_set_state(device, _NS(device, susp_nod, 0));
					end_state_change(resource, &irq_flags);
				}
			}

			/* Became sync source.  With protocol >= 96, we still need to send out
			 * the sync uuid now. Need to do that before any drbd_send_state, or
			 * the other side may go "paused sync" before receiving the sync uuids,
			 * which is unexpected. */
			if (!(repl_state[OLD] == L_SYNC_SOURCE || repl_state[OLD] == L_PAUSED_SYNC_S) &&
			     (repl_state[NEW] == L_SYNC_SOURCE || repl_state[NEW] == L_PAUSED_SYNC_S) &&
			    connection->agreed_pro_version >= 96 && get_ldev(device)) {
				drbd_gen_and_send_sync_uuid(peer_device);
				put_ldev(device);
			}

			/* Do not change the order of the if above and the two below... */
			if (peer_disk_state[OLD] == D_DISKLESS &&
			    peer_disk_state[NEW] > D_DISKLESS && peer_disk_state[NEW] != D_UNKNOWN) {      /* attach on the peer */
				drbd_send_uuids(peer_device);
				drbd_send_state(peer_device, new_state);
			}
			/* No point in queuing send_bitmap if we don't have a connection
			 * anymore, so check also the _current_ state, not only the new state
			 * at the time this work was queued. */
			if (repl_state[OLD] != L_WF_BITMAP_S && repl_state[NEW] == L_WF_BITMAP_S &&
			    peer_device->repl_state[NOW] == L_WF_BITMAP_S)
				drbd_queue_bitmap_io(device, &drbd_send_bitmap, NULL,
						"send_bitmap (WFBitMapS)",
						BM_LOCKED_TEST_ALLOWED,
						peer_device);

			/* Lost contact to peer's copy of the data */
			if (!(peer_disk_state[OLD] < D_INCONSISTENT || peer_disk_state[OLD] == D_UNKNOWN || peer_disk_state[OLD] == D_OUTDATED) &&
			     (peer_disk_state[NEW] < D_INCONSISTENT || peer_disk_state[NEW] == D_UNKNOWN || peer_disk_state[NEW] == D_OUTDATED)) {
				if (get_ldev(device)) {
					if ((role[NEW] == R_PRIMARY || peer_role[NEW] == R_PRIMARY) &&
					    device->ldev->md.uuid[UI_BITMAP] == 0 && disk_state[NEW] >= D_UP_TO_DATE) {
						if (drbd_suspended(device)) {
							set_bit(NEW_CUR_UUID, &device->flags);
						} else {
							drbd_uuid_new_current(device);
							drbd_send_uuids(peer_device);
						}
					}
					put_ldev(device);
				}
			}

			if (peer_disk_state[NEW] < D_INCONSISTENT && get_ldev(device)) {
				/* D_DISKLESS Peer becomes secondary */
				if (peer_role[OLD] == R_PRIMARY && peer_role[NEW] == R_SECONDARY)
					/* We may still be Primary ourselves.
					 * No harm done if the bitmap still changes,
					 * redirtied pages will follow later. */
					drbd_bitmap_io_from_worker(device, &drbd_bm_write,
						"demote diskless peer", BM_LOCKED_SET_ALLOWED,
						NULL);
				put_ldev(device);
			}

			/* Write out all changed bits on demote.
			 * Though, no need to da that just yet
			 * if there is a resync going on still */
			if (role[OLD] == R_PRIMARY && role[NEW] == R_SECONDARY &&
				peer_device->repl_state[NOW] <= L_CONNECTED && get_ldev(device)) {
				/* No changes to the bitmap expected this time, so assert that,
				 * even though no harm was done if it did change. */
				drbd_bitmap_io_from_worker(device, &drbd_bm_write,
						"demote", BM_LOCKED_TEST_ALLOWED,
						NULL);
				put_ldev(device);
			}

			/* Last part of the attaching process ... */
			if (repl_state[NEW] >= L_CONNECTED &&
			    disk_state[OLD] == D_ATTACHING && disk_state[NEW] == D_NEGOTIATING) {
				drbd_send_sizes(peer_device, 0, 0);  /* to start sync... */
				drbd_send_uuids(peer_device);
				drbd_send_state(peer_device, new_state);
			}

			/* We want to pause/continue resync, tell peer. */
			if (repl_state[NEW] >= L_CONNECTED &&
			     ((resync_susp_dependency[OLD] != resync_susp_dependency[NEW]) ||
			      (resync_susp_user[OLD] != resync_susp_user[NEW])))
				drbd_send_state(peer_device, new_state);

			/* In case one of the isp bits got set, suspend other devices. */
			if (!(resync_susp_dependency[OLD] || resync_susp_peer[OLD] || resync_susp_user[OLD]) &&
			     (resync_susp_dependency[NEW] || resync_susp_peer[NEW] || resync_susp_user[NEW]))
				suspend_other_sg(device);

			/* Make sure the peer gets informed about eventual state
			   changes (ISP bits) while we were in L_STANDALONE. */
			if (repl_state[OLD] == L_STANDALONE && repl_state[NEW] >= L_CONNECTED)
				drbd_send_state(peer_device, new_state);

			if (repl_state[OLD] != L_AHEAD && repl_state[NEW] == L_AHEAD)
				drbd_send_state(peer_device, new_state);

			/* We are in the progress to start a full sync... */
			if ((repl_state[OLD] != L_STARTING_SYNC_T && repl_state[NEW] == L_STARTING_SYNC_T) ||
			    (repl_state[OLD] != L_STARTING_SYNC_S && repl_state[NEW] == L_STARTING_SYNC_S))
				/* no other bitmap changes expected during this phase */
				drbd_queue_bitmap_io(device,
					&drbd_bmio_set_n_write, &abw_start_sync,
					"set_n_write from StartingSync", BM_LOCKED_TEST_ALLOWED,
					NULL);

			/* We are invalidating our self... */
			if (repl_state[OLD] < L_CONNECTED && repl_state[NEW] < L_CONNECTED &&
			    disk_state[OLD] > D_INCONSISTENT && disk_state[NEW] == D_INCONSISTENT)
				/* other bitmap operation expected during this phase */
				drbd_queue_bitmap_io(device, &drbd_bmio_set_n_write, NULL,
					"set_n_write from invalidate", BM_LOCKED_MASK,
					NULL);

			/* Disks got bigger while they were detached */
			if (disk_state[NEW] > D_NEGOTIATING && peer_disk_state[NEW] > D_NEGOTIATING &&
			    test_and_clear_bit(RESYNC_AFTER_NEG, &peer_device->flags)) {
				if (repl_state[NEW] == L_CONNECTED)
					resync_after_online_grow(device);
			}

			/* A resync finished or aborted, wake paused devices... */
			if ((repl_state[OLD] > L_CONNECTED && repl_state[NEW] <= L_CONNECTED) ||
			    (resync_susp_peer[OLD] && !resync_susp_peer[NEW]) ||
			    (resync_susp_user[OLD] && !resync_susp_user[NEW]))
				resume_next_sg(device);

			/* sync target done with resync.  Explicitly notify peer, even though
			 * it should (at least for non-empty resyncs) already know itself. */
			if (disk_state[OLD] < D_UP_TO_DATE && repl_state[OLD] >= L_SYNC_SOURCE && repl_state[NEW] == L_CONNECTED)
				drbd_send_state(peer_device, new_state);

			/* This triggers bitmap writeout of potentially still unwritten pages
			 * if the resync finished cleanly, or aborted because of peer disk
			 * failure, or because of connection loss.
			 * For resync aborted because of local disk failure, we cannot do
			 * any bitmap writeout anymore.
			 * No harm done if some bits change during this phase.
			 */
			if (repl_state[OLD] > L_CONNECTED && repl_state[NEW] <= L_CONNECTED && get_ldev(device)) {
				drbd_queue_bitmap_io(device, &drbd_bm_write, NULL,
					"write from resync_finished", BM_LOCKED_SET_ALLOWED,
					NULL);
				put_ldev(device);
			}

			if (disk_state[NEW] == D_DISKLESS &&
			    cstate[NEW] == C_STANDALONE &&
			    role[NEW] == R_SECONDARY) {
				if (resync_susp_dependency[OLD] != resync_susp_dependency[NEW])
					resume_next_sg(device);
			}
		}

		/* first half of local IO error, failure to attach,
		 * or administrative detach */
		if (disk_state[OLD] != D_FAILED && disk_state[NEW] == D_FAILED) {
			enum drbd_io_error_p eh;
			int was_io_error;

			/*
			 * finish_state_change() has grabbed a reference on
			 * ldev in this case.
			 */
			rcu_read_lock();
			eh = rcu_dereference(device->ldev->disk_conf)->on_io_error;
			rcu_read_unlock();
			was_io_error = test_and_clear_bit(WAS_IO_ERROR, &device->flags);

			/* Immediately allow completion of all application IO, that waits
			   for completion from the local disk. */
			tl_abort_disk_io(device);

			/* current state still has to be D_FAILED,
			 * there is only one way out: to D_DISKLESS,
			 * and that may only happen after our put_ldev below. */
			if (device->disk_state[NOW] != D_FAILED)
				drbd_err(device,
					"ASSERT FAILED: disk is %s during detach\n",
					drbd_disk_str(device->disk_state[NOW]));

			send_new_state_to_all_peer_devices(state_change, n_device);

			for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
				struct drbd_peer_device *peer_device;

				peer_device_state_change = &state_change->peer_devices[
					n_device * state_change->n_connections + n_connection];
				peer_device = peer_device_state_change->peer_device;
				drbd_rs_cancel_all(peer_device);
			}

			/* In case we want to get something to stable storage still,
			 * this may be the last chance.
			 * Following put_ldev may transition to D_DISKLESS. */
			drbd_md_sync(device);
			put_ldev(device);

			if (was_io_error && eh == EP_CALL_HELPER)
				drbd_khelper(device, "local-io-error");
		}

		/* second half of local IO error, failure to attach,
		 * or administrative detach,
		 * after local_cnt references have reached zero again */
		if (disk_state[OLD] != D_DISKLESS && disk_state[NEW] == D_DISKLESS) {
			struct drbd_peer_device *peer_device;

			/* We must still be diskless,
			 * re-attach has to be serialized with this! */
			if (device->disk_state[NOW] != D_DISKLESS)
				drbd_err(device,
					"ASSERT FAILED: disk is %s while going diskless\n",
					drbd_disk_str(device->disk_state[NOW]));

			rcu_read_lock();
			for_each_peer_device(peer_device, device) {
				peer_device->rs_total = 0;
				peer_device->rs_failed = 0;
				atomic_set(&peer_device->rs_pending_cnt, 0);
			}
			rcu_read_unlock();

			send_new_state_to_all_peer_devices(state_change, n_device);
			/*
			 * finish_state_change() has grabbed a reference on
			 * ldev in this case.
			 */
			put_ldev(device);
		}

		/* Notify peers that I had a local IO error and did not detach. */
		if (disk_state[OLD] == D_UP_TO_DATE && disk_state[NEW] == D_INCONSISTENT)
			send_new_state_to_all_peer_devices(state_change, n_device);

		drbd_md_sync(device);
	}

	for (n_connection = 0; n_connection < state_change->n_connections; n_connection++) {
		struct drbd_connection_state_change *connection_state_change = &state_change->connections[n_connection];
		struct drbd_connection *connection = connection_state_change->connection;
		enum drbd_conn_state *cstate = connection_state_change->cstate;

		/* Upon network configuration, we need to start the receiver */
		if (cstate[OLD] == C_STANDALONE && cstate[NEW] == C_UNCONNECTED)
			drbd_thread_start(&connection->receiver);

		if (cstate[OLD] == C_DISCONNECTING && cstate[NEW] == C_STANDALONE) {
			struct net_conf *old_conf;

			mutex_lock(&resource->conf_update);
			old_conf = connection->net_conf;
			connection->my_addr_len = 0;
			connection->peer_addr_len = 0;
			rcu_assign_pointer(connection->net_conf, NULL);
			conn_free_crypto(connection);
			mutex_unlock(&resource->conf_update);

			synchronize_rcu();
			kfree(old_conf);
		}

		if (susp_fen[NEW]) {
			bool all_peer_disks_outdated = true;
			bool all_peer_disks_connected = true;

			/* Iterate over all peer devices on this connection.  */
			for (n_device = 0; n_device < state_change->n_devices; n_device++) {
				struct drbd_peer_device_state_change *peer_device_state_change =
					&state_change->peer_devices[n_device * state_change->n_connections + n_connection];
				enum drbd_repl_state *repl_state = peer_device_state_change->repl_state;
				enum drbd_disk_state *peer_disk_state = peer_device_state_change->disk_state;

				if (peer_disk_state[NEW] > D_OUTDATED)
					all_peer_disks_outdated = false;
				if (repl_state[NEW] < L_CONNECTED)
					all_peer_disks_connected = false;
			}

			/* case1: The outdate peer handler is successful: */
			if (all_peer_disks_outdated) {
				struct drbd_peer_device *peer_device;
				int vnr;

				tl_clear(connection);
				rcu_read_lock();
				idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
					struct drbd_device *device = peer_device->device;
					if (test_bit(NEW_CUR_UUID, &device->flags)) {
						drbd_uuid_new_current(device);
						clear_bit(NEW_CUR_UUID, &device->flags);
					}
				}
				rcu_read_unlock();
				conn_request_state(connection,
						   (union drbd_state) { { .susp_fen = 1 } },
						   (union drbd_state) { { .susp_fen = 0 } },
						   CS_VERBOSE);
			}
			/* case2: The connection was established again: */
			if (all_peer_disks_connected) {
				struct drbd_peer_device *peer_device;
				unsigned long irq_flags;
				int vnr;

				rcu_read_lock();
				idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
					struct drbd_device *device = peer_device->device;
					clear_bit(NEW_CUR_UUID, &device->flags);
				}
				rcu_read_unlock();
				begin_state_change(resource, &irq_flags, CS_VERBOSE);
				_tl_restart(connection, RESEND);
				_conn_request_state(connection,
						    (union drbd_state) { { .susp_fen = 1 } },
						    (union drbd_state) { { .susp_fen = 0 } });
				end_state_change(resource, &irq_flags);
			}
		}
	}

	if (work->done)
		complete(work->done);
	forget_state_change(state_change);
	kfree(work);

	return 0;
}

static void conn_set_state(struct drbd_connection *connection,
			   union drbd_state mask, union drbd_state val)
{
	union drbd_state ns, os;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		os = drbd_get_peer_device_state(peer_device, NOW);
		ns = apply_mask_val(os, mask, val);
		__drbd_set_state(device, ns);
	}
	rcu_read_unlock();
}

void
_conn_request_state(struct drbd_connection *connection, union drbd_state mask, union drbd_state val)
{
	conn_set_state(connection, mask, val);
}

enum drbd_state_rv
conn_request_state(struct drbd_connection *connection, union drbd_state mask, union drbd_state val,
		   enum chg_state_flags flags)
{
	unsigned long irq_flags;
	enum drbd_state_rv rv;

	begin_state_change(connection->resource, &irq_flags, flags);
	_conn_request_state(connection, mask, val);
	rv = end_state_change(connection->resource, &irq_flags);

	return rv;
}

static inline bool local_state_change(enum chg_state_flags flags)
{
	return flags & (CS_HARD | CS_LOCAL_ONLY);
}

static enum drbd_state_rv
__peer_request(struct drbd_connection *connection, int vnr,
	       union drbd_state mask, union drbd_state val)
{
	enum drbd_state_rv rv = SS_SUCCESS;

	if (connection->cstate[NOW] == C_CONNECTED) {
		if (!conn_send_state_req(connection, vnr, mask, val)) {
			set_bit(CONN_WD_ST_CHG_REQ, &connection->flags);
			rv = SS_CW_SUCCESS;
		}
	}
	return rv;
}

static enum drbd_state_rv __peer_reply(struct drbd_connection *connection)
{
	if (test_and_clear_bit(CONN_WD_ST_CHG_FAIL, &connection->flags))
		return SS_CW_FAILED_BY_PEER;
	if (test_and_clear_bit(CONN_WD_ST_CHG_OKAY, &connection->flags) ||
	    !test_bit(CONN_WD_ST_CHG_REQ, &connection->flags))
		return SS_CW_SUCCESS;
	return SS_UNKNOWN_ERROR;
}

static enum drbd_state_rv
change_peer_state(struct drbd_connection *connection, int vnr,
		  union drbd_state mask, union drbd_state val, unsigned long *irq_flags)
{
	struct drbd_resource *resource = connection->resource;
	enum chg_state_flags flags = resource->state_change_flags;
	enum drbd_state_rv rv;

	if (!expect(resource, flags & CS_SERIALIZE))
		return SS_CW_FAILED_BY_PEER;
	begin_remote_state_change(resource, irq_flags);
	rv = __peer_request(connection, vnr, mask, val);
	if (rv == SS_CW_SUCCESS) {
		wait_event(resource->state_wait,
			((rv = __peer_reply(connection)) != SS_UNKNOWN_ERROR));
		clear_bit(CONN_WD_ST_CHG_REQ, &connection->flags);
	}
	end_remote_state_change(resource, irq_flags, flags);
	return rv;
}

void __change_disk_state(struct drbd_device *device, enum drbd_disk_state disk_state)
{
	device->disk_state[NEW] = disk_state;
}

void __change_disk_states(struct drbd_resource *resource, enum drbd_disk_state disk_state)
{
	struct drbd_device *device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&resource->devices, device, vnr)
		__change_disk_state(device, disk_state);
	rcu_read_unlock();
}

static bool device_has_connected_peer_devices(struct drbd_device *device)
{
	struct drbd_peer_device *peer_device;

	for_each_peer_device(peer_device, device)
		if (peer_device->repl_state[NOW] >= L_CONNECTED)
			return true;
	return false;
}

enum drbd_state_rv change_disk_state(struct drbd_device *device,
				     enum drbd_disk_state disk_state,
				     enum chg_state_flags flags)
{
	struct drbd_resource *resource = device->resource;
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags | CS_SERIALIZE | CS_LOCAL_ONLY);
	if (!local_state_change(flags) &&
	    device->disk_state[NOW] != D_DISKLESS && disk_state == D_DISKLESS &&
	    device_has_connected_peer_devices(device)) {
		enum drbd_state_rv rv;

		__change_disk_state(device, disk_state);
		rv = try_state_change(resource);
		if (rv == SS_SUCCESS)
			rv = change_peer_state(first_connection(resource), device->vnr,
					       NS(disk, disk_state), &irq_flags);
		if (rv < SS_SUCCESS) {
			abort_state_change(resource, &irq_flags);
			return rv;
		}
	}
	__change_disk_state(device, disk_state);
	return end_state_change(resource, &irq_flags);
}

void __change_cstate(struct drbd_connection *connection, enum drbd_conn_state cstate)
{
	connection->cstate[NEW] = cstate;
	if (cstate < C_CONNECTED) {
		struct drbd_peer_device *peer_device;
		int vnr;

		rcu_read_lock();
		idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
			__change_repl_state(peer_device, L_STANDALONE);
		rcu_read_unlock();
	}
}

static bool connection_has_connected_peer_devices(struct drbd_connection *connection)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		if (peer_device->repl_state[NOW] >= L_CONNECTED)
			return true;
	}
	return false;
}

enum outdate_what { OUTDATE_NOTHING, OUTDATE_DISKS, OUTDATE_PEER_DISKS };

static enum outdate_what outdate_on_disconnect(struct drbd_connection *connection)
{
	struct drbd_resource *resource = connection->resource;
	enum drbd_fencing_policy fencing_policy = highest_fencing_policy(connection);

	if (fencing_policy >= FP_RESOURCE &&
	    resource->role[NOW] != connection->peer_role[NOW]) {
		if (resource->role[NOW] == R_PRIMARY)
			return OUTDATE_PEER_DISKS;
		if (connection->peer_role[NOW] != R_PRIMARY)
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
			__change_disk_states(connection->resource, D_OUTDATED);
			break;
		case OUTDATE_PEER_DISKS:
			__change_peer_disk_states(connection, D_OUTDATED);
			break;
		case OUTDATE_NOTHING:
			break;
	}
}

/**
 * change_cstate()  -  change the connection state of a connection
 *
 * When disconnecting from a peer, we may also need to outdate the local or
 * peer disks depending on the fencing policy.  This cannot easily be split
 * into two state changes.
 */
enum drbd_state_rv change_cstate(struct drbd_connection *connection,
				 enum drbd_conn_state cstate,
				 enum chg_state_flags flags)
{
	struct drbd_resource *resource = connection->resource;
	unsigned long irq_flags;
	enum outdate_what outdate_what = OUTDATE_NOTHING;

	begin_state_change(resource, &irq_flags, flags | CS_SERIALIZE | CS_LOCAL_ONLY);
	if (!local_state_change(flags) &&
	    cstate == C_DISCONNECTING &&
	    connection_has_connected_peer_devices(connection)) {
		enum drbd_state_rv rv;

		outdate_what = outdate_on_disconnect(connection);
		__change_cstate_and_outdate(connection, cstate, outdate_what);
		rv = try_state_change(resource);
		if (rv == SS_SUCCESS) {
			switch(outdate_what) {
			case OUTDATE_DISKS:
				rv = change_peer_state(connection, -1,
					NS2(conn, cstate, disk, D_OUTDATED), &irq_flags);
				break;
			case OUTDATE_PEER_DISKS:
				rv = change_peer_state(connection, -1,
					NS2(conn, cstate, pdsk, D_OUTDATED), &irq_flags);
				break;
			case OUTDATE_NOTHING:
				rv = change_peer_state(connection, -1,
					NS(conn, cstate), &irq_flags);
				break;
			}
		}
		if (rv < SS_SUCCESS) {
			abort_state_change(resource, &irq_flags);
			return rv;
		}
	}
	__change_cstate_and_outdate(connection, cstate, outdate_what);
	return end_state_change(resource, &irq_flags);
}

void __change_repl_state(struct drbd_peer_device *peer_device, enum drbd_repl_state repl_state)
{
	peer_device->repl_state[NEW] = repl_state;
	if (repl_state > L_STANDALONE)
		peer_device->connection->cstate[NEW] = C_CONNECTED;
}

enum drbd_state_rv change_repl_state(struct drbd_peer_device *peer_device,
				     enum drbd_repl_state new_repl_state,
				     enum chg_state_flags flags)
{
	struct drbd_resource *resource = peer_device->device->resource;
	enum drbd_repl_state *repl_state = peer_device->repl_state;
	unsigned long irq_flags;

	begin_state_change(resource, &irq_flags, flags | CS_SERIALIZE | CS_LOCAL_ONLY);
	if (!local_state_change(flags) && repl_state[NOW] != new_repl_state &&
	    ((repl_state[NOW] >= L_CONNECTED &&
	      (new_repl_state == L_STARTING_SYNC_S || new_repl_state == L_STARTING_SYNC_T)) ||
	     (repl_state[NOW] == L_CONNECTED &&
	      (new_repl_state == L_VERIFY_S || new_repl_state == L_STANDALONE)))) {
		enum drbd_state_rv rv;

		__change_repl_state(peer_device, new_repl_state);
		rv = try_state_change(resource);
		if (rv == SS_SUCCESS)
			rv = change_peer_state(peer_device->connection, peer_device->device->vnr,
					       NS(conn, new_repl_state), &irq_flags);
		if (rv < SS_SUCCESS) {
			abort_state_change(resource, &irq_flags);
			return rv;
		}
	}
	__change_repl_state(peer_device, new_repl_state);
	return end_state_change(resource, &irq_flags);
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

void __change_peer_disk_states(struct drbd_connection *connection,
			       enum drbd_disk_state disk_state)
{
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr)
		__change_peer_disk_state(peer_device, disk_state);
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
