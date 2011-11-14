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

struct after_state_chg_work {
	struct drbd_work w;
	struct drbd_device *device;
	union drbd_state os;
	union drbd_state ns;
	enum chg_state_flags flags;
	struct completion *done;
};

STATIC int w_after_state_ch(struct drbd_work *w, int unused);
STATIC void after_state_ch(struct drbd_device *device, union drbd_state os,
			   union drbd_state ns, enum chg_state_flags flags);
static enum drbd_state_rv is_allowed_soft_transition(struct drbd_device *, union drbd_state, union drbd_state);
STATIC enum drbd_state_rv is_valid_soft_transition(union drbd_state, union drbd_state);
STATIC enum drbd_state_rv is_valid_transition(union drbd_state os, union drbd_state ns);
STATIC union drbd_state sanitize_state(struct drbd_device *device, union drbd_state ns);

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

/**
 * cl_wide_st_chg() - true if the state change is a cluster wide one
 * @device:	DRBD device.
 * @os:		old (current) state.
 * @ns:		new (wanted) state.
 */
STATIC int cl_wide_st_chg(struct drbd_device *device,
			  union drbd_state os, union drbd_state ns)
{
	return (os.conn >= L_CONNECTED && ns.conn >= L_CONNECTED &&
		 ((os.role != R_PRIMARY && ns.role == R_PRIMARY) ||
		  (os.conn != L_STARTING_SYNC_T && ns.conn == L_STARTING_SYNC_T) ||
		  (os.conn != L_STARTING_SYNC_S && ns.conn == L_STARTING_SYNC_S) ||
		  (os.disk != D_DISKLESS && ns.disk == D_DISKLESS))) ||
		(os.conn >= L_CONNECTED && ns.conn == C_DISCONNECTING) ||
		(os.conn == L_CONNECTED && ns.conn == L_VERIFY_S) ||
		(os.conn == L_CONNECTED && ns.conn == L_STANDALONE);
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
	unsigned long flags;
	union drbd_state ns;
	enum drbd_state_rv rv;

	spin_lock_irqsave(&device->resource->req_lock, flags);
	ns = apply_mask_val(drbd_get_peer_device_state(first_peer_device(device), NOW), mask, val);
	rv = _drbd_set_state(device, ns, f, NULL);
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	return rv;
}

STATIC enum drbd_state_rv
_req_st_cond(struct drbd_device *device, union drbd_state mask,
	     union drbd_state val)
{
	union drbd_state os, ns;
	unsigned long flags;
	enum drbd_state_rv rv;

	if (test_and_clear_bit(CL_ST_CHG_SUCCESS, &device->flags))
		return SS_CW_SUCCESS;

	if (test_and_clear_bit(CL_ST_CHG_FAIL, &device->flags))
		return SS_CW_FAILED_BY_PEER;

	spin_lock_irqsave(&device->resource->req_lock, flags);
	os = drbd_get_peer_device_state(first_peer_device(device), NOW);
	ns = sanitize_state(device, apply_mask_val(os, mask, val));
	rv = is_valid_transition(os, ns);
	if (rv == SS_SUCCESS)
		rv = SS_UNKNOWN_ERROR;  /* continue waiting */

	if (!cl_wide_st_chg(device, os, ns))
		rv = SS_CW_NO_NEED;
	if (rv == SS_UNKNOWN_ERROR) {
		rv = is_allowed_soft_transition(device, os, ns);
		if (rv == SS_SUCCESS) {
			rv = is_valid_soft_transition(os, ns);
			if (rv == SS_SUCCESS)
				rv = SS_UNKNOWN_ERROR;  /* continue waiting */
		}
	}
	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	return rv;
}

/**
 * drbd_req_state() - Perform an eventually cluster wide state change
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
	struct completion done;
	unsigned long flags;
	union drbd_state os, ns;
	enum drbd_state_rv rv;

	init_completion(&done);

	if (f & CS_SERIALIZE)
		mutex_lock(&device->resource->state_mutex);

	spin_lock_irqsave(&device->resource->req_lock, flags);
	os = drbd_get_peer_device_state(first_peer_device(device), NOW);
	ns = sanitize_state(device, apply_mask_val(os, mask, val));
	rv = is_valid_transition(os, ns);
	if (rv < SS_SUCCESS) {
		spin_unlock_irqrestore(&device->resource->req_lock, flags);
		goto abort;
	}

	if (cl_wide_st_chg(device, os, ns)) {
		rv = is_allowed_soft_transition(device, os, ns);
		if (rv == SS_SUCCESS)
			rv = is_valid_soft_transition(os, ns);
		spin_unlock_irqrestore(&device->resource->req_lock, flags);

		if (rv < SS_SUCCESS) {
			if (f & CS_VERBOSE)
				print_st_err(device, os, ns, rv);
			goto abort;
		}

		if (drbd_send_state_req(first_peer_device(device), mask, val)) {
			rv = SS_CW_FAILED_BY_PEER;
			if (f & CS_VERBOSE)
				print_st_err(device, os, ns, rv);
			goto abort;
		}

		wait_event(device->state_wait,
			(rv = _req_st_cond(device, mask, val)) != SS_UNKNOWN_ERROR);

		if (rv < SS_SUCCESS) {
			if (f & CS_VERBOSE)
				print_st_err(device, os, ns, rv);
			goto abort;
		}
		spin_lock_irqsave(&device->resource->req_lock, flags);
		ns = apply_mask_val(drbd_get_peer_device_state(first_peer_device(device), NOW), mask, val);
		rv = _drbd_set_state(device, ns, f, &done);
	} else {
		rv = _drbd_set_state(device, ns, f, &done);
	}

	spin_unlock_irqrestore(&device->resource->req_lock, flags);

	if (f & CS_WAIT_COMPLETE && rv == SS_SUCCESS) {
		D_ASSERT(device, current != first_peer_device(device)->connection->sender.task);
		wait_for_completion(&done);
	}

abort:
	if (f & CS_SERIALIZE)
		mutex_unlock(&device->resource->state_mutex);

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

	wait_event(device->state_wait,
		   (rv = drbd_req_state(device, mask, val, f)) != SS_IN_TRANSIENT_STATE);

	return rv;
}

/* pretty print of drbd internal state */

#define STATE_FMT	" %s = { cs:%s ro:%s/%s ds:%s/%s %c%c%c%c%c%c }\n"
#define STATE_ARGS(tag, s)		\
		tag,			\
		drbd_conn_str(s.conn),	\
		drbd_role_str(s.role),	\
		drbd_role_str(s.peer),	\
		drbd_disk_str(s.disk),	\
		drbd_disk_str(s.pdsk),	\
		is_susp(s) ? 's' : 'r',	\
		s.aftr_isp ? 'a' : '-',	\
		s.peer_isp ? 'p' : '-',	\
		s.user_isp ? 'u' : '-', \
		s.susp_fen ? 'F' : '-', \
		s.susp_nod ? 'N' : '-'

void print_st(struct drbd_device *device, const char *tag, union drbd_state s)
{
	drbd_err(device, STATE_FMT, STATE_ARGS(tag, s));
}


void print_st_err(struct drbd_device *device, union drbd_state os,
	          union drbd_state ns, enum drbd_state_rv err)
{
	if (err == SS_IN_TRANSIENT_STATE)
		return;
	drbd_err(device, "State change failed: %s\n", drbd_set_st_err_str(err));
	print_st(device, " state", os);
	print_st(device, "wanted", ns);
}

static long print_state_change(char *pb, union drbd_state os, union drbd_state ns,
			       enum chg_state_flags flags)
{
	char *pbp;
	pbp = pb;
	*pbp = 0;

	if (ns.role != os.role && flags & CS_DC_ROLE)
		pbp += sprintf(pbp, "role( %s -> %s ) ",
			       drbd_role_str(os.role),
			       drbd_role_str(ns.role));
	if (ns.peer != os.peer && flags & CS_DC_PEER)
		pbp += sprintf(pbp, "peer( %s -> %s ) ",
			       drbd_role_str(os.peer),
			       drbd_role_str(ns.peer));
	if (ns.conn != os.conn && flags & CS_DC_CONN)
		pbp += sprintf(pbp, "conn( %s -> %s ) ",
			       drbd_conn_str(os.conn),
			       drbd_conn_str(ns.conn));
	if (ns.disk != os.disk && flags & CS_DC_DISK)
		pbp += sprintf(pbp, "disk( %s -> %s ) ",
			       drbd_disk_str(os.disk),
			       drbd_disk_str(ns.disk));
	if (ns.pdsk != os.pdsk && flags & CS_DC_PDSK)
		pbp += sprintf(pbp, "pdsk( %s -> %s ) ",
			       drbd_disk_str(os.pdsk),
			       drbd_disk_str(ns.pdsk));

	return pbp - pb;
}

static void drbd_pr_state_change(struct drbd_device *device, union drbd_state os, union drbd_state ns,
				 enum chg_state_flags flags)
{
	char pb[300];
	char *pbp = pb;

	pbp += print_state_change(pbp, os, ns, flags ^ CS_DC_MASK);

	if (ns.aftr_isp != os.aftr_isp)
		pbp += sprintf(pbp, "aftr_isp( %d -> %d ) ",
			       os.aftr_isp,
			       ns.aftr_isp);
	if (ns.peer_isp != os.peer_isp)
		pbp += sprintf(pbp, "peer_isp( %d -> %d ) ",
			       os.peer_isp,
			       ns.peer_isp);
	if (ns.user_isp != os.user_isp)
		pbp += sprintf(pbp, "user_isp( %d -> %d ) ",
			       os.user_isp,
			       ns.user_isp);

	if (pbp != pb)
		drbd_info(device, "%s\n", pb);
}

static void conn_pr_state_change(struct drbd_connection *connection, union drbd_state os, union drbd_state ns,
				 enum chg_state_flags flags)
{
	char pb[300];
	char *pbp = pb;

	pbp += print_state_change(pbp, os, ns, flags);

	if (is_susp(ns) != is_susp(os) && flags & CS_DC_SUSP)
		pbp += sprintf(pbp, "susp( %d -> %d ) ",
			       is_susp(os),
			       is_susp(ns));

	if (pbp != pb)
		drbd_info(connection, "%s\n", pb);
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

/**
 * is_allowed_soft_transition() - Returns an SS_ error code if ns is not valid
 * @device:	DRBD device.
 * @os:		Old (current) state.
 * @ns:		New state.
 *
 * Allows a device which went "bad" because of an involuntary state change (such
 * as a connection loss or disk failure) to go to a "valid" state through
 * several similar "invalid" states: it is not always possible to go to a valid
 * state directly.
 */
static enum drbd_state_rv
is_allowed_soft_transition(struct drbd_device *device, union drbd_state os, union drbd_state ns)
{
	/* See drbd_state_sw_errors in drbd_strings.c */

	enum drbd_fencing_policy fencing_policy;
	enum drbd_state_rv rv = SS_SUCCESS;
	struct net_conf *nc;

	rcu_read_lock();
	fencing_policy = FP_DONT_CARE;
	if (get_ldev(device)) {
		fencing_policy = rcu_dereference(device->ldev->disk_conf)->fencing_policy;
		put_ldev(device);
	}

	nc = rcu_dereference(first_peer_device(device)->connection->net_conf);
	if (nc) {
		if (os.role != R_PRIMARY && ns.role == R_PRIMARY && !nc->two_primaries) {
			if (ns.peer == R_PRIMARY)
				rv = SS_TWO_PRIMARIES;
			else if (highest_peer_role(device->resource) == R_PRIMARY)
				rv = SS_O_VOL_PEER_PRI;
		}
	}

	if (rv <= 0)
		/* already found a reason to abort */;
	else if (os.role != R_SECONDARY && ns.role == R_SECONDARY && device->open_cnt)
		rv = SS_DEVICE_IN_USE;

	else if (!(os.role == R_PRIMARY && os.conn < L_CONNECTED && os.disk < D_UP_TO_DATE) &&
		   ns.role == R_PRIMARY && ns.conn < L_CONNECTED && ns.disk < D_UP_TO_DATE)
		rv = SS_NO_UP_TO_DATE_DISK;

	else if (fencing_policy >= FP_RESOURCE &&
		 !(os.role == R_PRIMARY && os.conn < L_CONNECTED && os.pdsk >= D_UNKNOWN) &&
		   ns.role == R_PRIMARY && ns.conn < L_CONNECTED && ns.pdsk >= D_UNKNOWN)
		rv = SS_PRIMARY_NOP;

	else if (!(os.role == R_PRIMARY && os.disk <= D_INCONSISTENT && os.pdsk <= D_INCONSISTENT) &&
		   ns.role == R_PRIMARY && ns.disk <= D_INCONSISTENT && ns.pdsk <= D_INCONSISTENT)
		rv = SS_NO_UP_TO_DATE_DISK;

	else if (!(os.conn > L_CONNECTED && os.disk < D_INCONSISTENT) &&
		   ns.conn > L_CONNECTED && ns.disk < D_INCONSISTENT)
		rv = SS_NO_LOCAL_DISK;

	else if (!(os.conn > L_CONNECTED && os.pdsk < D_INCONSISTENT) &&
		   ns.conn > L_CONNECTED && ns.pdsk < D_INCONSISTENT)
		rv = SS_NO_REMOTE_DISK;

	else if (!(os.conn > L_CONNECTED && os.disk < D_UP_TO_DATE && os.pdsk < D_UP_TO_DATE) &&
		   ns.conn > L_CONNECTED && ns.disk < D_UP_TO_DATE && ns.pdsk < D_UP_TO_DATE)
		rv = SS_NO_UP_TO_DATE_DISK;

	else if (!(os.disk == D_OUTDATED && !local_disk_may_be_outdated(os.conn)) &&
		   ns.disk == D_OUTDATED && !local_disk_may_be_outdated(ns.conn))
		rv = SS_CONNECTED_OUTDATES;

	else if (!(os.conn == L_VERIFY_S || os.conn == L_VERIFY_T) &&
		  (ns.conn == L_VERIFY_S || ns.conn == L_VERIFY_T) &&
		 (nc->verify_alg[0] == 0))
		rv = SS_NO_VERIFY_ALG;

	else if (!(os.conn == L_VERIFY_S || os.conn == L_VERIFY_T) &&
		  (ns.conn == L_VERIFY_S || ns.conn == L_VERIFY_T) &&
		  first_peer_device(device)->connection->agreed_pro_version < 88)
		rv = SS_NOT_SUPPORTED;

	else if (!(os.conn >= L_CONNECTED && os.pdsk == D_UNKNOWN) &&
		   ns.conn >= L_CONNECTED && ns.pdsk == D_UNKNOWN)
		rv = SS_CONNECTED_OUTDATES;

	rcu_read_unlock();

	return rv;
}

/**
 * is_valid_soft_transition() - Returns an SS_ error code if the state transition is not possible
 * This function limits state transitions that may be declined by DRBD. I.e.
 * user requests (aka soft transitions).
 * @device:	DRBD device.
 * @ns:		new state.
 * @os:		old state.
 */
STATIC enum drbd_state_rv
is_valid_soft_transition(union drbd_state os, union drbd_state ns)
{
	enum drbd_state_rv rv = SS_SUCCESS;

	if ((ns.conn == L_STARTING_SYNC_T || ns.conn == L_STARTING_SYNC_S) &&
	    os.conn > L_CONNECTED)
		rv = SS_RESYNC_RUNNING;

	if (ns.conn == C_DISCONNECTING && os.conn == C_STANDALONE)
		rv = SS_ALREADY_STANDALONE;

	if (ns.disk > D_ATTACHING && os.disk == D_DISKLESS)
		rv = SS_IS_DISKLESS;

	if (ns.conn == C_WF_CONNECTION && os.conn < C_UNCONNECTED)
		rv = SS_NO_NET_CONFIG;

	if (ns.disk == D_OUTDATED && os.disk < D_OUTDATED && os.disk != D_ATTACHING)
		rv = SS_LOWER_THAN_OUTDATED;

	if (ns.conn == C_DISCONNECTING && os.conn == C_UNCONNECTED)
		rv = SS_IN_TRANSIENT_STATE;

	/* if (ns.conn == os.conn && ns.conn == L_STANDALONE)
	   rv = SS_IN_TRANSIENT_STATE; */

	if ((ns.conn == L_VERIFY_S || ns.conn == L_VERIFY_T) && os.conn < L_CONNECTED)
		rv = SS_NEED_CONNECTION;

	if ((ns.conn == L_VERIFY_S || ns.conn == L_VERIFY_T) &&
	    ns.conn != os.conn && os.conn > L_CONNECTED)
		rv = SS_RESYNC_RUNNING;

	if ((ns.conn == L_STARTING_SYNC_S || ns.conn == L_STARTING_SYNC_T) &&
	    os.conn < L_CONNECTED)
		rv = SS_NEED_CONNECTION;

	if ((ns.conn == L_SYNC_TARGET || ns.conn == L_SYNC_SOURCE)
	    && os.conn < L_STANDALONE)
		rv = SS_NEED_CONNECTION; /* No NetworkFailure -> SyncTarget etc... */

	return rv;
}

STATIC enum drbd_state_rv
is_valid_conn_transition(enum drbd_conns oc, enum drbd_conns nc)
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
 * @ns:		new state.
 * @os:		old state.
 */
STATIC enum drbd_state_rv
is_valid_transition(union drbd_state os, union drbd_state ns)
{
	enum drbd_state_rv rv;

	rv = is_valid_conn_transition(os.conn, ns.conn);

	/* we cannot fail (again) if we already detached */
	if (ns.disk == D_FAILED && os.disk == D_DISKLESS)
		rv = SS_IS_DISKLESS;

	return rv;
}

/**
 * sanitize_state() - Resolves implicitly necessary additional changes to a state transition
 * @device:	DRBD device.
 * @ns:		new state.
 *
 * When we loose connection, we have to set the state of the peers disk (pdsk)
 * to D_UNKNOWN. This rule and many more along those lines are in this function.
 */
STATIC union drbd_state sanitize_state(struct drbd_device *device, union drbd_state ns)
{
	enum drbd_fencing_policy fencing_policy;
	enum drbd_disk_state disk_min, disk_max, pdsk_min, pdsk_max;

	fencing_policy = FP_DONT_CARE;
	if (get_ldev(device)) {
		rcu_read_lock();
		fencing_policy = rcu_dereference(device->ldev->disk_conf)->fencing_policy;
		rcu_read_unlock();
		put_ldev(device);
	}

	/* Implications from connection to peer and peer_isp */
	if (ns.conn < L_CONNECTED) {
		ns.peer_isp = 0;
		ns.peer = R_UNKNOWN;
		if (ns.pdsk > D_UNKNOWN || ns.pdsk < D_INCONSISTENT)
			ns.pdsk = D_UNKNOWN;
	}

	/* Clear the aftr_isp when becoming unconfigured */
	if (ns.conn == C_STANDALONE && ns.disk == D_DISKLESS && ns.role == R_SECONDARY)
		ns.aftr_isp = 0;

	/* An implication of the disk states onto the connection state */
	/* Abort resync if a disk fails/detaches */
	if (ns.conn > L_CONNECTED && (ns.disk <= D_FAILED || ns.pdsk <= D_FAILED))
		ns.conn = L_CONNECTED;

	/* Connection breaks down before we finished "Negotiating" */
	if (ns.conn < L_CONNECTED && ns.disk == D_NEGOTIATING &&
	    get_ldev_if_state(device, D_NEGOTIATING)) {
		if (device->ed_uuid == device->ldev->md.uuid[UI_CURRENT]) {
			ns.disk = device->new_state_tmp.disk;
			ns.pdsk = device->new_state_tmp.pdsk;
		} else {
			ns.disk = D_DISKLESS;
			ns.pdsk = D_UNKNOWN;
		}
		put_ldev(device);
	}

	/* D_CONSISTENT and D_OUTDATED vanish when we get connected */
	if (ns.conn >= L_CONNECTED && ns.conn < L_AHEAD) {
		if (ns.disk == D_CONSISTENT || ns.disk == D_OUTDATED)
			ns.disk = D_UP_TO_DATE;
		if (ns.pdsk == D_CONSISTENT || ns.pdsk == D_OUTDATED)
			ns.pdsk = D_UP_TO_DATE;
	}

	/* Implications of the connection stat on the disk states */
	disk_min = D_DISKLESS;
	disk_max = D_UP_TO_DATE;
	pdsk_min = D_INCONSISTENT;
	pdsk_max = D_UNKNOWN;
	if (ns.conn >= L_STANDALONE) {
		switch ((enum drbd_repl_state)ns.conn) {
		case L_WF_BITMAP_T:
		case L_PAUSED_SYNC_T:
		case L_STARTING_SYNC_T:
		case L_WF_SYNC_UUID:
		case L_BEHIND:
			disk_min = D_INCONSISTENT;
			disk_max = D_OUTDATED;
			pdsk_min = D_UP_TO_DATE;
			pdsk_max = D_UP_TO_DATE;
			break;
		case L_VERIFY_S:
		case L_VERIFY_T:
			disk_min = D_UP_TO_DATE;
			disk_max = D_UP_TO_DATE;
			pdsk_min = D_UP_TO_DATE;
			pdsk_max = D_UP_TO_DATE;
			break;
		case L_CONNECTED:
			disk_min = D_DISKLESS;
			disk_max = D_UP_TO_DATE;
			pdsk_min = D_DISKLESS;
			pdsk_max = D_UP_TO_DATE;
			break;
		case L_WF_BITMAP_S:
		case L_PAUSED_SYNC_S:
		case L_STARTING_SYNC_S:
		case L_AHEAD:
			disk_min = D_UP_TO_DATE;
			disk_max = D_UP_TO_DATE;
			pdsk_min = D_INCONSISTENT;
			pdsk_max = D_CONSISTENT; /* D_OUTDATED would be nice. But explicit outdate necessary*/
			break;
		case L_SYNC_TARGET:
			disk_min = D_INCONSISTENT;
			disk_max = D_INCONSISTENT;
			pdsk_min = D_UP_TO_DATE;
			pdsk_max = D_UP_TO_DATE;
			break;
		case L_SYNC_SOURCE:
			disk_min = D_UP_TO_DATE;
			disk_max = D_UP_TO_DATE;
			pdsk_min = D_INCONSISTENT;
			pdsk_max = D_INCONSISTENT;
			break;
		case L_STANDALONE:
			break;
		}
	}
	if (ns.disk > disk_max)
		ns.disk = disk_max;

	if (ns.disk < disk_min)
		ns.disk = disk_min;
	if (ns.pdsk > pdsk_max)
		ns.pdsk = pdsk_max;

	if (ns.pdsk < pdsk_min)
		ns.pdsk = pdsk_min;

	if (fencing_policy == FP_STONITH &&
	    (ns.role == R_PRIMARY && ns.conn < L_CONNECTED && ns.pdsk > D_OUTDATED))
		ns.susp_fen = 1; /* Suspend IO while fence-peer handler runs (peer lost) */

	if (device->resource->res_opts.on_no_data == OND_SUSPEND_IO &&
	    (ns.role == R_PRIMARY && ns.disk < D_UP_TO_DATE && ns.pdsk < D_UP_TO_DATE))
		ns.susp_nod = 1; /* Suspend IO while no data available (no accessible data available) */

	if (ns.aftr_isp || ns.peer_isp || ns.user_isp) {
		if (ns.conn == L_SYNC_SOURCE)
			ns.conn = L_PAUSED_SYNC_S;
		if (ns.conn == L_SYNC_TARGET)
			ns.conn = L_PAUSED_SYNC_T;
	} else {
		if (ns.conn == L_PAUSED_SYNC_S)
			ns.conn = L_SYNC_SOURCE;
		if (ns.conn == L_PAUSED_SYNC_T)
			ns.conn = L_SYNC_TARGET;
	}

	return ns;
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

/**
 * __drbd_set_state() - Set a new DRBD state
 * @device:	DRBD device.
 * @ns:		new state.
 * @flags:	Flags
 * @done:	Optional completion, that will get completed after the after_state_ch() finished
 *
 * Caller needs to hold req_lock, and global_state_lock. Do not call directly.
 */
enum drbd_state_rv
__drbd_set_state(struct drbd_device *device, union drbd_state ns,
	         enum chg_state_flags flags, struct completion *done)
{
	union drbd_state os;
	enum drbd_state_rv rv = SS_SUCCESS;
	struct after_state_chg_work *ascw;
	struct drbd_resource *resource;
	struct drbd_peer_device *peer_device;

	resource = device->resource;
	peer_device = first_peer_device(device);
	os = drbd_get_peer_device_state(peer_device, NOW);
	ns = sanitize_state(device, ns);
	if (ns.i == os.i)
		return SS_NOTHING_TO_DO;

	rv = is_valid_transition(os, ns);
	if (rv < SS_SUCCESS)
		return rv;

	if (!(flags & CS_HARD)) {
		/*  pre-state-change checks ; only look at ns  */
		/* See drbd_state_sw_errors in drbd_strings.c */

		rv = is_allowed_soft_transition(device, os, ns);
		if (rv == SS_SUCCESS)
			rv = is_valid_soft_transition(os, ns);
	}

	if (rv < SS_SUCCESS) {
		if (flags & CS_VERBOSE)
			print_st_err(device, os, ns, rv);
		return rv;
	}

	drbd_pr_state_change(device, os, ns, flags);

	/* Display changes to the susp* flags that where caused by the call to
	   sanitize_state(). Only display it here if we where not called from
	   _conn_request_state() */
	if (!(flags & CS_DC_SUSP))
		conn_pr_state_change(peer_device->connection, os, ns,
				     (flags & ~CS_DC_MASK) | CS_DC_SUSP);

	/* if we are going -> D_FAILED or D_DISKLESS, grab one extra reference
	 * on the ldev here, to be sure the transition -> D_DISKLESS resp.
	 * drbd_ldev_destroy() won't happen before our corresponding
	 * after_state_ch works run, where we put_ldev again. */
	if ((os.disk != D_FAILED && ns.disk == D_FAILED) ||
	    (os.disk != D_DISKLESS && ns.disk == D_DISKLESS))
		atomic_inc(&device->local_cnt);

	device->disk_state[NOW] = ns.disk;
	peer_device->resync_susp_user[NOW] = ns.user_isp;
	peer_device->resync_susp_peer[NOW] = ns.peer_isp;
	peer_device->resync_susp_dependency[NOW] = ns.aftr_isp;
	peer_device->repl_state[NOW] = max_t(unsigned, ns.conn, L_STANDALONE);
	peer_device->connection->peer_role[NOW] = ns.peer;
	resource->role[NOW] = ns.role;
	resource->susp[NOW] = ns.susp;
	resource->susp_nod[NOW] = ns.susp_nod;
	resource->susp_fen[NOW] = ns.susp_fen;
	peer_device->disk_state[NOW] = ns.pdsk;

	if (os.disk == D_ATTACHING && ns.disk >= D_NEGOTIATING)
		drbd_print_uuids(device, "attached to UUIDs");

	wake_up(&device->misc_wait);
	wake_up(&device->state_wait);
	wake_up(&peer_device->connection->ping_wait);

	/* aborted verify run. log the last position */
	if ((os.conn == L_VERIFY_S || os.conn == L_VERIFY_T) &&
	    ns.conn < L_CONNECTED) {
		peer_device->ov_start_sector =
			BM_BIT_TO_SECT(drbd_bm_bits(device) - peer_device->ov_left);
		drbd_info(peer_device, "Online Verify reached sector %llu\n",
			(unsigned long long)peer_device->ov_start_sector);
	}

	if ((os.conn == L_PAUSED_SYNC_T || os.conn == L_PAUSED_SYNC_S) &&
	    (ns.conn == L_SYNC_TARGET  || ns.conn == L_SYNC_SOURCE)) {
		drbd_info(peer_device, "Syncer continues.\n");
		peer_device->rs_paused += (long)jiffies
				  -(long)peer_device->rs_mark_time[peer_device->rs_last_mark];
		if (ns.conn == L_SYNC_TARGET)
			mod_timer(&peer_device->resync_timer, jiffies);
	}

	if ((os.conn == L_SYNC_TARGET  || os.conn == L_SYNC_SOURCE) &&
	    (ns.conn == L_PAUSED_SYNC_T || ns.conn == L_PAUSED_SYNC_S)) {
		drbd_info(peer_device, "Resync suspended\n");
		peer_device->rs_mark_time[peer_device->rs_last_mark] = jiffies;
	}

	if (os.conn == L_CONNECTED &&
	    (ns.conn == L_VERIFY_S || ns.conn == L_VERIFY_T)) {
		unsigned long now = jiffies;
		int i;

		set_ov_position(peer_device, (enum drbd_repl_state)ns.conn);
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

		if (ns.conn == L_VERIFY_S) {
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
		if (device->resource->role[NOW] == R_PRIMARY ||
		    (peer_device->disk_state[NOW] < D_INCONSISTENT &&
		     highest_peer_role(device->resource) == R_PRIMARY))
			mdf |= MDF_PRIMARY_IND;
		if (peer_device->repl_state[NOW] > L_STANDALONE)
			mdf |= MDF_CONNECTED_IND;
		if (device->disk_state[NOW] > D_INCONSISTENT)
			mdf |= MDF_CONSISTENT;
		if (device->disk_state[NOW] > D_OUTDATED)
			mdf |= MDF_WAS_UP_TO_DATE;
		if (peer_device->disk_state[NOW] <= D_OUTDATED &&
		    peer_device->disk_state[NOW] >= D_INCONSISTENT)
			mdf |= MDF_PEER_OUT_DATED;
		if (mdf != device->ldev->md.flags) {
			device->ldev->md.flags = mdf;
			drbd_md_mark_dirty(device);
		}
		if (os.disk < D_CONSISTENT && ns.disk >= D_CONSISTENT)
			drbd_set_ed_uuid(device, device->ldev->md.uuid[UI_CURRENT]);
		put_ldev(device);
	}

	/* Peer was forced D_UP_TO_DATE & R_PRIMARY, consider to resync */
	if (os.disk == D_INCONSISTENT && os.pdsk == D_INCONSISTENT &&
	    os.peer == R_SECONDARY && ns.peer == R_PRIMARY)
		set_bit(CONSIDER_RESYNC, &peer_device->flags);

	/* Receiver should clean up itself */
	if (os.conn != C_DISCONNECTING && ns.conn == C_DISCONNECTING)
		drbd_thread_stop_nowait(&peer_device->connection->receiver);

	/* Now the receiver finished cleaning up itself, it should die */
	if (os.conn != C_STANDALONE && ns.conn == C_STANDALONE)
		drbd_thread_stop_nowait(&peer_device->connection->receiver);

	/* Upon network failure, we need to restart the receiver. */
	if (os.conn > C_WF_CONNECTION &&
	    ns.conn <= C_TEAR_DOWN && ns.conn >= C_TIMEOUT)
		drbd_thread_restart_nowait(&peer_device->connection->receiver);

	/* Resume AL writing if we get a connection */
	if (os.conn < L_CONNECTED && ns.conn >= L_CONNECTED)
		drbd_resume_al(device);

	ascw = kmalloc(sizeof(*ascw), GFP_ATOMIC);
	if (ascw) {
		ascw->os = os;
		ascw->ns = ns;
		ascw->flags = flags;
		ascw->w.cb = w_after_state_ch;
		ascw->device = device;
		ascw->done = done;
		drbd_queue_work(&device->resource->work, &ascw->w);
	} else {
		drbd_err(device, "Could not kmalloc an ascw\n");
	}

	return rv;
}

STATIC int w_after_state_ch(struct drbd_work *w, int unused)
{
	struct after_state_chg_work *ascw =
		container_of(w, struct after_state_chg_work, w);
	struct drbd_device *device = ascw->device;

	after_state_ch(device, ascw->os, ascw->ns, ascw->flags);
	if (ascw->flags & CS_WAIT_COMPLETE)
		complete(ascw->done);
	kfree(ascw);

	return 0;
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

/**
 * after_state_ch() - Perform after state change actions that may sleep
 * @device:	DRBD device.
 * @os:		old state.
 * @ns:		new state.
 * @flags:	Flags
 */
STATIC void after_state_ch(struct drbd_device *device, union drbd_state os,
			   union drbd_state ns, enum chg_state_flags flags)
{
	struct sib_info sib;

	sib.sib_reason = SIB_STATE_CHANGE;
	sib.os = os;
	sib.ns = ns;

	if (os.conn != L_CONNECTED && ns.conn == L_CONNECTED) {
		clear_bit(CRASHED_PRIMARY, &device->flags);
		if (device->p_uuid)
			device->p_uuid[UI_FLAGS] &= ~((u64)2);
	}

	/* Inform userspace about the change... */
	drbd_bcast_event(device, &sib);

	if (!(os.role == R_PRIMARY && os.disk < D_UP_TO_DATE && os.pdsk < D_UP_TO_DATE) &&
	    (ns.role == R_PRIMARY && ns.disk < D_UP_TO_DATE && ns.pdsk < D_UP_TO_DATE))
		drbd_khelper(device, "pri-on-incon-degr");

	/* Here we have the actions that are performed after a
	   state change. This function might sleep */

	if (ns.susp_nod) {
		enum drbd_req_event what = NOTHING;

		if (os.conn < L_CONNECTED &&
		    conn_lowest_repl_state(first_peer_device(device)->connection) >= L_CONNECTED)
			what = RESEND;

		if ((os.disk == D_ATTACHING || os.disk == D_NEGOTIATING) &&
		    conn_lowest_disk(first_peer_device(device)->connection) > D_NEGOTIATING)
			what = RESTART_FROZEN_DISK_IO;

		if (what != NOTHING) {
			spin_lock_irq(&device->resource->req_lock);
			_tl_restart(first_peer_device(device)->connection, what);
			_drbd_set_state(_NS(device, susp_nod, 0), CS_VERBOSE, NULL);
			spin_unlock_irq(&device->resource->req_lock);
		}
	}

	/* Became sync source.  With protocol >= 96, we still need to send out
	 * the sync uuid now. Need to do that before any drbd_send_state, or
	 * the other side may go "paused sync" before receiving the sync uuids,
	 * which is unexpected. */
	if ((os.conn != L_SYNC_SOURCE && os.conn != L_PAUSED_SYNC_S) &&
	    (ns.conn == L_SYNC_SOURCE || ns.conn == L_PAUSED_SYNC_S) &&
	    first_peer_device(device)->connection->agreed_pro_version >= 96 && get_ldev(device)) {
		drbd_gen_and_send_sync_uuid(first_peer_device(device));
		put_ldev(device);
	}

	/* Do not change the order of the if above and the two below... */
	if (os.pdsk == D_DISKLESS &&
	    ns.pdsk > D_DISKLESS && ns.pdsk != D_UNKNOWN) {      /* attach on the peer */
		drbd_send_uuids(first_peer_device(device));
		drbd_send_state(first_peer_device(device), ns);
	}
	/* No point in queuing send_bitmap if we don't have a connection
	 * anymore, so check also the _current_ state, not only the new state
	 * at the time this work was queued. */
	if (os.conn != L_WF_BITMAP_S && ns.conn == L_WF_BITMAP_S &&
	    first_peer_device(device)->repl_state[NOW] == L_WF_BITMAP_S)
		drbd_queue_bitmap_io(device, &drbd_send_bitmap, NULL,
				"send_bitmap (WFBitMapS)",
				BM_LOCKED_TEST_ALLOWED,
				first_peer_device(device));

	/* Lost contact to peer's copy of the data */
	if ((os.pdsk >= D_INCONSISTENT &&
	     os.pdsk != D_UNKNOWN &&
	     os.pdsk != D_OUTDATED)
	&&  (ns.pdsk < D_INCONSISTENT ||
	     ns.pdsk == D_UNKNOWN ||
	     ns.pdsk == D_OUTDATED)) {
		if (get_ldev(device)) {
			if ((ns.role == R_PRIMARY || ns.peer == R_PRIMARY) &&
			    device->ldev->md.uuid[UI_BITMAP] == 0 && ns.disk >= D_UP_TO_DATE) {
				if (drbd_suspended(device)) {
					set_bit(NEW_CUR_UUID, &device->flags);
				} else {
					drbd_uuid_new_current(device);
					drbd_send_uuids(first_peer_device(device));
				}
			}
			put_ldev(device);
		}
	}

	if (ns.pdsk < D_INCONSISTENT && get_ldev(device)) {
		if (os.peer == R_SECONDARY && ns.peer == R_PRIMARY &&
		    device->ldev->md.uuid[UI_BITMAP] == 0 && ns.disk >= D_UP_TO_DATE) {
			drbd_uuid_new_current(device);
			drbd_send_uuids(first_peer_device(device));
		}
		/* D_DISKLESS Peer becomes secondary */
		if (os.peer == R_PRIMARY && ns.peer == R_SECONDARY)
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
	if (os.role == R_PRIMARY && ns.role == R_SECONDARY &&
		first_peer_device(device)->repl_state[NOW] <= L_CONNECTED && get_ldev(device)) {
		/* No changes to the bitmap expected this time, so assert that,
		 * even though no harm was done if it did change. */
		drbd_bitmap_io_from_worker(device, &drbd_bm_write,
				"demote", BM_LOCKED_TEST_ALLOWED,
				NULL);
		put_ldev(device);
	}

	/* Last part of the attaching process ... */
	if (ns.conn >= L_CONNECTED &&
	    os.disk == D_ATTACHING && ns.disk == D_NEGOTIATING) {
		drbd_send_sizes(first_peer_device(device), 0, 0);  /* to start sync... */
		drbd_send_uuids(first_peer_device(device));
		drbd_send_state(first_peer_device(device), ns);
	}

	/* We want to pause/continue resync, tell peer. */
	if (ns.conn >= L_CONNECTED &&
	     ((os.aftr_isp != ns.aftr_isp) ||
	      (os.user_isp != ns.user_isp)))
		drbd_send_state(first_peer_device(device), ns);

	/* In case one of the isp bits got set, suspend other devices. */
	if ((!os.aftr_isp && !os.peer_isp && !os.user_isp) &&
	    (ns.aftr_isp || ns.peer_isp || ns.user_isp))
		suspend_other_sg(device);

	/* Make sure the peer gets informed about eventual state
	   changes (ISP bits) while we were in L_STANDALONE. */
	if (os.conn == L_STANDALONE && ns.conn >= L_CONNECTED)
		drbd_send_state(first_peer_device(device), ns);

	if (os.conn != L_AHEAD && ns.conn == L_AHEAD)
		drbd_send_state(first_peer_device(device), ns);

	/* We are in the progress to start a full sync... */
	if ((os.conn != L_STARTING_SYNC_T && ns.conn == L_STARTING_SYNC_T) ||
	    (os.conn != L_STARTING_SYNC_S && ns.conn == L_STARTING_SYNC_S))
		/* no other bitmap changes expected during this phase */
		drbd_queue_bitmap_io(device,
			&drbd_bmio_set_n_write, &abw_start_sync,
			"set_n_write from StartingSync", BM_LOCKED_TEST_ALLOWED,
			NULL);

	/* We are invalidating our self... */
	if (os.conn < L_CONNECTED && ns.conn < L_CONNECTED &&
	    os.disk > D_INCONSISTENT && ns.disk == D_INCONSISTENT)
		/* other bitmap operation expected during this phase */
		drbd_queue_bitmap_io(device, &drbd_bmio_set_n_write, NULL,
			"set_n_write from invalidate", BM_LOCKED_MASK,
			NULL);

	/* first half of local IO error, failure to attach,
	 * or administrative detach */
	if (os.disk != D_FAILED && ns.disk == D_FAILED) {
		enum drbd_io_error_p eh;
		int was_io_error;
		/* corresponding get_ldev was in __drbd_set_state, to serialize
		 * our cleanup here with the transition to D_DISKLESS,
		 * so it is safe to dreference ldev here. */
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

		drbd_send_state(first_peer_device(device), ns);
		drbd_rs_cancel_all(first_peer_device(device));

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
        if (os.disk != D_DISKLESS && ns.disk == D_DISKLESS) {
                /* We must still be diskless,
                 * re-attach has to be serialized with this! */
                if (device->disk_state[NOW] != D_DISKLESS)
                        drbd_err(device,
                                "ASSERT FAILED: disk is %s while going diskless\n",
                                drbd_disk_str(device->disk_state[NOW]));

                first_peer_device(device)->rs_total = 0;
                first_peer_device(device)->rs_failed = 0;
                atomic_set(&first_peer_device(device)->rs_pending_cnt, 0);

		drbd_send_state(first_peer_device(device), ns);
		/* corresponding get_ldev in __drbd_set_state
		 * this may finaly trigger drbd_ldev_destroy. */
		put_ldev(device);
	}

	/* Notify peer that I had a local IO error and did not detach. */
	if (os.disk == D_UP_TO_DATE && ns.disk == D_INCONSISTENT)
		drbd_send_state(first_peer_device(device), ns);

	/* Disks got bigger while they were detached */
	if (ns.disk > D_NEGOTIATING && ns.pdsk > D_NEGOTIATING &&
	    test_and_clear_bit(RESYNC_AFTER_NEG, &first_peer_device(device)->flags)) {
		if (ns.conn == L_CONNECTED)
			resync_after_online_grow(device);
	}

	/* A resync finished or aborted, wake paused devices... */
	if ((os.conn > L_CONNECTED && ns.conn <= L_CONNECTED) ||
	    (os.peer_isp && !ns.peer_isp) ||
	    (os.user_isp && !ns.user_isp))
		resume_next_sg(device);

	/* sync target done with resync.  Explicitly notify peer, even though
	 * it should (at least for non-empty resyncs) already know itself. */
	if (os.disk < D_UP_TO_DATE && os.conn >= L_SYNC_SOURCE && ns.conn == L_CONNECTED)
		drbd_send_state(first_peer_device(device), ns);

	/* This triggers bitmap writeout of potentially still unwritten pages
	 * if the resync finished cleanly, or aborted because of peer disk
	 * failure, or because of connection loss.
	 * For resync aborted because of local disk failure, we cannot do
	 * any bitmap writeout anymore.
	 * No harm done if some bits change during this phase.
	 */
	if (os.conn > L_CONNECTED && ns.conn <= L_CONNECTED && get_ldev(device)) {
		drbd_queue_bitmap_io(device, &drbd_bm_write, NULL,
			"write from resync_finished", BM_LOCKED_SET_ALLOWED,
			NULL);
		put_ldev(device);
	}

	if (ns.disk == D_DISKLESS &&
	    ns.conn == C_STANDALONE &&
	    ns.role == R_SECONDARY) {
		if (os.aftr_isp != ns.aftr_isp)
			resume_next_sg(device);
	}

	drbd_md_sync(device);
}

struct after_conn_state_chg_work {
	struct drbd_work w;
	enum drbd_conns oc;
	union drbd_state ns_min;
	union drbd_state ns_max; /* new, max state, over all mdevs */
	enum chg_state_flags flags;
	struct drbd_connection *connection;
};

STATIC int w_after_conn_state_ch(struct drbd_work *w, int unused)
{
	struct after_conn_state_chg_work *acscw =
		container_of(w, struct after_conn_state_chg_work, w);
	struct drbd_connection *connection = acscw->connection;
	enum drbd_conns oc = acscw->oc;
	union drbd_state ns_max = acscw->ns_max;
	union drbd_state ns_min = acscw->ns_min;
	struct drbd_peer_device *peer_device;
	int vnr;

	kfree(acscw);

	/* Upon network configuration, we need to start the receiver */
	if (oc == C_STANDALONE && ns_max.conn == C_UNCONNECTED)
		drbd_thread_start(&connection->receiver);

	if (oc == C_DISCONNECTING && ns_max.conn == C_STANDALONE) {
		struct net_conf *old_conf;

		mutex_lock(&connection->resource->conf_update);
		old_conf = connection->net_conf;
		connection->my_addr_len = 0;
		connection->peer_addr_len = 0;
		rcu_assign_pointer(connection->net_conf, NULL);
		conn_free_crypto(connection);
		mutex_unlock(&connection->resource->conf_update);

		synchronize_rcu();
		kfree(old_conf);
	}

	if (ns_max.susp_fen) {
		/* case1: The outdate peer handler is successful: */
		if (ns_max.pdsk <= D_OUTDATED) {
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
		if (ns_min.conn >= L_CONNECTED) {
			rcu_read_lock();
			idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
				struct drbd_device *device = peer_device->device;
				clear_bit(NEW_CUR_UUID, &device->flags);
			}
			rcu_read_unlock();
			spin_lock_irq(&connection->resource->req_lock);
			_tl_restart(connection, RESEND);
			_conn_request_state(connection,
					    (union drbd_state) { { .susp_fen = 1 } },
					    (union drbd_state) { { .susp_fen = 0 } },
					    CS_VERBOSE);
			spin_unlock_irq(&connection->resource->req_lock);
		}
	}
	kref_put(&connection->kref, drbd_destroy_connection);
	return 0;
}

static void conn_old_common_state(struct drbd_connection *connection, union drbd_state *pcs, enum chg_state_flags *pf)
{
	enum chg_state_flags flags = ~0;
	struct drbd_peer_device *peer_device;
	int vnr, first_vol = 1;
	enum drbd_disk_state common_disk_state = D_DISKLESS;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;

		if (first_vol) {
			common_disk_state = device->disk_state[NOW];
			first_vol = 0;
			continue;
		}

		if (common_disk_state != device->disk_state[NOW])
			flags &= ~CS_DC_DISK;
	}
	rcu_read_unlock();

	*pf |= CS_DC_MASK;
	*pf &= flags;
	pcs->role = connection->resource->role[NOW];
	pcs->peer = connection->peer_role[NOW];
	pcs->disk = common_disk_state;
	pcs->conn = connection->cstate[NOW];
}

static enum drbd_state_rv
conn_is_valid_transition(struct drbd_connection *connection, union drbd_state mask, union drbd_state val,
			 enum chg_state_flags flags)
{
	enum drbd_state_rv rv = SS_SUCCESS;
	union drbd_state ns, os;
	struct drbd_peer_device *peer_device;
	int vnr;

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		os = drbd_get_peer_device_state(peer_device, NOW);
		ns = sanitize_state(device, apply_mask_val(os, mask, val));

		if (flags & CS_IGN_OUTD_FAIL && ns.disk == D_OUTDATED && os.disk < D_OUTDATED)
			ns.disk = os.disk;

		if (ns.i == os.i)
			continue;

		rv = is_valid_transition(os, ns);

		if (rv >= SS_SUCCESS && !(flags & CS_HARD)) {
			rv = is_allowed_soft_transition(device, os, ns);
			if (rv == SS_SUCCESS)
				rv = is_valid_soft_transition(os, ns);
		}

		if (rv < SS_SUCCESS) {
			if (flags & CS_VERBOSE)
				print_st_err(device, os, ns, rv);
			break;
		}
	}
	rcu_read_unlock();

	return rv;
}

static void conn_set_state(struct drbd_connection *connection,
			   union drbd_state mask, union drbd_state val,
			   union drbd_state *pns_min, union drbd_state *pns_max,
			   enum chg_state_flags flags)
{
	union drbd_state ns, os, ns_max = { };
	union drbd_state ns_min = {
		{ .disk = D_MASK,
		  .pdsk = D_MASK
		} };
	struct drbd_peer_device *peer_device;
	enum drbd_state_rv rv;
	int vnr, number_of_volumes = 0;

	if (mask.conn == C_MASK)
		connection->cstate[NOW] = min_t(unsigned, val.conn, C_CONNECTED);

	rcu_read_lock();
	idr_for_each_entry(&connection->peer_devices, peer_device, vnr) {
		struct drbd_device *device = peer_device->device;
		number_of_volumes++;
		os = drbd_get_peer_device_state(peer_device, NOW);
		ns = apply_mask_val(os, mask, val);
		ns = sanitize_state(device, ns);

		if (flags & CS_IGN_OUTD_FAIL && ns.disk == D_OUTDATED && os.disk < D_OUTDATED)
			ns.disk = os.disk;

		rv = __drbd_set_state(device, ns, flags, NULL);
		if (rv < SS_SUCCESS)
			BUG();

		ns_max.disk = max_t(enum drbd_disk_state, device->disk_state[NOW], ns_max.disk);
		ns_max.pdsk = max_t(enum drbd_disk_state, peer_device->disk_state[NOW], ns_max.pdsk);

		ns_min.disk = min_t(enum drbd_disk_state, device->disk_state[NOW], ns_min.disk);
		ns_min.pdsk = min_t(enum drbd_disk_state, peer_device->disk_state[NOW], ns_min.pdsk);
	}
	rcu_read_unlock();

	if (number_of_volumes == 0) {
		ns_min.disk = ns_max.disk = D_DISKLESS;
		ns_min.pdsk = ns_max.pdsk = D_UNKNOWN;
	}

	ns_min.peer = ns_max.peer = connection->peer_role[NOW];
	ns_min.role = ns_max.role = connection->resource->role[NOW];
	ns_min.conn = ns_max.conn = connection->cstate[NOW];
	ns_min.susp = ns_max.susp = connection->resource->susp[NOW];
	ns_min.susp_nod = ns_max.susp_nod = connection->resource->susp_nod[NOW];
	ns_min.susp_fen = ns_max.susp_fen = connection->resource->susp_fen[NOW];

	*pns_min = ns_min;
	*pns_max = ns_max;
}

static enum drbd_state_rv
_conn_rq_cond(struct drbd_connection *connection, union drbd_state mask, union drbd_state val)
{
	enum drbd_state_rv rv;

	if (test_and_clear_bit(CONN_WD_ST_CHG_OKAY, &connection->flags))
		return SS_CW_SUCCESS;

	if (test_and_clear_bit(CONN_WD_ST_CHG_FAIL, &connection->flags))
		return SS_CW_FAILED_BY_PEER;

	spin_lock_irq(&connection->resource->req_lock);
	rv = connection->cstate[NOW] != C_CONNECTED ? SS_CW_NO_NEED : SS_UNKNOWN_ERROR;

	if (rv == SS_UNKNOWN_ERROR)
		rv = conn_is_valid_transition(connection, mask, val, 0);

	if (rv == SS_SUCCESS)
		rv = SS_UNKNOWN_ERROR; /* continue waiting */

	spin_unlock_irq(&connection->resource->req_lock);

	return rv;
}

static enum drbd_state_rv
conn_cl_wide(struct drbd_connection *connection, union drbd_state mask, union drbd_state val,
	     enum chg_state_flags f)
{
	enum drbd_state_rv rv;

	spin_unlock_irq(&connection->resource->req_lock);
	mutex_lock(&connection->resource->state_mutex);

	if (conn_send_state_req(connection, mask, val)) {
		rv = SS_CW_FAILED_BY_PEER;
		/* if (f & CS_VERBOSE)
		   print_st_err(device, os, ns, rv); */
		goto abort;
	}

	wait_event(connection->ping_wait,
		(rv = _conn_rq_cond(connection, mask, val)) != SS_UNKNOWN_ERROR);

abort:
	mutex_unlock(&connection->resource->state_mutex);
	spin_lock_irq(&connection->resource->req_lock);

	return rv;
}

enum drbd_state_rv
_conn_request_state(struct drbd_connection *connection, union drbd_state mask, union drbd_state val,
		    enum chg_state_flags flags)
{
	enum drbd_state_rv rv = SS_SUCCESS;
	struct after_conn_state_chg_work *acscw;
	enum drbd_conns oc = connection->cstate[NOW];
	union drbd_state ns_max, ns_min, os;

	rv = is_valid_conn_transition(oc, val.conn);
	if (rv < SS_SUCCESS)
		goto abort;

	rv = conn_is_valid_transition(connection, mask, val, flags);
	if (rv < SS_SUCCESS)
		goto abort;

	if (oc == C_CONNECTED && val.conn == C_DISCONNECTING &&
	    !(flags & (CS_LOCAL_ONLY | CS_HARD))) {
		rv = conn_cl_wide(connection, mask, val, flags);
		if (rv < SS_SUCCESS)
			goto abort;
	}

	conn_old_common_state(connection, &os, &flags);
	flags |= CS_DC_SUSP;
	conn_set_state(connection, mask, val, &ns_min, &ns_max, flags);
	conn_pr_state_change(connection, os, ns_max, flags);

	acscw = kmalloc(sizeof(*acscw), GFP_ATOMIC);
	if (acscw) {
		acscw->oc = os.conn;
		acscw->ns_min = ns_min;
		acscw->ns_max = ns_max;
		acscw->flags = flags;
		acscw->w.cb = w_after_conn_state_ch;
		kref_get(&connection->kref);
		acscw->connection = connection;
		drbd_queue_work(&connection->data.work, &acscw->w);
	} else {
		drbd_err(connection, "Could not kmalloc an acscw\n");
	}

abort:
	return rv;
}

enum drbd_state_rv
conn_request_state(struct drbd_connection *connection, union drbd_state mask, union drbd_state val,
		   enum chg_state_flags flags)
{
	enum drbd_state_rv rv;

	spin_lock_irq(&connection->resource->req_lock);
	rv = _conn_request_state(connection, mask, val, flags);
	spin_unlock_irq(&connection->resource->req_lock);

	return rv;
}
