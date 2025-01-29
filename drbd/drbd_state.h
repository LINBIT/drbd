/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DRBD_STATE_H
#define DRBD_STATE_H

#include "drbd_protocol.h"

struct drbd_resource;
struct drbd_device;
struct drbd_connection;
struct drbd_peer_device;
struct drbd_work;
struct twopc_request;

/**
 * DOC: DRBD State macros
 *
 * These macros are used to express state changes in easily readable form.
 */
#define role_MASK R_MASK
#define peer_MASK R_MASK
#define disk_MASK D_MASK
#define pdsk_MASK D_MASK
#define conn_MASK C_MASK
#define susp_MASK 1
#define user_isp_MASK 1
#define aftr_isp_MASK 1
#define susp_nod_MASK 1
#define susp_fen_MASK 1

enum chg_state_flags {
	CS_HARD          = 1 << 0, /* Forced state change, such as a connection loss */
	CS_VERBOSE       = 1 << 1,
	CS_WAIT_COMPLETE = 1 << 2,
	CS_SERIALIZE     = 1 << 3,
	CS_ALREADY_SERIALIZED = 1 << 4, /* resource->state_sem already taken */
	CS_LOCAL_ONLY    = 1 << 5, /* Do not consider a cluster-wide state change */
	CS_PREPARE	 = 1 << 6,
	CS_PREPARED	 = 1 << 7,
	CS_ABORT	 = 1 << 8,
	CS_TWOPC	 = 1 << 9,
	CS_IGN_OUTD_FAIL = 1 << 10,
	CS_DONT_RETRY    = 1 << 11, /* Disable internal retry. Caller has a retry loop */
	CS_FORCE_RECALC  = 1 << 13, /* Force re-evaluation of state logic */
	CS_CLUSTER_WIDE  = 1 << 14, /* Make this a cluster wide state change! */
	CS_FP_LOCAL_UP_TO_DATE = 1 << 15, /* force promotion by making local disk state up_to_date */
	CS_FP_OUTDATE_PEERS = 1 << 16, /* force promotion by marking unknown peers as outdated */
	CS_FS_IGN_OPENERS = 1 << 17, /* force demote, ignore openers */
};

extern void drbd_resume_al(struct drbd_device *device);

enum drbd_disk_state conn_highest_disk(struct drbd_connection *connection);
enum drbd_disk_state conn_highest_pdsk(struct drbd_connection *connection);

extern void state_change_lock(struct drbd_resource *, unsigned long *, enum chg_state_flags);
extern void state_change_unlock(struct drbd_resource *, unsigned long *);

extern void begin_state_change(struct drbd_resource *, unsigned long *, enum chg_state_flags);
extern enum drbd_state_rv end_state_change(struct drbd_resource * resource, unsigned long *irq_flags, const char *tag);
extern void abort_state_change(struct drbd_resource *, unsigned long *);
extern void abort_state_change_locked(struct drbd_resource *resource);

extern void begin_state_change_locked(struct drbd_resource *, enum chg_state_flags);
extern enum drbd_state_rv end_state_change_locked(struct drbd_resource *resource, const char *tag);

extern void clear_remote_state_change(struct drbd_resource *resource);
extern void __clear_remote_state_change(struct drbd_resource *resource);


enum which_state;
extern union drbd_state drbd_get_device_state(struct drbd_device *, enum which_state);
extern union drbd_state drbd_get_peer_device_state(struct drbd_peer_device *, enum which_state);
extern union drbd_state drbd_get_connection_state(struct drbd_connection *, enum which_state);

#define stable_state_change(resource, change_state) ({				\
		enum drbd_state_rv rv;						\
		int err;							\
		err = wait_event_interruptible((resource)->state_wait,		\
			(rv = (change_state)) != SS_IN_TRANSIENT_STATE);	\
		if (err)							\
			err = -SS_UNKNOWN_ERROR;				\
		else								\
			err = rv;						\
		err;								\
	})

extern void nested_twopc_work(struct work_struct *work);
extern void drbd_maybe_cluster_wide_reply(struct drbd_resource *resource);
extern enum drbd_state_rv nested_twopc_request(struct drbd_resource *res, struct twopc_request *r);
extern bool drbd_twopc_between_peer_and_me(struct drbd_connection *connection);
extern bool cluster_wide_reply_ready(struct drbd_resource *);

extern enum drbd_state_rv change_role(struct drbd_resource *resource,
			       enum drbd_role role,
			       enum chg_state_flags flags,
			       const char *tag,
			       const char **err_str);

extern void __change_io_susp_user(struct drbd_resource *, bool);
extern enum drbd_state_rv change_io_susp_user(struct drbd_resource *, bool, enum chg_state_flags);
extern void __change_io_susp_no_data(struct drbd_resource *, bool);
extern void __change_io_susp_fencing(struct drbd_connection *, bool);
extern void __change_io_susp_quorum(struct drbd_resource *, bool);

extern void __change_disk_state(struct drbd_device *, enum drbd_disk_state);
extern void __downgrade_disk_states(struct drbd_resource *, enum drbd_disk_state);
extern enum drbd_state_rv change_disk_state(struct drbd_device *device,
				     enum drbd_disk_state disk_state,
				     enum chg_state_flags flags,
				     const char *tag,
				     const char **err_str);

extern void __change_cstate(struct drbd_connection *, enum drbd_conn_state);
extern enum drbd_state_rv change_cstate_tag(struct drbd_connection *connection,
				    enum drbd_conn_state cstate,
				    enum chg_state_flags flags,
				    const char *tag,
				    const char **err_str);
static inline enum drbd_state_rv change_cstate(struct drbd_connection *connection,
					       enum drbd_conn_state cstate,
					       enum chg_state_flags flags)
{
	return change_cstate_tag(connection, cstate, flags, NULL, NULL);
}

extern void __change_peer_role(struct drbd_connection *, enum drbd_role);

extern void __change_repl_state(struct drbd_peer_device *, enum drbd_repl_state);
extern enum drbd_state_rv change_repl_state(struct drbd_peer_device *peer_device,
				     enum drbd_repl_state new_repl_state,
				     enum chg_state_flags flags,
				     const char *tag);
extern enum drbd_state_rv stable_change_repl_state(struct drbd_peer_device *peer_device,
					    enum drbd_repl_state repl_state,
					    enum chg_state_flags flags,
					    const char *tag);

extern void __change_peer_disk_state(struct drbd_peer_device *, enum drbd_disk_state);
extern void __downgrade_peer_disk_states(struct drbd_connection *, enum drbd_disk_state);
extern void __outdate_myself(struct drbd_resource *resource);
extern enum drbd_state_rv change_peer_disk_state(struct drbd_peer_device *peer_device,
					  enum drbd_disk_state disk_state,
					  enum chg_state_flags flags,
					  const char *tag);

extern void __change_resync_susp_user(struct drbd_peer_device *, bool);
extern enum drbd_state_rv change_resync_susp_user(struct drbd_peer_device *, bool, enum chg_state_flags);
extern void __change_resync_susp_peer(struct drbd_peer_device *, bool);
extern void __change_resync_susp_dependency(struct drbd_peer_device *, bool);
extern void apply_connect(struct drbd_connection *, bool);

struct drbd_work;

extern bool resource_is_suspended(struct drbd_resource *resource, enum which_state which);
extern bool is_suspended_fen(struct drbd_resource *resource, enum which_state which);

enum dds_flags;
enum determine_dev_size;
struct resize_parms;

extern enum determine_dev_size
change_cluster_wide_device_size(struct drbd_device *, sector_t, uint64_t, enum dds_flags,
				struct resize_parms *);

extern void drbd_notify_peers_lost_primary(struct drbd_resource *resource);
extern bool drbd_data_accessible(struct drbd_device *, enum which_state);
extern bool drbd_res_data_accessible(struct drbd_resource *resource);


extern void drbd_empty_twopc_work_fn(struct work_struct *work);
#endif
