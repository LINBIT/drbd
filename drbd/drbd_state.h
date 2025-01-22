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

void drbd_resume_al(struct drbd_device *device);

enum drbd_disk_state conn_highest_disk(struct drbd_connection *connection);
enum drbd_disk_state conn_highest_pdsk(struct drbd_connection *connection);

void state_change_lock(struct drbd_resource *resource,
		       unsigned long *irq_flags, enum chg_state_flags flags);
void state_change_unlock(struct drbd_resource *resource,
			 unsigned long *irq_flags);

void begin_state_change(struct drbd_resource *resource,
			unsigned long *irq_flags, enum chg_state_flags flags);
enum drbd_state_rv end_state_change(struct drbd_resource *resource,
				    unsigned long *irq_flags, const char *tag);
void abort_state_change(struct drbd_resource *resource,
			unsigned long *irq_flags);
void abort_state_change_locked(struct drbd_resource *resource);

void begin_state_change_locked(struct drbd_resource *resource,
			       enum chg_state_flags flags);
enum drbd_state_rv end_state_change_locked(struct drbd_resource *resource,
					   const char *tag);

void clear_remote_state_change(struct drbd_resource *resource);
void __clear_remote_state_change(struct drbd_resource *resource);


enum which_state;
bool drbd_all_peer_replication(struct drbd_device *device, enum which_state which);
union drbd_state drbd_get_device_state(struct drbd_device *device,
				       enum which_state which);
union drbd_state drbd_get_peer_device_state(struct drbd_peer_device *peer_device,
					    enum which_state which);

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

void nested_twopc_work(struct work_struct *work);
void drbd_maybe_cluster_wide_reply(struct drbd_resource *resource);
enum drbd_state_rv nested_twopc_request(struct drbd_resource *resource,
					struct twopc_request *request);
bool drbd_twopc_between_peer_and_me(struct drbd_connection *connection);
bool cluster_wide_reply_ready(struct drbd_resource *resource);

enum drbd_state_rv change_role(struct drbd_resource *resource,
			       enum drbd_role role,
			       enum chg_state_flags flags, const char *tag,
			       const char **err_str);

void __change_io_susp_user(struct drbd_resource *resource, bool value);
enum drbd_state_rv change_io_susp_user(struct drbd_resource *resource,
				       bool value, enum chg_state_flags flags);
void __change_io_susp_no_data(struct drbd_resource *resource, bool value);
void __change_io_susp_fencing(struct drbd_connection *connection, bool value);
void __change_io_susp_quorum(struct drbd_resource *resource, bool value);

void __change_disk_state(struct drbd_device *device,
			 enum drbd_disk_state disk_state);
void __downgrade_disk_states(struct drbd_resource *resource,
			     enum drbd_disk_state disk_state);
enum drbd_state_rv change_disk_state(struct drbd_device *device,
				     enum drbd_disk_state disk_state,
				     enum chg_state_flags flags,
				     const char *tag, const char **err_str);

void __change_cstate(struct drbd_connection *connection,
		     enum drbd_conn_state cstate);
enum drbd_state_rv change_cstate_tag(struct drbd_connection *connection,
				     enum drbd_conn_state cstate,
				     enum chg_state_flags flags,
				     const char *tag, const char **err_str);
static inline enum drbd_state_rv change_cstate(struct drbd_connection *connection,
					       enum drbd_conn_state cstate,
					       enum chg_state_flags flags)
{
	return change_cstate_tag(connection, cstate, flags, NULL, NULL);
}

void __change_peer_role(struct drbd_connection *connection,
			enum drbd_role peer_role);

void __change_repl_state(struct drbd_peer_device *peer_device,
			 enum drbd_repl_state repl_state);
enum drbd_state_rv change_repl_state(struct drbd_peer_device *peer_device,
				     enum drbd_repl_state new_repl_state,
				     enum chg_state_flags flags,
				     const char *tag);
enum drbd_state_rv stable_change_repl_state(struct drbd_peer_device *peer_device,
					    enum drbd_repl_state repl_state,
					    enum chg_state_flags flags,
					    const char *tag);

void __change_peer_disk_state(struct drbd_peer_device *peer_device,
			      enum drbd_disk_state disk_state);
void __downgrade_peer_disk_states(struct drbd_connection *connection,
				  enum drbd_disk_state disk_state);
void __outdate_myself(struct drbd_resource *resource);
enum drbd_state_rv change_peer_disk_state(struct drbd_peer_device *peer_device,
					  enum drbd_disk_state disk_state,
					  enum chg_state_flags flags,
					  const char *tag);

void __change_resync_susp_user(struct drbd_peer_device *peer_device,
			       bool value);
enum drbd_state_rv change_resync_susp_user(struct drbd_peer_device *peer_device,
					   bool value,
					   enum chg_state_flags flags);
void __change_resync_susp_peer(struct drbd_peer_device *peer_device,
			       bool value);
void __change_resync_susp_dependency(struct drbd_peer_device *peer_device,
				     bool value);
void apply_connect(struct drbd_connection *connection, bool commit);

struct drbd_work;

bool resource_is_suspended(struct drbd_resource *resource,
			   enum which_state which);
bool is_suspended_fen(struct drbd_resource *resource, enum which_state which);

enum dds_flags;
enum determine_dev_size;
struct resize_parms;

enum determine_dev_size
change_cluster_wide_device_size(struct drbd_device *device,
				sector_t local_max_size,
				uint64_t new_user_size,
				enum dds_flags dds_flags,
				struct resize_parms *rs);

bool drbd_data_accessible(struct drbd_device *device, enum which_state which);
bool drbd_res_data_accessible(struct drbd_resource *resource);


void drbd_empty_twopc_work_fn(struct work_struct *work);
#endif
