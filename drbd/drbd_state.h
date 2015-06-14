#ifndef DRBD_STATE_H
#define DRBD_STATE_H

#include "drbd_protocol.h"

struct drbd_resource;
struct drbd_device;
struct drbd_connection;
struct drbd_peer_device;
struct drbd_work;

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
	CS_LOCAL_ONLY    = 1 << 5, /* Do not consider a device pair wide state change */
	CS_PREPARE	 = 1 << 6,
	CS_PREPARED	 = 1 << 7,
	CS_ABORT	 = 1 << 8,
	CS_TWOPC	 = 1 << 9,
	CS_IGN_OUTD_FAIL = 1 << 10,
	CS_DONT_RETRY    = 1 << 11, /* Disable internal retry. Caller has a retry loop */
};

extern void drbd_resume_al(struct drbd_device *device);

enum drbd_disk_state conn_highest_disk(struct drbd_connection *connection);
enum drbd_disk_state conn_lowest_disk(struct drbd_connection *connection);
enum drbd_disk_state conn_highest_pdsk(struct drbd_connection *connection);

extern void state_change_lock(struct drbd_resource *, unsigned long *, enum chg_state_flags);
extern void state_change_unlock(struct drbd_resource *, unsigned long *);

extern void begin_state_change(struct drbd_resource *, unsigned long *, enum chg_state_flags);
extern enum drbd_state_rv end_state_change(struct drbd_resource *, unsigned long *);
extern void abort_state_change(struct drbd_resource *, unsigned long *);
extern void abort_state_change_locked(struct drbd_resource *resource);

extern void begin_state_change_locked(struct drbd_resource *, enum chg_state_flags);
extern enum drbd_state_rv end_state_change_locked(struct drbd_resource *);

extern void abort_prepared_state_change(struct drbd_resource *);
extern void clear_remote_state_change(struct drbd_resource *resource);

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

extern int nested_twopc_work(struct drbd_work *work, int cancel);
extern enum drbd_state_rv nested_twopc_request(struct drbd_resource *, int, enum drbd_packet, struct p_twopc_request *);
extern bool cluster_wide_reply_ready(struct drbd_resource *);

extern enum drbd_state_rv change_role(struct drbd_resource *, enum drbd_role, enum chg_state_flags, bool);

extern void __change_io_susp_user(struct drbd_resource *, bool);
extern enum drbd_state_rv change_io_susp_user(struct drbd_resource *, bool, enum chg_state_flags);
extern void __change_io_susp_no_data(struct drbd_resource *, bool);
extern void __change_io_susp_fencing(struct drbd_resource *, bool);

extern void __change_disk_state(struct drbd_device *, enum drbd_disk_state);
extern void __change_disk_states(struct drbd_resource *, enum drbd_disk_state);
extern enum drbd_state_rv change_disk_state(struct drbd_device *, enum drbd_disk_state, enum chg_state_flags);

extern void __change_cstate(struct drbd_connection *, enum drbd_conn_state);
extern enum drbd_state_rv change_cstate(struct drbd_connection *, enum drbd_conn_state, enum chg_state_flags);

extern void __change_peer_role(struct drbd_connection *, enum drbd_role);

extern void __change_repl_state(struct drbd_peer_device *, enum drbd_repl_state);
extern enum drbd_state_rv change_repl_state(struct drbd_peer_device *, enum drbd_repl_state, enum chg_state_flags);
extern enum drbd_state_rv stable_change_repl_state(struct drbd_peer_device *, enum drbd_repl_state, enum chg_state_flags);

extern void __change_peer_disk_state(struct drbd_peer_device *, enum drbd_disk_state);
extern void __change_peer_disk_states(struct drbd_connection *, enum drbd_disk_state);
extern void __outdate_myself(struct drbd_resource *resource);
extern enum drbd_state_rv change_peer_disk_state(struct drbd_peer_device *, enum drbd_disk_state, enum chg_state_flags);

enum drbd_state_rv change_from_consistent(struct drbd_resource *, enum chg_state_flags);

extern void __change_resync_susp_user(struct drbd_peer_device *, bool);
extern enum drbd_state_rv change_resync_susp_user(struct drbd_peer_device *, bool, enum chg_state_flags);
extern void __change_resync_susp_peer(struct drbd_peer_device *, bool);
extern void __change_resync_susp_dependency(struct drbd_peer_device *, bool);

struct drbd_work;
extern int abort_nested_twopc_work(struct drbd_work *, int);

#endif
