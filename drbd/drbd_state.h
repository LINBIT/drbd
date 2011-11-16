#ifndef DRBD_STATE_H
#define DRBD_STATE_H

struct drbd_resource;
struct drbd_device;
struct drbd_connection;
struct drbd_peer_device;

/**
 * DOC: DRBD State macros
 *
 * These macros are used to express state changes in easily readable form.
 *
 * The NS macros expand to a mask and a value, that can be bit ored onto the
 * current state as soon as the spinlock (req_lock) was taken.
 *
 * The _NS macros are used for state functions that get called with the
 * spinlock. These macros expand directly to the new state value.
 *
 * Besides the basic forms NS() and _NS() additional _?NS[23] are defined
 * to express state changes that affect more than one aspect of the state.
 *
 * E.g. NS2(conn, L_CONNECTED, peer, R_SECONDARY)
 * Means that the network connection was established and that the peer
 * is in secondary role.
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

#define STATE_MASK(T) \
	({ union drbd_state mask; mask.i = 0; mask.T = T##_MASK; mask.i; })
#define STATE_VALUE(T, S) \
	({ union drbd_state val; val.i = 0; val.T = (S); val.i; })
#define STATE_TYPE(S) \
	((union drbd_state)(S))

#define NS(T, S) \
	STATE_TYPE(STATE_MASK(T)), \
	STATE_TYPE(STATE_VALUE(T, S))
#define NS2(T1, S1, T2, S2) \
	STATE_TYPE(STATE_MASK(T1) | STATE_MASK(T2)), \
	STATE_TYPE(STATE_VALUE(T1, S1) | STATE_VALUE(T2, S2))
#define NS3(T1, S1, T2, S2, T3, S3) \
	STATE_TYPE(STATE_MASK(T1) | STATE_MASK(T2) | STATE_MASK(T3)), \
	STATE_TYPE(STATE_VALUE(T1, S1) | STATE_VALUE(T2, S2) | STATE_VALUE(T3, S3))

#define _NS(D, T, S) \
	({ union drbd_state __ns; __ns = drbd_get_peer_device_state(first_peer_device(D), NOW); __ns.T = (S); __ns; })
#define _NS2(D, T1, S1, T2, S2) \
	({ union drbd_state __ns; __ns = drbd_get_peer_device_state(first_peer_device(D), NOW); __ns.T1 = (S1); \
	__ns.T2 = (S2); __ns; })

enum chg_state_flags {
	CS_HARD          = 1 << 0, /* Forced state change, such as a connection loss */
	CS_VERBOSE       = 1 << 1,
	CS_WAIT_COMPLETE = 1 << 2,
	CS_SERIALIZE     = 1 << 3,
	CS_ALREADY_SERIALIZED = 1 << 4, /* resource->state_mutex already taken */
	CS_LOCAL_ONLY    = 1 << 5, /* Do not consider a device pair wide state change */
	CS_IGN_OUTD_FAIL = 1 << 11,
	CS_GLOBAL_LOCKED = 1 << 12,  /* global_state_lock already taken */
};

extern enum drbd_state_rv drbd_change_state(struct drbd_device *device,
					    enum chg_state_flags f,
					    union drbd_state mask,
					    union drbd_state val);
extern enum drbd_state_rv _drbd_request_state(struct drbd_device *,
					      union drbd_state,
					      union drbd_state,
					      enum chg_state_flags);
extern void __drbd_set_state(struct drbd_device *, union drbd_state);

void
_conn_request_state(struct drbd_connection *connection, union drbd_state mask, union drbd_state val);

enum drbd_state_rv
conn_request_state(struct drbd_connection *connection, union drbd_state mask, union drbd_state val,
		   enum chg_state_flags flags);

extern void drbd_resume_al(struct drbd_device *device);

/**
 * drbd_request_state() - Reqest a state change
 * @device:	DRBD device.
 * @mask:	mask of state bits to change.
 * @val:	value of new state bits.
 *
 * This is the most graceful way of requesting a state change. It is verbose
 * quite verbose in case the state change is not possible, and all those
 * state changes are globally serialized.
 */
static inline int drbd_request_state(struct drbd_device *device,
				     union drbd_state mask,
				     union drbd_state val)
{
	return _drbd_request_state(device, mask, val, CS_VERBOSE | CS_WAIT_COMPLETE | CS_SERIALIZE);
}

enum drbd_role highest_peer_role(struct drbd_resource *);
enum drbd_disk_state conn_highest_disk(struct drbd_connection *connection);
enum drbd_disk_state conn_lowest_disk(struct drbd_connection *connection);
enum drbd_disk_state conn_highest_pdsk(struct drbd_connection *connection);

extern void begin_state_change(struct drbd_resource *, unsigned long *, enum chg_state_flags);
extern enum drbd_state_rv end_state_change(struct drbd_resource *, unsigned long *);
extern void abort_state_change(struct drbd_resource *, unsigned long *);
extern void abort_state_change_locked(struct drbd_resource *resource);

extern void begin_state_change_locked(struct drbd_resource *, enum chg_state_flags);
extern enum drbd_state_rv end_state_change_locked(struct drbd_resource *);

enum which_state;
extern union drbd_state drbd_get_device_state(struct drbd_device *, enum which_state);
extern union drbd_state drbd_get_peer_device_state(struct drbd_peer_device *, enum which_state);

extern void drbd_set_new_device_state(struct drbd_device *, union drbd_state);
extern void drbd_set_new_peer_device_state(struct drbd_peer_device *, union drbd_state);

#define stable_state_change(resource, change_state) ({							\
		enum drbd_state_rv rv;									\
		wait_event((resource)->state_wait, (rv = (change_state)) != SS_IN_TRANSIENT_STATE);	\
		rv;											\
	})

extern void __change_disk_state(struct drbd_device *, enum drbd_disk_state);
extern void __change_disk_states(struct drbd_resource *, enum drbd_disk_state);
extern enum drbd_state_rv change_disk_state(struct drbd_device *, enum drbd_disk_state, enum chg_state_flags);

extern void __change_cstate(struct drbd_connection *, enum drbd_conn_state);
extern enum drbd_state_rv change_cstate(struct drbd_connection *, enum drbd_conn_state, enum chg_state_flags);

extern void __change_repl_state(struct drbd_peer_device *, enum drbd_repl_state);
extern enum drbd_state_rv change_repl_state(struct drbd_peer_device *, enum drbd_repl_state, enum chg_state_flags);
extern enum drbd_state_rv stable_change_repl_state(struct drbd_peer_device *, enum drbd_repl_state, enum chg_state_flags);

extern void __change_peer_disk_state(struct drbd_peer_device *, enum drbd_disk_state);
extern void __change_peer_disk_states(struct drbd_connection *, enum drbd_disk_state);
extern enum drbd_state_rv change_peer_disk_state(struct drbd_peer_device *, enum drbd_disk_state, enum chg_state_flags);

extern void __change_resync_susp_user(struct drbd_peer_device *, bool);
extern enum drbd_state_rv change_resync_susp_user(struct drbd_peer_device *, bool, enum chg_state_flags);
extern void __change_resync_susp_peer(struct drbd_peer_device *, bool);
extern void __change_resync_susp_dependency(struct drbd_peer_device *, bool);

#endif
