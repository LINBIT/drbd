#ifndef DRBD_STATE_H
#define DRBD_STATE_H

struct drbd_conf;

enum chg_state_flags {
	CS_HARD	= 1,
	CS_VERBOSE = 2,
	CS_WAIT_COMPLETE = 4,
	CS_SERIALIZE    = 8,
	CS_ORDERED      = CS_WAIT_COMPLETE + CS_SERIALIZE,
};

extern enum drbd_state_rv drbd_change_state(struct drbd_conf *mdev,
					    enum chg_state_flags f,
					    union drbd_state mask,
					    union drbd_state val);
extern void drbd_force_state(struct drbd_conf *, union drbd_state,
			union drbd_state);
extern enum drbd_state_rv _drbd_request_state(struct drbd_conf *,
					      union drbd_state,
					      union drbd_state,
					      enum chg_state_flags);
extern enum drbd_state_rv __drbd_set_state(struct drbd_conf *, union drbd_state,
					   enum chg_state_flags,
					   struct completion *done);
extern void print_st_err(struct drbd_conf *, union drbd_state,
			union drbd_state, int);

extern void drbd_resume_al(struct drbd_conf *mdev);

/**
 * drbd_request_state() - Reqest a state change
 * @mdev:	DRBD device.
 * @mask:	mask of state bits to change.
 * @val:	value of new state bits.
 *
 * This is the most graceful way of requesting a state change. It is verbose
 * quite verbose in case the state change is not possible, and all those
 * state changes are globally serialized.
 */
static inline int drbd_request_state(struct drbd_conf *mdev,
				     union drbd_state mask,
				     union drbd_state val)
{
	return _drbd_request_state(mdev, mask, val, CS_VERBOSE + CS_ORDERED);
}

#endif
