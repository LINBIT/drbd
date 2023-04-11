/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __DRBD_INTERVAL_H
#define __DRBD_INTERVAL_H

#include <linux/types.h>
#include <linux/rbtree.h>

/* Interval types stored directly in drbd_interval so that we can handle
 * conflicts without having to inspect the containing object. The value 0 is
 * reserved for uninitialized intervals. */
enum drbd_interval_type {
	INTERVAL_LOCAL_WRITE = 1,
	INTERVAL_PEER_WRITE,
	INTERVAL_LOCAL_READ,
	INTERVAL_PEER_READ,
	INTERVAL_RESYNC_WRITE, /* L_SYNC_TARGET */
	INTERVAL_RESYNC_READ, /* L_SYNC_SOURCE */
	INTERVAL_OV_READ_SOURCE, /* L_VERIFY_S */
	INTERVAL_OV_READ_TARGET, /* L_VERIFY_T */
	INTERVAL_PEERS_IN_SYNC_LOCK,
};

#define INTERVAL_TYPE_MASK(type) (1 << (type))

enum drbd_interval_flags {
	/*
	 * Whether this peer request has been sent yet. For resync writes, the
	 * flag is set before sending.
	 *
	 * For resync reads, this flag is set after sending and is used to
	 * manage the lifetime of the request. When INTERVAL_SENT is not set,
	 * the sending path still has a reference to the request. This
	 * reference counting is protected by peer_reqs_lock.
	 */
	INTERVAL_SENT,

	/*
	 * Whether this peer request has been received yet.
	 *
	 * For resync reads, this flag is set when the corresponding ack has
	 * been received and is used to manage the lifetime of the request.
	 * When INTERVAL_RECEIVED is not set, the receiving path has a
	 * reference to the request. This reference counting is protected by
	 * peer_reqs_lock.
	 */
	INTERVAL_RECEIVED,

	/* Whether this has been queued after conflict. */
	INTERVAL_SUBMIT_CONFLICT_QUEUED,

	/* Whether this has been submitted already. */
	INTERVAL_SUBMITTED,

	/* Whether the local backing device bio is complete. */
	INTERVAL_BACKING_COMPLETED,

	/* This has been completed already; ignore for conflict detection. */
	INTERVAL_COMPLETED,

	/* For verify requests: whether this has conflicts. */
	INTERVAL_CONFLICT,

	/* For resync requests: whether this was canceled while waiting for conflict resolution. */
	INTERVAL_CANCELED,
};

/* Intervals used to manage conflicts between application requests and various
 * internal requests, so that the disk content is deterministic.
 *
 * The requests progress through states indicated by successively setting the
 * flags "INTERVAL_SUBMITTED", "INTERVAL_BACKING_COMPLETED" and
 * "INTERVAL_COMPLETED".
 *
 * Application and resync requests wait to be submitted until any conflicts
 * that are "INTERVAL_SUBMITTED" have reached "INTERVAL_BACKING_COMPLETED"
 * state. Application requests also wait for conflicting application requests
 * to ensure consistency between the replicated copies. In addition,
 * application requests wait for resync requests that have not yet been
 * submitted. Resync takes priority over application writes in this way because
 * a resync locks each block at most once, so it will finish at some point,
 * whereas the application may repeatedly write the same blocks, which would
 * potentially lock out resync indefinitely.
 *
 * Resync read requests do not conflict with each other, but they are
 * nevertheless mutually exclusive with writes, so that the bitmap can be
 * updated reliably.
 *
 * Verify requests do not wait for other requests. If there are conflicts, they
 * are simply cancelled. Futhermore, they do not lock out other requests;
 * instead they are simply marked as having conflicts and ignored.
 *
 * Application request intervals are retained even when they are
 * "INTERVAL_COMPLETED", so that they can be used to look up remote replies
 * that are still pending.
 */
struct drbd_interval {
	struct rb_node rb;
	sector_t sector;		/* start sector of the interval */
	unsigned int size;		/* size in bytes */
	enum drbd_interval_type type;	/* what type of interval this is */
	sector_t end;			/* highest interval end in subtree */
	unsigned long flags;
};

static inline bool drbd_interval_is_application(struct drbd_interval *i)
{
	return i->type == INTERVAL_LOCAL_WRITE || i->type == INTERVAL_PEER_WRITE ||
		i->type == INTERVAL_LOCAL_READ || i->type == INTERVAL_PEER_READ;
}

static inline bool drbd_interval_is_write(struct drbd_interval *i)
{
	return i->type == INTERVAL_LOCAL_WRITE || i->type == INTERVAL_PEER_WRITE ||
		i->type == INTERVAL_RESYNC_WRITE;
}

static inline bool drbd_interval_is_resync(struct drbd_interval *i)
{
	return i->type == INTERVAL_RESYNC_WRITE || i->type == INTERVAL_RESYNC_READ;
}

static inline bool drbd_interval_is_verify(struct drbd_interval *i)
{
	return i->type == INTERVAL_OV_READ_SOURCE || i->type == INTERVAL_OV_READ_TARGET;
}

static inline void drbd_clear_interval(struct drbd_interval *i)
{
	RB_CLEAR_NODE(&i->rb);
}

static inline bool drbd_interval_empty(struct drbd_interval *i)
{
	return RB_EMPTY_NODE(&i->rb);
}

extern const char *drbd_interval_type_str(struct drbd_interval *i);
extern bool drbd_insert_interval(struct rb_root *, struct drbd_interval *);
extern bool drbd_contains_interval(struct rb_root *, sector_t,
				   struct drbd_interval *);
extern void drbd_remove_interval(struct rb_root *, struct drbd_interval *);
extern struct drbd_interval *drbd_find_overlap(struct rb_root *, sector_t,
					unsigned int);
extern struct drbd_interval *drbd_next_overlap(struct drbd_interval *, sector_t,
					unsigned int);
extern void drbd_update_interval_size(struct drbd_interval *, unsigned int);

#define drbd_for_each_overlap(i, root, sector, size)		\
	for (i = drbd_find_overlap(root, sector, size);		\
	     i;							\
	     i = drbd_next_overlap(i, sector, size))

#endif  /* __DRBD_INTERVAL_H */
