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
};

enum drbd_interval_flags {
	/* Someone is waiting for completion. */
	INTERVAL_WAITING,

	/* This has been completed already; ignore for conflict detection. */
	INTERVAL_COMPLETED,
};

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
	return i->type == INTERVAL_LOCAL_WRITE || i->type == INTERVAL_PEER_WRITE;
}

static inline void drbd_clear_interval(struct drbd_interval *i)
{
	RB_CLEAR_NODE(&i->rb);
}

static inline bool drbd_interval_empty(struct drbd_interval *i)
{
	return RB_EMPTY_NODE(&i->rb);
}

extern bool drbd_insert_interval(struct rb_root *, struct drbd_interval *);
extern bool drbd_contains_interval(struct rb_root *, sector_t,
				   struct drbd_interval *);
extern void drbd_remove_interval(struct rb_root *, struct drbd_interval *);
extern struct drbd_interval *drbd_find_overlap(struct rb_root *, sector_t,
					unsigned int);
extern struct drbd_interval *drbd_next_overlap(struct drbd_interval *, sector_t,
					unsigned int);

#define drbd_for_each_overlap(i, root, sector, size)		\
	for (i = drbd_find_overlap(root, sector, size);		\
	     i;							\
	     i = drbd_next_overlap(i, sector, size))

#endif  /* __DRBD_INTERVAL_H */
