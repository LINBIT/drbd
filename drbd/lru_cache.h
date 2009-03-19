/*
-*- linux-c -*-
   lru_cache.c
   Kernel module for 2.6.x Kernels

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2003-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2003-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <linux/list.h>

struct lc_element {
	struct hlist_node colision;
	struct list_head list;		 /* LRU list or free list */
	unsigned int refcnt;
	unsigned int lc_number;
};

struct lru_cache {
	struct list_head lru;
	struct list_head free;
	struct list_head in_use;
	size_t element_size;
	unsigned int  nr_elements;
	unsigned int  new_number;

	unsigned int used;
	unsigned long flags;
	unsigned long hits, misses, starving, dirty, changed;
	struct lc_element *changing_element; /* just for paranoia */

	void  *lc_private;
	const char *name;

	struct hlist_head slot[0];
	/* hash colision chains here, then element storage. */
};


/* flag-bits for lru_cache */
enum {
	__LC_PARANOIA,
	__LC_DIRTY,
	__LC_STARVING,
};
#define LC_PARANOIA (1<<__LC_PARANOIA)
#define LC_DIRTY    (1<<__LC_DIRTY)
#define LC_STARVING (1<<__LC_STARVING)

extern struct lru_cache *lc_alloc(const char *name, unsigned int e_count,
				  size_t e_size, void *private_p);
extern void lc_reset(struct lru_cache *lc);
extern void lc_free(struct lru_cache *lc);
extern void lc_set(struct lru_cache *lc, unsigned int enr, int index);
extern void lc_del(struct lru_cache *lc, struct lc_element *element);

extern struct lc_element *lc_try_get(struct lru_cache *lc, unsigned int enr);
extern struct lc_element *lc_find(struct lru_cache *lc, unsigned int enr);
extern struct lc_element *lc_get(struct lru_cache *lc, unsigned int enr);
extern unsigned int lc_put(struct lru_cache *lc, struct lc_element *e);
extern void lc_changed(struct lru_cache *lc, struct lc_element *e);

struct seq_file;
extern size_t lc_printf_stats(struct seq_file *seq, struct lru_cache *lc);

void lc_dump(struct lru_cache *lc, struct seq_file *seq, char *utext,
	     void (*detail) (struct seq_file *, struct lc_element *));

/* This can be used to stop lc_get from changing the set of active elements.
 * Note that the reference counts and order on the lru list may still change.
 * returns true if we aquired the lock.
 */
static inline int lc_try_lock(struct lru_cache *lc)
{
	return !test_and_set_bit(__LC_DIRTY, &lc->flags);
}

static inline void lc_unlock(struct lru_cache *lc)
{
	clear_bit(__LC_DIRTY, &lc->flags);
	smp_mb__after_clear_bit();
}

static inline int lc_is_used(struct lru_cache *lc, unsigned int enr)
{
	struct lc_element *e = lc_find(lc, enr);
	return e && e->refcnt;
}

#define LC_FREE (-1U)

#define lc_e_base(lc)  ((char *)((lc)->slot + (lc)->nr_elements))
#define lc_entry(lc, i) ((struct lc_element *) \
		       (lc_e_base(lc) + (i)*(lc)->element_size))
#define lc_index_of(lc, e) (((char *)(e) - lc_e_base(lc))/(lc)->element_size)

#endif
