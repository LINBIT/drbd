/*
-*- linux-c -*-
   lru_cache.c
   Kernel module for 2.2.x/2.4.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003, Philipp Reisner <philipp.reisner@gmx.at>.
        main author.

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

/*
  The lru_cache describes a big space of objects that are addressed
  by an index number (=lc_number). Only a small fraction of this
  objects is present in the cache. (You set the size of the cache using
  lc_resize) You might get hold of objects in the cache with the 
  lc_find() function. You can force elements into the cache with the
  lc_add() function. When the cache needs to evict an object
  (BTW, it always evicts the least recently used element), it uses
  the may_evict element function and the evict_wq to make sure
  that it has the permission to evice this particular object.
 */

#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/wait.h>

struct lc_element {
	struct list_head list;           // LRU list or free list
	struct lc_element *hash_next;
	unsigned int lc_number;
};

struct lru_cache {
	void* elements;
	size_t element_size;
	int nr_elements;
	struct list_head lru;
	struct list_head free;
	spinlock_t lc_lock;
	int updates[3];
	int (*may_evict) (struct lru_cache *, struct lc_element *);
	wait_queue_head_t evict_wq;
};

extern void lc_init(struct lru_cache * mlc);
extern void lc_resize(struct lru_cache * mlc, int nr_elements);
extern void lc_free(struct lru_cache * mlc);
extern struct lc_element * lc_find(struct lru_cache * mlc, unsigned int enr);
extern struct lc_element * lc_add(struct lru_cache * mlc, 
				  unsigned int enr,
				  unsigned long * evicted);
extern void lc_set(struct lru_cache * mlc, unsigned int enr, int index);
extern int lc_fixup_hash_next(struct lru_cache * mlc);

static inline void lc_touch(struct lru_cache * mlc,struct lc_element * e) 
{
	list_move(&e->list,&mlc->lru);
}

#define LC_AT_INDEX(MLC,I) \
 ( (struct lc_element *)( (MLC)->elements + (I) * (MLC)->element_size ) )
#define LC_INDEX_OF(MLC,E) \
 ( ( ((void*)(E)) - (MLC)->elements ) / (MLC)->element_size )

#endif
