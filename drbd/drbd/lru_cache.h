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
  The lru_cache describes a big set of objects that are addressed
  by an index number (=lc_number). Only a small fraction of this set
  is present in the cache.
  (You set the size of the cache using lc_resize)
  Once created, the api consists of
    lc_find(,nr) -- finds the object with the given number, if present
    lc_get(,nr)  -- finds the object and increases the usage count
                    if not present, actions are taken to make sure that
		    the cache is updated, the user is notified of this by a callback.
		    Return value is NULL in this case.
		    As soon as the user informs the cache that it has been updated,
		    the next lc_get on that very object number will be successfull.
    lc_put(,lc_element*)
                 -- decreases the usage count of this object, and returns the new value.

    NOTE: It is the USERS responsibility to make sure that calls do not happen concurrently.
 */

#ifndef LRU_CACHE_H
#define LRU_CACHE_H

#include <linux/list.h>
#ifndef HLIST_HEAD_INIT
# include "hlist.h"
#endif

struct lc_element {
	struct hlist_node colision;
	struct list_head list;           // LRU list or free list
	unsigned int refcnt;
	unsigned int lc_number;
};

struct lru_cache;
typedef int (*lc_notify_on_change_fn)(struct lru_cache*,struct lc_element*,unsigned int);

struct lru_cache {
	struct list_head lru;
	struct list_head free;
	size_t element_size;
	unsigned int  nr_elements;
	unsigned long flags;

	lc_notify_on_change_fn notify_on_change;
	void  *lc_private;
	struct lc_element *changing;

	struct hlist_head *slot;
};


// flag-bits for lru_cache
enum {
	__LC_DIRTY,
	__LC_STARVING,
	__LC_LOCKED
};
#define LC_DIRTY    (1<<__LC_DIRTY)
#define LC_STARVING (1<<__LC_STARVING)
#define LC_LOCKED   (1<<__LC_LOCKED)

extern void lc_init  (struct lru_cache* lc);
extern void lc_resize(struct lru_cache* lc, unsigned int, spinlock_t* );
extern void lc_free  (struct lru_cache* lc);
extern void lc_set   (struct lru_cache* lc, unsigned int enr, int index);
extern void lc_del   (struct lru_cache* lc, struct lc_element *element);

extern struct lc_element* lc_find(struct lru_cache* lc, unsigned int enr);
extern struct lc_element* lc_get (struct lru_cache* lc, unsigned int enr);
extern unsigned int       lc_put (struct lru_cache* lc, struct lc_element* e);

static inline void lc_touch (struct lru_cache* lc,struct lc_element * e)
{
	// XXX paranoia: !list_empty(lru) && list_empty(free)
	list_move(&e->list,&lc->lru);
}

#define LC_FREE (-1)

#define lc_e_base(lc)  ((char*) ( (lc)->slot + (lc)->nr_elements ) )
#define lc_entry(lc,i) ((struct lc_element*) \
                       (lc_e_base(lc) + (i)*(lc)->element_size))
#define lc_index_of(lc,e) (((char*)(e) - lc_e_base(lc))/(lc)->element_size)

#endif
