/*
-*- linux-c -*-
   lru_cache.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003-2004, Philipp Reisner <philipp.reisner@linbit.com>.
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
  (You set the size of the cache during lc_alloc)
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

#include <linux/version.h>

struct lc_element {
	struct hlist_node colision;
	struct list_head list;           // LRU list or free list
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
	unsigned long flags;
	struct lc_element *changing_element; // just for paranoia

	void  *lc_private;

	struct hlist_head slot[0];
	// hash colision chains here, then element storage.
};


// flag-bits for lru_cache
enum {
	__LC_PARANOIA,
	__LC_DIRTY,
	__LC_STARVING,
};
#define LC_PARANOIA (1<<__LC_PARANOIA)
#define LC_DIRTY    (1<<__LC_DIRTY)
#define LC_STARVING (1<<__LC_STARVING)

extern struct lru_cache* lc_alloc(unsigned int e_count, size_t e_size,
				  void *private_p);
extern void lc_free(struct lru_cache* lc);
extern void lc_set (struct lru_cache* lc, unsigned int enr, int index);
extern void lc_del (struct lru_cache* lc, struct lc_element *element);

extern struct lc_element* lc_find(struct lru_cache* lc, unsigned int enr);
extern struct lc_element* lc_get (struct lru_cache* lc, unsigned int enr);
extern unsigned int       lc_put (struct lru_cache* lc, struct lc_element* e);
extern void            lc_changed(struct lru_cache* lc, struct lc_element* e);


/* This can be used to stop lc_get from changing the set of active elements.
 * Note that the reference counts and order on the lru list may still change.
 * returns true if we aquired the lock.
 */
static inline int lc_try_lock(struct lru_cache* lc)
{
	return !test_and_set_bit(__LC_DIRTY,&lc->flags);
}

static inline void lc_unlock(struct lru_cache* lc)
{
	clear_bit(__LC_DIRTY,&lc->flags);
	smp_mb__after_clear_bit();
}

#define LC_FREE (-1)

#define lc_e_base(lc)  ((char*) ( (lc)->slot + (lc)->nr_elements ) )
#define lc_entry(lc,i) ((struct lc_element*) \
                       (lc_e_base(lc) + (i)*(lc)->element_size))
#define lc_index_of(lc,e) (((char*)(e) - lc_e_base(lc))/(lc)->element_size)

#endif
