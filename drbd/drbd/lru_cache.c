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

#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include "lru_cache.h"

#define STATIC static

// this is developers aid only!
#define PARANOIA_ENTRY() BUG_ON(test_and_set_bit(__LC_LOCKED,&lc->flags))
#define PARANOIA_LEAVE() do { clear_bit(__LC_LOCKED,&lc->flags); smp_mb__after_clear_bit(); } while (0)
#define RETURN(x...)     do { PARANOIA_LEAVE(); return x ; } while (0)

static inline void lc_touch(struct lru_cache *lc,struct lc_element *e)
{
	// XXX paranoia: !list_empty(lru) && list_empty(free)
	list_move(&e->list,&lc->lru);
}

/**
 * lc_alloc: allocates memory for @e_count objects of @e_size bytes plus the
 * struct lru_cache, and the hash table slots.
 * returns pointer to a newly initialized lru_cache object with said parameters.
 */
struct lru_cache* lc_alloc(unsigned int e_count, unsigned int e_size,
			   lc_notify_on_change_fn fn, void *private_p)
{
	unsigned long bytes;
	struct lru_cache   *lc;
	struct lc_element *e;
	int i;

	e_size = max(sizeof(struct lc_element),e_size);
	bytes  = e_size+sizeof(struct hlist_head);
	bytes *= e_count;
	bytes += sizeof(struct lru_cache);
	lc     = vmalloc(bytes);
	memset(lc, 0, bytes);
	if (lc) {
		INIT_LIST_HEAD(&lc->lru);
		INIT_LIST_HEAD(&lc->free);
		lc->element_size     = e_size;
		lc->nr_elements      = e_count;
		lc->notify_on_change = fn;
		lc->lc_private       = private_p;
		for(i=0;i<e_count;i++) {
			e = lc_entry(lc,i);
			e->lc_number = LC_FREE;
			list_add(&e->list,&lc->free);
			// memset(,0,) did the rest of init for us
		}
	}
	return lc;
}

/**
 * lc_free: Frees memory allocated by lc_alloc.
 * @lc: The lru_cache object
 */
void lc_free(struct lru_cache* lc)
{
	vfree(lc);
}

static unsigned int lc_hash_fn(struct lru_cache* lc, unsigned int enr)
{
	return enr % lc->nr_elements;
}


/**
 * lc_find: Returns the pointer to an element, if the element is present
 * in the hash table. In case it is not this function returns NULL.
 * @lc: The lru_cache object
 * @enr: element number
 */
struct lc_element* lc_find(struct lru_cache* lc, unsigned int enr)
{
	struct hlist_node *n;
	struct lc_element *e;

	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);
	hlist_for_each_entry(e, n, lc->slot + lc_hash_fn(lc, enr), colision) {
		if (e->lc_number == enr) return e;
	}
	return NULL;
}

STATIC struct lc_element * lc_evict(struct lru_cache* lc)
{
	struct list_head  *n;
	struct lc_element *e;

	n=lc->lru.prev;
	e=list_entry(n, struct lc_element,list);

	if (e->refcnt) return NULL; // Dead code ?

	list_del(&e->list);
	hlist_del(&e->colision);
	return e;
}

/**
 * lc_del: Removes an element from the cache (and therefore adds the
 * element's storage to the free list)
 *
 * @lc: The lru_cache object
 * @e: The element to remove
 */
void lc_del(struct lru_cache* lc, struct lc_element *e)
{
	// FIXME what to do with refcnt != 0 ?
	PARANOIA_ENTRY();
	BUG_ON(e->refcnt);
	list_del(&e->list);
	hlist_del(&e->colision);
	e->lc_number = LC_FREE;
	e->refcnt = 0;
	list_add(&e->list,&lc->free);
	RETURN();
}

STATIC struct lc_element* lc_get_unused_element(struct lru_cache* lc)
{
	struct list_head *n;

	if (list_empty(&lc->free)) return lc_evict(lc);

	n=lc->free.next;
	list_del(n);
	return list_entry(n, struct lc_element,list);
}

STATIC int lc_unused_element_available(struct lru_cache* lc)
{
	struct list_head *n;
	struct lc_element *e;

	if (!list_empty(&lc->free)) return 1; // something on the free list
	n=lc->lru.prev;
	e=list_entry(n, struct lc_element,list);

	if (e->refcnt) return 0;  // the LRU element is still in use
	return 1; // we can evict the LRU element
}


/**
 * lc_get: Finds an element in the cache, increases its usage count,
 * "touches" and returns it.
 * In case the requested number is not present, it needs to be added to the
 * cache. Therefore it is possible that an other element becomes eviced from
 * the cache. In either case, the user is notified so he is able to e.g. keep
 * a persistent log of the cache changes, and therefore the objects in use.
 *
 * @lc: The lru_cache object
 * @enr: element number
 */
struct lc_element* lc_get(struct lru_cache* lc, unsigned int enr)
{
	struct lc_element *e;
	int sync;

	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);

	PARANOIA_ENTRY();
	// maybe this should be test_bit, but access needs be serialized
	// anyways, so this should be ok.
	if ( lc->flags & (LC_STARVING|LC_LOCKED) ) RETURN(NULL);

	e = lc_find(lc, enr);
	if (e) {
		++e->refcnt;
		lc_touch(lc,e);
		RETURN(e);
	}

	/* In case there is nothing available and we can not kick out
	   the LRU element, we have to wait ...
	 */
	if(!lc_unused_element_available(lc)) {
		__set_bit(__LC_STARVING,&lc->flags);
		RETURN(NULL);
	}

	/* it was not present in the cache, find an unused element,
	 * which then is replaced.
	 * we need to update the cache; serialize on lc->flags & LC_DIRTY
	 */
	if (test_and_set_bit(__LC_DIRTY,&lc->flags)) RETURN(NULL);

	e = lc_get_unused_element(lc);
	BUG_ON(!e);

	list_add(&e->list,&lc->lru);

	if(lc->notify_on_change) {
		PARANOIA_LEAVE();
		sync = lc->notify_on_change(lc,e,enr);
		PARANOIA_ENTRY();
		/* we set the STARVING bit when we try to evict the lru
		 * element, but it is still in use, to avoid usage patterns
		 * where we never can evict.
		 * as soon as we have successfully changed an element,
		 * we need to clear this flag again.
		 */
		clear_bit(__LC_STARVING,&lc->flags);
		smp_mb__after_clear_bit();
	} else {
		/* ok, user does not want to be notified.
		 * we just do it here and now.
		 */
		e->lc_number = enr;
		// I'd like to use __clear_bit, but 2.4.23 does not have it.
		clear_bit(__LC_DIRTY,&lc->flags);
		clear_bit(__LC_STARVING,&lc->flags);
		smp_mb__after_clear_bit();
		sync = 1;
	}

	hlist_add_head( &e->colision, lc->slot + lc_hash_fn(lc, enr) );

	if (sync) {
		BUG_ON(e->lc_number != enr);
		BUG_ON(++e->refcnt != 1);
		BUG_ON(lc->flags & LC_DIRTY);
		RETURN(e);
	} else {
		RETURN(NULL);
	}
}

unsigned int lc_put(struct lru_cache* lc, struct lc_element* e)
{
	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);
	BUG_ON(!e);

	PARANOIA_ENTRY();
	BUG_ON(e->refcnt == 0);
	if ( --e->refcnt == 0) {
		clear_bit(__LC_STARVING,&lc->flags);
		smp_mb__after_clear_bit();
	}
	RETURN(e->refcnt);
}


/**
 * lc_set: Sets an element in the cache. You might use this function to
 * setup the cache. It is expected that the elements are properly initialized.
 * @lc: The lru_cache object
 * @enr: element number
 * @index: The elements' position in the cache
 */
void lc_set(struct lru_cache* lc, unsigned int enr, int index)
{
	struct lc_element *e;

	if ( index < 0 || index >= lc->nr_elements ) return;

	e = lc_entry(lc,index);
	e->lc_number = enr;

	hlist_del_init(&e->colision);
	hlist_add_head( &e->colision, lc->slot + lc_hash_fn(lc,enr) );
	lc_touch(lc,e); // to make sure that his entry is not on the free list.
}

