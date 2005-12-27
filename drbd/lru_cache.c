/*
-*- linux-c -*-
   lru_cache.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003-2004, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2004, Lars Ellenberg <l.g.e@web.de>.
        authors.

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
#include <linux/string.h> // for memset
#include <linux/seq_file.h> // for seq_printf
#include "lru_cache.h"

#define STATIC static

// this is developers aid only!
#define PARANOIA_ENTRY() BUG_ON(test_and_set_bit(__LC_PARANOIA,&lc->flags))
#define PARANOIA_LEAVE() do { clear_bit(__LC_PARANOIA,&lc->flags); smp_mb__after_clear_bit(); } while (0)
#define RETURN(x...)     do { PARANOIA_LEAVE(); return x ; } while (0)

/**
 * lc_alloc: allocates memory for @e_count objects of @e_size bytes plus the
 * struct lru_cache, and the hash table slots.
 * returns pointer to a newly initialized lru_cache object with said parameters.
 */
struct lru_cache* lc_alloc(const char *name, unsigned int e_count,
			   size_t e_size, void *private_p)
{
	unsigned long bytes;
	struct lru_cache   *lc;
	struct lc_element *e;
	int i;

	BUG_ON(!e_count);
	e_size = max(sizeof(struct lc_element),e_size);
	bytes  = e_size+sizeof(struct hlist_head);
	bytes *= e_count;
	bytes += sizeof(struct lru_cache);
	lc     = vmalloc(bytes);
	memset(lc, 0, bytes);
	if (lc) {
		INIT_LIST_HEAD(&lc->in_use);
		INIT_LIST_HEAD(&lc->lru);
		INIT_LIST_HEAD(&lc->free);
		lc->element_size     = e_size;
		lc->nr_elements      = e_count;
		lc->new_number	     = -1;
		lc->lc_private       = private_p;
		lc->name             = name;
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

size_t	lc_printf_stats(struct seq_file *seq, struct lru_cache* lc)
{
	/* NOTE:
	 * total calls to lc_get are
	 * starving + hits + misses
	 * misses include "dirty" count (update from an other thread in progress)
	 * and "changed", when this in fact lead to an successful update of the cache.
	 */
	return seq_printf(seq,"\t%s: elements:%u "
		"hits:%lu misses:%lu starving:%lu dirty:%lu changed:%lu\n",
		lc->name, lc->nr_elements,
		lc->hits, lc->misses, lc->starving, lc->dirty, lc->changed);
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

	if (list_empty(&lc->lru)) return 0;

	n=lc->lru.prev;
	e=list_entry(n, struct lc_element,list);

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
	if (!list_empty(&lc->free)) return 1; // something on the free list
	if (!list_empty(&lc->lru)) return 1;  // something to evict

	return 0;
}


/**
 * lc_get: Finds an element in the cache, increases its usage count,
 * "touches" and returns it.
 * In case the requested number is not present, it needs to be added to the
 * cache. Therefore it is possible that an other element becomes eviced from
 * the cache. In either case, the user is notified so he is able to e.g. keep
 * a persistent log of the cache changes, and therefore the objects in use.
 *
 * Return values:
 *  NULL    if the requested element number was not in the cache, and no unused
 *          element could be recycled
 *  pointer to the element with the REQUESTED element number
 *          In this case, it can be used right away
 *
 *  pointer to an UNUSED element with some different element number.
 *          In this case, the cache is marked dirty, and the returned element
 *          pointer is removed from the lru list and hash collision chains.
 *          The user now should do whatever houskeeping is necessary. Then he
 *          needs to call lc_element_changed(lc,element_pointer), to finish the
 *          change.
 *
 * NOTE: The user needs to check the lc_number on EACH use, so he recognizes
 *       any cache set change.
 *
 * @lc: The lru_cache object
 * @enr: element number
 */
struct lc_element* lc_get(struct lru_cache* lc, unsigned int enr)
{
	struct lc_element *e;

	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);

	PARANOIA_ENTRY();
	if ( lc->flags & LC_STARVING ) {
		++lc->starving;
		RETURN(NULL);
	}

	e = lc_find(lc, enr);
	if (e) {
		++lc->hits;
		++e->refcnt;
		list_move(&e->list,&lc->in_use); // Not evictable...
		RETURN(e);
	}

	++lc->misses;

	/* In case there is nothing available and we can not kick out
	 * the LRU element, we have to wait ...
	 */
	if(!lc_unused_element_available(lc)) {
		__set_bit(__LC_STARVING,&lc->flags);
		RETURN(NULL);
	}

	/* it was not present in the cache, find an unused element,
	 * which then is replaced.
	 * we need to update the cache; serialize on lc->flags & LC_DIRTY
	 */
	if (test_and_set_bit(__LC_DIRTY,&lc->flags)) {
		++lc->dirty;
		RETURN(NULL);
	}

	e = lc_get_unused_element(lc);
	BUG_ON(!e);

	clear_bit(__LC_STARVING,&lc->flags);
	BUG_ON(++e->refcnt != 1);

	lc->changing_element = e;
	lc->new_number = enr;

	RETURN(e);
}

void lc_changed(struct lru_cache* lc, struct lc_element* e)
{
	PARANOIA_ENTRY();
	BUG_ON(e != lc->changing_element);
	++lc->changed;
	e->lc_number = lc->new_number;
	list_add(&e->list,&lc->in_use);
	hlist_add_head( &e->colision, lc->slot + lc_hash_fn(lc, lc->new_number) );
	lc->changing_element = NULL;
	lc->new_number = -1;
	clear_bit(__LC_DIRTY,&lc->flags);
	smp_mb__after_clear_bit();
	PARANOIA_LEAVE();
}


unsigned int lc_put(struct lru_cache* lc, struct lc_element* e)
{
	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);
	BUG_ON(!e);

	PARANOIA_ENTRY();
	BUG_ON(e->refcnt == 0);
	if ( --e->refcnt == 0) {
		list_move(&e->list,&lc->lru); // move it to the front of LRU.
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
	list_move(&e->list, e->refcnt ? &lc->in_use : &lc->lru);
}

