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
#include <linux/slab.h>
#include "lru_cache.h"

#define STATIC static

// this is developers aid only!
#define PARANOIA_ENTRY() BUG_ON(test_and_set_bit(__LC_LOCKED,&lc->flags))
#define PARANOIA_LEAVE() do { clear_bit(__LC_LOCKED,&lc->flags); smp_mb__after_clear_bit(); } while (0)
#define RETURN(x...)     do { PARANOIA_LEAVE(); return x ; } while (0)

/**
 * lc_init: Prepares a lru_cache. Important node: Before you may use it
 * you must also call lc_resize.
 * @lc: The lru_cache object
 * @f:   callback function which is called when lc_get needs to change
 *       the set of elements in the cache
 */
void lc_init(struct lru_cache* lc, lc_notify_on_change_fn f,void* d)
{
	PARANOIA_ENTRY();
	lc->nr_elements      = 0;
	lc->element_size     = sizeof(struct lc_element);
	lc->notify_on_change = f;
	lc->lc_private       = d;
	lc->changing         = NULL;
	lc->slot             = NULL;
	RETURN();
}

/**
 * lc_resize: Sets the number of elements in of a lru_cache. It also 
 * clears the chache. You should set the element_size member before 
 * calling this function.
 * @lc: The lru_cache object
 */
#define lc_entry(lc,i) ((struct lc_element*)(((char*)&(lc)->slot[(lc)->nr_elements])+(i)*(lc)->element_size))
void lc_resize(struct lru_cache* lc, unsigned int nr_elements,spinlock_t *lck)
{
	unsigned int i;
	void *data;
	int  bytes;
	struct lc_element *e;
	unsigned long flags;

	PARANOIA_ENTRY(); //TODO.
	if(lc->nr_elements == nr_elements) RETURN();

	if (lc->nr_elements) RETURN();

	bytes = ( lc->element_size + sizeof(lc->slot[0]) ) * nr_elements;
	data = kmalloc(bytes,GFP_KERNEL);

	if(!data) {
		printk(KERN_ERR"LC: can not kmalloc() cache's elements\n");
		RETURN();
	}
	memset(data, 0, bytes);

	spin_lock_irqsave(lck,flags); // The uggly exception.

	if (lc->slot) kfree(lc->slot);
	lc->slot = data;
	lc->nr_elements = nr_elements;

	INIT_LIST_HEAD(&lc->lru);
	INIT_LIST_HEAD(&lc->free);
	for(i=0;i<nr_elements;i++) {
		INIT_HLIST_HEAD( lc->slot + i );
		e= lc_entry(lc,i);
		e->lc_number = LC_FREE;
		list_add(&e->list,&lc->free);
	}

	spin_lock_irqrestore(lck,flags);

	RETURN();
}

/**
 * lc_free: Frees memory allocated by lc_resize.
 * @lc: The lru_cache object
 */
void lc_free(struct lru_cache* lc)
{
	PARANOIA_ENTRY();
	if(lc->slot) kfree(lc->slot);
	lc->slot = 0;
	lc->nr_elements = 0;
	RETURN();
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

	e = NULL;
	hlist_for_each_entry(e, n, &lc->slot[lc_hash_fn(lc, enr)], colision) {
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

	if (e->refcnt) return NULL;

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

STATIC void lc_touch(struct lru_cache * lc,struct lc_element* e)
{
	// XXX paranoia: !list_empty(lru) && list_empty(free)
	list_move(&e->list,&lc->lru);
}

STATIC struct lc_element* lc_get_unused_element(struct lru_cache* lc)
{
	struct list_head *n;

	if (list_empty(&lc->free)) return lc_evict(lc);

	n=lc->free.next;
	list_del(n);
	return list_entry(n, struct lc_element,list);
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

	PARANOIA_ENTRY();
	if (lc->flags & LC_STARVING) RETURN(NULL);

	e = lc_find(lc, enr);
	if (e) {
		++e->refcnt;
		RETURN(e);
	}

	/* it was not present in the cache, find an unused element,
	 * which then is replaced.
	 * we need to update the cache; serialize on lc->flags & LC_DIRTY
	 */
	if (test_and_set_bit(__LC_DIRTY,&lc->flags)) RETURN(NULL);
	
	// no, it was not. get any slot from the free list.
	e = lc_get_unused_element(lc);

	if (!e) {
		lc->flags |= LC_STARVING; // now (DIRTY | STARVING) !
		RETURN(NULL);
	}

	sync = lc->notify_on_change ? lc->notify_on_change(lc,e,enr) : 1;

	hlist_add_head( &e->colision, lc->slot + lc_hash_fn(lc, enr) );

	if (sync) {
		// e->lc_number = enr; //Moved this into the callback - Phil
		BUG_ON(++e->refcnt != 1);
		BUG_ON(lc->flags & LC_DIRTY);
		// BUG_ON(lc->flags & LC_STARVING); // ?? - Phil
		RETURN(e);
	} else {
		lc->changing = e;
		RETURN(NULL);
	}
}

unsigned int lc_put(struct lru_cache* lc, struct lc_element* e)
{
	PARANOIA_ENTRY();
	BUG_ON(!e);
	BUG_ON(e->refcnt == 0);
	RETURN(--e->refcnt);
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

	if(index < 0 || index >= lc->nr_elements ) return;

	e = lc_entry(lc,index);

	e->lc_number = enr;
	__hlist_del(&e->colision);
	hlist_add_head(&e->colision, lc->slot + lc_hash_fn(lc,enr) );
	lc_touch(lc,e);
}

