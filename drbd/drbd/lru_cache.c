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

#include "lru_cache.h"
#include <linux/slab.h>

#define LC_FREE (-1)
#define STATIC static

/**
 * lc_init: Prepares a lru_cache. Important node: Before you may use it
 * you must also call lc_resize.
 * @mlc: The lru_cache object
 */
void lc_init(struct lru_cache * mlc)
{
	mlc->elements = 0;
	mlc->nr_elements = 0;
	mlc->element_size = sizeof(struct lc_element);
	mlc->lc_lock = SPIN_LOCK_UNLOCKED;
	mlc->may_evict = 0;
	init_waitqueue_head(&mlc->evict_wq);
}

/**
 * lc_resize: Sets the number of elements in of a lru_cache. It also 
 * clears the chache. You should set the element_size member before 
 * calling this function.
 * @mlc: The lru_cache object
 */
void lc_resize(struct lru_cache * mlc, int nr_elements)
{
	int i;
	void * elements;
	struct lc_element * element;

	if(mlc->nr_elements == nr_elements) return;

	elements = kmalloc(mlc->element_size * nr_elements,GFP_KERNEL);

	if(!elements) {
		printk(KERN_ERR"LC: can not kmalloc() cache's elements\n");
		return;
	}
	memset(elements,nr_elements,mlc->element_size);
	spin_lock(&mlc->lc_lock);
	INIT_LIST_HEAD(&mlc->lru);
	INIT_LIST_HEAD(&mlc->free);
	for(i=0;i<nr_elements;i++) {
		element = elements + i * mlc->element_size;
		element->lc_number = LC_FREE;
		// element->hash_next = NULL;
		list_add(&element->list,&mlc->free);
	}
	mlc->nr_elements=nr_elements;
	if(mlc->elements) kfree(mlc->elements);
	mlc->elements = elements;
	spin_unlock(&mlc->lc_lock);
}

/**
 * lc_free: Frees memory allocated by lc_resize.
 * @mlc: The lru_cache object
 */
void lc_free(struct lru_cache * mlc)
{
	if(mlc->elements) kfree(mlc->elements);
	mlc->elements = 0;
	mlc->nr_elements = 0;
}

static struct lc_element *lc_hash_fn(struct lru_cache * mlc, unsigned int enr)
{
	return LC_AT_INDEX(mlc, enr % mlc->nr_elements );
}


/* When you add an element (and most probabely remove an other element)
   to the hash table, you can at most modifiy 3 slots in the hash table!
   lc_add() can only change the element number in two slots,
   lc_evict() might change the element number in one slot. Gives 3. */
static void lc_mark_update(struct lru_cache * mlc, struct lc_element *slot)
{
	int i;

	for(i=0;i<3;i++) {
		if(mlc->updates[i] == -1) {
			mlc->updates[i] = LC_INDEX_OF(mlc,slot);
			break;
		}
	}
}

/**
 * lc_find: Returns the pointer to an element, if the element is present
 * in the hash table. In case it is not this function will return NULL.
 * @mlc: The lru_cache object
 * @enr: element number
 */
struct lc_element * lc_find(struct lru_cache * mlc, unsigned int enr)
{
	struct lc_element *element;

	element = lc_hash_fn(mlc, enr);
	while(element) {
		if(element->lc_number == enr) break;
		element = element->hash_next;
	}
	return element;
}

STATIC void lc_move_element(struct lru_cache * mlc,
			    struct lc_element *from, 
			    struct lc_element *to)
{
	struct list_head *le;

	memcpy(to,from,mlc->element_size);
	le = from->list.prev; // Fixing list list here!
	list_del(&from->list);
	list_add(&to->list,le);
}

STATIC struct lc_element * lc_evict(struct lru_cache * mlc)
{
	struct list_head *le;
	struct lc_element *element, *slot;

 retry:
	le=mlc->lru.prev;
	element=list_entry(le, struct lc_element,list);

	if( mlc->may_evict ) {
		if( ! mlc->may_evict(mlc,element) ) {
			printk(KERN_WARNING "LC: need to wait\n");
			spin_unlock(mlc->lc_lock); 
			//TODO use wait_event_lock here
			wait_event(mlc->evict_wq,mlc->may_evict(mlc,element));
			spin_lock(mlc->lc_lock);
			goto retry;
		}
	}

	list_del(le);

	slot = lc_hash_fn( mlc, element->lc_number);
	if( slot == element) {
		slot = element->hash_next;
		if( slot == NULL) return element;
		// move the next in hash table (=slot) to its slot (=element)
		lc_move_element(mlc,slot,element);
		lc_mark_update(mlc, element);

		return slot;
	}
	do {
		if( slot->hash_next == element ) {
			slot->hash_next = element->hash_next;
			return element;
		}
		slot=slot->hash_next;
	} while(1);
}

STATIC struct lc_element * lc_get(struct lru_cache * mlc,
				  unsigned long * evicted)
{
	struct list_head *le;
	struct lc_element *element;

	if(list_empty(&mlc->free)) {
		element=lc_evict(mlc);
		if(evicted) *evicted = element->lc_number;
		element->lc_number = LC_FREE;
		return element;
	}

	le=mlc->free.next;
	list_del(le);
	element=list_entry(le, struct lc_element,list);

	return element;
}

/**
 * lc_add: Adds an element to the lru cache. In case there are no
 * availabible slots in the cache, it will evict the least recently
 * used element from the cache.
 * 
 * This functions sets the update[3] pointers to the slots that 
 * were changed with this call.
 *
 * @mlc: The lru_cache object
 * @enr: element number
 * @evicted: If an element was removed from the cache, the index
 * of the removed elements is stored in this pointer.
 */
struct lc_element * lc_add(struct lru_cache * mlc, 
			   unsigned int enr,
			   unsigned long * evicted)
{
	struct lc_element *slot, *n, *a;

	slot = lc_hash_fn( mlc, enr );
	if (slot->lc_number == LC_FREE) {
		list_del(&slot->list);
		slot->hash_next = NULL;
		goto have_slot;
	}

	n = lc_get(mlc,evicted);

	if ( n == slot) {
		// we got the slot we wanted 
		goto have_slot;
	}

	a = lc_hash_fn( mlc, slot->lc_number );
	if( a != slot ) {
		// our element is a better fit for this slot
		lc_move_element(mlc,slot,n);
		lc_mark_update(mlc, n);
		// fix the hash_next pointer to the element in slot
		a = lc_hash_fn( mlc, n->lc_number );
		while(a->hash_next != slot) a=a->hash_next;
		a->hash_next = n;
		
		goto have_slot;
	}

	// chain our element behind this slot 
	n->hash_next = slot->hash_next;
	slot->hash_next = n;
	slot = n;

 have_slot:
	slot->lc_number = enr;
	lc_mark_update(mlc, slot);
	list_add(&slot->list,&mlc->lru);

	return slot;
}

/**
 * lc_set: Sets an element in the cache. You might use this function to
 * setup the cache. After doing so you should use the lc_fixup_hash_next
 * function to initalise the hash collision chains.
 * @mlc: The lru_cache object
 * @enr: element number
 * @index: The elements' position in the cache
 */
void lc_set(struct lru_cache * mlc, unsigned int enr, int index)
{
	struct lc_element *element;

	if(index < 0 || index >= mlc->nr_elements ) return;

	element = LC_AT_INDEX(mlc,index);
	spin_lock(&mlc->lc_lock);

	element->lc_number = enr;
	list_move(&element->list, &mlc->lru);
	element->hash_next = 0;

	spin_unlock(&mlc->lc_lock);
}

/**
 * lc_fixup_hash_next: Sets up the collision chains in the hash table. 
 * Returns the number of elements actually in the chache.
 * @mlc: The lru_cache object
 */
int lc_fixup_hash_next(struct lru_cache * mlc)
{
	struct lc_element *slot, *want;
	int i;
	int active_extents=0;

	spin_lock(&mlc->lc_lock);

	for( i=0 ; i < mlc->nr_elements ; i++ ) {
		slot = LC_AT_INDEX(mlc,i); 
		if(slot->lc_number == LC_FREE) continue;
		active_extents++;
		want = lc_hash_fn(mlc,slot->lc_number);
		if( slot != want ) {
			while (want->hash_next) want=want->hash_next;
			want->hash_next = slot;
		}
	}

	spin_unlock(&mlc->lc_lock);

	return active_extents;
}

