/*
   lru_cache.c

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

#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/string.h> /* for memset */
#include <linux/seq_file.h> /* for seq_printf */
#include <linux/lru_cache.h>

/* this is developers aid only! */
#define PARANOIA_ENTRY() BUG_ON(test_and_set_bit(__LC_PARANOIA, &lc->flags))
#define PARANOIA_LEAVE() do { clear_bit(__LC_PARANOIA, &lc->flags); smp_mb__after_clear_bit(); } while (0)
#define RETURN(x...)     do { PARANOIA_LEAVE(); return x ; } while (0)

static size_t size_of_lc(unsigned int e_count, size_t e_size)
{
	return sizeof(struct lru_cache)
	     + e_count * (e_size + sizeof(struct hlist_head));
}

static void lc_init(struct lru_cache *lc,
		const size_t bytes, const char *name,
		const unsigned int e_count, const size_t e_size,
		const size_t e_off)
{
	struct lc_element *e;
	unsigned int i;

	memset(lc, 0, bytes);
	INIT_LIST_HEAD(&lc->in_use);
	INIT_LIST_HEAD(&lc->lru);
	INIT_LIST_HEAD(&lc->free);
	lc->element_size = e_size;
	lc->element_off  = e_off;
	lc->nr_elements  = e_count;
	lc->new_number	 = -1;
	lc->name         = name;
	for (i = 0; i < e_count; i++) {
		e = lc_element_by_index(lc, i);
		e->lc_number = LC_FREE;
		list_add(&e->list, &lc->free);
		/* memset(,0,) did the rest of init for us */
	}
}

/**
 * lc_create - prepares to track objects in an active set
 * @name: descriptive name only used in lc_seq_printf_stats and lc_seq_dump
 * @e_count: number of elements allowed to be active simultaneously
 * @e_size: size of the tracked objects
 * @e_off: offset to the &struct lc_element member in a tracked object
 *
 * Returns a pointer to a newly initialized struct lru_cache on success,
 * or NULL on (allocation) failure.
 */
struct lru_cache *lc_create(const char *name, unsigned int e_count,
			   size_t e_size, size_t e_off)
{
	struct lru_cache   *lc;
	size_t bytes;

	BUG_ON(!e_count);
	BUG_ON(e_size < sizeof(struct lc_element));
	BUG_ON(e_size - sizeof(struct lc_element) < e_off);
	e_size = ALIGN(e_size, sizeof(void *));
	e_size = max(sizeof(struct lc_element), e_size);
	bytes = size_of_lc(e_count, e_size);
	lc = kmalloc(bytes, GFP_KERNEL);
	if (lc)
		lc_init(lc, bytes, name, e_count, e_size, e_off);
	return lc;
}

/**
 * lc_destroy - frees memory allocated by lc_create()
 * @lc: the lru cache to operate on
 */
void lc_destroy(struct lru_cache *lc)
{
	kfree(lc);
}

/**
 * lc_reset - does a full reset for @lc and the hash table slots.
 * @lc: the lru cache to operate on
 *
 * It is roughly the equivalent of re-allocating a fresh lru_cache object,
 * basically a short cut to lc_destroy(lc); lc = lc_create(...);
 */
void lc_reset(struct lru_cache *lc)
{
	lc_init(lc, size_of_lc(lc->nr_elements, lc->element_size), lc->name,
			lc->nr_elements, lc->element_size, lc->element_off);
}

/**
 * lc_seq_printf_stats - print stats about @ts into @seq
 * @seq: the seq_file to print into
 * @ts: the tracked set to print statistics of
 */
size_t lc_seq_printf_stats(struct seq_file *seq, struct lru_cache *lc)
{
	/* NOTE:
	 * total calls to lc_get are
	 * (starving + hits + misses)
	 * misses include "dirty" count (update from an other thread in
	 * progress) and "changed", when this in fact lead to an successful
	 * update of the cache.
	 */
	return seq_printf(seq, "\t%s: used:%u/%u "
		"hits:%lu misses:%lu starving:%lu dirty:%lu changed:%lu\n",
		lc->name, lc->used, lc->nr_elements,
		lc->hits, lc->misses, lc->starving, lc->dirty, lc->changed);
}

static unsigned int lc_hash_fn(struct lru_cache *lc, unsigned int enr)
{
	return enr % lc->nr_elements;
}


/**
 * lc_find - find element by label, if present in the hash table
 * @lc: The lru_cache object
 * @enr: element number
 *
 * Returns the pointer to an element, if the element with the requested
 * "label" or element number is present in the hash table,
 * or NULL if not found. Does not change the refcnt.
 */
struct lc_element *lc_find(struct lru_cache *lc, unsigned int enr)
{
	struct hlist_node *n;
	struct lc_element *e;

	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);
	hlist_for_each_entry(e, n, lc->slot + lc_hash_fn(lc, enr), colision) {
		if (e->lc_number == enr)
			return e;
	}
	return NULL;
}

/* returned element will be "recycled" immediately */
static struct lc_element *lc_evict(struct lru_cache *lc)
{
	struct list_head  *n;
	struct lc_element *e;

	if (list_empty(&lc->lru))
		return NULL;

	n = lc->lru.prev;
	e = list_entry(n, struct lc_element, list);

	list_del(&e->list);
	hlist_del(&e->colision);
	return e;
}

/**
 * lc_del - removes an element from the cache
 * @lc: The lru_cache object
 * @e: The element to remove
 *
 * @e must be unused (refcnt == 0). Moves @e from "lru" to "free" list,
 * sets @e->enr to %LC_FREE.
 */
void lc_del(struct lru_cache *lc, struct lc_element *e)
{
	PARANOIA_ENTRY();
	BUG_ON(e < lc_element_by_index(lc, 0));
	BUG_ON(e > lc_element_by_index(lc, lc->nr_elements-1));
	BUG_ON(e->refcnt);
	list_del(&e->list);
	hlist_del_init(&e->colision);
	e->lc_number = LC_FREE;
	e->refcnt = 0;
	list_add(&e->list, &lc->free);
	RETURN();
}

static struct lc_element *lc_get_unused_element(struct lru_cache *lc)
{
	struct list_head *n;

	if (list_empty(&lc->free))
		return lc_evict(lc);

	n = lc->free.next;
	list_del(n);
	return list_entry(n, struct lc_element, list);
}

static int lc_unused_element_available(struct lru_cache *lc)
{
	if (!list_empty(&lc->free))
		return 1; /* something on the free list */
	if (!list_empty(&lc->lru))
		return 1;  /* something to evict */

	return 0;
}


/**
 * lc_get - get element by label, maybe change the active set
 * @lc: the lru cache to operate on
 * @enr: the label to look up
 *
 * Finds an element in the cache, increases its usage count,
 * "touches" and returns it.
 *
 * In case the requested number is not present, it needs to be added to the
 * cache. Therefore it is possible that an other element becomes eviced from
 * the cache. In either case, the user is notified so he is able to e.g. keep
 * a persistent log of the cache changes, and therefore the objects in use.
 *
 * Return values:
 *  NULL
 *     The cache was marked %TS_STARVING,
 *     or the requested label was not in the active set
 *     and a changing transaction is still pending (@lc was marked %LC_DIRTY).
 *     Or no unused or free element could be recycled (@ts will be marked as
 *     %TS_STARVING, blocking further ts_get() operations).
 *
 *  pointer to the element with the REQUESTED element number.
 *     In this case, it can be used right away
 *
 *  pointer to an UNUSED element with some different element number,
 *          where that different number may also be %LC_FREE.
 *
 *          In this case, the cache is marked %LC_DIRTY (blocking further changes),
 *          and the returned element pointer is removed from the lru list and
 *          hash collision chains.  The user now should do whatever houskeeping
 *          is necessary.
 *          Then he must call lc_changed(lc,element_pointer), to finish
 *          the change.
 *
 * NOTE: The user needs to check the lc_number on EACH use, so he recognizes
 *       any cache set change.
 */
struct lc_element *lc_get(struct lru_cache *lc, unsigned int enr)
{
	struct lc_element *e;

	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);

	PARANOIA_ENTRY();
	if (lc->flags & LC_STARVING) {
		++lc->starving;
		RETURN(NULL);
	}

	e = lc_find(lc, enr);
	if (e) {
		++lc->hits;
		if (e->refcnt++ == 0)
			lc->used++;
		list_move(&e->list, &lc->in_use); /* Not evictable... */
		RETURN(e);
	}

	++lc->misses;

	/* In case there is nothing available and we can not kick out
	 * the LRU element, we have to wait ...
	 */
	if (!lc_unused_element_available(lc)) {
		__set_bit(__LC_STARVING, &lc->flags);
		RETURN(NULL);
	}

	/* it was not present in the active set.
	 * we are going to recycle an unused (or even "free") element.
	 * user may need to commit a transaction to record that change.
	 * we serialize on flags & TF_DIRTY */
	if (test_and_set_bit(__LC_DIRTY, &lc->flags)) {
		++lc->dirty;
		RETURN(NULL);
	}

	e = lc_get_unused_element(lc);
	BUG_ON(!e);

	clear_bit(__LC_STARVING, &lc->flags);
	BUG_ON(++e->refcnt != 1);
	lc->used++;

	lc->changing_element = e;
	lc->new_number = enr;

	RETURN(e);
}

/* similar to lc_get,
 * but only gets a new reference on an existing element.
 * you either get the requested element, or NULL.
 * will be consolidated into one function.
 */
struct lc_element *lc_try_get(struct lru_cache *lc, unsigned int enr)
{
	struct lc_element *e;

	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);

	PARANOIA_ENTRY();
	if (lc->flags & LC_STARVING) {
		++lc->starving;
		RETURN(NULL);
	}

	e = lc_find(lc, enr);
	if (e) {
		++lc->hits;
		if (e->refcnt++ == 0)
			lc->used++;
		list_move(&e->list, &lc->in_use); /* Not evictable... */
	}
	RETURN(e);
}

/**
 * lc_changed - tell @lc that the change has been recorded
 * @lc: the lru cache to operate on
 * @e: the element pending label change
 */
void lc_changed(struct lru_cache *lc, struct lc_element *e)
{
	PARANOIA_ENTRY();
	BUG_ON(e != lc->changing_element);
	++lc->changed;
	e->lc_number = lc->new_number;
	list_add(&e->list, &lc->in_use);
	hlist_add_head(&e->colision,
		lc->slot + lc_hash_fn(lc, lc->new_number));
	lc->changing_element = NULL;
	lc->new_number = -1;
	clear_bit(__LC_DIRTY, &lc->flags);
	smp_mb__after_clear_bit();
	RETURN();
}


/**
 * lc_put - give up refcnt of @e
 * @lc: the lru cache to operate on
 * @e: the element to put
 *
 * If refcnt reaches zero, the element is moved to the lru list,
 * and a %TS_STARVING (if set) is cleared.
 * Returns the new (post-decrement) refcnt.
 */
unsigned int lc_put(struct lru_cache *lc, struct lc_element *e)
{
	BUG_ON(!lc);
	BUG_ON(!lc->nr_elements);
	BUG_ON(!e);

	PARANOIA_ENTRY();
	BUG_ON(e->refcnt == 0);
	BUG_ON(e == lc->changing_element);
	if (--e->refcnt == 0) {
		/* move it to the front of LRU. */
		list_move(&e->list, &lc->lru);
		lc->used--;
		clear_bit(__LC_STARVING, &lc->flags);
		smp_mb__after_clear_bit();
	}
	RETURN(e->refcnt);
}


/**
 * lc_set - associate index with label
 * @lc: the lru cache to operate on
 * @enr: the label to set
 * @index: the element index to associate label with.
 *
 * Used to initialize the active set to some previously recorded state.
 */
void lc_set(struct lru_cache *lc, unsigned int enr, int index)
{
	struct lc_element *e;

	if (index < 0 || index >= lc->nr_elements)
		return;

	e = lc_element_by_index(lc, index);
	e->lc_number = enr;

	hlist_del_init(&e->colision);
	hlist_add_head(&e->colision, lc->slot + lc_hash_fn(lc, enr));
	list_move(&e->list, e->refcnt ? &lc->in_use : &lc->lru);
}

/**
 * lc_dump - Dump a complete LRU cache to seq in textual form.
 * @lc: the lru cache to operate on
 * @seq: the &struct seq_file pointer to seq_printf into
 * @utext: user supplied "heading" or other info
 * @detail: function pointer the user may provide to dump further details
 * of the object the lc_element is embeded in.
 */
void lc_seq_dump_details(struct seq_file *seq, struct lru_cache *lc, char *utext,
	     void (*detail) (struct seq_file *, struct lc_element *))
{
	unsigned int nr_elements = lc->nr_elements;
	struct lc_element *e;
	int i;

	seq_printf(seq, "\tnn: lc_number refcnt %s\n ", utext);
	for (i = 0; i < nr_elements; i++) {
		e = lc_element_by_index(lc, i);
		if (e->lc_number == LC_FREE) {
			seq_printf(seq, "\t%2d: FREE\n", i);
		} else {
			seq_printf(seq, "\t%2d: %4u %4u    ", i,
				   e->lc_number,
				   e->refcnt);
			detail(seq, e);
		}
	}
}

EXPORT_SYMBOL(lc_create);
EXPORT_SYMBOL(lc_reset);
EXPORT_SYMBOL(lc_destroy);
EXPORT_SYMBOL(lc_set);
EXPORT_SYMBOL(lc_del);
EXPORT_SYMBOL(lc_try_get);
EXPORT_SYMBOL(lc_find);
EXPORT_SYMBOL(lc_get);
EXPORT_SYMBOL(lc_put);
EXPORT_SYMBOL(lc_changed);
EXPORT_SYMBOL(lc_seq_printf_stats);
EXPORT_SYMBOL(lc_seq_dump_details);
