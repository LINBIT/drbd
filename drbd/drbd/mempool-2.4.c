/*
 *  linux/mm/mempool.c
 *
 *  memory buffer pool support. Such pools are mostly used
 *  for guaranteed, deadlock-free memory allocations during
 *  extreme VM load.
 *
 *  started by Ingo Molnar, Copyright (C) 2001
 *  modified for inclusion with DRBD in 2003 by Philipp Reisner.
 */

#include <linux/compiler.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/module.h>
#include "mempool.h"

#ifndef BUG_ON
# define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)
#endif

/**
 * mempool_create - create a memory pool
 * @min_nr:    the minimum number of elements guaranteed to be
 *             allocated for this pool.
 * @alloc_fn:  user-defined element-allocation function.
 * @free_fn:   user-defined element-freeing function.
 * @pool_data: optional private data available to the user-defined functions.
 *
 * this function creates and allocates a guaranteed size, preallocated
 * memory pool. The pool can be used from the mempool_alloc and mempool_free
 * functions. This function might sleep. Both the alloc_fn() and the free_fn()
 * functions might sleep - as long as the mempool_alloc function is not called
 * from IRQ contexts.
 */
mempool_t * mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
				mempool_free_t *free_fn, void *pool_data)
{
	mempool_t *pool;
	int i;

	BUG_ON(!alloc_fn);
	BUG_ON(!free_fn);

	pool = kmalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return NULL;
	memset(pool, 0, sizeof(*pool));

	spin_lock_init(&pool->lock);
	pool->min_nr = min_nr;
	pool->pool_data = pool_data;
	INIT_LIST_HEAD(&pool->elements);
	init_waitqueue_head(&pool->wait);
	pool->alloc = alloc_fn;
	pool->free = free_fn;

	/*
	 * First pre-allocate the guaranteed number of buffers
	 * and nodes for them.
	 */
	for (i = 0; i < min_nr; i++) {
		void *element;
		mempool_node_t *node;

		node = kmalloc(sizeof(*node), GFP_KERNEL);
		element = NULL;
		if (node)
			element = pool->alloc(GFP_KERNEL, pool->pool_data);

		if (unlikely(!element)) {
			/*
			 * Not enough memory - free the allocated ones
			 * and return.  `node' may be NULL here.
			 */
			kfree(node);
			while (!list_empty(&pool->elements)) {
				node = list_entry(pool->elements.next,
						mempool_node_t, list);
				list_del(&node->list);
				pool->free(node->element, pool->pool_data);
				kfree(node);
			}
			kfree(pool);
			return NULL;
		}
		node->element = element;
		list_add(&node->list, &pool->elements);
		pool->curr_nr++;
	}
	return pool;
}

/**
 * mempool_resize - resize an existing memory pool
 * @pool:       pointer to the memory pool which was allocated via
 *              mempool_create().
 * @new_min_nr: the new minimum number of elements guaranteed to be
 *              allocated for this pool.
 * @gfp_mask:   the usual allocation bitmask.
 *
 * This function shrinks/grows the pool. In the case of growing,
 * it cannot be guaranteed that the pool will be grown to the new
 * size immediately, but new mempool_free() calls will refill it.
 *
 * Note, the caller must guarantee that no mempool_destroy is called
 * while this function is running. mempool_alloc() & mempool_free()
 * might be called (eg. from IRQ contexts) while this function executes.
 */
void mempool_resize(mempool_t *pool, int new_min_nr, int gfp_mask)
{
	int delta;
	unsigned long flags;

	if (new_min_nr <= 0)
		BUG();

	spin_lock_irqsave(&pool->lock, flags);
	if (new_min_nr < pool->min_nr) {
		pool->min_nr = new_min_nr;
		/*
		 * Free possible excess elements.
		 */
		while (pool->curr_nr > pool->min_nr) {
			mempool_node_t *node;

			if (list_empty(&pool->elements))
				BUG();
			node = list_entry(pool->elements.next,
					mempool_node_t, list);
			if (node->element == NULL)
				BUG();
			list_del(&node->list);
			pool->curr_nr--;
			spin_unlock_irqrestore(&pool->lock, flags);
			pool->free(node->element, pool->pool_data);
			kfree(node);
			spin_lock_irqsave(&pool->lock, flags);
		}
		spin_unlock_irqrestore(&pool->lock, flags);
		return;
	}
	delta = new_min_nr - pool->min_nr;
	pool->min_nr = new_min_nr;
	spin_unlock_irqrestore(&pool->lock, flags);

	/*
	 * We refill the pool up to the new treshold - but we dont
	 * (cannot) guarantee that the refill succeeds.
	 */
	while (delta) {
		mempool_node_t *node;

		node = kmalloc(sizeof(*node), gfp_mask);
		if (!node)
			break;
		node->element = pool->alloc(gfp_mask, pool->pool_data);
		if (!node->element) {
			kfree(node);
			break;
		}
		spin_lock_irqsave(&pool->lock, flags);
		list_add(&node->list, &pool->elements);
		pool->curr_nr++;
		spin_unlock_irqrestore(&pool->lock, flags);
		delta--;
	}
	wake_up(&pool->wait);
}

/**
 * mempool_destroy - deallocate a memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * this function only sleeps if the free_fn() function sleeps. The caller
 * has to guarantee that no mempool_alloc() nor mempool_free() happens in
 * this pool when calling this function.
 *
 * This function will go BUG() if there are outstanding elements in the
 * pool.  The mempool client must put them all back before destroying the
 * mempool.
 */
void mempool_destroy(mempool_t *pool)
{
	if (!pool)
		return;

	if (pool->curr_nr != pool->min_nr)
		printk(KERN_ERR "drbd: in %s(%p): curr_nr(%d) != min_nr(%d)\n",
		       __func__,pool,pool->curr_nr,pool->min_nr);
	while (!list_empty(&pool->elements)) {
		mempool_node_t *node;

		node = list_entry(pool->elements.prev,
				mempool_node_t, list);
		list_del(&node->list);
		if (node->element) {
			pool->curr_nr--;
			pool->free(node->element, pool->pool_data);
		}
		kfree(node);
	}
	if (pool->curr_nr)
		BUG();
	kfree(pool);
}

/**
 * mempool_alloc - allocate an element from a specific memory pool
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 * @gfp_mask:  the usual allocation bitmask.
 *
 * this function only sleeps if the alloc_fn function sleeps or
 * returns NULL. Note that due to preallocation, this function
 * *never* fails when called from process contexts. (it might
 * fail if called from an IRQ context.)
 */
void * mempool_alloc(mempool_t *pool, int gfp_mask)
{
	void *element;
	unsigned long flags;
	int curr_nr;
	DECLARE_WAITQUEUE(wait, current);
	int gfp_nowait = gfp_mask & ~(__GFP_WAIT | __GFP_IO);

repeat_alloc:
	element = pool->alloc(gfp_nowait, pool->pool_data);
	if (likely(element != NULL))
		return element;

	/*
	 * If the pool is less than 50% full then try harder
	 * to allocate an element:
	 */
	if ((gfp_mask != gfp_nowait) && (pool->curr_nr <= pool->min_nr/2)) {
		element = pool->alloc(gfp_mask, pool->pool_data);
		if (likely(element != NULL))
			return element;
	}

	/*
	 * Kick the VM at this point.
	 */
	// wakeup_bdflush();  -- Modules can not do this; PRE

	spin_lock_irqsave(&pool->lock, flags);
	if (likely(pool->curr_nr)) {
		mempool_node_t *node;

		node = list_entry(pool->elements.next,
				mempool_node_t, list);
		list_del(&node->list);
		element = node->element;
		if (element == NULL)
			BUG();
		node->element = NULL;
		list_add_tail(&node->list, &pool->elements);
		pool->curr_nr--;
		spin_unlock_irqrestore(&pool->lock, flags);
		return element;
	}
	spin_unlock_irqrestore(&pool->lock, flags);

	/* We must not sleep in the GFP_ATOMIC case */
	if (gfp_mask == gfp_nowait)
		return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	run_task_queue(&tq_disk);
#endif

	add_wait_queue_exclusive(&pool->wait, &wait);
	set_task_state(current, TASK_UNINTERRUPTIBLE);

	spin_lock_irqsave(&pool->lock, flags);
	curr_nr = pool->curr_nr;
	spin_unlock_irqrestore(&pool->lock, flags);

	if (!curr_nr)
		schedule();

	current->state = TASK_RUNNING;
	remove_wait_queue(&pool->wait, &wait);

	goto repeat_alloc;
}

/**
 * mempool_free - return an element to the pool.
 * @element:   pool element pointer.
 * @pool:      pointer to the memory pool which was allocated via
 *             mempool_create().
 *
 * this function only sleeps if the free_fn() function sleeps.
 */
void mempool_free(void *element, mempool_t *pool)
{
	unsigned long flags;

	if (pool->curr_nr < pool->min_nr) {
		spin_lock_irqsave(&pool->lock, flags);
		if (pool->curr_nr < pool->min_nr) {
			mempool_node_t *node;

			node = list_entry(pool->elements.prev,
					mempool_node_t, list);
			list_del(&node->list);
			if (node->element)
				BUG();
			node->element = element;
			list_add(&node->list, &pool->elements);
			pool->curr_nr++;
			spin_unlock_irqrestore(&pool->lock, flags);
			wake_up(&pool->wait);
			return;
		}
		spin_unlock_irqrestore(&pool->lock, flags);
	}
	pool->free(element, pool->pool_data);
}

/*
 * A commonly used alloc and free fn.
 */
void *mempool_alloc_slab(int gfp_mask, void *pool_data)
{
	kmem_cache_t *mem = (kmem_cache_t *) pool_data;
	return kmem_cache_alloc(mem, gfp_mask);
}

void mempool_free_slab(void *element, void *pool_data)
{
	kmem_cache_t *mem = (kmem_cache_t *) pool_data;
	kmem_cache_free(mem, element);
}
