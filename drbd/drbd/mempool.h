/*
 * memory buffer pool support
 */
#ifndef _LINUX_MEMPOOL_H
#define _LINUX_MEMPOOL_H

#include <linux/list.h>
#include <linux/wait.h>

typedef void * (mempool_alloc_t)(int gfp_mask, void *pool_data);
typedef void (mempool_free_t)(void *element, void *pool_data);

/*
 * A structure for linking multiple client objects into
 * a mempool_t
 */
typedef struct mempool_node_s {
	struct list_head list;
	void *element;
} mempool_node_t;

/*
 * The elements list has full mempool_node_t's at ->next, and empty ones
 * at ->prev.  Emptiness is signified by mempool_node_t.element == NULL.
 *
 * curr_nr refers to how many full mempool_node_t's are at ->elements.
 * We don't track the total number of mempool_node_t's at ->elements;
 * it is always equal to min_nr.
 */
typedef struct mempool_s {
	spinlock_t lock;
	int min_nr, curr_nr;
	struct list_head elements;

	void *pool_data;
	mempool_alloc_t *alloc;
	mempool_free_t *free;
	wait_queue_head_t wait;
} mempool_t;
extern mempool_t * mempool_create(int min_nr, mempool_alloc_t *alloc_fn,
				 mempool_free_t *free_fn, void *pool_data);
extern void mempool_resize(mempool_t *pool, int new_min_nr, int gfp_mask);
extern void mempool_destroy(mempool_t *pool);
extern void * mempool_alloc(mempool_t *pool, int gfp_mask);
extern void mempool_free(void *element, mempool_t *pool);
extern void *mempool_alloc_slab(int gfp_mask, void *pool_data);
extern void mempool_free_slab(void *element, void *pool_data);

#endif /* _LINUX_MEMPOOL_H */
