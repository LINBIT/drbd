#include <linux/err.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/rcupdate.h>

/* The idr_get_next() function exists since 2009-04-02 Linux-2.6.29 (commit 38460b48)
   but is exported for use in modules since 2010-01-29 Linux-2.6.35 (commit 4d1ee80f)  */
/* later fixes:
 * 93b7aca35dd7 2014-08-08 lib/idr.c: fix out-of-bounds pointer dereference
 * 326cf0f0f308 2013-02-27 idr: fix top layer handling
 * 6cdae7416a1c 2013-02-27 idr: fix a subtle bug in idr_get_next()
 * 9f7de8275b46 2012-03-21 idr: make idr_get_next() good for rcu_read_lock()
 */
#ifndef IDR_GET_NEXT_EXPORTED
#ifndef MAX_IDR_SHIFT
#define MAX_IDR_SHIFT MAX_ID_SHIFT
#endif

/* the maximum ID which can be allocated given idr->layers */
static int idr_max(int layers)
{
	int bits = min_t(int, layers * IDR_BITS, MAX_IDR_SHIFT);

	return (1 << bits) - 1;
}
/**
 * idr_get_next - lookup next object of id to given id.
 * @idp: idr handle
 * @nextidp:  pointer to lookup key
 *
 * Returns pointer to registered object with id, which is next number to
 * given id. After being looked up, *@nextidp will be updated for the next
 * iteration.
 *
 * This function can be called under rcu_read_lock(), given that the leaf
 * pointers lifetimes are correctly managed.
 */
void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_LEVEL + 1];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
	p = *paa = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;
	n = (p->layer + 1) * IDR_BITS;
	max = idr_max(p->layer + 1);

	while (id >= 0 && id <= max) {
		p = *paa;
		while (n > 0 && p) {
			n -= IDR_BITS;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
			*++paa = p;
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		/*
		 * Proceed to the next layer at the current level.  Unlike
		 * idr_for_each(), @id isn't guaranteed to be aligned to
		 * layer boundary at this point and adding 1 << n may
		 * incorrectly skip IDs.  Make sure we jump to the
		 * beginning of the next layer using round_up().
		 */
		id = round_up(id + 1, 1 << n);
		while (n < fls(id)) {
			n += IDR_BITS;
			--paa;
		}
	}
	return NULL;
}
#warning "using compat implementation of idr_get_next()"
#endif
