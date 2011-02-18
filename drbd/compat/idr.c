#include <linux/err.h>
#include <linux/string.h>
#include <linux/idr.h>

/* The idr_get_next() function exists since 2009-04-02 Linux-2.6.29 (commit 38460b48)
   but is exported for use in modules since 2010-01-29 Linux-2.6.35 (commit 4d1ee80f)  */
#ifndef IDR_GET_NEXT_EXPORTED
#ifndef rcu_dereference_raw
/* see c26d34a rcu: Add lockdep-enabled variants of rcu_dereference() */
#define rcu_dereference_raw(p) rcu_dereference(p)
#endif
void *idr_get_next(struct idr *idp, int *nextidp)
{
	struct idr_layer *p, *pa[MAX_LEVEL];
	struct idr_layer **paa = &pa[0];
	int id = *nextidp;
	int n, max;

	/* find first ent */
	n = idp->layers * IDR_BITS;
	max = 1 << n;
	p = rcu_dereference_raw(idp->top);
	if (!p)
		return NULL;

	while (id < max) {
		while (n > 0 && p) {
			n -= IDR_BITS;
			*paa++ = p;
			p = rcu_dereference_raw(p->ary[(id >> n) & IDR_MASK]);
		}

		if (p) {
			*nextidp = id;
			return p;
		}

		id += 1 << n;
		while (n < fls(id)) {
			n += IDR_BITS;
			p = *--paa;
		}
	}
	return NULL;
}
#endif
