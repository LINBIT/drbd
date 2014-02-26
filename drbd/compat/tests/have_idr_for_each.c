#include <linux/spinlock.h>
#include <linux/idr.h>

static int idr_has_entry(int id, void *p, void *data)
{
	return 1;
}

bool idr_is_empty(struct idr *idr)
{
	return !idr_for_each(idr, idr_has_entry, NULL);
}
