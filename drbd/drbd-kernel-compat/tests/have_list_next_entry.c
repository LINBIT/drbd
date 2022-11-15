#include <linux/list.h>

struct foo {
	struct list_head list;
};

void dummy(struct foo *f)
{
	list_next_entry(f, list);
}
