#include <linux/kernel.h>
#include <linux/list.h>

struct element {
	struct hlist_node colision;
	int x;
};

/*
 * Befor linux-3.9 it was hlist_for_each_entry(tpos, pos, head, member)
 * now it is hlist_for_each_entry(pos, head, member)
 */
void dummy(void)
{
	struct element *e;
	struct hlist_head head;

	INIT_HLIST_HEAD(&head);

	hlist_for_each_entry(e, &head, colision)
		;
}
