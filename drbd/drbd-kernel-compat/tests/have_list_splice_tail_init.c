#include <linux/list.h>

void *p = list_splice_tail_init;

void bar(void)
{
	LIST_HEAD(list1);
	LIST_HEAD(list2);

	list_splice_tail_init(&list1, &list2);
}
