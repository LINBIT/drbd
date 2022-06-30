/* { "version": "v5.1-rc1", "commit": "70b44595eafe9c7c235f076d653a268ca1ab9fdb", "comment": "list_is_first() was moved to list.h", "author": "Mel Gorman <mgorman@techsingularity.net>", "date": "Tue Mar 5 15:44:54 2019 -0800" } */
#include <linux/list.h>

bool dummy(const struct list_head *list, const struct list_head *head)
{
	return list_is_first(list, head);
}
