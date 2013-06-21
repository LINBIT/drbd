#include <linux/kernel.h>
#include <linux/list.h>

struct s {
	struct hlist_node node;
};

int main(void)
{
	HLIST_HEAD(head);
	struct s *s;

	hlist_for_each_entry(s, &head, node) {
	}
	return 0;
}
