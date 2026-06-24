#include <rdma/ib_verbs.h>

void foo(void)
{
	ib_alloc_cq(NULL, NULL, 0, 0, 0);
}
