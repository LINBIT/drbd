#include <rdma/ib_verbs.h>

void foo(void)
{
	ib_alloc_cq_any(NULL, NULL, 0, 0);
}
