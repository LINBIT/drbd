#include <rdma/ib_verbs.h>

void foo(void)
{
	ib_alloc_pd(NULL, 0);
}
