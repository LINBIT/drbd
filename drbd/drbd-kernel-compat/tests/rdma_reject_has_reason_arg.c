#include <rdma/rdma_cm.h>

void foo(void)
{
	rdma_reject(NULL, NULL, 0, 0);
}
