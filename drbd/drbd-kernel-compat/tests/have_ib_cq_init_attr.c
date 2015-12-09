#include <rdma/ib_verbs.h>

void foo(void)
{
	struct ib_cq_init_attr cq_attr = {};

	ib_create_cq(NULL, NULL, NULL, NULL, &cq_attr);
}
