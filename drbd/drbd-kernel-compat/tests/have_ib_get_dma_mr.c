#include <rdma/ib_verbs.h>

struct ib_mr * foo(void)
{
	struct ib_pd *pd = NULL;
	struct ib_mr *mr;

	mr = ib_get_dma_mr(pd, 0);

	return mr;
}
