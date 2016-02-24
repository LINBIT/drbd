#include <rdma/rdma_cm.h>

struct rdma_cm_id *foo(void)
{
	struct rdma_cm_id *id;
	id = rdma_create_id((struct net *)NULL,
			    (int (*)(struct rdma_cm_id *, struct rdma_cm_event *))NULL,
			    NULL, RDMA_PS_TCP, IB_QPT_RC);

	return id;
}
