/* Upstream commit
   33023fb85a42b53bf778bc025f9667b582282be4

   introduced max_send_sge and max_recv_sge and removed max_sge

   The first kernel with the split sge member is 4.18
 */

#include <rdma/ib_verbs.h>

void foo(struct ib_device_attr *dev_attr)
{
	dev_attr->max_send_sge = 1;
	dev_attr->max_recv_sge = 1;
}
