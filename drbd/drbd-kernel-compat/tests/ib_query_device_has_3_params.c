#include <rdma/ib_verbs.h>

void foo(void)
{
	struct ib_device_attr attr;
	struct ib_udata uhw = {.outlen = 0, .inlen = 0};
	struct ib_device *device = NULL;

	device->query_device(device, &attr, &uhw);
}
