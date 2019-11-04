/* { "version": "v5.0", "commit": "3023a1e93656c02b8d6a3a46e712b815843fa514", "comment": "ib_device ops were moved to a separate struct", "author": "Kamal Heib <kamalheib1@gmail.com>", "date": "Mon Dec 10 21:09:48 2018 +0200" } */
#include <rdma/ib_verbs.h>

void *dummy(struct ib_device *device)
{
	return (void *) &device->ops;
}
