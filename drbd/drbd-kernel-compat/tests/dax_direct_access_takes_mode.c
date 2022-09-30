/* { "version": "v5.18-rc5", "commit": "e511c4a3d2a1f64aafc1f5df37a2ffcf7ef91b55", "comment": "A new parameter, mode, was added to dax_direct_access", "author": "Jane Chu <jane.chu@oracle.com>", "date": "Fri May 13 15:10:58 2022 -0700" } */

#include <linux/dax.h>

long foo(struct dax_device *dax_dev, pgoff_t pgoff, long nr_pages,
		enum dax_access_mode mode, void **kaddr, pfn_t *pfn)
{
	return dax_direct_access(dax_dev, pgoff, nr_pages, mode, kaddr, pfn);
}
