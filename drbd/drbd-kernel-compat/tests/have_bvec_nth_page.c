/* { "version": "v5.1-rc1", "commit": "4d633062c1c0e8c5c7f6e43c12941095be1387bc", "comment": "bvec_nth_page was added in v5.1 and removed in v5.2 when bio_add_page gained a contiguous page struct check. Its presence indicates the kernel lacks that guarantee.", "author": "Ming Lei <ming.lei@redhat.com>", "date": "Wed Feb 27 20:40:10 2019 +0800" } */

#include <linux/bvec.h>

struct page *foo(struct page *page, int idx)
{
	return bvec_nth_page(page, idx);
}
