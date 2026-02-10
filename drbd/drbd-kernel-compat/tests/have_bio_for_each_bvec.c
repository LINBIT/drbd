/* { "version": "v5.1-rc1", "commit": "3d75ca0adef4fa27e6e4e47e713e3aaf53447894", "comment": "bio_for_each_bvec was added for iterating over multi-page bvecs", "author": "Ming Lei <ming.lei@redhat.com>", "date": "Tue Feb 26 10:38:41 2019 +0800" } */

#include <linux/bio.h>

void foo(struct bio *bio)
{
	struct bio_vec bvec;
	struct bvec_iter iter;

	bio_for_each_bvec(bvec, bio, iter);
}
