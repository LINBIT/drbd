#include <linux/bio.h>

/*
 * upstream commit (included in 2.6.29)
 * commit bb799ca0202a360fa74d5f17039b9100caebdde7
 * Author: Jens Axboe <jens.axboe@oracle.com>
 * Date:   Wed Dec 10 15:35:05 2008 +0100
 *
 *     bio: allow individual slabs in the bio_set
 *
 * does
 * -struct bio_set *bioset_create(int bio_pool_size, int bvec_pool_size)
 * +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *
 * Note that up until 2.6.21 inclusive, it was
 * struct bio_set *bioset_create(int bio_pool_size, int bvec_pool_size, int scale)
 * so if we want to support old kernels (RHEL5), we will need an additional compat check.
 *
 * This also means that we must not use the front_pad trick as long as we want
 * to keep compatibility with < 2.6.29.
 */
extern struct bio_set *compat_check_bioset_create(unsigned int, unsigned int);

#ifndef __same_type
# define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif
void dummy(void)
{
	BUILD_BUG_ON(!__same_type(&compat_check_bioset_create, &bioset_create));
}
