#ifndef DRBD_DAX_H
#define DRBD_DAX_H

#include <linux/kconfig.h>

#if IS_ENABLED(CONFIG_DEV_DAX_PMEM) && !defined(DAX_PMEM_IS_INCOMPLETE)

int drbd_dax_open(struct drbd_backing_dev *);
void drbd_dax_close(struct drbd_backing_dev *);
int drbd_dax_map(struct drbd_backing_dev *);

static inline bool drbd_md_dax_active(struct drbd_backing_dev *bdev)
{
	return bdev->dax_dev != NULL;
}
static inline struct meta_data_on_disk_9 *drbd_dax_md_addr(struct drbd_backing_dev *bdev)
{
	return bdev->md_on_pmem;
}
#else

#define drbd_dax_open(B) do { } while (0)
#define drbd_dax_close(B) do { } while (0)
#define drbd_dax_map(B) (-ENOTSUPP)
#define drbd_md_dax_active(B) (false)
#define drbd_dax_md_addr(B) (NULL)

#define arch_wb_cache_pmem(A, L) do { } while (0)

#endif /* IS_ENABLED(CONFIG_DEV_DAX_PMEM) */

#endif /* DRBD_DAX_H */
