/*
 * FIXME this file is bound to die, renamed or included in drbd_int.h
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
# error "use a 2.6 kernel, please"
#endif

#include <linux/buffer_head.h> // for fsync_bdev

/* see get_sb_bdev and bd_claim */
extern char* drbd_sec_holder;

// bi_end_io handlers
// int (bio_end_io_t) (struct bio *, unsigned int, int);
extern int drbd_md_io_complete (struct bio *bio, unsigned int bytes_done, int error);

extern int drbd_endio_read_sec (struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_endio_write_sec(struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_endio_read_pri (struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_endio_write_pri(struct bio *bio, unsigned int bytes_done, int error);

static inline sector_t drbd_get_hardsect(struct block_device *bdev)
{
	return bdev->bd_disk->queue->hardsect_size;
}

/* Returns the number of 512 byte sectors of the device */
static inline sector_t drbd_get_capacity(struct block_device *bdev)
{
	loff_t capacity = bdev ? bdev->bd_inode->i_size >> 9 : 0;
	if ((sector_t)capacity != capacity)
		printk(KERN_ERR "drbd: overflow in drbd_get_capacity\n");
	return (sector_t)capacity;
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(drbd_dev *mdev, sector_t size)
{
	set_capacity(mdev->vdisk,size);
	mdev->this_bdev->bd_inode->i_size = (loff_t)size << 9;
}

//#warning "FIXME why don't we care for the return value?"
static inline void drbd_set_blocksize(drbd_dev *mdev, int blksize)
{
	set_blocksize(mdev->this_bdev,blksize);
	if (mdev->backing_bdev) {
		set_blocksize(mdev->backing_bdev, blksize);
	} else {
		D_ASSERT(mdev->backing_bdev);
		// FIXME send some package over to the peer?
	}
}

static inline int drbd_sync_me(drbd_dev *mdev)
{
	return fsync_bdev(mdev->this_bdev);
}

#define drbd_bio_uptodate(bio) bio_flagged(bio,BIO_UPTODATE)

static inline void drbd_bio_IO_error(struct bio *bio)
{
	bio_endio(bio,bio->bi_size,-EIO);
}

static inline void drbd_bio_endio(struct bio *bio, int uptodate)
{
	bio_endio(bio,bio->bi_size,uptodate ? 0 : -EIO);
}

static inline drbd_dev* drbd_req_get_mdev(struct drbd_request *req)
{
	return (drbd_dev*) req->mdev;
}

static inline sector_t drbd_req_get_sector(struct drbd_request *req)
{
	return req->master_bio->bi_sector;
}

static inline unsigned short drbd_req_get_size(struct drbd_request *req)
{
	drbd_dev* mdev = req->mdev;
	D_ASSERT(req->master_bio->bi_size);
	return req->master_bio->bi_size;
}

static inline struct bio* drbd_req_private_bio(struct drbd_request *req)
{
	return req->private_bio;
}

static inline sector_t drbd_ee_get_sector(struct Tl_epoch_entry *ee)
{
	return ee->ee_sector;
}

static inline unsigned short drbd_ee_get_size(struct Tl_epoch_entry *ee)
{
	return ee->ee_size;
}

#ifdef CONFIG_HIGHMEM
/*
 * I don't know why there is no bvec_kmap, only bvec_kmap_irq ...
 *
 * we do a sock_recvmsg into the target buffer,
 * so we obviously cannot use the bvec_kmap_irq variant.	-lge
 *
 * Most likely it is only due to performance anyways:
  * kmap_atomic/kunmap_atomic is significantly faster than kmap/kunmap because
  * no global lock is needed and because the kmap code must perform a global TLB
  * invalidation when the kmap pool wraps.
  *
  * However when holding an atomic kmap is is not legal to sleep, so atomic
  * kmaps are appropriate for short, tight code paths only.
 */
static inline char *drbd_bio_kmap(struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec(bio);
	unsigned long addr;

	addr = (unsigned long) kmap(bvec->bv_page);

	if (addr & ~PAGE_MASK)
		BUG();

	return (char *) addr + bvec->bv_offset;
}

static inline void drbd_bio_kunmap(struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec(bio);

	kunmap(bvec->bv_page);
}

#else
static inline char *drbd_bio_kmap(struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec(bio);
	return page_address(bvec->bv_page) + bvec->bv_offset;
}
static inline void drbd_bio_kunmap(struct bio *bio)
{
	// do nothing.
}
#endif

static inline void
drbd_ee_prepare_write(drbd_dev *mdev, struct Tl_epoch_entry* e)
{
	e->private_bio->bi_end_io = drbd_endio_write_sec;
}

static inline void
drbd_ee_prepare_read(drbd_dev *mdev, struct Tl_epoch_entry* e)
{
	e->private_bio->bi_end_io = drbd_endio_read_sec;
}

static inline int drbd_bio_has_active_page(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	__bio_for_each_segment(bvec, bio, i, 0) {
		if (page_count(bvec->bv_page) > 1) return 1;
	}

	return 0;
}

/*
 * used to submit our private bio
 */
static inline void drbd_generic_make_request(int rw, struct bio *bio)
{
	drbd_dev *mdev = drbd_conf -1; // for DRBD_ratelimit
	bio->bi_rw = rw; // on the receiver side, e->..rw was not yet defined.

	if (!bio->bi_bdev) {
		if (DRBD_ratelimit(5*HZ,5)) {
			printk(KERN_ERR "drbd_generic_make_request: bio->bi_bdev == NULL\n");
			dump_stack();
		}
		drbd_bio_IO_error(bio);
		return;
	}

	generic_make_request(bio);
}

static inline void drbd_blk_run_queue(request_queue_t *q)
{
	if (q && q->unplug_fn)
		q->unplug_fn(q);
}

static inline void drbd_kick_lo(drbd_dev *mdev)
{
	if (!mdev->backing_bdev) {
		if (DRBD_ratelimit(5*HZ,5)) {
			ERR("backing_bdev==NULL in drbd_kick_lo\n");
			dump_stack();
		}
	} else {
		drbd_blk_run_queue(bdev_get_queue(mdev->backing_bdev));
	}
}

static inline void drbd_plug_device(drbd_dev *mdev)
{
	request_queue_t *q = bdev_get_queue(mdev->this_bdev);

	spin_lock_irq(q->queue_lock);

/* XXX the check on !blk_queue_plugged is redundant,
 * implicitly checked in blk_plug_device */

	if(!blk_queue_plugged(q)) {
		blk_plug_device(q);
		del_timer(&q->unplug_timer);
		// unplugging should not happen automatically...
	}
	spin_unlock_irq(q->queue_lock);
}

static inline int _drbd_send_bio(drbd_dev *mdev, struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec(bio);
	struct page *page = bvec->bv_page;
	size_t size = bvec->bv_len;
	int offset = bvec->bv_offset;
	int ret;

	ret = drbd_send(mdev, mdev->data.socket, kmap(page) + offset, size, 0);
	kunmap(page);
	return ret;
}
