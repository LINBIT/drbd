// currently only abstraction layer to get all references to buffer_head
// and b_some_thing out of our .c files.

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

// b_end_io handlers
extern void drbd_md_io_complete     (struct buffer_head *bh, int uptodate);
extern void enslaved_read_bi_end_io (struct buffer_head *bh, int uptodate);
extern void drbd_dio_end_sec        (struct buffer_head *bh, int uptodate);
extern void drbd_dio_end            (struct buffer_head *bh, int uptodate);

/*
 * because in 2.6.x [sg]et_capacity operate on gendisk->capacity, which is in
 * units of 512 bytes sectors, these wrappers have a <<1 or >>1 where
 * appropriate.
 */

/* Returns the number of 512 byte sectors of the lower level device */
static inline unsigned long drbd_get_lo_capacity(drbd_dev *mdev)
{
	return mdev->lo_device
		? blk_size[MAJOR(mdev->lo_device)][MINOR(mdev->lo_device)]<<1
		: 0;
}

/* Returns the number of 512 byte sectors of our virtual device */
static inline unsigned long drbd_get_my_capacity(drbd_dev *mdev)
{
	return blk_size[MAJOR_NR][(int)(mdev - drbd_conf)]<<1;
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(drbd_dev *mdev, sector_t size)
{
	blk_size[MAJOR_NR][(int)(mdev - drbd_conf)] = (size>>1);
}

#warning "FIXME why don't we care for the return value?"
static inline void drbd_set_blocksize(drbd_dev *mdev, int blksize)
{
	set_blocksize(MKDEV(MAJOR_NR, (int)(mdev-drbd_conf)), blksize);
	set_blocksize(mdev->lo_device, blksize);
}

static inline int drbd_sync_me(drbd_dev *mdev)
{
	return fsync_dev(MKDEV(MAJOR_NR, (int)(mdev-drbd_conf)));
}

#define drbd_bio_uptodate(bio) buffer_uptodate(bio)

static inline void drbd_bio_IO_error(struct buffer_head *bh)
{
	buffer_IO_error(bh);
}

static inline void drbd_bio_endio(struct buffer_head *bh, int uptodate)
{
	bh->b_end_io(bh,uptodate);
}

static inline drbd_dev* drbd_req_get_mdev(struct drbd_request *req)
{
	return (drbd_dev*) req->private_bio.b_private;
}

static inline sector_t drbd_req_get_sector(struct drbd_request *req)
{
	return req->private_bio.b_blocknr;
}

static inline unsigned short drbd_req_get_size(struct drbd_request *req)
{
	return req->private_bio.b_size;
}

static inline sector_t drbd_ee_get_sector(struct Tl_epoch_entry *ee)
{
	return ee->private_bio.b_blocknr;
}

static inline unsigned short drbd_ee_get_size(struct Tl_epoch_entry *ee)
{
	return ee->private_bio.b_size;
}

static inline sector_t drbd_pr_get_sector(struct Pending_read *pr)
{
	return pr->d.master_bio->b_rsector;
}

static inline short drbd_bio_get_size(struct buffer_head *bh)
{
	return bh->b_size;
}

static inline char *drbd_bio_kmap(struct buffer_head *bh)
{
	return bh_kmap(bh);
}

static inline void drbd_bio_kunmap(struct buffer_head *bh)
{
	bh_kunmap(bh);
}

static inline void drbd_ee_init(struct Tl_epoch_entry *e,struct page *page)
{
	struct buffer_head * const bh = &e->private_bio;
	memset(e, 0, sizeof(*e));

	// bh->b_list   = BUF_LOCKED; // does it matter?
	bh->b_size      = PAGE_SIZE;
	bh->b_this_page = bh;
	bh->b_state     = (1 << BH_Mapped);
	init_waitqueue_head(&bh->b_wait);
	set_bh_page(bh,page,0);
	atomic_set(&bh->b_count, 1);

	e->block_id = ID_VACANT;
}

static inline void drbd_bio_set_pages_dirty(struct buffer_head *bh)
{
	set_bit(BH_Dirty, &bh->b_state);
}

static inline void drbd_bio_set_end_io(struct buffer_head *bh, bh_end_io_t * h)
{
	bh->b_end_io = h;
}

static inline void
drbd_ee_bh_prepare(drbd_dev *mdev, struct buffer_head *bh,
		   sector_t sector, int size)
{
	bh->b_blocknr  = sector;	// We abuse b_blocknr here.
	bh->b_size     = size;
	bh->b_rsector  = sector;
	bh->b_rdev     = mdev->lo_device;
	bh->b_private  = mdev;
	bh->b_state    = (1 << BH_Req)
			|(1 << BH_Launder)
			|(1 << BH_Lock);
}

static inline void
drbd_ee_prepare_write(drbd_dev *mdev, struct Tl_epoch_entry* e,
		      sector_t sector, int size)
{
	struct buffer_head * const bh = &e->private_bio;

	drbd_ee_bh_prepare(mdev,bh,sector,size);
	set_bit(BH_Uptodate,&bh->b_state);
	set_bit(BH_Dirty,&bh->b_state);
	bh->b_end_io   = drbd_dio_end_sec;
}

static inline void
drbd_ee_prepare_read(drbd_dev *mdev, struct Tl_epoch_entry* e,
		     sector_t sector, int size)
{
	struct buffer_head * const bh = &e->private_bio;

	drbd_ee_bh_prepare(mdev,bh,sector,size);
	bh->b_end_io   = enslaved_read_bi_end_io;
}

static inline void
drbd_bh_clone(struct buffer_head *bh, struct buffer_head *bh_src)
{
	memset(bh,0,sizeof(*bh));
	bh->b_list    = bh_src->b_list; // BUF_LOCKED;
	bh->b_size    = bh_src->b_size;
	bh->b_state   = bh_src->b_state & ((1 << BH_PrivateStart)-1);
	bh->b_page    = bh_src->b_page;
	bh->b_data    = bh_src->b_data;
	bh->b_rsector = bh_src->b_rsector;
	bh->b_blocknr = bh_src->b_rsector; // We abuse b_blocknr here.
	bh->b_dev     = bh_src->b_dev;     // hint for LVM as to
					   // which device to call fsync_dev
					   // on for snapshots
	atomic_set(&bh->b_count, 1);
	init_waitqueue_head(&bh->b_wait);
	// other members stay NULL
}

static inline void
drbd_req_prepare_write(drbd_dev *mdev, struct drbd_request *req)
{
	struct buffer_head * const bh     = &req->private_bio;
	struct buffer_head * const bh_src =  req->master_bio;

	drbd_bh_clone(bh,bh_src);
	bh->b_rdev    = mdev->lo_device;
	bh->b_private = mdev;
	bh->b_end_io  = drbd_dio_end;

	D_ASSERT(buffer_req(bh));
	D_ASSERT(buffer_launder(bh));
	D_ASSERT(buffer_locked(bh));
	D_ASSERT(buffer_mapped(bh));
	// D_ASSERT(buffer_dirty(bh)); // It is not true ?!?
	D_ASSERT(buffer_uptodate(bh));

	// FIXME should not be necessary
	bh->b_state = (1 << BH_Uptodate)
		     |(1 << BH_Dirty)
		     |(1 << BH_Lock)
		     |(1 << BH_Req)
		     |(1 << BH_Mapped) ;

	req->rq_status = RQ_DRBD_NOTHING;
}

#if 0
/* not yet used
 */
static inline void
drbd_req_prepare_read(drbd_dev *mdev, struct drbd_request *req)
{
	struct buffer_head * const bh     = &req->private_bio;
	struct buffer_head * const bh_src =  req->master_bio;

	drbd_bh_clone(bh,bh_src);
	bh->b_rdev    = mdev->lo_device;
	bh->b_private = mdev;
	bh->b_end_io  = drbd_read_end_io;

	D_ASSERT(buffer_req(bh));
	D_ASSERT(buffer_launder(bh));
	D_ASSERT(buffer_locked(bh));
	D_ASSERT(buffer_mapped(bh));
	D_ASSERT(!buffer_uptodate(bh));

	// FIXME should not be necessary
	bh->b_state = (1 << BH_Lock)
		     |(1 << BH_Req)
		     |(1 << BH_Mapped) ;

	req->rq_status = RQ_DRBD_NOTHING;
}
#endif

static inline struct page* drbd_bio_get_page(struct buffer_head *bh)
{
	return bh->b_page;
}

static inline void drbd_generic_make_request(int rw, struct buffer_head *bh)
{
	generic_make_request(rw, bh);
}

static inline void drbd_kick_lo(drbd_dev *mdev)
{
	run_task_queue(&tq_disk);
}

static inline int _drbd_send_zc_bio(drbd_dev *mdev, struct buffer_head *bh)
{
	struct page *page = bh->b_page;
	size_t size = bh->b_size;
	int offset;

	/*
	 * CAUTION I do not yet understand this completely.
	 * I thought I have to kmap the page first... ?
	 * hm. obviously the tcp stack kmaps internally somewhere.
	 */
	if (PageHighMem(page))
		offset = (int)bh->b_data;
	else
		offset = (int)bh->b_data - (int)page_address(page);

	return _drbd_send_page(mdev,page,offset,size);
}

#else
#warning "FIXME these are still untested!"

#include <linux/buffer_head.h> // for fsync_bdev

/* see get_sb_bdev and bd_claim */
extern char* drbd_sec_holder;

// bi_end_io handlers
// int (bio_end_io_t) (struct bio *, unsigned int, int);
extern int drbd_md_io_complete     (struct bio *bio, unsigned int bytes_done, int error);
extern int enslaved_read_bi_end_io (struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_dio_end_sec        (struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_dio_end            (struct bio *bio, unsigned int bytes_done, int error);

// we should not accept bios crossing our extent boundaries!
extern int drbd_merge_bvec_fn(request_queue_t *q, struct bio *bio, struct bio_vec *bv);

/* Returns the number of 512 byte sectors of the lower level device */
static inline unsigned long drbd_get_lo_capacity(drbd_dev *mdev)
{
	return mdev->backing_bdev ?
		get_capacity(mdev->backing_bdev->bd_disk) : 0;
}

/* Returns the number of 512 byte sectors of our virtual device */
static inline unsigned long drbd_get_my_capacity(drbd_dev *mdev)
{
	sector_t c = get_capacity(mdev->vdisk);
	D_ASSERT(c == mdev->la_size);
	return c;
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(drbd_dev *mdev, sector_t size)
{
	set_capacity(mdev->vdisk,size);
}

#warning "FIXME why don't we care for the return value?"
static inline void drbd_set_blocksize(drbd_dev *mdev, int blksize)
{
	set_blocksize(mdev->this_bdev,blksize);
	set_blocksize(mdev->backing_bdev,blksize);
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
	return (drbd_dev*) req->private_bio.bi_private;
}

static inline sector_t drbd_req_get_sector(struct drbd_request *req)
{
	return req->master_bio->bi_sector;
}

static inline unsigned short drbd_req_get_size(struct drbd_request *req)
{
	return req->master_bio->bi_size;
}

static inline sector_t drbd_ee_get_sector(struct Tl_epoch_entry *ee)
{
	return ee->ee_sector;
}

static inline unsigned short drbd_ee_get_size(struct Tl_epoch_entry *ee)
{
	return ee->ee_size;
}

static inline sector_t drbd_pr_get_sector(struct Pending_read *pr)
{
	return pr->d.master_bio->bi_sector;
}

/* this is valid, since the only place where it is used is in recv_both_read,
 * on the untouched master_bio of the Pending_read.
 * DO NOT use it for anything but an untouched bio,
 * bi_size is mutable, see bio_endio()
 */
static inline short drbd_bio_get_size(struct bio *bio)
{
	return bio->bi_size;
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
	struct bio_vec *bvec;
	unsigned long addr;

	bvec = bio_iovec_idx(bio, bio->bi_idx);

	addr = (unsigned long) kmap(bvec->bv_page);

	if (addr & ~PAGE_MASK)
		BUG();

	return (char *) addr + bvec->bv_offset;
}

static inline void drbd_bio_kunmap(struct bio *bio)
{
	struct bio_vec *bvec;

	bvec = bio_iovec_idx(bio, bio->bi_idx);
	kunmap(bvec->bv_page);
}

#else
static inline char *drbd_bio_kmap(struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec_idx(bio, bio->bi_idx);
	return page_address(bvec->bv_page) + bvec->bv_offset;
}
static inline void drbd_bio_kunmap(struct bio *bio)
{
	// do nothing.
}
#endif

static inline void drbd_ee_init(struct Tl_epoch_entry *e,struct page *page)
{
	struct bio * const bio = &e->private_bio;
	struct bio_vec * const vec = &e->ee_bvec;
	memset(e, 0, sizeof(*e));

	// bio_init(&bio); memset did it for us.
	bio->bi_io_vec = vec;
	vec->bv_page   = page;
	vec->bv_len    =
	bio->bi_size   = PAGE_SIZE;
	bio->bi_flags  = 1 << BIO_UPTODATE;
	bio->bi_max_vecs = 1;
	bio->bi_destructor = NULL;
	atomic_set(&bio->bi_cnt, 1);

	e->block_id = ID_VACANT;
}

static inline void drbd_bio_set_pages_dirty(struct bio *bio)
{
	bio_set_pages_dirty(bio);
}

static inline void drbd_bio_set_end_io(struct bio *bio, bio_end_io_t * h)
{
	bio->bi_end_io = h;
}

static inline void
drbd_ee_bio_prepare(drbd_dev *mdev, struct Tl_epoch_entry* e,
		    sector_t sector, int size)
{
	struct bio * const bio = &e->private_bio;
	bio->bi_io_vec->bv_len =
	bio->bi_size    = size;
	bio->bi_bdev    = mdev->backing_bdev;
	bio->bi_sector  = sector;
	bio->bi_private = mdev;
}

static inline void
drbd_ee_prepare_write(drbd_dev *mdev, struct Tl_epoch_entry* e,
		      sector_t sector, int size)
{
	drbd_ee_bio_prepare(mdev,e,sector,size);
	e->private_bio.bi_end_io = drbd_dio_end_sec;
}

static inline void
drbd_ee_prepare_read(drbd_dev *mdev, struct Tl_epoch_entry* e,
		     sector_t sector, int size)
{
	drbd_ee_bio_prepare(mdev,e,sector,size);
	e->private_bio.bi_end_io = enslaved_read_bi_end_io;
}

static inline void
drbd_req_prepare_write(drbd_dev *mdev, struct drbd_request *req)
{
	struct bio * const bio     = &req->private_bio;
	struct bio * const bio_src =  req->master_bio;

	__bio_clone(bio,bio_src);
	bio->bi_bdev    = mdev->backing_bdev;
	bio->bi_private = mdev;
	bio->bi_end_io  = drbd_dio_end;

	// FIXME D_ASSERT(??)
	// what else?

	req->rq_status = RQ_DRBD_NOTHING;
}

#if 0
static inline void
drbd_req_prepare_read(drbd_dev *mdev, struct drbd_request *req)
{
}
#endif

static inline struct page* drbd_bio_get_page(struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec_idx(bio, bio->bi_idx);
	return bvec->bv_page;
}

static inline void drbd_generic_make_request(int rw, struct bio *bio)
{
	bio->bi_rw = rw; //??
	generic_make_request(bio);
}

static inline void drbd_kick_lo(drbd_dev *mdev)
{
	blk_run_queue(bdev_get_queue(mdev->backing_bdev)); 
}

static inline int _drbd_send_zc_bio(drbd_dev *mdev, struct bio *bio)
{
	struct bio_vec *bvec = bio_iovec_idx(bio, bio->bi_idx);
	return _drbd_send_page(mdev,bvec->bv_page,bvec->bv_offset,bvec->bv_len);
}
#endif
