// currently only abstraction layer to get all references to buffer_head
// and b_some_thing out of our .c files.

// FIXME
// some of these should not be "extern inline" but defined in kernel version
// dependend .c files...

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

// b_end_io handlers
extern void drbd_generic_end_io     (struct buffer_head *bh, int uptodate);
extern void drbd_async_eio          (struct buffer_head *bh, int uptodate);
extern void enslaved_read_bi_end_io (struct buffer_head *bh, int uptodate);
extern void drbd_dio_end_sec        (struct buffer_head *bh, int uptodate);
extern void drbd_dio_end            (struct buffer_head *bh, int uptodate);

/*
 * becase in 2.6.x [sg]et_capacity operate on gendisk->capacity, which is in
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

/* Returns the start sector for metadata, aligned to 4K */
static inline sector_t drbd_md_ss(drbd_dev *mdev)
{
	if( mdev->md_index == -1 ) {
		return (  (drbd_get_lo_capacity(mdev) & ~7L)
			- (MD_RESERVED_SIZE<<1) );
	} else {
		return 2 * MD_RESERVED_SIZE * mdev->md_index;
	}
}

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
	// drbd_conf + MINOR(req->master_bio->b_rdev);
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

static inline void drbd_init_bio(struct buffer_head *bh, int size)
{
	memset(bh, 0, sizeof(struct buffer_head));

	bh->b_list = BUF_LOCKED;
	init_waitqueue_head(&bh->b_wait);
	bh->b_size = size;
	atomic_set(&bh->b_count, 1);
	bh->b_state = (1 << BH_Mapped);	//has a disk mapping = dev & blocknr
}

static inline void drbd_bio_set_pages_dirty(struct buffer_head *bh)
{
	set_bit(BH_Dirty, &bh->b_state);
}

static inline void drbd_bio_set_end_io(struct buffer_head *bh, bh_end_io_t * h)
{
	bh->b_end_io = h;
}

static inline void drbd_md_prepare_write(drbd_dev *mdev, sector_t sector)
{
	struct buffer_head * const bh = &mdev->md_io_bio;

	bh->b_blocknr = sector;	// We abuse b_blocknr here.
	bh->b_size    = 512;
	bh->b_private = mdev;
	bh->b_rdev    = mdev->md_device;
	bh->b_rsector = sector;

	// we skip submit_bh, but use generic_make_request.
	// ?? set_bit(BH_Uptodate, &bh->b_state);
	set_bit(BH_Req, &bh->b_state);
	set_bit(BH_Launder, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state);

	drbd_bio_set_pages_dirty(bh);
	drbd_bio_set_end_io(&mdev->md_io_bio,drbd_generic_end_io);
}

static inline void drbd_md_prepare_read(drbd_dev *mdev, sector_t sector)
{
	struct buffer_head * const bh = &mdev->md_io_bio;

	bh->b_blocknr = sector;	// We abuse b_blocknr here.
	bh->b_size    = 512;
	bh->b_private = mdev;
	bh->b_rdev    = mdev->md_device;
	bh->b_rsector = sector;

	// we skip submit_bh, but use generic_make_request.
	clear_bit(BH_Uptodate, &bh->b_state);
	set_bit(BH_Req, &bh->b_state);
	set_bit(BH_Launder, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state);

	drbd_bio_set_end_io(&mdev->md_io_bio,drbd_generic_end_io);
}

static inline void
drbd_ee_prepare_write(drbd_dev *mdev, struct Tl_epoch_entry* e,
		      sector_t sector, int size)
{
	struct buffer_head * const bh = &e->private_bio;

	bh->b_blocknr  = sector;	// We abuse b_blocknr here.
	bh->b_size     = size;
	bh->b_rsector  = sector;
	bh->b_rdev     = mdev->md_device;
	bh->b_private  = mdev;
	bh->b_end_io   = drbd_dio_end_sec;

	set_bit(BH_Dirty, &bh->b_state);
	set_bit(BH_Req, &bh->b_state);
	set_bit(BH_Launder, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state);
}

static inline void
drbd_ee_prepare_read(drbd_dev *mdev, struct Tl_epoch_entry* e,
		     sector_t sector, int size)
{
	struct buffer_head * const bh = &e->private_bio;

	bh->b_blocknr  = sector;	// We abuse b_blocknr here.
	bh->b_size     = size;
	bh->b_rsector  = sector;
	bh->b_rdev     = mdev->md_device;
	bh->b_private  = mdev;
	bh->b_end_io   = enslaved_read_bi_end_io;

	clear_bit(BH_Uptodate, &e->private_bio.b_state);
	set_bit(BH_Dirty, &bh->b_state);
	set_bit(BH_Req, &bh->b_state);
	set_bit(BH_Launder, &bh->b_state);
	set_bit(BH_Lock, &bh->b_state);
}

static inline void
drbd_req_prepare_write(drbd_dev *mdev, struct drbd_request *req)
{
	struct buffer_head * const bh     = &req->private_bio;
	struct buffer_head * const bh_src =  req->master_bio;
	memset(bh, 0, sizeof(struct buffer_head));

	bh->b_list      = bh_src->b_list; // BUF_LOCKED;
	bh->b_size      = bh_src->b_size;
	bh->b_state     = bh_src->b_state & ((1 << BH_PrivateStart)-1);
	bh->b_page      = bh_src->b_page;
	bh->b_data      = bh_src->b_data;
	bh->b_rsector   = bh_src->b_rsector;
	bh->b_blocknr   = bh_src->b_rsector; // We abuse b_blocknr here.
	bh->b_dev       = bh_src->b_dev;     // so LVM has a hint as to
					     // which device to call fsync_dev
					     // on for snapshots
	bh->b_rdev      = mdev->lo_device;
	bh->b_private   = mdev;
	bh->b_end_io    = drbd_dio_end;

	atomic_set(&bh->b_count, 1);
	init_waitqueue_head(&bh->b_wait);

	// other members stay NULL

	D_ASSERT(buffer_req(bh));
	D_ASSERT(buffer_launder(bh));
	D_ASSERT(buffer_locked(bh));
	D_ASSERT(buffer_mapped(bh));
	// D_ASSERT(buffer_dirty(bh)); // It is not true ?!?

	// FIXME should not be necessary
	bh->b_state = (1 << BH_Dirty) | ( 1 << BH_Mapped) | (1 << BH_Lock);

	req->rq_status = RQ_DRBD_NOTHING;
}

static inline void
drbd_bio_add_page(struct buffer_head *bh, struct page *page, unsigned long offset)
{
	set_bh_page (bh,page,offset);
	bh->b_this_page = bh;

}

static inline struct page* drbd_bio_get_page(struct buffer_head *bh)
{
	return bh->b_page;
}

static inline void drbd_generic_make_request(int rw, struct buffer_head *bh)
{
	generic_make_request(rw, bh);
}

static inline void drbd_generic_make_request_wait(int rw, struct buffer_head *bh)
{
	generic_make_request(rw, bh);
	wait_on_buffer(bh);
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
# warning "FIXME these do nonsense. Currently I only check whether it compiles!"

#include <linux/buffer_head.h> // for fsync_bdev

extern void FIXME_DONT_USE(void); // unresolved symbol ;)

/* see get_sb_bdev and bd_claim */
extern char* drbd_sec_holder;

// bi_end_io handlers
// int (bio_end_io_t) (struct bio *, unsigned int, int);
extern int drbd_generic_end_io     (struct bio *bio, unsigned int ignored, int error);
extern int drbd_async_eio          (struct bio *bio, unsigned int ignored, int error);
extern int enslaved_read_bi_end_io (struct bio *bio, unsigned int ignored, int error);
extern int drbd_dio_end_sec        (struct bio *bio, unsigned int ignored, int error);
extern int drbd_dio_end            (struct bio *bio, unsigned int ignored, int error);

#ifdef DBG_BH_SECTOR
static inline sector_t APP_BH_SECTOR(struct bio *bio)
{
	return 0;
}
#else
# define APP_BH_SECTOR(BH) 0
#endif

static inline unsigned long drbd_get_lo_capacity(drbd_dev *mdev)
{
	FIXME_DONT_USE();
	return 0;
}

static inline unsigned long drbd_get_my_capacity(drbd_dev *mdev)
{
	return 0;
}

static inline void drbd_set_my_capacity(drbd_dev *mdev, sector_t size)
{
}

static inline sector_t drbd_md_ss(drbd_dev *mdev)
{
	return 0;
}

static inline void drbd_set_blocksize(drbd_dev *mdev, int blksize)
{
}

static inline int drbd_sync_me(drbd_dev *mdev)
{
	return fsync_bdev(mdev->this_bdev);
}

#define drbd_bio_uptodate(bio) bio_flagged(bio,BIO_UPTODATE)

static inline void drbd_bio_IO_error(struct bio *bio)
{
}

static inline void drbd_bio_endio(struct bio *bio, int uptodate)
{
}

static inline drbd_dev* drbd_req_get_mdev(struct drbd_request *req)
{
	return drbd_conf;
}

static inline sector_t drbd_req_get_sector(struct drbd_request *req)
{
	return 0;
}

static inline unsigned short drbd_req_get_size(struct drbd_request *req)
{
	return 0;
}

static inline sector_t drbd_ee_get_sector(struct Tl_epoch_entry *ee)
{
	return 0;
}

static inline unsigned short drbd_ee_get_size(struct Tl_epoch_entry *ee)
{
	return 0;
}

static inline sector_t drbd_pr_get_sector(struct Pending_read *pr)
{
	return 0;
}

static inline short drbd_bio_get_size(struct buffer_head *bh)
{
	return 0;
}

static inline char *drbd_bio_kmap(struct bio *bio)
{
	return NULL;
}

static inline void drbd_bio_kunmap(struct bio *bio)
{
}

static inline void drbd_init_bio(struct bio *bio, int size)
{
}

static inline void drbd_bio_set_pages_dirty(struct bio *bio)
{
}

static inline void drbd_bio_set_end_io(struct bio *bio, bio_end_io_t * h)
{
}

static inline void drbd_md_prepare_write(drbd_dev *mdev, sector_t sector)
{
}

static inline void drbd_md_prepare_read(drbd_dev *mdev, sector_t sector)
{
}

static inline void
drbd_ee_prepare_write(drbd_dev *mdev, struct Tl_epoch_entry* e,
		      sector_t sector, int size)
{
}

static inline void
drbd_ee_prepare_read(drbd_dev *mdev, struct Tl_epoch_entry* e,
		     sector_t sector, int size)
{
}

static inline void
drbd_req_prepare_write(drbd_dev *mdev, struct drbd_request *req)
{
}

static inline void
drbd_bio_add_page(struct bio *bio, struct page *page, unsigned long offset)
{
}

static inline struct page* drbd_bio_get_page(struct bio *bio)
{
	return NULL;
}

static inline void drbd_generic_make_request(int rw, struct bio *bio)
{
}

static inline void drbd_generic_make_request_wait(int rw, struct bio *bio)
{
}

static inline int _drbd_send_zc_bio(drbd_dev *mdev, struct bio *bio)
{
	return 0;
}
#endif
