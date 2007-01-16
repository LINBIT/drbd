/*
 * FIXME this file is bound to die, renamed or included in drbd_int.h
 */

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
# error "use a 2.6 kernel, please"
#endif


/* struct page has a union in 2.6.15 ...
 * an anonymous union and struct since 2.6.16 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)) || (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16))
#define U_PRIVATE private
#else
#define U_PRIVATE u.private
#endif

#include <linux/buffer_head.h> // for fsync_bdev

/* see get_sb_bdev and bd_claim */
extern char* drbd_sec_holder;

// bi_end_io handlers
// int (bio_end_io_t) (struct bio *, unsigned int, int);
extern int drbd_md_io_complete (struct bio *bio, unsigned int bytes_done, int error);

extern int drbd_endio_read_sec (struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_endio_write_sec(struct bio *bio, unsigned int bytes_done, int error);
extern int drbd_endio_pri      (struct bio *bio, unsigned int bytes_done, int error);

static inline sector_t drbd_get_hardsect(struct block_device *bdev)
{
	return bdev->bd_disk->queue->hardsect_size;
}

/* Returns the number of 512 byte sectors of the device */
static inline sector_t drbd_get_capacity(struct block_device *bdev)
{
	/* return bdev ? get_capacity(bdev->bd_disk) : 0; */
	return bdev ? bdev->bd_inode->i_size >> 9 : 0;
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(drbd_dev *mdev,
					sector_t size)
{
	/* set_capacity(mdev->this_bdev->bd_disk, size); */
	set_capacity(mdev->vdisk,size);
	mdev->this_bdev->bd_inode->i_size = (loff_t)size << 9;
}

static inline int drbd_sync_me(drbd_dev *mdev)
{
	return fsync_bdev(mdev->this_bdev);
}

#define drbd_bio_uptodate(bio) bio_flagged(bio,BIO_UPTODATE)

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
static inline void drbd_generic_make_request(int rw, int fault_type, struct bio *bio)
{
	bio->bi_rw = rw; // on the receiver side, e->..rw was not yet defined.

	if (!bio->bi_bdev) {
		printk(KERN_ERR "drbd_generic_make_request: bio->bi_bdev == NULL\n");
		dump_stack();
		bio_endio(bio, bio->bi_size, -ENODEV);
		return;
	}

	if (FAULT_ACTIVE(fault_type))
		bio_endio(bio,bio->bi_size,-EIO);
	else
		generic_make_request(bio);
}

static inline void drbd_plug_device(drbd_dev *mdev)
{
	request_queue_t *q;
	q = bdev_get_queue(mdev->this_bdev);

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

#ifdef DEFINE_SOCK_CREATE_KERN
#define sock_create_kern sock_create
#endif

#ifdef USE_KMEM_CACHE_S
typedef struct kmem_cache_s drbd_kmem_cache_t;
#else
typedef struct kmem_cache drbd_kmem_cache_t;
#endif

#ifdef NEED_BACKPORT_OF_ATOMIC_ADD

#if defined(__x86_64__)

static __inline__ int atomic_add_return(int i, atomic_t *v)
{
        int __i = i;
        __asm__ __volatile__(
                LOCK_PREFIX "xaddl %0, %1;"
                :"=r"(i)
                :"m"(v->counter), "0"(i));
        return i + __i;
}

static __inline__ int atomic_sub_return(int i, atomic_t *v)
{
        return atomic_add_return(-i,v);
}

#define atomic_inc_return(v)  (atomic_add_return(1,v))
#define atomic_dec_return(v)  (atomic_sub_return(1,v))

#elif defined(__i386__) || defined(__arch_um__)

static __inline__ int atomic_add_return(int i, atomic_t *v)
{
        int __i;
#ifdef CONFIG_M386
        unsigned long flags;
        if(unlikely(boot_cpu_data.x86==3))
                goto no_xadd;
#endif
        /* Modern 486+ processor */
        __i = i;
        __asm__ __volatile__(
                LOCK_PREFIX "xaddl %0, %1;"
                :"=r"(i)
                :"m"(v->counter), "0"(i));
        return i + __i;

#ifdef CONFIG_M386
no_xadd: /* Legacy 386 processor */
        local_irq_save(flags);
        __i = atomic_read(v);
        atomic_set(v, i + __i);
        local_irq_restore(flags);
        return i + __i;
#endif
}

static __inline__ int atomic_sub_return(int i, atomic_t *v)
{
        return atomic_add_return(-i,v);
}

#define atomic_inc_return(v)  (atomic_add_return(1,v))
#define atomic_dec_return(v)  (atomic_sub_return(1,v))

#else
# error "You need to copy/past atomic_inc_return()/atomic_dec_return() here"
# error "for your architecture. (Hint: Kernels after 2.6.10 have those"
# error "by default! Using a later kernel might be less effort!)"
#endif

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/* With Linux-2.6.19 the crypto API changed! */
/* This is not a generic backport of the new api, it just implements
   the corner case of "hmac(xxx)".  */

#define CRYPTO_ALG_ASYNC 4711
#define CRYPTO_ALG_TYPE_HASH CRYPTO_ALG_TYPE_DIGEST

struct crypto_hash {
        struct crypto_tfm *base;
	const u8 *key;
	int keylen;
};

struct hash_desc {
        struct crypto_hash *tfm;
        u32 flags;
};

static inline struct crypto_hash *
crypto_alloc_hash(char *alg_name, u32 type, u32 mask)
{
	struct crypto_hash *ch;
	char *closing_bracket;

	// "hmac(xxx)" is in alg_name we need that xxx.
	closing_bracket = strchr(alg_name,')');
	if(!closing_bracket) return NULL;
	if(closing_bracket-alg_name < 6) return NULL;

	ch = kmalloc(sizeof(struct crypto_hash),GFP_KERNEL);
	if(!ch) return NULL;

	*closing_bracket = 0;
	ch->base = crypto_alloc_tfm(alg_name + 5, 0);
	*closing_bracket = ')';

	if (ch->base == NULL) {
		kfree(ch);
		return NULL;
	}

	return ch;
}

static inline int
crypto_hash_setkey(struct crypto_hash *hash,const u8 *key,unsigned int keylen)
{
	hash->key = key;
	hash->keylen = keylen;

	return 0;
}

static inline int
crypto_hash_digest(struct hash_desc *desc, struct scatterlist *sg,
		   unsigned int nbytes, u8 *out)
{

	crypto_hmac(desc->tfm->base, (u8*)desc->tfm->key,
		    &desc->tfm->keylen, sg, 1 /* ! */ , out);
	/* ! this is not generic. Would need to convert nbytes -> nsg */

	return 0;
}

static inline void crypto_free_hash(struct crypto_hash *tfm)
{
	crypto_free_tfm(tfm->base);
	kfree(tfm);
}

static inline unsigned int crypto_hash_digestsize(struct crypto_hash *tfm)
{
	return crypto_tfm_alg_digestsize(tfm->base);
}

static inline struct crypto_tfm *crypto_hash_tfm(struct crypto_hash *tfm)
{
        return tfm->base;
}

#endif
