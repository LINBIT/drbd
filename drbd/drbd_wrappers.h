#ifndef _DRBD_WRAPPERS_H
#define _DRBD_WRAPPERS_H

#include <linux/ctype.h>
#include <linux/net.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
# error "use a 2.6 kernel, please"
#endif

/* The history of blkdev_issue_flush()

   It had 2 arguments before fbd9b09a177a481eda256447c881f014f29034fe,
   after it had 4 arguments. (With that commit came BLKDEV_IFL_WAIT)

   It had 4 arguments before dd3932eddf428571762596e17b65f5dc92ca361b,
   after it got 3 arguments. (With that commit came BLKDEV_DISCARD_SECURE
   and BLKDEV_IFL_WAIT disappeared again.) */
#include <linux/blkdev.h>
#ifndef BLKDEV_IFL_WAIT
#ifndef BLKDEV_DISCARD_SECURE
/* before fbd9b09a177 */
#define blkdev_issue_flush(b, gfpf, s)	blkdev_issue_flush(b, s)
#endif
/* after dd3932eddf4 no define at all */
#else
/* between fbd9b09a177 and dd3932eddf4 */
#define blkdev_issue_flush(b, gfpf, s)	blkdev_issue_flush(b, gfpf, s, BLKDEV_IFL_WAIT)
#endif

#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/completion.h>

/* for the proc_create wrapper */
#include <linux/proc_fs.h>

/* struct page has a union in 2.6.15 ...
 * an anonymous union and struct since 2.6.16
 * or in fc5 "2.6.15" */
#include <linux/mm.h>
#ifndef page_private
# define page_private(page)		((page)->private)
# define set_page_private(page, v)	((page)->private = (v))
#endif

/* mutex was not available before 2.6.16.
 * various vendors provide various degrees of backports.
 * we provide the missing parts ourselves, if neccessary.
 * this one is for RHEL/Centos 4 */
#if defined(mutex_lock) && !defined(mutex_is_locked)
#define mutex_is_locked(m) (atomic_read(&(m)->count) != 1)
#endif

/* see get_sb_bdev and bd_claim */
extern char *drbd_sec_holder;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
static inline unsigned short queue_logical_block_size(struct request_queue *q)
{
	int retval = 512;
	if (q && q->hardsect_size)
		retval = q->hardsect_size;
	return retval;
}

static inline sector_t bdev_logical_block_size(struct block_device *bdev)
{
	return queue_logical_block_size(bdev_get_queue(bdev));
}

static inline unsigned int queue_max_hw_sectors(struct request_queue *q)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
	/* before upstream commit ba066f3a0469dfc6d8fbdf70fabfd8c069fbf306,
	 * there is no max_hw_sectors. Simply use max_sectors here,
	 * it should be good enough. Affected: sles9. */
	return q->max_sectors;
#else
	return q->max_hw_sectors;
#endif
}

static inline unsigned int queue_max_sectors(struct request_queue *q)
{
	return q->max_sectors;
}

static inline void blk_queue_logical_block_size(struct request_queue *q, unsigned short size)
{
	q->hardsect_size = size;
}
#endif

/* Returns the number of 512 byte sectors of the device */
static inline sector_t drbd_get_capacity(struct block_device *bdev)
{
	/* return bdev ? get_capacity(bdev->bd_disk) : 0; */
	return bdev ? bdev->bd_inode->i_size >> 9 : 0;
}

/* sets the number of 512 byte sectors of our virtual device */
static inline void drbd_set_my_capacity(struct drbd_conf *mdev,
					sector_t size)
{
	/* set_capacity(mdev->this_bdev->bd_disk, size); */
	set_capacity(mdev->vdisk, size);
	mdev->this_bdev->bd_inode->i_size = (loff_t)size << 9;
}

#ifndef COMPAT_HAVE_BLKDEV_GET_BY_PATH
/* see kernel 2.6.37,
 * d4d7762 block: clean up blkdev_get() wrappers and their users
 * e525fd8 block: make blkdev_get/put() handle exclusive access
 * and kernel 2.6.28
 * 30c40d2 [PATCH] propagate mode through open_bdev_excl/close_bdev_excl
 * Also note that there is no FMODE_EXCL before
 * 86d434d [PATCH] eliminate use of ->f_flags in block methods
 */
#ifndef COMPAT_HAVE_OPEN_BDEV_EXCLUSIVE
#ifndef FMODE_EXCL
#define FMODE_EXCL 0
#endif
static inline
struct block_device *open_bdev_exclusive(const char *path, fmode_t mode, void *holder)
{
	/* drbd does not open readonly, but try to be correct, anyways */
	return open_bdev_excl(path, (mode & FMODE_WRITE) ? 0 : MS_RDONLY, holder);
}
static inline
void close_bdev_exclusive(struct block_device *bdev, fmode_t mode)
{
	/* mode ignored. */
	close_bdev_excl(bdev);
}
#endif
static inline struct block_device *blkdev_get_by_path(const char *path,
		fmode_t mode, void *holder)
{
	return open_bdev_exclusive(path, mode, holder);
}

static inline int drbd_blkdev_put(struct block_device *bdev, fmode_t mode)
{
	/* blkdev_put != close_bdev_exclusive, in general, so this is obviously
	 * not correct, and there should be some if (mode & FMODE_EXCL) ...
	 * But this is the only way it is used in DRBD,
	 * and for <= 2.6.27, there is no FMODE_EXCL anyways. */
	close_bdev_exclusive(bdev, mode);

	/* blkdev_put seems to not have useful return values,
	 * close_bdev_exclusive is void. */
	return 0;
}
#define blkdev_put(b, m)	drbd_blkdev_put(b, m)
#endif

#define drbd_bio_uptodate(bio) bio_flagged(bio, BIO_UPTODATE)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* Before Linux-2.6.24 bie_endio() had the size of the bio as second argument.
   See 6712ecf8f648118c3363c142196418f89a510b90 */
#define bio_endio(B,E) bio_endio(B, (B)->bi_size, E)
#define BIO_ENDIO_TYPE int
#define BIO_ENDIO_ARGS(b,e) (b, unsigned int bytes_done, e)
#define BIO_ENDIO_FN_START if (bio->bi_size) return 1
#define BIO_ENDIO_FN_RETURN return 0
#else
#define BIO_ENDIO_TYPE void
#define BIO_ENDIO_ARGS(b,e) (b,e)
#define BIO_ENDIO_FN_START do {} while (0)
#define BIO_ENDIO_FN_RETURN return
#endif

/* bi_end_io handlers */
extern BIO_ENDIO_TYPE drbd_md_io_complete BIO_ENDIO_ARGS(struct bio *bio, int error);
extern BIO_ENDIO_TYPE drbd_endio_sec BIO_ENDIO_ARGS(struct bio *bio, int error);
extern BIO_ENDIO_TYPE drbd_endio_pri BIO_ENDIO_ARGS(struct bio *bio, int error);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define part_inc_in_flight(A, B) part_inc_in_flight(A)
#define part_dec_in_flight(A, B) part_dec_in_flight(A)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
/* Before 2.6.23 (with 20c2df83d25c6a95affe6157a4c9cac4cf5ffaac) kmem_cache_create had a
   ctor and a dtor */
#define kmem_cache_create(N,S,A,F,C) kmem_cache_create(N,S,A,F,C,NULL)
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,26)
# undef HAVE_bvec_merge_data
# define HAVE_bvec_merge_data 1
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg->page   = page;
	sg->offset = offset;
	sg->length = len;
}

#define sg_init_table(S,N) ({})

#ifndef COMPAT_HAVE_SG_SET_BUF
static inline void sg_set_buf(struct scatterlist *sg, const void *buf,
			      unsigned int buflen)
{
	sg_set_page(sg, virt_to_page(buf), buflen, offset_in_page(buf));
}
#endif

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,28)
# define BD_OPS_USE_FMODE
#endif

/* how to get to the kobj of a gendisk.
 * see also upstream commits
 * edfaa7c36574f1bf09c65ad602412db9da5f96bf
 * ed9e1982347b36573cd622ee5f4e2a7ccd79b3fd
 * 548b10eb2959c96cef6fc29fc96e0931eeb53bc5
 */
#ifndef dev_to_disk
# define disk_to_kobj(disk) (&(disk)->kobj)
#else
# ifndef disk_to_dev
#  define disk_to_dev(disk) (&(disk)->dev)
# endif
# define disk_to_kobj(disk) (&disk_to_dev(disk)->kobj)
#endif
static inline void drbd_kobject_uevent(struct drbd_conf *mdev)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,15)
	kobject_uevent(disk_to_kobj(mdev->vdisk), KOBJ_CHANGE, NULL);
#else
	kobject_uevent(disk_to_kobj(mdev->vdisk), KOBJ_CHANGE);
	/* rhel4 / sles9 and older don't have this at all,
	 * which means user space (udev) won't get events about possible changes of
	 * corresponding resource + disk names after the initial drbd minor creation.
	 */
#endif
#endif
}


/*
 * used to submit our private bio
 */
static inline void drbd_generic_make_request(struct drbd_conf *mdev,
					     int fault_type, struct bio *bio)
{
	__release(local);
	if (!bio->bi_bdev) {
		printk(KERN_ERR "drbd%d: drbd_generic_make_request: "
				"bio->bi_bdev == NULL\n",
		       mdev_to_minor(mdev));
		dump_stack();
		bio_endio(bio, -ENODEV);
		return;
	}

	if (drbd_insert_fault(mdev, fault_type))
		bio_endio(bio, -EIO);
	else
		generic_make_request(bio);
}

static inline void drbd_plug_device(struct drbd_conf *mdev)
{
	struct request_queue *q;
	q = bdev_get_queue(mdev->this_bdev);

	spin_lock_irq(q->queue_lock);

/* XXX the check on !blk_queue_plugged is redundant,
 * implicitly checked in blk_plug_device */

	if (!blk_queue_plugged(q)) {
		blk_plug_device(q);
		del_timer(&q->unplug_timer);
		/* unplugging should not happen automatically... */
	}
	spin_unlock_irq(q->queue_lock);
}

static inline int drbd_backing_bdev_events(struct drbd_conf *mdev)
{
	struct gendisk *disk = mdev->ldev->backing_bdev->bd_contains->bd_disk;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
	/* very old kernel */
	return (int)disk_stat_read(disk, read_sectors)
	     + (int)disk_stat_read(disk, write_sectors);
#elif defined(__disk_stat_inc)
	/* older kernel */
	return (int)disk_stat_read(disk, sectors[0])
	     + (int)disk_stat_read(disk, sectors[1]);
#else
	/* recent kernel */
	return (int)part_stat_read(&disk->part0, sectors[0])
	     + (int)part_stat_read(&disk->part0, sectors[1]);
#endif
}

#ifndef COMPAT_HAVE_SOCK_CREATE
#define sock_create_kern sock_create
#endif

#ifdef COMPAT_USE_KMEM_CACHE_S
#define kmem_cache kmem_cache_s
#endif

#ifndef COMPAT_HAVE_SOCK_SHUTDOWN
enum sock_shutdown_cmd {
	SHUT_RD = 0,
	SHUT_WR = 1,
	SHUT_RDWR = 2,
};
static inline int kernel_sock_shutdown(struct socket *sock, enum sock_shutdown_cmd how)
{
	return sock->ops->shutdown(sock, how);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
static inline void drbd_unregister_blkdev(unsigned int major, const char *name)
{
	int ret = unregister_blkdev(major, name);
	if (ret)
		printk(KERN_ERR "drbd: unregister of device failed\n");
}
#else
#define drbd_unregister_blkdev unregister_blkdev
#endif

#ifndef COMPAT_HAVE_ATOMIC_ADD

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
	return atomic_add_return(-i, v);
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
	return atomic_add_return(-i, v);
}

#define atomic_inc_return(v)  (atomic_add_return(1,v))
#define atomic_dec_return(v)  (atomic_sub_return(1,v))

#else
# error "You need to copy/past atomic_inc_return()/atomic_dec_return() here"
# error "for your architecture. (Hint: Kernels after 2.6.10 have those"
# error "by default! Using a later kernel might be less effort!)"
#endif

#endif

#if !defined(CRYPTO_ALG_ASYNC)
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

	/* "hmac(xxx)" is in alg_name we need that xxx. */
	closing_bracket = strchr(alg_name, ')');
	if (!closing_bracket) {
		ch = kmalloc(sizeof(struct crypto_hash), GFP_KERNEL);
		if (!ch)
			return ERR_PTR(-ENOMEM);
		ch->base = crypto_alloc_tfm(alg_name, 0);
		if (ch->base == NULL) {
			kfree(ch);
			return ERR_PTR(-ENOMEM);
		}
		return ch;
	}
	if (closing_bracket-alg_name < 6)
		return ERR_PTR(-ENOENT);

	ch = kmalloc(sizeof(struct crypto_hash), GFP_KERNEL);
	if (!ch)
		return ERR_PTR(-ENOMEM);

	*closing_bracket = 0;
	ch->base = crypto_alloc_tfm(alg_name + 5, 0);
	*closing_bracket = ')';

	if (ch->base == NULL) {
		kfree(ch);
		return ERR_PTR(-ENOMEM);
	}

	return ch;
}

static inline int
crypto_hash_setkey(struct crypto_hash *hash, const u8 *key, unsigned int keylen)
{
	hash->key = key;
	hash->keylen = keylen;

	return 0;
}

static inline int
crypto_hash_digest(struct hash_desc *desc, struct scatterlist *sg,
		   unsigned int nbytes, u8 *out)
{

	crypto_hmac(desc->tfm->base, (u8 *)desc->tfm->key,
		    &desc->tfm->keylen, sg, 1 /* ! */ , out);
	/* ! this is not generic. Would need to convert nbytes -> nsg */

	return 0;
}

static inline void crypto_free_hash(struct crypto_hash *tfm)
{
	if (!tfm)
		return;
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

static inline int crypto_hash_init(struct hash_desc *desc)
{
	crypto_digest_init(desc->tfm->base);
	return 0;
}

static inline int crypto_hash_update(struct hash_desc *desc,
				     struct scatterlist *sg,
				     unsigned int nbytes)
{
	crypto_digest_update(desc->tfm->base,sg,1 /* ! */ );
	/* ! this is not generic. Would need to convert nbytes -> nsg */

	return 0;
}

static inline int crypto_hash_final(struct hash_desc *desc, u8 *out)
{
	crypto_digest_final(desc->tfm->base, out);
	return 0;
}

#endif

static inline int drbd_crypto_is_hash(struct crypto_tfm *tfm)
{
#ifdef CRYPTO_ALG_TYPE_HASH_MASK
	/* see include/linux/crypto.h */
	return !((crypto_tfm_alg_type(tfm) ^ CRYPTO_ALG_TYPE_HASH)
		& CRYPTO_ALG_TYPE_HASH_MASK);
#else
	return crypto_tfm_alg_type(tfm) == CRYPTO_ALG_TYPE_HASH;
#endif
}


#ifndef COMPAT_HAVE_KZALLOC
static inline void *kzalloc(size_t size, int flags)
{
	void *rv = kmalloc(size, flags);
	if (rv)
		memset(rv, 0, size);

	return rv;
}
#define COMPAT_HAVE_KZALLOC
#endif

/* see upstream commit 2d3854a37e8b767a51aba38ed6d22817b0631e33 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#ifndef cpumask_bits
#define nr_cpu_ids NR_CPUS
#define nr_cpumask_bits nr_cpu_ids

typedef cpumask_t cpumask_var_t[1];
#define cpumask_bits(maskp) ((unsigned long*)(maskp))
#define cpu_online_mask &(cpu_online_map)

static inline void cpumask_clear(cpumask_t *dstp)
{
	bitmap_zero(cpumask_bits(dstp), NR_CPUS);
}

static inline int cpumask_equal(const cpumask_t *src1p,
				const cpumask_t *src2p)
{
	return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p),
						 nr_cpumask_bits);
}

static inline void cpumask_copy(cpumask_t *dstp,
				cpumask_t *srcp)
{
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

static inline unsigned int cpumask_weight(const cpumask_t *srcp)
{
	return bitmap_weight(cpumask_bits(srcp), nr_cpumask_bits);
}

static inline void cpumask_set_cpu(unsigned int cpu, cpumask_t *dstp)
{
	set_bit(cpu, cpumask_bits(dstp));
}

static inline void cpumask_setall(cpumask_t *dstp)
{
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

static inline void free_cpumask_var(cpumask_var_t mask)
{
}
#endif
/* see upstream commit 0281b5dc0350cbf6dd21ed558a33cccce77abc02 */
#ifdef CONFIG_CPUMASK_OFFSTACK
static inline int zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return alloc_cpumask_var(mask, flags | __GFP_ZERO);
}
#else
static inline int zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	cpumask_clear(*mask);
	return 1;
}
#endif
/* see upstream commit cd8ba7cd9be0192348c2836cb6645d9b2cd2bfd2 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
/* As macro because RH has it in 2.6.18-128.4.1.el5, but not exported to modules !?!? */
#define set_cpus_allowed_ptr(P, NM) set_cpus_allowed(P, *NM)
#endif
#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define __bitmap_parse(BUF, BUFLEN, ISUSR, MASKP, NMASK) \
	backport_bitmap_parse(BUF, BUFLEN, ISUSR, MASKP, NMASK)

#define CHUNKSZ                         32
#define nbits_to_hold_value(val)        fls(val)
#define unhex(c)                        (isdigit(c) ? (c - '0') : (toupper(c) - 'A' + 10))

static inline int backport_bitmap_parse(const char *buf, unsigned int buflen,
		int is_user, unsigned long *maskp,
		int nmaskbits)
{
	int c, old_c, totaldigits, ndigits, nchunks, nbits;
	u32 chunk;
	const char __user *ubuf = buf;

	bitmap_zero(maskp, nmaskbits);

	nchunks = nbits = totaldigits = c = 0;
	do {
		chunk = ndigits = 0;

		/* Get the next chunk of the bitmap */
		while (buflen) {
			old_c = c;
			if (is_user) {
				if (__get_user(c, ubuf++))
					return -EFAULT;
			}
			else
				c = *buf++;
			buflen--;
			if (isspace(c))
				continue;

			/*
			 * If the last character was a space and the current
			 * character isn't '\0', we've got embedded whitespace.
			 * This is a no-no, so throw an error.
			 */
			if (totaldigits && c && isspace(old_c))
				return -EINVAL;

			/* A '\0' or a ',' signal the end of the chunk */
			if (c == '\0' || c == ',')
				break;

			if (!isxdigit(c))
				return -EINVAL;

			/*
			 * Make sure there are at least 4 free bits in 'chunk'.
			 * If not, this hexdigit will overflow 'chunk', so
			 * throw an error.
			 */
			if (chunk & ~((1UL << (CHUNKSZ - 4)) - 1))
				return -EOVERFLOW;

			chunk = (chunk << 4) | unhex(c);
			ndigits++; totaldigits++;
		}
		if (ndigits == 0)
			return -EINVAL;
		if (nchunks == 0 && chunk == 0)
			continue;

		bitmap_shift_left(maskp, maskp, CHUNKSZ, nmaskbits);
		*maskp |= chunk;
		nchunks++;
		nbits += (nchunks == 1) ? nbits_to_hold_value(chunk) : CHUNKSZ;
		if (nbits > nmaskbits)
			return -EOVERFLOW;
	} while (buflen && c == ',');

	return 0;
}
#endif

#ifndef __CHECKER__
# undef __cond_lock
# define __cond_lock(x,c) (c)
#endif

#ifndef COMPAT_HAVE_GFP_T
#define COMPAT_HAVE_GFP_T
typedef unsigned gfp_t;
#endif


/* struct kvec didn't exist before 2.6.8, this is an ugly
 * #define to work around it ... - jt */

#ifndef COMPAT_HAVE_KVEC
#define kvec iovec
#endif

#ifndef net_random
#define random32 net_random
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define BDI_async_congested BDI_write_congested
#define BDI_sync_congested  BDI_read_congested
#endif

/* see upstream commits
 * 2d3a4e3666325a9709cc8ea2e88151394e8f20fc (in 2.6.25-rc1)
 * 59b7435149eab2dd06dd678742faff6049cb655f (in 2.6.26-rc1)
 * this "backport" does not close the race that lead to the API change,
 * but only provides an equivalent function call.
 */
#ifndef COMPAT_HAVE_PROC_CREATE_DATA
static inline struct proc_dir_entry *proc_create_data(const char *name,
	mode_t mode, struct proc_dir_entry *parent,
	struct file_operations *proc_fops, void *data)
{
	struct proc_dir_entry *pde = create_proc_entry(name, mode, parent);
	if (pde) {
		pde->proc_fops = proc_fops;
		pde->data = data;
	}
	return pde;
}

#endif


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
#define TP_PROTO(args...)	args
#define TP_ARGS(args...)		args

#undef DECLARE_TRACE
#define DECLARE_TRACE(name, proto, args)				\
	static inline void _do_trace_##name(struct tracepoint *tp, proto) \
	{ }								\
	static inline void trace_##name(proto)				\
	{ }								\
	static inline int register_trace_##name(void (*probe)(proto))	\
	{								\
		return -ENOSYS;						\
	}								\
	static inline int unregister_trace_##name(void (*probe)(proto))	\
	{								\
		return -ENOSYS;						\
	}

#undef DEFINE_TRACE
#define DEFINE_TRACE(name)

#endif

#ifndef COMPAT_HAVE_BLK_QUEUE_MAX_HW_SECTORS
static inline void blk_queue_max_hw_sectors(struct request_queue *q, unsigned int max)
{
	blk_queue_max_sectors(q, max);
}
#elif defined(USE_BLK_QUEUE_MAX_SECTORS_ANYWAYS)
	/* For kernel versions 2.6.31 to 2.6.33 inclusive, even though
	 * blk_queue_max_hw_sectors is present, we actually need to use
	 * blk_queue_max_sectors to set max_hw_sectors. :-(
	 * RHEL6 2.6.32 chose to be different and already has eliminated
	 * blk_queue_max_sectors as upstream 2.6.34 did.
	 */
#define blk_queue_max_hw_sectors(q, max)	blk_queue_max_sectors(q, max)
#endif

#ifndef COMPAT_HAVE_BLK_QUEUE_MAX_SEGMENTS
static inline void blk_queue_max_segments(struct request_queue *q, unsigned short max_segments)
{
	blk_queue_max_phys_segments(q, max_segments);
	blk_queue_max_hw_segments(q, max_segments);
#define BLK_MAX_SEGMENTS MAX_HW_SEGMENTS /* or max MAX_PHYS_SEGMENTS. Probably does not matter */
}
#endif

#ifndef COMPAT_HAVE_ATOMIC_ADD_UNLESS
#ifndef atomic_xchg
static inline int atomic_xchg(atomic_t *v, int new)
{
	return xchg(&v->counter, new);
}
#endif
#ifndef atomic_cmpxchg
static inline int atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return cmpxchg(&v->counter, old, new);
}
#endif

/**
 * atomic_add_unless - add unless the number is already a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as @v was not already @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
static inline int atomic_add_unless(atomic_t *v, int a, int u)
{
	int c, old;
	c = atomic_read(v);
	for (;;) {
		if (unlikely(c == (u)))
			break;
		old = atomic_cmpxchg((v), c, c + (a));
		if (likely(old == c))
			break;
		c = old;
	}
	return c != (u);
}
#endif

#ifndef COMPAT_HAVE_BOOL_TYPE
typedef _Bool                   bool;
enum {
	false = 0,
	true = 1
};
#endif

/* REQ_* and BIO_RW_* flags have been moved around in the tree,
 * and have finally been "merged" with
 * 7b6d91daee5cac6402186ff224c3af39d79f4a0e and
 * 7cc015811ef8992dfcce314d0ed9642bc18143d1
 * We communicate between different systems,
 * so we have to somehow semantically map the bi_rw flags
 * bi_rw (some kernel version) -> data packet flags -> bi_rw (other kernel version)
 */

#if defined(BIO_RW_SYNC)
/* see upstream commits
 * 213d9417fec62ef4c3675621b9364a667954d4dd,
 * 93dbb393503d53cd226e5e1f0088fe8f4dbaa2b8
 * later, the defines even became an enum ;-) */
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNC)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_SYNC)
#elif defined(REQ_SYNC)		/* introduced in 2.6.36 */
#define DRBD_REQ_SYNC		REQ_SYNC
#define DRBD_REQ_UNPLUG		REQ_UNPLUG
#else
/* cannot test on defined(BIO_RW_SYNCIO), it may be an enum */
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)
#endif


#ifdef REQ_FLUSH	/* introduced in 2.6.36, now equivalent to bi_rw */
#define DRBD_REQ_FLUSH		REQ_FLUSH
#define DRBD_REQ_FUA		REQ_FUA
#define DRBD_REQ_DISCARD	REQ_DISCARD
/* REQ_HARDBARRIER has been around for a long time,
 * without being directly related to bi_rw.
 * so the ifdef is only usful inside the ifdef REQ_FLUSH!
 * commit 7cc0158 (v2.6.36-rc1) made it a bi_rw flag, ...  */
#ifdef REQ_HARDBARRIER
#define DRBD_REQ_HARDBARRIER	REQ_HARDBARRIER
#else
/* ... but REQ_HARDBARRIER was removed again in 02e031c (v2.6.37-rc4). */
#define DRBD_REQ_HARDBARRIER	0
#endif
#else

#define DRBD_REQ_FLUSH		(1UL << BIO_RW_BARRIER)
/* REQ_FUA has been around for a longer time,
 * without a direct equivalent in bi_rw. */
#define DRBD_REQ_FUA		(1UL << BIO_RW_BARRIER)
#define DRBD_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)

/* we don't support DISCARDS yet, anyways.
 * cannot test on defined(BIO_RW_DISCARD), it may be an enum */
#define DRBD_REQ_DISCARD	0
#endif

/* this results in:
	bi_rw   -> dp_flags

< 2.6.28
	SYNC	-> SYNC|UNPLUG
	BARRIER	-> FUA|FLUSH
	there is no DISCARD
2.6.28
	SYNC	-> SYNC|UNPLUG
	BARRIER	-> FUA|FLUSH
	DISCARD	-> DISCARD
2.6.29
	SYNCIO	-> SYNC
	UNPLUG	-> UNPLUG
	BARRIER	-> FUA|FLUSH
	DISCARD	-> DISCARD
2.6.36
	SYNC	-> SYNC
	UNPLUG	-> UNPLUG
	FUA	-> FUA
	FLUSH	-> FLUSH
	DISCARD	-> DISCARD
--------------------------------------
	dp_flags   -> bi_rw
< 2.6.28
	SYNC	-> SYNC (and unplug)
	UNPLUG	-> SYNC (and unplug)
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	there is no DISCARD,
	it will be silently ignored on the receiving side.
2.6.28
	SYNC	-> SYNC (and unplug)
	UNPLUG	-> SYNC (and unplug)
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	DISCARD -> DISCARD
	(if that fails, we handle it like any other IO error)
2.6.29
	SYNC	-> SYNCIO
	UNPLUG	-> UNPLUG
	FUA	-> BARRIER
	FLUSH	-> BARRIER
	DISCARD -> DISCARD
2.6.36
	SYNC	-> SYNC
	UNPLUG	-> UNPLUG
	FUA	-> FUA
	FLUSH	-> FLUSH
	DISCARD	-> DISCARD

NOTE: DISCARDs likely need some work still.  We should actually never see
DISCARD requests, as our queue does not announce QUEUE_FLAG_DISCARD yet.
*/

#ifndef COMPLETION_INITIALIZER_ONSTACK
#define COMPLETION_INITIALIZER_ONSTACK(work) \
	({ init_completion(&work); work; })
#endif

#ifndef COMPAT_HAVE_SCHEDULE_TIMEOUT_INTERR
static inline signed long schedule_timeout_interruptible(signed long timeout)
{
	__set_current_state(TASK_INTERRUPTIBLE);
        return schedule_timeout(timeout);
}

static inline signed long schedule_timeout_uninterruptible(signed long timeout)
{
        __set_current_state(TASK_UNINTERRUPTIBLE);
        return schedule_timeout(timeout);
}
#endif

#ifndef CONFIG_DYNAMIC_DEBUG
/* At least in 2.6.34 the function macro dynamic_dev_dbg() is broken when compiling
   without CONFIG_DYNAMIC_DEBUG. It has 'format' in the argument list, it references
   to 'fmt' in its body. */
#ifdef dynamic_dev_dbg
#undef dynamic_dev_dbg
#define dynamic_dev_dbg(dev, fmt, ...)                               \
        do { if (0) dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__); } while (0)
#endif
#endif

#ifndef min_not_zero
#define min_not_zero(x, y) ({			\
	typeof(x) __x = (x);			\
	typeof(y) __y = (y);			\
	__x == 0 ? __y : ((__y == 0) ? __x : min(__x, __y)); })
#endif

#endif
