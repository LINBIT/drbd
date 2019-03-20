#ifndef _DRBD_WRAPPERS_H
#define _DRBD_WRAPPERS_H

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
# error "At least kernel 2.6.32 (with patches) required"
#endif

#include "compat.h"
#include <linux/ctype.h>
#include <linux/net.h>
#include <linux/version.h>
#include <linux/crypto.h>
#include <linux/netlink.h>
#include <linux/idr.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/proc_fs.h>
#include <linux/blkdev.h>
#include <linux/backing-dev.h>
#include <linux/kernel.h>

#ifndef pr_fmt
#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt
#endif

#ifndef U32_MAX
#define U32_MAX ((u32)~0U)
#endif
#ifndef S32_MAX
#define S32_MAX ((s32)(U32_MAX>>1))
#endif

#ifndef __GFP_RECLAIM
#define __GFP_RECLAIM __GFP_WAIT
#endif

#ifndef COMPAT_QUEUE_LIMITS_HAS_DISCARD_ZEROES_DATA
static inline unsigned int queue_discard_zeroes_data(struct request_queue *q)
{
	return 0;
}
#endif

static	inline int drbd_always_getpeername(struct socket *sock, struct sockaddr *uaddr)
{
#ifdef COMPAT_SOCK_OPS_RETURNS_ADDR_LEN
	return sock->ops->getname(sock, uaddr, 2);
#else
	int len = 0;
	int err = sock->ops->getname(sock, uaddr, &len, 2);
	return err ?: len;
#endif
}

#ifdef COMPAT_HAVE_BLK_QC_T_MAKE_REQUEST
/* in Commit dece16353ef47d8d33f5302bc158072a9d65e26f
 * make_request() becomes type blk_qc_t. */
#define MAKE_REQUEST_TYPE blk_qc_t
#define MAKE_REQUEST_RETURN return BLK_QC_T_NONE
#else
#ifdef COMPAT_HAVE_VOID_MAKE_REQUEST
/* in Commit 5a7bbad27a410350e64a2d7f5ec18fc73836c14f (between Linux-3.1 and 3.2)
   make_request() becomes type void. Before it had type int. */
#define MAKE_REQUEST_TYPE void
#define MAKE_REQUEST_RETURN return
#else
#define MAKE_REQUEST_TYPE int
#define MAKE_REQUEST_RETURN return 0
#endif
#endif

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

#ifdef COMPAT_HAVE_BIO_BI_STATUS
static inline void drbd_bio_endio(struct bio *bio, blk_status_t status)
{
	bio->bi_status = status;
	bio_endio(bio);
}
#define BIO_ENDIO_ARGS(b) (b)
#define BIO_ENDIO_FN_START	\
	blk_status_t status = bio->bi_status
#define BIO_ENDIO_FN_RETURN return

#else

#ifndef BLK_STS_OK
typedef u8 __bitwise blk_status_t;
#define BLK_STS_OK 0
#define BLK_STS_NOTSUPP		((__force blk_status_t)1)
#define BLK_STS_MEDIUM		((__force blk_status_t)7)
#define BLK_STS_RESOURCE	((__force blk_status_t)9)
#define BLK_STS_IOERR		((__force blk_status_t)10)
#endif
static int blk_status_to_errno(blk_status_t status)
{
	return  status == BLK_STS_OK ? 0 :
		status == BLK_STS_RESOURCE ? -ENOMEM :
		status == BLK_STS_NOTSUPP ? -EOPNOTSUPP :
		-EIO;
}
static inline blk_status_t errno_to_blk_status(int errno)
{
	blk_status_t status =
		errno == 0 ? BLK_STS_OK :
		errno == -ENOMEM ? BLK_STS_RESOURCE :
		errno == -EOPNOTSUPP ? BLK_STS_NOTSUPP :
		BLK_STS_IOERR;

	return status;
}

#ifdef COMPAT_HAVE_BIO_BI_ERROR
static inline void drbd_bio_endio(struct bio *bio, blk_status_t status)
{
	bio->bi_error = blk_status_to_errno(status);
	bio_endio(bio);
}
#define BIO_ENDIO_ARGS(b) (b)
#define BIO_ENDIO_FN_START	\
	blk_status_t status = errno_to_blk_status(bio->bi_error)
#define BIO_ENDIO_FN_RETURN return

#else
static inline void drbd_bio_endio(struct bio *bio, blk_status_t status)
{
	bio_endio(bio, blk_status_to_errno(status));
}
#define BIO_ENDIO_ARGS(b) (b, int error)
#define BIO_ENDIO_FN_START	\
	int status = errno_to_blk_status(error); \
	int uptodate = bio_flagged(bio, BIO_UPTODATE); \
	if (!error && !uptodate) { error = -EIO; status = BLK_STS_IOERR; }
#define BIO_ENDIO_FN_RETURN return

#endif
#endif

/* bi_end_io handlers */
extern void drbd_md_endio BIO_ENDIO_ARGS(struct bio *bio);
extern void drbd_peer_request_endio BIO_ENDIO_ARGS(struct bio *bio);
extern void drbd_request_endio BIO_ENDIO_ARGS(struct bio *bio);

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

/* see 7eaceac block: remove per-queue plugging */
#ifdef blk_queue_plugged
static inline void drbd_plug_device(struct request_queue *q)
{
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
#else
static inline void drbd_plug_device(struct request_queue *q)
{
}
#endif

static inline int drbd_backing_bdev_events(struct gendisk *disk)
{
#if defined(__disk_stat_inc)
	/* older kernel */
	return (int)disk_stat_read(disk, sectors[0])
	     + (int)disk_stat_read(disk, sectors[1]);
#else
	/* recent kernel */
	return (int)part_stat_read(&disk->part0, sectors[0])
	     + (int)part_stat_read(&disk->part0, sectors[1]);
#endif
}

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

/* How do we tell the block layer to pass down flush/fua? */
#ifndef COMPAT_HAVE_BLK_QUEUE_WRITE_CACHE
static inline void blk_queue_write_cache(struct request_queue *q, bool enabled, bool fua)
{
#if defined(REQ_FLUSH) && !defined(REQ_HARDBARRIER)
/* Linux version 2.6.37 up to 4.7
 * needs blk_queue_flush() to announce driver support */
	blk_queue_flush(q, (enabled ? REQ_FLUSH : 0) | (fua ? REQ_FUA : 0));
#else
/* Older kernels either flag affected bios with BIO_RW_BARRIER, or do not know
 * how to handle this at all. No need to "announce" driver support. */
#endif
}
#endif

/* bio -> bi_rw/bi_opf REQ_* and BIO_RW_* REQ_OP_* compat stuff {{{1 */
/* REQ_* and BIO_RW_* flags have been moved around in the tree,
 * and have finally been "merged" with
 * 7b6d91daee5cac6402186ff224c3af39d79f4a0e and
 * 7cc015811ef8992dfcce314d0ed9642bc18143d1
 * We communicate between different systems,
 * so we have to somehow semantically map the bi_opf flags
 * bi_opf (some kernel version) -> data packet flags -> bi_opf (other kernel version)
 */

#if defined(COMPAT_HAVE_BIO_SET_OP_ATTRS) && \
	!(defined(RHEL_RELEASE_CODE /* 7.4 broke our compat detection here */) && \
			LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))

/* [4.8 ... ] Linux 4.8 split bio OPs and FLAGs {{{2 */

#define DRBD_REQ_PREFLUSH	REQ_PREFLUSH
#define DRBD_REQ_FUA		REQ_FUA
#define DRBD_REQ_SYNC		REQ_SYNC

	/* long gone */
#define DRBD_REQ_HARDBARRIER	0
#define DRBD_REQ_UNPLUG		0

	/* became an op, no longer flag */
#define DRBD_REQ_DISCARD	0
#define DRBD_REQ_WSAME		0

/* Gone in Linux 4.10 */
#ifndef WRITE_SYNC
#define WRITE_SYNC REQ_SYNC
#endif

#define COMPAT_WRITE_SAME_CAPABLE

#ifndef COMPAT_HAVE_REQ_OP_WRITE_ZEROES
#define REQ_OP_WRITE_ZEROES (-3u)
#endif

#elif defined(BIO_FLUSH)
/* RHEL 6.1 ("not quite 2.6.32") backported FLUSH/FUA as BIO_RW_FLUSH/FUA {{{2
 * and at that time also introduced the defines BIO_FLUSH/FUA.
 * There is also REQ_FLUSH/FUA, but these do NOT share
 * the same value space as the bio rw flags, yet.
 */

#define DRBD_REQ_PREFLUSH	(1UL << BIO_RW_FLUSH)
#define DRBD_REQ_FUA		(1UL << BIO_RW_FUA)
#define DRBD_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)
#define DRBD_REQ_DISCARD	(1UL << BIO_RW_DISCARD)
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)

#define REQ_RAHEAD		(1UL << BIO_RW_AHEAD)

#elif defined(REQ_FLUSH)	/* [2.6.36 .. 4.7] introduced in 2.6.36, {{{2
				 * now equivalent to bi_rw */

#define DRBD_REQ_SYNC		REQ_SYNC
#define DRBD_REQ_PREFLUSH	REQ_FLUSH
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

/* again: testing on this _inside_ the ifdef REQ_FLUSH,
 * see 721a960 block: kill off REQ_UNPLUG */
#ifdef REQ_UNPLUG
#define DRBD_REQ_UNPLUG		REQ_UNPLUG
#else
#define DRBD_REQ_UNPLUG		0
#endif

#ifdef REQ_WRITE_SAME
#define DRBD_REQ_WSAME         REQ_WRITE_SAME
#define COMPAT_WRITE_SAME_CAPABLE
#endif

#else				/* [<=2.6.35] "older", and hopefully not {{{2
				 * "partially backported" kernel */

#define REQ_RAHEAD             (1UL << BIO_RW_AHEAD)

#if defined(BIO_RW_SYNC)
/* see upstream commits
 * 213d9417fec62ef4c3675621b9364a667954d4dd,
 * 93dbb393503d53cd226e5e1f0088fe8f4dbaa2b8
 * later, the defines even became an enum ;-) */
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNC)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_SYNC)
#else
/* cannot test on defined(BIO_RW_SYNCIO), it may be an enum */
#define DRBD_REQ_SYNC		(1UL << BIO_RW_SYNCIO)
#define DRBD_REQ_UNPLUG		(1UL << BIO_RW_UNPLUG)
#endif

#define DRBD_REQ_PREFLUSH	(1UL << BIO_RW_BARRIER)
/* REQ_FUA has been around for a longer time,
 * without a direct equivalent in bi_rw. */
#define DRBD_REQ_FUA		(1UL << BIO_RW_BARRIER)
#define DRBD_REQ_HARDBARRIER	(1UL << BIO_RW_BARRIER)

#define COMPAT_MAYBE_RETRY_HARDBARRIER

/* we don't support DISCARDS yet, anyways.
 * cannot test on defined(BIO_RW_DISCARD), it may be an enum */
#define DRBD_REQ_DISCARD	0
#endif

#ifdef REQ_NOUNMAP
#define DRBD_REQ_NOUNMAP REQ_NOUNMAP
#else
#define DRBD_REQ_NOUNMAP	0
#endif

/* this results in:
	bi_opf   -> dp_flags

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
*/

/* fallback defines for older kernels {{{2 */

#ifndef DRBD_REQ_WSAME
#define DRBD_REQ_WSAME		0
#endif

#ifndef WRITE_FLUSH
#ifndef WRITE_SYNC
#error  FIXME WRITE_SYNC undefined??
#endif
#define WRITE_FLUSH       (WRITE_SYNC | DRBD_REQ_PREFLUSH)
#endif

#ifndef REQ_NOIDLE
/* introduced in aeb6faf (2.6.30), relevant for CFQ */
#define REQ_NOIDLE 0
#endif

#ifndef COMPAT_HAVE_REFCOUNT_INC
#define refcount_inc(R) atomic_inc(R)
#define refcount_read(R) atomic_read(R)
#define refcount_dec_and_test(R) atomic_dec_and_test(R)
#define refcount_set(R, V) atomic_set(R, V)
#endif

#ifndef KREF_INIT
#define KREF_INIT(N) { ATOMIC_INIT(N) }
#endif

#define _adjust_ra_pages(qrap, brap) do { \
	if (qrap != brap) { \
		drbd_info(device, "Adjusting my ra_pages to backing device's (%lu -> %lu)\n", qrap, brap); \
		qrap = brap; \
	} \
} while(0)

#ifdef BDI_CAP_STABLE_WRITES /* >= v3.9 */
#define set_bdi_cap_stable_writes(cap)	do { (cap) |= BDI_CAP_STABLE_WRITES; } while (0)
#else /* < v3.9 */
#warning "BDI_CAP_STABLE_WRITES not available"
#define set_bdi_cap_stable_writes(cap)	do { } while (0)
#endif

#ifdef COMPAT_HAVE_POINTER_BACKING_DEV_INFO /* >= v4.11 */
#define bdi_from_device(device) (device->ldev->backing_bdev->bd_disk->queue->backing_dev_info)
#define init_bdev_info(bdev_info, drbd_congested, device) do { \
	(bdev_info)->congested_fn = drbd_congested; \
	(bdev_info)->congested_data = device; \
	set_bdi_cap_stable_writes(bdev_info->capabilities); \
} while(0)
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->backing_dev_info->ra_pages, (b)->backing_dev_info->ra_pages)
#else /* < v4.11 */
#define bdi_rw_congested(BDI) bdi_rw_congested(&BDI)
#define bdi_congested(BDI, BDI_BITS) bdi_congested(&BDI, (BDI_BITS))
#define bdi_from_device(device) (&device->ldev->backing_bdev->bd_disk->queue->backing_dev_info)
#define init_bdev_info(bdev_info, drbd_congested, device) do { \
	(bdev_info).congested_fn = drbd_congested; \
	(bdev_info).congested_data = device; \
	set_bdi_cap_stable_writes((bdev_info).capabilities); \
} while(0)
#define adjust_ra_pages(q, b) _adjust_ra_pages((q)->backing_dev_info.ra_pages, (b)->backing_dev_info.ra_pages)
#endif


#if defined(COMPAT_HAVE_BIO_SET_OP_ATTRS) /* compat for Linux before 4.8 {{{2 */
#if (defined(RHEL_RELEASE_CODE /* 7.4 broke our compat detection here */) && \
			LINUX_VERSION_CODE < KERNEL_VERSION(4,8,0))
/* Thank you RHEL 7.4 for backporting just enough to break existing compat code,
 * but not enough to make it work for us without additional compat code.
 */
#define COMPAT_NEED_BI_OPF_AND_SUBMIT_BIO_COMPAT_DEFINES 1
# ifdef COMPAT_HAVE_REQ_OP_WRITE_ZEROES
#  error "unexpectedly defined REQ_OP_WRITE_ZEROES, double check compat wrappers!"
# else
#  define  REQ_OP_WRITE_ZEROES (-3u)
# endif
#endif
#else /* !defined(COMPAT_HAVE_BIO_SET_OP_ATTRS) */
#define COMPAT_NEED_BI_OPF_AND_SUBMIT_BIO_COMPAT_DEFINES 1

#ifndef REQ_WRITE
/* before 2.6.36 */
#define REQ_WRITE 1
#endif

enum req_op {
       REQ_OP_READ,				/* 0 */
       REQ_OP_WRITE		= REQ_WRITE,	/* 1 */

       /* Not yet a distinguished op,
	* but identified via FLUSH/FUA flags.
	* If at all. */
       REQ_OP_FLUSH		= REQ_OP_WRITE,

	/* These may be not supported in older kernels.
	 * In that case, the DRBD_REQ_* will be 0,
	 * bio_op() aka. op_from_rq_bits() will never return these,
	 * and we map the REQ_OP_* to something stupid.
	 */
       REQ_OP_DISCARD		= DRBD_REQ_DISCARD ?: -1,
       REQ_OP_WRITE_SAME	= DRBD_REQ_WSAME   ?: -2,
       REQ_OP_WRITE_ZEROES	= -3,
};
#define bio_op(bio)                            (op_from_rq_bits((bio)->bi_rw))

static inline void bio_set_op_attrs(struct bio *bio, const int op, const long flags)
{
	/* If we explicitly issue discards or write_same, we use
	 * blkdev_issue_discard() and blkdev_issue_write_same() helpers.
	 * If we implicitly submit them, we just pass on a cloned bio to
	 * generic_make_request().  We expect to use bio_set_op_attrs() with
	 * REQ_OP_READ or REQ_OP_WRITE only. */
	BUG_ON(!(op == REQ_OP_READ || op == REQ_OP_WRITE));
	bio->bi_rw |= (op | flags);
}

static inline int op_from_rq_bits(u64 flags)
{
	if (flags & DRBD_REQ_DISCARD)
		return REQ_OP_DISCARD;
	else if (flags & DRBD_REQ_WSAME)
		return REQ_OP_WRITE_SAME;
	else if (flags & REQ_WRITE)
		return REQ_OP_WRITE;
	else
		return REQ_OP_READ;
}
#endif

#ifdef COMPAT_NEED_BI_OPF_AND_SUBMIT_BIO_COMPAT_DEFINES
#define bi_opf bi_rw
#define submit_bio(__bio)	submit_bio(__bio->bi_rw, __bio)
/* see comment in above compat enum req_op */
#define REQ_OP_FLUSH		REQ_OP_WRITE
#endif
/* }}}1 bio -> bi_rw/bi_opf REQ_* and BIO_RW_* REQ_OP_* compat stuff */

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

/* Introduced with 2.6.26. See include/linux/jiffies.h */
#ifndef time_is_before_eq_jiffies
#define time_is_before_jiffies(a) time_after(jiffies, a)
#define time_is_after_jiffies(a) time_before(jiffies, a)
#define time_is_before_eq_jiffies(a) time_after_eq(jiffies, a)
#define time_is_after_eq_jiffies(a) time_before_eq(jiffies, a)
#endif

#ifndef time_in_range
#define time_in_range(a,b,c) \
	(time_after_eq(a,b) && \
	 time_before_eq(a,c))
#endif

/* history of bioset_create():
 *  v4.13  011067b  blk: replace bioset_create_nobvec() with a flags arg to bioset_create()
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad, int flags)
 *
 *  v3.18  d8f429e  block: add bioset_create_nobvec()
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *  +struct bio_set *bioset_create_nobvec(unsigned int pool_size, unsigned int front_pad)
 *
 *  v3.16  f9c78b2  block: move bio.c and bio-integrity.c from fs/ to block/
 *  +struct bio_set *bioset_create(unsigned int pool_size, unsigned int front_pad)
 *
 *  --- we don't care for older than 2.3.32 ---
 */
#if defined(COMPAT_HAVE_BIOSET_NEED_BVECS)
/* all good, "modern" kernel before v4.18 */
#elif defined(COMPAT_HAVE_BIOSET_CREATE_FRONT_PAD)
# define bioset_create(pool_size, front_pad, flags) bioset_create(pool_size, front_pad)
#elif defined(COMPAT_HAVE_BIOSET_INIT)
/* => v4.18*/
#else
# error "drbd compat layer broken"
#endif


#if !(defined(COMPAT_HAVE_RB_AUGMENT_FUNCTIONS) && \
      defined(AUGMENTED_RBTREE_SYMBOLS_EXPORTED))

/*
 * Make sure the replacements for the augmented rbtree helper functions do not
 * clash with functions the kernel implements but does not export.
 */
#define rb_augment_f drbd_rb_augment_f
#define rb_augment_path drbd_rb_augment_path
#define rb_augment_insert drbd_rb_augment_insert
#define rb_augment_erase_begin drbd_rb_augment_erase_begin
#define rb_augment_erase_end drbd_rb_augment_erase_end

typedef void (*rb_augment_f)(struct rb_node *node, void *data);

static inline void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
static inline void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
static inline struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
static inline void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}
#endif

#ifndef IDR_GET_NEXT_EXPORTED
/* Body in compat/idr.c */
extern void *idr_get_next(struct idr *idp, int *nextidp);
#endif

#ifndef RCU_INITIALIZER
#define RCU_INITIALIZER(v) (typeof(*(v)) *)(v)
#endif
#ifndef RCU_INIT_POINTER
#define RCU_INIT_POINTER(p, v) \
	do { \
		p = RCU_INITIALIZER(v); \
	} while (0)
#endif

#ifndef list_entry_rcu
#ifndef rcu_dereference_raw
/* see c26d34a rcu: Add lockdep-enabled variants of rcu_dereference() */
#define rcu_dereference_raw(p) rcu_dereference(p)
#endif
#define list_entry_rcu(ptr, type, member) \
	({typeof (*ptr) *__ptr = (typeof (*ptr) __force *)ptr; \
	 container_of((typeof(ptr))rcu_dereference_raw(__ptr), type, member); \
	})
#endif

#ifndef list_next_entry
/* introduced in 008208c (v3.13-rc1) */
#define list_next_entry(pos, member) \
        list_entry((pos)->member.next, typeof(*(pos)), member)
#endif

/*
 * Introduced in 930631ed (v2.6.19-rc1).
 */
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

/*
 * IS_ALIGNED() was added to <linux/kernel.h> in mainline commit 0c0e6195 (and
 * improved in f10db627); 2.6.24-rc1.
 */
#ifndef IS_ALIGNED
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)
#endif

/*
 * NLA_TYPE_MASK and nla_type() were added to <linux/netlink.h> in mainline
 * commit 8f4c1f9b; v2.6.24-rc1.  Before that, none of the nlattr->nla_type
 * flags had a special meaning.
 */

#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK ~0

static inline int nla_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

#endif

/*
 * v4.12 fceb6435e852 netlink: pass extended ACK struct to parsing functions
 * and some preparation commits introduce a new "netlink extended ack" error
 * reporting mechanism. For now, only work around that here.  As trigger, use
 * NETLINK_MAX_COOKIE_LEN introduced somewhere in the middle of that patchset.
 */
#ifndef NETLINK_MAX_COOKIE_LEN
#include <net/netlink.h>
#define nla_parse_nested(tb, maxtype, nla, policy, extack) \
       nla_parse_nested(tb, maxtype, nla, policy)
#endif

/*
 * list_for_each_entry_continue_rcu() was introduced in mainline commit
 * 254245d2 (v2.6.33-rc1).
 */
#ifndef list_for_each_entry_continue_rcu
#define list_for_each_entry_continue_rcu(pos, head, member)             \
	for (pos = list_entry_rcu(pos->member.next, typeof(*pos), member); \
	     &pos->member != (head);    \
	     pos = list_entry_rcu(pos->member.next, typeof(*pos), member))

#endif

#ifndef SK_CAN_REUSE
/* This constant was introduced by Pavel Emelyanov <xemul@parallels.com> on
   Thu Apr 19 03:39:36 2012 +0000. Before the release of linux-3.5
   commit 4a17fd52 sock: Introduce named constants for sk_reuse */
#define SK_CAN_REUSE   1
#endif

#ifdef COMPAT_KMAP_ATOMIC_PAGE_ONLY
/* see 980c19e3
 * highmem: mark k[un]map_atomic() with two arguments as deprecated */
#define drbd_kmap_atomic(page, km)	kmap_atomic(page)
#define drbd_kunmap_atomic(addr, km)	kunmap_atomic(addr)
#else
#define drbd_kmap_atomic(page, km)	kmap_atomic(page, km)
#define drbd_kunmap_atomic(addr, km)	kunmap_atomic(addr, km)
#endif

#if !defined(for_each_set_bit) && defined(for_each_bit)
#define for_each_set_bit(bit, addr, size) for_each_bit(bit, addr, size)
#endif

#ifndef COMPAT_HAVE_THREE_PARAMATER_HLIST_FOR_EACH_ENTRY
#undef hlist_for_each_entry
#define hlist_for_each_entry(pos, head, member)				\
	for (pos = hlist_entry((head)->first, typeof(*(pos)), member);	\
	     pos;							\
	     pos = hlist_entry((pos)->member.next, typeof(*(pos)), member))
#endif

#ifndef COMPAT_HAVE_PRANDOM_U32
static inline u32 prandom_u32(void)
{
	return random32();
}
#endif

#ifdef COMPAT_HAVE_NETLINK_CB_PORTID
#define NETLINK_CB_PORTID(skb) NETLINK_CB(skb).portid
#else
#define NETLINK_CB_PORTID(skb) NETLINK_CB(skb).pid
#endif

#ifndef COMPAT_HAVE_PROC_PDE_DATA
#define PDE_DATA(inode) PDE(inode)->data
#endif

#ifndef list_first_entry
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#endif

#ifndef list_first_entry_or_null
#define list_first_entry_or_null(ptr, type, member) \
	(!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#endif

#ifndef COMPAT_HAVE_IDR_ALLOC
static inline int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp_mask)
{
	int rv, got;

	if (!idr_pre_get(idr, gfp_mask))
		return -ENOMEM;
	rv = idr_get_new_above(idr, ptr, start, &got);
	if (rv < 0)
		return rv;

	if (got >= end) {
		idr_remove(idr, got);
		return -ENOSPC;
	}

	return got;
}
#endif

#ifndef BLKDEV_ISSUE_ZEROOUT_EXPORTED
/* Was introduced with 2.6.34 */
extern int blkdev_issue_zeroout(struct block_device *bdev, sector_t sector,
				sector_t nr_sects, gfp_t gfp_mask);
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, flags /* = NOUNMAP */) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#else
/* synopsis changed a few times, though */
#if  defined(BLKDEV_ZERO_NOUNMAP)
/* >= v4.12 */
/* use blkdev_issue_zeroout() as written out in the actual source code.
 * right now, we only use it with flags = BLKDEV_ZERO_NOUNMAP */
#elif  defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD)
/* no BLKDEV_ZERO_NOUNMAP as last parameter, but a bool discard instead */
/* still need to define BLKDEV_ZERO_NOUNMAP, to compare against 0 */
#define BLKDEV_ZERO_NOUNMAP 1
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, flags /* = NOUNMAP */) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP, (flags) == 0 /* bool discard */)
#else /* !defined(COMPAT_BLKDEV_ISSUE_ZEROOUT_DISCARD) */
#define blkdev_issue_zeroout(BDEV, SS, NS, GFP, discard) \
	blkdev_issue_zeroout(BDEV, SS, NS, GFP)
#endif
#endif


#if !defined(QUEUE_FLAG_DISCARD) || !defined(QUEUE_FLAG_SECDISCARD)
# define queue_flag_set_unlocked(F, Q)				\
	({							\
		if ((F) != -1)					\
			queue_flag_set_unlocked(F, Q);		\
	})

# define queue_flag_clear_unlocked(F, Q)			\
	({							\
		if ((F) != -1)					\
			queue_flag_clear_unlocked(F, Q);	\
	})

# ifndef blk_queue_discard
#  define blk_queue_discard(q)   (0)
#  define QUEUE_FLAG_DISCARD    (-1)
# endif

# ifndef blk_queue_secdiscard
#  define blk_queue_secdiscard(q)   (0)
#  define QUEUE_FLAG_SECDISCARD    (-1)
# endif
#endif

#ifdef COMPAT_HAVE_STRUCT_BVEC_ITER
/* since Linux 3.14 we have a new way to iterate a bio
   Mainline commits:
   7988613b0 block: Convert bio_for_each_segment() to bvec_iter
   4f024f379 block: Abstract out bvec iterator
 */
#define DRBD_BIO_VEC_TYPE struct bio_vec
#define DRBD_ITER_TYPE struct bvec_iter
#define BVD .
#define DRBD_BIO_BI_SECTOR(BIO) ((BIO)->bi_iter.bi_sector)
#define DRBD_BIO_BI_SIZE(BIO) ((BIO)->bi_iter.bi_size)
#else
#define DRBD_BIO_VEC_TYPE struct bio_vec *
#define DRBD_ITER_TYPE int
#define BVD ->
#define DRBD_BIO_BI_SECTOR(BIO) ((BIO)->bi_sector)
#define DRBD_BIO_BI_SIZE(BIO) ((BIO)->bi_size)

/* Attention: The backward comp version of this macro accesses bio from
   calling namespace */
#define bio_iter_last(BVEC, ITER) ((ITER) == bio->bi_vcnt - 1)
#endif

#ifndef list_next_rcu
#define list_next_rcu(list)	(*((struct list_head **)(&(list)->next)))
#endif

#ifndef list_first_or_null_rcu
#define list_first_or_null_rcu(ptr, type, member) \
({ \
	struct list_head *__ptr = (ptr); \
	struct list_head *__next = ACCESS_ONCE(__ptr->next); \
	likely(__ptr != __next) ? list_entry_rcu(__next, type, member) : NULL; \
})
#endif

#if defined(COMPAT_HAVE_GENERIC_START_IO_ACCT_Q_RW_SECT_PART)
/* void generic_start_io_acct(struct request_queue *q,
 *		int rw, unsigned long sectors, struct hd_struct *part); */
#elif defined(COMPAT_HAVE_GENERIC_START_IO_ACCT_RW_SECT_PART)
/* void generic_start_io_acct(
 *		int rw, unsigned long sectors, struct hd_struct *part); */
#define generic_start_io_acct(q, rw, sect, part) generic_start_io_acct(rw, sect, part)
#define generic_end_io_acct(q, rw, part, start) generic_end_io_acct(rw, part, start)

#elif defined(__disk_stat_inc)
/* too old, we don't care */
#warning "io accounting disabled"
#else

static inline void generic_start_io_acct(struct request_queue *q,
		int rw, unsigned long sectors, struct hd_struct *part)
{
	int cpu;

	cpu = part_stat_lock();
	part_round_stats(cpu, part);
	part_stat_inc(cpu, part, ios[rw]);
	part_stat_add(cpu, part, sectors[rw], sectors);
	(void) cpu; /* The macro invocations above want the cpu argument, I do not like
		       the compiler warning about cpu only assigned but never used... */
	/* part_inc_in_flight(part, rw); */
	{ BUILD_BUG_ON(sizeof(atomic_t) != sizeof(part->in_flight[0])); }
	atomic_inc((atomic_t*)&part->in_flight[rw]);
	part_stat_unlock();
}

static inline void generic_end_io_acct(struct request_queue *q,
		int rw, struct hd_struct *part, unsigned long start_time)
{
	unsigned long duration = jiffies - start_time;
	int cpu;

	cpu = part_stat_lock();
	part_stat_add(cpu, part, ticks[rw], duration);
	part_round_stats(cpu, part);
	/* part_dec_in_flight(part, rw); */
	atomic_dec((atomic_t*)&part->in_flight[rw]);
	part_stat_unlock();
}
#endif /* __disk_stat_inc, COMPAT_HAVE_GENERIC_START_IO_ACCT ... */


#ifndef COMPAT_SOCK_CREATE_KERN_HAS_FIVE_PARAMETERS
#define sock_create_kern(N,F,T,P,S) sock_create_kern(F,T,P,S)
#endif

#ifndef COMPAT_HAVE_WB_CONGESTED_ENUM
#define WB_async_congested BDI_async_congested
#define WB_sync_congested BDI_sync_congested
#endif

#ifndef COMPAT_HAVE_SIMPLE_POSITIVE
#include <linux/dcache.h>
static inline int simple_positive(struct dentry *dentry)
{
        return dentry->d_inode && !d_unhashed(dentry);
}
#endif

#ifndef COMPAT_HAVE_KVFREE
#include <linux/mm.h>
static inline void kvfree(void /* intentionally discarded const */ *addr)
{
	if (is_vmalloc_addr(addr))
		vfree(addr);
	else
		kfree(addr);
}
#endif

#ifdef blk_queue_plugged
/* pre 7eaceac block: remove per-queue plugging
 * Code has been converted over to the new explicit on-stack plugging ...
 *
 * provide dummy struct blk_plug and blk_start_plug/blk_finish_plug,
 * so the main code won't be cluttered with ifdef.
 */
struct blk_plug { };
#if 0
static void blk_start_plug(struct blk_plug *plug) {};
static void blk_finish_plug(struct blk_plug *plug) {};
#else
#define blk_start_plug(plug) do { (void)plug; } while (0)
#define blk_finish_plug(plug) do { } while (0)
#endif
#endif


#ifdef COMPAT_NEED_D_INODE
static inline struct inode *d_inode(struct dentry *dentry)
{
	return dentry->d_inode;
}
#endif

#ifndef COMPAT_HAVE_INODE_LOCK
/* up to kernel 2.6.38 inclusive, there was a
 * linux/writeback.h:extern spinlock_t inode_lock;
 * which was implicitly included.
 * avoid error: 'inode_lock' redeclared as different kind of symbol */
#define inode_lock(i) drbd_inode_lock(i)
static inline void inode_lock(struct inode *inode)
{
	mutex_lock(&inode->i_mutex);
}

static inline void inode_unlock(struct inode *inode)
{
	mutex_unlock(&inode->i_mutex);
}
#endif

#if !(defined(COMPAT_HAVE_AHASH_REQUEST_ON_STACK) && \
      defined(COMPAT_HAVE_SHASH_DESC_ON_STACK) &&    \
      defined COMPAT_HAVE_SHASH_DESC_ZERO)
#include <crypto/hash.h>

#ifndef COMPAT_HAVE_AHASH_REQUEST_ON_STACK
#define AHASH_REQUEST_ON_STACK(name, ahash)			   \
	char __##name##_desc[sizeof(struct ahash_request) +	   \
		crypto_ahash_reqsize(ahash)] CRYPTO_MINALIGN_ATTR; \
	struct ahash_request *name = (void *)__##name##_desc
#endif

#ifndef COMPAT_HAVE_SHASH_DESC_ON_STACK
#define SHASH_DESC_ON_STACK(shash, ctx)				  \
	char __##shash##_desc[sizeof(struct shash_desc) +	  \
		crypto_shash_descsize(ctx)] CRYPTO_MINALIGN_ATTR; \
	struct shash_desc *shash = (struct shash_desc *)__##shash##_desc
#endif

#ifndef COMPAT_HAVE_SHASH_DESC_ZERO
#ifndef barrier_data
#define barrier_data(ptr) barrier()
#endif
static inline void ahash_request_zero(struct ahash_request *req)
{
	/* memzero_explicit(...) */
	memset(req, 0, sizeof(*req) + crypto_ahash_reqsize(crypto_ahash_reqtfm(req)));
	barrier_data(req);
}

static inline void shash_desc_zero(struct shash_desc *desc)
{
	/* memzero_explicit(...) */
	memset(desc, 0, sizeof(*desc) + crypto_shash_descsize(desc->tfm));
	barrier_data(desc);
}
#endif
#endif

#ifdef COMPAT_HAVE_ATOMIC_DEC_IF_POSITIVE_LINUX
#include <linux/atomic.h>
#else
static inline int atomic_dec_if_positive(atomic_t *v)
{
        int c, old, dec;
        c = atomic_read(v);
        for (;;) {
                dec = c - 1;
                if (unlikely(dec < 0))
                        break;
                old = atomic_cmpxchg((v), c, dec);
                if (likely(old == c))
                        break;
                c = old;
        }
        return dec;
}
#endif

#ifndef COMPAT_HAVE_RATELIMIT_STATE_INIT
static inline void ratelimit_state_init(struct ratelimit_state *rs,
                                        int interval, int burst)
{
	rs->interval = interval;
	rs->burst = burst;
	rs->printed = 0;
	rs->missed = 0;
	rs->begin = 0;
}
#endif

#ifndef COMPAT_HAVE_IDR_IS_EMPTY
static inline bool idr_is_empty(struct idr *idr)
{
	int id = 0;
	return idr_get_next(idr, &id) == NULL;
}
#endif

/* RDMA related */
#ifndef COMPAT_HAVE_IB_CQ_INIT_ATTR
#include <rdma/ib_verbs.h>

struct ib_cq_init_attr {
	unsigned int    cqe;
	int             comp_vector;
	u32             flags;
};

static inline struct ib_cq *
drbd_ib_create_cq(struct ib_device *device,
		  ib_comp_handler comp_handler,
		  void (*event_handler)(struct ib_event *, void *),
		  void *cq_context,
		  const struct ib_cq_init_attr *cq_attr)
{
	return ib_create_cq(device, comp_handler, event_handler, cq_context,
			    cq_attr->cqe, cq_attr->comp_vector);
}

#define ib_create_cq(DEV, COMP_H, EVENT_H, CTX, ATTR) \
	drbd_ib_create_cq(DEV, COMP_H, EVENT_H, CTX, ATTR)
#endif


#ifndef COMPAT_RDMA_CREATE_ID_HAS_NET_NS
/* Since linux v4.4 it has a network namespace as first argument */
#define rdma_create_id(NS, H, C, P, T) rdma_create_id(H, C, P, T)
#endif

#ifndef COMPAT_IB_QUERY_DEVICE_HAS_3_PARAMS
/* Since linux v4.5 ib_query_device() is gone and device->query_device() is used
 * device->query_device() exists for all interesting kernel versions,
 * but the number of arguments got changed over time */
#define query_device(D, A, U) query_device(D, A)
#endif

#ifndef COMPAT_IB_ALLOC_PD_HAS_2_PARAMS
#define ib_alloc_pd(dev, flags) ib_alloc_pd(dev)
#endif
/* RDMA */

#ifndef COMPAT_HAVE_FILE_INODE
static inline struct inode *file_inode(const struct file *file)
{
	return file->f_dentry->d_inode;
}
#endif

#ifndef COMPAT_HAVE_KMALLOC_ARRAY
#define kmalloc_array(a, b, c) kmalloc((a) * (b), (c))
#endif

#ifdef COMPAT_HAVE_BIO_BI_BDEV
#define bio_set_dev(bio, bdev) (bio)->bi_bdev = bdev
#endif

#ifdef COMPAT_HAVE_TIMER_SETUP
/* starting with v4.16 new timer interface*/
#define DRBD_TIMER_FN_ARG struct timer_list *t
#define DRBD_TIMER_ARG2OBJ(OBJ, MEMBER) from_timer(OBJ, t, MEMBER)
#define drbd_timer_setup(OBJ, MEMBER, TIMER_FN) timer_setup(&OBJ->MEMBER, TIMER_FN, 0)
#define DRBD_TIMER_CALL_ARG(OBJ, MEMBER) &OBJ->MEMBER
#else
/* timer interface before v4.16 */
#define DRBD_TIMER_FN_ARG unsigned long data
#define DRBD_TIMER_ARG2OBJ(OBJ, MEMBER) (typeof(OBJ)) data
#define drbd_timer_setup(OBJ, MEMBER, TIMER_FN) setup_timer(&OBJ->MEMBER, TIMER_FN, (unsigned long)OBJ)
#define DRBD_TIMER_CALL_ARG(OBJ, MEMBER) (unsigned long) OBJ
#endif


#ifndef COMPAT_HAVE_PROC_CREATE_SINGLE
extern struct proc_dir_entry *proc_create_single(const char *name, umode_t mode,
		struct proc_dir_entry *parent,
		int (*show)(struct seq_file *, void *));
#endif

#ifndef COMPAT_HAVE_BIOSET_INIT
#define mempool_free(V, P) mempool_free(V, *P)
#define mempool_alloc(P, F) mempool_alloc(*P, F)

#ifndef COMPAT_HAVE_BIO_CLONE_FAST
# define bio_clone_fast(bio, gfp, bio_set) bio_clone(bio, gfp)
#else
# define bio_clone_fast(BIO, GFP, P) bio_clone_fast(BIO, GFP, *P)
#endif

#define bio_alloc_bioset(GFP, n, P) bio_alloc_bioset(GFP, n, *P)
#define DRBD_MEMPOOL_T mempool_t *
#define DRBD_BIO_SET   bio_set *
static inline void bioset_exit(struct bio_set **bs)
{
	if (*bs) {
		bioset_free(*bs);
		*bs = NULL;
	}
}
static inline void mempool_exit(mempool_t **p)
{
	if (*p) {
		mempool_destroy(*p);
		*p = NULL;
	}
}
#if defined(COMPAT_HAVE_BIOSET_NEED_BVECS)
#define bioset_init(BS, S, FP, F) __bioset_init(BS, S, FP, F)
#else
#define bioset_init(BS, S, FP, F) __bioset_init(BS, S, FP, 0)
#endif
static inline int
__bioset_init(struct bio_set **bs, unsigned int size, unsigned int front_pad, int flags)
{
	*bs = bioset_create(size, front_pad, flags);
	return *bs == NULL ? -ENOMEM : 0;
}
static inline int
mempool_init_page_pool(mempool_t **pool, int min_nr, int order)
{
	*pool = mempool_create_page_pool(min_nr, order);
	return *pool == NULL ? -ENOMEM : 0;
}
static inline int
mempool_init_slab_pool(mempool_t **pool, int min_nr, struct kmem_cache *mem_cache)
{
	*pool = mempool_create_slab_pool(min_nr, mem_cache);
	return *pool == NULL ? -ENOMEM : 0;
}
static inline bool
bioset_initialized(struct bio_set **bs)
{
	return *bs != NULL;
}
#else
#define DRBD_MEMPOOL_T mempool_t
#define DRBD_BIO_SET   bio_set
#endif

#if defined(COMPAT_BEFORE_4_13_KERNEL_READ)
#define kernel_read(F, B, C, P) kernel_read(F, *(P), B, C)
#endif

#ifdef COMPAT_HAVE_MAX_SEND_RECV_SGE
#define MAX_SGE(ATTR) min((ATTR).max_send_sge, (ATTR).max_recv_sge)
#else
#define MAX_SGE(ATTR) (ATTR).max_sge
#endif

#ifndef COMPAT_HAVE_TIME64_TO_TM
static inline void time64_to_tm(__s64 totalsecs, int offset, struct tm *result)
{
	time_to_tm((time_t)totalsecs, offset, result);
}
#endif
#ifndef ktime_to_timespec64
#define ktime_to_timespec64(kt) ktime_to_timespec(kt)
#define timespec64 timespec
#endif

#endif
