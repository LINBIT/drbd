/*
-*- linux-c -*-
   drbd_bitmap.c
   Kernel module for 2.6.x Kernels

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2004-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2004-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2004-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/drbd.h>
#include "drbd_int.h"

/* OPAQUE outside this file!
 * interface defined in drbd_int.h

 * convetion:
 * function name drbd_bm_... => used elsewhere, "public".
 * function name      bm_... => internal to implementation, "private".

 * Note that since find_first_bit returns int, at the current granularity of
 * the bitmap (4KB per byte), this implementation "only" supports up to
 * 1<<(32+12) == 16 TB...
 * other shortcomings in the meta data area may reduce this even further.
 *
 * we will eventually change the implementation to not allways hold the full
 * bitmap in memory, but only some 'lru_cache' of the on disk bitmap.

 * THINK
 * I'm not yet sure whether this file should be bits only,
 * or wether I want it to do all the sector<->bit calculation in here.
 */

/*
 * NOTE
 *  Access to the *bm is protected by bm_lock.
 *  It is safe to read the other members within the lock.
 *
 *  drbd_bm_set_bits is called from bio_endio callbacks,
 *  We may be called with irq already disabled,
 *  so we need spin_lock_irqsave().
 * FIXME
 *  for performance reasons, when we _know_ we have irq disabled, we should
 *  probably introduce some _in_irq variants, so we know to only spin_lock().
 *
 * FIXME
 *  Actually you need to serialize all resize operations.
 *  but then, resize is a drbd state change, and it should be serialized
 *  already. Unfortunately it is not (yet), so two concurrent resizes, like
 *  attach storage (drbdsetup) and receive the peers size (drbd receiver)
 *  may eventually blow things up.
 * Therefore,
 *  you may only change the other members when holding
 *  the bm_change mutex _and_ the bm_lock.
 *  thus reading them holding either is safe.
 *  this is sort of overkill, but I rather do it right
 *  than have two resize operations interfere somewhen.
 */
struct drbd_bitmap {
	unsigned long *bm;
	spinlock_t bm_lock;
	/* WARNING unsigned long bm_fo and friends:
	 * 32bit number of bit offset is just enough for 512 MB bitmap.
	 * it will blow up if we make the bitmap bigger...
	 * not that it makes much sense to have a bitmap that large,
	 * rather change the granularity to 16k or 64k or something.
	 * (that implies other problems, however...)
	 */
	unsigned long bm_fo;        /* next offset for drbd_bm_find_next */
	unsigned long bm_set;       /* nr of set bits; THINK maybe atomic_t? */
	unsigned long bm_bits;
	size_t   bm_words;
	sector_t bm_dev_capacity;
	struct semaphore bm_change; /* serializes resize operations */

	atomic_t bm_async_io;
	wait_queue_head_t bm_io_wait;

	unsigned long  bm_flags;

	/* debugging aid, in case we are still racy somewhere */
	unsigned long  bm_line;
	char          *bm_file;
};

/* definition of bits in bm_flags */
#define BM_LOCKED 0
#define BM_MD_IO_ERROR (BITS_PER_LONG-1) /* 31? 63? */

void __drbd_bm_lock(struct drbd_conf *mdev, char *file, int line)
{
	struct drbd_bitmap *b = mdev->bitmap;

	spin_lock_irq(&b->bm_lock);
	if (!__test_and_set_bit(BM_LOCKED,&b->bm_flags)) {
		b->bm_file = file;
		b->bm_line = line;
	} else if (DRBD_ratelimit(5*HZ,5)) {
		ERR("%s:%d: bitmap already locked by %s:%lu\n",
		    file, line, b->bm_file,b->bm_line);
		/*
		dump_stack();
		ERR("This is no oops, but debug stack trace only.\n");
		ERR("If you get this often, or in reproducable situations, "
		    "notify <drbd-devel@linbit.com>\n");
		*/
	}
	spin_unlock_irq(&b->bm_lock);
}

void drbd_bm_unlock(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	spin_lock_irq(&b->bm_lock);
	if (!__test_and_clear_bit(BM_LOCKED,&mdev->bitmap->bm_flags)) {
		ERR("bitmap not locked in bm_unlock\n");
	} else {
		/* FIXME if we got a "is already locked" previously,
		 * we unlock here even though we actually MUST NOT do so... */
		b->bm_file = NULL;
		b->bm_line = -1;
	}
	spin_unlock_irq(&b->bm_lock);
}

#if DUMP_MD >= 3
/* debugging aid */
void bm_end_info(struct drbd_conf *mdev, const char *where)
{
	struct drbd_bitmap *b = mdev->bitmap;
	size_t w = (b->bm_bits-1) >> LN2_BPL;

	INFO("%s: bm_set=%lu\n", where, b->bm_set);
	INFO("bm[%d]=0x%lX\n", w, b->bm[w]);
	w++;

	if (w < b->bm_words) {
		D_ASSERT(w == b->bm_words -1);
		INFO("bm[%d]=0x%lX\n", w, b->bm[w]);
	}
}
#else
#define bm_end_info(ignored...)	((void)(0))
#endif

/* long word offset of _bitmap_ sector */
#define S2W(s)	((s)<<(BM_EXT_SIZE_B-BM_BLOCK_SIZE_B-LN2_BPL))

/*
 * actually most functions herein should take a struct drbd_bitmap*, not a
 * struct drbd_conf*, but for the debug macros I like to have the mdev around
 * to be able to report device specific.
 */

/* FIXME TODO sometimes I use "int offset" as index into the bitmap.
 * since we currently are LIMITED to (128<<11)-64-8 sectors of bitmap,
 * this is ok [as long as we dont run on a 24 bit arch :)].
 * But it is NOT strictly ok.
 */

/*
 * called on driver init only. TODO call when a device is created.
 * allocates the drbd_bitmap, and stores it in mdev->bitmap.
 */
int drbd_bm_init(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	WARN_ON(b);
	b = kzalloc(sizeof(struct drbd_bitmap), GFP_KERNEL);
	if (!b)
		return -ENOMEM;
	spin_lock_init(&b->bm_lock);
	init_MUTEX(&b->bm_change);
	init_waitqueue_head(&b->bm_io_wait);

	mdev->bitmap = b;

	return 0;
}

sector_t drbd_bm_capacity(struct drbd_conf *mdev)
{
	ERR_IF(!mdev->bitmap) return 0;
	return mdev->bitmap->bm_dev_capacity;
}

/* called on driver unload. TODO: call when a device is destroyed.
 */
void drbd_bm_cleanup(struct drbd_conf *mdev)
{
	ERR_IF (!mdev->bitmap) return;
	/* FIXME I think we should explicitly change the device size to zero
	 * before this...
	 *
	WARN_ON(mdev->bitmap->bm);
	 */
	vfree(mdev->bitmap->bm);
	kfree(mdev->bitmap);
	mdev->bitmap = NULL;
}

/*
 * since (b->bm_bits % BITS_PER_LONG) != 0,
 * this masks out the remaining bits.
 * Rerturns the number of bits cleared.
 */
int bm_clear_surplus(struct drbd_bitmap *b)
{
	const unsigned long mask = (1UL << (b->bm_bits & (BITS_PER_LONG-1))) -1;
	size_t w = b->bm_bits >> LN2_BPL;
	int cleared = 0;

	if (w < b->bm_words) {
		cleared = hweight_long(b->bm[w] & ~mask);
		b->bm[w++] &= mask;
	}

	if (w < b->bm_words) {
		cleared += hweight_long(b->bm[w]);
		b->bm[w++] = 0;
	}

	return cleared;
}

void bm_set_surplus(struct drbd_bitmap *b)
{
	const unsigned long mask = (1UL << (b->bm_bits & (BITS_PER_LONG-1))) -1;
	size_t w = b->bm_bits >> LN2_BPL;

	if (w < b->bm_words)
		b->bm[w++] |= ~mask;

	if (w < b->bm_words)
		b->bm[w++] = ~(0UL);
}

STATIC unsigned long __bm_count_bits(struct drbd_bitmap *b, const int swap_endian)
{
	unsigned long *bm = b->bm;
	unsigned long *ep = b->bm + b->bm_words;
	unsigned long bits = 0;

	while ( bm < ep ) {
#ifndef __LITTLE_ENDIAN
		if (swap_endian) *bm = lel_to_cpu(*bm);
#endif
		bits += hweight_long(*bm++);
	}

	return bits;
}

static inline unsigned long bm_count_bits(struct drbd_bitmap *b)
{
	return __bm_count_bits(b,0);
}

static inline unsigned long bm_count_bits_swap_endian(struct drbd_bitmap *b)
{
	return __bm_count_bits(b,1);
}


void _drbd_bm_recount_bits(struct drbd_conf *mdev, char* file, int line)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long flags, bits;

	ERR_IF(!b) return;

	spin_lock_irqsave(&b->bm_lock, flags);
	bits = bm_count_bits(b);
	if (bits != b->bm_set) {
		ERR("bm_set was %lu, corrected to %lu. %s:%d\n",
		    b->bm_set, bits, file, line);
		b->bm_set = bits;
	}
	spin_unlock_irqrestore(&b->bm_lock, flags);
}

#define BM_SECTORS_PER_BIT (BM_BLOCK_SIZE/512)

/*
 * make sure the bitmap has enough room for the attached storage,
 * if neccessary, resize.
 * called whenever we may have changed the device size.
 * returns -ENOMEM if we could not allocate enough memory, 0 on success.
 * In case this is actually a resize, we copy the old bitmap into the new one.
 * Otherwise, the bitmap is initiallized to all bits set.
 */
int drbd_bm_resize(struct drbd_conf *mdev, sector_t capacity)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *nbm, *obm = NULL;
	unsigned long bits, bytes, words;
	int err = 0;
	int growing;

	ERR_IF(!b) return -ENOMEM;

	ERR_IF (down_trylock(&b->bm_change)) {
		down(&b->bm_change);
	}

	INFO("drbd_bm_resize called with capacity == %llu\n",
			(unsigned long long)capacity);

	if (capacity == b->bm_dev_capacity)
		goto out;

	if (capacity == 0) {
		spin_lock_irq(&b->bm_lock);
		obm = b->bm;
		b->bm = NULL;
		b->bm_fo    =
		b->bm_set   =
		b->bm_bits  =
		b->bm_words =
		b->bm_dev_capacity = 0;
		spin_unlock_irq(&b->bm_lock);
		goto free_obm;
	} else {
		bits = BM_SECT_TO_BIT(ALIGN(capacity, BM_SECTORS_PER_BIT));

		/* if we would use
		   words = ALIGN(bits,BITS_PER_LONG) >> LN2_BPL;
		   a 32bit host could present the wrong number of words
		   to a 64bit host.
		*/
		words = ALIGN(bits, 64) >> LN2_BPL;

		D_ASSERT((u64)bits <=
			(((u64)mdev->bc->md.md_size_sect-MD_BM_OFFSET) << 12));

		if (words == b->bm_words) {
			/* optimize: capacity has changed,
			 * but only within one long word worth of bits.
			 * just update the bm_dev_capacity and bm_bits members.
			 */
			spin_lock_irq(&b->bm_lock);
			b->bm_bits    = bits;
			b->bm_dev_capacity = capacity;
			b->bm_set -= bm_clear_surplus(b);
			bm_end_info(mdev, __FUNCTION__ );
			spin_unlock_irq(&b->bm_lock);
			goto out;
		} else {
			/* one extra long to catch off by one errors */
			bytes = (words+1)*sizeof(long);
			nbm = vmalloc(bytes);
			if (!nbm) {
				ERR("bitmap: failed to vmalloc %lu bytes\n",
					bytes);
				err = -ENOMEM;
				goto out;
			}
		}
		spin_lock_irq(&b->bm_lock);
		obm = b->bm;
		/* brgs. move several MB within spinlock...
		 * FIXME this should go into userspace! */
		if (obm) {
			bm_set_surplus(b);
			D_ASSERT(b->bm[b->bm_words] == DRBD_MAGIC);
			memcpy(nbm, obm, min_t(size_t, b->bm_words, words)
								*sizeof(long));
		}
		growing = words > b->bm_words;
		if (growing) {
			/* set all newly allocated bits
			 * start at -1, just to be sure. */
			memset( nbm + (b->bm_words?:1)-1 , 0xff,
				(words - ((b->bm_words?:1)-1)) * sizeof(long) );
			b->bm_set  += bits - b->bm_bits;
		}
		nbm[words] = DRBD_MAGIC;
		b->bm = nbm;
		b->bm_bits  = bits;
		b->bm_words = words;
		b->bm_dev_capacity = capacity;
		bm_clear_surplus(b);
		if (!growing)
			b->bm_set = bm_count_bits(b);
		bm_end_info(mdev, __FUNCTION__ );
		spin_unlock_irq(&b->bm_lock);
		INFO("resync bitmap: bits=%lu words=%lu\n", bits, words);
	}
 free_obm:
	vfree(obm); /* vfree(NULL) is noop */
 out:
	up(&b->bm_change);
	return err;
}

/* inherently racy:
 * if not protected by other means, return value may be out of date when
 * leaving this function...
 * we still need to lock it, since it is important that this returns
 * bm_set == 0 precisely.
 *
 * maybe bm_set should be atomic_t ?
 */
unsigned long drbd_bm_total_weight(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long s;
	unsigned long flags;

	ERR_IF(!b) return 0;

	spin_lock_irqsave(&b->bm_lock, flags);
	s = b->bm_set;
	spin_unlock_irqrestore(&b->bm_lock, flags);

	return s;
}

size_t drbd_bm_words(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	ERR_IF(!b) return 0;
	return b->bm_words;
}

/* merge number words from buffer into the bitmap starting at offset.
 * buffer[i] is expected to be little endian unsigned long.
 */
void drbd_bm_merge_lel( struct drbd_conf *mdev, size_t offset, size_t number,
			unsigned long *buffer )
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *bm;
	unsigned long word, bits;
	size_t n = number;

	if (number == 0)
		return;
	ERR_IF(!b) return;
	ERR_IF(!b->bm) return;
	WARN_ON(offset        >= b->bm_words);
	WARN_ON(offset+number >  b->bm_words);
	WARN_ON(number > PAGE_SIZE/sizeof(long));

	spin_lock_irq(&b->bm_lock);
	bm = b->bm + offset;
	while (n--) {
		bits = hweight_long(*bm);
		word = *bm | lel_to_cpu(*buffer++);
		*bm++ = word;
		b->bm_set += hweight_long(word) - bits;
	}
	/* with 32bit <-> 64bit cross-platform connect
	 * this is only correct for current usage,
	 * where we _know_ that we are 64 bit aligned,
	 * and know that this function is used in this way, too...
	 */
	if (offset+number == b->bm_words) {
		b->bm_set -= bm_clear_surplus(b);
		bm_end_info(mdev, __FUNCTION__ );
	}
	spin_unlock_irq(&b->bm_lock);
}

/* copy number words from the bitmap starting at offset into the buffer.
 * buffer[i] will be little endian unsigned long.
 */
void drbd_bm_get_lel(struct drbd_conf *mdev, size_t offset, size_t number,
		     unsigned long *buffer )
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *bm;

	if (number == 0)
		return;
	ERR_IF(!b) return;
	ERR_IF(!b->bm) return;
	if ( (offset        >= b->bm_words) ||
	     (offset+number >  b->bm_words) ||
	     (number > PAGE_SIZE/sizeof(long)) ||
	     (number <= 0) ) {
		/* yes, there is "%z", but that gives compiler warnings... */
		ERR("offset=%lu number=%lu bm_words=%lu\n",
			(unsigned long)	offset,
			(unsigned long)	number,
			(unsigned long) b->bm_words);
		return;
	}

	spin_lock_irq(&b->bm_lock);
	bm = b->bm + offset;
	while (number--) *buffer++ = cpu_to_lel(*bm++);
	spin_unlock_irq(&b->bm_lock);
}

/* set all bits in the bitmap */
void drbd_bm_set_all(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	ERR_IF(!b) return;
	ERR_IF(!b->bm) return;

	spin_lock_irq(&b->bm_lock);
	memset(b->bm, 0xff, b->bm_words*sizeof(long));
	bm_clear_surplus(b);
	b->bm_set = b->bm_bits;
	spin_unlock_irq(&b->bm_lock);
}

void bm_async_io_complete(struct bio *bio, int error)
{
	struct drbd_bitmap *b = bio->bi_private;
	int uptodate = bio_flagged(bio, BIO_UPTODATE);


	/* strange behaviour of some lower level drivers...
	 * fail the request by clearing the uptodate flag,
	 * but do not return any error?!
	 * do we want to WARN() on this? */
	if (!error && !uptodate)
		error = -EIO;

	if (error) {
		/* doh. what now?
		 * for now, set all bits, and flag MD_IO_ERROR
		 */
		/* FIXME kmap_atomic memset etc. pp. */
		__set_bit(BM_MD_IO_ERROR, &b->bm_flags);
	}
	if (atomic_dec_and_test(&b->bm_async_io))
		wake_up(&b->bm_io_wait);

	bio_put(bio);
}

void bm_page_io_async(struct drbd_conf *mdev, struct drbd_bitmap *b, int page_nr, int rw)
{
	/* we are process context. we always get a bio */
	/* THINK: do we need GFP_NOIO here? */
	struct bio *bio = bio_alloc(GFP_KERNEL, 1);
	struct page *page = vmalloc_to_page((char *)(b->bm)
						+ (PAGE_SIZE*page_nr));
	unsigned int len;
	sector_t on_disk_sector =
		mdev->bc->md.md_offset + mdev->bc->md.bm_offset;
	on_disk_sector += ((sector_t)page_nr) << (PAGE_SHIFT-9);

	/* this might happen with very small
	 * flexible external meta data device */
	len = min_t(unsigned int, PAGE_SIZE,
		(drbd_md_last_sector(mdev->bc) - on_disk_sector + 1)<<9);

	D_DUMPLU(on_disk_sector);
	D_DUMPI(len);

	bio->bi_bdev = mdev->bc->md_bdev;
	bio->bi_sector = on_disk_sector;
	bio_add_page(bio, page, len, 0);
	bio->bi_private = b;
	bio->bi_end_io = bm_async_io_complete;

	if (FAULT_ACTIVE(mdev, (rw&WRITE)?DRBD_FAULT_MD_WR:DRBD_FAULT_MD_RD)) {
		bio->bi_rw |= rw;
		bio_endio(bio, -EIO);
	} else {
		submit_bio(rw, bio);
	}
}

# if defined(__LITTLE_ENDIAN)
	/* nothing to do, on disk == in memory */
# define bm_cpu_to_lel(x) ((void)0)
# else
void bm_cpu_to_lel(struct drbd_bitmap *b)
{
	/* need to cpu_to_lel all the pages ...
	 * this may be optimized by using
	 * cpu_to_lel(-1) == -1 and cpu_to_lel(0) == 0;
	 * the following is still not optimal, but better than nothing */
	const unsigned long *end = b->bm+b->bm_words;
	unsigned long *bm;
	if (b->bm_set == 0) {
		/* no page at all; avoid swap if all is 0 */
		return;
	} else if (b->bm_set == b->bm_bits) {
		/* only the last words */
		bm = end-2;
	} else {
		/* all pages */
		bm = b->bm;
	}
	for (; bm < end; bm++)
		*bm = cpu_to_lel(*bm);
}
# endif
/* lel_to_cpu == cpu_to_lel */
# define bm_lel_to_cpu(x) bm_cpu_to_lel(x)

/*
 * bm_rw: read/write the whole bitmap from/to its on disk location.
 */
int bm_rw(struct drbd_conf *mdev, int rw)
{
	struct drbd_bitmap *b = mdev->bitmap;
	/* sector_t sector; */
	int bm_words, num_pages, i;
	unsigned long now;
	char ppb[10];
	int err = 0;

	bm_words  = drbd_bm_words(mdev);
	num_pages = (bm_words*sizeof(long) + PAGE_SIZE-1) >> PAGE_SHIFT;

	/* OK, I manipulate the bitmap low level,
	 * and I expect to be the exclusive user.
	 * If not, I am really in a bad mood...
	 * to catch such bugs early, make all people who want to access the
	 * bitmap while I read/write it dereference a NULL pointer :->
	 */
	mdev->bitmap = NULL;

	/* on disk bitmap is little endian */
	if (rw == WRITE)
		bm_cpu_to_lel(b);

	now = jiffies;
	atomic_set(&b->bm_async_io, num_pages);
	__clear_bit(BM_MD_IO_ERROR, &b->bm_flags);

	/* let the layers below us try to merge these bios... */
	for (i = 0; i < num_pages; i++)
		bm_page_io_async(mdev, b, i, rw);

	drbd_blk_run_queue(bdev_get_queue(mdev->bc->md_bdev));
	wait_event(b->bm_io_wait, atomic_read(&b->bm_async_io) == 0);
	INFO("%s of bitmap took %lu jiffies\n",
	     rw == READ ? "reading" : "writing", jiffies - now);

	if (test_bit(BM_MD_IO_ERROR, &b->bm_flags)) {
		ALERT("we had at least one MD IO ERROR during bitmap IO\n");
		drbd_chk_io_error(mdev, 1, TRUE);
		drbd_io_error(mdev, TRUE);
		err = -EIO;
	}

	now = jiffies;
	if (rw == WRITE) {
		/* swap back endianness */
		bm_lel_to_cpu(b);
		/* flush bitmap to stable storage */
		if (!test_bit(MD_NO_BARRIER,&mdev->flags))
			blkdev_issue_flush(mdev->bc->md_bdev, NULL);
	} else /* rw == READ */ {
		/* just read, if neccessary adjust endianness */
		b->bm_set = bm_count_bits_swap_endian(b);
		INFO("recounting of set bits took additional %lu jiffies\n",
		     jiffies - now);
	}
	now = b->bm_set;

	/* ok, done,
	 * now it is visible again
	 */

	mdev->bitmap = b;

	INFO("%s (%lu bits) marked out-of-sync by on disk bit-map.\n",
	     ppsize(ppb, now << (BM_BLOCK_SIZE_B-10)), now);

	return err;
}

/**
 * drbd_bm_read: Read the whole bitmap from its on disk location.
 *
 * currently only called from "drbd_nl_disk_conf"
 */
int drbd_bm_read(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	int err = 0;

	if (b->bm) {
		/* bitmap size > 0 */
		err = bm_rw(mdev, READ);

		if (err == 0)
			b->bm[b->bm_words] = DRBD_MAGIC;
	}

	return err;
}

/**
 * drbd_bm_write: Write the whole bitmap to its on disk location.
 *
 * called at various occasions.
 */
int drbd_bm_write(struct drbd_conf *mdev)
{
	return bm_rw(mdev, WRITE);
}

/**
 * drbd_bm_write_sect: Writes a 512 byte piece of the bitmap to its
 * on disk location. On disk bitmap is little endian.
 *
 * @enr: The _sector_ offset from the start of the bitmap.
 *
 */
int drbd_bm_write_sect(struct drbd_conf *mdev, unsigned long enr)
{
	sector_t on_disk_sector = enr + mdev->bc->md.md_offset
				      + mdev->bc->md.bm_offset;
	int bm_words, num_words, offset;
	int err = 0;

	down(&mdev->md_io_mutex);
	bm_words  = drbd_bm_words(mdev);
	offset    = S2W(enr);	/* word offset into bitmap */
	num_words = min(S2W(1), bm_words - offset);
#if DUMP_MD >= 3
	INFO("write_sect: sector=%lu offset=%u num_words=%u\n",
			enr, offset, num_words);
#endif
	if (num_words < S2W(1))
		memset(page_address(mdev->md_io_page), 0, MD_HARDSECT);
	drbd_bm_get_lel( mdev, offset, num_words,
			 page_address(mdev->md_io_page) );
	if (!drbd_md_sync_page_io(mdev, mdev->bc, on_disk_sector, WRITE)) {
		int i;
		err = -EIO;
		ERR( "IO ERROR writing bitmap sector %lu "
		     "(meta-disk sector %llus)\n",
		     enr, (unsigned long long)on_disk_sector );
		drbd_chk_io_error(mdev, 1, TRUE);
		drbd_io_error(mdev, TRUE);
		for (i = 0; i < AL_EXT_PER_BM_SECT; i++)
			drbd_bm_ALe_set_all(mdev, enr*AL_EXT_PER_BM_SECT+i);
	}
	mdev->bm_writ_cnt++;
	up(&mdev->md_io_mutex);
	return err;
}

void drbd_bm_reset_find(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;

	ERR_IF(!b) return;

	spin_lock_irq(&b->bm_lock);
	b->bm_fo = 0;
	spin_unlock_irq(&b->bm_lock);

}

/* NOTE
 * find_first_bit returns int, we return unsigned long.
 * should not make much difference anyways, but ...
 * this returns a bit number, NOT a sector!
 */
unsigned long drbd_bm_find_next(struct drbd_conf *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long i = -1UL;

	ERR_IF(!b) return i;
	ERR_IF(!b->bm) return i;

	spin_lock_irq(&b->bm_lock);
	if (b->bm_fo < b->bm_bits)
		i = find_next_bit(b->bm, b->bm_bits, b->bm_fo);
	else if (b->bm_fo > b->bm_bits)
		ERR("bm_fo=%lu bm_bits=%lu\n", b->bm_fo, b->bm_bits);

	if (i >= b->bm_bits) {
		i = -1UL;
		/* leave b->bm_fo unchanged. */
	} else {
		b->bm_fo = i+1;
	}
	spin_unlock_irq(&b->bm_lock);
	return i;
}

void drbd_bm_set_find(struct drbd_conf *mdev, unsigned long i)
{
	struct drbd_bitmap *b = mdev->bitmap;

	spin_lock_irq(&b->bm_lock);

	b->bm_fo = min_t(unsigned long, i, b->bm_bits);

	spin_unlock_irq(&b->bm_lock);
}


int drbd_bm_rs_done(struct drbd_conf *mdev)
{
	return (mdev->bitmap->bm_fo >= mdev->bitmap->bm_bits);
}

/* returns number of bits actually changed.
 * for val != 0, we change 0 -> 1, return code positiv
 * for val == 0, we change 1 -> 0, return code negative
 * wants bitnr, not sector */
static int bm_change_bits_to(struct drbd_conf *mdev, const unsigned long s,
	const unsigned long e, int val)
{
	unsigned long flags;
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long bitnr;
	int c = 0;
	ERR_IF(!b) return 1;
	ERR_IF(!b->bm) return 1;

	spin_lock_irqsave(&b->bm_lock,flags);
	for (bitnr = s; bitnr <= e; bitnr++) {
		ERR_IF (bitnr >= b->bm_bits) {
			ERR("bitnr=%lu bm_bits=%lu\n", bitnr, b->bm_bits);
		} else {
			if (val)
				c += (0 == __test_and_set_bit(bitnr, b->bm));
			else
				c -= (0 != __test_and_clear_bit(bitnr, b->bm));
		}
	}
	b->bm_set += c;
	spin_unlock_irqrestore(&b->bm_lock, flags);
	return c;
}

/* returns number of bits changed 0 -> 1 */
int drbd_bm_set_bits(struct drbd_conf *mdev, const unsigned long s, const unsigned long e)
{
	return bm_change_bits_to(mdev, s, e, 1);
}

/* returns number of bits changed 1 -> 0 */
int drbd_bm_clear_bits(struct drbd_conf *mdev, const unsigned long s, const unsigned long e)
{
	return -bm_change_bits_to(mdev, s, e, 0);
}

/* returns bit state
 * wants bitnr, NOT sector.
 * inherently racy... area needs to be locked by means of {al,rs}_lru
 *  1 ... bit set
 *  0 ... bit not set
 * -1 ... first out of bounds access, stop testing for bits!
 */
int drbd_bm_test_bit(struct drbd_conf *mdev, const unsigned long bitnr)
{
	unsigned long flags;
	struct drbd_bitmap *b = mdev->bitmap;
	int i;
	ERR_IF(!b) return 0;
	ERR_IF(!b->bm) return 0;

	spin_lock_irqsave(&b->bm_lock, flags);
	if (bitnr < b->bm_bits) {
		i = test_bit(bitnr, b->bm) ? 1 : 0;
	} else if (bitnr == b->bm_bits) {
		i = -1;
	} else { /* (bitnr > b->bm_bits) */
		ERR("bitnr=%lu > bm_bits=%lu\n", bitnr, b->bm_bits);
		i = 0;
	}

	spin_unlock_irqrestore(&b->bm_lock, flags);
	return i;
}

/* returns number of bits set */
int drbd_bm_count_bits(struct drbd_conf *mdev, const unsigned long s, const unsigned long e)
{
	unsigned long flags;
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long bitnr;
	int c = 0;
	ERR_IF(!b) return 1;
	ERR_IF(!b->bm) return 1;

	spin_lock_irqsave(&b->bm_lock,flags);
	for (bitnr = s; bitnr <=e; bitnr++) {
		ERR_IF (bitnr >= b->bm_bits) {
			ERR("bitnr=%lu bm_bits=%lu\n",bitnr, b->bm_bits);
		} else {
			c += (0 != test_bit(bitnr, b->bm));
		}
	}
	spin_unlock_irqrestore(&b->bm_lock,flags);
	return c;
}


/* inherently racy...
 * return value may be already out-of-date when this function returns.
 * but the general usage is that this is only use during a cstate when bits are
 * only cleared, not set, and typically only care for the case when the return
 * value is zero, or we already "locked" this "bitmap extent" by other means.
 *
 * enr is bm-extent number, since we chose to name one sector (512 bytes)
 * worth of the bitmap a "bitmap extent".
 *
 * TODO
 * I think since we use it like a reference count, we should use the real
 * reference count of some bitmap extent element from some lru instead...
 *
 */
int drbd_bm_e_weight(struct drbd_conf *mdev, unsigned long enr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	int count, s, e;
	unsigned long flags;

	ERR_IF(!b) return 0;
	ERR_IF(!b->bm) return 0;
	spin_lock_irqsave(&b->bm_lock, flags);

	s = S2W(enr);
	e = min((size_t)S2W(enr+1), b->bm_words);
	count = 0;
	if (s < b->bm_words) {
		const unsigned long *w = b->bm+s;
		int n = e-s;
		while (n--) count += hweight_long(*w++);
	} else {
		ERR("start offset (%d) too large in drbd_bm_e_weight\n", s);
	}
	spin_unlock_irqrestore(&b->bm_lock, flags);
#if DUMP_MD >= 3
	INFO("enr=%lu weight=%d e=%d s=%d\n", enr, count, e, s);
#endif
	return count;
}

/* set all bits covered by the AL-extent al_enr */
unsigned long drbd_bm_ALe_set_all(struct drbd_conf *mdev, unsigned long al_enr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long weight;
	int count, s, e;
	ERR_IF(!b) return 0;
	ERR_IF(!b->bm) return 0;

	spin_lock_irq(&b->bm_lock);
	weight = b->bm_set;

	s = al_enr * BM_WORDS_PER_AL_EXT;
	e = min_t(size_t, s + BM_WORDS_PER_AL_EXT, b->bm_words);
	count = 0;
	if (s < b->bm_words) {
		const unsigned long *w = b->bm+s;
		int n = e-s;
		while (n--) count += hweight_long(*w++);
		n = e-s;
		memset(b->bm+s, -1, n*sizeof(long));
		b->bm_set += n*BITS_PER_LONG - count;
		if (e == b->bm_words)
			b->bm_set -= bm_clear_surplus(b);
	} else {
		ERR("start offset (%d) too large in drbd_bm_ALe_set_all\n", s);
	}
	weight = b->bm_set - weight;
	spin_unlock_irq(&b->bm_lock);
	return weight;
}
