/*
-*- linux-c -*-
   drbd_bitmap.c
   Kernel module for 2.4.x/2.6.x Kernels

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2004, Lars Ellenberg <l.g.e@web.de>.
	main author.

   Copyright (C) 2004, Philipp Reisner <philipp.reisner@linbit.com>.
	contributions.

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
#include <linux/string.h> // for memset
#include <linux/swap.h>   // for total_swapcache_pages

#include <linux/drbd.h>
#include "drbd_int.h"

/* OPAQUE outside this file!
 * interface defined in drbd_int.h
 *
 * unfortunately this currently means that this file is not
 * yet selfcontained, because it needs to know about how to receive
 * the bitmap from the peer via the data socket.
 * This is to be solved with some sort of
 *  drbd_bm_copy(mdev,offset,size,unsigned long*) ...

 * Note that since find_first_bit returns int, this implementation
 * "only" supports up to 1<<(32+12) == 16 TB...  non issue, since
 * currently DRBD is limited to ca 3.8 TB storage anyways.
 *
 * we will eventually change the implementation to not allways hold the full
 * bitmap in memory, but only some 'lru_cache' of the on disk bitmap,
 * since vmalloc'ing mostly unused 128M is antisocial.

 * THINK
 * I'm not yet sure whether this file should be bits only,
 * or wether I want it to do all the sector<->bit calculation in here.
 */

/*
 * NOTE
 *  Access to the *bm_pages is protected by bm_lock.
 *  It is safe to read the other members within the lock.
 *
 *  drbd_bm_set_bit is called from bio_endio callbacks,
 *  so there we need a spin_lock_irqsave.
 *  Everywhere else we need a spin_lock_irq.
 *  And we need the kmap_atomic :-(
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
	struct page **bm_pages;
	spinlock_t bm_lock;
	/* WARNING unsigned long bm_fo and friends:
	 * 32bit number of bit offset is just enough for 512 MB bitmap.
	 * it will blow up if we make the bitmap bigger...
	 * not that it makes much sense to have a bitmap that large,
	 * rather change the granularity to 16k or 64k or something.
	 */
	unsigned long bm_fo;        // next offset for drbd_bm_find_next
	unsigned long bm_set;       // nr of set bits; THINK maybe atomic_t ?
	unsigned long bm_bits;
	size_t   bm_words;
	size_t   bm_number_of_pages;
	sector_t bm_dev_capacity;
	struct semaphore bm_change; // serializes resize operations

	atomic_t bm_async_io;
	wait_queue_head_t bm_io_wait;

	unsigned long  bm_flags;

	// { REMOVE
	unsigned long  bm_line;
	char          *bm_file;
	// }
};

// { REMOVE once we serialize all state changes properly
#define D_BUG_ON(x)	ERR_IF(x) { dump_stack(); }
#define BM_LOCKED      0
#define BM_MD_IO_ERROR (BITS_PER_LONG-1) // 31? 63?

#if 0 // simply disabled for now...
#define MUST_NOT_BE_LOCKED() do {					\
	if (test_bit(BM_LOCKED,&b->bm_flags)) {				\
		if (DRBD_ratelimit(5*HZ,5)) {				\
			ERR("%s:%d: bitmap is locked by %s:%lu\n",	\
			    __FILE__, __LINE__, b->bm_file,b->bm_line);	\
			dump_stack();					\
		}							\
	}								\
} while (0)
#define MUST_BE_LOCKED() do {						\
	if (!test_bit(BM_LOCKED,&b->bm_flags)) {			\
		if (DRBD_ratelimit(5*HZ,5)) {				\
			ERR("%s:%d: bitmap not locked!\n",		\
					__FILE__, __LINE__);		\
			dump_stack();					\
		}							\
	}								\
} while (0)
#else
#define MUST_NOT_BE_LOCKED() do {(void)b;} while (0)
#define MUST_BE_LOCKED() do {(void)b;} while (0)
#endif
void __drbd_bm_lock(drbd_dev *mdev, char* file, int line)
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
void drbd_bm_unlock(drbd_dev *mdev)
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

#if 0
// has been very helpful to indicate that rs_total and rs_left have been
// used in a non-smp safe way...
#define BM_PARANOIA_CHECK() do {						\
	D_ASSERT(b->bm_dev_capacity == drbd_get_capacity(mdev->this_bdev));	\
	if ( (b->bm_set != mdev->rs_total) &&					\
	     (b->bm_set != mdev->rs_left) ) {					\
		if ( DRBD_ratelimit(5*HZ,5) ) {					\
			ERR("%s:%d: ?? bm_set=%lu; rs_total=%lu, rs_left=%lu\n",\
				__FILE__ , __LINE__ ,				\
				b->bm_set, mdev->rs_total, mdev->rs_left );	\
		}								\
	}									\
} while (0)
#else
#define BM_PARANOIA_CHECK() do {					\
	if (b->bm_dev_capacity != drbd_get_capacity(mdev->this_bdev)) {	\
		ERR("%s:%d: bm_dev_capacity:%llu drbd_get_capacity:%llu\n", \
		__FILE__, __LINE__,					\
		(unsigned long long) b->bm_dev_capacity,		\
		(unsigned long long) drbd_get_capacity(mdev->this_bdev));\
	}								\
} while (0)
#endif
// }

#if DUMP_MD >= 3
/* debugging aid */
#error "FIXME"
STATIC void bm_end_info(drbd_dev *mdev, const char* where)
{
	struct drbd_bitmap *b = mdev->bitmap;
	size_t w = (b->bm_bits-1) >> LN2_BPL;

	INFO("%s: bm_set=%lu\n", where, b->bm_set);
	INFO("bm[%d]=0x%lX\n", w, b->bm[w]);
	w++;

	if ( w < b->bm_words ) {
		D_ASSERT(w == b->bm_words -1);
		INFO("bm[%d]=0x%lX\n",w,b->bm[w]);
	}
}
#else
#define bm_end_info(ignored...)	((void)(0))
#endif

#if 0
#define catch_oob_access_start() do {	\
	do {				\
		if ((bm-p_addr) >= PAGE_SIZE/sizeof(long)) { \
			printk(KERN_ALERT "drbd_bitmap.c:%u %s: p_addr:%p bm:%p %d\n", \
					__LINE__ , __func__ , p_addr, bm, (bm-p_addr)); \
			break;		\
		}
#define catch_oob_access_end()	\
	} while(0); } while (0)
#else
#define catch_oob_access_start() ((void)0)
#define catch_oob_access_end() ((void)0)
#endif

/* word offset to long pointer */
STATIC unsigned long * bm_map_paddr(struct drbd_bitmap* b, unsigned long offset)
{
	struct page * page;
	unsigned long page_nr;

	// page_nr = (word*sizeof(long)) >> PAGE_SHIFT;
	page_nr = offset >> (PAGE_SHIFT - LN2_BPL + 3);
	BUG_ON(page_nr >= b->bm_number_of_pages);
	page = b->bm_pages[page_nr];

	return (unsigned long*) kmap_atomic(page,KM_USER0);
}

STATIC void bm_unmap(unsigned long *p_addr) {
	kunmap_atomic(p_addr, KM_USER0);
};

/* long word offset of _bitmap_ sector */
#define S2W(s)	((s)<<(BM_EXT_SIZE_B-BM_BLOCK_SIZE_B-LN2_BPL))
/* word offset from start of bitmap to word number _in_page_
 * modulo longs per page
#define MLPP(X) ((X) % (PAGE_SIZE/sizeof(long))
 hm, well, Philipp thinks gcc might not optimze the % into & (... - 1)
 so do it explicitly:
 */
#define MLPP(X) ((X) & ((PAGE_SIZE/sizeof(long))-1))

/* Long words per page */
#define LWPP (PAGE_SIZE/sizeof(long))

/*
 * actually most functions herein should take a struct drbd_bitmap*, not a
 * drbd_dev*, but for the debug macros I like to have the mdev around
 * to be able to report device specific.
 */

/* FIXME TODO sometimes I use "int offset" as index into the bitmap.
 * since we currently are LIMITED to (128<<11)-64-8 sectors of bitmap,
 * this is ok [as long as we dont run on a 24 bit arch :)].
 * But it is NOT strictly ok.
 */

STATIC void bm_free_pages(struct page ** pages, unsigned long number)
{
	unsigned long i;
	if (!pages)
		return;

	for(i=0;i<number;i++) {
		if (!pages[i]) {
			printk(KERN_ALERT "drbd: bm_free_pages tried to free "
					  "a NULL pointer; i=%lu n=%lu\n",
					  i, number);
			continue;
		}
		__free_page(pages[i]);
		pages[i] = NULL;
	}
}

/*
 * "have" and "want" are NUMBER OF PAGES.
 */
STATIC struct page ** bm_realloc_pages(struct page ** old_pages,
				       unsigned long have,
				       unsigned long want)
{
	struct page** new_pages, *page;
	unsigned int i, bytes;

	BUG_ON(have == 0 && old_pages != NULL);
	BUG_ON(have != 0 && old_pages == NULL);

	if (have == want)
		return old_pages;

	/* don't even try if it is likely to be too much */
	if (want > have) {
		unsigned long nfree, nleft;
		nfree = nr_free_pages();
		nleft = nfree + get_page_cache_size()-total_swapcache_pages;

		if (nleft <= (want-have)) {
			printk(KERN_ALERT "drbd: bm_realloc_pages: OOM!\n");
			return NULL;
		}

		nleft -= (want-have);

		/* protect me agains the infamous oom killer.
		 * FIXME sorry, now it does no longer work on embeded boxes with less than 16MB main ram :-)
		 */
		if ( nleft < (10 << (20 - PAGE_SHIFT)) ) {
			printk(KERN_ALERT "drbd: bm_realloc_pages would have left less than 10MB ram free; OOM!\n");
			printk(KERN_ALERT "drbd: free:%lu buf+cache:%lu want:%lu have:%lu left:%lu\n"
			,	nfree
			,	get_page_cache_size()-total_swapcache_pages
			,	want, have, nleft
			);
			return NULL;
		}
	}

	/* To use kmalloc here is ok, as long as we support 4TB at max...
	 * otherwise this might become bigger than 128KB, which is
	 * the maximum for kmalloc.
	 *
	 * no, it is not: on 64bit boxes, sizeof(void*) == 8,
	 * 128MB bitmap @ 4K pages -> 256K of page pointers.
	 * ==> use vmalloc for now again.
	 * then again, we could do something like
	 *   if (nr_pages > watermark) vmalloc else kmalloc :*> ...
	 * or do cascading page arrays:
	 *   one page for the page array of the page array,
	 *   those pages for the real bitmap pages.
	 *   there we could even add some optimization members,
	 *   so we won't need to kmap_atomic in bm_find_next_bit just to see
	 *   that the page has no bits set ...
	 */
	bytes = sizeof(struct page*)*want;
	new_pages = vmalloc(bytes);
	if(!new_pages) return NULL;

	memset(new_pages,0,bytes);
	if( want >= have ) {
		for(i=0;i<have;i++) {
			new_pages[i] = old_pages[i];
		}
		for(;i<want;i++) {
			if ( !(page = alloc_page(GFP_HIGHUSER)) ) {
				bm_free_pages(new_pages + have, i - have);
				vfree(new_pages);
				return NULL;
			}
			new_pages[i] = page;
		}
	} else {
		for(i=0;i<want;i++) {
			new_pages[i] = old_pages[i];
		}
		/* NOT HERE, we are outside the spinlock!
		bm_free_pages(old_pages + want, have - want);
		*/
	}

	return new_pages;
}

/*
 * called on driver init only. TODO call when a device is created.
 * allocates the drbd_bitmap, and stores it in mdev->bitmap.
 */
int drbd_bm_init(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	D_BUG_ON(b);
	b = kmalloc(sizeof(struct drbd_bitmap),GFP_KERNEL);
	if (!b)
		return -ENOMEM;
	memset(b,0,sizeof(*b));
	spin_lock_init(&b->bm_lock);
	init_MUTEX(&b->bm_change);
	init_waitqueue_head(&b->bm_io_wait);
	mdev->bitmap = b;
	return 0;
}

sector_t drbd_bm_capacity(drbd_dev *mdev)
{
	ERR_IF(!mdev->bitmap) return 0;
	return mdev->bitmap->bm_dev_capacity;
}

/* called on driver unload. TODO: call when a device is destroyed.
 */
void drbd_bm_cleanup(drbd_dev *mdev)
{
	ERR_IF (!mdev->bitmap) return;
	/* FIXME I think we should explicitly change the device size to zero
	 * before this...
	 *
	D_BUG_ON(mdev->bitmap->bm);
	 */
	bm_free_pages(mdev->bitmap->bm_pages,mdev->bitmap->bm_number_of_pages);
	vfree(mdev->bitmap->bm_pages);
	kfree(mdev->bitmap);
	mdev->bitmap = NULL;
}

/*
 * since (b->bm_bits % BITS_PER_LONG) != 0,
 * this masks out the remaining bits.
 * Rerturns the number of bits cleared.
 */
STATIC int bm_clear_surplus(struct drbd_bitmap * b)
{
	const unsigned long mask = (1UL << (b->bm_bits & (BITS_PER_LONG-1))) -1;
	size_t w = b->bm_bits >> LN2_BPL;
	int cleared=0;
	unsigned long *p_addr, *bm;

	p_addr = bm_map_paddr(b,w);
	bm = p_addr + MLPP(w);
	if ( w < b->bm_words ) {
		catch_oob_access_start();
		cleared = hweight_long(*bm & ~mask);
		*bm &= mask;
		catch_oob_access_end();
		w++; bm++;
	}

	if ( w < b->bm_words ) {
		catch_oob_access_start();
		cleared += hweight_long(*bm);
		*bm=0;
		catch_oob_access_end();
	}
	bm_unmap(p_addr);
	return cleared;
}

STATIC void bm_set_surplus(struct drbd_bitmap * b)
{
	const unsigned long mask = (1UL << (b->bm_bits & (BITS_PER_LONG-1))) -1;
	size_t w = b->bm_bits >> LN2_BPL;
	unsigned long *p_addr, *bm;

	p_addr = bm_map_paddr(b,w);
	bm = p_addr + MLPP(w);
	if ( w < b->bm_words ) {
		catch_oob_access_start();
		*bm |= ~mask;
		bm++; w++;
		catch_oob_access_end();
	}

	if ( w < b->bm_words ) {
		catch_oob_access_start();
		*bm = ~(0UL);
		catch_oob_access_end();
	}
	bm_unmap(p_addr);
}

STATIC unsigned long bm_count_bits(struct drbd_bitmap * b, int just_read)
{
	unsigned long *p_addr, *bm, offset = 0;
	unsigned long bits = 0;
	unsigned long i,do_now;

	while ( offset < b->bm_words ) {
		i = do_now = min_t( size_t, b->bm_words-offset, LWPP );
		p_addr = bm_map_paddr(b,offset);
		bm = p_addr + MLPP(offset);
		while(i--) {
			catch_oob_access_start();
			/* on little endian, this is *bm = *bm;
			 * and should be optimized away by the compiler */
			if (just_read) *bm = lel_to_cpu(*bm);
			bits += hweight_long(*bm++);
			catch_oob_access_end();
		}
		bm_unmap(p_addr);
		offset += do_now;
	}

	return bits;
}

/* offset and len in long words.*/
STATIC void bm_memset(struct drbd_bitmap * b, size_t offset, int c, size_t len)
{
	unsigned long *p_addr, *bm;
	size_t do_now, end;

	end = offset+len;

	if( end > b->bm_words ) {
		printk(KERN_ALERT "drbd: bm_memset end > bm_words\n");
		return;
	}

	while (offset < end) {
		do_now = min_t(size_t,ALIGN(offset+1,LWPP),end) - offset;
		p_addr = bm_map_paddr(b,offset);
		bm = p_addr + MLPP(offset);
		catch_oob_access_start();
		if ( bm+do_now > p_addr + LWPP ) {
			printk(KERN_ALERT "drbd: BUG BUG BUG! p_addr:%p bm:%p do_now:%d\n",
					p_addr, bm, do_now);
			break;
		}
		memset(bm,c,do_now*sizeof(long));
		catch_oob_access_end();
		bm_unmap(p_addr);
		offset += do_now;
	}
}

/*
 * make sure the bitmap has enough room for the attached storage,
 * if neccessary, resize.
 * called whenever we may have changed the device size.
 * returns -ENOMEM if we could not allocate enough memory, 0 on success.
 * In case this is actually a resize, we copy the old bitmap into the new one.
 * Otherwise, the bitmap is initiallized to all bits set.
 */
int drbd_bm_resize(drbd_dev *mdev, sector_t capacity)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long bits, words, owords, obits, *p_addr, *bm;
	unsigned long want, have, onpages; // number of pages
	struct page **npages, **opages = NULL;
	int err = 0, growing;

	ERR_IF(!b) return -ENOMEM;
	MUST_BE_LOCKED();

	ERR_IF (down_trylock(&b->bm_change)) {
		down(&b->bm_change);
	}

	INFO("drbd_bm_resize called with capacity == %llu\n", (unsigned long long)capacity);

	if (capacity == b->bm_dev_capacity)
		goto out;

	if (capacity == 0) {
		spin_lock_irq(&b->bm_lock);
		opages = b->bm_pages;
		onpages = b->bm_number_of_pages;
		owords = b->bm_words;
		b->bm_pages = NULL;
		b->bm_number_of_pages =
		b->bm_fo    =
		b->bm_set   =
		b->bm_bits  =
		b->bm_words =
		b->bm_dev_capacity = 0;
		spin_unlock_irq(&b->bm_lock);
		bm_free_pages(opages, onpages);
		vfree(opages);
		goto out;
	}
	bits  = BM_SECT_TO_BIT(ALIGN(capacity,BM_SECT_PER_BIT));

	/* if we would use
	   words = ALIGN(bits,BITS_PER_LONG) >> LN2_BPL;
	   a 32bit host could present the wrong number of words
	   to a 64bit host.
	*/
	words = ALIGN(bits,64) >> LN2_BPL;

	D_ASSERT((u64)bits <= (((u64)mdev->bc->md.md_size_sect-MD_BM_OFFSET) << 12));

	/* one extra long to catch off by one errors */
	want = ALIGN( (words+1)*sizeof(long) ,PAGE_SIZE) >> PAGE_SHIFT;
	have = b->bm_number_of_pages;
	if (want == have) {
		D_ASSERT(b->bm_pages != NULL);
		npages = b->bm_pages;
	} else {
		npages = bm_realloc_pages(b->bm_pages,have,want);
	}

	if (!npages) {
		err = -ENOMEM;
		goto out;
	}

	spin_lock_irq(&b->bm_lock);
	opages = b->bm_pages;
	owords = b->bm_words;
	obits  = b->bm_bits;

	growing = bits > obits;
	if (opages) {
		bm_set_surplus(b);
	}

	b->bm_pages = npages;
	b->bm_number_of_pages = want;
	b->bm_bits  = bits;
	b->bm_words = words;
	b->bm_dev_capacity = capacity;

	if( growing ) {
		bm_memset(b,owords,0xff,words-owords);
		b->bm_set += bits - obits;
	}

	if ( want < have ) {
		/* implicit: (opages != NULL) && (opages != npages) */
		bm_free_pages(opages + want, have - want);
	}

	p_addr = bm_map_paddr(b,words);
	bm = p_addr + MLPP(words);
	catch_oob_access_start();
	*bm = DRBD_MAGIC;
	catch_oob_access_end();
	bm_unmap(p_addr);

	(void)bm_clear_surplus(b);
	if( !growing )
		b->bm_set = bm_count_bits(b, 0 /* not just read */ );

	bm_end_info(mdev, __FUNCTION__ );
	spin_unlock_irq(&b->bm_lock);
	if (opages != npages) vfree(opages);
	INFO("resync bitmap: bits=%lu words=%lu\n",bits,words);

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
unsigned long drbd_bm_total_weight(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long s;
	unsigned long flags;

	ERR_IF(!b) return 0;
	ERR_IF(!b->bm_pages) return 0;
	// MUST_BE_LOCKED(); well. yes. but ...

	spin_lock_irqsave(&b->bm_lock,flags);
	s = b->bm_set;
	spin_unlock_irqrestore(&b->bm_lock,flags);

	return s;
}

size_t drbd_bm_words(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	ERR_IF(!b) return 0;
	ERR_IF(!b->bm_pages) return 0;

	/* FIXME
	 * actually yes. really. otherwise it could just change its size ...
	 * but it triggers all the time...
	 * MUST_BE_LOCKED();
	 */

	return b->bm_words;
}

/* merge number words from buffer into the bitmap starting at offset.
 * buffer[i] is expected to be little endian unsigned long.
 */
void drbd_bm_merge_lel( drbd_dev *mdev, size_t offset, size_t number,
			unsigned long* buffer )
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr, *bm;
	unsigned long word, bits;
	size_t end, do_now;

	end = offset + number;

	ERR_IF(!b) return;
	ERR_IF(!b->bm_pages) return;
	D_BUG_ON(offset >= b->bm_words);
	D_BUG_ON(end    >  b->bm_words);

	MUST_BE_LOCKED();

	spin_lock_irq(&b->bm_lock);
	// BM_PARANOIA_CHECK(); no.
	while(offset < end) {
		do_now = min_t(size_t,ALIGN(offset+1,LWPP),end) - offset;
		p_addr = bm_map_paddr(b,offset);
		bm = p_addr + MLPP(offset);
		offset += do_now;
		while(do_now--) {
			catch_oob_access_start();
			bits = hweight_long(*bm);
			word = *bm | lel_to_cpu(*buffer++);
			*bm++ = word;
			b->bm_set += hweight_long(word) - bits;
			catch_oob_access_end();
		}
		bm_unmap(p_addr);
	}
	/* with 32bit <-> 64bit cross-platform connect
	 * this is only correct for current usage,
	 * where we _know_ that we are 64 bit aligned,
	 * and know that this function is used in this way, too...
	 */
	if (end == b->bm_words) {
		b->bm_set -= bm_clear_surplus(b);
		bm_end_info(mdev, __FUNCTION__ );
	}
	spin_unlock_irq(&b->bm_lock);
}

/* copy number words from buffer into the bitmap starting at offset.
 * buffer[i] is expected to be little endian unsigned long.
 */
void drbd_bm_set_lel( drbd_dev *mdev, size_t offset, size_t number,
		      unsigned long* buffer )
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr, *bm;
	unsigned long word, bits;
	size_t end, do_now;

	end = offset + number;

	ERR_IF(!b) return;
	ERR_IF(!b->bm_pages) return;
	D_BUG_ON(offset >= b->bm_words);
	D_BUG_ON(end    >  b->bm_words);

	MUST_BE_LOCKED();

	spin_lock_irq(&b->bm_lock);
	// BM_PARANOIA_CHECK(); no.
	while(offset < end) {
		do_now = min_t(size_t,ALIGN(offset+1,LWPP),end) - offset;
		p_addr = bm_map_paddr(b,offset);
		bm = p_addr + MLPP(offset);
		offset += do_now;
		while(do_now--) {
			catch_oob_access_start();
			bits = hweight_long(*bm);
			word = lel_to_cpu(*buffer++);
			*bm++ = word;
			b->bm_set += hweight_long(word) - bits;
			catch_oob_access_end();
		}
		bm_unmap(p_addr);
	}
	/* with 32bit <-> 64bit cross-platform connect
	 * this is only correct for current usage,
	 * where we _know_ that we are 64 bit aligned,
	 * and know that this function is used in this way, too...
	 */
	if (end == b->bm_words) {
		b->bm_set -= bm_clear_surplus(b);
		bm_end_info(mdev, __FUNCTION__ );
	}
	spin_unlock_irq(&b->bm_lock);
}

/* copy number words from the bitmap starting at offset into the buffer.
 * buffer[i] will be little endian unsigned long.
 */
void drbd_bm_get_lel( drbd_dev *mdev, size_t offset, size_t number,
		      unsigned long* buffer )
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr, *bm;
	size_t end, do_now;

	end = offset + number;

	ERR_IF(!b) return;
	ERR_IF(!b->bm_pages) return;

	if ( (offset >= b->bm_words) ||
	     (end    >  b->bm_words) ||
	     (number <= 0) ) {
		// yes, there is "%z", but that gives compiler warnings...
		ERR("offset=%lu number=%lu bm_words=%lu\n",
			(unsigned long)	offset,
			(unsigned long)	number,
			(unsigned long) b->bm_words);
		return;
	}

	// MUST_BE_LOCKED(); yes. but not neccessarily globally...

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();
	while(offset < end) {
		do_now = min_t(size_t,ALIGN(offset+1,LWPP),end) - offset;
		p_addr = bm_map_paddr(b,offset);
		bm = p_addr + MLPP(offset);
		offset += do_now;
		while(do_now--) {
			catch_oob_access_start();
			*buffer++ = cpu_to_lel(*bm++);
			catch_oob_access_end();
		}
		bm_unmap(p_addr);
	}
	spin_unlock_irq(&b->bm_lock);
}

/* set all bits in the bitmap */
void drbd_bm_set_all(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	ERR_IF(!b) return;
	ERR_IF(!b->bm_pages) return;

	MUST_BE_LOCKED();

	spin_lock_irq(&b->bm_lock);
	bm_memset(b,0,0xff,b->bm_words);
	(void)bm_clear_surplus(b);
	b->bm_set = b->bm_bits;
	spin_unlock_irq(&b->bm_lock);
}

int drbd_bm_async_io_complete(struct bio *bio, unsigned int bytes_done, int error)
{
	struct drbd_bitmap *b = bio->bi_private;

	if (bio->bi_size)
		return 1;

	if (error) {
		/* doh. what now?
		 * for now, set all bits, and flag MD_IO_ERROR
		 */
		/* FIXME kmap_atomic memset etc. pp. */
		__set_bit(BM_MD_IO_ERROR,&b->bm_flags);
	}
	if (atomic_dec_and_test(&b->bm_async_io))
		wake_up(&b->bm_io_wait);

	bio_put(bio);

	return 0;
}

STATIC void drbd_bm_page_io_async(drbd_dev *mdev, struct drbd_bitmap *b, int page_nr, int rw)
{
	/* we are process context. we always get a bio */
	struct bio *bio = bio_alloc(GFP_KERNEL, 1);
	unsigned int len;
	sector_t on_disk_sector = mdev->bc->md.md_offset + mdev->bc->md.bm_offset;
	on_disk_sector += ((sector_t)page_nr) << (PAGE_SHIFT-9);

	/* this might happen with very small flexible external meta data device */
	len = min_t(unsigned int, PAGE_SIZE,
		(drbd_md_last_sector(mdev->bc) - on_disk_sector + 1)<<9);

	D_DUMPLU(on_disk_sector);
	D_DUMPI(len);

	bio->bi_bdev = mdev->bc->md_bdev;
	bio->bi_sector = on_disk_sector;
	bio_add_page(bio, b->bm_pages[page_nr], len, 0);
	bio->bi_private = b;
	bio->bi_end_io = drbd_bm_async_io_complete;
	submit_bio(rw, bio);
}

/* read one sector of the on disk bitmap into memory.
 * on disk bitmap is little endian.
 * @enr is _sector_ offset from start of on disk bitmap (aka bm-extent nr).
 * returns 0 on success, -EIO on failure
 */
int drbd_bm_read_sect(drbd_dev *mdev,unsigned long enr)
{
	/* addition of sector_t/u64/s32... works anyways */
	sector_t on_disk_sector = mdev->bc->md.md_offset + mdev->bc->md.bm_offset + enr;
	int bm_words, num_words, offset, err  = 0;

	// MUST_BE_LOCKED(); not neccessarily global ...

	D_DUMPLU(on_disk_sector);
	down(&mdev->md_io_mutex);
	if(drbd_md_sync_page_io(mdev,mdev->bc,on_disk_sector,READ)) {
		bm_words  = drbd_bm_words(mdev);
		offset    = S2W(enr);	// word offset into bitmap
		num_words = min(S2W(1), bm_words - offset);
#if DUMP_MD >= 3
	INFO("read_sect: sector=%lu offset=%u num_words=%u\n",
			enr, offset, num_words);
#endif
		drbd_bm_set_lel( mdev, offset, num_words,
				 page_address(mdev->md_io_page) );
	} else {
		int i;
		err = -EIO;
		ERR( "IO ERROR reading bitmap sector %lu "
		     "(meta-disk sector %llu)\n",
		     enr, (unsigned long long)on_disk_sector );
		drbd_chk_io_error(mdev, 1);
		drbd_io_error(mdev);
		for (i = 0; i < AL_EXT_PER_BM_SECT; i++)
			drbd_bm_ALe_set_all(mdev,enr*AL_EXT_PER_BM_SECT+i);
	}
	up(&mdev->md_io_mutex);
	return err;
}

/**
 * drbd_bm_read: Read the whole bitmap from its on disk location.
 *
 * currently only called from "drbd_ioctl_set_disk"
 * FIXME need to be able to return an error!!
 *
 */
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
	if (b->bm_set == 0) {
		/* no page at all; avoid swap if all is 0 */
		i = b->bm_number_of_pages;
	} else if (b->bm_set == b->bm_bits) {
		/* only the last page */
		i = b->bm_number_of_pages -1;
	} else {
		/* all pages */
		i = 0;
	}
	for (; i < b->bm_number_of_pages; i++) {
		unsigned long *bm;
		p_addr = kmap_atomic(b->bm_pages[i],KM_USER0)
		for (bm = p_addr; bm < p_addr+PAGE_SIZE/sizeof(long); bm++) {
			*bm = cpu_to_lel(*bm);
		}
		kunmap_atomic(p_addr);
	}
}
# endif
/* lel_to_cpu == cpu_to_lel */
# define bm_lel_to_cpu(x) bm_cpu_to_lel(x)

STATIC void drbd_bm_rw(struct Drbd_Conf *mdev, int rw)
{
	struct drbd_bitmap *b = mdev->bitmap;
	/* sector_t sector; */
	int bm_words, num_sectors, i;
	unsigned long now;
	char ppb[10];

	MUST_BE_LOCKED();

	bm_words    = drbd_bm_words(mdev);
	num_sectors = (bm_words*sizeof(long) + 511) >> 9;

	/* OK, I manipulate the bitmap low level,
	 * and I expect to be the exclusive user.
	 * If not, I am really in a bad mood...
	 * to catch such bugs early, make all people who want to access the
	 * bitmap while I read it dereference a NULL pointer :->
	 */
	mdev->bitmap = NULL;

	if(rw == WRITE)	bm_cpu_to_lel(b);

	now = jiffies;
	atomic_set(&b->bm_async_io, b->bm_number_of_pages);
	for (i = 0; i < b->bm_number_of_pages; i++) {
		/* let the layers below us try to merge these bios... */
		drbd_bm_page_io_async(mdev,b,i,rw);
	}

	blk_run_queue(bdev_get_queue(mdev->bc->md_bdev));
	wait_event(b->bm_io_wait, atomic_read(&b->bm_async_io) == 0);
	INFO("%s of bitmap took %lu jiffies\n",
	     rw == READ ? "reading" : "writing", jiffies - now);

	if (test_bit(BM_MD_IO_ERROR,&b->bm_flags)) {
		/* FIXME correct handling of this.
		 * detach?
		 */
		ALERT("we had at least one MD IO ERROR during bitmap IO\n");
		drbd_chk_io_error(mdev, 1);
		drbd_io_error(mdev);
	}

	now = jiffies;
	/* just read, if neccessary adjust endianness */
	if(rw == WRITE) {
		bm_lel_to_cpu(b);
	} else /* rw == READ */ {
		b->bm_set = bm_count_bits(b, 1);
		INFO("recounting of set bits took additional %lu jiffies\n", 
		     jiffies - now);
	}

	/* ok, done,
	 * now it is visible again
	 */

	mdev->bitmap = b;

	INFO("%s marked out-of-sync by on disk bit-map.\n",
	     ppsize(ppb,drbd_bm_total_weight(mdev) << (BM_BLOCK_SIZE_B-10)) );
}

void drbd_bm_read(struct Drbd_Conf *mdev)
{
	drbd_bm_rw(mdev, READ);
}

/**
 * drbd_bm_write_sect: Writes a 512 byte piece of the bitmap to its
 * on disk location. On disk bitmap is little endian.
 *
 * @enr: The _sector_ offset from the start of the bitmap.
 *
 */
int drbd_bm_write_sect(struct Drbd_Conf *mdev,unsigned long enr)
{
	sector_t on_disk_sector = enr + mdev->bc->md.md_offset + mdev->bc->md.bm_offset;
	int bm_words, num_words, offset, err  = 0;

	// MUST_BE_LOCKED(); not neccessarily global...

	down(&mdev->md_io_mutex);
	bm_words  = drbd_bm_words(mdev);
	offset    = S2W(enr);	// word offset into bitmap
	num_words = min(S2W(1), bm_words - offset);
#if DUMP_MD >= 3
	INFO("write_sect: sector=%lu offset=%u num_words=%u\n",
			enr, offset, num_words);
#endif
	if (num_words < S2W(1)) {
		memset(page_address(mdev->md_io_page),0,MD_HARDSECT);
	}
	drbd_bm_get_lel( mdev, offset, num_words,
			 page_address(mdev->md_io_page) );
	D_DUMPLU(on_disk_sector);
	if (!drbd_md_sync_page_io(mdev,mdev->bc,on_disk_sector,WRITE)) {
		int i;
		err = -EIO;
		ERR( "IO ERROR writing bitmap sector %lu "
		     "(meta-disk sector %lu)\n",
		     enr, (unsigned long)on_disk_sector );
		drbd_chk_io_error(mdev, 1);
		drbd_io_error(mdev);
		for (i = 0; i < AL_EXT_PER_BM_SECT; i++)
			drbd_bm_ALe_set_all(mdev,enr*AL_EXT_PER_BM_SECT+i);
	}
	mdev->bm_writ_cnt++;
	up(&mdev->md_io_mutex);
	return err;
}

/**
 * drbd_bm_write: Write the whole bitmap to its on disk location.
 *
 * called at various occasions:
 *
int drbd_determin_dev_size(struct Drbd_Conf* mdev)
int drbd_ioctl_set_disk(struct Drbd_Conf *mdev,
			struct ioctl_disk_config * arg)
	case DRBD_IOCTL_INVALIDATE:
	case DRBD_IOCTL_INVALIDATE_REM:
	case DRBD_IOCTL_SET_DISK_SIZE:
int _drbd_send_bitmap(drbd_dev *mdev)
STATIC int drbd_sync_handshake(drbd_dev *mdev, Drbd_Parameter_Packet *p)
STATIC int receive_BecomeSyncTarget(drbd_dev *mdev, Drbd_Header *h)
STATIC int receive_BecomeSyncSource(drbd_dev *mdev, Drbd_Header *h)
STATIC int receive_param(drbd_dev *mdev, Drbd_Header *h)
 *
 * FIXME need to be able to return an error!!
 */

void drbd_bm_write(struct Drbd_Conf *mdev)
{
	drbd_bm_rw(mdev, WRITE);
}

/* clear all bits in the bitmap */
void drbd_bm_clear_all(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;

	ERR_IF(!b) return;
	ERR_IF(!b->bm_pages) return;

	MUST_BE_LOCKED();

	spin_lock_irq(&b->bm_lock);
	bm_memset(b,0,0x00,b->bm_words);
	b->bm_set = 0;
	spin_unlock_irq(&b->bm_lock);
}

void drbd_bm_reset_find(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;

	ERR_IF(!b) return;

	MUST_BE_LOCKED();

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();
	b->bm_fo = 0;
	spin_unlock_irq(&b->bm_lock);

}

/* NOTE
 * find_first_bit returns int, we return unsigned long.
 * should not make much difference anyways, but ...
 *
 * this returns a bit number, NOT a sector!
 */
#define BPP_MASK ((1UL << (PAGE_SHIFT+3) ) - 1)
unsigned long drbd_bm_find_next(drbd_dev *mdev)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long i = -1UL;
	unsigned long *p_addr;
	unsigned long bit_offset; //bit offset of the mapped page.

	ERR_IF(!b) return i;
	ERR_IF(!b->bm_pages) return i;

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();
	if (b->bm_fo > b->bm_bits) {
		ERR("bm_fo=%lu bm_bits=%lu\n",b->bm_fo, b->bm_bits);
	} else {
		while (b->bm_fo < b->bm_bits) {
			unsigned long offset;
			bit_offset = b->bm_fo & ~BPP_MASK; // bit offset of the page
			offset = bit_offset >> LN2_BPL;    // word offset of the page
			p_addr = bm_map_paddr(b,offset);
			i = find_next_bit(p_addr,PAGE_SIZE*8,b->bm_fo&BPP_MASK);
			bm_unmap(p_addr);
			if (i < PAGE_SIZE*8) {
				i = bit_offset + i;
				if( i >= b->bm_bits ) break;
				b->bm_fo = i+1;
				goto found;
			}
			b->bm_fo = bit_offset + PAGE_SIZE*8;
		}
		i = -1UL;
		b->bm_fo = 0;
	}
 found:
	spin_unlock_irq(&b->bm_lock);
	return i;
}

void drbd_bm_set_find(drbd_dev *mdev, unsigned long i)
{
	struct drbd_bitmap *b = mdev->bitmap;

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();

	if (i < b->bm_bits) {
		b->bm_fo = i;
	} else {
		b->bm_fo = 0;
	}

	spin_unlock_irq(&b->bm_lock);
}

int drbd_bm_rs_done(drbd_dev *mdev)
{
	return mdev->bitmap->bm_fo == 0;
}

// THINK maybe the D_BUG_ON(i<0)s in set/clear/test should be not that strict?

/* returns previous bit state
 * wants bitnr, NOT sector.
 */
int drbd_bm_set_bit(drbd_dev *mdev, const unsigned long bitnr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr;
	int i;

	ERR_IF(!b) return 1;
	ERR_IF(!b->bm_pages) return 1;

/*
 * only called from drbd_set_out_of_sync.
 * strange_state blubber is already in place there...
	strange_state = ( mdev->cstate  > Connected ) ||
	                ( mdev->cstate == Connected &&
	                 !(test_bit(DISKLESS,&mdev->flags) ||
	                   test_bit(PARTNER_DISKLESS,&mdev->flags)) );
	if (strange_state)
		ERR("%s in drbd_bm_set_bit\n", conns_to_name(mdev->cstate));
*/

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();
	MUST_NOT_BE_LOCKED();
	ERR_IF (bitnr >= b->bm_bits) {
		ERR("bitnr=%lu bm_bits=%lu\n",bitnr, b->bm_bits);
		i = 0;
	} else {
		unsigned long offset = bitnr>>LN2_BPL;
		p_addr = bm_map_paddr(b,offset);
		i = (0 != __test_and_set_bit(bitnr & BPP_MASK, p_addr));
		bm_unmap(p_addr);
		b->bm_set += !i;
	}
	spin_unlock_irq(&b->bm_lock);
	return i;
}

/* returns previous bit state
 * wants bitnr, NOT sector.
 */
int drbd_bm_clear_bit(drbd_dev *mdev, const unsigned long bitnr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr;
	unsigned long flags;
	int i;

	ERR_IF(!b) return 0;
	ERR_IF(!b->bm_pages) return 0;

	spin_lock_irqsave(&b->bm_lock,flags);
	BM_PARANOIA_CHECK();
	MUST_NOT_BE_LOCKED();
	ERR_IF (bitnr >= b->bm_bits) {
		ERR("bitnr=%lu bm_bits=%lu\n",bitnr, b->bm_bits);
		i = 0;
	} else {
		unsigned long offset = bitnr>>LN2_BPL;
		p_addr = bm_map_paddr(b,offset);
		i = (0 != __test_and_clear_bit(bitnr & BPP_MASK, p_addr));
		bm_unmap(p_addr);
		b->bm_set -= i;
	}
	spin_unlock_irqrestore(&b->bm_lock,flags);

	/* clearing bits should only take place when sync is in progress!
	 * this is only called from drbd_set_in_sync.
	 * strange_state blubber is already in place there ...
	if (i && mdev->cstate <= Connected)
		ERR("drbd_bm_clear_bit: cleared a bitnr=%lu while %s\n",
				bitnr, conns_to_name(mdev->cstate));
	 */

	return i;
}

/* returns bit state
 * wants bitnr, NOT sector.
 * inherently racy... area needs to be locked by means of {al,rs}_lru
 *  1 ... bit set
 *  0 ... bit not set
 * -1 ... first out of bounds access, stop testing for bits!
 */
int drbd_bm_test_bit(drbd_dev *mdev, const unsigned long bitnr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr;
	int i;

	ERR_IF(!b) return 0;
	ERR_IF(!b->bm_pages) return 0;

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();
	if (bitnr < b->bm_bits) {
		unsigned long offset = bitnr>>LN2_BPL;
		p_addr = bm_map_paddr(b,offset);
		i = test_bit(bitnr & BPP_MASK, p_addr);
		bm_unmap(p_addr);
	} else if (bitnr == b->bm_bits) {
		i = -1;
	} else /* (bitnr > b->bm_bits) */ {
		ERR("bitnr=%lu > bm_bits=%lu\n",bitnr, b->bm_bits);
		i = 0;		
	}

	spin_unlock_irq(&b->bm_lock);
	return i;
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
int drbd_bm_e_weight(drbd_dev *mdev, unsigned long enr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	int count, s, e;
	unsigned long flags;
	unsigned long *p_addr, *bm;

	ERR_IF(!b) return 0;
	ERR_IF(!b->bm_pages) return 0;

	spin_lock_irqsave(&b->bm_lock,flags);
	BM_PARANOIA_CHECK();

	s = S2W(enr);
	e = min((size_t)S2W(enr+1),b->bm_words);
	count = 0;
	if (s < b->bm_words) {
		int n = e-s;
		p_addr = bm_map_paddr(b,s);
		bm = p_addr + MLPP(s);
		while (n--) {
			catch_oob_access_start();
			count += hweight_long(*bm++);
			catch_oob_access_end();
		}
		bm_unmap(p_addr);
	} else {
		ERR("start offset (%d) too large in drbd_bm_e_weight\n", s);
	}
	spin_unlock_irqrestore(&b->bm_lock,flags);
#if DUMP_MD >= 3
	INFO("enr=%lu weight=%d e=%d s=%d\n", enr, count, e, s);
#endif
	return count;
}

/* set all bits covered by the AL-extent al_enr */
unsigned long drbd_bm_ALe_set_all(drbd_dev *mdev, unsigned long al_enr)
{
	struct drbd_bitmap *b = mdev->bitmap;
	unsigned long *p_addr, *bm;
	unsigned long weight;
	int count, s, e, i, do_now;
	ERR_IF(!b) return 0;
	ERR_IF(!b->bm_pages) return 0;

	MUST_BE_LOCKED();

	spin_lock_irq(&b->bm_lock);
	BM_PARANOIA_CHECK();
	weight = b->bm_set;

	s = al_enr * BM_WORDS_PER_AL_EXT;
	e = min_t(size_t, s + BM_WORDS_PER_AL_EXT, b->bm_words);
	/* assert that s and e are on the same page */
	D_ASSERT(  (e-1) >> (PAGE_SHIFT - LN2_BPL + 3)
		==  s    >> (PAGE_SHIFT - LN2_BPL + 3) );
	count = 0;
	if (s < b->bm_words) {
		i = do_now = e-s;
		p_addr = bm_map_paddr(b,s);
		bm = p_addr + MLPP(s);
		while (i--) {
			catch_oob_access_start();
			count += hweight_long(*bm);
			*bm = -1UL;
			catch_oob_access_end();
			bm++;
		}
		bm_unmap(p_addr);
		b->bm_set += do_now*BITS_PER_LONG - count;
		if (e == b->bm_words) {
			b->bm_set -= bm_clear_surplus(b);
		}
	} else {
		ERR("start offset (%d) too large in drbd_bm_ALe_set_all\n", s);
	}
	weight = b->bm_set - weight;
	spin_unlock_irq(&b->bm_lock);
	return weight;
}
