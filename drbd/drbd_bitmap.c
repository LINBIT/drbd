// SPDX-License-Identifier: GPL-2.0-or-later
/*
   drbd_bitmap.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2004-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2004-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2004-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

 */

#define pr_fmt(fmt)	KBUILD_MODNAME ": " fmt

#include <linux/bitops.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/drbd.h>
#include <linux/slab.h>
#include <linux/dynamic_debug.h>
#include <linux/libnvdimm.h>

#include "drbd_int.h"
#include "drbd_dax_pmem.h"

#ifndef BITS_PER_PAGE
#define BITS_PER_PAGE		(1UL << (PAGE_SHIFT + 3))
#else
# if BITS_PER_PAGE != (1UL << (PAGE_SHIFT + 3))
#  error "ambiguous BITS_PER_PAGE"
# endif
#endif

/* OPAQUE outside this file!
 * interface defined in drbd_int.h

 * convention:
 * function name drbd_bm_... => used elsewhere, "public".
 * function name      bm_... => internal to implementation, "private".
 */


/*
 * LIMITATIONS:
 * We want to support >= peta byte of backend storage, while for now still using
 * a granularity of one bit per 4KiB of storage.
 * 1 << 50		bytes backend storage (1 PiB)
 * 1 << (50 - 12)	bits needed
 *	38 --> we need u64 to index and count bits
 * 1 << (38 - 3)	bitmap bytes needed
 *	35 --> we still need u64 to index and count bytes
 *			(that's 32 GiB of bitmap for 1 PiB storage)
 * 1 << (35 - 2)	32bit longs needed
 *	33 --> we'd even need u64 to index and count 32bit long words.
 * 1 << (35 - 3)	64bit longs needed
 *	32 --> we could get away with a 32bit unsigned int to index and count
 *	64bit long words, but I rather stay with unsigned long for now.
 *	We probably should neither count nor point to bytes or long words
 *	directly, but either by bitnumber, or by page index and offset.
 * 1 << (35 - 12)
 *	22 --> we need that much 4KiB pages of bitmap.
 *	1 << (22 + 3) --> on a 64bit arch,
 *	we need 32 MiB to store the array of page pointers.
 *
 * Because I'm lazy, and because the resulting patch was too large, too ugly
 * and still incomplete, on 32bit we still "only" support 16 TiB (minus some),
 * (1 << 32) bits * 4k storage.
 *

 * bitmap storage and IO:
 *	Bitmap is stored little endian on disk, and is kept little endian in
 *	core memory. Currently we still hold the full bitmap in core as long
 *	as we are "attached" to a local disk, which at 32 GiB for 1PiB storage
 *	seems excessive.
 *
 *	We plan to reduce the amount of in-core bitmap pages by paging them in
 *	and out against their on-disk location as necessary, but need to make
 *	sure we don't cause too much meta data IO, and must not deadlock in
 *	tight memory situations. This needs some more work.
 */

/*
 * NOTE
 *  Access to the *bm_pages is protected by bm_lock.
 *  It is safe to read the other members within the lock.
 *
 *  drbd_bm_set_bits is called from bio_endio callbacks,
 *  We may be called with irq already disabled,
 *  so we need spin_lock_irqsave().
 *  And we need the kmap_atomic.
 */

enum bitmap_operations {
	BM_OP_CLEAR,
	BM_OP_SET,
	BM_OP_TEST,
	BM_OP_COUNT,
	BM_OP_MERGE,
	BM_OP_EXTRACT,
	BM_OP_FIND_BIT,
	BM_OP_FIND_ZERO_BIT,
};

static void
bm_print_lock_info(struct drbd_device *device, unsigned int bitmap_index, enum bitmap_operations op)
{
	static const char *op_names[] = {
		[BM_OP_CLEAR] = "clear",
		[BM_OP_SET] = "set",
		[BM_OP_TEST] = "test",
		[BM_OP_COUNT] = "count",
		[BM_OP_MERGE] = "merge",
		[BM_OP_EXTRACT] = "extract",
		[BM_OP_FIND_BIT] = "find_bit",
		[BM_OP_FIND_ZERO_BIT] = "find_zero_bit",
	};

	struct drbd_bitmap *b = device->bitmap;
	if (!drbd_ratelimit())
		return;
	drbd_err(device, "FIXME %s[%d] op %s, bitmap locked for '%s' by %s[%d]\n",
		 current->comm, task_pid_nr(current),
		 op_names[op], b->bm_why ?: "?",
		 b->bm_task_comm, b->bm_task_pid);
}

/* drbd_bm_lock() was introduced before drbd-9.0 to ensure that access to
   bitmap is locked out by other means (states, etc..). If a needed lock was
   not acquired or already taken a warning gets logged, and the critical
   sections get serialized on a mutex.

   Since drbd-9.0 actions on the bitmap could happen in parallel (e.g. "receive
   bitmap").
   The cheap solution taken right now, is to completely serialize bitmap
   operations but do not warn if they operate on different bitmap slots.

   The real solution is to make the locking more fine grained (one lock per
   bitmap slot) and to allow those operations to happen parallel.
 */
static void
_drbd_bm_lock(struct drbd_device *device, struct drbd_peer_device *peer_device,
	      char *why, enum bm_flag flags)
{
	struct drbd_bitmap *b = device->bitmap;
	int trylock_failed;

	if (!b) {
		drbd_err(device, "FIXME no bitmap in drbd_bm_lock!?\n");
		return;
	}

	trylock_failed = !mutex_trylock(&b->bm_change);

	if (trylock_failed && peer_device && b->bm_locked_peer != peer_device) {
		mutex_lock(&b->bm_change);
		trylock_failed = 0;
	}

	if (trylock_failed) {
		drbd_warn(device, "%s[%d] going to '%s' but bitmap already locked for '%s' by %s[%d]\n",
			  current->comm, task_pid_nr(current),
			  why, b->bm_why ?: "?",
			  b->bm_task_comm, b->bm_task_pid);
		mutex_lock(&b->bm_change);
	}
	if (b->bm_flags & BM_LOCK_ALL)
		drbd_err(device, "FIXME bitmap already locked in bm_lock\n");
	b->bm_flags |= flags & BM_LOCK_ALL;

	b->bm_why  = why;
	strcpy(b->bm_task_comm, current->comm);
	b->bm_task_pid = task_pid_nr(current);
	b->bm_locked_peer = peer_device;
}

void drbd_bm_lock(struct drbd_device *device, char *why, enum bm_flag flags)
{
	_drbd_bm_lock(device, NULL, why, flags);
}

void drbd_bm_slot_lock(struct drbd_peer_device *peer_device, char *why, enum bm_flag flags)
{
	_drbd_bm_lock(peer_device->device, peer_device, why, flags);
}

void drbd_bm_unlock(struct drbd_device *device)
{
	struct drbd_bitmap *b = device->bitmap;
	if (!b) {
		drbd_err(device, "FIXME no bitmap in drbd_bm_unlock!?\n");
		return;
	}

	if (!(device->bitmap->bm_flags & BM_LOCK_ALL))
		drbd_err(device, "FIXME bitmap not locked in bm_unlock\n");

	b->bm_flags &= ~BM_LOCK_ALL;
	b->bm_why  = NULL;
	b->bm_task_comm[0] = 0;
	b->bm_task_pid = 0;
	b->bm_locked_peer = NULL;
	mutex_unlock(&b->bm_change);
}

void drbd_bm_slot_unlock(struct drbd_peer_device *peer_device)
{
	drbd_bm_unlock(peer_device->device);
}

/* we store some "meta" info about our pages in page->private */
/* at a granularity of 4k storage per bitmap bit:
 * one peta byte storage: 1<<50 byte, 1<<38 * 4k storage blocks
 *  1<<38 bits,
 *  1<<23 4k bitmap pages.
 * Use 24 bits as page index, covers 2 peta byte storage
 * at a granularity of 4k per bit.
 * Used to report the failed page idx on io error from the endio handlers.
 */
#define BM_PAGE_IDX_MASK	((1UL<<24)-1)
/* this page is currently read in, or written back */
#define BM_PAGE_IO_LOCK		31
/* if there has been an IO error for this page */
#define BM_PAGE_IO_ERROR	30
/* this is to be able to intelligently skip disk IO,
 * set if bits have been set since last IO. */
#define BM_PAGE_NEED_WRITEOUT	29
/* to mark for lazy writeout once syncer cleared all clearable bits,
 * we if bits have been cleared since last IO. */
#define BM_PAGE_LAZY_WRITEOUT	28
/* pages marked with this "HINT" will be considered for writeout
 * on activity log transactions */
#define BM_PAGE_HINT_WRITEOUT	27

/* store_page_idx uses non-atomic assignment. It is only used directly after
 * allocating the page.  All other bm_set_page_* and bm_clear_page_* need to
 * use atomic bit manipulation, as set_out_of_sync (and therefore bitmap
 * changes) may happen from various contexts, and wait_on_bit/wake_up_bit
 * requires it all to be atomic as well. */
static void bm_store_page_idx(struct page *page, unsigned long idx)
{
	BUG_ON(0 != (idx & ~BM_PAGE_IDX_MASK));
	set_page_private(page, idx);
}

static unsigned long bm_page_to_idx(struct page *page)
{
	return page_private(page) & BM_PAGE_IDX_MASK;
}

/* As is very unlikely that the same page is under IO from more than one
 * context, we can get away with a bit per page and one wait queue per bitmap.
 */
static void bm_page_lock_io(struct drbd_device *device, int page_nr)
{
	struct drbd_bitmap *b = device->bitmap;
	void *addr = &page_private(b->bm_pages[page_nr]);
	wait_event(b->bm_io_wait, !test_and_set_bit(BM_PAGE_IO_LOCK, addr));
}

static void bm_page_unlock_io(struct drbd_device *device, int page_nr)
{
	struct drbd_bitmap *b = device->bitmap;
	void *addr = &page_private(b->bm_pages[page_nr]);
	clear_bit_unlock(BM_PAGE_IO_LOCK, addr);
	wake_up(&device->bitmap->bm_io_wait);
}

/* set _before_ submit_io, so it may be reset due to being changed
 * while this page is in flight... will get submitted later again */
static void bm_set_page_unchanged(struct page *page)
{
	/* use cmpxchg? */
	clear_bit(BM_PAGE_NEED_WRITEOUT, &page_private(page));
	clear_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

static void bm_set_page_need_writeout(struct drbd_bitmap *bitmap, unsigned int page_nr)
{
	if (!(bitmap->bm_flags & BM_ON_DAX_PMEM)) {
		struct page *page = bitmap->bm_pages[page_nr];
		set_bit(BM_PAGE_NEED_WRITEOUT, &page_private(page));
	}
}

void drbd_bm_reset_al_hints(struct drbd_device *device)
{
	device->bitmap->n_bitmap_hints = 0;
}

static int bm_test_page_unchanged(struct page *page)
{
	volatile const unsigned long *addr = &page_private(page);
	return (*addr & ((1UL<<BM_PAGE_NEED_WRITEOUT)|(1UL<<BM_PAGE_LAZY_WRITEOUT))) == 0;
}

static void bm_set_page_io_err(struct page *page)
{
	set_bit(BM_PAGE_IO_ERROR, &page_private(page));
}

static void bm_clear_page_io_err(struct page *page)
{
	clear_bit(BM_PAGE_IO_ERROR, &page_private(page));
}

static void bm_set_page_lazy_writeout(struct drbd_bitmap *bitmap, unsigned int page_nr)
{
	if (!(bitmap->bm_flags & BM_ON_DAX_PMEM)) {
		struct page *page = bitmap->bm_pages[page_nr];
		set_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
	}
}

static int bm_test_page_lazy_writeout(struct page *page)
{
	return test_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

/*
 * actually most functions herein should take a struct drbd_bitmap*, not a
 * struct drbd_device*, but for the debug macros I like to have the device around
 * to be able to report device specific.
 */


static void bm_free_pages(struct page **pages, unsigned long number)
{
	unsigned long i;
	if (!pages)
		return;

	for (i = 0; i < number; i++) {
		if (!pages[i]) {
			pr_alert("bm_free_pages tried to free a NULL pointer; i=%lu n=%lu\n",
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
static struct page **bm_realloc_pages(struct drbd_bitmap *b, unsigned long want)
{
	struct page **old_pages = b->bm_pages;
	struct page **new_pages, *page;
	unsigned int i, bytes;
	unsigned long have = b->bm_number_of_pages;

	BUG_ON(have == 0 && old_pages != NULL);
	BUG_ON(have != 0 && old_pages == NULL);

	if (have == want)
		return old_pages;

	/* Trying kmalloc first, falling back to vmalloc.
	 * GFP_NOIO, as this is called while drbd IO is "suspended",
	 * and during resize or attach on diskless Primary,
	 * we must not block on IO to ourselves.
	 * Context is receiver thread or dmsetup. */
	bytes = sizeof(struct page *)*want;
	new_pages = kzalloc(bytes, GFP_NOIO | __GFP_NOWARN);
	if (!new_pages) {
		new_pages = __vmalloc(bytes,
				GFP_NOIO | __GFP_HIGHMEM | __GFP_ZERO);
		if (!new_pages)
			return NULL;
	}

	if (want >= have) {
		for (i = 0; i < have; i++)
			new_pages[i] = old_pages[i];
		for (; i < want; i++) {
			page = alloc_page(GFP_NOIO | __GFP_HIGHMEM | __GFP_ZERO);
			if (!page) {
				bm_free_pages(new_pages + have, i - have);
				kvfree(new_pages);
				return NULL;
			}
			/* we want to know which page it is
			 * from the endio handlers */
			bm_store_page_idx(page, i);
			new_pages[i] = page;
		}
	} else {
		for (i = 0; i < want; i++)
			new_pages[i] = old_pages[i];
		/* NOT HERE, we are outside the spinlock!
		bm_free_pages(old_pages + want, have - want);
		*/
	}
	return new_pages;
}

struct drbd_bitmap *drbd_bm_alloc(void)
{
	struct drbd_bitmap *b;

	b = kzalloc(sizeof(struct drbd_bitmap), GFP_KERNEL);
	if (!b)
		return NULL;

	spin_lock_init(&b->bm_lock);
	mutex_init(&b->bm_change);
	init_waitqueue_head(&b->bm_io_wait);

	b->bm_max_peers = 1;

	return b;
}

sector_t drbd_bm_capacity(struct drbd_device *device)
{
	if (!expect(device, device->bitmap))
		return 0;
	return device->bitmap->bm_dev_capacity;
}

void drbd_bm_free(struct drbd_bitmap *bitmap)
{
	if (bitmap->bm_flags & BM_ON_DAX_PMEM)
		return;

	bm_free_pages(bitmap->bm_pages, bitmap->bm_number_of_pages);
	kvfree(bitmap->bm_pages);
	kfree(bitmap);
}

static inline unsigned long interleaved_word32(struct drbd_bitmap *bitmap,
					       unsigned int bitmap_index,
					       unsigned long bit)
{
	return (bit >> 5) * bitmap->bm_max_peers + bitmap_index;
}

static inline unsigned long word32_to_page(unsigned long word)
{
	return word >> (PAGE_SHIFT - 2);
}

static inline unsigned int word32_in_page(unsigned long word)
{
	return word & ((1 << (PAGE_SHIFT - 2)) - 1);
}

static inline unsigned long last_bit_on_page(struct drbd_bitmap *bitmap,
					     unsigned int bitmap_index,
					     unsigned long bit)
{
	unsigned long word = interleaved_word32(bitmap, bitmap_index, bit);

	return (bit | 31) + ((word32_in_page(-(word + 1)) / bitmap->bm_max_peers) << 5);
}

static inline unsigned long bit_to_page_interleaved(struct drbd_bitmap *bitmap,
						    unsigned int bitmap_index,
						    unsigned long bit)
{
	return word32_to_page(interleaved_word32(bitmap, bitmap_index, bit));
}

static void *bm_map(struct drbd_bitmap *bitmap, unsigned int page)
{
	if (!(bitmap->bm_flags & BM_ON_DAX_PMEM))
		return kmap_atomic(bitmap->bm_pages[page]);

	return ((unsigned char *)bitmap->bm_on_pmem) + (unsigned long)page * PAGE_SIZE;
}

static void bm_unmap(struct drbd_bitmap *bitmap, void *addr)
{
	if (!(bitmap->bm_flags & BM_ON_DAX_PMEM))
		kunmap_atomic(addr);
}

static __always_inline unsigned long
____bm_op(struct drbd_device *device, unsigned int bitmap_index, unsigned long start, unsigned long end,
	 enum bitmap_operations op, __le32 *buffer)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int word32_skip = 32 * bitmap->bm_max_peers;
	unsigned long total = 0;
	unsigned long word;
	unsigned int page, bit_in_page;

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	word = interleaved_word32(bitmap, bitmap_index, start);
	page = word32_to_page(word);
	bit_in_page = (word32_in_page(word) << 5) | (start & 31);

	for (; start <= end; page++) {
		unsigned int count = 0;
		void *addr;

		addr = bm_map(bitmap, page);
		if (((start & 31) && (start | 31) <= end) || op == BM_OP_TEST) {
			unsigned int last = bit_in_page | 31;

			switch(op) {
			default:
				do {
					switch(op) {
					case BM_OP_CLEAR:
						if (__test_and_clear_bit_le(bit_in_page, addr))
							count++;
						break;
					case BM_OP_SET:
						if (!__test_and_set_bit_le(bit_in_page, addr))
							count++;
						break;
					case BM_OP_COUNT:
						if (test_bit_le(bit_in_page, addr))
							total++;
						break;
					case BM_OP_TEST:
						total = !!test_bit_le(bit_in_page, addr);
						bm_unmap(bitmap, addr);
						return total;
					default:
						break;
					}
					bit_in_page++;
				} while (bit_in_page <= last);
				break;
			case BM_OP_MERGE:
			case BM_OP_EXTRACT:
				BUG();
				break;
			case BM_OP_FIND_BIT:
				count = find_next_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				bit_in_page = last + 1;
				break;
			case BM_OP_FIND_ZERO_BIT:
				count = find_next_zero_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				bit_in_page = last + 1;
				break;
			}
			start = (start | 31) + 1;
			bit_in_page += word32_skip - 32;
			if (bit_in_page >= BITS_PER_PAGE)
				goto next_page;
		}

		while (start + 31 <= end) {
			__le32 *p = (__le32 *)addr + (bit_in_page >> 5);

			switch(op) {
			case BM_OP_CLEAR:
				count += hweight32(*p);
				*p = 0;
				break;
			case BM_OP_SET:
				count += hweight32(~*p);
				*p = -1;
				break;
			case BM_OP_TEST:
				BUG();
				break;
			case BM_OP_COUNT:
				total += hweight32(*p);
				break;
			case BM_OP_MERGE:
				count += hweight32(~*p & *buffer);
				*p |= *buffer++;
				break;
			case BM_OP_EXTRACT:
				*buffer++ = *p;
				break;
			case BM_OP_FIND_BIT:
				count = find_next_bit_le(addr, bit_in_page + 32, bit_in_page);
				if (count < bit_in_page + 32)
					goto found;
				break;
			case BM_OP_FIND_ZERO_BIT:
				count = find_next_zero_bit_le(addr, bit_in_page + 32, bit_in_page);
				if (count < bit_in_page + 32)
					goto found;
				break;
			}
			start += 32;
			bit_in_page += word32_skip;
			if (bit_in_page >= BITS_PER_PAGE)
				goto next_page;
		}

		/* don't overrun buffers with MERGE or EXTRACT,
		 * jump to the kunmap and then out... */
		if (start > end)
			goto next_page;

		switch(op) {
		default:
			while (start <= end) {
				switch(op) {
				case BM_OP_CLEAR:
					if (__test_and_clear_bit_le(bit_in_page, addr))
						count++;
					break;
				case BM_OP_SET:
					if (!__test_and_set_bit_le(bit_in_page, addr))
						count++;
					break;
				case BM_OP_COUNT:
					if (test_bit_le(bit_in_page, addr))
						total++;
					break;
				default:
					break;
				}
				start++;
				bit_in_page++;
			}
			break;
		case BM_OP_MERGE:
			{
				__le32 *p = (__le32 *)addr + (bit_in_page >> 5);
				__le32 b = *buffer++ & cpu_to_le32((1 << (end - start + 1)) - 1);

				count += hweight32(~*p & b);
				*p |= b;

				start = end + 1;
			}
			break;
		case BM_OP_EXTRACT:
			{
				__le32 *p = (__le32 *)addr + (bit_in_page >> 5);

				*buffer++ = *p & cpu_to_le32((1 << (end - start + 1)) - 1);
				start = end + 1;
			}
			break;
		case BM_OP_FIND_BIT:
			{
				unsigned int last = bit_in_page + (end - start);

				count = find_next_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				start = end + 1;
			}
			break;
		case BM_OP_FIND_ZERO_BIT:
			{
				unsigned int last = bit_in_page + (end - start);
				count = find_next_zero_bit_le(addr, last + 1, bit_in_page);
				if (count < last + 1)
					goto found;
				start = end + 1;
			}
			break;
		}

	    next_page:
		bm_unmap(bitmap, addr);
		bit_in_page -= BITS_PER_PAGE;
		switch(op) {
		case BM_OP_CLEAR:
			if (count) {
				bm_set_page_lazy_writeout(bitmap, page);
				total += count;
			}
			break;
		case BM_OP_SET:
		case BM_OP_MERGE:
			if (count) {
				bm_set_page_need_writeout(bitmap, page);
				total += count;
			}
			break;
		default:
			break;
		}
		continue;

	    found:
		bm_unmap(bitmap, addr);
		return start + count - bit_in_page;
	}
	switch(op) {
	case BM_OP_CLEAR:
		if (total)
			bitmap->bm_set[bitmap_index] -= total;
		break;
	case BM_OP_SET:
	case BM_OP_MERGE:
		if (total)
			bitmap->bm_set[bitmap_index] += total;
		break;
	case BM_OP_FIND_BIT:
	case BM_OP_FIND_ZERO_BIT:
		total = DRBD_END_OF_BITMAP;
		break;
	default:
		break;
	}
	return total;
}

/* Returns the number of bits changed.  */
static __always_inline unsigned long
__bm_op(struct drbd_device *device, unsigned int bitmap_index, unsigned long start, unsigned long end,
	enum bitmap_operations op, __le32 *buffer)
/* kmap compat: KM_IRQ1 */
{
	struct drbd_bitmap *bitmap = device->bitmap;

	if (!expect(device, bitmap))
		return 1;
	if (!expect(device, bitmap->bm_pages))
		return 0;

	if (!bitmap->bm_bits)
		return 0;

	if (bitmap->bm_task_pid != task_pid_nr(current)) {
		switch(op) {
		case BM_OP_CLEAR:
			if (bitmap->bm_flags & BM_LOCK_CLEAR)
				bm_print_lock_info(device, bitmap_index, op);
			break;
		case BM_OP_SET:
		case BM_OP_MERGE:
			if (bitmap->bm_flags & BM_LOCK_SET)
				bm_print_lock_info(device, bitmap_index, op);
			break;
		case BM_OP_TEST:
		case BM_OP_COUNT:
		case BM_OP_EXTRACT:
		case BM_OP_FIND_BIT:
		case BM_OP_FIND_ZERO_BIT:
			if (bitmap->bm_flags & BM_LOCK_TEST)
				bm_print_lock_info(device, bitmap_index, op);
			break;
		}
	}
	return ____bm_op(device, bitmap_index, start, end, op, buffer);
}

static __always_inline unsigned long
bm_op(struct drbd_device *device, unsigned int bitmap_index, unsigned long start, unsigned long end,
      enum bitmap_operations op, __le32 *buffer)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned long irq_flags;
	unsigned long count;

	spin_lock_irqsave(&bitmap->bm_lock, irq_flags);
	count = __bm_op(device, bitmap_index, start, end, op, buffer);
	spin_unlock_irqrestore(&bitmap->bm_lock, irq_flags);
	return count;
}

#ifdef BITMAP_DEBUG
#define bm_op(device, bitmap_index, start, end, op, buffer) \
	({ unsigned long ret; \
	   drbd_info(device, "%s: bm_op(..., %u, %lu, %lu, %u, %p)\n", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = bm_op(device, bitmap_index, start, end, op, buffer); \
	   drbd_info(device, "= %lu\n", ret); \
	   ret; })

#define __bm_op(device, bitmap_index, start, end, op, buffer) \
	({ unsigned long ret; \
	   drbd_info(device, "%s: __bm_op(..., %u, %lu, %lu, %u, %p)\n", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = __bm_op(device, bitmap_index, start, end, op, buffer); \
	   drbd_info(device, "= %lu\n", ret); \
	   ret; })
#endif

#ifdef BITMAP_DEBUG
#define ___bm_op(device, bitmap_index, start, end, op, buffer) \
	({ unsigned long ret; \
	   drbd_info(device, "%s: ___bm_op(..., %u, %lu, %lu, %u, %p)\n", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = ____bm_op(device, bitmap_index, start, end, op, buffer); \
	   drbd_info(device, "= %lu\n", ret); \
	   ret; })
#else
#define ___bm_op(device, bitmap_index, start, end, op, buffer) \
	____bm_op(device, bitmap_index, start, end, op, buffer)
#endif

/* you better not modify the bitmap while this is running,
 * or its results will be stale */
static void bm_count_bits(struct drbd_device *device)
/* kmap compat: KM_USER0 */
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int bitmap_index;

	for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++) {
		unsigned long bit = 0, bits_set = 0;

		while (bit < bitmap->bm_bits) {
			unsigned long last_bit = last_bit_on_page(bitmap, bitmap_index, bit);

			bits_set += ___bm_op(device, bitmap_index, bit, last_bit, BM_OP_COUNT, NULL);
			bit = last_bit + 1;
			cond_resched();
		}
		bitmap->bm_set[bitmap_index] = bits_set;
	}
}

/* For the layout, see comment above drbd_md_set_sector_offsets(). */
static u64 drbd_md_on_disk_bits(struct drbd_device *device)
{
	struct drbd_backing_dev *ldev = device->ldev;
	u64 bitmap_sectors, word64_on_disk;
	if (ldev->md.al_offset == 8)
		bitmap_sectors = ldev->md.md_size_sect - ldev->md.bm_offset;
	else
		bitmap_sectors = ldev->md.al_offset - ldev->md.bm_offset;

	/* for interoperability between 32bit and 64bit architectures,
	 * we round on 64bit words.  FIXME do we still need this? */
	word64_on_disk = bitmap_sectors << (9 - 3); /* x * (512/8) */
	do_div(word64_on_disk, device->bitmap->bm_max_peers);
	return word64_on_disk << 6; /* x * 64 */;
}

/*
 * make sure the bitmap has enough room for the attached storage,
 * if necessary, resize.
 * called whenever we may have changed the device size.
 * returns -ENOMEM if we could not allocate enough memory, 0 on success.
 * In case this is actually a resize, we copy the old bitmap into the new one.
 * Otherwise, the bitmap is initialized to all bits set.
 */
int drbd_bm_resize(struct drbd_device *device, sector_t capacity, bool set_new_bits)
/* kmap compat: KM_IRQ1 */
{
	struct drbd_bitmap *b = device->bitmap;
	unsigned long bits, words, obits;
	unsigned long want, have, onpages; /* number of pages */
	struct page **npages = NULL, **opages = NULL;
	void *bm_on_pmem = NULL;
	int err = 0;
	bool growing;

	if (!expect(device, b))
		return -ENOMEM;

	drbd_bm_lock(device, "resize", BM_LOCK_ALL);

	drbd_info(device, "drbd_bm_resize called with capacity == %llu\n",
			(unsigned long long)capacity);

	if (capacity == b->bm_dev_capacity)
		goto out;

	if (capacity == 0) {
		unsigned int bitmap_index;

		spin_lock_irq(&b->bm_lock);
		opages = b->bm_pages;
		onpages = b->bm_number_of_pages;
		b->bm_pages = NULL;
		b->bm_number_of_pages = 0;
		for (bitmap_index = 0; bitmap_index < b->bm_max_peers; bitmap_index++)
			b->bm_set[bitmap_index] = 0;
		b->bm_bits = 0;
		b->bm_words = 0;
		b->bm_dev_capacity = 0;
		spin_unlock_irq(&b->bm_lock);
		if (!(b->bm_flags & BM_ON_DAX_PMEM)) {
			bm_free_pages(opages, onpages);
			kvfree(opages);
		}
		goto out;
	}
	bits  = BM_SECT_TO_BIT(ALIGN(capacity, BM_SECT_PER_BIT));
	words = (ALIGN(bits, 64) * b->bm_max_peers) / BITS_PER_LONG;

	if (get_ldev(device)) {
		u64 bits_on_disk = drbd_md_on_disk_bits(device);
		put_ldev(device);
		if (bits > bits_on_disk) {
			drbd_err(device, "Not enough space for bitmap: %lu > %lu\n",
				(unsigned long)bits, (unsigned long)bits_on_disk);
			err = -ENOSPC;
			goto out;
		}
	}

	want = ALIGN(words*sizeof(long), PAGE_SIZE) >> PAGE_SHIFT;
	have = b->bm_number_of_pages;
	if (drbd_md_dax_active(device->ldev)) {
		bm_on_pmem = drbd_dax_bitmap(device, want);
	} else {
		if (want == have) {
			D_ASSERT(device, b->bm_pages != NULL);
			npages = b->bm_pages;
		} else {
			if (drbd_insert_fault(device, DRBD_FAULT_BM_ALLOC))
				npages = NULL;
			else
				npages = bm_realloc_pages(b, want);
		}

		if (!npages) {
			err = -ENOMEM;
			goto out;
		}
	}

	spin_lock_irq(&b->bm_lock);
	obits  = b->bm_bits;

	growing = bits > obits;

	if (bm_on_pmem) {
		if (b->bm_on_pmem) {
			void *src = b->bm_on_pmem;
			memmove(bm_on_pmem, src, b->bm_words * sizeof(long));
			arch_wb_cache_pmem(bm_on_pmem, b->bm_words * sizeof(long));
		} else {
			/* We are attaching a bitmap on PMEM. Since the memory
			 * is persistent, the bitmap is still valid. Do not
			 * overwrite it. */
			growing = false;
		}
		b->bm_on_pmem = bm_on_pmem;
		b->bm_flags |= BM_ON_DAX_PMEM;
	} else {
		opages = b->bm_pages;
		b->bm_pages = npages;
	}
	b->bm_number_of_pages = want;
	b->bm_bits  = bits;
	b->bm_words = words;
	b->bm_dev_capacity = capacity;

	if (growing) {
		unsigned int bitmap_index;

		for (bitmap_index = 0; bitmap_index < b->bm_max_peers; bitmap_index++) {
			unsigned long bm_set = b->bm_set[bitmap_index];

			if (set_new_bits) {
				___bm_op(device, bitmap_index, obits, -1UL, BM_OP_SET, NULL);
				bm_set += bits - obits;
			}
			else
				___bm_op(device, bitmap_index, obits, -1UL, BM_OP_CLEAR, NULL);

			b->bm_set[bitmap_index] = bm_set;
		}
	}

	if (want < have && !(b->bm_flags & BM_ON_DAX_PMEM)) {
		/* implicit: (opages != NULL) && (opages != npages) */
		bm_free_pages(opages + want, have - want);
	}

	spin_unlock_irq(&b->bm_lock);
	if (opages != npages)
		kvfree(opages);
	if (!growing)
		bm_count_bits(device);
	drbd_info(device, "resync bitmap: bits=%lu words=%lu pages=%lu\n", bits, words, want);

 out:
	drbd_bm_unlock(device);
	return err;
}

/* inherently racy:
 * if not protected by other means, return value may be out of date when
 * leaving this function...
 * we still need to lock it, since it is important that this returns
 * bm_set == 0 precisely.
 */
unsigned long _drbd_bm_total_weight(struct drbd_device *device, int bitmap_index)
{
	struct drbd_bitmap *b = device->bitmap;
	unsigned long s;
	unsigned long flags;

	if (!expect(device, b))
		return 0;
	if (!expect(device, b->bm_pages))
		return 0;

	spin_lock_irqsave(&b->bm_lock, flags);
	s = b->bm_set[bitmap_index];
	spin_unlock_irqrestore(&b->bm_lock, flags);

	return s;
}

unsigned long drbd_bm_total_weight(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	unsigned long s;

	if (peer_device->bitmap_index == -1)
		return 0;

	/* if I don't have a disk, I don't know about out-of-sync status */
	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return 0;
	s = _drbd_bm_total_weight(device, peer_device->bitmap_index);
	put_ldev(device);
	return s;
}

/* Returns the number of unsigned long words per peer */
size_t drbd_bm_words(struct drbd_device *device)
{
	struct drbd_bitmap *b = device->bitmap;
	if (!expect(device, b))
		return 0;
	if (!expect(device, b->bm_pages))
		return 0;

	return b->bm_words / b->bm_max_peers;
}

unsigned long drbd_bm_bits(struct drbd_device *device)
{
	struct drbd_bitmap *b = device->bitmap;
	if (!expect(device, b))
		return 0;

	return b->bm_bits;
}

/* merge number words from buffer into the bitmap starting at offset.
 * buffer[i] is expected to be little endian unsigned long.
 * bitmap must be locked by drbd_bm_lock.
 * currently only used from receive_bitmap.
 */
void drbd_bm_merge_lel(struct drbd_peer_device *peer_device, size_t offset, size_t number,
			unsigned long *buffer)
{
	unsigned long start, end;

	start = offset * BITS_PER_LONG;
	end = start + number * BITS_PER_LONG - 1;
	bm_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_MERGE, (__le32 *)buffer);
}

/* copy number words from the bitmap starting at offset into the buffer.
 * buffer[i] will be little endian unsigned long.
 */
void drbd_bm_get_lel(struct drbd_peer_device *peer_device, size_t offset, size_t number,
		     unsigned long *buffer)
{
	unsigned long start, end;

	start = offset * BITS_PER_LONG;
	end = start + number * BITS_PER_LONG - 1;
	bm_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_EXTRACT, (__le32 *)buffer);
}


static void drbd_bm_aio_ctx_destroy(struct kref *kref)
{
	struct drbd_bm_aio_ctx *ctx = container_of(kref, struct drbd_bm_aio_ctx, kref);
	unsigned long flags;

	spin_lock_irqsave(&ctx->device->resource->req_lock, flags);
	list_del(&ctx->list);
	spin_unlock_irqrestore(&ctx->device->resource->req_lock, flags);
	put_ldev(ctx->device);
	kfree(ctx);
}

/* bv_page may be a copy, or may be the original */
static void drbd_bm_endio(struct bio *bio)
{
	struct drbd_bm_aio_ctx *ctx = bio->bi_private;
	struct drbd_device *device = ctx->device;
	struct drbd_bitmap *b = device->bitmap;
	unsigned int idx = bm_page_to_idx(bio->bi_io_vec[0].bv_page);

	blk_status_t status = bio->bi_status;

	if ((ctx->flags & BM_AIO_COPY_PAGES) == 0 &&
	    !bm_test_page_unchanged(b->bm_pages[idx]))
		drbd_warn(device, "bitmap page idx %u changed during IO!\n", idx);

	if (status) {
		/* ctx error will hold the completed-last non-zero error code,
		 * in case error codes differ. */
		ctx->error = blk_status_to_errno(status);
		bm_set_page_io_err(b->bm_pages[idx]);
		/* Not identical to on disk version of it.
		 * Is BM_PAGE_IO_ERROR enough? */
		if (drbd_ratelimit())
			drbd_err(device, "IO ERROR %d on bitmap page idx %u\n",
				 status, idx);
	} else {
		bm_clear_page_io_err(b->bm_pages[idx]);
		dynamic_drbd_dbg(device, "bitmap page idx %u completed\n", idx);
	}

	bm_page_unlock_io(device, idx);

	if (ctx->flags & BM_AIO_COPY_PAGES)
		mempool_free(bio->bi_io_vec[0].bv_page, &drbd_md_io_page_pool);

	bio_put(bio);

	if (atomic_dec_and_test(&ctx->in_flight)) {
		ctx->done = 1;
		wake_up(&device->misc_wait);
		kref_put(&ctx->kref, &drbd_bm_aio_ctx_destroy);
	}
}

static void bm_page_io_async(struct drbd_bm_aio_ctx *ctx, int page_nr) __must_hold(local)
{
	struct bio *bio = bio_alloc_drbd(GFP_NOIO);
	struct drbd_device *device = ctx->device;
	struct drbd_bitmap *b = device->bitmap;
	struct page *page;
	unsigned int len;
	unsigned int op = (ctx->flags & BM_AIO_READ) ? REQ_OP_READ : REQ_OP_WRITE;

	sector_t on_disk_sector =
		device->ldev->md.md_offset + device->ldev->md.bm_offset;
	on_disk_sector += ((sector_t)page_nr) << (PAGE_SHIFT-9);

	/* this might happen with very small
	 * flexible external meta data device,
	 * or with PAGE_SIZE > 4k */
	len = min_t(unsigned int, PAGE_SIZE,
		(drbd_md_last_sector(device->ldev) - on_disk_sector + 1)<<9);

	/* serialize IO on this page */
	bm_page_lock_io(device, page_nr);
	/* before memcpy and submit,
	 * so it can be redirtied any time */
	bm_set_page_unchanged(b->bm_pages[page_nr]);

	if (ctx->flags & BM_AIO_COPY_PAGES) {
		page = mempool_alloc(&drbd_md_io_page_pool,
				GFP_NOIO | __GFP_HIGHMEM);
		copy_highpage(page, b->bm_pages[page_nr]);
		bm_store_page_idx(page, page_nr);
	} else
		page = b->bm_pages[page_nr];
	bio_set_dev(bio, device->ldev->md_bdev);
	bio->bi_iter.bi_sector = on_disk_sector;
	/* bio_add_page of a single page to an empty bio will always succeed,
	 * according to api.  Do we want to assert that? */
	bio_add_page(bio, page, len, 0);
	bio->bi_private = ctx;
	bio->bi_end_io = drbd_bm_endio;
	bio->bi_opf = op;

	if (drbd_insert_fault(device, (op == REQ_OP_WRITE) ? DRBD_FAULT_MD_WR : DRBD_FAULT_MD_RD)) {
		bio->bi_status = BLK_STS_IOERR;
		bio_endio(bio);
	} else {
		submit_bio(bio);
		/* this should not count as user activity and cause the
		 * resync to throttle -- see drbd_rs_should_slow_down(). */
		atomic_add(len >> 9, &device->rs_sect_ev);
	}
}

/**
 * bm_rw_range() - read/write the specified range of bitmap pages
 * @device: drbd device this bitmap is associated with
 * @rw:	READ or WRITE
 * @start_page, @end_page: inclusive range of bitmap page indices to process
 * @flags: BM_AIO_*, see struct bm_aio_ctx.
 *
 * Silently limits end_page to the current bitmap size.
 *
 * We don't want to special case on logical_block_size of the backend device,
 * so we submit PAGE_SIZE aligned pieces.
 * Note that on "most" systems, PAGE_SIZE is 4k.
 *
 * In case this becomes an issue on systems with larger PAGE_SIZE,
 * we may want to change this again to do 4k aligned 4k pieces.
 */
static int bm_rw_range(struct drbd_device *device,
	unsigned int start_page, unsigned int end_page,
	unsigned flags) __must_hold(local)
{
	struct drbd_bm_aio_ctx *ctx;
	struct drbd_bitmap *b = device->bitmap;
	unsigned int i, count = 0;
	unsigned long now;
	int err = 0;

	if (b->bm_flags & BM_ON_DAX_PMEM) {
		if (flags & (BM_AIO_WRITE_HINTED | BM_AIO_WRITE_ALL_PAGES | BM_AIO_WRITE_LAZY))
			arch_wb_cache_pmem(b->bm_on_pmem, b->bm_words * sizeof(long));
		return 0;
	}
	/*
	 * We are protected against bitmap disappearing/resizing by holding an
	 * ldev reference (caller must have called get_ldev()).
	 * For read/write, we are protected against changes to the bitmap by
	 * the bitmap lock (see drbd_bitmap_io).
	 * For lazy writeout, we don't care for ongoing changes to the bitmap,
	 * as we submit copies of pages anyways.
	 */

	/* if we reach this, we should have at least *some* bitmap pages. */
	if (!expect(device, b->bm_number_of_pages))
		return -ENODEV;

	ctx = kmalloc(sizeof(struct drbd_bm_aio_ctx), GFP_NOIO);
	if (!ctx)
		return -ENOMEM;

	*ctx = (struct drbd_bm_aio_ctx) {
		.device = device,
		.start_jif = jiffies,
		.in_flight = ATOMIC_INIT(1),
		.done = 0,
		.flags = flags,
		.error = 0,
		.kref = KREF_INIT(2),
	};

	if (!expect(device, get_ldev_if_state(device, D_ATTACHING))) {  /* put is in drbd_bm_aio_ctx_destroy() */
		kfree(ctx);
		return -ENODEV;
	}
	/* Here, D_ATTACHING is sufficient because drbd_bm_read() is only
	 * called from drbd_adm_attach(), after device->ldev has been assigned.
	 *
	 * The corresponding put_ldev() happens in bm_aio_ctx_destroy().
	 */

	if (0 == (ctx->flags & ~BM_AIO_READ))
		WARN_ON(!(b->bm_flags & BM_LOCK_ALL));

	if (end_page >= b->bm_number_of_pages)
		end_page = b->bm_number_of_pages -1;

	spin_lock_irq(&device->resource->req_lock);
	list_add_tail(&ctx->list, &device->pending_bitmap_io);
	spin_unlock_irq(&device->resource->req_lock);

	now = jiffies;

	/* let the layers below us try to merge these bios... */

	if (flags & BM_AIO_READ) {
		for (i = start_page; i <= end_page; i++) {
			atomic_inc(&ctx->in_flight);
			bm_page_io_async(ctx, i);
			++count;
			cond_resched();
		}
	} else if (flags & BM_AIO_WRITE_HINTED) {
		/* ASSERT: BM_AIO_WRITE_ALL_PAGES is not set. */
		unsigned int hint;
		for (hint = 0; hint < b->n_bitmap_hints; hint++) {
			i = b->al_bitmap_hints[hint];
			if (i > end_page)
				continue;
			/* Several AL-extents may point to the same page. */
			if (!test_and_clear_bit(BM_PAGE_HINT_WRITEOUT,
			    &page_private(b->bm_pages[i])))
				continue;
			/* Has it even changed? */
			if (bm_test_page_unchanged(b->bm_pages[i]))
				continue;
			atomic_inc(&ctx->in_flight);
			bm_page_io_async(ctx, i);
			++count;
		}
	} else {
		for (i = start_page; i <= end_page; i++) {
			/* ignore completely unchanged pages,
			 * unless specifically requested to write ALL pages */
			if (!(flags & BM_AIO_WRITE_ALL_PAGES) &&
			    bm_test_page_unchanged(b->bm_pages[i])) {
				dynamic_drbd_dbg(device, "skipped bm write for idx %u\n", i);
				continue;
			}
			/* during lazy writeout,
			 * ignore those pages not marked for lazy writeout. */
			if ((flags & BM_AIO_WRITE_LAZY) &&
			    !bm_test_page_lazy_writeout(b->bm_pages[i])) {
				dynamic_drbd_dbg(device, "skipped bm lazy write for idx %u\n", i);
				continue;
			}
			atomic_inc(&ctx->in_flight);
			bm_page_io_async(ctx, i);
			++count;
			cond_resched();
		}
	}

	/*
	 * We initialize ctx->in_flight to one to make sure drbd_bm_endio
	 * will not set ctx->done early, and decrement / test it here.  If there
	 * are still some bios in flight, we need to wait for them here.
	 * If all IO is done already (or nothing had been submitted), there is
	 * no need to wait.  Still, we need to put the kref associated with the
	 * "in_flight reached zero, all done" event.
	 */
	if (!atomic_dec_and_test(&ctx->in_flight)) {
		wait_until_done_or_force_detached(device, device->ldev, &ctx->done);
	} else
		kref_put(&ctx->kref, &drbd_bm_aio_ctx_destroy);

	/* summary for global bitmap IO */
	if (flags == 0 && count) {
		unsigned int ms = jiffies_to_msecs(jiffies - now);
		if (ms > 5) {
			drbd_info(device, "bitmap %s of %u pages took %u ms\n",
				 (flags & BM_AIO_READ) ? "READ" : "WRITE",
				 count, ms);
		}
	}

	if (ctx->error) {
		drbd_err(device, "we had at least one MD IO ERROR during bitmap IO\n");
		drbd_chk_io_error(device, 1, DRBD_META_IO_ERROR);
		err = -EIO; /* ctx->error ? */
	}

	if (atomic_read(&ctx->in_flight))
		err = -EIO; /* Disk timeout/force-detach during IO... */

	if (flags & BM_AIO_READ) {
		now = jiffies;
		bm_count_bits(device);
		drbd_info(device, "recounting of set bits took additional %ums\n",
		     jiffies_to_msecs(jiffies - now));
	}

	kref_put(&ctx->kref, &drbd_bm_aio_ctx_destroy);
	return err;
}

static int bm_rw(struct drbd_device *device, unsigned flags)
{
	return bm_rw_range(device, 0, -1U, flags);
}

/**
 * drbd_bm_read() - Read the whole bitmap from its on disk location.
 * @device:	DRBD device.
 */
int drbd_bm_read(struct drbd_device *device,
		 struct drbd_peer_device *peer_device) __must_hold(local)
{
	return bm_rw(device, BM_AIO_READ);
}

static void push_al_bitmap_hint(struct drbd_device *device, unsigned int page_nr)
{
	struct drbd_bitmap *b = device->bitmap;
	struct page *page = b->bm_pages[page_nr];
	BUG_ON(b->n_bitmap_hints >= ARRAY_SIZE(b->al_bitmap_hints));
	if (!test_and_set_bit(BM_PAGE_HINT_WRITEOUT, &page_private(page)))
		b->al_bitmap_hints[b->n_bitmap_hints++] = page_nr;
}

/**
 * drbd_bm_mark_range_for_writeout() - mark with a "hint" to be considered for writeout
 * @device:	DRBD device.
 *
 * From within an activity log transaction, we mark a few pages with these
 * hints, then call drbd_bm_write_hinted(), which will only write out changed
 * pages which are flagged with this mark.
 */
void drbd_bm_mark_range_for_writeout(struct drbd_device *device, unsigned long start, unsigned long end)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int page_nr, last_page;

	if (bitmap->bm_flags & BM_ON_DAX_PMEM)
		return;

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	page_nr = bit_to_page_interleaved(bitmap, 0, start);
	last_page = bit_to_page_interleaved(bitmap, bitmap->bm_max_peers - 1, end);
	for (; page_nr <= last_page; page_nr++)
		push_al_bitmap_hint(device, page_nr);
}


/**
 * drbd_bm_write() - Write the whole bitmap to its on disk location.
 * @device:	DRBD device.
 *
 * Will only write pages that have changed since last IO.
 */
int drbd_bm_write(struct drbd_device *device,
		  struct drbd_peer_device *peer_device) __must_hold(local)
{
	return bm_rw(device, 0);
}

/**
 * drbd_bm_write_all() - Write the whole bitmap to its on disk location.
 * @device:	 DRBD device.
 * @peer_device: parameter ignored
 *
 * Will write all pages. Is used for online resize operations. The
 * whole bitmap should be written into its new position.
 */
int drbd_bm_write_all(struct drbd_device *device,
		      struct drbd_peer_device *peer_device) __must_hold(local)
{
	return bm_rw(device, BM_AIO_WRITE_ALL_PAGES);
}

/**
 * drbd_bm_write_lazy() - Write bitmap pages 0 to @upper_idx-1, if they have changed.
 * @device:	DRBD device.
 * @upper_idx:	0: write all changed pages; +ve: page index to stop scanning for changed pages
 */
int drbd_bm_write_lazy(struct drbd_device *device, unsigned upper_idx) __must_hold(local)
{
	return bm_rw_range(device, 0, upper_idx - 1, BM_AIO_COPY_PAGES | BM_AIO_WRITE_LAZY);
}

/**
 * drbd_bm_write_copy_pages() - Write the whole bitmap to its on disk location.
 * @device:	DRBD device.
 *
 * Will only write pages that have changed since last IO.
 * In contrast to drbd_bm_write(), this will copy the bitmap pages
 * to temporary writeout pages. It is intended to trigger a full write-out
 * while still allowing the bitmap to change, for example if a resync or online
 * verify is aborted due to a failed peer disk, while local IO continues, or
 * pending resync acks are still being processed.
 */
int drbd_bm_write_copy_pages(struct drbd_device *device,
			     struct drbd_peer_device *peer_device) __must_hold(local)
{
	return bm_rw(device, BM_AIO_COPY_PAGES);
}

/**
 * drbd_bm_write_hinted() - Write bitmap pages with "hint" marks, if they have changed.
 * @device:	DRBD device.
 */
int drbd_bm_write_hinted(struct drbd_device *device) __must_hold(local)
{
	return bm_rw(device, BM_AIO_WRITE_HINTED | BM_AIO_COPY_PAGES);
}

unsigned long drbd_bm_find_next(struct drbd_peer_device *peer_device, unsigned long start)
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		     BM_OP_FIND_BIT, NULL);
}

/* does not spin_lock_irqsave.
 * you must take drbd_bm_lock() first */
unsigned long _drbd_bm_find_next(struct drbd_peer_device *peer_device, unsigned long start)
/* kmap compat: KM_USER0 */
{
	/* WARN_ON(!(device->b->bm_flags & BM_LOCK_SET)); */
	return ____bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		    BM_OP_FIND_BIT, NULL);
}

unsigned long _drbd_bm_find_next_zero(struct drbd_peer_device *peer_device, unsigned long start)
/* kmap compat: KM_USER0 */
{
	/* WARN_ON(!(device->b->bm_flags & BM_LOCK_SET)); */
	return ____bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		    BM_OP_FIND_ZERO_BIT, NULL);
}

unsigned int drbd_bm_set_bits(struct drbd_device *device, unsigned int bitmap_index,
			      unsigned long start, unsigned long end)
{
	return bm_op(device, bitmap_index, start, end, BM_OP_SET, NULL);
}

static __always_inline void
__bm_many_bits_op(struct drbd_device *device, unsigned int bitmap_index, unsigned long start, unsigned long end,
		  enum bitmap_operations op)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned long bit = start;

	spin_lock_irq(&bitmap->bm_lock);

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	while (bit <= end) {
		unsigned long last_bit = last_bit_on_page(bitmap, bitmap_index, bit);

		if (end < last_bit)
			last_bit = end;

		__bm_op(device, bitmap_index, bit, last_bit, op, NULL);
		bit = last_bit + 1;
		if (need_resched()) {
			spin_unlock_irq(&bitmap->bm_lock);
			cond_resched();
			spin_lock_irq(&bitmap->bm_lock);
		}
	}
	spin_unlock_irq(&bitmap->bm_lock);
}

void drbd_bm_set_many_bits(struct drbd_peer_device *peer_device, unsigned long start, unsigned long end)
{
	if (peer_device->bitmap_index == -1)
		return;
	__bm_many_bits_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_SET);
}

void drbd_bm_clear_many_bits(struct drbd_peer_device *peer_device, unsigned long start, unsigned long end)
{
	if (peer_device->bitmap_index == -1)
		return;
	__bm_many_bits_op(peer_device->device, peer_device->bitmap_index, start, end, BM_OP_CLEAR);
}

void
_drbd_bm_clear_many_bits(struct drbd_device *device, int bitmap_index, unsigned long start, unsigned long end)
{
	__bm_many_bits_op(device, bitmap_index, start, end, BM_OP_CLEAR);
}

void
_drbd_bm_set_many_bits(struct drbd_device *device, int bitmap_index, unsigned long start, unsigned long end)
{
	__bm_many_bits_op(device, bitmap_index, start, end, BM_OP_SET);
}

/* set all bits in the bitmap */
void drbd_bm_set_all(struct drbd_device *device)
{
       struct drbd_bitmap *bitmap = device->bitmap;
       unsigned int bitmap_index;

       for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++)
	       __bm_many_bits_op(device, bitmap_index, 0, -1, BM_OP_SET);
}

/* clear all bits in the bitmap */
void drbd_bm_clear_all(struct drbd_device *device)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int bitmap_index;

	for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++)
		__bm_many_bits_op(device, bitmap_index, 0, -1, BM_OP_CLEAR);
}

unsigned int drbd_bm_clear_bits(struct drbd_device *device, unsigned int bitmap_index,
				unsigned long start, unsigned long end)
{
	return bm_op(device, bitmap_index, start, end, BM_OP_CLEAR, NULL);
}

/* returns bit state
 * wants bitnr, NOT sector.
 * inherently racy... area needs to be locked by means of {al,rs}_lru
 *  1 ... bit set
 *  0 ... bit not set
 * -1 ... first out of bounds access, stop testing for bits!
 */
int drbd_bm_test_bit(struct drbd_peer_device *peer_device, const unsigned long bitnr)
{
	struct drbd_bitmap *bitmap = peer_device->device->bitmap;
	unsigned long irq_flags;
	int ret;

	spin_lock_irqsave(&bitmap->bm_lock, irq_flags);
	if (bitnr >= bitmap->bm_bits)
		ret = -1;
	else
		ret = __bm_op(peer_device->device, peer_device->bitmap_index, bitnr, bitnr,
			      BM_OP_COUNT, NULL);
	spin_unlock_irqrestore(&bitmap->bm_lock, irq_flags);
	return ret;
}

/* returns number of bits set in the range [s, e] */
int drbd_bm_count_bits(struct drbd_device *device, unsigned int bitmap_index, unsigned long s, unsigned long e)
{
	return bm_op(device, bitmap_index, s, e, BM_OP_COUNT, NULL);
}

void drbd_bm_copy_slot(struct drbd_device *device, unsigned int from_index, unsigned int to_index)
/* kmap compat: KM_IRQ1 */
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned long word_nr, from_word_nr, to_word_nr, words32_total;
	unsigned int from_page_nr, to_page_nr, current_page_nr;
	u32 data_word, *addr;

	words32_total = bitmap->bm_words * sizeof(unsigned long) / sizeof(u32);
	spin_lock_irq(&bitmap->bm_lock);

	bitmap->bm_set[to_index] = 0;
	current_page_nr = 0;
	addr = bm_map(bitmap, current_page_nr);
	for (word_nr = 0; word_nr < words32_total; word_nr += bitmap->bm_max_peers) {
		from_word_nr = word_nr + from_index;
		from_page_nr = word32_to_page(from_word_nr);
		to_word_nr = word_nr + to_index;
		to_page_nr = word32_to_page(to_word_nr);

		if (current_page_nr != from_page_nr) {
			bm_unmap(bitmap, addr);
			if (need_resched()) {
				spin_unlock_irq(&bitmap->bm_lock);
				cond_resched();
				spin_lock_irq(&bitmap->bm_lock);
			}
			current_page_nr = from_page_nr;
			addr = bm_map(bitmap, current_page_nr);
		}
		data_word = addr[word32_in_page(from_word_nr)];

		if (word_nr == words32_total - bitmap->bm_max_peers) {
			unsigned long lw = word_nr / bitmap->bm_max_peers;
			if (bitmap->bm_bits < (lw + 1) * 32)
			    data_word &= cpu_to_le32((1 << (bitmap->bm_bits - lw * 32)) - 1);
		}

		if (current_page_nr != to_page_nr) {
			bm_unmap(bitmap, addr);
			current_page_nr = to_page_nr;
			addr = bm_map(bitmap, current_page_nr);
		}

		if (addr[word32_in_page(to_word_nr)] != data_word)
			bm_set_page_need_writeout(bitmap, current_page_nr);
		addr[word32_in_page(to_word_nr)] = data_word;
		bitmap->bm_set[to_index] += hweight32(data_word);
	}
	bm_unmap(bitmap, addr);

	spin_unlock_irq(&bitmap->bm_lock);
}
