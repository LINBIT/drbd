/*
   drbd_bitmap.c

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
#include <linux/slab.h>
#include <linux/dynamic_debug.h>
#include <asm/kmap_types.h>

#include <asm-generic/bitops/le.h>

#include "drbd_int.h"

/* See the ifdefs and comments inside that header file.
 * On recent kernels this is not needed. */
#include "compat/bitops.h"

#define BITS_PER_PAGE		(1UL << (PAGE_SHIFT + 3))

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

#define bm_print_lock_info(m) __bm_print_lock_info(m, __func__)
static void __bm_print_lock_info(struct drbd_device *device, const char *func)
{
	struct drbd_bitmap *b = device->bitmap;
	if (!drbd_ratelimit())
		return;
	drbd_err(device, "FIXME %s[%d] in %s, bitmap locked for '%s' by %s[%d]\n",
		 current->comm, task_pid_nr(current),
		 func, b->bm_why ?: "?",
		 b->bm_task->comm, task_pid_nr(b->bm_task));
}

void drbd_bm_lock(struct drbd_device *device, char *why, enum bm_flag flags)
{
	struct drbd_bitmap *b = device->bitmap;
	int trylock_failed;

	if (!b) {
		drbd_err(device, "FIXME no bitmap in drbd_bm_lock!?\n");
		return;
	}

	trylock_failed = !mutex_trylock(&b->bm_change);

	if (trylock_failed) {
		drbd_warn(device, "%s[%d] going to '%s' but bitmap already locked for '%s' by %s[%d]\n",
			  current->comm, task_pid_nr(current),
			  why, b->bm_why ?: "?",
			  b->bm_task->comm, task_pid_nr(b->bm_task));
		mutex_lock(&b->bm_change);
	}
	if (b->bm_flags & BM_LOCK_ALL)
		drbd_err(device, "FIXME bitmap already locked in bm_lock\n");
	b->bm_flags |= flags & BM_LOCK_ALL;

	b->bm_why  = why;
	b->bm_task = current;
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
	b->bm_task = NULL;
	mutex_unlock(&b->bm_change);
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

static void bm_set_page_need_writeout(struct page *page)
{
	set_bit(BM_PAGE_NEED_WRITEOUT, &page_private(page));
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

static void bm_set_page_lazy_writeout(struct page *page)
{
	set_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

static int bm_test_page_lazy_writeout(struct page *page)
{
	return test_bit(BM_PAGE_LAZY_WRITEOUT, &page_private(page));
}

#ifdef COMPAT_KMAP_ATOMIC_PAGE_ONLY
#define bm_kmap(b, idx, km) _bm_kmap(b, idx)
static unsigned long *_bm_kmap(struct drbd_bitmap *b, unsigned int idx)
#else
static unsigned long *bm_kmap(struct drbd_bitmap *b, unsigned int idx, const enum km_type km)
#endif
{
	struct page *page = b->bm_pages[idx];
	return (unsigned long *) drbd_kmap_atomic(page, km);
}

#ifdef COMPAT_KMAP_ATOMIC_PAGE_ONLY
#define bm_kunmap(p_addr, km) _bm_kunmap(p_addr)
static void _bm_kunmap(unsigned long *p_addr)
#else
static void bm_kunmap(unsigned long *p_addr, const enum km_type km)
#endif
{
	drbd_kunmap_atomic(p_addr, km);
};

/*
 * actually most functions herein should take a struct drbd_bitmap*, not a
 * struct drbd_device*, but for the debug macros I like to have the device around
 * to be able to report device specific.
 */


STATIC void bm_free_pages(struct page **pages, unsigned long number)
{
	unsigned long i;
	if (!pages)
		return;

	for (i = 0; i < number; i++) {
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

STATIC void bm_vk_free(void *ptr, int v)
{
	if (v)
		vfree(ptr);
	else
		kfree(ptr);
}

/*
 * "have" and "want" are NUMBER OF PAGES.
 */
STATIC struct page **bm_realloc_pages(struct drbd_bitmap *b, unsigned long want)
{
	struct page **old_pages = b->bm_pages;
	struct page **new_pages, *page;
	unsigned int i, bytes, vmalloced = 0;
	unsigned long have = b->bm_number_of_pages;

	BUG_ON(have == 0 && old_pages != NULL);
	BUG_ON(have != 0 && old_pages == NULL);

	if (have == want)
		return old_pages;

	/* Trying kmalloc first, falling back to vmalloc.
	 * GFP_KERNEL is ok, as this is done when a lower level disk is
	 * "attached" to the drbd.  Context is receiver thread or drbdsetup /
	 * netlink process.  As we have no disk yet, we are not in the IO path,
	 * not even the IO path of the peer. */
	bytes = sizeof(struct page *)*want;
	new_pages = kzalloc(bytes, GFP_KERNEL);
	if (!new_pages) {
		new_pages = vzalloc(bytes);
		if (!new_pages)
			return NULL;
		vmalloced = 1;
	}

	if (want >= have) {
		for (i = 0; i < have; i++)
			new_pages[i] = old_pages[i];
		for (; i < want; i++) {
			page = alloc_page(GFP_HIGHUSER | __GFP_ZERO);
			if (!page) {
				bm_free_pages(new_pages + have, i - have);
				bm_vk_free(new_pages, vmalloced);
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

	if (vmalloced)
		b->bm_flags |= BM_P_VMALLOCED;
	else
		b->bm_flags &= ~BM_P_VMALLOCED;

	return new_pages;
}

/*
 * called on driver init only. TODO call when a device is created.
 * allocates the drbd_bitmap, and stores it in device->bitmap.
 */
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

/* called on driver unload. TODO: call when a device is destroyed.
 */
void drbd_bm_free(struct drbd_bitmap *bitmap)
{
	bm_free_pages(bitmap->bm_pages, bitmap->bm_number_of_pages);
	bm_vk_free(bitmap->bm_pages, (BM_P_VMALLOCED & bitmap->bm_flags));
	kfree(bitmap);
}

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

static __always_inline unsigned long
___bm_op(struct drbd_device *device, unsigned int bitmap_index, unsigned long start, unsigned long end,
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

		addr = bm_kmap(bitmap, page, KM_IRQ1);
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
						bm_kunmap(addr, KM_IRQ1);
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
		case BM_OP_EXTRACT:
			BUG();
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
		bm_kunmap(addr, KM_IRQ1);
		bit_in_page -= BITS_PER_PAGE;
		switch(op) {
		case BM_OP_CLEAR:
			if (count) {
				bm_set_page_lazy_writeout(bitmap->bm_pages[page]);
				total += count;
			}
			break;
		case BM_OP_SET:
		case BM_OP_MERGE:
			if (count) {
				bm_set_page_need_writeout(bitmap->bm_pages[page]);
				total += count;
			}
			break;
		default:
			break;
		}
		continue;

	    found:
		bm_kunmap(addr, KM_IRQ1);
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
{
	struct drbd_bitmap *bitmap = device->bitmap;

	if (!expect(device, bitmap))
		return 1;
	if (!expect(device, bitmap->bm_pages))
		return 0;

	if (!bitmap->bm_bits)
		return 0;

	switch(op) {
	case BM_OP_CLEAR:
		if (bitmap->bm_flags & BM_LOCK_CLEAR)
			bm_print_lock_info(device);
		break;
	case BM_OP_SET:
	case BM_OP_MERGE:
		if (bitmap->bm_flags & BM_LOCK_SET)
			bm_print_lock_info(device);
		break;
	case BM_OP_TEST:
	case BM_OP_COUNT:
	case BM_OP_EXTRACT:
	case BM_OP_FIND_BIT:
	case BM_OP_FIND_ZERO_BIT:
		if (bitmap->bm_flags & BM_LOCK_TEST)
			bm_print_lock_info(device);
		break;
	}
	return ___bm_op(device, bitmap_index, start, end, op, buffer);
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

#define ___bm_op(device, bitmap_index, start, end, op, buffer) \
	({ unsigned long ret; \
	   drbd_info(device, "%s: ___bm_op(..., %u, %lu, %lu, %u, %p)\n", \
		     __func__, bitmap_index, start, end, op, buffer); \
	   ret = ___bm_op(device, bitmap_index, start, end, op, buffer); \
	   drbd_info(device, "= %lu\n", ret); \
	   ret; })
#endif

/* you better not modify the bitmap while this is running,
 * or its results will be stale */
static void bm_count_bits(struct drbd_device *device)
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

/*
 * make sure the bitmap has enough room for the attached storage,
 * if necessary, resize.
 * called whenever we may have changed the device size.
 * returns -ENOMEM if we could not allocate enough memory, 0 on success.
 * In case this is actually a resize, we copy the old bitmap into the new one.
 * Otherwise, the bitmap is initialized to all bits set.
 */
int drbd_bm_resize(struct drbd_device *device, sector_t capacity, int set_new_bits)
{
	struct drbd_bitmap *b = device->bitmap;
	unsigned long bits, words, owords, obits;
	unsigned long want, have, onpages; /* number of pages */
	struct page **npages, **opages = NULL;
	int err = 0, growing;
	int opages_vmalloced;

	if (!expect(device, b))
		return -ENOMEM;

	drbd_bm_lock(device, "resize", BM_LOCK_ALL);

	drbd_info(device, "drbd_bm_resize called with capacity == %llu\n",
			(unsigned long long)capacity);

	if (capacity == b->bm_dev_capacity)
		goto out;

	opages_vmalloced = (BM_P_VMALLOCED & b->bm_flags);

	if (capacity == 0) {
		unsigned int bitmap_index;

		spin_lock_irq(&b->bm_lock);
		opages = b->bm_pages;
		onpages = b->bm_number_of_pages;
		owords = b->bm_words;
		b->bm_pages = NULL;
		b->bm_number_of_pages = 0;
		for (bitmap_index = 0; bitmap_index < b->bm_max_peers; bitmap_index++)
			b->bm_set[bitmap_index] = 0;
		b->bm_bits = 0;
		b->bm_words = 0;
		b->bm_dev_capacity = 0;
		spin_unlock_irq(&b->bm_lock);
		bm_free_pages(opages, onpages);
		bm_vk_free(opages, opages_vmalloced);
		goto out;
	}
	bits  = BM_SECT_TO_BIT(ALIGN(capacity, BM_SECT_PER_BIT));
	words = (ALIGN(bits, 64) * b->bm_max_peers) >> LN2_BPL;

	if (get_ldev(device)) {
		struct drbd_md *md = &device->ldev->md;
		u64 words_on_disk, bits_on_disk;

		/* if we would use
		   words = ALIGN(bits,BITS_PER_LONG) >> LN2_BPL;
		   a 32bit host could present the wrong number of words
		   to a 64bit host.
		*/
		words_on_disk = ((u64)md->md_size_sect - MD_BM_OFFSET) << (12 - LN2_BPL);
		do_div(words_on_disk, b->bm_max_peers);
		bits_on_disk = words_on_disk << LN2_BPL;
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

	spin_lock_irq(&b->bm_lock);
	opages = b->bm_pages;
	owords = b->bm_words;
	obits  = b->bm_bits;

	growing = bits > obits;

	b->bm_pages = npages;
	b->bm_number_of_pages = want;
	b->bm_bits  = bits;
	b->bm_words = words;
	b->bm_dev_capacity = capacity;

	if (growing && set_new_bits) {
		unsigned int bitmap_index;

		for (bitmap_index = 0; bitmap_index < b->bm_max_peers; bitmap_index++)
			___bm_op(device, bitmap_index, obits, -1UL, BM_OP_SET, NULL);
	}

	if (want < have) {
		/* implicit: (opages != NULL) && (opages != npages) */
		bm_free_pages(opages + want, have - want);
	}

	spin_unlock_irq(&b->bm_lock);
	if (opages != npages)
		bm_vk_free(opages, opages_vmalloced);
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
unsigned long _drbd_bm_total_weight(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_bitmap *b = device->bitmap;
	unsigned long s;
	unsigned long flags;

	if (!expect(device, b))
		return 0;
	if (!expect(device, b->bm_pages))
		return 0;

	spin_lock_irqsave(&b->bm_lock, flags);
	s = b->bm_set[peer_device->bitmap_index];
	spin_unlock_irqrestore(&b->bm_lock, flags);

	return s;
}

unsigned long drbd_bm_total_weight(struct drbd_peer_device *peer_device)
{
	struct drbd_device *device = peer_device->device;
	unsigned long s;
	/* if I don't have a disk, I don't know about out-of-sync status */
	if (!get_ldev_if_state(device, D_NEGOTIATING))
		return 0;
	s = _drbd_bm_total_weight(peer_device);
	put_ldev(device);
	return s;
}

size_t drbd_bm_words(struct drbd_device *device)
{
	struct drbd_bitmap *b = device->bitmap;
	if (!expect(device, b))
		return 0;
	if (!expect(device, b->bm_pages))
		return 0;

	return b->bm_words;
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

/* set all bits in the bitmap */
void drbd_bm_set_all(struct drbd_device *device)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int bitmap_index;

	spin_lock_irq(&bitmap->bm_lock);
	for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++) {
		unsigned long bit = 0;

		while (bit < bitmap->bm_bits) {
			unsigned long last_bit = last_bit_on_page(bitmap, bitmap_index, bit);

			__bm_op(device, bitmap_index, bit, last_bit, BM_OP_SET, NULL);
			bit = last_bit + 1;
			if (need_resched()) {
				spin_unlock_irq(&bitmap->bm_lock);
				cond_resched();
				spin_lock_irq(&bitmap->bm_lock);
			}
		}
	}
	spin_unlock_irq(&bitmap->bm_lock);
}

/* clear all bits in the bitmap */
void drbd_bm_clear_all(struct drbd_device *device)
{
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int bitmap_index;

	spin_lock_irq(&bitmap->bm_lock);
	for (bitmap_index = 0; bitmap_index < bitmap->bm_max_peers; bitmap_index++) {
		unsigned long bit = 0;

		while (bit < bitmap->bm_bits) {
			unsigned long last_bit = last_bit_on_page(bitmap, bitmap_index, bit);

			__bm_op(device, bitmap_index, bit, last_bit, BM_OP_CLEAR, NULL);
			bit = last_bit + 1;
			if (need_resched()) {
				spin_unlock_irq(&bitmap->bm_lock);
				cond_resched();
				spin_lock_irq(&bitmap->bm_lock);
			}
		}
	}
	spin_unlock_irq(&bitmap->bm_lock);
}

struct bm_aio_ctx {
	struct drbd_device *device;
	atomic_t in_flight;
	unsigned int done;
	unsigned flags;
#define BM_AIO_COPY_PAGES	1
#define BM_AIO_WRITE_HINTED	2
	int error;
	struct kref kref;
};

static void bm_aio_ctx_destroy(struct kref *kref)
{
	struct bm_aio_ctx *ctx = container_of(kref, struct bm_aio_ctx, kref);

	put_ldev(ctx->device);
	kfree(ctx);
}

/* bv_page may be a copy, or may be the original */
static BIO_ENDIO_TYPE bm_async_io_complete BIO_ENDIO_ARGS(struct bio *bio, int error)
{
	struct bm_aio_ctx *ctx = bio->bi_private;
	struct drbd_device *device = ctx->device;
	struct drbd_bitmap *b = device->bitmap;
	unsigned int idx = bm_page_to_idx(bio->bi_io_vec[0].bv_page);
	int uptodate = bio_flagged(bio, BIO_UPTODATE);

	BIO_ENDIO_FN_START;

	/* strange behavior of some lower level drivers...
	 * fail the request by clearing the uptodate flag,
	 * but do not return any error?!
	 * do we want to WARN() on this? */
	if (!error && !uptodate)
		error = -EIO;

	if ((ctx->flags & BM_AIO_COPY_PAGES) == 0 &&
	    !bm_test_page_unchanged(b->bm_pages[idx]))
		drbd_warn(device, "bitmap page idx %u changed during IO!\n", idx);

	if (error) {
		/* ctx error will hold the completed-last non-zero error code,
		 * in case error codes differ. */
		ctx->error = error;
		bm_set_page_io_err(b->bm_pages[idx]);
		/* Not identical to on disk version of it.
		 * Is BM_PAGE_IO_ERROR enough? */
		if (drbd_ratelimit())
			drbd_err(device, "IO ERROR %d on bitmap page idx %u\n",
					error, idx);
	} else {
		bm_clear_page_io_err(b->bm_pages[idx]);
		dynamic_drbd_dbg(device, "bitmap page idx %u completed\n", idx);
	}

	bm_page_unlock_io(device, idx);

	if (ctx->flags & BM_AIO_COPY_PAGES)
		mempool_free(bio->bi_io_vec[0].bv_page, drbd_md_io_page_pool);

	bio_put(bio);

	if (atomic_dec_and_test(&ctx->in_flight)) {
		ctx->done = 1;
		wake_up(&device->misc_wait);
		kref_put(&ctx->kref, bm_aio_ctx_destroy);
	}

	BIO_ENDIO_FN_RETURN;
}

STATIC void bm_page_io_async(struct bm_aio_ctx *ctx, int page_nr, int rw) __must_hold(local)
{
	struct bio *bio = bio_alloc_drbd(GFP_NOIO);
	struct drbd_device *device = ctx->device;
	struct drbd_bitmap *b = device->bitmap;
	struct page *page;
	unsigned int len;

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
		void *src, *dest;
		page = mempool_alloc(drbd_md_io_page_pool, __GFP_HIGHMEM|__GFP_WAIT);
		dest = drbd_kmap_atomic(page, KM_USER0);
		src = drbd_kmap_atomic(b->bm_pages[page_nr], KM_USER1);
		memcpy(dest, src, PAGE_SIZE);
		drbd_kunmap_atomic(src, KM_USER1);
		drbd_kunmap_atomic(dest, KM_USER0);
		bm_store_page_idx(page, page_nr);
	} else
		page = b->bm_pages[page_nr];

	bio->bi_bdev = device->ldev->md_bdev;
	bio->bi_sector = on_disk_sector;
	/* bio_add_page of a single page to an empty bio will always succeed,
	 * according to api.  Do we want to assert that? */
	bio_add_page(bio, page, len, 0);
	bio->bi_private = ctx;
	bio->bi_end_io = bm_async_io_complete;

	if (drbd_insert_fault(device, (rw & WRITE) ? DRBD_FAULT_MD_WR : DRBD_FAULT_MD_RD)) {
		bio->bi_rw |= rw;
		bio_endio(bio, -EIO);
	} else {
		submit_bio(rw, bio);
		/* this should not count as user activity and cause the
		 * resync to throttle -- see drbd_rs_should_slow_down(). */
		atomic_add(len >> 9, &device->rs_sect_ev);
	}
}

/*
 * bm_rw: read/write the whole bitmap from/to its on disk location.
 */
STATIC int bm_rw(struct drbd_device *device, int rw, unsigned flags, unsigned lazy_writeout_upper_idx) __must_hold(local)
{
	struct bm_aio_ctx *ctx;
	struct drbd_bitmap *b = device->bitmap;
	int num_pages, i, count = 0;
	unsigned long now;
	int err = 0;

	/*
	 * We are protected against bitmap disappearing/resizing by holding an
	 * ldev reference (caller must have called get_ldev()).
	 * For read/write, we are protected against changes to the bitmap by
	 * the bitmap lock (see drbd_bitmap_io).
	 * For lazy writeout, we don't care for ongoing changes to the bitmap,
	 * as we submit copies of pages anyways.
	 */

	ctx = kmalloc(sizeof(struct bm_aio_ctx), GFP_NOIO);
	if (!ctx)
		return -ENOMEM;

	*ctx = (struct bm_aio_ctx) {
		.device = device,
		.in_flight = ATOMIC_INIT(1),
		.done = 0,
		.flags = flags,
		.error = 0,
		.kref = { ATOMIC_INIT(2) },
	};

	if (!get_ldev_if_state(device, D_ATTACHING)) {  /* put is in bm_aio_ctx_destroy() */
		drbd_err(device, "ASSERT FAILED: get_ldev_if_state() == 1 in bm_rw()\n");
		kfree(ctx);
		return -ENODEV;
	}

	if (!ctx->flags)
		WARN_ON(!(b->bm_flags & BM_LOCK_ALL));

	num_pages = b->bm_number_of_pages;

	now = jiffies;

	/* let the layers below us try to merge these bios... */
	for (i = 0; i < num_pages; i++) {
		/* ignore completely unchanged pages */
		if (lazy_writeout_upper_idx && i == lazy_writeout_upper_idx)
			break;
		if (rw & WRITE) {
			if ((flags & BM_AIO_WRITE_HINTED) &&
			    !test_and_clear_bit(BM_PAGE_HINT_WRITEOUT,
				    &page_private(b->bm_pages[i])))
				continue;
			if (bm_test_page_unchanged(b->bm_pages[i])) {
				dynamic_drbd_dbg(device, "skipped bm write for idx %u\n", i);
				continue;
			}
			/* during lazy writeout,
			 * ignore those pages not marked for lazy writeout. */
			if (lazy_writeout_upper_idx &&
			    !bm_test_page_lazy_writeout(b->bm_pages[i])) {
				dynamic_drbd_dbg(device, "skipped bm lazy write for idx %u\n", i);
				continue;
			}
		}
		atomic_inc(&ctx->in_flight);
		bm_page_io_async(ctx, i, rw);
		++count;
		cond_resched();
	}

	/*
	 * We initialize ctx->in_flight to one to make sure bm_async_io_complete
	 * will not set ctx->done early, and decrement / test it here.  If there
	 * are still some bios in flight, we need to wait for them here.
	 * If all IO is done already (or nothing had been submitted), there is
	 * no need to wait.  Still, we need to put the kref associated with the
	 * "in_flight reached zero, all done" event.
	 */
	if (!atomic_dec_and_test(&ctx->in_flight)) {
		drbd_blk_run_queue(bdev_get_queue(device->ldev->md_bdev));
		wait_until_done_or_disk_failure(device, device->ldev, &ctx->done);
	} else
		kref_put(&ctx->kref, bm_aio_ctx_destroy);

	/* summary for global bitmap IO */
	if (flags == 0)
		drbd_info(device, "bitmap %s of %u pages took %lu jiffies\n",
			 rw == WRITE ? "WRITE" : "READ",
			 count, jiffies - now);

	if (ctx->error) {
		drbd_alert(device, "we had at least one MD IO ERROR during bitmap IO\n");
		drbd_chk_io_error(device, 1, DRBD_META_IO_ERROR);
		err = -EIO; /* ctx->error ? */
	}

	if (atomic_read(&ctx->in_flight))
		err = -EIO; /* Disk failed during IO... */

	if (rw == WRITE) {
		drbd_md_flush(device);
	} else /* rw == READ */ {
		now = jiffies;
		bm_count_bits(device);
		drbd_info(device, "recounting of set bits took additional %lu jiffies\n",
		     jiffies - now);
	}

	kref_put(&ctx->kref, bm_aio_ctx_destroy);
	return err;
}

/**
 * drbd_bm_read() - Read the whole bitmap from its on disk location.
 * @device:	DRBD device.
 */
int drbd_bm_read(struct drbd_device *device,
		 struct drbd_peer_device *peer_device) __must_hold(local)
{
	return bm_rw(device, READ, 0, 0);
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
	struct page *page;

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	page_nr = bit_to_page_interleaved(bitmap, 0, start);
	last_page = bit_to_page_interleaved(bitmap, bitmap->bm_max_peers - 1, end);
	for (; page_nr <= last_page; page_nr++) {
		page = device->bitmap->bm_pages[page_nr];
		set_bit(BM_PAGE_HINT_WRITEOUT, &page_private(page));
	}
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
	return bm_rw(device, WRITE, 0, 0);
}

/**
 * drbd_bm_lazy_write_out() - Write bitmap pages 0 to @upper_idx-1, if they have changed.
 * @device:	DRBD device.
 * @upper_idx:	0: write all changed pages; +ve: page index to stop scanning for changed pages
 */
int drbd_bm_write_lazy(struct drbd_device *device, unsigned upper_idx) __must_hold(local)
{
	return bm_rw(device, WRITE, BM_AIO_COPY_PAGES, upper_idx);
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
	return bm_rw(device, WRITE, BM_AIO_COPY_PAGES, 0);
}

/**
 * drbd_bm_write_hinted() - Write bitmap pages with "hint" marks, if they have changed.
 * @device:	DRBD device.
 */
int drbd_bm_write_hinted(struct drbd_device *device) __must_hold(local)
{
	return bm_rw(device, WRITE, BM_AIO_WRITE_HINTED | BM_AIO_COPY_PAGES, 0);
}

/**
 * drbd_bm_write_range() - Writes a range of bitmap pages
 * @device:	DRBD device.
 *
 * We don't want to special case on logical_block_size of the backend device,
 * so we submit PAGE_SIZE aligned pieces.
 * Note that on "most" systems, PAGE_SIZE is 4k.
 *
 * In case this becomes an issue on systems with larger PAGE_SIZE,
 * we may want to change this again to write 4k aligned 4k pieces.
 */
int drbd_bm_write_range(struct drbd_peer_device *peer_device, unsigned long start, unsigned long end) __must_hold(local)
{
	struct drbd_device *device = peer_device->device;
	struct drbd_bitmap *bitmap = device->bitmap;
	unsigned int page_nr, end_page;
	int err = 0;

	if (end >= bitmap->bm_bits)
		end = bitmap->bm_bits - 1;

	page_nr = bit_to_page_interleaved(bitmap, peer_device->bitmap_index, start);
	end_page = bit_to_page_interleaved(bitmap, peer_device->bitmap_index, end);
	for (; page_nr <= end_page; page_nr++) {
		struct bm_aio_ctx *ctx;

		if (bm_test_page_unchanged(device->bitmap->bm_pages[page_nr])) {
			dynamic_drbd_dbg(device, "skipped bm page write for page %u\n", page_nr);
			continue;
		}

		ctx = kmalloc(sizeof(struct bm_aio_ctx), GFP_NOIO);
		if (!ctx)
			return -ENOMEM;

		*ctx = (struct bm_aio_ctx) {
			.device = device,
			.in_flight = ATOMIC_INIT(1),
			.done = 0,
			.flags = BM_AIO_COPY_PAGES,
			.error = 0,
			.kref = { ATOMIC_INIT(2) },
		};

		if (!expect(device, get_ldev_if_state(device, D_ATTACHING))) {  /* put is in bm_aio_ctx_destroy() */
			kfree(ctx);
			return -ENODEV;
		}

		bm_page_io_async(ctx, page_nr, WRITE_SYNC);
		wait_until_done_or_disk_failure(device, device->ldev, &ctx->done);

		if (ctx->error)
			drbd_chk_io_error(device, 1, DRBD_META_IO_ERROR);
			/* that should force detach, so the in memory bitmap will be
			 * gone in a moment as well. */

		device->bm_writ_cnt++;
		err = atomic_read(&ctx->in_flight) ? -EIO : ctx->error;
		kref_put(&ctx->kref, bm_aio_ctx_destroy);
	}
	return err;
}

unsigned long drbd_bm_find_next(struct drbd_peer_device *peer_device, unsigned long start)
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		     BM_OP_FIND_BIT, NULL);
}

#if 0
/* not yet needed for anything. */
unsigned long drbd_bm_find_next_zero(struct drbd_peer_device *peer_device, unsigned long start)
{
	return bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		     BM_OP_FIND_ZERO_BIT, NULL);
}
#endif

/* does not spin_lock_irqsave.
 * you must take drbd_bm_lock() first */
unsigned long _drbd_bm_find_next(struct drbd_peer_device *peer_device, unsigned long start)
{
	/* WARN_ON(!(device->b->bm_flags & BM_LOCK_SET)); */
	return __bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		       BM_OP_FIND_BIT, NULL);
}

unsigned long _drbd_bm_find_next_zero(struct drbd_peer_device *peer_device, unsigned long start)
{
	/* WARN_ON(!(device->b->bm_flags & BM_LOCK_SET)); */
	return __bm_op(peer_device->device, peer_device->bitmap_index, start, -1UL,
		       BM_OP_FIND_ZERO_BIT, NULL);
}

unsigned int drbd_bm_set_bits(struct drbd_device *device, unsigned int bitmap_index,
			      unsigned long start, unsigned long end)
{
	return bm_op(device, bitmap_index, start, end, BM_OP_SET, NULL);
}

void drbd_bm_set_many_bits(struct drbd_peer_device *peer_device, unsigned long start, unsigned long end)
{
	struct drbd_bitmap *bitmap = peer_device->device->bitmap;
	unsigned long bit = start;

	spin_lock_irq(&bitmap->bm_lock);
	while (bit <= end) {
		unsigned int bitmap_index = peer_device->bitmap_index;
		unsigned long last_bit = last_bit_on_page(bitmap, bitmap_index, bit);

		__bm_op(peer_device->device, bitmap_index, bit, last_bit, BM_OP_SET, NULL);
		bit = last_bit + 1;
		if (need_resched()) {
			spin_unlock_irq(&bitmap->bm_lock);
			cond_resched();
			spin_lock_irq(&bitmap->bm_lock);
		}
	}
	spin_unlock_irq(&bitmap->bm_lock);
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
