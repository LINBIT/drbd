
// currently only abstraction layer to get all references to buffer_head
// and b_some_thing out of our .c files.

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
#include <linux/highmem.h>

typedef struct buffer_head drbd_bio_t;
typedef unsigned long sector_t;

#define NOT_IN_26(x...)		x
#define ONLY_IN_26(x...)

#if !defined(CONFIG_HIGHMEM) && !defined(bh_kmap)
#define bh_kmap(bh)	((bh)->b_data)
#define bh_kunmap(bh)	do { } while (0)
#endif

#ifndef list_for_each
#define list_for_each(pos, head) \
	for(pos = (head)->next; pos != (head); pos = pos->next)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,19)
#define BH_Launder BH_launder
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,10)
#define min_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x < __y ? __x: __y; })
#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })
#define MODULE_LICENSE(L)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,7)
#define completion semaphore
#define init_completion(A) init_MUTEX_LOCKED(A)
#define wait_for_completion(A) down(A)
#define complete(A) up(A)
#else
#include <linux/completion.h>
#endif

/* note that if you use some verndor kernels like SuSE,
 * their 2.4.X variant probably already contain equivalent definitions.
 * you then have to disable this compat again...
 */

#ifndef HAVE_FIND_NEXT_BIT /* { */

#if defined(__i386__) || defined(__arch_um__)
/**
 * find_first_bit - find the first set bit in a memory region
 * @addr: The address to start the search at
 * @size: The maximum size to search
 *
 * Returns the bit-number of the first set bit, not the number of the byte
 * containing a bit.
 */
static __inline__ int find_first_bit(const unsigned long *addr, unsigned size)
{
        int d0, d1;
        int res;

        /* This looks at memory. Mark it volatile to tell gcc not to move it around */
        __asm__ __volatile__(
                "xorl %%eax,%%eax\n\t"
                "repe; scasl\n\t"
                "jz 1f\n\t"
                "leal -4(%%edi),%%edi\n\t"
                "bsfl (%%edi),%%eax\n"
                "1:\tsubl %%ebx,%%edi\n\t"
                "shll $3,%%edi\n\t"
                "addl %%edi,%%eax"
                :"=a" (res), "=&c" (d0), "=&D" (d1)
                :"1" ((size + 31) >> 5), "2" (addr), "b" (addr));
        return res;
}

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */

static __inline__ int find_next_bit(const unsigned long *addr, int size, int offset)
{
        const unsigned long *p = addr + (offset >> 5);
        int set = 0, bit = offset & 31, res;

        if (bit) {
                /*
                 * Look for nonzero in the first 32 bits:
                 */
                __asm__("bsfl %1,%0\n\t"
                        "jne 1f\n\t"
                        "movl $32, %0\n"
                        "1:"
                        : "=r" (set)
                        : "r" (*p >> bit));
                if (set < (32 - bit))
                        return set + offset;
                set = 32 - bit;
                p++;
        }
        /*
         * No set bit yet, search remaining full words for a bit
         */
        res = find_first_bit (p, size - 32 * (p - addr));
        return (offset + set + res);
}

#elif defined(__alpha__)

#include <asm/compiler.h>
#if __GNUC__ == 3 && __GNUC_MINOR__ >= 4 || __GNUC__ > 3
# define __kernel_cmpbge(a, b)          __builtin_alpha_cmpbge(a, b)
#else
# define __kernel_cmpbge(a, b)                                          \
  ({ unsigned long __kir;                                               \
     __asm__("cmpbge %r2,%1,%0" : "=r"(__kir) : "rI"(b), "rJ"(a));      \
     __kir; })
#endif

static inline unsigned long __ffs(unsigned long word)
{
#if defined(__alpha_cix__) && defined(__alpha_fix__)
	/* Whee.  EV67 can calculate it directly.  */
	return __kernel_cttz(word);
#else
	unsigned long bits, qofs, bofs;

	bits = __kernel_cmpbge(0, word);
	qofs = ffz_b(bits);
	bits = __kernel_extbl(word, qofs);
	bofs = ffz_b(~bits);

	return qofs*8 + bofs;
#endif
}

static inline unsigned long
find_next_bit(void * addr, unsigned long size, unsigned long offset)
{
	unsigned long * p = ((unsigned long *) addr) + (offset >> 6);
	unsigned long result = offset & ~63UL;
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset &= 63UL;
	if (offset) {
		tmp = *(p++);
		tmp &= ~0UL << offset;
		if (size < 64)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= 64;
		result += 64;
	}
	while (size & ~63UL) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += 64;
		size -= 64;
	}
	if (!size)
		return result;
	tmp = *p;
 found_first:
	tmp &= ~0UL >> (64 - size);
	if (!tmp)
		return result + size;
 found_middle:
	return result + __ffs(tmp);
}
#elif defined(USE_GENERIC_FIND_NEXT_BIT)

#if BITS_PER_LONG == 32
#define  _xFFFF 31ul
#define _x10000 32
#define _xSHIFT  5
#elif BITS_PER_LONG == 64
#define  _xFFFF 63ul
#define _x10000 64
#define _xSHIFT  6
#else
#error "Unexpected BITS_PER_LONG"
#endif

/* slightly large to be inlined, but anyways... */
static inline unsigned long
find_next_bit(void * addr, unsigned long size, unsigned long offset)
{
	unsigned long * p = ((unsigned long *) addr) + (offset >> _xSHIFT);
	unsigned long result = offset & ~_xFFFF;
	unsigned long tmp;

	if (offset >= size)
		return size;
	size -= result;
	offset &= _xFFFF;
	if (offset) {
		tmp = *(p++);
		tmp &= ~0UL << offset;
		if (size < _x10000)
			goto found_first;
		if (tmp)
			goto found_middle;
		size -= _x10000;
		result += _x10000;
	}
	while (size & ~_xFFFF) {
		if ((tmp = *(p++)))
			goto found_middle;
		result += _x10000;
		size -= _x10000;
	}
	if (!size)
		return result;
	tmp = *p;
 found_first:
	tmp &= ~0UL >> (_x10000 - size);
	if (!tmp)
		return result + size;
 found_middle: /* if this is reached, we know that (tmp != 0) */
	return result + generic_ffs(tmp)-1;
}

#undef _xFFFF
#undef _x10000
#undef _xSHIFT

#else
#warning "You probabely need to copy find_next_bit() from a 2.6.x kernel."
#warning "Or enable low performance generic C-code"
#warning "(USE_GENERIC_FIND_NEXT_BIT in drbd_config.h)"
#endif

#endif /* HAVE_FIND_NEXT_BIT } */

#ifndef ALIGN
#define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )
#endif

#ifndef BUG_ON
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)
#endif

#else // LINUX 2.6

typedef struct bio drbd_bio_t;

#define SIGHAND_HACK

#define NOT_IN_26(x...)
#define ONLY_IN_26(x...)	x

#endif
