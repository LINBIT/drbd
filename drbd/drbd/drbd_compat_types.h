
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

#if defined(CONFIG_X86)
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

#else
#warn You probabely need to copy find_next_bit() from a 2.6.x kernel.
#endif

#ifndef ALIGN
#define ALIGN(x,s) (((x) + (s - 1)) & ~(s - 1))
#endif

#ifndef BUG_ON
#define BUG_ON(condition) do { if (unlikely((condition)!=0)) BUG(); } while(0)
#endif

#else // LINUX 2.6
//#warning "FIXME"

typedef struct bio drbd_bio_t;

#define SIGHAND_HACK

#define NOT_IN_26(x...)
#define ONLY_IN_26(x...)	x

#endif
