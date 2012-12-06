#ifndef DRBD_ENDIAN_H
#define DRBD_ENDIAN_H 1

/*
 * we don't want additional dependencies on other packages,
 * and we want to avoid to introduce incompatibilities by including kernel
 * headers from user space.
 *
 * we need the uint32_t and uint64_t types,
 * the hamming weight functions,
 * and the cpu_to_le etc. endianness convert functions.
 */

#include <stdint.h>
#include <endian.h>

#ifndef BITS_PER_LONG
# define BITS_PER_LONG __WORDSIZE
#endif

/* linux/byteorder/swab.h */

/* casts are necessary for constants, because we never know for sure
 * how U/UL/ULL map to __u16, uint32_t, uint64_t. At least not in a portable way.
 */

/*
 * __asm__("bswap %0" : "=r" (x) : "0" (x));
 * oh, well...
 */

#define __swab16(x) \
({ \
	__u16 __x = (x); \
	((__u16)( \
		(((__u16)(__x) & (__u16)0x00ffUL) << 8) | \
		(((__u16)(__x) & (__u16)0xff00UL) >> 8) )); \
})

#define __swab32(x) \
({ \
	uint32_t __x = (x); \
	((uint32_t)( \
		(((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
		(((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
		(((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
		(((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) )); \
})

#define __swab64(x) \
({ \
	uint64_t __x = (x); \
	((uint64_t)( \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
		(uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

/*
 * linux/byteorder/little_endian.h
 * linux/byteorder/big_endian.h
 */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le64(x) ((uint64_t)(x))
#define le64_to_cpu(x) ((uint64_t)(x))
#define cpu_to_le32(x) ((uint32_t)(x))
#define le32_to_cpu(x) ((uint32_t)(x))
#define cpu_to_le16(x) ((__u16)(x))
#define le16_to_cpu(x) ((__u16)(x))
#define cpu_to_be64(x) __swab64((x))
#define be64_to_cpu(x) __swab64((x))
#define cpu_to_be32(x) __swab32((x))
#define be32_to_cpu(x) __swab32((x))
#define cpu_to_be16(x) __swab16((x))
#define be16_to_cpu(x) __swab16((x))
#elif __BYTE_ORDER == __BIG_ENDIAN
# define cpu_to_le64(x) __swab64((x))
# define le64_to_cpu(x) __swab64((x))
# define cpu_to_le32(x) __swab32((x))
# define le32_to_cpu(x) __swab32((x))
# define cpu_to_le16(x) __swab16((x))
# define le16_to_cpu(x) __swab16((x))
# define cpu_to_be64(x) ((uint64_t)(x))
# define be64_to_cpu(x) ((uint64_t)(x))
# define cpu_to_be32(x) ((uint32_t)(x))
# define be32_to_cpu(x) ((uint32_t)(x))
# define cpu_to_be16(x) ((__u16)(x))
# define be16_to_cpu(x) ((__u16)(x))
#else
# error "sorry, weird endianness on this box"
#endif

#if BITS_PER_LONG == 32
# define LN2_BPL 5
# define cpu_to_le_long cpu_to_le32
# define le_long_to_cpu le32_to_cpu
#elif BITS_PER_LONG == 64
# define LN2_BPL 6
# define cpu_to_le_long cpu_to_le64
# define le_long_to_cpu le64_to_cpu
#else
# error "LN2 of BITS_PER_LONG unknown!"
#endif

/* linux/bitops.h */

/*
 * hweightN: returns the hamming weight (i.e. the number
 * of bits set) of a N-bit word
 */

static inline unsigned int generic_hweight32(unsigned int w)
{
	unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
	res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
	return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

static inline unsigned long generic_hweight64(uint64_t w)
{
#if BITS_PER_LONG < 64
	return generic_hweight32((unsigned int)(w >> 32)) +
				generic_hweight32((unsigned int)w);
#else
	uint64_t res;
	res = (w & 0x5555555555555555) + ((w >> 1) & 0x5555555555555555);
	res = (res & 0x3333333333333333) + ((res >> 2) & 0x3333333333333333);
	res = (res & 0x0F0F0F0F0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F0F0F0F0F);
	res = (res & 0x00FF00FF00FF00FF) + ((res >> 8) & 0x00FF00FF00FF00FF);
	res = (res & 0x0000FFFF0000FFFF) + ((res >> 16) & 0x0000FFFF0000FFFF);
	return (res & 0x00000000FFFFFFFF) + ((res >> 32) & 0x00000000FFFFFFFF);
#endif
}

static inline unsigned long hweight_long(unsigned long w)
{
	return sizeof(w) == 4 ? generic_hweight32(w) : generic_hweight64(w);
}


/*
 * Format macros for printf()
 */

#if BITS_PER_LONG == 32
# define X32(a) "%"#a"X"
# define X64(a) "%"#a"llX"
# define D32 "%d"
# define D64 "%lld"
# define U32 "%u"
# define U64 "%llu"
#elif BITS_PER_LONG == 64
# define X32(a) "%"#a"X"
# define X64(a) "%"#a"lX"
# define D32 "%d"
# define D64 "%ld"
# define U32 "%u"
# define U64 "%lu"
#else
# error "sorry, unsupported word length on this box"
#endif



#if BITS_PER_LONG == 32
# define strto_u64 strtoull
#elif BITS_PER_LONG == 64
# define strto_u64 strtoul
#else
# error "sorry, unsupported word length on this box"
#endif

#endif
