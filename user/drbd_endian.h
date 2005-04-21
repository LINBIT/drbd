#ifndef DRBD_ENDIAN_H
#define DRBD_ENDIAN_H 1

/*
 * we don't want additional dependencies on other packages,
 * and we want to avoid to introduce incompatibilities by including kernel
 * headers from user space.
 *
 * we need the u32 and u64 types,
 * the hamming weight functions,
 * and the cpu_to_le etc. endianness convert functions.
 */

#include <stdint.h>
#include <endian.h>

#ifndef BITS_PER_LONG
# define BITS_PER_LONG __WORDSIZE
#endif

#define u64 uint64_t
#define u32 uint32_t
#define s32 int32_t
#define u16 uint16_t
#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t

/* linux/byteorder/swab.h */

/* casts are necessary for constants, because we never know how for sure
 * how U/UL/ULL map to __u16, __u32, __u64. At least not in a portable way.
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
	__u32 __x = (x); \
	((__u32)( \
		(((__u32)(__x) & (__u32)0x000000ffUL) << 24) | \
		(((__u32)(__x) & (__u32)0x0000ff00UL) <<  8) | \
		(((__u32)(__x) & (__u32)0x00ff0000UL) >>  8) | \
		(((__u32)(__x) & (__u32)0xff000000UL) >> 24) )); \
})

#define __swab64(x) \
({ \
	__u64 __x = (x); \
	((__u64)( \
		(__u64)(((__u64)(__x) & (__u64)0x00000000000000ffULL) << 56) | \
		(__u64)(((__u64)(__x) & (__u64)0x000000000000ff00ULL) << 40) | \
		(__u64)(((__u64)(__x) & (__u64)0x0000000000ff0000ULL) << 24) | \
		(__u64)(((__u64)(__x) & (__u64)0x00000000ff000000ULL) <<  8) | \
	        (__u64)(((__u64)(__x) & (__u64)0x000000ff00000000ULL) >>  8) | \
		(__u64)(((__u64)(__x) & (__u64)0x0000ff0000000000ULL) >> 24) | \
		(__u64)(((__u64)(__x) & (__u64)0x00ff000000000000ULL) >> 40) | \
		(__u64)(((__u64)(__x) & (__u64)0xff00000000000000ULL) >> 56) )); \
})

/*
 * no architecture-specific optimization is supplied here.
 * I still wonder why we should not use <asm/byteorder.h>,
 * but so be it.
 */

/*
 * linux/byteorder/little_endian.h
 * linux/byteorder/big_endian.h
 */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le64(x) ((__u64)(x))
#define le64_to_cpu(x) ((__u64)(x))
#define cpu_to_le32(x) ((__u32)(x))
#define le32_to_cpu(x) ((__u32)(x))
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
# define cpu_to_be64(x) ((__u64)(x))
# define be64_to_cpu(x) ((__u64)(x))
# define cpu_to_be32(x) ((__u32)(x))
# define be32_to_cpu(x) ((__u32)(x))
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

static inline unsigned long generic_hweight64(__u64 w)
{
#if BITS_PER_LONG < 64
	return generic_hweight32((unsigned int)(w >> 32)) +
				generic_hweight32((unsigned int)w);
#else
	u64 res;
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
# define X32 "%lX"
//# define X64 "%llX"
# define X64(a) "%"#a"llX"
# define D32 "%ld"
# define D64 "%lld"
# define U32 "%lu"
# define U64 "%llu"
#elif BITS_PER_LONG == 64
# define X32 "%X"
//# define X64 "%lX"
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

