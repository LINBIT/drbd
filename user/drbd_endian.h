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
#define s64 int64_t
#define u32 uint32_t
#define s32 int32_t
#define u16 uint16_t
#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t

#include <asm/byteorder.h>

#define cpu_to_le64(x) __cpu_to_le64(x)
#define le64_to_cpu(x) __le64_to_cpu(x)
#define cpu_to_le32(x) __cpu_to_le32(x)
#define le32_to_cpu(x) __le32_to_cpu(x)
#define cpu_to_le16(x) __cpu_to_le16(x)
#define le16_to_cpu(x) __le16_to_cpu(x)
#define cpu_to_be64(x) __cpu_to_be64(x)
#define be64_to_cpu(x) __be64_to_cpu(x)
#define cpu_to_be32(x) __cpu_to_be32(x)
#define be32_to_cpu(x) __be32_to_cpu(x)
#define cpu_to_be16(x) __cpu_to_be16(x)
#define be16_to_cpu(x) __be16_to_cpu(x)

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

