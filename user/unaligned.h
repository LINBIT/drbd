#ifndef UNALIGNED_H
#define UNALIGNED_H

#include <stdint.h>

#if defined(__i386__) || defined(__x86_64__)
#define UNALIGNED_ACCESS_SUPPORTED
#endif

#ifndef UNALIGNED_ACCESS_SUPPORTED
#warning "Assuming that your architecture can not do unaligned memory accesses."
#warning "Enabling extra code for unaligned memory accesses."
#endif

#ifdef UNALIGNED_ACCESS_SUPPORTED

/* On some architectures the hardware (or microcode) does it */

#define get_unaligned(ptr)		*(ptr)
#define put_unaligned(val, ptr)		*(ptr) = (val)

#else

/* on some architectures we have to do it in program code */

static inline uint16_t __get_unaligned_16(uint16_t *ptr)
{
	uint16_t rv;
	memcpy(&rv, ptr, sizeof(rv));
	return rv;
}

static inline uint32_t __get_unaligned_32(uint32_t *ptr)
{
	uint32_t rv;
	memcpy(&rv, ptr, sizeof(rv));
	return rv;
}

static inline uint64_t __get_unaligned_64(uint64_t *ptr)
{
	uint64_t rv;
	memcpy(&rv, ptr, sizeof(rv));
	return rv;
}

#define __bad_unaligned_access_size() ({			\
	fprintf(stderr, "bad unaligned access. abort()\n");	\
	abort();						\
	})

#define get_unaligned(ptr) ((typeof(*(ptr)))({							\
	__builtin_choose_expr(sizeof(*(ptr)) == 1, *(ptr),					\
	__builtin_choose_expr(sizeof(*(ptr)) == 2, __get_unaligned_16((uint16_t *)(ptr)),	\
	__builtin_choose_expr(sizeof(*(ptr)) == 4, __get_unaligned_32((uint32_t *)(ptr)),	\
	__builtin_choose_expr(sizeof(*(ptr)) == 8, __get_unaligned_64((uint64_t *)(ptr)),	\
	__bad_unaligned_access_size()))));							\
	}))

#define put_unaligned(val, ptr) ({					\
	typeof(val) v;							\
	switch (sizeof(*(ptr))) {					\
	case 1:								\
		*(uint8_t *)(ptr) = (uint8_t)(val);			\
		break;							\
	case 2:								\
	case 4:								\
	case 8:								\
		v = val;						\
		memcpy(ptr, &v, sizeof(*(ptr)));			\
		break;							\
	default:							\
		__bad_unaligned_access_size();				\
		break;							\
	}								\
	(void)0; })

#endif

#endif
