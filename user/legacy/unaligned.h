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

/* Better not use memcpy(). gcc generates broken code an ARM at higher
   optimisation levels
*/

#define __bad_unaligned_access_size() ({			\
	fprintf(stderr, "bad unaligned access. abort()\n");	\
	abort();						\
	})

#define get_unaligned(ptr) ((typeof(*(ptr)))({		\
	typeof(*(ptr)) v;			 	\
	unsigned char *s = (unsigned char*)(ptr);	\
	unsigned char *d = (unsigned char*)&v;		\
	switch (sizeof(v)) {				\
	case 8: *d++ = *s++;				\
		*d++ = *s++;				\
		*d++ = *s++;				\
		*d++ = *s++;				\
	case 4: *d++ = *s++;				\
		*d++ = *s++;				\
	case 2:	*d++ = *s++;				\
	case 1:	*d++ = *s++;				\
		break;					\
	default:					\
		__bad_unaligned_access_size();		\
		break;					\
	}						\
	v; }))


#define put_unaligned(val, ptr) ({			\
	typeof(*(ptr)) v = (val);			\
	unsigned char *d = (unsigned char*)(ptr);	\
	unsigned char *s = (unsigned char*)&v;		\
	switch (sizeof(v)) {				\
	case 8: *d++ = *s++;				\
		*d++ = *s++;				\
		*d++ = *s++;				\
		*d++ = *s++;				\
	case 4: *d++ = *s++;				\
		*d++ = *s++;				\
	case 2:	*d++ = *s++;				\
	case 1:	*d++ = *s++;				\
		break;					\
	default:					\
		__bad_unaligned_access_size();		\
		break;					\
	}						\
	(void)0; })

#endif

#endif
