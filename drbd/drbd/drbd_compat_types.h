
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


#else // LINUX 2.6
//#warning "FIXME"

typedef struct bio drbd_bio_t;

#define SIGHAND_HACK

#define NOT_IN_26(x...)
#define ONLY_IN_26(x...)	x

#endif
