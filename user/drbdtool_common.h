#ifndef DRBDTOOL_COMMON_H
#define DRBDTOOL_COMMON_H

#include <asm/types.h>
#include "drbd_endian.h"

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))


/* MetaDataIndex for v06 / v07 style meta data blocks */
enum MetaDataIndex {
	Flags,			/* Consistency flag,connected-ind,primary-ind */
	HumanCnt,		/* human-intervention-count */
	TimeoutCnt,		/* timout-count */
	ConnectedCnt,		/* connected-count */
	ArbitraryCnt,		/* arbitrary-count */
	GEN_CNT_SIZE		/* MUST BE LAST! (and Flags must stay first...) */
};

/*
#define PERROR(fmt, args...) \
do { fprintf(stderr,fmt ": " , ##args); perror(0); } while (0)
*/
#define PERROR(fmt, args...) fprintf(stderr, fmt ": %m\n" , ##args);

struct option;

extern int dt_lock_open_drbd(const char* device, int *lock_fd, int open_may_fail);
extern int dt_close_drbd_unlock(int drbd_fd, int lock_fd);
extern void dt_release_lockfile(int drbd_fd);
extern int dt_minor_of_dev(const char *device);
extern unsigned long long m_strtoll(const char* s,const char def_unit);
extern const char* make_optstring(struct option *options, char startc);
extern char* ppsize(char* buf, size_t size);
extern void dt_print_gc(const __u32* gen_cnt);
extern void dt_pretty_print_gc(const __u32* gen_cnt);
extern void dt_print_uuids(const __u64* uuid, unsigned int flags);
extern void dt_pretty_print_uuids(const __u64* uuid, unsigned int flags);
extern int fget_token(char *s, int size, FILE* stream);
extern int sget_token(char *s, int size, const char** text);
extern u64 bdev_size(int fd);
#endif
