#ifndef DRBDTOOL_COMMON_H
#define DRBDTOOL_COMMON_H

#include <asm/types.h>
#include "drbd_endian.h"
#include <stdarg.h>

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

#define COMM_TIMEOUT 120

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

enum new_strtoll_errs {
	MSE_OK,
	MSE_DEFAULT_UNIT,
	MSE_MISSING_NUMBER,
	MSE_INVALID_NUMBER,
	MSE_INVALID_UNIT,
	MSE_OUT_OF_RANGE,
};

struct option;

extern int dt_lock_drbd(const char* device);
extern void dt_unlock_drbd(int lock_fd);
extern void dt_release_lockfile(int drbd_fd);
extern int dt_minor_of_dev(const char *device);
extern int new_strtoll(const char *s, const char def_unit, unsigned long long *rv);
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
extern void get_random_bytes(void* buffer, int len);
/* Since glibc 2.8~20080505-0ubuntu7 asprintf() is declared with the
   warn_unused_result attribute.... */
extern int m_asprintf(char **strp, const char *fmt, ...);

#endif
