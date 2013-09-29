#ifndef DRBDTOOL_COMMON_H
#define DRBDTOOL_COMMON_H

#include "drbd_endian.h"
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <linux/major.h>

#define LANANA_DRBD_MAJOR 147	/* we should get this into linux/major.h */
#ifndef DRBD_MAJOR
#define DRBD_MAJOR LANANA_DRBD_MAJOR
#elif (DRBD_MAJOR != LANANA_DRBD_MAJOR)
# error "FIXME unexpected DRBD_MAJOR"
#endif

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(A) (sizeof(A)/sizeof(A[0]))
#endif

/**
 * BUILD_BUG_ON - break compile if a condition is true.
 * @condition: the condition which the compiler should know is false.
 *
 * If you have some code which relies on certain constants being equal, or
 * other compile-time-evaluated condition, you should use BUILD_BUG_ON to
 * detect if someone changes it.
 *
 * The implementation uses gcc's reluctance to create a negative array, but
 * gcc (as of 4.4) only emits that error for obvious cases (eg. not arguments
 * to inline functions).  So as a fallback we use the optimizer; if it can't
 * prove the condition is false, it will cause a link error on the undefined
 * "__build_bug_on_failed".  This error message can be harder to track down
 * though, hence the two different methods.
 */
#ifndef __OPTIMIZE__
#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#else
extern int __build_bug_on_failed;
#define BUILD_BUG_ON(condition)                                 \
	do {                                                    \
		((void)sizeof(char[1 - 2*!!(condition)]));      \
		if (condition) __build_bug_on_failed = 1;       \
	} while(0)
#endif

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

/* Flags which used to be in enum mdf_flag before version 09 */
enum mdf_flag_08 {
	MDF_CONNECTED_IND =  1 << 2,
	MDF_FULL_SYNC =      1 << 3,
	MDF_PEER_OUT_DATED = 1 << 5,
	MDF_FENCING_IND =    1 << 8,
};

struct option;

extern int only_digits(const char *s);
extern int dt_lock_drbd(int minor);
extern void dt_unlock_drbd(int lock_fd);
extern void dt_release_lockfile(int drbd_fd);
extern int dt_minor_of_dev(const char *device);
extern unsigned long long m_strtoll(const char* s,const char def_unit);
extern const char* make_optstring(struct option *options);
extern char* ppsize(char* buf, unsigned long long size);
extern void dt_print_gc(const uint32_t* gen_cnt);
extern void dt_pretty_print_gc(const uint32_t* gen_cnt);
extern void dt_print_uuids(const uint64_t* uuid, unsigned int flags);
extern void dt_pretty_print_uuids(const uint64_t* uuid, unsigned int flags);
extern int fget_token(char *s, int size, FILE* stream);
extern int sget_token(char *s, int size, const char** text);
extern uint64_t bdev_size(int fd);
extern void get_random_bytes(void* buffer, int len);

extern const char* shell_escape(const char* s);

void dt_print_v9_uuids(const uint64_t*, unsigned int, unsigned int);
void dt_pretty_print_v9_uuids(const uint64_t*, unsigned int, unsigned int);

/* In-place unescape double quotes and backslash escape sequences from a
 * double quoted string. Note: backslash is only useful to quote itself, or
 * double quote, no special treatment to any c-style escape sequences. */
extern void unescape(char *txt);

/* Since glibc 2.8~20080505-0ubuntu7 asprintf() is declared with the
   warn_unused_result attribute.... */
extern int m_asprintf(char **strp, const char *fmt, ...);

extern void fprintf_hex(FILE *fp, off_t file_offset, const void *buf, unsigned len);

/* If the lower level device is resized,
 * and DRBD did not move its "internal" meta data in time,
 * the next time we try to attach, we won't find our meta data.
 *
 * Some helpers for storing and retrieving "last known"
 * information, to be able to find it regardless,
 * without scanning the full device for magic numbers.
 */

/* We may want to store more things later...  if so, we can easily change to
 * some NULL terminated tag-value list format then.
 * For now: store the last known lower level block device size,
 * and its /dev/<name> */
struct bdev_info {
	uint64_t bd_size;
	uint64_t bd_uuid;
	char *bd_name;
};

/* these return 0 on sucess, error code if something goes wrong. */
/* create (update) the last-known-bdev-info file */
extern int lk_bdev_save(const unsigned minor, const struct bdev_info *bd);
/* we may want to remove all stored information */
extern int lk_bdev_delete(const unsigned minor);
/* load info from that file.
 * caller should free(bd->bd_name) once it is no longer needed. */
extern int lk_bdev_load(const unsigned minor, struct bdev_info *bd);
const char *canonical_hostname(void);

#endif
