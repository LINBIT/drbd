#ifndef DRBDTOOL_COMMON_H
#define DRBDTOOL_COMMON_H

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

/*
#define PERROR(fmt, args...) \
do { fprintf(stderr,fmt ": " , ##args); perror(0); } while (0)
*/
#define PERROR(fmt, args...) fprintf(stderr, fmt ": %m\n" , ##args);

struct option;

extern int dt_lock_open_drbd(const char* device, int *lock_fd, int open_may_fail);
extern int dt_close_drbd_unlock(int drbd_fd, int lock_fd);
extern void dt_release_lockfile(int drbd_fd);
extern unsigned long long m_strtoll(const char* s,const char def_unit);
const char* make_optstring(struct option *options, char startc);
char* ppsize(char* buf, size_t size);

#endif

