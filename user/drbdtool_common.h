#ifndef DRBDTOOL_COMMON_H
#define DRBDTOOL_COMMON_H

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

#define PERROR(fmt, args...) \
do { fprintf(stderr,fmt ": " , ##args); perror(0); } while (0)

struct option;

extern void dt_release_lockfile(int drbd_fd);
extern void dt_release_lockfile_dev_name(const char* device);
extern int dt_open_drbd_device(const char* device,int open_may_fail);
extern int dt_close_drbd_device(int drbd_fd);
extern unsigned long m_strtol(const char* s,int def_mult);
const char* make_optstring(struct option *options, char startc);
char* ppsize(char* buf, size_t size);

#endif

