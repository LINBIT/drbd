#ifndef DRBDTOOL_COMMON_H
#define DRBDTOOL_COMMON_H

#define PERROR(fmt, args...) \
do { fprintf(stderr,fmt ": " , ##args); perror(0); } while (0)

extern void dt_release_lockfile(int drbd_fd);
extern int dt_open_drbd_device(const char* device);
extern unsigned long m_strtol(const char* s,int def_mult);

#endif
