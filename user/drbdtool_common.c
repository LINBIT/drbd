#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include "drbdtool_common.h"

char* ppsize(char* buf, size_t size) 
{
	// Needs 9 bytes at max.
	static char units[] = { 'K','M','G','T' };
	int base = 0;
	while (size >= 10000 ) {
		size = size >> 10;
		base++;
	}
	sprintf(buf,"%d %cB",size,units[base]);

	return buf;
}

const char* make_optstring(struct option *options,char startc)
{
  static char buffer[200];
  static struct option* buffer_valid_for=NULL;
  struct option *opt;
  char *c;

  if(options==buffer_valid_for) return buffer;
  opt=buffer_valid_for=options;
  c=buffer;
  if(startc) *c++=startc;
  while(opt->name)
    {
      *c++=opt->val;
      if(opt->has_arg) *c++=':';
      opt++;
    }
  *c=0;
  return buffer;
}

unsigned long long
m_strtoll(const char *s, const char def_unit)
{
  unsigned long long r;
  char unit = 0;
  char dummy = 0;
  int shift, c;

  /*
   * paranoia
   */
  switch (def_unit)
    {
    default:
      fprintf(stderr, "%s:%d: unexpected default unit\n", __FILE__, __LINE__);
      exit(100);
    case 0:
    case 1:
    case '1':
      shift = 0;
      break;

    case 'K':
    case 'k':
      shift = -10;
      break;

      /*
         case 'M':
         case 'm':
         case 'G':
         case 'g':
       */
    }

  if (!s || !*s)
    {
      fprintf(stderr, "missing number argument\n");
      exit(100);
    }

  c = sscanf(s, "%llu%c%c", &r, &unit, &dummy);

  if (c != 1 && c != 2)
    {
      fprintf(stderr, "%s is not a valid number\n", s);
      exit(20);
    }

  switch (unit)
    {
    case 0:
      return r;
    case 'K':
    case 'k':
      shift += 10;
      break;
    case 'M':
    case 'm':
      shift += 20;
      break;
    case 'G':
    case 'g':
      shift += 30;
      break;
    default:
      fprintf(stderr, "%s is not a valid number\n", s);
      exit(20);
    }
  if (r > (~0ULL >> shift))
    {
      fprintf(stderr, "%s: out of range\n", s);
      exit(20);
    }
  return r << shift;
}

void alarm_handler(int signo)
{ /* nothing. just interrupt F_SETLKW */ }

/* it is implicitly unlocked when the process dies.
 * but if you want to explicitly unlock it, just close it. */
int unlock_fd(int fd)
{
	return close(fd);
}

int get_fd_lockfile_timeout(const char *path, int seconds)
{
    int fd, err;
    struct sigaction sa,so;
    struct flock fl = {
	.l_type = F_WRLCK,
	.l_whence = 0,
	.l_start = 0,
	.l_len = 0
    };

    if ((fd = open(path, O_RDWR | O_CREAT, 0600)) < 0) {
	fprintf(stderr,"open(%s): %m\n",path);
	return -1;
    }

    if (seconds) {
	sa.sa_handler=alarm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags=0;
	sigaction(SIGALRM,&sa,&so);
	alarm(seconds);
	err = fcntl(fd,F_SETLKW,&fl);
	if (err) err = errno;
	alarm(0);
	sigaction(SIGALRM,&so,NULL);
    } else {
	err = fcntl(fd,F_SETLK,&fl);
	if (err) err = errno;
    }

    if (!err) return fd;

    if (err != EINTR && err != EAGAIN) {
	close(fd);
	errno = err;
	fprintf(stderr,"fcntl(%s,...): %m\n", path);
	return -1;
    }

    /* do we want to know this? */
    if (!fcntl(fd,F_GETLK,&fl)) {
	fprintf(stderr,"lock on %s currently held by pid:%u\n",
		path, fl.l_pid);
    }
    close(fd);
    return -1;
}

int dt_lock_open_drbd(const char* device, int *lock_fd, int open_may_fail)
{
  int drbd_fd, lfd, err;
  struct stat drbd_stat;
  char lfname[40];

  drbd_fd=open(device,O_RDONLY);
  if(drbd_fd==-1 && !open_may_fail)
    {
      PERROR("can not open %s", device);
      exit(20);
    }

  err=stat(device, &drbd_stat);
  if(err)
    {
      PERROR("fstat(%s) failed",device);
    }

  if(!S_ISBLK(drbd_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", device);
      exit(20);
    }

  /* FIXME maybe check the major number, too?
   * you cannot be paranoid enough...
   * either NBD [43], or DRBD [147] (enforce for v08)
   */

  /* THINK.
   * maybe we should also place a fcntl lock on the
   * _physical_device_ we open later...
   *
   * This lock is to prevent a drbd minor from being configured
   * by drbdsetup while drbdmeta is about to mess with its meta data.
   *
   * If you happen to mess with the meta data of one device,
   * pretending it belongs to an other, you'll screw up completely.
   *
   * We should store something in the meta data to detect such abuses.
   * Philipp, see my suggestion for "/var/lib/drbd/drbd-toc",
   * or /etc/drbd/ for that matter ...
   */

  /* NOTE that /var/lock/drbd-*-* may not be "secure",
   * maybe we should rather use /var/lock/drbd/drbd-*-*,
   * and make sure that /var/lock/drbd is drwx.-..-. root:root  ...
   */

  snprintf(lfname,39,"/var/lock/drbd-%d-%d",
	   major(drbd_stat.st_rdev),minor(drbd_stat.st_rdev));

  lfd = get_fd_lockfile_timeout(lfname,1);
  if (lfd < 0)
	exit(20);
  if (lock_fd) *lock_fd = lfd;

  return drbd_fd;
}

int dt_close_drbd_unlock(int drbd_fd, int lock_fd)
{
  int err = 0;
  if (drbd_fd >= 0) err = close(drbd_fd);
  if (lock_fd >= 0) unlock_fd(lock_fd); /* ignore errors */
  return err;
}
