#define _GNU_SOURCE

#include <sys/types.h>
#include <asm/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/drbd.h>

#include "drbdtool_common.h"
#include "drbd_endian.h"

char* ppsize(char* buf, size_t size) 
{
	// Needs 9 bytes at max.
	static char units[] = { 'K','M','G','T' };
	int base = 0;
	while (size >= 10000 ) {
		size = size >> 10;
		base++;
	}
	sprintf(buf,"%lu %cB",(unsigned long)size,units[base]);

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

int dt_minor_of_dev(const char *device)
{
	struct stat sb;

	if(stat(device,&sb)) {
		// On udev/devfs based system the device nodes does not
		// exist before the module is loaded. Therefore assume that
		// the number in the device name is the minor number.
		const char *c;

		c=device;
		while(*c) {
			if(isdigit(*c)) return strtol(c,NULL,10);
			c++;
		}
		return 0;
	}

	return minor(sb.st_rdev);
}


int dt_lock_open_drbd(const char* device, int *lock_fd, int open_may_fail)
{
	int drbd_fd, lfd;
	struct stat drbd_stat;
	char lfname[40];
	int dev_major,dev_minor;

	drbd_fd=open(device,O_RDONLY);
	if(drbd_fd==-1 && !open_may_fail) {
		PERROR("can not open %s", device);
		exit(20);
	}
	
	dev_major = 147; //LANANA_DRBD_MAJOR;

	if( !stat(device, &drbd_stat) ) {

		if(!S_ISBLK(drbd_stat.st_mode)) {
			fprintf(stderr, "%s is not a block device!\n", device);
			exit(20);
		}

		dev_major = major(drbd_stat.st_rdev);

		/* FIXME maybe check the major number, too?
		 * you cannot be paranoid enough...
		 * either NBD [43], or DRBD [147] (enforce for v08)
		 */
	}


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

	dev_minor = dt_minor_of_dev(device);
	snprintf(lfname,39,"/var/lock/drbd-%d-%d",dev_major,dev_minor);

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

void dt_print_gc(const __u32* gen_cnt)
{
	printf("%d:%d:%d:%d:%d:%d:%d:%d:%d\n",
	       gen_cnt[Flags] & MDF_Consistent ? 1 : 0,
	       gen_cnt[Flags] & MDF_WasUpToDate ? 1 : 0,
	       gen_cnt[HumanCnt],
	       gen_cnt[TimeoutCnt],
	       gen_cnt[ConnectedCnt],
	       gen_cnt[ArbitraryCnt],
	       gen_cnt[Flags] & MDF_PrimaryInd ? 1 : 0,
	       gen_cnt[Flags] & MDF_ConnectedInd ? 1 : 0,
	       gen_cnt[Flags] & MDF_FullSync ? 1 : 0);
}

void dt_pretty_print_gc(const __u32* gen_cnt)
{
	printf("\n"
	       "                                              WantFullSync |\n"
	       "                                        ConnectedInd |     |\n"
	       "                                     lastState |     |     |\n"
	       "                            ArbitraryCnt |     |     |     |\n"
	       "                      ConnectedCnt |     |     |     |     |\n"
	       "                  TimeoutCnt |     |     |     |     |     |\n"
	       "              HumanCnt |     |     |     |     |     |     |\n"
	       "     WasUpToDate |     |     |     |     |     |     |     |\n"
	       "Consistent |     |     |     |     |     |     |     |     |\n"
	       "   --------+-----+-----+-----+-----+-----+-----+-----+-----+\n"
	       "       %3s | %3s | %3d | %3d | %3d | %3d | %3s | %3s | %3s  \n"
	       "\n",
	       gen_cnt[Flags] & MDF_Consistent ? "1/c" : "0/i",
	       gen_cnt[Flags] & MDF_WasUpToDate ? "1/y" : "0/n",
	       gen_cnt[HumanCnt],
	       gen_cnt[TimeoutCnt],
	       gen_cnt[ConnectedCnt],
	       gen_cnt[ArbitraryCnt],
	       gen_cnt[Flags] & MDF_PrimaryInd ? "1/p" : "0/s",
	       gen_cnt[Flags] & MDF_ConnectedInd ? "1/c" : "0/n",
	       gen_cnt[Flags] & MDF_FullSync ? "1/y" : "0/n");
}

void dt_print_uuids(const __u64* uuid, unsigned int flags)
{
	int i;
	printf(X64(016)":"X64(016)":",
	       uuid[Current],
	       uuid[Bitmap]);
	for ( i=History_start ; i<=History_end ; i++ ) {
		printf(X64(016)":", uuid[i]);
	}
	printf("%d:%d:%d:%d:%d\n",
	       flags & MDF_Consistent ? 1 : 0,
	       flags & MDF_WasUpToDate ? 1 : 0,
	       flags & MDF_PrimaryInd ? 1 : 0,
	       flags & MDF_ConnectedInd ? 1 : 0,
	       flags & MDF_FullSync ? 1 : 0);
}

void dt_pretty_print_uuids(const __u64* uuid, unsigned int flags)
{
	printf(
"\n"
"       +--<  Current data generation UUID  >-\n"
"       |               +--<  Bitmap's base data generation UUID  >-\n"
"       |               |                 +--<  younger historiy UUID  >-\n"
"       |               |                 |         +-<  older history  >-\n"
"       V               V                 V         V\n");               
	dt_print_uuids(uuid, flags);
	printf(
"                                                                    ^ ^ ^ ^ ^\n"
"                                      -<  Data consistancy flag  >--+ | | | |\n"
"                             -<  Data was/is currently up-to-date  >--+ | | |\n"
"                                  -<  Node was/is currently primary  >--+ | |\n"
"                                  -<  Node was/is currently connected  >--+ |\n"
"         -<  Node was in the progress of setting all bits in the bitmap  >--+\n"
"\n");
}
