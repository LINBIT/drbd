#define _GNU_SOURCE

#include <sys/types.h>
#include <asm/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <linux/drbd.h>
#include <linux/fs.h>           /* for BLKGETSIZE64 */
#include <string.h>

#include "drbdtool_common.h"

#define LANANA_DRBD_MAJOR 147	/* we should get this into linux/major.h */

int force = 0;
int confirmed(const char *text)
{
	const char yes[] = "yes";
	const ssize_t N = sizeof(yes);
	char *answer = NULL;
	size_t n = 0;
	int ok;

	printf("\n%s\n", text);

	if (force) {
	    printf("*** confirmation forced via --force option ***\n");
	    ok = 1;
	}
	else {
	    printf("[need to type '%s' to confirm] ", yes);
	    ok = getline(&answer,&n,stdin) == N &&
		strncmp(answer,yes,N-1) == 0;
	    if (answer) free(answer);
	    printf("\n");
	}
	return ok;
}


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
  struct option *opt;
  char *c;

  opt = options;
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

int
new_strtoll(const char *s, const char def_unit, unsigned long long *rv)
{
	char unit = 0;
	char dummy = 0;
	int shift, c;

	switch (def_unit) {
	default:
		return MSE_DEFAULT_UNIT;
	case 0:
	case 1:
	case '1':
		shift = 0;
		break;
	case 'K':
	case 'k':
		shift = -10;
		break;
	case 's':
		shift = -9;   // sectors
		break;
		/*
		  case 'M':
		  case 'm':
		  case 'G':
		  case 'g':
		*/
	}
	
	if (!s || !*s) return MSE_MISSING_NUMBER;

	c = sscanf(s, "%llu%c%c", rv, &unit, &dummy);

	if (c != 1 && c != 2) return MSE_INVALID_NUMBER;

	switch (unit) {
	case 0:
		return MSE_OK;
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
	case 's':
		shift += 9;
		break;		
	default:
		return MSE_INVALID_UNIT;
	}
	if (*rv > (~0ULL >> shift)) return MSE_OUT_OF_RANGE;

	*rv = *rv << shift;
	return MSE_OK;
}

unsigned long long
m_strtoll(const char *s, const char def_unit)
{
	unsigned long long r;

	switch(new_strtoll(s, def_unit, &r)) {
	case MSE_OK:
		return r;
	case MSE_DEFAULT_UNIT:
		fprintf(stderr, "unexpected default unit: %d\n",def_unit);
		exit(100);
	case MSE_MISSING_NUMBER:
		fprintf(stderr, "missing number argument\n");
		exit(100);
	case MSE_INVALID_NUMBER:
		fprintf(stderr, "%s is not a valid number\n", s);
		exit(20);
	case MSE_INVALID_UNIT:
		fprintf(stderr, "%s is not a valid number\n", s);
		exit(20);
	case MSE_OUT_OF_RANGE:
		fprintf(stderr, "%s: out of range\n", s);
		exit(20);
	default:
		fprintf(stderr, "m_stroll() is confused\n");
		exit(20);
	}
}

void alarm_handler(int __attribute((unused)) signo)
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
			if(isdigit(*c))
				return strtol(c,NULL,10);
			c++;
		}
		/* if there is not even a digit in that name, fail. */
		return -1;
	}

	return minor(sb.st_rdev);
}


int dt_lock_drbd(const char* device)
{
	int lfd;
	struct stat drbd_stat;
	char lfname[40];
	int dev_major,dev_minor;

	dev_major = 147; //LANANA_DRBD_MAJOR;
	if (!stat(device, &drbd_stat)) {
		if (!S_ISBLK(drbd_stat.st_mode)) {
			fprintf(stderr, "%s is not a block device!\n", device);
			exit(20);
		}

		dev_major = major(drbd_stat.st_rdev);

		if (dev_major != LANANA_DRBD_MAJOR) {
			fprintf(stderr, "%s does not appear to be a DRBD (major %u, expected %u)!\n",
					device, dev_major, LANANA_DRBD_MAJOR);
			exit(20);
		}
	} else {
		/* See also dt_minor_of_dev(),
		 * maybe we are about to create it?
		 * But warn people which expect drbdsetup to behave like
		 * "drbdsetup cute_name attach", it is
		 * "drbdsetup /dev/drbd# attach". */
		if (0 < strncmp("/dev/drbd0",device,10) ||
		    0 > strncmp("/dev/drbd9",device,10))
		{
			/* warn only, don't fail, there may be a reason to not
			 * use this device naming convention.
			 *
			 * but people expecting to be able to use arbitrary
			 * names for device names, just because we default to
			 * drbd0, should be made aware of their error. */
			fprintf(stderr,
				"We expect our device names to be named\n"
				"/dev/drbd<minor-number>, not %s\n", device);
		}
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
	if (dev_minor < 0) {
		fprintf(stderr,
			"Could not determine device minor number of '%s'.\n"
			"Try /dev/drbd<minor-number> instead.\n", device);
		exit(20);
	}
	snprintf(lfname,39,"/var/lock/drbd-%d-%d",dev_major,dev_minor);

	lfd = get_fd_lockfile_timeout(lfname,1);
	if (lfd < 0)
		exit(20);
	return lfd;
}

/* ignore errors */
void dt_unlock_drbd(int lock_fd)
{
	if (lock_fd >= 0) unlock_fd(lock_fd);
}

void dt_print_gc(const __u32* gen_cnt)
{
	printf("%d:%d:%d:%d:%d:%d:%d:%d\n",
	       gen_cnt[Flags] & MDF_Consistent ? 1 : 0,
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
	       "                                        WantFullSync |\n"
	       "                                  ConnectedInd |     |\n"
	       "                               lastState |     |     |\n"
	       "                      ArbitraryCnt |     |     |     |\n"
	       "                ConnectedCnt |     |     |     |     |\n"
	       "            TimeoutCnt |     |     |     |     |     |\n"
	       "        HumanCnt |     |     |     |     |     |     |\n"
	       "Consistent |     |     |     |     |     |     |     |\n"
	       "   --------+-----+-----+-----+-----+-----+-----+-----+\n"
	       "       %3s | %3d | %3d | %3d | %3d | %3s | %3s | %3s  \n"
	       "\n",
	       gen_cnt[Flags] & MDF_Consistent ? "1/c" : "0/i",
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
	printf("%d:%d:%d:%d:%d:%d\n",
	       flags & MDF_Consistent ? 1 : 0,
	       flags & MDF_WasUpToDate ? 1 : 0,
	       flags & MDF_PrimaryInd ? 1 : 0,
	       flags & MDF_ConnectedInd ? 1 : 0,
	       flags & MDF_FullSync ? 1 : 0,
	       flags & MDF_PeerOutDated ? 1 : 0);
}

void dt_pretty_print_uuids(const __u64* uuid, unsigned int flags)
{
	printf(
"\n"
"       +--<  Current data generation UUID  >-\n"
"       |               +--<  Bitmap's base data generation UUID  >-\n"
"       |               |                 +--<  younger history UUID  >-\n"
"       |               |                 |         +-<  older history  >-\n"
"       V               V                 V         V\n");
	dt_print_uuids(uuid, flags);
	printf(
"                                                                    ^ ^ ^ ^ ^ ^\n"
"                                      -<  Data consistancy flag  >--+ | | | | |\n"
"                             -<  Data was/is currently up-to-date  >--+ | | | |\n"
"                                  -<  Node was/is currently primary  >--+ | | |\n"
"                                  -<  Node was/is currently connected  >--+ | |\n"
"         -<  Node was in the progress of setting all bits in the bitmap  >--+ |\n"
"                        -<  The peer's disk was out-dated or inconsistent  >--+\n"
"\n");
}

int fget_token(char *s, int size, FILE* stream)
{
	int c;
	char* sp = s;

	do { // eat white spaces in front.
		c = getc(stream);
		if( c == EOF) return EOF;
	} while (!isgraph(c));

	do { // read the first word into s
		*sp++ = c;
		c = getc(stream);
		if ( c == EOF) break;
	} while (isgraph(c) && --size);

	*sp=0;
	return 1;
}

int sget_token(char *s, int size, const char** text)
{
	int c;
	char* sp = s;

	do { // eat white spaces in front.
		c = *(*text)++;
		if( c == 0) return EOF;
	} while (!isgraph(c));

	do { // read the first word into s
		*sp++ = c;
		c = *(*text)++;
		if ( c == 0) break;
	} while (isgraph(c) && --size);

	*sp=0;
	return 1;
}

u64 bdev_size(int fd)
{
	u64 size64;		/* size in byte. */
	long size;		/* size in sectors. */
	int err;

	err = ioctl(fd, BLKGETSIZE64, &size64);
	if (err) {
		if (errno == EINVAL) {
			printf("INFO: falling back to BLKGETSIZE\n");
			err = ioctl(fd, BLKGETSIZE, &size);
			if (err) {
				perror("ioctl(,BLKGETSIZE,) failed");
				exit(20);
			}
			size64 = (u64)512 *size;
		} else {
			perror("ioctl(,BLKGETSIZE64,) failed");
			exit(20);
		}
	}

	return size64;
}

void get_random_bytes(void* buffer, int len)
{
	int fd;

	fd = open("/dev/urandom",O_RDONLY);
	if( fd == -1) {
		perror("Open of /dev/urandom failed");
		exit(20);
	}
	if(read(fd,buffer,len) != len) {
		fprintf(stderr,"Reading from /dev/urandom failed\n");
		exit(20);
	}
	close(fd);
}
