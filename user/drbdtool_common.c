#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#define _GNU_SOURCE
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

void create_lockfile_mm(int major, int minor)
{
  char lfname[40];
  int fd,pid;
  FILE* fi;

  snprintf(lfname,39,"/var/lock/drbd-%d-%d.pid",major,minor);

  while ( (fd = open(lfname,O_CREAT|O_EXCL|O_WRONLY,00644)) == -1 )
    {
      fd = open(lfname,O_RDONLY);
      if(fd == -1 )
	{
	  PERROR("Creation and open(,O_RDONLY) of lockfile failed");
	  exit(20);
	}
      fi = fdopen(fd,"r");
      fscanf(fi,"%d",&pid);
      fclose(fi);
      errno = 0;
      kill(pid,0);
      if(errno == ESRCH) {
	fprintf(stderr,"Stale lock file found and removed.\n");
	remove(lfname);
      } else {
	fprintf(stderr,"A drbd tool with pid %d has the device locked.\n",pid);
	exit(20);
      }
    }

  fi = fdopen(fd,"w");
  fprintf(fi,"%d\n",getpid());
  fclose(fi);
}

int dt_open_drbd_device(const char* device,int open_may_fail)
{
  int drbd_fd,err;
  struct stat drbd_stat;

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

  create_lockfile_mm(major(drbd_stat.st_rdev),minor(drbd_stat.st_rdev));

  return drbd_fd;
}

void dt_release_lockfile(int drbd_fd)
{
  int err;
  struct stat drbd_stat;
  char lfname[40];

  err=fstat(drbd_fd, &drbd_stat);
  if(err)
    {
      PERROR("fstat() failed");
      exit(20);
    }

  snprintf(lfname,39,"/var/lock/drbd-%d-%d.pid",
	   major(drbd_stat.st_rdev),minor(drbd_stat.st_rdev));

  remove(lfname);
}

void dt_release_lockfile_dev_name(const char* device)
{
  int err;
  struct stat drbd_stat;
  char lfname[40];

  err=stat(device, &drbd_stat);
  if(err)
    {
      PERROR("stat() failed");
      exit(20);
    }

  snprintf(lfname,39,"/var/lock/drbd-%d-%d.pid",
	   major(drbd_stat.st_rdev),minor(drbd_stat.st_rdev));

  remove(lfname);
}

int dt_close_drbd_device(int drbd_fd)
{
  dt_release_lockfile(drbd_fd);
  return close(drbd_fd);
}
