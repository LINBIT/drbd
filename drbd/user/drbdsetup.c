/*
   drbdsetup.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999 2000, Philipp Reisner <philipp@linuxfreak.com>.
        Initial author.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
        Added sanity checks before using the device.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h> 
#include <string.h>
#include "../drbd/drbd.h"
#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <linux/kdev_t.h>

/* Copied from drbd.c (the module's source), this probably belongs in a header file */
#define MAJOR_NR 43

unsigned long resolv(const char* name)
{
  unsigned long retval;

  if((retval = inet_addr(name)) == INADDR_NONE ) 
    {
      struct hostent *he;
      he = gethostbyname(name);
      if (!he)
	{
	  perror("can not resolv hostname");
	  exit(20);
	}
      retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
    }
  return retval;
}

int m_strtol(const char* s)
{
  char *e = (char*)s;
  long r;

  r = strtol(s,&e,0);
  if(*e == 0)
    return r;

  fprintf(stderr,"%s is not a valid number\n",s);
  exit(20);
}

const char* addr_part(const char* s)
{
  static char buffer[200];
  char *b;

  b=strchr(s,':');
  if(b)
    {
      strncpy(buffer,s,b-s);
      buffer[b-s]=0;
      return buffer;
    }
  return s;
}

int port_part(const char* s)
{
  char *b;

  b=strchr(s,':');
  if(b)
      return m_strtol(b+1);

  return 7788;
}


int main(int argc, char** argv)
{
  int dtbd_fd;

  if(argc != 3 && argc < 6)
    {
      fprintf(stderr,
	      " %s device {Pri|Sec|Wait|Repl}\n"
	      " %s device lower_device protocol local_addr[:port] "
	      "remote_addr[:port] \n"
	      "       [-t|--timout val] [-r|--sync-rate val] "
	      "[-k|--skip-sync] [-s|-tl-size val]\n"
	      "       [-d|--disk-size val] [-p|--do-panic]\n\n"
	      "       protocol\n"
	      "          protocol may be A, B or C.\n\n" 
	      "       port\n"
	      "          TCP port number\n"
	      "          Default: 7788\n"
	      "       -t --timeout  val\n"
	      "          If communication blocks for val * 1/10 seconds,\n"
	      "          drbd falls back into unconnected operation.\n"
	      "          Default: 30 = 3 sec.\n\n"
	      "       -r --sync-rate val\n"
	      "          The synchronisations sends up to val KB per sec.\n"
	      "          Default: 250 = 250 KB/sec\n\n"
	      "       -k --skip-sync\n"
	      "          Instruct drbd not to do synchronisation.\n\n"
	      "       -s --tl-size val\n"
	      "          Sets the size of the transfer log(=TL). The TL is\n"
	      "          is used for dependency analysis. For long latency\n"
	      "          high bandwith links it might be necessary to set\n"
	      "          the size bigger than 256.\n"
	      "          You will see error messages in the system log\n"
	      "          if the TL is too small.\n"
	      "          Default: 256 entries\n\n"
	      "      -d --disk-size\n"
	      "          Sets drbd's size. When given 0 drbd negotiates the\n"
	      "          size with the remote node.\n"
	      "          Default: 0 KB.\n\n"
	      "      -p --do-panic\n"
	      "          drbd will trigger a kernel panic if there is an\n"
	      "          IO error on the lower_device. May be usefull when\n"
	      "          drbd is used in a HA cluster.\n\n"
	      "          Version: "VERSION"\n"
	      ,argv[0],argv[0]);
      exit(20);
    }

  dtbd_fd=open(argv[1],O_RDONLY);
  if(dtbd_fd==-1)
    {
      perror("can not open device");
      exit(20);
    }

  {
    int retval;
    int err;
    struct stat drbd_stat;

    /* Check if the device is really drbd */
    err=fstat(dtbd_fd, &drbd_stat);
    if(err)
      {
	perror("fstat() failed");
      }
    if(!S_ISBLK(drbd_stat.st_mode))
      {
	fprintf(stderr, "%s is not a block device!\n", argv[1]);
	exit(20);
      }
    if(MAJOR(drbd_stat.st_rdev) != MAJOR_NR)
      {
	fprintf(stderr, "%s is not a drbd device!\n", argv[1]);
	exit(20);
      }
    err=ioctl(dtbd_fd,DRBD_IOCTL_GET_VERSION,&retval);
    if(err)
      {
	perror("ioctl() failed");
      }
    
    if (retval != MOD_VERSION)
      {
	fprintf(stderr,"Versions of drbdsetup and module does not match!\n");
	exit(20);
      }    
  }

  if(argc == 3)
    {
      int err;
      Drbd_State state;
      if(argv[2][0]=='p' || argv[2][0]=='P')
	{
	  state = Primary;
	}
      else if(argv[2][0]=='s' || argv[2][0]=='S')
	{
	  state = Secondary;
	}
      else if(argv[2][0]=='w' || argv[2][0]=='W')
	{
	  int retval;
	  err=ioctl(dtbd_fd,DRBD_IOCTL_WAIT_SYNC,&retval);
	  exit(!retval);
	}
      else if(argv[2][0]=='r' || argv[2][0]=='R')
        {
	  err=ioctl(dtbd_fd,DRBD_IOCTL_DO_SYNC_ALL);
	  exit(0);	  
	}
      else 
	{
	  fprintf(stderr,"this is no known command!\n");
	  exit(20);
	}
      err=ioctl(dtbd_fd,DRBD_IOCTL_SET_STATE,state);
      if(err)
	{
	  perror("ioctl() failed");
	}

      exit(0);
    }

  if(argc >= 6)
    {

      int lower_device;
      struct ioctl_drbd_config config;
      struct sockaddr_in *other_addr;
      struct sockaddr_in *my_addr;
      int err;
      struct stat lower_stat;

      if((lower_device = open(argv[2],O_RDWR))==-1)
	{
	  perror("Can not open lower device");
	  exit(20);
	}
      /* Check if the device is a block device */
      err=fstat(lower_device, &lower_stat);
      if(err)
	{
	  perror("fstat() failed");
	}
      if(!S_ISBLK(lower_stat.st_mode))
	{
	  fprintf(stderr, "%s is not a block device!\n", argv[2]);
	  exit(20);
	}

      config.lower_device=lower_device;

      switch(argv[3][0])
	{
	case 'a':
	case 'A':
	  config.wire_protocol = DRBD_PROT_A;
	  break;
	case 'b':
	case 'B':
	  config.wire_protocol = DRBD_PROT_B;
	  break;
	case 'c':
	case 'C':
	  config.wire_protocol = DRBD_PROT_C;
	  break;
	default:	  
	  fprintf(stderr,"Invalid protocol specifier.\n");
	  exit(20);	  
	}

      config.my_addr_len = sizeof(struct sockaddr_in);
      my_addr = (struct sockaddr_in *)config.my_addr;
      my_addr->sin_port = htons(port_part(argv[4]));
      my_addr->sin_family = AF_INET;
      my_addr->sin_addr.s_addr = resolv(addr_part(argv[4]));

      config.other_addr_len = sizeof(struct sockaddr_in);
      other_addr = (struct sockaddr_in *)config.other_addr;
      other_addr->sin_port = htons(port_part(argv[5]));
      other_addr->sin_family = AF_INET;
      other_addr->sin_addr.s_addr = resolv(addr_part(argv[5]));

      config.timeout = 30; /* = 3 seconds */
      config.sync_rate = 250; /* KB/sec */
      config.skip_sync = 0; 
      config.tl_size = 256;
      config.disk_size = 0;
      config.do_panic  = 0;

      optind=6;
      while(1)
	{
	  int c;
	  static struct option options[] = {
	    { "timeout",   required_argument, 0, 't' },
	    { "sync-rate", required_argument, 0, 'r' },
	    { "skip-sync", no_argument,       0, 'k' },
	    { "tl-size",   required_argument, 0, 's' },
	    { "disk-size", required_argument, 0, 'd' },
	    { "do-panic",  no_argument,       0, 'p' },
	    { 0,           0,                 0, 0   }
	  };
	  
	  c = getopt_long(argc,argv,"t:r:ks:d:p",options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 't': 
	      config.timeout = m_strtol(optarg);
	      break;
	    case 'r':
	      config.sync_rate = m_strtol(optarg);
	      break;
	    case 'k':
	      config.skip_sync=1;
	      break;
	    case 's':
	      config.tl_size = m_strtol(optarg);
	      break;
	    case 'd':
	      config.disk_size = m_strtol(optarg);
	      break;
	    case 'p':
	      config.do_panic=1;
	      break;
	    }
	}

      err=ioctl(dtbd_fd,DRBD_IOCTL_SET_CONFIG,&config);      
      if(err)
	{
	  perror("ioctl() failed");
	}
    }
  return 0;
}
