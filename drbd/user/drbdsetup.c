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
#include <errno.h>

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

unsigned long resolv(const char* name)
{
  unsigned long retval;

  if((retval = inet_addr(name)) == INADDR_NONE ) 
    {
      struct hostent *he;
      he = gethostbyname(name);
      if (!he)
	{
	  perror("can not resolv the hostname");
	  exit(20);
	}
      retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
    }
  return retval;
}

int m_strtol(const char* s,int def_mult)
{
  char *e = (char*)s;
  long r;

  r = strtol(s,&e,0);
  switch(*e)
    {
    case 0:
      return r;
    case 'K':
    case 'k':
      return r*(1024/def_mult);
    case 'M':
    case 'm':
      return r*1024*(1024/def_mult);
    case 'G':
    case 'g':      
      return r*1024*1024*(1024/def_mult);
    default:
      fprintf(stderr,"%s is not a valid number\n",s);
      exit(20);
    }
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
      return m_strtol(b+1,1);

  return 7788;
}

int already_in_use_tab(const char* dev_name,const char* tab_name)
{
  FILE* tab;
  char line[200];
  int dev_name_len;  

  if( ! (tab=fopen(tab_name,"r")) )
    return 0;

  dev_name_len=strlen(dev_name);

  while( fgets(line,200,tab) )
    {
      if(!strncmp(line,dev_name,dev_name_len))
	{
	  fclose(tab);
	  return 1;
	}
    }
  fclose(tab);
  return 0;
}

int already_in_use(const char* dev_name)
{        
  return already_in_use_tab(dev_name,"/etc/mtab") || 
    already_in_use_tab(dev_name,"/proc/mounts");
}

void print_usage(const char* prgname)
{
  fprintf(stderr,
	  " %s device {Pri|Sec|Wait [-t|--time val]|Repl|Down}\n"
	  " %s device lower_device protocol local_addr[:port] "
	  "remote_addr[:port] \n"
	  "       [-t|--timout val] [-r|--sync-rate val] "
	  "[-k|--skip-sync] [-s|-tl-size val]\n"
	  "       [-d|--disk-size val] [-p|--do-panic] "
	  "[-c|--connect-int] [-i|--ping-int]\n\n"
	  "       protocol\n"
	  "          protocol may be A, B or C.\n\n" 
	  "       port\n"
	  "          TCP port number\n"
	  "          Default: 7788\n\n"
	  "       -t --timeout  val\n"
	  "          If communication blocks for val * 1/10 seconds,\n"
	  "          drbd falls back into unconnected operation.\n"
	  "          Default: 60 = 6 sec.\n\n"
	  "       -r --sync-rate val\n"
	  "          The synchronisation sends up to val KB per sec.\n"
	  "          Default: 250 = 250 KB/sec\n\n"
	  "       -k --skip-sync\n"
	  "          Instructs drbd not to do synchronisation.\n\n"
	  "       -s --tl-size val\n"
	  "          Sets the size of the transfer log(=TL). The TL is\n"
	  "          used for dependency analysis. For long latency\n"
	  "          high bandwith links it might be necessary to set\n"
	  "          the size bigger than 256.\n"
	  "          You will find error messages in the system log\n"
	  "          if the TL is too small.\n"
	  "          Default: 256 entries\n\n"
	  "      -d --disk-size\n"
	  "          Sets drbd's size. When set to 0, drbd negotiates the\n"
	  "          size with the remote node.\n"
	  "          Default: 0 KB.\n\n"
	  "      -p --do-panic\n"
	  "          Drbd will trigger a kernel panic if there is an\n"
	  "          IO error on the lower_device. May be useful when\n"
	  "          drbd is used in a HA cluster.\n\n"
	  "      -c --connect-int\n"
	  "          If drbd cannot connect it will retry every val seconds.\n"
	  "          Default: 10 Seconds\n\n"
	  "      -i --ping-int\n"
	  "          If the connection is idle for more than val seconds\n"
	  "          DRBD will send a NOP packet. This helps DRBD to\n"
	  "          detect broken connections.\n"
	  "          Default: 10 Seconds\n\n"
	  "     multipliers\n"
	  "          You may append K, M or G to the values of -r and -d\n"
	  "          where K=2^10, M=2^20 and G=2^30.\n\n"
	  "          Version: "VERSION"\n"
	  ,prgname,prgname);
  exit(20);
}


int main(int argc, char** argv)
{
  int drbd_fd;

  if(argc == 1) print_usage(argv[0]);

  drbd_fd=open(argv[1],O_RDONLY);
  if(drbd_fd==-1)
    {
      perror("can not open device");
      exit(20);
    }

  {
    int retval;
    int err;
    struct stat drbd_stat;

    /* Check if the device is really drbd */
    err=fstat(drbd_fd, &drbd_stat);
    if(err)
      {
	perror("fstat() failed");
      }
    if(!S_ISBLK(drbd_stat.st_mode))
      {
	fprintf(stderr, "%s is not a block device!\n", argv[1]);
	exit(20);
      }
    err=ioctl(drbd_fd,DRBD_IOCTL_GET_VERSION,&retval);
    if(err)
      {
	perror("ioctl() failed");
      }
    
    if (retval != MOD_VERSION)
      {
	fprintf(stderr,"Versions of drbdsetup and module are not matching!\n");
	exit(20);
      }    
  }

  if(argv[2][0] != '/') /* UGGLY !!! */
    {
      int err;
      int retval;
      Drbd_State state;

      switch(argv[2][0])
        {
	case 'p':
	case 'P':
	  state = Primary;
	  break;
	case 's':
	case 'S':
	  state = Secondary;
	  break;
	case 'w':
	case 'W':
	  optind=3; 
	  retval=8; /* Do not wait longer than 8 seconds for a connection */
	  while(1)
	    {
	      int c;
	      static struct option options[] = {
		{ "time",    required_argument, 0, 't' },
		{ 0,           0,                 0, 0 }
	      };
	  
	      c = getopt_long(argc,argv,"t:",options,0);
	      if(c == -1) break;
	      switch(c)
		{
		case 't': 
		  retval = m_strtol(optarg,1);
		  break;
		}
	    }
	  err=ioctl(drbd_fd,DRBD_IOCTL_WAIT_SYNC,&retval);
	  if(err)
	    {
	      perror("ioctl() failed");
	      exit(20);
	    }
	  exit(!retval);
	case 'r':
	case 'R':
	  err=ioctl(drbd_fd,DRBD_IOCTL_DO_SYNC_ALL);
	  if(err)
	    {
	      perror("ioctl() failed");
	      if(errno==EINPROGRESS)
	        fprintf(stderr,"Can not start SyncAll. No Primary!\n");
	      if(errno==ENXIO)
	        fprintf(stderr,"Can not start SyncAll. Not connected!\n");
	      exit(20);
	    }
         exit(0);        
	case 'd':
	case 'D':
	  err=ioctl(drbd_fd,DRBD_IOCTL_UNCONFIG);
	  if(err)
	    {
	      perror("ioctl() failed");
	      if(errno==ENXIO)
		fprintf(stderr,"Device is not configured!\n");
	      if(errno==EBUSY)
		fprintf(stderr,"Someone has opened the device!\n");
	      exit(20);
	    }
	  exit(0);        
	  break;
	default:
	  print_usage(argv[0]);
        }
      err=ioctl(drbd_fd,DRBD_IOCTL_SET_STATE,state);
      if(err)
	{
	  perror("ioctl() failed");
	  if(errno==EBUSY)	    
	    fprintf(stderr,"Someone has opened the device for RW access!\n");
	  if(errno==EINPROGRESS)
	    fprintf(stderr,"Resynchronization process currently running!\n");
	  exit(20);
	}

      exit(0);
    }

  if(argc >= 6)
    {

      int lower_device;
      struct ioctl_drbd_config cn;
      struct sockaddr_in *other_addr;
      struct sockaddr_in *my_addr;
      int err;
      struct stat lower_stat;

      if(already_in_use(argv[2]))
	{
	  fprintf(stderr,"Lower device (%s) is already mounted\n",argv[2]);
	  exit(20);
	}

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

      cn.config.lower_device=lower_device;

      switch(argv[3][0])
	{
	case 'a':
	case 'A':
	  cn.config.wire_protocol = DRBD_PROT_A;
	  break;
	case 'b':
	case 'B':
	  cn.config.wire_protocol = DRBD_PROT_B;
	  break;
	case 'c':
	case 'C':
	  cn.config.wire_protocol = DRBD_PROT_C;
	  break;
	default:	  
	  fprintf(stderr,"Invalid protocol specifier.\n");
	  exit(20);	  
	}

      cn.config.my_addr_len = sizeof(struct sockaddr_in);
      my_addr = (struct sockaddr_in *)cn.config.my_addr;
      my_addr->sin_port = htons(port_part(argv[4]));
      my_addr->sin_family = AF_INET;
      my_addr->sin_addr.s_addr = resolv(addr_part(argv[4]));

      cn.config.other_addr_len = sizeof(struct sockaddr_in);
      other_addr = (struct sockaddr_in *)cn.config.other_addr;
      other_addr->sin_port = htons(port_part(argv[5]));
      other_addr->sin_family = AF_INET;
      other_addr->sin_addr.s_addr = resolv(addr_part(argv[5]));

      cn.config.timeout = 60; /* = 6 seconds */
      cn.config.sync_rate = 250; /* KB/sec */
      cn.config.skip_sync = 0; 
      cn.config.tl_size = 256;
      cn.config.disk_size = 0;
      cn.config.do_panic  = 0;
      cn.config.try_connect_int = 10;
      cn.config.ping_int = 10;

      optind=6;
      while(1)
	{
	  int c;
	  static struct option options[] = {
	    { "timeout",    required_argument, 0, 't' },
	    { "sync-rate",  required_argument, 0, 'r' },
	    { "skip-sync",  no_argument,       0, 'k' },
	    { "tl-size",    required_argument, 0, 's' },
	    { "disk-size",  required_argument, 0, 'd' },
	    { "do-panic",   no_argument,       0, 'p' },
	    { "connect-int",required_argument, 0, 'c' },
	    { "ping-int",   required_argument, 0, 'i' },
	    { 0,           0,                 0, 0   }
	  };
	  
	  c = getopt_long(argc,argv,"t:r:ks:d:pc:i:",options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 't': 
	      cn.config.timeout = m_strtol(optarg,1);
	      break;
	    case 'r':
	      cn.config.sync_rate = m_strtol(optarg,1024);
	      break;
	    case 'k':
	      cn.config.skip_sync=1;
	      break;
	    case 's':
	      cn.config.tl_size = m_strtol(optarg,1);
	      break;
	    case 'd':
	      cn.config.disk_size = m_strtol(optarg,1024);
	      break;
	    case 'p':
	      cn.config.do_panic=1;
	      break;
	    case 'c':
	      cn.config.try_connect_int = m_strtol(optarg,1);
	      break;
	    case 'i':
	      cn.config.ping_int = m_strtol(optarg,1);
	      break;
	    }
	}

      /* sanity checks of the timeouts */

      if(cn.config.timeout >= cn.config.try_connect_int * 10 ||
	 cn.config.timeout >= cn.config.ping_int * 10)
	{
	  fprintf(stderr,"The timeout has to be smaller than "
		  "connect-int and ping-int.\n");
	  exit(20);
	}

      err=ioctl(drbd_fd,DRBD_IOCTL_SET_CONFIG,&cn);
      if(err)
	{
	  perror("ioctl() failed");
	  if(errno == EINVAL)
	    {
	      const char *etext[] = {
		"No further Information available.\n"/*NoError*/,
		"Local address(port) already in use.\n"/*LAAlreadyInUse*/,
		"Remove address(port) already in use.\n"/* OAAlreadyInUse*/,
		"Filedescriptor for lower device invalid.\n"/*LDFDInvalid*/,
		"Lower device already in use.\n"/*LDAlreadyInUse*/,
		"Lower device is not a block device.\n"/*LDNoBlockDev*/,
		"Open of lower device failed.\n"/*LDOpenFailed*/
	      };
	      int i = cn.ret_code;
	      if (i>ARRY_SIZE(etext) || i<0) i=0;
	      fprintf(stderr,etext[i]);
	    }
	}
    }
  return 0;
}
