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
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

struct drbd_cmd {
  const char* cmd;
  int (* function)(int, char**, int, struct option*);
  char **args;
  struct option *options;
};

int cmd_primary(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_secondary(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_sec_rem(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_wait_sync(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_wait_connect(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_invalidate(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_invalidate_rem(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_down(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_net_conf(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_disk_conf(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_disk_size(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_disconnect(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_show(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_syncer(int drbd_fd,char** argv,int argc,struct option *options);

struct drbd_cmd commands[] = {
  {"primary", cmd_primary,           0, 
   (struct option[]) {
     { "human",      no_argument,       0, 'h' },
     { "do-what-I-say",no_argument,     0, 'd' },
     { "timeout-expired",no_argument,   0, 't' },
     { 0,            0,                 0, 0   } } },
  {"secondary", cmd_secondary,       0, 0 },
  {"secondary_remote", cmd_sec_rem,  0, 0 },
  {"wait_sync", cmd_wait_sync,       0,
   (struct option[]) {
     { "time",       required_argument, 0, 't' },
     { 0,            0,                 0, 0   } } },
  {"wait_connect", cmd_wait_connect, 0,
   (struct option[]) {
     { "time",       required_argument, 0, 't' },
     { 0,            0,                 0, 0   } } },
  {"invalidate", cmd_invalidate,     0, 0 },
  {"invalidate_remote", cmd_invalidate_rem,0, 0 },
  {"syncer", cmd_syncer,                0,
   (struct option[]) {
     { "use-csums",  no_argument,       0, 'c' },
     { "skip-sync",  no_argument,       0, 'k' },
     { "rate",       required_argument, 0, 'r' },
     { 0,            0,                 0, 0 } } },
  {"down", cmd_down,                 0, 0 },
  {"net", cmd_net_conf, (char *[]){"local_addr","remote_addr","protocol",0}, 
   (struct option[]) {
     { "timeout",    required_argument, 0, 't' },
     { "tl-size",    required_argument, 0, 's' },
     { "connect-int",required_argument, 0, 'c' },
     { "ping-int",   required_argument, 0, 'i' },
     { 0,            0,                 0, 0 } } },
  {"disk", cmd_disk_conf,(char *[]){"lower_device",0},
   (struct option[]) {
     { "size",  required_argument,      0, 'd' }, 
     { "do-panic",   no_argument,       0, 'p' },
     { 0,            0,                 0, 0 } } },
  {"resize", cmd_disk_size,             0,
   (struct option[]) {
     { "size",  required_argument,      0, 'd' }, 
     { 0,            0,                 0, 0 } } },
  {"disconnect", cmd_disconnect,     0, 0 },
  {"show", cmd_show,                 0, 0 },
};

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

const char* make_optstring(struct option *options)
{
  static char buffer[200];
  static struct option* buffer_valid_for=NULL;
  struct option *opt;
  char *c;

  if(options==buffer_valid_for) return buffer;
  opt=buffer_valid_for=options;
  c=buffer;
  *c++='-';
  while(opt->name)
    {
      *c++=opt->val;
      if(opt->has_arg) *c++=':';
      opt++;
    }
  *c=0;
  return buffer;
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
  struct mntent* entry;


  if( ! (tab=setmntent(tab_name,"r")) )
    return 0;

  while( (entry=getmntent(tab)) ) 
    {
      if( !strcmp(entry->mnt_fsname, dev_name) )
	{
	  endmntent(tab);
	  return 1;
	}
    }

  endmntent(tab);

  return 0;
}

int already_in_use(const char* dev_name)
{        
  return already_in_use_tab(dev_name,"/etc/mtab") || 
    already_in_use_tab(dev_name,"/proc/mounts");
}

void print_usage(const char* prgname)
{
  int i;
  char **args;
  struct option *options;

  printf("\nUSAGE: %s device command arguments options\n\n"
	 "Device is usually /dev/nbX or /dev/drbd/X.\n"
         "Commands, arguments and options are:\n",prgname);
        

  for(i=0;i<ARRY_SIZE(commands);i++) 
    {
      printf(" %s",commands[i].cmd);
      if((args=commands[i].args)) 
	{
	  while(*args) printf(" %s",*args++);
	}
      if((options=commands[i].options))
	{
	  while(options->name) 
	    {
	      if(options->has_arg == required_argument) 
		printf(" [{--%s|-%c} val]",options->name,options->val);
	      else 
		printf(" [{--%s|-%c}]",options->name,options->val);
	      options++;
	    }
	}
      printf("\n");
    }
  
  printf("\nVersion: "REL_VERSION" (api:%d)\n",API_VERSION);

  exit(20);
}

int open_drbd_device(const char* device)
{
  int drbd_fd,err,version;
  struct stat drbd_stat;

  drbd_fd=open(device,O_RDONLY);
  if(drbd_fd==-1)
    {
      perror("can not open device");
      exit(20);
    }

  
  err=fstat(drbd_fd, &drbd_stat);
  if(err)
    {
      perror("fstat() failed");
    }
  if(!S_ISBLK(drbd_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", device);
      exit(20);
    }
  err=ioctl(drbd_fd,DRBD_IOCTL_GET_VERSION,&version);
  if(err)
    {
      perror("ioctl() failed");
    }
  
  if (version != API_VERSION)
    {
      fprintf(stderr,"Drbdsetup and drbd kernel module are not matching!\n");
      exit(20);
    }    

  return drbd_fd;
}

void check_state_dir(void)
{
  struct stat drbd_stat;
  if(stat(DRBD_MD_PATH,&drbd_stat))
    {
      if (errno==ENOENT) 
	{
	  fprintf(stderr,DRBD_MD_PATH " does not exists. Creating it.\n");
	  if(!mkdir(DRBD_MD_PATH,00600)) return;
	  fprintf(stderr,"Can not create " DRBD_MD_PATH "\n");
	  exit(20);
	}
      fprintf(stderr,"Something is wrong with " DRBD_MD_PATH "\n");
      exit(20);
    }
}

int scan_disk_options(char **argv,
		      int argc,
		      struct ioctl_disk_config* cn,
		      struct option *options)
{
  cn->config.disk_size = 0; /* default not known */
  cn->config.do_panic  = 0;

  if(argc==0) return 0;

  optind=0; 
  opterr=0; /* do not print error messages upon not valid options */
  while(1)
    {
      int c;
	  
      c = getopt_long(argc,argv,make_optstring(options),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 'd':
	  cn->config.disk_size = m_strtol(optarg,1024);
	  break;
	case 'p':
	  cn->config.do_panic=1;
	  break;
	case '?':
	  fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	  return 20;
	  break;
	}
    }
  return 0;
}


int scan_net_options(char **argv,
		     int argc,
		     struct ioctl_net_config* cn,
		     struct option *options)
{
  cn->config.timeout = 60; /* = 6 seconds */
  cn->config.tl_size = 256;
  cn->config.try_connect_int = 10;
  cn->config.ping_int = 10;

  if(argc==0) return 0;

  optind=0;
  opterr=0; /* do not print error messages upon not valid options */
  while(1)
    {
      int c;

      c = getopt_long(argc,argv,make_optstring(options),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 't': 
	  cn->config.timeout = m_strtol(optarg,1);
	  break;
	case 's':
	  cn->config.tl_size = m_strtol(optarg,1);
	  break;
	case 'c':
	  cn->config.try_connect_int = m_strtol(optarg,1);
	  break;
	case 'i':
	  cn->config.ping_int = m_strtol(optarg,1);
	  break;
	case '?':
	  fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	  return 20;
	  break;
	}
    }

  /* sanity checks of the timeouts */
  
  if(cn->config.timeout >= cn->config.try_connect_int * 10 ||
     cn->config.timeout >= cn->config.ping_int * 10)
    {
      fprintf(stderr,"The timeout has to be smaller than "
	      "connect-int and ping-int.\n");
      return 20;
    }
  return 0;
}

void print_config_ioctl_err(int err_no) 
{
  const char *etext[] = {
    [NoError]="No further Information available.",
    [LAAlreadyInUse]="Local address(port) already in use.",
    [OAAlreadyInUse]="Remove address(port) already in use.",
    [LDFDInvalid]="Filedescriptor for lower device is invalid.",
    [LDAlreadyInUse]="Lower device already in use.",
    [LDNoBlockDev]="Lower device is not a block device.",
    [LDOpenFailed]="Open of lower device failed.",
    [LDDeviceTooSmall]="Low.dev. smaller than requested DRBD-dev. size.",
    [LDNoConfig]="You have to use the disk command first.",
    [LDMounted]="Lower device is already mounted."
  };

  if (err_no>ARRY_SIZE(etext) || err_no<0) err_no=0;
  fprintf(stderr,"%s\n",etext[err_no]);
}

int do_disk_conf(int drbd_fd,
		 const char* lower_dev_name,
		 struct ioctl_disk_config* cn)
{
  int lower_device,err;
  struct stat lower_stat;

  if(already_in_use(lower_dev_name))
    {
      fprintf(stderr,"Lower device (%s) is already mounted\n",lower_dev_name);
      return 20;
    }

  if((lower_device = open(lower_dev_name,O_RDWR))==-1)
    {
      perror("Can not open lower device");
      return 20;
    }

      /* Check if the device is a block device */
  err=fstat(lower_device, &lower_stat);
  if(err)
    {
      perror("fstat() failed");
      return 20;
    }
  if(!S_ISBLK(lower_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", lower_dev_name);
      return 20;
    }

  cn->config.lower_device=lower_device;

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_DISK_CONFIG,cn);
  if(err)
    {
      err=errno;
      perror("ioctl() failed");
      if(err == EINVAL) print_config_ioctl_err(cn->ret_code);
      return 20;
    }
  return 0;
}


int do_net_conf(int drbd_fd,
		const char* proto,
		const char* local_addr,
		const char* remote_addr,
		struct ioctl_net_config* cn)
{
  struct sockaddr_in *other_addr;
  struct sockaddr_in *my_addr;
  int err;

  if(proto[1] != 0) 
    {
      fprintf(stderr,"Invalid protocol specifier.\n");
      return 20;
    }
  switch(proto[0])
    {
    case 'a':
    case 'A':
      cn->config.wire_protocol = DRBD_PROT_A;
      break;
    case 'b':
    case 'B':
      cn->config.wire_protocol = DRBD_PROT_B;
      break;
    case 'c':
    case 'C':
      cn->config.wire_protocol = DRBD_PROT_C;
      break;
    default:	  
      fprintf(stderr,"Invalid protocol specifier.\n");
      return 20;
    }

  cn->config.my_addr_len = sizeof(struct sockaddr_in);
  my_addr = (struct sockaddr_in *)cn->config.my_addr;
  my_addr->sin_port = htons(port_part(local_addr));
  my_addr->sin_family = AF_INET;
  my_addr->sin_addr.s_addr = resolv(addr_part(local_addr));
  
  cn->config.other_addr_len = sizeof(struct sockaddr_in);
  other_addr = (struct sockaddr_in *)cn->config.other_addr;
  other_addr->sin_port = htons(port_part(remote_addr));
  other_addr->sin_family = AF_INET;
  other_addr->sin_addr.s_addr = resolv(addr_part(remote_addr));

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_NET_CONFIG,cn);
  if(err)
    {
      err=errno;
      perror("ioctl() failed");
      if(err == EINVAL) print_config_ioctl_err(cn->ret_code);
      return 20;
    }
  return 0;
}



int set_state(int drbd_fd,Drbd_State state)
{
  int err;
  err=ioctl(drbd_fd,DRBD_IOCTL_SET_STATE,state);
  if(err) {
    err=errno;
    perror("ioctl() failed");
    switch(err)
      {
      case EBUSY:
	fprintf(stderr,"Someone has opened the device for RW access!\n");
	break;
      case EINPROGRESS:
	fprintf(stderr,"Resynchronization process currently running!\n");
	break;
      case ENXIO:
	fprintf(stderr,"Device not configured\n");
	break;
      case EACCES:
	fprintf(stderr,"Partner is already primary\n");
	break;
      case EIO:
	fprintf(stderr,"Local replica is inconsistent (--do-what-I-say ?)\n");
	return 21;
      default:
      }
    return 20;
  }
  return 0;
}


int cmd_primary(int drbd_fd,char** argv,int argc,struct option *options)
{
  Drbd_State newstate=Primary;

  optind=0; 
  if(argc > 0) 
    {
      while(1)
	{
	  int c;
	  
	  c = getopt_long(argc+1,argv-1,make_optstring(options),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 'h': 
	      newstate |= Human;
	      break;
	    case 'd':
	      newstate |= DontBlameDrbd;
	      break;
	    case 't':
	      newstate |= TimeoutExpired;
	      break;
	    case '?':
	      fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	      return 20;
	      break;
	    }
	}
    }
  
  return set_state(drbd_fd,newstate);
}

int cmd_secondary(int drbd_fd,char** argv,int argc,struct option *options)
{
  return set_state(drbd_fd,Secondary);
}

int cmd_sec_rem(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;
  err=ioctl(drbd_fd,DRBD_IOCTL_SECONDARY_REM);
  if(err) 
    {
      err=errno;
      perror("ioctl() failed");
      if(err==ENXIO)
	fprintf(stderr,"Not connected to remote DRBD device!\n");
    
      if(err==ESRCH) 
	{
	  fprintf(stderr,"remote DRBD device is already in Secondary state\n");
	  return 1;
	}
      return 20;
    }
  return 0;
}

int wait_on(int drbd_fd,char** argv,int argc,int def_time, int req,
	    struct option *options)
{
  int err,retval;

  optind=0; 
  retval=def_time;
  if(argc > 0) 
    {
      while(1)
	{
	  int c;
	  
	  c = getopt_long(argc+1,argv-1,make_optstring(options),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 't': 
	      retval = m_strtol(optarg,1);
	      break;
	    case '?':
	      fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	      return 20;
	      break;
	    }
	}
    }
  err=ioctl(drbd_fd,req,&retval);
  if(err)
    {
      perror("ioctl() failed");
      exit(20);
    }
  return !retval;
}

int cmd_wait_connect(int drbd_fd,char** argv,int argc,struct option *options)
{
  return wait_on(drbd_fd,argv,argc,0,DRBD_IOCTL_WAIT_CONNECT,options);
}

int cmd_wait_sync(int drbd_fd,char** argv,int argc,struct option *options)
{
  return wait_on(drbd_fd,argv,argc,8,DRBD_IOCTL_WAIT_SYNC,options);
}

int cmd_syncer(int drbd_fd,char** argv,int argc,struct option *options)
{
  struct ioctl_syncer_config cn;
  struct ioctl_get_config current_cn;
  int err;  

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&current_cn);
  if(err)
    {
      perror("ioctl() failed");
      return 20;
    }

  cn.config.rate = current_cn.sconf.rate;
  cn.config.use_csums = 0; //current_cn.sconf.use_csums;
  cn.config.skip = 0; //current_cn.sconf.skip;

  optind=0; 
  opterr=0; /* do not print error messages upon not valid options */
  if(argc > 0) 
    {
      while(1)
	{
	  int c;
	  
	  c = getopt_long(argc+3,argv-3,make_optstring(options),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 'c': 
	      cn.config.use_csums=1;
	      break;
	    case 'k':
  	      cn.config.skip=1;
	      break;
	    case 'r':
	      cn.config.rate=m_strtol(optarg,1024);
	      break;
	    case '?':
	      fprintf(stderr,"Unknown option %s\n",argv[optind-4]);
	      return 20;
	      break;
	    }
	}
    }

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_SYNC_CONFIG,&cn);
  if(err)
    {
      perror("DRBD_IOCTL_SET_SYNC_CONFIG ioctl() failed");
      return 20;
    }

  return 0;
}

int cmd_invalidate(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_INVALIDATE);
  if(err)
    {
      err=errno;
      perror("ioctl() failed");
      if(err==EINPROGRESS)
	fprintf(stderr,"Can not start resynchronisation. Already running\n");
      if(err==ENXIO)
	fprintf(stderr,"Can not start resynchronisation. Not connected\n");
      return 20;
    }
  return 0;  
}

int cmd_invalidate_rem(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_INVALIDATE_REM);
  if(err)
    {
      err=errno;
      perror("ioctl() failed");
      if(err==EINPROGRESS)
	fprintf(stderr,"Can not start resynchronisation. Already running\n");
      if(err==ENXIO)
	fprintf(stderr,"Can not start resynchronisation. Not connected\n");
      return 20;
    }
  return 0;  
}

int cmd_down(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_UNCONFIG_BOTH);
  if(err)
    {
      err=errno;
      perror("ioctl() failed");
      if(err==ENXIO)
	fprintf(stderr,"Device is not configured!\n");
      if(err==EBUSY)
	fprintf(stderr,"Someone has opened the device!\n");
      return 20;
    }
  return 0;
}

int cmd_disconnect(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_UNCONFIG_NET);
  if(err)
    {
      err=errno;
      perror("ioctl() failed");
      if(err==ENXIO)
	fprintf(stderr,"Device is not configured!\n");
      return 20;
    }
  return 0;

}     

int cmd_net_conf(int drbd_fd,char** argv,int argc,struct option *options)
{
  struct ioctl_net_config cn;
  int retval;

  retval=scan_net_options(argv+2,argc-2,&cn,options);
  if(retval) return retval;

  return do_net_conf(drbd_fd,argv[2],argv[0],argv[1],&cn);
}

int cmd_disk_conf(int drbd_fd,char** argv,int argc,struct option *options)
{
  struct ioctl_disk_config cn;
  int retval;

  retval=scan_disk_options(argv,argc,&cn,options);
  if(retval) return retval;

  return do_disk_conf(drbd_fd,argv[0],&cn);
}

int cmd_disk_size(int drbd_fd,char** argv,int argc,struct option *options)
{
  unsigned long u_size=0;
  int err;

  optind=0; 
  opterr=0; /* do not print error messages upon not valid options */
  if(argc > 0) 
    {
      while(1)
	{
	  int c;
	  
	  c = getopt_long(argc+3,argv-3,make_optstring(options),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 'd': 
	      u_size=m_strtol(optarg,1024);
	      break;
	    case '?':
	      fprintf(stderr,"Unknown option %s\n",argv[optind-4]);
	      return 20;
	      break;
	    }
	}
    }

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_DISK_SIZE,u_size);
  if(err)
    {
      perror("DRBD_IOCTL_SET_DISK_SIZE ioctl() failed");
      return 20;
    }

  return 0;
}

const char* guess_dev_name(const char* dir,int major,int minor)
{
  DIR* device_dir;
  struct dirent* dde;
  struct stat sb;
  static char dev_name[50];

  device_dir=opendir(dir);

  if(!device_dir) goto err_out;

  while((dde=readdir(device_dir))) 
    {
      snprintf(dev_name,50,"%s/%s",dir,dde->d_name);
      if(stat(dev_name,&sb)) continue;

      if(S_ISBLK(sb.st_mode)) 
	{
	  if (major == (int)(sb.st_rdev & 0xff00) >> 8 &&
	      minor == (int)(sb.st_rdev & 0x00ff) )
	    {
	      closedir(device_dir);
	      return dev_name;
	    }
	}
    }

  rewinddir(device_dir);

  while((dde=readdir(device_dir))) 
    {
      snprintf(dev_name,50,"%s/%s",dir,dde->d_name);
      if(stat(dev_name,&sb)) continue;
      
      if(!strcmp(dde->d_name,".")) continue;
      if(!strcmp(dde->d_name,"..")) continue;
      if(!strcmp(dde->d_name,"fd")) continue;
      
      if(S_ISDIR(sb.st_mode)) 
	{
	  char subdir[50];
	  
	  if(snprintf(subdir,50,"%s/%s",dir,dde->d_name)==49) 
	    { /* recursion is too deep */
	      strcpy(dev_name,"can not guess name");
	      return dev_name;
	    }
	  
	  if(guess_dev_name(subdir,major,minor)) return dev_name;
	}
    }

  closedir(device_dir);
 err_out:
  return NULL;
}

int cmd_show(int drbd_fd,char** argv,int argc,struct option *options)
{
  struct ioctl_get_config cn;
  struct sockaddr_in *other_addr;
  struct sockaddr_in *my_addr;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&cn);
  if(err)
    {
      perror("ioctl() failed");
      return 20;
    }

  if( cn.cstate < StandAlone )
    {
      printf("Not configured\n");
      return 0;
    }

  printf("Lower device: %02d:%02d   (%s)\n",
	 cn.lower_device_major,
	 cn.lower_device_minor,
	 guess_dev_name("/dev",cn.lower_device_major,cn.lower_device_minor));
  printf("Disk options:\n");
  if( cn.disk_size_user ) printf(" disk-size = %d KB\n",cn.disk_size_user);
  if( cn.do_panic ) printf(" do-panic\n");

  if( cn.cstate < Unconnected ) return 0;

  my_addr = (struct sockaddr_in *)cn.nconf.my_addr;
  other_addr = (struct sockaddr_in *)cn.nconf.other_addr;
  printf("Local address: %s:%d\n",
	 inet_ntoa(my_addr->sin_addr),
	 ntohs(my_addr->sin_port));
  printf("Remote address: %s:%d\n",
	 inet_ntoa(other_addr->sin_addr),
	 ntohs(other_addr->sin_port));
  printf("Wire protocol: %c\n",'A'-1+cn.nconf.wire_protocol); 
  printf("Net options:\n");
  if( cn.nconf.timeout ) 
    printf(" timeout = %d.%d sec\n",cn.nconf.timeout/10,cn.nconf.timeout%10);
  if( cn.nconf.tl_size ) printf(" tl-size = %d\n",cn.nconf.tl_size);
  if( cn.nconf.try_connect_int ) 
    printf(" connect-int = %d sec\n",cn.nconf.try_connect_int);
  if( cn.nconf.ping_int ) printf(" ping-int = %d sec\n",cn.nconf.ping_int);

  printf("Syncer options:\n");
  printf(" rate = %d KB/sec\n",cn.sconf.rate);
  if( cn.sconf.skip ) printf(" skip-sync\n");
  if( cn.sconf.use_csums ) printf(" use-csums\n");

  return 0;
}

int main(int argc, char** argv)
{
  int drbd_fd,i;
  int num_of_args;
  char **args;

  if(argc < 3) print_usage(argv[0]);

  chdir("/");

  drbd_fd=open_drbd_device(argv[1]);
  check_state_dir();

  for(i=0;i<ARRY_SIZE(commands);i++) 
    {
      if(strcmp(argv[2],commands[i].cmd)==0)
	{
	  num_of_args=0;
	  if((args=commands[i].args))
	    {
	      while(*args++) num_of_args++; 
	    }
	  if (argc-3 < num_of_args) print_usage(argv[0]);
	  if (argc-3-num_of_args>0 && commands[i].options==0) 
	    {
	      fprintf(stderr,"Too many arguments or options.\n");
	      return 20;
	    }
	  return commands[i].function(drbd_fd,argv+3,argc-3,
				      commands[i].options);
	}
    }
  fprintf(stderr,"%s is not a command\n",argv[2]);
  return 20;
}
