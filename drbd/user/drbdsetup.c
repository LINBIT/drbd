/*
   drbdsetup.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2003, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
        Added sanity checks before using the device.

   Copyright (C) 2002-2003, Lars Ellenberg <l.g.e@web.de>
	main contributor.

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
#include <linux/drbd.h>
#include <linux/drbd_config.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

/* Default values */
#define DEF_NET_TIMEOUT             60      //  6 seconds
#define DEF_NET_TRY_CON_I           10      // 10 seconds
#define DEF_NET_PING_I              10      // 10 seconds
#define DEF_SYNC_RATE              250
#define DEF_SYNC_GROUP               0
#define DEF_WFC_TIMEOUT              0      // forever
#define DEF_DEGR_WFC_TIMEOUT        60      // 60 Seconds
#define DEF_SYNC_WFC_TIMEOUT         8      // 8 seconds
#define DEF_SYNC_DEGR_WFC_TIMEOUT    4      // 4 seconds
#define DEF_SYNC_AL_EXTENTS        127
#define DEF_MAX_EPOCH_SIZE        2048      // entries
#define DEF_MAX_BUFFERS           2048      // entries
#define DEF_SNDBUF_SIZE           (2*65535) // ~128KB
#define DEF_DISK_SIZE                0
#define DEF_ON_IO_ERROR         PassOn

#if 0
# define ioctl(X...) (fprintf(stderr,"ioctl(%s)\n",#X),0);
# define PRINT_ARGV do { \
	int i; \
		fprintf(stderr,"# argv (optind=%i argc=%i) in %s:%i:\n#",\
			optind, argc, __FUNCTION__, __LINE__); \
		for (i=optind; i < argc; i++) \
			fprintf(stderr," %s",argv[i]); \
				fprintf(stderr,"\n"); \
} while(0)
#else
# define PRINT_ARGV
#endif

#define PERROR(fmt, args...) \
do { fprintf(stderr,fmt ": ", ##args); perror(0); } while (0)


// some globals
char* basename = 0;

struct drbd_cmd {
  const char* cmd;
  int (* function)(int, char**, int, struct option*);
  char **args;
  struct option *options;
};

int cmd_primary(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_secondary(int drbd_fd,char** argv,int argc,struct option *options);
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
int cmd_detach(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_state(int drbd_fd,char** argv,int argc,struct option *options);

struct drbd_cmd commands[] = {
  {"primary", cmd_primary,           0,
   (struct option[]) {
     { "human",      no_argument,       0, 'h' },
     { "do-what-I-say",no_argument,     0, 'd' },
     { "timeout-expired",no_argument,   0, 't' },
     { 0,            0,                 0, 0   } } },
  {"secondary", cmd_secondary,       0, 0, },
  {"wait_sync", cmd_wait_sync,       0,
   (struct option[]) {
     { "time",       required_argument, 0, 't' },
     { 0,            0,                 0, 0   } } },
  {"wait_connect", cmd_wait_connect, 0,
   (struct option[]) {
     { "wfc-timeout",required_argument, 0, 't' },
     { "degr-wfc-timeout",required_argument,0,'d'},
     { 0,            0,                 0, 0   } } },
  {"invalidate", cmd_invalidate,     0, 0, },
  {"invalidate_remote", cmd_invalidate_rem,0, 0, },
  {"syncer", cmd_syncer,                0,
   (struct option[]) {
     { "use-csums",  no_argument,       0, 'c' },
     { "skip-sync",  no_argument,       0, 'k' },
     { "group",      required_argument, 0, 'g' },
     { "rate",       required_argument, 0, 'r' },
     { "al-extents", required_argument, 0, 'e' },
     { 0,            0,                 0, 0 } } },
  {"down", cmd_down,                 0, 0, },
  {"detach", cmd_detach,             0, 0, },
  {"net", cmd_net_conf, (char *[]){"local_addr","remote_addr","protocol",0},
   (struct option[]) {
     { "timeout",    required_argument, 0, 't' },
     { "max-epoch-size", required_argument, 0, 'e' },
     { "max-buffers",required_argument, 0, 'b' },
     { "connect-int",required_argument, 0, 'c' },
     { "ping-int",   required_argument, 0, 'i' },
     { "sndbuf-size",required_argument, 0, 'S' },
     { 0,            0,                 0, 0 } } },
  {"disk", cmd_disk_conf,(char *[]){"lower_dev","meta_data_dev",
				    "meta_data_index",0},
   (struct option[]) {
     { "size",       required_argument, 0, 'd' },
     { "on-io-error",required_argument, 0, 'e' },
     { 0,            0,                 0, 0 } } },
  {"resize", cmd_disk_size,             0,
   (struct option[]) {
     { "size",  required_argument,      0, 'd' },
     { 0,            0,                 0, 0 } } },
  {"disconnect", cmd_disconnect,     0, 0, },
  {"state", cmd_state,               0, 0, },
  {"show", cmd_show,                 0, 0, }
};

const char *eh_names[] = {
  [PassOn] = "pass_on",
  [Panic]  = "panic",
  [Detach] = "detach" 
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
	  PERROR("can not resolv the hostname");
	  exit(20);
	}
      retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
    }
  return retval;
}

unsigned long m_strtol(const char* s,int def_mult)
{
  char *e = (char*)s;
  unsigned long r;

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

void print_command_usage(int i, const char *addinfo)
    // CAUTION no range check for i
{
  char **args;
  struct option *options;
#define  maxcol 70 // plus initial tab ...
  static char line[maxcol+1];
  int col,prevcol;

  prevcol=col=0;

  col += snprintf(line+col, maxcol-col, " %s", commands[i].cmd);
  if ((args = commands[i].args)) {
    while (*args)
      col += snprintf(line+col, maxcol-col, " %s", *args++);
  }
  if (col > maxcol) {
    printf("%s\n\t",line);
    col=0;
  }
  prevcol=col;
  if ((options = commands[i].options)) {
    while (options->name) {
      if (options->has_arg == required_argument) {
	col += snprintf(line+col, maxcol-col, " [{--%s|-%c} val]",
			options->name, options->val);
      } else {
	col += snprintf(line+col, maxcol-col, " [{--%s|-%c}]",
			options->name, options->val);
      }
      if (col >= maxcol) {
	line[prevcol]=0;
	printf("%s\n\t",line);
	prevcol=col=0;
      } else {
	prevcol=col;
	options++;
      }
    }
  }
  line[col]=0;
  printf("%s\n",line);
  if (addinfo) {
      printf("%s\n",addinfo);
      exit(20);
  }
}

void print_usage(const char* addinfo)
{
  int i;

  printf("\nUSAGE: %s device command arguments options\n\n"
	 "Device is usually /dev/nbX or /dev/drbd/X.\n"
         "Commands, arguments and options are:\n",basename);


  for (i = 0; i < ARRY_SIZE(commands); i++)
    print_command_usage(i, 0);

  printf("\nAvailable on-io-error handlers:");
  for(i=0;i<ARRY_SIZE(eh_names);i++) {
    printf(" %s",eh_names[i]);
    if(i < ARRY_SIZE(eh_names)-1) printf(",");
  }

  printf("\n\nVersion: "REL_VERSION" (api:%d)\n",API_VERSION);
  if (addinfo)
      printf("\n%s\n",addinfo);

  exit(20);
}

int open_drbd_device(const char* device)
{
  int drbd_fd,err,version;
  struct stat drbd_stat;

  drbd_fd=open(device,O_RDONLY);
  if(drbd_fd==-1)
    {
      PERROR("can not open %s", device);
      exit(20);
    }


  err=fstat(drbd_fd, &drbd_stat);
  if(err)
    {
      PERROR("fstat(%s) failed",device);
    }
  if(!S_ISBLK(drbd_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", device);
      exit(20);
    }
  err=ioctl(drbd_fd,DRBD_IOCTL_GET_VERSION,&version);
  if(err)
    {
      PERROR("ioctl(,GET_VERSION,) failed");
      exit(20);
    }

  if (version != API_VERSION)
    {
      fprintf(stderr,"\tVersion tags of drbdsetup and drbd kernel module are not matching!\n"
		     "\tAPI_VERSION: drbdsetup:%d -- drbd module:%d\n"
		     "\tPlease check your installation!\n", API_VERSION, version);
      exit(20);
    }

  return drbd_fd;
}

int scan_disk_options(char **argv,
		      int argc,
		      struct ioctl_disk_config* cn,
		      struct option *options)
{
  cn->config.disk_size = 0; /* default not known */
  cn->config.on_io_error = DEF_ON_IO_ERROR;

  if(argc==0) return 0;

  while(1)
    {
      int c,i;

      PRINT_ARGV;
      next_option:
      c = getopt_long(argc,argv,make_optstring(options),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 'd':
	  cn->config.disk_size = m_strtol(optarg,1024);
	  break;
	case 'e':
	  for(i=0;i<ARRY_SIZE(eh_names);i++) {
	    if (strcmp(optarg,eh_names[i])==0) {
	      cn->config.on_io_error=i;
	      goto next_option;
	    }
	  }
	  fprintf(stderr,"%s: '%s' is an invalid on-io-error handler.\n",
		  basename,optarg);
	  return 20;
	case 1:	// non option argument. see getopt_long(3)
	  fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",basename,optarg);
	case '?':
	  return 20;
	}
    }
  return 0;
}

int scan_net_options(char **argv,
		     int argc,
		     struct ioctl_net_config* cn,
		     struct option *options)
{
  cn->config.timeout = DEF_NET_TIMEOUT;
  cn->config.try_connect_int = DEF_NET_TRY_CON_I;
  cn->config.ping_int = DEF_NET_PING_I;
  cn->config.max_epoch_size = DEF_MAX_EPOCH_SIZE;
  cn->config.max_buffers = DEF_MAX_BUFFERS;
  cn->config.sndbuf_size = DEF_SNDBUF_SIZE ;


  if(argc==0) return 0;

  while(1)
    {
      int c;

      PRINT_ARGV;
      c = getopt_long(argc,argv,make_optstring(options),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 't':
	  cn->config.timeout = m_strtol(optarg,1);
	  break;
	case 'e':
	  cn->config.max_epoch_size = m_strtol(optarg,1);
	  break;
	case 'b':
	  cn->config.max_buffers = m_strtol(optarg,1);
	  break;
	case 'c':
	  cn->config.try_connect_int = m_strtol(optarg,1);
	  break;
	case 'i':
	  cn->config.ping_int = m_strtol(optarg,1);
	  break;
	case 'S':
	  cn->config.sndbuf_size = m_strtol(optarg,1);
	  break;
	case 1:	// non option argument. see getopt_long(3)
	  fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",basename,optarg);
	case '?':
	  return 20;
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
    [OAAlreadyInUse]="Remote address(port) already in use.",
    [LDFDInvalid]="Filedescriptor for lower device is invalid.",
    [MDFDInvalid]="Filedescriptor for meta device is invalid.",
    [LDAlreadyInUse]="Lower device already in use.",
    [LDNoBlockDev]="Lower device is not a block device.",
    [MDNoBlockDev]="Meta device is not a block device.",
    [LDOpenFailed]="Open of lower device failed.",
    [MDOpenFailed]="Open of meta device failed.",
    [LDDeviceTooSmall]="Low.dev. smaller than requested DRBD-dev. size.",
    [MDDeviceTooSmall]="Meta device too small.",
    [LDNoConfig]="You have to use the disk command first.",
    [LDMounted]="Lower device is already mounted.",
    [MDMounted]="Meta device is already mounted.",
    [LDMDInvalid]="Lower device / meta device / index combination invalid."
  };

  if (err_no>ARRY_SIZE(etext) || err_no<0) err_no=0;
  fprintf(stderr,"%s\n",etext[err_no]);
}

int check_if_blk_dev(int fd,const char* dev_name)
{
  struct stat lower_stat;
  int err;

  err=fstat(fd, &lower_stat);
  if(err)
    {
      PERROR("fstat(%s) failed", dev_name);
      return 20;
    }
  if(!S_ISBLK(lower_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", dev_name);
      return 20;
    }

  return 0;
}

int do_disk_conf(int drbd_fd,
		 const char* lower_dev_name,
		 const char* meta_dev_name,
		 struct ioctl_disk_config* cn)
{
  int lower_device,meta_device,err;

  if(already_in_use(lower_dev_name))
    {
      fprintf(stderr,"Lower device (%s) is already mounted\n",lower_dev_name);
      return 20;
    }

  if((lower_device = open(lower_dev_name,O_RDWR))==-1)
    {
      PERROR("Can not open lower device '%s'", lower_dev_name);
      return 20;
    }

  err = check_if_blk_dev(lower_device,lower_dev_name);
  if(err) return err;

  if(!strcmp(meta_dev_name,"internal")) {
    meta_dev_name = lower_dev_name;
  }

  if((meta_device = open(meta_dev_name,O_RDWR))==-1)
    {
      PERROR("Can not open meta data device '%s'", meta_dev_name);
      return 20;
    }

  err = check_if_blk_dev(meta_device,meta_dev_name);
  if(err) return err;

  cn->config.lower_device=lower_device;
  cn->config.meta_device=meta_device;

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_DISK_CONFIG,cn);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,SET_DISK_CONFIG,) failed");
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
      fprintf(stderr,"Invalid protocol specifier '%s'.\n",proto);
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
      fprintf(stderr,"Invalid protocol specifier '%s'.\n",proto);
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
      PERROR("ioctl(,SET_NET_CONFIG,) failed");
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
    PERROR("ioctl(,SET_STATE,) failed");
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
      }
    return 20;
  }
  return 0;
}


int cmd_primary(int drbd_fd,char** argv,int argc,struct option *options)
{
  Drbd_State newstate=Primary;

  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  c = getopt_long(argc,argv,make_optstring(options),options,0);
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
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",basename,optarg);
	    case '?':
	      return 20;
	    }
	}
    }

  return set_state(drbd_fd,newstate);
}

int cmd_secondary(int drbd_fd,char** argv,int argc,struct option *options)
{
  return set_state(drbd_fd,Secondary);
}

int wait_on(int drbd_fd,char** argv,int argc,int wfct,int dwfct, int req,
	    struct option *options)
{
  int err;
  struct ioctl_wait p;

  p.wfc_timeout=wfct;
  p.degr_wfc_timeout=dwfct;

  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  c = getopt_long(argc,argv,make_optstring(options),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 't':
	      p.wfc_timeout = m_strtol(optarg,1);
	      break;
	    case 'd':
	      p.degr_wfc_timeout = m_strtol(optarg,1);
	      break;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",basename,optarg);
	    case '?':
	      return 20;
	    }
	}
    }
  err=ioctl(drbd_fd,req,&p);
  if(err)
    {
      PERROR("ioctl(,WAIT_*,) failed");
      exit(20);
    }
  return !p.ret_code;
}

int cmd_wait_connect(int drbd_fd,char** argv,int argc,struct option *options)
{
  return wait_on(drbd_fd,argv,argc,
		 DEF_WFC_TIMEOUT,
		 DEF_DEGR_WFC_TIMEOUT,
		 DRBD_IOCTL_WAIT_CONNECT,options);
}

int cmd_wait_sync(int drbd_fd,char** argv,int argc,struct option *options)
{
  return wait_on(drbd_fd,argv,argc,
		 DEF_SYNC_WFC_TIMEOUT,
		 DEF_SYNC_DEGR_WFC_TIMEOUT,
		 DRBD_IOCTL_WAIT_SYNC,options);
}

int cmd_syncer(int drbd_fd,char** argv,int argc,struct option *options)
{
  struct ioctl_syncer_config cn;
  struct ioctl_get_config current_cn;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&current_cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

  cn.config.rate = current_cn.sconf.rate;
  cn.config.group = current_cn.sconf.group;
  cn.config.al_extents = current_cn.sconf.al_extents;
  cn.config.use_csums = 0; //current_cn.sconf.use_csums;
  cn.config.skip = 0; //current_cn.sconf.skip;

  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  c = getopt_long(argc,argv,make_optstring(options),options,0);
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
	    case 'g':
	      cn.config.group=m_strtol(optarg,1);
	      break;
	    case 'e':
	      cn.config.al_extents=m_strtol(optarg,1);
	      break;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",basename,optarg);
	    case '?':
	      return 20;
	    }
	}
    }


  if (cn.config.al_extents < 7)
	cn.config.al_extents = 127;

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_SYNC_CONFIG,&cn);
  if(err)
    {
      PERROR("ioctl(,SET_SYNC_CONFIG,) failed");
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
      PERROR("ioctl(,INVALIDATE,) failed");
      if(err==EINPROGRESS)
	fprintf(stderr,"Only in 'Connected' cstate possible.\n");
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
      PERROR("ioctl(,INVALIDATE_REM,) failed");
      if(err==EINPROGRESS)
	fprintf(stderr,"Only in 'Connected' cstate possible.\n");
      return 20;
    }
  return 0;
}

int cmd_down(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;
  err = cmd_secondary(drbd_fd,argv,argc,options);
  if (!err) err = cmd_disconnect(drbd_fd,argv,argc,options);
  if (!err) err = cmd_detach(drbd_fd,argv,argc,options);
  return err;
}

int cmd_detach(int drbd_fd,char** argv,int argc,struct option *options)
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_UNCONFIG_DISK);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,UNCONFIG_DISK,) failed");
      if(err==EBUSY)
	fprintf(stderr,"Not possible during resynchronisation.\n");
      if(err==ENETRESET)
	fprintf(stderr,"Not possible, since the device is in primary state\n"
		"and not connected.\n");
      if(err==ENODATA)
	fprintf(stderr,"Not possible, since the device is in primary state\n"
		"and has no local disk.\n");
      if(err==ENXIO)
	fprintf(stderr," - Do not shoot yourself in the foot. -\n"
		"A system without backing storage is not possible.\n");
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
      PERROR("ioctl(,UNCONFIG_NET,) failed");
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

  retval=scan_net_options(argv,argc,&cn,options);
  if(retval) return retval;

  return do_net_conf(drbd_fd,argv[5],argv[3],argv[4],&cn);
}

int cmd_disk_conf(int drbd_fd,char** argv,int argc,struct option *options)
{
  struct ioctl_disk_config cn;
  int retval,mi;


  retval=scan_disk_options(argv,argc,&cn,options);
  if(retval) return retval;

  mi = m_strtol(argv[5],1);
  if( mi < -1 ) {
    fprintf(stderr,"meta_index may not be smaller than -1.\n");
    return 20;    
  }
  //TODO check that mi*128M is not bigger than meta device!
  cn.config.meta_index = mi;

  return do_disk_conf(drbd_fd,argv[3],argv[4],&cn);
}

int cmd_disk_size(int drbd_fd,char** argv,int argc,struct option *options)
{
  unsigned long u_size=0;
  int err;

  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  c = getopt_long(argc,argv,make_optstring(options),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 'd':
	      u_size=m_strtol(optarg,1024);
	      break;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",basename,optarg);
	    case '?':
	      return 20;
	    }
	}
    }

  fprintf(stderr,"err=ioctl(drbd_fd,DRBD_IOCTL_SET_DISK_SIZE,%lu);\n",u_size);
  err=ioctl(drbd_fd,DRBD_IOCTL_SET_DISK_SIZE,u_size);
  if(err)
    {
      PERROR("ioctl(,SET_DISK_SIZE,) failed");
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
      PERROR("ioctl(,GET_CONFIG,) failed");
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
  if( cn.lower_device_major == cn.meta_device_major && 
       cn.lower_device_minor == cn.meta_device_minor ) {
    printf("Meta device: internal\n");
  } else {
    printf("Meta device: %02d:%02d   (%s)\n",
	   cn.meta_device_major,
	   cn.meta_device_minor,
	   guess_dev_name("/dev",cn.meta_device_major,cn.meta_device_minor));
    printf("Meta index: %d\n",cn.meta_index);
  }

  printf("Disk options:\n");
  if( cn.disk_size_user ) printf(" size = %d KB\n",cn.disk_size_user);
  if( cn.on_io_error != DEF_ON_IO_ERROR) {
    printf(" on-io-error = %s\n",eh_names[cn.on_io_error]);
  }

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
  printf(" timeout = %d.%d sec %s\n",cn.nconf.timeout/10,cn.nconf.timeout%10,
	 cn.nconf.timeout == DEF_NET_TIMEOUT ? "(default)" : "" );

#define SHOW_I(T,U,M,D) printf(" " T " = %d " U " %s\n", M, M == D ? "(default)" : "")

  SHOW_I("connect-int","sec", cn.nconf.try_connect_int, DEF_NET_TRY_CON_I);
  SHOW_I("ping-int","sec", cn.nconf.ping_int, DEF_NET_PING_I);
  SHOW_I("max-epoch-size","", cn.nconf.max_epoch_size, DEF_MAX_EPOCH_SIZE);
  SHOW_I("max-buffers","", cn.nconf.max_buffers, DEF_MAX_BUFFERS);
  SHOW_I("sndbuf-size","", cn.nconf.sndbuf_size, DEF_SNDBUF_SIZE);


  printf("Syncer options:\n");

  SHOW_I("rate","KB/sec", cn.sconf.rate, DEF_SYNC_RATE);
  SHOW_I("group","", cn.sconf.group, DEF_SYNC_GROUP);
  SHOW_I("al-extents","", cn.sconf.al_extents, DEF_SYNC_AL_EXTENTS);

  if( cn.sconf.skip ) printf(" skip-sync\n");
  if( cn.sconf.use_csums ) printf(" use-csums\n");

  return 0;
}

int cmd_state(int drbd_fd,char** argv,int argc,struct option *options)
{
  static const char *state_names[] = {
    [Primary]   = "Primary",
    [Secondary] = "Secondary",
    [Unknown]   = "Unknown"
  };

  struct ioctl_get_config cn;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

  if( cn.cstate < StandAlone )
    {
      printf("Not configured\n");
      return 0;
    }

  printf("%s/%s\n",state_names[cn.state],state_names[cn.peer_state]);

  return 0;
}

int main(int argc, char** argv)
{
  int drbd_fd,i;
  int num_of_args;
  int help = 0;
  char **args;

  if ( (basename = strrchr(argv[0],'/')) )
      argv[0] = ++basename;
  else
      basename = argv[0];

  if (argc > 1 && !strcmp(argv[1],"help")) help = 1;
  if (argc < 3) print_usage(argc==1 ? 0 : " Insufficient arguments");

  chdir("/");

  for(i=0;i<ARRY_SIZE(commands);i++)
    {
      if(strcmp(argv[2],commands[i].cmd)==0)
	{
	  num_of_args=0;
	  if((args=commands[i].args))
	    {
	      while(*args++) num_of_args++;
	    }
	  if (help || argc-3 < num_of_args)
	      print_command_usage(i,help?"":"Not enough arguments.");
	  if (argc-3-num_of_args>0 && commands[i].options==0)
	    {
	      fprintf(stderr,"Too many arguments or options.\n");
	      return 20;
	    }

	  drbd_fd=open_drbd_device(argv[1]);

	  opterr = 1; /* let getopt() print error messages */
	  optind = 3+num_of_args;
	  return commands[i].function(drbd_fd,argv,argc,
				      commands[i].options);
	}
    }
  fprintf(stderr,"%s is not a command\n",argv[2]);
  return 20;
}
