/*
   drbdsetup.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

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

#define _GNU_SOURCE

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
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#include "drbdtool_common.h"
#include "drbd_limits.h"

/* Default values */
#define DEF_NET_TIMEOUT             60      //  6 seconds
#define DEF_NET_TRY_CON_I           10      // 10 seconds
#define DEF_NET_PING_I              10      // 10 seconds
#define DEF_SYNC_RATE              250
#define DEF_SYNC_AFTER              -1
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
#define DEF_KO_COUNT                 0
#define DEF_ON_DISCONNECT       Reconnect
#define DEF_FENCING             DontCare
#define DEF_TWO_PRIMARIES            0
#define DEF_AFTER_SB_0P       Disconnect
#define DEF_AFTER_SB_1P       Disconnect
#define DEF_AFTER_SB_2P       Disconnect
#define DEF_UNPLUG_WATERMARK       (DEF_MAX_BUFFERS/16)

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

/* avoid warnings with -W for unused function arguments;
 * alternative use __attribute((unused))
#define UNUSED(x)	(void)(x == x)
 */

// some globals
char* cmdname = 0;

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
int cmd_outdate(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_disconnect(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_show(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_syncer(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_pause_sync(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_resume_sync(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_detach(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_state(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_cstate(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_dstate(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_show_gi(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_get_gi(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_suspend_io(int drbd_fd,char** argv,int argc,struct option *options);
int cmd_resume_io(int drbd_fd,char** argv,int argc,struct option *options);


struct drbd_cmd commands[] = {
  {"primary", cmd_primary,           0,
   (struct option[]) {
     { "do-what-I-say",no_argument,     0, 'd' },
     { "overwrite-data-of-peer",no_argument, 0, 'o' },
     { 0,            0,                 0, 0   } } },
  {"secondary", cmd_secondary,       0, 0, },
  {"wait_sync", cmd_wait_sync,       0,
   (struct option[]) {
     { "wfc-timeout",required_argument, 0, 't' },
     { "degr-wfc-timeout",required_argument,0,'d'},
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
     { "after",      required_argument, 0, 'a' },
     { "rate",       required_argument, 0, 'r' },
     { "al-extents", required_argument, 0, 'e' },
     { 0,            0,                 0, 0 } } },
  {"pause-sync",  cmd_pause_sync,       0, 0, },
  {"resume-sync", cmd_resume_sync,      0, 0, },
  {"down", cmd_down,                 0, 0, },
  {"detach", cmd_detach,             0, 0, },
  {"net", cmd_net_conf, (char *[]){"local_addr","remote_addr","protocol",0},
   (struct option[]) {
     { "timeout",    required_argument, 0, 't' },
     { "max-epoch-size", required_argument, 0, 'e' },
     { "max-buffers",required_argument, 0, 'b' },
     { "unplug-watermark",required_argument, 0, 'u' },
     { "connect-int",required_argument, 0, 'c' },
     { "ping-int",   required_argument, 0, 'i' },
     { "sndbuf-size",required_argument, 0, 'S' },
     { "ko-count",   required_argument, 0, 'k' },
     { "on-disconnect",required_argument, 0, 'd' },
     { "allow-two-primaries",no_argument, 0, 'm' },
     { "cram-hmac-alg",required_argument, 0, 'a' },
     { "shared-secret",required_argument, 0, 'x' },
     { "after-sb-0pri",required_argument, 0, 'A' },
     { "after-sb-1pri",required_argument, 0, 'B' },
     { "after-sb-2pri",required_argument, 0, 'C' },
     { "discard-my-data",    no_argument, 0, 'D' },
     { 0,            0,                 0, 0 } } },
  {"disk", cmd_disk_conf,(char *[]){"lower_dev","meta_data_dev",
				    "meta_data_index",0},
   (struct option[]) {
     { "size",       required_argument, 0, 'd' },
     { "on-io-error",required_argument, 0, 'e' },
     { "fencing",    required_argument, 0, 'f' },
     { 0,            0,                 0, 0 } } },
  {"resize", cmd_disk_size,             0,
   (struct option[]) {
     { "size",  required_argument,      0, 'd' },
     { 0,            0,                 0, 0 } } },
  {"outdate", cmd_outdate,           0, 0, },
  {"disconnect", cmd_disconnect,     0, 0, },
  {"state", cmd_state,               0, 0, },
  {"cstate", cmd_cstate,             0, 0, },
  {"dstate", cmd_dstate,             0, 0, },
  {"show-gi", cmd_show_gi,           0, 0, },
  {"get-gi", cmd_get_gi,             0, 0, },
  {"show", cmd_show,                 0, 0, },
  {"suspend-io", cmd_suspend_io,     0, 0, },
  {"resume-io", cmd_resume_io,       0, 0, },
};

const char *eh_names[] = {
  [PassOn] = "pass_on",
  [Panic]  = "panic",
  [Detach] = "detach" 
};

const char *dh_names[] = {
  [Reconnect]   = "reconnect",
  [DropNetConf] = "stand_alone",
  // [FreezeIO]    = "freeze_io" // TODO on the kernel side...
};

const char *fencing_names[] = {
  [DontCare] = "dont-care",
  [Resource] = "resource-only",
  [Stonith]  = "resource-and-stonith" 
};

const char *asb0p_names[] = {
  [Disconnect]        = "disconnect",
  [DiscardYoungerPri] = "discard-younger-primary",
  [DiscardOlderPri]   = "discard-older-primary",
  [DiscardLeastChg]   = "discard-least-changes",
  [DiscardLocal]      = "discard-local",
  [DiscardRemote]     = "discard-remote"
};

const char *asb1p_names[] = {
  [Disconnect]        = "disconnect",
  [Consensus]         = "consensus",
  [DiscardSecondary]  = "discard-secondary",
  [PanicPrimary]      = "panic-primary"
};

const char *asb2p_names[] = {
  [Disconnect]        = "disconnect",
  [PanicPrimary]      = "panic"
};

int _lookup_handler(const char* text, const char** handlers, int size)
{
  int i;

  for(i=0;i<size;i++) {
    if (handlers[i]==0) continue;
    if (strcmp(text,handlers[i])==0) {
      return i;
    }
  }
  return -1;
}

#define lookup_handler(A,B) _lookup_handler(A,B,ARRY_SIZE(B))

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

/* NOTE all values are _unsigned_ */
unsigned long long
m_strtoll_range(const char *s, const char def_unit, const char *name,
		const unsigned long long min, const unsigned long long max)
{
  unsigned long long r = m_strtoll(s, def_unit);
  char unit[] = { def_unit > '1' ? def_unit : 0, 0 };
  if (min > r || r > max)
    {
      fprintf(stderr, "%s %s => %llu%s out of range [%llu..%llu]%s\n",
	      name, s, r, unit, min, max, unit);
      exit(20);
    }
  if (DEBUG_RANGE_CHECK)
    {
      fprintf(stderr,
	      "OK: %s %s => %llu%s in range [%llu..%llu]%s.\n",
	      name, s, r, unit, min, max, unit);
    }
  return r;
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
      return m_strtoll_range(b+1,1, "port", DRBD_PORT_MIN, DRBD_PORT_MAX);

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
  size_t i;

  printf("\nUSAGE: %s device command arguments options\n\n"
	 "Device is usually /dev/drbdX or /dev/drbd/X.\n"
         "Commands, arguments and options are:\n",cmdname);


  for (i = 0; i < ARRY_SIZE(commands); i++)
    print_command_usage(i, 0);

  printf("\nAvailable on-io-error handlers:");
  for(i=0;i<ARRY_SIZE(eh_names);i++) {
    printf(" %s",eh_names[i]);
    if(i < ARRY_SIZE(eh_names)-1) printf(",");
  }

  printf("\nAvailable on-disconnect handlers:");
  for(i=0;i<ARRY_SIZE(dh_names);i++) {
    printf(" %s",dh_names[i]);
    if(i < ARRY_SIZE(dh_names)-1) printf(",");
  }

  printf("\nAvailable fencing policies:");
  for(i=0;i<ARRY_SIZE(fencing_names);i++) {
    printf(" %s",fencing_names[i]);
    if(i < ARRY_SIZE(fencing_names)-1) printf(",");
  }

  printf("\n\nVersion: "REL_VERSION" (api:%d)\n%s\n",
		  API_VERSION, drbd_buildtag());
  if (addinfo)
      printf("\n%s\n",addinfo);

  exit(20);
}

int open_drbd_device(const char* device)
{
  int err,drbd_fd,version = 0;

  drbd_fd = dt_lock_open_drbd(device,NULL,0);

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
  cn->config.fencing = DEF_FENCING;

  if(argc==0) return 0;

  while(1)
    {
      int c;

      PRINT_ARGV;
      c = getopt_long(argc,argv,make_optstring(options,'-'),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 'd':
	  cn->config.disk_size = m_strtoll_range(optarg,'K', "size",
			      DRBD_DISK_SIZE_SECT_MIN>>1,
			      DRBD_DISK_SIZE_SECT_MAX>>1 ) << 1;
	  break;
	case 'e':
	  cn->config.on_io_error=lookup_handler(optarg,eh_names);
	  if( cn->config.on_io_error == -1U ) {
	    fprintf(stderr,"%s: '%s' is an invalid on-io-error handler.\n",
		    cmdname,optarg);
	    return 20;
	  }
	  break;
	case 'f':
	  cn->config.fencing = lookup_handler(optarg,fencing_names);
	  if( cn->config.fencing == -1U ) {
	    fprintf(stderr,"%s: '%s' is an invalid fency policy.\n",
		    cmdname,optarg);
	    return 20;
	  }
	  break;
	case 1:	// non option argument. see getopt_long(3)
	  fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",cmdname,optarg);
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
  cn->config.on_disconnect = DEF_ON_DISCONNECT;
  cn->config.two_primaries = DEF_TWO_PRIMARIES;
  cn->config.cram_hmac_alg[0] = 0;
  cn->config.shared_secret[0] = 0;
  cn->config.after_sb_0p = DEF_AFTER_SB_0P;
  cn->config.after_sb_1p = DEF_AFTER_SB_1P;
  cn->config.after_sb_2p = DEF_AFTER_SB_2P;
  cn->config.want_lose = 0;
  cn->config.ko_count = DEF_KO_COUNT;
  cn->config.unplug_watermark = DEF_UNPLUG_WATERMARK;

  if(argc==0) return 0;

  while(1)
    {
      int c;

      PRINT_ARGV;
      c = getopt_long(argc,argv,make_optstring(options,'-'),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 't':
	  cn->config.timeout = m_strtoll_range(optarg,1, "timeout",
			  DRBD_TIMEOUT_MIN, DRBD_TIMEOUT_MAX);
	  break;
	case 'e':
	  cn->config.max_epoch_size = m_strtoll_range(optarg,1,
			  "max-epoch-size",
			  DRBD_MAX_EPOCH_SIZE_MIN, DRBD_MAX_EPOCH_SIZE_MAX);
	  break;
	case 'b':
	  cn->config.max_buffers = m_strtoll_range(optarg,1, "max-buffers",
			  DRBD_MAX_BUFFERS_MIN, DRBD_MAX_BUFFERS_MAX);
	  break;
	case 'u':
	  cn->config.unplug_watermark = m_strtoll_range(optarg,1, "unplug-watermark",
			  DRBD_UNPLUG_WATERMARK_MIN, DRBD_UNPLUG_WATERMARK_MAX);
	  break;
	case 'c':
	  cn->config.try_connect_int = m_strtoll_range(optarg,1, "connect-int",
			  DRBD_CONNECT_INT_MIN, DRBD_CONNECT_INT_MAX);
	  break;
	case 'i':
	  cn->config.ping_int = m_strtoll_range(optarg,1, "ping-int",
			  DRBD_PING_INT_MIN, DRBD_PING_INT_MAX);
	  break;
	case 'S':
	  cn->config.sndbuf_size = m_strtoll_range(optarg,1, "sndbuf-size",
			  DRBD_SNDBUF_SIZE_MIN, DRBD_SNDBUF_SIZE_MAX);
	  break;
       case 'k':
          cn->config.ko_count = m_strtoll_range(optarg,1, "ko-count",
			  DRBD_KO_COUNT_MIN, DRBD_KO_COUNT_MAX);
          break;
       case 'm':
	  cn->config.two_primaries = 1;
          break;
	case 'd':
	  cn->config.on_disconnect = lookup_handler(optarg,dh_names);
	  if( cn->config.on_disconnect == -1U ) {
	    fprintf(stderr,"%s: '%s' is an invalid on-disconnect handler.\n",
		    cmdname,optarg);
	    return 20;
	  }
	  break;
	case 'a':
	  strncpy(cn->config.cram_hmac_alg,optarg,CRYPTO_MAX_ALG_NAME);
	  break;
	case 'x':
	  strncpy(cn->config.shared_secret,optarg,SHARED_SECRET_MAX);
	  break;
	case 'A':
	  cn->config.after_sb_0p = lookup_handler(optarg,asb0p_names);
	  if( cn->config.after_sb_0p == -1U ) {
	    fprintf(stderr,"%s: '%s' is an invalid after-sb-0pri handler.\n",
		    cmdname,optarg);
	    return 20;
	  }
	  break;
	case 'B':
	  cn->config.after_sb_1p = lookup_handler(optarg,asb1p_names);
	  if( cn->config.after_sb_0p == -1U ) {
	    fprintf(stderr,"%s: '%s' is an invalid after-sb-1pri handler.\n",
		    cmdname,optarg);
	    return 20;
	  }
	  break;
	case 'C':
	  cn->config.after_sb_2p = lookup_handler(optarg,asb2p_names);
	  if( cn->config.after_sb_0p == -1U ) {
	    fprintf(stderr,"%s: '%s' is an invalid after-sb-2pri handler.\n",
		    cmdname,optarg);
	    return 20;
	  }
	  break;
       case 'D':
	  cn->config.want_lose = 1;
          break;


	case 1:	// non option argument. see getopt_long(3)
	  fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",cmdname,optarg);
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
    [LDMDInvalid]="Lower device / meta device / index combination invalid.",
    [LDDeviceTooLarge]="Currently we only support devices up to 3.998TB.\n"
                       "(up to 2TB in case you do not have CONFIG_LBD set)",
                       "Contact office@linbit.com, if you need more.",
    [MDIOError]="IO error(s) orruced during initial access to meta-data.\n",
    [MDInvalid]="No valid meta-data signature found.\n"
                "Use 'drbdadm create-md res' to initialize meta-data area.\n",
    [CRAMAlgNotAvail]="The 'cram-hmac-alg' you specified is not known in "
                      "the kernel.\n",
    [CRAMAlgNotDigest]="The 'cram-hmac-alg' you specified is not a digest.",
    [KMallocFailed]="kmalloc() failed. Out of memory?",
    [DiscardNotAllowed]="--discard-my-data not allowed when primary."
  };

  if (err_no<0 || (size_t)err_no>ARRY_SIZE(etext)) err_no=0;
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



int set_state(int drbd_fd,drbd_role_t state)
{
  int err, arg = state;
  err=ioctl(drbd_fd,DRBD_IOCTL_SET_STATE,&arg);
  if(err) {
    err=errno;
    PERROR("ioctl(,SET_STATE,) failed");
    switch(err)
      {
      case EBUSY:
	fprintf(stderr,"Someone has opened the device for RW access!\n");
	break;
      case EIO:
	fprintf(stderr,"%s\n", set_st_err_name(arg));
        break;
      }
    return 20;
  }
  return 0;
}


int cmd_primary(int drbd_fd,char** argv,int argc,struct option *options)
{
  drbd_role_t newstate=Primary;

  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  /* --do-what-I-say have to be spelled out */
	  c = getopt_long_only(argc,argv,make_optstring(options,'-'),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 'o':
	      if (strcmp("--overwrite-data-of-peer",argv[optind-1])) {
		      fprintf(stderr,"%s\nYou have to spell out --overwrite-data-of-peer, if you mean it\n",
				      argv[optind-1]);
		      return 20;
	      }
	      newstate |= DontBlameDrbd;
	      break;
	    case 'd':
	      fprintf(stderr,
"--do-what-I-say was renamed to --overwrite-data-of-peer, since that is\n"
"less ambiguous.\n"
"Only do it if you really know what you are doing. DRBD is going to save\n"
"this fact to its metadata, and it will really overwrite the peer's copy\n"
"of data with the local copy.\n");
	      return 20;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",cmdname,optarg);
	    case '?':
	      return 20;
	    }
	}
    }

  return set_state(drbd_fd,newstate);
}

int cmd_secondary(int drbd_fd,char **argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
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
	  c = getopt_long(argc,argv,make_optstring(options,'-'),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 't':
	      p.wfc_timeout = m_strtoll_range(optarg,1, "wfc-timeout",
			      DRBD_WFC_TIMEOUT_MIN, DRBD_WFC_TIMEOUT_MAX);
	      break;
	    case 'd':
	      p.degr_wfc_timeout = m_strtoll_range(optarg,1,
			      "degr-wfc-timeout",
			      DRBD_DEGR_WFC_TIMEOUT_MIN,
			      DRBD_DEGR_WFC_TIMEOUT_MAX);
	      break;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",cmdname,optarg);
	    case '?':
	      return 20;
	    }
	}
    }
  err=ioctl(drbd_fd,req,&p);
  if(errno == ETIME) exit(5);
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

  /*
  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&current_cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

  cn.config.rate = current_cn.sconf.rate;
  cn.config.after = current_cn.sconf.after;
  cn.config.al_extents = current_cn.sconf.al_extents;
  cn.config.use_csums = 0; //current_cn.sconf.use_csums;
  cn.config.skip = 0; //current_cn.sconf.skip;
  */
  cn.config.rate = DEF_SYNC_RATE;
  cn.config.after = DEF_SYNC_AFTER;
  cn.config.al_extents = DEF_SYNC_AL_EXTENTS;
  cn.config.use_csums = 0; //current_cn.sconf.use_csums;
  cn.config.skip = 0; //current_cn.sconf.skip;


  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  c = getopt_long(argc,argv,make_optstring(options,'-'),options,0);
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
	      cn.config.rate=m_strtoll_range(optarg,'K', "rate",
			      DRBD_RATE_MIN, DRBD_RATE_MAX);
	      break;
	    case 'a':
	      cn.config.after=m_strtoll(optarg,1);
	      break;
	    case 'e':
	      cn.config.al_extents=m_strtoll_range(optarg,1, "al-extents",
			      DRBD_AL_EXTENTS_MIN, DRBD_AL_EXTENTS_MAX);
	      break;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",cmdname,optarg);
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
      err=errno;
      PERROR("ioctl(,SET_SYNC_CONFIG,) failed");
      if(err == EBADMSG) fprintf(stderr,"Sync-after cycle found!\n");
      if(err == ERANGE) fprintf(stderr,"Sync-after to small or big.\n");
      return 20;
    }

  return 0;
}

int cmd_pause_sync(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_PAUSE_SYNC);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,PAUSE_SYNC,) failed");
      if(err == EINPROGRESS) fprintf(stderr,"Pause flag is already set!\n");
      return 20;
    }
  return 0;
}

int cmd_resume_sync(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_RESUME_SYNC);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,RESUME_SYNC,) failed");
      if(err == EINPROGRESS) fprintf(stderr,"Pause flag is not set!\n");
      return 20;
    }
  return 0;
}

int cmd_invalidate(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
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

int cmd_invalidate_rem(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
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

int cmd_outdate(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  int err;
  int reason;

  err=ioctl(drbd_fd,DRBD_IOCTL_OUTDATE_DISK,&reason);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,OUTDATE_DISK,) failed");
      if(err==EIO) 
	{
	  fprintf(stderr,"%s\n",set_st_err_name(reason));
	  if(reason == SS_NoUpToDateDisk) return 17;
	}
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

int cmd_detach(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
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

int cmd_disconnect(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
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

int cmd_disk_conf(int drbd_fd, char **argv, int argc, struct option *options)
{
  struct ioctl_disk_config cn;
  int retval, mi = 0;

  retval = scan_disk_options(argv, argc, &cn, options);
  if (retval)
    return retval;

  if (argc == 5) {
    /* short variant, index and other options omitted */
    if (!strcmp("internal", argv[4])) {
      mi = DRBD_MD_INDEX_FLEX_INT;
    } else {
      fprintf(stderr, "meta_index missing.\n");
    }
  } else {
    /* index or any options given. check the index */
    if (!strcmp("internal", argv[4])) {
      /* in drbd8, internal is always flexible */
      if (!strncmp("flex", argv[5], 4) ||
	  !strcmp("-1", argv[5]) ||
	  !strcmp("internal", argv[5]))
      {
	  mi = DRBD_MD_INDEX_FLEX_INT;
      } else {
	  fprintf(stderr, "invalid meta_index for 'internal'.\n");
	  return 20;
      }
    } else {
      if (!strncmp("flex", argv[5], 4)) {
	  mi = DRBD_MD_INDEX_FLEX_EXT;
      } else {
	mi = m_strtoll(argv[5], 1);
	if (mi < 0) {
	  fprintf(stderr, "meta_index may not be negative.\n");
	  return 20;
	}
      }
    }
  }
  //FIXME check that mi*128M is not bigger than meta device!
  cn.config.meta_index = mi;
  return do_disk_conf(drbd_fd, argv[3], argv[4], &cn);
}

int cmd_disk_size(int drbd_fd,char** argv,int argc,struct option *options)
{
  __u64 u_size=0; // unit: sectors.
  int err;

  if(argc > 0)
    {
      while(1)
	{
	  int c;

	  PRINT_ARGV;
	  c = getopt_long(argc,argv,make_optstring(options,'-'),options,0);
	  if(c == -1) break;
	  switch(c)
	    {
	    case 'd':
	      u_size=m_strtoll_range(optarg,'K', "size",
			      DRBD_DISK_SIZE_SECT_MIN>>1,
			      DRBD_DISK_SIZE_SECT_MAX>>1 ) << 1;
	      break;
	    case 1:	// non option argument. see getopt_long(3)
	      fprintf(stderr,"%s: Unexpected nonoption argument '%s'\n",cmdname,optarg);
	    case '?':
	      return 20;
	    }
	}
    }

  err=ioctl(drbd_fd,DRBD_IOCTL_SET_DISK_SIZE,u_size);
  if(err)
    {
      PERROR("ioctl(,SET_DISK_SIZE,) failed");
      if(err==EBUSY) {
	fprintf(stderr,"Online resizing is not allowed during resync.");
      }
      if(err==EINPROGRESS) {
	fprintf(stderr,"One node must be primary to do online resizing.");
      }
      return 20;
    }

  return 0;
}

const char* guess_dev_name(const char* dir,unsigned int g_major,unsigned int g_minor)
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
	  if (g_major == major(sb.st_rdev) &&
	      g_minor == minor(sb.st_rdev) )
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
      if(!strcmp(dde->d_name,"shm")) continue;
      if(S_ISLNK(sb.st_mode)) continue;

      if(S_ISDIR(sb.st_mode))
	{
	  char subdir[50];

	  if(snprintf(subdir,50,"%s/%s",dir,dde->d_name)==49)
	    { /* recursion is too deep */
	      strcpy(dev_name,"can not guess name");
	      return dev_name;
	    }

	  if(guess_dev_name(subdir,g_major,g_minor)) return dev_name;
	}
    }

  closedir(device_dir);
 err_out:
  return NULL;
}

const char* check_dev_name(const char* dev_name , int major, int minor)
{
  // this is because the SmartArray (Compaq, HP, whatever...) driver
  // returns a closing bracket in the device name...

  if(!dev_name || !dev_name[0] || index(dev_name,')') )
    {
      dev_name = guess_dev_name("/dev",major,minor);
    }
  if(dev_name) return dev_name;
  else return "n.a.";
}

int cmd_show(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  struct ioctl_get_config cn;
  struct sockaddr_in *other_addr;
  struct sockaddr_in *my_addr;
  struct stat sb;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

#define SHOW_I(T,U,M,D) \
printf("\t" T "\t%d",M); \
if(M==D) printf(" _is_default"); \
printf(";  \t# " U "\n")

#define SHOW_IU(T,U1,U2,M,D) \
printf("\t" T "\t%d"U1,M); \
if(M==D) printf(" _is_default"); \
printf(";  \t# " U2 "\n")

#define SHOW_H(T,M,D,H) \
printf("\t" T "\t%s",H[M]); \
if(M==D) printf(" _is_default"); \
printf(";\n")

#define SHOW_S(T,M,D) \
printf("\t" T "\t\"%s\"",M); \
if(!strcmp(M,D)) printf(" _is_default"); \
printf(";\n")

  if( cn.state.disk == Diskless && cn.state.conn == StandAlone)
    {
      printf("# not configured.\n");
    }

  if( cn.state.disk > Diskless)
    {
      printf("disk {\n");
      SHOW_H("on-io-error",cn.on_io_error,DEF_ON_IO_ERROR,eh_names);
      SHOW_H("fencing\t",cn.fencing,DEF_FENCING,fencing_names);
      if( cn.disk_size_user ) printf("\tsize\t%luK;\n",
				     (unsigned long)cn.disk_size_user);
      printf("}\n");
    }

  if( cn.state.conn > StandAlone)
    {
      printf("protocol %c;\n",'A'-1+cn.nconf.wire_protocol);
      printf("net {\n");
      SHOW_I("timeout\t","1/10 seconds",cn.nconf.timeout,DEF_NET_TIMEOUT);
      SHOW_I("connect-int","seconds", cn.nconf.try_connect_int, DEF_NET_TRY_CON_I);
      SHOW_I("ping-int","seconds", cn.nconf.ping_int, DEF_NET_PING_I);
      SHOW_I("max-epoch-size","write requests", cn.nconf.max_epoch_size, DEF_MAX_EPOCH_SIZE);
      SHOW_I("max-buffers","pages", cn.nconf.max_buffers, DEF_MAX_BUFFERS);
      SHOW_I("unplug-watermark","write requests", cn.nconf.unplug_watermark, DEF_UNPLUG_WATERMARK);
      SHOW_I("sndbuf-size","byte", cn.nconf.sndbuf_size, DEF_SNDBUF_SIZE);
      SHOW_I("ko-count","1", cn.nconf.ko_count, DEF_KO_COUNT);
      // SHOW_H("on-disconnect",cn.nconf.on_disconnect,DEF_ON_DISCONNECT,dh_names);
      SHOW_H("after-sb-0pri",cn.nconf.after_sb_0p,DEF_AFTER_SB_0P,asb0p_names);
      SHOW_H("after-sb-1pri",cn.nconf.after_sb_1p,DEF_AFTER_SB_0P,asb1p_names);
      SHOW_H("after-sb-2pri",cn.nconf.after_sb_2p,DEF_AFTER_SB_0P,asb2p_names);
      SHOW_S("cram-hmac-alg",cn.nconf.cram_hmac_alg,"");
      SHOW_S("shared-secret",cn.nconf.shared_secret,"");
      if( cn.nconf.two_primaries ) printf("\tallow-two-primaries;\n");
      if( cn.nconf.want_lose ) printf("\tdiscard-my-data;\n");
      printf("}\n");
    }

  if( cn.state.disk > Diskless || cn.state.conn > StandAlone)
    {
      printf("syncer {\n");
      SHOW_IU("rate\t","K","(K)Byte/second", cn.sconf.rate, DEF_SYNC_RATE);
      SHOW_I("after\t","minor", cn.sconf.after, DEF_SYNC_AFTER);
      SHOW_I("al-extents","4MByte", cn.sconf.al_extents, DEF_SYNC_AL_EXTENTS);
      if( cn.sconf.skip ) printf("\tskip-sync;\n");
      if( cn.sconf.use_csums ) printf("\tuse-csums;\n");
      printf("}\n");

      err=fstat(drbd_fd,&sb);
      if(err)
	{
	  PERROR("fstat() failed");
	  return 20;
	}
      printf("_this_host {\n");
      printf("\tdevice\t\t\"/dev/drbd%d\";\n",minor(sb.st_rdev));
      printf("\tdisk\t\t\"/dev/%s\" _major %d _minor %d;\n",
	     check_dev_name(cn.lower_device_name,cn.lower_device_major,
			    cn.lower_device_minor),
	     cn.lower_device_major,
	     cn.lower_device_minor);

      if( cn.lower_device_major == cn.meta_device_major && 
	  cn.lower_device_minor == cn.meta_device_minor ) {
	printf("\tmeta-disk\tinternal;\n");
      } else {
	if( cn.meta_index == DRBD_MD_INDEX_FLEX_EXT ) {
  	  printf("\tflexible-meta-disk\t\"%s\" _major %d _minor %d;\n",
		 check_dev_name(cn.meta_device_name,cn.meta_device_major,
				cn.meta_device_minor),
		 cn.meta_device_major,
		 cn.meta_device_minor);
	} else {
  	  printf("\tmeta-disk\t\"%s\" [%d] _major %d _minor %d;\n",
		 check_dev_name(cn.meta_device_name,cn.meta_device_major,
				cn.meta_device_minor),
		 cn.meta_index,
		 cn.meta_device_major,
		 cn.meta_device_minor);
	}
      }

      if( cn.state.conn > StandAlone) {
	my_addr = (struct sockaddr_in *)cn.nconf.my_addr;
	printf("\taddress\t\t%s:%d;\n",
	       inet_ntoa(my_addr->sin_addr),
	       ntohs(my_addr->sin_port));
      }
      printf("}\n");
    }

  if( cn.state.conn > StandAlone)
    {
      other_addr = (struct sockaddr_in *)cn.nconf.other_addr;
      printf("_remote_host {\n");
      printf("\taddress\t%s:%d;\n",
	     inet_ntoa(other_addr->sin_addr),
	     ntohs(other_addr->sin_port));
      printf("}\n");
    }

  return 0;
}

int cmd_state(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  struct ioctl_get_config cn;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

  if( cn.state.conn == StandAlone && cn.state.disk == Diskless)
    {
      fprintf(stderr,"Not configured\n");
      return 10;
    }

  printf("%s/%s\n",roles_to_name(cn.state.role),
	 roles_to_name(cn.state.peer));

  return 0;
}

int cmd_cstate(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  struct ioctl_get_config cn;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

  if( cn.state.conn == StandAlone && cn.state.disk == Diskless)
    {
      fprintf(stderr,"Not configured\n");
      return 10;
    }

  printf("%s\n",conns_to_name(cn.state.conn));

  return 0;
}

int cmd_dstate(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  struct ioctl_get_config cn;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_CONFIG,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_CONFIG,) failed");
      return 20;
    }

  if( cn.state.conn == StandAlone && cn.state.disk == Diskless)
    {
      fprintf(stderr,"Not configured\n");
      return 10;
    }

  printf("%s/%s\n",disks_to_name(cn.state.disk),disks_to_name(cn.state.pdsk));

  return 0;
}

int cmd_get_gi(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  struct ioctl_get_uuids cn;
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_UUIDS,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_GEN_UUIDS,) failed");
      return 20;
    }
  
  dt_print_uuids(cn.uuid, cn.flags);

  return 0;
}

int cmd_show_gi(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  struct ioctl_get_uuids cn;
  char ppb[10];
  int err;

  err=ioctl(drbd_fd,DRBD_IOCTL_GET_UUIDS,&cn);
  if(err)
    {
      PERROR("ioctl(,GET_GEN_UUIDS,) failed");
      return 20;
    }
  
  dt_pretty_print_uuids(cn.uuid, cn.flags);

  printf("current agreed size: %s\n", ppsize(ppb, cn.current_size >> 1));
  printf("%u bits set in the bitmap [ %s out of sync ]\n",
	 cn.bits_set, ppsize(ppb, cn.bits_set * 4));

  return 0;
}

int cmd_suspend_io(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  int err;
  int reason;

  err=ioctl(drbd_fd,DRBD_IOCTL_SUSPEND_IO, &reason);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,DRBD_IOCTL_SUSPEND_IO) failed");
      if(err==EIO) 
	{
	  fprintf(stderr,"%s\n",set_st_err_name(reason));
	}
      return 20;
    }
  
  return 0;
}

int cmd_resume_io(int drbd_fd,char** argv __attribute((unused)),int argc __attribute((unused)),struct option *options __attribute((unused)))
{
  int err;
  int reason;

  err=ioctl(drbd_fd,DRBD_IOCTL_RESUME_IO, &reason);
  if(err)
    {
      err=errno;
      PERROR("ioctl(,DRBD_IOCTL_RESUME_IO) failed");
      if(err==EIO) 
	{
	  fprintf(stderr,"%s\n",set_st_err_name(reason));
	}
      return 20;
    }
  
  return 0;
}

int main(int argc, char** argv)
{
  int drbd_fd;
  int num_of_args;
  int help = 0;
  int err;
  size_t i;
  char **args;

  if ( (cmdname = strrchr(argv[0],'/')) )
      argv[0] = ++cmdname;
  else
      cmdname = argv[0];

  /* == '-' catches -h, --help, and similar */
  if (argc > 1 && (!strcmp(argv[1],"help") || argv[1][0] == '-'))
	  help = 1;
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
	  if (0 == strcmp(argv[2],"disk") && (argc == 5) &&
	      0 == strcmp(argv[4],"internal") ) {
	      --num_of_args;
	      /* don't require that stupid "-1" */
	  }
	  if (help || argc-3 < num_of_args)
	      print_command_usage(i,help?"":"Not enough arguments.");
	  if (argc-3-num_of_args>0 && commands[i].options==0)
	    {
	      fprintf(stderr,"Too many arguments or options.\n");
	      return 20;
	    }

	  if (strncmp ("/dev/drbd", argv[1], 9))
	    {
	      fprintf (stderr,
		       "  | NOTE: we now have officially asigned"
		       " device name and major number.\n"
		       "  | Please use /dev/drbd*; if neccessary"
		       " create the device nodes first.\n"
		       "  | To do so: for i in `seq 0 15` ;"
		       " do mknod -m 0660 /dev/drbd$i b 147 $i; done\n");
	    }
	  drbd_fd=open_drbd_device(argv[1]);

	  opterr = 1; /* let getopt() print error messages */
	  optind = 3+num_of_args;
	  err =  commands[i].function(drbd_fd,argv,argc,
				      commands[i].options);
	  close(drbd_fd); // explicit close on drbd device!
	  return err;
	}
    }
  fprintf(stderr,"%s is not a command\n",argv[2]);
  return 20;
}
