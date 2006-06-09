/*
   drbdadm_adjust.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003-2006, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

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
#include <sys/wait.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "drbdadm.h"

#define PERROR(fmt, args...) \
do { fprintf(stderr,fmt ": ", ##args); perror(0); } while (0)

/******
 This is a bit uggly.
 If you think you are clever, then consider to contribute a nicer
 implementation of adm_adjust()

*/

FILE *m_popen(int *pid,char** argv)
{
  int mpid;
  int pipes[2];

  if(pipe(pipes)) {
    perror("Creation of pipes failed");
    exit(E_exec_error);
  }

  mpid = fork();
  if(mpid == -1) {
    fprintf(stderr,"Can not fork");
    exit(E_exec_error);
  }
  if(mpid == 0) {
    close(pipes[0]); // close reading end
    dup2(pipes[1],1); // 1 = stdout
    close(pipes[1]);
    execvp(argv[0],argv);
    fprintf(stderr,"Can not exec");
    exit(E_exec_error);
  }

  close(pipes[1]); // close writing end
  *pid=mpid;
  return fdopen(pipes[0],"r");
}


static unsigned long m_strtol(const char* s,int def_mult)
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
      exit(E_config_invalid);
    }
}

int check_opt_b(FILE *in,char* name,struct d_option* base)
{
  struct d_option* o;
  char uu[2],scs[200],sn[50];
  int l,rv=0;

  strcpy(sn,name);
  l=strlen(sn)-1;
  sn[l]=0;
  sprintf(scs," %*s%%[%c]\n",l,sn,name[l]);

  if(fscanf(in,scs,uu)>0) {
    o=find_opt(base,name);
    if(o) o->mentioned=1;
    else rv=1;
  } // else { unexpected input... }

  //printf("check_opt_b(%s)=%d\n",name,rv);
  return rv;
}

int check_opt_d(FILE *in,char* name,int dm, char* unit,struct d_option* base)
{
  unsigned long  ul;
  struct d_option* o;
  char uu[2];
  char scs[200];
  int rv=0;

  sprintf(scs," %s = %%lu %s (%%[d]efault)\n",name,unit);
  if(fscanf(in,scs,&ul,uu)>0) {
    o=find_opt(base,name);
    if(o) {
      o->mentioned=1;
      if(m_strtol(o->value,dm) != ul) rv=1;
    } else {
      if( uu[0] != 'd' ) rv=1;
    }
  }
  //printf("check_opt_d(%s)=%d\n",name,rv);

  return rv;
}

int check_opt_s(FILE *in,char* name,struct d_option* base)
{
  struct d_option* o;
  char scs[200];  
  char value[200];
  int rv=0;

  sprintf(scs," %s = %%s\n",name);
  if(fscanf(in,scs,value)>0) {
    o=find_opt(base,name);
    if(o) {
      o->mentioned=1;
      if(strcmp(o->value,value)) rv=1;
    } else {
      rv=1;
    }
  }

  //printf("check_opt_s(%s)=%d [value=%s]\n",name,rv,value);

  return rv;
}

int complete(struct d_option* base)
{
  int rv=0;

  while(base) {
    if(base->mentioned == 0) {
      //printf("complete(): '%s'\n",base->name);
      rv=1;
      break;
    }
    base=base->next;
  }

  //printf("complete()=%d\n",rv);

  return rv;
}

int m_fscanf(FILE *stream,const char *fmt, ...)
{
  va_list ap;
  int rv;

  va_start(ap, fmt);
  rv=vfscanf(stream,fmt,ap);
  va_end(ap);

  if(rv==0) {
    fprintf(stderr,"fscanf() faild for fmt string: %s\n",fmt);
  }

  return rv;
}


/* NOTE
 * return before waitpit is a BUG. "goto out;" instead!
 *
 * calling drbdsetup again before waitpid("drbdsetup show") has a race with
 * the next ioctl failing because of the zombie still holding an open_cnt on
 * the drbd device. so don't do that.
 */
int adm_adjust(struct d_resource* res,char* unused)
{
  char* argv[20];
  int rv,pid,argc=0;
  FILE *in;
  char str1[255],str2[255];
  unsigned long  ul1,ul2;
  struct d_option* o;
  char uu[2];
  int do_attach=0;
  int do_resize=0;
  int do_connect=0;
  int do_syncer=0;

  struct stat sb;
  int major, minor;
  int err = 10;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="show";
  argv[argc++]=0;

  in=m_popen(&pid,argv);

  rv=fscanf(in,"%[Not] configured",str1);
  if(rv==1 && !strcmp("Not",str1) ) {
    do_attach=1;
    do_connect=1;
    do_syncer=1;
    goto do_up;
  }

  if (stat(res->me->disk, &sb)) {
    PERROR("stat '%s' failed:", res->me->device);
    goto out;
  }
  if (!S_ISBLK(sb.st_mode)) {
    fprintf(stderr, "'%s' not a block device!\n", res->me->disk);
    goto out;
  }
  rv=m_fscanf(in,"Lower device: %d:%d (%*[^)])\n",&major,&minor);
  if( (rv!=2) || (((major<<8)|minor) != (int)sb.st_rdev)) do_attach=1;

  if (strcmp("internal", res->me->meta_disk)) {
    if (stat(res->me->meta_disk, &sb)) {
      PERROR("stat '%s' failed:", res->me->meta_disk);
      goto out;
    }
    if (!S_ISBLK(sb.st_mode)) {
      fprintf(stderr, "'%s' not a block device!\n", res->me->disk);
      goto out;
    }
  } else {
    sb.st_rdev = 0;
  }

  rv = m_fscanf(in, "Meta device: %s (%[^)])\n", str1, str2);
  if (rv == 1) {
    if (!strcmp("internal", str1)) {
      if (strcmp("internal", res->me->meta_disk))
	do_attach = 1;
    } else {
      fprintf(stderr, "parse error, '%s' read, 'internal' expected\n", str1);
      goto out;
    }
  }
  if (rv == 2) {
    sscanf(str1, "%d:%d", &major, &minor);
    if ((rv != 2) || (((major << 8) | minor) != (int) sb.st_rdev))
      do_attach = 1;
    rv = m_fscanf(in, "Meta index: %[0-9]\n", str1);
    if (rv == 1) {
      if (strcmp(str1, res->me->meta_index))
	do_attach = 1;
    } else {
      fprintf(stderr, "parse error\n");
      goto out;
    }
  }

  rv=m_fscanf(in,"Disk options%[:]\n",uu);
  if(rv==1) {
    do_resize |= check_opt_d(in,"size",1024,"KB",res->disk_options);
    do_attach |= check_opt_s(in,"on-io-error",res->disk_options);

    // Check if every options is also present in drbdsetup show's output.
    o=res->disk_options;
    while(o) {
      if(o->mentioned == 0) {
	if(!strcmp(o->name,"size")) do_resize=1;
	   else do_attach=1;
      }
      o=o->next;
    }
  }

  rv=m_fscanf(in,"Local address: %[0-9.]:%s\n",str1,str2);
  if(rv!=2 || strcmp(str1,res->me->address) || strcmp(str2,res->me->port) ) {
    do_connect=1;
  }

  rv=m_fscanf(in,"Remote address: %[0-9.]:%s\n",str1,str2);
  if(rv!=2 || strcmp(str1,res->peer->address) ||
     strcmp(str2,res->peer->port) ) {
    do_connect=1;
  }

  rv=m_fscanf(in,"Wire protocol: %1[ABC]\n",str1);
  if(rv!=1 || strcmp(str1,res->protocol) ) {
    do_connect=1;
  }

  rv=m_fscanf(in,"Net options%[:]\n",uu);
  if(rv==1) {
    rv=m_fscanf(in," timeout = %lu.%lu sec (%[d]efault)\n",&ul1,&ul2,uu);
    o=find_opt(res->net_options,"timeout");
    if(o) {
      o->mentioned=1;
      if(m_strtol(o->value,1) != ul1*10 + ul2) do_connect=1;
    } else {
      if( uu[0] != 'd' ) do_connect=1;
    }

    do_connect |= check_opt_d(in,"connect-int",1,"sec",res->net_options);
    do_connect |= check_opt_d(in,"ping-int",1,"sec",res->net_options);
    do_connect |= check_opt_d(in,"max-epoch-size",1,"",res->net_options);
    do_connect |= check_opt_d(in,"max-buffers",1,"",res->net_options);
    do_connect |= check_opt_d(in,"unplug-watermark",1,"",res->net_options);
    do_connect |= check_opt_d(in,"sndbuf-size",1,"",res->net_options);
    do_connect |= check_opt_d(in,"ko-count",1,"",res->net_options);
    do_connect |= check_opt_s(in,"on-disconnect",res->net_options);
    do_connect |= complete(res->net_options);
  }

  rv=m_fscanf(in,"Syncer options%[:]\n",uu);
  if(rv==1) {
    do_syncer |= check_opt_d(in,"rate",1024,"KB/sec",res->sync_options);
    do_syncer |= check_opt_d(in,"group",1,"",res->sync_options);
    do_syncer |= check_opt_d(in,"al-extents",1,"",res->sync_options);
    do_syncer |= check_opt_b(in,"skip-sync",res->sync_options);
    do_syncer |= check_opt_b(in,"use-csums",res->sync_options);
    do_syncer |= complete(res->sync_options);
  } else do_syncer=1;

 do_up:
  err = 0;
 out:
  // drain, close, wait for drbdsetup to "officially die".
  { static char drain[1024]; while (fgets(drain,1024,in)); }
  fclose(in);
  waitpid(pid,0,0);
  if (err) return err;

  if(do_attach) {
    schedule_dcmd(adm_attach,res,0);
    do_resize=0;
  }
  if(do_resize)  schedule_dcmd(adm_resize,res,0);
  if(do_syncer)  schedule_dcmd(adm_syncer,res,1);
  if(do_connect) schedule_dcmd(adm_connect,res,2);

  return 0;
}
