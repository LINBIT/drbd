/*
   drbdadm_adjust.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003, Philipp Reisner <philipp.reisner@gmx.at>.
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

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "drbdadm.h"

FILE *m_popen(int *pid,char** argv)
{
  int mpid;
  int pipes[2];

  if(pipe(pipes)) {
    perror("Creation of pipes failed");
    exit(20);
  }

  mpid = fork();
  if(mpid == -1) {
    fprintf(stderr,"Can not fork");
    exit(20);    
  }
  if(mpid == 0) {
    close(pipes[0]); // close reading end
    dup2(pipes[1],1); // 1 = stdout
    close(pipes[1]);
    execv(argv[0],argv);
    fprintf(stderr,"Can not exec");
    exit(20);    
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
      exit(20);
    }
}

int adm_adjust(struct d_resource* res,char* unused)
{
  char* argv[20];
  int rv,pid,argc=0;
  FILE *in;
  char str1[255],str2[255];
  unsigned long  ul1;
  struct d_option* o;
  char uu[2];
  int do_attach=0;
  int do_resize=0;
  int do_connect=0;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="show";
  argv[argc++]=0;

  in=m_popen(&pid,argv);

  rv=fscanf(in,"Lower device: %*02d:%*02d   (%[^)])\n",str1);
  if( (rv!=1) || strcmp(str1,res->me->disk)) {
    do_attach=1;
  }

  fscanf(in,"Disk options%[:]\n",uu);
  rv=fscanf(in," size = %lu KB\n",&ul1);
  if(rv==1) {
    o=find_opt(res->disk_options,"size");
    o->mentioned=1;
    if(o) {
      if(m_strtol(o->value,1024) != ul1) {
	do_resize=1;
      }
    } else {
      do_attach=1;
    }
  }
  rv=fscanf(in," do-pani%[c]\n",uu); // 1 == SUCCESS
  if(rv==1) {
    o=find_opt(res->disk_options,"do-panic");
    o->mentioned=1;
    if(!o) do_attach=1;
  }

  // Check if every options is also present in drbdsetup show's output.
  o=res->disk_options;
  while(o) {
    if(o->mentioned == 0) do_attach=1;
    o=o->next;
  }

  rv=fscanf(in,"Local address: %[0-9.]:%s\n",str1,str2);
  if(rv!=2 || strcmp(str1,res->me->address) || strcmp(str2,res->me->port) ) {
    do_connect=1;
  }
    
  rv=fscanf(in,"Remote address: %[0-9.]:%s\n",str1,str2);
  if(rv!=2 || strcmp(str1,res->partner->address) || 
     strcmp(str2,res->partner->port) ) {
    do_connect=1;
  }
  
  rv=fscanf(in,"Wire protocol: %1[ABC]\n",str1);
  if(rv!=1 || strcmp(str1,res->protocol) ) {
    do_connect=1;
  }

  fscanf(in,"Net options%[:]\n",uu);

  fscanf(in,"Syncer options%[:]\n",uu);
  
  if(do_attach) {
    adm_attach(res,0);
    do_resize=0;
  }
  if(do_resize)  adm_resize(res,0);
  if(do_connect) adm_connect(res,0);
  
  fclose(in);
  waitpid(pid,0,0);

  return 0;
}
