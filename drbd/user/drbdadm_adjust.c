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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include "drbdadm.h"

#define ssprintf(ptr,...) \
  ptr=strcpy(alloca(snprintf(ss_buffer,255,##__VA_ARGS__)+1),ss_buffer) 


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

static struct d_option* find_opt(struct d_option* base,char* name)
{
  while(base) {
    if(!strcmp(base->name,name)) {
      base->mentioned=1;
      return base;
    }
    base=base->next;
  }
  return 0;
}


int adm_adjust(struct d_resource* res,char* unused)
{
  char* argv[20];
  int rv,pid,argc=0;
  FILE *in;
  char str1[255],str2[255];
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
  rv=fscanf(in," size = %s KB\n",str1);
  if(rv) {
    o=find_opt(res->disk_options,"size");
    if(o) {
      if(strcmp(o->value,str1)) {
	do_resize=1;
      }
    } else {
      do_attach=1;
    }
  }
  rv=fscanf(in," do-pani%[c]\n",uu); // 1 == SUCCESS
  if(rv) {
    o=find_opt(res->disk_options,"do-panic");
    if(!o) do_attach=1;
  }

  // check if every option was mentioned.

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

  rv=fscanf(in,"Net options%[:]\n",uu); // rv=1
  rv=fscanf(in,"Syncer options%[:]\n",uu); // rv=1
  
  if(do_attach) {
    adm_attach(res,0);
    do_resize=0;
  }
  if(do_resize) adm_generic(res,"resize"); // missing options (!) FIX.
  if(do_connect) adm_connect(res,0);


  // call wait/wait4
  return 0;
}
