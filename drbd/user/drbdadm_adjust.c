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


int adm_adjust(struct d_resource* res,char* unused)
{
  char* argv[20];
  int rv,pid,argc=0;
  FILE *in;
  char* device=NULL;
  char *disk_size,*loc_ip,*loc_port,*rem_ip,*rem_port,*proto;
  char uu[2];

  printf("Not implemented yet.\n");
  return 0;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="show";
  argv[argc++]=0;

  in=m_popen(&pid,argv);

  if(fscanf(in,"Lower device: %*02d:%*02d   (%a[^)])\n",&device)!=1) goto err;
  if(fscanf(in,"Disk options%[:]\n",uu)!=1) goto err;
  rv=fscanf(in," disk-size = %as KB\n",&disk_size); // 1 == SUCCESS
  rv=fscanf(in," do-pani%[c]\n",uu); // 1 == SUCCESS
  if(fscanf(in,"Local address: %a[0-9.]:%as\n",&loc_ip,&loc_port)!=2) goto err;
  if(fscanf(in,"Remote address: %a[0-9.]:%as\n",&rem_ip,&rem_port)!=2)goto err;
  if(fscanf(in,"Wire protocol: %1a[ABC]\n",&proto)!=1) goto err;
  if(fscanf(in,"Net options%[:]\n",uu)!=1) goto err;
  if(fscanf(in,"Syncer options%[:]\n",uu)!=1) goto err;
  
 err:
  free(device);
  return 0;
}
