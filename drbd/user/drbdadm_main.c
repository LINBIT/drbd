/*
   drbdadm_main.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2002, Philipp Reisner <philipp.reisner@gmx.at>.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "drbdadm.h"

extern int yyparse();
extern FILE* yyin;

/* ssprintf() places the result of the printf in the current stack
   frame and sets ptr to the resulting string. If the current stack
   frame is destroyed (=function returns), the allocated memory is 
   freed automatically */
char ss_buffer[255];
#define ssprintf(ptr,...) \
  ptr=strcpy(alloca(snprintf(ss_buffer,255,##__VA_ARGS__)+1),ss_buffer) 

int line=1;
struct d_resource* config;
int config_valid=1;
int dry_run=0;
char* drbdsetup;

/*** These functions are used to the print the config again ***/

static char* esc(char* str)
{
  static char buffer[1024];

  if(strchr(str,' ')) {
    snprintf(buffer,1024,"\"%s\"",str);
    return buffer;
  }
  return str;
}

static void dump_options(char* name,struct d_option* opts)
{
  if(!opts) return;

  printf("  %s {\n",name);
  while(opts) {
    printf("    %s=%s\n",opts->name,opts->value);
    opts=opts->next;
  }
  printf("  }\n");
}

static void dump_host_info(struct d_host_info* hi)
{
  if(!hi) {
    printf("  # No host section data available.\n");
    return;
  }

  printf("  on %s {\n",esc(hi->name));
  printf("    device=%s\n",esc(hi->device));
  printf("    disk=%s\n",esc(hi->disk));
  printf("    address=%s\n",hi->address);
  printf("    port=%s\n",hi->port);
  printf("  }\n");
}

static void dump_conf(struct d_resource* res)
{
  while(res) {
    printf("resource %s {\n",esc(res->name));
    printf("  protocol=%s\n",res->protocol);
    if(res->ind_cmd) printf("  incon-degr-cmd=%s\n",esc(res->ind_cmd));
    dump_host_info(res->me);
    dump_host_info(res->partner);
    dump_options("net",res->net_options);
    dump_options("disk",res->disk_options);
    dump_options("syncer",res->sync_options);
    printf("}\n\n");
    res=res->next;
  }
}

static void find_drbdsetup(void)
{
  static char* pathes[] = { "/sbin/drbdsetup", "./drbdsetup", 0 };
  struct stat buf;
  char **path;
  
  path=pathes;
  while(*path) {
    if(stat(*path,&buf)==0) {
      drbdsetup=*path;
      return;
    }
    path++;
  }

  fprintf(stderr,"Can not find drbdsetup");
  exit(20);
}

static int m_system(char** argv)
{
  int pid,status;

  if(dry_run) {
    while(*argv) {
      printf("%s ",*argv++);
    }
    printf("\n");

    return 0;
  }

  pid = fork();
  if(pid == -1) {
    fprintf(stderr,"Can not fork");
    exit(20);    
  }
  if(pid == 0) {
    execv(argv[0],argv);
    fprintf(stderr,"Can not exec");
    exit(20);    
  }
  while(1) {
    if (waitpid(pid, &status, 0) == -1) {
      if (errno != EINTR)
	return -1;
    } else
      return status;    
  }
}

static void conf_disk(struct d_resource* res)
{
  char* argv[20];
  struct d_option* opt;  

  while(res) {
    int argc=0;
    
    argv[argc++]=drbdsetup;
    argv[argc++]=res->me->device;
    argv[argc++]="disk";
    argv[argc++]=res->me->disk;
    opt=res->disk_options;
    while(opt) {
      ssprintf(argv[argc++],"--%s=%s",opt->name,opt->value);
      opt=opt->next;
    }
    argv[argc++]=0;

    m_system(argv);
    res=res->next;
  }
}

static void conf_net(struct d_resource* res)
{
  char* argv[20];
  struct d_option* opt;  

  while(res) {
    int argc=0;
    
    argv[argc++]=drbdsetup;
    argv[argc++]=res->me->device;
    argv[argc++]="net";
    ssprintf(argv[argc++],"%s:%s",res->me->address,res->me->port);
    ssprintf(argv[argc++],"%s:%s",res->partner->address,res->partner->port);
    argv[argc++]=res->protocol;

    opt=res->net_options;
    while(opt) {
      ssprintf(argv[argc++],"--%s=%s",opt->name,opt->value);
      opt=opt->next;
    }

    argv[argc++]=0;

    m_system(argv);
    res=res->next;
  }
}

int main(int argc, char** argv)
{
  
  if(argc>1) 
    {
      yyin = fopen(argv[1],"r");
    }

  yyparse();

  // TODO write real functionality...

  find_drbdsetup(); // setup global variable drbdsetup.
  dump_conf(config);  
  dry_run=1;
  if(!config_valid) exit(10);
  conf_disk(config);
  conf_net(config);

  return 0;
}

void yyerror(char* text)
{
  printf("LEXICAL ERROR in Line %d: %s\n",line,text);
  exit(1); 
}
