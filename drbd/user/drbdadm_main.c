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
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>

#include "drbdadm.h"

struct adm_cmd {
  const char* name;
  int (* function)(struct d_resource*,char* );
  char* arg;
  int show_in_usage;
  int res_name_required;
};

extern int yyparse();
extern FILE* yyin;

int adm_attach(struct d_resource* ,char* );
int adm_connect(struct d_resource* ,char* );
int adm_generic(struct d_resource* ,char* );
int adm_resize(struct d_resource* ,char* );
int adm_syncer(struct d_resource* ,char* );
static int adm_up(struct d_resource* ,char* );
extern int adm_adjust(struct d_resource* ,char* );
static int adm_dump(struct d_resource* ,char* );
static int helper_dev(struct d_resource* ,char* );

char ss_buffer[255];
int line=1;
struct d_resource* config;
int config_valid=1;
int dry_run;
char* drbdsetup;
char* setup_opts[10];
int soi=0;
int alarm_raised;

struct option admopt[] = {
  { "dry-run",      no_argument,      0, 'd' },
  { "config-file",  required_argument,0, 'c' },
  { "drbdsetup",    required_argument,0, 's' },
  { 0,              0,                0, 0   } 
};

struct adm_cmd cmds[] = {
  { "attach",            adm_attach,  0                  ,1,1 },
  //{ "detach",            adm_generic, "??missing??"    ,1,1 },  
  { "connect",           adm_connect, 0                  ,1,1 },
  { "disconnect",        adm_generic, "disconnect"       ,1,1 },
  { "up",                adm_up,      0                  ,1,1 },
  { "down",              adm_generic, "down"             ,1,1 },
  { "primary",           adm_generic, "primary"          ,1,1 },
  { "secondary",         adm_generic, "secondary"        ,1,1 },
  { "secondary_remote",  adm_generic, "secondary_remote" ,1,1 },
  { "invalidate",        adm_generic, "invalidate"       ,1,1 },
  { "invalidate_remote", adm_generic, "invalidate_remote",1,1 },
  { "resize",            adm_resize,  0                  ,1,1 },
  { "syncer",            adm_syncer,  0                  ,1,1 },
  { "adjust",            adm_adjust,  0                  ,1,1 },
  { "dump",              adm_dump,    0                  ,1,1 },
  { "sh-devices",        helper_dev,  0                  ,0,0 },
  //{ "sh-globals",      helper_globals,  0              ,0,0 },
};

#define ARRY_SIZE(A) (sizeof(A)/sizeof(A[0]))

/*** These functions are used to the print the config ***/

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
    if(opts->value) printf("    %s=%s\n",opts->name,opts->value);
    else printf("    %s\n",opts->name);
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

static int adm_dump(struct d_resource* res,char* unused)
{
  printf("resource %s {\n",esc(res->name));
  printf("  protocol=%s\n",res->protocol);
  if(res->ind_cmd) printf("  incon-degr-cmd=%s\n",esc(res->ind_cmd));
  dump_host_info(res->me);
  dump_host_info(res->partner);
  dump_options("net",res->net_options);
  dump_options("disk",res->disk_options);
  dump_options("syncer",res->sync_options);
  printf("}\n\n");
    
  return 1;
}

static int helper_dev(struct d_resource* res,char* unused)
{
  while(1) {
    printf("%s",esc(res->name));
    res=res->next;
    if(res) printf(" ");
    else {
      printf("\n");
      break;
    }
  }

  return 0;
}

static void free_host_info(struct d_host_info* hi)
{
  if(!hi) return;

  free(hi->name);
  free(hi->device);
  free(hi->disk);
  free(hi->address);
  free(hi->port);
}

static void free_options(struct d_option* opts)
{
  struct d_option* f;
  while(opts) {
    free(opts->name);
    free(opts->value);
    f=opts;
    opts=opts->next;
    free(f);
  }
}

static void free_config(struct d_resource* res)
{
  struct d_resource* f;
  while(res) {
    free(res->name);
    free(res->protocol);
    free(res->ind_cmd);
    free_host_info(res->me);
    free_host_info(res->partner);
    free_options(res->net_options);
    free_options(res->disk_options);
    free_options(res->sync_options);
    f=res;
    res=res->next;
    free(f);
  }
}

static void find_drbdsetup(char** pathes)
{
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

static void alarm_handler(int signo)
{
  alarm_raised=1;
}

int m_system(char** argv)
{
  int pid,status;
  int rv=-1;

  struct sigaction so;
  struct sigaction sa;

  sa.sa_handler=&alarm_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags=0;

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

  sigaction(SIGALRM,&sa,&so);
  alarm_raised=0;
  alarm(2);

  while(1) {
    if (waitpid(pid, &status, 0) == -1) {
      if (errno != EINTR) break;
      if (alarm_raised) {
	fprintf(stderr,"Child process does not terminate!\nExiting.\n");
	exit(20);
      }
    } else {
      if(WIFEXITED(status)) {
	rv=WEXITSTATUS(status);
	break;
      }
    }
  }
  
  alarm(0);
  sigaction(SIGALRM,&so,NULL);  

  return rv;
}


#define make_options(OPT) \
  while(OPT) { \
    if(OPT->value) { \
      ssprintf(argv[argc++],"--%s=%s",OPT->name,OPT->value); \
    } else { \
      ssprintf(argv[argc++],"--%s",OPT->name); \
    } \
    OPT=OPT->next; \
  }

int adm_attach(struct d_resource* res,char* unused)
{
  char* argv[20];
  struct d_option* opt;  
  int argc=0;
    
  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="disk";
  argv[argc++]=res->me->disk;
  opt=res->disk_options;
  make_options(opt);
  argv[argc++]=0;

  return m_system(argv);
}

struct d_option* find_opt(struct d_option* base,char* name)
{
  while(base) {
    if(!strcmp(base->name,name)) {
      return base;
    }
    base=base->next;
  }
  return 0;
}

int adm_resize(struct d_resource* res,char* unused)
{
  char* argv[20];
  struct d_option* opt;  
  int argc=0;
    
  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="resize";
  opt=find_opt(res->disk_options,"size");
  ssprintf(argv[argc++],"--%s=%s",opt->name,opt->value);
  argv[argc++]=0;

  return m_system(argv);
}

int adm_generic(struct d_resource* res,char* cmd)
{
  char* argv[20];
  int argc=0,i;
    
  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]=cmd;
  for(i=0;i<soi;i++) {
    argv[argc++]=setup_opts[i];
  }
  argv[argc++]=0;

  return m_system(argv);
}

int adm_connect(struct d_resource* res,char* unused)
{
  char* argv[20];
  struct d_option* opt;  

  int argc=0;
    
  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="net";
  ssprintf(argv[argc++],"%s:%s",res->me->address,res->me->port);
  ssprintf(argv[argc++],"%s:%s",res->partner->address,res->partner->port);
  argv[argc++]=res->protocol;
  opt=res->net_options;
  make_options(opt);
  argv[argc++]=0;

  return m_system(argv);
}

int adm_syncer(struct d_resource* res,char* unused)
{
  char* argv[20];
  struct d_option* opt;  
  int argc=0;
    
  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="syncer";
  opt=res->sync_options;
  make_options(opt);
  argv[argc++]=0;

  return m_system(argv);
}

static int adm_up(struct d_resource* res,char* unused)
{
  int r;
  if( (r=adm_attach(res,unused)) ) return r;
  if( (r=adm_connect(res,unused)) ) return r;
  return adm_syncer(res,unused);
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
  while(opt->name) {
    *c++=opt->val;
    if(opt->has_arg) *c++=':';
    opt++;
  }
  *c=0;
  return buffer;
}

void print_usage(const char* prgname)
{
  int i;
  struct option *opt;

  printf("\nUSAGE: %s [OPTION...] [-- DRBDSETUP-OPTION...] COMMAND "
	 "{ALL|RESOURCE...}\n\n"
	 "OPTIONS:\n",prgname);

  opt=admopt;
  while(opt->name) {
    if(opt->has_arg == required_argument) 
      printf(" {--%s|-%c} val\n",opt->name,opt->val);
    else 
      printf(" {--%s|-%c}\n",opt->name,opt->val);
    opt++;
  }

  printf("\nCOMMANDS:\n");
  
  for(i=0;i<ARRY_SIZE(cmds);i++) {
    if(cmds[i].show_in_usage==0) break;
    if(i%2) {
      printf("%-35s\n",cmds[i].name);      
    } else {
      printf(" %-35s",cmds[i].name);      
    }
  }

  printf("\nVersion: "REL_VERSION" (api:%d)\n",API_VERSION);

  exit(20);
}

int main(int argc, char** argv)
{
  int i;
  struct adm_cmd* cmd;
  struct d_resource* res;

  drbdsetup=NULL;
  dry_run=0;
  yyin=NULL;

  if(argc == 1) print_usage(argv[0]); // arguments missing.

  optind=0;
  while(1)
    {  
      int c;
	  
      c = getopt_long(argc,argv,make_optstring(admopt),admopt,0);
      if(c == -1) break;
      switch(c)
	{
	case 'd':
	  dry_run=1;
	  break;
	case 'c':
	  if(!strcmp(optarg,"-")) { 
	    yyin=stdin; 
	  } else {
	    yyin=fopen(optarg,"r");
	    if(!yyin) {
	      fprintf(stderr,"Can not open '%s'.\n.",optarg);
	      exit(20);
	    }
	  }
	  break;
	case 's':
	  {
	    char* pathes[2];
	    pathes[0]=optarg;
	    pathes[1]=0;
	    find_drbdsetup(pathes);
	  }
	  break;
	case '?':
	  fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	  return 20;
	  break;
	}
    }

  if(yyin==NULL) {
    yyin = fopen("/etc/drbd-07.conf","r");
    if(yyin == 0) {
      yyin = fopen("/etc/drbd.conf","r");
      if(yyin == 0) {
	fprintf(stderr,"Can not open '/etc/drbd.conf'.\n.");
	exit(20);	
      }
    }
  }

  yyparse();

  if(drbdsetup == NULL) {
    find_drbdsetup((char *[]){"/sbin/drbdsetup", "./drbdsetup", 0 });
  }

  if(!config_valid) exit(10);

  if (optind == argc) print_usage(argv[0]);

  while(argv[optind][0]=='-') {
    setup_opts[soi++]=argv[optind++];
    if (optind == argc) print_usage(argv[0]);
  }

  cmd=NULL;
  for(i=0;i<ARRY_SIZE(cmds);i++) {
      if(!strcmp(cmds[i].name,argv[optind])) {
	cmd=cmds+i;
      }
  }

  if(cmd==NULL) {
    fprintf(stderr,"Unknown command '%s'.\n",argv[optind]);
    exit(20);	
  }
  optind++;

  if(cmd->res_name_required) 
    {
      if (optind+1 > argc) print_usage(argv[0]); // arguments missing.

      if(!strcmp(argv[optind],"all")) {
	res=config;
	while(res) {
	  cmd->function(res,cmd->arg);
	  res=res->next;
	}
      } else {
	int i;
	res=config;
	while(res) {
	  for(i=optind;i<argc;i++) {
	    if(!strcmp(argv[i],res->name)) cmd->function(res,cmd->arg);
	  }
	  res=res->next;
	}    
      }
    } else { // Commands which does not need a resource name
      cmd->function(config,cmd->arg);
    }

  free_config(config);

  return 0;
}

void yyerror(char* text)
{
  printf("%s in %d of config file.\n",text,line);
  exit(20); 
}
