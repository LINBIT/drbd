/*
   drbdadm_main.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2002-2003, Philipp Reisner <philipp.reisner@gmx.at>.
        Initial author.

   Copyright (C) 2003, Lars Ellenberg <l.g.e@web.de>
        contributions.

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

#define for_each_resource(res,tmp,config)                 \
	for (res = (config), tmp = 0;                     \
	     ({ tmp != (config) && (tmp = res->next); }); \
	     res = tmp)

#define for_completed(res,tmp,config)                     \
            ( (res) == (tmp) ) 

// basic format
#define INDENT "    "
#define FMT    INDENT "%-12s"
#define BFMT   INDENT FMT "\n"
// assignment format
#define AFMT0 FMT INDENT " = %s\n"
#define AFMT  INDENT FMT " = %s\n"


char* basename;

struct adm_cmd {
  const char* name;
  int (* function)(struct d_resource*,char* );
  char* arg;
  int show_in_usage;
  int res_name_required;
  const char* help;
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
static int adm_wait_c(struct d_resource* ,char* );
static int sh_devices(struct d_resource* ,char* );
static int sh_mod_parms(struct d_resource* ,char* );
static int sh_ll_dev(struct d_resource* ,char* );

char ss_buffer[255];
int line=1;
struct d_globals global_options = { 0, 0 };
char *config_file = NULL;
struct d_resource* config = NULL;
int nr_resources;
int config_valid=1;
int dry_run;
char* drbdsetup;
char* setup_opts[10];
int soi=0;
volatile int alarm_raised;

struct option admopt[] = {
  { "dry-run",      no_argument,      0, 'd' },
  { "config-file",  required_argument,0, 'c' },
  { "drbdsetup",    required_argument,0, 's' },
  { "help",         no_argument,      0, 'h' },
  { 0,              0,                0, 0   }
};

struct adm_cmd cmds[] = {
  { "attach",            adm_attach,  0                  ,1,1, "FIXME attach help" },
  { "detach",            adm_generic, "detach"           ,1,1, "FIXME detach help" },
  { "connect",           adm_connect, 0                  ,1,1, "FIXME connect help" },
  { "disconnect",        adm_generic, "disconnect"       ,1,1, "FIXME disconnect help" },
  { "up",                adm_up,      0                  ,1,1, "FIXME up help" },
  { "down",              adm_generic, "down"             ,1,1, "FIXME down help" },
  { "primary",           adm_generic, "primary"          ,1,1, "FIXME primary help" },
  { "secondary",         adm_generic, "secondary"        ,1,1, "FIXME secondary help" },
  { "invalidate",        adm_generic, "invalidate"       ,1,1, "FIXME invalidate help" },
  { "invalidate_remote", adm_generic, "invalidate_remote",1,1, "FIXME invalidate_remote help" },
  { "resize",            adm_resize,  0                  ,1,1, "FIXME resize help" },
  { "syncer",            adm_syncer,  0                  ,1,1, "FIXME syncer help" },
  { "adjust",            adm_adjust,  0                  ,1,1, "FIXME adjust help" },
  { "wait_connect",      adm_wait_c,  0                  ,1,1, "FIXME wait_connect help" },
  { "dump",              adm_dump,    0                  ,1,1, "FIXME dump help" },
  { "sh-devices",        sh_devices,  0                  ,0,0, "FIXME sh-devices help" },
  { "sh-mod-parms",      sh_mod_parms,0                  ,0,0, "FIXME sh-mod-parms help" },
  { "sh-ll-dev",         sh_ll_dev,   0                  ,0,1, "FIXME sh-ll-dev help" },
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

  printf(INDENT "%s {\n",name);
  while(opts) {
    if(opts->value) printf(AFMT,opts->name,opts->value);
    else printf(BFMT,opts->name);
    opts=opts->next;
  }
  printf(INDENT "}\n");
}

static void dump_global_info()
{
  if (global_options.minor_count || global_options.disable_io_hints)
    {
      printf("global {\n");
      if (global_options.disable_io_hints)
	printf(INDENT "disable_io_hints\n");
      if (global_options.minor_count)
	printf(INDENT "minor_count = %i\n", global_options.minor_count);
      printf("}\n\n");
    }
}

static void dump_host_info(struct d_host_info* hi)
{
  if(!hi) {
    printf("  # No host section data available.\n");
    return;
  }

  printf(INDENT "on %s {\n",esc(hi->name));
  printf(AFMT, "device"    , esc(hi->device));
  printf(AFMT, "disk"      , esc(hi->disk));
  printf(AFMT, "address"   , hi->address);
  printf(AFMT, "port"      , hi->port);
  printf(AFMT, "meta-disk" , esc(hi->meta_disk));
  printf(AFMT, "meta-index", esc(hi->meta_index));
  printf(INDENT "}\n");
}

static int adm_dump(struct d_resource* res,char* unused)
{
  printf("resource %s {\n",esc(res->name));
  printf(AFMT0,"protocol",res->protocol);
  if(res->ind_cmd)
    printf(AFMT0,"incon-degr-cmd",esc(res->ind_cmd));
  dump_host_info(res->me);
  dump_host_info(res->partner);
  dump_options("net",res->net_options);
  dump_options("disk",res->disk_options);
  dump_options("syncer",res->sync_options);
  dump_options("startup",res->startup_options);
  printf("}\n\n");

  return 0;
}

static int sh_devices(struct d_resource* res,char* unused)
{
  while(1) {
    printf("%s",esc(res->name));
    res=res->next;
    if(res != config) printf(" ");
    else {
      printf("\n");
      break;
    }
  }

  return 0;
}

static int sh_ll_dev(struct d_resource* res,char* unused)
{
  printf("%s\n",res->me->disk);

  return 0;
}


static int sh_mod_parms(struct d_resource* res,char* unused)
{
  int mc=global_options.minor_count;

  if(global_options.disable_io_hints) printf("disable_io_hints=1 ");
  printf("minor_count=%d\n",mc ? mc : nr_resources);
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
  free(hi->meta_disk);
  free(hi->meta_index);
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
  struct d_resource *f,*t;
  for_each_resource(f,t,res) {
    free(f->name);
    free(f->protocol);
    free(f->ind_cmd);
    free_host_info(f->me);
    free_host_info(f->partner);
    free_options(f->net_options);
    free_options(f->disk_options);
    free_options(f->sync_options);
    free_options(f->startup_options);
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

int m_system(int may_sleep,char** argv)
{
  int pid,status;
  int rv=-1;
  char **cmdline = argv;

  struct sigaction so;
  struct sigaction sa;

  sa.sa_handler=&alarm_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags=0;

  if(dry_run) {
    while(*cmdline) {
      fprintf(stdout,"%s ",*cmdline++);
    }
    fprintf(stdout,"\n");
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

  if( !may_sleep ) {
    sigaction(SIGALRM,&sa,&so);
    alarm_raised=0;
    alarm(2);
  }

  while(1) {
    if (waitpid(pid, &status, 0) == -1) {
      if (errno != EINTR) break;
      if (alarm_raised) {
	fprintf(stderr,"Child process does not terminate!\nExiting.\n");
	exit(20);
      } else {
	fprintf(stderr,"logic bug in %s:%d\n",__FILE__,__LINE__);
	exit(20);
      }
    } else {
      if(WIFEXITED(status)) {
	rv=WEXITSTATUS(status);
	break;
      }
    }
  }

  if( !may_sleep ) {
    alarm(0);
    sigaction(SIGALRM,&so,NULL);
  }

  if(!may_sleep && rv) {
    fprintf(stderr,"Command line was '");
    while(*argv) {
      fprintf(stderr,"%s",*argv++);
      if (*argv) fputc(' ',stderr);
    }
    fprintf(stderr,"'\n");
  }

  return rv;
}


#define make_options(OPT) \
  while(OPT) { \
    if (argc>=20) {\
      fprintf(stderr,"logic bug in %s:%d\n",__FILE__,__LINE__); \
      exit(20); \
    } \
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
  argv[argc++]=res->me->meta_disk;
  argv[argc++]=res->me->meta_index;
  opt=res->disk_options;
  make_options(opt);
  argv[argc++]=0;

  return m_system(0,argv);
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
  if(opt) ssprintf(argv[argc++],"--%s=%s",opt->name,opt->value);
  argv[argc++]=0;

  return m_system(0,argv);
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

  return m_system(0,argv);
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

  return m_system(0,argv);
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

  return m_system(0,argv);
}

static int adm_up(struct d_resource* res,char* unused)
{
  int r;
  if( (r=adm_attach(res,unused)) ) return r;
  if( (r=adm_connect(res,unused)) ) return r;
  return adm_syncer(res,unused);
}

static int adm_wait_c(struct d_resource* res ,char* unused)
{
  char* argv[20];
  struct d_option* opt;
  int argc=0;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="wait_connect";
  opt=res->startup_options;
  make_options(opt);
  argv[argc++]=0;

  return m_system(1,argv);
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

void print_cmd_help(struct adm_cmd *cmd)
{
  struct option *opt;

  printf("\nUSAGE: %s [OPTION...] [-- DRBDSETUP-OPTION...] COMMAND "
	 "{all|RESOURCE...}\n\n"
	 "OPTIONS:\n",basename);

  opt=admopt;
  while(opt->name) {
    if(opt->has_arg == required_argument)
      printf(" {--%s|-%c} val\n",opt->name,opt->val);
    else
      printf(" {--%s|-%c}\n",opt->name,opt->val);
    opt++;
  }
  printf("\n%s:\n%s\n",cmd->name,cmd->help);
  exit(20);
}

void print_usage()
{
  int i;
  struct option *opt;

  printf("\nUSAGE: %s [OPTION...] [-- DRBDSETUP-OPTION...] COMMAND "
	 "{all|RESOURCE...}\n\n"
	 "OPTIONS:\n",basename);

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

static char* conf_file[] = {
    "/etc/drbd-07.conf",
    "/etc/drbd.conf",
    0
};

int main(int argc, char** argv)
{
  int i,rv;
  int help = 0;
  struct adm_cmd *cmd;
  struct d_resource *res,*tmp;

  drbdsetup=NULL;
  dry_run=0;
  yyin=NULL;

  if( (basename=strrchr(argv[0],'/')) )
    argv[0] = ++basename;
  else
    basename=argv[0];
  if(argc == 1) print_usage(); // arguments missing.

  opterr=1;
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
	    ssprintf(config_file,"STDIN");
	  } else {
	    yyin=fopen(optarg,"r");
	    if(!yyin) {
	      fprintf(stderr,"Can not open '%s'.\n.",optarg);
	      exit(20);
	    }
	    ssprintf(config_file,"%s",optarg);
	  }
	  break;
	case 'h':
	  print_usage();
	case 's':
	  {
	    char* pathes[2];
	    pathes[0]=optarg;
	    pathes[1]=0;
	    find_drbdsetup(pathes);
	  }
	  break;
	case '?':
	  // commented out, since opterr=1
	  //fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	  return 20;
	  break;
	}
    }

  if ( optind == argc ) print_usage();

  while(argv[optind][0]=='-') {
    setup_opts[soi++]=argv[optind++];
    if (optind == argc) print_usage();
  }
  if (!strcmp(argv[optind],"help")) { help = 1; ++optind; }
  if (optind == argc) print_usage();

  cmd=NULL;
  for(i=0;i<ARRY_SIZE(cmds);i++) {
      if(!strcmp(cmds[i].name,argv[optind])) {
	cmd=cmds+i;
	if (help) print_cmd_help(cmd); // noreturn
	break;
      }
  }

  if(cmd==NULL) {
    fprintf(stderr,"Unknown command '%s'.\n",argv[optind]);
    exit(20);
  }
  optind++;

  if (!config_file) {
    i=0;
    do {
      yyin = fopen(conf_file[i],"r");
      if(yyin != 0) {
	config_file = conf_file[i];
	break;
      }
      if (i) {
	fprintf(stderr,"Can not open '%s': ",conf_file[i]);
	perror("");
      }
    } while (conf_file[++i]);
  }
  if(!config_file) {
    exit(20);
  }

  yyparse();

  if(!config_valid) exit(10);

  { // check if minor_count is sane.
    int mc=global_options.minor_count;

    for_each_resource(res,tmp,config) nr_resources++;

    if( mc && mc<nr_resources ) {
      fprintf(stderr,"You have %d resources but a minor_count of %d in your"
	      " config!\n",nr_resources,mc);
      exit(20);
    }
  }

  if(drbdsetup == NULL) {
    find_drbdsetup((char *[]){"/sbin/drbdsetup", "./drbdsetup", 0 });
  }

  if(cmd->res_name_required)
    {
      if (optind + 1 > argc && cmd->function != adm_dump)
        print_usage (argv[0]);	// arguments missing.

      if(optind==argc || !strcmp(argv[optind],"all")) {
        if (cmd->function == adm_dump) dump_global_info();
        for_each_resource(res,tmp,config) {
	  if( (rv=cmd->function(res,cmd->arg)) ) {
	    fprintf(stderr,"drbdsetup exited with code %d\n",rv);
	    exit(20);
	  }
	}
      } else {
	for(i=optind;i<argc;i++) {
	  struct d_resource *tmp;
	  for_each_resource(res,tmp,config) {
	    if(!strcmp(argv[i],res->name)) goto found;
	  }
	  fprintf(stderr,"'%s' not defined in you config.\n",argv[i]);
	  exit(20);
	found:
	  if( (rv=cmd->function(res,cmd->arg)) ) {
	    fprintf(stderr,"drbdsetup exited with code %d\n",rv);
	    exit(20);
	  }
	}
      }
    } else { // Commands which does not need a resource name
      if( (rv=cmd->function(config,cmd->arg)) ) {
	fprintf(stderr,"drbdsetup exited with code %d\n",rv);
	exit(20);
      }
    }

  free_config(config);

  return 0;
}

void yyerror(char* text)
{
  fprintf(stderr,"%s:%d: %s\n",config_file,line,text);
  exit(20);
}
