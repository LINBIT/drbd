/*
   drbdadm_main.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2002-2004, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

   Copyright (C) 2003-2004, Lars Ellenberg <l.g.e@web.de>
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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <search.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include "drbdtool_common.h"
#include "drbdadm.h"

static int indent = 0;
#define INDENT_WIDTH 4
#define BFMT  "%s;\n"
#define IPFMT "%-16s %s:%s;\n"
#define MDISK "%-16s %s [%s];\n"
#define FMDISK "%-16s %s;\n"
#define printI(fmt, args... ) printf("%*s" fmt,INDENT_WIDTH * indent,"" , ## args )
#define printA(name, val ) \
	printf("%*s%*s %3s;\n", \
	  INDENT_WIDTH * indent,"" , \
	  -24+INDENT_WIDTH * indent, \
	  name, val )

char* progname;

struct adm_cmd {
  const char* name;
  int (* function)(struct d_resource*,const char* );
  unsigned int show_in_usage     :3;
  unsigned int res_name_required :1;
  unsigned int verify_ips        :1;
};

struct deferred_cmd
{
  int (* function)(struct d_resource*,const char* );
  struct d_resource* res;
  struct deferred_cmd* next;
};

extern int yyparse();
extern int yydebug;
extern FILE* yyin;

int adm_attach(struct d_resource* ,const char* );
int adm_connect(struct d_resource* ,const char* );
int adm_generic_s(struct d_resource* ,const char* );
int adm_generic_l(struct d_resource* ,const char* );
int adm_resize(struct d_resource* ,const char* );
int adm_syncer(struct d_resource* ,const char* );
static int adm_up(struct d_resource* ,const char* );
extern int adm_adjust(struct d_resource* ,const char* );
static int adm_dump(struct d_resource* ,const char* );
static int adm_wait_c(struct d_resource* ,const char* );
static int adm_wait_ci(struct d_resource* ,const char* );
static int sh_resources(struct d_resource* ,const char* );
static int sh_mod_parms(struct d_resource* ,const char* );
static int sh_dev(struct d_resource* ,const char* );
static int sh_ll_dev(struct d_resource* ,const char* );
static int sh_md_dev(struct d_resource* ,const char* );
static int sh_md_idx(struct d_resource* ,const char* );
static int admm_generic(struct d_resource* ,const char* );
static int adm_khelper(struct d_resource* ,const char* );
static int adm_generic_b(struct d_resource* ,const char* );
static int hidden_cmds(struct d_resource* ,const char* );

char ss_buffer[255];
struct utsname nodeinfo;
int line=1;
int fline, c_resource_start;
struct d_globals global_options = { 0, 0, 0, 1, UC_ASK };
char *config_file = NULL;
struct d_resource* config = NULL;
struct d_resource* common = NULL;
int nr_resources;
int highest_minor;
int config_valid=1;
int dry_run;
int do_verify_ips;
char* drbdsetup;
char* drbdmeta;
char* setup_opts[10];
int soi=0;
volatile int alarm_raised;

struct deferred_cmd *deferred_cmds[3] = { NULL, NULL, NULL };

void schedule_dcmd( int (* function)(struct d_resource*,const char* ),
		    struct d_resource* res,
		    int order)
{
  struct deferred_cmd *d;

  if( (d = malloc(sizeof(struct deferred_cmd))) == NULL) 
    {
      perror("malloc");
      exit(E_exec_error);
    }

  d->function = function;
  d->res = res;
  d->next = deferred_cmds[order];

  deferred_cmds[order] = d;
}

int _run_dcmds(struct deferred_cmd *d)
{
  int rv;
  if(d == NULL) return 0;

  if(d->next == NULL) 
    {
      rv = d->function(d->res,NULL);
      free(d);
      return rv;
    }

  rv = _run_dcmds(d->next);
  if(!rv) rv |= d->function(d->res,NULL);
  free(d);

  return rv;
}

int run_dcmds(void)
{
  return _run_dcmds(deferred_cmds[0]) || 
    _run_dcmds(deferred_cmds[1]) || 
    _run_dcmds(deferred_cmds[2]);
}

struct option admopt[] = {
  { "dry-run",      no_argument,      0, 'd' },
  { "config-file",  required_argument,0, 'c' },
  { "drbdsetup",    required_argument,0, 's' },
  { "drbdmeta",     required_argument,0, 'm' },
  { 0,              0,                0, 0   }
};

struct adm_cmd cmds[] = {
/*   name, function,                  show, needs res, verify_ips */
  { "attach",            adm_attach,    1,1,1 },
  { "detach",            adm_generic_s, 1,1,1 },
  { "connect",           adm_connect,   1,1,1 },
  { "disconnect",        adm_generic_s, 1,1,0 },
  { "up",                adm_up,        1,1,1 },
  { "down",              adm_generic_s, 1,1,0 },
  { "primary",           adm_generic_s, 1,1,1 },
  { "secondary",         adm_generic_s, 1,1,1 },
  { "invalidate",        adm_generic_l, 1,1,1 },
  { "invalidate_remote", adm_generic_l, 1,1,1 },
  { "outdate",           adm_generic_b, 1,1,0 },
  { "resize",            adm_resize,    1,1,1 },
  { "syncer",            adm_syncer,    1,1,1 },
  { "pause-sync",        adm_generic_s, 1,1,1 },
  { "resume-sync",       adm_generic_s, 1,1,1 },
  { "adjust",            adm_adjust,    1,1,1 },
  { "wait_connect",      adm_wait_c,    1,1,1 },
  { "state",             adm_generic_s, 1,1,0 },
  { "cstate",            adm_generic_s, 1,1,1 },
  { "dstate",            adm_generic_b, 1,1,1 },
  { "dump",              adm_dump,      1,1,1 },
  { "create-md",         adm_create_md, 1,1,0 },
  { "show-gi",           adm_generic_b, 1,1,0 },
  { "get-gi",            adm_generic_b, 1,1,0 },
  { "dump-md",           admm_generic,  1,1,0 },
  { "wait_con_int",      adm_wait_ci,   1,0,1 },
  { "hidden-commands",   hidden_cmds,   1,0,0 },
  { "sh-resources",      sh_resources,  2,0,0 },
  { "sh-mod-parms",      sh_mod_parms,  2,0,0 },
  { "sh-dev",            sh_dev,        2,1,0 },
  { "sh-ll-dev",         sh_ll_dev,     2,1,0 },
  { "sh-md-dev",         sh_md_dev,     2,1,0 },
  { "sh-md-idx",         sh_md_idx,     2,1,0 },
  { "pri-on-incon-degr", adm_khelper,   3,1,0 },
  { "pri-lost-after-sb", adm_khelper,   3,1,0 },
  { "outdate-peer",      adm_khelper,   3,1,0 },
  { "set-gi",            admm_generic,  4,1,0 },
  { "suspend-io",        adm_generic_s, 4,1,0 },
  { "resume-io",         adm_generic_s, 4,1,0 },
};

/*** These functions are used to the print the config ***/

static char* esc(char* str)
{
  static char buffer[1024];
  char *ue = str, *e = buffer;

  if (!str || !str[0]) {
	return "\"\"";
  }
  if(strchr(str,' ')||strchr(str,'\t')||strchr(str,'\\')) {
    *e++ = '"';
    while(*ue) {
      if (*ue == '"' || *ue == '\\') {
	  *e++ = '\\';
      }
      if (e-buffer >= 1022) { fprintf(stderr,"string too long.\n"); exit(E_syntax); }
      *e++ = *ue++;
      if (e-buffer >= 1022) { fprintf(stderr,"string too long.\n"); exit(E_syntax); }
    }
    *e++ = '"';
    *e++ = '\0';
    return buffer;
  }
  return str;
}

static void dump_options(char* name,struct d_option* opts)
{
  if(!opts) return;

  printI("%s {\n",name); ++indent;
  while(opts) {
    if(opts->value) printA(opts->name,esc(opts->value));
    else            printI(BFMT,opts->name);
    opts=opts->next;
  }
  --indent;
  printI("}\n");
}

static void dump_global_info()
{
  if (  !global_options.minor_count
     && !global_options.disable_ip_verification
     &&  global_options.dialog_refresh == 1 ) return;
  printI("global {\n"); ++indent;
  if (global_options.disable_ip_verification)
    printI("disable-ip-verification;\n");
  if (global_options.minor_count)
    printI("minor-count %i;\n", global_options.minor_count);
  if (global_options.dialog_refresh != 1)
    printI("dialog-refresh %i;\n", global_options.dialog_refresh);
  --indent; printI("}\n\n");
}

static void dump_common_info()
{
  if(!common) return;
  printI("common {\n"); ++indent;
  dump_options("net",common->net_options);
  dump_options("disk",common->disk_options);
  dump_options("syncer",common->sync_options);
  dump_options("startup",common->startup_options);
  dump_options("handlers",common->handlers);
  --indent; printf("}\n\n");  
}

static void dump_host_info(struct d_host_info* hi)
{
  if(!hi) {
    printI("  # No host section data available.\n");
    return;
  }

  printI("on %s {\n",esc(hi->name)); ++indent;
  printA("device", esc(hi->device));
  printA("disk"  , esc(hi->disk));
  printI(IPFMT,"address"   , hi->address, hi->port);
  if (!strncmp(hi->meta_index,"flex",4))
    printI(FMDISK,"flexible-meta-disk", esc(hi->meta_disk));
  else if (!strcmp(hi->meta_index,"internal"))
    printA("meta-disk", "internal");
  else
    printI(MDISK,"meta-disk", esc(hi->meta_disk), hi->meta_index);
  --indent; printI("}\n");
}

static int adm_dump(struct d_resource* res,const char* unused __attribute((unused)))
{
  printI("resource %s {\n",esc(res->name)); ++indent;
  printA("protocol",res->protocol);
  dump_host_info(res->me);
  dump_host_info(res->peer);
  dump_options("net",res->net_options);
  dump_options("disk",res->disk_options);
  dump_options("syncer",res->sync_options);
  dump_options("startup",res->startup_options);
  dump_options("handlers",res->handlers);
  --indent; printf("}\n\n");

  return 0;
}

static int sh_resources(struct d_resource* ignored __attribute((unused)),const char* unused __attribute((unused)))
{
  struct d_resource *res,*t;
  int first=1;

  for_each_resource(res,t,config) {
    printf(first?"%s":" %s",esc(res->name));
    first=0;
  }
  printf("\n");

  return 0;
}

static int sh_dev(struct d_resource* res,const char* unused __attribute((unused)))
{
  printf("%s\n",res->me->device);

  return 0;
}

static int sh_ll_dev(struct d_resource* res,const char* unused __attribute((unused)))
{
  printf("%s\n",res->me->disk);

  return 0;
}

static int sh_md_dev(struct d_resource* res,const char* unused __attribute((unused)))
{
  char *r;

  if(strcmp("internal",res->me->meta_disk)==0) r = res->me->disk;
  else r = res->me->meta_disk;

  printf("%s\n",r);

  return 0;
}

static int sh_md_idx(struct d_resource* res,const char* unused __attribute((unused)))
{
  printf("%s\n",res->me->meta_index);

  return 0;
}


static int sh_mod_parms(struct d_resource* res __attribute((unused)),const char* unused __attribute((unused)))
{
  int mc=global_options.minor_count;

  if(global_options.disable_io_hints) printf("disable_io_hints=1 ");
  printf("minor_count=%d\n",mc ?: (highest_minor+1) );
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
    free_host_info(f->me);
    free_host_info(f->peer);
    free_options(f->net_options);
    free_options(f->disk_options);
    free_options(f->sync_options);
    free_options(f->startup_options);
    free_options(f->handlers);
    free(f);
  }
  if(common) {
    free_options(common->net_options);
    free_options(common->disk_options);
    free_options(common->sync_options);
    free_options(common->startup_options);
    free_options(common->handlers);
    free(common);
  }
}

static void expand_opts(struct d_option* co, struct d_option** opts)
{
  struct d_option* no;

  while(co) {
    if(!find_opt(*opts,co->name)) {
      // prepend new item to opts
      no = malloc(sizeof(struct d_option));
      no->name = strdup(co->name);
      no->value = co->value ? strdup(co->value) : NULL ;
      no->next = *opts;
      *opts = no;
    }
    co=co->next;
  }
}

static void expand_common(void)
{
  struct d_resource *res,*tmp;

  if(!common) return;

  for_each_resource(res,tmp,config) {
    expand_opts(common->net_options,     &res->net_options);
    expand_opts(common->disk_options,    &res->disk_options);
    expand_opts(common->sync_options,    &res->sync_options);
    expand_opts(common->startup_options, &res->startup_options);
    expand_opts(common->handlers,        &res->handlers);
  }
}

static void find_drbdcmd(char** cmd, char** pathes)
{
  char **path;

  path=pathes;
  while(*path) {
    if(access(*path,X_OK)==0) {
      *cmd=*path;
      return;
    }
    path++;
  }

  fprintf(stderr,"Can not find command (drbdsetup/drbdmeta)\n");
  exit(E_exec_error);
}

static void alarm_handler(int __attribute((unused)) signo)
{
  alarm_raised=1;
}

pid_t m_system(char** argv,int flags)
{
  pid_t pid;
  int status,rv=-1;
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
    fprintf(stderr,"Can not fork\n");
    exit(E_exec_error);
  }
  if(pid == 0) {
    if(flags & SUPRESS_STDERR) fclose(stderr);
    execvp(argv[0],argv);
    fprintf(stderr,"Can not exec\n");
    exit(E_exec_error);
  }

  if( flags & SLEEPS_FINITE ) {
    int timeout;
    sigaction(SIGALRM,&sa,&so);
    alarm_raised=0;
    switch(flags & SLEEPS_MASK) {
    case SLEEPS_SHORT:     timeout = 5; break;
    case SLEEPS_LONG:      timeout = 120; break;
    case SLEEPS_VERY_LONG: timeout = 600; break;
    default:
	fprintf(stderr,"logic bug in %s:%d\n",__FILE__,__LINE__);
	exit(E_thinko);
    }
    alarm(timeout);
  }

  if( flags == RETURN_PID ) {
    return pid;
  }

  while(1) {
    if (waitpid(pid, &status, 0) == -1) {
      if (errno != EINTR) break;
      if (alarm_raised) {
	fprintf(stderr,"Child process does not terminate!\nExiting.\n");
	exit(E_exec_error);
      } else {
	fprintf(stderr,"logic bug in %s:%d\n",__FILE__,__LINE__);
	exit(E_exec_error);
      }
    } else {
      if(WIFEXITED(status)) {
	rv=WEXITSTATUS(status);
	break;
      }
    }
  }

  if( flags & SLEEPS_FINITE ) {
    alarm(0);
    sigaction(SIGALRM,&so,NULL);
    if(rv >= 10 && !(flags & (DONT_REPORT_FAILED|SUPRESS_STDERR))) {
      fprintf(stderr,"Command '");
      while(*argv) {
	fprintf(stderr,"%s",*argv++);
	if (*argv) fputc(' ',stderr);
      }
      fprintf(stderr,"' terminated with exit code %d\n",rv);
    }
  }

  return rv;
}


#define make_options(OPT) \
  while(OPT) { \
    if (argc>=20) {\
      fprintf(stderr,"logic bug in %s:%d\n",__FILE__,__LINE__); \
      exit(E_thinko); \
    } \
    if(OPT->value) { \
      ssprintf(argv[argc++],"--%s=%s",OPT->name,OPT->value); \
    } else { \
      ssprintf(argv[argc++],"--%s",OPT->name); \
    } \
    OPT=OPT->next; \
  }

int adm_attach(struct d_resource* res,const char* unused __attribute((unused)))
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

  return m_system(argv,SLEEPS_LONG);
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

int adm_resize(struct d_resource* res,const char* unused __attribute((unused)))
{
  char* argv[20];
  struct d_option* opt;
  int i,argc=0;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="resize";
  opt=find_opt(res->disk_options,"size");
  if(opt) ssprintf(argv[argc++],"--%s=%s",opt->name,opt->value);
  for(i=0;i<soi;i++) {
    argv[argc++]=setup_opts[i];
  }
  argv[argc++]=0;

  return m_system(argv,SLEEPS_SHORT);
}

int _admm_generic(struct d_resource* res ,const char* cmd, int flags)
{
  char* argv[20];
  int argc=0,i;

  argv[argc++]=drbdmeta;
  argv[argc++]=res->me->device;
  argv[argc++]="v08";
  if(!strcmp(res->me->meta_disk,"internal")) {
    argv[argc++]=res->me->disk;
  } else {
    argv[argc++]=res->me->meta_disk;
  }
  if(!strcmp(res->me->meta_index,"flexible")) {
	if(!strcmp(res->me->meta_disk,"internal")) {
		argv[argc++]="flex-internal";
	} else {
		argv[argc++]="flex-external";
	}
  } else {
	  argv[argc++]=res->me->meta_index;
  }
  argv[argc++]=(char*)cmd;
  for(i=0;i<soi;i++) {
    argv[argc++]=setup_opts[i];
  }

  argv[argc++]=0;

  return m_system(argv,flags);
}

static int admm_generic(struct d_resource* res ,const char* cmd)
{
  return _admm_generic(res, cmd, SLEEPS_VERY_LONG);
}

static int adm_generic(struct d_resource* res,const char* cmd,int flags)
{
  char* argv[20];
  int argc=0,i;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]=(char*)cmd;
  for(i=0;i<soi;i++) {
    argv[argc++]=setup_opts[i];
  }
  argv[argc++]=0;

  return m_system(argv,flags);
}

int adm_generic_s(struct d_resource* res,const char* cmd)
{
  return adm_generic(res,cmd,SLEEPS_SHORT);
}

int adm_generic_l(struct d_resource* res,const char* cmd)
{
  return adm_generic(res,cmd,SLEEPS_LONG);
}

static int adm_generic_b(struct d_resource* res,const char* cmd)
{
  int rv;

  rv=adm_generic(res,cmd,SLEEPS_SHORT|SUPRESS_STDERR);
  if(rv == 17) return rv; 
  // 17 returned by drbdsetup outdate, if it is already primary.

  if( rv || dry_run ) {
    rv = admm_generic(res,cmd);
  }
  return rv;
}

static char* get_opt_val(struct d_option*,const char*,char*);

static int adm_khelper(struct d_resource* res ,const char* cmd)
{
  int rv=0;
  char *sh_cmd;
  char *argv[] = { "/bin/sh", "-c", NULL , NULL };

  setenv("DRBD_RESOURCE",res->name,1);

  if( (sh_cmd = get_opt_val(res->handlers,cmd,NULL)) ) {
    argv[2]=sh_cmd;
    rv = m_system(argv,SLEEPS_VERY_LONG);
  }
  return rv;
}

// need to convert discard-node-nodename to discard-local or discard-remote.
void convert_discard_opt(struct d_resource* res)
{
  struct d_option* opt;

  if ( (opt = find_opt(res->net_options, "after-sb-0pri")) ) {
    if(!strncmp(opt->value,"discard-node-",13)) {
      if(!strcmp(nodeinfo.nodename,opt->value+13)) {
	free(opt->value);
	opt->value=strdup("discard-local");
      } else {
	free(opt->value);
	opt->value=strdup("discard-remote");
      }
    }
  }
}

int adm_connect(struct d_resource* res,const char* unused __attribute((unused)))
{
  char* argv[20];
  struct d_option* opt;
  int i;
  int argc=0;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="net";
  ssprintf(argv[argc++],"%s:%s",res->me->address,res->me->port);
  ssprintf(argv[argc++],"%s:%s",res->peer->address,res->peer->port);
  argv[argc++]=res->protocol;

  convert_discard_opt(res);

  opt=res->net_options;
  make_options(opt);

  for(i=0;i<soi;i++) {
    argv[argc++]=setup_opts[i];
  }

  argv[argc++]=0;

  return m_system(argv,SLEEPS_SHORT);
}

struct d_resource* res_by_name(const char *name);

// Need to convert after from resourcename to minor_number.
void convert_after_option(struct d_resource* res)
{
  struct d_option* opt;

  if ( (opt = find_opt(res->sync_options, "after")) ) {
    char *ptr;
    ssprintf(ptr,"%d",dt_minor_of_dev(res_by_name(opt->value)->me->device));
    free(opt->value);
    opt->value=strdup(ptr);
  }
}

int adm_syncer(struct d_resource* res,const char* unused __attribute((unused)))
{
  char* argv[20];
  struct d_option* opt;
  int argc=0;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="syncer";

  convert_after_option(res);

  opt=res->sync_options;
  make_options(opt);
  argv[argc++]=0;

  return m_system(argv,SLEEPS_SHORT);
}

static int adm_up(struct d_resource* res,const char* unused __attribute((unused)))
{
  schedule_dcmd(adm_attach,res,0);
  schedule_dcmd(adm_syncer,res,1);
  schedule_dcmd(adm_connect,res,2);

  return 0;
}

static int adm_wait_c(struct d_resource* res ,const char* unused __attribute((unused)))
{
  char* argv[20];
  struct d_option* opt;
  int argc=0,rv;

  argv[argc++]=drbdsetup;
  argv[argc++]=res->me->device;
  argv[argc++]="wait_connect";
  opt=res->startup_options;
  make_options(opt);
  argv[argc++]=0;

  rv = m_system(argv,SLEEPS_FOREVER);
  
  return rv;
}

struct d_resource* res_by_minor(const char *id)
{
  struct d_resource *res,*t;
  int mm;
  if(strncmp(id,"minor-",6)) return NULL;
  
  mm = m_strtoll(id+6,1);

  for_each_resource(res,t,config) {
    if( mm == dt_minor_of_dev(res->me->device)) return res;
  }
  return NULL;
}

struct d_resource* res_by_name(const char *name)
{
  struct d_resource *res,*t;

  for_each_resource(res,t,config) {
    if( strcmp(name,res->name) == 0 ) return res;
  }
  return NULL;
}

/* In case a child exited, or exits, its return code is stored as
   negative number in the pids[i] array */
static int childs_running(pid_t* pids,int opts)
{
  int i=0,wr,rv=0,status;

  for(i=0;i<nr_resources;i++) {
    if(pids[i]<=0) continue;
    wr = waitpid(pids[i], &status, opts);
    if( wr == -1) {            // Wait error.
      if (errno == ECHILD) {
	printf("No exit code for %d\n",pids[i]);
	pids[i] = 0;           // Child exited before ?
	continue;
      }
      perror("waitpid");
      exit(E_exec_error);
    }
    if( wr == 0 ) rv = 1;      // Child still running.
    if( wr > 0 ) {
      pids[i] = 0;
      if( WIFEXITED(status) ) pids[i] = -WEXITSTATUS(status);
      if( WIFSIGNALED(status) ) pids[i] = -1000;
    }
  }
  return rv;
}

static void kill_childs(pid_t* pids)
{
  int i;

  for(i=0;i<nr_resources;i++) {
    if(pids[i]<=0) continue;
    kill(pids[i],SIGINT);
  }
}

/*
  returns:
  -1 ... all childs terminated
   0 ... timeout expired
   1 ... a string was read
 */
int gets_timeout(pid_t* pids, char* s, int size, int timeout)
{
  int pr,rr,n=0;
  struct pollfd pfd;

  if(s) {
    pfd.fd = fileno(stdin);
    pfd.events = POLLIN | POLLHUP | POLLERR | POLLNVAL;
    n=1;
  }

  if(!childs_running(pids,WNOHANG)) {
    pr = -1;
    goto out;
  }

  do {
    pr = poll(&pfd, n, timeout);

    if( pr == -1 ) {   // Poll error.
      if (errno == EINTR) {
	if(childs_running(pids,WNOHANG)) continue;
	goto out; // pr = -1 here.
      }
      perror("poll");
      exit(E_exec_error);
    }
  } while(pr == -1);
  
  if( pr == 1 ) {  // Input available.
    rr = read(fileno(stdin),s,size-1);
    if(rr == -1) {
      perror("read");
      exit(E_exec_error);
    }
    s[rr]=0;
  }

 out:
   return pr;
}

static char* get_opt_val(struct d_option* base,const char* name,char* def)
{
  while(base) {
    if(!strcmp(base->name,name)) {
      return base->value;
    }
    base=base->next;
  }
  return def;
}

void chld_sig_hand(int __attribute((unused)) unused)
{
  // do nothing. But interrupt systemcalls :)
}

static int check_exit_codes(pid_t* pids)
{
  struct d_resource *res,*t;
  int i=0,rv=0;

  for_each_resource(res,t,config) {
    if (pids[i] == -5 || pids[i] == -1000) {
      pids[i]=0;
    }
    if (pids[i] == -20) rv = 20;
    i++;
  }
  return rv;
}

static int adm_wait_ci(struct d_resource* ignored __attribute((unused)),const char* unused __attribute((unused)))
{
  struct d_resource *res,*t;
  char *argv[20], answer[40];
  pid_t* pids;
  struct d_option* opt;
  int rr,wtime,argc,i=0;
  time_t start;
  int saved_stdin,saved_stdout,fd;

  struct sigaction so,sa;

  saved_stdin = -1;
  saved_stdout = -1;
  if( isatty(fileno(stdin)) == 0 || isatty(fileno(stdout)) == 0 ) {
    fprintf(stderr,"WARN: stdin/stdout is not a TTY; using /dev/console");
    fprintf(stdout,"WARN: stdin/stdout is not a TTY; using /dev/console");
    saved_stdin  = dup(fileno(stdin));
    if( saved_stdin == -1) perror("dup(stdin)");
    saved_stdout = dup(fileno(stdout));
    if( saved_stdin == -1) perror("dup(stdout)");
    fd = open( "/dev/console", O_RDONLY);
    if(fd == -1) perror("open('/dev/console, O_RDONLY)");
    dup2(fd, fileno(stdin) );
    fd = open( "/dev/console", O_WRONLY);
    if(fd == -1) perror("open('/dev/console, O_WRONLY)");
    dup2(fd, fileno(stdout) );
  }

  sa.sa_handler=chld_sig_hand;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags=SA_NOCLDSTOP;
  sigaction(SIGCHLD,&sa,&so);

  pids = alloca( nr_resources * sizeof(pid_t) );

  for_each_resource(res,t,config) {
    argc=0;
    argv[argc++]=drbdsetup;
    argv[argc++]=res->me->device;
    argv[argc++]="wait_connect";
    opt=res->startup_options;
    make_options(opt);
    argv[argc++]=0;

    pids[i++]=m_system(argv,RETURN_PID);
  }

  wtime = global_options.dialog_refresh ?: -1;

  start = time(0);
  for (i = 0; i < 10; i++) {
    // no string, but timeout
    rr = gets_timeout(pids,0,0,1*1000);
    if (rr < 0) break;
    putchar('.');
    fflush(stdout);
    check_exit_codes(pids);
  }

  if(rr == 0) {
    printf("\n***************************************************************\n"
	   " DRBD's startup script waits for the peer node(s) to appear.\n"
	   " - In case this node was already a degraded cluster before the\n"
	   "   reboot the timeout is %s seconds. [degr-wfc-timeout]\n"
	   " - If the peer was available before the reboot the timeout will\n"
	   "   expire after %s seconds. [wfc-timeout]\n"
	   "   (These values are for resource '%s'; 0 sec -> wait forever)\n",
	   get_opt_val(config->startup_options,"degr-wfc-timeout","0"),
	   get_opt_val(config->startup_options,"wfc-timeout","0"),
	   config->name);

    printf(" To abort waiting enter 'yes' [ -- ]:");
    do {
      printf("\e[s\e[31G[%4d]:\e[u",(int)(time(0)-start)); // Redraw sec.
      fflush(stdout);
      rr = gets_timeout(pids,answer,40,wtime*1000);
      check_exit_codes(pids);

      if(rr==1) {
	if(!strcmp(answer,"yes\n")) {
	  kill_childs(pids);
	  childs_running(pids,0);
	  check_exit_codes(pids);
	  rr = -1;
	} else {
	  printf(" To abort waiting enter 'yes' [ -- ]:");
	}
      }
    } while( rr != -1 );
    printf("\n");
  }

  if( saved_stdin != -1 ) {
    dup2(saved_stdin,  fileno(stdin ) );
    dup2(saved_stdout, fileno(stdout) );
  }

  return 0;
}

static void print_cmds(int level)
{
  size_t i;
  int j=0;

  for(i=0;i<ARRY_SIZE(cmds);i++) {
    if(cmds[i].show_in_usage!=level) continue;
    if(j++ % 2) {
      printf("%-35s\n",cmds[i].name);
    } else {
      printf(" %-35s",cmds[i].name);
    }
  }
  if(j % 2) printf("\n");
}

static int hidden_cmds(struct d_resource* ignored __attribute((unused)),
		       const char* ignored2 __attribute((unused)) )
{
  printf("\nThese additional commands might be usefull for writing\n"
	 "nifty shell scripts around drbdadm\n\n");

  print_cmds(2);

  printf("\nThese command are used by the kernel part of DRBD to\n"
	 "invoke user mode helper programs\n\n");

  print_cmds(3);

  printf("\nThese commands ought to be used by experts and developers\n\n");
  
  print_cmds(4);

  printf("\n");

  exit(0);
}

void print_usage_and_exit(const char* addinfo)
{
  struct option *opt;

  printf("\nUSAGE: %s [OPTION...] [-- DRBDSETUP-OPTION...] COMMAND "
	 "{all|RESOURCE...}\n\n"
	 "OPTIONS:\n",progname);

  opt=admopt;
  while(opt->name) {
    if(opt->has_arg == required_argument)
      printf(" {--%s|-%c} val\n",opt->name,opt->val);
    else
      printf(" {--%s|-%c}\n",opt->name,opt->val);
    opt++;
  }

  printf("\nCOMMANDS:\n");

  print_cmds(1);

  printf("\nVersion: "REL_VERSION" (api:%d)\n%s\n",
		  API_VERSION, drbd_buildtag());

  if (addinfo)
      printf("\n%s\n",addinfo);

  exit(E_usage);
}

/* if not verifyable, prints a message to stderr,
 * and sets config_valid = 0 if INVALID_IP_IS_INVALID_CONF is defined */
#define INVALID_IP_IS_INVALID_CONF 0
void verify_ips(struct d_resource* res)
{
  char *my_ip = NULL;
  char *his_ip = NULL;
  char *argv[] = { "/bin/bash", "-c", NULL, "drbdadm:verify_ips", NULL };
  int ex;

  if (global_options.disable_ip_verification) return;
  if (dry_run == 1 || do_verify_ips == 0) return;

  if (!(res && res->me   && res->me->address
	    && res->peer && res->peer->address)) {
    fprintf(stderr, "OOPS, no resource info in verify_ips!\n");
    exit(E_config_invalid);
  }
  my_ip  = res->me->address;
  his_ip = res->peer->address;

  ex = asprintf(&argv[2],
	"IP=%s; IP=${IP//./\\\\.};"
	"LANG=; PATH=/sbin/:$PATH;"
	"if   type -p ip       ; then"
	"  ip addr show | grep -qE 'inet '$IP'[ /]';"
	"elif type -p ifconfig ; then"
	"  ifconfig | grep -qE ' inet addr:'$IP' ';"
	"else"
	"  echo >&2 $0: 'neither ip nor ifconfig found!';"
	"fi >/dev/null",
	my_ip);
  if (ex < 0) { perror("asprintf"); exit(E_thinko); }
  ex = m_system(argv,SLEEPS_SHORT|DONT_REPORT_FAILED);
  free(argv[2]); argv[2] = NULL;

  if (ex != 0) {
    ENTRY e, *ep;
    e.key = e.data = ep = NULL;
    asprintf(&e.key,"%s:%s",my_ip,res->me->port);
    ep = hsearch(e, FIND);
    fprintf(stderr, "%s:%d: in resource %s, on %s:\n\t"
		    "IP %s not found on this host.\n",
	    config_file,(int)(long)ep->data,res->name, res->me->name,my_ip);
    if (INVALID_IP_IS_INVALID_CONF)
	    config_valid = 0;
    free(e.key);
    return;
  }

#if 1
/* seems to not work as expected with aliases.
 * maybe drop it completely and trust the admin.
 */
  ex = asprintf(&argv[2],
	"IP=%s; IPQ=${IP//./\\\\.};"
	"peerIP=%s; peerIPQ=${peerIP//./\\\\.};"
	"LANG=; PATH=/sbin/:$PATH;"
	"if type -p ip ; then "
	"  ip -o route get to $peerIP from $IP 2>/dev/null |"
	"    grep -qE ^$peerIPQ' from '$IPQ' ';"
	/* "else"
	 * "  echo >&2 $0: 'cannot check route to peer';" */
	"fi >/dev/null",
	my_ip,his_ip);
  if (ex < 0) { perror("asprintf"); exit(E_thinko); }
  ex = m_system(argv,SLEEPS_SHORT);
  free(argv[2]); argv[2] = NULL;
  if (ex != 0) {
    ENTRY e, *ep;
    e.key = e.data = ep = NULL;
    asprintf(&e.key,"%s:%s",his_ip,res->peer->port);
    ep = hsearch(e, FIND);
    fprintf(stderr, "%s:%d: in resource %s:\n\tNo route from me (%s) to peer (%s).\n",
	    config_file,(int)(long)ep->data,res->name, my_ip, his_ip);
    if (INVALID_IP_IS_INVALID_CONF)
	    config_valid = 0;
    return;
  }
#endif

  return;
}

static char* conf_file[] = {
    "/etc/drbd-08.conf",
    "/etc/drbd.conf",
    0
};

/* FIXME
 * strictly speaking we don't need to check for uniqueness of disk and device names,
 * but for uniqueness of their major:minor numbers ;-)
 */

int check_uniq(const char* what, const char *fmt, ...)
{
  va_list ap;
  int rv;
  ENTRY e, *ep;
  e.key = e.data = ep = NULL;

  va_start(ap, fmt);
  rv=vasprintf(&e.key,fmt,ap);
  va_end(ap);

  if (rv < 0) { perror("vasprintf"); exit(E_thinko); }

  if (EXIT_ON_CONFLICT && !what) {
    fprintf(stderr,"Oops, unset argument in %s:%d.\n", __FILE__ , __LINE__ );
    exit(E_thinko);
  }
  e.data = (void*)(long)fline;
  ep = hsearch(e, FIND);
  // fprintf(stderr,"%s: FIND %s: %p\n",res->name,e.key,ep);
  if (ep) {
    if (what) {
      fprintf(stderr,
	      "%s:%d: conflicting use of %s '%s' ...\n"
	      "%s:%d: %s '%s' first used here.\n",
	      config_file, line, what, ep->key,
	      config_file, (int)(long)ep->data, what, ep->key );
    }
    free(e.key);
    config_valid = 0;
  } else {
    ep = hsearch(e, ENTER);
    // fprintf(stderr,"%s: ENTER %s as %s: %p\n",res->name,e.key,ep->key,ep);
    if (!ep) {
      fprintf(stderr, "entry failed.\n");
      exit(E_thinko);
    }
    ep = NULL;
  }
  if (EXIT_ON_CONFLICT && ep) exit(E_config_invalid);
  return !ep;
}

void validate_resource(struct d_resource * res)
{
  if (!res->protocol) {
    fprintf(stderr,
	    "%s:%d: in resource %s:\n\tprotocol definition missing.\n",
	    config_file, c_resource_start, res->name);
    config_valid = 0;
  } else {
    res->protocol[0] = toupper(res->protocol[0]);
  }
  if (!res->me) {
    fprintf(stderr,
	    "%s:%d: in resource %s:\n\tmissing section 'on %s { ... }'.\n",
	    config_file, c_resource_start, res->name, nodeinfo.nodename);
    config_valid = 0;
  }
  if (!res->peer) {
    fprintf(stderr,
	    "%s:%d: in resource %s:\n\t"
	    "missing section 'on <PEER> { ... }'.\n",
	    config_file, c_resource_start, res->name);
    config_valid = 0;
  }
  if (res->me && res->peer) {
    verify_ips(res);
  }
}

static void global_validate(void)
{
  struct d_resource *res,*tmp;
  struct d_option* opt;

  for_each_resource(res,tmp,config) {

    // need to verify that in the "after" key words only valid resources
    // are named.
    if ( (opt = find_opt(res->sync_options, "after")) ) {
      if( res_by_name(opt->value) == NULL ) {
	fprintf(stderr,
		" in resource %s:\n\t"
		"the resource named '%s' in the after option is "
		"not known.\n\t",
		res->name, opt->value);
	config_valid = 0;
      }
    }

    // need to verify that in the discard-node-nodename options only known
    // nodenames are mentioned.
    if ( (opt = find_opt(res->net_options, "after-sb-0pri")) ) {
      if(!strncmp(opt->value,"discard-node-",13)) {
	if(strcmp(res->peer->name,opt->value+13) &&
	   strcmp(res->me->name,opt->value+13)) {
	  fprintf(stderr,
		  " in resource %s:\n\t"
		  "the nodename in the '%s' option is "
		  "not known.\n\t"
		  "valid nodenames are: '%s' and '%s'.\n",
		  res->name, opt->value,
		  res->me->name, res->peer->name );
	  config_valid = 0;
	}
      }
    }
  }
}


int main(int argc, char** argv)
{
  size_t i;
  int rv=0;
  struct adm_cmd *cmd;
  struct d_resource *res,*tmp;
  char *env_drbd_nodename = NULL;

  drbdsetup=NULL;
  drbdmeta=NULL;
  dry_run=0;
  yyin=NULL;
  uname(&nodeinfo); /* FIXME maybe fold to lower case ? */

  env_drbd_nodename = getenv("__DRBD_NODE__");
  if (env_drbd_nodename && *env_drbd_nodename) {
    strncpy(nodeinfo.nodename,env_drbd_nodename,sizeof(nodeinfo.nodename)-1);
    nodeinfo.nodename[sizeof(nodeinfo.nodename)-1] = 0;
    fprintf(stderr, "\n"
            "   found __DRBD_NODE__ in environment\n"
            "   PRETENDING that I am >>%s<<\n\n",nodeinfo.nodename);
  }

  if(argc == 1) print_usage_and_exit("missing arguments"); // arguments missing.

  /* in case drbdadm is called with an absolut or relative pathname
   * look for the drbdsetup binary in the same location,
   * otherwise, just let execvp sort it out... */
  if( (progname=strrchr(argv[0],'/')) == 0 ) {
    progname=argv[0];
    drbdsetup = strdup("drbdsetup");
  } else {
    size_t len = strlen(argv[0]) + 1;
    ++progname;
    len += strlen("drbdsetup") - strlen(progname);
    drbdsetup = malloc(len);
    if (drbdsetup) {
      strncpy(drbdsetup, argv[0], (progname - argv[0]));
      strcpy(drbdsetup + (progname - argv[0]), "drbdsetup");
    }
    argv[0] = progname;
  }
  if (drbdsetup == NULL) {
    fprintf(stderr,"could not strdup argv[0].\n");
    exit(E_exec_error);
  }

  opterr=1;
  optind=0;
  while(1)
    {
      int c;

      c = getopt_long(argc,argv,make_optstring(admopt,0),admopt,0);
      if(c == -1) break;
      switch(c)
	{
	case 'd':
	  dry_run++;
	  break;
	case 'c':
	  if(!strcmp(optarg,"-")) {
	    yyin=stdin;
	    ssprintf(config_file,"STDIN");
	  } else {
	    yyin=fopen(optarg,"r");
	    if(!yyin) {
	      fprintf(stderr,"Can not open '%s'.\n.",optarg);
	      exit(E_exec_error);
	    }
	    ssprintf(config_file,"%s",optarg);
	  }
	  break;
	case 's':
	  {
	    char* pathes[2];
	    pathes[0]=optarg;
	    pathes[1]=0;
	    find_drbdcmd(&drbdsetup,pathes);
	  }
	  break;
	case 'm':
	  {
	    char* pathes[2];
	    pathes[0]=optarg;
	    pathes[1]=0;
	    find_drbdcmd(&drbdmeta,pathes);
	  }
	  break;
	case '?':
	  // commented out, since opterr=1
	  //fprintf(stderr,"Unknown option %s\n",argv[optind-1]);
	  fprintf(stderr,"try '%s help'\n",progname);
	  return 20;
	  break;
	}
    }

  if ( optind == argc ) print_usage_and_exit(0);

  while(argv[optind][0]=='-' || argv[optind][0]==':' || 
	isdigit(argv[optind][0]) ) {
    setup_opts[soi++]=argv[optind++];
    if (optind == argc) print_usage_and_exit(0);
  }
  if (optind == argc) print_usage_and_exit(0);

  if(!strcmp("hidden-commands",argv[optind])) {
    // before parsing the configuration file...
    hidden_cmds(NULL,NULL);
    exit(0);
  }

  cmd=NULL;
  for(i=0;i<ARRY_SIZE(cmds);i++) {
      if(!strcmp(cmds[i].name,argv[optind])) {
	cmd=cmds+i;
	break;
      }
  }

  if(cmd==NULL) {
    if (!strncmp("help",argv[optind],5)) print_usage_and_exit(0);
    fprintf(stderr,"Unknown command '%s'.\n",argv[optind]);
    exit(E_usage);
  }
  optind++;
  do_verify_ips = cmd->verify_ips;

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
    exit(E_config_invalid);
  }

  /*
   * for check_uniq: check uniqueness of
   * resource names, ip:port, node:disk and node:device combinations
   * as well as resource:section ...
   * hash table to test for uniqness of these values...
   *  256  (max minors)
   *  *(
   *       2 (host sections) * 4 (res ip:port node:disk node:device)
   *     + 4 (other sections)
   *     + some more,
   *       if we want to check for scoped uniqueness of *every* option
   *   )
   *     since nobody (?) will actually use more than a dozend minors,
   *     this should be more than enough.
   */
  if (!hcreate(256*((2*4)+4))) {
    fprintf(stderr,"Insufficient memory.\n");
    exit(E_exec_error);
  };

  //yydebug = 1;
  yyparse();

  if(!config_valid) exit(E_config_invalid);

  if (config == NULL) {
    fprintf(stderr, "no resources defined!\n");
    exit(0); /* THINK exit here? what code? */
  }

  { /* block for mc to avoid compiler warnings */
    int mc=global_options.minor_count;

    highest_minor=0;
    for_each_resource(res,tmp,config) {
      int m = dt_minor_of_dev(res->me->device);
      if ( m > highest_minor ) highest_minor = m;
      nr_resources++;
    }

    // Just for the case that minor_of_res() returned 0 for all devices.
    if( nr_resources > (highest_minor+1) ) highest_minor=nr_resources-1;

    if( mc && mc<(highest_minor+1) ) {
      fprintf(stderr,"The highest minor you have in your config is %d"
	      "but a minor_count of %d in your config!\n", highest_minor,mc);
      exit(E_usage);
    }
  }

  if(drbdsetup == NULL) {
    find_drbdcmd(&drbdsetup,(char *[]){"./drbdsetup", "/sbin/drbdsetup", 0 });
  }

  if(drbdmeta == NULL) {
    find_drbdcmd(&drbdmeta,(char *[]){"./drbdmeta", "/sbin/drbdmeta", 0 });
  }

  uc_node(global_options.usage_count);

  if(cmd->res_name_required)
    {
      int is_dump = (cmd->function == adm_dump);
      if (optind + 1 > argc && !is_dump)
        print_usage_and_exit("missing arguments"); // arguments missing.

      if(!is_dump) expand_common();

      if ( optind==argc || !strcmp(argv[optind],"all") ) {
        if (is_dump) {
	  dump_global_info();
	  dump_common_info();
	} else {
	  global_validate(); 
	  if(!config_valid) exit(E_config_invalid);
	}
        for_each_resource(res,tmp,config) {
	  if( (rv |= cmd->function(res,cmd->name)) >= 10 ) {
	    fprintf(stderr,"drbdsetup exited with code %d\n",rv);
	    exit(E_exec_error);
	  }
	}
      } else {
	for(i=optind;(int)i<argc;i++) {
	  res = res_by_name(argv[i]);
	  if( !res ) res=res_by_minor(argv[i]);
	  if( !res ) {
	    fprintf(stderr,"'%s' not defined in your config.\n",argv[i]);
	    exit(E_usage);
	  }
	  if( (rv=cmd->function(res,cmd->name)) >= 20 ) {
	    fprintf(stderr,"drbdadm aborting\n");
	    exit(rv);
	  }
	}
      }
    } else { // Commands which do not need a resource name
      if( (rv=cmd->function(config,cmd->name)) >= 10) {
	fprintf(stderr,"drbdsetup exited with code %d\n",rv);
	exit(E_exec_error);
      }
    }

  run_dcmds();

  free_config(config);

  return rv;
}

void yyerror(char* text)
{
  fprintf(stderr,"%s:%d: %s\n",config_file,line,text);
  exit(E_syntax);
}
