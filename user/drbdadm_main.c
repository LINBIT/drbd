/*
   drbdadm_main.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2002-2007, LINBIT Information Technologies GmbH.
   Copyright (C) 2002-2007, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2007, Lars Ellenberg <lars.ellenberg@linbit.com>.

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
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include "drbdtool_common.h"
#include "drbdadm.h"

#define MAX_ARGS 40

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
  unsigned int me_is_localhost   :1;
};

struct deferred_cmd
{
  int (* function)(struct d_resource*,const char* );
  char *arg;
  struct d_resource* res;
  struct deferred_cmd* next;
};

extern int my_parse();
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
static int adm_dump_xml(struct d_resource* ,const char* );
static int adm_wait_c(struct d_resource* ,const char* );
static int adm_wait_ci(struct d_resource* ,const char* );
static int adm_proxy_up(struct d_resource* ,const char* );
static int sh_nop(struct d_resource* ,const char* );
static int sh_resources(struct d_resource* ,const char* );
static int sh_mod_parms(struct d_resource* ,const char* );
static int sh_dev(struct d_resource* ,const char* );
static int sh_ip(struct d_resource* ,const char* );
static int sh_ll_dev(struct d_resource* ,const char* );
static int sh_md_dev(struct d_resource* ,const char* );
static int sh_md_idx(struct d_resource* ,const char* );
static int sh_b_pri(struct d_resource* ,const char* );
static int admm_generic(struct d_resource* ,const char* );
static int adm_khelper(struct d_resource* ,const char* );
static int adm_generic_b(struct d_resource* ,const char* );
static int hidden_cmds(struct d_resource* ,const char* );

static char* get_opt_val(struct d_option*,const char*,char*);

static struct ifreq* get_ifreq();

char ss_buffer[255];
struct utsname nodeinfo;
int line=1;
int fline, c_resource_start;
struct d_globals global_options = { 0, 0, 0, 1, UC_ASK };
char *config_file = NULL;
struct d_resource* config = NULL;
struct d_resource* common = NULL;
struct ifreq *ifreq_list = NULL;
int nr_resources;
int highest_minor;
int config_valid=1;
int no_tty;
int dry_run;
int verbose;
int do_verify_ips;
char* drbdsetup;
char* drbdmeta;
char* drbd_proxy_ctl;
char* setup_opts[10];
int soi=0;
volatile int alarm_raised;

struct deferred_cmd *deferred_cmds[3] = { NULL, NULL, NULL };

void schedule_dcmd( int (* function)(struct d_resource*,const char* ),
		    struct d_resource* res,
		    char* arg,
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
  d->arg = arg;
  d->next = deferred_cmds[order];

  deferred_cmds[order] = d;
}

int _run_dcmds(struct deferred_cmd *d)
{
  int rv;
  if(d == NULL) return 0;

  if(d->next == NULL)
    {
      rv = d->function(d->res,d->arg);
      free(d);
      return rv;
    }

  rv = _run_dcmds(d->next);
  if(!rv) rv |= d->function(d->res,d->arg);
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
  { "verbose",      no_argument,      0, 'v' },
  { "config-file",  required_argument,0, 'c' },
  { "drbdsetup",    required_argument,0, 's' },
  { "drbdmeta",     required_argument,0, 'm' },
  { "drbd-proxy-ctl",required_argument,0,'p' },
  { 0,              0,                0, 0   }
};

struct adm_cmd cmds[] = {
/*   name, function,                  show, needs res, verify_ips, me_localhost */
  { "attach",            adm_attach,    1,1,0,1 },
  { "detach",            adm_generic_s, 1,1,0,1 },
  { "connect",           adm_connect,   1,1,1,1 },
  { "disconnect",        adm_generic_s, 1,1,0,1 },
  { "up",                adm_up,        1,1,1,1 },
  { "down",              adm_generic_s, 1,1,0,1 },
  { "primary",           adm_generic_s, 1,1,0,1 },
  { "secondary",         adm_generic_s, 1,1,0,1 },
  { "invalidate",        adm_generic_b, 1,1,0,1 },
  { "invalidate-remote", adm_generic_l, 1,1,1,1 },
  { "outdate",           adm_generic_b, 1,1,0,1 },
  { "resize",            adm_resize,    1,1,1,1 },
  { "syncer",            adm_syncer,    1,1,1,1 },
  { "pause-sync",        adm_generic_s, 1,1,1,1 },
  { "resume-sync",       adm_generic_s, 1,1,1,1 },
  { "adjust",            adm_adjust,    1,1,1,1 },
  { "wait-connect",      adm_wait_c,    1,1,1,1 },
  { "state",             adm_generic_s, 1,1,0,1 },
  { "cstate",            adm_generic_s, 1,1,1,1 },
  { "dstate",            adm_generic_b, 1,1,1,1 },
  { "dump",              adm_dump,      1,1,1,0 },
  { "dump-xml",          adm_dump_xml,  1,1,1,0 },
  { "create-md",         adm_create_md, 1,1,0,1 },
  { "show-gi",           adm_generic_b, 1,1,0,1 },
  { "get-gi",            adm_generic_b, 1,1,0,1 },
  { "dump-md",           admm_generic,  1,1,0,1 },
  { "wait-con-int",      adm_wait_ci,   1,0,1,1 },
  { "hidden-commands",   hidden_cmds,   1,0,0,0 },
  { "proxy-up",          adm_proxy_up,  2,1,0,0 },
  { "sh-nop",            sh_nop,        2,0,0,0 },
  { "sh-resources",      sh_resources,  2,0,0,0 },
  { "sh-mod-parms",      sh_mod_parms,  2,0,0,0 },
  { "sh-dev",            sh_dev,        2,1,0,0 },
  { "sh-ll-dev",         sh_ll_dev,     2,1,0,0 },
  { "sh-md-dev",         sh_md_dev,     2,1,0,0 },
  { "sh-md-idx",         sh_md_idx,     2,1,0,0 },
  { "sh-ip",             sh_ip,         0,1,0,0 },
  { "sh-b-pri",          sh_b_pri,      2,1,0,0 },
  { "pri-on-incon-degr", adm_khelper,   3,1,0,1 },
  { "pri-lost-after-sb", adm_khelper,   3,1,0,1 },
  { "outdate-peer",      adm_khelper,   3,1,0,1 },
  { "local-io-error",    adm_khelper,   3,1,0,1 },
  { "set-gi",            admm_generic,  4,1,0,1 },
  { "suspend-io",        adm_generic_s, 4,1,0,1 },
  { "resume-io",         adm_generic_s, 4,1,0,1 },
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

static char* esc_xml(char* str)
{
  static char buffer[1024];
  char *ue = str, *e = buffer;

  if (!str || !str[0]) {
	return "";
  }
  if (strchr(str,'"') || strchr(str,'\'') || strchr(str,'<') ||
      strchr(str,'>') || strchr(str,'&') || strchr(str,'\\')) {
    while(*ue) {
      if (*ue == '"' || *ue == '\\') {
	  *e++ = '\\';
          if (e-buffer >= 1021) {
	     fprintf(stderr,"string too long.\n");
	     exit(E_syntax);
	  }
          *e++ = *ue++;
      } else if (*ue == '\'' || *ue == '<' || *ue == '>' || *ue == '&') {
          if (*ue == '\'' && e-buffer < 1017) {
            strcpy(e, "&apos;");
            e += 6;
          } else if (*ue == '<' && e-buffer < 1019) {
            strcpy(e, "&lt;");
            e += 4;
          } else if (*ue == '>' && e-buffer < 1019) {
            strcpy(e, "&gt;");
            e += 4;
          } else if (*ue == '&' && e-buffer < 1018) {
            strcpy(e, "&amp;");
            e += 5;
          } else {
            fprintf(stderr,"string too long.\n");
	    exit(E_syntax);
	  }
	  ue++;
      } else {
          *e++ = *ue++;
          if (e-buffer >= 1022) {
	    fprintf(stderr,"string too long.\n");
	    exit(E_syntax);
	  }
      }
    }
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
  if(common->protocol) printA("protocol",common->protocol);
  dump_options("net",common->net_options);
  dump_options("disk",common->disk_options);
  dump_options("syncer",common->sync_options);
  dump_options("startup",common->startup_options);
  dump_options("proxy",common->proxy_options);
  dump_options("handlers",common->handlers);
  --indent; printf("}\n\n");
}

static void dump_proxy_info(struct d_proxy_info* pi)
{
  printI("proxy on %s {\n",esc(pi->name)); ++indent;
  printI(IPFMT,"inside", pi->inside_addr, pi->inside_port);
  printI(IPFMT,"outside", pi->outside_addr, pi->outside_port);
  --indent; printI("}\n");
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
  if(hi->proxy) dump_proxy_info(hi->proxy);
  --indent; printI("}\n");
}

static void dump_options_xml(char* name,struct d_option* opts)
{
  if(!opts) return;

  printI("<section name=\"%s\">\n",name); ++indent;
  while(opts) {
    if(opts->value) printI("<option name=\"%s\" value=\"%s\"/>\n", opts->name, esc_xml(opts->value));
    else            printI("<option name=\"%s\"/>\n", opts->name);
    opts=opts->next;
  }
  --indent;
  printI("</section>\n");
}

static void dump_global_info_xml()
{
  if (  !global_options.minor_count
     && !global_options.disable_ip_verification
     &&  global_options.dialog_refresh == 1 ) return;
  printI("<global>\n"); ++indent;
  if (global_options.disable_ip_verification)
    printI("<disable-ip-verification/>\n");
  if (global_options.minor_count)
    printI("<minor-count count=\"%i\"/>\n", global_options.minor_count);
  if (global_options.dialog_refresh != 1)
    printI("<dialog-refresh refresh=\"%i\"/>\n", global_options.dialog_refresh);
  --indent; printI("</global>\n");
}

static void dump_common_info_xml()
{
  if(!common) return;
  printI("<common");
  if(common->protocol) printf(" protocol=\"%s\"",common->protocol);
  printf(">\n"); ++indent;
  dump_options_xml("net",common->net_options);
  dump_options_xml("disk",common->disk_options);
  dump_options_xml("syncer",common->sync_options);
  dump_options_xml("startup",common->startup_options);
  dump_options_xml("proxy",common->proxy_options);
  dump_options_xml("handlers",common->handlers);
  --indent; printI("</common>\n");
}

static void dump_proxy_info_xml(struct d_proxy_info* pi)
{
  printI("<proxy hostname=\"%s\">\n",esc_xml(pi->name)); ++indent;
  printI("<inside port=\"%s\">%s</inside>\n", pi->inside_port, pi->inside_addr);
  printI("<outside port=\"%s\">%s</outside>\n", pi->outside_port, pi->outside_addr);
  --indent; printI("</proxy>\n");
}

static void dump_host_info_xml(struct d_host_info* hi)
{
  if(!hi) {
    printI("<!-- No host section data available. -->\n");
    return;
  }

  printI("<host name=\"%s\">\n",esc_xml(hi->name)); ++indent;
  printI("<device>%s</device>\n", esc_xml(hi->device));
  printI("<disk>%s</disk>\n", esc_xml(hi->disk));
  printI("<address port=\"%s\">%s</address>\n", hi->port, hi->address);
  if (!strncmp(hi->meta_index,"flex",4))
    printI("<flexible-meta-disk>%s</flexible-meta-disk>\n", esc_xml(hi->meta_disk));
  else if (!strcmp(hi->meta_index,"internal"))
    printI("<meta-disk>internal</meta-disk>\n");
  else {
    printI("<meta-disk index=\"%s\">%s</meta-disk>\n", hi->meta_index, esc_xml(hi->meta_disk));
  }
  if(hi->proxy) dump_proxy_info_xml(hi->proxy);
  --indent; printI("</host>\n");
}

static int adm_dump(struct d_resource* res,const char* unused __attribute((unused)))
{
  printI("resource %s {\n",esc(res->name)); ++indent;
  if(res->protocol) printA("protocol",res->protocol);
  // else if (common && common->protocol) printA("# common protocol", common->protocol);
  dump_host_info(res->me);
  dump_host_info(res->peer);
  dump_options("net",res->net_options);
  dump_options("disk",res->disk_options);
  dump_options("syncer",res->sync_options);
  dump_options("startup",res->startup_options);
  dump_options("proxy",res->proxy_options);
  dump_options("handlers",res->handlers);
  --indent; printf("}\n\n");

  return 0;
}

static int adm_dump_xml(struct d_resource* res,const char* unused __attribute((unused)))
{
  printI("<resource name=\"%s\"",esc_xml(res->name));
  if(res->protocol) printf(" protocol=\"%s\"",res->protocol);
  printf(">\n"); ++indent;
  // else if (common && common->protocol) printA("# common protocol", common->protocol);
  dump_host_info_xml(res->me);
  dump_host_info_xml(res->peer);
  dump_options_xml("net",res->net_options);
  dump_options_xml("disk",res->disk_options);
  dump_options_xml("syncer",res->sync_options);
  dump_options_xml("startup",res->startup_options);
  dump_options_xml("proxy",res->proxy_options);
  dump_options_xml("handlers",res->handlers);
  --indent; printI("</resource>\n");

  return 0;
}

static int sh_nop(struct d_resource* ignored __attribute((unused)),
		  const char* unused __attribute((unused)))
{
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

static int sh_ip(struct d_resource* res,const char* unused __attribute((unused)))
{
  printf("%s\n",res->me->address);

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

static int sh_b_pri(struct d_resource *res,const char* unused __attribute((unused)))
{
  char* val;

  val = get_opt_val(res->startup_options, "become-primary-on", NULL);
  if ( val && ( !strcmp(val,nodeinfo.nodename) ||
		!strcmp(val,"both") ) ) {
    return adm_generic_s(res,"primary");
  }
  return 0;
}

static int sh_mod_parms(struct d_resource* res __attribute((unused)),const char* unused __attribute((unused)))
{
  int mc=global_options.minor_count;

  if( mc == 0) mc = highest_minor+11;
  if( mc < 32) mc = 32;
  printf("minor_count=%d\n",mc);
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
    free(f->device);
    free(f->disk);
    free(f->meta_disk);
    free(f->meta_index);
    free_host_info(f->me);
    free_host_info(f->peer);
    free_options(f->net_options);
    free_options(f->disk_options);
    free_options(f->sync_options);
    free_options(f->startup_options);
    free_options(f->proxy_options);
    free_options(f->handlers);
    free(f);
  }
  if(common) {
    free_options(common->net_options);
    free_options(common->disk_options);
    free_options(common->sync_options);
    free_options(common->startup_options);
    free_options(common->proxy_options);
    free_options(common->handlers);
    free(common);
  }
  if (ifreq_list) free(ifreq_list);
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
    expand_opts(common->proxy_options,   &res->proxy_options);
    expand_opts(common->handlers,        &res->handlers);
    if(common->protocol && ! res->protocol) {
      res->protocol = strdup(common->protocol);
    }
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

  if(dry_run || verbose) {
    while(*cmdline) {
      fprintf(stdout,"%s ",esc(*cmdline++));
    }
    fprintf(stdout,"\n");
    if (dry_run) return 0;
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
	fprintf(stderr,"%s",esc(*argv++));
	if (*argv) fputc(' ',stderr);
      }
      fprintf(stderr,"' terminated with exit code %d\n",rv);
    }
  }

  return rv;
}

#define NA(ARGC) \
  ({ if((ARGC) >= MAX_ARGS) { fprintf(stderr,"MAX_ARGS too small\n"); \
       exit(E_thinko); \
     } \
     (ARGC)++; \
  })

#define make_options(OPT) \
  while(OPT) { \
    if(OPT->value) { \
      ssprintf(argv[NA(argc)],"--%s=%s",OPT->name,OPT->value); \
    } else { \
      ssprintf(argv[NA(argc)],"--%s",OPT->name); \
    } \
    OPT=OPT->next; \
  }

#define make_options_wait(OPT) \
  while(OPT) { \
    if(!strcmp(OPT->name,"become-primary-on")) {\
      OPT=OPT->next; continue; \
    } \
    if(OPT->value) { \
      ssprintf(argv[NA(argc)],"--%s=%s",OPT->name,OPT->value); \
    } else { \
      ssprintf(argv[NA(argc)],"--%s",OPT->name); \
    } \
    OPT=OPT->next; \
  }

int adm_attach(struct d_resource* res,const char* unused __attribute((unused)))
{
  char* argv[MAX_ARGS];
  struct d_option* opt;
  int argc=0;

  argv[NA(argc)]=drbdsetup;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]="disk";
  argv[NA(argc)]=res->me->disk;
  if(!strcmp(res->me->meta_disk,"internal")) {
    argv[NA(argc)]=res->me->disk;
  } else {
    argv[NA(argc)]=res->me->meta_disk;
  }
  argv[NA(argc)]=res->me->meta_index;
  argv[NA(argc)]="--set-defaults";
  argv[NA(argc)]="--create-device";
  opt=res->disk_options;
  make_options(opt);
  argv[NA(argc)]=0;

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
  char* argv[MAX_ARGS];
  struct d_option* opt;
  int i,argc=0;

  argv[NA(argc)]=drbdsetup;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]="resize";
  opt=find_opt(res->disk_options,"size");
  if(opt) ssprintf(argv[NA(argc)],"--%s=%s",opt->name,opt->value);
  for(i=0;i<soi;i++) {
    argv[NA(argc)]=setup_opts[i];
  }
  argv[NA(argc)]=0;

  return m_system(argv,SLEEPS_SHORT);
}

int _admm_generic(struct d_resource* res ,const char* cmd, int flags)
{
  char* argv[MAX_ARGS];
  int argc=0,i;

  argv[NA(argc)]=drbdmeta;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]="v08";
  if(!strcmp(res->me->meta_disk,"internal")) {
    argv[NA(argc)]=res->me->disk;
  } else {
    argv[NA(argc)]=res->me->meta_disk;
  }
  if(!strcmp(res->me->meta_index,"flexible")) {
	if(!strcmp(res->me->meta_disk,"internal")) {
		argv[NA(argc)]="flex-internal";
	} else {
		argv[NA(argc)]="flex-external";
	}
  } else {
	  argv[NA(argc)]=res->me->meta_index;
  }
  argv[NA(argc)]=(char*)cmd;
  for(i=0;i<soi;i++) {
    argv[NA(argc)]=setup_opts[i];
  }

  argv[NA(argc)]=0;

  return m_system(argv,flags);
}

static int admm_generic(struct d_resource* res ,const char* cmd)
{
  return _admm_generic(res, cmd, SLEEPS_VERY_LONG);
}

static int adm_generic(struct d_resource* res,const char* cmd,int flags)
{
  char* argv[MAX_ARGS];
  int argc=0,i;

  argv[NA(argc)]=drbdsetup;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]=(char*)cmd;
  for(i=0;i<soi;i++) {
    argv[NA(argc)]=setup_opts[i];
  }
  argv[NA(argc)]=0;

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

static int adm_khelper(struct d_resource* res ,const char* cmd)
{
  int rv=0;
  char *sh_cmd;
  char *argv[] = { "/bin/sh", "-c", NULL , NULL };

  setenv("DRBD_RESOURCE",res->name,1);
  setenv("DRBD_PEER",res->peer->name,1);

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

  if (res==NULL) return;

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
  char* argv[MAX_ARGS];
  struct d_option* opt;
  int i;
  int argc=0;

  argv[NA(argc)]=drbdsetup;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]="net";
  ssprintf(argv[NA(argc)],"%s:%s",res->me->address,res->me->port);
  if(res->me->proxy) {
    ssprintf(argv[NA(argc)],"%s:%s",res->me->proxy->inside_addr,res->me->proxy->inside_port);
  } else {
    ssprintf(argv[NA(argc)],"%s:%s",res->peer->address,res->peer->port);
  }
  argv[NA(argc)]=res->protocol;

  argv[NA(argc)]="--set-defaults";
  argv[NA(argc)]="--create-device";
  opt=res->net_options;
  make_options(opt);

  for(i=0;i<soi;i++) {
    argv[NA(argc)]=setup_opts[i];
  }

  argv[NA(argc)]=0;

  return m_system(argv,SLEEPS_SHORT);
}

struct d_resource* res_by_name(const char *name);

// Need to convert after from resourcename to minor_number.
void convert_after_option(struct d_resource* res)
{
  struct d_option* opt;

  if (res==NULL) return;

  if ( (opt = find_opt(res->sync_options, "after")) ) {
    char *ptr;
    ssprintf(ptr,"%d",dt_minor_of_dev(res_by_name(opt->value)->me->device));
    free(opt->value);
    opt->value=strdup(ptr);
  }
}

static int adm_proxy_up(struct d_resource* res, const char* unused __attribute((unused)))
{
  char* argv[MAX_ARGS];
  int argc=0, rv;
  struct d_option* opt;

  if(!res->me->proxy) {
    fprintf(stderr,"There is no proxy config for host %s in resource %s.\n",
	    nodeinfo.nodename, res->name);
    exit(E_config_invalid);
  }

  if(strcmp(res->me->proxy->name,nodeinfo.nodename)) {
    fprintf(stderr,"The proxy config in resource %s is for %s, this is %s.\n",
	    res->name, res->me->proxy->name,nodeinfo.nodename);
    exit(E_config_invalid);
  }

  argv[NA(argc)]=drbd_proxy_ctl;
  argv[NA(argc)]="-c";
  ssprintf(argv[NA(argc)],
	   "add connection %s-%s-%s %s:%s %s:%s %s:%s %s:%s",
	   res->me->name, res->name, res->peer->name,
	   res->me->proxy->inside_addr, res->me->proxy->inside_port,
	   res->peer->proxy->outside_addr, res->peer->proxy->outside_port,
	   res->me->proxy->outside_addr, res->me->proxy->outside_port,
	   res->me->address, res->me->port);
  argv[NA(argc)]=0;

  rv = m_system(argv,SLEEPS_SHORT);
  if(rv != 0) return rv;

  argc=0;
  argv[NA(argc)]=drbd_proxy_ctl;
  opt = res->proxy_options;
  while(opt) {
    argv[NA(argc)]="-c";
    ssprintf(argv[NA(argc)], "set %s %s-%s-%s %s",
	     opt->name, res->me->name, res->name, res->peer->name, opt->value);
    opt=opt->next; 
  }
  argv[NA(argc)]=0;
  if(argc > 2) return m_system(argv,SLEEPS_SHORT);  
  return rv;
}


int adm_syncer(struct d_resource* res,const char* unused __attribute((unused)))
{
  char* argv[MAX_ARGS];
  struct d_option* opt;
  int argc=0;

  argv[NA(argc)]=drbdsetup;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]="syncer";

  argv[NA(argc)]="--set-defaults";
  argv[NA(argc)]="--create-device";
  opt=res->sync_options;
  make_options(opt);
  argv[NA(argc)]=0;

  return m_system(argv,SLEEPS_SHORT);
}

static int adm_up(struct d_resource* res,const char* unused __attribute((unused)))
{
  schedule_dcmd(adm_attach,res,NULL,0);
  schedule_dcmd(adm_syncer,res,NULL,1);
  schedule_dcmd(adm_connect,res,NULL,2);

  return 0;
}

static int adm_wait_c(struct d_resource* res ,const char* unused __attribute((unused)))
{
  char* argv[MAX_ARGS];
  struct d_option* opt;
  int argc=0,rv;

  argv[NA(argc)]=drbdsetup;
  argv[NA(argc)]=res->me->device;
  argv[NA(argc)]="wait-connect";
  opt=res->startup_options;
  make_options_wait(opt);
  argv[NA(argc)]=0;

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
  if (no_tty) {
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
  /* alloca can not fail, it can "only" overflow the stack :)
   * but it needs to be initialized anyways! */
  memset(pids,0,nr_resources * sizeof(pid_t));

  for_each_resource(res,t,config) {
    argc=0;
    argv[NA(argc)]=drbdsetup;
    argv[NA(argc)]=res->me->device;
    argv[NA(argc)]="wait-connect";
    opt=res->startup_options;
    make_options_wait(opt);
    argv[NA(argc)]=0;

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

/*
 * I'd really rather parse the output of
 *   ip -o a s
 * once, and be done.
 * But anyways....
 */

static struct ifreq * get_ifreq(void)
{
  int                sockfd, num_ifaces;
  struct ifreq       *ifr;
  struct ifconf      ifc;
  size_t buf_size;

  if (0 > (sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP ))) {
    perror("Cannot open socket");
    exit(EXIT_FAILURE);
  }

  num_ifaces = 0;
  ifc.ifc_req = NULL;

  /* realloc buffer size until no overflow occurs  */
  do {
    num_ifaces += 16; /* initial guess and increment */
    buf_size = ++num_ifaces * sizeof(struct ifreq);
    ifc.ifc_len = buf_size;
    if (NULL == (ifc.ifc_req = realloc(ifc.ifc_req, ifc.ifc_len))) {
      fprintf(stderr, "Out of memory.\n");
      return NULL;
    }
    if (ioctl(sockfd, SIOCGIFCONF, &ifc)) {
      perror("ioctl SIOCFIFCONF");
      free(ifc.ifc_req);
      return NULL;
    }
  } while  (buf_size <= (size_t)ifc.ifc_len);

  num_ifaces = ifc.ifc_len / sizeof(struct ifreq);
  /* Since we allocated at least one more than neccessary,
   * this serves as a stop marker for the iteration in
   * have_ip() */
  ifc.ifc_req[num_ifaces].ifr_name[0] = 0;
  for (ifr = ifc.ifc_req; ifr->ifr_name[0] != 0; ifr++) {
    /* we only want to look up the presence or absence of a certain address
     * here. but we want to skip "down" interfaces.  if an interface is down,
     * we store an invalid sa_family, so the lookup will skip it.
     */
    struct ifreq ifr_for_flags = *ifr; /* get a copy to work with */
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr_for_flags) < 0) {
      perror("ioctl SIOCGIFFLAGS");
      ifr->ifr_addr.sa_family = -1; /* what's wrong here? anyways: skip */
      continue;
    }
    if (!(ifr_for_flags.ifr_flags & IFF_UP)) {
      ifr->ifr_addr.sa_family = -1; /* is not up: skip */
      continue;
    }
  }
  close(sockfd);
  return ifc.ifc_req;
}

int have_ip(const char *ip)
{
  struct ifreq *ifr;
  struct in_addr query_addr;

  query_addr.s_addr = inet_addr(ip);

  if (!ifreq_list) ifreq_list = get_ifreq();

  for (ifr = ifreq_list; ifr && ifr->ifr_name[0] != 0; ifr++) {
    /* currently we only support AF_INET */
    struct sockaddr_in * list_addr = (struct sockaddr_in *)&ifr->ifr_addr;
    if (ifr->ifr_addr.sa_family != AF_INET)
      continue;
    if (query_addr.s_addr == list_addr->sin_addr.s_addr)
      return 1;
  }
  return 0;
}

void verify_ips(struct d_resource *res)
{
  if (global_options.disable_ip_verification) return;
  if (dry_run == 1 || do_verify_ips == 0) return;

  if (! have_ip(res->me->address)) {
    ENTRY e, *ep;
    e.key = e.data = ep = NULL;
    asprintf(&e.key, "%s:%s", res->me->address, res->me->port);
    ep = hsearch(e, FIND);
    fprintf(stderr, "%s:%d: in resource %s, on %s:\n\t"
      "IP %s not found on this host.\n",
      config_file, (int)(long)ep->data, res->name,
      res->me->name, res->me->address);
    if (INVALID_IP_IS_INVALID_CONF)
      config_valid = 0;
  }
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

  /* if we are done parsing the config file,
   * switch off this paranoia */
  if (config_valid >= 2)
	  return 1;

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

int sanity_check_abs_cmd(char* cmd_name)
{
  struct stat sb;
  int err;

  if ( (err=stat(cmd_name,&sb)) ) {
    return 0;
  }

  if(!sb.st_mode&S_ISUID || sb.st_mode&S_IXOTH || sb.st_gid==0) {
    fprintf(stderr,"WARN:\n"
	    "  You are using the 'drbd-peer-outdater' as outdate-peer program.\n"
	    "  If you use that mechanism the dopd heartbeat plugin program needs\n"
	    "  to be able to call drbdsetup and drbdmeta with root privileges.\n\n"
	    "  You need to fix this with these commands:\n"
	    "  chgrp haclient %s\n"
	    "  chmod o-x %s\n"
	    "  chmod u+s %s\n\n\n",
	    cmd_name,cmd_name,cmd_name);
  }
  return 1;
}

void sanity_check_cmd(char* cmd_name)
{
  char *path,*pp,*c;
  char abs_path[100];

  if( strchr(cmd_name,'/') ) {
    sanity_check_abs_cmd(cmd_name);
  } else {
    path = pp = c = strdup(getenv("PATH"));

    while(1) {
      c = strchr(pp,':');
      if(c) *c = 0;
      snprintf(abs_path,100,"%s/%s",pp,cmd_name);
      if(sanity_check_abs_cmd(abs_path)) break;
      if(!c) break;
      c++;
      if(!*c) break;
      pp = c;
    }
    free(path);
  }
}

void sanity_check_perm()
{
  static int checked=0;

  if(checked) return;

  sanity_check_cmd(drbdsetup);
  sanity_check_cmd(drbdmeta);
}

void validate_resource(struct d_resource * res)
{
  struct d_option* opt;
  char *bpo;

  if (!res->protocol) {
    if (!common || !common->protocol) {
      fprintf(stderr,
	      "%s:%d: in resource %s:\n\tprotocol definition missing.\n",
	      config_file, c_resource_start, res->name);
      config_valid = 0;
    } /* else:
       * may not have been expanded yet for "dump" subcommand */
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
  if ( (opt = find_opt(res->sync_options, "after")) ) {
    if (res_by_name(opt->value) == NULL) {
      fprintf(stderr,"In resource %s:\n\tresource '%s' mentioned in "
	      "'after' option is not known.\n",res->name,opt->value);
      config_valid=0;
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
  if (res->me && res->peer) {
    verify_ips(res);
  }

  if ( (opt = find_opt(res->handlers, "outdate-peer")) ) {
    if(strstr(opt->value,"drbd-peer-outdater")) sanity_check_perm();
  }

  bpo = get_opt_val(res->startup_options, "become-primary-on", "undef");
  opt = find_opt(res->net_options, "allow-two-primaries");
  if(!strcmp(bpo,"both") && opt == NULL) {
    fprintf(stderr,
	    "In resource %s:\n"
	    "become-primary-on is set to both, but allow-two-primaries "
	    "is not set.\n", res->name);
    config_valid = 0;
  }

  if (( res->me->proxy == NULL ) != (res->peer->proxy == NULL)) {
	fprintf(stderr,
		"Incomplete proxy configuration. in resource %s.\n",
		res->name);
	config_valid = 0;
  }
}

static void global_validate(void)
{
  struct d_resource *res,*tmp;
  for_each_resource(res,tmp,config) {
    validate_resource(res);
  }
}


int main(int argc, char** argv)
{
  size_t i;
  int rv=0;
  struct adm_cmd *cmd;
  struct d_resource *res,*tmp;
  char *env_drbd_nodename = NULL;
  int is_dump_xml;
  int is_dump;

  drbdsetup=NULL;
  drbdmeta=NULL;
  dry_run=0;
  verbose=0;
  yyin=NULL;
  uname(&nodeinfo); /* FIXME maybe fold to lower case ? */
  no_tty = (!isatty(fileno(stdin)) || !isatty(fileno(stdout)));

  env_drbd_nodename = getenv("__DRBD_NODE__");
  if (env_drbd_nodename && *env_drbd_nodename) {
    strncpy(nodeinfo.nodename,env_drbd_nodename,sizeof(nodeinfo.nodename)-1);
    nodeinfo.nodename[sizeof(nodeinfo.nodename)-1] = 0;
    fprintf(stderr, "\n"
            "   found __DRBD_NODE__ in environment\n"
            "   PRETENDING that I am >>%s<<\n\n",nodeinfo.nodename);
  }

  /* in case drbdadm is called with an absolut or relative pathname
   * look for the drbdsetup binary in the same location,
   * otherwise, just let execvp sort it out... */
  if( (progname=strrchr(argv[0],'/')) == 0 ) {
    progname=argv[0];
    drbdsetup = strdup("drbdsetup");
    drbdmeta = strdup("drbdmeta");
    drbd_proxy_ctl = strdup("drbd-proxy-ctl");
  } else {
    size_t len = strlen(argv[0]) + 1;
    ++progname;

    len += strlen("drbdsetup") - strlen(progname);
    drbdsetup = malloc(len);
    if (drbdsetup) {
      strncpy(drbdsetup, argv[0], (progname - argv[0]));
      strcpy(drbdsetup + (progname - argv[0]), "drbdsetup");
    }

    len += strlen("drbdmeta") - strlen(progname);
    drbdmeta = malloc(len);
    if (drbdmeta) {
      strncpy(drbdmeta, argv[0], (progname - argv[0]));
      strcpy(drbdmeta + (progname - argv[0]), "drbdmeta");
    }

    len += strlen("drbd-proxy-ctl") - strlen(progname);
    drbd_proxy_ctl = malloc(len);
    if (drbd_proxy_ctl) {
      strncpy(drbd_proxy_ctl, argv[0], (progname - argv[0]));
      strcpy(drbd_proxy_ctl + (progname - argv[0]), "drbd-proxy-ctl");
    }

    argv[0] = progname;
  }

  if(argc == 1) print_usage_and_exit("missing arguments"); // arguments missing.

  if (drbdsetup == NULL || drbdmeta == NULL || drbd_proxy_ctl == NULL) {
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
	case 'v':
	  verbose++;
	  break;
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
	case 'p':
	  {
	    char* pathes[2];
	    pathes[0]=optarg;
	    pathes[1]=0;
	    find_drbdcmd(&drbd_proxy_ctl,pathes);
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
    } while (conf_file[++i]);
  }
  if(!config_file) {
    fprintf(stderr,"Can not open '%s': ",conf_file[i-1]);
    perror("");
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
  my_parse();

  if(!config_valid) exit(E_config_invalid);

  /* disable check_uniq, so it won't interfere
   * with parsing of drbdsetup show output */
  config_valid = 2;

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

  uc_node(global_options.usage_count);

  is_dump_xml = (cmd->function == adm_dump_xml);
  is_dump = (is_dump_xml || cmd->function == adm_dump);
  if (!is_dump || dry_run) expand_common();

  if(cmd->res_name_required)
    {
      if (optind + 1 > argc && !is_dump)
        print_usage_and_exit("missing arguments"); // arguments missing.

      global_validate();
      if (!is_dump) {
        for_each_resource(res,tmp,config) {
	  convert_after_option(res);
	  convert_discard_opt(res);

	  if(cmd->me_is_localhost) {
	    if(strcmp(res->me->name, nodeinfo.nodename)) {
	      fprintf(stderr,"In resource %s there is no host section for this"
		      " host %s\n.", res->name, nodeinfo.nodename);
	      config_valid=0;
	    }
	  }
	}
	if(!config_valid) exit(E_config_invalid);
      }

      if ( optind==argc || !strcmp(argv[optind],"all") ) {
        if (is_dump) {
          if (is_dump_xml) {
            printf("<config file=\"%s\">\n", config_file); ++indent;
            dump_global_info_xml();
            dump_common_info_xml();
          } else {
            printf("# %s\n",config_file);
            dump_global_info();
            dump_common_info();
          }
	}
        for_each_resource(res,tmp,config) {
	  if( (rv |= cmd->function(res,cmd->name)) >= 10 ) {
	    fprintf(stderr,"command exited with code %d\n",rv);
	    exit(E_exec_error);
	  }
	}
        if (is_dump_xml) {
            --indent; printf("</config>\n");
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
	fprintf(stderr,"command exited with code %d\n",rv);
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
