%{

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "drbdadm.h"
#include "drbd_limits.h"
#include "drbdtool_common.h"

extern void yyerror(char* text);
extern int  yylex(void);

#define APPEND(LIST,ITEM) ({		      \
  typeof((LIST)) _l = (LIST);		      \
  typeof((ITEM)) _i = (ITEM);		      \
  typeof((ITEM)) _t;			      \
  _i->next = NULL;			      \
  if (_l == NULL) { _l = _i; }		      \
  else {				      \
    for (_t = _l; _t->next; _t = _t->next);   \
    _t->next = _i;			      \
  };					      \
  _l;					      \
})

static struct d_resource* c_res;
static struct d_host_info* c_host;
static char* c_hostname;
static int   c_section_start, n_hosts;

void
m_strtoll_range(const char *s, char def_unit,
		const char *name,
		unsigned long long min, unsigned long long max)
{
  unsigned long long r = m_strtoll(s, def_unit);
  char unit[] = { def_unit > '1' ? def_unit : 0, 0 };
  if (min > r || r > max)
    {
      fprintf(stderr,
	      "%s:%d: %s %s => %llu%s out of range [%llu..%llu]%s.\n",
	      config_file, fline, name, s, r, unit, min, max, unit);
      exit(E_config_invalid);
    }
  if (DEBUG_RANGE_CHECK)
    {
      fprintf(stderr,
	      "%s:%d: %s %s => %llu%s in range [%llu..%llu]%s.\n",
	      config_file, fline, name, s, r, unit, min, max, unit);
    }
}

enum range_checks
{
  R_MINOR_COUNT,
  R_DIALOG_REFRESH,
  R_DISK_SIZE,
  R_TIMEOUT,
  R_CONNECT_INT,
  R_PING_INT,
  R_MAX_BUFFERS,
  R_MAX_EPOCH_SIZE,
  R_SNDBUF_SIZE,
  R_KO_COUNT,
  R_RATE,
  R_GROUP,
  R_AL_EXTENTS,
  R_PORT,
  R_META_IDX,
  R_WFC_TIMEOUT,
  R_DEGR_WFC_TIMEOUT,
};

void
range_check(const enum range_checks what, const char *name, const char *value)
{
  switch (what)
    {
    default:
      fprintf(stderr, "%s:%d: unknown range for %s => %s\n",
	      config_file, fline, name, value);
      break;
    case R_MINOR_COUNT:
      m_strtoll_range(value, 1, name,
		      DRBD_MINOR_COUNT_MIN, DRBD_MINOR_COUNT_MAX);
      break;
    case R_DIALOG_REFRESH:
      m_strtoll_range(value, 1, name,
		      DRBD_DIALOG_REFRESH_MIN, DRBD_DIALOG_REFRESH_MAX);
      break;
    case R_DISK_SIZE:
      m_strtoll_range(value, 'K', name,
		      DRBD_DISK_SIZE_SECT_MIN >> 1,
		      DRBD_DISK_SIZE_SECT_MAX >> 1);
      break;
    case R_TIMEOUT:
      m_strtoll_range(value, 1, name, DRBD_TIMEOUT_MIN, DRBD_TIMEOUT_MAX);
      break;
    case R_CONNECT_INT:
      m_strtoll_range(value, 1, name, DRBD_CONNECT_INT_MIN,
		      DRBD_CONNECT_INT_MAX);
      break;
    case R_PING_INT:
      m_strtoll_range(value, 1, name, DRBD_PING_INT_MIN, DRBD_PING_INT_MAX);
      break;
    case R_MAX_BUFFERS:
      m_strtoll_range(value, 1, name, DRBD_MAX_BUFFERS_MIN,
		      DRBD_MAX_BUFFERS_MAX);
      break;
    case R_MAX_EPOCH_SIZE:
      m_strtoll_range(value, 1, name, DRBD_MAX_EPOCH_SIZE_MIN,
		      DRBD_MAX_EPOCH_SIZE_MAX);
      break;
    case R_SNDBUF_SIZE:
      m_strtoll_range(value, 1, name, DRBD_SNDBUF_SIZE_MIN,
		      DRBD_SNDBUF_SIZE_MAX);
      break;
    case R_KO_COUNT:
      m_strtoll_range(value, 1, name, DRBD_KO_COUNT_MIN, DRBD_KO_COUNT_MAX);
      break;
    case R_RATE:
      m_strtoll_range(value, 'K', name, DRBD_RATE_MIN, DRBD_RATE_MAX);
      break;
    case R_GROUP:
      m_strtoll_range(value, 1, name, DRBD_GROUP_MIN, DRBD_GROUP_MAX);
      break;
    case R_AL_EXTENTS:
      m_strtoll_range(value, 1, name, DRBD_AL_EXTENTS_MIN,
		      DRBD_AL_EXTENTS_MAX);
      break;
    case R_PORT:
      m_strtoll_range(value, 1, name, DRBD_PORT_MIN, DRBD_PORT_MAX);
      break;
      /* FIXME not yet implemented!
         case R_META_IDX:
         m_strtoll_range(value, 1, name, DRBD_META_IDX_MIN, DRBD_META_IDX_MAX);
         break;
       */
    case R_WFC_TIMEOUT:
      m_strtoll_range(value, 1, name, DRBD_WFC_TIMEOUT_MIN,
		      DRBD_WFC_TIMEOUT_MAX);
      break;
    case R_DEGR_WFC_TIMEOUT:
      m_strtoll_range(value, 1, name, DRBD_DEGR_WFC_TIMEOUT_MIN,
		      DRBD_DEGR_WFC_TIMEOUT_MAX);
      break;
    }
}

static struct d_option* new_opt(char* name,char* value)
{
  struct d_option* cn = malloc(sizeof(struct d_option));

  /* fprintf(stderr,"%s:%d: %s = %s\n",config_file,line,name,value); */
  cn->name=name;
  cn->value=value;
  cn->mentioned=0;

  return cn;
}

static void derror(char* text)
{
  config_valid=0;
  fprintf(stderr, "%s:%d: in resource %s, on %s { ... }:"
	          " '%s' keyword missing.\n",
	  config_file,c_section_start,c_res->name,c_hostname,text);
}

static void host_sec(char *name)
{
  c_host->name = name;
  if (!c_host->device)	  derror("device");
  if (!c_host->disk)	  derror("disk");
  if (!c_host->address)   derror("address");
  if (!c_host->meta_disk) derror("meta-disk");

  if (strcmp(name, nodeinfo.nodename) == 0) {
    // if (c_res->me) error(...); -- already done by check_uniq in the rules.
    c_res->me = c_host;
  } else {
    if (c_res->peer) {
      config_valid = 0;
      fprintf(stderr,
	      "%s:%d: in resource %s, on %s { ... } ... on %s { ... }:\n"
	      "\tThere are multiple host sections for the peer.\n"
	      "\tMaybe misspelled local host name '%s'?\n",
	      config_file, c_section_start, c_res->name,
	      c_res->peer->name, c_hostname, nodeinfo.nodename);
    }
    c_res->peer = c_host;
  }
}

static struct d_resource* new_resource(char* name)
{
  struct d_resource* res;
  res=calloc(1,sizeof(struct d_resource));
  res->name=name;
  res->next = NULL;

  return res;
}

void check_meta_disk()
{
  if (strcmp(c_host->meta_disk, "internal")) {
    if (c_host->meta_index == NULL) {
      fprintf(stderr, "%s:%d: expected 'meta-disk = %s [index]'.\n",
	      config_file, fline, c_host->meta_disk);
    }
    check_uniq("meta-disk", "%s:%s[%s]", c_hostname,
	       c_host->meta_disk, c_host->meta_index);
  } else if (c_host->meta_index) {
    fprintf(stderr,
	    "%s:%d: no index allowed with 'meta-disk = internal'.\n",
	    config_file, fline);
  } else {
    c_host->meta_index = strdup("-1");
  }
}

#define CHKU(what,val) \
	c_host->what = val; \
	check_uniq( #what, "%s:%s",c_hostname,val)

#define CHKS(sname) \
	check_uniq(sname " section","%s:" sname, c_res->name)
%}

%union {
  char* txt;
  struct d_option* d_option;
  struct d_resource* d_resource;
}

%token TK_GLOBAL TK_RESOURCE
%token TK_ON TK_NET TK_DISK_S TK_SYNCER TK_STARTUP
%token TK_DISABLE_IO_HINTS
%token TK_PROTOCOL TK_HANDLERS
%token TK_ADDRESS TK_DISK TK_DEVICE TK_META_DISK
%token <txt> TK_MINOR_COUNT TK_INTEGER TK_STRING
%token <txt> TK_ON_IO_ERROR TK_SIZE
%token <txt> TK_TIMEOUT TK_CONNECT_INT TK_PING_INT TK_MAX_BUFFERS TK_IPADDR
%token <txt> TK_MAX_EPOCH_SIZE TK_SNDBUF_SIZE
%token <txt> TK_SKIP_SYNC TK_USE_CSUMS TK_RATE TK_SYNC_GROUP TK_AL_EXTENTS
%token <txt> TK_WFC_TIMEOUT TK_DEGR_WFC_TIMEOUT
%token <txt> TK_KO_COUNT TK_ON_DISCONNECT TK_DIALOG_REFRESH
%token <txt> TK_ALLOW_TWO_PRIMARIES
%token <txt> TK_PRI_ON_INCON_DEGR TK_PRI_SEES_SEC_WITH_HIGHER_GC
%token <txt> TK_OUTDATE_PEER

%type <txt> hostname resource_name
%type <d_option> disk_stmts disk_stmt
%type <d_option> net_stmts net_stmt
%type <d_option> sync_stmts sync_stmt
%type <d_option> startup_stmts startup_stmt
%type <d_option> handler_stmts handler_stmt
%type <d_resource> resources resource

%%
config:		  global_sec resources	 { config=$2; }
		;

global_sec:	  /* empty */
		| TK_GLOBAL glob_stmts
		;

glob_stmts:	  /* empty */
		| glob_stmts glob_stmt
		;

glob_stmt:	  TK_DISABLE_IO_HINTS
			{ global_options.disable_io_hints=1;   }
		| TK_MINOR_COUNT TK_INTEGER
		{
			range_check(R_MINOR_COUNT,$1,$2);
			global_options.minor_count=atoi($2);
		}
		| TK_DIALOG_REFRESH TK_INTEGER
                {
			range_check(R_DIALOG_REFRESH,$1,$2);
			global_options.dialog_refresh=atoi($2);
		}
		;

resources:	  /* empty */	     { $$ = 0; }
		| resources resource { $$=APPEND($1,$2); }
		;

resource:	TK_RESOURCE { n_hosts = 0; } resource_name res_stmts
			{ $$ = c_res; validate_resource(c_res); }
		;

resource_name:	TK_STRING
		{
			int uniq;
			c_resource_start = line;
			c_res		 = new_resource($1);
			uniq = check_uniq("resource","%s",$1);
			if (!uniq) exit(E_config_invalid);
		}
		;

res_stmts:	  /* empty */
		| res_stmts res_stmt
		| res_stmts section
		;

res_stmt:	  TK_PROTOCOL	    TK_STRING { c_res->protocol=$2; }
		;

section:	  TK_DISK_S   disk_stmts
		{ CHKS("disk");    c_res->disk_options=$2;    }
		| TK_NET      net_stmts
		{ CHKS("net");     c_res->net_options=$2;     }
		| TK_SYNCER   sync_stmts
		{ CHKS("syncer");  c_res->sync_options=$2;    }
		| TK_STARTUP  startup_stmts
		{ CHKS("startup"); c_res->startup_options=$2; }
		| TK_ON hostname host_stmts { host_sec($2); }
		| TK_HANDLERS  handler_stmts
		{ CHKS("handlers"); c_res->handlers=$2; }
		;

hostname:	TK_STRING
		{
		  int uniq;
		  c_section_start = line;
		  c_hostname = $1;
		  uniq = check_uniq("host section", "%s: on %s",
				    c_res->name, c_hostname);
		  if (!uniq)
		    exit(E_config_invalid);
		  if (++n_hosts > 2) {
		    fprintf(stderr,
			    "%s:%d: in resource %s, "
			    "unsupported third host section on %s { ... }.\n",
			    config_file, c_section_start, c_res->name,
			    c_hostname);
		    exit(E_config_invalid);
		  }
		}
		;

disk_stmts:	  /* empty */	           { $$ = 0; }
		| disk_stmts disk_stmt	   { $$=APPEND($1,$2); }
		;

disk_stmt:	  TK_ON_IO_ERROR TK_STRING { $$=new_opt($1,$2); }
		| TK_SIZE TK_INTEGER
		{ $$=new_opt($1,$2); range_check(R_DISK_SIZE,$1,$2); }
		;

net_stmts:	  /* empty */	           { $$ = 0; }
		| net_stmts net_stmt       { $$=APPEND($1,$2); }
		;

net_stmt:	  TK_TIMEOUT	    TK_INTEGER
		{ range_check(R_TIMEOUT,$1,$2);		$$=new_opt($1,$2); }
		| TK_CONNECT_INT    TK_INTEGER
		{ range_check(R_CONNECT_INT,$1,$2);	$$=new_opt($1,$2); }
		| TK_PING_INT	    TK_INTEGER
		{ range_check(R_PING_INT,$1,$2);	$$=new_opt($1,$2); }
		| TK_MAX_BUFFERS    TK_INTEGER
		{ range_check(R_MAX_BUFFERS,$1,$2);	$$=new_opt($1,$2); }
		| TK_MAX_EPOCH_SIZE TK_INTEGER
		{ range_check(R_MAX_EPOCH_SIZE,$1,$2);	$$=new_opt($1,$2); }
		| TK_SNDBUF_SIZE    TK_INTEGER
		{ range_check(R_SNDBUF_SIZE,$1,$2);	$$=new_opt($1,$2); }
		| TK_KO_COUNT       TK_INTEGER
		{ range_check(R_KO_COUNT,$1,$2);	$$=new_opt($1,$2); }
		| TK_ON_DISCONNECT  TK_STRING	{	$$=new_opt($1,$2); }
		| TK_ALLOW_TWO_PRIMARIES	{	$$=new_opt($1,0);  }
		;

sync_stmts:	  /* empty */	           { $$ = 0; }
		| sync_stmts sync_stmt	   { $$=APPEND($1,$2); }
		;

sync_stmt:	  TK_SKIP_SYNC		   { $$=new_opt($1,0);  }
		| TK_USE_CSUMS		   { $$=new_opt($1,0);  }
		| TK_RATE	TK_INTEGER
		{ range_check(R_RATE,$1,$2); $$=new_opt($1,$2); }
		| TK_SYNC_GROUP TK_INTEGER { $$=new_opt($1,$2); }
		{ range_check(R_GROUP,$1,$2); $$=new_opt($1,$2); }
		| TK_AL_EXTENTS TK_INTEGER { $$=new_opt($1,$2); }
		{ range_check(R_AL_EXTENTS,$1,$2); $$=new_opt($1,$2); }
		;

host_stmts:	  /* empty */ { c_host=calloc(1,sizeof(struct d_host_info)); }
		| host_stmts host_stmt
		;

host_stmt:	  TK_DISK    TK_STRING	  { CHKU(disk,$2); }
		| TK_DEVICE  TK_STRING	  { CHKU(device,$2); }
		| TK_ADDRESS ip_and_port
		{ check_uniq("IP","%s:%s", c_host->address,c_host->port); }
		| TK_META_DISK meta_disk_and_index { check_meta_disk(); }
		;


ip_and_port:	  TK_IPADDR TK_INTEGER
		{
			range_check(R_PORT, "port", $2);
			c_host->address=$1; c_host->port = $2;
		}
		;

meta_disk_and_index:
		  TK_STRING TK_INTEGER
		{ c_host->meta_disk = $1; c_host->meta_index = $2; }
		| TK_STRING { c_host->meta_disk = $1; }
		;

startup_stmts:	  /* empty */  { $$ = 0; }
		| startup_stmts startup_stmt   { $$=APPEND($1,$2); }
		;

startup_stmt:	  TK_WFC_TIMEOUT      TK_INTEGER
		{ range_check(R_WFC_TIMEOUT,$1,$2);	$$=new_opt($1,$2); }
		| TK_DEGR_WFC_TIMEOUT TK_INTEGER
		{ range_check(R_DEGR_WFC_TIMEOUT,$1,$2);$$=new_opt($1,$2); }
		;

handler_stmts:	  /* empty */	           { $$ = 0; }
		| handler_stmts handler_stmt	   { $$=APPEND($1,$2); }
		;

handler_stmt:	  TK_PRI_ON_INCON_DEGR TK_STRING	{ $$=new_opt($1,$2); }
		| TK_PRI_SEES_SEC_WITH_HIGHER_GC TK_STRING
		{ $$=new_opt($1,$2); }
		| TK_OUTDATE_PEER TK_STRING		{ $$=new_opt($1,$2); }
		;
