%{
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "drbdadm.h"

extern void yyerror(char* text);
extern int yylex();

#define APPEND(LIST,ITEM) ({                  \
  typeof((LIST)) _l = (LIST);                 \
  typeof((ITEM)) _i = (ITEM);                 \
  typeof((ITEM)) _t;                          \
  _i->next = NULL;                            \
  if (_l == NULL) { _l = _i; }                \
  else {                                      \
    for (_t = _l; _t->next; _t = _t->next);   \
    _t->next = _i;                            \
  };                                          \
  _l;                                         \
})

static struct d_resource* c_res;
static struct d_host_info* c_host;

static struct d_option* new_opt(char* name,char* value)
{
  struct d_option* cn = malloc(sizeof(struct d_option));

  cn->name=name;
  cn->value=value;
  cn->mentioned=0;

  return cn;
}

static void derror(char* text)
{
  config_valid=0;
  fprintf(stderr,
	  "%s:%d:\n\t'%s' keyword missing from host section ending here.\n"
	  "\t(Host sections are those beginning with the 'on' keyword)\n\n",
	  config_file,line,text);
}

static void derror2(char* text)
{
  config_valid=0;
  fprintf(stderr,
	  "%s:%d:\n\t%s\n\tDetected at host section ending here.\n"
	  "\t(Host sections are those beginning with the 'on' keyword)\n\n",
	  config_file,line,text);
}

static void host_sec(char* name)
{
  char hostname[255];

  gethostname(hostname,255);

  c_host->name=name;
  if(c_host->device==0) derror("device");
  if(c_host->disk==0) derror("disk");
  if(c_host->address==0) derror("address");
  if(c_host->port==0) derror("port");
  if(c_host->meta_disk==0) derror("meta-disk");
  if(c_host->meta_disk) {
    if( !strcmp(c_host->meta_disk,"internal") && c_host->meta_index==0) 
      c_host->meta_index=strdup("-1");
  }
  if(c_host->meta_index==0) derror("meta-index");

  if(strcmp(name,hostname)==0) {
    if(c_res->me) derror2("Thre are multiple host sections for this host.");
    c_res->me = c_host;
  } else {
    if(c_res->partner) derror2("There are multiple host sections for the peer."
			       "\n\t(Maybe misspelled local host name?)");
    c_res->partner = c_host;
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

%}

%union {
  char* txt;
  struct d_option* d_option;
  struct d_resource* d_resource;
}

%token TK_RESOURCE TK_DISK TK_NET TK_SYNCER TK_ON
%token TK_PORT TK_DEVICE TK_ADDRESS TK_GLOBAL TK_STARTUP
%token TK_META_DISK TK_META_INDEX
%token <txt> TK_PROTOCOL TK_ON_IO_ERROR
%token <txt> TK_SIZE TK_TIMEOUT TK_CONNECT_INT
%token <txt> TK_RATE TK_USE_CSUMS TK_SKIP_SYNC TK_PING_INT
%token <txt> TK_INTEGER TK_STRING TK_IPADDR TK_INCON_DEGR_CMD
%token <txt> TK_DISABLE_IO_HINTS TK_MINOR_COUNT
%token <txt> TK_WFC_TIMEOUT TK_DEGR_WFC_TIMEOUT
%token <txt> TK_MAX_BUFFERS TK_MAX_EPOCH_SIZE
%token <txt> TK_SNDBUF_SIZE TK_SYNC_GROUP TK_AL_EXTENTS
%token <txt> TK_SINTEGER

%type <d_option> disk_stmts disk_stmt
%type <d_option> net_stmts net_stmt
%type <d_option> sync_stmts sync_stmt
%type <d_option> startup_stmts startup_stmt
%type <d_resource> resources resource
%type <txt> signed_int

%%
config:           global_sec resources   { config=$2; }
		;

global_sec:       /* empty */
                | TK_GLOBAL '{' glob_stmts '}'
		;

glob_stmts:       /* empty */
		| glob_stmts glob_stmt
		;

glob_stmt:        TK_DISABLE_IO_HINTS   { global_options.disable_io_hints=1; }
		| TK_MINOR_COUNT '=' TK_INTEGER   { global_options.minor_count=atoi($3); }
                ;

resources:        /* empty */   { $$ = 0; }
		| resources resource   { $$=APPEND($1,$2); }
		;

resource:	  TK_RESOURCE TK_STRING { c_res = new_resource($2); }
                  '{' res_stmts '}' { $$ = c_res; }
		;

res_stmts:        /* empty */
		| res_stmts res_stmt
		| res_stmts section
		;

res_stmt:         TK_PROTOCOL '=' TK_STRING   { c_res->protocol=$3; }
		| TK_INCON_DEGR_CMD '=' TK_STRING   { c_res->ind_cmd=$3; }
		;

section:	  TK_DISK '{' disk_stmts '}' { c_res->disk_options=$3; }
		| TK_NET  '{' net_stmts '}'  { c_res->net_options=$3; }
		| TK_ON TK_STRING '{' host_stmts '}' { host_sec($2); }
		| TK_SYNCER '{' sync_stmts '}' { c_res->sync_options=$3; }
		| TK_STARTUP '{' startup_stmts '}' {c_res->startup_options=$3;}
		;

disk_stmts:       /* empty */   { $$ = 0; }
		| disk_stmts disk_stmt   { $$=APPEND($1,$2); }
		;

disk_stmt:        TK_ON_IO_ERROR '=' TK_STRING   { $$=new_opt($1,$3); }
		| TK_SIZE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

net_stmts:        /* empty */   { $$ = 0; }
		| net_stmts net_stmt   { $$=APPEND($1,$2); }
		;

net_stmt:         TK_TIMEOUT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_CONNECT_INT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_PING_INT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_MAX_BUFFERS '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_MAX_EPOCH_SIZE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_SNDBUF_SIZE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

sync_stmts:       /* empty */   { $$ = 0; }
		| sync_stmts sync_stmt   { $$=APPEND($1,$2); }
		;

sync_stmt:        TK_SKIP_SYNC   { $$=new_opt($1,0); }
		| TK_USE_CSUMS   { $$=new_opt($1,0); }
		| TK_RATE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_SYNC_GROUP '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_AL_EXTENTS '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

host_stmts:       /* empty */  { c_host=calloc(1,sizeof(struct d_host_info)); }
		| host_stmts host_stmt
		;

host_stmt:        TK_DISK '=' TK_STRING     { c_host->disk=$3; }
		| TK_DEVICE '=' TK_STRING   { c_host->device=$3; }
		| TK_ADDRESS '=' TK_IPADDR  { c_host->address=$3; }
		| TK_PORT '=' TK_INTEGER    { c_host->port=$3; }
		| TK_META_DISK '=' TK_STRING { c_host->meta_disk=$3; }
		| TK_META_INDEX '=' signed_int { c_host->meta_index=$3; }
		;

signed_int:       TK_SINTEGER
                | TK_INTEGER
                ;

startup_stmts:    /* empty */  { $$ = 0; }
		| startup_stmts startup_stmt   { $$=APPEND($1,$2); }
		;

startup_stmt:     TK_WFC_TIMEOUT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_DEGR_WFC_TIMEOUT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;
