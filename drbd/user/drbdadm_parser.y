%{
#include <unistd.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "drbdadm.h"

extern void yyerror(char* text);
extern int yylex();

#define APPEND(LIST,ITEM)   (ITEM); ((ITEM)->next=(LIST))

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
  fprintf(stderr,"%s\n",text);
}

static void host_sec(char* name)
{
  char hostname[255];

  gethostname(hostname,255);

  c_host->name=name;
  if(c_host->device==0) derror("device missing");
  if(c_host->disk==0) derror("disk missing");
  if(c_host->address==0) derror("address missing");
  if(c_host->port==0) derror("port missing");

  if(strcmp(name,hostname)==0) {
    if(c_res->me) derror("multiple host sections");
    c_res->me = c_host;
  } else {
    if(c_res->partner) derror("multiple partner host sections");
    c_res->partner = c_host;
  }
}

static struct d_resource* new_resource(char* name)
{      
  struct d_resource* res;
  res=calloc(1,sizeof(struct d_resource));
  res->name=name;

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
%token <txt> TK_PROTOCOL TK_DISK TK_DO_PANIC
%token <txt> TK_SIZE TK_TIMEOUT TK_CONNECT_INT 
%token <txt> TK_RATE TK_USE_CSUMS TK_SKIP_SYNC TK_PING_INT 
%token <txt> TK_INTEGER TK_STRING TK_IPADDR TK_INCON_DEGR_CMD 
%token <txt> TK_DISABLE_IO_HINTS TK_MINOR_COUNT 
%token <txt> TK_WFC_TIMEOUT TK_DEGR_WFC_TIMEOUT
%token <txt> TK_MAX_BUFFERS TK_MAX_EPOCH_SIZE

%type <d_option> disk_stmts disk_stmt 
%type <d_option> net_stmts net_stmt
%type <d_option> sync_stmts sync_stmt 
%type <d_option> startup_stmts startup_stmt 
%type <d_resource> resources resource

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

disk_stmt:        TK_DO_PANIC   { $$=new_opt($1,0); }
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
		;

sync_stmts:       /* empty */   { $$ = 0; }
		| sync_stmts sync_stmt   { $$=APPEND($1,$2); }
		;

sync_stmt:        TK_SKIP_SYNC   { $$=new_opt($1,0); }
		| TK_USE_CSUMS   { $$=new_opt($1,0); }
		| TK_RATE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

host_stmts:       /* empty */  { c_host=calloc(1,sizeof(struct d_host_info)); }
		| host_stmts host_stmt
		;

host_stmt:        TK_DISK '=' TK_STRING     { c_host->disk=$3; }
		| TK_DEVICE '=' TK_STRING   { c_host->device=$3; }
		| TK_ADDRESS '=' TK_IPADDR  { c_host->address=$3; }
		| TK_PORT '=' TK_INTEGER    { c_host->port=$3; }
		;

startup_stmts:    /* empty */  { $$ = 0; }
		| startup_stmts startup_stmt   { $$=APPEND($1,$2); }
		;

startup_stmt:     TK_WFC_TIMEOUT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_DEGR_WFC_TIMEOUT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;
