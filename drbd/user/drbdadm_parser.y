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

%token TK_RESOURCE TK_DISK TK_NET TK_SYNCER TK_ON TK_DISABLE_IO_HINTS
%token TK_PORT TK_DEVICE TK_ADDRESS TK_GLOBAL TK_MINOR_COUNT 
%token <txt> TK_PROTOCOL TK_DISK TK_DO_PANIC
%token <txt> TK_SIZE TK_TL_SIZE TK_TIMEOUT TK_CONNECT_INT 
%token <txt> TK_RATE TK_USE_CSUMS TK_SKIP_SYNC TK_PING_INT 
%token <txt> TK_INTEGER TK_STRING TK_IPADDR TK_INCON_DEGR_CMD 

%type <d_option> disk_statements disk_statement 
%type <d_option> net_statements net_statement
%type <d_option> sync_statements sync_statement 
%type <d_resource> resources resource

%%
config:           global_sec resources   { config=$1; }
		;	 

global_sec:       /* empty */
                | TK_GLOBAL { glob_statements }
		;

glob_statements:  /* empty */
		| glob_statements glob_statement
		;

glob_statement:   TK_DISABLE_IO_HINTS
		| TK_MINOR_COUNT '=' TK_STRING   { $$=APPEND($1,$2); }
                ;

resources:        /* empty */   { $$ = 0; }
	    	| resources resource   { $$=APPEND($1,$2); }
		;

resource:	  TK_RESOURCE TK_STRING { c_res = new_resource($2); }
                  '{' res_statements '}' { $$ = c_res; }
		; 

res_statements:   /* empty */
		| res_statements res_statement
		| res_statements section
		;

res_statement:    TK_PROTOCOL '=' TK_STRING   { c_res->protocol=$3; }
		| TK_INCON_DEGR_CMD '=' TK_STRING   { c_res->ind_cmd=$3; }
		;
	
section:	  TK_DISK '{' disk_statements '}' { c_res->disk_options=$3; }
		| TK_NET  '{' net_statements '}'  { c_res->net_options=$3; }
		| TK_ON TK_STRING '{' host_statements '}' { host_sec($2); }
		| TK_SYNCER '{' sync_statements '}' { c_res->sync_options=$3; }
		;

disk_statements:  /* empty */   { $$ = 0; }
		| disk_statements disk_statement   { $$=APPEND($1,$2); }
		;

disk_statement:   TK_DO_PANIC   { $$=new_opt($1,0); }
		| TK_SIZE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

net_statements:   /* empty */   { $$ = 0; }
		| net_statements net_statement   { $$=APPEND($1,$2); }
		;

net_statement:    TK_TIMEOUT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_CONNECT_INT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_PING_INT '=' TK_INTEGER   { $$=new_opt($1,$3); }
		| TK_TL_SIZE  '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

sync_statements:  /* empty */   { $$ = 0; }
		| sync_statements sync_statement   { $$=APPEND($1,$2); }
		;

sync_statement:   TK_SKIP_SYNC   { $$=new_opt($1,0); }
		| TK_USE_CSUMS   { $$=new_opt($1,0); }
		| TK_RATE '=' TK_INTEGER   { $$=new_opt($1,$3); }
		;

host_statements:  /* empty */  { c_host=calloc(1,sizeof(struct d_host_info)); }
		| host_statements host_statement
		;

host_statement:   TK_DISK '=' TK_STRING     { c_host->disk=$3; }
		| TK_DEVICE '=' TK_STRING   { c_host->device=$3; }
		| TK_ADDRESS '=' TK_IPADDR  { c_host->address=$3; }
		| TK_PORT '=' TK_INTEGER    { c_host->port=$3; }
		;
