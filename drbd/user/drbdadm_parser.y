%{
#include <stdlib.h>
#include "drbdadm.h"

extern void yyerror(char* text);
extern int yylex();

struct cnode* cn_concat(struct cnode* list, struct cnode* new)
{
  new->next=list;

  printf("%p=cn_concat(%p,%p);\n",new,list,new);
  return new;
}

struct cnode* cn_new_value(char* name,char* value)
{
  struct cnode* cn = malloc(sizeof(struct cnode));

  cn->type=CVALUE;
  cn->name=name;
  cn->d.value=value;
  
  printf("%p=cn_new_value('%s','%s');\n",cn,name,value);
  return cn;
}

struct cnode* cn_new_sub(char* name,struct cnode* subtree)
{
  struct cnode* cn = malloc(sizeof(struct cnode));

  cn->type=CNODE;
  cn->name=name;
  cn->d.subtree=subtree;

  printf("%p=cn_new_sub('%s',%p);\n",cn,name,subtree);
  return cn;
}


%}

%union {
  char* txt;
  struct cnode* cnode;
}

%token TK_RESOURCE TK_DISK TK_NET TK_SYNCER TK_ON
%token <txt> TK_PROTOCOL TK_FSCK_CMD TK_DISK TK_DO_PANIC
%token <txt> TK_SIZE TK_TL_SIZE TK_TIMEOUT TK_CONNECT_INT 
%token <txt> TK_RATE TK_USE_CSUMS TK_SKIP_SYNC TK_DEVICE 
%token <txt> TK_PORT TK_INTEGER TK_STRING TK_IPADDR TK_INCON_DEGR_CMD 
%token <txt> TK_PING_INT TK_ADDRESS

%type <cnode> disk_statements disk_statement 
%type <cnode> net_statements net_statement
%type <cnode> sync_statements sync_statement 
%type <cnode> host_statements host_statement 
%type <cnode> res_statements res_statement
%type <cnode> resources resource
%type <cnode> section config

%%
config:           resources   { global_conf=$1; }
		;	 

resources:        /* empty */   { $$ = 0; }
	    	| resources resource   { $$=cn_concat($1,$2); }
		;

resource:	  TK_RESOURCE TK_STRING '{' res_statements '}' 
			  { $$=cn_new_sub($2,$4); }
		; 

res_statements:   /* empty */   { $$ = 0; }
		| res_statements res_statement   { $$=cn_concat($1,$2); }
		| res_statements section   { $$=cn_concat($1,$2); }
		;

res_statement:    TK_PROTOCOL '=' TK_STRING   { $$=cn_new_value($1,$3); }
		| TK_INCON_DEGR_CMD '=' TK_STRING   { $$=cn_new_value($1,$3); }
		;
	
section:	  TK_DISK '{' disk_statements '}' 
			  { $$=cn_new_sub("#DISK",$3); }
		| TK_NET  '{' net_statements '}'  
			  { $$=cn_new_sub("#NET",$3); }
		| TK_ON TK_STRING '{' host_statements '}' 
			  { $$=cn_new_sub($2,$4); }
		| TK_SYNCER '{' sync_statements '}' 
			  { $$=cn_new_sub("#SYNC",$3); }
		;

disk_statements:  /* empty */   { $$ = 0; }
		| disk_statements disk_statement   { $$=cn_concat($1,$2); }
		;

disk_statement:   TK_DO_PANIC   { $$=cn_new_value($1,"true"); }
		| TK_SIZE '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		;

net_statements:   /* empty */   { $$ = 0; }
		| net_statements net_statement   { $$=cn_concat($1,$2); }
		;

net_statement:    TK_TIMEOUT '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		| TK_CONNECT_INT '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		| TK_PING_INT '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		| TK_TL_SIZE  '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		;

sync_statements:  /* empty */   { $$ = 0; }
		| sync_statements sync_statement   { $$=cn_concat($1,$2); }
		;

sync_statement:   TK_SKIP_SYNC   { $$=cn_new_value($1,"true"); }
		| TK_USE_CSUMS   { $$=cn_new_value($1,"true"); }
		| TK_RATE '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		;

host_statements:  /* empty */   { $$ = 0; }
		| host_statements host_statement   { $$=cn_concat($1,$2); }
		;

host_statement:   TK_DISK '=' TK_STRING   { $$=cn_new_value($1,$3); }
		| TK_DEVICE '=' TK_STRING   { $$=cn_new_value($1,$3); }
		| TK_ADDRESS '=' TK_IPADDR   { $$=cn_new_value($1,$3); }
		| TK_PORT '=' TK_INTEGER   { $$=cn_new_value($1,$3); }
		;
