%{

extern void yyerror(char* text);
extern int yylex();

%}

%token TK_RESOURCE TK_PROTOCOL TK_FSCK_CMD TK_DISK TK_DO_PANIC
%token TK_DISK TK_SIZE TK_NET TK_TL_SIZE TK_TIMEOUT TK_CONNECT_INT TK_PING_INT
%token TK_SYNCER TK_RATE TK_USE_CSUMS TK_SKIP_SYNC TK_ON TK_DEVICE TK_ADDRESS
%token TK_PORT TK_INTEGER TK_STRING TK_IPADDR TK_INCON_DEGR_CMD

%%
config:           resources ;	 

resources:        /* empty */
	    	| resources resource 
		;

resource:	  TK_RESOURCE TK_STRING '{' res_statements '}' ;

res_statements:   /* empty */
		| res_statements res_statement
		| res_statements section 
		;

res_statement:    TK_PROTOCOL TK_STRING ';'
		| TK_INCON_DEGR_CMD TK_STRING ';'
		;
	
section:	  TK_DISK '{' disk_statements '}'
		| TK_NET  '{' net_statements '}'
		| TK_ON TK_STRING '{' host_statements '}'
		| TK_SYNCER '{' sync_statements '}' 
		;

disk_statements:  /* empty */
		| disk_statements disk_statement 
		;

disk_statement:   TK_DO_PANIC ';'
		| TK_SIZE TK_INTEGER ';'
		;

net_statements:   /* empty */
		| net_statements net_statement 
		;

net_statement:    TK_TIMEOUT TK_INTEGER ';'
		| TK_CONNECT_INT TK_INTEGER ';'
		| TK_PING_INT TK_INTEGER ';'
		| TK_TL_SIZE  TK_INTEGER ';'
		;

sync_statements:  /* empty */
		| sync_statements sync_statement 
		;

sync_statement:   TK_SKIP_SYNC ';'
		| TK_USE_CSUMS ';'
		| TK_RATE TK_INTEGER ';'
		;

host_statements:  /* empty */
		| host_statements host_statement 
		;

host_statement:   TK_DISK TK_STRING ';'
		| TK_DEVICE TK_STRING ';'
		| TK_ADDRESS TK_IPADDR ';'
		| TK_PORT TK_INTEGER ';'
		;
