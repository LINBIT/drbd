#include <stdio.h>
#include <string.h>
#include "drbdadm.h"

extern int line;
extern int yyparse();
extern FILE* yyin;
extern int yydebug;

struct d_resource* config;

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
    printf("    %s=%s\n",opts->name,opts->value);
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

static void dump_conf(struct d_resource* res)
{
  while(res) {
    printf("resource %s {\n",esc(res->name));
    printf("  protocol=%s\n",res->protocol);
    if(res->ind_cmd) printf("  incon-degr-cmd=%s\n",esc(res->ind_cmd));
    dump_host_info(res->me);
    dump_host_info(res->partner);
    dump_options("net",res->net_options);
    dump_options("disk",res->disk_options);
    dump_options("syncer",res->sync_options);
    res=res->next;
    printf("}\n\n");
  }
}

int main(int argc, char** argv)
{

  if(argc>1) 
    {
      yyin = fopen(argv[1],"r");
#ifdef YYDEBUG      
      yydebug = 1;
#endif      
    }

  yyparse();
  dump_conf(config);

  return 0;
}

void yyerror(char* text)
{
  printf("LEXICAL ERROR in Line %d: %s\n",line,text);
  exit(1); 
}
