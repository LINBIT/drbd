#include <stdio.h>
#include "drbdadm.h"

extern int line;
extern int yyparse();
extern FILE* yyin;
extern int yydebug;

struct cnode* global_conf;

void dump_conf(int indention,struct cnode* conf)
{
  while(conf) {
    if(conf->type==CNODE) {
      printf("%*s%s {\n",indention*3,"",conf->name);
      dump_conf(indention+1,conf->d.subtree);
      printf("%*s}\n",indention*3,"");
    } else {
      printf("%*s%s=%s\n",indention*3,"",conf->name,conf->d.value);
    }
    conf=conf->next;
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
  dump_conf(0,global_conf);

  return 0;
}

void yyerror(char* text)
{
  printf("LEXICAL ERROR in Line %d: %s\n",line,text);
  exit(1); 
}
