#include <stdio.h>

extern int line;
extern int yyparse();
extern FILE* yyin;
extern int yydebug;

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
  return 0;
}

void yyerror(char* text)
{
  printf("LEXICAL ERROR in Line %d: %s\n",line,text);
  exit(1); 
}
