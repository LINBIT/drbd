#include <stdio.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>

#include "drbdadm.h"

extern int line;
extern int yyparse();
extern FILE* yyin;
extern int yydebug;

struct d_resource* config;

int dry_run=0;
char* drbdsetup;

/*** These functions are used the print the config again ***/

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
    printf("}\n\n");
    res=res->next;
  }
}

static void find_drbdsetup(void)
{
  static char* pathes[] = { "/sbin/drbdsetup", "./drbdsetup", 0 };
  struct stat buf;
  char **path;
  
  path=pathes;
  while(*path) {
    if(stat(*path,&buf)==0) {
      drbdsetup=*path;
      return;
    }
    path++;
  }

  fprintf(stderr,"Can not find drbdsetup");
  exit(20);
}

static int m_system(char** argv)
{
  int pid,status;

  if(dry_run) {
    while(*argv) {
      printf("%s ",*argv++);
    }
    printf("\n");

    return 0;
  }

  pid = fork();
  if(pid == -1) {
    fprintf(stderr,"Can not fork");
    exit(20);    
  }
  if(pid == 0) {
    execv(argv[0],argv);
    fprintf(stderr,"Can not exec");
    exit(20);    
  }
  while(1) {
    if (waitpid(pid, &status, 0) == -1) {
      if (errno != EINTR)
	return -1;
    } else
      return status;    
  }
}


static void conf_disk(struct d_resource* res)
{
  char* argv[20];
  struct d_option* opt;  

  while(res) {
    int argc=0;
    
    argv[argc++]=drbdsetup;
    argv[argc++]=res->me->device;
    argv[argc++]="disk";
    argv[argc++]=res->me->disk;
    opt=res->disk_options;
    while(opt) {
      char buffer[255],*b;

      b=alloca(snprintf(buffer,255,"--%s=%s",opt->name,opt->value)+1);
      strcpy(b,buffer);
      argv[argc++]=b;
      opt=opt->next;
    }
    argv[argc++]=0;

    m_system(argv);
    res=res->next;
  }
}

static void conf_net(struct d_resource* res)
{
  char buffer[255],*b;
  char* argv[20];
  struct d_option* opt;  

  while(res) {
    int argc=0;
    
    argv[argc++]=drbdsetup;
    argv[argc++]=res->me->device;
    argv[argc++]="net";
    b=alloca(snprintf(buffer,255,"%s:%s",res->me->address,res->me->port)+1);
    strcpy(b,buffer);
    argv[argc++]=b;
    b=alloca(snprintf(buffer,255,"%s:%s",res->partner->address,res->partner->port)+1);
    strcpy(b,buffer);
    argv[argc++]=b;
    argv[argc++]=res->protocol;

    opt=res->net_options;
    while(opt) {
      char buffer[255],*b;

      b=alloca(snprintf(buffer,255,"--%s=%s",opt->name,opt->value)+1);
      strcpy(b,buffer);
      argv[argc++]=b;
      opt=opt->next;
    }

    argv[argc++]=0;

    m_system(argv);
    res=res->next;
  }
}



int main(int argc, char** argv)
{
  
  if(argc>1) 
    {
      yyin = fopen(argv[1],"r");
    }

  yyparse();
  
  dry_run=1;
  find_drbdsetup(); // setup global variable drbdsetup.
  dump_conf(config);
  conf_disk(config);
  conf_net(config);

  return 0;
}

void yyerror(char* text)
{
  printf("LEXICAL ERROR in Line %d: %s\n",line,text);
  exit(1); 
}
