#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#define BLOCK_S (1024)
#define NUMBER (BLOCK_S/sizeof(int))

main(int argc, char** argv)
{
  int data[NUMBER];
  int fd,blocks,i,j;
  sigset_t sset;


  if(argc != 3)
    {
      fprintf(stderr,"USAGE: %s device nr_of_blocks\n",argv[0]);
      exit(20);
    }
  
  fd = open(argv[1],O_RDWR);
  if(fd == -1) 
    {
      fprintf(stderr,"can not open %s.\n",argv[1]);
      exit(20);	      
    }
  blocks = atoi(argv[2]);
  
  sigfillset(&sset);
  sigprocmask(SIG_SETMASK,&sset,NULL);

  for(i=0;i<blocks;i++)
    {
      for(j=0;j<NUMBER;)
	{
	  data[j++] = i;
	  data[j++] = j;	    	
	}
      write(fd,data,BLOCK_S);
    }  
}
