#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char** argv)
{
  int fd1,fd2;
  unsigned char *m1,*m2,*p1,*p2;
  struct stat st1,st2;

  fd1 = open(argv[1],O_RDONLY);
  if(fd1==-1)
    { 
      fprintf(stderr,"Can not open input file/device\n");
      exit(20);
    }

  fd2 = open(argv[2],O_RDONLY);
  if(fd2==-1)
    {
      fprintf(stderr,"Can not open input file/device\n");
      exit(20);
    }

  fstat(fd1,&st1);
  fstat(fd2,&st2);

  m1=mmap(0,st1.st_size,PROT_READ,MAP_SHARED,fd1,0);
  if(m1==MAP_FAILED)
    {
      fprintf(stderr,"Can not mmap\n");
      exit(20);
    }

  m2=mmap(0,st2.st_size,PROT_READ,MAP_SHARED,fd2,0);
  if(m2==MAP_FAILED)
    {
      fprintf(stderr,"Can not mmap\n");
      exit(20);
    }
 
  p1=m1;
  p2=m2;
  while(1)
    {
      if(!memcmp(p1,p2,1024))
	{
	  if(*p2 == 0xA0 && p2[1] == 0xA0 && p2[2] == 0xA0 && p2[30] == 0xA0)
	    printf("Z");
	  else 
	    printf("=");
	}
      else
	{
	  if(*p1 == 0xA0 && *p2 == 0x05)
	   printf("-");
	 else 
	   {
	     if( *p2 == 0x05 )
	       printf("N");
	     else
	       printf("*");
	   }
	}
      p1=p1+1024;
      p2=p2+1024;
      if(p1 >= m1+st1.st_size) break;
    }
  
}




