#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdio.h> 
#include <string.h>
#include "../drbd/drbd.h"

/* only defined in the headers included with glibc-2.1.2, not in glibc-2.1.1 */
#ifndef MSG_WAITALL
#define MSG_WAITALL	0x100
#endif

unsigned long resolv(char* name)
{
  unsigned long retval;

  if((retval = inet_addr(name)) == INADDR_NONE ) 
    {
      struct hostent *he;
      he = gethostbyname(name);
      if (!he)
	{
	  perror("can not resolv hostname");
	  exit(20);
	}
      retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
    }
  return retval;
}


int main(int argc, char** argv)
{
  int fd,rfd;
  struct sockaddr_in other_addr;
  unsigned char data[4096],rdata[4096];
  Drbd_ParameterBlock param;
  Drbd_Packet rpacket;
  int blocksize = 1024;
  int i;

  if(argc != 2 && argc != 3) 
    {
      fprintf(stderr,"USAGE: %s my_addr [blksize]\n",argv[0]);
      exit(20);
    }

  if(argc == 3)
    blocksize = atol(argv[2]);

  fd = socket(PF_INET,SOCK_STREAM,0);
  if(fd == -1) exit(20);

  other_addr.sin_port = htons(7788);
  other_addr.sin_family = AF_INET;
  other_addr.sin_addr.s_addr = resolv(argv[1]);

  if(bind(fd,&other_addr,sizeof(struct sockaddr_in))==-1)
    exit(20);

  listen(fd,5);
  
  while(1)
    {
      printf("\n waiting for connection\n");
      rfd = accept(fd,NULL,NULL);

      for(i=0;i<1024;i++)
	data[i]=0;

      printf(" accepted a connection \n");

      rpacket.magic=htonl(DRBD_MAGIC);
      rpacket.command=htons(ReportParams);
      rpacket.length=htons(sizeof(param));
      send(rfd,&rpacket,sizeof(rpacket),0);
      param.my_size=0x0000100000000000;
      param.my_state=htonl(Secondary);
      param.my_blksize=htonl(blocksize);
      send(rfd,&param,sizeof(param),0);

      for(i=0;;i++)
	{
	  if(recv(rfd,&rpacket,sizeof(rpacket),MSG_WAITALL)!=sizeof(rpacket)) 
	    break;
	  if(recv(rfd,rdata,ntohs(rpacket.length),MSG_WAITALL) != 
	     ntohs(rpacket.length)) 
	    break;
	  if(ntohl(rpacket.magic) != DRBD_MAGIC) printf(".\n");
	  if(ntohs(rpacket.length) == sizeof(param)) printf("got config\n");
	  /*else*/
	      /*if(memcmp(rdata,data,ntohs(rpacket.length))) printf("*\n");*/
	    /* if(ntohs(rpacket.length)!=1024) printf("*\n");*/
	  printf("  %6d  %4d\r",i,ntohs(rpacket.length)); fflush(stdout);
	}
    }
}



