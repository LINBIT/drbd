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
  int fd;
  struct sockaddr_in other_addr;
  unsigned char data[1024];
  unsigned char header[16];
  Drbd_ParameterBlock param;
  Drbd_Packet rpacket;
  int i,nr;

  if(argc != 3) 
    {
      fprintf(stderr,"USAGE: %s other_addr nr_of_blocks\n",argv[0]);
      exit(20);
    }

  nr = atoi(argv[2]);

  fd = socket(PF_INET,SOCK_STREAM,0);
  if(fd == -1) exit(20);

  other_addr.sin_port = htons(7788);
  other_addr.sin_family = AF_INET;
  other_addr.sin_addr.s_addr = resolv(argv[1]);

  if(connect(fd,&other_addr,sizeof(struct sockaddr_in))==-1)
    exit(20);

  rpacket.magic=htonl(DRBD_MAGIC);
  rpacket.command=htons(ReportParams);
  rpacket.length=htons(sizeof(param));
  rpacket.block_nr = 0x0000000000000000;
  send(fd,&rpacket,sizeof(rpacket),0);
  param.my_size    = 0x0000100000000000;
  param.my_state=htonl(Primary);
  param.my_blksize=htonl(1024);
  send(fd,&param,sizeof(param),0);

  if(recv(fd,&rpacket,sizeof(rpacket),MSG_WAITALL)!=sizeof(rpacket)) 
    exit(20);
  if(recv(fd,data,ntohs(rpacket.length),MSG_WAITALL)!=ntohs(rpacket.length)) 
    exit(20);

  rpacket.magic=htonl(DRBD_MAGIC);
  rpacket.command=htons(Data);
  rpacket.length=htons(1024);
  rpacket.block_nr = 0x0000000000000000;

  for(i=0;i<1024;i++)
    data[i]=0;

  printf(" Sending ...\n");

  for(i=0;i<nr;i++)
    {
      send(fd,&rpacket,sizeof(rpacket),0);
      send(fd,data,1024,0);
    }
}










