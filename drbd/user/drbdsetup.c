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
  int dtbd_fd;

  if(argc != 5 && argc != 3)
    {
      fprintf(stderr,"USAGE: %s device lower_device local_address "
	               "remote_address\n"
	             "OR:    %s device (p|s)\n",argv[0],argv[0]);
      exit(20);
    }

  dtbd_fd=open(argv[1],O_RDONLY);
  if(dtbd_fd==-1)
    {
      perror("can not open device");
      exit(20);
    }

  if(argc == 3)
    {
      Drbd_State state;
      if(argv[2][0]=='p')
	{
	  state = Primary;
	}
      else if(argv[2][0]=='s')
	{
	  state = Secondary;
	}
      else 
	{
	  fprintf(stderr,"this is no known state!\n");
	  exit(20);
	}
      ioctl(dtbd_fd,DRBD_IOCTL_SET_STATE,state);
      printf("done.\n");
      exit(0);
    }

  if(argc == 5)
    {
      /*      int socket_fd; */
      int lower_device;
      struct ioctl_drbd_config config;
      struct sockaddr_in *other_addr;
      struct sockaddr_in *my_addr;
      int err;
      /*
      socket_fd = socket(PF_INET,SOCK_STREAM,0);
      if(socket_fd==-1)
	{
	  perror("socket()");
	  exit(20);
	}
      */
      if((lower_device = open(argv[2],O_RDWR))==-1)
	{
	  perror("Can not open lower device");
	  exit(20);
	}


      config.lower_device=lower_device;

      config.my_addr_len = sizeof(struct sockaddr_in);
      my_addr = (struct sockaddr_in *)config.my_addr;
      my_addr->sin_port = htons(7788);
      my_addr->sin_family = AF_INET;
      my_addr->sin_addr.s_addr = resolv(argv[3]);

      /*
      err = bind(socket_fd,my_addr,sizeof(struct sockaddr_in));
      if(err)
	{
	  perror("bind() failed");
	  exit(20);
	}
      */

      config.other_addr_len = sizeof(struct sockaddr_in);
      other_addr = (struct sockaddr_in *)config.other_addr;
      other_addr->sin_port = htons(7788);
      other_addr->sin_family = AF_INET;
      other_addr->sin_addr.s_addr = resolv(argv[4]);

      config.timeout = 30 ; /* = 3 seconds */
      config.sync_rate = 250; /* KB/sec */
      config.skip_sync = 0; 


      err=ioctl(dtbd_fd,DRBD_IOCTL_SET_CONFIG,&config);      
      if(err)
	{
	  perror("ioctl() failed");
	}
      printf("done.\n");
    }

  return 0;
}
