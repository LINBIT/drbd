/*
   access_and_verify.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

   drbd is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   drbd is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with drbd; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#define _GNU_SOURCE /* want lseek64 to be declared */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <linux/fs.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>


static struct option options[] = {        
  { "block-size",   required_argument, 0, 'b' },
  { "read-latency", required_argument, 0, 'l' },
  { "device",       required_argument, 0, 'd' },
  { "help",         no_argument,       0, 'h' },
  { 0,              0,                 0, 0   }
};

int run=1;
int *datab; // data block buffer

static void usage(char* prgname,int exit_code)
{
  struct option *option;

  printf("USAGE: %s [options] \n\n"
	  " Available options are\n",prgname);

  option = options;

  while(option->name) 
    {
      if(option->has_arg == required_argument) 
	printf(" --%s | -%c  val\n",option->name,option->val);
      else 
      printf(" --%s | -%c\n",option->name,option->val);
      option++;
    }

  printf("You may postfix numeric values with one of the multiplicators: "
	 "k,M or G\n");

  exit(exit_code);
}

static unsigned long long m_strtol(const char* s)
{
  char *e = (char*)s;
  unsigned long long r;

  r = strtol(s,&e,0);
  switch(*e)
    {
    case 0:
      return r;
    case 'K':
    case 'k':
      return r*1024;
    case 'M':
    case 'm':
      return r*1024*1024;
    case 'G':
    case 'g':      
      return r*1024*1024*1024;
    default:
      fprintf(stderr,"%s is not a valid number\n",s);
      exit(20);
    }
}

static const char* make_optstring(struct option *options)
{
  static char buffer[200];
  static struct option* buffer_valid_for=NULL;
  struct option *opt;
  char *c;

  if(options==buffer_valid_for) return buffer;
  opt=buffer_valid_for=options;
  c=buffer;
  *c++='-';
  while(opt->name)
    {
      *c++=opt->val;
      if(opt->has_arg) *c++=':';
      opt++;
    }
  *c=0;
  return buffer;
}

static unsigned long long fsize(int in_fd)
{
  struct stat dm_stat;
  unsigned long long size;
  
  if(fstat(in_fd, &dm_stat))
    {
      perror("Can not fstat");
      exit(20);
    }
  if(S_ISBLK(dm_stat.st_mode))
    {
      unsigned long ls;
      if( ioctl(in_fd,BLKGETSIZE,&ls) )
	{
	  perror("Can not ioctl(BLKGETSIZE)");
	  exit(20);
	}
      size=((unsigned long long)ls)*512;
    }
  else if(S_ISREG(dm_stat.st_mode))
    {
      size=dm_stat.st_size;
    }
  else size=-1;

  return size;
}

static int get_blocksize(int fd)
{
  int block_size;

  if( ioctl(fd,BLKBSZGET,&block_size))
    {
      perror("Can not ioctl(BLKBSZGET)");
      exit(20);      
    }
  return block_size;
}

void set_blocksize(int fd, int block_size)
{
  if( ioctl(fd,BLKBSZSET,&block_size))
    {
      perror("Can not ioctl(BLKBSZSET)");
      exit(20);      
    }
}

// Returns the run_number found in the block.
static 
int read_check(int fd,unsigned long block,int block_size,int run_number)
{
  unsigned long long offset;

  offset = ((unsigned long long)block) * block_size;
  if(lseek64(fd,offset,SEEK_SET) == -1)
    {
      perror("Can not lseek(2) in device");
      exit(20);
    }

  if( read(fd,datab,block_size) != block_size ) 
    {
      fprintf(stderr,"Read from device failed\n");
      exit(20);
    }

  if( run_number != datab[ block % (block_size/sizeof(int)-1) ] )
    {
      fprintf(stderr,"While reading block %lu got _not_ what was"
	      "written before!\n"
	      "Block number signature found is %d\n",
	      block, datab[ (block_size/sizeof(int)-1) ] );
      exit(20);
    }
  datab[ block % (block_size/sizeof(int)-1) ] = 0;

  return run_number;
}

static 
void write_pattern(int fd,unsigned long block,int block_size,int run_number)
{
  unsigned long long offset;

  offset = ((unsigned long long)block) * block_size;
  if(lseek64(fd,offset,SEEK_SET) == -1)
    {
      perror("Can not lseek(2) in device");
      exit(20);
    }

  datab[ block % (block_size/sizeof(int)-1) ] = run_number;
  datab[ (block_size/sizeof(int)-1) ] = block;

  if( write(fd,datab,block_size) != block_size ) 
    {
      perror("Write to device failed");
      fprintf(stderr,"block=%lu\n",block);
      exit(20);
    }

  datab[ block % (block_size/sizeof(int)-1) ] = 0;

}

static 
unsigned long makeup_block_nr(unsigned long long device_size,int block_size)
{
  static int sequence=0;
  static unsigned long block;

  if(sequence == 0) 
    { 
      sequence = rand() % 500;
      block = rand();
      block = block % ( device_size / block_size );
    }
  else 
    {
      block++;
      block = block % ( device_size / block_size );
      sequence--;
    }

  return block;
}

static void intr_handler(int signo)
{
  run=0;
}

int main(int argc, char** argv)
{
  int fd=0;
  int block_size=0;
  int rl_bytes=128*1024*1024; // read_latency
  int rl_blocks; //read_latency
  unsigned long long device_size;
  int run_number; //different for each run!
  char c;

  unsigned long* latencyb; // buffer for block numbers
  int i;
  unsigned long block;
  unsigned long bcnt=0,bcnt_last=0;
  time_t time_last,time_start;

  struct sigaction sa;

  printf("\nThis is a combined write/read/verify test. It writes\n"
	 "up to 500 adjacent blocks, then it continues at a random block.\n"
	 "As soon as [read_latency] bytes are written it also reads\n"
	 "the previously written data and verifies that the data\n"
	 "read back is the same as what was written before.\n"
	 "Please make sure that [read_latency] is bigger than your physical\n"
	 "RAM.\n\n");

  while(1)
    {
      c = getopt_long(argc,argv,make_optstring(options),options,0);
      if(c == -1) break;
      switch(c)
	{
	case 'b': 
	  block_size=m_strtol(optarg);
	  break;
	case 'l':
	  rl_bytes=m_strtol(optarg);
	  break;
	case 'h':
	  usage(argv[0],0);
	  break;
	case 'd':
	  fd = open(optarg,O_RDWR);
	  if(fd==-1)
	    {
	      perror("Can not open device");
	      exit(20);
	    }
	  break;
	}
    }

  if(fd == 0) {
    fprintf(stderr,"You have to specify a device.\n");
    usage(argv[0],20);
  }

  if(block_size == 0) block_size = get_blocksize(fd);
  else set_blocksize(fd,block_size);
  device_size=fsize(fd);
  rl_blocks=rl_bytes/block_size;
  run_number=time(NULL);

  if( ! (datab=malloc(block_size)) ) 
    {
      perror("Can not malloc datab.");
      exit(20);
    }
  memset(datab,block_size,1);

  if( ! (latencyb=malloc(rl_blocks * sizeof(unsigned long))) ) 
    {
      perror("Can not malloc latencyb.");
      exit(20);
    }

  for(i=0;i<rl_blocks;i++) latencyb[i]=-1;

  printf("device_size = %llu.%llu MB \n"
	 "block_size = %d Byte\n"
	 "read_latency = %d Byte / %d Blocks\n"
	 "run_number = %d\n\n"
	 "press CTRL-C to abort test\n",
	 device_size / (1024*1024), device_size % (1024*1024),
	 block_size,
	 rl_bytes,rl_blocks,
	 run_number);

  sa.sa_handler=&intr_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags=0;
  sigaction(SIGINT,&sa,NULL);

  time_last=time(NULL);
  time_start=time_last;
  i=0;  

  while(run) 
    {
      block=latencyb[i];
      if(block != -1) 
	{ 
	  read_check(fd,block,block_size,run_number);
	}
      block = makeup_block_nr(device_size,block_size);
      latencyb[i]=block;
      write_pattern(fd,block,block_size,run_number);
      bcnt++;

      if( time_last != time(NULL) )
	{
	  int kb_p_second;
	  int kb_avg;
	  kb_p_second=((bcnt-bcnt_last)/(block_size/1024))/
	    (time(NULL)-time_last);
	  kb_avg=(bcnt/(block_size/1024))/(time(NULL)-time_start);
	  printf("IO throughput is %d.%d MB/sec (avg %d.%d MB/sec) "
		 "runnning %ld seconds    \r",
		 kb_p_second/1024,kb_p_second%1024,
		 kb_avg/1024,kb_avg%1024,time(NULL)-time_start);
	  fflush(stdout);

	  time_last = time(NULL);
	  bcnt_last = bcnt;
	}
      if( ++i == rl_blocks) i=0;
    }

  printf("\n\nCTRL-C pressed. Test aborted.\n"
	 "Please be patient while the system flushes write buffers.\n");
  
  free(latencyb);
  free(datab);

  close(fd);

  return 0;
}
