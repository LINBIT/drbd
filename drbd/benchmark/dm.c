/*
   dm.c

   By Philipp Reisner.

   Copyright (C) 1999 2000, Philipp Reisner <philipp@linuxfreak.com>.
        Initial author.

   dm is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   dm is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with dm; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include<sys/time.h>
#define _GNU_SOURCE
#include <getopt.h>

#define min(a,b) ( (a) < (b) ? (a) : (b) )

unsigned long m_strtol(const char* s)
{
  char *e = (char*)s;
  long r;

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

void usage(char* prgname)
{
  fprintf(stderr,"USAGE: %s [options] \n"
	  "  Available options:\n"
	  "   --input-file val  -i val \n"
	  "   --output-file val -o val\n"
	  "   --buffer-size val -b val\n"
	  "   --seek-input val  -k val\n"
	  "   --seek-output val -l val\n"
	  "   --size val        -s val\n"
	  "   --sync            -y\n"
	  "   --progress        -m\n"
	  "   --performance     -p\n"
	  "   --help            -h\n",
	  prgname);
  exit(20);

}

int main(int argc, char** argv)
{
  char* buffer;
  size_t rr,ww;
  unsigned long seek_offs_i=0;
  unsigned long seek_offs_o=0;
  unsigned long size=-1,rsize;
  int in_fd=0, out_fd=1;
  unsigned long buffer_size=65536;
  int do_sync=0;
  int show_progress=0;
  int show_performance=0;
  struct timeval tv1,tv2;

  int c;
  static struct option options[] = {
    { "input-file",  required_argument, 0, 'i' },
    { "output-file", required_argument, 0, 'o' },
    { "buffer-size", required_argument, 0, 'b' },
    { "seek-input",  required_argument, 0, 'k' },
    { "seek-output", required_argument, 0, 'l' },
    { "size"       , required_argument, 0, 's' },
    { "sync",        no_argument,       0, 'y' },
    { "progress",    no_argument,       0, 'm' },
    { "performance", no_argument,       0, 'p' },
    { "help",        no_argument,       0, 'h' },
    { 0,             0,                 0, 0   }
  };

  while(1)
    {
      c = getopt_long(argc,argv,"i:o:b:k:l:s:ymph",options,0);
      if(c == -1) break;
      switch(c)
	{
	case 'i': 
	  in_fd = open(optarg,O_RDONLY);
	  if(in_fd==-1)
	    {
	      fprintf(stderr,"Can not open input file/device\n");
	      exit(20);
	    }
	  break;
	case 'o':
	  out_fd = open(optarg,O_WRONLY);
	  if(out_fd==-1)
	    {
	      fprintf(stderr,"Can not open output file/device\n");
	      exit(20);
	    }
	  break;
	case 'b':
	  buffer_size = m_strtol(optarg);
	  break;
	case 'k':
	  seek_offs_i = m_strtol(optarg);
	  break;
	case 'l':
	  seek_offs_o = m_strtol(optarg);
	  break;
	case 's':
	  size = m_strtol(optarg);
	  break;
	case 'y':
	  do_sync = 1;
	  break;
	case 'm':
	  show_progress = 1;
	  break;
	case 'p':
	  show_performance = 1;
	  break;
	case 'h':
	  usage(argv[0]);
	  break;
	}
    }
  
  buffer=malloc(buffer_size);
  if(!buffer)
    {
      fprintf(stderr,"Can not allocate the Buffer memory\n");
      exit(20);
    }

  if(seek_offs_i)
    {
      if(lseek(in_fd,seek_offs_i,SEEK_SET) != seek_offs_i)
	{
	  fprintf(stderr,"Can not lseek(2) in input file/device\n");
	  exit(20);
	}
    }

  if(seek_offs_o)
    {
      if(lseek(out_fd,seek_offs_o,SEEK_SET) != seek_offs_o)
	{
	  fprintf(stderr,"Can not lseek(2) in input file/device\n");
	  exit(20);
	}
    }

  rsize = size;
  gettimeofday(&tv1,NULL);
  while(1)
    {
      rr=read(in_fd,buffer,(size_t)min(buffer_size,rsize));
      if(rr==0) break;
      if(rr==-1)
	{
	  perror("Read failed");
	  exit(20);
	}
      if(rr==buffer_size) 
	{
	  if(show_progress)
	    {
	      printf("R");
	      fflush(stdout);
	    }
	}
      else 
	{
	  if(show_progress)
	    {
	      printf("r");
	      fflush(stdout);
	    }
	}
      ww=write(out_fd,buffer,rr);
      if(ww==-1)
	{
	  perror("Write failed");
	  exit(20);	  
	}
      if(ww!=rr)
	{
	  fprintf(stderr,"Write returned odd number!\n");
	  exit(20);	  
	}
      rsize = rsize - ww;
    }
      
  if(do_sync) fsync(out_fd);

  gettimeofday(&tv2,NULL);

  if(show_performance)
    {
      long mps = (100 * (size - rsize)) /
	((tv2.tv_sec-tv1.tv_sec)*1000000+tv2.tv_usec-tv1.tv_usec);
      long sec = tv2.tv_sec - tv1.tv_sec;
      long usec = tv2.tv_usec-tv1.tv_usec;
      if(usec<0)
	{
	  sec--;
	  usec+=1000000;
	}

      mps = (mps * 15625) / 16385;

      printf("%ld.%02ld MB/sec (%ld B / %02ld:%02ld.%06ld)\n",mps/100,mps%100,
	     size-rsize,sec/60,sec%60,usec);
    }

  if(size != -1 && rsize)
    fprintf(stderr,"Could transfer only %ld Byte.\n",(size - rsize)); 

  return 0;
}

