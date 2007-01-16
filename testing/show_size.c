/*
   show_size.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2002-2007, LINBIT Information Technologies GmbH.
   Copyright (C) 2002-2007, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2007, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

typedef unsigned long long u64;

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/fs.h>

int main(int argc, char** argv)
{
  int fd,err;
  struct stat drbd_stat;
  u64 size64=0;
  long size=0;

  if(argc != 2) 
    {
      fprintf(stderr, "USAGE: %s device\n", argv[0]);
      exit(20);
    }

  fd=open(argv[1],O_RDONLY);
  if(fd==-1)
    {
      perror("can not open device");
      exit(20);
    }

  
  err=fstat(fd, &drbd_stat);
  if(err)
    {
      perror("fstat() failed");
    }

  if(!S_ISBLK(drbd_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", argv[1]);
      exit(20);
    }
  err=ioctl(fd,BLKGETSIZE,&size);
  if(err)
    {
      perror("ioctl() failed");
    }
  
  printf("BLKGETSIZE: %ld sectors: %ld KB   %ld MB  %ld GB\n",
	 size, size/2,size/2048,size/2097152);

  err=ioctl(fd,BLKGETSIZE64,&size64);
  if(err)
    {
      perror("ioctl() failed");
    }
  
  printf("BLKGETSIZE64: %llu byte: %llu KB   %llu MB  %llu GB  %llu TB \n",
	 size64,size64/(1U<<10),size64/(1LU<<20),size64/(1LLU<<30),
	 size64/(1LLU<<40));

  return 0;
}
