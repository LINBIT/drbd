/*
   show_size.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2002, Philipp Reisner <philipp.reisner@linbit.com>.
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
  long size;

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
  
  printf("Device size: %ld KB (%ld MB)\n",size/2,size/2048);

  return 0;
}
