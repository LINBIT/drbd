/*
   show_size.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999 2000, Philipp Reisner <philipp@linuxfreak.com>.
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
#include <fcntl.h>
#include <stdio.h>
#include <linux/fs.h>

int main(int argc, char** argv)
{
  int drbd_fd,err,version;
  struct stat drbd_stat;
  long size;

  if(argc != 2) 
    {
      fprintf(stderr, "USAGE: %s device\n", argv[0]);
      exit(20);
    }

  drbd_fd=open(argv[1],O_RDONLY);
  if(drbd_fd==-1)
    {
      perror("can not open device");
      exit(20);
    }

  
  err=fstat(drbd_fd, &drbd_stat);
  if(err)
    {
      perror("fstat() failed");
    }
  if(!S_ISBLK(drbd_stat.st_mode))
    {
      fprintf(stderr, "%s is not a block device!\n", argv[1]);
      exit(20);
    }
  err=ioctl(drbd_fd,BLKGETSIZE,&size);
  if(err)
    {
      perror("ioctl() failed");
    }
  
  printf("Device size: %ld KB (%ld MB)\n",size,size/1024);

  return 0;
}
