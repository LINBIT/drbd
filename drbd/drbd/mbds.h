/*
  mbds.h
  Kernel module for 2.2.x Kernels
  
  This file is part of drbd by Philipp Reisner.

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

#ifndef MBDS_H
#define MBDS_H

#include <linux/ioctl.h>

/* Mirroring block device's syncer operations */
struct mbds_operations { 
  void (*block_not_replicated) (kdev_t dev, unsigned long blocknr); 
  int (*get_blocks_need_sync) (kdev_t dev, unsigned long *blocknrs, int count);
};

#define MBDS_SYNC_ALL -2
#define MBDS_DONE -3

/*
    
  mirror_lost()
  mirror_rejoined()
     I think these are too loose, what happens to all that blocks
     somwhere on the fly??

  block_not_replicated(blocknr)
                     This block was not replicated by drbd.

  get_blocks_need_sync(*blocknrs,count)
                     get_blocks_need_sync should write up to count
		     block numbers into blocknrs and return the nuber
		     of entries written. 
		     If all blocks are synced it should return MBDS_DONE.
                     If the filesystem can not fullfill the request it
                     may return MBDS_SYNC_ALL.
*/

#define BLKSYNCISET   _IOW(0x12,106, struct mbds_operations) 
#define BLKSYNCIUNSET _IO(0x23,107)


#endif /* ifndef MBDS_H */
