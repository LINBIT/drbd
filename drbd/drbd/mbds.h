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

#define SS_OUT_OF_SYNC (1)
#define SS_IN_SYNC     (0)

/* Mirroring block device's syncer operations */
struct mbds_operations { 
	void* (*init)               (kdev_t dev);
	/* May _not_ return NULL */
	void (*cleanup)            (void* id);
	void (*reset)              (void* id,int ln2_bs);
	void (*set_block_status)   (void* id,unsigned long blocknr,
				    int ln2_bs, int status);	
	/*
	  id          is the pointer returned by init(kdev_t)
	  blocknr     block number
	  ln2_bs      ln2(blocksize); e.g. ln2_bs=10 <=> blocksize=1024
	  status      one of SS_OUT_OF_SYNC or SS_IN_SYNC
	*/
	unsigned long (*get_block) (void* id, int ln2_bs);
};

#define MBDS_SYNC_ALL (-2)
#define MBDS_DONE     (-3)


#define BLKSYNCISET   _IOW(0x12,106, struct mbds_operations) 
#define BLKSYNCIUNSET _IO(0x23,107)


#endif /* ifndef MBDS_H */
