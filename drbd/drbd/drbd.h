/*
  drbd.h
  Kernel module for 2.4.x Kernels

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
#ifndef DRBD_H
#define DRBD_H
#include "../drbd_config.h"

#include <asm/types.h>

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <limits.h>
#endif

#ifdef __KERNEL__
#define IN const
#define OUT
#define INOUT
#else
#define IN
#define OUT const
#define INOUT
#endif


#define MAX_SOCK_ADDR	128	/* 108 for Unix domain -
				   16 for IP, 16 for IPX,
				   24 for IPv6,
				   about 80 for AX.25
				   must be at least one bigger than
				   the AF_UNIX size (see net/unix/af_unix.c
				   :unix_mkname()).
				 */

struct disk_config {
	IN int      lower_device;
	IN unsigned int disk_size;
	IN int      do_panic;  /* Panic on error upon LL_DEV */
};

struct net_config {
	IN char     my_addr[MAX_SOCK_ADDR];
	IN int      my_addr_len;
	IN char     other_addr[MAX_SOCK_ADDR];
	IN int      other_addr_len;
	IN int      timeout;          // deci seconds
	IN int      wire_protocol;
	IN int      try_connect_int;  /* seconds */
	IN int      ping_int;         /* seconds */
	IN int      max_epoch_size;
	IN int      max_buffers;
	IN int      sndbuf_size;  /* socket send buffer size */
};

struct syncer_config {
	int      rate; /* KB/sec */
	int      use_csums;   /* use checksum based syncing*/
	int      skip;
	int      group;
	int      al_extents;
};

enum ret_codes {
	NoError=0,
	LAAlreadyInUse,
	OAAlreadyInUse,
	LDFDInvalid,
	LDAlreadyInUse,
	LDNoBlockDev,
	LDOpenFailed,
	LDDeviceTooSmall,
	LDNoConfig,
	LDMounted
};

struct ioctl_disk_config {
	struct disk_config    config;
	OUT enum ret_codes    ret_code;
};

struct ioctl_net_config {
	struct net_config     config;
	OUT enum ret_codes    ret_code;
};

struct ioctl_syncer_config {
	struct syncer_config  config;
	OUT enum ret_codes    ret_code;
};

struct ioctl_wait {
	IN int wfc_timeout;
	IN int degr_wfc_timeout;
	OUT int ret_code;
};

#define DRBD_PROT_A   1
#define DRBD_PROT_B   2
#define DRBD_PROT_C   3

typedef enum {
	Unknown=0,
	Primary=1,     // role
	Secondary=2,   // role
	Human=4,           // flag for set_state
	TimeoutExpired=8,  // flag for set_state
	DontBlameDrbd=16   // flag for set_state
} Drbd_State;

/* The order of these constants is important.
 * The lower ones (<WFReportParams) indicate
 * that there is no socket!
 * >=WFReportParams ==> There is a socket
 */
typedef enum {
	Unconfigured,
	StandAlone,
	Unconnected,
	Timeout,
	BrokenPipe,
	WFConnection,
	WFReportParams, // we have a socket
	Connected,      // we have introduced each other
	SkippedSyncS,   // we should have synced, but user said no
	SkippedSyncT,
	WFBitMap,
	SyncSource,
	SyncTarget,
	PausedSyncS,    // is sync source, but higher priority groups first
	PausedSyncT,    // is sync target, but higher priority groups first
} Drbd_CState;

struct ioctl_get_config {
	struct net_config     nconf;
	struct syncer_config  sconf;
	OUT int               lower_device_major;
	OUT int               lower_device_minor;
	OUT unsigned int      disk_size_user;
	OUT int               do_panic;
	OUT Drbd_CState       cstate;
};


#define DRBD_MD_PATH   "/var/lib/drbd"
#define DRBD_MD_FILES  DRBD_MD_PATH"/drbd%d"

#define DRBD_MAGIC 0x83740267
#define BE_DRBD_MAGIC __constant_cpu_to_be32(DRBD_MAGIC)

#define DRBD_IOCTL_GET_VERSION   _IOR( 'D', 0x00, int )
#define DRBD_IOCTL_SET_STATE     _IOW( 'D', 0x02, Drbd_State )
#define DRBD_IOCTL_SET_DISK_CONFIG _IOW( 'D', 0x06, struct ioctl_disk_config )
#define DRBD_IOCTL_SET_NET_CONFIG _IOW( 'D', 0x07, struct ioctl_net_config )
#define DRBD_IOCTL_UNCONFIG_NET  _IO ( 'D', 0x08 )
#define DRBD_IOCTL_UNCONFIG_BOTH _IO ( 'D', 0x09 )
#define DRBD_IOCTL_GET_CONFIG    _IOW( 'D', 0x0A, struct ioctl_get_config)
#define DRBD_IOCTL_SECONDARY_REM _IOR( 'D', 0x0C, int )
#define DRBD_IOCTL_INVALIDATE    _IO ( 'D', 0x0D )
#define DRBD_IOCTL_INVALIDATE_REM _IO ( 'D', 0x0E )
#define DRBD_IOCTL_SET_SYNC_CONFIG _IOW( 'D', 0x0F,struct ioctl_syncer_config)
#define DRBD_IOCTL_SET_DISK_SIZE  _IOW( 'D', 0x10, unsigned int)
#define DRBD_IOCTL_WAIT_CONNECT  _IOR( 'D', 0x11, struct ioctl_wait)
#define DRBD_IOCTL_WAIT_SYNC     _IOR( 'D', 0x12, struct ioctl_wait)
#endif

