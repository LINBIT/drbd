/*
  drbd.h
  Kernel module for 2.4.x/2.6.x Kernels

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
#include <linux/drbd_config.h>

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

/* 
   - Never forget to place bigger members before the smaller ones, 
     to avoid unaligned placement of members on 64 bit architectures. 
   - Never forget to add explicit _pad members to make sizeof(struct)
     divisible by 8.
*/

#define MAX_SOCK_ADDR	128	/* 108 for Unix domain -
				   16 for IP, 16 for IPX,
				   24 for IPv6,
				   about 80 for AX.25
				   must be at least one bigger than
				   the AF_UNIX size (see net/unix/af_unix.c
				   :unix_mkname()).
				 */

enum io_error_handler {
	PassOn,
	Panic,
	Detach
};


struct disk_config {
	IN __u64    disk_size;
	IN int      lower_device;
	IN enum io_error_handler on_io_error;
	IN int      meta_device;
	IN int      meta_index;
};

enum disconnect_handler {
	Reconnect,
	DropNetConf,
	FreezeIO
};

struct net_config {
	IN char     my_addr[MAX_SOCK_ADDR];
	IN char     other_addr[MAX_SOCK_ADDR];
	IN int      my_addr_len;
	IN int      other_addr_len;
	IN int      timeout;          // deci seconds
	IN int      wire_protocol;
	IN int      try_connect_int;  /* seconds */
	IN int      ping_int;         /* seconds */
	IN int      max_epoch_size;
	IN int      max_buffers;
	IN int      sndbuf_size;  /* socket send buffer size */
	IN int      two_primaries;
	IN unsigned int ko_count;
	IN enum disconnect_handler on_disconnect;
};

struct syncer_config {
	int      rate; /* KB/sec */
	int      use_csums;   /* use checksum based syncing*/
	int      skip;
	int      group;
	int      al_extents;
	const int _pad;
};

/* KEEP the order, do not delete or insert!
 * Or change the API_VERSION, too. */
enum ret_codes {
	NoError=0,
	LAAlreadyInUse,
	OAAlreadyInUse,
	LDFDInvalid,
	MDFDInvalid,
	LDAlreadyInUse,
	LDNoBlockDev,
	MDNoBlockDev,
	LDOpenFailed,
	MDOpenFailed,
	LDDeviceTooSmall,
	MDDeviceTooSmall,
	LDNoConfig,
	LDMounted,
	MDMounted,
	LDMDInvalid,
	LDDeviceTooLarge,
};

struct ioctl_disk_config {
	struct disk_config    config;
	OUT enum ret_codes    ret_code;
	const int             _pad;
};

struct ioctl_net_config {
	struct net_config     config;
	OUT enum ret_codes    ret_code;
	const int             _pad;
};

struct ioctl_syncer_config {
	struct syncer_config  config;
	OUT enum ret_codes    ret_code;
	const int             _pad;
};

struct ioctl_wait {
	IN int wfc_timeout;
	IN int degr_wfc_timeout;
	OUT int ret_code;
	int      _pad;
};

#define DRBD_PROT_A   1
#define DRBD_PROT_B   2
#define DRBD_PROT_C   3

typedef enum {
	Unknown=0,
	Primary=1,     // role
	Secondary=2,   // role
	role_mask=3,
	Human=4,           // flag for set_state
	TimeoutExpired=8,  // flag for set_state
	DontBlameDrbd=16   // flag for set_state
} drbd_role_t;

/* The order of these constants is important.
 * The lower ones (<WFReportParams) indicate
 * that there is no socket!
 * >=WFReportParams ==> There is a socket
 *
 * THINK
 * Skipped should be < Connected,
 * so writes on a Primary after Skipped sync are not mirrored either ?
 */
typedef enum {
	Unconfigured,
	StandAlone,
	Unconnected,
	Timeout,
	BrokenPipe,
	NetworkFailure,
	WFConnection,
	WFReportParams, // we have a socket
	Connected,      // we have introduced each other
	SkippedSyncS,   // we should have synced, but user said no
	SkippedSyncT,
	WFBitMapS,
	WFBitMapT,
	SyncSource,     // The distance between original state and pause
	SyncTarget,     // state must be the same for source and target. (+2)
	PausedSyncS,    // see _drbd_rs_resume() and _drbd_rs_pause()
	PausedSyncT,    // is sync target, but higher priority groups first
	conn_mask=31
} drbd_conns_t;

typedef enum {
	DUnknown,
	Diskless,
	Failed,         /* Becomes Diskless as soon as we told it the peer */
	Inconsistent,
	Outdated,
	Consistent,     /* Might be Outdated, might be UpToDate ... */
	UpToDate,
	disk_mask=7
} drbd_disks_t;

typedef union {
	struct {
		unsigned role : 2 ;   // 3/3      primary/secondary/unknown
		unsigned peer : 2 ;   // 3/3      primary/secondary/unknown
		unsigned conn : 5 ;   // 17/32    cstates
		unsigned disk : 3 ;   // 7/7      from DUnknown to UpToDate
		unsigned pdsk : 3 ;   // 7/7      from DUnknown to UpToDate
		unsigned susp : 1 ;   // 2/2      IO suspended  no/yes
		unsigned _pad : 16;   // 0        unused
	} s;
	unsigned int i;
} drbd_state_t;

/* from drbd_strings.c */
extern const char* conns_to_name(drbd_conns_t);
extern const char* roles_to_name(drbd_role_t);
extern const char* disks_to_name(drbd_disks_t);
extern const char* set_st_err_name(int);

#ifndef BDEVNAME_SIZE
# define BDEVNAME_SIZE 32
#endif

struct ioctl_get_config {
	OUT __u64             disk_size_user;
	OUT char              lower_device_name[BDEVNAME_SIZE];
	OUT char              meta_device_name[BDEVNAME_SIZE];
	struct net_config     nconf;
	struct syncer_config  sconf;
	OUT int               lower_device_major;
	OUT int               lower_device_minor;
	OUT enum io_error_handler on_io_error;
	OUT int               meta_device_major;
	OUT int               meta_device_minor;
	OUT int               meta_index;
	OUT drbd_state_t      state;
	int                   _pad;
};

#define DRBD_MAGIC 0x83740267
#define BE_DRBD_MAGIC __constant_cpu_to_be32(DRBD_MAGIC)

/* 'D' already taken by s390 dasd driver.
 *  maybe we want to change to something else, and register it officially?
 */
#define DRBD_IOCTL_LETTER 'D'
#define DRBD_IOCTL_GET_VERSION      _IOR( DRBD_IOCTL_LETTER, 0x00, int )
#define DRBD_IOCTL_SET_STATE        _IOW( DRBD_IOCTL_LETTER, 0x02, drbd_role_t )
#define DRBD_IOCTL_SET_DISK_CONFIG  _IOW( DRBD_IOCTL_LETTER, 0x06, struct ioctl_disk_config )
#define DRBD_IOCTL_SET_NET_CONFIG   _IOW( DRBD_IOCTL_LETTER, 0x07, struct ioctl_net_config )
#define DRBD_IOCTL_UNCONFIG_NET     _IO ( DRBD_IOCTL_LETTER, 0x08 )
#define DRBD_IOCTL_GET_CONFIG       _IOW( DRBD_IOCTL_LETTER, 0x0A, struct ioctl_get_config )
#define DRBD_IOCTL_INVALIDATE       _IO ( DRBD_IOCTL_LETTER, 0x0D )
#define DRBD_IOCTL_INVALIDATE_REM   _IO ( DRBD_IOCTL_LETTER, 0x0E )
#define DRBD_IOCTL_SET_SYNC_CONFIG  _IOW( DRBD_IOCTL_LETTER, 0x0F, struct ioctl_syncer_config )
#define DRBD_IOCTL_SET_DISK_SIZE    _IOW( DRBD_IOCTL_LETTER, 0x10, unsigned int )
#define DRBD_IOCTL_WAIT_CONNECT     _IOR( DRBD_IOCTL_LETTER, 0x11, struct ioctl_wait )
#define DRBD_IOCTL_WAIT_SYNC        _IOR( DRBD_IOCTL_LETTER, 0x12, struct ioctl_wait )
#define DRBD_IOCTL_UNCONFIG_DISK    _IO ( DRBD_IOCTL_LETTER, 0x13 )
#define DRBD_IOCTL_SET_STATE_FLAGS  _IOW( DRBD_IOCTL_LETTER, 0x14, drbd_role_t )
#define DRBD_IOCTL_OUTDATE_DISK     _IO ( DRBD_IOCTL_LETTER, 0x15 )


#endif

