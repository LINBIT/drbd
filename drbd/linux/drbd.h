/*
  drbd.h
  Kernel module for 2.6.x Kernels

  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

  Copyright (C) 2001-2007, LINBIT Information Technologies GmbH.
  Copyright (C) 2001-2007, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2001-2007, Lars Ellenberg <lars.ellenberg@linbit.com>.

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
#else
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#endif

enum io_error_handler {
	PassOn, /* FIXME should the better be named "Ignore"? */
	CallIOEHelper,
	Detach
};

enum fencing_policy {
	DontCare,
	Resource,
	Stonith
};

enum disconnect_handler {
	Reconnect,
	DropNetConf,
	FreezeIO
};

enum after_sb_handler {
	Disconnect,
	DiscardYoungerPri,
	DiscardOlderPri,
	DiscardZeroChg,
	DiscardLeastChg,
	DiscardLocal,
	DiscardRemote,
	Consensus,
	DiscardSecondary,
	CallHelper,
	Violently
};

/* KEEP the order, do not delete or insert!
 * Or change the API_VERSION, too. */
enum ret_codes {
	RetCodeBase = 100,
	NoError,         /* 101 ... */
	LAAlreadyInUse,
	OAAlreadyInUse,
	LDNameInvalid,
	MDNameInvalid,
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
	MDIOError,
	MDInvalid,
	CRAMAlgNotAvail,
	CRAMAlgNotDigest,
	KMallocFailed,
	DiscardNotAllowed,
	HaveDiskConfig,
	HaveNetConfig,
	UnknownMandatoryTag,
	MinorNotKnown,
	StateNotAllowed,
	GotSignal, /* EINTR */
	NoResizeDuringResync,
	APrimaryNodeNeeded,
	SyncAfterInvalid,
	SyncAfterCycle,
	PauseFlagAlreadySet,
	PauseFlagAlreadyClear,
	DiskLowerThanOutdated,
	UnknownNetLinkPacket,
	HaveNoDiskConfig,
	ProtocolCRequired,
	VMallocFailed,

	/* insert new ones above this line */
	AfterLastRetCode
};

#define DRBD_PROT_A   1
#define DRBD_PROT_B   2
#define DRBD_PROT_C   3

enum drbd_role {
	Unknown = 0,
	Primary = 1,     /* role */
	Secondary = 2,   /* role */
	role_mask = 3,
};

/* The order of these constants is important.
 * The lower ones (<WFReportParams) indicate
 * that there is no socket!
 * >=WFReportParams ==> There is a socket
 *
 * THINK
 * Skipped should be < Connected,
 * so writes on a Primary after Skipped sync are not mirrored either ?
 */
enum drbd_conns {
	StandAlone,
	Disconnecting,  /* Temporal state on the way to StandAlone. */
	Unconnected,    /* >= Unconnected -> inc_net() succeeds */

	/* These temporal states are all used on the way
	 * from >= Connected to Unconnected.
	 * The 'disconnect reason' states
	 * I do not allow to change beween them. */
	Timeout,
	BrokenPipe,
	NetworkFailure,
	ProtocolError,
	TearDown,

	WFConnection,
	WFReportParams, /* we have a socket */
	Connected,      /* we have introduced each other */
	StartingSyncS,  /* starting full sync by IOCTL. */
	StartingSyncT,  /* stariing full sync by IOCTL. */
	WFBitMapS,
	WFBitMapT,
	WFSyncUUID,

	/* The distance between original state and pause
	 * state must be the same for source and target. (+2)
	 * All SyncStates are tested with this comparison
	 * xx >= SyncSource && xx <= PausedSyncT */
	SyncSource,
	SyncTarget,
	PausedSyncS,
	PausedSyncT,
	conn_mask = 31
};

enum drbd_disk_state {
	Diskless,
	Attaching,      /* In the process of reading the meta-data */
	Failed,         /* Becomes Diskless as soon as we told it the peer */
			/* when >= Failed it is legal to access mdev->bc */
	Negotiating,    /* Late attaching state, we need to talk to the peer */
	Inconsistent,
	Outdated,
	DUnknown,       /* Only used for the peer, never for myself */
	Consistent,     /* Might be Outdated, might be UpToDate ... */
	UpToDate,       /* Only this disk state allows applications' IO ! */
	disk_mask = 15
};

union drbd_state_t {
	struct {
		unsigned role : 2 ;   /* 3/4      primary/secondary/unknown */
		unsigned peer : 2 ;   /* 3/4      primary/secondary/unknown */
		unsigned conn : 5 ;   /* 17/32    cstates */
		unsigned disk : 4 ;   /* 8/16     from Diskless to UpToDate */
		unsigned pdsk : 4 ;   /* 8/16     from Diskless to UpToDate */
		unsigned susp : 1 ;   /* 2/2      IO suspended  no/yes */
		unsigned aftr_isp : 1 ; /* isp .. imposed sync pause */
		unsigned peer_isp : 1 ;
		unsigned user_isp : 1 ;
		unsigned _pad : 11;   /* 0        unused */
	};
	unsigned int i;
};

enum set_st_err {
	SS_CW_NoNeed = 4,
	SS_CW_Success = 3,
	SS_NothingToDo = 2,
	SS_Success = 1,
	SS_UnknownError = 0, /* Used to sleep longer in _drbd_request_state */
	SS_TwoPrimaries = -1,
	SS_NoUpToDateDisk = -2,
	SS_BothInconsistent = -4,
	SS_SyncingDiskless = -5,
	SS_ConnectedOutdates = -6,
	SS_PrimaryNOP = -7,
	SS_ResyncRunning = -8,
	SS_AlreadyStandAlone = -9,
	SS_CW_FailedByPeer = -10,
	SS_IsDiskLess = -11,
	SS_DeviceInUse = -12,
	SS_NoNetConfig = -13
};

/* from drbd_strings.c */
extern const char *conns_to_name(enum drbd_conns);
extern const char *roles_to_name(enum drbd_role);
extern const char *disks_to_name(enum drbd_disk_state);
extern const char *set_st_err_name(enum set_st_err);

#ifndef BDEVNAME_SIZE
# define BDEVNAME_SIZE 32
#endif

#define SHARED_SECRET_MAX 64

enum MetaDataFlags {
	__MDF_Consistent,
	__MDF_PrimaryInd,
	__MDF_ConnectedInd,
	__MDF_FullSync,
	__MDF_WasUpToDate,
	__MDF_PeerOutDated /* or worse (e.g. invalid). */
};
#define MDF_Consistent      (1<<__MDF_Consistent)
#define MDF_PrimaryInd      (1<<__MDF_PrimaryInd)
#define MDF_ConnectedInd    (1<<__MDF_ConnectedInd)
#define MDF_FullSync        (1<<__MDF_FullSync)
#define MDF_WasUpToDate     (1<<__MDF_WasUpToDate)
#define MDF_PeerOutDated    (1<<__MDF_PeerOutDated)

enum UuidIndex {
	Current,
	Bitmap,
	History_start,
	History_end,
	UUID_SIZE,      /* nl-packet: number of dirty bits */
	UUID_FLAGS,     /* nl-packet: flags */
	EXT_UUID_SIZE   /* Everything. */
};

#define UUID_JUST_CREATED ((__u64)4)

#define DRBD_MAGIC 0x83740267
#define BE_DRBD_MAGIC __constant_cpu_to_be32(DRBD_MAGIC)

/* these are of type "int" */
#define DRBD_MD_INDEX_INTERNAL -1
#define DRBD_MD_INDEX_FLEX_EXT -2
#define DRBD_MD_INDEX_FLEX_INT -3

/* Start of the new netlink/connector stuff */

#define DRBD_NL_CREATE_DEVICE 0x01
#define DRBD_NL_SET_DEFAULTS  0x02

/* The following line should be moved over to linux/connector.h
 * when the time comes */
#define CN_IDX_DRBD			0x4
#define CN_VAL_DRBD			0x1

struct drbd_nl_cfg_req {
	int packet_type;
	int drbd_minor;
	int flags;
	unsigned short tag_list[];
};

struct drbd_nl_cfg_reply {
	int packet_type;
	int minor;
	int ret_code; /* enum ret_code or set_st_err_t */
	unsigned short tag_list[]; /* only used with get_* calls */
};

#endif
