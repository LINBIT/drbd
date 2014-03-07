/*
  drbd.h

  This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

  Copyright (C) 2003-2008, LINBIT Information Technologies GmbH.
  Copyright (C) 2003-2008, Philipp Reisner <philipp.reisner@linbit.com>.
  Copyright (C) 2003-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#include <linux/drbd.h>
#include "drbd_strings.h"

const char *drbd_conn_s_names[] = {
	[C_STANDALONE]       = "StandAlone",
	[C_DISCONNECTING]    = "Disconnecting",
	[C_UNCONNECTED]      = "Unconnected",
	[C_TIMEOUT]          = "Timeout",
	[C_BROKEN_PIPE]      = "BrokenPipe",
	[C_NETWORK_FAILURE]  = "NetworkFailure",
	[C_PROTOCOL_ERROR]   = "ProtocolError",
	[C_TEAR_DOWN]        = "TearDown",
	[C_CONNECTING]       = "Connecting",
	[C_CONNECTED]	     = "Connected",
	0
};

const char *drbd_repl_s_names[] = {
	[L_OFF]              = "Off",
	[L_ESTABLISHED]      = "Established",
	[L_STARTING_SYNC_S]  = "StartingSyncS",
	[L_STARTING_SYNC_T]  = "StartingSyncT",
	[L_WF_BITMAP_S]      = "WFBitMapS",
	[L_WF_BITMAP_T]      = "WFBitMapT",
	[L_WF_SYNC_UUID]     = "WFSyncUUID",
	[L_SYNC_SOURCE]      = "SyncSource",
	[L_SYNC_TARGET]      = "SyncTarget",
	[L_VERIFY_S]         = "VerifyS",
	[L_VERIFY_T]         = "VerifyT",
	[L_PAUSED_SYNC_S]    = "PausedSyncS",
	[L_PAUSED_SYNC_T]    = "PausedSyncT",
	[L_AHEAD]            = "Ahead",
	[L_BEHIND]           = "Behind",
	0
};

const char *drbd_role_s_names[] = {
	[R_PRIMARY]   = "Primary",
	[R_SECONDARY] = "Secondary",
	[R_UNKNOWN]   = "Unknown",
	0
};

const char *drbd_disk_s_names[] = {
	[D_DISKLESS]     = "Diskless",
	[D_ATTACHING]    = "Attaching",
	[D_DETACHING]    = "Detaching",
	[D_FAILED]       = "Failed",
	[D_NEGOTIATING]  = "Negotiating",
	[D_INCONSISTENT] = "Inconsistent",
	[D_OUTDATED]     = "Outdated",
	[D_UNKNOWN]      = "DUnknown",
	[D_CONSISTENT]   = "Consistent",
	[D_UP_TO_DATE]   = "UpToDate",
	0
};

const char *drbd_state_sw_errors[] = {
	[-SS_TWO_PRIMARIES] = "Multiple primaries not allowed by config",
	[-SS_NO_UP_TO_DATE_DISK] = "Need access to UpToDate data",
	[-SS_NO_LOCAL_DISK] = "Can not resync without local disk",
	[-SS_NO_REMOTE_DISK] = "Can not resync without remote disk",
	[-SS_CONNECTED_OUTDATES] = "Refusing to be Outdated while Connected",
	[-SS_PRIMARY_NOP] = "Refusing to be Primary while peer is not outdated",
	[-SS_RESYNC_RUNNING] = "Can not start OV/resync since it is already active",
	[-SS_ALREADY_STANDALONE] = "Can not disconnect a StandAlone device",
	[-SS_CW_FAILED_BY_PEER] = "State change was refused by peer node",
	[-SS_IS_DISKLESS] = "Device is diskless, the requested operation requires a disk",
	[-SS_DEVICE_IN_USE] = "Device is held open by someone",
	[-SS_NO_NET_CONFIG] = "Have no net/connection configuration",
	[-SS_NO_VERIFY_ALG] = "Need a verify algorithm to start online verify",
	[-SS_NEED_CONNECTION] = "Need a connection to start verify or resync",
	[-SS_NOT_SUPPORTED] = "Peer does not support protocol",
	[-SS_LOWER_THAN_OUTDATED] = "Disk state is lower than outdated",
	[-SS_IN_TRANSIENT_STATE] = "In transient state, retry after next state change",
	[-SS_CONCURRENT_ST_CHG] = "Concurrent state changes detected and aborted",
	[-SS_O_VOL_PEER_PRI] = "Other vol primary on peer not allowed by config",
	[-SS_PRIMARY_READER] = "Peer may not become primary while device is opened read-only",
	[-SS_INTERRUPTED] = "Interrupted state change",
	[-SS_TIMEOUT] = "Timeout in operation",
	[-SS_WEAKLY_CONNECTED] = "Primary nodes must be strongly connected among each other",
	0
};

const char *drbd_repl_str(enum drbd_repl_state s)
{
	int size = sizeof drbd_repl_s_names / sizeof drbd_repl_s_names[0];
	return s < 0 || s >= size ||
	       !drbd_repl_s_names[s] ? "?" : drbd_repl_s_names[s];
}

const char *drbd_conn_str(enum drbd_conn_state s)
{
	int size = sizeof drbd_conn_s_names / sizeof drbd_conn_s_names[0];
	return s < 0 || s >= size ||
	       !drbd_conn_s_names[s] ? "?" : drbd_conn_s_names[s];
}

const char *drbd_role_str(enum drbd_role s)
{
	int size = sizeof drbd_role_s_names / sizeof drbd_role_s_names[0];
	return s < 0 || s >= size ||
	       !drbd_role_s_names[s] ? "?" : drbd_role_s_names[s];
}

const char *drbd_disk_str(enum drbd_disk_state s)
{
	int size = sizeof drbd_disk_s_names / sizeof drbd_disk_s_names[0];
	return s < 0 || s >= size ||
	       !drbd_disk_s_names[s] ? "?" : drbd_disk_s_names[s];
}

const char *drbd_set_st_err_str(enum drbd_state_rv err)
{
	int size = sizeof drbd_state_sw_errors / sizeof drbd_state_sw_errors[0];
	return -err < 0 || -err >= size ||
	       !drbd_state_sw_errors[-err] ? "?" : drbd_state_sw_errors[-err];
}
