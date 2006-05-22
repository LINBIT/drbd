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

#include <linux/drbd.h>

static const char *drbd_conn_s_names[] = {
	[StandAlone]     = "StandAlone",
	[Unconnected]    = "Unconnected",
	[Timeout]        = "Timeout",
	[BrokenPipe]     = "BrokenPipe",
	[NetworkFailure] = "NetworkFailure",
	[WFConnection]   = "WFConnection",
	[WFReportParams] = "WFReportParams",
	[TearDown]       = "TearDown",
	[Connected]      = "Connected",
	[SkippedSyncS]   = "SkippedSyncS",
	[SkippedSyncT]   = "SkippedSyncT",
	[WFBitMapS]      = "WFBitMapS",
	[WFBitMapT]      = "WFBitMapT",
	[WFSyncUUID]     = "WFSyncUUID",
	[SyncSource]     = "SyncSource",
	[SyncTarget]     = "SyncTarget",
	[PausedSyncS]    = "PausedSyncS",
	[PausedSyncT]    = "PausedSyncT"
};

static const char *drbd_role_s_names[] = {
	[Primary]   = "Primary",
	[Secondary] = "Secondary",
	[Unknown]   = "Unknown"
};

static const char *drbd_disk_s_names[] = {
	[DUnknown]     = "DUnknown",
	[Diskless]     = "Diskless",
	[Failed]       = "Failed",
	[Attaching]    = "Attaching",
	[Inconsistent] = "Inconsistent",
	[Outdated]     = "Outdated",
	[Consistent]   = "Consistent",
	[UpToDate]     = "UpToDate",
};

static const char *drbd_state_sw_errors[] = {
	[-SS_TowPrimaries] = "Multiple primaries now allowed by config",
	[-SS_NoConsistnetDisk] = 
		"Refusing to be Primary without at least one consistent disk",
	[-SS_BothInconsistent] = "Refusing to be inconsistent on both nodes",
	[-SS_SyncingDiskless] = "Refusing to be syncing and diskless",
	[-SS_ConnectedOutdates] = "Refusing to be Outdated while Connected",
	[-SS_PrimaryNOP] = "Refusing to be Primary while peer is not outdated",
	[-SS_CW_FailedByPeer] = "State changed was refused by peer node"
};

const char* conns_to_name(drbd_conns_t s) {
	/* enums are unsigned... */
	return s > PausedSyncT  ? "TOO_LARGE"
		                : drbd_conn_s_names[s];
}

const char* roles_to_name(drbd_role_t s) {
	return s > Secondary  ? "TOO_LARGE"
		              : drbd_role_s_names[s];
}

const char* disks_to_name(drbd_disks_t s) {
	return s > UpToDate    ? "TOO_LARGE"
		               : drbd_disk_s_names[s];
}

const char* set_st_err_name(set_st_err_t err) {
	return err < SS_CW_FailedByPeer ? "TOO_SMALL" :
	       err > SS_TowPrimaries ? "TOO_LARGE"
		        : drbd_state_sw_errors[-err];
}
