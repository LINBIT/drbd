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
	[Unconfigured]   = "Unconfigured",
	[StandAlone]     = "StandAlone",
	[Unconnected]    = "Unconnected",
	[Timeout]        = "Timeout",
	[BrokenPipe]     = "BrokenPipe",
	[NetworkFailure] = "NetworkFailure",
	[WFConnection]   = "WFConnection",
	[WFReportParams] = "WFReportParams",
	[Connected]      = "Connected",
	[SkippedSyncS]   = "SkippedSyncS",
	[SkippedSyncT]   = "SkippedSyncT",
	[WFBitMapS]      = "WFBitMapS",
	[WFBitMapT]      = "WFBitMapT",
	[SyncSource]     = "SyncSource",
	[SyncTarget]     = "SyncTarget",
	[PausedSyncS]    = "PausedSyncS",
	[PausedSyncT]    = "PausedSyncT",
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
	[Inconsistent] = "Inconsistent",
	[Outdated]     = "Outdated",
	[Consistent]   = "Consistent",
	[UpToDate]     = "UpToDate",
};

static const char *drbd_state_sw_errors[] = {
	[1] = "Multiple primaries now allowed by config",
	[2] = "Refusing to be Primary without at least one consistent disk",
	[3] = "Refusing to make peer Primary without disk",
	[4] = "Refusing to be inconsistent on both nodes",
	[5] = "Refusing to be syncing and diskless",
	[6] = "Refusing to be Outdated while Connected",
	[7] = "Refusing to be Primary while peer is not outdated",
};

const char* conns_to_name(drbd_conns_t s) {
	return s < Unconfigured ? "TO_SMALL" :
	       s > PausedSyncT  ? "TO_LARGE"
		                : drbd_conn_s_names[s];
}

const char* roles_to_name(drbd_role_t s) {
	return s < Unknown    ? "TO_SMALL" :
	       s > Secondary  ? "TO_LARGE"
		              : drbd_role_s_names[s];
}

const char* disks_to_name(drbd_disks_t s) {
	return s < Diskless    ? "TO_SMALL" :
	       s > UpToDate    ? "TO_LARGE"
		               : drbd_disk_s_names[s];
}

const char* set_st_err_name(int err) {
	return err < -7 ? "TO_SMALL" :
	       err > -1 ? "TO_LARGE"
		        : drbd_state_sw_errors[-err];
}
