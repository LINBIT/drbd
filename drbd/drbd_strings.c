static const char *conn_s_names[] = {
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

static const char *role_s_names[] = {
	[Primary]   = "Primary",
	[Secondary] = "Secondary",
	[Unknown]   = "Unknown"
};

static const char *disk_s_names[] = {
	[Diskless]     = "Diskless",
	[Failed]       = "Failed",
	[Inconsistent] = "Inconsistent",
	[Outdated]     = "Outdated",
	[Consistent]   = "Consistent",
	[UpToDate]     = "UpToDate",
};
