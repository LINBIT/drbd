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
#include "drbd_protocol.h"

static const char *__conn_state_names[] = {
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
};

struct state_names drbd_conn_state_names = {
	.names = __conn_state_names,
	.size = sizeof __conn_state_names / sizeof __conn_state_names[0],
};

static const char *__repl_state_names[] = {
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
};

struct state_names drbd_repl_state_names = {
	.names = __repl_state_names,
	.size = sizeof __repl_state_names / sizeof __repl_state_names[0],
};

static const char *__role_state_names[] = {
	[R_UNKNOWN]   = "Unknown",
	[R_PRIMARY]   = "Primary",
	[R_SECONDARY] = "Secondary",
};

struct state_names drbd_role_state_names = {
	.names = __role_state_names,
	.size = sizeof __role_state_names / sizeof __role_state_names[0],
};

static const char *__disk_state_names[] = {
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
};

struct state_names drbd_disk_state_names = {
	.names = __disk_state_names,
	.size = sizeof __disk_state_names / sizeof __disk_state_names[0],
};

static const char *__error_messages[] = {
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
};

struct state_names drbd_error_messages = {
	.names = __error_messages,
	.size = sizeof __error_messages / sizeof __error_messages[0],
};

static const char *__packet_names[] = {
	[P_DATA]	        = "Data",
	[P_DATA_REPLY]	        = "DataReply",
	[P_RS_DATA_REPLY]	= "RSDataReply",
	[P_BARRIER]	        = "Barrier",
	[P_BITMAP]	        = "ReportBitMap",
	[P_BECOME_SYNC_TARGET]  = "BecomeSyncTarget",
	[P_BECOME_SYNC_SOURCE]  = "BecomeSyncSource",
	[P_UNPLUG_REMOTE]	= "UnplugRemote",
	[P_DATA_REQUEST]	= "DataRequest",
	[P_RS_DATA_REQUEST]     = "RSDataRequest",
	[P_SYNC_PARAM]	        = "SyncParam",
	[P_SYNC_PARAM89]	= "SyncParam89",
	[P_PROTOCOL]            = "ReportProtocol",
	[P_UUIDS]	        = "ReportUUIDs",
	[P_SIZES]	        = "ReportSizes",
	[P_STATE]	        = "ReportState",
	[P_SYNC_UUID]           = "ReportSyncUUID",
	[P_AUTH_CHALLENGE]      = "AuthChallenge",
	[P_AUTH_RESPONSE]	= "AuthResponse",
	[P_PING]		= "Ping",
	[P_PING_ACK]	        = "PingAck",
	[P_RECV_ACK]	        = "RecvAck",
	[P_WRITE_ACK]	        = "WriteAck",
	[P_RS_WRITE_ACK]	= "RSWriteAck",
	[P_SUPERSEDED]		= "DiscardWrite",
	[P_NEG_ACK]	        = "NegAck",
	[P_NEG_DREPLY]	        = "NegDReply",
	[P_NEG_RS_DREPLY]	= "NegRSDReply",
	[P_BARRIER_ACK]	        = "BarrierAck",
	[P_STATE_CHG_REQ]       = "StateChgRequest",
	[P_STATE_CHG_REPLY]     = "StateChgReply",
	[P_OV_REQUEST]          = "OVRequest",
	[P_OV_REPLY]            = "OVReply",
	[P_OV_RESULT]           = "OVResult",
	[P_CSUM_RS_REQUEST]     = "CsumRSRequest",
	[P_RS_IS_IN_SYNC]	= "CsumRSIsInSync",
	[P_COMPRESSED_BITMAP]   = "CBitmap",
	[P_DELAY_PROBE]         = "DelayProbe",
	[P_OUT_OF_SYNC]		= "OutOfSync",
	[P_RETRY_WRITE]		= "RetryWrite",
	[P_RS_CANCEL]		= "RSCancel",
	[P_CONN_ST_CHG_REQ]	= "conn_st_chg_req",
	[P_CONN_ST_CHG_REPLY]	= "conn_st_chg_reply",
	[P_RETRY_WRITE]		= "retry_write",
	[P_PROTOCOL_UPDATE]	= "protocol_update",
	[P_TWOPC_PREPARE]	= "twopc_prepare",
	[P_TWOPC_ABORT]		= "twopc_abort",
	[P_DAGTAG]		= "dagtag",
	[P_PEER_ACK]		= "peer_ack",
	[P_PEERS_IN_SYNC]       = "peers_in_sync",
	[P_UUIDS110]            = "uuids_110",
	[P_PEER_DAGTAG]         = "peer_dagtag",
	[P_CURRENT_UUID]        = "current_uuid",
	[P_TWOPC_COMMIT]	= "twopc_commit",
	[P_TWOPC_YES]		= "twopc_yes",
	[P_TWOPC_NO]		= "twopc_no",
	[P_TWOPC_RETRY]		= "twopc_retry",
	/* enum drbd_packet, but not commands - obsoleted flags:
	 *	P_MAY_IGNORE
	 *	P_MAX_OPT_CMD
	 */
};

struct state_names drbd_packet_names = {
        .names = __packet_names,
        .size = sizeof __packet_names / sizeof __packet_names[0],
};

const char *drbd_repl_str(enum drbd_repl_state s)
{
	return (s < 0 || s >= drbd_repl_state_names.size ||
	        !drbd_repl_state_names.names[s]) ?
	       "?" : drbd_repl_state_names.names[s];
}

const char *drbd_conn_str(enum drbd_conn_state s)
{
	return (s < 0 || s >= drbd_conn_state_names.size ||
	        !drbd_conn_state_names.names[s]) ?
	       "?" : drbd_conn_state_names.names[s];
}

const char *drbd_role_str(enum drbd_role s)
{
	return (s < 0 || s >= drbd_role_state_names.size ||
	        !drbd_role_state_names.names[s]) ?
	       "?" : drbd_role_state_names.names[s];
}

const char *drbd_disk_str(enum drbd_disk_state s)
{
	return (s < 0 || s >= drbd_disk_state_names.size ||
	        !drbd_disk_state_names.names[s]) ?
	       "?" : drbd_disk_state_names.names[s];
}

const char *drbd_set_st_err_str(enum drbd_state_rv err)
{
	return (-err < 0 || -err >= drbd_error_messages.size ||
	        !drbd_error_messages.names[-err]) ?
	       "?" : drbd_error_messages.names[-err];
}

const char *drbd_packet_name(enum drbd_packet cmd)
{
	/* too big for the array: 0xfffX */
	if (cmd == P_INITIAL_META)
		return "InitialMeta";
	if (cmd == P_INITIAL_DATA)
		return "InitialData";
	if (cmd == P_CONNECTION_FEATURES)
		return "ConnectionFeatures";
	return (cmd < 0 || cmd >= ARRAY_SIZE(__packet_names) ||
		!__packet_names[cmd]) ?
	       "?" : __packet_names[cmd];
}
