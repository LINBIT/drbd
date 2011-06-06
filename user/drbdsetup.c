/*
   drbdsetup.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#define _GNU_SOURCE

#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define __bitwise /* Build-workaround for broken RHEL4 kernels (2.6.9_78.0.1) */
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/connector.h>

#include <linux/drbd.h>
#include <linux/drbd_tag_magic.h>
#include <linux/drbd_limits.h>

#include "unaligned.h"
#include "drbdtool_common.h"

#ifndef __CONNECTOR_H
#error "You need to set KDIR while building drbdsetup."
#endif

#ifndef AF_INET_SDP
#define AF_INET_SDP 27
#define PF_INET_SDP AF_INET_SDP
#endif

enum usage_type {
	BRIEF,
	FULL,
	XML,
};

struct drbd_tag_list {
	struct nlmsghdr *nl_header;
	struct cn_msg   *cn_header;
	struct drbd_nl_cfg_req* drbd_p_header;
	unsigned short *tag_list_start;
	unsigned short *tag_list_cpos;
	int    tag_size;
};

struct drbd_argument {
	const char* name;
	const enum drbd_tags tag;
	int (*convert_function)(struct drbd_argument *,
				struct drbd_tag_list *,
				char *);
};

struct drbd_option {
	const char* name;
	const char short_name;
	const enum drbd_tags tag;
	int (*convert_function)(struct drbd_option *,
				struct drbd_tag_list *,
				char *);
	void (*show_function)(struct drbd_option *,unsigned short*);
	int (*usage_function)(struct drbd_option *, char*, int);
	void (*xml_function)(struct drbd_option *);
	union {
		struct {
			const long long min;
			const long long max;
			const long long def;
			const unsigned char unit_prefix;
			const char* unit;
		} numeric_param; // for conv_numeric
		struct {
			const char** handler_names;
			const int number_of_handlers;
			const int def;
		} handler_param; // conv_handler
	};
};

struct drbd_cmd {
	const char* cmd;
	const int packet_id;
	int (*function)(struct drbd_cmd *, unsigned, int, char **);
	void (*usage)(struct drbd_cmd *, enum usage_type);
	union {
		struct {
			struct drbd_argument *args;
			struct drbd_option *options;
		} cp; // for generic_config_cmd, config_usage
		struct {
			int (*show_function)(struct drbd_cmd *, unsigned,
					     unsigned short* );
		} gp; // for generic_get_cmd, get_usage
		struct {
			struct option *options;
			int (*proc_event)(unsigned int, int,
					  struct drbd_nl_cfg_reply *);
		} ep; // for events_cmd, events_usage
	};
};


// Connector functions
#define NL_TIME (COMM_TIMEOUT*1000)
static int open_cn();
static int send_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size);
static int receive_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size, int timeout_ms);
static int call_drbd(int sk_nl, struct drbd_tag_list *tl, struct nlmsghdr* nl_hdr,
		     int size, int timeout_ms);
static void close_cn(int sk_nl);

// other functions
static int get_af_ssocks(int warn);
static void print_command_usage(int i, const char *addinfo, enum usage_type);

// command functions
static int generic_config_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int down_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int generic_get_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int events_cmd(struct drbd_cmd *cm, unsigned minor, int argc,char **argv);

// usage functions
static void config_usage(struct drbd_cmd *cm, enum usage_type);
static void get_usage(struct drbd_cmd *cm, enum usage_type);
static void events_usage(struct drbd_cmd *cm, enum usage_type);

// sub usage functions for config_usage
static int numeric_opt_usage(struct drbd_option *option, char* str, int strlen);
static int handler_opt_usage(struct drbd_option *option, char* str, int strlen);
static int bit_opt_usage(struct drbd_option *option, char* str, int strlen);
static int string_opt_usage(struct drbd_option *option, char* str, int strlen);

// sub usage function for config_usage as xml
static void numeric_opt_xml(struct drbd_option *option);
static void handler_opt_xml(struct drbd_option *option);
static void bit_opt_xml(struct drbd_option *option);
static void string_opt_xml(struct drbd_option *option);

// sub commands for generic_get_cmd
static int show_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int role_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int status_xml_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int sh_status_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int cstate_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int dstate_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int uuids_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);
static int lk_bdev_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl);

// convert functions for arguments
static int conv_block_dev(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
static int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
static int conv_address(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
static int conv_protocol(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);

// convert functions for options
static int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
static int conv_sndbuf(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
static int conv_handler(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
static int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
static int conv_string(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);

// show functions for options (used by show_scmd)
static void show_numeric(struct drbd_option *od, unsigned short* tp);
static void show_handler(struct drbd_option *od, unsigned short* tp);
static void show_bit(struct drbd_option *od, unsigned short* tp);
static void show_string(struct drbd_option *od, unsigned short* tp);

// sub functions for events_cmd
static int print_broadcast_events(unsigned int seq, int, struct drbd_nl_cfg_reply *reply);
static int w_connected_state(unsigned int seq, int, struct drbd_nl_cfg_reply *reply);
static int w_synced_state(unsigned int seq, int, struct drbd_nl_cfg_reply *reply);

const char *on_error[] = {
	[EP_PASS_ON]         = "pass_on",
	[EP_CALL_HELPER]  = "call-local-io-error",
	[EP_DETACH]         = "detach",
};

const char *fencing_n[] = {
	[FP_DONT_CARE] = "dont-care",
	[FP_RESOURCE] = "resource-only",
	[FP_STONITH]  = "resource-and-stonith",
};

const char *asb0p_n[] = {
        [ASB_DISCONNECT]        = "disconnect",
	[ASB_DISCARD_YOUNGER_PRI] = "discard-younger-primary",
	[ASB_DISCARD_OLDER_PRI]   = "discard-older-primary",
	[ASB_DISCARD_ZERO_CHG]    = "discard-zero-changes",
	[ASB_DISCARD_LEAST_CHG]   = "discard-least-changes",
	[ASB_DISCARD_LOCAL]      = "discard-local",
	[ASB_DISCARD_REMOTE]     = "discard-remote"
};

const char *asb1p_n[] = {
	[ASB_DISCONNECT]        = "disconnect",
	[ASB_CONSENSUS]         = "consensus",
	[ASB_VIOLENTLY]         = "violently-as0p",
	[ASB_DISCARD_SECONDARY]  = "discard-secondary",
	[ASB_CALL_HELPER]        = "call-pri-lost-after-sb"
};

const char *asb2p_n[] = {
	[ASB_DISCONNECT]        = "disconnect",
	[ASB_VIOLENTLY]         = "violently-as0p",
	[ASB_CALL_HELPER]        = "call-pri-lost-after-sb"
};

const char *rrcf_n[] = {
	[ASB_DISCONNECT]        = "disconnect",
	[ASB_VIOLENTLY]         = "violently",
	[ASB_CALL_HELPER]        = "call-pri-lost"
};

const char *on_no_data_n[] = {
	[OND_IO_ERROR]		= "io-error",
	[OND_SUSPEND_IO]	= "suspend-io"
};

const char *on_congestion_n[] = {
	[OC_BLOCK]              = "block",
	[OC_PULL_AHEAD]         = "pull-ahead",
	[OC_DISCONNECT]         = "disconnect"
};

struct option wait_cmds_options[] = {
	{ "wfc-timeout",required_argument, 0, 't' },
	{ "degr-wfc-timeout",required_argument,0,'d'},
	{ "outdated-wfc-timeout",required_argument,0,'o'},
	{ "wait-after-sb",no_argument,0,'w'},
	{ 0,            0,           0,  0  }
};

#define EN(N,U,UN) \
	conv_numeric, show_numeric, numeric_opt_usage, numeric_opt_xml, \
	{ .numeric_param = { DRBD_ ## N ## _MIN, DRBD_ ## N ## _MAX, \
		DRBD_ ## N ## _DEF ,U,UN  } }
#define EN_sndbuf(N,U,UN) \
	conv_sndbuf, show_numeric, numeric_opt_usage, numeric_opt_xml, \
	{ .numeric_param = { DRBD_ ## N ## _MIN, DRBD_ ## N ## _MAX, \
		DRBD_ ## N ## _DEF ,U,UN  } }
#define EH(N,D) \
	conv_handler, show_handler, handler_opt_usage, handler_opt_xml, \
	{ .handler_param = { N, ARRY_SIZE(N), \
	DRBD_ ## D ## _DEF } }
#define EB      conv_bit, show_bit, bit_opt_usage, bit_opt_xml, { }
#define ES      conv_string, show_string, string_opt_usage, string_opt_xml, { }
#define CLOSE_OPTIONS  { NULL,0,0,NULL,NULL,NULL, NULL, { } }

#define F_CONFIG_CMD	generic_config_cmd, config_usage
#define F_GET_CMD	generic_get_cmd, get_usage
#define F_EVENTS_CMD	events_cmd, events_usage

struct drbd_cmd commands[] = {
	{"primary", P_primary, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "overwrite-data-of-peer",'o',T_primary_force, EB   }, /* legacy name */
		 { "force",'f',			T_primary_force, EB   },
		 CLOSE_OPTIONS }} }, },

	{"secondary", P_secondary, F_CONFIG_CMD, {{NULL, NULL}} },

	{"disk", P_disk_conf, F_CONFIG_CMD, {{
	 (struct drbd_argument[]) {
		 { "lower_dev",		T_backing_dev,	conv_block_dev },
		 { "meta_data_dev",	T_meta_dev,	conv_block_dev },
		 { "meta_data_index",	T_meta_dev_idx,	conv_md_idx },
		 { NULL,                0,           	NULL}, },
	 (struct drbd_option[]) {
		 { "size",'d',		T_disk_size,	EN(DISK_SIZE_SECT,'s',"bytes") },
		 { "on-io-error",'e',	T_on_io_error,	EH(on_error,ON_IO_ERROR) },
		 { "fencing",'f',	T_fencing,      EH(fencing_n,FENCING) },
		 { "use-bmbv",'b',	T_use_bmbv,     EB },
		 { "no-disk-barrier",'a',T_no_disk_barrier,EB },
		 { "no-disk-flushes",'i',T_no_disk_flush,EB },
		 { "no-disk-drain",'D', T_no_disk_drain,EB },
		 { "no-md-flushes",'m', T_no_md_flush,  EB },
		 { "max-bio-bvecs",'s',	T_max_bio_bvecs,EN(MAX_BIO_BVECS,1,NULL) },
		 CLOSE_OPTIONS }} }, },

	{"detach", P_detach, F_CONFIG_CMD, {{NULL, NULL}} },

	{"net", P_net_conf, F_CONFIG_CMD, {{
	 (struct drbd_argument[]) {
		 { "[af:]local_addr[:port]",T_my_addr,	conv_address },
		 { "[af:]remote_addr[:port]",T_peer_addr,conv_address },
		 { "protocol",		T_wire_protocol,conv_protocol },
		 { NULL,                0,           	NULL}, },
	 (struct drbd_option[]) {
		 { "timeout",'t',	T_timeout,	EN(TIMEOUT,1,"1/10 seconds") },
		 { "max-epoch-size",'e',T_max_epoch_size,EN(MAX_EPOCH_SIZE,1,NULL) },
		 { "max-buffers",'b',	T_max_buffers,	EN(MAX_BUFFERS,1,NULL) },
		 { "unplug-watermark",'u',T_unplug_watermark, EN(UNPLUG_WATERMARK,1,NULL) },
		 { "connect-int",'c',	T_try_connect_int, EN(CONNECT_INT,1,"seconds") },
		 { "ping-int",'i',	T_ping_int,	   EN(PING_INT,1,"seconds") },
		 { "sndbuf-size",'S',	T_sndbuf_size,	   EN_sndbuf(SNDBUF_SIZE,1,"bytes") },
		 { "rcvbuf-size",'r',	T_rcvbuf_size,	   EN_sndbuf(RCVBUF_SIZE,1,"bytes") },
		 { "ko-count",'k',	T_ko_count,	   EN(KO_COUNT,1,NULL) },
		 { "allow-two-primaries",'m',T_two_primaries, EB },
		 { "cram-hmac-alg",'a',	T_cram_hmac_alg,   ES },
		 { "shared-secret",'x',	T_shared_secret,   ES },
		 { "after-sb-0pri",'A',	T_after_sb_0p,EH(asb0p_n,AFTER_SB_0P) },
		 { "after-sb-1pri",'B',	T_after_sb_1p,EH(asb1p_n,AFTER_SB_1P) },
		 { "after-sb-2pri",'C',	T_after_sb_2p,EH(asb2p_n,AFTER_SB_2P) },
		 { "always-asbp",'P',   T_always_asbp,     EB },
		 { "rr-conflict",'R',	T_rr_conflict,EH(rrcf_n,RR_CONFLICT) },
		 { "ping-timeout",'p',  T_ping_timeo,	   EN(PING_TIMEO,1,"1/10 seconds") },
		 { "discard-my-data",'D', T_want_lose,     EB },
		 { "data-integrity-alg",'d', T_integrity_alg,     ES },
		 { "no-tcp-cork",'o',   T_no_cork,         EB },
		 { "dry-run",'n',   T_dry_run,		   EB },
		 { "on-congestion", 'g', T_on_congestion, EH(on_congestion_n,ON_CONGESTION) },
		 { "congestion-fill", 'f', T_cong_fill,    EN(CONG_FILL,'s',"byte") },
		 { "congestion-extents", 'h', T_cong_extents, EN(CONG_EXTENTS,1,NULL) },
		 CLOSE_OPTIONS }} }, },

	{"disconnect", P_disconnect, F_CONFIG_CMD, {{NULL,
	 (struct drbd_option[]) {
		 { "force", 'F',	T_force,	EB },
		CLOSE_OPTIONS }} }, },

	{"resize", P_resize, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "size",'s',T_resize_size,		EN(DISK_SIZE_SECT,'s',"bytes") },
		 { "assume-peer-has-space",'f',T_resize_force,	EB },
		 { "assume-clean", 'c',        T_no_resync, EB },
		 CLOSE_OPTIONS }} }, },

	{"syncer", P_syncer_conf, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "rate",'r',T_rate,			EN(RATE,'k',"bytes/second") },
		 { "after",'a',T_after,			EN(AFTER,1,NULL) },
		 { "al-extents",'e',T_al_extents,	EN(AL_EXTENTS,1,NULL) },
		 { "csums-alg", 'C',T_csums_alg,        ES },
		 { "verify-alg", 'v',T_verify_alg,      ES },
		 { "cpu-mask",'c',T_cpu_mask,           ES },
		 { "use-rle",'R',T_use_rle,   EB },
		 { "on-no-data-accessible",'n',	T_on_no_data, EH(on_no_data_n,ON_NO_DATA) },
		 { "c-plan-ahead", 'p',         T_c_plan_ahead, EN(C_PLAN_AHEAD,1,"1/10 seconds") },
		 { "c-delay-target", 'd',       T_c_delay_target, EN(C_DELAY_TARGET,1,"1/10 seconds") },
		 { "c-fill-target", 's',        T_c_fill_target, EN(C_FILL_TARGET,'s',"bytes") },
		 { "c-max-rate", 'M',		T_c_max_rate, EN(C_MAX_RATE,'k',"bytes/second") },
		 { "c-min-rate", 'm',	        T_c_min_rate, EN(C_MIN_RATE,'k',"bytes/second") },
		 CLOSE_OPTIONS }} }, },

	{"new-current-uuid", P_new_c_uuid, F_CONFIG_CMD, {{NULL,
	 (struct drbd_option[]) {
		 { "clear-bitmap",'c',T_clear_bm, EB   },
		 CLOSE_OPTIONS }} }, },

	{"invalidate", P_invalidate, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"invalidate-remote", P_invalidate_peer, F_CONFIG_CMD, {{NULL, NULL}} },
	{"pause-sync", P_pause_sync, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"resume-sync", P_resume_sync, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"suspend-io", P_suspend_io, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"resume-io", P_resume_io, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"outdate", P_outdate, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"verify", P_start_ov, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "start",'s',T_start_sector, EN(DISK_SIZE_SECT,'s',"bytes") },
		 CLOSE_OPTIONS }} }, },
	{"down",            0, down_cmd, get_usage, { {NULL, NULL }} },
	/* "state" is deprecated! please use "role".
	 * find_cmd_by_name still understands "state", however. */
	{"role", P_get_state, F_GET_CMD, { .gp={ role_scmd} } },
	{"status", P_get_state, F_GET_CMD, {.gp={ status_xml_scmd } } },
	{"sh-status", P_get_state, F_GET_CMD, {.gp={ sh_status_scmd } } },
	{"cstate", P_get_state, F_GET_CMD, {.gp={ cstate_scmd} } },
	{"dstate", P_get_state, F_GET_CMD, {.gp={ dstate_scmd} } },
	{"show-gi", P_get_uuids, F_GET_CMD, {.gp={ uuids_scmd} }},
	{"get-gi", P_get_uuids, F_GET_CMD, {.gp={ uuids_scmd} } },
	{"show", P_get_config, F_GET_CMD, {.gp={ show_scmd} } },
	{"check-resize", P_get_config, F_GET_CMD, {.gp={ lk_bdev_scmd} } },
	{"events",          0, F_EVENTS_CMD, { .ep = {
		(struct option[]) {
			{ "unfiltered", no_argument, 0, 'u' },
			{ "all-devices",no_argument, 0, 'a' },
			{ 0,            0,           0,  0  } },
		print_broadcast_events } } },
	{"wait-connect", 0, F_EVENTS_CMD, { .ep = {
		wait_cmds_options, w_connected_state } } },
	{"wait-sync", 0, F_EVENTS_CMD, { .ep = {
		wait_cmds_options, w_synced_state } } },
};

#define OTHER_ERROR 900

#define EM(C) [ C - ERR_CODE_BASE ]

/* The EM(123) are used for old error messages. */
static const char *error_messages[] = {
	EM(NO_ERROR) = "No further Information available.",
	EM(ERR_LOCAL_ADDR) = "Local address(port) already in use.",
	EM(ERR_PEER_ADDR) = "Remote address(port) already in use.",
	EM(ERR_OPEN_DISK) = "Can not open backing device.",
	EM(ERR_OPEN_MD_DISK) = "Can not open meta device.",
	EM(106) = "Lower device already in use.",
	EM(ERR_DISK_NOT_BDEV) = "Lower device is not a block device.",
	EM(ERR_MD_NOT_BDEV) = "Meta device is not a block device.",
	EM(109) = "Open of lower device failed.",
	EM(110) = "Open of meta device failed.",
	EM(ERR_DISK_TOO_SMALL) = "Low.dev. smaller than requested DRBD-dev. size.",
	EM(ERR_MD_DISK_TOO_SMALL) = "Meta device too small.",
	EM(113) = "You have to use the disk command first.",
	EM(ERR_BDCLAIM_DISK) = "Lower device is already claimed. This usually means it is mounted.",
	EM(ERR_BDCLAIM_MD_DISK) = "Meta device is already claimed. This usually means it is mounted.",
	EM(ERR_MD_IDX_INVALID) = "Lower device / meta device / index combination invalid.",
	EM(117) = "Currently we only support devices up to 3.998TB.\n"
	"(up to 2TB in case you do not have CONFIG_LBD set)\n"
	"Contact office@linbit.com, if you need more.",
	EM(ERR_IO_MD_DISK) = "IO error(s) occurred during initial access to meta-data.\n",
	EM(ERR_MD_INVALID) = "No valid meta-data signature found.\n\n"
	"\t==> Use 'drbdadm create-md res' to initialize meta-data area. <==\n",
	EM(ERR_AUTH_ALG) = "The 'cram-hmac-alg' you specified is not known in "
	"the kernel. (Maybe you need to modprobe it, or modprobe hmac?)",
	EM(ERR_AUTH_ALG_ND) = "The 'cram-hmac-alg' you specified is not a digest.",
	EM(ERR_NOMEM) = "kmalloc() failed. Out of memory?",
	EM(ERR_DISCARD) = "--discard-my-data not gllowed when primary.",
	EM(ERR_DISK_CONFIGURED) = "Device is attached to a disk (use detach first)",
	EM(ERR_NET_CONFIGURED) = "Device has a net-config (use disconnect first)",
	EM(ERR_MANDATORY_TAG) = "UnknownMandatoryTag",
	EM(ERR_MINOR_INVALID) = "Device minor not allocated",
	EM(128) = "Resulting device state would be invalid",
	EM(ERR_INTR) = "Interrupted by Signal",
	EM(ERR_RESIZE_RESYNC) = "Resize not allowed during resync.",
	EM(ERR_NO_PRIMARY) = "Need one Primary node to resize.",
	EM(ERR_SYNC_AFTER) = "The sync-after minor number is invalid",
	EM(ERR_SYNC_AFTER_CYCLE) = "This would cause a sync-after dependency cycle",
	EM(ERR_PAUSE_IS_SET) = "Sync-pause flag is already set",
	EM(ERR_PAUSE_IS_CLEAR) = "Sync-pause flag is already cleared",
	EM(136) = "Disk state is lower than outdated",
	EM(ERR_PACKET_NR) = "Kernel does not know how to handle your request.\n"
	"Maybe API_VERSION mismatch?",
	EM(ERR_NO_DISK) = "Device does not have a disk-config",
	EM(ERR_NOT_PROTO_C) = "Protocol C required",
	EM(ERR_NOMEM_BITMAP) = "vmalloc() failed. Out of memory?",
	EM(ERR_INTEGRITY_ALG) = "The 'data-integrity-alg' you specified is not known in "
	"the kernel. (Maybe you need to modprobe it, or modprobe hmac?)",
	EM(ERR_INTEGRITY_ALG_ND) = "The 'data-integrity-alg' you specified is not a digest.",
	EM(ERR_CPU_MASK_PARSE) = "Invalid cpu-mask.",
	EM(ERR_VERIFY_ALG) = "VERIFYAlgNotAvail",
	EM(ERR_VERIFY_ALG_ND) = "VERIFYAlgNotDigest",
	EM(ERR_VERIFY_RUNNING) = "Can not change verify-alg while online verify runs",
	EM(ERR_DATA_NOT_CURRENT) = "Can only attach to the data we lost last (see kernel log).",
	EM(ERR_CONNECTED) = "Need to be StandAlone",
	EM(ERR_CSUMS_ALG) = "CSUMSAlgNotAvail",
	EM(ERR_CSUMS_ALG_ND) = "CSUMSAlgNotDigest",
	EM(ERR_CSUMS_RESYNC_RUNNING) = "Can not change csums-alg while resync is in progress",
	EM(ERR_PERM) = "Permission denied. CAP_SYS_ADMIN necessary",
	EM(ERR_NEED_APV_93) = "Protocol version 93 required to use --assume-clean",
	EM(ERR_STONITH_AND_PROT_A) = "Fencing policy resource-and-stonith only with prot B or C allowed",
	EM(ERR_CONG_NOT_PROTO_A) = "on-congestion policy pull-ahead only with prot A allowed",
	EM(ERR_PIC_AFTER_DEP) = "Sync-pause flag is already cleared.\n"
	"Note: Resync pause caused by a local sync-after dependency.",
	EM(ERR_PIC_PEER_DEP) = "Sync-pause flag is already cleared.\n"
	"Note: Resync pause caused by the peer node.",
};
#define MAX_ERROR (sizeof(error_messages)/sizeof(*error_messages))
const char * error_to_string(int err_no)
{
	const unsigned int idx = err_no - ERR_CODE_BASE;
	if (idx >= MAX_ERROR) return "Unknown... maybe API_VERSION mismatch?";
	return error_messages[idx];
}
#undef MAX_ERROR

char *cmdname = NULL; /* "drbdsetup" for reporting in usage etc. */
char *devname = NULL; /* "/dev/drbd12" for reporting in print_config_error */
char *resname = NULL; /* for pretty printing in "status" only,
			 taken from environment variable DRBD_RESOURCE */
int debug_dump_argv = 0; /* enabled by setting DRBD_DEBUG_DUMP_ARGV in the environment */
int lock_fd;
unsigned int cn_idx;

static int dump_tag_list(unsigned short *tlc)
{
	enum drbd_tags tag;
	unsigned int tag_nr;
	int len;
	int integer;
	char bit;
	uint64_t int64;
	const char* string;
	int found_unknown=0;

	while( (tag = *tlc++ ) != TT_END) {
		len = *tlc++;
		if(tag == TT_REMOVED) goto skip;

		tag_nr = tag_number(tag);
		if(tag_nr<ARRY_SIZE(tag_descriptions)) {
			string = tag_descriptions[tag_nr].name;
		} else {
			string = "unknown tag";
			found_unknown=1;
		}
		printf("# (%2d) %16s = ",tag_nr,string);
		switch(tag_type(tag)) {
		case TT_INTEGER:
			integer = *(int*)tlc;
			printf("(integer) %d",integer);
			break;
		case TT_INT64:
			int64 = *(uint64_t*)tlc;
			printf("(int64) %lld",(long long)int64);
			break;
		case TT_BIT:
			bit = *(char*)tlc;
			printf("(bit) %s", bit ? "on" : "off");
			break;
		case TT_STRING:
			string = (char*)tlc;
			printf("(string)'%s'", len ? string : "");
			break;
		}
		printf(" \t[len: %u]\n",len);
	skip:
		tlc = (unsigned short*)((char*)tlc + len);
	}

	return found_unknown;
}

static struct drbd_tag_list *create_tag_list(int size)
{
	struct drbd_tag_list *tl;

	tl = malloc(sizeof(struct drbd_tag_list));
	tl->nl_header  = malloc(NLMSG_SPACE( sizeof(struct cn_msg) +
					     sizeof(struct drbd_nl_cfg_req) +
					     size) );
	tl->cn_header = NLMSG_DATA(tl->nl_header);
	tl->drbd_p_header = (struct drbd_nl_cfg_req*) tl->cn_header->data;
	tl->tag_list_start = tl->drbd_p_header->tag_list;
	tl->tag_list_cpos = tl->tag_list_start;
	tl->tag_size = size;

	return tl;
}

static void add_tag(struct drbd_tag_list *tl, short int tag, void *data, short int data_len)
{
	if(data_len > tag_descriptions[tag_number(tag)].max_len) {
		fprintf(stderr, "The value for %s may only be %d byte long."
			" You requested %d.\n",
			tag_descriptions[tag_number(tag)].name,
			tag_descriptions[tag_number(tag)].max_len,
			data_len);
		exit(20);
	}

	if( (tl->tag_list_cpos - tl->tag_list_start) + data_len
	    > tl->tag_size ) {
		fprintf(stderr, "Tag list size exceeded!\n");
		exit(20);
	}
	put_unaligned(tag, tl->tag_list_cpos++);
	put_unaligned(data_len, tl->tag_list_cpos++);
	memcpy(tl->tag_list_cpos, data, data_len);
	tl->tag_list_cpos = (unsigned short*)((char*)tl->tag_list_cpos + data_len);
}

static void free_tag_list(struct drbd_tag_list *tl)
{
	free(tl->nl_header);
	free(tl);
}

static int conv_block_dev(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	struct stat sb;
	int device_fd;
	int err;

	if ((device_fd = open(arg,O_RDWR))==-1) {
		PERROR("Can not open device '%s'", arg);
		return OTHER_ERROR;
	}

	if ( (err=fstat(device_fd, &sb)) ) {
		PERROR("fstat(%s) failed", arg);
		return OTHER_ERROR;
	}

	if(!S_ISBLK(sb.st_mode)) {
		fprintf(stderr, "%s is not a block device!\n", arg);
		return OTHER_ERROR;
	}

	close(device_fd);

	add_tag(tl,ad->tag,arg,strlen(arg)+1); // include the null byte.

	return NO_ERROR;
}

static int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = DRBD_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flexible")) idx = DRBD_MD_INDEX_FLEX_EXT;
	else idx = m_strtoll(arg,1);

	add_tag(tl,ad->tag,&idx,sizeof(idx));

	return NO_ERROR;
}

static void resolv6(char *name, struct sockaddr_in6 *addr)
{
	struct addrinfo hints, *res, *tmp;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	err = getaddrinfo(name, 0, &hints, &res);
	if (err) {
		fprintf(stderr, "getaddrinfo %s: %s\n", name, gai_strerror(err));
		exit(20);
	}

	/* Yes, it is a list. We use only the first result. The loop is only
	 * there to document that we know it is a list */
	for (tmp = res; tmp; tmp = tmp->ai_next) {
		memcpy(addr, tmp->ai_addr, sizeof(*addr));
		break;
	}
	freeaddrinfo(res);
	if (0) { /* debug output */
		char ip[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
		fprintf(stderr, "%s -> %02x %04x %08x %s %08x\n",
				name,
				addr->sin6_family,
				addr->sin6_port,
				addr->sin6_flowinfo,
				ip,
				addr->sin6_scope_id);
	}
}

static unsigned long resolv(const char* name)
{
	unsigned long retval;

	if((retval = inet_addr(name)) == INADDR_NONE ) {
		struct hostent *he;
		he = gethostbyname(name);
		if (!he) {
			fprintf(stderr, "can not resolve the hostname: gethostbyname(%s): %s\n",
					name, hstrerror(h_errno));
			exit(20);
		}
		retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
	}
	return retval;
}

static void split_ipv6_addr(char **address, int *port)
{
	/* ipv6:[fe80::0234:5678:9abc:def1]:8000; */
	char *b = strrchr(*address,']');
	if (address[0][0] != '[' || b == NULL ||
		(b[1] != ':' && b[1] != '\0')) {
		fprintf(stderr, "unexpected ipv6 format: %s\n",
				*address);
		exit(20);
	}

	*b = 0;
	*address += 1; /* skip '[' */
	if (b[1] == ':')
		*port = m_strtoll(b+2,1); /* b+2: "]:" */
	else
		*port = 7788; /* will we ever get rid of that default port? */
}

static void split_address(char* text, int *af, char** address, int* port)
{
	static struct { char* text; int af; } afs[] = {
		{ "ipv4:", AF_INET  },
		{ "ipv6:", AF_INET6 },
		{ "sdp:",  AF_INET_SDP },
		{ "ssocks:",  -1 },
	};

	unsigned int i;
	char *b;

	*af=AF_INET;
	*address = text;
	for (i=0; i<ARRY_SIZE(afs); i++) {
		if (!strncmp(text, afs[i].text, strlen(afs[i].text))) {
			*af = afs[i].af;
			*address = text + strlen(afs[i].text);
			break;
		}
	}

	if (*af == AF_INET6 && address[0][0] == '[')
		return split_ipv6_addr(address, port);

	if (*af == -1)
		*af = get_af_ssocks(1);

	b=strrchr(text,':');
	if (b) {
		*b = 0;
		if (*af == AF_INET6) {
			/* compatibility handling of ipv6 addresses,
			 * in the style expected before drbd 8.3.9.
			 * may go wrong without explicit port */
			fprintf(stderr, "interpreting ipv6:%s:%s as ipv6:[%s]:%s\n",
					*address, b+1, *address, b+1);
		}
		*port = m_strtoll(b+1,1);
	} else
		*port = 7788;

}

static int conv_address(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	static int mind_af_set = 0;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	int af, port;
	char *address, bit=0;

	split_address(arg, &af, &address, &port);

	/* The mind_af tag is mandatory. I.e. the module may not silently ignore it.
	   That means that an older DRBD module must fail the operation since it does
	   not know the mind_af tag. We set it in case we use an other AF then AF_INET,
	   so that the alternate AF is not silently ignored by the DRBD module */
	if (af != AF_INET && !mind_af_set) {
		add_tag(tl,T_mind_af,&bit,sizeof(bit));
		mind_af_set=1;
	}

	if (af == AF_INET6) {
		memset(&addr6, 0, sizeof(struct sockaddr_in6));
		resolv6(address, &addr6);
		addr6.sin6_port = htons(port);
		add_tag(tl,ad->tag,&addr6,sizeof(addr6));
	} else {
		/* AF_INET, AF_SDP, AF_SSOCKS,
		 * all use the IPv4 addressing scheme */
		addr.sin_port = htons(port);
		addr.sin_family = af;
		addr.sin_addr.s_addr = resolv(address);
		add_tag(tl,ad->tag,&addr,sizeof(addr));
	}

	return NO_ERROR;
}

static int conv_protocol(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	int prot;

	if(!strcmp(arg,"A") || !strcmp(arg,"a")) {
		prot=DRBD_PROT_A;
	} else if (!strcmp(arg,"B") || !strcmp(arg,"b")) {
		prot=DRBD_PROT_B;
	} else if (!strcmp(arg,"C") || !strcmp(arg,"c")) {
		prot=DRBD_PROT_C;
	} else {
		fprintf(stderr, "'%s' is no valid protocol.\n", arg);
		return OTHER_ERROR;
	}

	add_tag(tl,ad->tag,&prot,sizeof(prot));

	return NO_ERROR;
}

static int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg __attribute((unused)))
{
	char bit=1;

	add_tag(tl,od->tag,&bit,sizeof(bit));

	return NO_ERROR;
}

/* It will only print the WARNING if the warn flag is set
   with the _first_ call! */
#define PROC_NET_AF_SCI_FAMILY "/proc/net/af_sci/family"
#define PROC_NET_AF_SSOCKS_FAMILY "/proc/net/af_ssocks/family"

static int get_af_ssocks(int warn_and_use_default)
{
	char buf[16];
	int c, fd;
	static int af = -1;

	if (af > 0)
		return af;

	fd = open(PROC_NET_AF_SSOCKS_FAMILY, O_RDONLY);

	if (fd < 0)
		fd = open(PROC_NET_AF_SCI_FAMILY, O_RDONLY);

	if (fd < 0) {
		if (warn_and_use_default) {
			fprintf(stderr, "open(" PROC_NET_AF_SSOCKS_FAMILY ") "
				"failed: %m\n WARNING: assuming AF_SSOCKS = 27. "
				"Socket creation may fail.\n");
			af = 27;
		}
		return af;
	}
	c = read(fd, buf, sizeof(buf)-1);
	if (c > 0) {
		buf[c] = 0;
		if (buf[c-1] == '\n')
			buf[c-1] = 0;
		af = m_strtoll(buf,1);
	} else {
		if (warn_and_use_default) {
			fprintf(stderr, "read(" PROC_NET_AF_SSOCKS_FAMILY ") "
				"failed: %m\n WARNING: assuming AF_SSOCKS = 27. "
				"Socket creation may fail.\n");
			af = 27;
		}
	}
	close(fd);
	return af;
}

static int conv_sndbuf(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	int err = conv_numeric(od, tl, arg);
	long long l = m_strtoll(arg, 0);
	char bit = 0;

	if (err != NO_ERROR || l != 0)
		return err;
	/* this is a mandatory bit,
	 * to avoid newer userland to configure older modules with
	 * a sndbuf size of zero, which would lead to Oops. */
	add_tag(tl, T_auto_sndbuf_size, &bit, sizeof(bit));
	return NO_ERROR;
}

static int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	const long long min = od->numeric_param.min;
	const long long max = od->numeric_param.max;
	const unsigned char unit_prefix = od->numeric_param.unit_prefix;
	long long l;
	int i;
	char unit[] = {0,0};

	l = m_strtoll(arg, unit_prefix);

	if (min > l || l > max) {
		unit[0] = unit_prefix > 1 ? unit_prefix : 0;
		fprintf(stderr,"%s %s => %llu%s out of range [%llu..%llu]%s\n",
			od->name, arg, l, unit, min, max, unit);
		return OTHER_ERROR;
	}

	switch(tag_type(od->tag)) {
	case TT_INT64:
		add_tag(tl,od->tag,&l,sizeof(l));
		break;
	case TT_INTEGER:
		i=l;
		add_tag(tl,od->tag,&i,sizeof(i));
		break;
	default:
		fprintf(stderr, "internal error in conv_numeric()\n");
	}
	return NO_ERROR;
}

static int conv_handler(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	const char** handler_names = od->handler_param.handler_names;
	const int number_of_handlers = od->handler_param.number_of_handlers;
	int i;

	for(i=0;i<number_of_handlers;i++) {
		if(handler_names[i]==NULL) continue;
		if(strcmp(arg,handler_names[i])==0) {
			add_tag(tl,od->tag,&i,sizeof(i));
			return NO_ERROR;
		}
	}

	fprintf(stderr, "%s-handler '%s' not known\n", od->name, arg);
	fprintf(stderr, "known %s-handlers:\n", od->name);
	for (i = 0; i < number_of_handlers; i++) {
		if (handler_names[i])
			printf("\t%s\n", handler_names[i]);
	}
	return OTHER_ERROR;
}

static int conv_string(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	add_tag(tl,od->tag,arg,strlen(arg)+1);

	return NO_ERROR;
}


static struct option *	make_longoptions(struct drbd_option* od)
{
	/* room for up to N options,
	 * plus set-defaults, create-device, and the terminating NULL */
#define N 30
	static struct option buffer[N+3];
	int i=0;

	while(od && od->name) {
		buffer[i].name = od->name;
		buffer[i].has_arg = tag_type(od->tag) == TT_BIT ?
			no_argument : required_argument ;
		buffer[i].flag = NULL;
		buffer[i].val = od->short_name;
		if (i++ == N) {
			/* we must not leave this loop with i > N */
			fprintf(stderr,"buffer in make_longoptions to small.\n");
			abort();
		}
		od++;
	}
#undef N

	// The two omnipresent options:
	buffer[i].name = "set-defaults";
	buffer[i].has_arg = 0;
	buffer[i].flag = NULL;
	buffer[i].val = '(';
	i++;

	buffer[i].name = "create-device";
	buffer[i].has_arg = 0;
	buffer[i].flag = NULL;
	buffer[i].val = ')';
	i++;

	buffer[i].name = NULL;
	buffer[i].has_arg = 0;
	buffer[i].flag = NULL;
	buffer[i].val = 0;

	return buffer;
}

static struct drbd_option *find_opt_by_short_name(struct drbd_option *od, int c)
{
	if(!od) return NULL;
	while(od->name) {
		if(od->short_name == c) return od;
		od++;
	}

	return NULL;
}

/* prepends global devname to output (if any) */
static int print_config_error(int err_no)
{
	int rv=0;

	if (err_no == NO_ERROR || err_no == SS_SUCCESS)
		return 0;
	if (err_no == OTHER_ERROR)
		return 20;

	if ( ( err_no >= AFTER_LAST_ERR_CODE || err_no <= ERR_CODE_BASE ) &&
	     ( err_no > SS_CW_NO_NEED || err_no <= SS_AFTER_LAST_ERROR) ) {
		fprintf(stderr,"Error code %d unknown.\n"
			"You should update the drbd userland tools.\n",err_no);
		rv = 20;
	} else {
		if(err_no > ERR_CODE_BASE ) {
			fprintf(stderr,"%s: Failure: (%d) %s\n",
				devname, err_no, error_to_string(err_no));
			rv = 10;
		} else if (err_no == SS_UNKNOWN_ERROR) {
			fprintf(stderr,"%s: State change failed: (%d)"
				"unknown error.\n", devname, err_no);
			rv = 11;
		} else if (err_no > SS_TWO_PRIMARIES) {
			// Ignore SS_SUCCESS, SS_NOTHING_TO_DO, SS_CW_Success...
		} else {
			fprintf(stderr,"%s: State change failed: (%d) %s\n",
				devname, err_no, drbd_set_st_err_str(err_no));
			if (err_no == SS_NO_UP_TO_DATE_DISK) {
				/* all available disks are inconsistent,
				 * or I am consistent, but cannot outdate the peer. */
				rv = 17;
			} else if (err_no == SS_LOWER_THAN_OUTDATED) {
				/* was inconsistent anyways */
				rv = 5;
			} else if (err_no == SS_NO_LOCAL_DISK) {
				/* Can not start resync, no local disks, try with drbdmeta */
				rv = 16;
			} else {
				rv = 11;
			}
		}
	}
	return rv;
}

#define RCV_SIZE NLMSG_SPACE(sizeof(struct cn_msg)+sizeof(struct drbd_nl_cfg_reply))

/* cmdname and optind are global variables */
static void warn_unrecognized_option(char **argv)
{
	fprintf(stderr, "%s %s: unrecognized option '%s'\n",
		cmdname, argv[0], argv[optind - 1]);
}

static void warn_missing_required_arg(char **argv)
{
	fprintf(stderr, "%s %s: option '%s' requires an argument\n",
		cmdname, argv[0], argv[optind - 1]);
}

static void warn_print_excess_args(int argc, char **argv, int i)
{
	fprintf(stderr, "Ignoring excess arguments:");
	for (; i < argc; i++)
		fprintf(stderr, " %s", argv[i]);
	printf("\n");
}

static void dump_argv(int argc, char **argv, int first_non_option, int n_known_args)
{
	int i;
	if (!debug_dump_argv)
		return;
	fprintf(stderr, ",-- ARGV dump (optind %d, known_args %d, argc %u):\n",
		first_non_option, n_known_args, argc);
	for (i = 0; i < argc; i++) {
		if (i == 1)
			fprintf(stderr, "-- consumed options:");
		if (i == first_non_option)
			fprintf(stderr, "-- known args:");
		if (i == (first_non_option + n_known_args))
			fprintf(stderr, "-- unexpected args:");
		fprintf(stderr, "| %2u: %s\n", i, argv[i]);
	}
	fprintf(stderr, "`--\n");
}

static int _generic_config_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv)
{
	char buffer[ RCV_SIZE ];
	struct drbd_nl_cfg_reply *reply;
	struct drbd_argument *ad = cm->cp.args;
	struct drbd_option *od;
	struct option *lo;
	struct drbd_tag_list *tl;
	int c,i=1,rv=NO_ERROR,sk_nl;
	int flags=0;
	int n_args;

	tl = create_tag_list(4096);

	while(ad && ad->name) {
		if(argc < i+1) {
			fprintf(stderr,"Missing argument '%s'\n", ad->name);
			print_command_usage(cm-commands, "",FULL);
			rv = OTHER_ERROR;
			goto error;
		}
		rv = ad->convert_function(ad,tl,argv[i++]);
		if (rv != NO_ERROR)
			goto error;
		ad++;
	}
	n_args = i - 1;

	lo = make_longoptions(cm->cp.options);
	opterr=0;
	while( (c=getopt_long(argc,argv,make_optstring(lo,':'),lo,0)) != -1 ) {
		od = find_opt_by_short_name(cm->cp.options,c);
		if (od)
			rv = od->convert_function(od,tl,optarg);
		else {
			if(c=='(') flags |= DRBD_NL_SET_DEFAULTS;
			else if(c==')') flags |= DRBD_NL_CREATE_DEVICE;
			else {
				if (c == ':') {
					warn_missing_required_arg(argv);
					rv = OTHER_ERROR;
					goto error;
				}
				warn_unrecognized_option(argv);
				rv = OTHER_ERROR;
				goto error;
			}
		}
		if (rv != NO_ERROR)
			goto error;
	}

	/* argc should be cmd + n options + n args;
	 * if it is more, we did not understand some */
	if (n_args + optind < argc)
		warn_print_excess_args(argc, argv, optind + n_args);

	dump_argv(argc, argv, optind, i - 1);

	add_tag(tl,TT_END,NULL,0); // close the tag list

	if(rv == NO_ERROR) {
		//dump_tag_list(tl->tag_list_start);
		int received;
		sk_nl = open_cn();
		if (sk_nl < 0) {
			rv = OTHER_ERROR;
			goto error;
		}

		tl->drbd_p_header->packet_type = cm->packet_id;
		tl->drbd_p_header->drbd_minor = minor;
		tl->drbd_p_header->flags = flags;

		received = call_drbd(sk_nl,tl, (struct nlmsghdr*)buffer,RCV_SIZE,NL_TIME);

		close_cn(sk_nl);

		if (received >= 0) {
			reply = (struct drbd_nl_cfg_reply *)
				((struct cn_msg *)NLMSG_DATA(buffer))->data;
			rv = reply->ret_code;
		}
	}
error:
	free_tag_list(tl);

	return rv;
}

static int generic_config_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv)
{
	return print_config_error(_generic_config_cmd(cm, minor, argc, argv));
}

#define ASSERT(exp) if (!(exp)) \
		fprintf(stderr,"ASSERT( " #exp " ) in %s:%d\n", __FILE__,__LINE__);

static void show_numeric(struct drbd_option *od, unsigned short* tp)
{
	long long val;
	const unsigned char unit_prefix = od->numeric_param.unit_prefix;

	switch(tag_type(get_unaligned(tp++))) {
	case TT_INTEGER:
		ASSERT( get_unaligned(tp++) == sizeof(int) );
		val = get_unaligned((int*)tp);
		break;
	case TT_INT64:
		ASSERT( get_unaligned(tp++) == sizeof(uint64_t) );
		val = get_unaligned((uint64_t*)tp);
		break;
	default:
		ASSERT(0);
		val=0;
	}

	if(unit_prefix == 1) printf("\t%-16s\t%lld",od->name,val);
	else printf("\t%-16s\t%lld%c",od->name,val,unit_prefix);
	if(val == (long long) od->numeric_param.def) printf(" _is_default");
	if(od->numeric_param.unit) {
		printf("; # %s\n",od->numeric_param.unit);
	} else {
		printf(";\n");
	}
}

static void show_handler(struct drbd_option *od, unsigned short* tp)
{
	const char** handler_names = od->handler_param.handler_names;
	int i;

	ASSERT( tag_type(get_unaligned(tp++)) == TT_INTEGER );
	ASSERT( get_unaligned(tp++) == sizeof(int) );
	i = get_unaligned((int*)tp);
	printf("\t%-16s\t%s",od->name,handler_names[i]);
	if( i == (long long)od->numeric_param.def) printf(" _is_default");
	printf(";\n");
}

static void show_bit(struct drbd_option *od, unsigned short* tp)
{
	ASSERT( tag_type(get_unaligned(tp++)) == TT_BIT );
	ASSERT( get_unaligned(tp++) == sizeof(char) );
	if(get_unaligned((char*)tp)) printf("\t%-16s;\n",od->name);
}

static void show_string(struct drbd_option *od, unsigned short* tp)
{
	ASSERT( tag_type(get_unaligned(tp++)) == TT_STRING );
	if( get_unaligned(tp++) > 0 && get_unaligned((char*)tp)) printf("\t%-16s\t\"%s\";\n",od->name,(char*)tp);
}

static unsigned short *look_for_tag(unsigned short *tlc, unsigned short tag)
{
	enum drbd_tags t;
	int len;

	while( (t = get_unaligned(tlc)) != TT_END ) {
		if(t == tag) return tlc;
		tlc++;
		len = get_unaligned(tlc++);
		tlc = (unsigned short*)((char*)tlc + len);
	}
	return NULL;
}

static void print_options(struct drbd_option *od, unsigned short *tlc, const char* sect_name)
{
	unsigned short *tp;
	int opened = 0;

	while(od->name) {
		tp = look_for_tag(tlc,od->tag);
		if(tp) {
			if(!opened) {
				opened=1;
				printf("%s {\n",sect_name);
			}
			od->show_function(od,tp);
			put_unaligned(TT_REMOVED, tp);
		}
		od++;
	}
	if(opened) {
		printf("}\n");
	}
}


static void consume_everything(unsigned short *tlc)
{
	enum drbd_tags t;
	int len;
	while( (t = get_unaligned(tlc)) != TT_END ) {
		put_unaligned(TT_REMOVED, tlc++);
		len = get_unaligned(tlc++);
		tlc = (unsigned short*)((char*)tlc + len);
	}
}

static int consume_tag_blob(enum drbd_tags tag, unsigned short *tlc,
		     char** val, unsigned int* len)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		put_unaligned(TT_REMOVED, tp++);
		*len = get_unaligned(tp++);
		*val = (char*)tp;
		return 1;
	}
	return 0;
}

static int consume_tag_string(enum drbd_tags tag, unsigned short *tlc, char** val)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		put_unaligned(TT_REMOVED, tp++);
		if( get_unaligned(tp++) > 0 )
			*val = (char*)tp;
		else
			*val = "";
		return 1;
	}
	return 0;
}

static int consume_tag_int(enum drbd_tags tag, unsigned short *tlc, int* val)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		put_unaligned(TT_REMOVED, tp++);
		tp++;
		*val = get_unaligned((int *)tp);
		return 1;
	}
	return 0;
}

static int consume_tag_u64(enum drbd_tags tag, unsigned short *tlc, unsigned long long* val)
{
	unsigned short *tp;
	unsigned short len;
	tp = look_for_tag(tlc, tag);
	if(tp) {
		put_unaligned(TT_REMOVED, tp++);
		len = get_unaligned(tp++);
		/* check the data size.
		 * actually it has to be long long, but I'm paranoid */
		if (len == sizeof(int))
			*val = get_unaligned((unsigned int*)tp);
		else if (len == sizeof(long))
			*val = get_unaligned((unsigned long *)tp);
		else if (len == sizeof(long long))
			*val = get_unaligned((unsigned long long *)tp);
		else {
			fprintf(stderr, "%s: unexpected tag len: %u\n",
					__func__ , len);
			return 0;
		}
		return 1;
	}
	return 0;
}

static int consume_tag_bit(enum drbd_tags tag, unsigned short *tlc, int* val)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		put_unaligned(TT_REMOVED, tp++);
		tp++;
		*val = (int)(*(char *)tp);
		return 1;
	}
	return 0;
}

static int generic_get_cmd(struct drbd_cmd *cm, unsigned minor, int argc,
		    char **argv __attribute((unused)))
{
	char buffer[ 4096 ];
	struct drbd_tag_list *tl;
	struct drbd_nl_cfg_reply *reply;
	int sk_nl,rv;
	int ignore_minor_not_known;
	int dummy;

	if (argc > 1)
		warn_print_excess_args(argc, argv, 1);

	dump_argv(argc, argv, 1, 0);

	tl = create_tag_list(2);
	add_tag(tl,TT_END,NULL,0); // close the tag list

	sk_nl = open_cn();
	if(sk_nl < 0) return 20;

	tl->drbd_p_header->packet_type = cm->packet_id;
	tl->drbd_p_header->drbd_minor = minor;
	tl->drbd_p_header->flags = 0;

	memset(buffer,0,sizeof(buffer));
	call_drbd(sk_nl,tl, (struct nlmsghdr*)buffer,4096,NL_TIME);

	close_cn(sk_nl);
	reply = (struct drbd_nl_cfg_reply *)
		((struct cn_msg *)NLMSG_DATA(buffer))->data;

	/* if there was an error, report and abort --
	 * unless it was "this device is not there",
	 * and command was "status" */
	ignore_minor_not_known =
		cm->gp.show_function == status_xml_scmd ||
		cm->gp.show_function == sh_status_scmd;
	if (reply->ret_code != NO_ERROR &&
	   !(reply->ret_code == ERR_MINOR_INVALID && ignore_minor_not_known))
		return print_config_error(reply->ret_code);

	rv = cm->gp.show_function(cm,minor,reply->tag_list);

	/* in case cm->packet_id == P_get_state, and the gp.show_function did
	 * nothing with the sync_progress info, consume it here, so it won't
	 * confuse users because it gets dumped below. */
	consume_tag_int(T_sync_progress, reply->tag_list, &dummy);

	if(dump_tag_list(reply->tag_list)) {
		printf("# Found unknown tags, you should update your\n"
		       "# userland tools\n");
	}

	return rv;
}

static char *af_to_str(int af)
{
	if (af == AF_INET)
		return "ipv4";
	else if (af == AF_INET6)
		return "ipv6";
	/* AF_SSOCKS typically is 27, the same as AF_INET_SDP.
	 * But with warn_and_use_default = 0, it will stay at -1 if not available.
	 * Just keep the test on ssocks before the one on SDP (which is hard-coded),
	 * and all should be fine.  */
	else if (af == get_af_ssocks(0))
		return "ssocks";
	else if (af == AF_INET_SDP)
		return "sdp";
	else return "unknown";
}

static void show_address(void* address, int addr_len)
{
	struct sockaddr     *addr;
	struct sockaddr_in  *addr4;
	struct sockaddr_in6 *addr6;
	char buffer[INET6_ADDRSTRLEN];

	addr = (struct sockaddr *)address;
	if (addr->sa_family == AF_INET
	|| addr->sa_family == get_af_ssocks(0)
	|| addr->sa_family == AF_INET_SDP) {
		addr4 = (struct sockaddr_in *)address;
		printf("\taddress\t\t\t%s %s:%d;\n",
		       af_to_str(addr4->sin_family),
		       inet_ntoa(addr4->sin_addr),
		       ntohs(addr4->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		addr6 = (struct sockaddr_in6 *)address;
		printf("\taddress\t\t\t%s [%s]:%d;\n",
		       af_to_str(addr6->sin6_family),
		       inet_ntop(addr6->sin6_family, &addr6->sin6_addr, buffer, INET6_ADDRSTRLEN),
		       ntohs(addr6->sin6_port));
	} else {
		printf("\taddress\t\t\t[unknown af=%d, len=%d]\n", addr->sa_family, addr_len);
	}
}

static int show_scmd(struct drbd_cmd *cm, unsigned minor, unsigned short *rtl)
{
	int idx = idx;
	char *str = NULL, *backing_dev, *address;
	unsigned int addr_len = 0;

	// find all commands that have options and print those...
	for ( cm = commands ; cm < commands + ARRY_SIZE(commands) ; cm++ ) {
		if(cm->function == generic_config_cmd && cm->cp.options )
			print_options(cm->cp.options, rtl, cm->cmd);
	}

	// start of spaghetti code...
	if(consume_tag_int(T_wire_protocol,rtl,&idx))
		printf("protocol %c;\n",'A'+idx-1);
	backing_dev = address = NULL;
	consume_tag_string(T_backing_dev,rtl,&backing_dev);
	consume_tag_blob(T_my_addr, rtl, &address, &addr_len);
	if(backing_dev || address) {
		printf("_this_host {\n");
		printf("\tdevice\t\t\tminor %d;\n",minor);
		if(backing_dev) {
			printf("\tdisk\t\t\t\"%s\";\n",backing_dev);
			consume_tag_int(T_meta_dev_idx,rtl,&idx);
			consume_tag_string(T_meta_dev,rtl,&str);
			switch(idx) {
			case DRBD_MD_INDEX_INTERNAL:
			case DRBD_MD_INDEX_FLEX_INT:
				printf("\tmeta-disk\t\tinternal;\n");
				break;
			case DRBD_MD_INDEX_FLEX_EXT:
				printf("\tflexible-meta-disk\t\"%s\";\n",str);
				break;
			default:
				printf("\tmeta-disk\t\t\"%s\" [ %d ];\n",str,
				       idx);
			 }
		}
		if(address)
			show_address(address, addr_len);
		printf("}\n");
	}

	if(consume_tag_blob(T_peer_addr, rtl, &address, &addr_len)) {
		printf("_remote_host {\n");
		show_address(address, addr_len);
		printf("}\n");
	}
	consume_tag_bit(T_mind_af, rtl, &idx); /* consume it, its value has no relevance */
	consume_tag_bit(T_auto_sndbuf_size, rtl, &idx); /* consume it, its value has no relevance */

	return 0;
}

static int lk_bdev_scmd(struct drbd_cmd *cm, unsigned minor,
			unsigned short *rtl)
{
	struct bdev_info bd = { 0, };
	char *backing_dev = NULL;
	uint64_t bd_size;
	int fd;
	int idx = idx;
	int index_valid = 0;

	consume_tag_string(T_backing_dev, rtl, &backing_dev);
	index_valid = consume_tag_int(T_meta_dev_idx, rtl, &idx);

	/* consume everything */
	consume_everything(rtl);

	if (!backing_dev) {
		fprintf(stderr, "Has no disk config, try with drbdmeta.\n");
		return 1;
	}

	if (!index_valid) {
		/* cannot happen, right? ;-) */
		fprintf(stderr, "No meta data index!?\n");
		return 1;
	}

	if (idx >= 0 || idx == DRBD_MD_INDEX_FLEX_EXT) {
		lk_bdev_delete(minor);
		return 0;
	}

	fd = open(backing_dev, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Could not open %s: %m.\n", backing_dev);
		return 1;
	}
	bd_size = bdev_size(fd);
	close(fd);

	if (lk_bdev_load(minor, &bd) == 0 &&
	    bd.bd_size == bd_size &&
	    bd.bd_name && !strcmp(bd.bd_name, backing_dev))
		return 0;	/* nothing changed. */

	bd.bd_size = bd_size;
	bd.bd_name = backing_dev;
	lk_bdev_save(minor, &bd);

	return 0;
}

static int status_xml_scmd(struct drbd_cmd *cm __attribute((unused)),
		unsigned minor, unsigned short *rtl)
{
	union drbd_state state = { .i = 0 };
	int synced = 0;

	if (!consume_tag_int(T_state_i,rtl,(int*)&state.i)) {
		printf( "<!-- resource minor=\"%u\"", minor);
		if (resname)
			printf(" name=\"%s\"", resname);
		printf(" not available or not yet created -->\n");
		return 0;
	}
	printf("<resource minor=\"%u\"", minor);
	if (resname)
		printf(" name=\"%s\"", resname);

	if (state.conn == C_STANDALONE && state.disk == D_DISKLESS) {
		printf(" cs=\"Unconfigured\" />\n");
		return 0;
	}

	printf( /* connection state */
		" cs=\"%s\""
		/* role */
		" ro1=\"%s\" ro2=\"%s\""
		/* disk state */
		" ds1=\"%s\" ds2=\"%s\"",
	       drbd_conn_str(state.conn),
	       drbd_role_str(state.role),
	       drbd_role_str(state.peer),
	       drbd_disk_str(state.disk),
	       drbd_disk_str(state.pdsk));

	/* io suspended ? */
	if (state.susp)
		printf(" suspended");
	/* reason why sync is paused */
	if (state.aftr_isp)
		printf(" aftr_isp");
	if (state.peer_isp)
		printf(" peer_isp");
	if (state.user_isp)
		printf(" user_isp");

	if (consume_tag_int(T_sync_progress, rtl, &synced))
		printf(" resynced_percent=\"%i.%i\"", synced / 10, synced % 10);

	printf(" />\n");
	return 0;
}

static int sh_status_scmd(struct drbd_cmd *cm __attribute((unused)),
		unsigned minor, unsigned short *rtl)
{
/* variable prefix; maybe rather make that a command line parameter?
 * or use "drbd_sh_status"? */
#define _P ""
	union drbd_state state = { .i = 0 };
	int available = 0;
	int synced = 0;

	printf("%s_minor=%u\n", _P, minor);
	printf("%s_res_name=%s\n", _P, shell_escape(resname ?: "UNKNOWN"));

	available = consume_tag_int(T_state_i,rtl,(int*)&state.i);

	if (state.conn == C_STANDALONE && state.disk == D_DISKLESS) {
		printf("%s_known=%s\n\n", _P,
			available ? "Unconfigured"
			          : "NA # not available or not yet created");
		printf("%s_cstate=Unconfigured\n", _P);
		printf("%s_role=\n", _P);
		printf("%s_peer=\n", _P);
		printf("%s_disk=\n", _P);
		printf("%s_pdisk=\n", _P);
		printf("%s_flags_susp=\n", _P);
		printf("%s_flags_aftr_isp=\n", _P);
		printf("%s_flags_peer_isp=\n", _P);
		printf("%s_flags_user_isp=\n", _P);
		printf("%s_resynced_percent=\n", _P);
	} else {
		printf( "%s_known=Configured\n\n"
			/* connection state */
			"%s_cstate=%s\n"
			/* role */
			"%s_role=%s\n"
			"%s_peer=%s\n"
			/* disk state */
			"%s_disk=%s\n"
			"%s_pdsk=%s\n\n",
			_P,
			_P, drbd_conn_str(state.conn),
			_P, drbd_role_str(state.role),
			_P, drbd_role_str(state.peer),
			_P, drbd_disk_str(state.disk),
			_P, drbd_disk_str(state.pdsk));

		/* io suspended ? */
		printf("%s_flags_susp=%s\n", _P, state.susp ? "1" : "");
		/* reason why sync is paused */
		printf("%s_flags_aftr_isp=%s\n", _P, state.aftr_isp ? "1" : "");
		printf("%s_flags_peer_isp=%s\n", _P, state.peer_isp ? "1" : "");
		printf("%s_flags_user_isp=%s\n\n", _P, state.user_isp ? "1" : "");

		printf("%s_resynced_percent=", _P);

		if (consume_tag_int(T_sync_progress, rtl, &synced))
			printf("%i.%i\n", synced / 10, synced % 10);
		else
			printf("\n");
	}
	printf("\n%s_sh_status_process\n\n\n", _P);

	fflush(stdout);
	return 0;
#undef _P
}

static int role_scmd(struct drbd_cmd *cm __attribute((unused)),
	       unsigned minor __attribute((unused)),
	       unsigned short *rtl)
{
	union drbd_state state = { .i = 0 };
	consume_tag_int(T_state_i,rtl,(int*)&state.i);
	if ( state.conn == C_STANDALONE &&
	     state.disk == D_DISKLESS) {
		printf("Unconfigured\n");
	} else {
		printf("%s/%s\n",drbd_role_str(state.role),drbd_role_str(state.peer));
	}
	return 0;
}

static int cstate_scmd(struct drbd_cmd *cm __attribute((unused)),
		unsigned minor __attribute((unused)),
		unsigned short *rtl)
{
	union drbd_state state = { .i = 0 };
	consume_tag_int(T_state_i,rtl,(int*)&state.i);
	if ( state.conn == C_STANDALONE &&
	     state.disk == D_DISKLESS) {
		printf("Unconfigured\n");
	} else {
		printf("%s\n",drbd_conn_str(state.conn));
	}
	return 0;
}

static int dstate_scmd(struct drbd_cmd *cm __attribute((unused)),
		unsigned minor __attribute((unused)),
		unsigned short *rtl)
{
	union drbd_state state = { .i = 0 };
	consume_tag_int(T_state_i,rtl,(int*)&state.i);
	if ( state.conn == C_STANDALONE &&
	     state.disk == D_DISKLESS) {
		printf("Unconfigured\n");
	} else {
		printf("%s/%s\n",drbd_disk_str(state.disk),drbd_disk_str(state.pdsk));
	}
	return 0;
}

static int uuids_scmd(struct drbd_cmd *cm,
	       unsigned minor __attribute((unused)),
	       unsigned short *rtl)
{
	uint64_t uuids[UI_SIZE];
	char *tl_uuids;
	int flags = flags;
	unsigned int len;

	if (!consume_tag_blob(T_uuids, rtl, &tl_uuids, &len)) {
		fprintf(stderr,"Reply payload did not carry an uuid-tag,\n"
			"Probably the device has no disk!\n");
		return 1;
	}

	consume_tag_int(T_uuids_flags,rtl,&flags);
	if( len == UI_SIZE * sizeof(uint64_t)) {
		memcpy(uuids, tl_uuids, len);
		if(!strcmp(cm->cmd,"show-gi")) {
			dt_pretty_print_uuids(uuids,flags);
		} else if(!strcmp(cm->cmd,"get-gi")) {
			dt_print_uuids(uuids,flags);
		} else {
			ASSERT( 0 );
		}
	} else {
		fprintf(stderr, "Unexpected length of T_uuids tag. "
			"You should upgrade your userland tools\n");
	}
	return 0;
}

static struct drbd_cmd *find_cmd_by_name(char *name)
{
	unsigned int i;

	if (!strcmp(name, "state")) {
		fprintf(stderr, "'%s ... state' is deprecated, use '%s ... role' instead.\n",
			cmdname, cmdname);
		name = "role";
	}

	for (i = 0; i < ARRY_SIZE(commands); i++) {
		if (!strcmp(name, commands[i].cmd)) {
			return commands + i;
		}
	}
	return NULL;
}

static int down_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv)
{
	int rv;
	int success;

	if(argc > 1) {
		fprintf(stderr,"Ignoring excess arguments\n");
	}

	cm = find_cmd_by_name("secondary");
	rv = _generic_config_cmd(cm, minor, argc, argv); // No error messages
	if (rv == ERR_MINOR_INVALID)
		return 0;
	success = (rv >= SS_SUCCESS && rv < ERR_CODE_BASE) || rv == NO_ERROR;
	if (!success)
		return print_config_error(rv);
	cm = find_cmd_by_name("disconnect");
	cm->function(cm,minor,argc,argv);
	cm = find_cmd_by_name("detach");
	return cm->function(cm,minor,argc,argv);
}


static void print_digest(const char* label, const int len, const unsigned char *hash)
{
	int i;
	printf("\t%s: ", label);
	for (i = 0; i < len; i++)
		printf("%02x",hash[i]);
	printf("\n");
}

static char printable_or_dot(char c)
{
	return (' ' < c && c <= '~') ? c : '.';
}

static void print_hex_line(int offset, unsigned char *data)
{

	printf(	" %04x:"
		" %02x %02x %02x %02x %02x %02x %02x %02x "
		" %02x %02x %02x %02x %02x %02x %02x %02x"
		"  %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
		offset,
		data[0], data[1], data[2], data[3],
		data[4], data[5], data[6], data[7],
		data[8], data[9], data[10], data[11],
		data[12], data[13], data[14], data[15],
		printable_or_dot(data[0]), printable_or_dot(data[1]),
		printable_or_dot(data[2]), printable_or_dot(data[3]),
		printable_or_dot(data[4]), printable_or_dot(data[5]),
		printable_or_dot(data[6]), printable_or_dot(data[7]),
		printable_or_dot(data[8]), printable_or_dot(data[9]),
		printable_or_dot(data[10]), printable_or_dot(data[11]),
		printable_or_dot(data[12]), printable_or_dot(data[13]),
		printable_or_dot(data[14]), printable_or_dot(data[15]));
}

/* successive identical lines are collapsed into just printing one star */
static void print_hex_dump(int len, void *data)
{
	int i;
	int star = 0;
	for (i = 0; i < len-15; i += 16) {
		if (i == 0 || memcmp(data + i, data + i - 16, 16)) {
			print_hex_line(i, data + i);
			star = 0;
		} else if (!star)  {
			printf(" *\n");
			star = 1;
		}
	}
	/* yes, I ignore remainders of len not modulo 16 here.
	 * so what, usage is currently to dump bios, which are
	 * multiple of 512. */
	/* for good measure, print the total size as offset now,
	 * last line may have been a '*' */
	printf(" %04x.\n", len);
}

static void print_dump_ee(struct drbd_nl_cfg_reply *reply)
{
	unsigned long long sector = -1ULL;
	unsigned long long block_id = 0;
	char *reason = "UNKNOWN REASON";
	char *dig_in = NULL;
	char *dig_vv = NULL;
	unsigned int dgs_in = 0, dgs_vv = 0;
	unsigned int size = 0;
	char *data = NULL;

	if (!consume_tag_string(T_dump_ee_reason, reply->tag_list, &reason))
		printf("\tno reason?\n");
	if (!consume_tag_blob(T_seen_digest, reply->tag_list, &dig_in, &dgs_in))
		printf("\tno digest in?\n");
	if (!consume_tag_blob(T_calc_digest, reply->tag_list, &dig_vv, &dgs_vv))
		printf("\tno digest out?\n");
	if (!consume_tag_u64(T_ee_sector, reply->tag_list, &sector))
		printf("\tno sector?\n");
	if (!consume_tag_u64(T_ee_block_id, reply->tag_list, &block_id))
		printf("\tno block_id?\n");
	if (!consume_tag_blob(T_ee_data, reply->tag_list, &data, &size))
		printf("\tno data?\n");

	printf("\tdumping ee, reason: %s\n", reason);
	printf("\tsector: %llu block_id: 0x%llx size: %u\n",
			sector, block_id, size);
	
	/* "input sanitation". Did I mention yet that I'm paranoid? */
	if (!data) size = 0;
	if (!dig_in) dgs_in = 0;
	if (!dig_vv) dgs_vv = 0;
	if (dgs_in > SHARED_SECRET_MAX) dgs_in = SHARED_SECRET_MAX;
	if (dgs_vv > SHARED_SECRET_MAX) dgs_vv = SHARED_SECRET_MAX;

	print_digest("received digest", dgs_in, (unsigned char*)dig_in);
	print_digest("verified digest", dgs_vv, (unsigned char*)dig_vv);

	/* dump at most 32 K */
	if (size > 0x8000) {
		size = 0x8000;
		printf("\tWARNING truncating data to %u!\n", 0x8000);
	}
	print_hex_dump(size,data);
}

/* this is not pretty; but it's api... ;-( */
const char *pretty_print_return_code(int e)
{
	return
		e == NO_ERROR ? "No error" :
		e > ERR_CODE_BASE ?
			error_to_string(e) :
		e > SS_AFTER_LAST_ERROR && e <= SS_TWO_PRIMARIES ?
			drbd_set_st_err_str(e) :
		e == SS_CW_NO_NEED ? "Cluster wide state change: nothing to do" :
		e == SS_CW_SUCCESS ? "Cluster wide state change successful" :
		e == SS_NOTHING_TO_DO ? "State change: nothing to do" :
		e == SS_SUCCESS ? "State change successful" :
		e == SS_UNKNOWN_ERROR ? "Unspecified error" :
		"Unknown return code";
}

static int print_broadcast_events(unsigned int seq, int u __attribute((unused)),
			   struct drbd_nl_cfg_reply *reply)
{
	union drbd_state state;
	char* str;
	int synced = 0;

	switch (reply->packet_type) {
	case 0: /* used to be this way in drbd_nl.c for some responses :-( */
	case P_return_code_only: /* used by drbd_nl.c for most "empty" responses */
		printf("%u ZZ %d ret_code: %d %s\n", seq, reply->minor,
			reply->ret_code,
			pretty_print_return_code(reply->ret_code));
		break;
	case P_get_state:
		if(consume_tag_int(T_state_i,reply->tag_list,(int*)&state.i)) {
			printf("%u ST %d { cs:%s ro:%s/%s ds:%s/%s %c%c%c%c }\n",
			       seq,
			       reply->minor,
			       drbd_conn_str(state.conn),
			       drbd_role_str(state.role),
			       drbd_role_str(state.peer),
			       drbd_disk_str(state.disk),
			       drbd_disk_str(state.pdsk),
			       state.susp ? 's' : 'r',
			       state.aftr_isp ? 'a' : '-',
			       state.peer_isp ? 'p' : '-',
			       state.user_isp ? 'u' : '-' );
		} else fprintf(stderr,"Missing tag !?\n");
		break;
	case P_call_helper:
		if(consume_tag_string(T_helper,reply->tag_list,&str)) {
			printf("%u UH %d %s\n", seq, reply->minor, str);
		} else fprintf(stderr,"Missing tag !?\n");
		break;
	case P_sync_progress:
		if (consume_tag_int(T_sync_progress, reply->tag_list, &synced)) {
			printf("%u SP %d %i.%i\n",
				seq,
				reply->minor,
				synced / 10,
				synced % 10);
		} else fprintf(stderr,"Missing tag !?\n");
		break;
	case P_dump_ee:
		printf("%u DE %d\n", seq, reply->minor);
		print_dump_ee(reply);
		break;
	default:
		printf("%u ?? %d <other message %d>\n",seq, reply->minor, reply->packet_type);
		break;
	}

	fflush(stdout);

	return 1;
}

void print_failure_code(int ret_code)
{
	if (ret_code > ERR_CODE_BASE)
		fprintf(stderr,"%s: Failure: (%d) %s\n",
			devname, ret_code, error_to_string(ret_code));
	else
		fprintf(stderr,"%s: Failure: (ret_code=%d)\n",
			devname, ret_code);
}

static int w_connected_state(unsigned int seq __attribute((unused)),
		      int wait_after_sb,
		      struct drbd_nl_cfg_reply *reply)
{
	union drbd_state state;

	if (reply->ret_code != NO_ERROR) {
		print_failure_code(reply->ret_code);
		return 0;
	}

	if(reply->packet_type == P_get_state) {
		if(consume_tag_int(T_state_i,reply->tag_list,(int*)&state.i)) {
			if(state.conn >= C_CONNECTED) return 0;
			if(!wait_after_sb && state.conn < C_UNCONNECTED) return 0;
		} else fprintf(stderr,"Missing tag !?\n");
	}

	return 1;
}

static int w_synced_state(unsigned int seq __attribute((unused)),
		   int wait_after_sb,
		   struct drbd_nl_cfg_reply *reply)
{
	union drbd_state state;

	if (reply->ret_code != NO_ERROR) {
		print_failure_code(reply->ret_code);
		return 0;
	}

	if(reply->packet_type == P_get_state) {
		if(consume_tag_int(T_state_i,reply->tag_list,(int*)&state.i)) {
			if(state.conn == C_CONNECTED) return 0;
			if(!wait_after_sb && state.conn < C_UNCONNECTED) return 0;
		} else fprintf(stderr,"Missing tag !?\n");
	}
	return 1;
}

static int events_cmd(struct drbd_cmd *cm, unsigned minor, int argc ,char **argv)
{
	void *buffer;
	struct cn_msg *cn_reply;
	struct drbd_nl_cfg_reply *reply;
	struct drbd_tag_list *tl;
	struct option *lo;
	unsigned int b_seq=0, r_seq=0;
	int sk_nl,c,cont=1,rr = rr,i,last;
	int unfiltered=0, all_devices=0, timeout_ms=0;
	int wfc_timeout=DRBD_WFC_TIMEOUT_DEF;
	int degr_wfc_timeout=DRBD_DEGR_WFC_TIMEOUT_DEF;
	int outdated_wfc_timeout=DRBD_OUTDATED_WFC_TIMEOUT_DEF;
	struct timeval before,after;
	int wasb=0;

	lo = cm->ep.options;

	while( (c=getopt_long(argc,argv,make_optstring(lo,':'),lo,0)) != -1 ) {
		switch(c) {
		default:
		case '?':
			warn_unrecognized_option(argv);
			return 20;
		case ':':
			warn_missing_required_arg(argv);
			return 20;
		case 'u': unfiltered=1; break;
		case 'a': all_devices=1; break;
		case 't':
			wfc_timeout=m_strtoll(optarg,1);
			if(DRBD_WFC_TIMEOUT_MIN > wfc_timeout ||
			   wfc_timeout > DRBD_WFC_TIMEOUT_MAX) {
				fprintf(stderr, "wfc_timeout => %d"
					" out of range [%d..%d]\n",
					wfc_timeout, DRBD_WFC_TIMEOUT_MIN,
					DRBD_WFC_TIMEOUT_MAX);
				return 20;
			}
			break;
		case 'd':
			degr_wfc_timeout=m_strtoll(optarg,1);
			if(DRBD_DEGR_WFC_TIMEOUT_MIN > degr_wfc_timeout ||
			   degr_wfc_timeout > DRBD_DEGR_WFC_TIMEOUT_MAX) {
				fprintf(stderr, "degr_wfc_timeout => %d"
					" out of range [%d..%d]\n",
					degr_wfc_timeout, DRBD_DEGR_WFC_TIMEOUT_MIN,
					DRBD_DEGR_WFC_TIMEOUT_MAX);
				return 20;
			}
			break;
		case 'o':
			outdated_wfc_timeout=m_strtoll(optarg,1);
			if(DRBD_OUTDATED_WFC_TIMEOUT_MIN > degr_wfc_timeout ||
			   degr_wfc_timeout > DRBD_OUTDATED_WFC_TIMEOUT_MAX) {
				fprintf(stderr, "degr_wfc_timeout => %d"
					" out of range [%d..%d]\n",
					outdated_wfc_timeout, DRBD_OUTDATED_WFC_TIMEOUT_MIN,
					DRBD_OUTDATED_WFC_TIMEOUT_MAX);
				return 20;
			}
			break;

		case 'w':
			wasb=1;
			break;
		}
	}

	if (optind < argc)
		warn_print_excess_args(argc, argv, optind);

	dump_argv(argc, argv, optind, 0);

	tl = create_tag_list(2);
	add_tag(tl,TT_END,NULL,0); // close the tag list

	sk_nl = open_cn();
	if(sk_nl < 0) return 20;

	/* allocate 64k to be on the safe side. */
#define NL_BUFFER_SIZE (64 << 10)
	buffer = malloc(NL_BUFFER_SIZE);
	if (!buffer) {
		fprintf(stderr, "could not allocate buffer of %u bytes\n", NL_BUFFER_SIZE);
		exit(20);
	}

	/* drbdsetup events should not ask for timeout "type",
	 * this is only useful with wait-sync and wait-connected callbacks.
	 */
	if (cm->ep.proc_event != print_broadcast_events) {
		// Find out which timeout value to use.
		tl->drbd_p_header->packet_type = P_get_timeout_flag;
		tl->drbd_p_header->drbd_minor = minor;
		tl->drbd_p_header->flags = 0;

		if (0 >= call_drbd(sk_nl,tl, buffer, NL_BUFFER_SIZE, NL_TIME))
			exit(20);

		cn_reply = (struct cn_msg *)NLMSG_DATA(buffer);
		reply = (struct drbd_nl_cfg_reply *)cn_reply->data;

		if (reply->ret_code != NO_ERROR)
			return print_config_error(reply->ret_code);

		consume_tag_bit(T_use_degraded,reply->tag_list,&rr);
		if (rr != UT_DEFAULT) {
			if (0 < wfc_timeout &&
			      (wfc_timeout < degr_wfc_timeout || degr_wfc_timeout == 0)) {
				degr_wfc_timeout = wfc_timeout;
				fprintf(stderr, "degr-wfc-timeout has to be shorter than wfc-timeout\n"
						"degr-wfc-timeout implicitly set to wfc-timeout (%ds)\n",
						degr_wfc_timeout);
			}

			if (0 < degr_wfc_timeout &&
			    (degr_wfc_timeout < outdated_wfc_timeout || outdated_wfc_timeout == 0)) {
				outdated_wfc_timeout = wfc_timeout;
				fprintf(stderr, "outdated-wfc-timeout has to be shorter than degr-wfc-timeout\n"
						"outdated-wfc-timeout implicitly set to degr-wfc-timeout (%ds)\n",
						degr_wfc_timeout);
			}

		}

		switch (rr) {
		case UT_DEFAULT:
			timeout_ms = wfc_timeout;
			break;
		case UT_DEGRADED:
			timeout_ms = degr_wfc_timeout;
			break;
		case UT_PEER_OUTDATED:
			timeout_ms = outdated_wfc_timeout;
			break;
		}
	}

	timeout_ms = timeout_ms * 1000 - 1; /* 0 -> -1 "infinite", 1000 -> 999, nobody cares...  */

	// ask for the current state before waiting for state updates...
	if (all_devices) {
		i = 0;
		last = 255;
	}
	else {
		i = last = minor;
	}

	while (i <= last) {
		tl->drbd_p_header->packet_type = P_get_state;
		tl->drbd_p_header->drbd_minor = i;
		tl->drbd_p_header->flags = 0;
		send_cn(sk_nl,tl->nl_header,(char*)tl->tag_list_cpos-(char*)tl->nl_header);
		i++;
	}

	dt_unlock_drbd(lock_fd);
	lock_fd=-1;

	do {
		gettimeofday(&before,NULL);
		rr = receive_cn(sk_nl, buffer, NL_BUFFER_SIZE, timeout_ms);
		gettimeofday(&after,NULL);
		if(rr == -2) break; // timeout expired.

		if(timeout_ms > 0 ) {
			timeout_ms -= ( (after.tv_sec - before.tv_sec) * 1000 +
					(after.tv_usec - before.tv_usec) / 1000 );
		}

		cn_reply = (struct cn_msg *)NLMSG_DATA(buffer);
		reply = (struct drbd_nl_cfg_reply *)cn_reply->data;

		// dump_tag_list(reply->tag_list);

		/* There are two value spaces for sequence numbers. The first
		   is the one created by this drbdsetup instance, the kernel's
		   reply packets simply echo those sequence numbers.
		   The second is created by the kernel's broadcast packets. */
		if (!unfiltered) {
			if (cn_reply->ack == 0) { // broadcasts
				/* Careful, potential wrap around!
				 * Will skip a lot of packets if you
				 * unload/reload the module in between,
				 * but keep this drbdsetup events running.
				 * So don't do that.
				 */
				if ((int)(cn_reply->seq - b_seq) <= 0)
					continue;
				b_seq = cn_reply->seq;
			} else if ((all_devices || minor == reply->minor)
					&& cn_reply->ack == (uint32_t)getpid() + 1) {
				// replies to drbdsetup packets and for this device.
				if ((int)(cn_reply->seq - r_seq) <= 0)
					continue;
				r_seq = cn_reply->seq;
			} else {
				/* or reply to configuration request of other drbdsetup */
				continue;
			}
		}

		if( all_devices || minor == reply->minor ) {
			cont=cm->ep.proc_event(cn_reply->seq, wasb, reply);
		}
	} while(cont);

	free(buffer);

	close_cn(sk_nl);

	/* return code becomes exit code.
	 * timeout? => exit 5
	 * else     => exit 0 */
	return (rr == -2) ? 5 : 0;
}

static int numeric_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c} %lld ... %lld]",
			option->name, option->short_name,
			option->numeric_param.min,
			option->numeric_param.max);
}

static int handler_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	const char** handlers;
	int i, chars=0,first=1;

	chars += snprintf(str,strlen," [{--%s|-%c} {",
			  option->name, option->short_name);
	handlers = option->handler_param.handler_names;
	for(i=0;i<option->handler_param.number_of_handlers;i++) {
		if(handlers[i]) {
			if(!first) chars += snprintf(str+chars,strlen,"|");
			first=0;
			chars += snprintf(str+chars,strlen,
					  "%s",handlers[i]);
		}
	}
	chars += snprintf(str+chars,strlen,"}]");
	return chars;
}

static int bit_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c}]",
			option->name, option->short_name);
}

static int string_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c} <str>]",
			option->name, option->short_name);
}

static void numeric_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"numeric\">\n",option->name);
	printf("\t\t<min>%lld</min>\n",option->numeric_param.min);
	printf("\t\t<max>%lld</max>\n",option->numeric_param.max);
	printf("\t\t<default>%lld</default>\n",option->numeric_param.def);
	if(option->numeric_param.unit_prefix==1) {
		printf("\t\t<unit_prefix>1</unit_prefix>\n");
	} else {
		printf("\t\t<unit_prefix>%c</unit_prefix>\n",
		       option->numeric_param.unit_prefix);
	}
	if(option->numeric_param.unit) {
		printf("\t\t<unit>%s</unit>\n",option->numeric_param.unit);
	}
	printf("\t</option>\n");
}

static void handler_opt_xml(struct drbd_option *option)
{
	const char** handlers;
	int i;

	printf("\t<option name=\"%s\" type=\"handler\">\n",option->name);
	handlers = option->handler_param.handler_names;
	for(i=0;i<option->handler_param.number_of_handlers;i++) {
		if(handlers[i]) {
			printf("\t\t<handler>%s</handler>\n",handlers[i]);
		}
	}
	printf("\t</option>\n");
}

static void bit_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"boolean\">\n",option->name);
	printf("\t</option>\n");
}

static void string_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"string\">\n",option->name);
	printf("\t</option>\n");
}


static void config_usage(struct drbd_cmd *cm, enum usage_type ut)
{
	struct drbd_argument *args;
	struct drbd_option *options;
	static char line[300];
	int maxcol,col,prevcol,startcol,toolong;
	char *colstr;

	if(ut == XML) {
		printf("<command name=\"%s\">\n",cm->cmd);
		if( (args = cm->cp.args) ) {
			while (args->name) {
				printf("\t<argument>%s</argument>\n",
				       args->name);
				args++;
			}
		}

		options = cm->cp.options;
		while (options && options->name) {
			options->xml_function(options);
			options++;
		}
		printf("</command>\n");
		return;
	}

	prevcol=col=0;
	maxcol=100;

	if((colstr=getenv("COLUMNS"))) maxcol=atoi(colstr)-1;

	col += snprintf(line+col, maxcol-col, " %s", cm->cmd);

	if( (args = cm->cp.args) ) {
		if(ut == BRIEF) {
			col += snprintf(line+col, maxcol-col, " [args...]");
		} else {
			while (args->name) {
				col += snprintf(line+col, maxcol-col, " %s",
						args->name);
				args++;
			}
		}
	}

	if (col > maxcol) {
		printf("%s\n",line);
		col=0;
	}
	startcol=prevcol=col;

	options = cm->cp.options;
	if(ut == BRIEF) {
		if(options)
			col += snprintf(line+col, maxcol-col, " [opts...]");
		printf("%-40s",line);
		return;
	}

	while (options && options->name) {
		col += options->usage_function(options, line+col, maxcol-col);
		if (col >= maxcol) {
			toolong = (prevcol == startcol);
			if( !toolong ) line[prevcol]=0;
			printf("%s\n",line);
			startcol=prevcol=col = sprintf(line,"    ");
			if( toolong) options++;
		} else {
			prevcol=col;
			options++;
		}
	}
	line[col]=0;

	printf("%s\n",line);
}

static void get_usage(struct drbd_cmd *cm, enum usage_type ut)
{
	if(ut == BRIEF) {
		printf(" %-39s", cm->cmd);
	} else {
		printf(" %s\n", cm->cmd);
	}
}

static void events_usage(struct drbd_cmd *cm, enum usage_type ut)
{
	struct option *lo;
	char line[41];

	if(ut == BRIEF) {
		sprintf(line,"%s [opts...]", cm->cmd);
		printf(" %-39s",line);
	} else {
		printf(" %s", cm->cmd);
		lo = cm->ep.options;
		while(lo && lo->name) {
			printf(" [{--%s|-%c}]",lo->name,lo->val);
			lo++;
		}
		printf("\n");
	}
}

static void print_command_usage(int i, const char *addinfo, enum usage_type ut)
{
	if(ut != XML) printf("USAGE:\n");
	commands[i].usage(commands+i,ut);

	if (addinfo) {
		printf("%s\n",addinfo);
		exit(20);
	}
}

static void print_usage(const char* addinfo)
{
	size_t i;

	printf("\nUSAGE: %s device command arguments options\n\n"
	       "Device is usually /dev/drbdX or /dev/drbd/X.\n"
	       "General options: --create-device, --set-defaults\n"
	       "\nCommands are:\n",cmdname);


	for (i = 0; i < ARRY_SIZE(commands); i++) {
		commands[i].usage(commands+i,BRIEF);
		if(i%2==1) printf("\n");
	}

	printf("\n\n"
	       "To get more details about a command issue "
	       "'drbdsetup help cmd'.\n"
	       "\n");
	/*
	printf("\n\nVersion: "REL_VERSION" (api:%d)\n%s\n",
	       API_VERSION, drbd_buildtag());
	*/
	if (addinfo)
		printf("\n%s\n",addinfo);

	exit(20);
}

static int open_cn()
{
	int sk_nl;
	int err;
	struct sockaddr_nl my_nla;

	sk_nl = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
	if (sk_nl == -1) {
		perror("socket() failed");
		return -1;
	}

	my_nla.nl_family = AF_NETLINK;
	my_nla.nl_groups = -1; //cn_idx
	my_nla.nl_pid = getpid();

	err = bind(sk_nl, (struct sockaddr *)&my_nla, sizeof(my_nla));
	if (err == -1) {
		err = errno;
		perror("bind() failed");
		switch(err) {
		case ENOENT:
			fprintf(stderr,"Connector module not loaded? Try 'modprobe cn'.\n");
			break;
		case EPERM:
			fprintf(stderr,"Missing privileges? You should run this as root.\n");
			break;
		}
		return -1;
	}

	return sk_nl;
}


static void prepare_nl_header(struct nlmsghdr* nl_hdr, int size)
{
	static uint32_t cn_seq = 1;
	struct cn_msg *cn_hdr;
	cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);

	/* fill the netlink header */
	nl_hdr->nlmsg_len = NLMSG_LENGTH(size - sizeof(struct nlmsghdr));
	nl_hdr->nlmsg_type = NLMSG_DONE;
	nl_hdr->nlmsg_flags = 0;
	nl_hdr->nlmsg_seq = cn_seq;
	nl_hdr->nlmsg_pid = getpid();
	/* fill the connector header */
	cn_hdr->id.val = CN_VAL_DRBD;
	cn_hdr->id.idx = cn_idx;
	cn_hdr->seq = cn_seq++;
	cn_hdr->ack = getpid();
	cn_hdr->len = size - sizeof(struct nlmsghdr) - sizeof(struct cn_msg);
}


static int send_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size)
{
	int rr;

	prepare_nl_header(nl_hdr,size);

	rr = send(sk_nl,nl_hdr,nl_hdr->nlmsg_len,0);
	if( rr != (ssize_t)nl_hdr->nlmsg_len) {
		perror("send() failed");
		return -1;
	}
	return rr;
}

static int receive_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size, int timeout_ms)
{
	struct pollfd pfd;
	int rr;

	pfd.fd = sk_nl;
	pfd.events = POLLIN;

	rr = poll(&pfd,1,timeout_ms);
	if(rr == 0) return -2; // timeout expired.

	rr = recv(sk_nl,nl_hdr,size,0);

	if( rr < 0 ) {
		perror("recv() failed");
		return -1;
	}
	return rr;
}

int receive_reply_cn(int sk_nl, struct drbd_tag_list *tl, struct nlmsghdr* nl_hdr,
		     int size, int timeout_ms)
{
	struct cn_msg *request_cn_hdr;
	struct cn_msg *reply_cn_hdr;
	int rr;

	request_cn_hdr = (struct cn_msg *)NLMSG_DATA(tl->nl_header);
	reply_cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);

	while(1) {
		rr = receive_cn(sk_nl,nl_hdr,size,timeout_ms);
		if( rr < 0 ) return rr;
		if(reply_cn_hdr->seq == request_cn_hdr->seq &&
		   reply_cn_hdr->ack == request_cn_hdr->ack+1 ) return rr;
		/* printf("INFO: got other message \n"
		   "got seq: %d ; ack %d \n"
		   "exp seq: %d ; ack %d \n",
		   reply_cn_hdr->seq,reply_cn_hdr->ack,
		   request_cn_hdr->seq,request_cn_hdr->ack); */
	}

	return rr;
}

static int call_drbd(int sk_nl, struct drbd_tag_list *tl, struct nlmsghdr* nl_hdr,
		     int size, int timeout_ms)
{
	int rr;
	prepare_nl_header(tl->nl_header, (char*)tl->tag_list_cpos -
			  (char*)tl->nl_header);

	rr = send(sk_nl,tl->nl_header,tl->nl_header->nlmsg_len,0);
	if( rr != (ssize_t)tl->nl_header->nlmsg_len) {
		perror("send() failed");
		return -1;
	}

	rr = receive_reply_cn(sk_nl,tl,nl_hdr,size,timeout_ms);

	if( rr == -2) {
		fprintf(stderr,"No response from the DRBD driver!"
			" Is the module loaded?\n");
	}
	return rr;
}

static void close_cn(int sk_nl)
{
	close(sk_nl);
}

static int is_drbd_driver_missing(void)
{
	struct stat sb;
	FILE *cn_idx_file;
	int err;

	cn_idx = CN_IDX_DRBD;
	cn_idx_file = fopen("/sys/module/drbd/parameters/cn_idx", "r");
	if (cn_idx_file) {
		unsigned int idx; /* gcc is picky */
		if (fscanf(cn_idx_file, "%u", &idx))
			cn_idx = idx;
		fclose(cn_idx_file);
	}

	err = stat("/proc/drbd", &sb);
	if (!err)
		return 0;

	if (err == ENOENT)
		fprintf(stderr, "DRBD driver appears to be missing\n");
	else
		fprintf(stderr, "Could not stat(\"/proc/drbd\"): %m\n");

	return 1;
}

int main(int argc, char** argv)
{
	unsigned minor;
	struct drbd_cmd *cmd;
	int rv=0;

	if (chdir("/")) {
		/* highly unlikely, but gcc is picky */
		perror("cannot chdir /");
		return -111;
	}

	cmdname = strrchr(argv[0],'/');
	if (cmdname)
		argv[0] = ++cmdname;
	else
		cmdname = argv[0];

	/* == '-' catches -h, --help, and similar */
	if (argc > 1 && (!strcmp(argv[1],"help") || argv[1][0] == '-')) {
		if(argc >= 3) {
			cmd=find_cmd_by_name(argv[2]);
			if(cmd) print_command_usage(cmd-commands,NULL,FULL);
			else print_usage("unknown command");
			exit(0);
		}
	}

	/* it is enough to set it, value is ignored */
	if (getenv("DRBD_DEBUG_DUMP_ARGV"))
		debug_dump_argv = 1;
	resname = getenv("DRBD_RESOURCE");

	if (argc > 1 && (!strcmp(argv[1],"xml"))) {
		if(argc >= 3) {
			cmd=find_cmd_by_name(argv[2]);
			if(cmd) print_command_usage(cmd-commands,NULL,XML);
			else print_usage("unknown command");
			exit(0);
		}
	}

	if (argc < 3) print_usage(argc==1 ? 0 : " Insufficient arguments");

	cmd=find_cmd_by_name(argv[2]);

	if (is_drbd_driver_missing()) {
		if (!strcmp(argv[2], "down") ||
		    !strcmp(argv[2], "secondary") ||
		    !strcmp(argv[2], "disconnect") ||
		    !strcmp(argv[2], "detach"))
			return 0; /* "down" succeeds even if drbd is missing */

		fprintf(stderr, "do you need to load the module?\n"
				"try: modprobe drbd\n");
		return 20;
	}

	if(cmd) {
		lock_fd = dt_lock_drbd(argv[1]);
		minor=dt_minor_of_dev(argv[1]);
		/* maybe rather canonicalize, using asprintf? */
		devname = argv[1];
		// by passing argc-2, argv+2 the function has the command name
		// in argv[0], e.g. "syncer"
		rv = cmd->function(cmd,minor,argc-2,argv+2);
		dt_unlock_drbd(lock_fd);
	} else {
		print_usage("invalid command");
	}

	return rv;
}
