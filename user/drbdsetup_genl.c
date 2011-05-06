/*
 * DRBD setup via genetlink
 *
 * This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
 *
 * Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
 * Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
 * Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.
 *
 * drbd is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * drbd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with drbd; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>

#include <linux/netlink.h>
#include <linux/genetlink.h>



#define EXIT_NOMEM 20
#define EXIT_NO_FAMILY 20
#define EXIT_SEND_ERR 20
#define EXIT_RECV_ERR 20
#define EXIT_TIMED_OUT 20
#define EXIT_NOSOCK 30
#define EXIT_THINKO 42

/*
 * We are not using libnl,
 * using its API for the few things we want to do
 * ends up being almost as much lines of code as
 * coding the necessary bits right here.
 */

#include "libgenl.h"
#include <linux/drbd_config.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd_limits.h>
#include <linux/genl_magic_func.h>
#include "drbdtool_common.h"
#include "registry.h"

/* for parsing of messages */
static struct nlattr *global_attrs[128];
/* there is an other table, nested_attr_tb, defined in genl_magic_func.h,
 * which can be used after <struct>_from_attrs,
 * to check for presence of struct fields. */
#define ntb(t)	nested_attr_tb[__nla_type(t)]

#ifdef PRINT_NLMSG_LEN
/* I'm to lazy to check the maximum possible nlmsg length by hand */
int main(void)
{
	static __u16 nla_attr_minlen[NLA_TYPE_MAX+1] __read_mostly = {
		[NLA_U8]        = sizeof(__u8),
		[NLA_U16]       = sizeof(__u16),
		[NLA_U32]       = sizeof(__u32),
		[NLA_U64]       = sizeof(__u64),
		[NLA_NESTED]    = NLA_HDRLEN,
	};
	int i;
	int sum_total = 0;
#define LEN__(policy) do {					\
	int sum = 0;						\
	for (i = 0; i < ARRAY_SIZE(policy); i++) {		\
		sum += nla_total_size(policy[i].len ?:		\
			nla_attr_minlen[policy[i].type]);	\
								\
	}							\
	sum += 4;						\
	sum_total += sum;					\
	printf("%-30s %4u [%4u]\n",				\
			#policy ":", sum, sum_total);		\
} while (0)
#define LEN_(p) LEN__(p ## _nl_policy)
	LEN_(disk_conf);
	LEN_(syncer_conf);
	LEN_(net_conf);
	LEN_(set_role_parms);
	LEN_(resize_parms);
	LEN_(state_info);
	LEN_(start_ov_parms);
	LEN_(new_c_uuid_parms);
	sum_total += sizeof(struct nlmsghdr) + sizeof(struct genlmsghdr)
		+ sizeof(struct drbd_genlmsghdr);
	printf("sum total inclusive hdr overhead: %4u\n", sum_total);
	return 0;
}
#else

#ifndef AF_INET_SDP
#define AF_INET_SDP 27
#define PF_INET_SDP AF_INET_SDP
#endif

/* pretty print helpers */
static int indent = 0;
#define INDENT_WIDTH	4
#define printI(fmt, args... ) printf("%*s" fmt,INDENT_WIDTH * indent,"" , ## args )

enum usage_type {
	BRIEF,
	FULL,
	XML,
};

struct drbd_argument {
	const char* name;
	__u16 nla_type;
	int (*convert_function)(struct drbd_argument *,
				struct msg_buff *,
				char *);
};

struct drbd_option {
	const char* name;
	const char short_name;
	__u16 nla_type;
	int (*convert_function)(struct drbd_option *,
				struct msg_buff *,
				char *);
	void (*show_function)(struct drbd_option *, struct nlattr *);
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
	bool optional_yesno_argument;
};

/* Configuration requests typically need a context to operate on.
 * Possible keys are device minor/volume id (both fit in the drbd_genlmsghdr),
 * the replication link (aka connection) name,
 * and/or the replication group (aka resource) name */
enum cfg_ctx_key {
	CTX_MINOR = 1,
	CTX_CONN = 2,
	CTX_ALL = 4,
};

struct drbd_cmd {
	const char* cmd;
	const enum cfg_ctx_key ctx_key;
	const int cmd_id;
	const int tla_id; /* top level attribute id */
	struct nla_policy *policy;
	int maxattr;
	int (*function)(struct drbd_cmd *, unsigned, int, char **);
	void (*usage)(struct drbd_cmd *, enum usage_type);
	union {
		struct {
			struct drbd_argument *args;
			struct drbd_option *options;
		} cp; // for generic_config_cmd, config_usage
	};
	int (*show_function)(struct drbd_cmd*, struct genl_info *);
	struct option *options;
	bool ignore_minor_not_known;
	bool continuous_poll;
	bool wait_for_connect_timeouts;
};

// other functions
static int get_af_ssocks(int warn);
static void print_command_usage(int i, const char *addinfo, enum usage_type);

// command functions
static int generic_config_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int down_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int generic_get_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int del_minor_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);
static int del_connection_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv);

// usage functions
static void config_usage(struct drbd_cmd *cm, enum usage_type);
static void get_usage(struct drbd_cmd *cm, enum usage_type);

// sub usage functions for config_usage
static int numeric_opt_usage(struct drbd_option *option, char* str, int strlen);
static int handler_opt_usage(struct drbd_option *option, char* str, int strlen);
static int flag_opt_usage(struct drbd_option *option, char* str, int strlen);
static int yesno_opt_usage(struct drbd_option *option, char* str, int strlen);
static int string_opt_usage(struct drbd_option *option, char* str, int strlen);
static int protocol_opt_usage(struct drbd_option *option, char* str, int strlen);

// sub usage function for config_usage as xml
static void numeric_opt_xml(struct drbd_option *option);
static void handler_opt_xml(struct drbd_option *option);
static void flag_opt_xml(struct drbd_option *option);
static void yesno_opt_xml(struct drbd_option *option);
static void string_opt_xml(struct drbd_option *option);
static void protocol_opt_xml(struct drbd_option *option);

// sub commands for generic_get_cmd
static int show_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int role_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int status_xml_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int sh_status_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int cstate_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int dstate_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int uuids_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int lk_bdev_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int print_broadcast_events(struct drbd_cmd *, struct genl_info *);
static int w_connected_state(struct drbd_cmd *, struct genl_info *);
static int w_synced_state(struct drbd_cmd *, struct genl_info *);

// convert functions for arguments
static int conv_block_dev(struct drbd_argument *ad, struct msg_buff *msg, char* arg);
static int conv_md_idx(struct drbd_argument *ad, struct msg_buff *msg, char* arg);
static int conv_address(struct drbd_argument *ad, struct msg_buff *msg, char* arg);
static int conv_conn_name(struct drbd_argument *ad, struct msg_buff *msg, char* arg);
static int conv_volume(struct drbd_argument *ad, struct msg_buff *msg, char* arg);

// convert functions for options
static int conv_numeric(struct drbd_option *od, struct msg_buff *msg, char* arg);
static int conv_handler(struct drbd_option *od, struct msg_buff *msg, char* arg);
static int conv_flag(struct drbd_option *od, struct msg_buff *msg, char* arg);
static int conv_yesno(struct drbd_option *od, struct msg_buff *msg, char* arg);
static int conv_string(struct drbd_option *od, struct msg_buff *msg, char* arg);
static int conv_protocol(struct drbd_option *od, struct msg_buff *msg, char* arg);

// show functions for options (used by show_scmd)
static void show_numeric(struct drbd_option *od, struct nlattr *nla);
static void show_handler(struct drbd_option *od, struct nlattr *nla);
static void show_flag(struct drbd_option *od, struct nlattr *nla);
static void show_yesno(struct drbd_option *od, struct nlattr *nla);
static void show_string(struct drbd_option *od, struct nlattr *nla);
static void show_protocol(struct drbd_option *od, struct nlattr *nla);

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
#define EH(N,D) \
	conv_handler, show_handler, handler_opt_usage, handler_opt_xml, \
	{ .handler_param = { N, ARRAY_SIZE(N), \
	DRBD_ ## D ## _DEF } }
#define EFLAG \
	conv_flag, show_flag, flag_opt_usage, flag_opt_xml, \
	.optional_yesno_argument = true
#define EYN(D) \
	conv_yesno, show_yesno, yesno_opt_usage, yesno_opt_xml, \
	{ .numeric_param = { .def = DRBD_ ## D ## _DEF } }, \
	.optional_yesno_argument = true
#define ES      conv_string, show_string, string_opt_usage, string_opt_xml, { }
#define CLOSE_ARGS_OPTS  { .name = NULL, }

#define F_CONFIG_CMD	generic_config_cmd, config_usage
#define NO_PAYLOAD	0, NULL, 0
#define F_GET_CMD(scmd)	DRBD_ADM_GET_STATUS, NO_PAYLOAD, generic_get_cmd, \
			get_usage, .show_function = scmd
#define POLICY(x)	x ## _nl_policy, (ARRAY_SIZE(x ## _nl_policy) -1)

#define CHANGEABLE_DISK_OPTIONS						\
	{ "on-io-error",'E',	T_on_io_error,	EH(on_error,ON_IO_ERROR) }, \
	{ "fencing",'f',	T_fencing,      EH(fencing_n,FENCING) }, \
	{ "disk-barrier",'B', T_disk_barrier, EYN(DISK_BARRIER) },			\
	{ "disk-flushes",'F', T_disk_flushes, EYN(DISK_FLUSHES) },			\
	{ "disk-drain",'D', T_disk_drain, EYN(DISK_DRAIN) },			\
	{ "md-flushes",'M', T_md_flushes,  EYN(MD_FLUSHES) },			\
	{ "resync-rate",'t',   T_resync_rate,	EN(RATE,'k',"bytes/second") }, \
	{ "resync-after",'a',  T_resync_after,	EN(AFTER,1,NULL) },	\
	{ "al-extents",'e',    T_al_extents,	EN(AL_EXTENTS,1,NULL) }, \
	{ "c-plan-ahead", 'p', T_c_plan_ahead, EN(C_PLAN_AHEAD,1,"1/10 seconds") }, \
	{ "c-delay-target", 'd',T_c_delay_target, EN(C_DELAY_TARGET,1,"1/10 seconds") }, \
	{ "c-fill-target", 's',T_c_fill_target, EN(C_FILL_TARGET,'s',"bytes") }, \
	{ "c-max-rate", 'R',	T_c_max_rate, EN(C_MAX_RATE,'k',"bytes/second") }, \
	{ "c-min-rate", 'r',	T_c_min_rate, EN(C_MIN_RATE,'k',"bytes/second") },

#define CHANGEABLE_NET_OPTIONS						\
	{ "protocol",'p',	T_wire_protocol, \
		conv_protocol, show_protocol, protocol_opt_usage, protocol_opt_xml, }, \
	{ "timeout",'t',	T_timeout,	EN(TIMEOUT,1,"1/10 seconds") }, \
	{ "max-epoch-size",'e',T_max_epoch_size,EN(MAX_EPOCH_SIZE,1,NULL) }, \
	{ "max-buffers",'b',	T_max_buffers,	EN(MAX_BUFFERS,1,NULL) }, \
	{ "unplug-watermark",'u',T_unplug_watermark, EN(UNPLUG_WATERMARK,1,NULL) }, \
	{ "connect-int",'c',	T_try_connect_int, EN(CONNECT_INT,1,"seconds") }, \
	{ "ping-int",'i',	T_ping_int,	   EN(PING_INT,1,"seconds") }, \
	{ "sndbuf-size",'s',	T_sndbuf_size,	   EN(SNDBUF_SIZE,1,"bytes") }, \
	{ "rcvbuf-size",'r',	T_rcvbuf_size,	   EN(RCVBUF_SIZE,1,"bytes") }, \
	{ "ko-count",'k',	T_ko_count,	   EN(KO_COUNT,1,NULL) }, \
	{ "allow-two-primaries",'m',T_two_primaries, EYN(ALLOW_TWO_PRIMARIES) }, \
	{ "cram-hmac-alg",'a',	T_cram_hmac_alg,   ES },		\
	{ "shared-secret",'x',	T_shared_secret,   ES },		\
	{ "after-sb-0pri",'0',	T_after_sb_0p,EH(asb0p_n,AFTER_SB_0P) }, \
	{ "after-sb-1pri",'1',	T_after_sb_1p,EH(asb1p_n,AFTER_SB_1P) }, \
	{ "after-sb-2pri",'2',	T_after_sb_2p,EH(asb2p_n,AFTER_SB_2P) }, \
	{ "always-asbp",'P',   T_always_asbp,     EYN(ALWAYS_ASBP) }, \
	{ "rr-conflict",'R',	T_rr_conflict,EH(rrcf_n,RR_CONFLICT) }, \
	{ "ping-timeout",'T',  T_ping_timeo,	   EN(PING_TIMEO,1,"1/10 seconds") }, \
	{ "data-integrity-alg",'d', T_integrity_alg,     ES },		\
	{ "tcp-cork",'o',   T_tcp_cork, EYN(TCP_CORK) }, \
	{ "on-congestion", 'g', T_on_congestion, EH(on_congestion_n,ON_CONGESTION) }, \
	{ "congestion-fill", 'f', T_cong_fill,    EN(CONG_FILL,'s',"byte") }, \
	{ "congestion-extents", 'h', T_cong_extents, EN(CONG_EXTENTS,1,NULL) }, \
	{ "csums-alg", 'C',T_csums_alg,        ES },			\
	{ "verify-alg", 'V',T_verify_alg,      ES },			\
	{ "use-rle",'E',T_use_rle,   EYN(USE_RLE) },

struct drbd_cmd commands[] = {
	{"primary", CTX_MINOR, DRBD_ADM_PRIMARY, DRBD_NLA_SET_ROLE_PARMS, POLICY(set_role_parms),
		F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "force", 'f',	     T_assume_uptodate, EFLAG   },
		 CLOSE_ARGS_OPTS }} }, },

	{"secondary", CTX_MINOR, DRBD_ADM_SECONDARY, NO_PAYLOAD, F_CONFIG_CMD, {{NULL, NULL}} },

	{"attach", CTX_MINOR, DRBD_ADM_ATTACH, DRBD_NLA_DISK_CONF, POLICY(disk_conf),
		F_CONFIG_CMD, {{
	 (struct drbd_argument[]) {
		 { "lower_dev",		T_backing_dev,	conv_block_dev },
		 { "meta_data_dev",	T_meta_dev,	conv_block_dev },
		 { "meta_data_index",	T_meta_dev_idx,	conv_md_idx },
		 CLOSE_ARGS_OPTS },
	 (struct drbd_option[]) {
		 { "size",'S',		T_disk_size,	EN(DISK_SIZE_SECT,'s',"bytes") },
		 { "max-bio-bvecs",'v',	T_max_bio_bvecs,EN(MAX_BIO_BVECS,1,NULL) },
		 CHANGEABLE_DISK_OPTIONS
		 CLOSE_ARGS_OPTS } }} },

	{"disk-options", CTX_MINOR, DRBD_ADM_CHG_DISK_OPTS, DRBD_NLA_DISK_CONF, POLICY(disk_conf),
		F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 CHANGEABLE_DISK_OPTIONS
		 CLOSE_ARGS_OPTS } }} },

	{"detach", CTX_MINOR, DRBD_ADM_DETACH, NO_PAYLOAD, F_CONFIG_CMD, {{ NULL, NULL }} },

	{"connect", CTX_CONN, DRBD_ADM_CONNECT, DRBD_NLA_NET_CONF, POLICY(net_conf),
		F_CONFIG_CMD, {{
	 (struct drbd_argument[]) {
		 { "[af:]local_addr[:port]",T_my_addr,	conv_address },
		 { "[af:]remote_addr[:port]",T_peer_addr,conv_address },
		 CLOSE_ARGS_OPTS },
	 (struct drbd_option[]) {
		 { "dry-run",'n',   T_dry_run,		   EFLAG },
		 { "discard-my-data",'D', T_want_lose,     EFLAG },
		 CHANGEABLE_NET_OPTIONS
		 CLOSE_ARGS_OPTS } }} },

	{"net-options", CTX_CONN, DRBD_ADM_CHG_NET_OPTS, DRBD_NLA_NET_CONF, POLICY(net_conf),
		F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 CHANGEABLE_NET_OPTIONS
		 CLOSE_ARGS_OPTS } }} },

	{"disconnect", CTX_CONN, DRBD_ADM_DISCONNECT, DRBD_NLA_DISCONNECT_PARMS, POLICY(disconnect_parms),
		F_CONFIG_CMD, {{NULL,
	 (struct drbd_option[]) {
		 { "force", 'F',	T_force_disconnect,	EFLAG },
		 CLOSE_ARGS_OPTS } }} },

	{"resize", CTX_MINOR, DRBD_ADM_RESIZE, DRBD_NLA_RESIZE_PARMS, POLICY(resize_parms),
		F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "size",'s',T_resize_size,		EN(DISK_SIZE_SECT,'s',"bytes") },
		 { "assume-peer-has-space",'f',T_resize_force,	EFLAG },
		 { "assume-clean", 'c',        T_no_resync, EFLAG },
		 CLOSE_ARGS_OPTS }} }, },

	{"resource-options", CTX_CONN, DRBD_ADM_RESOURCE_OPTS, DRBD_NLA_RESOURCE_OPTS, POLICY(res_opts),
		F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "cpu-mask",'c',T_cpu_mask,           ES },
		 { "on-no-data-accessible",'n',	T_on_no_data, EH(on_no_data_n,ON_NO_DATA) },
		 CLOSE_ARGS_OPTS } }} },

	{"new-current-uuid", CTX_MINOR, DRBD_ADM_NEW_C_UUID, DRBD_NLA_NEW_C_UUID_PARMS, POLICY(new_c_uuid_parms),
		F_CONFIG_CMD, {{NULL,
	 (struct drbd_option[]) {
		 { "clear-bitmap",'c',T_clear_bm, EFLAG   },
		 CLOSE_ARGS_OPTS }} }, },

	{"invalidate", CTX_MINOR, DRBD_ADM_INVALIDATE, NO_PAYLOAD, F_CONFIG_CMD, },
	{"invalidate-remote", CTX_MINOR, DRBD_ADM_INVAL_PEER, NO_PAYLOAD, F_CONFIG_CMD, },
	{"pause-sync", CTX_MINOR, DRBD_ADM_PAUSE_SYNC, NO_PAYLOAD, F_CONFIG_CMD, },
	{"resume-sync", CTX_MINOR, DRBD_ADM_RESUME_SYNC, NO_PAYLOAD, F_CONFIG_CMD, },
	{"suspend-io", CTX_MINOR, DRBD_ADM_SUSPEND_IO, NO_PAYLOAD, F_CONFIG_CMD, },
	{"resume-io", CTX_MINOR, DRBD_ADM_RESUME_IO, NO_PAYLOAD, F_CONFIG_CMD, },
	{"outdate", CTX_MINOR, DRBD_ADM_OUTDATE, NO_PAYLOAD, F_CONFIG_CMD, },
	{"verify", CTX_MINOR, DRBD_ADM_START_OV, DRBD_NLA_START_OV_PARMS, POLICY(start_ov_parms),
		F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "start",'s',T_ov_start_sector, EN(DISK_SIZE_SECT,'s',"bytes") },
		 CLOSE_ARGS_OPTS }} }, },
	{"down", CTX_CONN, DRBD_ADM_DOWN, NO_PAYLOAD, down_cmd, get_usage, },
	/* "state" is deprecated! please use "role".
	 * find_cmd_by_name still understands "state", however. */
	{"role", CTX_MINOR, F_GET_CMD(role_scmd) },
	{"status", CTX_MINOR, F_GET_CMD(status_xml_scmd),
		.ignore_minor_not_known = true, },
	{"sh-status", CTX_MINOR, F_GET_CMD(sh_status_scmd),
		.ignore_minor_not_known = true, },
	{"cstate", CTX_MINOR, F_GET_CMD(cstate_scmd) },
	{"dstate", CTX_MINOR, F_GET_CMD(dstate_scmd) },
	{"show-gi", CTX_MINOR, F_GET_CMD(uuids_scmd) },
	{"get-gi", CTX_MINOR, F_GET_CMD(uuids_scmd) },
	{"show", CTX_MINOR | CTX_CONN | CTX_ALL, F_GET_CMD(show_scmd) },
	{"check-resize", CTX_MINOR, F_GET_CMD(lk_bdev_scmd) },
	{"events", CTX_MINOR | CTX_ALL, F_GET_CMD(print_broadcast_events),
		.ignore_minor_not_known = true,
		.continuous_poll = true, },
	{"wait-connect", CTX_MINOR, F_GET_CMD(w_connected_state),
		.options = wait_cmds_options,
		.continuous_poll = true,
		.wait_for_connect_timeouts = true, },
	{"wait-sync", CTX_MINOR | CTX_ALL, F_GET_CMD(w_synced_state),
		.options = wait_cmds_options,
		.continuous_poll = true,
		.wait_for_connect_timeouts = true, },

	{"new-connection", CTX_CONN, DRBD_ADM_ADD_LINK, NO_PAYLOAD, F_CONFIG_CMD, },

	/* only payload is connection name and volume number */
	{"new-minor", CTX_MINOR, DRBD_ADM_ADD_MINOR, DRBD_NLA_CFG_CONTEXT, POLICY(drbd_cfg_context),
		F_CONFIG_CMD, {{
	 (struct drbd_argument[]) {
		 { "conn-name", T_ctx_conn_name, conv_conn_name },
		 { "volume-number", T_ctx_volume, conv_volume },
		 CLOSE_ARGS_OPTS }} }, },

	{"del-minor", CTX_MINOR, DRBD_ADM_DEL_MINOR, NO_PAYLOAD, del_minor_cmd, config_usage, },
	{"del-connection", CTX_CONN, DRBD_ADM_DEL_LINK, NO_PAYLOAD, del_connection_cmd, config_usage, }
};

bool wait_after_split_brain;

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
	EM(ERR_DISK_TO_SMALL) = "Low.dev. smaller than requested DRBD-dev. size.",
	EM(ERR_MD_DISK_TO_SMALL) = "Meta device too small.",
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
	EM(ERR_DISCARD) = "--discard-my-data not allowed when primary.",
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
	EM(ERR_CONN_NOT_KNOWN) = "Unknown connection",
	EM(ERR_CONN_IN_USE) = "Connection still in use (delete all minors first)",
	EM(ERR_MINOR_CONFIGURED) = "Minor still configured (down it first)",
	EM(ERR_MINOR_EXISTS) = "Minor exists already (delete it first)",
	EM(ERR_INVALID_REQUEST) = "Invalid configuration request",
	EM(ERR_NEED_APV_100) = "Prot version 100 required in order to online change\n"
	"between replication prot A, B or C",
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
/*
 * This is argv[1] as given on command line.
 * Connection name for CTX_CONN commands.
 * Device name for CTX_MINOR, for reporting in
 * print_config_error.
 */
char *objname = NULL;
/* for pretty printing in "status" only,
 * taken from environment variable DRBD_RESOURCE */
char *resname = NULL;
int debug_dump_argv = 0; /* enabled by setting DRBD_DEBUG_DUMP_ARGV in the environment */
int lock_fd;

struct nla_policy *current_policy = NULL;
struct genl_sock *drbd_sock = NULL;
int try_genl = 1;

struct genl_family drbd_genl_family = {
	.name = "drbd"
};

static int conv_block_dev(struct drbd_argument *ad, struct msg_buff *msg, char* arg)
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

	nla_put_string(msg, ad->nla_type, arg);

	return NO_ERROR;
}

static int conv_md_idx(struct drbd_argument *ad, struct msg_buff *msg, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = DRBD_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flexible")) idx = DRBD_MD_INDEX_FLEX_EXT;
	else idx = m_strtoll(arg,1);

	nla_put_u32(msg, ad->nla_type, idx);

	return NO_ERROR;
}

static int conv_conn_name(struct drbd_argument *ad, struct msg_buff *msg, char* arg)
{
	/* additional sanity checks? */
	nla_put_string(msg, T_ctx_conn_name, arg);
	return NO_ERROR;
}

static int conv_volume(struct drbd_argument *ad, struct msg_buff *msg, char* arg)
{
	unsigned vol = m_strtoll(arg,1);
	/* sanity check on vol < 256? */
	nla_put_u32(msg, T_ctx_volume, vol);
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
	for (i=0; i<ARRAY_SIZE(afs); i++) {
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

static int conv_address(struct drbd_argument *ad, struct msg_buff *msg, char* arg)
{
	struct sockaddr_in addr = { 0 };
	struct sockaddr_in6 addr6 = { 0 };
	int af, port;
	char *address;

	split_address(arg, &af, &address, &port);

	if (af == AF_INET6) {
		resolv6(address, &addr6);
		addr6.sin6_port = htons(port);
		/* addr6.sin6_len = sizeof(addr6); */
		nla_put(msg,ad->nla_type,sizeof(addr6),&addr6);
	} else {
		/* AF_INET, AF_SDP, AF_SSOCKS,
		 * all use the IPv4 addressing scheme */
		addr.sin_port = htons(port);
		addr.sin_family = af;
		addr.sin_addr.s_addr = resolv(address);
		nla_put(msg,ad->nla_type,sizeof(addr),&addr);
	}

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

static int conv_numeric(struct drbd_option *od, struct msg_buff *msg, char* arg)
{
	const long long min = od->numeric_param.min;
	const long long max = od->numeric_param.max;
	const unsigned char unit_prefix = od->numeric_param.unit_prefix;
	long long l;
	char unit[] = {0,0};

	l = m_strtoll(arg, unit_prefix);

	if (min > l || l > max) {
		unit[0] = unit_prefix > 1 ? unit_prefix : 0;
		fprintf(stderr,"%s %s => %llu%s out of range [%llu..%llu]%s\n",
			od->name, arg, l, unit, min, max, unit);
		return OTHER_ERROR;
	}

	switch(current_policy[__nla_type(od->nla_type)].type) {
	case NLA_U8:
		nla_put_u8(msg,od->nla_type,l);
		break;
	case NLA_U16:
		nla_put_u16(msg,od->nla_type,l);
		break;
	case NLA_U32:
		nla_put_u32(msg,od->nla_type,l);
		break;
	case NLA_U64:
		nla_put_u64(msg,od->nla_type,l);
		break;
	default:
		fprintf(stderr, "internal error in conv_numeric()\n");
	}
	return NO_ERROR;
}

static int conv_protocol(struct drbd_option *od, struct msg_buff *msg, char* arg)
{
	int proto = 0; /* initialize to an invalid protocol value */
	if (arg && arg[0] && arg[1] == 0) {
		switch(arg[0]) {
		case 'A': case 'a': proto = DRBD_PROT_A; break;
		case 'B': case 'b': proto = DRBD_PROT_B; break;
		case 'C': case 'c': proto = DRBD_PROT_C; break;
		default: /* nothing */;
		};
	};
	if (proto) {
		nla_put_u32(msg, od->nla_type, proto);
		return NO_ERROR;
	}
	/* not a valid protocol value */
	fprintf(stderr, "Invalid protocol '%s'. Known protocols: A,B,C\n", arg);
	return OTHER_ERROR;
}

static int conv_handler(struct drbd_option *od, struct msg_buff *msg, char* arg)
{
	const char** handler_names = od->handler_param.handler_names;
	const int number_of_handlers = od->handler_param.number_of_handlers;
	int i;

	for(i=0;i<number_of_handlers;i++) {
		if(handler_names[i]==NULL) continue;
		if(strcmp(arg,handler_names[i])==0) {
			nla_put_u32(msg,od->nla_type,i);
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

static bool eval_optional_yesno_arg(const char *name, const char *arg,
				    bool *flag)
{
	if (arg) {
		if (!strcmp(arg, "yes"))
			*flag = true;
		else if (!strcmp(arg, "no"))
			*flag = false;
		else {
			fprintf(stderr, "Invalid argument '%s' for option --%s. "
				"Allowed values: yes, no\n", arg, name);
			return false;
		}
	} else
		*flag = true;
	return true;
}

static int conv_flag(struct drbd_option *od, struct msg_buff *msg, char *arg)
{
	bool flag;
	if (!eval_optional_yesno_arg(od->name, arg, &flag))
		return OTHER_ERROR;
	if (flag)
		nla_put_u8(msg, od->nla_type, flag);
	return NO_ERROR;
}

static int conv_yesno(struct drbd_option *od, struct msg_buff *msg, char *arg)
{
	bool flag;
	if (!eval_optional_yesno_arg(od->name, arg, &flag))
		return OTHER_ERROR;
	nla_put_u8(msg, od->nla_type, flag);
	return NO_ERROR;
}

static int conv_string(struct drbd_option *od, struct msg_buff *msg, char* arg)
{
	nla_put_string(msg,od->nla_type,arg);
	return NO_ERROR;
}

static struct option *make_longoptions(struct drbd_option* od, struct nla_policy *policy)
{
	/* room for up to N options,
	 * plus set-defaults, and the terminating NULL */
#define N 40
	static struct option buffer[N+2];
	int i=0;

	while(od && od->name) {
		buffer[i].name = od->name;
		buffer[i].has_arg =
			od->optional_yesno_argument ? optional_argument :
			policy[__nla_type(od->nla_type)].type == NLA_FLAG ?
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

/* prepends global objname to output (if any) */
static int print_config_error(int err_no, char *desc)
{
	int rv=0;

	if (err_no == NO_ERROR || err_no == SS_SUCCESS)
		return 0;

	if (err_no == OTHER_ERROR) {
		if (desc)
			fprintf(stderr,"%s: %s\n", objname, desc);
		return 20;
	}

	if ( ( err_no >= AFTER_LAST_ERR_CODE || err_no <= ERR_CODE_BASE ) &&
	     ( err_no > SS_CW_NO_NEED || err_no <= SS_AFTER_LAST_ERROR) ) {
		fprintf(stderr,"%s: Error code %d unknown.\n"
			"You should update the drbd userland tools.\n",
			objname, err_no);
		rv = 20;
	} else {
		if(err_no > ERR_CODE_BASE ) {
			fprintf(stderr,"%s: Failure: (%d) %s\n",
				objname, err_no, desc ?: error_to_string(err_no));
			rv = 10;
		} else if (err_no == SS_UNKNOWN_ERROR) {
			fprintf(stderr,"%s: State change failed: (%d)"
				"unknown error.\n", objname, err_no);
			rv = 11;
		} else if (err_no > SS_TWO_PRIMARIES) {
			// Ignore SS_SUCCESS, SS_NOTHING_TO_DO, SS_CW_Success...
		} else {
			fprintf(stderr,"%s: State change failed: (%d) %s\n",
				objname, err_no, drbd_set_st_err_str(err_no));
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
	if (global_attrs[DRBD_NLA_CFG_REPLY] &&
	    global_attrs[DRBD_NLA_CFG_REPLY]->nla_len) {
		struct nlattr *nla;
		int rem;
		fprintf(stderr, "additional info from kernel:\n");
		nla_for_each_nested(nla, global_attrs[DRBD_NLA_CFG_REPLY], rem) {
			if (nla_type(nla) == __nla_type(T_info_text))
				fprintf(stderr, "%s\n", (char*)nla_data(nla));
		}
	}
	return rv;
}

static void warn_print_excess_args(int argc, char **argv, int i)
{
	fprintf(stderr, "Excess arguments:");
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

int drbd_tla_parse(struct nlmsghdr *nlh)
{
	return nla_parse(global_attrs, ARRAY_SIZE(drbd_tla_nl_policy)-1,
		nlmsg_attrdata(nlh, GENL_HDRLEN + drbd_genl_family.hdrsize),
		nlmsg_attrlen(nlh, GENL_HDRLEN + drbd_genl_family.hdrsize),
		drbd_tla_nl_policy);
}

#define ASSERT(exp) if (!(exp)) \
		fprintf(stderr,"ASSERT( " #exp " ) in %s:%d\n", __FILE__,__LINE__);

static int _generic_config_cmd(struct drbd_cmd *cm, unsigned minor, int argc,
			       char **argv, int quiet)
{
	struct drbd_argument *ad = cm->cp.args;
	struct nlattr *nla = NULL;
	struct drbd_option *od;
	struct option *lo;
	int c, i = 1;
	int n_args;
	int rv = NO_ERROR;
	char *desc = NULL; /* error description from kernel reply message */
	const char *opts;

	struct drbd_genlmsghdr *dhdr;
	struct msg_buff *smsg;
	struct iovec iov;

	/* pre allocate request message and reply buffer */
	iov.iov_len = DEFAULT_MSG_SIZE;
	iov.iov_base = malloc(iov.iov_len);
	smsg = msg_new(DEFAULT_MSG_SIZE);
	if (!smsg || !iov.iov_base) {
		desc = "could not allocate netlink messages";
		rv = OTHER_ERROR;
		goto error;
	}

	dhdr = genlmsg_put(smsg, &drbd_genl_family, 0, cm->cmd_id);
	dhdr->minor = minor;
	dhdr->flags = 0;

	if (cm->ctx_key & CTX_CONN) {
		/* we just allocated 8k,
		 * and now we put a few bytes there.
		 * this cannot possibly fail, can it? */
		nla = nla_nest_start(smsg, DRBD_NLA_CFG_CONTEXT);
		nla_put_string(smsg, T_ctx_conn_name, objname);
		nla_nest_end(smsg, nla);
	}

	current_policy = cm->policy;
	if (cm->tla_id)
		nla = nla_nest_start(smsg, cm->tla_id);

	while (ad && ad->name) {
		if (argc < i + 1) {
			fprintf(stderr, "Missing argument '%s'\n", ad->name);
			print_command_usage(cm - commands, "", FULL);
			rv = OTHER_ERROR;
			goto error;
		}
		rv = ad->convert_function(ad, smsg, argv[i++]);
		if (rv != NO_ERROR)
			goto error;
		ad++;
	}
	n_args = i - 1;

	lo = make_longoptions(cm->cp.options, cm->policy);
	opts = make_optstring(lo, 0);
	while ((c = getopt_long(argc, argv, opts, lo, 0)) != -1) {
		od = find_opt_by_short_name(cm->cp.options, c);
		if (od)
			rv = od->convert_function(od, smsg, optarg);
		else {
			if (c == '(')
				dhdr->flags |= DRBD_GENL_F_SET_DEFAULTS;
			else if (c == ')')
				/* Used to be DRBD_GENL_F_CREATE_DEVICE.
				 * Ignore. */;
			else {
				rv = OTHER_ERROR;
				goto error;
			}
		}
		if (rv != NO_ERROR)
			goto error;
	}

	/* argc should be cmd + n options + n args;
	 * if it is more, we did not understand some */
	if (n_args + optind < argc) {
		warn_print_excess_args(argc, argv, optind + n_args);
		rv = OTHER_ERROR;
		goto error;
	}

	dump_argv(argc, argv, optind, i - 1);

	if (rv == NO_ERROR) {
		int received;

		if (nla)
			nla_nest_end(smsg, nla);
		if (genl_send(drbd_sock, smsg)) {
			desc = "error sending config command";
			rv = OTHER_ERROR;
			goto error;
		}

retry_recv:
		/* reduce timeout! limit retries */
		received = genl_recv_msgs(drbd_sock, &iov, &desc, 120000);
		if (received > 0) {
			struct nlmsghdr *nlh = (struct nlmsghdr*)iov.iov_base;
			struct drbd_genlmsghdr *dh = genlmsg_data(nlmsg_data(nlh));
			ASSERT(dh->minor == minor);
			rv = dh->ret_code;
			drbd_tla_parse(nlh);
		} else {
			if (received == -E_RCV_ERROR_REPLY && !errno)
					goto retry_recv;
			if (!desc)
				desc = "error receiving config reply";

			rv = OTHER_ERROR;
		}
	}
error:
	msg_free(smsg);

	if (!quiet)
		rv = print_config_error(rv, desc);
	free(iov.iov_base);
	return rv;
}

static int generic_config_cmd(struct drbd_cmd *cm, unsigned minor, int argc,
			       char **argv)
{
	return _generic_config_cmd(cm, minor, argc, argv, 0);
}

static int del_minor_cmd(struct drbd_cmd *cm, unsigned minor, int argc,
			 char **argv)
{
	int rv;

	rv = generic_config_cmd(cm, minor, argc, argv);
	if (!rv)
		unregister_minor(minor);
	return rv;
}

static int del_connection_cmd(struct drbd_cmd *cm, unsigned minor, int argc,
			      char **argv)
{
	int rv;

	rv = generic_config_cmd(cm, minor, argc, argv);
	if (!rv)
		unregister_resource(objname);
	return rv;
}

static void show_numeric(struct drbd_option *od, struct nlattr *nla)
{
	long long val;
	const unsigned char unit_prefix = od->numeric_param.unit_prefix;

	switch(current_policy[nla_type(nla)].type) {
	case NLA_U8:
		val = (char)nla_get_u8(nla);
		break;
	case NLA_U16:
		val = (short)nla_get_u16(nla);
		break;
	case NLA_U32:
		val = (int)nla_get_u32(nla);
		break;
	case NLA_U64:
		val = nla_get_u64(nla);
		break;
	default:
		ASSERT(0);
		val=0;
	}

	if (unit_prefix == 1)
		printI("%-16s\t%lld", od->name, val);
	else
		printI("%-16s\t%lld%c", od->name, val, unit_prefix);
	if (val == od->numeric_param.def)
		printf(" _is_default");
	if (od->numeric_param.unit) {
		printf("; # %s\n", od->numeric_param.unit);
	} else {
		printf(";\n");
	}
}

static void show_protocol(struct drbd_option *od, struct nlattr *nla)
{
	int i = nla_get_u32(nla);
	printI("%-16s\t%c",od->name, '@' + i);
	if (i == DRBD_PROTOCOL_DEF)
		printf(" _is_default");
	printf(";\n");
}

static void show_handler(struct drbd_option *od, struct nlattr *nla)
{
	const char** handler_names = od->handler_param.handler_names;
	int i;

	i = nla_get_u32(nla);
	printI("%-16s\t%s",od->name,handler_names[i]);
	if (i == od->handler_param.def)
		printf(" _is_default");
	printf(";\n");
}

static void show_flag(struct drbd_option *od, struct nlattr *nla)
{
	bool val;

	/* FIXME: what do we do with this? */
	val = nla_get_u8(nla);
	if (val)
		printI("%-16s;\n", od->name);
}

static void show_yesno(struct drbd_option *od, struct nlattr *nla)
{
	bool val;

	val = nla_get_u8(nla);
	printI("%-16s\t%s", od->name, val ? "yes" : "no");
	if (!val == !od->numeric_param.def)
		printf(" _is_default");
	printf(";\n");
}

static void show_string(struct drbd_option *od, struct nlattr *nla)
{

	char *str = nla_data(nla);
	if (str[0])
		printI("%-16s\t\"%s\";\n",od->name,str);
}

static struct drbd_cmd *find_cmd_by_name(const char *name)
{
	unsigned int i;

	if (!strcmp(name, "state")) {
		fprintf(stderr, "'%s ... state' is deprecated, use '%s ... role' instead.\n",
			cmdname, cmdname);
		name = "role";
	}

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strcmp(name, commands[i].cmd)) {
			return commands + i;
		}
	}
	return NULL;
}

static void print_options(const char *cmd_name, const char *sect_name)
{
	struct drbd_cmd *cmd;
	struct drbd_option *od;
	int opened = 0;

	cmd = find_cmd_by_name(cmd_name);
	if (!cmd) {
		fprintf(stderr, "%s internal error, no such cmd %s\n",
				cmdname, cmd_name);
		abort();
	}
	if (!global_attrs[cmd->tla_id])
		return;
	if (nla_parse_nested(nested_attr_tb, cmd->maxattr, global_attrs[cmd->tla_id], cmd->policy)) {
		fprintf(stderr, "nla_policy violation for %s payload!\n", sect_name);
		/* still, print those that validated ok */
	}
	current_policy = cmd->policy; /* for show_numeric */

	for (od = cmd->cp.options; od && od->name; od++) {
		if (!ntb(od->nla_type))
			continue;
		if (!opened) {
			opened=1;
			printI("%s {\n",sect_name);
			++indent;
		}
		od->show_function(od, ntb(od->nla_type));
	}
	if(opened) {
		--indent;
		printI("}\n");
	}
}

struct choose_timo_ctx {
	unsigned minor;
	struct msg_buff *smsg;
	struct iovec *iov;
	int timeout;
	int wfc_timeout;
	int degr_wfc_timeout;
	int outdated_wfc_timeout;
};

int choose_timeout(struct choose_timo_ctx *ctx)
{
	char *desc = NULL;
	struct drbd_genlmsghdr *dhdr;
	int rr;

	if (0 < ctx->wfc_timeout &&
	      (ctx->wfc_timeout < ctx->degr_wfc_timeout || ctx->degr_wfc_timeout == 0)) {
		ctx->degr_wfc_timeout = ctx->wfc_timeout;
		fprintf(stderr, "degr-wfc-timeout has to be shorter than wfc-timeout\n"
				"degr-wfc-timeout implicitly set to wfc-timeout (%ds)\n",
				ctx->degr_wfc_timeout);
	}

	if (0 < ctx->degr_wfc_timeout &&
	    (ctx->degr_wfc_timeout < ctx->outdated_wfc_timeout || ctx->outdated_wfc_timeout == 0)) {
		ctx->outdated_wfc_timeout = ctx->wfc_timeout;
		fprintf(stderr, "outdated-wfc-timeout has to be shorter than degr-wfc-timeout\n"
				"outdated-wfc-timeout implicitly set to degr-wfc-timeout (%ds)\n",
				ctx->degr_wfc_timeout);
	}
	dhdr = genlmsg_put(ctx->smsg, &drbd_genl_family, 0, DRBD_ADM_GET_TIMEOUT_TYPE);
	dhdr->minor = ctx->minor;
	dhdr->flags = 0;

	if (genl_send(drbd_sock, ctx->smsg)) {
		desc = "error sending config command";
		goto error;
	}

	rr = genl_recv_msgs(drbd_sock, ctx->iov, &desc, 120000);
	if (rr > 0) {
		struct nlmsghdr *nlh = (struct nlmsghdr*)ctx->iov->iov_base;
		struct genl_info info = {
			.seq = nlh->nlmsg_seq,
			.nlhdr = nlh,
			.genlhdr = nlmsg_data(nlh),
			.userhdr = genlmsg_data(nlmsg_data(nlh)),
			.attrs = global_attrs,
		};
		struct drbd_genlmsghdr *dh = info.userhdr;
		struct timeout_parms parms;
		ASSERT(dh->minor == ctx->minor);
		rr = dh->ret_code;
		if (rr == ERR_MINOR_INVALID) {
			desc = "minor not available";
			goto error;
		}
		if (rr != NO_ERROR)
			goto error;
		if (drbd_tla_parse(nlh)
		|| timeout_parms_from_attrs(&parms, &info)) {
			desc = "reply did not validate - "
				"do you need to upgrade your useland tools?";
			goto error;
		}
		rr = parms.timeout_type;
		ctx->timeout =
			(rr == UT_DEGRADED) ? ctx->degr_wfc_timeout :
			(rr == UT_PEER_OUTDATED) ? ctx->outdated_wfc_timeout :
			ctx->wfc_timeout;
		return 0;
	}
error:
	if (!desc)
		desc = "error receiving netlink reply";
	fprintf(stderr, "error determining which timeout to use: %s\n",
			desc);
	return 20;
}

static int generic_get_cmd(struct drbd_cmd *cm, unsigned minor, int argc,
			   char **argv)
{
	char *desc = NULL;
	struct drbd_genlmsghdr *dhdr;
	struct msg_buff *smsg;
	struct iovec iov;
	struct choose_timo_ctx timeo_ctx = {
		.wfc_timeout = DRBD_WFC_TIMEOUT_DEF,
		.degr_wfc_timeout = DRBD_DEGR_WFC_TIMEOUT_DEF,
		.outdated_wfc_timeout = DRBD_OUTDATED_WFC_TIMEOUT_DEF,
	};
	int timeout_ms = -1;  /* "infinite" */
	int flags;
	int rv = NO_ERROR;
	int err = 0;

	/* pre allocate request message and reply buffer */
	iov.iov_len = 8192;
	iov.iov_base = malloc(iov.iov_len);
	smsg = msg_new(DEFAULT_MSG_SIZE);
	if (!smsg || !iov.iov_base) {
		desc = "could not allocate netlink messages";
		rv = OTHER_ERROR;
		goto out;
	}

	if (cm->options) {
		const char *opts = make_optstring(cm->options, 0);
		int c;

		while((c = getopt_long(argc, argv, opts, cm->options, 0)) != -1) {
			switch(c) {
			default:
			case '?':
				return 20;
			case 't':
				timeo_ctx.wfc_timeout = m_strtoll(optarg, 1);
				if(DRBD_WFC_TIMEOUT_MIN > timeo_ctx.wfc_timeout ||
				   timeo_ctx.wfc_timeout > DRBD_WFC_TIMEOUT_MAX) {
					fprintf(stderr, "wfc_timeout => %d"
						" out of range [%d..%d]\n",
						timeo_ctx.wfc_timeout,
						DRBD_WFC_TIMEOUT_MIN,
						DRBD_WFC_TIMEOUT_MAX);
					return 20;
				}
				break;
			case 'd':
				timeo_ctx.degr_wfc_timeout = m_strtoll(optarg, 1);
				if(DRBD_DEGR_WFC_TIMEOUT_MIN > timeo_ctx.degr_wfc_timeout ||
				   timeo_ctx.degr_wfc_timeout > DRBD_DEGR_WFC_TIMEOUT_MAX) {
					fprintf(stderr, "degr_wfc_timeout => %d"
						" out of range [%d..%d]\n",
						timeo_ctx.degr_wfc_timeout,
						DRBD_DEGR_WFC_TIMEOUT_MIN,
						DRBD_DEGR_WFC_TIMEOUT_MAX);
					return 20;
				}
				break;
			case 'o':
				timeo_ctx.outdated_wfc_timeout = m_strtoll(optarg, 1);
				if(DRBD_OUTDATED_WFC_TIMEOUT_MIN > timeo_ctx.outdated_wfc_timeout ||
				   timeo_ctx.outdated_wfc_timeout > DRBD_OUTDATED_WFC_TIMEOUT_MAX) {
					fprintf(stderr, "outdated_wfc_timeout => %d"
						" out of range [%d..%d]\n",
						timeo_ctx.outdated_wfc_timeout,
						DRBD_OUTDATED_WFC_TIMEOUT_MIN,
						DRBD_OUTDATED_WFC_TIMEOUT_MAX);
					return 20;
				}
				break;

			case 'w':
				wait_after_split_brain = true;
				break;
			}
		}
	}
	if (optind < argc) {
		warn_print_excess_args(argc, argv, optind);
		return 20;
	}

	dump_argv(argc, argv, optind, 0);

	/* otherwise we need to change handling/parsing
	 * of expected replies */
	ASSERT(cm->cmd_id == DRBD_ADM_GET_STATUS);

	if (cm->wait_for_connect_timeouts) {
		int rr;

		timeo_ctx.minor = minor;
		timeo_ctx.smsg = smsg;
		timeo_ctx.iov = &iov;
		rr = choose_timeout(&timeo_ctx);
		if (rr)
			return rr;
		if (timeo_ctx.timeout)
			timeout_ms = timeo_ctx.timeout * 1000;

		/* rewind send message buffer */
		smsg->tail = smsg->data;
	} else if (!cm->continuous_poll)
		timeout_ms = 120000;

	if (cm->continuous_poll) {
		if (genl_join_mc_group(drbd_sock, "events")) {
			fprintf(stderr, "unable to join drbd events multicast group\n");
			return 20;
		}
	}

	flags = 0;
	if (minor == -1U)
		flags |= NLM_F_DUMP;
	dhdr = genlmsg_put(smsg, &drbd_genl_family, flags, cm->cmd_id);
	dhdr->minor = minor;
	dhdr->flags = 0;
	if (minor == -1U && strcmp(objname, "ALL")) {
		/* Restrict the dump to a single resource. */
		struct nlattr *nla;
		nla = nla_nest_start(smsg, DRBD_NLA_CFG_CONTEXT);
		nla_put_string(smsg, T_ctx_conn_name, objname);
		nla_nest_end(smsg, nla);
	}

	if (genl_send(drbd_sock, smsg)) {
		desc = "error sending config command";
		rv = OTHER_ERROR;
		goto out2;
	}

	/* disable sequence number check in genl_recv_msgs */
	drbd_sock->s_seq_expect = 0;

	for (;;) {
		int received, rem;
		struct nlmsghdr *nlh = (struct nlmsghdr *)iov.iov_base;
		struct timeval before;

		if (timeout_ms != -1)
			gettimeofday(&before, NULL);

		received = genl_recv_msgs(drbd_sock, &iov, &desc, timeout_ms);
		if (received < 0) {
			switch(received) {
			case E_RCV_TIMEDOUT:
				err = 5;
				goto out2;
			case -E_RCV_FAILED:
				err = 20;
				goto out2;
			case -E_RCV_NO_SOURCE_ADDR:
				continue; /* ignore invalid message */
			case -E_RCV_SEQ_MISMATCH:
				/* we disabled it, so it should not happen */
				err = 20;
				goto out2;
			case -E_RCV_MSG_TRUNC:
				continue;
			case -E_RCV_UNEXPECTED_TYPE:
				continue;
			case -E_RCV_NLMSG_DONE:
				if (cm->continuous_poll)
					continue;
				err = cm->show_function(cm, NULL);
				if (err)
					goto out2;
				err = *(int*)nlmsg_data(nlh);
				if (err)
					printf("# error: %d: %s\n", err, strerror(-err));
				goto out2;
			case -E_RCV_ERROR_REPLY:
				if (!errno) /* positive ACK message */
					continue;
				if (!desc)
					desc = strerror(errno);
				fprintf(stderr, "received netlink error reply: %s\n",
					       desc);
				err = 20;
				goto out2;
			default:
				if (!desc)
					desc = "error receiving config reply";
				err = 20;
				goto out2;
			}
		}

		if (timeout_ms != -1) {
			struct timeval after;

			gettimeofday(&after, NULL);
			timeout_ms -= (after.tv_sec - before.tv_sec) * 1000 +
				      (after.tv_usec - before.tv_usec) / 1000;
			if (timeout_ms <= 0) {
				err = 5;
				goto out2;
			}
		}

		/* There may be multiple messages in one datagram (for dump replies). */
		nlmsg_for_each_msg(nlh, nlh, received, rem) {
			struct drbd_genlmsghdr *dh = genlmsg_data(nlmsg_data(nlh));
			struct genl_info info = (struct genl_info){
				.seq = nlh->nlmsg_seq,
				.nlhdr = nlh,
				.genlhdr = nlmsg_data(nlh),
				.userhdr = genlmsg_data(nlmsg_data(nlh)),
				.attrs = global_attrs,
			};
			if (cm->continuous_poll) {
				/*
				 * We will receive all events and have to
				 * filter for what we want ourself.
				 */
				if (minor != -1U) {
					if (minor != dh->minor)
						continue;
				} else if (strcmp(objname, "ALL")) {
					struct drbd_cfg_context ctx =
						{ .ctx_volume = -1U };

					drbd_cfg_context_from_attrs(&ctx, &info);
					if (ctx.ctx_volume == -1U ||
					    strcmp(objname, ctx.ctx_conn_name))
						continue;
				}
			}
			rv = dh->ret_code;
			if (rv == ERR_MINOR_INVALID && cm->ignore_minor_not_known)
				rv = NO_ERROR;
			if (rv != NO_ERROR)
				goto out2;
			if (drbd_tla_parse(nlh)) {
				desc = "reply did not validate - "
					"do you need to upgrade your useland tools?";
				rv = OTHER_ERROR;
				goto out2;
			}
			err = cm->show_function(cm, &info);
			if (err) {
				if (err < 0)
					err = 0;
				goto out2;
			}
		}
		if (!cm->continuous_poll && !(flags & NLM_F_DUMP)) {
			/* There will be no more reply packets.  */
			err = cm->show_function(cm, NULL);
			goto out2;
		}
	}

out2:
	msg_free(smsg);

out:
	if (rv != NO_ERROR)
		err = print_config_error(rv, desc);
	free(iov.iov_base);
	return err;
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
		printI("address\t\t\t%s %s:%d;\n",
		       af_to_str(addr4->sin_family),
		       inet_ntoa(addr4->sin_addr),
		       ntohs(addr4->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		addr6 = (struct sockaddr_in6 *)address;
		printI("address\t\t\t%s [%s]:%d;\n",
		       af_to_str(addr6->sin6_family),
		       inet_ntop(addr6->sin6_family, &addr6->sin6_addr, buffer, INET6_ADDRSTRLEN),
		       ntohs(addr6->sin6_port));
	} else {
		printI("address\t\t\t[unknown af=%d, len=%d]\n", addr->sa_family, addr_len);
	}
}

struct minors_list {
	struct minors_list *next;
	unsigned minor;
};
struct minors_list *__remembered_minors;

static int remember_minor(struct drbd_cmd *cmd, struct genl_info *info)
{
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };

	if (!info)
		return 0;

	drbd_cfg_context_from_attrs(&cfg, info);
	if (cfg.ctx_volume != -1U) {
		unsigned minor = ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
		struct minors_list *m = malloc(sizeof(*m));
		m->next = __remembered_minors;
		m->minor = minor;
		__remembered_minors = m;
	}
	return 0;
}

static void free_minors(struct minors_list *minors)
{
	while (minors) {
		struct minors_list *m = minors;
		minors = minors->next;
		free(m);
	}
}

/*
 * Expects objname to be setto the connection name or "ALL".
 */
static struct minors_list *enumerate_minors(void)
{
	struct drbd_cmd cmd = {
		.cmd_id = DRBD_ADM_GET_STATUS,
		.show_function = remember_minor,
	};
	struct minors_list *m;
	int err;

	err = generic_get_cmd(&cmd, -1, 0, NULL);
	m = __remembered_minors;
	__remembered_minors = NULL;
	if (err) {
		free_minors(m);
		m = NULL;
	}
	return m;
}

/* may be called for a "show" of a single minor device.
 * prints all available configuration information in that case.
 *
 * may also be called iteratively for a "show-all", which should try to not
 * print redundant configuration information for the same resource (tconn).
 */
static int show_scmd(struct drbd_cmd *cm, struct genl_info *info)
{
	/* FIXME need some define for max len here */
	static char last_ctx_conn_name[128];
	static int call_count;

	struct drbd_cfg_context cfg = { .ctx_volume = -1U };
	struct disk_conf dc = { .disk_size = 0, };
	struct net_conf nc = { .timeout = 0, };;

	if (!info) {
		if (call_count) {
			--indent;
			printI("}\n"); /* close _this_host */
			--indent;
			printI("}\n"); /* close resource */
		}
		fflush(stdout);
		return 0;
	}
	call_count++;

	/* FIXME: Is the folowing check needed? */
	if (!global_attrs[DRBD_NLA_CFG_CONTEXT])
		dbg(1, "unexpected packet, configuration context missing!\n");

	drbd_cfg_context_from_attrs(&cfg, info);
	disk_conf_from_attrs(&dc, info);
	net_conf_from_attrs(&nc, info);

	if (strncmp(last_ctx_conn_name, cfg.ctx_conn_name, sizeof(last_ctx_conn_name))) {
		if (strncmp(last_ctx_conn_name, "", sizeof(last_ctx_conn_name))) {
			--indent;
			printI("}\n"); /* close _this_host */
			--indent;
			printI("}\n\n");
		}
		strncpy(last_ctx_conn_name, cfg.ctx_conn_name, sizeof(last_ctx_conn_name));

		printI("resource %s {\n", cfg.ctx_conn_name);
		++indent;
		print_options("resource-options", "options");
		print_options("net-options", "net");

		if (global_attrs[DRBD_NLA_NET_CONF]) {
			if (nc.peer_addr_len) {
				printI("_remote_host {\n");
				++indent;
				show_address(nc.peer_addr, nc.peer_addr_len);
				--indent;
				printI("}\n");
			}
		}
		printI("_this_host {\n");
		++indent;
		if (global_attrs[DRBD_NLA_NET_CONF]) {
			if (nc.my_addr[0])
				show_address(nc.my_addr, nc.my_addr_len);
		}
	}

	if (cfg.ctx_volume != -1U) {
		unsigned minor = ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
		printI("volume %d {\n", cfg.ctx_volume);
		++indent;
		printI("device\t\t\tminor %d;\n", minor);
		if (global_attrs[DRBD_NLA_DISK_CONF]) {
			if (dc.backing_dev[0]) {
				printI("disk\t\t\t\"%s\";\n", dc.backing_dev);
				switch(dc.meta_dev_idx) {
				case DRBD_MD_INDEX_INTERNAL:
				case DRBD_MD_INDEX_FLEX_INT:
					printI("meta-disk\t\t\tinternal;\n");
					break;
				case DRBD_MD_INDEX_FLEX_EXT:
					printI("flexible-meta-disk\t\t\"%s\";\n", dc.meta_dev);
					break;
				default:
					printI("meta-disk\t\t\t\"%s\" [ %d ];\n", dc.meta_dev,
					       dc.meta_dev_idx);
				 }
			}
		}
		print_options("attach", "disk");
		--indent;
		printI("}\n"); /* close volume */
	}

	return 0;
}

static int lk_bdev_scmd(struct drbd_cmd *cm, struct genl_info *info)
{
	unsigned minor;
	struct disk_conf dc = { .disk_size = 0, };
	struct bdev_info bd = { 0, };
	uint64_t bd_size;
	int fd;

	if (!info)
		return 0;

	minor = ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
	disk_conf_from_attrs(&dc, info);
	if (!dc.backing_dev) {
		fprintf(stderr, "Has no disk config, try with drbdmeta.\n");
		return 1;
	}

	if (dc.meta_dev_idx >= 0 || dc.meta_dev_idx == DRBD_MD_INDEX_FLEX_EXT) {
		lk_bdev_delete(minor);
		return 0;
	}

	fd = open(dc.backing_dev, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "Could not open %s: %m.\n", dc.backing_dev);
		return 1;
	}
	bd_size = bdev_size(fd);
	close(fd);

	if (lk_bdev_load(minor, &bd) == 0 &&
	    bd.bd_size == bd_size &&
	    bd.bd_name && !strcmp(bd.bd_name, dc.backing_dev))
		return 0;	/* nothing changed. */

	bd.bd_size = bd_size;
	bd.bd_name = dc.backing_dev;
	lk_bdev_save(minor, &bd);

	return 0;
}

static int status_xml_scmd(struct drbd_cmd *cm __attribute((unused)),
		struct genl_info *info)
{
	unsigned minor;
	union drbd_state state = { .i = 0 };
	struct state_info si = { .current_state = 0, };
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };

	if (!info)
		return 0;

	minor = ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
	if (!global_attrs[DRBD_NLA_STATE_INFO]) {
		printf( "<!-- resource minor=\"%u\"", minor);
		if (resname)
			printf(" name=\"%s\"", resname);
		printf(" not available or not yet created -->\n");
		return 0;
	}
	drbd_cfg_context_from_attrs(&cfg, info);

	printf("<resource minor=\"%u\"", minor);
	printf(" conn_name=\"%s\"", cfg.ctx_conn_name ? cfg.ctx_conn_name : "n/a");
	printf(" volume=\"%u\"", cfg.ctx_volume);
	if (resname)
		printf(" name=\"%s\"", resname);

	state_info_from_attrs(&si, info);
	if (ntb(T_current_state))
		state.i = si.current_state;

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
	printf(" capacity_sect=\"%llu\"", (unsigned long long)si.capacity);
	printf(" ed_uuid=\"%016llX\"", (unsigned long long)si.ed_uuid);
	printf(" bits_total=\"%lli\"", (unsigned long long)si.bits_total);
	printf(" bits_oos=\"%lli\"", (unsigned long long)si.bits_oos);
	if (ntb(T_bits_rs_total)) {
		printf(" rs_failed=\"%lli\"", (unsigned long long)si.bits_rs_failed);
		printf(" rs_total=\"%lli\"", (unsigned long long)si.bits_rs_total);

		uint32_t shift = si.bits_rs_total >= (1ULL << 32) ? 16 : 10;
		uint64_t left = (si.bits_oos - si.bits_rs_failed) >> shift;
		uint64_t total = 1UL + (si.bits_rs_total >> shift);
		uint64_t tmp = 1000UL - left * 1000UL/total;

		unsigned synced = tmp;
		printf(" resynced_percent=\"%i.%i\"", synced / 10, synced % 10);
	}
	/* what else do you want to know rasto?
	 * pick your format... everything available! */

	printf(" />\n");
	return 0;
}

static int sh_status_scmd(struct drbd_cmd *cm __attribute((unused)),
		struct genl_info *info)
{
	unsigned minor;
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };
	struct state_info si = { .current_state = 0, };
	union drbd_state state;
	int available = 0;

	if (!info)
		return 0;

	minor = ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
/* variable prefix; maybe rather make that a command line parameter?
 * or use "drbd_sh_status"? */
#define _P ""
	printf("%s_minor=%u\n", _P, minor);
	printf("%s_res_name=%s\n", _P, shell_escape(resname ?: "UNKNOWN"));

	drbd_cfg_context_from_attrs(&cfg, info);
	printf("%s_conn_name=%s\n", _P, cfg.ctx_conn_name ? shell_escape(cfg.ctx_conn_name) : "n/a");
	printf("%s_volume=%d\n", _P, cfg.ctx_volume);

	if (state_info_from_attrs(&si, info) == 0)
		available = 1;
	state.i = si.current_state;

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

		if (ntb(T_bits_rs_total)) {
			uint32_t shift = si.bits_rs_total >= (1ULL << 32) ? 16 : 10;
			uint64_t left = (si.bits_oos - si.bits_rs_failed) >> shift;
			uint64_t total = 1UL + (si.bits_rs_total >> shift);
			uint64_t tmp = 1000UL - left * 1000UL/total;

			unsigned synced = tmp;
			printf("%i.%i\n", synced / 10, synced % 10);
			/* what else? everything available! */
		} else
			printf("\n");
	}
	printf("\n%s_sh_status_process\n\n\n", _P);

	fflush(stdout);
	return 0;
#undef _P
}

static int role_scmd(struct drbd_cmd *cm __attribute((unused)),
		struct genl_info *info)
{
	union drbd_state state = { .i = 0 };

	if (!info)
		return 0;

	if (global_attrs[DRBD_NLA_STATE_INFO]) {
		nla_parse_nested(nested_attr_tb, ARRAY_SIZE(state_info_nl_policy)-1,
				global_attrs[DRBD_NLA_STATE_INFO], state_info_nl_policy);
		if (ntb(T_current_state))
			state.i = nla_get_u32(ntb(T_current_state));
	}
	if (state.conn == C_STANDALONE &&
	    state.disk == D_DISKLESS) {
		printf("Unconfigured\n");
	} else {
		printf("%s/%s\n",drbd_role_str(state.role),drbd_role_str(state.peer));
	}
	return 0;
}

static int cstate_scmd(struct drbd_cmd *cm __attribute((unused)),
		struct genl_info *info)
{
	union drbd_state state = { .i = 0 };

	if (!info)
		return 0;

	if (global_attrs[DRBD_NLA_STATE_INFO]) {
		nla_parse_nested(nested_attr_tb, ARRAY_SIZE(state_info_nl_policy)-1,
				global_attrs[DRBD_NLA_STATE_INFO], state_info_nl_policy);
		if (ntb(T_current_state))
			state.i = nla_get_u32(ntb(T_current_state));
	}
	if (state.conn == C_STANDALONE &&
	    state.disk == D_DISKLESS) {
		printf("Unconfigured\n");
	} else {
		printf("%s\n",drbd_conn_str(state.conn));
	}
	return 0;
}

static int dstate_scmd(struct drbd_cmd *cm __attribute((unused)),
		struct genl_info *info)
{
	union drbd_state state = { .i = 0 };

	if (!info)
		return 0;

	if (global_attrs[DRBD_NLA_STATE_INFO]) {
		nla_parse_nested(nested_attr_tb, ARRAY_SIZE(state_info_nl_policy)-1,
				global_attrs[DRBD_NLA_STATE_INFO], state_info_nl_policy);
		if (ntb(T_current_state))
			state.i = nla_get_u32(ntb(T_current_state));
	}
	if ( state.conn == C_STANDALONE &&
	     state.disk == D_DISKLESS) {
		printf("Unconfigured\n");
	} else {
		printf("%s/%s\n",drbd_disk_str(state.disk),drbd_disk_str(state.pdsk));
	}
	return 0;
}

static int uuids_scmd(struct drbd_cmd *cm,
		struct genl_info *info)
{
	union drbd_state state = { .i = 0 };
	uint64_t ed_uuid;
	uint64_t *uuids = NULL;
	int flags = flags;

	if (!info)
		return 0;

	if (global_attrs[DRBD_NLA_STATE_INFO]) {
		nla_parse_nested(nested_attr_tb, ARRAY_SIZE(state_info_nl_policy)-1,
			global_attrs[DRBD_NLA_STATE_INFO], state_info_nl_policy);
		if (ntb(T_current_state))
			state.i = nla_get_u32(ntb(T_current_state));
		if (ntb(T_uuids))
			uuids = nla_data(ntb(T_uuids));
		if (ntb(T_disk_flags))
			flags = nla_get_u32(ntb(T_disk_flags));
		if (ntb(T_ed_uuid))
			ed_uuid = nla_get_u64(ntb(T_ed_uuid));
	}
	if (state.conn == C_STANDALONE &&
	    state.disk == D_DISKLESS) {
		fprintf(stderr, "Device is unconfigured\n");
		return 1;
	}
	if (state.disk == D_DISKLESS) {
		/* XXX we could print the ed_uuid anyways:
		printf("X64(016)\n", ed_uuid); */
		fprintf(stderr, "Device has no disk\n");
		return 1;
	}
	if (uuids) {
		if(!strcmp(cm->cmd,"show-gi")) {
			dt_pretty_print_uuids(uuids,flags);
		} else if(!strcmp(cm->cmd,"get-gi")) {
			dt_print_uuids(uuids,flags);
		} else {
			ASSERT( 0 );
		}
	} else {
		fprintf(stderr, "No uuids found in reply!\n"
			"Maybe you need to upgrade your userland tools?\n");
	}
	return 0;
}

static int down_cmd(struct drbd_cmd *cm, unsigned minor, int argc, char **argv)
{
	struct minors_list *minors, *m;
	int rv;
	int success;

	if(argc > 1) {
		fprintf(stderr,"Ignoring excess arguments\n");
	}

	minors = enumerate_minors();
	rv = _generic_config_cmd(cm, minor, argc, argv, 1);
	success = (rv >= SS_SUCCESS && rv < ERR_CODE_BASE) || rv == NO_ERROR;
	if (success) {
		for (m = minors; m; m = m->next)
			unregister_minor(m->minor);
		free_minors(minors);
		unregister_resource(objname);
	} else {
		free_minors(minors);
		return print_config_error(rv, NULL);
	}
	return 0;
}

/* printf format for minor, resource name, volume */
#define MNV_FMT	"%d,%s[%d]"
static void print_state(char *tag, unsigned seq, unsigned minor,
		const char *conn_name, unsigned vnr, __u32 state_i)
{
	union drbd_state s = { .i = state_i };
	printf("%u %s " MNV_FMT " { cs:%s ro:%s/%s ds:%s/%s %c%c%c%c }\n",
	       seq,
	       tag,
	       minor, conn_name, vnr,
	       drbd_conn_str(s.conn),
	       drbd_role_str(s.role),
	       drbd_role_str(s.peer),
	       drbd_disk_str(s.disk),
	       drbd_disk_str(s.pdsk),
	       s.susp ? 's' : 'r',
	       s.aftr_isp ? 'a' : '-',
	       s.peer_isp ? 'p' : '-',
	       s.user_isp ? 'u' : '-' );
}

static int print_broadcast_events(struct drbd_cmd *cm, struct genl_info *info)
{
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };
	struct state_info si = { .current_state = 0 };
	struct disk_conf dc = { .disk_size = 0, };
	struct net_conf nc = { .timeout = 0, };
	struct drbd_genlmsghdr *dh;

	if (!info)
		return 0;

	dh = info->userhdr;
	if (dh->ret_code == ERR_MINOR_INVALID && cm->ignore_minor_not_known)
		return 0;

	if (drbd_cfg_context_from_attrs(&cfg, info)) {
		dbg(1, "unexpected packet, configuration context missing!\n");
		/* keep running anyways. */
		goto out;
	}
	if (state_info_from_attrs(&si, info)) {
		/* this is a DRBD_ADM_GET_STATUS reply
		 * with information about a resource without any volumes */
		printf("%u R - %s\n", info->seq, cfg.ctx_conn_name);
		goto out;
	}

	disk_conf_from_attrs(&dc, info);
	net_conf_from_attrs(&nc, info);

	switch (si.sib_reason) {
	case SIB_STATE_CHANGE:
		print_state("ST-prev", info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				si.prev_state);
		print_state("ST-new", info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				si.new_state);
		/* fall through */
	case SIB_GET_STATUS_REPLY:
		print_state("ST", info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				si.current_state);
		break;
	case SIB_HELPER_PRE:
		printf("%u UH " MNV_FMT " %s\n", info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				si.helper);
		break;
	case SIB_HELPER_POST:
		printf("%u UH-post " MNV_FMT " %s 0x%04x\n", info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				si.helper, si.helper_exit_code);
		break;
	case SIB_SYNC_PROGRESS:
		{
		uint32_t shift = si.bits_rs_total >= (1ULL << 32) ? 16 : 10;
		uint64_t left = (si.bits_oos - si.bits_rs_failed) >> shift;
		uint64_t total = 1UL + (si.bits_rs_total >> shift);
		uint64_t tmp = 1000UL - left * 1000UL/total;

		unsigned synced = tmp;
		printf("%u SP " MNV_FMT " %i.%i\n", info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				synced / 10, synced % 10);
		}
		break;
	default:
		/* we could add the si.reason */
		printf("%u ?? " MNV_FMT " <other message, state info broadcast reason:%u>\n",
				info->seq,
				dh->minor, cfg.ctx_conn_name, cfg.ctx_volume,
				si.sib_reason);
		break;
	}
out:
	fflush(stdout);

	return 0;
}

static int w_connected_state(struct drbd_cmd *cm, struct genl_info *info)
{
	struct state_info si = { .current_state = 0 };
	union drbd_state state;

	if (!info)
		return 0;

	if (!global_attrs[DRBD_NLA_STATE_INFO])
		return 0;

	if (state_info_from_attrs(&si, info)) {
		fprintf(stderr,"nla_policy violation!?\n");
		return 0;
	}

	if (si.sib_reason != SIB_STATE_CHANGE &&
	    si.sib_reason != SIB_GET_STATUS_REPLY)
		return 0;

	state.i = si.current_state;
	if (state.conn >= C_CONNECTED)
		return -1;  /* done waiting */
	if (state.conn < C_UNCONNECTED) {
		struct drbd_genlmsghdr *dhdr = info->userhdr;
		struct drbd_cfg_context cfg = { .ctx_volume = -1U };

		if (!wait_after_split_brain)
			return -1;  /* done waiting */
		drbd_cfg_context_from_attrs(&cfg, info);

		fprintf(stderr, "\ndrbd%u (%s[%u]) is %s, "
			       "but I'm configured to wait anways (--wait-after-sb)\n",
			       dhdr->minor,
			       cfg.ctx_conn_name, cfg.ctx_volume,
			       drbd_conn_str(state.conn));
	}

	return 0;
}

static int w_synced_state(struct drbd_cmd *cm, struct genl_info *info)
{
	struct state_info si = { .current_state = 0 };
	union drbd_state state;

	if (!info)
		return 0;

	if (!global_attrs[DRBD_NLA_STATE_INFO])
		return 0;

	if (state_info_from_attrs(&si, info)) {
		fprintf(stderr,"nla_policy violation!?\n");
		return 0;
	}

	if (si.sib_reason != SIB_STATE_CHANGE &&
	    si.sib_reason != SIB_GET_STATUS_REPLY)
		return 0;

	state.i = si.current_state;

	if (state.conn == C_CONNECTED)
		return -1;  /* done waiting */

	if (!wait_after_split_brain && state.conn < C_UNCONNECTED)
		return -1;  /* done waiting */

	return 0;
}

static int numeric_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c}=(%lld ... %lld)]",
			option->name, option->short_name,
			option->numeric_param.min,
			option->numeric_param.max);
}

static int protocol_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [--protocol={A,B,C}]");
}

static int handler_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	const char** handlers;
	int i, chars=0,first=1;

	chars += snprintf(str,strlen," [{--%s|-%c}={",
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

static int flag_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str, strlen, " [{--%s|-%c}[={yes|no}]]",
			option->name, option->short_name);
}

static int yesno_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str, strlen, " [{--%s|-%c}[={yes|no}]]",
			option->name, option->short_name);
}

static int string_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c}=<str>]",
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

static void protocol_opt_xml(struct drbd_option *option)
{
	printf(
		"\t<option name=\"protocol\" type=\"handler\">\n"
		"\t\t<handler>A</handler>\n"
		"\t\t<handler>B</handler>\n"
		"\t\t<handler>C</handler>\n"
		"\t</option>\n"
	);
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

static void flag_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"boolean\">\n"
	       "\t</option>\n",
	       option->name);
}

static void yesno_opt_xml(struct drbd_option *option)
{
	/* FIXME: Check with Rasto if this is useful to him.  */
	printf("\t<option name=\"%s\" type=\"handler\">\n"
	       "\t\t<handler>yes</handler>\n"
	       "\t\t<handler>no</handler>\n"
	       "\t</option>\n",
	       option->name);
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

	static char *ctx_names[] = {
	  [CTX_MINOR] = "minor",
	  [CTX_CONN] = "connection",
	  [CTX_ALL] = "minor_or_connection",
	};

	if(ut == XML) {
		printf("<command name=\"%s\" operates_on=\"%s\">\n",
		       cm->cmd, ctx_names[cm->ctx_key]);
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
	struct option *lo;
	char line[41];

	if(ut == BRIEF) {
		sprintf(line,"%s [opts...]", cm->cmd);
		printf(" %-39s",line);
	} else {
		printf(" %s", cm->cmd);
		lo = cm->options;
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

static void print_usage_and_exit(const char* addinfo)
{
	size_t i;

	printf("\nUSAGE: %s device command arguments options\n\n"
	       "Device is usually /dev/drbdX or /dev/drbd/X.\n"
	       "General options: --set-defaults\n"
	       "\nCommands are:\n",cmdname);


	for (i = 0; i < ARRAY_SIZE(commands); i++) {
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

static int is_drbd_driver_missing(void)
{
	struct stat sb;
	int err;

	err = stat("/proc/drbd", &sb);
	if (!err)
		return 0;

	if (err == ENOENT)
		fprintf(stderr, "DRBD driver appears to be missing\n");
	else
		fprintf(stderr, "Could not stat(\"/proc/drbd\"): %m\n");
	return 1;
}

int main(int argc, char **argv)
{
	unsigned minor = -1U;
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
			else print_usage_and_exit("unknown command");
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
			else print_usage_and_exit("unknown command");
			exit(0);
		}
	}

	if (argc < 3)
		print_usage_and_exit(argc==1 ? 0 : " Insufficient arguments");

	cmd = find_cmd_by_name(argv[2]);
	if (!cmd)
		print_usage_and_exit("invalid command");

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

	if (try_genl) {
		drbd_sock = genl_connect_to_family(&drbd_genl_family);
		if (!drbd_sock) {
			try_genl = 0;
			fprintf(stderr, "Could not connect to 'drbd' generic netlink family\n");
			/* FIXME fall back to connector ... */
			/* MAYBE re-exec drbdsetup.cn */
			return 20;
		}
		if (drbd_genl_family.version != API_VERSION ||
		    drbd_genl_family.hdrsize != sizeof(struct drbd_genlmsghdr)) {
			fprintf(stderr, "API mismatch!\n\t"
				"API version drbdsetup: %u kernel: %u\n\t"
				"header size drbdsetup: %u kernel: %u\n",
				API_VERSION, drbd_genl_family.version,
				(unsigned)sizeof(struct drbd_genlmsghdr),
				drbd_genl_family.hdrsize);
			return 20;
		}
	}

	objname = argv[1];
	if (!strcmp(objname, "ALL")) {
		if (!(cmd->ctx_key & CTX_ALL))
			print_usage_and_exit("command does not accept argument 'ALL'");
	} else if (cmd->ctx_key & CTX_MINOR) {
		minor = dt_minor_of_dev(argv[1]);
		if (minor == -1U && !(cmd->ctx_key & CTX_CONN)) {
			fprintf(stderr, "Cannot determine minor device number of "
					"device '%s'\n",
				argv[1]);
			exit(20);
		}
		if (cmd->cmd_id != DRBD_ADM_GET_STATUS)
			lock_fd = dt_lock_drbd(minor);
	} else {
		/* objname is expected to be a connection name. */
	}

	// by passing argc-2, argv+2 the function has the command name
	// in argv[0], e.g. "syncer"
	rv = cmd->function(cmd,minor,argc-2,argv+2);
	dt_unlock_drbd(lock_fd);
	return rv;
}
#endif
