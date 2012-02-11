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
#include <assert.h>
#include <libgen.h>

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
#include "drbd_nla.h"
#include <linux/drbd_config.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd_limits.h>
#include <linux/genl_magic_func.h>
#include "drbdtool_common.h"
#include "drbd_strings.h"
#include "registry.h"
#include "config.h"
#include "config_flags.h"
#include "wrap_printf.h"

char *progname;

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
				struct drbd_genlmsghdr *dhdr,
				char *);
};

/* Configuration requests typically need a context to operate on.
 * Possible keys are device minor/volume id (both fit in the drbd_genlmsghdr),
 * the replication link (aka connection) name,
 * and/or the replication group (aka resource) name */
enum cfg_ctx_key {
	/* Only one of these can be present in a command: */
	CTX_RESOURCE = 1,
	CTX_MINOR = 2,
	CTX_VOLUME = 4,
	CTX_MY_ADDR = 8,
	CTX_PEER_ADDR = 16,
	CTX_ALL = 32,

	CTX_MULTIPLE_ARGUMENTS = 64,

	CTX_CONNECTION = CTX_MY_ADDR | CTX_PEER_ADDR | CTX_MULTIPLE_ARGUMENTS,
	CTX_PEER_DEVICE = CTX_MY_ADDR | CTX_PEER_ADDR | CTX_VOLUME | CTX_MULTIPLE_ARGUMENTS,

	CTX_RESOURCE_AND_CONNECTION = 0,
};

enum cfg_ctx_key ctx_next_arg(enum cfg_ctx_key *key)
{
	enum cfg_ctx_key next_arg;

	if (*key & CTX_MULTIPLE_ARGUMENTS) {
		next_arg = *key & ~(*key - 1);  /* the lowest set bit */
		next_arg &= ~CTX_MULTIPLE_ARGUMENTS;
	} else
		next_arg = *key;

	*key &= ~next_arg;
	return next_arg;
}

const char *ctx_arg_string(enum cfg_ctx_key key)
{
	switch(key) {
	case CTX_RESOURCE:
		return "{resource}";
	case CTX_MINOR:
		return "{minor}";
	case CTX_VOLUME:
		return "{volume}";
	case CTX_MY_ADDR:
		return "[{af}:]{local_addr}[:{port}]";
	case CTX_PEER_ADDR:
		return "[{af}:]{remote_addr}[:{port}]";
	case CTX_ALL:
		return "all";
	default:
		assert(0);
	}
}

struct drbd_cmd {
	const char* cmd;
	enum cfg_ctx_key ctx_key;
	int cmd_id;
	int tla_id; /* top level attribute id */
	int (*function)(struct drbd_cmd *, int, char **);
	struct drbd_argument *drbd_args;
	int (*show_function)(struct drbd_cmd*, struct genl_info *);
	struct option *options;
	bool missing_ok;
	bool continuous_poll;
	bool wait_for_connect_timeouts;
	bool set_defaults;
	struct context_def *ctx;
};

// other functions
static int get_af_ssocks(int warn);
static void print_command_usage(struct drbd_cmd *cm, enum usage_type);

// command functions
static int generic_config_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int down_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int generic_get_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int del_minor_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int del_resource_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int show_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int status_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int role_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int cstate_cmd(struct drbd_cmd *cm, int argc, char **argv);
static int dstate_cmd(struct drbd_cmd *cm, int argc, char **argv);

// sub commands for generic_get_cmd
static int uuids_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int lk_bdev_scmd(struct drbd_cmd *cm, struct genl_info *info);
static int print_notifications(struct drbd_cmd *, struct genl_info *);
static int wait_connect_or_sync(struct drbd_cmd *, struct genl_info *);
static int show_current_volume(struct drbd_cmd *cm, struct genl_info *info);

#define ADDRESS_STR_MAX 256
static char *address_str(char *buffer, void* address, int addr_len);

// convert functions for arguments
static int conv_block_dev(struct drbd_argument *ad, struct msg_buff *msg, struct drbd_genlmsghdr *dhdr, char* arg);
static int conv_md_idx(struct drbd_argument *ad, struct msg_buff *msg, struct drbd_genlmsghdr *dhdr, char* arg);

struct resources_list {
	struct resources_list *next;
	char *name;
	struct nlattr *res_opts;
	struct resource_info info;
	struct resource_statistics statistics;
};
static struct resources_list *list_resources(void);
static void free_resources(struct resources_list *);

struct devices_list {
	struct devices_list *next;
	unsigned minor;
	struct drbd_cfg_context ctx;
	struct disk_conf disk_conf;
	struct device_info info;
	struct device_statistics statistics;
};
static struct devices_list *list_devices(void);
static void free_devices(struct devices_list *);

struct connections_list {
	struct connections_list *next;
	struct drbd_cfg_context ctx;
	struct connection_info info;
	struct connection_statistics statistics;
};
static struct connections_list *list_connections(void);
static void free_connections(struct connections_list *);

struct peer_devices_list {
	struct peer_devices_list *next;
	struct drbd_cfg_context ctx;
	struct peer_device_info info;
	struct peer_device_statistics statistics;
};
static struct peer_devices_list *list_peer_devices(void);
static void free_peer_devices(struct peer_devices_list *);

struct minors_list {
	struct minors_list *next;
	unsigned minor;
};
static struct minors_list *enumerate_minors(void);
static void free_minors(struct minors_list *);

struct option wait_cmds_options[] = {
	{ "wfc-timeout",required_argument, 0, 't' },
	{ "degr-wfc-timeout",required_argument,0,'d'},
	{ "outdated-wfc-timeout",required_argument,0,'o'},
	{ "wait-after-sb",no_argument,0,'w'},
	{ 0,            0,           0,  0  }
};

struct option show_cmd_options[] = {
	{ "show-defaults", no_argument, 0, 'D' },
	{ }
};

#define F_CONFIG_CMD	generic_config_cmd
#define NO_PAYLOAD	0
#define F_GET_CMD(scmd)	DRBD_ADM_GET_STATUS, NO_PAYLOAD, generic_get_cmd, \
			.show_function = scmd
#define F_NEW_EVENTS_CMD(scmd)	DRBD_ADM_GET_INITIAL_STATE, NO_PAYLOAD, generic_get_cmd, \
			.show_function = scmd

struct drbd_cmd commands[] = {
	{"primary", CTX_RESOURCE, DRBD_ADM_PRIMARY, DRBD_NLA_SET_ROLE_PARMS,
		F_CONFIG_CMD,
	 .ctx = &primary_cmd_ctx },

	{"secondary", CTX_RESOURCE, DRBD_ADM_SECONDARY, NO_PAYLOAD, F_CONFIG_CMD },

	{"attach", CTX_MINOR, DRBD_ADM_ATTACH, DRBD_NLA_DISK_CONF,
		F_CONFIG_CMD,
	 .drbd_args = (struct drbd_argument[]) {
		 { "lower_dev",		T_backing_dev,	conv_block_dev },
		 { "meta_data_dev",	T_meta_dev,	conv_block_dev },
		 { "meta_data_index",	T_meta_dev_idx,	conv_md_idx },
		 { } },
	 .ctx = &attach_cmd_ctx },

	{"disk-options", CTX_MINOR, DRBD_ADM_CHG_DISK_OPTS, DRBD_NLA_DISK_CONF,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &disk_options_ctx },

	{"detach", CTX_MINOR, DRBD_ADM_DETACH, DRBD_NLA_DETACH_PARMS, F_CONFIG_CMD,
	 .ctx = &detach_cmd_ctx },

	{"connect", CTX_RESOURCE | CTX_CONNECTION,
		DRBD_ADM_CONNECT, DRBD_NLA_NET_CONF,
		F_CONFIG_CMD,
	 .ctx = &connect_cmd_ctx },

	{"net-options", CTX_CONNECTION, DRBD_ADM_CHG_NET_OPTS, DRBD_NLA_NET_CONF,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &net_options_ctx },

	{"disconnect", CTX_CONNECTION, DRBD_ADM_DISCONNECT, DRBD_NLA_DISCONNECT_PARMS,
		F_CONFIG_CMD,
	 .ctx = &disconnect_cmd_ctx },

	{"resize", CTX_MINOR, DRBD_ADM_RESIZE, DRBD_NLA_RESIZE_PARMS,
		F_CONFIG_CMD,
	 .ctx = &resize_cmd_ctx },

	{"resource-options", CTX_RESOURCE, DRBD_ADM_RESOURCE_OPTS, DRBD_NLA_RESOURCE_OPTS,
		F_CONFIG_CMD,
	 .set_defaults = true,
	 .ctx = &resource_options_ctx },

	{"new-current-uuid", CTX_MINOR, DRBD_ADM_NEW_C_UUID, DRBD_NLA_NEW_C_UUID_PARMS,
		F_CONFIG_CMD,
	 .ctx = &new_current_uuid_cmd_ctx },

	{"invalidate", CTX_MINOR, DRBD_ADM_INVALIDATE, NO_PAYLOAD, F_CONFIG_CMD, },
	{"invalidate-remote", CTX_MINOR, DRBD_ADM_INVAL_PEER, NO_PAYLOAD, F_CONFIG_CMD, },
	{"pause-sync", CTX_MINOR, DRBD_ADM_PAUSE_SYNC, NO_PAYLOAD, F_CONFIG_CMD, },
	{"resume-sync", CTX_MINOR, DRBD_ADM_RESUME_SYNC, NO_PAYLOAD, F_CONFIG_CMD, },
	{"suspend-io", CTX_MINOR, DRBD_ADM_SUSPEND_IO, NO_PAYLOAD, F_CONFIG_CMD, },
	{"resume-io", CTX_MINOR, DRBD_ADM_RESUME_IO, NO_PAYLOAD, F_CONFIG_CMD, },
	{"outdate", CTX_MINOR, DRBD_ADM_OUTDATE, NO_PAYLOAD, F_CONFIG_CMD, },
	{"verify", CTX_MINOR, DRBD_ADM_START_OV, DRBD_NLA_START_OV_PARMS,
		F_CONFIG_CMD,
	 .ctx = &verify_cmd_ctx },
	{"down", CTX_RESOURCE, DRBD_ADM_DOWN, NO_PAYLOAD, down_cmd,
		.missing_ok = true, },
	{"role", CTX_RESOURCE, 0, NO_PAYLOAD, role_cmd },
	{"cstate", CTX_CONNECTION, 0, NO_PAYLOAD, cstate_cmd },
	{"dstate", CTX_MINOR, 0, NO_PAYLOAD, dstate_cmd },
	{"show-gi", CTX_MINOR, F_GET_CMD(uuids_scmd) },
	{"get-gi", CTX_MINOR, F_GET_CMD(uuids_scmd) },
	{"show", CTX_RESOURCE | CTX_ALL, 0, 0, show_cmd, },
	{"status", CTX_RESOURCE | CTX_ALL, 0, 0, status_cmd, },
	{"check-resize", CTX_MINOR, F_GET_CMD(lk_bdev_scmd) },
	{"events", CTX_ALL, F_NEW_EVENTS_CMD(print_notifications),
		.missing_ok = true,
		.continuous_poll = true, },
	{"wait-connect", CTX_PEER_DEVICE, F_NEW_EVENTS_CMD(wait_connect_or_sync),
		.options = wait_cmds_options,
		.continuous_poll = true,
		.wait_for_connect_timeouts = true, },
	{"wait-sync", CTX_PEER_DEVICE, F_NEW_EVENTS_CMD(wait_connect_or_sync),
		.options = wait_cmds_options,
		.continuous_poll = true,
		.wait_for_connect_timeouts = true, },

	{"new-resource", CTX_RESOURCE, DRBD_ADM_NEW_RESOURCE, DRBD_NLA_RESOURCE_OPTS, F_CONFIG_CMD,
	 .ctx = &resource_options_ctx },

	/* only payload is resource name and volume number */
	{"new-minor", CTX_RESOURCE | CTX_MINOR | CTX_VOLUME | CTX_MULTIPLE_ARGUMENTS,
		DRBD_ADM_NEW_MINOR, DRBD_NLA_CFG_CONTEXT,
		F_CONFIG_CMD,
	 .ctx = &device_options_ctx },

	{"del-minor", CTX_MINOR, DRBD_ADM_DEL_MINOR, NO_PAYLOAD, del_minor_cmd, },
	{"del-resource", CTX_RESOURCE, DRBD_ADM_DEL_RESOURCE, NO_PAYLOAD, del_resource_cmd, }
};

bool show_defaults;
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
	EM(ERR_MD_UNCLEAN) = "Unclean meta-data found.\nYou need to 'drbdadm apply-al res'\n",
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
	EM(ERR_RESYNC_AFTER) = "The resync-after minor number is invalid",
	EM(ERR_RESYNC_AFTER_CYCLE) = "This would cause a resync-after dependency cycle",
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
	"Note: Resync pause caused by a local resync-after dependency.",
	EM(ERR_PIC_PEER_DEP) = "Sync-pause flag is already cleared.\n"
	"Note: Resync pause caused by the peer node.",
	EM(ERR_RES_NOT_KNOWN) = "Unknown resource",
	EM(ERR_RES_IN_USE) = "Resource still in use (delete all minors first)",
	EM(ERR_MINOR_CONFIGURED) = "Minor still configured (down it first)",
	EM(ERR_MINOR_OR_VOLUME_EXISTS) = "Minor or volume exists already (delete it first)",
	EM(ERR_INVALID_REQUEST) = "Invalid configuration request",
	EM(ERR_NEED_APV_100) = "Prot version 100 required in order to change\n"
	"these network options while connected",
	EM(ERR_NEED_ALLOW_TWO_PRI) = "Can not clear allow_two_primaries as long as\n"
	"there a primaries on both sides",
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
 * In CTX_MINOR, CTX_RESOURCE, CTX_ALL, objname and minor refer to the object
 * the command operates on.
 */
char *objname;
unsigned minor = -1U;
struct sockaddr_storage my_addr, peer_addr;
int my_addr_len, peer_addr_len;
unsigned int volume;
enum cfg_ctx_key context;

int debug_dump_argv = 0; /* enabled by setting DRBD_DEBUG_DUMP_ARGV in the environment */
int lock_fd;

struct genl_sock *drbd_sock = NULL;
int try_genl = 1;

struct genl_family drbd_genl_family = {
	.name = "drbd",
	.version = GENL_MAGIC_VERSION,
	.hdrsize = GENL_MAGIC_FAMILY_HDRSZ,
};

static int conv_block_dev(struct drbd_argument *ad, struct msg_buff *msg,
			  struct drbd_genlmsghdr *dhdr, char* arg)
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

static int conv_md_idx(struct drbd_argument *ad, struct msg_buff *msg,
		       struct drbd_genlmsghdr *dhdr, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = DRBD_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flexible")) idx = DRBD_MD_INDEX_FLEX_EXT;
	else idx = m_strtoll(arg,1);

	nla_put_u32(msg, ad->nla_type, idx);

	return NO_ERROR;
}

static void resolv6(const char *name, struct sockaddr_in6 *addr)
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

static void split_ipv6_addr(const char **address, int *port)
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

static void split_address(const char* text, int *af, const char** address, int* port)
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

static int sockaddr_from_str(struct sockaddr_storage *storage, const char *str)
{
	int af, port;
	const char *address;

	split_address(str, &af, &address, &port);
	if (af == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)storage;

		memset(sin6, 0, sizeof(*sin6));
		resolv6(address, sin6);
		sin6->sin6_port = htons(port);
		/* sin6->sin6_len = sizeof(*sin6); */
		return sizeof(*sin6);
	} else {
		/* AF_INET, AF_SDP, AF_SSOCKS,
		 * all use the IPv4 addressing scheme */
		struct sockaddr_in *sin = (struct sockaddr_in *)storage;

		memset(sin, 0, sizeof(*sin));
		sin->sin_port = htons(port);
		sin->sin_family = af;
		sin->sin_addr.s_addr = resolv(address);
		return sizeof(*sin);
	}
	return 0;
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

static struct option *make_longoptions(struct drbd_cmd *cm)
{
	static struct option buffer[42];
	int i = 0;
	int primary_force_index = -1;
	int connect_tentative_index = -1;

	if (cm->ctx) {
		struct field_def *field;

		/*
		 * Make sure to keep cm->ctx->fields first: we use the index
		 * returned by getopt_long() to access cm->ctx->fields.
		 */
		for (field = cm->ctx->fields; field->name; field++) {
			assert(i < ARRAY_SIZE(buffer));
			buffer[i].name = field->name;
			buffer[i].has_arg = field->argument_is_optional ?
				optional_argument : required_argument;
			buffer[i].flag = NULL;
			buffer[i].val = 0;
			if (!strcmp(cm->cmd, "primary") && !strcmp(field->name, "force"))
				primary_force_index = i;
			if (!strcmp(cm->cmd, "connect") && !strcmp(field->name, "tentative"))
				connect_tentative_index = i;
			i++;
		}
		assert(field - cm->ctx->fields == i);
	}

	if (primary_force_index != -1) {
		/*
		 * For backward compatibility, add --overwrite-data-of-peer as
		 * an alias to --force.
		 */
		assert(i < ARRAY_SIZE(buffer));
		buffer[i] = buffer[primary_force_index];
		buffer[i].name = "overwrite-data-of-peer";
		buffer[i].val = 1000 + primary_force_index;
		i++;
	}

	if (connect_tentative_index != -1) {
		/*
		 * For backward compatibility, add --dry-run as an alias to
		 * --tentative.
		 */
		assert(i < ARRAY_SIZE(buffer));
		buffer[i] = buffer[connect_tentative_index];
		buffer[i].name = "dry-run";
		buffer[i].val = 1000 + connect_tentative_index;
		i++;
	}

	if (cm->set_defaults) {
		assert(i < ARRAY_SIZE(buffer));
		buffer[i].name = "set-defaults";
		buffer[i].has_arg = 0;
		buffer[i].flag = NULL;
		buffer[i].val = '(';
		i++;
	}

	assert(i < ARRAY_SIZE(buffer));
	buffer[i].name = NULL;
	buffer[i].has_arg = 0;
	buffer[i].flag = NULL;
	buffer[i].val = 0;

	return buffer;
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

static int _generic_config_cmd(struct drbd_cmd *cm, int argc,
			       char **argv, int quiet)
{
	struct drbd_argument *ad = cm->drbd_args;
	struct nlattr *nla;
	struct option *lo;
	int c, i;
	int n_args;
	int rv = NO_ERROR;
	char *desc = NULL; /* error description from kernel reply message */

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
	dhdr->minor = -1;
	dhdr->flags = 0;

	if (context & ~CTX_MINOR)
		nla = nla_nest_start(smsg, DRBD_NLA_CFG_CONTEXT);
	if (context & CTX_RESOURCE)
		nla_put_string(smsg, T_ctx_resource_name, objname);
	if (context & CTX_MINOR)
		dhdr->minor = minor;
	if (context & CTX_VOLUME)
		nla_put_u32(smsg, T_ctx_volume, volume);
	if (context & CTX_MY_ADDR)
		nla_put(smsg, T_ctx_my_addr, my_addr_len, &my_addr);
	if (context & CTX_PEER_ADDR)
		nla_put(smsg, T_ctx_peer_addr, peer_addr_len, &peer_addr);
	if (context & ~CTX_MINOR)
		nla_nest_end(smsg, nla);

	nla = NULL;
	for (i = 1, ad = cm->drbd_args; ad && ad->name; i++) {
		if (argc < i + 1) {
			fprintf(stderr, "Missing argument '%s'\n", ad->name);
			print_command_usage(cm, FULL);
			rv = OTHER_ERROR;
			goto error;
		}
		if (!nla) {
			assert (cm->tla_id != NO_PAYLOAD);
			nla = nla_nest_start(smsg, cm->tla_id);
		}
		rv = ad->convert_function(ad, smsg, dhdr, argv[i]);
		if (rv != NO_ERROR)
			goto error;
		ad++;
	}
	n_args = i - 1;  /* command name "doesn't count" here */

	/* dhdr->minor may have been set by one of the convert functions. */
	minor = dhdr->minor;

	lo = make_longoptions(cm);
	optind = 0;  /* reset getopt_long() */
	for (;;) {
		int idx;

		c = getopt_long(argc, argv, "(", lo, &idx);
		if (c == -1)
			break;
		if (c >= 1000) {
			/* This is a field alias. */
			idx = c - 1000;
			c = 0;
		}
		if (c == 0) {
			struct field_def *field = &cm->ctx->fields[idx];
			assert (field->name == lo[idx].name);
			if (!nla) {
				assert (cm->tla_id != NO_PAYLOAD);
				nla = nla_nest_start(smsg, cm->tla_id);
			}
			if (!field->put(cm->ctx, field, smsg, optarg)) {
				rv = OTHER_ERROR;
				goto error;
			}
		} else if (c == '(')
			dhdr->flags |= DRBD_GENL_F_SET_DEFAULTS;
		else {
			rv = OTHER_ERROR;
			goto error;
		}
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
			if (rv == ERR_RES_NOT_KNOWN && cm->missing_ok)
				rv = NO_ERROR;
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

static int generic_config_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	return _generic_config_cmd(cm, argc, argv, 0);
}

static int del_minor_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	int rv;

	rv = generic_config_cmd(cm, argc, argv);
	if (!rv)
		unregister_minor(minor);
	return rv;
}

static int del_resource_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	int rv;

	rv = generic_config_cmd(cm, argc, argv);
	if (!rv)
		unregister_resource(objname);
	return rv;
}

static struct drbd_cmd *find_cmd_by_name(const char *name)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (!strcmp(name, commands[i].cmd)) {
			return commands + i;
		}
	}
	return NULL;
}

static void print_options(struct nlattr *attr, struct context_def *ctx, const char *sect_name)
{
	struct field_def *field;
	int opened = 0;

	if (!attr)
		return;

	if (drbd_nla_parse_nested(nested_attr_tb, ctx->nla_policy_size - 1,
				  attr, ctx->nla_policy)) {
		fprintf(stderr, "nla_policy violation for %s payload!\n", sect_name);
		/* still, print those that validated ok */
	}

	for (field = ctx->fields; field->name; field++) {
		struct nlattr *nlattr;
		const char *str;
		bool is_default;

		nlattr = ntb(field->nla_type);
		if (!nlattr)
			continue;
		str = field->get(ctx, field, nlattr);
		is_default = field->is_default(field, str);
		if (is_default && !show_defaults)
			continue;
		if (!opened) {
			opened=1;
			printI("%s {\n",sect_name);
			++indent;
		}
		if (field->needs_double_quoting)
			str = double_quote_string(str);
		printI("%-16s\t%s;",field->name, str);
		if (field->unit || is_default) {
				printf(" # ");
			if (field->unit)
				printf("%s", field->unit);
			if (field->unit && is_default)
				printf(", ");
			if (is_default)
				printf("default");
		}
		printf("\n");
	}
	if(opened) {
		--indent;
		printI("}\n");
	}
}

static void print_current_options(struct context_def *ctx, const char *sect_name)
{
	print_options(global_attrs[ctx->nla_type], ctx, sect_name);
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

#include <sys/utsname.h>
static bool kernel_older_than(int version, int patchlevel, int sublevel)
{
	struct utsname utsname;
	char *rel;
	int l;

	if (uname(&utsname) != 0)
		return false;
	rel = utsname.release;
	l = strtol(rel, &rel, 10);
	if (l > version)
		return false;
	else if (l < version || *rel == 0)
		return true;
	l = strtol(rel + 1, &rel, 10);
	if (l > patchlevel)
		return false;
	else if (l < patchlevel || *rel == 0)
		return true;
	l = strtol(rel + 1, &rel, 10);
	if (l >= sublevel)
		return false;
	return true;
}

static int generic_get_cmd(struct drbd_cmd *cm, int argc, char **argv)
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

	struct option *options = cm->options;
	if (!options) {
		static struct option none[] = { { } };
		options = none;
	}
	const char *opts = make_optstring(options);
	int c;

	optind = 0;  /* reset getopt_long() */
	for(;;) {
		c = getopt_long(argc, argv, opts, options, 0);
		if (c == -1)
			break;
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

		case 'D':
			show_defaults = true;
		}
	}
	if (optind + 1 < argc) {
		warn_print_excess_args(argc, argv, optind + 1);
		return 20;
	}

	dump_argv(argc, argv, optind, 0);

	if (cm->wait_for_connect_timeouts) {
		/* wait-connect, wait-sync */
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
		/* normal "get" request, or "show" */
		timeout_ms = 120000;
	/* else: events command, defaults to "infinity" */

	if (cm->continuous_poll) {
		if (genl_join_mc_group(drbd_sock, "events") &&
		    !kernel_older_than(2, 6, 23)) {
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
	if (minor == -1U && strcmp(objname, "all")) {
		/* Restrict the dump to a single resource. */
		struct nlattr *nla;
		nla = nla_nest_start(smsg, DRBD_NLA_CFG_CONTEXT);
		nla_put_string(smsg, T_ctx_resource_name, objname);
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
				err = -*(int*)nlmsg_data(nlh);
				if (err &&
				    (err != ENODEV || !cm->missing_ok)) {
					fprintf(stderr, "received netlink error reply: %s\n",
						strerror(err));
					err = 20;
				}
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

			/* parse early, otherwise drbd_cfg_context_from_attrs
			 * can not work */
			if (drbd_tla_parse(nlh)) {
				/* FIXME
				 * should continuous_poll continue?
				 */
				desc = "reply did not validate - "
					"do you need to upgrade your useland tools?";
				rv = OTHER_ERROR;
				goto out2;
			}
			if (cm->continuous_poll) {
				/*
				 * We will receive all events and have to
				 * filter for what we want ourself.
				 */
				/* FIXME
				 * Do we want to ignore broadcasts until the
				 * initial get/dump requests is done? */
				if (minor != -1U) {
					/* Assert that, for an unicast reply,
					 * reply minor matches request minor.
					 * "unsolicited" kernel broadcasts are "pid=0" (netlink "port id")
					 * (and expected to be genlmsghdr.cmd == DRBD_EVENT) */
					if (minor != dh->minor) {
						if (info.nlhdr->nlmsg_pid != 0)
							dbg(1, "received netlink packet for minor %u, while expecting %u\n",
								dh->minor, minor);
						continue;
					}
				} else if (strcmp(objname, "all")) {
					struct drbd_cfg_context ctx =
						{ .ctx_volume = -1U };

					drbd_cfg_context_from_attrs(&ctx, &info);
					if (ctx.ctx_volume == -1U ||
					    strcmp(objname, ctx.ctx_resource_name))
						continue;
				}
			}
			rv = dh->ret_code;
			if (rv == ERR_MINOR_INVALID && cm->missing_ok)
				rv = NO_ERROR;
			if (rv != NO_ERROR)
				goto out2;
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

static int print_current_connection(struct drbd_cmd *cm, struct genl_info *info)
{
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };

	if (!info)
		return 0;

	drbd_cfg_context_from_attrs(&cfg, info);

	printI("connection {\n");
	++indent;
	if (cfg.ctx_my_addr_len) {
		char address[ADDRESS_STR_MAX];
		if (address_str(address, cfg.ctx_my_addr, cfg.ctx_my_addr_len)) {
			char *colon = strchr(address, ':');
			if (colon)
				*colon = ' ';
			printI("_this_host %s;\n", address);
		}
	}
	if (cfg.ctx_peer_addr_len) {
		char address[ADDRESS_STR_MAX];
		if (address_str(address, cfg.ctx_peer_addr, cfg.ctx_peer_addr_len)) {
			char *colon = strchr(address, ':');
			if (colon)
				*colon = ' ';
			printI("_remote_host %s;\n", address);
		}
	}
	print_current_options(&net_options_ctx, "net");
	--indent;
	printI("}\n");

	return 0;
}

static int show_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources_list, *resource;
	char *old_objname = objname;
	int c;

	optind = 0;  /* reset getopt_long() */
	for (;;) {
		c = getopt_long(argc, argv, "D", show_cmd_options, 0);
		if (c == -1)
			break;
		switch(c) {
		default:
		case '?':
			return 20;
		case 'D':
			show_defaults = true;
			break;
		}
	}

	resources_list = list_resources();

	for (resource = resources_list; resource; resource = resource->next) {
		struct drbd_cmd cmd = {};

		if (strcmp(old_objname, "all") && strcmp(old_objname, resource->name))
			continue;

		objname = resource->name;

		printI("resource %s {\n", resource->name);
		++indent;

		print_options(resource->res_opts, &resource_options_ctx, "options");

		cmd.cmd_id = DRBD_ADM_GET_DEVICES;
		cmd.show_function = show_current_volume;
		generic_get_cmd(&cmd, 0, NULL);

		cmd.cmd_id = DRBD_ADM_GET_CONNECTIONS;
		cmd.show_function = print_current_connection;
		generic_get_cmd(&cmd, 0, NULL);

		--indent;
		printI("}\n\n");
	}

	free(resources_list);
	objname = old_objname;
	return 0;
}

static bool opt_verbose;
static bool opt_statistics;

static const char *susp_str(struct resource_info *info)
{
	static char buffer[32];

	*buffer = 0;
	if (info->res_susp)
		strcat(buffer, ",user" + (*buffer == 0));
	if (info->res_susp_nod)
		strcat(buffer, ",no-disk" + (*buffer == 0));
	if (info->res_susp_fen)
		strcat(buffer, ",fencing" + (*buffer == 0));
	if (*buffer == 0)
		strcat(buffer, "no");

	return buffer;
}

void resource_status(struct resources_list *resource)
{
	wrap_printf(0, "%s", resource->name);
	wrap_printf(4, " role:%s", drbd_role_str(resource->info.res_role));
	if (opt_verbose ||
	    resource->info.res_susp ||
	    resource->info.res_susp_nod ||
	    resource->info.res_susp_fen)
		wrap_printf(4, " suspended:%s", susp_str(&resource->info));
	if (opt_statistics && opt_verbose) {
		const char *write_ordering_str[] = {
			[WO_NONE] = "none",
			[WO_DRAIN_IO] = "drain",
			[WO_BDEV_FLUSH] = "flush",
			[WO_BIO_BARRIER] = "barrier",
		};
		uint32_t wo = resource->statistics.res_stat_write_ordering;

		if (wo < ARRAY_SIZE(write_ordering_str) && write_ordering_str[wo]) {
			wrap_printf(4, "\n");
			wrap_printf(4, " write-ordering:%s",
				    write_ordering_str[wo]);
		}

	}
	wrap_printf(0, "\n");
}

static void device_status(struct devices_list *device, bool single_device)
{
	int indent = 2;

	if (opt_verbose || !(single_device && device->ctx.ctx_volume == 0)) {
		wrap_printf(indent, "volume:%u",  device->ctx.ctx_volume);
		indent = 6;
		if (opt_verbose)
			wrap_printf(indent, " minor:%u", device->minor);
	}
	wrap_printf(indent, " disk:%s", drbd_disk_str(device->info.dev_disk_state));
	indent = 6;
	if (opt_statistics && device->statistics.dev_size != -1) {
		wrap_printf(indent, "\n");
		if (opt_verbose)
			wrap_printf(indent, " size:" U64,
				    (uint64_t)device->statistics.dev_size / 2);
		wrap_printf(indent, " read:" U64,
			    (uint64_t)device->statistics.dev_read / 2);
		wrap_printf(indent, " written:" U64,
			    (uint64_t)device->statistics.dev_write / 2);
		if (opt_verbose) {
			wrap_printf(indent, " al-writes:" U64,
				    (uint64_t)device->statistics.dev_al_writes);
			wrap_printf(indent, " bm-writes:" U64,
				    (uint64_t)device->statistics.dev_bm_writes);
			wrap_printf(indent, " upper-pending:" U32,
				    device->statistics.dev_upper_pending);
			wrap_printf(indent, " lower-pending:" U32,
				    device->statistics.dev_lower_pending);
			wrap_printf(indent, " al-suspended:%s",
				    device->statistics.dev_al_suspended ? "yes" : "no");
		}
	}
	if (device->statistics.dev_size != -1 && (opt_verbose ||
	    device->statistics.dev_upper_blocked ||
	    device->statistics.dev_lower_blocked)) {
		const char *x1 = "", *x2 = "";
		bool first = true;

		if (device->statistics.dev_upper_blocked) {
			x1 = ",upper" + first;
			first = false;
		}
		if (device->statistics.dev_lower_blocked) {
			x2 = ",lower" + first;
			first = false;
		}
		if (first)
			x1 = "no";

		wrap_printf(indent, " blocked:%s%s", x1, x2);
	}
	wrap_printf(indent, "\n");
}

static const char *resync_susp_str(struct peer_device_info *info)
{
	static char buffer[64];

	*buffer = 0;
	if (info->peer_resync_susp_user)
		strcat(buffer, ",user" + (*buffer == 0));
	if (info->peer_resync_susp_peer)
		strcat(buffer, ",peer" + (*buffer == 0));
	if (info->peer_resync_susp_dependency)
		strcat(buffer, ",dependency" + (*buffer == 0));
	if (*buffer == 0)
		strcat(buffer, "no");

	return buffer;
}

static void peer_device_status(struct peer_devices_list *peer_device, bool single_device)
{
	int indent = 4;

	if (opt_verbose || !(single_device && peer_device->ctx.ctx_volume == 0)) {
		wrap_printf(indent, "volume:%d", peer_device->ctx.ctx_volume);
		indent = 8;
	}
	if (opt_verbose || peer_device->info.peer_repl_state != L_CONNECTED) {
		wrap_printf(indent, " replication:%s", drbd_conn_str(peer_device->info.peer_repl_state));
		indent = 8;
	}
	if (peer_device->info.peer_repl_state != L_STANDALONE ||
	    peer_device->info.peer_disk_state != D_UNKNOWN) {
		wrap_printf(indent, " disk:%s", drbd_disk_str(peer_device->info.peer_disk_state));
		indent = 8;
		if (opt_verbose ||
		    peer_device->info.peer_resync_susp_user ||
		    peer_device->info.peer_resync_susp_peer ||
		    peer_device->info.peer_resync_susp_dependency)
			wrap_printf(indent, " resync-suspended:%s",
				    resync_susp_str(&peer_device->info));
		if (opt_statistics && peer_device->statistics.peer_dev_received != -1) {
			wrap_printf(indent, "\n");
			wrap_printf(indent, " received:" U64,
				    (uint64_t)peer_device->statistics.peer_dev_received / 2);
			wrap_printf(indent, " sent:" U64,
				    (uint64_t)peer_device->statistics.peer_dev_sent / 2);
			if (opt_verbose || peer_device->statistics.peer_dev_out_of_sync != 0)
				wrap_printf(indent, " out-of-sync:" U64,
					    (uint64_t)peer_device->statistics.peer_dev_out_of_sync / 2);
			if (opt_verbose) {
				wrap_printf(indent, " pending:" U32,
					    peer_device->statistics.peer_dev_pending);
				wrap_printf(indent, " unacked:" U32,
					    peer_device->statistics.peer_dev_unacked);
			}
		}
	}
	wrap_printf(0, "\n");
}

static void peer_devices_status(struct drbd_cfg_context *ctx, struct peer_devices_list *peer_devices, bool single_device)
{
	struct peer_devices_list *peer_device;

	for (peer_device = peer_devices; peer_device; peer_device = peer_device->next) {
		if (ctx->ctx_my_addr_len != peer_device->ctx.ctx_my_addr_len ||
		    memcmp(ctx->ctx_my_addr, peer_device->ctx.ctx_my_addr, ctx->ctx_my_addr_len) ||
		    ctx->ctx_peer_addr_len != peer_device->ctx.ctx_peer_addr_len ||
		    memcmp(ctx->ctx_peer_addr, peer_device->ctx.ctx_peer_addr, ctx->ctx_peer_addr_len))
			continue;
		peer_device_status(peer_device, peer_device);
	}
}

static void connection_status(struct connections_list *connection,
			      struct peer_devices_list *peer_devices,
			      bool single_device)
{
	char local_addr[ADDRESS_STR_MAX], peer_addr[ADDRESS_STR_MAX];

	if (!address_str(local_addr, connection->ctx.ctx_my_addr, connection->ctx.ctx_my_addr_len))
		strcpy(local_addr, "?");
	if (!address_str(peer_addr, connection->ctx.ctx_peer_addr, connection->ctx.ctx_peer_addr_len))
		strcpy(peer_addr, "?");
	/* FIXME: Reject undefined endpoints once the kernel stops creating NULL connections. */
	wrap_printf(2, "local:%s", local_addr);
	wrap_printf(6, " peer:%s", peer_addr);
	if (opt_verbose || connection->info.conn_connection_state != C_CONNECTED)
		wrap_printf(6, " connection:%s", drbd_conn_str(connection->info.conn_connection_state));
	if (opt_verbose || connection->info.conn_connection_state == C_CONNECTED)
		wrap_printf(6, " role:%s", drbd_role_str(connection->info.conn_role));
	if (opt_verbose || connection->statistics.conn_congested > 0) {
		wrap_printf(6, "\n");
		wrap_printf(6, " congested:%s", connection->statistics.conn_congested ? "yes" : "no");
	}
	wrap_printf(0, "\n");
	if (connection->info.conn_connection_state == C_CONNECTED)
		peer_devices_status(&connection->ctx, peer_devices, single_device);
}

static int status_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources, *resource;
	char *old_objname = objname;
	bool found = false;
	int c;

	optind = 0;  /* reset getopt_long() */
	for (;;) {
		static struct option status_cmd_options[] = {
			{ "verbose", no_argument, 0, 'v' },
			{ "statistics", no_argument, 0, 's' },
			{ }
		};

		c = getopt_long(argc, argv, "vs", status_cmd_options, 0);
		if (c == -1)
			break;
		switch(c) {
		default:
		case '?':
			return 20;
		case 'v':
			opt_verbose = true;
			break;
		case 's':
			opt_statistics = true;
			break;
		}
	}

	resources = list_resources();

	for (resource = resources; resource; resource = resource->next) {
		struct devices_list *devices, *device;
		struct connections_list *connections, *connection;
		struct peer_devices_list *peer_devices = NULL;
		bool single_device;

		if (strcmp(old_objname, "all") && strcmp(old_objname, resource->name))
			continue;

		objname = resource->name;

		devices = list_devices();
		connections = list_connections();
		if (devices && connections)
			peer_devices = list_peer_devices();

		resource_status(resource);
		single_device = devices && !devices->next;
		for (device = devices; device; device = device->next)
			device_status(device, single_device);
		for (connection = connections; connection; connection = connection->next)
			connection_status(connection, peer_devices, single_device);
		wrap_printf(0, "\n");

		free_connections(connections);
		free_devices(devices);
		free_peer_devices(peer_devices);
		found = true;
	}

	free_resources(resources);
	objname = old_objname;
	if (!found && strcmp(objname, "all")) {
		fprintf(stderr, "%s: No such resource\n", objname);
		return 10;
	}
	return 0;
}

static int role_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct resources_list *resources, *resource;
	int ret = ERR_RES_NOT_KNOWN;

	resources = list_resources();

	for (resource = resources; resource; resource = resource->next) {
		if (strcmp(objname, resource->name))
			continue;

		printf("%s\n", drbd_role_str(resource->info.res_role));
		ret = NO_ERROR;
		break;
	}

	free_resources(resources);

	if (ret != NO_ERROR) {
		fprintf(stderr, "%s: %s\n", objname, error_to_string(ret));
		return 10;
	}
	return 0;
}

static int cstate_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct connections_list *connections, *connection;
	char *old_objname = objname;
	bool found = false;

	objname = "all";
	connections = list_connections();
	for (connection = connections; connection; connection = connection->next) {
		if (my_addr_len != connection->ctx.ctx_my_addr_len ||
		    memcmp(&my_addr, connection->ctx.ctx_my_addr, my_addr_len) ||
		    peer_addr_len != connection->ctx.ctx_peer_addr_len ||
		    memcmp(&peer_addr, connection->ctx.ctx_peer_addr, peer_addr_len))
			continue;

		printf("%s\n", drbd_conn_str(connection->info.conn_connection_state));
		found = true;
		break;
	}
	free_connections(connections);
	objname = old_objname;

	if (!found) {
		fprintf(stderr, "%s: No such connection\n", objname);
		return 10;
	}
	return 0;
}

static int dstate_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct devices_list *devices, *device;
	char *old_objname = objname;
	unsigned old_minor = minor;
	bool found = false;

	objname = "all";
	minor = -1;
	devices = list_devices();
	for (device = devices; device; device = device->next) {
		if (device->minor != old_minor)
			continue;

		printf("%s\n", drbd_disk_str(device->info.dev_disk_state));
		/* printf("%s/%s\n",drbd_disk_str(state.disk),drbd_disk_str(state.pdsk)); */
		found = true;
		break;
	}
	free_devices(devices);
	objname = old_objname;

	if (!found) {
		fprintf(stderr, "%s: No such device\n", objname);
		return 10;
	}
	return 0;
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

static char *address_str(char *buffer, void* address, int addr_len)
{
	struct sockaddr     *addr;
	struct sockaddr_in  *addr4;
	struct sockaddr_in6 *addr6;

	addr = (struct sockaddr *)address;
	if (addr->sa_family == AF_INET
	|| addr->sa_family == get_af_ssocks(0)
	|| addr->sa_family == AF_INET_SDP) {
		addr4 = (struct sockaddr_in *)address;
		snprintf(buffer, ADDRESS_STR_MAX, "%s:%s:%u",
			 af_to_str(addr4->sin_family),
			 inet_ntoa(addr4->sin_addr),
			 ntohs(addr4->sin_port));
		return buffer;
	} else if (addr->sa_family == AF_INET6) {
		char buffer2[INET6_ADDRSTRLEN];
		addr6 = (struct sockaddr_in6 *)address;
		snprintf(buffer, ADDRESS_STR_MAX, "%s:[%s]:%u",
		        af_to_str(addr6->sin6_family),
		        inet_ntop(addr6->sin6_family, &addr6->sin6_addr, buffer2, INET6_ADDRSTRLEN),
		        ntohs(addr6->sin6_port));
		return buffer;
	} else
		return NULL;
}

struct resources_list *__remembered_resources, **__remembered_resources_tail;

static int remember_resource(struct drbd_cmd *cmd, struct genl_info *info)
{
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };

	if (!info)
		return 0;

	drbd_cfg_context_from_attrs(&cfg, info);
	if (cfg.ctx_resource_name) {
		struct resources_list *r = malloc(sizeof(*r));
		struct nlattr *res_opts = global_attrs[DRBD_NLA_RESOURCE_OPTS];

		memset(r, 0, sizeof(*r));
		r->name = strdup(cfg.ctx_resource_name);
		if (res_opts) {
			int size = nla_total_size(nla_len(res_opts));

			r->res_opts = malloc(size);
			memcpy(r->res_opts, res_opts, size);
		}
		resource_info_from_attrs(&r->info, info);
		memset(&r->statistics, -1, sizeof(r->statistics));
		resource_statistics_from_attrs(&r->statistics, info);
		*__remembered_resources_tail = r;
		__remembered_resources_tail = &r->next;
	}
	return 0;
}

static void free_resources(struct resources_list *resources)
{
	while (resources) {
		struct resources_list *r = resources;
		resources = resources->next;
		free(r->name);
		free(r->res_opts);
		free(r);
	}
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct resources_list *list_resources(void)
{
	struct drbd_cmd cmd = {
		.cmd_id = DRBD_ADM_GET_RESOURCES,
		.show_function = remember_resource,
		.missing_ok = false,
	};
	struct resources_list *r;
	int err;

	__remembered_resources_tail = &__remembered_resources;
	err = generic_get_cmd(&cmd, 0, NULL);
	r = __remembered_resources;
	__remembered_resources = NULL;
	if (err) {
		free_resources(r);
		r = NULL;
	}
	return r;
}

struct devices_list *__remembered_devices, **__remembered_devices_tail;

static int remember_device(struct drbd_cmd *cm, struct genl_info *info)
{
	struct drbd_cfg_context ctx = { .ctx_volume = -1U };

	if (!info)
		return 0;

	drbd_cfg_context_from_attrs(&ctx, info);

	if (ctx.ctx_volume != -1U) {
		struct devices_list *d = malloc(sizeof(*d));

		memset(d, 0, sizeof(*d));
		d->minor =  ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
		d->ctx = ctx;
		disk_conf_from_attrs(&d->disk_conf, info);
		d->info.dev_disk_state = D_DISKLESS;
		device_info_from_attrs(&d->info, info);
		memset(&d->statistics, -1, sizeof(d->statistics));
		device_statistics_from_attrs(&d->statistics, info);
		*__remembered_devices_tail = d;
		__remembered_devices_tail = &d->next;
	}
	return 0;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct devices_list *list_devices(void)
{
	struct drbd_cmd cmd = {
		.cmd_id = DRBD_ADM_GET_DEVICES,
		.show_function = remember_device,
		.missing_ok = false,
	};
	struct devices_list *r;
	int err;

	__remembered_devices_tail = &__remembered_devices;
	err = generic_get_cmd(&cmd, 0, NULL);
	r = __remembered_devices;
	__remembered_devices = NULL;
	if (err) {
		free_devices(r);
		r = NULL;
	}
	return r;
}

static void free_devices(struct devices_list *devices)
{
	while (devices) {
		struct devices_list *d = devices;
		devices = devices->next;
		free(d);
	}
}

struct connections_list *__remembered_connections, **__remembered_connections_tail;

static int remember_connection(struct drbd_cmd *cmd, struct genl_info *info)
{
	struct drbd_cfg_context ctx = { .ctx_volume = -1U };

	if (!info)
		return 0;

	drbd_cfg_context_from_attrs(&ctx, info);
	if (ctx.ctx_resource_name) {
		struct connections_list *c = malloc(sizeof(*c));

		memset(c, 0, sizeof(*c));
		c->ctx = ctx;
		connection_info_from_attrs(&c->info, info);
		memset(&c->statistics, -1, sizeof(c->statistics));
		connection_statistics_from_attrs(&c->statistics, info);
		*__remembered_connections_tail = c;
		__remembered_connections_tail = &c->next;
	}
	return 0;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct connections_list *list_connections(void)
{
	struct drbd_cmd cmd = {
		.cmd_id = DRBD_ADM_GET_CONNECTIONS,
		.show_function = remember_connection,
		.missing_ok = true,
	};
	struct connections_list *c;
	int err;

	__remembered_connections_tail = &__remembered_connections;
	err = generic_get_cmd(&cmd, 0, NULL);
	c = __remembered_connections;
	__remembered_connections = NULL;
	if (err) {
		free_connections(c);
		c = NULL;
	}
	return c;
}

static void free_connections(struct connections_list *connections)
{
	while (connections) {
		struct connections_list *l = connections;
		connections = connections->next;
		free(l);
	}
}

struct peer_devices_list *__remembered_peer_devices, **__remembered_peer_devices_tail;

static int remember_peer_device(struct drbd_cmd *cmd, struct genl_info *info)
{
	struct drbd_cfg_context ctx = { .ctx_volume = -1U };

	if (!info)
		return 0;

	drbd_cfg_context_from_attrs(&ctx, info);
	if (ctx.ctx_resource_name) {
		struct peer_devices_list *p = malloc(sizeof(*p));

		memset(p, 0, sizeof(*p));
		p->ctx = ctx;
		peer_device_info_from_attrs(&p->info, info);
		memset(&p->statistics, -1, sizeof(p->statistics));
		peer_device_statistics_from_attrs(&p->statistics, info);
		*__remembered_peer_devices_tail = p;
		__remembered_peer_devices_tail = &p->next;
	}
	return 0;
}

/*
 * Expects objname to be set to the resource name or "all".
 */
static struct peer_devices_list *list_peer_devices(void)
{
	struct drbd_cmd cmd = {
		.cmd_id = DRBD_ADM_GET_PEER_DEVICES,
		.show_function = remember_peer_device,
		.missing_ok = false,
	};
	struct peer_devices_list *r;
	int err;

	__remembered_peer_devices_tail = &__remembered_peer_devices;
	err = generic_get_cmd(&cmd, 0, NULL);
	r = __remembered_peer_devices;
	__remembered_peer_devices = NULL;
	if (err) {
		free_peer_devices(r);
		r = NULL;
	}
	return r;
}

static void free_peer_devices(struct peer_devices_list *peer_devices)
{
	while (peer_devices) {
		struct peer_devices_list *p = peer_devices;
		peer_devices = peer_devices->next;
		free(p);
	}
}

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
 * Expects objname to be set to the resource name or "all".
 */
static struct minors_list *enumerate_minors(void)
{
	struct drbd_cmd cmd = {
		.cmd_id = DRBD_ADM_GET_STATUS,
		.show_function = remember_minor,
		.missing_ok = true,
	};
	struct minors_list *m;
	int err;

	err = generic_get_cmd(&cmd, 0, NULL);
	m = __remembered_minors;
	__remembered_minors = NULL;
	if (err) {
		free_minors(m);
		m = NULL;
	}
	return m;
}

static int __show_current_volume(struct drbd_cmd *cm, struct genl_info *info)
{
	unsigned minor;
	struct drbd_cfg_context cfg = { .ctx_volume = -1U };
	struct disk_conf dc = { .disk_size = 0, };

	if (!info)
		return 0;

	minor = ((struct drbd_genlmsghdr*)(info->userhdr))->minor;
	drbd_cfg_context_from_attrs(&cfg, info);
	disk_conf_from_attrs(&dc, info);

	printI("volume %d {\n", cfg.ctx_volume);
	++indent;
	printI("device\t\t\tminor %d;\n", minor);
	if (global_attrs[DRBD_NLA_DISK_CONF]) {
		if (dc.backing_dev[0]) {
			printI("disk\t\t\t\"%s\";\n", dc.backing_dev);
			printI("meta-disk\t\t\t");
			switch(dc.meta_dev_idx) {
			case DRBD_MD_INDEX_INTERNAL:
			case DRBD_MD_INDEX_FLEX_INT:
				printf("internal;\n");
				break;
			case DRBD_MD_INDEX_FLEX_EXT:
				printf("%s;\n",
				       double_quote_string(dc.meta_dev));
				break;
			default:
				printf("%s [ %d ];\n",
				       double_quote_string(dc.meta_dev),
				       dc.meta_dev_idx);
			 }
		}
	}
	print_current_options(&attach_cmd_ctx, "disk");
	--indent;
	printI("}\n"); /* close volume */

	return 0;
}

static int show_current_volume(struct drbd_cmd *cm, struct genl_info *info)
{
	static bool in_this_host_section;

	if (info) {
		if (!in_this_host_section) {
			printI("_this_host {\n");
			++indent;
			in_this_host_section = true;
		}
	} else {
		if (in_this_host_section) {
			--indent;
			printI("}\n");
			in_this_host_section = false;
		}
	}

	return __show_current_volume(cm, info);
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
		drbd_nla_parse_nested(nested_attr_tb,
				      ARRAY_SIZE(state_info_nl_policy)-1,
				      global_attrs[DRBD_NLA_STATE_INFO],
				      state_info_nl_policy);
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
		/* XXX we could print the ed_uuid anyways: */
		if (0)
			printf(X64(016)"\n", ed_uuid);
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

static int down_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct minors_list *minors, *m;
	int rv;
	int success;

	if(argc > 2) {
		warn_print_excess_args(argc, argv, 2);
		return OTHER_ERROR;
	}

	minors = enumerate_minors();
	rv = _generic_config_cmd(cm, argc, argv, 1);
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

static int print_notifications(struct drbd_cmd *cm, struct genl_info *info)
{
	static const char *action_name[] = {
		[NOTIFY_EXISTS] = "exists",
		[NOTIFY_CREATE] = "create",
		[NOTIFY_CHANGE] = "change",
		[NOTIFY_DESTROY] = "destroy",
		[NOTIFY_CALL] = "call",
		[NOTIFY_RESPONSE] = "response",
	};
	static char *object_name[] = {
		[DRBD_RESOURCE_STATE] = "resource",
		[DRBD_DEVICE_STATE] = "device",
		[DRBD_CONNECTION_STATE] = "connection",
		[DRBD_PEER_DEVICE_STATE] = "peer-device",
		[DRBD_HELPER] = "helper",
	};
	static uint32_t last_seq;
	static bool last_seq_known;

	struct drbd_cfg_context ctx = { .ctx_volume = -1U };
	struct drbd_notification_header nh = { .nh_type = -1U };
	enum drbd_notification_type action;
	char addr[ADDRESS_STR_MAX];
	struct drbd_genlmsghdr *dh;

	if (!info)
		return 0;

	dh = info->userhdr;
	if (dh->ret_code == ERR_MINOR_INVALID && cm->missing_ok)
		return 0;
	if (dh->ret_code != NO_ERROR)
		return dh->ret_code;

	if (drbd_cfg_context_from_attrs(&ctx, info) ||
	    drbd_notification_header_from_attrs(&nh, info))
		return 0;
	if (info->genlhdr->cmd >= ARRAY_SIZE(object_name) ||
	    !object_name[info->genlhdr->cmd]) {
		dbg(1, "unknown notification\n");
		goto out;
	}
	action = nh.nh_type & ~NOTIFY_FLAGS;
	if (action >= ARRAY_SIZE(action_name) ||
	    !action_name[action]) {
		dbg(1, "unknown notification type\n");
		goto out;
	}

	if (action != NOTIFY_EXISTS) {
		if (last_seq_known) {
			uint32_t skipped = info->nlhdr->nlmsg_seq - (last_seq + 1);

			if (skipped)
				printf("- skipped %u\n", skipped);
		}
		last_seq = info->nlhdr->nlmsg_seq;
		last_seq_known = true;
	}

	printf("%u %s %s",
	       nh.nh_id,
	       action_name[action],
	       object_name[info->genlhdr->cmd]);
	if (ctx.ctx_resource_name)
		printf(" name:%s", ctx.ctx_resource_name);
	if (ctx.ctx_my_addr_len &&
	    address_str(addr, ctx.ctx_my_addr, ctx.ctx_my_addr_len))
		printf(" local:%s", addr);
	if (ctx.ctx_peer_addr_len &&
	    address_str(addr, ctx.ctx_peer_addr, ctx.ctx_peer_addr_len))
		printf(" peer:%s", addr);
	if (ctx.ctx_volume != -1U)
		printf(" volume:%u", ctx.ctx_volume);
	if (dh->minor != -1U)
		printf(" minor:%u", dh->minor);

	switch(info->genlhdr->cmd) {
	case DRBD_RESOURCE_STATE:
		if (action != NOTIFY_DESTROY) {
			struct resource_info resource_info;

			if (resource_info_from_attrs(&resource_info, info)) {
				dbg(1, "resource info missing\n");
				goto out;
			}
			printf(" role:%s suspended:%s",
			       drbd_role_str(resource_info.res_role),
			       susp_str(&resource_info));
		}
		break;
	case DRBD_DEVICE_STATE:
		if (action != NOTIFY_DESTROY) {
			struct device_info device_info;

			if (device_info_from_attrs(&device_info, info)) {
				dbg(1, "device info missing\n");
				goto out;
			}
			printf(" disk:%s",
			       drbd_disk_str(device_info.dev_disk_state));
		}
		break;
	case DRBD_CONNECTION_STATE:
		if (action != NOTIFY_DESTROY) {
			struct connection_info connection_info;

			if (connection_info_from_attrs(&connection_info, info)) {
				dbg(1, "connection info missing\n");
				goto out;
			}
			printf(" connection:%s role:%s",
			       drbd_conn_str(connection_info.conn_connection_state),
			       drbd_role_str(connection_info.conn_role));
		}
		break;
	case DRBD_PEER_DEVICE_STATE:
		if (action != NOTIFY_DESTROY) {
			struct peer_device_info peer_device_info;

			if (peer_device_info_from_attrs(&peer_device_info, info)) {
				dbg(1, "peer device info missing\n");
				goto out;
			}
			printf(" replication:%s disk:%s resync-suspended:%s",
			       drbd_conn_str(peer_device_info.peer_repl_state),
			       drbd_disk_str(peer_device_info.peer_disk_state),
			       resync_susp_str(&peer_device_info));
		}
		break;
	case DRBD_HELPER: {
		struct drbd_helper_info helper_info;

		if (!drbd_helper_info_from_attrs(&helper_info, info)) {
			printf(" helper:%s", helper_info.helper_name);
			if (action == NOTIFY_RESPONSE)
				printf(" status:%u", helper_info.helper_status);
		} else {
			dbg(1, "helper info missing\n");
			goto out;
		}
		}
		break;
	}
	printf("\n");

out:
	fflush(stdout);

	return 0;
}

static int wait_connect_or_sync(struct drbd_cmd *cm, struct genl_info *info)
{
	struct drbd_cfg_context ctx = { .ctx_volume = -1U };
	struct drbd_notification_header nh = { .nh_type = -1U };
	struct drbd_genlmsghdr *dh;

	if (!info)
		return 0;

	if (drbd_cfg_context_from_attrs(&ctx, info) ||
	    drbd_notification_header_from_attrs(&nh, info))
		return 0;

	dh = info->userhdr;
	if (dh->ret_code != NO_ERROR)
		return dh->ret_code;

	if (nh.nh_type == NOTIFY_DESTROY)
		return 0;
	if (info->genlhdr->cmd != DRBD_CONNECTION_STATE &&
	    info->genlhdr->cmd != DRBD_PEER_DEVICE_STATE)
		return 0;
	if (my_addr_len != ctx.ctx_my_addr_len ||
	    memcmp(&my_addr, ctx.ctx_my_addr, my_addr_len) ||
	    peer_addr_len != ctx.ctx_peer_addr_len ||
	    memcmp(&peer_addr, ctx.ctx_peer_addr, peer_addr_len))
		return 0;

	switch(info->genlhdr->cmd) {
	case DRBD_CONNECTION_STATE: {
		struct connection_info connection_info;

		if (connection_info_from_attrs(&connection_info, info)) {
			dbg(1, "connection info missing\n");
			goto out;
		}
		if (connection_info.conn_connection_state < C_CONNECTED)
			if (!wait_after_split_brain)
				return -1;  /* done waiting */

			fprintf(stderr, "\ndrbd%u (%s[%u]) is %s, "
				       "but I'm configured to wait anways (--wait-after-sb)\n",
				       dh->minor,
				       ctx.ctx_resource_name, ctx.ctx_volume,
				       drbd_conn_str(connection_info.conn_connection_state));
		}
		break;
	case DRBD_PEER_DEVICE_STATE: {
		struct peer_device_info peer_device_info;

		if (peer_device_info_from_attrs(&peer_device_info, info)) {
			dbg(1, "peer device info missing\n");
			goto out;
		}
		if ((!strcmp(cm->cmd, "wait-connect") &&
		     peer_device_info.peer_repl_state >= L_CONNECTED) ||
		    (/* !strcmp(cm->cmd, "wait-sync") && */
		     peer_device_info.peer_repl_state == L_CONNECTED))
			return -1;  /* done waiting */
		}
		break;
	}

out:
	return 0;
}

/*
 * Check if an integer is a power of two.
 */
static bool power_of_two(int i)
{
	return i && !(i & (i - 1));
}

static void print_command_usage(struct drbd_cmd *cm, enum usage_type ut)
{
	struct drbd_argument *args;

	if(ut == XML) {
		enum cfg_ctx_key ctx = cm->ctx_key;

		printf("<command name=\"%s\">\n", cm->cmd);
		if (ctx & (CTX_RESOURCE | CTX_MINOR | CTX_ALL)) {
			bool more_than_one_choice =
				!(ctx & CTX_MULTIPLE_ARGUMENTS) &&
				!power_of_two(ctx & (CTX_RESOURCE | CTX_MINOR | CTX_ALL));
			const char *indent = "\t\t" + !more_than_one_choice;
			if (more_than_one_choice)
				printf("\t<group>\n");
			if (ctx & CTX_RESOURCE)
				printf("%s<argument>resource</argument>\n", indent);
			if (ctx & CTX_MINOR)
				printf("%s<argument>minor</argument>\n", indent);
			if (ctx & CTX_ALL)
				printf("%s<argument>all</argument>\n", indent);
			if (more_than_one_choice)
				printf("\t</group>\n");
		}
		if (ctx & CTX_CONNECTION) {
			printf("\t<argument>local_addr</argument>\n");
			printf("\t<argument>remote_addr</argument>\n");
		}

		if(cm->drbd_args) {
			for (args = cm->drbd_args; args->name; args++) {
				printf("\t<argument>%s</argument>\n",
				       args->name);
			}
		}

		if (cm->options) {
			struct option *option;

			for (option = cm->options; option->name; option++) {
				/*
				 * The "string" options here really are
				 * timeouts, but we can't describe them
				 * in a resonable way here.
				 */
				printf("\t<option name=\"%s\" type=\"%s\">\n"
				       "\t</option>\n",
				       option->name,
				       option->has_arg == no_argument ?
					 "flag" : "string");
			}
		}

		if (cm->set_defaults)
			printf("\t<option name=\"set-defaults\" type=\"flag\">\n"
			       "\t</option>\n");

		if (cm->ctx) {
			struct field_def *field;

			for (field = cm->ctx->fields; field->name; field++)
				field->describe_xml(field);
		}
		printf("</command>\n");
		return;
	}

	if (ut == BRIEF)
		wrap_printf(4, "%-18s  ", cm->cmd);
	else {
		wrap_printf(0, "USAGE:\n");

		wrap_printf(1, "%s %s", progname, cm->cmd);
		if (cm->ctx_key && ut != BRIEF) {
			enum cfg_ctx_key ctx = cm->ctx_key, arg;
			bool more_than_one_choice =
				!power_of_two(ctx & ~CTX_MULTIPLE_ARGUMENTS) &&
				!(ctx & CTX_MULTIPLE_ARGUMENTS);
			bool first = true;

			if (more_than_one_choice)
				wrap_printf(4, " {");
			ctx |= CTX_MULTIPLE_ARGUMENTS;
			for (arg = ctx_next_arg(&ctx); arg; arg = ctx_next_arg(&ctx)) {
				if (more_than_one_choice && !first)
					wrap_printf(4, " |");
				first = false;
				wrap_printf(4, " %s", ctx_arg_string(arg));
			}
			if (more_than_one_choice)
				wrap_printf(4, " }");
		}

		if (cm->drbd_args) {
			for (args = cm->drbd_args; args->name; args++)
				wrap_printf(4, " {%s}", args->name);
		}

		if (cm->options) {
			struct option *option;

			for (option = cm->options; option->name; option++)
				wrap_printf(4, " [--%s%s]",
					    option->name,
					    option->has_arg == no_argument ?
					        "" : "=...");
		}

		if (cm->set_defaults)
			wrap_printf(4, " [--set-defaults]");

		if (cm->ctx) {
			struct field_def *field;

			for (field = cm->ctx->fields; field->name; field++) {
				char buffer[300];
				int n;
				n = field->usage(field, buffer, sizeof(buffer));
				assert(n < sizeof(buffer));
				wrap_printf(4, " %s", buffer);
			}
		}
		wrap_printf(4, "\n");
	}
}

static void print_usage_and_exit(const char* addinfo)
{
	size_t i;

	printf("\nUSAGE: %s command device arguments options\n\n"
	       "Device is usually /dev/drbdX or /dev/drbd/X.\n"
	       "\nCommands are:\n",cmdname);


	for (i = 0; i < ARRAY_SIZE(commands); i++)
		print_command_usage(&commands[i], BRIEF);

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

void exec_legacy_drbdsetup(char **argv)
{
#ifdef DRBD_LEGACY_83
	static const char * const legacy_drbdsetup = "drbdsetup-83";
	char *progname, *drbdsetup;

	/* in case drbdsetup is called with an absolute or relative pathname
	 * look for the legacy drbdsetup binary in the same location,
	 * otherwise, just let execvp sort it out... */
	if ((progname = strrchr(argv[0], '/')) == 0) {
		drbdsetup = strdup(legacy_drbdsetup);
	} else {
		size_t len_dir, l;

		++progname;
		len_dir = progname - argv[0];

		l = len_dir + strlen(legacy_drbdsetup) + 1;
		drbdsetup = malloc(l);
		if (!drbdsetup) {
			fprintf(stderr, "Malloc() failed\n");
			exit(20);
		}
		strncpy(drbdsetup, argv[0], len_dir);
		strcpy(drbdsetup + len_dir, legacy_drbdsetup);
	}
	execvp(drbdsetup, argv);
#else
	fprintf(stderr, "This drbdsetup was not built with support for legacy drbd-8.3\n"
		"Eventually rebuild with ./configure --with-legacy-connector\n");
#endif
}

int main(int argc, char **argv)
{
	struct drbd_cmd *cmd;
	int rv=0;

	progname = basename(argv[0]);

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

	if (argc > 2 && (!strcmp(argv[2], "--help")  || !strcmp(argv[2], "-h"))) {
		char *swap = argv[1];
		argv[1] = argv[2];
		argv[2] = swap;
	}

	if (argc > 1 && (!strcmp(argv[1], "help") || !strcmp(argv[1], "xml-help")  ||
			 !strcmp(argv[1], "--help")  || !strcmp(argv[1], "-h"))) {
		enum usage_type usage_type = !strcmp(argv[1], "xml-help") ? XML : FULL;
		if(argc > 2) {
			cmd = find_cmd_by_name(argv[2]);
			if(cmd) {
				print_command_usage(cmd, usage_type);
				exit(0);
			} else
				print_usage_and_exit("unknown command");
		} else
			print_usage_and_exit(0);
	}

	/*
	 * drbdsetup previously took the object to operate on as its first argument,
	 * followed by the command.  For backwards compatibility, still support his.
	 */
	if (argc >= 3 && !find_cmd_by_name(argv[1]) && find_cmd_by_name(argv[2])) {
		char *swap = argv[1];
		argv[1] = argv[2];
		argv[2] = swap;
	}

	/* it is enough to set it, value is ignored */
	if (getenv("DRBD_DEBUG_DUMP_ARGV"))
		debug_dump_argv = 1;

	if (argc < 2)
		print_usage_and_exit(0);

	cmd = find_cmd_by_name(argv[1]);
	if (!cmd)
		print_usage_and_exit("invalid command");

	if (is_drbd_driver_missing()) {
		if (!strcmp(argv[1], "down") ||
		    !strcmp(argv[1], "secondary") ||
		    !strcmp(argv[1], "disconnect") ||
		    !strcmp(argv[1], "detach"))
			return 0; /* "down" succeeds even if drbd is missing */

		fprintf(stderr, "do you need to load the module?\n"
				"try: modprobe drbd\n");
		return 20;
	}

	if (try_genl) {
		if (cmd->continuous_poll)
			drbd_genl_family.nl_groups = -1;
		drbd_sock = genl_connect_to_family(&drbd_genl_family);
		if (!drbd_sock) {
			try_genl = 0;
			exec_legacy_drbdsetup(argv);
			/* Only reached in case exec() failed... */
			fprintf(stderr, "Could not connect to 'drbd' generic netlink family\n");
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

	context = 0;
	enum cfg_ctx_key ctx_key = cmd->ctx_key, next_arg;
	for (next_arg = ctx_next_arg(&ctx_key), optind = 2;
	     next_arg;
	     next_arg = ctx_next_arg(&ctx_key), optind++) {
		if (argc == optind && !(ctx_key & CTX_MULTIPLE_ARGUMENTS) && (next_arg & CTX_ALL))
			context |= CTX_ALL;  /* assume "all" if no argument is given */
		else if (argc <= optind) {
			fprintf(stderr, "Missing argument %d\n", optind);
			print_command_usage(cmd, FULL);
			exit(20);
		} else if (next_arg & (CTX_RESOURCE | CTX_MINOR | CTX_ALL)) {
			if (!objname)
				objname = argv[optind];
			if (!strcmp(argv[optind], "all")) {
				if (!(next_arg & CTX_ALL))
					print_usage_and_exit("command does not accept argument 'all'");
				context |= CTX_ALL;
			} else if (next_arg & CTX_MINOR) {
				minor = dt_minor_of_dev(argv[optind]);
				if (minor == -1U && next_arg == CTX_MINOR) {
					fprintf(stderr, "Cannot determine minor device number of "
							"device '%s'\n",
						argv[optind]);
					exit(20);
				}
				context |= CTX_MINOR;
			} else
				context |= CTX_RESOURCE;
		} else {
			if (next_arg == CTX_MY_ADDR)
				my_addr_len = sockaddr_from_str(&my_addr, argv[optind]);
			else if (next_arg == CTX_PEER_ADDR)
				peer_addr_len = sockaddr_from_str(&peer_addr, argv[optind]);
			else if (next_arg == CTX_VOLUME)
				volume = m_strtoll(argv[optind], 1);
			context |= next_arg;
		}
	}

	if (objname == NULL) {
		if ((context & CTX_MY_ADDR) && (context & CTX_PEER_ADDR))
			m_asprintf(&objname, "connection %s %s", argv[2], argv[3]);  /* FIXME: Which indexes? */
		else
			objname = "all";
	}

	if ((context & CTX_MINOR) && cmd->cmd_id != DRBD_ADM_GET_STATUS)
		lock_fd = dt_lock_drbd(minor);

	/* Make it so that argv[0] is the command name. */
	optind--;
	argv[optind] = argv[1];
	rv = cmd->function(cmd, argc - optind, argv + optind);

	if ((context & CTX_MINOR) && cmd->cmd_id != DRBD_ADM_GET_STATUS)
		dt_unlock_drbd(lock_fd);
	return rv;
}
#endif
