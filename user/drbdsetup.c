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

#include <linux/netlink.h>
#include <linux/connector.h>

#include <linux/drbd.h>
#include <linux/drbd_config.h>
#include <linux/drbd_tag_magic.h>
#include <linux/drbd_limits.h>

#include "drbdtool_common.h"

#ifndef __CONNECTOR_H
#error "You need to set KDIR while building drbdsetup."
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
	int (*function)(struct drbd_cmd *, int, int, char **);
	void (*usage)(struct drbd_cmd *, enum usage_type);
	union {
		struct {
			struct drbd_argument *args;
			struct drbd_option *options;
		} cp; // for generic_config_cmd, config_usage
		struct {
			int (*show_function)(struct drbd_cmd *, int,
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
int open_cn();
int send_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size);
int receive_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size, int timeout_ms);
int call_drbd(int sk_nl, struct drbd_tag_list *tl, struct nlmsghdr* nl_hdr,
	      int size, int timeout_ms);
void close_cn(int sk_nl);

// other functions
int get_af_sci(int warn);
void print_command_usage(int i, const char *addinfo, enum usage_type);

// command functions
int generic_config_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv);
int down_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv);
int generic_get_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv);
int events_cmd(struct drbd_cmd *cm, int minor, int argc,char **argv);

// usage functions
void config_usage(struct drbd_cmd *cm, enum usage_type);
void get_usage(struct drbd_cmd *cm, enum usage_type);
void events_usage(struct drbd_cmd *cm, enum usage_type);

// sub usage functions for config_usage
int numeric_opt_usage(struct drbd_option *option, char* str, int strlen);
int handler_opt_usage(struct drbd_option *option, char* str, int strlen);
int bit_opt_usage(struct drbd_option *option, char* str, int strlen);
int string_opt_usage(struct drbd_option *option, char* str, int strlen);

// sub usage function for config_usage as xml
void numeric_opt_xml(struct drbd_option *option);
void handler_opt_xml(struct drbd_option *option);
void bit_opt_xml(struct drbd_option *option);
void string_opt_xml(struct drbd_option *option);

// sub commands for generic_get_cmd
int show_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl);
int state_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl);
int cstate_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl);
int dstate_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl);
int uuids_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl);

// convert functions for arguments
int conv_block_dev(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
int conv_address(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
int conv_protocol(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);

// convert functions for options
int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_sndbuf(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_handler(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_string(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);

// show functions for options (used by show_scmd)
void show_numeric(struct drbd_option *od, unsigned short* tp);
void show_handler(struct drbd_option *od, unsigned short* tp);
void show_bit(struct drbd_option *od, unsigned short* tp);
void show_string(struct drbd_option *od, unsigned short* tp);

// sub functions for events_cmd
int print_broadcast_events(unsigned int seq, int, struct drbd_nl_cfg_reply *reply);
int w_connected_state(unsigned int seq, int, struct drbd_nl_cfg_reply *reply);
int w_synced_state(unsigned int seq, int, struct drbd_nl_cfg_reply *reply);

const char *on_error[] = {
	[PassOn]         = "pass_on",
	[CallIOEHelper]  = "call-local-io-error",
	[Detach]         = "detach",
};

const char *fencing_n[] = {
	[DontCare] = "dont-care",
	[Resource] = "resource-only",
	[Stonith]  = "resource-and-stonith",
};

const char *asb0p_n[] = {
	[Disconnect]        = "disconnect",
	[DiscardYoungerPri] = "discard-younger-primary",
	[DiscardOlderPri]   = "discard-older-primary",
	[DiscardZeroChg]    = "discard-zero-changes",
	[DiscardLeastChg]   = "discard-least-changes",
	[DiscardLocal]      = "discard-local",
	[DiscardRemote]     = "discard-remote"
};

const char *asb1p_n[] = {
	[Disconnect]        = "disconnect",
	[Consensus]         = "consensus",
	[Violently]         = "violently-as0p",
	[DiscardSecondary]  = "discard-secondary",
	[CallHelper]        = "call-pri-lost-after-sb"
};

const char *asb2p_n[] = {
	[Disconnect]        = "disconnect",
	[Violently]         = "violently-as0p",
	[CallHelper]        = "call-pri-lost-after-sb"
};

const char *rrcf_n[] = {
	[Disconnect]        = "disconnect",
	[Violently]         = "violently",
	[CallHelper]        = "call-pri-lost"
};

struct option wait_cmds_options[] = {
	{ "wfc-timeout",required_argument, 0, 't' },
	{ "degr-wfc-timeout",required_argument,0,'d'},
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
		 { "overwrite-data-of-peer",'o',T_overwrite_peer, EB   },
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
		 CLOSE_OPTIONS }} }, },

	{"disconnect", P_disconnect, F_CONFIG_CMD, {{NULL, NULL}} },

	{"resize", P_resize, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "size",'s',T_resize_size,		EN(DISK_SIZE_SECT,'s',"bytes") },
		 CLOSE_OPTIONS }} }, },

	{"syncer", P_syncer_conf, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "rate",'r',T_rate,			EN(RATE,'k',"bytes/second") },
		 { "after",'a',T_after,			EN(AFTER,1,NULL) },
		 { "al-extents",'e',T_al_extents,	EN(AL_EXTENTS,1,NULL) },
		 { "verify-alg", 'v',T_verify_alg,      ES },
		 { "cpu-mask",'c',T_cpu_mask,           ES },
		 CLOSE_OPTIONS }} }, },

	{"invalidate", P_invalidate, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"invalidate-remote", P_invalidate_peer, F_CONFIG_CMD, {{NULL, NULL}} },
	{"pause-sync", P_pause_sync, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"resume-sync", P_resume_sync, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"suspend-io", P_suspend_io, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"resume-io", P_resume_io, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"outdate", P_outdate, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"verify", P_start_ov, F_CONFIG_CMD, {{NULL, NULL}} },
	{"down",            0, down_cmd, get_usage, { {NULL, NULL }} },
	{"state", P_get_state, F_GET_CMD, { .gp={ state_scmd} } },
	{"cstate", P_get_state, F_GET_CMD, {.gp={ cstate_scmd} } },
	{"dstate", P_get_state, F_GET_CMD, {.gp={ dstate_scmd} } },
	{"show-gi", P_get_uuids, F_GET_CMD, {.gp={ uuids_scmd} }},
	{"get-gi", P_get_uuids, F_GET_CMD, {.gp={ uuids_scmd} } },
	{"show", P_get_config, F_GET_CMD, {.gp={ show_scmd} } },
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

#define EM(C) [ C - RetCodeBase ]

static const char *error_messages[] = {
	EM(NoError) = "No further Information available.",
	EM(LAAlreadyInUse) = "Local address(port) already in use.",
	EM(OAAlreadyInUse) = "Remote address(port) already in use.",
	EM(LDNameInvalid) = "Can not open backing device.",
	EM(MDNameInvalid) = "Can not open meta device.",
	EM(LDAlreadyInUse) = "Lower device already in use.",
	EM(LDNoBlockDev) = "Lower device is not a block device.",
	EM(MDNoBlockDev) = "Meta device is not a block device.",
	EM(LDOpenFailed) = "Open of lower device failed.",
	EM(MDOpenFailed) = "Open of meta device failed.",
	EM(LDDeviceTooSmall) = "Low.dev. smaller than requested DRBD-dev. size.",
	EM(MDDeviceTooSmall) = "Meta device too small.",
	EM(LDNoConfig) = "You have to use the disk command first.",
	EM(LDMounted) = "Lower device is already claimed. This usually means it is mounted.",
	EM(MDMounted) = "Meta device is already claimed. This usually means it is mounted.",
	EM(LDMDInvalid) = "Lower device / meta device / index combination invalid.",
	EM(LDDeviceTooLarge) = "Currently we only support devices up to 3.998TB.\n"
	"(up to 2TB in case you do not have CONFIG_LBD set)\n"
	"Contact office@linbit.com, if you need more.",
	EM(MDIOError) = "IO error(s) occurred during initial access to meta-data.\n",
	EM(MDInvalid) = "No valid meta-data signature found.\n\n"
	"\t==> Use 'drbdadm create-md res' to initialize meta-data area. <==\n",
	EM(CRAMAlgNotAvail) = "The 'cram-hmac-alg' you specified is not known in "
	"the kernel. (Maybe you need to modprobe it, or modprobe hmac?)",
	EM(CRAMAlgNotDigest) = "The 'cram-hmac-alg' you specified is not a digest.",
	EM(KMallocFailed) = "kmalloc() failed. Out of memory?",
	EM(DiscardNotAllowed) = "--discard-my-data not allowed when primary.",
	EM(HaveDiskConfig) = "Device is attached to a disk (use detach first)",
	EM(HaveNetConfig) = "Device has a net-config (use disconnect first)",
	EM(UnknownMandatoryTag) = "UnknownMandatoryTag",
	EM(MinorNotKnown) = "Device minor not allocated",
	EM(StateNotAllowed) = "Resulting device state would be invalid",
	EM(GotSignal) = "Interrupted by Signal",
	EM(NoResizeDuringResync) = "Resize not allowed during resync.",
	EM(APrimaryNodeNeeded) = "Need one Primary node to resize.",
	EM(SyncAfterInvalid) = "The sync-after minor number is invalid",
	EM(SyncAfterCycle) = "This would cause a sync-after dependency cycle",
	EM(PauseFlagAlreadySet) = "Sync-pause flag is already set",
	EM(PauseFlagAlreadyClear) = "Sync-pause flag is already cleared",
	EM(DiskLowerThanOutdated) = "Disk state is lower than outdated",
	EM(HaveNoDiskConfig) = "Device does not have a disk-config",
	EM(ProtocolCRequired) = "Protocol C required",
	EM(VMallocFailed) = "vmalloc() failed. Out of memory?",
	EM(IntegrityAlgNotAvail) = "The 'data-integrity-alg' you specified is not known in "
	"the kernel. (Maybe you need to modprobe it, or modprobe hmac?)",
	EM(IntegrityAlgNotDigest) = "The 'data-integrity-alg' you specified is not a digest.",
	EM(CPUMaskParseFailed) = "Invalid cpu-mask.",
	EM(VERIFYAlgNotAvail) = "VERIFYAlgNotAvail",
	EM(VERIFYAlgNotDigest) = "VERIFYAlgNotDigest",
	EM(VERIFYIsRunning) = "Can not change verify-alg while online verify runs",
	EM(DataOfWrongCurrent) = "Can only attach to the data we lost last (see kernel log).",
};
#define MAX_ERROR (sizeof(error_messages)/sizeof(*error_messages))
const char * error_to_string(int err_no)
{
	const unsigned int idx = err_no - RetCodeBase;
	if (idx >= MAX_ERROR) return "Unknown... maybe API_VERSION mismatch?";
	return error_messages[idx];
}
#undef MAX_ERROR

char *cmdname = NULL; /* "drbdsetup" for reporting in usage etc. */
char *devname = NULL; /* "/dev/drbd12" for reporting in print_config_error */
int debug_dump_argv = 0; /* enabled by setting DRBD_DEBUG_DUMP_ARGV in the environment */
int lock_fd;

int dump_tag_list(unsigned short *tlc)
{
	enum drbd_tags tag;
	unsigned int tag_nr;
	int len;
	int integer;
	char bit;
	__u64 int64;
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
			int64 = *(__u64*)tlc;
			printf("(int64) %lld",(long long)int64);
			break;
		case TT_BIT:
			bit = *(char*)tlc;
			printf("(bit) %s", bit ? "on" : "off");
			break;
		case TT_STRING:
			string = (char*)tlc;
			printf("(string)'%s'",string);
			break;
		}
		printf(" \t[len: %u]\n",len);
	skip:
		tlc = (unsigned short*)((char*)tlc + len);
	}

	return found_unknown;
}

struct drbd_tag_list *create_tag_list(int size)
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

void add_tag(struct drbd_tag_list *tl, int tag, void *data, int data_len)
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
	*tl->tag_list_cpos++ = tag;
	*tl->tag_list_cpos++ = data_len;
	memcpy(tl->tag_list_cpos,data,data_len);
	tl->tag_list_cpos = (unsigned short*)((char*)tl->tag_list_cpos + data_len);
}

void free_tag_list(struct drbd_tag_list *tl)
{
	free(tl->nl_header);
	free(tl);
}

int conv_block_dev(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
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

	return NoError;
}

int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = DRBD_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flexible")) idx = DRBD_MD_INDEX_FLEX_EXT;
	else idx = m_strtoll(arg,1);

	add_tag(tl,ad->tag,&idx,sizeof(idx));

	return NoError;
}

const char* addr_part(const char* s)
{
	static char buffer[200];
	char *b;

	b=strchr(s,':');
	if(b) {
		strncpy(buffer,s,b-s);
		buffer[b-s]=0;
		return buffer;
	}
	return s;
}

int port_part(const char* s)
{
	char *b;

	b=strchr(s,':');

	// m_strtoll_range(b+1,1, "port", DRBD_PORT_MIN, DRBD_PORT_MAX);
	if(b) return m_strtoll(b+1,1);
	return 7788;
}

void resolv6(char *name, struct in6_addr *addr)
{
	int rv;
	struct hostent *he;

	rv = inet_pton(AF_INET6, name, addr);
	if (rv > 0)
		return;
	else if (rv == 0) {
		he = gethostbyname2(name, AF_INET6);
		if (!he) {
			PERROR("can not resolv the hostname");
			exit(20);
		}
		memcpy(addr, he->h_addr_list[0], sizeof(struct in6_addr));
	}
}

unsigned long resolv(const char* name)
{
	unsigned long retval;

	if((retval = inet_addr(name)) == INADDR_NONE ) {
		struct hostent *he;
		he = gethostbyname(name);
		if (!he) {
			PERROR("can not resolv the hostname");
			exit(20);
		}
		retval = ((struct in_addr *)(he->h_addr_list[0]))->s_addr;
	}
	return retval;
}

static void split_address(char* text, int *af, char** address, int* port)
{
	static struct { char* text; int af; } afs[] = {
		{ "ipv4:", AF_INET  },
		{ "ipv6:", AF_INET6 },
		{ "sci:",  -1 },
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
	if (*af == -1)
		*af = get_af_sci(1);

	b=strrchr(text,':');
	if (b) {
		*b = 0;
		*port = m_strtoll(b+1,1);
	} else
		*port = 7788;
}

int conv_address(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	static int mind_af_set = 0;
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	int af, port;
	char *address, bit=1;

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
		addr6.sin6_port = htons(port);
		addr6.sin6_family = AF_INET6;
		resolv6(address, &addr6.sin6_addr);
		/* addr6.sin6_len = sizeof(addr6); */
		add_tag(tl,ad->tag,&addr6,sizeof(addr6));
	} else {
		/* AF_INET and AF_SCI */
		addr.sin_port = htons(port);
		addr.sin_family = af;
		addr.sin_addr.s_addr = resolv(address);
		add_tag(tl,ad->tag,&addr,sizeof(addr));
	}

	return NoError;
}

int conv_protocol(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
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

	return NoError;
}

int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg __attribute((unused)))
{
	char bit=1;

	add_tag(tl,od->tag,&bit,sizeof(bit));

	return NoError;
}

/* It will only print the WARNING if the warn flag is set
   with the _first_ call! */
#define PROC_NET_AF_SCI_FAMILY "/proc/net/af_sci/family"
int get_af_sci(int warn)
{
	char buf[16];
	int c, fd;
	static int af = -1;

	if (af > 0)
		return af;

	fd = open(PROC_NET_AF_SCI_FAMILY, O_RDONLY);
	if (fd < 0) {
		if (warn)
			fprintf(stderr, "open(" PROC_NET_AF_SCI_FAMILY ") "
				"failed: %m\n WARNING: assuming AF_SCI = 27. "
				"Socket creation will probabely fail.\n");
		af = 27;
		return af;
	}
	c = read(fd, buf, sizeof(buf)-1);
	if (c > 0) {
		buf[c] = 0;
		if (buf[c-1] == '\n')
			buf[c-1] = 0;
		af = m_strtoll(buf,1);
	} else {
		if (warn)
			fprintf(stderr, "read(" PROC_NET_AF_SCI_FAMILY ") "
				"failed: %m\n WARNING: assuming AF_SCI = 27. "
				"Socket creation will probabely fail.\n");
		af = 27;
	}
	close(fd);
	return af;
}

int conv_sndbuf(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	int err = conv_numeric(od, tl, arg);
	long long l = m_strtoll(arg, 0);
	char bit = 1;

	if (err != NoError || l != 0)
		return err;
	/* this is a mandatory bit,
	 * to avoid newer userland to configure older modules with
	 * a sndbuf size of zero, which would lead to Oops. */
	add_tag(tl, T_auto_sndbuf_size, &bit, sizeof(bit));
	return NoError;
}

int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
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
	return NoError;
}

int conv_handler(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	const char** handler_names = od->handler_param.handler_names;
	const int number_of_handlers = od->handler_param.number_of_handlers;
	int i;

	for(i=0;i<number_of_handlers;i++) {
		if(handler_names[i]==NULL) continue;
		if(strcmp(arg,handler_names[i])==0) {
			add_tag(tl,od->tag,&i,sizeof(i));
			return NoError;
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

int conv_string(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	add_tag(tl,od->tag,arg,strlen(arg)+1);

	return NoError;
}


struct option *	make_longoptions(struct drbd_option* od)
{
	/* room for up to N options,
	 * plus set-defaults, create-device, and the terminating NULL */
#define N 20
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

struct drbd_option *find_opt_by_short_name(struct drbd_option *od, int c)
{
	if(!od) return NULL;
	while(od->name) {
		if(od->short_name == c) return od;
		od++;
	}

	return NULL;
}

/* prepends global devname to output (if any) */
int print_config_error(int err_no)
{
	int rv=0;

	if (err_no == NoError || err_no == SS_Success)
		return 0;
	if (err_no == OTHER_ERROR)
		return 20;

	if ( ( err_no >= AfterLastRetCode || err_no <= RetCodeBase ) &&
	     ( err_no > SS_CW_NoNeed || err_no < SS_NotSupported) ) {
		fprintf(stderr,"Error code %d unknown.\n"
			"You should update the drbd userland tools.\n",err_no);
		rv = 20;
	} else {
		if(err_no > RetCodeBase ) {
			fprintf(stderr,"%s: Failure: (%d) %s\n",
				devname, err_no, error_to_string(err_no));
			rv = 10;
		} else if (err_no == SS_UnknownError) {
			fprintf(stderr,"%s: State change failed: (%d)"
				"unknown error.\n", devname, err_no);
			rv = 11;
		} else if (err_no > SS_TwoPrimaries) {
			// Ignore SS_Success, SS_NothingToDo, SS_CW_Success...
		} else {
			fprintf(stderr,"%s: State change failed: (%d) %s\n",
				devname, err_no, set_st_err_name(err_no));
			if (err_no == SS_NoUpToDateDisk) {
				/* am Primary, cannot outdate */
				rv = 17;
			} else if (err_no == SS_LowerThanOutdated) {
				/* was inconsistent anyways */
				rv = 5;
			} else {
				rv = 11;
			}
		}
	}
	return rv;
}

#define RCV_SIZE NLMSG_SPACE(sizeof(struct cn_msg)+sizeof(struct drbd_nl_cfg_reply))

/* cmdname and optind are global variables */
void warn_unrecognized_option(char **argv)
{
	fprintf(stderr, "%s %s: unrecognized option '%s'\n",
		cmdname, argv[0], argv[optind - 1]);
}

void warn_missing_required_arg(char **argv)
{
	fprintf(stderr, "%s %s: option '%s' requires an argument\n",
		cmdname, argv[0], argv[optind - 1]);
}

void warn_print_excess_args(int argc, char **argv, int i)
{
	fprintf(stderr, "Ignoring excess arguments:");
	for (; i < argc; i++)
		fprintf(stderr, " %s", argv[i]);
	printf("\n");
}

void dump_argv(int argc, char **argv, int first_non_option, int n_known_args)
{
	int i;
	if (!debug_dump_argv)
		return;
	printf(",-- ARGV dump (optind %d, known_args %d, argc %u):\n",
		first_non_option, n_known_args, argc);
	for (i = 0; i < argc; i++) {
		if (i == 1)
			puts("-- consumed options:");
		if (i == first_non_option)
			puts("-- known args:");
		if (i == (first_non_option + n_known_args))
			puts("-- unexpected args:");
		printf("| %2u: %s\n", i, argv[i]);
	}
	printf("`--\n");
}

int _generic_config_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv)
{
	char buffer[ RCV_SIZE ];
	struct drbd_nl_cfg_reply *reply;
	struct drbd_argument *ad = cm->cp.args;
	struct drbd_option *od;
	struct option *lo;
	struct drbd_tag_list *tl;
	int c,i=1,rv=NoError,sk_nl;
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
		if (rv != NoError)
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
		if (rv != NoError)
			goto error;
	}

	/* argc should be cmd + n options + n args;
	 * if it is more, we did not understand some */
	if (n_args + optind < argc)
		warn_print_excess_args(argc, argv, optind + n_args);

	dump_argv(argc, argv, optind, i - 1);

	add_tag(tl,TT_END,NULL,0); // close the tag list

	if(rv == NoError) {
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

int generic_config_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv)
{
	return print_config_error(_generic_config_cmd(cm, minor, argc, argv));
}

#define ASSERT(exp) if (!(exp)) \
		fprintf(stderr,"ASSERT( " #exp " ) in %s:%d\n", __FILE__,__LINE__);

void show_af(struct drbd_option *od, unsigned short* tp)
{
	int af_sci = get_af_sci(0);
	int val;
	const char *msg;

	ASSERT(tag_type(*tp++) == TT_INTEGER);
	ASSERT( *tp++ == sizeof(int) );
	val = *(int*)tp;

	msg = (val == af_sci) ? "sci" :
	      (val == AF_INET) ? "IPv4" :
	      "UNKNOWN";
	printf("\t%-16s\t%s", od->name, msg);
	if (val == AF_INET) printf(" _is_default");
	if (val != AF_INET && val != af_sci)
		printf("; # %u ??\n", val);
	else
		printf(";\n");
}

void show_numeric(struct drbd_option *od, unsigned short* tp)
{
	long long val;
	const unsigned char unit_prefix = od->numeric_param.unit_prefix;

	switch(tag_type(*tp++)) {
	case TT_INTEGER:
		ASSERT( *tp++ == sizeof(int) );
		val = *(int*)tp;
		break;
	case TT_INT64:
		ASSERT( *tp++ == sizeof(__u64) );
		val = *(__u64*)tp;
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

void show_handler(struct drbd_option *od, unsigned short* tp)
{
	const char** handler_names = od->handler_param.handler_names;
	int i;

	ASSERT( tag_type(*tp++) == TT_INTEGER );
	ASSERT( *tp++ == sizeof(int) );
	i = *(int*)tp;
	printf("\t%-16s\t%s",od->name,handler_names[i]);
	if( i == (long long)od->numeric_param.def) printf(" _is_default");
	printf(";\n");
}

void show_bit(struct drbd_option *od, unsigned short* tp)
{
	ASSERT( tag_type(*tp++) == TT_BIT );
	ASSERT( *tp++ == sizeof(char) );
	if(*(char*)tp) printf("\t%-16s;\n",od->name);
}

void show_string(struct drbd_option *od, unsigned short* tp)
{
	ASSERT( tag_type(*tp++) == TT_STRING );
	if( *tp++ > 0) printf("\t%-16s\t\"%s\";\n",od->name,(char*)tp);
}

unsigned short *look_for_tag(unsigned short *tlc, unsigned short tag)
{
	enum drbd_tags t;
	int len;

	while( (t = *tlc) != TT_END ) {
		if(t == tag) return tlc;
		tlc++;
		len = *tlc++;
		tlc = (unsigned short*)((char*)tlc + len);
	}
	return NULL;
}

void print_options(struct drbd_option *od, unsigned short *tlc, const char* sect_name)
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
			*tp = TT_REMOVED;
		}
		od++;
	}
	if(opened) {
		printf("}\n");
	}
}


int consume_tag_blob(enum drbd_tags tag, unsigned short *tlc,
		     char** val, unsigned int* len)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		*len = *tp++;
		*val = (char*)tp;
		return 1;
	}
	return 0;
}

int consume_tag_string(enum drbd_tags tag, unsigned short *tlc, char** val)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		if( *tp++ > 0 )
			*val = (char*)tp;
		else
			*val = "";
		return 1;
	}
	return 0;
}

int consume_tag_int(enum drbd_tags tag, unsigned short *tlc, int* val)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		tp++;
		*val = *(int *)tp;
		return 1;
	}
	return 0;
}

int consume_tag_u64(enum drbd_tags tag, unsigned short *tlc, unsigned long long* val)
{
	unsigned short *tp;
	unsigned short len;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		len = *tp++;
		/* check the data size.
		 * actually it has to be long long, but I'm paranoid */
		if (len == sizeof(int))
			*val = *(unsigned int*)tp;
		else if (len == sizeof(long))
			*val = *(unsigned long *)tp;
		else if (len == sizeof(long long))
			*val = *(unsigned long long *)tp;
		else {
			fprintf(stderr, "%s: unexpected tag len: %u\n",
					__func__ , len);
			return 0;
		}
		return 1;
	}
	return 0;
}

int consume_tag_bit(enum drbd_tags tag, unsigned short *tlc, int* val)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		tp++;
		*val = (int)(*(char *)tp);
		return 1;
	}
	return 0;
}

int generic_get_cmd(struct drbd_cmd *cm, int minor, int argc,
		    char **argv __attribute((unused)))
{
	char buffer[ 4096 ];
	struct drbd_tag_list *tl;
	struct drbd_nl_cfg_reply *reply;
	int sk_nl,rv;

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

	call_drbd(sk_nl,tl, (struct nlmsghdr*)buffer,4096,NL_TIME);

	close_cn(sk_nl);
	reply = (struct drbd_nl_cfg_reply *)
		((struct cn_msg *)NLMSG_DATA(buffer))->data;

	if (reply->ret_code != NoError)
		return print_config_error(reply->ret_code);

	rv = cm->gp.show_function(cm,minor,reply->tag_list);

	if(dump_tag_list(reply->tag_list)) {
		printf("# Found unknown tags, you should update your\n"
		       "# userland tools\n");
	}

	return rv;
}

char *af_to_str(int af)
{
	if (af == AF_INET)
		return "ipv4";
	else if (af == AF_INET6)
		return "ipv6";
	else if (af == get_af_sci(0))
		return "sci";
	else return "unknown";
}

void show_address(void* address, int addr_len)
{
	struct sockaddr     *addr;
	struct sockaddr_in  *addr4;
	struct sockaddr_in6 *addr6;
	char buffer[INET6_ADDRSTRLEN];

	addr = (struct sockaddr *)address;
	if (addr->sa_family == AF_INET || addr->sa_family == get_af_sci(0)) {
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

int show_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl)
{
	int idx;
	char *str, *backing_dev, *address;
	unsigned int addr_len;

	// find all commands that have options and print those...
	for ( cm = commands ; cm < commands + ARRY_SIZE(commands) ; cm++ ) {
		if(cm->function == generic_config_cmd && cm->cp.options )
			print_options(cm->cp.options, rtl, cm->cmd);
	}

	// start of spagethi code...
	if(consume_tag_int(T_wire_protocol,rtl,&idx))
		printf("protocol %c;\n",'A'+idx-1);
	backing_dev = address = NULL;
	consume_tag_string(T_backing_dev,rtl,&backing_dev);
	consume_tag_blob(T_my_addr, rtl, &address, &addr_len);
	if(backing_dev || address) {
		printf("_this_host {\n");
		printf("\tdevice\t\t\t\"/dev/drbd%d\";\n",minor);
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

	return 0;
}

int state_scmd(struct drbd_cmd *cm __attribute((unused)),
	       int minor __attribute((unused)),
	       unsigned short *rtl)
{
	union drbd_state_t state;
	consume_tag_int(T_state_i,rtl,(int*)&state.i);
	if ( state.conn == StandAlone &&
	     state.disk == Diskless) {
		printf("Unconfigured\n");
	} else {
		printf("%s/%s\n",roles_to_name(state.role),roles_to_name(state.peer));
	}
	return 0;
}

int cstate_scmd(struct drbd_cmd *cm __attribute((unused)),
		int minor __attribute((unused)),
		unsigned short *rtl)
{
	union drbd_state_t state;
	consume_tag_int(T_state_i,rtl,(int*)&state.i);
	if ( state.conn == StandAlone &&
	     state.disk == Diskless) {
		printf("Unconfigured\n");
	} else {
		printf("%s\n",conns_to_name(state.conn));
	}
	return 0;
}

int dstate_scmd(struct drbd_cmd *cm __attribute((unused)),
		int minor __attribute((unused)),
		unsigned short *rtl)
{
	union drbd_state_t state;
	consume_tag_int(T_state_i,rtl,(int*)&state.i);
	if ( state.conn == StandAlone &&
	     state.disk == Diskless) {
		printf("Unconfigured\n");
	} else {
		printf("%s/%s\n",disks_to_name(state.disk),disks_to_name(state.pdsk));
	}
	return 0;
}

int uuids_scmd(struct drbd_cmd *cm,
	       int minor __attribute((unused)),
	       unsigned short *rtl)
{
	__u64 *uuids;
	int flags;
	unsigned int len;

	if(!consume_tag_blob(T_uuids,rtl,(char **) &uuids,&len)) {
		fprintf(stderr,"Reply payload did not carry an uuid-tag,\n"
			"Probabely the device has no disk!\n");
		return 1;
	}
	consume_tag_int(T_uuids_flags,rtl,&flags);
	if( len == UUID_SIZE * sizeof(__u64)) {
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

static struct drbd_cmd *find_cmd_by_name(const char* name)
{
	unsigned int i;

	for(i=0;i<ARRY_SIZE(commands);i++) {
		if(!strcmp(name,commands[i].cmd)) {
			return commands+i;
		}
	}
	return NULL;
}

int down_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv)
{
	int rv;
	int success;

	if(argc > 1) {
		fprintf(stderr,"Ignoring excess arguments\n");
	}

	cm = find_cmd_by_name("secondary");
	rv = _generic_config_cmd(cm, minor, argc, argv); // No error messages
	if (rv == MinorNotKnown)
		return 0;
	success = (rv >= SS_Success && rv < RetCodeBase) || rv == NoError;
	if (!success)
		return print_config_error(rv);
	cm = find_cmd_by_name("disconnect");
	cm->function(cm,minor,argc,argv);
	cm = find_cmd_by_name("detach");
	return cm->function(cm,minor,argc,argv);
}


void print_digest(const char* label, const int len, const unsigned char *hash)
{
	int i;
	printf("\t%s: ", label);
	for (i = 0; i < len; i++)
		printf("%02x",hash[i]);
	printf("\n");
}

static inline char printable_or_dot(char c)
{
	return (' ' < c && c <= '~') ? c : '.';
}

void print_hex_line(int offset, unsigned char *data)
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
void print_hex_dump(int len, void *data)
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

void print_dump_ee(struct drbd_nl_cfg_reply *reply)
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

int print_broadcast_events(unsigned int seq, int u __attribute((unused)),
			   struct drbd_nl_cfg_reply *reply)
{
	union drbd_state_t state;
	char* str;
	int synced = 0;

	/* Ignore error replies */
	if (reply->ret_code != NoError)
		return 1;

	switch (reply->packet_type) {
	case P_get_state:
		if(consume_tag_int(T_state_i,reply->tag_list,(int*)&state.i)) {
			printf("%u ST %d { cs:%s st:%s/%s ds:%s/%s %c%c%c%c }\n",
			       seq,
			       reply->minor,
			       conns_to_name(state.conn),
			       roles_to_name(state.role),
			       roles_to_name(state.peer),
			       disks_to_name(state.disk),
			       disks_to_name(state.pdsk),
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
		printf("%u ?? %d <other message>\n",seq, reply->minor);
		break;
	}

	fflush(stdout);

	return 1;
}

int w_connected_state(unsigned int seq __attribute((unused)),
		      int wait_after_sb,
		      struct drbd_nl_cfg_reply *reply)
{
	union drbd_state_t state;

	if(reply->packet_type == P_get_state) {
		if(consume_tag_int(T_state_i,reply->tag_list,(int*)&state.i)) {
			if(state.conn >= Connected) return 0;
			if(!wait_after_sb && state.conn < Unconnected) return 0;
		} else fprintf(stderr,"Missing tag !?\n");
	}

	return 1;
}

int w_synced_state(unsigned int seq __attribute((unused)),
		   int wait_after_sb,
		   struct drbd_nl_cfg_reply *reply)
{
	union drbd_state_t state;

	if(reply->packet_type == P_get_state) {
		if(consume_tag_int(T_state_i,reply->tag_list,(int*)&state.i)) {
			if(state.conn == Connected) return 0;
			if(!wait_after_sb && state.conn < Unconnected) return 0;
		} else fprintf(stderr,"Missing tag !?\n");
	}
	return 1;
}

int events_cmd(struct drbd_cmd *cm, int minor, int argc ,char **argv)
{
	void *buffer;
	struct cn_msg *cn_reply;
	struct drbd_nl_cfg_reply *reply;
	struct drbd_tag_list *tl;
	struct option *lo;
	unsigned int seq=0;
	int sk_nl,c,cont=1,rr,i,last;
	int unfiltered=0, all_devices=0;
	int wfc_timeout=0, degr_wfc_timeout=0,timeout_ms;
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

	// Find out which timeout value to use.
	tl->drbd_p_header->packet_type = P_get_timeout_flag;
	tl->drbd_p_header->drbd_minor = minor;
	tl->drbd_p_header->flags = 0;

	/* allocate 64k to be on the safe side. */
#define NL_BUFFER_SIZE (64 << 10)
	buffer = malloc(NL_BUFFER_SIZE);
	if (!buffer) {
		fprintf(stderr, "could not allocate buffer of %u bytes\n", NL_BUFFER_SIZE);
		exit(20);
	}

	call_drbd(sk_nl,tl, buffer, NL_BUFFER_SIZE, NL_TIME);

	cn_reply = (struct cn_msg *)NLMSG_DATA(buffer);
	reply = (struct drbd_nl_cfg_reply *)cn_reply->data;
	consume_tag_bit(T_use_degraded,reply->tag_list,&rr);
	if (rr) {
		if (0 < wfc_timeout &&
		      (wfc_timeout < degr_wfc_timeout
				  || degr_wfc_timeout == 0)) {
			degr_wfc_timeout = wfc_timeout;
			fprintf(stderr, "degr-wfc-timeout has to be shorter than wfc-timeout\n"
					"degr-wfc-timeout implicitly set to wfc-timeout (%ds)\n",
					degr_wfc_timeout);
		}
	}

	timeout_ms= 1000 * (  rr ? degr_wfc_timeout : wfc_timeout) - 1;

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

		if(!unfiltered && cn_reply->seq <= seq) continue;
		seq = cn_reply->seq;

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

int numeric_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c} %lld ... %lld]",
			option->name, option->short_name,
			option->numeric_param.min,
			option->numeric_param.max);
}

int handler_opt_usage(struct drbd_option *option, char* str, int strlen)
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

int bit_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c}]",
			option->name, option->short_name);
}

int string_opt_usage(struct drbd_option *option, char* str, int strlen)
{
	return snprintf(str,strlen," [{--%s|-%c} <str>]",
			option->name, option->short_name);
}

void af_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"addrfamily\">\n",option->name);
	printf("\t\t<addrfamily>%s</addrfamily>\n", "IPv4");
	printf("\t\t<addrfamily>%s</addrfamily>\n", "SCI");
	printf("\t</option>\n");
}

void numeric_opt_xml(struct drbd_option *option)
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

void handler_opt_xml(struct drbd_option *option)
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

void bit_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"boolean\">\n",option->name);
	printf("\t</option>\n");
}

void string_opt_xml(struct drbd_option *option)
{
	printf("\t<option name=\"%s\" type=\"string\">\n",option->name);
	printf("\t</option>\n");
}


void config_usage(struct drbd_cmd *cm, enum usage_type ut)
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

void get_usage(struct drbd_cmd *cm, enum usage_type ut)
{
	if(ut == BRIEF) {
		printf(" %-39s", cm->cmd);
	} else {
		printf(" %s\n", cm->cmd);
	}
}

void events_usage(struct drbd_cmd *cm, enum usage_type ut)
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

void print_command_usage(int i, const char *addinfo, enum usage_type ut)
{
	if(ut != XML) printf("USAGE:\n");
	commands[i].usage(commands+i,ut);

	if (addinfo) {
		printf("%s\n",addinfo);
		exit(20);
	}
}

void print_usage(const char* addinfo)
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

int open_cn()
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
	my_nla.nl_groups = -1; //CN_IDX_DRBD;
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


void prepare_nl_header(struct nlmsghdr* nl_hdr, int size)
{
	static __u32 cn_seq = 1;
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
	cn_hdr->id.idx = CN_IDX_DRBD;
	cn_hdr->seq = cn_seq++;
	get_random_bytes(&cn_hdr->ack,sizeof(cn_hdr->ack));
	cn_hdr->len = size - sizeof(struct nlmsghdr) - sizeof(struct cn_msg);
}


int send_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size)
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

int receive_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size, int timeout_ms)
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

int call_drbd(int sk_nl, struct drbd_tag_list *tl, struct nlmsghdr* nl_hdr,
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

void close_cn(int sk_nl)
{
	close(sk_nl);
}

void ensure_drbd_driver_is_present(void)
{
	struct drbd_tag_list *tl;
	char buffer[4096];
	int sk_nl, rr;

	sk_nl = open_cn();
	/* Might print:
	   Missing privileges? You should run this as root.
	   Connector module not loaded? try 'modprobe cn'. */
	if (sk_nl < 0) exit(20);

	tl = create_tag_list(2);
	add_tag(tl, TT_END, NULL, 0); // close the tag list

	tl->drbd_p_header->packet_type = P_get_state;
	tl->drbd_p_header->drbd_minor = 0;
	tl->drbd_p_header->flags = 0;

	rr = call_drbd(sk_nl, tl, (struct nlmsghdr*)buffer, 4096, 500);
	/* Might print: (after 500ms)
	   No response from the DRBD driver! Is the module loaded? */
	close_cn(sk_nl);
	if (rr == -2) exit(20);
}

int main(int argc, char** argv)
{
	int minor;
	struct drbd_cmd *cmd;
	int rv=0;

	chdir("/");

	if ( (cmdname = strrchr(argv[0],'/')) )
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

	ensure_drbd_driver_is_present();

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
