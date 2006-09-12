/*
   drbdsetup.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2006, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2006, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2001-2006, LINBIT Information Technologies GmbH.

   Copyright (C) 2000, Fábio Olivé Leite <olive@conectiva.com.br>.
        Added sanity checks before using the device.

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
	union {
		struct {
			const long long min;
			const long long max;
			const long long def;
			const unsigned char default_unit;
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
	void (*usage)(struct drbd_cmd *, int );
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
			int (*proc_event)();
		} ep; // for events_cmd, events_usage
	};
};


// Connector functions
int open_cn();
int send_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size);
int send_tag_list_cn(int, struct drbd_tag_list *, const int, int, int);
int receive_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size);
void close_cn(int sk_nl);

// other functions
void print_command_usage(int i, const char *addinfo);

// command functions
int generic_config_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv);
int down_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv);
int generic_get_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv);
int events_cmd(struct drbd_cmd *cm, int minor, int argc,char **argv);

// usage functions 
void config_usage(struct drbd_cmd *cm, int);
void get_usage(struct drbd_cmd *cm, int);
void events_usage(struct drbd_cmd *cm, int);

// sub usage functions for config_usage
int numeric_opt_usage(struct drbd_option *option, char* str, int strlen);
int handler_opt_usage(struct drbd_option *option, char* str, int strlen);
int bit_opt_usage(struct drbd_option *option, char* str, int strlen);
int string_opt_usage(struct drbd_option *option, char* str, int strlen);

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
int conv_handler(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_string(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);

// show functions for options (used by show_scmd)
void show_numeric(struct drbd_option *od, unsigned short* tp);
void show_handler(struct drbd_option *od, unsigned short* tp);
void show_bit(struct drbd_option *od, unsigned short* tp);
void show_string(struct drbd_option *od, unsigned short* tp);

// sub functions for events_cmd
int print_state(unsigned int seq, int minor, drbd_state_t ns);
int w_connected_state(unsigned int seq, int minor, drbd_state_t ns);
int w_synced_state(unsigned int seq, int minor, drbd_state_t ns);

const char *on_error[] = {
	[PassOn] = "pass_on",
	[Panic]  = "panic",
	[Detach] = "detach",
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
	[DiscardLeastChg]   = "discard-least-changes",
	[DiscardLocal]      = "discard-local",
	[DiscardRemote]     = "discard-remote"
};

const char *asb1p_n[] = {
	[Disconnect]        = "disconnect",
	[Consensus]         = "consensus",
	[DiscardSecondary]  = "discard-secondary",
	[PanicPrimary]      = "panic-primary"
};

const char *asb2p_n[] = {
	[Disconnect]        = "disconnect",
	[PanicPrimary]      = "panic"
};

struct option wait_cmds_options[] = {
	{ "wfc-timeout",required_argument, 0, 't' },
	{ "degr-wfc-timeout",required_argument,0,'d'},
	{ 0,            0,           0,  0  } 
};

#define EN(N,U) \
	conv_numeric, show_numeric, numeric_opt_usage, \
	{ .numeric_param = { DRBD_ ## N ## _MIN, DRBD_ ## N ## _MAX, \
		DRBD_ ## N ## _DEF ,U  } }
#define EH(N,D) \
	conv_handler, show_handler, handler_opt_usage, \
	{ .handler_param = { N, ARRY_SIZE(N), \
	DRBD_ ## D ## _DEF } }
#define EB      conv_bit, show_bit, bit_opt_usage, { } 
#define ES      conv_string, show_string, string_opt_usage, { } 
#define CLOSE_OPTIONS  { NULL,0,0,NULL,NULL,NULL, { } }

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
		 { "size",'d',		T_disk_size,	EN(DISK_SIZE_SECT,'s') },
		 { "on-io-error",'e',	T_on_io_error,	EH(on_error,ON_IO_ERROR) },
		 { "fencing",'f',	T_fencing,      EH(fencing_n,FENCING) },
		 CLOSE_OPTIONS }} }, },

	{"detach", P_detach, F_CONFIG_CMD, {{NULL, NULL}} },

	{"net", P_net_conf, F_CONFIG_CMD, {{
	 (struct drbd_argument[]) {
		 { "local_addr",	T_my_addr,	conv_address },
		 { "remote_addr",	T_peer_addr,	conv_address },
		 { "protocol",		T_wire_protocol,conv_protocol },
 		 { NULL,                0,           	NULL}, },
	 (struct drbd_option[]) {
		 { "timeout",'t',	T_timeout,	EN(TIMEOUT,1) },
		 { "max-epoch-size",'e',T_max_epoch_size,EN(MAX_EPOCH_SIZE,1) },
		 { "max-buffers",'b',	T_max_buffers,	EN(MAX_BUFFERS,1) },
		 { "unplug-watermark",'u',T_unplug_watermark, EN(UNPLUG_WATERMARK,1) },
		 { "connect-int",'c',	T_try_connect_int, EN(CONNECT_INT,1) },
		 { "ping-int",'i',	T_ping_int,	   EN(PING_INT,1) },
		 { "sndbuf-size",'S',	T_sndbuf_size,	   EN(SNDBUF_SIZE,1) },
		 { "ko-count",'k',	T_ko_count,	   EN(KO_COUNT,1) },
		 { "allow-two-primaries",'m',T_two_primaries, EB },
		 { "cram-hmac-alg",'a',	T_cram_hmac_alg,   ES },
		 { "shared-secret",'x',	T_shared_secret,   ES },
		 { "after-sb-0pri",'A',	T_after_sb_0p,EH(asb0p_n,AFTER_SB_0P) },
		 { "after-sb-1pri",'B',	T_after_sb_1p,EH(asb1p_n,AFTER_SB_1P) },
		 { "after-sb-2pri",'C',	T_after_sb_2p,EH(asb2p_n,AFTER_SB_2P) },
		 { "discard-my-data",'D', T_want_lose,     EB },
		 CLOSE_OPTIONS }} }, },

	{"disconnect", P_disconnect, F_CONFIG_CMD, {{NULL, NULL}} },

	{"resize", P_resize, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "size",'s',T_resize_size,		EN(DISK_SIZE_SECT,'s') },
		 CLOSE_OPTIONS }} }, },

	{"syncer", P_syncer_conf, F_CONFIG_CMD, {{ NULL,
	 (struct drbd_option[]) {
		 { "rate",'r',T_rate,			EN(RATE,'k') },
		 { "after",'a',T_after,			EN(AFTER,1) },
		 { "al-extents",'e',T_al_extents,	EN(AL_EXTENTS,1) },
		 CLOSE_OPTIONS }} }, },

	{"invalidate", P_invalidate, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"invalidate-remote", P_invalidate_peer, F_CONFIG_CMD, {{NULL, NULL}} },
	{"pause-sync", P_pause_sync, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"resume-sync", P_resume_sync, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"suspend-io", P_suspend_io, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"resume-io", P_resume_io, F_CONFIG_CMD, {{ NULL, NULL }} },
	{"outdate", P_outdate, F_CONFIG_CMD, {{ NULL, NULL }} },
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
		print_state } } },
	{"wait-connect", 0, F_EVENTS_CMD, { .ep = {
		wait_cmds_options, w_connected_state } } },
	{"wait-sync", 0, F_EVENTS_CMD, { .ep = {
		wait_cmds_options, w_synced_state } } },
};

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
	EM(LDMounted) = "Lower device is already mounted.",
	EM(MDMounted) = "Meta device is already mounted.",
	EM(LDMDInvalid) = "Lower device / meta device / index combination invalid.",
	EM(LDDeviceTooLarge) = "Currently we only support devices up to 3.998TB.\n"
	"(up to 2TB in case you do not have CONFIG_LBD set)"
	"Contact office@linbit.com, if you need more.",
	EM(MDIOError) = "IO error(s) orruced during initial access to meta-data.\n",
	EM(MDInvalid) = "No valid meta-data signature found.\n)"
	"Use 'drbdadm create-md res' to initialize meta-data area.\n",
	EM(CRAMAlgNotAvail) = "The 'cram-hmac-alg' you specified is not known in )"
	"the kernel.\n",
	EM(CRAMAlgNotDigest) = "The 'cram-hmac-alg' you specified is not a digest.",
	EM(KMallocFailed) = "kmalloc() failed. Out of memory?",
	EM(DiscardNotAllowed) = "--discard-my-data not allowed when primary.",
	EM(HaveDiskConfig) = "HaveDiskConfig",
	EM(UnknownMandatoryTag) = "UnknownMandatoryTag",
	EM(MinorNotKnown) = "MinorNotKnown",
	EM(StateNotAllowed) = "StateNotAllowed",
	EM(GotSignal) = "GotSignal",
	EM(NoResizeDuringResync) = "Resize not allowed during resync.",
	EM(APrimaryNodeNeeded) = "Need the a primary node to resize.",
	EM(SyncAfterInvalid) = "The sync after minor number is invalid",
	EM(SyncAfterCycle) = "This would cause a sync-after dependency cycle",
	EM(PauseFlagAlreadySet) = "PauseFlagAlreadySet",
	EM(PauseFlagAlreadyClear) = "PauseFlagAlreadyClear",
	EM(DiskLowerThanOutdated) = "DiskLowerThanOutdated",
	EM(FailedToClaimMyself) = "FailedToClaimMyself",
};

const char empty_string[] = "";
char* cmdname = 0;

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
		return 20;
	}

	if ( (err=fstat(device_fd, &sb)) ) {
		PERROR("fstat(%s) failed", arg);
		return 20;
	}

	if(!S_ISBLK(sb.st_mode)) {
		fprintf(stderr, "%s is not a block device!\n", arg);
		return 20;
	}
	
	close(device_fd);

	add_tag(tl,ad->tag,arg,strlen(arg)+1); // include the null byte. 

	return 0;
}

int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = DRBD_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flexible")) idx = DRBD_MD_INDEX_FLEX_EXT;
	else idx = m_strtoll(arg,1);

	add_tag(tl,ad->tag,&idx,sizeof(idx));

	return 0;
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

int conv_address(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	struct sockaddr_in addr;
	int addr_len = sizeof(struct sockaddr_in);

	addr.sin_port = htons(port_part(arg));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = resolv(addr_part(arg));

	add_tag(tl,ad->tag,&addr,addr_len);

	return 0;
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
		return 20;
	}

	add_tag(tl,ad->tag,&prot,sizeof(prot));

	return 0;
}

int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg __attribute((unused)))
{
	char bit=1;

	add_tag(tl,od->tag,&bit,sizeof(bit));

	return 0;
}

int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	const long long min = od->numeric_param.min;
	const long long max = od->numeric_param.max;
	const unsigned char default_unit = od->numeric_param.default_unit;
	long long l;
	int i;
	char unit[] = {0,0};

	l = m_strtoll(arg, default_unit);

	if (min > l || l > max) {
		unit[0] = default_unit > 1 ? default_unit : 0;
		fprintf(stderr,"%s %s => %llu%s out of range [%llu..%llu]%s\n",
			od->name, arg, l, unit, min, max, unit);
		return(20);
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
	return 0;

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
			return 0;
		}
	}
	
	fprintf(stderr, "Handler not known\n");
	return 20;
}

int conv_string(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	add_tag(tl,od->tag,arg,strlen(arg)+1);

	return 0;
}

struct option *	make_longoptions(struct drbd_option* od)
{
	static struct option buffer[20];
	int i=0;

	while(od && od->name) {
		buffer[i].name = od->name;
		buffer[i].has_arg = tag_type(od->tag) == TT_BIT ? 
			no_argument : required_argument ;
		buffer[i].flag = NULL;
		buffer[i].val = od->short_name;
		if(i++ == 20) {
			fprintf(stderr,"buffer in make_longoptions to small.\n");
		}
		od++;
	}
	
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
	while(od->name) {
		if(od->short_name == c) return od;
		od++;
	}

	return NULL;
}

void print_config_error( struct drbd_nl_cfg_reply *reply)
{
	int err_no = reply->ret_code;

	if (err_no == NoError) return;
	if (err_no == SS_Success) return;

	if ( ( err_no >= AfterLastRetCode || err_no <= RetCodeBase ) &&
	     ( err_no > SS_CW_NoNeed || err_no < SS_CW_FailedByPeer) ) {
		fprintf(stderr,"Error code %d unknown.\n"
			"You should updated the drbd userland tools.\n",err_no);
	} else {
		if(err_no > RetCodeBase ) {
			fprintf(stderr,"Failure: (%d) %s\n",err_no,
				error_messages[err_no-RetCodeBase]);
		} else if (err_no == SS_UnknownError) {
			fprintf(stderr,"State change failed: (%d)"
				"unknown error.\n", err_no);
		} else if (err_no > SS_TowPrimaries) {
			// Ignore SS_Success, SS_NothingToDo, SS_CW_Success... 
		} else {
			fprintf(stderr,"State change failed: (%d) %s\n",
				err_no, set_st_err_name(err_no));
		}
	}
}

#define RCV_SIZE NLMSG_SPACE(sizeof(struct cn_msg)+sizeof(struct drbd_nl_cfg_reply))

int generic_config_cmd(struct drbd_cmd *cm, int minor, int argc, char **argv)
{
	char buffer[ RCV_SIZE ];
	struct drbd_nl_cfg_reply *reply;
	struct drbd_argument *ad = cm->cp.args;
	struct drbd_option *od;
	struct option *lo;
	struct drbd_tag_list *tl;
	int c,i=1,rv=0,sk_nl;
	int flags=0;

	tl = create_tag_list(4096);

	while(ad && ad->name) {
		if(argc < i+1) {
			fprintf(stderr,"Missing argument '%s'\n", ad->name);
			print_command_usage(cm-commands, "");
			rv=20;
			break;
		}
		rv |= ad->convert_function(ad,tl,argv[i++]);
		if(rv) break;
		ad++;
	}

	lo = make_longoptions(cm->cp.options);
	opterr=0;
	while( (c=getopt_long(argc,argv,make_optstring(lo,0),lo,0)) != -1 ) {
		od = find_opt_by_short_name(cm->cp.options,c);
		if(od) rv |= od->convert_function(od,tl,optarg);
		else {
			if(c=='(') flags |= DRBD_NL_SET_DEFAULTS;
			else if(c==')') flags |= DRBD_NL_CREATE_DEVICE;
			else {
				fprintf(stderr,
					"%s: unrecognized option '%s'\n",
					cmdname, argv[optind-1]);
				rv=20;
			}
		}
		if(rv) break;
	}

	add_tag(tl,TT_END,NULL,0); // close the tag list

	if(rv == 0) {
		//dump_tag_list(tl->tag_list_start);
		sk_nl = open_cn();
		if(sk_nl < 0) return 20;

		send_tag_list_cn(sk_nl,tl,cm->packet_id,minor,flags);

		receive_cn(sk_nl, (struct nlmsghdr*)buffer, RCV_SIZE );
		close_cn(sk_nl);
		reply = (struct drbd_nl_cfg_reply *)
			((struct cn_msg *)NLMSG_DATA(buffer))->data;
		print_config_error(reply);
	}
	free_tag_list(tl);

	return rv;
}

#define ASSERT(exp) if (!(exp)) \
		fprintf(stderr,"ASSERT( " #exp " ) in %s:%d\n", __FILE__,__LINE__);

void show_numeric(struct drbd_option *od, unsigned short* tp)
{
	long long val;
	const unsigned char def_unit = od->numeric_param.default_unit;

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

	if(def_unit == 1) printf("\t%-16s\t%lld",od->name,val);
	else printf("\t%-16s\t%lld%c",od->name,val,def_unit);
	if(val == (long long) od->numeric_param.def) printf(" _is_default");
	printf(";\n");
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


const char* consume_tag_blob(enum drbd_tags tag, unsigned short *tlc, 
			     unsigned int* len)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		*len = *tp++;
		return (char*)tp;
	}
	return NULL;
}

const char* consume_tag_string(enum drbd_tags tag, unsigned short *tlc)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		if( *tp++ > 0) return (char*)tp;
	}
	return empty_string;
}

int consume_tag_int(enum drbd_tags tag, unsigned short *tlc)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		tp++;
		return *(int *)tp;
	}
	return 0;
}

char consume_tag_bit(enum drbd_tags tag, unsigned short *tlc)
{
	unsigned short *tp;
	tp = look_for_tag(tlc,tag);
	if(tp) {
		*tp++ = TT_REMOVED;
		tp++;
		return *(char *)tp;
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

	if(argc > 1) {
		fprintf(stderr,"Ignoring excess arguments\n");
	}

	tl = create_tag_list(2);
	add_tag(tl,TT_END,NULL,0); // close the tag list

	sk_nl = open_cn();
	if(sk_nl < 0) return 20;

	send_tag_list_cn(sk_nl,tl,cm->packet_id,minor,0);

	receive_cn(sk_nl, (struct nlmsghdr*)buffer, 4096 );
	close_cn(sk_nl);
	reply = (struct drbd_nl_cfg_reply *)
		((struct cn_msg *)NLMSG_DATA(buffer))->data;

	rv = cm->gp.show_function(cm,minor,reply->tag_list);

	if(dump_tag_list(reply->tag_list)) {
		printf("# Found unknown tags, you should update your\n"
		       "# userland tools\n");
	}

	return rv;
}

int show_scmd(struct drbd_cmd *cm, int minor, unsigned short *rtl)
{
	int idx;
	const char* str;
	struct sockaddr_in *addr;

	// find all commands that have options and print those...
	for ( cm = commands ; cm < commands + ARRY_SIZE(commands) ; cm++ ) {
		if(cm->cp.options)
			print_options(cm->cp.options, rtl, cm->cmd);
	}

	// start of spagethi code...
	idx = consume_tag_int(T_wire_protocol,rtl);
	if(idx) printf("protocol %c;\n",'A'+idx-1);
	str = consume_tag_string(T_backing_dev,rtl);
	if(str != empty_string) {
		printf("_this_host {\n");
		printf("\tdevice\t\t\t\"/dev/drbd%d\";\n",minor);
		printf("\tdisk\t\t\t\"%s\";\n",str);
		idx=consume_tag_int(T_meta_dev_idx,rtl);
		switch(idx) {
		case DRBD_MD_INDEX_INTERNAL:
		case DRBD_MD_INDEX_FLEX_INT:
			printf("\tmeta-disk\t\tinternal;\n");
			consume_tag_string(T_meta_dev,rtl);
			break;
		case DRBD_MD_INDEX_FLEX_EXT:
			printf("\tflexible-meta-disk\t\"%s\";\n",
			       consume_tag_string(T_meta_dev,rtl));
			break;
		default:
			printf("\tmeta-disk\t\t\"%s\" [ %d ];\n",
			       consume_tag_string(T_meta_dev,rtl),idx);
		}
		str = consume_tag_string(T_my_addr,rtl);
		if(str != empty_string ) {
			addr = (struct sockaddr_in *)str;
			printf("\taddress\t\t\t%s:%d;\n",
			       inet_ntoa(addr->sin_addr),
			       ntohs(addr->sin_port));
		}
		printf("}\n");
	}

	str = consume_tag_string(T_peer_addr,rtl);
	if(str != empty_string) {
		printf("_remote_host {\n");
		addr = (struct sockaddr_in *)str;
		printf("\taddress\t\t\t%s:%d;\n",
		       inet_ntoa(addr->sin_addr),
		       ntohs(addr->sin_port));
		printf("}\n");
	}

	return 0;
}

int state_scmd(struct drbd_cmd *cm __attribute((unused)), 
	       int minor __attribute((unused)), 
	       unsigned short *rtl)
{
	drbd_state_t state;
	state = (drbd_state_t)(unsigned int)consume_tag_int(T_state_i,rtl);
	printf("%s\n",roles_to_name(state.role));
	return 0;
}

int cstate_scmd(struct drbd_cmd *cm __attribute((unused)), 
		int minor __attribute((unused)), 
		unsigned short *rtl)
{
	drbd_state_t state;
	state = (drbd_state_t)(unsigned int)consume_tag_int(T_state_i,rtl);
	printf("%s\n",conns_to_name(state.conn));
	return 0;
}

int dstate_scmd(struct drbd_cmd *cm __attribute((unused)), 
		int minor __attribute((unused)), 
		unsigned short *rtl)
{
	drbd_state_t state;
	state = (drbd_state_t)(unsigned int)consume_tag_int(T_state_i,rtl);
	printf("%s\n",disks_to_name(state.disk));
	return 0;
}

int uuids_scmd(struct drbd_cmd *cm, 
	       int minor __attribute((unused)), 
	       unsigned short *rtl)
{
	__u64 *uuids;
	int flags;
	unsigned int len = 4711;

	uuids = (__u64 *)consume_tag_blob(T_uuids,rtl,&len);
	if(len == 4711) {
		fprintf(stderr,"Reply payload did not carry an uuid-tag,\n"
			"Probabely the device has no disk!\n");
		return 1;
	}
	flags = consume_tag_int(T_uuids_flags,rtl);
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
	int rv = 0;

	if(argc > 1) {
		fprintf(stderr,"Ignoring excess arguments\n");	
	}

	cm = find_cmd_by_name("secondary");
	rv |= cm->function(cm,minor,argc,argv);
	cm = find_cmd_by_name("disconnect");
	rv |= cm->function(cm,minor,argc,argv);
	cm = find_cmd_by_name("detach");
	rv |= cm->function(cm,minor,argc,argv);

	return rv;
}

int print_state(unsigned int seq, int minor, drbd_state_t ns)
{
	/*char stime[20];
	  time_t now;
	  time(&now);
	  strftime(stime,20,"%a %e %T",gmtime(&now)); */

	printf("%u ST %d { cs:%s st:%s/%s ds:%s/%s %c%c%c%c }\n",
	       seq,
	       minor,
	       conns_to_name(ns.conn),
	       roles_to_name(ns.role),
	       roles_to_name(ns.peer),
	       disks_to_name(ns.disk),
	       disks_to_name(ns.pdsk),
	       ns.susp ? 's' : 'r',
	       ns.aftr_isp ? 'a' : '-',
	       ns.peer_isp ? 'p' : '-',
	       ns.user_isp ? 'u' : '-' );

	return 1;
}

int w_connected_state(unsigned int seq __attribute((unused)), 
		      int minor __attribute((unused)), 
		      drbd_state_t ns)
{
	if(ns.conn >= Connected) return 0;
	return 1;
}

int w_synced_state(unsigned int seq __attribute((unused)), 
		   int minor __attribute((unused)), 
		   drbd_state_t ns)
{
	if(ns.conn == Connected || ns.conn < Unconnected ) return 0;
	return 1;
}

int events_cmd(struct drbd_cmd *cm, int minor, int argc ,char **argv)
{
	char buffer[ 4096 ];
	struct cn_msg *cn_reply;
	struct drbd_nl_cfg_reply *reply;
	struct drbd_tag_list *tl;
	struct option *lo;
	unsigned int seq=0;
	int sk_nl,c,cont=1,rr;
	drbd_state_t state;
	int unfiltered=0, all_devices=0;
	int wfc_timeout=0, degr_wfc_timeout=0,timeout_ms;
	struct pollfd pfd;
	struct timeval before,after;
	
	lo = cm->ep.options;

	while( (c=getopt_long(argc,argv,make_optstring(lo,0),lo,0)) != -1 ) {
		switch(c) {
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
		}
	}

	if(optind > argc) {
		fprintf(stderr,"Ignoring excess arguments\n");
	}

	tl = create_tag_list(2);
	add_tag(tl,TT_END,NULL,0); // close the tag list

	sk_nl = open_cn();
	if(sk_nl < 0) return 20;

	// Find out which timeout value to use.
	send_tag_list_cn(sk_nl,tl,P_get_timeout_flag,minor,0);
	receive_cn(sk_nl, (struct nlmsghdr*)buffer, 4096 );
	cn_reply = (struct cn_msg *)NLMSG_DATA(buffer);
	reply = (struct drbd_nl_cfg_reply *)cn_reply->data;
	rr = consume_tag_bit(T_use_degraded,reply->tag_list);
	timeout_ms= 1000 * (  rr ? degr_wfc_timeout : wfc_timeout) - 1;

	// ask for the current state before waiting for state updates...
	send_tag_list_cn(sk_nl,tl,P_get_state,minor,0);

	do {
		pfd.fd = sk_nl;
		pfd.events = POLLIN;

		// printf("calling poll(,,%d)\n",timeout_ms);
		gettimeofday(&before,NULL);
		rr = poll(&pfd,1,timeout_ms);
		if(rr == 0) return 5; // timeout expired.
		gettimeofday(&after,NULL);

		if(timeout_ms > 0 ) {
			timeout_ms -= ( (after.tv_sec - before.tv_sec) * 1000 +
					(after.tv_usec - before.tv_usec) / 1000 );
		}
		receive_cn(sk_nl, (struct nlmsghdr*)buffer, 4096 );

		cn_reply = (struct cn_msg *)NLMSG_DATA(buffer);
		reply = (struct drbd_nl_cfg_reply *)cn_reply->data;

		// dump_tag_list(reply->tag_list);
		
		if(!unfiltered && cn_reply->seq <= seq) continue;
		seq = cn_reply->seq;

		state.i = consume_tag_int(T_state_i,reply->tag_list);
		
		if(dump_tag_list(reply->tag_list)) {
			printf("# Found unknown tags, you should update your\n"
			       "# userland tools\n");
		}

		if( all_devices || minor == reply->minor ) {
			cont=cm->ep.proc_event(cn_reply->seq, reply->minor, state);
		}
	} while(cont);

	close_cn(sk_nl);

	return 0;
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
	return snprintf(str,strlen," [{--%s|-%c} hdlr]",
			option->name, option->short_name);
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

void config_usage(struct drbd_cmd *cm, int brief __attribute((unused)))
{
	struct drbd_argument *args;
	struct drbd_option *options;
#define  maxcol 100 // plus initial tab ...
	static char line[maxcol+1];
	int col,prevcol;

	prevcol=col=0;

	col += snprintf(line+col, maxcol-col, " %s", cm->cmd);

	if ((args = cm->cp.args)) {
		while (args->name) {
			col += snprintf(line+col, maxcol-col, " %s", args->name);
			args++;
		}
					
	}
	if (col > maxcol) {
		printf("%s\n\t",line);
		col=0;
	}
	prevcol=col;
	if ((options = cm->cp.options)) {
		while (options->name) {
			col += options->usage_function(options,line+col,maxcol-col);
			if (col >= maxcol) {
				line[prevcol]=0;
				printf("%s\n\t",line);
				prevcol=col=0;
			} else {
				prevcol=col;
				options++;
			}
		}
	}
	line[col]=0;

	printf("%s\n",line);
}

void get_usage(struct drbd_cmd *cm, int brief __attribute((unused)))
{
	printf(" %s\n", cm->cmd);
}

void events_usage(struct drbd_cmd *cm, int brief __attribute((unused)))
{
	struct option *lo;
	printf(" %s", cm->cmd);

	lo = cm->ep.options;
	while(lo && lo->name) {
		printf(" [{--%s|-%c}]",lo->name,lo->val);
		lo++;
	}
	printf("\n");
}

void print_command_usage(int i, const char *addinfo)
{
	commands[i].usage(commands+i,0);

	if (addinfo) {
		printf("%s\n",addinfo);
		exit(20);
	}
}

void print_handler(const char* info, const char** handlers, unsigned int size)
{
	unsigned int i;

	printf(info);

	for(i=0;i<size;i++) {
		if(handlers[i]) {
			printf(" %s",handlers[i]);
			if(i < size-1) printf(",");
		}
	}
}

void print_usage(const char* addinfo)
{
	size_t i;

	printf("\nUSAGE: %s device command arguments options\n\n"
	       "Device is usually /dev/drbdX or /dev/drbd/X.\n"
	       "Commands, arguments and options are:\n",cmdname);


	for (i = 0; i < ARRY_SIZE(commands); i++)
		print_command_usage(i, 0);

	printf("\nGeneral options: --create-device, --set-defaults\n");

	print_handler("\non-io-error handlers:",on_error,ARRY_SIZE(on_error));
	print_handler("\nfencing policies:",fencing_n,ARRY_SIZE(fencing_n));
	print_handler("\nafter-sb-0pri handler:",asb0p_n,ARRY_SIZE(asb0p_n));
	print_handler("\nafter-sb-1pri handler:",asb1p_n,ARRY_SIZE(asb1p_n));
	print_handler("\nafter-sb-2pri handler:",asb2p_n,ARRY_SIZE(asb2p_n));

	printf("\n\n");
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
		if(err == ENOENT) {
			fprintf(stderr,"DRBD driver not present in the kernel?\n");
		}
		return -1;
	}

	return sk_nl;
}


int send_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size)
{
	struct cn_msg *cn_hdr;
	cn_hdr = (struct cn_msg *)NLMSG_DATA(nl_hdr);
	int rr;

	/* fill the netlink header */
	nl_hdr->nlmsg_len = NLMSG_LENGTH(size - sizeof(struct nlmsghdr));
	nl_hdr->nlmsg_type = NLMSG_DONE;
	nl_hdr->nlmsg_flags = 0;
	nl_hdr->nlmsg_seq = 0;
	nl_hdr->nlmsg_pid = getpid();
	/* fill the connector header */
	cn_hdr->id.idx = CN_IDX_DRBD;
	cn_hdr->seq = 1;
	cn_hdr->ack = 0;
	cn_hdr->len = size - sizeof(struct nlmsghdr) - sizeof(struct cn_msg);

	rr = send(sk_nl,nl_hdr,nl_hdr->nlmsg_len,0);
	if( rr != (ssize_t)nl_hdr->nlmsg_len) {
		perror("send() failed");
		return -1;
	}
	return rr;
}

int receive_cn(int sk_nl, struct nlmsghdr* nl_hdr, int size)
{
	int rr;

	rr = recv(sk_nl,nl_hdr,size,0);

	if( rr < 0 ) {
		perror("recv() failed");
		return -1;
	}
	return rr;
}

int send_tag_list_cn(int sk_nl, struct drbd_tag_list *tl, const int packet_id, int minor, int flags)
{
	tl->cn_header->id.val = CN_VAL_DRBD;
	tl->drbd_p_header->packet_type = packet_id;
	tl->drbd_p_header->drbd_minor = minor;
	tl->drbd_p_header->flags = flags;

	return send_cn(sk_nl, tl->nl_header, (char*)tl->tag_list_cpos - 
		       (char*)tl->nl_header);
}

void close_cn(int sk_nl)
{
	close(sk_nl);
}

int main(int argc, char** argv)
{
	int minor,drbd_fd,lock_fd;
	struct drbd_cmd *cmd;
	int help = 0, rv=0;

	chdir("/");

	if ( (cmdname = strrchr(argv[0],'/')) )
		argv[0] = ++cmdname;
	else
		cmdname = argv[0];

	/* == '-' catches -h, --help, and similar */
	if (argc > 1 && (!strcmp(argv[1],"help") || argv[1][0] == '-'))
		help = 1;

	if (argc < 3) print_usage(argc==1 ? 0 : " Insufficient arguments");

	cmd=find_cmd_by_name(argv[2]);

	if(cmd) {
		//drbd_fd = dt_lock_open_drbd(argv[1], &lock_fd, 1 );
		minor=dt_minor_of_dev(argv[1]);
		rv = cmd->function(cmd,minor,argc-2,argv+2);
		// by passing argc-2, argv+2 the function has the command name
		// in argv[0], e.g. "syncer"
		//dt_close_drbd_unlock(drbd_fd,lock_fd);
	} else {
		print_usage("invalid command");
	}

	return rv;
}
