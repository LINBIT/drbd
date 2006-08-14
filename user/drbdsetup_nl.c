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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <linux/drbd.h>
#include <linux/drbd_config.h>
#include <getopt.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include <mntent.h>
#include "drbdtool_common.h"
#include "drbd_limits.h"
#include "drbd_tag_magic.h"

struct drbd_tag_list {
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
	union {
		struct {
			const unsigned long long min;
			const unsigned long long max;
			const unsigned long long def;
			const unsigned char default_unit;
		} numeric_param;
		struct {
			const char** handler_names;
			const int number_of_handlers;
		} handler_param;
	};
};

struct drbd_cmd {
	const char* cmd;
	const int packet_id;
	int (*function)(struct drbd_cmd *, int, char **);
	struct drbd_argument *args;
	struct drbd_option *options;
};


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

// other functions
void print_command_usage(int i, const char *addinfo);
// command functions
int generic_config_cmd(struct drbd_cmd *cm, int argc, char **argv);
// convert functions for arguments
int conv_block_dev(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
int conv_address(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
int conv_protocol(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg);
// convert functions for options
int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_handler(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);
int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg);

#define EN(N) \
	conv_numeric, { .numeric_param = { N ## _min, N ## _max, N ## _default } }
#define EN0 	conv_numeric, { .numeric_param = { 0, -1, 0, 0 } }
#define EH(N) \
	conv_handler, { .handler_param = { N, ARRY_SIZE(N) } }
#define EB      conv_bit, { } 




struct drbd_cmd commands[] = {
	{"primary", P_primary, generic_config_cmd, NULL,
	 (struct drbd_option[]) {
		 { "overwrite-data-of-peer",'o',T_disk_size, EB	     },
		 { NULL,0,0,NULL, { } }, }, },

	{"secondary", P_secondary, generic_config_cmd, NULL, NULL },

	{"disk", P_disk_conf, generic_config_cmd,
	 (struct drbd_argument[]) {
		 { "lower_dev",		T_backing_dev,	conv_block_dev },
		 { "meta_data_dev",	T_meta_dev,	conv_block_dev },
		 { "meta_data_index",	T_meta_dev_idx,	conv_md_idx },
		 { NULL,                0,           	NULL}, },
	 (struct drbd_option[]) {
		 { "size",'d',		T_disk_size,	EN0 },
		 { "on-io-error",'e',	T_on_io_error,	EH(on_error) },
		 { "fencing",'f',	T_fencing,	EH(fencing_n) },
		 { NULL,0,0,NULL, { } }, }, },

	{"detach", P_detach, generic_config_cmd, NULL, NULL },

	{"net", P_net_conf, generic_config_cmd,
	 (struct drbd_argument[]) {
		 { "local_addr",	T_my_addr,	conv_address },
		 { "remote_addr",	T_peer_addr,	conv_address },
		 { "protocol",		T_wire_protocol,conv_protocol },
 		 { NULL,                0,           	NULL}, },
	 (struct drbd_option[]) {
		 { "timeout",'t',	T_timeout,	EN0 },
		 { "max-epoch-size",'e',T_max_epoch_size,EN0 },
		 { "max-buffers",'b',	T_max_buffers,	EN0 },
		 { "unplug-watermark",'u',T_unplug_watermark, EN0 },
		 { "connect-int",'c',	T_try_connect_int, EN0 },
		 { "ping-int",'i',	T_ping_int,	   EN0 },
		 { "sndbuf-size",'S',	T_sndbuf_size,	   EN0 },
		 { "ko-count",'k',	T_ko_count,	   EN0 },
		 { "allow-two-primaries",'m',T_two_primaries, EN0 },
		 { "cram-hmac-alg",'a',	T_cram_hmac_alg,   EN0 },
		 { "shared-secret",'x',	T_shared_secret,   EN0 },
		 { "after-sb-0pri",'A',	T_after_sb_0p,     EH(asb0p_n) },
		 { "after-sb-1pri",'B',	T_after_sb_1p,     EH(asb1p_n) },
		 { "after-sb-2pri",'C',	T_after_sb_2p,     EH(asb2p_n) },
		 { "discard-my-data",'D', T_want_lose,     EB },
		 { NULL,0,0,NULL, { } }, }, },
};

char* cmdname = 0;

void dump_tag_list(struct drbd_tag_list *tl)
{
	unsigned short *tlc = tl->tag_list_start;
	enum drbd_tags tag;
	int len;
	int integer;
	char bit;
	__u64 int64;
	char* string;

	while(*tlc != TT_END) {
		tag = tag_number(*tlc++);
		printf("(%d) %s = ",tag,tag_descriptions[tag].name);
		len = *tlc++;
		switch(tag_type(tag)) {
		case TT_INTEGER: 
			integer = *(int*)tlc;
			printf("%d",integer);
			break;
		case TT_INT64:
			int64 = *(__u64*)tlc;
			printf("%lld",(long long)int64);
			break;
		case TT_BIT:
			bit = *(char*)tlc;
			printf( bit ? "on" : "off");
			break;
		case TT_STRING:
			string = (char*)tlc;
			printf("%s",string);
			break;
		}
		printf(" (len: %u)\n",len);
		tlc = (unsigned short*)((char*)tlc + len);
	}
}

struct drbd_tag_list *create_tag_list(int size)
{
	struct drbd_tag_list *tl;

	tl = malloc(sizeof(struct drbd_tag_list));
	tl->tag_list_start = malloc(size);
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
	free(tl->tag_list_start);
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

	add_tag(tl,ad->tag,&device_fd,sizeof(device_fd));

	return 0;
}

int conv_md_idx(struct drbd_argument *ad, struct drbd_tag_list *tl, char* arg)
{
	int idx;

	if(!strcmp(arg,"internal")) idx = DRBD_MD_INDEX_FLEX_INT;
	else if(!strcmp(arg,"flex")) idx = DRBD_MD_INDEX_FLEX_EXT;
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

	switch(ad->tag) {
	case T_my_addr:
		add_tag(tl,T_my_addr,&addr,addr_len);
		add_tag(tl,T_my_addr_len,&addr_len,sizeof(addr_len));
		break;
	case T_peer_addr:
		add_tag(tl,T_peer_addr,&addr,addr_len);
		add_tag(tl,T_peer_addr_len,&addr_len,sizeof(addr_len));
		break;
	default:
		fprintf(stderr, "internal error in conv_address()\n");
	}

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

int conv_bit(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	char bit=1;

	add_tag(tl,od->tag,&bit,sizeof(bit));

	return 0;
}

int conv_numeric(struct drbd_option *od, struct drbd_tag_list *tl, char* arg)
{
	const unsigned long long min = od->numeric_param.min;
	const unsigned long long max = od->numeric_param.max;
	const unsigned char default_unit = od->numeric_param.default_unit;
	unsigned long long l;
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
	int i,nr;

	for(i=0;i<number_of_handlers;i++) {
		if(strcmp(arg,handler_names[i])==0) {
			nr = i;
			break;
		}
	}

	add_tag(tl,od->tag,&nr,sizeof(nr));

	return 0;
}

struct option *	make_longoptions(struct drbd_option* od)
{
	static struct option buffer[20];
	int i=0;

	while(od->name) {
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

int generic_config_cmd(struct drbd_cmd *cm, int argc, char **argv)
{
	struct drbd_argument *ad = cm->args;
	struct drbd_option *od;
	static struct option *lo;
	struct drbd_tag_list *tl;
	int c,i=0,rv=0;

	tl = create_tag_list(4096);

	while(ad->name) {
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

	lo = make_longoptions(cm->options);
	while( (c=getopt_long(argc,argv,make_optstring(lo,0),lo,0)) != -1 ) {
		od = find_opt_by_short_name(cm->options,c);
		if(od) rv |= od->convert_function(od,tl,optarg);
		else {
			fprintf(stderr,"opt for short '%c' (%d) not found\n",
				c,c);
			rv=20;			
		}
		if(rv) break;
	}

	if(rv == 0) dump_tag_list(tl);
	free_tag_list(tl);

	return rv;
}


void print_command_usage(int i, const char *addinfo)
    // CAUTION no range check for i
{
	struct drbd_argument *args;
	struct drbd_option *options;
#define  maxcol 70 // plus initial tab ...
	static char line[maxcol+1];
	int col,prevcol;

	prevcol=col=0;

	col += snprintf(line+col, maxcol-col, " %s", commands[i].cmd);
	if ((args = commands[i].args)) {
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
	if ((options = commands[i].options)) {
		while (options->name) {
			if (tag_type(options->tag) == TT_BIT) {
				col += snprintf(line+col, maxcol-col, 
						" [{--%s|-%c}]",
						options->name, options->short_name);
			} else {
				col += snprintf(line+col, maxcol-col, 
						" [{--%s|-%c} val]",
						options->name, options->short_name);
			}
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
	       "Commands, arguments and options are:\n",cmdname);


	for (i = 0; i < ARRY_SIZE(commands); i++)
		print_command_usage(i, 0);

	printf("\nAvailable on-io-error handlers:");
	for(i=0;i<ARRY_SIZE(on_error);i++) {
		printf(" %s",on_error[i]);
		if(i < ARRY_SIZE(on_error)-1) printf(",");
	}

	printf("\nAvailable fencing policies:");
	for(i=0;i<ARRY_SIZE(fencing_n);i++) {
		printf(" %s",fencing_n[i]);
		if(i < ARRY_SIZE(fencing_n)-1) printf(",");
	}
	/*
	printf("\n\nVersion: "REL_VERSION" (api:%d)\n%s\n",
	       API_VERSION, drbd_buildtag());
	*/
	if (addinfo)
		printf("\n%s\n",addinfo);

	exit(20);
}

int main(int argc, char** argv)
{
	int help = 0;
	unsigned int i;

	if ( (cmdname = strrchr(argv[0],'/')) )
		argv[0] = ++cmdname;
	else
		cmdname = argv[0];

	/* == '-' catches -h, --help, and similar */
	if (argc > 1 && (!strcmp(argv[1],"help") || argv[1][0] == '-'))
		help = 1;
	if (argc < 3) print_usage(argc==1 ? 0 : " Insufficient arguments");

	chdir("/");

	for(i=0;i<ARRY_SIZE(commands);i++) {
		if(strcmp(argv[2],commands[i].cmd)==0) {
			commands[i].function(commands+i,argc-3,argv+3);
		}
	}

	return 0;
}
