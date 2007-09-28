/*
   drbdadm_parser.c a hand crafted parser

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2006-2007, LINBIT Information Technologies GmbH
   Copyright (C) 2006-2007, Philipp Reisner <philipp.reisner@linbit.com>
   Copyright (C) 2006-2007, Lars Ellenberg  <lars.ellenberg@linbit.com>

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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "drbdadm.h"
#include "linux/drbd_limits.h"
#include "drbdtool_common.h"
#include "drbdadm_parser.h"

YYSTYPE yylval;

/////////////////////

#define APPEND(LIST,ITEM) ({		      \
  typeof((LIST)) _l = (LIST);		      \
  typeof((ITEM)) _i = (ITEM);		      \
  typeof((ITEM)) _t;			      \
  _i->next = NULL;			      \
  if (_l == NULL) { _l = _i; }		      \
  else {				      \
    for (_t = _l; _t->next; _t = _t->next);   \
    _t->next = _i;			      \
  };					      \
  _l;					      \
})

static int c_section_start;

void m_strtoll_range(const char *s, char def_unit,
		     const char *name,
		     unsigned long long min, unsigned long long max)
{
	unsigned long long r = m_strtoll(s, def_unit);
	char unit[] = { def_unit > '1' ? def_unit : 0, 0 };
	if (min > r || r > max) {
		fprintf(stderr,
			"%s:%d: %s %s => %llu%s out of range [%llu..%llu]%s.\n",
			config_file, fline, name, s, r, unit, min, max, unit);
		exit(E_config_invalid);
	}
	if (DEBUG_RANGE_CHECK) {
		fprintf(stderr,
			"%s:%d: %s %s => %llu%s in range [%llu..%llu]%s.\n",
			config_file, fline, name, s, r, unit, min, max, unit);
	}
}

void range_check(const enum range_checks what, const char *name,
		 const char *value)
{
	switch (what) {
	case R_NO_CHECK:
		break;
	default:
		fprintf(stderr, "%s:%d: unknown range for %s => %s\n",
			config_file, fline, name, value);
		break;
	case R_MINOR_COUNT:
		m_strtoll_range(value, 1, name,
				DRBD_MINOR_COUNT_MIN, DRBD_MINOR_COUNT_MAX);
		break;
	case R_DIALOG_REFRESH:
		m_strtoll_range(value, 1, name,
				DRBD_DIALOG_REFRESH_MIN,
				DRBD_DIALOG_REFRESH_MAX);
		break;
	case R_DISK_SIZE:
		m_strtoll_range(value, 'K', name,
				DRBD_DISK_SIZE_SECT_MIN >> 1,
				DRBD_DISK_SIZE_SECT_MAX >> 1);
		break;
	case R_TIMEOUT:
		m_strtoll_range(value, 1, name, DRBD_TIMEOUT_MIN,
				DRBD_TIMEOUT_MAX);
		break;
	case R_CONNECT_INT:
		m_strtoll_range(value, 1, name, DRBD_CONNECT_INT_MIN,
				DRBD_CONNECT_INT_MAX);
		break;
	case R_PING_INT:
		m_strtoll_range(value, 1, name, DRBD_PING_INT_MIN,
				DRBD_PING_INT_MAX);
		break;
	case R_MAX_BUFFERS:
		m_strtoll_range(value, 1, name, DRBD_MAX_BUFFERS_MIN,
				DRBD_MAX_BUFFERS_MAX);
		break;
	case R_MAX_EPOCH_SIZE:
		m_strtoll_range(value, 1, name, DRBD_MAX_EPOCH_SIZE_MIN,
				DRBD_MAX_EPOCH_SIZE_MAX);
		break;
	case R_SNDBUF_SIZE:
		m_strtoll_range(value, 1, name, DRBD_SNDBUF_SIZE_MIN,
				DRBD_SNDBUF_SIZE_MAX);
		break;
	case R_KO_COUNT:
		m_strtoll_range(value, 1, name, DRBD_KO_COUNT_MIN,
				DRBD_KO_COUNT_MAX);
		break;
	case R_RATE:
		m_strtoll_range(value, 'K', name, DRBD_RATE_MIN, DRBD_RATE_MAX);
		break;
	case R_AL_EXTENTS:
		m_strtoll_range(value, 1, name, DRBD_AL_EXTENTS_MIN,
				DRBD_AL_EXTENTS_MAX);
		break;
	case R_PORT:
		m_strtoll_range(value, 1, name, DRBD_PORT_MIN, DRBD_PORT_MAX);
		break;
		/* FIXME not yet implemented!
		   case R_META_IDX:
		   m_strtoll_range(value, 1, name, DRBD_META_IDX_MIN, DRBD_META_IDX_MAX);
		   break;
		 */
	case R_WFC_TIMEOUT:
		m_strtoll_range(value, 1, name, DRBD_WFC_TIMEOUT_MIN,
				DRBD_WFC_TIMEOUT_MAX);
		break;
	case R_DEGR_WFC_TIMEOUT:
		m_strtoll_range(value, 1, name, DRBD_DEGR_WFC_TIMEOUT_MIN,
				DRBD_DEGR_WFC_TIMEOUT_MAX);
		break;
	}
}

static struct d_option *new_opt(char *name, char *value)
{
	struct d_option *cn = malloc(sizeof(struct d_option));

	/* fprintf(stderr,"%s:%d: %s = %s\n",config_file,line,name,value); */
	cn->name = name;
	cn->value = value;
	cn->mentioned = 0;
	cn->is_default = 0;

	return cn;
}
static void derror(struct d_host_info *host, struct d_resource *res, char *text)
{
	config_valid = 0;
	fprintf(stderr, "%s:%d: in resource %s, on %s { ... }:"
		" '%s' keyword missing.\n",
		config_file, c_section_start, res->name, host->name, text);
}

void check_meta_disk(struct d_host_info *host)
{
	if (strcmp(host->meta_disk, "internal") != 0) {
		/* external */
		if (host->meta_index == NULL) {
			fprintf(stderr,
				"%s:%d: expected 'meta-disk = %s [index]'.\n",
				config_file, fline, host->meta_disk);
		}
		/* index either some number, or "flexible" */
		check_uniq("meta-disk", "%s:%s[%s]", host->name,
			   host->meta_disk, host->meta_index);
	} else if (host->meta_index) {
		/* internal */
		if (strcmp(host->meta_index, "flexible") != 0) {
			/* internal, not flexible, but index given: no sir! */
			fprintf(stderr,
				"%s:%d: no index allowed with 'meta-disk = internal'.\n",
				config_file, fline);
		}		/* else internal, flexible: fine */
	} else {
		/* internal, not flexible */
		host->meta_index = strdup("internal");
	}
}

#define EXP(TOKEN1)						\
({ 								\
	int token;						\
	token = yylex();					\
	if(token != TOKEN1)					\
		pe_expected_got( #TOKEN1, token);		\
	token;							\
})

#define EXP2(TOKEN1,TOKEN2)						\
({ 									\
	int token;							\
	token = yylex();						\
	if(token != TOKEN1 && token != TOKEN2)				\
		pe_expected_got( #TOKEN1 "|" # TOKEN2, token);		\
	token;								\
})

static void pe_expected(const char *exp)
{
	fprintf(stderr, "%s:%u: Parse error: '%s' expected,\n\t"
		"but got '%s'\n", config_file, line, exp, yytext);
	exit(E_config_invalid);
}

static void pe_expected_got(const char *exp, int got)
{
	static char tmp[2] = "\0";
	if (exp[0] == '\'' && exp[1] && exp[2] == '\'' && exp[3] == 0) {
		tmp[0] = exp[1];
	}
	fprintf(stderr, "%s:%u: Parse error: '%s' expected,\n\t"
		"but got '%s' (TK %d)\n",
		config_file, line,
		tmp[0] ? tmp : exp, yytext, got);
	exit(E_config_invalid);
}

static void parse_global(void)
{
	fline = line;
	check_uniq("global section", "global");
	if (config) {
		fprintf(stderr,
			"%s:%u: You should put the global {} section\n\t"
			"in front of any resource {} section\n",
			config_file, line);
	}
	EXP('{');
	while (1) {
		switch (yylex()) {
		case TK_DISABLE_IP_VERIFICATION:
			global_options.disable_ip_verification = 1;
			break;
		case TK_MINOR_COUNT:
			EXP(TK_INTEGER);
			range_check(R_MINOR_COUNT, "minor-count", yylval.txt);
			global_options.minor_count = atoi(yylval.txt);
			break;
		case TK_DIALOG_REFRESH:
			EXP(TK_INTEGER);
			range_check(R_DIALOG_REFRESH, "dialog-refresh",
				    yylval.txt);
			global_options.dialog_refresh = atoi(yylval.txt);
			break;
		case TK_USAGE_COUNT:
			switch (yylex()) {
			case TK_YES:
				global_options.usage_count = UC_YES;
				break;
			case TK_NO:
				global_options.usage_count = UC_NO;
				break;
			case TK_ASK:
				global_options.usage_count = UC_ASK;
				break;
			default:
				pe_expected("yes | no | ask");
			}
			break;
		case '}':
			return;
		default:
			pe_expected("dialog-refresh | minor-count | "
				    "disable-ip-verification");
		}
		EXP(';');
	}
}

static struct d_option *parse_options(int token_switch, int token_option)
{
	char *opt_name;
	int token;
	enum range_checks rc;

	struct d_option *options = NULL, *ro = NULL;
	fline = line;

	EXP('{');
	while (1) {
		token = yylex();
		if (token == token_switch) {
			options = APPEND(options, new_opt(yylval.txt, NULL));
		} else if (token == token_option) {
			opt_name = yylval.txt;
			rc = yylval.rc;
			EXP2(TK_STRING, TK_INTEGER);
			range_check(rc, opt_name, yylval.txt);
			ro = new_opt(opt_name, yylval.txt);
			options = APPEND(options, ro);
		} else if (token == '}') {
			return options;
		} else {
			pe_expected("an option keyword");
		}
		switch (yylex()) {
		case TK__IS_DEFAULT:
			ro->is_default = 1;
			EXP(';');
			break;
		case ';':
			break;
		default:
			pe_expected("_is_default | ;");
		}
	}
}

static void parse_proxy_section(struct d_resource* res, struct d_host_info *host)
{
	struct d_proxy_info *proxy;
	struct d_host_info *tmp;

	proxy=calloc(1,sizeof(struct d_proxy_info));
	host->proxy = proxy;

	EXP(TK_ON);
	EXP(TK_STRING);
	proxy->name = yylval.txt;

	/* TODO: This needs to get improved! This works now only for trivial two
	   node cases! */
	if(strcmp(proxy->name, nodeinfo.nodename) == 0 && host == res->peer) {
		tmp = res->me;
		res->me = res->peer;
		res->peer = tmp;
	}

	EXP('{');
	while (1) {
		switch (yylex()) {
		case TK_INSIDE:
			EXP(TK_IPADDR);
			proxy->inside_addr = yylval.txt;
			EXP(':');
			EXP(TK_INTEGER);
			proxy->inside_port = yylval.txt;
			EXP(';');
			break;
		case TK_OUTSIDE:
			EXP(TK_IPADDR);
			proxy->outside_addr = yylval.txt;
			EXP(':');
			EXP(TK_INTEGER);
			proxy->outside_port = yylval.txt;
			EXP(';');
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("inside | outside");

		}
	}
	
 break_loop:
	return;
}


static void parse_host_body(struct d_host_info *host,
			    struct d_resource *res, int require_all)
{
	EXP('{');
	while (1) {
		switch (yylex()) {
		case TK_DISK:
			check_uniq("disk statement", "%s:%s:disk", res->name,
				   host->name);
			EXP(TK_STRING);
			host->disk = yylval.txt;
			check_uniq("disk", "%s:%s:%s", "disk",
				   host->name, yylval.txt);
			EXP(';');
			break;
		case TK_DEVICE:
			check_uniq("device statement", "%s:%s:device",
				   res->name, host->name);
			EXP(TK_STRING);
			host->device = yylval.txt;
			check_uniq("device", "%s:%s:%s", "device",
				   host->name, yylval.txt);
			EXP(';');
			break;
		case TK_ADDRESS:
			check_uniq("address statement", "%s:%s:address",
				   res->name, host->name);
			EXP(TK_IPADDR);
			host->address = yylval.txt;
			EXP(':');
			EXP(TK_INTEGER);
			host->port = yylval.txt;
			range_check(R_PORT, "port", yylval.txt);
			check_uniq("IP", "%s:%s", host->address, host->port);
			EXP(';');
			break;
		case TK_META_DISK:
			check_uniq("meta-disk statement", "%s:%s:meta-disk",
				   res->name, host->name);
			EXP(TK_STRING);
			host->meta_disk = yylval.txt;
			if (strcmp("internal", yylval.txt)) {
				EXP('[');
				EXP(TK_INTEGER);
				host->meta_index = yylval.txt;
				EXP(']');
				EXP(';');
			} else {
				EXP(';');
			}
			check_meta_disk(host);
			break;
		case TK_FLEX_META_DISK:
			check_uniq("meta-disk statement", "%s:%s:meta-disk",
				   res->name, host->name);
			EXP(TK_STRING);
			host->meta_disk = yylval.txt;
			if (strcmp("internal", yylval.txt)) {
				host->meta_index = strdup("flexible");
			}
			check_meta_disk(host);
			switch (yylex()) {
			case TK__MAJOR:
				EXP(TK_INTEGER);
				host->meta_major = atoi(yylval.txt);
				EXP(TK__MINOR);
				EXP(TK_INTEGER);
				host->meta_minor = atoi(yylval.txt);
				EXP(';');
			case ';':
				break;
			}
			break;
		case TK_PROXY:
			parse_proxy_section(res,host);
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("disk | device | address | meta-disk "
				    "| flexible-meta-disk");
		}
	}
      break_loop:
	if (!require_all)
		return;
	if (!host->device)
		derror(host, res, "device");
	if (!host->disk)
		derror(host, res, "disk");
	if (!host->address)
		derror(host, res, "address");
	if (!host->meta_disk)
		derror(host, res, "meta-disk");
}

void parse_skip()
{
	int level;
	fline = line;

	switch (yylex()) {
	case TK_STRING:
		EXP('{');
		break;
	case '{':
		break;
	default:
		pe_expected("[ some_text ] {");
	}

	level = 1;
	while (level) {
		switch (yylex()) {
		case '{':
			/* if you really want to,
			   you can wrap this with a GB size config file :) */
			level++;
			break;
		case '}':
			level--;
			break;
		case 0:
			fprintf(stderr, "%s:%u: reached eof "
				"while parsing this skip block.\n",
				config_file, fline);
			exit(E_config_invalid);
		}
	}
	while (level) ;
}


static void parse_host_section(struct d_resource* res)
{
	struct d_host_info *host;

	c_section_start = line;
	fline = line;

	host=calloc(1,sizeof(struct d_host_info));
	EXP(TK_STRING);
	host->name = yylval.txt;

	check_uniq("host section", "%s: on %s", res->name, host->name);
	if(strcmp(host->name, nodeinfo.nodename) == 0) {
		// if (res->me) die duplicate entry ... done by check_uniq above
		res->me = host;
	} else {
		if (res->peer) {
			config_valid = 0;
			fprintf(stderr,
		"%s:%d: in resource %s, on %s { ... } ... on %s { ... }:\n"
		"\tThere are multiple host sections for the peer.\n"
		"\tMaybe misspelled local host name '%s'?\n",
				config_file, c_section_start, res->name,
				res->peer->name, host->name, nodeinfo.nodename);
		}
		res->peer = host;
	}
	parse_host_body(host,res,1);
}

static void parse_drbdsetup_host_dump(struct d_resource* res, int local)
{
	struct d_host_info *host;

	c_section_start = line;

	host=calloc(1,sizeof(struct d_host_info));

	if(local) {
		res->me = host;
		host->name = strdup("_this_host");
	} else {
		res->peer = host;
		host->name = strdup("_remote_host");
	}

	parse_host_body(host,res,0);
}

struct d_resource* parse_resource(char* res_name, enum pr_flags flags)
{
	struct d_resource* res;
	int token;

	fline = line;

	res=calloc(1,sizeof(struct d_resource));
	res->name = res_name;
	res->next = NULL;

	while(1) {
		switch((token=yylex())) {
		case TK_PROTOCOL:
			check_uniq("protocol statement","%s: protocol",res->name);
			EXP(TK_STRING);
			res->protocol=yylval.txt;
			EXP(';');
			break;
		case TK_ON:
			parse_host_section(res);
			break;
		case TK__THIS_HOST:
			parse_drbdsetup_host_dump(res, 1);
			break;
		case TK__REMOTE_HOST:
			parse_drbdsetup_host_dump(res, 0);
			break;
		case TK_DISK:
			check_uniq("disk section", "%s:disk", res->name);
			res->disk_options = parse_options(TK_DISK_SWITCH,
							  TK_DISK_OPTION);
			break;
		case TK_NET:
			check_uniq("net section", "%s:net", res->name);
			res->net_options = parse_options(TK_NET_SWITCH,
							 TK_NET_OPTION);
			break;
		case TK_SYNCER:
			check_uniq("syncer section", "%s:syncer", res->name);
			res->sync_options = parse_options(TK_SYNCER_SWITCH,
							  TK_SYNCER_OPTION);
			break;
		case TK_STARTUP:
			check_uniq("startup section", "%s:startup", res->name);
			res->startup_options=parse_options(TK_STARTUP_SWITCH,
							   TK_STARTUP_OPTION);
			break;
		case TK_HANDLER:
			check_uniq("handlers section", "%s:handlers", res->name);
			res->handlers =  parse_options(0, TK_HANDLER_OPTION);
			break;
		case TK_PROXY:
			check_uniq("proxy section", "%s:proxy", res->name);
			res->proxy_options =  parse_options(TK_PROXY_SWITCH,
							    TK_PROXY_OPTION);
			break;
		case '}':
		case 0:
			goto exit_loop;
		default:
			pe_expected_got("protocol | on | disk | net | syncer |"
					" startup | handler",token);
		}
	}

 exit_loop:
	if(flags & ThisHRequired && !res->me) {
		config_valid = 0;

		fprintf(stderr,
			"%s:%d: in resource %s, there is no host section"
			" for this host.\n"
			"\tMissing 'on %s {...}' ?\n",
			config_file, c_section_start, res->name,
			nodeinfo.nodename);
	}
	if(flags & PeerHRequired && !res->peer) {
		config_valid = 0;

		fprintf(stderr,
			"%s:%d: in resource %s, there is no host section"
			" for the peer host.\n"
			"\tMissing 'on <peer-name> {...}' ?\n",
			config_file, c_section_start, res->name);
	}
	if(flags == NoneHAllowed && ( res->me || res->peer ) ) {
		config_valid = 0;

		fprintf(stderr,
			"%s:%d: in the %s section, there are no host sections"
			" allowed.\n",
			config_file, c_section_start, res->name);
	}

	return res;
}

void my_parse(void)
{
	common = NULL;
	config = NULL;

	while (1) {
		switch (yylex()) {
		case TK_GLOBAL:
			parse_global();
			break;
		case TK_COMMON:
			EXP('{');
			common = parse_resource("common",NoneHAllowed);
			break;
		case TK_RESOURCE:
			EXP(TK_STRING);
			EXP('{');
			config=APPEND(config, 
				      parse_resource(yylval.txt,BothHRequired));
			break;
		case TK_SKIP:
			parse_skip();
			break;
		case 0:
			return;
		default:
			pe_expected("global | common | resource | skip");
		}
	}
}
