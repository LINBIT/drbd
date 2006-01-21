/*
   drbdadm_parser.c a hand crafted parser

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2006, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

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
#include "drbd_limits.h"
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

static int   c_section_start;

void
m_strtoll_range(const char *s, char def_unit,
		const char *name,
		unsigned long long min, unsigned long long max)
{
  unsigned long long r = m_strtoll(s, def_unit);
  char unit[] = { def_unit > '1' ? def_unit : 0, 0 };
  if (min > r || r > max)
    {
      fprintf(stderr,
	      "%s:%d: %s %s => %llu%s out of range [%llu..%llu]%s.\n",
	      config_file, fline, name, s, r, unit, min, max, unit);
      exit(E_config_invalid);
    }
  if (DEBUG_RANGE_CHECK)
    {
      fprintf(stderr,
	      "%s:%d: %s %s => %llu%s in range [%llu..%llu]%s.\n",
	      config_file, fline, name, s, r, unit, min, max, unit);
    }
}

enum range_checks
{
  R_MINOR_COUNT,
  R_DIALOG_REFRESH,
  R_DISK_SIZE,
  R_TIMEOUT,
  R_CONNECT_INT,
  R_PING_INT,
  R_MAX_BUFFERS,
  R_MAX_EPOCH_SIZE,
  R_SNDBUF_SIZE,
  R_KO_COUNT,
  R_RATE,
  R_GROUP,
  R_AL_EXTENTS,
  R_PORT,
  R_META_IDX,
  R_WFC_TIMEOUT,
  R_DEGR_WFC_TIMEOUT,
};

void
range_check(const enum range_checks what, const char *name, const char *value)
{
  switch (what)
    {
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
		      DRBD_DIALOG_REFRESH_MIN, DRBD_DIALOG_REFRESH_MAX);
      break;
    case R_DISK_SIZE:
      m_strtoll_range(value, 'K', name,
		      DRBD_DISK_SIZE_SECT_MIN >> 1,
		      DRBD_DISK_SIZE_SECT_MAX >> 1);
      break;
    case R_TIMEOUT:
      m_strtoll_range(value, 1, name, DRBD_TIMEOUT_MIN, DRBD_TIMEOUT_MAX);
      break;
    case R_CONNECT_INT:
      m_strtoll_range(value, 1, name, DRBD_CONNECT_INT_MIN,
		      DRBD_CONNECT_INT_MAX);
      break;
    case R_PING_INT:
      m_strtoll_range(value, 1, name, DRBD_PING_INT_MIN, DRBD_PING_INT_MAX);
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
      m_strtoll_range(value, 1, name, DRBD_KO_COUNT_MIN, DRBD_KO_COUNT_MAX);
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

static struct d_option* new_opt(char* name,char* value)
{
	struct d_option* cn = malloc(sizeof(struct d_option));

	/* fprintf(stderr,"%s:%d: %s = %s\n",config_file,line,name,value); */
	cn->name=name;
	cn->value=value;
	cn->mentioned=0;

	return cn;
}

static void derror(struct d_host_info *host,
		   struct d_resource* res,
		   char* text)
{
	config_valid=0;
	fprintf(stderr, "%s:%d: in resource %s, on %s { ... }:"
		" '%s' keyword missing.\n",
		config_file,c_section_start,res->name,host->name,text);
}

void check_meta_disk(struct d_host_info *host)
{
  if (strcmp(host->meta_disk, "internal") != 0) {
    /* external */
    if (host->meta_index == NULL) {
      fprintf(stderr, "%s:%d: expected 'meta-disk = %s [index]'.\n",
	      config_file, fline, host->meta_disk);
    }
    /* index either some number, or "flexible" */
    check_uniq("meta-disk", "%s:%s[%s]", host->name,
	       host->meta_disk, host->meta_index);
  } else if (host->meta_index) {
    /* internal */
    if (strcmp(host->meta_index,"flexible") != 0) {
      /* internal, not flexible, but index given: no sir! */
      fprintf(stderr,
	      "%s:%d: no index allowed with 'meta-disk = internal'.\n",
	      config_file, fline);
    } /* else internal, flexible: fine */
  } else {
    /* internal, not flexible */
    host->meta_index = strdup("internal");
  }
}

///////////////////////////


#define EXP(TOKEN1)					\
({ 							\
	int token; 					\
	token = yylex(); 				\
	if(token != TOKEN1)				\
		pe_expected_got( #TOKEN1, token ); 	\
})

#define EXP2(TOKEN1,TOKEN2)					\
({ 								\
	int token; 						\
	token = yylex(); 					\
	if(token != TOKEN1 && token != TOKEN2) 			\
		pe_expected_got( #TOKEN1 "|" # TOKEN2, token );	\
})

static void pe_expected(const char *exp)
{
	fprintf(stderr,"Parse error '%s' expected, at line %d\n",exp,line);
	exit(10);
}

static void pe_expected_got(const char *exp, int got)
{
	fprintf(stderr,"Parse error '%s' expected but got %d, at line %d\n",
		exp,got,line);
	exit(10);
}

static void parse_global(void) {
	EXP('{');
	while(1) {
		switch(yylex()) {
		case TK_DISABLE_IP_VERIFICATION:
			global_options.disable_ip_verification=1;
			break;
		case TK_MINOR_COUNT:
			EXP(TK_INTEGER);
			range_check(R_MINOR_COUNT,"minor-count",yylval.txt);
			global_options.minor_count=atoi(yylval.txt);
			break;
		case TK_DIALOG_REFRESH:
			EXP(TK_INTEGER);
			range_check(R_DIALOG_REFRESH,"dialog-refresh",yylval.txt);
			global_options.dialog_refresh=atoi(yylval.txt);
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

static struct d_option* parse_options(int token_switch,int token_option)
{
	char *opt_name;
	int token;

	struct d_option* options = NULL;

	EXP('{');
	while(1) {
		token = yylex();
		if( token == token_switch) {
			options = APPEND(options,new_opt(yylval.txt,NULL));
		} else if ( token == token_option) {
			opt_name=yylval.txt;
			EXP2(TK_STRING,TK_INTEGER);
			options = APPEND(options,new_opt(opt_name,yylval.txt));
		} else if ( token == '}' ) {
			return options;
		} else {
			pe_expected("An option keyword");
		}
		EXP(';');
	}
}

static void parse_host_section(struct d_resource* res)
{
	struct d_host_info *host;

	c_section_start = line;

	host=calloc(1,sizeof(struct d_host_info));
	EXP(TK_STRING);
	host->name = yylval.txt;
	if(strcmp(host->name, nodeinfo.nodename) == 0) {
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

	EXP('{');
	while(1) {
		switch(yylex()) {
		case TK_DISK:
			EXP(TK_STRING);
			host->disk = yylval.txt;
			check_uniq("disk", "%s:%s:%s","disk",
				   host->name,yylval.txt);
			break;
		case TK_DEVICE:
			EXP(TK_STRING);
			host->device = yylval.txt;
			check_uniq("device", "%s:%s:%s","device",
				   host->name,yylval.txt);
			break;
		case TK_ADDRESS:
			EXP(TK_IPADDR);
			host->address = yylval.txt;
			EXP(':');
			EXP(TK_INTEGER);
			host->port = yylval.txt;
			range_check(R_PORT, "port", yylval.txt);
			break;
		case TK_META_DISK:
			EXP(TK_STRING);
			host->meta_disk = yylval.txt;
			if(strcmp("internal",yylval.txt)) {
				EXP('[');
				EXP(TK_INTEGER);
				host->meta_index = yylval.txt;
				EXP(']');
			}
			check_meta_disk(host);
			break;
		case TK_FLEX_META_DISK:
			EXP(TK_STRING);
			host->meta_disk = yylval.txt;
			host->meta_index = strdup("flexible");
			check_meta_disk(host);
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("disk | device | address | meta-disk "
				    "| flex-meta-disk");
		}
		EXP(';');
	}
 break_loop:
	if (!host->device)	derror(host,res,"device");
	if (!host->disk)	derror(host,res,"disk");
	if (!host->address)	derror(host,res,"address");
	if (!host->meta_disk)	derror(host,res,"meta-disk");
}

struct d_resource* parse_resource(char* res_name)
{
	struct d_resource* res;

	res=calloc(1,sizeof(struct d_resource));
	res->name = res_name;
	res->next = NULL;

	EXP('{');
	while(1) {
		switch(yylex()) {
		case TK_PROTOCOL:
			EXP(TK_STRING);
			res->protocol=yylval.txt;
			EXP(';');
			break;
		case TK_ON:
			parse_host_section(res);
			break;
		case TK_DISK:
			res->disk_options = parse_options(TK_DISK_SWITCH,
							  TK_DISK_OPTION);
			break;
		case TK_NET: 
			res->net_options = parse_options(TK_NET_SWITCH,
							 TK_NET_OPTION);
			break;
		case TK_SYNCER:
			res->sync_options = parse_options(TK_SYNCER_SWITCH,
							  TK_SYNCER_OPTION);
			break;
		case TK_STARTUP:
			res->startup_options=parse_options(TK_STARTUP_SWITCH,
							   TK_STARTUP_OPTION);
			break;
		case TK_HANDLER:
			res->handlers =  parse_options(0,
						       TK_HANDLER_OPTION);
			break;
		case '}': return res;
		default:
			pe_expected("protocol | on | disk | net | syncer |"
				    " startup | handler");
		}
	}
}

void parse_skip()
{
	int level=0;
	do {
		switch(yylex()) {
		case '{': 
			level++;
			break;
		case '}': 
			level--;
			break;
		}
	} while(level);
}

void yyparse(void)
{
	common = NULL;
	config = NULL;

	while(1) {
		switch(yylex()) {
		case TK_GLOBAL: parse_global(); break;
		case TK_COMMON: common = parse_resource("common"); break;
		case TK_RESOURCE: 
			EXP(TK_STRING);
			config = APPEND( config , parse_resource(yylval.txt) );
			break;
		case TK_SKIP: parse_skip(); break;
		case 0: return;
		default:
			pe_expected("global | common | resource | skip");
		}
	}
}
