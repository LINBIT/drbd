/*
   drbdadm_parser.h a hand crafted parser

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2006-2008, LINBIT Information Technologies GmbH
   Copyright (C) 2006-2008, Philipp Reisner <philipp.reisner@linbit.com>
   Copyright (C) 2006-2008, Lars Ellenberg  <lars.ellenberg@linbit.com>

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


enum range_checks
{
	R_NO_CHECK,
	R_MINOR_COUNT,
	R_DIALOG_REFRESH,
	R_DISK_SIZE,
	R_TIMEOUT,
	R_CONNECT_INT,
	R_PING_INT,
	R_MAX_BUFFERS,
	R_MAX_EPOCH_SIZE,
	R_SNDBUF_SIZE,
	R_RCVBUF_SIZE,
	R_KO_COUNT,
	R_RATE,
	R_GROUP,
	R_AL_EXTENTS,
	R_PORT,
	R_META_IDX,
	R_WFC_TIMEOUT,
	R_DEGR_WFC_TIMEOUT,
	R_OUTDATED_WFC_TIMEOUT,
	R_C_PLAN_AHEAD,
	R_C_DELAY_TARGET,
	R_C_FILL_TARGET,
	R_C_MAX_RATE,
	R_C_MIN_RATE,
	R_CONG_FILL,
	R_CONG_EXTENTS,
};

enum yytokentype {
	TK_GLOBAL = 258,
	TK_RESOURCE,
	TK_ON,
	TK_STACKED,
	TK_IGNORE,
	TK_NET,
	TK_DISK,
	TK_SKIP,
	TK_SYNCER,
	TK_STARTUP,
	TK_DISABLE_IP_VERIFICATION,
	TK_DIALOG_REFRESH,
	TK_PROTOCOL,
	TK_HANDLER,
	TK_COMMON,
	TK_ADDRESS,
	TK_DEVICE,
	TK_MINOR,
	TK_META_DISK,
	TK_FLEX_META_DISK,
	TK_MINOR_COUNT,
	TK_IPADDR,
	TK_INTEGER,
	TK_STRING,
	TK_ELSE,
	TK_DISK_SWITCH,
	TK_DISK_OPTION,
	TK_NET_SWITCH,
	TK_NET_OPTION,
	TK_SYNCER_SWITCH,
	TK_SYNCER_OPTION,
	TK_STARTUP_SWITCH,
	TK_STARTUP_OPTION,
	TK_STARTUP_DELEGATE,
	TK_HANDLER_OPTION,
	TK_USAGE_COUNT,
	TK_ASK,
	TK_YES,
	TK_NO,
	TK__IS_DEFAULT,
	TK__THIS_HOST,
	TK__REMOTE_HOST,
	TK_PROXY,
	TK_INSIDE,
	TK_OUTSIDE,
	TK_MEMLIMIT,
	TK_PROXY_OPTION,
	TK_PROXY_SWITCH,
	TK_PROXY_DELEGATE,
	TK_ERR_STRING_TOO_LONG,
	TK_ERR_DQSTRING_TOO_LONG,
	TK_ERR_DQSTRING,
	TK_SCI,
	TK_SDP,
	TK_SSOCKS,
	TK_IPV4,
	TK_IPV6,
	TK_IPADDR6,
	TK_NET_DELEGATE,
	TK_INCLUDE,
	TK_FLOATING,
	TK_DEPRECATED_OPTION,
};

typedef struct YYSTYPE {
	char* txt;
	enum range_checks rc;
} YYSTYPE;

#define yystype YYSTYPE /* obsolescent; will be withdrawn */
#define YYSTYPE_IS_DECLARED 1
#define YYSTYPE_IS_TRIVIAL 1

extern yystype yylval;
extern char* yytext;
extern FILE* yyin;

/* avoid compiler warnings about implicit declaration */
int yylex(void);
void my_yypush_buffer_state(FILE *f);
void yypop_buffer_state (void );
void yyrestart(FILE *input_file);
