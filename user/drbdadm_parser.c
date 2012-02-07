/*
 *
   drbdadm_parser.c a hand crafted parser

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

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <search.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>

#include "drbdadm.h"
#include "linux/drbd_limits.h"
#include "drbdtool_common.h"
#include "drbdadm_parser.h"

YYSTYPE yylval;

/////////////////////

static int c_section_start;
void my_parse(void);

struct d_name *names_from_str(char* str)
{
	struct d_name *names;

	names = malloc(sizeof(struct d_name));
	names->name = strdup(str);

	return names;
}

char *_names_to_str_c(char* buffer, struct names *names, char c)
{
	int n = 0;
	struct d_name *name;

	if (STAILQ_EMPTY(names)) {
		snprintf(buffer, NAMES_STR_SIZE, "UNKNOWN");
		return buffer;
	}

	name = STAILQ_FIRST(names);
	while (1) {
		n += snprintf(buffer + n, NAMES_STR_SIZE - n, "%s", name->name);
		name = STAILQ_NEXT(name, link);
		if (!name)
			return buffer;
		n += snprintf(buffer + n, NAMES_STR_SIZE - n, "%c", c);
	}
}

char *_names_to_str(char* buffer, struct names *names)
{
	return _names_to_str_c(buffer, names, ' ');
}

int name_in_names(char *name, struct names *names)
{
	struct d_name *n;

	STAILQ_FOREACH(n, names, link)
		if (!strcmp(n->name, name))
			return 1;

	return 0;
}

void free_names(struct names *names)
{
	struct d_name *n, *nf;

	n = STAILQ_FIRST(names);
	while (n) {
		nf = STAILQ_NEXT(n, link);
		free(n->name);
		free(n);
		n = nf;
	}
}

void m_strtoll_range(const char *s, char def_unit,
		     const char *name,
		     unsigned long long min, unsigned long long max)
{
	unsigned long long r = m_strtoll(s, def_unit);
	char unit[] = { def_unit != '1' ? def_unit : 0, 0 };
	if (min > r || r > max) {
		fprintf(stderr,
			"%s:%d: %s %s => %llu%s out of range [%llu..%llu]%s.\n",
			config_file, fline, name, s, r, unit, min, max, unit);
		if (config_valid <= 1) {
			config_valid = 0;
			return;
		}
	}
	if (DEBUG_RANGE_CHECK) {
		fprintf(stderr,
			"%s:%d: %s %s => %llu%s in range [%llu..%llu]%s.\n",
			config_file, fline, name, s, r, unit, min, max, unit);
	}
}

void range_check(const enum range_checks what, const char *name,
		 char *value)
{
	char proto = 0;

	/*
	 * FIXME: Handle signed/unsigned values correctly by checking the
	 * F_field_name_IS_SIGNED defines.
	 */

#define M_STRTOLL_RANGE(x) \
		m_strtoll_range(value, DRBD_ ## x ## _SCALE, name, \
				DRBD_ ## x ## _MIN, \
				DRBD_ ## x ## _MAX)

	switch (what) {
	case R_NO_CHECK:
		break;
	default:
		fprintf(stderr, "%s:%d: unknown range for %s => %s\n",
			config_file, fline, name, value);
		break;
	case R_MINOR_COUNT:
		M_STRTOLL_RANGE(MINOR_COUNT);
		break;
	case R_DIALOG_REFRESH:
		M_STRTOLL_RANGE(DIALOG_REFRESH);
		break;
	case R_DISK_SIZE:
		M_STRTOLL_RANGE(DISK_SIZE);
		break;
	case R_TIMEOUT:
		M_STRTOLL_RANGE(TIMEOUT);
		break;
	case R_CONNECT_INT:
		M_STRTOLL_RANGE(CONNECT_INT);
		break;
	case R_PING_INT:
		M_STRTOLL_RANGE(PING_INT);
		break;
	case R_MAX_BUFFERS:
		M_STRTOLL_RANGE(MAX_BUFFERS);
		break;
	case R_MAX_EPOCH_SIZE:
		M_STRTOLL_RANGE(MAX_EPOCH_SIZE);
		break;
	case R_SNDBUF_SIZE:
		M_STRTOLL_RANGE(SNDBUF_SIZE);
		break;
	case R_RCVBUF_SIZE:
		M_STRTOLL_RANGE(RCVBUF_SIZE);
		break;
	case R_KO_COUNT:
		M_STRTOLL_RANGE(KO_COUNT);
		break;
	case R_RATE:
		M_STRTOLL_RANGE(RESYNC_RATE);
		break;
	case R_AL_EXTENTS:
		M_STRTOLL_RANGE(AL_EXTENTS);
		break;
	case R_PORT:
		M_STRTOLL_RANGE(PORT);
		break;
	/* FIXME not yet implemented!
	case R_META_IDX:
		M_STRTOLL_RANGE(META_IDX);
		break;
	*/
	case R_WFC_TIMEOUT:
		M_STRTOLL_RANGE(WFC_TIMEOUT);
		break;
	case R_DEGR_WFC_TIMEOUT:
		M_STRTOLL_RANGE(DEGR_WFC_TIMEOUT);
		break;
	case R_OUTDATED_WFC_TIMEOUT:
		M_STRTOLL_RANGE(OUTDATED_WFC_TIMEOUT);
		break;

	case R_C_PLAN_AHEAD:
		M_STRTOLL_RANGE(C_PLAN_AHEAD);
		break;

	case R_C_DELAY_TARGET:
		M_STRTOLL_RANGE(C_DELAY_TARGET);
		break;

	case R_C_FILL_TARGET:
		M_STRTOLL_RANGE(C_FILL_TARGET);
		break;

	case R_C_MAX_RATE:
		M_STRTOLL_RANGE(C_MAX_RATE);
		break;

	case R_C_MIN_RATE:
		M_STRTOLL_RANGE(C_MIN_RATE);
		break;

	case R_CONG_FILL:
		M_STRTOLL_RANGE(CONG_FILL);
		break;

	case R_CONG_EXTENTS:
		M_STRTOLL_RANGE(CONG_EXTENTS);
		break;
	case R_PROTOCOL:
		if (value && value[0] && value[1] == 0) {
			proto = value[0] & ~0x20; /* toupper */
			if (proto == 'A' || proto == 'B' || proto == 'C')
				value[0] = proto;
			else
				proto = 0;
		}
		if (!proto && config_valid <= 1) {
			config_valid = 0;
			fprintf(stderr, "unknown protocol '%s', should be one of A,B,C\n", value);
		}
	}
}

struct d_option *new_opt(char *name, char *value)
{
	struct d_option *cn = malloc(sizeof(struct d_option));

	/* fprintf(stderr,"%s:%d: %s = %s\n",config_file,line,name,value); */
	cn->name = name;
	cn->value = value;
	cn->mentioned = 0;
	cn->is_escaped = 0;

	return cn;
}

void pdperror(char *text)
{
	config_valid = 0;
	fprintf(stderr, "%s:%d: in proxy plugin section: %s.\n",
		config_file, line, text);
	exit(E_CONFIG_INVALID);
}

static void pperror(struct d_host_info *host, struct d_proxy_info *proxy, char *text)
{
	config_valid = 0;
	fprintf(stderr, "%s:%d: in section: on %s { proxy on %s { ... } }:"
		" '%s' keyword missing.\n",
		config_file, c_section_start, names_to_str(&host->on_hosts),
		names_to_str(&proxy->on_hosts), text);
}

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

/*
 * for check_uniq: check uniqueness of
 * resource names, ip:port, node:disk and node:device combinations
 * as well as resource:section ...
 * hash table to test for uniqueness of these values...
 *  256  (max minors)
 *  *(
 *       2 (host sections) * 4 (res ip:port node:disk node:device)
 *     + 4 (other sections)
 *     + some more,
 *       if we want to check for scoped uniqueness of *every* option
 *   )
 *     since nobody (?) will actually use more than a dozen minors,
 *     this should be more than enough.
 */
struct hsearch_data global_htable;
void check_uniq_init(void)
{
	memset(&global_htable, 0, sizeof(global_htable));
	if (!hcreate_r(256 * ((2 * 4) + 4), &global_htable)) {
		fprintf(stderr, "Insufficient memory.\n");
		exit(E_EXEC_ERROR);
	};
}

/* some settings need only be unique within one resource definition.
 * we need currently about 8 + (number of host) * 8 entries,
 * 200 should be much more than enough. */
struct hsearch_data per_resource_htable;
void check_upr_init(void)
{
	static int created = 0;
	if (config_valid >= 2)
		return;
	if (created)
		hdestroy_r(&per_resource_htable);
	memset(&per_resource_htable, 0, sizeof(per_resource_htable));
	if (!hcreate_r(256, &per_resource_htable)) {
		fprintf(stderr, "Insufficient memory.\n");
		exit(E_EXEC_ERROR);
	};
	created = 1;
}

/* FIXME
 * strictly speaking we don't need to check for uniqueness of disk and device names,
 * but for uniqueness of their major:minor numbers ;-)
 */
int vcheck_uniq(struct hsearch_data *ht, const char *what, const char *fmt, va_list ap)
{
	int rv;
	ENTRY e, *ep;
	e.key = e.data = ep = NULL;

	/* if we are done parsing the config file,
	 * switch off this paranoia */
	if (config_valid >= 2)
		return 1;

	rv = vasprintf(&e.key, fmt, ap);

	if (rv < 0) {
		perror("vasprintf");
		exit(E_THINKO);
	}

	if (EXIT_ON_CONFLICT && !what) {
		fprintf(stderr, "Oops, unset argument in %s:%d.\n", __FILE__,
			__LINE__);
		exit(E_THINKO);
	}
	m_asprintf((char **)&e.data, "%s:%u", config_file, fline);
	hsearch_r(e, FIND, &ep, ht);
	//fprintf(stderr, "FIND %s: %p\n", e.key, ep);
	if (ep) {
		if (what) {
			fprintf(stderr,
				"%s: conflicting use of %s '%s' ...\n"
				"%s: %s '%s' first used here.\n",
				(char *)e.data,  what, ep->key,
				(char *)ep->data, what, ep->key);
		}
		free(e.key);
		free(e.data);
		config_valid = 0;
	} else {
		//fprintf(stderr, "ENTER %s\t=>\t%s\n", e.key, (char *)e.data);
		hsearch_r(e, ENTER, &ep, ht);
		if (!ep) {
			fprintf(stderr, "hash table entry (%s => %s) failed\n",
					e.key, (char *)e.data);
			exit(E_THINKO);
		}
		ep = NULL;
	}
	if (EXIT_ON_CONFLICT && ep)
		exit(E_CONFIG_INVALID);
	return !ep;
}

int check_uniq(const char *what, const char *fmt, ...)
{
	int rv;
	va_list ap;

	va_start(ap, fmt);
	rv = vcheck_uniq(&global_htable, what, fmt, ap);
	va_end(ap);

	return rv;
}

/* unique per resource */
int check_upr(const char *what, const char *fmt, ...)
{
	int rv;
	va_list ap;

	va_start(ap, fmt);
	rv = vcheck_uniq(&per_resource_htable, what, fmt, ap);
	va_end(ap);

	return rv;
}

static void pe_expected(const char *exp)
{
	const char *s = yytext;
	fprintf(stderr, "%s:%u: Parse error: '%s' expected,\n\t"
		"but got '%.20s%s'\n", config_file, line, exp, s,
		strlen(s) > 20 ? "..." : "");
	exit(E_CONFIG_INVALID);
}

static void check_string_error(int got)
{
	const char *msg;
	switch(got) {
	case TK_ERR_STRING_TOO_LONG:
		msg = "Token too long";
		break;
	case TK_ERR_DQSTRING_TOO_LONG:
		msg = "Double quoted string too long";
		break;
	case TK_ERR_DQSTRING:
		msg = "Unterminated double quoted string\n  we don't allow embedded newlines\n ";
		break;
	default:
		return;
	}
	fprintf(stderr,"%s:%u: %s >>>%.20s...<<<\n", config_file, line, msg, yytext);
	exit(E_CONFIG_INVALID);
}

static void pe_expected_got(const char *exp, int got)
{
	static char tmp[2] = "\0";
	const char *s = yytext;
	if (exp[0] == '\'' && exp[1] && exp[2] == '\'' && exp[3] == 0) {
		tmp[0] = exp[1];
	}
	fprintf(stderr, "%s:%u: Parse error: '%s' expected,\n\t"
		"but got '%.20s%s' (TK %d)\n",
		config_file, line,
		tmp[0] ? tmp : exp, s, strlen(s) > 20 ? "..." : "", got);
	exit(E_CONFIG_INVALID);
}

#define EXP(TOKEN1)						\
({								\
	int token;						\
	token = yylex();					\
	if (token != TOKEN1) {					\
		if (TOKEN1 == TK_STRING)			\
			check_string_error(token);		\
		pe_expected_got( #TOKEN1, token);		\
	}							\
	token;							\
})

static void expect_STRING_or_INT(void)
{
	int token = yylex();
	switch(token) {
	case TK_INTEGER:
	case TK_STRING:
		break;
	case TK_ON:
		yylval.txt = strdup(yytext);
		break;
	default:
		check_string_error(token);
		pe_expected_got("TK_STRING | TK_INTEGER", token);
	}
}

static void parse_global(void)
{
	fline = line;
	check_uniq("global section", "global");
	if (!STAILQ_EMPTY(&config)) {
		fprintf(stderr,
			"%s:%u: You should put the global {} section\n\t"
			"in front of any resource {} section\n",
			config_file, line);
	}
	EXP('{');
	while (1) {
		int token = yylex();
		fline = line;
		switch (token) {
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

static void check_and_change_deprecated_alias(char **name, int token)
{
	int i;
	static struct {
		enum yytokentype token;
		char *old_name, *new_name;
	} table[] = {
		{ TK_HANDLER_OPTION, "outdate-peer", "fence-peer" },
		{ TK_DISK_OPTION, "rate", "resync-rate" },
		{ TK_DISK_OPTION, "after", "resync-after" },
	};

	for (i = 0; i < ARRAY_SIZE(table); i++) {
		if (table[i].token == token &&
		    !strcmp(table[i].old_name, *name)) {
			free(*name);
			*name = strdup(table[i].new_name);
		}
	}
}

/* The syncer section is deprecated. Distribute the options to the disk or net options. */
void parse_options_syncer(struct d_resource *res)
{
	char *opt_name;
	int token;
	enum range_checks rc;

	struct options *options = NULL;
	c_section_start = line;
	fline = line;

	while (1) {
		token = yylex();
		fline = line;
		if (token >= TK_GLOBAL && !(token & TK_SYNCER_OLD_OPT))
			pe_expected("a syncer option keyword");
		token &= ~TK_SYNCER_OLD_OPT;
		switch (token) {
		case TK_NET_FLAG:
		case TK_NET_NO_FLAG:
		case TK_NET_OPTION:
			options = &res->net_options;
			break;
		case TK_DISK_FLAG:
		case TK_DISK_NO_FLAG:
		case TK_DISK_OPTION:
			options = &res->disk_options;
			break;
		case TK_RES_OPTION:
			options = &res->res_options;
			break;
		case '}':
			return;
		default:
			pe_expected("a syncer option keyword");
		}
		opt_name = yylval.txt;
		switch (token) {
		case TK_NET_FLAG:
		case TK_DISK_FLAG:
			token = yylex();
			switch(token) {
			case TK_NO:
				insert_tail(options, new_opt(opt_name, strdup("no")));
				token = yylex();
				break;
			default:
				insert_tail(options, new_opt(opt_name, strdup("yes")));
				if (token == TK_YES)
					token = yylex();
				break;
			}
			break;
		case TK_NET_NO_FLAG:
		case TK_DISK_NO_FLAG:
			/* Backward compatibility with the old config file syntax. */
			assert(!strncmp(opt_name, "no-", 3));
			insert_tail(options, new_opt(strdup(opt_name + 3), strdup("no")));
			free(opt_name);
			token = yylex();
			break;
		case TK_NET_OPTION:
		case TK_DISK_OPTION:
		case TK_RES_OPTION:
			check_and_change_deprecated_alias(&opt_name, token);
			rc = yylval.rc;
			expect_STRING_or_INT();
			range_check(rc, opt_name, yylval.txt);
			insert_tail(options, new_opt(opt_name, yylval.txt));
			token = yylex();
			break;
		}
		switch (token) {
		case ';':
			break;
		default:
			pe_expected(";");
		}
	}
}

static struct options parse_options_d(int token_flag, int token_no_flag, int token_option,
				      int token_delegate, void (*delegate)(void*),
				      void *ctx)
{
	char *opt_name;
	int token, token_group;
	enum range_checks rc;
	struct options options = STAILQ_HEAD_INITIALIZER(options);

	c_section_start = line;
	fline = line;

	while (1) {
		token_group = yylex();
		/* Keep the higher bits in token_option, remove them from token. */
		token = REMOVE_GROUP_FROM_TOKEN(token_group);
		fline = line;
		opt_name = yylval.txt;
		if (token == token_flag) {
			switch(yylex()) {
			case TK_YES:
				insert_tail(&options, new_opt(opt_name, strdup("yes")));
				break;
			case TK_NO:
				insert_tail(&options, new_opt(opt_name, strdup("no")));
				break;
			case ';':
				/* Flag value missing; assume yes.  */
				insert_tail(&options, new_opt(opt_name, strdup("yes")));
				continue;
			default:
				pe_expected("yes | no | ;");
			}
		} else if (token == token_no_flag) {
			/* Backward compatibility with the old config file syntax. */
			assert(!strncmp(opt_name, "no-", 3));
			insert_tail(&options, new_opt(strdup(opt_name + 3), strdup("no")));
			free(opt_name);
		} else if (token == token_option ||
				GET_TOKEN_GROUP(token_option & token_group)) {
			check_and_change_deprecated_alias(&opt_name, token_option);
			rc = yylval.rc;
			expect_STRING_or_INT();
			range_check(rc, opt_name, yylval.txt);
			insert_tail(&options, new_opt(opt_name, yylval.txt));
		} else if (token == token_delegate ||
				GET_TOKEN_GROUP(token_delegate & token_group)) {
			delegate(ctx);
			continue;
		} else if (token == TK_DEPRECATED_OPTION) {
			/* fprintf(stderr, "Warn: Ignoring deprecated option '%s'\n", yylval.txt); */
			expect_STRING_or_INT();
		} else if (token == '}') {
			return options;
		} else {
			pe_expected("an option keyword");
		}
		EXP(';');
	}
}

static struct options parse_options(int token_flag, int token_no_flag, int token_option)
{
	return parse_options_d(token_flag, token_no_flag, token_option, 0, NULL, NULL);
}

static void __parse_address(struct d_address *a)
{
	switch(yylex()) {
	case TK_SCI:   /* 'ssocks' was names 'sci' before. */
		a->af = strdup("ssocks");
		EXP(TK_IPADDR);
		break;
	case TK_SSOCKS:
	case TK_SDP:
	case TK_IPV4:
		a->af = yylval.txt;
		EXP(TK_IPADDR);
		break;
	case TK_IPV6:
		a->af = yylval.txt;
		EXP('[');
		EXP(TK_IPADDR6);
		break;
	case TK_IPADDR:
		a->af = strdup("ipv4");
		break;
	/* case '[': // Do not foster people's laziness ;)
		EXP(TK_IPADDR6);
		*af = strdup("ipv6");
		break; */
	default:
		pe_expected("ssocks | sdp | ipv4 | ipv6 | <ipv4 address> ");
	}

	a->addr = yylval.txt;
	if (!strcmp(a->af, "ipv6"))
		EXP(']');
	EXP(':');
	EXP(TK_INTEGER);
	a->port = yylval.txt;
	range_check(R_PORT, "port", yylval.txt);
}

static void parse_address(struct names *on_hosts, struct d_address *address)
{
	struct d_name *h;
	__parse_address(address);
	if ((!strcmp(address->addr, "127.0.0.1") || !strcmp(address->addr, "::1")) &&
		on_hosts)
		STAILQ_FOREACH(h, on_hosts, link)
			check_uniq("IP", "%s:%s:%s", h->name, address->addr,
				   address->port);
	else
		check_uniq("IP", "%s:%s", address->addr, address->port);
	EXP(';');
}

static void parse_hosts(struct names *hosts, char delimeter)
{
	char errstr[20];
	struct d_name *name;
	int nr_hosts = 0;
	int token;

	while (1) {
		token = yylex();
		switch (token) {
		case TK_STRING:
			name = malloc(sizeof(struct d_name));
			name->name = yylval.txt;
			insert_tail(hosts, name);
			nr_hosts++;
			break;
		default:
			if (token == delimeter) {
				if (nr_hosts == 0)
					pe_expected_got("TK_STRING", token);
				return;
			} else {
				sprintf(errstr, "TK_STRING | '%c'", delimeter);
				pe_expected_got(errstr, token);
			}
		}
	}
}

static void parse_proxy_section(struct d_host_info *host)
{
	struct d_proxy_info *proxy;

	proxy = calloc(1, sizeof(struct d_proxy_info));
	STAILQ_INIT(&proxy->on_hosts);
	host->proxy = proxy;

	EXP(TK_ON);
	parse_hosts(&proxy->on_hosts, '{');
	while (1) {
		switch (yylex()) {
		case TK_INSIDE:
			parse_address(&proxy->on_hosts, &proxy->inside);
			break;
		case TK_OUTSIDE:
			parse_address(&proxy->on_hosts, &proxy->outside);
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("inside | outside");

		}
	}

 break_loop:
	if (!proxy->inside.addr)
		pperror(host, proxy, "inside");

	if (!proxy->outside.addr)
		pperror(host, proxy, "outside");

	return;
}

void parse_meta_disk(struct d_volume *vol)
{
	EXP(TK_STRING);
	vol->meta_disk = yylval.txt;
	if (strcmp("internal", yylval.txt) == 0) {
		/* internal, flexible size */
		vol->meta_index = strdup("internal");
		EXP(';');
	} else {
		switch(yylex()) {
		case '[':
			EXP(TK_INTEGER);
			/* external, static size */
			vol->meta_index = yylval.txt;
			EXP(']');
			EXP(';');
			break;
		case ';':
			/* external, flexible size */
			vol->meta_index = strdup("flexible");
			break;
		default:
			pe_expected("[ | ;");
		}
	}
}

static void check_minor_nonsense(const char *devname, const int explicit_minor)
{
	if (!devname)
		return;

	/* if devname is set, it starts with /dev/drbd */
	if (only_digits(devname + 9)) {
		int m = strtol(devname + 9, NULL, 10);
		if (m == explicit_minor)
			return;

		fprintf(stderr,
			"%s:%d: explicit minor number must match with device name\n"
			"\tTry \"device /dev/drbd%u minor %u;\",\n"
			"\tor leave off either device name or explicit minor.\n"
			"\tArbitrary device names must start with /dev/drbd_\n"
			"\tmind the '_'! (/dev/ is optional, but drbd_ is required)\n",
			config_file, fline, explicit_minor, explicit_minor);
		config_valid = 0;
		return;
	} else if (devname[9] == '_')
		return;

	fprintf(stderr,
		"%s:%d: arbitrary device name must start with /dev/drbd_\n"
		"\tmind the '_'! (/dev/ is optional, but drbd_ is required)\n",
		config_file, fline);
	config_valid = 0;
	return;
}

static void parse_device(struct names* on_hosts, struct d_volume *vol)
{
	struct d_name *h;
	int m;

	switch (yylex()) {
	case TK_STRING:
		if (!strncmp("drbd", yylval.txt, 4)) {
			m_asprintf(&vol->device, "/dev/%s", yylval.txt);
			free(yylval.txt);
		} else
			vol->device = yylval.txt;

		if (strncmp("/dev/drbd", vol->device, 9)) {
			fprintf(stderr,
				"%s:%d: device name must start with /dev/drbd\n"
				"\t(/dev/ is optional, but drbd is required)\n",
				config_file, fline);
			config_valid = 0;
			/* no goto out yet,
			 * as that would additionally throw a parse error */
		}
		switch (yylex()) {
		default:
			pe_expected("minor | ;");
			/* fall through */
		case ';':
			m = dt_minor_of_dev(vol->device);
			if (m < 0) {
				fprintf(stderr,
					"%s:%d: no minor given nor device name contains a minor number\n",
					config_file, fline);
				config_valid = 0;
			}
			vol->device_minor = m;
			goto out;
		case TK_MINOR:
			; /* double fall through */
		}
	case TK_MINOR:
		EXP(TK_INTEGER);
		vol->device_minor = atoi(yylval.txt);
		EXP(';');

		/* if both device name and minor number are explicitly given,
		 * force /dev/drbd<minor-number> or /dev/drbd_<arbitrary> */
		check_minor_nonsense(vol->device, vol->device_minor);
	}
out:
	if (!on_hosts)
		return;

	STAILQ_FOREACH(h, on_hosts, link) {
		check_uniq("device-minor", "device-minor:%s:%u", h->name, vol->device_minor);
		if (vol->device)
			check_uniq("device", "device:%s:%s", h->name, vol->device);
	}
}

struct d_volume *volume0(struct volumes *volumes)
{
	struct d_volume *vol = STAILQ_FIRST(volumes);

	if (!vol) {
		vol = calloc(1, sizeof(struct d_volume));
		vol->device_minor = -1;
		vol->implicit = 1;
		insert_head(volumes, vol);
		return vol;
	} else {
		if (vol->vnr == 0 && STAILQ_NEXT(vol, link) == NULL && vol->implicit)
			return vol;

		config_valid = 0;
		fprintf(stderr,
			"%s:%d: Explicit and implicit volumes not allowed\n",
			config_file, line);
		return vol;
	}
}

int parse_volume_stmt(struct d_volume *vol, struct names* on_hosts, int token)
{
	switch (token) {
	case TK_DISK:
		token = yylex();
		switch (token) {
		case TK_STRING:
			vol->disk = yylval.txt;
			EXP(';');
			break;
		case '{':
			vol->disk_options = parse_options(TK_DISK_FLAG,
							  TK_DISK_NO_FLAG,
							  TK_DISK_OPTION);
			break;
		default:
			check_string_error(token);
			pe_expected_got( "TK_STRING | {", token);
		}
		vol->parsed_disk = 1;
		break;
	case TK_DEVICE:
		parse_device(on_hosts, vol);
		vol->parsed_device = 1;
		break;
	case TK_META_DISK:
		parse_meta_disk(vol);
		vol->parsed_meta_disk = 1;
		break;
	case TK_FLEX_META_DISK:
		EXP(TK_STRING);
		vol->meta_disk = yylval.txt;
		if (strcmp("internal", yylval.txt) != 0) {
			/* external, flexible ize */
			vol->meta_index = strdup("flexible");
		} else {
			/* internal, flexible size */
			vol->meta_index = strdup("internal");
		}
		EXP(';');
		vol->parsed_meta_disk = 1;
		break;
	default:
		return 0;
	}
	return 1;
}

struct d_volume *parse_volume(int vnr, struct names* on_hosts)
{
	struct d_volume *vol;
	int token;

	vol = calloc(1,sizeof(struct d_volume));
	STAILQ_INIT(&vol->disk_options);
	vol->device_minor = -1;
	vol->vnr = vnr;

	EXP('{');
	while (1) {
		token = yylex();
		if (token == '}')
			break;
		if (!parse_volume_stmt(vol, on_hosts, token))
			pe_expected_got("device | disk | meta-disk | flex-meta-disk | }",
					token);
	}

	return vol;
}

struct d_volume *parse_stacked_volume(int vnr)
{
	struct d_volume *vol;

	vol = calloc(1,sizeof(struct d_volume));
	STAILQ_INIT(&vol->disk_options);
	vol->device_minor = -1;
	vol->vnr = vnr;

	EXP('{');
	EXP(TK_DEVICE);
	parse_device(NULL, vol);
	EXP('}');
	vol->meta_disk = strdup("internal");
	vol->meta_index = strdup("internal");

	return vol;
}

enum parse_host_section_flags {
	REQUIRE_ALL = 1,
	BY_ADDRESS  = 2,
};

static void parse_host_section(struct d_resource *res,
			       struct names *on_hosts,
			       enum parse_host_section_flags flags)
{
	struct d_host_info *host;
	struct d_name *h;
	int in_braces = 1;

	c_section_start = line;
	fline = line;

	host = calloc(1,sizeof(struct d_host_info));
	STAILQ_INIT(&host->res_options);
	STAILQ_INIT(&host->volumes);
	host->on_hosts = *on_hosts;
	host->config_line = c_section_start;
	host->require_all = flags & REQUIRE_ALL ? 1 : 0;

	if (flags & BY_ADDRESS) {
		/* floating <address> {} */
		char *fake_uname = NULL;
		int token;

		host->by_address = 1;
		__parse_address(&host->address);
		check_uniq("IP", "%s:%s", host->address.addr, host->address.port);
		if (!strcmp(host->address.af, "ipv6"))
			m_asprintf(&fake_uname, "ipv6 [%s]:%s", host->address.addr, host->address.port);
		else
			m_asprintf(&fake_uname, "%s:%s", host->address.addr, host->address.port);
		insert_head(&host->on_hosts, names_from_str(fake_uname));

		token = yylex();
		switch(token) {
		case '{':
			break;
		case ';':
			in_braces = 0;
			break;
		default:
			pe_expected_got("{ | ;", token);
		}
	}

	STAILQ_FOREACH(h, on_hosts, link)
		check_upr("host section", "%s: on %s", res->name, h->name);
	insert_tail(&res->all_hosts, host);

	while (in_braces) {
		int token = yylex();
		fline = line;
		switch (token) {
		case TK_DISK:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("disk statement", "%s:%s:disk", res->name, h->name);
			goto vol0stmt;
			/* STAILQ_FOREACH(h, on_hosts)
			  check_uniq("disk", "disk:%s:%s", h->name, yylval.txt); */
		case TK_DEVICE:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("device statement", "%s:%s:device", res->name, h->name);
			goto vol0stmt;
		case TK_META_DISK:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("meta-disk statement", "%s:%s:meta-disk", res->name, h->name);
			goto vol0stmt;
		case TK_FLEX_META_DISK:
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("meta-disk statement", "%s:%s:meta-disk", res->name, h->name);
			goto vol0stmt;
			break;
		case TK_ADDRESS:
			if (host->by_address) {
				fprintf(stderr,
					"%s:%d: address statement not allowed for floating {} host sections\n",
					config_file, fline);
				config_valid = 0;
				exit(E_CONFIG_INVALID);
			}
			STAILQ_FOREACH(h, on_hosts, link)
				check_upr("address statement", "%s:%s:address", res->name, h->name);
			parse_address(on_hosts, &host->address);
			range_check(R_PORT, "port", host->address.port);
			break;
		case TK_PROXY:
			parse_proxy_section(host);
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			insert_volume(&host->volumes, parse_volume(atoi(yylval.txt), on_hosts));
			break;
		case TK_OPTIONS:
			EXP('{');
			host->res_options = parse_options(0,
							  0,
							  TK_RES_OPTION);
			break;
		case '}':
			in_braces = 0;
			break;
		vol0stmt:
			if (parse_volume_stmt(volume0(&host->volumes), on_hosts, token))
				break;
			/* else fall through */
		default:
			pe_expected("disk | device | address | meta-disk "
				    "| flexible-meta-disk");
		}
	}
}

void parse_skip()
{
	int level;
	int token;
	fline = line;

	token = yylex();
	switch (token) {
	case TK_STRING:
		EXP('{');
		break;
	case '{':
		break;
	default:
		check_string_error(token);
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
			exit(E_CONFIG_INVALID);
		}
	}
}

void parse_stacked_section(struct d_resource* res)
{
	struct d_host_info *host;
	struct d_name *h;

	c_section_start = line;
	fline = line;

	host = calloc(1, sizeof(struct d_host_info));
	STAILQ_INIT(&host->res_options);
	STAILQ_INIT(&host->on_hosts);
	STAILQ_INIT(&host->volumes);
	insert_tail(&res->all_hosts, host);
	EXP(TK_STRING);
	check_uniq("stacked-on-top-of", "stacked:%s", yylval.txt);
	host->lower_name = yylval.txt;

	EXP('{');
	while (1) {
		switch(yylex()) {
		case TK_DEVICE:
			/* STAILQ_FOREACH(h, host->on_hosts)
			  check_upr("device statement", "%s:%s:device", res->name, h->name); */
			parse_device(&host->on_hosts, volume0(&host->volumes));
			volume0(&host->volumes)->meta_disk = strdup("internal");
			volume0(&host->volumes)->meta_index = strdup("internal");
			break;
		case TK_ADDRESS:
			STAILQ_FOREACH(h, &host->on_hosts, link)
				check_upr("address statement", "%s:%s:address", res->name, h->name);
			parse_address(NULL, &host->address);
			range_check(R_PORT, "port", yylval.txt);
			break;
		case TK_PROXY:
			parse_proxy_section(host);
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			insert_volume(&host->volumes, parse_stacked_volume(atoi(yylval.txt)));
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("device | address | proxy");
		}
	}
 break_loop:

	res->stacked_on_one = 1;
}

void startup_delegate(void *ctx)
{
	struct d_resource *res = (struct d_resource *)ctx;

	if (!strcmp(yytext, "become-primary-on")) {
		parse_hosts(&res->become_primary_on, ';');
	} else if (!strcmp(yytext, "stacked-timeouts")) {
		res->stacked_timeouts = 1;
		EXP(';');
	} else
		pe_expected("<an option keyword> | become-primary-on | stacked-timeouts");
}

void net_delegate(void *ctx)
{
	enum pr_flags flags = (enum pr_flags)ctx;

	if (!strcmp(yytext, "discard-my-data") && flags & PARSE_FOR_ADJUST) {
		switch(yylex()) {
		case TK_YES:
		case TK_NO:
			/* Ignore this option.  */
			EXP(';');
			break;
		case ';':
			/* Ignore this option.  */
			return;
		default:
			pe_expected("yes | no | ;");
		}
	} else
		pe_expected("an option keyword");
}

void proxy_delegate(void *ctx)
{
	struct d_resource *res = (struct d_resource *)ctx;
	int token;
	struct options options = STAILQ_HEAD_INITIALIZER(options);
	struct d_option *opt;
	struct names line;
	struct d_name *word;

	opt = NULL;
	token = yylex();
	if (token != '{') {
		fprintf(stderr,	"%s:%d: expected \"{\" after \"proxy\" keyword\n",
				config_file, fline);
		exit(E_CONFIG_INVALID);
	}

	while (1) {
		STAILQ_INIT(&line);
		while (1) {
			token = yylex();
			if (token == ';')
				break;
			if (token == '}') {
				if (STAILQ_EMPTY(&line))
					goto out;

				fprintf(stderr,	"%s:%d: Missing \";\" before  \"}\"\n",
					config_file, fline);
				exit(E_CONFIG_INVALID);
			}

			word = malloc(sizeof(struct d_name));
			if (!word)
				pdperror("out of memory.");
			word->name = yylval.txt;
			insert_tail(&line, word);
		}

		opt = calloc(1, sizeof(struct d_option));
		if (!opt)
			pdperror("out of memory.");
		opt->name = strdup(names_to_str(&line));
		insert_tail(&options, opt);
		free_names(&line);
	}
out:
	if (res)
		res->proxy_plugins = options;
}

int parse_proxy_settings(struct d_resource *res, int flags)
{
	int token;
	struct options proxy_options;

	if (flags & PARSER_CHECK_PROXY_KEYWORD) {
		token = yylex();
		if (token != TK_PROXY) {
			if (flags & PARSER_STOP_IF_INVALID) {
				yyrestart(yyin); /* flushes flex's buffers */
				return 1;
			}

			pe_expected_got("proxy", token);
		}
	}

	EXP('{');

	proxy_options = parse_options_d(0,
					0,
					TK_PROXY_OPTION | TK_PROXY_GROUP,
					TK_PROXY_DELEGATE,
					proxy_delegate,
					res);

	if (res)
		res->proxy_options = proxy_options;
	return 0;
}

static struct hname_address *parse_hname_address_pair()
{
	struct hname_address *ha;
	int token;

	ha = calloc(1, sizeof(struct hname_address));
	ha->config_line = line;

	EXP(TK_STRING);
	ha->name = yylval.txt;

	token = yylex();
	switch (token) {
	case TK_ADDRESS:
		__parse_address(&ha->address);
		ha->parsed_address = 1;
		EXP(';');
		break;
	case TK_PORT:
		EXP(TK_INTEGER);
		ha->address.port = yylval.txt;
		ha->parsed_port = 1;
		EXP(';');
		break;
	case ';':
		break;
	default:
		pe_expected_got( "address | port | ;", token);
	}

	return ha;
}

static struct connection *parse_connection(enum pr_flags flags)
{
	struct connection *conn;
	int hosts = 0, token;

	conn = calloc(1, sizeof(struct connection));
	STAILQ_INIT(&conn->hname_address_pairs);
	STAILQ_INIT(&conn->net_options);
	conn->config_line = line;

	token = yylex();
	switch (token) {
	case '{':
		break;
	case TK_STRING:
		conn->name = yylval.txt;
		EXP('{');
		break;
	default:
		pe_expected_got( "<connection name> | {", token);
	}
	while (1) {
		token = yylex();
		switch(token) {
		case TK_HOST:
			insert_tail(&conn->hname_address_pairs, parse_hname_address_pair());
			if (++hosts >= 3) {
				fprintf(stderr,	"%s:%d: only two 'host' keywords per connection allowed\n",
					config_file, fline);
				config_valid = 0;
			}
			break;
		case TK_NET:
			if (!STAILQ_EMPTY(&conn->net_options)) {
				fprintf(stderr,	"%s:%d: only one 'net' section per connection allowed\n",
					config_file, fline);
				config_valid = 0;
			}
			EXP('{');
			conn->net_options = parse_options_d(TK_NET_FLAG, TK_NET_NO_FLAG, TK_NET_OPTION,
							    TK_NET_DELEGATE, &net_delegate, (void *)flags);
			break;
		case '}':
			return conn;
		default:
			pe_expected_got( "host | net | }", token);
		}
	}
}

struct d_resource* parse_resource(char* res_name, enum pr_flags flags)
{
	struct d_resource* res;
	struct names host_names;
	struct options options;
	char *opt_name;
	int token;

	check_upr_init();
	check_uniq("resource section", res_name);

	res = calloc(1, sizeof(struct d_resource));
	STAILQ_INIT(&res->volumes);
	STAILQ_INIT(&res->connections);
	STAILQ_INIT(&res->all_hosts);
	STAILQ_INIT(&res->net_options);
	STAILQ_INIT(&res->disk_options);
	STAILQ_INIT(&res->res_options);
	STAILQ_INIT(&res->startup_options);
	STAILQ_INIT(&res->handlers);
	STAILQ_INIT(&res->proxy_options);
	STAILQ_INIT(&res->proxy_plugins);
	res->name = res_name;
	res->config_file = config_save;
	res->start_line = line;

	while(1) {
		token = yylex();
		fline = line;
		switch(token) {
		case TK_NET_OPTION:
			if (strcmp(yylval.txt, "protocol"))
				goto goto_default;
			check_upr("protocol statement","%s: protocol",res->name);
			opt_name = yylval.txt;
			EXP(TK_STRING);
			range_check(R_PROTOCOL, opt_name, yylval.txt);
			insert_tail(&res->net_options, new_opt(opt_name, yylval.txt));
			EXP(';');
			break;
		case TK_ON:
			STAILQ_INIT(&host_names);
			parse_hosts(&host_names, '{');
			parse_host_section(res, &host_names, REQUIRE_ALL);
			break;
		case TK_STACKED:
			parse_stacked_section(res);
			break;
		case TK__THIS_HOST:
			EXP('{');
			STAILQ_INIT(&host_names);
			insert_head(&host_names, names_from_str("_this_host"));
			parse_host_section(res, &host_names, 0);
			break;
		case TK__REMOTE_HOST:
			EXP('{');
			STAILQ_INIT(&host_names);
			insert_head(&host_names, names_from_str("_remote_host"));
			parse_host_section(res, &host_names, 0);
			break;
		case TK_FLOATING:
			STAILQ_INIT(&host_names);
			parse_host_section(res, &host_names, REQUIRE_ALL + BY_ADDRESS);
			break;
		case TK_DISK:
			switch (token=yylex()) {
			case TK_STRING:
				/* open coded parse_volume_stmt() */
				volume0(&res->volumes)->disk = yylval.txt;
				EXP(';');
				break;
			case '{':
				check_upr("disk section", "%s:disk", res->name);
				options = parse_options(TK_DISK_FLAG, TK_DISK_NO_FLAG, TK_DISK_OPTION);
				STAILQ_CONCAT(&res->disk_options, &options);
				break;
			default:
				check_string_error(token);
				pe_expected_got( "TK_STRING | {", token);
			}
			break;
		case TK_NET:
			check_upr("net section", "%s:net", res->name);
			EXP('{');
			options = parse_options_d(TK_NET_FLAG, TK_NET_NO_FLAG, TK_NET_OPTION,
						  TK_NET_DELEGATE, &net_delegate, (void *)flags);
			STAILQ_CONCAT(&res->net_options, &options);
			break;
		case TK_SYNCER:
			check_upr("syncer section", "%s:syncer", res->name);
			EXP('{');
			parse_options_syncer(res);
			break;
		case TK_STARTUP:
			check_upr("startup section", "%s:startup", res->name);
			EXP('{');
			res->startup_options = parse_options_d(TK_STARTUP_FLAG,
							       0,
							       TK_STARTUP_OPTION,
							       TK_STARTUP_DELEGATE,
							       &startup_delegate,
							       res);
			break;
		case TK_HANDLER:
			check_upr("handlers section", "%s:handlers", res->name);
			EXP('{');
			res->handlers =  parse_options(0, 0, TK_HANDLER_OPTION);
			break;
		case TK_PROXY:
			check_upr("proxy section", "%s:proxy", res->name);
			parse_proxy_settings(res, 0);
			break;
		case TK_DEVICE:
			check_upr("device statement", "%s:device", res->name);
		case TK_META_DISK:
		case TK_FLEX_META_DISK:
			parse_volume_stmt(volume0(&res->volumes), NULL, token);
			break;
		case TK_VOLUME:
			EXP(TK_INTEGER);
			insert_volume(&res->volumes, parse_volume(atoi(yylval.txt), NULL));
			break;
		case TK_OPTIONS:
			check_upr("resource options section", "%s:res_options", res->name);
			EXP('{');
			options = parse_options(0, 0, TK_RES_OPTION);
			STAILQ_CONCAT(&res->res_options, &options);
			break;
		case TK_CONNECTION:
			insert_tail(&res->connections, parse_connection(flags));
			break;
		case '}':
		case 0:
			goto exit_loop;
		default:
		goto_default:
			pe_expected_got("protocol | on | disk | net | syncer |"
					" startup | handlers | connection |"
					" ignore-on | stacked-on-top-of",token);
		}
	}

 exit_loop:

	if (flags == NO_HOST_SECT_ALLOWED && !STAILQ_EMPTY(&res->all_hosts)) {
		config_valid = 0;

		fprintf(stderr,
			"%s:%d: in the %s section, there are no host sections"
			" allowed.\n",
			config_file, c_section_start, res->name);
	}

	return res;
}

struct d_resource* parse_resource_for_adjust(struct cfg_ctx *ctx)
{
	int token;

	token = yylex();
	if (token != TK_RESOURCE)
		return NULL;

	token = yylex();
	if (token != TK_STRING)
		return NULL;

	/* FIXME assert that string and ctx->res->name match? */

	token = yylex();
	if (token != '{')
		return NULL;

	return parse_resource(ctx->res->name, PARSE_FOR_ADJUST);
}

void include_file(FILE *f, char *name)
{
	int saved_line;
	char *saved_config_file, *saved_config_save;

	saved_line = line;
	saved_config_file = config_file;
	saved_config_save = config_save;
	line = 1;
	config_file = name;
	config_save = canonify_path(name);

	my_yypush_buffer_state(f);
	my_parse();
	yypop_buffer_state();

	line = saved_line;
	config_file = saved_config_file;
	config_save = saved_config_save;
}

void include_stmt(char *str)
{
	char *last_slash, *tmp;
	glob_t glob_buf;
	int cwd_fd;
	FILE *f;
	size_t i;
	int r;

	/* in order to allow relative paths in include statements we change
	   directory to the location of the current configuration file. */
	cwd_fd = open(".", O_RDONLY);
	if (cwd_fd < 0) {
		fprintf(stderr, "open(\".\") failed: %m\n");
		exit(E_USAGE);
	}

	tmp = strdupa(config_save);
	last_slash = strrchr(tmp, '/');
	if (last_slash)
		*last_slash = 0;

	if (chdir(tmp)) {
		fprintf(stderr, "chdir(\"%s\") failed: %m\n", tmp);
		exit(E_USAGE);
	}

	r = glob(str, 0, NULL, &glob_buf);
	if (r == 0) {
		for (i=0; i<glob_buf.gl_pathc; i++) {
			f = fopen(glob_buf.gl_pathv[i], "r");
			if (f) {
				include_file(f, strdup(glob_buf.gl_pathv[i]));
				fclose(f);
			} else {
				fprintf(stderr,
					"%s:%d: Failed to open include file '%s'.\n",
					config_file, line, yylval.txt);
				config_valid = 0;
			}
		}
		globfree(&glob_buf);
	} else if (r == GLOB_NOMATCH) {
		if (!strchr(str, '?') && !strchr(str, '*') && !strchr(str, '[')) {
			fprintf(stderr,
				"%s:%d: Failed to open include file '%s'.\n",
				config_file, line, yylval.txt);
			config_valid = 0;
		}
	} else {
		fprintf(stderr, "glob() failed: %d\n", r);
		exit(E_USAGE);
	}

	if (fchdir(cwd_fd) < 0) {
		fprintf(stderr, "fchdir() failed: %m\n");
		exit(E_USAGE);
	}
}

void my_parse(void)
{
	static int global_htable_init = 0;
	if (!global_htable_init) {
		check_uniq_init();
		global_htable_init = 1;
	}

	while (1) {
		int token = yylex();
		fline = line;
		switch(token) {
		case TK_GLOBAL:
			parse_global();
			break;
		case TK_COMMON:
			EXP('{');
			common = parse_resource("common",NO_HOST_SECT_ALLOWED);
			break;
		case TK_RESOURCE:
			EXP(TK_STRING);
			EXP('{');
			insert_tail(&config, parse_resource(yylval.txt, 0));
			break;
		case TK_SKIP:
			parse_skip();
			break;
		case TK_INCLUDE:
			EXP(TK_STRING);
			EXP(';');
			include_stmt(yylval.txt);
			break;
		case 0:
			return;
		default:
			pe_expected("global | common | resource | skip | include");
		}
	}
}
