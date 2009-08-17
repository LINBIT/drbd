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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <search.h>

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
	names->next = NULL;
	names->name = strdup(str);

	return names;
}

char *_names_to_str_c(char* buffer, struct d_name *names, char c)
{
	int n = 0;

	if (!names)
		return buffer;

	while (1) {
		n += snprintf(buffer + n, NAMES_STR_SIZE - n, "%s", names->name);
		names = names->next;
		if (!names)
			return buffer;
		n += snprintf(buffer + n, NAMES_STR_SIZE - n, "%c", c);
	}
}

char *_names_to_str(char* buffer, struct d_name *names)
{
	return _names_to_str_c(buffer, names, ' ');
}

int name_in_names(char *name, struct d_name *names)
{
	while (names) {
		if (!strcmp(names->name, name))
			return 1;
		names = names->next;
	}
	return 0;
}

void free_names(struct d_name *names)
{
	struct d_name *nf;
	while (names) {
		nf = names->next;
		free(names->name);
		free(names);
		names = nf;
	}
}

static void append_names(struct d_name **head, struct d_name ***last, struct d_name *to_copy)
{
	struct d_name *new;

	while (to_copy) {
		new = malloc(sizeof(struct d_name));
		if (!*head)
			*head = new;
		new->name = strdup(to_copy->name);
		new->next = NULL;
		if (*last)
			**last = new;
		*last = &new->next;
		to_copy = to_copy->next;
	}
}


struct d_name *concat_names(struct d_name *to_copy1, struct d_name *to_copy2)
{
	struct d_name *head = NULL, **last = NULL;

	append_names(&head, &last, to_copy1);
	append_names(&head, &last, to_copy2);

	return head;
}

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
		m_strtoll_range(value, 's', name,
				DRBD_DISK_SIZE_SECT_MIN,
				DRBD_DISK_SIZE_SECT_MAX);
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
	case R_RCVBUF_SIZE:
		m_strtoll_range(value, 1, name, DRBD_RCVBUF_SIZE_MIN,
				DRBD_RCVBUF_SIZE_MAX);
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
	case R_OUTDATED_WFC_TIMEOUT:
		m_strtoll_range(value, 1, name, DRBD_OUTDATED_WFC_TIMEOUT_MIN,
				DRBD_OUTDATED_WFC_TIMEOUT_MAX);
		break;
	}
}

struct d_option *new_opt(char *name, char *value)
{
	struct d_option *cn = malloc(sizeof(struct d_option));

	/* fprintf(stderr,"%s:%d: %s = %s\n",config_file,line,name,value); */
	cn->name = name;
	cn->value = value;
	cn->mentioned = 0;
	cn->is_default = 0;
	cn->is_escaped = 0;

	return cn;
}
static void derror(struct d_host_info *host, struct d_resource *res, char *text)
{
	config_valid = 0;
	fprintf(stderr, "%s:%d: in resource %s, on %s { ... }:"
		" '%s' keyword missing.\n",
		config_file, c_section_start, res->name, names_to_str(host->on_hosts), text);
}

static void pperror(struct d_host_info *host, struct d_proxy_info *proxy, char *text)
{
	config_valid = 0;
	fprintf(stderr, "%s:%d: in section: on %s { proxy on %s { ... } }:"
		" '%s' keyword missing.\n",
		config_file, c_section_start, names_to_str(host->on_hosts),
		names_to_str(proxy->on_hosts), text);
}

#define typecheck(type,x) \
({	type __dummy; \
	typeof(x) __dummy2; \
	(void)(&__dummy == &__dummy2); \
	1; \
})

#define for_each_host(h_,hosts_) \
	for ( ({ typecheck(struct d_name*, h_); \
		h_ = hosts_; }); \
	 	h_; h_ = h_->next)

/*
 * for check_uniq: check uniqueness of
 * resource names, ip:port, node:disk and node:device combinations
 * as well as resource:section ...
 * hash table to test for uniqness of these values...
 *  256  (max minors)
 *  *(
 *       2 (host sections) * 4 (res ip:port node:disk node:device)
 *     + 4 (other sections)
 *     + some more,
 *       if we want to check for scoped uniqueness of *every* option
 *   )
 *     since nobody (?) will actually use more than a dozend minors,
 *     this should be more than enough.
 */
struct hsearch_data global_htable;
void check_uniq_init(void)
{
	memset(&global_htable, 0, sizeof(global_htable));
	if (!hcreate_r(256 * ((2 * 4) + 4), &global_htable)) {
		fprintf(stderr, "Insufficient memory.\n");
		exit(E_exec_error);
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
		exit(E_exec_error);
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
		exit(E_thinko);
	}

	if (EXIT_ON_CONFLICT && !what) {
		fprintf(stderr, "Oops, unset argument in %s:%d.\n", __FILE__,
			__LINE__);
		exit(E_thinko);
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
			exit(E_thinko);
		}
		ep = NULL;
	}
	if (EXIT_ON_CONFLICT && ep)
		exit(E_config_invalid);
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

void check_meta_disk(struct d_host_info *host)
{
	struct d_name *h;
	if (strcmp(host->meta_disk, "internal") != 0) {
		/* external */
		if (host->meta_index == NULL) {
			fprintf(stderr,
				"%s:%d: expected 'meta-disk = %s [index]'.\n",
				config_file, fline, host->meta_disk);
		}
		/* index either some number, or "flexible" */
		for_each_host(h, host->on_hosts)
			check_uniq("meta-disk", "%s:%s[%s]", h->name, host->meta_disk, host->meta_index);
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

static void pe_expected(const char *exp)
{
	const char *s = yytext;
	fprintf(stderr, "%s:%u: Parse error: '%s' expected,\n\t"
		"but got '%.20s%s'\n", config_file, line, exp, s,
		strlen(s) > 20 ? "..." : "");
	exit(E_config_invalid);
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
	exit(E_config_invalid);
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
	exit(E_config_invalid);
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
	if (config) {
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

static void check_and_change_deprecated_alias(char **name, int token_option)
{
	if (token_option == TK_HANDLER_OPTION) {
		if (!strcmp(*name, "outdate-peer")) {
			/* fprintf(stder, "config file:line: name is deprecated ...\n") */
			free(*name);
			*name = strdup("fence-peer");
		}
	}
}

static struct d_option *parse_options_d(int token_switch, int token_option,
					int token_delegate, void (*delegate)(void*),
					void *ctx)
{
	char *opt_name;
	int token;
	enum range_checks rc;

	struct d_option *options = NULL, *ro = NULL;
	c_section_start = line;
	fline = line;

	while (1) {
		token = yylex();
		fline = line;
		if (token == token_switch) {
			options = APPEND(options, new_opt(yylval.txt, NULL));
		} else if (token == token_option) {
			opt_name = yylval.txt;
			check_and_change_deprecated_alias(&opt_name, token_option);
			rc = yylval.rc;
			expect_STRING_or_INT();
			range_check(rc, opt_name, yylval.txt);
			ro = new_opt(opt_name, yylval.txt);
			options = APPEND(options, ro);
		} else if (token == token_delegate) {
			delegate(ctx);
			continue;
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

static struct d_option *parse_options(int token_switch, int token_option)
{
	return parse_options_d(token_switch, token_option, 0, NULL, NULL);
}

static void __parse_address(char** addr, char** port, char** af)
{
	switch(yylex()) {
	case TK_SCI:   /* 'ssocks' was names 'sci' before. */
		if (af)
			*af = strdup("ssocks");
		EXP(TK_IPADDR);
		break;
	case TK_SSOCKS:
	case TK_SDP:
	case TK_IPV4:
		if (af)
			*af = yylval.txt;
		EXP(TK_IPADDR);
		break;
	case TK_IPV6:
		if (af)
			*af = yylval.txt;
		EXP('[');
		EXP(TK_IPADDR6);
		break;
	case TK_IPADDR:
		if (af)
			*af = strdup("ipv4");
		break;
	/* case '[': // Do not foster people's laziness ;)
		EXP(TK_IPADDR6);
		*af = strdup("ipv6");
		break; */
	default:
		pe_expected("ssocks | sdp | ipv4 | ipv6 | <ipv4 address> ");
	}

	if (addr)
		*addr = yylval.txt;
	if (af && !strcmp(*af, "ipv6"))
		EXP(']');
	EXP(':');
	EXP(TK_INTEGER);
	if (port)
		*port = yylval.txt;
	range_check(R_PORT, "port", yylval.txt);
}

static void parse_address(struct d_name *on_hosts, char** addr, char** port, char** af)
{
	struct d_name *h;
	__parse_address(addr, port, af);
	if (!strcmp(*addr, "127.0.0.1") || !strcmp(*addr, "::1"))
		for_each_host(h, on_hosts)
			check_uniq("IP", "%s:%s:%s", h->name, *addr, *port);
	else
		check_uniq("IP", "%s:%s", *addr, *port);
	EXP(';');
}

static void parse_hosts(struct d_name **pnp, char delimeter)
{
	char errstr[20];
	struct d_name *name;
	int hosts = 0;
	int token;

	while (1) {
		token = yylex();
		switch (token) {
		case TK_STRING:
			name = malloc(sizeof(struct d_name));
			name->name = yylval.txt;
			name->next = NULL;
			*pnp = name;
			pnp = &name->next;
			hosts++;
			break;
		default:
			if (token == delimeter) {
				if (!hosts)
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

	proxy=calloc(1,sizeof(struct d_proxy_info));
	host->proxy = proxy;

	EXP(TK_ON);
	parse_hosts(&proxy->on_hosts, '{');
	while (1) {
		switch (yylex()) {
		case TK_INSIDE:
			parse_address(proxy->on_hosts, &proxy->inside_addr, &proxy->inside_port, &proxy->inside_af);
			break;
		case TK_OUTSIDE:
			parse_address(proxy->on_hosts, &proxy->outside_addr, &proxy->outside_port, &proxy->outside_af);
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("inside | outside");

		}
	}

 break_loop:
	if (!proxy->inside_addr)
		pperror(host, proxy, "inside");

	if (!proxy->outside_addr)
		pperror(host, proxy, "outside");

	return;
}

static void parse_meta_disk(char **disk, char** index)
{
	EXP(TK_STRING);
	*disk = yylval.txt;
	if (strcmp("internal", yylval.txt)) {
		EXP('[');
		EXP(TK_INTEGER);
		*index = yylval.txt;
		EXP(']');
		EXP(';');
	} else {
		EXP(';');
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

static void parse_device(struct d_name* on_hosts, unsigned *minor, char **device)
{
	struct d_name *h;
	int m;

	switch (yylex()) {
	case TK_STRING:
		if (!strncmp("drbd", yylval.txt, 4)) {
			m_asprintf(device, "/dev/%s", yylval.txt);
			free(yylval.txt);
		} else
			*device = yylval.txt;

		if (strncmp("/dev/drbd", *device, 9)) {
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
			m = dt_minor_of_dev(*device);
			if (m < 0) {
				fprintf(stderr,
					"%s:%d: no minor given nor device name conains a minor number\n",
					config_file, fline);
				config_valid = 0;
			}
			*minor = m;
			goto out;
		case TK_MINOR:
			; /* double fall through */
		}
	case TK_MINOR:
		EXP(TK_INTEGER);
		*minor = atoi(yylval.txt);
		EXP(';');

		/* if both device name and minor number are explicitly given,
		 * force /dev/drbd<minor-number> or /dev/drbd_<arbitrary> */
		check_minor_nonsense(*device, *minor);
	}
out:
	for_each_host(h, on_hosts) {
		check_uniq("device-minor", "device-minor:%s:%u", h->name, *minor);
		check_uniq("device", "device:%s:%s", h->name, *device);
	}
}

enum parse_host_section_flags {
	REQUIRE_ALL = 1,
	BY_ADDRESS  = 2,
};

static void parse_host_section(struct d_resource *res,
			       struct d_name* on_hosts,
			       enum parse_host_section_flags flags)
{
	struct d_host_info *host;
	struct d_name *h;
	int in_braces = 1;

	c_section_start = line;
	fline = line;

	host=calloc(1,sizeof(struct d_host_info));
	host->on_hosts = on_hosts;
	host->config_line = c_section_start;
	host->device_minor = -1;

	if (flags & BY_ADDRESS) {
		/* floating <address> {} */
		char *fake_uname = NULL;
		int token;

		host->by_address = 1;
		__parse_address(&host->address, &host->port, &host->address_family);
		check_uniq("IP", "%s:%s", host->address, host->port);
		if (!strcmp(host->address_family, "ipv6"))
			m_asprintf(&fake_uname, "ipv6 [%s]:%s", host->address, host->port);
		else
			m_asprintf(&fake_uname, "%s:%s", host->address, host->port);
		on_hosts = names_from_str(fake_uname);
		host->on_hosts = on_hosts;

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

	for_each_host(h, on_hosts)
		check_upr("host section", "%s: on %s", res->name, h->name);
	res->all_hosts = APPEND(res->all_hosts, host);

	while (in_braces) {
		int token = yylex();
		fline = line;
		switch (token) {
		case TK_DISK:
			for_each_host(h, on_hosts)
				check_upr("disk statement", "%s:%s:disk", res->name, h->name);
			EXP(TK_STRING);
			host->disk = yylval.txt;
			for_each_host(h, on_hosts)
				check_uniq("disk", "disk:%s:%s", h->name, yylval.txt);
			EXP(';');
			break;
		case TK_DEVICE:
			for_each_host(h, on_hosts)
				check_upr("device statement", "%s:%s:device", res->name, h->name);
			parse_device(on_hosts, &host->device_minor, &host->device);
			break;
		case TK_ADDRESS:
			if (host->by_address) {
				fprintf(stderr,
					"%s:%d: address statement not allowed for floating {} host sections\n",
					config_file, fline);
				config_valid = 0;
				exit(E_config_invalid);
			}
			for_each_host(h, on_hosts)
				check_upr("address statement", "%s:%s:address", res->name, h->name);
			parse_address(on_hosts, &host->address, &host->port, &host->address_family);
			range_check(R_PORT, "port", host->port);
			break;
		case TK_META_DISK:
			for_each_host(h, on_hosts)
				check_upr("meta-disk statement", "%s:%s:meta-disk", res->name, h->name);
			parse_meta_disk(&host->meta_disk, &host->meta_index);
			check_meta_disk(host);
			break;
		case TK_FLEX_META_DISK:
			for_each_host(h, on_hosts)
				check_upr("meta-disk statement", "%s:%s:meta-disk", res->name, h->name);
			EXP(TK_STRING);
			host->meta_disk = yylval.txt;
			if (strcmp("internal", yylval.txt)) {
				host->meta_index = strdup("flexible");
			}
			check_meta_disk(host);
			EXP(';');
			break;
		case TK_PROXY:
			parse_proxy_section(host);
			break;
		case '}':
			in_braces = 0;
			break;
		default:
			pe_expected("disk | device | address | meta-disk "
				    "| flexible-meta-disk");
		}
	}

	/* Inherit device, disk, meta_disk and meta_index from the resource. */
	if(!host->disk && res->disk) {
		host->disk = strdup(res->disk);
		for_each_host(h, on_hosts)
			check_uniq("disk", "disk:%s:%s", h->name, host->disk);
	}

	if(!host->device && res->device) {
		host->device = strdup(res->device);
	}

	if (host->device_minor == -1U && res->device_minor != -1U) {
		host->device_minor = res->device_minor;
		for_each_host(h, on_hosts)
			check_uniq("device-minor", "device-minor:%s:%d", h->name, host->device_minor);
	}

	if(!host->meta_disk && res->meta_disk) {
		host->meta_disk = strdup(res->meta_disk);
		if(res->meta_index) host->meta_index = strdup(res->meta_index);
		check_meta_disk(host);
	}

	if (!(flags & REQUIRE_ALL))
		return;
	if (!host->device && host->device_minor == -1U)
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
			exit(E_config_invalid);
		}
	}
	while (level) ;
}

static void parse_stacked_section(struct d_resource* res)
{
	struct d_host_info *host;
	struct d_name *h;

	c_section_start = line;
	fline = line;

	host=calloc(1,sizeof(struct d_host_info));
	host->device_minor = -1;
	res->all_hosts = APPEND(res->all_hosts, host);
	EXP(TK_STRING);
	check_uniq("stacked-on-top-of", "stacked:%s", yylval.txt);
	host->lower_name = yylval.txt;

	m_asprintf(&host->meta_disk, "%s", "internal");
	m_asprintf(&host->meta_index, "%s", "internal");

	EXP('{');
	while (1) {
		switch(yylex()) {
		case TK_DEVICE:
			for_each_host(h, host->on_hosts)
				check_upr("device statement", "%s:%s:device", res->name, h->name);
			parse_device(host->on_hosts, &host->device_minor, &host->device);
			break;
		case TK_ADDRESS:
			for_each_host(h, host->on_hosts)
				check_upr("address statement", "%s:%s:address", res->name, h->name);
			parse_address(NULL, &host->address, &host->port, &host->address_family);
			range_check(R_PORT, "port", yylval.txt);
			break;
		case TK_PROXY:
			parse_proxy_section(host);
			break;
		case '}':
			goto break_loop;
		default:
			pe_expected("device | address | proxy");
		}
	}
 break_loop:

	res->stacked_on_one = 1;

	/* inherit device */
	if (!host->device && res->device) {
		host->device = strdup(res->device);
		for_each_host(h, host->on_hosts)
			check_uniq("device", "device:%s:%s", h->name, host->device);
	}

	if (host->device_minor == -1U && res->device_minor != -1U) {
		host->device_minor = res->device_minor;
		for_each_host(h, host->on_hosts)
			check_uniq("device-minor", "device-minor:%s:%d", h->name, host->device_minor);
	}

	if (!host->device && host->device_minor == -1U)
		derror(host, res, "device");
	if (!host->address)
		derror(host,res,"address");
	if (!host->meta_disk)
		derror(host,res,"meta-disk");
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

	if (!strcmp(yytext, "discard-my-data") && flags & IgnDiscardMyData)
		EXP(';');
	else
		pe_expected("an option keyword");
}

void set_me_in_resource(struct d_resource* res, int match_on_proxy)
{
	struct d_host_info *host;

	/* Determin the local host section */
	for (host = res->all_hosts; host; host=host->next) {
		/* do we match  this host? */
		if (match_on_proxy) {
		       if (!host->proxy || !name_in_names(nodeinfo.nodename, host->proxy->on_hosts))
			       continue;
		} else if (host->by_address) {
			if (!have_ip(host->address_family, host->address) &&
				/* for debugging only, e.g. __DRBD_NODE__=10.0.0.1 */
			    strcmp(nodeinfo.nodename, host->address))
				continue;
		} else if (host->lower) {
			if (!host->lower->me)
				continue;
		} else {
			if (!name_in_names(nodeinfo.nodename, host->on_hosts) &&
			    strcmp("_this_host", host->on_hosts->name))
				continue;
		}
		/* we matched. */
		if (res->ignore) {
			config_valid = 0;
			fprintf(stderr,
				"%s:%d: in resource %s, %s %s { ... }:\n"
				"\tYou cannot ignore and define at the same time.\n",
				res->config_file, host->config_line, res->name,
				host->lower ? "stacked-on-top-of" : "on",
				host->lower ? host->lower->name : names_to_str(host->on_hosts));
		}
		if (res->me) {
			config_valid = 0;
			fprintf(stderr,
				"%s:%d: in resource %s, %s %s { ... } ... %s %s { ... }:\n"
				"\tThere are multiple host sections for this node.\n",
				res->config_file, host->config_line, res->name,
				res->me->lower ? "stacked-on-top-of" : "on",
				res->me->lower ? res->me->lower->name : names_to_str(res->me->on_hosts),
				host->lower ? "stacked-on-top-of" : "on",
				host->lower ? host->lower->name : names_to_str(host->on_hosts));
		}
		res->me = host;
		if (host->lower)
			res->stacked = 1;
	}

	/* If there is no me, implicitly ignore that resource */
	if (!res->me) {
		res->ignore = 1;
		return;
	}
}

void set_peer_in_resource(struct d_resource* res, int peer_required)
{
	struct d_host_info *host = NULL;

	if (res->ignore)
		return;

	/* me must be already set */
	if (!res->me) {
		/* should have been implicitly ignored. */
		fprintf(stderr, "%s:%d: in resource %s:\n"
				"\tcannot determin the peer, don't even know myself!\n",
				res->config_file, res->start_line, res->name);
		exit(E_thinko);
	}

	/* only one host section? */
	if (!res->all_hosts->next) {
		if (peer_required) {
			fprintf(stderr,
				"%s:%d: in resource %s:\n"
				"\tMissing section 'on <PEER> { ... }'.\n",
				res->config_file, res->start_line, res->name);
			config_valid = 0;
		}
		return;
	}

	/* short cut for exactly two host sections.
	 * silently ignore any --peer connect_to_host option. */
	if (res->all_hosts->next->next == NULL) {
		res->peer = res->all_hosts == res->me ?
			res->all_hosts->next : res->all_hosts;
		if (dry_run > 1 && connect_to_host)
			fprintf(stderr,
				"%s:%d: in resource %s:\n"
				"\tIgnoring --peer '%s': there are only two host sections.\n",
				res->config_file, res->start_line, res->name, connect_to_host);
		return;
	}

	/* Multiple peer hosts to choose from.
	 * we need some help! */
	if (!connect_to_host) {
		if (peer_required) {
			fprintf(stderr,
				"%s:%d: in resource %s:\n"
				"\tThere are multiple host sections for the peer node.\n"
				"\tUse the --peer option to select which peer section to use.\n",
				res->config_file, res->start_line, res->name);
			config_valid = 0;
		}
		return;
	}

	for (host = res->all_hosts; host; host=host->next) {
		if (host->by_address && strcmp(connect_to_host, host->address))
			continue;
		if (host->proxy && !name_in_names(nodeinfo.nodename, host->proxy->on_hosts))
			continue;
		if (!name_in_names(connect_to_host, host->on_hosts))
			continue;

		if (host == res->me) {
			fprintf(stderr,
				"%s:%d: in resource %s\n"
				"\tInvoked with --peer '%s', but that matches myself!\n",
				res->config_file, res->start_line, res->name, connect_to_host);
			res->peer = NULL;
			break;
		}

		if (res->peer) {
			fprintf(stderr,
				"%s:%d: in resource %s:\n"
				"\tInvoked with --peer '%s', but that matches multiple times!\n",
				res->config_file, res->start_line, res->name, connect_to_host);
			res->peer = NULL;
			break;
		}
		res->peer = host;
	}

	if (peer_required && !res->peer) {
		config_valid = 0;
		if (!host)
			fprintf(stderr,
				"%s:%d: in resource %s:\n"
				"\tNo host ('on' or 'floating') section matches --peer '%s'\n",
				res->config_file, res->start_line, res->name, connect_to_host);
	}
}

void set_on_hosts_in_res(struct d_resource *res)
{
	struct d_resource *l_res, *tmp;
	struct d_host_info *host, *host2;
	struct d_name *h, **last;

	for (host = res->all_hosts; host; host=host->next) {
		if (host->lower_name) {
			for_each_resource(l_res, tmp, config) {
				if (!strcmp(l_res->name, host->lower_name))
					break;
			}

			if (l_res == NULL) {
				fprintf(stderr, "%s:%d: in resource %s, "
					"referenced resource '%s' not defined.\n",
					res->config_file, res->start_line, res->name, l_res->name);
				config_valid = 0;
			}

			/* Simple: host->on_hosts = concat_names(l_res->me->on_hosts, l_res->peer->on_hosts); */
			last = NULL;
			for (host2 = l_res->all_hosts; host2; host2 = host2->next)
				if (!host2->lower_name)
					append_names(&host->on_hosts, &last, host2->on_hosts);

			host->lower = l_res;

			/* */
			if (!strcmp(host->address, "127.0.0.1") || !strcmp(host->address, "::1"))
				for_each_host(h, host->on_hosts)
					check_uniq("IP", "%s:%s:%s", h->name, host->address, host->port);

		}
	}
}

void set_disk_in_res(struct d_resource *res)
{
	struct d_host_info *host;

	if (res->ignore)
		return;

	for (host = res->all_hosts; host; host=host->next) {
		if (host->lower) {
			if (res->stacked && host->lower->stacked) {
				fprintf(stderr,
					"%s:%d: in resource %s, stacked-on-top-of %s { ... }:\n"
					"\tFIXME. I won't stack stacked resources.\n",
					res->config_file, res->start_line, res->name, host->lower_name);
				config_valid = 0;
			}

			if (host->lower->ignore)
				continue;

			if (host->lower->me->device)
				m_asprintf(&host->disk, "%s", host->lower->me->device);
			else
				m_asprintf(&host->disk, "/dev/drbd%u", host->lower->me->device_minor);

			if (!host->disk)
				derror(host,res,"disk");
		}
	}
}

struct d_resource* parse_resource(char* res_name, enum pr_flags flags)
{
	struct d_resource* res;
	struct d_name *host_names;
	int token;

	check_upr_init();
	check_uniq("resource section", res_name);

	res=calloc(1,sizeof(struct d_resource));
	res->name = res_name;
	res->device_minor = -1;
	res->config_file = config_file;
	res->start_line = line;

	while(1) {
		token = yylex();
		fline = line;
		switch(token) {
		case TK_PROTOCOL:
			check_upr("protocol statement","%s: protocol",res->name);
			EXP(TK_STRING);
			res->protocol=yylval.txt;
			EXP(';');
			break;
		case TK_ON:
			parse_hosts(&host_names, '{');
			parse_host_section(res, host_names, REQUIRE_ALL);
			break;
		case TK_STACKED:
			parse_stacked_section(res);
			break;
		case TK_IGNORE:
			if (res->me || res->peer) {
				fprintf(stderr,
					"%s:%d: in resource %s, "
					"'ignore-on' statement must precede any real host section (on ... { ... }).\n",
					config_file, line, res->name);
				exit(E_config_invalid);
			}
			EXP(TK_STRING);
			fprintf(stderr, "%s:%d: in resource %s, "
			       "WARN: The 'ignore-on' keyword is deprecated.\n",
			       config_file, line, res->name);
			EXP(';');
			break;
		case TK__THIS_HOST:
			EXP('{');
			host_names = names_from_str("_this_host");
			parse_host_section(res, host_names, 0);
			break;
		case TK__REMOTE_HOST:
			EXP('{');
			host_names = names_from_str("_remote_host");
			parse_host_section(res, host_names, 0);
			break;
		case TK_FLOATING:
			parse_host_section(res, NULL, REQUIRE_ALL + BY_ADDRESS);
			break;
		case TK_DISK:
			switch (token=yylex()) {
			case TK_STRING:
				res->disk = yylval.txt;
				EXP(';');
				break;
			case '{':
				check_upr("disk section", "%s:disk", res->name);
				res->disk_options = parse_options(TK_DISK_SWITCH,
								  TK_DISK_OPTION);
				break;
			default:
				check_string_error(token);
				pe_expected_got( "TK_STRING | {", token);
			}
			break;
		case TK_NET:
			check_upr("net section", "%s:net", res->name);
			EXP('{');
			res->net_options = parse_options_d(TK_NET_SWITCH,
							   TK_NET_OPTION,
							   TK_NET_DELEGATE,
							   &net_delegate,
							   (void *)flags);
			break;
		case TK_SYNCER:
			check_upr("syncer section", "%s:syncer", res->name);
			EXP('{');
			res->sync_options = parse_options(TK_SYNCER_SWITCH,
							  TK_SYNCER_OPTION);
			break;
		case TK_STARTUP:
			check_upr("startup section", "%s:startup", res->name);
			EXP('{');
			res->startup_options=parse_options_d(TK_STARTUP_SWITCH,
							     TK_STARTUP_OPTION,
							     TK_STARTUP_DELEGATE,
							     &startup_delegate,
							     res);
			break;
		case TK_HANDLER:
			check_upr("handlers section", "%s:handlers", res->name);
			EXP('{');
			res->handlers =  parse_options(0, TK_HANDLER_OPTION);
			break;
		case TK_PROXY:
			check_upr("proxy section", "%s:proxy", res->name);
			EXP('{');
			res->proxy_options =  parse_options(TK_PROXY_SWITCH,
							    TK_PROXY_OPTION);
			break;
		case TK_DEVICE:
			check_upr("device statement", "%s:device", res->name);
			parse_device(NULL, &res->device_minor, &res->device);
			break;
		case TK_META_DISK:
			parse_meta_disk(&res->meta_disk, &res->meta_index);
			break;
		case TK_FLEX_META_DISK:
			EXP(TK_STRING);
			res->meta_disk = yylval.txt;
			if (strcmp("internal", yylval.txt)) {
				res->meta_index = strdup("flexible");
			}
			EXP(';');
			break;
		case '}':
		case 0:
			goto exit_loop;
		default:
			pe_expected_got("protocol | on | disk | net | syncer |"
					" startup | handlers |"
					" ignore-on | stacked-on-top-of",token);
		}
	}

 exit_loop:

	if (flags == NoneHAllowed && res->all_hosts) {
		config_valid = 0;

		fprintf(stderr,
			"%s:%d: in the %s section, there are no host sections"
			" allowed.\n",
			config_file, c_section_start, res->name);
	}

	return res;
}

void post_parse(struct d_resource *config, enum pp_flags flags)
{
	struct d_resource *res,*tmp;

	for_each_resource(res, tmp, config)
		if (res->stacked_on_one)
			set_on_hosts_in_res(res); /* sets on_hosts and host->lower */

	/* Needs "on_hosts" and host->lower already set */
	for_each_resource(res, tmp, config)
		if (!res->stacked_on_one)
			set_me_in_resource(res, flags & match_on_proxy);

	/* Needs host->lower->me already set */
	for_each_resource(res, tmp, config)
		if (res->stacked_on_one)
			set_me_in_resource(res, flags & match_on_proxy);

	// Needs "me" set already
	for_each_resource(res, tmp, config)
		if (res->stacked_on_one)
			set_disk_in_res(res);
}

void include_file(FILE *f, char* name)
{
	int saved_line;
	char* saved_config_file;

	saved_line = line;
	saved_config_file = config_file;
	line = 1;
	config_file = name;

	my_yypush_buffer_state(f);
	my_parse();
	yypop_buffer_state();

	line = saved_line;
	config_file = saved_config_file;
}

void include_stmt(char *str)
{
	glob_t glob_buf;
	FILE *f;
	size_t i;

	f = fopen(str, "r");
	if (f) {
		include_file(f, str);
		fclose(f);
	} else if (glob(str, 0, NULL, &glob_buf) == 0) {
		for (i=0; i<glob_buf.gl_pathc; i++) {
			f = fopen(glob_buf.gl_pathv[i], "r");
			if (f)
				include_file(f, strdup(glob_buf.gl_pathv[i]));
			fclose(f);
		}
		globfree(&glob_buf);
	} else {
		fprintf(stderr,
			"%s:%d: Failed to open include file '%s'.\n",
			config_file, line, yylval.txt);
		config_valid = 0;
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
			common = parse_resource("common",NoneHAllowed);
			break;
		case TK_RESOURCE:
			EXP(TK_STRING);
			EXP('{');
			config = APPEND(config, parse_resource(yylval.txt, 0));
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
