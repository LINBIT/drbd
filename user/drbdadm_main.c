/*
   drbdadm_main.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2002-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2002-2008, Philipp Reisner <philipp.reisner@linbit.com>.
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
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <search.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include "linux/drbd_limits.h"
#include "drbdtool_common.h"
#include "drbdadm.h"
#include "registry.h"
#include "config_flags.h"

#define MAX_ARGS 40

static int indent = 0;
#define INDENT_WIDTH 4
#define BFMT  "%s;\n"
#define IPV4FMT "%-16s %s %s:%s;\n"
#define IPV6FMT "%-16s %s [%s]:%s;\n"
#define MDISK "%-16s %s;\n"
#define MDISKI "%-16s %s [%s];\n"
#define printI(fmt, args... ) printf("%*s" fmt,INDENT_WIDTH * indent,"" , ## args )
#define printA(name, val ) \
	printf("%*s%*s %3s;\n", \
	  INDENT_WIDTH * indent,"" , \
	  -24+INDENT_WIDTH * indent, \
	  name, val )

char *progname;

struct adm_cmd {
	const char *name;
	int (*function) (struct cfg_ctx *);
	/* which level this command is for.
	 * 0: don't show this command, ever
	 * 1: normal administrative commands, shown in normal help
	 * 2-4: shown on "drbdadm hidden-commands"
	 * 2: useful for shell scripts
	 * 3: callbacks potentially called from kernel module on certain events
	 * 4: advanced, experts and developers only */
	unsigned int show_in_usage:3;
	/* if set, command requires an explicit resource name */
	unsigned int res_name_required:1;
	/* if set, command requires an explicit volume number as well */
	unsigned int vol_id_required:1;
	/* most commands need to iterate over all volumes in the resource */
	unsigned int iterate_volumes:1;
	/* error out if the ip specified is not available/active now */
	unsigned int verify_ips:1;
	/* if set, use the "cache" in /var/lib/drbd to figure out
	 * which config file to use.
	 * This is necessary for handlers (callbacks from kernel) to work
	 * when using "drbdadm -c /some/other/config/file" */
	unsigned int use_cached_config_file:1;
	unsigned int need_peer:1;
	unsigned int is_proxy_cmd:1;
	unsigned int uc_dialog:1; /* May show usage count dialog */
	unsigned int test_config:1; /* Allow -t option */
	const struct context_def *drbdsetup_ctx;
};

struct deferred_cmd {
	int (*function) (struct cfg_ctx *);
	struct cfg_ctx ctx;
	struct deferred_cmd *next;
};

struct option general_admopt[] = {
	{"stacked", no_argument, 0, 'S'},
	{"dry-run", no_argument, 0, 'd'},
	{"verbose", no_argument, 0, 'v'},
	{"config-file", required_argument, 0, 'c'},
	{"config-to-test", required_argument, 0, 't'},
	{"drbdsetup", required_argument, 0, 's'},
	{"drbdmeta", required_argument, 0, 'm'},
	{"drbd-proxy-ctl", required_argument, 0, 'p'},
	{"sh-varname", required_argument, 0, 'n'},
	{"yes", no_argument, 0, 'y'},
	{"peer", required_argument, 0, 'P'},
	{"version", no_argument, 0, 'V'},
	{"setup-option", required_argument, 0, 'W'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};
struct option *admopt = general_admopt;

extern int my_parse();
extern int yydebug;
extern FILE *yyin;


static int adm_generic_l(struct cfg_ctx *);
static int adm_status_xml(struct cfg_ctx *);
static int adm_up(struct cfg_ctx *);
static int adm_dump(struct cfg_ctx *);
static int adm_dump_xml(struct cfg_ctx *);
static int adm_wait_c(struct cfg_ctx *);
static int adm_wait_ci(struct cfg_ctx *);
static int adm_proxy_up(struct cfg_ctx *);
static int adm_proxy_down(struct cfg_ctx *);
static int sh_nop(struct cfg_ctx *);
static int sh_resources(struct cfg_ctx *);
static int sh_resource(struct cfg_ctx *);
static int sh_mod_parms(struct cfg_ctx *);
static int sh_dev(struct cfg_ctx *);
static int sh_udev(struct cfg_ctx *);
static int sh_minor(struct cfg_ctx *);
static int sh_ip(struct cfg_ctx *);
static int sh_lres(struct cfg_ctx *);
static int sh_ll_dev(struct cfg_ctx *);
static int sh_md_dev(struct cfg_ctx *);
static int sh_md_idx(struct cfg_ctx *);
static int sh_b_pri(struct cfg_ctx *);
static int sh_status(struct cfg_ctx *);
static int admm_generic(struct cfg_ctx *);
static int adm_khelper(struct cfg_ctx *);
static int adm_generic_b(struct cfg_ctx *);
static int hidden_cmds(struct cfg_ctx *);
static int adm_outdate(struct cfg_ctx *);
static int adm_chk_resize(struct cfg_ctx *);
static void dump_options(char *name, struct d_option *opts);

struct d_volume *volume_by_vnr(struct d_volume *volumes, int vnr);
struct d_resource *res_by_name(const char *name);
int ctx_by_name(struct cfg_ctx *ctx, const char *id);
int ctx_set_implicit_volume(struct cfg_ctx *ctx);

static char *get_opt_val(struct d_option *, const char *, char *);

static struct ifreq *get_ifreq();

char ss_buffer[1024];
struct utsname nodeinfo;
int line = 1;
int fline;
struct d_globals global_options = { 0, 0, 0, 1, UC_ASK };

char *config_file = NULL;
char *config_save = NULL;
char *config_test = NULL;
struct d_resource *config = NULL;
struct d_resource *common = NULL;
struct ifreq *ifreq_list = NULL;
int is_drbd_top;
enum { NORMAL, STACKED, IGNORED, __N_RESOURCE_TYPES };
int nr_resources[__N_RESOURCE_TYPES];
int nr_volumes[__N_RESOURCE_TYPES];
int highest_minor;
int config_from_stdin = 0;
int config_valid = 1;
int no_tty;
int dry_run = 0;
int verbose = 0;
bool help;
int do_verify_ips = 0;
int do_register = 1;
/* whether drbdadm was called with "all" instead of resource name(s) */
int all_resources = 0;
char *drbdsetup = NULL;
char *drbdmeta = NULL;
char *drbdadm_83 = NULL;
char *drbd_proxy_ctl;
char *sh_varname = NULL;
struct setup_option *setup_options;


char *connect_to_host = NULL;
volatile int alarm_raised;

struct deferred_cmd *deferred_cmds[__CFG_LAST] = { NULL, };
struct deferred_cmd *deferred_cmds_tail[__CFG_LAST] = { NULL, };

void add_setup_option(bool explicit, char *option)
{
	int n = 0;
	if (setup_options) {
		while (setup_options[n].option)
			n++;
	}

	setup_options = realloc(setup_options, (n + 2) * sizeof(*setup_options));
	if (!setup_options) {
		/* ... */
	}
	setup_options[n].explicit = explicit;
	setup_options[n].option = option;
	n++;
	setup_options[n].option = NULL;
}

/* DRBD adm_cmd flags shortcuts,
 * to avoid merge conflicts and unreadable diffs
 * when we add the next flag */

#define DRBD_acf1_default		\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define DRBD_acf1_resname		\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.uc_dialog = 1,			\

#define DRBD_acf1_connect		\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 0,		\
	.verify_ips = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define DRBD_acf1_up			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define DRBD_acf1_defnet		\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 1,		\
	.uc_dialog = 1,			\

#define DRBD_acf3_handler		\
	.show_in_usage = 3,		\
	.res_name_required = 1,		\
	.iterate_volumes = 0,		\
	.vol_id_required = 1,		\
	.verify_ips = 0,		\
	.use_cached_config_file = 1,	\

#define DRBD_acf4_advanced		\
	.show_in_usage = 4,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define DRBD_acf4_advanced_need_vol	\
	.show_in_usage = 4,		\
	.res_name_required = 1,		\
	.iterate_volumes = 0,		\
	.vol_id_required = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define DRBD_acf1_dump			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.verify_ips = 1,		\
	.uc_dialog = 1,			\
	.test_config = 1,		\

#define DRBD_acf2_shell			\
	.show_in_usage = 2,		\
	.iterate_volumes = 1,		\
	.res_name_required = 1,		\
	.verify_ips = 0,		\

#define DRBD_acf2_sh_resname		\
	.show_in_usage = 2,		\
	.iterate_volumes = 0,		\
	.res_name_required = 1,		\
	.verify_ips = 0,		\

#define DRBD_acf2_proxy			\
	.show_in_usage = 2,		\
	.res_name_required = 1,		\
	.verify_ips = 0,		\
	.need_peer = 1,			\
	.is_proxy_cmd = 1,		\

#define DRBD_acf2_hook			\
	.show_in_usage = 2,		\
	.res_name_required = 1,		\
	.verify_ips = 0,                \
	.use_cached_config_file = 1,	\

#define DRBD_acf2_gen_shell		\
	.show_in_usage = 2,		\
	.res_name_required = 0,		\
	.verify_ips = 0,		\

struct adm_cmd cmds[] = {
	/*  name, function, flags
	 *  sort order:
	 *  - normal config commands,
	 *  - normal meta data manipulation
	 *  - sh-*
	 *  - handler
	 *  - advanced
	 ***/
	{"attach", adm_attach, DRBD_acf1_default
	 .drbdsetup_ctx = &attach_cmd_ctx, },
	{"disk-options", adm_disk_options, DRBD_acf1_default
	 .drbdsetup_ctx = &disk_options_ctx, },
	{"detach", adm_generic_l, DRBD_acf1_default},
	{"connect", adm_connect, DRBD_acf1_connect
	 .drbdsetup_ctx = &connect_cmd_ctx, },
	{"net-options", adm_net_options, DRBD_acf1_connect
	 .drbdsetup_ctx = &net_options_ctx, },
	{"disconnect", adm_disconnect, DRBD_acf1_resname
	 .drbdsetup_ctx = &disconnect_cmd_ctx, },
	{"up", adm_up, DRBD_acf1_up},
	{"resource-options", adm_res_options, DRBD_acf1_resname
	 .drbdsetup_ctx = &resource_options_cmd_ctx, },
	{"down", adm_generic_l, DRBD_acf1_resname},
	{"primary", adm_generic_l, DRBD_acf1_default
	 .drbdsetup_ctx = &primary_cmd_ctx, },
	{"secondary", adm_generic_l, DRBD_acf1_default},
	{"invalidate", adm_generic_b, DRBD_acf1_default},
	{"invalidate-remote", adm_generic_l, DRBD_acf1_defnet},
	{"outdate", adm_outdate, DRBD_acf1_default},
	{"resize", adm_resize, DRBD_acf1_defnet},
	{"verify", adm_generic_s, DRBD_acf1_defnet},
	{"pause-sync", adm_generic_s, DRBD_acf1_defnet},
	{"resume-sync", adm_generic_s, DRBD_acf1_defnet},
	{"adjust", adm_adjust, DRBD_acf1_connect},
	{"wait-connect", adm_wait_c, DRBD_acf1_defnet},
	{"wait-con-int", adm_wait_ci,
	 .show_in_usage = 1,.verify_ips = 1,},
	{"status", adm_status_xml, DRBD_acf2_gen_shell},
	{"role", adm_generic_s, DRBD_acf1_default},
	{"cstate", adm_generic_s, DRBD_acf1_default},
	{"dstate", adm_generic_b, DRBD_acf1_default},

	{"dump", adm_dump, DRBD_acf1_dump},
	{"dump-xml", adm_dump_xml, DRBD_acf1_dump},

	{"create-md", adm_create_md, DRBD_acf1_default},
	{"show-gi", adm_generic_b, DRBD_acf1_default},
	{"get-gi", adm_generic_b, DRBD_acf1_default},
	{"dump-md", admm_generic, DRBD_acf1_default},
	{"wipe-md", admm_generic, DRBD_acf1_default},
	{"hidden-commands", hidden_cmds,.show_in_usage = 1,},

	{"sh-nop", sh_nop, DRBD_acf2_gen_shell .uc_dialog = 1, .test_config = 1},
	{"sh-resources", sh_resources, DRBD_acf2_gen_shell},
	{"sh-resource", sh_resource, DRBD_acf2_sh_resname},
	{"sh-mod-parms", sh_mod_parms, DRBD_acf2_gen_shell},
	{"sh-dev", sh_dev, DRBD_acf2_shell},
	{"sh-udev", sh_udev, .vol_id_required = 1, DRBD_acf2_hook},
	{"sh-minor", sh_minor, DRBD_acf2_shell},
	{"sh-ll-dev", sh_ll_dev, DRBD_acf2_shell},
	{"sh-md-dev", sh_md_dev, DRBD_acf2_shell},
	{"sh-md-idx", sh_md_idx, DRBD_acf2_shell},
	{"sh-ip", sh_ip, DRBD_acf2_shell},
	{"sh-lr-of", sh_lres, DRBD_acf2_shell},
	{"sh-b-pri", sh_b_pri, DRBD_acf2_shell},
	{"sh-status", sh_status, DRBD_acf2_gen_shell},

	{"proxy-up", adm_proxy_up, DRBD_acf2_proxy},
	{"proxy-down", adm_proxy_down, DRBD_acf2_proxy},

	{"new-resource", adm_new_resource, DRBD_acf2_sh_resname},
	{"sh-new-minor", adm_new_minor, DRBD_acf4_advanced},

	{"before-resync-target", adm_khelper, DRBD_acf3_handler},
	{"after-resync-target", adm_khelper, DRBD_acf3_handler},
	{"before-resync-source", adm_khelper, DRBD_acf3_handler},
	{"pri-on-incon-degr", adm_khelper, DRBD_acf3_handler},
	{"pri-lost-after-sb", adm_khelper, DRBD_acf3_handler},
	{"fence-peer", adm_khelper, DRBD_acf3_handler},
	{"local-io-error", adm_khelper, DRBD_acf3_handler},
	{"pri-lost", adm_khelper, DRBD_acf3_handler},
	{"initial-split-brain", adm_khelper, DRBD_acf3_handler},
	{"split-brain", adm_khelper, DRBD_acf3_handler},
	{"out-of-sync", adm_khelper, DRBD_acf3_handler},

	{"suspend-io", adm_generic_s, DRBD_acf4_advanced},
	{"resume-io", adm_generic_s, DRBD_acf4_advanced},
	{"set-gi", admm_generic, DRBD_acf4_advanced_need_vol},
	{"new-current-uuid", adm_generic_s, DRBD_acf4_advanced_need_vol
	 .drbdsetup_ctx = &new_current_uuid_cmd_ctx, },
	{"check-resize", adm_chk_resize, DRBD_acf4_advanced},
};


void schedule_deferred_cmd(int (*function) (struct cfg_ctx *),
		   struct cfg_ctx *ctx,
		   const char *arg, enum drbd_cfg_stage stage)
{
	struct deferred_cmd *d, *t;

	d = calloc(1, sizeof(struct deferred_cmd));
	if (d == NULL) {
		perror("calloc");
		exit(E_exec_error);
	}

	d->function = function;
	d->ctx.res = ctx->res;
	d->ctx.vol = ctx->vol;
	d->ctx.arg = arg;

	/* first to come is head */
	if (!deferred_cmds[stage])
		deferred_cmds[stage] = d;

	/* link it in at tail */
	t = deferred_cmds_tail[stage];
	if (t)
		t->next = d;

	/* advance tail */
	deferred_cmds_tail[stage] = d;
}

enum on_error { KEEP_RUNNING, EXIT_ON_FAIL };
int call_cmd_fn(int (*function) (struct cfg_ctx *),
		struct cfg_ctx *ctx, enum on_error on_error)
{
	int rv;
	rv = function(ctx);
	if (rv >= 20) {
		fprintf(stderr, "%s %s %s: exited with code %d\n",
			progname, ctx->arg, ctx->res->name, rv);
		if (on_error == EXIT_ON_FAIL)
			exit(rv);
	}
	return rv;
}

/* If ctx->vol is NULL, and cmd->iterate_volumes is set,
 * iterate over all volumes in ctx->res.
 * Else, just pass it on.
 * */
int call_cmd(struct adm_cmd *cmd, struct cfg_ctx *ctx,
	     enum on_error on_error)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol;
	int ret;

	if (!res->peer)
		set_peer_in_resource(res, cmd->need_peer);

	if (!cmd->iterate_volumes || ctx->vol != NULL)
		return call_cmd_fn(cmd->function, ctx, on_error);

	for_each_volume(vol, res->me->volumes) {
		ctx->vol = vol;
		ret = call_cmd_fn(cmd->function, ctx, on_error);
		/* FIXME: Do we want to keep running?
		 * When?
		 * How would we determine which return value to return? */
		if (ret)
			return ret;
	}

	return 0;
}

int _run_deferred_cmds(enum drbd_cfg_stage stage)
{
	struct deferred_cmd *d = deferred_cmds[stage];
	struct deferred_cmd *t;
	int r = 0;
	int rv = 0;

	while (d) {
		r = call_cmd_fn(d->function, &d->ctx, KEEP_RUNNING);
		t = d->next;
		free(d);
		d = t;
		if (r > rv)
			rv = r;
	}
	return rv;
}

int run_deferred_cmds(void)
{
	enum drbd_cfg_stage stage;
	int ret;
	for (stage = CFG_PREREQ; stage < __CFG_LAST; stage++) {
		ret = _run_deferred_cmds(stage);
		if (ret)
			return 1; /* FIXME ret? */
	}
	return 0;
}

/*** These functions are used to the print the config ***/

static char *esc(char *str)
{
	static char buffer[1024];
	char *ue = str, *e = buffer;

	if (!str || !str[0]) {
		return "\"\"";
	}
	if (strchr(str, ' ') || strchr(str, '\t') || strchr(str, '\\')) {
		*e++ = '"';
		while (*ue) {
			if (*ue == '"' || *ue == '\\') {
				*e++ = '\\';
			}
			if (e - buffer >= 1022) {
				fprintf(stderr, "string too long.\n");
				exit(E_syntax);
			}
			*e++ = *ue++;
			if (e - buffer >= 1022) {
				fprintf(stderr, "string too long.\n");
				exit(E_syntax);
			}
		}
		*e++ = '"';
		*e++ = '\0';
		return buffer;
	}
	return str;
}

static char *esc_xml(char *str)
{
	static char buffer[1024];
	char *ue = str, *e = buffer;

	if (!str || !str[0]) {
		return "";
	}
	if (strchr(str, '"') || strchr(str, '\'') || strchr(str, '<') ||
	    strchr(str, '>') || strchr(str, '&') || strchr(str, '\\')) {
		while (*ue) {
			if (*ue == '"' || *ue == '\\') {
				*e++ = '\\';
				if (e - buffer >= 1021) {
					fprintf(stderr, "string too long.\n");
					exit(E_syntax);
				}
				*e++ = *ue++;
			} else if (*ue == '\'' || *ue == '<' || *ue == '>'
				   || *ue == '&') {
				if (*ue == '\'' && e - buffer < 1017) {
					strcpy(e, "&apos;");
					e += 6;
				} else if (*ue == '<' && e - buffer < 1019) {
					strcpy(e, "&lt;");
					e += 4;
				} else if (*ue == '>' && e - buffer < 1019) {
					strcpy(e, "&gt;");
					e += 4;
				} else if (*ue == '&' && e - buffer < 1018) {
					strcpy(e, "&amp;");
					e += 5;
				} else {
					fprintf(stderr, "string too long.\n");
					exit(E_syntax);
				}
				ue++;
			} else {
				*e++ = *ue++;
				if (e - buffer >= 1022) {
					fprintf(stderr, "string too long.\n");
					exit(E_syntax);
				}
			}
		}
		*e++ = '\0';
		return buffer;
	}
	return str;
}

static void dump_options2(char *name, struct d_option *opts,
		void(*within)(void*), void *ctx)
{
	if (!opts && !(within && ctx))
		return;

	printI("%s {\n", name);
	++indent;
	while (opts) {
		if (opts->value)
			printA(opts->name,
			       opts->is_escaped ? opts->value : esc(opts->
								    value));
		else
			printI(BFMT, opts->name);
		opts = opts->next;
	}
	if (within)
		within(ctx);
	--indent;
	printI("}\n");
}

static void dump_options(char *name, struct d_option *opts)
{
	dump_options2(name, opts, NULL, NULL);
}

void dump_proxy_plugins(void *ctx)
{
	struct d_option *opt = ctx;

	dump_options("plugin", opt);
}

static void dump_global_info()
{
	if (!global_options.minor_count
	    && !global_options.disable_ip_verification
	    && global_options.dialog_refresh == 1)
		return;
	printI("global {\n");
	++indent;
	if (global_options.disable_ip_verification)
		printI("disable-ip-verification;\n");
	if (global_options.minor_count)
		printI("minor-count %i;\n", global_options.minor_count);
	if (global_options.dialog_refresh != 1)
		printI("dialog-refresh %i;\n", global_options.dialog_refresh);
	--indent;
	printI("}\n\n");
}

static void fake_startup_options(struct d_resource *res);

static void dump_common_info()
{
	if (!common)
		return;
	printI("common {\n");
	++indent;

	fake_startup_options(common);
	dump_options("options", common->res_options);
	dump_options("net", common->net_options);
	dump_options("disk", common->disk_options);
	dump_options("startup", common->startup_options);
	dump_options2("proxy", common->proxy_options,
			dump_proxy_plugins, common->proxy_plugins);
	dump_options("handlers", common->handlers);
	--indent;
	printf("}\n\n");
}

static void dump_address(char *name, char *addr, char *port, char *af)
{
	if (!strcmp(af, "ipv6"))
		printI(IPV6FMT, name, af, addr, port);
	else
		printI(IPV4FMT, name, af, addr, port);
}

static void dump_proxy_info(struct d_proxy_info *pi)
{
	printI("proxy on %s {\n", names_to_str(pi->on_hosts));
	++indent;
	dump_address("inside", pi->inside_addr, pi->inside_port, pi->inside_af);
	dump_address("outside", pi->outside_addr, pi->outside_port,
		     pi->outside_af);
	--indent;
	printI("}\n");
}

static void dump_volume(int has_lower, struct d_volume *vol)
{
	if (!vol->implicit) {
		printI("volume %d {\n", vol->vnr);
		++indent;
	}

	dump_options("disk", vol->disk_options);

	printI("device%*s", -19 + INDENT_WIDTH * indent, "");
	if (vol->device)
		printf("%s ", esc(vol->device));
	printf("minor %d;\n", vol->device_minor);

	if (!has_lower)
		printA("disk", esc(vol->disk));

	if (!has_lower) {
		if (!strcmp(vol->meta_index, "flexible"))
			printI(MDISK, "meta-disk", esc(vol->meta_disk));
		else if (!strcmp(vol->meta_index, "internal"))
			printA("meta-disk", "internal");
		else
			printI(MDISKI, "meta-disk", esc(vol->meta_disk),
			       vol->meta_index);
	}

	if (!vol->implicit) {
		--indent;
		printI("}\n");
	}
}

static void dump_host_info(struct d_host_info *hi)
{
	struct d_volume *vol;

	if (!hi) {
		printI("  # No host section data available.\n");
		return;
	}

	if (hi->lower) {
		printI("stacked-on-top-of %s {\n", esc(hi->lower->name));
		++indent;
		printI("# on %s \n", names_to_str(hi->on_hosts));
	} else if (hi->by_address) {
		if (!strcmp(hi->address_family, "ipv6"))
			printI("floating ipv6 [%s]:%s {\n", hi->address, hi->port);
		else
			printI("floating %s %s:%s {\n", hi->address_family, hi->address, hi->port);
		++indent;
	} else {
		printI("on %s {\n", names_to_str(hi->on_hosts));
		++indent;
	}

	dump_options("options", hi->res_options);

	for_each_volume(vol, hi->volumes)
		dump_volume(!!hi->lower, vol);

	if (!hi->by_address)
		dump_address("address", hi->address, hi->port, hi->address_family);
	if (hi->proxy)
		dump_proxy_info(hi->proxy);
	--indent;
	printI("}\n");
}

static void dump_options_xml2(char *name, struct d_option *opts,
		void(*within)(void*), void *ctx)
{
	if (!opts && !(within && ctx))
		return;

	printI("<section name=\"%s\">\n", name);
	++indent;
	while (opts) {
		if (opts->value)
			printI("<option name=\"%s\" value=\"%s\"/>\n",
			       opts->name,
			       opts->is_escaped ? opts->value : esc_xml(opts->
									value));
		else
			printI("<option name=\"%s\"/>\n", opts->name);
		opts = opts->next;
	}
	if (within)
		within(ctx);
	--indent;
	printI("</section>\n");
}

static void dump_options_xml(char *name, struct d_option *opts)
{
	dump_options_xml2(name, opts, NULL, NULL);
}

void dump_proxy_plugins_xml(void *ctx)
{
	struct d_option *opt = ctx;

	dump_options_xml("plugin", opt);
}

static void dump_global_info_xml()
{
	if (!global_options.minor_count
	    && !global_options.disable_ip_verification
	    && global_options.dialog_refresh == 1)
		return;
	printI("<global>\n");
	++indent;
	if (global_options.disable_ip_verification)
		printI("<disable-ip-verification/>\n");
	if (global_options.minor_count)
		printI("<minor-count count=\"%i\"/>\n",
		       global_options.minor_count);
	if (global_options.dialog_refresh != 1)
		printI("<dialog-refresh refresh=\"%i\"/>\n",
		       global_options.dialog_refresh);
	--indent;
	printI("</global>\n");
}

static void dump_common_info_xml()
{
	if (!common)
		return;
	printI("<common>\n");
	++indent;
	fake_startup_options(common);
	dump_options_xml("options", common->res_options);
	dump_options_xml("net", common->net_options);
	dump_options_xml("disk", common->disk_options);
	dump_options_xml("startup", common->startup_options);
	dump_options2("proxy", common->proxy_options,
			dump_proxy_plugins, common->proxy_plugins);
	dump_options_xml("handlers", common->handlers);
	--indent;
	printI("</common>\n");
}

static void dump_proxy_info_xml(struct d_proxy_info *pi)
{
	printI("<proxy hostname=\"%s\">\n", names_to_str(pi->on_hosts));
	++indent;
	printI("<inside family=\"%s\" port=\"%s\">%s</inside>\n", pi->inside_af,
	       pi->inside_port, pi->inside_addr);
	printI("<outside family=\"%s\" port=\"%s\">%s</outside>\n",
	       pi->outside_af, pi->outside_port, pi->outside_addr);
	--indent;
	printI("</proxy>\n");
}

static void dump_volume_xml(struct d_volume *vol)
{
	printI("<volume vnr=\"%d\">\n", vol->vnr);
	++indent;

	dump_options_xml("disk", vol->disk_options);
	printI("<device minor=\"%d\">%s</device>\n", vol->device_minor,
	       esc_xml(vol->device));
	printI("<disk>%s</disk>\n", esc_xml(vol->disk));

	if (!strcmp(vol->meta_index, "flexible"))
		printI("<meta-disk>%s</meta-disk>\n",
		       esc_xml(vol->meta_disk));
	else if (!strcmp(vol->meta_index, "internal"))
		printI("<meta-disk>internal</meta-disk>\n");
	else {
		printI("<meta-disk index=\"%s\">%s</meta-disk>\n",
		       vol->meta_index, esc_xml(vol->meta_disk));
	}
	--indent;
	printI("</volume>\n");
}

static void dump_host_info_xml(struct d_host_info *hi)
{
	struct d_volume *vol;

	if (!hi) {
		printI("<!-- No host section data available. -->\n");
		return;
	}

	if (hi->by_address)
		printI("<host floating=\"1\">\n");
	else
		printI("<host name=\"%s\">\n", names_to_str(hi->on_hosts));

	++indent;

	dump_options_xml("options", hi->res_options);
	for_each_volume(vol, hi->volumes)
		dump_volume_xml(vol);

	printI("<address family=\"%s\" port=\"%s\">%s</address>\n",
	       hi->address_family, hi->port, hi->address);
	if (hi->proxy)
		dump_proxy_info_xml(hi->proxy);
	--indent;
	printI("</host>\n");
}

static void fake_startup_options(struct d_resource *res)
{
	struct d_option *opt;
	char *val;

	if (res->stacked_timeouts) {
		opt = new_opt(strdup("stacked-timeouts"), NULL);
		res->startup_options = APPEND(res->startup_options, opt);
	}

	if (res->become_primary_on) {
		val = strdup(names_to_str(res->become_primary_on));
		opt = new_opt(strdup("become-primary-on"), val);
		opt->is_escaped = 1;
		res->startup_options = APPEND(res->startup_options, opt);
	}
}

static int adm_dump(struct cfg_ctx *ctx)
{
	struct d_host_info *host;
	struct d_resource *res = ctx->res;

	printI("# resource %s on %s: %s, %s\n",
	       esc(res->name), nodeinfo.nodename,
	       res->ignore ? "ignored" : "not ignored",
	       res->stacked ? "stacked" : "not stacked");
	printI("resource %s {\n", esc(res->name));
	++indent;

	for (host = res->all_hosts; host; host = host->next)
		dump_host_info(host);

	fake_startup_options(res);
	dump_options("options", res->res_options);
	dump_options("net", res->net_options);
	dump_options("disk", res->disk_options);
	dump_options("startup", res->startup_options);
	dump_options2("proxy", res->proxy_options,
			dump_proxy_plugins, res->proxy_plugins);
	dump_options("handlers", res->handlers);
	--indent;
	printf("}\n\n");

	return 0;
}

static int adm_dump_xml(struct cfg_ctx *ctx)
{
	struct d_host_info *host;
	struct d_resource *res = ctx->res;

	printI("<resource name=\"%s\">\n", esc_xml(res->name));
	++indent;
	// else if (common && common->protocol) printA("# common protocol", common->protocol);
	for (host = res->all_hosts; host; host = host->next)
		dump_host_info_xml(host);
	fake_startup_options(res);
	dump_options_xml("options", res->res_options);
	dump_options_xml("net", res->net_options);
	dump_options_xml("disk", res->disk_options);
	dump_options_xml("startup", res->startup_options);
	dump_options_xml2("proxy", res->proxy_options,
			dump_proxy_plugins_xml, res->proxy_plugins);
	dump_options_xml("handlers", res->handlers);
	--indent;
	printI("</resource>\n");

	return 0;
}

static int sh_nop(struct cfg_ctx *ctx)
{
	return 0;
}

static int sh_resources(struct cfg_ctx *ctx)
{
	struct d_resource *res, *t;
	int first = 1;

	for_each_resource(res, t, config) {
		if (res->ignore)
			continue;
		if (is_drbd_top != res->stacked)
			continue;
		printf(first ? "%s" : " %s", esc(res->name));
		first = 0;
	}
	if (!first)
		printf("\n");

	return 0;
}

static int sh_resource(struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->res->name);
	return 0;
}

static int sh_dev(struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->vol->device);
	return 0;
}

static int sh_udev(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol = ctx->vol;

	/* No shell escape necessary. Udev does not handle it anyways... */
	if (!vol) {
		fprintf(stderr, "volume not specified\n");
		return 1;
	}

	if (vol->implicit)
		printf("RESOURCE=%s\n", res->name);
	else
		printf("RESOURCE=%s/%u\n", res->name, vol->vnr);

	if (!strncmp(vol->device, "/dev/drbd", 9))
		printf("DEVICE=%s\n", vol->device + 5);
	else
		printf("DEVICE=drbd%u\n", vol->device_minor);

	if (!strncmp(vol->disk, "/dev/", 5))
		printf("DISK=%s\n", vol->disk + 5);
	else
		printf("DISK=%s\n", vol->disk);

	return 0;
}

static int sh_minor(struct cfg_ctx *ctx)
{
	printf("%d\n", ctx->vol->device_minor);
	return 0;
}

static int sh_ip(struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->res->me->address);
	return 0;
}

static int sh_lres(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	if (!is_drbd_top) {
		fprintf(stderr,
			"sh-lower-resource only available in stacked mode\n");
		exit(E_usage);
	}
	if (!res->stacked) {
		fprintf(stderr, "'%s' is not stacked on this host (%s)\n",
			res->name, nodeinfo.nodename);
		exit(E_usage);
	}
	printf("%s\n", res->me->lower->name);

	return 0;
}

static int sh_ll_dev(struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->vol->disk);
	return 0;
}


static int sh_md_dev(struct cfg_ctx *ctx)
{
	struct d_volume *vol = ctx->vol;
	char *r;

	if (strcmp("internal", vol->meta_disk) == 0)
		r = vol->disk;
	else
		r = vol->meta_disk;

	printf("%s\n", r);
	return 0;
}

static int sh_md_idx(struct cfg_ctx *ctx)
{
	printf("%s\n", ctx->vol->meta_index);
	return 0;
}

static int sh_b_pri(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	int i, rv;

	if (name_in_names(nodeinfo.nodename, res->become_primary_on) ||
	    name_in_names("both", res->become_primary_on)) {
		/* upon connect resync starts, and both sides become primary at the same time.
		   One's try might be declined since an other state transition happens. Retry. */
		for (i = 0; i < 5; i++) {
			rv = adm_generic_s(ctx);
			if (rv == 0)
				return rv;
			sleep(1);
		}
		return rv;
	}
	return 0;
}

/* FIXME this module parameter will go */
static int sh_mod_parms(struct cfg_ctx *ctx)
{
	int mc = global_options.minor_count;

	if (mc == 0) {
		mc = highest_minor + 11;
		if (mc > DRBD_MINOR_COUNT_MAX)
			mc = DRBD_MINOR_COUNT_MAX;

		if (mc < DRBD_MINOR_COUNT_DEF)
			mc = DRBD_MINOR_COUNT_DEF;
	}
	printf("minor_count=%d\n", mc);
	return 0;
}

static void free_volume(struct d_volume *vol)
{
	if (!vol)
		return;

	free(vol->device);
	free(vol->disk);
	free(vol->meta_disk);
	free(vol->meta_index);
	free(vol);
}

static void free_host_info(struct d_host_info *hi)
{
	struct d_volume *vol;

	if (!hi)
		return;

	free_names(hi->on_hosts);
	for_each_volume(vol, hi->volumes)
		free_volume(vol);
	free(hi->address);
	free(hi->address_family);
	free(hi->port);
}

static void free_options(struct d_option *opts)
{
	struct d_option *f;
	while (opts) {
		free(opts->name);
		free(opts->value);
		f = opts;
		opts = opts->next;
		free(f);
	}
}

static void free_config(struct d_resource *res)
{
	struct d_resource *f, *t;
	struct d_host_info *host;

	for_each_resource(f, t, res) {
		free(f->name);
		free_volume(f->volumes);
		for (host = f->all_hosts; host; host = host->next)
			free_host_info(host);
		free_options(f->net_options);
		free_options(f->disk_options);
		free_options(f->startup_options);
		free_options(f->proxy_options);
		free_options(f->handlers);
		free(f);
	}
	if (common) {
		free_options(common->net_options);
		free_options(common->disk_options);
		free_options(common->startup_options);
		free_options(common->proxy_options);
		free_options(common->handlers);
		free(common);
	}
	if (ifreq_list)
		free(ifreq_list);
}

static void expand_opts(struct d_option *co, struct d_option **opts)
{
	struct d_option *no;

	while (co) {
		if (!find_opt(*opts, co->name)) {
			// prepend new item to opts
			no = new_opt(strdup(co->name),
				     co->value ? strdup(co->value) : NULL);
			no->next = *opts;
			*opts = no;
		}
		co = co->next;
	}
}

static void expand_common(void)
{
	struct d_resource *res, *tmp;
	struct d_volume *vol, *host_vol;
	struct d_host_info *h;

	/* make sure vol->device is non-NULL */
	for_each_resource(res, tmp, config) {
		for (h = res->all_hosts; h; h = h->next) {
			for_each_volume(vol, h->volumes) {
				if (!vol->device)
					m_asprintf(&vol->device, "/dev/drbd%u",
						   vol->device_minor);
			}
		}
	}

	for_each_resource(res, tmp, config) {
		if (!common)
			break;

		expand_opts(common->net_options, &res->net_options);
		expand_opts(common->disk_options, &res->disk_options);
		expand_opts(common->startup_options, &res->startup_options);
		expand_opts(common->proxy_options, &res->proxy_options);
		expand_opts(common->handlers, &res->handlers);
		expand_opts(common->res_options, &res->res_options);

		if (common->stacked_timeouts)
			res->stacked_timeouts = 1;

		if (!res->become_primary_on)
			res->become_primary_on = common->become_primary_on;

		if (common->proxy_plugins && !res->proxy_plugins)
			expand_opts(common->proxy_plugins, &res->proxy_plugins);

	}

	/* now that common disk options (if any) have been propagated to the
	 * resource level, further propagate them to the volume level. */
	for_each_resource(res, tmp, config) {
		for (h = res->all_hosts; h; h = h->next) {
			for_each_volume(vol, h->volumes) {
				expand_opts(res->disk_options, &vol->disk_options);
			}
		}
	}

	/* now from all volume/disk-options on resource level to host level */
	for_each_resource(res, tmp, config) {
		for_each_volume(vol, res->volumes) {
			for (h = res->all_hosts; h; h = h->next) {
				host_vol = volume_by_vnr(h->volumes, vol->vnr);
				expand_opts(vol->disk_options, &host_vol->disk_options);
			}
		}
	}
}

static void find_drbdcmd(char **cmd, char **pathes)
{
	char **path;

	path = pathes;
	while (*path) {
		if (access(*path, X_OK) == 0) {
			*cmd = *path;
			return;
		}
		path++;
	}

	fprintf(stderr, "Can not find command (drbdsetup/drbdmeta)\n");
	exit(E_exec_error);
}

static void alarm_handler(int __attribute((unused)) signo)
{
	alarm_raised = 1;
}

void m__system(char **argv, int flags, const char *res_name, pid_t *kid, int *fd, int *ex)
{
	pid_t pid;
	int status, rv = -1;
	int timeout = 0;
	char **cmdline = argv;
	int pipe_fds[2];

	struct sigaction so;
	struct sigaction sa;

	sa.sa_handler = &alarm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	if (dry_run || verbose) {
		if (sh_varname && *cmdline)
			printf("%s=%s\n", sh_varname,
					res_name ? shell_escape(res_name) : "");
		while (*cmdline) {
			printf("%s ", shell_escape(*cmdline++));
		}
		printf("\n");
		if (dry_run) {
			if (kid)
				*kid = -1;
			if (fd)
				*fd = 0;
			if (ex)
				*ex = 0;
			return;
		}
	}

	/* flush stdout and stderr, so output of drbdadm
	 * and helper binaries is reported in order! */
	fflush(stdout);
	fflush(stderr);

	if (flags & (RETURN_STDOUT_FD | RETURN_STDERR_FD)) {
		if (pipe(pipe_fds) < 0) {
			perror("pipe");
			fprintf(stderr, "Error in pipe, giving up.\n");
			exit(E_exec_error);
		}
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Can not fork\n");
		exit(E_exec_error);
	}
	if (pid == 0) {
		if (flags & RETURN_STDOUT_FD) {
			close(pipe_fds[0]);
			dup2(pipe_fds[1], 1);
		}
		if (flags & RETURN_STDERR_FD) {
			close(pipe_fds[0]);
			dup2(pipe_fds[1], 2);
		}
		if (flags & SUPRESS_STDERR)
			fclose(stderr);
		execvp(argv[0], argv);
		fprintf(stderr, "Can not exec\n");
		exit(E_exec_error);
	}

	if (flags & (RETURN_STDOUT_FD | RETURN_STDERR_FD))
		close(pipe_fds[1]);

	if (flags & SLEEPS_FINITE) {
		sigaction(SIGALRM, &sa, &so);
		alarm_raised = 0;
		switch (flags & SLEEPS_MASK) {
		case SLEEPS_SHORT:
			timeout = 5;
			break;
		case SLEEPS_LONG:
			timeout = COMM_TIMEOUT + 1;
			break;
		case SLEEPS_VERY_LONG:
			timeout = 600;
			break;
		default:
			fprintf(stderr, "logic bug in %s:%d\n", __FILE__,
				__LINE__);
			exit(E_thinko);
		}
		alarm(timeout);
	}

	if (kid)
		*kid = pid;
	if (fd)
		*fd = pipe_fds[0];

	if (flags & (RETURN_STDOUT_FD | RETURN_STDERR_FD)
	||  flags == RETURN_PID)
		return;

	while (1) {
		if (waitpid(pid, &status, 0) == -1) {
			if (errno != EINTR)
				break;
			if (alarm_raised) {
				alarm(0);
				sigaction(SIGALRM, &so, NULL);
				rv = 0x100;
				break;
			} else {
				fprintf(stderr, "logic bug in %s:%d\n",
					__FILE__, __LINE__);
				exit(E_exec_error);
			}
		} else {
			if (WIFEXITED(status)) {
				rv = WEXITSTATUS(status);
				break;
			}
		}
	}

	if (flags & SLEEPS_FINITE) {
		if (rv >= 10
		    && !(flags & (DONT_REPORT_FAILED | SUPRESS_STDERR))) {
			fprintf(stderr, "Command '");
			for (cmdline = argv; *cmdline; cmdline++) {
				fprintf(stderr, "%s", *cmdline);
				if (cmdline[1])
					fputc(' ', stderr);
			}
			if (alarm_raised) {
				fprintf(stderr,
					"' did not terminate within %u seconds\n",
					timeout);
				exit(E_exec_error);
			} else {
				fprintf(stderr,
					"' terminated with exit code %d\n", rv);
			}
		}
	}
	fflush(stdout);
	fflush(stderr);

	if (ex)
		*ex = rv;
}

#define NA(ARGC) \
  ({ if((ARGC) >= MAX_ARGS) { fprintf(stderr,"MAX_ARGS too small\n"); \
       exit(E_thinko); \
     } \
     (ARGC)++; \
  })

#define make_options(OPT) \
  while(OPT) { \
    if(OPT->value) { \
      ssprintf(argv[NA(argc)],"--%s=%s",OPT->name,OPT->value); \
    } else { \
      ssprintf(argv[NA(argc)],"--%s",OPT->name); \
    } \
    OPT=OPT->next; \
  }

/* FIXME: Don't leak the memory allocated by asprintf. */
#define make_address(ADDR, PORT, AF)		\
  if (!strcmp(AF, "ipv6")) { \
    asprintf(&argv[NA(argc)], "%s:[%s]:%s", AF, ADDR, PORT); \
  } else { \
    asprintf(&argv[NA(argc)], "%s:%s:%s", AF, ADDR, PORT); \
  }

static int adm_attach_or_disk_options(struct cfg_ctx *ctx, bool do_attach, bool reset)
{
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	struct d_option *opt;
	int argc = 0;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = do_attach ? "attach" : "disk-options";
	ssprintf(argv[NA(argc)], "%d", vol->device_minor);
	if (do_attach) {
		argv[NA(argc)] = vol->disk;
		if (!strcmp(vol->meta_disk, "internal")) {
			argv[NA(argc)] = vol->disk;
		} else {
			argv[NA(argc)] = vol->meta_disk;
		}
		argv[NA(argc)] = vol->meta_index;
	}
	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (reset || do_attach) {
		opt = ctx->vol->disk_options;
		if (!do_attach) {
			while (opt && opt->adj_skip)
				opt = opt->next;
		}
		make_options(opt);
	}
	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_LONG, ctx->res->name);
}

int adm_attach(struct cfg_ctx *ctx)
{
	return adm_attach_or_disk_options(ctx, true, false);
}

int adm_disk_options(struct cfg_ctx *ctx)
{
	return adm_attach_or_disk_options(ctx, false, false);
}

int adm_set_default_disk_options(struct cfg_ctx *ctx)
{
	return adm_attach_or_disk_options(ctx, false, true);
}

struct d_option *find_opt(struct d_option *base, char *name)
{
	while (base) {
		if (!strcmp(base->name, name)) {
			return base;
		}
		base = base->next;
	}
	return 0;
}

int adm_new_minor(struct cfg_ctx *ctx)
{
	char *argv[MAX_ARGS];
	int argc = 0, ex;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = "new-minor";
	ssprintf(argv[NA(argc)], "%s", ctx->res->name);
	ssprintf(argv[NA(argc)], "%u", ctx->vol->device_minor);
	ssprintf(argv[NA(argc)], "%u", ctx->vol->vnr);
	argv[NA(argc)] = NULL;

	ex = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
	if (!ex && do_register)
		register_minor(ctx->vol->device_minor, config_save);
	return ex;
}

static int adm_new_resource_or_res_options(struct cfg_ctx *ctx, bool do_new_resource, bool reset)
{
	char *argv[MAX_ARGS];
	int argc = 0, ex;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = do_new_resource ? "new-resource" : "resource-options";
	ssprintf(argv[NA(argc)], "%s", ctx->res->name);
	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (reset || do_new_resource)
		make_options(ctx->res->res_options);

	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}
	argv[NA(argc)] = NULL;

	ex = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
	if (!ex && do_new_resource && do_register)
		register_resource(ctx->res->name, config_save);
	return ex;
}

int adm_new_resource(struct cfg_ctx *ctx)
{
	return adm_new_resource_or_res_options(ctx, true, false);
}

int adm_res_options(struct cfg_ctx *ctx)
{
	return adm_new_resource_or_res_options(ctx, false, false);
}

int adm_set_default_res_options(struct cfg_ctx *ctx)
{
	return adm_new_resource_or_res_options(ctx, false, true);
}

int adm_resize(struct cfg_ctx *ctx)
{
	char *argv[MAX_ARGS];
	struct d_option *opt;
	int argc = 0;
	int silent;
	int ex;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = "resize";
	ssprintf(argv[NA(argc)], "%d", ctx->vol->device_minor);
	opt = find_opt(ctx->vol->disk_options, "size");
	if (!opt)
		opt = find_opt(ctx->res->disk_options, "size");
	if (opt)
		ssprintf(argv[NA(argc)], "--%s=%s", opt->name, opt->value);
	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}
	argv[NA(argc)] = 0;

	/* if this is not "resize", but "check-resize", be silent! */
	silent = !strcmp(ctx->arg, "check-resize") ? SUPRESS_STDERR : 0;
	ex = m_system_ex(argv, SLEEPS_SHORT | silent, ctx->res->name);

	if (ex)
		return ex;

	/* Record last-known bdev info.
	 * Unfortunately drbdsetup did not have enough information
	 * when doing the "resize", and in theory, _our_ information
	 * about the backing device may even be wrong.
	 * Call drbdsetup again, tell it to ask the kernel for
	 * current config, and update the last known bdev info
	 * according to that. */
	/* argv[0] = drbdsetup; */
	argv[1] = "check-resize";
	/* argv[2] = minor; */
	argv[3] = NULL;
	/* ignore exit code */
	m_system_ex(argv, SLEEPS_SHORT | silent, ctx->res->name);

	return 0;
}

int _admm_generic(struct cfg_ctx *ctx, int flags)
{
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = drbdmeta;
	ssprintf(argv[NA(argc)], "%d", vol->device_minor);
	argv[NA(argc)] = "v08";
	if (!strcmp(vol->meta_disk, "internal")) {
		argv[NA(argc)] = vol->disk;
	} else {
		argv[NA(argc)] = vol->meta_disk;
	}
	if (!strcmp(vol->meta_index, "flexible")) {
		if (!strcmp(vol->meta_disk, "internal")) {
			argv[NA(argc)] = "flex-internal";
		} else {
			argv[NA(argc)] = "flex-external";
		}
	} else {
		argv[NA(argc)] = vol->meta_index;
	}
	argv[NA(argc)] = (char *)ctx->arg;
	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}
	argv[NA(argc)] = 0;

	return m_system_ex(argv, flags, ctx->res->name);
}

static int admm_generic(struct cfg_ctx *ctx)
{
	return _admm_generic(ctx, SLEEPS_VERY_LONG);
}

static void _adm_generic(struct cfg_ctx *ctx, int flags, pid_t *pid, int *fd, int *ex)
{
	char *argv[MAX_ARGS];
	int argc = 0;

	if (!ctx->res) {
		/* ASSERT */
		fprintf(stderr, "sorry, need at least a resource name to call drbdsetup\n");
		abort();
	}

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = (char *)ctx->arg;
	if (ctx->vol)
		ssprintf(argv[NA(argc)], "%d", ctx->vol->device_minor);
	else
		ssprintf(argv[NA(argc)], "%s", ctx->res->name);
	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}
	argv[NA(argc)] = 0;

	setenv("DRBD_RESOURCE", ctx->res->name, 1);
	m__system(argv, flags, ctx->res->name, pid, fd, ex);
}

static int adm_generic(struct cfg_ctx *ctx, int flags)
{
	int ex;
	_adm_generic(ctx, flags, NULL, NULL, &ex);
	return ex;
}

int adm_generic_s(struct cfg_ctx *ctx)
{
	return adm_generic(ctx, SLEEPS_SHORT);
}

int adm_status_xml(struct cfg_ctx *ctx)
{
	int rv, max_rv = 0;
	struct d_resource *r, *t;
	struct d_volume *vol;

	if (!dry_run) {
		printf("<drbd-status version=\"%s\" api=\"%u\">\n",
		       REL_VERSION, API_VERSION);
		printf("<resources config_file=\"%s\">\n", config_save);
	}

	/* TODO: remove thes loops, have drbdsetup use dump
	 * and optionally filter on resource name.
	 * Fix adm_generic to figure out how to call drbdsetup
	 * if neither volume nor resource is set in ctx. */
	for_each_resource(r, t, config) {
		if (r->ignore)
			continue;
		ctx->res = r;
		for_each_volume(vol, r->me->volumes) {
			ctx->vol = vol;
			rv = adm_generic(ctx, SLEEPS_SHORT);
			/* FIXME what if rv != 0 */
			if (rv > max_rv)
				max_rv = rv;
		}
	}

	if (!dry_run)
		printf("</resources>\n</drbd-status>\n");
	return max_rv;
}

int sh_status(struct cfg_ctx *ctx)
{
	struct d_resource *r, *t;
	struct d_volume *vol, *lower_vol;
	int rv = 0;

	if (!dry_run) {
		printf("_drbd_version=%s\n_drbd_api=%u\n",
		       shell_escape(REL_VERSION), API_VERSION);
		printf("_config_file=%s\n\n", shell_escape(config_save));
	}

	for_each_resource(r, t, config) {
		if (r->ignore)
			continue;
		printf("_res_name=%s\n", r->name);
		printf("_stacked_on=%s\n", r->stacked && r->me->lower ?
		       shell_escape(r->me->lower->name) : "");
		/* reset stuff */
		printf("_stacked_on_device=\n");
		printf("_stacked_on_minor=\n");
		ctx->res = r;
		lower_vol = r->stacked && r->me->lower ?
			r->me->lower->me->volumes : NULL;
		/* TODO: remove this loop, have drbdsetup use dump
		 * and optionally filter on resource name. */
		for_each_volume(vol, r->me->volumes) {
			/* do not continue in this loop,
			 * or lower_vol will get out of sync */
			if (lower_vol) {
				printf("_stacked_on_device=%s\n", shell_escape(lower_vol->device));
				printf("_stacked_on_minor=%d\n", lower_vol->device_minor);
			} else if (r->stacked && r->me->lower) {
				/* ASSERT */
				fprintf(stderr, "in %s: stacked volume[%u] without lower volume\n",
						r->name, vol->vnr);
				abort();
			}
			ctx->vol = vol;
			rv = adm_generic(ctx, SLEEPS_SHORT);
			if (rv)
				return rv;

			if (lower_vol)
				lower_vol = lower_vol->next;
			/* vol is advanced by for_each_volume */
		}
	}
	return 0;
}

int adm_generic_l(struct cfg_ctx *ctx)
{
	return adm_generic(ctx, SLEEPS_LONG);
}

static int adm_outdate(struct cfg_ctx *ctx)
{
	int rv;

	rv = adm_generic(ctx, SLEEPS_SHORT | SUPRESS_STDERR);
	/* special cases for outdate:
	 * 17: drbdsetup outdate, but is primary and thus cannot be outdated.
	 *  5: drbdsetup outdate, and is inconsistent or worse anyways. */
	if (rv == 17)
		return rv;

	if (rv == 5) {
		/* That might mean it is diskless. */
		rv = admm_generic(ctx);
		if (rv)
			rv = 5;
		return rv;
	}

	if (rv || dry_run) {
		rv = admm_generic(ctx);
	}
	return rv;
}

/* shell equivalent:
 * ( drbdsetup resize && drbdsetup check-resize ) || drbdmeta check-resize */
static int adm_chk_resize(struct cfg_ctx *ctx)
{
	/* drbdsetup resize && drbdsetup check-resize */
	int ex = adm_resize(ctx);
	if (ex == 0)
		return 0;

	/* try drbdmeta check-resize */
	return admm_generic(ctx);
}

static int adm_generic_b(struct cfg_ctx *ctx)
{
	char buffer[4096];
	int fd, status, rv = 0, rr, s = 0;
	pid_t pid;

	_adm_generic(ctx, SLEEPS_SHORT | RETURN_STDERR_FD, &pid, &fd, NULL);

	if (fd < 0) {
		fprintf(stderr, "Strange: got negative fd.\n");
		exit(E_thinko);
	}

	if (!dry_run) {
		while (1) {
			rr = read(fd, buffer + s, 4096 - s);
			if (rr <= 0)
				break;
			s += rr;
		}

		close(fd);
		rr = waitpid(pid, &status, 0);
		alarm(0);

		if (WIFEXITED(status))
			rv = WEXITSTATUS(status);
		if (alarm_raised) {
			rv = 0x100;
		}
	}

	/* see drbdsetup.c, print_config_error():
	 *  11: some unspecific state change error
	 *  17: SS_NO_UP_TO_DATE_DISK
	 * In both cases, we don't need to retry with drbdmeta,
	 * it would fail anyways with "Device is configured!" */
	if (rv == 11 || rv == 17) {
		/* Some state transition error, report it ... */
		rr = write(fileno(stderr), buffer, s);
		return rv;
	}

	if (rv || dry_run) {
		/* On other errors
		   rv = 10 .. no minor allocated
		   rv = 20 .. module not loaded
		   rv = 16 .. we are diskless here
		   retry with drbdmeta.
		 */
		rv = admm_generic(ctx);
	}
	return rv;
}

static int adm_khelper(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol = ctx->vol;
	int rv = 0;
	char *sh_cmd;
	char minor_string[8];
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };

	if (!res->peer) {
		/* Since 8.3.2 we get DRBD_PEER_AF and DRBD_PEER_ADDRESS from the kernel.
		   If we do not know the peer by now, use these to find the peer. */
		struct d_host_info *host;
		char *peer_address = getenv("DRBD_PEER_ADDRESS");
		char *peer_af = getenv("DRBD_PEER_AF");

		if (peer_address && peer_af) {
			for (host = res->all_hosts; host; host = host->next) {
				if (!strcmp(host->address_family, peer_af) &&
				    !strcmp(host->address, peer_address)) {
					res->peer = host;
					break;
				}
			}
		}
	}

	if (res->peer) {
		setenv("DRBD_PEER_AF", res->peer->address_family, 1);	/* since 8.3.0 */
		setenv("DRBD_PEER_ADDRESS", res->peer->address, 1);	/* since 8.3.0 */
		setenv("DRBD_PEER", res->peer->on_hosts->name, 1);	/* deprecated */
		setenv("DRBD_PEERS", names_to_str(res->peer->on_hosts), 1);
			/* since 8.3.0, but not usable when using a config with "floating" statements. */
	}

	if (vol) {
		snprintf(minor_string, sizeof(minor_string), "%u", vol->device_minor);
		setenv("DRBD_MINOR", minor_string, 1);
	}

	setenv("DRBD_RESOURCE", res->name, 1);
	setenv("DRBD_CONF", config_save, 1);

	if ((sh_cmd = get_opt_val(res->handlers, ctx->arg, NULL))) {
		argv[2] = sh_cmd;
		rv = m_system_ex(argv, SLEEPS_VERY_LONG, res->name);
	}
	return rv;
}

// need to convert discard-node-nodename to discard-local or discard-remote.
void convert_discard_opt(struct d_resource *res)
{
	struct d_option *opt;

	if (res == NULL)
		return;

	if ((opt = find_opt(res->net_options, "after-sb-0pri"))) {
		if (!strncmp(opt->value, "discard-node-", 13)) {
			if (!strcmp(nodeinfo.nodename, opt->value + 13)) {
				free(opt->value);
				opt->value = strdup("discard-local");
			} else {
				free(opt->value);
				opt->value = strdup("discard-remote");
			}
		}
	}
}

static int add_connection_endpoints(char **argv, int *argcp, struct d_resource *res)
{
	int argc = *argcp;

	make_address(res->me->address, res->me->port, res->me->address_family);
	if (res->me->proxy) {
		make_address(res->me->proxy->inside_addr,
			     res->me->proxy->inside_port,
			     res->me->proxy->inside_af);
	} else if (res->peer) {
		make_address(res->peer->address, res->peer->port,
			     res->peer->address_family);
	} else if (dry_run) {
		argv[NA(argc)] = "N/A";
	} else {
		fprintf(stderr, "resource %s: cannot configure network without knowing my peer.\n", res->name);
		return 20;
	}
	*argcp = argc;
	return 0;
}

static int adm_connect_or_net_options(struct cfg_ctx *ctx, bool do_connect, bool reset)
{
	struct d_resource *res = ctx->res;
	char *argv[MAX_ARGS];
	struct d_option *opt;
	int argc = 0;
	int err;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = do_connect ? "connect" : "net-options";
	if (do_connect)
		ssprintf(argv[NA(argc)], "%s", res->name);
	err = add_connection_endpoints(argv, &argc, res);
	if (err)
		return err;

	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (reset || do_connect) {
		opt = res->net_options;
		make_options(opt);
	}

	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}

	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
}

int adm_connect(struct cfg_ctx *ctx)
{
	return adm_connect_or_net_options(ctx, true, false);
}

int adm_net_options(struct cfg_ctx *ctx)
{
	return adm_connect_or_net_options(ctx, false, false);
}

int adm_set_default_net_options(struct cfg_ctx *ctx)
{
	return adm_connect_or_net_options(ctx, false, true);
}

int adm_disconnect(struct cfg_ctx *ctx)
{
	char *argv[MAX_ARGS];
	int argc = 0;

	if (!ctx->res) {
		/* ASSERT */
		fprintf(stderr, "sorry, need at least a resource name to call drbdsetup\n");
		abort();
	}

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = (char *)ctx->arg;
	/*
	if (ctx->vol)
		ssprintf(argv[NA(argc)], "%d", ctx->vol->device_minor);
	else
		ssprintf(argv[NA(argc)], "%s", ctx->res->name);
	*/
	add_connection_endpoints(argv, &argc, ctx->res);
	if (setup_options) {
		int i;
		for (i = 0; setup_options[i].option; i++)
			argv[NA(argc)] = setup_options[i].option;
	}
	argv[NA(argc)] = 0;

	setenv("DRBD_RESOURCE", ctx->res->name, 1);
	return m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
}

struct d_option *del_opt(struct d_option *base, struct d_option *item)
{
	struct d_option *i;
	if (base == item) {
		base = item->next;
		free(item->name);
		free(item->value);
		free(item);
		return base;
	}

	for (i = base; i; i = i->next) {
		if (i->next == item) {
			i->next = item->next;
			free(item->name);
			free(item->value);
			free(item);
			return base;
		}
	}
	return base;
}

// Need to convert after from resourcename to minor_number.
void _convert_after_option(struct d_resource *res, struct d_volume *vol)
{
	struct d_option *opt, *next;
	struct cfg_ctx depends_on_ctx = { };
	int volumes;

	if (res == NULL)
		return;

	opt = vol->disk_options;
	while ((opt = find_opt(opt, "resync-after"))) {
		next = opt->next;
		ctx_by_name(&depends_on_ctx, opt->value);
		volumes = ctx_set_implicit_volume(&depends_on_ctx);
		if (volumes > 1) {
			fprintf(stderr,
				"%s:%d: in resource %s:\n\t"
				"resync-after contains '%s', which is ambiguous, since it contains %d volumes\n",
				res->config_file, res->start_line, res->name,
				opt->value, volumes);
			config_valid = 0;
			return;
		}

		if (!depends_on_ctx.res || depends_on_ctx.res->ignore) {
			vol->disk_options = del_opt(vol->disk_options, opt);
		} else {
			free(opt->value);
			m_asprintf(&opt->value, "%d", depends_on_ctx.vol->device_minor);
		}
		opt = next;
	}
}

// Need to convert after from resourcename/volume to minor_number.
void convert_after_option(struct d_resource *res)
{
	struct d_volume *vol;
	struct d_host_info *h;

	for (h = res->all_hosts; h; h = h->next)
		for_each_volume(vol, h->volumes)
			_convert_after_option(res, vol);
}

char *proxy_connection_name(struct d_resource *res)
{
	static char conn_name[128];
	int counter;

	counter = snprintf(conn_name, sizeof(conn_name), "%s-%s-%s",
			 res->name,
			 names_to_str_c(res->peer->proxy->on_hosts, '_'),
			 names_to_str_c(res->me->proxy->on_hosts, '_')
			 );
	if (counter >= sizeof(conn_name)-3) {
		fprintf(stderr,
				"The connection name in resource %s got too long.\n",
				res->name);
		exit(E_config_invalid);
	}

	return conn_name;
}

int do_proxy_conn_up(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char *argv[4] = { drbd_proxy_ctl, "-c", NULL, NULL };
	char *conn_name;
	int rv;

	conn_name = proxy_connection_name(res);

	ssprintf(argv[2],
			"add connection %s %s:%s %s:%s %s:%s %s:%s",
			conn_name,
			res->me->proxy->inside_addr,
			res->me->proxy->inside_port,
			res->peer->proxy->outside_addr,
			res->peer->proxy->outside_port,
			res->me->proxy->outside_addr,
			res->me->proxy->outside_port, res->me->address,
			res->me->port);

	rv = m_system_ex(argv, SLEEPS_SHORT, res->name);
	return rv;
}

int do_proxy_conn_plugins(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char *argv[MAX_ARGS];
	char *conn_name;
	int argc = 0;
	struct d_option *opt;
	int counter;

	conn_name = proxy_connection_name(res);

	argc = 0;
	argv[NA(argc)] = drbd_proxy_ctl;
	opt = res->proxy_options;
	while (opt) {
		argv[NA(argc)] = "-c";
		ssprintf(argv[NA(argc)], "set %s %s %s",
			 opt->name, conn_name, opt->value);
		opt = opt->next;
	}

	counter = 0;
	opt = res->proxy_plugins;
	/* Don't send the "set plugin ... END" line if no plugins are defined 
	 * - that's incompatible with the drbd proxy version 1. */
	if (opt) {
		while (1) {
			argv[NA(argc)] = "-c";
			ssprintf(argv[NA(argc)], "set plugin %s %d %s",
					conn_name, counter, opt ? opt->name : "END");
			if (!opt) break;
			opt = opt->next;
			counter ++;
		}
	}

	argv[NA(argc)] = 0;
	if (argc > 2)
		return m_system_ex(argv, SLEEPS_SHORT, res->name);

	return 0;
}

int do_proxy_conn_down(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char *conn_name;
	char *argv[4] = { drbd_proxy_ctl, "-c", NULL, NULL};
	int rv;

	conn_name = proxy_connection_name(res);
	ssprintf(argv[2], "del connection %s", conn_name);

	rv = m_system_ex(argv, SLEEPS_SHORT, res->name);
	return rv;
}


static int check_proxy(struct cfg_ctx *ctx, int do_up)
{
	struct d_resource *res = ctx->res;
	int rv;

	if (!res->me->proxy) {
		if (all_resources)
			return 0;
		fprintf(stderr,
			"There is no proxy config for host %s in resource %s.\n",
			nodeinfo.nodename, res->name);
		exit(E_config_invalid);
	}

	if (!name_in_names(nodeinfo.nodename, res->me->proxy->on_hosts)) {
		if (all_resources)
			return 0;
		fprintf(stderr,
			"The proxy config in resource %s is not for %s.\n",
			res->name, nodeinfo.nodename);
		exit(E_config_invalid);
	}

	if (!res->peer) {
		fprintf(stderr, "Cannot determine the peer in resource %s.\n",
			res->name);
		exit(E_config_invalid);
	}

	if (!res->peer->proxy) {
		fprintf(stderr,
			"There is no proxy config for the peer in resource %s.\n",
			res->name);
		if (all_resources)
			return 0;
		exit(E_config_invalid);
	}


	if (do_up) {
		rv = do_proxy_conn_up(ctx);
		if (!rv)
			rv = do_proxy_conn_plugins(ctx);
	}
	else
		rv = do_proxy_conn_down(ctx);

	return rv;
}

static int adm_proxy_up(struct cfg_ctx *ctx)
{
	return check_proxy(ctx, 1);
}

static int adm_proxy_down(struct cfg_ctx *ctx)
{
	return check_proxy(ctx, 0);
}

/* The "main" loop iterates over resources.
 * This "sorts" the drbdsetup commands to bring those up
 * so we will later first create all objects,
 * then attach all local disks,
 * adjust various settings,
 * and then configure the network part */
static int adm_up(struct cfg_ctx *ctx)
{
	static char *current_res_name;

	if (!current_res_name || strcmp(current_res_name, ctx->res->name)) {
		free(current_res_name);
		current_res_name = strdup(ctx->res->name);

		schedule_deferred_cmd(adm_new_resource, ctx, "new-resource", CFG_PREREQ);
		schedule_deferred_cmd(adm_connect, ctx, "connect", CFG_NET);
	}
	schedule_deferred_cmd(adm_new_minor, ctx, "new-minor", CFG_PREREQ);
	schedule_deferred_cmd(adm_attach, ctx, "attach", CFG_DISK);

	/*
	 * FIXME:
	 * quick fix to make the al-extent setting apply on freshly created meta-data.
	 * Needs to be fixed in-kernel drbd_adm_attach().
	 */
	schedule_deferred_cmd(adm_set_default_disk_options, ctx, "disk-options", CFG_DISK);

	return 0;
}

/* The stacked-timeouts switch in the startup sections allows us
   to enforce the use of the specified timeouts instead the use
   of a sane value. Should only be used if the third node should
   never become primary. */
static int adm_wait_c(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	struct d_option *opt;
	int argc = 0, rv;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = "wait-connect";
	ssprintf(argv[NA(argc)], "%d", vol->device_minor);
	if (is_drbd_top && !res->stacked_timeouts) {
		unsigned long timeout = 20;
		if ((opt = find_opt(res->net_options, "connect-int"))) {
			timeout = strtoul(opt->value, NULL, 10);
			// one connect-interval? two?
			timeout *= 2;
		}
		argv[argc++] = "-t";
		ssprintf(argv[argc], "%lu", timeout);
		argc++;
	} else {
		opt = res->startup_options;
		make_options(opt);
	}
	argv[NA(argc)] = 0;

	rv = m_system_ex(argv, SLEEPS_FOREVER, res->name);

	return rv;
}

static unsigned minor_by_id(const char *id)
{
	if (strncmp(id, "minor-", 6))
		return -1U;
	return m_strtoll(id + 6, 1);
}

int ctx_by_minor(struct cfg_ctx *ctx, const char *id)
{
	struct d_resource *res, *t;
	struct d_volume *vol;
	unsigned int mm;

	mm = minor_by_id(id);
	if (mm == -1U)
		return -ENOENT;

	for_each_resource(res, t, config) {
		if (res->ignore)
			continue;
		for_each_volume(vol, res->me->volumes) {
			if (mm == vol->device_minor) {
				is_drbd_top = res->stacked;
				ctx->res = res;
				ctx->vol = vol;
				return 0;
			}
		}
	}
	return -ENOENT;
}

struct d_resource *res_by_name(const char *name)
{
	struct d_resource *res, *t;

	for_each_resource(res, t, config) {
		if (strcmp(name, res->name) == 0)
			return res;
	}
	return NULL;
}

struct d_volume *volume_by_vnr(struct d_volume *volumes, int vnr)
{
	struct d_volume *vol;

	for_each_volume(vol, volumes)
		if (vnr == vol->vnr)
			return vol;

	return NULL;
}

int ctx_by_name(struct cfg_ctx *ctx, const char *id)
{
	struct d_resource *res, *t;
	struct d_volume *vol;
	char *name = strdupa(id);
	char *vol_id = strchr(name, '/');
	unsigned vol_nr = ~0U;

	if (vol_id) {
		*vol_id++ = '\0';
		vol_nr = m_strtoll(vol_id, 0);
	}

	for_each_resource(res, t, config) {
		if (strcmp(name, res->name) == 0)
			break;
	}
	if (!res)
		return -ENOENT;

	if (!vol_id) {
		/* We could assign implicit volumes here.
		 * But that broke "drbdadm up specific-resource".
		 */
		ctx->res = res;
		ctx->vol = NULL;
		return 0;
	}

	vol = volume_by_vnr(res->me->volumes, vol_nr);
	if (vol) {
		ctx->res = res;
		ctx->vol = vol;
		return 0;
	}

	return -ENOENT;
}

int ctx_set_implicit_volume(struct cfg_ctx *ctx)
{
	struct d_volume *vol, *v;
	int volumes = 0;

	if (ctx->vol || !ctx->res)
		return 0;

	for_each_volume(vol, ctx->res->me->volumes) {
		volumes++;
		v = vol;
	}

	if (volumes == 1)
		ctx->vol = v;

	return volumes;
}

/* In case a child exited, or exits, its return code is stored as
   negative number in the pids[i] array */
static int childs_running(pid_t * pids, int opts)
{
	int i = 0, wr, rv = 0, status;
	int N = nr_volumes[is_drbd_top ? STACKED : NORMAL];

	for (i = 0; i < N; i++) {
		if (pids[i] <= 0)
			continue;
		wr = waitpid(pids[i], &status, opts);
		if (wr == -1) {	// Wait error.
			if (errno == ECHILD) {
				printf("No exit code for %d\n", pids[i]);
				pids[i] = 0;	// Child exited before ?
				continue;
			}
			perror("waitpid");
			exit(E_exec_error);
		}
		if (wr == 0)
			rv = 1;	// Child still running.
		if (wr > 0) {
			pids[i] = 0;
			if (WIFEXITED(status))
				pids[i] = -WEXITSTATUS(status);
			if (WIFSIGNALED(status))
				pids[i] = -1000;
		}
	}
	return rv;
}

static void kill_childs(pid_t * pids)
{
	int i;
	int N = nr_volumes[is_drbd_top ? STACKED : NORMAL];

	for (i = 0; i < N; i++) {
		if (pids[i] <= 0)
			continue;
		kill(pids[i], SIGINT);
	}
}

/*
  returns:
  -1 ... all childs terminated
   0 ... timeout expired
   1 ... a string was read
 */
int gets_timeout(pid_t * pids, char *s, int size, int timeout)
{
	int pr, rr, n = 0;
	struct pollfd pfd;

	if (s) {
		pfd.fd = fileno(stdin);
		pfd.events = POLLIN | POLLHUP | POLLERR | POLLNVAL;
		n = 1;
	}

	if (!childs_running(pids, WNOHANG)) {
		pr = -1;
		goto out;
	}

	do {
		pr = poll(&pfd, n, timeout);

		if (pr == -1) {	// Poll error.
			if (errno == EINTR) {
				if (childs_running(pids, WNOHANG))
					continue;
				goto out;	// pr = -1 here.
			}
			perror("poll");
			exit(E_exec_error);
		}
	} while (pr == -1);

	if (pr == 1) {		// Input available.
		rr = read(fileno(stdin), s, size - 1);
		if (rr == -1) {
			perror("read");
			exit(E_exec_error);
		}
		s[rr] = 0;
	}

out:
	return pr;
}

static char *get_opt_val(struct d_option *base, const char *name, char *def)
{
	while (base) {
		if (!strcmp(base->name, name)) {
			return base->value;
		}
		base = base->next;
	}
	return def;
}

void chld_sig_hand(int __attribute((unused)) unused)
{
	// do nothing. But interrupt systemcalls :)
}

static int check_exit_codes(pid_t * pids)
{
	struct d_resource *res, *t;
	int i = 0, rv = 0;

	for_each_resource(res, t, config) {
		if (res->ignore)
			continue;
		if (is_drbd_top != res->stacked)
			continue;
		if (pids[i] == -5 || pids[i] == -1000) {
			pids[i] = 0;
		}
		if (pids[i] == -20)
			rv = 20;
		i++;
	}
	return rv;
}

static int adm_wait_ci(struct cfg_ctx *ctx)
{
	struct d_resource *res, *t;
	char *argv[20], answer[40];
	pid_t *pids;
	struct d_option *opt;
	int rr, wtime, argc, i = 0;
	time_t start;
	int saved_stdin, saved_stdout, fd;
	int N;
	struct sigaction so, sa;

	saved_stdin = -1;
	saved_stdout = -1;
	if (no_tty) {
		fprintf(stderr,
			"WARN: stdin/stdout is not a TTY; using /dev/console");
		fprintf(stdout,
			"WARN: stdin/stdout is not a TTY; using /dev/console");
		saved_stdin = dup(fileno(stdin));
		if (saved_stdin == -1)
			perror("dup(stdin)");
		saved_stdout = dup(fileno(stdout));
		if (saved_stdin == -1)
			perror("dup(stdout)");
		fd = open("/dev/console", O_RDONLY);
		if (fd == -1)
			perror("open('/dev/console, O_RDONLY)");
		dup2(fd, fileno(stdin));
		fd = open("/dev/console", O_WRONLY);
		if (fd == -1)
			perror("open('/dev/console, O_WRONLY)");
		dup2(fd, fileno(stdout));
	}

	sa.sa_handler = chld_sig_hand;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_NOCLDSTOP;
	sigaction(SIGCHLD, &sa, &so);

	N = nr_volumes[is_drbd_top ? STACKED : NORMAL];
	pids = alloca(N * sizeof(pid_t));
	/* alloca can not fail, it can "only" overflow the stack :)
	 * but it needs to be initialized anyways! */
	memset(pids, 0, N * sizeof(pid_t));

	for_each_resource(res, t, config) {
		struct d_volume *vol;
		if (res->ignore)
			continue;
		if (is_drbd_top != res->stacked)
			continue;

		for_each_volume(vol, res->me->volumes) {
			/* ctx is not used */
			argc = 0;
			argv[NA(argc)] = drbdsetup;
			argv[NA(argc)] = "wait-connect";
			ssprintf(argv[NA(argc)], "%u", vol->device_minor);
			opt = res->startup_options;
			make_options(opt);
			argv[NA(argc)] = 0;

			m__system(argv, RETURN_PID, res->name, &pids[i++], NULL, NULL);
		}
	}

	wtime = global_options.dialog_refresh ? : -1;

	start = time(0);
	for (i = 0; i < 10; i++) {
		// no string, but timeout
		rr = gets_timeout(pids, 0, 0, 1 * 1000);
		if (rr < 0)
			break;
		putchar('.');
		fflush(stdout);
		check_exit_codes(pids);
	}

	if (rr == 0) {
		printf
		    ("\n***************************************************************\n"
		     " DRBD's startup script waits for the peer node(s) to appear.\n"
		     " - In case this node was already a degraded cluster before the\n"
		     "   reboot the timeout is %s seconds. [degr-wfc-timeout]\n"
		     " - If the peer was available before the reboot the timeout will\n"
		     "   expire after %s seconds. [wfc-timeout]\n"
		     "   (These values are for resource '%s'; 0 sec -> wait forever)\n",
		     get_opt_val(config->startup_options, "degr-wfc-timeout",
				 "0"), get_opt_val(config->startup_options,
						   "wfc-timeout", "0"),
		     config->name);

		printf(" To abort waiting enter 'yes' [ -- ]: ");
		do {
			printf("\e[s\e[31G[%4d]:\e[u", (int)(time(0) - start));	// Redraw sec.
			fflush(stdout);
			rr = gets_timeout(pids, answer, 40, wtime * 1000);
			check_exit_codes(pids);

			if (rr == 1) {
				if (!strcmp(answer, "yes\n")) {
					kill_childs(pids);
					childs_running(pids, 0);
					check_exit_codes(pids);
					rr = -1;
				} else {
					printf(" To abort waiting enter 'yes' [ -- ]: ");
				}
			}
		} while (rr != -1);
		printf("\n");
	}

	if (saved_stdin != -1) {
		dup2(saved_stdin, fileno(stdin));
		dup2(saved_stdout, fileno(stdout));
	}

	return 0;
}

static void print_cmds(int level)
{
	size_t i;
	int j = 0;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (cmds[i].show_in_usage != level)
			continue;
		if (j++ % 2) {
			printf("%-35s\n", cmds[i].name);
		} else {
			printf(" %-35s", cmds[i].name);
		}
	}
	if (j % 2)
		printf("\n");
}

static int hidden_cmds(struct cfg_ctx *ignored __attribute((unused)))
{
	printf("\nThese additional commands might be useful for writing\n"
	       "nifty shell scripts around drbdadm:\n\n");

	print_cmds(2);

	printf("\nThese commands are used by the kernel part of DRBD to\n"
	       "invoke user mode helper programs:\n\n");

	print_cmds(3);

	printf
	    ("\nThese commands ought to be used by experts and developers:\n\n");

	print_cmds(4);

	printf("\n");

	exit(0);
}

static void field_to_option(const struct field_def *field, struct option *option)
{
	option->name = field->name;
	option->has_arg = field->argument_is_optional ?
		optional_argument : required_argument;
	option->flag = NULL;
	option->val = 257;
}

static void print_option(struct option *opt)
{
	if (opt->has_arg == required_argument) {
		printf("  --%s=...", opt->name);
		if (opt->val > 1 && opt->val < 256)
			 printf(", -%c ...", opt->val);
		printf("\n");
	} else if (opt->has_arg == optional_argument) {
		printf("  --%s[=...]", opt->name);
		if (opt->val > 1 && opt->val < 256)
			 printf(", -%c...", opt->val);
		printf("\n");
	} else {
		printf("  --%s", opt->name);
		if (opt->val > 1 && opt->val < 256)
			 printf(", -%c", opt->val);
		printf("\n");
	}
}

void print_usage_and_exit(struct adm_cmd *cmd, const char *addinfo)
{
	struct option *opt;

	printf("\nUSAGE: %s [OPTION...] %s {all|RESOURCE...}\n\n"
	       "GENERAL OPTIONS:\n", progname, cmd ? cmd->name : "COMMAND");

	for (opt = general_admopt; opt->name; opt++)
		print_option(opt);
	if (cmd && cmd->drbdsetup_ctx) {
		const struct field_def *field;

		printf("\nOPTIONS FOR %s:\n", cmd->name);
		for (field = cmd->drbdsetup_ctx->fields; field->name; field++) {
			struct option opt;

			field_to_option(field, &opt);
			print_option(&opt);
		}
	}

	if (!cmd) {
		printf("\nCOMMANDS:\n");

		print_cmds(1);
	}

	printf("\nVersion: " REL_VERSION " (api:%d)\n%s\n",
	       API_VERSION, drbd_buildtag());

	if (addinfo)
		printf("\n%s\n", addinfo);

	exit(E_usage);
}

/*
 * I'd really rather parse the output of
 *   ip -o a s
 * once, and be done.
 * But anyways....
 */

static struct ifreq *get_ifreq(void)
{
	int sockfd, num_ifaces;
	struct ifreq *ifr;
	struct ifconf ifc;
	size_t buf_size;

	if (0 > (sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))) {
		perror("Cannot open socket");
		exit(EXIT_FAILURE);
	}

	num_ifaces = 0;
	ifc.ifc_req = NULL;

	/* realloc buffer size until no overflow occurs  */
	do {
		num_ifaces += 16;	/* initial guess and increment */
		buf_size = ++num_ifaces * sizeof(struct ifreq);
		ifc.ifc_len = buf_size;
		if (NULL == (ifc.ifc_req = realloc(ifc.ifc_req, ifc.ifc_len))) {
			fprintf(stderr, "Out of memory.\n");
			return NULL;
		}
		if (ioctl(sockfd, SIOCGIFCONF, &ifc)) {
			perror("ioctl SIOCFIFCONF");
			free(ifc.ifc_req);
			return NULL;
		}
	} while (buf_size <= (size_t) ifc.ifc_len);

	num_ifaces = ifc.ifc_len / sizeof(struct ifreq);
	/* Since we allocated at least one more than necessary,
	 * this serves as a stop marker for the iteration in
	 * have_ip() */
	ifc.ifc_req[num_ifaces].ifr_name[0] = 0;
	for (ifr = ifc.ifc_req; ifr->ifr_name[0] != 0; ifr++) {
		/* we only want to look up the presence or absence of a certain address
		 * here. but we want to skip "down" interfaces.  if an interface is down,
		 * we store an invalid sa_family, so the lookup will skip it.
		 */
		struct ifreq ifr_for_flags = *ifr;	/* get a copy to work with */
		if (ioctl(sockfd, SIOCGIFFLAGS, &ifr_for_flags) < 0) {
			perror("ioctl SIOCGIFFLAGS");
			ifr->ifr_addr.sa_family = -1;	/* what's wrong here? anyways: skip */
			continue;
		}
		if (!(ifr_for_flags.ifr_flags & IFF_UP)) {
			ifr->ifr_addr.sa_family = -1;	/* is not up: skip */
			continue;
		}
	}
	close(sockfd);
	return ifc.ifc_req;
}

int have_ip_ipv4(const char *ip)
{
	struct ifreq *ifr;
	struct in_addr query_addr;

	query_addr.s_addr = inet_addr(ip);

	if (!ifreq_list)
		ifreq_list = get_ifreq();

	for (ifr = ifreq_list; ifr && ifr->ifr_name[0] != 0; ifr++) {
		/* SIOCGIFCONF only supports AF_INET */
		struct sockaddr_in *list_addr =
		    (struct sockaddr_in *)&ifr->ifr_addr;
		if (ifr->ifr_addr.sa_family != AF_INET)
			continue;
		if (query_addr.s_addr == list_addr->sin_addr.s_addr)
			return 1;
	}
	return 0;
}

int have_ip_ipv6(const char *ip)
{
	FILE *if_inet6;
	struct in6_addr addr6, query_addr;
	unsigned int b[4];
	char tmp_ip[INET6_ADDRSTRLEN+1];
	char name[20]; /* IFNAMSIZ aka IF_NAMESIZE is 16 */
	int i;

	/* don't want to do getaddrinfo lookup, but inet_pton get's confused by
	 * %eth0 link local scope specifiers. So we have a temporary copy
	 * without that part. */
	for (i=0; ip[i] && ip[i] != '%' && i < INET6_ADDRSTRLEN; i++)
		tmp_ip[i] = ip[i];
	tmp_ip[i] = 0;

	if (inet_pton(AF_INET6, tmp_ip, &query_addr) <= 0)
		return 0;

#define PROC_IF_INET6 "/proc/net/if_inet6"
	if_inet6 = fopen(PROC_IF_INET6, "r");
	if (!if_inet6) {
		if (errno != ENOENT)
			perror("open of " PROC_IF_INET6 " failed:");
#undef PROC_IF_INET6
		return 0;
	}

	while (fscanf
	       (if_inet6,
		X32(08) X32(08) X32(08) X32(08) " %*02x %*02x %*02x %*02x %s",
		b, b + 1, b + 2, b + 3, name) > 0) {
		for (i = 0; i < 4; i++)
			addr6.s6_addr32[i] = cpu_to_be32(b[i]);

		if (memcmp(&query_addr, &addr6, sizeof(struct in6_addr)) == 0) {
			fclose(if_inet6);
			return 1;
		}
	}
	fclose(if_inet6);
	return 0;
}

int have_ip(const char *af, const char *ip)
{
	if (!strcmp(af, "ipv4"))
		return have_ip_ipv4(ip);
	else if (!strcmp(af, "ipv6"))
		return have_ip_ipv6(ip);

	return 1;		/* SCI */
}

void verify_ips(struct d_resource *res)
{
	if (global_options.disable_ip_verification)
		return;
	if (dry_run == 1 || do_verify_ips == 0)
		return;
	if (res->ignore)
		return;
	if (res->stacked && !is_drbd_top)
		return;

	if (!have_ip(res->me->address_family, res->me->address)) {
		ENTRY e, *ep;
		e.key = e.data = ep = NULL;
		m_asprintf(&e.key, "%s:%s", res->me->address, res->me->port);
		hsearch_r(e, FIND, &ep, &global_htable);
		fprintf(stderr, "%s: in resource %s, on %s:\n\t"
			"IP %s not found on this host.\n",
			ep ? (char *)ep->data : res->config_file,
			res->name, names_to_str(res->me->on_hosts),
			res->me->address);
		if (INVALID_IP_IS_INVALID_CONF)
			config_valid = 0;
	}
}

static char *conf_file[] = {
	DRBD_CONFIG_DIR "/drbd-84.conf",
	DRBD_CONFIG_DIR "/drbd-83.conf",
	DRBD_CONFIG_DIR "/drbd-82.conf",
	DRBD_CONFIG_DIR "/drbd-08.conf",
	DRBD_CONFIG_DIR "/drbd.conf",
	0
};

int sanity_check_abs_cmd(char *cmd_name)
{
	struct stat sb;

	if (stat(cmd_name, &sb)) {
		/* If stat fails, just ignore this sanity check,
		 * we are still iterating over $PATH probably. */
		return 0;
	}

	if (!(sb.st_mode & S_ISUID) || sb.st_mode & S_IXOTH || sb.st_gid == 0) {
		static int did_header = 0;
		if (!did_header)
			fprintf(stderr,
				"WARN:\n"
				"  You are using the 'drbd-peer-outdater' as fence-peer program.\n"
				"  If you use that mechanism the dopd heartbeat plugin program needs\n"
				"  to be able to call drbdsetup and drbdmeta with root privileges.\n\n"
				"  You need to fix this with these commands:\n");
		did_header = 1;
		fprintf(stderr,
			"  chgrp haclient %s\n"
			"  chmod o-x %s\n"
			"  chmod u+s %s\n\n", cmd_name, cmd_name, cmd_name);
	}
	return 1;
}

void sanity_check_cmd(char *cmd_name)
{
	char *path, *pp, *c;
	char abs_path[100];

	if (strchr(cmd_name, '/')) {
		sanity_check_abs_cmd(cmd_name);
	} else {
		path = pp = c = strdup(getenv("PATH"));

		while (1) {
			c = strchr(pp, ':');
			if (c)
				*c = 0;
			snprintf(abs_path, 100, "%s/%s", pp, cmd_name);
			if (sanity_check_abs_cmd(abs_path))
				break;
			if (!c)
				break;
			c++;
			if (!*c)
				break;
			pp = c;
		}
		free(path);
	}
}

/* if the config file is not readable by haclient,
 * dopd cannot work.
 * NOTE: we assume that any gid != 0 will be the group dopd will run as,
 * typically haclient. */
void sanity_check_conf(char *c)
{
	struct stat sb;

	/* if we cannot stat the config file,
	 * we have other things to worry about. */
	if (stat(c, &sb))
		return;

	/* permissions are funny: if it is world readable,
	 * but not group readable, and it belongs to my group,
	 * I am denied access.
	 * For the file to be readable by dopd (hacluster:haclient),
	 * it is not enough to be world readable. */

	/* ok if world readable, and NOT group haclient (see NOTE above) */
	if (sb.st_mode & S_IROTH && sb.st_gid == 0)
		return;

	/* ok if group readable, and group haclient (see NOTE above) */
	if (sb.st_mode & S_IRGRP && sb.st_gid != 0)
		return;

	fprintf(stderr,
		"WARN:\n"
		"  You are using the 'drbd-peer-outdater' as fence-peer program.\n"
		"  If you use that mechanism the dopd heartbeat plugin program needs\n"
		"  to be able to read the drbd.config file.\n\n"
		"  You need to fix this with these commands:\n"
		"  chgrp haclient %s\n" "  chmod g+r %s\n\n", c, c);
}

void sanity_check_perm()
{
	static int checked = 0;
	if (checked)
		return;

	sanity_check_cmd(drbdsetup);
	sanity_check_cmd(drbdmeta);
	sanity_check_conf(config_file);
	checked = 1;
}

void validate_resource(struct d_resource *res)
{
	struct d_option *opt, *next;
	struct d_name *bpo;

	/* there may be more than one "resync-after" statement,
	 * see commit 89cd0585 */
	opt = res->disk_options;
	while ((opt = find_opt(opt, "resync-after"))) {
		next = opt->next;
		if (res_by_name(opt->value) == NULL) {
			fprintf(stderr,
				"%s:%d: in resource %s:\n\tresource '%s' mentioned in "
				"'resync-after' option is not known.\n",
				res->config_file, res->start_line, res->name,
				opt->value);
			/* Non-fatal if run from some script.
			 * When deleting resources, it is an easily made
			 * oversight to leave references to the deleted
			 * resources in resync-after statements.  Don't fail on
			 * every pacemaker-induced action, as it would
			 * ultimately lead to all nodes committing suicide. */
			if (no_tty)
				res->disk_options = del_opt(res->disk_options, opt);
			else
				config_valid = 0;
		}
		opt = next;
	}
	if (res->ignore)
		return;
	if (!res->me) {
		fprintf(stderr,
			"%s:%d: in resource %s:\n\tmissing section 'on %s { ... }'.\n",
			res->config_file, res->start_line, res->name,
			nodeinfo.nodename);
		config_valid = 0;
	}
	// need to verify that in the discard-node-nodename options only known
	// nodenames are mentioned.
	if ((opt = find_opt(res->net_options, "after-sb-0pri"))) {
		if (!strncmp(opt->value, "discard-node-", 13)) {
			if (res->peer &&
			    !name_in_names(opt->value + 13, res->peer->on_hosts)
			    && !name_in_names(opt->value + 13,
					      res->me->on_hosts)) {
				fprintf(stderr,
					"%s:%d: in resource %s:\n\t"
					"the nodename in the '%s' option is "
					"not known.\n\t"
					"valid nodenames are: '%s %s'.\n",
					res->config_file, res->start_line,
					res->name, opt->value,
					names_to_str(res->me->on_hosts),
					names_to_str(res->peer->on_hosts));
				config_valid = 0;
			}
		}
	}

	if ((opt = find_opt(res->handlers, "fence-peer"))) {
		if (strstr(opt->value, "drbd-peer-outdater"))
			sanity_check_perm();
	}

	opt = find_opt(res->net_options, "allow-two-primaries");
	if (name_in_names("both", res->become_primary_on) && opt == NULL) {
		fprintf(stderr,
			"%s:%d: in resource %s:\n"
			"become-primary-on is set to both, but allow-two-primaries "
			"is not set.\n", res->config_file, res->start_line,
			res->name);
		config_valid = 0;
	}

	if (!res->peer)
		set_peer_in_resource(res, 0);

	if (res->peer
	    && ((res->me->proxy == NULL) != (res->peer->proxy == NULL))) {
		fprintf(stderr,
			"%s:%d: in resource %s:\n\t"
			"Either both 'on' sections must contain a proxy subsection, or none.\n",
			res->config_file, res->start_line, res->name);
		config_valid = 0;
	}

	for (bpo = res->become_primary_on; bpo; bpo = bpo->next) {
		if (res->peer &&
		    !name_in_names(bpo->name, res->me->on_hosts) &&
		    !name_in_names(bpo->name, res->peer->on_hosts) &&
		    strcmp(bpo->name, "both")) {
			fprintf(stderr,
				"%s:%d: in resource %s:\n\t"
				"become-primary-on contains '%s', which is not named with the 'on' sections.\n",
				res->config_file, res->start_line, res->name,
				bpo->name);
			config_valid = 0;
		}
	}
}

static void global_validate_maybe_expand_die_if_invalid(int expand)
{
	struct d_resource *res, *tmp;
	for_each_resource(res, tmp, config) {
		validate_resource(res);
		if (!config_valid)
			exit(E_config_invalid);
		if (expand) {
			convert_after_option(res);
			convert_discard_opt(res);
		}
		if (!config_valid)
			exit(E_config_invalid);
	}
}

/*
 * returns a pointer to an malloced area that contains
 * an absolute, canonical, version of path.
 * aborts if any allocation or syscall fails.
 * return value should be free()d, once no longer needed.
 */
char *canonify_path(char *path)
{
	int cwd_fd = -1;
	char *last_slash;
	char *tmp;
	char *that_wd;
	char *abs_path;

	if (!path || !path[0]) {
		fprintf(stderr, "cannot canonify an empty path\n");
		exit(E_usage);
	}

	tmp = strdupa(path);
	last_slash = strrchr(tmp, '/');

	if (last_slash) {
		*last_slash++ = '\0';
		cwd_fd = open(".", O_RDONLY);
		if (cwd_fd < 0) {
			fprintf(stderr, "open(\".\") failed: %m\n");
			exit(E_usage);
		}
		if (chdir(tmp)) {
			fprintf(stderr, "chdir(\"%s\") failed: %m\n", tmp);
			exit(E_usage);
		}
	} else {
		last_slash = tmp;
	}

	that_wd = getcwd(NULL, 0);
	if (!that_wd) {
		fprintf(stderr, "getcwd() failed: %m\n");
		exit(E_usage);
	}

	if (!strcmp("/", that_wd))
		m_asprintf(&abs_path, "/%s", last_slash);
	else
		m_asprintf(&abs_path, "%s/%s", that_wd, last_slash);

	free(that_wd);
	if (cwd_fd >= 0) {
		if (fchdir(cwd_fd) < 0) {
			fprintf(stderr, "fchdir() failed: %m\n");
			exit(E_usage);
		}
	}

	return abs_path;
}

void assign_command_names_from_argv0(char **argv)
{
	/* in case drbdadm is called with an absolute or relative pathname
	 * look for the drbdsetup binary in the same location,
	 * otherwise, just let execvp sort it out... */
	if ((progname = strrchr(argv[0], '/')) == 0) {
		progname = argv[0];
		drbdsetup = strdup("drbdsetup");
		drbdmeta = strdup("drbdmeta");
		drbd_proxy_ctl = strdup("drbd-proxy-ctl");
		drbdadm_83 = strdup("_drbdadm_83");
	} else {
		struct cmd_helper {
			char *name;
			char **var;
		};
		struct cmd_helper helpers[] = {
			{"drbdsetup", &drbdsetup},
			{"drbdmeta", &drbdmeta},
			{"drbd-proxy-ctl", &drbd_proxy_ctl},
			{"_drbdadm_83", &drbdadm_83},
			{NULL, NULL}
		};
		size_t len_dir, l;
		struct cmd_helper *c;

		++progname;
		len_dir = progname - argv[0];

		for (c = helpers; c->name; ++c) {
			l = len_dir + strlen(c->name) + 1;
			*(c->var) = malloc(l);
			if (*(c->var)) {
				strncpy(*(c->var), argv[0], len_dir);
				strcpy(*(c->var) + len_dir, c->name);
			}
		}

		/* for pretty printing, truncate to basename */
		argv[0] = progname;
	}
}

static void recognize_all_drbdsetup_options(void)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		const struct adm_cmd *cmd = &cmds[i];
		const struct field_def *field;

		if (!cmd->drbdsetup_ctx)
			continue;

		for (field = cmd->drbdsetup_ctx->fields; field->name; field++) {
			struct option opt;
			int n;

			field_to_option(field, &opt);
			for (n = 0; admopt[n].name; n++) {
				if (!strcmp(admopt[n].name, field->name)) {
					if (admopt[n].val == 257)
						assert (admopt[n].has_arg == opt.has_arg);
					else
						goto skip;
				}
			}

			if (admopt == general_admopt) {
				admopt = malloc((n + 2) * sizeof(*admopt));
				memcpy(admopt, general_admopt, (n + 1) * sizeof(*admopt));
			} else
				admopt = realloc(admopt, (n + 2) * sizeof(*admopt));
			memcpy(&admopt[n+1], &admopt[n], sizeof(*admopt));
			admopt[n] = opt;

		    skip:
			/* dummy statement required because of label */ ;
		}
	}
}

struct adm_cmd *find_cmd(char *cmdname);

int parse_options(int argc, char **argv, struct adm_cmd **cmd, char ***resource_names)
{
	char *optstring;
	int longindex, first_non_cmd_arg = 1;
	int i;

	optstring = alloca(strlen(make_optstring(admopt) + 2));
	optstring[0] = '-';
	strcpy(optstring + 1, make_optstring(admopt));

	*cmd = NULL;
	*resource_names = malloc(sizeof(char *));
	(*resource_names)[0] = NULL;

	opterr = 1;
	optind = 0;
	while (1) {
		int c;

		c = getopt_long(argc, argv, optstring, admopt, &longindex);
		if (c == -1)
			break;
		switch (c) {
		case 1:  /* non-option argument */
			if (*cmd) {
				int n;
				for (n = 0; (*resource_names)[n]; n++)
					/* do nothing */ ;
				*resource_names = realloc(*resource_names,
							  (n + 2) * sizeof(char *));
				(*resource_names)[n++] = optarg;
				(*resource_names)[n] = NULL;
			} else if (!strcmp(optarg, "help"))
				help = true;
			else {
				*cmd = find_cmd(optarg);
				if (!*cmd) {
					add_setup_option(true, optarg);
					if (first_non_cmd_arg == 1)
						first_non_cmd_arg = optind - 1;
				}
			}
			break;
		case 257:  /* drbdsetup option */
			{
				struct option *option = &admopt[longindex];
				char *opt;
				int len;

				len = strlen(option->name) + 2;
				if (optarg)
					len += 1 + strlen(optarg);
				opt = malloc(len + 1);
				if (optarg)
					sprintf(opt, "--%s=%s", option->name, optarg);
				else
					sprintf(opt, "--%s", option->name);
				add_setup_option(false, opt);
			}
			break;
		case 'S':
			is_drbd_top = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'd':
			dry_run++;
			break;
		case 'c':
			if (!strcmp(optarg, "-")) {
				yyin = stdin;
				if (asprintf(&config_file, "STDIN") < 0) {
					fprintf(stderr,
						"asprintf(config_file): %m\n");
					return 20;
				}
				config_from_stdin = 1;
			} else {
				yyin = fopen(optarg, "r");
				if (!yyin) {
					fprintf(stderr, "Can not open '%s'.\n.",
						optarg);
					exit(E_exec_error);
				}
				if (asprintf(&config_file, "%s", optarg) < 0) {
					fprintf(stderr,
						"asprintf(config_file): %m\n");
					return 20;
				}
			}
			break;
		case 't':
			config_test = optarg;
			break;
		case 's':
			{
				char *pathes[2];
				pathes[0] = optarg;
				pathes[1] = 0;
				find_drbdcmd(&drbdsetup, pathes);
			}
			break;
		case 'm':
			{
				char *pathes[2];
				pathes[0] = optarg;
				pathes[1] = 0;
				find_drbdcmd(&drbdmeta, pathes);
			}
			break;
		case 'p':
			{
				char *pathes[2];
				pathes[0] = optarg;
				pathes[1] = 0;
				find_drbdcmd(&drbd_proxy_ctl, pathes);
			}
			break;
		case 'n':
			{
				char *c;
				int shell_var_name_ok = 1;
				for (c = optarg; *c && shell_var_name_ok; c++) {
					switch (*c) {
					case 'a'...'z':
					case 'A'...'Z':
					case '0'...'9':
					case '_':
						break;
					default:
						shell_var_name_ok = 0;
					}
				}
				if (shell_var_name_ok)
					sh_varname = optarg;
				else
					fprintf(stderr,
						"ignored --sh-varname=%s: "
						"contains suspect characters, allowed set is [a-zA-Z0-9_]\n",
						optarg);
			}
			break;
		case 'y':
			force = 1;
			break;
		case 'V':
			printf("DRBDADM_BUILDTAG=%s\n", shell_escape(drbd_buildtag()));
			printf("DRBDADM_API_VERSION=%u\n", API_VERSION);
			printf("DRBD_KERNEL_VERSION_CODE=0x%06x\n", version_code_kernel());
			printf("DRBDADM_VERSION_CODE=0x%06x\n", version_code_userland());
			printf("DRBDADM_VERSION=%s\n", shell_escape(REL_VERSION));
			exit(0);
			break;
		case 'P':
			connect_to_host = optarg;
			break;
		case 'W':
			add_setup_option(true, optarg);
			break;
		case 'h':
			help = true;
			break;
		case '?':
			goto help;
		}
	}

	if (help)
		print_usage_and_exit(*cmd, 0);

	if (*cmd == NULL) {
		fprintf(stderr, "Unknown command '%s'.\n", argv[first_non_cmd_arg]);
		return E_usage;
	}

	if (setup_options) {
		/*
		 * The drbdsetup options are command specific.  Make sure that only
		 * setup options that this command recognizes are used.
		 */
		for (i = 0; setup_options[i].option; i++) {
			const struct field_def *field;

			if (setup_options[i].explicit)
				continue;

			field = NULL;
			if ((*cmd)->drbdsetup_ctx) {
				for (field = (*cmd)->drbdsetup_ctx->fields; field->name; field++) {
					if (setup_options[i].option[0] == '-' &&
					    setup_options[i].option[1] == '-' &&
					    !strcmp(setup_options[i].option + 2, field->name))
						break;
				}
				if (!field->name)
					field = NULL;
			}

			if (!field) {
				char *equals;

				equals = strchr(setup_options[i].option, '=');
				if (equals)
					*equals = 0;

				fprintf(stderr, "%s: unrecognized option '%s'\n",
					progname,
					setup_options[i].option);
				goto help;
			}
		}
	}

	return 0;

help:
	if (*cmd)
		fprintf(stderr, "try '%s help %s'\n", progname, (*cmd)->name);
	else
		fprintf(stderr, "try '%s help'\n", progname);
	return E_usage;
}

static void substitute_deprecated_cmd(char **c, char *deprecated,
				      char *substitution)
{
	if (!strcmp(*c, deprecated)) {
		fprintf(stderr, "'%s %s' is deprecated, use '%s %s' instead.\n",
			progname, deprecated, progname, substitution);
		*c = substitution;
	}
}

struct adm_cmd *find_cmd(char *cmdname)
{
	struct adm_cmd *cmd = NULL;
	unsigned int i;
	if (!strcmp("hidden-commands", cmdname)) {
		// before parsing the configuration file...
		hidden_cmds(NULL);
		exit(0);
	}

	/* R_PRIMARY / R_SECONDARY is not a state, but a role.  Whatever that
	 * means, actually.  But anyways, we decided to start using _role_ as
	 * the terminus of choice, and deprecate "state". */
	substitute_deprecated_cmd(&cmdname, "state", "role");

	/* "outdate-peer" got renamed to fence-peer,
	 * it is not required to actually outdate the peer,
	 * depending on situation it may be sufficient to power-reset it
	 * or do some other fencing action, or even call out to "meatware".
	 * The name of the handler should not imply something that is not done. */
	substitute_deprecated_cmd(&cmdname, "outdate-peer", "fence-peer");

	for (i = 0; i < ARRAY_SIZE(cmds); i++) {
		if (!strcmp(cmds[i].name, cmdname)) {
			cmd = cmds + i;
			break;
		}
	}
	return cmd;
}

char *config_file_from_arg(char *arg)
{
	char *f;
	int minor = minor_by_id(arg);

	if (minor >= 0) {
		f = lookup_minor(minor);
		if (!f) {
			fprintf(stderr, "Don't know which config file belongs "
					"to minor %d, trying default ones...\n",
				minor);
			return NULL;
		}
	} else {
		f = lookup_resource(arg);
		if (!f) {
			fprintf(stderr, "Don't know which config file belongs "
					"to resource %s, trying default "
					"ones...\n",
				arg);
			return NULL;
		}
	}

	yyin = fopen(f, "r");
	if (yyin == NULL) {
		fprintf(stderr,
			"Couldn't open file %s for reading, reason: %m\n"
			"trying default config file...\n", config_file);
		return NULL;
	}
	return f;
}

void assign_default_config_file(void)
{
	int i;
	for (i = 0; conf_file[i]; i++) {
		yyin = fopen(conf_file[i], "r");
		if (yyin) {
			config_file = conf_file[i];
			break;
		}
	}
	if (!config_file) {
		fprintf(stderr, "Can not open '%s': %m\n", conf_file[i - 1]);
		exit(E_config_invalid);
	}
}

void count_resources_or_die(void)
{
	int m, mc = global_options.minor_count;
	struct d_resource *res, *tmp;
	struct d_volume *vol;

	highest_minor = 0;
	for_each_resource(res, tmp, config) {
		if (res->ignore) {
			nr_resources[IGNORED]++;
			/* How can we count ignored volumes?
			 * Do we want to? */
			continue;
		} else if (res->stacked)
			nr_resources[STACKED]++;
		else
			nr_resources[NORMAL]++;

		for_each_volume(vol, res->me->volumes) {
			m = vol->device_minor;
			if (m > highest_minor)
				highest_minor = m;
			if (res->stacked)
				nr_volumes[STACKED]++;
			/* res->ignored won't come here */
			else
				nr_volumes[NORMAL]++;
		}
	}

	// Just for the case that minor_of_res() returned 0 for all devices.
	if (nr_volumes[NORMAL]+nr_volumes[STACKED] > (highest_minor + 1))
		highest_minor = nr_volumes[NORMAL] + nr_volumes[STACKED] -1;

	if (mc && mc < (highest_minor + 1)) {
		fprintf(stderr,
			"The highest minor you have in your config is %d"
			"but a minor_count of %d in your config!\n",
			highest_minor, mc);
		exit(E_usage);
	}
}

void die_if_no_resources(void)
{
	if (!is_drbd_top && nr_resources[IGNORED] > 0 && nr_resources[NORMAL] == 0) {
		fprintf(stderr,
			"WARN: no normal resources defined for this host (%s)!?\n"
			"Misspelled name of the local machine with the 'on' keyword ?\n",
			nodeinfo.nodename);
		exit(E_usage);
	}
	if (!is_drbd_top && nr_resources[NORMAL] == 0) {
		fprintf(stderr,
			"WARN: no normal resources defined for this host (%s)!?\n",
			nodeinfo.nodename);
		exit(E_usage);
	}
	if (is_drbd_top && nr_resources[STACKED] == 0) {
		fprintf(stderr, "WARN: nothing stacked for this host (%s), "
			"nothing to do in stacked mode!\n", nodeinfo.nodename);
		exit(E_usage);
	}
}

void print_dump_xml_header(void)
{
	printf("<config file=\"%s\">\n", config_save);
	++indent;
	dump_global_info_xml();
	dump_common_info_xml();
}

void print_dump_header(void)
{
	printf("# %s\n", config_save);
	dump_global_info();
	dump_common_info();
}

int main(int argc, char **argv)
{
	size_t i;
	int rv = 0;
	struct adm_cmd *cmd = NULL;
	char **resource_names = NULL;
	struct d_resource *res, *tmp;
	char *env_drbd_nodename = NULL;
	int is_dump_xml;
	int is_dump;
	struct cfg_ctx ctx = { .arg = NULL };

	yyin = NULL;
	uname(&nodeinfo);	/* FIXME maybe fold to lower case ? */
	no_tty = (!isatty(fileno(stdin)) || !isatty(fileno(stdout)));

	env_drbd_nodename = getenv("__DRBD_NODE__");
	if (env_drbd_nodename && *env_drbd_nodename) {
		strncpy(nodeinfo.nodename, env_drbd_nodename,
			sizeof(nodeinfo.nodename) - 1);
		nodeinfo.nodename[sizeof(nodeinfo.nodename) - 1] = 0;
		fprintf(stderr, "\n"
			"   found __DRBD_NODE__ in environment\n"
			"   PRETENDING that I am >>%s<<\n\n",
			nodeinfo.nodename);
	}

	assign_command_names_from_argv0(argv);

	if (argc == 1)
		print_usage_and_exit(NULL, "missing arguments");	// arguments missing.

	if (drbdsetup == NULL || drbdmeta == NULL || drbd_proxy_ctl == NULL) {
		fprintf(stderr, "could not strdup argv[0].\n");
		exit(E_exec_error);
	}

	if (!getenv("DRBD_DONT_WARN_ON_VERSION_MISMATCH"))
		warn_on_version_mismatch();

	maybe_exec_drbdadm_83(argv);

	recognize_all_drbdsetup_options();
	rv = parse_options(argc, argv, &cmd, &resource_names);
	if (rv)
		return rv;

	if (config_test && !cmd->test_config) {
		fprintf(stderr, "The --config-to-test (-t) option is only allowed "
			"with the dump and sh-nop commands\n");
		exit(E_usage);
	}

	do_verify_ips = cmd->verify_ips;

	is_dump_xml = (cmd->function == adm_dump_xml);
	is_dump = (is_dump_xml || cmd->function == adm_dump);

	if (!resource_names[0]) {
		if (is_dump)
			all_resources = 1;
		else if (cmd->res_name_required)
			print_usage_and_exit(cmd, "missing resourcename arguments");
	} else if (resource_names[0] && resource_names[1]) {
		if (!cmd->res_name_required)
			fprintf(stderr,
				"this command will ignore resource names!\n");
		else if (cmd->use_cached_config_file)
			fprintf(stderr,
				"You should not use this command with multiple resources!\n");
	}

	if (!config_file && cmd->use_cached_config_file)
		config_file = config_file_from_arg(resource_names[0]);

	if (!config_file)
		/* may exit if no config file can be used! */
		assign_default_config_file();

	/* for error-reporting reasons config_file may be re-assigned by adm_adjust,
	 * we need the current value for register_minor, though.
	 * save that. */
	if (config_from_stdin)
		config_save = config_file;
	else
		config_save = canonify_path(config_file);

	my_parse();

	if (config_test) {
		char *saved_config_file = config_file;
		char *saved_config_save = config_save;

		config_file = config_test;
		config_save = canonify_path(config_test);

		fclose(yyin);
		yyin = fopen(config_test, "r");
		if (!yyin) {
			fprintf(stderr, "Can not open '%s'.\n.", config_test);
			exit(E_exec_error);
		}
		my_parse();

		config_file = saved_config_file;
		config_save = saved_config_save;
	}

	if (!config_valid)
		exit(E_config_invalid);

	post_parse(config, cmd->is_proxy_cmd ? match_on_proxy : 0);

	if (!is_dump || dry_run || verbose)
		expand_common();
	if (dry_run || config_from_stdin)
		do_register = 0;

	count_resources_or_die();

	if (cmd->uc_dialog)
		uc_node(global_options.usage_count);

	ctx.arg = cmd->name;
	if (cmd->res_name_required) {
		if (config == NULL) {
			fprintf(stderr, "no resources defined!\n");
			exit(E_usage);
		}

		global_validate_maybe_expand_die_if_invalid(!is_dump);

		if (!resource_names[0] || !strcmp(resource_names[0], "all")) {
			/* either no resource arguments at all,
			 * but command is dump / dump-xml, so implicit "all",
			 * or an explicit "all" argument is given */
			all_resources = 1;
			if (!is_dump || !force)
				die_if_no_resources();
			/* verify ips first, for all of them */
			for_each_resource(res, tmp, config) {
				verify_ips(res);
			}
			if (!config_valid)
				exit(E_config_invalid);

			if (is_dump_xml)
				print_dump_xml_header();
			else if (is_dump)
				print_dump_header();

			for_each_resource(res, tmp, config) {
				if (!is_dump && res->ignore)
					continue;

				if (!is_dump && is_drbd_top != res->stacked)
					continue;
				ctx.res = res;
				ctx.vol = NULL;
				int r = call_cmd(cmd, &ctx, EXIT_ON_FAIL);	/* does exit for r >= 20! */
				/* this super positioning of return values is soo ugly
				 * anyone any better idea? */
				if (r > rv)
					rv = r;
			}
			if (is_dump_xml) {
				--indent;
				printf("</config>\n");
			}
		} else {
			/* explicit list of resources to work on */
			for (i = 0; resource_names[i]; i++) {
				ctx.res = NULL;
				ctx.vol = NULL;
				ctx_by_name(&ctx, resource_names[i]);
				if (!ctx.res)
					ctx_by_minor(&ctx, resource_names[i]);
				if (!ctx.res) {
					fprintf(stderr,
						"'%s' not defined in your config.\n",
						resource_names[i]);
					exit(E_usage);
				}
				if (!cmd->vol_id_required && !cmd->iterate_volumes && ctx.vol != NULL) {
					if (ctx.vol->implicit)
						ctx.vol = NULL;
					else {
						fprintf(stderr, "%s operates on whole resources, but you specified a specific volume!\n",
								cmd->name);
						exit(E_usage);
					}
				}
				if (cmd->vol_id_required && !ctx.vol && ctx.res->me->volumes->implicit)
					ctx.vol = ctx.res->me->volumes;
				if (cmd->vol_id_required && !ctx.vol) {
					fprintf(stderr, "%s requires a specific volume id, but none is specified.\n"
							"Try '%s minor-<minor_number>' or '%s %s/<vnr>'\n",
							cmd->name, cmd->name,
							cmd->name, resource_names[i]);
					exit(E_usage);
				}
				if (ctx.res->ignore && !is_dump) {
					fprintf(stderr,
						"'%s' ignored, since this host (%s) is not mentioned with an 'on' keyword.\n",
						ctx.res->name, nodeinfo.nodename);
					rv = E_usage;
					continue;
				}
				if (is_drbd_top != ctx.res->stacked && !is_dump) {
					fprintf(stderr,
						"'%s' is a %s resource, and not available in %s mode.\n",
						ctx.res->name,
						ctx.res->stacked ? "stacked" : "normal",
						is_drbd_top ? "stacked" :
						"normal");
					rv = E_usage;
					continue;
				}
				verify_ips(ctx.res);
				if (!is_dump && !config_valid)
					exit(E_config_invalid);
				rv = call_cmd(cmd, &ctx, EXIT_ON_FAIL);	/* does exit for rv >= 20! */
			}
		}
	} else {		// Commands which do not need a resource name
		/* no call_cmd, as that implies register_minor,
		 * which does not make sense for resource independent commands.
		 * It does also not need to iterate over volumes: it does not even know the resource. */
		rv = cmd->function(&ctx);
		if (rv >= 10) {	/* why do we special case the "generic sh-*" commands? */
			fprintf(stderr, "command %s exited with code %d\n",
				cmd->name, rv);
			exit(rv);
		}
	}

	/* do we really have to bitor the exit code?
	 * it is even only a Boolean value in this case! */
	rv |= run_deferred_cmds();

	free_config(config);
	free(resource_names);
	if (admopt != general_admopt)
		free(admopt);

	return rv;
}

void yyerror(char *text)
{
	fprintf(stderr, "%s:%d: %s\n", config_file, line, text);
	exit(E_syntax);
}
