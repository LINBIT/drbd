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
#include "drbdadm_dump.h"

#define MAX_ARGS 40

char *progname;

struct deferred_cmd {
	struct adm_cmd *cmd;
	struct cfg_ctx ctx;
	STAILQ_ENTRY(deferred_cmd) link;
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

static int adm_new_minor(struct cfg_ctx *ctx);
static int adm_resource(struct cfg_ctx *);
static int adm_attach(struct cfg_ctx *);
static int adm_connect(struct cfg_ctx *);
static int adm_disconnect(struct cfg_ctx *);
static int adm_resize(struct cfg_ctx *);
static int adm_generic_l(struct cfg_ctx *);
static int adm_up(struct cfg_ctx *);
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
static int adm_generic_s(struct cfg_ctx *);

int ctx_by_name(struct cfg_ctx *ctx, const char *id);

static char *get_opt_val(struct options *, const char *, char *);

static struct ifreq *get_ifreq();

char ss_buffer[1024];
struct utsname nodeinfo;
int line = 1;
int fline;
struct d_globals global_options = { 0, 0, 0, 1, UC_ASK };

char *config_file = NULL;
char *config_save = NULL;
char *config_test = NULL;
struct resources config = STAILQ_HEAD_INITIALIZER(config);
struct d_resource *common = NULL;
struct ifreq *ifreq_list = NULL;
int is_drbd_top;
enum { NORMAL, STACKED, IGNORED, __N_RESOURCE_TYPES };
int nr_resources[__N_RESOURCE_TYPES];
int nr_volumes[__N_RESOURCE_TYPES];
int highest_minor;
int number_of_minors = 0;
int config_from_stdin = 0;
int config_valid = 1;
int no_tty;
int dry_run = 0;
int verbose = 0;
int adjust_with_progress = 0;
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

STAILQ_HEAD(deferred_cmds, deferred_cmd) deferred_cmds[__CFG_LAST];

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

int adm_adjust_wp(struct cfg_ctx *ctx)
{
	if (!verbose && !dry_run)
		adjust_with_progress = 1;
	return adm_adjust(ctx);
}

/* DRBD adm_cmd flags shortcuts,
 * to avoid merge conflicts and unreadable diffs
 * when we add the next flag */

#define ACF1_DEFAULT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF1_RESNAME			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.uc_dialog = 1,			\

#define ACF1_CONNECT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 0,		\
	.verify_ips = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define ACF1_DISCONNECT			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.need_peer = 1,			\
	.uc_dialog = 1,			\

#define ACF1_DEFNET			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 1,		\
	.uc_dialog = 1,			\

#define ACF1_PEER_DEVICE		\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.need_peer = 1,			\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF3_RES_HANDLER		\
	.show_in_usage = 3,		\
	.res_name_required = 1,		\
	.iterate_volumes = 0,		\
	.vol_id_required = 0,		\
	.verify_ips = 0,		\
	.use_cached_config_file = 1,	\

#define ACF4_ADVANCED			\
	.show_in_usage = 4,		\
	.res_name_required = 1,		\
	.iterate_volumes = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF4_ADVANCED_NEED_VOL		\
	.show_in_usage = 4,		\
	.res_name_required = 1,		\
	.iterate_volumes = 0,		\
	.vol_id_required = 1,		\
	.verify_ips = 0,		\
	.uc_dialog = 1,			\

#define ACF1_DUMP			\
	.show_in_usage = 1,		\
	.res_name_required = 1,		\
	.verify_ips = 1,		\
	.uc_dialog = 1,			\
	.test_config = 1,		\

#define ACF2_SHELL			\
	.show_in_usage = 2,		\
	.iterate_volumes = 1,		\
	.res_name_required = 1,		\
	.verify_ips = 0,		\

#define ACF2_SH_RESNAME			\
	.show_in_usage = 2,		\
	.iterate_volumes = 0,		\
	.res_name_required = 1,		\
	.verify_ips = 0,		\

#define ACF2_PROXY			\
	.show_in_usage = 2,		\
	.res_name_required = 1,		\
	.verify_ips = 0,		\
	.need_peer = 1,			\
	.is_proxy_cmd = 1,		\

#define ACF2_HOOK			\
	.show_in_usage = 2,		\
	.res_name_required = 1,		\
	.verify_ips = 0,                \
	.use_cached_config_file = 1,	\

#define ACF2_GEN_SHELL			\
	.show_in_usage = 2,		\
	.res_name_required = 0,		\
	.verify_ips = 0,		\

/*  */ struct adm_cmd attach_cmd = {"attach", adm_attach, &attach_cmd_ctx, ACF1_DEFAULT};
/*  */ struct adm_cmd disk_options_cmd = {"disk-options", adm_attach, &attach_cmd_ctx, ACF1_DEFAULT};
/*  */ struct adm_cmd detach_cmd = {"detach", adm_generic_l, &detach_cmd_ctx, ACF1_DEFAULT};
/*  */ struct adm_cmd connect_cmd = {"connect", adm_connect, &connect_cmd_ctx, ACF1_CONNECT};
/*  */ struct adm_cmd net_options_cmd = {"net-options", adm_connect, &net_options_ctx, ACF1_CONNECT};
/*  */ struct adm_cmd disconnect_cmd = {"disconnect", adm_disconnect, &disconnect_cmd_ctx, ACF1_DISCONNECT};
static struct adm_cmd up_cmd = {"up", adm_up, ACF1_RESNAME };
/*  */ struct adm_cmd res_options_cmd = {"resource-options", adm_resource, &resource_options_ctx, ACF1_RESNAME};
static struct adm_cmd down_cmd = {"down", adm_generic_l, ACF1_RESNAME};
static struct adm_cmd primary_cmd = {"primary", adm_generic_l, &primary_cmd_ctx, ACF1_RESNAME};
static struct adm_cmd secondary_cmd = {"secondary", adm_generic_l, ACF1_RESNAME};
static struct adm_cmd invalidate_cmd = {"invalidate", adm_generic_b, ACF1_PEER_DEVICE};
static struct adm_cmd invalidate_remote_cmd = {"invalidate-remote", adm_generic_l, ACF1_PEER_DEVICE};
static struct adm_cmd outdate_cmd = {"outdate", adm_outdate, ACF1_DEFAULT};
/*  */ struct adm_cmd resize_cmd = {"resize", adm_resize, ACF1_DEFNET};
static struct adm_cmd verify_cmd = {"verify", adm_generic_s, ACF1_PEER_DEVICE};
static struct adm_cmd pause_sync_cmd = {"pause-sync", adm_generic_s, ACF1_PEER_DEVICE};
static struct adm_cmd resume_sync_cmd = {"resume-sync", adm_generic_s, ACF1_PEER_DEVICE};
static struct adm_cmd adjust_cmd = {"adjust", adm_adjust, ACF1_RESNAME};
static struct adm_cmd adjust_wp_cmd = {"adjust-with-progress", adm_adjust_wp, ACF1_CONNECT};
static struct adm_cmd wait_c_cmd = {"wait-connect", adm_wait_c, ACF1_DEFNET};
static struct adm_cmd wait_ci_cmd = {"wait-con-int", adm_wait_ci, .show_in_usage = 1,.verify_ips = 1,};
static struct adm_cmd role_cmd = {"role", adm_generic_s, ACF1_DEFAULT};
static struct adm_cmd cstate_cmd = {"cstate", adm_generic_s, ACF1_DEFAULT};
static struct adm_cmd dstate_cmd = {"dstate", adm_generic_b, ACF1_DEFAULT};
static struct adm_cmd status_cmd = {"status", adm_generic_l, .show_in_usage = 1, .uc_dialog = 1};
static struct adm_cmd dump_cmd = {"dump", adm_dump, ACF1_DUMP};
static struct adm_cmd dump_xml_cmd = {"dump-xml", adm_dump_xml, ACF1_DUMP};

static struct adm_cmd create_md_cmd = {"create-md", adm_create_md, ACF1_DEFAULT};
static struct adm_cmd show_gi_cmd = {"show-gi", adm_generic_b, ACF1_PEER_DEVICE};
static struct adm_cmd get_gi_cmd = {"get-gi", adm_generic_b, ACF1_PEER_DEVICE};
static struct adm_cmd dump_md_cmd = {"dump-md", admm_generic, ACF1_DEFAULT};
static struct adm_cmd wipe_md_cmd = {"wipe-md", admm_generic, ACF1_DEFAULT};
static struct adm_cmd apply_al_cmd = {"apply-al", admm_generic, ACF1_DEFAULT};

static struct adm_cmd hidden_cmd = {"hidden-commands", hidden_cmds,.show_in_usage = 1,};

static struct adm_cmd sh_nop_cmd = {"sh-nop", sh_nop, ACF2_GEN_SHELL .uc_dialog = 1, .test_config = 1};
static struct adm_cmd sh_resources_cmd = {"sh-resources", sh_resources, ACF2_GEN_SHELL};
static struct adm_cmd sh_resource_cmd = {"sh-resource", sh_resource, ACF2_SH_RESNAME};
static struct adm_cmd sh_mod_parms_cmd = {"sh-mod-parms", sh_mod_parms, ACF2_GEN_SHELL};
static struct adm_cmd sh_dev_cmd = {"sh-dev", sh_dev, ACF2_SHELL};
static struct adm_cmd sh_udev_cmd = {"sh-udev", sh_udev, .vol_id_required = 1, ACF2_HOOK};
static struct adm_cmd sh_minor_cmd = {"sh-minor", sh_minor, ACF2_SHELL};
static struct adm_cmd sh_ll_dev_cmd = {"sh-ll-dev", sh_ll_dev, ACF2_SHELL};
static struct adm_cmd sh_md_dev_cmd = {"sh-md-dev", sh_md_dev, ACF2_SHELL};
static struct adm_cmd sh_md_idx_cmd = {"sh-md-idx", sh_md_idx, ACF2_SHELL};
static struct adm_cmd sh_ip_cmd = {"sh-ip", sh_ip, ACF2_SHELL};
static struct adm_cmd sh_lr_of_cmd = {"sh-lr-of", sh_lres, ACF2_SHELL};
static struct adm_cmd sh_b_pri_cmd = {"sh-b-pri", sh_b_pri, ACF2_SHELL};
static struct adm_cmd sh_status_cmd = {"sh-status", sh_status, ACF2_GEN_SHELL};

static struct adm_cmd proxy_up_cmd = {"proxy-up", adm_proxy_up, ACF2_PROXY};
static struct adm_cmd proxy_down_cmd = {"proxy-down", adm_proxy_down, ACF2_PROXY};

/*  */ struct adm_cmd new_resource_cmd = {"new-resource", adm_resource, ACF2_SH_RESNAME};
/*  */ struct adm_cmd new_minor_cmd = {"sh-new-minor", adm_new_minor, ACF4_ADVANCED};

static struct adm_cmd khelper01_cmd = {"before-resync-target", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper02_cmd = {"after-resync-target", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper03_cmd = {"before-resync-source", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper04_cmd = {"pri-on-incon-degr", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper05_cmd = {"pri-lost-after-sb", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper06_cmd = {"fence-peer", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper07_cmd = {"local-io-error", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper08_cmd = {"pri-lost", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper09_cmd = {"initial-split-brain", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper10_cmd = {"split-brain", adm_khelper, ACF3_RES_HANDLER};
static struct adm_cmd khelper11_cmd = {"out-of-sync", adm_khelper, ACF3_RES_HANDLER};

static struct adm_cmd suspend_io_cmd = {"suspend-io", adm_generic_s, ACF4_ADVANCED};
static struct adm_cmd resume_io_cmd = {"resume-io", adm_generic_s, ACF4_ADVANCED};
static struct adm_cmd set_gi_cmd = {"set-gi", admm_generic, .need_peer = 1, ACF4_ADVANCED_NEED_VOL};
static struct adm_cmd new_current_uuid_cmd = {"new-current-uuid", adm_generic_s, &new_current_uuid_cmd_ctx, ACF4_ADVANCED_NEED_VOL};
static struct adm_cmd check_resize_cmd = {"check-resize", adm_chk_resize, ACF4_ADVANCED};

struct adm_cmd *cmds[] = {
	/*  name, function, flags
	 *  sort order:
	 *  - normal config commands,
	 *  - normal meta data manipulation
	 *  - sh-*
	 *  - handler
	 *  - advanced
	 ***/
	&attach_cmd,
	&disk_options_cmd,
	&detach_cmd,
	&connect_cmd,
	&net_options_cmd,
	&disconnect_cmd,
	&up_cmd,
	&res_options_cmd,
	&down_cmd,
	&primary_cmd,
	&secondary_cmd,
	&invalidate_cmd,
	&invalidate_remote_cmd,
	&outdate_cmd,
	&resize_cmd,
	&verify_cmd,
	&pause_sync_cmd,
	&resume_sync_cmd,
	&adjust_cmd,
	&adjust_wp_cmd,
	&wait_c_cmd,
	&wait_ci_cmd,
	&role_cmd,
	&cstate_cmd,
	&dstate_cmd,
	&status_cmd,
	&dump_cmd,
	&dump_xml_cmd,

	&create_md_cmd,
	&show_gi_cmd,
	&get_gi_cmd,
	&dump_md_cmd,
	&wipe_md_cmd,
	&apply_al_cmd,

	&hidden_cmd,

	&sh_nop_cmd,
	&sh_resources_cmd,
	&sh_resource_cmd,
	&sh_mod_parms_cmd,
	&sh_dev_cmd,
	&sh_udev_cmd,
	&sh_minor_cmd,
	&sh_ll_dev_cmd,
	&sh_md_dev_cmd,
	&sh_md_idx_cmd,
	&sh_ip_cmd,
	&sh_lr_of_cmd,
	&sh_b_pri_cmd,
	&sh_status_cmd,

	&proxy_up_cmd,
	&proxy_down_cmd,

	&new_resource_cmd,
	&new_minor_cmd,

	&khelper01_cmd,
	&khelper02_cmd,
	&khelper03_cmd,
	&khelper04_cmd,
	&khelper05_cmd,
	&khelper06_cmd,
	&khelper07_cmd,
	&khelper08_cmd,
	&khelper09_cmd,
	&khelper10_cmd,
	&khelper11_cmd,

	&suspend_io_cmd,
	&resume_io_cmd,
	&set_gi_cmd,
	&new_current_uuid_cmd,
	&check_resize_cmd,
};

/* internal commands: */
/*  */ struct adm_cmd del_minor_cmd = {"del-minor", adm_generic_s, ACF1_DEFAULT};
/*  */ struct adm_cmd res_options_defaults_cmd = {
	"resource-options",
	adm_resource,
	&resource_options_ctx,
	ACF1_RESNAME
};
/*  */ struct adm_cmd disk_options_defaults_cmd = {
	"disk-options",
	adm_attach,
	&attach_cmd_ctx,
	ACF1_DEFAULT
};
/*  */ struct adm_cmd net_options_defaults_cmd = {
	"net-options",
	adm_connect,
	&net_options_ctx,
	ACF1_CONNECT
};
/*  */ struct adm_cmd proxy_conn_down_cmd = { "", do_proxy_conn_down, ACF1_DEFAULT};
/*  */ struct adm_cmd proxy_conn_up_cmd = { "", do_proxy_conn_up, ACF1_DEFAULT};
/*  */ struct adm_cmd proxy_conn_plugins_cmd = { "", do_proxy_conn_plugins, ACF1_DEFAULT};
static struct adm_cmd primary_s_cmd = {"primary", adm_generic_s, &primary_cmd_ctx, ACF1_RESNAME};

static void initialize_deferred_cmds()
{
	enum drbd_cfg_stage stage;
	for (stage = CFG_PREREQ; stage < __CFG_LAST; stage++)
		STAILQ_INIT(&deferred_cmds[stage]);
}

void schedule_deferred_cmd(struct adm_cmd *cmd,
			   struct cfg_ctx *ctx,
			   enum drbd_cfg_stage stage)
{
	struct deferred_cmd *d;

	d = calloc(1, sizeof(struct deferred_cmd));
	if (d == NULL) {
		perror("calloc");
		exit(E_EXEC_ERROR);
	}

	d->cmd = cmd;
	d->ctx = *ctx;

	STAILQ_INSERT_TAIL(&deferred_cmds[stage], d, link);
}

enum on_error { KEEP_RUNNING, EXIT_ON_FAIL };
int call_cmd_fn(struct adm_cmd *cmd, struct cfg_ctx *ctx, enum on_error on_error)
{
	struct cfg_ctx tmp_ctx = *ctx;
	int rv;

	tmp_ctx.cmd = cmd;
	rv = cmd->function(&tmp_ctx);
	if (rv >= 20) {
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
	struct connection *conn;
	bool iterate_vols, iterate_conns;
	int ret = 0;

	if (!res->peers_addrs_set && cmd->need_peer)
		set_peer_in_resource(res, cmd->need_peer);

	iterate_vols = ctx->vol ? 0 : cmd->iterate_volumes;
	iterate_conns = ctx->conn ? 0 : cmd->need_peer;

	if (iterate_vols && iterate_conns) {
		for_each_volume(vol, &res->me->volumes) {
			ctx->vol = vol;
			for_each_connection(conn, &res->connections) {
				if (conn->ignore)
					continue;
				ctx->conn = conn;
				ret = call_cmd_fn(cmd, ctx, on_error);
				if (ret)
					goto out;
			}
		}
	} else if (iterate_vols) {
		for_each_volume(vol, &res->me->volumes) {
			ctx->vol = vol;
			ret = call_cmd_fn(cmd, ctx, on_error);
			if (ret)
				break;
		}
	} else if (iterate_conns) {
		for_each_connection(conn, &res->connections) {
			if (conn->ignore)
				continue;
			ctx->conn = conn;
			ret = call_cmd_fn(cmd, ctx, on_error);
			if (ret)
				break;
		}
	} else {
		ret = call_cmd_fn(cmd, ctx, on_error);
	}
out:
	return ret;
}

static char *drbd_cfg_stage_string[] = {
	[CFG_PREREQ] = "create res",
	[CFG_RESOURCE] = "adjust res",
	[CFG_DISK_PREREQ] = "prepare disk",
	[CFG_DISK] = "adjust disk",
	[CFG_NET_PREREQ] = "prepare net",
	[CFG_NET] = "adjust net",
};

int _run_deferred_cmds(enum drbd_cfg_stage stage)
{
	struct d_resource *last_res = NULL;
	struct deferred_cmd *d = STAILQ_FIRST(&deferred_cmds[stage]);
	struct deferred_cmd *t;
	int r;
	int rv = 0;

	if (d && adjust_with_progress) {
		printf("\n%15s:", drbd_cfg_stage_string[stage]);
		fflush(stdout);
	}

	while (d) {
		if (d->ctx.res->skip_further_deferred_command) {
			if (adjust_with_progress) {
				if (d->ctx.res != last_res)
					printf(" [skipped:%s]", d->ctx.res->name);
			} else
				fprintf(stderr, "%s: %s %s: skipped due to earlier error\n",
					progname, d->cmd->name, d->ctx.res->name);
			r = 0;
		} else {
			if (adjust_with_progress) {
				if (d->ctx.res != last_res)
					printf(" %s", d->ctx.res->name);
			}
			r = call_cmd_fn(d->cmd, &d->ctx, KEEP_RUNNING);
			if (r) {
				/* If something in the "prerequisite" stages failed,
				 * there is no point in trying to continue.
				 * However if we just failed to adjust some
				 * options, or failed to attach, we still want
				 * to adjust other options, or try to connect.
				 */
				if (stage == CFG_PREREQ || stage == CFG_DISK_PREREQ)
					d->ctx.res->skip_further_deferred_command = 1;
				if (adjust_with_progress)
					printf(":failed(%s:%u)", d->cmd->name, r);
			}
		}
		last_res = d->ctx.res;
		t = STAILQ_NEXT(d, link);
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
	int r;
	int ret = 0;
	if (adjust_with_progress)
		printf("[");
	for (stage = CFG_PREREQ; stage < __CFG_LAST; stage++) {
		r = _run_deferred_cmds(stage);
		if (r) {
			if (!adjust_with_progress)
				return 1; /* FIXME r? */
			ret = 1;
		}
	}
	if (adjust_with_progress)
		printf("\n]\n");
	return ret;
}

static int sh_nop(struct cfg_ctx *ctx)
{
	return 0;
}

static int sh_resources(struct cfg_ctx *ctx)
{
	struct d_resource *res;
	int first = 1;

	for_each_resource(res, &config) {
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
	printf("%s\n", ctx->res->me->address.addr);
	return 0;
}

static int sh_lres(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	if (!is_drbd_top) {
		fprintf(stderr,
			"sh-lower-resource only available in stacked mode\n");
		exit(E_USAGE);
	}
	if (!res->stacked) {
		fprintf(stderr, "'%s' is not stacked on this host (%s)\n",
			res->name, nodeinfo.nodename);
		exit(E_USAGE);
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

	if (name_in_names(nodeinfo.nodename, &res->become_primary_on) ||
	    name_in_names("both", &res->become_primary_on)) {
		/* upon connect resync starts, and both sides become primary at the same time.
		   One's try might be declined since an other state transition happens. Retry. */
		for (i = 0; i < 5; i++) {
			rv = call_cmd_fn(&primary_s_cmd, ctx, KEEP_RUNNING);
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
		mc = number_of_minors + 3;
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
	struct d_volume *vol, *n;

	if (!hi)
		return;

	free_names(&hi->on_hosts);
	vol = STAILQ_FIRST(&hi->volumes);
	while (vol) {
		n = STAILQ_NEXT(vol, link);
		free_volume(vol);
		vol = n;
	}
	free(hi->address.addr);
	free(hi->address.af);
	free(hi->address.port);
}

static void free_options(struct options *options)
{
	struct d_option *f, *option = STAILQ_FIRST(options);
	while (option) {
		free(option->name);
		free(option->value);
		f = option;
		option = STAILQ_NEXT(option, link);
		free(f);
	}
}

static void free_config()
{
	struct d_resource *f, *t;
	struct d_host_info *host;

	f = STAILQ_FIRST(&config);
	while (f) {
		free(f->name);
		for_each_host(host, &f->all_hosts)
			free_host_info(host);
		free_options(&f->net_options);
		free_options(&f->disk_options);
		free_options(&f->startup_options);
		free_options(&f->proxy_options);
		free_options(&f->handlers);
		t = STAILQ_NEXT(f, link);
		free(f);
		f = t;
	}
	if (common) {
		free_options(&common->net_options);
		free_options(&common->disk_options);
		free_options(&common->startup_options);
		free_options(&common->proxy_options);
		free_options(&common->handlers);
		free(common);
	}
	if (ifreq_list)
		free(ifreq_list);
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
	exit(E_EXEC_ERROR);
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

	if (adjust_with_progress && !(flags & RETURN_STDERR_FD))
		flags |= SUPRESS_STDERR;

	if (flags & (RETURN_STDOUT_FD | RETURN_STDERR_FD)) {
		if (pipe(pipe_fds) < 0) {
			perror("pipe");
			fprintf(stderr, "Error in pipe, giving up.\n");
			exit(E_EXEC_ERROR);
		}
	}

	pid = fork();
	if (pid == -1) {
		fprintf(stderr, "Can not fork\n");
		exit(E_EXEC_ERROR);
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
		exit(E_EXEC_ERROR);
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
			exit(E_THINKO);
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
				exit(E_EXEC_ERROR);
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
				exit(E_EXEC_ERROR);
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
       exit(E_THINKO); \
     } \
     (ARGC)++; \
  })

static void add_setup_options(char **argv, int *argcp)
{
	int argc = *argcp;
	int i;

	if (!setup_options)
		return;

	for (i = 0; setup_options[i].option; i++)
		argv[NA(argc)] = setup_options[i].option;
	*argcp = argc;
}

#define make_option(ARG, OPT) do {					\
	if(OPT->value)							\
		ARG = ssprintf("--%s=%s", OPT->name, OPT->value);	\
	else 								\
		ARG = ssprintf("--%s", OPT->name);			\
} while (0)

#define make_options(ARG, OPTIONS) do {					\
	struct d_option *option;					\
	STAILQ_FOREACH(option, OPTIONS, link) 				\
		make_option(ARG, option);				\
} while (0)

#define ssprintf_addr(A)					\
ssprintf(strcmp((A)->af, "ipv6") ? "%s:%s:%s" : "%s:[%s]:%s",	\
	 (A)->af, (A)->addr, (A)->port);

static int adm_attach(struct cfg_ctx *ctx)
{
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	int argc = 0;
	bool do_attach = (ctx->cmd == &attach_cmd);
	bool reset = (ctx->cmd == &disk_options_defaults_cmd);

	if (do_attach) {
		int rv = call_cmd_fn(&apply_al_cmd, ctx, KEEP_RUNNING);
		if (rv)
			return rv;
	}

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "attach" : "disk-options"; */
	argv[NA(argc)] = ssprintf("%d", vol->device_minor);
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
		if (!do_attach) {
			struct d_option *option;
			STAILQ_FOREACH(option, &ctx->vol->disk_options, link)
				if (!option->adj_skip)
					make_option(argv[NA(argc)], option);
		} else {
			make_options(argv[NA(argc)], &ctx->vol->disk_options);
		}
	}
	add_setup_options(argv, &argc);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_LONG, ctx->res->name);
}

struct d_option *find_opt(struct options *base, const char *name)
{
	struct d_option *option;

	STAILQ_FOREACH(option, base, link)
		if (!strcmp(option->name, name))
			return option;

	return NULL;
}

int adm_new_minor(struct cfg_ctx *ctx)
{
	char *argv[MAX_ARGS];
	int argc = 0, ex;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = "new-minor";
	argv[NA(argc)] = ssprintf("%s", ctx->res->name);
	argv[NA(argc)] = ssprintf("%u", ctx->vol->device_minor);
	argv[NA(argc)] = ssprintf("%u", ctx->vol->vnr);
	argv[NA(argc)] = NULL;

	ex = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
	if (!ex && do_register)
		register_minor(ctx->vol->device_minor, config_save);
	return ex;
}

static int adm_resource(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	char *argv[MAX_ARGS];
	int argc = 0, ex;
	bool do_new_resource = (ctx->cmd == &new_resource_cmd);
	bool reset = (ctx->cmd == &res_options_defaults_cmd);

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "new-resource" or "resource-options" */
	argv[NA(argc)] = ssprintf("%s", res->name);
	if (do_new_resource)
		argv[NA(argc)] = ctx->res->me->node_id;
	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (reset || do_new_resource)
		make_options(argv[NA(argc)], &res->res_options);
	add_setup_options(argv, &argc);
	argv[NA(argc)] = NULL;

	ex = m_system_ex(argv, SLEEPS_SHORT, res->name);
	if (!ex && do_new_resource && do_register)
		register_resource(res->name, config_save);
	return ex;
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
	argv[NA(argc)] = ssprintf("%d", ctx->vol->device_minor);
	opt = find_opt(&ctx->vol->disk_options, "size");
	if (!opt)
		opt = find_opt(&ctx->res->disk_options, "size");
	if (opt)
		argv[NA(argc)] = ssprintf("--%s=%s", opt->name, opt->value);
	add_setup_options(argv, &argc);
	argv[NA(argc)] = 0;

	/* if this is not "resize", but "check-resize", be silent! */
	silent = !strcmp(ctx->cmd->name, "check-resize") ? SUPRESS_STDERR : 0;
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

int _admm_generic(struct cfg_ctx *ctx, int flags, char *argument)
{
	struct d_volume *vol = ctx->vol;
	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = drbdmeta;
	argv[NA(argc)] = ssprintf("%d", vol->device_minor);
	argv[NA(argc)] = "v09";
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
	if (ctx->cmd->need_peer)
		argv[NA(argc)] = ssprintf("--node-id=%s", ctx->conn->peer->node_id);
	argv[NA(argc)] = (char *)ctx->cmd->name;
	if (argument)
		argv[NA(argc)] = argument;
	add_setup_options(argv, &argc);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, flags, ctx->res->name);
}

static int admm_generic(struct cfg_ctx *ctx)
{
	return _admm_generic(ctx, SLEEPS_VERY_LONG, NULL);
}

static void _adm_generic(struct cfg_ctx *ctx, int flags, pid_t *pid, int *fd, int *ex)
{
	char *argv[MAX_ARGS];
	int argc = 0;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name;
	if (ctx->vol)
		argv[NA(argc)] = ssprintf("%d", ctx->vol->device_minor);
	else if (ctx->res)
		argv[NA(argc)] = ssprintf("%s", ctx->res->name);

	if (ctx->cmd->need_peer) {
		argv[NA(argc)] = ssprintf_addr(ctx->conn->my_address);
		argv[NA(argc)] = ssprintf_addr(ctx->conn->connect_to);
	}

	add_setup_options(argv, &argc);
	argv[NA(argc)] = 0;

	if (ctx->res)
		setenv("DRBD_RESOURCE", ctx->res->name, 1);

	m__system(argv, flags, ctx->res ? ctx->res->name : NULL, pid, fd, ex);
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

int sh_status(struct cfg_ctx *ctx)
{
	struct d_resource *r;
	struct d_volume *vol, *lower_vol;
	int rv = 0;

	if (!dry_run) {
		printf("_drbd_version=%s\n_drbd_api=%u\n",
		       shell_escape(REL_VERSION), API_VERSION);
		printf("_config_file=%s\n\n\n", shell_escape(config_save));
	}

	for_each_resource(r, &config) {
		if (r->ignore)
			continue;
		ctx->res = r;

		printf("_conf_res_name=%s\n", shell_escape(r->name));
		printf("_conf_file_line=%s:%u\n\n", shell_escape(r->config_file), r->start_line);
		if (r->stacked && r->me->lower) {
			printf("_stacked_on=%s\n", shell_escape(r->me->lower->name));
			lower_vol = STAILQ_FIRST(&r->me->lower->me->volumes);
		} else {
			/* reset stuff */
			printf("_stacked_on=\n");
			printf("_stacked_on_device=\n");
			printf("_stacked_on_minor=\n");
			lower_vol = NULL;
		}
		/* TODO: remove this loop, have drbdsetup use dump
		 * and optionally filter on resource name.
		 * "stacked" information is not directly known to drbdsetup, though.
		 */
		for_each_volume(vol, &r->me->volumes) {
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
			printf("_conf_volume=%d\n", vol->vnr);

			ctx->vol = vol;
			rv = adm_generic(ctx, SLEEPS_SHORT);
			if (rv)
				return rv;

			if (lower_vol)
				lower_vol = STAILQ_NEXT(lower_vol, link);
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
		exit(E_THINKO);
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
	int rv = 0;
	char *sh_cmd;
	char *argv[] = { "/bin/sh", "-c", NULL, NULL };

	if ((sh_cmd = get_opt_val(&res->handlers, ctx->cmd->name, NULL))) {
		argv[2] = sh_cmd;
		rv = m_system_ex(argv, SLEEPS_VERY_LONG, res->name);
	}
	return rv;
}

static int adm_connect(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	char *argv[MAX_ARGS];
	int argc = 0;
	bool do_connect = (ctx->cmd == &connect_cmd);
	bool reset = (ctx->cmd == &net_options_defaults_cmd);

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = (char *)ctx->cmd->name; /* "connect" : "net-options"; */
	if (do_connect)
		argv[NA(argc)] = ssprintf("%s", res->name);
	argv[NA(argc)] = ssprintf_addr(conn->my_address);
	argv[NA(argc)] = ssprintf_addr(conn->connect_to);

	if (reset)
		argv[NA(argc)] = "--set-defaults";
	if (do_connect)
		argv[NA(argc)] = ssprintf("--peer-node-id=%s", conn->peer->node_id);
	if (reset || do_connect)
		make_options(argv[NA(argc)], &conn->net_options);

	add_setup_options(argv, &argc);
	argv[NA(argc)] = 0;

	return m_system_ex(argv, SLEEPS_SHORT, res->name);
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
	argv[NA(argc)] = (char *)ctx->cmd->name;
	argv[NA(argc)] = ssprintf_addr(ctx->conn->my_address);
	argv[NA(argc)] = ssprintf_addr(ctx->conn->connect_to);
	add_setup_options(argv, &argc);
	argv[NA(argc)] = 0;

	setenv("DRBD_RESOURCE", ctx->res->name, 1);
	return m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
}

void free_opt(struct d_option *item)
{
	free(item->name);
	free(item->value);
	free(item);
}

char *proxy_connection_name(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	static char conn_name[128];
	int counter;

	counter = snprintf(conn_name, sizeof(conn_name), "%s-%s-%s",
			 res->name,
			 names_to_str_c(&conn->peer->proxy->on_hosts, '_'),
			 names_to_str_c(&res->me->proxy->on_hosts, '_')
			 );
	if (counter >= sizeof(conn_name)-3) {
		fprintf(stderr,
				"The connection name in resource %s got too long.\n",
				res->name);
		exit(E_CONFIG_INVALID);
	}

	return conn_name;
}

int do_proxy_conn_up(struct cfg_ctx *ctx)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	char *argv[4] = { drbd_proxy_ctl, "-c", NULL, NULL };
	char *conn_name;
	int rv;

	conn_name = proxy_connection_name(ctx);

	argv[2] = ssprintf(
		 "add connection %s %s:%s %s:%s %s:%s %s:%s",
		 conn_name,
		 res->me->proxy->inside.addr,
		 res->me->proxy->inside.port,
		 conn->peer->proxy->outside.addr,
		 conn->peer->proxy->outside.port,
		 res->me->proxy->outside.addr,
		 res->me->proxy->outside.port,
		 res->me->address.addr,
		 res->me->address.port);

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

	conn_name = proxy_connection_name(ctx);

	argc = 0;
	argv[NA(argc)] = drbd_proxy_ctl;
	STAILQ_FOREACH(opt, &res->proxy_options, link) {
		argv[NA(argc)] = "-c";
		argv[NA(argc)] = ssprintf("set %s %s %s",
			 opt->name, conn_name, opt->value);
	}

	counter = 0;
	/* Don't send the "set plugin ... END" line if no plugins are defined
	 * - that's incompatible with the drbd proxy version 1. */
	if (!STAILQ_EMPTY(&res->proxy_plugins)) {
		STAILQ_FOREACH(opt, &res->proxy_options, link) {
			argv[NA(argc)] = "-c";
			argv[NA(argc)] = ssprintf("set plugin %s %d %s",
					conn_name, counter, opt->name);
			counter++;
		}
		argv[NA(argc)] = ssprintf("set plugin %s %d END", conn_name, counter);
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

	conn_name = proxy_connection_name(ctx);
	argv[2] = ssprintf("del connection %s", conn_name);

	rv = m_system_ex(argv, SLEEPS_SHORT, res->name);
	return rv;
}

static int check_proxy(struct cfg_ctx *ctx, int do_up)
{
	struct d_resource *res = ctx->res;
	struct connection *conn = ctx->conn;
	int rv;

	if (!res->me->proxy) {
		if (all_resources)
			return 0;
		fprintf(stderr,
			"There is no proxy config for host %s in resource %s.\n",
			nodeinfo.nodename, res->name);
		exit(E_CONFIG_INVALID);
	}

	if (!name_in_names(nodeinfo.nodename, &res->me->proxy->on_hosts)) {
		if (all_resources)
			return 0;
		fprintf(stderr,
			"The proxy config in resource %s is not for %s.\n",
			res->name, nodeinfo.nodename);
		exit(E_CONFIG_INVALID);
	}

	if (!conn->peer->proxy) {
		fprintf(stderr,
			"There is no proxy config for the peer in resource %s.\n",
			res->name);
		if (all_resources)
			return 0;
		exit(E_CONFIG_INVALID);
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
	struct connection *conn;
	struct d_volume *vol;

	schedule_deferred_cmd(&new_resource_cmd, ctx, CFG_PREREQ);

	set_peer_in_resource(ctx->res, true);
	for_each_connection(conn, &ctx->res->connections) {
		if (conn->ignore)
			continue;

		ctx->conn = conn;
		schedule_deferred_cmd(&connect_cmd, ctx, CFG_NET);
	}
	ctx->conn = NULL;

	for_each_volume(vol, &ctx->res->me->volumes) {
		ctx->vol = vol;
		schedule_deferred_cmd(&new_minor_cmd, ctx, CFG_PREREQ);
		schedule_deferred_cmd(&attach_cmd, ctx, CFG_DISK);
	}

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
	int argc = 0, rv;

	argv[NA(argc)] = drbdsetup;
	argv[NA(argc)] = "wait-connect";
	argv[NA(argc)] = ssprintf("%d", vol->device_minor);
	if (is_drbd_top && !res->stacked_timeouts) {
		struct d_option *opt;
		unsigned long timeout = 20;
		if ((opt = find_opt(&res->net_options, "connect-int"))) {
			timeout = strtoul(opt->value, NULL, 10);
			// one connect-interval? two?
			timeout *= 2;
		}
		argv[argc++] = "-t";
		argv[argc] = ssprintf("%lu", timeout);
		argc++;
	} else
		make_options(argv[NA(argc)], &res->startup_options);
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
	struct d_resource *res;
	struct d_volume *vol;
	unsigned int mm;

	mm = minor_by_id(id);
	if (mm == -1U)
		return -ENOENT;

	for_each_resource(res, &config) {
		if (res->ignore)
			continue;
		for_each_volume(vol, &res->me->volumes) {
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

struct d_volume *volume_by_vnr(struct volumes *volumes, int vnr)
{
	struct d_volume *vol;

	for_each_volume(vol, volumes)
		if (vnr == vol->vnr)
			return vol;

	return NULL;
}

int ctx_by_name(struct cfg_ctx *ctx, const char *id)
{
	struct d_resource *res;
	struct d_volume *vol;
	struct connection *conn;
	char *input = strdupa(id);
	char *vol_id = strchr(input, '/');
	char *res_name, *conn_name;
	unsigned vol_nr = ~0U;

	if (vol_id) {
		*vol_id++ = '\0';
		vol_nr = m_strtoll(vol_id, 0);
	}

	res_name = strchr(input, '@');
	if (res_name) {
		*res_name++ = '\0';
		conn_name = input;
	} else {
		res_name = input;
		conn_name = NULL;
	}

	res = res_by_name(res_name);
	if (!res || res->ignore)
		return -ENOENT;
	ctx->res = res;

	set_peer_in_resource(res, 1);

	if (conn_name) {
		ctx->conn = NULL;
		for_each_connection(conn, &res->connections) {
			struct d_option *opt;

			opt = find_opt(&conn->net_options, "_name");
			if (opt && !strcmp(opt->value, conn_name))
				goto found;
		}
		fprintf(stderr,	"Connection/peer name '%s' is not a peer\n", conn_name);
		return -ENOENT;
	} else if (connect_to_host) {
		struct d_host_info *hi;

		hi = find_host_info_by_name(res, connect_to_host);
		if (!hi) {
			fprintf(stderr,
				"Host name '%s' (given with --peer option) is not "
				"mentioned in any connection section\n", connect_to_host);
			return -ENOENT;
		}
		if (res->me == hi) {
			fprintf(stderr,
				"Host name '%s' (given with --peer option) is not a "
				"peer, but the local node\n", connect_to_host);
			return -ENOENT;
		}
		ctx->conn = NULL;
		for_each_connection(conn, &res->connections) {
			if (conn->peer == hi)
				goto found;
		}
		return -ENOENT;
	}
	if (0) {
	found:
		if (conn->ignore) {
			fprintf(stderr, "Connection '%s' has the ignore flag set\n", conn_name);
			return -ENOENT;
		}

		ctx->conn = conn;
	}

	if (!vol_id) {
		/* We could assign implicit volumes here.
		 * But that broke "drbdadm up specific-resource".
		 */
		ctx->vol = NULL;
		return 0;
	}

	vol = volume_by_vnr(&res->me->volumes, vol_nr);
	if (vol) {
		ctx->vol = vol;
		return 0;
	}

	return -ENOENT;
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
			exit(E_EXEC_ERROR);
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
			exit(E_EXEC_ERROR);
		}
	} while (pr == -1);

	if (pr == 1) {		// Input available.
		rr = read(fileno(stdin), s, size - 1);
		if (rr == -1) {
			perror("read");
			exit(E_EXEC_ERROR);
		}
		s[rr] = 0;
	}

out:
	return pr;
}

static char *get_opt_val(struct options *base, const char *name, char *def)
{
	struct d_option *option;

	option = find_opt(base, name);
	return option ? option->value : def;
}

void chld_sig_hand(int __attribute((unused)) unused)
{
	// do nothing. But interrupt systemcalls :)
}

static int check_exit_codes(pid_t * pids)
{
	struct d_resource *res;
	int i = 0, rv = 0;

	for_each_resource(res, &config) {
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
	struct d_resource *res;
	char *argv[20], answer[40];
	pid_t *pids;
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

	for_each_resource(res, &config) {
		struct d_volume *vol;
		if (res->ignore)
			continue;
		if (is_drbd_top != res->stacked)
			continue;

		for_each_volume(vol, &res->me->volumes) {
			/* ctx is not used */
			argc = 0;
			argv[NA(argc)] = drbdsetup;
			argv[NA(argc)] = "wait-connect";
			argv[NA(argc)] = ssprintf("%u", vol->device_minor);
			make_options(argv[NA(argc)], &res->startup_options);
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
		/* track a "yes", as well as ctrl-d and ctrl-c,
		 * in case our tty is stuck in "raw" mode, and
		 * we get it one character a time (-icanon) */
		char yes_string[] = "yes\n";
		char *yes_expect = yes_string;
		int ctrl_c_count = 0;
		int ctrl_d_count = 0;

		/* Just in case, if plymouth or usplash is running,
		 * tell them to step aside.
		 * Also try to force canonical tty mode. */
		if (system("exec > /dev/null 2>&1; plymouth quit ; usplash_write QUIT ; "
			   "stty echo icanon icrnl"))
			/* Ignore return value. Cannot do anything about it anyways. */;

		printf
		    ("\n***************************************************************\n"
		     " DRBD's startup script waits for the peer node(s) to appear.\n"
		     " - In case this node was already a degraded cluster before the\n"
		     "   reboot the timeout is %s seconds. [degr-wfc-timeout]\n"
		     " - If the peer was available before the reboot the timeout will\n"
		     "   expire after %s seconds. [wfc-timeout]\n"
		     "   (These values are for resource '%s'; 0 sec -> wait forever)\n",
		     get_opt_val(&STAILQ_FIRST(&config)->startup_options, "degr-wfc-timeout",
				 "0"), get_opt_val(&STAILQ_FIRST(&config)->startup_options,
						   "wfc-timeout", "0"),
		     STAILQ_FIRST(&config)->name);

		printf(" To abort waiting enter 'yes' [ -- ]: ");
		do {
			printf("\e[s\e[31G[%4d]:\e[u", (int)(time(0) - start));	// Redraw sec.
			fflush(stdout);
			rr = gets_timeout(pids, answer, 40, wtime * 1000);
			check_exit_codes(pids);

			if (rr != 1)
				continue;

			/* If our tty is in "sane" or "canonical" mode,
			 * we get whole lines.
			 * If it still is in "raw" mode, even though we
			 * tried to set ICANON above, possibly some other
			 * "boot splash thingy" is in operation.
			 * We may be lucky to get single characters.
			 * If a sysadmin sees things stuck during boot,
			 * I expect that ctrl-c or ctrl-d will be one
			 * of the first things that are tried.
			 * In raw mode, we get these characters directly.
			 * But I want them to try that three times ;)
			 */
			if (answer[0] && answer[1] == 0) {
				if (answer[0] == '\3')
					++ctrl_c_count;
				if (answer[0] == '\4')
					++ctrl_d_count;
				if (yes_expect && answer[0] == *yes_expect)
					++yes_expect;
				else if (answer[0] == '\n')
					yes_expect = yes_string;
				else
					yes_expect = NULL;
			}

			if (!strcmp(answer, "yes\n") ||
			    (yes_expect && *yes_expect == '\0') ||
			    ctrl_c_count >= 3 ||
			    ctrl_d_count >= 3) {
				kill_childs(pids);
				childs_running(pids, 0);
				check_exit_codes(pids);
				break;
			}

			printf(" To abort waiting enter 'yes' [ -- ]:");
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
		if (cmds[i]->show_in_usage != level)
			continue;
		if (j++ % 2) {
			printf("%-35s\n", cmds[i]->name);
		} else {
			printf(" %-35s", cmds[i]->name);
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

void print_usage_and_exit(struct adm_cmd *cmd, const char *addinfo, int status)
{
	struct option *opt;

	printf("\nUSAGE: %s %s [OPTION...] {all|RESOURCE...}\n\n"
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

	exit(status);
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
	if (!res->me->address.addr)
		return;

	if (!have_ip(res->me->address.af, res->me->address.addr)) {
		ENTRY e, *ep;
		e.key = e.data = ep = NULL;
		m_asprintf(&e.key, "%s:%s", res->me->address.addr, res->me->address.port);
		hsearch_r(e, FIND, &ep, &global_htable);
		fprintf(stderr, "%s: in resource %s, on %s:\n\t"
			"IP %s not found on this host.\n",
			ep ? (char *)ep->data : res->config_file,
			res->name, names_to_str(&res->me->on_hosts),
			res->me->address.addr);
		if (INVALID_IP_IS_INVALID_CONF)
			config_valid = 0;
	}
}

static char *conf_file[] = {
	DRBD_CONFIG_DIR "/drbd-90.conf",
	DRBD_CONFIG_DIR "/drbd-84.conf",
	DRBD_CONFIG_DIR "/drbd-83.conf",
	DRBD_CONFIG_DIR "/drbd-82.conf",
	DRBD_CONFIG_DIR "/drbd-08.conf",
	DRBD_CONFIG_DIR "/drbd.conf",
	0
};


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
		exit(E_USAGE);
	}

	tmp = strdupa(path);
	last_slash = strrchr(tmp, '/');

	if (last_slash) {
		*last_slash++ = '\0';
		cwd_fd = open(".", O_RDONLY);
		if (cwd_fd < 0) {
			fprintf(stderr, "open(\".\") failed: %m\n");
			exit(E_USAGE);
		}
		if (chdir(tmp)) {
			fprintf(stderr, "chdir(\"%s\") failed: %m\n", tmp);
			exit(E_USAGE);
		}
	} else {
		last_slash = tmp;
	}

	that_wd = getcwd(NULL, 0);
	if (!that_wd) {
		fprintf(stderr, "getcwd() failed: %m\n");
		exit(E_USAGE);
	}

	if (!strcmp("/", that_wd))
		m_asprintf(&abs_path, "/%s", last_slash);
	else
		m_asprintf(&abs_path, "%s/%s", that_wd, last_slash);

	free(that_wd);
	if (cwd_fd >= 0) {
		if (fchdir(cwd_fd) < 0) {
			fprintf(stderr, "fchdir() failed: %m\n");
			exit(E_USAGE);
		}
	}

	return abs_path;
}

void assign_command_names_from_argv0(char **argv)
{
	struct cmd_helper {
		char *name;
		char **var;
	};
	static struct cmd_helper helpers[] = {
		{"drbdsetup", &drbdsetup},
		{"drbdmeta", &drbdmeta},
		{"drbd-proxy-ctl", &drbd_proxy_ctl},
		{"drbdadm-83", &drbdadm_83},
		{NULL, NULL}
	};
	struct cmd_helper *c;

	/* in case drbdadm is called with an absolute or relative pathname
	 * look for the drbdsetup binary in the same location,
	 * otherwise, just let execvp sort it out... */
	if ((progname = strrchr(argv[0], '/')) == NULL) {
		progname = argv[0];
		for (c = helpers; c->name; ++c)
			*(c->var) = strdup(c->name);
	} else {
		size_t len_dir, l;

		++progname;
		len_dir = progname - argv[0];

		for (c = helpers; c->name; ++c) {
			l = len_dir + strlen(c->name) + 1;
			*(c->var) = malloc(l);
			if (*(c->var)) {
				strncpy(*(c->var), argv[0], len_dir);
				strcpy(*(c->var) + len_dir, c->name);
				if (access(*(c->var), X_OK))
					strcpy(*(c->var), c->name); /* see add_lib_drbd_to_path() */
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
		const struct adm_cmd *cmd = cmds[i];
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
					else {
						fprintf(stderr, "Warning: drbdsetup %s option --%s "
							"can only be passed as -W--%s\n",
							cmd->name, admopt[n].name, admopt[n].name);
						goto skip;
					}
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
	const char *optstring = make_optstring(admopt);
	int longindex, first_arg_index;
	int i;

	*cmd = NULL;
	*resource_names = malloc(sizeof(char **));
	(*resource_names)[0] = NULL;

	opterr = 1;
	optind = 0;
	while (1) {
		int c;

		c = getopt_long(argc, argv, optstring, admopt, &longindex);
		if (c == -1)
			break;
		switch (c) {
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
					exit(E_EXEC_ERROR);
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

	first_arg_index = optind;
	for (; optind < argc; optind++) {
		optarg = argv[optind];
		if (*cmd) {
			int n;
			for (n = 0; (*resource_names)[n]; n++)
				/* do nothing */ ;
			*resource_names = realloc(*resource_names,
						  (n + 2) * sizeof(char **));
			(*resource_names)[n++] = optarg;
			(*resource_names)[n] = NULL;
		} else if (!strcmp(optarg, "help"))
			help = true;
		else {
			*cmd = find_cmd(optarg);
			if (!*cmd) {
				/* Passing drbdsetup options like this is discouraged! */
				add_setup_option(true, optarg);
			}
		}
	}

	if (help)
		print_usage_and_exit(*cmd, 0, 0);

	if (*cmd == NULL) {
		if (first_arg_index < argc) {
			fprintf(stderr, "%s: Unknown command '%s'\n",
				progname, argv[first_arg_index]);
			return E_USAGE;
		}
		print_usage_and_exit(*cmd, "No command specified", E_USAGE);
	}

	if (setup_options) {
		/*
		 * The drbdsetup options are command specific.  Make sure that only
		 * setup options that this command recognizes are used.
		 */
		for (i = 0; setup_options[i].option; i++) {
			const struct field_def *field;
			const char *option;
			int len;

			if (setup_options[i].explicit)
				continue;

			option = setup_options[i].option;
			for (len = 0; option[len]; len++)
				if (option[len] == '=')
					break;

			field = NULL;
			if (option[0] == '-' && option[1] == '-' && (*cmd)->drbdsetup_ctx) {
				for (field = (*cmd)->drbdsetup_ctx->fields; field->name; field++) {
					if (strlen(field->name) == len - 2 &&
					    !strncmp(option + 2, field->name, len - 2))
						break;
				}
				if (!field->name)
					field = NULL;
			}
			if (!field) {
				fprintf(stderr, "%s: unrecognized option '%.*s'\n",
					progname, len, option);
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
	return E_USAGE;
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
		if (!strcmp(cmds[i]->name, cmdname)) {
			cmd = cmds[i];
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
		exit(E_CONFIG_INVALID);
	}
}

void count_resources_or_die(void)
{
	int m, mc = global_options.minor_count;
	struct d_resource *res;
	struct d_volume *vol;

	highest_minor = 0;
	number_of_minors = 0;
	for_each_resource(res, &config) {
		if (res->ignore) {
			nr_resources[IGNORED]++;
			/* How can we count ignored volumes?
			 * Do we want to? */
			continue;
		} else if (res->stacked)
			nr_resources[STACKED]++;
		else
			nr_resources[NORMAL]++;

		for_each_volume(vol, &res->me->volumes) {
			number_of_minors++;
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
		exit(E_USAGE);
	}
}

void die_if_no_resources(void)
{
	if (!is_drbd_top && nr_resources[IGNORED] > 0 && nr_resources[NORMAL] == 0) {
		fprintf(stderr,
			"WARN: no normal resources defined for this host (%s)!?\n"
			"Misspelled name of the local machine with the 'on' keyword ?\n",
			nodeinfo.nodename);
		exit(E_USAGE);
	}
	if (!is_drbd_top && nr_resources[NORMAL] == 0) {
		fprintf(stderr,
			"WARN: no normal resources defined for this host (%s)!?\n",
			nodeinfo.nodename);
		exit(E_USAGE);
	}
	if (is_drbd_top && nr_resources[STACKED] == 0) {
		fprintf(stderr, "WARN: nothing stacked for this host (%s), "
			"nothing to do in stacked mode!\n", nodeinfo.nodename);
		exit(E_USAGE);
	}
}

int main(int argc, char **argv)
{
	size_t i;
	int rv = 0;
	struct adm_cmd *cmd = NULL;
	char **resource_names = NULL;
	struct d_resource *res;
	char *env_drbd_nodename = NULL;
	int is_dump_xml;
	int is_dump;
	struct cfg_ctx ctx = { };

	initialize_deferred_cmds();
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

	if (drbdsetup == NULL || drbdmeta == NULL || drbd_proxy_ctl == NULL) {
		fprintf(stderr, "could not strdup argv[0].\n");
		exit(E_EXEC_ERROR);
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
		exit(E_USAGE);
	}

	do_verify_ips = cmd->verify_ips;

	is_dump_xml = (cmd == &dump_xml_cmd);
	is_dump = (is_dump_xml || cmd == &dump_cmd);

	if (!resource_names[0]) {
		if (is_dump)
			all_resources = 1;
		else if (cmd->res_name_required)
			print_usage_and_exit(cmd, "No resource names specified", E_USAGE);
	} else if (resource_names[0] && resource_names[1]) {
		if (!cmd->res_name_required)
			fprintf(stderr,
				"This command will ignore resource names!\n");
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
			exit(E_EXEC_ERROR);
		}
		my_parse();

		config_file = saved_config_file;
		config_save = saved_config_save;
	}

	if (!config_valid)
		exit(E_CONFIG_INVALID);

	post_parse(cmd->is_proxy_cmd ? MATCH_ON_PROXY : 0);

	if (!is_dump || dry_run || verbose)
		expand_common();
	if (dry_run || config_from_stdin)
		do_register = 0;

	count_resources_or_die();

	if (cmd->uc_dialog)
		uc_node(global_options.usage_count);

	ctx.cmd = cmd;
	if (cmd->res_name_required || resource_names[0]) {
		if (STAILQ_EMPTY(&config)) {
			fprintf(stderr, "no resources defined!\n");
			exit(E_USAGE);
		}

		global_validate_maybe_expand_die_if_invalid(!is_dump);

		if (!resource_names[0] || !strcmp(resource_names[0], "all")) {
			/* either no resource arguments at all,
			 * but command is dump / dump-xml, so implicit "all",
			 * or an explicit "all" argument is given */
			all_resources = 1;
			if (!is_dump)
				die_if_no_resources();
			/* verify ips first, for all of them */
			for_each_resource(res, &config) {
				verify_ips(res);
			}
			if (!config_valid)
				exit(E_CONFIG_INVALID);

			if (is_dump_xml)
				print_dump_xml_header();
			else if (is_dump)
				print_dump_header();

			for_each_resource(res, &config) {
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
			if (is_dump_xml)
				printf("</config>\n");
		} else {
			/* explicit list of resources to work on */
			for (i = 0; resource_names[i]; i++) {
				int rv;
				ctx.res = NULL;
				ctx.vol = NULL;
				rv = ctx_by_name(&ctx, resource_names[i]);
				if (!ctx.res) {
					ctx_by_minor(&ctx, resource_names[i]);
					rv = 0;
				}
				if (!ctx.res) {
					fprintf(stderr,
						"'%s' not defined in your config (for this host).\n",
						resource_names[i]);
					exit(E_USAGE);
				}
				if (rv)
					exit(E_USAGE);
				if (!cmd->vol_id_required && !cmd->iterate_volumes && ctx.vol != NULL) {
					if (ctx.vol->implicit)
						ctx.vol = NULL;
					else {
						fprintf(stderr, "%s operates on whole resources, but you specified a specific volume!\n",
								cmd->name);
						exit(E_USAGE);
					}
				}
				if (cmd->vol_id_required && !ctx.vol && STAILQ_FIRST(&ctx.res->me->volumes)->implicit)
					ctx.vol = STAILQ_FIRST(&ctx.res->me->volumes);
				if (cmd->vol_id_required && !ctx.vol) {
					fprintf(stderr, "%s requires a specific volume id, but none is specified.\n"
							"Try '%s minor-<minor_number>' or '%s %s/<vnr>'\n",
							cmd->name, cmd->name,
							cmd->name, resource_names[i]);
					exit(E_USAGE);
				}
				if (ctx.res->ignore && !is_dump) {
					fprintf(stderr,
						"'%s' ignored, since this host (%s) is not mentioned with an 'on' keyword.\n",
						ctx.res->name, nodeinfo.nodename);
					rv = E_USAGE;
					continue;
				}
				if (is_drbd_top != ctx.res->stacked && !is_dump) {
					fprintf(stderr,
						"'%s' is a %s resource, and not available in %s mode.\n",
						ctx.res->name,
						ctx.res->stacked ? "stacked" : "normal",
						is_drbd_top ? "stacked" :
						"normal");
					rv = E_USAGE;
					continue;
				}
				verify_ips(ctx.res);
				if (!is_dump && !config_valid)
					exit(E_CONFIG_INVALID);
				rv = call_cmd(cmd, &ctx, EXIT_ON_FAIL);	/* does exit for rv >= 20! */
			}
		}
	} else {		// Commands which do not need a resource name
		/* no call_cmd, as that implies register_minor,
		 * which does not make sense for resource independent commands.
		 * It does also not need to iterate over volumes: it does not even know the resource. */
		rv = call_cmd_fn(cmd, &ctx, KEEP_RUNNING);
		if (rv >= 10) {	/* why do we special case the "generic sh-*" commands? */
			fprintf(stderr, "command %s exited with code %d\n",
				cmd->name, rv);
			exit(rv);
		}
	}

	/* do we really have to bitor the exit code?
	 * it is even only a Boolean value in this case! */
	rv |= run_deferred_cmds();

	free_config();
	free(resource_names);
	if (admopt != general_admopt)
		free(admopt);

	return rv;
}

void yyerror(char *text)
{
	fprintf(stderr, "%s:%d: %s\n", config_file, line, text);
	exit(E_SYNTAX);
}
