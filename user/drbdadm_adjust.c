/*
   drbdadm_adjust.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2003-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2003-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2003-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>

#include "drbdadm.h"
#include "drbdtool_common.h"
#include "drbdadm_parser.h"
#include "config_flags.h"

/* drbdsetup show might complain that the device minor does
   not exist at all. Redirect stderr to /dev/null therefore.
 */
static FILE *m_popen(int *pid,char** argv)
{
	int mpid;
	int pipes[2];
	int dev_null;

	if(pipe(pipes)) {
		perror("Creation of pipes failed");
		exit(E_EXEC_ERROR);
	}

	dev_null = open("/dev/null", O_WRONLY);
	if (dev_null == -1) {
		perror("Opening /dev/null failed");
		exit(E_EXEC_ERROR);
	}

	mpid = fork();
	if(mpid == -1) {
		fprintf(stderr,"Can not fork");
		exit(E_EXEC_ERROR);
	}
	if(mpid == 0) {
		close(pipes[0]); // close reading end
		dup2(pipes[1], fileno(stdout));
		close(pipes[1]);
		dup2(dev_null, fileno(stderr));
		close(dev_null);
		execvp(argv[0],argv);
		fprintf(stderr,"Can not exec");
		exit(E_EXEC_ERROR);
	}

	close(pipes[1]); // close writing end
	close(dev_null);
	*pid=mpid;
	return fdopen(pipes[0],"r");
}

static int is_equal(struct context_def *ctx, struct d_option *a, struct d_option *b)
{
	struct field_def *field;

	for (field = ctx->fields; field->name; field++) {
		if (!strcmp(field->name, a->name))
			return field->is_equal(field, a->value, b->value);
	}

	fprintf(stderr, "Internal error: option '%s' not known in this context\n", a->name);
	abort();
}

static bool is_default(struct context_def *ctx, struct d_option *opt)
{
	struct field_def *field;

	for (field = ctx->fields; field->name; field++) {
		if (strcmp(field->name, opt->name))
			continue;
		return field->is_default(field, opt->value);
	}
	return false;
}

static int opts_equal(struct context_def *ctx, struct options *conf, struct options *run_base)
{
	struct d_option *opt, *run_opt;

	STAILQ_FOREACH(run_opt, run_base, link) {
		if (run_opt->adj_skip)
			continue;

		opt = find_opt(conf, run_opt->name);
		if (opt) {
			if (!is_equal(ctx, run_opt, opt)) {
				if (verbose > 2)
					fprintf(stderr, "Value of '%s' differs: r=%s c=%s\n",
						opt->name,run_opt->value,opt->value);
				return 0;
			}
			if (verbose > 3)
				fprintf(stderr, "Value of '%s' equal: r=%s c=%s\n",
					opt->name,run_opt->value,opt->value);
			opt->mentioned = 1;
		} else {
			if (!is_default(ctx, run_opt)) {
				if (verbose > 2)
					fprintf(stderr, "Only in running config %s: %s\n",
						run_opt->name,run_opt->value);
				return 0;
			}
			if (verbose > 3)
				fprintf(stderr, "Is default: '%s' equal: r=%s\n",
					run_opt->name,run_opt->value);
		}
	}

	STAILQ_FOREACH(opt, conf, link) {
		if (opt->adj_skip)
			continue;

		if (opt->mentioned==0 && !is_default(ctx, opt)) {
			if (verbose > 2)
				fprintf(stderr, "Only in optig file %s: %s\n",
					opt->name, opt->value);
			return 0;
		}
	}
	return 1;
}

static int addr_equal(struct d_address *a1, struct d_address *a2)
{
	return  !strcmp(a1->addr, a2->addr) &&
		!strcmp(a1->port, a2->port) &&
		!strcmp(a1->af, a2->af);
}

static struct connection *matching_conn(struct connection *pattern, struct connections *pool)
{
	struct connection *conn;

	for_each_connection(conn, pool) {
		if (conn->ignore)
			continue;
		if (addr_equal(pattern->my_address, conn->my_address) &&
		    addr_equal(pattern->connect_to, conn->connect_to))
			return conn;
	}

	return NULL;
}

/* Are both internal, or are both not internal. */
static int int_eq(char* m_conf, char* m_running)
{
	return !strcmp(m_conf,"internal") == !strcmp(m_running,"internal");
}

static int disk_equal(struct d_volume *conf, struct d_volume *running)
{
	int eq = 1;

	if (conf->disk == NULL && running->disk == NULL)
		return 1;
	if (conf->disk == NULL || running->disk == NULL)
		return 0;

	eq &= !strcmp(conf->disk, running->disk);
	eq &= int_eq(conf->meta_disk, running->meta_disk);
	if (!strcmp(conf->meta_disk, "internal"))
		return eq;
	eq &= !strcmp(conf->meta_disk, running->meta_disk);

	return eq;
}

/* The following is a cruel misuse of the cmd->name field. The whole proxy_reconf
   function should be rewritten in a sane way!
   It should schedule itself to get invoked later, and at the late point in time
   iterate the config and find out what to do...

   Obviously the schedule_deferred_proxy_reconf() function should go away */

static int do_proxy_reconf(const struct cfg_ctx *ctx)
{
	int rv;
	char *argv[4] = { drbd_proxy_ctl, "-c", (char*)ctx->cmd->name, NULL };

	rv = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
	return rv;
}

static void schedule_deferred_proxy_reconf(const struct cfg_ctx *ctx, char *text)
{
	struct adm_cmd *cmd;

	cmd = calloc(1, sizeof(struct adm_cmd));
	if (cmd == NULL) {
		perror("calloc");
		exit(E_EXEC_ERROR);
	}

	cmd->name = text;
	cmd->function = &do_proxy_reconf;
	schedule_deferred_cmd(cmd, ctx, CFG_NET);
}

#define MAX_PLUGINS (10)
#define MAX_PLUGIN_NAME (16)

/* The new name is appended to the alist. */
int _is_plugin_in_list(char *string,
		char slist[MAX_PLUGINS][MAX_PLUGIN_NAME],
		char alist[MAX_PLUGINS][MAX_PLUGIN_NAME],
		int list_len)
{
	int word_len, i;
	char *copy;

	for(word_len=0; string[word_len]; word_len++)
		if (isspace(string[word_len]))
			break;

	if (word_len+1 >= MAX_PLUGIN_NAME) {
		fprintf(stderr, "Wrong proxy plugin name %*.*s",
				word_len, word_len, string);
		exit(E_CONFIG_INVALID);
	}

	copy = alist[list_len];
	strncpy(copy, string, word_len);
	copy[word_len] = 0;


	for(i=0; i<list_len && *slist; i++) {
		if (strcmp(slist[i], copy) == 0)
			return 1;
	}

	/* Not found, insert into list. */
	if (list_len >= MAX_PLUGINS) {
		fprintf(stderr, "Too many proxy plugins.");
		exit(E_CONFIG_INVALID);
	}

	return 0;
}


static int proxy_reconf(const struct cfg_ctx *ctx, struct d_resource *running)
{
	int reconn = 0;
	struct d_resource *res = ctx->res;
	struct d_option* res_o, *run_o;
	unsigned long long v1, v2, minimum;
	char *plugin_changes[MAX_PLUGINS], *cp, *conn_name;
	/* It's less memory usage when we're storing char[]. malloc overhead for
	 * the few bytes + pointers is much more. */
	char p_res[MAX_PLUGINS][MAX_PLUGIN_NAME],
		 p_run[MAX_PLUGINS][MAX_PLUGIN_NAME];
	int used, i, re_do;

	reconn = 0;

	if (!running)
		goto redo_whole_conn;

	res_o = find_opt(&res->proxy_options, "memlimit");
	run_o = find_opt(&running->proxy_options, "memlimit");
	v1 = res_o ? m_strtoll(res_o->value, 1) : 0;
	v2 = run_o ? m_strtoll(run_o->value, 1) : 0;
	minimum = v1 < v2 ? v1 : v2;
	/* We allow an є [epsilon] of 2%, so that small (rounding) deviations do
	 * not cause the connection to be re-established. */
	if (res_o &&
			(!run_o || abs(v1-v2)/(float)minimum > 0.02))
	{
redo_whole_conn:
		/* As the memory is in use while the connection is allocated we have to
		 * completely destroy and rebuild the connection. */

		schedule_deferred_cmd(&proxy_conn_down_cmd, ctx, CFG_NET_PREREQ);
		schedule_deferred_cmd(&proxy_conn_up_cmd, ctx, CFG_NET_PREREQ);
		schedule_deferred_cmd(&proxy_conn_plugins_cmd, ctx, CFG_NET_PREREQ);

		/* With connection cleanup and reopen everything is rebuild anyway, and
		 * DRBD will get a reconnect too.  */
		return 0;
	}


	res_o = STAILQ_FIRST(&res->proxy_plugins);
	run_o = STAILQ_FIRST(&running->proxy_plugins);
	used = 0;
	conn_name = proxy_connection_name(ctx);
	for(i=0; i<MAX_PLUGINS; i++)
	{
		if (used >= sizeof(plugin_changes)-1) {
			fprintf(stderr, "Too many proxy plugin changes");
			exit(E_CONFIG_INVALID);
		}
		/* Now we can be sure that we can store another pointer. */

		if (!res_o) {
			if (run_o) {
				/* More plugins running than configured - just stop here. */
				m_asprintf(&cp, "set plugin %s %d end", conn_name, i);
				plugin_changes[used++] = cp;
			}
			else {
				/* Both at the end? ok, quit loop */
			}
			break;
		}

		/* res_o != NULL. */

		if (!run_o) {
			p_run[i][0] = 0;
			if (_is_plugin_in_list(res_o->name, p_run, p_res, i)) {
				/* Current plugin was already active, just at another position.
				 * Redo the whole connection. */
				goto redo_whole_conn;
			}

			/* More configured than running - just add it, if it's not already
			 * somewhere else. */
			m_asprintf(&cp, "set plugin %s %d %s", conn_name, i, res_o->name);
			plugin_changes[used++] = cp;
		} else {
			/* If we get here, both lists have been filled in parallel, so we
			 * can simply use the common counter. */
			re_do = _is_plugin_in_list(res_o->name, p_run, p_res, i) ||
				_is_plugin_in_list(run_o->name, p_res, p_run, i);
			if (re_do) {
				/* Plugin(s) were moved, not simple reconfigured.
				 * Re-do the whole connection. */
				goto redo_whole_conn;
			}

			/* TODO: We don't (yet) account for possible different ordering of
			 * the parameters to the plugin.
			 *    plugin A 1 B 2
			 * should be treated as equal to
			 *    plugin B 2 A 1. */
			if (strcmp(run_o->name, res_o->name) != 0) {
				/* Either a different plugin, or just different settings
				 * - plugin can be overwritten.  */
				m_asprintf(&cp, "set plugin %s %d %s", conn_name, i, res_o->name);
				plugin_changes[used++] = cp;
			}
		}


		if (res_o)
			res_o = STAILQ_NEXT(res_o, link);
		if (run_o)
			run_o = STAILQ_NEXT(run_o, link);
	}

	/* change only a few plugin settings. */
	for(i=0; i<used; i++)
		schedule_deferred_proxy_reconf(ctx, plugin_changes[i]);

	return reconn;
}

int need_trigger_kobj_change(struct d_resource *res)
{
	struct stat sbuf;
	char *link_name;
	int err;

	m_asprintf(&link_name, "/dev/drbd/by-res/%s", res->name);

	err = stat("/dev/drbd/by-res", &sbuf);
	if (err)	/* probably no udev rules in use */
		return 0;

	err = stat(link_name, &sbuf);
	if (err)
		/* resource link cannot be stat()ed. */
		return 1;

	/* double check device information */
	if (!S_ISBLK(sbuf.st_mode))
		return 1;
	if (major(sbuf.st_rdev) != DRBD_MAJOR)
		return 1;
	if (minor(sbuf.st_rdev) != STAILQ_FIRST(&res->me->volumes)->device_minor)
		return 1;

	/* Link exists, and is expected block major:minor.
	 * Do nothing. */
	return 0;
}

void compare_size(struct d_volume *conf, struct d_volume *kern)
{
	struct d_option *c = find_opt(&conf->disk_options, "size");
	struct d_option *k = find_opt(&kern->disk_options, "size");

	if (c)
		c->adj_skip = 1;
	if (k)
		k->adj_skip = 1;

	/* simplify logic below, would otherwise have to
	 * (!x || is_default(x) all the time. */
	if (k && is_default(&attach_cmd_ctx, k))
		k = NULL;

	/* size was set, but it is no longer in config, or vice versa */
	if (!k != !c)
		conf->adj_resize = 1;

	/* size options differ */
	if (k && c && !is_equal(&attach_cmd_ctx, c, k))
		conf->adj_resize = 1;
}

void compare_volume(struct d_volume *conf, struct d_volume *kern)
{
	/* Special case "size", we need to issue a resize command to change that.
	 * Move both options to the head of the disk_options list,
	 * so we can easily skip them in the opts_equal, later.
	 */

	conf->adj_new_minor = conf->device_minor != kern->device_minor;
	conf->adj_del_minor = conf->adj_new_minor && kern->disk;

	if (!disk_equal(conf, kern)) {
		if (conf->disk && kern->disk) {
			conf->adj_attach = 1;
			conf->adj_detach = 1;
		} else {
			conf->adj_attach = conf->disk != NULL;
			conf->adj_detach = kern->disk != NULL;
		}
	}

	/* do we need to resize? */
	compare_size(conf, kern);

	/* is it sufficient to only adjust the disk options? */
	if (!(conf->adj_detach || conf->adj_attach) && conf->disk)
		conf->adj_disk_opts = !opts_equal(&disk_options_ctx, &conf->disk_options, &kern->disk_options);
}

struct d_volume *new_to_be_deleted_minor_from_template(struct d_volume *kern)
{
	/* need to delete it from kernel.
	 * Create a minimal volume,
	 * and flag it as "del_minor". */
	struct d_volume *conf = calloc(1, sizeof(*conf));
	conf->vnr = kern->vnr;
	/* conf->device: no need */
	conf->device_minor = kern->device_minor;
	conf->disk = strdup(kern->disk);
	conf->meta_disk = strdup(kern->meta_disk);
	conf->meta_index = strdup(kern->meta_index);

	conf->adj_detach = 1;
	conf->adj_del_minor = 1;
	return conf;
}

#define ASSERT(x) do { if (!(x)) {				\
	fprintf(stderr, "%s:%u:%s: ASSERT(%s) failed.\n",	\
		__FILE__ , __LINE__ , __func__ , #x );		\
	abort(); }						\
	} while (0)

/* Both conf and kern are single linked lists
 * supposed to be ordered by ->vnr;
 * We may need to conjure dummy volumes to issue "del-minor" on,
 * and insert these into the conf list.
 */
void compare_volumes(struct volumes *conf_head, struct volumes *kern_head)
{
	struct volumes to_be_deleted = STAILQ_HEAD_INITIALIZER(to_be_deleted);
	struct d_volume *conf = STAILQ_FIRST(conf_head);
	struct d_volume *kern = STAILQ_FIRST(kern_head);
	while (conf || kern) {
		if (kern && (conf == NULL || kern->vnr < conf->vnr)) {
			insert_volume(&to_be_deleted, new_to_be_deleted_minor_from_template(kern));
			kern = STAILQ_NEXT(kern, link);
		} else if (conf && (kern == NULL || kern->vnr > conf->vnr)) {
			conf->adj_new_minor = 1;
			if (conf->disk)
				conf->adj_attach = 1;
			conf = STAILQ_NEXT(conf, link);
		} else {
			ASSERT(conf);
			ASSERT(kern);
			ASSERT(conf->vnr == kern->vnr);

			compare_volume(conf, kern);
			conf = STAILQ_NEXT(conf, link);
			kern = STAILQ_NEXT(kern, link);
		}
	}
	for_each_volume(conf, &to_be_deleted)
		insert_volume(conf_head, conf);
}

/*
 * CAUTION this modifies global static char * config_file!
 */
int adm_adjust(const struct cfg_ctx *ctx)
{
	char* argv[20];
	int pid,argc, i;
	struct d_resource* running;
	struct d_volume *vol;
	struct connection *conn;
	struct volumes empty = STAILQ_HEAD_INITIALIZER(empty);

	/* necessary per resource actions */
	int do_res_options = 0;

	/* necessary per volume actions are flagged
	 * in the vol->adj_* members. */

	int can_do_proxy = 1;
	char config_file_dummy[250];
	char show_conn[128];
	char *resource_name;

	/* disable check_uniq, so it won't interfere
	 * with parsing of drbdsetup show output */
	config_valid = 2;

	set_me_in_resource(ctx->res, true);
	set_peer_in_resource(ctx->res, true);

	/* setup error reporting context for the parsing routines */
	line = 1;
	sprintf(config_file_dummy,"drbdsetup show %s", ctx->res->name);
	config_file = config_file_dummy;

	argc = 0;
	argv[argc++] = drbdsetup;
	argv[argc++] = "show";
	argv[argc++] = ctx->res->name;
	argv[argc++] = NULL;

	/* actually parse drbdsetup show output */
	yyin = m_popen(&pid,argv);
	running = parse_resource_for_adjust(ctx);
	fclose(yyin);
	waitpid(pid, 0, 0);

	if (running) {
		struct resources running_as_list;
		STAILQ_INIT(&running_as_list);
		insert_tail(&running_as_list, running);
		post_parse(&running_as_list, 0);

		set_me_in_resource(running, 0);
		set_peer_in_resource(running, 0);
	}


	/* Parse proxy settings, if this host has a proxy definition.
	 * FIXME what about "zombie" proxy settings, if we remove proxy
	 * settings from the config file without prior proxy-down, this won't
	 * clean them from the proxy. */
	if (ctx->res->me->proxy) {
		line = 1;
		resource_name = proxy_connection_name(ctx);
		i=snprintf(show_conn, sizeof(show_conn), "show proxy-settings %s", resource_name);
		if (i>= sizeof(show_conn)-1) {
			fprintf(stderr,"connection name too long");
			exit(E_THINKO);
		}
		sprintf(config_file_dummy,"drbd-proxy-ctl -c '%s'", show_conn);
		config_file = config_file_dummy;

		argc=0;
		argv[argc++]=drbd_proxy_ctl;
		argv[argc++]="-c";
		argv[argc++]=show_conn;
		argv[argc++]=0;

		/* actually parse "drbd-proxy-ctl show" output */
		yyin = m_popen(&pid,argv);
		can_do_proxy = !parse_proxy_settings(running,
				PARSER_CHECK_PROXY_KEYWORD | PARSER_STOP_IF_INVALID);
		fclose(yyin);

		waitpid(pid,0,0);
	}

	compare_volumes(&ctx->res->me->volumes, running ? &running->me->volumes : &empty);

	if (running) {
		do_res_options = !opts_equal(&resource_options_ctx, &ctx->res->res_options, &running->res_options);
	} else {
		schedule_deferred_cmd(&new_resource_cmd, ctx, CFG_PREREQ);
	}

	if (running) {
		for_each_connection(conn, &running->connections) {
			struct connection *configured_conn;

			configured_conn = matching_conn(conn, &ctx->res->connections);
			if (!configured_conn) {
				struct cfg_ctx tmp_ctx = { .res = running, .conn = conn };
				schedule_deferred_cmd(&disconnect_cmd, &tmp_ctx, CFG_NET);
			}
		}
	}

	for_each_connection(conn, &ctx->res->connections) {
		struct connection *running_conn = NULL;
		struct cfg_ctx tmp_ctx = { .res = ctx->res, .conn = conn };

		if (conn->ignore)
			continue;

		if (running)
			running_conn = matching_conn(conn, &running->connections);
		if (!running_conn) {
			schedule_deferred_cmd(&connect_cmd, &tmp_ctx, CFG_NET);
		} else {
			if (!opts_equal(&net_options_ctx, &conn->net_options, &running_conn->net_options))
				schedule_deferred_cmd(&net_options_defaults_cmd, &tmp_ctx, CFG_NET);
		}
	}

	if (ctx->res->me->proxy && can_do_proxy)
		proxy_reconf(ctx, running);

	if (do_res_options)
		schedule_deferred_cmd(&res_options_defaults_cmd, ctx, CFG_RESOURCE);

	/* do we need to attach,
	 * do we need to detach first,
	 * or is this just some attribute change? */
	for_each_volume(vol, &ctx->res->me->volumes) {
		struct cfg_ctx tmp_ctx = { .res = ctx->res, .vol = vol };
		if (vol->adj_detach)
			schedule_deferred_cmd(&detach_cmd, &tmp_ctx, CFG_PREREQ);
		if (vol->adj_del_minor)
			schedule_deferred_cmd(&del_minor_cmd, &tmp_ctx, CFG_PREREQ);
		if (vol->adj_new_minor)
			schedule_deferred_cmd(&new_minor_cmd, &tmp_ctx, CFG_DISK_PREREQ);
		if (vol->adj_attach)
			schedule_deferred_cmd(&attach_cmd, &tmp_ctx, CFG_DISK);
		if (vol->adj_disk_opts)
			schedule_deferred_cmd(&disk_options_defaults_cmd, &tmp_ctx, CFG_DISK);
		if (vol->adj_resize)
			schedule_deferred_cmd(&resize_cmd, &tmp_ctx, CFG_DISK);
	}

	return 0;
}
