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
		exit(E_exec_error);
	}

	dev_null = open("/dev/null", O_WRONLY);
	if (dev_null == -1) {
		perror("Opening /dev/null failed");
		exit(E_exec_error);
	}

	mpid = fork();
	if(mpid == -1) {
		fprintf(stderr,"Can not fork");
		exit(E_exec_error);
	}
	if(mpid == 0) {
		close(pipes[0]); // close reading end
		dup2(pipes[1], fileno(stdout));
		close(pipes[1]);
		dup2(dev_null, fileno(stderr));
		close(dev_null);
		execvp(argv[0],argv);
		fprintf(stderr,"Can not exec");
		exit(E_exec_error);
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

static int opts_equal(struct context_def *ctx, struct d_option* conf, struct d_option* running)
{
	struct d_option* opt;

	while(running) {
		if((opt=find_opt(conf,running->name))) {
			if(!is_equal(ctx, running, opt)) {
				if (verbose > 2)
					fprintf(stderr, "Value of '%s' differs: r=%s c=%s\n",
						opt->name,running->value,opt->value);
				return 0;
			}
			if (verbose > 3)
				fprintf(stderr, "Value of '%s' equal: r=%s c=%s\n",
					opt->name,running->value,opt->value);
			opt->mentioned=1;
		} else {
			if(!is_default(ctx, running)) {
				if (verbose > 2)
					fprintf(stderr, "Only in running config %s: %s\n",
						running->name,running->value);
				return 0;
			}
			if (verbose > 3)
				fprintf(stderr, "Is default: '%s' equal: r=%s\n",
					running->name,running->value);
		}
		running=running->next;
	}

	while(conf) {
		if(conf->mentioned==0 && !is_default(ctx, conf)) {
			if (verbose > 2)
				fprintf(stderr, "Only in config file %s: %s\n",
					conf->name,conf->value);
			return 0;
		}
		conf=conf->next;
	}
	return 1;
}

static int addr_equal(struct d_resource* conf, struct d_resource* running)
{
	int equal;

	if (conf->peer == NULL && running->peer == NULL) return 1;
	if (running->peer == NULL) return 0;

	equal = !strcmp(conf->me->address,        running->me->address) &&
		!strcmp(conf->me->port,           running->me->port) &&
		!strcmp(conf->me->address_family, running->me->address_family);

	if(conf->me->proxy)
		equal = equal &&
			!strcmp(conf->me->proxy->inside_addr, running->peer->address) &&
			!strcmp(conf->me->proxy->inside_port, running->peer->port) &&
			!strcmp(conf->me->proxy->inside_af,   running->peer->address_family);
	else
		equal = equal && conf->peer &&
			!strcmp(conf->peer->address,        running->peer->address) &&
			!strcmp(conf->peer->port,           running->peer->port) &&
			!strcmp(conf->peer->address_family, running->peer->address_family);

	return equal;
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


/* NULL terminated */
static void find_option_in_resources(char *name,
		struct d_option *list, struct d_option **opt, ...)
{
	va_list va;

	va_start(va, opt);
	/* We need to keep setting *opt to NULL, even if a list == NULL. */
	while (list || opt) {
		while (list) {
			if (strcmp(list->name, name) == 0)
				break;
			list = list->next;
		}

		*opt = list;

		list = va_arg(va, struct d_option*);
		opt  = va_arg(va, struct d_option**);
	}
	va_end(va);
}

static int do_proxy_reconf(struct cfg_ctx *ctx)
{
	int rv;
	char *argv[4] = { drbd_proxy_ctl, "-c", (char*)ctx->arg, NULL };

	rv = m_system_ex(argv, SLEEPS_SHORT, ctx->res->name);
	return rv;
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
		exit(E_config_invalid);
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
		exit(E_config_invalid);
	}

	return 0;
}


static int proxy_reconf(struct cfg_ctx *ctx, struct d_resource *running)
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

	find_option_in_resources("memlimit",
			res->proxy_options, &res_o,
			running->proxy_options, &run_o,
			NULL, NULL);
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

		schedule_deferred_cmd( do_proxy_conn_down, ctx, NULL, CFG_NET_PREREQ);
		schedule_deferred_cmd( do_proxy_conn_up, ctx, NULL, CFG_NET_PREREQ);
		schedule_deferred_cmd( do_proxy_conn_plugins, ctx, NULL, CFG_NET_PREREQ);

		/* With connection cleanup and reopen everything is rebuild anyway, and
		 * DRBD will get a reconnect too.  */
		return 0;
	}


	res_o = res->proxy_plugins;
	run_o = running->proxy_plugins;
	used = 0;
	conn_name = proxy_connection_name(res);
	for(i=0; i<MAX_PLUGINS; i++)
	{
		if (used >= sizeof(plugin_changes)-1) {
			fprintf(stderr, "Too many proxy plugin changes");
			exit(E_config_invalid);
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
			res_o = res_o->next;
		if (run_o)
			run_o = run_o->next;
	}

	/* change only a few plugin settings. */
	for(i=0; i<used; i++)
		schedule_deferred_cmd(do_proxy_reconf, ctx, plugin_changes[i], CFG_NET);

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
	if (minor(sbuf.st_rdev) != res->me->volumes->device_minor)
		return 1;

	/* Link exists, and is expected block major:minor.
	 * Do nothing. */
	return 0;
}

/* moves option to the head of the single linked option list,
 * and marks it as to be skiped for "adjust only" commands
 * like disk-options see e.g. adm_attach_and_or_disk_options().
 */
static void move_opt_to_head(struct d_option **head, struct d_option *o)
{
	struct d_option *t;
	if (!o)
		return;
	o->adj_skip = 1;
	if (o == *head)
		return;

	for (t = *head; t->next != o; t = t->next)
		;
	t->next = o->next;
	o->next = *head;
	*head = o;
}

void compare_max_bio_bvecs(struct d_volume *conf, struct d_volume *kern)
{
	struct d_option *c = find_opt(conf->disk_options, "max-bio-bvecs");
	struct d_option *k = find_opt(kern->disk_options, "max-bio-bvecs");

	/* move to front of list, so we can skip it
	 * for the following opts_equal */
	move_opt_to_head(&conf->disk_options, c);
	move_opt_to_head(&kern->disk_options, k);

	/* simplify logic below, would otherwise have to
	 * (!x || is_default(x) all the time. */
	if (k && is_default(&disk_options_ctx, k))
		k = NULL;

	/* there was a bvec restriction set,
	 * but it is no longer in config, or vice versa */
	if (!k != !c)
		conf->adj_attach = 1;

	/* restrictions differ */
	if (k && c && !is_equal(&disk_options_ctx, k, c))
		conf->adj_attach = 1;
}

/* similar to compare_max_bio_bvecs above */
void compare_size(struct d_volume *conf, struct d_volume *kern)
{
	struct d_option *c = find_opt(conf->disk_options, "size");
	struct d_option *k = find_opt(kern->disk_options, "size");

	move_opt_to_head(&conf->disk_options, c);
	move_opt_to_head(&kern->disk_options, k);

	if (k && is_default(&disk_options_ctx, k))
		k = NULL;
	if (!k != !c)
		conf->adj_resize = 1;
	if (k && c && !is_equal(&disk_options_ctx, c, k))
		conf->adj_resize = 1;
}

void compare_volume(struct d_volume *conf, struct d_volume *kern)
{
	/* Special-case "max-bio-bvecs", we do not allow to change that
	 * while attached, yet.
	 * Also special case "size", we need to issue a resize command to change that.
	 * Move both options to the head of the disk_options list,
	 * so we can easily skip them in the opts_equal, later.
	 */
	struct d_option *c, *k;

	/* do we need to do a full attach,
	 * potentially with a detach first? */
	conf->adj_attach = (conf->device_minor != kern->device_minor)
			|| !disk_equal(conf, kern);

	/* do we need to do a full (detach/)attach,
	 * because max_bio_bvec setting differs? */
	compare_max_bio_bvecs(conf, kern);

	/* do we need to resize? */
	compare_size(conf, kern);

	/* skip these two options (if present) for the opts_equal below.
	 * These have been move_opt_to_head()ed before already. */
	k = kern->disk_options;
	while (k && (!strcmp(k->name, "size") || !strcmp(k->name, "max-bio-bvecs")))
		k = k->next;
	c = conf->disk_options;
	while (c && (!strcmp(c->name, "size") || !strcmp(c->name, "max-bio-bvecs")))
		c = c->next;

	/* is it sufficient to only adjust the disk options? */
	if (!conf->adj_attach)
		conf->adj_disk_opts = !opts_equal(&disk_options_ctx, c, k);

	if (conf->adj_attach && kern->disk)
		conf->adj_detach = 1;
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
 * The resulting new conf list head is returned.
 */
struct d_volume *compare_volumes(struct d_volume *conf, struct d_volume *kern)
{
	struct d_volume *to_be_deleted = NULL;
	struct d_volume *conf_head = conf;
	while (conf || kern) {
		if (kern && (conf == NULL || kern->vnr < conf->vnr)) {
			to_be_deleted = INSERT_SORTED(to_be_deleted,
					new_to_be_deleted_minor_from_template(kern),
					vnr);
			kern = kern->next;
		} else if (conf && (kern == NULL || kern->vnr > conf->vnr)) {
			conf->adj_add_minor = 1;
			conf->adj_attach = 1;
			conf = conf->next;
		} else {
			ASSERT(conf);
			ASSERT(kern);
			ASSERT(conf->vnr == kern->vnr);

			compare_volume(conf, kern);
			conf = conf->next;
			kern = kern->next;
		}
	}
	for_each_volume(conf, to_be_deleted)
		conf_head = INSERT_SORTED(conf_head, conf, vnr);
	return conf_head;
}

/*
 * CAUTION this modifies global static char * config_file!
 */
int adm_adjust(struct cfg_ctx *ctx)
{
	char* argv[20];
	int pid,argc, i;
	struct d_resource* running;
	struct d_volume *vol;

	/* necessary per resource actions */
	int do_res_options = 0;

	/* necessary per connection actions
	 * (currently we still only have one connection per resource */
	int do_net_options = 0;
	int do_disconnect = 0;
	int do_connect = 0;

	/* necessary per volume actions are flagged
	 * in the vol->adj_* members. */

	int can_do_proxy = 1;
	char config_file_dummy[250];
	char show_conn[128];
	char *resource_name;

	/* disable check_uniq, so it won't interfere
	 * with parsing of drbdsetup show output */
	config_valid = 2;


	/* setup error reporting context for the parsing routines */
	line = 1;
	sprintf(config_file_dummy,"drbdsetup %s show", ctx->res->name);
	config_file = config_file_dummy;

	argc=0;
	argv[argc++]=drbdsetup;
	ssprintf(argv[argc++], "%s", ctx->res->name);
	argv[argc++]="show";
	argv[argc++]=0;

	/* actually parse drbdsetup show output */
	yyin = m_popen(&pid,argv);
	running = parse_resource_for_adjust(ctx);
	fclose(yyin);
	waitpid(pid, 0, 0);

	if (running) {
		/* Sets "me" and "peer" pointer */
		post_parse(running, 0);
		set_peer_in_resource(running, 0);
	}


	/* Parse proxy settings, if this host has a proxy definition.
	 * FIXME what about "zombie" proxy settings, if we remove proxy
	 * settings from the config file without prior proxy-down, this won't
	 * clean them from the proxy. */
	if (ctx->res->me->proxy) {
		line = 1;
		resource_name = proxy_connection_name(ctx->res);
		i=snprintf(show_conn, sizeof(show_conn), "show proxy-settings %s", resource_name);
		if (i>= sizeof(show_conn)-1) {
			fprintf(stderr,"connection name too long");
			exit(E_thinko);
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

	ctx->res->me->volumes = compare_volumes(ctx->res->me->volumes,
			running ? running->me->volumes : NULL);

	if (running) {
		do_connect = !addr_equal(ctx->res,running);
		do_net_options = !opts_equal(&net_options_ctx, ctx->res->net_options, running->net_options);
	} else {
		do_res_options = 1;
		do_connect = 1;
		schedule_deferred_cmd(adm_new_resource, ctx, "new-resource", CFG_PREREQ);
	}

	if (ctx->res->me->proxy && can_do_proxy)
		do_connect |= proxy_reconf(ctx, running);

	if (do_connect && running)
		do_disconnect = running->net_options != NULL;

	if (do_res_options)
		schedule_deferred_cmd(adm_res_options, ctx, "resource-options", CFG_RESOURCE);

	/* do we need to attach,
	 * do we need to detach first,
	 * or is this just some attribute change? */
	for_each_volume(vol, ctx->res->me->volumes) {
		struct cfg_ctx tmp_ctx = { .res = ctx->res, .vol = vol };
		if (vol->adj_detach)
			schedule_deferred_cmd(adm_generic_s, &tmp_ctx, "detach", CFG_PREREQ);
		if (vol->adj_del_minor)
			schedule_deferred_cmd(adm_generic_s, &tmp_ctx, "del-minor", CFG_PREREQ);
		if (vol->adj_add_minor)
			schedule_deferred_cmd(adm_new_minor, &tmp_ctx, "new-minor", CFG_DISK_PREREQ);
		if (vol->adj_attach)
			schedule_deferred_cmd(adm_attach, &tmp_ctx, "attach", CFG_DISK);
		if (vol->adj_disk_opts)
			schedule_deferred_cmd(adm_attach, &tmp_ctx, "disk-options", CFG_DISK);
		if (vol->adj_resize)
			schedule_deferred_cmd(adm_resize, &tmp_ctx, "resize", CFG_DISK);
	}

	if (do_connect) {
		if (do_disconnect && ctx->res->peer)
			schedule_deferred_cmd(adm_generic_s, ctx, "disconnect", CFG_NET_PREREQ);
		schedule_deferred_cmd(adm_connect, ctx, "connect", CFG_NET);
		do_net_options = 0;
	}

	if (do_net_options)
		schedule_deferred_cmd(adm_connect, ctx, "net-options", CFG_NET);

	return 0;
}
