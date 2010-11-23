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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "drbdadm.h"
#include "drbdtool_common.h"
#include "drbdadm_parser.h"

extern FILE* yyin;

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

/* option value equal? */
static int ov_eq(char* val1, char* val2)
{
	unsigned long long v1,v2;

	if(val1 == NULL && val2 == NULL) return 1;
	if(val1 == NULL || val2 == NULL) return 0;

	if(new_strtoll(val1,0,&v1) == MSE_OK &&
	   new_strtoll(val2,0,&v2) == MSE_OK) return v1 == v2;

	return !strcmp(val1,val2);
}

static int opts_equal(struct d_option* conf, struct d_option* running)
{
	struct d_option* opt;

	while(running) {
		if((opt=find_opt(conf,running->name))) {
			if(!ov_eq(running->value,opt->value)) {
			/* printf("Value of '%s' differs: r=%s c=%s\n",
			   opt->name,running->value,opt->value); */
				return 0;
			}
			opt->mentioned=1;
		} else {
			if(!running->is_default) {
				/*printf("Only in running config %s: %s\n",
				  running->name,running->value);*/
				return 0;
			}
		}
		running=running->next;
	}

	while(conf) {
		if(conf->mentioned==0) {
			/*printf("Only in config file %s: %s\n",
			  conf->name,conf->value);*/
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

static int proto_equal(struct d_resource* conf, struct d_resource* running)
{
	if (conf->protocol == NULL && running->protocol == NULL) return 1;
	if (conf->protocol == NULL || running->protocol == NULL) return 0;

	return !strcmp(conf->protocol, running->protocol);
}

/* Are both internal, or are both not internal. */
static int int_eq(char* m_conf, char* m_running)
{
	return !strcmp(m_conf,"internal") == !strcmp(m_running,"internal");
}

static int disk_equal(struct d_host_info* conf, struct d_host_info* running)
{
	int eq = 1;

	if (conf->disk == NULL && running->disk == NULL) return 1;
	if (conf->disk == NULL || running->disk == NULL) return 0;

	eq &= !strcmp(conf->disk,running->disk);
	eq &= int_eq(conf->meta_disk,running->meta_disk);
	if(!strcmp(conf->meta_disk,"internal")) return eq;
	eq &= !strcmp(conf->meta_disk,running->meta_disk);

	return eq;
}


/* NULL terminated */
static void find_option_in_resources(char *name,
		struct d_option *list, struct d_option **opt, ...)
{
	va_list va;

	va_start(va, opt);
	while (list && opt) {
		while (list) {
			if (strcmp(list->name, name) == 0)
				break;
			list = list->next;
		}

		*opt = list;

		list = va_arg(va, struct d_option*);
		opt  = va_arg(va, struct d_option**);
	}
}

static int do_proxy_reconf(struct d_resource *res, const char *cmd)
{
	int rv;
	char *argv[4] = { drbd_proxy_ctl, "-c", (char*)cmd, NULL };

	rv = m_system_ex(argv, SLEEPS_SHORT, res);
	return rv;
}


static int proxy_reconf(struct d_resource *res, struct d_resource *running)
{
	int reconn = 0;
	struct d_option* res_o, *run_o;
	char *str;

	reconn = 0;

	find_option_in_resources("memlimit",
			res->proxy_options, &res_o,
			running->proxy_options, &run_o,
			NULL);
	/* TODO: convert both to integers, and compare (with some є [epsilon])? */
	if (res_o &&
			(!run_o || strcmp(res_o->value, run_o->value) != 0))
	{
		reconn = 1;
		asprintf(&str, "set memlimit %s %s", res->name, res_o->value);
		schedule_dcmd(do_proxy_reconf, res, str, 1);
	}


#if 0
	/* TODO: loglevel gets reported by connection, but works only globally */
	find_option_in_resources("loglevel",
			res->proxy_options, &res_o,
			running->proxy_options, &run_o,
			NULL);
	if (res_o &&
			(!run_o || strcmp(res_o->value, run_o->value) != 0))
	{
		asprintf(&str, "set loglevel %s", res_o->value);
		schedule_dcmd2(NULL, drbd_proxy_ctl, res, str, 1);
	}
#endif


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
	if (minor(sbuf.st_rdev) != res->me->device_minor)
		return 1;

	/* Link exists, and is expected block major:minor.
	 * Do nothing. */
	return 0;
}

/*
 * CAUTION this modifies global static char * config_file!
 */
int adm_adjust(struct d_resource* res,char* unused __attribute((unused)))
{
	char* argv[20];
	int pid,argc, i;
	struct d_resource* running;
	int do_attach=0,do_connect=0,do_syncer=0;
	int have_disk=0,have_net=0;
	char config_file_dummy[250], *conn_name, show_conn[128];

	/* disable check_uniq, so it won't interfere
	 * with parsing of drbdsetup show output */
	config_valid = 2;


	/* setup error reporting context for the parsing routines */
	line = 1;
	sprintf(config_file_dummy,"drbdsetup %u show", res->me->device_minor);
	config_file = config_file_dummy;

	argc=0;
	argv[argc++]=drbdsetup;
	argv[argc++]=res->me->device;
	argv[argc++]="show";
	argv[argc++]=0;

	/* actually parse drbdsetup show output */
	yyin = m_popen(&pid,argv);
	running = parse_resource(res->name, IgnDiscardMyData);
	fclose(yyin);

	waitpid(pid,0,0);
	/* Sets "me" and "peer" pointer */
	post_parse(running, 0);
	set_peer_in_resource(running, 0);


	/* Parse proxy settings */
	line = 1;
	conn_name = proxy_connection_name(res);
	i=snprintf(show_conn, sizeof(show_conn), "show proxy-settings %s", conn_name);
	if (i>= sizeof(show_conn)-1)
	{
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

	/* actually parse drbdsetup show output */
	yyin = m_popen(&pid,argv);
	yyrestart(yyin);
	parse_proxy_settings(running, 1);
	fclose(yyin);

	waitpid(pid,0,0);


	do_attach  = !opts_equal(res->disk_options, running->disk_options);
	if(running->me) {
		do_attach |= (res->me->device_minor != running->me->device_minor);
		do_attach |= !disk_equal(res->me, running->me);
		have_disk = (running->me->disk != NULL);
	} else  do_attach |= 1;

	do_connect  = !opts_equal(res->net_options, running->net_options);
	do_connect |= !addr_equal(res,running);
	do_connect |= !proto_equal(res,running);
	do_connect |= proxy_reconf(res,running);
	have_net = (running->protocol != NULL);

	do_syncer = !opts_equal(res->sync_options, running->sync_options);

	/* Special case: nothing changed, but the resource name.
	 * Trigger a no-op syncer request, which will cause a KOBJ_CHANGE
	 * to be broadcast, so udev may pick up the resource name change
	 * and update its symlinks. */
	if (!(do_attach || do_syncer || do_connect))
		do_syncer = need_trigger_kobj_change(running);

	if(do_attach) {
		if(have_disk) schedule_dcmd(adm_generic_s,res,"detach",0);
		schedule_dcmd(adm_attach,res,"attach",0);
	}
	if(do_syncer)  schedule_dcmd(adm_syncer,res,"syncer",1);
	if(do_connect) {
		if (have_net && res->peer)
			schedule_dcmd(adm_generic_s,res,"disconnect",0);
		schedule_dcmd(adm_connect,res,"connect",2);
	}

	return 0;
}
