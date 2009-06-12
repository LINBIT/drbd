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

/*
 * CAUTION this modifies global static char * config_file!
 */
int adm_adjust(struct d_resource* res,char* unused __attribute((unused)))
{
	char* argv[20];
	int pid,argc=0;
	struct d_resource* running;
	int do_attach=0,do_connect=0,do_syncer=0;
	int have_disk=0,have_net=0;
	char config_file_dummy[250];

	argv[argc++]=drbdsetup;
	argv[argc++]=res->me->device;
	argv[argc++]="show";
	argv[argc++]=0;

	/* disable check_uniq, so it won't interfere
	 * with parsing of drbdsetup show output */
	config_valid = 2;

	yyin = m_popen(&pid,argv);
	line = 1;
	sprintf(config_file_dummy,"drbdsetup %u show", res->me->device_minor);
	config_file = config_file_dummy;
	running = parse_resource(config_file_dummy, IgnDiscardMyData);
	fclose(yyin);
	waitpid(pid,0,0);
	post_parse(running);
	set_peer_in_resource(running, 0);

	do_attach  = !opts_equal(res->disk_options, running->disk_options);
	if(running->me) {
		do_attach |= (res->me->device_minor != running->me->device_minor);
		do_attach |= !disk_equal(res->me, running->me);
		have_disk = (running->me->disk != NULL);
	} else  do_attach |= 1;

	do_connect  = !opts_equal(res->net_options, running->net_options);
	do_connect |= !addr_equal(res,running);
	do_connect |= !proto_equal(res,running);
	have_net = (running->protocol != NULL);

	do_syncer = !opts_equal(res->sync_options, running->sync_options);

	if(do_attach) {
		if(have_disk) schedule_dcmd(adm_generic_s,res,"detach",0);
		schedule_dcmd(adm_attach,res,"attach",0);
	}
	if(do_syncer)  schedule_dcmd(adm_syncer,res,"syncer",1);
	if(do_connect) {
		if(have_net) schedule_dcmd(adm_generic_s,res,"disconnect",0);
		schedule_dcmd(adm_connect,res,"connect",2);
	}

	return 0;
}
