/*
   drbdadm_adjust.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2003-2006, Philipp Reisner <philipp.reisner@linbit.com>.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "drbdadm.h"
#include "drbdtool_common.h"

extern FILE* yyin;
extern struct d_resource* parse_resource(char*);

static FILE *m_popen(int *pid,char** argv)
{
	int mpid;
	int pipes[2];

	if(pipe(pipes)) {
		perror("Creation of pipes failed");
		exit(E_exec_error);
	}

	mpid = fork();
	if(mpid == -1) {
		fprintf(stderr,"Can not fork");
		exit(E_exec_error);
	}
	if(mpid == 0) {
		close(pipes[0]); // close reading end
		dup2(pipes[1],1); // 1 = stdout
		close(pipes[1]);
		execvp(argv[0],argv);
		fprintf(stderr,"Can not exec");
		exit(E_exec_error);
	}

	close(pipes[1]); // close writing end
	*pid=mpid;
	return fdopen(pipes[0],"r");
}

/* option value equal? */
static int ov_eq(char* val1, char* val2)
{
	unsigned long long v1,v2;

	if(val1 == NULL && val2 == NULL) return 1;
	if(val1 == NULL || val2 == NULL) return 0;

	if(isdigit(val1[0])) {
		v1 = m_strtoll(val1,0);
		v2 = m_strtoll(val2,0);

		return v1 == v2;
	}

	return !strcmp(val1,val2);
}

static int opts_equal(struct d_option* conf, struct d_option* running)
{
	struct d_option* opt;

	while(running) {
		if((opt=find_opt(conf,running->name))) {
			if(!ov_eq(running->value,opt->value)) {
				/*printf("Value of '%s' differs: r=%s c=%s\n",
				  opt->name,running->value,opt->value);*/
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
	if (conf->peer == NULL && running->peer == NULL) return 1;
	if (conf->peer == NULL || running->peer == NULL) return 0;

	return !strcmp(conf->me->address,  running->me->address) &&
		!strcmp(conf->me->port,     running->me->port) &&
		!strcmp(conf->peer->address,running->peer->address) &&
		!strcmp(conf->peer->port,   running->peer->port) ;
}

static int proto_equal(struct d_resource* conf, struct d_resource* running)
{
	if (conf->protocol == NULL && running->protocol == NULL) return 1;
	if (conf->protocol == NULL || running->protocol == NULL) return 0;

	return !strcmp(conf->protocol, running->protocol);
}

static int dev_eq(char* device_name, unsigned int g_major, unsigned int g_minor)
{
	struct stat sb;
	
	if(stat(device_name,&sb)) return 0;

	return major(sb.st_rdev) == g_major && minor(sb.st_rdev) == g_minor;
}

/* Are both internal, or are both not internal. */
static int int_eq(char* m_conf, char* m_running)
{
	return !strcmp(m_conf,"internal") == !strcmp(m_running,"internal");
}

static int disk_equal(struct d_host_info* conf, struct d_host_info* running)
{
	int eq = 1;

	eq &= dev_eq(conf->disk,running->disk_major,running->disk_minor);
	eq &= int_eq(conf->meta_disk,running->meta_disk);
	if(!strcmp(conf->meta_disk,"internal")) return eq;
	eq &= dev_eq(conf->meta_disk,running->meta_major,running->meta_minor);

	return eq;
}

/*
 * calling drbdsetup again before waitpid("drbdsetup show") has a race with
 * the next ioctl failing because of the zombie still holding an open_cnt on
 * the drbd device. so don't do that.
 */
int adm_adjust(struct d_resource* res,char* unused __attribute((unused)))
{
	char* argv[20];
	int pid,argc=0;
	struct d_resource* running;
	int do_attach=0;
	int do_connect=0;
	int do_syncer=0;

	argv[argc++]=drbdsetup;
	argv[argc++]=res->me->device;
	argv[argc++]="show";
	argv[argc++]=0;

	yyin = m_popen(&pid,argv);
	line = 1;
	running = parse_resource("drbdsetup/show");
	fclose(yyin);
	waitpid(pid,0,0);

	do_attach  = !opts_equal(res->disk_options, running->disk_options);
	if(running->me) {
		do_attach |= strcmp(res->me->device, running->me->device);
		do_attach |= !disk_equal(res->me, running->me);
	} else  do_attach |= 1;

	do_connect  = !opts_equal(res->net_options, running->net_options);
	do_connect |= !addr_equal(res,running);
	do_connect |= !proto_equal(res,running);

	do_syncer = !opts_equal(res->sync_options, running->sync_options);

	if(do_attach)  schedule_dcmd(adm_attach,res,0);
	if(do_syncer)  schedule_dcmd(adm_syncer,res,1);
	if(do_connect) schedule_dcmd(adm_connect,res,2);

	return 0;
}
