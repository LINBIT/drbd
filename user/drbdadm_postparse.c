/*
   drbdadm_postparse.c actions to do after config parsing

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2012, LINBIT Information Technologies GmbH

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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include "drbdtool_common.h"
#include "drbdadm.h"

static void append_names(struct names *head, struct names *to_copy)
{
	struct d_name *new, *copy;

	STAILQ_FOREACH(copy, to_copy, link) {
		new = malloc(sizeof(struct d_name));
		new->name = strdup(copy->name);
		insert_tail(head, new);
	}
}

void set_on_hosts_in_res(struct d_resource *res)
{
	struct d_resource *l_res;
	struct d_host_info *host, *host2;
	struct d_name *h;

	for_each_host(host, &res->all_hosts) {
		if (host->lower_name) {
			for_each_resource(l_res, &config) {
				if (!strcmp(l_res->name, host->lower_name))
					break;
			}

			if (l_res == NULL) {
				fprintf(stderr, "%s:%d: in resource %s, "
					"referenced resource '%s' not defined.\n",
					res->config_file, res->start_line, res->name,
					host->lower_name);
				config_valid = 0;
				continue;
			}

			/* Simple: host->on_hosts = concat_names(l_res->me->on_hosts, l_res->peer->on_hosts); */
			for_each_host(host2, &l_res->all_hosts)
				if (!host2->lower_name)
					append_names(&host->on_hosts, &host2->on_hosts);

			host->lower = l_res;

			/* */
			if (!strcmp(host->address.addr, "127.0.0.1") || !strcmp(host->address.addr, "::1"))
				STAILQ_FOREACH(h, &host->on_hosts, link)
					check_uniq("IP", "%s:%s:%s", h->name, host->address.addr, host->address.port);

		}
	}
}

void set_me_in_resource(struct d_resource* res, int match_on_proxy)
{
	struct d_host_info *host;

	/* Determine the local host section */
	for_each_host(host, &res->all_hosts) {
		/* do we match  this host? */
		if (match_on_proxy) {
		       if (!host->proxy || !name_in_names(nodeinfo.nodename, &host->proxy->on_hosts))
			       continue;
		} else if (host->by_address) {
			if (!have_ip(host->address.af, host->address.addr) &&
				/* for debugging only, e.g. __DRBD_NODE__=10.0.0.1 */
			    strcmp(nodeinfo.nodename, host->address.addr))
				continue;
		} else if (host->lower) {
			if (!host->lower->me)
				continue;
		} else if (STAILQ_EMPTY(&host->on_hosts)) {
			/* huh? a resource without hosts to run on?! */
			continue;
		} else {
			if (!name_in_names(nodeinfo.nodename, &host->on_hosts) &&
			    strcmp("_this_host", STAILQ_FIRST(&host->on_hosts)->name))
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
				host->lower ? host->lower->name : names_to_str(&host->on_hosts));
		}
		if (res->me) {
			config_valid = 0;
			fprintf(stderr,
				"%s:%d: in resource %s, %s %s { ... } ... %s %s { ... }:\n"
				"\tThere are multiple host sections for this node.\n",
				res->config_file, host->config_line, res->name,
				res->me->lower ? "stacked-on-top-of" : "on",
				res->me->lower ? res->me->lower->name : names_to_str(&res->me->on_hosts),
				host->lower ? "stacked-on-top-of" : "on",
				host->lower ? host->lower->name : names_to_str(&host->on_hosts));
		}
		res->me = host;
		host->used_as_me = 1;
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
	struct d_host_info *host = NULL, *candidate = NULL;
	int nr_hosts = 0, candidates = 0;

	if (res->ignore)
		return;

	/* me must be already set */
	if (!res->me) {
		/* should have been implicitly ignored. */
		fprintf(stderr, "%s:%d: in resource %s:\n"
				"\tcannot determine the peer, don't even know myself!\n",
				res->config_file, res->start_line, res->name);
		exit(E_THINKO);
	}

	for_each_host(host, &res->all_hosts) {
		nr_hosts++;
		if (!host->used_as_me) {
			candidates++;
			candidate = host;
		}
	}

	if (nr_hosts == 1) {
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
	if (candidates == 1 && nr_hosts == 2) {
		res->peer = candidate;
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

	for_each_host(host, &res->all_hosts) {
		if (host->by_address && strcmp(connect_to_host, host->address.addr))
			continue;
		if (host->proxy && !name_in_names(nodeinfo.nodename, &host->proxy->on_hosts))
			continue;
		if (!name_in_names(connect_to_host, &host->on_hosts))
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


void set_disk_in_res(struct d_resource *res)
{
	struct d_host_info *host;
	struct d_volume *a, *b;

	if (res->ignore)
		return;

	for_each_host(host, &res->all_hosts) {
		if (!host->lower)
			continue;

		if (res->stacked && host->lower->stacked) {
			fprintf(stderr,
				"%s:%d: in resource %s, stacked-on-top-of %s { ... }:\n"
				"\tFIXME. I won't stack stacked resources.\n",
				res->config_file, res->start_line, res->name, host->lower_name);
			config_valid = 0;
		}

		if (host->lower->ignore)
			continue;

		check_volume_sets_equal(res, host, host->lower->me);
		if (!config_valid)
			/* don't even bother for broken config. */
			continue;

		/* volume lists are sorted on vnr */
		a = STAILQ_FIRST(&host->volumes);
		b = STAILQ_FIRST(&host->lower->me->volumes);
		while (a) {
			while (b && a->vnr > b->vnr) {
				/* Lower resource has more volumes.
				 * Probably unusual, but we decided
				 * that it should be legal.
				 * Skip those that do not match */
				b = STAILQ_NEXT(b, link);
			}
			if (a && b && a->vnr == b->vnr) {
				if (b->device)
					m_asprintf(&a->disk, "%s", b->device);
				else
					m_asprintf(&a->disk, "/dev/drbd%u", b->device_minor);
				/* stacked implicit volumes need internal meta data, too */
				if (!a->meta_disk)
					m_asprintf(&a->meta_disk, "internal");
				if (!a->meta_index)
					m_asprintf(&a->meta_index, "internal");
				a = STAILQ_NEXT(a, link);
				b = STAILQ_NEXT(b, link);
			} else {
				/* config_invalid should have been set
				 * by check_volume_sets_equal */
				assert(0);
			}
		}
	}
}

void post_parse(enum pp_flags flags)
{
	struct d_resource *res;

	for_each_resource(res, &config)
		if (res->stacked_on_one)
			set_on_hosts_in_res(res); /* sets on_hosts and host->lower */

	/* Needs "on_hosts" and host->lower already set */
	for_each_resource(res, &config)
		if (!res->stacked_on_one)
			set_me_in_resource(res, flags & MATCH_ON_PROXY);

	/* Needs host->lower->me already set */
	for_each_resource(res, &config)
		if (res->stacked_on_one)
			set_me_in_resource(res, flags & MATCH_ON_PROXY);

	// Needs "me" set already
	for_each_resource(res, &config)
		if (res->stacked_on_one)
			set_disk_in_res(res);
}
