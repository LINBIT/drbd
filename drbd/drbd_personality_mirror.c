/*
   drbd_personality_mirror.c

   This file is part of DRBD.

   Copyright (C) 2017, LINBIT HA-Solutions GmbH.

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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/socket.h>
#include <linux/pkt_sched.h>
#include <linux/sched/signal.h>
#include <linux/net.h>
#include <linux/tcp.h>
#include <linux/highmem.h>
#include <linux/drbd_genl_api.h>
#include <linux/drbd_config.h>
#include <drbd_protocol.h>
#include <drbd_personality.h>
#include "drbd_wrappers.h"


MODULE_AUTHOR("Philipp Reisner <philipp.reisner@linbit.com>");
MODULE_AUTHOR("Lars Ellenberg <lars.ellenberg@linbit.com>");
MODULE_AUTHOR("Roland Kammerer <roland.kammerer@linbit.com>");
MODULE_DESCRIPTION("RAID1 personality for DRBD");
MODULE_LICENSE("GPL");
MODULE_VERSION(REL_VERSION);


struct drbd_mirror_personality {
	struct drbd_personality personality; /* Must be first! */
	unsigned long flags;
};

static int dmp_init(struct drbd_personality *personality);
static int dmp_encode(struct drbd_personality *personality, struct drbd_request *req, u64 in_bm);
static int dmp_decode(struct drbd_personality *personality, struct drbd_request *req, u64 in_bm);
static void dmp_stats(struct drbd_personality *personality, struct drbd_personality_stats *stats);

static struct drbd_personality_class mirror_personality_class = {
	.name = "mirror",
	.instance_size = sizeof(struct drbd_mirror_personality),
	.module = THIS_MODULE,
	.init = dmp_init,
	.list = LIST_HEAD_INIT(mirror_personality_class.list),
};

static struct drbd_personality_ops dmp_ops = {
	.encode = dmp_encode,
	.decode = dmp_decode,
	.stats = dmp_stats,
};

static int dmp_init(struct drbd_personality *personality)
{
	struct drbd_mirror_personality *mirror_pers =
		container_of(personality, struct drbd_mirror_personality, personality);

	/* TODO(rck): obviously, these are nonsense numbers */
	mirror_pers->personality.n = 42;
	mirror_pers->personality.k = 23;
	mirror_pers->personality.block_size = 4096;

	mirror_pers->personality.ops = &dmp_ops;
	mirror_pers->personality.class = &mirror_personality_class;

	return 0;
}

static int dmp_encode(struct drbd_personality *personality, struct drbd_request *req, u64 in_bm)
{
	return 0;
}

static int dmp_decode(struct drbd_personality *personality, struct drbd_request *req, u64 in_bm)
{
	return 0;
}

/* THINK about the params
static int dmp_reshape(struct drbd_personality *personality)
{
	return 0;
}
*/

static void dmp_stats(struct drbd_personality *personality, struct drbd_personality_stats *stats)
{
}

static int __init dpm_initialize(void)
{
	return drbd_register_personality_class(&mirror_personality_class,
					     DRBD_PERSONALITY_API_VERSION,
					     sizeof(struct drbd_personality));
}

static void __exit dpm_cleanup(void)
{
	drbd_unregister_personality_class(&mirror_personality_class);
}

module_init(dpm_initialize)
module_exit(dpm_cleanup)
