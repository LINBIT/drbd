// SPDX-License-Identifier: GPL-2.0-only

#include "drbd_legacy_84.h"

/*
 *   drbd-8.4                      drbd-9 md.flags                   drbd-9 peer-md.flags
 * MDF_CONSISTENT      1 << 0  MDF_CONSISTENT =        1 << 0,   MDF_PEER_CONNECTED =    1 << 0,
 * MDF_PRIMARY_IND     1 << 1  MDF_PRIMARY_IND =       1 << 1,   MDF_PEER_OUTDATED =     1 << 1,
 * MDF_CONNECTED_IND   1 << 2                                    MDF_PEER_FENCING =      1 << 2,
 * MDF_FULL_SYNC       1 << 3                                    MDF_PEER_FULL_SYNC =    1 << 3,
 * MDF_WAS_UP_TO_DATE  1 << 4  MDF_WAS_UP_TO_DATE =    1 << 4,   MDF_PEER_DEVICE_SEEN =  1 << 4,
 * MDF_PEER_OUT_DATED  1 << 5
 * MDF_CRASHED_PRIMARY 1 << 6  MDF_CRASHED_PRIMARY =   1 << 6,
 * MDF_AL_CLEAN        1 << 7  MDF_AL_CLEAN =          1 << 7,
 * MDF_AL_DISABLED     1 << 8  MDF_AL_DISABLED =       1 << 8,
 *                             MDF_PRIMARY_LOST_QUORUM = 1 << 9,
 *                             MDF_HAVE_QUORUM =       1 << 10,
 *                                                                MDF_NODE_EXISTS =      1 << 16,
 */

#define MDF_84_MASK (MDF_CONSISTENT | MDF_PRIMARY_IND | MDF_WAS_UP_TO_DATE | \
		     MDF_CRASHED_PRIMARY | MDF_AL_CLEAN | MDF_AL_DISABLED)
#define MDF_84_PEER_MASK (MDF_PEER_FULL_SYNC)
#define MDF_84_CONNECTED_IND (1<<2)
#define MDF_84_PEER_OUTDATED (1<<5)

struct meta_data_on_disk_84 {
	u64 la_size_sect;      /* last agreed size. */
	u64 uuid[UI_SIZE];   /* UUIDs. */
	u64 device_uuid;
	u64 reserved_u64_1;
	u32 flags;             /* MDF */
	u32 magic;
	u32 md_size_sect;
	u32 al_offset;         /* offset to this block */
	u32 al_nr_extents;     /* important for restoring the AL (userspace) */
	      /* `-- act_log->nr_elements <-- ldev->dc.al_extents */
	u32 bm_offset;         /* offset to the bitmap, from here */
	u32 bm_bytes_per_bit;  /* 4k. Treat as magic number, must keep it compatible. */
	u32 la_peer_max_bio_size;   /* last peer max_bio_size */

	/* see al_tr_number_to_on_disk_sector() */
	u32 al_stripes;
	u32 al_stripe_size_4k;

	u8 reserved_u8[4096 - (7*8 + 10*4)];
} __packed;


static const char * const drbd_conn_s_names[] = {
	[C_STANDALONE]       = "StandAlone",
	[C_DISCONNECTING]    = "Disconnecting",
	[C_UNCONNECTED]      = "Unconnected",
	[C_TIMEOUT]          = "Timeout",
	[C_BROKEN_PIPE]      = "BrokenPipe",
	[C_NETWORK_FAILURE]  = "NetworkFailure",
	[C_PROTOCOL_ERROR]   = "ProtocolError",
	[C_CONNECTING]       = "WFConnection",
	/* [C_WF_REPORT_PARAMS] = "WFReportParams", */
	[C_TEAR_DOWN]        = "TearDown",
	[C_CONNECTED]        = "Connected",
	[L_STARTING_SYNC_S]  = "StartingSyncS",
	[L_STARTING_SYNC_T]  = "StartingSyncT",
	[L_WF_BITMAP_S]      = "WFBitMapS",
	[L_WF_BITMAP_T]      = "WFBitMapT",
	[L_WF_SYNC_UUID]     = "WFSyncUUID",
	[L_SYNC_SOURCE]      = "SyncSource",
	[L_SYNC_TARGET]      = "SyncTarget",
	[L_PAUSED_SYNC_S]    = "PausedSyncS",
	[L_PAUSED_SYNC_T]    = "PausedSyncT",
	[L_VERIFY_S]         = "VerifyS",
	[L_VERIFY_T]         = "VerifyT",
	[L_AHEAD]            = "Ahead",
	[L_BEHIND]           = "Behind",
};

static const char write_ordering_chars[] = {
	[WO_NONE] = 'n',
	[WO_DRAIN_IO] = 'd',
	[WO_BDEV_FLUSH] = 'f',
	[WO_BIO_BARRIER] = 'b',
};


static int seq_print_device_proc_drbd(struct seq_file *m, struct drbd_device *device);

int nr_drbd8_devices;

void drbd_md_decode_84(struct meta_data_on_disk_84 *on_disk, struct drbd_md *md)
{
	struct drbd_peer_md *peer_md;
	const int peer_node_id = 0; /* setup_node_ids_84() moves it later */
	u32 on_disk_flags;
	int i;

	md->effective_size = be64_to_cpu(on_disk->la_size_sect);
	md->current_uuid = be64_to_cpu(on_disk->uuid[UI_CURRENT]);
	md->prev_members = 0;
	md->device_uuid = be64_to_cpu(on_disk->device_uuid);
	md->md_size_sect = be32_to_cpu(on_disk->md_size_sect);
	md->al_offset = be32_to_cpu(on_disk->al_offset);

	md->bm_offset = be32_to_cpu(on_disk->bm_offset);

	on_disk_flags = be32_to_cpu(on_disk->flags);
	md->flags = on_disk_flags & MDF_84_MASK;

	md->max_peers = 1;
	md->bm_block_size = be32_to_cpu(on_disk->bm_bytes_per_bit);
	md->node_id = -1; /* no node_id in the drbd-8.4 meta-data */
	md->al_stripes = be32_to_cpu(on_disk->al_stripes);
	md->al_stripe_size_4k = be32_to_cpu(on_disk->al_stripe_size_4k);


	for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
		peer_md = &md->peers[i];

		peer_md->bitmap_uuid = 0;
		peer_md->bitmap_dagtag = 0;
		peer_md->flags = 0;
		peer_md->bitmap_index = -1;
	}
	peer_md = &md->peers[peer_node_id];
	peer_md->bitmap_uuid = be64_to_cpu(on_disk->uuid[UI_BITMAP]);
	peer_md->bitmap_index = 0;
	peer_md->flags = on_disk_flags & MDF_84_PEER_MASK;
	peer_md->flags |= MDF_HAVE_BITMAP;
	peer_md->flags |= on_disk_flags & MDF_84_PEER_OUTDATED ? MDF_PEER_OUTDATED : 0;
	peer_md->flags |= on_disk_flags & MDF_84_CONNECTED_IND ? MDF_PEER_CONNECTED : 0;


	for (i = UI_HISTORY_START; i < UI_HISTORY_END; i++)
		md->history_uuids[i - UI_HISTORY_START] = be64_to_cpu(on_disk->uuid[i]);
}

void drbd_md_encode_84(struct drbd_device *device, struct meta_data_on_disk_84 *buffer)
{
	struct drbd_md *md = &device->ldev->md;
	int peer_node_id = !md->node_id;
	struct drbd_peer_md *peer_md = &md->peers[peer_node_id];
	u32 flags = (md->flags & MDF_84_MASK) | (peer_md->flags & MDF_84_PEER_MASK);
	int i;

	flags |= peer_md->flags & MDF_PEER_OUTDATED ? MDF_84_PEER_OUTDATED : 0;
	flags |= peer_md->flags & MDF_PEER_CONNECTED ? MDF_84_CONNECTED_IND : 0;
	buffer->la_size_sect = cpu_to_be64(md->effective_size);
	buffer->device_uuid = cpu_to_be64(md->device_uuid);
	buffer->uuid[UI_CURRENT] = cpu_to_be64(md->current_uuid);
	buffer->uuid[UI_BITMAP] = cpu_to_be64(peer_md->bitmap_uuid);
	for (i = UI_HISTORY_START; i < UI_HISTORY_END; i++)
		buffer->uuid[i] = cpu_to_be64(md->history_uuids[i - UI_HISTORY_START]);
	buffer->reserved_u64_1 = 0;
	buffer->flags = cpu_to_be32(flags);
	buffer->magic = cpu_to_be32(DRBD_MD_MAGIC_84_UNCLEAN);
	buffer->md_size_sect = cpu_to_be32(md->md_size_sect);
	buffer->al_offset = cpu_to_be32(md->al_offset);
	buffer->al_nr_extents = cpu_to_be32(device->act_log->nr_elements);
	buffer->bm_offset = cpu_to_be32(md->bm_offset);
	buffer->bm_bytes_per_bit = cpu_to_be32(BM_BLOCK_SIZE_4k); /* treat as magic number */
	buffer->la_peer_max_bio_size = cpu_to_be32(device->device_conf.max_bio_size);

	buffer->al_stripes = cpu_to_be32(md->al_stripes);
	buffer->al_stripe_size_4k = cpu_to_be32(md->al_stripe_size_4k);
}


/*
 * This is DRBD 8 userspace compatibility mode, so we do not have a node ID
 * yet. We derive our own node ID from the peer node ID. drbdsetup gives us the
 * peer-node-id, which it determines by comparing the IP addresses.
 */
int drbd_setup_node_ids_84(struct drbd_connection *connection, struct drbd_path *path,
			    unsigned int peer_node_id)
{
	int vnr, my_node_id, nr_legacy = 0, nr_v9 = 0;
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;

	my_node_id = !peer_node_id;
	idr_for_each_entry(&resource->devices, device, vnr) {
		if (test_bit(LEGACY_84_MD, &device->flags)) {
			nr_legacy++;
		} else {
			nr_v9++;
			if (get_ldev(device)) {
				int md_my_node_id = device->ldev->md.node_id;

				put_ldev(device);
				if (my_node_id != md_my_node_id) {
					drbd_err(connection, "inconsistent node_ids %d %d\n",
						 my_node_id, md_my_node_id);
					return -ENOTUNIQ;
				}
			}
		}
	}

	if (nr_legacy && nr_v9)
		drbd_warn(connection, "legacy-84 and drbd-9 metadata in one resource\n");

	drbd_info(connection, "drbd8 userspace compat mode: setting my node id to %d\n",
		  my_node_id);

	/* setting up all node_ids*/
	resource->res_opts.node_id = my_node_id;
	connection->peer_node_id = peer_node_id;
	idr_for_each_entry(&resource->devices, device, vnr) {
		peer_device = list_first_entry_or_null(&device->peer_devices,
						       struct drbd_peer_device, peer_devices);
		peer_device->node_id = peer_node_id;
		peer_device->bitmap_index = 0;

		if (get_ldev(device)) {
			const struct drbd_peer_md clear = { .bitmap_index = -1 };
			struct drbd_md *md = &device->ldev->md;
			struct drbd_peer_md *to = &md->peers[peer_node_id];
			int i;

			md->node_id = my_node_id;

			for (i = 0; i < DRBD_NODE_ID_MAX; i++) {
				struct drbd_peer_md *from = &md->peers[i];

				if (from->bitmap_index != -1) {
					if (from != to) {
						*to = *from;
						*from = clear;
					}
					break;
				}
			}
			put_ldev(device);
		}
	}

	return 0;
}


/*
 * Some resources may be operating in "DRBD 8 compatibility mode", where the
 * user created the resource using the old drbd8-style drbdsetup command line
 * syntax.
 * This implies that the user probably also expects the old drbd8-style
 * /proc/drbd output showing the device state.
 * If the flag is set for a resource, we show the old-style output for that
 * resource.
 * If any resource is in DRBD 8 compatibility mode, this function returns true.
 */
bool drbd_show_legacy_device(struct seq_file *seq, void *v)
{
	struct drbd_device *device;
	int i, prev_i = -1;

	if (!nr_drbd8_devices)
		return false;

	rcu_read_lock();
	idr_for_each_entry(&drbd_devices, device, i) {
		if (!device->resource->res_opts.drbd8_compat_mode)
			continue;

		if (prev_i != i - 1)
			seq_putc(seq, '\n');
		prev_i = i;

		seq_print_device_proc_drbd(seq, device);
	}
	rcu_read_unlock();
	return true;
}

static void seq_printf_with_thousands_grouping(struct seq_file *seq, long v)
{
	/* v is in kB/sec. We don't expect TiByte/sec yet. */
	if (unlikely(v >= 1000000)) {
		/* cool: > GiByte/s */
		seq_printf(seq, "%ld,", v / 1000000);
		v %= 1000000;
		seq_printf(seq, "%03ld,%03ld", v/1000, v % 1000);
	} else if (likely(v >= 1000))
		seq_printf(seq, "%ld,%03ld", v/1000, v % 1000);
	else
		seq_printf(seq, "%ld", v);
}

static void drbd_get_syncer_progress(struct drbd_peer_device *pd,
		enum drbd_repl_state repl_state, unsigned long *rs_total,
		unsigned long *bits_left, unsigned int *per_mil_done)
{
	/* this is to break it at compile time when we change that, in case we
	 * want to support more than (1<<32) bits on a 32bit arch.
	 */
	typecheck(unsigned long, pd->rs_total);
	*rs_total = pd->rs_total;

	/* note: both rs_total and rs_left are in bits, i.e. in
	 * units of BM_BLOCK_SIZE.
	 * for the percentage, we don't care.
	 */

	if (repl_state == L_VERIFY_S || repl_state == L_VERIFY_T)
		*bits_left = atomic64_read(&pd->ov_left);
	else
		*bits_left = drbd_bm_total_weight(pd) - pd->rs_failed;
	/* >> 10 to prevent overflow,
	 * +1 to prevent division by zero
	 */
	if (*bits_left > *rs_total) {
		/* D'oh. Maybe a logic bug somewhere.  More likely just a race
		 * between state change and reset of rs_total.
		 */
		*bits_left = *rs_total;
		*per_mil_done = *rs_total ? 0 : 1000;
	} else {
		/* Make sure the division happens in long context.
		 * We allow up to one petabyte storage right now,
		 * at a granularity of 4k per bit that is 2**38 bits.
		 * After shift right and multiplication by 1000,
		 * this should still fit easily into a 32bit long,
		 * so we don't need a 64bit division on 32bit arch.
		 * Note: currently we don't support such large bitmaps on 32bit
		 * arch anyways, but no harm done to be prepared for it here.
		 */
		unsigned int shift = *rs_total > UINT_MAX ? 16 : 10;
		unsigned long left = *bits_left >> shift;
		unsigned long total = 1UL + (*rs_total >> shift);
		unsigned long tmp = 1000UL - left * 1000UL/total;
		*per_mil_done = tmp;
	}
}

static void drbd_syncer_progress(struct drbd_peer_device *pd, struct seq_file *seq,
		enum drbd_repl_state repl_state)
{
	unsigned long db, dt, dbdt, rt, rs_total, rs_left;
	unsigned int res;
	int i, x, y;
	int stalled = 0;
	unsigned int bm_block_shift = pd->device->last_bm_block_shift;

	drbd_get_syncer_progress(pd, repl_state, &rs_total, &rs_left, &res);

	x = res/50;
	y = 20-x;
	seq_puts(seq, "\t[");
	for (i = 1; i < x; i++)
		seq_putc(seq, '=');
	seq_putc(seq, '>');
	for (i = 0; i < y; i++)
		seq_putc(seq, '.');
	seq_puts(seq, "] ");

	if (repl_state == L_VERIFY_S || repl_state == L_VERIFY_T)
		seq_puts(seq, "verified:");
	else
		seq_puts(seq, "sync'ed:");
	seq_printf(seq, "%3u.%u%% ", res / 10, res % 10);

	/* if more than a few GB, display in MB */
	if (rs_total > (4UL << (30 - bm_block_shift)))
		seq_printf(seq, "(%llu/%llu)M",
			    bit_to_kb(rs_left >> 10, bm_block_shift),
			    bit_to_kb(rs_total >> 10, bm_block_shift));
	else
		seq_printf(seq, "(%llu/%llu)K",
			    bit_to_kb(rs_left, bm_block_shift),
			    bit_to_kb(rs_total, bm_block_shift));

	seq_puts(seq, "\n\t");

	/* see drivers/md/md.c
	 * We do not want to overflow, so the order of operands and
	 * the * 100 / 100 trick are important. We do a +1 to be
	 * safe against division by zero. We only estimate anyway.
	 *
	 * dt: time from mark until now
	 * db: blocks written from mark until now
	 * rt: remaining time
	 */
	/* Rolling marks. last_mark+1 may just now be modified.  last_mark+2 is
	 * at least (DRBD_SYNC_MARKS-2)*DRBD_SYNC_MARK_STEP old, and has at
	 * least DRBD_SYNC_MARK_STEP time before it will be modified.
	 */
	/* ------------------------ ~18s average ------------------------ */
	i = (pd->rs_last_mark + 2) % DRBD_SYNC_MARKS;
	dt = (jiffies - pd->rs_mark_time[i]) / HZ;
	if (dt > 180)
		stalled = 1;

	if (!dt)
		dt++;
	db = pd->rs_mark_left[i] - rs_left;
	rt = (dt * (rs_left / (db/100+1)))/100; /* seconds */

	seq_printf(seq, "finish: %lu:%02lu:%02lu",
		rt / 3600, (rt % 3600) / 60, rt % 60);

	dbdt = bit_to_kb(db/dt, bm_block_shift);
	seq_puts(seq, " speed: ");
	seq_printf_with_thousands_grouping(seq, dbdt);
	seq_puts(seq, " (");
	/* ------------------------- ~3s average ------------------------ */
	if (1) {
		/* this is what drbd_rs_should_slow_down() uses */
		i = (pd->rs_last_mark + DRBD_SYNC_MARKS-1) % DRBD_SYNC_MARKS;
		dt = (jiffies - pd->rs_mark_time[i]) / HZ;
		if (!dt)
			dt++;
		db = pd->rs_mark_left[i] - rs_left;
		dbdt = bit_to_kb(db/dt, bm_block_shift);
		seq_printf_with_thousands_grouping(seq, dbdt);
		seq_puts(seq, " -- ");
	}

	/* --------------------- long term average ---------------------- */
	/* mean speed since syncer started we do account for PausedSync periods */
	dt = (jiffies - pd->rs_start - pd->rs_paused) / HZ;
	if (dt == 0)
		dt = 1;
	db = rs_total - rs_left;
	dbdt = bit_to_kb(db/dt, bm_block_shift);
	seq_printf_with_thousands_grouping(seq, dbdt);
	seq_putc(seq, ')');

	if (repl_state == L_SYNC_TARGET ||
	    repl_state == L_VERIFY_S) {
		seq_puts(seq, " want: ");
		seq_printf_with_thousands_grouping(seq, pd->c_sync_rate);
	}
	seq_printf(seq, " K/sec%s\n", stalled ? " (stalled)" : "");

	{
		/* 64 bit: we convert to sectors in the display below. */
		unsigned long bm_bits = drbd_bm_bits(pd->device);
		unsigned long bit_pos;
		unsigned long long stop_sector = 0;

		if (repl_state == L_VERIFY_S ||
		    repl_state == L_VERIFY_T) {
			bit_pos = bm_bits - (unsigned long)atomic64_read(&pd->ov_left);
			if (verify_can_do_stop_sector(pd))
				stop_sector = pd->ov_stop_sector;
		} else
			bit_pos = pd->resync_next_bit;
		/* Total sectors may be slightly off for oddly sized devices. So what. */
		seq_printf(seq,
			"\t%3d%% sector pos: %llu/%llu",
			(int)(bit_pos / (bm_bits/100+1)),
			(unsigned long long)bit_pos * sect_per_bit(bm_block_shift),
			(unsigned long long)bm_bits * sect_per_bit(bm_block_shift));
		if (stop_sector != 0 && stop_sector != ULLONG_MAX)
			seq_printf(seq, " stop sector: %llu", stop_sector);
		seq_putc(seq, '\n');
	}
}

static const char *drbd_conn_str_84(enum drbd_conn_state s)
{
	/* enums are unsigned... */
	return (int)s > (int)L_BEHIND ? "TOO_LARGE" : drbd_conn_s_names[s];
}


static int seq_print_device_proc_drbd(struct seq_file *m, struct drbd_device *device)
{
	unsigned int send_kb, recv_kb, pending_cnt, unacked_cnt, epochs;
	struct drbd_connection *connection = NULL;
	struct drbd_peer_device *peer_device;
	union drbd_state state;
	const char *sn;
	char wp;

	peer_device = list_first_or_null_rcu(&device->peer_devices, struct drbd_peer_device,
					     peer_devices);

	if (peer_device) {
		state = drbd_get_peer_device_state(peer_device, NOW);
		connection = peer_device->connection;
		send_kb = peer_device->send_cnt/2;
		recv_kb = peer_device->recv_cnt/2;
		pending_cnt = atomic_read(&peer_device->ap_pending_cnt) +
			atomic_read(&peer_device->rs_pending_cnt);
		unacked_cnt = atomic_read(&peer_device->unacked_cnt);
	} else {
		state = drbd_get_device_state(device, NOW);
		connection = list_first_or_null_rcu(&device->resource->connections,
						    struct drbd_connection, connections);
		send_kb = 0;
		recv_kb = 0;
		pending_cnt = 0;
		unacked_cnt = 0;
	}
	if (connection) {
		struct net_conf *nc = rcu_dereference(connection->transport.net_conf);

		wp = nc ? nc->wire_protocol - DRBD_PROT_A + 'A' : ' ';
		epochs = connection->epochs;
	} else {
		wp = 'C';
		epochs = 0;
	}

	sn = drbd_conn_str_84(state.conn);

	if (state.conn == C_STANDALONE &&
	    state.disk == D_DISKLESS &&
	    state.role == R_SECONDARY) {
		seq_printf(m, "%2d: cs:Unconfigured\n", device->minor);
	} else {
		seq_printf(m,
			   "%2d: cs:%s ro:%s/%s ds:%s/%s %c %c%c%c%c%c%c\n"
			   "    ns:%u nr:%u dw:%u dr:%u al:%u bm:%u "
			   "lo:%d pe:%d ua:%d ap:%d ep:%d wo:%c",
			   device->minor, sn,
			   drbd_role_str(state.role),
			   drbd_role_str(state.peer),
			   drbd_disk_str(state.disk),
			   drbd_disk_str(state.pdsk),
			   wp,
			   drbd_suspended(device) ? 's' : 'r',
			   state.aftr_isp ? 'a' : '-',
			   state.peer_isp ? 'p' : '-',
			   state.user_isp ? 'u' : '-',
			   '-' /* congestion reason... FIXME */,
			   test_bit(AL_SUSPENDED, &device->flags) ? 's' : '-',
			   send_kb,
			   recv_kb,
			   device->writ_cnt/2,
			   device->read_cnt/2,
			   device->al_writ_cnt,
			   device->bm_writ_cnt,
			   atomic_read(&device->local_cnt),
			   pending_cnt,
			   unacked_cnt,
			   atomic_read(&device->ap_bio_cnt[WRITE]) +
			   atomic_read(&device->ap_bio_cnt[READ]),
			   epochs,
			   write_ordering_chars[device->resource->write_ordering]
			);
		seq_printf(m, " oos:%llu\n",
			   peer_device ?
				device_bit_to_kb(device, drbd_bm_total_weight(peer_device)) : 0);
	}
	if (state.conn == L_SYNC_SOURCE ||
	    state.conn == L_SYNC_TARGET ||
	    state.conn == L_VERIFY_S ||
	    state.conn == L_VERIFY_T)
		drbd_syncer_progress(peer_device, m, state.conn);

	/* drbd_proc_details 1 or 2 missing */

	return 0;
}
