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
	u32 bm_bytes_per_bit;  /* BM_BLOCK_SIZE */
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

void drbd_md_decode_84(struct meta_data_on_disk_84 *on_disk, struct drbd_md *md,
		       int *max_peers, int *bytes_per_bit)
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

	*max_peers = 1;
	*bytes_per_bit = be32_to_cpu(on_disk->bm_bytes_per_bit);
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
	buffer->bm_bytes_per_bit = cpu_to_be32(BM_BLOCK_SIZE);
	buffer->la_peer_max_bio_size = cpu_to_be32(device->device_conf.max_bio_size);

	buffer->al_stripes = cpu_to_be32(md->al_stripes);
	buffer->al_stripe_size_4k = cpu_to_be32(md->al_stripe_size_4k);
}


static int compare_sockaddr(struct sockaddr_storage *a_sockaddr,
			    struct sockaddr_storage *b_sockaddr)
{
	if (a_sockaddr->ss_family < b_sockaddr->ss_family)
		return -1;
	if (a_sockaddr->ss_family > b_sockaddr->ss_family)
		return 1;
	if (a_sockaddr->ss_family == AF_INET) {
		struct sockaddr_in *a4_sockaddr = (struct sockaddr_in *)a_sockaddr;
		struct sockaddr_in *b4_sockaddr = (struct sockaddr_in *)b_sockaddr;
		int cmp = memcmp(&a4_sockaddr->sin_addr, &b4_sockaddr->sin_addr,
									sizeof(struct in_addr));
		if (cmp)
			return cmp;
		if (a4_sockaddr->sin_port < b4_sockaddr->sin_port)
			return -1;
		if (a4_sockaddr->sin_port > b4_sockaddr->sin_port)
			return 1;
		return 0;
	} else if (a_sockaddr->ss_family == AF_INET6) {
		struct sockaddr_in6 *a6_sockaddr = (struct sockaddr_in6 *)a_sockaddr;
		struct sockaddr_in6 *b6_sockaddr = (struct sockaddr_in6 *)b_sockaddr;
		int cmp = memcmp(&a6_sockaddr->sin6_addr, &b6_sockaddr->sin6_addr,
									sizeof(struct in6_addr));
		if (!cmp)
			return cmp;
		if (a6_sockaddr->sin6_port < b6_sockaddr->sin6_port)
			return -1;
		if (a6_sockaddr->sin6_port > b6_sockaddr->sin6_port)
			return 1;
		return 0;
	}
	pr_err("drbd: %s: Invalid sockaddr family %ul\n", __func__, a_sockaddr->ss_family);
	return 1;
}

/*
 * This is drbd 8 userspace compat mode, so we do not have a node_id yet. Since
 * we only ever have two peers, we can arbitrate our node ids by comparing IP
 * addresses. The lower address gets node id 0, the other one gets 1.
 */
void drbd_setup_node_ids_84(struct drbd_connection *connection, struct drbd_path *path)
{
	int vnr, cmp, peer_node_id, my_node_id = -1, nr_legacy = 0, nr_v9 = 0;
	struct drbd_resource *resource = connection->resource;
	struct drbd_peer_device *peer_device;
	struct drbd_device *device;

	idr_for_each_entry(&resource->devices, device, vnr) {
		if (test_bit(LEGACY_84_MD, &device->flags)) {
			nr_legacy++;
		} else {
			nr_v9++;
			if (get_ldev(device)) {
				if (my_node_id == -1)
					my_node_id = device->ldev->md.node_id;
				else if (my_node_id != device->ldev->md.node_id)
					drbd_err(connection, "inconsistent node_ids\n");
				put_ldev(device);
			}
		}
	}

	if (nr_legacy && nr_v9)
		drbd_err(connection, "legacy-84 and drbd-9 metadata in one resource\n");

	if (my_node_id == -1) {
		cmp = compare_sockaddr(&path->my_addr, &path->peer_addr);
		D_ASSERT(connection, cmp != 0); /* addresses cannot be equal */
		my_node_id = cmp == 1;
		drbd_info(connection, "drbd8 userspace compat mode: setting my node id to %d\n",
			  my_node_id);
	}
	peer_node_id = !my_node_id;

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
}
