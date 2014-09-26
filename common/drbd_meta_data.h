#ifndef DRBD_META_DATA_H
#define DRBD_META_DATA_H

#ifdef __KERNEL__
#define be_u64 u64
#define be_u32 u32
#define be_s32 s32
#define be_u16 u16
#else
#define be_u64 struct { uint64_t be; }
#define be_u32 struct { uint32_t be; }
#define be_s32 struct { int32_t be; }
#define be_u16 struct { uint16_t be; }
#endif

struct peer_dev_md_on_disk_9 {
	be_u64 bitmap_uuid;
	be_u64 bitmap_dagtag;
	be_u32 flags;
	be_s32 bitmap_index;
	be_u32 reserved_u32[2];
} __packed;

struct meta_data_on_disk_9 {
	be_u64 effective_size;    /* last agreed size */
	be_u64 current_uuid;
	be_u64 reserved_u64[4];   /* to have the magic at the same position as in v07, and v08 */
	be_u64 device_uuid;
	be_u32 flags;             /* MDF */
	be_u32 magic;
	be_u32 md_size_sect;
	be_u32 al_offset;         /* offset to this block */
	be_u32 al_nr_extents;     /* important for restoring the AL */
	be_u32 bm_offset;         /* offset to the bitmap, from here */
	be_u32 bm_bytes_per_bit;  /* BM_BLOCK_SIZE */
	be_u32 la_peer_max_bio_size;   /* last peer max_bio_size */
	be_u32 bm_max_peers;
	be_s32 node_id;

	/* see al_tr_number_to_on_disk_sector() */
	be_u32 al_stripes;
	be_u32 al_stripe_size_4k;

	be_u32 reserved_u32[2];

	struct peer_dev_md_on_disk_9 peers[DRBD_PEERS_MAX];
	be_u64 history_uuids[HISTORY_UUIDS];

	char padding[0] __attribute__((aligned(4096)));
} __packed;


#undef be_u64
#undef be_u32
#undef be_s32
#undef be_u16

#endif
