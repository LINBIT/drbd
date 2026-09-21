/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2025, LINBIT HA-Solutions GmbH.
 */

#ifndef __DRBD_LEGACY_84_H
#define __DRBD_LEGACY_84_H

#include "drbd_int.h"

struct meta_data_on_disk_84;

/*
 *   drbd-8.4                      drbd-9 md.flags                   drbd-9 peer-md.flags
 * MDF_CONSISTENT      1 << 0  MDF_CONSISTENT =        1 << 0,   MDF_PEER_CONNECTED =    1 << 0,
 * MDF_PRIMARY_IND     1 << 1  MDF_PRIMARY_IND =       1 << 1,   MDF_PEER_OUTDATED =     1 << 1,
 * MDF_CONNECTED_IND   1 << 2                                    MDF_PEER_FENCING =      1 << 2,
 * MDF_FULL_SYNC       1 << 3                                    MDF_PEER_FULL_SYNC =    1 << 3,
 * MDF_WAS_UP_TO_DATE  1 << 4  MDF_WAS_UP_TO_DATE =    1 << 4,   MDF_PEER_DEVICE_SEEN =  1 << 4,
 * MDF_PEER_OUT_DATED  1 << 5                                    MDF_PEER_DIVERGENCE_BITMAP = 1 << 5
 * MDF_CRASHED_PRIMARY 1 << 6  MDF_CRASHED_PRIMARY =   1 << 6,   MDF_PEER_BITMAP_AUTHORITATIVE
 *                                                                                       = 1 << 6
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

/*
 * Mask for the v1 DEVICE_STATISTICS dev_disk_flags and PEER_DEVICE_STATISTICS
 * peer_dev_flags wire attributes (drbd_nl_84.c's compat84_emit_device(),
 * compat84_emit_peer_device() and their compat84_notify_* twins), which copy
 * DRBD 9's raw device_to_statistics()/peer_device_to_statistics() output
 * (drbd_nl.c) onto the wire. These are plain masks, not a peer-bit
 * translation: DRBD 9's md.flags and peer_md.flags keep the same bit
 * positions as mainline 8.4's for every bit 8.4 knows about (peer flags:
 * PEER_DEV_FLAGS_84_MASK, matching mainline drivers/block/drbd/drbd_nl.c's
 * local enum mdf_peer_flag), so masking off DRBD 9's newer bits
 * (MDF_PRIMARY_LOST_QUORUM,
 * MDF_HAVE_QUORUM; MDF_PEER_DEVICE_SEEN, MDF_PEER_DIVERGENCE_BITMAP,
 * MDF_NODE_EXISTS, MDF_HAVE_BITMAP) is enough; nothing needs remapping.
 */
#define PEER_DEV_FLAGS_84_MASK (MDF_PEER_CONNECTED | MDF_PEER_OUTDATED | \
				 MDF_PEER_FENCING | MDF_PEER_FULL_SYNC)

#ifdef CONFIG_DRBD_COMPAT_84
extern atomic_t nr_drbd8_devices;

void drbd_md_decode_84(struct meta_data_on_disk_84 *on_disk, struct drbd_md *md);
void drbd_md_encode_84(struct drbd_device *device, struct meta_data_on_disk_84 *buffer);
int drbd_setup_node_ids_84(struct drbd_connection *connection, struct drbd_path *path,
			   unsigned int peer_node_id);
bool drbd_show_legacy_device(struct seq_file *seq, void *v);
u32 drbd_pack_state_84(struct drbd_device *device);
void drbd_get_syncer_progress_84(struct drbd_peer_device *pd,
		enum drbd_repl_state repl_state, unsigned long *rs_total,
		unsigned long *bits_left, unsigned int *per_mil_done);

/*
 * Remap a DRBD 9 enum drbd_state_rv value to one 8.4 userland's own SS_*
 * string table can render truthfully. SS_UNKNOWN_ERROR (0) through
 * SS_O_VOL_PEER_PRI (-20), every success code and every enum drbd_ret_code
 * are numerically identical in both dialects. From SS_INTERRUPTED (-21)
 * down, DRBD 9 has nine codes 8.4 numbers differently (SS_INTERRUPTED
 * collides with 8.4's SS_OUTDATE_WO_CONN) or lacks entirely (8.4 ends at
 * SS_AFTER_LAST_ERROR = -22); passed through raw they would print a wrong
 * message or "unknown error code". Map each to the nearest 8.4 code whose
 * string does not mislead: the interrupted, timed-out and retried
 * handshake cases to SS_IN_TRANSIENT_STATE ("retry"), a blocking
 * read-only opener to SS_DEVICE_IN_USE, a handshake-forced disconnect to
 * SS_CW_FAILED_BY_PEER, and the quorum, weak-connectivity, bitmap
 * negotiation and sentinel codes, which have no 8.4 meaning, to
 * SS_UNKNOWN_ERROR. compat84_put_outcome() is the only place a
 * drbd_state_rv reaches the v1 wire.
 */
static inline enum drbd_state_rv drbd_state_rv_84(enum drbd_state_rv rv)
{
	switch (rv) {
	case SS_INTERRUPTED:
	case SS_TIMEOUT:
	case SS_HANDSHAKE_RETRY:
		return SS_IN_TRANSIENT_STATE;
	case SS_PRIMARY_READER:
		return SS_DEVICE_IN_USE;
	case SS_HANDSHAKE_DISCONNECT:
		return SS_CW_FAILED_BY_PEER;
	case SS_WEAKLY_CONNECTED:
	case SS_NO_QUORUM:
	case SS_ATTACH_NO_BITMAP:
	case SS_AFTER_LAST_ERROR:
		return SS_UNKNOWN_ERROR;
	default:
		return rv;
	}
}
#else
static inline void drbd_md_decode_84(struct meta_data_on_disk_84 *on_disk, struct drbd_md *md) {};
static inline void drbd_md_encode_84(struct drbd_device *device,
	struct meta_data_on_disk_84 *buffer) {};
static inline int drbd_setup_node_ids_84(struct drbd_connection *connection, struct drbd_path *path,
			   unsigned int peer_node_id) { return 0; };
static inline bool drbd_show_legacy_device(struct seq_file *seq, void *v) { return false; };
static inline u32 drbd_pack_state_84(struct drbd_device *device) { return 0; };
static inline void drbd_get_syncer_progress_84(struct drbd_peer_device *pd,
		enum drbd_repl_state repl_state, unsigned long *rs_total,
		unsigned long *bits_left, unsigned int *per_mil_done) {};
#endif  /* CONFIG_DRBD_COMPAT_84 */

#endif  /* __DRBD_LEGACY_84_H */
