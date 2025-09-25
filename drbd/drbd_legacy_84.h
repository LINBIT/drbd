// SPDX-License-Identifier: GPL-2.0-only

#ifndef __DRBD_LEGACY_84_H
#define __DRBD_LEGACY_84_H

#include "drbd_int.h"

struct meta_data_on_disk_84;

void drbd_md_decode_84(struct meta_data_on_disk_84 *on_disk, struct drbd_md *md,
		       int *max_peers, int *bytes_per_bit);
void drbd_md_encode_84(struct drbd_device *device, struct meta_data_on_disk_84 *buffer);
void drbd_setup_node_ids_84(struct drbd_connection *connection, struct drbd_path *path);

#endif  /* __DRBD_LEGACY_84_H */
