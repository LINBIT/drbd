/* SPDX-License-Identifier: GPL-2.0-only */
/*
  drbd_config.h
  DRBD's compile time configuration.
*/

#ifndef DRBD_CONFIG_H
#define DRBD_CONFIG_H

#include <drbd_protocol.h>

const char *drbd_buildtag(void);

#define REL_VERSION "9.2.15-xen.1"
#define PRO_VERSION_MIN 118 /* 9.0.26 */
#define PRO_VERSION_MAX 123
#define PRO_FEATURES (DRBD_FF_TRIM | DRBD_FF_THIN_RESYNC | DRBD_FF_WSAME | DRBD_FF_WZEROES | \
		      DRBD_FF_RESYNC_DAGTAG | \
		      DRBD_FF_2PC_V2 | DRBD_FF_RS_SKIP_UUID)

#define PRO_VERSION_8_MIN 86
#define PRO_VERSION_8_MAX 101

/* We support two ranges of DRBD protocol version:
 *  86-101: accepted DRBD 8 protocol versions as "rolling upgrade" path
 * 102-109: never defined
 * 110-117: _rejected_ because of bugs in the backward compat path
 *	in more recent DRBD versions.  That is 9.0.0 to 9.0.25 inclusive.
 *	"Rolling" upgrade path for those versions:
 *	first upgrade to 9.0.latest, then connect to 9.1/9.2 or later.
 * 118-PRO_VERSION_MAX: accepted DRBD 9 protocol versions.
 */

#endif
