/* SPDX-License-Identifier: GPL-2.0-only */
/*
  drbd_config.h
  DRBD's compile time configuration.

*/

#ifndef DRBD_CONFIG_H
#define DRBD_CONFIG_H

extern const char *drbd_buildtag(void);

#define REL_VERSION "9.2.1"
#define PRO_VERSION_MIN 86
#define PRO_VERSION_MAX 121

/* some extra checks
#define PARANOIA
 */

/* Enable fault insertion code */
#ifndef CONFIG_DRBD_FAULT_INJECTION
#define CONFIG_DRBD_FAULT_INJECTION 1
#endif

/* CONFIG_KREF_DEBUG has to be enabled in Kbuild */

/* Do not enable CONFIG_DRBD_TIMING_STATS */

#endif
