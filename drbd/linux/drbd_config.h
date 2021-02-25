// SPDX-License-Identifier: GPL-2.0-or-later
/*
  drbd_config.h
  DRBD's compile time configuration.

*/

#ifndef DRBD_CONFIG_H
#define DRBD_CONFIG_H

extern const char *drbd_buildtag(void);

/* Necessary to build the external module against >= Linux-2.6.33 */
#ifdef REL_VERSION
#undef REL_VERSION
#undef API_VERSION
#undef PRO_VERSION_MIN
#undef PRO_VERSION_MAX
#endif

/* End of external module for 2.6.33 stuff */

#define REL_VERSION "9.0.28-1"
#define PRO_VERSION_MIN 86
#define PRO_VERSION_MAX 119

#ifndef __CHECKER__   /* for a sparse run, we need all STATICs */
#define DBG_ALL_SYMBOLS /* no static functs, improves quality of OOPS traces */
#endif

/* Dump all cstate changes */
#define DUMP_MD 2

/* some extra checks
#define PARANOIA
 */

/* Enable fault insertion code */
#ifndef CONFIG_DRBD_FAULT_INJECTION
#define CONFIG_DRBD_FAULT_INJECTION 1
#endif

/* CONFIG_KREF_DEBUG has to be enabled in Kbuild */

/* Do not enable CONFIG_DRBD_TIMING_STATS */

#ifdef __KERNEL__
#include "compat.h"
#endif

#endif
