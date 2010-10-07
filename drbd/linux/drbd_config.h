/*
  drbd_config.h
  DRBD's compile time configuration.

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

#ifndef DRBD_DEBUG_MD_SYNC
#define DRBD_DEBUG_MD_SYNC
#endif

/* End of external module for 2.6.33 stuff */

#define REL_VERSION "8.3.8"
#define API_VERSION 88
#define PRO_VERSION_MIN 86
#define PRO_VERSION_MAX 95

#ifndef __CHECKER__   /* for a sparse run, we need all STATICs */
#define DBG_ALL_SYMBOLS /* no static functs, improves quality of OOPS traces */
#endif

/* drbd_assert_breakpoint() function
#define DBG_ASSERTS
 */

/* Dump all cstate changes */
#define DUMP_MD 2

/* some extra checks
#define PARANOIA
 */

/* Enable fault insertion code */
#define DRBD_ENABLE_FAULTS

/* RedHat's 2.6.9 kernels have the gfp_t type. Mainline has this feature
 * since 2.6.16. If you build for RedHat enable the line below. */
#define KERNEL_HAS_GFP_T

/* kernel.org has atomic_add_return since 2.6.10. some vendor kernels
 * have it backported, though. Others don't. */
//#define NEED_BACKPORT_OF_ATOMIC_ADD

/* 2.6.something has deprecated kmem_cache_t
 * some older still use it.
 * some have it defined as struct kmem_cache_s, some as struct kmem_cache */
//#define USE_KMEM_CACHE_S

/* 2.6.something has sock_create_kern (SE-linux security context stuff)
 * some older distribution kernels don't. */
//#define DEFINE_SOCK_CREATE_KERN

/* 2.6.24 and later have kernel_sock_shutdown.
 * some older distribution kernels may also have a backport. */
//#define DEFINE_KERNEL_SOCK_SHUTDOWN

/* in older kernels (vanilla < 2.6.16) struct netlink_skb_parms has a
 * member called dst_groups. Later it is called dst_group (without 's'). */
//#define DRBD_NL_DST_GROUPS

/* in older kernels (vanilla < 2.6.14) is no kzalloc() */
//#define NEED_BACKPORT_OF_KZALLOC

// some vendor kernels have it, some don't
//#define NEED_SG_SET_BUF
#define HAVE_LINUX_SCATTERLIST_H

/* 2.6.29 and up no longer have swabb.h */
//#define HAVE_LINUX_BYTEORDER_SWABB_H

/* some vendor kernel have it backported. */
#define HAVE_SET_CPUS_ALLOWED_PTR

/* Some vendor kernels < 2.6.7 might define msleep in one or
 * another way .. */

#define KERNEL_HAS_MSLEEP

/* Some other kernels < 2.6.8 do not have struct kvec,
 * others do.. */

#define KERNEL_HAS_KVEC

/* Actually availabe since 2.6.26, but vendors have backported...
 */
#define KERNEL_HAS_PROC_CREATE_DATA

/* In 2.6.32 we finally fixed connector to pass netlink_skb_parms to the callback
 */
#define KERNEL_HAS_CN_SKB_PARMS

/* In the 2.6.34 mergewindow blk_queue_max_sectors() got blk_queue_max_hw_sectors() and
   blk_queue_max_(phys|hw)_segments() got blk_queue_max_segments()
   See Linux commits: 086fa5ff0854c676ec333 8a78362c4eefc1deddbef */
//#define NEED_BLK_QUEUE_MAX_HW_SECTORS
//#define NEED_BLK_QUEUE_MAX_SEGMENTS

/* some old kernels do not have atomic_add_unless() */
//#define NEED_ATOMIC_ADD_UNLESS

/* some old kernels do not have the bool type */
//#define NEED_BOOL_TYPE

#endif
