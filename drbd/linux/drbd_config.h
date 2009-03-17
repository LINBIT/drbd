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

#define REL_VERSION "8.3.1rc1"
#define API_VERSION 88
#define PRO_VERSION_MIN 86
#define PRO_VERSION_MAX 89

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

/* Dump every hour the usage / not usage of zero copy IO */
/* #define SHOW_SENDPAGE_USAGE */

/* Define this to enable dynamic tracing controlled by module parameters
 * at run time. This enables ALL use of dynamic tracing including packet
 * and bio dumping, etc */
#define ENABLE_DYNAMIC_TRACE

/* You can disable the use of the sendpage() call (= zero copy IO)
 * If you have the feeling that this might be the cause for troubles.
#define DRBD_DISABLE_SENDPAGE
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

/* in older kernels (vanilla < 2.6.16) struct netlink_skb_parms has a
 * member called dst_groups. Later it is called dst_group (without 's'). */
//#define DRBD_NL_DST_GROUPS

/* in older kernels (vanilla < 2.6.14) is no kzalloc() */
//#define NEED_BACKPORT_OF_KZALLOC

// some vendor kernels have it, some don't
//#define NEED_SG_SET_BUF
#define HAVE_LINUX_SCATTERLIST_H

/* 2.6.29 and up no longer have swabb.h */
#define HAVE_LINUX_BYTEORDER_SWABB_H

/* Some vendor kernels < 2.6.7 might define msleep in one or
 * another way .. */

#define KERNEL_HAS_MSLEEP

/* Some other kernels < 2.6.8 do not have struct kvec,
 * others do.. */

#define KERNEL_HAS_KVEC

#endif
