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

extern const char * drbd_buildtag(void);

#define REL_VERSION "0.7.3"
#define API_VERSION 76
#define PRO_VERSION 74

//#define DBG_ALL_SYMBOLS // no static functs, improves quality of OOPS traces

//#define DBG_SPINLOCKS   // enables MUST_HOLD macro (assertions for spinlocks)
//#define DBG_ASSERTS     // drbd_assert_breakpoint() function
//#define DUMP_MD 1       // Dump metadata to syslog upon connect
#define DUMP_MD 2       // Dump even all cstate changes (I like it!)
//#define DUMP_MD 3       // Dump even all meta data access
                          // (don't! unless we track down a bug...)

//#define SIGHAND_HACK           // Needed for RH 2.4.20 and later kernels.
//#define REDHAT_HLIST_BACKPORT  // Makes DRBD work on RH9 kernels
/* Redhat 2.4.18 already includes BH_Launder,
 * other  2.4.18 still have       BH_launder ...
 * most likely we could do without it completely,
 * since it is only used in drbd_ee_bh_prepare().
 * anyways...
 */
//#define REDHAT_2_4_18
/* some redhat 2.4.X-Y.Z.whatever kernel flavours have an mm_inline.h,
 * which needs to be included explicitly. most 2.4.x kernels don't have that
 * header file at all. So uncomment for these, and ignore for all others.
 * in 2.6., it will be included anyways.
 */
//#define HAVE_MM_INLINE_H

//Your 2.4 verndor kernel already defines find_next_bit()
//#define HAVE_FIND_NEXT_BIT

//Your 2.4 kernel does not define find_next_bit(),
//and you are too lazy to "backport" it from 2.6 for your arch:
//#define USE_GENERIC_FIND_NEXT_BIT

//#define PARANOIA // some extra checks

// don't enable this, unless you can cope with gigabyte syslogs :)
//#define DUMP_EACH_PACKET

// Dump every hour the usage / not usage of zero copy IO 
//#define SHOW_SENDPAGE_USAGE

// You can disable the use of the sendpage() call (= zero copy
// IO )  If you have the feeling that this might be the cause
// for troubles.
// #define DRBD_DISABLE_SENDPAGE

#endif
