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

#define REL_VERSION "0.7-pre10 cvs $Date: 2004/07/09 18:29:24 $"
#define API_VERSION 74
#define PRO_VERSION 73 /* actually already 74, but I expect some more
			* protocol changes, maybe even an additional packet
			* soonish... */

//#define DBG_ALL_SYMBOLS // no static functs, improves quality of OOPS traces

//#define DBG_SPINLOCKS   // enables MUST_HOLD macro (assertions for spinlocks)
//#define DBG_ASSERTS     // drbd_assert_breakpoint() function
//#define DUMP_MD 1       // Dump metadata to syslog upon connect
//#define DUMP_MD 2       // Dump even all cstate changes (I like it!)
//#define DUMP_MD 3       // Dump even all meta data access
                          // (don't! unless we track down a bug...)

//#define SIGHAND_HACK           // Needed for RH 2.4.20 and later kernels.
//#define REDHAT_HLIST_BACKPORT  // Makes DRBD work on RH9 kernels

//Your 2.4 verndor kernel already defines find_next_bit()
//#define HAVE_FIND_NEXT_BIT

//Your 2.4 kernel does not define find_next_bit(),
//and you are too lazy to "backport" it from 2.6 for your arch:
//#define USE_GENERIC_FIND_NEXT_BIT

#define PARANOIA // some extra checks

// don't enable this, unless you can cope with gigabyte syslogs :)
//#define DUMP_EACH_PACKET

#endif
