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

#define REL_VERSION "0.7-pre4"
#define API_VERSION 71
#define PRO_VERSION 71

//#define DBG_ALL_SYMBOLS // no static functs, improves quality of OOPS traces
//#define DBG_SPINLOCKS   // enables MUST_HOLD macro (assertions for spinlocks)
//#define DBG_ASSERTS     // drbd_assert_breakpoint() function
//#define DBG_BH_SECTOR   // enables chekcs in BH_SECTOR macro

#endif
