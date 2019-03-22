/*
   erasure_code_gf16.h

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2004-2019, LINBIT Information Technologies GmbH.
   Copyright (C) 2004-2019, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2004-2019, Lars Ellenberg <lars.ellenberg@linbit.com>.
   Copyright (C) 2019, Joel Colledge <joel.colledge@linbit.com>.

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

extern void erasure_code_gf16_init(void);

extern void erasure_code_gf16_encode(void);

extern void erasure_code_gf16_decode(int plast, unsigned rm);
