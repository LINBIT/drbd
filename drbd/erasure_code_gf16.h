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

typedef unsigned char gf_t;
typedef long long word_t  __attribute__ ((__vector_size__ (32)));

#define GF_M 4
#define GF_Q (1 << GF_M)

#define NMAX GF_Q
#define RMAX (NMAX / 2)

#define BS 4096

#define SS (BS / GF_M)
#define WS sizeof(word_t)
#define SLEN (SS / WS)

typedef word_t slice_t[SLEN];
typedef slice_t block_t[GF_M];

struct erasure_code {
	int disk_count_total;
	int disk_count_data;
	gf_t generator_matrix[NMAX * NMAX];
};

extern void erasure_code_gf16_init(struct erasure_code *ec);

extern void erasure_code_gf16_encode(struct erasure_code *ec, block_t **data_blocks, int block_index, int parity_number, block_t *parity_out);

extern void erasure_code_gf16_decode(struct erasure_code *ec, block_t **data_blocks, int block_index, int plast, unsigned rmask);
