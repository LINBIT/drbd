/*
-*- linux-c -*-
   drbd_receiver.c
   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2001-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 1999-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

#ifndef _DRBD_VLI_H
#define _DRBD_VLI_H

/*
 * At a granularity of 4KiB storage represented per bit,
 * and stroage sizes of several TiB,
 * and possibly small-bandwidth replication,
 * the bitmap transfer time can take much too long,
 * if transmitted in plain text.
 *
 * We try to reduce the transfered bitmap information
 * by encoding runlengths of bit polarity.
 *
 * We never actually need to encode a "zero" (runlengths are positive).
 * But then we have to store the value of the first bit.
 * So we can as well have the "zero" be a valid runlength,
 * and start encoding/decoding by "number of _set_ bits" by convention.
 *
 * We assume that large areas are either completely set or unset,
 * which gives good compression with any runlength method,
 * even when encoding the runlength as fixed size 32bit/64bit integers.
 *
 * Still, there may be areas where the polarity flips every few bits,
 * and encoding the runlength sequence of those ares with fix size
 * integers would be much worse than plaintext.
 *
 * We want to encode small runlength values with minimum code length,
 * while still being able to encode a Huge run of all zeros.
 *
 * Thus we need a Variable Length Integer encoding, VLI.
 *
 * For runlength < 8, we produce more code bits than plaintext input.
 * we need to send incompressible chunks as plaintext, skip over them
 * and then see if the next chunk compresses better.
 *
 * We don't care too much about "excellent" compression ratio
 * for large runlengths, 249 bit/24 bit still gives a factor of > 10.
 *
 * We care for cpu time needed to actually encode/decode
 * into the transmitted byte stream.
 *
 * There are endless variants of VLI.
 * For this special purpose, we just need something that is "good enough",
 * and easy to understand and code, fast to encode and decode,
 * and does not consume memory.
 */

/*
 * buf points to the current position in the tranfered byte stream.
 * stream is by definition little endian.
 * *buf_len gives the remaining number of bytes at that position.
 * *out will receive the decoded value.
 * returns number of bytes consumed,
 * or 0 if not enough bytes left in buffer (which would be invalid input).
 */
static inline int vli_decode_bytes(u64 *out, unsigned char *buf, unsigned buf_len)
{
	u64 tmp = 0;
	unsigned bytes; /* extra bytes after code byte */

	if (buf_len == 0)
		return 0;

	switch(*buf) {
	case 0xff: bytes = 8; break;
	case 0xfe: bytes = 7; break;
	case 0xfd: bytes = 6; break;
	case 0xfc: bytes = 5; break;
	case 0xfb: bytes = 4; break;
	case 0xfa: bytes = 3; break;
	case 0xf9: bytes = 2; break;
	default:
		*out = *buf;
		return 1;
	}

	if (buf_len <= bytes)
		return 0;

	/* no pointer cast assignment, there may be funny alignment
	 * requirements on certain architectures */
	memcpy(&tmp, buf+1, bytes);
	*out = le64_to_cpu(tmp);
	return bytes+1;
}

/*
 * similarly, encode n into buf.
 * returns consumed bytes,
 * or zero if not enough room left in buffer
 * (in which case the buf is left unchanged).
 *
 * encoding is little endian, first byte codes how much bytes follow.
 * first byte <= 0xf8 means just this byte, value = code byte.
 * first byte == 0xf9 .. 0xff: (code byte - 0xf7) data bytes follow.
 */
static inline int vli_encode_bytes(unsigned char *buf, u64 n, unsigned buf_len)
{
	unsigned bytes; /* _extra_ bytes after code byte */

	if (buf_len == 0)
		return 0;

	if (n <= 0xf8) {
		*buf = (unsigned char)n;
		return 1;
	}

	bytes = (n < (1ULL << 32))
	      ? (n < (1ULL << 16)) ? 2
	      : (n < (1ULL << 24)) ? 3 : 4
	      : (n < (1ULL << 48)) ?
		(n < (1ULL << 40)) ? 5 : 6
	      : (n < (1ULL << 56)) ? 7 : 8;

	if (buf_len <= bytes)
		return 0;

	/* no pointer cast assignment, there may be funny alignment
	 * requirements on certain architectures */
	*buf++ = 0xf7 + bytes; /* code, 0xf9 .. 0xff */
	n = cpu_to_le64(n);
	memcpy(buf, &n, bytes); /* plain */
	return bytes+1;
}

#undef VLI_LEVELS
#endif
