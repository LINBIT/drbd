/*
   drbdmeta.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 1999-2004, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

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

/* have the <sys/....h> first, otherwise you get e.g. "redefined" types from
 * sys/types.h and other weird stuff */

#define _GNU_SOURCE
#define __USE_LARGEFILE64

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <linux/fs.h>		/* for BLKGETSIZE64 */
#include <linux/drbd.h>		/* only use DRBD_MAGIC from here! */

#include "drbdtool_common.h"
#include "drbd_endian.h"

/* FIXME? should use sector_t and off_t, not long/u64 ... */
/* FIXME? rename open -> mmap, close -> munmap */

/* Note RETURN VALUES:
 * exit code convention: int vXY_something() and meta_blah return some negative
 * error code, usually -1, when failed, 0 for success.
 *
 * FIXME some of the return -1; probably should better be exit(something);
 * or some of the exit() should be rather some return?
 *
 * AND, the exit codes should follow some defined scheme.
 */

/*
 * I think this block of declarations and definitions should be
 * in some common.h, too.
 * {
 */

#ifndef ALIGN
# define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )
#endif

#define MD_AL_OFFSET_07    8
#define MD_AL_MAX_SIZE_07  64
#define MD_BM_OFFSET_07    (MD_AL_OFFSET_07 + MD_AL_MAX_SIZE_07)
#define MD_RESERVED_SIZE_07 ( (u64)128 * (1<<20) )
#define MD_BM_MAX_SIZE_07  ( MD_RESERVED_SIZE_07 - MD_BM_OFFSET_07*512 )

#define DRBD_MD_MAGIC_06   (DRBD_MAGIC+2)
#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)
#define DRBD_MD_MAGIC_08   (DRBD_MAGIC+4)

enum MetaDataFlags {
	__MDF_Consistent,
	__MDF_PrimaryInd,
	__MDF_ConnectedInd,
	__MDF_FullSync,
};
#define MDF_Consistent      (1<<__MDF_Consistent)
#define MDF_PrimaryInd      (1<<__MDF_PrimaryInd)
#define MDF_ConnectedInd    (1<<__MDF_ConnectedInd)
#define MDF_FullSync        (1<<__MDF_FullSync)

enum MetaDataIndex {
	Flags,			/* Consistency flag,connected-ind,primary-ind */
	HumanCnt,		/* human-intervention-count */
	TimeoutCnt,		/* timout-count */
	ConnectedCnt,		/* connected-count */
	ArbitraryCnt,		/* arbitrary-count */
	GEN_CNT_SIZE		/* MUST BE LAST! (and Flags must stay first...) */
};

/*
 * }
 * end of should-be-shared
 */

/*
 * A word about mmap.
 * The reason to use it is that I do not want to malloc 128MB just to
 * read() and then count the bits, especially not within uml.
 * the resulting program code is simpler, too.
 * BUT we have to be carefull not to accidentally touch that memory region,
 * because it would change the on-disk content.
 * We must check for out-of-band access anyways.
 *
 * I chose to have three different mmap'ed areas, because when we move to
 * more flexible layout, this is more flexible, too.
 *
 * The al-sectors can then be indexed directly:
 *   extent = be32_to_cpu(on_disk.al[7].updates[7].extent.be);
 *
 * similar the bitmap:
 *   test_bit(bitnr & (BITS_PER_LONG-1),
 *            le_long_to_cpu(on_disk.bm[bitnr>>BITS_PER_LONG].le));
 *
 *   when counting the bits only, we can ignore endianness.  well, strictly
 *   speaking, we'd need to verify the very last word for oob bits.
 *
 */

unsigned long count_bits(const unsigned long *w, const size_t nr_long_words)
{
	unsigned long bits = 0;
	int i;
	for (i = 0; i < nr_long_words; i++)
		bits += hweight_long(w[i]);
	return bits;
}

/* let gcc help us get it right.
 * some explicit endian types */
typedef struct { u64 le; } le_u64;
typedef struct { u64 be; } be_u64;
typedef struct { u32 le; } le_u32;
typedef struct { u32 be; } be_u32;
typedef struct { unsigned long le; } le_ulong;
typedef struct { unsigned long be; } be_ulong;

/* NOTE that this structure does not need to be packed,
 * aligned, nor does it need to be in the same order as the on_disk variants.
 */
struct md_cpu {
	/* present since drbd 0.6 */
	u32 gc[GEN_CNT_SIZE];	/* generation counter */
	u32 magic;
	/* added in drbd 0.7;
	 * 0.7 stores la_size on disk as kb, 0.8 in units of sectors.
	 * we use sectors in our general working structure here */
	u64 la_sect;		/* last agreed size. */
	u32 md_size;
	u32 al_offset;		/* offset to this block */
	u32 al_nr_extents;	/* important for restoring the AL */
	u32 bm_offset;		/* offset to the bitmap, from here */
	/* more to come eventually */
};

/*
 * FIXME md_size not yet validated or used.
 */

/*
 * -- DRBD 0.6 --------------------------------------
 */

struct __attribute__ ((packed)) md_on_disk_06 {
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
};

void md_disk_06_to_cpu(struct md_cpu *cpu, const struct md_on_disk_06 *disk)
{
	int i;
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
}

void md_cpu_to_disk_06(struct md_on_disk_06 *disk, const struct md_cpu *cpu)
{
	int i;
	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
}

int v06_validate_md(struct md_cpu *md)
{
	if (md->magic != DRBD_MD_MAGIC_06) {
		fprintf(stderr, "v06 Magic number not found\n");
		return -1;
	}
	return 0;
}

/*
 * -- DRBD 0.7 --------------------------------------
 */

struct __attribute__ ((packed)) md_on_disk_07 {
	be_u64 la_kb;		/* last agreed size. */
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
	be_u32 md_size;
	be_u32 al_offset;	/* offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_u32 bm_offset;	/* offset to the bitmap, from here */
	char reserved[8 * 512 - 48];
};

void md_disk_07_to_cpu(struct md_cpu *cpu, const struct md_on_disk_07 *disk)
{
	int i;
	cpu->la_sect = be64_to_cpu(disk->la_kb.be) << 1;
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size = be32_to_cpu(disk->md_size.be);
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
}

void md_cpu_to_disk_07(struct md_on_disk_07 *disk, const struct md_cpu *cpu)
{
	int i;
	disk->la_kb.be = cpu_to_be64(cpu->la_sect >> 1);
	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size.be = cpu_to_be32(cpu->md_size);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	memset(disk->reserved, sizeof(disk->reserved), 0);
}

int v07_validate_md(struct md_cpu *md)
{
	if (md->magic != DRBD_MD_MAGIC_07) {
		fprintf(stderr, "v07 Magic number not found\n");
		return -1;
	}

	if (md->al_offset != MD_AL_OFFSET_07) {
		fprintf(stderr, "v07 Magic number (al_offset) not found\n");
		return -1;
	}

	if (md->bm_offset != MD_BM_OFFSET_07) {
		fprintf(stderr, "v07 Magic number (bm_offset) not found\n");
		return -1;
	}

	/* fixme consistency check, la_size < ll_device_size,
	 * no overlap with internal meta data,
	 * no overlap of flexible meta data offsets/sizes
	 * ...
	 */

	return 0;
}

/*
 * these stay the same for 0.8, too:
 */

struct __attribute__ ((packed)) al_sector_cpu {
	u32 magic;
	u32 tr_number;
	struct __attribute__ ((packed)) {
		u32 pos;
		u32 extent;
	} updates[62];
	u32 xor_sum;
};

struct __attribute__ ((packed)) al_sector_on_disk {
	be_u32 magic;
	be_u32 tr_number;
	struct __attribute__ ((packed)) {
		be_u32 pos;
		be_u32 extent;
	} updates[62];
	be_u32 xor_sum;
};

/*
 * -- DRBD 0.8 --------------------------------------
 *  even though they now differ only by la-size being kb or sectors,
 *  I expect them to diverge, so lets have different structures.
 */

struct __attribute__ ((packed)) md_on_disk_08 {
	be_u64 la_sect;		/* last agreed size. */
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
	be_u32 md_size;
	be_u32 al_offset;	/* offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_u32 bm_offset;	/* offset to the bitmap, from here */
	char reserved[8 * 512 - 48];
};

void md_disk_08_to_cpu(struct md_cpu *cpu, const struct md_on_disk_08 *disk)
{
	int i;
	cpu->la_sect = be64_to_cpu(disk->la_sect.be);
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size = be32_to_cpu(disk->md_size.be);
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
}

void md_cpu_to_disk_08(struct md_on_disk_08 *disk, const struct md_cpu *cpu)
{
	int i;
	disk->la_sect.be = cpu_to_be64(cpu->la_sect);
	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size.be = cpu_to_be32(cpu->md_size);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	memset(disk->reserved, sizeof(disk->reserved), 0);
}

int v08_validate_md(struct md_cpu *md)
{
	if (md->magic != DRBD_MD_MAGIC_08) {
		fprintf(stderr, "v08 Magic number not found\n");
		return -1;
	}

	if (md->al_offset != MD_AL_OFFSET_07) {
		fprintf(stderr, "v08 Magic number (al_offset) not found\n");
		return -1;
	}

	if (md->bm_offset != MD_BM_OFFSET_07) {
		fprintf(stderr, "v08 Magic number (bm_offset) not found\n");
		return -1;
	}

	/* fixme consistency check, la_size < ll_device_size,
	 * no overlap with internal meta data,
	 * no overlap of flexible meta data offsets/sizes
	 * ...
	 */

	return 0;
}

/*
 * drbdmeta specific types
 */

struct format_ops;

struct format {
	struct format_ops *ops;
	char *device_name;	/* well, in 06 it is file name */
	int fd;
	/* byte offset of our "super block", within fd */
	u64 md_offset;

	/* unused in 06 */
	int md_index;
	unsigned int bm_bytes;
	unsigned int bits_set;	/* 32 bit should be enough. @4k ==> 16TB */

	struct md_cpu md;

	struct {
		/* "super block", fixed 4096 byte for the next century */
		union {
			struct md_on_disk_06 *md6;
			struct md_on_disk_07 *md7;
			struct md_on_disk_08 *md8;
		};

		/* variable size; well, in 07 it is fixed 64*512 byte,
		 * which may be partially unused */
		struct al_on_disk_sector *al;

		/* variable size; well, in 07 it is fixed (256-64-8)*512 byte
		 * which may be partially unused
		 * use le_long for now. */
		le_ulong *bm;
	} on_disk;
};

struct format_ops {
	const char *name;
	char **args;
	int (*parse) (struct format *, char **, int, int *);
	int (*open) (struct format *);
	int (*close) (struct format *);
	int (*md_initialize) (struct format *);
	int (*md_disk_to_cpu) (struct format *);
	int (*md_cpu_to_disk) (struct format *);
};

/*
 * global vaiables
 */

enum Known_Formats {
	Drbd_06,
	Drbd_07,
	Drbd_08,
	Drbd_Unknown,
};

/* pre declarations */
int v06_md_close(struct format *cfg);
int v06_md_cpu_to_disk(struct format *cfg);
int v06_md_disk_to_cpu(struct format *cfg);
int v06_parse(struct format *cfg, char **argv, int argc, int *ai);
int v06_md_open(struct format *cfg);
int v06_md_initialize(struct format *cfg);

int v07_md_close(struct format *cfg);
int v07_md_cpu_to_disk(struct format *cfg);
int v07_md_disk_to_cpu(struct format *cfg);
int v07_md_open(struct format *cfg);
int v07_parse(struct format *cfg, char **argv, int argc, int *ai);
int v07_md_initialize(struct format *cfg);

int v08_md_cpu_to_disk(struct format *cfg);
int v08_md_disk_to_cpu(struct format *cfg);
int v08_md_initialize(struct format *cfg);

struct format_ops f_ops[] = {
	[Drbd_06] = {
		     .name = "v06",
		     .args = (char *[]){"minor", NULL},
		     .parse = v06_parse,
		     .open = v06_md_open,
		     .close = v06_md_close,
		     .md_initialize = v06_md_initialize,
		     .md_disk_to_cpu = v06_md_disk_to_cpu,
		     .md_cpu_to_disk = v06_md_cpu_to_disk,
		     },
	[Drbd_07] = {
		     .name = "v07",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v07_md_open,
		     .close = v07_md_close,
		     .md_initialize = v07_md_initialize,
		     .md_disk_to_cpu = v07_md_disk_to_cpu,
		     .md_cpu_to_disk = v07_md_cpu_to_disk,
		     },
	[Drbd_08] = {
		     .name = "v08",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v07_md_open,
		     .close = v07_md_close,
		     .md_initialize = v08_md_initialize,
		     .md_disk_to_cpu = v08_md_disk_to_cpu,
		     .md_cpu_to_disk = v08_md_cpu_to_disk,
		     },
};

/******************************************
  Commands we know about:
 ******************************************/

struct meta_cmd {
	const char *name;
	const char *args;
	int (*function) (struct format *, char **argv, int argc);
	int show_in_usage;
};

/* pre declarations */
int meta_get_gc(struct format *cfg, char **argv, int argc);
int meta_show_gc(struct format *cfg, char **argv, int argc);
int meta_dump_md(struct format *cfg, char **argv, int argc);
int meta_create_md(struct format *cfg, char **argv, int argc);
int meta_set_gc(struct format *cfg, char **argv, int argc);

struct meta_cmd cmds[] = {
	{"get-gc", 0, meta_get_gc, 1},
	{"show-gc", 0, meta_show_gc, 1},
	{"dump-md", 0, meta_dump_md, 1},
	{"create-md", 0, meta_create_md, 1},
	/* FIXME convert still missing.
	 * implicit convert from v07 to v08 by create-md
	 * see comments there */
	{"set-gc", ":::VAL:VAL:...", meta_set_gc, 0},
};

char *progname = 0;
int drbd_fd = -1;
int lock_fd = -1;
char *drbd_dev_name;

/*
 * generic helpers
 */

int confirmed(const char *text)
{
	char answer[16];
	int rr;

	printf("%s [yes/no] ", text);
	rr = scanf("%[yesno]15s", answer);
	return !strcmp(answer, "yes");
}

unsigned long bm_words(u64 sectors)
{
	unsigned long long bits;
	unsigned long long words;

	/* bits  = ALIGN(capacity,BM_SECTORS_PER_BIT) >> (BM_BLOCK_SIZE_B-9); */
	bits = ALIGN(sectors, 8) >> 3;
	words = ALIGN(bits, 64) >> LN2_BPL;

	return words;
}

u64 bdev_size(int fd)
{
	u64 size64;		/* size in byte. */
	long size;		/* size in sectors. */
	int err;

	err = ioctl(fd, BLKGETSIZE64, &size64);
	if (err) {
		if (errno == EINVAL) {
			printf("INFO: falling back to BLKGETSIZE\n");
			err = ioctl(fd, BLKGETSIZE, &size);
			if (err) {
				perror("ioctl(,BLKGETSIZE,) failed");
				exit(20);
			}
			size64 = (typeof(u64)) 512 *size;
		} else {
			perror("ioctl(,BLKGETSIZE64,) failed");
			exit(20);
		}
	}

	return size64;
}

#if BITS_PER_LONG == 32
# define FMT " 0x%016llX;"
#else
# define FMT " 0x%016lX;"
#endif

/* le_u64, because we want to be able to hexdump it reliably
 * regardless of sizeof(long) */
void printf_bm(const le_u64 * bm, const unsigned int n)
{
	int i;
	printf("bm {");
	for (i = 0; i < n; i++) {
		if ((i & 3) == 0)
			printf("\n   ");
		printf(FMT, le64_to_cpu(bm[i].le));
	}
	printf("\n }\n");
}

#undef FMT

void printf_gc(const struct md_cpu *md)
{
	printf("%d:%d:%d:%d:%d:%d:%d:%d\n",
	       md->gc[Flags] & MDF_Consistent ? 1 : 0,
	       md->gc[HumanCnt],
	       md->gc[TimeoutCnt],
	       md->gc[ConnectedCnt],
	       md->gc[ArbitraryCnt],
	       md->gc[Flags] & MDF_PrimaryInd ? 1 : 0,
	       md->gc[Flags] & MDF_ConnectedInd ? 1 : 0,
	       md->gc[Flags] & MDF_FullSync ? 1 : 0);
}

/******************************************
 begin of v06 {{{
 ******************************************/

int v06_md_disk_to_cpu(struct format *cfg)
{
	md_disk_06_to_cpu(&cfg->md, cfg->on_disk.md6);
	return v06_validate_md(&cfg->md);
}

int v06_md_cpu_to_disk(struct format *cfg)
{
	int err;
	if (v06_validate_md(&cfg->md))
		return -1;
	if (!cfg->on_disk.md6) {
		fprintf(stderr, "BUG: on-disk-md not mapped\n");
		exit(30);
	}
	md_cpu_to_disk_06(cfg->on_disk.md6, &cfg->md);
	err = msync(cfg->on_disk.md6, sizeof(*cfg->on_disk.md6),
		    MS_SYNC | MS_INVALIDATE);
	if (err) {
		PERROR("msync(on_disk_md)");
		return -1;
	};
	return 0;
}

int v06_parse(struct format *cfg, char **argv, int argc, int *ai)
{
	unsigned long minor;
	char *e;

	if (argc < 1) {
		fprintf(stderr, "Too few arguments for format\n");
		exit(20);
	}

	e = argv[0];
	minor = strtol(argv[0], &e, 0);
	if (*e != 0 || minor > 255UL) {
		fprintf(stderr, "'%s' is not a valid minor number.\n", argv[0]);
		exit(20);
	}
	if (asprintf(&e, "/var/lib/drbd/drbd%lu", minor) <= 18) {
		fprintf(stderr, "asprintf() failed.\n");
		exit(20);
	};
	cfg->device_name = e;

	*ai += 1;

	return 0;
}

int v06_md_open(struct format *cfg)
{
	struct stat sb;

	cfg->fd = open(cfg->device_name, O_RDWR);

	if (cfg->fd == -1) {
		PERROR("open(%s) failed", cfg->device_name);
		return -1;
	}

	if (fstat(cfg->fd, &sb)) {
		PERROR("fstat() failed");
		return -1;
	}

	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "'%s' is not a plain file!\n",
			cfg->device_name);
		return -1;
	}

	cfg->on_disk.md6 =
	    mmap(NULL, sizeof(struct md_on_disk_06), PROT_READ | PROT_WRITE,
		 MAP_SHARED, cfg->fd, 0);
	if (cfg->on_disk.md6 == NULL) {
		PERROR("mmap(md_on_disk) failed");
		return -1;
	}

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return -1;
	}

	return 0;
}

int v06_md_close(struct format *cfg)
{
	if (munmap(cfg->on_disk.md6, sizeof(struct md_on_disk_06))) {
		PERROR("munmap(md_on_disk) failed");
		return -1;
	}
	if (fsync(cfg->fd) == -1) {
		PERROR("fsync() failed");
		return -1;
	}
	if (close(cfg->fd)) {
		PERROR("close() failed");
		return -1;
	}
	return 0;
}

int v06_md_initialize(struct format *cfg)
{
	cfg->md.gc[Flags] = 0;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.magic = DRBD_MD_MAGIC_06;
	return 0;
}

/******************************************
  }}} end of v06
 ******************************************/
/******************************************
 begin of v07 {{{
 ******************************************/

u64 v07_offset(struct format * cfg)
{
	u64 offset;

	if (cfg->md_index == -1) {
		offset = (bdev_size(cfg->fd) & ~((1 << 12) - 1))
		    - MD_RESERVED_SIZE_07;
	} else {
		offset = MD_RESERVED_SIZE_07 * cfg->md_index;
	}
	return offset;
}

int v07_md_disk_to_cpu(struct format *cfg)
{
	md_disk_07_to_cpu(&cfg->md, cfg->on_disk.md7);
	return v07_validate_md(&cfg->md);
}

int v07_md_cpu_to_disk(struct format *cfg)
{
	int err;
	if (v07_validate_md(&cfg->md))
		return -1;
	if (!cfg->on_disk.md7) {
		fprintf(stderr, "BUG: on-disk-md not mapped\n");
		return -1;
	}
	md_cpu_to_disk_07(cfg->on_disk.md7, &cfg->md);
	err = msync(cfg->on_disk.md7, sizeof(*cfg->on_disk.md7),
		    MS_SYNC | MS_INVALIDATE);
	if (err) {
		PERROR("msync(on_disk_md)");
		return -1;
	};
	return 0;
}

int v07_parse(struct format *cfg, char **argv, int argc, int *ai)
{
	long index;
	char *e;

	if (argc < 2) {
		fprintf(stderr, "Too few arguments for format\n");
		return -1;
	}

	cfg->device_name = strdup(argv[0]);
	e = argv[1];
	index = strtol(argv[1], &e, 0);
	if (*e != 0 || -1 > index || index > 255) {
		fprintf(stderr, "'%s' is not a valid index number.\n", argv[1]);
		exit(20);
	}
	cfg->md_index = index;

	*ai += 2;

	return 0;
}

int v07_md_open(struct format *cfg)
{
	struct stat sb;
	unsigned long words;
	u64 offset, al_offset, bm_offset;

	cfg->fd = open(cfg->device_name, O_RDWR);

	if (cfg->fd == -1) {
		PERROR("open(%s) failed", cfg->device_name);
		exit(20);
	}

	if (fstat(cfg->fd, &sb)) {
		PERROR("fstat(%s) failed", cfg->device_name);
		exit(20);
	}

	if (!S_ISBLK(sb.st_mode)) {
		fprintf(stderr, "'%s' is not a block device!\n",
			cfg->device_name);
		exit(20);
	}

	if (ioctl(cfg->fd, BLKFLSBUF) == -1) {
		PERROR("ioctl(,BLKFLSBUF,) failed");
		exit(20);
	}

	offset = v07_offset(cfg);
	cfg->on_disk.md7 =
	    mmap(NULL, sizeof(struct md_on_disk_07), PROT_READ | PROT_WRITE,
		 MAP_SHARED, cfg->fd, offset);
	if (cfg->on_disk.md7 == NULL) {
		PERROR("mmap(md_on_disk) failed");
		exit(20);
	}
	cfg->md_offset = offset;

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return -1;
	}

	al_offset = offset + cfg->md.al_offset * 512;
	bm_offset = offset + cfg->md.bm_offset * 512;

	cfg->on_disk.al =
	    mmap(NULL, MD_AL_MAX_SIZE_07 * 512, PROT_READ | PROT_WRITE,
		 MAP_SHARED, cfg->fd, al_offset);
	if (cfg->on_disk.al == NULL) {
		PERROR("mmap(al_on_disk) failed");
		exit(20);
	}

	cfg->on_disk.bm = mmap(NULL, MD_BM_MAX_SIZE_07, PROT_READ | PROT_WRITE,
			       MAP_SHARED, cfg->fd, bm_offset);
	if (cfg->on_disk.bm == NULL) {
		PERROR("mmap(bm_on_disk) failed");
		exit(20);
	}

	words = bm_words(cfg->md.la_sect);
	cfg->bm_bytes = words * sizeof(long);
	cfg->bits_set =
	    count_bits((const unsigned long *)cfg->on_disk.bm, words);

	/* FIXME paranoia verify that unused bits and words are unset... */

	return 0;
}

int v07_md_close(struct format *cfg)
{
	if (munmap(cfg->on_disk.bm, MD_BM_MAX_SIZE_07)) {
		PERROR("munmap(bm_on_disk) failed");
		return -1;
	}
	if (munmap(cfg->on_disk.al, MD_AL_MAX_SIZE_07 * 512)) {
		PERROR("munmap(al_on_disk) failed");
		return -1;
	}
	if (munmap(cfg->on_disk.md7, 8 * 512)) {
		PERROR("munmap(md_on_disk) failed");
		return -1;
	}
	if (fsync(cfg->fd) == -1) {
		PERROR("fsync() failed");
		return -1;
	}
	if (ioctl(cfg->fd, BLKFLSBUF) == -1) {
		PERROR("ioctl(,BLKFLSBUF,) failed");
		return -1;
	}
	if (close(cfg->fd)) {
		PERROR("close() failed");
		return -1;
	}
	return 0;
}

int v07_md_initialize(struct format *cfg)
{
	u64 al_offset, bm_offset;

	cfg->md.la_sect = 0;
	cfg->md.gc[Flags] = MDF_FullSync;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.magic = DRBD_MD_MAGIC_07;

	/*
	 * FIXME md_size not yet validated or used.
	 */
	cfg->md.md_size = MD_RESERVED_SIZE_07;
	cfg->md.al_offset = MD_AL_OFFSET_07;
	cfg->md.al_nr_extents = 257;	/* arbitrary. */
	cfg->md.bm_offset = MD_BM_OFFSET_07;

	al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;
	if (cfg->on_disk.al == NULL) {
		cfg->on_disk.al =
		    mmap(NULL, MD_AL_MAX_SIZE_07 * 512, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->fd, al_offset);
		if (cfg->on_disk.al == NULL) {
			PERROR("mmap(al_on_disk) failed");
			exit(20);
		}
	}

	if (cfg->on_disk.bm == NULL) {
		cfg->on_disk.bm =
		    mmap(NULL, MD_BM_MAX_SIZE_07, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->fd, bm_offset);
		if (cfg->on_disk.bm == NULL) {
			PERROR("mmap(bm_on_disk) failed");
			exit(20);
		}
	}

	memset(cfg->on_disk.al, MD_AL_MAX_SIZE_07, 0);
	memset(cfg->on_disk.bm, MD_BM_MAX_SIZE_07, 0);
	return 0;
}

/******************************************
  }}} end of v07
 ******************************************/
/******************************************
 begin of v08 {{{
 ******************************************/

int v08_md_disk_to_cpu(struct format *cfg)
{
	md_disk_08_to_cpu(&cfg->md, cfg->on_disk.md8);
	return v08_validate_md(&cfg->md);
}

int v08_md_cpu_to_disk(struct format *cfg)
{
	int err;
	if (v08_validate_md(&cfg->md))
		return -1;
	if (!cfg->on_disk.md8) {
		fprintf(stderr, "BUG: on-disk-md not mapped\n");
		return -1;
	}
	md_cpu_to_disk_08(cfg->on_disk.md8, &cfg->md);
	err = msync(cfg->on_disk.md8, sizeof(*cfg->on_disk.md8),
		    MS_SYNC | MS_INVALIDATE);
	if (err) {
		PERROR("msync(on_disk_md)");
		return -1;
	};
	return 0;
}

int v08_md_initialize(struct format *cfg)
{
	u64 al_offset, bm_offset;

	cfg->md.la_sect = 0;
	cfg->md.gc[Flags] = MDF_FullSync;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.magic = DRBD_MD_MAGIC_08;

	/*
	 * FIXME md_size not yet validated or used.
	 * FIXME make it flexible, not fixed anymore as with 07.
	 */
	cfg->md.md_size = MD_RESERVED_SIZE_07;
	cfg->md.al_offset = MD_AL_OFFSET_07;
	cfg->md.al_nr_extents = 257;	/* arbitrary. */
	cfg->md.bm_offset = MD_BM_OFFSET_07;

	al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;
	if (cfg->on_disk.al == NULL) {
		cfg->on_disk.al =
		    mmap(NULL, MD_AL_MAX_SIZE_07 * 512, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->fd, al_offset);
		if (cfg->on_disk.al == NULL) {
			PERROR("mmap(al_on_disk) failed");
			exit(20);
		}
	}

	if (cfg->on_disk.bm == NULL) {
		cfg->on_disk.bm =
		    mmap(NULL, MD_BM_MAX_SIZE_07, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->fd, bm_offset);
		if (cfg->on_disk.bm == NULL) {
			PERROR("mmap(bm_on_disk) failed");
			exit(20);
		}
	}

	/* do you want to initilize al to something more usefull? */
	memset(cfg->on_disk.al, MD_AL_MAX_SIZE_07, 0);
	memset(cfg->on_disk.bm, MD_BM_MAX_SIZE_07, 0);
	return 0;
}

/******************************************
  }}} end of v08
 ******************************************/

int meta_get_gc(struct format *cfg, char **argv, int argc)
{
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;
	printf_gc(&cfg->md);
	return cfg->ops->close(cfg);
}

int meta_show_gc(struct format *cfg, char **argv, int argc)
{
	char ppb[10];

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	printf("\n"
	       "                                        WantFullSync |\n"
	       "                                  ConnectedInd |     |\n"
	       "                               lastState |     |     |\n"
	       "                      ArbitraryCnt |     |     |     |\n"
	       "                ConnectedCnt |     |     |     |     |\n"
	       "            TimeoutCnt |     |     |     |     |     |\n"
	       "        HumanCnt |     |     |     |     |     |     |\n"
	       "Consistent |     |     |     |     |     |     |     |\n"
	       "   --------+-----+-----+-----+-----+-----+-----+-----+\n"
	       "       %3s | %3d | %3d | %3d | %3d | %3s | %3s | %3s  \n"
	       "\n",
	       cfg->md.gc[Flags] & MDF_Consistent ? "1/c" : "0/i",
	       cfg->md.gc[HumanCnt],
	       cfg->md.gc[TimeoutCnt],
	       cfg->md.gc[ConnectedCnt],
	       cfg->md.gc[ArbitraryCnt],
	       cfg->md.gc[Flags] & MDF_PrimaryInd ? "1/p" : "0/s",
	       cfg->md.gc[Flags] & MDF_ConnectedInd ? "1/c" : "0/n",
	       cfg->md.gc[Flags] & MDF_FullSync ? "1/y" : "0/n");

	if (cfg->md.la_sect) {
		printf("last agreed size: %s\n",
		       ppsize(ppb, cfg->md.la_sect >> 1));
		printf("%u bits set in the bitmap [ %s out of sync ]\n",
		       cfg->bits_set, ppsize(ppb, cfg->bits_set * 4));
	} else {
		printf("zero size device -- never seen peer yet?\n");
	}

	return cfg->ops->close(cfg);
}

int meta_dump_md(struct format *cfg, char **argv, int argc)
{
	int i;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	/* FIXME invent some sceme to identify this dump,
	 * so we can safely restore it later */
	printf("DRBD meta data dump version <FIXME drbdmeta dump version>\n");
	printf("meta data version %s\n\n", cfg->ops->name);
	printf("gc {");
	for (i = 0; i < GEN_CNT_SIZE; i++) {
		printf(" 0x%X;", cfg->md.gc[i]);
	}
	printf(" }\n");

	if (cfg->ops > f_ops + Drbd_06) {
		printf("la-size-sect %llu;\n", cfg->md.la_sect);
		printf("# bm-bytes %u;\n", cfg->bm_bytes);	/* informational only */
		printf("# bits-set %u;\n", cfg->bits_set);	/* informational only */
		printf
		    ("# FIXME include offsets, once they are not fixed anymore\n");
		if (cfg->on_disk.bm)
			printf_bm((le_u64 *) cfg->on_disk.bm,
				  cfg->bm_bytes / sizeof(le_u64));
	}

	/* MAYBE dump activity log?
	 * but that probably does not make any sense,
	 * beyond debugging. */

	return cfg->ops->close(cfg);
}

int md_convert_07_to_08(struct format *cfg)
{
	/* Note that al and bm are not touched!
	 * (they are currently not even mmaped)
	 *
	 * KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	printf("Converting meta data...\n");
	cfg->md.magic = DRBD_MD_MAGIC_08;
	if (cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg)) {
		fprintf(stderr, "conversion failed\n");
		return -1;
	}
	printf("Successfully converted v07 meta data to v08 format.\n");
	return 0;
}

/* FIXME create v07 replaces a valid v08 block without confirmation!
 * we need better format auto-detection */
int meta_create_md(struct format *cfg, char **argv, int argc)
{
	int virgin, err;
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	virgin = cfg->ops->open(cfg);
	if (virgin && cfg->ops == f_ops + Drbd_08) {
		/* wrong format. if we want to create a v08,
		 * we might have a v07 in place.
		 * if so, maybe just convert.
		 */
		virgin = v07_md_disk_to_cpu(cfg);
		if (!virgin) {
			if (confirmed("Valid v07 meta-data found, convert?"))
				return md_convert_07_to_08(cfg);
		}
	}
	if (!virgin) {
		if (!confirmed("Valid meta-data already in place, create new?")) {
			printf("Operation cancelled.\n");
			exit(0);
		}
	}

	printf("Creating meta data...\n");
	err = cfg->ops->md_initialize(cfg)
	    || cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "conversion failed\n");

	return err;
}

int m_strsep(char **s, int *val)
{
	char *t, *e;
	long v;

	if ((t = strsep(s, ":"))) {
		if (strlen(t)) {
			e = t;
			v = strtol(t, &e, 0);
			if (*e != 0) {
				fprintf(stderr, "'%s' is not a number.\n", *s);
				exit(10);
			}
			if (v < 0) {
				fprintf(stderr, "'%s' is negative.\n", *s);
				exit(10);
			}
			if (v > 0xFFffFFff) {
				fprintf(stderr,
					"'%s' is out of range (max 0xFFffFFff).\n",
					*s);
				exit(10);
			}
			*val = v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_b(char **s, int *val, int mask)
{
	int d;
	int rv;

	d = *val & mask;

	rv = m_strsep(s, &d);

	if (d > 1) {
		fprintf(stderr, "'%d' is not 0 or 1.\n", d);
		exit(10);
	}

	if (d)
		*val |= mask;
	else
		*val &= ~mask;

	return rv;
}

int meta_set_gc(struct format *cfg, char **argv, int argc)
{
	struct md_cpu tmp;
	int err;
	char **str;

	if (argc > 1) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}
	if (argc < 1) {
		fprintf(stderr, "Required Argument missing\n");
		exit(10);
	}

	if (cfg->ops->open(cfg))
		return -1;

	tmp = cfg->md;
	str = &argv[0];

	do {
		if (!m_strsep_b(str, &tmp.gc[Flags], MDF_Consistent)) break;
		if (!m_strsep(str, &tmp.gc[HumanCnt])) break;
		if (!m_strsep(str, &tmp.gc[TimeoutCnt])) break;
		if (!m_strsep(str, &tmp.gc[ConnectedCnt])) break;
		if (!m_strsep(str, &tmp.gc[ArbitraryCnt])) break;
		if (!m_strsep_b(str, &tmp.gc[Flags], MDF_PrimaryInd)) break;
		if (!m_strsep_b(str, &tmp.gc[Flags], MDF_ConnectedInd)) break;
		if (!m_strsep_b(str, &tmp.gc[Flags], MDF_FullSync)) break;
	} while (0);

	printf("  consistent:H:T:C:A:p:c:f\n");
	printf("previously ");
	printf_gc(&cfg->md);
	printf("GCs set to ");
	printf_gc(&tmp);

	if (!confirmed("Write new GCs to disk?")) {
		printf("Operation cancelled.\n");
		exit(0);
	}

	cfg->md = tmp;

	err = cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}

void print_usage()
{
	char **args;
	int i;

	printf
	    ("\nUSAGE: %s DEVICE FORMAT [FORMAT ARGS...] COMMAND [CMD ARGS...]\n",
	     progname);

	printf("\nFORMATS:\n");
	for (i = Drbd_06; i < Drbd_Unknown; i++) {
		printf("  %s", f_ops[i].name);
		if ((args = f_ops[i].args)) {
			while (*args) {
				printf(" %s", *args++);
			}
		}
		printf("\n");
	}

	printf("\nCOMMANDS:\n");
	for (i = 0; i < ARRY_SIZE(cmds); i++) {
		if (!cmds[i].show_in_usage)
			continue;
		printf("  %s %s\n", cmds[i].name,
		       cmds[i].args ? cmds[i].args : "");
	}

	exit(0);
}

struct format *parse_format(char **argv, int argc, int *ai)
{
	struct format *cfg;
	enum Known_Formats f;

	if (argc < 1) {
		fprintf(stderr, "Format identifier missing\n");
		exit(20);
	}

	for (f = Drbd_06; f < Drbd_Unknown; f++) {
		if (!strcmp(f_ops[f].name, argv[0]))
			break;
	}
	if (f == Drbd_Unknown) {
		fprintf(stderr, "Unknown format '%s'.\n", argv[0]);
		exit(20);
	}

	(*ai)++;

	cfg = calloc(1, sizeof(struct format));
	cfg->ops = f_ops + f;
	cfg->ops->parse(cfg, argv + 1, argc - 1, ai);

	return cfg;
}

int main(int argc, char **argv)
{
	struct meta_cmd *command = NULL;
	struct format *cfg;
	int i, ai;

	if ((progname = strrchr(argv[0], '/'))) {
		argv[0] = ++progname;
	} else {
		progname = argv[0];
	}

	if (argc < 4)
		print_usage();

	ai = 1;
	drbd_dev_name = argv[ai++];
	drbd_fd = dt_lock_open_drbd(drbd_dev_name, &lock_fd, 1);
	if (drbd_fd > -1) {
		/* avoid DRBD specific ioctls here...
		 * If the device is _not_ configured, block device ioctls
		 * should fail. So if we _can_ determine whether it is readonly,
		 * it is configured; and we better not touch its meta data.
		 */
		int dummy_is_ro;
		if (ioctl(drbd_fd, BLKROGET, &dummy_is_ro) == 0) {
			fprintf(stderr, "Device '%s' is configured!\n",
				drbd_dev_name);
			exit(20);
		}
	}

	/* implicit cfg = calloc */
	cfg = parse_format(argv + ai, argc - ai, &ai);

	if (ai >= argc) {
		fprintf(stderr, "command missing\n");
		exit(20);
	}

	for (i = 0; i < ARRY_SIZE(cmds); i++) {
		if (!strcmp(cmds[i].name, argv[ai])) {
			command = cmds + i;
			break;
		}
	}
	if (command == NULL) {
		fprintf(stderr, "Unknown command '%s'.\n", argv[ai]);
		exit(20);
	}
	ai++;

	return command->function(cfg, argv + ai, argc - ai);
	/* and if we want an explicit free,
	 * this would be the place for it.
	 * free(cfg->device_name), free(cfg) ...
	 */
}
