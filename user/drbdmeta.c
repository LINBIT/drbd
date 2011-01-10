/*
   drbdmeta.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2004-2008, LINBIT Information Technologies GmbH
   Copyright (C) 2004-2008, Philipp Reisner <philipp.reisner@linbit.com>
   Copyright (C) 2004-2008, Lars Ellenberg  <lars.ellenberg@linbit.com>

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

#define INITIALIZE_BITMAP 0

#define _GNU_SOURCE
#define _XOPEN_SOURCE 600
#define _FILE_OFFSET_BITS 64
#define __USE_LARGEFILE64

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

#include <linux/major.h>
#include <linux/kdev_t.h>
#include <linux/drbd.h>		/* only use DRBD_MAGIC from here! */
#include <linux/fs.h>           /* for BLKFLSBUF */

#include "drbd_endian.h"
#include "drbdtool_common.h"

#include "drbdmeta_parser.h"

#include "config.h"

extern FILE* yyin;
YYSTYPE yylval;

/* int     force = 0; now extern, see drbdtool_common.c */
int	verbose = 0;
int	ignore_sanity_checks = 0;
int	dry_run = 0;

struct option metaopt[] = {
    { "ignore-sanity-checks",  no_argument, &ignore_sanity_checks, 1000 },
    { "dry-run",  no_argument, &dry_run, 1000 },
    { "force",  no_argument,    0, 'f' },
    { "verbose",  no_argument,    0, 'v' },
    { NULL,     0,              0, 0 },
};

/* FIXME? should use sector_t and off_t, not long/uint64_t ... */

/* Note RETURN VALUES:
 * exit code convention: int vXY_something() and meta_blah return some negative
 * error code, usually -1, when failed, 0 for success.
 *
 * FIXME some of the return -1; probably should better be exit(something);
 * or some of the exit() should be rather some return?
 *
 * AND, the exit codes should follow some defined scheme.
 */

#if 0
#define ASSERT(x) ((void)(0))
#else
#define ASSERT(x) do { if (!(x)) {			\
	fprintf(stderr, "%s:%u:%s: ASSERT(%s) failed.\n",	\
		__FILE__ , __LINE__ , __func__ , #x );		\
	abort(); }						\
	} while (0)
#endif

/*
 * FIXME
 *
 * when configuring a drbd device:
 *
 * Require valid drbd meta data at the respective location.  A meta data
 * block would only be created by the drbdmeta command.
 *
 * (How) do we want to implement this: A meta data block contains some
 * reference to the physical device it belongs. Refuse to attach not
 * corresponding meta data.
 *
 * THINK: put a checksum within the on-disk meta data block, too?
 *
 * When asked to create a new meta data block, the drbdmeta command
 * warns loudly if either the data device or the meta data device seem
 * to contain some data, and requires explicit confirmation anyways.
 *
 * See current implementation in check_for_existing_data below.
 *
 * XXX should also be done for meta-data != internal, i.e.  refuse to
 * create meta data blocks on a device that seems to be in use for
 * something else.
 *
 * Maybe with an external meta data device, we want to require a "meta
 * data device super block", which could also serve as TOC to the meta
 * data, once we have variable size meta data.  Other option could be a
 * /var/lib/drbd/md-toc plain file, and some magic block on every device
 * that serves as md storage.
 *
 * For certain content on the lower level device, we should refuse
 * always.  e.g. refuse to be created on top of a LVM2 physical volume,
 * or on top of swap space. This would require people to do an dd
 * if=/dev/zero of=device.  Protects them from shooting themselves,
 * and blaming us...
 */

/* reiserfs sb offset is 64k plus
 * align it to 4k, in case someone has unusual hard sect size (!= 512),
 * otherwise direct io will fail with EINVAL */
#define SO_MUCH (68*1024)

/*
 * I think this block of declarations and definitions should be
 * in some common.h, too.
 * {
 */

#ifndef ALIGN
# define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )
#endif

#define MD_AL_OFFSET_07        8
#define MD_AL_MAX_SECT_07     64
#define MD_BM_OFFSET_07        (MD_AL_OFFSET_07 + MD_AL_MAX_SECT_07)
#define MD_RESERVED_SECT_07    ( (uint64_t)(128ULL << 11) )
#define MD_BM_MAX_BYTE_07      ( (uint64_t)(MD_RESERVED_SECT_07 - MD_BM_OFFSET_07)*512 )
#if BITS_PER_LONG == 32
#define MD_BM_MAX_BYTE_FLEX    ( (uint64_t)(1ULL << (32-3)) )
#else
#define MD_BM_MAX_BYTE_FLEX    ( (uint64_t)(1ULL << (38-3)) )
#endif

#define DEFAULT_BM_BLOCK_SIZE  (1<<12)

#define DRBD_MD_MAGIC_06   (DRBD_MAGIC+2)
#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)
#define DRBD_MD_MAGIC_08   (DRBD_MAGIC+4)

/*
 * }
 * end of should-be-shared
 */

/*
 * global variables and data types
 */

const size_t buffer_size = 128*1024;
size_t pagesize; /* = sysconf(_SC_PAGESIZE) */
int opened_odirect = 1;
void *on_disk_buffer = NULL;
int global_argc;
char **global_argv;

enum Known_Formats {
	Drbd_06,
	Drbd_07,
	Drbd_08,
	Drbd_Unknown,
};

/* let gcc help us get it right.
 * some explicit endian types */
typedef struct { uint64_t le; } le_u64;
typedef struct { uint64_t be; } be_u64;
typedef struct { uint32_t le; } le_u32;
typedef struct { uint32_t be; } be_u32;
typedef struct { int32_t be; } be_s32;
typedef struct { unsigned long le; } le_ulong;
typedef struct { unsigned long be; } be_ulong;

/* NOTE that this structure does not need to be packed,
 * aligned, nor does it need to be in the same order as the on_disk variants.
 */
struct md_cpu {
	/* present since drbd 0.6 */
	uint32_t gc[GEN_CNT_SIZE];	/* generation counter */
	uint32_t magic;
	/* added in drbd 0.7;
	 * 0.7 stores la_size on disk as kb, 0.8 in units of sectors.
	 * we use sectors in our general working structure here */
	uint64_t la_sect;		/* last agreed size. */
	uint32_t md_size_sect;
	int32_t al_offset;		/* signed sector offset to this block */
	uint32_t al_nr_extents;	/* important for restoring the AL */
	int32_t bm_offset;		/* signed sector offset to the bitmap, from here */
	/* Since DRBD 0.8 we have uuid instead of gc */
	uint64_t uuid[UI_SIZE];
	uint32_t flags;
	uint64_t device_uuid;
	uint32_t bm_bytes_per_bit;
};

/*
 * drbdmeta specific types
 */

struct format_ops;

struct format {
	const struct format_ops *ops;
	char *md_device_name;	/* well, in 06 it is file name */
	char *drbd_dev_name;
	unsigned minor;		/* cache, determined from drbd_dev_name */
	int lock_fd;
	int drbd_fd;		/* no longer used!   */
	int ll_fd;		/* not yet used here */
	int md_fd;
	int md_hard_sect_size;


	/* unused in 06 */
	int md_index;
	unsigned int bm_bytes;
	unsigned int bits_set;	/* 32 bit should be enough. @4k ==> 16TB */
	int bits_counted:1;
	int update_lk_bdev:1;	/* need to update the last known bdev info? */

	struct md_cpu md;

	/* _byte_ offsets of our "super block" and other data, within fd */
	uint64_t md_offset;
	uint64_t al_offset;
	uint64_t bm_offset;

	/* if create_md actually does convert,
	 * we want to wipe the old meta data block _after_ convertion. */
	uint64_t wipe_fixed;
	uint64_t wipe_flex;

	/* convenience */
	uint64_t bd_size; /* size of block device for internal meta data */

	/* last-known bdev info,
	 * to increase the chance of finding internal meta data in case the
	 * lower level device has been resized without telling DRBD.
	 * Loaded from file for internal metadata */
	struct bdev_info lk_bd;
};

/* - parse is expected to exit() if it does not work out.
 * - open is expected to read the respective on_disk members,
 *   and copy the "superblock" meta data into the struct mem_cpu
 * FIXME describe rest of them, and when they should exit,
 * return error or success.
 */
struct format_ops {
	const char *name;
	char **args;
	int (*parse) (struct format *, char **, int, int *);
	int (*open) (struct format *);
	int (*close) (struct format *);
	int (*md_initialize) (struct format *);
	int (*md_disk_to_cpu) (struct format *);
	int (*md_cpu_to_disk) (struct format *);
	void (*get_gi) (struct md_cpu *md);
	void (*show_gi) (struct md_cpu *md);
	void (*set_gi) (struct md_cpu *md, char **argv, int argc);
	int (*outdate_gi) (struct md_cpu *md);
	int (*invalidate_gi) (struct md_cpu *md);
};

/*
 * -- DRBD 0.6 --------------------------------------
 */

struct __packed md_on_disk_06 {
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
};

void md_disk_06_to_cpu(struct md_cpu *cpu, const struct md_on_disk_06 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
}

void md_cpu_to_disk_06(struct md_on_disk_06 *disk, struct md_cpu *cpu)
{
	int i;

	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
}

int v06_validate_md(struct format *cfg)
{
	if (cfg->md.magic != DRBD_MD_MAGIC_06) {
		fprintf(stderr, "v06 Magic number not found\n");
		return -1;
	}
	return 0;
}

/*
 * -- DRBD 0.7 --------------------------------------
 */

struct __packed md_on_disk_07 {
	be_u64 la_kb;		/* last agreed size. */
	be_u32 gc[GEN_CNT_SIZE];	/* generation counter */
	be_u32 magic;
	be_u32 md_size_kb;
	be_s32 al_offset;	/* signed sector offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_s32 bm_offset;	/* signed sector offset to the bitmap, from here */
	char reserved[8 * 512 - 48];
};

void md_disk_07_to_cpu(struct md_cpu *cpu, const struct md_on_disk_07 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->la_sect = be64_to_cpu(disk->la_kb.be) << 1;
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size_sect = be32_to_cpu(disk->md_size_kb.be) << 1;
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
	cpu->bm_bytes_per_bit = 4096;
}

void md_cpu_to_disk_07(struct md_on_disk_07 *disk, const struct md_cpu const *cpu)
{
	int i;

	disk->la_kb.be = cpu_to_be64(cpu->la_sect >> 1);
	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size_kb.be = cpu_to_be32(cpu->md_size_sect >> 1);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	memset(disk->reserved, 0, sizeof(disk->reserved));
}

int is_valid_md(int f,
	const struct md_cpu const *md, const int md_index, const uint64_t ll_size)
{
	uint64_t md_size_sect;
	char *v = (f == Drbd_07) ? "v07" : "v08";
	const unsigned int magic = (f == Drbd_07) ? DRBD_MD_MAGIC_07 : DRBD_MD_MAGIC_08;


	ASSERT(f == Drbd_07 || f == Drbd_08);

	if (md->magic != magic) {
		if (verbose >= 1)
			fprintf(stderr, "%s Magic number not found\n", v);
		return 0;
	}

	switch(md_index) {
	default:
	case DRBD_MD_INDEX_INTERNAL:
	case DRBD_MD_INDEX_FLEX_EXT:
		if (md->al_offset != MD_AL_OFFSET_07) {
			fprintf(stderr, "%s Magic number (al_offset) not found\n", v);
			fprintf(stderr, "\texpected: %d, found %d\n",
				MD_AL_OFFSET_07, md->al_offset);
			return 0;
		}
		if (md->bm_offset != MD_BM_OFFSET_07) {
			fprintf(stderr, "%s Magic number (bm_offset) not found\n", v);
			return 0;
		}
		break;
	case DRBD_MD_INDEX_FLEX_INT:
		if (md->al_offset != -MD_AL_MAX_SECT_07) {
			fprintf(stderr, "%s Magic number (al_offset) not found\n", v);
			fprintf(stderr, "\texpected: %d, found %d\n",
				-MD_AL_MAX_SECT_07, md->al_offset);
			return 0;
		}

		/* we need (slightly less than) ~ this much bitmap sectors: */
		md_size_sect = (ll_size + (1UL<<24)-1) >> 24; /* BM_EXT_SIZE_B */
		md_size_sect = (md_size_sect + 7) & ~7ULL;    /* align on 4K blocks */
		/* plus the "drbd meta data super block",
		 * and the activity log; unit still sectors */
		md_size_sect += MD_BM_OFFSET_07;

		if (md->bm_offset != -(int64_t)md_size_sect + MD_AL_OFFSET_07) {
			fprintf(stderr, "strange bm_offset %d (expected: "D64")\n",
					md->bm_offset, -(int64_t)md_size_sect + MD_AL_OFFSET_07);
			return 0;
		};
		if (md->md_size_sect != md_size_sect) {
			fprintf(stderr, "strange md_size_sect %u (expected: "U64")\n",
					md->md_size_sect, md_size_sect);
			if (f == Drbd_08) return 0;
			/* else not an error,
			 * was inconsistently implemented in v07 */
		}
		break;
	}

	/* FIXME consistency check, la_size < ll_device_size,
	 * no overlap with internal meta data,
	 * no overlap of flexible meta data offsets/sizes
	 * ...
	 */

	return 1; /* VALID */
}

/*
 * these stay the same for 0.8, too:
 */

struct __packed al_sector_cpu {
	uint32_t magic;
	uint32_t tr_number;
	struct __packed {
		uint32_t pos;
		uint32_t extent;
	} updates[62];
	uint32_t xor_sum;
};

struct __packed al_sector_on_disk {
	be_u32 magic;
	be_u32 tr_number;
	struct __packed {
		be_u32 pos;
		be_u32 extent;
	} updates[62];
	be_u32 xor_sum;
	be_u32 pad;
};

int v07_al_disk_to_cpu(struct al_sector_cpu *al_cpu, struct al_sector_on_disk *al_disk)
{
	uint32_t xor_sum = 0;
	int i;
	al_cpu->magic = be32_to_cpu(al_disk->magic.be);
	al_cpu->tr_number = be32_to_cpu(al_disk->tr_number.be);
	for (i = 0; i < 62; i++) {
		al_cpu->updates[i].pos = be32_to_cpu(al_disk->updates[i].pos.be);
		al_cpu->updates[i].extent = be32_to_cpu(al_disk->updates[i].extent.be);
		xor_sum ^= al_cpu->updates[i].extent;
	}
	al_cpu->xor_sum = be32_to_cpu(al_disk->xor_sum.be);
	return al_cpu->magic == DRBD_MAGIC &&
		al_cpu->xor_sum == xor_sum;
}

/*
 * -- DRBD 0.8 --------------------------------------
 */

struct __packed md_on_disk_08 {
	be_u64 la_sect;		/* last agreed size. */
	be_u64 uuid[UI_SIZE];   // UUIDs.
	be_u64 device_uuid;
	be_u64 reserved_u64_1;
	be_u32 flags;
	be_u32 magic;
	be_u32 md_size_sect;
	be_s32 al_offset;	/* signed sector offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_s32 bm_offset;	/* signed sector offset to the bitmap, from here */
	be_u32 bm_bytes_per_bit;
	be_u32 reserved_u32[4];

	char reserved[8 * 512 - (8*(UI_SIZE+3)+4*11)];
};

void md_disk_08_to_cpu(struct md_cpu *cpu, const struct md_on_disk_08 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->la_sect = be64_to_cpu(disk->la_sect.be);
	for ( i=UI_CURRENT ; i<UI_SIZE ; i++ )
		cpu->uuid[i] = be64_to_cpu(disk->uuid[i].be);
	cpu->device_uuid = be64_to_cpu(disk->device_uuid.be);
	cpu->flags = be32_to_cpu(disk->flags.be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size_sect = be32_to_cpu(disk->md_size_sect.be);
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);
	cpu->bm_bytes_per_bit = be32_to_cpu(disk->bm_bytes_per_bit.be);
}

void md_cpu_to_disk_08(struct md_on_disk_08 *disk, const struct md_cpu *cpu)
{
	int i;
	disk->la_sect.be = cpu_to_be64(cpu->la_sect);
	for ( i=UI_CURRENT ; i<UI_SIZE ; i++ ) {
		disk->uuid[i].be = cpu_to_be64(cpu->uuid[i]);
	}
	disk->device_uuid.be = cpu_to_be64(cpu->device_uuid);
	disk->flags.be = cpu_to_be32(cpu->flags);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size_sect.be = cpu_to_be32(cpu->md_size_sect);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	disk->bm_bytes_per_bit.be = cpu_to_be32(cpu->bm_bytes_per_bit);
	memset(disk->reserved, 0, sizeof(disk->reserved));
}

/* pre declarations */
void m_get_gc(struct md_cpu *md);
void m_show_gc(struct md_cpu *md);
void m_set_gc(struct md_cpu *md, char **argv, int argc);
int m_outdate_gc(struct md_cpu *md);
int m_invalidate_gc(struct md_cpu *md);
void m_get_uuid(struct md_cpu *md);
void m_show_uuid(struct md_cpu *md);
void m_set_uuid(struct md_cpu *md, char **argv, int argc);
int m_outdate_uuid(struct md_cpu *md);
int m_invalidate_uuid(struct md_cpu *md);

int generic_md_close(struct format *cfg);

int v06_md_cpu_to_disk(struct format *cfg);
int v06_md_disk_to_cpu(struct format *cfg);
int v06_parse(struct format *cfg, char **argv, int argc, int *ai);
int v06_md_open(struct format *cfg);
int v06_md_initialize(struct format *cfg);

int v07_md_cpu_to_disk(struct format *cfg);
int v07_md_disk_to_cpu(struct format *cfg);
int v07_parse(struct format *cfg, char **argv, int argc, int *ai);
int v07_md_initialize(struct format *cfg);

int v07_style_md_open(struct format *cfg);

int v08_md_open(struct format *cfg);
int v08_md_cpu_to_disk(struct format *cfg);
int v08_md_disk_to_cpu(struct format *cfg);
int v08_md_initialize(struct format *cfg);
int v08_md_close(struct format *cfg);

/* return codes for md_open */
enum {
	VALID_MD_FOUND = 0,
	NO_VALID_MD_FOUND = -1,
	VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION = -2,
};

struct format_ops f_ops[] = {
	[Drbd_06] = {
		     .name = "v06",
		     .args = (char *[]){"minor", NULL},
		     .parse = v06_parse,
		     .open = v06_md_open,
		     .close = generic_md_close,
		     .md_initialize = v06_md_initialize,
		     .md_disk_to_cpu = v06_md_disk_to_cpu,
		     .md_cpu_to_disk = v06_md_cpu_to_disk,
		     .get_gi = m_get_gc,
		     .show_gi = m_show_gc,
		     .set_gi = m_set_gc,
		     .outdate_gi = m_outdate_gc,
		     .invalidate_gi = m_invalidate_gc,
		     },
	[Drbd_07] = {
		     .name = "v07",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v07_style_md_open,
		     .close = generic_md_close,
		     .md_initialize = v07_md_initialize,
		     .md_disk_to_cpu = v07_md_disk_to_cpu,
		     .md_cpu_to_disk = v07_md_cpu_to_disk,
		     .get_gi = m_get_gc,
		     .show_gi = m_show_gc,
		     .set_gi = m_set_gc,
		     .outdate_gi = m_outdate_gc,
		     .invalidate_gi = m_invalidate_gc,
		     },
	[Drbd_08] = {
		     .name = "v08",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v08_md_open,
		     .close = v08_md_close,
		     .md_initialize = v08_md_initialize,
		     .md_disk_to_cpu = v08_md_disk_to_cpu,
		     .md_cpu_to_disk = v08_md_cpu_to_disk,
		     .get_gi = m_get_uuid,
		     .show_gi = m_show_uuid,
		     .set_gi = m_set_uuid,
		     .outdate_gi = m_outdate_uuid,
		     .invalidate_gi = m_invalidate_uuid,
		     },
};

static inline enum Known_Formats format_version(struct format *cfg)
{
	return (cfg->ops - f_ops);
}
static inline int is_v06(struct format *cfg)
{
	return format_version(cfg) == Drbd_06;
}
static inline int is_v07(struct format *cfg)
{
	return format_version(cfg) == Drbd_07;
}
static inline int is_v08(struct format *cfg)
{
	return format_version(cfg) == Drbd_08;
}

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
int meta_get_gi(struct format *cfg, char **argv, int argc);
int meta_show_gi(struct format *cfg, char **argv, int argc);
int meta_dump_md(struct format *cfg, char **argv, int argc);
int meta_restore_md(struct format *cfg, char **argv, int argc);
int meta_verify_dump_file(struct format *cfg, char **argv, int argc);
int meta_create_md(struct format *cfg, char **argv, int argc);
int meta_wipe_md(struct format *cfg, char **argv, int argc);
int meta_outdate(struct format *cfg, char **argv, int argc);
int meta_invalidate(struct format *cfg, char **argv, int argc);
int meta_set_gi(struct format *cfg, char **argv, int argc);
int meta_read_dev_uuid(struct format *cfg, char **argv, int argc);
int meta_write_dev_uuid(struct format *cfg, char **argv, int argc);
int meta_dstate(struct format *cfg, char **argv, int argc);
int meta_chk_offline_resize(struct format *cfg, char **argv, int argc);

struct meta_cmd cmds[] = {
	{"get-gi", 0, meta_get_gi, 1},
	{"show-gi", 0, meta_show_gi, 1},
	{"dump-md", 0, meta_dump_md, 1},
	{"restore-md", "file", meta_restore_md, 1},
	{"verify-dump", "file", meta_verify_dump_file, 1},
	{"create-md", 0, meta_create_md, 1},
	{"wipe-md", 0, meta_wipe_md, 1},
	{"outdate", 0, meta_outdate, 1},
	{"invalidate", 0, meta_invalidate, 1},
	{"dstate", 0, meta_dstate, 1},
	{"read-dev-uuid", "VAL",  meta_read_dev_uuid,  0},
	{"write-dev-uuid", "VAL", meta_write_dev_uuid, 0},
	{"set-gi", ":::VAL:VAL:...", meta_set_gi, 0},
	{"check-resize", 0, meta_chk_offline_resize, 1},
};

/*
 * generic helpers
 */

#define PREAD(a,b,c,d) pread_or_die((a),(b),(c),(d), __func__ )
#define PWRITE(a,b,c,d) pwrite_or_die((a),(b),(c),(d), __func__ )
/* Do we want to exit() right here,
 * or do we want to duplicate the error handling everywhere? */
void pread_or_die(int fd, void *buf, size_t count, off_t offset, const char* tag)
{
	ssize_t c = pread(fd, buf, count, offset);
	if (verbose >= 2) {
		fflush(stdout);
		fprintf(stderr, " %-26s: pread(%u, ...,%6lu,%12llu)\n", tag,
			fd, (unsigned long)count, (unsigned long long)offset);
		if (count & ((1<<12)-1))
			fprintf(stderr, "\tcount will cause EINVAL on hard sect size != 512\n");
		if (offset & ((1<<12)-1))
			fprintf(stderr, "\toffset will cause EINVAL on hard sect size != 512\n");
	}
	if (c < 0) {
		fprintf(stderr,"pread(%u,...,%lu,%llu) in %s failed: %s\n",
			fd, (unsigned long)count, (unsigned long long)offset,
			tag, strerror(errno));
		exit(10);
	} else if ((size_t)c != count) {
		fprintf(stderr,"confused in %s: expected to read %d bytes,"
			" actually read %d\n",
			tag, (int)count, (int)c);
		exit(10);
	}
	if (verbose > 10)
		fprintf_hex(stderr, offset, buf, count);
}

static unsigned n_writes = 0;
void pwrite_or_die(int fd, const void *buf, size_t count, off_t offset, const char* tag)
{
	ssize_t c;
	++n_writes;
	if (dry_run) {
		fprintf(stderr, " %-26s: pwrite(%u, ...,%6lu,%12llu) SKIPPED DUE TO DRY-RUN\n",
			tag, fd, (unsigned long)count, (unsigned long long)offset);
		if (verbose > 10)
			fprintf_hex(stderr, offset, buf, count);
		return;
	}
	c = pwrite(fd, buf, count, offset);
	if (verbose >= 2) {
		fflush(stdout);
		fprintf(stderr, " %-26s: pwrite(%u, ...,%6lu,%12llu)\n", tag,
			fd, (unsigned long)count, (unsigned long long)offset);
		if (count & ((1<<12)-1))
			fprintf(stderr, "\tcount will cause EINVAL on hard sect size != 512\n");
		if (offset & ((1<<12)-1))
			fprintf(stderr, "\toffset will cause EINVAL on hard sect size != 512\n");
	}
	if (c < 0) {
		fprintf(stderr,"pwrite(%u,...,%lu,%llu) in %s failed: %s\n",
			fd, (unsigned long)count, (unsigned long long)offset,
			tag, strerror(errno));
		exit(10);
	} else if ((size_t)c != count) {
		/* FIXME we might just now have corrupted the on-disk data */
		fprintf(stderr,"confused in %s: expected to write %d bytes,"
			" actually wrote %d\n", tag, (int)count, (int)c);
		exit(10);
	}
}

void m_get_gc(struct md_cpu *md)
{
	dt_print_gc(md->gc);
}

void m_show_gc(struct md_cpu *md)
{
	dt_pretty_print_gc(md->gc);
}

void m_get_uuid(struct md_cpu *md)
{
	dt_print_uuids(md->uuid,md->flags);
}

void m_show_uuid(struct md_cpu *md)
{
	dt_pretty_print_uuids(md->uuid,md->flags);
}

int m_strsep_u32(char **s, uint32_t *val)
{
	char *t, *e;
	unsigned long v;

	if ((t = strsep(s, ":"))) {
		if (strlen(t)) {
			e = t;
			errno = 0;
			v = strtoul(t, &e, 0);
			if (*e != 0) {
				fprintf(stderr, "'%s' is not a number.\n", *s);
				exit(10);
			}
			if (errno) {
				fprintf(stderr, "'%s': ", *s);
				perror(0);
				exit(10);
			}
			if (v > 0xFFffFFffUL) {
				fprintf(stderr,
					"'%s' is out of range (max 0xFFffFFff).\n",
					*s);
				exit(10);
			}
			*val = (uint32_t)v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_u64(char **s, uint64_t *val)
{
	char *t, *e;
	uint64_t v;

	if ((t = strsep(s, ":"))) {
		if (strlen(t)) {
			e = t;
			errno = 0;
			v = strto_u64(t, &e, 16);
			if (*e != 0) {
				fprintf(stderr, "'%s' is not a number.\n", *s);
				exit(10);
			}
			if (errno) {
				fprintf(stderr, "'%s': ", *s);
				perror(0);
				exit(10);
			}
			*val = v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_bit(char **s, uint32_t *val, int mask)
{
	uint32_t d;
	int rv;

	d = *val & mask ? 1 : 0;

	rv = m_strsep_u32(s, &d);

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

void m_set_gc(struct md_cpu *md, char **argv, int argc __attribute((unused)))
{
	char **str;

	str = &argv[0];

	do {
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_CONSISTENT)) break;
		if (!m_strsep_u32(str, &md->gc[HumanCnt])) break;
		if (!m_strsep_u32(str, &md->gc[TimeoutCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ConnectedCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ArbitraryCnt])) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_PRIMARY_IND)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_CONNECTED_IND)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_FULL_SYNC)) break;
	} while (0);
}

void m_set_uuid(struct md_cpu *md, char **argv, int argc __attribute((unused)))
{
	char **str;
	int i;

	str = &argv[0];

	do {
		for ( i=UI_CURRENT ; i<UI_SIZE ; i++ ) {
			if (!m_strsep_u64(str, &md->uuid[i])) return;
		}
		if (!m_strsep_bit(str, &md->flags, MDF_CONSISTENT)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_WAS_UP_TO_DATE)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PRIMARY_IND)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_CONNECTED_IND)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_FULL_SYNC)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PEER_OUT_DATED)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_CRASHED_PRIMARY)) break;
	} while (0);
}

int m_outdate_gc(struct md_cpu *md __attribute((unused)))
{
	fprintf(stderr, "Can not outdate GC based meta data!\n");

	return 5;
}

int m_outdate_uuid(struct md_cpu *md)
{
	if ( !(md->flags & MDF_CONSISTENT) ) {
		return 5;
	}

	md->flags &= ~MDF_WAS_UP_TO_DATE;

	return 0;
}

int m_invalidate_gc(struct md_cpu *md)
{
	md->gc[Flags] &= ~MDF_CONSISTENT;
	md->gc[Flags] |= MDF_FULL_SYNC;

	return 5;
}

int m_invalidate_uuid(struct md_cpu *md)
{
	md->flags &= ~MDF_CONSISTENT;
	md->flags &= ~MDF_WAS_UP_TO_DATE;
	md->flags |= MDF_FULL_SYNC;

	return 0;
}


/******************************************
 begin of v06 {{{
 ******************************************/

int v06_md_disk_to_cpu(struct format *cfg)
{
	PREAD(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_06), cfg->md_offset);
	md_disk_06_to_cpu(&cfg->md, (struct md_on_disk_06*)on_disk_buffer);
	return v06_validate_md(cfg);
}

int v06_md_cpu_to_disk(struct format *cfg)
{
	if (v06_validate_md(cfg))
		return -1;
	md_cpu_to_disk_06(on_disk_buffer, &cfg->md);
	PWRITE(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_06), cfg->md_offset);
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
	if (asprintf(&e, "%s/drbd%lu", DRBD_LIB_DIR, minor) <= 18) {
		fprintf(stderr, "asprintf() failed.\n");
		exit(20);
	};
	cfg->md_device_name = e;

	*ai += 1;

	return 0;
}

int v06_md_open(struct format *cfg)
{
	struct stat sb;

	cfg->md_fd = open(cfg->md_device_name, O_RDWR);

	if (cfg->md_fd == -1) {
		PERROR("open(%s) failed", cfg->md_device_name);
		return NO_VALID_MD_FOUND;
	}

	if (fstat(cfg->md_fd, &sb)) {
		PERROR("fstat() failed");
		return NO_VALID_MD_FOUND;
	}

	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "'%s' is not a plain file!\n",
			cfg->md_device_name);
		return NO_VALID_MD_FOUND;
	}

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return NO_VALID_MD_FOUND;
	}

	return VALID_MD_FOUND;
}

int generic_md_close(struct format *cfg)
{
	if (close(cfg->md_fd)) {
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

void re_initialize_md_offsets(struct format *cfg)
{
	uint64_t md_size_sect;
	switch(cfg->md_index) {
	default:
		cfg->md.md_size_sect = MD_RESERVED_SECT_07;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = MD_BM_OFFSET_07;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
		cfg->md.md_size_sect = cfg->bd_size >> 9;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = MD_BM_OFFSET_07;
		break;
	case DRBD_MD_INDEX_INTERNAL:
		cfg->md.md_size_sect = MD_RESERVED_SECT_07;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = MD_BM_OFFSET_07;
		break;
	case DRBD_MD_INDEX_FLEX_INT:
		/* al size is still fixed */
		cfg->md.al_offset = -MD_AL_MAX_SECT_07;

		/* we need (slightly less than) ~ this much bitmap sectors: */
		md_size_sect = (cfg->bd_size + (1UL<<24)-1) >> 24; /* BM_EXT_SIZE_B */
		md_size_sect = (md_size_sect + 7) & ~7ULL;         /* align on 4K blocks */

		if (md_size_sect > (MD_BM_MAX_BYTE_FLEX>>9)) {
			char ppbuf[10];
			fprintf(stderr, "Device too large. We only support up to %s.\n",
					ppsize(ppbuf, MD_BM_MAX_BYTE_FLEX << (3+2)));
			if (BITS_PER_LONG == 32)
				fprintf(stderr, "Maybe try a 64bit arch?\n");
			exit(10);
		}
		/* plus the "drbd meta data super block",
		 * and the activity log; unit still sectors */
		md_size_sect += MD_BM_OFFSET_07;
		cfg->md.md_size_sect = md_size_sect;
		cfg->md.bm_offset = -md_size_sect + MD_AL_OFFSET_07;
		break;
	}
	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;
}

/* MAYBE DOES DISK WRITES!! */
int md_initialize_common(struct format *cfg, int do_disk_writes)
{
	/* no need to re-initialize the offset of md
	 * FIXME we need to, if we convert, or resize, in case we allow/implement that...
	 */
	re_initialize_md_offsets(cfg);

	cfg->md.al_nr_extents = 257;	/* arbitrary. */
	cfg->md.bm_bytes_per_bit = DEFAULT_BM_BLOCK_SIZE;

	if (verbose >= 2) {
		fprintf(stderr,"md_offset: "U64"\n", cfg->md_offset);
		fprintf(stderr,"al_offset: "U64" (%d)\n", cfg->al_offset, cfg->md.al_offset);
		fprintf(stderr,"bm_offset: "U64" (%d)\n", cfg->bm_offset, cfg->md.bm_offset);
		fprintf(stderr,"md_size_sect: %lu\n", (unsigned long)cfg->md.md_size_sect);
	}

	if (!do_disk_writes)
		return 0;

	/* do you want to initialize al to something more useful? */
	printf("initializing activity log\n");
	if (MD_AL_MAX_SECT_07*512 > buffer_size) {
		fprintf(stderr, "%s:%u: LOGIC BUG\n" , __FILE__ , __LINE__ );
		exit(111);
	}
	memset(on_disk_buffer, 0x00, MD_AL_MAX_SECT_07*512);
	pwrite_or_die(cfg->md_fd, on_disk_buffer, MD_AL_MAX_SECT_07*512, cfg->al_offset,
		"md_initialize_common:AL");

	/* THINK
	 * do we really need to initialize the bitmap? */
	if (INITIALIZE_BITMAP) {
		/* need to sector-align this for O_DIRECT.
		 * "sector" here means hard-sect size, which may be != 512.
		 * Note that even though ALIGN does round up, for sector sizes
		 * of 512, 1024, 2048, 4096 Bytes, this will be fully within
		 * the claimed meta data area, since we already align all
		 * "interesting" parts of that to 4kB */
		const size_t bm_bytes = ALIGN(cfg->bm_bytes, cfg->md_hard_sect_size);
		size_t i = bm_bytes;
		off_t bm_on_disk_off = cfg->bm_offset;
		unsigned int percent_done = 0;
		unsigned int percent_last_report = 0;
		size_t chunk;
		fprintf(stderr,"initializing bitmap (%u KB)\n",
			(unsigned int)(bm_bytes>>10));

		memset(on_disk_buffer, 0xff, buffer_size);
		while (i) {
			chunk = buffer_size < i ? buffer_size : i;
			pwrite_or_die(cfg->md_fd, on_disk_buffer,
				chunk, bm_on_disk_off,
				"md_initialize_common:BM");
			bm_on_disk_off += chunk;
			i -= chunk;
			percent_done = 100*(bm_bytes-i)/bm_bytes;
			if (percent_done != percent_last_report) {
				fprintf(stderr,"\r%u%%", percent_done);
				percent_last_report = percent_done;
			}
		}
		fprintf(stderr,"\r100%%\n");
	} else {
		fprintf(stderr,"NOT initialized bitmap\n");
	}
	return 0;
}

/******************************************
 begin of v07 {{{
 ******************************************/

uint64_t v07_style_md_get_byte_offset(const int idx, const uint64_t bd_size)
{
	uint64_t offset;

	switch(idx) {
	default: /* external, some index */
		offset = MD_RESERVED_SECT_07 * idx * 512;
		break;
	case DRBD_MD_INDEX_INTERNAL:
		offset = (bd_size & ~4095LLU)
		    - MD_RESERVED_SECT_07 * 512;
		break;
	case DRBD_MD_INDEX_FLEX_INT:
		/* sizeof(struct md_on_disk_07) == 4k
		 * position: last 4k aligned block of 4k size */
		offset  = bd_size - 4096LLU;
		offset &= ~4095LLU;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		offset = 0;
		break;
	}
	return offset;
}

void printf_al(struct format *cfg)
{
	struct al_sector_cpu al_cpu;
	off_t al_on_disk_off = cfg->al_offset;
	off_t al_size = MD_AL_MAX_SECT_07 * 512;
	struct al_sector_on_disk *al_disk = on_disk_buffer;
	unsigned s, i;
	unsigned max_slot_nr = 0;

	printf("# al {\n");
	pread_or_die(cfg->md_fd, on_disk_buffer, al_size, al_on_disk_off, "printf_al");
	for (s = 0; s < MD_AL_MAX_SECT_07; s++) {
		int ok = v07_al_disk_to_cpu(&al_cpu, al_disk + s);
		printf("#     sector %2u { %s\n", s, ok ? "valid" : "invalid");
		printf("# \tmagic: 0x%08x\n", al_cpu.magic);
		printf("# \ttr: %10u\n", al_cpu.tr_number);
		for (i = 0; i < 62; i++) {
			printf("# \t%2u: %10u %10u\n", i,
				al_cpu.updates[i].pos,
				al_cpu.updates[i].extent);
			if (al_cpu.updates[i].pos > max_slot_nr &&
			    al_cpu.updates[i].pos != -1U)
				max_slot_nr = al_cpu.updates[i].pos;
		}
		printf("# \txor: 0x%08x\n", al_cpu.xor_sum);
		printf("#     }\n");
	}
	printf("# }\n");
	if (max_slot_nr >= cfg->md.al_nr_extents)
		printf(
		"### CAUTION: maximum slot number found in AL: %u\n"
		"### CAUTION: but 'super-block' al-extents is: %u\n",
		max_slot_nr, cfg->md.al_nr_extents);

}

unsigned long bm_words(uint64_t sectors, int bytes_per_bit)
{
	unsigned long long bits;
	unsigned long long words;

	bits = ALIGN(sectors, 8) / (bytes_per_bit / 512);
	words = ALIGN(bits, 64) >> LN2_BPL;

	return words;
}

static void printf_bm_eol(unsigned int i)
{
	if ((i & 31) == 0)
		printf("\n   # at %llukB\n   ", (256LLU * i));
	else
		printf("\n   ");
}

/* le_u64, because we want to be able to hexdump it reliably
 * regardless of sizeof(long) */
void printf_bm(struct format *cfg)
{
	off_t bm_on_disk_off = cfg->bm_offset;
	le_u64 const *bm = on_disk_buffer;
	le_u64 cw; /* current word for rl encoding */
	const unsigned int n = cfg->bm_bytes/sizeof(*bm);
	unsigned int count = 0;
	unsigned int bits_set = 0;
	unsigned int n_buffer = 0;
	unsigned int r; /* real offset */
	unsigned int i; /* in-buffer offset */
	unsigned int j;

	i=0; r=0;
	cw.le = 0; /* silence compiler warning */
	printf("bm {");
	while (r < n) {
		/* need to read on first iteration,
		 * and on buffer wrap */
		if (r*sizeof(*bm) % buffer_size == 0) {
			size_t chunk = ALIGN( (n-r)*sizeof(*bm), cfg->md_hard_sect_size );
			if (chunk > buffer_size) chunk = buffer_size;
			ASSERT(chunk);
			pread_or_die(cfg->md_fd, on_disk_buffer,
				chunk, bm_on_disk_off, "printf_bm");
			bm_on_disk_off += chunk;
			i = 0;
			n_buffer = chunk/sizeof(*bm);
		}
next:
		ASSERT(i < n_buffer);
		if (count == 0) cw = bm[i];
		if ((i & 3) == 0) {
			if (!count) printf_bm_eol(r);

			/* j = i, because it may be continuation after buffer wrap */
			for (j = i; j < n_buffer && cw.le == bm[j].le; j++)
				;
			j &= ~3; // round down to a multiple of 4
			unsigned int tmp = (j-i);
			if (tmp > 4) {
				count += tmp;
				r += tmp;
				i = j;
				if (j == n_buffer && r < n) continue;
			}
			if (count) {
				printf(" %u times 0x"X64(016)";",
				       count, le64_to_cpu(cw.le));
				bits_set += count * generic_hweight64(cw.le);
				count = 0;
				if (r >= n)
					break;
				/* don't "continue;", we may have not advanced i after buffer wrap,
				 * so that would be treated as an other buffer wrap */
				goto next;
			}
		}
		ASSERT(i < n_buffer);
		printf(" 0x"X64(016)";", le64_to_cpu(bm[i].le));
		bits_set += generic_hweight64(bm[i].le);
		r++; i++;
	}
	printf("\n}\n");
	cfg->bits_set = bits_set;
}

int v07_style_md_open(struct format *cfg)
{
	struct stat sb;
	unsigned long words;
	unsigned long hard_sect_size = 0;
	int ioctl_err;
	int open_flags = O_RDWR | O_SYNC | O_DIRECT;

 retry:
	cfg->md_fd = open(cfg->md_device_name, open_flags );

	if (cfg->md_fd == -1) {
		if (errno == EINVAL && (open_flags & O_DIRECT)) {
			/* shoo. O_DIRECT is not supported?
			 * retry, but remember this, so we can
			 * BLKFLSBUF appropriately */
			fprintf(stderr, "could not open with O_DIRECT, retrying without\n");
			open_flags &= ~O_DIRECT;
			opened_odirect = 0;
			goto retry;
		}
		PERROR("open(%s) failed", cfg->md_device_name);
		exit(20);
	}

	if (fstat(cfg->md_fd, &sb)) {
		PERROR("fstat(%s) failed", cfg->md_device_name);
		exit(20);
	}

	if (!S_ISBLK(sb.st_mode)) {
		fprintf(stderr, "'%s' is not a block device!\n",
			cfg->md_device_name);
		exit(20);
	}

	if (is_v08(cfg)) {
		ASSERT(cfg->md_index != DRBD_MD_INDEX_INTERNAL);
	}
	ioctl_err = ioctl(cfg->md_fd, BLKSSZGET, &hard_sect_size);
	if (ioctl_err) {
		fprintf(stderr, "ioctl(md_fd, BLKSSZGET) returned %d, "
			"assuming hard_sect_size is 512 Byte\n", ioctl_err);
		cfg->md_hard_sect_size = 512;
	} else {
		cfg->md_hard_sect_size = hard_sect_size;
		if (verbose >= 2)
			fprintf(stderr, "hard_sect_size is %d Byte\n",
				cfg->md_hard_sect_size);
	}

	cfg->bd_size = bdev_size(cfg->md_fd);
	if ((cfg->bd_size >> 9) < MD_BM_OFFSET_07) {
		fprintf(stderr, "%s is only %llu bytes. That's not enough.\n",
			cfg->md_device_name, (long long unsigned)cfg->bd_size);
		exit(10);
	}
	cfg->md_offset =
		v07_style_md_get_byte_offset(cfg->md_index, cfg->bd_size);
	if (cfg->md_offset > cfg->bd_size - 4096) {
		fprintf(stderr,
			"Device too small: expecting meta data block at\n"
			"byte offset %lld, but %s is only %llu bytes.\n",
			(signed long long)cfg->md_offset,
			cfg->md_device_name,
			(long long unsigned)cfg->bd_size);
		exit(10);
	}

	if (!opened_odirect &&
	    (MAJOR(sb.st_rdev) != RAMDISK_MAJOR)) {
		ioctl_err = ioctl(cfg->md_fd, BLKFLSBUF);
		/* report error, but otherwise ignore.  we could not open
		 * O_DIRECT, it is a "strange" device anyways. */
		if (ioctl_err)
			fprintf(stderr, "ioctl(md_fd, BLKFLSBUF) returned %d, "
					"we may read stale data\n", ioctl_err);
	}

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		/* no valid meta data found.  but we want to initialize
		 * al_offset and bm_offset anyways, so check_for_existing_data
		 * has something to work with. */
		re_initialize_md_offsets(cfg);
		return NO_VALID_MD_FOUND;
	}

	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;

	// For the case that someone modified la_sect by hand..
	if( (cfg->md_index == DRBD_MD_INDEX_INTERNAL ||
	     cfg->md_index == DRBD_MD_INDEX_FLEX_INT ) &&
	    (cfg->md.la_sect*512 > cfg->md_offset) ) {
		printf("la-size-sect was too big, fixed.\n");
		cfg->md.la_sect = cfg->md_offset/512;
	}
	if(cfg->md.bm_bytes_per_bit == 0 ) {
		printf("bm-byte-per-bit was 0, fixed. (Set to 4096)\n");
		cfg->md.bm_bytes_per_bit = 4096;
	}
	words = bm_words(cfg->md.la_sect, cfg->md.bm_bytes_per_bit);
	cfg->bm_bytes = words * sizeof(long);

	//fprintf(stderr,"al_offset: "U64" (%d)\n", cfg->al_offset, cfg->md.al_offset);
	//fprintf(stderr,"bm_offset: "U64" (%d)\n", cfg->bm_offset, cfg->md.bm_offset);

	cfg->bits_set = -1U;

	/* FIXME paranoia verify that unused bits and words are unset... */
	/* FIXME paranoia verify that unused bits and words are unset... */

	return VALID_MD_FOUND;
}

int v07_md_disk_to_cpu(struct format *cfg)
{
	struct md_cpu md;
	int ok;
	PREAD(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_07), cfg->md_offset);
	md_disk_07_to_cpu(&md, (struct md_on_disk_07*)on_disk_buffer);
	ok = is_valid_md(Drbd_07, &md, cfg->md_index, cfg->bd_size);
	if (ok)
		cfg->md = md;
	return ok ? 0 : -1;
}

int v07_md_cpu_to_disk(struct format *cfg)
{
	if (!is_valid_md(Drbd_07, &cfg->md, cfg->md_index, cfg->bd_size))
		return -1;
	md_cpu_to_disk_07(on_disk_buffer, &cfg->md);
	PWRITE(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_07), cfg->md_offset);
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

	cfg->md_device_name = strdup(argv[0]);
	if (!strcmp(argv[1],"internal")) {
		index =
		  is_v07(cfg) ? DRBD_MD_INDEX_INTERNAL
			      : DRBD_MD_INDEX_FLEX_INT;
	} else if (!strcmp(argv[1],"flex-external")) {
		index = DRBD_MD_INDEX_FLEX_EXT;
	} else if (!strcmp(argv[1],"flex-internal")) {
		index = DRBD_MD_INDEX_FLEX_INT;
	} else {
		e = argv[1];
		errno = 0;
		index = strtol(argv[1], &e, 0);
		if (*e != 0 || 0 > index || index > 255 || errno != 0) {
			fprintf(stderr, "'%s' is not a valid index number.\n", argv[1]);
			return -1;
		}
	}
	cfg->md_index = index;

	*ai += 2;

	return 0;
}

int _v07_md_initialize(struct format *cfg, int do_disk_writes)
{
	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.la_sect = 0;
	cfg->md.gc[Flags] = 0;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.magic = DRBD_MD_MAGIC_07;

	return md_initialize_common(cfg, do_disk_writes);
}

int v07_md_initialize(struct format *cfg)
{
	return _v07_md_initialize(cfg, 1);
}

/******************************************
  }}} end of v07
 ******************************************/
/******************************************
 begin of v08 {{{
 ******************************************/

/* if this returns with something != 0 in cfg->lk_bd.bd_size,
 * caller knows he must move the meta data to actually find it. */
void v08_check_for_resize(struct format *cfg)
{
	struct md_cpu md_08;
	off_t flex_offset;
	int found = 0;

	/* you should not call me if you already found something. */
	ASSERT(cfg->md.magic == 0);

	/* check for resized lower level device ... only check for drbd 8 */
	if (!is_v08(cfg))
		return;
	if (cfg->md_index != DRBD_MD_INDEX_FLEX_INT)
		return;

	/* Do we know anything? Maybe it never was stored. */
	if (lk_bdev_load(cfg->minor, &cfg->lk_bd)) {
		if (verbose)
			fprintf(stderr, "no last-known offset information available.\n");
		return;
	}

	if (verbose) {
		fprintf(stderr, " last known info: %llu %s\n",
			(unsigned long long)cfg->lk_bd.bd_size,
			cfg->lk_bd.bd_name ?: "-unknown device name-");
		if (cfg->lk_bd.bd_uuid)
			fprintf(stderr, " last known uuid: "X64(016)"\n",
				cfg->lk_bd.bd_uuid);
	}

	/* I just checked that offset, nothing to see there. */
	if (cfg->lk_bd.bd_size == cfg->bd_size)
		return;

	flex_offset = v07_style_md_get_byte_offset(
		DRBD_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);

	/* actually check that offset, if it is accessible. */
	/* If someone shrunk that device, I won't be able to read it! */
	if (flex_offset < cfg->bd_size) {
		PREAD(cfg->md_fd, on_disk_buffer, 4096, flex_offset);
		md_disk_08_to_cpu(&md_08, (struct md_on_disk_08*)on_disk_buffer);
		found = is_valid_md(Drbd_08, &md_08, DRBD_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);
	}

	if (verbose) {
		fprintf(stderr, "While checking for internal meta data for drbd%u on %s,\n"
				"it appears that it may have been relocated.\n"
				"It used to be ", cfg->minor, cfg->md_device_name);
		if (cfg->lk_bd.bd_name &&
			strcmp(cfg->lk_bd.bd_name, cfg->md_device_name)) {
			fprintf(stderr, "on %s ", cfg->lk_bd.bd_name);
		}
		fprintf(stderr, "at byte offset %llu", (unsigned long long)flex_offset);

		if (!found) {
			fprintf(stderr, ", but I cannot find it now.\n");
			if (flex_offset >= cfg->bd_size)
				fprintf(stderr, "Device is too small now!\n");
		} else
			fprintf(stderr, ", and seems to still be valid.\n");
	}

	if (found) {
		if (cfg->lk_bd.bd_uuid && md_08.device_uuid != cfg->lk_bd.bd_uuid) {
			fprintf(stderr, "Last known and found uuid differ!?\n"
					X64(016)" != "X64(016)"\n",
					cfg->lk_bd.bd_uuid, cfg->md.device_uuid);
			if (!force) {
				found = 0;
				fprintf(stderr, "You may --force me to ignore that.\n");
			} else
				fprintf(stderr, "You --force'ed me to ignore that.\n");
		}
	}
	if (found)
		cfg->md = md_08;
	return;
}

int v08_md_open(struct format *cfg) {
	int r = v07_style_md_open(cfg);
	if (r == VALID_MD_FOUND)
		return r;

	v08_check_for_resize(cfg);
	if (!cfg->lk_bd.bd_size || !cfg->md.magic)
		return NO_VALID_MD_FOUND;
	else
		return VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION;
}

int v08_md_disk_to_cpu(struct format *cfg)
{
	struct md_cpu md;
	int ok;
	PREAD(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_08), cfg->md_offset);
	md_disk_08_to_cpu(&md, (struct md_on_disk_08*)on_disk_buffer);
	ok = is_valid_md(Drbd_08, &md, cfg->md_index, cfg->bd_size);
	if (ok)
		cfg->md = md;
	if (verbose >= 3 + !!ok && verbose <= 10)
		fprintf_hex(stderr, cfg->md_offset, on_disk_buffer, 4096);
	return ok ? 0 : -1;
}

int v08_md_cpu_to_disk(struct format *cfg)
{
	if (!is_valid_md(Drbd_08, &cfg->md, cfg->md_index, cfg->bd_size))
		return -1;
	md_cpu_to_disk_08((struct md_on_disk_08 *)on_disk_buffer, &cfg->md);
	PWRITE(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_08), cfg->md_offset);
	cfg->update_lk_bdev = 1;
	return 0;
}

int _v08_md_initialize(struct format *cfg, int do_disk_writes)
{
	size_t i;

	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.la_sect = 0;
	cfg->md.uuid[UI_CURRENT] = UUID_JUST_CREATED;
	cfg->md.uuid[UI_BITMAP] = 0;
	for ( i=UI_HISTORY_START ; i<=UI_HISTORY_END ; i++ ) {
		cfg->md.uuid[i]=0;
	}
	cfg->md.flags = 0;
	cfg->md.magic = DRBD_MD_MAGIC_08;

	return md_initialize_common(cfg, do_disk_writes);
}

int v08_md_initialize(struct format *cfg)
{
	return _v08_md_initialize(cfg, 1);
}

int v08_md_close(struct format *cfg)
{
	/* update last known info, if we changed anything,
	 * or if explicitly requested. */
	if (cfg->update_lk_bdev && !dry_run) {
		if (cfg->md_index != DRBD_MD_INDEX_FLEX_INT)
			lk_bdev_delete(cfg->minor);
		else {
			cfg->lk_bd.bd_size = cfg->bd_size;
			cfg->lk_bd.bd_uuid = cfg->md.device_uuid;
			cfg->lk_bd.bd_name = cfg->md_device_name;
			lk_bdev_save(cfg->minor, &cfg->lk_bd);
		}
	}
	return generic_md_close(cfg);
}

/******************************************
  }}} end of v08
 ******************************************/
int meta_get_gi(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->ops->get_gi(&cfg->md);

	return cfg->ops->close(cfg);
}

int meta_show_gi(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	char ppb[10];

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->ops->show_gi(&cfg->md);

	if (cfg->md.la_sect) {
		printf("last agreed size: %s\n",
		       ppsize(ppb, cfg->md.la_sect >> 1));
#if 0
		/* FIXME implement count_bits() */
		printf("%u bits set in the bitmap [ %s out of sync ]\n",
		       cfg->bits_set, ppsize(ppb, cfg->bits_set * 4));
#endif
	} else {
		printf("zero size device -- never seen peer yet?\n");
	}

	return cfg->ops->close(cfg);
}

int meta_dstate(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg)) {
		fprintf(stderr, "No valid meta data found\n");
		return -1;
	}

	if(cfg->md.flags & MDF_CONSISTENT) {
		if(cfg->md.flags & MDF_WAS_UP_TO_DATE) {
			printf("Consistent/DUnknown\n");
		} else {
			printf("Outdated/DUnknown\n");
		}
	} else {
		printf("Inconsistent/DUnknown\n");
	}

	return cfg->ops->close(cfg);
}

int meta_set_gi(struct format *cfg, char **argv, int argc)
{
	struct md_cpu tmp;
	int err;

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

	cfg->ops->set_gi(&tmp,argv,argc);
	printf("previously ");
	cfg->ops->get_gi(&cfg->md);
	printf("set GI to  ");
	cfg->ops->get_gi(&tmp);

	if (!confirmed("Write new GI to disk?")) {
		printf("Operation canceled.\n");
		exit(0);
	}

	cfg->md = tmp;

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}

void print_dump_header()
{
	char time_str[60];
	struct utsname nodeinfo;
	time_t t = time(NULL);
	int i;

	strftime(time_str, sizeof(time_str), "%F %T %z [%s]", localtime(&t));
	uname(&nodeinfo);
	printf("# DRBD meta data dump\n# %s\n# %s>",
		time_str, nodeinfo.nodename);

	for (i=0; i < global_argc; i++)
		printf(" %s",global_argv[i]);
	printf("\n#\n\n");
}

int meta_dump_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int i;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	i = cfg->ops->open(cfg);
	if (i == NO_VALID_MD_FOUND)
		return -1;

	print_dump_header();
	printf("version \"%s\";\n\n", cfg->ops->name);
	printf("# md_size_sect %llu\n", (long long unsigned)cfg->md.md_size_sect);

	if (i == VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION) {
		printf("#\n"
		"### Device seems to have been resized!\n"
		"### dumping meta data from the last known position\n"
		"### current size of %s: %llu byte\n"
		"### expected position of meta data:\n",
		cfg->md_device_name, (unsigned long long)cfg->bd_size);

		printf("## md_offset %llu\n", (long long unsigned)cfg->md_offset);
		printf("## al_offset %llu\n", (long long unsigned)cfg->al_offset);
		printf("## bm_offset %llu\n", (long long unsigned)cfg->bm_offset);

		printf(
		"### last known size of %s: %llu byte\n"
		"### adjusted position of meta data:\n",
		cfg->lk_bd.bd_name ?: "-?-",
		(unsigned long long)cfg->lk_bd.bd_size);

		cfg->md_offset = v07_style_md_get_byte_offset(
			DRBD_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);

		cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512;
		cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;
		cfg->bm_bytes = sizeof(long) *
			bm_words(cfg->md.la_sect, cfg->md.bm_bytes_per_bit);
	}
	printf("# md_offset %llu\n", (long long unsigned)cfg->md_offset);
	printf("# al_offset %llu\n", (long long unsigned)cfg->al_offset);
	printf("# bm_offset %llu\n", (long long unsigned)cfg->bm_offset);
	printf("\n");

	if (format_version(cfg) < Drbd_08) {
		printf("gc {\n   ");
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			printf(" %d;", cfg->md.gc[i]);
		}
		printf("\n}\n");
	} else { // >= 08
		printf("uuid {\n   ");
		for ( i=UI_CURRENT ; i<UI_SIZE ; i++ ) {
			printf(" 0x"X64(016)";", cfg->md.uuid[i]);
		}
		printf("\n");
		printf("    flags 0x"X32(08)";\n",cfg->md.flags);
		printf("}\n");
	}

	if (format_version(cfg) >= Drbd_07) {
		printf("# al-extents %u;\n", cfg->md.al_nr_extents);
		printf("la-size-sect "U64";\n", cfg->md.la_sect);
		if (format_version(cfg) >= Drbd_08) {
			printf("bm-byte-per-bit "U32";\n",
			       cfg->md.bm_bytes_per_bit);
			printf("device-uuid 0x"X64(016)";\n",
			       cfg->md.device_uuid);
		}
		printf("# bm-bytes %u;\n", cfg->bm_bytes);
		printf_bm(cfg); /* pretty prints the whole bitmap */
		printf("# bits-set %u;\n", cfg->bits_set);

		/* This is half assed, still. Hide it. */
		if (verbose >= 10)
			printf_al(cfg);
	}

	return cfg->ops->close(cfg);
}

void md_parse_error(int expected_token, int seen_token,const char *etext)
{
	if (!etext) {
		switch(expected_token) {
		/* leading space indicates to strip off "expected" below */
		default : etext = " invalid/unexpected token!"; break;
		case 0  : etext = "end of file"; break;
		case ';': etext = "semicolon (;)"; break;
		case '{': etext = "opening brace ({)"; break;
		case '}': etext = "closing brace (})"; break;
		case TK_BM:
			etext = "keyword 'bm'"; break;
		case TK_BM_BYTE_PER_BIT:
			etext = "keyword 'bm-byte-per-bit'"; break;
		case TK_DEVICE_UUID:
			etext = "keyword 'device-uuid'"; break;
		case TK_FLAGS:
			etext = "keyword 'flags'"; break;
		case TK_GC:
			etext = "keyword 'gc'"; break;
		case TK_LA_SIZE:
			etext = "keyword 'la-size-sect'"; break;
		case TK_TIMES:
			etext = "keyword 'times'"; break;
		case TK_UUID:
			etext = "keyword 'uuid'"; break;
		case TK_VERSION:
			etext = "keyword 'version'"; break;
		case TK_NUM:
			etext = "number ([0-9], up to 20 digits)"; break;
		case TK_STRING:
			etext = "short quoted string "
				"(\"..up to 20 characters, no newline..\")";
				break;
		case TK_U32:
			etext = "an 8-digit hex number"; break;
		case TK_U64:
			etext = "a 16-digit hex number"; break;
		}
	}
	fflush(stdout);
	fprintf(stderr,"Parse error in line %u: %s%s",
		yylineno, etext,
		(etext[0] == ' ' ? ":" : " expected")
		);

	switch(seen_token) {
	case 0:
		fprintf(stderr, ", but end of file encountered\n"); break;

	case   1 ...  58: /* ord(';') == 58 */
	case  60 ... 122: /* ord('{') == 123 */
	case 124:         /* ord('}') == 125 */
	case 126 ... 257:
		/* oopsie. these should never be returned! */
		fprintf(stderr, "; got token value %u (this should never happen!)\n", seen_token); break;
		break;

	case TK_INVALID_CHAR:
		fprintf(stderr,"; got invalid input character '\\x%02x' [%c]\n",
			(unsigned char)yylval.txt[0], yylval.txt[0]);
		break;
	case ';': case '{': case '}':
		fprintf(stderr, ", not '%c'\n", seen_token); break;
	case TK_NUM:
	case TK_U32:
	case TK_U64:
		fprintf(stderr, ", not some number\n"); break;
	case TK_INVALID:
		/* already reported by scanner */
		fprintf(stderr,"\n"); break;
	default:
		fprintf(stderr, ", not '%s'\n", yylval.txt);
	}
	exit(10);
}

static void EXP(int expected_token) {
	int tok = yylex();
	if (tok != expected_token)
		md_parse_error(expected_token, tok, NULL);
}

void check_for_existing_data(struct format *cfg);

int verify_dumpfile_or_restore(struct format *cfg, char **argv, int argc, int parse_only)
{
	int i,times;
	int err;
	off_t bm_on_disk_off;
	le_u64 *bm, value;

	if (argc > 0) {
		yyin = fopen(argv[0],"r");
		if(yyin == NULL) {
			fprintf(stderr, "open of '%s' failed.\n",argv[0]);
			exit(20);
		}
	}

	if (!parse_only) {
		if (!cfg->ops->open(cfg)) {
			if (!confirmed("Valid meta-data in place, overwrite?"))
				return -1;
		} else {
			check_for_existing_data(cfg);

			ASSERT(!is_v06(cfg));
		}
		fprintf(stderr, "reinitializing\n");
		if (is_v07(cfg))
			_v07_md_initialize(cfg,0);
		else
			_v08_md_initialize(cfg,0);
	}

	EXP(TK_VERSION); EXP(TK_STRING);
	if(strcmp(yylval.txt,cfg->ops->name)) {
		fprintf(stderr,"dump is '%s' you requested '%s'.\n",
			yylval.txt,cfg->ops->name);
		exit(10);
	}
	EXP(';');
	if (format_version(cfg) < Drbd_08) {
		EXP(TK_GC); EXP('{');
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			EXP(TK_NUM); EXP(';');
			cfg->md.gc[i] = yylval.u64;
		}
		EXP('}');
	} else { // >= 08
		EXP(TK_UUID); EXP('{');
		for ( i=UI_CURRENT ; i<UI_SIZE ; i++ ) {
			EXP(TK_U64); EXP(';');
			cfg->md.uuid[i] = yylval.u64;
		}
		EXP(TK_FLAGS); EXP(TK_U32); EXP(';');
		cfg->md.flags = (uint32_t)yylval.u64;
		EXP('}');
	}
	EXP(TK_LA_SIZE); EXP(TK_NUM); EXP(';');
	cfg->md.la_sect = yylval.u64;
	if (format_version(cfg) >= Drbd_08) {
		EXP(TK_BM_BYTE_PER_BIT); EXP(TK_NUM); EXP(';');
		cfg->md.bm_bytes_per_bit = yylval.u64;
		EXP(TK_DEVICE_UUID); EXP(TK_U64); EXP(';');
		cfg->md.device_uuid = yylval.u64;
	} else {
		cfg->md.bm_bytes_per_bit = 4096;
	}
	EXP(TK_BM); EXP('{');
	bm = (le_u64 *)on_disk_buffer;
	i = 0;
	bm_on_disk_off = cfg->bm_offset;
	while(1) {
		int tok = yylex();
		switch(tok) {
		case TK_U64:
			EXP(';');
			/* NOTE:
			 * even though this EXP(';'); already advanced
			 * to the next token, yylval will *not* be updated
			 * for * ';', so it is still valid.
			 *
			 * This seemed to be the least ugly way to implement a
			 * "parse_only" functionality without ugly if-branches
			 * or the maintenance nightmare of code duplication */
			if (parse_only) break;
			bm[i].le = cpu_to_le64(yylval.u64);
			if ((unsigned)++i == buffer_size/sizeof(*bm)) {
				pwrite_or_die(cfg->md_fd, on_disk_buffer,
					buffer_size, bm_on_disk_off,
					"meta_restore_md:TK_U64");
				bm_on_disk_off += buffer_size;
				i = 0;
			}
			break;
		case TK_NUM:
			times = yylval.u64;
			EXP(TK_TIMES);
			EXP(TK_U64);
			EXP(';');
			if (parse_only) break;
			value.le = cpu_to_le64(yylval.u64);
			while(times--) {
				bm[i] = value;
				if ((unsigned)++i == buffer_size/sizeof(*bm)) {
					pwrite_or_die(cfg->md_fd, on_disk_buffer,
						buffer_size, bm_on_disk_off,
						"meta_restore_md:TK_NUM");
					bm_on_disk_off += buffer_size;
					i = 0;
				}
			}
			break;
		case '}':
			goto break_loop;
		default:
			md_parse_error(0 /* ignored, since etext is set */,
				tok, "repeat count, 16-digit hex number, or closing brace (})");
			goto break_loop;
		}
	}
	break_loop:

	/* there should be no trailing garbage in the input file */
	EXP(0);

	if (parse_only) {
		printf("input file parsed ok\n");
		return 0;
	}

	/* not reached if parse_only */
	if (i) {
		size_t s = i * sizeof(*bm);
		memset(bm+i, 0x00, buffer_size - s);
		/* need to sector-align this for O_DIRECT. to be
		 * generic, maybe we even need to PAGE align it? */
		s = ALIGN(s, cfg->md_hard_sect_size);
		pwrite_or_die(cfg->md_fd, on_disk_buffer,
			s, bm_on_disk_off, "meta_restore_md");
	}

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err) {
		fprintf(stderr, "Writing failed\n");
		return -1;
	}

	printf("Successfully restored meta data\n");

	return 0;
}

int meta_restore_md(struct format *cfg, char **argv, int argc)
{
	return verify_dumpfile_or_restore(cfg,argv,argc,0);
}

int meta_verify_dump_file(struct format *cfg, char **argv, int argc)
{
	return verify_dumpfile_or_restore(cfg,argv,argc,1);
}

void md_convert_07_to_08(struct format *cfg)
{
	int i,j;
	/*
	 * FIXME
	 * what about the UI_BITMAP, and the Activity Log?
	 * how to bring them over for internal meta data?
	 *
	 * maybe just refuse to convert anything that is not
	 * "clean"? how to detect that?
	 *
	 * FIXME: if I am a crashed R_PRIMARY, or D_INCONSISTENT,
	 * or Want-Full-Sync or the like,
	 * refuse, and indicate how to solve this */

	printf("Converting meta data...\n");

	//if (!cfg->bits_counted) count_bits(cfg);
	/* FIXME:
	 * if this is "internal" meta data, and I have bits set,
	 * either move the bitmap into the newly expected place,
	 * or refuse, and indicate how to solve this */

	/* KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	cfg->md.magic = DRBD_MD_MAGIC_08;

	// The MDF Flags are (nearly) the same in 07 and 08
	cfg->md.flags = cfg->md.gc[Flags];

	cfg->md.uuid[UI_CURRENT] =
		(uint64_t)(cfg->md.gc[HumanCnt] & 0xffff) << 48 |
		(uint64_t)(cfg->md.gc[TimeoutCnt] & 0xffff) << 32 |
		(uint64_t)((cfg->md.gc[ConnectedCnt]+cfg->md.gc[ArbitraryCnt])
		       & 0xffff) << 16 |
		(uint64_t)0xbabe;
	cfg->md.uuid[UI_BITMAP] = (uint64_t)0;

	for (i = cfg->bits_set ? UI_BITMAP : UI_HISTORY_START, j = 1;
		i <= UI_HISTORY_END ; i++, j++)
		cfg->md.uuid[i] = cfg->md.uuid[UI_CURRENT] - j*0x10000;

	/* unconditionally re-initialize offsets,
	 * not necessary if fixed size external,
	 * necessary if flex external or internal */
	re_initialize_md_offsets(cfg);

	if (!is_valid_md(Drbd_08, &cfg->md, cfg->md_index, cfg->bd_size)) {
		fprintf(stderr, "Conversion failed.\nThis is a bug :(\n");
		exit(111);
	}
}

void md_convert_08_to_07(struct format *cfg)
{
	/*
	 * FIXME
	 * what about the UI_BITMAP, and the Activity Log?
	 * how to bring them over for internal meta data?
	 *
	 * maybe just refuse to convert anything that is not
	 * "clean"? how to detect that?
	 *
	 * FIXME: if I am a crashed R_PRIMARY, or D_INCONSISTENT,
	 * or Want-Full-Sync or the like,
	 * refuse, and indicate how to solve this */

	printf("Converting meta data...\n");
	//if (!cfg->bits_counted) count_bits(cfg);
	/* FIXME:
	 * if this is "internal" meta data, and I have bits set,
	 * either move the bitmap into the newly expected place,
	 * or refuse, and indicate how to solve this */

	/* KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	cfg->md.magic = DRBD_MD_MAGIC_07;

	/* FIXME somehow generate GCs in a sane way */
	/* FIXME convert the flags? */
	printf("Conversion v08 -> v07 is BROKEN!\n"
		"Be prepared to manually intervene!\n");
	/* FIXME put some more helpful text here, indicating what exactly is to
	 * be done to make this work as expected. */

	/* unconditionally re-initialize offsets,
	 * not necessary if fixed size external,
	 * necessary if flex external or internal */
	re_initialize_md_offsets(cfg);

	if (!is_valid_md(Drbd_07, &cfg->md, cfg->md_index, cfg->bd_size)) {
		fprintf(stderr, "Conversion failed.\nThis is a bug :(\n");
		exit(111);
	}
}

/* if on the physical device we find some data we can interpret,
 * print some informational message about what we found,
 * and what we think how much room it needs.
 *
 * look into /usr/share/misc/magic for inspiration
 * also consider e.g. xfsprogs/libdisk/fstype.c,
 * and of course the linux kernel headers...
 */
struct fstype_s {
	const char * type;
	unsigned long long bnum, bsize;
};

int may_be_extX(const char *data, struct fstype_s *f)
{
	unsigned int size;
	if (le16_to_cpu(*(uint16_t*)(data+0x438)) == 0xEF53) {
		if ( (le32_to_cpu(*(data+0x45c)) & 4) == 4 )
			f->type = "ext3 filesystem";
		else
			f->type = "ext2 filesystem";
		f->bnum  = le32_to_cpu(*(uint32_t*)(data+0x404));
		size     = le32_to_cpu(*(uint32_t*)(data+0x418));
		f->bsize = size == 0 ? 1024 :
			size == 1 ? 2048 :
			size == 2 ? 4096 :
			4096; /* DEFAULT */
		return 1;
	}
	return 0;
}

int may_be_xfs(const char *data, struct fstype_s *f)
{
	if (be32_to_cpu(*(uint32_t*)(data+0)) == 0x58465342) {
		f->type = "xfs filesystem";
		f->bsize = be32_to_cpu(*(uint32_t*)(data+4));
		f->bnum  = be64_to_cpu(*(uint64_t*)(data+8));
		return 1;
	}
	return 0;
}

int may_be_reiserfs(const char *data, struct fstype_s *f)
{
	if (strncmp("ReIsErFs",data+0x10034,8) == 0 ||
	    strncmp("ReIsEr2Fs",data+0x10034,9) == 0) {
		f->type = "reiser filesystem";
		f->bnum  = le32_to_cpu(*(uint32_t*)(data+0x10000));
		f->bsize = le16_to_cpu(*(uint16_t*)(data+0x1002c));
		return 1;
	}
	return 0;
}

int may_be_jfs(const char *data, struct fstype_s *f)
{
	if (strncmp("JFS1",data+0x8000,4) == 0) {
		f->type = "JFS filesystem";
		f->bnum = le64_to_cpu(*(uint64_t*)(data+0x8008));
		f->bsize = le32_to_cpu(*(uint32_t*)(data+0x8018));
		return 1;
	}
	return 0;
}

/* really large block size,
 * will always refuse */
#define REFUSE_BSIZE	0xFFFFffffFFFF0000LLU
#define ERR_BSIZE	0xFFFFffffFFFF0001LLU
#define REFUSE_IT()	do { f->bnum = 1; f->bsize = REFUSE_BSIZE; } while(0)
#define REFUSE_IT_ERR()	do { f->bnum = 1; f->bsize = ERR_BSIZE; } while(0)
int may_be_swap(const char *data, struct fstype_s *f)
{
	int looks_like_swap =
		strncmp(data+(1<<12)-10, "SWAP-SPACE", 10) == 0 ||
		strncmp(data+(1<<12)-10, "SWAPSPACE2", 10) == 0 ||
		strncmp(data+(1<<13)-10, "SWAP-SPACE", 10) == 0 ||
		strncmp(data+(1<<13)-10, "SWAPSPACE2", 10) == 0;
	if (looks_like_swap) {
		f->type = "swap space signature";
		REFUSE_IT();
		return 1;
	}
	return 0;
}

#define N_ERR_LINES 4
#define MAX_ERR_LINE_LEN 1024
int guessed_size_from_pvs(struct fstype_s *f, char *dev_name)
{
	char buf_in[200];
	char *buf_err[N_ERR_LINES];
	size_t c;
	unsigned long long bnum;
	int pipes[3][2];
	int err_lines = 0;
	FILE *child_err = NULL;
	int i;
	int ret = 0;
	pid_t pid;

	buf_err[0] = calloc(N_ERR_LINES, MAX_ERR_LINE_LEN);
	if (!buf_err[0])
		return 0;
	for (i = 1; i < N_ERR_LINES; i++)
		buf_err[i] = buf_err[i-1] + MAX_ERR_LINE_LEN;

	for (i = 0; i < 3; i++) {
		if (pipe(pipes[i]))
			goto out;
	}

	pid = fork();
	if (pid < 0)
		goto out;

	if (pid == 0) {
		/* child */
		char *argv[] = {
			"pvs", "-vvv", "--noheadings", "--nosuffix", "--units", "s",
			"-o", "pv_size",
			dev_name,
			NULL,
		};
		close(pipes[0][1]); /* close unused pipe ends */
		close(pipes[1][0]);
		close(pipes[2][0]);

		dup2(pipes[0][0],0); /* map to expected stdin/out/err */
		dup2(pipes[1][1],1);
		dup2(pipes[2][1],2);

		close(0); /* we do not use stdin */
		execvp(argv[0], argv);
		_exit(0);
	}
	/* parent */
	close(pipes[0][0]); /* close unused pipe ends */
	close(pipes[1][1]);
	close(pipes[2][1]);

	close(pipes[0][1]); /* we do not use stdin in child */

	/* We use blocking IO on pipes. This could deadlock,
	 * If the child process would do something unexpected.
	 * We do know the behaviour of pvs, though,
	 * and expect only a few bytes on stdout,
	 * and quite a few debug messages on stderr.
	 *
	 * First drain stderr, keeping the last N_ERR_LINES,
	 * then read stdout. */
	child_err = fdopen(pipes[2][0], "r");
	if (child_err) {
		char *b;
		do {
			err_lines = (err_lines + 1) % N_ERR_LINES;
			b = fgets(buf_err[err_lines], MAX_ERR_LINE_LEN, child_err);
		} while (b);
	}

	c = read(pipes[1][0], buf_in, sizeof(buf_in)-1);
	if (c > 0) {
		buf_in[c] = 0;
		if (1 == sscanf(buf_in, " %llu\n", &bnum)) {
			f->bnum = bnum;
			f->bsize = 512;
			ret = 1;
		}
	}
	if (!ret) {
		for (i = 0; i < N_ERR_LINES; i++) {
			char *b = buf_err[(err_lines + i) % N_ERR_LINES];
			if (b[0] == 0)
				continue;
			fprintf(stderr, "pvs stderr:%s", b);
		}
		fprintf(stderr, "\n");
	}

	i = 2;
out:
	for ( ; i >= 0; i--) {
		close(pipes[i][0]);
		close(pipes[i][1]);
	}
	if (child_err)
		fclose(child_err);
	free(buf_err[0]);
	return ret;
}

int may_be_LVM(const char *data, struct fstype_s *f, char *dev_name)
{
	if (strncmp("LVM2",data+0x218,4) == 0) {
		f->type = "LVM2 physical volume signature";
		if (!guessed_size_from_pvs(f, dev_name))
			REFUSE_IT_ERR();
		return 1;
	}
	return 0;
}

/* XXX should all this output go to stderr? */
void check_for_existing_data(struct format *cfg)
{
	struct fstype_s f;
	size_t i;
	uint64_t fs_kB;
	uint64_t max_usable_kB;

	PREAD(cfg->md_fd, on_disk_buffer, SO_MUCH, 0);

	for (i = 0; i < SO_MUCH/sizeof(long); i++) {
		if (((long*)(on_disk_buffer))[i] != 0LU) break;
	}
	/* all zeros? no message */
	if (i == SO_MUCH/sizeof(long)) return;

	f.type = "some data";
	f.bnum = 0;
	f.bsize = 0;

/* FIXME add more detection magic.
 * Or, rather, use some lib.
 */

	(void)(
	may_be_swap     (on_disk_buffer,&f) ||
	may_be_LVM      (on_disk_buffer,&f, cfg->md_device_name) ||

	may_be_extX     (on_disk_buffer,&f) ||
	may_be_xfs      (on_disk_buffer,&f) ||
	may_be_jfs      (on_disk_buffer,&f) ||
	may_be_reiserfs (on_disk_buffer,&f)
	);

	/* FIXME
	 * some of the messages below only make sense for internal meta data.
	 * for external meta data, we now only checked the meta-disk.
	 * we should still check the actual lower level storage area for
	 * existing data, too, and give appropriate warnings when it would
	 * appear to be truncated by too small external meta data */

	printf("md_offset %llu\n", (long long unsigned)cfg->md_offset);
	printf("al_offset %llu\n", (long long unsigned)cfg->al_offset);
	printf("bm_offset %llu\n", (long long unsigned)cfg->bm_offset);

	printf("\nFound %s\n", f.type);

	/* FIXME overflow check missing!
	 * relevant for ln2(bsize) + ln2(bnum) >= 64, thus only for
	 * device sizes of more than several exa byte.
	 * seems irrelevant to me for now.
	 */
	fs_kB = ((f.bsize * f.bnum) + (1<<10)-1) >> 10;
#define min(x,y) ((x) < (y) ? (x) : (y))
	max_usable_kB =
		min( cfg->md_offset,
		min( cfg->al_offset,
		     cfg->bm_offset )) >> 10;
#undef min


	if (f.bnum) {
		if (cfg->md_index >= 0 ||
		    cfg->md_index == DRBD_MD_INDEX_FLEX_EXT) {
			printf("\nThis would corrupt existing data.\n");
			if (ignore_sanity_checks) {
				printf("\nIgnoring sanity check on user request.\n\n");
				return;
			}
			printf(
"If you want me to do this, you need to zero out the first part\n"
"of the device (destroy the content).\n"
"You should be very sure that you mean it.\n"
"Operation refused.\n\n");
			exit(40); /* FIXME sane exit code! */
		}

		if (f.bsize < REFUSE_BSIZE)
			printf("%12llu kB data area apparently used\n", (unsigned long long)fs_kB);
		printf("%12llu kB left usable by current configuration\n", (unsigned long long)max_usable_kB);

		if (f.bsize == ERR_BSIZE)
			printf(
"Could not determine the size of the actually used data area.\n\n");
		if (f.bsize >= REFUSE_BSIZE) {
			printf(
"Device size would be truncated, which\n"
"would corrupt data and result in\n"
"'access beyond end of device' errors.\n");
			if (ignore_sanity_checks) {
				printf("\nIgnoring sanity check on user request.\n\n");
				return;
			}
			printf(
"If you want me to do this, you need to zero out the first part\n"
"of the device (destroy the content).\n"
"You should be very sure that you mean it.\n"
"Operation refused.\n\n");
			exit(40); /* FIXME sane exit code! */
		}

		/* looks like file system data */
		if (fs_kB > max_usable_kB) {
			printf(
"\nDevice size would be truncated, which\n"
"would corrupt data and result in\n"
"'access beyond end of device' errors.\n"
"You need to either\n"
"   * use external meta data (recommended)\n"
"   * shrink that filesystem first\n"
"   * zero out the device (destroy the filesystem)\n"
"Operation refused.\n\n");
			exit(40); /* FIXME sane exit code! */
		} else {
			printf(
"\nEven though it looks like this would place the new meta data into\n"
"unused space, you still need to confirm, as this is only a guess.\n");
		}
	} else
		printf("\n ==> This might destroy existing data! <==\n");

	if (!confirmed("Do you want to proceed?")) {
		printf("Operation canceled.\n");
		exit(1); // 1 to avoid online resource counting
	}
}

void check_internal_md_flavours(struct format * cfg) {
	struct md_cpu md_07;
	struct md_cpu md_07p;
	struct md_cpu md_08;
	off_t fixed_offset, flex_offset;
	int have_fixed_v07 = 0;
	int have_flex_v07  = 0;
	int have_flex_v08  = 0;

	ASSERT( cfg->md_index == DRBD_MD_INDEX_INTERNAL ||
		cfg->md_index == DRBD_MD_INDEX_FLEX_INT );

	fixed_offset = v07_style_md_get_byte_offset(
		DRBD_MD_INDEX_INTERNAL, cfg->bd_size);
	flex_offset = v07_style_md_get_byte_offset(
		DRBD_MD_INDEX_FLEX_INT, cfg->bd_size);

	/* printf("%lld\n%lld\n%lld\n", (long long unsigned)cfg->bd_size,
	   (long long unsigned)fixed_offset, (long long unsigned)flex_offset); */
	if (0 <= fixed_offset && fixed_offset < (off_t)cfg->bd_size - 4096) {
		/* ... v07 fixed-size internal meta data? */
		PREAD(cfg->md_fd, on_disk_buffer, 4096, fixed_offset);

		md_disk_07_to_cpu(&md_07,
			(struct md_on_disk_07*)on_disk_buffer);
		have_fixed_v07 = is_valid_md(Drbd_07,
			&md_07, DRBD_MD_INDEX_INTERNAL, cfg->bd_size);
	}

	PREAD(cfg->md_fd, on_disk_buffer, 4096, flex_offset);

	/* ... v07 (plus) flex-internal meta data? */
	md_disk_07_to_cpu(&md_07p, (struct md_on_disk_07*)on_disk_buffer);
	have_flex_v07 = is_valid_md(Drbd_07,
		&md_07p, DRBD_MD_INDEX_FLEX_INT, cfg->bd_size);

	/* ... v08 flex-internal meta data?
	 * (same offset, same on disk data) */
	md_disk_08_to_cpu(&md_08, (struct md_on_disk_08*)on_disk_buffer);
	have_flex_v08 = is_valid_md(Drbd_08,
		&md_08, DRBD_MD_INDEX_FLEX_INT, cfg->bd_size);

	if (!(have_fixed_v07 || have_flex_v07 || have_flex_v08))
		return;

	ASSERT(have_flex_v07 == 0 || have_flex_v08 == 0); /* :-) */

	fprintf(stderr, "You want me to create a %s%s style %s internal meta data block.\n",
		cfg->ops->name,
		(is_v07(cfg) && cfg->md_index == DRBD_MD_INDEX_FLEX_INT) ? "(plus)" : "",
		cfg->md_index == DRBD_MD_INDEX_FLEX_INT ? "flexible-size" : "fixed-size");

	if (have_fixed_v07) {
		fprintf(stderr, "There appears to be a v07 fixed-size internal meta data block\n"
				"already in place on %s at byte offset %llu\n",
				cfg->md_device_name, (long long unsigned)fixed_offset);
	}
	if (have_flex_v07) {
		fprintf(stderr, "There appears to be a v07(plus) flexible-size internal meta data block\n"
				"already in place on %s at byte offset %llu",
		cfg->md_device_name, (long long unsigned)flex_offset);
	}
	if (have_flex_v08) {
		fprintf(stderr, "There appears to be a v08 flexible-size internal meta data block\n"
				"already in place on %s at byte offset %llu",
		cfg->md_device_name, (long long unsigned)flex_offset);
	}

	if (have_fixed_v07 && have_flex_v07) {
		fprintf(stderr, "Don't know what to do now. If you want this to work,\n"
				"Please wipe out at least one of these.\n");
		exit(10);
	}

	if (is_v08(cfg)) {
		if (have_flex_v08) {
			if (!confirmed("Do you really want to overwrite the existing v08 meta-data?")) {
				printf("Operation cancelled.\n");
				exit(1); // 1 to avoid online resource counting
			}
			/* no need to wipe flex offset,
			 * will be overwritten with new data */
			cfg->md.magic = 0;
			have_flex_v08 = 0;
		}
		if ( (have_fixed_v07||have_flex_v07) ) {
			if (confirmed("Convert the existing v07 meta-data to v08?")) {
				cfg->md = have_fixed_v07 ? md_07 : md_07p;
				md_convert_07_to_08(cfg);
				/* goto wipe; */
			} else if (!confirmed("So you want me to wipe out the v07 meta-data?")) {
				printf("Operation cancelled.\n");
				exit(1); // 1 to avoid online resource counting
			}
		}
	} else { /* is_v07(cfg) */
		if (have_fixed_v07 || have_flex_v07) {
			if (!confirmed("Do you really want to overwrite the existing v07 meta-data?")) {
				printf("Operation cancelled.\n");
				exit(1); // 1 to avoid online resource counting
			}
			/* no need to wipe the requested flavor,
			 * will be overwritten with new data */
			cfg->md.magic = 0;
			if (cfg->md_index == DRBD_MD_INDEX_INTERNAL)
				have_fixed_v07 = 0;
			else
				have_flex_v07 = 0;
		}
		if (have_flex_v08) {
			if (confirmed("Valid v08 meta-data found, convert back to v07?")) {
				cfg->md = md_08;
				md_convert_08_to_07(cfg);
				if (cfg->md_index == DRBD_MD_INDEX_FLEX_INT)
					have_flex_v08 = 0;
				/* goto wipe; */
			}
		}
	}
	if (have_fixed_v07)
		cfg->wipe_fixed = fixed_offset;
	if (have_flex_v08 || have_flex_v07)
		cfg->wipe_flex = flex_offset;
}

void wipe_after_convert(struct format *cfg)
{
	memset(on_disk_buffer, 0x00, 4096);
	if (cfg->wipe_fixed)
		pwrite_or_die(cfg->md_fd, on_disk_buffer, 4096, cfg->wipe_fixed,
			"wipe fixed-size v07 internal md");
	if (cfg->wipe_flex)
		pwrite_or_die(cfg->md_fd, on_disk_buffer, 4096, cfg->wipe_flex,
			"wipe flexible-size internal md");
}

void check_external_md_flavours(struct format * cfg) {
	struct md_cpu md_07;
	struct md_cpu md_08;

	ASSERT( cfg->md_index >= 0 ||
		cfg->md_index == DRBD_MD_INDEX_FLEX_EXT );

	if (cfg->md.magic) {
		if (!confirmed("Valid meta data seems to be in place.\n"
				"Do you really want to overwrite?")) {
			printf("Operation cancelled.\n");
			exit(1);
		}
		cfg->md.magic = 0; /* will be re-initialized below */
		return;
	}
	PREAD(cfg->md_fd, on_disk_buffer, 4096, cfg->md_offset);
	if (is_v08(cfg)) {
		md_disk_07_to_cpu(&md_07, (struct md_on_disk_07*)on_disk_buffer);
		if (!is_valid_md(Drbd_07, &md_07, cfg->md_index, cfg->bd_size))
			return;
		if (confirmed("Valid v07 meta-data found, convert to v08?")) {
			cfg->md = md_07;
			md_convert_07_to_08(cfg);
			return;
		}
		if (!confirmed("So you want me to replace the v07 meta-data\n"
				"with newly initialized v08 meta-data?")) {
			printf("Operation cancelled.\n");
			exit(1);
		}
	} else if (is_v07(cfg)) {
		md_disk_08_to_cpu(&md_08, (struct md_on_disk_08*)on_disk_buffer);
		if (!is_valid_md(Drbd_08, &md_08, cfg->md_index, cfg->bd_size))
			return;
		if (confirmed("Valid v08 meta-data found, convert back to v07?")) {
			cfg->md = md_08;
			md_convert_08_to_07(cfg);
			return;
		}
		if (!confirmed("So you want me to replace the v08 meta-data\n"
				"with newly initialized v07 meta-data?")) {
			printf("Operation cancelled.\n");
			exit(1);
		}
	}
}

/* ok, so there is no valid meta data at the end of the device,
 * but there is valid internal meta data at the "last known"
 * position.  Move the stuff.
 * Areas may overlap:
 * |--...~//~[BITMAP][AL][SB]|     <<- last known
 * |--.......~//~[BITMAP][AL][SB]| <<- what it should look like now
 * So we move it in chunks.
 */
int v08_move_internal_md_after_resize(struct format *cfg)
{
	off_t old_offset;
	off_t old_bm_offset;
	off_t cur_offset;
	off_t last_chunk_size;
	int err;

	ASSERT(is_v08(cfg));
	ASSERT(cfg->md_index == DRBD_MD_INDEX_FLEX_INT);
	ASSERT(cfg->lk_bd.bd_size <= cfg->bd_size);

	/* we just read it in v08_check_for_resize().
	 * no need to do it again, but ASSERT this. */
	old_offset = v07_style_md_get_byte_offset(DRBD_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size);
	/*
	PREAD(cfg->md_fd, on_disk_buffer, 4096, old_offset);
	md_disk_08_to_cpu(&md_08, (struct md_on_disk_08*)on_disk_buffer);
	*/
	ASSERT(is_valid_md(Drbd_08, &cfg->md, DRBD_MD_INDEX_FLEX_INT, cfg->lk_bd.bd_size));

	fprintf(stderr, "Moving the internal meta data to its proper location\n");

	/* FIXME
	 * If the new meta data area overlaps the old "super block",
	 * and we crash before we successfully wrote the new super block,
	 * but after we overwrote the old, we are out of luck!
	 * But I don't want to write the new superblock early, either.
	 */

	/* move activity log, fixed size immediately preceeding the "super block". */
	cur_offset = old_offset + cfg->md.al_offset * 512;
	PREAD(cfg->md_fd, on_disk_buffer, old_offset - cur_offset, cur_offset);
	PWRITE(cfg->md_fd, on_disk_buffer, old_offset - cur_offset, cfg->al_offset);

	/* The AL was of fixed size.
	 * Bitmap is of flexible size, new bitmap is likely larger.
	 * We do not initialize that part, we just leave "garbage" in there.
	 * Once DRBD "agrees" on the new lower level device size, that part of
	 * the bitmap will be handled by the module, anyways. */
	old_bm_offset = old_offset + cfg->md.bm_offset * 512;

	/* move bitmap, in chunks, peel off from the end. */
	cur_offset = old_offset + cfg->md.al_offset * 512 - buffer_size;
	while (cur_offset > old_bm_offset) {
		PREAD(cfg->md_fd, on_disk_buffer, buffer_size, cur_offset);
		PWRITE(cfg->md_fd, on_disk_buffer, buffer_size,
				cfg->bm_offset + (cur_offset - old_bm_offset));
		cur_offset -= buffer_size;
	}

	/* Adjust for last, possibly partial buffer. */
	last_chunk_size = buffer_size - (old_bm_offset - cur_offset);
	PREAD(cfg->md_fd, on_disk_buffer, last_chunk_size, old_bm_offset);
	PWRITE(cfg->md_fd, on_disk_buffer, last_chunk_size, cfg->bm_offset);

	/* fix bitmap offset in meta data,
	 * and rewrite the "super block" */
	re_initialize_md_offsets(cfg);

	err = cfg->ops->md_cpu_to_disk(cfg);

	if (!err)
		printf("Internal drbd meta data successfully moved.\n");

	if (!err && old_offset < cfg->bm_offset) {
		/* wipe out previous meta data block, it has been superseeded. */
		memset(on_disk_buffer, 0, 4096);
		PWRITE(cfg->md_fd, on_disk_buffer, 4096, old_offset);
	}

	err = cfg->ops->close(cfg) || err;
	if (err)
		fprintf(stderr, "operation failed\n");

	return err;
}

int meta_create_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err = 0;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	err = cfg->ops->open(cfg);

	/* Maybe we want to use some library that provides detection of
	 * fs/partition/usage types? */
	check_for_existing_data(cfg);

	/* Suggest to move existing meta data after offline resize.  Though, if
	 * you --force create-md, you probably mean it, so we don't even ask.
	 * If you want to automatically move it, use check-resize.
	 */
	if (err == VALID_MD_FOUND_AT_LAST_KNOWN_LOCATION) {
		if (!force &&
		    confirmed("Move internal meta data from last-known position?\n"))
			return v08_move_internal_md_after_resize(cfg);
		/* else: reset cfg->md, it needs to be re-initialized below */
		memset(&cfg->md, 0, sizeof(cfg->md));
	}

	/* the offset of v07 fixed-size internal meta data is different from
	 * the offset of the flexible-size v07 ("plus") and v08 (default)
	 * internal meta data.
	 * to avoid the situation where we would have "valid" meta data blocks
	 * of different versions at different offsets, we also need to check
	 * the other format, and the other offset.
	 *
	 * on a request to create v07 fixed-size internal meta data, we also
	 * check flex-internal v08 [and v07 (plus)] at the other offset.
	 *
	 * on a request to create v08 flex-internal meta data (or v07 plus, for
	 * that matter), we also check the same offset for the respective other
	 * flex-internal format version, as well as the v07 fixed-size internal
	 * meta data offset for its flavor of meta data.
	 */
	if (cfg->md_index == DRBD_MD_INDEX_INTERNAL ||
	    cfg->md_index == DRBD_MD_INDEX_FLEX_INT)
		check_internal_md_flavours(cfg);
	else
		check_external_md_flavours(cfg);

	printf("Writing meta data...\n");
	if (!cfg->md.magic) /* not converted: initialize */
		err = cfg->ops->md_initialize(cfg); /* Clears on disk AL implicitly */
	else
		err = 0; /* we have sucessfully converted somthing */

	/* FIXME
	 * if this converted fixed-size 128MB internal meta data
	 * to flexible size, we'd need to move the AL and bitmap
	 * over to the new location!
	 * But the upgrade procedure in such case is documented to first get
	 * the previous DRBD into "clean" C_CONNECTED R_SECONDARY/R_SECONDARY, so AL
	 * and bitmap should be empty anyways.
	 */
	err = err || cfg->ops->md_cpu_to_disk(cfg); // <- short circuit
	if (!err)
		wipe_after_convert(cfg);
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err)
		fprintf(stderr, "operation failed\n");
	else
		printf("New drbd meta data block successfully created.\n");

	return err;
}

int meta_wipe_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int virgin, err;
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	virgin = cfg->ops->open(cfg);
	if (virgin) {
		fprintf(stderr,"There appears to be no drbd meta data to wipe out?\n");
		return 0;
	}

	if (!confirmed("Do you really want to wipe out the DRBD meta data?")) {
		printf("Operation cancelled.\n");
		exit(1);
	}

	printf("Wiping meta data...\n");
	memset(on_disk_buffer, 0, 4096);
	PWRITE(cfg->md_fd, on_disk_buffer, 4096, cfg->md_offset);

	err = cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "operation failed\n");
	else
		printf("DRBD meta data block successfully wiped out.\n");

	/* delete last-known bdev info, it is of no use now. */
	lk_bdev_delete(cfg->minor);

	return err;
}

int meta_outdate(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	if (cfg->ops->outdate_gi(&cfg->md)) {
		fprintf(stderr, "Device is inconsistent.\n");
		exit(5);
	}

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}

int meta_invalidate(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->ops->invalidate_gi(&cfg->md);
	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}

int meta_read_dev_uuid(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	printf(X64(016)"\n",cfg->md.device_uuid);

	return cfg->ops->close(cfg);
}

int meta_write_dev_uuid(struct format *cfg, char **argv, int argc)
{
	int err;

	if (argc > 1) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}
	if (argc < 1) {
		fprintf(stderr, "Required Argument missing\n");
		exit(10);
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->md.device_uuid = strto_u64(argv[0],NULL,16);

	err = cfg->ops->md_cpu_to_disk(cfg);
	err = cfg->ops->close(cfg) || err;
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}

char *progname = NULL;
void print_usage_and_exit()
{
	char **args;
	size_t i;

	printf
	    ("\nUSAGE: %s [--force] DEVICE FORMAT [FORMAT ARGS...] COMMAND [CMD ARGS...]\n",
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

	exit(20);
}

int parse_format(struct format *cfg, char **argv, int argc, int *ai)
{
	enum Known_Formats f;

	if (argc < 1) {
		fprintf(stderr, "Format identifier missing\n");
		return -1;
	}

	for (f = Drbd_06; f < Drbd_Unknown; f++) {
		if (!strcmp(f_ops[f].name, argv[0]))
			break;
	}
	if (f == Drbd_Unknown) {
		fprintf(stderr, "Unknown format '%s'.\n", argv[0]);
		return -1;
	}

	(*ai)++;

	cfg->ops = f_ops + f;
	return cfg->ops->parse(cfg, argv + 1, argc - 1, ai);
}

int is_attached(int minor)
{
	FILE *pr;
	char token[128];	/* longest interesting token is 40 Byte (git hash) */
	int rv = -1;
	long m, cm = -1;
	char *p;

	pr = fopen("/proc/drbd", "r");
	if (!pr)
		return 0;

	while (fget_token(token, sizeof(token), pr) != EOF) {
		m = strtol(token, &p, 10);
		/* keep track of currently parsed minor */
		if (p[0] == ':' && p[1] == 0)
			cm = m;
		/* we found the minor number that was asked for */
		if (cm == minor) {
			/* first, assume it is attached */
			if (rv == -1)
				rv = 1;
			/* unless, of course, it is unconfigured or diskless */
			if (!strcmp(token, "cs:Unconfigured"))
				rv = 0;
			if (!strncmp(token, "ds:Diskless", 11))
				rv = 0;
		}
	}
	fclose(pr);

	if (rv == -1)
		rv = 0;		// minor not found -> not attached.
	return rv;
}

int meta_chk_offline_resize(struct format *cfg, char **argv, int argc)
{
	int err;

	err = cfg->ops->open(cfg);

	/* this is first, so that lk-bdev-info files are removed/updated
	 * if we find valid meta data in the expected place. */
	if (err == VALID_MD_FOUND) {
		/* Do not clutter the output of the init script
		printf("Found valid meta data in the expected location, %llu bytes into %s.\n",
		       (unsigned long long)cfg->md_offset, cfg->md_device_name);
		*/
		/* create, delete or update the last known info */
		err = lk_bdev_load(cfg->minor, &cfg->lk_bd);
		if (cfg->md_index != DRBD_MD_INDEX_FLEX_INT)
			lk_bdev_delete(cfg->minor);
		else if (cfg->lk_bd.bd_size != cfg->bd_size ||
			 cfg->lk_bd.bd_uuid != cfg->md.device_uuid)
			cfg->update_lk_bdev = 1;
		return cfg->ops->close(cfg);
	} else if (err == NO_VALID_MD_FOUND) {
		if (!is_v08(cfg) || cfg->md_index != DRBD_MD_INDEX_FLEX_INT) {
			fprintf(stderr, "Operation only supported for v8 internal meta data\n");
			return -1;
		}
		fprintf(stderr, "no suitable meta data found :(\n");
		return -1; /* sorry :( */
	}

	ASSERT(is_v08(cfg));
	ASSERT(cfg->md_index == DRBD_MD_INDEX_FLEX_INT);
	ASSERT(cfg->lk_bd.bd_size);
	ASSERT(cfg->md.magic);

	return v08_move_internal_md_after_resize(cfg);
}

/* CALL ONLY ONCE as long as on_disk_buffer is global! */
struct format *new_cfg()
{
	int err;
	struct format *cfg;

	errno = 0;
	pagesize = sysconf(_SC_PAGESIZE);
	if (errno) {
		perror("could not determine pagesize");
		exit(20);
	}
	cfg = calloc(1, sizeof(struct format));
	if (!cfg) {
		fprintf(stderr, "could not calloc() cfg\n");
		exit(20);
	}
	err = posix_memalign(&on_disk_buffer,pagesize,
		(buffer_size+pagesize-1)/pagesize*pagesize);
	if (err) {
		fprintf(stderr, "could not posix_memalign() on_disk_buffer\n");
		exit(20);
	}
	return cfg;
}

int main(int argc, char **argv)
{
	struct meta_cmd *command = NULL;
	struct format *cfg;
	size_t i;
	int ai;


#if 1
	if (sizeof(struct md_on_disk_07) != 4096) {
		fprintf(stderr, "Where did you get this broken build!?\n"
				"sizeof(md_on_disk_07) == %lu, should be 4096\n",
				(unsigned long)sizeof(struct md_on_disk_07));
		exit(111);
	}
	if (sizeof(struct md_on_disk_08) != 4096) {
		fprintf(stderr, "Where did you get this broken build!?\n"
				"sizeof(md_on_disk_08) == %lu, should be 4096\n",
				(unsigned long)sizeof(struct md_on_disk_08));
		exit(111);
	}
#if 0
	printf("v07: al_offset: %u\n", (int)&(((struct md_on_disk_07*)0)->al_offset));
	printf("v07: bm_offset: %u\n", (int)&(((struct md_on_disk_07*)0)->bm_offset));
	printf("v08: al_offset: %u\n", (int)&(((struct md_on_disk_08*)0)->al_offset));
	printf("v08: bm_offset: %u\n", (int)&(((struct md_on_disk_08*)0)->bm_offset));
	exit(0);
#endif
#endif

	if ((progname = strrchr(argv[0], '/'))) {
		argv[0] = ++progname;
	} else {
		progname = argv[0];
	}

	if (argc < 4)
		print_usage_and_exit();

	/* so dump_md can write a nice header */
	global_argc = argc;
	global_argv = argv;

	/* Check for options (e.g. --force) */
	while (1) {
	    int c = getopt_long(argc,argv,make_optstring(metaopt,0),metaopt,0);

	    if (c == -1)
		break;

	    switch (c) {
	    case 0:
		break;
	    case 'f':
		force = 1;
		break;
	    case 'v':
		verbose++;
		break;
	    default:
		print_usage_and_exit();
		break;
	    }
	}

	// Next argument to process is specified by optind...
	ai = optind;

	cfg = new_cfg();
	cfg->drbd_dev_name = argv[ai++];

	if (parse_format(cfg, argv + ai, argc - ai, &ai)) {
		/* parse has already printed some error message */
		exit(20);
	}

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

	/* does exit() unless we acquired the lock.
	 * unlock happens implicitly when the process dies,
	 * but may be requested implicitly
	 */
	cfg->lock_fd = dt_lock_drbd(cfg->drbd_dev_name);
	cfg->minor = dt_minor_of_dev(cfg->drbd_dev_name);

	/* unconditionally check whether this is in use */
	if (is_attached(cfg->minor)) {
		if (!(force && (command->function == meta_dump_md))) {
			fprintf(stderr, "Device '%s' is configured!\n",
				cfg->drbd_dev_name);
			exit(20);
		}
	}

	return command->function(cfg, argv + ai, argc - ai);
	/* and if we want an explicit free,
	 * this would be the place for it.
	 * free(cfg->md_device_name), free(cfg) ...
	 */
}
