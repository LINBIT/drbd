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

#include <linux/drbd.h>		/* only use DRBD_MAGIC from here! */
#include <linux/fs.h>           /* for BLKFLSBUF */

#include "drbd_endian.h"
#include "drbdtool_common.h"

#include "drbdmeta_parser.h"
extern FILE* yyin;
YYSTYPE yylval;

int     force = 0;

struct option metaopt[] = {
    { "force",  no_argument,    0, 'f' },
    { NULL,     0,              0, 0 },
};

/* FIXME? should use sector_t and off_t, not long/u64 ... */

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
 * allways.  e.g. refuse to be created on top of a LVM2 physical volume,
 * or on top of swap space. This would require people to do an dd
 * if=/dev/zero of=device.  Protects them from shooting themselves,
 * and blaming us...
 */

/* reiserfs sb offset is 64k plus */
#define SO_MUCH (65*1024)

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
#define MD_RESERVED_SECT_07    ( (u64)(128ULL << 11) )
#define MD_BM_MAX_BYTE_07      ( (u64)(MD_RESERVED_SECT_07 - MD_BM_OFFSET_07)*512 )
#define MD_BM_MAX_BYTE_FLEX    ( (u64)(1ULL << (32-3)) )

#define DEFAULT_BM_BLOCK_SIZE  (1<<12)

#define DRBD_MD_MAGIC_06   (DRBD_MAGIC+2)
#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)
#define DRBD_MD_MAGIC_08   (DRBD_MAGIC+4)

/*
 * }
 * end of should-be-shared
 */

/*
 * global vaiables and data types
 */

const size_t buffer_size = 128*1024;
size_t pagesize; /* = sysconf(_SC_PAGESIZE) */
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
typedef struct { u64 le; } le_u64;
typedef struct { u64 be; } be_u64;
typedef struct { u32 le; } le_u32;
typedef struct { u32 be; } be_u32;
typedef struct { s32 be; } be_s32;
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
	u32 md_size_sect;
	s32 al_offset;		/* signed sector offset to this block */
	u32 al_nr_extents;	/* important for restoring the AL */
	s32 bm_offset;		/* signed sector offset to the bitmap, from here */
	/* Since DRBD 0.8 we have uuid instead of gc */
	u64 uuid[UUID_SIZE];
	u32 flags;
	u64 device_uuid;
	u32 bm_bytes_per_bit;
};

/*
 * drbdmeta specific types
 */

struct format_ops;

struct format {
	const struct format_ops *ops;
	char *md_device_name;	/* well, in 06 it is file name */
	char *drbd_dev_name;
	int lock_fd;
	int drbd_fd;		/* no longer used!   */
	int ll_fd;		/* not yet used here */
	int md_fd;

	/* unused in 06 */
	int md_index;
	unsigned int bm_bytes;
	unsigned int bits_set;	/* 32 bit should be enough. @4k ==> 16TB */
	int bits_counted:1;

	struct md_cpu md;

	/* _byte_ offsets of our "super block" and other data, within fd */
	u64 md_offset;
	u64 al_offset;
	u64 bm_offset;

	/* convenience */
	u64 bd_size; /* size of block device for internal meta data */
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

struct __attribute__ ((packed)) md_on_disk_06 {
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

struct __attribute__ ((packed)) md_on_disk_07 {
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
	const struct md_cpu const *md, const int md_index, const u64 ll_size)
{
	u64 md_size_sect;
	char *v = (f == Drbd_07) ? "v07" : "v08";
	const unsigned int magic = (f == Drbd_07) ? DRBD_MD_MAGIC_07 : DRBD_MD_MAGIC_08;


	ASSERT(f == Drbd_07 || f == Drbd_08);

	if (md->magic != magic) {
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

		if (md->bm_offset != -(s64)md_size_sect + MD_AL_OFFSET_07) {
			fprintf(stderr, "strange bm_offset %d (expected: "D64")\n",
					md->bm_offset, -(s64)md_size_sect + MD_AL_OFFSET_07);
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

	/* fixme consistency check, la_size < ll_device_size,
	 * no overlap with internal meta data,
	 * no overlap of flexible meta data offsets/sizes
	 * ...
	 */

	return 1; /* VALID */
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
 */

struct __attribute__ ((packed)) md_on_disk_08 {
	be_u64 la_sect;		/* last agreed size. */
	be_u64 uuid[UUID_SIZE];   // UUIDs.
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

	char reserved[8 * 512 - (8*(UUID_SIZE+3)+4*11)];
};

void md_disk_08_to_cpu(struct md_cpu *cpu, const struct md_on_disk_08 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->la_sect = be64_to_cpu(disk->la_sect.be);
	for ( i=Current ; i<UUID_SIZE ; i++ )
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
	for ( i=Current ; i<UUID_SIZE ; i++ ) {
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

int v07_style_md_open(struct format *cfg); /* also v08 */

int v08_md_cpu_to_disk(struct format *cfg);
int v08_md_disk_to_cpu(struct format *cfg);
int v08_md_initialize(struct format *cfg);

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
		     .open = v07_style_md_open,
		     .close = generic_md_close,
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
	//printf("pread(%u,...,%lu,%llu)\n", fd, (unsigned long)count, (unsigned long long)offset);
	if (c < 0) {
		fprintf(stderr,"pread in %s failed: %s\n",
			tag, strerror(errno));
		exit(10);
	} else if ((size_t)c != count) {
		fprintf(stderr,"confused in %s: expected to read %d bytes,"
			" actually read %d\n",
			tag, (int)count, (int)c);
		exit(10);
	}
}

void pwrite_or_die(int fd, const void *buf, size_t count, off_t offset, const char* tag)
{
	ssize_t c = pwrite(fd, buf, count, offset);
	//printf("pwrite(%u,...,%lu,%llu)\n", fd, (unsigned long)count, (unsigned long long)offset);
	if (c < 0) {
		fprintf(stderr,"pwrite in %s failed: %s\n",
			tag, strerror(errno));
		exit(10);
	} else if ((size_t)c != count) {
		/* FIXME we might just now have corrupted the on-disk data */
		fprintf(stderr,"confused in %s: expected to write %d bytes,"
			" actually wrote %d\n", tag, (int)count, (int)c);
		exit(10);
	}
}

int confirmed(const char *text)
{
	const char yes[] = "yes";
	const ssize_t N = sizeof(yes);
	char *answer = NULL;
	size_t n = 0;
	int ok;

	printf("\n%s\n", text);

	if (force) {
	    printf("*** confirmation forced via --force option ***\n");
	    ok = 1;
	}
	else {
	    printf("[need to type '%s' to confirm] ", yes);
	    ok = getline(&answer,&n,stdin) == N &&
		strncmp(answer,yes,N-1) == 0;
	    if (answer) free(answer);
	    printf("\n");
	}
	return ok;
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

int m_strsep_u32(char **s, u32 *val)
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
			*val = (u32)v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_u64(char **s, u64 *val)
{
	char *t, *e;
	u64 v;

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

int m_strsep_bit(char **s, u32 *val, int mask)
{
	u32 d;
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
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_Consistent)) break;
		if (!m_strsep_u32(str, &md->gc[HumanCnt])) break;
		if (!m_strsep_u32(str, &md->gc[TimeoutCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ConnectedCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ArbitraryCnt])) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_PrimaryInd)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_ConnectedInd)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_FullSync)) break;
	} while (0);
}

void m_set_uuid(struct md_cpu *md, char **argv, int argc __attribute((unused)))
{
	char **str;
	int i;

	str = &argv[0];

	do {
		for ( i=Current ; i<UUID_SIZE ; i++ ) {
			if (!m_strsep_u64(str, &md->uuid[i])) return;
		}
		if (!m_strsep_bit(str, &md->flags, MDF_Consistent)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_WasUpToDate)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PrimaryInd)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_ConnectedInd)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_FullSync)) break;
		if (!m_strsep_bit(str, &md->flags, MDF_PeerOutDated)) break;
	} while (0);
}

int m_outdate_gc(struct md_cpu *md __attribute((unused)))
{
	fprintf(stderr, "Can not outdate GC based meta data!\n");

	return 5;
}

int m_outdate_uuid(struct md_cpu *md)
{
	if ( !(md->flags & MDF_Consistent) ) {
		return 5;
	}

	md->flags &= ~MDF_WasUpToDate;

	return 0;
}

int m_invalidate_gc(struct md_cpu *md)
{
	md->gc[Flags] &= ~MDF_Consistent;

	return 5;
}

int m_invalidate_uuid(struct md_cpu *md)
{
	md->flags &= ~MDF_Consistent;
	md->flags &= ~MDF_WasUpToDate;

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
	if (asprintf(&e, "/var/lib/drbd/drbd%lu", minor) <= 18) {
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
		return -1;
	}

	if (fstat(cfg->md_fd, &sb)) {
		PERROR("fstat() failed");
		return -1;
	}

	if (!S_ISREG(sb.st_mode)) {
		fprintf(stderr, "'%s' is not a plain file!\n",
			cfg->md_device_name);
		return -1;
	}

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return -1;
	}

	return 0;
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
	u64 md_size_sect;
	switch(cfg->md_index) {
	default:
		cfg->md.md_size_sect = MD_RESERVED_SECT_07;
		cfg->md.al_offset = MD_AL_OFFSET_07;
		cfg->md.bm_offset = MD_BM_OFFSET_07;
		break;
	case DRBD_MD_INDEX_FLEX_EXT:
		/* just occupy the full device; unit: sectors */
		cfg->md.md_size_sect = bdev_size(cfg->md_fd)>>9;
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
		md_size_sect = (bdev_size(cfg->md_fd) + (1UL<<24)-1) >> 24; /* BM_EXT_SIZE_B */
		md_size_sect = (md_size_sect + 7) & ~7ULL;             /* align on 4K blocks */

		if (md_size_sect > (MD_BM_MAX_BYTE_FLEX>>9)) {
			fprintf(stderr, "Device too large. We only support up to ~16TB.\n");
			exit(10);
		}
		/* plus the "drbd meta data super block",
		 * and the activity log; unit still sectors */
		md_size_sect += MD_BM_OFFSET_07;
		cfg->md.md_size_sect = md_size_sect;
		cfg->md.bm_offset = -md_size_sect + MD_AL_OFFSET_07;
		break;
	}
}

/* DOES DISK WRITES!! */
int md_initialize_common(struct format *cfg)
{
	/* no need to re-initialize the offset of md
	 * FIXME we need to, if we convert, or resize, in case we allow/implement that...
	 */
	re_initialize_md_offsets(cfg);

	cfg->md.al_nr_extents = 257;	/* arbitrary. */
	cfg->md.bm_bytes_per_bit = DEFAULT_BM_BLOCK_SIZE;

	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;

	//fprintf(stderr,"md_offset: "U64"\n", cfg->md_offset);
	//fprintf(stderr,"al_offset: "U64" (%d)\n", cfg->al_offset, cfg->md.al_offset);
	//fprintf(stderr,"bm_offset: "U64" (%d)\n", cfg->bm_offset, cfg->md.bm_offset);
	//fprintf(stderr,"md_size_sect: %lu\n", (unsigned long)cfg->md.md_size_sect);
	//fprintf(stderr,"bm_mmaped_length: %lu\n", (unsigned long)cfg->bm_mmaped_length);

	/* do you want to initilize al to something more usefull? */
	printf("initialising activity log\n");
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
		/* need to sector-align this for O_DIRECT. to be
		 * generic, maybe we even need to PAGE align it? */
		const size_t bm_bytes = ALIGN(cfg->bm_bytes, 512);
		size_t i = bm_bytes;
		off_t bm_on_disk_off = cfg->bm_offset;
		unsigned int percent_done = 0;
		unsigned int percent_last_report = 0;
		size_t chunk;
		fprintf(stderr,"initialising bitmap (%u KB)\n",
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

u64 v07_style_md_get_byte_offset(const int idx, const u64 bd_size)
{
	u64 offset;

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

unsigned long bm_words(u64 sectors, int bytes_per_bit)
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
	le_u64 cw; /* current word for rll encoding */
	const unsigned int n = cfg->bm_bytes/sizeof(*bm);
	unsigned int count = 0;
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
			size_t chunk = ALIGN( (n-r)*sizeof(*bm), 512 );
			if (chunk > buffer_size) chunk = buffer_size;
			ASSERT(chunk);
			pread_or_die(cfg->md_fd, on_disk_buffer,
				chunk, bm_on_disk_off, "printf_bm");
			bm_on_disk_off += chunk;
			i = 0;
			n_buffer = chunk/sizeof(*bm);
		}
		ASSERT(i < n_buffer);
		if (count == 0) cw = bm[i];
		if ((i & 3) == 0) {
			if (!count) printf_bm_eol(r);

			for (j = i+1; j < n_buffer; j++) {
				if(cw.le != bm[j].le) break;
			}
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
				count = 0;
				continue;
			}
		}
		ASSERT(i < n_buffer);
		printf(" 0x"X64(016)";", le64_to_cpu(bm[i].le));
		r++; i++;
	}
	printf("\n}\n");
}

int v07_style_md_open(struct format *cfg)
{
	struct stat sb;
	unsigned long words;

	cfg->md_fd = open(cfg->md_device_name, O_RDWR | O_DIRECT);

	if (cfg->md_fd == -1) {
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

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return -1;
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

	return 0;
}

int v07_md_disk_to_cpu(struct format *cfg)
{
	PREAD(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_07), cfg->md_offset);
	md_disk_07_to_cpu(&cfg->md, (struct md_on_disk_07*)on_disk_buffer);
	return !is_valid_md(Drbd_07,&cfg->md, cfg->md_index, cfg->bd_size);
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

int v07_md_initialize(struct format *cfg)
{
	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.la_sect = 0;
	cfg->md.gc[Flags] = 0;
	cfg->md.gc[HumanCnt] = 1;	/* THINK 0? 1? */
	cfg->md.gc[TimeoutCnt] = 1;
	cfg->md.gc[ConnectedCnt] = 1;
	cfg->md.gc[ArbitraryCnt] = 1;
	cfg->md.magic = DRBD_MD_MAGIC_07;

	return md_initialize_common(cfg);
}

/******************************************
  }}} end of v07
 ******************************************/
/******************************************
 begin of v08 {{{
 ******************************************/

int v08_md_disk_to_cpu(struct format *cfg)
{
	PREAD(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_08), cfg->md_offset);
	md_disk_08_to_cpu(&cfg->md, (struct md_on_disk_08*)on_disk_buffer);
	return !is_valid_md(Drbd_08, &cfg->md, cfg->md_index, cfg->bd_size);
}

int v08_md_cpu_to_disk(struct format *cfg)
{
	if (!is_valid_md(Drbd_08, &cfg->md, cfg->md_index, cfg->bd_size))
		return -1;
	md_cpu_to_disk_08((struct md_on_disk_08 *)on_disk_buffer, &cfg->md);
	PWRITE(cfg->md_fd, on_disk_buffer,
		sizeof(struct md_on_disk_08), cfg->md_offset);
	return 0;
}

int v08_md_initialize(struct format *cfg)
{
	size_t i;

	memset(&cfg->md, 0, sizeof(cfg->md));

	cfg->md.la_sect = 0;
	cfg->md.uuid[Current] = UUID_JUST_CREATED;
	cfg->md.uuid[Bitmap] = 0;
	for ( i=History_start ; i<=History_end ; i++ ) {
		cfg->md.uuid[i]=0;
	}
	cfg->md.flags = 0;
	cfg->md.magic = DRBD_MD_MAGIC_08;

	return md_initialize_common(cfg);
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
		printf("%u bits set in the bitmap [ %s out of sync ]\n",
		       cfg->bits_set, ppsize(ppb, cfg->bits_set * 4));
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

	if (cfg->ops->open(cfg))
		return -1;

	if(cfg->md.flags & MDF_Consistent) {
		if(cfg->md.flags & MDF_WasUpToDate) {
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
		printf("Operation cancelled.\n");
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

	if (cfg->ops->open(cfg))
		return -1;

	print_dump_header();
	printf("version \"%s\";\n\n", cfg->ops->name);
	if (format_version(cfg) < Drbd_08) {
		printf("gc {\n   ");
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			printf(" %d;", cfg->md.gc[i]);
		}
		printf("\n}\n");
	} else { // >= 08
		printf("uuid {\n   ");
		for ( i=Current ; i<UUID_SIZE ; i++ ) {
			printf(" 0x"X64(016)";", cfg->md.uuid[i]);
		}
		printf("\n");
		printf("    flags 0x"X32(08)";\n",cfg->md.flags);
		printf("}\n");
	}

	if (format_version(cfg) >= Drbd_07) {
		printf("la-size-sect "U64";\n", cfg->md.la_sect);
		if (format_version(cfg) >= Drbd_08) {
			printf("bm-byte-per-bit "U32";\n",
			       cfg->md.bm_bytes_per_bit);
			printf("device-uuid 0x"X64(016)";\n",
			       cfg->md.device_uuid);
		}
		printf("# bm-bytes %u;\n", cfg->bm_bytes);
		printf("# bits-set %u;\n", cfg->bits_set);
		printf_bm(cfg);
	}

	/* MAYBE dump activity log?
	 * but that probably does not make any sense,
	 * beyond debugging. */

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

	if (!parse_only && !cfg->ops->open(cfg)) {
		if (!confirmed("Valid meta-data in place, overwrite?"))
			return -1;
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
		for ( i=Current ; i<UUID_SIZE ; i++ ) {
			EXP(TK_U64); EXP(';');
			cfg->md.uuid[i] = yylval.u64;
		}
		EXP(TK_FLAGS); EXP(TK_U32); EXP(';');
		cfg->md.flags = (u32)yylval.u64;
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
			if (++i == buffer_size/sizeof(*bm)) {
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
				if (++i == buffer_size/sizeof(*bm)) {
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
		s = ALIGN(s, 512);
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
	 * what about the Bitmap, and the Activity Log?
	 * how to bring them over for internal meta data?
	 *
	 * maybe just refuse to convert anything that is not
	 * "clean"? how to detect that?
	 *
	 * FIXME: if I am a crashed Primary, or Inconsistent,
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

	cfg->md.uuid[Current] =
		(u64)(cfg->md.gc[HumanCnt] & 0xffff) << 48 |
		(u64)(cfg->md.gc[TimeoutCnt] & 0xffff) << 32 |
		(u64)((cfg->md.gc[ConnectedCnt]+cfg->md.gc[ArbitraryCnt])
		       & 0xffff) << 16 |
		(u64)0xbabe;
	cfg->md.uuid[Bitmap] = (u64)0;

	for (i = cfg->bits_set ? Bitmap : History_start, j = 1;
		i <= History_end ; i++, j++)
		cfg->md.uuid[i] = cfg->md.uuid[Current] - j*0x10000;

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
	 * what about the Bitmap, and the Activity Log?
	 * how to bring them over for internal meta data?
	 *
	 * maybe just refuse to convert anything that is not
	 * "clean"? how to detect that?
	 *
	 * FIXME: if I am a crashed Primary, or Inconsistent,
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
	if (le16_to_cpu(*(u16*)(data+0x438)) == 0xEF53) {
		if ( (le32_to_cpu(*(data+0x45c)) & 4) == 4 )
			f->type = "ext3 filesystem";
		else
			f->type = "ext2 filesystem";
		f->bnum  = le32_to_cpu(*(u32*)(data+0x404));
		size     = le32_to_cpu(*(u32*)(data+0x418));
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
	if (be32_to_cpu(*(u32*)(data+0)) == 0x58465342) {
		f->type = "xfs filesystem";
		f->bsize = be32_to_cpu(*(u32*)(data+4));
		f->bnum  = be64_to_cpu(*(u64*)(data+8));
		return 1;
	}
	return 0;
}

int may_be_reiserfs(const char *data, struct fstype_s *f)
{
	if (strncmp("ReIsErFs",data+0x10034,8) == 0 ||
	    strncmp("ReIsEr2Fs",data+0x10034,9) == 0) {
		f->type = "reiser filesystem";
		f->bnum  = le32_to_cpu(*(u32*)(data+0x10000));
		f->bsize = le16_to_cpu(*(u16*)(data+0x1002c));
		return 1;
	}
	return 0;
}

int may_be_jfs(const char *data, struct fstype_s *f)
{
	if (strncmp("JFS1",data+0x8000,4) == 0) {
		f->type = "JFS filesystem";
		f->bnum = le64_to_cpu(*(u64*)(data+0x8008));
		f->bsize = le32_to_cpu(*(u32*)(data+0x8018));
		return 1;
	}
	return 0;
}

/* really large block size,
 * will always refuse */
#define REFUSE_BSIZE 0xFFFFffffFFFF0000LLU
#define REFUSE_IT    f->bnum = 1; f->bsize = REFUSE_BSIZE;
int may_be_swap(const char *data, struct fstype_s *f)
{
	int looks_like_swap =
		strncmp(data+(1<<12)-10, "SWAP-SPACE", 10) == 0 ||
		strncmp(data+(1<<12)-10, "SWAPSPACE2", 10) == 0 ||
		strncmp(data+(1<<13)-10, "SWAP-SPACE", 10) == 0 ||
		strncmp(data+(1<<13)-10, "SWAPSPACE2", 10) == 0;
	if (looks_like_swap) {
		f->type = "swap space signature";
		REFUSE_IT
		return 1;
	}
	return 0;
}

int may_be_LVM(const char *data, struct fstype_s *f)
{
	if (strncmp("LVM2",data+0x218,4) == 0) {
		f->type = "LVM2 physical volume signature";
		REFUSE_IT
		return 1;
	}
	return 0;
}

void check_for_existing_data(struct format *cfg)
{
	struct fstype_s f;
	size_t i;

	PREAD(cfg->md_fd, on_disk_buffer, SO_MUCH, 0);

	for (i = 0; i < SO_MUCH/sizeof(long); i++) {
		if (((long*)(on_disk_buffer))[i] != 0LU) break;
	}
	/* all zeros? no message */
	if (i == SO_MUCH/sizeof(long)) return;

	f.type = "some data";
	f.bnum = 0;
	f.bsize = 0;

/* FIXME add more detection magic
 */

	(void)(
	may_be_swap     (on_disk_buffer,&f) ||
	may_be_LVM      (on_disk_buffer,&f) ||

	may_be_extX     (on_disk_buffer,&f) ||
	may_be_xfs      (on_disk_buffer,&f) ||
	may_be_jfs      (on_disk_buffer,&f) ||
	may_be_reiserfs (on_disk_buffer,&f)
	);

	/* FIXME
	 * some of the messages below only make sense for internal meta data.
	 * for external meta data, we now only checked the meta-disk.
	 * we should still check the actual lower level storage area for
	 * existing data, too, and give apropriate warnings when it would
	 * appear to be truncated by too small external meta data */

	printf("\nFound %s ", f.type);
	if (f.bnum) {
		/* FIXME overflow check missing!
		 * relevant for ln2(bsize) + ln2(bnum) >= 64, thus only for
		 * device sizes of more than several exa byte.
		 * seems irrelevant to me for now.
		 */
		u64 fs_kB = ((f.bsize * f.bnum) + (1<<10)-1) >> 10;
		u64 max_usable_kB;

		if (f.bsize == REFUSE_BSIZE) {
			printf(
"\nDevice size would be truncated, which\n"
"would corrupt data and result in\n"
"'access beyond end of device' errors.\n"
"If you want me to do this, you need to zero out the first part\n"
"of the device (destroy the content).\n"
"You should be very sure that you mean it.\n"
"Operation refused.\n\n");
			exit(40); /* FIXME sane exit code! */
		}

#define min(x,y) ((x) < (y) ? (x) : (y))
		max_usable_kB =
			min( cfg->md_offset,
			min( cfg->al_offset,
			     cfg->bm_offset )) >> 10;
#undef min

		printf("md_offset %llu\n", (long long unsigned)cfg->md_offset);
		printf("al_offset %llu\n", (long long unsigned)cfg->al_offset);
		printf("bm_offset %llu\n", (long long unsigned)cfg->bm_offset);

		/* looks like file system data */
		printf("which uses "U64" kB\n", fs_kB);
		printf("current configuration leaves usable "U64" kB\n", max_usable_kB);
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
		}
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
		fprintf(stderr, "There apears to be a v07 fixed-size internal meta data block\n"
				"already in place on %s at byte offset %llu\n",
				cfg->md_device_name, (long long unsigned)fixed_offset);
	}
	if (have_flex_v07) {
		fprintf(stderr, "There apears to be a v07(plus) flexible-size internal meta data block\n"
				"already in place on %s at byte offset %llu",
		cfg->md_device_name, (long long unsigned)flex_offset);
	}
	if (have_flex_v08) {
		fprintf(stderr, "There apears to be a v08 flexible-size internal meta data block\n"
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
			/* no need to wipe the requested flavour,
			 * will be overwritten with new data */
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

 /* wipe: */
	memset(on_disk_buffer, 0x00, 4096);
	if (have_fixed_v07) {
		pwrite_or_die(cfg->md_fd, on_disk_buffer, 4096, fixed_offset,
			"wipe fixed-size v07 internal md");
	}
	if (have_flex_v08 || have_flex_v07)
		pwrite_or_die(cfg->md_fd, on_disk_buffer, 4096, flex_offset,
			"wipe flexible-size internal md");
}

int meta_create_md(struct format *cfg, char **argv __attribute((unused)), int argc)
{
	int err = 0;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg)) /* reset cfg->md if not valid */
		memset(&cfg->md, 0, sizeof(cfg->md));

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
	 * meta data offset for its flavour of meta data.
	 */
	if (cfg->md_index == DRBD_MD_INDEX_INTERNAL ||
	    cfg->md_index == DRBD_MD_INDEX_FLEX_INT)
		check_internal_md_flavours(cfg);

	printf("Writing meta data...\n");
	if (!cfg->md.magic) /* not converted: initialize */
		err = cfg->ops->md_initialize(cfg); /* Clears on disk AL implicitly */
	/* otherwise, AL and bitmap are compatible between 07 and 08 */
	err = err || cfg->ops->md_cpu_to_disk(cfg); // <- short circuit
	err = cfg->ops->close(cfg)          || err; // <- close always
	if (err)
		fprintf(stderr, "operation failed\n");
	else
		printf("New drbd meta data block sucessfully created.\n");

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
		fprintf(stderr,"There apears to be no drbd meta data to wipe out?\n");
		return 0;
	}

	printf("Wiping meta data...\n");
	memset(on_disk_buffer, 0, 4096);
	PWRITE(cfg->md_fd, on_disk_buffer, 4096, cfg->md_offset);

	err = cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "operation failed\n");
	else
		printf("DRBD meta data block successfully wiped out.\n");

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
	char token[40];
	int rv=-1;
	long m,cm=-1;
	char *p;

	pr = fopen("/proc/drbd","r");
	if(!pr) return 0;

	while(fget_token(token,40,pr) != EOF) {
		m=strtol(token,&p,10);
		if(*p==':' && p-token == (long)strlen(token)-1 ) cm=m;
		if( cm == minor && rv == -1 ) rv=1;
		if( cm == minor ) {
			if(!strcmp(token,"cs:Unconfigured")) rv = 0;
			if(!strncmp(token,"ds:Diskless",11)) rv = 0;
		}
	}
	fclose(pr);

	if(rv == -1) rv = 0; // minor not found -> not attached.
	return rv;
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
	    case 'f':
		force = 1;
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

	/* does exit() unless we aquired the lock.
	 * unlock happens implicitly when the process dies,
	 * but may be requested implicitly
	 */
	cfg->lock_fd = dt_lock_drbd(cfg->drbd_dev_name);

	/* unconditionally check whether this is in use */
	if (is_attached(dt_minor_of_dev(cfg->drbd_dev_name))) {
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
