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

#include <linux/fs.h>           /* for BLKGETSIZE64 */
#include <linux/drbd.h>		/* only use DRBD_MAGIC from here! */

#include "drbdtool_common.h"
#include "drbd_endian.h"

#include "drbdmeta_parser.h"
extern FILE* yyin;
YYSTYPE yylval;

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
 * See current implementation in check_for_exiting_data below.
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
#define HOW_MUCH (65*1024)

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
#define MD_RESERVED_SIZE_07 ( (u64)(128 * (1<<20)) )
#define MD_BM_MAX_SIZE_07  ( (u64)(MD_RESERVED_SIZE_07 - MD_BM_OFFSET_07*512) )

#define DRBD_MD_MAGIC_06   (DRBD_MAGIC+2)
#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)
#define DRBD_MD_MAGIC_08   (DRBD_MAGIC+4)

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
	u32 md_size;
	s32 al_offset;		/* signed sector offset to this block */
	u32 al_nr_extents;	/* important for restoring the AL */
	s32 bm_offset;		/* signed sector offset to the bitmap, from here */
	/* Since DRBD 0.8 we have uuid instead of gc */
	u64 uuid[UUID_SIZE];
	u32 flags;
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
	u32 flags;

	memset(cpu, 0, sizeof(*cpu));
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);

	/* 06 does not have the UpToDate flag, set it according to
	   the Consistent Flag */
	flags = cpu->gc[Flags];
	if( flags & MDF_Consistent) flags = flags | MDF_WasUpToDate;
	cpu->gc[Flags]=flags;
}

void md_cpu_to_disk_06(struct md_on_disk_06 *disk, struct md_cpu *cpu)
{
	int i;
	u32 flags;

	/* clear Consistent flag if UpToDate is not set*/
	flags = cpu->gc[Flags];
	if(!((flags & MDF_Consistent) && (flags & MDF_WasUpToDate))) {
		flags &= ~MDF_Consistent;
	}
	flags &= ~MDF_WasUpToDate;
	cpu->gc[Flags]=flags;

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
	be_s32 al_offset;	/* signed sector offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_s32 bm_offset;	/* signed sector offset to the bitmap, from here */
	char reserved[8 * 512 - 48];
};

void md_disk_07_to_cpu(struct md_cpu *cpu, const struct md_on_disk_07 *disk)
{
	int i;
	u32 flags;

	memset(cpu, 0, sizeof(*cpu));
	cpu->la_sect = be64_to_cpu(disk->la_kb.be) << 1;
	for (i = 0; i < GEN_CNT_SIZE; i++)
		cpu->gc[i] = be32_to_cpu(disk->gc[i].be);
	cpu->magic = be32_to_cpu(disk->magic.be);
	cpu->md_size = be32_to_cpu(disk->md_size.be);
	cpu->al_offset = be32_to_cpu(disk->al_offset.be);
	cpu->al_nr_extents = be32_to_cpu(disk->al_nr_extents.be);
	cpu->bm_offset = be32_to_cpu(disk->bm_offset.be);

	/* 07 does not have the UpToDate flag, set it according to
	   the Consistent Flag */
	flags = cpu->gc[Flags];
	if( flags & MDF_Consistent) flags = flags | MDF_WasUpToDate;
	cpu->gc[Flags]=flags;
}

void md_cpu_to_disk_07(struct md_on_disk_07 *disk, struct md_cpu *cpu)
{
	int i;
	u32 flags;

	/* clear Consistent flag if UpToDate is not set*/
	flags = cpu->gc[Flags];
	if(!((flags & MDF_Consistent) && (flags & MDF_WasUpToDate))) {
		flags &= ~MDF_Consistent;
	}
	flags &= ~MDF_WasUpToDate;
	cpu->gc[Flags]=flags;

	disk->la_kb.be = cpu_to_be64(cpu->la_sect >> 1);
	for (i = 0; i < GEN_CNT_SIZE; i++)
		disk->gc[i].be = cpu_to_be32(cpu->gc[i]);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size.be = cpu_to_be32(cpu->md_size);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	memset(disk->reserved, 0, sizeof(disk->reserved));
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
 */

struct __attribute__ ((packed)) md_on_disk_08 {
	be_u64 la_sect;		/* last agreed size. */
	be_u64 uuid[UUID_SIZE];   // UUIDs.
	be_u32 flags;
	be_u32 magic;
	be_u32 md_size;
	be_s32 al_offset;	/* signed sector offset to this block */
	be_u32 al_nr_extents;	/* important for restoring the AL */
	be_s32 bm_offset;	/* signed sector offset to the bitmap, from here */
	char reserved[8 * 512 - (8*(UUID_SIZE+1)+4*6)];
};

void md_disk_08_to_cpu(struct md_cpu *cpu, const struct md_on_disk_08 *disk)
{
	int i;

	memset(cpu, 0, sizeof(*cpu));
	cpu->la_sect = be64_to_cpu(disk->la_sect.be);
	for ( i=Current ; i<UUID_SIZE ; i++ )
		cpu->uuid[i] = be64_to_cpu(disk->uuid[i].be);
	cpu->flags = be32_to_cpu(disk->flags.be);
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
	for ( i=Current ; i<UUID_SIZE ; i++ ) {
		disk->uuid[i].be = cpu_to_be64(cpu->uuid[i]);
	}
	disk->flags.be = cpu_to_be32(cpu->flags);
	disk->magic.be = cpu_to_be32(cpu->magic);
	disk->md_size.be = cpu_to_be32(cpu->md_size);
	disk->al_offset.be = cpu_to_be32(cpu->al_offset);
	disk->al_nr_extents.be = cpu_to_be32(cpu->al_nr_extents);
	disk->bm_offset.be = cpu_to_be32(cpu->bm_offset);
	memset(disk->reserved, 0, sizeof(disk->reserved));
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
	const struct format_ops *ops;
	char *md_device_name;	/* well, in 06 it is file name */
	char *drbd_dev_name;
	int lock_fd;
	int drbd_fd;
	int ll_fd;		/* not yet used here */
	int md_fd;

	/* byte offsets of our "super block" and other data, within fd */
	u64 md_offset;
	u64 al_offset;
	u64 bm_offset;

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

		/* to check for existing data on physical devices */
		void *ll_data;
	} on_disk;
};

/* - parse is expected to exit() if it does not work out.
 * - open is expected to mmap the respective on_disk members,
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
void m_get_gc(struct md_cpu *md);
void m_show_gc(struct md_cpu *md);
void m_set_gc(struct md_cpu *md, char **argv, int argc);
int m_outdate_gc(struct md_cpu *md);
void m_get_uuid(struct md_cpu *md);
void m_show_uuid(struct md_cpu *md);
void m_set_uuid(struct md_cpu *md, char **argv, int argc);
int m_outdate_uuid(struct md_cpu *md);

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

int v08_md_open(struct format *cfg);
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
		     .get_gi = m_get_gc,
		     .show_gi = m_show_gc,
		     .set_gi = m_set_gc,
		     .outdate_gi = m_outdate_gc,
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
		     .get_gi = m_get_gc,
		     .show_gi = m_show_gc,
		     .set_gi = m_set_gc,
		     .outdate_gi = m_outdate_gc,
		     },
	[Drbd_08] = {
		     .name = "v08",
		     .args = (char *[]){"device", "index", NULL},
		     .parse = v07_parse,
		     .open = v08_md_open,
		     .close = v07_md_close,
		     .md_initialize = v08_md_initialize,
		     .md_disk_to_cpu = v08_md_disk_to_cpu,
		     .md_cpu_to_disk = v08_md_cpu_to_disk,
		     .get_gi = m_get_uuid,
		     .show_gi = m_show_uuid,
		     .set_gi = m_set_uuid,
		     .outdate_gi = m_outdate_uuid,
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
int meta_get_gi(struct format *cfg, char **argv, int argc);
int meta_show_gi(struct format *cfg, char **argv, int argc);
int meta_dump_md(struct format *cfg, char **argv, int argc);
int meta_restore_md(struct format *cfg, char **argv, int argc);
int meta_create_md(struct format *cfg, char **argv, int argc);
int meta_set_gi(struct format *cfg, char **argv, int argc);
int meta_outdate(struct format *cfg, char **argv, int argc);
int meta_set_uuid(struct format *cfg, char **argv, int argc);

struct meta_cmd cmds[] = {
	{"get-gi", 0, meta_get_gi, 1},
	{"show-gi", 0, meta_show_gi, 1},
	{"dump-md", 0, meta_dump_md, 1},
	{"restore-md", "file", meta_restore_md, 1},
	{"create-md", 0, meta_create_md, 1},
	/* FIXME convert still missing.
	 * implicit convert from v07 to v08 by create-md
	 * see comments there */
	{"outdate", 0, meta_outdate, 1},
	{"set-gi", ":::VAL:VAL:...", meta_set_gi, 0},
};

/*
 * generic helpers
 */

int confirmed(const char *text)
{
	const char yes[] = "yes";
	const ssize_t N = sizeof(yes);
	char *answer = NULL;
	size_t n = 0;
	int ok;

	printf("\n%s\n[need to type '%s' to confirm] ", text, yes);
	ok = getline(&answer,&n,stdin) == N &&
	     strncmp(answer,yes,N-1) == 0;
	if (answer) free(answer);
	printf("\n");
	return ok;
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

/* le_u64, because we want to be able to hexdump it reliably
 * regardless of sizeof(long) */
void printf_bm(const le_u64 * bm, const unsigned int n)
{
	unsigned int i;
	printf("bm {");
	for (i = 0; i < n; i++) {
		if ((i & 3) == 0) {
			if ((i & 31) == 0)
				printf("\n   # %llukB\n   ", (256LLU * i));
			else
				printf("\n   ");
		}
		printf(" 0x"X64(016)";", le64_to_cpu(bm[i].le));
	}
	printf("\n}\n");
}

u64 new_style_offset(struct format * cfg)
{
	u64 offset;

	if (cfg->md_index == -1) {
		offset = (bdev_size(cfg->md_fd) & ~((1LLU << 12) - 1))
		    - MD_RESERVED_SIZE_07;
	} else {
		offset = MD_RESERVED_SIZE_07 * cfg->md_index;
	}
	return offset;
}

int new_style_md_open(struct format *cfg, size_t size)
{
	struct stat sb;
	unsigned long words;
	u64 offset;

	cfg->md_fd = open(cfg->md_device_name, O_RDWR);

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

	if (ioctl(cfg->md_fd, BLKFLSBUF) == -1) {
		PERROR("WARN: ioctl(,BLKFLSBUF,) failed");
	}

	offset = new_style_offset(cfg);
	cfg->on_disk.md7 =
	    mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, cfg->md_fd, 
		 offset);
	if (cfg->on_disk.md7 == NULL) {
		PERROR("mmap(md_on_disk) failed");
		exit(20);
	}
	cfg->md_offset = offset;

	/* in case this is internal meta data, mmap first <some>KB of device,
	 * so we can try and detect existing file systems on the physical
	 * device, and warn about that.
	 */
	if (cfg->md_index == -1) {
		cfg->on_disk.ll_data =
		    mmap(NULL, HOW_MUCH, PROT_READ | PROT_WRITE, MAP_SHARED,
			 cfg->md_fd, 0);
		if (cfg->on_disk.ll_data == NULL) {
			PERROR("mmap(ll_data) failed");
			exit(20);
		}
	}

	if (cfg->ops->md_disk_to_cpu(cfg)) {
		return -1;
	}

	cfg->al_offset = offset + cfg->md.al_offset * 512;
	cfg->bm_offset = offset + cfg->md.bm_offset * 512;

	cfg->on_disk.al =
	    mmap(NULL, MD_AL_MAX_SIZE_07 * 512, PROT_READ | PROT_WRITE,
		 MAP_SHARED, cfg->md_fd, cfg->al_offset);
	if (cfg->on_disk.al == NULL) {
		PERROR("mmap(al_on_disk) failed");
		exit(20);
	}

	cfg->on_disk.bm = mmap(NULL, MD_BM_MAX_SIZE_07, PROT_READ | PROT_WRITE,
			       MAP_SHARED, cfg->md_fd, cfg->bm_offset);
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
	u32 v;

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

int m_strsep_u64(char **s, u64 *val)
{
	char *t, *e;
	u64 v;

	if ((t = strsep(s, ":"))) {
		if (strlen(t)) {
			e = t;
			v = strto_u64(t, &e, 16);
			if (*e != 0) {
				fprintf(stderr, "'%s' is not a number.\n", *s);
				exit(10);
			}
			if (v < 0) {
				fprintf(stderr, "'%s' is negative.\n", *s);
				exit(10);
			}
			*val = v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_bit(char **s, int *val, int mask)
{
	int d;
	int rv;

	d = *val & mask;

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

void m_set_gc(struct md_cpu *md, char **argv, int argc)
{
	char **str;

	str = &argv[0];

	do {
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_Consistent)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_WasUpToDate)) break;
		if (!m_strsep_u32(str, &md->gc[HumanCnt])) break;
		if (!m_strsep_u32(str, &md->gc[TimeoutCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ConnectedCnt])) break;
		if (!m_strsep_u32(str, &md->gc[ArbitraryCnt])) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_PrimaryInd)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_ConnectedInd)) break;
		if (!m_strsep_bit(str, &md->gc[Flags], MDF_FullSync)) break;
	} while (0);
}

void m_set_uuid(struct md_cpu *md, char **argv, int argc)
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
	} while (0);
}

int m_outdate_gc(struct md_cpu *md)
{
	if ( !(md->gc[Flags] & MDF_Consistent) ) {
		return 5;
	}

	md->gc[Flags] &= ~MDF_WasUpToDate;

	return 0;
}

int m_outdate_uuid(struct md_cpu *md)
{
	if ( !(md->flags & MDF_Consistent) ) {
		return 5;
	}

	md->flags &= ~MDF_WasUpToDate;

	return 0;
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

	cfg->on_disk.md6 =
	    mmap(NULL, sizeof(struct md_on_disk_06), PROT_READ | PROT_WRITE,
		 MAP_SHARED, cfg->md_fd, 0);
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
	if (fsync(cfg->md_fd) == -1) {
		PERROR("fsync() failed");
		return -1;
	}
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
/******************************************
 begin of v07 {{{
 ******************************************/

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

	cfg->md_device_name = strdup(argv[0]);
	e = argv[1];
	index = strtol(argv[1], &e, 0);
	if (*e != 0 || -1 > index || index > 255) {
		fprintf(stderr, "'%s' is not a valid index number.\n", argv[1]);
		return -1;
	}
	cfg->md_index = index;

	*ai += 2;

	return 0;
}

int v07_md_open(struct format *cfg)
{
	return new_style_md_open(cfg, sizeof(struct md_on_disk_07));
}

int v07_md_close(struct format *cfg)
{
	int err = 0;
	if (cfg->on_disk.ll_data && munmap(cfg->on_disk.ll_data, HOW_MUCH)) {
		PERROR("munmap(ll_data) failed");
		err = -1;
	}
	if (munmap(cfg->on_disk.bm, MD_BM_MAX_SIZE_07)) {
		PERROR("munmap(bm_on_disk) failed");
		err = -1;
	}
	if (munmap(cfg->on_disk.al, MD_AL_MAX_SIZE_07 * 512)) {
		PERROR("munmap(al_on_disk) failed");
		err = -1;
	}
	if (munmap(cfg->on_disk.md7, 8 * 512)) {
		PERROR("munmap(md_on_disk) failed");
		err = -1;
	}
	if (fsync(cfg->md_fd) == -1) {
		PERROR("fsync() failed");
		err = -1;
	}
	if (ioctl(cfg->md_fd, BLKFLSBUF) == -1) {
		PERROR("ioctl(,BLKFLSBUF,) failed");
		err = -1;
	}
	if (close(cfg->md_fd)) {
		PERROR("close() failed");
		err = -1;
	}
	return err;
}

int v07_md_initialize(struct format *cfg)
{
	cfg->md.la_sect = 0;
	cfg->md.gc[Flags] = 0;
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

	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;
	if (cfg->on_disk.al == NULL) {
		cfg->on_disk.al =
		    mmap(NULL, MD_AL_MAX_SIZE_07 * 512, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->md_fd, cfg->al_offset);
		if (cfg->on_disk.al == NULL) {
			PERROR("mmap(al_on_disk) failed");
			exit(20);
		}
	}

	if (cfg->on_disk.bm == NULL) {
		cfg->on_disk.bm =
		    mmap(NULL, MD_BM_MAX_SIZE_07, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->md_fd, cfg->bm_offset);
		if (cfg->on_disk.bm == NULL) {
			PERROR("mmap(bm_on_disk) failed");
			exit(20);
		}
	}

	memset(cfg->on_disk.al, 0x00, MD_AL_MAX_SIZE_07);
	memset(cfg->on_disk.bm, 0xff, MD_BM_MAX_SIZE_07);
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

int v08_md_open(struct format *cfg)
{
	return new_style_md_open(cfg, sizeof(struct md_on_disk_08));
}

int v08_md_initialize(struct format *cfg)
{
	int i;

	cfg->md.la_sect = 0;
	cfg->md.uuid[Current] = UUID_JUST_CREATED;
	cfg->md.uuid[Bitmap] = 0;
	for ( i=History_start ; i<=History_end ; i++ ) {
		cfg->md.uuid[i]=0;
	}
	cfg->md.flags = 0;
	cfg->md.magic = DRBD_MD_MAGIC_08;

	/*
	 * FIXME md_size not yet validated or used.
	 * FIXME make it flexible, not fixed anymore as with 07.
	 */
	cfg->md.md_size = MD_RESERVED_SIZE_07;
	cfg->md.al_offset = MD_AL_OFFSET_07;
	cfg->md.al_nr_extents = 257;	/* arbitrary. */
	cfg->md.bm_offset = MD_BM_OFFSET_07;

	cfg->al_offset = cfg->md_offset + cfg->md.al_offset * 512;
	cfg->bm_offset = cfg->md_offset + cfg->md.bm_offset * 512;
	if (cfg->on_disk.al == NULL) {
		cfg->on_disk.al =
		    mmap(NULL, MD_AL_MAX_SIZE_07 * 512, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->md_fd, cfg->al_offset);
		if (cfg->on_disk.al == NULL) {
			PERROR("mmap(al_on_disk) failed");
			exit(20);
		}
	}

	if (cfg->on_disk.bm == NULL) {
		cfg->on_disk.bm =
		    mmap(NULL, MD_BM_MAX_SIZE_07, PROT_READ | PROT_WRITE,
			 MAP_SHARED, cfg->md_fd, cfg->bm_offset);
		if (cfg->on_disk.bm == NULL) {
			PERROR("mmap(bm_on_disk) failed");
			exit(20);
		}
	}

	/* do you want to initilize al to something more usefull? */
	memset(cfg->on_disk.al, 0x00, MD_AL_MAX_SIZE_07);
	memset(cfg->on_disk.bm, 0xff, MD_BM_MAX_SIZE_07);
	return 0;
}

/******************************************
  }}} end of v08
 ******************************************/
int meta_get_gi(struct format *cfg, char **argv, int argc)
{
	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	cfg->ops->get_gi(&cfg->md);

	return cfg->ops->close(cfg);
}

int meta_show_gi(struct format *cfg, char **argv, int argc)
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

	err = cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}

int meta_dump_md(struct format *cfg, char **argv, int argc)
{
	int i;

	if (argc > 0) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}

	if (cfg->ops->open(cfg))
		return -1;

	printf("version \"%s\";\n\n", cfg->ops->name);
	if (cfg->ops < f_ops + Drbd_08) {
		printf("gc {");
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			printf(" 0x%X;", cfg->md.gc[i]);
		}
	} else { // >= 08
		printf("uuid {");
		for ( i=Current ; i<UUID_SIZE ; i++ ) {
			printf(" 0x"X64(016)";", cfg->md.uuid[i]);
		}
	}
	printf(" }\n");

	if (cfg->ops >= f_ops + Drbd_07) {
		printf("la-size-sect "U64";\n", cfg->md.la_sect);
		printf("# bm-bytes %u;\n", cfg->bm_bytes);
		printf("# bits-set %u;\n", cfg->bits_set);
		if (cfg->on_disk.bm)
			printf_bm((le_u64 *) cfg->on_disk.bm,
				  cfg->bm_bytes / sizeof(le_u64));
	}

	/* MAYBE dump activity log?
	 * but that probably does not make any sense,
	 * beyond debugging. */

	return cfg->ops->close(cfg);
}

void md_parse_error(const char *etext)
{
	fprintf(stderr,"Parse error '%s' expected.",etext);
	exit(10);
}

#define EXP(TOKEN) if(yylex() != TOKEN) md_parse_error( #TOKEN );

int meta_restore_md(struct format *cfg, char **argv, int argc)
{
	int i;
	le_u64 *bm;

	if (argc > 0) {
		yyin = fopen(argv[0],"r");
		if(yyin == NULL) {
			fprintf(stderr, "open of '%s' failed.\n",argv[0]);
			exit(20);
		}
	}

	if (!cfg->ops->open(cfg)) {
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
	if (cfg->ops < f_ops + Drbd_08) {
		EXP(TK_GC); EXP('{');
		for (i = 0; i < GEN_CNT_SIZE; i++) {
			EXP(TK_U64); EXP(';');
			cfg->md.gc[i] = yylval.u64;
		}
		EXP('}');
	} else { // >? 08
		EXP(TK_UUID); EXP('{');
		for ( i=Current ; i<UUID_SIZE ; i++ ) {
			EXP(TK_U64); EXP(';');
			cfg->md.uuid[i] = yylval.u64;
		}
		EXP('}');
	}
	EXP(TK_LA_SIZE); EXP(TK_NUM); EXP(';');
	cfg->md.la_sect = yylval.u64;
	EXP(TK_BM); EXP('{');
	bm = (le_u64 *)cfg->on_disk.bm;
	i = 0;
	while(yylex() == TK_U64) {
		bm[i].le = cpu_to_le64(yylval.u64);
		i++;
		EXP(';');
	}

	if (cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg)) {
		fprintf(stderr, "Writing failed\n");
		return -1;
	}

	printf("Successfully restored meta data\n");

	return 0;
}

#undef EXP

int md_convert_07_to_08(struct format *cfg)
{
	int i,j=1;
	/* Note that al and bm are not touched!
	 * (they are currently not even mmaped)
	 *
	 * KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	printf("Converting meta data...\n");
	cfg->md.magic = DRBD_MD_MAGIC_08;

	// The MDF Flags are the same in 07 and 08
	cfg->md.flags = cfg->md.gc[Flags];
	/* 
	 */
	cfg->md.uuid[Current] = 
		(u64)(cfg->md.gc[HumanCnt] & 0xffff) << 48 |
		(u64)(cfg->md.gc[TimeoutCnt] & 0xffff) << 32 |
		(u64)((cfg->md.gc[ConnectedCnt]+cfg->md.gc[ArbitraryCnt])
		       & 0xffff) << 16 |
		(u64)0xbabe;
	cfg->md.uuid[Bitmap] = (u64)0;
	if (cfg->bits_set) i = Bitmap;
	else i = History_start;
	for ( ; i<=History_end ; i++ ) {
		cfg->md.uuid[i] = cfg->md.uuid[Current] - j*0x10000;
		j++;
	}

	if (cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg)) {
		fprintf(stderr, "conversion failed\n");
		return -1;
	}
	printf("Successfully converted v07 meta data to v08 format.\n");
	return 0;
}

int md_convert_08_to_07(struct format *cfg)
{
	/* Note that al and bm are not touched!
	 * (they are currently not even mmaped)
	 *
	 * KB <-> sectors is done in the md disk<->cpu functions.
	 * We only need to adjust the magic here. */
	printf("Converting meta data...\n");
	cfg->md.magic = DRBD_MD_MAGIC_07;
	// somehow generate GCs in a sane way
	if (cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg)) {
		fprintf(stderr, "conversion failed\n");
		return -1;
	}
	printf("Conversion Currently BROKEN!\n");
	//printf("Successfully converted v08 meta data to v07 format.\n");
	return 0;
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

int may_be_extX(char *data, struct fstype_s *f)
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

int may_be_xfs(char *data, struct fstype_s *f)
{
	if (be32_to_cpu(*(u32*)(data+0)) == 0x58465342) {
		f->type = "xfs filesystem";
		f->bsize = be32_to_cpu(*(u32*)(data+4));
		f->bnum  = be64_to_cpu(*(u64*)(data+8));
		return 1;
	}
	return 0;
}

int may_be_reiserfs(char *data, struct fstype_s *f)
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

int may_be_jfs(char *data, struct fstype_s *f)
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
int may_be_swap(char *data, struct fstype_s *f)
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

int may_be_LVM(char *data, struct fstype_s *f)
{
	if (strncmp("LVM2",data+0x218,4) == 0) {
		f->type = "LVM2 physical volume signature";
		REFUSE_IT
		return 1;
	}
	return 0;
}

void check_for_exiting_data(struct format *cfg)
{
	char *data = cfg->on_disk.ll_data;
	struct fstype_s f;
	int i;
	if (data == NULL)
		return;

	for (i = 0; i < HOW_MUCH/sizeof(long); i++) {
		if (((long*)(data))[i] != 0LU) break;
	}
	/* all zeros? no message */
	if (i == HOW_MUCH/sizeof(long)) return;

	f.type = "some data";
	f.bnum = 0;
	f.bsize = 0;

/* FIXME add more detection magic
 */

	may_be_swap     (data,&f) ||
	may_be_LVM      (data,&f) ||

	may_be_extX     (data,&f) ||
	may_be_xfs      (data,&f) ||
	may_be_jfs      (data,&f) ||
	may_be_reiserfs (data,&f);

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

#if 0
#define min(x,y) ((x) < (y) ? (x) : (y))
		max_usable_kB =
			min( cfg->md_offset,
			min( cfg->al_offset,
			     cfg->bm_offset )) >> 10;
#undef min

		printf("md_offset %llu\n", cfg->md_offset);
		printf("al_offset %llu\n", cfg->al_offset);
		printf("bm_offset %llu\n", cfg->bm_offset);
#else
		/* for now (we still have no flexible size meta data) */
		max_usable_kB = cfg->md_offset >> 10;
#endif

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
			if (confirmed("Valid v07 meta-data found, convert to v08?"))
				return md_convert_07_to_08(cfg);
		}
	}
	if (virgin && cfg->ops == f_ops + Drbd_07) {
		/* don't just overwrite existing v08 with v07
		 */
		virgin = v08_md_disk_to_cpu(cfg);
		if (!virgin) {
			if (confirmed("Valid v08 meta-data found, convert back to v07?"))
				return md_convert_08_to_07(cfg);
		}
	}

	if (!virgin) {
		if (!confirmed("Valid meta-data already in place, recreate new?")) {
			printf("Operation cancelled.\n");
			exit(0);
		}
	} else {
		printf("About to create a new drbd meta data block\non %s.\n",
				cfg->md_device_name);
		check_for_exiting_data(cfg);

		if (!confirmed(" ==> This might destroy existing data! <==\n\n"
				"Do you want to proceed?")) {
			printf("Operation cancelled.\n");
			exit(0);
		}
	}

	printf("Creating meta data...\n");
	memset(&cfg->md, 0, sizeof(cfg->md));
	err = cfg->ops->md_initialize(cfg)
	    || cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "operation failed\n");

	return err;
}

int meta_outdate(struct format *cfg, char **argv, int argc)
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

	err = cfg->ops->md_cpu_to_disk(cfg)
		|| cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}


#if 0
int meta_set_size(struct format *cfg, char **argv, int argc)
{
	struct md_cpu tmp;
	unsigned long long kB, ll_kB;
	int err;
	char **str;

#warning	"sorry, not yet correctly implemented"
	fprintf(stderr,	"sorry, not yet correctly implemented\n");
	exit(30);
	if (argc > 1) {
		fprintf(stderr, "Ignoring additional arguments\n");
	}
	if (argc < 1) {
		fprintf(stderr, "Required Argument missing\n");
		exit(10);
	}

	if (cfg->ops->open(cfg))
		return -1;

	ll_kB = bdev_size(cfg->drbd_fd) >> 10;

	/* FIXME make flexible for v08
	 * new method vXY_max_dev_sect? */
	if (cfg->md_index == -1) {
		if (ll_kB < (MD_RESERVED_SIZE_07>>10)) {
			fprintf(stderr, "device too small for internal meta data\n");
			exit(20);
		}
		ll_kB = ALIGN(ll_kB,4) - (MD_RESERVED_SIZE_07 >> 10);
	}

	kB = m_strtoll(argv[0],'k');
	if (kB > ll_kB) {
		fprintf(stderr,
			"%s out of range, maximum available %llukB.\n",
			argv[0], ll_kB);
		exit(20);
	}
	tmp = cfg->md;
	tmp.la_sect = kB<<1;

	printf("available   %llukB\n", ll_kB);
	printf("previously  %llukB\n", cfg->md.la_sect>>1);
	printf("size set to %llukB\n", kB);

	if (!confirmed("Write new size to disk?")) {
		printf("Operation cancelled.\n");
		exit(0);
	}

	if (cfg->on_disk.bm) {
		u64 a,b,ll;
		a = cfg->md.la_sect;
		b = tmp.la_sect;
		/* convert sectors to bit numbers */
		a >>= 8;
		b = (b+7) >> 8;
		if (b > a) {
			/* first word */
		}
	}
	cfg->md = tmp;
	err = cfg->ops->md_cpu_to_disk(cfg)
	    || cfg->ops->close(cfg);
	if (err)
		fprintf(stderr, "update failed\n");

	return err;
}
#endif

char *progname = NULL;
void print_usage_and_exit()
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

int is_configured(int minor)
{
	FILE *pr;
	char line[120], tok[40];
	int m,rv=0;

	pr = fopen("/proc/drbd","r");
	if(!pr) return rv;

	while(fgets(line,120,pr)) {
		if(sscanf(line,"%2d: %s",&m,tok)) {
			if( m == minor ) {
				rv = strcmp(tok,"Unconfigured");
				break;
			}
		}
	}
	fclose(pr);

	return rv;
}

int main(int argc, char **argv)
{
	struct meta_cmd *command = NULL;
	struct format *cfg;
	int i, ai;

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
#endif

	if ((progname = strrchr(argv[0], '/'))) {
		argv[0] = ++progname;
	} else {
		progname = argv[0];
	}

	if (argc < 4)
		print_usage_and_exit();

	/* FIXME should have a "drbd_cfg_new" and a "drbd_cfg_free"
	 * function, maybe even a "get" and "put" ?
	 */
	cfg = calloc(1, sizeof(struct format));
	cfg->drbd_dev_name = argv[1];

	/* argv[0] is progname, argv[1] was drbd_dev_name. */
	ai = 2;
	if (parse_format(cfg, argv + ai, argc - ai, &ai)) {
		/* parse has already printed some error message */
		exit(20);
	}

	if (ai >= argc) {
		fprintf(stderr, "command missing\n");
		exit(20);
	}

	cfg->drbd_fd = dt_lock_open_drbd(cfg->drbd_dev_name, &cfg->lock_fd, 1);
	if (cfg->drbd_fd > -1) {
		if (is_configured(dt_minor_of_dev(cfg->drbd_dev_name))) {
			fprintf(stderr, "Device '%s' is configured!\n",
				cfg->drbd_dev_name);
			exit(20);
		}
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
	 * free(cfg->md_device_name), free(cfg) ...
	 */
}
