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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include <linux/fs.h>     /* for BLKGETSIZE64 */
#include <linux/drbd.h>   /* only use DRBD_MAGIC from here! */

#include "drbdtool_common.h"
#include "drbd_endian.h"


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
#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)
#define MD_RESERVED_SIZE_07 ( (u64)128 * (1<<20) )
#define MD_BM_MAX_SIZE_07  ( MD_RESERVED_SIZE_07 - MD_BM_OFFSET_07*512 )

#define DRBD_MD_MAGIC_08   (DRBD_MAGIC+4)

#define DRBD_MD_MAGIC_06   (DRBD_MAGIC+2)

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

#define OR_EXIT(OBJ,OP,args...) \
({ if(! OBJ->ops-> OP(OBJ, ##args) ) format_op_failed(OBJ, #OP ); })

enum MetaDataIndex {
	Flags,          /* Consistency flag,connected-ind,primary-ind */
	HumanCnt,       /* human-intervention-count */
	TimeoutCnt,     /* timout-count */
	ConnectedCnt,   /* connected-count */
	ArbitraryCnt,   /* arbitrary-count */
	GEN_CNT_SIZE	/* MUST BE LAST! (and Flags must stay first...) */
};

struct meta_data {
	u32 gc[GEN_CNT_SIZE];   /* v06 */

	u64 la_size;              /* v07  [ units of KB ] */
	int bm_size;              /* v07 */
	unsigned long *bitmap;    /* v07 */
	int al_size;              /* v07 */
	unsigned int  *act_log;   /* not yet implemented... */

	unsigned long bits_set;   /* additional info, set by fopts->read() */
};

/*
 * }
 * end of should-be-shared
 */


/*
 * drbdmeta specific types
 */

struct format_06 {
	int fd;
	int minor;
};

struct format_07 {
	int fd;
	char *device_name;
	int index;
};

struct format_ops;

struct format {
	struct format_ops *ops;
	union {
		struct format_06 f06;
		struct format_07 f07;
	} d;
};

typedef void* conf_t;

struct format_ops {
	const char* name;
	char** args;
	int conf_size;
	int (* parse)(struct format *, char **, int, int*);
	int (* open) (struct format *);
	int (* close)(struct format *);
	struct meta_data * (* md_alloc)(void);
	int (* read) (struct format *, struct meta_data *);
	int (* write)(struct format *, struct meta_data *, int);
};

void format_op_failed(struct format * fcfg, char* op)
{
	fprintf(stderr,"%s_%s() failed\n",fcfg->ops->name,op);
	exit(20);
}

/* capacity in units of 512 byte (AKA sectors)
 */
int bm_words(unsigned long capacity)
{
	unsigned long bits;
	int words;

	/* bits  = ALIGN(capacity,BM_SECTORS_PER_BIT) >> (BM_BLOCK_SIZE_B-9); */
	bits = ALIGN(capacity,8) >> 3;
	words = ALIGN(bits,64) >> LN2_BPL;

	return words;
}

void to_lel(unsigned long* buffer, int words)
{
	int i;
	unsigned long w;

	for (i=0;i<words;i++) {
		w = cpu_to_le_long(buffer[i]);
		buffer[i] = w;
	}
}


unsigned long from_lel(unsigned long* buffer, int words)
{
	int i;
	unsigned long w;
	unsigned long bits=0;

	for (i=0;i<words;i++) {
		w = le_long_to_cpu(buffer[i]);
		bits += hweight_long(w);
		buffer[i] = w;
	}

	return bits;
}

u64 bdev_size(int fd)
{
	u64 size64; /* size in byte. */
	long size;    /* size in sectors. */
	int err;

	err=ioctl(fd,BLKGETSIZE64,&size64);
	if(err) {
		if (errno == EINVAL)  {
			printf("INFO: falling back to BLKGETSIZE\n");
			err=ioctl(fd,BLKGETSIZE,&size);
			if(err) {
				perror("ioctl(,BLKGETSIZE,) failed");
				exit(20);
			}
			size64 = (typeof(u64))512 * size;
		} else {
			perror("ioctl(,BLKGETSIZE64,) failed");
			exit(20);
		}
	}

	return size64;
}

void md_free(struct meta_data * m)
{

	if(m->bitmap)  free(m->bitmap);
	if(m->act_log) free(m->act_log);

	free(m);
}

/******************************************
 begin of v07 {
 ******************************************/
struct __attribute__((packed)) meta_data_on_disk_07 {
	u64 la_size;           /* last agreed size. */
	u32 gc[GEN_CNT_SIZE];  /* generation counter */
	u32 magic;
	u32 md_size;
	u32 al_offset;         /* offset to this block */
	u32 al_nr_extents;     /* important for restoring the AL */
	u32 bm_offset;         /* offset to the bitmap, from here */
};

u64 v07_offset(struct format_07* cfg)
{
	u64 offset;

	if(cfg->index == -1) {
		offset = ( bdev_size(cfg->fd) & ~((1<<12)-1) )
			- MD_RESERVED_SIZE_07;
	} else {
		offset = MD_RESERVED_SIZE_07 * cfg->index;
	}
	return offset;
}

int v07_parse(struct format * config, char **argv, int argc, int *ai);
int v07_open(struct format * config);
int v07_close(struct format * config);
struct meta_data * v07_md_alloc(void);
int v07_read(struct format * config, struct meta_data *);
int v07_write(struct format * config, struct meta_data *, int init_al);

int v07_parse(struct format * config, char **argv, int argc, int *ai)
{
	struct format_07* cfg = &config->d.f07;
	char *e;

	if(argc < 2) {
		fprintf(stderr,"Too few arguments for format\n");
		return 0;
	}

	cfg->device_name = strdup(argv[0]);
	e = argv[1];
	cfg->index = strtol(argv[1],&e,0);
	if(*e != 0) {
		fprintf(stderr,"'%s' is not a valid index number.\n",argv[1]);
		return 0;
	}

	*ai+=2;

	return 1;
}

int v07_open(struct format * config)
{
	struct format_07* cfg = &config->d.f07;
	struct stat sb;

	cfg->fd = open(cfg->device_name,O_RDWR);

	if(cfg->fd == -1) {
		PERROR("open() failed");
		return 0;
	}

	if(fstat(cfg->fd, &sb)) {
		PERROR("fstat() failed");
		return 0;
	}

	if(!S_ISBLK(sb.st_mode)) {
		fprintf(stderr, "'%s' is not a block device!\n",
			cfg->device_name);
		return 0;
	}

	if( ioctl(cfg->fd,BLKFLSBUF) == -1) {
		PERROR("ioctl(,BLKFLSBUF,) failed");
		return 0;
	}

	return 1;
}

int v07_close(struct format * config)
{
	struct format_07* cfg = &config->d.f07;

	if( fsync(cfg->fd) == -1) {
		PERROR("fsync() failed");
		return 0;
	}

	if( ioctl(cfg->fd,BLKFLSBUF) == -1) {
		PERROR("ioctl(,BLKFLSBUF,) failed");
		return 0;
	}

	return close(cfg->fd) == 0;
}

struct meta_data * v07_md_alloc(void)
{
	struct meta_data *m;

	m = malloc(sizeof(struct meta_data ));
	memset(m,0,sizeof(struct meta_data ));

	m->bitmap = malloc(MD_BM_MAX_SIZE_07);
	if( ! m->bitmap) {
		PERROR("Can not allocate memory for bitmap.");
		return 0;
	}

	m->bm_size = MD_BM_MAX_SIZE_07;

	return m;
}

int v07_read(struct format * config, struct meta_data * m)
{
	struct format_07* cfg = &config->d.f07;
	struct meta_data_on_disk_07 buffer;
	int rr,i,bmw;
	u64 offset = v07_offset(cfg);

	if(lseek64(cfg->fd,offset,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = read(cfg->fd, &buffer, sizeof(struct meta_data_on_disk_07));
	if( rr != sizeof(struct meta_data_on_disk_07)) {
		PERROR("read failed");
		return 0;
	}

	if( be32_to_cpu(buffer.magic) != DRBD_MD_MAGIC_07 ) {
		fprintf(stderr,"Magic number not found\n");
		return 0;
	}

	if( be32_to_cpu(buffer.al_offset) != MD_AL_OFFSET_07 ) {
		fprintf(stderr,"Magic number (al_offset) not found\n");
		return 0;
	}

	if( be32_to_cpu(buffer.bm_offset) != MD_BM_OFFSET_07 ) {
		fprintf(stderr,"Magic number (bm_offset) not found\n");
		return 0;
	}

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		m->gc[i] = be32_to_cpu(buffer.gc[i]);

	m->la_size = be64_to_cpu(buffer.la_size);

	if(m->bitmap) {
		bmw = bm_words(m->la_size);

		offset = offset + 512 * MD_BM_OFFSET_07;
		if(lseek64(cfg->fd, offset, SEEK_SET) == -1) {
			PERROR("lseek() failed");
			return 0;
		}

		rr = read(cfg->fd, m->bitmap, bmw*sizeof(long));
		if( rr != bmw*sizeof(long) ) {
			PERROR("read failed");
			return 0;
		}

		m->bm_size = bmw*sizeof(long);
		m->bits_set = from_lel(m->bitmap,bmw);
	}

	return 1;
}

int v07_write(struct format * config, struct meta_data * m, int init_al)
{
	struct format_07* cfg = &config->d.f07;
	struct meta_data_on_disk_07 buffer;
	int rr,i;
	u64 offset = v07_offset(cfg);

	buffer.magic = cpu_to_be32( DRBD_MD_MAGIC_07 );
	buffer.al_offset = cpu_to_be32( MD_AL_OFFSET_07 );
	buffer.bm_offset = cpu_to_be32( MD_BM_OFFSET_07 );

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		buffer.gc[i] = cpu_to_be32(m->gc[i]);

	buffer.la_size = cpu_to_be64(m->la_size);

	if(lseek64(cfg->fd,offset,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = write(cfg->fd, &buffer, sizeof(struct meta_data_on_disk_07));
	if( rr != sizeof(struct meta_data_on_disk_07)) {
		PERROR("write failed");
		return 0;
	}

	if(lseek64(cfg->fd,offset + 512 * MD_BM_OFFSET_07 ,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	to_lel(m->bitmap, m->bm_size/sizeof(long) );

	rr = write(cfg->fd, m->bitmap, m->bm_size);
	if( rr != m->bm_size) {
		PERROR("write failed");
		return 0;
	}

	from_lel(m->bitmap, m->bm_size/sizeof(long) );

	if( init_al ) {
		char sector[512] = { [ 0 ... 511 ] = 0 };

		if(lseek64(cfg->fd,offset+512*MD_AL_OFFSET_07, SEEK_SET)==-1) {
			PERROR("lseek() failed");
			return 0;
		}

		for (i = 0; i < MD_AL_MAX_SIZE_07; i++) {
			rr = write(cfg->fd, &sector, 512);
			if(rr != 512) {
				PERROR("write failed");
				return 0;
			}
		}
	}

	return 1;
}
/******************************************
 } end of v07
 ******************************************/

/******************************************
 begin of v08 {
 ******************************************/

int v08_read(struct format * config, struct meta_data *);
int v08_write(struct format * config, struct meta_data *, int init_al);

int v08_read(struct format * config, struct meta_data * m)
{
	struct format_07* cfg = &config->d.f07;
	struct meta_data_on_disk_07 buffer;
	int rr,i,bmw;
	__u64 offset = v07_offset(cfg);

	if(lseek64(cfg->fd,offset,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = read(cfg->fd, &buffer, sizeof(struct meta_data_on_disk_07));
	if( rr != sizeof(struct meta_data_on_disk_07)) {
		PERROR("read failed");
		return 0;
	}

	if( be32_to_cpu(buffer.magic) != DRBD_MD_MAGIC_08 ) {
		fprintf(stderr,"Magic number not found\n");
		return 0;
	}

	if( be32_to_cpu(buffer.al_offset) != MD_AL_OFFSET_07 ) {
		fprintf(stderr,"Magic number (al_offset) not found\n");
		return 0;
	}

	if( be32_to_cpu(buffer.bm_offset) != MD_BM_OFFSET_07 ) {
		fprintf(stderr,"Magic number (bm_offset) not found\n");
		return 0;
	}

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		m->gc[i] = be32_to_cpu(buffer.gc[i]);

	m->la_size = be64_to_cpu(buffer.la_size) / 2 ;

	if(m->bitmap) {
		bmw = bm_words(m->la_size);

		offset = offset + 512 * MD_BM_OFFSET_07;
		if(lseek64(cfg->fd, offset, SEEK_SET) == -1) {
			PERROR("lseek() failed");
			return 0;
		}

		rr = read(cfg->fd, m->bitmap, bmw*sizeof(long));
		if( rr != bmw*sizeof(long) ) {
			PERROR("read failed");
			return 0;
		}

		m->bm_size = bmw*sizeof(long);
		m->bits_set = from_lel(m->bitmap,bmw);
	}

	return 1;
}

int v08_write(struct format * config, struct meta_data * m, int init_al)
{
	struct format_07* cfg = &config->d.f07;
	struct meta_data_on_disk_07 buffer;
	int rr,i;
	__u64 offset = v07_offset(cfg);

	buffer.magic = cpu_to_be32( DRBD_MD_MAGIC_08 );
	buffer.al_offset = cpu_to_be32( MD_AL_OFFSET_07 );
	buffer.bm_offset = cpu_to_be32( MD_BM_OFFSET_07 );

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		buffer.gc[i] = cpu_to_be32(m->gc[i]);

	buffer.la_size = cpu_to_be64(m->la_size * 2);

	if(lseek64(cfg->fd,offset,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = write(cfg->fd, &buffer, sizeof(struct meta_data_on_disk_07));
	if( rr != sizeof(struct meta_data_on_disk_07)) {
		PERROR("write failed");
		return 0;
	}

	if(lseek64(cfg->fd,offset + 512 * MD_BM_OFFSET_07 ,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	to_lel(m->bitmap, m->bm_size/sizeof(long) );

	rr = write(cfg->fd, m->bitmap, m->bm_size);
	if( rr != m->bm_size) {
		PERROR("write failed");
		return 0;
	}

	from_lel(m->bitmap, m->bm_size/sizeof(long) );

	if( init_al ) {
		char sector[512] = { [ 0 ... 511 ] = 0 };

		if(lseek64(cfg->fd,offset+512*MD_AL_OFFSET_07, SEEK_SET)==-1) {
			PERROR("lseek() failed");
			return 0;
		}

		for (i = 0; i < MD_AL_MAX_SIZE_07; i++) {
			rr = write(cfg->fd, &sector, 512);
			if(rr != 512) {
				PERROR("write failed");
				return 0;
			}
		}
	}

	return 1;
}
/******************************************
 } end of v08
 ******************************************/

/******************************************
 begin of v06 {
 ******************************************/
struct __attribute__((packed)) meta_data_on_disk_06 {
	u32 gc[GEN_CNT_SIZE];  /* generation counter */
	u32 magic;
};

int v06_parse(struct format * config, char **argv, int argc, int *ai);
int v06_open(struct format * config);
int v06_close(struct format * config);
struct meta_data * v06_md_alloc(void);
int v06_read(struct format * config, struct meta_data *);
int v06_write(struct format * config, struct meta_data *, int init_al);

int v06_parse(struct format * config, char **argv, int argc, int *ai)
{
	struct format_06* cfg = &config->d.f06;
	char *e;

	if(argc < 1) {
		fprintf(stderr,"Too few arguments for format\n");
		return 0;
	}

	e = argv[0];
	cfg->minor = strtol(argv[0],&e,0);
	if(*e != 0) {
		fprintf(stderr,"'%s' is not a valid index number.\n",argv[1]);
		return 0;
	}

	*ai+=1;

	return 1;
}

int v06_open(struct format * config)
{
	struct format_06* cfg = &config->d.f06;
	char fn[100];

	snprintf(fn,99,"/var/lib/drbd/drbd%d",cfg->minor);

	cfg->fd = open(fn,O_RDWR);

	if(cfg->fd == -1) {
		PERROR("open() failed");
		return 0;
	}

	return 1;
}

int v06_close(struct format * config)
{
	struct format_06* cfg = &config->d.f06;

	return close(cfg->fd) == 0;
}

struct meta_data * v06_md_alloc(void)
{
	struct meta_data *m;

	m = malloc(sizeof(struct meta_data ));
	memset(m,0,sizeof(struct meta_data ));

	return m;
}

int v06_read(struct format * config, struct meta_data * m)
{
	struct format_06* cfg = &config->d.f06;
	struct meta_data_on_disk_06 buffer;
	int rr,i;

	if(lseek64(cfg->fd,0,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = read(cfg->fd, &buffer, sizeof(struct meta_data_on_disk_06));
	if( rr != sizeof(struct meta_data_on_disk_06)) {
		PERROR("read failed");
		return 0;
	}

	if( be32_to_cpu(buffer.magic) != DRBD_MD_MAGIC_06 ) {
		fprintf(stderr,"Magic number not found\n");
		return 0;
	}

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		m->gc[i] = be32_to_cpu(buffer.gc[i]);

	return 1;
}

int v06_write(struct format * config, struct meta_data * m, int init_al)
{
	struct format_06* cfg = &config->d.f06;
	struct meta_data_on_disk_06 buffer;
	int rr,i;

	buffer.magic = cpu_to_be32( DRBD_MD_MAGIC_06 );

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		buffer.gc[i] = cpu_to_be32(m->gc[i]);

	if(lseek64(cfg->fd,0,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = write(cfg->fd, &buffer, sizeof(struct meta_data_on_disk_06));
	if( rr != sizeof(struct meta_data_on_disk_06)) {
		PERROR("write failed");
		return 0;
	}

	return 1;
}
/******************************************
 } end of v06
 ******************************************/

struct format_ops formats[] = {
	{ 
		"v06",
		(char *[]) { "minor", 0 },
		sizeof(struct format_06),
		v06_parse,
		v06_open,
		v06_close,
		v06_md_alloc,
		v06_read,
		v06_write
	}, { 
		"v07",
		(char *[]) { "device","index",0 },
		sizeof(struct format_07),
		v07_parse,
		v07_open,
		v07_close,
		v07_md_alloc,
		v07_read,
		v07_write
	}, { 
		"v08",
		(char *[]) { "device","index",0 },
		sizeof(struct format_07),
		v07_parse,
		v07_open,
		v07_close,
		v07_md_alloc,
		v08_read,
		v08_write
	}
};

struct format_ops *fops_v06 = formats+0;
struct format_ops *fops_v07 = formats+1;
struct format_ops *fops_v08 = formats+2;

struct meta_cmd {
	const char* name;
	const char* args;
	int (* function)(struct format *, char** argv, int argc );
	int show_in_usage;
};

int meta_show_gc(struct format * fcfg, char** argv, int argc )
{
	struct meta_data* md;
	char ppb[10];

	if(argc > 0) {
		fprintf(stderr,"Ignoring additional arguments\n");
	}
	md = fcfg->ops->md_alloc();

	OR_EXIT(fcfg,open);
	OR_EXIT(fcfg,read,md);
	printf( "\n"
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
		md->gc[Flags] & MDF_Consistent ? "1/c" : "0/i",
		md->gc[HumanCnt],
		md->gc[TimeoutCnt],
		md->gc[ConnectedCnt],
		md->gc[ArbitraryCnt],
		md->gc[Flags] & MDF_PrimaryInd ? "1/p" : "0/s",
		md->gc[Flags] & MDF_ConnectedInd ? "1/c" : "0/n",
		md->gc[Flags] & MDF_FullSync ? "1/y" : "0/n");


	if(md->la_size) {
		printf("last agreed size: %s\n", ppsize(ppb,md->la_size));
	}

	if(md->bitmap) {
		printf("%lu bits set in the bitmap [ %s out of sync ]\n",
		       md->bits_set, ppsize(ppb,md->bits_set));
	}

	OR_EXIT(fcfg,close);

	md_free(md);

	return 0;
}

int meta_get_gc(struct format * fcfg, char** argv, int argc )
{
	struct meta_data* md;

	if(argc > 0) {
		fprintf(stderr,"Ignoring additional arguments\n");
	}

	md = fcfg->ops->md_alloc();

	OR_EXIT(fcfg,open);
	OR_EXIT(fcfg,read,md);
	printf("%d:%d:%d:%d:%d:%d:%d:%d\n",
		md->gc[Flags] & MDF_Consistent ? 1 : 0,
		md->gc[HumanCnt],
		md->gc[TimeoutCnt],
		md->gc[ConnectedCnt],
		md->gc[ArbitraryCnt],
		md->gc[Flags] & MDF_PrimaryInd ? 1 : 0,
		md->gc[Flags] & MDF_ConnectedInd ? 1 : 0,
		md->gc[Flags] & MDF_FullSync ? 1 : 0);

	OR_EXIT(fcfg,close);

	md_free(md);

	return 0;
}

int m_convert_md(struct format * , struct format * );

struct format * dup_v07(struct format * fcfg)
{
	struct format * new;

	new = malloc(fops_v07->conf_size + sizeof(void*) );
	new->ops = fops_v07;
	new->d.f07.fd = 0;
	new->d.f07.device_name = fcfg->d.f07.device_name;
	new->d.f07.index = fcfg->d.f07.index;
	
	return new;
}

int ask(char *text)
{
	char answer[200];
	int rr;

	printf("%s [yes/no] ",text);

	rr = scanf("%s",answer);

	return !strcmp(answer,"yes");
}

int meta_create_md(struct format * fcfg, char** argv, int argc )
{
	struct meta_data* md;

	if(argc > 0) {
		fprintf(stderr,"Ignoring additional arguments\n");
	}

	OR_EXIT(fcfg,open);

	md = fcfg->ops->md_alloc();

	/* Hackisch but efficient, knows details about v07 and v08 */
	if( fcfg->ops == fops_v08 ) {
		if(fops_v07->read(fcfg,md)) {
			if(ask("Valid v07 meta-data found, convert?")) {
				md_free(md);
				return m_convert_md(dup_v07(fcfg), fcfg);
			}
			goto question2;
		}
	}

	if(fcfg->ops->read(fcfg,md)) {
	question2:
		if(!ask("Valid meta-data already in place, create new?")) {
			printf("Operation cancelled.\n");
			exit(0);
		}
	}

	printf("Creating meta data...\n");

	md_free(md);
	md = fcfg->ops->md_alloc();
	OR_EXIT(fcfg,write,md,1);
	OR_EXIT(fcfg,close);

	md_free(md);

	return 0;
}

int m_convert_md(struct format * source, struct format * target)
{
	struct meta_data* md;

	md = target->ops->md_alloc();

	printf("Converting meta data...\n");

	OR_EXIT(source,open);
	OR_EXIT(source,read,md);
	OR_EXIT(source,close);

	OR_EXIT(target,open);
	OR_EXIT(target,write,md,0);
	OR_EXIT(target,close);

	md_free(md);

	return 0;
}

struct format* parse_format(char** argv, int argc, int* ai);

int meta_convert_md(struct format * fcfg, char** argv, int argc )
{
	struct format * target;
	int unused;

	target = parse_format(argv, argc, &unused );

	return m_convert_md(fcfg, target);
}

int meta_dump_md(struct format * fcfg, char** argv, int argc )
{
	struct meta_data* md;
	u64 *b;
	int words;
	int i;

	if(argc > 0) {
		fprintf(stderr,"Ignoring additional arguments\n");
	}

	md = fcfg->ops->md_alloc();

	OR_EXIT(fcfg,open);
	OR_EXIT(fcfg,read,md);
	printf("gc {");
	for(i=0;i<GEN_CNT_SIZE;i++) {
		printf(" 0x%X;",md->gc[i]);
	}
	printf(" }\n");

	/* if(md->la_size)  TODO. */

	if(md->bitmap) {
		words = md->bm_size/sizeof(u64);
		b = (u64*) md->bitmap;
		printf("bm {");
		for (i=0;i<words;i++) {
#if BITS_PER_LONG == 32
			printf(" 0x%016llX;",b[i]);
#elif BITS_PER_LONG == 64
			printf(" 0x%016lX;",b[i]);
#endif
			if(i%4 == 3) printf("\n    ");
		}
		printf(" }\n");
	}

	OR_EXIT(fcfg,close);

	md_free(md);

	return 0;
}

int m_strsep(char **s,int *val)
{
	char *t, *e;
	int v;

	if( (t = strsep(s,":")) ) {
		if(strlen(t)) {
			e = t;
			v = strtol(t,&e,0);
			if(*e != 0) {
				fprintf(stderr,"'%s' is not a number.\n",*s);
				exit(10);
			}
			if(v < 0 ) {
				fprintf(stderr,"'%s' is negative.\n",*s);
				exit(10);
			}
			*val = v;
		}
		return 1;
	}
	return 0;
}

int m_strsep_b(char **s,int *val, int mask)
{
	int d;
	int rv;

	d = *val & mask;

	rv = m_strsep(s,&d);

	if(d > 1) {
		fprintf(stderr,"'%d' is not 0 or 1.\n",d);
		exit(10);
	}

	if(d) *val |=  mask;
	else  *val &= ~mask;

	return rv;
}

/* "::14" sets the TimeoutCnt to 14 */
int meta_set_gc(struct format * fcfg, char** argv, int argc )
{
	struct meta_data* md;
	char **str;

	if(argc < 1) {
		fprintf(stderr,"Required Argument missing\n");
		exit(10);
	}
	str = &argv[0];

	md = fcfg->ops->md_alloc();

	OR_EXIT(fcfg,open);
	OR_EXIT(fcfg,read,md);

	do {
		if(!m_strsep_b(str,&md->gc[Flags],MDF_Consistent)) break;
		if(!m_strsep(str,&md->gc[HumanCnt])) break;
		if(!m_strsep(str,&md->gc[TimeoutCnt])) break;
		if(!m_strsep(str,&md->gc[ConnectedCnt])) break;
		if(!m_strsep(str,&md->gc[ArbitraryCnt])) break;
		if(!m_strsep_b(str,&md->gc[Flags],MDF_PrimaryInd)) break;
		if(!m_strsep_b(str,&md->gc[Flags],MDF_ConnectedInd)) break;
		if(!m_strsep_b(str,&md->gc[Flags],MDF_FullSync)) break;
	} while(0);

	OR_EXIT(fcfg,write,md,0);
	OR_EXIT(fcfg,close);

	md_free(md);

	return 0;
}

/*
 * global vaiables
 */

struct meta_cmd cmds[] = {
	{ "show-gc",    0,                         meta_show_gc,      1 },
	{ "get-gc",     0,                         meta_get_gc,       1 },
	{ "create-md",  0,                         meta_create_md,    1 },
	{ "dump-md",    0,                         meta_dump_md,      1 },
	{ "convert-md", "FORMAT [FORMAT ARGS...]", meta_convert_md,   1 },
	/* { "restore-md",    0,                    meta_restore_md,   0 }, */
	{ "set-gc",     ":::VAL:VAL:...",          meta_set_gc,       0 }
};

char* progname = 0;
int drbd_fd;
char* drbd_dev_name;

void print_usage()
{
	int i;
	char **args;

	printf("\nUSAGE: %s DEVICE FORMAT [FORMAT ARGS...] COMMAND [CMD ARGS...]\n"
	       ,progname);

	printf("\nFORMATS:\n");
	for (i = 0; i < ARRY_SIZE(formats); i++ ) {
		printf("  %s",formats[i].name);
		if ((args = formats[i].args)) {
			while(*args) {
				printf(" %s",*args++);
			}
		}
		printf("\n");
	}

	printf("\nCOMMANDS:\n");
	for (i = 0; i < ARRY_SIZE(cmds); i++ ) {
		if(!cmds[i].show_in_usage) continue;
		printf("  %s %s\n",cmds[i].name,
		       cmds[i].args ? cmds[i].args : "" );
	}

	exit(0);
}

void cleanup(void)
{
	if(drbd_fd == -1) {
		dt_release_lockfile_dev_name(drbd_dev_name);
	} else {
		dt_close_drbd_device(drbd_fd);
	}
}

struct format* parse_format(char** argv, int argc, int* ai)
{
	struct format_ops* fmt = NULL;
	struct format* fcfg;

	int i;

	if(argc < 1) {
		fprintf(stderr,"Format identifier missing\n");
		exit(20);
	}

	for (i = 0; i < ARRY_SIZE(formats); i++ ) {
		if( !strcmp(formats[i].name,argv[0]) ) {
			fmt = formats+i;
			break;
		}
	}
	if(fmt == NULL) {
		fprintf(stderr,"Unknown format '%s'.\n",argv[0]);
		exit(20);
	}

	(*ai)++;

	fcfg = malloc(fmt->conf_size + sizeof(void*) );
	fcfg->ops = fmt;
	fmt->parse(fcfg,argv+1,argc-1,ai);

	return fcfg;
}

int main(int argc, char** argv)
{
	struct meta_cmd* command = NULL;
	struct format * fcfg;
	int i,ai;

	if ( (progname = strrchr(argv[0],'/')) ) {
		argv[0] = ++progname;
	} else {
		progname = argv[0];
	}

	if (argc < 4) print_usage();

	ai = 1;
	drbd_dev_name=argv[ai++];
	drbd_fd=dt_open_drbd_device(drbd_dev_name,1); /* Create the lock file. */
	atexit(cleanup);
	if(drbd_fd > -1) {
		int fd2 = open(drbd_dev_name,O_RDWR);
		/* I want to avoid DRBD specific ioctls here... */
		if(fd2) {
			fprintf(stderr,"Device '%s' is configured!\n",
				drbd_dev_name);
			exit(20);
		}
		close(fd2);
	}

	fcfg = parse_format(argv+ai, argc-ai, &ai);

	for (i = 0; i < ARRY_SIZE(cmds); i++ ) {
		if( !strcmp(cmds[i].name,argv[ai]) ) {
			command = cmds+i;
			break;
		}
	}
	if(command == NULL) {
		fprintf(stderr,"Unknown command '%s'.\n",argv[ai]);
		exit(20);
	}
	ai++;

	return command->function(fcfg, argv+ai, argc-ai);
}
