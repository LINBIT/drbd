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
#include <linux/fs.h> // for BLKGETSIZE64
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#define __USE_LARGEFILE64
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/drbd.h>   // only use DRBD_MAGIC from here!
#include <glib.h>         // gint32, GINT64_FROM_BE()
#include "drbdtool_common.h"

#define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )

#if G_MAXLONG == 0x7FFFFFFF
#define LN2_BPL 5
#define hweight_long hweight32
#define WW UL
#elif G_MAXLONG == 0x7FFFFFFFFFFFFFFF
#define LN2_BPL 6
#define hweight_long hweight64
#else
#error "LN2 of BITS_PER_LONG unknown!"
#endif

#define MD_AL_OFFSET_07    8
#define MD_AL_MAX_SIZE_07  64
#define MD_BM_OFFSET_07    (MD_AL_OFFSET_07 + MD_AL_MAX_SIZE_07)
#define DRBD_MD_MAGIC_07   (DRBD_MAGIC+3)

char* progname = 0;

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
	Flags,          /* Consistency flag,connected-ind,primary-ind */
	HumanCnt,       /* human-intervention-count */
	TimeoutCnt,     /* timout-count */
	ConnectedCnt,   /* connected-count */
	ArbitraryCnt,   /* arbitrary-count */
	GEN_CNT_SIZE	// MUST BE LAST! (and Flags must stay first...)
};

struct meta_data {
	guint32 gc[GEN_CNT_SIZE];   // v06
	
	guint64 la_size;            // v07
	int bm_size;            // v07
	unsigned long *bitmap;  // v07
	int al_size;            // v07
	unsigned int  *act_log; // v07

	unsigned long bits_set; // additional info, set by fopts->read()
};

struct meta_data_on_disk_07 {
	guint64 la_size;           // last agreed size.
	guint32 gc[GEN_CNT_SIZE];  // generation counter
	guint32 magic;
	guint32 md_size;
	guint32 al_offset;         // offset to this block
	guint32 al_nr_extents;     // important for restoring the AL
	guint32 bm_offset;         // offset to the bitmap, from here
};

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
	int (* parse)(struct format *, char **argv, int argc, int*);
	int (* open) (struct format *);
	int (* close)(struct format *);
	int (* read) (struct format *, struct meta_data *);
	int (* write)(struct format *, struct meta_data *);
};

int v07_parse(struct format * config, char **argv, int argc, int *ai);
int v07_open(struct format * config);
int v07_close(struct format * config);
int v07_read(struct format * config, struct meta_data *);
int v07_write(struct format * config, struct meta_data *);

struct format_ops formats[] = {
	{ "v07",
	  (char *[]) { "device","index",0 },
	  sizeof(struct format_07),
	  v07_parse,
	  v07_open,
	  v07_close,
	  v07_read,
	  v07_write
	}
};


static inline guint32 hweight32(guint32 w)
{
        guint32 res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
        res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
        res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
        res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
        return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

static inline guint64 hweight64(guint64 w)
{
#if G_MAXLONG == 0x7FFFFFFF
	return hweight32((unsigned int)(w >> 32)) +
				hweight32((unsigned int)w);
#else
	guint64 res;
	res = (w & 0x5555555555555555ul) + ((w >> 1) & 0x5555555555555555ul);
	res = (res & 0x3333333333333333ul) + ((res >> 2) & 0x3333333333333333ul);
	res = (res & 0x0F0F0F0F0F0F0F0Ful) + ((res >> 4) & 0x0F0F0F0F0F0F0F0Ful);
	res = (res & 0x00FF00FF00FF00FFul) + ((res >> 8) & 0x00FF00FF00FF00FFul);
	res = (res & 0x0000FFFF0000FFFFul) + ((res >> 16) & 0x0000FFFF0000FFFFul);
	return (res & 0x00000000FFFFFFFFul) + ((res >> 32) & 0x00000000FFFFFFFFul);
#endif
}

/* capacity in units of 512 byte (AKA sectors)
 */
int bm_words(unsigned long capacity)
{
	unsigned long bits;
	int words;

	//bits  = ALIGN(capacity,BM_SECTORS_PER_BIT) >> (BM_BLOCK_SIZE_B-9);
	bits = ALIGN(capacity,8) >> 3;
	words = ALIGN(bits,64) >> LN2_BPL;

	return words;
}

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

	return 1;
}

int v07_close(struct format * config)
{
	struct format_07* cfg = &config->d.f07;

	return close(cfg->fd) == 0;
}

struct meta_data * md_alloc()
{
	struct meta_data *m;

	m = malloc(sizeof(struct meta_data ));
	memset(m,0,sizeof(struct meta_data ));
  
	return m;  
}

void md_free(struct meta_data * m)
{

	if(m->bitmap)  free(m->bitmap);
	if(m->act_log) free(m->act_log);

	free(m);
}

#define MD_RESERVED_SIZE_07 ( (typeof(guint64))128 * (1<<20) )


guint64 bdev_size(int fd)
{
	guint64 size64; // size in byte.
	long size;    // size in sectors.
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
			size64 = (typeof(guint64))512 * size;
		} else {
			perror("ioctl(,BLKGETSIZE64,) failed");
			exit(20);
		}
	}

	return size64;
}

unsigned long from_lel(unsigned long* buffer, int words)
{
	int i;
	unsigned long w;
	unsigned long bits=0;

	for (i=0;i<words;i++) {
		w = GULONG_FROM_LE(buffer[i]);
		bits += hweight_long(w);
		buffer[i] = w;
	}

	return bits;
}

int v07_read(struct format * config, struct meta_data * m)
{
	struct format_07* cfg = &config->d.f07;
	struct meta_data_on_disk_07 * buffer;
	int rr,i,bmw;
	guint64 offset;

	buffer = malloc(sizeof(struct meta_data_on_disk_07));

	if(cfg->index == -1) {
		offset = ( bdev_size(cfg->fd) & ~((1<<12)-1) )
			- MD_RESERVED_SIZE_07;
	} else {
		offset = MD_RESERVED_SIZE_07 * cfg->index;
	}
	
	if(lseek64(cfg->fd,offset,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = read(cfg->fd, buffer, sizeof(struct meta_data_on_disk_07));
	if( rr != sizeof(struct meta_data_on_disk_07)) {
		PERROR("read failed");
		return 0;
	}
    
	if( GUINT32_FROM_BE(buffer->magic) != DRBD_MD_MAGIC_07 ) {
		fprintf(stderr,"Magic number not found");
		return 0;
	}

	if( GUINT32_FROM_BE(buffer->al_offset) != MD_AL_OFFSET_07 ) {
		fprintf(stderr,"Magic number (al_offset) not found");
		return 0;
	}

	if( GUINT32_FROM_BE(buffer->bm_offset) != MD_BM_OFFSET_07 ) {
		fprintf(stderr,"Magic number (bm_offset) not found");
		return 0;
	}

	for (i = Flags; i < GEN_CNT_SIZE; i++)
		m->gc[i] = GUINT32_FROM_BE(buffer->gc[Flags]);

	m->la_size = GUINT64_FROM_BE(buffer->la_size);
	bmw = bm_words(m->la_size);

	m->bitmap = malloc(sizeof(long) * bmw);
	if( ! m->bitmap) {
		PERROR("Can not allocate memory for bitmap.");
		return 0;
	}
	m->bm_size = bmw*sizeof(long);

	if(lseek64(cfg->fd,offset + 512 * MD_BM_OFFSET_07 ,SEEK_SET) == -1) {
		PERROR("lseek() failed");
		return 0;
	}

	rr = read(cfg->fd, m->bitmap, bmw*sizeof(long));
	if( rr != bmw*sizeof(long) ) {
		PERROR("read failed");
		return 0;
	}

	m->bits_set = from_lel(m->bitmap,bmw);

	return 1;
}

int v07_write(struct format * config, struct meta_data * m)
{
	//struct format_07* cfg = &config->d.f07;

	return 0;
}

struct meta_cmd {
	const char* name;
	const char* args;
	int (* function)(struct format *, char** argv, int argc );
	int show_in_usage;
};

void format_op_failed(struct format * fcfg, char* op)
{
	fprintf(stderr,"%s_%s() failed\n",fcfg->ops->name,op);
	exit(20);
}

#define F_OP_OR_EXIT(OP,args...) \
({ if(! fcfg->ops-> OP(fcfg, ##args) ) format_op_failed(fcfg, #OP ); })

int meta_show_gc(struct format * fcfg, char** argv, int argc )
{
	struct meta_data* md;
	char ppb[10];

	if(argc > 0) {
		fprintf(stderr,"Ignoring additional arguments\n");
	}

	md = md_alloc();

	F_OP_OR_EXIT(open);
	F_OP_OR_EXIT(read,md);
	printf(
		"                                        WantFullSync |\n"
		"                                  ConnectedInd |     |\n"
		"                               lastState |     |     |\n"
		"                      ArbitraryCnt |     |     |     |\n"
		"                ConnectedCnt |     |     |     |     |\n"
		"            TimeoutCnt |     |     |     |     |     |\n"
		"        HumanCnt |     |     |     |     |     |     |\n"
		"Consistent |     |     |     |     |     |     |     |       Size\n"
		"   --------+-----+-----+-----+-----+-----+-----+-----+------------------+\n"
		"       %3s | %3d | %3d | %3d | %3d | %3s | %3s | %3s | %s\n",
		md->gc[Flags] & MDF_Consistent ? "1/c" : "0/i",
		md->gc[HumanCnt],
		md->gc[TimeoutCnt],
		md->gc[ConnectedCnt],
		md->gc[ArbitraryCnt],
		md->gc[Flags] & MDF_PrimaryInd ? "1/p" : "0/s",
		md->gc[Flags] & MDF_ConnectedInd ? "1/c" : "0/n",
		md->gc[Flags] & MDF_FullSync ? "1/y" : "0/n",
		ppsize(ppb,md->la_size));

	fcfg->ops->close(fcfg);
	
	md_free(md);

	return 1;
}

int meta_create_md(struct format * fcfg, char** argv, int argc ) { return 0; }
int meta_dump_md(struct format * fcfg, char** argv, int argc ) { return 0; }
int meta_convert_md(struct format * fcfg, char** argv, int argc ) { return 0; }
int meta_modify_gc(struct format * fcfg, char** argv, int argc ) { return 0; }

struct meta_cmd cmds[] = {
	{ "create-md",  0,                         meta_create_md,      1 },
	{ "show-gc",    0,                         meta_show_gc,      1 },
	{ "dump-md",    0,                         meta_dump_md,      1 },
	{ "convert-md", "FORMAT [FORMAT ARGS...]", meta_convert_md,   1 },
	{ "modify-gc",  "ID=VAL ...",              meta_modify_gc,    0 }
};

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

int drbd_fd;
char* drbd_dev_name;

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
	drbd_fd=dt_open_drbd_device(drbd_dev_name,1); // Create the lock file.
	atexit(cleanup);
	if(drbd_fd > -1) {
		int fd2 = open(drbd_dev_name,O_RDWR);
		// I want to avoid DRBD specific ioctls here...
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

	command->function(fcfg, argv+ai, argc-ai);

	return 0;
}
