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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>  // gint32, GINT64_FROM_BE()
#include "drbdtool_common.h"

#define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )

#if G_MAXLONG == 0x7FFFFFFF
#define LN2_BPL 5
#elif G_MAXLONG == 0x7FFFFFFFFFFFFFFF
#define LN2_BPL 6
#else
#error "LN2 of BITS_PER_LONG unknown!"
#endif

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

struct conf_06 {
	int fd;
	int minor;
};

struct conf_07 {
	int fd;
	char *device_name;
	int index;
};

typedef void* conf_t;

struct format {
	const char* name;
	char** args;
	int conf_size;
	int (* parse)(conf_t, char **argv, int*);
	int (* open) (conf_t);
	int (* close)(conf_t);
	int (* read) (conf_t, struct meta_data *);
	int (* write)(conf_t, struct meta_data *);
};

int v07_parse(conf_t config, char **argv, int *ai);
int v07_open(conf_t config);
int v07_close(conf_t config);
int v07_read(conf_t config, struct meta_data *);
int v07_write(conf_t config, struct meta_data *);

struct format formats[] = {
	{ "v07",
	  (char *[]) { "device","index",0 },
	  sizeof(struct conf_07),
	  v07_parse,
	  v07_open,
	  v07_close,
	  v07_read,
	  v07_write
	}
};

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

int v07_parse(conf_t config, char **argv, int *ai)
{
	struct conf_07* cfg = (struct conf_07*) config;
	char *e;

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

int v07_open(conf_t config)
{
	struct conf_07* cfg = (struct conf_07*) config;

	cfg->fd = open(cfg->device_name,O_RDWR);

	return (cfg->fd != -1) ;
}

int v07_close(conf_t config)
{
	struct conf_07* cfg = (struct conf_07*) config;

	return close(cfg->fd) == 0;
}

struct meta_data * md_alloc()
{
	struct meta_data *m;

	m = malloc(sizeof(struct meta_data ));
	memset(m,sizeof(struct meta_data ),1);
  
	return m;  
}

void md_free(struct meta_data * m)
{

	if(m->bitmap)  free(m->bitmap);
	if(m->act_log) free(m->act_log);

	free(m);
}


int v07_read(conf_t config, struct meta_data * m)
{
	struct conf_07* cfg = (struct conf_07*) config;
	struct meta_data_on_disk_07 * buffer;
	int rr,i,bmw;

	buffer = malloc(sizeof(struct meta_data_on_disk_07));
  
	rr = read(cfg->fd, buffer, sizeof(struct meta_data_on_disk_07));
	if( rr != sizeof(struct meta_data_on_disk_07)) {
		PERROR("read failed");
		exit(20);
	}
    
	for (i = Flags; i < GEN_CNT_SIZE; i++)
		m->gc[i] = GINT32_FROM_BE(buffer->gc[Flags]);

	m->la_size = GINT64_FROM_BE(buffer->la_size);
	bmw = bm_words(m->la_size);

	return 1;
}

int v07_write(conf_t config, struct meta_data * m)
{
	return 0;
}

struct meta_cmd {
	const char* name;
	const char* args;
	int (* function)(struct format*, conf_t);
	int show_in_usage;
};

int meta_show_gc(struct format* fmt, conf_t fcfg)
{
	struct meta_data* md;
	char ppb[10];

	md = md_alloc();

	fmt->open(fcfg);
	fmt->read(fcfg,md);
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

	fmt->close(fcfg);
	
	md_free(md);

	return 1;
}

int meta_create_md(struct format* fmt, conf_t fcfg) { return 0; }
int meta_dump_md(struct format* fmt, conf_t fcfg) { return 0; }
int meta_convert_md(struct format* fmt, conf_t fcfg) { return 0; }
int meta_modify_gc(struct format* fmt, conf_t fcfg) { return 0; }

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

int main(int argc, char** argv)
{
	int i,ai,drbd_fd;
	struct format* fmt = NULL;
	struct meta_cmd* command = NULL;
	conf_t fcfg;

	if ( (progname = strrchr(argv[0],'/')) ) {
		argv[0] = ++progname;
	} else {
		progname = argv[0];
	}

	if (argc < 4) print_usage();

	ai = 1;
	drbd_fd=dt_open_drbd_device(argv[ai++]); // This creates the lock file.

	for (i = 0; i < ARRY_SIZE(formats); i++ ) {
		if( !strcmp(formats[i].name,argv[ai]) ) {
			fmt = formats+i;
			break;
		}
	}
	if(fmt == NULL) {
		fprintf(stderr,"Unknown format '%s'.\n",argv[ai]);
	}
	ai++;

	fcfg = malloc(fmt->conf_size);
	fmt->parse(fcfg,argv+2,&ai);

	for (i = 0; i < ARRY_SIZE(cmds); i++ ) {
		if( !strcmp(cmds[i].name,argv[ai]) ) {
			command = cmds+i;
			break;
		}
	}
	if(command == NULL) {
		fprintf(stderr,"Unknown command '%s'.\n",argv[ai]);
	}
	ai++;

	command->function(fmt,fcfg);

	dt_close_drbd_device(drbd_fd);
	return 0;
}
