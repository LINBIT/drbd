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
#include <unistd.h>
#include <string.h>
#include "drbdtool_common.h"
#include <glib.h>  // gint32, GINT64_FROM_BE()

#define ALIGN(x,a) ( ((x) + (a)-1) &~ ((a)-1) )

char* basename = 0;

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

struct version {
  const char* name;
  int (* parse)(conf_t, char **argv);
  int (* open) (conf_t);
  int (* close)(conf_t);
  struct meta_data * (* alloc) (conf_t);
  void (* free) (conf_t, struct meta_data *);
  int (* read) (conf_t, struct meta_data *);
  int (* write)(conf_t, struct meta_data *);
};

struct meta_cmd {
  const char* name;
  int (* function)(void *,char* );
  int show_in_usage;
};

int meta_dump(void* v, char* c)
{
  return 0;
}

struct meta_cmd cmds[] = {
  { "dump",    meta_dump,      1 }
};

int v07_parse(conf_t config, char **argv);
int v07_open(conf_t config);
int v07_close(conf_t config);
struct meta_data * vxx_alloc(conf_t config);
void vxx_free(conf_t config, struct meta_data * m);
int v07_read(conf_t config, struct meta_data *);
int v07_write(conf_t config, struct meta_data *);

struct version versions[] = {
  { "v07",v07_parse,v07_open,v07_close,vxx_alloc,vxx_free,v07_read,v07_write},
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

int v07_parse(conf_t config, char **argv)
{
  struct conf_07* cfg = (struct conf_07*) config;
  char *e;

  cfg.device_name = strdup(argv[0]);
  e = argv[1];
  cfg.index = strtol(argv[1],&e,0);
  if(*e != 0) {
    fprintf(stderr,"'%s' is not a valid index number.\n",argv[1]);
    return 0;
  }
  return 1;
}

int v07_open(conf_t config)
{
  struct conf_07* cfg = (struct conf_07*) config;

  cfg.fd = open(cfg.device_name,O_RDWR);

  return (cfg.fd != -1) ;
}

int v07_close(conf_t config)
{
  struct conf_07* cfg = (struct conf_07*) config;

  return close(cfg.fd) == 0;
}

struct meta_data * vxx_alloc(conf_t config)
{
  struct meta_data *m;

  m = malloc(sizeof(struct meta_data ));
  memset(m,sizeof(struct meta_data ),1);
  
  return m;  
}

void vxx_free(conf_t config, struct meta_data * m)
{
  struct meta_data *m;

  if(m->bitmap)  free(m->bitmap);
  if(m->act_log) free(m->act_log);

  free(m);
}


int v07_read(conf_t config, struct meta_data * m)
{
  struct meta_data_on_disk * buffer;
  int rr,i,bmw;

  buffer = malloc(sizeof(struct meta_data_on_disk));
  
  rr = read(cfg.fd, buffer, sizeof(struct meta_data_on_disk));
  if( rr != sizeof(struct meta_data_on_disk)) {
    PERROR("read failed");
    exit(20);
  }
    
  for (i = Flags; i < GEN_CNT_SIZE; i++)
    m->gc[i] = GINT32_FROM_BE(buffer->gc[Flags]);

  m->la_size = GINT64_FROM_BE(buffer->la_size);
  bmw = bm_words(m->la_size);

  
}

int v07_write(conf_t config)
{
}


int main(int argc, char** argv)
{
  int drbd_fd;

  if ( (basename = strrchr(argv[0],'/')) )
      argv[0] = ++basename;
  else
      basename = argv[0];

  chdir("/");

  drbd_fd=dt_open_drbd_device(device); // This creates the lock file.
}
