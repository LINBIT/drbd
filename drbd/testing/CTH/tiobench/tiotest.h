/*
 *    Threaded io test
 *
 *  Copyright (C) 1999-2000 Mika Kuoppala <miku@iki.fi>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  
 *
 *
 */

#ifndef TIOTEST_H
#define TIOTEST_H

#ifdef LARGEFILES 
#define __USE_LARGEFILE64
#define _LARGEFILE64_SOURCE 
#endif

#define _GNU_SOURCE
#define _REENTRANT
#define _THREAD_SAFE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/mman.h>

#ifdef LARGEFILES
#ifndef _LFS64_LARGEFILE
#error no large file support available, remove -DLARGEFILES from makefile
#endif
#endif

#if (LARGEFILES && USE_MMAP)
#warning "LARGEFILES and USE_MMAP might not work on 32bit architectures!"
#endif

#ifdef LONG_OPTIONS
#include <getopt.h>
#endif

#define TESTS_COUNT            4

#define DEFAULT_DEBUG_LEVEL    0

#define LATENCY_STAT1          2
#define LATENCY_STAT2          10

#define MAX_PATHS              50

#define KBYTE                  1024
#define MBYTE                  (1024*KBYTE)
#define PAGE_SIZE              (4096)

#define DEFAULT_FILESIZE       (10) /* In Megs !!! */
#define DEFAULT_THREADS        4
#define DEFAULT_RANDOM_OPS     1000
#define DEFAULT_DIRECTORY      "."
#define DEFAULT_BLOCKSIZE      (4*KBYTE)
#define DEFAULT_RAW_OFFSET     0

#define TRUE                   1
#define FALSE                  0

#ifdef LARGEFILES
typedef off64_t toff_t;
#define tlseek	lseek64
#else
typedef off_t   toff_t;
#define tlseek	lseek
#endif

typedef struct {
	struct timeval startRealTime;
	struct timeval startUserTime;
	struct timeval startSysTime;

	struct timeval stopRealTime;
	struct timeval stopUserTime;
	struct timeval stopSysTime;
} Timings;

typedef struct {
	double avg, max;
	int count, count1, count2;
} Latencies;

typedef struct {

	pthread_t        thread;
	pthread_attr_t   thread_attr;
    
	char             fileName[KBYTE];
	toff_t           fileSizeInMBytes;
	toff_t           fileOffset;
	unsigned long    numRandomOps;

	unsigned long    blockSize;
	unsigned char*   buffer;
	unsigned long    bufferCrc;

	unsigned long    myNumber;

	unsigned long    blocksWritten;
	Timings          writeTimings;
	Latencies	 writeLatency;

	unsigned long    blocksRandomWritten;
	Timings          randomWriteTimings;
	Latencies	 randomWriteLatency;

	unsigned long    blocksRead;
	Timings          readTimings;
	Latencies	 readLatency;

	unsigned long    blocksRandomRead;
	Timings          randomReadTimings;
	Latencies	 randomReadLatency;

} ThreadData;

typedef struct {
    
	ThreadData* threads;
	int numThreads;
    
	Timings totalTimeWrite;
	Timings totalTimeRandomWrite;
	Timings totalTimeRead;
	Timings totalTimeRandomRead;

} ThreadTest;

typedef struct {
	
	char     path[MAX_PATHS][KBYTE];
	int      pathsCount;
	int      fileSizeInMBytes;
	int      numThreads;
	int      blockSize;
	int      numRandomOps;
	int      verbose;
	int      terse;
	int      sequentialWriting;
	int      syncWriting;
	int	 rawDrives;
	int      consistencyCheckData;
	int      showLatency;
	long	 threadOffset;
	int	 useThreadOffsetForFirstThread;
	
	int	 testsToRun[TESTS_COUNT];
	int	 runRandomWrite;
	int	 runRead;
	int	 runRandomRead;

	/*
	  Debug level
	  This should be from 0 - 10
	*/
	int      debugLevel;

} ArgumentOptions;

void    print_help_and_exit();

void*   do_write_test( ThreadData *d );
void*   do_read_test( ThreadData *d );
void*   do_random_read_test( ThreadData *d );
void*   do_random_write_test( ThreadData *d );

void    initialize_test( ThreadTest *d  );

void    cleanup_test( ThreadTest *d );
void 	do_test( ThreadTest *test, int testCase, int sequential,
		Timings *t, char *debugMessage );
void    print_results( ThreadTest *threadTest );
void    do_tests( ThreadTest *d );

void    timer_init(Timings *t);
void    timer_start(Timings *t);
void    timer_stop(Timings *t);
const double timer_realtime(const Timings *t);
const double timer_usertime(const Timings *t);
const double timer_systime(const Timings *t);

clock_t get_time();
unsigned int get_random_seed();

inline const toff_t get_random_offset(const toff_t filesize, unsigned int *seed);

void    parse_args( ArgumentOptions* args, int argc, char *argv[] );

typedef void*(*TestFunc)(ThreadData *);

#define WRITE_TEST         0
#define RANDOM_WRITE_TEST  1
#define READ_TEST          2
#define RANDOM_READ_TEST   3

TestFunc Tests[TESTS_COUNT+1] = { 
    do_write_test, 
    do_random_write_test, 
    do_read_test, 
    do_random_read_test, 
    0 };

#endif /* TIOTEST_H */
