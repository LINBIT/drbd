/*
 * Copyright (C) 2003-2004 EMC Corporation
 *
 * wbtest.c - a testing utility for the write barrier file system
 *            functionality.
 *
 * Written by Brett Russ <russb@emc.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ----------
 * 2004 modified by Lars Ellenberg for testing the data integrity
 * on a "shared" storage like DRBD.
 *
 * - I don't need the "Checkpoint files", since any data file name
 *   already contains all neccessary information about its content.
 *   So I remove all references to the Checkpoint thingy.
 * - a data file starts as  "$DATA_DIR/%pid-%size-%rnum+"
 *   and will be renamed to "$DATA_DIR/%pid-%size-%rnum"
 *   when it was fsynced to disk.
 * - in the verify stage, we first delete all files that are not fully
 *   synced to disk ("*+"). Then, all files are verified against their
 *   expected content (according to their name), then removed.
 * - when the disk fills up, we do some additional verify stage in
 *   between, so we continuously to produce IO-load, but never fill up
 *   the disk.
 * - explicitly open log file early
 *
 * ToDo:
 * - make endian save to be able to test cross platform DRBD
 * - handle signals more gracefully
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <assert.h>
#include <time.h>
#include <endian.h>

#define WBTEST_VERSION "1.1-lge"

typedef unsigned int UINT_32;

/* hard limit number of passes before internal cleanup is due */
#define MAX_RECYCLE   10000
#define DATA_BUF_LEN   4096
#define FNAME_LEN       128


/* global parameters, can be changed on commandline, with defaults: */
static char Data_path[FNAME_LEN] = "";	// -d
static char Log_fname[FNAME_LEN] = "";	// -l
static int Verify_only   = 0;		// -V
static int Dont_verify   = 0;		// -v
static UINT_32 Recycle   = 4000;	// -r
static UINT_32 Pass_cnt  = 100;		// -p
static UINT_32 Max_conc  = 25;		// -c
static UINT_32 Min_size  = 4;		// -m
static UINT_32 Max_size  = 100*1024;	// -M

/* globals, initialized after option parsing */
static DIR     *Data_dir;	// so I can fsync(dirfd(dp));
static FILE    *Log_fp;
static UINT_32  Data_buffer[DATA_BUF_LEN];

#define MIN(x,y) (((x) < (y)) ? (x) : (y))
#define MAX(x,y) (((x) > (y)) ? (x) : (y))

void Logf(char *fmt, ...)
{
	va_list ap;

	if (Log_fp) {
		va_start(ap, fmt);
		vfprintf(Log_fp, fmt, ap);
		va_end(ap);
		if ( fflush(Log_fp) || fsync(fileno(Log_fp)) ) {
			fprintf(stderr, "Logf error: ");
			perror(0);
		}
	}
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

#define PERROR(fmt , args...) do {		\
	Logf( fmt ": %s (%d)\n" , ##args ,	\
	      strerror(errno), errno );		\
} while (0)

/*
 * in child process
 ******************************************************/

void fill(const UINT_32 word, const size_t num_bytes)
{
	UINT_32 i;
	UINT_32 *p = Data_buffer;
	for (i = 0; i < num_bytes; i += 4) *p++ = word;
}

int write_file(const pid_t pid, size_t size)
{
	static char    Fname_curr[FNAME_LEN] = "";
	static char    Fname_done[FNAME_LEN] = "";
	int fd;
	ssize_t c = 0;
	UINT_32 rnum = (UINT_32) random();
	size_t wsize = size;

	snprintf(Fname_done, FNAME_LEN, "%u-%u-%08X", pid, size, rnum);
	snprintf(Fname_curr, FNAME_LEN, "%s+", Fname_done);

	fill(rnum, MIN(size, DATA_BUF_LEN));

	fd = open(Fname_curr, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (-1 == fd) {
		PERROR("open(%s,WRITE)", Fname_curr);
		return -1;
	}

	while (DATA_BUF_LEN < wsize) {
		c = write(fd, (const void *) Data_buffer, DATA_BUF_LEN);
		if (c != DATA_BUF_LEN) {
			PERROR("D write(%s) (wrote %i/%u)",
				Fname_curr, c, DATA_BUF_LEN);
			wsize = 0;
			c = -1;
			break;
		}
		wsize -= DATA_BUF_LEN;
	}

	if (wsize) {
		c = write(fd, (const void *) Data_buffer, wsize);
		if (c != wsize) {
			PERROR("D write(%s) (wrote %i/%u)",
				Fname_curr, c, wsize);
			c = -1;
		}
	}

	if (0 != fsync(fd)) {
		PERROR("D fsync(%s)", Fname_curr);
	}

	fd = close(fd);
	assert(-1 != fd);

	if (-1 != c) {
		if (rename(Fname_curr, Fname_done)) {
			PERROR("D rename(%s)", Fname_curr);
		};
	}
	fsync(dirfd(Data_dir));

	return 0;
}

void run_ascending(const pid_t pid)
{
	UINT_32 size;
	for (size = Min_size; size <= Max_size; size <<= 1) {
		// size &= ~3;
		if (write_file(pid, size)) {
			Logf("ending ascending run\n");
			break;
		}
	}
}

void run_descending(const pid_t pid)
{
	UINT_32 size;
	for (size = Max_size; size >= Min_size; size >>= 1) {
		size &= ~3;
		if (write_file(pid, size)) {
			Logf("ending descending run\n");
			break;
		}
	}
}

/*
 * below only called from master process
 ******************************************************/

void usage(char *prog)
{
	printf("Usage: %s [-hvV] [-m <min>] [-M <max>] [-p <passes>]\n"
	       "\t\t[-r <recycle>] [-c <concurrent>] [-l <vLog>] -d <datadir>\n"
	       "\n%s - Version %s Options:\n"
	       "  -h prints this usage text\n"
	       "  -v SKIP verification step of existing files (if any)\n"
	       "  -V forces exit after verification step of existing files\n"
	       "  min         minimum IO size to use (bytes)\n"
	       "  max         maximum IO size to use (bytes)\n"
	       "  passes      # of passes to run (0 for INF)\n"
	       "  recycle     # of passes after which recycling of disk space starts\n"
	       "  concurrent  # of processes to run at once\n"
	       "  vLog        log (append) all file verify failures here.\n"
	       "              otherwise /tmp/wbtest-vLog-<timestamp>-<pid> will be used\n"
	       "  datadir     required; writable directory on DRBD to store 'test data' files\n",
	       prog, prog, WBTEST_VERSION);
}

void parse_options(int argc, char *argv[])
{
	char c;

	while ((c = getopt(argc, argv, "c:hl:m:M:p:d:r:vV")) != -1) {
		UINT_32 scr;

		switch (c) {
		case 'd':
			/* "test" path -- dir on DRBD to store test data files
			 */
			snprintf(Data_path, FNAME_LEN, "%s", optarg);
			assert(strlen(Data_path) == strlen(optarg));
			break;
		case 'l':
			/* where to store the verify "log" showing found problems
			 */
			snprintf(Log_fname, FNAME_LEN, "%s", optarg);
			assert(strlen(Log_fname) == strlen(optarg));
			break;
		case 'm':
			scr = ((UINT_32) atoi(optarg)) & ~3;
			Min_size = scr;
			break;
		case 'M':
			scr = ((UINT_32) atoi(optarg)) & ~3;
			Max_size = scr;
			break;
		case 'p':
			scr = ((UINT_32) atoi(optarg));
			Pass_cnt = scr;
			break;
		case 'c':
			scr = ((UINT_32) atoi(optarg));
			Max_conc = scr;
			break;
		case 'r':
			scr = ((UINT_32) atoi(optarg));
			Recycle = scr;
			break;
		case 'v':
			Dont_verify = 1;
			break;
		case 'V':
			Verify_only = 1;
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0]);
			exit(1);
		}
	}
	if (Min_size < 4)         Min_size = 4;
	if (Max_size > 1024*1024) Max_size = 1024*1024;
	if (Verify_only) Dont_verify = 0;
	if (!Data_path[0]) {
		fprintf(stderr,
			"Missing -d Data_Path argument, required\n");
		usage(argv[0]);
		exit(1);
	}
	if (Log_fname[0]) {
		Log_fp = fopen(Log_fname, "a");
	} else {
		int fd = 0;
		time_t t = time(NULL);

		snprintf(Log_fname, FNAME_LEN,
			"/tmp/wbtest-vLog-%u-%u",
			(unsigned int)t, getpid());
		fd = open(Log_fname, O_WRONLY | O_CREAT | O_EXCL | O_APPEND,
		          S_IRUSR | S_IWUSR);
		assert(-1 != fd); // if this was a real program, retry!
		Log_fp = fdopen(fd, "a");
	}
	assert(NULL != Log_fp);
	if (chdir(Data_path)) {
		PERROR("chdir(%s)", Data_path);
		exit(1);
	}
	{
	char *p;
	p = getcwd(Data_path,sizeof(Data_path));
	assert(p == Data_path);
	}
	Data_dir = opendir(".");
	if (NULL == Data_dir) {
		PERROR("opendir(%s)", Data_path);
		exit(1);
	}
}

int wait_for_kid(pid_t kid)
{
	int err = 0;

	pid_t reaped_pid;
	int status;

	do {
		reaped_pid = waitpid(kid,&status,0);
	} while (reaped_pid == -EINTR);

	if (WIFEXITED(status)) {
		if (WEXITSTATUS(status)) {
			Logf("child %u exited with status %u\n",
				reaped_pid, WEXITSTATUS(status) );
			err = 1; // DO error here, we do NOT want to keep going
		}
	} else if (WIFSIGNALED(status)) {
		Logf("child %u exited with status %u\n",
			reaped_pid, WTERMSIG(status) );
		err = 1; // DO error here, we do NOT want to keep going
	} else if (0 > reaped_pid) {
		Logf("wait exited with error; quitting\n");
		err = 1;
	}
	return err;
}

pid_t spawn(int pass)
{
	time_t seed;
	pid_t pid;

	fflush(0);
	pid = fork();
	assert(-1 != pid);

	if (pid) return pid;

	// in child
	pid = getpid();

	seed = time(NULL);
	assert(-1 != seed);
	seed ^= pid;
	srandom((UINT_32) seed);

	if (pass & 1) {
		run_ascending(pid);
	} else {
		run_descending(pid);
	}
	exit(0); // child exit
}

void strange_fname(const char *name)
{
	Logf("%s: strange filename\n", name);
}

void remove_unfinished(const char *name)
{
	if (unlink(name)) {
		PERROR("unlink(%s)", name);
	} else {
		Logf("%s: unfinished, removed.\n", name);
	}
}

int verify_fname(const char *name, UINT_32 size, UINT_32 rnum)
{
	UINT_32 rsize, errors;
	int fd, i, c;
	fd = open(name, O_RDONLY);
	if (-1 == fd) {
		PERROR("open(%s,READ)", name);
		return -1;
	}
	rsize = 0;
	errors = 0;
	do {
		c = read(fd, (void *) Data_buffer, DATA_BUF_LEN);
		if (c < 0) {
			PERROR("read(%s)", name);
			fd = close(fd);
			assert(-1 != fd);
			return -1;
		}
		for (i = 0; i < c/sizeof(UINT_32); i++) {
			if (Data_buffer[i] != rnum) {
				++errors;
			}
		}
		rsize += c;
	} while(c > 0);
	fd = close(fd);
	assert(-1 != fd);
	if (errors == 0 && rsize == size) {
		if (unlink(name)) {
			PERROR("unlink(%s)", name);
			return -1;
		}
		return 0;
	}
	if (errors)
		Logf("%s: %u word errors\n", name, errors);
	if (rsize != size)
		Logf("%s: %u byte read, but %u expected\n",
			name, rsize, size);
	return -1;
}

int do_verify(pid_t glob_pid)
{
	static char glob[FNAME_LEN];
	int verified       = 0;
	int verify_failure = 0;
	struct dirent *dir_p;
	char unfinished, tmp;

	if (glob_pid) {
		snprintf(glob,FNAME_LEN, "%u-%%u-%%08x%%c%%c", glob_pid);
	} else {
		snprintf(glob,FNAME_LEN, "%s", "%*[0-9]-%u-%08x%c%c");
	}

	rewinddir(Data_dir);

	while ((dir_p = readdir(Data_dir)) != NULL) {
		int c, size, rnum;
		if ((strcmp(dir_p->d_name, ".") == 0) ||
		    (strcmp(dir_p->d_name, "..") == 0)) {
			continue;
		}

		unfinished = tmp = '\0';
		c = sscanf(dir_p->d_name, glob,
				&size, &rnum, &unfinished, &tmp);
		if (c == 2) {
			++verified;
			if (verify_fname(dir_p->d_name, size, rnum)) {
				++verify_failure;
			} else {
				putchar('.');
			}
			if (verified % 50 == 0) {
				printf("\t(%u/%u)\n",
					verified - verify_failure,
					verified);
			}
		} else if (c == 3) {
			if (unfinished != '+') {
				strange_fname(dir_p->d_name);
				continue;
			}
			remove_unfinished(dir_p->d_name);
			continue;
		} else {
			if (glob_pid) continue;
			strange_fname(dir_p->d_name);
			continue;
		}
	}
	printf("\t(%u/%u)\n",
		verified - verify_failure,
		verified);
	if (glob_pid) {
		/*
		fprintf(stdout, "verify \"%u-*-*\": (%u/%u) passed\n",
				glob_pid,
				verified - verify_failure,
				verified);
		*/
	} else {
		Logf("verify: (%u/%u) passed\n",
			verified - verify_failure,
			verified);
	}
	return verify_failure;
}

struct array_s {
	UINT_32 first, last, count, number;
	UINT_32 v[0];
};

struct array_s * array_new(UINT_32 number)
{
	UINT_32 bytes = sizeof(struct array_s)
		      + sizeof(UINT_32)*number;
	struct array_s *a = malloc(bytes);
	if (!a) return NULL;
	memset(a,0,bytes);
	a->number = number;
	return a;
}

void array_destroy(struct array_s *a)
{
	free(a);
}

void array_push(struct array_s *a, const UINT_32 v)
{
	assert(a->count < a->number);
	if (a->count > 0) {
		if (++a->last == a->number)
			a->last = 0;
	}
	a->v[a->last] = v;
	++a->count;
	/*
	fprintf(stderr, "=p v(%u:%u)[%u]: %u\n",
		a->first, a->last, a->count, v);
	*/
}

UINT_32 array_shift(struct array_s *a)
{
	UINT_32 v;
	assert(a->count > 0);
	v = a->v[a->first];
	if (++a->first == a->number)
		a->first = 0;
	--a->count;
	/*
	fprintf(stderr, "=s v(%u:%u)[%u]: %u\n",
		a->first, a->last, a->count, v);
	*/
	return v;
}

UINT_32 array_idx(struct array_s *a, UINT_32 i)
{
	UINT_32 v;
	assert(a->count > i);
	v = a->v[(a->first + i) % a->number];
	/*
	fprintf(stderr, "=i v(%u:%u)[%u:%u]: %u\n",
		a->first, a->last, a->count, i, v);
	*/
	return v;
}

int main(int argc, char *argv[])
{

	struct statfs s;
	struct array_s *Kids;
	UINT_32 blocks_per_pass, tmp, pass, kids = 0;

	parse_options(argc,argv);

	if (!Dont_verify) {
		printf( "Data_path: %s\nLogfile:   %s\n"
			"Beginning global verify stage.\n",
			Data_path, Log_fname );
		if (do_verify(0)) {
			printf("Verify failed; program exiting.\n");
			exit(1);
		}
		if (Verify_only) {
			printf("Verify completed successfully.\n");
			printf("Nothing else to do (-V).\n");
			fclose(Log_fp);
			exit(0);
		}
		printf("Verify completed successfully; program continuing.\n");
	} else {
		printf("Skip initial verify step (-v).\n");
	}

	if (fstatfs(dirfd(Data_dir),&s)) {
		perror("statfs");
		return 1;
	}

	/* estimate recycle count */
	blocks_per_pass = ( ((Max_size<<1) -1) + (Min_size-1) ) / s.f_bsize;
	tmp = (s.f_bavail>>1) / blocks_per_pass +1;
	if (tmp > MAX_RECYCLE) tmp = MAX_RECYCLE;
	if (Recycle > tmp) Recycle = tmp;
	Recycle = MAX(Recycle,Max_conc+1);

	Logf("Using I/O Min: %u, Max: %u, %u passes, "
	     "with %u procs running\n"
	     "Recycling starts with the %u. pass\n"
	     "Data_path: %s\n"
	     "Logfile:   %s\n",
	     Min_size, Max_size, Pass_cnt, Max_conc,
	     Recycle, Data_path, Log_fname);

	Kids = array_new(Recycle+10);
	if (!Kids) {
		Logf("array_new(%u): out of memory\n", Recycle);
		exit(1);
	}

	// now launch new I/O
	for (pass = 0; (pass < Pass_cnt) || (0 == Pass_cnt); pass++) {
		if (Kids->count >= Recycle) {
			do_verify(array_shift(Kids));
		}
		array_push(Kids, spawn(pass) );
		if (++kids >= Max_conc) {
			if ( wait_for_kid(array_idx(Kids,Kids->count - kids)) )
				exit(1);
			--kids;
		}
	}

	/* we have finished the number of passes we wanted to originate.  Wait
	 * for the rest of the kids before leaving
	 */
	while (kids--) {
	       if (wait_for_kid(-1)) exit(1);
	}

	fclose(Log_fp);
	closedir(Data_dir);
	array_destroy(Kids);

	exit(0);
}
