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
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <assert.h>
#include <time.h>

#define WBTEST_VERSION "1.0"

typedef unsigned int UINT_32;


#define MEM_SCRATCH_LEN 128
#define DATA_BUF_LEN 8096

#define WAIT_ON_SINGLE_CHILD 1
#define WAIT_ON_ALL_CHILDREN 2

#define DEFAULT_MAX_CONCURRENT 25
#define DEFAULT_PASS_COUNT 100

#define MIN(x,y) (((x) < (y)) ? (x) : (y))

/* The range of file sizes in bytes we will write
 */
static UINT_32 Min_io_sz = 4;
static UINT_32 Max_io_sz = 102400;

/* Checkpoint file descriptor and pointer 
 */
static int Ckpt_fd = 0;
static FILE *Ckpt_fp = NULL;

static char *Mem_scratch_p = NULL;
static char *Mem_scratch2_p = NULL;
static UINT_32 *Data_p = NULL;

#define FLAG_NO_VERIFY 0x00000001
#define FLAG_VERIFY_ONLY 0x00000002
static UINT_32 Flags = 0;

/* Directory required to hold checkpoint files.  This dir should be 
 * on a disk w/write cache and write barrier disabled.
 */
static char *Checkpoint_path = NULL;
/* Directory required to hold data files.  This dir should be 
 * on a disk w/write cache and write barrier enabled.
 */
static char *Data_path = NULL;
/* Failed verifies (data filenames that don't match the checkpoint file)
 * are logged here.
 */
static char *Verify_fail_logf = NULL;


UINT_32 initial_setup_child(const pid_t pid)
{
	char *mem_p = NULL;
	time_t seed;

	Mem_scratch_p = (char *) malloc((size_t) MEM_SCRATCH_LEN);
	if (NULL == Mem_scratch_p) {
		fprintf(stderr, "can't alloc mem scratch\n");
		return 1;
	}
	mem_p = Mem_scratch_p;

	sprintf(mem_p, "%s/%08u.chk", Checkpoint_path, pid);

	Ckpt_fd =
	    open(mem_p, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (-1 == Ckpt_fd) {
		fprintf(stderr,
			"can't open fd for checkpoint file errno=%i\n",
			errno);
		return 1;
	}

	Ckpt_fp = fdopen(Ckpt_fd, "w");
	if (NULL == Ckpt_fp) {
		fprintf(stderr,
			"can't open fp for checkpoint file errno=%i\n",
			errno);
		return 1;
	}


	Data_p = (UINT_32 *) malloc((size_t) DATA_BUF_LEN);
	if (NULL == Data_p) {
		fprintf(stderr, "can't alloc data mem\n");
		return 1;
	}

	seed = time(NULL);
	assert(-1 != seed);
	seed ^= pid;
	srandom((UINT_32) seed);

	return 0;
}

void cleanup_mem(void)
{
	if (NULL != Mem_scratch_p) {
		free((void *) Mem_scratch_p);
		Mem_scratch_p = NULL;
	}
	if (NULL != Mem_scratch2_p) {
		free((void *) Mem_scratch2_p);
		Mem_scratch2_p = NULL;
	}
	if (NULL != Data_p) {
		free((void *) Data_p);
		Data_p = NULL;
	}
}

UINT_32 initial_setup_parent(void)
{
	Mem_scratch_p = (char *) malloc((size_t) MEM_SCRATCH_LEN);
	if (NULL == Mem_scratch_p) {
		fprintf(stderr, "can't alloc mem scratch\n");
		return 1;
	}

	Mem_scratch2_p = (char *) malloc((size_t) MEM_SCRATCH_LEN);
	if (NULL == Mem_scratch2_p) {
		fprintf(stderr, "can't alloc mem scratch2\n");
		return 1;
	}

	Data_p = (UINT_32 *) malloc((size_t) DATA_BUF_LEN);
	if (NULL == Data_p) {
		fprintf(stderr, "can't alloc data mem\n");
		return 1;
	}

	return 0;
}

int wait_for_kids(UINT_32 * kids, int single)
{
	int err = 0;

	while (*kids) {
		pid_t reaped_pid;
		int status;

		reaped_pid = wait(&status);

		if (WIFEXITED(status)) {
			(*kids)--;
			if (WEXITSTATUS(status)) {
				fprintf(stderr,
					"child %u exited with status %u (%u remain)\n",
					reaped_pid, WEXITSTATUS(status),
					*kids);
				// don't error here, we want to keep going
			}
			if (WAIT_ON_SINGLE_CHILD == single) {
				break;
			}
		} else if (0 > reaped_pid) {
			fprintf(stderr,
				"wait exited with error; quitting\n");
			err = 1;
			break;
		}
	}

	return err;
}

/* Function responsible for recording the contents and size of each file
 * written to the WSC/WB enabled FS
 */
UINT_32 record_file(const size_t size, const UINT_32 rNum)
{

	fprintf(Ckpt_fp, "%08u:%08X\n", size, rNum);

	if (0 != fflush(Ckpt_fp)) {
		fprintf(stderr, "fflush error: errno=%i\n", errno);
	}

	if (0 != fsync(Ckpt_fd)) {
		fprintf(stderr, "fsync error: errno=%i\n", errno);
	}

	return 0;
}

void log_verify_failure(char *file_path_p)
{
	static FILE *fp = NULL;
	int err;

	if (NULL == file_path_p) {
		if (NULL != fp) {
			err = fclose(fp);
			assert(EOF != err);
			fp = NULL;
		}
	} else {
		if (NULL == fp) {
			/* not open yet, open it */
			if (Verify_fail_logf) {
				fp = fopen(Verify_fail_logf, "a");
			} else {
				int fd = 0;
				fd = mkstemp("/tmp/wbtest-vLog-XXXXXXX");
				assert(-1 != fd);
				fp = fdopen(fd, "a");
			}
			assert(NULL != fp);
		}
		fprintf(fp, "%s\n", file_path_p);
	}
}

void fill(const UINT_32 * loc_p, const UINT_32 word,
	  const size_t num_bytes)
{
	UINT_32 ctr;
	UINT_32 *d_p = (UINT_32 *) loc_p;

	for (ctr = 0; ctr < num_bytes; ctr += 4) {
		*d_p++ = word;
	}

	return;
}

int write_file(const pid_t pid, size_t size)
{
	int fd;
	ssize_t wrote;
	char *mem_p = Mem_scratch_p;
	UINT_32 *d_p = Data_p;
	UINT_32 rnum = (UINT_32) random();
	size_t size_sv = size;
	DIR *dp;

	dp = opendir(Checkpoint_path);
	if (NULL == dp) {
		fprintf(stderr, "opendir failed\n");
		return 1;
	}

	sprintf(mem_p, "%s/%u-%u-%08X", Data_path, pid, size, rnum);

	fill(d_p, rnum, MIN(size, DATA_BUF_LEN));

	fd = open(mem_p, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
	if (-1 == fd) {
		fprintf(stderr, "can't open fd for data file errno=%i\n",
			errno);
		return 1;
	}

	while (DATA_BUF_LEN < size) {
		wrote = write(fd, (const void *) d_p, DATA_BUF_LEN);
		if (wrote != DATA_BUF_LEN) {
			fprintf(stderr,
				"D write error (wrote %i/%u): errno=%i\n",
				wrote, DATA_BUF_LEN, errno);
		}
		size -= DATA_BUF_LEN;
	}

	if (size) {
		wrote = write(fd, (const void *) d_p, size);
		if (wrote != size) {
			fprintf(stderr,
				"D write error (wrote %i/%u): errno=%i\n",
				wrote, size, errno);
		}
	}

	if (0 != fsync(fd)) {
		fprintf(stderr, "D fsync error: errno=%i\n", errno);
	}

	fd = close(fd);
	assert(-1 != fd);

	fsync(dirfd(dp));
	closedir(dp);

	record_file(size_sv, rnum);

	return 0;
}

int verify_data(const UINT_32 * loc_p,
		const size_t num_bytes, const UINT_32 word)
{
	UINT_32 ctr;
	UINT_32 *d_p = (UINT_32 *) loc_p;
	int mismatches = 0;

	for (ctr = 0; ctr < num_bytes; ctr += 4) {
		if (word != *d_p++) {
			mismatches++;
		}
	}

	return mismatches;
}

int read_file(pid_t pid, size_t size, UINT_32 rnum)
{
	char *mem_p = Mem_scratch2_p;
	UINT_32 *d_p = Data_p;
	int fd;
	ssize_t reads;
	int mismatches = 0;
	int err = 0;

	sprintf(mem_p, "%s/%u-%u-%08X", Data_path, pid, size, rnum);
	fd = open(mem_p, O_RDONLY);
	if (-1 == fd) {
		fprintf(stderr,
			"can't open fd %s for read data: errno=%i\n",
			mem_p, errno);
		return 1;
	}

	while (DATA_BUF_LEN < size) {
		reads = read(fd, (void *) d_p, DATA_BUF_LEN);
		assert(DATA_BUF_LEN == reads);

		mismatches += verify_data(d_p, DATA_BUF_LEN, rnum);

		size -= DATA_BUF_LEN;
	}

	if (size) {
		reads = read(fd, (void *) d_p, size);
		assert(size == reads);

		mismatches += verify_data(d_p, size, rnum);
	}

	fd = close(fd);
	assert(-1 != fd);

	if (0 < mismatches) {
		printf("FAILED verify of %s: %i word mismatches\n", mem_p,
		       mismatches);
		err = 1;
		log_verify_failure(mem_p);
	} else {
		fd = unlink(mem_p);
		assert(-1 != fd);
	}

	return err;
}

int parse_chkfile(char *filepath_p, pid_t pid)
{
	UINT_32 count_ttl = 0, count_err = 0;
	int err = 0;
	char buf[32];
	FILE *fp = fopen(filepath_p, "r");
	int j;

	if (NULL == fp) {
		fprintf(stderr,
			"fopen ret err in parse_chkfile, errno=%i\n",
			errno);
		return 1;
	}

	while (fgets(buf, 32, fp) != NULL) {
		char *tok_p;
		size_t nl_pos = strlen(buf) - 1;
		size_t iosz;
		UINT_32 rnum;

		// chomp:
		if (buf[nl_pos] == '\n') {
			buf[nl_pos] = '\0';
		}

		iosz = strtoul(buf, &tok_p, 10);
		assert(NULL != tok_p);

		/* Advance past the colon */
		/* assert(':' == *tok_p); */
		if (':' != *tok_p) {
			/* OK, I've seen this case where the checkfile will end with 
			 * a bunch of NUL bytes and the line read in will not have
			 * the correct format (will be all 0's).  This seems like a
			 * FS quirk so in the interest of assuring all the data is OK 
			 * on the write barrier/write cache partition I will log the 
			 * quirk and move on.
			 */
			log_verify_failure(filepath_p);
			continue;
		}
		++tok_p;

		rnum = (UINT_32) strtoul(tok_p, NULL, 16);

		++count_ttl;

		if (read_file(pid, iosz, rnum)) {
			err = 1;
			++count_err;
		}
	}

	printf("Processed checkfile %s: %u/%u passed\n",
	       filepath_p, (count_ttl - count_err), count_ttl);

	j = fclose(fp);
	assert(EOF != j);

	j = unlink(filepath_p);
	assert(-1 != j);

	return err;
}

int parse_dir(void)
{
	int err = 0;
	char *tmp_p = Mem_scratch_p;
	DIR *dp;
	struct dirent *dir_p;
	pid_t pid;

	dp = opendir(Checkpoint_path);
	if (NULL == dp) {
		fprintf(stderr, "opendir failed\n");
		return 1;
	}

	while ((dir_p = readdir(dp)) != NULL) {
		if ((strcmp(dir_p->d_name, ".") == 0) ||
		    (strcmp(dir_p->d_name, "..") == 0)) {
			continue;
		}

		pid = strtoul(dir_p->d_name, NULL, 10);

		sprintf(tmp_p, "%s/%s", Checkpoint_path, dir_p->d_name);

		if (parse_chkfile(tmp_p, pid)) {
			err = 1;
		}
		fsync(dirfd(dp));
	}

	return err;
}

/* This function starts with a small file size and increases
 */
void run_ascending(const pid_t pid)
{
	UINT_32 size;

	for (size = Min_io_sz; size < Max_io_sz; size *= 2) {
		size &= ~3;
		if (write_file(pid, size)) {
			fprintf(stderr, "ending ascending run\n");
			break;
		}
	}
}

/* This function starts with a large file size and decreases
 */
void run_descending(const pid_t pid)
{
	size_t size;

	for (size = Max_io_sz; size > Min_io_sz; size /= 2) {
		size &= ~3;
		if (write_file(pid, size)) {
			fprintf(stderr, "ending descending run\n");
			break;
		}
	}
}

void usage(char *prog)
{
	printf("Usage: %s [-hvVs] [-m <min>] [-M <max>] [-p <passes>]\n"
	       "[-c <concurrent>] [-l <vLog>] -s <safedir> -t <testdir>\n"
	       "\n%s - Version %s Options:\n"
	       "\t-h prints this usage text\n"
	       "\t-v forces NO verification step of existing files (if any)\n"
	       "\t-V forces exit after verification step of existing files\n"
	       "\t<min> == minimum IO size to use (bytes)\n"
	       "\t<max> == maximum IO size to use (bytes)\n"
	       "\t<passes> == # of passes to run (0 for INF)\n"
	       "\t<concurrent> == # of processes to run at once\n"
	       "\t<vLog> == log all file verify failures here, otherwise mkstemp\n"
	       "\t<safedir> == writable DIRECTORY to store 'checkpoint' files\n"
	       "\t<testdir> == writable DIRECTORY to store 'test data' files\n"
	       "\n"
	       "\tDifference between safedir and testdir is that safedir should \n"
	       "\tbe 'safe' storage meaning that it is not using drive write \n"
	       "\tcache, whereas testdir is intended to be using drive write \n"
	       "\tcache and the write barrier. Naturally, the two should be on \n"
	       "\tseparate drives\n", prog, prog, WBTEST_VERSION);
}

void exit_safe(int ret_code)
{
	cleanup_mem();
	exit(ret_code);
}

int main(int argc, char *argv[])
{
	int c;
	pid_t pid = 1;
	UINT_32 pass, pass_cnt = DEFAULT_PASS_COUNT;
	UINT_32 max_conc = DEFAULT_MAX_CONCURRENT;
	UINT_32 kids = 0;

	while ((c = getopt(argc, argv, "c:hl:m:M:p:s:t:vV")) != -1) {
		UINT_32 scr;

		switch (c) {
		case 's':
			/* "safe" path -- non-cached dir to store checkpoint files
			 */
			Checkpoint_path = optarg;
			break;
		case 't':
			/* "test" path -- cached/barrier protected dir to store test data
			 * files
			 */
			Data_path = optarg;
			break;
		case 'l':
			/* where to store the verify "log" showing found problems
			 */
			Verify_fail_logf = optarg;
			break;
		case 'm':
			scr = ((UINT_32) atoi(optarg)) & ~3;
			Min_io_sz = scr;
			break;
		case 'M':
			scr = ((UINT_32) atoi(optarg)) & ~3;
			Max_io_sz = scr;
			break;
		case 'p':
			scr = ((UINT_32) atoi(optarg));
			pass_cnt = scr;
			break;
		case 'c':
			scr = ((UINT_32) atoi(optarg));
			max_conc = scr;
			break;
		case 'v':
			Flags |= FLAG_NO_VERIFY;
			break;
		case 'V':
			Flags |= FLAG_VERIFY_ONLY;
			break;
		case 'h':
		case '?':
		default:
			usage(argv[0]);
			exit_safe(1);
		}
	}

	if (!Checkpoint_path || !Data_path) {
		fprintf(stderr,
			"Missing -s or -t arguments, both required\n");
		usage(argv[0]);
		exit_safe(1);
	}
	// first, verify what's there using the checkpoint files
	if (!(Flags & FLAG_NO_VERIFY)) {
		printf("Beginning verify stage\n");
		if (initial_setup_parent()) {
			exit_safe(1);
		}
		if (parse_dir()) {
			printf("Verify failed; program exiting.\n");
			exit_safe(1);
		} else {
			printf
			    ("Verify completed successfully; program continuing.\n");
		}

		log_verify_failure(NULL);	/* close out the failure log if opened */
		cleanup_mem();	/* free used mem from parent */

		if (Flags & FLAG_VERIFY_ONLY) {
			printf("Performing verify step ONLY as desired\n");
			exit_safe(0);
		}
	} else {
		printf("skipping verify step as desired\n");
	}

	printf
	    ("Using I/O Min: %u, Max: %u, %u passes with %u procs running\n",
	     Min_io_sz, Max_io_sz, pass_cnt, max_conc);

	// now launch new I/O
	for (pass = 0; (pass < pass_cnt) || (0 == pass_cnt); pass++) {
		fflush(0);
		pid = fork();
		assert(-1 != pid);

		if (0 == pid) {
			// child
			pid_t new_pid = getpid();

			if (0 != initial_setup_child(new_pid)) {
				exit_safe(1);
			}

			if (new_pid % 2) {
				run_ascending(new_pid);
			} else {
				run_descending(new_pid);
			}
			exit_safe(0); // child exit
		} else {
			if (++kids < max_conc) {
				continue;
			} else {
				if (wait_for_kids
				    (&kids, WAIT_ON_SINGLE_CHILD)) {
					exit_safe(1);
				}
			}
		}

	}			// end pass loop

	/* we have finished the number of passes we wanted to originate.  Wait
	 * for the rest of the kids before leaving
	 */
	if ((pid > 0) && wait_for_kids(&kids, WAIT_ON_ALL_CHILDREN)) {
		exit_safe(1);
	}

	exit_safe(0);
	return 0;
}
