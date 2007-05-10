/*
   dm.c

   Copright 2001-2007 LINBIT Information Technologies
   Philipp Reisner, Lars Ellenberg

   dm is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   dm is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with dm; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#define min(a,b) ( (a) < (b) ? (a) : (b) )

unsigned long long fsize(int in_fd)
{
	struct stat dm_stat;
	unsigned long long size;

	if (fstat(in_fd, &dm_stat)) {
		fprintf(stderr, "Can not fstat\n");
		exit(20);
	}
	if (S_ISBLK(dm_stat.st_mode)) {
		unsigned long ls;
		if (ioctl(in_fd, BLKGETSIZE, &ls)) {
			fprintf(stderr, "Can not ioctl(BLKGETSIZE)\n");
			exit(20);
		}
		size = ((unsigned long long)ls) * 512;
	} else if (S_ISREG(dm_stat.st_mode)) {
		size = dm_stat.st_size;
	} else
		size = -1;

	return size;
}

unsigned long long m_strtol(const char *s)
{
	char *e = (char *)s;
	unsigned long long r;

	r = strtol(s, &e, 0);
	switch (*e) {
	case 0:
		return r;
	case 's':
	case 'S':
		return r << 9; // * 512;
	case 'K':
	case 'k':
		return r << 10; // * 1024;
	case 'M':
	case 'm':
		return r << 20; // * 1024 * 1024;
	case 'G':
	case 'g':
		return r << 30; // * 1024 * 1024 * 1024;
	default:
		fprintf(stderr, "%s is not a valid number\n", s);
		exit(20);
	}
}

void usage(char *prgname)
{
	fprintf(stderr, "USAGE: %s [options] \n"
		"  Available options:\n"
		"   --input-pattern val -a val \n"
		"   --input-file val    -i val \n"
		"   --output-file val   -o val\n"
		"   --buffer-size val   -b val\n"
		"   --seek-input val    -k val\n"
		"   --seek-output val   -l val\n"
		"   --size val          -s val\n"
		"   --o_direct          -x\n"
		"     should be given first to affect\n"
	        "     -i/-o given later on the command line\n"
		"   --bandwidth         -w val byte/second \n"
		"   --sync              -y\n"
		"   --progress          -m\n"
		"   --performance       -p\n"
		"   --dialog            -d\n"
		"   --help              -h\n", prgname);
	exit(20);

}

int main(int argc, char **argv)
{
	void *buffer;
	size_t rr, ww;
	unsigned long long seek_offs_i = 0;
	unsigned long long seek_offs_o = 0;
	unsigned long long size = -1, rsize;
	int in_fd = 0, out_fd = 1;
	unsigned long buffer_size = 65536;
	unsigned long long target_bw = 0;
	int o_direct = 0;
	int do_sync = 0;
	int show_progress = 0;
	int show_performance = 0;
	struct timeval tv1, tv2;
	int use_pattern = 0;
	int pattern;
	int dialog = 0, show_input_size = 0;
	int last_percentage = 0;

	int c;
	static struct option options[] = {
		{"input-pattern", required_argument, 0, 'a'},
		{"input-file", required_argument, 0, 'i'},
		{"output-file", required_argument, 0, 'o'},
		{"buffer-size", required_argument, 0, 'b'},
		{"seek-input", required_argument, 0, 'k'},
		{"seek-output", required_argument, 0, 'l'},
		{"size", required_argument, 0, 's'},
		{"o_direct", no_argument, 0, 'x'},
		{"bandwidth", required_argument, 0, 'w'},
		{"sync", no_argument, 0, 'y'},
		{"progress", no_argument, 0, 'm'},
		{"performance", no_argument, 0, 'p'},
		{"dialog", no_argument, 0, 'd'},
		{"help", no_argument, 0, 'h'},
		{"show-input-size", no_argument, 0, 'z'},
		{0, 0, 0, 0}
	};

	if (argc == 1)
		usage(argv[0]);

	while (1) {
		c = getopt_long(argc, argv, "i:o:b:k:l:s:w:xympha:dz", options, 0);
		if (c == -1)
			break;
		switch (c) {
		case 'i':
			/* make sure you specify -x before -i,
			 * if you mean to use O_DIRECT here! */
			in_fd = open(optarg, O_RDONLY | (o_direct ? O_DIRECT : 0));
			if (in_fd == -1) {
				fprintf(stderr,
					"Can not open input file/device\n");
				exit(20);
			}
			break;
		case 'o':
			out_fd =
			    open(optarg, O_WRONLY | O_CREAT | O_TRUNC |
					 (o_direct? O_DIRECT : 0) , 0664);
			if (out_fd == -1) {
				fprintf(stderr,
					"Can not open output file/device\n");
				exit(20);
			}
			break;
		case 'b':
			buffer_size = m_strtol(optarg);
			break;
		case 'k':
			seek_offs_i = m_strtol(optarg);
			break;
		case 'l':
			seek_offs_o = m_strtol(optarg);
			break;
		case 's':
			size = m_strtol(optarg);
			break;
		case 'x':
			o_direct = 1;
			break;
		case 'y':
			do_sync = 1;
			break;
		case 'm':
			show_progress = 1;
			break;
		case 'p':
			show_performance = 1;
			break;
		case 'h':
			usage(argv[0]);
			break;
		case 'a':
			use_pattern = 1;
			pattern = m_strtol(optarg);
			break;
		case 'd':
			dialog = 1;
			break;
		case 'z':
			show_input_size = 1;
			break;
		case 'w':
			target_bw = m_strtol(optarg);
			break;

		}
	}

	(void)posix_memalign(&buffer, sysconf(_SC_PAGESIZE), buffer_size);
	if (!buffer) {
		fprintf(stderr, "Can not allocate the Buffer memory\n");
		exit(20);
	}

	if (seek_offs_i) {
		if (lseek(in_fd, seek_offs_i, SEEK_SET) == -1) {
			fprintf(stderr,
				"Can not lseek(2) in input file/device\n");
			exit(20);
		}
	}

	if (seek_offs_o) {
		if (lseek(out_fd, seek_offs_o, SEEK_SET) == -1) {
			fprintf(stderr,
				"Can not lseek(2) in output file/device\n");
			exit(20);
		}
	}

	if (use_pattern) {
		memset(buffer, pattern, buffer_size);
	}

	if (dialog && size == -1) {
		size = min(fsize(in_fd), fsize(out_fd));
		if (size == -1) {
			fprintf(stderr, "Can not determine the size\n");
			exit(20);
		}
		if (size == 0) {
			fprintf(stderr, "Nothing to do?\n");
			exit(20);
		}
	}

	if (show_input_size) {
		size = fsize(in_fd);
		if (size == -1) {
			fprintf(stderr, "Can not determine the size\n");
			exit(20);
		}
		printf("%lldK\n", size / 1024);
		exit(0);
	}

	rsize = size;
	gettimeofday(&tv1, NULL);
	while (1) {
		if (use_pattern)
			rr = min(buffer_size, rsize);
		else
			rr = read(in_fd, buffer,
				  (size_t) min(buffer_size, rsize));

		if (rr == 0)
			break;
		if (rr == -1) {
			if (errno == EINVAL && o_direct) {
				fprintf(stderr,
				"either leave off --o_direct,"
				" or fix the alignment of the buffer/size/offset!\n");
			}
			perror("Read failed");
			break;
		}

		if (show_progress) {
			printf(rr == buffer_size ? "R" : "r");
			fflush(stdout);
		}

		ww = write(out_fd, buffer, rr);
		if (ww == -1) {
			if (errno == EINVAL && o_direct) {
				fprintf(stderr,
				"either leave off --o_direct,"
				" or fix the alignment of the buffer/size/offset!\n");
			}
			perror("Write failed");
			break;
		}
		rsize = rsize - ww;
		if (dialog) {
			int new_percentage =
			    (int)(100.0 * (size - rsize) / size);
			if (new_percentage != last_percentage) {
				printf("\r%3d", new_percentage);
				fflush(stdout);
				last_percentage = new_percentage;
			}
		}

		if (target_bw) {
			gettimeofday(&tv2, NULL);

			long sec = tv2.tv_sec - tv1.tv_sec;
			long usec = tv2.tv_usec - tv1.tv_usec;
			double bps;
			double time_should;
			int time_wait;

			if (usec < 0) {
				sec--;
				usec += 1000000;
			}

			bps = ((double)(size - rsize)) /
				(sec + ((double)usec) / 1000000);

			if ( bps > target_bw ) {
				time_should = ((double)(size - rsize)) *
					1000 / target_bw; // mili seconds.

				time_wait = (int)
					(time_should - 
					 (sec*1000 + ((double)usec) / 1000));
				poll(NULL,0,time_wait);
			}
		}

		if (ww != rr)
			break;
	}

	if (do_sync)
		fsync(out_fd);

	gettimeofday(&tv2, NULL);

	if (show_progress || dialog)
		printf("\n");

	if (show_performance) {
		long sec = tv2.tv_sec - tv1.tv_sec;
		long usec = tv2.tv_usec - tv1.tv_usec;
		double mps;

		if (usec < 0) {
			sec--;
			usec += 1000000;
		}

		mps = (((double)(size - rsize)) / (1 << 20)) /
		    (sec + ((double)usec) / 1000000);

		printf("%.2f MB/sec (%llu B / ", mps, size - rsize);
		printf("%02ld:%02ld.%06ld)\n", sec / 60, sec % 60, usec);
	}

	if (size != -1 && rsize)
		fprintf(stderr, "Could transfer only %lld Byte.\n",
			(size - rsize));

	return 0;
}
