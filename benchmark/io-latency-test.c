/*
   io-latency-test.c

   By Philipp Reisner.

   Copyright (C) 2006, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

   io-latency-test is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   io-latency-test is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with dm; see the file COPYING.  If not, write to
   the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

 */

/* In case this crashes (in your UML)
   touch /etc/ld.so.nohwcap
 */

// compile with gcc -pthread -o io-latency-test io-latency-test.c

#include <sys/poll.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <getopt.h>

#define MONITOR_TIME 300000
// Check every 300 milliseconds. (3.33 times per second)

#define RECORD_TIME 20000
// Try to write a record every 20 milliseconds (50 per second)

unsigned int monitor_time=MONITOR_TIME;
unsigned int record_time=RECORD_TIME;
unsigned long records=0;

struct shared_data {
	pthread_mutex_t mutex;
	unsigned long record_nr;
	unsigned int write_duration_us;
	unsigned int write_duration_records;
	double avg_write_duration;
};

void* wd_thread(void *arg)
{
	struct shared_data *data = (struct shared_data*) arg;
	unsigned long last_record_nr=-1, current_record_nr=0;
	unsigned int avg_write,wd,wr;
	double avg_write_duration;

	enum { IO_RUNNING, IO_BLOCKED } io_state = IO_RUNNING;
	
	while(1) {
		usleep(monitor_time); // sleep some milliseconds

		pthread_mutex_lock(&data->mutex);
		current_record_nr = data->record_nr;
		wd = data->write_duration_us;
		wr = data->write_duration_records;
		data->write_duration_us = 0;
		data->write_duration_records = 0;
		avg_write_duration = data->avg_write_duration;
		pthread_mutex_unlock(&data->mutex);

		if( records && current_record_nr == records) break;

		switch(io_state) {
		case IO_RUNNING:
			if(current_record_nr == last_record_nr) {
				printf("IO got frozen. Last completely "
				       "written record: %lu"
				       "                        \n",
				       last_record_nr);
				io_state = IO_BLOCKED;
			} else {
				if(wr==0) wr=1;
				avg_write = wd/wr;

				printf("Current record: %lu "
				       "( cur. write duration %d.%02dms; "
				       "avg. wd. %.2fms)\r",
				       current_record_nr,
				       avg_write/1000,(avg_write%1000)/10,
				       avg_write_duration/1000);
				fflush(stdout);
			}
			last_record_nr = current_record_nr;
		case IO_BLOCKED:
			if(current_record_nr != last_record_nr) {
				printf("IO just resumed.\n");
				io_state = IO_RUNNING;
			}
		}
	}
	if(io_state == IO_RUNNING) printf("\n");
}

void usage(char *prgname)
{
	fprintf(stderr, "USAGE: %s [options] recordfile\n"
		"  Available options:\n"
		"   --records val         -n val\n"
		"   --record-interval-ms  -r val\n"
		"   --monitor-interval-ms -m val\n",
		prgname);
	exit(20);
}

int main(int argc, char** argv)
{
	pthread_t watch_dog;
	unsigned long record_nr=0;
	FILE* record_f;

	struct timeval now_tv, then_tv;
	struct tm now_tm;
	int write_duration_us=0;
	int min_wd=(1<<30), max_wd=0;
	double avg_write_duration;
	int avg_wd_nr=0,c;

	struct shared_data data;

	static struct option options[] = {
		{"records", required_argument, 0, 'n'},
		{"record-interval-ms", required_argument, 0, 'r'},
		{"monitor-interval-ms", required_argument, 0, 'm'},
		{0, 0, 0, 0 }
	};

	while (1) {
		c = getopt_long(argc, argv, "n:r:m:", options, 0);
		if (c == -1)
			break;
		switch (c) {
		case 'n':
			records = atol(optarg);
			break;
		case 'r':
			record_time = atoi(optarg) * 1000;
			break;
		case 'm':
			monitor_time = atoi(optarg) * 1000;
			break;
		default:
			usage(argv[0]);
		}
	}

	if(optind != argc-1) {
		usage(argv[0]);
	}

	if(!(record_f = fopen(argv[optind],"w"))) {
		perror("fopen:");
		fprintf(stderr,"Failed to open '%s' for writing\n",
			argv[optind]);
		return 10;
	}

	printf("\n"
	       "This programm writes records to a file, shows the write latency\n"
	       "of the file system and block device combination and informs\n"
	       "you in case IO completely stalls.\n\n"
	       "  Due to the nature of the 'D' process state on Linux\n"
	       "  (and other Unix operating systems) you can not kill this\n"
	       "  test programm while IO is frozen. You have to kill it with\n"
	       "  Ctrl-C (SIGINT) while IO is running.\n\n"
	       "In case the record file's block device freezes, this "
	       "program will\n"
	       "inform you here which record was completely written before it "
	       "freezed.\n\n"
	       );

	pthread_mutex_init(&data.mutex,NULL);
	data.record_nr = record_nr;
	data.write_duration_us = 0;
	data.write_duration_records = 1;
	pthread_create(&watch_dog,NULL,wd_thread,&data);

	for( ; !records || record_nr < records ; record_nr++) {
		gettimeofday(&now_tv, NULL);
		localtime_r(&now_tv.tv_sec,&now_tm);

		fprintf(record_f,
			"%04d-%02d-%02d %02d:%02d:%02d.%06ld: "
			"Record number: %-6lu "
			"(L.r.w.t.: %d.%02dms)\n",
			1900+ now_tm.tm_year,
			1+ now_tm.tm_mon,
			now_tm.tm_mday,
			now_tm.tm_hour,
			now_tm.tm_min,
			now_tm.tm_sec,
			now_tv.tv_usec,
			record_nr,
			write_duration_us/1000,
			(write_duration_us%1000)/10);
		
		if(fflush(record_f)) { // flush it from glibc to the kernel.
			perror("fflush:");
			return 10;
		}
		if(fdatasync(fileno(record_f))) { // from buffer cache to disk.
			perror("fdatasync:");
			return 10;
		}
		// eventually wait for full record_time
		gettimeofday(&then_tv, NULL);
		write_duration_us =
			( (then_tv.tv_sec  - now_tv.tv_sec ) * 1000000 +
			  (then_tv.tv_usec - now_tv.tv_usec) );

		if(write_duration_us < monitor_time) {
			if(write_duration_us < min_wd) min_wd = write_duration_us;
			if(write_duration_us > max_wd) max_wd = write_duration_us;

			avg_write_duration = 
				(avg_write_duration * avg_wd_nr + 
				 write_duration_us) / (++avg_wd_nr);
		}

		pthread_mutex_lock(&data.mutex);
		data.record_nr = record_nr;
		data.write_duration_us += write_duration_us;
		data.write_duration_records++;
		data.avg_write_duration = avg_write_duration;
		pthread_mutex_unlock(&data.mutex);

		if(write_duration_us < record_time ) {
			usleep(record_time - write_duration_us);
		}
	}

	pthread_mutex_lock(&data.mutex);
	data.record_nr = record_nr;
	pthread_mutex_unlock(&data.mutex);

	pthread_join(watch_dog,NULL);

	printf( "STATS:\n"
		"  Records written: %lu\n"
		"  Average write duration: %.2fms\n"
		"  Longest write duration (<%dms): %.2fms\n"
		"  Shortest write duration: %.2fms\n",
		records,
		avg_write_duration/1000,
		monitor_time/1000,(double)max_wd/1000,
		(double)min_wd/1000);
}
