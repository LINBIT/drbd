/*
   drbdadm_usage_cnt.c

   This file is part of drbd by Philipp Reisner.

   Copyright (C) 2006, Philipp Reisner <philipp.reisner@linbit.com>.
        Initial author.

   Copyright (C) 2006, Lars Ellenberg <l.g.e@web.de>
        contributions.

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "drbdadm.h"
#include "drbdtool_common.h"
#include "drbd_endian.h"
#include "linux/drbd.h"		/* only use DRBD_MAGIC from here! */

#define HTTP_PORT 80
#define HTTP_HOST "usage.drbd.org"
#define HTTP_ADDR "212.69.162.23"
#define DRBD_LIB_DIR "/var/lib/drbd"
#define NODE_ID_FILE DRBD_LIB_DIR"/node_id"

struct node_info {
	u64	node_uuid;
	u32	version_code;
};

struct node_info_od {
	u32 magic;
	struct node_info ni;
} __attribute((packed));

/* For our purpose (finding the revision) SLURP_SIZE is always enough.
 */
static char* slurp_proc_drbd()
{
	const int SLURP_SIZE = 4096;
	char* buffer;
	int rr, fd;

	fd = open("/proc/drbd",O_RDONLY);
	if( fd == -1) return 0;
	
	buffer = malloc(SLURP_SIZE);
	if(!buffer) return 0;

	rr = read(fd, buffer, SLURP_SIZE-1);
	if( rr == -1) {
		free(buffer);
		return 0;
	}
	
	buffer[rr]=0;
	close(fd);

	return buffer;
}

static unsigned int extract_svn_revision(const char* text)
{
	char token[40];
	unsigned int svn_rev = 0;
	int plus=0;
	enum { begin,f_svn,f_rev } ex=begin;

	while(sget_token(token,40,&text) != EOF) {
		switch(ex) {
		case begin: 
			if(!strcmp(token,"plus")) plus = 1;
			if(!strcmp(token,"SVN"))  ex = f_svn;
			break;
		case f_svn:
			if(!strcmp(token,"Revision:"))  ex = f_rev;
			break;
		case f_rev:
			svn_rev = atol(token); 
			goto out;
		}
	}
 out:
	svn_rev = svn_rev * 10;
	if( svn_rev && plus ) svn_rev += 1;
	return svn_rev;
}

static unsigned int current_svn_revision()
{
	char* version_txt;
	unsigned int svn_rev;

	version_txt = slurp_proc_drbd();
	if(version_txt) {
		svn_rev = extract_svn_revision(version_txt);
		free(version_txt);
	} else {
		svn_rev = extract_svn_revision(drbd_buildtag());
	}

	return svn_rev;
}

static void get_random_bytes(void* buffer, int len)
{
	int fd;

	fd = open("/dev/random",O_RDONLY);
	if( fd == -1) {
		perror("Open of /dev/random failed");
		exit(20);
	}
	if(read(fd,buffer,len) != len) {
		fprintf(stderr,"Reading from /dev/random failed\n");
		exit(20);
	}
	close(fd);	
}

static void write_node_id(struct node_info *ni)
{
	int fd;
	struct node_info_od on_disk;

	fd = open(NODE_ID_FILE,O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR);
	if( fd == -1 && errno == ENOENT) {
		mkdir(DRBD_LIB_DIR,S_IRWXU);
		fd = open(NODE_ID_FILE,O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR);
	}

	if( fd == -1) {
		perror("Creation of "NODE_ID_FILE" failed.");
		exit(20);
	}

	on_disk.magic           = cpu_to_be32(DRBD_MAGIC);
	on_disk.ni.node_uuid    = cpu_to_be64(ni->node_uuid);
	on_disk.ni.version_code = cpu_to_be32(ni->version_code);

	if( write(fd,&on_disk, sizeof(on_disk)) != sizeof(on_disk)) {
		perror("Write to "NODE_ID_FILE" failed.");
		exit(20);
	}

	close(fd);
}


static int read_node_id(struct node_info *ni)
{
	int fd;
	struct node_info_od on_disk;

	fd = open(NODE_ID_FILE,O_RDONLY);
	if( fd == -1) {
		return 0;
	}
	
	if( read(fd,&on_disk, sizeof(on_disk)) != sizeof(on_disk)) {
		close(fd);
		return 0;
	}

	if ( be32_to_cpu(on_disk.magic) != DRBD_MAGIC ) return 0;

	ni->node_uuid    = be64_to_cpu(on_disk.ni.node_uuid);
	ni->version_code = be32_to_cpu(on_disk.ni.version_code);

	close(fd);
	return 1;
}

/**
 * insert_usage_with_socket:
 * 
 * Return codes:
 *
 * 0 - success
 * 1 - failed to create socket
 * 2 - unknown server
 * 3 - cannot connect to server
 * 5 - other error
 */
static int make_get_request(char *req_buf) {
	struct sockaddr_in server;
	struct hostent *host_info;
	unsigned long addr;
	int sock;
	char *http_host = HTTP_HOST;
	int buf_len = 1024;
	char buffer[buf_len];
	FILE *sockfd;
	int writeit;
	sock = socket( PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return 1;
	}
	memset (&server, 0, sizeof(server));

	/* convert host name to ip */
	host_info = gethostbyname(http_host);
	if (host_info == NULL) {
		/* unknown host, try with ip */
		if ((addr = inet_addr( HTTP_ADDR )) != INADDR_NONE)
			memcpy((char *)&server.sin_addr, &addr, sizeof(addr));
		else {
			close(sock);
			return 2;
		}
	} else {
		memcpy((char *)&server.sin_addr, host_info->h_addr,
			host_info->h_length);
	}

	server.sin_family = AF_INET;
	server.sin_port = htons(HTTP_PORT);

	if (connect(sock, (struct sockaddr*)&server, sizeof(server))<0) {
		/* cannot connect to server */
		close(sock);
		return 3;
	}

	if ((sockfd = fdopen(sock, "r+")) == NULL) {
		close(sock);
		return 5;
	}

	if (fputs(req_buf, sockfd) == EOF) {
		fclose(sockfd);
		close(sock);
		return 5;
	}

	writeit = 0;
	while (fgets(buffer, buf_len, sockfd) != NULL) {
		/* ignore http headers */
		if (writeit == 0) {
			if (buffer[0] == '\r' || buffer[0] == '\n')
				writeit = 1;
		} else {
			printf("%s", buffer);
		}
	}
	fclose(sockfd);
	close(sock);
	return 0;
}

static void url_encode(char* in, char* out)
{
	char *h = "0123456789abcdef";
	char c;

	while( (c = *in++) != 0 ) {
		if( c == '\n' ) break;
		if( ( 'a' <= c && c <= 'z' )
		    || ( 'A' <= c && c <= 'Z' )
		    || ( '0' <= c && c <= '9' )
		    || c == '-' || c == '_' || c == '.' )
			*out++ = c;
		else if( c == ' ' )
			*out++ = '+';
		else {
			*out++ = '%';
			*out++ = h[c >> 4];
			*out++ = h[c & 0x0f];
		}
	}
	*out = 0;
}

/* Ensure that the node is counted on http://usage.drbd.org
 */
#define ANSWER_SIZE 80

void uc_node(enum usage_count_type type)
{
	struct node_info ni;
	char *req_buf;
	u32 current;
	int send = 0;
	int update = 0;
	char answer[ANSWER_SIZE];
	char n_comment[ANSWER_SIZE*3];

	if( type == UC_NO ) return;

	current = current_svn_revision();

	if( ! read_node_id(&ni) ) {
		get_random_bytes(&ni.node_uuid,sizeof(ni.node_uuid));
		ni.version_code = current;
		send = 1;
	} else {
		// read_node_id() was successull
		if (ni.version_code != current) {
			ni.version_code = current;
			update = 1;
			send = 1;
		}
	}

	if(!send) return;

	n_comment[0]=0;
	if (type == UC_ASK ) {
		printf(
"\n"
"\t\t--== This is %s of DRBD ==--\n"
"Please take part in the global DRBD usage count at http://"HTTP_HOST".\n\n"
"The conter works completely anonymous. A random number gets created on\n"
"you machine, and that randomer number (as identifier for this machine) and\n"
"DRBD's version number are sent to "HTTP_HOST".\n\n"
"The benifits for you are:\n"
" * As a respose to your data, the server ("HTTP_HOST") will tell you\n"
"   how many users before you have installed this version (%s).\n"
" * With a high counter the DRBD developers have a high motivation to\n"
"   continue development of the software.\n\n"
"http://"HTTP_HOST"/cgi-bin/insert_usage.pl?nu="U64"&nv="U32"\n\n"
"In case you want to participate but know that this machines is firewalled\n"
"simply issue the query string with your favourite web browser or wget.\n"
"You can control all this by setting 'usage-count' in your drbd.conf.\n\n"
"* You may enter a free form comment about your machine, that gets\n"
"  used on "HTTP_HOST" instead of the big random number.\n"
"* Enter 'no' to opt out.\n"
"* To count this node without comment, just press [RETURN]\n",
			update ? "an update" : "a new installation",
			REL_VERSION,ni.node_uuid, ni.version_code);
		fgets(answer,ANSWER_SIZE,stdin);
		if(!strcmp(answer,"no\n")) send = 0;
		url_encode(answer,n_comment);
	}

	ssprintf(req_buf,"GET http://"HTTP_HOST"/cgi-bin/insert_usage.pl?"
		 "nu="U64"&nv="U32"%s%s HTTP/1.0\n\n",
		 ni.node_uuid, ni.version_code,
		 n_comment[0] ? "&nc=" : "", n_comment);

	if (send) {
		write_node_id(&ni);

		printf(
"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
"  --==  Thank you for participating in the global usage survey  ==--\n"
"The server's response is:\n\n");
		make_get_request(req_buf);
		printf(
"\n"
"In the future drbdadm will only contact "HTTP_HOST" when you update\n"
"DRBD or when you use 'drbdadm create-md'. Of course it will continue\n"
"to ask you for confirmation as long as 'usage-count' is at its default\n"
"value of 'ask'.\n\n"
"Just press [enter] to continue: ");
		fgets(answer,9,stdin);
	}
}

/* For our purpose (finding the revision) SLURP_SIZE is always enough.
 */
char* run_admm_generic(struct d_resource* res ,const char* cmd)
{
	const int SLURP_SIZE = 4096;
	int rr,pipes[2];
	char* buffer;
	pid_t pid;

	buffer = malloc(SLURP_SIZE);
	if(!buffer) return 0;

	if(pipe(pipes)) return 0;

	pid = fork();
	if(pid == -1) {
		fprintf(stderr,"Can not fork\n");
		exit(E_exec_error);
	}
	if(pid == 0) {
		// child
		close(pipes[0]); // close reading end
		dup2(pipes[1],1); // 1 = stdout
		close(pipes[1]);
		exit(_admm_generic(res,cmd,
				   SLEEPS_VERY_LONG|SUPRESS_STDERR|
				   DONT_REPORT_FAILED));
	}
	close(pipes[1]); // close writing end

	rr = read(pipes[0], buffer, SLURP_SIZE-1);
	if( rr == -1) {
		free(buffer);
		// FIXME cleanup
		return 0;
	}
	buffer[rr]=0;
	close(pipes[0]);
	
	waitpid(pid,0,0);

	return buffer;
}

int adm_create_md(struct d_resource* res ,const char* cmd)
{
	char answer[ANSWER_SIZE];
	struct node_info ni;
	u64 device_uuid=0;
	u64 device_size=0;
	char *req_buf;
	int send=0;
	char *tb;
	int rv,fd;

	tb = run_admm_generic(res, "read-dev-uuid");
	device_uuid = strto_u64(tb,NULL,16);
	free(tb);

	rv = _admm_generic(res, cmd, SLEEPS_VERY_LONG); // cmd is "create-md".

	fd = open(res->me->disk,O_RDONLY);
	if( fd != -1) {
		device_size = bdev_size(fd);
		close(fd);
	}

	if( read_node_id(&ni) && device_size && !device_uuid) {
		get_random_bytes(&device_uuid, sizeof(u64));

		if( global_options.usage_count == UC_YES ) send = 1;
		if( global_options.usage_count == UC_ASK ) {
			printf(
"\n"
"\t\t--== Creating metadata ==--\n"
"As with nodes we count the total number of devices mirrored by DRBD at\n"
"at http://"HTTP_HOST".\n\n"
"The counter works completely anonymous. A random number gets created for\n"
"this device, and that randomer number and the devices size will be sent.\n\n"
"http://"HTTP_HOST"/cgi-bin/insert_usage.pl?nu="U64"&ru="U64"&rs="U64"\n\n"
"Enter 'no' to opt out, or just press [return] to continue:",
				ni.node_uuid,device_uuid,device_size
				);
		fgets(answer,ANSWER_SIZE,stdin);
		if(strcmp(answer,"no\n")) send = 1;
		}
	}

	if(!device_uuid) {
		get_random_bytes(&device_uuid, sizeof(u64));
	}

	if (send) {
		ssprintf(req_buf,"GET http://"HTTP_HOST"/cgi-bin/insert_usage.pl?"
			 "nu="U64"&ru="U64"&rs="U64" HTTP/1.0\n\n",
			 ni.node_uuid, device_uuid, device_size);
		make_get_request(req_buf);
	}

	ssprintf( setup_opts[0], X64(016), device_uuid);
	soi=1;
	_admm_generic(res, "write-dev-uuid", SLEEPS_VERY_LONG);

	return rv;
}

