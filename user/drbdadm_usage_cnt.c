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
#include "drbd_endian.h"
#include "linux/drbd.h"		/* only use DRBD_MAGIC from here! */

#define HTTP_PORT 80
#define HTTP_HOST "usage.drbd.org"
#define HTTP_ADDR "212.69.162.23"
#define NODE_ID_FILE "/var/lib/drbd/node_id"

struct node_info {
	u64	node_uuid;
	u32	version_code;
};

struct node_info_od {
	u32 magic;
	struct node_info ni;
} __attribute((packed));

/* FIX: mark plus versions, mark production vs beta releases.
        read the version string from the /proc file, so we
	look at the version of the module and not at the version
	of the drbdadm executable.
 */
static unsigned int numeric_version_code(char* text)
{
	unsigned int nc;
	char buffer[5], *c, *b;
	unsigned m = 1000000;

	nc = 0;
	c = text;

	while(*c) {
		while(!isdigit(*c)) c++;
		b = buffer;
		while(isdigit(*c)) *b++=*c++;
		*b=0;

		nc = nc + atoi( buffer ) * m;
		m=m/1000;
	}

	return nc;
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

static int insert_resource(u64 node_uuid, u64 res_uuid, u64 res_size) {
	char *req_buf;
        ssprintf( req_buf, "GET http://"HTTP_HOST"/cgi-bin/insert_usage.pl?"
		  "nu="U64"&ru="U64"&rs="U64" HTTP/1.0\n\n",
		  node_uuid, res_uuid, res_size);
	return make_get_request(req_buf);
}

/* Ensure that the node is counted on http://usage.drbd.org
 */
void uc_node(enum usage_count_type type)
{
	struct node_info ni;
	char *req_buf;
	u32 current;
	int send = 0;
	int update = 0;
	char answer[10];

	if( type == UC_NO ) return;

	current = numeric_version_code(REL_VERSION);

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
"   how many users before your have installed this version (%s).\n"
" * With a high counter the DRBD developers have a high motivation to\n"
"   continue development of the software.\n\n"
"The following string will be send to the server:\n"
"http://"HTTP_HOST"/cgi-bin/insert_usage.pl?nu="U64"&nv="U32"\n\n"
"In case you want to participate but know that this machines is firewalled\n"
"simply issue the query string with your favourite web browser or wget\n\n"
"You can control all this by setting 'usage-count' in the globals section\n"
"of your drbd.conf\n\n"
"Just press [enter] or enter 'no'[enter] to opt out: ",
			update ? "an update" : "a new installation",
			REL_VERSION,ni.node_uuid, ni.version_code);
		fgets(answer,9,stdin);
		if(!strcmp(answer,"no")) send = 0;
	}

        ssprintf(req_buf,"GET http://"HTTP_HOST"/cgi-bin/insert_usage.pl?"
		 "nu="U64"&nv="U32" HTTP/1.0\n\n",
		 ni.node_uuid, ni.version_code);

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
