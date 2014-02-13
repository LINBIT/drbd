/*
   drbdadm_usage_cnt.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.

   Copyright (C) 2006-2008, LINBIT Information Technologies GmbH
   Copyright (C) 2006-2008, Philipp Reisner <philipp.reisner@linbit.com>
   Copyright (C) 2006-2008, Lars Ellenberg  <lars.ellenberg@linbit.com>

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
#include <setjmp.h>

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
#define HTTP_ADDR "212.69.161.111"
#define NODE_ID_FILE DRBD_LIB_DIR"/node_id"
#define GIT_HASH_BYTE   20
#define SRCVERSION_BYTE 12     /* actually 11 and a half. */
#define SRCVERSION_PAD (GIT_HASH_BYTE - SRCVERSION_BYTE)
#define SVN_STYLE_OD  16

struct version {
	uint32_t svn_revision;
	char git_hash[GIT_HASH_BYTE];
	struct {
		unsigned major, minor, sublvl;
	} version;
	unsigned version_code;
};

struct node_info {
	uint64_t node_uuid;
	struct version rev;
};

struct node_info_od {
	uint32_t magic;
	struct node_info ni;
} __packed;

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

void read_hex(char* dst, char* src, int dst_size, int src_size)
{
	int dst_i, u, src_i=0;

	for(dst_i=0;dst_i<dst_size;dst_i++) {
		if (src[src_i] == 0) break;
		if (src_size - src_i < 2) {
			sscanf(src+src_i,"%1x",&u);
			dst[dst_i]=u<<4;
		} else {
			sscanf(src+src_i,"%2x",&u);
			dst[dst_i]=u;
		}
		if(++src_i >= src_size) break;
		if(src[src_i] == 0) break;
		if(++src_i >= src_size) break;
	}
}

static void version_from_str(struct version *rel, const char *token)
{
	char *dot;
	long maj, min, sub;
	maj = strtol(token, &dot, 10);
	if (*dot != '.')
		return;
	min = strtol(dot+1, &dot, 10);
	if (*dot != '.')
		return;
	sub = strtol(dot+1, &dot, 10);
	/* don't check on *dot == 0,
	 * we may want to add some extraversion tag sometime
	if (*dot != 0)
		return;
	*/

	rel->version.major = maj;
	rel->version.minor = min;
	rel->version.sublvl = sub;

	rel->version_code = (maj << 16) + (min << 8) + sub;
}

static void parse_version(struct version *rel, const char *text)
{
	char token[80];
	int plus=0;
	enum { BEGIN, F_VER, F_SVN, F_REV, F_GIT, F_SRCV } ex = BEGIN;

	while (sget_token(token, sizeof(token), &text) != EOF) {
		switch(ex) {
		case BEGIN:
			if (!strcmp(token, "version:"))
				ex = F_VER;
			if (!strcmp(token, "SVN"))
				ex = F_SVN;
			if (!strcmp(token, "GIT-hash:"))
				ex = F_GIT;
			if (!strcmp(token, "srcversion:"))
				ex = F_SRCV;
			break;
		case F_VER:
			if (!strcmp(token, "plus")) {
				plus = 1;
				/* still waiting for version */
			} else {
				version_from_str(rel, token);
				ex = BEGIN;
			}
			break;
		case F_SVN:
			if (!strcmp(token,"Revision:"))
				ex = F_REV;
			break;
		case F_REV:
			rel->svn_revision = atol(token) * 10;
			if (plus)
				rel->svn_revision += 1;
			memset(rel->git_hash, 0, GIT_HASH_BYTE);
			return;
		case F_GIT:
			read_hex(rel->git_hash, token, GIT_HASH_BYTE, strlen(token));
			rel->svn_revision = 0;
			return;
		case F_SRCV:
			memset(rel->git_hash, 0, SRCVERSION_PAD);
			read_hex(rel->git_hash + SRCVERSION_PAD, token, SRCVERSION_BYTE, strlen(token));
			rel->svn_revision = 0;
			return;
		}
	}
}

static struct version __drbd_driver_version = {};
static struct version __drbd_utils_version = {};
enum driver_version_policy {
	STRICT,
	FALLBACK_TO_UTILS
};

const struct version *drbd_utils_version(void);

const struct version *drbd_driver_version(enum driver_version_policy fallback)
{
	char* version_txt;

	if (__drbd_driver_version.version_code)
		return &__drbd_driver_version;

	version_txt = slurp_proc_drbd();
	if (version_txt) {
		parse_version(&__drbd_driver_version, version_txt);
		free(version_txt);
		return &__drbd_driver_version;
	}

	if (fallback == FALLBACK_TO_UTILS)
		return drbd_utils_version();

	return NULL;
}

const struct version *drbd_utils_version(void)
{
	if (!__drbd_utils_version.version_code) {
		version_from_str(&__drbd_utils_version, REL_VERSION);
		parse_version(&__drbd_utils_version, drbd_buildtag());
	}

	return &__drbd_utils_version;
}

int version_code_kernel(void)
{
	const struct version *driver_version = drbd_driver_version(STRICT);
	return driver_version ? driver_version->version_code : 0;
}

int version_code_userland(void)
{
	const struct version *utils_version = drbd_utils_version();
	return utils_version->version_code;
}

static int vcs_eq(const struct version *rev1, const struct version *rev2)
{
	if( rev1->svn_revision || rev2->svn_revision ) {
		return rev1->svn_revision == rev2->svn_revision;
	} else {
		return !memcmp(rev1->git_hash,rev2->git_hash,GIT_HASH_BYTE);
	}
}

void add_lib_drbd_to_path(void)
{
	char *new_path = NULL;
	char *old_path = getenv("PATH");

	m_asprintf(&new_path, "%s%s%s",
			old_path,
			old_path ? ":" : "",
			"/lib/drbd");
	setenv("PATH", new_path, 1);
}

void maybe_exec_legacy_drbdadm(char **argv)
{
	const struct version *driver_version = drbd_driver_version(FALLBACK_TO_UTILS);

	if (driver_version->version.major == 8 &&
	    driver_version->version.minor == 3) {
#ifdef DRBD_LEGACY_83
		/* This drbdadm warned already... */
		setenv("DRBD_DONT_WARN_ON_VERSION_MISMATCH", "1", 0);
		add_lib_drbd_to_path();
		execvp(drbdadm_83, argv);
		fprintf(stderr, "execvp() failed to exec %s: %m\n", drbdadm_83);
#else
		fprintf(stderr, "This drbdadm was build without support for legacy\n"
			"drbd kernel code (8.3). Consider to rebuild your user land\n"
			"tools with ./configure --with-legacy-connector\n");
#endif
		exit(E_EXEC_ERROR);
	}
	if (driver_version->version.major == 8 &&
	    driver_version->version.minor == 4) {
#ifdef DRBD_LEGACY_84
		/* This drbdadm warned already... */
		setenv("DRBD_DONT_WARN_ON_VERSION_MISMATCH", "1", 0);
		add_lib_drbd_to_path();
		execvp(drbdadm_84, argv);
		fprintf(stderr, "execvp() failed to exec %s: %m\n", drbdadm_84);
#else
		fprintf(stderr, "This drbdadm was build without support for legacy\n"
			"drbd kernel code (8.4). Consider to rebuild your user land\n"
			"tools with and do not give --without-legacy-utils-8.4 on the\n"
			"commandline\n");
#endif
		exit(E_EXEC_ERROR);
	}
}

static char *vcs_to_str(struct version *rev)
{
	static char buffer[80]; // Not generic, sufficient for the purpose.

	if( rev->svn_revision ) {
		snprintf(buffer,80,"nv="U32,rev->svn_revision);
	} else {
		int len=20,p;
		unsigned char *bytes;

		p = sprintf(buffer,"git=");
		bytes = (unsigned char*)rev->git_hash;
		while(len--) p += sprintf(buffer+p,"%02x",*bytes++);
	}
	return buffer;
}

static void write_node_id(struct node_info *ni)
{
	int fd;
	struct node_info_od on_disk;
	int size;

	fd = open(NODE_ID_FILE,O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR);
	if( fd == -1 && errno == ENOENT) {
		mkdir(DRBD_LIB_DIR,S_IRWXU);
		fd = open(NODE_ID_FILE,O_WRONLY|O_CREAT,S_IRUSR|S_IWUSR);
	}

	if( fd == -1) {
		perror("Creation of "NODE_ID_FILE" failed.");
		exit(20);
	}

	if(ni->rev.svn_revision != 0) { // SVN style (old)
		on_disk.magic               = cpu_to_be32(DRBD_MAGIC);
		on_disk.ni.node_uuid        = cpu_to_be64(ni->node_uuid);
		on_disk.ni.rev.svn_revision = cpu_to_be32(ni->rev.svn_revision);
		memset(on_disk.ni.rev.git_hash,0,GIT_HASH_BYTE);
		size = SVN_STYLE_OD;
	} else {
		on_disk.magic               = cpu_to_be32(DRBD_MAGIC+1);
		on_disk.ni.node_uuid        = cpu_to_be64(ni->node_uuid);
		on_disk.ni.rev.svn_revision = 0;
		memcpy(on_disk.ni.rev.git_hash,ni->rev.git_hash,GIT_HASH_BYTE);
		size = sizeof(on_disk);
	}

	if( write(fd,&on_disk, size) != size) {
		perror("Write to "NODE_ID_FILE" failed.");
		exit(20);
	}

	close(fd);
}


static int read_node_id(struct node_info *ni)
{
	int rr,fd;
	struct node_info_od on_disk;

	fd = open(NODE_ID_FILE,O_RDONLY);
	if( fd == -1) {
		return 0;
	}

	rr = read(fd,&on_disk, sizeof(on_disk)); 
	if( rr != sizeof(on_disk) && rr != SVN_STYLE_OD ) {
		close(fd);
		return 0;
	}

	switch(be32_to_cpu(on_disk.magic)) {
	case DRBD_MAGIC:
		ni->node_uuid    = be64_to_cpu(on_disk.ni.node_uuid);
		ni->rev.svn_revision = be32_to_cpu(on_disk.ni.rev.svn_revision);
		memset(ni->rev.git_hash,0,GIT_HASH_BYTE);
		break;
	case DRBD_MAGIC+1:
		ni->node_uuid    = be64_to_cpu(on_disk.ni.node_uuid);
		ni->rev.svn_revision = 0;
		memcpy(ni->rev.git_hash,on_disk.ni.rev.git_hash,GIT_HASH_BYTE);
		break;
	default:
		return 0;
	}

	close(fd);
	return 1;
}

/* to interrupt gethostbyname,
 * we not only need a signal,
 * but also the long jump:
 * gethostbyname would otherwise just restart the syscall
 * and timeout again. */
static jmp_buf timed_out;
static void alarm_handler(int __attribute((unused)) signo)
{
	longjmp(timed_out, 1);
}

#define DNS_TIMEOUT 3	/* seconds */
#define SOCKET_TIMEOUT 3 /* seconds */
struct hostent *my_gethostbyname(const char *name)
{
	struct sigaction sa;
	struct sigaction so;
	struct hostent *h;

	alarm(0);
	sa.sa_handler = &alarm_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sigaction(SIGALRM, &sa, &so);

	if (!setjmp(timed_out)) {
		alarm(DNS_TIMEOUT);
		h = gethostbyname(name);
	} else
		/* timed out, longjmp of SIGALRM jumped here */
		h = NULL;

	alarm(0);
	sigaction(SIGALRM, &so, NULL);

	return h;
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
static int make_get_request(char *uri) {
	struct sockaddr_in server;
	struct hostent *host_info;
	unsigned long addr;
	int sock;
	char *req_buf;
	char *http_host = HTTP_HOST;
	int buf_len = 1024;
	char buffer[buf_len];
	FILE *sockfd;
	int writeit;
	struct timeval timeout = { .tv_sec = SOCKET_TIMEOUT };
	struct utsname nodeinfo;

	sock = socket( PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return 1;

	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

	memset (&server, 0, sizeof(server));

	/* convert host name to ip */
	host_info = my_gethostbyname(http_host);
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

	uname(&nodeinfo);
	req_buf = ssprintf("GET %s HTTP/1.0\r\n"
			   "Host: "HTTP_HOST"\r\n"
			   "User-Agent: drbdadm/"REL_VERSION" (%s; %s; %s; %s)\r\n"
			   "\r\n",
			   uri,
			   nodeinfo.sysname, nodeinfo.release,
			   nodeinfo.version, nodeinfo.machine);

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
			fprintf(stderr,"%s", buffer);
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
	char *uri;
	int send = 0;
	int update = 0;
	char answer[ANSWER_SIZE];
	char n_comment[ANSWER_SIZE*3];
	char *r;
	const struct version *driver_version = drbd_driver_version(FALLBACK_TO_UTILS);

	if( type == UC_NO ) return;
	if( getuid() != 0 ) return;

	/* not when running directly from init,
	 * or if stdout is no tty.
	 * you do not want to have the "user information message"
	 * as output from `drbdadm sh-resources all`
	 */
	if (getenv("INIT_VERSION")) return;
	if (no_tty) return;

	if( ! read_node_id(&ni) ) {
		get_random_bytes(&ni.node_uuid,sizeof(ni.node_uuid));
		ni.rev = *driver_version;
		send = 1;
	} else {
		// read_node_id() was successful
		if (!vcs_eq(&ni.rev, driver_version)) {
			ni.rev = *driver_version;
			update = 1;
			send = 1;
		}
	}

	if(!send) return;

	n_comment[0]=0;
	if (type == UC_ASK ) {
		fprintf(stderr,
"\n"
"\t\t--== This is %s of DRBD ==--\n"
"Please take part in the global DRBD usage count at http://"HTTP_HOST".\n\n"
"The counter works anonymously. It creates a random number to identify\n"
"your machine and sends that random number, along with the kernel and\n"
"DRBD version, to "HTTP_HOST".\n\n"
"The benefits for you are:\n"
" * In response to your submission, the server ("HTTP_HOST") will tell you\n"
"   how many users before you have installed this version (%s).\n"
" * With a high counter LINBIT has a strong motivation to\n"
"   continue funding DRBD's development.\n\n"
"http://"HTTP_HOST"/cgi-bin/insert_usage.pl?nu="U64"&%s\n\n"
"In case you want to participate but know that this machine is firewalled,\n"
"simply issue the query string with your favorite web browser or wget.\n"
"You can control all of this by setting 'usage-count' in your drbd.conf.\n\n"
"* You may enter a free form comment about your machine, that gets\n"
"  used on "HTTP_HOST" instead of the big random number.\n"
"* If you wish to opt out entirely, simply enter 'no'.\n"
"* To count this node without comment, just press [RETURN]\n",
			update ? "an update" : "a new installation",
			REL_VERSION,ni.node_uuid, vcs_to_str(&ni.rev));
		r = fgets(answer, ANSWER_SIZE, stdin);
		if(r && !strcmp(answer,"no\n")) send = 0;
		url_encode(answer,n_comment);
	}

	uri = ssprintf("http://"HTTP_HOST"/cgi-bin/insert_usage.pl?nu="U64"&%s%s%s",
		       ni.node_uuid, vcs_to_str(&ni.rev),
		       n_comment[0] ? "&nc=" : "", n_comment);

	if (send) {
		write_node_id(&ni);

		fprintf(stderr,
"\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n"
"  --==  Thank you for participating in the global usage survey  ==--\n"
"The server's response is:\n\n");
		make_get_request(uri);
		if (type == UC_ASK) {
			fprintf(stderr,
"\n"
"From now on, drbdadm will contact "HTTP_HOST" only when you update\n"
"DRBD or when you use 'drbdadm create-md'. Of course it will continue\n"
"to ask you for confirmation as long as 'usage-count' is at its default\n"
"value of 'ask'.\n\n"
"Just press [RETURN] to continue: ");
			r = fgets(answer, 9, stdin);
		}
	}
}

/* For our purpose (finding the revision) SLURP_SIZE is always enough.
 */
static char* run_adm_drbdmeta(const struct cfg_ctx *ctx, const char *arg_override)
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
		exit(E_EXEC_ERROR);
	}
	if(pid == 0) {
		struct adm_cmd local_cmd = *ctx->cmd;
		struct cfg_ctx local_ctx = *ctx;
		// child
		close(pipes[0]); // close reading end
		dup2(pipes[1],1); // 1 = stdout
		close(pipes[1]);
		local_cmd.name = arg_override;
		local_ctx.cmd = &local_cmd;
		rr = _adm_drbdmeta(&local_ctx,
				   SLEEPS_VERY_LONG|SUPRESS_STDERR|
				   DONT_REPORT_FAILED,
				   NULL);
		exit(rr);
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

static struct d_name *find_backend_option(const char *opt_name)
{
	struct d_name *b_opt;
	const int str_len = strlen(opt_name);

	STAILQ_FOREACH(b_opt, &backend_options, link) {
		if (!strncmp(b_opt->name, opt_name, str_len))
			return b_opt;
	}
	return NULL;
}

int adm_create_md(const struct cfg_ctx *ctx)
{
	struct connection *conn;
	char answer[ANSWER_SIZE];
	struct node_info ni;
	uint64_t device_uuid=0;
	uint64_t device_size=0;
	char *uri;
	int send=0;
	char *tb;
	int rv,fd;
	char *r, *max_peers_str = NULL;
	struct d_name *b_opt;
	const char *opt_max_peers = "--max-peers=";

	b_opt = find_backend_option(opt_max_peers);
	if (b_opt) {
		max_peers_str = ssprintf("%s", b_opt->name + strlen(opt_max_peers));
		STAILQ_REMOVE(&backend_options, b_opt, d_name, link);
		free(b_opt);
	} else {
		int max_peers = 0;

		for_each_connection(conn, &ctx->res->connections)
			if (!conn->ignore)
				max_peers++;

		if (max_peers == 0)
			max_peers = 1;

		max_peers_str = ssprintf("%d", max_peers);
	}

	tb = run_adm_drbdmeta(ctx, "read-dev-uuid");
	device_uuid = strto_u64(tb,NULL,16);
	free(tb);

	/* this is "drbdmeta ... create-md" */
	rv = _adm_drbdmeta(ctx, SLEEPS_VERY_LONG, max_peers_str);

	if(rv || dry_run) return rv;

	fd = open(ctx->vol->disk,O_RDONLY);
	if( fd != -1) {
		device_size = bdev_size(fd);
		close(fd);
	}

	if( read_node_id(&ni) && device_size && !device_uuid) {
		get_random_bytes(&device_uuid, sizeof(uint64_t));

		if( global_options.usage_count == UC_YES ) send = 1;
		if( global_options.usage_count == UC_ASK ) {
			fprintf(stderr,
"\n"
"\t\t--== Creating metadata ==--\n"
"As with nodes, we count the total number of devices mirrored by DRBD\n"
"at http://"HTTP_HOST".\n\n"
"The counter works anonymously. It creates a random number to identify\n"
"the device and sends that random number, along with the kernel and\n"
"DRBD version, to "HTTP_HOST".\n\n"
"http://"HTTP_HOST"/cgi-bin/insert_usage.pl?nu="U64"&ru="U64"&rs="U64"\n\n"
"* If you wish to opt out entirely, simply enter 'no'.\n"
"* To continue, just press [RETURN]\n",
				ni.node_uuid,device_uuid,device_size
				);
			r = fgets(answer, ANSWER_SIZE, stdin);
			if(r && strcmp(answer,"no\n")) send = 1;
		}
	}

	if(!device_uuid) {
		get_random_bytes(&device_uuid, sizeof(uint64_t));
	}

	if (send) {
		uri = ssprintf("http://"HTTP_HOST"/cgi-bin/insert_usage.pl?"
			       "nu="U64"&ru="U64"&rs="U64,
			       ni.node_uuid, device_uuid, device_size);
		make_get_request(uri);
	}

	/* HACK */
	{
		struct adm_cmd local_cmd = *ctx->cmd;
		struct cfg_ctx local_ctx = *ctx;
		struct names old_backend_options;
		char *opt;

		opt = ssprintf(X64(016), device_uuid);
		old_backend_options = backend_options;
		STAILQ_INIT(&backend_options);
		insert_tail(&backend_options, names_from_str(opt));

		local_cmd.name = "write-dev-uuid";
		local_ctx.cmd = &local_cmd;
		_adm_drbdmeta(&local_ctx, SLEEPS_VERY_LONG, NULL);

		free_names(&backend_options);
		backend_options = old_backend_options;
	}
	return rv;
}

