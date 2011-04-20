/*
   drbdadm_registry.c

   This file is part of DRBD by Philipp Reisner and Lars Ellenberg.
   It was written by Johannes Thoma <johannes.thoma@linbit.com>

   Copyright (C) 2002-2008, LINBIT Information Technologies GmbH.
   Copyright (C) 2002-2008, Philipp Reisner <philipp.reisner@linbit.com>.
   Copyright (C) 2002-2008, Lars Ellenberg <lars.ellenberg@linbit.com>.

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

/* This keeps track of which DRBD minor was configured in which
 * config file. This is required to have alternative config files
 * (-c switch) and userland event handlers.
 */


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <limits.h>

#include "config.h"
#include "registry.h"

static void linkname_from_minor(char *linkname, int minor)
{
	sprintf(linkname, "%s/drbd-minor-%d.conf", DRBD_RUN_DIR, minor);
}

int unregister_minor(int minor)
{
	char linkname[PATH_MAX];

	linkname_from_minor(linkname, minor);
	if (unlink(linkname) < 0) {
		if (errno != ENOENT) {
			perror("unlink");
			return -1;
		}
	}
	return 0;
}

static ssize_t __readlink(const char *path, char *buf, size_t bufsiz)
{
	ssize_t ret;

	ret = readlink(path, buf, bufsiz);
	if (ret >= 0) {
		if (ret >= bufsiz) {
			errno = ENAMETOOLONG;
			return -1;
		}
		buf[ret] = 0;
	}
	return ret;
}

static int register_path(const char *linkname, const char *path)
{
	char target[PATH_MAX];

	if (path[0] != '/') {
		fprintf(stderr, "File %s: absolute path expected; won't "
				"register relative path.",
			path);
		return -1;
	}
	if (!strncmp(path, DRBD_RUN_DIR, strlen(DRBD_RUN_DIR)))
		return -1;
	if (__readlink(linkname, target, sizeof(target)) >= 0 &&
	    !strcmp(target, path))
		return 0;
	if (unlink(linkname) != 0 && errno != ENOENT) {
		perror(linkname);
		return -1;
	}
	if (mkdir(DRBD_RUN_DIR, S_IRWXU) != 0 && errno != EEXIST) {
		perror(DRBD_RUN_DIR);
		return -1;
	}
	if (symlink(path, linkname) != 0) {
		fprintf(stderr, "symlink(%s, %s): %m\n", path, linkname);
		return -1;
	}
	return 0; 
}

int register_minor(int minor, const char *path)
{
	char linkname[PATH_MAX];

	linkname_from_minor(linkname, minor);
	return register_path(linkname, path);
}

char *lookup_minor(int minor)
{
	static char linkname[PATH_MAX];
	struct stat stat_buf;

	linkname_from_minor(linkname, minor);
	if (stat(linkname, &stat_buf) != 0) {
		if (errno != ENOENT)
			perror(linkname);
		return NULL;
	}
	return linkname;
}

static void linkname_from_resource_name(char *linkname, const char *name)
{
	sprintf(linkname, "%s/drbd-resource-%s.conf", DRBD_RUN_DIR, name);
}

int unregister_resource(const char *name)
{
	char linkname[PATH_MAX];

	linkname_from_resource_name(linkname, name);
	if (unlink(linkname) != 0) {
		if (errno != ENOENT) {
			perror(linkname);
			return -1;
		}
	}
	return 0;
}

int register_resource(const char *name, const char *path)
{
	char linkname[PATH_MAX];

	linkname_from_resource_name(linkname, name);
	return register_path(linkname, path);
}

/* This returns a static buffer containing the real
 * configuration file known to be used last for this minor.
 * If you need the return value longer, stuff it away with strdup. */
char *lookup_resource(const char *name)
{
	static char linkname[PATH_MAX];
	struct stat stat_buf;

	linkname_from_resource_name(linkname, name);
	if (stat(linkname, &stat_buf) != 0) {
		if (errno != ENOENT)
			perror(linkname);
		return NULL;
	}
	return linkname;
}


#ifdef TEST

int main(int argc, char ** argv)
{
	register_minor(1, "/etc/drbd-xy.conf");
	register_minor(15, "/etc/drbd-82.conf");
	register_minor(14, "/../../../../../../etc/drbd-82.conf");
	printf("Minor 1 is %s.\n", lookup_minor(1));
	printf("Minor 2 is %s.\n", lookup_minor(2));
	printf("Minor 14 is %s.\n", lookup_minor(14));
	printf("Minor 15 is %s.\n", lookup_minor(15));
	return 0;
}

#endif
