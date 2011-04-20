/*
   drbdadm_minor_table.c

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

/* buf has to be big enough to hold that path.
 * it is assumed that sprintf cannot fail :-] */
void linkname_from_minor(char *buf, int minor)
{
	sprintf(buf, "%s/drbd-minor-%d.conf", DRBD_LIB_DIR, minor);
}

int unregister_minor(int minor)
{
	char buf[PATH_MAX];

	linkname_from_minor(buf, minor);
	if (unlink(buf) < 0) {
		if (errno != ENOENT) {
			perror("unlink");
			return -1;
		}
	}
	return 0;
}

int register_minor(int minor, const char *path)
{
	char buf[PATH_MAX];
	struct stat stat_buf;
	int err = -1;

	linkname_from_minor(buf, minor);

	if (!path || !path[0])
		fprintf(stderr, "Cannot register an empty path.\n");
	else if (path[0] != '/')
		fprintf(stderr, "Absolute path expected, "
			"won't register relative path (%s).\n", path);
	else if (strlen(path) > PATH_MAX)
		fprintf(stderr, "path (%s):\ntoo long to be registered, "
				"max path len supported: %u\n",
				path, PATH_MAX);
	else if (stat(path, &stat_buf) < 0)
		fprintf(stderr, "stat(%s): %m\n", path);
	else if (unlink(buf) < 0 && errno != ENOENT)
		fprintf(stderr, "unlink(%s): %m\n", buf);
	else if (symlink(path, buf) < 0)
		fprintf(stderr, "symlink(%s, %s): %m\n", path, buf);
	else
		/* it did work out after all! */
		err = 0;

	return err;
}

/* This returns a static buffer containing the real
 * configuration file known to be used last for this minor.
 * If you need the return value longer, stuff it away with strdup. */
char *lookup_minor(int minor)
{
	static char buf[PATH_MAX];
	static char resolved_path[PATH_MAX];
	struct stat stat_buf;
	ssize_t len;

	linkname_from_minor(buf, minor);

	if (stat(buf, &stat_buf) < 0) {
		if (errno != ENOENT)
			fprintf(stderr, "stat(%s): %m\n", buf);
		return NULL;
	}

	len = readlink(buf, resolved_path, sizeof(resolved_path));
	if (len < 0) {
		perror("readlink");
		return NULL;
	}
	if (len >= PATH_MAX) {
		fprintf(stderr, "readlink(%s): result has probably been truncated\n",
				buf);
		return NULL;
	}

	resolved_path[len] = '\0';
	return resolved_path;
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
