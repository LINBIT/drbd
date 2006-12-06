/* $Id$ */
/* drbd-peer-outdater
 * Copyright (C) 2006 LINBIT <http://www.linbit.com/>
 *
 * Written by Rasto Levrinc <rasto@linbit.com>
 *
 * based on attrd
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <portability.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <crm/common/ipc.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/Gmain_timeout.h>
#include <dopd.h>

#define OPTARGS      "hVt:p:r:"
#define DEFAULT_TIMEOUT 60 // timeout in seconds

typedef struct dop_client_s
{
	int timeout;
	GMainLoop *mainloop;
	int rc;
} dop_client_t;

const char *crm_system_name = "drbd-peer-outdater";

static void usage(const char* cmd, int exit_status);

static void
dop_exit(dop_client_t *client)
{
	int rc;

	if (client == NULL)
		exit(5);
	rc = client->rc;

	crm_free(client);
	exit(rc);
}

static gboolean
outdate_callback(IPC_Channel * server, gpointer user_data)
{
	dop_client_t *client = (dop_client_t *)user_data;
	HA_Message *msg = NULL;
	const char *rc_string;
	char *ep;
	int rc;

	msg = msgfromIPC_noauth(server);
	if (!msg) {
		fprintf(stderr, "no message from server or other "
				"instance is running\n");
		if (client->mainloop != NULL &&
		    g_main_is_running(client->mainloop))
			g_main_quit(client->mainloop);
		return FALSE;
	}
	crm_debug_2("message: %s, %s\n",
			ha_msg_value(msg, F_TYPE),
			ha_msg_value(msg, F_ORIG)
			);
	rc_string = ha_msg_value(msg, F_DOPD_VALUE);

	errno = 0;
	rc = strtol(rc_string, &ep, 10);
	if (errno != 0 || *ep != EOS) {
		fprintf(stderr, "unknown message: %s from server", rc_string);
		ha_msg_del(msg);
		if (client->mainloop != NULL &&
		    g_main_is_running(client->mainloop))
			g_main_quit(client->mainloop);
		return FALSE;
	}

	ha_msg_del(msg);

	if (client->mainloop != NULL && g_main_is_running(client->mainloop)) {
		client->rc = rc;
		g_main_quit(client->mainloop);
	} else
		dop_exit(client);

	return TRUE;
}

static void
outdater_dispatch_destroy(gpointer user_data)
{
	return;
}

static gboolean
outdater_timeout_dispatch(gpointer user_data)
{
	dop_client_t *client = (dop_client_t *)user_data;
	fprintf(stderr, "error: could not connect to dopd after %i seconds"
			": timeout reached\n", client->timeout);
	if (client->mainloop != NULL && g_main_is_running(client->mainloop))
		g_main_quit(client->mainloop);
	return FALSE;
}

int
main(int argc, char ** argv)
{
	HA_Message *update = NULL;
	IPC_Channel *ipc_server = NULL;
	int argerr = 0;
	int flag;
	char *drbd_peer = NULL;
	char *drbd_resource = NULL;
	int timeout = DEFAULT_TIMEOUT;

	dop_client_t *new_client = NULL;
	GCHSource *src = NULL;

	crm_log_init(crm_system_name);

	crm_debug_3("Begining option processing");
	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				alter_debug(DEBUG_INC);
				break;
			case 'h':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
				break;
			case 'p':
				drbd_peer = crm_strdup(optarg);
				break;
			case 'r':
				drbd_resource = crm_strdup(optarg);
				break;
			case 't':
				timeout = atoi(optarg);
				break;
			default:
				++argerr;
				break;
		}
	}

	crm_debug_3("Option processing complete");

	/* the caller drbdadm sets DRBD_PEER env variable, use it if
	 * -p option was not specified */
	if ((drbd_peer == NULL) && !(drbd_peer = getenv("DRBD_PEER"))) {
		++argerr;
	}

	/* the caller drbdadm sets DRBD_RESOURCE env variable, use it if
	 * -r option was not specified */
	if ((drbd_resource == NULL) && !(drbd_resource = getenv("DRBD_RESOURCE"))) {
		++argerr;
	}

	if (optind > argc) {
		++argerr;
	}

	if (argerr) {
		usage(crm_system_name, LSB_EXIT_GENERIC);
	}

	crm_debug_2("drbd peer: %s\n", drbd_peer);
	crm_debug_2("drbd resource: %s\n", drbd_resource);

	crm_malloc0(new_client, sizeof(dop_client_t));
	new_client->timeout = timeout;
	new_client->mainloop = g_main_new(FALSE);
	new_client->rc = 5;

	/* Connect to the IPC server */
	src = init_client_ipc_comms(T_OUTDATER, outdate_callback,
			      (gpointer)new_client, &ipc_server);

	if (ipc_server == NULL) {
		fprintf(stderr, "Could not connect to "T_OUTDATER" channel\n");
		dop_exit(new_client); // unreachable
	}

	/* send message with drbd resource to dopd */
	update = ha_msg_new(3);
	ha_msg_add(update, F_TYPE, T_OUTDATER);
	ha_msg_add(update, F_ORIG, crm_system_name);
	ha_msg_add(update, F_OUTDATER_PEER, drbd_peer);
	ha_msg_add(update, F_OUTDATER_RES, drbd_resource);

	if (send_ipc_message(ipc_server, update) == FALSE) {
		fprintf(stderr, "Could not send message\n");
		dop_exit(new_client);
	}

	Gmain_timeout_add_full(G_PRIORITY_DEFAULT, new_client->timeout * 1000,
			       outdater_timeout_dispatch, (gpointer)new_client,
			       outdater_dispatch_destroy);

	g_main_run(new_client->mainloop);
	dop_exit(new_client);
	return 5;
}

static void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;
	fprintf(stream, "usage: %s -r <string> -p <string> [-t <int>]\n", cmd);
	fprintf(stream, "\t-p <string>\tdrbd peer\n");
	fprintf(stream, "\t-r <string>\tdrbd resource\n");
	fprintf(stream, "\t-t <int>\ttimeout in seconds; default: %d\n\n",
			DEFAULT_TIMEOUT);
	fprintf(stream, "The drbd peer and drbd resource have to be specified either on the\n"
			"commandline using the -p and -r options, or using the $DRBD_PEER and\n"
			"$DRBD_RESOURCE environment variables. $DRBD_RESOURCE and $DRBD_PEER\n"
			"will be ignored, if the command line options are used.\n");
	fflush(stream);

	exit(exit_status);
}

