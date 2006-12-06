/* $Id$ */
/* drbd outdate peer daemon
 * Copyright (C) 2006 LINBIT <http://www.linbit.com/>
 *
 * Written by Rasto Levrinc <rasto@linbit.at>
 *
 * This library is free software; you can redistribute it and/or
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


#define T_OUTDATER		"outdater"
#define F_OUTDATER_PEER		"outdater_peer"
#define F_OUTDATER_RES		"outdater_res"
#define F_DOPD_VALUE            "dop_value"
#define F_DOPD_RES              "dop_res"

#define OUTDATE_COMMAND		"/sbin/drbdadm outdate"


/* Prototypes */
void node_walk(ll_cluster_t *);
gboolean check_drbd_peer(const char *);
void set_signals(ll_cluster_t *);
void gotsig(int);
void set_callbacks(ll_cluster_t *);
void open_api(ll_cluster_t *);
void close_api(ll_cluster_t *);
gboolean dopd_dispatch(IPC_Channel *, gpointer);
void dopd_dispatch_destroy(gpointer);
gboolean dopd_timeout_dispatch(gpointer);
int is_stable(ll_cluster_t *);
void msg_start_outdate(struct ha_msg *, void *);
void msg_outdate_rc(struct ha_msg *, void *);
