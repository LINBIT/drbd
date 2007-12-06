/*
 * A small program to enumerate all states considered by pre_state_checks() as
 * valid, and to potentially improve that function.
 */
#include <stdio.h>
#include <linux/drbd.h>

#define STATIC static

struct Drbd_Conf {
	int dummy;
};
typedef struct Drbd_Conf drbd_dev;

static void print_st(drbd_state_t ns, set_st_err_t rv)
{
	printf("{ cs:%s\tst:%s/%s\tds:%s/%s\t%c%c%c%c } = %s\n",
	       conns_to_name(ns.conn),
	       roles_to_name(ns.role),
	       roles_to_name(ns.peer),
	       disks_to_name(ns.disk),
	       disks_to_name(ns.pdsk),
	       ns.susp ? 's' : 'r',
	       ns.aftr_isp ? 'a' : '-',
	       ns.peer_isp ? 'p' : '-',
	       ns.user_isp ? 'u' : '-',
	       set_st_err_name(rv)
	    );
}


STATIC int pre_state_checks(drbd_dev* mdev, drbd_state_t ns)
{
	/* See drbd_state_sw_errors in drbd_strings.c */

	enum fencing_policy fp;
	int rv=SS_Success;

/*
	fp = DontCare;
	if(inc_local(mdev)) {
		fp = mdev->bc->fencing;
		dec_local(mdev);
	}

	if(inc_net(mdev)) {
		if( !mdev->net_conf->two_primaries &&
		    ns.role == Primary && ns.peer == Primary ) 
			rv=SS_TowPrimaries;
		dec_net(mdev);
	}
*/

	if( rv <= 0 ) /* already found a reason to abort */;
	else if( ns.role == Primary && ns.conn < Connected &&
		 ns.disk < UpToDate ) rv=SS_NoUpToDateDisk;

	else if( fp >= Resource &&
		 ns.role == Primary && ns.conn < Connected &&
		 ns.pdsk >= DUnknown ) rv=SS_PrimaryNOP;

	else if( ns.role == Primary && ns.disk <= Inconsistent &&
		 ns.pdsk <= Inconsistent ) rv=SS_NoUpToDateDisk;
	
	else if( ns.conn > Connected &&
		 ns.disk < UpToDate && ns.pdsk < UpToDate ) 
		rv=SS_BothInconsistent;

	else if( ns.conn > Connected &&
		 (ns.disk == Diskless || ns.pdsk == Diskless ) )
		rv=SS_SyncingDiskless;

	else if( (ns.conn == Connected ||
		  ns.conn == SkippedSyncS ||
		  ns.conn == WFBitMapS ||
		  ns.conn == SyncSource ||
		  ns.conn == PausedSyncS) &&
		 ns.disk == Outdated ) rv=SS_ConnectedOutdates;

	return rv;
}


int main(int argc, char **argv)
{
	drbd_role_t role, peer;
	drbd_conns_t conn;
	drbd_disks_t disk, pdsk;
	drbd_state_t s;
	int rv;
	unsigned long all=0, valid=0;

	for ( role = Primary ; role <= Secondary ; role++ ) {
		for ( peer = Unknown ; peer <= Secondary ; peer++ ) {
			for ( conn = StandAlone; conn <= PausedSyncT ; conn++ ) {
				for ( disk = Diskless ; disk <= UpToDate ; disk++) {
					for ( pdsk = Diskless ; pdsk <= UpToDate ; pdsk++) {
						s = (drbd_state_t){{ role,peer,conn,disk,pdsk }};
						rv = pre_state_checks(NULL,s);

						all++;
						if( rv == SS_Success ) {
							print_st(s,rv);
							valid++;
						}
					}
				}
			}
		}
	}

	printf("states considered: %lu\n",all);
	printf("valid(?) states: %lu\n",valid);

	return 0;
}

