From: Erik de Wilde <E.deWilde@eijsink.nl>
Subject: Re: [DRBD-dev] Bad performance when disks mounted with sync but data
+corruption without sync
To: Philipp Reisner <philipp.reisner@linbit.com>
Cc: drbd-devel@lists.sourceforge.net
From E.deWilde@eijsink.nl  Tue Feb 26 14:10:30 2002

Hi,

I did some testing, and I think I know what gave me the bad throughput

I rebuild the filesystem on /dev/nb0 with reiserfs v3.6 in order not to
have to use the sync option for mounting /dev/nbo
on the server.  This didn't give me a good throughput, but it doubled
from 64kB/sec to 128kB/sec, without data corruption on failover.

I discovered I was using the sync option while mounting the filesystem
on the workstation. I turned this off and guess what,
througput now is about 2.5MB/sec, also without data-corruption during
fail-over.

I was wondering what would happen if I also turned off sync and
no_wdelay on the server.
Well, I tried and througput was 4.2MB/sec BUT I got DATA-CORRUPTION
during failover.

Conclusions:

If using a non-journalling filesystem like ext2 one should mount
/dev/nb0 with the sync option. (Why things where messed up for me using
ext3 is still not clear to me). The sync option is not needed for
journalling filesystems like reiserfs
Example fstab entries (Just use one for each nbd device) for mounting
/dev/nb0 on /drbd0:
/dev/nb0        /drbd0  ext2             noauto,sync  0 0
/dev/nb0        /drbd0  reiserfs        noauto          0 0

Use the sync and no_wdelay option in your /etc/exports file on the
server or else you will get data-corruption on fail-over
Exampe exports entries:
/drbd0/export         *(rw,no_root_squash,sync,no_wdelay)

Do NOT USE THE SYNC OPTION while mounting the NFS filesystem on your
client (workstation). When you do, things
will slow down terribly

Regards, Erik de Wilde


From: Erik de Wilde <E.deWilde@eijsink.nl>
Subject: [DRBD-dev] Stale NFS handles
Date: Tue, 05 Mar 2002 16:27:34 +0100
 
Hello,
 
I read some messages about stale NFS handles and I thought some of you
would be interested in this information.
Until a few hours ago I got Stale NFS handles during fail-back
operation, and it was reproducable.
I first thought there was something wrong with DRBD's sync or that it
had to do with heartbeat, but no, it
was my nfsserver script that was causing them.
In my nfsserver script there was the following line:
/usr/sbin/exportfs -au
This causes an unexport of all directories, which means that your server
is really telling to its clients that it is going down, and this
definitly is something YOU DO NOT WANT TO HAPPEN.
Just execute the command on your server while copying big files to your
server and look at the screen of your workstation.
 
So, if you don't want the Stale NFS handles to occur, just get rid of
the line containing something like /usr/sbin/exportfs -au
And, do not forget to do the same for the script in the /etc/rc.d (or
/etc/init.d) directory or you will still get the same
to happen when rebooting your fileserver (the one that is  actually
exporting the filesystem at that moment)
 
Regards, Erik de Wilde
