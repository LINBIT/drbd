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
