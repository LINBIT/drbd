#!/usr/bin/perl -w

use strict;
use constant F_SIZE => 24;
use constant DRBD_MD_MAGIC => 0x83740269;

sub read_print_gc_file($)
  {
    my $minor=shift;
    my ($rr,$buffer);

    open (GCF,"/var/lib/drbd/drbd".$minor)
      or die "can not open GC file";

    $rr=sysread(GCF,$buffer,F_SIZE);
    die "can not read 24 bytes" if($rr != F_SIZE );

    my ($Flags,$HumanCnt,$TimeoutCnt,$ConnectedCnt,$ArbitraryCnt,$MagicNr) =
      unpack("N6",$buffer);

    die "state file corrupt" if($MagicNr != DRBD_MD_MAGIC);

    printf(" drbd%d | %3s | %3d | %3d | %3d | %3d | %3s | %3s |\n",
	   $minor,$Flags & 0x01 ? "1/c" : "0/i",$HumanCnt,$TimeoutCnt,
	   $ConnectedCnt,$ArbitraryCnt,$Flags & 0x02 ? "1/p" : "0/s",
	   $Flags & 0x04 ? "1/c" : "0/n");
    close(GCF);
  }


my $count=0;

print <<EOS;
                                    ConnectedInd |
                                 lastState |     |
                        ArbitraryCnt |     |     |
                  ConnectedCnt |     |     |     |
              TimeoutCnt |     |     |     |     |
          HumanCnt |     |     |     |     |     |
  Consistent |     |     |     |     |     |     |
device |     |     |     |     |     |     |     |
-------+-----+-----+-----+-----+-----+-----+-----+
EOS
while( -e "/var/lib/drbd/drbd$count" ) {
  read_print_gc_file($count);
  $count++;
}




