#!/usr/bin/perl -w

use strict;
use constant F_SIZE => 32;
use constant DRBD_MD_MAGIC => 0x83740269;

sub read_print_gc_file($)
  {
    my $minor=shift;
    my ($rr,$buffer);

    open (GCF,"/var/lib/drbd/drbd".$minor)
      or die "can not open GC file";

    $rr=sysread(GCF,$buffer,F_SIZE);
    die "can not read 24 bytes" if($rr != F_SIZE );

    my ($size_u,$size,$Flags,$HumanCnt,$TimeoutCnt,$ConnectedCnt,$ArbitraryCnt,
	$MagicNr) =
      unpack("N8",$buffer);
    # $size = $size + 4294967296 * $size_u;

    die "state file corrupt" if($MagicNr != DRBD_MD_MAGIC);

    printf(" drbd%d | %3s | %3d | %3d | %3d | %3d | %3s | %3s | %6d \n",
	   $minor,$Flags & 0x01 ? "1/c" : "0/i",$HumanCnt,$TimeoutCnt,
	   $ConnectedCnt,$ArbitraryCnt,$Flags & 0x02 ? "1/p" : "0/s",
	   $Flags & 0x04 ? "1/c" : "0/n",size);
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
device |     |     |     |     |     |     |     |  Size
-------+-----+-----+-----+-----+-----+-----+-----+--------+
EOS
while( -e "/var/lib/drbd/drbd$count" ) {
  read_print_gc_file($count);
  $count++;
}




