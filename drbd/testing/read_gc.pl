#!/usr/bin/perl -w

use strict;
use constant F_SIZE => 24;
use constant DRBD_MAGIC => 0x83740267;

sub read_print_gc_file($)
  {
    my $minor=shift;
    my ($rr,$buffer);

    open (GCF,"/var/lib/drbd/drbd".$minor)
      or die "can not open GC file";

    $rr=sysread(GCF,$buffer,F_SIZE);
    die "can not read 24 bytes" if($rr != F_SIZE );

    my ($Consistent,$HumanCnt,$ConnectedCnt,$ArbitraryCnt,$PrimaryInd,
	$MagicNr) = unpack("N6",$buffer);

    die "state file corrupt" if($MagicNr != DRBD_MAGIC);

    printf(" drbd%d       %3d          %3d           %3d           %3d   ".
	   "      %s\n",
	   $minor,$Consistent,$HumanCnt,$ConnectedCnt,$ArbitraryCnt,
	   $PrimaryInd ? "primary" : "secondary" );

    close(GCF);
  }


my $count=0;

printf(" device  | Consistent | HumanCnt | ConnectedCnt | ArbitraryCnt |".
       " lastState\n");
while( -e "/var/lib/drbd/drbd$count" ) {
  read_print_gc_file($count);
  $count++;
}




