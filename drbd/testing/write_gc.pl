#!/usr/bin/perl -w

use strict;
use Fcntl;
use Fcntl ":seek";

use constant F_SIZE => 32;
use constant DRBD_MD_MAGIC => 0x83740267+3;
use constant BLKFLSBUF => 0x1261; # 0x1261 is BLKFLSBUF on intel.

sub ensure_default
{
    my($ref,$text,$default) = @_;

    if(!defined($$ref)) {
	print "Assuming $text = $default\n";
	$$ref = $default;
    }
}

sub write_gc_file
{
    my ($ll_dev,$Consistent,$HumanCnt,$TimeoutCnt,$ConnectedCnt,$ArbitraryCnt,
	$lastState,$ConnectedInd) = @_;
    my ($Flags,$rr,$pos,$out);

    ensure_default(\$Consistent,"Consistent",1);
    ensure_default(\$HumanCnt,"HumanCnt",1);
    ensure_default(\$TimeoutCnt,"TimeoutCnt",1);
    ensure_default(\$ConnectedCnt,"ConnectedCnt",1);
    ensure_default(\$ArbitraryCnt,"ArbitraryCnt",1);
    ensure_default(\$lastState,"lastState",0);
    ensure_default(\$ConnectedInd,"ConnectedInd",0);

    sysopen (GCF,$ll_dev,O_WRONLY)
	or die "can not open GC file";

    ioctl(GCF,BLKFLSBUF,0);
    # DRBD uses its private buffer for writing meta data, therefore
    # we flush all the buffer cache's buffers of the device. Without
    # this we would simply the same values at subsequent calls, that
    # we saw at the first call.

    $pos=sysseek(GCF, 0, SEEK_END);
    $pos = (int($pos / (4*1024)) - 1) * (4*1024) + 8;

    $rr=sysseek(GCF, $pos, SEEK_SET);
    die "2nd seek failed rr=$rr pos=$pos" if ($rr != $pos) ;

    $Flags = 0;
    if($Consistent)    { $Flags |= 0x01; }
    if($lastState)     { $Flags |= 0x02; }
    if($ConnectedInd)  { $Flags |= 0x04; }

    $out = pack("N6", $Flags,$HumanCnt,$TimeoutCnt,$ConnectedCnt,
		$ArbitraryCnt, DRBD_MD_MAGIC);

    $rr = syswrite(GCF, $out, length($out));
    die "syswrite failed: $!\n" unless $rr == length($out);

    ioctl(GCF,BLKFLSBUF,0);  # Ask the buffer cache to forget this buffer. 

    close(GCF);
}

sub main
{
    my ($res, @other_args) = @_;
    my $disk;

    if(!defined($res)) {
	print "USAGE: write_gc.pl resource-name\n";
	exit 10;
    }
    chomp($disk = `drbdadm sh-ll-dev $res`);

    write_gc_file($disk,@other_args);

}


main(@ARGV);

