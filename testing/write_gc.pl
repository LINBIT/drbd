#!/usr/bin/perl -w

use strict;
use Fcntl;
use Fcntl ":seek";

use constant F_SIZE => 32;
use constant DRBD_MD_MAGIC => 0x83740267+3;
use constant BLKFLSBUF => 0x1261; # 0x1261 is BLKFLSBUF on intel.
use constant MD_AL_OFFSET =>   8  * 512;
use constant MD_AL_MAX_SIZE => 64 * 512;

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
    my ($md_dev,$md_index,$del_al,$Consistent,$HumanCnt,$TimeoutCnt,
	$ConnectedCnt,$ArbitraryCnt,$lastState,$ConnectedInd,
	$WantFullSync) = @_;
    my ($Flags,$rr,$pos,$md_start,$out);

    ensure_default(\$Consistent,"Consistent",1);
    ensure_default(\$HumanCnt,"HumanCnt",1);
    ensure_default(\$TimeoutCnt,"TimeoutCnt",1);
    ensure_default(\$ConnectedCnt,"ConnectedCnt",1);
    ensure_default(\$ArbitraryCnt,"ArbitraryCnt",1);
    ensure_default(\$lastState,"lastState",0);
    ensure_default(\$ConnectedInd,"ConnectedInd",0);
    ensure_default(\$WantFullSync,"WantFullSync",0);

    sysopen (GCF,$md_dev,O_WRONLY)
	or die "can not open GC file";

    ioctl(GCF,BLKFLSBUF,0);
    # DRBD uses its private buffer for writing meta data, therefore
    # we flush all the buffer cache's buffers of the device. Without
    # this we would simply the same values at subsequent calls, that
    # we saw at the first call.

    if ($md_index == -1) {
	$pos = sysseek(GCF, 0, SEEK_END);
	$md_start = (int($pos / (4*1024)) * (4*1024)) - 128 *1024*1024;
    } else {
	$md_start = 128*1024*1024*$md_index;
    }

    $rr=sysseek(GCF, $md_start+8, SEEK_SET);
    die "2nd seek failed rr=$rr md_start=$md_start" if ($rr != $md_start+8) ;

    $Flags = 0;
    if($Consistent)    { $Flags |= 0x01; }
    if($lastState)     { $Flags |= 0x02; }
    if($ConnectedInd)  { $Flags |= 0x04; }
    if($WantFullSync)  { $Flags |= 0x08; }

    $out = pack("N5", $Flags,$HumanCnt,$TimeoutCnt,$ConnectedCnt,
		$ArbitraryCnt);

    $rr = syswrite(GCF, $out, length($out));
    die "syswrite failed: $!\n" unless $rr == length($out);

    if($del_al) {	
	$rr=sysseek(GCF, $md_start + MD_AL_OFFSET, SEEK_SET);
	if ($rr != $md_start+MD_AL_OFFSET) {
	    die "seek failed rr=$rr md_start=$md_start"
	    }

	$out = "\0" x 4096;
	my($todo, $size);
	$todo = MD_AL_MAX_SIZE;
	while( $todo > 0 ) {
	    $size = $todo < 4096 ? $todo : 4096;
	    $rr = syswrite(GCF, $out, $size);
	    if( $rr != $size ) {
		print "syswrite failed $rr\n";
		last;
	    }
	    $todo -= $size;
	}
    }

    ioctl(GCF,BLKFLSBUF,0);  # Ask the buffer cache to forget this buffer. 

    close(GCF);
}

sub main
{
    my ($res, $opt, @other_args) = @_;
    my ($disk,$index,$del_al);

    if(!defined($res)) {
	print "USAGE: write_gc.pl resource-name [--del-al] counter-values...\n";
	exit 10;
    }

    if($opt eq "--del-al") {
	$del_al=1;
    } else {
	unshift @other_args,$opt;
	$del_al=0;
    }

    chomp($disk = `drbdadm sh-md-dev $res`);
    chomp($index = `drbdadm sh-md-idx $res`);

    write_gc_file($disk,$index,$del_al,@other_args);

}


main(@ARGV);
