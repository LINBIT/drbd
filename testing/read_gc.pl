#!/usr/bin/perl -w

use strict;
use Fcntl;
use Fcntl ":seek";

use constant F_SIZE => 32;
use constant DRBD_MD_MAGIC => 0x83740267+3;
use constant BLKFLSBUF => 0x1261; # 0x1261 is BLKFLSBUF on intel.

sub read_print_gc_file($$$)
  {
    my ($md_dev,$md_index,$resource)=@_;
    my ($rr,$buffer,$pos,$md_start,$sector);

    sysopen (GCF,$md_dev,O_RDONLY)
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

    $rr=sysseek(GCF, $md_start, SEEK_SET);
    die "2nd seek failed rr=$rr md_start=$md_start" if ($rr != $md_start) ;

    $rr=sysread(GCF,$buffer,F_SIZE);
    die "can not read " if( $rr != F_SIZE );

    my ($size_u,$size,$Flags,$HumanCnt,$TimeoutCnt,$ConnectedCnt,$ArbitraryCnt,
	$MagicNr) =
      unpack("N8",$buffer);
    $size = $size + 4294967296 * $size_u;

    die "state file corrupt" if($MagicNr != DRBD_MD_MAGIC);

    printf(" %6s | %3s | %3d | %3d | %3d | %3d | %3s | %3s | %6d KB\n",
	   $resource,$Flags & 0x01 ? "1/c" : "0/i",$HumanCnt,$TimeoutCnt,
	   $ConnectedCnt,$ArbitraryCnt,$Flags & 0x02 ? "1/p" : "0/s",
	   $Flags & 0x04 ? "1/c" : "0/n",$size);

    ioctl(GCF,BLKFLSBUF,0);  # Ask the buffer cache to forget this buffer. 

    close(GCF);
  }


sub main()
{

    my (@resources,$res,$disk,$index);

    @resources = sort(split(' ',`drbdadm sh-resources`));

    print <<EOS;
                                     ConnectedInd |
                                  lastState |     |
                         ArbitraryCnt |     |     |
                   ConnectedCnt |     |     |     |
               TimeoutCnt |     |     |     |     |
           HumanCnt |     |     |     |     |     |
   Consistent |     |     |     |     |     |     |
resource|     |     |     |     |     |     |     |   Size
--------+-----+-----+-----+-----+-----+-----+-----+----------+
EOS

    for $res (@resources) {
	chomp($disk = `drbdadm sh-md-dev $res`);
	chomp($index = `drbdadm sh-md-idx $res`);
	read_print_gc_file($disk,$index,$res);
    }
}

main();

