#!/usr/bin/perl -w

use strict;
use constant F_SIZE => 24;
use constant DRBD_MAGIC => 0x83740267;
use Fcntl;
use File::Path;

sub write_gc_file($ $ $ $ $ $)
  {
      my $minor        = $_[0];
      my $Consistent   = $_[1];
      my $HumanCnt     = $_[2];
      my $ConnectedCnt = $_[3];
      my $ArbitraryCnt = $_[4];
      my $PrimaryInd   = $_[5];
      my $MagicNr = DRBD_MAGIC;
      my ($out, $written);
      my @entry;
      
      # Delete the existing meta-data file.
      unlink ("/var/lib/drbd/drbd".$minor); # ignore return code 

      # Create the directory if needed.
      @entry = stat("/var/lib/drbd")
          or mkpath( "/var/lib/drbd", 0, 0755 );

      $out = pack("N6", $Consistent,$HumanCnt,$ConnectedCnt,
                  $ArbitraryCnt,$PrimaryInd, $MagicNr);

      sysopen GCF, "/var/lib/drbd/drbd".$minor, O_RDWR | O_CREAT
          or die "sysopen /var/lib/drbd/drbd\n";

      $written = syswrite(GCF, $out, length($out));
      die "syswrite failed: $!\n" unless $written == length($out);

      printf(" device  | Consistent | HumanCnt | ConnectedCnt | ArbitraryCnt |".
             " lastState\n");
      printf(" drbd%d       %3d          %3d           %3d           %3d   ".
             "      %s\n",
             $minor,$Consistent,$HumanCnt,$ConnectedCnt,$ArbitraryCnt,
             $PrimaryInd ? "primary" : "secondary" );
      close(GCF);
  }

my ($f1, $f2, $f3, $f4, $f5, $f6) = @ARGV;
write_gc_file($f1, $f2, $f3, $f4, $f5, $f6);

