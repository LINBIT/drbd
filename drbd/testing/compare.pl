#!/usr/bin/perl -w

use strict;
use Digest::MD5;
use FileHandle;
use IPC::Open2;
use Getopt::Long;
use POSIX;

sub print_md5s($$) {
  my ($devname,$blksize)=@_;
  my ($data,$rr,$blknum);

  open(INF,"<$devname") or die "can not open device";

  print "blksize: $blksize\n";

  $blknum=0;
  while($rr=sysread(INF,$data,$blksize)) {
    print "blk:$blknum md5:".Digest::MD5::md5_hex($data)."\n";
    $blknum++;
  }

  close INF;
}

sub send_sub($$) {
  my ($stream,$subroutine)=@_;
  my ($line,$in,$brks,$level,$was_positive);

  open(INF,"<$0") or die "can not open program text";

  $in=0;
  $level=0;
  $was_positive=0;
  while($line=<INF>) {

    if($line =~ m/(?:(?:^sub\s)|(?:\ssub\s))([^\s\(\{]+)/ ) {
      if ($1 eq $subroutine) {
	$in=1;
      }
    }

    if($in) {
      print $stream $line if ($in);

      $brks=$line;
      $brks =~ s/\\\{//g; #Things like strings and comments are not handeld.
      $brks =~ s/[^{]//g;
      $level=$level+length($brks);
      $was_positive=1 if ($level > 0);
      $brks=$line;
      $brks =~ s/\\\}//g;
      $brks =~ s/[^}]//g;
      $level=$level-length($brks);

      last if($level == 0 && $was_positive);
    }
  }

  close INF;
}

sub run_remote($$) {
  my ($statement,$host)=@_;
  my ($rfh,$wfh,$pid,$line,$subroutine);

  $pid=open2($rfh,$wfh,"ssh $host perl");

  if($statement =~ m/^([^(]+)/ ) {
    $subroutine=$1;
  }

  print $wfh "use strict;\n";
  print $wfh "use Digest::MD5;\n"; ## hmmm, this is not generic.
  send_sub($wfh,$subroutine);
  print $wfh $statement;
  close $wfh;

  return ($pid,$rfh);
}

sub run_local($) {
  my ($statement,$host)=@_;
  my($pid);
  $pid=open(PIPE,"-|");
  if($pid == 0) {
    eval $statement;
    exit 0;
  }

  return ($pid,\*PIPE);
}

sub check_ssh($) {
  my ($host)=@_;
  my ($pid,$cnt,$r);

  if( $> != 0) {
    print
      " Since this script needs to read from block devices it is very \n".
      " likely that you need to run it as root.\n";
  }

  $pid=fork();
  if($pid==0) {
    exec "ssh $host echo It works > /dev/null 2> /dev/null ";
  }

  for($cnt=0;$cnt<3;$cnt++) {
    $r=waitpid($pid,&POSIX::WNOHANG);
    if($r==0) {
      sleep 1;
      print ".";
    } elsif ($r==$pid) {
      return;
    } else {
      print "waitpid() failed\n";
    }
  }

  kill 9,$pid;
  print
    " This scripts needs to make ssh connections to your machines \n".
    " without using a password.\n".
    " \n".
    " use ssh-keygen and ~/.ssh/authorized_keys (or authorized_keys2) to \n".
    " make this possible.\n";
  waitpid($pid,0);
  exit 10;
}

sub main {
  my($rline,$lline,$cbn,$lt,$lbc,$cbc);
  my($lpid,$lfh,$rpid,$rfh,$lname,$rname,$ldev,$rdev);
  my $blksize=4096;

  GetOptions("blksize=i" => \$blksize);

  if($#ARGV != 2 && $#ARGV != 3) {
    print "USAGE: $0 [options] local_blk_dev host remote_blk_dev\n".
          "   OR: $0 [options] host1 blk_dev1 host2 bkl_dev2\n".
	  " options: --blksize=BYTES\n\n";
    exit 10;
  }

  if($#ARGV == 2) {
    $lname="localhost";
    ($ldev,$rname,$rdev)=@ARGV;
  } else {
    ($lname,$ldev,$rname,$rdev)=@ARGV;
  }

  waitpid(-1,&POSIX::WNOHANG); # to load the posix pm ...
  check_ssh($rname);

  if($lname eq "localhost") {
    ($lpid,$lfh) = run_local("print_md5s(\"${ldev}\",${blksize});");
  } else {
    ($lpid,$lfh) = run_remote("print_md5s(\"${ldev}\",${blksize});",$lname);
  }
  ($rpid,$rfh) = run_remote("print_md5s(\"${rdev}\",${blksize});",$rname);

  $lt=0;
  $lbc=0;
  while(1) {
    $lline=<$lfh>;
    $rline=<$rfh>;
    last if(!defined($lline) && !defined($rline));
    if(!defined($lline)) {
      print "\ndevice on $lname smaller\n";
      last;
    }
    if(!defined($lline)) {
      print "\ndevice on $rname smaller\n";
      last;
    }
    if( $lline ne $rline) {
      print "$lname: $lline";
      print "$rname: $rline";
    } elsif ($lt != time()) {
      $lt=time();
      if ( $lline =~ /^blk:(\d+)/ ) {
	$cbc=$1;
	print "Current block: $cbc Speed: ".($cbc-$lbc)*$blksize/1048576
	  ." MB/s              \r";
	$lbc=$cbc;
      }
    }
  }

  close $lfh;
  close $rfh;

  waitpid($lpid,0);
  waitpid($rpid,0);
}

$|=1;
main;





