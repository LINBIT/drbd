#!/usr/bin/perl -w

use strict;
use Digest::MD5;
use FileHandle;
use IPC::Open2;

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
      $brks =~ s/\\\{//g; #Things like strings and comments are not handeld.. 
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

  print $wfh "use Digest::MD5;\n"; ## hmmm, not generic.
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

sub main {
  my($rline,$lline);
  my($lpid,$lfh) = run_local('print_md5s("/dev/hde5",4096);');
  my($rpid,$rfh) = run_remote('print_md5s("/dev/hda1",4096);',"moni");

  while(1) {
    $lline=<$lfh>;
    $rline=<$rfh>;
    last if(!defined($lline) && !defined($rline));
    if(!defined($lline)) {
      print "local device smaller";
      last;
    }
    if(!defined($lline)) {
      print "remote device smaller";
      last;
    }
    if( $lline ne $rline) {
      print "l: $lline";
      print "r: $rline";
    }
  }
  waitpid $lpid,0;
  waitpid $rpid,0;
}

main;





