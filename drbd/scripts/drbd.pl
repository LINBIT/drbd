#!/usr/bin/perl -w
#
# chkconfig: 345 30 70
# description: Loads and unloads the drbd module
#
# complete rewrite from scratch by Philipp Reisner in March and April 2001
# rewritten in perl in May
#

use strict;
use Sys::Hostname;
use Data::Dumper;

my $drbdsetup="/usr/sbin/drbdsetup";
my $modprobe="/sbin/modprobe";
my $rmmod="/sbin/rmmod";

my @get_token_line;
my $token_line=0;
my ($pname,$resource,$command);
my %conf;

#=================
# The parser for the configuration file
#

sub get_token()
  {
    my $token;
    if($#get_token_line < 0) {
      while(<CONFIG>) {
	$token_line++;
	chomp;                  # no newline
	s/\#.*//;               # no comments
	s/^\s+//;               # no leading white
	s/\s+$//;               # no trailing white
	next unless length;     # anything left?
	if( m/=/ ) { return $_; }
	else       { @get_token_line=split(/ /,$_); }
	return shift @get_token_line;
      }
    }
    $token=shift @get_token_line;
    if($token) { return $token; }
    return undef;
  }

sub open_section()
  {
    my $token=get_token();
    if($token ne "{") {
      die "$pname: expected { found $token in line $token_line";
    }
  }

sub skip_section()
  {
    my ($token,$dept);
    while($token=get_token())
      {
	if($token eq "{") { $dept++; }
	if($token eq "}") { $dept--; }
	if($dept == 0) { return; }
      }
  }

sub read_host_section($)
{
  my $mconf=shift;
  my ($token,$name,$val);
  my %valid=("device" => "n",
	     "disk" => "n",
	     "address" => "n",
	     "port" => "n",
	    );

  open_section();

  while($token=get_token()) {
    if( $token =~ /=/ ) {
      ($name,$val)=split(/=/,$_);
      if($valid{$name} eq "n") {
	$valid{$name}="d";
	$$mconf{$name}=$val;
	next;
      } else { die "$pname: unexpected token $token in line $token_line";}
    }
    if( $token eq "}") {
      foreach $name (keys %valid) {
	if($valid{$name} eq "n") {
	  die "$pname: $name not defined in line $token_line";
	}
      }
      return;
    }
    die "$pname: unexpected token $token in line $token_line";
  }
}

sub read_option_section($)
{
  my $mconf=shift;
  my ($token,$val);

  open_section();

  while($token=get_token()) {
	if($token eq "}") { return; }
	$$mconf=$$mconf." --".$token;
    }
}

sub read_resource_sec($)
{
    my $mconf=shift;
    my ($token,$name);
    my %this;

    $name=get_token();
    $$mconf{$name}=\%this;

    $this{"disk"}="";
    $this{"net"}="";

    open_section();

    while($token=get_token()) {
      if($token eq "disk" || $token eq "net") {
	  read_option_section(\$this{$token});
	  next;
      }
      if($token eq "on") {
	$name=get_token();
	if($name eq hostname()) {
	  read_host_section($this{"self"}={});
	} else {
	  read_host_section($this{"other"}={});
	}
	next;
      }
      if( $token =~ /^protocol=(.*)/ ) { $this{"protocol"}=$1; next; }
      if( $token =~ /^fsckcmd=(.*)/ ) { $this{"fsckcmd"}=$1; next;}
      if($token eq "}") {
	if(! $this{"protocol"} || !$this{"fsckcmd"}) {
	  die "$pname: protocol or fsckcmd missing line $token_line";
	}
	if(! $this{"self"}) {
	  die "$pname: This host not mentioned until line $token_line";
	}
	if(! $this{"other"}) {
	  die "$pname: No partner host mentioned until line $token_line";
	}
	return;
      }
      die "$pname: unexpected token $token in line $token_line";
    }
  }

sub read_config()
{
    my $token;

    open (CONFIG,"</etc/drbd.conf")
	or die "can not open config file";

    while($token=get_token()) {
      if($token eq "resource") { read_resource_sec(\%conf); next; }
      die "$pname: unexpected token $token in line $token_line";
    }

    close CONFIG;
}

#
# End of parser
#=================
# These functions are called by the parser to perform the actual actions.
# They will find these variables in the environment:
#  $RES $DEVICE $DISK $DISK_OPTS $ADDR $O_ADDR $PROTO $NET_OPTS $FSCK_CMD
#

sub doconfig($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt);
    
    print "Setting up $res...";
    $errtxt=`$drbdsetup $$mconf{self}{device} disk $$mconf{self}{disk} $$mconf{disk}`;
    if($errtxt) { die "$errtxt"; }
    $errtxt=`$drbdsetup $$mconf{self}{device} net $$mconf{self}{address}:$$mconf{self}{port} $$mconf{other}{address}:$$mconf{other}{port} $$mconf{protocol} $$mconf{net}`;
    if($errtxt) { die "$errtxt"; }
    print "[ OK ]\n";
}

sub wait_ready($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt,$pid);

    $pid=fork();
    if($pid == 0) {
	my ($cstate,$state);

	$errtxt=`$drbdsetup $$mconf{self}{device} wait_connect`;
	if($errtxt) { die "$errtxt"; }

	($cstate,$state) = get_drbd_status($$mconf{self}{device});
#	print "\n$$mconf{self}{device} is $cstate,$state";
	if($cstate =~ m/^Syncing/ && $state eq "Secondary" ) {
	    print "\nWaiting until $res is up to date (using $cstate) abort? ";
	    $errtxt=`$drbdsetup $$mconf{self}{device} wait_sync`;
	    if($errtxt) { die "$errtxt"; }
	    `$drbdsetup $$mconf{self}{device} secondary_remote 2>&1`;
	    # No error check here, on purpose!		
	}
	exit 0;
    } elsif( $pid == -1 ) {
	die "fork failed";
    }

    return $pid;    
}

sub increase_h_count($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt);
    
    print "Setting up $res...";
    $errtxt=`$drbdsetup $$mconf{self}{device} primary --human`;
    if($errtxt) { die $errtxt; }
    $errtxt=`$drbdsetup $$mconf{self}{device} secondary`;
    if($errtxt) { die $errtxt; }
}


sub become_pri($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt,$line,$mounted);

    $errtxt=`$drbdsetup $$mconf{self}{device} primary`;
    if($errtxt) { die $errtxt; }
    
    open(MOUNT,"mount |")
  	or die " can not execute mount";

    $mounted=0;
    while($line=<MOUNT>) {
  	if( index($line,$$mconf{self}{device}) < 0 ) {
	    print "pname: $$mconf{self}{device} is already mounted";
	    $mounted=1;
  	}
    }
    close MOUNT;

    if(! $mounted) {
	`$$mconf{fsckcmd} $$mconf{self}{device}`;
	`mount $$mconf{self}{device}`;
    }
}


sub become_sec($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt,$line,$mounted);

    `$drbdsetup $$mconf{self}{device} secondary 2>&1`;    
    if ( $? ) {
	`umount $$mconf{self}{device} 2> /dev/null`;
	if ( $? ) {
	    `fuser -k -m $$mconf{self}{device} > /dev/null`;
	    sleep 1; #Hopefully the signals get delivered within one second...
	    $errtxt=`umount $$mconf{self}{device} 2>&1`;
	    if ( $? ) {
		print "$pname: umount FAILED:";
		die $errtxt;
	    }
	}
	$errtxt=`$drbdsetup $$mconf{self}{device} secondary 2>&1`;
	if ( $? ) {
	    print "$pname: drbdsetup FAILED:";
	    die $errtxt;
	}
    }
}

#
# End of action functions.
#=================
# Helpers 
#

sub get_drbd_status($)
{
    my ($device)=@_;
    my ($minor,$line);

    $minor=$device;
    $minor =~ s/\/dev\/nb//;

    open (PROC,"</proc/drbd")
	or die "can not open /proc/drbd";

    while($line = <PROC>) {
	if($line =~ /^(\d+):\scs:(\w+)\sst:(\w+)\//) {
	    if($1==$minor) {
		close(PROC);
		return ($2,$3);
	    }
	}	    
    }
    close (PROC);
    die "My minor not found in /proc/drbd";
}


sub ask_for_abort()
{
    my ($pid,$in);

    print "Do you want to abort waiting for other server and make this one primary? ";
    $pid=fork();
    if($pid == 0) {
	while($in=<STDIN>) {
	    chomp $in;
	    if($in eq "yes") { exit 0; }
	    print "Answer either \"yes\" or not at all: "
	}
	exit 10;
    } elsif( $pid == -1 ) {
	die "fork failed";
    }

    return $pid;
}

sub fcaller($)
{
    my ($function)=@_;
    my ($res,%ret,$rv);

    if($resource) { 
	$rv=&$function($resource,$conf{$resource}); 
	if($rv) {$ret{$rv}=$resource;}
    }
    else {
	foreach $res (keys %conf) {
	    $rv=&$function($res,$conf{$res}); 
	    if($rv) {$ret{$rv}=$res;}
	}
    }
    return %ret;
}

#
# End of helpers.
#=================
# Here we have the implementation of the commands.
#

sub drbd()
{
    if($command eq "start") { 
	my (%syncers,$user,$pid);
	# load the module 
	if ( ! -e "/proc/drbd" ) {
	    my $minor_count=scalar(keys %conf);
	    `$modprobe -s drbd minor_count=$minor_count`;
	    if( $? ) {
		die "$pname: Can not load the drbd module.";
	    }
	}
	# configure the devices etc...
	fcaller( \&doconfig );
	$user = ask_for_abort();
	%syncers = fcaller( \&wait_ready );	
	if (scalar(keys %syncers) == 0) { die "no child processes"; }
	while(1) {
	    $pid = wait();
	    if($pid == $user) {
		my $res;
		
		kill 'INT',keys %syncers;
		foreach $res (keys %syncers) {
		    increase_h_count($res,$conf{$res});
		}
		last;
		
	    }
	    if($syncers{$pid}) {
		my $res=$syncers{$pid};
		delete $syncers{$pid};
		if (scalar(keys %syncers) == 0) {
		    print "no\n";
		    kill 'INT',$user;			
		    last;
		}
		next;
	    }
	    print "$user ",keys %syncers," $syncers{$pid}\n";
	    die "Wait returned strange pid $pid";
	}
    } elsif ($command eq "stop") { 
	if ( -e "/proc/drbd" ) {
	    `$rmmod -s drbd`;
	    if( $? ) {
		die "$pname: Can not unload the drbd module.";
	    }
	}
    } else {
	print "USAGE: drbd [resource] start|stop\n";
    }
    exit 0;
}

sub datadisk()
{
    if($command eq "start") { 
	fcaller( \&become_pri );
    } elsif ($command eq "stop") { 
	fcaller( \&become_sec );
    } elsif ($command eq "status") { 
	# TODO: status.
    } else {
	print "USAGE: datadisk [resource] start|stop|status\n";
    }

}

sub basename($)
{
  my @name=split(/\//,shift);
  return pop @name;
}


$pname=basename($0);
$|=1;

if($#ARGV == 1) {
    $resource=$ARGV[0];
    $command=$ARGV[1];
} elsif ($#ARGV == 0) {
    $command=$ARGV[0];
} else { die "USAGE: $pname [ressource] start|stop|status"; }

read_config();
#print Dumper(\%conf);

if( $pname =~ /drbd$/ ) { drbd(); }
elsif( $pname =~ /datadisk$/ ) { datadisk(); }
else { die "do not know what to do"; }
