#!/usr/bin/perl -w
#
# chkconfig: 345 60 40
# description: Loads and unloads the drbd module
#
# complete rewrite from scratch by Philipp Reisner in March and April 2001
# rewritten in perl in May
#
# with patches form:
#  Thomas Stinner <t.stinner@billiton.de>
#  Sergio Talens-Oliag <sto@isoco.com>
#  Martin Bene <Martin.Bene@KPNQwest.com>
#

use strict;
use Sys::Hostname;
#use Data::Dumper;

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
    my $host_name;

    $host_name=(split(/\./,hostname()))[0];

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
	if($name eq $host_name) {
	  read_host_section($this{"self"}={});
	} else {
	  read_host_section($this{"other"}={});
	}
	next;
      }
      if( $token =~ /^protocol=(.*)/ ) { $this{"protocol"}=$1; next; }
      if( $token =~ /^inittimeout=(.*)/ ) { $this{"inittimeout"}=$1; next; }
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
	if(! $this{"inittimeout"}) {
	  $this{"inittimeout"}="0";
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

#FIXME: Check returncodes, not output!
    my ($res,$mconf)=@_;
    my ($errtxt);
    
    print "Setting up $res...";
    $errtxt=`$drbdsetup $$mconf{self}{device} disk $$mconf{self}{disk} $$mconf{disk} 2>&1`;
    if( $? ) { die "$errtxt"; }
    $errtxt=`$drbdsetup $$mconf{self}{device} net $$mconf{self}{address}:$$mconf{self}{port} $$mconf{other}{address}:$$mconf{other}{port} $$mconf{protocol} $$mconf{net} 2>&1`;
    if( $? ) { die "$errtxt"; }
    print "[ OK ]\n";
}

sub wait_ready($$)
{
    my ($res,$mconf)=@_;
    my ($pid);

    $pid=fork();
    if(!defined($pid)) { die "fork failed"; }
    if($pid == 0) {
	my ($cstate,$state,$child);

	m_system("$drbdsetup $$mconf{self}{device} wait_connect -t $$mconf{inittimeout}");

	($cstate,$state) = get_drbd_status($$mconf{self}{device});
#	print "\n$$mconf{self}{device} is $cstate,$state";
	if($cstate =~ m/^Syncing/ && $state eq "Secondary" ) {
	    print "\nWaiting until $res is up to date (using $cstate) abort? ";
	    m_system("$drbdsetup $$mconf{self}{device} wait_sync");
	    sleep 4; # This is necesary since DRBD does not yet include
	             # the syncer's blocks in the unacked_cnd 
	             # Quick and dirty :(
	    `$drbdsetup $$mconf{self}{device} secondary_remote 2>&1`;
	    # No error check here, on purpose!		
	}
	exit 0;
    }

    return $pid;    
}

sub increase_h_count($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt);
    
    $errtxt=`$drbdsetup $$mconf{self}{device} primary --human 2>&1`;
    if( $? ) { die $errtxt; }
#    $errtxt=`$drbdsetup $$mconf{self}{device} secondary`;
#    if($errtxt) { die $errtxt; }
}


sub become_pri($$)
{
    my ($res,$mconf)=@_;
    my ($errtxt,$line,$mounted);

    $errtxt=`$drbdsetup $$mconf{self}{device} primary 2>&1 `;
    if( $? ) { die $errtxt; }
    
    open(MOUNT,"mount |")
  	or die " can not execute mount";

    $mounted=0;
    while($line=<MOUNT>) {
  	if( index($line,$$mconf{self}{device}) > -1 ) {
	    print "pname: $$mconf{self}{device} is already mounted\n";
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
	    sleep 3; #Hopefully the signals get delivered within 3 seconds..
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

sub reconnect($$)
{
    my ($res,$mconf)=@_;
    my $errtxt;

    $errtxt=`$drbdsetup $$mconf{self}{device} net $$mconf{self}{address}:$$mconf{self}{port} $$mconf{other}{address}:$$mconf{other}{port} $$mconf{protocol} $$mconf{net} 2>&1 `;
    if( $? ) { die "$errtxt"; }

}

sub drbd_status($$)
{
    my ($res,$mconf)=@_;
    my $cs;
    my %retcode_table = ("Unconfigured"   => "stopped",
			 "StandAlone"     => "stopped",
			 "Unconnected"    => "stopped",
			 "Timeout"        => "stopped",
			 "BrokenPipe"     => "stopped",
			 "WFConnection"   => "stopped",
			 "WFReportParams" => "stopped",
			 "Connected"      => "running",
			 "SyncingAll"     => "running",
			 "SyncingQuick"   => "running");
    
    ($cs,undef)=get_drbd_status($$mconf{self}{device});

    return $retcode_table{$cs};
}

sub datadisk_status($$)
{
    my ($res,$mconf)=@_;
    my $st;
    my %retcode_table = (
		         "Primary"      => "running",
		         "Secondary"    => "stopped",
		         "Unknown"      => "stopped");
    
    (undef,$st)=get_drbd_status($$mconf{self}{device});

    return $retcode_table{$st};
}

#
# End of action functions.
#=================
# Helpers 
#

sub m_system($)
{ 
    my $cmd=shift;
    my $pid;

    $pid=fork();
    if(!defined($pid)) { die "fork failed"; }
    if($pid == 0) {
	exec $cmd;
	die "exec failed";
    }
    $SIG{INT}=sub { kill 'INT',$pid; }; #closures are really nice.
    wait();
    if( $? & 127 ) { exit 0; } #we got a signal.
    return ($? >> 8);
}

sub get_drbd_status($)
{
    my ($device)=@_;
    my ($minor,$line,@st);

    if ( -b $device && (@st = stat(_))) {
	#$major = ($st[6] & 0xff00) >> 8;
	$minor = $st[6] & 0xff;
    } else { die "Can not stat $device (or it is not a block device)"; }

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
    if(!defined($pid)) { die "fork failed"; }
    if($pid == 0) {
	while($in=<STDIN>) {
	    chomp $in;
	    if($in eq "yes") { exit 0; }
	    print "Answer either \"yes\" or not at all: "
	}
	exit 10;
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
    } else {
	foreach $res (keys %conf) {
	    $rv=&$function($res,$conf{$res}); 
	    if($rv) {$ret{$rv}=$res;}
	}
    }
    return %ret;
}

sub status_fcaller($)
{
    my ($function)=@_;
    my ($res,$status);

    if($resource) {
	$status=&$function($resource,$conf{$resource});
    } else {
	$status="running";
	foreach $res (keys %conf) {
	    $status="stopped" if(&$function($res,$conf{$res}) eq "stopped");
	}
    }
    return $status;
}

sub u_check($$)
{
    my ($name,$func)=@_;
    my (%hash,$res,$obj);

    foreach $res (keys %conf) {
	$obj=&$func($res);
	if(defined($hash{$obj})) { 
	    die "$name $obj used by resource $res and $hash{$obj}.";
	}
	$hash{$obj}=$res;
    }
}

sub sanity_checker()
{
    u_check("Device", sub { my $res=shift; return $conf{$res}{self}{device};});
    u_check("Disk", sub { my $res=shift; return $conf{$res}{self}{disk}; } );
    u_check("Address/port",
	    sub { my $res=shift;
		return $conf{$res}{self}{address}.":".$conf{$res}{self}{port};
	    } );
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
		my $mpid;
		
		kill 'INT',keys %syncers;

		foreach $mpid (keys %syncers) {
		    increase_h_count($syncers{$mpid},$conf{$syncers{$mpid}});
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
    } elsif ($command eq "reconnect") { 
	fcaller( \&reconnect );
    } elsif ($command eq "status") { 
	print status_fcaller( \&drbd_status) . "\n";
    } else {
	print "USAGE: drbd [resource] start|reconnect|status|stop\n";
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
	print status_fcaller( \&datadisk_status) . "\n";
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
sanity_checker();

if(defined($resource)) {
   if(!defined($conf{$resource})) {
       die "resource $resource not defined in the configuration file";
   }
}

if( $pname =~ /drbd$/ ) { drbd(); }
elsif( $pname =~ /datadisk$/ ) { datadisk(); }
else { die "do not know what to do"; }

