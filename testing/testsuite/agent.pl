#!/usr/bin/perl -W

# agent
# 
# Part of the DRBD TestSuite
#
# (c)2006 by Dworschak, Roland       <roland.dworschak@fh-hagenberg.at>
#            Hofmann, Florian        <florian.hofmann@fh-hagenberg.at>
#            Huber, Sabine           <sabine.huber@fh-hagenberg.at>
#            Leitner, Alexander      <alexander.leitner@fh-hagenberg.at>
#            Poettinger, Joachim     <joachim.poettinger@fh-hagenberg.at>
#            
# Licensed under the GNU GPL v2
# see http://www.gnu.org for more details
#

my $version = 'v1.00';

use strict;
use Time::HiRes qw(usleep gettimeofday tv_interval);
use Time::Local;
use IO::Socket;

# set rtprio to 99 (for testing purpose: 50)
require 'sys/syscall.ph';
eval {
  syscall(&SYS_sched_setscheduler,0,1,pack('i', 50)) == 0 or die ($!."\n");
};
if ($@) {
  die unless $@ eq "Operation not permitted\n";
  WARN ("Couldn't set realtime scheduler, are you root?");
}

eval {
  syscall(&SYS_mlockall, 3) == 0 or die ($!."\n");
};
if ($@) {
  die unless $@ eq "Cannot allocate memory\n";
  WARN ("Couldn't set mlockall, are you root?");
}


# program variables
use vars qw (
  %config
  $opt_h $opt_c $opt_d $opt_D
  $client $sock
  $log_timestamp
);

require 'getopts.pl';
if ( ! Getopts ('hdDc:') ) {
  usage();
  exit 1;
}

if (defined($opt_h)) {
  usage();
  exit 0;
}

if (defined($opt_d)) {
  print "DEBUG MODE not implemented yet - only OUTPUT!\n";
}

# show usage information
sub usage {
  print "TestSuite $version \n";
  print "agent.pl [ -hdD ] [ -c config ]\n";
  print " -h  shows help\n";
  print " -d  run in debug mode (not implemented - only OUTPUT)\n";
  print " -D  don't daemonize, run in foreground\n";
  print " -c  specifiy a configuration file other than the default (agent.conf)\n";
}


###############################################################################
######  functions
###############################################################################

# setup information (system time, latency, ...)
sub setup {
  my ($testsuite_timestamp) = @_;
  my $timestamp = Time::HiRes::time;
  
  send_reply(1, 0, 0, $timestamp. " " .($timestamp - $testsuite_timestamp));
  return;
}

sub load_conf {
  if (!defined($opt_c)) {
    $opt_c = "agent.conf";
  }
  if (! -e $opt_c) {
    ERROR ("Configuration file not available!\n");
  }
  open (CONF, $opt_c) or ERROR ("Cannot read the config file $opt_c, $!\n");

  # initiate variables
  $config{'interface'} = "";
  $config{'addr'} = "";
  $config{'port'} = "";
  $config{'resource'} = "";
  $config{'mountpoint'} = "";
  $config{'device'} = "";
  $config{'logfile'} = "";
  while (<CONF>) {
    next if (/^\s*$/); # skip blank lines
    next if (/^\s*#/); # skip comment lines
    $_ = trim($_);

    if (/interface\s+(.*);/) {
      $config{'interface'} = $1;
    }
    elsif (/addr\s+(.*);/) {
      $config{'addr'} = $1;
    }
    elsif (/port\s+(.*);/) {
      $config{'port'} = $1;
    }
    elsif (/resource\s+(.*);/) {
      $config{'resource'} = $1;
    }
    elsif (/mountpoint\s+(.*);/) {
      $config{'mountpoint'} = $1;
    }
    elsif (/device\s+(.*);/) {
      $config{'device'} = $1;
    }
    elsif (/logfile\s+(.*);/) {
      $config{'logfile'} = $1;
    }	
    else {
      ERROR ("Unknown configuration settings: ".$_);
    }
  }

}

###############################################################################
######  functions
###############################################################################


# tests configuration variables. currently only permissions to open
# the logfile is tested.
sub test_conf {
  my $fh;

  if (defined($config{'logfile'})) {
    eval {
      open($fh, $config{'logfile'}) or die ($!."\n");
    };
    if ($@) {
      if ($@ eq "Permission denied\n") {
        WARN ("No permission to read logfile: ".$config{'logfile'});
      }
      else {
        ERROR ($@);
      }
    }
  }

  close $fh;

  #if ($config{'interface'} eq ""){
  #  print "Warning! interface is undefined!\n";
  #}
  #if ($config{'addr'} eq ""){
  #  print "Warning! address is undefined!\n";
  #}
  #if ($config{'port'} eq ""){
  #  print "Warning! port is undefined!\n";
  #}
  #if ($config{'resource'} eq ""){
  #  print "Warning! drbd-resource is undefined!\n";
  #}
  #if ($config{'mountpoint'} eq ""){
  #  print "Warning! mountpoint is undefined!\n";
  #}

  return;
}

# parses through command and changes marked keys
sub parse_command {
  my ($command) = @_;
  my $key;
  my $value;

  while (($key, $value) = each(%config)) {
    $$command =~ s/{$key}/$value/g;
  }

  return 1;
}
  
# execute requested command
sub execute {
  my ($command, $timeout, $timestamp, $expected) = @_;
  my $sleeptime;
  my $output;
  
  parse_command(\$command);
  $sleeptime = get_sleep_duration($timestamp);
  
  # wait for given timestamp
  usleep($sleeptime);

  my $start_time = Time::HiRes::time;
  
  eval {
    local $SIG{ALRM} = sub { die "timeout\n" };
    alarm $timeout;
    do {
      $output = `$command 2>&1`;
      chomp($output);
    } while (defined($expected) && !($output eq $expected));
    alarm 0;
  };
  if ($@) {
    # exceptions
    die unless $@ eq "timeout\n";
    $output = (defined($expected) && defined($output))?$output:'timeout';
  }
  
  my $execution_time = Time::HiRes::time - $start_time;

  send_reply((($output ne 'timeout') && (!defined($expected) || ($output eq $expected)))?1:0, $start_time, $execution_time, $output);
}

# send reply to testsuite
sub send_reply {
  my ($success, $start_time, $execution_time, $output) = @_;

  if ($execution_time == 0) {
    usleep(1000000);
  }
  
  #generate reply
  #ErrorTag
  my $reply = $success;
  #cmd - ain't needed, never asked
  #$reply .= " '".$command."'";
  #Timestamp
  $reply .= " ".$start_time;
  #Execution_Time
  $reply .= " ".$execution_time."\n";
  #Output
  $reply .= $output;
  #end-tag
  $reply .= "\n.\n";           #signalizes end of output

  #send response
  print $client $reply;
}

sub send_log {
  if (!defined($config{'logfile'})) {
    send_reply(0,0,0, 'logfile has not be specified in config.');
    return 1;
  }
 
  my @varlog;
  my $varlog_out = "";

  my $logtime = 0;
  my $found = 0;
  my $firstcounter = 0;

  my %mnames = (Jan => 0, Feb => 1, Mar => 2, Apr => 3,
                May => 4, Jun => 5, Jul => 6, Aug => 7,
                Sep => 8, Oct => 9, Nov => 10, Dec => 11);

  my $date = `date | awk \'{ print \$6 }\'`;

  # try to open file
  eval {
    open(LOGFILE, $config{'logfile'}) or die ($!."\n");
  };
  if ($@) {
    send_reply(0,0,0,"Error reading logfile: ".$@);
    return 1;
  }
  
  @varlog = <LOGFILE>;
 
  foreach (@varlog) {
    next if (/^\s*$/);
    
    if (/^([a-zA-Z]{3})\ +([0-9]+)\ +([0-9]{2}):([0-9]{2}):([0-9]{2})\ +(.*)$/) {
      $logtime = timegm($5,$4,$3,$2,$mnames{trim($1)},$date);

      if ($log_timestamp <= $logtime) {
        $varlog_out .= $_."\n";
      }
    }
  }
  
  close (LOGFILE);
  
  if ($varlog_out eq "") {
    send_reply(0,0,0,"No significant log.\n");
  }
  else {
    send_reply(1,0,0,$varlog_out);
  }
  
  return 1;
}

###
# help functions
#


# Return sleep duration for given timestamp
sub get_sleep_duration {
  my ($timestamp) = @_;
  my $duration = 0;
  
  $duration = $timestamp - Time::HiRes::time;

  return ($duration > 0)?$duration:0;
}

# binds to local port
sub get_socket {
  eval {
    $sock = new IO::Socket::INET (
      LocalHost => $config{'addr'},
      LocalPort => $config{'port'},
      Proto => 'tcp',
      Listen => 1,
      Reuse => 1,
    ) or die ($!."\n") unless $sock;
  };
  if ($@) {
    ERROR ($@);
  }
}

# handle log messages
sub LOG {
  my ($msg) = @_;
  print "LOG: ".$msg."\n";
}


# run in background
sub daemonize {
  my ($home);
  if (fork()) {
    # parent
    exit(0);
  }
  else {
    # child
    LOG "process id: $$";
    $home = (getpwuid($>))[7] || die "No home directory!\n";
    chdir($home);                   # go to my homedir
    setpgrp(0,0);                   # become process leader
    close(STDOUT);
    close(STDIN);
    close(STDERR);
  }
}

# waits for requests by testsuite
sub wait_for_request {
  my $cmd = "";
  #my $client;
  
  while ($client = $sock->accept()) {
    #LOG "waiting for connection";
    LOG "got connection from ". $client->peerhost;
    log_timestamp(); 
    # as long as the testsuite's not closing the socket
    while (<$client>)
    {
      eval($_);
      #cmd ("cat /proc/cpuinfo |grep MH",10,Time::HiRes::time + 3_000_000); # 5 secs
    }
  }

  LOG "got quit command.";
  close($sock);
}

# get timestamp for log parsing in right form
sub log_timestamp {

  my %mnames = (Jan => 0, Feb => 1, Mar => 2, Apr => 3,
                May => 4, Jun => 5, Jul => 6, Aug => 7,
                Sep => 8, Oct => 9, Nov => 10, Dec => 11);
  
  my $tmp = `date`;
  my @date = split(/\s+/, $tmp);
  my $cd = $date[2];
  my $cm = $date[1];
  my $ctime = $date[3];
  my @ctime = split(/:/, $ctime);
  my $y = $date[5];

  $log_timestamp = timegm($ctime[2],$ctime[1],$ctime[0],$cd,$mnames{trim($cm)},$y);

}


###############################################################################
######  help functions
###############################################################################

# handle warnings
sub WARN {
  my ($msg) = @_;
  print "WARN: ". $msg."\n";
}

# print error messages
sub ERROR {
  my ($msg) = @_;
  print "ERROR: ".$msg."\n";
  exit 1;
}

# remove whitespaces at the beginning and at the end
sub trim($) {
  my $string = shift;
  $string =~ s/^\s+//;
  $string =~ s/\s+$//;
  return $string;
}


###############################################################################
######  testing stuff
###############################################################################

sub test {
  print "\nPRINT:\n";
  print "Agent interface: $config{'interface'}\n";
  print "Agent address: $config{'addr'}\n";
  print "Agent port: $config{'port'}\n";
  print "Agent drbd-resource: $config{'resource'}\n";
  print "Agent mountpoint: $config{'mountpoint'}\n";
  print "Agent drbd-device: $config{'device'}\n";
}


###############################################################################
######  main
###############################################################################

load_conf;
test_conf;
get_socket;
if (!defined($opt_D)) {
  daemonize;
}
wait_for_request;

exit 0;
