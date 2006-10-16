#!/usr/bin/perl -W

# DRBD TestSuite
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

use Time::HiRes qw(gettimeofday);
use Time::Local;
use IO::Socket;
use threads;
use threads::shared;

# program variables
use vars qw (
  $pid $cpid
  $opt_c $opt_h $opt_d $opt_v $opt_i $opt_l
  $outreply $outcommand
  %config @seqcommands
  %seqvars
  %commands
  @logList
  %verbose
  $terminated_node $terminated
  $seriallog
);

$seriallog = "";
$SIG{USR1} = 'IGNORE';
$SIG{USR2} = 'IGNORE';
$SIG{PIPE} = 'IGNORE';
$SIG{TERM} = 'IGNORE';

###############################################################################
######  commands
###############################################################################

#GENERAL:
$commands{'cpuinfo'} = 'cat /proc/cpuinfo | grep MH | awk -F: \'{print $2}\'';
$commands{'tiobench'} = 'tiobench -- dir {mountpoint}';

#DEVICE MAPPER:
$commands{'dm_deviceremoveOne'} = 'dmsetup remove {lvm_device}';
$commands{'dm_deviceinfo'} = 'dmsetup info {lvm_device}';
$commands{'dm_devicemake'} = 'dmsetup create {lvm_device}';
$commands{'dm_devicestatus'} = 'dmsetup status {lvm_device}';
$commands{'dm_devicesuspend'} = 'dmsetup suspend {lvm_device}';
$commands{'dm_deviceresume'} = 'dmsetup resume {lvm_device}';

#STATES:
$commands{'state_st'} = '/sbin/drbdsetup /dev/{device} state';
$commands{'state_cs'} = '/sbin/drbdsetup /dev/{device} cstate';
$commands{'state_ds'} = '/sbin/drbdsetup /dev/{device} dstate';
$commands{'state_iptables'} = 'iptables -L OUTPUT -nv'; #FIXME: not yet implemented

#NETWORK:
$commands{'link_down'} = '/sbin/iptables -I OUTPUT -o {interface} -j DROP';
$commands{'link_up'} = '/sbin/iptables -F OUTPUT';

#DRBD-SPECIFIC:
$commands{'primary'} = '/sbin/drbdadm primary {resource}';
$commands{'secondary'} = '/sbin/drbdadm secondary {resource}';
$commands{'drbd_fullsync'} = 'drbdadm -- --overwrite-data-of-peer {resource}';
$commands{'drbd_turnoffnw'} = 'iptables -I OUTPUT -o {interface} -j DROP';
$commands{'drbd_turnonnw'} = 'iptables -I OUTPUT -o {interface} -j DROP';
$commands{'drbd_start'} = '/etc/init.d/drbd start';
$commands{'drbd_stop'} = '/etc/init.d/drbd stop';
$commands{'drbd_restart'} = '/etc/init.d/drbd restart';
$commands{'drbd_mount'} = 'mount /dev/{device} {mountpoint}';
$commands{'drbd_umount'} = 'umount /dev/{device}';
$commands{'drbd_loaded'} = 'lsmod | grep drdb';
$commands{'drbd_make'} = 'drbdadm create-md {resource}';

#FILESYSTEM:
$commands{'fs_make'} = 'mkfs.{filesystem} /dev/{device}'; #FIXME FileSystem - agent.conf!!'

#FAULTS
$commands{'set_fr'} = 'echo 10 >/sys/module/drbd/parameters/fault_rate';
$commands{'clr_fr'} = 'echo 0 >/sys/module/drbd/parameters/fault_rate; echo 0 >/sys/module/drbd/parameters/enable_faults';
$commands{'set_md_wr'} = 'echo 1 >/sys/module/drbd/parameters/enable_faults';
$commands{'set_md_rd'} = 'echo 2 >/sys/module/drbd/parameters/enable_faults';
$commands{'set_rs_wr'} = 'echo 4 >/sys/module/drbd/parameters/enable_faults';
$commands{'set_rs_rd'} = 'echo 8 >/sys/module/drbd/parameters/enable_faults';
$commands{'set_dt_wr'} = 'echo 16 >/sys/module/drbd/parameters/enable_faults';
$commands{'set_dt_rd'} = 'echo 32 >/sys/module/drbd/parameters/enable_faults';

###############################################################################

require 'getopts.pl';
if ( ! Getopts ('hc:vdil:') ) {
  usage();
  exit 1;
}

if (defined($opt_h)) {
  usage();
  exit 0;
}

if (defined($opt_d)) {
  print "DEBUG activated!\n";
}

# show usage information
sub usage {
  print "TestSuite $version \n";
  print "testsuite.pl [ -hd ] [ -c config ] [ -l logfile ]\n";
  print " -h  shows help\n";
  print " -i  ignore connection info\n";
  print " -v  verbose mode\n";
  print " -d  run in debug mode (console output)\n";
  print " -c  specifiy a configuration file other than the default (testsuite.conf)\n";
  print " -l  writes all information to specified logfile\n";

  return;
}


###############################################################################
######  functions
###############################################################################

sub load_conf {
  if (!defined($opt_c)) {
    $opt_c = "testsuite.conf";
  }
  if (! -e $opt_c) {
    die "Configuration file not availiable!\n";
  }
  open (CONF, $opt_c) or die "Cannot read the config file $opt_c, $!\n";

  my $section = 0;
  my $nodes = 0;
  my $seqsection = 0; # {} sections in seq-commands

  #initiate variables
  $config{'node1addr'} = "";
  $config{'node1port'} = "";
  $config{'node2addr'} = "";
  $config{'node2port'} = "";
  $config{'timeout'} = "";
  $config{'latency'} = 0;
  $config{'max_latency'} = 0.5;
  $config{'connect_timeout'} = 3;
  $config{'timeserver'} = "";

  while (<CONF>) {
    next if (/^\s*$/); #skip blank lines
    next if (/^\s*#/); # skip comment lines
    $_ = trim($_);

    if (/^}$/ and $seqsection == 0) {
      $section = 0;
    }
    elsif ($section == 4) {
      push @seqcommands, $_;
      if (/{/) {
        $seqsection += 1;
      }
      if (/}/) {
        $seqsection -= 1;
      }
    }
    elsif ($section == 1 or $section == 2) {
      if (/^addr\s+(.*);$/) { # addr <hostname/ip>;
        if ($nodes == 1 or $nodes == 2) {
          $config{'node'.$nodes.'addr'} = $1;
        }
        else {
	  ERROR ("ip without node configuration");
	}
      }
      elsif (/^port\s+(.*);$/) { # port <port>;
        if ($nodes == 1 or $nodes == 2) {
          $config{'node'.$nodes.'port'} = $1;
        }
        else {
	  ERROR ("port without node configuration");
	}
      }
      else {
        ERROR ("unknown configuration at node: ".$_);
      }
    }
    elsif ($section == 3) {
      if (/^timeout\s+(.*);$/) {
        $config{'timeout'} = $1;
      }
      elsif (/^latency\s+(.*);$/) {
        $config{'max_latency'} = $1;
      }
      elsif (/^connect_timeout\s+([0-9]+);$/) {
        $config{'connect_timeout'} = $1;
      }
      elsif (/^timeserver\s+(.*);$/) {
        $config{'timeserver'} = $1;
      }
      else {
        ERROR ("unknown configuration in default section: ".$_);
      }
    }
    elsif (/^node\ (.*)\ ?{$/) {
      $section = 1;
      $nodes++;
      $config{'node'.$nodes.'name'} = trim($1);
    } 
    elsif (/defaults\s{/) {
      $section = 3;
    }
    elsif (/seq-commands\s{/) {
      $section = 4;
    }
    else {
      ERROR ("unknown configuration: ".$_);
    }
  }
}

# creates sockets for both nodes
sub get_sockets {
  eval {
    $config{'node1'} = new IO::Socket::INET (
      PeerAddr => $config{'node1addr'},
      PeerPort => $config{'node1port'},
      Proto => 'tcp',
      Timeout => $config{'connect_timeout'},
    ) or die("node1\n");

    $config{'node2'} = new IO::Socket::INET (
     PeerAddr => $config{'node2addr'},
     PeerPort => $config{'node2port'},
     Proto => 'tcp',
     Timeout => $config{'connect_timeout'},
    ) or die("node2\n");
  };
  if ($@) {
    if ($terminated) {
      $terminated_node =  "Lost connection to " .$@;
    }
    else {
      ERROR ("Can't connect to " .$@);
    }
  }

  return;
}

# someone tried to kill parent process
sub kill_parent {
  $terminated = 1;
  $terminated_node = ""; 
  get_sockets(); 

  if ($terminated_node eq "") {
    WARN ("Received INT signal");
  }
  else {
    WARN ($terminated_node);
  }

  show_report();
  exit 0;
}

###############################################################################
######  eval part
###############################################################################

# time that agent may need to execute requested command
sub timeout {
  $seqvars{'timeout'} = $_[0];
  return 1;
}

# timestamp when the command should be executed
sub rc {
  # uses $config{'latency'}
  $seqvars{'rc'} = ($_[0] == 0)?(Time::HiRes::time):(Time::HiRes::time + $config{'latency'} + $_[0]);
  return 1;
}

# command will be sent to that node
sub on {
  $seqvars{'on'} = $_[0];
  return 1;
}

# type of state (st, cs, ds, ...)
sub type {
  $seqvars{'type'} = $_[0];
  return 1;
}

# value of state ('Primary/Secondary', 'Connected', ...)
sub state {
  $seqvars{'state'} = $_[0];
  return 1;
}

# send 'execute command' to agent(s)
sub cmd {
  my $command = "execute (q{$_[0]}, $seqvars{'timeout'}, $seqvars{'rc'});";
  $seqvars{'seq_type'} = 1;
  
  VERBOSE ("$_[0]", $seqvars{'on'});
  
  send_command($command) || die ("cmd failed\n");
  set_default_vars();
  
  return 1;
}

# send 'expected command' to agent(s)
sub expected {
  my $command = "execute (q{$commands{'state_'.$_[0]}}, $seqvars{'timeout'}, $seqvars{'rc'}, q{$seqvars{'state'}});";
  $seqvars{'seq_type'} = 2;

  VERBOSE ("$commands{'state_'.$_[0]}", $seqvars{'on'});

  send_command($command) || die ("expected failed\n");
  set_default_vars();

  return 1;
}

# send 'get command' to agent(s)
sub get {
  my $command = "execute (q{$_[0]}, $seqvars{'timeout'}, $seqvars{'rc'});";
  $seqvars{'seq_type'} = 3;
 
  VERBOSE ("$_[0]", $seqvars{'on'});
  
  my $reply = send_command($command) || die ("get failed\n");
  set_default_vars();

  return $reply;
}

###############################################################################
######  functions
###############################################################################

sub send_command {
  my ($command) = @_;
  my @reply;
 
  LOG ("Sent: ".$command);

  if ($seqvars{'on'} > 0) { # only one node
    print {$config{'node'.$seqvars{'on'}}} $command."\n";
    push @reply, wait_for_reply($seqvars{'on'});
  }
  else {
    print {$config{'node1'}} $command."\n";
    print {$config{'node2'}} $command."\n";
    push @reply, wait_for_reply(1);
    push @reply, wait_for_reply(2);
  }

  return process_reply($command, @reply);
}

# sync time on specified node
sub sync_node() {
  set_default_vars();
  $seqvars{'timeout'} = 10;

  # FIXME, use config vars
  my @reply = send_command("execute (q{".'ntpdate -b '.$config{'timeserver'}."}, $seqvars{'timeout'}, $seqvars{'rc'});");
  
  return;
}


# process latency and timestamp of nodes
sub parse_time_details {
  my ($input) = @_;
  
  if ($input =~ /^([1-2])\ ([0-9.]+)\ ([0-9.-]+)$/) {
    return ($2, $3, $1);
  }
    
  return 0;
}

# check system time, get latency and sync nodes if needed
sub get_connection_info {
  my ($tries) = @_;
  if (!defined($tries)) { $tries = 0; }
  
  set_default_vars();
  
  my $timestamp = Time::HiRes::time;
  my $command = "setup ($timestamp)";
  my @reply = send_command($command);
  my $timestamp_sent = Time::HiRes::time;
  
  my $time_difference;
  my $node1;
  my $node2;
 
  my $n1_latency;
  my $n2_latency;
  
  ($time_difference, $n1_latency, $node1) = parse_time_details($reply[0]);
  ($time_difference, $n2_latency, $node2) = parse_time_details($reply[1]);
  
  if ( !defined($n1_latency) ) {
    ERROR ("Node timed out on setup");
  }
  elsif ( !defined($n2_latency) ) {
    ERROR ("Node timed out on setup");
  }
  
  VERBOSE ("Node time difference: ".abs($n1_latency - $n2_latency));

  if ( abs($n1_latency - $n2_latency) > $config{'max_latency'} ) {
    if ($tries > 2) {
      ERROR ("Couldn't sync nodes: ".abs($n1_latency - $n2_latency)." - abort after 3 retries.");
      exit 0;
    }
    
    if ($config{'timeserver'} ne "") {
      WARN ("Nodes out of sync - resyncing ".++$tries." time(s)");
      sync_node();
      sleep 3;
      get_connection_info($tries);
    }
    else {
      ERROR ("Nodes out of sync! No timeserver configured, aborting.");
    }

    return;
  }

  $config{'latency'} = ( $n1_latency + abs( ($n1_latency) * 0.20) );
  VERBOSE ("RC latency set to: ".$config{'latency'});
  
  return;
}

# wait for a reply. timeout on closed socket
sub wait_for_reply {
  my ($node_number) = @_;
  my $reply = "$node_number ";
  my $timeout;
  my $buf;

  # FIXME, also use RC value!

  $timeout = ($seqvars{'timeout'} + 2);

  eval {
    local $SIG{ALRM} = sub { die "timeout\n" };

    alarm $timeout;

    #read from socket
    my $node = $config{'node'.$node_number};

    while (<$node>) {
      last unless ($_ ne ".\n"); # last line
      $reply .= $_ unless $_ eq "\n"; # skip blank lines
    }

    alarm 0;
  };
  if ($@) {
    # exception, should never happen
    die unless $@ eq "timeout\n";
    $reply = "timeout";
  }

  return $reply;
}


# process reply of agents
sub process_reply {
  my ($command, @reply) = @_;
  my $return = 1;

  foreach(@reply) {
    LOG ("Got reply: ". $_);
  }
  
  # setup messages
  if ($command =~ /^setup\ /) {
    $reply[0] =~ s/^([1,2])\ (.*)\n/$1 /;
    $reply[1] =~ s/^([1,2])\ (.*)\n/$1 /;

    return @reply;
  }
  elsif ($command =~ /^send_log()/) {
    return @reply;
  }
  elsif ($command =~ /^execute\ /) {
    if ($seqvars{'seq_type'} == 1) {           #execute command
      foreach (@reply) {
        if (/^([1,2])\ ([0,1])\ /) {
          VERBOSE ( ($2)?'done':'failed', -1 , $1 );
          $return &= $2;
        }
        else {
          ERROR ("unknown reply: ".$_);
        }
      }
      
      return $return;
    }
    elsif ($seqvars{'seq_type'} == 2) {      #expected command
    
      foreach (@reply) {
        if (/^([1,2])\ ([0,1])\ ([0-9.]+)\ ([0-9.]+)\n(.*)$/) {
          VERBOSE ( ($2)?'done ('.$5.')':'failed ('.$5.')', -1 , $1 );
          $return &= $2;
        }
        else {
          ERROR ("unknown reply: ".$_);
        }
      }

      return $return;
    }
    elsif ($seqvars{'seq_type'} == 3) {      #get command
      
      # return first reply
      foreach (@reply) {
        if (/^([1,2])\ ([0,1])\ ([0-9.]+)\ ([0-9.]+)\n(.*)$/s) {
          if ($2 == 0) {
            return 0;
          }
          elsif ($2 == 1) {
            my $output = $5;
            chomp($output);
            VERBOSE ($output, -1 , $1 );
            return $output;
          }
        }
        else {
          ERROR ("unknown reply: ".$_);
        }
      }
      return 0;

    }
  }

}


# process and show report
sub show_report {
  my ($result) = @_;
  
  if (defined($opt_l)) {
    eval {
      open(LOGFILE, ">".$opt_l) or die ($!."\n");
    };
    if ($@) {
      WARN ("Unable to handle logfile: ".$@);
    }

    my @mnames = ('Jan', 'Feb', 'Mar', 'Apr',
                  'May', 'Jun', 'Jul', 'Aug',
                  'Sep', 'Oct', 'Nov', 'Dec');

    my $sec;
    my $min;
    my $hour;
    my $mday;
    my $mon;
    my $year;
    my $wday;
    my $yday;

    print LOGFILE "--------- TestSuite --------\n";
    foreach(@logList) {
      ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday) = (localtime($$_[0]));
      printf LOGFILE "%s %02d %02d:%02d:%02d ", $mnames[$mon], $mday, $hour, $min, $sec;
      print LOGFILE $$_[1]."\n";    
    }
    print LOGFILE "--------- TestSuite --------\n";  

    if(!$terminated) {    
      get_agent_log();
    }

    if ($seriallog ne "") {
      print LOGFILE "\n\n--------- Kernel Messages (serial) ---------\n";
      print LOGFILE "$seriallog";
      print LOGFILE "--------- Kernel Messages (serial) ---------\n";
    }
 
    close(LOGFILE);
  }

  print "Test ". (($result)?'ok':'failed') ."\n\n";

  return;
}


# Check if we have permission to write to logfile
sub test_log {
  eval {
    open(LOGFILE, ">".$opt_l) or die ($!."\n");
  };
  if ($@) {
    ERROR ("Unable to handle logfile: ".$@);
  }

  close LOGFILE;
}

# Get and write log information of agents if available
sub get_agent_log {
  set_default_vars();
  my @reply = send_command("send_log();");

  foreach(@reply) {
    if (/^([1,2])\ ([0,1])\ 0\ 0\n(.*)\s$/s) {
        if ($2 == 0) {
          WARN ("$3 on ".$config{'node'.$1.'name'});
        } else {
          print LOGFILE "\n\n--------- ".$config{'node'.$1.'name'}." ---------\n";
          print LOGFILE "$3";
          print LOGFILE "\n\n--------- ".$config{'node'.$1.'name'}." ---------\n";
        }
    }
  }
  
  return;
}


# process seqcommands
sub process_seqcommands {
  # uses seqcommands (array with each command)
  my $seqcommands_eval = join("\n",@seqcommands);
  $seqcommands_eval =~ s/on\ $config{node1name}/on\ '1'/g;
  $seqcommands_eval =~ s/on\ $config{node2name}/on\ '2'/g;
  
  my $key;
  my $value;
  
  while(($key, $value) = each(%commands)) {
    $seqcommands_eval =~ s/cmd $key/cmd '$value'/g;
    $seqcommands_eval =~ s/get $key/get '$value'/g;
  }
  
  set_default_vars();
  eval ($seqcommands_eval);
  if ($@) {
    # exceptions
    LOG ($@);
    return 0;
  }

  return 1;
}


# set seq parameters to default values
sub set_default_vars() {
  $seqvars{'timeout'} = $config{'timeout'};
  $seqvars{'on'} = 0;
  $seqvars{'rc'} = 0;
  $seqvars{'type'} = '';
  $seqvars{'state'} = '';
  $seqvars{'seq_type'} = 0;
  $seqvars{'FIXME'} = 0;
}

###############################################################################
######  help functions
###############################################################################

# print verbose information
sub VERBOSE {
  if (!defined($opt_v) && !defined($opt_l)) {
    return;
  }

  my ($msg, $to, $from) = @_;
  my $tmp = "";

 
  if (defined($from)) {
    if ($from == 0) {
      $from = 'both';
    }
    else {
      $from = $config{'node'.$from.'name'};
    }
    
    $tmp = $from ." -> ";
  }
  elsif (defined($to)) {
    if ($to == 0) {
      $to = 'both';
    }
    elsif ($to > 0) {
      $to = $config{'node'.$to.'name'};
    }
    
    $tmp = $to ." <- ";
   }
  
  $tmp .= $msg;
  if(defined($opt_v)) {
    print $tmp. "\n";
  }

  LOG($tmp);
}

# write debug
sub LOG {
  my ($msg) = @_;

  if (defined($opt_d))  { 
     print Time::HiRes::time. " -> " .$msg. "\n";
  }

  if (defined($opt_l)) { 
    push (@logList, [Time::HiRes::time, $msg]);
  } 
  return;
}


# print info messages
sub INFO {
  my ($msg) = @_;
  
 if (defined($opt_l)) {
       LOG($msg);
  }

  print $msg. "\n";

  return;
}

# print warn messages
sub WARN {
  my ($msg) = @_;
  
 if (defined($opt_l)) {
       LOG("Warning: ".$msg);
  }

  print "Warning: ". $msg. "\n";

  return;
}

# print error messages - an error message will be printed in every mode
sub ERROR {
  my ($msg) = @_;
  
  print "Error: " .$msg. "\n";

  LOG(" ERROR " .$msg);
  $terminated = 1;
  show_report();

  $SIG{HUP} = 'IGNORE';
  kill HUP => -$$;
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
 
# do something, execute command, process output
sub test {
  print "\nPRINT:\n";
  print "Node1 Name: $config{'node1name'}\n";
  print "Node1 IP: $config{'node1addr'}\n";
  print "Node1 Port: $config{'node1port'}\n";
  print "Node2 Name: $config{'node2name'}\n";
  print "Node2 IP: $config{'node2addr'}\n";
  print "Node2 Port: $config{'node2port'}\n";
  print "Timeout: $config{'timeout'}\n";
  
  foreach (@seqcommands) {
    print ": ".$_."\n";
  }

  LOG ("Testlog");
  WARN ("Testwarn");

  ERROR("Testerror");
  exit;
}

###############################################################################
######  main
###############################################################################

load_conf();
if (defined($opt_l)) {
  test_log();
  #listen_serial();
}
get_sockets();


$SIG{INT} = \&kill_parent;

# check system time, process commands, show report 
if (!defined($opt_i)) {
    get_connection_info();
}

my $result = process_seqcommands();

show_report($result);

# kill child processes  
local $SIG{HUP} = 'IGNORE';
kill HUP => -$$;

exit 0;
