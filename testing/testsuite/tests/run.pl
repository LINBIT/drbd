#!/usr/bin/perl
#

sub cmd {
  if (!$rc) { $rc = 0; }
  print "rc = $rc\n";
  eval {
    local $SIG{ALRM} = sub { die "alarm\n" };
    alarm $timeout;
    $x = `$command`;
    alarm 0;
  };
  if ($@) {
    die unless $@ eq "alarm\n";
    print "TIMEOUT\n";
  }
  else {
    print "FINISHED IN TIME\n";

    print $x;
  }
}

require 'sys/syscall.ph';
$x = syscall(&SYS_sched_setscheduler(0, 'SCHED_FIFO', 99));
print $x;

use LinuxRealTime;
LinuxRealTime::setRealTime(99);


#$TIMEVAL_T = "LL";
#$done = $start = pack($TIMEVAL_T, ());
#syscall(&SYS_gettimeofday, $start, 0) != -1
#  or die "gettimeofday: $!";
#@start = unpack($TIMEVAL_T, $start);

#$time = $start[0].$start[1];
#print $time."\n";
#$time2 = "1146225000000000";
#print (($time2 - $time) / 100000000). "\n";
#exit 0;
#eval {
#  local $SIG{ALRM} = sub { print "XXXXXXXXX"; die "alarm\n" };
#  select(undef,undef,undef,$x); 
#};

use Time::HiRes qw(ualarm nanosleep usleep gettimeofday tv_interval);

for ($i = 0; $i < 5; ++$i) {
  $t0 = [gettimeofday];
  nanosleep(Time::HiRes::time + 2_000_000_000 - Time::HiRes::time);
  $elapsed = tv_interval ( $t0, [gettimeofday]);
  print $elapsed."\n";
}

#cmd($command = 'cat /proc/cpuinfo |grep MHz', $timeout = 1, $rc = 4);

for ($i = 0; $i < 5; ++$i)
{
  ualarm(50_000_000);
  $t0 = [gettimeofday];
  eval {
    local $SIG{ALRM} = sub { die "alarm\n" };
    sleep(10);
  };
  if ($@) {
    die unless $@ eq "alarm\n";
    print "TIMEOUT\n";
    $elapsed = tv_interval ( $t0, [gettimeofday]);
    print $elapsed."\n";
  }
}

  


exit 0;
