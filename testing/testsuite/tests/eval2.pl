#!/usr/bin/perl
#
#
#

$timeout = 0;
$rc = 0;
$node = "";
$cmd = "";
$state = "";


sub listNodes {
  ($node eq "")?"all":$node;
}

sub rc {
  $rc = $_[0];
}

sub on {
  $node = $_[0];
}

sub timeout {
  $timeout = $_[0];
}

sub cmd {
  print "Trying to run:\n";
  print "Command: ".$_[0]."\n";
  print "On: ".eval(listNodes)."\n";
  print "Timeout: ".$timeout."\n";
  print "Timestamp: ".$rc."\n\n";
}

sub excpect {
  if (1 != 2) { die("unexpected state"); };
}

# cmd 'drbdadm create-md r0' rc 0;
# cmd 'drbdadm -- DDFFC66571C5E5CB::::1 set-gi r0' rc 0; #no sync on connect!
# on n1 cmd 'drbdadm up r0' rc 0;
# on n2 cmd 'drbdadm up r0' rc 0;
# exp cs Connected timeo 10;
# sleep 10;

eval {
  cmd 'drbdadm create-md r0', timeout 15, rc 4;
  cmd 'drbdadm primary r0', on n1, timeout 5;
};

exit 0;

#eval{
#  on n1 cmd "drbdadm up r0";
#  cmd 'drbdadm create-md r0';
#  sleep 1;
#  expect cs Connected timeout 10;
#}; # warn $@ if $@;
#if ($@) {
#  print $@;
#  print "XXXXXXXXXx\n";
#}



exit 0;
