#!/usr/bin/perl
#
#
#

$numArg = 1;

sub rc {
  ++$numArg;
  return "timestamp: ". $_[0];
}

sub n1 {
  return "127.0.0.1";
}

sub cmd {
  ++$numArg;
  print $_[1];
  return "Execute Command: '". $_[0]."'";
}

sub on {
  print $_[2]."\n";
  return;
  my $node = $_[0];
  print "on ".$node." do: ";
  for ($i = 0; $i < $numArg; ++$i) {
    print $_[$i+1];
  }
  print $_[2];
  
  print "\n";
  return true;
}

sub timeout {
  ++$numArg;
  return "Max Wait Time = ". $_[0];
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


on n1, cmd 'drbdadm create-md r0', rc 0, timeout 5;

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
