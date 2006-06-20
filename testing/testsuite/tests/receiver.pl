#!/usr/bin/perl
#

use IO::Socket;
my $sock = new IO::Socket::INET (
  LocalHost => '127.0.0.1',
  LocalPort => '4000',
  Proto => 'tcp',
  Listen => 1,
  Reuse => 1,
);
die "Could not create socket: $!\n" unless $sock;

my $new_sock = $sock->accept();
while(<$new_sock>) {
  print $_;
}
close($sock);

print "exit\n";
exit 0;
