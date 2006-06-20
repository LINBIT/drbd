#!/usr/bin/perl
#

use IO::Socket;
my $sock = new IO::Socket::INET (
  PeerAddr => '127.0.0.1',
  PeerPort => '4000',
  Proto => 'tcp',
);
die "Could not create socket: $!\n" unless $sock;
print $sock "Hello there!\n";
close($sock);

