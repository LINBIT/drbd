package LGE_CTH::Link;
# $Id: Link.pm,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $

use strict;
use warnings;
use Carp;

use LGE_CTH ":util";
use LGE_CTH::Node;
use LGE_CTH::Component;
our @ISA = qw(LGE_CTH::Component);

#
# Class to track a network link status
#

our %ClassData = (
	states => [ qw( up down ) ],
	events => {
		fail => 'down',
		heal => 'up',
	},
	config_template => {
		may_fail  => 0,
		endpoints => [ { node => undef, interface => undef, ip => undef } ],
	}
);

# takes events, regardless of node status
sub takes_events {
	my $me = shift;
	$me->may_fail
	and not $me->{_busy};
}

my $valid_ip = qr{
	([1-9][0-9]?|1\d\d|2[0-4]\d|25[0-5])\.
	(0|[1-9][0-9]?|1\d\d|2[0-4]\d|25[0-5])\.
	(0|[1-9][0-9]?|1\d\d|2[0-4]\d|25[0-5])\.
	([1-9][0-9]?|1\d\d|2[0-4]\d|25[0-4])
}x;

sub CheckConfig {
	my $me = shift;
	my $endpoints = $me->{_config}->{endpoints};

	my %seen = ();
	my $id;

	for my $h (@$endpoints) {
		my ($node,$nic,$ip) = @$h{qw(node interface ip)};

		croak "expected Node ref, not $node\n"
			unless ref $node and $node->isa('LGE_CTH::Node');
		croak "$node->{_config}->{hostname} seen more than once!?\n"
			if ++$seen{$node->id} != 1;

		croak "expected interface name, not '$nic'\n"
			unless ref $nic eq ''
			and $nic =~ /^[a-z0-9:]+$/;
		$id = $node->{_config}->{_nics}->{$nic}->{id};
		croak "$node->{_config}->{hostname}:$nic already used by $id.\n"
			if $id;
		$node->{_config}->{_nics}->{$nic} = { ip => $ip, id => $me->id, link => $me };

		croak "expected valid ip in dotted quad, not '$ip'\n"
			unless ref $ip eq ''
			and $ip =~ /^$valid_ip$/o;
		$id = $LGE_CTH::uniq{admin_ip}->{$ip};
		croak "do NOT use the admin_ip of a Node ($ip => $id) for a controlled Link!\n"
			if $id;
		$id = $LGE_CTH::uniq{ip}->{$ip};
		croak "IPs need to be unique, $ip is already used by $id.\n"
			if $id;
		$LGE_CTH::uniq{ip}->{$ip} = $me->id;
		$me->depends_on($node,$h);
		$me->{_config}->{_nodes}->{$node->id} = $h;
	}
}

sub Initialize {
	my $me = shift;
	$me->{_status}->{status} = "up";
}

sub Node_changed {
	my ($me,$node,$info,$event) = @_;	
	return if $event eq "fail";
	warn $node->as_string if $node->{_status}->{status} ne 'up';

	my ($nic,$ip)            = @$info{qw(interface ip)};
	my ($hostname,$admin_ip) = @{$node->{_config}}{qw(hostname admin_ip)};

	my $cmd;
	if ($me->{_status}->{status} eq 'down') {
		$cmd = "on $admin_ip: iptables_DROP   nic=$nic hostname=$hostname"
	} else {
		$cmd = "on $admin_ip: iptables_UNDROP nic=$nic hostname=$hostname"
	}
	_spawn( "configure $nic on $hostname after $event", $cmd, 'SYNC');
}

sub _Link_event {
	my ($me,$cmd) = @_;
	my $nodes = $me->{_config}->{endpoints};
	my $exit = 0;
	my $lcmd = "";
	for my $h (@$nodes) {
		my ($node,$nic)          = @$h{qw(node interface)};
		my ($hostname,$admin_ip) = @{$node->{_config}}{qw(hostname admin_ip)};
		next unless $node->{_status}->{status} eq 'up';
		$lcmd .= "on $admin_ip: $cmd nic=$nic hostname=$hostname\n"
	}
	$lcmd;
}

sub fail {
	my $me = shift;
	my $cmd = $me->_Link_event("iptables_DROP");
	$me->_generic_event("fail","down",$cmd) if $cmd;
}

sub heal {
	my $me = shift;
	my $cmd = $me->_Link_event("iptables_UNDROP");
	$me->_generic_event("heal","up",$cmd) if $cmd;
}


1;
