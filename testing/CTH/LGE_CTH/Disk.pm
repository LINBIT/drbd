package LGE_CTH::Disk;
# $Id: Disk.pm,v 1.1.2.3 2004/07/07 08:56:26 lars Exp $

use strict;
use warnings;
use Carp;

use LGE_CTH ":util";
use LGE_CTH::Component;
our @ISA = qw(LGE_CTH::Component);

#
# Simple Class to track a disk status
#

our %ClassData = (
	states => [ qw( up down ) ],
	events => {
		fail => 'down',
		heal => 'up',
	},
	config_template => {
		node => undef,
		dev  => undef,
		name => undef,
		may_fail => 0,
		usize => 0,
		setup_script => 'empty_script',
		heal_script => 'dmsetup_linear',
		fail_script => 'dmsetup_error',
	}
);

sub takes_events {
	my $me = shift;
	my $node = $me->{_config}->{node};
	my $nstate = $node->{_status}->{status}; 

	$me->may_fail
		and not $me->{_busy}
		and (
			$nstate eq 'down' and $me->{_status}->{status} eq 'down'
			or not $node->{_busy}
		)
}

sub CheckConfig {
	my $me = shift;
	my ($node,$dev,$name) = @{$me->{_config}}{qw(node dev name)};
	croak "expected Node ref, not $node\n"
		unless ref $node and $node->isa('LGE_CTH::Node');
	my $id = $node->{_config}->{_disks}->{$dev}->{id};
	croak "$node->{_config}->{hostname}:$dev already used by $id.\n"
		if $id;
	$id = $node->{_config}->{_disks}->{$name}->{id};
	croak "$node->{_config}->{hostname}:$name already used by $id.\n"
		if $id;
	$node->{_config}->{_disks}->{$dev}  =
	$node->{_config}->{_disks}->{$name} = { name => $name, id => $me->id, disk => $me };
	$me->depends_on($node);
}

sub Initialize {
	my $me = shift;
	$me->{_status}->{status} = "up";
}

sub Node_changed {
	my ($me,$node,$info,$event) = @_;	

	if ($event eq 'END_OF_TEST') {
		# FIXME any cleanup here ?	
		return;
	}
	if ($node->{_status}->{status} eq 'down') {
		# $me->say("ignored $event on $node->{_id}") if $::LGE_IS_DEBUGGING;
		return;
	};
	$me->reconfigure;
}

sub fail {
	my $me = shift;
	my ($dev,$name,$node,$usize) = @{$me->{_config}}{qw(dev name node usize)};
	my ($hostname,$admin_ip) = @{$node->{_config}}{qw(hostname admin_ip)};
	my $blocks = $usize ? "blocks=$usize" : "";
	my $cmd = "on $admin_ip: dmsetup_error name=$name dev=$dev $blocks\n";
	$me->_generic_event("fail","down",$cmd);
}

sub heal {
	my $me = shift;
	my ($dev,$name,$node,$usize) = @{$me->{_config}}{qw(dev name node usize)};
	my ($hostname,$admin_ip) = @{$node->{_config}}{qw(hostname admin_ip)};
	my $blocks = $usize ? "blocks=$usize" : "";
	my $cmd = "on $admin_ip: dmsetup_linear name=$name dev=$dev $blocks\n";
	$me->_generic_event("heal","up",$cmd);
}

sub reconfigure {
	my $me = shift;
	my ($dev,$name,$node,$usize) = @{$me->{_config}}{qw(dev name node usize)};
	my ($hostname,$admin_ip) = @{$node->{_config}}{qw(hostname admin_ip)};
	my $blocks = $usize ? "blocks=$usize" : "";
	my $cmd;
	if ($me->{_status}->{status} eq 'down') {
        	$cmd = "on $admin_ip: dmsetup_error name=$name dev=$dev $blocks\n";
	} else {
        	$cmd = "on $admin_ip: dmsetup_linear name=$name dev=$dev $blocks\n";
	}
	_spawn( "configure $dev as $name on $hostname after boot", $cmd, 'SYNC');
}

1;
