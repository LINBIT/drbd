package LGE_CTH::CRM;

use strict;
use warnings;
use Carp;

use LGE_CTH ":util";
use LGE_CTH::Component;
our @ISA = qw(LGE_CTH::Component);

#
# Class to track Cluster Resources
#

our %ClassData = (
	states => [ qw( OK degraded FUBAR ) ],
	events => { },
	config_template => { unused => "" },
);

sub takes_events { 0 }

sub CheckConfig {
	die "you can only have ONE cluster resource manager!\n"
		unless $LGE_CTH::Component::ClassData{_id}->{'LGE_CTH::CRM'} == 1;
}

sub start_all {
	my ($n,$s);
	for $s (@LGE_CTH::Resource) {
		$n = (
			# much TODO
			# improve the sort with node preferences and so on
			# currently I only support two nodes, and
			# find the "most idle" node.
			# 'down' nodes are busy waiting for boot...
			# FIXME maybe a given Resource can only be started on certain nodes...
			sort { $a->{_resources} <=> $b->{_resources} } 
			grep { not $_->{_busy} } @LGE_CTH::Node)[0];

		die unless $n;
		$s->start($n);
	}
}

sub stop_all {
	my ($n,$s);
	for $s (@LGE_CTH::Resource) {
		$n = $s->{_current_node};
		$s->stop($n) if $n;
	}
}

sub Node_changed {
	my ($me,$node,$info,$event) = @_;	
	my $services = $me->{_config}->{services};

	my $nstate = $node->{_status}->{status};
	
	# TODO sort by priority, add constraints ... 

	return if ($event eq 'END_OF_TEST');

	# $me->say("$node->{_id} now $nstate: $event") if $::LGE_IS_DEBUGGING;
	if ($event eq 'initial_boot') {
		# $me->say("irgnored $event on $node->{_id}") if $::LGE_IS_DEBUGGING;
		return;
	}
	my @affected;

	if ($nstate eq 'down') {
		@affected = grep { $_->{_current_node} and $_->{_current_node} == $node } @LGE_CTH::Resource;
	} else {
		@affected = grep { $_->{_status}->{status} eq 'stopped' } @LGE_CTH::Resource;
		if (!@affected) {
			# if all are running, relocate some
			# TODO improve!
			@affected = @LGE_CTH::Resource;
		}
	}

	for my $s (@affected) {
		my $best_node = (
			# much TODO
			# improve the sort with node preferences and so on
			# currently I only support two nodes, and
			# find the "most idle" node.
			# 'down' nodes are busy waiting for boot...
			# FIXME maybe a given Resource can only be started on certain nodes...
			sort { $a->{_resources} <=> $b->{_resources} } 
			grep { not $_->{_busy} } @LGE_CTH::Node)[0];

		next if $best_node and $s->{_current_node}
			and $s->{_current_node} == $best_node;
		$s->stop($s->{_current_node}) if $s->{_current_node};
		$s->start($best_node) if $best_node;
	}
}

1;
