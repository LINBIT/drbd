package LGE_CTH::Resource;
# $Id: Resource.pm,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $

use strict;
use warnings;
use Carp;

use LGE_CTH ":util";
use LGE_CTH::Component;
our @ISA = qw(LGE_CTH::Component);

#
# Simple Base Class to track a Resource status
#

our %ClassData = (
	states => [ qw( running stopped ) ],
	events => { },
	config_template => {
		do_once => undef,
		do_once_per_node => undef,
		do_on_first_start => undef,
		start_script => undef,
		stop_script => undef,
	}
);

sub takes_events { 0 }

sub CheckConfig {
	my $me = shift;
	my $class = ref $me;

	die "Do not use LGE_CTH::Resource directly!"
		if ref $me eq __PACKAGE__;

	die "${class}::env() undefined\n"
		unless $me->can("env");

	for my $script (qw/ start_script stop_script do_once do_once_per_node do_on_first_start /) {
		croak "$script missing from argument list!\n"
		unless defined $me->{_config}->{$script};
	}

	$me->{_config}->{start_ASYNC}||=0;
}

sub start {
	my ($me,$node) = @_;
	my $current_node = $me->{_current_node};
	my $status = $me->{_status}->{status};
	my $ip     = $node->{_config}->{admin_ip};
	my $cmd;

	$me->say("start: already running on $node->{_id}"), return
		if $status eq 'running' and $node == $current_node;

	croak "oops, not runnung on $node->{_id} but on $current_node->{_id}!"
		if $current_node;

	for my $d (values %{$me->{_deps}}) {
		# propagate down the stack.
		$d->start($node);
	}

	if ($me->{_config}->{do_once} and not $me->{did_once}++) {
		$cmd = $me->env . "\n" . $me->{_config}->{do_once};
		_spawn("$me->{_id} do_once_per_node on $node->{_id}", $cmd, 'SYNC');
	}
	if ($me->{_config}->{do_once_per_node} and not $me->{"did_once:$node->{_id}"}++) {
		$cmd = "on $ip: $me->{_config}->{do_once_per_node} " . $me->env;
		_spawn("$me->{_id} do_once_per_node on $node->{_id}", $cmd, 'SYNC');
	}
	if ($me->{_config}->{do_on_first_start} and not $me->{did_on_first_start}++) {
		$cmd = "on $ip: $me->{_config}->{do_on_first_start} " . $me->env;
		_spawn("$me->{_id} do_on_first_start on $node->{_id}", $cmd, 'SYNC') if $cmd;
	}

	$me->status("running","start","done");
	$me->{_current_node} = $node;
	$node->{_resources}++;

	$cmd = "on $ip: $me->{_config}->{start_script} " . $me->env; 
	if (not $me->{_config}->{start_ASYNC}) {
		_spawn("start $me->{_id} on $node->{_id}",$cmd,'SYNC');
	} else {
		$me->{_current_pid} = 
		_spawn("run $me->{_id} on $node->{_id}",$cmd,
			sub {
				my $ex = shift;
				$me->{_current_pid} = 0;
				if ($node->{_status}->{status} eq 'up') {
					if ($ex) {
						$me->say(sprintf "STOPPED, exit code %d:%d\n", $ex >> 8,$ex & 255);
					} else {
						my $i;
						for ($i=0; $i < @LGE_CTH::Resource; $i++) {
							last if $me == $LGE_CTH::Resource[$i];
						}
						if ($i < @LGE_CTH::Resource) {
							splice(@LGE_CTH::Resource,$i,1);
							# if this hits 0, at the next convenient moment we exit the main loop.
							--$LGE_CTH::pending;
						} else {
							$me->say("STANGE! I'm done, but not on the Resource array??");
						}
						$me->say("DONE.");
					}
					$me->stop($node);
				} else {
					# probably crashed.
					# let the rest of the callbacks do their magic
					# hopefully I got it right :-/
					$me->say(sprintf "STOPPED, exit code %d:%d, node crashed?\n", $ex >> 8,$ex & 255);
				}
			}
		);
	}
}

sub stop {
	my ($me,$node) = @_;
	my $current_node = $me->{_current_node};
	my $status = $me->{_status}->{status};
	my $nstate = $node->{_status}->{status};
	my $ip     = $node->{_config}->{admin_ip};
	my $cmd;

	$me->say("stop: not running", join " ",caller), return
		if $status ne 'running';
	$me->say("not running on $node->{_id}, but on $current_node->{_id}"), die
		if $node != $current_node;

	$me->status("stopped","stop","..."); # propagates up the stack
	if ($nstate eq 'up') {
		$cmd = "on $ip: $me->{_config}->{stop_script} " . $me->env;
		_spawn("stop $me->{_id} on $node->{_id}",$cmd,'SYNC');
		sleep 1;
	}
	my $pid = $me->{_current_pid};
	if ($pid) {
		kill_if_pending($pid);
		$me->{_current_pid} = 0;
	}

	for my $d (values %{$me->{_deps}}) {
		# propagate down the stack.
		$d->stop($node);
	}
	$me->{_current_node} = "";
	$me->status("stopped","stop","done");
	$node->{_resources}--;
}

sub relocate_to {
	my ($me,$node) = @_;
	my $current_node = $me->{_current_node};

	$me->say("MOVING to $node->{_id} ...");
	$me->stop($current_node) if ($current_node);
	$me->start($node);
}

1;
