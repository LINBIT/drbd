package LGE_CTH::Node;
# $Id: Node.pm,v 1.1.2.2 2004/06/07 10:16:39 lars Exp $

use strict;
use warnings;
use English;
use POSIX; #  ':errno_h';
use Carp;
use LGE_CTH ":util";
use LGE_CTH::Component;
our @ISA = qw(LGE_CTH::Component);


# XXX
# for some general purpose cluster test harness,
# one could generalize this first to some "LinkEndpoint",
# which then would be parent of "Switch" and "Nic", which would be
# Components of ...
# :)
# 

#
# Simple Class to track a Node status
#

our %ClassData = (
	config_template => {
		hostname    => undef,
		admin_ip    => undef,
		admin_nic   => undef,
		boot_timeout => undef,
		may_fail => 0,
		min_uptime => 30,
		boot_script => 'generic_wait_for_boot',
		heartbeat_script => 'generic_heartbeat',
		# arch => ;)
		# cost => :(
	},
	states => [ qw( up down shutdown ) ],
	events => {
		fail => 'down',
		# heal => 'up', hopefully by rebooting itself ...
	},
);

# takes events if not busy; this should be the same as status => up
sub takes_events {
	my $me = shift;
	not $me->{_busy}
	and $me->may_fail
	and (time - $me->{_boot_time}) > $me->{_config}->{min_uptime};
}

sub CheckConfig {
	my $me = shift;
	my $config = $me->{_config};
	my ($ip,$nic,$hostname) = @$config{qw(admin_ip admin_nic hostname)};

	# XXX check validity of $nic and $hostname and $ip and yada yada
	# I think if the paranoia level gets too high, this is of no use
	# to anyone anymore.

	my $id = $LGE_CTH::uniq{ip}->{$ip};
	croak "IPs need to be unique, $ip is already used by $id.\n"
		if $id;
	$LGE_CTH::uniq{ip}->{$ip}       =
	$LGE_CTH::uniq{admin_ip}->{$ip} = $me->id;

	$id = $LGE_CTH::uniq{hostname}->{$hostname};
	croak "hostname ($hostname) already used by $id!\n"
		if $id;
	$LGE_CTH::uniq{hostname}->{$hostname} = $me->id;

	croak "boot_timeout must be an integer!\n"
		unless $me->{_config}->{boot_timeout} =~ /^\d+$/;

	$me->{_config}->{_nics} = { $nic => { ip => $ip, id => 'admin' } };
	$me->{_resources} = 0;
	1;
}

# these are no events, but the body of the function is very similar

sub heartbeat {
	my $me = shift;
	my ($hostname,$ip) =
		@{$me->{_config}}{qw(hostname admin_ip)};
	
	$me->say("starting heartbeat");
	_spawn( "$me->{_id}->heartbeat", "ip=$ip\n$me->{_config}->{heartbeat_script}",
		sub {
			my $ex = shift;
			my $uptime = time - $me->{_boot_time};
			$me->say(sprintf "heartbeat died, uptime=$uptime, exit code %d:%d\n",
				$ex >> 8,$ex & 255);

			if (not $LGE_CTH::exiting) {
				$me->say("unexpected crash of $me->{_config}->{hostname}!\n")
					unless $me->{_busy} eq "fail";
				$me->status("down","fail","done");
				$LGE_CTH::FAILED -= 499;
				$me->wait_for_boot;
			} else {
				$me->status("shutdown","END_OF_TEST","done");
			}
		}
	);
};

sub wait_for_boot {
	my $me = shift;

	$me->say("no point in booting me, I'm up!"), return
		if $me->{_status}->{status} eq "up";

	my ($hostname,$ip,$timeout) =
		@{$me->{_config}}{qw(hostname admin_ip boot_timeout)};
	my $initial = $me->{_status}->{status} eq '__UNDEF__' ? "true" : "false";
	my $have_drbd = scalar(grep { /^DRBD/ } keys %{$me->{_users}}) ? "true" : "false";
	my $cmd = "ip=$ip\nhostname=$hostname\ntimeout=$timeout\ninitial=$initial\nhave_drbd=$have_drbd\n"
		. "DRBD_MAJOR=$DRBD_MAJOR\nDRBD_DEVNAME=$DRBD_DEVNAME\nMINOR_COUNT=$MINOR_COUNT\n"
		. $me->{_config}->{boot_script};

	$me->{_busy} = "wait_for_boot";
	_spawn( "$me->{_id}->wait_for_boot", $cmd,
		sub {
			my $ex = shift;
			$me->say(sprintf "wait_for_boot: exit code %d:%d\n", $ex >> 8,$ex & 255);
			return if $::LGE_CTH::exiting;

			die("please help me to boot $me->{_config}->{hostname}\n",caller) if ($ex);

			$me->{_boot_time} = time;
			$me->{_busy} = 0;
			if ($me->{_status}->{status} eq '__UNDEF__') {
				$me->status("up","initial_boot", "done");
			} else {
				$me->status("up","heal", "done");
				Log("HEAL $me->{_id}");
				--$LGE_CTH::FAILED;
			}
			$me->heartbeat;
		}
	);
};

sub fail {
	my $me = shift;
	my ($hostname,$ip) =
		@{$me->{_config}}{qw(hostname admin_ip)};
	croak "$me->{_id} is busy $me->{_busy}\n"
		if $me->{_busy};
	$me->say("no point in crashing me, I'm down!"), return
		if $me->{_status}->{status} ne "up";

	$LGE_CTH::FAILED += 500;
	$me->{_busy} = "fail";
	$me->{_status}->{status} = "crashing"; # don't propagate yet, failing heartbeat will propagate it
	Log("FAIL $me->{_id}");
	_spawn( "$me->{_id}->fail", "on $ip: generic_do_crash", 'SYNC');
}

1;
