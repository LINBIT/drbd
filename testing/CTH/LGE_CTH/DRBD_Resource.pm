# $Id: DRBD_Resource.pm,v 1.1.2.3 2004/07/07 08:56:26 lars Exp $
package LGE_CTH::DRBD_ResourceInstance;
use strict;
use warnings;
use Carp;

#
# helper class first. This is one instance of a pair of DRBDs.
#

use LGE_CTH ":util";
our @ISA = 'LGE_CTH::Component';

sub takes_events { 0 };

our %ClassData = (
	events => {},
	config_template => {
			master_resource => undef,
			index    => undef,
			settings => undef,
			disk     => undef,
	},
	states => {
		role => [ qw(active passive) ],
		data => [ qw(valid inconsistent) ],
		disk => [ qw(attached detached) ],
		# keep these state names, I may depend on the sort order!
		conn => [ qw(Alone Try connected syncSource syncTarget) ],
	},
);

sub wait_sync {
	my ($me,$event) = @_;
	my ($link,$minor,$name) = @{$me->{_config}->{master_resource}->{_config}}{qw( link minor name )};
	my $node = $me->{_config}->{settings}->{node};
	my ($hostname,$ip) = @{$node->{_config}}{qw/hostname admin_ip/};
	my $cmd;

	if ($link->{_status}->{status} ne 'up') {
		warn "$link->{_id} not up??\n";
	} elsif ($node->{_busy} and $node->{_busy} !~ /^wait_sync/) {
		warn "$node->{_id} busy: $node->{_busy}\n";
	} else {
		$cmd = "on $ip: drbd_wait_sync DEV=/dev/$DRBD_DEVNAME$minor";
		$node->{_busy} = "wait_sync" unless $node->{_busy};
		$node->{_busy} .= " $name ";
		$LGE_CTH::FAILED += 1000;
		_spawn( "wait_sync $name on $hostname after $event", $cmd,
			sub {
				my $ex = $_[0];
				$node->say("wait_sync $name on $hostname done: $ex");
				$node->{_busy} =~ s/ $name / /;
				$node->{_busy} = ""  if $node->{_busy} =~ /^wait_sync\s*$/;
				$LGE_CTH::FAILED -= 1000;
				# TODO update state and so on.
			}
		);
	}
}

sub initial_setup {
	my ($me,$node) = @_;

	my ($mr,$settings,$disk) = @{$me->{_config}}{qw(master_resource settings disk )};
	die unless $node == $settings->{node};
	return if $me->{DID_SETUP}++;

	_spawn("$me->{_id}: initial_setup on $node->{_config}->{hostname}",
		sub {
			my $cmd = ". ./functions.sh; on $node->{_config}->{admin_ip}: drbd_append_config "
			     . "RES=$mr->{_config}->{name} LO_DEV=$disk->{_config}->{dev} NAME=$disk->{_config}->{name}";
			open (DRBD_CONF,"|$cmd")
				or die "$cmd $node->{_id}:drbd.conf: $!";
			print DRBD_CONF $mr->as_conf_string
				or die "print | $cmd $node->{_id}:drbd.conf: $!";
			close DRBD_CONF
				or die "close $node->{_id}:drbd.conf status $? $!";
			0;
		},
		'SYNC'
	);
	$me->wait_sync('initial_boot');
}

sub Node_changed {
	my ($me,$node,$info,$event) = @_;	
	my ($hostname,$ip) = @{$node->{_config}}{qw/hostname admin_ip/};
	my $name = $me->{_config}->{master_resource}->{_config}->{name};
	my ($cmd,$what);

	return if ($node->{_status}->{status} eq 'down');
	$what = ($event eq 'END_OF_TEST') ? "down" : "up";

	return $me->initial_setup($node) if ($event eq 'initial_boot');

	$cmd = "on $ip: drbdadm_$what name=$name";
	_spawn( "drbdadm $what $name on $hostname after $event", $cmd, 'SYNC');
	$me->wait_sync($event) if $what eq 'up';
}

sub Disk_changed {
	my ($me,$disk,$info,$event) = @_;	
	my $node = $me->{_config}->{settings}->{node};
	my ($hostname,$ip) = @{$node->{_config}}{qw/hostname admin_ip/};
	my ($link,$minor,$name) = @{$me->{_config}->{master_resource}->{_config}}{qw( link minor name )};
	my ($cmd,$what);

	return if $event ne 'heal';
	return if $node->{_status}->{status} ne 'up';

	$cmd = "on $ip: drbd_reattach DEV=/dev/$DRBD_DEVNAME$minor name=$name";
	_spawn( "drbd_reattach $name on $hostname", $cmd, 'SYNC');
	$me->wait_sync("attach");
}

1;

########################################################################

package LGE_CTH::DRBD_Resource;
use strict;
use warnings;
use Carp;

use LGE_CTH ":util";
use LGE_CTH::Disk;
use LGE_CTH::Component;

our @ISA = 'LGE_CTH::Component'; # XXX no, its a resource/service ...

our %ClassData = (
	states => [ qw(operational degraded FUBAR) ],
	events => {},
	config_template => {
		name              => undef,
		minor             => undef,
		protocol          => 'C',       # A,B,C
		usize             => 0,
  	        'incon-degr-cmd'  => "reboot -f",
		startup => {
			'degr-wfc-timeout' => 120, # 2 minutes.
		},
		disk    => {
			'on-io-error' => 'detach', # passon,panic,detach
			# 'size'        => undef,    # deprecated
		},
		net     => {
			'sndbuf-size'    => 2*65535,  # 512*1024 or similar
			'timeout'        => 60,       #  6 seconds  (unit = 0.1 seconds)
			'connect-int'    => 10,       # 10 seconds  (unit = 1 second)
			'ping-int'       => 10,       # 10 seconds  (unit = 1 second)
			'max-buffers'    => 32,
			'max-epoch-size' => 2048,
		},
		syncer  => {
			'rate'  => '10M',
			'group' => 1,
			'al-extents' => 257,
		},
		link   => undef,
		peers  => [{
			node         => undef,
			lodev        => undef,
			port         => undef,
			'meta-disk'  => 'internal',
			'meta-index' => -1,
			lo_may_fail   => 0,
			meta_may_fail => 0,
		}],
	},
);

# does not take events
sub takes_events { 0 }

sub CheckConfig {
	my $me = shift;
	my $c = $me->{_config};
	my $link  = $c->{link};
	my $peers = $c->{peers};
	die "link should be a LGE_CTH::Link, not '$link'!\n"
		unless ref $link and $link->isa('LGE_CTH::Link');
	die "need exactly two peers.\n"
		unless @$peers == 2;
	for (my $i = 0; $i < 2; $i++) {
		my $n = $peers->[$i];
		my ($node,$lodev) = @$n{qw(node lodev)};
		die "sorry, meta-disk != internal not yet implemented\n"
			if $n->{'meta-disk'} ne 'internal';
		$n->{'meta-index'} = -1;
		die "node should be a LGE_CTH::Node, not '$node'!\n"
			unless ref $node and $node->isa('LGE_CTH::Node');
		die "$node->{_id} not connected to $link->{_id}!\n"
			unless exists $link->{_config}->{_nodes}->{$node->id};
		my $disk = new LGE_CTH::Disk {
			node => $node,
			name => $c->{name},
			dev  => $lodev,
			may_fail => \$n->{lo_may_fail},
			usize => ($c->{usize} ? ($c->{usize}+128*1024) : 0)
		};
		my $instance = new LGE_CTH::DRBD_ResourceInstance {
			master_resource => $me,
			disk     => $disk,
			index    => $i,
			settings => $n,
		};
		push @{$me->{_config}->{_instances}}, $instance;

		$instance->depends_on($node);
		$instance->depends_on($disk);
		$me->depends_on($instance);
	}
	$me->depends_on($link);
}

sub as_conf_string {
	my $me = shift;
	my $c  = $me->{_config};
	my $link = $me->{_config}->{link};
	my $s  = <<___ ;
resource $c->{name} {
    protocol        $c->{protocol};
    incon-degr-cmd "$c->{'incon-degr-cmd'}";
___
	for my $n (@{$me->{_config}->{peers}}) {
		my $ip = $link->{_config}->{_nodes}->{$n->{node}->id}->{ip};
		$s .= <<___ ;
    on $n->{node}->{_config}->{hostname} {
        device         /dev/$DRBD_DEVNAME$c->{minor};
        disk           /dev/mapper/$c->{name};
        address        $ip:$n->{port};
        meta-disk      $n->{'meta-disk'}@{[ $n->{'meta-disk'} eq "internal" ? ";" : "[$n->{'meta-index'}];" ]}
    }
___
	};
	for my $k (qw(net disk syncer startup)) {
		$s .= "    $k {\n        "
		. join "\n        ",
		map {
			my $v = $c->{$k}->{$_};
			$v =~ /\s/
			? sprintf('%-14s "%s";', $_, $v)
			: sprintf('%-14s %s;', $_, $v)
		} sort keys %{$c->{$k}};
		$s .= "\n    }\n";
	}
	$s .= "}\n";
	return $s;
};

sub start {
	my ($me,$node) = @_;
	# FIXME paranoia: $node in peers, and up...
	my ($minor,$name) = @{$me->{_config}}{qw( minor name )};
	my ($hostname,$ip) = @{$node->{_config}}{qw/hostname admin_ip/};
	my ($cmd,$force);

	if ($me->{_config}->{do_once_per_node} and not $me->{"did_once:$node->{_id}"}++) {
		$cmd = "on $ip: $me->{_config}->{do_once_per_node} " . $me->env;
		_spawn("$me->{_id} do once per node on $node->{_id}", $cmd, 'SYNC');
	}
	if (not $me->{did_on_first_start}++) {
		if ($me->{_config}->{do_on_first_start}) {
			$cmd = "on $ip: $me->{_config}->{do_on_first_start} " . $me->env;
			_spawn("$me->{_id} do on first start on $node->{_id}", $cmd, 'SYNC') if $cmd;
		}
		$force = 1;
	}

       	$cmd = "on $ip: drbd_wait_peer_not_pri minor=$minor";
	_spawn("$me->{_id}: wait for $hostname to recognize ... ",$cmd,'SYNC');

       	$cmd = "on $ip: drbdadm_pri name=$name";
        $cmd .=	' "force=-- -d"' if $force;
	_spawn("$me->{_id}: Primary $name on $node->{_config}->{hostname}",$cmd,'SYNC');
}

sub stop {
	my ($me,$node) = @_;
	my $name = $me->{_config}->{name};
	my ($hostname,$ip) = @{$node->{_config}}{qw/hostname admin_ip/};
	# FIXME paranoia: $node in peers, and up...
	my $cmd = "on $ip: drbdadm_sec name=$name";
	_spawn("$me->{_id}: Secondary $name on $hostname",$cmd,'SYNC');
}

sub DRBD_ResourceInstance_changed {
	# FIXME
}

sub Link_changed {
	my ($me,$link,$info,$event) = @_;	

	# FIXME update internal state

	if ($event eq 'heal') {
		for my $i (@{$me->{_config}->{_instances}}) { $i->wait_sync("$link->{_id} heal"); }
	}
}

1;
