package LGE_CTH::FileSystem;
# $Id: FileSystem.pm,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $
use strict;
use warnings;
use Carp;

#
# Simple Class for a FileSystem
#

use LGE_CTH ":util";
our @ISA = 'LGE_CTH::Resource';

sub takes_events { 0 };

our %ClassData = (
	%LGE_CTH::Resource::ClassData,
	config_template => {
		type => undef,
		mount_point => undef,
		drbd => undef,
		do_once => '',
		do_once_per_node => '',
		do_on_first_start => '# mkfs_$type, set in CheckConfig',
		start_script => 'do_mount',
		stop_script => 'do_umount',
		start_SYNC => 1,
	},
);

sub CheckConfig {
	my $me = shift;
	my $type = $me->{_config}->{type};
	$me->SUPER::CheckConfig;
	$me->{_config}->{do_on_first_start} = "mkfs_$type";
	# FIXME add more paranoia, check that drbd is right class, ...

	$me->depends_on($me->{_config}->{drbd});
}

sub env {
	my $me = shift;
	my $minor = $me->{_config}->{drbd}->{_config}->{minor};
	return "TYPE=$me->{_config}->{type} DEV=/dev/nb$minor MNT=$me->{_config}->{mount_point}";
}

sub DRBD_Resource_changed {
	# FIXME
}

1;
