package LGE_CTH::FileSystem;
# $Id: FileSystem.pm,v 1.1.2.2 2004/06/07 10:16:39 lars Exp $
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
		bdev => undef,
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
	# FIXME add more paranoia, check that bdev is right class, ...

	$me->depends_on($me->{_config}->{bdev});
}

sub env {
	my $me = shift;
	my $minor = $me->{_config}->{bdev}->{_config}->{minor};
	return "TYPE=$me->{_config}->{type} DEV=/dev/$DRBD_DEVNAME$minor MNT=$me->{_config}->{mount_point}";
}

sub DRBD_Resource_changed {
	# FIXME
}

1;
