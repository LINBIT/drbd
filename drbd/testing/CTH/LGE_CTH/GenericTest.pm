package LGE_CTH::GenericTest;
# $Id: GenericTest.pm,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $
our @ISA = 'LGE_CTH::Resource';

our %ClassData = (
	%LGE_CTH::Resource::ClassData,
	config_template => {
		which => undef,
		fs    => undef,
		do_once => '',
		do_once_per_node => '',
		do_on_first_start => '',
		start_script => '# overridden in CheckConfig!',
		stop_script => 'generic_test_stop',
		start_ASYNC => 1,
	},
);

sub CheckConfig {
	my $me = shift;

	$me->SUPER::CheckConfig;

	my $which = $me->{_config}->{which};
	# FIXME die unless fs -> isa FileSystem ...
	for my $s (qw( do_on_first_start start_script stop_script )) {
		next unless $me->{_config}->{$s} eq '# overridden in CheckConfig!';
		(my $fn = $s) =~ s/_script$//;
		$me->{_config}->{$s} = "${which}_$fn";
	}
}

sub env {
	my $me = shift;
	return "MNT=$me->{_config}->{fs}->{_config}->{mount_point}"
};


sub Initialize {
	my $me = shift;
	$me->depends_on($me->{_config}->{fs});
}

sub FileSystem_changed { }

