package main;
# $Id: generic_test.pl,v 1.1.2.1 2004/05/27 12:44:18 lars Exp $
use strict;
use warnings;

use LGE_CTH;

sub show_usage() {
	print <<___;
Usage: $0 test_name
where currently supported tests are:
	wbtest
	tiobench
	dummy     (does only touch one file, and sleep, in a loop)

since the path to ./functions.sh is still hardcoded, you have to start
this in the directory where it lives, or copy functions.sh over to the
current directory...

to tune which "HW" parts may fail, or what config file to use
or which file system you like best, or where to mount them,
you still have to edit this file...

to add more tests, you have to edit this file, and you need to add bash
functions named <your_test>_start, and maybe <your_test>_stop if the
generic_test_stop does not fit, to functions.sh.

there currently is no paranoia implemented about whether the needed
programs exist on the target box.
___
}

show_usage and exit 1
unless $ARGV[0] =~ /^(wbtest|tiobench|dummy)$/
	and -e "./functions.sh";

my $which = $ARGV[0];

our (
	$left,$right,$link,
	$r0, $r1, $fs0, $fs1,
);

# CHANGE
# sleeptime, move_res, logfile
# logfile gets OVERWRITTEN with each run !!
Configure(
	rand_seed => 1234567890,
	logfile => "tmp.out",
	logprefix => "test0",
	config_file => "uml-minna.conf",
	# config_file => "bloodymary.conf",
	# config_file => "chipdale.conf",
	sleeptime => 30,
	move_res => 50, # probability (percent) of moving resources when $FAILED == 0
);


# $::LGE_IS_DEBUGGING = 1;
# $ENV{DEBUG} = '-vx';
# $ENV{DEBUG} = '-v';
# $ENV{DEBUG} = '';

new LGE_CTH::GenericTest {
	fs    => $fs0,
	which => $which,
};

new LGE_CTH::GenericTest {
	fs    => $fs1,
	which => $which,
};


	Run;

die "NOT REACHED ??";
