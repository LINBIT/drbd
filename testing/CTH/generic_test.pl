#!/usr/bin/perl
# $Id: generic_test.pl,v 1.1.2.4 2004/07/07 08:56:26 lars Exp $
use strict;
use warnings;

use LGE_CTH;
use Pod::Usage;
use Getopt::Long;


my $logfile = 'tmp.log';
my $logprefix = 'test0';
my $test_name = 'wbtest';
my $config_file = 'NONE';
my $sleeptime = 30;
my $move_prob = 50;
my $rand_seed;
my $help = 0;

GetOptions(
	"h"           => \$help,
	"help"        => sub { $help = 2 },
	"rand_seed=i" => \$rand_seed,
	"test_name=s" => \$test_name,
	"logfile=s"   => \$logfile,
	"logprefix=s" => \$logprefix,
	"config=s"    => \$config_file,
	"sleep=i"     => \$sleeptime,
	"move=i"      => \$move_prob,
) or pod2usage(2);

while(not $help) {
	$test_name =~ /^(wbtest|tiobench|dummy)$/
		or warn("unknown testname '$test_name'\n"),         $help++, last;
	$config_file and -e $config_file 
		or warn("config file ($config_file) not found\n"),  $help++, last;
	-e "./functions.sh" or warn("./functions.sh not found\n"),  $help++, last;
	last;
};

pod2usage(-exitstatus => 0, -verbose => 2) if $help > 1;
pod2usage(1) if $help;

our (
	$left,$right,$link,
	$r0, $r1, $r2, $r3, $fs0, $fs1, $fs2, $fs3,
);

# CHANGE
Configure(
	rand_seed   => $rand_seed,
	logfile     => $logfile,
	logprefix   => $logprefix,
	config_file => $config_file,
	sleeptime   => $sleeptime,
	move_res    => $move_prob,
);


# $::LGE_IS_DEBUGGING = 1;
# $ENV{DEBUG} = '-vx';
# $ENV{DEBUG} = '-v';
# $ENV{DEBUG} = '';

new LGE_CTH::GenericTest {
	fs    => $fs0,
	which => $test_name,
};

new LGE_CTH::GenericTest {
	fs    => $fs1,
	which => $test_name,
} if defined $fs1;

new LGE_CTH::GenericTest {
	fs    => $fs2,
	which => $test_name,
} if defined $fs2;

new LGE_CTH::GenericTest {
	fs    => $fs3,
	which => $test_name,
} if defined $fs3;

	Run;

die "NOT REACHED ??";

__END__

=head1 NAME

Generic test script.

=head1 SYNOPSIS

  -h		short help
  -help         more verbose help
  -rand_seed    set random seed
  -test_name    select which test to run; currently supported:
  		wbtest, tiobench, dummy
  -logfile	where to log to
  -logprefix	used to tag log lines of this run
  -config	config file to use
  -sleep	min time between two events
  -move		probability (percent) to move resources
		instead of failing some HW component

=head1 DESCRIPTION

 <config_file> should look like bloodymary.conf or chipdale.conf
 <test_name>   currently supported tests are:
	wbtest
	tiobench
	dummy     (does only touch one file, and sleep, in a loop)

since the path to ./functions.sh is still hardcoded, you have to start
this in the directory where it lives, or copy functions.sh over to the
current directory...

to tune which "HW" parts may fail, or what config file to use
or which file system you like best, or where to mount them,
you still have to change your config file...

to add more tests, you have to edit this file, and you need to add bash
functions named <your_test>_start, and maybe <your_test>_stop if the
generic_test_stop does not fit, to functions.sh.

there currently is no paranoia implemented about whether the needed
programs exist on the target box.
