package LGE_CTH;
# $Id: LGE_CTH.pm,v 1.1.2.3 2004/07/07 08:56:26 lars Exp $
use strict;
use warnings;
use Carp;

require Exporter;
our @ISA = "Exporter";
our @EXPORT = (qw{ Configure Run Log });
our @EXPORT_OK = (qw{
	mytimestr _spawn pid_is_pending kill_if_pending
	$DRBD_DEVNAME $DRBD_MAJOR $MINOR_COUNT
	});
our %EXPORT_TAGS = (
	util => [qw{
		Log mytimestr _spawn pid_is_pending kill_if_pending
		$DRBD_DEVNAME $DRBD_MAJOR $MINOR_COUNT
	}], # for internal use only
); 

use POSIX;
use IPC::SysV qw(IPC_PRIVATE IPC_CREAT);
use IPC::Semaphore;
use Time::HiRes;
use Fcntl qw(:DEFAULT :flock);

# at the end of this file, because they use helpers defined here:
#require LGE_CTH::Node;
#require LGE_CTH::DRBD_Resource;
#...

##
## Interface
##

our %bash_script;

sub Configure;
sub Run;
sub Log;

my  $clean_exit = 0;
sub clean_exit { $clean_exit = 1; exit @_; };

our $MINOR_COUNT =  4;
our $DRBD_MAJOR  = 43;
our $DRBD_DEVNAME = "nb";   # the part between /dev/ and the minor number.
		# = "nbd/";
		# = "drbd";
		# = "drbd/";

# set this to something ne '' to skip the initial full sync
# NOTE: "false" is also true. only "" is false :-)
$::DRBD_SKIP_INITIAL_SYNC="";

##
## private
##

# some variables used by our submodules

# referenced by subclasses of ::Component to check uniqueness of certain
# things, like ips and hostnames
our %uniq = ();

our @ALL_OBJ   = ();
our @EVENT_OBJ = ();
our $FAILED    = 0;

our @Node = ();
our @Link = ();
our @Disk = ();

our @DRBD_Resource = ();
our @FileSystem = ();

our @Resource = ();
our @CRM     = ();
our $CRM;

# some internal variables

our $pending = 0;
our $exiting;

# FIXME make it "random" and the "randomness" configurable
my $sleeptime = 20; # seconds between two generated events.

my $configured = 0;
my $config_file;
my $max_fail = 1;  # DO NOT up this yet, you will break internal consistency in this CTH terribly.
my $move_resource_prob = 30;

my $logprefix;
my $logname;
my $logfile;
my $srand;

my %pending_events = ();
my ($sem, $mpid);

# functions

sub mytimestr();
sub Log;
sub boot_nodes;

sub pid_is_pending($) { return exists $pending_events{$_[0]} }
sub kill_if_pending($) {
	local $SIG{CHLD}; # ?
	my $pid = $_[0];
	return unless pid_is_pending $pid;
	my $cb = delete $pending_events{$pid};
	# kill 'TERM' => $pid;
	kill -15 => $pid;
	return undef if waitpid($pid,0) <= 0;
	# die "THINKO" if $pid != waitpid ...
	$cb->($?) if $cb;
}

##
## implementation
##

my $usage = <<___;
Usage:
use LGE_CTH::Configure (
	logfile   => "some.file.log",
	logprefix => "test_run_name",
	config_file => "some.config.file";
	FIXME add missing...
);
___
sub Configure {
	die "You must use Config exactly ONCE!\n" if $configured;

	OPTION: while (@_) {
		for ($_[0]) {
			/^logfile$/   and shift, $logname   = shift, next OPTION;
			/^logprefix$/ and shift, $logprefix = shift, next OPTION;
			/^sleeptime$/ and shift, $sleeptime = shift, next OPTION;
			/^rand_seed$/ and shift, $srand     = shift, next OPTION;
			/^config_file$/ and shift, $config_file = shift, next OPTION;
			/^move_res$/  and shift, $move_resource_prob = shift, next OPTION;
		}
		die "unkown option $_[0]\n$usage";
	}
	die "logfile missing from argument list\n$usage"
		unless defined $logname;
	die "logprefix missing from argument list\n$usage"
		unless defined $logprefix;
	die "config_file missing from argument list\n$usage"
		unless defined $config_file;
	# unlink $logname;
	-e $logname and warn ("appending log to '$logname'\n");
	# FIXME LOG -=> $logfile = IO::Handle ...
	sysopen(LOG,$logname,O_WRONLY|O_APPEND|O_CREAT) or die "open logfile '$logname': $!";
	syswrite(LOG,"\n\n-- \n\n") or die "syswrite>LOG: $!";

	$srand = unpack "L", `head -c4 /dev/urandom` if not defined $srand;
	srand($srand);

	my $died = 0;
	$SIG{__WARN__} = sub { print STDERR "@_"; Log(@_); };
	$SIG{__DIE__}  = sub { warn @_; exit 255 unless $died++ or $exiting; };

	warn(<<___);
New Start $0 @ARGV
rand_seed = $srand
sleeptime = $sleeptime
move_res  = $move_resource_prob
config_file = $config_file
___

	$SIG{CHLD} = \&__reap;
	$SIG{INT}  = sub { $SIG{INT} = 'DEFAULT'; warn("SIGINT caught, exiting"); $pending = -1; };

	-r $config_file and do $config_file
		or die "configuration in $config_file is unusable.\n$@\n";

	$CRM = new LGE_CTH::CRM;
	for my $n (@Node) { $CRM->depends_on($n); }

	$configured = 1;
};


# FIXME make it configurable which parts will reveice events
# e.g. selectively only test for network failure

sub active_objects {
	if ($FAILED < $max_fail) {
		return grep { $_->takes_events } @EVENT_OBJ;
	} else {
		return grep { $_->takes_events and $_->{_status}->{status} eq 'down'; } @EVENT_OBJ;
	}
}

sub wait_for_pending_events {
	while (grep { $_->{_busy} } @EVENT_OBJ) {
	       	exit 130 if $pending < 0;
		sleep 1
	}
}

sub choose { @_ ? $_[rand @_] : undef; }


# not just sleep, because every SIGCHLD or similar wakes us up
sub mysleep($) {
	my $now = time;
	my $expire = $now + $_[0];
	# print STDERR "time=$now\nexpire=$expire\n"; 
	while (time < $expire and $pending > 0) { sleep 1 }
}

sub Run {
	die "You must use Config first!\n" if not $configured;

	@Resource = grep { $_->isa('LGE_CTH::Resource') and $_->{_refcnt} == 0; } @ALL_OBJ;
	die "No Resource configured in $config_file??\n" unless @Resource;
	print "Services:\n", map { "\t" . $_->as_string . "\n" } @Resource;

	boot_nodes;

	warn join "\n", ".", (map { $_->as_string } @EVENT_OBJ, @Resource),
		 $::LGE_IS_DEBUGGING ? "Failed: $FAILED\n" : "";
	wait_for_pending_events;

	warn("\n.\n#\n#\tINITIAL SETUP\n#\n");

	$CRM->start_all;
	# wait_for_pending_events;

	kill 'CHLD' => $$;
	# effect: trigger an other SIGCHLD...
	# this whole signal magic is a little bit messy :(

	warn("\n.\n#\n#\tENTER MAINLOOP\n#\n");
	warn("Failed: $FAILED\n") if $::LGE_IS_DEBUGGING;


	my ($part,$event,$lasttime,@obj);

	print STDERR "Event Obj:", map({ " $_->{_id}" } @EVENT_OBJ),"\n";
	$pending = @Resource;
	my $did_something = 0;
	my $last_time = time;
	for (;;) {
		# if all nodes are busy, we don't do anything.
		# wait_for_pending_events unless grep { not $_->{_busy} } @Node;

		if ($did_something) {
			warn join "\n", ".", (map { $_->as_string } @EVENT_OBJ, @Resource),
				 $::LGE_IS_DEBUGGING ? "Failed: $FAILED\n" : "";
		}

		if ($FAILED and time - $last_time > 600) {
			# in case we could not do something for over 10 minutes,
			# conclude this won't work out anymore.
			die "Seems I have some hanging processes, maybe wait_sync blocks because DRBD receiver blocks?\n"
		}
		mysleep $sleeptime;

		last if $pending <= 0;
		$did_something = 0;

		# wait_sync and wait_for_boot increase $FAILED by 0x800 or 0x1000,
		# so if the hardware is up, we still may move resources.
		if ( ($FAILED & 0xff) == 0 and
		     int(rand(100)) < $move_resource_prob ) {
			$part = choose(@Resource);
		} else {
			@obj = active_objects;
			$part = choose(@obj);
		}
		if ($part and $part->isa('LGE_CTH::Resource')) {
			# TODO: $CRM->balance :-)>
			my ($cn,$nn);
			$cn = $part->{_current_node};
			if ($cn) {
				$nn = ( sort { $a->{_resources} <=> $b->{_resources} } 
				        grep { $_ != $cn and $_->{_busy} =~ /^$|^wait_sync/ }
					@LGE_CTH::Node
				)[0];
				$part->relocate_to($nn) if $nn;
				$did_something = 1;
				$last_time = time;
			}
		} elsif ($part) {
			$event = choose($part->events);
			if ($event) {
				$part->$event;
				$did_something = 1;
				$last_time = time;
			} else {
				$part->say("active, but no event possible?");
			}
		} else {
			print STDERR "cannot do anything, FAILED=$FAILED\n";
			kill 'CHLD' => $$;
			# effect: trigger an other SIGCHLD...
			# this whole signal magic is a little bit messy :(
		}
	}

	# FIXME clean up ...
	$::link->heal unless $::link->{_status}->{status} eq 'up';

	clean_exit 0;
}

sub boot_nodes {
	for my $node (@Node) {
		$node->wait_for_boot;
	}
}

sub mytimestr() {
	my ($t,$m) = Time::HiRes::gettimeofday();
	my @t = (gmtime($t))[5,4,3,2,1,0];
	$t[0]+=1900;
	$t[1]+=1;
	return sprintf "%d-%02d-%02dt%02d%02d%02d.%06d",@t,$m;
}
sub Log {
	my $t   = mytimestr;
	my $msg = join " ", @_;
	# squeeze, just in case
	$msg =~ s/^\s*(.*?)\s*$/$1/gs;
	$msg =~ s/\n/\n> /gm;
	syswrite(LOG,"$t $logprefix $msg\n") or die "syswrite>LOG: $!";

	## flock is not really necessary as long as we
	## use sysopen O_APPEND and syswrite. (unbuffered io)
	## but one _could_ play safe ...
	# flock(LOG, LOCK_EX) or die "flock: $!";
	# syswrite(LOG,"$t $logprefix $msg\n") or die "$!";
	# flock(LOG, LOCK_UN) or die "flock: $!";
}

BEGIN {
	die "oops, \$mpid already set ?? \$\$=$$, \$mpid=$mpid" if $mpid;
	# END is called on exit of forked child, too :(
	# BEGIN is only called once, so this is the master process,
	# and the only one that may destroy the semaphore again.
	$mpid = $$;
	#print STDERR "master pid is $$\n";
	# I need one semaphore, initialized to zero.
	$sem = new IPC::Semaphore(IPC_PRIVATE,1,S_IRWXU)
		or die "could not get semaphore: $!\n";
	$ENV{__I_MEAN_IT__} = '__YES__';
}
END {
	if ($$ == $mpid and not $exiting) {
		$exiting = 1;
		warn("\n.\n#\n#\tEXITING\n#\n") if $configured;
		#print STDERR "$$ removing semaphore\n";
		$CRM->stop_all if $clean_exit;
		my $pid;
		for $pid (keys %pending_events) {
			kill_if_pending($pid);
		}
		$sem->remove or warn "could not remove semaphore: $!";
		if ($configured) {
			# Log( LGE_CTH::Component::__dump_hash( \%LGE_CTH::uniq ) );
			# for (@ALL_OBJ) { Log($_->Dump); }
		}
	}
}
sub __down { $sem->op(0,-1,0) or warn "__down failed: $!" }
sub __up   { $sem->op(0,+1,0) or warn "__up   failed: $!" }

sub __exec_with_logger {
	my ($tag,$script) = @_;
	my $logger = open(STDOUT,"|-");
	die "fork failed: $!" unless defined $logger;
	if ($logger == 0) {
		$0 = "logger for $tag";
		while (defined($_=<STDIN>)) { Log("$tag: $_"); }
		exit 0;
	} else {
		$| = 1;
		open(STDERR,">&STDOUT") or die "could not dup STDERR to STDOUT";

		my $ex;
		if (ref $script eq 'CODE') {
			$ex = &$script;
		} else {
			$ex = system qw(bash -c),"source ./functions.sh\n$script";
			$ex = ($ex & 255)
				? 0x80|$ex & 255
				: $ex >> 8;
		}

		# print "exit with $ex from: $script";

		# make sure the logging sub process has flushed and
		# exited, too ...
		close STDERR;
		close STDOUT;

		exit $ex;
	}
	die "NOT REACHED. ??";
}

# spawn (logger tag, bash script, { callback })
sub _spawn {
	my ($tag,$script, $cb) = @_;

	die "_spawn may only be used by the top level script process!"
		unless $$ == $mpid;

	croak "CODE ref or 'SYNC' expected, not '$cb'\n"
		unless ref($cb) eq "CODE" or $cb eq 'SYNC';

	my $kid;
	if (ref $cb eq 'CODE') {
		return 0 if $exiting; # when exiting, only allow SYNC commands

		$kid = fork;
		die "fork failed: $!" unless defined $kid;
		if ($kid) {
			print STDERR mytimestr . " [$kid]: $tag\n";
			Log("begat [$kid] $tag\n");
			$pending_events{$kid} = $cb;
			__up; # tell kid I set up the hash.
			return $kid;
		}
	} else {
		local $SIG{CHLD};
		$kid = fork;
		die "fork failed: $!" unless defined $kid;
		if ($kid) {
			print STDERR mytimestr . " exec $tag\n";
			Log(" exec [$kid] $tag\n");
			__up; # tell kid it may continue
			waitpid($kid,0);
			my $ex  = $?;
			Log (sprintf "pid = $kid; ex = %d:%d\n", $ex >> 8,$ex & 255);
			die (sprintf "cannot $tag, returned %d:%d\n", $ex >> 8,$ex & 255)
				if $ex;
			return $ex;
		}
	}
	# in child
	local ($SIG{CHLD},$SIG{INT});
	$0 = "action of $tag";
	$tag = "[$$] $tag";

	# synchronisation with parent,
	# or we could die early,
	# before the pending_events hash was set up ...
	__down;
	__exec_with_logger($tag,$script);
}

sub __reap {
	# return unless $mpid == $$;
	my ($pid,$ex);
	while (1) {
		$pid = waitpid(-1, WNOHANG);
		$ex = $?;
		last if $pid <= 0;
		Log(sprintf "pid = %d; ex = %d:%d\n",	$pid,$ex >> 8,$ex & 255);
		next if not exists $pending_events{$pid};
		my $cb = delete $pending_events{$pid};
		&$cb($ex) if $cb;
		if ($ex) {
			# $SIG{CHLD} = "DEFAULT";
			die "$pid terminated with nonzero exit code.  please FIX this!\n"
				unless $exiting;
		}
	}
}

# {{{1
# at the end of this file, because they use helpers defined here:
require LGE_CTH::Node;
require LGE_CTH::Link;
require LGE_CTH::Disk;
require LGE_CTH::DRBD_Resource;
require LGE_CTH::Resource;
require LGE_CTH::FileSystem;
require LGE_CTH::GenericTest;
require LGE_CTH::CRM;

1;
