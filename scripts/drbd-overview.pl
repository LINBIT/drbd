#!/usr/bin/perl

use strict;
use warnings;

#use Data::Dumper;

# globals
my $stderr_to_dev_null = 1;
my $watch = 0;
my %drbd;
my %minor_of_name;
my @resources;
my @devices;
my @stacked_resources;
my @stacked_devices;
my @stacked_devices_ll_dev;

my %xen_info;

# sets $drbd{minor}->{name} (and possibly ->{ll_dev})
sub map_minor_to_resource_names()
{
	my $i;
	for ($i = 0; $i < @resources; $i++) {
		$drbd{$devices[$i]}{name} = $resources[$i];
		$minor_of_name{$resources[$i]} = $devices[$i];
	}
	for ($i = 0; $i < @stacked_resources; $i++) {
		$drbd{$stacked_devices[$i]}{name} = $stacked_resources[$i];
		$drbd{$stacked_devices[$i]}{ll_dev} = $stacked_devices_ll_dev[$i];
	}
}

# sets $drbd{minor}->{state} and (and possibly ->{sync})
sub slurp_proc_drbd_or_exit() {
	unless (open(PD,"/proc/drbd")) {
		print "drbd not loaded\n";
		exit 0;
	}

	my $minor;
	while (defined($_ = <PD>)) {
		chomp;
		/^ *(\d+):/ and do {
			# skip unconfigured devices
			$minor = $1;
			if (/^ *(\d+): cs:Unconfigured/) {
				next
				unless exists $drbd{$minor}
				   and exists $drbd{$minor}{name};
			}
			# add "-" for protocol, in case it is missing
	     		s/^(.* cs:.*\S)   ([rs]...)$/$1 - $2/;
			# strip off what will be in the heading
			s/^(.* )cs:([^ ]* )st:([^ ]* )ds:([^ ]*)/$1$2$3$4/;
			s/^(.* )cs:([^ ]* )st:([^ ]* )ld:([^ ]*)/$1$2$3$4/;
			s/^(.* )cs:([^ ]*)$/$1$2/;
			# strip off leading minor number
			s/^ *\d+:\s+//;
			$drbd{$minor}{state} = $_;
		};
		/^\t\[.*sync.ed:/ and do {
			$drbd{$minor}{sync} = $_;
		};
		/^\t[0-9 %]+oos:/ and do {
			$drbd{$minor}{sync} = $_;
		};
	}
	close PD;
}

# sets $drbd{minor}->{pv_info}
sub get_pv_info()
{
	for (`pvs --noheadings --units g -o pv_name,vg_name,pv_size,pv_used`) {
		m{^\s*/dev/drbd(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$} or next;
		#  PV  VG  PSize  Used
		$drbd{$1}{pv_info} = { vg => $2, size => $3, used => $4 };
	}
}

sub pv_info
{
	my $t = shift;
	"lvm-pv:", @{$t}{qw(vg size used)};
}

# sets $drbd{minor}->{df_info}
sub get_df_info()
{
	for (`df -TPhl -x tmpfs`) {
		#  Filesystem  Type  Size  Used  Avail  Use%  Mounted  on
		m{^/dev/drbd(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)} or next;
		$drbd{$1}{df_info} = { type => $2, size => $3, used => $4,
			avail => $5, use_percent => $6, mountpoint => $7 };
	}
}

sub df_info
{
	my $t = shift;
	@{$t}{qw(mountpoint type size used avail use_percent)};
}

# sets $drbd{minor}->{xen_info}
sub get_xen_info()
{
	my $dom_name;
	for (`xm list --long`) {
		/^\s+\(name ([^)\n]+)\)/ and $dom_name = $1;
		/drbd:([^)\n]+)/ and $drbd{$minor_of_name{$1}}{xen_info} = $dom_name;
		m{phy:/dev/drbd(\d+)} and $drbd{$1}{xen_info} = $dom_name;
	}
}

# very stupid option handling
$stderr_to_dev_null = 0 if @ARGV and $ARGV[0] eq '-d';

open STDERR, "/dev/null"
	if $stderr_to_dev_null;

@resources = split(/\s+/, `drbdadm sh-resources`);
@devices = map { s,^/dev/drbd(\d+)\n?\z,$1,; $_ } `drbdadm sh-dev all`;
@stacked_resources = split(/\s+/,`drbdadm -S sh-resources`);
@stacked_devices = map { s,^/dev/drbd(\d+)\n?\z$,$1,; $_ } `drbdadm -S sh-dev all`;
@stacked_devices_ll_dev = map { s,^/dev/drbd(\d+)\n?\z$,$1,; $_ } `drbdadm -S sh-ll-dev all`;

map_minor_to_resource_names;

slurp_proc_drbd_or_exit;

get_pv_info;
get_df_info;
get_xen_info;

# generate output, adjust columns
my @out = [];
my @maxw = ();
my $line = 0;
for my $m (sort { $a <=> $b } keys %drbd) {
	my $t = $drbd{$m};
	my @used_by = exists $t->{xen_info} ? "xen-vbd: $t->{xen_info}"
		    : exists $t->{pv_info} ? pv_info $t->{pv_info}
		    : exists $t->{df_info} ? df_info $t->{df_info}
		    : ();

	$out[$line] = [
		sprintf("%3u:%s", $m, $t->{name} || "??not-found??"),
		$t->{ll_dev} ? "^^$t->{ll_dev}" : "",
		split(/\s+/, $t->{state}),
		@used_by
	];
	for (my $c = 0; $c <  @{$out[$line]}; $c++) {
		my $l =  length($out[$line][$c]) + 1;
		$maxw[$c] = $l unless $maxw[$c] and $l < $maxw[$c];
	}
	++$line;
}
my @fmt = map { "%-${_}s" } @maxw;
for (@out) {
	for (my $c = 0; $c < @$_; $c++) {
		printf $fmt[$c], $_->[$c];
	}
	print "\n";
}
