#!/usr/bin/perl -w
#    Author: Randy Hron <rwhron (at) earthlink dot net>
#       This software may be used and distributed according to the terms of
#       the GNU General Public License, http://www.gnu.org/copyleft/gpl.html
# 
#     Summarize output of tiobench2.pl for multiple kernels/runs.
#       Assumes logfiles created with: 
#       ./tiobench2.pl > tiobench-`uname -r` 2> tiobench-`uname -r`.err
use strict;
$|++;

# these keywords in tiobench.pl logfile determine "field"
# Sequential Reads
# Random Reads
# Sequential Writes
# Random Writes

my $field = 'none';
my $file;

# each "paydirt" line has these fields.
my ($kver, $size, $block, $thread, $rate, $cpu, $avg_lat, $max_lat, $lat_gt_2, $lat_gt_10, $cpu_eff);
my (%kver, %size, %block, %thread, %rate, %cpu, %avg_lat, %max_lat, %lat_gt_2, %lat_gt_10, %cpu_eff);

# read in tiobench.pl output files
opendir(DIR, ".") or die $!;

while ($file = (readdir(DIR))) {
	# convention is logs are called tiobench-`uname -r`
	next unless $file =~ /tiobench-.*/o;
	next if $file =~ /.err$/o;
	open(FILE, $file) or die $!;
	while (<FILE>) {
		next if /^$/o;
		next if /---------/o;
		next if /Kernel|Maximum/o;	# headers
		next if /^File|^Read|^Latency|^Percent/o;
		# old logfile format
		next if /^ /o;
		if (/Sequential Reads/o) {
			$field = 'read';
			next;
		} elsif (/Random Reads/o) {
			$field = 'rread';
			next;
		} elsif (/Sequential Writes/o) {
			$field = 'write';
			next;
		} elsif (/Random Writes/o) {
			$field = 'rwrite';
			next;
		} 
		next if $field eq 'none';
		($kver, $size, $block, $thread, $rate, $cpu, $avg_lat, 
		$max_lat, $lat_gt_2, $lat_gt_10, $cpu_eff) = split;
		# track versions, etc for later looping
		next unless $kver;
		$kver{$kver}		= $kver;
		$block{$block}		= $block;
		$thread{$thread}	= $thread;
		$size{$size}		= $size;
		# fields
		$cpu =~ s/%//o;
		$rate{$kver}{$thread}{$size}{$block}{$field}		= $rate;
		$cpu{$kver}{$thread}{$size}{$block}{$field}		= $cpu;
		$avg_lat{$kver}{$thread}{$size}{$block}{$field}		= $avg_lat;
		$max_lat{$kver}{$thread}{$size}{$block}{$field}		= $max_lat;
		$lat_gt_2{$kver}{$thread}{$size}{$block}{$field}	= $lat_gt_2;
		$lat_gt_10{$kver}{$thread}{$size}{$block}{$field}	= $lat_gt_10;
		$cpu_eff{$kver}{$thread}{$size}{$block}{$field}		= $cpu_eff;
	}
}
my $header = "
                              File  Blk   Num                    Avg       Maximum     Lat%     Lat%    CPU
Kernel                        Size  Size  Thr   Rate  (CPU%)   Latency     Latency      >2s     >10s    Eff
---------------------------- ------ ----- ---  ------------------------------------------------------------
";
format REPORT = 
@<<<<<<<<<<<<<<<<<<<<<<<<<<< @||||| @|||| @##  @##.## @#.##% @####.### @#######.## @#.##### @#.##### @#####
$kver, $size{$size}, $block{$block}, $thread{$thread}, $rate{$kver}{$thread}{$size}{$block}{$field}, $cpu{$kver}{$thread}{$size}{$block}{$field}, $avg_lat{$kver}{$thread}{$size}{$block}{$field}, $max_lat{$kver}{$thread}{$size}{$block}{$field}, $lat_gt_2{$kver}{$thread}{$size}{$block}{$field}, $lat_gt_10{$kver}{$thread}{$size}{$block}{$field}, $cpu_eff{$kver}{$thread}{$size}{$block}{$field}
.

# print summary
print "
File size in megabytes, Blk Size in bytes. 
Read, write, and seek rates in MB/sec. 
Latency in milliseconds.
Percent of requests that took longer than 2 and 10 seconds.
";


my %report;
$report{'read'}		= "Sequential Reads";
$report{'rread'}	= "Random Reads";
$report{'write'}	= "Sequential Writes";
$report{'rwrite'}	= "Random Writes";

$-=0; $~='REPORT'; $^L=''; # reporting variables
my ($a, $b);
foreach $field ('read', 'rread', 'write', 'rwrite') {
	print "\n", $report{$field};
	print $header;
	foreach $block (sort keys %block) {
		foreach $size (sort keys %size) {
			#foreach $thread (keys %thread) {
			foreach $thread (8, 16, 32, 64, 128) {
				foreach $kver (sort keys %kver) {
					next unless $rate{$kver}{$thread}{$size}{$block}{$field};
					write;
				}
			}
		}
	}
}
