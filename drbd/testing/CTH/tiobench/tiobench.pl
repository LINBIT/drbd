#!/usr/bin/perl -w

#    Author: James Manning <jmm@users.sf.net>
#       This software may be used and distributed according to the terms of
#       the GNU General Public License, http://www.gnu.org/copyleft/gpl.html
#
#    Description:
#       Perl wrapper for calling the tiotest executable multiple times
#       with varying sets of parameters as instructed
#
#     Updated: Randy Hron <rwhron at earthlink dot net>
#        Added latency results and CPU efficiency calculation.

use strict;
use Getopt::Long;

$|=1; # give output ASAP

sub usage {
   print "Usage: $0 [<options>]\n","Available options:\n\t",
            "[--help] (this help text)\n\t",
            "[--identifier IdentString] (use IdentString as identifier in output)\n\t",
            "[--nofrag] (don't write fragmented files)\n\t",
            "[--size SizeInMB]+\n\t",
            "[--numruns NumberOfRuns]+\n\t",
            "[--dir TestDir]+\n\t",
            "[--block BlkSizeInBytes]+\n\t",
            "[--random NumberRandOpsPerThread]+\n\t",
            "[--threads NumberOfThreads]+\n\n",
   "+ means you can specify this option multiple times to cover multiple\n",
   "cases, for instance: $0 --block 4096 --block 8192 will first run\n",
   "through with a 4KB block size and then again with a 8KB block size.\n",
   "--numruns specifies over how many runs each test should be averaged\n";
   exit(1);
}

# look around for tiotest in different places
my @tiotest_places=(
   '.',                      # current directory
   '/usr/local/bin',         # install target location
   split(':',$ENV{'PATH'}),  # directories in current $PATH
   ($0 =~m#(.*)/#)           # directory this script resides in
);
my $tiotest='';

foreach my $place (@tiotest_places) {
   $tiotest=$place . '/tiotest';
   last if -x $tiotest;
}

if (! -x $tiotest) {
    print "tiotest program not found in any of the following places:\n\n",
          join(' ',@tiotest_places),"\n\n",
          "copy it to one of them or modify this perl script's ",
          "\@tiotest_places array\n";
    exit(1);
}

# variables
my @sizes;       my $size;      my @dirs;    my $dir;
my @blocks;      my $block;     my @threads; my $thread;
my $random_ops;  my %stat_data; my $area;    my $mem_size;

my $write_mbytes;  my $write_time;  my $write_utime;  my $write_stime;
my $rwrite_mbytes; my $rwrite_time; my $rwrite_utime; my $rwrite_stime;
my $read_mbytes;   my $read_time;   my $read_utime;   my $read_stime;
my $rread_mbytes;  my $rread_time;  my $rread_utime;  my $rread_stime;
my $num_runs;      my $run_number;  my $help;         my $nofrag;
my $identifier;    my $verify;

# option parsing
GetOptions("dir=s@",\@dirs,
           "identifier=s",\$identifier,
           "size=i@",\@sizes,
           "block=i@",\@blocks,
           "random=i",\$random_ops,
           "numruns=i",\$num_runs,
           "help",\$help,
           "nofrag",\$nofrag,
           "verify",\$verify,
           "threads=i@",\@threads);

&usage if $help || $Getopt::Long::error;

# give some default values
$num_runs=1 unless $num_runs && $num_runs > 0;
@dirs=qw(.) unless @dirs;
@blocks=qw(4096) unless @blocks;
@threads=qw(1 2 4 8) unless @threads;
$random_ops=4000 unless $random_ops;
$identifier=`uname -r` unless $identifier;
unless(@sizes) { # try to be a little smart about file size when possible
   my $mem_size; my @stat_ret;
   if(@stat_ret = stat("/proc/kcore")) {
      $mem_size=int($stat_ret[7]/(1024*1024));
   } else { $mem_size=256; }           # default in case no kcore
   my $use_size=2*($mem_size);         # try to use at least twice memory
   $use_size=200  if $use_size < 200;  # min
   $use_size=2000 if $use_size > 2000; # max
   @sizes=($use_size);
   print "No size specified, using $use_size MB\n";
}

# setup the reporting stuff for fancy output
format SEQ_READS_TOP =
                              File  Blk   Num                   Avg      Maximum      Lat%     Lat%    CPU
Identifier                    Size  Size  Thr   Rate  (CPU%)  Latency    Latency      >2s      >10s    Eff
---------------------------- ------ ----- ---  ------ ------ --------- -----------  -------- -------- -----
.

format SEQ_READS =
@<<<<<<<<<<<<<<<<<<<<<<<<<<< @||||| @|||| @>>  @##.## @>>>>% @####.### @#######.##  @#.##### @#.##### @####
$identifier,$size,$block,$thread,$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'rate'},$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'cpu'},$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'avglat'},$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'maxlat'},$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'pct_gt_2_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'pct_gt_10_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'read'}{'cpueff'}
.

format RAND_READS =
@<<<<<<<<<<<<<<<<<<<<<<<<<<< @||||| @|||| @>>  @##.## @>>>>% @####.### @#######.##  @#.##### @#.##### @####
$identifier,$size,$block,$thread,$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'rate'},$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'cpu'},$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'avglat'},$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'maxlat'},$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'pct_gt_2_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'pct_gt_10_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'rread'}{'cpueff'}
.

format SEQ_WRITES =
@<<<<<<<<<<<<<<<<<<<<<<<<<<< @||||| @|||| @>>  @##.## @>>>>% @####.### @#######.##  @#.##### @#.##### @####
$identifier,$size,$block,$thread,$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'rate'},$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'cpu'},$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'avglat'},$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'maxlat'},$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'pct_gt_2_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'pct_gt_10_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'write'}{'cpueff'}
.


format RAND_WRITES =
@<<<<<<<<<<<<<<<<<<<<<<<<<<< @||||| @|||| @>>  @##.## @>>>>% @####.### @#######.##  @#.##### @#.##### @####
$identifier,$size,$block,$thread,$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'rate'},$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'cpu'},$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'avglat'},$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'maxlat'},$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'pct_gt_2_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'pct_gt_10_sec'},$stat_data{$identifier}{$thread}{$size}{$block}{'rwrite'}{'cpueff'}
.


# run all the possible combinations/permutations/whatever
foreach $dir (@dirs) {
   foreach $size (@sizes) {
      foreach $block (@blocks) {
         foreach $thread (@threads) {
            my $thread_rand=int($random_ops/$thread);
            my $thread_size=int($size/$thread); $thread_size=1 if $thread_size==0;
            my $run_string = "$tiotest -t $thread -f $thread_size ".
                             "-r $thread_rand -b $block -d $dir -T";
            $run_string .= " -W" if $nofrag;
            $run_string .= " -c" if $verify;
            foreach $run_number (1..$num_runs) {
               my $prompt="Run #$run_number: $run_string";
               print STDERR $prompt;
               open(TIOTEST,"$run_string |") or die "Could not run $tiotest";

               while(<TIOTEST>) {
                  next if /^total/o; # this may be useful, but it's been ignored up to this point.
                  my ($field,$amount,$time,$utime,$stime,$avglat,$maxlat,$pct_gt_2_sec,$pct_gt_10_sec)=split(/[:,]/);
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'amount'} += $amount;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'time'}   += $time;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'utime'}  += $utime;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'stime'}  += $stime;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'avglat'} += $avglat;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'maxlat'} += $maxlat;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'pct_gt_2_sec'}  += $pct_gt_2_sec;
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'pct_gt_10_sec'} += $pct_gt_10_sec;
               }
               close(TIOTEST) or last;
               print STDERR "" x length($prompt); # erase prompt
            }
            for my $field ('read','rread','write','rwrite') {
               $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'rate'} = 
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'amount'} /
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'time'};
               $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'cpu'} = 
                  100 * ( $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'utime'} +
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'stime'} ) / 
                  $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'time'};
               $stat_data{$identifier}{$thread}{$size}{$block}{$field}{'cpueff'} =
                  ($stat_data{$identifier}{$thread}{$size}{$block}{$field}{'rate'} /
                  ($stat_data{$identifier}{$thread}{$size}{$block}{$field}{'cpu'}/100));
            }
         }
      }
   }
}
print STDERR "\n"; # look nicer for redir'd stdout

# report summary
print "
Unit information
================
File size = megabytes
Blk Size  = bytes
Rate      = megabytes per second
CPU%      = percentage of CPU used during the test
Latency   = milliseconds
Lat%      = percent of requests that took longer than X seconds
CPU Eff   = Rate divided by CPU% - throughput per cpu load
";

my %report;
$report{'SEQ_READS'}    = "Sequential Reads";
$report{'RAND_READS'}   = "Random Reads";
$report{'SEQ_WRITES'}   = "Sequential Writes";
$report{'RAND_WRITES'}  = "Random Writes";

foreach my $title ('SEQ_READS', 'RAND_READS', 'SEQ_WRITES', 'RAND_WRITES') {
   $-=0; $~="$title"; $^L=''; # reporting variables
   print "\n$report{$title}\n";
   foreach $size (@sizes) {
      foreach $block (@blocks) {
         foreach $thread (@threads) {
            write;
         }
      }
   }
}
