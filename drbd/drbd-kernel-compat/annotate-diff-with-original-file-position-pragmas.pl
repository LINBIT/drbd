#!/usr/bin/perl -w

# Filter a patch.
# Annotate with original line number and filename,
# so the compiler messages reference the actual source,
# and not the patched file.

use Cwd qw(getcwd);
$CWD = getcwd() or die "getcwd: $!\n";

$DRBDSRC = $ENV{DRBDSRC} // $CWD;
$DRBDSRC =~ m{^/} or die "DRBDSRC ($DRBDSRC) should be an absolute path\n";
$DRBDSRC =~ s#/*$#/#; # single trailing slash
-d $DRBDSRC 	or die "DRBDSRC ($DRBDSRC): not a directory\n";

$OUTDIR = $ENV{OUTDIR} or die "OUTDIR environment not set\n";
$OUTDIR =~ m{^/} or die "OUTDIR ($OUTDIR) should be an absolute path\n";
$OUTDIR =~ s#/*$#/#; # single trailing slash

-d $OUTDIR	or die "OUTDIR ($OUTDIR): not a directory\n";
-w _		or die "OUTDIR ($OUTDIR): cannot write here\n";

$PATCHES_DIR = $ENV{PATCHES_DIR} // $OUTDIR .".patches";
$PATCHES_DIR =~ m{^/} or die "PATCHES_DIR ($PATCHES_DIR) should be an absolute path\n";
$PATCHES_DIR =~ s#/*$#/#; # single trailing slash

-d $PATCHES_DIR	or die "PATCHES_DIR ($PATCHES_DIR): not a directory\n";
-w _		or die "PATCHES_DIR ($PATCHES_DIR): cannot write here\n";

sub patchname_from_orig($) {
	my $patch = $_[0];
	# splitdiff -a mangles '/' to '_' and appends .patch.
	$patch =~ s,/,_,g;
	$patch .= ".patch";
	# prefix absulute .patches directory.
	$patch = $PATCHES_DIR . $patch unless $patch =~ m{^/};
	return $patch;
}

sub print_and_reset_prev_chunk() {
	return unless $chunk;
	print qq{\@\@ -$o_line,$o_count +$n_line,$n_count \@\@$annotation\n} . $chunk;
	$chunk = "";
	if ($file_line_context_points_to_orig == 0) {
		warn "$patch_name:$.: could not reset file:line context back to original\n";
		$file_line_context_points_to_orig == -1
	}
}

# annotate orig file position and line in the patch
# and position in actual output file.
# would be great if we even could point to the cocci rule.
# Do not add line number pragma annotations in the middle of some macro line
# continuation. That is too much fun.

while (defined($_=<STDIN>)) {
$continuation_line = $trailing_backslash_or_first_line_in_chunk // "";

m{^[ +@]} and do { $trailing_backslash_or_first_line_in_chunk = m{\\$} || /^@/; };

/^\+{3} .*/	and next;
s/^(---.*?)\t.*$/$1/; # strip timestamps
m{^--- } and $NAME and die "$NAME: $.: Expected a patch for a single file only, found:\n|$_";

m{^--- .*?(/\.\./|\s).*\n} and die "bad input line $.: >$1<\n|\t$_";
m{^--- (?:\./)?(\S+)$} and do {
	($NAME, $o_line, $o_count, $n_line, $n_count, $state) = ($1,0,0,0,0,"");
	$NAME =~ s/^\Q$DRBDSRC\E//;
	$ABS_NAME = ($NAME =~ m{^/}) ? $NAME : $DRBDSRC.$NAME;
	($ABS_PATCHED_NAME = $ABS_NAME) =~ s/^\Q$DRBDSRC\E/$OUTDIR/;
	$patch_name = patchname_from_orig($NAME);
	next;
	};
/^\@\@ / and do {
	if ($o_line == 0) { # first line original file annotation
		print qq{--- $NAME\n+++ $NAME\n\@\@ -0,0 +0,1 \@\@\n+# 1 "$ABS_NAME"\n};
		$file_line_context_points_to_orig = 1;
		$extra_ncount = 1;
	}
	print_and_reset_prev_chunk();
	($o_line, $o_count, $n_line, $n_count, $annotation) = /^@@ -(\d+),(\d+) [+](\d+),(\d+) @@(.*)$/g;
	$n_line += $extra_ncount;
	$o_pos = $o_line;
	$n_pos = $n_line;
	next;
	};
/^-/ and do { $state = '-'; $o_pos++; $chunk .= $_; next; };
/^ / and do {
	if ($state ne ' ') {
		if (not $continuation_line) {
			$chunk .= qq{+# $. "$patch_name"\n};
			$chunk .= qq{+# $o_pos "$ABS_NAME"\n};
			$n_count += 2;
			$extra_ncount += 2;
			$file_line_context_points_to_orig = 1;
			$state = ' ';
		} else {
			$state = ' c';
		}
	}
	$o_pos++;
	$n_pos++;
	$chunk .= $_;
	next;
	};
/^[+]/ and do {
	if ($state ne '+') {
		if (not $continuation_line) {
			$extra_ncount += 3;
			$n_count += 3;
			$n_pos += 3;
			$chunk .= qq{+# $o_pos "$ABS_NAME"\n};
			$chunk .= qq{+# $. "$patch_name"\n};
			$chunk .= qq{+# $n_pos "$ABS_PATCHED_NAME"\n};
			$file_line_context_points_to_orig = 0;
			$state = '+';
		} else {
			warn	"$patch_name:$.: could not annotate 'plus' lines, line offsets may be wrong\n"
			.	"$ABS_PATCHED_NAME:$n_pos: could not annotate 'plus' lines, line offsets may be wrong\n"
				unless $file_line_context_points_to_orig == -1;

			$file_line_context_points_to_orig = -1;
			$state = '+c';
		}
	}
	$n_pos++;
	$chunk .= $_;
	next;
	};

die "$patch_name:$.: unexpected input: $_";
}
print_and_reset_prev_chunk();
