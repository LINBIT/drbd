%seen = ();
while (defined($_=<STDIN>)) {
	/^--- (?:.\/)?(\S+)/ and do {
		($out = $1) =~ s,/,_,g;
		$mode = '>';
		if (exists $seen{$out}) {
			warn qq{$.: $out patched multiple times, APPENDING to previous version: @{[join ", ", @{$seen{$out}}]}\n};
			$mode = '>>';
		}
		push @{$seen{$out}}, $.;
		$out .= ".patch";
		open STDOUT,$mode,$out or die "$out: $!";
		print STDERR "$mode$out\n" if $ENV{V};
	};

	/^[+-]{3} / and next if $mode eq '>>';

	print;
}
close STDOUT;

# Sort hunks by line number in files that were patched multiple times.
# When multiple patches touch the same file, their hunks may interleave
# (e.g., patch A has hunks at lines 253 and 321, patch B at line 298).
# Appending produces out-of-order hunks that GNU patch silently misapplies.
for my $out (keys %seen) {
	next unless @{$seen{$out}} > 1;
	my $file = "$out.patch";
	open my $fh, '<', $file or die "$file: $!";
	my $content = do { local $/; <$fh> };
	close $fh;

	my ($header, $rest) = $content =~ /\A(---[^\n]*\n\+\+\+[^\n]*\n)(.*)/s;
	next unless $header;

	my @hunks = grep { length } split /(?=^@@)/m, $rest;
	@hunks = sort {
		my ($la) = $a =~ /^@@ -(\d+)/;
		my ($lb) = $b =~ /^@@ -(\d+)/;
		$la <=> $lb;
	} @hunks;

	open $fh, '>', $file or die "$file: $!";
	print $fh $header, @hunks;
	close $fh;
}
