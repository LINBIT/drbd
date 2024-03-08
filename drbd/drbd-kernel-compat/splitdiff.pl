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
