#!/usr/bin/perl

sub readdrbd
{
    my $nr = shift;
    my $prot,$val,$i;
    $line = <STDIN>;
    $line = <STDIN>;

    for ($i=0;$i<3;$i++)
    {
	$line = <STDIN>;
	($prot, $val) =
	    ($line =~ /^ Protocol (.)\: ([0-9\.]+)/);
	$drbd{$prot}[$nr] = $val;
    }    
}

sub readnetwork
{
    $line = <STDIN>;
    $line = <STDIN>;

    $line = <STDIN>;
    ($bandwidth) =
	($line =~ /^ Bandwidth\: ([0-9\.]+)/);

    $line = <STDIN>;
    ($latency) =
	($line =~ / Latency\: round-trip min\/avg\/max = ([0-9\.\/]+) ms/);
}

sub readnode    
{
    my $nr = shift;
    $line = <STDIN>;
    $line = <STDIN>;

    $line = <STDIN>;
    ($os[$nr], $rev[$nr], $arch[$nr]) =
       ($line =~ /^ ([a-zA-Z0-9\-\.]+) ([a-zA-Z0-9\-\.]+) ([a-zA-Z0-9\-\.]+)/);

    $line = <STDIN>;
    ($mips[$nr]) = 
	($line =~ /^ [Bb][Oo][Gg][Oo][Mm][Ii][Pp][Ss]\s+\:\s+([0-9\.]+)/);

    $line = <STDIN>;
    ($disk[$nr]) = 
	($line =~ /^ Disk write\: ([0-9\.]+)/);

    $line = <STDIN>;
    ($unconn[$nr]) = 
	($line =~ /^ Drbd unconnected\: ([0-9\.]+)/);
}

sub printtable
{
    my $i;

    printf("<table BGCOLOR=#a0a0a0>\n");
    printf(" <tr><td>\n");
    printf("  <table BGCOLOR=#d3d3d3 CELLPADDING=2 width=100%>\n");
    printf("   <tr><th>Network bandwidth</th><th>Network latency ");
    printf("(min/avg/max)</th><th>Setsize</th><th>Drbd rev.</th></tr>\n");
    printf("   <tr><td>$bandwidth MB/s</td><td>$latency ms</td> ");
    printf("<td>$setsize</td><td>$drbd_rev</td></tr>\n");
    printf("  </table>\n");
    printf("  <table BGCOLOR=#d3d3d3 CELLPADDING=2>\n");
    printf("   <tr><td></td><th>OS</th><th>Rev.</th><th>Arch</th> ");
    printf("<th>BogoMips</th><th>Disk write</th><th>Drbd uncon.</th> ");
    printf("<th>Prot. A</th><th>Prot. B </th><th>Prot. C</th></tr>\n");
    for($i=1;$i<3;$i++)
    {
	printf("   ");
	printf("<tr><th>Node$i</th><td>$os[$i]</td><td>$rev[$i]</td>");
	printf("<td>$arch[$i]</td><td>$mips[$i]</td><td>$disk[$i] MB/s</td>");
	printf("<td>$unconn[$i] MB/s</td><td>$drbd{A}[$i] MB/s</td>");
	printf("<td>$drbd{B}[$i] MB/s</td><td>$drbd{C}[$i] MB/s</td></tr>\n");
    }
    printf("  </table>\n");
    printf(" </td></tr>\n");
    printf("</table>\n");
}


#
# main() 
#

$line="";

while($line = <STDIN>)
{
    if( $line eq "DRBD Benchmark\n")
    {
	$line = <STDIN>;

	($is_there,$drbd_rev) = ($line =~ /^ (Version:) ([0-9\.]+)/);
	if($is_there eq "Version:")
	{
	    $line = <STDIN>;
	}
	else
	{
	    $drbd_rev = "0.5.3";
	}
	($setsize) = ($line =~ /^ ?SETSIZE = ([0-9]+[KMG])/);
	
	readnode(1);
	readnode(2);
	readnetwork;
	readdrbd(1);
	readdrbd(2);
	printtable;
    }
}




    
