package LinuxRealTime;

# Thanks to SWIG for creating parts of this file

require Exporter;
require DynaLoader;

our @ISA = qw(Exporter DynaLoader);
our @EXPORT = qw();

package LinuxRealTimec;
bootstrap LinuxRealTime;
package LinuxRealTime;

our $VERSION = '0.01';

*setRealTime = *LinuxRealTimec::setRealTime;

1;
__END__

=head1 NAME

LinuxRealTime - Perl extension for setting real time priority

=head1 SYNOPSIS

  use LinuxRealTime;
  LinuxRealTime::setRealTime(10);

  # freeze the computer for a while
  my $j; my $i;
  foreach $j (0..30_000_000)
  {  $i = sqrt ($j);   }

=head1 DESCRIPTION

Calling LinuxRealTime::setRealTime(10) sets the scheduling method of the current task
to SCHED_FIFO with a priority of 10 (if the script is executed by root). The parameter
specifies the priority, so different scripts can run with different priorities.

SCHED_FIFO is used to build real time applications. The linux kernel (>= 2.6) 
schedules all tasks using SCHED_FIFO _before_ any other "interactive task". 
Therefore all CPU resources are then used by the Perl skript.

This can be used to meassure execution times or to build real time applications.

!!!!! BE CAREFULL !!!!!
Be CAREFULL with scripts that have long execution times. Once started as root,
you will not even be able to send a CTRL-C to your script as the shell or X 
won't get any CPU ressources.

=head2 EXPORT

None by default.

=head1 SEE ALSO

=head1 AUTHOR

Daniel Zinn, E<lt>perl-public@qmic.de<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2005 by Daniel Zinn

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut

