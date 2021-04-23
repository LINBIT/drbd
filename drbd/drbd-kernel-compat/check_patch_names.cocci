virtual report

@find_compat@
expression compat;
expression suffix;
position p;
@@
* patch(..., compat@p, suffix);

@script:python depends on report@
c << find_compat.compat;
p << find_compat.p;
@@
import sys
from os import listdir

def exists(c):
    for f in listdir('drbd/drbd-kernel-compat/tests/'):
        if c == 'COMPAT_' + f.upper()[:-len('.c')]:
            return True
    return False

if c in ['YES', 'NO']:
	sys.exit(0)

if not c.startswith('COMPAT_'):
	msg = 'ERROR: compat define {} does not start with COMPAT_'.format(c)
	coccilib.report.print_report(p[0], msg)
	sys.exit(1)

if not exists(c):
	msg = 'ERROR: compat define {} does not correspond to a compat test'.format(c)
	coccilib.report.print_report(p[0], msg)
	sys.exit(1)
