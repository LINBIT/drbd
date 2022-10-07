@ add_blk_queue_max_write_same_sectors @
identifier q;
@@
blk_queue_max_hw_sectors(q, ...);
+ blk_queue_max_write_same_sectors(q, 0);

@ script:python depends on !add_blk_queue_max_write_same_sectors @
@@
import sys
print('ERROR: A rule making an essential change was not executed!', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: Check blk_queue_max_write_same_sectors_yes_present.cocci', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)
