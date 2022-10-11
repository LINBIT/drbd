@@
expression bd;
@@
- bdev_max_discard_sectors(bd)
+ bdev_get_queue(bd)->limits.max_discard_sectors
