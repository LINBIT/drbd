@@
struct block_device *bd;
@@
- bdev_nr_sectors(bd)
+ get_capacity(bd->bd_disk)
