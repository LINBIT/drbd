@@
struct block_device *bd;
@@
- bdev_nr_sectors(bd)
+ i_size_read(bd->bd_inode) >> 9
