@@
const char *path;
expression mode;
void *holder;
@@
- open_bdev_exclusive(path, mode, holder)
+ open_bdev_excl(path, ((mode) & FMODE_WRITE) ? 0 : MS_RDONLY, holder)

@@
struct block_device *bdev;
expression mode;
@@
- close_bdev_exclusive(bdev, mode)
+ close_bdev_excl(bdev)
