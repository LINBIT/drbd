@@
const char *path;
expression mode;
void *holder;
@@
- blkdev_get_by_path(path, mode, holder)
+ open_bdev_exclusive(path, mode, holder)

// the following is a workaround for a limitation in coccinelle.
// the spatch parser doesn't know about statement expressions
// because they are a gcc extension and not standard C.
// the parser can be tricked by generating the code as a constant
// string in a script.
@find_blkdev_put@
struct block_device *bdev;
expression mode;
@@
 blkdev_put(bdev, mode)

@script:python gen_blkdev_put@
bdev << find_blkdev_put.bdev;
mode << find_blkdev_put.mode;
x;
@@
coccinelle.x = "({ close_bdev_exclusive(" + bdev + ", (" + mode + ")); 0; })"

@@
struct block_device *find_blkdev_put.bdev;
expression find_blkdev_put.mode;
identifier gen_blkdev_put.x;
@@
// blkdev_put != close_bdev_exclusive, in general, so this is obviously
// not correct, and there should be some if (mode & FMODE_EXCL) ...
// But this is the only way it is used in DRBD,
// and for <= 2.6.27, there is no FMODE_EXCL anyways.
- blkdev_put(bdev, mode)
// blkdev_put seems to not have useful return values,
// close_bdev_exclusive is void. -> always return 0
+ x
