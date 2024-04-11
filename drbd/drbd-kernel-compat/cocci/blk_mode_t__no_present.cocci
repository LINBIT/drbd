@@
identifier fn;
identifier mode;
@@
  fn (
  	...,
- 	blk_mode_t mode
+ 	fmode_t mode
  ) {
  <...
(
- BLK_OPEN_WRITE
+ FMODE_WRITE
|
- BLK_OPEN_NDELAY
+ FMODE_NDELAY
)
  ...>
  }

@@
@@
// special case: bdev_open_by_path takes a blk_mode_t, so convert that too. I can't seem to get
// coccinelle to match the "READ | WRITE" condition generically, so just hard code it.
// NOTE: we use blkdev_get_by_path instead of bdev_open_by_path in some compat cases, so support that too.
(
bdev_open_by_path
|
blkdev_get_by_path
)
 (...,
- BLK_OPEN_READ | BLK_OPEN_WRITE
+ FMODE_READ | FMODE_WRITE
 , ...)
