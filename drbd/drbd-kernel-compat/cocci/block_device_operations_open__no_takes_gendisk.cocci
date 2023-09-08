@ drbd_open_arg @
identifier gd;
fresh identifier bdev = "" ## "bdev";
@@
  drbd_open(
- 	struct gendisk *gd,
+ 	struct block_device *bdev,
  ... ) {
<...
(
- 	gd->part0
+ 	bdev
|
- 	gd
+ 	bdev->bd_disk
)
...>
}
