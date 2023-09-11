@@
expression path, mode;
@@
  blkdev_get_by_path(
  	path,
- 	mode,
+ 	mode | FMODE_EXCL,
  	...
  )

@@
expression bdev, holder;
@@
  blkdev_put(
  	bdev,
- 	holder
+ 	FMODE_READ | FMODE_WRITE | FMODE_EXCL
  )

@@
identifier device, bdev, holder, do_bd_unlink;
@@
  void close_backing_dev(
  	struct drbd_device *device,
  	struct block_device *bdev,
-  	void *holder,
  	bool do_bd_unlink
  ) { ... }

@@
expression device, bdev, holder, do_bd_unlink;
@@
  close_backing_dev(
  	device,
  	bdev,
- 	holder,
  	do_bd_unlink
  )
