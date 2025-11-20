@@
@@
  struct drbd_device {
  	...
- 	bool bdev_frozen;
+ 	struct super_block *frozen_super_block;
  	...
  }

@@
expression expr;
struct drbd_device *device;
symbol false;
@@
  <+...
- thaw_bdev(expr);
+ thaw_bdev(expr, device->frozen_super_block);
  ...+>
- device->bdev_frozen = false;
+ device->frozen_super_block = NULL;

@@
identifier i;
expression expr;
struct drbd_device *device;
symbol true;
identifier out_thaw;
@@
  <+...
- i = freeze_bdev(expr);
+ device->frozen_super_block = freeze_bdev(expr);
  ...+>
- if (i) { goto out_thaw; }
+ if (IS_ERR(device->frozen_super_block)) {
+ 	i = PTR_ERR(device->frozen_super_block);
+ 	device->frozen_super_block = NULL;
+ 	goto out_thaw;
+ }
- device->bdev_frozen = true;


@@
struct drbd_device *device;
@@
- device->bdev_frozen
+ device->frozen_super_block
