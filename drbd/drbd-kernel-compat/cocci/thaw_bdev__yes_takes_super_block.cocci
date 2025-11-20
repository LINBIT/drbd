@@
@@
  struct drbd_device {
  	...
+ 	struct super_block *frozen_super_block;
  }

@@
expression expr;
struct drbd_device *device;
symbol false;
@@
  if (test_and_clear_bit(BDEV_FROZEN, &device->flags)) {
  <+...
- thaw_bdev(expr);
+ thaw_bdev(expr, device->frozen_super_block);
+ device->frozen_super_block = NULL;
  ...+>
  }

@@
identifier err;
expression expr;
struct drbd_device *device;
symbol true;
identifier out_thaw;
@@
  <+...
- err = freeze_bdev(expr);
+ device->frozen_super_block = freeze_bdev(expr);
  ...+>
- if (err) { goto out_thaw; }
+ if (IS_ERR(device->frozen_super_block)) {
+ 	err = PTR_ERR(device->frozen_super_block);
+ 	device->frozen_super_block = NULL;
+ 	goto out_thaw;
+ }
  set_bit(BDEV_FROZEN, &device->flags);
