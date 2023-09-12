@@
identifier gd;
fresh identifier mode = "" ## "mode";
@@
  drbd_release(
  	struct gendisk *gd
+ 	, fmode_t mode
  ) { ... }

@@
symbol drbd_release;
expression gd;
@@
  drbd_release(
  	gd
+ 	, 0
  )
