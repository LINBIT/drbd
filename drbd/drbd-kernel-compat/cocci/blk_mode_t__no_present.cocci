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
