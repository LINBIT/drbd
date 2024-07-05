@@
identifier gd;
fresh identifier mode = "" ## "mode";
@@
  drbd_release(
	struct gendisk *gd
+ 	, fmode_t mode
  ) { ... }


// remove the local variable mode, so that it does not shadow the parameter mode
@@
expression ex;
@@
drbd_release(...)
{
...
- fmode_t mode = ex;
...
}

@@
symbol drbd_release;
expression gd;
@@
  drbd_release(
  	gd
+ 	, 0
  )
