@@
identifier gd, mode;
typedef fmode_t;
@@
static
-void
+int
drbd_release(struct gendisk *gd, fmode_t mode)
{
       ...
+      return 0;
}
