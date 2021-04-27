@@
expression vdisk;
@@
- bdgrab(vdisk->part0)
+ bdget_disk(vdisk, 0)
