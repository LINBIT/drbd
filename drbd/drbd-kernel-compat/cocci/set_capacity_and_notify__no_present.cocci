@@
expression disk, size;
@@
- set_capacity_and_notify(disk, size);
+ set_capacity(disk, size);
+ revalidate_disk_size(disk, false);
