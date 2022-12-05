@@
expression b;
identifier d;
identifier off;
@@
- u64 off;
...
- d = fs_dax_get_by_bdev(b, &off, NULL, NULL);
+ if (!blk_queue_dax(b ->bd_queue))
+	return -ENODEV;
+ d = fs_dax_get_by_host(b->bd_disk->disk_name);
