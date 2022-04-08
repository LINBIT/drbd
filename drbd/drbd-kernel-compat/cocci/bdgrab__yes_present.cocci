// If bdgrab is still around on this kernel, that implies that it still uses
// the "old" way of refcounting for partitions -- see 9d3b8813895d
// ("block: change the refcounting for partitions").
// As a consequence, we need to explicitly grab the partition before fsyncing it.
@@
expression part;
@@
- sync_blockdev(part);
+ struct block_device *bdev = bdgrab(part);
+ if (bdev)
+	sync_blockdev(bdev);
+ bdput(bdev);
