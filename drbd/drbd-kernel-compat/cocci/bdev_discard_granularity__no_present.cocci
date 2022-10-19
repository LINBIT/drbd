@@
expression bdev;
@@
-		bdev_discard_granularity(bdev)
+		(bdev->bd_disk->queue->limits.discard_granularity ?: 512)
