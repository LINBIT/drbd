@@
type T;
identifier x;
@@
+		/* compat:
+ 	 	* old kernel has 0 granularity means "unknown" means one sector.
+ 	 	* current kernel has 0 granularity means "discard not supported".
+ 	 	* Not supported is checked above already with !bdev_max_discard_sectors(bdev).
+ 	 	*/
		T x =
-		bdev_discard_granularity(bdev)
+		bdev->bd_disk->queue->limits.discard_granularity ?: 512
		;
