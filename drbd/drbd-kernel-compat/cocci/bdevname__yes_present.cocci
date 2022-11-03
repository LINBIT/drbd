@initialize:python@
@@

@@
identifier dev, fn;
constant old_format;
fresh identifier new_format = script:python(old_format) { old_format.replace("%pg", "%s") };
@@
{
+	char b[BDEVNAME_SIZE];
...
	fn(...,
-		old_format
+		new_format
	, ...,
-	dev->ldev->backing_bdev
+	bdevname(dev->ldev->backing_bdev, b)
	);
	...
}
