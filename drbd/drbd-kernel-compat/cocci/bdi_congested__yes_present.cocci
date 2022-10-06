@ add_bdi_read_congested_congested_remote @
symbol false;
@@
switch (...)
{
case ...:
case RB_CONGESTED_REMOTE:
-	return false;
+	return bdi_read_congested(device->ldev->backing_bdev->bd_disk->bdi);
...
}

@ add_bdi_read_congested_device_to_statistics @
struct device_statistics *s;
@@
- s->dev_lower_blocked = false;
+ s->dev_lower_blocked = bdi_congested(device->ldev->backing_bdev->bd_disk->bdi,
+			(1 << WB_async_congested) |
+			(1 << WB_sync_congested));

@ script:python depends on !(add_bdi_read_congested_congested_remote && add_bdi_read_congested_device_to_statistics) @
@@
import sys
print('ERROR: A rule making an essential change was not executed!', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: Check bdi_congested__yes_present.cocci', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)
