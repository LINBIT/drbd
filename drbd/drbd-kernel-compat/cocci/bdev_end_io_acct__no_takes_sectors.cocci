// Before Linux 6.3, bio-based devices count a bio's sectors in part_stat at
// submission; blk-mq devices count at completion. Count DRBD's own IO for the
// busy detector at the same point as the backing device.

@ own_io_read_endio @
identifier D;
expression S;
@@
drbd_endio_read_sec_final(...)
{
<+...
- atomic_add(S, &D->rs_sect_done);
+ if (bdev_get_queue(D->ldev->backing_bdev)->mq_ops)
+	atomic_add(S, &D->rs_sect_done);
...+>
}

@ own_io_write_endio @
identifier D;
expression S;
@@
drbd_endio_write_sec_final(...)
{
<+...
- atomic_add(S, &D->rs_sect_done);
+ if (bdev_get_queue(D->ldev->backing_bdev)->mq_ops)
+	atomic_add(S, &D->rs_sect_done);
...+>
}

@ own_io_bm_endio @
identifier D;
expression S;
@@
drbd_bm_endio(...)
{
<+...
- atomic_add(S, &D->rs_sect_done);
+ if (bdev_get_queue(D->ldev->backing_bdev)->mq_ops)
+	atomic_add(S, &D->rs_sect_done);
...+>
}

@ own_io_peer_req_submit_zeroout @
identifier P;
symbol jiffies;
@@
drbd_submit_peer_request(struct drbd_peer_request *P)
{
<+...
if (P->flags & (EE_TRIM|EE_ZEROOUT)) {
  P->submit_jif = jiffies;
+ if (!bdev_get_queue(P->peer_device->device->ldev->backing_bdev)->mq_ops &&
+     !drbd_interval_is_application(&P->i))
+	atomic_add(P->i.size >> 9, &P->peer_device->device->rs_sect_done);
  ...
}
...+>
}

@ own_io_peer_req_submit_bio @
identifier P;
expression N;
symbol jiffies;
@@
drbd_submit_peer_request(struct drbd_peer_request *P)
{
<+...
  atomic_set(&P->pending_bios, N);
  P->submit_jif = jiffies;
+ if (!bdev_get_queue(P->peer_device->device->ldev->backing_bdev)->mq_ops &&
+     !drbd_interval_is_application(&P->i))
+	atomic_add(P->i.size >> 9, &P->peer_device->device->rs_sect_done);
...+>
}

@ own_io_bm_submit @
identifier D, ctx;
symbol len;
@@
bm_page_io_async(struct drbd_bm_aio_ctx *ctx, ...)
{
...
struct drbd_device *D = ctx->device;
<+...
+ if (D->ldev->md_bdev->bd_disk == D->ldev->backing_bdev->bd_disk &&
+     !bdev_get_queue(D->ldev->backing_bdev)->mq_ops)
+	atomic_add(len >> 9, &D->rs_sect_done);
  submit_bio(...);
...+>
}

@ script:python depends on !(own_io_read_endio && own_io_write_endio && own_io_bm_endio && own_io_peer_req_submit_zeroout && own_io_peer_req_submit_bio && own_io_bm_submit) @
@@
import sys
print('ERROR: A rule making an essential change was not executed! (busy detector own IO at submission)', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: Check bdev_end_io_acct__no_takes_sectors.cocci', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)
