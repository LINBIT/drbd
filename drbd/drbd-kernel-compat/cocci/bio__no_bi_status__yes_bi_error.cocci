@@
expression b;
expression x;
@@
(
- b->bi_status = x
+ b->bi_error = blk_status_to_errno(x)
|
- b->bi_status
+ errno_to_blk_status(b->bi_error)
)
