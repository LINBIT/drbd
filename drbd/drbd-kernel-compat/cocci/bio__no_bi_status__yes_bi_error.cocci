@@
struct bio *b;
expression x;
@@
(
- b->bi_status = errno_to_blk_status(x)
+ b->bi_error = x
|
// specific, more readable variants
- b->bi_status = BLK_STS_IOERR
+ b->bi_error = -EIO
|
- b->bi_status = BLK_STS_RESOURCE
+ b->bi_error = -ENOMEM
|
- b->bi_status = BLK_STS_NOTSUPP
+ b->bi_error = -EOPNOTSUPP
|
// generic variant, in case something is missing
- b->bi_status = x
+ b->bi_error = blk_status_to_errno(x)
|
// do not double convert
- blk_status_to_errno(b->bi_status)
+ b->bi_error
|
- b->bi_status
+ errno_to_blk_status(b->bi_error)
)
