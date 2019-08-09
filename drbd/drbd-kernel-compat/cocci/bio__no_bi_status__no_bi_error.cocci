@ find_endio @
struct bio *b;
identifier fn;
@@
b->bi_end_io = fn;

@@ identifier find_endio.fn, b; @@
- fn(struct bio* b)
+ fn(struct bio* b, int error)
{
...
}

@@ identifier find_endio.fn, b, e; @@
fn(struct bio *b, int e)
{
...
// Note that this doesn't cover the case of assigning something to the status,
// or using the status outside of the callback function. This is, however, the
// only way it's used in DRBD and this is still a whole lot more flexible than
// the old way, so it's fine for now.
- b->bi_status
+ errno_to_blk_status(e)
...
}

@@
expression status;
struct bio *b;
@@
- b->bi_status = status;
...
- bio_endio(b);
+ bio_endio(b, blk_status_to_errno(status));
