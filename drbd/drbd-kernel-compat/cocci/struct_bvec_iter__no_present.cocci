@@ identifier bvec, f; @@
- struct bio_vec bvec;
+ struct bio_vec *bvec;
<...
- bvec.f
+ bvec->f
...>

@@ identifier iter; @@
- struct bvec_iter iter;
+ int iter;

@@ local idexpression struct bio *bio; @@
(
- bio->bi_iter.bi_sector
+ bio->bi_sector
|
- bio->bi_iter.bi_size
+ bio->bi_size
)

@@
identifier bio;
expression bvec, iter;
identifier fn;
@@
fn(..., struct bio *bio, ...) {
<...
- bio_iter_last(bvec, iter)
+ ((iter) == bio->bi_vcnt - 1)
...>
}

@@
struct bio *b;
identifier f;
@@
// handle special case of bio_iovec, which is a macro that changed its
// "return type" from a struct bio_vec pointer to a struct bio_vec.
- bio_iovec(b).f
+ bio_iovec(b)->f
