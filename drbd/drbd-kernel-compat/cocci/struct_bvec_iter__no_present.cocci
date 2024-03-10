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

@@ local idexpression struct bio *b; @@
(
- b->bi_iter.bi_sector
+ b->bi_sector
|
- b->bi_iter.bi_size
+ b->bi_size
)

@@
identifier b;
expression bvec, iter;
identifier fn;
identifier bio = bio;
@@
fn(..., struct bio *b, ...) {
<...
- bio_iter_last(bvec, iter)
+ ((iter) == b->bi_vcnt - 1)
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
