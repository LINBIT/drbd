@@ identifier bvec, f; @@
- struct bio_vec bvec;
+ struct bio_vec *bvec;
<...
- bvec.f
+ bvec->f
...>

@@
identifier iter;
local idexpression struct bio *bio;
@@
struct bvec_iter iter =
- bio->bi_iter
+ { bio->bi_size, bio->bi_idx }
;

@@
expression iter;
expression bvec;
expression bio;
iterator name bio_for_each_segment;
@@
bio_for_each_segment(bvec, bio,
- iter
+ iter.bi_idx
 ) {
...
}

@@
expression iter;
local idexpression struct bio *bio;
@@
- bio_iter_iovec(bio, iter)
+ bio_iovec_idx(bio, (iter).bi_idx)

@@
expression iter;
expression len;
local idexpression struct bio *bio;
@@
-  bio_advance_iter_single(bio, iter, len);
+  (iter)->bi_idx++;
+  (iter)->bi_size -= len;


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
+ ((iter).bi_idx == b->bi_vcnt - 1)
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
