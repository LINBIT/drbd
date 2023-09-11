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

@@
identifier iter;
fresh identifier iter_btg = iter ## "_btg";
local idexpression struct bio *bio;
@@
- struct bvec_iter iter = bio->bi_iter;
+ int iter = bio->bi_idx;
+ int iter_btg = bio->bi_size;

@@
identifier iter;
identifier bvec;
fresh identifier iter_btg = iter ## "_btg";
local idexpression struct bio *bio;
iterator name __bio_for_each_segment;
@@
- __bio_for_each_segment(bvec, bio, iter, iter) {
+ for (bvec = bio_iovec_idx(bio, iter); iter < bio->bi_vcnt; iter_btg -= bvec->bv_len, bvec++, iter++) {
...
}

@@
identifier iter;
expression len;
fresh identifier iter_btg = iter ## "_btg";
local idexpression struct bio *bio;
@@
-  bio_advance_iter_single(bio, &iter, len);
+  iter++;
+  iter_btg -= len;

@@
//local idexpression struct iter iter;
identifier iter =~ "^iter";
fresh identifier iter_btg = iter ## "_btg";
@@
- iter.bi_size
+ iter_btg


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
