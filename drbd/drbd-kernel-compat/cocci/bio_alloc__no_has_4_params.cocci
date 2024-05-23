@@
local idexpression struct bio *b;
expression ebdev, _opf, gfp_mask, nr_vecs, bioset;
@@
b =
(
bio_alloc(
- ebdev, nr_vecs, _opf, gfp_mask
+ gfp_mask, nr_vecs
 )
|
bio_alloc_bioset(
- ebdev, nr_vecs, _opf, gfp_mask, bioset
+ gfp_mask, nr_vecs, bioset
 )
);
+ bio_set_dev(b, ebdev);
...
b->bi_end_io = ...;
+ b->bi_opf = _opf;

// special case for the bio_alloc in submit_one_flush
// 1) because it is "struct bio *b = ...", not just "b = ...", and
// 2) because it has the "bio_set_dev" and "b->bi_opf" assignments in different
//    places
@@
identifier b;
expression ebdev, _opf, gfp_mask, nr_vecs;
@@
struct bio *b = bio_alloc(
- ebdev, nr_vecs, _opf, gfp_mask
+ gfp_mask, nr_vecs
 );
...
+ bio_set_dev(b, ebdev);
b->bi_private = ...;
...
+ b->bi_opf = _opf;
submit_bio(b);
