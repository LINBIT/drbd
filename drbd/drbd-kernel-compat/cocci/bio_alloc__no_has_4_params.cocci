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
+ if (b) {
+ 	bio_set_dev(b, ebdev);
+ 	b->bi_opf = _opf;
+ }

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

// a bio_alloc_bioset() whose result is returned directly; the assignments the
// old signature needs have to go somewhere, so give the result a variable
@@
expression ebdev, _opf, gfp_mask, nr_vecs, bioset;
@@
- return bio_alloc_bioset(ebdev, nr_vecs, _opf, gfp_mask, bioset);
+ {
+ 	struct bio *new_bio = bio_alloc_bioset(gfp_mask, nr_vecs, bioset);
+
+ 	if (new_bio) {
+ 		bio_set_dev(new_bio, ebdev);
+ 		new_bio->bi_opf = _opf;
+ 	}
+ 	return new_bio;
+ }
