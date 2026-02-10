// On kernels without bio_for_each_bvec (<v5.1), bio_for_each_segment does
// not split multi-page bvecs. Submitting bios with multi-page bvecs to
// drivers that iterate with bio_for_each_segment (e.g. brd) would cause
// buffer overflows. Force single-page allocations on these kernels.
@@
expression E;
@@
 drbd_alloc_pages(...)
 {
  ...
  order =
- E
+ 0 /* Multi page bvecs not supported on this kernel */
  ...
}
