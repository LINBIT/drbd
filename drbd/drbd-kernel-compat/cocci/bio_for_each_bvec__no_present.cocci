// On kernels without bio_for_each_bvec (<v5.1), bio_for_each_segment does
// not split multi-page bvecs. Submitting bios with multi-page bvecs to
// drivers that iterate with bio_for_each_segment (e.g. brd) would cause
// buffer overflows. Force single-page allocations on these kernels.
@ single_page_order @
expression E;
symbol order;
@@
 alloc_pages_throttled(...)
 {
  ...
  order =
- E
+ 0 /* Multi page bvecs not supported on this kernel */
  ...
}

@ script:python depends on !single_page_order @
@@
import sys
print('ERROR: A rule making an essential change was not executed! (single_page_order)', file=sys.stderr)
print('ERROR: This would not show up as a compiler error, but would still break DRBD.', file=sys.stderr)
print('ERROR: Check bio_for_each_bvec__no_present.cocci', file=sys.stderr)
print('ERROR: As a precaution, the build will be aborted here.', file=sys.stderr)
sys.exit(1)
